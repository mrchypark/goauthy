// Command goauthy-smtp-sink provides a local-kind-only SMTP mailbox for E2E
// tests. It intentionally has neither TLS nor authentication and must never
// be deployed outside an isolated test namespace.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	maxMessages   = 128
	maxRecipients = 32
	maxMessage    = 64 << 10
	maxSMTPLine   = 4 << 10
)

type message struct {
	ID   uint64   `json:"id"`
	From string   `json:"from"`
	To   []string `json:"to"`
	Data string   `json:"data"`
}

type mailbox struct {
	mu       sync.Mutex
	nextID   uint64
	messages []message
}

func (m *mailbox) store(from string, to []string, data string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	m.messages = append(m.messages, message{ID: m.nextID, From: from, To: append([]string(nil), to...), Data: data})
	if len(m.messages) > maxMessages {
		m.messages = m.messages[len(m.messages)-maxMessages:]
	}
}

func (m *mailbox) snapshot() []message {
	m.mu.Lock()
	defer m.mu.Unlock()
	messages := make([]message, len(m.messages))
	for i, value := range m.messages {
		messages[i] = message{ID: value.ID, From: value.From, To: append([]string(nil), value.To...), Data: value.Data}
	}
	return messages
}

func (m *mailbox) reset() {
	m.mu.Lock()
	m.messages = nil
	m.mu.Unlock()
}

func (m *mailbox) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/livez", m.livez)
	mux.HandleFunc("/messages", m.messagesHandler)
	return mux
}

func (m *mailbox) livez(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (m *mailbox) messagesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		http.Error(w, "query parameters are not accepted", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Messages []message `json:"messages"`
		}{Messages: m.snapshot()})
	case http.MethodDelete:
		m.reset()
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func serveSMTP(listener net.Listener, mailbox *mailbox) error {
	for {
		connection, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go func() {
			defer connection.Close()
			handleSMTP(connection, mailbox)
		}()
	}
}

func handleSMTP(connection net.Conn, mailbox *mailbox) {
	_ = connection.SetDeadline(time.Now().Add(30 * time.Second))
	reader := bufio.NewReader(connection)
	writer := bufio.NewWriter(connection)
	defer writer.Flush()
	writeSMTP(writer, 220, "goauthy smtp sink")

	var from string
	var recipients []string
	for {
		line, err := readSMTPLine(reader)
		if err != nil {
			return
		}
		command, argument := splitSMTPCommand(line)
		switch command {
		case "EHLO":
			if argument == "" {
				writeSMTP(writer, 501, "EHLO requires a domain")
				continue
			}
			_, _ = writer.WriteString("250-goauthy-smtp-sink\r\n250 SIZE 65536\r\n")
			_ = writer.Flush()
		case "HELO":
			if argument == "" {
				writeSMTP(writer, 501, "HELO requires a domain")
				continue
			}
			writeSMTP(writer, 250, "hello")
		case "MAIL":
			value, ok := smtpPath(argument, "FROM:")
			if !ok {
				writeSMTP(writer, 501, "invalid MAIL FROM")
				continue
			}
			from, recipients = value, nil
			writeSMTP(writer, 250, "sender accepted")
		case "RCPT":
			if from == "" {
				writeSMTP(writer, 503, "MAIL FROM required")
				continue
			}
			value, ok := smtpPath(argument, "TO:")
			if !ok {
				writeSMTP(writer, 501, "invalid RCPT TO")
				continue
			}
			if len(recipients) >= maxRecipients {
				writeSMTP(writer, 452, "too many recipients")
				continue
			}
			recipients = append(recipients, value)
			writeSMTP(writer, 250, "recipient accepted")
		case "DATA":
			if argument != "" {
				writeSMTP(writer, 501, "DATA accepts no arguments")
				continue
			}
			if from == "" || len(recipients) == 0 {
				writeSMTP(writer, 503, "MAIL FROM and RCPT TO required")
				continue
			}
			writeSMTP(writer, 354, "end data with <CR><LF>.<CR><LF>")
			data, err := readSMTPData(reader)
			if err != nil {
				writeSMTP(writer, 552, "message rejected")
				from, recipients = "", nil
				continue
			}
			mailbox.store(from, recipients, data)
			from, recipients = "", nil
			writeSMTP(writer, 250, "message accepted")
		case "RSET":
			if argument != "" {
				writeSMTP(writer, 501, "RSET accepts no arguments")
				continue
			}
			from, recipients = "", nil
			writeSMTP(writer, 250, "reset")
		case "NOOP":
			writeSMTP(writer, 250, "ok")
		case "QUIT":
			writeSMTP(writer, 221, "bye")
			return
		default:
			writeSMTP(writer, 502, "command not implemented")
		}
	}
}

func readSMTPLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) > maxSMTPLine || !strings.HasSuffix(line, "\r\n") {
		return "", errors.New("invalid smtp line")
	}
	return strings.TrimSuffix(line, "\r\n"), nil
}

func readSMTPData(reader *bufio.Reader) (string, error) {
	var data strings.Builder
	for {
		line, err := readSMTPLine(reader)
		if err != nil {
			return "", err
		}
		if line == "." {
			return data.String(), nil
		}
		if strings.HasPrefix(line, "..") {
			line = line[1:]
		}
		if data.Len()+len(line)+2 > maxMessage {
			return "", errors.New("message too large")
		}
		data.WriteString(line)
		data.WriteString("\r\n")
	}
}

func splitSMTPCommand(line string) (string, string) {
	command, argument, found := strings.Cut(line, " ")
	if !found {
		return strings.ToUpper(command), ""
	}
	return strings.ToUpper(command), strings.TrimSpace(argument)
}

func smtpPath(argument, prefix string) (string, bool) {
	if !strings.HasPrefix(strings.ToUpper(argument), prefix) {
		return "", false
	}
	value := strings.TrimSpace(argument[len(prefix):])
	if len(value) < 2 || value[0] != '<' || value[len(value)-1] != '>' || strings.ContainsAny(value, "\r\n") {
		return "", false
	}
	return value[1 : len(value)-1], true
}

func writeSMTP(writer *bufio.Writer, status int, text string) {
	_, _ = fmt.Fprintf(writer, "%03d %s\r\n", status, text)
	_ = writer.Flush()
}

func main() {
	smtpAddress := flag.String("smtp-addr", ":1025", "SMTP listen address")
	httpAddress := flag.String("http-addr", ":8082", "HTTP listen address")
	flag.Parse()

	mailbox := &mailbox{}
	smtpListener, err := net.Listen("tcp", *smtpAddress)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	defer smtpListener.Close()
	httpServer := &http.Server{Addr: *httpAddress, Handler: mailbox.handler(), ReadHeaderTimeout: 5 * time.Second}
	errChannel := make(chan error, 2)
	go func() { errChannel <- serveSMTP(smtpListener, mailbox) }()
	go func() {
		err := httpServer.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errChannel <- err
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = smtpListener.Close()
		_ = httpServer.Shutdown(shutdown)
	case err := <-errChannel:
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}
}
