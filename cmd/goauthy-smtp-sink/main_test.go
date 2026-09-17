package main

import (
	"bufio"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestSMTPStoresMessageAndHTTPResetsIt(t *testing.T) {
	mailbox := &mailbox{}
	listener, done := startSMTP(t, mailbox)
	connection, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	reader := bufio.NewReader(connection)
	writer := bufio.NewWriter(connection)
	wantSMTP(t, reader, "220 ")
	for _, command := range []string{
		"EHLO test.example\r\n",
		"MAIL FROM:<sender@example.test>\r\n",
		"RCPT TO:<recipient@example.test>\r\n",
		"DATA\r\n",
	} {
		if _, err := writer.WriteString(command); err != nil {
			t.Fatal(err)
		}
		if err := writer.Flush(); err != nil {
			t.Fatal(err)
		}
		switch command[:4] {
		case "EHLO":
			wantSMTP(t, reader, "250-")
			wantSMTP(t, reader, "250 ")
		case "DATA":
			wantSMTP(t, reader, "354 ")
		default:
			wantSMTP(t, reader, "250 ")
		}
	}
	if _, err := writer.WriteString("Subject: reset\r\n\r\nhttps://issuer.example.test/account/reset?token=secret\r\n..dot-stuffed\r\n.\r\n"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	wantSMTP(t, reader, "250 ")
	if _, err := writer.WriteString("QUIT\r\n"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	wantSMTP(t, reader, "221 ")

	httpServer := httptest.NewServer(mailbox.handler())
	defer httpServer.Close()
	response, err := http.Get(httpServer.URL + "/messages")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var got struct {
		Messages []message `json:"messages"`
	}
	if err := json.NewDecoder(response.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" || len(got.Messages) != 1 || got.Messages[0].ID != 1 || got.Messages[0].From != "sender@example.test" || len(got.Messages[0].To) != 1 || got.Messages[0].To[0] != "recipient@example.test" || !strings.Contains(got.Messages[0].Data, "\r\n.dot-stuffed\r\n") {
		t.Fatalf("messages=%#v status=%d headers=%#v", got.Messages, response.StatusCode, response.Header)
	}

	request, err := http.NewRequest(http.MethodDelete, httpServer.URL+"/messages", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("reset status=%d", response.StatusCode)
	}
	if messages := mailbox.snapshot(); len(messages) != 0 {
		t.Fatalf("messages after reset=%#v", messages)
	}

	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSMTPRejectsInvalidTransactions(t *testing.T) {
	mailbox := &mailbox{}
	listener, done := startSMTP(t, mailbox)
	connection, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(connection)
	writer := bufio.NewWriter(connection)
	wantSMTP(t, reader, "220 ")
	for _, tc := range []struct {
		command string
		want    string
	}{
		{"DATA\r\n", "503 "},
		{"MAIL FROM:bad\r\n", "501 "},
		{"MAIL FROM:<sender@example.test>\r\n", "250 "},
		{"RCPT TO:bad\r\n", "501 "},
		{"WAT\r\n", "502 "},
		{"RSET extra\r\n", "501 "},
		{"QUIT\r\n", "221 "},
	} {
		if _, err := writer.WriteString(tc.command); err != nil {
			t.Fatal(err)
		}
		if err := writer.Flush(); err != nil {
			t.Fatal(err)
		}
		wantSMTP(t, reader, tc.want)
	}
	_ = connection.Close()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if messages := mailbox.snapshot(); len(messages) != 0 {
		t.Fatalf("invalid SMTP transaction stored messages=%#v", messages)
	}
}

func TestMailboxIsConcurrentAndBounded(t *testing.T) {
	mailbox := &mailbox{}
	var group sync.WaitGroup
	for range maxMessages * 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			mailbox.store("sender@example.test", []string{"recipient@example.test"}, "body")
		}()
	}
	group.Wait()
	messages := mailbox.snapshot()
	if len(messages) != maxMessages || messages[0].ID <= 1 || messages[len(messages)-1].ID != maxMessages*2 {
		t.Fatalf("bounded messages=%#v", messages)
	}
}

func TestHTTPControlEndpoints(t *testing.T) {
	mailbox := &mailbox{}
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/livez", http.StatusNoContent},
		{http.MethodPost, "/messages", http.StatusMethodNotAllowed},
		{http.MethodGet, "/messages?x=1", http.StatusBadRequest},
	} {
		request := httptest.NewRequest(tc.method, tc.path, nil)
		response := httptest.NewRecorder()
		mailbox.handler().ServeHTTP(response, request)
		if response.Code != tc.want || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s %s status=%d headers=%#v", tc.method, tc.path, response.Code, response.Header())
		}
	}
}

func startSMTP(t *testing.T, mailbox *mailbox) (net.Listener, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- serveSMTP(listener, mailbox) }()
	return listener, done
}

func wantSMTP(t *testing.T, reader *bufio.Reader, prefix string) {
	t.Helper()
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(line, prefix) {
		t.Fatalf("SMTP response=%q, want prefix %q", line, prefix)
	}
}
