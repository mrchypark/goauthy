package smtptransport

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"

	mail "github.com/wneessen/go-mail"
	"github.com/wneessen/go-mail/smtp"
)

// Dialer ties the connection lifetime to ctx. For implicit TLS it also
// performs the handshake here because go-mail's custom dialer hook otherwise
// bypasses its implicit-TLS dial path.
func Dialer(ctx context.Context, implicitTLS bool, config *tls.Config) (mail.DialContextFunc, func(string, string) mail.Option) {
	var tlsConn *tls.Conn
	var dialer net.Dialer
	dial := func(dialCtx context.Context, network, address string) (net.Conn, error) {
		conn, err := dialer.DialContext(dialCtx, network, address)
		if err != nil {
			return nil, err
		}
		tracked := &contextConn{Conn: conn}
		tracked.stop = context.AfterFunc(ctx, func() { _ = conn.Close() })
		if err := ctx.Err(); err != nil {
			_ = tracked.Close()
			return nil, err
		}
		if !implicitTLS {
			return tracked, nil
		}
		tlsConn = tls.Client(tracked, config.Clone())
		if err := tlsConn.HandshakeContext(dialCtx); err != nil {
			_ = tracked.Close()
			return nil, err
		}
		return tlsConn, nil
	}
	authOption := func(username, password string) mail.Option {
		return mail.WithSMTPAuthCustom(&autoAuth{username: username, password: password, tlsConn: &tlsConn})
	}
	return dial, authOption
}

type contextConn struct {
	net.Conn
	stop func() bool
	once sync.Once
	err  error
}

func (c *contextConn) Close() error {
	c.once.Do(func() {
		if c.stop != nil {
			c.stop()
		}
		c.err = c.Conn.Close()
	})
	return c.err
}

type autoAuth struct {
	username, password string
	tlsConn            **tls.Conn
	delegate           smtp.Auth
}

func (a *autoAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if server == nil {
		return "", nil, errors.New("SMTP server information unavailable")
	}
	// Match go-mail's AutoDiscover order; its implicit-TLS flag is private and
	// remains false when its custom dialer hook is used.
	prefer := []string{"SCRAM-SHA-256-PLUS", "SCRAM-SHA-256", "SCRAM-SHA-1-PLUS", "SCRAM-SHA-1", "CRAM-MD5", "PLAIN", "LOGIN"}
	if !server.TLS {
		prefer = []string{"SCRAM-SHA-256", "SCRAM-SHA-1", "CRAM-MD5"}
	}
	selected := ""
	for _, candidate := range prefer {
		for _, supported := range server.Auth {
			if candidate == supported {
				selected = candidate
				break
			}
		}
		if selected != "" {
			break
		}
	}
	if selected == "" {
		return "", nil, mail.ErrNoSupportedAuthDiscovered
	}
	var state *tls.ConnectionState
	if server.TLS && a.tlsConn != nil && *a.tlsConn != nil {
		value := (*a.tlsConn).ConnectionState()
		state = &value
	}
	switch selected {
	case "SCRAM-SHA-256-PLUS":
		if state == nil {
			return "", nil, errors.New("implicit TLS connection state unavailable")
		}
		a.delegate = smtp.ScramSHA256PlusAuth(a.username, a.password, state)
	case "SCRAM-SHA-256":
		a.delegate = smtp.ScramSHA256Auth(a.username, a.password)
	case "SCRAM-SHA-1-PLUS":
		if state == nil {
			return "", nil, errors.New("implicit TLS connection state unavailable")
		}
		a.delegate = smtp.ScramSHA1PlusAuth(a.username, a.password, state)
	case "SCRAM-SHA-1":
		a.delegate = smtp.ScramSHA1Auth(a.username, a.password)
	case "CRAM-MD5":
		a.delegate = smtp.CRAMMD5Auth(a.username, a.password)
	case "PLAIN":
		a.delegate = smtp.PlainAuth("", a.username, a.password, server.Name, false)
	case "LOGIN":
		a.delegate = smtp.LoginAuth(a.username, a.password, server.Name, false)
	default:
		return "", nil, errors.New("unsupported SMTP authentication mechanism")
	}
	return a.delegate.Start(server)
}

func (a *autoAuth) Next(challenge []byte, more bool) ([]byte, error) {
	if a.delegate == nil {
		return nil, errors.New("SMTP authentication was not started")
	}
	return a.delegate.Next(challenge, more)
}
