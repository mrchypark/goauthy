package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
)

type HTTPFactory struct {
	SlackWebhook, MatrixHomeserver, MatrixRoom, MatrixToken string
	Client                                                  *http.Client
	Email                                                   Sender
}

func (f HTTPFactory) Sender(t Target) (Sender, error) {
	kind := t.Kind
	if kind == "" {
		kind = strings.SplitN(t.Name, ":", 2)[0]
	}
	switch kind {
	case "email":
		if f.Email == nil {
			return nil, fmt.Errorf("email sender is not configured")
		}
		return f.Email, nil
	case "slack":
		u, err := secureURL(f.SlackWebhook)
		if err != nil {
			return nil, fmt.Errorf("slack webhook: %w", err)
		}
		return webhookSender{u.String(), f.Client}, nil
	case "matrix":
		u, err := secureURL(f.MatrixHomeserver)
		if err != nil {
			return nil, fmt.Errorf("matrix homeserver: %w", err)
		}
		if f.MatrixRoom == "" || f.MatrixToken == "" || strings.ContainsAny(f.MatrixRoom, "/?#") {
			return nil, fmt.Errorf("matrix room and access token are required")
		}
		return matrixSender{u, f.MatrixRoom, f.MatrixToken, f.Client}, nil
	default:
		return nil, fmt.Errorf("unknown notification target")
	}
}
func eventText(e eventlog.Event) string { b, _ := json.Marshal(e); return string(b) }

type webhookSender struct {
	URL    string
	Client *http.Client
}

func (s webhookSender) Send(ctx context.Context, e eventlog.Event) error {
	body, _ := json.Marshal(map[string]any{"text": eventText(e)})
	return postJSON(ctx, s.Client, http.MethodPost, s.URL, "", body)
}

type matrixSender struct {
	Base        *url.URL
	Room, Token string
	Client      *http.Client
}

func (s matrixSender) Send(ctx context.Context, e eventlog.Event) error {
	u := *s.Base
	u.Path = path.Join(u.Path, "_matrix/client/v3/rooms", s.Room, "send/m.room.message", e.ID)
	body, _ := json.Marshal(map[string]any{"msgtype": "m.text", "body": eventText(e)})
	return postJSON(ctx, s.Client, http.MethodPut, u.String(), s.Token, body)
}
func postJSON(ctx context.Context, client *http.Client, method, raw, token string, body []byte) error {
	if client == nil {
		client = HTTPClient(10 * time.Second)
	}
	// Preserve injected transports/certificates but never forward credentials
	// through redirects, even if the supplied client uses the stdlib default.
	boundedClient := *client
	boundedClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	req, err := http.NewRequestWithContext(ctx, method, raw, bytes.NewReader(body))
	if err != nil {
		return errorsSafe(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := boundedClient.Do(req)
	if err != nil {
		return errorsSafe(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("notification endpoint returned HTTP %s", strconv.Itoa(resp.StatusCode))
	}
	return nil
}
func errorsSafe(err error) error { return fmt.Errorf("notification request failed") }
