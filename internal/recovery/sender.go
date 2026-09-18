// Package recovery serves password-recovery delivery and HTTP boundaries.
package recovery

import (
	"context"
	"time"
)

// Message contains a public, one-time password link delivered to one canonical
// email. Senders must not log ResetURL because it contains a bearer token.
type Message struct {
	To        string
	Language  string
	ResetURL  string
	ExpiresAt time.Time
}

// Sender delivers password messages. The event-specific methods prevent a
// new-account link from accidentally using reset-mail copy.
type Sender interface {
	SendPasswordReset(context.Context, Message) error
	SendPasswordNew(context.Context, Message) error
	SendAlreadyRegistered(context.Context, Message) error
	SendEmailChange(context.Context, EmailChangeMessage) error
}
