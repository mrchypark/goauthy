package eventlog

import (
	"net/netip"
	"time"
)

// LoginRevoke records a user revoking an illegal login.
func LoginRevoke(operationID, email string, badIP netip.Addr, location *string, at time.Time) Event {
	loc := "Unknown Location"
	if location != nil {
		loc = *location
	}
	text := "User `" + email + "` revoked illegal login from " + badIP.String() + " (" + loc + ")"
	ip := badIP.String()
	return Event{ID: eventID(operationID, UserLoginRevoke), Timestamp: at.UTC().UnixMilli(), Level: Warning, Type: UserLoginRevoke, IP: &ip, Text: &text}
}
