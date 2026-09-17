package eventlog

import (
	"net/netip"
	"time"
)

// NewLoginLocation describes the first observation of a login location.
func NewLoginLocation(operationID, email, userAgent string, ip netip.Addr, location *string, at time.Time) Event {
	text := email + " / " + userAgent
	if location != nil {
		text += " / " + *location
	}
	address := ip.String()
	return Event{ID: eventID(operationID, LoginNewLocation), Timestamp: at.UTC().UnixMilli(), Level: Warning, Type: LoginNewLocation, IP: &address, Text: &text}
}
