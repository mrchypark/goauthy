package eventlog

import "time"

// ForceLogout describes an administrator's user-wide session revocation.
// It is not emitted for ordinary RP-initiated or individual-session logout.
func ForceLogout(operationID, email string, at time.Time) Event {
	return Event{ID: eventID(operationID, ForcedLogout), Timestamp: at.UTC().UnixMilli(), Level: Notice, Type: ForcedLogout, Text: &email}
}
