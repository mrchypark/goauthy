package eventlog

import "time"

func IssuedToken(operationID, flow, clientID, email string, level Level, at time.Time) Event {
	text := clientID + " (" + flow + ") " + email
	return Event{
		ID:        eventID(operationID, TokenIssued),
		Timestamp: at.UTC().UnixMilli(),
		Level:     level,
		Type:      TokenIssued,
		Text:      &text,
	}
}
