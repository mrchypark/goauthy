package eventlog

import "time"

// EmailChange records a user's email address change.
func EmailChange(operationID, text string, at time.Time) Event {
	return Event{ID: eventID(operationID, UserEmailChange), Timestamp: at.UTC().UnixMilli(), Level: Notice, Type: UserEmailChange, Text: &text}
}
