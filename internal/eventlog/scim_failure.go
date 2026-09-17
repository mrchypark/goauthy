package eventlog

import "time"

// ScimFailure records a terminal SCIM reconciliation attempt.
func ScimFailure(operationID, clientID, action string, attempts int64, at time.Time) Event {
	text := clientID + " / " + action
	return Event{ID: eventID(operationID, ScimTaskFailed), Timestamp: at.UTC().UnixMilli(), Level: Critical, Type: ScimTaskFailed, Data: &attempts, Text: &text}
}
