package eventlog

import "time"

func EmailSendErrorEvent(operationID, mailType, recipient string, at time.Time) Event {
	text := mailType + " / " + recipient
	return Event{
		ID:        eventID(operationID, EmailSendError),
		Timestamp: at.UTC().UnixMilli(),
		Level:     Critical,
		Type:      EmailSendError,
		Text:      &text,
	}
}
