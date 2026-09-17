package eventlog

import "time"

func SuspiciousApiScanEvent(operationID, keyName, ip string, at time.Time) Event {
	return Event{
		ID:        eventID(operationID, SuspiciousApiScan),
		Timestamp: at.UTC().UnixMilli(),
		Level:     Warning,
		Type:      SuspiciousApiScan,
		IP:        &ip,
		Text:      &keyName,
	}
}
