package eventlog

import "time"

func SuspiciousApiScanEvent(operationID, keyName, ip string, at time.Time) Event {
	var peerIP *string
	if ip != "" {
		peerIP = &ip
	}
	return Event{
		ID:        eventID(operationID, SuspiciousApiScan),
		Timestamp: at.UTC().UnixMilli(),
		Level:     Warning,
		Type:      SuspiciousApiScan,
		IP:        peerIP,
		Text:      &keyName,
	}
}
