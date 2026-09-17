package eventlog

import "time"

// CredentialStuffingEvent records a detected credential stuffing attack.
func CredentialStuffingEvent(operationID, accountHash, ip string, distinctIPs int64, at time.Time) Event {
	return Event{
		ID:        eventID(operationID, CredentialStuffing),
		Timestamp: at.UTC().UnixMilli(),
		Level:     Critical,
		Type:      CredentialStuffing,
		IP:        &ip,
		Data:      &distinctIPs,
		Text:      &accountHash,
	}
}
