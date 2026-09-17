package backup

import (
	"context"
	"errors"

	"github.com/mrchypark/rhiza"
	"github.com/mrchypark/rhiza/pkg/checkpoint"
	rhizarecovery "github.com/mrchypark/rhiza/pkg/recovery"
)

// FailureMessage returns only fixed classifications; provider errors can contain secrets.
func FailureMessage(err error) string {
	// An unknown commit can wrap a timeout or availability error: retain the
	// ambiguity instead of reporting a definite failure of the mutation.
	if errors.Is(err, rhiza.ErrCommitUnknown) {
		return "database commit outcome unknown"
	}
	if errors.Is(err, context.Canceled) {
		return "operation canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "operation timed out"
	}
	for _, category := range []struct {
		cause   error
		message string
	}{
		{rhiza.ErrNotReady, "database node not ready"},
		{rhiza.ErrQuorumUnavailable, "database quorum unavailable"},
		{rhiza.ErrDurabilityUnavailable, "database object-store durability unavailable"},
		{rhiza.ErrRequestConflict, "database request conflict"},
		{rhiza.ErrInvalidRequest, "database request invalid"},
	} {
		if errors.Is(err, category.cause) {
			return category.message
		}
	}
	if errors.Is(err, rhizarecovery.ErrArchiveBusy) {
		return "archive maintenance is active"
	}
	if errors.Is(err, checkpoint.ErrPublisherBusy) {
		return "checkpoint publisher is active"
	}
	if errors.Is(err, checkpoint.ErrPublisherFenced) {
		return "checkpoint recovery pin ownership was lost"
	}
	switch err.Error() {
	case "conflicting capture":
		return "snapshot captured conflicting object versions"
	case "incomplete capture", "capture reader remains open", "capture reader already active", "capture reader is closed":
		return "snapshot capture was incomplete"
	case "capture limits exceeded", "backup limits exceeded":
		return "backup size limits exceeded"
	case "checkpoint appeared during export; retry":
		return "source checkpoint appeared during snapshot acquisition"
	case "snapshot has no certified checkpoint", "snapshot checkpoint state mismatch", "invalid snapshot archive base", "snapshot archive gap", "invalid snapshot archive range":
		return "snapshot recovery validation failed"
	case "catalog timestamp is in the future":
		return "catalog contains a future timestamp"
	case "catalog artifact mismatch", "catalog artifact size changed", "unauthorized catalog record", "invalid signed catalog record":
		return "catalog integrity validation failed"
	case "backup completion watermark changed", "invalid backup completion watermark":
		return "backup completion watermark validation failed"
	case "shared archive head changed during chain load":
		return "source archive changed during snapshot acquisition"
	case "shared archive head regressed or changed recovery base":
		return "source archive recovery boundary changed"
	}
	return "operation failed"
}
