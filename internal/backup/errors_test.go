package backup

import (
	"context"
	"errors"
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestFailureMessageDatabaseErrorsDoNotExposeCauses(t *testing.T) {
	for _, tc := range []struct {
		cause error
		want  string
	}{
		{errors.Join(rhiza.ErrCommitUnknown, context.DeadlineExceeded, rhiza.ErrNotReady), "database commit outcome unknown"},
		{rhiza.ErrNotReady, "database node not ready"},
		{rhiza.ErrQuorumUnavailable, "database quorum unavailable"},
		{rhiza.ErrDurabilityUnavailable, "database object-store durability unavailable"},
		{rhiza.ErrRequestConflict, "database request conflict"},
		{rhiza.ErrInvalidRequest, "database request invalid"},
		{errors.New("unrecognized provider failure"), "operation failed"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			err := errors.Join(errors.New("credential=must-not-appear"), tc.cause)
			if got := FailureMessage(err); got != tc.want {
				t.Fatalf("got %q; want %q", got, tc.want)
			}
		})
	}
}
