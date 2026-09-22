package recovery

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/rhiza"
)

func adminCreateInput() identity.UserCreation {
	expires := time.Now().Add(time.Hour).UnixMilli()
	return identity.UserCreation{OpenRegistration: identity.OpenRegistration{
		Email: "admin-created@example.test", Language: "ko", GivenName: "Admin", TTL: time.Hour,
	}, Roles: []string{}, Groups: []string{}, UserExpires: &expires}
}

func TestCreateUserSendsFirstPasswordMailAfterCommit(t *testing.T) {
	t.Parallel()
	service, sender := testService(t, "subject-1", "alice")
	result, err := service.CreateUser(context.Background(), adminCreateInput(), "1=1", nil)
	if err != nil || !result.Created || result.Subject == "" || result.Token == "" {
		t.Fatalf("create result=%#v err=%v", result, err)
	}
	messages := sender.passwordNewMessages()
	if len(messages) != 1 || messages[0].To != "admin-created@example.test" || messages[0].Language != "ko" || messages[0].ResetURL == "" {
		t.Fatalf("first-password messages=%#v", messages)
	}
}

func TestCreateUserDeliveryFailurePreservesSuccess(t *testing.T) {
	t.Parallel()
	service, sender := testService(t, "subject-1", "alice")
	deliveryErr := errors.New("smtp unavailable")
	sender.err = deliveryErr
	var reported error
	service.OnError = func(err error) { reported = err }
	callbackCalls := 0
	callbackSubjectExists := false
	service.OnUserCreated = func() {
		callbackCalls++
		rows, err := service.db.Query(context.Background(), rhiza.QueryRequest{
			SQL: `SELECT COUNT(*) FROM identity_users WHERE username=?`, Args: []any{"admin-created@example.test"}, Consistency: rhiza.ConsistencyLinearizable,
		})
		callbackSubjectExists = err == nil && len(rows.Rows) == 1 && rows.Rows[0][0] == int64(1)
	}
	result, err := service.CreateUser(context.Background(), adminCreateInput(), "1=1", nil)
	if err != nil || !result.Created || !errors.Is(reported, deliveryErr) {
		t.Fatalf("create result=%#v err=%v reported=%v", result, err, reported)
	}
	if callbackCalls != 1 || !callbackSubjectExists {
		t.Fatalf("created callback calls=%d committed=%t", callbackCalls, callbackSubjectExists)
	}
	if len(sender.passwordNewMessages()) != 1 {
		t.Fatalf("password-new messages=%d, want 1", len(sender.passwordNewMessages()))
	}
}

func TestCreateUserAuthorityFailureDoesNotSendMail(t *testing.T) {
	t.Parallel()
	service, sender := testService(t, "subject-1", "alice")
	callbackCalls := 0
	service.OnUserCreated = func() { callbackCalls++ }
	result, err := service.CreateUser(context.Background(), adminCreateInput(), "0", nil)
	if err == nil || result.Created || len(sender.passwordNewMessages()) != 0 || callbackCalls != 0 {
		t.Fatalf("authority failure result=%#v err=%v messages=%d callbacks=%d", result, err, len(sender.passwordNewMessages()), callbackCalls)
	}
}
