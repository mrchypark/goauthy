package recovery

import (
	"context"
	"sync"
	"testing"
)

func TestIssueForSubjectDeliversToRegisteredEmail(t *testing.T) {
	service, sender := testService(t, "subject-1", "alice")
	if err := service.BindEmail(context.Background(), "subject-1", "alice@example.test"); err != nil {
		t.Fatal(err)
	}
	if err := service.IssueForSubject(context.Background(), "subject-1"); err != nil {
		t.Fatal(err)
	}
	messages := sender.messages()
	if len(messages) != 1 || messages[0].To != "alice@example.test" || messages[0].ExpiresAt.IsZero() {
		t.Fatalf("messages=%#v", messages)
	}
}

func TestIssueForSubjectMissingRegistrationDoesNotDeliver(t *testing.T) {
	service, sender := testService(t, "subject-1", "alice")
	if err := service.IssueForSubject(context.Background(), "subject-1"); err != nil {
		t.Fatal(err)
	}
	if got := sender.messages(); len(got) != 0 {
		t.Fatalf("messages=%#v", got)
	}
}

func TestIssueForSubjectConcurrentDifferentSubjects(t *testing.T) {
	service, sender := testService(t, "subject-1", "alice")
	ctx := context.Background()
	if err := service.BindEmail(ctx, "subject-1", "alice@example.test"); err != nil {
		t.Fatal(err)
	}
	if err := service.BindEmail(ctx, "subject-2", "bob@example.test"); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errs := make(chan error, 2)
	var group sync.WaitGroup
	for _, subject := range []string{"subject-1", "subject-2"} {
		group.Add(1)
		go func(subject string) {
			defer group.Done()
			<-start
			errs <- service.IssueForSubject(ctx, subject)
		}(subject)
	}
	close(start)
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	messages := sender.messages()
	if len(messages) != 2 {
		t.Fatalf("messages=%#v", messages)
	}
}
