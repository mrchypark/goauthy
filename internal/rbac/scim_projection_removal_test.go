package rbac

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/scim"
)

// rbacRemovalTarget is one local entity whose SCIM projection is removed.
type rbacRemovalTarget struct {
	kind       string
	externalID string
	display    string
	remove     func() error
}

func rbacRemovalTargets(ctx context.Context, store *Store, group, role Entity) []rbacRemovalTarget {
	return []rbacRemovalTarget{
		{kind: "group", externalID: identity.SCIMGroupExternalID("group", group.ID), display: group.Name, remove: func() error {
			return store.DeleteGroup(ctx, "admin", group.ID, group.Revision)
		}},
		{kind: "role", externalID: identity.SCIMGroupExternalID("role", role.ID), display: role.Name, remove: func() error {
			return store.DeleteRole(ctx, "admin", role.ID, role.Revision)
		}},
	}
}

// TestDeleteRejectsStaleProjectionOverwrite covers the first GA66-SCIM-001
// schedule: a projection pass snapshots the local entity and delivers its sync,
// the local deletion commits a provider-scoped remote delete, and the paused
// projection then offers that same stale sync. Admission is bound to the live
// local entity, so the stale offer cannot repoint the row, and a restarted
// worker delivers the deletion alone. Roles share the same helper.
func TestDeleteRejectsStaleProjectionOverwrite(t *testing.T) {
	ctx, store, db := rbacTestStore(t)
	insertActive(t, db, "admin")
	if _, err := store.EnsureBootstrapPrincipal(ctx, "admin", nil, nil); err != nil {
		t.Fatal(err)
	}
	group, err := store.CreateGroup(ctx, "admin", "team/a", nil)
	if err != nil {
		t.Fatal(err)
	}
	role, err := store.CreateRole(ctx, "admin", "viewer", nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.UnixMilli(1_700_000_000_000).UTC()
	queue := scim.NewOutbox(db, func(context.Context, string) (scim.Reconciler, error) {
		return rbacSCIMReconciler(func(context.Context, scim.Request) (scim.Result, error) {
			return scim.Result{Action: scim.ActionCreated, RemoteID: "remote-group"}, nil
		}), nil
	}, scim.OutboxConfig{Random: bytes.NewReader(bytes.Repeat([]byte{7}, 512))})
	for _, target := range rbacRemovalTargets(ctx, store, group, role) {
		// The projection is the durable evidence that a remote group exists.
		if _, err := queue.EnqueueGroup(ctx, "provider", scim.Group{ExternalID: target.externalID, DisplayName: target.display}, now); err != nil {
			t.Fatalf("%s projection: %v", target.kind, err)
		}
		if err := queue.Step(ctx, now); err != nil {
			t.Fatalf("%s sync: %v", target.kind, err)
		}
		if err := target.remove(); err != nil {
			t.Fatalf("%s deletion: %v", target.kind, err)
		}
		removal, found, err := queue.LookupGroup(ctx, "provider", target.externalID)
		if err != nil || !found || removal.Status != "pending" || !removal.Request.Delete || removal.Request.DeletePolicy != scim.DeleteRemote {
			t.Fatalf("%s removal=%+v found=%v err=%v", target.kind, removal, found, err)
		}
		// The paused projection resumes with the snapshot it took before the
		// deletion. It must not repoint the row back at a sync.
		if _, err := queue.EnqueueGroup(ctx, "provider", scim.Group{ExternalID: target.externalID, DisplayName: target.display}, now.Add(time.Second)); !errors.Is(err, scim.ErrOutboxStale) {
			t.Fatalf("%s stale projection err=%v", target.kind, err)
		}
		current, found, err := queue.LookupGroup(ctx, "provider", target.externalID)
		if err != nil || !found || !current.Request.Delete || current.Request.DeletePolicy != scim.DeleteRemote || current.Revision != removal.Revision {
			t.Fatalf("%s overwritten=%+v found=%v err=%v", target.kind, current, found, err)
		}
		var delivered []scim.Request
		worker := scim.NewOutbox(db, func(context.Context, string) (scim.Reconciler, error) {
			return rbacSCIMReconciler(func(_ context.Context, request scim.Request) (scim.Result, error) {
				delivered = append(delivered, request)
				return scim.Result{Action: scim.ActionDeleted, RemoteID: "remote-group"}, nil
			}), nil
		}, scim.OutboxConfig{Random: bytes.NewReader(bytes.Repeat([]byte{8}, 512))})
		if err := worker.Step(ctx, now.Add(2*time.Second)); err != nil {
			t.Fatalf("%s restart step: %v", target.kind, err)
		}
		if len(delivered) != 1 || !delivered[0].Delete || delivered[0].Group.ExternalID != target.externalID || delivered[0].DeletePolicy != scim.DeleteRemote || len(delivered[0].Group.Members) != 0 {
			t.Fatalf("%s delivered=%+v", target.kind, delivered)
		}
	}
}

// TestDeleteSupersedesProjectionAdmittedDuringDeletion covers the second
// GA66-SCIM-001 schedule: an earlier queue read sees no projection for the
// entity, and the first projection lands before the deletion transaction
// commits. The removal statement is unconditional and guarded by the deletion
// itself, so a projection present when the deletion executes is superseded, and
// a restarted worker delivers the deletion alone. Roles share the same helper.
func TestDeleteSupersedesProjectionAdmittedDuringDeletion(t *testing.T) {
	ctx, store, db := rbacTestStore(t)
	insertActive(t, db, "admin")
	if _, err := store.EnsureBootstrapPrincipal(ctx, "admin", nil, nil); err != nil {
		t.Fatal(err)
	}
	group, err := store.CreateGroup(ctx, "admin", "team/a", nil)
	if err != nil {
		t.Fatal(err)
	}
	role, err := store.CreateRole(ctx, "admin", "viewer", nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.UnixMilli(1_700_000_000_000).UTC()
	queue := scim.NewOutbox(db, nil, scim.OutboxConfig{Random: bytes.NewReader(bytes.Repeat([]byte{7}, 512))})
	for _, target := range rbacRemovalTargets(ctx, store, group, role) {
		var interposed error
		projected := false
		// The seam is the exact window between the deletion's earlier reads and
		// its replicated transaction: the entity is still live here, so the
		// projection pass admits this first projection of it.
		store.beforeDeleteExecute = func() {
			store.beforeDeleteExecute = nil
			_, interposed = queue.EnqueueGroup(ctx, "provider", scim.Group{ExternalID: target.externalID, DisplayName: target.display}, now)
			projected = true
		}
		removeErr := target.remove()
		store.beforeDeleteExecute = nil
		if removeErr != nil {
			t.Fatalf("%s deletion: %v", target.kind, removeErr)
		}
		if !projected {
			t.Fatalf("%s deletion did not reach the interposition seam", target.kind)
		}
		if interposed != nil {
			t.Fatalf("%s interposed projection: %v", target.kind, interposed)
		}
		job, found, err := queue.LookupGroup(ctx, "provider", target.externalID)
		if err != nil || !found || job.Status != "pending" || !job.Request.Delete || job.Request.DeletePolicy != scim.DeleteRemote || job.Revision != 2 {
			t.Fatalf("%s superseded projection=%+v found=%v err=%v", target.kind, job, found, err)
		}
		var delivered []scim.Request
		worker := scim.NewOutbox(db, func(context.Context, string) (scim.Reconciler, error) {
			return rbacSCIMReconciler(func(_ context.Context, request scim.Request) (scim.Result, error) {
				delivered = append(delivered, request)
				return scim.Result{Action: scim.ActionDeleted, RemoteID: "remote-group"}, nil
			}), nil
		}, scim.OutboxConfig{Random: bytes.NewReader(bytes.Repeat([]byte{8}, 512))})
		if err := worker.Step(ctx, now.Add(2*time.Second)); err != nil {
			t.Fatalf("%s restart step: %v", target.kind, err)
		}
		if len(delivered) != 1 || !delivered[0].Delete || delivered[0].Group.ExternalID != target.externalID || delivered[0].DeletePolicy != scim.DeleteRemote {
			t.Fatalf("%s delivered=%+v", target.kind, delivered)
		}
	}
}
