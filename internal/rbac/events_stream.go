package rbac

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/rhiza"
)

const eventStreamIOTimeout = 5 * time.Second

// EventsStream implements the Rauthy SSE wire format. A durable commit cursor,
// not the wall clock or an at-most-once notification, controls progression.
func (h *Handler) EventsStream(w http.ResponseWriter, r *http.Request) {
	h.securityHeaders(w)
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.crossSite(r) {
		h.genericUnauthorized(w)
		return
	}
	actor, key, ok := h.principalFor(w, r, false, "Events", apikey.Read, true)
	if !ok {
		return
	}
	latest, level, err := eventStreamQuery(r)
	if err != nil {
		h.badRequest(w)
		return
	}
	// This is a resource limit, not an IP identity map: multiple authorized
	// clients behind the same NAT do not replace each other's subscriptions.
	if h.eventStreams.Add(1) > 64 {
		h.eventStreams.Add(-1)
		w.Header().Set("Retry-After", "10")
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	defer h.eventStreams.Add(-1)
	guard, err := h.eventReadGuard(r, actor, key)
	if err != nil {
		h.genericUnauthorized(w)
		return
	}
	store, err := eventlog.NewStore(h.store.db)
	if err != nil {
		h.unavailable(w)
		return
	}
	cursor := int64(-1)
	if lastID := r.Header.Get("Last-Event-ID"); lastID != "" {
		ctx, cancel := context.WithTimeout(r.Context(), eventStreamIOTimeout)
		defer cancel()
		seq, err := store.SequenceForID(ctx, lastID)
		if err != nil {
			h.unavailable(w)
			return
		}
		if seq >= 0 {
			cursor = seq
		}
	}
	read := func(c int64) (eventlog.StreamPage, error) {
		ctx, cancel := context.WithTimeout(r.Context(), eventStreamIOTimeout)
		defer cancel()
		condition, args := guard()
		return store.StreamPageGuarded(ctx, c, latest, level, condition, args...)
	}
	if h.beforeEventRead != nil {
		h.beforeEventRead()
	}
	page, err := read(cursor)
	if err != nil {
		h.unavailable(w)
		return
	}
	if !page.Authorized {
		h.error(w, http.StatusForbidden, "Forbidden")
		return
	}
	controller := http.NewResponseController(w)
	if err := controller.SetWriteDeadline(time.Now().Add(eventStreamIOTimeout)); err != nil {
		h.unavailable(w)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	write := func(frame string) bool {
		if r.Context().Err() != nil || controller.SetWriteDeadline(time.Now().Add(eventStreamIOTimeout)) != nil {
			return false
		}
		if _, err := io.WriteString(w, frame); err != nil {
			return false
		}
		if controller.Flush() != nil {
			return false
		}
		// Bound an actual write, not the idle interval (HTTP/2 deadlines can
		// actively reset a stream even when no write is currently pending).
		return controller.SetWriteDeadline(time.Time{}) == nil
	}
	if !write("retry: 10000\n\n") {
		return
	}
	// ponytail: O(streams) idle reads, capped at 64/node; add shared Notify
	// wakeups only if needed, retaining reconciliation for dropped notifications.
	poll := time.NewTicker(time.Second)
	defer poll.Stop()
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		for _, event := range page.Events {
			// Refresh both the clock and authority immediately before each frame;
			// a large initial history must not cache permission for its duration.
			if !h.eventStreamAuthorized(r.Context(), guard) {
				return
			}
			payload, err := json.Marshal(event)
			if err != nil || !write("id: "+event.ID+"\ndata: "+string(payload)+"\n\n") {
				return
			}
		}
		cursor := page.Cursor
		if !page.More {
			select {
			case <-r.Context().Done():
				return
			case <-poll.C:
			case <-heartbeat.C:
				if !h.eventStreamAuthorized(r.Context(), guard) || !write(": keep-alive\n\n") {
					return
				}
			}
		}
		page, err = read(cursor)
		if err != nil || !page.Authorized {
			return // Headers already sent: close, never mix a JSON error into SSE.
		}
	}
}

func eventStreamQuery(r *http.Request) (int, eventlog.Level, error) {
	if r.ContentLength != 0 || len(r.URL.RawQuery) > int(adminRequestLimit) {
		return 0, "", errors.New("invalid event stream request")
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return 0, "", err
	}
	latest, level := 0, eventlog.Info
	for name, values := range query {
		if len(values) != 1 || values[0] == "" {
			return 0, "", errors.New("invalid event stream parameter")
		}
		switch name {
		case "latest":
			for _, digit := range values[0] {
				if digit < '0' || digit > '9' {
					return 0, "", errors.New("invalid latest")
				}
			}
			n, err := strconv.ParseUint(values[0], 10, 16)
			if err != nil || n > 1000 {
				return 0, "", errors.New("invalid latest")
			}
			latest = int(n)
		case "level":
			level = eventlog.Level(values[0])
			if !level.Valid() {
				return 0, "", errors.New("invalid event level")
			}
		default:
			return 0, "", errors.New("unknown event stream parameter")
		}
	}
	return latest, level, nil
}

// The closure retains identity, not permission or a frozen authorization clock.
func (h *Handler) eventReadGuard(r *http.Request, actor string, key *apikey.Principal) (func() (string, []any), error) {
	if key != nil {
		return func() (string, []any) { return h.store.apiKeys.AuthorizationGuard(*key, "Events", apikey.Read) }, nil
	}
	name, err := browser.CookieName(h.issuer)
	if err != nil {
		return nil, err
	}
	cookie, err := r.Cookie(name)
	if err != nil {
		return nil, err
	}
	peer := browser.PeerIPFromContext(r.Context())
	session, err := h.browser.LoadSessionReadOnlyForPeer(r.Context(), cookie.Value, peer)
	if err != nil || !session.Authenticated() || session.Subject != actor {
		return nil, errors.New("invalid event reader")
	}
	return func() (string, []any) {
		condition, args := h.browser.SessionAuthorizationGuard(session, peer)
		return "(" + adminGuard() + " OR " + delegatedAdminGuard() + ") AND " + condition, append([]any{actor, actor}, args...)
	}, nil
}

func (h *Handler) eventStreamAuthorized(parent context.Context, guard func() (string, []any)) bool {
	ctx, cancel := context.WithTimeout(parent, eventStreamIOTimeout)
	defer cancel()
	condition, args := guard()
	result, err := h.store.db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT 1 WHERE " + condition, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	return err == nil && len(result.Rows) == 1
}
