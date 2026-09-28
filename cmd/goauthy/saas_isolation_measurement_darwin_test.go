//go:build goauthy_integration

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/authcollection"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/login"
	"github.com/mrchypark/goauthy/internal/loginpolicy"
	"github.com/mrchypark/goauthy/internal/oauth"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/rbac"
	"github.com/mrchypark/goauthy/internal/saas"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const isolationResource = "https://resource.example.test/connections"
const isolationPassword = "synthetic correct password 113"

// The manifest is supplied unchanged to all three fresh primary processes.
// Durations and caps are experiment controls, never production SLOs.
type isolationManifest struct {
	Version                                                        int
	PhaseSeconds, RecoverySeconds, RecoveryProbeSeconds, Inventory int
	IAMIntervalMS, SaaSIntervalMS, RequestDeadlineMS, SampleMS     int
	FaultOAuth, FaultAPI, HealthyOAuth, HealthyAPI, IAM            int
	RSSLimit, HeapLimit                                            uint64
	GoroutineLimit                                                 int
}

func isolationDefaults() isolationManifest {
	return isolationManifest{1, 16, 50, 12, 16, 1000, 1000, 3000, 100, 12, 12, 4, 4, 4, 1 << 30, 512 << 20, 1024}
}

type isolationAttempt struct {
	ID, Phase, Route, Outcome                                   string
	ScheduledNS, DispatchNS, ClientNS, HandlerNS, GetNS, PostNS int64
	Status                                                      int
	ClientDoneWhileActive                                       bool
}
type isolationTicket struct{ entered, done chan struct{} }
type isolationHandlerEvent struct {
	ID              string
	EntryNS, ExitNS int64
	Status          int
}
type isolationResponse struct {
	http.ResponseWriter
	status int
}

func (w *isolationResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *isolationResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *isolationResponse) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(data)
}

type isolationResources struct {
	ActiveHandlers        int
	ElapsedNS             int64
	Phase                 string
	Heap, TotalAlloc, RSS uint64
	Goroutines            int
	Active                [5]int
	Pools                 []saas.IsolationPoolSample
}
type isolationRun struct {
	clientFinished          chan string // deterministic accounting control only
	abort                   context.CancelFunc
	mu                      sync.Mutex
	tickets                 map[string]*isolationTicket
	cancels                 map[string]context.CancelFunc
	posts, identities, gets map[string]int
	active, peak            [5]int
	attempts                []isolationAttempt
	handlers                []isolationHandlerEvent
	samples                 []isolationResources
	violations              []string
	fixture                 *saas.IsolationFixture
	started                 time.Time
}

func (r *isolationRun) violation(s string) {
	r.mu.Lock()
	r.violations = append(r.violations, s)
	r.mu.Unlock()
}
func (r *isolationRun) observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		id := req.Header.Get("X-Measurement-ID")
		r.mu.Lock()
		ticket := r.tickets[id]
		r.mu.Unlock()
		if ticket != nil {
			close(ticket.entered)
			entry := time.Since(r.started).Nanoseconds()
			wrapped := &isolationResponse{ResponseWriter: w}
			defer func() {
				r.mu.Lock()
				r.handlers = append(r.handlers, isolationHandlerEvent{id, entry, time.Since(r.started).Nanoseconds(), wrapped.status})
				r.mu.Unlock()
				close(ticket.done)
			}()
			w = wrapped
		}
		next.ServeHTTP(w, req)
	})
}
func (r *isolationRun) reserve(class, cap int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active[class] >= cap {
		return false
	}
	r.active[class]++
	r.peak[class] = max(r.peak[class], r.active[class])
	return true
}
func (r *isolationRun) release(class int) { r.mu.Lock(); r.active[class]--; r.mu.Unlock() }

// Client completion is recorded before waiting for actual handler completion.
// The caller owns the generator reservation until this function returns.
func (r *isolationRun) request(client *http.Client, req *http.Request, id string) (*http.Response, []byte, int64, bool, error) {
	ticket := &isolationTicket{make(chan struct{}), make(chan struct{})}
	r.mu.Lock()
	r.tickets[id] = ticket
	r.mu.Unlock()
	req.Header.Set("X-Measurement-ID", id)
	begin := time.Now()
	response, err := client.Do(req)
	var data []byte
	if response != nil {
		var readErr error
		data, readErr = io.ReadAll(io.LimitReader(response.Body, 128<<10))
		if err == nil {
			err = readErr
		}
		response.Body.Close()
	}
	elapsed := time.Since(begin).Nanoseconds()
	if r.clientFinished != nil {
		r.clientFinished <- id
	}
	active := false
	select {
	case <-ticket.done:
	default:
		select {
		case <-ticket.entered:
			active = true
		default:
		}
	}
	// A failed local dispatch must not silently free a potentially active handler.
	select {
	case <-ticket.done:
	case <-time.After(8 * time.Second):
		r.violation("handler completion unobserved: " + id)
		if r.abort != nil {
			r.abort()
		}
		// Retain capacity until the handler exits, even after the watchdog fires.
		<-ticket.done
		err = fmt.Errorf("handler completion exceeded watchdog")
	}
	r.mu.Lock()
	delete(r.tickets, id)
	r.mu.Unlock()
	return response, data, elapsed, active, err
}

func (r *isolationRun) provider(w http.ResponseWriter, req *http.Request) {
	route := strings.Split(strings.TrimPrefix(req.URL.Path, "/"), "/")[0]
	w.Header().Set("Content-Type", "application/json")
	id := ""
	if strings.HasSuffix(req.URL.Path, "/token") {
		if req.Method != "POST" || req.ParseForm() != nil {
			http.Error(w, "bad fixture request", 400)
			return
		}
		id = r.fixture.IdentifySecret(req.Form.Get("refresh_token"))
		if id == "" {
			r.violation("unknown fixture token")
			http.Error(w, "invalid", 400)
			return
		}
		r.mu.Lock()
		r.posts[id]++
		cancel := r.cancels[id]
		r.mu.Unlock()
		if strings.HasPrefix(id, "mixed-oauth-cancel-") {
			if cancel == nil {
				r.violation("missing accepted-POST cancellation")
			} else {
				cancel()
			}
			<-req.Context().Done()
			return
		}
		_, _ = fmt.Fprintf(w, `{"access_token":%q,"refresh_token":"next","token_type":"Bearer","scope":"openid","expires_in":3600}`, r.fixture.AccessToken(id))
		return
	}
	id = r.fixture.IdentifySecret(strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer "))
	if id == "" {
		r.violation("unknown fixture authorization")
		http.Error(w, "invalid", 400)
		return
	}
	r.mu.Lock()
	if strings.HasSuffix(req.URL.Path, "/identity") {
		r.identities[id]++
	} else {
		r.gets[id]++
	}
	r.mu.Unlock()
	if route == "api-dial" {
		w.Header().Set("Connection", "close")
	}
	if strings.HasPrefix(id, "mixed-oauth-header-") {
		<-req.Context().Done()
		return
	}
	if strings.HasPrefix(id, "mixed-api-body-") {
		_, _ = io.WriteString(w, `{"value":"`)
		w.(http.Flusher).Flush()
		<-req.Context().Done()
		return
	}
	if strings.HasSuffix(req.URL.Path, "/identity") {
		_, _ = io.WriteString(w, `{"sub":"account"}`)
	} else {
		_, _ = io.WriteString(w, `{"value":"synthetic"}`)
	}
}

var isolationInteraction = regexp.MustCompile(`name="interaction" value="([^"]+)"`)
var isolationCSRF = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

func TestSaaSIsolation113Measurement(t *testing.T) {
	mode := os.Getenv("GOAUTHY_ISOLATION113")
	if mode == "" {
		t.Skip("opt-in standalone measurement")
	}
	manifest := isolationDefaults()
	if path := os.Getenv("GOAUTHY_ISOLATION113_MANIFEST"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(data, &manifest); err != nil {
			t.Fatal(err)
		}
	} else if mode != "pilot" && mode != "check" {
		t.Fatal("primary requires frozen manifest")
	}
	if manifest != isolationDefaults() {
		// Only resource ceilings may be reduced after the pilot.
		fixed := manifest
		defaults := isolationDefaults()
		fixed.RSSLimit = defaults.RSSLimit
		fixed.HeapLimit = defaults.HeapLimit
		fixed.GoroutineLimit = defaults.GoroutineLimit
		if fixed != defaults || manifest.RSSLimit > defaults.RSSLimit || manifest.HeapLimit > defaults.HeapLimit || manifest.GoroutineLimit > defaults.GoroutineLimit {
			t.Fatal("unsupported manifest")
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 125*time.Second)
	defer cancel()
	r := &isolationRun{abort: cancel, started: time.Now(), tickets: map[string]*isolationTicket{}, cancels: map[string]context.CancelFunc{}, posts: map[string]int{}, identities: map[string]int{}, gets: map[string]int{}}
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "isolation113", DataDir: migratedDataDir(t, "isolation113")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	keys := providerRegistryTestKeyring(t)
	hasher, err := credential.NewHasher(credential.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	identities, err := identity.NewStoreWithHasher(db, hasher)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := hasher.Hash(ctx, []byte(isolationPassword))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"owner", "iam0", "iam1", "iam2", "iam3"} {
		if _, err = identities.BootstrapUser(ctx, id, id, hash); err != nil {
			t.Fatal(err)
		}
	}
	sessions, err := browser.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	guard := func() (string, []any) {
		return `EXISTS(SELECT 1 FROM identity_users WHERE subject='owner' AND disabled=0)`, nil
	}
	managed := clients.NewStore(db, keys)
	if _, err = managed.CreateWithGuard(ctx, clients.NewRequest{ID: "consumer", RedirectURIs: []string{"https://rp.example.test/callback"}, Scopes: []string{"goauthy.connections.use"}, DefaultScopes: []string{"goauthy.connections.use"}, Audiences: []string{isolationResource}, GrantTypes: []string{"authorization_code"}}, guard); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	// Synthetic fixed peers enter through the runtime peer-context middleware.
	// This header is interpreted only by this tagged fixture.
	app := httptest.NewTLSServer(r.observe(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if p := req.Header.Get("X-Isolation-Peer"); p != "" {
			req.RemoteAddr = p + ":1234"
		}
		peerIPMiddleware(mux, nil).ServeHTTP(w, req)
	})))
	defer app.Close()
	issuer := app.URL
	signing, err := oidc.EnsureSigningKey(ctx, db, keys, issuer, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	oauthServer, err := oauth.NewServerWithOIDC(ctx, db, bytes.Repeat([]byte{9}, 32), "bootstrap", "synthetic-client-secret", "https://rp.example.test/callback", []string{isolationResource}, oauth.OIDCConfig{Issuer: issuer, LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return signing, nil }, ManagedClients: managed, ValidateSubject: identities.ValidateSubject})
	if err != nil {
		t.Fatal(err)
	}
	loginHandler, err := login.NewWithPolicy(issuer, sessions, identities, oauthServer, loginpolicy.NewStore(db))
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/account/login", loginHandler.AccountLoginHandler(false))
	provider := saas.IntegrationIsolationTLS(t, http.HandlerFunc(r.provider))
	defer provider.Close()
	f := saas.IntegrationIsolation(t, db, keys, provider, manifest.Inventory, isolationResource)
	r.fixture = f
	h, err := rbac.NewHandler(rbac.NewStore(db), sessions, identities, issuer)
	if err != nil {
		t.Fatal(err)
	}
	for _, err := range []error{h.BindSaaSProviderStore(f.Providers), h.BindSaaSCredentials(f.Credentials), h.BindAuthCollections(authcollection.NewStore(db)), h.BindConnectionUseResource(isolationResource), h.BindConnectionUseAuthorizer(func(req *http.Request) (string, string, func() (string, []any), error) {
		return oauthServer.AuthorizeConnectionUse(req, isolationResource)
	})} {
		if err != nil {
			t.Fatal(err)
		}
	}
	mux.HandleFunc("POST /refresh/{collection_id}/{connection_id}", h.AccountConnectionOAuth2Refresh)
	mux.HandleFunc("POST /invoke/{grant_id}", h.InvokeConnectionGrant)
	owner, err := sessions.CreateSession(ctx, "owner", "pwd", time.Now().Add(time.Hour), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	ownerCookie, err := browser.SessionCookie(issuer, owner.Token, owner.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	ownerCSRF, err := browser.DeriveCSRFToken(owner.Token)
	if err != nil {
		t.Fatal(err)
	}
	token := isolationBearer(t, oauthServer, issuer)
	client := app.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	makeSaaS := func(phase, route string, n int) (string, *http.Request, context.CancelFunc) {
		id := fmt.Sprintf("%s-%s-%03d", phase, route, n)
		requestCtx, stop := context.WithTimeout(ctx, time.Duration(manifest.RequestDeadlineMS)*time.Millisecond)
		path, body := "/refresh/"+route+"/"+id, `{"version":1}`
		if strings.HasPrefix(route, "api-") {
			path = "/invoke/" + f.Grants[id]
			body = `{"operation":"read"}`
		}
		req, _ := http.NewRequestWithContext(requestCtx, "POST", issuer+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if strings.HasPrefix(route, "api-") {
			req.Header.Set("Authorization", "Bearer "+token)
		} else {
			req.AddCookie(ownerCookie)
			req.Header.Set("X-CSRF-Token", ownerCSRF)
		}
		return id, req, stop
	}
	// Negative authority/CSRF controls outside primary timing, with untouched IDs.
	for i, route := range []string{"oauth-healthy", "api-healthy"} {
		id, req, stop := makeSaaS("control", route, 0)
		if i == 0 {
			req.Header.Del("X-CSRF-Token")
		} else {
			req.Header.Set("Authorization", "Bearer invalid")
		}
		res, _, _, _, err := r.request(client, req, "negative-"+id)
		stop()
		if err != nil || res == nil || res.StatusCode < 400 {
			t.Fatal("invalid authority accepted")
		}
	}
	loginFlow := func(id string, who int, password string, badCSRF bool) (isolationAttempt, *http.Cookie) {
		a := isolationAttempt{ID: id, Route: "iam"}
		begin := time.Now()
		requestCtx, stop := context.WithTimeout(ctx, 3*time.Second)
		defer stop()
		req, _ := http.NewRequestWithContext(requestCtx, "GET", issuer+"/account/login", nil)
		// Four stable trusted test peers, matching the production peer middleware.
		req.Header.Set("X-Isolation-Peer", fmt.Sprintf("203.0.113.%d", who+1))
		res, data, elapsed, _, err := r.request(client, req, id+"-get")
		a.GetNS = elapsed
		a.ClientNS = elapsed
		if res != nil {
			a.Status = res.StatusCode
		}
		if err != nil || res == nil || res.StatusCode != 200 {
			a.Outcome = "get-failed"
			return a, nil
		}
		interaction, csrf := isolationInteraction.FindSubmatch(data), isolationCSRF.FindSubmatch(data)
		if len(interaction) != 2 || len(csrf) != 2 || len(res.Cookies()) != 1 {
			a.Outcome = "form-failed"
			return a, nil
		}
		cookie := res.Cookies()[0]
		csrfText := string(csrf[1])
		if badCSRF {
			csrfText = "invalid"
		}
		form := url.Values{"interaction": {string(interaction[1])}, "csrf_token": {csrfText}, "username": {fmt.Sprintf("iam%d", who)}, "password": {password}}
		req, _ = http.NewRequestWithContext(requestCtx, "POST", issuer+"/account/login", strings.NewReader(form.Encode()))
		req.AddCookie(cookie)
		req.Header.Set("Origin", issuer)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Isolation-Peer", fmt.Sprintf("203.0.113.%d", who+1))
		postStart := time.Now()
		res, _, elapsed, active, err := r.request(client, req, id+"-post")
		a.PostNS = elapsed
		a.ClientDoneWhileActive = active
		a.ClientNS = postStart.Sub(begin).Nanoseconds() + elapsed
		a.Outcome = "client-error"
		if res != nil {
			a.Status = res.StatusCode
		}
		if err == nil && res.StatusCode == 303 && len(res.Cookies()) > 0 {
			rotated := res.Cookies()[0]
			s, e := sessions.LoadSession(ctx, rotated.Value)
			if e == nil && s.Subject == fmt.Sprintf("iam%d", who) && s.Authenticated() && rotated.Value != cookie.Value {
				a.Outcome = "success"
				return a, rotated
			}
			a.Outcome = "binding-failed"
			r.violation("incorrect login binding")
		} else if err == nil {
			a.Outcome = fmt.Sprintf("http-%d", res.StatusCode)
		}
		return a, nil
	}
	for _, control := range []struct {
		password string
		badCSRF  bool
	}{{"incorrect", false}, {isolationPassword, true}} {
		a, _ := loginFlow(fmt.Sprintf("negative-login-%t", control.badCSRF), 0, control.password, control.badCSRF)
		if a.Status != 401 && a.Status != 403 {
			t.Fatalf("login negative control: %s %d", a.Outcome, a.Status)
		}
	}
	// Positive controls validate real authenticated routes before starting load.
	for _, route := range []string{"oauth-healthy", "api-healthy"} {
		id, req, stop := makeSaaS("control", route, 0)
		res, _, _, _, err := r.request(client, req, "positive-"+id)
		stop()
		if err != nil || res == nil || res.StatusCode != 200 {
			t.Fatalf("authenticated %s control failed: status=%v error=%v", route, res.StatusCode, err)
		}
	}
	if a, _ := loginFlow("positive-login", 1, isolationPassword, false); a.Outcome != "success" {
		t.Fatalf("authenticated login control: %s %d", a.Outcome, a.Status)
	}
	// Current grant revocation must prevent dispatch after real bearer validation.
	controlID := "control-api-healthy-000"
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "control-revoke", SQL: `UPDATE saas_use_grants SET revoked=1 WHERE id=?`, Args: []any{f.Grants[controlID]}}); err != nil {
		t.Fatal(err)
	}
	id, req, stop := makeSaaS("control", "api-healthy", 0)
	res, _, _, _, err := r.request(client, req, "revoked-"+id)
	stop()
	if err != nil || res == nil || res.StatusCode < 400 {
		t.Fatal("revoked grant accepted")
	}
	if r.gets[controlID] != 1 {
		t.Fatal("revoked grant dispatched")
	}
	// A successfully consumed old version cannot issue a second token POST.
	id, req, stop = makeSaaS("control", "oauth-healthy", 0)
	res, _, _, _, err = r.request(client, req, "replay-"+id)
	stop()
	if err != nil || res == nil || res.StatusCode < 400 || r.posts[id] != 1 {
		t.Fatal("old refresh version replayed")
	}
	// Same-binding contention is a control, not primary refresh throughput.
	start := make(chan struct{})
	results := make(chan int, 2)
	for i := range 2 {
		go func() {
			<-start
			id, req, stop := makeSaaS("control", "oauth-header", 0)
			defer stop()
			response, _, _, _, err := r.request(client, req, fmt.Sprintf("contend-%d-%s", i, id))
			status := 0
			if err == nil && response != nil {
				status = response.StatusCode
			}
			results <- status
		}()
	}
	close(start)
	one, two := <-results, <-results
	if (one == 200) == (two == 200) || one == 0 || two == 0 || r.posts["control-oauth-header-000"] != 1 {
		t.Fatalf("refresh contention statuses %d/%d", one, two)
	}
	if mode == "check" {
		return
	}
	// No pending queue: each tick either reserves immediately or is recorded dropped.
	r.started = time.Now()
	r.handlers = nil // setup controls have a separate time origin
	var usageBefore, usageAfter syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &usageBefore)
	var workers sync.WaitGroup
	for _, phase := range []string{"baseline", "mixed", "recovery"} {
		f.SetMixed(phase == "mixed")
		phaseStart := time.Now()
		duration := time.Duration(manifest.PhaseSeconds) * time.Second
		if phase == "recovery" {
			duration = time.Duration(manifest.RecoverySeconds) * time.Second
		}
		end := phaseStart.Add(duration)
		nextIAM, nextSaaS, nextSample := phaseStart, phaseStart, phaseStart
		iamIndex, saasIndex := 0, 0
		for time.Now().Before(end) && ctx.Err() == nil {
			now := time.Now()
			offering := phase != "recovery" || now.Sub(phaseStart) < time.Duration(manifest.RecoveryProbeSeconds)*time.Second
			if offering && !now.Before(nextIAM) {
				scheduled := nextIAM
				nextIAM = nextIAM.Add(time.Duration(manifest.IAMIntervalMS) * time.Millisecond)
				who := iamIndex % 4
				id := fmt.Sprintf("%s-iam-%03d", phase, iamIndex)
				iamIndex++
				a := isolationAttempt{ID: id, Phase: phase, Route: "iam", ScheduledNS: scheduled.Sub(r.started).Nanoseconds(), DispatchNS: now.Sub(r.started).Nanoseconds()}
				if now.Sub(scheduled) > time.Duration(manifest.IAMIntervalMS)*time.Millisecond {
					a.Outcome = "schedule-missed"
					r.mu.Lock()
					r.attempts = append(r.attempts, a)
					r.mu.Unlock()
				} else if !r.reserve(4, manifest.IAM) {
					a.Outcome = "generator-drop"
					r.mu.Lock()
					r.attempts = append(r.attempts, a)
					r.mu.Unlock()
				} else {
					workers.Go(func() {
						defer r.release(4)
						dispatched := time.Since(r.started).Nanoseconds()
						result, _ := loginFlow(id, who, isolationPassword, false)
						result.Phase = phase
						result.ScheduledNS = a.ScheduledNS
						result.DispatchNS = dispatched
						result.HandlerNS = time.Since(r.started).Nanoseconds()
						r.mu.Lock()
						r.attempts = append(r.attempts, result)
						r.mu.Unlock()
					})
				}
			}
			if offering && !now.Before(nextSaaS) {
				scheduled := nextSaaS
				nextSaaS = nextSaaS.Add(time.Duration(manifest.SaaSIntervalMS) * time.Millisecond)
				index := saasIndex
				saasIndex++
				for ri, route := range saas.IsolationRoutes {
					if phase == "recovery" && ri != 0 && ri != 3 {
						continue
					}
					a := isolationAttempt{ID: fmt.Sprintf("%s-%s-%03d", phase, route, index), Phase: phase, Route: route, ScheduledNS: scheduled.Sub(r.started).Nanoseconds(), DispatchNS: now.Sub(r.started).Nanoseconds()}
					class, cap := 0, manifest.FaultOAuth
					if ri >= 3 {
						class, cap = 1, manifest.FaultAPI
					}
					if ri == 0 {
						class, cap = 2, manifest.HealthyOAuth
					}
					if ri == 3 {
						class, cap = 3, manifest.HealthyAPI
					}
					if index >= manifest.Inventory || now.Sub(scheduled) > time.Duration(manifest.SaaSIntervalMS)*time.Millisecond {
						a.Outcome = "schedule-missed"
					} else if !r.reserve(class, cap) {
						a.Outcome = "generator-drop"
					} else {
						id, req, stop := makeSaaS(phase, route, index)
						r.mu.Lock()
						r.cancels[id] = stop
						r.mu.Unlock()
						workers.Go(func() {
							defer r.release(class)
							defer stop()
							a.DispatchNS = time.Since(r.started).Nanoseconds()
							res, _, elapsed, active, err := r.request(client, req, id)
							a.ClientNS = elapsed
							a.HandlerNS = time.Since(r.started).Nanoseconds()
							a.ClientDoneWhileActive = active
							a.Outcome = "client-error"
							if res != nil {
								a.Status = res.StatusCode
								a.Outcome = fmt.Sprintf("http-%d", res.StatusCode)
							}
							if err == nil && res.StatusCode == 200 {
								a.Outcome = "success"
							}
							r.mu.Lock()
							r.attempts = append(r.attempts, a)
							delete(r.cancels, id)
							r.mu.Unlock()
						})
						continue
					}
					r.mu.Lock()
					r.attempts = append(r.attempts, a)
					r.mu.Unlock()
				}
			}
			if !now.Before(nextSample) {
				var mem runtime.MemStats
				runtime.ReadMemStats(&mem)
				var usage syscall.Rusage
				_ = syscall.Getrusage(syscall.RUSAGE_SELF, &usage)
				sample := isolationResources{ElapsedNS: time.Since(r.started).Nanoseconds(), Phase: phase, Heap: mem.HeapAlloc, TotalAlloc: mem.TotalAlloc, RSS: uint64(usage.Maxrss), Goroutines: runtime.NumGoroutine(), Pools: f.Pools()}
				r.mu.Lock()
				sample.Active = r.active
				for _, ticket := range r.tickets {
					select {
					case <-ticket.entered:
						select {
						case <-ticket.done:
						default:
							sample.ActiveHandlers++
						}
					default:
					}
				}
				r.samples = append(r.samples, sample)
				r.mu.Unlock()
				if sample.RSS > manifest.RSSLimit || sample.Heap > manifest.HeapLimit || sample.Goroutines > manifest.GoroutineLimit {
					r.violation("resource abort")
					cancel()
				}
				nextSample = now.Add(time.Duration(manifest.SampleMS) * time.Millisecond)
			}
			select {
			case <-ctx.Done():
			case <-time.After(5 * time.Millisecond):
			}
		}
		// Preserve every frozen arrival in the denominator even on an abort or
		// a scheduler stall. Expired arrivals are dropped, never dispatched late.
		limit := manifest.PhaseSeconds
		if phase == "recovery" {
			limit = manifest.RecoveryProbeSeconds
		}
		for ; iamIndex < limit; iamIndex++ {
			r.mu.Lock()
			r.attempts = append(r.attempts, isolationAttempt{ID: fmt.Sprintf("%s-iam-%03d", phase, iamIndex), Phase: phase, Route: "iam", Outcome: "schedule-missed", ScheduledNS: phaseStart.Add(time.Duration(iamIndex) * time.Second).Sub(r.started).Nanoseconds()})
			r.mu.Unlock()
		}
		for ; saasIndex < limit; saasIndex++ {
			for ri, route := range saas.IsolationRoutes {
				if phase == "recovery" && ri != 0 && ri != 3 {
					continue
				}
				r.mu.Lock()
				r.attempts = append(r.attempts, isolationAttempt{ID: fmt.Sprintf("%s-%s-%03d", phase, route, saasIndex), Phase: phase, Route: route, Outcome: "schedule-missed", ScheduledNS: phaseStart.Add(time.Duration(saasIndex) * time.Second).Sub(r.started).Nanoseconds()})
				r.mu.Unlock()
			}
		}
		if phase == "baseline" {
			workers.Wait()
		}
	}
	workers.Wait()
	if ctx.Err() != nil {
		r.violation("run context expired")
	}
	if len(r.attempts) != manifest.PhaseSeconds*14+manifest.RecoveryProbeSeconds*3 {
		r.violation("frozen schedule incomplete")
	}
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &usageAfter)
	// Freeze recovery observations BEFORE teardown. No forced GC or pool closure.
	finalPools := f.Pools()
	for _, p := range finalPools {
		if p.Leases != 0 || p.Dials != 0 || p.Connections != 0 {
			r.violation("natural recovery did not drain " + p.Owner)
		}
	}
	rows, err := db.Query(context.WithoutCancel(ctx), rhiza.QueryRequest{SQL: `SELECT connection_id,state,token_version FROM saas_connection_credentials ORDER BY connection_id`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		t.Fatal(err)
	}
	for id, count := range r.posts {
		if count > 1 {
			r.violation("repeated mutation " + id)
		}
	}
	for _, row := range rows.Rows {
		id, state, version := row[0].(string), row[1].(string), row[2].(int64)
		if strings.Contains(id, "-oauth-") {
			if version < 1 || version > 2 || version == 2 && (state != "ready" || r.posts[id] != 1) || version == 1 && state != "ready" && state != "refreshing" && state != "uncertain" {
				r.violation("invalid durable outcome " + id)
			}
		} else if state != "ready" || version != 1 {
			r.violation("API-key binding changed " + id)
		}
	}
	for id, count := range r.gets {
		if strings.HasPrefix(id, "mixed-api-dial-") && count != 0 {
			r.violation("connect-failure origin received a request")
		}
	}
	for _, a := range r.attempts {
		if (a.Phase == "baseline" || a.Route == "iam" || strings.HasSuffix(a.Route, "healthy")) && a.Outcome != "success" {
			r.violation("protected operation failed " + a.ID + " " + a.Outcome)
		}
	}
	result := map[string]any{"manifest": manifest, "mode": mode, "go": runtime.Version(), "gomaxprocs": runtime.GOMAXPROCS(0), "attempts": r.attempts, "samples": r.samples, "peak_workflows": r.peak, "posts": r.posts, "identities": r.identities, "gets": r.gets, "durable": rows.Rows, "final_pools": finalPools, "violations": r.violations, "cpu_user_us": isolationMicros(usageAfter.Utime) - isolationMicros(usageBefore.Utime), "cpu_system_us": isolationMicros(usageAfter.Stime) - isolationMicros(usageBefore.Stime)}
	result["handlers"] = r.handlers
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	output := os.Getenv("GOAUTHY_ISOLATION113_OUTPUT")
	if output == "" {
		t.Fatal("output required")
	}
	if len(raw) > 8<<20 {
		t.Fatal("evidence bound")
	}
	if err = os.WriteFile(filepath.Clean(output), raw, 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("synthetic attempts=%d violations=%d", len(r.attempts), len(r.violations))
	if len(r.violations) > 0 {
		t.Fail()
	}
}
func isolationMicros(v syscall.Timeval) int64 { return v.Sec*1000000 + int64(v.Usec) }

func isolationBearer(t *testing.T, s *oauth.Server, issuer string) string {
	t.Helper()
	verifier := strings.Repeat("v", 43)
	digest := sha256.Sum256([]byte(verifier))
	form := url.Values{"response_type": {"code"}, "client_id": {"consumer"}, "redirect_uri": {"https://rp.example.test/callback"}, "state": {strings.Repeat("s", 32)}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"}, "scope": {"goauthy.connections.use"}, "resource": {isolationResource}}
	w := httptest.NewRecorder()
	s.WriteAuthorization(w, httptest.NewRequest("GET", issuer+"/oidc/authorize?"+form.Encode(), nil), "owner", []string{"goauthy.connections.use"})
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil || u.Query().Get("code") == "" {
		t.Fatalf("consumer authorization failed %d", w.Code)
	}
	req := httptest.NewRequest("POST", issuer+"/oidc/token", strings.NewReader(url.Values{"client_id": {"consumer"}, "grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "redirect_uri": {"https://rp.example.test/callback"}, "code_verifier": {verifier}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	s.TokenHandler().ServeHTTP(w, req)
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &token) != nil || token.AccessToken == "" {
		t.Fatalf("consumer token failed %d", w.Code)
	}
	return token.AccessToken
}

// A deterministic generator-only control holds the handler after cancellation.
// It tests reservation lifetime without altering production refresh cleanup.
func TestIsolation113ReservationSurvivesClientCancellation(t *testing.T) {
	r := &isolationRun{tickets: map[string]*isolationTicket{}, clientFinished: make(chan string, 1)}
	entered, release := make(chan struct{}), make(chan struct{})
	app := httptest.NewServer(r.observe(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { close(entered); <-req.Context().Done(); <-release })))
	defer app.Close()
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", app.URL, nil)
	if !r.reserve(0, 1) {
		t.Fatal("initial reserve")
	}
	done := make(chan struct{})
	go func() { defer close(done); r.request(app.Client(), req, "control"); r.release(0) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("handler did not enter")
	}
	cancel()
	select {
	case <-r.clientFinished:
	case <-time.After(time.Second):
		t.Fatal("client did not finish cancellation")
	}
	if r.reserve(0, 1) {
		t.Fatal("replacement admitted before handler return")
	}
	unblock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not drain")
	}
	if !r.reserve(0, 1) {
		t.Fatal("reservation leaked")
	}
	r.release(0)
}
