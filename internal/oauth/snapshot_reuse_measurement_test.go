package oauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"os"
	"reflect"
	"strings"

	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/ory/fosite"
)

// Measurement-only two-call candidate. The decoded first output owns all data;
// false-negative comparisons (e.g. int versus decoded float64) fall back safely.
// Never installed in Store or shared between transactions.
type snapshotReusePair struct {
	owned     requestRecord
	encoded   string
	calls     int
	valid     bool
	extraJSON []byte
}

func (p *snapshotReusePair) encode(r fosite.Requester) (string, error) {
	p.calls++
	if p.calls == 2 && p.valid {
		current, err := snapshotReuseProjection(r)
		if err != nil {
			return "", err
		}
		if reflect.DeepEqual(p.owned, current) {
			// DeepEqual considers -0 and +0 equal; their JSON bytes differ.
			// Compare Extra's representation too, including its full cost.
			extra, err := json.Marshal(current.Extra)
			if err == nil && bytes.Equal(extra, p.extraJSON) {
				return p.encoded, nil
			}
		}
	}
	encoded, err := encodeRequest(r)
	if p.calls == 1 && err == nil {
		p.valid = json.Unmarshal([]byte(encoded), &p.owned) == nil
		if p.valid {
			p.encoded = encoded
			extra, copyErr := json.Marshal(p.owned.Extra)
			p.extraJSON, p.valid = extra, copyErr == nil
		}
	}
	return encoded, err
}

// Mirrors the complete production projection, not just request/client identity.
// Oracle tests cover every requestRecord field and nested client field. This
// duplication is deliberately confined to this rejected/accepted experiment.
func snapshotReuseProjection(request fosite.Requester) (requestRecord, error) {
	session, ok := request.GetSession().(*fosite.DefaultSession)
	if !ok {
		return requestRecord{}, fmt.Errorf("unsupported OAuth session type %T", request.GetSession())
	}
	record := requestRecord{
		ID: request.GetID(), ClientID: request.GetClient().GetID(), RequestedAt: request.GetRequestedAt().UnixMilli(),
		RequestedScopes: append([]string(nil), request.GetRequestedScopes()...), GrantedScopes: append([]string(nil), request.GetGrantedScopes()...),
		RequestedAudience: append([]string(nil), request.GetRequestedAudience()...), GrantedAudience: append([]string(nil), request.GetGrantedAudience()...),
		Form: persistedRequestForm(request.GetRequestForm()), ExpiresAt: map[fosite.TokenType]int64{}, Username: session.Username, Subject: session.Subject, Extra: session.Extra,
	}
	if client, ok := request.GetClient().(*ephemeralClient); ok {
		snapshot := client.metadata.clone()
		record.EphemeralClient = &snapshot
	}
	if client, ok := request.GetClient().(*clients.Client); ok {
		record.ManagedClient = &managedClientRecord{ID: client.ID, Revision: client.Revision, Generation: client.Generation, Enabled: client.Enabled, Confidential: client.Confidential, RedirectURIs: append([]string(nil), client.RedirectURIs...), Scopes: append([]string(nil), client.Scopes...), DefaultScopes: append([]string(nil), client.DefaultScopes...), GrantTypes: append([]string(nil), client.GrantTypes...)}
	}
	for _, kind := range []fosite.TokenType{fosite.AuthorizeCode, fosite.AccessToken, fosite.RefreshToken} {
		if expiry := session.GetExpiresAt(kind); !expiry.IsZero() {
			record.ExpiresAt[kind] = expiry.UnixMilli()
		}
	}
	return record, nil
}

func snapshotReuseRequest(shape int, category string) *fosite.Request {
	var client fosite.Client = &fosite.DefaultClient{ID: testClientID}
	switch category {
	case "managed":
		client = &clients.Client{ID: "managed", Revision: 1, Generation: "generation", Enabled: true, RedirectURIs: []string{testRedirectURI}, Scopes: []string{"goauthy.read"}, DefaultScopes: []string{"goauthy.read"}, GrantTypes: []string{"authorization_code", "refresh_token"}}
	case "ephemeral":
		var err error
		client, err = newEphemeralClientRecord(ephemeralClientRecord{ID: "https://client.example.test/metadata", Name: "synthetic", RedirectURIs: []string{"https://client.example.test/callback"}, Scopes: []string{"goauthy.read"}, AllowedResources: []string{"https://resource.example.test"}, AllowedResourcesPresent: true})
		if err != nil {
			panic(err)
		} // Invalid fixed fixture, never external input.
	}
	r := snapshotRequest(client, shape)
	r.Form = url.Values{"grant_type": {"authorization_code"}, "scope": {r.Form.Get("scope")}, "retained_extension": {"one", "two"}, "password": {"SECRET_PASSWORD"}, "client_secret": {"SECRET_CLIENT"}}
	r.RequestedAudience = []string{"https://requested.example.test"}
	r.GrantedAudience = []string{"https://granted.example.test"}
	s := r.Session.(*fosite.DefaultSession)
	s.Username = "synthetic"
	s.Subject = "subject"
	s.SetExpiresAt(fosite.AccessToken, time.Unix(4000000000, 0))
	s.SetExpiresAt(fosite.RefreshToken, time.Unix(4000000100, 0))
	s.Extra["nested"] = map[string]interface{}{"values": []interface{}{float64(1), "value"}}
	s.Extra["zero"] = float64(0)
	return r
}

func snapshotReuseOracle(t *testing.T, r fosite.Requester, mutate func()) {
	t.Helper()
	var pair snapshotReusePair
	for i := 0; i < 2; i++ {
		if i == 1 {
			mutate()
		}
		want, werr := encodeRequest(r)
		got, gerr := pair.encode(r)
		if got != want || reflect.TypeOf(gerr) != reflect.TypeOf(werr) || fmt.Sprint(gerr) != fmt.Sprint(werr) {
			t.Fatalf("call %d byte/error oracle: equal=%v got_error=%v want_error=%v", i, got == want, gerr, werr)
		}
	}
}

func TestSnapshotReuseProjectionMutations(t *testing.T) {
	// The inventory prevents silently adding a persisted field without revisiting
	// this experiment. Client descriptors have their own field inventories below.
	if reflect.TypeOf(requestRecord{}).NumField() != 14 || reflect.TypeOf(managedClientRecord{}).NumField() != 9 || reflect.TypeOf(ephemeralClientRecord{}).NumField() != 6 {
		t.Fatal("persisted projection changed; update equivalence inventory")
	}
	mutations := map[string]func(*fosite.Request){
		"ID":                func(r *fosite.Request) { r.ID += "changed" },
		"ClientID":          func(r *fosite.Request) { r.Client.(*fosite.DefaultClient).ID += "changed" },
		"RequestedAt":       func(r *fosite.Request) { r.RequestedAt = r.RequestedAt.Add(time.Second) },
		"RequestedScopes":   func(r *fosite.Request) { r.RequestedScope[0] = "changed" },
		"GrantedScopes":     func(r *fosite.Request) { r.GrantedScope[0] = "changed" },
		"RequestedAudience": func(r *fosite.Request) { r.RequestedAudience[0] = "changed" },
		"GrantedAudience":   func(r *fosite.Request) { r.GrantedAudience[0] = "changed" },
		"Form":              func(r *fosite.Request) { r.Form["retained_extension"][0] = "changed" },
		"FormNil":           func(r *fosite.Request) { r.Form = nil },
		"FormEmpty":         func(r *fosite.Request) { r.Form = url.Values{} },
		"Transient":         func(r *fosite.Request) { r.Form["password"][0] = "DIFFERENT_SECRET" },
		"Username":          func(r *fosite.Request) { r.Session.(*fosite.DefaultSession).Username = "changed" },
		"Subject":           func(r *fosite.Request) { r.Session.(*fosite.DefaultSession).Subject = "changed" },
		"Extra": func(r *fosite.Request) {
			r.Session.(*fosite.DefaultSession).Extra["nested"].(map[string]interface{})["values"].([]interface{})[1] = "changed"
		},
		"ExtraNil":           func(r *fosite.Request) { r.Session.(*fosite.DefaultSession).Extra = nil },
		"ExtraEmpty":         func(r *fosite.Request) { r.Session.(*fosite.DefaultSession).Extra = map[string]interface{}{} },
		"ExtraError":         func(r *fosite.Request) { r.Session.(*fosite.DefaultSession).Extra["invalid"] = make(chan int) },
		"ExtraNumberType":    func(r *fosite.Request) { r.Session.(*fosite.DefaultSession).Extra["integer"] = int64(2) },
		"ExtraSignedZero":    func(r *fosite.Request) { r.Session.(*fosite.DefaultSession).Extra["zero"] = math.Copysign(0, -1) },
		"UnsupportedSession": func(r *fosite.Request) { r.Session = nil },
	}
	for _, kind := range []fosite.TokenType{fosite.AuthorizeCode, fosite.AccessToken, fosite.RefreshToken} {
		mutations["Expiry-"+string(kind)] = func(r *fosite.Request) { r.Session.SetExpiresAt(kind, time.Unix(4100000000, 0)) }
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			r := snapshotReuseRequest(0, "static")
			snapshotReuseOracle(t, r, func() { mutate(r) })
		})
	}
	for _, category := range []string{"managed", "ephemeral"} {
		count := 9
		if category == "ephemeral" {
			count = 6
		}
		for i := 0; i < count; i++ {
			t.Run(fmt.Sprintf("%s-field-%d", category, i), func(t *testing.T) {
				r := snapshotReuseRequest(0, category)
				snapshotReuseOracle(t, r, func() {
					// Only persisted fields: use descriptor field names to locate source fields.
					var source reflect.Value
					var descriptor reflect.Type
					if category == "managed" {
						source = reflect.ValueOf(r.Client).Elem()
						descriptor = reflect.TypeOf(managedClientRecord{})
					} else {
						source = reflect.ValueOf(&r.Client.(*ephemeralClient).metadata).Elem()
						descriptor = reflect.TypeOf(ephemeralClientRecord{})
					}
					field := source.FieldByName(descriptor.Field(i).Name)
					switch field.Kind() {
					case reflect.String:
						field.SetString(field.String() + "changed")
					case reflect.Bool:
						field.SetBool(!field.Bool())
					case reflect.Int64:
						field.SetInt(field.Int() + 1)
					case reflect.Slice:
						field.Index(0).SetString("changed")
					default:
						t.Fatal("unhandled persisted field")
					}
				})
			})
		}
	}
}

func TestSnapshotReusePairOwnership(t *testing.T) {
	r := snapshotReuseRequest(0, "static")
	var pair snapshotReusePair
	first, err := pair.encode(r)
	if err != nil {
		t.Fatal(err)
	}
	if !pair.valid {
		t.Fatal("owned snapshot unavailable")
	}
	projection, err := snapshotReuseProjection(r)
	if err != nil || !reflect.DeepEqual(pair.owned, projection) {
		t.Fatal("unchanged JSON-compatible projection should be eligible")
	}
	second, err := pair.encode(r)
	if err != nil || first != second {
		t.Fatal("unchanged pair diverged")
	}
	r.Session.(*fosite.DefaultSession).Extra["synthetic_claim"] = "third call"
	want, _ := encodeRequest(r)
	third, err := pair.encode(r)
	if err != nil || third != want || third == first {
		t.Fatal("reuse escaped two-call lifetime")
	}
	// First-call error must not publish a partial cache entry.
	r.Session.(*fosite.DefaultSession).Extra["invalid"] = make(chan int)
	snapshotReuseOracle(t, r, func() { delete(r.Session.(*fosite.DefaultSession).Extra, "invalid") })
}

// One case and one mode per fresh process; both calls include sanitation and all
// candidate ownership/projection/equality cost. No database/authority work is
// removed or simulated as an endpoint saving.
func BenchmarkSnapshotReusePair(b *testing.B) {
	mode, caseName := os.Getenv("SNAPSHOT112_REUSE_MODE"), os.Getenv("SNAPSHOT112_REUSE_CASE")
	if mode != "baseline" && mode != "candidate" {
		b.Skip("explicit A/B mode required")
	}
	shape, category := 0, "static"
	switch caseName {
	case "small-static":
	case "medium-static":
		shape = 1
	case "large-static":
		shape = 2
	case "medium-managed":
		shape = 1
		category = "managed"
	case "medium-ephemeral":
		shape = 1
		category = "ephemeral"
	default:
		b.Fatal("explicit case required")
	}
	r := snapshotReuseRequest(shape, category)
	b.Run(caseName+"/"+mode, func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			var pair snapshotReusePair
			for range 2 {
				request := r.Sanitize([]string{})
				var err error
				if mode == "candidate" {
					_, err = pair.encode(request)
				} else {
					_, err = encodeRequest(request)
				}
				if err != nil {
					b.Fatal(err)
				}
			}
		}
	})
}

// Exercise the actual writers' intervening work without submitting SQL. This
// proves the pair's projection for these fixtures, not HTTP/commit equivalence.
func TestSnapshotReuseActualWriterPair(t *testing.T) {
	for _, category := range []string{"static", "managed", "ephemeral"} {
		t.Run(category, func(t *testing.T) {
			r := snapshotReuseRequest(1, category)
			store := &Store{client: &fosite.DefaultClient{ID: testClientID}, now: func() time.Time { return time.Unix(1800000000, 0) }}
			ctx, err := store.BeginTX(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := configureTX(ctx, "code", "source-code"); err != nil {
				t.Fatal(err)
			}
			sanitized := r.Sanitize([]string{})
			before, err := encodeRequest(sanitized)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.CreateAccessTokenSession(ctx, "access", sanitized); err != nil {
				t.Fatal(err)
			}
			between, err := encodeRequest(r.Sanitize([]string{}))
			if err != nil || before != between {
				t.Fatal("access writer changed persisted projection")
			}
			if err := store.CreateRefreshTokenSession(ctx, "refresh", "access", r.Sanitize([]string{})); err != nil {
				t.Fatal(err)
			}
			after, err := encodeRequest(r.Sanitize([]string{}))
			if err != nil || before != after {
				t.Fatal("refresh writer changed persisted projection")
			}
			var pair snapshotReusePair
			access, err := pair.encode(r.Sanitize([]string{}))
			if err != nil {
				t.Fatal(err)
			}
			refresh, err := pair.encode(r.Sanitize([]string{}))
			if err != nil {
				t.Fatal(err)
			}
			var accessFound, refreshFound bool
			for _, statement := range txFrom(ctx).statements {
				if strings.HasPrefix(statement.SQL, "INSERT INTO oauth_token_requests ") {
					accessFound = true
					if statement.Args[1] != access {
						t.Fatal("access durable bytes differ")
					}
				}
				if strings.HasPrefix(statement.SQL, "INSERT INTO oauth_refresh_tokens") {
					refreshFound = true
					if statement.Args[3] != refresh {
						t.Fatal("refresh durable bytes differ")
					}
				}
			}
			if !accessFound || !refreshFound || access != refresh {
				t.Fatal("actual writer pair not equivalent")
			}
		})
	}
}

func TestSnapshotReuseSensitiveSet(t *testing.T) {
	r := snapshotReuseRequest(0, "static")
	// Literal inventory, independent of transientRequestFormFields and constants.
	fields := []string{"client_secret", "client_assertion", "client_assertion_type", "subject_token", "subject_token_type", "actor_token", "actor_token_type", "assertion", "code", "code_verifier", "device_code", "refresh_token", "password", "id_token_hint", "request", "request_uri", "goauthy_exchange_source_signature", "goauthy_exchange_source_expiry", "goauthy_exchange_actor_signature", "goauthy_exchange_actor_expiry"}
	for _, field := range fields {
		r.Form[field] = []string{"SECRET_SENTINEL_first", "SECRET_SENTINEL_second"}
	}
	before, _ := json.Marshal(r.Form)
	var pair snapshotReusePair
	for range 2 {
		got, err := pair.encode(r)
		if err != nil {
			t.Fatal(err)
		}
		want, err := encodeRequest(r)
		if err != nil || got != want || strings.Contains(got, "SECRET_SENTINEL") {
			t.Fatal("filtering byte/error oracle failed")
		}
	}
	after, _ := json.Marshal(r.Form)
	if !bytes.Equal(before, after) {
		t.Fatal("form mutated")
	}
}
