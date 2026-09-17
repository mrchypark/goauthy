package oauth

import (
	"net/http"
	"strings"
	"testing"
)

func TestForwardAuthHeadersOverwriteSpoofedValuesAndCanonicalize(t *testing.T) {
	headers := http.Header{
		"x-forwarded-user":        {"attacker"},
		"X-FORWARDED-USER-ROLES":  {"attacker-role"},
		"X-Forwarded-User-Groups": {"attacker-group"},
		"X-Forwarded-User-Email":  {"attacker@example.test"},
		"X-Unmanaged":             {"preserve"},
	}
	identity := ForwardAuthIdentity{
		Subject:       " user-1 ",
		Roles:         []string{"writer", "admin", "writer"},
		Groups:        []string{"zeta", "alpha"},
		Email:         " alice@example.test ",
		EmailVerified: true,
		FamilyName:    "Example",
		GivenName:     "Alice",
	}
	identity.MFAEnabled = true
	identity.PreferredUsername = "alice"
	if err := ApplyForwardAuthHeaders(headers, identity, true); err != nil {
		t.Fatal(err)
	}
	if got := headers.Get(ForwardAuthUserHeader); got != "user-1" {
		t.Fatalf("user=%q", got)
	}
	if got := headers.Get(ForwardAuthRolesHeader); got != "admin,writer" {
		t.Fatalf("roles=%q", got)
	}
	if got := headers.Get(ForwardAuthGroupsHeader); got != "alpha,zeta" {
		t.Fatalf("groups=%q", got)
	}
	if got := headers.Get(ForwardAuthEmailHeader); got != "alice@example.test" {
		t.Fatalf("email=%q", got)
	}
	if headers.Get(ForwardAuthEmailVerifiedHeader) != "true" || headers.Get(ForwardAuthMFAHeader) != "true" {
		t.Fatalf("boolean headers=%v", headers)
	}
	if got := headers.Get(ForwardAuthPreferredUsernameHeader); got != "alice" {
		t.Fatalf("preferred username=%q", got)
	}
	identity.PreferredUsername = ""
	if err := ApplyForwardAuthHeaders(headers, identity, true); err != nil {
		t.Fatal(err)
	}
	if headers.Get(ForwardAuthPreferredUsernameHeader) != "" {
		t.Fatalf("stale preferred username=%v", headers)
	}
	if headers.Get("X-Unmanaged") != "preserve" {
		t.Fatalf("unmanaged header changed: %v", headers)
	}
}

func TestForwardAuthHeadersDisabledClearsAllManagedNames(t *testing.T) {
	headers := make(http.Header)
	for i, name := range managedForwardAuthHeaders {
		if i%2 == 0 {
			headers[strings.ToLower(name)] = []string{"spoof"}
		} else {
			headers[name] = []string{"spoof"}
		}
	}
	headers.Set("X-Unmanaged", "preserve")
	if err := ApplyForwardAuthHeaders(headers, ForwardAuthIdentity{}, false); err != nil {
		t.Fatal(err)
	}
	for _, name := range managedForwardAuthHeaders {
		for key := range headers {
			if strings.EqualFold(key, name) {
				t.Fatalf("managed header %q survived as %q", name, key)
			}
		}
	}
	if headers.Get("X-Unmanaged") != "preserve" {
		t.Fatalf("unmanaged header changed: %v", headers)
	}
}

func TestForwardAuthHeadersRejectHostileIdentityAndClear(t *testing.T) {
	for name, identity := range map[string]ForwardAuthIdentity{
		"crlf":           {Subject: "user\r\nX-Evil: 1"},
		"control":        {Subject: "user\x7f"},
		"invalid":        {Subject: string([]byte{0xff})},
		"oversize":       {Subject: strings.Repeat("u", maxForwardAuthHeaderValueBytes+1)},
		"hostile_role":   {Subject: "user", Roles: []string{"ok\nno"}},
		"ambiguous_role": {Subject: "user", Roles: []string{"admin,root"}},
	} {
		t.Run(name, func(t *testing.T) {
			headers := http.Header{}
			for i, managed := range managedForwardAuthHeaders {
				if i%2 == 0 {
					headers[strings.ToLower(managed)] = []string{"spoof"}
				} else {
					headers[managed] = []string{"spoof"}
				}
			}
			if err := ApplyForwardAuthHeaders(headers, identity, true); err == nil {
				t.Fatal("hostile identity accepted")
			}
			for _, managed := range managedForwardAuthHeaders {
				for key := range headers {
					if strings.EqualFold(key, managed) {
						t.Fatalf("spoofed header survived as %q: %v", key, headers)
					}
				}
			}
		})
	}
}

func TestForwardAuthHeadersMissingSubjectAndNilHeaderFailClosed(t *testing.T) {
	headers := http.Header{}
	headers.Set(ForwardAuthUserHeader, "spoof")
	if err := ApplyForwardAuthHeaders(headers, ForwardAuthIdentity{}, true); err == nil {
		t.Fatal("missing subject accepted")
	}
	if len(headers) != 0 {
		t.Fatalf("headers=%v", headers)
	}
	if err := ApplyForwardAuthHeaders(nil, ForwardAuthIdentity{Subject: "user"}, true); err == nil {
		t.Fatal("nil header accepted")
	}
}
