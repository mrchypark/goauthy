package rbac

import (
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func userUpdateRequest(body, query, contentType string) *http.Request {
	r := httptest.NewRequest(http.MethodPut, "/auth/v1/users/user"+query, strings.NewReader(body))
	r.Header.Set("Content-Type", contentType)
	return r
}

func TestDecodeUserUpdateBoundaries(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"email": "x@example.test", "roles": []string{}, "enabled": false, "email_verified": false}
	}
	for _, field := range []string{"email", "roles", "enabled", "email_verified"} {
		for _, absent := range []bool{false, true} {
			body := base()
			if absent {
				delete(body, field)
			} else {
				body[field] = nil
			}
			raw, _ := json.Marshal(body)
			if _, err := decodeUserUpdate(httptest.NewRecorder(), userUpdateRequest(string(raw), "", "application/json")); err == nil {
				t.Fatalf("required field %s accepted (absent=%t)", field, absent)
			}
		}
	}
	for _, tc := range []struct {
		name, key string
		value     any
		wantError bool
	}{
		{"password max runes", "password", strings.Repeat("é", 256), false},
		{"policy checked later", "password", "", false},
		{"expiry max safe seconds", "user_expires", int64(math.MaxInt64 / 1000), false},
		{"expiry fractional", "user_expires", 1719784800.5, true},
		{"role scalar", "roles", "viewer", true},
		{"role null item", "roles", []any{nil}, true},
		{"group null item", "groups", []any{nil}, true},
		{"groups scalar", "groups", "team/a", true},
		{"profile scalar", "user_values", "profile", true},
		{"profile array", "user_values", []any{}, true},
		{"profile number", "user_values", map[string]any{"city": 1}, true},
		{"profile fields null", "user_values", map[string]any{"city": nil, "zip": nil}, false},
		{"city Unicode whitespace", "user_values", map[string]any{"city": "New\u00a0York"}, false},
		{"street Unicode whitespace", "user_values", map[string]any{"street": "Main\u2003Street"}, false},
		{"empty ZIP forbidden upstream", "user_values", map[string]any{"zip": ""}, true},
		{"ZIP max", "user_values", map[string]any{"zip": strings.Repeat("A", 24)}, false},
		{"ZIP too long", "user_values", map[string]any{"zip": strings.Repeat("A", 25)}, true},
		{"date syntax only upstream", "user_values", map[string]any{"birthdate": "2000-99-99"}, false},
		{"invalid timezone", "user_values", map[string]any{"tz": "Not/AZone"}, true},
		{"empty timezone", "user_values", map[string]any{"tz": ""}, true},
		{"oversized field", "password", strings.Repeat("a", int(adminRequestLimit)), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := base()
			body[tc.key] = tc.value
			raw, _ := json.Marshal(body)
			_, err := decodeUserUpdate(httptest.NewRecorder(), userUpdateRequest(string(raw), "", "application/json"))
			if (err != nil) != tc.wantError {
				t.Fatalf("err=%v wantError=%t", err, tc.wantError)
			}
		})
	}
	valid, _ := json.Marshal(base())
	for _, raw := range []string{string(valid) + `{}`, `[]`, `null`, `{"email":"x@example.test","roles":[],"enabled":true,"email_verified":false,"\u0065nabled":false}`} {
		if _, err := decodeUserUpdate(httptest.NewRecorder(), userUpdateRequest(raw, "", "application/json")); err == nil {
			t.Fatal("ambiguous JSON accepted")
		}
	}
	r := userUpdateRequest(string(valid), "", "application/json")
	r.Header.Add("Content-Type", "application/json")
	if _, err := decodeUserUpdate(httptest.NewRecorder(), r); err == nil {
		t.Fatal("duplicate content type accepted")
	}
	got, err := decodeUserUpdate(httptest.NewRecorder(), userUpdateRequest(string(valid), "", "application/json; charset=utf-8"))
	if err != nil || got.Enabled || got.EmailVerified || got.Language != nil || got.UserValues != nil || got.Groups != nil || got.UserExpires != nil || got.Password != nil || got.GivenName != nil || got.FamilyName != nil {
		t.Fatalf("omitted values not preserved: %+v err=%v", got, err)
	}
}

func TestDecodeUserUpdate(t *testing.T) {
	valid := `{"email":"New@Example.TEST","given_name":"José Name","language":"en","password":"päss","roles":["viewer"],"groups":["team/a"],"enabled":false,"email_verified":true,"user_expires":1719784800,"user_values":{"birthdate":"2000-01-02","phone":"+821012345678","street":"1 Main-Street","zip":"12345","city":"Seoul","country":"Korea","tz":"Asia/Seoul"}}`
	tests := []struct {
		name    string
		body    string
		query   string
		ctype   string
		wantErr bool
	}{
		{"valid", valid, "", "application/json", false},
		{"required false accepted", `{"email":"x@example.test","roles":[],"enabled":false,"email_verified":false}`, "", "application/json", false},
		{"optional omitted", `{"email":"x@example.test","roles":[],"enabled":true,"email_verified":false}`, "", "application/json", false},
		{"optional null", `{"email":"x@example.test","given_name":null,"language":null,"password":null,"groups":null,"user_expires":null,"user_values":null,"roles":[],"enabled":true,"email_verified":false}`, "", "application/json", false},
		{"unknown top-level", `{"email":"x@example.test","roles":[],"enabled":true,"email_verified":false,"preferred_username":"x"}`, "", "application/json", true},
		{"unknown nested", `{"email":"x@example.test","roles":[],"enabled":true,"email_verified":false,"user_values":{"preferred_username":"x"}}`, "", "application/json", true},
		{"nested duplicate", `{"email":"x@example.test","roles":[],"enabled":true,"email_verified":false,"user_values":{"city":"A","city":"B"}}`, "", "application/json", true},
		{"top duplicate", `{"email":"x@example.test","roles":[],"enabled":true,"email_verified":false,"roles":[]}`, "", "application/json", true},
		{"wrong string types", `{"email":12,"roles":[],"enabled":true,"email_verified":false}`, "", "application/json", true},
		{"wrong bool types", `{"email":"x@example.test","roles":[],"enabled":"false","email_verified":false}`, "", "application/json", true},
		{"email required", `{"roles":[],"enabled":true,"email_verified":false}`, "", "application/json", true},
		{"roles required", `{"email":"x@example.test","enabled":true,"email_verified":false}`, "", "application/json", true},
		{"language invalid", `{"email":"x@example.test","language":"EN","roles":[],"enabled":true,"email_verified":false}`, "", "application/json", true},
		{"name invalid", `{"email":"x@example.test","given_name":"bad\u0001","roles":[],"enabled":true,"email_verified":false}`, "", "application/json", true},
		{"password rune limit", `{"email":"x@example.test","password":"` + strings.Repeat("😀", 257) + `","roles":[],"enabled":true,"email_verified":false}`, "", "application/json", true},
		{"expiry below minimum", `{"email":"x@example.test","roles":[],"enabled":true,"email_verified":false,"user_expires":1719784799}`, "", "application/json", true},
		{"expiry overflow ms", `{"email":"x@example.test","roles":[],"enabled":true,"email_verified":false,"user_expires":9223372036854776}`, "", "application/json", true},
		{"timezone valid", `{"email":"x@example.test","roles":[],"enabled":true,"email_verified":false,"user_values":{"tz":"Etc/UTC"}}`, "", "application/json", false},
		{"timezone local unsafe", `{"email":"x@example.test","roles":[],"enabled":true,"email_verified":false,"user_values":{"tz":"Local"}}`, "", "application/json", true},
		{"value regex invalid", `{"email":"x@example.test","roles":[],"enabled":true,"email_verified":false,"user_values":{"zip":"12-34"}}`, "", "application/json", true},
		{"query rejected", valid, "?x=1", "application/json", true},
		{"content type rejected", valid, "", "text/plain", true},
		{"invalid utf8", "{\"email\":\"x@example.test\",\"roles\":[],\"enabled\":true,\"email_verified\":false,\"given_name\":\xff}", "", "application/json", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeUserUpdate(httptest.NewRecorder(), userUpdateRequest(tc.body, tc.query, tc.ctype))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%t input=%+v", err, tc.wantErr, got)
			}
			if !tc.wantErr && tc.name == "valid" && (got.Email != "new@example.test" || got.Language == nil || *got.Language != "en" || got.Groups == nil || len(*got.Groups) != 1 || got.UserValues == nil || got.UserValues.Timezone == nil) {
				t.Fatalf("decoded=%+v", got)
			}
		})
	}
}
