package scim

import (
	"strconv"
	"strings"
	"testing"
)

func TestScimFailureActionUsesSafeQuotedExternalIDs(t *testing.T) {
	cases := []struct {
		name    string
		request Request
		want    string
	}{
		{"user create", Request{User: User{ExternalID: "ascii"}}, `UserCreateUpdate("ascii")`},
		{"user delete", Request{User: User{ExternalID: "ascii"}, Delete: true}, `UserDelete("ascii")`},
		{"group create", Request{Group: Group{ExternalID: "group"}}, `GroupCreateUpdate("group")`},
		{"group delete", Request{Group: Group{ExternalID: "group"}, Delete: true}, `GroupDelete("group")`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := scimFailureAction(tc.request); got != tc.want {
				t.Fatalf("got=%q want=%q", got, tc.want)
			}
		})
	}
	for _, externalID := range []string{"quote\"slash\\line\n", "한글\x00"} {
		for _, group := range []bool{false, true} {
			req := Request{User: User{ExternalID: externalID}, Delete: true}
			if group {
				req.Group.ExternalID = externalID
			}
			got := scimFailureAction(req)
			prefix := "UserDelete("
			if group {
				prefix = "GroupDelete("
			}
			want := prefix + strconv.Quote(externalID) + ")"
			if got != want {
				t.Fatalf("group=%v got=%q want=%q", group, got, want)
			}
			if strings.Contains(got, "\n") {
				t.Fatalf("raw newline escaped: %q", got)
			}
		}
	}
}
