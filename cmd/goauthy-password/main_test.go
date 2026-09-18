package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/credential"
)

func TestReadPassword(t *testing.T) {
	for _, test := range []struct {
		name  string
		input string
		want  string
		ok    bool
	}{
		{name: "pipe EOF", input: "correct horse", want: "correct horse", ok: true},
		{name: "line feed", input: "correct horse\n", want: "correct horse", ok: true},
		{name: "Windows line feed", input: "correct horse\r\n", want: "correct horse", ok: true},
		{name: "maximum Windows line", input: strings.Repeat("a", maxPasswordBytes) + "\r\n", want: strings.Repeat("a", maxPasswordBytes), ok: true},
		{name: "empty"},
		{name: "newline only", input: "\n"},
		{name: "multiple lines", input: "one\ntwo\n"},
		{name: "oversize", input: strings.Repeat("a", maxPasswordBytes+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := readPassword(strings.NewReader(test.input))
			if (err == nil) != test.ok || string(got) != test.want {
				t.Fatalf("got=%q err=%v", got, err)
			}
		})
	}
}

func TestRunPrintsOnlyVerifiablePHC(t *testing.T) {
	var out bytes.Buffer
	if err := run(nil, strings.NewReader("correct horse\n"), &out); err != nil {
		t.Fatal(err)
	}
	phc := strings.TrimSuffix(out.String(), "\n")
	if strings.Contains(out.String(), "correct horse") {
		t.Fatal("password was printed")
	}
	valid, _, err := credential.Verify([]byte("correct horse"), phc)
	if err != nil || !valid {
		t.Fatalf("valid=%t err=%v output=%q", valid, err, out.String())
	}
}

func TestPolicyFromArgs(t *testing.T) {
	defaults := credential.DefaultPolicy()
	configured := defaults
	configured.MemoryKiB = 32768
	configured.Iterations = 3
	configured.Parallelism = 2
	for _, test := range []struct {
		name string
		args []string
		want credential.Policy
		ok   bool
	}{
		{name: "defaults", want: defaults, ok: true},
		{name: "configured", args: []string{"-memory-kib=32768", "-iterations=3", "-parallelism=2"}, want: configured, ok: true},
		{name: "signed", args: []string{"-memory-kib=+32768"}},
		{name: "fraction", args: []string{"-iterations=2.0"}},
		{name: "non canonical", args: []string{"-iterations=03"}},
		{name: "below policy", args: []string{"-iterations=1"}},
		{name: "positional", args: []string{"password"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := policyFromArgs(test.args)
			if (err == nil) != test.ok || got != test.want {
				t.Fatalf("policy=%+v err=%v", got, err)
			}
		})
	}
}

func TestRunUsesConfiguredPolicy(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"-memory-kib=32768", "-iterations=3", "-parallelism=2"}, strings.NewReader("correct horse\n"), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "$m=32768,t=3,p=2$") {
		t.Fatalf("PHC does not use configured policy: %q", out.String())
	}
}
