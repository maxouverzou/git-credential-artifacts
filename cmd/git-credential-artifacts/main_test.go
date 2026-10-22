package main

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestOperations(t *testing.T) {
	t.Setenv("GIT_CREDENTIAL_ARTIFACTS_SCOPE", "write")
	t.Setenv("GIT_CREDENTIAL_ARTIFACTS_TTL", "3600")
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	for _, op := range []string{"get", "store", "erase", "unknown", ""} {
		t.Run(op, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := run([]string{op}, bytes.NewBufferString("protocol=https\nhost=0123456789abcdef0123456789abcdef.artifacts.cloudflare.net\npath=git/default/demo.git\n\n"), &stdout, &stderr); err != nil {
				t.Fatal(err)
			}
			if op == "get" {
				if stdout.String() != "quit=true\n\n" || stderr.String() != "artifacts: set a nonempty, header-safe CLOUDFLARE_API_TOKEN with Artifacts Edit permission\n" {
					t.Fatal("missing authentication must fail closed")
				}
			} else if stdout.Len() != 0 || stderr.Len() != 0 {
				t.Fatal("unsupported operation must be silent")
			}
		})
	}
	for _, args := range [][]string{nil, {"get", "extra"}} {
		if err := run(args, nil, io.Discard, io.Discard); err != nil {
			t.Fatal(err)
		}
	}
}

func TestConfigurationFailures(t *testing.T) {
	t.Setenv("CLOUDFLARE_API_TOKEN", "") // Never use ambient credentials/network.
	for _, tc := range []struct{ scope, ttl, diagnostic string }{
		{"seeded-api-secret", "3600", "artifacts: set GIT_CREDENTIAL_ARTIFACTS_SCOPE to read or write\n"},
		{"write", "seeded-api-secret", "artifacts: set GIT_CREDENTIAL_ARTIFACTS_TTL to decimal seconds between 60 and 31536000\n"},
	} {
		t.Setenv("GIT_CREDENTIAL_ARTIFACTS_SCOPE", tc.scope)
		t.Setenv("GIT_CREDENTIAL_ARTIFACTS_TTL", tc.ttl)
		var stdout, stderr bytes.Buffer
		input := "protocol=https\nhost=0123456789abcdef0123456789abcdef.artifacts.cloudflare.net\npath=git/default/demo.git\n\n"
		if err := run([]string{"get"}, bytes.NewBufferString(input), &stdout, &stderr); err != nil || stdout.String() != "quit=true\n\n" || stderr.String() != tc.diagnostic {
			t.Fatal("configuration must fail closed before authentication")
		}
	}
}

func TestGetClassification(t *testing.T) {
	for _, test := range []struct {
		name, input, diagnostic string
	}{
		{"unrelated", "protocol=https\nhost=example.com\n\n", ""},
		{"lookalike", "protocol=https\nhost=0123456789abcdef0123456789abcdef.artifacts.cloudflare.net.attacker.invalid\n\n", ""},
		{"missing path", "protocol=https\nhost=0123456789abcdef0123456789abcdef.artifacts.cloudflare.net\n\n", "artifacts: missing repository path; set credential.useHttpPath=true\n"},
		{"malformed", "host=example.com\nmalformed\n", "artifacts: invalid credential input\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := run([]string{"get"}, bytes.NewBufferString(test.input), &stdout, &stderr); err != nil {
				t.Fatal(err)
			}
			want := ""
			if test.diagnostic != "" {
				want = "quit=true\n\n"
			}
			if stdout.String() != want || stderr.String() != test.diagnostic {
				t.Fatal("command classification produced incorrect protocol output or diagnostics")
			}
		})
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestWriteFailure(t *testing.T) {
	if err := run([]string{"get"}, bytes.NewBufferString("host=0123456789abcdef0123456789abcdef.artifacts.cloudflare.net\n"), failingWriter{}, io.Discard); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("stdout error must propagate")
	}
}
