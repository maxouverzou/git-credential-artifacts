package app

import (
	"bytes"
	"strings"
	"testing"

	"github.com/maxouverzou/git-credential-artifacts/internal/artifacts"
	"github.com/maxouverzou/git-credential-artifacts/internal/credential"
)

const artifactsAccount = "0123456789abcdef0123456789abcdef"
const artifactsHost = artifactsAccount + ".artifacts.cloudflare.net"

func TestResolvedGetCallsGenerationOnce(t *testing.T) {
	var stdout, diagnostics bytes.Buffer
	authLookups, apiCalls := 0, 0
	get := ResolveArtifacts(func(remote artifacts.Remote, username string) (*credential.Response, error) {
		authLookups++
		apiCalls++
		if remote != (artifacts.Remote{AccountID: artifactsAccount, Namespace: "Default", Repository: "demo.git"}) || username != "provided=equals" {
			t.Fatal("generation received an incorrect identity or username")
		}
		return &credential.Response{Username: username, Password: "synthetic-token", ExpiryUnix: 1760000000}, nil
	})
	input := "protocol=https\nhost=" + strings.ToUpper(artifactsHost) + "\npath=git/Default/demo.git.git\nusername=provided=equals\n\n"
	if err := Run([]string{"get"}, strings.NewReader(input), &stdout, &diagnostics, get); err != nil {
		t.Fatal(err)
	}
	if authLookups != 1 || apiCalls != 1 || diagnostics.Len() != 0 ||
		stdout.String() != "username=provided=equals\npassword=synthetic-token\npassword_expiry_utc=1760000000\n\n" {
		t.Fatal("valid resolution must reach generation once and emit only its credential")
	}
}

func TestResolutionGateNeverAcquiresCredentials(t *testing.T) {
	for _, test := range []struct {
		name, input, diagnostic string
	}{
		{"unrelated", "protocol=ssh\nhost=example.com\npath=malformed\n\n", ""},
		{"suffix confusion", "protocol=https\nhost=" + artifactsHost + ".attacker.invalid\n\n", ""},
		{"empty host", "protocol=https\n\n", ""},
		{"invalid account", "protocol=https\nhost=synthetic-secret.artifacts.cloudflare.net\n\n", "artifacts: invalid Artifacts hostname; use the exact repository hostname without a port or trailing dot\n"},
		{"port", "protocol=https\nhost=" + artifactsHost + ":443\npath=git/default/demo.git\n\n", "artifacts: invalid Artifacts hostname; use the exact repository hostname without a port or trailing dot\n"},
		{"protocol", "protocol=http\nhost=" + artifactsHost + "\npath=git/default/demo.git\n\n", "artifacts: Artifacts requests require protocol=https\n"},
		{"missing path", "protocol=https\nhost=" + artifactsHost + "\n\n", "artifacts: missing repository path; set credential.useHttpPath=true\n"},
		{"invalid path", "protocol=https\nhost=" + artifactsHost + "\npath=git/default/synthetic-secret%2fother.git\n\n", "artifacts: invalid repository path; expected git/<namespace>/<repo>.git\n"},
		{"malformed input", "host=" + artifactsHost + "\nmalformed-synthetic-secret\n", "artifacts: invalid credential input\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, diagnostics bytes.Buffer
			authLookups, apiCalls := 0, 0
			get := ResolveArtifacts(func(artifacts.Remote, string) (*credential.Response, error) {
				authLookups++
				apiCalls++
				return nil, nil
			})
			if err := Run([]string{"get"}, strings.NewReader(test.input), &stdout, &diagnostics, get); err != nil {
				t.Fatal(err)
			}
			want := ""
			if test.diagnostic != "" {
				want = "quit=true\n\n"
			}
			if stdout.String() != want || diagnostics.String() != test.diagnostic || authLookups != 0 || apiCalls != 0 {
				t.Fatal("invalid/unrelated request reached generation or produced unsafe output")
			}
		})
	}
}

func TestResolutionGateNilHandler(t *testing.T) {
	var stdout, diagnostics bytes.Buffer
	input := "protocol=https\nhost=" + artifactsHost + "\npath=git/default/demo.git\n\n"
	err := Run([]string{"get"}, strings.NewReader(input), &stdout, &diagnostics, ResolveArtifacts(nil))
	if err != nil || stdout.String() != "quit=true\n\n" || diagnostics.String() != "artifacts: credential generation unavailable\n" {
		t.Fatal("missing generation dependency must fail closed")
	}
}
