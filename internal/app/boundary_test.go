package app

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/maxouverzou/git-credential-artifacts/internal/artifacts"
	"github.com/maxouverzou/git-credential-artifacts/internal/cloudflare"
	"github.com/maxouverzou/git-credential-artifacts/internal/config"
	"github.com/maxouverzou/git-credential-artifacts/internal/credential"
)

type boundaryTransport func(*http.Request) (*http.Response, error)

func (f boundaryTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Exercise M4 through the M3 gate without wiring token issuance into production
// before M5. Configuration must be validated before acquiring API authentication.
func TestSDKBoundaryBehindResolutionAndConfiguration(t *testing.T) {
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	for _, tc := range []struct {
		name          string
		request       credential.Request
		scope, ttl    string
		want          error
		constructions int
	}{
		{name: "unrelated", request: credential.Request{Host: "example.com"}, scope: "write", ttl: "3600"},
		{name: "invalid remote", request: credential.Request{Host: artifactsHost, Protocol: "https"}, scope: "write", ttl: "3600", want: artifacts.ErrMissingPath},
		{name: "invalid scope", request: credential.Request{Host: artifactsHost, Protocol: "https", Path: "git/default/demo.git"}, scope: "seeded-secret", ttl: "3600", want: config.ErrScope},
		{name: "invalid TTL", request: credential.Request{Host: artifactsHost, Protocol: "https", Path: "git/default/demo.git"}, scope: "write", ttl: "-1", want: config.ErrTTL},
		{name: "missing auth", request: credential.Request{Host: artifactsHost, Protocol: "https", Path: "git/default/demo.git"}, scope: "read", ttl: "60", want: cloudflare.ErrAuthentication, constructions: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(config.ScopeEnv, tc.scope)
			t.Setenv(config.TTLEnv, tc.ttl)
			constructions, calls := 0, 0
			get := ResolveArtifacts(func(remote artifacts.Remote, _ string) (*credential.Response, error) {
				if _, err := config.Load(); err != nil {
					return nil, err
				}
				constructions++
				client, err := cloudflare.New(boundaryTransport(func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New("seeded-secret") }))
				if err != nil {
					return nil, err
				}
				return nil, client.PostToken(context.Background(), remote, nil, nil)
			})
			response, err := get(tc.request)
			if response != nil || err != tc.want || constructions != tc.constructions || calls != 0 {
				t.Fatal("resolution/configuration gate failed")
			}
			if err != nil && strings.Contains(err.Error(), "seeded-secret") {
				t.Fatal("unsafe diagnostic")
			}
		})
	}
}
