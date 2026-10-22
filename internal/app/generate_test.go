package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/maxouverzou/git-credential-artifacts/internal/artifacts"
	"github.com/maxouverzou/git-credential-artifacts/internal/cloudflare"
	"github.com/maxouverzou/git-credential-artifacts/internal/config"
	"github.com/maxouverzou/git-credential-artifacts/internal/credential"
)

const seededAPI = "seeded-api-credential"
const seededRepo = "art_v1_0123456789abcdef0123456789abcdef01234567"
const seededExpiry int64 = 1700003600
const validInput = "protocol=https\nhost=" + artifactsHost + "\npath=git/Default/demo.git.git\n"

var selectedSettings = config.Settings{Scope: "read", TTL: 120}
var selectedRemote = artifacts.Remote{AccountID: artifactsAccount, Namespace: "Default", Repository: "demo.git"}

type issuerFunc func(context.Context, artifacts.Remote, config.Settings) (artifacts.Token, error)

func (f issuerFunc) Issue(ctx context.Context, r artifacts.Remote, s config.Settings) (artifacts.Token, error) {
	return f(ctx, r, s)
}

func TestComposedGetSuccess(t *testing.T) {
	for _, username := range []string{"", "provided=equals", " user name ", "développeur"} {
		t.Run(username, func(t *testing.T) {
			configCalls, factoryCalls, issueCalls := 0, 0, 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			get := NewGetWithDependencies(ctx, Dependencies{
				LoadSettings: func() (config.Settings, error) { configCalls++; return selectedSettings, nil },
				NewIssuer: func() (TokenIssuer, error) {
					factoryCalls++
					if configCalls != 1 {
						t.Fatal("authentication before configuration")
					}
					return issuerFunc(func(gotCtx context.Context, r artifacts.Remote, s config.Settings) (artifacts.Token, error) {
						issueCalls++
						if gotCtx != ctx || r != selectedRemote || s != selectedSettings {
							t.Fatal("incorrect issuance arguments")
						}
						return artifacts.Token{Secret: seededRepo, ExpiryUnix: seededExpiry}, nil
					}), nil
				},
			})
			var stdout, stderr bytes.Buffer
			input := validInput + "password=" + seededAPI + "\nscope=write\nttl=31536000\napi_token=" + seededAPI + "\n"
			if username != "" {
				input += "username=" + username + "\n"
			} else {
				input += "username=\n"
			}
			if err := Run([]string{"get"}, strings.NewReader(input+"\n"), &stdout, &stderr, get); err != nil {
				t.Fatal("get failed")
			}
			wantUsername := username
			if wantUsername == "" {
				wantUsername = "x"
			}
			want := fmt.Sprintf("username=%s\npassword=%s\npassword_expiry_utc=%d\n\n", wantUsername, seededRepo, seededExpiry)
			if stdout.String() != want || stderr.Len() != 0 || configCalls != 1 || factoryCalls != 1 || issueCalls != 1 || strings.Contains(stdout.String(), seededAPI) {
				t.Fatal("incorrect successful composition")
			}
		})
	}
}

func TestComposedGateSkipsAllAcquisition(t *testing.T) {
	calls := 0
	get := NewGetWithDependencies(context.Background(), Dependencies{
		LoadSettings: func() (config.Settings, error) { calls++; return selectedSettings, nil },
		NewIssuer:    func() (TokenIssuer, error) { calls++; return nil, errors.New(seededAPI) },
	})
	for _, tc := range []struct {
		args  []string
		input string
		quit  bool
	}{
		{[]string{"get"}, "protocol=https\nhost=example.com\n\n", false},
		{[]string{"get"}, "host=" + artifactsHost + ".attacker.invalid\n\n", false},
		{[]string{"get"}, "host=" + artifactsHost + "\nprotocol=https\n\n", true},
		{[]string{"get"}, "protocol=http\nhost=" + artifactsHost + "\npath=git/default/demo.git\n\n", true},
		{[]string{"get"}, validInput + "username=unsafe\t" + seededAPI + "\n\n", true},
		{[]string{"get"}, validInput + "host=example.com\n\n", true},
		{[]string{"get"}, "host=example.com\nmalformed-" + seededAPI + "\n", true},
		{[]string{"store"}, validInput + "\n", false},
		{[]string{"erase"}, validInput + "\n", false},
		{[]string{"unknown"}, validInput + "\n", false},
	} {
		var stdout, stderr bytes.Buffer
		if err := Run(tc.args, strings.NewReader(tc.input), &stdout, &stderr, get); err != nil {
			t.Fatal("dispatch failed")
		}
		want := ""
		if tc.quit {
			want = "quit=true\n\n"
		}
		if calls != 0 || stdout.String() != want || (tc.quit && stderr.Len() == 0) || (!tc.quit && stderr.Len() != 0) || strings.Contains(stderr.String(), seededAPI) {
			t.Fatal("gate acquired credentials or leaked unsafe data")
		}
	}
	// Direct callers also cannot bypass username validation before acquisition.
	for _, username := range []string{"unsafe\npassword=inject", "unsafe\x00", "unsafe\r", strings.Repeat("a", credential.MaxLineBytes)} {
		response, err := get(credential.Request{Protocol: "https", Host: artifactsHost, Path: "git/default/demo.git", Username: username})
		if response != nil || err != credential.ErrInvalidResponse || calls != 0 {
			t.Fatal("unsafe username reached acquisition")
		}
	}
}

func TestComposedFailures(t *testing.T) {
	for _, tc := range []struct {
		name, stage string
		cause       error
		message     string
	}{
		{"scope", "config", config.ErrScope, "set GIT_CREDENTIAL_ARTIFACTS_SCOPE to read or write"},
		{"TTL", "config", config.ErrTTL, "set GIT_CREDENTIAL_ARTIFACTS_TTL to decimal seconds between 60 and 31536000"},
		{"auth", "factory", cloudflare.ErrAuthentication, "set a nonempty, header-safe CLOUDFLARE_API_TOKEN with Artifacts Edit permission"},
		{"timeout", "issue", cloudflare.ErrTimeout, "Cloudflare token request timed out; check network connectivity"},
		{"canceled", "issue", cloudflare.ErrCanceled, "Cloudflare token request canceled"},
		{"transport", "issue", cloudflare.ErrTransport, "Cloudflare token request failed; check network connectivity"},
		{"API", "issue", cloudflare.ErrAPI, "Cloudflare rejected token issuance; check API-token permissions and repository access"},
		{"rejected envelope", "issue", artifacts.ErrTokenRejected, "Cloudflare rejected token issuance; check API-token permissions and repository access"},
		{"SDK response", "issue", cloudflare.ErrResponse, "invalid Cloudflare token response; no credential returned"},
		{"token response", "issue", artifacts.ErrTokenResponse, "invalid Cloudflare token response; no credential returned"},
		{"route", "issue", cloudflare.ErrRoute, "invalid repository path; expected git/<namespace>/<repo>.git"},
		{"unknown config", "config", errors.New(seededAPI + seededRepo), "credential generation failed"},
		{"unknown factory", "factory", errors.New(seededAPI + seededRepo), "credential generation failed"},
		{"unknown issuance", "issue", errors.New(seededAPI + seededRepo), "credential generation failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configCalls, factoryCalls, issueCalls := 0, 0, 0
			get := NewGetWithDependencies(context.Background(), Dependencies{
				LoadSettings: func() (config.Settings, error) {
					configCalls++
					if tc.stage == "config" {
						return config.Settings{}, tc.cause
					}
					return selectedSettings, nil
				},
				NewIssuer: func() (TokenIssuer, error) {
					factoryCalls++
					if tc.stage == "factory" {
						return nil, tc.cause
					}
					return issuerFunc(func(context.Context, artifacts.Remote, config.Settings) (artifacts.Token, error) {
						issueCalls++
						return artifacts.Token{Secret: seededRepo, ExpiryUnix: seededExpiry}, tc.cause
					}), nil
				},
			})
			var stdout, stderr bytes.Buffer
			if err := Run([]string{"get"}, strings.NewReader(validInput+"\n"), &stdout, &stderr, get); err != nil {
				t.Fatal("get failed")
			}
			if stdout.String() != "quit=true\n\n" || stderr.String() != "artifacts: "+tc.message+"\n" || strings.Contains(stderr.String(), seededAPI) || strings.Contains(stderr.String(), seededRepo) {
				t.Fatal("unsafe failure output")
			}
			wantFactory, wantIssue := 0, 0
			if tc.stage != "config" {
				wantFactory = 1
			}
			if tc.stage == "issue" {
				wantIssue = 1
			}
			if configCalls != 1 || factoryCalls != wantFactory || issueCalls != wantIssue {
				t.Fatal("failure did not stop acquisition")
			}
		})
	}
}

func TestInvalidDirectSettingsSkipFactory(t *testing.T) {
	for _, settings := range []config.Settings{{Scope: "admin", TTL: 3600}, {Scope: "read", TTL: 59}} {
		get := NewGetWithDependencies(context.Background(), Dependencies{
			LoadSettings: func() (config.Settings, error) { return settings, nil },
			NewIssuer:    func() (TokenIssuer, error) { t.Fatal("invalid settings constructed issuer"); return nil, nil },
		})
		response, err := get(credential.Request{Protocol: "https", Host: artifactsHost, Path: "git/default/demo.git"})
		if response != nil || err == nil {
			t.Fatal("invalid direct settings accepted")
		}
	}
}

func TestMissingGenerationDependencies(t *testing.T) {
	for _, deps := range []Dependencies{
		{},
		{LoadSettings: func() (config.Settings, error) { return selectedSettings, nil }},
		{LoadSettings: func() (config.Settings, error) { return selectedSettings, nil }, NewIssuer: func() (TokenIssuer, error) { return nil, nil }},
	} {
		var stdout, stderr bytes.Buffer
		err := Run([]string{"get"}, strings.NewReader(validInput+"\n"), &stdout, &stderr, NewGetWithDependencies(context.Background(), deps))
		if err != nil || stdout.String() != "quit=true\n\n" || stderr.String() != "artifacts: credential generation unavailable\n" {
			t.Fatal("missing dependencies must fail closed")
		}
	}
}

func TestInvalidIssuedCredentialFailsClosed(t *testing.T) {
	for _, token := range []artifacts.Token{
		{}, {Secret: seededRepo + "\npassword=unsafe", ExpiryUnix: seededExpiry}, {Secret: seededRepo, ExpiryUnix: 0},
	} {
		get := NewGetWithDependencies(context.Background(), Dependencies{
			LoadSettings: func() (config.Settings, error) { return selectedSettings, nil },
			NewIssuer: func() (TokenIssuer, error) {
				return issuerFunc(func(context.Context, artifacts.Remote, config.Settings) (artifacts.Token, error) { return token, nil }), nil
			},
		})
		var stdout, stderr bytes.Buffer
		if err := Run([]string{"get"}, strings.NewReader(validInput+"\n"), &stdout, &stderr, get); err != nil || stdout.String() != "quit=true\n\n" || stderr.String() != "artifacts: invalid credential response\n" {
			t.Fatal("invalid issuance emitted partial credentials")
		}
	}
}

func TestFullSDKComposition(t *testing.T) {
	t.Setenv("CLOUDFLARE_API_TOKEN", seededAPI)
	t.Setenv(config.ScopeEnv, "read")
	t.Setenv(config.TTLEnv, "120")
	now := time.Unix(1700000000, 0)
	good := fmt.Sprintf(`{"success":true,"result":{"plaintext":"%s?expires=%d","scope":"read","expires_at":"%s"}}`, seededRepo, seededExpiry, time.Unix(seededExpiry, 0).UTC().Format(time.RFC3339))
	for _, tc := range []struct {
		name, body string
		status     int
		failure    error
		message    string
	}{
		{name: "success", body: good, status: 200},
		{name: "v2 success", body: strings.Replace(good, seededRepo, "art_v2_x_syntheticPayload0123456789_-", 1), status: 201},
		{name: "v2 malformed", body: strings.Replace(good, seededRepo, "art_v2_x_", 1), status: 201, message: "invalid Cloudflare token response; no credential returned"},
		{name: "malformed", body: seededAPI + seededRepo, status: 200, message: "invalid Cloudflare token response; no credential returned"},
		{name: "wrong scope", body: strings.Replace(good, `"read"`, `"write"`, 1), status: 200, message: "invalid Cloudflare token response; no credential returned"},
		{name: "expired", body: strings.Replace(good, "?expires=1700003600", "?expires=1699999999", 1), status: 200, message: "invalid Cloudflare token response; no credential returned"},
		{name: "API rejected", body: seededAPI + seededRepo, status: 403, message: "Cloudflare rejected token issuance; check API-token permissions and repository access"},
		{name: "envelope rejected", body: `{"success":false}`, status: 200, message: "Cloudflare rejected token issuance; check API-token permissions and repository access"},
		{name: "transport", failure: errors.New(seededAPI + seededRepo), message: "Cloudflare token request failed; check network connectivity"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			factoryCalls, calls := 0, 0
			get := NewGetWithDependencies(context.Background(), Dependencies{
				LoadSettings: config.Load,
				NewIssuer: func() (TokenIssuer, error) {
					factoryCalls++
					client, err := cloudflare.New(boundaryTransport(func(r *http.Request) (*http.Response, error) {
						calls++
						if r.Method != "POST" || r.URL.String() != cloudflare.APIOrigin+"accounts/"+artifactsAccount+"/artifacts/namespaces/Default/tokens" || r.Header.Get("Authorization") != "Bearer "+seededAPI {
							t.Fatal("incorrect trusted request")
						}
						var body map[string]any
						if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body) != 3 || body["repo"] != "demo.git" || body["scope"] != "read" || body["ttl"] != float64(120) {
							t.Fatal("incorrect settings/identity body")
						}
						if tc.failure != nil {
							return nil, tc.failure
						}
						return &http.Response{StatusCode: tc.status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
					}))
					if err != nil {
						return nil, err
					}
					return artifacts.NewIssuer(client, func() time.Time { return now }), nil
				},
			})
			var stdout, stderr bytes.Buffer
			if err := Run([]string{"get"}, strings.NewReader(validInput+"password="+seededAPI+"\n\n"), &stdout, &stderr, get); err != nil {
				t.Fatal("get failed")
			}
			secret := seededRepo
			if tc.name == "v2 success" {
				secret = "art_v2_x_syntheticPayload0123456789_-"
			}
			want := fmt.Sprintf("username=x\npassword=%s\npassword_expiry_utc=%d\n\n", secret, seededExpiry)
			message := ""
			if tc.message != "" {
				want = "quit=true\n\n"
				message = "artifacts: " + tc.message + "\n"
			}
			if stdout.String() != want || stderr.String() != message || calls != 1 || factoryCalls != 1 || strings.Contains(stdout.String(), seededAPI) || strings.Contains(stderr.String(), seededAPI) || strings.Contains(stderr.String(), seededRepo) {
				t.Fatal("unsafe full-pipeline output or multiple issuance attempts")
			}
		})
	}
}
