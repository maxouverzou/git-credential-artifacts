package artifacts_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/maxouverzou/git-credential-artifacts/internal/artifacts"
	"github.com/maxouverzou/git-credential-artifacts/internal/cloudflare"
	"github.com/maxouverzou/git-credential-artifacts/internal/config"
)

const apiSecret = "seeded-cloudflare-api-secret"
const repoSecret = "art_v1_0123456789abcdefABCDEF0123456789abcdef01"
const expires int64 = 1700003600

var fixedNow = time.Unix(1700000000, 0)
var remote = artifacts.Remote{AccountID: strings.Repeat("a", 32), Namespace: "Name.space_1-2", Repository: "demo.git"}

type tokenTransport func(*http.Request) (*http.Response, error)

func (f tokenTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func envelope(scope string) string {
	raw, _ := json.Marshal(map[string]any{
		"success": true,
		"result":  map[string]any{"id": "ignored", "plaintext": repoSecret + "?expires=" + strconv.FormatInt(expires, 10), "scope": scope, "expires_at": time.Unix(expires, 0).UTC().Format(time.RFC3339)},
		"errors":  []any{}, "messages": []any{},
	})
	return string(raw)
}

func httpResult(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}

func testIssuer(t *testing.T, transport tokenTransport) *artifacts.Issuer {
	t.Helper()
	t.Setenv("CLOUDFLARE_API_TOKEN", apiSecret)
	c, err := cloudflare.New(transport)
	if err != nil {
		t.Fatal("client creation failed")
	}
	return artifacts.NewIssuer(c, func() time.Time { return fixedNow })
}

func TestIssueExactRequest(t *testing.T) {
	for _, scope := range []string{"read", "write"} {
		t.Run(scope, func(t *testing.T) {
			calls := 0
			issuer := testIssuer(t, func(r *http.Request) (*http.Response, error) {
				calls++
				route := "accounts/" + url.PathEscape(remote.AccountID) + "/artifacts/namespaces/" + url.PathEscape(remote.Namespace) + "/tokens"
				if r.Method != http.MethodPost || r.URL.String() != cloudflare.APIOrigin+route || r.URL.RawQuery != "" {
					t.Fatal("wrong method, origin, or route")
				}
				if r.Header.Get("Authorization") != "Bearer "+apiSecret || r.Header.Get("Content-Type") != "application/json" {
					t.Fatal("missing trusted authentication or content type")
				}
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body) != 3 || body["repo"] != remote.Repository || body["scope"] != scope || body["ttl"] != float64(3600) {
					t.Fatal("incorrect token request body")
				}
				return httpResult(200, envelope(scope)), nil
			})
			token, err := issuer.Issue(context.Background(), remote, config.Settings{Scope: scope, TTL: 3600})
			if err != nil || calls != 1 || token != (artifacts.Token{Secret: repoSecret, ExpiryUnix: expires}) {
				t.Fatal("issuance did not return the exact repository secret and expiry")
			}
		})
	}
}

func TestIssueMalformedResponses(t *testing.T) {
	good := envelope("write")
	cases := []struct {
		name, body string
		want       error
	}{
		{"success false", strings.Replace(good, `"success":true`, `"success":false`, 1), artifacts.ErrTokenRejected},
		{"missing success", `{"result":{}}`, artifacts.ErrTokenRejected},
		{"null envelope", `null`, artifacts.ErrTokenRejected},
		{"missing result", `{"success":true}`, artifacts.ErrTokenResponse},
		{"null result", `{"success":true,"result":null}`, artifacts.ErrTokenResponse},
		{"empty result", `{"success":true,"result":{}}`, artifacts.ErrTokenResponse},
		{"malformed JSON", `{"success":true`, artifacts.ErrTokenResponse},
		{"trailing garbage", good + apiSecret, artifacts.ErrTokenResponse},
		{"second document", good + good, artifacts.ErrTokenResponse},
		{"invalid success type", `{"success":"true","result":{}}`, artifacts.ErrTokenResponse},
		{"invalid result type", `{"success":true,"result":[]}`, artifacts.ErrTokenResponse},
		{"wrong scope", envelope("read"), artifacts.ErrTokenResponse},
		{"unknown scope", envelope(apiSecret), artifacts.ErrTokenResponse},
		{"API credential as plaintext", strings.Replace(good, repoSecret+"?expires=1700003600", apiSecret, 1), artifacts.ErrTokenResponse},
		{"missing expiry suffix", strings.Replace(good, "?expires=1700003600", "", 1), artifacts.ErrTokenResponse},
		{"overflowing expiry", strings.Replace(good, "?expires=1700003600", "?expires=9223372036854775808", 1), artifacts.ErrTokenResponse},
		{"expiry mismatch", strings.Replace(good, "?expires=1700003600", "?expires=1700003601", 1), artifacts.ErrTokenResponse},
		{"expired token", strings.Replace(good, "?expires=1700003600", "?expires=1699999999", 1), artifacts.ErrTokenResponse},
	}
	// Every required result field must be present, non-null, and the correct type.
	for _, field := range []string{"plaintext", "scope", "expires_at"} {
		for _, kind := range []string{"missing", "null", "empty", "number", "object"} {
			var body map[string]any
			if err := json.Unmarshal([]byte(good), &body); err != nil {
				t.Fatal(err)
			}
			result := body["result"].(map[string]any)
			switch kind {
			case "missing":
				delete(result, field)
			case "null":
				result[field] = nil
			case "empty":
				result[field] = ""
			case "number":
				result[field] = 123
			case "object":
				result[field] = map[string]any{"secret": apiSecret}
			}
			raw, _ := json.Marshal(body)
			cases = append(cases, struct {
				name, body string
				want       error
			}{field + " " + kind, string(raw), artifacts.ErrTokenResponse})
		}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			issuer := testIssuer(t, func(*http.Request) (*http.Response, error) { calls++; return httpResult(200, tc.body), nil })
			got, err := issuer.Issue(context.Background(), remote, config.Settings{Scope: "write", TTL: 3600})
			assertSafeFailure(t, got, err, tc.want)
			if calls != 1 {
				t.Fatal("response failure retried")
			}
		})
	}
}

func assertSafeFailure(t *testing.T, got artifacts.Token, err, want error) {
	t.Helper()
	if got != (artifacts.Token{}) || err != want {
		t.Fatal("wrong failure category or partial token returned")
	}
	if strings.Contains(err.Error(), apiSecret) || strings.Contains(err.Error(), repoSecret) {
		t.Fatal("secret leaked in error")
	}
}

func TestIssueHTTPAndTransportFailures(t *testing.T) {
	for _, status := range []int{302, 307, 400, 401, 403, 408, 409, 429, 500, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			calls := 0
			issuer := testIssuer(t, func(*http.Request) (*http.Response, error) {
				calls++
				response := httpResult(status, apiSecret+repoSecret)
				response.Header.Set("Location", "https://attacker.invalid/"+apiSecret)
				return response, nil
			})
			got, err := issuer.Issue(context.Background(), remote, config.Settings{Scope: "write", TTL: 3600})
			assertSafeFailure(t, got, err, cloudflare.ErrAPI)
			if calls != 1 {
				t.Fatal("failed issuance retried or followed redirect")
			}
		})
	}
	for _, tc := range []struct{ cause, want error }{
		{errors.New(apiSecret + repoSecret), cloudflare.ErrTransport},
		{context.DeadlineExceeded, cloudflare.ErrTimeout},
		{context.Canceled, cloudflare.ErrCanceled},
	} {
		calls := 0
		issuer := testIssuer(t, func(*http.Request) (*http.Response, error) { calls++; return nil, tc.cause })
		got, err := issuer.Issue(context.Background(), remote, config.Settings{Scope: "write", TTL: 3600})
		assertSafeFailure(t, got, err, tc.want)
		if calls != 1 {
			t.Fatal("transport failure retried")
		}
	}
}

func TestIssueChecksClockAfterResponse(t *testing.T) {
	t.Setenv("CLOUDFLARE_API_TOKEN", apiSecret)
	for _, now := range []time.Time{time.Unix(expires-1, 999999999), time.Unix(expires, 0), time.Unix(expires+1, 0)} {
		calls, clockCalls := 0, 0
		client, err := cloudflare.New(tokenTransport(func(*http.Request) (*http.Response, error) {
			calls++
			return httpResult(200, envelope("write")), nil
		}))
		if err != nil {
			t.Fatal("client construction failed")
		}
		issuer := artifacts.NewIssuer(client, func() time.Time {
			clockCalls++
			if calls != 1 {
				t.Fatal("expiry clock sampled before response")
			}
			return now
		})
		got, err := issuer.Issue(context.Background(), remote, config.Settings{Scope: "write", TTL: 3600})
		if now.Unix() < expires {
			if err != nil || got.ExpiryUnix != expires {
				t.Fatal("unexpected early-expiry margin")
			}
		} else {
			assertSafeFailure(t, got, err, artifacts.ErrTokenResponse)
		}
		if calls != 1 || clockCalls != 1 {
			t.Fatal("issuance or clock sampled more than once")
		}
	}
}

func TestIssueRejectsInvalidSettingsBeforeHTTP(t *testing.T) {
	calls := 0
	issuer := testIssuer(t, func(*http.Request) (*http.Response, error) { calls++; return httpResult(200, envelope("write")), nil })
	for _, tc := range []struct {
		settings config.Settings
		want     error
	}{
		{config.Settings{}, config.ErrScope},
		{config.Settings{Scope: apiSecret, TTL: 3600}, config.ErrScope},
		{config.Settings{Scope: "write", TTL: -1}, config.ErrTTL},
		{config.Settings{Scope: "read", TTL: 59}, config.ErrTTL},
		{config.Settings{Scope: "write", TTL: 31536001}, config.ErrTTL},
	} {
		got, err := issuer.Issue(context.Background(), remote, tc.settings)
		assertSafeFailure(t, got, err, tc.want)
	}
	if calls != 0 {
		t.Fatal("invalid settings dispatched")
	}
}

func TestIssueRejectsInvalidRemoteBeforeHTTP(t *testing.T) {
	calls := 0
	issuer := testIssuer(t, func(*http.Request) (*http.Response, error) { calls++; return httpResult(200, envelope("write")), nil })
	got, err := issuer.Issue(context.Background(), artifacts.Remote{AccountID: remote.AccountID, Namespace: "default/../../evil", Repository: "repo"}, config.Settings{Scope: "write", TTL: 3600})
	assertSafeFailure(t, got, err, cloudflare.ErrRoute)
	if calls != 0 {
		t.Fatal("invalid route dispatched")
	}
}
