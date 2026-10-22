package cloudflare

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/maxouverzou/git-credential-artifacts/internal/artifacts"
)

const fakeSecret = "seeded-api-secret"

var validRemote = artifacts.Remote{AccountID: strings.Repeat("a", 32), Namespace: "default", Repository: "repo"}

func fakeResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}

func newTestClient(t *testing.T, transport http.RoundTripper) *Client {
	t.Helper()
	t.Setenv("CLOUDFLARE_API_TOKEN", fakeSecret)
	c, err := New(transport)
	if err != nil {
		t.Fatal("client construction failed")
	}
	return c
}

func TestAuthentication(t *testing.T) {
	for _, value := range []string{"", " ", "secret\r\nInjected: true", "secret\t", "secret\x7f", "sécret"} {
		t.Run("invalid token", func(t *testing.T) {
			t.Setenv("CLOUDFLARE_API_TOKEN", value)
			t.Setenv("CLOUDFLARE_API_KEY", fakeSecret)
			t.Setenv("CLOUDFLARE_EMAIL", "fake@example.invalid")
			t.Setenv("CLOUDFLARE_API_USER_SERVICE_KEY", fakeSecret)
			calls := 0
			c, err := New(roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New(fakeSecret) }))
			if c != nil || err != ErrAuthentication || calls != 0 {
				t.Fatal("invalid auth must fail without alternative auth or requests")
			}
		})
	}
	// Test genuinely absent credentials too, not just an empty variable.
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	t.Setenv("CLOUDFLARE_API_KEY", "")
	t.Setenv("CLOUDFLARE_EMAIL", "")
	t.Setenv("CLOUDFLARE_API_USER_SERVICE_KEY", "")
	if err := os.Unsetenv("CLOUDFLARE_API_TOKEN"); err != nil {
		t.Fatal(err)
	}
	for _, alternative := range []string{"", "CLOUDFLARE_API_KEY", "CLOUDFLARE_EMAIL", "CLOUDFLARE_API_USER_SERVICE_KEY"} {
		t.Run("unsupported "+alternative, func(t *testing.T) {
			if alternative != "" {
				t.Setenv(alternative, fakeSecret)
			}
			if _, err := New(nil); err != ErrAuthentication {
				t.Fatal("missing token or unsupported authentication accepted")
			}
		})
	}
}

func TestDefaultTransportConstructionDoesNotSend(t *testing.T) {
	t.Setenv("CLOUDFLARE_API_TOKEN", fakeSecret)
	if c, err := New(nil); err != nil || c == nil {
		t.Fatal("default client construction failed")
	}
}

func TestTrustedRequestWithHostileEnvironment(t *testing.T) {
	for _, base := range []string{"http://attacker.invalid/", "https://api.cloudflare.com.attacker.invalid/", "://malformed"} {
		t.Run(base, func(t *testing.T) {
			t.Setenv("CLOUDFLARE_BASE_URL", base)
			t.Setenv("CLOUDFLARE_API_KEY", "injected\r\nHost: attacker.invalid")
			t.Setenv("CLOUDFLARE_EMAIL", "injected-email")
			t.Setenv("CLOUDFLARE_API_USER_SERVICE_KEY", "injected-service-key")
			t.Setenv("CLOUDFLARE_HEADERS", "Authorization: injected")
			calls := 0
			c := newTestClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != http.MethodPost || r.URL.String() != APIOrigin+"accounts/"+validRemote.AccountID+"/artifacts/namespaces/default/tokens" || (r.Host != "" && r.Host != "api.cloudflare.com") {
					t.Fatal("untrusted destination")
				}
				if r.Header.Get("Authorization") != "Bearer "+fakeSecret {
					t.Fatal("wrong authentication")
				}
				for _, h := range []string{"X-Auth-Key", "X-Auth-Email", "X-Auth-User-Service-Key"} {
					if r.Header.Get(h) != "" {
						t.Fatal("alternative authentication leaked")
					}
				}
				deadline, ok := r.Context().Deadline()
				if !ok || time.Until(deadline) > RequestDeadline {
					t.Fatal("unbounded request")
				}
				return fakeResponse(200, `{"success":true}`), nil
			}))
			var out struct {
				Success bool `json:"success"`
			}
			if err := c.PostToken(context.Background(), validRemote, nil, &out); err != nil || !out.Success || calls != 1 {
				t.Fatal("trusted request failed")
			}
		})
	}
}

func TestFailuresAreSanitizedAndNeverRetried(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308, 400, 401, 403, 408, 409, 429, 500, 502, 503, 504} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			calls := 0
			c := newTestClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				response := fakeResponse(status, fakeSecret)
				response.Header.Set("Location", "https://attacker.invalid/"+fakeSecret)
				return response, nil
			}))
			err := c.PostToken(context.Background(), validRemote, nil, nil)
			if err != ErrAPI || calls != 1 || strings.Contains(err.Error(), fakeSecret) {
				t.Fatal("API failure must be sanitized without follow-up")
			}
		})
	}
	for _, tc := range []struct{ cause, errorWant error }{
		{errors.New(fakeSecret), ErrTransport},
		{context.DeadlineExceeded, ErrTimeout},
		{context.Canceled, ErrCanceled},
	} {
		calls := 0
		c := newTestClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return nil, tc.cause }))
		if err := c.PostToken(context.Background(), validRemote, nil, nil); err != tc.errorWant || calls != 1 {
			t.Fatal("wrong safe transport error or retry")
		}
	}
	c := newTestClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) { return fakeResponse(200, fakeSecret), nil }))
	var out map[string]any
	if err := c.PostToken(context.Background(), validRemote, nil, &out); err != ErrResponse {
		t.Fatal("decode error must be sanitized")
	}
}

func TestCancellation(t *testing.T) {
	c := newTestClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, r.Context().Err()
	}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.PostToken(ctx, validRemote, nil, nil); err != ErrCanceled {
		t.Fatal("cancellation not honored")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := c.PostToken(ctx, validRemote, nil, nil); err != ErrTimeout {
		t.Fatal("shorter caller deadline not honored")
	}
}

// Body reads must remain inside the total issuance deadline, not merely the
// RoundTrip phase. No wall clock delay is needed for this cancellation probe.
type cancellationBody struct {
	ctx    context.Context
	cancel context.CancelFunc
}

func (b cancellationBody) Read([]byte) (int, error) {
	b.cancel()
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}
func (b cancellationBody) Close() error { return nil }
func TestCancellationDuringResponseRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newTestClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		response := fakeResponse(200, "")
		response.Body = cancellationBody{r.Context(), cancel}
		return response, nil
	}))
	var out map[string]any
	if err := c.PostToken(ctx, validRemote, nil, &out); err != ErrCanceled {
		t.Fatal("response reading escaped total deadline")
	}
}

func TestInvalidRemoteNeverDispatches(t *testing.T) {
	calls := 0
	c := newTestClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New(fakeSecret) }))
	for _, remote := range []artifacts.Remote{
		{}, {AccountID: strings.Repeat("A", 32), Namespace: "default", Repository: "repo"},
		{AccountID: validRemote.AccountID, Namespace: "default/../../evil", Repository: "repo"},
		{AccountID: validRemote.AccountID, Namespace: "default", Repository: "repo?secret=" + fakeSecret},
	} {
		if err := c.PostToken(context.Background(), remote, nil, nil); err != ErrRoute {
			t.Fatal("unsafe remote accepted")
		}
	}
	if calls != 0 {
		t.Fatal("invalid remote reached transport")
	}
}

func TestTransportOriginGuard(t *testing.T) {
	calls := 0
	transport := guardedTransport{roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return fakeResponse(200, "{}"), nil })}
	route := APIOrigin + "accounts/" + validRemote.AccountID + "/artifacts/namespaces/default/tokens"
	for _, target := range []string{
		"http://api.cloudflare.com/client/v4/test", "https://attacker.invalid/", "https://api.cloudflare.com:443/",
		"https://user@api.cloudflare.com/", route + "?secret=" + fakeSecret, route + "?", route + "#fragment",
		APIOrigin + "accounts/" + validRemote.AccountID + "/artifacts/namespaces/default%2fevil/tokens",
		APIOrigin + "accounts/" + validRemote.AccountID + "/artifacts/namespaces/%64efault/tokens",
		APIOrigin + "accounts/" + validRemote.AccountID + "/artifacts/namespaces/../tokens", APIOrigin + "test",
		"https://api.cloudflare.com/other", route + "/extra",
	} {
		r, err := http.NewRequest(http.MethodPost, target, nil)
		if err != nil {
			t.Fatal("bad test fixture")
		}
		if _, err := transport.RoundTrip(r); err != ErrRoute {
			t.Fatal("unsafe route reached transport")
		}
	}
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.Host = "attacker.invalid" },
		func(r *http.Request) { r.Method = http.MethodGet },
		func(r *http.Request) { r.URL.Opaque = "//attacker.invalid/" },
		func(r *http.Request) { r.Header.Set("X-Auth-Key", fakeSecret) },
		func(r *http.Request) { r.Header.Set("X-Auth-Email", fakeSecret) },
		func(r *http.Request) { r.Header.Set("X-Auth-User-Service-Key", fakeSecret) },
	} {
		r, _ := http.NewRequest(http.MethodPost, route, nil)
		mutate(r)
		if _, err := transport.RoundTrip(r); err != ErrRoute {
			t.Fatal("unsafe request reached transport")
		}
	}
	if calls != 0 {
		t.Fatal("origin guard dispatched")
	}
}
