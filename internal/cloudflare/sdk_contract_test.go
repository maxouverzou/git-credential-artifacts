// These tests pin the upstream custom-request contract, not the production
// authentication boundary (implemented in milestone 4).
package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	sdk "github.com/cloudflare/cloudflare-go/v6"
	"github.com/cloudflare/cloudflare-go/v6/option"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func contractClient(transport http.RoundTripper) *sdk.Client {
	// Avoid ambient environment defaults: these tests must never use live auth.
	return &sdk.Client{Options: []option.RequestOption{
		option.WithBaseURL("https://api.cloudflare.com/client/v4/"),
		option.WithAPIToken("synthetic-api-token"),
		option.WithMaxRetries(0),
		option.WithRequestTimeout(30 * time.Second),
		option.WithHTTPClient(&http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}),
	}}
}

func TestCustomPostEnvelope(t *testing.T) {
	calls := 0
	client := contractClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != http.MethodPost || r.URL.String() != "https://api.cloudflare.com/client/v4/accounts/test/artifacts/namespaces/default/tokens" {
			t.Fatal("unexpected request destination or method")
		}
		if r.Header.Get("Authorization") != "Bearer synthetic-api-token" {
			t.Fatal("expected API token authentication")
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body) != 3 ||
			body["repo"] != "demo" || body["scope"] != "write" || body["ttl"] != float64(3600) {
			t.Fatal("unexpected JSON body")
		}
		return &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": {"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"success":true,"result":{"plaintext":"synthetic-repo-token"}}`)),
		}, nil
	}))
	var envelope struct {
		Success bool `json:"success"`
		Result  struct {
			Plaintext string `json:"plaintext"`
		} `json:"result"`
	}
	params := struct {
		Repo  string `json:"repo"`
		Scope string `json:"scope"`
		TTL   int    `json:"ttl"`
	}{"demo", "write", 3600}
	err := client.Post(context.Background(), "accounts/test/artifacts/namespaces/default/tokens", params, &envelope)
	if err != nil || calls != 1 || !envelope.Success || envelope.Result.Plaintext != "synthetic-repo-token" {
		t.Fatal("custom Post must decode the complete envelope exactly once")
	}
}

func TestDisabledRetries(t *testing.T) {
	for _, status := range []int{408, 409, 429, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			calls := 0
			client := contractClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{
					StatusCode: status,
					Header:     http.Header{"Content-Type": {"application/json"}},
					Body:       io.NopCloser(strings.NewReader(`{"success":false,"errors":[]}`)),
				}, nil
			}))
			err := client.Post(context.Background(), "test", nil, nil)
			if err == nil || calls != 1 {
				t.Fatal("failed POST must not retry")
			}
		})
	}
	calls := 0
	client := contractClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("synthetic transport failure")
	}))
	if err := client.Post(context.Background(), "test", nil, nil); err == nil || calls != 1 {
		t.Fatal("network failure must not retry")
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	calls := 0
	client := contractClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{
			StatusCode: 307,
			Header:     http.Header{"Location": {"https://untrusted.invalid/"}},
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	}))
	var response *http.Response
	if err := client.Post(context.Background(), "test", nil, &response); err != nil {
		t.Fatal("raw redirect response should be available for rejection by issuer")
	}
	defer response.Body.Close()
	if calls != 1 || response.StatusCode != 307 {
		t.Fatal("redirect must not be followed")
	}
}

func TestRequestDeadline(t *testing.T) {
	client := contractClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > 30*time.Second {
			t.Fatal("request must have bounded deadline")
		}
		return nil, context.DeadlineExceeded
	}))
	if err := client.Post(context.Background(), "test", nil, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("deadline error must propagate")
	}
}
