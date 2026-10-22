// Package cloudflare owns authentication and the trusted SDK transport boundary.
package cloudflare

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	sdk "github.com/cloudflare/cloudflare-go/v6"
	"github.com/cloudflare/cloudflare-go/v6/option"
	"github.com/maxouverzou/git-credential-artifacts/internal/artifacts"
	"github.com/maxouverzou/git-credential-artifacts/internal/credential"
)

const (
	APIOrigin       = "https://api.cloudflare.com/client/v4/"
	RequestDeadline = 30 * time.Second
)

// These errors deliberately contain no upstream error text or response data.
var (
	ErrAuthentication = errors.New("Cloudflare authentication requires a nonempty header-safe CLOUDFLARE_API_TOKEN")
	ErrRoute          = errors.New("invalid Cloudflare token request route")
	ErrTimeout        = errors.New("Cloudflare request timed out")
	ErrCanceled       = errors.New("Cloudflare request canceled")
	ErrTransport      = errors.New("Cloudflare request failed")
	ErrAPI            = errors.New("Cloudflare API rejected the request")
	ErrResponse       = errors.New("invalid Cloudflare API response")
)

// Client does not expose SDK options, arbitrary URLs, or authentication values.
type Client struct{ sdk *sdk.Client }

// New uses only the supported SDK API-token environment variable. Supplying an
// explicit option list (rather than NewClient's ambient defaults) prevents even
// malformed base URL or alternative-auth environment values from being applied.
// A nil transport selects the standard HTTPS transport; injection is for tests,
// not a runtime endpoint/configuration override. Construct only after resolution
// and configuration validation.
func New(transport http.RoundTripper) (*Client, error) {
	token := os.Getenv("CLOUDFLARE_API_TOKEN")
	if token == "" {
		return nil, ErrAuthentication
	}
	for i := range len(token) {
		if token[i] < 0x21 || token[i] > 0x7e {
			return nil, ErrAuthentication
		}
	}
	if transport == nil {
		transport = http.DefaultTransport
	}
	httpClient := &http.Client{
		Transport:     guardedTransport{next: transport},
		Timeout:       RequestDeadline,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return &Client{sdk: &sdk.Client{Options: []option.RequestOption{
		option.WithBaseURL(APIOrigin),
		option.WithAPIToken(token),
		option.WithMaxRetries(0),
		option.WithRequestTimeout(RequestDeadline),
		option.WithHTTPClient(httpClient),
	}}}, nil
}

// PostToken permits only a validated repository identity's namespace-token route.
// The issuance layer owns JSON types and envelope/token validation. The total
// context deadline remains active through SDK decoding and response body reads.
func (c *Client) PostToken(ctx context.Context, remote artifacts.Remote, body, result any) error {
	route, err := tokenRoute(remote)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, RequestDeadline)
	defer cancel()
	err = c.sdk.Post(ctx, route, body, result)
	if err == nil && ctx.Err() == nil {
		return nil
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(ctx.Err(), context.DeadlineExceeded):
		return ErrTimeout
	case errors.Is(err, context.Canceled), errors.Is(ctx.Err(), context.Canceled):
		return ErrCanceled
	case errors.Is(err, ErrAPI):
		return ErrAPI
	case errors.Is(err, ErrRoute):
		return ErrRoute
	case errors.Is(err, ErrTransport):
		return ErrTransport
	default:
		return ErrResponse
	}
}

func tokenRoute(remote artifacts.Remote) (string, error) {
	resolved, recognized, err := artifacts.Resolve(credential.Request{
		Protocol: "https", Host: remote.AccountID + ".artifacts.cloudflare.net",
		Path: "git/" + remote.Namespace + "/" + remote.Repository + ".git",
	})
	if err != nil || !recognized || resolved != remote {
		return "", ErrRoute
	}
	return "accounts/" + url.PathEscape(remote.AccountID) + "/artifacts/namespaces/" + url.PathEscape(remote.Namespace) + "/tokens", nil
}

type guardedTransport struct{ next http.RoundTripper }

func (t guardedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	// Defense in depth: no alternate origin, redirect, userinfo, query, encoded
	// boundary, Host override, or alternate authentication may reach transport.
	if r.URL.Scheme != "https" || r.URL.Host != "api.cloudflare.com" || r.URL.User != nil ||
		r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Fragment != "" || r.URL.Opaque != "" ||
		r.Host != "" && r.Host != "api.cloudflare.com" || r.Method != http.MethodPost ||
		r.Header.Get("X-Auth-Key") != "" || r.Header.Get("X-Auth-Email") != "" || r.Header.Get("X-Auth-User-Service-Key") != "" {
		return nil, ErrRoute
	}
	// Check exact route grammar by rebuilding it from the path segments.
	const prefix = "/client/v4/"
	path := r.URL.Path
	if len(path) < len(prefix) || path[:len(prefix)] != prefix {
		return nil, ErrRoute
	}
	// Splitting instead of URL-decoding prevents encoded separators from changing
	// identity. The canonical comparison also rejects all encoded path spellings.
	segments := strings.Split(path[len(prefix):], "/")
	if len(segments) != 6 || segments[0] != "accounts" || segments[2] != "artifacts" || segments[3] != "namespaces" || segments[5] != "tokens" {
		return nil, ErrRoute
	}
	account, namespace := segments[1], segments[4]
	route, err := tokenRoute(artifacts.Remote{AccountID: account, Namespace: namespace, Repository: "validation"})
	if err != nil || r.URL.EscapedPath() != prefix+route {
		return nil, ErrRoute
	}
	response, err := t.next.RoundTrip(r)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, context.DeadlineExceeded
		}
		if errors.Is(err, context.Canceled) {
			return nil, context.Canceled
		}
		return nil, ErrTransport
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if response.Body != nil {
			response.Body.Close()
		}
		return nil, ErrAPI
	}
	return response, nil
}
