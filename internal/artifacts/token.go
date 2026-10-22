package artifacts

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/maxouverzou/git-credential-artifacts/internal/config"
)

var (
	ErrTokenResponse = errors.New("invalid Artifacts token response")
	ErrTokenRejected = errors.New("Artifacts API did not issue a token")
)

// Token contains only the repository secret and reconciled Unix-second expiry.
// It must not be logged or persisted by the generator.
type Token struct {
	Secret     string
	ExpiryUnix int64
}

// TokenClient is implemented by the guarded Cloudflare SDK boundary. Errors
// must be sanitized; implementations must validate remote and enforce the trusted
// endpoint, single-attempt policy, and deadline. Kept here to avoid coupling
// resolution to SDK construction (and a package import cycle).
type TokenClient interface {
	PostToken(context.Context, Remote, any, any) error
}

type Issuer struct {
	client TokenClient
	now    func() time.Time
}

// NewIssuer requires a guarded client and clock; production supplies time.Now.
func NewIssuer(client TokenClient, now func() time.Time) *Issuer {
	return &Issuer{client: client, now: now}
}

type tokenRequest struct {
	Repo  string `json:"repo"`
	Scope string `json:"scope"`
	TTL   int    `json:"ttl"`
}

type tokenEnvelope struct {
	Success bool         `json:"success"`
	Result  *tokenResult `json:"result"`
}

type tokenResult struct {
	Plaintext string `json:"plaintext"`
	Scope     string `json:"scope"`
	ExpiresAt string `json:"expires_at"`
}

// Issue mints once and fails closed without returning partial token data. Scope
// and TTL are rechecked for callers constructing settings without config.Load.
func (i *Issuer) Issue(ctx context.Context, remote Remote, settings config.Settings) (Token, error) {
	if err := settings.Validate(); err != nil {
		return Token{}, err
	}
	// Custom SDK requests decode the whole envelope, not just result. Request raw
	// bytes so json.Unmarshal checks the entire document: the pinned SDK's default
	// decoder accepts a valid JSON prefix followed by trailing garbage.
	var raw []byte
	if err := i.client.PostToken(ctx, remote, tokenRequest{remote.Repository, settings.Scope, settings.TTL}, &raw); err != nil {
		return Token{}, err
	}
	var envelope tokenEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return Token{}, ErrTokenResponse
	}
	if !envelope.Success {
		return Token{}, ErrTokenRejected
	}
	if envelope.Result == nil || envelope.Result.Scope != settings.Scope {
		return Token{}, ErrTokenResponse
	}
	return validateToken(envelope.Result.Plaintext, envelope.Result.ExpiresAt, i.now())
}

// time.Parse accepts some non-RFC3339 spellings (e.g. comma fractions and
// out-of-range timezone components). Check syntax before calendar validation.
var rfc3339Syntax = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$`)

// validTokenSecret retains the documented v1 contract and accepts the observed
// v2_x format. The v2 payload is opaque: do not impose v1's hex encoding or
// fixed length. Bound it and permit only URL-safe characters, never delimiters
// or whitespace. Unknown versions and variants remain unsupported.
func validTokenSecret(secret string) bool {
	if payload, ok := strings.CutPrefix(secret, "art_v1_"); ok {
		if len(payload) != 40 {
			return false
		}
		for _, c := range []byte(payload) {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return false
			}
		}
		return true
	}
	payload, ok := strings.CutPrefix(secret, "art_v2_x_")
	if !ok || payload == "" || len(secret) > 4096 {
		return false
	}
	for _, c := range []byte(payload) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func validateToken(plaintext, expiresAt string, now time.Time) (Token, error) {
	secret, suffix, ok := strings.Cut(plaintext, "?expires=")
	if !ok || !validTokenSecret(secret) || suffix == "" {
		return Token{}, ErrTokenResponse
	}
	for _, c := range []byte(suffix) {
		if c < '0' || c > '9' {
			return Token{}, ErrTokenResponse
		}
	}
	expiry, err := strconv.ParseInt(suffix, 10, 64)
	if err != nil || expiry <= 0 || expiry <= now.Unix() || !rfc3339Syntax.MatchString(expiresAt) {
		return Token{}, ErrTokenResponse
	}
	timestamp, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil || timestamp.Unix() != expiry {
		return Token{}, ErrTokenResponse
	}
	return Token{Secret: secret, ExpiryUnix: expiry}, nil
}
