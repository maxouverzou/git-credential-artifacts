// Package artifacts resolves repository identities and issues repository-scoped
// tokens. Resolution never obtains authentication or performs network access.
package artifacts

import (
	"errors"
	"strings"

	"github.com/maxouverzou/git-credential-artifacts/internal/credential"
)

const hostSuffix = "artifacts.cloudflare.net"

var (
	ErrInvalidHost     = errors.New("invalid Artifacts hostname")
	ErrInvalidProtocol = errors.New("Artifacts requires HTTPS")
	ErrMissingPath     = errors.New("missing Artifacts repository path")
	ErrInvalidPath     = errors.New("invalid Artifacts repository path")
)

// Remote identifies exactly one repository. Only Resolve constructs trusted
// values; callers must not build API routes from unvalidated credential input.
type Remote struct {
	AccountID  string
	Namespace  string
	Repository string
}

// Resolve returns (zero, false, nil) for unrelated hosts, (zero, true, error)
// for recognized-invalid requests, and (remote, true, nil) for valid requests.
// Host recognition is deliberately broader than acceptance so malformed account
// labels, explicit ports, and trailing DNS dots fail closed. No input value is
// interpolated into errors. Git's fields are never URL-decoded or normalized.
func Resolve(request credential.Request) (Remote, bool, error) {
	host := asciiLower(request.Host)
	// This is classification only, NOT authority parsing or normalization.
	// Any port spelling and any number of trailing dots remain invalid below.
	hostname, _, _ := strings.Cut(host, ":")
	hostname = strings.TrimRight(hostname, ".")
	if hostname != hostSuffix && !strings.HasSuffix(hostname, "."+hostSuffix) {
		return Remote{}, false, nil
	}
	account, ok := strings.CutSuffix(host, "."+hostSuffix)
	if !ok || len(account) != 32 || !isHex(account) {
		return Remote{}, true, ErrInvalidHost
	}
	if request.Protocol != "https" {
		return Remote{}, true, ErrInvalidProtocol
	}
	if request.Path == "" {
		return Remote{}, true, ErrMissingPath
	}
	segments := strings.Split(request.Path, "/")
	if len(segments) != 3 || segments[0] != "git" ||
		len(segments[1]) < 2 || len(segments[1]) > 63 || !isName(segments[1]) {
		return Remote{}, true, ErrInvalidPath
	}
	repository, ok := strings.CutSuffix(segments[2], ".git")
	if !ok || !isName(repository) {
		return Remote{}, true, ErrInvalidPath
	}
	return Remote{AccountID: account, Namespace: segments[1], Repository: repository}, true, nil
}

// DNS matching is ASCII case-insensitive, not Unicode case folding.
func asciiLower(value string) string {
	b := []byte(value)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

func isHex(value string) bool {
	for i := range len(value) {
		c := value[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func isName(value string) bool {
	if value == "" || !isAlphanumeric(value[0]) {
		return false
	}
	for i := 1; i < len(value); i++ {
		c := value[i]
		if !isAlphanumeric(c) && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

func isAlphanumeric(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}
