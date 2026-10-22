// Package app composes Git helper dispatch and lazy credential generation.
package app

import (
	"errors"
	"io"

	"github.com/maxouverzou/git-credential-artifacts/internal/artifacts"
	"github.com/maxouverzou/git-credential-artifacts/internal/cloudflare"
	"github.com/maxouverzou/git-credential-artifacts/internal/config"
	"github.com/maxouverzou/git-credential-artifacts/internal/credential"
)

// ErrUnavailable identifies a missing generation dependency, never fallback auth.
var ErrUnavailable = errors.New("credential generation unavailable")

// GetFunc runs only after a get record is fully parsed. A nil response with no
// error means a silent no-op. A response accompanied by an error is discarded.
type GetFunc func(credential.Request) (*credential.Response, error)

// Run reserves stdout for protocol output and diagnostics for sanitized text.
// Unsupported operations return before reading input or invoking get.
func Run(args []string, stdin io.Reader, stdout, diagnostics io.Writer, get GetFunc) error {
	if len(args) != 1 || args[0] != "get" {
		return nil
	}
	request, err := credential.Parse(stdin)
	if err != nil {
		return fail(stdout, diagnostics, "artifacts: invalid credential input\n")
	}
	if get == nil {
		return fail(stdout, diagnostics, "artifacts: credential generation unavailable\n")
	}
	response, err := get(request)
	if err != nil {
		message := "artifacts: credential generation failed\n"
		switch {
		case errors.Is(err, ErrUnavailable):
			message = "artifacts: credential generation unavailable\n"
		case errors.Is(err, artifacts.ErrMissingPath):
			message = "artifacts: missing repository path; set credential.useHttpPath=true\n"
		case errors.Is(err, artifacts.ErrInvalidProtocol):
			message = "artifacts: Artifacts requests require protocol=https\n"
		case errors.Is(err, artifacts.ErrInvalidHost):
			message = "artifacts: invalid Artifacts hostname; use the exact repository hostname without a port or trailing dot\n"
		case errors.Is(err, artifacts.ErrInvalidPath), errors.Is(err, cloudflare.ErrRoute):
			message = "artifacts: invalid repository path; expected git/<namespace>/<repo>.git\n"
		case errors.Is(err, config.ErrScope):
			message = "artifacts: set GIT_CREDENTIAL_ARTIFACTS_SCOPE to read or write\n"
		case errors.Is(err, config.ErrTTL):
			message = "artifacts: set GIT_CREDENTIAL_ARTIFACTS_TTL to decimal seconds between 60 and 31536000\n"
		case errors.Is(err, cloudflare.ErrAuthentication):
			message = "artifacts: set a nonempty, header-safe CLOUDFLARE_API_TOKEN with Artifacts Edit permission\n"
		case errors.Is(err, cloudflare.ErrTimeout):
			message = "artifacts: Cloudflare token request timed out; check network connectivity\n"
		case errors.Is(err, cloudflare.ErrCanceled):
			message = "artifacts: Cloudflare token request canceled\n"
		case errors.Is(err, cloudflare.ErrTransport):
			message = "artifacts: Cloudflare token request failed; check network connectivity\n"
		case errors.Is(err, cloudflare.ErrAPI), errors.Is(err, artifacts.ErrTokenRejected):
			message = "artifacts: Cloudflare rejected token issuance; check API-token permissions and repository access\n"
		case errors.Is(err, cloudflare.ErrResponse), errors.Is(err, artifacts.ErrTokenResponse):
			message = "artifacts: invalid Cloudflare token response; no credential returned\n"
		case errors.Is(err, credential.ErrInvalidResponse):
			message = "artifacts: invalid credential response\n"
		}
		return fail(stdout, diagnostics, message)
	}
	if response == nil {
		return nil
	}
	if err := response.Validate(); err != nil {
		return fail(stdout, diagnostics, "artifacts: invalid credential response\n")
	}
	// Do not log writer errors or retry output after a possibly partial write.
	return credential.WriteResponse(stdout, *response)
}

func fail(stdout, diagnostics io.Writer, message string) error {
	// Fail closed even if the diagnostic writer is broken.
	if err := credential.WriteQuit(stdout); err != nil {
		return err
	}
	n, err := io.WriteString(diagnostics, message)
	if err == nil && n != len(message) {
		return io.ErrShortWrite
	}
	return err
}
