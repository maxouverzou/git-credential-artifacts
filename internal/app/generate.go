package app

import (
	"context"
	"time"

	"github.com/maxouverzou/git-credential-artifacts/internal/artifacts"
	"github.com/maxouverzou/git-credential-artifacts/internal/cloudflare"
	"github.com/maxouverzou/git-credential-artifacts/internal/config"
	"github.com/maxouverzou/git-credential-artifacts/internal/credential"
)

// TokenIssuer returns only validated repository credentials, never API auth.
type TokenIssuer interface {
	Issue(context.Context, artifacts.Remote, config.Settings) (artifacts.Token, error)
}

// Dependencies are lazy acquisition seams for offline tests and integration
// harnesses. Production uses NewGet; Git input/environment cannot replace these.
type Dependencies struct {
	LoadSettings func() (config.Settings, error)
	NewIssuer    func() (TokenIssuer, error)
}

// NewGet builds a handler without reading configuration/authentication or
// constructing the SDK. Acquisition happens only after a fully parsed valid
// Artifacts request; unsupported operations and unrelated hosts remain no-ops.
func NewGet(ctx context.Context) GetFunc {
	return NewGetWithDependencies(ctx, Dependencies{
		LoadSettings: config.Load,
		NewIssuer: func() (TokenIssuer, error) {
			client, err := cloudflare.New(nil)
			if err != nil {
				return nil, err
			}
			return artifacts.NewIssuer(client, time.Now), nil
		},
	})
}

func NewGetWithDependencies(ctx context.Context, deps Dependencies) GetFunc {
	return ResolveArtifacts(func(remote artifacts.Remote, username string) (*credential.Response, error) {
		if username == "" {
			username = "x"
		}
		if err := credential.ValidateUsername(username); err != nil {
			return nil, err
		}
		if deps.LoadSettings == nil || deps.NewIssuer == nil {
			return nil, ErrUnavailable
		}
		settings, err := deps.LoadSettings()
		if err != nil {
			return nil, err
		}
		if err := settings.Validate(); err != nil {
			return nil, err
		}
		issuer, err := deps.NewIssuer()
		if err != nil {
			return nil, err
		}
		if issuer == nil {
			return nil, ErrUnavailable
		}
		token, err := issuer.Issue(ctx, remote, settings)
		if err != nil {
			return nil, err
		}
		return &credential.Response{Username: username, Password: token.Secret, ExpiryUnix: token.ExpiryUnix}, nil
	})
}
