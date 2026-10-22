package app

import (
	"github.com/maxouverzou/git-credential-artifacts/internal/artifacts"
	"github.com/maxouverzou/git-credential-artifacts/internal/credential"
)

// ArtifactsGetFunc is the post-resolution credential-generation boundary.
// Authentication/configuration/API construction must happen inside this callback,
// never before ResolveArtifacts has accepted the remote.
type ArtifactsGetFunc func(artifacts.Remote, string) (*credential.Response, error)

// ResolveArtifacts gates generation on a fully validated Artifacts request.
// The callback receives the resolved remote and supplied username unchanged.
// A nil callback fails closed for valid requests.
func ResolveArtifacts(get ArtifactsGetFunc) GetFunc {
	return func(request credential.Request) (*credential.Response, error) {
		remote, recognized, err := artifacts.Resolve(request)
		if err != nil {
			return nil, err
		}
		if !recognized {
			return nil, nil
		}
		if get == nil {
			return nil, ErrUnavailable
		}
		return get(remote, request.Username)
	}
}
