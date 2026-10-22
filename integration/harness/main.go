// This test-only executable runs the real application with an injected transport.
// It is not a production endpoint override and is never installed as the helper.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/maxouverzou/git-credential-artifacts/integration/fixture"
	"github.com/maxouverzou/git-credential-artifacts/internal/app"
	"github.com/maxouverzou/git-credential-artifacts/internal/artifacts"
	"github.com/maxouverzou/git-credential-artifacts/internal/cloudflare"
	"github.com/maxouverzou/git-credential-artifacts/internal/config"
)

func exchange(event fixture.Event) (fixture.Reply, error) {
	conn, err := net.DialTimeout("unix", os.Getenv("ARTIFACTS_TEST_SOCKET"), 5*time.Second)
	if err != nil {
		return fixture.Reply{}, errors.New("fixture connection failed")
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return fixture.Reply{}, err
	}
	if err := json.NewEncoder(conn).Encode(event); err != nil {
		return fixture.Reply{}, errors.New("fixture write failed")
	}
	var reply fixture.Reply
	if err := json.NewDecoder(conn).Decode(&reply); err != nil {
		return fixture.Reply{}, errors.New("fixture read failed")
	}
	return reply, nil
}

type transport struct{}

func (transport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodPost || r.URL.Scheme != "https" || r.URL.Host != "api.cloudflare.com" || r.Header.Get("Authorization") != "Bearer "+fixture.APISecret {
		return nil, errors.New("invalid fixture request")
	}
	var body struct {
		Repo  string `json:"repo"`
		Scope string `json:"scope"`
		TTL   int    `json:"ttl"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return nil, errors.New("invalid fixture body")
	}
	reply, err := exchange(fixture.Event{Kind: "api", Method: r.Method, Path: r.URL.EscapedPath(), Repo: body.Repo, Scope: body.Scope, TTL: body.TTL})
	if err != nil {
		return nil, err
	}
	if reply.TransportError {
		return nil, errors.New(fixture.APISecret + " synthetic-repository-secret")
	}
	return &http.Response{StatusCode: reply.Status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(reply.Body))}, nil
}

func run() error {
	args := os.Args[1:]
	if len(args) == 0 {
		return errors.New("missing fixture role")
	}
	role := args[0]
	if role != "generator" && role != "sentinel" {
		// GIT_ASKPASS passes a prompt, not a helper operation. Never log the prompt.
		_, _ = exchange(fixture.Event{Kind: "prompt"})
		return errors.New("prompt sentinel invoked")
	}
	args = args[1:]
	operation := ""
	if len(args) == 1 {
		operation = args[0]
	}
	if _, err := exchange(fixture.Event{Kind: role, Operation: operation}); err != nil {
		return err
	}
	if role == "sentinel" {
		return nil
	}
	get := app.NewGetWithDependencies(context.Background(), app.Dependencies{
		LoadSettings: config.Load,
		NewIssuer: func() (app.TokenIssuer, error) {
			client, err := cloudflare.New(transport{})
			if err != nil {
				return nil, err
			}
			return artifacts.NewIssuer(client, time.Now), nil
		},
	})
	return app.Run(args, os.Stdin, os.Stdout, os.Stderr, get)
}

func main() {
	if err := run(); err != nil {
		os.Exit(1)
	} // Never print raw fixture/I/O errors.
}
