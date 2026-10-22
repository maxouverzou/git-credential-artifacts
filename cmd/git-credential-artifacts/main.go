// Command git-credential-artifacts generates Git credentials for Cloudflare Artifacts.
package main

import (
	"context"
	"io"
	"os"

	"github.com/maxouverzou/git-credential-artifacts/internal/app"
)

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "-?" || args[0] == "help") {
		_, err := io.WriteString(stdout, `Description:

  Generate repository-scoped Git credentials for Cloudflare Artifacts.

Usage:
  git-credential-artifacts <operation>

Operations:
  get     Return a credential for a Git request (Git protocol)
  store   Ignore credential storage requests
  erase   Ignore credential erase requests

Options:
  -?, -h, --help  Show help and usage information
`)
		return err
	}
	return app.Run(args, stdin, stdout, stderr, app.NewGet(context.Background()))
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		os.Exit(1)
	}
}
