package app

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/maxouverzou/git-credential-artifacts/internal/credential"
)

func TestUnsupportedOperations(t *testing.T) {
	for _, args := range [][]string{nil, {"store"}, {"erase"}, {"unknown"}, {"capability"}, {""}, {"get", "extra"}} {
		var stdout, diagnostics bytes.Buffer
		err := Run(args, forbiddenReader{}, &stdout, &diagnostics, func(credential.Request) (*credential.Response, error) {
			t.Fatal("unsupported operation reached authentication/token handler")
			return nil, nil
		})
		if err != nil || stdout.Len() != 0 || diagnostics.Len() != 0 {
			t.Fatal("unsupported operation must be entirely silent")
		}
	}
}

type forbiddenReader struct{}

func (forbiddenReader) Read([]byte) (int, error) { panic("stdin must not be read") }

func TestSuccessfulGet(t *testing.T) {
	calls := 0
	var stdout, diagnostics bytes.Buffer
	input := "protocol=https\nhost=example.com\npath=git/default/demo.git\nusername=provided\npassword=synthetic-api-secret\n\n"
	err := Run([]string{"get"}, strings.NewReader(input), &stdout, &diagnostics, func(request credential.Request) (*credential.Response, error) {
		calls++
		if request != (credential.Request{Protocol: "https", Host: "example.com", Path: "git/default/demo.git", Username: "provided"}) {
			t.Fatal("unexpected parsed request")
		}
		return &credential.Response{Username: request.Username, Password: "synthetic-repo-token", ExpiryUnix: 1760000000}, nil
	})
	if err != nil || calls != 1 || diagnostics.Len() != 0 {
		t.Fatal("get must call its handler exactly once without diagnostics")
	}
	if stdout.String() != "username=provided\npassword=synthetic-repo-token\npassword_expiry_utc=1760000000\n\n" {
		t.Fatal("stdout must contain only the complete protocol response")
	}
}

func TestSilentGet(t *testing.T) {
	var stdout, diagnostics bytes.Buffer
	err := Run([]string{"get"}, strings.NewReader("host=unrelated.invalid\n\n"), &stdout, &diagnostics, func(credential.Request) (*credential.Response, error) {
		return nil, nil
	})
	if err != nil || stdout.Len() != 0 || diagnostics.Len() != 0 {
		t.Fatal("nil response must be a silent no-op")
	}
}

func TestParseFailureDoesNotCallHandler(t *testing.T) {
	for _, reader := range []io.Reader{
		strings.NewReader("host=valid\nmalformed-synthetic-secret\n"),
		strings.NewReader("host=one\nhost=two\n"),
		strings.NewReader(strings.Repeat("a", credential.MaxInputBytes+1)),
		io.MultiReader(strings.NewReader("host=partial\n"), errorReader{}),
	} {
		var stdout, diagnostics bytes.Buffer
		err := Run([]string{"get"}, reader, &stdout, &diagnostics, func(credential.Request) (*credential.Response, error) {
			t.Fatal("parse failure must not reach authentication/token handler")
			return nil, nil
		})
		if err != nil || stdout.String() != "quit=true\n\n" || diagnostics.String() != "artifacts: invalid credential input\n" {
			t.Fatal("parse failure must fail closed with a sanitized diagnostic")
		}
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("synthetic-secret-reader-error") }

func TestHandlerFailureDiscardsResponse(t *testing.T) {
	for _, failure := range []error{errors.New("synthetic-api-secret synthetic-repo-token"), ErrUnavailable} {
		var stdout, diagnostics bytes.Buffer
		err := Run([]string{"get"}, strings.NewReader("\n"), &stdout, &diagnostics, func(credential.Request) (*credential.Response, error) {
			return &credential.Response{Username: "user", Password: "synthetic-repo-token", ExpiryUnix: 1}, failure
		})
		if err != nil || stdout.String() != "quit=true\n\n" || diagnostics.Len() == 0 || strings.Contains(diagnostics.String(), "synthetic-") {
			t.Fatal("handler failure must emit only quit and a sanitized diagnostic")
		}
	}
	var stdout, diagnostics bytes.Buffer
	if err := Run([]string{"get"}, strings.NewReader(""), &stdout, &diagnostics, nil); err != nil || stdout.String() != "quit=true\n\n" {
		t.Fatal("missing handler must fail closed")
	}
}

func TestInvalidResponseFailsClosed(t *testing.T) {
	for _, response := range []credential.Response{
		{Username: "user\nquit=false", Password: "synthetic-token", ExpiryUnix: 1},
		{Username: "user", Password: "synthetic-token\npassword=attacker", ExpiryUnix: 1},
		{Username: "user", Password: "synthetic-token", ExpiryUnix: 0},
	} {
		var stdout, diagnostics bytes.Buffer
		err := Run([]string{"get"}, strings.NewReader("\n"), &stdout, &diagnostics, func(credential.Request) (*credential.Response, error) {
			return &response, nil
		})
		if err != nil || stdout.String() != "quit=true\n\n" || diagnostics.String() != "artifacts: invalid credential response\n" {
			t.Fatal("invalid response must not emit partial credentials")
		}
	}
}

type brokenWriter struct {
	calls   int
	partial bool
	err     error
}

func (w *brokenWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.partial {
		return len(p) / 2, nil
	}
	if w.err != nil {
		return 1, w.err
	}
	return 0, io.ErrClosedPipe
}

func TestWriterErrorCannotTriggerQuit(t *testing.T) {
	stdout := &brokenWriter{err: credential.ErrInvalidResponse}
	var diagnostics bytes.Buffer
	err := Run([]string{"get"}, strings.NewReader("\n"), stdout, &diagnostics, func(credential.Request) (*credential.Response, error) {
		return &credential.Response{Username: "user", Password: "synthetic-token", ExpiryUnix: 1}, nil
	})
	if !errors.Is(err, credential.ErrInvalidResponse) || stdout.calls != 1 || diagnostics.Len() != 0 {
		t.Fatal("writer error must never be mistaken for pre-write validation failure")
	}
}

func TestOutputErrors(t *testing.T) {
	for _, partial := range []bool{false, true} {
		for _, get := range []GetFunc{
			func(credential.Request) (*credential.Response, error) { return nil, errors.New("synthetic-secret") },
			func(credential.Request) (*credential.Response, error) {
				return &credential.Response{Username: "user", Password: "synthetic-token", ExpiryUnix: 1}, nil
			},
		} {
			stdout := &brokenWriter{partial: partial}
			var diagnostics bytes.Buffer
			err := Run([]string{"get"}, strings.NewReader("\n"), stdout, &diagnostics, get)
			want := io.ErrClosedPipe
			if partial {
				want = io.ErrShortWrite
			}
			if !errors.Is(err, want) || stdout.calls != 1 || diagnostics.Len() != 0 {
				t.Fatal("output error must propagate without retry or response logging")
			}
		}
	}
}

func TestDiagnosticErrorStillWritesQuit(t *testing.T) {
	for _, partial := range []bool{false, true} {
		var stdout bytes.Buffer
		diagnostics := &brokenWriter{partial: partial}
		err := Run([]string{"get"}, strings.NewReader("malformed\n"), &stdout, diagnostics, nil)
		want := io.ErrClosedPipe
		if partial {
			want = io.ErrShortWrite
		}
		if !errors.Is(err, want) || stdout.String() != "quit=true\n\n" || diagnostics.calls != 1 {
			t.Fatal("diagnostic failure must not suppress fail-closed output")
		}
	}
}
