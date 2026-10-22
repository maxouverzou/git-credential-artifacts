// Package credential implements the line-oriented Git credential protocol.
// It has no authentication, network, storage, or remote-resolution dependencies.
package credential

import (
	"bufio"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode"
)

const (
	// MaxInputBytes bounds a single record, including its terminating blank line.
	MaxInputBytes = 64 * 1024
	// MaxLineBytes is Git's documented line limit, including a trailing LF.
	MaxLineBytes = 65535
)

var (
	ErrInvalidInput    = errors.New("invalid credential input")
	ErrInputTooLarge   = errors.New("credential input too large")
	ErrReadInput       = errors.New("cannot read credential input")
	ErrInvalidResponse = errors.New("invalid credential response")
)

// Request retains only fields consumed by this generator. Passwords, URLs,
// capabilities, and other unknown fields are discarded, never echoed.
type Request struct {
	Protocol string
	Host     string
	Path     string
	Username string
}

// Parse reads one record through a blank line or EOF. Duplicate consumed fields
// are rejected, even when empty or identical. Unknown fields may repeat. Any
// failure returns a zero Request so callers cannot use partially parsed input.
// Controls are rejected in keys and values; values otherwise remain byte-for-byte.
func Parse(r io.Reader) (Request, error) {
	reader := bufio.NewReader(io.LimitReader(r, MaxInputBytes+1))
	var request Request
	seen := make(map[string]bool, 4)
	total := 0
	for {
		line, err := reader.ReadString('\n')
		total += len(line)
		if total > MaxInputBytes || len(line) > MaxLineBytes {
			return Request{}, ErrInputTooLarge
		}
		if err != nil && !errors.Is(err, io.EOF) {
			// Reader errors can contain secrets; don't retain their text.
			return Request{}, ErrReadInput
		}
		line = strings.TrimSuffix(line, "\n")
		if line == "" {
			return request, nil
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" || hasControl(key) || hasControl(value) {
			return Request{}, ErrInvalidInput
		}
		var field *string
		switch key {
		case "protocol":
			field = &request.Protocol
		case "host":
			field = &request.Host
		case "path":
			field = &request.Path
		case "username":
			field = &request.Username
		}
		if field != nil {
			if seen[key] {
				return Request{}, ErrInvalidInput
			}
			seen[key] = true
			*field = value
		}
		if errors.Is(err, io.EOF) {
			return request, nil
		}
	}
}

// Response is a complete Basic credential. ExpiryUnix is an already-validated
// Unix-second expiry; token format and clock validation belong to the issuer.
type Response struct {
	Username   string
	Password   string
	ExpiryUnix int64
}

// ValidateUsername requires a nonempty, protocol-safe Basic username. It can be
// used before issuance so an unsafe supplied username never triggers minting.
func ValidateUsername(username string) error {
	if username == "" || hasControl(username) || len("username="+username+"\n") > MaxLineBytes {
		return ErrInvalidResponse
	}
	return nil
}

// Validate checks completeness and safe protocol representation, without
// checking token format or expiry against a clock.
func (response Response) Validate() error {
	if ValidateUsername(response.Username) != nil || response.Password == "" || response.ExpiryUnix <= 0 ||
		hasControl(response.Password) {
		return ErrInvalidResponse
	}
	username := "username=" + response.Username + "\n"
	password := "password=" + response.Password + "\n"
	expiry := "password_expiry_utc=" + strconv.FormatInt(response.ExpiryUnix, 10) + "\n\n"
	if len(username) > MaxLineBytes || len(password) > MaxLineBytes ||
		len(username)+len(password)+len(expiry) > MaxInputBytes {
		return ErrInvalidResponse
	}
	return nil
}

// WriteResponse validates the entire response before touching w, preventing
// invalid values from emitting partial credentials. It never logs values.
// An I/O failure may still leave partial bytes at the destination; it cannot
// be undone and must not be followed by another protocol response.
func WriteResponse(w io.Writer, response Response) error {
	if err := response.Validate(); err != nil {
		return err
	}
	return write(w, "username="+response.Username+"\npassword="+response.Password+
		"\npassword_expiry_utc="+strconv.FormatInt(response.ExpiryUnix, 10)+"\n\n")
}

// WriteQuit emits only Git's fail-closed attribute and a terminating blank line.
func WriteQuit(w io.Writer) error {
	return write(w, "quit=true\n\n")
}

func write(w io.Writer, record string) error {
	n, err := io.WriteString(w, record)
	if err == nil && n != len(record) {
		return io.ErrShortWrite
	}
	return err
}

func hasControl(value string) bool {
	return strings.ContainsFunc(value, unicode.IsControl)
}
