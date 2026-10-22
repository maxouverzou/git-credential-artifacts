// Package config loads minting defaults, never Git input or stored credentials.
package config

import (
	"errors"
	"os"
	"strconv"
)

const (
	ScopeEnv = "GIT_CREDENTIAL_ARTIFACTS_SCOPE"
	TTLEnv   = "GIT_CREDENTIAL_ARTIFACTS_TTL"
)

var (
	ErrScope = errors.New("Artifacts scope must be read or write")
	ErrTTL   = errors.New("Artifacts TTL must be decimal seconds between 60 and 31536000")
)

type Settings struct {
	Scope string
	TTL   int
}

// Validate checks settings constructed directly by application callers.
func (s Settings) Validate() error {
	if s.Scope != "read" && s.Scope != "write" {
		return ErrScope
	}
	if s.TTL < 60 || s.TTL > 31536000 {
		return ErrTTL
	}
	return nil
}

// Load uses environment values over defaults. Present empty values are invalid.
func Load() (Settings, error) { return LoadWithLookup(os.LookupEnv) }

// LoadWithLookup permits deterministic tests without reading ambient settings.
func LoadWithLookup(lookup func(string) (string, bool)) (Settings, error) {
	settings := Settings{Scope: "write", TTL: 3600}
	if value, ok := lookup(ScopeEnv); ok {
		if value != "read" && value != "write" {
			return Settings{}, ErrScope
		}
		settings.Scope = value
	}
	if value, ok := lookup(TTLEnv); ok {
		if value == "" {
			return Settings{}, ErrTTL
		}
		for i := range len(value) {
			if value[i] < '0' || value[i] > '9' {
				return Settings{}, ErrTTL
			}
		}
		ttl, err := strconv.ParseUint(value, 10, 32)
		if err != nil || ttl < 60 || ttl > 31536000 {
			return Settings{}, ErrTTL
		}
		settings.TTL = int(ttl)
	}
	return settings, nil
}
