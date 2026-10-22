package config

import (
	"errors"
	"testing"
)

func TestSettings(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
		want Settings
		err  error
	}{
		{name: "defaults", want: Settings{"write", 3600}},
		{name: "scope", env: map[string]string{ScopeEnv: "read"}, want: Settings{"read", 3600}},
		{name: "ttl", env: map[string]string{TTLEnv: "60"}, want: Settings{"write", 60}},
		{name: "both", env: map[string]string{ScopeEnv: "read", TTLEnv: "31536000"}, want: Settings{"read", 31536000}},
		{name: "explicit defaults", env: map[string]string{ScopeEnv: "write", TTLEnv: "3600"}, want: Settings{"write", 3600}},
		{name: "leading zeros", env: map[string]string{TTLEnv: "00060"}, want: Settings{"write", 60}},
		{name: "empty scope", env: map[string]string{ScopeEnv: ""}, err: ErrScope},
		{name: "upper scope", env: map[string]string{ScopeEnv: "READ"}, err: ErrScope},
		{name: "unknown scope", env: map[string]string{ScopeEnv: "admin"}, err: ErrScope},
		{name: "space scope", env: map[string]string{ScopeEnv: "read "}, err: ErrScope},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := LoadWithLookup(func(k string) (string, bool) { v, ok := tc.env[k]; return v, ok })
			if !errors.Is(err, tc.err) || got != tc.want {
				t.Fatalf("got %v, %v; want %v, %v", got, err, tc.want, tc.err)
			}
		})
	}
	for _, value := range []string{"", "0", "59", "31536001", "-60", "+60", "60.0", "6e2", " 60", "60\n", "６０", "4294967296", "999999999999999999999999999999999999", "seeded-secret"} {
		t.Run("invalid TTL "+value, func(t *testing.T) {
			got, err := LoadWithLookup(func(k string) (string, bool) { return value, k == TTLEnv })
			if err != ErrTTL || got != (Settings{}) {
				t.Fatal("invalid TTL accepted or echoed")
			}
		})
	}
}

func TestValidateSettings(t *testing.T) {
	for _, tc := range []struct {
		settings Settings
		want     error
	}{
		{Settings{"write", 3600}, nil},
		{Settings{"read", 60}, nil},
		{Settings{"write", 31536000}, nil},
		{Settings{"", 3600}, ErrScope},
		{Settings{"admin", 3600}, ErrScope},
		{Settings{"read", -1}, ErrTTL},
		{Settings{"read", 59}, ErrTTL},
		{Settings{"write", 31536001}, ErrTTL},
	} {
		if err := tc.settings.Validate(); err != tc.want {
			t.Fatal("incorrect direct settings validation")
		}
	}
}

func TestLoadEnvironment(t *testing.T) {
	t.Setenv(ScopeEnv, "read")
	t.Setenv(TTLEnv, "120")
	got, err := Load()
	if err != nil || got != (Settings{"read", 120}) {
		t.Fatal("environment not loaded")
	}
}
