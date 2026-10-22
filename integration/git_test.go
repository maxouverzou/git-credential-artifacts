// These tests require explicitly supplied executables. Unit-test workflows skip
// them visibly; Nix integration checks require and supply the complete matrix.
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/maxouverzou/git-credential-artifacts/integration/fixture"
)

const account = "0123456789abcdef0123456789abcdef"
const host = account + ".artifacts.cloudflare.net"
const repository = "https://" + host + "/git/default/demo.git"

type backend struct {
	mu       sync.Mutex
	events   []fixture.Event
	tokens   []string
	mode     string
	lifetime int64
}

func (b *backend) serve(event fixture.Event) fixture.Reply {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = append(b.events, event)
	if event.Kind != "api" {
		return fixture.Reply{Status: 200}
	}
	id := len(b.tokens) + 1
	secret := fmt.Sprintf("art_v1_%040x", id)
	b.tokens = append(b.tokens, secret)
	lifetime := b.lifetime
	if lifetime == 0 {
		lifetime = 3600
	}
	expiry := time.Now().Unix() + lifetime
	scope := event.Scope
	if b.mode == "scope" {
		scope = "unexpected"
	}
	plaintext := fmt.Sprintf("%s?expires=%d", secret, expiry)
	if b.mode == "expiry" {
		plaintext += "?expires=bad"
	}
	body, _ := json.Marshal(map[string]any{"success": b.mode != "rejected", "result": map[string]any{"plaintext": plaintext, "scope": scope, "expires_at": time.Unix(expiry, 0).UTC().Format(time.RFC3339)}})
	reply := fixture.Reply{Status: 200, Body: string(body)}
	switch b.mode {
	case "api":
		reply.Status = 403
		reply.Body = fixture.APISecret + secret
	case "json":
		reply.Body = fixture.APISecret + secret
	case "transport":
		reply.TransportError = true
	case "missing":
		reply.Body = `{"success":true}`
	}
	return reply
}
func (b *backend) set(mode string, lifetime int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.mode = mode
	b.lifetime = lifetime
}
func (b *backend) count(kind, op string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, e := range b.events {
		if e.Kind == kind && (op == "" || e.Operation == op) {
			n++
		}
	}
	return n
}
func (b *backend) check(t *testing.T, diagnostics string) {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if strings.Contains(diagnostics, fixture.APISecret) || strings.Contains(diagnostics, "synthetic-repository-secret") {
		t.Error("seeded secret leaked in diagnostics")
	}
	for _, secret := range b.tokens {
		if strings.Contains(diagnostics, secret) {
			t.Error("repository token leaked in diagnostics")
		}
	}
	for _, event := range b.events {
		raw, _ := json.Marshal(event)
		if strings.Contains(string(raw), fixture.APISecret) || strings.Contains(string(raw), "art_v1_") {
			t.Error("fixture event log contains credentials")
		}
		if event.Kind == "api" && (event.Method != "POST" || !strings.HasPrefix(event.Path, "/client/v4/accounts/") || !strings.HasSuffix(event.Path, "/tokens")) {
			t.Error("unexpected issuance or revocation route")
		}
	}
}

type gitFixture struct {
	t                                                    *testing.T
	git, helper, production, home, config, cache, socket string
	env                                                  map[string]string
	backend                                              *backend
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
func newFixture(t *testing.T) *gitFixture {
	t.Helper()
	required := os.Getenv("ARTIFACTS_INTEGRATION_REQUIRED") == "1"
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		if required {
			t.Fatal("Git/cache integration unsupported on this platform")
		}
		t.Skip("Git/cache integration requires Linux or Darwin Unix sockets")
	}
	git, helper, production := os.Getenv("ARTIFACTS_TEST_GIT"), os.Getenv("ARTIFACTS_TEST_HELPER"), os.Getenv("ARTIFACTS_TEST_PRODUCTION_HELPER")
	if git == "" || helper == "" || production == "" {
		if required {
			t.Fatal("integration check requires explicit Git, harness, and production executable paths")
		}
		t.Skip("Git/cache integration not configured: use the flake's git-current/git-245 checks")
	}
	for _, path := range []string{git, helper, production} {
		info, err := os.Stat(path)
		if !filepath.IsAbs(path) || err != nil || info.Mode()&0111 == 0 {
			t.Fatal("integration executable must be an absolute executable path")
		}
	}
	// /tmp keeps Unix socket paths short even on Darwin's long per-user TMPDIR.
	root, err := os.MkdirTemp("/tmp", "ach-")
	if err != nil {
		t.Fatal("cannot create private integration directory")
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	home := filepath.Join(root, "h")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal("cannot create isolated HOME")
	}
	f := &gitFixture{t: t, git: git, helper: helper, production: production, home: home, config: filepath.Join(home, "gitconfig"), cache: filepath.Join(root, "c"), socket: filepath.Join(root, "b"), backend: &backend{}}
	f.env = map[string]string{
		"HOME": home, "XDG_CONFIG_HOME": home, "PATH": filepath.Dir(git), "LANG": "C", "LC_ALL": "C",
		"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": os.DevNull, "GIT_CONFIG_GLOBAL": f.config,
		"GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": helper, "SSH_ASKPASS": helper,
		"CLOUDFLARE_API_TOKEN": fixture.APISecret, "GIT_CREDENTIAL_ARTIFACTS_SCOPE": "write", "GIT_CREDENTIAL_ARTIFACTS_TTL": "3600",
		"ARTIFACTS_TEST_SOCKET": f.socket,
		// Avoid a one-second race-runtime exit delay on every helper invocation.
		"GORACE": "atexit_sleep_ms=0",
	}
	listener, err := net.Listen("unix", f.socket)
	if err != nil {
		t.Fatal("Unix-socket fixture unavailable")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			var event fixture.Event
			if err := json.NewDecoder(conn).Decode(&event); err == nil {
				json.NewEncoder(conn).Encode(f.backend.serve(event))
			}
			conn.Close()
		}
	}()
	t.Cleanup(func() {
		// Only this fixture's private daemon is stopped, never the default socket.
		_, _, err := f.command(f.git, []string{"credential-cache", "--socket=" + f.cache, "exit"}, "")
		if err != nil {
			t.Error("private credential-cache cleanup failed")
		}
		listener.Close()
		<-done
		f.backend.check(t, "")
	})
	version, stderr, err := f.command(git, []string{"--version"}, "")
	if err != nil || stderr != "" {
		t.Fatal("supplied Git is unavailable")
	}
	if want := os.Getenv("ARTIFACTS_TEST_GIT_VERSION"); want != "" && strings.TrimSpace(version) != "git version "+want {
		t.Fatal("supplied Git version does not match the declared matrix")
	}
	t.Log(strings.TrimSpace(version) + "; " + runtime.GOOS + "/" + runtime.GOARCH + "; private built-in cache")
	for _, item := range []struct{ key, value string }{
		{"credential.helper", ""},
		{"credential.helper", "cache --timeout=300 --socket=" + f.cache},
		{"credential.helper", "!exec " + shellQuote(helper) + " generator"},
		{"credential.helper", "!exec " + shellQuote(helper) + " sentinel"},
		{"credential.useHttpPath", "true"},
	} {
		_, _, err := f.command(git, []string{"config", "--file", f.config, "--add", item.key, item.value}, "")
		if err != nil {
			t.Fatal("isolated credential configuration failed")
		}
	}
	return f
}
func (f *gitFixture) command(binary string, args []string, input string) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = f.home
	for k, v := range f.env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Stdin = strings.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	f.backend.check(f.t, stderr.String())
	if strings.Contains(stdout.String(), fixture.APISecret) {
		f.t.Error("API credential leaked on stdout")
	}
	return stdout.String(), stderr.String(), err
}
func parseRecord(t *testing.T, raw string) map[string]string {
	t.Helper()
	record := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(raw, "\n"), "\n") {
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || record[k] != "" {
			t.Fatal("non-protocol or duplicate credential output")
		}
		switch k {
		case "protocol", "host", "path", "username", "password", "password_expiry_utc":
		default:
			t.Fatal("unexpected protocol output field")
		}
		record[k] = v
	}
	return record
}
func (f *gitFixture) fill(url string) string {
	f.t.Helper()
	stdout, stderr, err := f.command(f.git, []string{"credential", "fill"}, "url="+url+"\n\n")
	if err != nil || stderr != "" {
		f.t.Fatal("Git credential fill failed unexpectedly (diagnostics withheld)")
	}
	record := parseRecord(f.t, stdout)
	expiry, err := strconv.ParseInt(record["password_expiry_utc"], 10, 64)
	if record["protocol"] != "https" || record["username"] != "x" || len(record["password"]) != 47 || !strings.HasPrefix(record["password"], "art_v1_") || err != nil || expiry <= time.Now().Unix() {
		f.t.Fatal("Git did not preserve the complete expiring credential")
	}
	return stdout
}
func (f *gitFixture) approve(record string) {
	f.t.Helper()
	out, stderr, err := f.command(f.git, []string{"credential", "approve"}, record+"\n")
	if err != nil || out != "" || stderr != "" {
		f.t.Fatal("Git credential approve failed or emitted output")
	}
}
func (f *gitFixture) assertCalls(api, get, sentinel, prompt int) {
	f.t.Helper()
	if f.backend.count("api", "") != api || f.backend.count("generator", "get") != get || f.backend.count("sentinel", "get") != sentinel || f.backend.count("prompt", "") != prompt {
		f.t.Fatal("unexpected API/generator/fallback/prompt call counts")
	}
}

func TestGitColdWarmReject(t *testing.T) {
	f := newFixture(t)
	first := f.fill(repository)
	f.assertCalls(1, 1, 0, 0)
	second := f.fill(repository)
	f.assertCalls(2, 2, 0, 0)
	if parseRecord(t, first)["password"] == parseRecord(t, second)["password"] {
		t.Fatal("fill unexpectedly stored/reused a cold credential")
	}
	f.approve(second)
	if f.backend.count("generator", "store") != 1 {
		t.Fatal("approve did not dispatch the generator's store no-op")
	}
	warm := f.fill(repository)
	f.assertCalls(2, 2, 0, 0)
	if parseRecord(t, warm)["password"] != parseRecord(t, second)["password"] {
		t.Fatal("approved credential was not reused")
	}
	out, stderr, err := f.command(f.git, []string{"credential", "reject"}, warm+"\n")
	if err != nil || out != "" || stderr != "" || f.backend.count("generator", "erase") != 1 {
		t.Fatal("reject failed or erase was not a no-op")
	}
	f.assertCalls(2, 2, 0, 0)
	replacement := f.fill(repository)
	f.assertCalls(3, 3, 0, 0)
	if parseRecord(t, replacement)["password"] == parseRecord(t, warm)["password"] {
		t.Fatal("reject did not erase the cached credential")
	}
}

// Validate the README's account-scoped helper reset against an inherited helper
// and a conflicting global useHttpPath default, not just isolated global config.
func TestDocumentedAccountScopedConfiguration(t *testing.T) {
	f := newFixture(t)
	configure := func(args ...string) {
		t.Helper()
		_, stderr, err := f.command(f.git, append([]string{"config", "--file", f.config}, args...), "")
		if err != nil || stderr != "" {
			t.Fatal("documented account configuration failed")
		}
	}
	configure("--unset-all", "credential.helper")
	configure("--replace-all", "credential.useHttpPath", "false")
	configure("--add", "credential.helper", "!exec "+shellQuote(f.helper)+" sentinel")
	context := "credential.https://" + host
	configure("--add", context+".useHttpPath", "true")
	for _, helper := range []string{"", "cache --timeout=3600 --socket=" + f.cache, "!exec " + shellQuote(f.helper) + " generator"} {
		configure("--add", context+".helper", helper)
	}
	first := f.fill(repository)
	f.approve(first)
	warm := f.fill(repository)
	if parseRecord(t, warm)["password"] != parseRecord(t, first)["password"] {
		t.Fatal("account-scoped cache configuration did not reuse approval")
	}
	f.assertCalls(1, 1, 0, 0) // The account's empty helper reset removed the inherited sentinel.
	stdout, _, err := f.command(f.git, []string{"credential", "fill"}, "url=https://unrelated.invalid/repository.git\n\n")
	if err == nil || stdout != "" || f.backend.count("api", "") != 1 || f.backend.count("generator", "get") != 1 || f.backend.count("sentinel", "get") != 1 || f.backend.count("prompt", "") == 0 {
		t.Fatal("account-scoped configuration changed unrelated helper behavior")
	}
}

func TestGitExpiry(t *testing.T) {
	f := newFixture(t)
	f.backend.set("", 4)
	first := f.fill(repository)
	f.approve(first)
	warm := f.fill(repository)
	f.assertCalls(1, 1, 0, 0)
	if parseRecord(t, warm)["password"] != parseRecord(t, first)["password"] {
		t.Fatal("short-lived credential was not cached")
	}
	expiry, _ := strconv.ParseInt(parseRecord(t, first)["password_expiry_utc"], 10, 64)
	// Both tested Git versions compare expiry with '< now', so cross the second
	// boundary strictly; do not assume equality is expired in Git itself.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Unix() <= expiry {
		if time.Now().After(deadline) {
			t.Fatal("bounded expiry wait exceeded")
		}
		time.Sleep(50 * time.Millisecond)
	}
	f.backend.set("", 0)
	replacement := f.fill(repository)
	f.assertCalls(2, 2, 0, 0)
	if parseRecord(t, replacement)["password"] == parseRecord(t, first)["password"] {
		t.Fatal("expired cached token was reused")
	}
}

func TestGitCacheIdentityIsolation(t *testing.T) {
	f := newFixture(t)
	urls := []string{repository, "https://" + host + "/git/default/other.git", "https://" + host + "/git/Other/demo.git", "https://" + strings.Repeat("b", 32) + ".artifacts.cloudflare.net/git/default/demo.git"}
	credentials := make([]string, len(urls))
	seen := map[string]bool{}
	for i, url := range urls {
		credentials[i] = f.fill(url)
		f.approve(credentials[i])
		f.assertCalls(i+1, i+1, 0, 0)
		password := parseRecord(t, credentials[i])["password"]
		if seen[password] {
			t.Fatal("repositories/namespaces/accounts shared a cached token")
		}
		seen[password] = true
	}
	for i, url := range urls {
		warm := f.fill(url)
		if parseRecord(t, warm)["password"] != parseRecord(t, credentials[i])["password"] {
			t.Fatal("cache identity mismatch")
		}
		f.assertCalls(len(urls), len(urls), 0, 0)
	}
}

func TestGitCachedMintingDefaultsBypass(t *testing.T) {
	f := newFixture(t)
	first := f.fill(repository)
	f.approve(first)
	f.env["GIT_CREDENTIAL_ARTIFACTS_SCOPE"] = "read"
	f.env["GIT_CREDENTIAL_ARTIFACTS_TTL"] = "60"
	if parseRecord(t, f.fill(repository))["password"] != parseRecord(t, first)["password"] {
		t.Fatal("minting defaults unexpectedly enforced over cache")
	}
	f.assertCalls(1, 1, 0, 0)
	f.env["GIT_CREDENTIAL_ARTIFACTS_SCOPE"] = "invalid"
	f.env["CLOUDFLARE_API_TOKEN"] = ""
	f.fill(repository)
	f.assertCalls(1, 1, 0, 0)
	// With valid changed defaults, invalidation causes the next actual issuance
	// to receive the new settings, without any revocation request.
	f.env["GIT_CREDENTIAL_ARTIFACTS_SCOPE"] = "read"
	f.env["CLOUDFLARE_API_TOKEN"] = fixture.APISecret
	_, stderr, err := f.command(f.git, []string{"credential", "reject"}, first+"\n")
	if err != nil || stderr != "" {
		t.Fatal("cache invalidation failed")
	}
	f.fill(repository)
	f.assertCalls(2, 2, 0, 0)
	f.backend.mu.Lock()
	defer f.backend.mu.Unlock()
	var last fixture.Event
	for _, event := range f.backend.events {
		if event.Kind == "api" {
			last = event
		}
	}
	if last.Scope != "read" || last.TTL != 60 {
		t.Fatal("new minting defaults did not reach replacement issuance")
	}
}

func TestGitRecognizedFailuresStopFallbackAndPrompt(t *testing.T) {
	for _, tc := range []struct {
		name, mode, key, value, input, guidance string
		api                                     int
	}{
		{name: "missing path", input: "url=" + repository + "\n\n", key: "useHttpPath", value: "false", guidance: "credential.useHttpPath=true"},
		{name: "invalid path", input: "url=https://" + host + "/git/default/demo%2Fother.git\n\n", guidance: "invalid repository path"},
		{name: "scope", key: "GIT_CREDENTIAL_ARTIFACTS_SCOPE", value: "synthetic-repository-secret", guidance: "GIT_CREDENTIAL_ARTIFACTS_SCOPE"},
		{name: "TTL", key: "GIT_CREDENTIAL_ARTIFACTS_TTL", value: "synthetic-repository-secret", guidance: "GIT_CREDENTIAL_ARTIFACTS_TTL"},
		{name: "auth", key: "CLOUDFLARE_API_TOKEN", value: "", guidance: "CLOUDFLARE_API_TOKEN"},
		{name: "API", mode: "api", guidance: "permissions", api: 1},
		{name: "transport", mode: "transport", guidance: "connectivity", api: 1},
		{name: "malformed JSON", mode: "json", guidance: "invalid Cloudflare token response", api: 1},
		{name: "scope mismatch", mode: "scope", guidance: "invalid Cloudflare token response", api: 1},
		{name: "expiry", mode: "expiry", guidance: "invalid Cloudflare token response", api: 1},
		{name: "rejected envelope", mode: "rejected", guidance: "permissions", api: 1},
		{name: "missing result", mode: "missing", guidance: "invalid Cloudflare token response", api: 1},
		{name: "protocol", input: "url=http://" + host + "/git/default/demo.git\n\n", guidance: "protocol=https"},
		{name: "port", input: "url=https://" + host + ":443/git/default/demo.git\n\n", guidance: "invalid Artifacts hostname"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.backend.set(tc.mode, 0)
			args := []string{"credential", "fill"}
			if tc.key == "useHttpPath" {
				args = append([]string{"-c", "credential.useHttpPath=false"}, args...)
			} else if tc.key != "" {
				f.env[tc.key] = tc.value
			}
			input := tc.input
			if input == "" {
				input = "url=" + repository + "\n\n"
			}
			stdout, stderr, err := f.command(f.git, args, input)
			if err == nil || stdout != "" || (tc.guidance != "" && !strings.Contains(stderr, tc.guidance)) {
				t.Fatal("recognized failure did not stop real Git with actionable diagnostics")
			}
			f.assertCalls(tc.api, 1, 0, 0)
		})
	}
}

func TestGitUnrelatedAndUnsupportedOperations(t *testing.T) {
	f := newFixture(t)
	stdout, _, err := f.command(f.git, []string{"credential", "fill"}, "url=https://unrelated.invalid/repository.git\n\n")
	if err == nil || stdout != "" {
		t.Fatal("sentinel unexpectedly supplied unrelated credentials")
	}
	if f.backend.count("api", "") != 0 || f.backend.count("generator", "get") != 1 || f.backend.count("sentinel", "get") != 1 || f.backend.count("prompt", "") == 0 {
		t.Fatal("unrelated request did not fall through without API use")
	}
	for _, operation := range []string{"store", "erase", "unknown"} {
		stdout, stderr, err := f.command(f.helper, []string{"generator", operation}, "malformed-synthetic-repository-secret\n")
		if err != nil || stdout != "" || stderr != "" || f.backend.count("api", "") != 0 {
			t.Fatal("unsupported operation read input, emitted output, or invoked API")
		}
	}
}

func TestProductionExecutableOfflineGate(t *testing.T) {
	f := newFixture(t)
	f.env["CLOUDFLARE_API_TOKEN"] = ""
	for _, tc := range []struct{ op, input, out, guidance string }{
		{"get", "protocol=https\nhost=" + host + "\npath=git/default/demo.git\n\n", "quit=true\n\n", "CLOUDFLARE_API_TOKEN"},
		{"get", "host=unrelated.invalid\n\n", "", ""},
		{"get", "protocol=https\nhost=" + host + "\n\n", "quit=true\n\n", "credential.useHttpPath=true"},
		{"get", "host=unrelated.invalid\nmalformed-synthetic-repository-secret\n", "quit=true\n\n", "invalid credential input"},
		{"store", "malformed\n", "", ""}, {"erase", "malformed\n", "", ""}, {"unknown", "malformed\n", "", ""},
	} {
		stdout, stderr, err := f.command(f.production, []string{tc.op}, tc.input)
		if err != nil || stdout != tc.out || (tc.guidance == "" && stderr != "") || (tc.guidance != "" && !strings.Contains(stderr, tc.guidance)) {
			t.Fatal("packaged production executable failed offline protocol gate")
		}
	}
	f.assertCalls(0, 0, 0, 0)
}
