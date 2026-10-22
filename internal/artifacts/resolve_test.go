package artifacts

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/maxouverzou/git-credential-artifacts/internal/credential"
)

const testAccount = "0123456789abcdef0123456789abcdef"
const testHost = testAccount + ".artifacts.cloudflare.net"

func TestResolveValid(t *testing.T) {
	for _, test := range []struct {
		name, host, path, namespace, repository string
	}{
		{"standard", testHost, "git/default/demo.git", "default", "demo"},
		{"DNS case", strings.ToUpper(testHost), "git/Default/Repo.git", "Default", "Repo"},
		{"name characters", testHost, "git/0.A_b-c/1.A_b-c.git", "0.A_b-c", "1.A_b-c"},
		{"minimal names", testHost, "git/ab/x.git", "ab", "x"},
		{"namespace upper bound", testHost, "git/" + strings.Repeat("a", 63) + "/repo.git", strings.Repeat("a", 63), "repo"},
		{"repository dots", testHost, "git/default/project.v2.git", "default", "project.v2"},
		{"repository git suffix", testHost, "git/default/project.git.git", "default", "project.git"},
		{"strip only one suffix", testHost, "git/default/project.git.git.git", "default", "project.git.git"},
		{"internal consecutive dots", testHost, "git/a..b/project..v2.git", "a..b", "project..v2"},
		{"trailing name dot", testHost, "git/ab./repo..git", "ab.", "repo."},
		{"no invented repository length limit", testHost, "git/default/" + strings.Repeat("a", 512) + ".git", "default", strings.Repeat("a", 512)},
	} {
		t.Run(test.name, func(t *testing.T) {
			remote, recognized, err := Resolve(credential.Request{Protocol: "https", Host: test.host, Path: test.path})
			want := Remote{AccountID: testAccount, Namespace: test.namespace, Repository: test.repository}
			if err != nil || !recognized || remote != want {
				t.Fatalf("Resolve = %v, %v, %v; want %v", remote, recognized, err, want)
			}
		})
	}
}

func TestResolveUnrelated(t *testing.T) {
	for _, host := range []string{
		"", "example.com", "api.cloudflare.com", "cloudflare.net",
		testHost + ".attacker.invalid", testHost + ".attacker.invalid:443",
		"evilartifacts.cloudflare.net", testAccount + ".evilartifacts.cloudflare.net",
		"artifacts-cloudflare.net", testAccount + ".artifacts.cloudflare.net-attacker.invalid",
		testAccount + ".artifacts.cloudflare.net@attacker.invalid",
		testAccount + ".artifacts.cloudflare.net/attacker.invalid",
		testAccount + ".artifacts.cloudflare.net?attacker.invalid",
		"attacker.invalid:" + testHost,
		testAccount + ".artifacts.cloudflare.net.attacker.invalid.",
		testAccount + ".artifacts.cloudflare.net%2eattacker.invalid",
		testAccount + ".artifacts.cloudflare%2enet",
		testAccount + ".artifacts.cloudfla\u212ae.net",
		testAccount + ".art\u0130facts.cloudflare.net", // do not Unicode-fold dotted I
		testAccount + ".artifact\u017f.cloudflare.net", // do not Unicode-fold long s
		"[" + testHost + "]:443",
	} {
		remote, recognized, err := Resolve(credential.Request{Protocol: "ssh", Host: host, Path: "malformed"})
		if err != nil || recognized || remote != (Remote{}) {
			t.Fatalf("unrelated host was recognized: %q", host)
		}
	}
}

func TestResolveInvalidHosts(t *testing.T) {
	for _, host := range []string{
		"artifacts.cloudflare.net", ".artifacts.cloudflare.net",
		"bad.artifacts.cloudflare.net", strings.Repeat("a", 31) + ".artifacts.cloudflare.net",
		strings.Repeat("a", 33) + ".artifacts.cloudflare.net", strings.Repeat("g", 32) + ".artifacts.cloudflare.net",
		"other." + testHost, " " + testHost, "user@" + testHost,
		"synthetic-secret/" + testHost, "\x00" + testHost,
		"\u00e9" + strings.Repeat("a", 30) + ".artifacts.cloudflare.net",
		"%30" + testAccount[1:] + ".artifacts.cloudflare.net",
		testHost + ":443", testHost + ":", testHost + ":https", testHost + ":-1",
		testHost + ":443:extra", testHost + ".", testHost + "..", testHost + ".:443",
		"artifacts.cloudflare.net.:443",
	} {
		remote, recognized, err := Resolve(credential.Request{Protocol: "https", Host: host, Path: "git/default/demo.git"})
		if !errors.Is(err, ErrInvalidHost) || !recognized || remote != (Remote{}) {
			t.Fatalf("invalid host did not fail closed: %q (%v)", host, err)
		}
		if strings.Contains(err.Error(), "synthetic-secret") {
			t.Fatal("error exposed input")
		}
	}
}

func TestResolveProtocolAndMissingPath(t *testing.T) {
	for _, protocol := range []string{"", "http", "ssh", "HTTPS", "https ", "https\x00"} {
		remote, recognized, err := Resolve(credential.Request{Protocol: protocol, Host: testHost, Path: "git/default/demo.git"})
		if !errors.Is(err, ErrInvalidProtocol) || !recognized || remote != (Remote{}) {
			t.Fatal("recognized request must require exact https protocol")
		}
	}
	remote, recognized, err := Resolve(credential.Request{Protocol: "https", Host: testHost})
	if !errors.Is(err, ErrMissingPath) || !recognized || remote != (Remote{}) {
		t.Fatal("missing credential path must be actionable and fail closed")
	}
}

func TestResolveInvalidPaths(t *testing.T) {
	for _, path := range []string{
		"/git/default/demo.git", "git/default/demo.git/", "Git/default/demo.git",
		"default/demo.git", "git/default", "git/default/demo.git/extra",
		"git//demo.git", "git/default/", "git/default/.git", "git/default/demo",
		"git/default/demo.GIT", "git/a/demo.git", "git/" + strings.Repeat("a", 64) + "/demo.git",
		"git/_default/demo.git", "git/-default/demo.git", "git/.default/demo.git",
		"git/default/_demo.git", "git/default/-demo.git", "git/default/.demo.git",
		"git/./demo.git", "git/../demo.git", "git/default/..git", "git/default/...git",
		"git/default/../demo.git", "git/default/demo.git?query", "git/default/demo.git#fragment",
		"git/de?fault/demo.git", "git/default/demo;param.git",
		"git/de%66ault/demo.git", "git/default/demo%2egit", "git/default/repo%2Fother.git",
		"git/default/repo%2fother.git", "git/default/repo%5Cother.git", "git/%2e%2e/demo.git",
		"git/default/repo%252fother.git", "git/default/demo%.git", "git/default/demo%GG.git",
		"git/default/repo\\other.git", "git/default/demo\nquit=true.git", "git/default/demo\r.git",
		"git/default/demo\x00.git", "git/default/demo\t.git", "git/default/demo\x7f.git",
		"git/def\u0085ault/demo.git", "git/d\u00e9fault/demo.git", "git/default/r\u00e9po.git",
		"git/default/repo=other.git", "git/default/repo other.git",
		"https://" + testHost + "/git/default/demo.git",
	} {
		remote, recognized, err := Resolve(credential.Request{Protocol: "https", Host: testHost, Path: path})
		if !errors.Is(err, ErrInvalidPath) || !recognized || remote != (Remote{}) {
			t.Fatalf("invalid path accepted: %q (%v)", path, err)
		}
	}
}

func TestResolveIdentityBoundaries(t *testing.T) {
	seen := make(map[Remote]bool)
	for _, account := range []string{testAccount, strings.Repeat("f", 32)} {
		for _, namespace := range []string{"default", "prod"} {
			for _, repository := range []string{"app", "App", "app.git"} {
				remote, recognized, err := Resolve(credential.Request{
					Protocol: "https", Host: account + ".artifacts.cloudflare.net",
					Path: "git/" + namespace + "/" + repository + ".git",
				})
				if err != nil || !recognized || seen[remote] {
					t.Fatal("different identities were collapsed")
				}
				seen[remote] = true
			}
		}
	}
}

func FuzzResolve(f *testing.F) {
	for _, seed := range []struct{ protocol, host, path string }{
		{"https", testHost, "git/default/demo.git"},
		{"https", strings.ToUpper(testHost), "git/Default/demo.git.git"},
		{"http", testHost, "git/default/demo.git"},
		{"https", testHost + ":443", "git/default/demo.git"},
		{"https", testHost + ".attacker.invalid", "git/default/demo.git"},
		{"https", testHost, "git/default/repo%2Fother.git"},
		{"https", testHost, ""},
	} {
		f.Add(seed.protocol, seed.host, seed.path)
	}
	// An independent grammar checks every accepted identity and exact path
	// reconstruction, rather than reusing the production validators.
	accountPattern := regexp.MustCompile("^[0-9a-f]{32}$")
	namespacePattern := regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._-]{1,62}$")
	repositoryPattern := regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._-]*$")
	f.Fuzz(func(t *testing.T, protocol, host, path string) {
		remote, recognized, err := Resolve(credential.Request{Protocol: protocol, Host: host, Path: path})
		if err != nil || !recognized {
			if remote != (Remote{}) || !recognized && err != nil {
				t.Fatal("unsuccessful classification retained identity or failed an unrelated request")
			}
			return
		}
		if protocol != "https" || !accountPattern.MatchString(remote.AccountID) ||
			!namespacePattern.MatchString(remote.Namespace) || !repositoryPattern.MatchString(remote.Repository) ||
			path != "git/"+remote.Namespace+"/"+remote.Repository+".git" ||
			!strings.EqualFold(host, remote.AccountID+".artifacts.cloudflare.net") {
			t.Fatal("accepted request changed repository boundaries or violated grammar")
		}
		for _, c := range host {
			if c > 127 {
				t.Fatal("accepted non-ASCII hostname")
			}
		}
	})
}
