# git-credential-artifacts

A Go Git credential generator for Cloudflare Artifacts, built with Nix.

The core implementation, Git/cache integration, and release checks are implemented.
The validated matrix is **x86_64-linux, Git 2.45.0 and 2.55.0, built-in cache**.
ARM/Linux, Darwin, other Git versions, and other storage helpers remain unverified.
The package is still `0.0.0-dev`; no tag or binary release has been published.
GitHub CI is configured, but a hosted run is not claimed by local validation.

## Install

Enable Nix's `nix-command` and `flakes` features. From this checkout:

```sh
nix build                          # result/bin/git-credential-artifacts
nix profile install .              # installs into your Nix profile
command -v git-credential-artifacts # confirm Git can find it on PATH
```

Newer Nix versions call `nix profile install .` by the name `nix profile add .`;
`install` remains a compatible alias. Your profile's `bin` directory must be on
the PATH of the process launching Git,
including any IDE or service. `nix run . -- <operation>` runs the executable once;
it does **not** install it or make `helper = artifacts` available to other Git
processes. Direnv is optional and is not needed to use the installed helper.
For a published revision, pin the flake URL to an audited commit/tag rather than
assuming an unreviewed branch is stable.

For declarative installation, add this input to your own flake and commit its
lockfile:

```nix
inputs.artifacts-helper.url = "github:maxouverzou/git-credential-artifacts";
```

A Home Manager module can install the package (supply `inputs` through
`extraSpecialArgs = { inherit inputs; };`):

```nix
{ inputs, pkgs, ... }:
{
  home.packages = [
    inputs.artifacts-helper.packages.${pkgs.stdenv.hostPlatform.system}.default
  ];
}
```

In NixOS, use the same package expression in `environment.systemPackages`,
supplying `inputs` through `specialArgs`. These are declared package targets,
not evidence that every architecture has been tested. Never put runtime API
credentials in a flake, Home Manager session variables, Git settings, derivation
arguments, or generated configuration: Nix store contents are world-readable.

## Configure Git for each account

Replace `<account-id>` with the exact 32-hex-character account ID and add this to
your Git configuration:

```gitconfig
[credential "https://<account-id>.artifacts.cloudflare.net"]
    useHttpPath = true
    helper =
    helper = cache --timeout 3600
    helper = artifacts
```

The empty `helper` resets inherited helpers for this matching account context,
without changing unrelated hosts. Built-in cache runs first; the generator runs
only on a miss. Repeat the block for every account. `useHttpPath=true` is
mandatory: repositories and namespaces share a hostname but must not share
credentials. A remote has the form:

```text
https://<account-id>.artifacts.cloudflare.net/git/<namespace>/<repo>.git
```

Keep credentials out of remote URLs. You may manage the same non-secret Git
configuration through Nix/Home Manager, but authentication must remain runtime-only.
Other storage helpers are not certified for expiry preservation or path isolation.
Git's cache requires Unix sockets; it retains repository tokens in memory, not
Cloudflare API credentials. The generator never invokes other helpers itself.

## Runtime authentication and minting defaults

There are two distinct credentials:

1. **Cloudflare API token**: supply `CLOUDFLARE_API_TOKEN` in the environment of
   the Git process. It needs **Artifacts Edit** permission for the relevant
   account. This authorizes control-plane token issuance, not Git authentication.
2. **Artifacts repository token**: minted for the resolved repository with the
   selected scope and TTL. Only its secret is returned as Git's Basic password;
   the nonempty username is preserved when safe, otherwise defaults to `x`.

Use a secret manager that injects the environment, or enter the API token in an
interactive **Bash** session without placing it in command history:

```sh
# Do not enable shell tracing (set -x).
read -r -s -p 'Cloudflare API token: ' CLOUDFLARE_API_TOKEN
printf '\n'
export CLOUDFLARE_API_TOKEN
# Run your normal Git command in this environment.
# When finished:
# unset CLOUDFLARE_API_TOKEN
```

Only nonempty, visible-ASCII API-token authentication is supported. API keys,
email authentication, user-service keys, Wrangler login files, and browser/OAuth
flows are not used. SDK endpoint/alternative-auth environment overrides cannot
change the trusted Cloudflare API destination or inject authentication headers.
Never supply a credential through `nix --arg`, a Nix expression, a committed
`.envrc`, a test fixture, or a generated Nix-store file.

| Variable | Unset default | Accepted values |
| --- | --- | --- |
| `GIT_CREDENTIAL_ARTIFACTS_SCOPE` | `write` | `read` or `write` |
| `GIT_CREDENTIAL_ARTIFACTS_TTL` | `3600` | ASCII decimal integer seconds, 60–31,536,000 inclusive |

Present-but-empty values are invalid; signs, whitespace, and overflow are
rejected. Environment values override defaults; no flags, Git configuration,
account-specific settings, or credential-input fields override these settings.
`write` is the default because a credential lookup does not distinguish fetching
from pushing. For example, runtime `read`/600 settings are:

```sh
export GIT_CREDENTIAL_ARTIFACTS_SCOPE=read
export GIT_CREDENTIAL_ARTIFACTS_TTL=600
```

These are **minting defaults, not enforcement over earlier cached credentials**.
Changing them—or removing API authentication—does not invalidate a valid cached
token. To affect the next lookup, erase the matching cached credential without
printing it:

```sh
# Set ACCOUNT_ID, NAMESPACE, and REPO to non-secret repository identifiers.
printf 'protocol=https\nhost=%s.artifacts.cloudflare.net\npath=git/%s/%s.git\n\n' \
  "$ACCOUNT_ID" "$NAMESPACE" "$REPO" | git credential reject
```

`reject` erases the matching storage entry; the generator's `erase` is a no-op
and does not revoke tokens through the API. `store` and unknown operations are
also silent no-ops. Token revocation, if needed, is a separate control-plane task.

The issuer makes one non-idempotent POST, with no redirects or automatic retries
and a 30-second total request deadline. It validates the complete response,
returned scope, supported token format, and agreement between the
`?expires=<seconds>` suffix and RFC3339 `expires_at`. Supported secrets are
`art_v1_<40 hex>` and the observed `art_v2_x_<URL-safe payload>` format (nonempty
ASCII letters, digits, `_`, or `-`; at most 4096 bytes including the prefix).
Public Cloudflare documentation still describes v1; v2 payloads are treated as
opaque rather than assuming a fixed encoding or length. It strips the suffix for the password and
returns the actual Unix-second expiry as `password_expiry_utc`; it never invents
expiry from the requested TTL. Cache retention and token validity are independent.
There is no early-expiry margin. Both tested Git versions discard cached
passwords when expiry is **less than** the current Unix second, so a cache may
serve a credential during the exact expiry second. After expiry, a cache miss
mints a replacement; there is no OAuth refresh token or refresh grant.

## Fail-closed behavior and safe troubleshooting

Unrelated hosts return silently without authentication/API access. Recognized
invalid remotes, missing paths, configuration/authentication failures, and
API/response failures emit only `quit=true` plus a fixed diagnostic. When the
generator is invoked on a cache miss, real Git stops later helpers and prompting;
the process exit status
alone is not the failure signal. Malformed protocol input discards all partial
fields and fails closed even when its host is unknown. Fail-closed behavior does
not override a credential already supplied by an earlier storage helper.

- Check `command -v git-credential-artifacts` and `git --version`.
- Check the account hostname and `git/<namespace>/<repo>.git` path. Ports,
  trailing dots/slashes, extra segments, and ambiguous encoded boundaries are
  rejected; exact naming rules are enforced in
  [the resolver](internal/artifacts/resolve.go) and covered by
  [its tests](internal/artifacts/resolve_test.go).
- Verify `credential.useHttpPath=true` for the remote. For example,
  `git config --get-urlmatch credential.useHttpPath "https://$ACCOUNT_ID.artifacts.cloudflare.net/git/$NAMESPACE/$REPO.git"`
  reports the boolean setting, not a credential.
- Ensure the Git process has runtime API authentication, valid scope/TTL, and
  permission for the account/repository. Read the sanitized stderr diagnostic;
  do not print environment values to check them.
- Invalidate the matching cached entry after changing minting defaults. A warm
  cache can hide invalid configuration or missing authentication until a miss.
- For connectivity failures, check network/service availability. A timed-out
  POST may have created a token; the helper intentionally does not retry it.

Do **not** use `git credential fill` as a debugging printout: it outputs a
password. Do not enable `set -x`, `GIT_TRACE`, `GIT_TRACE_CURL`, or verbose SDK/HTTP
logging, dump credential records/environment/configuration, or share raw
responses. Never log API tokens, repository passwords, authorization headers,
or secrets in URLs. The helper's diagnostics do not include raw SDK errors,
response bodies, or credential input/output. An I/O write failure may leave
partial bytes; the helper cannot undo them and does not retry or append output.

## Development, checks, and CI

```sh
nix develop
# Optional convenience: direnv allow (.envrc uses `use flake`)
nix develop -c go test ./...        # fast unit tests; Git integration skips here
nix develop -c go build ./...
nix build
nix flake check -L                  # the complete native automated suite
nix fmt                            # Nix files only
nix develop -c gofmt -w cmd internal integration
nix run . -- store                 # silent no-op smoke check
```

Go 1.27.1 and Git 2.55.0 come from the committed nixpkgs lock. The shell includes
Go tools, Git, the Nix formatter, and a native C compiler. `GOTOOLCHAIN=local`
forbids implicit toolchain downloads; standard Go commands work inside the shell.
Direnv is optional. Builds/checks use writable temporary HOME and Go caches.

`nix flake check` covers the package, unit tests, vet, separate Go/Nix formatting,
workflow lint, race-enabled tests, and both race-enabled Git/cache suites. The
race/fuzz derivations explicitly supply the native compiler and enable cgo on
all three declared supported targets. Four fuzz targets each run for 10 seconds
with two workers and a two-minute runtime timeout. Longer local validation is
available without changing CI bounds:

```sh
nix develop -c go test -race ./...
nix develop -c go test ./internal/credential -run '^$' -fuzz '^FuzzParse$' -fuzztime=60s -parallel=2
nix develop -c go test ./internal/credential -run '^$' -fuzz '^FuzzWriteResponse$' -fuzztime=60s -parallel=2
nix develop -c go test ./internal/artifacts -run '^$' -fuzz '^FuzzResolve$' -fuzztime=60s -parallel=2
nix develop -c go test ./internal/artifacts -run '^$' -fuzz '^FuzzValidateToken$' -fuzztime=60s -parallel=2
```

[CI](.github/workflows/ci.yml) uses a native Ubuntu x86_64 runner and SHA-pinned
checkout/Nix-install actions with read-only repository permissions. It runs
`nix build` and `nix flake check` with `--no-write-lock-file`, sandboxing enabled,
and no separately installed Go/Git test toolchains or Cloudflare credentials.
It checks that dependency pins were not rewritten. Hosted CI success must be
observed after pushing; a locally linted workflow is not proof of a hosted run.
Add native ARM/Linux or Darwin jobs/builders before claiming those platforms.

## Git/cache integration coverage

| Platform | Git | Storage | Status |
| --- | --- | --- | --- |
| x86_64-linux | 2.45.0 (separately pinned baseline) | Built-in cache | Passed locally, including sandboxed race-enabled Nix checks |
| x86_64-linux | 2.55.0 (locked nixpkgs) | Built-in cache | Passed locally, including sandboxed race-enabled Nix checks |
| aarch64-linux / aarch64-darwin | Declared targets | Built-in cache | Evaluated only; not built/tested |
| Any platform | Other versions/helpers | Other storage | Unverified |

Run just the integration matrix (replace the system for a native builder):

```sh
nix build --no-link -L .#checks.x86_64-linux.git-current .#checks.x86_64-linux.git-245
```

Fast unit workflows skip integration unless explicit Git, harness, and
production executable paths are supplied; they do not certify the matrix. Nix
checks require those paths and fail instead of silently skipping. Tests use the
real application through a separate test-only executable and an injected fake
HTTP transport, isolated HOME/config/environment, private Unix sockets, and
fallback/prompt sentinels. No live credentials, outbound network, loopback TCP,
host shell assumption, or writable source tree is required. Only the private
fixture-owned daemon is shut down. The harness is not installed and introduces
no production endpoint override; lower-level SDK/token tests remain in place.

Coverage includes cold fill without automatic storage, explicit approval, warm
bypass, actual expiry preservation with longer retention, repository/namespace/
account isolation, rejection without revocation, failure stopping later helpers
and prompting, no-op operations, and cached minting-default bypass. Expiry tests
wait strictly beyond the expiry second. These are credential-protocol tests,
not end-to-end Git HTTP authentication tests or live Cloudflare certification.
The baseline test build disables unrelated HTTP/GUI features and uses GNU C11
for the locked compiler; credential/cache sources are unchanged.

## Reproducibility and release maintenance

- Keep `flake.lock` committed. Intentionally update it with `nix flake update`,
  review the diff, and rerun `nix build`/`nix flake check` on native tested systems.
- Keep the `go_1_27` overlay, `buildGoModule`, Go-based tools, and `go.mod`
  aligned. Review any Go version change; keep `GOTOOLCHAIN=local` enabled.
- Pin the official SDK (currently v6.10.0). Update via
  `nix develop -c go get github.com/cloudflare/cloudflare-go/v6@<version>` and
  `nix develop -c go mod tidy`; review the security/SDK contract tests.
- Update `vendorHash` alongside module files. Copy the allowlisted Go/module
  sources into a temporary directory, run `go mod vendor` there, and compute
  `nix hash path <temporary-directory>/vendor`. Verify the real hash with the
  build/checks. Never set `vendorHash = null`, use an unchecked dependency hash,
  or commit a vendor tree as a substitute for verification.
- Git 2.45.0's independent source version/hash is in `nix/git-245.nix`. Update
  deliberately and rerun both Git checks; never substitute host Git.
- Update SHA-pinned CI actions deliberately, review their upstream changes, and
  run the workflow-lint check as well as the complete suite.
- Package sources contain only module files and `.go` files under `cmd`,
  `internal`, and `integration`. Only the production command is installed.
  `.git`, `.direnv`, documentation, unrelated files, and runtime credentials
  do not enter the package source. Do not commit credentials: even a flake's
  tracked source or unrelated generated derivation can enter the Nix store.
- Fixed-output dependency fetching may use the network. Subsequent sandboxed
  builds/tests use verified dependencies without network access. All fixtures
  contain synthetic credentials only; no automated test needs a real account.

Before publishing, choose a release version, update the package's development
version in `flake.nix`, commit the reviewed code/lockfiles, observe CI success,
and tag that tested commit. No tag, upload, or remote release is created by
`nix build`/`nix flake check`. A clean checkout should pass the same interfaces;
new build inputs must be tracked for a Git-backed flake to include them.

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed design and security contracts.
