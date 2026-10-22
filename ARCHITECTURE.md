# Architecture

`git-credential-artifacts` generates repository-scoped Git credentials through
Cloudflare's API. It does not store credentials. Installation, operational
settings, build workflows, and verified compatibility are in [README.md](README.md).

## Credential flow

```text
Git lookup → storage helper → usable cached credential → Git
                  │ cache miss
                  ▼
           git-credential-artifacts
           parse → resolve → validate settings → authenticate → mint → return
```

The two credential layers remain separate:

- **Cloudflare API token:** runtime `CLOUDFLARE_API_TOKEN`, with Artifacts Edit
  permission for the account. It authorizes issuance and is never returned to Git.
- **Repository token:** returned as Git's Basic password with its actual expiry;
  a separate storage helper caches it.

`credential fill` alone does not store credentials; Git approves them after
successful authentication. The generator never persists credentials or invokes
other helpers. `store`, `erase`, and unsupported operations are silent no-ops
without input reads or authentication. There is no revocation or OAuth refresh
flow: an expired token is replaced by a new issuance.

## Component boundaries

| Component | Responsibility |
| --- | --- |
| `internal/credential` | Bounded Git protocol parsing and complete-response serialization |
| `internal/artifacts` | Pure remote resolution, issuance, and token/expiry validation |
| `internal/config` | Environment-over-default scope/TTL loading and validation |
| `internal/cloudflare` | Private official SDK client, authentication, guarded transport, sanitized errors |
| `internal/app` | Dispatch and lazy composition of the validated request flow |
| `cmd/git-credential-artifacts` | Process entry point and standard I/O wiring |

Configuration and SDK construction occur only after parsing, remote resolution,
and username validation succeed. The application depends on a token-issuer
interface; the issuer uses a guarded token-client interface and an injected clock.
Tests inject dependencies/transports without adding production endpoint overrides.
Concurrent misses issue independently, without cross-process coordination.

## Input and failure boundary

Git supplies protocol/host/path fields for an HTTPS remote of this shape:

```text
https://<account-id>.artifacts.cloudflare.net/git/<namespace>/<repo>.git
```

Input is bounded and repository identity is strictly validated before acquiring
API authentication. The resolver never URL-decodes or normalizes paths already
processed by Git, and Git input is never used as an API URL. Exact parsing and
naming rules are owned by the implementation and its tests.

Unrelated hosts return silently. Recognized-invalid Artifacts requests fail
closed; missing paths require `credential.useHttpPath=true`. Parse failures
discard partial fields and fail closed even when the host cannot be classified.
A safe supplied username is preserved; an absent/empty one becomes `x`.

Responses are validated before writing. Stdout contains only complete credentials
or standalone `quit=true`; diagnostics are fixed, sanitized stderr messages.
`quit=true` stops later helpers and prompting when the generator is invoked.
Write failures cannot undo partial bytes and never trigger retries or appended
responses. Neither credential layer, raw SDK errors, nor response bodies are logged.

## API trust boundary

The official SDK client uses explicit options rather than ambient defaults.
Only nonempty, visible-ASCII API-token authentication is supported; alternative
authentication, Wrangler files, browser login, and endpoint overrides are not used.
This keeps hostile environment defaults from changing destinations or headers.

The fixed origin is `https://api.cloudflare.com/client/v4/`. The transport accepts
only canonical namespace-token POST routes built from revalidated, escaped
identities. Alternate origins, Host overrides, and alternative-auth headers are
rejected. Token creation is non-idempotent: there are no automatic retries or
redirects, non-2xx responses are rejected, and the request deadline is 30 seconds
through response reading. A timeout may follow successful creation, so an
ambiguous request is not retried.

Issuance uses the SDK's custom `client.Post` with project-owned types. Raw response
bytes are strictly decoded as a complete v4 envelope because the pinned SDK
otherwise accepts trailing data after valid JSON. Success requires `success=true`,
a usable result, matching scope, valid token format, and agreement between both expiry
representations. Only the repository secret and validated expiry reach Git;
expiry is never synthesized from requested TTL, and no early-expiry margin applies.

## Scope/TTL and cache semantics

Environment values override defaults:

| Setting | Variable | Default | Accepted values |
| --- | --- | --- | --- |
| Scope | `GIT_CREDENTIAL_ARTIFACTS_SCOPE` | `write` | `read` or `write` |
| TTL | `GIT_CREDENTIAL_ARTIFACTS_TTL` | `3600` seconds | ASCII decimal seconds, 60–31,536,000 inclusive |

Present-but-empty values, signs, whitespace, overflow, and out-of-range values
are invalid before authentication/API use. There are no flag, Git-config,
account-specific, or credential-input overrides. `write` is the default because
a Git credential lookup does not distinguish fetching from pushing.

Cached credentials bypass the generator, including after scope/TTL or API-auth
changes. These settings govern minting, not cached policy; fail-closed behavior
cannot override credentials supplied earlier. `git credential reject` invalidates
a matching storage entry without API revocation. Cache retention does not extend
token validity. Both tested Git versions may return a cached password during its
exact expiry second; the issuer itself requires expiry strictly in the future.
