# Cloudflare Artifacts reference

Unmodified Markdown snapshots retrieved from the official [Cloudflare Artifacts documentation](https://developers.cloudflare.com/artifacts/). These are reference material for developing an Artifacts Git credential helper, not project-specific implementation guidance. Each page includes its original source URL; `llms.txt` contains the complete upstream documentation index.

## Start here

- [Authentication](guides-authentication.md): Cloudflare API tokens versus repo-scoped Git tokens.
- [Git protocol](api-git-protocol.md): remote URLs, Bearer and Basic authentication, token format, and scopes.
- [REST API](api-rest-api.md): token issuance, TTLs, revocation, response types, and repository lookup.
- [Wrangler commands](api-wrangler.md): CLI repository and token management.
- [Errors](api-errors.md): API and binding error codes.

## Supporting documentation

- [Overview](index.md)
- [How Artifacts works](concepts-how-artifacts-works.md)
- [Namespaces](concepts-namespaces.md)
- [Repositories](concepts-repositories.md)
- [Best practices](concepts-best-practices.md)
- [REST API getting started](get-started-rest-api.md)
- [Workers binding](api-workers-binding.md)
- [Limits](platform-limits.md)
- [Pricing](platform-pricing.md)
- [Changelog](platform-changelog.md)

## Using these snapshots

Prefer the current API reference over historical changelog examples: old entries contain obsolete remote URLs and API shapes. Recheck upstream documentation before relying on availability, pricing, limits, or authentication behavior.
