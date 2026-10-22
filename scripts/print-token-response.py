#!/usr/bin/env python3
"""Issue one Artifacts token and print the raw API response (contains secrets)."""

import json
import os
import sys
import urllib.error
import urllib.request


def main():
    token = os.environ.get("CLOUDFLARE_API_TOKEN", "")
    if not token or any(not 33 <= ord(c) <= 126 for c in token):
        raise SystemExit("API token missing or not header-safe")

    scope = os.environ.get("GIT_CREDENTIAL_ARTIFACTS_SCOPE", "write")
    ttl = os.environ.get("GIT_CREDENTIAL_ARTIFACTS_TTL", "3600")
    try:
        ttl = int(ttl)
    except ValueError:
        raise SystemExit("Invalid TTL") from None
    if scope not in ("read", "write") or not 60 <= ttl <= 31536000:
        raise SystemExit("Invalid scope or TTL")

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None

    request = urllib.request.Request(
        "https://api.cloudflare.com/client/v4/accounts/"
        "a2158851968b97304b435529c1c62a07/"
        "artifacts/namespaces/testing/tokens",
        data=json.dumps({"repo": "test", "scope": scope, "ttl": ttl}).encode(),
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    print("Warning: response may contain a live repository token. Redact before sharing.", file=sys.stderr)
    try:
        response = urllib.request.build_opener(NoRedirect).open(request, timeout=30)
    except urllib.error.HTTPError as error:
        response = error
    except Exception:
        raise SystemExit("Request failed (details suppressed)") from None

    with response:
        print("HTTP status:", response.status, file=sys.stderr)
        raw = response.read()
    sys.stdout.buffer.write(raw)
    if not raw.endswith(b"\n"):
        sys.stdout.buffer.write(b"\n")


if __name__ == "__main__":
    main()
