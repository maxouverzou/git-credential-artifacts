#!/usr/bin/env python3
"""Issue one Artifacts token and print validation checks, never credentials."""

import datetime as dt
import json
import os
import re
import time
import urllib.error
import urllib.request


def main():
    token = os.environ.get("CLOUDFLARE_API_TOKEN", "")
    if not token or any(not 33 <= ord(c) <= 126 for c in token):
        raise SystemExit("API token missing or not header-safe")

    scope = os.environ.get("GIT_CREDENTIAL_ARTIFACTS_SCOPE", "write")
    ttl = os.environ.get("GIT_CREDENTIAL_ARTIFACTS_TTL", "3600")
    if scope not in ("read", "write") or not re.fullmatch(r"[0-9]+", ttl):
        raise SystemExit("Invalid scope or TTL configuration")
    if len(ttl.lstrip("0")) > 8 or not 60 <= int(ttl) <= 31536000:
        raise SystemExit("TTL outside supported range")

    url = (
        "https://api.cloudflare.com/client/v4/accounts/"
        "a2158851968b97304b435529c1c62a07/"
        "artifacts/namespaces/testing/tokens"
    )
    request = urllib.request.Request(
        url,
        data=json.dumps({"repo": "test", "scope": scope, "ttl": int(ttl)}).encode(),
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
        },
        method="POST",
    )

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None

    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
            print("HTTP status:", response.status)
            raw = response.read()
    except urllib.error.HTTPError as error:
        raise SystemExit("HTTP status: " + str(error.code)) from None
    except Exception:
        raise SystemExit("Request failed (details suppressed)") from None

    try:
        envelope = json.loads(raw)
    except Exception:
        raise SystemExit("Valid JSON: False") from None
    print("Valid JSON: True")
    if not isinstance(envelope, dict):
        raise SystemExit("Envelope is an object: False")
    print("Success is true:", envelope.get("success") is True)
    result = envelope.get("result")
    print("Result is an object:", isinstance(result, dict))
    if not isinstance(result, dict):
        return

    print("Scope matches request:", result.get("scope") == scope)
    plaintext = result.get("plaintext")
    print("plaintext is a string:", isinstance(plaintext, str))
    if isinstance(plaintext, str):
        secret, separator, suffix = plaintext.partition("?expires=")
        print("Plaintext length:", len(plaintext))
        print("Has expected expiry separator:", bool(separator))
        print("Secret length:", len(secret))
        print("Secret starts with art_v1_:", secret.startswith("art_v1_"))
        print("Secret starts with art_v2_x_:", secret.startswith("art_v2_x_"))
        for prefix in ("art_v1_", "art_v2_x_"):
            if secret.startswith(prefix):
                payload = secret[len(prefix):]
                print("Secret payload length:", len(payload))
                print("Secret payload is hex:", bool(re.fullmatch(r"[0-9a-fA-F]+", payload)))
                print("Secret payload is URL-safe:", bool(re.fullmatch(r"[0-9a-zA-Z_-]+", payload)))
        print("Expiry suffix is decimal:", bool(re.fullmatch(r"[0-9]+", suffix)))
        print("Has surrounding whitespace:", plaintext != plaintext.strip())
    match = re.fullmatch(
        r"(?:art_v1_[0-9a-fA-F]{40}|art_v2_x_[0-9a-zA-Z_-]+)\?expires=([0-9]+)",
        plaintext if isinstance(plaintext, str) else "",
    )
    format_valid = match is not None and len(plaintext.partition("?expires=")[0]) <= 4096
    print("Token format valid:", format_valid)
    expiry = None
    if format_valid:
        digits = match[1].lstrip("0") or "0"
        if len(digits) <= 19:
            value = int(digits)
            if value <= 9223372036854775807:
                expiry = value
    print("Expiry is in future:", expiry is not None and expiry > int(time.time()))

    timestamp = result.get("expires_at")
    syntax = (
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
        r"(\.[0-9]+)?(Z|[+-]([01][0-9]|2[0-3]):[0-5][0-9])"
    )
    parsed = None
    if isinstance(timestamp, str) and re.fullmatch(syntax, timestamp):
        try:
            parsed = dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            pass
    print("expires_at is valid RFC3339:", parsed is not None)
    print(
        "Expiry fields agree:",
        parsed is not None and expiry is not None
        and int(parsed.timestamp()) == expiry,
    )


if __name__ == "__main__":
    main()
