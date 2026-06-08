"""Minimal JSON-over-HTTP client (stdlib ``urllib``) for REST provider adapters.

Dependency-free on purpose (no ``requests``) to keep the supply-chain surface of
a security tool small. Bearer-token auth, JSON in/out, and retry-with-backoff on
429/5xx (best practice for flaky cloud APIs). The single network chokepoint
provider adapters call this rather than urllib directly.
"""
from __future__ import annotations

import http.client
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .errors import SshManagerError

RETRY_STATUS = {429, 500, 502, 503, 504}
# Only these methods are safe to retry: a 502/504 (or a read-phase timeout) often
# means the request reached the backend and may have succeeded, so retrying a
# POST/PATCH could create a duplicate. We therefore retry transport errors only
# for idempotent methods.
IDEMPOTENT_METHODS = {"GET", "HEAD", "PUT", "DELETE"}
# Headers that must never survive a cross-origin redirect (token exfiltration).
_SENSITIVE_HEADERS = {"authorization", "x-auth-token", "cookie"}


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects, but (a) refuse an https->non-https downgrade and (b) drop
    credential headers when the redirect crosses origin - stdlib's default would
    forward the bearer token to the redirect target, even a different host."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> Any:
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is None:
            return None
        old = urllib.parse.urlsplit(req.full_url)
        nxt = urllib.parse.urlsplit(newurl)
        if old.scheme == "https" and nxt.scheme != "https":
            raise urllib.error.HTTPError(
                newurl, code, "refusing an https -> non-https redirect", headers, fp)
        # Compare effective origins (default ports filled in) so a same-host
        # redirect that only makes the :443/:80 explicit isn't treated as cross-origin.
        if _origin(nxt) != _origin(old):
            for name in [h for h in new.headers if h.lower() in _SENSITIVE_HEADERS]:
                del new.headers[name]
        return new


def _origin(u: urllib.parse.SplitResult) -> tuple[str | None, str | None, int | None]:
    port = u.port or {"https": 443, "http": 80}.get(u.scheme or "")
    return (u.scheme, u.hostname, port)


_OPENER = urllib.request.build_opener(_SafeRedirectHandler())


def _retry_after(exc: urllib.error.HTTPError) -> float | None:
    raw = exc.headers.get("Retry-After") if exc.headers else None
    if raw and raw.strip().isdigit():
        return min(float(raw.strip()), 30.0)   # cap so a hostile header can't stall us
    return None


class HttpError(SshManagerError):
    """A REST call failed (non-2xx, or transport error after retries)."""


def request_json(method: str, url: str, *, token: str | None = None,
                 headers: dict[str, str] | None = None,
                 body: Any = None, timeout: float = 30.0, retries: int = 4,
                 _sleep: Any = time.sleep) -> Any:
    """Make a JSON request and return the parsed body ({} for 204/empty).

    Pass ``headers`` for non-Bearer auth (e.g. Scaleway's ``X-Auth-Token``);
    otherwise ``token`` is sent as ``Authorization: Bearer``.
    """
    data = json.dumps(body).encode("utf-8") if body is not None else None
    hdrs = {"Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    elif token:
        hdrs["Authorization"] = f"Bearer {token}"
    if data is not None:
        hdrs["Content-Type"] = "application/json"

    idempotent = method.upper() in IDEMPOTENT_METHODS
    for attempt in range(retries + 1):
        req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
        try:
            with _OPENER.open(req, timeout=timeout) as resp:
                raw = resp.read()
            if getattr(resp, "status", 200) == 204 or not raw:
                return {}
            try:
                return json.loads(raw)
            except json.JSONDecodeError as exc:
                snippet = raw.decode("utf-8", "replace")[:300]
                raise HttpError(
                    f"{method} {url} -> non-JSON response: {snippet}") from exc
        except urllib.error.HTTPError as exc:
            # Only retry a 5xx/429 for idempotent methods (a retried POST can dup).
            if idempotent and exc.code in RETRY_STATUS and attempt < retries:
                wait = _retry_after(exc)
                _sleep(wait if wait is not None else 1.0 * (attempt + 1))
                continue
            detail = exc.read().decode("utf-8", "replace")[:300] if exc.fp else ""
            raise HttpError(f"{method} {url} -> {exc.code} {detail}".strip()) from exc
        except (OSError, http.client.HTTPException) as exc:
            # Transport failure - includes connect/read timeouts and dropped
            # connections (urllib.error.URLError is an OSError subclass). The
            # request may have reached the backend, so retry idempotent methods only.
            if idempotent and attempt < retries:
                _sleep(1.0 * (attempt + 1))
                continue
            reason = getattr(exc, "reason", exc)
            raise HttpError(f"{method} {url} failed: {reason}") from exc
    # Reached only if the loop never ran (retries < 0); the normal exhausted-retries
    # case raises the actual last error inside the loop above.
    raise HttpError(f"{method} {url} not attempted (retries={retries})")
