"""One HTTP client for every source: records each outgoing query, caches answers, never leaks tokens."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urljoin, urlparse

import httpx

from predisclose import __version__

NOT_FOUND_TTL = 30 * 60


class RateLimited(Exception):
    """GitHub refused the request because the hourly or per-minute quota is used up."""


def private_file(path: Path) -> Path:
    """Create the directory (0700) and an empty file (0600) if missing, so other local users
    cannot read cached answers or the ledger. The file's permissions are tightened if it exists;
    the directory's only if it is our own `predisclose` directory (never a folder the user named)."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        if path.parent.name == "predisclose":
            os.chmod(path.parent, 0o700)
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        os.chmod(path, 0o600)
    except OSError:
        pass  # e.g. a read-only or foreign-owned directory; sqlite will report real problems
    return path


class NetworkError(Exception):
    pass


def default_cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "predisclose"


def github_token_from_env() -> str | None:
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or None


class Http:
    """
    dry_run:  record the queries that would be sent, send nothing, return (0, None).
    use_cache: answers (200/404 only) are kept in a local sqlite file for `ttl` seconds.
    The GitHub token is attached only to api.github.com requests and never written to
    the query log or the cache key.
    """

    def __init__(
        self,
        *,
        cache_dir: Path | None = None,
        ttl: int = 6 * 3600,
        use_cache: bool = True,
        dry_run: bool = False,
        token: str | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.queries: list[str] = []
        self.dry_run = dry_run
        self.ttl = ttl
        self.token = token
        self._db: sqlite3.Connection | None = None
        if use_cache and not dry_run:
            directory = cache_dir or default_cache_dir()
            self._db = sqlite3.connect(private_file(directory / "http.sqlite"))
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS cache "
                "(k TEXT PRIMARY KEY, t REAL NOT NULL, status INTEGER NOT NULL, body TEXT NOT NULL)"
            )
        self._client = httpx.Client(
            timeout=20.0,
            follow_redirects=False,  # redirects are followed by hand: same host, https only, logged
            headers={"User-Agent": f"predisclose/{__version__}"},
            transport=transport,
        )

    def close(self) -> None:
        self._client.close()
        if self._db is not None:
            self._db.close()

    # -- public helpers ---------------------------------------------------------------
    def get_json(self, url: str, params: dict[str, Any] | None = None) -> tuple[int, Any]:
        return self._request("GET", url, params=params, body=None, as_json=True)

    def post_json(self, url: str, body: dict[str, Any]) -> tuple[int, Any]:
        return self._request("POST", url, params=None, body=body, as_json=True)

    def get_text(self, url: str) -> tuple[int, str | None]:
        return self._request("GET", url, params=None, body=None, as_json=False)

    # -- internals --------------------------------------------------------------------
    def _request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None,
        body: dict[str, Any] | None,
        as_json: bool,
    ) -> tuple[int, Any]:
        shown = url + ("?" + urlencode(params) if params else "")
        line = f"{method} {shown}"
        if body is not None:
            line += "  body=" + json.dumps(body, sort_keys=True)
        self.queries.append(line)
        if self.dry_run:
            return 0, None

        key = hashlib.sha256(
            # An answer fetched with a token can differ from an anonymous one; keep them apart.
            json.dumps([method, url, params or {}, body, bool(self.token)], sort_keys=True).encode()
        ).hexdigest()
        cached = self._cache_get(key)
        if cached is not None:
            status, text = cached
            return status, self._decode(text, as_json)

        response = self._send(method, url, params=params, body=body)
        is_github_api = url.startswith("https://api.github.com/")

        if is_github_api and response.status_code == 401 and self.token:
            raise NetworkError(
                "GitHub rejected the token in GITHUB_TOKEN (HTTP 401). Create a new one "
                "(e.g. export GITHUB_TOKEN=$(gh auth token)) or unset it."
            )
        if is_github_api and response.status_code in (403, 429):
            remaining = response.headers.get("x-ratelimit-remaining")
            if response.status_code == 429 or remaining == "0" or "rate limit" in response.text.lower():
                reset = response.headers.get("x-ratelimit-reset")
                when = ""
                if reset and reset.isdigit():
                    when = f" (resets at {time.strftime('%H:%M:%S %Z', time.localtime(int(reset)))})"
                raise RateLimited(
                    "GitHub API rate limit reached"
                    + when
                    + ". Set GITHUB_TOKEN to raise the limit, e.g. export GITHUB_TOKEN=$(gh auth token)"
                )

        text = response.text
        if response.status_code in (200, 404):
            self._cache_put(key, response.status_code, text)
        return response.status_code, self._decode(text, as_json)

    def _send(
        self, method: str, url: str, *, params: dict[str, Any] | None, body: dict[str, Any] | None
    ) -> httpx.Response:
        """Send one request. Redirects are followed only to the same host over https, at most 5."""
        origin = urlparse(url).hostname
        current, current_params = url, params
        for _ in range(6):
            headers: dict[str, str] = {}
            if current.startswith("https://api.github.com/"):
                headers["Accept"] = "application/vnd.github+json"
                headers["X-GitHub-Api-Version"] = "2022-11-28"
                if self.token:
                    headers["Authorization"] = f"Bearer {self.token}"
            try:
                response = self._client.request(
                    method, current, params=current_params, json=body, headers=headers
                )
            except (httpx.HTTPError, httpx.InvalidURL, ValueError) as exc:
                raise NetworkError(f"{method} {current}: {exc}") from exc
            if not response.is_redirect:
                return response
            location = response.headers.get("location", "")
            try:
                target = urljoin(str(response.url), location)
                parsed = urlparse(target)
                port = parsed.port  # raises ValueError for an out-of-range or malformed port
            except ValueError:
                self.queries.append(f"  (redirect to {location} not followed: malformed address)")
                return response
            if (
                parsed.scheme != "https"
                or parsed.hostname != origin
                or port not in (None, 443)
                or parsed.username
                or parsed.password
            ):
                self.queries.append(f"  (redirect to {target} not followed: different host or not https)")
                return response
            self.queries.append(f"  -> {method} {target}")
            current, current_params = target, None
        raise NetworkError(f"{method} {url}: too many redirects")

    @staticmethod
    def _decode(text: str, as_json: bool) -> Any:
        if not as_json:
            return text
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None

    def _cache_get(self, key: str) -> tuple[int, str] | None:
        if self._db is None:
            return None
        row = self._db.execute("SELECT t, status, body FROM cache WHERE k = ?", (key,)).fetchone()
        if row is None:
            return None
        # "Not found" answers expire sooner: new packages, policies and advisories appear all the time.
        ttl = min(self.ttl, NOT_FOUND_TTL) if int(row[1]) == 404 else self.ttl
        if time.time() - row[0] > ttl:
            return None
        return int(row[1]), str(row[2])

    def _cache_put(self, key: str, status: int, text: str) -> None:
        if self._db is None:
            return
        self._db.execute(
            "INSERT OR REPLACE INTO cache (k, t, status, body) VALUES (?, ?, ?, ?)",
            (key, time.time(), status, text),
        )
        self._db.commit()
