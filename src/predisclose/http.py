"""One HTTP client for every source: records each outgoing query, caches answers, never leaks tokens."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx

from predisclose import __version__

NOT_FOUND_TTL = 30 * 60


class RateLimited(Exception):
    """GitHub refused the request because the hourly or per-minute quota is used up."""


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
            directory.mkdir(parents=True, exist_ok=True)
            self._db = sqlite3.connect(directory / "http.sqlite")
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS cache "
                "(k TEXT PRIMARY KEY, t REAL NOT NULL, status INTEGER NOT NULL, body TEXT NOT NULL)"
            )
        self._client = httpx.Client(
            timeout=20.0,
            follow_redirects=True,
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
            json.dumps([method, url, params or {}, body], sort_keys=True).encode()
        ).hexdigest()
        cached = self._cache_get(key)
        if cached is not None:
            status, text = cached
            return status, self._decode(text, as_json)

        headers: dict[str, str] = {}
        is_github_api = url.startswith("https://api.github.com/")
        if is_github_api:
            headers["Accept"] = "application/vnd.github+json"
            headers["X-GitHub-Api-Version"] = "2022-11-28"
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
        try:
            response = self._client.request(method, url, params=params, json=body, headers=headers)
        except httpx.HTTPError as exc:
            raise NetworkError(f"{method} {url}: {exc}") from exc

        if is_github_api and response.status_code in (403, 429):
            remaining = response.headers.get("x-ratelimit-remaining")
            if response.status_code == 429 or remaining == "0" or "rate limit" in response.text.lower():
                reset = response.headers.get("x-ratelimit-reset")
                when = ""
                if reset and reset.isdigit():
                    when = f" (resets at {time.strftime('%H:%M:%S', time.localtime(int(reset)))})"
                raise RateLimited(
                    "GitHub API rate limit reached"
                    + when
                    + ". Set GITHUB_TOKEN to raise the limit, e.g. export GITHUB_TOKEN=$(gh auth token)"
                )

        text = response.text
        if response.status_code in (200, 404):
            self._cache_put(key, response.status_code, text)
        return response.status_code, self._decode(text, as_json)

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
