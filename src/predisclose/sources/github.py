"""Public GitHub repository data: metadata, private reporting status, files, commits, releases."""

from __future__ import annotations

import base64
import binascii
import re
from typing import Any
from urllib.parse import quote

from predisclose.ecosystems import looks_like_sha
from predisclose.http import Http, NetworkError, RateLimited

API = "https://api.github.com"
RAW = "https://raw.githubusercontent.com"


def repo_info(http: Http, repo: str) -> dict[str, Any] | None:
    status, data = http.get_json(f"{API}/repos/{repo}")
    return data if status == 200 and isinstance(data, dict) else None


def private_reporting_enabled(http: Http, repo: str) -> bool | None:
    status, data = http.get_json(f"{API}/repos/{repo}/private-vulnerability-reporting")
    if status == 200 and isinstance(data, dict) and "enabled" in data:
        return bool(data["enabled"])
    return None


def raw_file(http: Http, repo: str, path: str) -> str | None:
    """
    Read a file from the default branch without spending API quota. raw.githubusercontent.com
    sometimes fails to serve a file that exists; only a 404 means the file is missing, so any
    other answer is retried once through the contents API. That retry is best effort: a rate limit
    or network error there must not discard the rest of the route answer.
    """
    status, text = http.get_text(f"{RAW}/{repo}/HEAD/{path}")
    if status == 200:
        return text or None
    if status == 404:
        return None
    try:
        status, data = http.get_json(f"{API}/repos/{repo}/contents/{quote(path)}")
    except (RateLimited, NetworkError):
        return None
    if status != 200 or not isinstance(data, dict) or data.get("encoding") != "base64":
        return None
    try:
        decoded = base64.b64decode(str(data.get("content") or ""), validate=False)
    except (ValueError, binascii.Error):
        return None
    return decoded.decode("utf-8", errors="replace") or None


GO_PSEUDO = re.compile(r"v\d+\.\d+\.\d+-(?:[0-9A-Za-z.]+\.)?(?:0\.)?\d{14}-([0-9a-f]{12})(?:\+incompatible)?")


def resolve_version(
    http: Http, repo: str, version: str, package: str | None = None
) -> tuple[str, str, str] | None:
    """Turn a version (tag name guess) or a commit sha into (ref, sha, iso_date)."""
    candidates = [version]
    pseudo = GO_PSEUDO.fullmatch(version)
    if pseudo:  # Go pseudo-version: vX.Y.Z-yyyymmddhhmmss-<12-char commit>
        candidates.insert(0, pseudo.group(1))
    elif not looks_like_sha(version):
        candidates.append(f"v{version}")
        if package:
            short = package.rsplit("/", 1)[-1].rsplit(":", 1)[-1]
            candidates += [f"{short}-{version}", f"{short}@{version}", f"{short}-v{version}"]
        candidates.append(f"release-{version}")
    seen: set[str] = set()
    for ref in candidates:
        if ref in seen:
            continue
        seen.add(ref)
        status, data = http.get_json(f"{API}/repos/{repo}/commits/{quote(ref, safe='')}")
        if status == 200 and isinstance(data, dict) and data.get("sha"):
            date = ((data.get("commit") or {}).get("committer") or {}).get("date") or ""
            return ref, str(data["sha"]), str(date)
    return None


def tree_paths(http: Http, repo: str, ref: str) -> tuple[list[str], bool] | None:
    """All file paths at a ref. Returns (paths, truncated) or None."""
    status, data = http.get_json(
        f"{API}/repos/{repo}/git/trees/{quote(ref, safe='')}", params={"recursive": "1"}
    )
    if status != 200 or not isinstance(data, dict):
        return None
    paths = [str(t.get("path")) for t in data.get("tree") or [] if t.get("type") == "blob"]
    return paths, bool(data.get("truncated"))


def commits_since(
    http: Http, repo: str, since: str, path: str | None = None, per_page: int = 100
) -> list[dict[str, Any]]:
    params: dict[str, Any] = {"since": since, "per_page": per_page}
    if path:
        params["path"] = path
    status, data = http.get_json(f"{API}/repos/{repo}/commits", params=params)
    return data if status == 200 and isinstance(data, list) else []


def releases(http: Http, repo: str, per_page: int = 50) -> list[dict[str, Any]]:
    status, data = http.get_json(f"{API}/repos/{repo}/releases", params={"per_page": per_page})
    return data if status == 200 and isinstance(data, list) else []
