"""Find the source repository of a package from public registry metadata."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from predisclose.ecosystems import parse_repo
from predisclose.http import Http


def infer_repo(http: Http, ecosystem: str, name: str) -> str | None:
    return lookup(http, ecosystem, name)[0]


def lookup(http: Http, ecosystem: str, name: str) -> tuple[str | None, bool | None]:
    """
    (repository, exists). `exists` is True or False for registries we can ask, None otherwise.
    A package that does not exist is almost always a typo, and every other result would be empty.
    """
    urls: list[str] = []
    exists: bool | None = None
    if ecosystem == "PyPI":
        status, data = http.get_json(f"https://pypi.org/pypi/{quote(name)}/json")
        exists = _exists(status)
        if status == 200 and isinstance(data, dict):
            info = data.get("info") or {}
            urls += _ranked_project_urls(info.get("project_urls") or {})
            urls.append(str(info.get("home_page") or ""))
    elif ecosystem == "npm":
        status, data = http.get_json(f"https://registry.npmjs.org/{quote(name, safe='@')}/latest")
        exists = _exists(status)
        if status == 200 and isinstance(data, dict):
            urls.append(_repository_url(data.get("repository")))
            urls.append(str(data.get("homepage") or ""))
    elif ecosystem == "crates.io":
        status, data = http.get_json(f"https://crates.io/api/v1/crates/{quote(name)}")
        exists = _exists(status)
        if status == 200 and isinstance(data, dict):
            crate = data.get("crate") or {}
            urls += [str(crate.get("repository") or ""), str(crate.get("homepage") or "")]
    elif ecosystem == "RubyGems":
        status, data = http.get_json(f"https://rubygems.org/api/v1/gems/{quote(name)}.json")
        exists = _exists(status)
        if status == 200 and isinstance(data, dict):
            urls += [str(data.get("source_code_uri") or ""), str(data.get("homepage_uri") or "")]
    elif ecosystem == "Packagist":
        status, data = http.get_json(f"https://repo.packagist.org/p2/{name}.json")
        exists = _exists(status)
        if status == 200 and isinstance(data, dict):
            versions = (data.get("packages") or {}).get(name) or []
            if versions:
                urls.append(str((versions[0].get("source") or {}).get("url") or ""))
    elif ecosystem == "Go" and name.startswith("github.com/"):
        urls.append(name)

    for url in urls:
        repo = parse_repo(url)
        if repo:
            return repo, exists
    return None, exists


def _exists(status: int) -> bool | None:
    if status == 200:
        return True
    if status == 404:
        return False
    return None


SOURCE_KEYS = ("source", "repository", "code", "github", "git", "homepage", "home")


def _ranked_project_urls(project_urls: Any) -> list[str]:
    """PyPI project URLs, the ones that name a source repository first (not Funding, Sponsor...)."""
    if not isinstance(project_urls, dict):
        return []

    def rank(item: tuple[Any, Any]) -> int:
        key = str(item[0]).lower()
        return next((i for i, k in enumerate(SOURCE_KEYS) if k in key), len(SOURCE_KEYS))

    return [str(url) for _key, url in sorted(project_urls.items(), key=rank)]


def _repository_url(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("url") or "")
    return str(value or "")
