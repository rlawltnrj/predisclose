"""Find the source repository of a package from public registry metadata."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from predisclose.ecosystems import parse_repo
from predisclose.http import Http


def infer_repo(http: Http, ecosystem: str, name: str) -> str | None:
    urls: list[str] = []
    if ecosystem == "PyPI":
        status, data = http.get_json(f"https://pypi.org/pypi/{quote(name)}/json")
        if status == 200 and isinstance(data, dict):
            info = data.get("info") or {}
            urls += [str(u) for u in (info.get("project_urls") or {}).values()]
            urls.append(str(info.get("home_page") or ""))
    elif ecosystem == "npm":
        status, data = http.get_json(f"https://registry.npmjs.org/{quote(name, safe='@')}/latest")
        if status == 200 and isinstance(data, dict):
            urls.append(_repository_url(data.get("repository")))
            urls.append(str(data.get("homepage") or ""))
    elif ecosystem == "crates.io":
        status, data = http.get_json(f"https://crates.io/api/v1/crates/{quote(name)}")
        if status == 200 and isinstance(data, dict):
            crate = data.get("crate") or {}
            urls += [str(crate.get("repository") or ""), str(crate.get("homepage") or "")]
    elif ecosystem == "RubyGems":
        status, data = http.get_json(f"https://rubygems.org/api/v1/gems/{quote(name)}.json")
        if status == 200 and isinstance(data, dict):
            urls += [str(data.get("source_code_uri") or ""), str(data.get("homepage_uri") or "")]
    elif ecosystem == "Packagist":
        status, data = http.get_json(f"https://repo.packagist.org/p2/{name}.json")
        if status == 200 and isinstance(data, dict):
            versions = (data.get("packages") or {}).get(name) or []
            if versions:
                urls.append(str((versions[0].get("source") or {}).get("url") or ""))
    elif ecosystem == "Go" and name.startswith("github.com/"):
        urls.append(name)

    for url in urls:
        repo = parse_repo(url)
        if repo:
            return repo
    return None


def _repository_url(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("url") or "")
    return str(value or "")
