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
    elif ecosystem == "Go":
        # The module proxy knows every public module; it answers 404/410 for one that doesn't exist.
        # "stdlib" and "toolchain" are OSV's names for Go itself, not proxy modules.
        if "." in name.split("/", 1)[0]:
            exists = _go_module_exists(http, name)
        if name.startswith("github.com/"):
            urls.append(name)
    elif ecosystem == "Maven" and ":" in name:
        group, artifact = name.split(":", 1)
        path = "/".join(quote(part) for part in group.split(".")) + "/" + quote(artifact)
        status, _ = http.get_text(f"https://repo1.maven.org/maven2/{path}/maven-metadata.xml")
        exists = _exists(status)
    elif ecosystem == "NuGet":
        status, _ = http.get_json(f"https://api.nuget.org/v3-flatcontainer/{quote(name.lower())}/index.json")
        exists = _exists(status)
    elif ecosystem == "Pub":
        status, data = http.get_json(f"https://pub.dev/api/packages/{quote(name)}")
        exists = _exists(status)
        if status == 200 and isinstance(data, dict):
            pubspec = (data.get("latest") or {}).get("pubspec") or {}
            if isinstance(pubspec, dict):
                urls += [str(pubspec.get("repository") or ""), str(pubspec.get("homepage") or "")]
    elif ecosystem == "Hex":
        status, data = http.get_json(f"https://hex.pm/api/packages/{quote(name)}")
        exists = _exists(status)
        if status == 200 and isinstance(data, dict):
            links = (data.get("meta") or {}).get("links") or {}
            if isinstance(links, dict):
                urls += _ranked_project_urls(links)

    for url in urls:
        repo = parse_repo(url)
        if repo:
            return repo, exists
    return None, exists


def _go_module_exists(http: Http, path: str) -> bool | None:
    """
    Whether `path` is a Go module or a package inside one. The proxy only knows modules, so
    github.com/gin-gonic/gin/binding is found through github.com/gin-gonic/gin.
    """
    parts = path.split("/")
    for end in range(len(parts), 1, -1):  # longest prefix first, at least host/one-element
        status, _ = http.get_text(f"https://proxy.golang.org/{_go_escape('/'.join(parts[:end]))}/@v/list")
        if status == 200:
            return True
        if status not in (404, 410):
            return None  # can't tell
    return False


def _go_escape(module: str) -> str:
    """Go module proxy path: upper-case letters become '!' plus the lower-case letter."""
    return "".join("!" + c.lower() if c.isupper() else c for c in module)


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
