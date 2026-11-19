"""End-to-end run against canned responses. No network is used."""

import json

import httpx
from typer.testing import CliRunner

from predisclose.cli import app
from predisclose.core import run_check
from predisclose.http import Http
from predisclose.models import Finding

REPO = "acme/widget"
TAG_SHA = "a" * 40

OSV_VULN = {
    "id": "GHSA-1111-2222-3333",
    "aliases": ["CVE-2026-1000"],
    "summary": "Path traversal in upload.py",
    "details": "The save() helper in upload.py does not normalize paths.",
    "published": "2026-06-01T00:00:00Z",
    "database_specific": {"cwe_ids": ["CWE-22"]},
    "references": [{"type": "WEB", "url": f"https://github.com/{REPO}/commit/{'b' * 40}"}],
}


def handler(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    if url.startswith("https://pypi.org/pypi/widget/json"):
        return httpx.Response(200, json={"info": {"project_urls": {"Source": f"https://github.com/{REPO}"}}})
    if url.startswith("https://api.osv.dev/v1/query"):
        body = json.loads(request.content)
        if "version" in body:
            return httpx.Response(200, json={"vulns": [OSV_VULN]})
        return httpx.Response(200, json={"vulns": [OSV_VULN]})
    if url.startswith("https://api.github.com/advisories"):
        return httpx.Response(200, json=[])
    if url.startswith(f"https://api.github.com/repos/{REPO}/commits/"):
        ref = url.rsplit("/", 1)[-1]
        if ref == "1.0.0":
            return httpx.Response(200, json={"sha": TAG_SHA, "commit": {"committer": {"date": "2026-01-01T00:00:00Z"}}})
        return httpx.Response(404, json={})
    if url.startswith(f"https://api.github.com/repos/{REPO}/git/trees/"):
        return httpx.Response(200, json={"tree": [{"path": "src/widget/upload.py", "type": "blob"}]})
    if url.startswith(f"https://api.github.com/repos/{REPO}/commits?"):
        return httpx.Response(
            200,
            json=[
                {
                    "sha": "c" * 40,
                    "html_url": f"https://github.com/{REPO}/commit/{'c' * 40}",
                    "commit": {
                        "message": "Fix path traversal in upload",
                        "committer": {"date": "2026-05-30T00:00:00Z"},
                    },
                }
            ],
        )
    if url == f"https://api.github.com/repos/{REPO}":
        return httpx.Response(200, json={"homepage": "", "archived": False})
    if url == f"https://api.github.com/repos/{REPO}/private-vulnerability-reporting":
        return httpx.Response(200, json={"enabled": True})
    if url == f"https://api.github.com/repos/{REPO}/security-advisories?state=published&per_page=100":
        return httpx.Response(200, json=[])
    if url.startswith("https://raw.githubusercontent.com/"):
        return httpx.Response(404, text="")
    return httpx.Response(404, json={"unexpected": url})


def make_http() -> Http:
    return Http(use_cache=False, transport=httpx.MockTransport(handler))


def test_full_run():
    finding = Finding(ecosystem="PyPI", package="widget", version="1.0.0", cwe=["CWE-22"], files=["upload.py"])
    report = run_check(make_http(), finding)
    by = {r.check: r for r in report.results}

    assert report.finding.repo == REPO
    assert by["public_record"].level == "strong"
    assert by["public_record"].evidence[0].id == "GHSA-1111-2222-3333"

    fix = by["public_fix"]
    assert fix.status == "found"
    assert any("path traversal" in e.title.lower() for e in fix.evidence)
    assert any(e.source == "advisory" for e in fix.evidence)  # fix commit named by the advisory

    assert by["where_to_report"].summary.startswith("GitHub private vulnerability reporting")
    assert report.queries, "every request must be recorded"


def test_finding_text_never_sent():
    finding = Finding(ecosystem="PyPI", package="widget", version="1.0.0", keywords=["secretword"])
    report = run_check(make_http(), finding)
    assert not any("secretword" in q for q in report.queries)


def test_token_not_in_query_log():
    http = Http(use_cache=False, transport=httpx.MockTransport(handler), token="ghp_supersecret")
    report = run_check(http, Finding(repo=REPO), ("route",))
    assert not any("supersecret" in q for q in report.queries)


def test_cli_dry_run_sends_nothing():
    result = CliRunner().invoke(app, ["check", "--pkg", "pypi:widget", "--version", "1.0.0", "--dry-run"])
    assert result.exit_code == 0, result.output
    assert "Dry run" in result.output


def test_cli_rejects_bad_input():
    result = CliRunner().invoke(app, ["check", "--pkg", "widget"])
    assert result.exit_code == 2
