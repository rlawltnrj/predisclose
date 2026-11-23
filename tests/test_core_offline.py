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


def test_not_found_answers_expire_sooner(tmp_path, monkeypatch):
    import predisclose.http as http_mod

    calls = []

    def counting(request):
        calls.append(str(request.url))
        return httpx.Response(404, text="")

    h = Http(cache_dir=tmp_path, transport=httpx.MockTransport(counting))
    h.get_text("https://raw.githubusercontent.com/a/b/HEAD/SECURITY.md")
    h.get_text("https://raw.githubusercontent.com/a/b/HEAD/SECURITY.md")
    assert len(calls) == 1  # cached

    real_time = http_mod.time.time
    monkeypatch.setattr(http_mod.time, "time", lambda: real_time() + http_mod.NOT_FOUND_TTL + 1)
    h.get_text("https://raw.githubusercontent.com/a/b/HEAD/SECURITY.md")
    assert len(calls) == 2  # 404 expired, 200s would still be cached
    h.close()


def _not_found(request):
    url = str(request.url)
    if url.startswith("https://pypi.org/pypi/"):
        return httpx.Response(404, json={"message": "Not Found"})
    if url.startswith("https://api.github.com/repos/"):
        return httpx.Response(404, json={"message": "Not Found"})
    if url.startswith("https://api.osv.dev/"):
        return httpx.Response(200, json={"vulns": []})  # no advisory names the typo either
    if url.startswith("https://api.github.com/advisories"):
        return httpx.Response(200, json=[])
    return handler(request)


def test_misspelled_package_is_an_error_not_a_clean_result():
    http = Http(use_cache=False, transport=httpx.MockTransport(_not_found))
    report = run_check(http, Finding(ecosystem="PyPI", package="widgte", version="1.0.0"))
    assert all(r.status == "error" for r in report.results)
    assert "Check the spelling" in report.results[0].summary


def test_missing_repository_is_reported():
    http = Http(use_cache=False, transport=httpx.MockTransport(_not_found))
    report = run_check(http, Finding(repo="nobody/nothing", version="1.0"))
    assert all(r.status == "error" for r in report.results)
    assert "not found" in report.results[0].summary


def test_homepage_redirect_to_internal_host_is_not_followed():
    from predisclose.checks import route

    seen = []

    def evil(request):
        seen.append(str(request.url))
        if str(request.url) == "https://curl.se/.well-known/security.txt":
            return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data/"})
        return httpx.Response(200, text="Contact: x@y.z")

    http = Http(use_cache=False, transport=httpx.MockTransport(evil))
    assert route.security_txt_contacts(http, "https://curl.se") is None
    assert seen == ["https://curl.se/.well-known/security.txt"]
    assert any("not followed" in q for q in http.queries)


def test_internal_homepages_are_never_contacted():
    from predisclose.checks.route import public_host

    for home in ["http://127.0.0.1:8080", "http://user:pw@127.0.0.1", "http://169.254.169.254",
                 "http://localhost", "https://printer.local", "https://[::1]/", "https://["]:
        assert public_host(home) is None, home


def test_terminal_output_strips_control_characters():
    from io import StringIO

    from rich.console import Console

    from predisclose.models import CheckResult, Evidence, Report
    from predisclose.output import to_terminal

    bad = "title\x1b[2J\x1b[H [bold]x[/] \x07"
    report = Report("0", "now", Finding(repo="a/b"), [CheckResult("public_record", "found", "weak", bad,
                    [Evidence("osv", "ID\x1b]0;pwn\x07", bad, "https://x.example/a b")])], [])
    buf = StringIO()
    to_terminal(report, Console(file=buf, force_terminal=False, width=200))
    out = buf.getvalue()
    assert "\x1b" not in out and "\x07" not in out


def test_malformed_public_data_does_not_crash_the_run():
    def weird(request):
        url = str(request.url)
        if url.startswith("https://api.github.com/advisories"):
            return httpx.Response(200, json=[{"ghsa_id": "GHSA-x", "identifiers": [None], "cwes": [None],
                                               "vulnerabilities": [None], "references": [None]}])
        if url.startswith("https://raw.githubusercontent.com/acme/widget/HEAD/SECURITY.md"):
            return httpx.Response(200, text="Report to https://[ or [here](https://[)")
        return handler(request)

    http = Http(use_cache=False, transport=httpx.MockTransport(weird))
    report = run_check(http, Finding(ecosystem="PyPI", package="widget", version="1.0.0"))
    assert len(report.results) == 4
    assert {r.check for r in report.results} == {"public_record", "public_fix", "recent_activity", "where_to_report"}


def test_tested_versions_own_release_is_not_a_later_fix():
    def rel(request):
        url = str(request.url)
        if url.startswith(f"https://api.github.com/repos/{REPO}/releases"):
            return httpx.Response(200, json=[{"tag_name": "1.0.0", "name": "1.0.0", "body": "Security fixes",
                                               "published_at": "2026-01-01T02:00:00Z", "html_url": "x"}])
        return handler(request)

    http = Http(use_cache=False, transport=httpx.MockTransport(rel))
    report = run_check(http, Finding(repo=REPO, version="1.0.0"), ("fixes",))
    assert report.results[0].status == "none"


def test_security_txt_failure_does_not_hide_security_md(monkeypatch):
    # Regression: a redirect loop on the homepage's security.txt turned the whole
    # "where to report" answer into an error although SECURITY.md named a channel.
    from predisclose.checks import route

    monkeypatch.setattr(route, "public_host", lambda home: "docs.example.org")
    policy = "# Security\n\nPlease use GitHub private vulnerability reporting.\n"

    def loop(request):
        url = str(request.url)
        if url == "https://api.github.com/repos/acme/widget":
            return httpx.Response(200, json={"homepage": "https://docs.example.org", "archived": False})
        if url == "https://api.github.com/repos/acme/widget/private-vulnerability-reporting":
            return httpx.Response(200, json={"enabled": True})
        if url.startswith("https://raw.githubusercontent.com/acme/widget/") and url.endswith("/SECURITY.md"):
            return httpx.Response(200, text=policy)
        if url.startswith("https://docs.example.org/"):
            return httpx.Response(302, headers={"location": url + "x"})
        return httpx.Response(404, text="")

    http = Http(use_cache=False, transport=httpx.MockTransport(loop))
    result = route.check(http, "acme/widget")
    assert result.status == "found", result.summary
    assert "GitHub private vulnerability reporting" in result.summary
    assert any("security.txt could not be read" in n for n in result.notes)


def test_registry_404_with_advisories_is_not_a_typo():
    # Regression: Jenkins/androidx Maven artifacts and Go package paths are absent from Maven
    # Central / the Go proxy but have advisories; they were reported as misspelled.
    def elsewhere(request):
        url = str(request.url)
        if url.startswith("https://repo1.maven.org/"):
            return httpx.Response(404, text="")
        if url.startswith("https://api.osv.dev/"):
            return httpx.Response(200, json={"vulns": [OSV_VULN]})
        if url.startswith("https://api.github.com/advisories"):
            return httpx.Response(200, json=[])
        return httpx.Response(404, json={})

    http = Http(use_cache=False, transport=httpx.MockTransport(elsewhere))
    report = run_check(http, Finding(ecosystem="Maven", package="org.jenkins-ci.plugins:script-security",
                                     version="1.0.0"), ("known",))
    result = report.results[0]
    assert result.status == "found"
    assert any("does not list" in n for n in result.notes)


def test_off_registry_package_with_unaffected_version_is_not_a_typo():
    # Regression: a Jenkins plugin (not on Maven Central) at a version no advisory covers was
    # called a typo. The package-wide OSV query proves the name is real.
    def handler_(request):
        url = str(request.url)
        if url.startswith("https://repo1.maven.org/"):
            return httpx.Response(404, text="")
        if url.startswith("https://api.osv.dev/"):
            versioned = b'"version"' in request.content
            return httpx.Response(200, json={"vulns": [] if versioned else [OSV_VULN]})
        if url.startswith("https://api.github.com/advisories"):
            return httpx.Response(200, json=[])
        return httpx.Response(404, json={})

    http = Http(use_cache=False, transport=httpx.MockTransport(handler_))
    report = run_check(http, Finding(ecosystem="Maven", package="org.jenkins-ci.plugins:script-security",
                                     version="9999.0"), ("known",))
    result = report.results[0]
    assert result.status == "none"
    assert "Check the spelling" not in result.summary
    assert any("name is real" in n for n in result.notes)


def test_go_package_path_inside_a_module_exists():
    from predisclose.sources import registry

    def proxy(request):
        ok = str(request.url) == "https://proxy.golang.org/github.com/gin-gonic/gin/@v/list"
        return httpx.Response(200 if ok else 404, text="v1.10.0\n" if ok else "not found")

    http = Http(use_cache=False, transport=httpx.MockTransport(proxy))
    assert registry.lookup(http, "Go", "github.com/gin-gonic/gin/binding")[1] is True
    assert registry.lookup(http, "Go", "github.com/gin-gonic/gim/binding")[1] is False


def test_typo_does_not_get_an_inferred_repository():
    def typo(request):
        url = str(request.url)
        if url.startswith("https://proxy.golang.org/"):
            return httpx.Response(404, text="")
        if url.startswith("https://api.osv.dev/"):
            return httpx.Response(200, json={"vulns": []})
        return httpx.Response(200, json=[])

    http = Http(use_cache=False, transport=httpx.MockTransport(typo))
    report = run_check(http, Finding(ecosystem="Go", package="github.com/klauspost/compresss", version="v1.0.0"))
    assert report.finding.repo is None
    assert all(r.status == "error" for r in report.results)


def _raw_refused_handler(seen, raw_status):
    import base64

    policy = "# Security\n\nEmail security@acme.example to report a vulnerability.\n"

    def h(request):
        url = str(request.url)
        seen.append(url)
        if url == "https://api.github.com/repos/acme/widget":
            return httpx.Response(200, json={"homepage": "", "archived": False})
        if url == "https://api.github.com/repos/acme/widget/private-vulnerability-reporting":
            return httpx.Response(200, json={"enabled": False})
        if url == "https://raw.githubusercontent.com/acme/widget/HEAD/SECURITY.md":
            return httpx.Response(raw_status, text="")
        if url == "https://api.github.com/repos/acme/widget/contents/SECURITY.md":
            return httpx.Response(200, json={"encoding": "base64",
                                             "content": base64.b64encode(policy.encode()).decode()})
        return httpx.Response(404, text="")
    return h


def test_security_md_is_read_through_the_api_when_raw_refuses():
    # Regression (live check 2026-11-23): raw.githubusercontent.com answered CI runners with an
    # error, and SECURITY.md was treated as missing (curl fell back to security.txt, openssl to
    # "no channel").
    from predisclose.checks import route

    seen = []
    http = Http(use_cache=False, transport=httpx.MockTransport(_raw_refused_handler(seen, 429)))
    result = route.check(http, "acme/widget")
    assert result.status == "found", result.summary
    assert "Follow SECURITY.md: email security@acme.example" in result.summary
    assert "https://api.github.com/repos/acme/widget/contents/SECURITY.md" in seen


def test_missing_security_md_does_not_spend_api_quota():
    from predisclose.checks import route

    seen = []
    http = Http(use_cache=False, transport=httpx.MockTransport(_raw_refused_handler(seen, 404)))
    assert route.check(http, "acme/widget").status == "none"
    assert not any("/contents/" in u for u in seen)


def test_rate_limit_on_the_security_md_retry_keeps_the_rest_of_the_answer():
    # Review finding: the contents API retry raised RateLimited, which turned the whole
    # "where to report" answer into an error although private reporting was known to be on.
    from predisclose.checks import route

    def h(request):
        url = str(request.url)
        if url == "https://api.github.com/repos/acme/widget":
            return httpx.Response(200, json={"homepage": "", "archived": False})
        if url == "https://api.github.com/repos/acme/widget/private-vulnerability-reporting":
            return httpx.Response(200, json={"enabled": True})
        if url.startswith("https://raw.githubusercontent.com/"):
            return httpx.Response(429, text="")
        if "/contents/" in url:
            return httpx.Response(429, headers={"x-ratelimit-remaining": "0"}, text="rate limit")
        return httpx.Response(404, text="")

    http = Http(use_cache=False, transport=httpx.MockTransport(h))
    result = route.check(http, "acme/widget")
    assert result.status == "found", result.summary
    assert "GitHub private vulnerability reporting" in result.summary
