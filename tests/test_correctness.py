"""Regression tests for the 0.1.2 review (correctness)."""

from __future__ import annotations

import httpx
import pytest
from typer.testing import CliRunner

from predisclose.checks import known
from predisclose.checks.known import is_exact_version
from predisclose.checks.route import parse_policy
from predisclose.cli import app
from predisclose.core import repo_from_advisories, run_check
from predisclose.http import Http
from predisclose.models import Finding
from predisclose.sources import ghsa, github
from predisclose.sources.advisory import Advisory


def _adv(i: int, hint: str | None) -> Advisory:
    return Advisory(id=f"GHSA-{i}", aliases=set(), summary="", details="", published=None, cwes=set(),
                    functions=set(), url="", sources={"ghsa"}, repo_hint=hint)


def test_go_x_packages_map_to_their_own_repository():
    f = Finding(ecosystem="Go", package="golang.org/x/crypto", version="v0.16.0")
    assert repo_from_advisories(f, [_adv(1, "warp-tech/russh")]) == ("golang/crypto", None)


def test_conflicting_repo_hints_are_not_guessed():
    f = Finding(ecosystem="Maven", package="org.example:thing", version="1.0")
    repo, note = repo_from_advisories(f, [_adv(1, "a/one"), _adv(2, "b/two")])
    assert repo is None and "--repo" in note
    assert repo_from_advisories(f, [_adv(1, "a/x"), _adv(2, "b/thing")])[0] == "b/thing"
    assert repo_from_advisories(f, [_adv(1, "a/x"), _adv(2, "a/x"), _adv(3, "b/y")])[0] == "a/x"


def test_multi_package_advisory_gives_no_repo_hint():
    data = {
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "source_code_location": "https://github.com/warp-tech/russh",
        "vulnerabilities": [{"package": {"name": "russh"}}, {"package": {"name": "golang.org/x/crypto"}}],
    }
    assert ghsa.to_advisory(data, version_checked=True).repo_hint is None
    data["vulnerabilities"] = [{"package": {"name": "russh"}}]
    assert ghsa.to_advisory(data, version_checked=True).repo_hint == "warp-tech/russh"


@pytest.mark.parametrize("osv_status,ghsa_status", [(503, 200), (200, 502)])
def test_advisory_source_failure_is_an_error_not_a_clean_result(osv_status, ghsa_status):
    def handler(request):
        url = str(request.url)
        if url.startswith("https://pypi.org/"):
            return httpx.Response(200, json={"info": {"project_urls": {}}})
        if url.startswith("https://api.osv.dev/"):
            return httpx.Response(osv_status, json={"vulns": []} if osv_status == 200 else {})
        if url.startswith("https://api.github.com/advisories"):
            return httpx.Response(ghsa_status, json=[] if ghsa_status == 200 else {})
        return httpx.Response(404, json={})

    http = Http(use_cache=False, transport=httpx.MockTransport(handler))
    report = run_check(http, Finding(ecosystem="PyPI", package="jinja2", version="2.10"), ("known",))
    result = report.results[0]
    assert result.status == "error", result.summary
    assert "No public advisory" not in result.summary


def test_headings_and_negations_do_not_choose_github():
    def best(text):
        return parse_policy(text, "a/b", True)[0].kind

    assert best("## Report a Vulnerability\n\nPlease email security@acme.org with details.\n") == "email"
    assert best("Please do not use GitHub security advisories. Send reports to security@acme.org.\n") == "email"
    assert best("Do not open a public issue; use GitHub private vulnerability reporting.\n") == "github"
    assert best("If you are not sure, use GitHub private vulnerability reporting.\n") == "github"


@pytest.mark.parametrize("v", ["1.2.3", "v0.16.0", "2.0.0-rc1", "20260522", "8.0.5.1",
                               "v0.0.0-20210226172049-e18ecbb05110", "1.0.0.Final"])
def test_exact_versions(v):
    assert is_exact_version(v)


@pytest.mark.parametrize("v", ["4.x", "2.10.x", "2.10.*", "latest", ">=1.0", "^1.2"])
def test_ranges_are_not_sent_as_versions(v):
    sent = []

    def handler(request):
        sent.append(request.content.decode() if request.content else str(request.url))
        if "osv.dev" in str(request.url):
            return httpx.Response(200, json={"vulns": []})
        return httpx.Response(200, json=[])

    http = Http(use_cache=False, transport=httpx.MockTransport(handler))
    advs, notes = known.gather(http, Finding(ecosystem="PyPI", package="jinja2", version=v))
    assert not any(v in s for s in sent), sent
    assert any("not an exact version" in n for n in notes)


def test_long_advisory_list_says_it_may_be_cut_off():
    page = [{"ghsa_id": f"GHSA-{i:04d}-aaaa-bbbb"} for i in range(100)]

    def handler(request):
        if "osv.dev" in str(request.url):
            return httpx.Response(200, json={"vulns": []})
        return httpx.Response(200, json=page)

    http = Http(use_cache=False, transport=httpx.MockTransport(handler))
    _, notes = known.gather(http, Finding(ecosystem="PyPI", package="big", version="1.0"))
    assert any("maximum of 100" in n for n in notes)


def test_go_pseudo_version_resolves_to_its_commit():
    asked = []

    def handler(request):
        asked.append(str(request.url))
        if str(request.url).endswith("/commits/e18ecbb05110"):
            return httpx.Response(200, json={"sha": "e18ecbb05110" + "0" * 28,
                                             "commit": {"committer": {"date": "2021-02-26T17:20:49Z"}}})
        return httpx.Response(404, json={})

    http = Http(use_cache=False, transport=httpx.MockTransport(handler))
    got = github.resolve_version(http, "a/b", "v0.0.0-20210226172049-e18ecbb05110")
    assert got and got[0] == "e18ecbb05110"
    assert len(asked) == 1


@pytest.mark.parametrize("body,needle", [
    ('package = "pypi:jinja2"\nversion = 2.10\n', "version"),
    ('package = "pypi:jinja2"\nversion = "2.10"\nfiles = [1, 2]\n', "files"),
])
def test_finding_file_with_wrong_types_fails_cleanly(tmp_path, body, needle):
    path = tmp_path / "f.toml"
    path.write_text(body)
    result = CliRunner().invoke(app, ["check", "--from", str(path), "--dry-run"])
    assert result.exit_code == 2
    assert needle in result.output


def test_single_string_in_finding_file_becomes_one_item(tmp_path):
    from predisclose.cli import _load_finding_file

    path = tmp_path / "f.toml"
    path.write_text('package = "pypi:jinja2"\nversion = "2.10"\nfiles = "sandbox.py"\n')
    assert _load_finding_file(path)["files"] == ["sandbox.py"]


def test_unfiltered_advisories_are_not_said_to_affect_the_version():
    def handler(request):
        if "osv.dev" in str(request.url):
            return httpx.Response(200, json={"vulns": [{"id": "GHSA-aaaa-bbbb-cccc", "summary": "x"}]})
        return httpx.Response(200, json=[])

    http = Http(use_cache=False, transport=httpx.MockTransport(handler))
    f = Finding(ecosystem="npm", package="express", version="4.x")
    advs, notes = known.gather(http, f)
    result = known.check(http, f, advs, notes)
    assert "affect" not in result.summary
    assert "not filtered by version" in result.summary


@pytest.mark.parametrize("text", [
    "Do not open a public issue and use the Security tab to report a vulnerability.",
    "Never file public issues - use GitHub private vulnerability reporting instead.",
    "Avoid public issues and privately report via the Security tab.",
    "Don't hesitate to report a vulnerability through the Security tab.",
    "## Use GitHub private vulnerability reporting",
    "Report at https://github.com/a/b/security/advisories/new",
])
def test_positive_github_phrasings_still_count(text):
    assert parse_policy(text, "a/b", True)[0].kind == "github"


def test_heading_can_carry_the_only_channel():
    assert parse_policy("## Contact security@acme.io\n", "a/b", None)[0].value == "security@acme.io"


def test_negated_github_link_is_not_recommended():
    text = "Do not use [GitHub Security Advisories](https://github.com/a/b/security/advisories/new). " \
           "Email security@acme.org.\n"
    got = parse_policy(text, "a/b", True)
    assert got[0].kind == "email"
    assert not any("advisories" in c.value for c in got)


def test_artifacts_of_one_project_keep_the_repo_hint():
    data = {
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "source_code_location": "https://github.com/bcgit/bc-java",
        "vulnerabilities": [{"package": {"name": "org.bouncycastle:bcprov-jdk15on"}},
                            {"package": {"name": "org.bouncycastle:bcprov-jdk18on"}}],
    }
    assert ghsa.to_advisory(data, version_checked=True).repo_hint == "bcgit/bc-java"


def test_one_failed_source_keeps_the_other_with_a_note():
    def handler(request):
        if "osv.dev" in str(request.url):
            return httpx.Response(200, json={"vulns": [{"id": "GHSA-aaaa-bbbb-cccc", "summary": "x"}]})
        return httpx.Response(502, json={})

    http = Http(use_cache=False, transport=httpx.MockTransport(handler))
    advs, notes = known.gather(http, Finding(ecosystem="PyPI", package="jinja2", version="2.10"))
    assert [a.id for a in advs] == ["GHSA-aaaa-bbbb-cccc"]
    assert notes[0].startswith("Incomplete:")


@pytest.mark.parametrize("v", ["1!2.0", "1.0.0-x.1", "1.2.3-alpha.x"])
def test_more_exact_versions(v):
    assert is_exact_version(v)


def test_numeric_cwe_in_finding_file(tmp_path):
    from predisclose.cli import _load_finding_file

    path = tmp_path / "f.toml"
    path.write_text('package = "pypi:jinja2"\nversion = "2.10"\ncwe = [79]\n')
    assert _load_finding_file(path)["cwe"] == ["79"]


# -- pre-release review of 0.1.2 -----------------------------------------------------


@pytest.mark.parametrize("location", ["https://acme.example:99999/x", "https://[bad/x"])
def test_malformed_redirect_does_not_hide_security_md(monkeypatch, location):
    from predisclose.checks import route

    monkeypatch.setattr(route, "public_host", lambda home: "acme.example")

    def handler(request):
        url = str(request.url)
        if url == "https://api.github.com/repos/acme/widget":
            return httpx.Response(200, json={"homepage": "https://acme.example", "archived": False})
        if url.endswith("/private-vulnerability-reporting"):
            return httpx.Response(200, json={"enabled": False})
        if url.startswith("https://raw.githubusercontent.com/acme/widget/") and url.endswith("/SECURITY.md"):
            return httpx.Response(200, text="Please report vulnerabilities to security@acme.org\n")
        if url.startswith("https://acme.example/"):
            return httpx.Response(302, headers={"location": location})
        return httpx.Response(404, text="")

    http = Http(use_cache=False, transport=httpx.MockTransport(handler))
    result = route.check(http, "acme/widget")
    assert result.status == "found"
    assert "security@acme.org" in result.summary
    assert any("malformed" in q for q in http.queries)


def test_partial_result_says_incomplete_in_the_summary():
    def handler(request):
        if "osv.dev" in str(request.url):
            return httpx.Response(200, json={"vulns": [{"id": "GHSA-aaaa-bbbb-cccc", "summary": "x"}]})
        return httpx.Response(502, json={})

    http = Http(use_cache=False, transport=httpx.MockTransport(handler))
    f = Finding(ecosystem="npm", package="express", version="4.17.1")
    advs, notes = known.gather(http, f)
    assert "incomplete" in known.check(http, f, advs, notes).summary


@pytest.mark.parametrize("text", [
    "Please do **not** report through GitHub security advisories. Email security@acme.org.",
    "Email security@acme.org instead of using GitHub security advisories.",
    "Email security@acme.org rather than GitHub security advisories.",
    "No GitHub security advisories please. Email security@acme.org.",
    "GitHub security advisories are not monitored. Email security@acme.org.",
    "Do not use https://github.com/a/b/security/advisories/new - email security@acme.org.",
])
def test_more_negated_github_phrasings(text):
    got = parse_policy(text, "a/b", True)
    assert got[0].kind == "email"
    assert not any(c.kind == "github" or "advisories" in c.value for c in got)


def test_unrequested_public_record_error_is_not_shown():
    def handler(request):
        url = str(request.url)
        if url.startswith("https://pypi.org/"):
            return httpx.Response(200, json={"info": {"project_urls": {}}})
        if "osv.dev" in url or url.startswith("https://api.github.com/advisories"):
            return httpx.Response(503, json={})
        return httpx.Response(404, json={})

    http = Http(use_cache=False, transport=httpx.MockTransport(handler))
    report = run_check(http, Finding(ecosystem="PyPI", package="jinja2", version="2.10"), ("activity",))
    assert [r.check for r in report.results] == ["recent_activity"]


def test_version_range_is_not_used_as_a_starting_point_for_fixes():
    from predisclose.checks import fixes

    http = Http(use_cache=False, transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    result = fixes.check(http, Finding(repo="expressjs/express", version="4.x"))
    assert result.status == "skipped" and "not an exact version" in result.summary


# -- withdrawn advisories -------------------------------------------------------------


def test_withdrawn_advisories_are_left_out_with_a_note():
    def handler(request):
        url = str(request.url)
        if "osv.dev" in url:
            return httpx.Response(200, json={"vulns": [
                {"id": "GHSA-live-aaaa-bbbb", "summary": "real"},
                {"id": "GHSA-gone-aaaa-bbbb", "summary": "gone", "withdrawn": "2025-12-02T00:00:00Z"},
            ]})
        return httpx.Response(200, json=[
            {"ghsa_id": "GHSA-wdrn-aaaa-bbbb", "summary": "Withdrawn Advisory: x", "withdrawn_at": "2025-12-02"},
        ])

    http = Http(use_cache=False, transport=httpx.MockTransport(handler))
    advs, notes = known.gather(http, Finding(ecosystem="npm", package="express", version="4.17.1"))
    assert [a.id for a in advs] == ["GHSA-live-aaaa-bbbb"]
    assert any("withdrawn" in n and "GHSA-gone-aaaa-bbbb" in n for n in notes)


@pytest.mark.parametrize("summary,gone", [
    ("REJECTED (not a vulnerability): improperly controlled modification", True),
    ("[Withdrawn] duplicate of GHSA-xxxx", True),
    ("Rejection sampling bug allows bias", False),
    ("Invalidated session tokens are still accepted", False),
])
def test_retracted_repository_advisory_titles(summary, gone):
    adv = ghsa.to_advisory({"ghsa_id": "GHSA-aaaa-bbbb-cccc", "summary": summary}, version_checked=False)
    assert adv.withdrawn is gone


def test_activity_ignores_withdrawn_advisories():
    from datetime import UTC, datetime

    from predisclose.checks import activity

    def handler(request):
        if "osv.dev" in str(request.url):
            return httpx.Response(200, json={"vulns": []})
        return httpx.Response(200, json=[{"ghsa_id": "GHSA-aaaa-bbbb-cccc", "published_at": "2026-10-01T00:00:00Z",
                                          "summary": "REJECTED (not a vulnerability): x"}])

    http = Http(use_cache=False, transport=httpx.MockTransport(handler))
    result = activity.check(http, Finding(ecosystem="npm", package="express", repo="expressjs/express"),
                            now=datetime(2026, 11, 19, tzinfo=UTC))
    assert result.evidence == []
