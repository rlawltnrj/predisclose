"""Regression tests for the 0.1.2 review (security and robustness)."""

from __future__ import annotations

import io
import stat
import time

import httpx
from rich.console import Console

from predisclose.checks import route
from predisclose.http import Http
from predisclose.ledger import Ledger
from predisclose.models import CheckResult, Evidence, Finding, Report
from predisclose.output import to_markdown, to_terminal
from predisclose.text import md_url, one_line


def test_huge_policy_line_is_parsed_quickly():
    text = "# Security\n\nreport " + "a" * 150_000 + "\n\nPlease report vulnerabilities to security@acme.org\n"
    start = time.monotonic()
    channels = route.parse_policy(text, "acme/widget", None)
    assert time.monotonic() - start < 2
    assert any(c.value == "security@acme.org" for c in channels)


def _report(url: str) -> Report:
    ev = Evidence("ghsa", "GHSA-xxxx-xxxx-xxxx", "title", url, level="medium")
    res = CheckResult("public_fix", "found", "medium", "summary", [ev])
    return Report("0", "now", Finding(repo="acme/widget"), [res], [])


def test_urls_with_markup_characters_are_encoded():
    for url in [
        "https://github.com/x/y/commit/abc1234[/link]",
        "https://e.com/x]evil",
        'https://e.com/"onmouseover',
        "https://e.com/a\\b",
    ]:
        safe = md_url(url)
        assert safe.startswith("https://") and not any(c in safe for c in "[]\"'\\`"), safe
        buf = io.StringIO()
        to_terminal(_report(url), Console(file=buf, width=200))  # must not raise MarkupError
        assert "evil]" not in buf.getvalue()
        line = to_markdown(_report(url)).split("GHSA-xxxx-xxxx-xxxx", 1)[1].split("\n", 1)[0]
        assert "](" not in line.replace(f"]({safe})", "")
    assert md_url("https://e.com/?a[]=1") == "https://e.com/?a%5B%5D=1"
    assert md_url("https://github.com/x/y/commit/abc") == "https://github.com/x/y/commit/abc"
    assert md_url("javascript:alert(1)") == ""


def test_bidi_controls_are_stripped():
    assert one_line("safe‮evil⁦x⁩") == "safeevilx"


def test_redirect_to_other_port_is_not_followed():
    def handler(request):
        if request.url.port in (None, 443):
            return httpx.Response(302, headers={"location": "https://api.github.com:8443/x"})
        raise AssertionError("followed a redirect to another port")

    http = Http(use_cache=False, transport=httpx.MockTransport(handler), token="ghp_x")
    status, _ = http.get_json("https://api.github.com/repos/a/b")
    assert status == 302
    assert any("not followed" in q for q in http.queries)


def test_cache_does_not_share_token_and_anonymous_answers(tmp_path):
    calls = []

    def handler(request):
        calls.append(request.headers.get("authorization"))
        return httpx.Response(200, json={"n": len(calls)})

    with_token = Http(cache_dir=tmp_path, transport=httpx.MockTransport(handler), token="ghp_x")
    with_token.get_json("https://api.github.com/repos/a/b")
    with_token.close()
    anon = Http(cache_dir=tmp_path, transport=httpx.MockTransport(handler))
    anon.get_json("https://api.github.com/repos/a/b")
    anon.close()
    assert calls == ["Bearer ghp_x", None]


def test_cache_and_ledger_are_private(tmp_path):
    own = tmp_path / "predisclose"
    Http(cache_dir=own, transport=httpx.MockTransport(lambda r: httpx.Response(200))).close()
    Ledger(own / "ledger.sqlite").close()
    assert stat.S_IMODE(own.stat().st_mode) == 0o700
    for name in ("http.sqlite", "ledger.sqlite"):
        assert stat.S_IMODE((own / name).stat().st_mode) == 0o600


def test_user_named_directory_keeps_its_permissions(tmp_path):
    folder = tmp_path / "shared"
    folder.mkdir(mode=0o755)
    folder.chmod(0o755)
    Ledger(folder / "my.sqlite").close()
    assert stat.S_IMODE(folder.stat().st_mode) == 0o755
    assert stat.S_IMODE((folder / "my.sqlite").stat().st_mode) == 0o600


def test_query_log_is_cleaned_before_printing(monkeypatch):
    from typer.testing import CliRunner

    from predisclose import cli

    class FakeHttp(Http):
        def __init__(self, *a, **k):
            super().__init__(use_cache=False, transport=httpx.MockTransport(lambda r: httpx.Response(404)))
            self.queries.append("  -> GET https://e.com/\u202eabc\x9b2J")

    buf = io.StringIO()
    monkeypatch.setattr(cli, "Http", FakeHttp)
    monkeypatch.setattr(cli, "err", Console(file=buf, width=200))
    CliRunner().invoke(cli.app, ["check", "--repo", "acme/widget", "--only", "route", "--show-queries"])
    printed = buf.getvalue()
    assert "e.com/abc2J" in printed
    assert "\u202e" not in printed and "\x9b" not in printed


def test_markup_in_user_input_gives_a_clean_error(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from predisclose import cli

    monkeypatch.setattr(cli, "_ledger", lambda: Ledger(tmp_path / "l.sqlite"))
    result = CliRunner().invoke(cli.app, ["ledger", "add", "o/r", "t", "--sent", "[/x]"])
    assert result.exit_code == 2
    assert result.exception is None or isinstance(result.exception, SystemExit)
