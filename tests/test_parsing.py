import pytest

from predisclose.checks.similarity import score
from predisclose.ecosystems import normalize_cwe, parse_package, parse_repo
from predisclose.models import Finding
from predisclose.sources.advisory import Advisory, merge


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("pypi:jinja2", ("PyPI", "jinja2")),
        ("npm:@scope/pkg", ("npm", "@scope/pkg")),
        ("maven:org.example:lib", ("Maven", "org.example:lib")),
        ("cargo:hyper", ("crates.io", "hyper")),
        ("go:github.com/gin-gonic/gin", ("Go", "github.com/gin-gonic/gin")),
    ],
)
def test_parse_package(spec, expected):
    assert parse_package(spec) == expected


@pytest.mark.parametrize("spec", ["jinja2", "nope:thing", "pypi:"])
def test_parse_package_rejects(spec):
    with pytest.raises(ValueError):
        parse_package(spec)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("pallets/jinja", "pallets/jinja"),
        ("https://github.com/pallets/jinja", "pallets/jinja"),
        ("git+https://github.com/pallets/jinja.git", "pallets/jinja"),
        ("git@github.com:pallets/jinja.git", "pallets/jinja"),
        ("https://gitlab.com/a/b", None),
        ("", None),
    ],
)
def test_parse_repo(text, expected):
    assert parse_repo(text) == expected


def test_normalize_cwe():
    assert normalize_cwe("79") == "CWE-79"
    assert normalize_cwe("cwe-079") == "CWE-79"
    with pytest.raises(ValueError):
        normalize_cwe("XSS")


def _adv(**kw):
    base = dict(id="GHSA-aaaa-bbbb-cccc", summary="", details="", cwes=set(), functions=set())
    base.update(kw)
    return Advisory(**base)


def test_score_levels():
    adv = _adv(summary="Sandbox escape in sandbox.py via format", cwes={"CWE-693"})
    assert score(adv, Finding(cwe=["CWE-693"], files=["src/jinja2/sandbox.py"]))[0] == "strong"
    assert score(adv, Finding(cwe=["CWE-693"]))[0] == "medium"
    assert score(adv, Finding(cwe=["CWE-79"]))[0] == "weak"


def test_score_function_from_structured_data():
    adv = _adv(functions={"pkg.module.parse_header"})
    level, reasons = score(adv, Finding(functions=["parse_header"], files=["header.c"]))
    assert level == "medium"
    assert any("function" in r for r in reasons)


def test_names_match_whole_tokens_only():
    # Regression: substring matching rated these "strong - likely already known".
    adv = _adv(summary="overflow in radio.c path handling", cwes={"CWE-22"})
    assert score(adv, Finding(cwe=["CWE-22"], files=["io.c"]))[0] == "medium"  # CWE only
    adv = _adv(summary="race in thread pool, already fixed", cwes={"CWE-362"})
    assert score(adv, Finding(cwe=["CWE-362"], functions=["read"]))[0] == "medium"
    adv = _adv(summary="bug in lib/io.c when calling `read()`", cwes={"CWE-22"})
    assert score(adv, Finding(cwe=["CWE-22"], files=["io.c"]))[0] == "strong"
    assert score(adv, Finding(functions=["read"], files=["io.c"]))[0] == "strong"


def test_short_function_name_needs_code_form():
    adv = _adv(summary="attackers can read arbitrary files")
    assert score(adv, Finding(functions=["read"]))[0] == "weak"
    adv = _adv(summary="calling read( with a large size overflows")
    assert score(adv, Finding(functions=["read"]))[0] == "medium"


def test_unversioned_advisory_is_capped():
    adv = _adv(summary="bug in sandbox.py", cwes={"CWE-693"}, version_checked=False)
    level, reasons = score(adv, Finding(cwe=["CWE-693"], files=["sandbox.py"]))
    assert level == "medium"
    assert "version not checked" in reasons


def test_merge_by_alias():
    a = _adv(id="PYSEC-2019-1", aliases={"GHSA-aaaa-bbbb-cccc", "CVE-2019-1"}, sources={"osv"})
    b = _adv(id="GHSA-aaaa-bbbb-cccc", aliases={"CVE-2019-1"}, cwes={"CWE-79"}, sources={"ghsa"},
             url="https://github.com/advisories/GHSA-aaaa-bbbb-cccc")
    merged = merge([a, b])
    assert len(merged) == 1
    assert merged[0].display_id() == "GHSA-aaaa-bbbb-cccc"
    assert merged[0].cwes == {"CWE-79"}
    assert merged[0].sources == {"osv", "ghsa"}


def test_merge_is_transitive():
    a = _adv(id="PYSEC-1", aliases={"CVE-1"})
    b = _adv(id="GHSA-1", aliases={"OSV-9"})
    c = _adv(id="CVE-1", aliases={"GHSA-1"})
    merged = merge([a, b, c])
    assert len(merged) == 1
    assert merged[0].all_ids() == {"PYSEC-1", "CVE-1", "GHSA-1", "OSV-9"}


@pytest.mark.parametrize(
    "text",
    [
        "https://github.com/sponsors/alice",
        "https://gist.github.com/alice/abc123",
        "https://github.com/orgs/acme/projects",
        "https://notgithub.com/a/b",
    ],
)
def test_parse_repo_rejects_non_repositories(text):
    assert parse_repo(text) is None


def test_date_like_version_is_not_a_sha():
    from predisclose.ecosystems import looks_like_sha

    assert not looks_like_sha("20231215")
    assert looks_like_sha("6de60977acd7")
    assert looks_like_sha("a" * 40)


def test_pypi_source_url_beats_funding_url():
    from predisclose.sources.registry import _ranked_project_urls

    urls = _ranked_project_urls({"Funding": "https://github.com/sponsors/alice", "Source": "https://github.com/acme/widget"})
    assert urls[0] == "https://github.com/acme/widget"
