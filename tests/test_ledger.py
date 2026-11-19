from datetime import date

import pytest

from predisclose.ledger import Ledger, export


@pytest.fixture
def lg(tmp_path):
    ledger = Ledger(tmp_path / "ledger.sqlite")
    yield ledger
    ledger.close()


def test_add_sets_deadline(lg):
    rid = lg.add("acme/widget", "Secret bug", sent_on="2026-01-01", deadline_days=90)
    row = lg.all()[0]
    assert row["id"] == rid
    assert row["deadline"] == "2026-04-01"


def test_published_becomes_public(lg):
    rid = lg.add("acme/widget", "Bug", sent_on="2026-01-01")
    assert lg.update(rid, status="published", ids="CVE-2026-1")
    assert lg.all()[0]["public"] == 1


def test_export_hides_undisclosed(lg):
    lg.add("acme/secret", "Auth bypass in login", sent_on="2026-03-15")
    rid = lg.add("acme/open", "XSS in search", sent_on="2026-02-01")
    lg.update(rid, status="published", ids="CVE-2026-2", url="https://example.net/adv")
    text = export(lg.all(), "md")
    assert "acme/secret" not in text
    assert "Auth bypass" not in text
    assert "Undisclosed report" in text
    assert "2026-03" in text and "2026-03-15" not in text
    assert "XSS in search" in text and "CVE-2026-2" in text
    assert "2 reports: 1 public, 1 not yet public." in text


def test_export_json_hides_undisclosed(lg):
    lg.add("acme/secret", "Auth bypass", sent_on="2026-03-15")
    text = export(lg.all(), "json")
    assert "Auth bypass" not in text and "acme/secret" not in text


def test_due(lg):
    lg.add("a/b", "x", sent_on="2026-01-01", deadline_days=30)
    lg.add("a/c", "y", sent_on="2026-01-01", deadline_days=300)
    due = lg.due(within_days=14, today=date(2026, 1, 20))
    assert [r["project"] for r in due] == ["a/b"]


def test_bad_status(lg):
    with pytest.raises(ValueError):
        lg.add("a/b", "x", status="lost")


def test_basic_iso_date_is_normalized(lg):
    lg.add("acme/secret", "x", sent_on="20260315")
    assert lg.all()[0]["sent_on"] == "2026-03-15"
    assert "2026-03 " in export(lg.all(), "md").replace("|", " ")


def test_bad_date_is_rejected(lg):
    with pytest.raises(ValueError):
        lg.add("a/b", "x", sent_on="15/03/2026")


def test_export_escapes_markdown(lg):
    rid = lg.add("acme/open", "Bad | title [x](javascript:alert(1)) <b>", sent_on="2026-02-01")
    lg.update(rid, status="published")
    # Older ledgers may hold such a URL (input is validated since 0.1.3); export must stay safe.
    lg.db.execute("UPDATE reports SET url = ? WHERE id = ?", ("javascript:alert(1)", rid))
    text = export(lg.all(), "md")
    import re

    assert re.search(r"(?<!\\)\]\(javascript", text) is None  # no live link to javascript:
    assert "\\|" in text and "<b>" not in text  # table cell and HTML are neutralized


def test_bad_ledger_input_is_rejected(lg):
    import pytest

    with pytest.raises(ValueError):
        lg.add("", "title")
    with pytest.raises(ValueError):
        lg.add("a/b", "t", deadline_days=-5)
    with pytest.raises(ValueError):
        lg.add("a/b", "t", url="javascript:alert(1)")
    rid = lg.add("a/b", "t")
    with pytest.raises(ValueError):
        lg.update(rid, url="javascript:alert(1)")
    with pytest.raises(ValueError):
        lg.all("nope")
    assert lg.exists(rid) and not lg.exists(rid + 100)
