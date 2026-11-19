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
