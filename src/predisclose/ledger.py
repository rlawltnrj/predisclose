"""A local record of the reports you have sent. Nothing here ever leaves your machine."""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import date, timedelta
from pathlib import Path
from typing import Any

STATUSES = (
    "draft",
    "sent",
    "acknowledged",
    "accepted",
    "fixed",
    "published",
    "duplicate",
    "rejected",
    "withdrawn",
)
CLOSED = {"published", "duplicate", "rejected", "withdrawn"}
FIELDS = ("project", "title", "channel", "sent_on", "deadline", "status", "ids", "url", "public", "notes")


def default_path() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "predisclose" / "ledger.sqlite"


class Ledger:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or default_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project TEXT NOT NULL,
                title TEXT NOT NULL,
                channel TEXT NOT NULL DEFAULT '',
                sent_on TEXT NOT NULL DEFAULT '',
                deadline TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'sent',
                ids TEXT NOT NULL DEFAULT '',
                url TEXT NOT NULL DEFAULT '',
                public INTEGER NOT NULL DEFAULT 0,
                notes TEXT NOT NULL DEFAULT '',
                updated TEXT NOT NULL DEFAULT ''
            )"""
        )
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def add(
        self,
        project: str,
        title: str,
        *,
        channel: str = "",
        sent_on: str | None = None,
        deadline_days: int = 90,
        status: str = "sent",
        ids: str = "",
        url: str = "",
        public: bool = False,
        notes: str = "",
        today: date | None = None,
    ) -> int:
        _check_status(status)
        today = today or date.today()
        sent = sent_on or today.isoformat()
        deadline = (date.fromisoformat(sent) + timedelta(days=deadline_days)).isoformat()
        cur = self.db.execute(
            "INSERT INTO reports (project, title, channel, sent_on, deadline, status, ids, url, "
            "public, notes, updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (project, title, channel, sent, deadline, status, ids, url, int(public), notes,
             today.isoformat()),
        )
        self.db.commit()
        return int(cur.lastrowid)

    def update(self, report_id: int, *, today: date | None = None, **changes: Any) -> bool:
        changes = {k: v for k, v in changes.items() if v is not None}
        unknown = set(changes) - set(FIELDS)
        if unknown:
            raise ValueError(f"unknown fields: {', '.join(sorted(unknown))}")
        if "status" in changes:
            _check_status(changes["status"])
            if changes["status"] == "published" and "public" not in changes:
                changes["public"] = True
        if "public" in changes:
            changes["public"] = int(bool(changes["public"]))
        if not changes:
            return False
        changes["updated"] = (today or date.today()).isoformat()
        sets = ", ".join(f"{k} = ?" for k in changes)
        cur = self.db.execute(
            f"UPDATE reports SET {sets} WHERE id = ?", (*changes.values(), report_id)
        )
        self.db.commit()
        return cur.rowcount > 0

    def all(self, status: str | None = None) -> list[dict[str, Any]]:
        if status:
            rows = self.db.execute(
                "SELECT * FROM reports WHERE status = ? ORDER BY id", (status,)
            ).fetchall()
        else:
            rows = self.db.execute("SELECT * FROM reports ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    def due(self, within_days: int = 14, today: date | None = None) -> list[dict[str, Any]]:
        limit = ((today or date.today()) + timedelta(days=within_days)).isoformat()
        return [
            r for r in self.all() if r["status"] not in CLOSED and r["deadline"] and r["deadline"] <= limit
        ]


def _check_status(status: str) -> None:
    if status not in STATUSES:
        raise ValueError(f"status must be one of: {', '.join(STATUSES)}")


def redact(rows: list[dict[str, Any]], *, show_projects: bool = False) -> list[dict[str, Any]]:
    """Public entries keep their details. Undisclosed ones keep only what reveals nothing."""
    out = []
    for r in rows:
        if r["public"]:
            out.append(
                {k: r[k] for k in ("id", "project", "title", "status", "ids", "url", "sent_on")}
            )
        else:
            out.append(
                {
                    "id": r["id"],
                    "project": r["project"] if show_projects else "(undisclosed)",
                    "title": "Undisclosed report",
                    "status": r["status"],
                    "ids": "",
                    "url": "",
                    "sent_on": r["sent_on"][:7],
                }
            )
    return out


def export(rows: list[dict[str, Any]], fmt: str = "md", *, show_projects: bool = False) -> str:
    safe = redact(rows, show_projects=show_projects)
    if fmt == "json":
        return json.dumps(safe, indent=2, ensure_ascii=False)
    public = sum(1 for r in rows if r["public"])
    lines = [
        "# Vulnerability reports",
        "",
        f"{len(rows)} reports: {public} public, {len(rows) - public} not yet public.",
        "",
        "| # | Project | Report | Status | IDs | Sent |",
        "|---|---|---|---|---|---|",
    ]
    for r in safe:
        title = f"[{r['title']}]({r['url']})" if r["url"] else r["title"]
        lines.append(
            f"| {r['id']} | {r['project']} | {title} | {r['status']} | {r['ids']} | {r['sent_on']} |"
        )
    return "\n".join(lines) + "\n"
