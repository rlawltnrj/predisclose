"""Render a Report for people (terminal, Markdown) and for programs (JSON)."""

from __future__ import annotations

import json

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from predisclose.models import Report

LABELS = {
    "public_record": "Public record",
    "public_fix": "Public fix",
    "recent_activity": "Recent activity",
    "where_to_report": "Where to report",
}
STYLE = {"strong": "bold red", "medium": "yellow", "weak": "cyan", "info": "cyan", "none": "dim"}


def _result_word(status: str, level: str) -> str:
    if status == "found":
        return {"strong": "MATCH", "medium": "CHECK", "weak": "FOUND", "info": "FOUND"}.get(level, "FOUND")
    return {"none": "none", "skipped": "skipped", "error": "error"}.get(status, status)


def to_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)


def to_terminal(report: Report, console: Console, *, max_evidence: int = 5) -> None:
    console.print(
        f"[bold]predisclose {report.tool_version}[/]  {escape(report.finding.target())}"
        + (f"  [dim](repo: {escape(report.finding.repo)})[/]" if report.finding.repo else "")
    )
    table = Table(show_header=True, header_style="bold", expand=False)
    table.add_column("Check")
    table.add_column("Result")
    table.add_column("Summary", overflow="fold")
    for r in report.results:
        word = _result_word(r.status, r.level)
        table.add_row(LABELS.get(r.check, r.check), f"[{STYLE.get(r.level, '')}]{word}[/]", escape(r.summary))
    console.print(table)

    for r in report.results:
        if not r.evidence and not r.notes:
            continue
        console.print(f"\n[bold]{LABELS.get(r.check, r.check)}[/]")
        for e in r.evidence[:max_evidence]:
            reasons = f" [dim]({escape('; '.join(e.reasons))})[/]" if e.reasons else ""
            date = f" {e.date}" if e.date else ""
            console.print(
                f"  [{STYLE.get(e.level, '')}]{e.level:<6}[/] {escape(e.id)}{date}  "
                f"{escape(e.title)}{reasons}"
            )
            if e.url:
                console.print(f"         [link={e.url}]{escape(e.url)}[/link]")
        if len(r.evidence) > max_evidence:
            console.print(f"  [dim]... {len(r.evidence) - max_evidence} more (use --json)[/]")
        for note in r.notes:
            console.print(f"  [dim]note: {escape(note)}[/]")
    console.print(f"\n[dim]{escape(report.disclaimer)}[/]")


def to_markdown(report: Report, *, max_evidence: int = 10) -> str:
    lines = [
        f"# predisclose report: {report.finding.target()}",
        "",
        f"- Generated: {report.generated_at} (predisclose {report.tool_version})",
    ]
    if report.finding.repo:
        lines.append(f"- Repository: {report.finding.repo}")
    if report.finding.cwe:
        lines.append(f"- CWE: {', '.join(report.finding.cwe)}")
    lines += ["", "| Check | Result | Summary |", "|---|---|---|"]
    for r in report.results:
        summary = r.summary.replace("|", "\\|")
        lines.append(f"| {LABELS.get(r.check, r.check)} | {_result_word(r.status, r.level)} | {summary} |")
    for r in report.results:
        if not r.evidence and not r.notes:
            continue
        lines += ["", f"## {LABELS.get(r.check, r.check)}", ""]
        for e in r.evidence[:max_evidence]:
            link = f"[{e.id}]({e.url})" if e.url else e.id
            reasons = f" ({'; '.join(e.reasons)})" if e.reasons else ""
            date = f" {e.date}" if e.date else ""
            lines.append(f"- **{e.level}** {link}{date}: {e.title}{reasons}")
        for note in r.notes:
            lines.append(f"- _note: {note}_")
    lines += ["", f"> {report.disclaimer}", ""]
    return "\n".join(lines)
