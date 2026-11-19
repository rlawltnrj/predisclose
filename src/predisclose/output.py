"""Render a Report for people (terminal, Markdown) and for programs (JSON).

Every string from a public source goes through `predisclose.text` first: advisory titles, commit
messages and policies are written by strangers and must not control the terminal or the Markdown.
"""

from __future__ import annotations

import json

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from predisclose.models import Report
from predisclose.text import clean, md_text, md_url, one_line

LABELS = {
    "public_record": "Public record",
    "public_fix": "Public fix",
    "recent_activity": "Recent activity",
    "where_to_report": "Where to report",
}
STYLE = {"strong": "bold red", "medium": "yellow", "weak": "cyan", "info": "cyan", "none": "dim"}


def _t(value: object) -> str:
    """Safe for Rich markup on one line."""
    return escape(one_line(value))


def _result_word(status: str, level: str) -> str:
    if status == "found":
        return {"strong": "MATCH", "medium": "CHECK", "weak": "FOUND", "info": "FOUND"}.get(level, "FOUND")
    return {"none": "none", "skipped": "skipped", "error": "error"}.get(status, status)


def to_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)


def to_terminal(report: Report, console: Console, *, max_evidence: int = 5) -> None:
    console.print(
        f"[bold]predisclose {report.tool_version}[/]  {_t(report.finding.target())}"
        + (f"  [dim](repo: {_t(report.finding.repo)})[/]" if report.finding.repo else ""),
        highlight=False,
    )
    table = Table(show_header=True, header_style="bold", expand=False)
    table.add_column("Check")
    table.add_column("Result")
    table.add_column("Summary", overflow="fold")
    for r in report.results:
        word = _result_word(r.status, r.level)
        table.add_row(LABELS.get(r.check, r.check), f"[{STYLE.get(r.level, '')}]{word}[/]", _t(r.summary))
    console.print(table)

    for r in report.results:
        if not r.evidence and not r.notes:
            continue
        console.print(f"\n[bold]{LABELS.get(r.check, r.check)}[/]")
        for e in r.evidence[:max_evidence]:
            reasons = f" [dim]({_t('; '.join(e.reasons))})[/]" if e.reasons else ""
            date = f" {_t(e.date)}" if e.date else ""
            console.print(
                f"  [{STYLE.get(e.level, '')}]{e.level:<6}[/] {_t(e.id)}{date}  {_t(e.title)}{reasons}",
                highlight=False,
            )
            url = md_url(e.url)
            if url:
                console.print(f"         [link={url}]{escape(url)}[/link]", highlight=False)
            elif e.url:
                console.print(f"         {_t(e.url)}", highlight=False)
        if len(r.evidence) > max_evidence:
            console.print(f"  [dim]... {len(r.evidence) - max_evidence} more (use --json)[/]")
        for note in r.notes:
            console.print(f"  [dim]note: {_t(note)}[/]", highlight=False)
    if any(r.status in ("found", "none") for r in report.results):
        console.print(f"\n[dim]{_t(report.disclaimer)}[/]", highlight=False)


def to_markdown(report: Report, *, max_evidence: int = 10) -> str:
    lines = [
        f"# predisclose report: {md_text(report.finding.target())}",
        "",
        f"- Generated: {report.generated_at} (predisclose {report.tool_version})",
    ]
    if report.finding.repo:
        lines.append(f"- Repository: {md_text(report.finding.repo)}")
    if report.finding.cwe:
        lines.append(f"- CWE: {md_text(', '.join(report.finding.cwe))}")
    lines += ["", "| Check | Result | Summary |", "|---|---|---|"]
    for r in report.results:
        lines.append(
            f"| {LABELS.get(r.check, r.check)} | {_result_word(r.status, r.level)} | {md_text(r.summary)} |"
        )
    for r in report.results:
        if not r.evidence and not r.notes:
            continue
        lines += ["", f"## {LABELS.get(r.check, r.check)}", ""]
        for e in r.evidence[:max_evidence]:
            url = md_url(e.url)
            link = f"[{md_text(e.id)}]({url})" if url else md_text(e.id)
            reasons = f" ({md_text('; '.join(e.reasons))})" if e.reasons else ""
            date = f" {md_text(e.date)}" if e.date else ""
            lines.append(f"- **{e.level}** {link}{date}: {md_text(e.title)}{reasons}")
        for note in r.notes:
            lines.append(f"- _note: {md_text(note)}_")
    lines += ["", f"> {md_text(report.disclaimer)}", ""]
    return "\n".join(lines)


__all__ = ["to_json", "to_markdown", "to_terminal", "clean"]
