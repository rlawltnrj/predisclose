"""Command line: predisclose check | route | ledger."""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from predisclose import __version__
from predisclose import ledger as ledger_mod
from predisclose.core import ALL_CHECKS, run_check
from predisclose.ecosystems import normalize_cwe, parse_package, parse_repo
from predisclose.http import Http, github_token_from_env
from predisclose.models import Finding
from predisclose.output import to_json, to_markdown, to_terminal

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Before you disclose a vulnerability: check public records, public fixes, "
    "and the project's official reporting channel. Uses public data only.",
)
ledger_app = typer.Typer(no_args_is_help=True, help="Track the reports you have sent (stored locally).")
app.add_typer(ledger_app, name="ledger")

out = Console()
err = Console(stderr=True)


def _version_callback(value: bool) -> None:
    if value:
        out.print(f"predisclose {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    show_version: Annotated[
        bool,
        typer.Option("--about", callback=_version_callback, is_eager=True, help="Show the version."),
    ] = False,
) -> None:
    pass


def _fail(message: str) -> None:
    err.print(f"[red]error:[/] {message}")
    raise typer.Exit(2)


def _load_finding_file(path: Path) -> dict:
    try:
        with path.open("rb") as f:
            data = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        _fail(f"cannot read {path}: {exc}")
    allowed = {"package", "version", "repo", "cwe", "files", "functions", "keywords", "notes"}
    unknown = set(data) - allowed
    if unknown:
        _fail(f"unknown keys in {path}: {', '.join(sorted(unknown))}")
    return data


def _build_finding(
    pkg: str | None,
    version: str | None,
    repo: str | None,
    cwe: list[str],
    files: list[str],
    functions: list[str],
    keywords: list[str],
    from_file: Path | None,
) -> Finding:
    base: dict = _load_finding_file(from_file) if from_file else {}
    pkg = pkg or base.get("package")
    finding = Finding(
        version=version or base.get("version"),
        files=list(files or base.get("files") or []),
        functions=list(functions or base.get("functions") or []),
        keywords=list(keywords or base.get("keywords") or []),
    )
    try:
        if pkg:
            finding.ecosystem, finding.package = parse_package(str(pkg))
        finding.cwe = [normalize_cwe(str(c)) for c in (cwe or base.get("cwe") or [])]
    except ValueError as exc:
        _fail(str(exc))
    repo_text = repo or base.get("repo")
    if repo_text:
        finding.repo = parse_repo(str(repo_text))
        if not finding.repo:
            _fail(f"cannot understand repository {repo_text!r}; use owner/name or a GitHub URL")
    if not (finding.package or finding.repo):
        _fail("give a package (--pkg pypi:NAME) or a repository (--repo owner/name)")
    return finding


@app.command()
def check(
    pkg: Annotated[str | None, typer.Option("--pkg", "-p", help="ECOSYSTEM:NAME, e.g. pypi:jinja2, npm:lodash")] = None,
    version: Annotated[str | None, typer.Option("--version", "-v", help="Version, tag, or commit you tested.")] = None,
    repo: Annotated[str | None, typer.Option("--repo", "-r", help="GitHub repository, owner/name or URL.")] = None,
    cwe: Annotated[list[str], typer.Option("--cwe", help="Weakness type, e.g. CWE-79. Repeatable.")] = [],  # noqa: B006
    file: Annotated[list[str], typer.Option("--file", "-f", help="Affected file path. Repeatable.")] = [],  # noqa: B006
    function: Annotated[list[str], typer.Option("--function", help="Affected function. Repeatable.")] = [],  # noqa: B006
    keyword: Annotated[list[str], typer.Option("--keyword", "-k", help="Extra word to look for. Repeatable.")] = [],  # noqa: B006
    from_file: Annotated[Path | None, typer.Option("--from", help="Read the finding from a TOML file.")] = None,
    only: Annotated[str | None, typer.Option("--only", help="Comma list of checks: known,fixes,activity,route")] = None,
    json_out: Annotated[bool, typer.Option("--json", help="Print JSON instead of a table.")] = False,
    markdown: Annotated[Path | None, typer.Option("--markdown", help="Also write a Markdown report here.")] = None,
    show_queries: Annotated[bool, typer.Option("--show-queries", help="List every request that was sent.")] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Show the first requests; send nothing.")] = False,
    no_cache: Annotated[bool, typer.Option("--no-cache", help="Do not read or write the local cache.")] = False,
) -> None:
    """Check public records, public fixes, recent activity, and where to report."""
    finding = _build_finding(pkg, version, repo, cwe, file, function, keyword, from_file)
    checks = ALL_CHECKS
    if only:
        checks = tuple(c.strip() for c in only.split(",") if c.strip())
        bad = [c for c in checks if c not in ALL_CHECKS]
        if bad:
            _fail(f"unknown check(s): {', '.join(bad)}; choose from {', '.join(ALL_CHECKS)}")

    http = Http(dry_run=dry_run, use_cache=not no_cache, token=github_token_from_env())
    try:
        report = run_check(http, finding, checks)
    finally:
        http.close()

    if json_out:
        sys.stdout.write(to_json(report) + "\n")
    else:
        to_terminal(report, out)
    if markdown:
        markdown.write_text(to_markdown(report), encoding="utf-8")
        err.print(f"[dim]Markdown report written to {markdown}[/]")
    if show_queries or dry_run:
        err.print("\n[bold]Requests[/]" + (" (dry run: none were sent)" if dry_run else ""))
        for q in report.queries:
            err.print(f"  {q}", markup=False, highlight=False)


@app.command()
def route(
    repo: Annotated[str, typer.Argument(help="GitHub repository, owner/name or URL.")],
    json_out: Annotated[bool, typer.Option("--json", help="Print JSON instead of a table.")] = False,
    no_cache: Annotated[bool, typer.Option("--no-cache", help="Do not use the local cache.")] = False,
) -> None:
    """Only find where the project wants security reports."""
    target = parse_repo(repo)
    if not target:
        _fail(f"cannot understand repository {repo!r}; use owner/name or a GitHub URL")
    http = Http(use_cache=not no_cache, token=github_token_from_env())
    try:
        report = run_check(http, Finding(repo=target), ("route",))
    finally:
        http.close()
    if json_out:
        sys.stdout.write(to_json(report) + "\n")
    else:
        to_terminal(report, out)


# -- ledger --------------------------------------------------------------------------


def _ledger() -> ledger_mod.Ledger:
    return ledger_mod.Ledger()


@ledger_app.command("add")
def ledger_add(
    project: Annotated[str, typer.Argument(help="Project, e.g. owner/name.")],
    title: Annotated[str, typer.Argument(help="Short title. Stays on this machine.")],
    channel: Annotated[str, typer.Option(help="e.g. github-pvr, email, hackerone")] = "",
    sent: Annotated[str | None, typer.Option(help="Date sent, YYYY-MM-DD (default: today).")] = None,
    deadline_days: Annotated[int, typer.Option(help="Disclosure deadline in days.")] = 90,
    status: Annotated[str, typer.Option(help="One of: " + ", ".join(ledger_mod.STATUSES))] = "sent",
) -> None:
    """Record a report you sent."""
    lg = _ledger()
    try:
        rid = lg.add(project, title, channel=channel, sent_on=sent, deadline_days=deadline_days, status=status)
    except ValueError as exc:
        _fail(str(exc))
    finally:
        lg.close()
    out.print(f"Added report #{rid}")


@ledger_app.command("update")
def ledger_update(
    report_id: Annotated[int, typer.Argument(help="Report number.")],
    status: Annotated[str | None, typer.Option(help="New status.")] = None,
    ids: Annotated[str | None, typer.Option("--ids", help="CVE / GHSA ids, comma separated.")] = None,
    url: Annotated[str | None, typer.Option(help="Public advisory URL.")] = None,
    public: Annotated[bool | None, typer.Option("--public/--private", help="Mark as public or not.")] = None,
    notes: Annotated[str | None, typer.Option(help="Private notes.")] = None,
) -> None:
    """Change the status or details of a report."""
    lg = _ledger()
    try:
        ok = lg.update(report_id, status=status, ids=ids, url=url, public=public, notes=notes)
    except ValueError as exc:
        _fail(str(exc))
    finally:
        lg.close()
    if not ok:
        _fail(f"report #{report_id} not found or nothing to change")
    out.print(f"Updated report #{report_id}")


@ledger_app.command("list")
def ledger_list(
    status: Annotated[str | None, typer.Option(help="Only this status.")] = None,
) -> None:
    """Show every report (full details, local only)."""
    from rich.table import Table

    lg = _ledger()
    rows = lg.all(status)
    lg.close()
    table = Table("#", "Project", "Title", "Channel", "Sent", "Deadline", "Status", "IDs", "Public")
    for r in rows:
        table.add_row(
            str(r["id"]), r["project"], r["title"], r["channel"], r["sent_on"], r["deadline"],
            r["status"], r["ids"], "yes" if r["public"] else "no",
        )
    out.print(table)


@ledger_app.command("due")
def ledger_due(
    within: Annotated[int, typer.Option(help="Days ahead to look.")] = 14,
) -> None:
    """Reports whose disclosure deadline is near or past."""
    lg = _ledger()
    rows = lg.due(within)
    lg.close()
    if not rows:
        out.print(f"Nothing due in the next {within} days.")
        return
    for r in rows:
        out.print(f"#{r['id']}  {r['deadline']}  {r['status']:<12} {r['project']}  {r['title']}")


@ledger_app.command("export")
def ledger_export(
    fmt: Annotated[str, typer.Option("--format", help="md or json")] = "md",
    show_projects: Annotated[bool, typer.Option(help="Keep project names of reports that are not public yet.")] = False,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Write to a file.")] = None,
) -> None:
    """Export for a portfolio. Reports that are not public are reduced to a placeholder."""
    if fmt not in ("md", "json"):
        _fail("format must be md or json")
    lg = _ledger()
    text = ledger_mod.export(lg.all(), fmt, show_projects=show_projects)
    lg.close()
    if output:
        output.write_text(text, encoding="utf-8")
        err.print(f"[dim]Written to {output}[/]")
    else:
        sys.stdout.write(text)
