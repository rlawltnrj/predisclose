# Changelog

## 0.1.1 (2026-11-19)

Fixes from a full review (five passes, including an independent one).

Security and privacy
- The project homepage (set by the repository owner) is only contacted when it is a public host:
  IP addresses, local names, and names resolving to private, loopback or link-local addresses are
  skipped, and user names, passwords and ports are dropped.
- Redirects are followed only to the same host over https, and every hop is logged in
  `--show-queries`. Previously a redirect could reach any host without being logged.
- Text from public sources can no longer inject terminal escape sequences, Rich markup, or
  Markdown links into the output, the report, or the ledger export.

Correctness
- A misspelled package or repository is now an error instead of "no public advisory found".
- Files, functions and keywords match whole tokens only (`io.c` no longer matches `radio.c`,
  `read` no longer matches `thread`); short function names must appear in code form.
- The release of the tested version itself is no longer counted as a later fix.
- PyPI source links are preferred over funding links; GitHub pages such as sponsors and gists are
  no longer taken for repositories.
- Advisories that share ids through a chain of aliases are merged into one.
- Without `--version`, results no longer claim to "affect this version".
- Date-like versions such as `20231215` are no longer mistaken for commit shas.
- Unexpected data from a source no longer stops the other checks.
- Ledger dates are stored as `YYYY-MM-DD`, so the export always reduces them to the month;
  `ledger list` no longer fails on titles with square brackets.
- "Not found" answers are cached for 30 minutes instead of six hours.
- The minimum `typer` version is now 0.13 (0.12 could not start), checked in CI.
- Wording: "1 public advisory affects" instead of "1 public advisories affect".

## 0.1.0 (2026-11-19)

First release.

- `check`: public record (OSV + GitHub Advisory Database), public fix (commits and releases since
  the tested version, fix commits named by advisories), recent activity, and where to report.
- `route`: reporting channel only. Reads `SECURITY.md` (repository, then the owner's `.github`
  repository), GitHub private vulnerability reporting status, and `security.txt`.
- `ledger`: local record of sent reports with deadlines and a redacted export for portfolios.
- `--json`, `--markdown`, `--show-queries`, `--dry-run`, `--only`, finding files in TOML.
- Skill file for coding agents in `skills/predisclose/SKILL.md`.
