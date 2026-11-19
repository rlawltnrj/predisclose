# Changelog

## Unreleased

- "Not found" answers are cached for 30 minutes instead of 6 hours, so newly published
  packages, policies and advisories show up sooner.

## 0.1.0 (2026-11-19)

First release.

- `check`: public record (OSV + GitHub Advisory Database), public fix (commits and releases since
  the tested version, fix commits named by advisories), recent activity, and where to report.
- `route`: reporting channel only. Reads `SECURITY.md` (repository, then the owner's `.github`
  repository), GitHub private vulnerability reporting status, and `security.txt`.
- `ledger`: local record of sent reports with deadlines and a redacted export for portfolios.
- `--json`, `--markdown`, `--show-queries`, `--dry-run`, `--only`, finding files in TOML.
- Skill file for coding agents in `skills/predisclose/SKILL.md`.
