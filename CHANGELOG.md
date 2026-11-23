# Changelog

## Unreleased

- Where to report: a SECURITY.md that raw.githubusercontent.com refused to serve (for example
  HTTP 429 from shared CI addresses) was treated as missing, so the answer silently fell back to
  security.txt or "no channel". Any answer other than 200 or 404 is now retried once through the
  GitHub contents API. Found by the weekly live check of 2026-11-23 (curl and openssl).
- Live route check: curl is also correct when the answer is the HackerOne contact in curl.se's
  security.txt.

## 0.1.3 (2026-11-19)

Fixes from a pre-release review and an end-to-end check as a new user.

Correctness
- Withdrawn advisories are left out, with a note naming them: global advisories with
  `withdrawn_at` or OSV `withdrawn`, and repository advisories that stay "published" with a title
  starting with a marker such as "REJECTED (not a vulnerability): ..." (titles like "Invalid curve
  attack ..." are never treated as withdrawn). A merged advisory is hidden only if every source
  agrees it was withdrawn. Previously a withdrawn express advisory was listed as affecting 4.17.1.
- A misspelled package is now an error for Maven, NuGet, Go, Pub and Hex too (it read as "No
  public advisory found"). For every registry, a name the registry doesn't list is called a typo
  only when no advisory names it for any version; packages hosted elsewhere (Jenkins, Google
  Maven) keep their advisories, with a note, and Go package paths are found through their module. pub.dev and Hex also supply the source
  repository.
- Real tag names such as `curl-8_0_0` or `openssl-3.0.0` are accepted again for the public-fix
  check; ranges (`4.x`, `>=1.0`, `[1.0,2.0)`, `latest`) and branch names (`main`, `master`) are
  refused, since a branch head is not a tested release.
- Repository-only checks say how many advisories affect the version and how many more are not
  filtered by version, instead of "N affect" for all of them.
- The reporting channel for `golang.org/x/...` modules comes from Go's own policy (`golang/go`).
- An empty public record for a package suggests checking component packages (e.g. rails →
  actionpack).
- A rejected `GITHUB_TOKEN` is reported as such, not as "repository not found".
- `check` exits with status 1 when every check errored; the closing disclaimer is shown only when
  something was checked.
- "No release mentions security terms" now suggests `--file`.

Ledger
- Empty project or title, a negative deadline, a non-http(s) URL and an unknown `--status` filter
  are rejected. `ledger due` marks overdue reports, `ledger list` says when there are none, and
  `ledger update` tells "not found" apart from "nothing to change".

CLI and docs
- `predisclose --version` shows the version (as `--about` does); `check --version` is unchanged.
- The rate-limit reset time shows its time zone.
- README: a short demo GIF of a real run (`docs/demo.gif`, made by `scripts/demo_gif.py`), left
  out of the source distribution. Docs list the registries contacted and two more limitations.

## 0.1.2 (2026-11-19)

Fixes from a full review (three independent passes: security, correctness, project setup)

Correctness
- A failed OSV or GitHub Advisory Database answer (HTTP 5xx, a broken page) no longer reads as
  "No public advisory found": the other source's results are shown and the summary says the list
  is incomplete; if neither answered the check is an error.
- The repository is no longer guessed from an advisory that covers packages of different projects
  (for example `golang.org/x/crypto` was mapped to `warp-tech/russh`). Conflicting guesses ask for `--repo`;
  `golang.org/x/NAME` maps to `golang/NAME`.
- A version range or word (`4.x`, `latest`) is not sent as a version, so unrelated advisories are
  no longer labelled "affects this version".
- In SECURITY.md, headings such as "Report a Vulnerability" and phrases such as "do not use GitHub
  security advisories", "instead of GitHub security advisories" or "advisories are not monitored"
  no longer make GitHub the preferred channel.
- A version range is no longer used as the starting point of the public-fix check.
- A check you did not ask for no longer appears as an error.
- Wrong types in a `--from` TOML file (`version = 2.10`, `files = "a.py"`) are rejected or
  corrected instead of being misread; numeric CWE ids (`cwe = [79]`) are accepted.
- Go pseudo-versions resolve to their commit.
- A note says when GitHub's limit of 100 advisories was reached.

Security and privacy
- A crafted SECURITY.md with a very long line can no longer stall the run.
- Brackets, quotes and backslashes in advisory URLs are percent-encoded; such a URL could crash
  the terminal output or show a misleading link.
- Bidirectional control characters are stripped, and the `--show-queries` log is cleaned.
- Redirects are followed only on the default https port; a malformed redirect address is not
  followed (instead of failing the reporting-channel check).
- The cache and the ledger are created readable only by you; cached answers fetched with a token
  are kept apart from anonymous ones.
- `docs/privacy.md` now lists the package name in GitHub tag lookups and says that a token ties
  GitHub requests to your account.
- Error messages no longer interpret your own input as Rich markup.

Other fixes
- A network error on the homepage's security.txt (for example a redirect loop) no longer turns
  "Where to report" into an error when SECURITY.md or GitHub already names a channel; it becomes
  a note. Found by the first weekly live check.

Project
- README: removed the pre-PyPI install line.
- Weekly live check (`.github/workflows/live-check.yml`): runs `scripts/eval_recall.py` and the new
  `scripts/eval_routes.py` against public data and opens an issue when either fails. Both scripts
  now exit non-zero on a miss, and retry once before calling a network error a failure.
- Dependabot for GitHub Actions and pip, OpenSSF Scorecard, and issue templates for a wrong
  reporting channel, a wrong match, and bugs.

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
