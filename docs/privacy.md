# Privacy

A vulnerability that has not been disclosed is sensitive. predisclose is built so that using it
does not leak one.

## What leaves your machine

| Sent | To |
|---|---|
| ecosystem, package name, version | OSV, GitHub Advisory Database, the package registry |
| repository name, version or commit, file paths you passed | GitHub API |
| repository name | raw.githubusercontent.com (to read `SECURITY.md`) |
| project homepage host | that host (to read `/.well-known/security.txt`) |

CWE ids, function names and keywords are **not** sent: matching happens locally, after the public
records are downloaded. The `notes` field of a finding file is never read by any check.

Run with `--show-queries` to see the exact requests, or `--dry-run` to see them without sending
anything.

## What stays on your machine

- The HTTP cache: `~/.cache/predisclose/http.sqlite` (delete it at any time).
- The ledger: `~/.local/share/predisclose/ledger.sqlite`.
- Reports you write with `--markdown`.

`ledger export` keeps full details only for reports you marked public (or set to `published`).
Every other report becomes "Undisclosed report", its project hidden unless you pass
`--show-projects`, and its date reduced to the month.

## What predisclose never does

- It never posts, comments, opens issues, or submits reports.
- It never runs code from the target project and never sends requests to the target's services,
  except reading its public `security.txt`.
- It has no telemetry.
