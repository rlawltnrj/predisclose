# Privacy

A vulnerability that has not been disclosed is sensitive. predisclose is built so that using it
does not leak one.

## What leaves your machine

| Sent | To |
|---|---|
| ecosystem, package name, version | OSV, GitHub Advisory Database |
| ecosystem, package name | the package registry (to check it exists and find the repository) |
| commit sha of the tested version (repository-only checks) | OSV |
| repository name, version or commit, package name (in tag guesses such as `name-1.2.3`), file paths you passed | GitHub API |
| repository name | raw.githubusercontent.com (to read `SECURITY.md`; if it answers with anything other than the file or "not found", the same path is read through the GitHub API) |
| project homepage host name | your DNS resolver, then that host (to read `/.well-known/security.txt`) |

The homepage is chosen by the repository owner, so predisclose only contacts it when it is a
public host name: bare IP addresses, `localhost`, `.local`-style names and names that resolve to
private, loopback or link-local addresses are skipped, and any user name, password or port in the
homepage URL is dropped. Redirects are followed only to the same host over https; every hop is
shown by `--show-queries`, and a redirect that is not followed is shown too.

If you set `GITHUB_TOKEN`, GitHub sees which account made each GitHub API request above
(repository, version, file paths). The token is sent only to `api.github.com`. Leave it unset if
you do not want these lookups tied to your account; you will be limited to 60 requests an hour.

CWE ids, function names and keywords are **not** sent: matching happens locally, after the public
records are downloaded. The `notes` field of a finding file is never read by any check.

Run with `--show-queries` to see the exact requests, or `--dry-run` to see them without sending
anything.

## What stays on your machine

- The HTTP cache: `~/.cache/predisclose/http.sqlite` (delete it at any time).
- The ledger: `~/.local/share/predisclose/ledger.sqlite`.
- Both are created readable only by you (directory 0700, file 0600).
- Reports you write with `--markdown`.

`ledger export` keeps full details only for reports you marked public (or set to `published`).
Every other report becomes "Undisclosed report", its project hidden unless you pass
`--show-projects`, and its date reduced to the month.

## What predisclose never does

- It never posts, comments, opens issues, or submits reports.
- It never runs code from the target project and never sends requests to the target's services,
  except reading its public `security.txt`.
- It has no telemetry.
