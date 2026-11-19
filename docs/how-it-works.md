# How predisclose works

`predisclose check` runs four independent checks. Each one reads public data, explains every
match, and never raises because a source is missing: a check that cannot run says why and the
others continue.

## 0. Finding the repository

If you give a package but no repository, predisclose reads the package's public registry
metadata (PyPI, npm, crates.io, RubyGems, Packagist; Go module paths on github.com) and, failing
that, the `source_code_location` of matching GitHub advisories. Advisories that cover packages of
different projects are ignored for this (several artifacts of one Maven group, npm scope or module
owner are fine), and a guess is used only when it names the package or all
advisories agree (most of them, when there are three or more); otherwise predisclose asks for
`--repo`. Go modules under `golang.org/x/` map to `golang/<name>`. The note under *Public record*
says where the repository came from.

## 1. Public record

Sources: [OSV](https://osv.dev) (`POST /v1/query`) and the
[GitHub Advisory Database](https://github.com/advisories) (`GET /advisories?affects=`).

- With a package and a version, both sources return only advisories that affect that version.
  A range or a word (`4.x`, `2.10.*`, `latest`) is not sent: the package's advisories are listed
  unfiltered, with a note, because OSV would otherwise answer with most of them as "affected".
- If OSV or GitHub fails to answer, the other source's advisories are shown with a note that the
  list is incomplete; if neither gives an answer, the check is an error, never "no public advisory". GitHub
  lists at most 100 advisories per query; a note says so when that limit is reached.
- With only a repository and a version, the version is resolved to a commit and OSV is queried by
  commit. Published repository advisories are added too, but they are not filtered by version, so
  their score is capped at *medium*.
- Records that share an id or alias (for example `PYSEC-…`, `GHSA-…`, `CVE-…`) are merged.

Every advisory is scored against your hints:

| Level | Rule |
|---|---|
| strong | same CWE and (same file or same function), or same file and same function |
| medium | same CWE, or same file, or same function, or a keyword match |
| weak | affects the version, nothing else in common |

A file matches when the advisory text contains the path you gave, or its file name if that name is
specific (it has an extension and is at least five characters). A function matches when the
advisory's structured data lists it (GitHub `vulnerable_functions`, Go vulndb symbols) or the text
mentions it.

## 2. Public fix

The version is turned into a commit and a date by trying the tag names projects commonly use
(`1.2.3`, `v1.2.3`, `name-1.2.3`, `name@1.2.3`, `release-1.2.3`) or by using a commit sha directly.
A Go pseudo-version (`v0.0.0-20210226172049-e18ecbb05110`) uses its commit.

- With `--file`, the file name is resolved to real paths at the tested version and on the default
  branch, so files that moved are followed. Every commit on the default branch that changed those
  paths since the tested version is listed. Commits whose message uses security words, or that an
  advisory names as its fix, are marked *medium*.
- Fix commits named by similar advisories are listed even when they sit on a release branch,
  because the same change often has a different commit id on each branch.
- Without `--file`, release notes published after the tested version are searched for security
  words.

## 3. Recent activity

All advisories for the package (and published advisories of the repository) from the last 365
days are listed. Those that resemble your finding are marked *medium*: areas with recent similar
advisories tend to receive parallel reports from other researchers.

## 4. Where to report

1. `SECURITY.md` in the repository (`/`, `.github/`, `docs/`), else in the owner's `.github`
   repository, as GitHub itself does.
2. GitHub private vulnerability reporting status
   (`GET /repos/{owner}/{repo}/private-vulnerability-reporting`).
3. `/.well-known/security.txt` on the project homepage.

Channels found in `SECURITY.md` are ranked. A channel the policy calls *preferred* wins. After that
the kind of channel and its place in the text decide: channels in a "Reporting" section and links
whose text says *report* or *disclosure* rank higher, contacts meant for escalation rank lower,
and lines about copyright or licensing are ignored. Headings name a topic, not a channel, and a
mention such as "do not use GitHub security advisories" does not count for GitHub (a heading
still counts when it names a concrete channel, such as an address or "use GitHub private
vulnerability reporting"). Only the first
200,000 characters of a policy, and 2,000 per line, are read. If the homepage's `security.txt`
cannot be read, that is a note; the other sources still answer. The other channels are listed as "also
mentioned".

## Requests and caching

Every request is recorded and shown with `--show-queries`, including each redirect hop.
`--dry-run` shows the first requests and sends nothing. Redirects are followed only to the same
host over https on the default port. Answers with status 200 are cached for six hours and "not found" answers for 30
minutes in `~/.cache/predisclose/http.sqlite`. A GitHub token, if set, is sent only to
`api.github.com` and never appears in the request log or the cache key; answers fetched with and
without a token are cached apart. The cache and the ledger are readable only by you.

## Untrusted text

Advisory titles, commit messages, release notes and security policies are written by other
people. Before anything is shown, control characters (including terminal escape sequences) are
removed (and bidirectional overrides that could reorder a line), Rich markup is escaped, and
Markdown output escapes table and link syntax. Links are only rendered for `http(s)` URLs, with
brackets, quotes and backslashes percent-encoded. The request log is cleaned the same way.
