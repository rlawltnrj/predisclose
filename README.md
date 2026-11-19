# predisclose

**Before you disclose a vulnerability, spend one minute checking what is already public.**

`predisclose` looks at public data only and answers four questions about an open-source project:

1. **Public record**: is there already a public advisory that looks like your finding? (OSV, GitHub Advisory Database)
2. **Public fix**: has the affected code changed since the version you tested?
3. **Recent activity**: has this area had advisories recently? Busy areas get more parallel reports.
4. **Where to report**: what channel does the project ask for? (SECURITY.md, GitHub private vulnerability reporting, security.txt)

It also keeps a **local ledger** of the reports you have sent, with deadlines and an export for your portfolio that hides anything not yet public.

```text
$ predisclose check --pkg pypi:jinja2 --version 2.10 --cwe CWE-693 --file sandbox.py

Check            Result  Summary
Public record    CHECK   6 public advisories affect PyPI jinja2 2.10; 0 strong and 2 medium matches
Public fix       CHECK   33 commits changed sandbox.py since 2.10 (2017-11-08); 2 look security-related
                         (1 linked to public advisories)
Recent activity  none    No advisories published in the last 365 days.
Where to report  FOUND   Follow SECURITY.md: GitHub private vulnerability reporting ->
                         https://github.com/pallets/jinja/security/advisories/new

Public record
  medium GHSA-q2x7-8rv6-6q7h 2024-12-23  Jinja has a sandbox breakout through indirect reference
         to format method (same CWE: CWE-693)
  ...
```

Note what happened there: the file moved from `jinja2/` to `src/jinja2/` after 2.10 and is still
followed, and the reporting channel came from the organization-wide policy in `pallets/.github`.

## What it does not do

- It does **not** say a finding is new. Reports sent privately by other people are invisible to everyone except the maintainers. "No public record" is the strongest thing any tool can honestly say.
- It does **not** reproduce, scan, or test anything. It only reads public metadata.
- It does **not** send reports for you or post anything anywhere.
- It does **not** send your description of the issue anywhere. Only the package name, version, file paths, and CWE ids leave your machine, as listed by `--show-queries`.

## Install

```bash
pipx install predisclose      # or: uv tool install predisclose
# before the first PyPI release:
pipx install git+https://github.com/rlawltnrj/predisclose
```

Python 3.11 or newer. A GitHub token is optional but recommended: unauthenticated GitHub API calls are limited to 60 per hour.

```bash
export GITHUB_TOKEN=$(gh auth token)   # any token works; no scopes are needed for public data
```

## Use

```bash
# Package on a registry (PyPI, npm, crates.io, Go, Maven, NuGet, RubyGems, Packagist, Pub, Hex)
predisclose check --pkg npm:express --version 4.17.1 --cwe CWE-601

# A GitHub repository that is not on a registry (version = tag or commit)
predisclose check --repo owner/name --version v1.2.0 --file src/parser.c --function parse_header

# Only the reporting channel
predisclose route owner/name

# From a file (handy for agents and scripts)
predisclose check --from finding.toml --json
```

`finding.toml`:

```toml
package = "pypi:jinja2"
version = "2.10"
cwe = ["CWE-693"]
files = ["src/jinja2/sandbox.py"]
functions = ["SandboxedEnvironment"]
notes = "free text for yourself; never sent anywhere"
```

Useful flags: `--show-queries` (print every request that was sent), `--dry-run` (print the first requests and send nothing), `--markdown report.md`, `--only known,route`, `--no-cache`.

### Ledger

```bash
predisclose ledger add owner/name "Path traversal in upload handler" --channel github-pvr
predisclose ledger update 1 --status published --ids CVE-2026-12345 --url https://github.com/advisories/GHSA-xxxx
predisclose ledger due                 # deadlines in the next 14 days
predisclose ledger export -o reports.md
```

The ledger lives in `~/.local/share/predisclose/ledger.sqlite` and never leaves your machine. `export` keeps full details only for reports marked public. Everything else becomes "Undisclosed report" with the month it was sent.

## How matching works

Every advisory that affects the target is scored against your hints. The rules are deterministic, so the same input always gives the same answer:

| Level | When |
|---|---|
| strong | same CWE **and** same file or function, or same file **and** same function |
| medium | same CWE, or same file, or same function, or a keyword match |
| weak | affects this version, no other overlap |

Each match lists its reasons and a link, so you can judge it yourself. More in [docs/how-it-works.md](docs/how-it-works.md).

## Validation

`scripts/eval_recall.py` samples reviewed GitHub advisories in seven ecosystems (PyPI, npm,
crates.io, Go, Maven, RubyGems, Packagist). For each one it checks a version inside the vulnerable
range with the advisory's CWE, and the first patched version as a control.

| Run | Recall (advisory found at medium or above) | Control (not listed for the patched version) |
|---|---|---|
| 2026-11-19, 32 advisories | 32 / 32 | 32 / 32 |

The reporting-channel parser was checked by hand against the policies of curl, express, hyper,
Jinja, Django, Node.js, OpenSSL, Go, Rails and Next.js (all ten match), and its test suite holds
our own examples of each layout it has to handle.

## For AI agents

`skills/predisclose/SKILL.md` is a ready-made skill for Claude Code, Codex, and similar agents. It tells them to call `predisclose check --json`, never to describe a finding as new, and never to send finding details to other services.

## Privacy and limitations

See [docs/privacy.md](docs/privacy.md) and [docs/limitations.md](docs/limitations.md).

## License

Apache-2.0
