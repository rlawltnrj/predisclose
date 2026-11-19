# predisclose: notes for coding agents

predisclose is a Python CLI that, before someone reports a vulnerability, reads **public data
only** (OSV, GitHub Advisory Database, GitHub repository API, SECURITY.md, security.txt) and says:
is there a public record, has the code changed since the tested version, has the area had recent
advisories, and where does the project want reports. It also keeps a local ledger of sent reports.

## Layout

- `src/predisclose/sources/`: one module per public data source (`osv`, `ghsa`, `github`, `registry`)
- `src/predisclose/checks/`: the four checks (`known`, `fixes`, `activity`, `route`) and `similarity`
- `src/predisclose/core.py`: runs the checks; `cli.py`: Typer commands; `output.py` + `text.py`: rendering
- `src/predisclose/http.py`: the only HTTP client (query log, cache, token handling, redirects)
- `tests/`: offline tests with `httpx.MockTransport`; `scripts/eval_recall.py`: live evaluation

## Commands

```bash
uv venv && uv pip install -e ".[dev]"
.venv/bin/ruff check . && .venv/bin/pytest -q
GITHUB_TOKEN=$(gh auth token) .venv/bin/python scripts/eval_recall.py 5   # live, ~3 min
```

## Rules the code keeps (do not break these)

1. Public data only. No feature may reproduce, scan, or test a target, or post anything anywhere.
2. Nothing the user writes about their finding (keywords, functions, CWE, notes) leaves the machine.
   Only package, version, repository and file paths are sent. Keep `docs/privacy.md` exact.
3. Never word a result as "new" or "unreported": private reports by others are invisible.
4. Every request goes through `Http`, is logged for `--show-queries`, and redirects are followed
   only to the same host over https. The GitHub token goes only to `api.github.com`.
5. Hosts taken from repository data (the homepage) are contacted only if `public_host()` allows it.
6. All text from public sources is untrusted: render it through `predisclose.text` (`one_line`,
   `md_text`, `md_url`) and escape Rich markup.
7. A check must never crash the run: unexpected data becomes an `error` result for that check.

## Tests

- Tests never touch the network. Add a `MockTransport` handler like `tests/test_core_offline.py`.
- SECURITY.md parsing fixtures are written in our own words, modelled on real layouts; never paste
  a project's policy text.
- Every bug fix gets a regression test.

## Releasing

1. Bump `version` in `pyproject.toml` and `__version__` in `src/predisclose/__init__.py`.
2. Move CHANGELOG entries under the new version with the date.
3. Run lint, tests, a lowest-dependency install (`uv pip install --resolution lowest-direct`) on
   Python 3.11, and the live evaluation. Get an independent code review before tagging.
4. `gh release create vX.Y.Z --target main` publishes to PyPI through Trusted Publishing
   (`.github/workflows/release.yml`, environment `pypi`). No tokens are stored anywhere.
