# Contributing

Thanks for helping. Small, focused pull requests are easiest to review.

## Setup

```bash
uv venv && uv pip install -e ".[dev]"     # or: python -m venv .venv && pip install -e ".[dev]"
ruff check . && pytest -q
```

Tests never touch the network. Use `httpx.MockTransport` like `tests/test_core_offline.py`.

## Good first contributions

- **A SECURITY.md layout we get wrong.** Add a short example of the layout to
  `tests/test_route_policy.py` (write it in your own words; do not paste the project's text),
  then fix `parse_policy` in `src/predisclose/checks/route.py`.
- **A registry we cannot map to a repository.** Extend `src/predisclose/sources/registry.py`.
- **A tag naming pattern we miss.** Extend `resolve_version` in `src/predisclose/sources/github.py`.

## Rules the code keeps

- Public data only. No feature may reproduce, scan, or test a target, or post anything.
- Nothing the user writes about their finding (keywords, functions, notes) may be sent anywhere.
  CWE ids are matched locally too.
- Never word a result as "new" or "unreported".
- Every result explains why, with a link.

## AI-assisted contributions

They are welcome. Please say so in the pull request, and make sure you have read and tested every
line yourself.
