# Security Policy

## Reporting a Vulnerability

Please report security issues in predisclose privately through
[GitHub private vulnerability reporting](https://github.com/rlawltnrj/predisclose/security/advisories/new)
(preferred). Do not open a public issue.

You will get an acknowledgement within 7 days. Fixes are released as soon as they are ready, and
the advisory is published with credit to the reporter unless you ask otherwise.

## Scope

Issues of particular interest:

- predisclose sending data it promises not to send (see `docs/privacy.md`)
- the GitHub token leaking into logs, caches, or requests to hosts other than `api.github.com`
- `ledger export` revealing details of reports that are not marked public
- a reporting-channel result that sends people to the wrong place
