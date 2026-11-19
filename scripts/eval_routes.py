"""
Live check of the reporting-channel answer for ten well-known projects.

Each project's expected channel was checked by hand against its own policy. A failure means
either our parsing regressed or the project changed its policy; both need a look.

Usage:  GITHUB_TOKEN=... python scripts/eval_routes.py
"""

from __future__ import annotations

import sys

from predisclose.core import run_check
from predisclose.http import Http, github_token_from_env
from predisclose.models import Finding

# repository -> text the "Where to report" summary must contain
EXPECTED = {
    "curl/curl": "curl.se/dev/vuln-disclosure.html",
    "expressjs/express": "GitHub private vulnerability reporting",
    "hyperium/hyper": "GitHub private vulnerability reporting",
    "pallets/jinja": "GitHub private vulnerability reporting",
    "rails/rails": "GitHub private vulnerability reporting",
    "django/django": "djangoproject.com/security",
    "nodejs/node": "HackerOne",
    "openssl/openssl": "community/#securityreports",
    "golang/go": "go.dev/security/policy",
    "vercel/next.js": "responsible.disclosure@vercel.com",
}


def main() -> int:
    http = Http(use_cache=False, token=github_token_from_env())
    ok = 0
    try:
        for repo, want in EXPECTED.items():
            report = run_check(http, Finding(repo=repo), ("route",))
            result = report.results[0]
            good = result.status == "found" and want in result.summary
            ok += good
            print(f"{repo:<20} {'ok  ' if good else 'FAIL'} {result.summary}")
            if not good:
                print(f"{'':<20}      expected to contain: {want}")
    finally:
        http.close()
    print(f"\nroutes {ok}/{len(EXPECTED)}")
    return 0 if ok == len(EXPECTED) else 1


if __name__ == "__main__":
    sys.exit(main())
