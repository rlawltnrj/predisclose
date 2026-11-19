"""SECURITY.md parsing. Each fixture mirrors a structure seen in real projects (text is our own)."""

import pytest

from predisclose.checks.route import parse_policy

REPO = "acme/widget"
PVR = f"https://github.com/{REPO}/security/advisories/new"

COPYRIGHT_EMAIL_THEN_LINK = """\
Copyright (C) Jane Doe, <jane@example.net>, et al.

# Security

Found a security problem? Please [report it](https://widget.dev/vuln-disclosure.html)!
"""

PREFERRED_SECTION = """\
# Security Policy

## Reporting a Security Vulnerability

You can email the team at widget-security@lists.example.net.

### Reporting via GitHub Security Advisory (Preferred)

The preferred way to report is through
[GitHub Security Advisories](https://github.com/advisories).
"""

REFERENCE_STYLE_LINK = """\
## Reporting a Security Issue

Do not open a public issue. To report a security issue, use GitHub's
[security advisory system][gh-docs]. You can also email security@widget.dev.

[gh-docs]: https://docs.github.com/en/code-security
"""

PLATFORM_WITH_ESCALATION = """\
## Reporting a bug

Report security bugs via [HackerOne](https://hackerone.com/widget).

If you do not receive an acknowledgement within 6 days, you may escalate to
`security@foundation.example.net`.
"""

POLICY_LINK_BEFORE_REPORTING = """\
# Security Policy

[Widget Security Policy](https://widget.dev/policies/secpolicy.html)

## Reporting a Vulnerability

To report a new vulnerability please follow the [Widget reporting process](https://widget.dev/community/#reports).
"""

SINGLE_SENTENCE_EMAIL = """\
# Reporting Security Issues

Please report any vulnerabilities in our open source repositories to responsible.disclosure@widget.dev.
"""


@pytest.mark.parametrize(
    ("text", "pvr", "kind", "value"),
    [
        (COPYRIGHT_EMAIL_THEN_LINK, False, "link", "https://widget.dev/vuln-disclosure.html"),
        (PREFERRED_SECTION, True, "github", PVR),
        (REFERENCE_STYLE_LINK, True, "github", PVR),
        (PLATFORM_WITH_ESCALATION, False, "platform", "HackerOne (https://hackerone.com/widget)"),
        (POLICY_LINK_BEFORE_REPORTING, False, "link", "https://widget.dev/community/#reports"),
        (SINGLE_SENTENCE_EMAIL, False, "email", "responsible.disclosure@widget.dev"),
    ],
)
def test_best_channel(text, pvr, kind, value):
    channels = parse_policy(text, REPO, pvr)
    assert channels, "expected at least one channel"
    assert (channels[0].kind, channels[0].value) == (kind, value)


def test_copyright_email_is_never_a_channel():
    channels = parse_policy(COPYRIGHT_EMAIL_THEN_LINK, REPO, False)
    assert all(c.value != "jane@example.net" for c in channels)


def test_escalation_contact_ranks_below_platform():
    channels = parse_policy(PLATFORM_WITH_ESCALATION, REPO, False)
    kinds = [c.kind for c in channels]
    assert kinds.index("platform") < kinds.index("email")


def test_github_reporting_drops_when_disabled():
    channels = parse_policy(REFERENCE_STYLE_LINK, REPO, False)
    assert channels[0].kind == "email"
