"""Make text from public sources safe to show. Advisory titles, commit messages and policies are
written by strangers, so they must not be able to move the cursor, clear the screen, or break
Markdown and Rich markup."""

from __future__ import annotations

import re

# C0 controls except tab and newline, DEL, and C1 controls (covers ESC and CSI sequences).
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def clean(value: object) -> str:
    return _CONTROL.sub("", "" if value is None else str(value))


def one_line(value: object) -> str:
    return " ".join(clean(value).split())


def md_text(value: object) -> str:
    """Plain text for a Markdown table cell or list item."""
    text = one_line(value)
    for ch in "\\|[]<>*_`":
        text = text.replace(ch, "\\" + ch)
    return text


def md_url(value: object) -> str:
    """A URL for a Markdown link target, or '' if it is not a plain http(s) URL."""
    url = one_line(value)
    if not re.fullmatch(r"https?://[^\s<>()]+", url):
        return ""
    return url
