"""Make text from public sources safe to show. Advisory titles, commit messages and policies are
written by strangers, so they must not be able to move the cursor, clear the screen, or break
Markdown and Rich markup."""

from __future__ import annotations

import re

# C0 controls except tab and newline, DEL, C1 controls (covers ESC and CSI sequences), and
# bidirectional overrides/isolates, which can visually reorder a line.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]")


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
    # Characters that could end a Rich [link=...] tag or a Markdown link target are encoded;
    # the link still works and cannot be bent into markup.
    for ch, enc in (("[", "%5B"), ("]", "%5D"), ('"', "%22"), ("'", "%27"), ("\\", "%5C"), ("`", "%60")):
        url = url.replace(ch, enc)
    return url
