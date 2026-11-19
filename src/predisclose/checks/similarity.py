"""How closely an advisory resembles the user's finding. Deterministic and explainable."""

from __future__ import annotations

import posixpath
import re

from predisclose.models import Finding
from predisclose.sources.advisory import Advisory

# A name counts only as a whole token: "io.c" must not match "radio.c", "read" not "thread".
_LEFT = r"(?<![A-Za-z0-9_.\-])"
_RIGHT = r"(?![A-Za-z0-9_])"


def _token(text: str, name: str) -> bool:
    return re.search(_LEFT + re.escape(name) + _RIGHT, text) is not None


def _mentions_file(text: str, path: str) -> bool:
    p = path.strip().strip("/").lower()
    if not p:
        return False
    if "/" in p and _token(text, p):
        return True
    base = posixpath.basename(p)
    # A bare file name must look like a file (has an extension) or be long enough to be specific.
    if ("." in base and len(base) >= 3) or len(base) >= 8:
        return _token(text, base)
    return False


def _mentions_function(text: str, functions: set[str], name: str) -> bool:
    n = name.strip().lower()
    if not n:
        return False
    for f in functions:
        fl = f.lower()
        if fl == n or fl.endswith("." + n) or fl.endswith("::" + n):
            return True
    if len(n) >= 6:
        return _token(text, n)
    # Short names ("read", "open") are ordinary words: require them to look like code.
    return re.search(_LEFT + re.escape(n) + r"\s*\(|`" + re.escape(n) + r"(\(\))?`", text) is not None


def score(adv: Advisory, finding: Finding) -> tuple[str, list[str]]:
    text = f"{adv.summary}\n{adv.details}".lower()
    reasons: list[str] = []

    cwe_hit = sorted({c.upper() for c in finding.cwe} & adv.cwes)
    file_hit = [f for f in finding.files if _mentions_file(text, f)]
    func_hit = [fn for fn in finding.functions if _mentions_function(text, adv.functions, fn)]
    kw_hit = [k for k in finding.keywords if len(k.strip()) >= 3 and _token(text, k.strip().lower())]

    if cwe_hit:
        reasons.append("same CWE: " + ", ".join(cwe_hit))
    if file_hit:
        reasons.append("mentions file: " + ", ".join(file_hit))
    if func_hit:
        reasons.append("mentions function: " + ", ".join(func_hit))
    if kw_hit:
        reasons.append("mentions keyword: " + ", ".join(kw_hit))

    same_place = bool(file_hit or func_hit)
    if (cwe_hit and same_place) or (file_hit and func_hit):
        level = "strong"
    elif cwe_hit or same_place or kw_hit:
        level = "medium"
    else:
        level = "weak"
        reasons.append("affects this version" if adv.version_checked else "same package")

    if not adv.version_checked and level == "strong":
        level = "medium"
        reasons.append("version not checked")
    return level, reasons
