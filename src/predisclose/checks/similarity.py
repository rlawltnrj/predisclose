"""How closely an advisory resembles the user's finding. Deterministic and explainable."""

from __future__ import annotations

import posixpath

from predisclose.models import Finding
from predisclose.sources.advisory import Advisory


def _mentions_file(text: str, path: str) -> bool:
    p = path.strip().lower()
    if not p:
        return False
    if p in text:
        return True
    base = posixpath.basename(p)
    # A bare basename counts only when it is specific enough (has an extension, not tiny).
    return "." in base and len(base) >= 5 and base in text


def _mentions_function(text: str, functions: set[str], name: str) -> bool:
    n = name.strip().lower()
    if not n:
        return False
    for f in functions:
        fl = f.lower()
        if fl == n or fl.endswith("." + n) or fl.endswith("::" + n):
            return True
    return len(n) >= 4 and n in text


def score(adv: Advisory, finding: Finding) -> tuple[str, list[str]]:
    text = f"{adv.summary}\n{adv.details}".lower()
    reasons: list[str] = []

    cwe_hit = sorted({c.upper() for c in finding.cwe} & adv.cwes)
    file_hit = [f for f in finding.files if _mentions_file(text, f)]
    func_hit = [fn for fn in finding.functions if _mentions_function(text, adv.functions, fn)]
    kw_hit = [k for k in finding.keywords if len(k.strip()) >= 3 and k.strip().lower() in text]

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
        reasons.append("affects this version" if adv.version_checked else "same project")

    if not adv.version_checked and level == "strong":
        level = "medium"
        reasons.append("version not checked")
    return level, reasons
