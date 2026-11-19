"""
Live sanity check of the public-record check across ecosystems.

For each sampled reviewed GitHub advisory:
  * a version listed as affected by OSV must surface the advisory at level >= medium
    when the advisory's CWE is given (recall), and
  * the first patched version must not list it at all (control).

Usage:  GITHUB_TOKEN=... python scripts/eval_recall.py [per_ecosystem]
"""

from __future__ import annotations

import sys

from predisclose.checks import known
from predisclose.ecosystems import GHSA_ECOSYSTEM
from predisclose.http import Http, github_token_from_env
from predisclose.models import LEVELS, Finding

ECOSYSTEMS = ["PyPI", "npm", "crates.io", "Go", "Maven", "RubyGems", "Packagist"]


def _semver(v: str) -> tuple[int, ...] | None:
    core = v.lstrip("v").split("-", 1)[0].split("+", 1)[0]
    try:
        return tuple(int(x) for x in core.split("."))
    except ValueError:
        return None


def registry_versions(http: Http, ecosystem: str, name: str) -> list[str]:
    if ecosystem == "npm":
        status, data = http.get_json(f"https://registry.npmjs.org/{name.replace('/', '%2F')}")
        return list((data or {}).get("versions", {}).keys()) if status == 200 else []
    if ecosystem == "Go":
        status, text = http.get_text(f"https://proxy.golang.org/{name.lower()}/@v/list")
        return text.split() if status == 200 and text else []
    return []


def last_before(versions: list[str], fixed: str) -> str | None:
    f = _semver(fixed)
    if f is None:
        return None
    best = None
    for v in versions:
        sv = _semver(v)
        if sv is None or "-" in v.lstrip("v"):
            continue
        if sv < f and (best is None or sv > _semver(best)):
            best = v
    return best


def sample(http: Http, ecosystem: str, n: int) -> list[dict]:
    status, data = http.get_json(
        "https://api.github.com/advisories",
        params={"type": "reviewed", "ecosystem": GHSA_ECOSYSTEM[ecosystem], "per_page": 40},
    )
    out = []
    for adv in data if status == 200 and isinstance(data, list) else []:
        cwes = [c["cwe_id"] for c in adv.get("cwes") or [] if c.get("cwe_id")]
        vulns = adv.get("vulnerabilities") or []
        if not cwes or not vulns or adv.get("withdrawn_at"):
            continue
        v = vulns[0]
        patched = v.get("first_patched_version")
        name = (v.get("package") or {}).get("name")
        if not patched or not name:
            continue
        status, osv_entry = http.get_json(f"https://api.osv.dev/v1/vulns/{adv['ghsa_id']}")
        if status != 200 or not isinstance(osv_entry, dict):
            continue
        versions = []
        for aff in osv_entry.get("affected") or []:
            if (aff.get("package") or {}).get("name") == name:
                versions = aff.get("versions") or []
        vuln = versions[-1] if versions else last_before(registry_versions(http, ecosystem, name), patched)
        if not vuln:
            continue
        lower = next(
            (p.strip()[2:].strip() for p in (v.get("vulnerable_version_range") or "").split(",")
             if p.strip().startswith(">=")),
            None,
        )
        if lower and not versions:
            lo, sv = _semver(lower), _semver(vuln)
            if lo is None or sv is None or "-" in lower or sv < lo:
                continue  # cannot pick a version that is surely inside the range
        if ecosystem == "Go" and not patched.startswith("v"):
            patched = "v" + patched
        out.append({"id": adv["ghsa_id"], "name": name, "cwe": cwes[0], "vuln": vuln, "fixed": patched})
        if len(out) >= n:
            break
    return out


def main() -> None:
    per = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    http = Http(token=github_token_from_env())
    hits = total = control_ok = 0
    for eco in ECOSYSTEMS:
        for case in sample(http, eco, per):
            total += 1
            f = Finding(ecosystem=eco, package=case["name"], version=case["vuln"], cwe=[case["cwe"]])
            advs, _ = known.gather(http, f)
            result = known.check(http, f, advs, [])
            level = next(
                (e.level for e in result.evidence if e.id == case["id"] or case["id"] in e.reasons), None
            )
            if level is None:
                level = next(
                    (e.level for e, a in zip(result.evidence, advs, strict=False) if case["id"] in a.all_ids()),
                    None,
                )
            found = any(case["id"] in a.all_ids() for a in advs)
            ok = found and level is not None and LEVELS.index(level) >= LEVELS.index("medium")
            hits += ok

            g = Finding(ecosystem=eco, package=case["name"], version=case["fixed"], cwe=[case["cwe"]])
            advs_fixed, _ = known.gather(http, g)
            clean = not any(case["id"] in a.all_ids() for a in advs_fixed)
            control_ok += clean
            print(
                f"{eco:<10} {case['id']}  {case['name'][:30]:<30} vuln={case['vuln']:<12} "
                f"recall={'ok' if ok else 'MISS'}  control={'ok' if clean else 'LEAK'}"
            )
    http.close()
    print(f"\nrecall {hits}/{total}   control {control_ok}/{total}")


if __name__ == "__main__":
    main()
