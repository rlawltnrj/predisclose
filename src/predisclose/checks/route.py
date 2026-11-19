"""Check 4: where does this project want security reports?"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

from predisclose.http import Http, NetworkError
from predisclose.models import CheckResult, Evidence
from predisclose.sources import github

NAME = "where_to_report"

MAX_POLICY_CHARS = 200_000
MAX_LINE_CHARS = 2_000
POLICY_PATHS = ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
MD_LINK = re.compile(r"\[([^\]]+)\]\((https?://[^)\s]+)\)")
BARE_URL = re.compile(r"(?<![(\[])https?://[^\s)>\]\"'`]+")
GITHUB_REPORTING = re.compile(
    r"security advisor(y|ies)|advisories/new|private vulnerability report|privately report|"
    r"report a vulnerability|security tab|\"security\" at the top",
    re.IGNORECASE,
)
PREFERRED = re.compile(r"preferred|preferably|primary|please use|recommended way", re.IGNORECASE)
FALLBACK = re.compile(
    r"escalat|if you do not (receive|hear)|no (response|acknowledg)|fallback|alternatively|otherwise|\bcna\b",
    re.IGNORECASE,
)
REPORT_WORDS = re.compile(r"report|disclos|vulnerab|security|bounty|contact|send|e-?mail", re.IGNORECASE)
STRONG_WORDS = re.compile(r"report|disclos|vulnerab|bounty", re.IGNORECASE)
SECURITY_LOCAL = re.compile(r"secur|vuln|psirt|cert|disclos|bounty", re.IGNORECASE)
NOT_A_CHANNEL = re.compile(r"copyright|\(c\)|©|spdx|license|licence|all rights reserved", re.IGNORECASE)
PLATFORMS = {
    "hackerone": "HackerOne",
    "bugcrowd": "Bugcrowd",
    "intigriti": "Intigriti",
    "huntr": "huntr",
    "yeswehack": "YesWeHack",
    "immunefi": "Immunefi",
    "tidelift": "Tidelift",
}
IGNORED_EMAIL_DOMAINS = ("example.com", "example.org", "users.noreply.github.com")
IGNORED_URL_HOSTS = ("img.shields.io", "badge", "spdx.org", "opensource.org", "creativecommons.org")


@dataclass
class Channel:
    kind: str  # github | platform | email | link
    value: str
    score: int
    position: int
    context: str

    def describe(self) -> str:
        return {
            "github": f"GitHub private vulnerability reporting -> {self.value}",
            "platform": f"report through {self.value}",
            "email": f"email {self.value}",
            "link": f"follow {self.value}",
        }[self.kind]


KIND_ORDER = {"github": 0, "platform": 1, "email": 2, "link": 3}


def _host(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except ValueError:
        return ""


def find_policy(http: Http, repo: str) -> tuple[str, str] | None:
    """SECURITY.md in the repository, else the organization's .github repository."""
    for path in POLICY_PATHS:
        text = github.raw_file(http, repo, path)
        if text:
            return f"https://github.com/{repo}/blob/HEAD/{path}", text
    owner = repo.split("/", 1)[0]
    for path in ("SECURITY.md", ".github/SECURITY.md"):
        text = github.raw_file(http, f"{owner}/.github", path)
        if text:
            return f"https://github.com/{owner}/.github/blob/HEAD/{path}", text
    return None


NEGATION = re.compile(r"\b(do not|don't|dont|never|avoid)\b(?!\s+hesitate)", re.IGNORECASE)
# What ends the reach of a "do not": punctuation, a dash, or a conjunction starting a new instruction.
CLAUSE_BREAK = re.compile(r"[.,;:!?]|\s[-\u2013\u2014]+\s|\b(instead|but|rather|and)\b", re.IGNORECASE)
URL_ANYWHERE = re.compile(r"https?://\S+")
GENERIC_PHRASE = "report a vulnerability"  # names a topic; alone it does not mean GitHub


def _without_urls(line: str) -> str:
    """The line with each URL blanked out (same length), so its dots and colons don't split clauses."""
    return URL_ANYWHERE.sub(lambda m: " " * len(m.group(0)), line)


def _negated_at(line: str, at: int) -> bool:
    """True when the clause leading up to position `at` says not to do it ("do not use GitHub ...")."""
    clause = CLAUSE_BREAK.split(_without_urls(line)[:at])[-1]
    return bool(NEGATION.search(clause or ""))


def _asks_for_github(line: str, *, heading: bool = False) -> bool:
    text = _without_urls(line)
    for m in GITHUB_REPORTING.finditer(text):
        if heading and m.group(0).lower() == GENERIC_PHRASE:
            continue
        if not _negated_at(line, m.start()):
            return True
    return any(
        "/security/advisories" in u.group(0) and not _negated_at(line, u.start())
        for u in URL_ANYWHERE.finditer(line)
    )


def parse_policy(text: str, repo: str, pvr: bool | None) -> list[Channel]:
    """
    Every reporting channel a SECURITY.md mentions, best first.
    Order of preference: a channel the policy marks as preferred, then the strongest kind of
    channel, then the one mentioned first. Escalation-only contacts rank low.
    """
    channels: dict[tuple[str, str], Channel] = {}
    pvr_url = f"https://github.com/{repo}/security/advisories/new"
    heading = ""

    def add(kind: str, value: str, base: int, pos: int, line: str) -> None:
        score = base
        if PREFERRED.search(line) or PREFERRED.search(heading):
            score += 5
        if STRONG_WORDS.search(heading):
            score += 1
        if FALLBACK.search(line):
            score -= 3
        key = (kind, value.lower())
        if key not in channels or channels[key].score < score:
            channels[key] = Channel(kind, value, score, pos, line.strip()[:160])

    # Policies are written by the repository owner: bound the work so a crafted file (one huge
    # line, megabytes of text) cannot stall the run.
    for pos, line in enumerate(text[:MAX_POLICY_CHARS].splitlines()):
        line = line[:MAX_LINE_CHARS]
        is_heading = line.lstrip().startswith("#")
        if is_heading:
            heading = line
        if NOT_A_CHANNEL.search(line):
            continue
        relevant_line = bool(REPORT_WORDS.search(line) or REPORT_WORDS.search(heading))
        if _asks_for_github(line, heading=is_heading):
            add("github", pvr_url, 4 if pvr else 1, pos, line)
        for m in MD_LINK.finditer(line):
            label, url = m.group(1), m.group(2)
            if _negated_at(line, m.start()):
                continue  # "do not use [this](...)"
            host = _host(url)
            if not host or any(h in host or h in url.lower() for h in IGNORED_URL_HOSTS):
                continue
            platform = next((name for key, name in PLATFORMS.items() if key in host), None)
            if platform:
                add("platform", f"{platform} ({url})", 4, pos, line)
            elif "/security/advisories" in url or GITHUB_REPORTING.search(label):
                add("github", pvr_url, 4 if pvr else 1, pos, line)
            else:
                if STRONG_WORDS.search(label) or STRONG_WORDS.search(url):
                    base = 4
                elif REPORT_WORDS.search(label) or REPORT_WORDS.search(url):
                    base = 3
                else:
                    base = 2 if relevant_line else 0
                add("link", url, base, pos, line)
        for url in BARE_URL.findall(line):
            url = url.rstrip(".,;:")
            host = _host(url)
            if not host or any(h in host for h in IGNORED_URL_HOSTS):
                continue
            platform = next((name for key, name in PLATFORMS.items() if key in host), None)
            if platform:
                add("platform", f"{platform} ({url})", 4, pos, line)
            else:
                if STRONG_WORDS.search(url):
                    base = 4
                elif REPORT_WORDS.search(url):
                    base = 3
                else:
                    base = 2 if relevant_line else 0
                add("link", url, base, pos, line)
        for email in EMAIL.findall(line) if "@" in line else ():
            if any(email.lower().endswith(d) for d in IGNORED_EMAIL_DOMAINS):
                continue
            local = email.split("@", 1)[0]
            add("email", email, 3 + (1 if SECURITY_LOCAL.search(local) else 0), pos, line)
        lower = line.lower()
        for key, name in PLATFORMS.items():
            if key in lower and not any(c.kind == "platform" and name in c.value for c in channels.values()):
                add("platform", name, 3, pos, line)

    ranked = [c for c in channels.values() if c.score > 0]
    ranked.sort(key=lambda c: (-c.score, c.position, KIND_ORDER[c.kind]))
    return ranked


def public_host(homepage: str) -> str | None:
    """
    The host of a project homepage, only if it is safe to contact: a public DNS name that does not
    resolve to a private, loopback, link-local or otherwise internal address. The homepage is set by
    the repository owner, so it must never make this tool reach into the user's own network.
    """
    try:
        parsed = urlparse(homepage.strip())
        host = (parsed.hostname or "").rstrip(".").lower()
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https") or not host or "." not in host:
        return None
    if host == "github.com" or host.endswith((".github.com", ".localhost", ".local", ".internal", ".lan", ".home")):
        return None
    try:
        ipaddress.ip_address(host)
        return None  # a bare IP address is never a project homepage worth trusting
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except (OSError, UnicodeError):
        return None
    for info in infos:
        address = ipaddress.ip_address(info[4][0])
        if not address.is_global:
            return None
    return host


def security_txt_contacts(http: Http, homepage: str) -> tuple[str, list[str]] | None:
    host = public_host(homepage)
    if host is None:
        return None
    url = f"https://{host}/.well-known/security.txt"
    status, text = http.get_text(url)
    if status != 200 or not text or "contact:" not in text.lower():
        return None
    contacts = [
        line.split(":", 1)[1].strip()
        for line in text.splitlines()
        if line.lower().startswith("contact:")
    ]
    return (url, contacts[:5]) if contacts else None


def check(http: Http, repo: str | None) -> CheckResult:
    if http.dry_run:
        return CheckResult(NAME, "skipped", "none", "Dry run: nothing was sent.")
    if not repo:
        return CheckResult(NAME, "skipped", "none", "Need a repository (--repo, or a package we can map to one).")

    info = github.repo_info(http, repo)
    if info is None:
        return CheckResult(NAME, "error", "none", f"Repository {repo} not found or not public.")
    pvr = github.private_reporting_enabled(http, repo)
    pvr_url = f"https://github.com/{repo}/security/advisories/new"
    policy = find_policy(http, repo)
    homepage = str(info.get("homepage") or "")
    evidence: list[Evidence] = []
    notes: list[str] = []

    # security.txt is a fallback on a host the repository owner chose; a failure there (redirect
    # loop, timeout) must not hide the answer from SECURITY.md or GitHub.
    try:
        sectxt = security_txt_contacts(http, homepage) if homepage else None
    except NetworkError:
        sectxt = None
        notes.append("The project homepage's security.txt could not be read (network error).")

    if policy:
        url, text = policy
        channels = parse_policy(text, repo, pvr)
        evidence.append(Evidence("security.md", "SECURITY.md", "Security policy", url, level="info"))
        if channels:
            summary = "Follow SECURITY.md: " + channels[0].describe()
            for c in channels[1:4]:
                evidence.append(
                    Evidence("security.md", c.kind, "also mentioned: " + c.describe(), url, level="info")
                )
        elif pvr:
            summary = f"Read SECURITY.md; private reporting is also enabled -> {pvr_url}"
        else:
            summary = f"Read SECURITY.md for instructions -> {url}"
        if any(c.kind == "github" for c in channels) and pvr is False:
            notes.append("SECURITY.md mentions GitHub reporting, but private reporting is turned off.")
        status = "found"
    elif pvr:
        summary = f"GitHub private vulnerability reporting -> {pvr_url}"
        status = "found"
    elif sectxt:
        summary = "security.txt contact: " + ", ".join(sectxt[1][:3])
        status = "found"
    else:
        summary = (
            "No channel in the standard places (SECURITY.md, GitHub private reporting, security.txt). "
            "Check the project's documentation; if there is none, ask the maintainers for a private "
            "contact without sharing any details of the issue."
        )
        status = "none"

    if pvr is not None:
        evidence.append(
            Evidence(
                "github",
                "private-reporting",
                "GitHub private vulnerability reporting: " + ("on" if pvr else "off"),
                pvr_url if pvr else f"https://github.com/{repo}/security",
                level="info",
            )
        )
    if sectxt:
        evidence.append(Evidence("security.txt", "security.txt", ", ".join(sectxt[1][:3]), sectxt[0], level="info"))
    if info.get("archived"):
        notes.append("The repository is archived; maintainers may not respond.")
    notes.append("GitHub-hosted projects can request a CVE through a GitHub security advisory.")
    return CheckResult(NAME, status, "info", summary, evidence, notes)
