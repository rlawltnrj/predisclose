---
name: predisclose
description: Use when someone has a candidate vulnerability in an open-source project and is preparing to report it. Checks public advisory databases for prior records, lists public changes to the affected code since the tested version, shows recent advisory activity, and finds the project's official private reporting channel. Uses public data only.
---

# predisclose

Run the check with whatever the user knows, as JSON:

```bash
predisclose check --pkg <ecosystem:name> --version <version> \
  [--repo owner/name] [--cwe CWE-<n>] [--file <path>] [--function <name>] --json
```

Ecosystems: pypi, npm, cargo, go, maven, nuget, rubygems, composer, pub, hex. For a project that is
not on a registry, use `--repo owner/name --version <tag-or-commit>` instead of `--pkg`.

Report the four results in this order:

1. `public_record`: list *strong* and *medium* matches with their ids, links and reasons. A strong
   match means the issue is probably already known: say so plainly and suggest reading it first.
2. `public_fix`: commits or releases after the tested version that touched the affected code. Tell
   the user to re-test on the latest release before reporting.
3. `recent_activity`: if similar advisories were published recently, say that parallel reports are
   more likely in this area.
4. `where_to_report`: the recommended channel and the link to the policy.

Rules:

- Never describe a finding as "new" or "unreported". Say "no public record found"; private reports
  by others are not visible.
- Do not send details of the finding to any other service, search engine, or issue tracker.
- Do not submit, post, or draft a public issue about the vulnerability. Reporting is the user's
  decision and goes through the private channel the project asks for.
- If a check returns `error` because of a GitHub rate limit, suggest
  `export GITHUB_TOKEN=$(gh auth token)` and running again.
