# Limitations

Read these before trusting a result.

1. **Private reports are invisible.** If someone else reported the same issue privately and it is
   not public yet, no tool can see it. "No public record" never means "new".
2. **Matching is textual.** Advisories that describe the same bug in different words, or without
   naming files or functions, can score *weak*. Read the weak list too when it is short.
3. **Advisory data lags and has gaps.** Some fixed issues never get an advisory; some advisories
   list wrong version ranges. When you find a wrong range, consider fixing it upstream in OSV or
   the GitHub Advisory Database.
4. **Version to commit is a guess.** Tags are matched by common naming patterns. If your project
   tags releases differently, pass the exact tag or commit sha as `--version`.
5. **Only the default branch is searched for commits.** Fixes made only on a release branch are
   found only when an advisory names them.
6. **GitHub only, for repository data.** Projects hosted elsewhere still get the public record
   check through their package, but not the fix or reporting-channel checks.
   When the registry does not name a repository, it is guessed from advisories, which can be
   wrong (packages of one family, such as `node-fetch` and `node-forge`, look alike) or missing
   (an advisory spanning `System.*` and `Microsoft.*` NuGet packages). The output says where the
   repository came from; pass `--repo` when it is wrong or missing.
7. **Some layouts are missed.** A policy stored only as lowercase `security.md` is not read
   (GitHub private reporting is still checked). Go advisories name package paths such as
   `golang.org/x/net/html`, so `--file html/token.go` may not match them; pass `--function`.
8. **SECURITY.md parsing is heuristic.** It handles the common layouts and common ways of saying
   "do not use X", but not every phrasing. Always open the policy and read it. When a project has no `SECURITY.md`, its website may state a different
   preference than the one shown.
9. **Rate limits.** Without a token, GitHub allows 60 API requests per hour. One full check uses
   about 10 of them (more with several `--file` paths). Set `GITHUB_TOKEN`.
