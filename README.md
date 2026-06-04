# Security Report: Write role can move tags/releases past branch protection

**Severity:** High · **Status:** Verified (live PoC) · **Date:** 2026-06-04

## Summary

GitHub branch protection / PR-review rules protect **branches only**. They place
no constraint on **tags**. Since the `write` role is sufficient to create, move,
and delete tags and releases, a write-role collaborator can repoint a release tag
(including the "Latest" release) onto **unreviewed code** — fully bypassing the
code-review gate on the default branch.

## Impact

Anyone consuming a tag/release — `git checkout vX`, release tarballs, a
`uses: org/repo@vX` Action ref, package/Docker builds pinned to a tag — receives
attacker-controlled code that never passed review.

## Proof of concept

Setup: `main` protected (1 approving review required, `enforce_admins: true`);
release `v1.0.0` on reviewed `main`; unreviewed `attacker` branch with a malicious
commit. Actor: a collaborator with `push:true, admin:false, maintain:false`.

| # | Actor (write) | Action | Result |
|---|---|---|---|
| 1 | writer | push unreviewed code → `main` | ❌ `Changes must be made through a pull request` |
| 2 | writer | force-move tag `v1.0.0` → attacker commit | ✅ **Succeeded** |
| 3 | — | "Latest" release `v1.0.0` now serves | `MALICIOUS unreviewed code` |

The writer, *explicitly denied* direct push to `main`, moved the Latest release
onto unreviewed code with one API call:

```bash
gh api -X PATCH repos/$REPO/git/refs/tags/v1.0.0 -f sha=$ATTACKER_SHA -F force=true
```

## Root cause

`write` **is** the tag/release permission — there is no lower "can push but cannot
tag" role. Branch protection and branch-targeted rulesets do not apply to tags.

## Remediation

Add a **Repository Ruleset** targeting **tags** (Settings → Rules → Rulesets):

- **Target tags:** `refs/tags/v*`, `refs/tags/latest` (every release-grade pattern)
- **Rules:**
  - **Restrict updates** — blocks moving an existing tag (the core fix)
  - **Restrict creations** — blocks the "new `v2.0.0` on my branch" variant
  - **Restrict deletions** — (default-on)
- **Bypass actors:** repo **admins** and/or a release-bot App/team only.
  **Do not add the Write role to bypass** — doing so reopens the hole.

> Legacy: Settings → Tags → Tag protection rules (deprecated in favor of rulesets).
> Note: `make_latest=true` can flag any non-draft release as "Latest", so the
> protected pattern must cover *all* release-grade tag names.

### Verified fix

With the ruleset active, the same writer retried — both variants rejected:

| Retry (write) | Result |
|---|---|
| force-move `v1.0.0` → attacker commit | ❌ `Repository rule violations found — Cannot update this protected ref` |
| create `v2.0.0` on attacker commit | ❌ `Reference update failed` |
