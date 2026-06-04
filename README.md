# Write role moves tags/releases past branch protection

High · Verified live · 2026-06-04 · `stefanpenner/tag-release-test`

**Claim:** a `write`-role collaborator, denied direct push to a review-protected
default branch, can repoint the **Latest release tag** to unreviewed code.

**At a glance:** the attacked release [`v1.0.0`](https://github.com/stefanpenner/tag-release-test/releases/tag/v1.0.0)
was moved from its legitimate, reviewed target [`a1c628d`](https://github.com/stefanpenner/tag-release-test/commit/a1c628d3fe200bdb6cc49d9b52aa83a4600cfae8)
onto the unreviewed [`d17977b`](https://github.com/stefanpenner/tag-release-test/commit/d17977ba8e5a2bbeb38d39e93937da7db78eda91)
— [diff: what consumers silently got](https://github.com/stefanpenner/tag-release-test/compare/a1c628d3fe200bdb6cc49d9b52aa83a4600cfae8...d17977ba8e5a2bbeb38d39e93937da7db78eda91).

## Setup

- `main`: protected — `required_approving_review_count=1`, `enforce_admins=true`
- release [`v1.0.0`](https://github.com/stefanpenner/tag-release-test/releases/tag/v1.0.0) → reviewed commit [`a1c628d`](https://github.com/stefanpenner/tag-release-test/commit/a1c628d3fe200bdb6cc49d9b52aa83a4600cfae8)
- branch [`attacker`](https://github.com/stefanpenner/tag-release-test/tree/attacker) — unreviewed commit [`d17977b`](https://github.com/stefanpenner/tag-release-test/commit/d17977ba8e5a2bbeb38d39e93937da7db78eda91) (`app.py` = malicious)
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

## API — create the protecting ruleset

`POST /repos/{owner}/{repo}/rulesets` (org-wide: `POST /orgs/{org}/rulesets`).
The "rule" is an entry in `rules[]`: `update` blocks moving a tag, `creation`
blocks new tags, `deletion` blocks deletes.

```bash
gh api -X POST repos/OWNER/REPO/rulesets --input - <<'JSON'
{
  "name": "protect-release-tags",
  "target": "tag",
  "enforcement": "active",
  "bypass_actors": [
    { "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always" }
  ],
  "conditions": { "ref_name": { "include": ["refs/tags/v*", "refs/tags/latest"], "exclude": [] } },
  "rules": [ { "type": "creation" }, { "type": "update" }, { "type": "deletion" } ]
}
JSON
```

`actor_id` for `RepositoryRole`: `1` read · `2` triage · `3` write · `4` maintain
· **`5` admin**. The fix depends on **`3` (write) NOT being in `bypass_actors`**.

Related: `GET .../rulesets` (list) · `GET .../rulesets/{id}` (read) ·
`PUT .../rulesets/{id}` (update, e.g. `-f enforcement=disabled`) ·
`DELETE .../rulesets/{id}` (remove).

## API — audit: is your repo affected?

Affected = no active tag ruleset restricting tag `update` (and no legacy tag
protection). Run against any repo:

```bash
audit() {
  local R="$1" protected=false
  for id in $(gh api repos/$R/rulesets --jq '.[] | select(.target=="tag" and .enforcement=="active") | .id' 2>/dev/null); do
    gh api repos/$R/rulesets/$id --jq '[.rules[].type]' 2>/dev/null | grep -q '"update"' && protected=true
  done
  local legacy=$(gh api repos/$R/tags/protection --jq 'length' 2>/dev/null)
  [[ "$legacy" =~ ^[0-9]+$ ]] && [ "$legacy" -gt 0 ] && protected=true
  $protected && echo "PROTECTED  $R" || echo "AFFECTED   $R"
}
audit OWNER/REPO
```

Verified output (toggling this repo's ruleset enforcement):

```
ruleset active:    PROTECTED  stefanpenner/tag-release-test
ruleset disabled:  AFFECTED   stefanpenner/tag-release-test
ruleset active:    PROTECTED  stefanpenner/tag-release-test
```

## Artifacts & references

- [Repo `stefanpenner/tag-release-test`](https://github.com/stefanpenner/tag-release-test)
- [Latest release `v1.0.0`](https://github.com/stefanpenner/tag-release-test/releases/tag/v1.0.0) → reviewed tag target [`a1c628d`](https://github.com/stefanpenner/tag-release-test/commit/a1c628d3fe200bdb6cc49d9b52aa83a4600cfae8)
- Unreviewed [`attacker` commit `d17977b`](https://github.com/stefanpenner/tag-release-test/commit/d17977ba8e5a2bbeb38d39e93937da7db78eda91) on the [`attacker` branch](https://github.com/stefanpenner/tag-release-test/tree/attacker)
- [PR #1 — report](https://github.com/stefanpenner/tag-release-test/pull/1) (approved + merged via the gate) · [PR #2 — API + audit](https://github.com/stefanpenner/tag-release-test/pull/2)
- [Protecting ruleset `protect-release-tags`](https://github.com/stefanpenner/tag-release-test/settings/rules/17286036) (admin only)

GitHub docs: [About rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets) ·
[Available rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets) ·
[About releases](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases)
