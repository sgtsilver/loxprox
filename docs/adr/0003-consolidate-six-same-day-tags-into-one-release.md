# 0003. Consolidate six same-day tags into a single v1.5.0 release

- **Status:** accepted
- **Date:** 2026-05-26

## Context

On 2026-05-26 a single intense work session produced **six tagged GitHub
releases** in a few hours: `v1.4.0` (16:28 UTC, skills-audit response),
`v1.5.0` first cut (17:25, per-host config separation), `v1.5.1` (17:34, a
whitespace-regex hotfix found while dogfooding the v1.5.0 live deploy), `v1.6.0`
(18:06, optional HTTPS via acme.sh + HTTP-01), `v1.6.1` (21:21, nftables `:80`
open for the ACME challenge + an acme.sh rc=0 fix), and `v1.6.2` (21:28, the
`error_page 497 → 301` redirect that broke the Loxone-iOS-app self-ban loop).

Most of these were not deliberate version boundaries — they were working commits
tagged on reflex, several of them immediate live-deploy fixes for the tag just
before. Shipping six versions in a day is twice the entire prior release history
of the v1.3.x line combined, and it pollutes the public release timeline so
readers cannot tell which tag represents a validated state.

Context source: `wiki/loxprox.md` (Version History → v1.5.0, "Release Cadence
Convention"), repo `CHANGELOG.md` `[1.5.0]` entry and its "Retired tags" table.

## Decision

We will collapse the six same-day tags into a **single `v1.5.0` release** that
absorbs all of them, and we will adopt a release-cadence convention going
forward:

- Local-only deploys to the live VM need no tagged release — push, deploy,
  validate; do not tag yet.
- Defer release-cutting until the session is ending or there is an explicit
  "cut a release" call; bundle a session's iteration into one well-shaped
  release.
- Fold live-deploy bugs caught during dogfooding back into the same in-flight
  branch, not separate patch tags — so the tag covers the validated state.
- When in doubt, ask "own release or roll into the next?" rather than reflex-
  tagging every working commit.

The consolidation was done fix-forward in two passes (≈18:06 then ≈21:49 UTC);
all six original tags and their GitHub releases were deleted.

## Consequences

- **Positive:** A single, well-shaped release per session keeps the public
  timeline legible — each tag represents a dogfooded, validated state. The
  CHANGELOG `[1.5.0]` entry preserves the full engineering history (what was
  tried, reverted, and why) so no lessons are lost despite the deletions.
- **Negative:** Tag deletion rewrites public release history, which can confuse
  anyone who had already fetched a now-retired tag. The CHANGELOG must carry a
  prominent "Retired tags" table as the canonical record of what was collapsed.
- **Neutral:** The convention is loxprox-specific; other projects in the
  workspace keep their own release cadence. SemVer is still followed — the point
  is to version *deliberately*, not to abandon versioning.
