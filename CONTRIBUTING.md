**Language:** [Deutsch](CONTRIBUTING.de.md) · English

# Contributing to LoxProx

This is a specialized security appliance for Loxone Miniserver Gen 1. Contributions are welcome, but please keep the scope focused.

## AI-Generated Contributions

AI-assisted code and reports are welcome **only if a human has reviewed, understood, and verified them on real hardware**. Low-effort AI-generated slop — copy-pasted vulnerability reports, untested PRs, or issues without reproduction steps — will be closed without comment.

If you used AI to help find a bug: include the actual test output and steps to reproduce. If you used AI to write a fix: run it on a real system before submitting. The quality bar is the same whether the code came from a human or a model.

> **Works on my machine. If it doesn't on yours — well, ask your AI.**

## What We're Looking For

- **Bug fixes** in the deploy script or monitoring tools
- **New CrowdSec scenarios** for Loxone-specific threats
- **Documentation improvements** — including keeping the bilingual pair in sync (see below)
- **Pi compatibility fixes** for different ARM boards
- **Test coverage** for edge cases

## What We're NOT Looking For

- Generic hardening advice that duplicates CrowdSec/base Debian docs
- Breaking changes to the deployment flow without strong justification
- Features that significantly increase resource usage (the target is 512MB RAM)

## Before Submitting

1. Run `bash -n` on any modified shell scripts
2. Test on a fresh Debian 12 VM or Raspberry Pi if possible
3. Update `SECURITY.md` if the threat model changes — and `SECURITY.de.md` to match
4. Keep changes surgical — this project values simplicity over completeness

## Bilingual Documentation

Every tracked Markdown doc exists in both German and English. The two files must be kept semantically in sync — if you change one, change the other in the same PR.

Naming convention (matches the existing `README.md` / `README.en.md` precedent):

| Pattern | Language |
|---|---|
| `README.md` | German (primary — historical exception) |
| `README.en.md` | English |
| `<other>.md` | English (kept at the unsuffixed path for backwards compatibility) |
| `<other>.de.md` | German |

Every file carries a language-switcher banner at the very top:

- English file: `**Language:** [Deutsch](<file>.de.md) · English`
- German file: `**Sprache:** Deutsch · [English](<file>.md)`

If you contribute a new doc in only one language, an accompanying translation must follow before merge. Match the existing voice: terse, operator-focused, `du`-form German; direct technical-reader English. Code blocks, file paths, command names, and CVE / config-key identifiers are never translated. Anglicisms in the German prose are fine where they're the working term in this repo (`nginx`, `Reverse Proxy`, `Port-Forward`, `Cert`, `Renewal`, `AppSec`, `Bouncer`, etc.).

Translation issues / drift can be filed as their own issues and tagged `docs:translation`.

## Code Style

- 4-space indentation
- `set -euo pipefail` on all scripts
- F-strings in Python, if any
- Comments explain *why*, not *what*

## Questions?

Open an issue. Include your Miniserver firmware version, gateway specs, and what you're trying to achieve.
