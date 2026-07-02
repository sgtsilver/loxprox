# 0004. VM-only deployment substrate (LXC unsupported)

- **Status:** accepted
- **Date:** 2026-05-23

## Context

The production gateway was originally deployed as an unprivileged Proxmox LXC
container (CT 200). The defense stack (see ADR 0001) relies on several
kernel-level controls that an unprivileged container cannot apply and that fail
or silently no-op from inside one:

- kernel sysctls, including the Fragnesia / CVE-2026-46300 mitigation and the
  CIS hardening sysctls (`kernel.yama.ptrace_scope`, `fs.suid_dumpable`);
- `auditd` rule loading (config-tampering / persistence-vector watches);
- AppArmor profile enforcement for nginx;
- nftables table creation.

A silent no-op is the dangerous failure mode here: the operator believes a
control is active when it is not. `deploy.sh` had no guard, so an LXC deploy
produced a gateway that looked hardened but was missing kernel-level defenses.

Context source: `wiki/loxprox.md` (Production Runbook → "Substrate note", VM-only
docs change `04d0a51`), repo `ABOUT.md` (Show HN section: "VM-only — LXC
unsupported").

## Decision

We will make a VM the only supported deployment substrate. `deploy.sh` aborts on
LXC by default, directing the operator to provision a VM (`qm create` on
Proxmox). Deployments must run on a VM so every kernel-level control actually
takes effect rather than silently no-op'ing.

## Consequences

- **Positive:** The hardening the operator sees is the hardening that is actually
  enforced — no silent gap between intended and effective state. Aligns the
  supported substrate with the controls the project depends on.
- **Negative:** A VM has higher overhead than an LXC, and existing LXC operators
  (including the original production instance, CT 200) must migrate. That
  migration is tracked separately and not yet done.
- **Neutral:** The minimum was raised to 1 vCPU / 1 GB (2 vCPU / 2 GB
  recommended for attack headroom). Raspberry Pi 4/5 hardware remains supported
  since it runs a full kernel, not a shared-kernel container.
