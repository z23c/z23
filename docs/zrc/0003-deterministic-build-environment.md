<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# 0003: Deterministic build environment

| Field | Value |
|---|---|
| ZRC | 0003 |
| Title | Deterministic build environment |
| Status | draft |
| Owner | orchestrator |
| Created | 2026-09-05 |
| Supersedes | none |

## Problem

The owner wants every Z23 node to also host a deterministic C23 build
environment, on every platform it runs on, and to be able to build and run
C23 code without that work touching the rest of the machine. For that to be
useful across a fleet of independently owned nodes, two nodes with the same
toolchain and the same sources need to be able to prove they built the same
thing — not just claim it.

Today a build's identity is derived by hashing a generated build script
rather than the toolchain itself. That script bakes in things that differ
between machines for no good reason, such as the absolute path of the
checkout and the raw value of `PATH`. Two boxes with an identical toolchain
and identical sources therefore get different identity roots, so a receipt
cannot answer the question that matters: did these two builds actually use
the same compiler.

## Design

Key every build receipt's identity by a toolchain capsule that is
content-derived rather than path-derived, and make that capsule the one
source of truth for every place a build's identity is checked.

- **Toolchain capsule.** Content-hash the compiler driver and backend bytes,
  the assembler by its version string, the sysroot and ABI, and a target
  probe. No absolute paths, no timestamps, go into the capsule.
- **Path-neutral flags and build graph.** Derive the flags identity and the
  build-graph identity from text that has already had the checkout's
  absolute path rewritten away, the same rewrite the build already applies
  to make its own output byte-identical regardless of where the checkout
  lives, so two checkouts of the same sources at different paths hash equal.
- **Environment identity from what resolves the compiler, not from raw
  `PATH`.** Derive the environment identity from the variables that actually
  change which compiler and flags get used (things like `CC`, `CFLAGS`,
  `LDFLAGS`, and the project's own build knobs) and from the resolved
  compiler's own capsule, never from the literal text of `PATH`. Reordering
  `PATH` without changing which compiler it resolves to changes nothing;
  resolving a genuinely different compiler changes the identity.
- **Old receipts are refused, not silently compared.** A receipt produced
  under the previous, path-derived identity scheme is refused with a typed
  reason when it is compared against a capsule-keyed receipt, rather than
  treated as comparable.
- **One capture function.** Any warm-start or donor identity used elsewhere
  to skip redundant work calls the same capsule-capture function the receipt
  uses, so the two can never disagree about what "the same toolchain" means.
- **Two-directory byte identity stays a standing gate.** The project already
  proves reproducibility by building the same sources in two different build
  directories and comparing the output byte for byte (`make repro-verify`,
  and the three-build variant `make repro-build`). That comparison remains a
  standing gate rather than a one-time measurement, and its scope grows to
  cover vendored dependencies (`vendor/lib`) as its own follow-on.
- **Capsule on the wire.** Once receipts carry a portable identity, a live
  node can offer its toolchain capsule to a peer so the peer can decide
  whether to trust a build result without re-running it itself. This is a
  separate proposal built on the capsule identity defined here.
- **Sandboxed build-and-run leaf per platform.** The owner's directive that
  every node "run a VM for C23 code" resolves, at the smallest correct scope,
  to a sandboxed build-and-run leaf on each platform the node runs: Linux
  confinement (Landlock and seccomp), macOS confinement (Seatbelt), and
  Windows confinement (a Job Object) in place of refusing the platform
  outright. A full general-purpose virtual machine is a larger and slower
  answer than the guarantee actually needed — that untrusted C23 source can
  be built and run without touching anything outside its declared inputs and
  outputs — so this proposal treats the confined build-and-run leaf as the
  target, not a VM. This leaf is its own follow-on proposal, built on the
  capsule identity defined here so a sandboxed build still produces a
  receipt comparable across nodes.

## Acceptance

- Capturing the toolchain capsule and the receipt's compiler, flags, and
  build-graph identity roots from the same sources checked out at two
  different absolute paths on one box yields identical roots; this
  comparison, run and its equal roots pasted into the record, is this
  design's own acceptance evidence.
- Changing a build flag changes the flags identity only, and nothing else.
- Reordering `PATH` without changing which compiler it resolves to changes
  no identity root; pointing `PATH` at a genuinely different compiler
  changes the compiler identity root.
- A receipt produced under the previous identity scheme is refused, by name,
  when compared against a capsule-keyed receipt, instead of being silently
  treated as equivalent or silently rejected without a reason.
- `make repro-verify` continues to pass as a standing gate, proving
  byte-identical output across two build directories.

## Out of scope

Putting the capsule on the wire for live peer-to-peer trust decisions, the
per-platform sandboxed build-and-run leaf's implementation, extending the
two-directory byte-identity gate to `vendor/lib`, and any general-purpose
virtual machine. Each is its own follow-on ZRC or lane.

## Landing

Not yet landed.

## Discussion

Board rows carrying `zrc-0003` (see
[`../agent/NATIVE_CHANNEL.md`](../agent/NATIVE_CHANNEL.md)), until
[`0004-wiki-daily-board-public-page.md`](0004-wiki-daily-board-public-page.md)
lands and the wiki page for this ZRC becomes the index.
