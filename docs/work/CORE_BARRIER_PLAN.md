<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Core barrier: core/ holds exactly the consensus code

Goal ([Ambition](../THE_Z23_WAY.md#ambition)): anyone can read `core/` and know
that every line decides what is valid, with a one-way barrier that a lint gate
enforces. Owner direction 2026-11-26: move non-consensus code out of `core/`.
Decision record: [ADR-0002](../adr/0002-sealed-consensus-core.md); the seal
ritual is in `core/UNSEAL.md`. Nothing here changes a consensus rule.

## What is in core/ today (measured 2026-11-26, 580 tracked files)

A read-only map by nine classifiers (files read, includes and symbols
checked, an architect pass over the result):

| Class | Files | Lines | Share |
|---|---|---|---|
| Consensus (C): validity, parameters, proof and script rules | 116 | 33,743 | 20% |
| Shared primitive (S): hashing, arithmetic, base serialization | 87 | 15,610 | 9% |
| Non-consensus (N): networking, sync, mempool, mining, wallet-side Sapling | 377 | 117,879 | 71% |

The `net` module alone is 245 files and 85,000 lines, 51% of core. Five whole
modules (net, noise, sync, mining, policy) are 272 files, 55% of the lines, and
no C or S file depends on them. 162 of the 224 core files touched since 10-26
were N. About 230 of 317 unseal log entries concern non-consensus areas
(keyword match, approximate). Moves need no `#include` edits because modules
are found by directory name on the include path; the cost is literal paths in
the Makefile, 17 lint baselines, tests and docs.

## The barrier rule (for the lint gate)

Every `#include` in a file under `core/` must resolve, by file location, to a
file under `core/`, a libc or OS header, or a header on a sealed allowlist; and
every undefined symbol in a `core/` object must be defined by a `core/` object
or by code behind an allowed header. Today 831 includes in `core/` resolve
outside it: 83 from C files, 45 from S files, 703 from N files; kept files
reach N files through 8 includes and 19 symbol references.

## What blocks a clean cut (all fixable by moving functions unchanged)

1. Sapling verify code shares files with wallet note encryption and proving.
2. The verifying-key loader shares a file with the proving-key loader.
3. Three dead includes (mempool headers) in validation.
4. Ordering code calls engine hooks directly (a hook struct set at boot fixes it).
5. Consensus ECDSA parse and verify lives in the wallet (move it into core).
6. Validity code emits telemetry (one observer port with a null default).
7. Kept files call storage directly (a reader port implemented in engine).
8. A few C files do file I/O and JSON (move the persistence and listing out).

## Waves, smallest and safest first

| Wave | What | Files | Needs unseal |
|---|---|---|---|
| W0 | Barrier lint gate over all of core/, RATCHET mode, baseline of today's edges | 4 | no |
| W1 | Move whole modules net, noise, sync, mining, policy out with `git mv` | 272 | yes |
| W2 | Move N leaves of mixed modules (validation, crypto, chain, script, wallet Sapling) | 73 | yes |
| W3 | Validation cuts: delete dead includes, hook struct, move mempool group | 21 | yes |
| W4 | Split Sapling verify from prove, move prover files to the wallet | 20 | yes |
| W5 | Pull consensus ECDSA in, add ports, move allowlist into the seal, gate HARD | 20 | yes |

Proof for every move: renames only in `git diff -M100%`; every remaining
per-file digest in `core/MANIFEST.sha3` identical, sealed section digests
unchanged; `check-core-seal`, `check-consensus-parity`, the immutable-history
canaries, `custody-check` for wallet moves, and full lint once in the land proof.
Moved bytes change `__FILE__` strings, so byte-identical binaries are not the
proof; the digests and the parity tests are.

## Risks

- Code leaving the seal still steers the chain (state offers, header fetch,
  FlyClient, fast-sync coins). Each unseal reason names it; the new engine paths
  join the highest-proof class.
- Dependencies includes do not show (extern declarations, weak symbols): the
  gate adds a symbol pass over the object files.
- Path-keyed baselines and mirrors go stale: one scripted rewrite per wave.
- W1 touches 272 files while others edit them: claim the paths, freeze briefly,
  land as one slice, rebase other lanes with rename detection.
- W3 to W5 edit sealed files: functions move unchanged, a non-author reviews,
  parity tests run.

## Decision needed from the owner

W1 and later are sealed-core changes (the ritual in `core/UNSEAL.md`) and one
large rename slice that touches every open lane. W0 needs neither and starts
now. The full machine-readable map is kept with the lane notes, not in git.
