#!/usr/bin/env bash
# Lint gate E13 — consensus-parity guard (HARD).
#
# zclassic23 MUST stay BIT-FOR-BIT consensus-compatible with zclassicd
# (the canonical C++ ZClassic daemon). The non-negotiable rule, stated in
# docs/CONSENSUS_PARITY_DOCTRINE.md:
#
#   Equihash (N,K) and EVERY network-upgrade activation resolve from a
#   STATIC, height-keyed table only — never from miner signaling, a
#   versionbits/BIP9/BIP8 deployment state machine, or any dynamic
#   per-height parameter override.
#
# zclassicd has no versionbits / signaling apparatus: it activates all
# upgrades purely by fixed height (nHeight >= nActivationHeight) and reads
# Equihash (N,K) from EquihashUpgradeInfo[CurrentEpoch(height)]. Introducing
# a miner-signaled override (the PR #6 "Equihash 200,9 sidegrade" class)
# would make nodes disagree on which (N,K) / which rules are valid at a
# height and FORK the chain away from zclassicd.
#
# ── SCAN CLASS 0 — forbidden mechanism tokens (original gate) ──────────────
# Fails if any such mechanism token appears in the consensus source surface.
# False positive? Add `// consensus-parity-ok:<reason>` to the line. The
# reason must explain why this is NOT a divergence from zclassicd. This is
# the ONLY escape mechanism this gate has; classes 1/2 below reuse it for
# nothing new — they get their own registry instead (see below).
#
# ── SCAN CLASS 1 — future-height literal in a height comparison ───────────
# ── SCAN CLASS 2 — wall-clock read in the consensus surface ───────────────
# Added after an adversarial review planted
#     if (n_height >= 3400000) halvings--;
# two lines below a legitimate height gate in core/consensus/src/subsidy.c.
# It is a bare integer comparison: it matches NONE of the class-0 forbidden
# tokens (no versionbits/BIP9/signaling identifier anywhere near it), so the
# class-0 scan is structurally blind to it. The bomb is set for a height
# ~170k blocks in the future, so deterministic rebuild, full-chain replay,
# and historical UTXO-root agreement all pass TODAY — the divergence only
# fires once the chain reaches the planted height.
#
# Class 1 catches the shape of that bomb directly: any integer literal
# >= HEIGHT_LITERAL_FLOOR (3,100,000 — the last baked mainnet checkpoint,
# i.e. strictly in the FUTURE relative to every height this codebase has
# ever validated) sitting next to a relational operator on a line that also
# mentions "height" — the exact shape of `n_height >= 3400000`.
#
# Class 2 catches the sibling trick: smuggling a non-deterministic,
# non-height-keyed control input (the wall clock) into the same surface.
# time(NULL)/GetTime()/GetAdjustedTime()/gettimeofday()/clock_gettime() are
# themselves legitimate in a few known places (the standard "block timestamp
# too far in the future" DoS check, the initial-block-download heuristic, a
# progress-log speed metric, and a miner setting its own candidate's nTime) —
# none of those are a divergence from zclassicd, which has the identical
# calls. But an attacker could just as easily hide
#     if (n_height >= 3400000 || time(NULL) > 1234567890) halvings--;
# and every wall-clock read in this surface deserves the same forced,
# reviewed, one-line-per-site accounting that class-0 already gives the
# versionbits family.
#
# Unlike class 0, classes 1/2 are cleared ONLY by an entry in
# tools/lint/FLAG_DAYS.txt (format documented at the top of that file), not
# by the `consensus-parity-ok:` comment: the comment marks a line the GATE
# AUTHOR could edit; classes 1/2 exist specifically to be checkable by
# someone who does NOT own the flagged file (this rollout registered four
# pre-existing wall-clock sites in core/modules/validation and core/modules/mining without
# touching either directory). A matching FLAG_DAYS.txt row still doesn't
# stop a hostile publisher who edits the registry alongside the bomb in the
# same commit — nothing textual can. What it buys is that the edit is
# VISIBLE and DIFFABLE: a weak/light node (or a human) that only checks
# "did FLAG_DAYS.txt change, and does the new row's rationale hold up" gets
# a small, targeted diff instead of having to re-audit the whole consensus
# surface. See docs/CONSENSUS_PARITY_DOCTRINE.md for the full limitations
# list — this is a textual heuristic, not a C parser, and it does not catch
# every way to hide a future-height or wall-clock dependency (named
# constants, digit-separated literals, hex-encoded heights, and macro
# indirection all evade it; see the doctrine doc).
#
# Run `./tools/scripts/check_consensus_parity.sh --selftest` to prove both
# directions: a planted, unregistered violation FAILS; the same violation,
# registered, PASSES.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-consensus-parity "$@"
