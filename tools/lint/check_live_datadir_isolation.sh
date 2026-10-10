#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_live_datadir_isolation.sh — nothing under test, and no command an
# agent is told to copy, may be aimed at the OPERATOR'S LIVE NODE.
#
# ── THE TWO BUGS THIS EXISTS TO CATCH, BOTH REPRODUCED ─────────────────────
#
# (1) A GREEN TEST THAT WAS GREEN BECAUSE OF THE LIVE NODE. On 2026-07-30 the
#     first hosted-CI run of the full suite failed 6 of 842 groups that are
#     green here. `test_chain_integrity_failed_condition` was one: it never
#     called SetDataDir, so GetDataDir() resolved to the default
#     ~/.zclassic-c23, and on this host — which runs a node there —
#     chain_restore_quarantine_synthetic_tip() pread() the LIVE
#     blocks/blk00000.dat and the assertion passed off real, unrelated block
#     bytes. On a runner with no node the same test failed honestly. THIS HOST
#     STRUCTURALLY CANNOT FIND THAT CLASS BY RUNNING TESTS — a passing suite
#     is exactly the symptom. It can only be found by reading the source, which
#     is what this gate does.
#
# (2) A "READ" COMMAND THAT WROTE TO THE LIVE DATADIR. `z23 app service
#     access --input='{"service":"reference"}'` is declared READ / PUBLIC /
#     IDEMPOTENT and its handler called node_db_open() — the boot ceremony:
#     OPEN_CREATE, quick_check with a rename-aside on failure, create_schema,
#     migrate, then two DELETEs. `datadir` falls back to the process datadir
#     when the caller passes none, so a bare invocation did all of that to the
#     operator's live node.db. Six leaves had it. An auditor tripped it while
#     being deliberately careful, because THE DOCUMENTED EXAMPLE OMITS THE
#     DATADIR — docs/SERVICES.md still says `z23 app service access
#     <name>`. The property is enforced at runtime by
#     test_read_leaf_no_datadir_write; what nothing enforced is that the
#     examples an agent copies name a throwaway datadir.
#
# ── THE THREE PRONGS ───────────────────────────────────────────────────────
#
# A. LIVE-DATADIR PATH CONSTRUCTED IN A TEST (ratchet, per-file count).
#    A test source that builds `<something>/.zclassic` or
#    `<something>/.zclassic-c23` — the two real datadir names, EXACTLY, with
#    no suffix. A suffixed sibling (`-dev`, `-test`, `-COPY-…`) is a
#    deliberately distinct scratch directory and is NOT counted; the exact
#    names are the operator's live ones.
#
#    HONEST LIMIT, stated because it decides how to read the number: this is
#    a textual test, and roughly half the current rows build the path from a
#    SANDBOX home (a mkdtemp result, a `$root/gate-home`) rather than the real
#    $HOME, so they are harmless today. Distinguishing them needs intra-file
#    dataflow — the same identifier `home` is the sandbox in one file and
#    `getenv("HOME")` in the next — and a gate that guesses at that would be
#    worse than one that counts honestly. Every current row is therefore
#    classified BY HAND in the baseline with its reason, and the ratchet is
#    count-only: the property enforced is "no NEW test learns to spell the
#    live datadir", which is cheap, exact, and the thing that actually
#    regresses.
#
# B. A TEST THAT RESOLVES THE DATADIR WITHOUT PINNING IT (HARD, zero debt).
#    A test source that names GetDataDir()/GetDefaultDataDir() but never calls
#    SetDataDir() is bug (1) in its directly-visible form. Zero files do this
#    today, so this prong is HARD with no baseline — the first one to appear
#    fails the build.
#
#    HONEST LIMIT: bug (1)'s actual instance is NOT visible to this prong.
#    test_chain_integrity_failed_condition never wrote `GetDataDir` itself; it
#    called condition_engine_tick(), which reached GetDataDir several frames
#    down. Catching that needs a whole-program call graph, not a grep. Prong B
#    catches the direct spelling and says so; it is a floor, not the class.
#
# C. A COPYABLE INVOCATION OF A datadir-TAKING LEAF WITH NO --datadir
#    (ratchet, per-file count). The leaf set is DERIVED from argument 10
#    (`input_keys`) of the leaf macros in engine/composition/commands/*.def,
#    never from a hand list, so a leaf that gains a `datadir` input is
#    covered the day it lands. Scanned: tracked *.md (where an agent copies
#    its commands from) and tracked *.sh with comments stripped. A hit is a
#    line that invokes such a leaf and carries no `-datadir=`/`--datadir=`
#    and no `"datadir"` JSON key: exactly the shape that silently falls back
#    to the operator's live node.
#
#    NOT GATED, and named here so the decision is visible rather than
#    invisible: ~20 further sites pass a datadir whose VALUE is the live path
#    (`-datadir=/home/you/.zclassic-c23`, `-datadir="$HOME/.zclassic-c23"`),
#    mostly generated API_REFERENCE rows mirroring .def `example` fields, plus
#    node-start command lines that are not native-command invocations at all
#    and are legitimately aimed at a real node. Gating those needs a
#    per-example judgement about whether the doc is for an operator or for an
#    agent; it is a real follow-up, not something to fold in silently here.
#
# ── MODES ──────────────────────────────────────────────────────────────────
# ZCL_LINT_MODE: FAIL (default) | WARN | UPDATE (rewrite the baselines).
# Ratchet ceilings are defaults in tools/lint/lintc/gate_live_datadir_isolation.c, so raising one is a source diff
# in review, never a quiet data-file edit. They may only go down.
#
# NO PER-LINE ESCAPE HATCH EXISTS, deliberately. The one thing an `# ok`
# marker would be used for is the case that needs a human to look.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
exec "$ROOT/build/bin/z23-lint" check-live-datadir-isolation "$@"
