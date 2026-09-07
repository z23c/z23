#!/usr/bin/env bash
# Architecture gate — a dumpstate view never blocks behind the reducer.
#
# Program O0/O1: the diagnostic snapshot plane. A `*_dump_state_json` function
# runs on native/RPC threads while the reducer fold owns progress_store_tx_lock
# around bulk folds. A dumper that takes that lock BLOCKING — or runs a
# SELECT COUNT(*) over a multi-million-row stage log under it — queues the RPC
# worker behind the fold, so `dumpstate` / `status` disappears exactly when the
# node is busiest (the "RPC-dark under load" defect class). This gate proves no
# dumper reaches for a blocking primitive.
#
# WHAT IT SCANS: only the BODY of each `*_dump_state_json(...)` **or**
# `*_dump_state_fill(...)` function (from its signature down to the column-0 `}`
# that closes it — the project's function style). A blocking primitive used by a
# NON-dumper function in the same TU (a stage step, a service's background work)
# is legitimate and NOT flagged.
#
# WHY `_fill` IS IN SCOPE. The table-driven telemetry layer
# (util/telemetry_render.h) splits a dumper in two: a generic renderer emits the
# JSON, and a per-domain provider `<domain>_dump_state_fill()` collects the
# values into a typed snapshot. The collector is where the reads live, so it is
# where progress_store_tx_lock() and COUNT(*) would land — and it runs on the
# SAME RPC/native thread the old dumper ran on. Scanning only `_dump_state_json`
# would report PASS on a controller that does nothing while the risky code runs
# one call deeper. Both spellings are therefore scanned identically.
#
# THE MANIFEST (tools/scripts/dumper_blocking_primitives.tsv): rows of
# "<primitive>\t<ERE>". A dumper body that matches any ERE is a violation unless
# its (primitive, path) pair is in the ratchet baseline.
#
# THE BASELINE (tools/scripts/dumper_blocking_baseline.tsv): rows of
# "<primitive>\t<path>" for reviewed-but-not-yet-migrated dumpers. Goal: EMPTY.
# As each is migrated onto the published snapshot plane, delete its baseline row;
# a baseline row whose dumper no longer matches fails as stale (shrink it).
#
# Allowed (never flagged): progress_store_tx_trylock() — the non-blocking
# acquire a dumper uses to emit {"snapshot_status":"progress_store_busy"} for
# cold single-row detail; and the O(1) published counters (stage_log_rows_*,
# stage_cursor_rows_value, refold_from_anchor_target_cached).
exec "$(dirname "$0")/../../build/bin/z23-lint" check-dumper-never-blocks "$@"
