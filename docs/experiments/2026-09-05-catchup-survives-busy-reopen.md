<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Catchup survives a busy reopen instead of killing the node

## Intention

Stop the bulk SQLite projection catchup from aborting a whole pass because one
`BEGIN IMMEDIATE` came back busy, and stop the periodic database-maintenance
tick from being the writer that makes that happen.

## Production observation

Read from the first hosted node's log. The node was in a restart loop: the log
records 88 occurrences of the same three-line sequence, the first at log line
1,142 and the last at line 246,905, with an abort roughly every four minutes
across the sampled window.

Each occurrence reads:

```
db: exec failed: database is locked
catchup: failed to reopen transaction after batch commit
catchup: aborting (failed=1, restore_ok=1, indexed=<N>)
```

`indexed=<N>` is different every time — the sampled values run from 254,000 to
1,950,000 — because the walk restarts from whatever the last durable batch left
behind and dies at whatever height the next collision lands on. `restore_ok=1`
in every one of the 88: nothing was corrupted and every committed batch stayed
durable. The failure was purely a scheduling one.

The sequence is:

1. A batch of the walk COMMITs cleanly. The rows are durable.
2. The walk calls `node_db_begin_immediate()` to reopen its write transaction.
3. Another writer holds the `node.db` write lock for longer than this handle's
   10 s busy timeout, so that BEGIN returns a plain `SQLITE_BUSY`. The
   maintenance scheduler's periodic wal/analyze/vacuum op is the writer that
   does it (`db_maintenance_run_now`, 15-minute default); memory-pressure
   latency at the cgroup ceiling makes it hold the lock long enough often.
4. The walk set `failed = true` and broke out unconditionally, so the pass
   aborted.

With catchup stopped, the boot watchdog correctly withholds its ping and
systemd kills the node. The node reboots, catchup resumes from the last durable
batch, and the collision recurs at a new random height. Nothing in the loop was
wrong except step 4.

## Change

Two halves of one policy.

**Catchup retries the reopen.** A plain `SQLITE_BUSY` on the post-commit
`BEGIN IMMEDIATE` is the wait-curable class — the batch is already durable and
the walk holds no read snapshot — so the walk now spends
`NODE_DB_CATCHUP_REOPEN_MAX_ATTEMPTS` attempts on it before the abort:

| Constant | Value | Meaning |
|---|---|---|
| `NODE_DB_CATCHUP_REOPEN_MAX_ATTEMPTS` | `2 * NODE_DB_CATCHUP_SNAPSHOT_MAX_RESTARTS` = 6 | BEGIN IMMEDIATE attempts per reopen |
| `NODE_DB_CATCHUP_REOPEN_MAX_RETRIES` | 5 | retries after the first attempt |
| `NODE_DB_CATCHUP_REOPEN_BACKOFF_BASE_MS` | 250 | first inter-attempt sleep |
| `NODE_DB_CATCHUP_REOPEN_BACKOFF_MAX_MS` | 2000 | backoff cap (doubling) |

Six attempts each honouring the existing 10 s busy timeout is roughly 60 s of
patience, plus at most 5.75 s of backoff. One `catchup: reopen busy, retry k/n`
WARN per retry. After exhaustion the pass keeps the unchanged fail-closed abort
and the unchanged `catchup: failed to reopen transaction after batch commit`
message, so the watchdog behaviour on a genuinely stuck lock is untouched.

The attempt budget is derived from `NODE_DB_CATCHUP_SNAPSHOT_MAX_RESTARTS`
rather than picked, so the two busy guards read as one policy: the snapshot
guard spends three whole re-walks on the class no wait can cure
(`SQLITE_BUSY_SNAPSHOT`), and this one spends twice as many cheap in-place
BEGINs on the class a wait can. A `BUSY_SNAPSHOT` seen on the reopen path is
handed straight to the restart guard instead of being retried, so each class is
answered in exactly one place.

**Maintenance yields to a running walk.** `node_db_catchup_service_active()`
is a depth counter incremented and decremented in lockstep with the catchup job
status, so the bounded whole-walk restart nests. `db_maintenance_run_now()`
consults it and skips the tick with one INFO line,
`db_maintenance: deferred, catchup active (op=… deferral=k/8)`. A skipped tick
leaves the op's last-run timestamp untouched, so the next tick still finds it
due — there is no separate rescheduling path to get wrong.

The yield is bounded at `DB_MAINT_MAX_CATCHUP_DEFERRALS` (8) consecutive
deferrals, because housekeeping that defers forever is housekeeping that never
happens: a multi-hour catchup would otherwise silence the WAL byte cap for its
whole duration. At the bound one run goes ahead and says so
(`db_maintenance: deferral bound reached, running with catchup active`), and
catchup's own reopen retry absorbs the lock it takes. Deference is a courtesy,
not a veto, and neither side can wedge the other.

The disk-full reclaim leg (`db_maintenance_checkpoint_now`) never defers:
deferring an emergency checkpoint is what fills the disk.

## Repeated evidence

Host: Linux 6.8.0-138-generic, 32 workers; local worktree, baseline
`7b0b11641`.

- `make -j8 build-only`:
  `build-only: all node objects compiled epoch=51f9bb98…`
- `make lint-fast`: see the lane report for the literal verdict line.
- `make -j8 t-fast ONLY=node_db_catchup_service`:
  `ALL TESTS PASSED — 0/1 groups failed, 0 skipped`
- `make -j8 t-fast ONLY=db_maintenance` (2 groups):
  `ALL TESTS PASSED — 0/2 groups failed, 0 skipped`
- Every other group `z23 code tests` routes for the two changed sources
  (`catchup_lifecycle_service`, `syncdiag_rpc`, `supervisor`,
  `make_lint_gates`, `sapling_ckpt_persist`, `sapling_tree`,
  `utxo_apply_stage`, `sapling_anchor_frontier_condition`, `health_rollup`):
  all `ALL TESTS PASSED`, zero skips.

Three regressions in `tests/harness/src/test_node_db_catchup_service.c` drive
the real walk over the existing five-block on-disk fixture with the batch cap
set to 2, so two mid-walk commits and two real reopens happen:

- one injected busy retries and the walk still completes with the identical
  tip, max height, and exactly one extra BEGIN attempt;
- a busy that never clears spends exactly six attempts, emits
  `catchup: reopen busy, retry 1/5` through `retry 5/5`, and still returns the
  fail-closed `catchup: aborting (failed=1, restore_ok=1, …)` — asserted
  against captured stderr, not against a paraphrase;
- `db_maintenance_run_now()` defers while catchup is active, runs on the next
  call once it ends, holds the courtesy for the whole eight-deferral budget,
  and then runs anyway.

This is a source-level result. Live acceptance still requires an
owner-approved deployment and observation of the first hosted node across at
least one maintenance interval with catchup running; the 88-occurrence loop is
the pre-change evidence, not a post-change measurement.
