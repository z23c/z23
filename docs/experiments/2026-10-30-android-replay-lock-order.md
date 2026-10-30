<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Android replay lock order

Date: 2026-10-30. Source base: `a185072351`. Device: Pixel 3, Android 12,
arm64 node `libz23node.so` from the same build as `build/bin/z23.debug`.

## Observation

The phone app showed "Node starting" while the node process ran. Every
authenticated RPC call, including `getblockcount`, returned no bytes within
30 s. The RPC listener had accepted 38 connections, and the node process held
all of their descriptors, but no worker answered them.

Thread states were read from `/proc/<pid>/task/*/syscall`. Two global
recursive mutexes each had a queue of waiters. Bionic stores a recursive
mutex's owner thread in the word after its state:

| Mutex | Symbol (`z23.debug`) | Owner | Owner waits on |
|---|---|---|---|
| A | `progress_store.c` `g_tx_lock` | `zcl_p2p_ingest` | B |
| B | `boot.c` `g_state` offset 0, `main_state.cs_main` | `zcl_self_heal` | A |

The RPC workers, the P2P message handler and the bundle exporter waited on
A. Background validation, gap fill and metrics waited on B. Block intake had
stopped.

## Stacks

Return addresses were read from each thread's stack through
`/proc/<pid>/mem` and resolved against `z23.debug`.

- `zcl_p2p_ingest`: `msg_block_intake_worker` → `reducer_kick` →
  `reducer_drain_core` → `tip_finalize_stage_drain`. The stage batch holds
  the progress store, then `tip_finalize_reconcile_block` takes `cs_main`.
- `zcl_self_heal`: `stage_reducer_frontier_try_stale_script_replay` →
  `maybe_replay_stale_script_via`. It held `cs_main` and blocked in
  `progress_store_tx_lock`.

## Cause

The tree nests both lock orders: the reducer drain holds the progress store
and takes `cs_main`, while boot-window `cs_main` holders read the progress
store. The documented rule in `jobs/stage_repair.h` is that a repair must
never wait for one of these locks while owning the other. The stale-script
replay and its created-outputs backfill acquired `cs_main` with a blocking
lock and then blocked on the progress store, which closes the cycle against
the steady-state drain.

## Change

`reducer_frontier_replay_lock` takes the progress store, then tries
`cs_main`. When `cs_main` is busy, it releases the progress store, sleeps
1 ms and retries, so the replay never waits while owning either lock. The
stale-script replay holds both locks over the snapshot and the kernel
transaction, then releases both before the best-effort created-outputs
transaction. The backfill uses the same acquisition.
<!-- claim: symbol-present reducer_frontier_replay_lock engine/reducer/jobs/src/reducer_frontier_replay_tx.c # progress then main, never waiting while owning either -->
<!-- claim: symbol-present maybe_replay_stale_script_via engine/reducer/jobs/src/reducer_frontier_replay.c # TX1 under both locks, TX2 after release -->

## Proof

`reducer_frontier_reconcile_light` runs the readable stale-script replay
twice:

- With `cs_main` held by the test thread. The worker must reach a second
  acquisition attempt, which proves it released the progress store after
  finding `cs_main` busy, and the progress store must be free at that point.
- With the progress store claimed by the test thread while the worker is
  parked at its first attempt, as the reducer drain claims it. The worker
  must not own `cs_main` there. While still holding the progress store, the
  test thread then takes `cs_main` repeatedly for 200 ms after the worker
  resumes, which is tip finalization's order.

`stage_rederive_range` proves the same busy-main release for the
created-outputs backfill.

Both groups pass with the change (0 of 2 failed, 0 skipped). With the
previous replay code and the new tests, both groups fail: the main-held cycle
never reaches a second attempt, the progress-held cycle finds `cs_main` owned
by the waiting worker, and the backfill cycle never reaches a second attempt.
<!-- claim: symbol-present rfrl_main_stays_free tests/harness/src/test_reducer_frontier_reconcile_light.c # tip-finalization order window -->
<!-- claim: symbol-present sr_release_parked tests/harness/src/test_stage_rederive_range.c # backfill busy-main release -->

## Diagnosis recipe

A wedged node with a stripped binary can be read without a debugger:

1. `cut -d' ' -f2,3,4 /proc/<pid>/task/*/syscall` groups futex waiters by
   address; untimed waits show a null timeout argument.
2. For a bionic recursive mutex, the state word reads `0x4002`/`0x4006` and
   the next 32-bit word is the owner thread id
   (`dd if=/proc/<pid>/mem bs=1 skip=<addr> count=8`).
3. Subtract the load base of `libz23node.so` from `/proc/<pid>/maps` and
   resolve with `llvm-nm -n build/bin/z23.debug`.
4. Dump 64 KiB above each owner's stack pointer (field 8 of `syscall`), keep
   words inside the text mapping, and resolve them with
   `llvm-symbolizer --obj=build/bin/z23.debug`.
<!-- claim: symbol-present rfrl_run_lock_cycle tests/harness/src/test_reducer_frontier_reconcile_light.c # both holder orders -->
