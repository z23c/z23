/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * backpressure watchdog — caps RAM blow-up under a tip-stall.
 *
 * A regression in update_tip that traps the chain at a fixed height while
 * new blocks keep arriving but chain_tip never advances lets download
 * buffers + connect-block scratch climb to GB-scale RSS before the cgroup
 * OOM path fires. This watchdog is the diagnostic
 * backstop that turns a tip-stall regression into a bounded
 * EV_BACKPRESSURE_* event stream instead of an OOM.
 *
 * State machine:
 *   INACTIVE → ACTIVE  when (now - last_tip_advance > 60s)
 *                       AND  download_queue_bytes > 256 MiB
 *                       AND  the re-arm latch is set (see below)
 *   ACTIVE → INACTIVE  when chain_tip advances OR 120s have elapsed
 *
 * Re-arm hysteresis latch: entering ACTIVE consumes a latch that is
 * only re-armed once the byte estimate has been observed below
 * DOWNLOAD_QUEUE_LOW_WATER (= HIGH_WATER/2) while INACTIVE. This
 * stops the observed active→cooldown→active flapping on an
 * unchanged backlog: after a cooldown exit the watchdog will not
 * re-enter until the backlog has genuinely halved and re-grown.
 *
 * In ACTIVE we drain the download manager's queue + in-flight set
 * (peers stop being asked for new blocks), and inv/block messages
 * arriving from any peer are dropped after parse but before
 * dispatch. Drops emit EV_BACKPRESSURE_REJECT with the peer id but
 * do NOT bump ban-score — peers aren't misbehaving.
 */

#ifndef ZCL_NET_TIP_WATCHDOG_H
#define ZCL_NET_TIP_WATCHDOG_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* Tuning constants. Compile-time only in this patch — RPC-tunable
 * policy is a separate row. Numbers chosen against the observed shape:
 * a stuck tip held for ~10 minutes accumulates 6 GB of
 * residency; 256 MiB is ~25% of that, well under the cgroup high
 * watermark and large enough that normal IBD bursts don't trip. */
#define TIP_STALL_THRESHOLD_SEC      60
#define DOWNLOAD_QUEUE_HIGH_WATER    (256UL * 1024 * 1024)
#define BACKPRESSURE_REJECT_SEC      120

/* Re-entry low-water mark for the re-arm hysteresis latch: after the
 * watchdog leaves ACTIVE, it may not enter again until the byte
 * estimate has been observed below this while INACTIVE. */
#define DOWNLOAD_QUEUE_LOW_WATER     (DOWNLOAD_QUEUE_HIGH_WATER / 2)

/* Per-slot footprint used to estimate download_queue_bytes:
 *
 *   estimate = in_flight * BACKPRESSURE_AVG_BLOCK_BYTES
 *            + queued    * DL_QUEUED_ENTRY_BYTES
 *
 * in_flight slots have a getdata outstanding — each may be paid back
 * with a full block body, so they're charged a worst-case-leaning
 * average body size. queued entries are hash + bookkeeping ONLY (no
 * bytes have been solicited yet), so they're charged their honest
 * in-memory size, ~64 B. Charging queued entries at body size caused
 * the observed false trigger: 3,066 queued entries (~196 KB real)
 * were "estimated" as 6 GB. At 64 B, queued alone can never trip the
 * 256 MiB high water (it would take ~4M entries).
 *
 * Reachability arithmetic (the trigger must be structurally reachable
 * with margin in BOTH in-flight regimes — strict `>` compare):
 *   non-IBD: DL_MAX_IN_FLIGHT_TOTAL     = 1024 slots
 *            1024 * 512 KiB = 512 MiB > 256 MiB HIGH_WATER
 *            → trips at  >512 in-flight slots (2x headroom)
 *   IBD:     DL_MAX_IN_FLIGHT_TOTAL_IBD = 4096 slots
 *            4096 * 512 KiB = 2 GiB   > 256 MiB HIGH_WATER
 *            → trips at the same >512 slots
 * 512 KiB is deliberate: the consensus 2 MiB upper bound would trip
 * at >128 slots (normal burst territory → false triggers), while
 * 256 KiB would make the non-IBD cap exactly equal the high water
 * (1024 * 256 KiB == 256 MiB, strict `>` never fires — dead code).
 * >512 outstanding worst-case bodies is a genuine 100 MB–1 GB
 * exposure band — the regime this backstop exists for. */
#define BACKPRESSURE_AVG_BLOCK_BYTES (512UL * 1024)
#define DL_QUEUED_ENTRY_BYTES        (64UL)

/* Initialize the watchdog. Idempotent; seeds the stall timer to
 * "now" so a fresh process doesn't fire before the chain has had
 * a chance to advance. */
void tip_watchdog_init(void);

/* Note that the chain tip has advanced. Resets the stall timer.
 * Driven by EV_BLOCK_CONNECTED / EV_TIP_UPDATED observers wired in
 * msg_processor_init. The height value is recorded for diagnostics
 * only — only the timestamp matters for stall detection. */
void tip_watchdog_note_tip_advance(int height);

/* Periodic state-machine tick. Cheap (a few atomics + one hash-table
 * stat read). Call from the msgprocessor loops on every iteration.
 * Returns the post-tick value of the active flag. */
bool tip_watchdog_tick(void);

/* Lock-free read of the active flag. */
bool tip_watchdog_is_active(void);

/* Pre-dispatch hook for inv/block messages.
 *
 * Returns true if the caller must drop the message (already emitted
 * EV_BACKPRESSURE_REJECT). Returns false for any non-block command
 * or when the watchdog is INACTIVE — callers can blanket-call it for
 * every message without checking the active flag themselves. Does
 * NOT touch peer ban-score. */
bool tip_watchdog_should_reject(uint32_t peer_id, const char *cmd);

/* ── Test hooks ──────────────────────────────────────────────
 * Drive the watchdog with an explicit clock and queue size.  Not
 * intended for production callers — used by test_net.c cases. */

/* Resets all state including the re-arm latch (back to armed) and
 * clears every test override. */
void tip_watchdog_test_reset(void);
void tip_watchdog_test_set_now_ns(int64_t now_ns);
/* Overrides the FINAL byte estimate (skips the in_flight/queued
 * formula entirely). Takes precedence over the counts override. */
void tip_watchdog_test_set_queue_bytes(size_t bytes);
/* Overrides the dl_get_stats counts feeding the estimate formula, so
 * tests exercise the real in_flight/queued accounting (reachability
 * at the 1024/4096 caps, queued-only never trips). -1 = unset. */
void tip_watchdog_test_set_dl_counts(int64_t in_flight, int64_t queued);
void tip_watchdog_test_inject_tip_advance(int height, int64_t when_ns);

#endif /* ZCL_NET_TIP_WATCHDOG_H */
