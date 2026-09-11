/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tier-2 fast restart glue (boot layer).
 *
 * Keeps the verified-clean quick_check-skip wiring out of the already-large
 * boot.c: arming node_db_open's skip probe, and the post-READY background
 * quick_check that re-validates node.db when a boot took the skip.
 */

#ifndef ZCL_CONFIG_BOOT_FAST_RESTART_H
#define ZCL_CONFIG_BOOT_FAST_RESTART_H

#include "platform/storage_probe.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct shutdown_clean_binding;
struct main_state;
struct block_index;

/* Post-flat decision + install. Verifies the clean-shutdown bindings against the
 * loaded state; on a full match, installs the tip from the in-memory index (no
 * per-height disk header re-read) and returns true with *out_tip set. Records
 * the verdict for `z23 dumpstate boot`. Returns false (full boot path) on
 * any mismatch or absent binding. Call the eligibility guard (no reindex / log
 * rebuild / mint / refold / snapshot) at the caller. */
bool boot_fast_restart_try(struct main_state *ms, struct block_index **out_tip);

/* Shutdown: capture {tip, coins_best, block_index_count} into the marker facts
 * for the next boot to verify. No-op-safe; records nothing (⇒ next boot full
 * path) when there is no live tip or derivable coins frontier. Call while state
 * + progress.kv are still live, just before boot_shutdown_marker_write_clean. */
void boot_fast_restart_capture_shutdown_facts(struct main_state *ms);

/* Cheaply-derived current-boot facts, gathered AFTER the block index + coins
 * frontier have loaded, to verify against the shutdown marker's fast-restart
 * binding. Each field is an O(1)/O(log n) read — never a full recompute. */
struct boot_fast_restart_facts {
    bool     node_db_clean;       /* quick_check was skipped (P1 verified)  */
    int64_t  block_index_count;   /* g_state.map_block_index.size           */
    bool     tip_hash_found;      /* marker tip_hash present in the map      */
    int64_t  tip_height;          /* nHeight of that entry (-1 if absent)    */
    bool     coins_best_found;    /* coins frontier derivable this boot      */
    int64_t  coins_best_height;
    uint8_t  coins_best_hash[32];
};

/* Verdict: whether the verify-then-trust fast restart may be taken, plus a
 * human/operator-readable reason naming the FIRST binding that failed (or
 * "all-bindings-verified" on success). Never partial-trust: any single
 * mismatch → fast_restart=false and the full dirty-boot path runs. */
struct boot_fast_restart_verdict {
    bool fast_restart;
    char reason[96];
};

/* Pure decision (no I/O; unit-tested). `binding` is this boot's marker binding
 * (NULL or fr_valid=false ⇒ no fast restart). Fills `out`. */
void boot_fast_restart_evaluate(const struct shutdown_clean_binding *binding,
                                const struct boot_fast_restart_facts *cur,
                                struct boot_fast_restart_verdict *out);

/* Register the shutdown-marker quick_check-skip probe with node_db_open. Call
 * once, BEFORE node.db is opened (after detect_unclean has cached the marker). */
void boot_fast_restart_arm_quick_check_skip_probe(void);

/* If this boot skipped or deferred quick_check on node.db, spawn one
 * background quick_check (fresh read-only connection) so the check is still
 * eventually run. A failure is raised loudly via EV_DB_ERROR +
 * EV_OPERATOR_NEEDED. No-op when quick_check actually ran inline this boot.
 * `datadir` locates node.db. */
void boot_fast_restart_start_bg_quick_check(const char *datadir);

/* ── pacing the background quick_check on rotational storage ──────────
 *
 * The scan streams a multi-GB node.db front to back on a read-only handle.
 * On a spinning disk that is the whole device queue, and it runs head-to-head
 * with the reducer's per-batch fsync: node3 held the supervisor's tick runner
 * in uninterruptible sleep for 14 s and then 109 s while this scan was
 * reading. The scan is NOT skipped, shortened or sampled — it is cut into
 * bounded slices that share the spindle through the maintenance token the
 * other rotational writers already queue on.
 */

/* Whether `klass` paces the scan at all, expressed as the class's compiled-in
 * idle gap in milliseconds: 0 when that class does not serialise maintenance
 * (solid state and unknown, where the scan runs exactly as it always did).
 * PURE — no clock, no disk — so the decision is unit-testable by forcing each
 * class. The running scan takes the gap it actually sleeps from the resolved
 * policy (storage_pacing()->maintenance_gap_ms), which is this number unless
 * an operator overrode it. */
int64_t boot_bg_quick_check_pace_gap_ms(enum platform_storage_class klass);

/* The scan's slice state, carried through sqlite3_progress_handler's void*
 * so pacing adds no process-wide state. `calls` counts progress callbacks,
 * which is the only honest measure of how much VM work the scan did. */
struct boot_bg_quick_check_pace {
    int64_t  gap_ms;            /* idle left between slices; 0 = unpaced   */
    int64_t  slice_ms;          /* work held per token acquisition         */
    int64_t  slice_started_ms;  /* monotonic stamp of the current slice    */
    bool     token_held;        /* maintenance token currently ours        */
    uint64_t calls;             /* progress callbacks so far               */
};

/* Fill `pace` for `klass`, taking the gap from the resolved policy so the
 * work and the idle always come from the same number. slice_ms is twice
 * gap_ms: full-speed scanning for slice_ms while the token is held, then a
 * throttled trickle for gap_ms while the token is free — not idle. Each
 * progress callback during the trickle naps at most 50 ms inside
 * storage_pacing_maintenance_try_begin(), returns 0, and SQLite runs
 * another 100 VM ops before the next callback tries again, so a 250 ms gap
 * is paid as roughly five 50 ms naps with reads interleaved between them.
 * The resulting wall time is bounded at 1.5x the unpaced scan as an upper
 * bound, plus the same waits every other maintenance writer already
 * accepts.
 *
 * What the scan does to the shared token, precisely: it holds it for one
 * slice per acquisition and NEVER across the gap (the token is free for the
 * whole trickle, not held), it never queues for a token another writer
 * owns, and it does not try to retake the token until its own gap has
 * elapsed — so a maintenance writer blocked in
 * storage_pacing_maintenance_begin() gets the token at the next slice
 * boundary, at most slice_ms away. */
void boot_bg_quick_check_pace_init(struct boot_bg_quick_check_pace *pace,
                                   enum platform_storage_class klass);

/* Three-way result of one quick_check scan. Only FAILED is an integrity
 * finding (the row came back and said something other than "ok"); OK and
 * INCOMPLETE are both "no finding" but must not print the same word — OK
 * means the row said ok, INCOMPLETE means no row ever came back (shutdown
 * interrupted the VM, or prepare/step failed outright). */
enum boot_bg_quick_check_outcome {
    BOOT_BG_QUICK_CHECK_OK = 0,
    BOOT_BG_QUICK_CHECK_FAILED,
    BOOT_BG_QUICK_CHECK_INCOMPLETE,
};

#ifdef ZCL_TESTING
/* Execute a real SQLite VM under the production cancellation hook. The caller
 * requests registry shutdown first; true proves SQLite returned INTERRUPT. */
bool boot_fast_restart_bg_quick_check_cancel_for_test(void);

/* The PRODUCTION progress handler, so the pacing tests drive the same code
 * SQLite calls. `arg` is a struct boot_bg_quick_check_pace * (NULL is the
 * unpaced cancellation-only behaviour). Returns 1 to abort the VM. */
int boot_bg_quick_check_progress_for_test(void *arg);

/* Run the real "PRAGMA quick_check(1)" against `path` on a read-only handle
 * under the production progress handler, paced for the currently resolved
 * storage class. Returns whether SQLite answered "ok"; `pace` reports the
 * slice state the scan finished with. */
bool boot_fast_restart_bg_quick_check_scan_for_test(
    const char *path, struct boot_bg_quick_check_pace *pace);

/* The exact word the completion line in boot_bg_quick_check_entry() prints
 * for `outcome` — "ok" / "FAILED" / "did not complete" — so tests can pin
 * the three-way mapping without re-deriving it. */
const char *boot_bg_quick_check_outcome_str_for_test(
    enum boot_bg_quick_check_outcome outcome);
#endif

#ifdef __cplusplus
}
#endif

#endif /* ZCL_CONFIG_BOOT_FAST_RESTART_H */
