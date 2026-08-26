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

#ifdef ZCL_TESTING
/* Execute a real SQLite VM under the production cancellation hook. The caller
 * requests registry shutdown first; true proves SQLite returned INTERRUPT. */
bool boot_fast_restart_bg_quick_check_cancel_for_test(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* ZCL_CONFIG_BOOT_FAST_RESTART_H */
