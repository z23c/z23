/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_crashonly — crash-only recovery decisions for boot's post-restore
 * integrity gate, factored out of the boot orchestrator (boot.c) so it stays
 * lean. When a derived tip is installed above the validated on-disk index
 * extent, the cure is to RE-DERIVE the UTXO set via -reindex-chainstate (rewind
 * to the consistent target + replay from blocks/), not to FATAL or surgically
 * repair. See storage/boot_auto_reindex.h for the durable, bounded request.
 */

#ifndef ZCL_CONFIG_BOOT_CRASHONLY_H
#define ZCL_CONFIG_BOOT_CRASHONLY_H

#include <stdbool.h>

/* Consume a pending self-rebuild request (logs when it does). Returns true if
 * the next boot should run -reindex-chainstate. */
bool boot_crashonly_consume_reindex_request(const char *datadir);

/* Clear a stale tip-height reindex request when durable coins authority
 * already covers the request anchor. Covered means: coins-best strictly ABOVE
 * the anchor (the live reducer moved on), OR coins-best exactly AT the anchor
 * AND HASH-VERIFIED — a hash-verified coins-best at the wedge tip proves the
 * transparent UTXO set is intact through it, so consuming reindex-chainstate
 * would only WIPE a healthy near-tip coins set and burn an O(chain) rebuild
 * without fixing a downstream (e.g. shielded-anchor) wedge. Coins-best at the
 * anchor but UNVERIFIED could still be torn, so it keeps consuming. Anchor 0 is
 * the distinct boot-storage episode and is never cleared by this covered-tip
 * guard. */
bool boot_crashonly_clear_reindex_request_if_covered(const char *datadir,
                                                     int coins_best_height,
                                                     bool coins_best_hash_verified);

/* Clear the self-rebuild budget once the boot reaches a clean integrity state. */
void boot_crashonly_clear(const char *datadir);

/* Handle a post-restore CHAIN_INTEGRITY_UNRECOVERABLE verdict. If it is the
 * reindex-recoverable shape (zero_nbits==0: holes only ABOVE the validated
 * index extent), the verb is executable (reindex_executable: the caller
 * verified blocks/ can serve the replay start), and the bounded budget
 * allows, request a self-rebuild and log it.
 * Returns true  => the caller must exit boot (reindex requested for the next
 *                  boot, or structural-corruption FATAL).
 * Returns false => the caller must KEEP SERVING degraded instead of exiting
 *                  into a crash-loop. Two cases:
 *                   (a) replay-from-blocks/ is not executable (cold-import
 *                       window): no sentinel was written, the
 *                       cold_import_reseed_required page fired.
 *                   (b) the bounded reindex budget is EXHAUSTED at a stable
 *                       anchor: a TERMINAL marker was persisted (so the next
 *                       boot does NOT re-arm the budget and crash-loop), the
 *                       crashonly_auto_reindex_exhausted page fired, and the
 *                       node stays up degraded — matching chain_tip_watchdog.
 *                  Either way operator_needed is latched (EV_OPERATOR_NEEDED). */
bool boot_crashonly_handle_unrecoverable(const char *datadir, int tip_h,
                                         int zero_nbits, int mismatches,
                                         int first_mismatch_h,
                                         bool reindex_executable);

/* Action a caller of boot_crashonly_storage_gate() must take. */
enum boot_gate_action {
    /* The bounded reindex budget allows another attempt: a self-rebuild
     * request was recorded. The caller must return from app_init with a
     * FAILURE so the process exits cleanly; the NEXT boot consumes the
     * request, runs -reindex-chainstate, and re-derives the inconsistent
     * state from blocks/. This is the crash-only re-derive rung. */
    BOOT_GATE_EXIT_FOR_REINDEX = 0,
    /* The bounded budget is EXHAUSTED at this boot-storage gate (or no
     * datadir). A terminal marker was persisted (so the next boot does NOT
     * re-arm and crash-loop) and an operator page fired. The caller must
     * NOT _exit() into a Restart=always crash-loop: it parks the process
     * alive-but-degraded (see boot_park_until_shutdown) so the halt is
     * observable and named, never a silent power-cycle. */
    BOOT_GATE_PARK_DEGRADED = 1,
};

/* Crash-only gate for a boot-phase storage incoherence that runs BEFORE the
 * node can serve degraded (coins-view integrity, progress.kv open, the
 * post-anchor sapling rebuild). These sites historically _exit(EXIT_FAILURE),
 * which under systemd Restart=always is an unbounded crash-loop with no
 * in-binary remedy. Convert that into the SAME bounded re-derive ladder the
 * post-restore integrity gate uses: record a bounded -reindex-chainstate
 * request keyed on a per-boot-storage episode (anchor 0 = "boot storage
 * incoherence"), so the restart re-derives the UTXO set from blocks/ instead
 * of re-hitting the identical corrupt derived state. Returns
 * BOOT_GATE_EXIT_FOR_REINDEX while the budget allows (caller exits → restart
 * reindexes), or BOOT_GATE_PARK_DEGRADED once the budget is spent (caller
 * parks, never crash-loops). `gate_name` names the failing gate in the log +
 * the EV_OPERATOR_NEEDED page.
 *
 * `reindex_executable` is the caller's h=0/1 readability probe (the same verb
 * check boot_crashonly_handle_unrecoverable takes): a from-genesis reindex
 * replay needs genesis-side block data. When it is FALSE (a cold-import /
 * bodyless datadir), arming a -reindex-chainstate request would burn a boot
 * cycle per attempt and — with the early coins clear — wipe the coins mirror
 * before the reindex verb check discovers the dead end. In that case the gate
 * does NOT arm: it names the cold-import re-seed remedy (EV_OPERATOR_NEEDED
 * condition=cold_import_reseed_required), clears any stale sentinel, and
 * returns BOOT_GATE_PARK_DEGRADED so the caller parks alive-degraded. */
enum boot_gate_action boot_crashonly_storage_gate(const char *datadir,
                                                  const char *gate_name,
                                                  bool reindex_executable);

/* Pure predicate: is on-disk body coverage of [0..reindex_best_h] dense enough
 * that a from-genesis -reindex-chainstate replay can complete without hitting a
 * missing body? The replay reads every block from h=0 and cannot skip one, so a
 * cold-import (bodyless) seed — have_data_count ~0 and max_have_data_h ~0 while
 * reindex_best_h is ~tip — returns false. A healthy datadir (bodies densely
 * cover the span) returns true; a small benign tail gap that gap-fill can heal
 * still returns true. Reindex-selection only — never touches consensus state. */
bool boot_reindex_body_coverage_sufficient(int reindex_best_h,
                                           int max_have_data_h,
                                           int have_data_count);

/* Reindex-target coverage decision: returns true iff the from-genesis reindex
 * should proceed, false iff it must be REFUSED in favour of fold-forward from a
 * seed. Refusal fires only when coins are already seeded AND
 * boot_reindex_body_coverage_sufficient() is false — a replay would wipe the
 * seed then stall on the first missing body. On refusal it logs, pages
 * (EV_BOOT_ACTIVATE reindex_refused_sparse_bodies), and CLEARS the auto-reindex
 * sentinel (boot_auto_reindex_clear) so it does not re-arm every boot. */
bool boot_crashonly_reindex_coverage_ok(const char *datadir,
                                        int reindex_best_h,
                                        int max_have_data_h,
                                        int have_data_count,
                                        bool coins_seeded);

#endif /* ZCL_CONFIG_BOOT_CRASHONLY_H */
