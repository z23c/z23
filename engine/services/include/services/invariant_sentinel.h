/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * invariant_sentinel — fail-loud validation pack, always-on detectors:
 *
 *   check 3: authority-pair self-check — every site that persists a
 *            (height, hash) authority pair asserts the hash resolves to
 *            the same height in the blocks projection BEFORE the write;
 *            a mismatch refuses the write + pages. SCOPE: this catches
 *            the WRONG-BINDING class (a hash the projection resolves to
 *            a different height — the cold-import +1 height-binding
 *            race). It deliberately PASSES unknown hashes (snapshot/
 *            import tips legitimately publish before projection rows
 *            land), so a restore-ABOVE-EXTENT pair (no blocks row at
 *            all) passes here by design; that class is gated where it
 *            belongs — at restore/boot time, by the Invariant A
 *            restore-clamp (trust-rooted derivability at commit_tip,
 *            merge a2da7e107) + the crash-only boot auto-reindex
 *            (706a7c00a).
 *   check 4: window consistency sweep — a 60 s supervisor child
 *            (chain.invariant_sweep) re-derives the cheap durable-state
 *            invariants every minute under ONE progress-lock hold
 *            (transaction-atomic snapshot): stage-cursor pipeline
 *            ordering, utxo_apply log contiguity below its cursor,
 *            coins_applied vs utxo_apply's OWN ok=1 prefix (Invariant B
 *            re-asserted), and tip_finalize reorg-oscillation (the
 *            live-wedge signature). A violation must repeat on two
 *            consecutive sweeps (the reorg-unwind window disagrees by
 *            design for ms) before it raises the typed blocker naming
 *            the EXACT invariant + heights, HOLD + PAGE; a later clean
 *            sweep self-clears (repair jobs may legitimately fix holes).
 *   check 5: commitment audit — an hourly supervisor child
 *            (coins.commitment_audit) recomputes the XOR UTXO commitment
 *            over the utxos table and compares it to the persisted
 *            checkpoint (co-committed with every coins flush). Discards
 *            the pass when the set moved during the scan (tip cursor OR
 *            the stored checkpoint itself changed) or while bulk-import
 *            commitment tracking is frozen. A mismatch classifies via
 *            utxo_recovery_xor_mismatch_is_corruption_candidate: shrink
 *            or equal-count-different-hash = corruption candidate;
 *            growth = stale checkpoint (never fires). On a candidate it
 *            logs 16 per-txid-prefix range counts to LOCALIZE the
 *            divergence (a keyspace-tail truncation names itself), then
 *            blocker + HOLD + PAGE.
 *
 * All check states are exposed through ONE dumper registered as
 * `z23 dumpstate validation_pack` (covers this module + the HOLD
 * latch in core/modules/validation/chain_linkage_check + the seed gate + the
 * mirror divergence locator).
 *
 * CRASH-ONLY: nothing here ever kills the process. Refusal = returning
 * false / holding the latch; paging = EV_OPERATOR_NEEDED on a fresh
 * blocker write. */

#ifndef ZCL_SERVICES_INVARIANT_SENTINEL_H
#define ZCL_SERVICES_INVARIANT_SENTINEL_H

#include <stdbool.h>
#include <stdint.h>

struct node_db;
struct json_value;

/* ── Check 3: authority-pair self-check ─────────────────────────── */

/* Returns true when (height, hash) is publishable: the blocks projection
 * either does not know `hash` (unknown is OK — snapshot/import tips are
 * written before projection rows land) or resolves it to exactly
 * `height`. Returns false on a mismatch, after registering the
 * `authority.pair_self_check` blocker (PERMANENT) + paging once — the
 * caller MUST refuse the write. A NULL/closed ndb passes (unit tests /
 * very early boot). O(1): one indexed point SELECT. */
bool invariant_sentinel_check_pair(struct node_db *ndb,
                                   const uint8_t hash[32], int height,
                                   const char *site);

/* Record a pair violation detected by an EXISTING refusal path (e.g. the
 * csr Step-4 hash/height cross-check, which already refuses) — blocker +
 * page only, no second refusal. resolved_h < 0 = unknown. */
void invariant_sentinel_pair_violation(const char *site, int height,
                                       int64_t resolved_h);

/* ── Checks 4 + 5: supervised periodic sweeps ──────────────────── */

/* Register both supervisor children (idempotent). Call once at boot,
 * next to condition_registry_register_all(). */
void invariant_sentinel_register(void);

/* Pure verdict function for the window sweep — separated from the
 * readers so the fire/non-fire logic is unit-testable without a real
 * progress.kv. All heights in block-height units; negative = unknown
 * (the corresponding invariant is skipped). */
struct invariant_sweep_inputs {
    int64_t cur_tip_finalize;
    int64_t cur_utxo_apply;
    int64_t cur_script_validate;
    int64_t cur_body_fetch;
    int64_t cur_validate_headers;
    int32_t ua_log_frontier;     /* utxo_apply_log contiguous ok=1 prefix */
    bool    ua_log_frontier_known;
    int32_t coins_applied;       /* coins_applied_height, -1 = absent */
    bool    coins_applied_found;
    uint64_t reorg_detected_total;       /* monotonic stage counter */
    uint64_t prev_reorg_detected_total;  /* value at the previous sweep */
    int64_t prev_cur_tip_finalize;       /* cursor at the previous sweep */
};

struct invariant_sweep_verdict {
    bool violated;
    char invariant[16];   /* "I4.1".."I4.5" */
    int  first_bad_h;     /* HOLD boundary; -1 when not applicable */
    char detail[200];
};

void invariant_sentinel_sweep_evaluate(
    const struct invariant_sweep_inputs *in,
    struct invariant_sweep_verdict *out);

/* Two-sweep confirmation gate (single-sweep-thread state machine, exposed
 * for tests): returns true only when the SAME named violation (invariant
 * id + first_bad_h) was also pending from the previous call. A clean
 * verdict (or NULL) resets the pending state and returns false. Exists
 * because one durably-committed window disagrees BY DESIGN: a reorg
 * unwind rewinds {utxo_apply cursor, log, coins} in one txn while the
 * tip_finalize cursor is rewound by a LATER separate txn — a sweep
 * sampling between them sees a real I4.1 shape on a healthy node. */
bool invariant_sentinel_confirm_violation(
    const struct invariant_sweep_verdict *v);

/* One sweep pass over the real durable state (reads progress.kv under ONE
 * progress_store_tx_lock hold — the snapshot is transaction-atomic).
 * Exposed for tests + the post-boot one-shot; the supervisor child calls
 * this on its 60 s tick. A violation raises blocker/page/HOLD only when
 * it repeats on two consecutive sweeps (invariant_sentinel_confirm_
 * violation above). Returns false only when the stores are not available
 * yet (not a violation). */
bool invariant_sentinel_sweep_once(void);

/* One commitment audit pass (reads node.db). Same exposure rationale. */
bool invariant_sentinel_commitment_audit_once(void);

/* Auto-terminating owner hook: release a latched coins.commitment_spot_check
 * diagnostic (and any residual commitment_audit chain_linkage hold). NO node.db
 * access — safe from the condition-engine thread. Called by the
 * state_window_inconsistent condition remedy so a benign projection skew never
 * pages the operator forever. The underlying checkpoint resync happens on the
 * audit thread; this clears only the operator-facing signal. */
void invariant_sentinel_clear_commitment_blocker(void);

/* ── `z23 dumpstate validation_pack` ─────────────────────── */
bool invariant_sentinel_dump_state_json(struct json_value *out,
                                        const char *key);

/* Quick health rollup: true iff NO validation-pack blocker is active and
 * the HOLD latch is clear. detail (optional) receives the first active
 * blocker id. */
bool invariant_sentinel_healthy(char *detail, int detail_cap);

/* Counter feeds from the other pack modules, so ONE dumper covers the
 * whole pack (seed_integrity_gate, mirror_divergence_locator, the
 * block_index_loader by-height fallback). */
void invariant_sentinel_note_seed_gate(bool refused);
void invariant_sentinel_note_locator(int first_div_h);
void invariant_sentinel_note_loader_height_fallback(void);

#ifdef ZCL_TESTING
void invariant_sentinel_reset_for_testing(void);
void invariant_sentinel_set_node_db_for_testing(struct node_db *ndb);
#endif

#endif /* ZCL_SERVICES_INVARIANT_SENTINEL_H */
