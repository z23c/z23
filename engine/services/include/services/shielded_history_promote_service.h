/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * shielded_history_promote_service — the VERIFIED promote of a FINISHED
 * from-genesis producer's below-checkpoint shielded history (Sprout+Sapling
 * anchors + the nullifier set) into a WEDGED COPY datadir's progress.kv,
 * atomically, flipping all three shielded activation cursors to 0.
 *
 * WHY: a snapshot/seed datadir reached its transparent tip but holds NO
 * historical Sprout/Sapling anchor roots or nullifiers below the reducer's
 * adoption cursor. anchor_kv/nullifier_kv fail those below-cursor lookups CLOSED
 * (HISTORY_INCOMPLETE) while their activation cursors are positive, pinning H*
 * at the wedge height (utxo_apply.anchor_backfill_gap + nullifier_backfill_gap).
 * A SEPARATE, finished full-validation producer datadir (folded genesis ->
 * checkpoint, HARD-matched to the compiled SHA3 UTXO checkpoint) DOES hold that
 * complete below-checkpoint set. This service promotes that set into the wedged
 * COPY and flips the cursors — WITHOUT a from-genesis refold on the copy.
 *
 * CONSENSUS-CRITICAL / ALL-OR-NOTHING (mirrors shielded_history_import_service):
 * flipping a cursor to 0 converts a SAFE halt (missing root = HISTORY_INCOMPLETE,
 * block held) into an ACCEPT (missing root = MISSING, block false-rejected ->
 * re-wedge / fork). The install is therefore atomic: ANY gate failure ROLLS BACK
 * the whole transaction and leaves all three cursors POSITIVE (the safe wedge).
 *
 * The gates (all fail-closed -> ROLLBACK, cursors stay positive):
 *   G1  producer self-consistency: producer anchor_state.activation_cursor == 0
 *       for BOTH pools AND producer nullifier_kv.activation_cursor == 0 (a
 *       finished from-genesis producer).
 *   G2  Sapling per-row header bind: each installed Sapling frontier's own
 *       recomputed root must equal the block header's hashFinalSaplingRoot at
 *       that height (from the in-RAM block index, NOT node.db). A null expected
 *       root above Sapling activation is a hard FAIL (corrupt/unimported header).
 *   G2b Sapling completeness: every distinct header hashFinalSaplingRoot over
 *       [sapling_activation, anchor_boundary) must have a present sapling_anchors
 *       row. A hole refuses (this is what makes the AC->0 flip safe).
 *   G3  Sprout install gated on a PASSING body crosscheck (sprout_ok).
 *   G4  Nullifier install gated on a PASSING body crosscheck (nullifiers_ok).
 *   G5  boundary: no producer row above the compiled checkpoint height.
 *   G6  atomic install + flip of ALL THREE cursors in ONE BEGIN IMMEDIATE
 *       (direct-UPDATE cursor flip, never the delete-then-reset primitives).
 *
 * Owner-gated, copy-prove-gated: the -promote-shielded-history verb refuses any
 * path that does not carry the throwaway "-COPY-" marker (both target AND
 * producer) and never touches a live datadir. See
 * engine/composition/src/boot_promote_shielded_history.c.
 */
#ifndef ZCL_SERVICES_SHIELDED_HISTORY_PROMOTE_SERVICE_H
#define ZCL_SERVICES_SHIELDED_HISTORY_PROMOTE_SERVICE_H

#include <stdbool.h>
#include <stdint.h>

struct sqlite3;
struct block_index;
struct crosscheck_result;

/* progress_meta key the promote stamps its provenance row under on a successful
 * commit (source producer, per-pool counts, boundary, checkpoint height,
 * self_folded=false). */
#define SHIELDED_PROMOTE_PROVENANCE_KEY "shielded_history.promote.provenance"

/* Per-run outcome. Populated on both success and refusal; nothing was committed
 * unless `committed` is true. */
struct shielded_promote_report {
    int64_t sapling_anchors_installed;
    int64_t sprout_anchors_installed;
    int64_t sapling_nullifiers_installed;
    int64_t sprout_nullifiers_installed;
    int64_t producer_sapling_rows;
    int64_t producer_sprout_rows;
    int64_t producer_sapling_nf;
    int64_t producer_sprout_nf;
    int64_t anchor_boundary;         /* target anchor cursor before the flip */
    int64_t nullifier_boundary;      /* target nullifier cursor before the flip */
    bool sapling_header_complete;    /* G2b passed */
    bool sprout_crosscheck_ok;       /* G3 */
    bool nullifiers_crosscheck_ok;   /* G4 */
    bool committed;                  /* true iff the atomic transaction COMMITted */
};

/* One promote request. All paths must be already validated (the verb enforces
 * the -COPY- path-safety guard before constructing this). */
struct shielded_promote_request {
    struct sqlite3 *target_progress_db;  /* open, writable — the wedged COPY */
    const char *target_copy_datadir;     /* local-body datadir for the crosscheck */
    const char *producer_datadir;        /* producer COPY; <dir>/progress.kv read RO */
    struct block_index *header_tip;      /* in-RAM best-header tip (hashFinalSaplingRoot) */
    int64_t sapling_activation_height;   /* G2b scan floor + null-guard boundary */
    int64_t checkpoint_height;           /* G5 boundary (sha3_utxo_checkpoint.height) */
};

/* Run the verified promote. All-or-nothing: on ANY gate failure it ROLLS BACK,
 * writes NOTHING, leaves all three activation cursors POSITIVE (safe wedge) and
 * returns false. Returns true only when the complete set committed and all three
 * cursors are durably zero. `out` may be NULL. */
bool shielded_history_promote_run(const struct shielded_promote_request *req,
                                  struct shielded_promote_report *out);

/* Test seam — the body-crosscheck invocation is indirected through this pointer
 * so a fixture can inject a deterministic verdict without building a full
 * local-body datadir. Default (unset / NULL) = the REAL symbol linked in
 * production (shielded_history_body_crosscheck_run — placeholder until lane B
 * lands its real local-body verifier). Tests only. */
typedef bool (*shielded_promote_crosscheck_fn)(const char *copy_datadir,
                                               const char *producer_datadir,
                                               int64_t checkpoint_height,
                                               struct crosscheck_result *out);
void shielded_history_promote_set_crosscheck_for_test(
    shielded_promote_crosscheck_fn fn);
void shielded_history_promote_reset_crosscheck_for_test(void);

#endif /* ZCL_SERVICES_SHIELDED_HISTORY_PROMOTE_SERVICE_H */
