/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_recovery_internal.h — shared declarations across the files that
 * make up the UTXO recovery service:
 *
 *   utxo_recovery_service.c       — public API: wipe, prepare_reimport,
 *                                   count-check classify, execute (validation
 *                                   recovery), clean_above_tip, backfill
 *   utxo_recovery_restore.c       — heavy boot recovery paths:
 *                                   import_ldb (LevelDB→SQLite migration) and
 *                                   restore_chain_tip (coins-best restoration)
 *   utxo_recovery_frontier_gate.c — Invariant A primitives: validated header
 *                                   frontier read, candidate clamp, and the
 *                                   evidence-based finalized-floor rewind
 *
 * NOT a public header. Only included by the files above. The
 * trailing "_internal" suffix marks these symbols as file-local to the
 * utxo_recovery translation units; they are the shared CSR-commit
 * primitives used by both the validation-recovery path and the boot
 * import/restore path, and should not be referenced from elsewhere. */

#ifndef ZCL_UTXO_RECOVERY_INTERNAL_H
#define ZCL_UTXO_RECOVERY_INTERNAL_H

#include "services/utxo_recovery_service.h"

#include <stdbool.h>
#include <stdint.h>

struct block_index;

/* Commit `*tip_inout` as the active chain tip + coins-best cursor through
 * the chain_state_repository (CSR). `reason` is a grep-able tag. When
 * `persist_coins_best` is true the coins_best_block key is durably
 * written.
 *
 * INVARIANT A GATE (unless `frontier_exempt`): the committed tip is
 * min(candidate, validated header frontier) — `*tip_inout` may be LOWERED
 * to the hash-linked frontier ancestor, so callers must read the pointer
 * back after a successful commit. `frontier_exempt` is true ONLY for
 * SHA3-verified snapshot imports (the typed snapshot carve-out: a re-import
 * carries its own cryptographic evidence and must not be clamped by a stale
 * pre-import log; the subsequent seed-anchor stamp re-raises the frontier).
 *
 * Returns ZCL_OK on success; a non-ok zcl_result with a self-describing
 * message on failure (code -43 invalid args, -44 CSR rejected the
 * promotion, -47 candidate not derivable from the frontier — install
 * refused).
 *
 * This is the single CSR-gated promotion primitive shared by the
 * validation-recovery path (utxo_recovery_service.c) and the boot
 * import/restore path (utxo_recovery_restore.c). */
struct zcl_result utxo_recovery_commit_tip(struct utxo_recovery_ctx *ctx,
                              struct block_index **tip_inout,
                              const char *reason,
                              bool persist_coins_best,
                              bool frontier_exempt);

/* ── Invariant A primitives (utxo_recovery_frontier_gate.c) ─────────── */

/* Deepest durably-finalized height: MAX(tip_finalize_log.height WHERE ok=1),
 * or -1 when none / progress store closed. Optionally returns that row's
 * tip_hash. */
int utxo_recovery_finalized_served_floor(struct uint256 *hash_out,
                                         bool *have_hash_out);

/* Validated header frontier (the Invariant A LOG authority): the contiguous
 * ok=1 prefix of validate_headers_log above the trusted anchor. Returns
 * false when there is NO log evidence (fresh datadir / missing tables) —
 * the caller must FAIL OPEN and behave as if ungated. */
bool utxo_recovery_header_frontier(int32_t *out_h);

/* utxo_recovery_block_trust_rooted (the Invariant A INDEX authority) is
 * declared in the PUBLIC services/utxo_recovery_service.h — boot.c gates
 * its CSR tip promotions on it too. Implemented in
 * utxo_recovery_frontier_gate.c. */

/* Boot-restore glue (utxo_recovery_frontier_gate.c): if `tip` is a detached
 * island, run utxo_recovery_relink_scrambled_ancestry and, on a FIXED verdict,
 * durably re-save the flat block index. No-op (one bounded gate walk) when the
 * tip is already trust-rooted. Lives in the gate TU (not restore.c) purely to
 * keep utxo_recovery_restore.c under the E1 file-size ceiling. */
struct utxo_recovery_ctx;
void utxo_recovery_relink_island_if_present(struct utxo_recovery_ctx *ctx,
                                            struct block_index *tip);

/* INVARIANT A GATE — never INSTALL a tip above what the validated header
 * log can DERIVE. Returns the candidate itself (no clamp needed, or
 * fail-open with no frontier evidence), the hash-linked ancestor at the
 * frontier height, or NULL when the candidate is provably not linked to
 * the frontier and the frontier block is absent from the index (the
 * caller refuses the install). Loud on every clamp/refusal. */
struct block_index *utxo_recovery_clamp_tip_to_header_frontier(
    struct utxo_recovery_ctx *ctx, struct block_index *candidate,
    const char *reason, int32_t *frontier_out, bool *clamped_out);

/* EVIDENCE-BASED FLOOR REWIND — only a finalized floor neither authority
 * can back is provably unbackable; flip its ok=1 rows above `frontier`
 * (the rewind bound) to ok=0 with status='floor_rewind' (history
 * preserved, status marks provenance). NEVER fires when floor <= the
 * bound (ordinary boots are untouched — the anti-rewind guard holds).
 * Returns false only on a DB write failure. */
bool utxo_recovery_rewind_finalized_floor(int32_t frontier, int floor,
                                          const char *reason);

/* THE SETTLE LOOP — re-derive a servable finalized floor. While the floor
 * outranks scan_fallback_h AND fails either Invariant A authority (LOG
 * half: within the validated frontier or below the log's rolling window;
 * INDEX half: row hash resolves at the recorded height on a trust-rooted
 * chain), flip it via utxo_recovery_rewind_finalized_floor and re-read.
 * Returns the settled floor; served_hash/have_served_hash track the
 * surviving row. A floor that settles above scan_fallback_h is VERIFIED
 * backable by both authorities (modulo a defensive no-progress hold). */
int utxo_recovery_settle_finalized_floor(struct utxo_recovery_ctx *ctx,
                                         int scan_fallback_h,
                                         int served_floor,
                                         struct uint256 *served_hash,
                                         bool *have_served_hash);

/* Reset the coins-best cursor + active tip to the genesis block and
 * flush the coins cache. Returns ZCL_OK on success; a non-ok zcl_result
 * on failure (code -45 invalid args, -46 genesis missing from the block
 * index, or the propagated commit_tip error). */
struct zcl_result utxo_recovery_commit_genesis(struct utxo_recovery_ctx *ctx,
                                  const char *reason);

/* scan_fallback restore epilogue (implemented in utxo_recovery_service.c):
 * true when the committed tip stands (fast rebuild succeeded, or the coins
 * view is unwired — legacy anchor commit); false when the commit was rolled
 * back to genesis because the wired canonical coins store is genuinely
 * empty (a tip with no state behind it is a phantasm). */
bool utxo_recovery_scan_fallback_keep_commit(struct utxo_recovery_ctx *ctx,
                                             const struct block_index *committed);

/* utxo_recovery_copy_chainstate_stable (point-in-time chainstate copy,
 * implemented in utxo_recovery_ldb_copy.c) is now declared in the PUBLIC
 * services/utxo_recovery_service.h (included above) so the borrowed-frontier
 * cure can reuse it. */

/* ── Cold-import seed provenance (utxo_recovery_seed_provenance.c) ────
 * The durable seed-anchor keys cold_import_seed_anchor_{height,hash,
 * utxo_count} + the wave-2 canonical token cold_import_seed_coins_kv_count.
 * Writer below; clear MUST be called by every path that wipes or prepares
 * to re-import the UTXO set so a stale key can never outlive the coins it
 * attests to — closing the torn-then-stale-key wrong-seed window in
 * block_index_loader_seed_stages_from_cold_import. Both best-effort
 * (non-fatal on failure; the consumer's live coin-count cross-check is the
 * backstop). */
void utxo_recovery_write_cold_import_seed(struct node_db *ndb,
                                          int height,
                                          const struct uint256 *hash,
                                          int64_t utxo_count);
void utxo_recovery_clear_cold_import_seed(struct node_db *ndb);
bool utxo_recovery_clear_cold_import_seed_checked(struct node_db *ndb);

/* Read the durable cold-import seed anchor identity (height + 32B hash).
 * Returns true and fills *out_height / *out_hash ONLY when both keys are
 * present and the hash is exactly 32 bytes (the legitimate snapshot base);
 * false on any normal / P2P-origin datadir (no keys), so the caller treats
 * the result as "no seed anchor" and behaves identically to before. */
bool utxo_recovery_read_cold_import_seed(struct node_db *ndb,
                                         int *out_height,
                                         struct uint256 *out_hash);

/* utxo_recovery_set_cold_import_trust_anchor() is now declared in the public
 * services/utxo_recovery_service.h (PART C trust-root terminus setter) so the
 * shielded-history import can register the cured coins tip. */

/* ── Mirror-walk helpers (utxo_recovery_mirror_walk.c) ────────────────
 * Legacy fallbacks below the wave-2 derived coins-best: MAX(height) over
 * the rebuildable utxos mirror, and the newest mirror tip that is
 * consensus-backed on disk. Whole TU is a wave-3 deletion unit. */
int utxo_recovery_max_utxo_height(struct utxo_recovery_ctx *ctx);
struct block_index *utxo_recovery_find_disk_backed_utxo_tip(
    struct utxo_recovery_ctx *ctx,
    int max_height);

/* Shared boot-repair tuning shared by utxo_recovery_service.c and
 * utxo_recovery_stale_cursor.c. */
#define UTXO_CHECKPOINT_NEAR_WINDOW 144
#define UTXO_BOOT_REWIND_MAX_ROWS 32

#endif /* ZCL_UTXO_RECOVERY_INTERNAL_H */
