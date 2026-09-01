/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * tip_finalize_post_step — reducer post-finalize side effects.
 *
 * The post-finalize side-effect step: once tip_finalize has moved the
 * in-memory active-chain window, this runs the derived effects that belong to
 * tip connection but are not reducer cursor authority:
 * wallet transaction sync + Sapling trial-decrypt/note-persist, nullifier
 * spend marking, mempool removal of confirmed txs, and the MMR/MMB appends.
 * Internal to engine/jobs/src — not a public jobs/ API. */

#ifndef ZCL_JOBS_TIP_FINALIZE_POST_STEP_H
#define ZCL_JOBS_TIP_FINALIZE_POST_STEP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct block_index;

/* Run the post-finalize side effects for the just-connected tip block.
 *
 * `pindex_new` is the block_index of the newly finalized tip (already set
 * as chain[] tip by the caller). The block body is read back from disk via
 * GetDataDir() (resolved here, not threaded from the stage). NULL
 * pindex_new is a no-op; a missing on-disk body (HAVE_DATA absent / read
 * failure) is a benign skip.
 *
 * Every subsystem handle (wallet, mempool, node_db) is fetched via the
 * public app_runtime_* accessors and individually NULL-guarded. */
void tip_finalize_run_post_finalize(struct block_index *pindex_new);

/* Reconcile the connected block with the live coins cache and mempool only.
 * This is the mandatory idempotent subset of post-finalize work: callers use
 * it when another authority path has already published the same tip, so the
 * one-time wallet/MMR/MMB effects must not be repeated. The block body is
 * acquired and released under the same rules as the full post step. */
bool tip_finalize_run_mempool_reconcile(struct block_index *pindex_new);

/* Apply only the idempotent wallet effects for an already-published active
 * block. Used by late-visible-body reconciliation; never appends MMR/MMB. */
bool tip_finalize_run_wallet_reconcile(struct block_index *pindex_new);

/* ── SHA3 golden-window corroboration tripwire (OBSERVE-ONLY) ─────────────
 *
 * At every 1000-block window boundary the post-finalize step recomputes the
 * SHA3-256 digest over the concatenated raw block payloads of the window that
 * just closed and compares it to the immutable golden commitment in
 * chain/sha3_windows (`g_sha3_windows`). This is a CORROBORATION tripwire, not
 * a consensus check: a mismatch means either a lying peer fed a bad body or
 * local disk corruption, so the node records EVIDENCE (a typed blocker + a
 * telemetry event) and keeps going. It NEVER rejects a block, NEVER raises a
 * pipeline HOLD, NEVER changes the tip — consensus parity with zclassicd is
 * bit-for-bit unchanged whether the tripwire fires or not (E13-neutral).
 *
 * The functions below are exposed for the sha3_windows test group so the
 * fire/silent/observe-only behaviour is exercised deterministically without
 * real chain data. */
enum sha3_window_tripwire_result {
    SHA3_WINDOW_TRIPWIRE_SKIP     = 0,  /* window not covered by the table */
    SHA3_WINDOW_TRIPWIRE_MATCH    = 1,  /* corroborated — silent, cheap */
    SHA3_WINDOW_TRIPWIRE_MISMATCH = 2,  /* evidence emitted (blocker + event) */
};

/* Emit the observe-only evidence for window `window_index` given a precomputed
 * match verdict. `matched == true` is silent; `matched == false` registers the
 * `sha3_window_mismatch` typed blocker (PERMANENT, owner "sha3_window_tripwire")
 * and emits EV_BLOCK_INDEX_CORRUPT once (blocker dedup discipline). Returns the
 * result enum. Out-of-range windows return SKIP without emitting. */
enum sha3_window_tripwire_result
sha3_window_tripwire_report(int window_index, bool matched);

/* Recompute the window digest over `concat`/`len` via
 * sha3_windows_verify_window and route the verdict through
 * sha3_window_tripwire_report. Out-of-range or uncovered windows return SKIP. */
enum sha3_window_tripwire_result
sha3_window_tripwire_eval(int window_index, const uint8_t *concat, size_t len);

#endif /* ZCL_JOBS_TIP_FINALIZE_POST_STEP_H */
