/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Block Index Integrity — load-time verification of block_index.bin.
 *
 * Invariant
 * ---------
 * `block_index.bin` must never silently disagree with the SQLite `blocks`
 * table: a stale flat-file tip entry, trusted by boot code, drives the
 * recovery path to "fix" the divergence by dropping real UTXO rows above the
 * (wrong) tip.
 *
 * The safeguard is belt-and-braces: a write-time sidecar that commits to
 * the bytes of `block_index.bin` plus a load-time cross-check
 * against SQLite so boot can refuse to proceed on any mismatch
 * instead of acting on a stale view.
 *
 * Sidecar format
 * --------------
 * Stored next to block_index.bin as `block_index.bin.sha3`. 48 bytes:
 *
 *     struct block_index_sidecar {
 *         uint8_t  magic[4];         // "BIIX"
 *         uint32_t version;          // 1
 *         uint64_t body_size;        // file size at write time
 *         uint8_t  body_sha3[32];    // SHA3-256 of block_index.bin
 *     };
 *
 * Write semantics
 * ---------------
 * `bii_write_sidecar()` is called AFTER `save_block_index_flat()`
 * finishes writing `block_index.bin`. It streams the full body
 * through SHA3-256, stat()s the file for the definitive size, and
 * writes the 48-byte sidecar atomically (open O_TRUNC, fsync,
 * rename from a `.tmp` stage).
 *
 * Verify semantics
 * ----------------
 * `bii_verify()` reads the sidecar, re-hashes the body, and
 * cross-checks the declared tip against SQLite. Returns a
 * structured verdict rather than a boolean so the caller can
 * decide per-verdict policy. The `declared_tip` argument is the
 * in-memory tip the loader just derived from `block_index.bin` —
 * pass NULL to skip the SQLite cross-check (for pre-wiring tests).
 *
 * Quarantine semantics
 * --------------------
 * On any hash/tip mismatch the caller should invoke
 * `bii_quarantine_corrupt()` which renames both files to
 * `<name>.corrupt.<unix_ts>` — NEVER deletes them. Operators need
 * the bytes for forensic analysis, and the files must be out of
 * the way so a subsequent boot builds a fresh index.
 */

#ifndef ZCL_SERVICES_BLOCK_INDEX_INTEGRITY_H
#define ZCL_SERVICES_BLOCK_INDEX_INTEGRITY_H

#include "models/database.h"
#include "chain/chain.h"
#include "util/result.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* ── Sidecar layout ─────────────────────────────────────────── */

#define BII_MAGIC "BIIX"
#define BII_SIDECAR_VERSION 1u
#define BII_SIDECAR_BYTES 48u

/* Embedded single-file format (task #32): the 48-byte integrity header
 * is the FIRST 48 bytes of block_index.bin itself, so the body and its
 * SHA3/size commitment publish as ONE atomic rename — no separate
 * sidecar, no inter-rename crash window. Distinct magic "BIIE" so the
 * verifier tells an embedded header from the "ZCLI" payload magic of a
 * legacy two-file body. */
#define BII_EMBEDDED_MAGIC "BIIE"
#define BII_EMBEDDED_VERSION 2u
#define BII_EMBEDDED_HEADER_BYTES 48u

/* ── Verdict ─────────────────────────────────────────────────
 * The possible outcomes of a bii_verify() call. Anything other
 * than BII_OK or BII_SIDECAR_MISSING (first-run upgrade path)
 * means the caller should quarantine and refuse to boot unless
 * ZCL_ALLOW_CORRUPT_INDEX=1 is set. */
enum bii_verdict {
    BII_OK = 0,
    BII_SIDECAR_MISSING,       /* no .sha3 next to block_index.bin — warn, accept */
    BII_SIDECAR_STALE,         /* sidecar body_size differs from actual */
    BII_HASH_MISMATCH,         /* sha3 of body does not match sidecar */
    BII_TIP_HEIGHT_MISMATCH,   /* block_map tip height disagrees with SQLite */
    BII_TIP_MISSING_IN_SQL,    /* block_map tip hash not found in SQLite blocks */
    BII_BODY_MISSING,          /* block_index.bin itself is missing */
    BII_BODY_UNREADABLE,       /* open/read/stat failed on block_index.bin */
    BII_SIDECAR_BAD_MAGIC,     /* wrong magic in the sidecar header */
    BII_SIDECAR_UNSUPPORTED,   /* sidecar version we don't understand */
    BII_NUM_VERDICTS           /* sentinel */
};

const char *bii_verdict_name(enum bii_verdict v);

enum bii_recovery_action {
    BII_RECOVERY_NONE = 0,
    BII_RECOVERY_ACCEPTED,
    BII_RECOVERY_RECONCILE_REQUIRED,
    BII_RECOVERY_QUARANTINED,
    BII_RECOVERY_OVERRIDE,
};

const char *bii_recovery_action_name(enum bii_recovery_action a);

struct bii_recovery_status {
    enum bii_verdict verdict;
    enum bii_recovery_action action;
    int64_t unix_time;
    bool degraded;
    bool unsafe_override;
    /* AUDITED for silent truncation: no zcl_text_fit guard needed. Every
     * bii_record_recovery_status() caller passes either a short literal or the
     * `char err[256]` that bii_verify() filled, so the store is a copy between
     * buffers of EQUAL capacity and cannot cut. A guard here could never fire. */
    char reason[256];
};

void bii_record_recovery_status(enum bii_verdict verdict,
                                enum bii_recovery_action action,
                                const char *reason,
                                bool degraded,
                                bool unsafe_override);

void bii_get_recovery_status(struct bii_recovery_status *out);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe. */
struct json_value;
bool block_index_integrity_dump_state_json(struct json_value *out,
                                           const char *key);

/* ── Verification entry point ─────────────────────────────────
 * Reads `<datadir>/block_index.bin.sha3` and re-hashes
 * `<datadir>/block_index.bin`, then optionally cross-checks the
 * declared tip against SQLite.
 *
 * Params:
 *   - datadir:      parent directory containing both files
 *   - db:           node_db handle for SQLite cross-check (nullable)
 *   - declared_tip: in-memory tip that block_index.bin just produced
 *                   (nullable — skip SQLite cross-check if NULL)
 *   - err_out:      optional caller-provided buffer for a human
 *                   diagnostic string (nullable)
 *   - err_cap:      capacity of err_out (ignored if err_out is NULL)
 */
enum bii_verdict bii_verify(const char *datadir,
                             struct node_db *db,
                             const struct block_index *declared_tip,
                             char *err_out, size_t err_cap);

/* ── Sidecar writer ───────────────────────────────────────────
 * Call AFTER save_block_index_flat() has completed. Hashes the
 * body and writes the 48-byte sidecar atomically. Returns a
 * non-ok zcl_result on any I/O error; the caller may choose to
 * leave the body in place (a future bii_verify() will then return
 * SIDECAR_MISSING). */
struct zcl_result bii_write_sidecar(const char *datadir);

/* Sidecar write from a caller-supplied size + SHA3 — no body rehash.
 * save_block_index_flat streams the hash while writing the body, so
 * the sidecar lands milliseconds after the rename instead of after a
 * multi-second 500 MB rehash (a shutdown killed in that window leaves a
 * fresh body under a stale sidecar and the next boot quarantines a
 * good file).
 *
 * RETAINED for the legacy two-file format only — kept so the
 * make-lint atomic-save contract and historical callers still link.
 * The current writer uses the embedded single-file path below. */
struct zcl_result bii_write_sidecar_raw(const char *datadir,
                                        uint64_t body_size,
                                        const uint8_t body_sha3[32]);

/* ── Embedded single-file integrity (task #32) ────────────────────
 * The writer streams the payload through `emit_payload` while the
 * shared helper owns the 48-byte header + atomic tmp/fsync/rename, so
 * the body and its integrity commitment are published as ONE file in
 * ONE rename. Verify re-hashes the payload against the embedded header
 * and reports the byte offset (48) at which the payload begins. */
struct ssio_sidecar_header;
struct zcl_result bii_write_embedded(
    const char *datadir,
    bool (*emit_payload)(FILE *f, void *ctx,
                         uint64_t *out_payload_size,
                         uint8_t out_payload_sha3[32]),
    void *ctx);

/* Returns an ssio_read_verdict (cast to int). SSIO_READ_OK (0) means
 * the embedded header verified; SSIO_READ_BAD_MAGIC means the file is
 * the legacy "ZCLI"-magic two-file format (caller falls back to the
 * sidecar path); any other value is a hard integrity failure. */
int bii_verify_embedded(const char *datadir,
                        struct ssio_sidecar_header *out,
                        uint64_t *out_payload_off);

/* ── Quarantine ───────────────────────────────────────────────
 * Renames both block_index.bin and block_index.bin.sha3 to
 * `<name>.corrupt.<unix_ts>`. Does NOT delete — operators need
 * the bytes for forensic analysis. Emits EV_BLOCK_INDEX_CORRUPT
 * with the verdict that triggered the quarantine. Missing files
 * are silently ignored (already-gone is fine). */
void bii_quarantine_corrupt(const char *datadir, enum bii_verdict v);

/* ── Bulk height repair ──────────────────────────────────────
 * After LDB import, block index entries may have scrambled nHeight
 * values.  This function walks the entire block map, finds entries
 * where nHeight != pprev->nHeight + 1, and fixes them all in O(n)
 * using a BFS-style forward propagation from roots (genesis or
 * first correct ancestors).  Also recomputes nChainWork.
 *
 * Returns the number of entries repaired (0 = nothing to fix).
 * Sets the global "heights repaired" flag on success so that
 * other subsystems (e.g. getheaders locator) can trust heights.
 *
 * Must be called AFTER block index is loaded, BEFORE header sync. */
struct main_state;
int block_index_repair_heights(struct main_state *ms);

/* Cursor-gated overload (OS-S2 #1). Only entries with nHeight > min_height are
 * counted as candidates for repair (pass -1 for a full scan); the true genesis
 * is always checked. When a wrong height IS found above the cursor the full
 * genesis-rooted propagation runs (idempotent — it never disturbs an
 * already-correct below-cursor prefix). out_max_height (optional) receives the
 * highest nHeight present so the caller can advance the cursor.
 * block_index_repair_heights(ms) == block_index_repair_heights_range(ms,-1,NULL). */
int block_index_repair_heights_range(struct main_state *ms, int min_height,
                                     int *out_max_height);

/* Returns true if block_index_repair_heights() has been called
 * (even if it repaired 0 entries — the scan itself is the signal). */
bool block_index_heights_repaired(void);

/* ── pprev chain repair ────────────────────────────────────────
 * Reads hashPrevBlock from block data on disk for every entry with
 * BLOCK_HAVE_DATA and fixes pprev if it points to the wrong parent.
 * Also recomputes nChainWork and nChainTx after repair.
 *
 * Must be called AFTER block_index_repair_heights(), BEFORE header sync. */
/* min_height: only re-scan blocks with nHeight > min_height (pass -1 for a
 * full scan). Lets boot skip the O(chain) disk walk when a persisted
 * "repaired-through" cursor already covers the index (fresh datadirs stamp
 * -1 and do the full work once). out_max_height (optional) receives the
 * highest nHeight present in the index so the caller can advance the cursor. */
int block_index_repair_pprev(struct main_state *ms, const char *datadir,
                             int min_height, int *out_max_height);

/* ── Post-activation anchor repair ─────────────
 *
 * Lifted from core/modules/net/src/msg_headers.c (~88 lines), which is the
 * wrong layer for structural block-index surgery. Called after a
 * block_file_scan activation pass discovers that the active tip
 * was placed below the known UTXO anchor (coins_best_block) — a
 * classic post-LDB-import shape where the block_file_scan picked
 * a short fork and left the real tip orphaned.
 *
 * Steps:
 *   1. Anchor the coins_bi block's nHeight to the known UTXO
 *      height (pre_scan_coins_h is the source of truth).
 *   2. Walk DOWN pprev from coins_bi fixing any height that
 *      disagrees with `parent_height + 1`.
 *   3. Re-propagate heights forward across the WHOLE block_map
 *      in a multi-pass scan so blocks above the anchor get
 *      correct heights too.
 *   4. If active_chain_tip is BELOW coins_bi AND coins_bi is
 *      disk-backed (consensus-validatable), promote coins_bi to
 *      active tip and pindex_best_header.
 *
 * `result` (may be NULL) is filled with counts and a summary.
 * Returns 0 on success, -1 if the anchor isn't valid (coins
 * height < 100k or coins_bi not in map). */

struct coins_view_cache;

struct bii_post_activation_result {
    int  heights_fixed_down;     /* walking down from coins_bi */
    int  heights_repropagated;   /* forward multi-pass */
    bool tip_restored;           /* active tip moved to coins_bi */
    bool tip_restore_refused;    /* coins_bi not disk-backed */
    int  tip_restore_old_h;
    int  tip_restore_new_h;
};

int bii_repair_post_activation_anchor(
    struct main_state            *ms,
    struct coins_view_cache      *coins_tip,
    const char                   *datadir,
    struct bii_post_activation_result *result);

#endif /* ZCL_SERVICES_BLOCK_INDEX_INTEGRITY_H */
