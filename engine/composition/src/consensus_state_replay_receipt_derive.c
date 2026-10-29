/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the DERIVATION half of the independent replay receipt — the
 * UTXO, anchor and nullifier row scans that re-derive the consensus
 * components from the datadir's OWN folded progress-store tables (coins,
 * sprout_anchors, sapling_anchors, nullifiers), plus the parked-at-anchor
 * precondition that guards them. The bundle's own tables are never read
 * here; the caller compares these digests against the bundle manifest.
 *
 * Split out of consensus_state_replay_receipt.c along the file-size ceiling
 * seam (E1) at the section boundary that file already declared. That file
 * keeps the RECEIPT half — payload codec, atomic write, read-back, the
 * verifier-binary digest, and the public authority/binding queries. Contract
 * + threat model: config/consensus_state_replay_receipt.h; the symbols that
 * cross the seam live in consensus_state_replay_receipt_internal.h.
 */

#include "config/consensus_state_replay_receipt.h"

#include "config/consensus_state_snapshot_install.h"
#include "base/serialize_le.h"
#include "coins/utxo_commitment.h"
#include "core/amount.h"
#include "crypto/sha3.h"
#include "platform/os_proc.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "script/script.h"
#include "storage/anchor_kv.h"
#include "storage/coins_kv.h"
#include "util/log_macros.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#endif

#include "consensus_state_replay_receipt_internal.h"

/* ── Independent derivation from the datadir's OWN folded tables ───────────── */

static bool rr_column_i64(sqlite3_stmt *st, int col, int64_t *out)
{
    if (sqlite3_column_type(st, col) != SQLITE_INTEGER)
        return false;
    *out = sqlite3_column_int64(st, col);
    return true;
}

/* One `coins` row as read from the progress store; `numeric` is false when an
 * integer column is not an INTEGER. */
struct rr_utxo_row {
    const uint8_t *txid;
    const uint8_t *script;
    int script_len;
    int64_t vout, value, height, coinbase;
    bool numeric;
};

static void derive_utxo_load(sqlite3_stmt *st, struct rr_utxo_row *row)
{
    row->txid = sqlite3_column_type(st, 0) == SQLITE_BLOB
        ? sqlite3_column_blob(st, 0) : NULL;
    row->script = sqlite3_column_type(st, 3) == SQLITE_BLOB
        ? sqlite3_column_blob(st, 3) : NULL;
    row->script_len = row->script ? sqlite3_column_bytes(st, 3) : 0;
    row->vout = -1;
    row->value = -1;
    row->height = -1;
    row->coinbase = -1;
    row->numeric = rr_column_i64(st, 1, &row->vout) &&
                   rr_column_i64(st, 2, &row->value) &&
                   rr_column_i64(st, 4, &row->height) &&
                   rr_column_i64(st, 5, &row->coinbase);
}

static bool derive_utxo_bad_shape(sqlite3_stmt *st, const struct rr_utxo_row *row)
{
    return !row->txid || sqlite3_column_bytes(st, 0) != 32 || !row->numeric ||
           sqlite3_column_type(st, 3) != SQLITE_BLOB;
}

static bool derive_utxo_bad_range(const struct rr_utxo_row *row,
                                  int32_t max_height, int64_t supply,
                                  uint64_t count)
{
    return row->script_len < 0 || row->script_len > MAX_SCRIPT_SIZE ||
           row->vout < 0 || row->vout > UINT32_MAX ||
           !MoneyRange(row->value) || supply > MAX_MONEY - row->value ||
           row->height < 0 || row->height > max_height ||
           (row->coinbase != 0 && row->coinbase != 1) ||
           count == UINT64_MAX;
}

static bool derive_utxo_fold_row(sqlite3_stmt *st, int32_t max_height,
                                 struct sha3_256_ctx *ctx, uint64_t count,
                                 int64_t *supply)
{
    struct rr_utxo_row row;
    derive_utxo_load(st, &row);
    if (derive_utxo_bad_shape(st, &row) ||
        derive_utxo_bad_range(&row, max_height, *supply, count))
        return false;
    utxo_commitment_sha3_write_record(ctx, row.txid, (uint32_t)row.vout,
                                      row.value,
                                      row.script_len ? row.script : NULL,
                                      (uint32_t)row.script_len,
                                      (uint32_t)row.height,
                                      (uint8_t)row.coinbase);
    *supply += row.value;
    return true;
}

static bool derive_utxo(sqlite3 *db, int32_t max_height, uint8_t root[32],
                        uint64_t *count_out, int64_t *supply_out)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT txid,vout,value,script,height,is_coinbase "
            "FROM coins ORDER BY txid,vout", -1, &st, NULL) != SQLITE_OK)
        return false;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    uint64_t count = 0;
    int64_t supply = 0;
    bool ok = true;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) { // raw-sql-ok:read-only-introspection
        if (!derive_utxo_fold_row(st, max_height, &ctx, count, &supply)) {
            ok = false;
            break;
        }
        count++;
    }
    if (rc != SQLITE_DONE)
        ok = false;
    sqlite3_finalize(st);
    if (!ok || count == 0)
        return false;
    sha3_256_finalize(&ctx, root);
    *count_out = count;
    *supply_out = supply;
    return true;
}

/* One anchor row as read from sprout_anchors or sapling_anchors; `numeric` is
 * false when the pool or height column is not an INTEGER. */
struct rr_anchor_row {
    const uint8_t *root;
    const uint8_t *tree;
    int tree_len;
    int64_t pool, height;
    bool numeric;
};

static void derive_anchors_load(sqlite3_stmt *st, struct rr_anchor_row *row)
{
    row->root = sqlite3_column_type(st, 1) == SQLITE_BLOB
        ? sqlite3_column_blob(st, 1) : NULL;
    row->tree = sqlite3_column_type(st, 3) == SQLITE_BLOB
        ? sqlite3_column_blob(st, 3) : NULL;
    row->tree_len = row->tree ? sqlite3_column_bytes(st, 3) : 0;
    row->pool = -1;
    row->height = -1;
    row->numeric = rr_column_i64(st, 0, &row->pool) &&
                   rr_column_i64(st, 2, &row->height);
}

static bool derive_anchors_bad_row(sqlite3_stmt *st,
                                   const struct rr_anchor_row *row,
                                   int32_t max_height, uint64_t count)
{
    return !row->numeric ||
           (row->pool != ANCHOR_POOL_SPROUT && row->pool != ANCHOR_POOL_SAPLING) ||
           !row->root || sqlite3_column_bytes(st, 1) != 32 || !row->tree ||
           row->tree_len <= 0 || row->height < 0 || row->height > max_height ||
           count == UINT64_MAX;
}

static bool derive_anchors(sqlite3 *db, int32_t max_height, uint8_t digest[32],
                           uint64_t *count_out)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT pool,anchor,height,tree FROM ("
            "SELECT 0 AS pool,anchor,height,tree FROM sprout_anchors "
            "UNION ALL "
            "SELECT 1 AS pool,anchor,height,tree FROM sapling_anchors) "
            "ORDER BY pool,anchor", -1, &st, NULL) != SQLITE_OK)
        return false;
    struct sha3_256_ctx ctx;
    consensus_state_bundle_anchor_digest_begin(&ctx);
    bool have_pool[2] = {false, false};
    uint64_t count = 0;
    bool ok = true;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) { // raw-sql-ok:read-only-introspection
        struct rr_anchor_row row;
        derive_anchors_load(st, &row);
        if (derive_anchors_bad_row(st, &row, max_height, count)) {
            ok = false;
            break;
        }
        consensus_state_bundle_anchor_digest_row(&ctx, (uint8_t)row.pool,
                                                 row.root, (uint64_t)row.height,
                                                 row.tree,
                                                 (uint32_t)row.tree_len);
        have_pool[row.pool] = true;
        count++;
    }
    if (rc != SQLITE_DONE)
        ok = false;
    sqlite3_finalize(st);
    /* A complete shielded history has both pools present. */
    if (!ok || !have_pool[0] || !have_pool[1])
        return false;
    sha3_256_finalize(&ctx, digest);
    *count_out = count;
    return true;
}

static bool derive_nullifiers(sqlite3 *db, int32_t max_height, uint8_t digest[32],
                              uint64_t *count_out)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT pool,nf,height FROM nullifiers ORDER BY pool,nf", -1, &st,
            NULL) != SQLITE_OK)
        return false;
    struct sha3_256_ctx ctx;
    consensus_state_bundle_nullifier_digest_begin(&ctx);
    uint64_t count = 0;
    bool ok = true;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) { // raw-sql-ok:read-only-introspection
        const uint8_t *nf = sqlite3_column_type(st, 1) == SQLITE_BLOB
            ? sqlite3_column_blob(st, 1) : NULL;
        int64_t pool = -1, height = -1;
        bool numeric = rr_column_i64(st, 0, &pool) &&
                       rr_column_i64(st, 2, &height);
        if (!numeric || (pool != 0 && pool != 1) || !nf ||
            sqlite3_column_bytes(st, 1) != 32 || height < 0 ||
            height > max_height || count == UINT64_MAX) {
            ok = false;
            break;
        }
        consensus_state_bundle_nullifier_digest_row(&ctx, (uint8_t)pool, nf,
                                                    (uint64_t)height);
        count++;
    }
    if (rc != SQLITE_DONE)
        ok = false;
    sqlite3_finalize(st);
    if (!ok)
        return false;
    sha3_256_finalize(&ctx, digest);
    *count_out = count;
    return true;
}

/* Fill `r`'s independently derived components from the datadir progress store
 * and return the derived digests; the caller compares them to the manifest. */
bool rr_derive_from_datadir(sqlite3 *db,
                            const struct consensus_state_bundle_manifest *m,
                            struct rr_receipt *r,
                            struct consensus_state_replay_result *out)
{
    int32_t applied = -1;
    bool applied_found = false;
    if (!coins_kv_get_applied_height(db, &applied, &applied_found) ||
        !applied_found)
        return rr_fail(out, "datadir has no coins_applied_height; the local "
                            "genesis->anchor fold has not run here");
    if (applied != m->height + 1)
        return rr_fail(out, "datadir is not parked at the bundle anchor "
                            "(coins_applied=%d, want %d); re-derivation must run "
                            "against a store folded EXACTLY to the anchor",
                       applied, m->height + 1);
    if (!derive_utxo(db, m->height, r->utxo_root, &r->utxo_count,
                     &r->total_supply))
        return rr_fail(out, "independent UTXO derivation from the datadir "
                            "failed (empty/malformed coins)");
    if (!derive_anchors(db, m->height, r->anchor_digest, &r->anchor_count))
        return rr_fail(out, "independent anchor derivation from the datadir "
                            "failed (missing/malformed Sprout or Sapling "
                            "anchors)");
    if (!derive_nullifiers(db, m->height, r->nullifier_digest,
                           &r->nullifier_count))
        return rr_fail(out, "independent nullifier derivation from the datadir "
                            "failed");
    return true;
}
