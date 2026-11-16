/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_mirror_delta — incremental projection and guarded checkpoint adoption.
 */

// one-result-type-ok:delta-apply-3-valued-status — E2 (one way out): the one
// public fallible entry point (utxo_mirror_delta_apply) returns a single domain
// enum, utxo_mirror_delta_status (OK / ERROR / FALLBACK-to-full-rebuild). A
// struct zcl_result's bool+message cannot express the three-way FALLBACK
// outcome, and every failure IS logged via LOG_RETURN/LOG_FAIL. This is a
// stateless helper invoked by the utxo_mirror_sync service, not a lifecycle
// service surface of its own.
#include "services/utxo_mirror_delta.h"
#include "services/utxo_mirror_sync_service.h"

#include "coins/utxo_commitment.h"
#include "config/db_service.h"
#include "config/runtime.h"
#include "jobs/tip_finalize_stage.h"
#include "models/database.h"
#include "models/utxo.h"
#include "script/script.h"    /* MAX_SCRIPT_SIZE */
#include "script/standard.h"  /* utxo_classify_script */
#include "storage/progress_store.h"
#include "storage/utxo_mirror_schema.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Touched-address set (open addressing, 20-byte keys) ─────────────
 * Dedup the addresses touched by a delta pass so each is re-derived exactly
 * once. Small at tip (a handful); bounded by the per-pass height cap. */

struct addr_set {
    uint8_t (*keys)[20];
    bool *used;
    size_t cap;    /* power of two, or 0 when empty */
    size_t count;
};

static uint64_t addr_hash20(const uint8_t h[20])
{
    uint64_t x = 1469598103934665603ULL;
    for (int i = 0; i < 20; i++) { x ^= h[i]; x *= 1099511628211ULL; }
    return x;
}

static bool addr_set_grow(struct addr_set *s, size_t new_cap)
{
    uint8_t (*nk)[20] = zcl_calloc(new_cap, sizeof(*nk), "mirror_delta_addr_keys");
    bool *nu = zcl_calloc(new_cap, sizeof(*nu), "mirror_delta_addr_used");
    if (!nk || !nu) { free(nk); free(nu); return false; }
    size_t mask = new_cap - 1;
    for (size_t i = 0; i < s->cap; i++) {
        if (!s->used[i]) continue;
        size_t p = (size_t)addr_hash20(s->keys[i]) & mask;
        while (nu[p]) p = (p + 1) & mask;
        memcpy(nk[p], s->keys[i], 20);
        nu[p] = true;
    }
    free(s->keys);
    free(s->used);
    s->keys = nk;
    s->used = nu;
    s->cap = new_cap;
    return true;
}

static bool addr_set_add(struct addr_set *s, const uint8_t h[20])
{
    if (s->cap == 0 && !addr_set_grow(s, 64))
        return false;
    if ((s->count + 1) * 4 >= s->cap * 3 && !addr_set_grow(s, s->cap * 2))
        return false;
    size_t mask = s->cap - 1;
    size_t p = (size_t)addr_hash20(h) & mask;
    while (s->used[p]) {
        if (memcmp(s->keys[p], h, 20) == 0)
            return true;   /* already present */
        p = (p + 1) & mask;
    }
    memcpy(s->keys[p], h, 20);
    s->used[p] = true;
    s->count++;
    return true;
}

static void addr_set_free(struct addr_set *s)
{
    free(s->keys);
    free(s->used);
    memset(s, 0, sizeof(*s));
}

/* ── One added/spent coin → node.db mirror row ──────────────────────── */

/* Insert (INSERT OR REPLACE) one coin into the utxos mirror and record its
 * address for later cache refresh. `script`/`slen` alias the caller's buffer
 * (the sqlite column or the spent-blob), valid until the next step. */
static bool mirror_upsert_coin(struct node_db *ndb, struct addr_set *touched,
                               const uint8_t txid[32], uint32_t vout,
                               int64_t value, int height, bool is_coinbase,
                               const uint8_t *script, size_t slen)
{
    struct db_utxo u;
    memset(&u, 0, sizeof(u));
    memcpy(u.txid, txid, 32);
    u.vout = vout;
    u.value = value;
    u.height = height < 0 ? 0 : height;    /* utxos schema CHECK(height >= 0) */
    u.is_coinbase = is_coinbase;
    u.script = (uint8_t *)script;
    u.script_len = slen;
    u.script_type = utxo_classify_script(u.script, u.script_len,
                                         u.address_hash, &u.has_address);
    if (!db_utxo_insert_raw(ndb, &u))
        LOG_FAIL("utxo_mirror", "delta: upsert insert failed vout=%u", vout);
    if (u.has_address && !addr_set_add(touched, u.address_hash))
        LOG_FAIL("utxo_mirror", "delta: touched-address set OOM");
    return true;
}

/* ── spent_blob parse ────────────────────────────────────────────────
 * Wire layout per entry (serialize_spent, utxo_apply_delta.c):
 *   txid[32] | vout(u32 LE) | value(i64 LE) | height(u32 LE)
 *   | is_coinbase(u8) | script_len(u32 LE) | script[script_len]
 * We need txid, vout, and the script (to classify the paid-to address whose
 * aggregate changes when the coin leaves the set). Returns false on a
 * malformed/short blob (caller falls back to a full rebuild). */
static uint32_t rd_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int64_t rd_i64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v |= (uint64_t)p[i] << (8 * i);
    return (int64_t)v;
}

/* Fold one spent entry's ORIGINAL (txid, vout, value, creation_height) out of
 * *uc — the SAME per-UTXO hash inputs utxo_commitment_add used when the coin
 * entered the set (see coins/utxo_commitment.h). This is the retry-safe
 * (idempotent-under-re-apply) gate; XOR is its own inverse, so folding an
 * unmatched value in — either an add that was never counted, or a remove
 * already folded by an earlier attempt — corrupts the accumulator instead of
 * being a harmless no-op the way INSERT-OR-REPLACE/no-op-DELETE are for the
 * mirror table. TWO independent conditions must BOTH hold, checked against
 * `ch` (the checkpoint's OWN covering height, not the delta pass's `cursor` —
 * see utxo_mirror_delta_apply for why they can differ on a retried pass):
 *   1. creation_height < ch — the coin actually EXISTED in the checkpointed
 *      set (a coin created inside the still-open window [ch, upper) was never
 *      added to *uc in the first place — created-and-spent-within-the-window
 *      is a real case the mirror table also treats as a no-op delete).
 *   2. spend_height >= ch — THIS spend event has not already been folded into
 *      *uc by an earlier attempt over an overlapping range (a retry replays
 *      utxo_apply_delta rows already < ch verbatim; without this check a
 *      long-lived coin spent inside an already-committed sub-range would be
 *      XOR-canceled a second time). */
static void maybe_commitment_remove(struct utxo_commitment *uc, int32_t ch,
                                    const uint8_t txid[32], uint32_t vout,
                                    int64_t value, int32_t creation_height,
                                    int32_t spend_height)
{
    if (!uc || creation_height >= ch || spend_height < ch)
        return;
    utxo_commitment_remove(uc, txid, vout, value, creation_height);
}

static bool mirror_apply_spent_blob(struct node_db *ndb, struct addr_set *touched,
                                    const uint8_t *blob, size_t len,
                                    int64_t *rows_changed,
                                    struct utxo_commitment *uc, int32_t ch,
                                    int32_t spend_height)
{
    size_t off = 0;
    while (off < len) {
        if (len - off < 32 + 4 + 8 + 4 + 1 + 4)
            LOG_FAIL("utxo_mirror", "delta: spent_blob truncated header");
        const uint8_t *txid = blob + off;
        uint32_t vout = rd_u32(blob + off + 32);
        int64_t value = rd_i64(blob + off + 32 + 4);
        uint32_t coin_h = rd_u32(blob + off + 32 + 4 + 8);
        uint32_t slen = rd_u32(blob + off + 32 + 4 + 8 + 4 + 1);
        size_t entry = 32 + 4 + 8 + 4 + 1 + 4 + (size_t)slen;
        if (slen > MAX_SCRIPT_SIZE || len - off < entry)
            LOG_FAIL("utxo_mirror", "delta: spent_blob bad script_len=%u", slen);
        const uint8_t *script = blob + off + 32 + 4 + 8 + 4 + 1 + 4;

        /* Record the paid-to address BEFORE deleting so its aggregate is
         * re-derived; a coin that was created-and-spent within the catch-up
         * range was never inserted, so the delete is a harmless no-op but the
         * address refresh (re-derive from utxos) is still idempotent. */
        uint8_t addr[20];
        bool has_addr = false;
        (void)utxo_classify_script(script, slen, addr, &has_addr);
        if (has_addr && !addr_set_add(touched, addr))
            LOG_FAIL("utxo_mirror", "delta: touched-address set OOM (spent)");
        if (!db_utxo_delete(ndb, txid, vout))
            LOG_FAIL("utxo_mirror", "delta: spent delete failed vout=%u", vout);
        maybe_commitment_remove(uc, ch, txid, vout, value, (int32_t)coin_h,
                                spend_height);
        (*rows_changed)++;
        off += entry;
    }
    return true;
}

/* Count the utxo_apply_delta rows persisted for [cursor, upper); -1 when the
 * query could not run to a row. */
static int64_t mirror_count_delta_rows(sqlite3 *rdb, int32_t cursor, int32_t upper)
{
    sqlite3_stmt *cnt = NULL;
    int64_t delta_rows = -1;
    if (sqlite3_prepare_v2(rdb,
            "SELECT COUNT(*) FROM utxo_apply_delta WHERE height >= ? AND height < ?",
            -1, &cnt, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(cnt, 1, cursor);
        sqlite3_bind_int64(cnt, 2, upper);
        if (sqlite3_step(cnt) == SQLITE_ROW)  // raw-sql-ok:progress-kv-kernel-store
            delta_rows = sqlite3_column_int64(cnt, 0);
    }
    sqlite3_finalize(cnt);
    return delta_rows;
}

static bool mirror_delta_tip_hash(sqlite3 *rdb, int32_t upper,
                                  uint8_t out[32])
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(rdb,
            "SELECT branch_hash FROM utxo_apply_delta WHERE height = ?",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int64(st, 1, upper - 1);
    bool ok = false;
    if (ar_step_checked(st, "utxo mirror delta branch hash", NULL) == ZCL_STEP_ROW) {
        const void *blob = sqlite3_column_blob(st, 0);
        int len = sqlite3_column_bytes(st, 0);
        if (blob && len == 32) {
            memcpy(out, blob, 32);
            ok = true;
        }
    }
    return sqlite3_finalize(st) == SQLITE_OK && ok;
}

bool utxo_mirror_node_branch_hash(struct node_db *ndb, uint8_t expected[32],
                                  bool *present)
{
    if (!ndb || !expected || !present)
        return false;
    uint8_t stored[33];
    size_t len = 0;
    if (!node_db_state_read(ndb, UTXO_MIRROR_BRANCH_HASH_KEY,
                            stored, sizeof(stored), &len, present))
        return false;
    if (!*present)
        return true;
    if (len != 32)
        return false;
    memcpy(expected, stored, 32);
    return true;
}

enum utxo_mirror_branch_verdict
utxo_mirror_branch_check(struct sqlite3 *db, int64_t cursor,
                         const uint8_t expected[32])
{
    if (!db || !expected || cursor <= 0)
        return UTXO_MIRROR_BRANCH_HISTORY_MISSING;
    sqlite3_stmt *st = NULL;
    enum utxo_mirror_branch_verdict verdict = UTXO_MIRROR_BRANCH_HISTORY_MISSING;
    progress_store_tx_lock();
    if (sqlite3_prepare_v2(db,
            "SELECT branch_hash FROM utxo_apply_delta WHERE height = ?",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(st, 1, cursor - 1);
        if (ar_step_checked(st, "utxo mirror branch check", NULL) == ZCL_STEP_ROW) {
            const void *blob = sqlite3_column_blob(st, 0);
            int len = sqlite3_column_bytes(st, 0);
            if (blob && len == 32)
                verdict = memcmp(expected, blob, 32) == 0
                    ? UTXO_MIRROR_BRANCH_OK : UTXO_MIRROR_BRANCH_MISMATCH;
        }
    }
    if (sqlite3_finalize(st) != SQLITE_OK)
        verdict = UTXO_MIRROR_BRANCH_HISTORY_MISSING;
    progress_store_tx_unlock();
    return verdict;
}

enum mirror_coin_row {
    MIRROR_COIN_ROW_OK,
    MIRROR_COIN_ROW_BAD_TXID,
    MIRROR_COIN_ROW_BIG_SCRIPT,
};

/* Classify the current coins row; *slen_out is the clamped script length. */
static enum mirror_coin_row mirror_coin_row_check(sqlite3_stmt *sel, int *slen_out)
{
    const void *txid = sqlite3_column_blob(sel, 0);
    if (!txid || sqlite3_column_bytes(sel, 0) != 32)
        return MIRROR_COIN_ROW_BAD_TXID;
    int slen = sqlite3_column_bytes(sel, 5);
    if (slen < 0) slen = 0;
    *slen_out = slen;
    if (slen > MAX_SCRIPT_SIZE)
        return MIRROR_COIN_ROW_BIG_SCRIPT;
    return MIRROR_COIN_ROW_OK;
}

/* Upsert the current (already checked) coins row and fold it into the
 * commitment. Returns the upsert result. */
static bool mirror_add_coin_row(struct node_db *ndb, struct addr_set *touched,
                                sqlite3_stmt *sel, int slen,
                                struct utxo_commitment *uc, bool track_commitment,
                                int32_t ch, int64_t *rows_changed)
{
    const void *txid = sqlite3_column_blob(sel, 0);
    const void *sc = sqlite3_column_blob(sel, 5);
    int64_t add_value = sqlite3_column_int64(sel, 2);
    int add_h_raw = sqlite3_column_int(sel, 3);
    bool ok = mirror_upsert_coin(ndb, touched,
                                 (const uint8_t *)txid,
                                 (uint32_t)sqlite3_column_int(sel, 1),
                                 add_value, add_h_raw,
                                 sqlite3_column_int(sel, 4) != 0,
                                 (const uint8_t *)sc, (size_t)slen);
    if (ok) {
        (*rows_changed)++;
        /* creation_height >= ch: skip a coin a prior (retried) attempt
         * already folded in — see the maybe_commitment_remove doc
         * comment for the matching REMOVE-side rationale. */
        int32_t add_h = add_h_raw < 0 ? 0 : add_h_raw;
        if (track_commitment && add_h >= ch)
            utxo_commitment_add(uc, (const uint8_t *)txid,
                                (uint32_t)sqlite3_column_int(sel, 1),
                                add_value, add_h);
    }
    return ok;
}

/* 2. DELETE spends: outpoints in spent_blob for the range. */
static bool mirror_delete_spends(struct node_db *ndb, sqlite3 *rdb,
                                 struct addr_set *touched, int64_t *rows_changed,
                                 struct utxo_commitment *uc, int32_t ch,
                                 int32_t cursor, int32_t upper)
{
    bool ok = true;
    sqlite3_stmt *sp = NULL;
    if (sqlite3_prepare_v2(rdb,
            "SELECT height, spent_blob FROM utxo_apply_delta "
            "WHERE height >= ? AND height < ? ORDER BY height",
            -1, &sp, NULL) != SQLITE_OK) {
        ok = false;
    } else {
        sqlite3_bind_int64(sp, 1, cursor);
        sqlite3_bind_int64(sp, 2, upper);
        while (ok) {
            int rc = sqlite3_step(sp);  // raw-sql-ok:progress-kv-kernel-store
            if (rc == SQLITE_DONE) break;
            if (rc != SQLITE_ROW) { ok = false; break; }
            int32_t spend_h = (int32_t)sqlite3_column_int64(sp, 0);
            const uint8_t *blob = sqlite3_column_blob(sp, 1);
            int blen = sqlite3_column_bytes(sp, 1);
            if (blen > 0 && blob)
                ok = mirror_apply_spent_blob(ndb, touched, blob, (size_t)blen,
                                             rows_changed, uc, ch, spend_h);
        }
    }
    sqlite3_finalize(sp);
    return ok;
}

/* 3. Re-derive the addresses + wallet_utxos caches for touched addresses. */
static bool mirror_refresh_touched(struct node_db *ndb, const struct addr_set *touched)
{
    bool ok = true;
    for (size_t i = 0; i < touched->cap && ok; i++) {
        if (!touched->used[i]) continue;
        ok = db_utxo_refresh_caches_for_address(ndb, touched->keys[i]);
    }
    return ok;
}

/* Reject unusable arguments before any work is done. */
static bool mirror_delta_args_ok(const struct node_db *ndb, int32_t cursor,
                                 int32_t frontier, const char *cursor_key,
                                 const int32_t *out_applied_through,
                                 const int64_t *out_rows_changed)
{
    if (!ndb || !ndb->open || !cursor_key || !cursor_key[0] ||
        !out_applied_through || !out_rows_changed)
        return false;
    return frontier > cursor;
}

/* Clamp the pass to max_heights when that is smaller than the span. */
static int32_t mirror_delta_upper(int32_t cursor, int32_t frontier,
                                  int32_t max_heights)
{
    int32_t upper = frontier;
    if (max_heights > 0 && (int64_t)cursor + max_heights < (int64_t)frontier)
        upper = cursor + max_heights;
    return upper;
}

/* Open progress.kv read-only; on failure nothing stays open and *rdb is NULL.
 * The caller logs. */
static bool mirror_open_progress_ro(const char *pkv_path, sqlite3 **rdb)
{
    *rdb = NULL;
    if (sqlite3_open_v2(pkv_path, rdb, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (*rdb) sqlite3_close(*rdb);
        *rdb = NULL;
        return false;
    }
    sqlite3_busy_timeout(*rdb, 5000);
    return true;
}

/* Load the height-stamped checkpoint; true only when its stamp is within
 * [cursor, upper]. */
static bool mirror_commitment_tracked(struct node_db *ndb, struct utxo_commitment *uc,
                                      int32_t cursor, int32_t upper, int32_t *ch)
{
    return utxo_commitment_load_checkpoint_at_height(ndb->db, uc, ch) &&
           *ch >= cursor && *ch <= upper;
}

/* Prepare and bind the live-coins query for [cursor, upper). */
static bool mirror_coins_query_open(sqlite3 *rdb, int32_t cursor, int32_t upper,
                                    sqlite3_stmt **sel)
{
    if (sqlite3_prepare_v2(rdb,
            "SELECT txid, vout, value, height, is_coinbase, script "
            "FROM coins WHERE height >= ? AND height < ? ORDER BY height",
            -1, sel, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int64(*sel, 1, cursor);
    sqlite3_bind_int64(*sel, 2, upper);
    return true;
}

enum mirror_coin_step {
    MIRROR_COIN_STEP_OK,
    MIRROR_COIN_STEP_DONE,
    MIRROR_COIN_STEP_FAIL,
    MIRROR_COIN_STEP_SKIP_BAD_TXID,
    MIRROR_COIN_STEP_SKIP_BIG_SCRIPT,
};

/* Advance the coins query one row and apply it; the caller logs skips. */
static enum mirror_coin_step mirror_coin_step_apply(
    struct node_db *ndb, struct addr_set *touched, sqlite3_stmt *sel,
    struct utxo_commitment *uc, bool track_commitment, int32_t ch,
    int64_t *rows_changed)
{
    int rc = sqlite3_step(sel);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_DONE) return MIRROR_COIN_STEP_DONE;
    if (rc != SQLITE_ROW) return MIRROR_COIN_STEP_FAIL;
    int slen = 0;
    enum mirror_coin_row kind = mirror_coin_row_check(sel, &slen);
    if (kind == MIRROR_COIN_ROW_BAD_TXID) return MIRROR_COIN_STEP_SKIP_BAD_TXID;
    if (kind == MIRROR_COIN_ROW_BIG_SCRIPT) return MIRROR_COIN_STEP_SKIP_BIG_SCRIPT;
    return mirror_add_coin_row(ndb, touched, sel, slen, uc, track_commitment,
                               ch, rows_changed)
               ? MIRROR_COIN_STEP_OK
               : MIRROR_COIN_STEP_FAIL;
}

/* Steps 2 and 3 after the adds: delete spends, close the read handle, refresh
 * the touched caches, free the touched set. */
static bool mirror_finish_range(struct node_db *ndb, sqlite3 *rdb,
                                struct addr_set *touched, int64_t *rows_changed,
                                struct utxo_commitment *uc, bool track_commitment,
                                int32_t ch, int32_t cursor, int32_t upper, bool ok)
{
    if (ok)
        ok = mirror_delete_spends(ndb, rdb, touched, rows_changed,
                                  track_commitment ? uc : NULL, ch,
                                  cursor, upper);
    sqlite3_close(rdb);

    if (ok)
        ok = mirror_refresh_touched(ndb, touched);
    addr_set_free(touched);
    return ok;
}

enum mirror_rollback_why {
    MIRROR_ROLLBACK_CHECKPOINT_GAP,
    MIRROR_ROLLBACK_AFTER_ERROR,
    MIRROR_ROLLBACK_COMMITMENT,
    MIRROR_ROLLBACK_CURSOR,
    MIRROR_ROLLBACK_COMMIT,
};

/* Roll node.db back. Log the selected failure when the rollback itself fails. */
static void mirror_rollback_warn(struct node_db *ndb, enum mirror_rollback_why why)
{
    if (node_db_rollback(ndb))
        return;
    switch (why) {
    case MIRROR_ROLLBACK_CHECKPOINT_GAP:
        LOG_WARN_IN("utxo_mirror_delta_apply", "utxo_mirror",
                    "delta: node.db ROLLBACK failed after checkpoint gap");
        break;
    case MIRROR_ROLLBACK_AFTER_ERROR:
        LOG_WARN_IN("utxo_mirror_delta_apply", "utxo_mirror",
                    "delta: node.db ROLLBACK failed after error");
        break;
    case MIRROR_ROLLBACK_COMMITMENT:
        LOG_WARN_IN("utxo_mirror_delta_apply", "utxo_mirror",
                    "delta: node.db ROLLBACK failed after commitment error");
        break;
    case MIRROR_ROLLBACK_CURSOR:
        LOG_WARN_IN("utxo_mirror_delta_apply", "utxo_mirror",
                    "delta: node.db ROLLBACK failed after cursor error");
        break;
    case MIRROR_ROLLBACK_COMMIT:
        LOG_WARN_IN("utxo_mirror_delta_apply", "utxo_mirror",
                    "delta: node.db ROLLBACK failed after commit fail");
        break;
    }
}

/* Upsert live coins in [cursor, upper). False when the query or an upsert fails. */
static bool mirror_apply_live_coins(struct node_db *ndb, sqlite3 *rdb,
                                    struct addr_set *touched,
                                    struct utxo_commitment *uc,
                                    bool track_commitment, int32_t ch,
                                    int32_t cursor, int32_t upper,
                                    int64_t *rows_changed)
{
    *rows_changed = 0;
    sqlite3_stmt *sel = NULL;
    bool ok = mirror_coins_query_open(rdb, cursor, upper, &sel);
    while (ok) {
        enum mirror_coin_step step =
            mirror_coin_step_apply(ndb, touched, sel, uc, track_commitment,
                                   ch, rows_changed);
        if (step == MIRROR_COIN_STEP_DONE) break;
        if (step == MIRROR_COIN_STEP_SKIP_BAD_TXID) {
            LOG_WARN_IN("utxo_mirror_delta_apply", "utxo_mirror",
                        "delta: malformed coin txid — skipping");
            continue;
        }
        if (step == MIRROR_COIN_STEP_SKIP_BIG_SCRIPT) {
            LOG_WARN_IN("utxo_mirror_delta_apply", "utxo_mirror",
                        "delta: oversize coin script — skipping");
            continue;
        }
        ok = step == MIRROR_COIN_STEP_OK;
    }
    sqlite3_finalize(sel);
    return ok;
}

static sqlite3 *mirror_delta_snapshot_open(const char *pkv_path,
    struct node_db *ndb, int32_t cursor, int32_t upper,
    uint8_t branch_hash[32], enum utxo_mirror_delta_status *status)
{
    sqlite3 *rdb = NULL;
    *status = UTXO_MIRROR_DELTA_ERROR;
    if (!mirror_open_progress_ro(pkv_path, &rdb))
        LOG_RETURN(NULL, "utxo_mirror",
                   "delta: open ro progress.kv failed: %s", pkv_path);
    if (sqlite3_exec(rdb, "BEGIN", NULL, NULL, NULL) != SQLITE_OK) {
        int rc = sqlite3_extended_errcode(rdb);
        sqlite3_close(rdb);
        LOG_RETURN(NULL, "utxo_mirror",
                   "delta: BEGIN authority snapshot failed: %s", sqlite3_errstr(rc));
    }

    int64_t delta_rows = mirror_count_delta_rows(rdb, cursor, upper);
    if (delta_rows != (int64_t)(upper - cursor)) {
        sqlite3_close(rdb);
        *status = UTXO_MIRROR_DELTA_FALLBACK;
        LOG_RETURN(NULL, "utxo_mirror",
                   "delta: utxo_apply_delta rows=%lld != span=%d [%d,%d) — quarantine",
                   (long long)delta_rows, upper - cursor, cursor, upper);
    }
    if (!mirror_delta_tip_hash(rdb, upper, branch_hash)) {
        sqlite3_close(rdb);
        *status = UTXO_MIRROR_DELTA_FALLBACK;
        LOG_RETURN(NULL, "utxo_mirror",
                   "delta: branch hash missing at tip height=%d — quarantine",
                   upper - 1);
    }

    bool has_start_hash = false;
    uint8_t start_hash[32];
    if (!utxo_mirror_node_branch_hash(ndb, start_hash, &has_start_hash)) {
        sqlite3_close(rdb);
        LOG_RETURN(NULL, "utxo_mirror",
                   "delta: stored branch identity is unreadable or malformed");
    }
    bool replay = has_start_hash && memcmp(start_hash, branch_hash, 32) == 0;
    if (has_start_hash && !replay &&
        utxo_mirror_branch_check(rdb, cursor, start_hash) != UTXO_MIRROR_BRANCH_OK) {
        sqlite3_close(rdb);
        *status = UTXO_MIRROR_DELTA_FALLBACK;
        LOG_RETURN(NULL, "utxo_mirror",
                   "delta: starting branch identity changed at height=%d — quarantine",
                   cursor - 1);
    }
    *status = UTXO_MIRROR_DELTA_OK;
    return rdb;
}

/* ── The delta pass ──────────────────────────────────────────────────── */

int utxo_mirror_delta_apply(struct node_db *ndb,
                            int32_t cursor, int32_t frontier,
                            int32_t max_heights,
                            const char *cursor_key,
                            int32_t *out_applied_through,
                            int64_t *out_rows_changed)
{
    if (!mirror_delta_args_ok(ndb, cursor, frontier, cursor_key,
                              out_applied_through, out_rows_changed))
        return UTXO_MIRROR_DELTA_ERROR;

    int32_t upper = mirror_delta_upper(cursor, frontier, max_heights);

    char pkv_path[PROGRESS_STORE_PATH_MAX];
    if (!progress_store_path(pkv_path, sizeof(pkv_path)))
        LOG_RETURN(UTXO_MIRROR_DELTA_ERROR, "utxo_mirror",
                   "delta: progress store path unavailable");

    enum utxo_mirror_delta_status snapshot_status = UTXO_MIRROR_DELTA_OK;
    uint8_t branch_hash[32];
    sqlite3 *rdb = mirror_delta_snapshot_open(pkv_path, ndb, cursor, upper,
                                              branch_hash, &snapshot_status);
    if (!rdb)
        return snapshot_status;

    if (!node_db_begin(ndb)) {
        sqlite3_close(rdb);
        LOG_RETURN(UTXO_MIRROR_DELTA_ERROR, "utxo_mirror", "delta: node.db BEGIN failed");
    }

    /* Height-tracked XOR checkpoint maintenance, atomic with this same
     * transaction (see UTXO_COMMITMENT_HEIGHT_KEY / utxo_commitment_load_
     * checkpoint_at_height). Trust it ONLY when its stamped `ch` is within
     * [cursor, upper]: `ch == cursor` is the steady state; `ch > cursor` is a
     * retry (a prior attempt's commitment update landed but the SEPARATE
     * mirror-cursor persist afterward failed — see mirror_persist_cursor's
     * caller, which intentionally leaves cursor unadvanced and re-runs the
     * same range); `ch < cursor` means an untracked gap exists (an upgrade
     * from a build that didn't maintain this stamp, or a resync via the
     * plain, unstamped utxo_commitment_save_checkpoint) — do NOT attempt
     * incremental math over an unknown gap, leave the checkpoint alone and
     * let the boot-time O(n) safety net (utxo_commitment_boot_check_and_
     * refresh) re-establish the stamp once. */
    struct utxo_commitment uc;
    utxo_commitment_init(&uc);
    int32_t ch = -1;
    bool track_commitment =
        mirror_commitment_tracked(ndb, &uc, cursor, upper, &ch);
    if (!track_commitment) {
        sqlite3_close(rdb);
        mirror_rollback_warn(ndb, MIRROR_ROLLBACK_CHECKPOINT_GAP);
        LOG_RETURN(UTXO_MIRROR_DELTA_FALLBACK, "utxo_mirror",
                   "delta: commitment checkpoint does not cover cursor=%d "
                   "upper=%d — quarantine", cursor, upper);
    }

    struct addr_set touched;
    memset(&touched, 0, sizeof(touched));
    int64_t rows_changed = 0;

    /* 1. UPSERT adds: live coins created in the range. */
    bool ok = mirror_apply_live_coins(ndb, rdb, &touched, &uc, track_commitment,
                                      ch, cursor, upper, &rows_changed);

    ok = mirror_finish_range(ndb, rdb, &touched, &rows_changed, &uc,
                             track_commitment, ch, cursor, upper, ok);

    if (!ok) {
        mirror_rollback_warn(ndb, MIRROR_ROLLBACK_AFTER_ERROR);
        LOG_RETURN(UTXO_MIRROR_DELTA_ERROR, "utxo_mirror",
                   "delta: aborted [%d,%d) after %lld ops",
                   cursor, upper, (long long)rows_changed);
    }

    /* Commitment, branch identity and next-height cursor are mandatory members
     * of this mirror transaction. Any failure rolls derived state back. */
    if (!utxo_commitment_save_checkpoint_at_height(ndb->db, &uc, upper)) {
        mirror_rollback_warn(ndb, MIRROR_ROLLBACK_COMMITMENT);
        LOG_RETURN(UTXO_MIRROR_DELTA_ERROR, "utxo_mirror",
                   "delta: commitment checkpoint save failed at frontier=%d",
                   upper);
    }
    if (!node_db_state_set(ndb, UTXO_MIRROR_BRANCH_HASH_KEY,
                           branch_hash, sizeof(branch_hash))) {
        mirror_rollback_warn(ndb, MIRROR_ROLLBACK_CURSOR);
        LOG_RETURN(UTXO_MIRROR_DELTA_ERROR, "utxo_mirror",
                   "delta: branch hash persist failed at frontier=%d", upper);
    }

    int64_t next_cursor = upper;
    if (!node_db_state_set(ndb, cursor_key, &next_cursor,
                           sizeof(next_cursor))) {
        mirror_rollback_warn(ndb, MIRROR_ROLLBACK_CURSOR);
        LOG_RETURN(UTXO_MIRROR_DELTA_ERROR, "utxo_mirror",
                   "delta: cursor persist failed at frontier=%d", upper);
    }

    if (!node_db_commit(ndb)) {
        mirror_rollback_warn(ndb, MIRROR_ROLLBACK_COMMIT);
        LOG_RETURN(UTXO_MIRROR_DELTA_ERROR, "utxo_mirror", "delta: node.db COMMIT failed");
    }

    *out_applied_through = upper;
    *out_rows_changed = rows_changed;
    return UTXO_MIRROR_DELTA_OK;
}

static struct db_service *mirror_db_service_for(struct node_db *ndb)
{
    struct db_service *dbsvc = app_runtime_db_service();

    if (!ndb || !dbsvc || !db_service_is_started(dbsvc))
        return NULL;
    return db_service_node_db(dbsvc) == ndb ? dbsvc : NULL;
}

bool utxo_mirror_sync_run_db_lane(struct node_db *ndb,
                                  db_service_write_fn fn, void *ctx)
{
    struct db_service *dbsvc = mirror_db_service_for(ndb);

    if (!ndb || !fn)
        return false;
    if (dbsvc)
        return db_service_run_write(dbsvc, fn, ctx);
    return fn(ndb, ctx);
}

struct mirror_checkpoint_adopt_ctx {
    struct utxo_mirror_sync_service *svc;
    int32_t cursor;
    const struct utxo_commitment *expected;
    const struct utxo_commitment *computed;
    int64_t tip;
    uint64_t generation;
    bool adopted;
    bool unsettled;
    char reason[96];
};

#ifdef ZCL_TESTING
static bool (*mirror_checkpoint_adopt_hook)(void *ctx);
static void *mirror_checkpoint_adopt_hook_ctx;

void utxo_mirror_sync_test_set_checkpoint_adopt_hook(bool (*fn)(void *ctx),
                                                     void *ctx)
{
    mirror_checkpoint_adopt_hook = fn;
    mirror_checkpoint_adopt_hook_ctx = ctx;
}
#endif

static const char *mirror_checkpoint_adoption_mismatch(
    struct node_db *ndb, const struct mirror_checkpoint_adopt_ctx *a)
{
    int64_t cursor = -1;
    struct utxo_commitment current;
    if (!node_db_state_get_int(ndb, UTXO_MIRROR_SYNC_CURSOR_KEY, &cursor) ||
        cursor != a->cursor)
        return "cursor missing or moved";
    if (!utxo_commitment_load_checkpoint(ndb->db, &current) ||
        !utxo_commitment_equal(&current, a->expected))
        return "checkpoint changed before adoption";
    if (tip_finalize_stage_last_height() != a->tip)
        return "tip moved before adoption";
    if (a->svc &&
        (atomic_load(&a->svc->updates_active) != 1 ||
         atomic_load(&a->svc->update_generation) != a->generation + 1))
        return "mirror update generation moved";
    return NULL;
}

static bool mirror_checkpoint_adopt_lane(struct node_db *ndb, void *ctx)
{
    struct mirror_checkpoint_adopt_ctx *a = ctx;
#ifdef ZCL_TESTING
    if (mirror_checkpoint_adopt_hook &&
        !mirror_checkpoint_adopt_hook(mirror_checkpoint_adopt_hook_ctx)) {
        (void)snprintf(a->reason, sizeof(a->reason), "test hook refused");
        return false;
    }
#endif
    if (!node_db_begin_immediate(ndb)) {
        if (!node_db_rollback(ndb))
            a->unsettled = true;
        (void)snprintf(a->reason, sizeof(a->reason), "begin immediate failed%s",
                       a->unsettled ? "; rollback failed" : "");
        return false;
    }

    const char *why = mirror_checkpoint_adoption_mismatch(ndb, a);
    if (!why && !utxo_commitment_save_checkpoint_at_height(
                    ndb->db, a->computed, a->cursor))
        why = "height-stamped checkpoint save failed";
    if (!why && !node_db_commit(ndb))
        why = "checkpoint commit failed";
    if (why) {
        if (!node_db_rollback(ndb))
            a->unsettled = true;
        (void)snprintf(a->reason, sizeof(a->reason), "%s%s", why,
                       a->unsettled ? "; rollback failed" : "");
        return false;
    }
    a->adopted = true;
    return true;
}

static enum utxo_mirror_checkpoint_adoption_result
mirror_checkpoint_adoption_finish(const struct mirror_checkpoint_adopt_ctx *a,
                                  bool lane_ok)
{
    if (a->unsettled || (lane_ok && !a->adopted)) {
        LOG_WARN("utxo_mirror", "checkpoint adoption UNSETTLED: %s",
                 a->reason[0] ? a->reason : "no adoption witness");
        return UTXO_MIRROR_CHECKPOINT_ADOPTION_UNSETTLED;
    }
    if (!lane_ok || !a->adopted) {
        LOG_INFO("utxo_mirror", "checkpoint adoption refused: %s",
                 a->reason[0] ? a->reason : "write lane failed");
        return UTXO_MIRROR_CHECKPOINT_ADOPTION_REFUSED;
    }
    LOG_INFO("utxo_mirror",
             "[utxo_cmt] checkpoint adopted count=%llu height=%d",
             (unsigned long long)a->computed->count, a->cursor);
    return UTXO_MIRROR_CHECKPOINT_ADOPTION_ADOPTED;
}

enum utxo_mirror_checkpoint_adoption_result utxo_mirror_sync_adopt_checkpoint(
    struct node_db *ndb, int32_t expected_cursor,
    const struct utxo_commitment *expected,
    const struct utxo_commitment *computed,
    int64_t expected_tip, uint64_t expected_generation)
{
    if (!ndb || !expected || !computed || expected_cursor < 0) {
        LOG_FAIL("utxo_mirror", "checkpoint adoption invalid arguments");
        return UTXO_MIRROR_CHECKPOINT_ADOPTION_REFUSED;
    }

    struct utxo_mirror_sync_service *svc = g_utxo_mirror_sync;
    if (svc && (svc->ndb != ndb ||
                atomic_load(&svc->updates_active) != 0 ||
                atomic_load(&svc->update_generation) != expected_generation)) {
        LOG_INFO("utxo_mirror",
                 "checkpoint adoption skipped: mirror changed before write");
        return UTXO_MIRROR_CHECKPOINT_ADOPTION_REFUSED;
    }

    struct mirror_checkpoint_adopt_ctx a = {
        .svc = svc,
        .cursor = expected_cursor,
        .expected = expected,
        .computed = computed,
        .tip = expected_tip,
        .generation = expected_generation,
        .adopted = false,
        .unsettled = false,
        .reason = {0},
    };
    if (svc) {
        atomic_fetch_add(&svc->updates_active, 1u);
        atomic_fetch_add(&svc->update_generation, 1u);
    }
    bool lane_ok = utxo_mirror_sync_run_db_lane(ndb, mirror_checkpoint_adopt_lane, &a);
    if (svc) {
        atomic_fetch_add(&svc->update_generation, 1u);
        atomic_fetch_sub(&svc->updates_active, 1u);
    }
    return mirror_checkpoint_adoption_finish(&a, lane_ok);
}
