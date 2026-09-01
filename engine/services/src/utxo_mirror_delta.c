/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_mirror_delta — implementation. See services/utxo_mirror_delta.h.
 */

// one-result-type-ok:delta-apply-3-valued-status — E2 (one way out): the one
// public fallible entry point (utxo_mirror_delta_apply) returns a single domain
// enum, utxo_mirror_delta_status (OK / ERROR / FALLBACK-to-full-rebuild). A
// struct zcl_result's bool+message cannot express the three-way FALLBACK
// outcome, and every failure IS logged via LOG_RETURN/LOG_FAIL. This is a
// stateless helper invoked by the utxo_mirror_sync service, not a lifecycle
// service surface of its own.
#include "services/utxo_mirror_delta.h"

#include "coins/utxo_commitment.h"
#include "models/database.h"
#include "models/utxo.h"
#include "script/script.h"    /* MAX_SCRIPT_SIZE */
#include "script/standard.h"  /* utxo_classify_script */
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <sqlite3.h>
#include <stdint.h>
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

/* ── The delta pass ──────────────────────────────────────────────────── */

int utxo_mirror_delta_apply(struct node_db *ndb,
                            int32_t cursor, int32_t frontier,
                            int32_t max_heights,
                            const char *cursor_key,
                            int32_t *out_applied_through,
                            int64_t *out_rows_changed)
{
    if (!ndb || !ndb->open || !cursor_key || !cursor_key[0] ||
        !out_applied_through || !out_rows_changed)
        return UTXO_MIRROR_DELTA_ERROR;
    if (frontier <= cursor)
        return UTXO_MIRROR_DELTA_ERROR;

    int32_t upper = frontier;
    if (max_heights > 0 && (int64_t)cursor + max_heights < (int64_t)frontier)
        upper = cursor + max_heights;

    char pkv_path[PROGRESS_STORE_PATH_MAX];
    if (!progress_store_path(pkv_path, sizeof(pkv_path)))
        LOG_RETURN(UTXO_MIRROR_DELTA_ERROR, "utxo_mirror",
                   "delta: progress store path unavailable");

    sqlite3 *rdb = NULL;
    if (sqlite3_open_v2(pkv_path, &rdb, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (rdb) sqlite3_close(rdb);
        LOG_RETURN(UTXO_MIRROR_DELTA_ERROR, "utxo_mirror",
                   "delta: open ro progress.kv failed: %s", pkv_path);
    }
    sqlite3_busy_timeout(rdb, 5000);

    /* Missing utxo_apply_delta rows in the range mean the spent side would be
     * incomplete → refuse the delta and let the caller quarantine. Every
     * applied height persists a row (utxo_apply_stage.c), so the count must
     * equal the height span. */
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
    if (delta_rows != (int64_t)(upper - cursor)) {
        sqlite3_close(rdb);
        LOG_RETURN(UTXO_MIRROR_DELTA_FALLBACK, "utxo_mirror",
                   "delta: utxo_apply_delta rows=%lld != span=%d [%d,%d) — quarantine",
                   (long long)delta_rows, upper - cursor, cursor, upper);
    }

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
        utxo_commitment_load_checkpoint_at_height(ndb->db, &uc, &ch) &&
        ch >= cursor && ch <= upper;
    if (!track_commitment) {
        sqlite3_close(rdb);
        if (!node_db_rollback(ndb))
            LOG_WARN("utxo_mirror",
                     "delta: node.db ROLLBACK failed after checkpoint gap");
        LOG_RETURN(UTXO_MIRROR_DELTA_FALLBACK, "utxo_mirror",
                   "delta: commitment checkpoint does not cover cursor=%d "
                   "upper=%d — quarantine", cursor, upper);
    }

    struct addr_set touched;
    memset(&touched, 0, sizeof(touched));
    int64_t rows_changed = 0;
    bool ok = true;

    /* 1. UPSERT adds: live coins created in the range. */
    sqlite3_stmt *sel = NULL;
    if (sqlite3_prepare_v2(rdb,
            "SELECT txid, vout, value, height, is_coinbase, script "
            "FROM coins WHERE height >= ? AND height < ? ORDER BY height",
            -1, &sel, NULL) != SQLITE_OK) {
        ok = false;
    } else {
        sqlite3_bind_int64(sel, 1, cursor);
        sqlite3_bind_int64(sel, 2, upper);
        while (ok) {
            int rc = sqlite3_step(sel);  // raw-sql-ok:progress-kv-kernel-store
            if (rc == SQLITE_DONE) break;
            if (rc != SQLITE_ROW) { ok = false; break; }
            const void *txid = sqlite3_column_blob(sel, 0);
            if (!txid || sqlite3_column_bytes(sel, 0) != 32) {
                LOG_WARN("utxo_mirror", "delta: malformed coin txid — skipping");
                continue;
            }
            const void *sc = sqlite3_column_blob(sel, 5);
            int slen = sqlite3_column_bytes(sel, 5);
            if (slen < 0) slen = 0;
            if (slen > MAX_SCRIPT_SIZE) {
                LOG_WARN("utxo_mirror", "delta: oversize coin script — skipping");
                continue;
            }
            int64_t add_value = sqlite3_column_int64(sel, 2);
            int add_h_raw = sqlite3_column_int(sel, 3);
            ok = mirror_upsert_coin(ndb, &touched,
                                    (const uint8_t *)txid,
                                    (uint32_t)sqlite3_column_int(sel, 1),
                                    add_value, add_h_raw,
                                    sqlite3_column_int(sel, 4) != 0,
                                    (const uint8_t *)sc, (size_t)slen);
            if (ok) {
                rows_changed++;
                /* creation_height >= ch: skip a coin a prior (retried) attempt
                 * already folded in — see the maybe_commitment_remove doc
                 * comment for the matching REMOVE-side rationale. */
                int32_t add_h = add_h_raw < 0 ? 0 : add_h_raw;
                if (track_commitment && add_h >= ch)
                    utxo_commitment_add(&uc, (const uint8_t *)txid,
                                        (uint32_t)sqlite3_column_int(sel, 1),
                                        add_value, add_h);
            }
        }
    }
    sqlite3_finalize(sel);

    /* 2. DELETE spends: outpoints in spent_blob for the range. */
    sqlite3_stmt *sp = NULL;
    if (ok && sqlite3_prepare_v2(rdb,
            "SELECT height, spent_blob FROM utxo_apply_delta "
            "WHERE height >= ? AND height < ? ORDER BY height",
            -1, &sp, NULL) != SQLITE_OK) {
        ok = false;
    } else if (ok) {
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
                ok = mirror_apply_spent_blob(ndb, &touched, blob, (size_t)blen,
                                             &rows_changed,
                                             track_commitment ? &uc : NULL, ch,
                                             spend_h);
        }
    }
    sqlite3_finalize(sp);
    sqlite3_close(rdb);

    /* 3. Re-derive the addresses + wallet_utxos caches for touched addresses. */
    if (ok) {
        for (size_t i = 0; i < touched.cap && ok; i++) {
            if (!touched.used[i]) continue;
            ok = db_utxo_refresh_caches_for_address(ndb, touched.keys[i]);
        }
    }
    addr_set_free(&touched);

    if (!ok) {
        if (!node_db_rollback(ndb))
            LOG_WARN("utxo_mirror", "delta: node.db ROLLBACK failed after error");
        LOG_RETURN(UTXO_MIRROR_DELTA_ERROR, "utxo_mirror",
                   "delta: aborted [%d,%d) after %lld ops",
                   cursor, upper, (long long)rows_changed);
    }

    /* Commitment and next-height cursor are mandatory members of this mirror
     * transaction. Any failure rolls every derived row and cache back. */
    if (!utxo_commitment_save_checkpoint_at_height(ndb->db, &uc, upper)) {
        if (!node_db_rollback(ndb))
            LOG_WARN("utxo_mirror",
                     "delta: node.db ROLLBACK failed after commitment error");
        LOG_RETURN(UTXO_MIRROR_DELTA_ERROR, "utxo_mirror",
                   "delta: commitment checkpoint save failed at frontier=%d",
                   upper);
    }

    int64_t next_cursor = upper;
    if (!node_db_state_set(ndb, cursor_key, &next_cursor,
                           sizeof(next_cursor))) {
        if (!node_db_rollback(ndb))
            LOG_WARN("utxo_mirror",
                     "delta: node.db ROLLBACK failed after cursor error");
        LOG_RETURN(UTXO_MIRROR_DELTA_ERROR, "utxo_mirror",
                   "delta: cursor persist failed at frontier=%d", upper);
    }

    if (!node_db_commit(ndb)) {
        if (!node_db_rollback(ndb))
            LOG_WARN("utxo_mirror", "delta: node.db ROLLBACK failed after commit fail");
        LOG_RETURN(UTXO_MIRROR_DELTA_ERROR, "utxo_mirror", "delta: node.db COMMIT failed");
    }

    *out_applied_through = upper;
    *out_rows_changed = rows_changed;
    return UTXO_MIRROR_DELTA_OK;
}
