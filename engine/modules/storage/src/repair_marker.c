/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * repair_marker — implementation. See storage/repair_marker.h.
 *
 * This module sits below the AR lifecycle, in the same kernel store as
 * progress_meta / stage_cursor, so its direct sqlite3_step calls carry the
 * kernel-primitive marker (the (kind,height,hash) rows are not models). It
 * borrows the singleton consensus.db handle's transaction lock from
 * progress_store — one file, one writer-actor — so every SQL touch here is
 * serialized on progress_store_tx_lock(). */

#include "storage/repair_marker.h"

#include "core/uint256.h"
#include "platform/time_compat.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int64_t repair_marker_now_s(void)
{
    struct timespec ts;
    platform_time_realtime_timespec(&ts);
    return (int64_t)ts.tv_sec;
}

bool repair_marker_table_ensure(sqlite3 *db)
{
    if (!db)
        return false;  // raw-return-ok:null-db-no-context
    char *err = NULL;
    /* WITHOUT ROWID matches the sibling kernel tables (coins_kv, anchor_kv,
     * nullifier_kv): the composite PRIMARY KEY (kind,height,hash) IS the row
     * identity, so a rowid would only bloat the b-tree. */
    int rc = sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS repair_marker ("
        "  kind       TEXT NOT NULL,"
        "  height     INTEGER NOT NULL,"
        "  hash       BLOB NOT NULL,"
        "  payload    BLOB,"
        "  created_at INTEGER NOT NULL,"
        "  PRIMARY KEY(kind, height, hash)"
        ") WITHOUT ROWID",
        NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        LOG_WARN("repair_marker",
                 "[repair_marker] CREATE TABLE failed: %s",
                 err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;  // raw-return-ok:create-failure-logged
    }
    return true;
}

/* INSERT OR REPLACE the marker; the statement enrolls in whatever transaction
 * the connection currently has open. `hash32` must be 32 bytes. */
static bool repair_marker_note_stmt(sqlite3 *db, const char *kind,
                                    int64_t height, const uint8_t hash32[32],
                                    const void *payload, size_t payload_len)
{
    if (!db || !kind || !kind[0] || !hash32)
        return false;  // raw-return-ok:bad-input-caller-logs
    if (payload_len > 0 && !payload)
        return false;  // raw-return-ok:bad-input-caller-logs
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO repair_marker"
            "(kind, height, hash, payload, created_at) VALUES(?,?,?,?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;  // raw-return-ok:prepare-failure-caller-logs
    sqlite3_bind_text(st, 1, kind, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, height);
    sqlite3_bind_blob(st, 3, hash32, 32, SQLITE_TRANSIENT);
    if (payload_len > 0)
        sqlite3_bind_blob(st, 4, payload, (int)payload_len, SQLITE_TRANSIENT);
    else
        sqlite3_bind_null(st, 4);
    sqlite3_bind_int64(st, 5, repair_marker_now_s());
    int rc = sqlite3_step(st);  // raw-sql-ok:kernel-primitive
    sqlite3_finalize(st);
    return rc == SQLITE_DONE;
}

static bool repair_marker_forget_stmt(sqlite3 *db, const char *kind,
                                      int64_t height, const uint8_t hash32[32])
{
    if (!db || !kind || !kind[0] || !hash32)
        return false;  // raw-return-ok:bad-input-caller-logs
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "DELETE FROM repair_marker WHERE kind=? AND height=? AND hash=?",
            -1, &st, NULL) != SQLITE_OK)
        return false;  // raw-return-ok:prepare-failure-caller-logs
    sqlite3_bind_text(st, 1, kind, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, height);
    sqlite3_bind_blob(st, 3, hash32, 32, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);  // raw-sql-ok:kernel-primitive
    sqlite3_finalize(st);
    return rc == SQLITE_DONE;
}

bool repair_marker_note_in_tx(sqlite3 *db, const char *kind, int64_t height,
                              const uint8_t hash32[32],
                              const void *payload, size_t payload_len)
{
    if (!repair_marker_note_stmt(db, kind, height, hash32, payload,
                                 payload_len))
        LOG_FAIL("repair_marker",
                 "[repair_marker] note_in_tx failed kind=%s h=%lld",
                 kind ? kind : "(null)", (long long)height);
    return true;
}

bool repair_marker_forget_in_tx(sqlite3 *db, const char *kind, int64_t height,
                                const uint8_t hash32[32])
{
    if (!repair_marker_forget_stmt(db, kind, height, hash32))
        LOG_FAIL("repair_marker",
                 "[repair_marker] forget_in_tx failed kind=%s h=%lld",
                 kind ? kind : "(null)", (long long)height);
    return true;
}

/* Batch-aware own-tx runner (same discipline as progress_meta_run_in_tx): when
 * a transaction is already open on the connection, nest a named savepoint so
 * the op enrolls in the outer transaction; otherwise a bare BEGIN IMMEDIATE.
 * The savepoint name is distinct from every other module's so it never
 * collides. `op` binds and steps its own statement. */
#define REPAIR_MARKER_SP "repair_marker_write"

static void repair_marker_txn_rollback(sqlite3 *db, bool nested)
{
    if (nested) {
        sqlite3_exec(db, "ROLLBACK TO SAVEPOINT " REPAIR_MARKER_SP,
                     NULL, NULL, NULL);
        sqlite3_exec(db, "RELEASE SAVEPOINT " REPAIR_MARKER_SP, NULL, NULL, NULL);
    } else {
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    }
}

static bool repair_marker_run_in_tx(sqlite3 *db,
                                    bool (*op)(sqlite3 *, void *), void *arg)
{
    if (!db)
        return false;  // raw-return-ok:null-db-no-context
    progress_store_tx_lock();
    bool nested = sqlite3_get_autocommit(db) == 0;
    if (sqlite3_exec(db, nested ? "SAVEPOINT " REPAIR_MARKER_SP
                                : "BEGIN IMMEDIATE",
                     NULL, NULL, NULL) != SQLITE_OK) {
        progress_store_tx_unlock();
        return false;  // raw-return-ok:begin-failure-caller-logs
    }
    bool ok = op(db, arg);
    if (!ok) {
        repair_marker_txn_rollback(db, nested);
        progress_store_tx_unlock();
        return false;  // raw-return-ok:op-failure-op-logs
    }
    const char *fini = nested ? "RELEASE SAVEPOINT " REPAIR_MARKER_SP : "COMMIT";
    if (sqlite3_exec(db, fini, NULL, NULL, NULL) != SQLITE_OK) {
        repair_marker_txn_rollback(db, nested);
        progress_store_tx_unlock();
        return false;  // raw-return-ok:commit-failure-caller-logs
    }
    progress_store_tx_unlock();
    return true;
}

struct repair_marker_note_args {
    const char *kind;
    int64_t height;
    const uint8_t *hash32;
    const void *payload;
    size_t payload_len;
};

static bool repair_marker_note_op(sqlite3 *db, void *arg)
{
    struct repair_marker_note_args *a = arg;
    return repair_marker_note_stmt(db, a->kind, a->height, a->hash32,
                                   a->payload, a->payload_len);
}

struct repair_marker_forget_args {
    const char *kind;
    int64_t height;
    const uint8_t *hash32;
};

static bool repair_marker_forget_op(sqlite3 *db, void *arg)
{
    struct repair_marker_forget_args *a = arg;
    return repair_marker_forget_stmt(db, a->kind, a->height, a->hash32);
}

bool repair_marker_note(sqlite3 *db, const char *kind, int64_t height,
                        const uint8_t hash32[32],
                        const void *payload, size_t payload_len)
{
    struct repair_marker_note_args a = { kind, height, hash32, payload,
                                         payload_len };
    if (!repair_marker_run_in_tx(db, repair_marker_note_op, &a))
        LOG_FAIL("repair_marker",
                 "[repair_marker] note failed kind=%s h=%lld",
                 kind ? kind : "(null)", (long long)height);
    return true;
}

bool repair_marker_forget(sqlite3 *db, const char *kind, int64_t height,
                          const uint8_t hash32[32])
{
    struct repair_marker_forget_args a = { kind, height, hash32 };
    if (!repair_marker_run_in_tx(db, repair_marker_forget_op, &a))
        LOG_FAIL("repair_marker",
                 "[repair_marker] forget failed kind=%s h=%lld",
                 kind ? kind : "(null)", (long long)height);
    return true;
}

bool repair_marker_have(sqlite3 *db, const char *kind, int64_t height,
                        const uint8_t hash32[32], bool *out_have,
                        void *payload_out, size_t payload_cap,
                        size_t *payload_len)
{
    if (out_have) *out_have = false;
    if (payload_len) *payload_len = 0;
    if (!db || !kind || !kind[0] || !hash32 || !out_have)
        return false;  // raw-return-ok:bad-input-caller-logs

    progress_store_tx_lock();
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT payload FROM repair_marker "
            "WHERE kind=? AND height=? AND hash=?",
            -1, &st, NULL) != SQLITE_OK) {
        progress_store_tx_unlock();
        return false;  // raw-return-ok:prepare-failure-caller-logs
    }
    sqlite3_bind_text(st, 1, kind, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, height);
    sqlite3_bind_blob(st, 3, hash32, 32, SQLITE_TRANSIENT);

    int rc = sqlite3_step(st);  // raw-sql-ok:kernel-primitive
    bool ok = true;
    if (rc == SQLITE_ROW) {
        *out_have = true;
        int n = sqlite3_column_bytes(st, 0);
        const void *blob = sqlite3_column_blob(st, 0);
        if (payload_len) *payload_len = (size_t)(n < 0 ? 0 : n);
        if (payload_out && payload_cap > 0 && n > 0) {
            size_t copy = (size_t)n < payload_cap ? (size_t)n : payload_cap;
            if (blob && copy > 0) memcpy(payload_out, blob, copy);
        }
    } else if (rc != SQLITE_DONE) {
        ok = false;
    }
    sqlite3_finalize(st);
    progress_store_tx_unlock();
    return ok;
}

struct repair_marker_gc_args {
    const char *kind;
    int64_t below;
    int deleted;
};

static bool repair_marker_gc_op(sqlite3 *db, void *arg)
{
    struct repair_marker_gc_args *a = arg;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "DELETE FROM repair_marker WHERE kind=? AND height<?",
            -1, &st, NULL) != SQLITE_OK)
        return false;  // raw-return-ok:prepare-failure-caller-logs
    sqlite3_bind_text(st, 1, a->kind, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, a->below);
    int rc = sqlite3_step(st);  // raw-sql-ok:kernel-primitive
    if (rc == SQLITE_DONE)
        a->deleted = sqlite3_changes(db);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE;
}

int repair_marker_gc_below(sqlite3 *db, const char *kind, int64_t below)
{
    if (!db || !kind || !kind[0])
        return -1;  // raw-return-ok:bad-input-tri-state-error
    struct repair_marker_gc_args a = { kind, below, 0 };
    if (!repair_marker_run_in_tx(db, repair_marker_gc_op, &a)) {
        LOG_WARN("repair_marker",
                 "[repair_marker] gc_below failed kind=%s below=%lld",
                 kind, (long long)below);
        return -1;  // raw-return-ok:gc-failure-logged
    }
    return a.deleted;
}

int repair_marker_gc_settled(sqlite3 *db, int64_t hstar)
{
    if (!db || hstar <= REPAIR_MARKER_GC_RETENTION)
        return 0;  // raw-return-ok:nothing-settled-yet
    int64_t below = hstar - REPAIR_MARKER_GC_RETENTION;
    static const char *const kinds[] = {
        REPAIR_MARKER_KIND_UTXO_VALUE_OVERFLOW,
        REPAIR_MARKER_KIND_COIN_BACKFILL_ROUNDS,
        REPAIR_MARKER_KIND_COIN_BACKFILL_REFUSED,
        REPAIR_MARKER_KIND_COIN_BACKFILL_SCAN,
        REPAIR_MARKER_KIND_RF_PROOF_REPLAY,
        REPAIR_MARKER_KIND_RF_TIPFIN_BACKFILL,
    };
    int total = 0;
    for (size_t i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
        int d = repair_marker_gc_below(db, kinds[i], below);
        if (d < 0)
            return -1;  // raw-return-ok:gc-failure-logged-in-callee
        total += d;
    }
    return total;
}

/* ── One-time migration from the four legacy progress_meta namespaces ── */

/* True iff `s` (length `n`) is all lowercase-or-uppercase hex. */
static bool all_hex(const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                   (c >= 'A' && c <= 'F');
        if (!hex)
            return false;
    }
    return true;
}

/* True iff `s` (length `n`) is a non-empty run of decimal digits. */
static bool all_digits(const char *s, size_t n)
{
    if (n == 0)
        return false;
    for (size_t i = 0; i < n; i++)
        if (s[i] < '0' || s[i] > '9')
            return false;
    return true;
}

/* Does `prefix` (length `plen`) name one of the four migratable namespaces?
 * The reducer_frontier / utxo_apply namespaces are pattern-matched
 * ("reducer_frontier."…"_repair", "utxo_apply."…"_repair") because their
 * infix varies; the coin_backfill sub-namespaces are exact. */
static bool prefix_is_migratable(const char *prefix, size_t plen)
{
    struct exact { const char *s; size_t n; };
    static const struct exact exacts[] = {
        { REPAIR_MARKER_KIND_COIN_BACKFILL_ROUNDS,
          sizeof(REPAIR_MARKER_KIND_COIN_BACKFILL_ROUNDS) - 1 },
        { REPAIR_MARKER_KIND_COIN_BACKFILL_REFUSED,
          sizeof(REPAIR_MARKER_KIND_COIN_BACKFILL_REFUSED) - 1 },
        { REPAIR_MARKER_KIND_COIN_BACKFILL_SCAN,
          sizeof(REPAIR_MARKER_KIND_COIN_BACKFILL_SCAN) - 1 },
    };
    for (size_t i = 0; i < sizeof(exacts) / sizeof(exacts[0]); i++)
        if (plen == exacts[i].n && memcmp(prefix, exacts[i].s, plen) == 0)
            return true;

    struct pat { const char *head; size_t hn; };
    static const struct pat pats[] = {
        { "utxo_apply.", 11 },
        { "reducer_frontier.", 17 },
    };
    static const char k_repair[] = "_repair";
    const size_t rn = sizeof(k_repair) - 1;
    for (size_t i = 0; i < sizeof(pats) / sizeof(pats[0]); i++) {
        if (plen > pats[i].hn + rn &&
            memcmp(prefix, pats[i].head, pats[i].hn) == 0 &&
            memcmp(prefix + plen - rn, k_repair, rn) == 0)
            return true;
    }
    return false;
}

/* Parse a legacy per-(height,hash) key "<prefix>.<height>.<64hex>". On a match
 * copies the prefix into out_kind (<= out_cap-1 chars), sets *out_height and
 * out_hash32 (reconstructed via uint256_set_hex — the exact inverse of the
 * uint256_get_hex that built the key, so it round-trips regardless of byte
 * order). Returns false if the key does not have this shape or the prefix is
 * not one of the four namespaces. */
static bool parse_legacy_hh_key(const char *key, char *out_kind, size_t out_cap,
                                int64_t *out_height, uint8_t out_hash32[32])
{
    size_t len = strlen(key);
    if (len < 1 + 1 + 64 + 1)  /* p.h.hash needs at least this */
        return false;
    /* Last '.' -> the 64-hex hash tail. */
    const char *dot2 = strrchr(key, '.');
    if (!dot2)
        return false;
    const char *hash_hex = dot2 + 1;
    size_t hash_len = len - (size_t)(hash_hex - key);
    if (hash_len != 64 || !all_hex(hash_hex, 64))
        return false;
    /* '.' before that -> the height segment. */
    const char *dot1 = NULL;
    for (const char *p = dot2 - 1; p >= key; p--) {
        if (*p == '.') { dot1 = p; break; }
        if (p == key) break;
    }
    if (!dot1 || dot1 == key)
        return false;
    const char *h_str = dot1 + 1;
    size_t h_len = (size_t)(dot2 - h_str);
    if (!all_digits(h_str, h_len))
        return false;
    size_t plen = (size_t)(dot1 - key);
    if (plen == 0 || plen >= out_cap)
        return false;
    if (!prefix_is_migratable(key, plen))
        return false;

    char hbuf[24];
    if (h_len >= sizeof(hbuf))
        return false;
    memcpy(hbuf, h_str, h_len);
    hbuf[h_len] = '\0';
    long long hv = strtoll(hbuf, NULL, 10);
    if (hv < 0)
        return false;

    struct uint256 u;
    uint256_set_hex(&u, hash_hex);
    memcpy(out_hash32, u.data, 32);
    memcpy(out_kind, key, plen);
    out_kind[plen] = '\0';
    *out_height = (int64_t)hv;
    return true;
}

struct legacy_marker {
    char kind[192];
    int64_t height;
    uint8_t hash[32];
    uint8_t *payload;  /* heap-owned; may be NULL for a 0-length value */
    size_t payload_len;
    char oldkey[256];
};

#define REPAIR_MARKER_MIGRATE_CHUNK 1024

static void free_chunk(struct legacy_marker *buf, size_t n)
{
    for (size_t i = 0; i < n; i++)
        free(buf[i].payload);
}

/* Gather up to CHUNK still-present legacy markers. Returns count (>=0) or -1 on
 * error. Runs under progress_store_tx_lock (held by the caller). */
static int migrate_gather_chunk(sqlite3 *db, struct legacy_marker *buf)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "SELECT key, value FROM progress_meta",
                           -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("repair_marker",
                 "[repair_marker] migrate gather prepare failed: %s",
                 sqlite3_errmsg(db));
        return -1;
    }
    int n = 0;
    int rc;
    while (n < REPAIR_MARKER_MIGRATE_CHUNK &&
           (rc = sqlite3_step(st)) == SQLITE_ROW) {  // raw-sql-ok:kernel-primitive
        const char *key = (const char *)sqlite3_column_text(st, 0);
        if (!key)
            continue;
        struct legacy_marker *m = &buf[n];
        bool matched = false;
        if (strcmp(key, REPAIR_MARKER_KIND_TIPFIN_PROGRESS) == 0) {
            snprintf(m->kind, sizeof(m->kind), "%s",
                     REPAIR_MARKER_KIND_TIPFIN_PROGRESS);
            m->height = REPAIR_MARKER_TIPFIN_HEIGHT;
            memset(m->hash, 0, 32);
            matched = true;
        } else if (parse_legacy_hh_key(key, m->kind, sizeof(m->kind),
                                       &m->height, m->hash)) {
            matched = true;
        }
        if (!matched)
            continue;
        if (strlen(key) >= sizeof(m->oldkey))
            continue;  /* absurd key length; never one of ours */
        snprintf(m->oldkey, sizeof(m->oldkey), "%s", key);
        int vn = sqlite3_column_bytes(st, 1);
        const void *vb = sqlite3_column_blob(st, 1);
        m->payload = NULL;
        m->payload_len = 0;
        if (vn > 0 && vb) {
            m->payload = zcl_malloc((size_t)vn, "repair_marker_migrate_payload");
            if (!m->payload) {
                sqlite3_finalize(st);
                free_chunk(buf, (size_t)n);
                LOG_WARN("repair_marker",
                         "[repair_marker] migrate payload alloc failed len=%d",
                         vn);
                return -1;
            }
            memcpy(m->payload, vb, (size_t)vn);
            m->payload_len = (size_t)vn;
        }
        n++;
    }
    sqlite3_finalize(st);
    return n;
}

bool repair_marker_migrate_from_progress_meta(sqlite3 *db)
{
    if (!db)
        LOG_FAIL("repair_marker", "[repair_marker] migrate: NULL db");

    struct legacy_marker *buf = zcl_malloc(
        REPAIR_MARKER_MIGRATE_CHUNK * sizeof(*buf), "repair_marker_migrate_buf");
    if (!buf)
        LOG_FAIL("repair_marker", "[repair_marker] migrate: buffer alloc failed");

    bool ok = true;
    for (;;) {
        progress_store_tx_lock();
        int n = migrate_gather_chunk(db, buf);
        if (n < 0) {
            progress_store_tx_unlock();
            ok = false;
            break;
        }
        if (n == 0) {
            progress_store_tx_unlock();
            break;  /* nothing left — converged */
        }
        if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
            free_chunk(buf, (size_t)n);
            progress_store_tx_unlock();
            LOG_WARN("repair_marker", "[repair_marker] migrate BEGIN failed: %s",
                     sqlite3_errmsg(db));
            ok = false;
            break;
        }
        bool chunk_ok = true;
        for (int i = 0; i < n && chunk_ok; i++) {
            if (!repair_marker_note_stmt(db, buf[i].kind, buf[i].height,
                                         buf[i].hash, buf[i].payload,
                                         buf[i].payload_len)) {
                chunk_ok = false;
                break;
            }
            sqlite3_stmt *del = NULL;
            if (sqlite3_prepare_v2(db,
                    "DELETE FROM progress_meta WHERE key=?",
                    -1, &del, NULL) != SQLITE_OK) {
                chunk_ok = false;
                break;
            }
            sqlite3_bind_text(del, 1, buf[i].oldkey, -1, SQLITE_TRANSIENT);
            int drc = sqlite3_step(del);  // raw-sql-ok:kernel-primitive
            sqlite3_finalize(del);
            if (drc != SQLITE_DONE)
                chunk_ok = false;
        }
        if (chunk_ok &&
            sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
            LOG_WARN("repair_marker", "[repair_marker] migrate COMMIT failed: %s",
                     sqlite3_errmsg(db));
            chunk_ok = false;
        }
        if (!chunk_ok)
            sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        free_chunk(buf, (size_t)n);
        progress_store_tx_unlock();
        if (!chunk_ok) {
            ok = false;
            break;
        }
    }

    free(buf);
    if (!ok)
        LOG_FAIL("repair_marker",
                 "[repair_marker] migration from progress_meta failed");
    return true;
}
