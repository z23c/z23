/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: persist and restore transparent wallet keypool membership. */

#include "wallet_sqlite_internal.h"
#include "util/ar_step_readonly.h"
#include <string.h>

struct zcl_result wallet_sqlite_read_keypool_r(struct wallet_sqlite *ws,
                                                struct wallet *w)
{
    if (!ws || !w)
        return ZCL_ERR(WSQL_NULL_ARG,
                       "read_keypool: wallet_sqlite or wallet is NULL");
    if (!ws->open)
        return wsql_fail(ws, ZCL_ERR(WSQL_DB_NOT_OPEN,
            "read_keypool: wallet_sqlite is not open"));

    sqlite3_stmt *s = ws->stmt_keypool_read;
    sqlite3_reset(s);
    int loaded = 0;
    int rc;
    while ((rc = AR_STEP_ROW_READONLY(s)) == SQLITE_ROW) {
        const void *hash = sqlite3_column_blob(s, 0);
        int hash_len = sqlite3_column_bytes(s, 0);
        int64_t generation = sqlite3_column_int64(s, 1);
        struct key_id keyid;
        if (!hash || hash_len != (int)sizeof(keyid.id.data) || generation < 0) {
            sqlite3_reset(s);
            return wsql_fail(ws, ZCL_ERR(WSQL_READ_FAIL,
                "read_keypool: malformed row after %d entries", loaded));
        }
        memcpy(keyid.id.data, hash, sizeof(keyid.id.data));
        if (!wallet_key_pool_restore(w, &keyid, generation)) {
            sqlite3_reset(s);
            return wsql_fail(ws, ZCL_ERR(WSQL_READ_FAIL,
                "read_keypool: row is duplicate, unowned, or over capacity "
                "after %d entries", loaded));
        }
        loaded++;
    }
    sqlite3_reset(s);
    if (rc != SQLITE_DONE)
        return wsql_fail(ws, ZCL_ERR(WSQL_READ_FAIL,
            "read_keypool: step rc=%d after %d entries: %s",
            rc, loaded, sqlite3_errmsg(ws->db)));
    return ZCL_OK;
}

/* Called with w->cs held inside the surrounding SQLite transaction. Replacing
 * the full small set prevents a consumed change key returning after restart. */
bool wallet_sqlite_replace_keypool_locked(struct wallet_sqlite *ws,
                                          const struct wallet *w)
{
    sqlite3_stmt *clear = ws->stmt_keypool_clear;
    sqlite3_reset(clear);
    sqlite3_clear_bindings(clear);
    bool ok = AR_STEP_WRITE(clear) == SQLITE_DONE;
    sqlite3_reset(clear);
    if (!ok)
        return false; /* raw-return-ok:caller rolls back and reports */

    sqlite3_stmt *write = ws->stmt_keypool_write;
    for (size_t i = 0; i < w->key_pool_size; i++) {
        sqlite3_reset(write);
        sqlite3_clear_bindings(write);
        sqlite3_bind_blob(write, 1, w->key_pool[i].keyid.id.data,
                          sizeof(w->key_pool[i].keyid.id.data), SQLITE_STATIC);
        sqlite3_bind_int64(write, 2, w->key_pool[i].generation);
        if (AR_STEP_WRITE(write) != SQLITE_DONE) {
            sqlite3_reset(write);
            return false; /* raw-return-ok:caller rolls back and reports */
        }
    }
    sqlite3_reset(write);
    return true;
}
