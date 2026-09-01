/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet persistence canary — see wallet_canary.h for rationale. */

#include "platform/time_compat.h"
#include "wallet/wallet_canary.h"
#include "wallet/wallet_sqlite.h"

#include "core/random.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define CANARY_PROBE_LEN 32

static pthread_mutex_t             g_status_lock = PTHREAD_MUTEX_INITIALIZER;
static struct wallet_canary_status g_status = { 0 };

static int64_t now_unix(void)
{
    return platform_time_wall_unix();
}

static void set_status(bool ok, int code, int64_t now, const char *msg)
{
    pthread_mutex_lock(&g_status_lock);
    g_status.ok   = ok;
    g_status.code = code;
    g_status.last_attempt_ts = now;
    if (ok) g_status.last_ok_ts = now;
    if (msg) {
        snprintf(g_status.error, sizeof(g_status.error), "%s", msg);
    } else {
        g_status.error[0] = '\0';
    }
    pthread_mutex_unlock(&g_status_lock);
}

static int fail(int code, struct wallet_canary_status *out,
                const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    int64_t now = now_unix();
    set_status(false, code, now, buf);
    if (out) *out = wallet_canary_get_status();
    fprintf(stderr, "[wallet_canary] %s:%d %s(): code=%d: %s\n",  // obs-ok:pre-existing-diagnostic
            __FILE__, __LINE__, __func__, code, buf);
    return code;
}

int wallet_canary_run(sqlite3 *db, struct wallet_canary_status *out_status)
{
    if (!db)
        return fail(WALLET_CANARY_ERR_NULL_DB, out_status,
                    "sqlite3 handle is NULL");

    /* 1. Random probe. */
    unsigned char probe[CANARY_PROBE_LEN];
    GetRandBytes(probe, sizeof(probe));
    /* Paranoia: reject all-zero probe (vanishingly unlikely, but a
     * zero-filled buffer might indicate GetRandBytes misconfiguration
     * and would silently "match" a zero-filled read). */
    bool all_zero = true;
    for (size_t i = 0; i < sizeof(probe); i++) {
        if (probe[i] != 0) { all_zero = false; break; }
    }
    if (all_zero)
        return fail(WALLET_CANARY_ERR_RANDOM, out_status,
                    "GetRandBytes returned all-zero probe");

    /* 2. INSERT OR REPLACE. */
    sqlite3_stmt *ins = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO wallet_canary(id,probe,ts) VALUES(1,?1,?2)",
        -1, &ins, NULL);
    if (rc != SQLITE_OK) {
        int code = (rc == SQLITE_ERROR &&
                    sqlite3_errcode(db) == SQLITE_ERROR)
                       ? WALLET_CANARY_ERR_SCHEMA
                       : WALLET_CANARY_ERR_PREPARE;
        return fail(code, out_status,
                    "prepare INSERT: rc=%d err=%s", rc, sqlite3_errmsg(db));
    }
    sqlite3_bind_blob(ins, 1, probe, (int)sizeof(probe), SQLITE_STATIC);
    sqlite3_bind_int64(ins, 2, now_unix());
    rc = AR_STEP_WRITE(ins);
    sqlite3_finalize(ins);
    if (rc != SQLITE_DONE)
        return fail(WALLET_CANARY_ERR_WRITE, out_status,
                    "step INSERT: rc=%d err=%s", rc, sqlite3_errmsg(db));

    /* 3. SELECT probe. */
    sqlite3_stmt *sel = NULL;
    rc = sqlite3_prepare_v2(db,
        "SELECT probe FROM wallet_canary WHERE id=1",
        -1, &sel, NULL);
    if (rc != SQLITE_OK)
        return fail(WALLET_CANARY_ERR_PREPARE, out_status,
                    "prepare SELECT: rc=%d err=%s", rc, sqlite3_errmsg(db));

    rc = AR_STEP_ROW_READONLY(sel);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(sel);
        return fail(WALLET_CANARY_ERR_READ, out_status,
                    "step SELECT: rc=%d (expected SQLITE_ROW) err=%s",
                    rc, sqlite3_errmsg(db));
    }
    const void *got = sqlite3_column_blob(sel, 0);
    int         got_len = sqlite3_column_bytes(sel, 0);
    if (!got || got_len != (int)sizeof(probe)) {
        sqlite3_finalize(sel);
        return fail(WALLET_CANARY_ERR_READ, out_status,
                    "SELECT returned blob of %d bytes (expected %zu)",
                    got_len, sizeof(probe));
    }
    int cmp = memcmp(got, probe, sizeof(probe));
    sqlite3_finalize(sel);
    if (cmp != 0)
        return fail(WALLET_CANARY_ERR_MISMATCH, out_status,
                    "probe roundtrip mismatch — wrote %d bytes, read differs",
                    (int)sizeof(probe));

    /* 4. Success. */
    int64_t now = now_unix();
    set_status(true, WALLET_CANARY_OK, now, NULL);
    if (out_status) *out_status = wallet_canary_get_status();
    return WALLET_CANARY_OK;
}

struct wallet_canary_status wallet_canary_get_status(void)
{
    pthread_mutex_lock(&g_status_lock);
    struct wallet_canary_status copy = g_status;
    pthread_mutex_unlock(&g_status_lock);
    return copy;
}

struct wallet_persistence_health
wallet_persistence_get_health(sqlite3 *db, int keystore_count)
{
    struct wallet_persistence_health h = {
        .open           = (db != NULL),
        .canary_ok      = false,
        .canary_last_ok_ts = 0,
        .row_count      = -1,
        .keystore_count = keystore_count,
        .mismatch       = false,
        .corrupt_rows   = wallet_sqlite_read_keys_corrupt_count(),
        .last_error     = { 0 },
    };

    struct wallet_canary_status s = wallet_canary_get_status();
    h.canary_ok         = s.ok;
    h.canary_last_ok_ts = s.last_ok_ts;
    if (!s.ok) {
        snprintf(h.last_error, sizeof(h.last_error), "%s", s.error);
    }

    if (!db) {
        if (h.last_error[0] == '\0')
            snprintf(h.last_error, sizeof(h.last_error), "%s",
                     "sqlite handle closed");
        return h;
    }

    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(db, "SELECT count(*) FROM wallet_keys",
                                 -1, &st, NULL);
    if (rc != SQLITE_OK) {
        h.mismatch = true;
        snprintf(h.last_error, sizeof(h.last_error),
                 "prepare count: rc=%d err=%s", rc, sqlite3_errmsg(db));
        return h;
    }
    rc = AR_STEP_ROW_READONLY(st);
    if (rc == SQLITE_ROW) {
        h.row_count = sqlite3_column_int(st, 0);
        if (h.row_count != keystore_count) {
            h.mismatch = true;
            if (h.last_error[0] == '\0') {
                snprintf(h.last_error, sizeof(h.last_error),
                         "row_count=%d keystore_count=%d",
                         h.row_count, keystore_count);
            }
        }
    } else {
        h.mismatch = true;
        snprintf(h.last_error, sizeof(h.last_error),
                 "step count: rc=%d err=%s", rc, sqlite3_errmsg(db));
    }
    sqlite3_finalize(st);
    return h;
}
