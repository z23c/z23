/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet persistence canary.
 *
 * A boot-time self-test that proves the wallet storage path is
 * write-then-read-back-readable on THIS datadir with THIS process.
 *
 * Bug this defends against: a silent wallet_sqlite_open() failure
 * on a datadir that already has wallet_keys rows — the node would
 * fall through to "generate fresh keypool", overwrite the user's
 * in-memory state, and on next flush mask the real keys — silently
 * making previously-spendable funds unspendable. The canary runs BEFORE any RPC handler accepts a
 * request, so if the write path is broken the daemon aborts instead
 * of silently regenerating.
 *
 * Schema:
 *
 *   CREATE TABLE IF NOT EXISTS wallet_canary (
 *     id    INTEGER PRIMARY KEY CHECK (id = 1),
 *     probe BLOB NOT NULL,
 *     ts    INTEGER NOT NULL
 *   )
 *
 * Self-test:
 *   1. Generate 32 fresh random bytes.
 *   2. INSERT OR REPLACE (id=1, probe, platform_time_wall_time_t()).
 *   3. SELECT probe FROM wallet_canary WHERE id=1.
 *   4. memcmp: if equal, success; otherwise CANARY_MISMATCH.
 *
 * The canary table is distinct from wallet_keys and is not
 * included in wallet_backup_service's table set. */

#ifndef ZCL_WALLET_CANARY_H
#define ZCL_WALLET_CANARY_H

#include "platform/time_compat.h"
#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>

/* Error codes. Negative to avoid collision with SQLITE_OK=0. */
enum wallet_canary_code {
    WALLET_CANARY_OK                = 0,
    WALLET_CANARY_ERR_NULL_DB       = -1,
    WALLET_CANARY_ERR_SCHEMA        = -2,   /* wallet_canary table missing */
    WALLET_CANARY_ERR_PREPARE       = -3,
    WALLET_CANARY_ERR_WRITE         = -4,
    WALLET_CANARY_ERR_READ          = -5,
    WALLET_CANARY_ERR_MISMATCH      = -6,   /* probe round-trip diverged */
    WALLET_CANARY_ERR_RANDOM        = -7,
};

struct wallet_canary_status {
    bool    ok;              /* most recent run succeeded */
    int     code;            /* one of wallet_canary_code */
    int64_t last_ok_ts;      /* unix time of most recent successful run */
    int64_t last_attempt_ts; /* unix time of most recent run, pass or fail */
    char    error[256];      /* populated on failure with diagnostic */
};

/* Aggregate health snapshot for getwalletinfo.persistence.
 * Defined here (not in wallet_sqlite.h) because Agent 2 owns that
 * header. When Agent 2 lands wallet_sqlite_get_health per plan §5.2,
 * the two can be merged. */
struct wallet_persistence_health {
    bool    open;                /* wallet_sqlite subsystem was opened */
    bool    canary_ok;           /* last canary run succeeded */
    int64_t canary_last_ok_ts;   /* unix time of last passing canary */
    int     row_count;           /* SELECT count(*) FROM wallet_keys */
    int     keystore_count;      /* caller-supplied in-memory count */
    bool    mismatch;            /* row_count != keystore_count */
    int     corrupt_rows;        /* rows dropped by read_keys since boot */
    char    last_error[256];     /* most recent canary error, empty if healthy */
};

/* Run the canary self-test against `db`.
 *
 * Returns WALLET_CANARY_OK on success; a WALLET_CANARY_ERR_* code
 * otherwise. On any non-ok return, `out_status->error` is filled
 * with a human-readable diagnostic.
 *
 * `db` must be an open sqlite3 handle. `out_status` may be NULL if
 * the caller only wants the return code.
 *
 * This call updates the module-private global consulted by
 * wallet_canary_get_status() — call it from boot (mandatory) and
 * optionally from long-running code paths that want a fresh probe.
 */
int wallet_canary_run(sqlite3 *db, struct wallet_canary_status *out_status);

/* Read-only snapshot of the last canary run. Safe from any thread. */
struct wallet_canary_status wallet_canary_get_status(void);

/* Compose the full persistence health snapshot. Non-destructive.
 * `db` may be NULL (treated as closed). `keystore_count` is the
 * caller's in-memory keypool + imported count.
 *
 * Queries SELECT count(*) FROM wallet_keys for row_count. On any
 * sqlite error populates last_error, leaves row_count = -1, and
 * sets mismatch = false (we can't meaningfully compare). */
struct wallet_persistence_health
wallet_persistence_get_health(sqlite3 *db, int keystore_count);

#endif /* ZCL_WALLET_CANARY_H */
