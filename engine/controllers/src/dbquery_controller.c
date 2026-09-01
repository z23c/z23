/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * DB-query controller for the native `dbquery` primitive.
 *
 * SELECT-only SQL passthrough against the node's SQLite database. Hard
 * validation: must start with SELECT, no semicolons, no DDL/DML
 * keywords, no reference to wallet secret material (see
 * dbq_secret_hit() below — denied regardless of wallet-encryption
 * state), auto-LIMIT appended if missing, 2 s wall-clock budget
 * enforced via sqlite3_progress_handler, 100-row hard cap.
 *
 * Exposed as a high-cost read: it cannot mutate, but arbitrary scans against
 * a 100M-row table can still be expensive.
 */

#include "base/hex.h"
#include "platform/time_compat.h"
#include "controllers/diagnostics_controller.h"
#include "controllers/diagnostics_internal.h"

#include "json/json.h"
#include "rpc/server.h"
#include "controllers/strong_params.h"
#include "models/database.h"
#include "config/runtime.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <ctype.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <time.h>

#define DBQUERY_MAX_SQL_LEN       1024
#define DBQUERY_HARD_ROW_CAP       100
#define DBQUERY_DEFAULT_LIMIT       10
#define DBQUERY_PROGRESS_OPS_TICK 1000   /* progress_handler callback granularity */

/* Wall-clock budget in milliseconds. Checked in the progress handler. */
#define DBQUERY_BUDGET_MS         2000

struct dbq_progress_ctx {
    int64_t start_ms;
    int64_t budget_ms;
};

static int64_t now_ms(void)
{
    struct timespec ts;
    platform_time_monotonic_timespec(&ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int dbq_progress_cb(void *vp)
{
    struct dbq_progress_ctx *c = vp;
    if (!c) return 0;
    int64_t elapsed = now_ms() - c->start_ms;
    return (elapsed > c->budget_ms) ? 1 : 0;  /* nonzero → interrupt */
}

static bool sql_has_word(const char *sql, const char *word)
{
    /* Case-insensitive whole-word search. */
    size_t wlen = strlen(word);
    const char *p = sql;
    while (*p) {
        if (strncasecmp(p, word, wlen) == 0) {
            char prev = (p > sql) ? p[-1] : ' ';
            char next = p[wlen];
            bool prev_b = !(isalnum((unsigned char)prev) || prev == '_');
            bool next_b = !(isalnum((unsigned char)next) || next == '_');
            if (prev_b && next_b) return true;
        }
        p++;
    }
    return false;
}

/* ── Secret-material denylist ──────────────────────────────────────
 *
 * dbquery is SELECT-only and DDL/DML-blocked, but it had no
 * notion of *which* SELECTs are safe to run: `SELECT privkey FROM
 * wallet_keys` was legal SQL and exposed the plaintext keystore to any
 * authenticated loopback RPC caller, regardless of whether the wallet was
 * encrypted at rest.
 *
 * The line the lists draw is AUTHORIZING MATERIAL, not "private key".
 * Anything whose mere possession lets the holder move value belongs here
 * even when it is not a key:
 *
 *   - `agent_sessions.session_id` is a bearer grant. Presenting it in
 *     ZCL_AGENT_SESSION is what makes a dispatch spend under that grant's
 *     caps (services/agent_spend_policy.h), so a bounded session that could
 *     read the table could read a WIDER grant's token and spend under it —
 *     a bound the bounded party raises for itself. `vault session list` is
 *     the readable view; it redacts to the first 8 chars.
 *   - `zswp_contracts.secret` is the HTLC preimage. Whoever holds it can
 *     redeem the counterparty's locked output on the other chain
 *     (core/modules/script/src/htlc.c). `app swap list` / `app swap status` are the
 *     readable views.
 *
 * These two lists are whole-word, case-insensitive substring checks
 * against the *entire raw query text* (not just the FROM clause), so
 * a hit inside a subquery, CTE, alias target, quoted/bracketed
 * identifier, or SQL comment is still caught — SQLite's SELECT
 * grammar has no way to construct a table/column identifier
 * dynamically inside a single statement, so any real reference to a
 * secret table or column must appear as a literal ASCII token
 * somewhere in the query text. Whitespace and case variation between
 * tokens don't matter because the scan is a raw string walk, not a
 * tokenizer keyed on specific spacing.
 *
 * SECRET_TABLES are blocked WHOLESALE, and the table list — not the
 * column list — is what actually holds: `SELECT * FROM t` names no
 * column, so a column-level rule cannot see it. A table whose row
 * carries any authorizing value goes on the table list; the column list
 * only adds defense-in-depth for an explicit projection, a join that
 * transplants the column, or a same-named column appearing in an
 * otherwise-public table later.
 *
 * Update SECRET_TABLES/SECRET_COLUMNS whenever
 * engine/models/src/database_schema.c or the migrations in
 * database_migrate_features*.c gain a table whose rows authorize a
 * spend. Fail closed: if a query cannot be confidently proven
 * secret-free, it is rejected. */
static const char *const SECRET_TABLES[] = {
    "wallet_keys",          /* privkey (transparent) */
    "wallet_sapling_keys",  /* xsk (Sapling extended spending key) */
    "wallet_seed",          /* seed (HD wallet seed) */
    "agent_sessions",       /* session_id (bearer spend grant) */
    "zswp_contracts",       /* secret (HTLC redemption preimage) */
};

static const char *const SECRET_COLUMNS[] = {
    "privkey", "xsk", "seed", "hdseed", "spending_key",
    "spendingkey", "mnemonic", "master_key", "masterkey",
    "session_id", "secret",
};

/* Returns the matched secret token, or NULL if the query is clean. */
static const char *dbq_secret_hit(const char *sql)
{
    for (size_t i = 0; i < sizeof(SECRET_TABLES) / sizeof(SECRET_TABLES[0]); i++) {
        if (sql_has_word(sql, SECRET_TABLES[i])) return SECRET_TABLES[i];
    }
    for (size_t i = 0; i < sizeof(SECRET_COLUMNS) / sizeof(SECRET_COLUMNS[0]); i++) {
        if (sql_has_word(sql, SECRET_COLUMNS[i])) return SECRET_COLUMNS[i];
    }
    return NULL;
}

/* See controllers/diagnostics_controller.h for the contract. Shared by
 * diag_rpc_dbquery (live node.db via app_runtime_node_db()) and the
 * core.storage.query.offline native handler (an ad hoc SQLITE_OPEN_READONLY
 * handle against a copied/stopped datadir's node.db) — identical validation
 * and execution either way; only where `db` comes from differs. */
bool dbquery_execute(sqlite3 *db, const char *sql_in, int64_t limit,
                     struct json_value *result)
{
    if (limit < 1) limit = 1;
    if (limit > DBQUERY_HARD_ROW_CAP) limit = DBQUERY_HARD_ROW_CAP;

    if (!sql_in || !sql_in[0]) {
        json_set_str(result, "dbquery: missing sql");
        LOG_FAIL("diag", "dbquery: missing sql");
    }
    size_t slen = strlen(sql_in);
    if (slen > DBQUERY_MAX_SQL_LEN) {
        json_set_str(result, "dbquery: sql too long");
        LOG_FAIL("diag", "dbquery: sql too long (%zu > %d)",
                 slen, DBQUERY_MAX_SQL_LEN);
    }

    /* Skip leading whitespace. */
    const char *sql = sql_in;
    while (*sql && isspace((unsigned char)*sql)) sql++;

    if (strncasecmp(sql, "SELECT", 6) != 0 ||
        !(sql[6] == ' ' || sql[6] == '\t' || sql[6] == '\n')) {
        json_set_str(result, "dbquery: query must start with SELECT");
        LOG_FAIL("diag", "dbquery: query must start with SELECT");
    }

    if (strchr(sql, ';')) {
        json_set_str(result, "dbquery: semicolons not allowed");
        LOG_FAIL("diag", "dbquery: semicolons not allowed");
    }

    static const char *blocked[] = {
        "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE",
        "REPLACE", "ATTACH", "DETACH", "PRAGMA", "VACUUM", "REINDEX",
        "TRIGGER", "TRUNCATE",
    };
    for (size_t i = 0; i < sizeof(blocked) / sizeof(blocked[0]); i++) {
        if (sql_has_word(sql, blocked[i])) {
            json_set_str(result, "dbquery: blocked keyword not allowed");
            LOG_FAIL("diag", "dbquery: keyword '%s' not allowed",
                     blocked[i]);
        }
    }

    /* Secret-material denylist. Fails closed regardless of wallet
     * encryption state — see the block comment above dbq_secret_hit(). */
    const char *secret_hit = dbq_secret_hit(sql);
    if (secret_hit) {
        json_set_str(result,
            "dbquery: query references secret or spend-authorizing "
            "material and is denied");
        LOG_FAIL("diag", "dbquery: denied secret reference '%s'",
                 secret_hit);
    }

    if (!db) {
        json_set_str(result, "dbquery: node_db not available");
        LOG_FAIL("diag", "dbquery: node_db not available");
    }

    /* Build the executed SQL: append LIMIT if not present. */
    char executed[DBQUERY_MAX_SQL_LEN + 64];
    if (sql_has_word(sql, "LIMIT")) {
        snprintf(executed, sizeof(executed), "%s", sql);
    } else {
        snprintf(executed, sizeof(executed), "%s LIMIT %lld",
                 sql, (long long)limit);
    }

    struct dbq_progress_ctx pctx = {
        .start_ms = now_ms(),
        .budget_ms = DBQUERY_BUDGET_MS,
    };
    sqlite3_progress_handler(db, DBQUERY_PROGRESS_OPS_TICK,
                             dbq_progress_cb, &pctx);

    sqlite3_stmt *stmt = NULL;
    if (!node_db_prepare_readonly_stmt(db, executed, &stmt)) {
        sqlite3_progress_handler(db, 0, NULL, NULL);
        json_set_str(result, "dbquery: prepare failed");
        LOG_FAIL("diag", "dbquery: prepare failed");
    }
    int rc = SQLITE_OK;

    int ncols = sqlite3_column_count(stmt);

    json_set_object(result);
    struct json_value cols_arr = {0};
    json_set_array(&cols_arr);
    for (int c = 0; c < ncols; c++) {
        struct json_value cv = {0};
        const char *name = sqlite3_column_name(stmt, c);
        json_set_str(&cv, name ? name : "");
        json_push_back(&cols_arr, &cv);
        json_free(&cv);
    }
    json_push_kv(result, "columns", &cols_arr);
    json_free(&cols_arr);

    struct json_value rows_arr = {0};
    json_set_array(&rows_arr);
    int row_count = 0;
    bool truncated = false;
    bool interrupted = false;

    while (row_count < DBQUERY_HARD_ROW_CAP) {
        rc = AR_STEP_ROW_READONLY(stmt);
        if (rc == SQLITE_DONE) break;
        if (rc == SQLITE_INTERRUPT) { interrupted = true; break; }
        if (rc != SQLITE_ROW) {
            const char *err = sqlite3_errmsg(db);
            sqlite3_finalize(stmt);
            sqlite3_progress_handler(db, 0, NULL, NULL);
            json_set_str(result, "dbquery: step failed");
            LOG_FAIL("diag", "dbquery: step failed (rc=%d): %s",
                     rc, err ? err : "(null)");
        }
        struct json_value row = {0};
        json_set_array(&row);
        for (int c = 0; c < ncols; c++) {
            struct json_value cell = {0};
            int t = sqlite3_column_type(stmt, c);
            switch (t) {
                case SQLITE_INTEGER:
                    json_set_int(&cell, (int64_t)sqlite3_column_int64(stmt, c));
                    break;
                case SQLITE_FLOAT:
                    json_set_real(&cell, sqlite3_column_double(stmt, c));
                    break;
                case SQLITE_TEXT: {
                    const char *txt = (const char *)sqlite3_column_text(stmt, c);
                    json_set_str(&cell, txt ? txt : "");
                    break;
                }
                case SQLITE_NULL:
                    json_set_null(&cell);
                    break;
                case SQLITE_BLOB: {
                    /* Encode as hex string (BLOBs in our schema are
                     * usually 20–32 byte hashes). Truncate at 256 hex
                     * chars to keep responses small. */
                    int blen = sqlite3_column_bytes(stmt, c);
                    if (blen > 128) blen = 128;
                    const unsigned char *b = sqlite3_column_blob(stmt, c);
                    char hex[257];
                    zcl_hex_encode(b, (size_t)blen, hex);
                    json_set_str(&cell, hex);
                    break;
                }
            }
            json_push_back(&row, &cell);
            json_free(&cell);
        }
        json_push_back(&rows_arr, &row);
        json_free(&row);
        row_count++;
    }

    if (row_count >= DBQUERY_HARD_ROW_CAP) truncated = true;

    int64_t elapsed = now_ms() - pctx.start_ms;
    sqlite3_finalize(stmt);
    sqlite3_progress_handler(db, 0, NULL, NULL);

    json_push_kv(result, "rows", &rows_arr);
    json_free(&rows_arr);
    json_push_kv_int(result, "row_count", (int64_t)row_count);
    json_push_kv_bool(result, "truncated", truncated);
    json_push_kv_bool(result, "interrupted", interrupted);
    json_push_kv_int(result, "elapsed_ms", elapsed);
    json_push_kv_str(result, "sql_executed", executed);
    return true;
}

bool diag_rpc_dbquery(const struct json_value *params, bool help,
                      struct json_value *result)
{
    RPC_HELP(help, result,
        "dbquery <sql> [limit=10]\n"
        "\nRead-only SELECT passthrough against node.db. Hard limits:\n"
        "  - must start with SELECT (case-insensitive)\n"
        "  - no semicolons anywhere in the query\n"
        "  - DDL/DML keywords rejected (INSERT, UPDATE, DELETE, etc.)\n"
        "  - secret and spend-authorizing material denied (wallet_keys,\n"
        "    wallet_sapling_keys, wallet_seed, agent_sessions,\n"
        "    zswp_contracts, privkey/xsk/seed/session_id/secret/etc.)\n"
        "  - LIMIT auto-appended if missing\n"
        "  - 2 s wall-clock budget enforced\n"
        "  - 100-row hard cap regardless of LIMIT\n"
        "\nResult: { columns, rows, elapsed_ms, truncated, sql_executed }");

    const char *sql_in = json_get_str(json_at(params, 0));
    int64_t limit = json_at(params, 1) ?
        json_get_int(json_at(params, 1)) : DBQUERY_DEFAULT_LIMIT;

    struct node_db *ndb = app_runtime_node_db();
    return dbquery_execute(ndb ? ndb->db : NULL, sql_in, limit, result);
}
