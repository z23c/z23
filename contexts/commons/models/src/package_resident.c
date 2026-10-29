/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: persist crash-atomic serving acceptance through ActiveRecord. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#include "models/package_resident.h"
#include "models/activerecord.h"
#include "models/query_builder.h"
#include "base/hex.h"
#include "util/ar_step_readonly.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

DEFINE_MODEL_CALLBACKS(package_resident_record)

#if !defined(_WIN32)
static struct zcl_result pr_schema(struct package_resident_store *store);
#endif
static void pr_pending_clear(struct package_resident_record *row);
static bool pr_pending_valid(const struct package_resident_record *row);
static bool pr_proof_valid(const char *nonce, uint64_t token);


static bool pr_identity_empty(const struct package_resident_identity *id)
{
    return !id->package_root[0] && !id->receipt_id[0] && !id->artifact_sha3[0] &&
        !id->program[0] && id->configuration_generation == 0;
}

static bool pr_identity_valid(const struct package_resident_identity *id)
{
    uint8_t digest[32];
    return memchr(id->package_root, 0, sizeof(id->package_root)) &&
        memchr(id->receipt_id, 0, sizeof(id->receipt_id)) &&
        memchr(id->artifact_sha3, 0, sizeof(id->artifact_sha3)) &&
        memchr(id->program, 0, sizeof(id->program)) &&
        zcl_hex_decode_lower(id->package_root, digest, sizeof(digest)) &&
        zcl_hex_decode_lower(id->receipt_id, digest, sizeof(digest)) &&
        zcl_hex_decode_lower(id->artifact_sha3, digest, sizeof(digest)) &&
        strncmp(id->program, "bin/", 4) == 0 && id->program[4] &&
        id->configuration_generation > 0;
}

static bool pr_record_valid(const struct package_resident_record *row,
                            struct ar_errors *errors)
{
    ar_errors_clear(errors);
    validates_custom(errors, row && row->revision >= row->generation &&
        row->generation >= 0, "generation", "must not exceed successor high-water mark");
    if (row) {
        validates_custom(errors, row->generation == 0 ? pr_identity_empty(&row->current) : pr_identity_valid(&row->current),
            "current", "must name the complete accepted identity");
        validates_custom(errors, pr_identity_empty(&row->previous) ||
            (row->generation > 0 && pr_identity_valid(&row->previous)),
            "previous", "must be absent or name the complete prior accepted identity");
    }
    if (row) validates_custom(errors, pr_pending_valid(row), "pending", "must bind a complete current candidate probe");
    return !ar_errors_any(errors);
}

bool package_resident_identity_equal(const struct package_resident_identity *a,
                                    const struct package_resident_identity *b)
{
    return a && b && strcmp(a->package_root, b->package_root) == 0 &&
        strcmp(a->receipt_id, b->receipt_id) == 0 &&
        strcmp(a->artifact_sha3, b->artifact_sha3) == 0 &&
        strcmp(a->program, b->program) == 0 &&
        a->configuration_generation == b->configuration_generation;
}

static bool pr_record_save(struct package_resident_store *store,
                           const struct package_resident_record *row)
{
    AR_BEGIN_SAVE(db_package_resident_record_callbacks(),
        "package_resident_record", row, pr_record_valid);
    struct qb q;
    qb_insert(&q, QB_T_resident_serving, QB_INSERT_PLAIN);
    qb_value_text(&q, QB_C_resident_serving_app, store->app);
    qb_value_int(&q, QB_C_resident_serving_revision, row->revision);
    qb_value_int(&q, QB_C_resident_serving_generation, row->generation);
    qb_value_text(&q, QB_C_resident_serving_root, row->current.package_root);
    qb_value_text(&q, QB_C_resident_serving_receipt, row->current.receipt_id);
    qb_value_text(&q, QB_C_resident_serving_digest, row->current.artifact_sha3);
    qb_value_text(&q, QB_C_resident_serving_program, row->current.program);
    qb_value_int(&q, QB_C_resident_serving_config, row->current.configuration_generation);
    qb_value_text(&q, QB_C_resident_serving_prior_root, row->previous.package_root);
    qb_value_text(&q, QB_C_resident_serving_prior_receipt, row->previous.receipt_id);
    qb_value_text(&q, QB_C_resident_serving_prior_digest, row->previous.artifact_sha3);
    qb_value_text(&q, QB_C_resident_serving_prior_program, row->previous.program);
    qb_value_int(&q, QB_C_resident_serving_prior_config, row->previous.configuration_generation);
    qb_value_text(&q, QB_C_resident_serving_pending_root, row->pending.package_root);
    qb_value_text(&q, QB_C_resident_serving_pending_receipt, row->pending.receipt_id);
    qb_value_text(&q, QB_C_resident_serving_pending_digest, row->pending.artifact_sha3);
    qb_value_text(&q, QB_C_resident_serving_pending_program, row->pending.program);
    qb_value_int(&q, QB_C_resident_serving_pending_config, row->pending.configuration_generation);
    qb_value_int(&q, QB_C_resident_serving_pending_ticket, row->pending_ticket);
    qb_value_int(&q, QB_C_resident_serving_pending_generation, row->pending_generation);
    qb_value_text(&q, QB_C_resident_serving_pending_nonce, row->pending_nonce);
    qb_value_int(&q, QB_C_resident_serving_pending_token, row->pending_start_token);
    qb_value_text(&q, QB_C_resident_serving_current_nonce, row->current_nonce);
    qb_value_int(&q, QB_C_resident_serving_current_token, row->current_start_token);
    qb_value_int(&q, QB_C_resident_serving_consumed_ticket, row->consumed_ticket);
    const enum qb_column conflict[] = { QB_C_resident_serving_app };
    qb_on_conflict_do_update(&q, conflict, 1);
    const enum qb_column updates[] = {
        QB_C_resident_serving_revision,
        QB_C_resident_serving_generation,
        QB_C_resident_serving_root,
        QB_C_resident_serving_receipt,
        QB_C_resident_serving_digest,
        QB_C_resident_serving_program,
        QB_C_resident_serving_config,
        QB_C_resident_serving_prior_root,
        QB_C_resident_serving_prior_receipt,
        QB_C_resident_serving_prior_digest,
        QB_C_resident_serving_prior_program,
        QB_C_resident_serving_prior_config,
        QB_C_resident_serving_pending_root,
        QB_C_resident_serving_pending_receipt,
        QB_C_resident_serving_pending_digest,
        QB_C_resident_serving_pending_program,
        QB_C_resident_serving_pending_config,
        QB_C_resident_serving_pending_ticket,
        QB_C_resident_serving_pending_generation,
        QB_C_resident_serving_pending_nonce,
        QB_C_resident_serving_pending_token,
        QB_C_resident_serving_current_nonce,
        QB_C_resident_serving_current_token,
        QB_C_resident_serving_consumed_ticket,
    };
    for (size_t i = 0; i < sizeof(updates) / sizeof(updates[0]); ++i)
        qb_conflict_set_excluded(&q, updates[i]);
    sqlite3_stmt *statement = NULL;
    if (!QB_PREPARE(store, &q, statement)) return false;
    bool ok = false;
    AR_FINALIZE_STEP_DONE(statement, ok);
    AR_FINISH_SAVE(db_package_resident_record_callbacks(), row, ok);
}

static struct zcl_result pr_sql(struct package_resident_store *store, const char *sql)
{
    if (!store || !store->db || sqlite3_exec(store->db, sql, NULL, NULL, NULL) != SQLITE_OK)
        return ZCL_ERR(-1, "resident-store: %s", store && store->db ? sqlite3_errmsg(store->db) : "not open");
    return ZCL_OK;
}

#if !defined(_WIN32)
static bool pr_directory_controlled(char *directory)
{
    size_t length = strlen(directory);
    for (size_t i = 1; i <= length; ++i) {
        if (directory[i] && directory[i] != '/') continue;
        char saved = directory[i];
        directory[i] = 0;
        struct stat st;
        bool ok = lstat(directory, &st) == 0 && S_ISDIR(st.st_mode) &&
            (st.st_uid == 0 || st.st_uid == getuid()) &&
            (!(st.st_mode & 0022) || (st.st_mode & 01000));
        directory[i] = saved;
        if (!ok) return false;
    }
    return true;
}
#endif

#if !defined(_WIN32)
static struct zcl_result pr_resolve_directory(const char *datadir, char directory[PATH_MAX])
{
    char locator[4608];
    int n = snprintf(locator, sizeof(locator), "%s/zcode", datadir);
    if (n < 0 || (size_t)n >= sizeof(locator))
        return ZCL_ERR(-1, "resident-store: datadir too long");
    /* /tmp is itself a symlink on macOS. Resolve the trusted directory,
     * then retain SQLite NOFOLLOW for the database and journal namespace. */
    if (!realpath(locator, directory))
        return ZCL_ERR(-1, "resident-store: resolve package directory: %s", strerror(errno));
    if (!pr_directory_controlled(directory))
        return ZCL_ERR(-1, "resident-store: ancestor ownership or write authority refused");
    int fd = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    if (fd < 0) return ZCL_ERR(-1, "resident-store: open installed package directory: %s", strerror(errno));
    bool controlled = fstat(fd, &st) == 0 && st.st_uid == getuid() && !(st.st_mode & 0022);
    bool closed = close(fd) == 0;
    if (!controlled || !closed)
        return ZCL_ERR(-1, "resident-store: package directory ownership or permissions refused");
    return ZCL_OK;
}

static struct zcl_result pr_database_path(const char *datadir, char path[4640])
{
    char directory[PATH_MAX];
    ZCL_CHECK(pr_resolve_directory(datadir, directory));
    struct stat st;
    int n = snprintf(path, 4640, "%s/resident.db", directory);
    if (n < 0 || (size_t)n >= 4640)
        return ZCL_ERR(-1, "resident-store: database path too long");
    int inspected = lstat(path, &st);
    if ((inspected != 0 && errno != ENOENT) ||
        (inspected == 0 && (!S_ISREG(st.st_mode) || st.st_uid != getuid() || (st.st_mode & 0022))))
        return ZCL_ERR(-1, "resident-store: database ownership or file type refused");
    return ZCL_OK;
}
#endif

struct zcl_result package_resident_store_open(
    struct package_resident_store *store, const char *datadir)
{
    if (!store || store->db || !datadir || datadir[0] != '/')
        return ZCL_ERR(-1, "resident-store: unused owner and explicit absolute datadir required");
#if defined(_WIN32)
    return ZCL_ERR(-1, "resident-store: Windows execution remains unavailable");
#else
    char path[4640];
    ZCL_CHECK(pr_database_path(datadir, path));
    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW;
    if (sqlite3_open_v2(path, &store->db, flags, NULL) != SQLITE_OK) {
        struct zcl_result result = ZCL_ERR(-1, "resident-store: database open refused");
        struct zcl_result cleanup = package_resident_store_close(store);
        return cleanup.ok ? result : cleanup;
    }
    /* 5000 ms matches vcs_index: a background update writer and the editor save
     * contend for resident.db, and 250 ms expired under load (database is locked). */
    struct zcl_result result = sqlite3_busy_timeout(store->db, 5000) == SQLITE_OK
        ? ZCL_OK : ZCL_ERR(-1, "resident-store: bounded contention setup refused");
    /* EXTRA also synchronizes the directory when the rollback journal is
     * unlinked. SQLite's single transaction is the only commit authority;
     * neither an install symlink nor a process handle can override it. */
    if (result.ok) result = pr_schema(store);
    if (!result.ok) {
        struct zcl_result cleanup = package_resident_store_close(store);
        if (!cleanup.ok) return cleanup;
    }
    if (result.ok) (void)snprintf(store->app, sizeof(store->app), "%s", "@legacy");
    return result;
#endif
}

struct zcl_result package_resident_store_close(struct package_resident_store *store)
{
    if (!store) return ZCL_ERR(-1, "resident-store-close: missing owner");
    if (store->db && sqlite3_close(store->db) != SQLITE_OK)
        return ZCL_ERR(-1, "resident-store-close: outstanding database work");
    store->db = NULL;
    return ZCL_OK;
}

static bool pr_read_text(sqlite3_stmt *s, int column, char *out, size_t capacity)
{
    if (sqlite3_column_type(s, column) != SQLITE_TEXT) return false;
    int bytes = sqlite3_column_bytes(s, column);
    const unsigned char *text = sqlite3_column_text(s, column);
    if (!text || bytes < 0 || (size_t)bytes >= capacity || memchr(text, 0, (size_t)bytes))
        return false;
    memcpy(out, text, (size_t)bytes);
    out[bytes] = 0;
    return true;
}

static bool pr_read_identity(sqlite3_stmt *s, int column,
    struct package_resident_identity *out)
{
    if (sqlite3_column_type(s, column + 4) != SQLITE_INTEGER) return false;
    out->configuration_generation = sqlite3_column_int64(s, column + 4);
    return pr_read_text(s, column, out->package_root, sizeof(out->package_root)) &&
        pr_read_text(s, column + 1, out->receipt_id, sizeof(out->receipt_id)) &&
        pr_read_text(s, column + 2, out->artifact_sha3, sizeof(out->artifact_sha3)) &&
        pr_read_text(s, column + 3, out->program, sizeof(out->program));
}

static bool pr_read_pending(sqlite3_stmt *s, struct package_resident_record *out);
static bool pr_read_row(sqlite3_stmt *s, struct package_resident_record *out)
{
    if (sqlite3_column_type(s, 0) != SQLITE_INTEGER ||
        sqlite3_column_type(s, 1) != SQLITE_INTEGER) return false;
    out->revision = sqlite3_column_int64(s, 0);
    out->generation = sqlite3_column_int64(s, 1);
    return pr_read_identity(s, 2, &out->current) &&
        pr_read_identity(s, 7, &out->previous) && pr_read_pending(s, out);
}


struct zcl_result package_resident_record_read(
    struct package_resident_store *store, struct package_resident_record *out)
{
    if (!store || !store->db || !out)
        return ZCL_ERR(-1, "resident-record-read: missing owner or output");
    memset(out, 0, sizeof(*out));
    sqlite3_stmt *s = NULL;
    struct qb q;
    qb_select(&q, QB_T_resident_serving);
    const enum qb_column columns[] = {
        QB_C_resident_serving_revision,
        QB_C_resident_serving_generation,
        QB_C_resident_serving_root,
        QB_C_resident_serving_receipt,
        QB_C_resident_serving_digest,
        QB_C_resident_serving_program,
        QB_C_resident_serving_config,
        QB_C_resident_serving_prior_root,
        QB_C_resident_serving_prior_receipt,
        QB_C_resident_serving_prior_digest,
        QB_C_resident_serving_prior_program,
        QB_C_resident_serving_prior_config,
        QB_C_resident_serving_pending_root,
        QB_C_resident_serving_pending_receipt,
        QB_C_resident_serving_pending_digest,
        QB_C_resident_serving_pending_program,
        QB_C_resident_serving_pending_config,
        QB_C_resident_serving_pending_ticket,
        QB_C_resident_serving_pending_generation,
        QB_C_resident_serving_pending_nonce,
        QB_C_resident_serving_pending_token,
        QB_C_resident_serving_current_nonce,
        QB_C_resident_serving_current_token,
        QB_C_resident_serving_consumed_ticket,
    };
    qb_select_columns(&q, columns, sizeof(columns) / sizeof(columns[0]));
    qb_where_text(&q, QB_C_resident_serving_app, QB_EQ, store->app);
    if (!QB_PREPARE(store, &q, s))
        return ZCL_ERR(-1, "resident-record-read: %s", sqlite3_errmsg(store->db));
    int rc = AR_STEP_ROW_READONLY(s);
    bool shape = true;
    if (rc == SQLITE_ROW) shape = pr_read_row(s, out);
    int finalized = sqlite3_finalize(s);
    struct ar_errors errors;
    if (!shape || (rc != SQLITE_ROW && rc != SQLITE_DONE) || finalized != SQLITE_OK ||
        !pr_record_valid(out, &errors))
        return ZCL_ERR(-1, "resident-record-read: malformed or unreadable acceptance");
    return ZCL_OK;
}

static struct zcl_result pr_finish(struct package_resident_store *store,
                                    struct zcl_result result)
{
    if (result.ok) result = pr_sql(store, "COMMIT");
    if (!result.ok && !sqlite3_get_autocommit(store->db)) {
        struct zcl_result cleanup = pr_sql(store, "ROLLBACK");
        if (!cleanup.ok) return cleanup;
    }
    return result;
}

struct zcl_result package_resident_record_begin(
    struct package_resident_store *store, int64_t expected_generation,
    struct package_resident_record *out)
{
    ZCL_CHECK(pr_sql(store, "BEGIN IMMEDIATE"));
    struct zcl_result result = package_resident_record_read(store, out);
    if (result.ok && out->generation != expected_generation)
        result = ZCL_ERR(-1, "resident-generation-precondition: acceptance changed before reservation");
    if (result.ok && out->revision == INT64_MAX)
        result = ZCL_ERR(-1, "resident-generation-exhausted");
    struct package_resident_identity displaced = {0};
    if (result.ok) {
        displaced = out->pending;
        ++out->revision;
        pr_pending_clear(out);
        if (!pr_record_save(store, out)) result = ZCL_ERR(-1, "resident-candidate-ticket: save refused");
    }
    result = pr_finish(store, result);
    if (result.ok) out->displaced_pending = displaced;
    return result;
}

struct zcl_result package_resident_record_commit(
    struct package_resident_store *store, int64_t ticket,
    int64_t expected_generation, const struct package_resident_identity *identity,
    struct package_resident_record *out)
{
    if (!store || strcmp(store->app, "@legacy") != 0 || !identity || !pr_identity_valid(identity))
        return ZCL_ERR(-1, "resident-commit: complete accepted identity required");
    const struct package_resident_identity target = *identity;
    ZCL_CHECK(pr_sql(store, "BEGIN IMMEDIATE"));
    struct zcl_result result = package_resident_record_read(store, out);
    if (result.ok && (ticket <= out->generation || out->revision != ticket || out->generation != expected_generation))
        result = ZCL_ERR(-1, "resident-candidate-superseded: generation precondition changed");
    if (result.ok) {
        if (!package_resident_identity_equal(&out->current, &target))
            out->previous = out->current;
        out->current = target;
        out->generation = ticket;
        out->consumed_ticket = ticket;
        if (!pr_record_save(store, out)) result = ZCL_ERR(-1, "resident-activation: acceptance save refused");
    }
    return pr_finish(store, result);
}

static bool pr_proof_valid(const char *nonce, uint64_t token)
{
    uint8_t digest[32];
    return nonce && strnlen(nonce, 65) == 64 && token > 0 &&
        token <= INT64_MAX && zcl_hex_decode_lower(nonce, digest, sizeof(digest));
}

static void pr_pending_clear(struct package_resident_record *row)
{
    memset(&row->pending, 0, sizeof(row->pending));
    row->pending_ticket = 0;
    row->pending_generation = 0;
    row->pending_nonce[0] = 0;
    row->pending_start_token = 0;
}

static bool pr_pending_valid(const struct package_resident_record *row)
{
    bool current_proof = !row->current_nonce[0] && row->current_start_token == 0;
    if (!current_proof)
        current_proof = row->generation > 0 && pr_proof_valid(row->current_nonce, row->current_start_token);
    if (!current_proof) return false;
    if (row->consumed_ticket < 0 || row->consumed_ticket > row->revision) return false;
    if (!row->pending_ticket)
        return pr_identity_empty(&row->pending) && !row->pending_nonce[0] &&
            !row->pending_start_token && !row->pending_generation;
    return row->pending_ticket > row->consumed_ticket && row->pending_ticket == row->revision &&
        row->pending_generation == row->generation &&
        pr_identity_valid(&row->pending) &&
        pr_proof_valid(row->pending_nonce, row->pending_start_token);
}

static bool pr_read_pending(sqlite3_stmt *s, struct package_resident_record *out)
{
    const int ints[] = {16, 17, 18, 20, 22, 23};
    for (size_t i = 0; i < sizeof(ints) / sizeof(ints[0]); ++i)
        if (sqlite3_column_type(s, ints[i]) != SQLITE_INTEGER || sqlite3_column_int64(s, ints[i]) < 0)
            return false;
    out->pending.configuration_generation = sqlite3_column_int64(s, 16);
    out->pending_ticket = sqlite3_column_int64(s, 17);
    out->pending_generation = sqlite3_column_int64(s, 18);
    out->pending_start_token = (uint64_t)sqlite3_column_int64(s, 20);
    out->current_start_token = (uint64_t)sqlite3_column_int64(s, 22);
    out->consumed_ticket = sqlite3_column_int64(s, 23);
    return pr_read_text(s, 12, out->pending.package_root, sizeof(out->pending.package_root)) &&
        pr_read_text(s, 13, out->pending.receipt_id, sizeof(out->pending.receipt_id)) &&
        pr_read_text(s, 14, out->pending.artifact_sha3, sizeof(out->pending.artifact_sha3)) &&
        pr_read_text(s, 15, out->pending.program, sizeof(out->pending.program)) &&
        pr_read_text(s, 19, out->pending_nonce, sizeof(out->pending_nonce)) &&
        pr_read_text(s, 21, out->current_nonce, sizeof(out->current_nonce));
}



#if !defined(_WIN32)
static bool pr_migrate_save(struct package_resident_store *store)
{
    sqlite3_stmt *statement = NULL;
    const struct package_resident_record row = {0};
    AR_ADHOC_SAVE(store, statement,
        qb_schema_sql(QB_S_resident_legacy_copy),
        db_package_resident_record_callbacks(), "package_resident_record", &row,
        pr_record_valid, (void)statement);
}

static struct zcl_result pr_schema_migrate(struct package_resident_store *store)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(store->db, qb_schema_sql(QB_S_resident_columns), -1, &s, NULL) != SQLITE_OK)
        return ZCL_ERR(-1, "resident-migrate: schema inspection refused");
    int rc;
    bool named = false;
    while ((rc = AR_STEP_ROW_READONLY(s)) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(s, 1);
        if (name && strcmp((const char *)name, "app") == 0) named = true;
    }
    int finished = sqlite3_finalize(s);
    if (rc != SQLITE_DONE || finished != SQLITE_OK)
        return ZCL_ERR(-1, "resident-migrate: incomplete schema inspection");
    if (named) return ZCL_OK;
    ZCL_CHECK(pr_sql(store, qb_schema_sql(QB_S_resident_legacy_rename)));
    ZCL_CHECK(pr_sql(store, qb_schema_sql(QB_S_resident_create)));
    if (!pr_migrate_save(store)) return ZCL_ERR(-1, "resident-migrate: legacy acceptance copy refused");
    return pr_sql(store, qb_schema_sql(QB_S_resident_legacy_drop));
}

static struct zcl_result pr_schema(struct package_resident_store *store)
{
    ZCL_CHECK(pr_sql(store, qb_schema_sql(QB_S_resident_durable_begin)));
    struct zcl_result result = pr_sql(store, qb_schema_sql(QB_S_resident_create));
    if (result.ok) result = pr_schema_migrate(store);
    return pr_finish(store, result);
}
#endif

static bool pr_app_character(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
        c == '-' || c == '_' || c == '.';
}

static bool pr_app_valid(const char *app)
{
    if (!app || !app[0] || strnlen(app, 256) >= 256) return false;
    unsigned slashes = 0;
    for (size_t i = 0; app[i]; ++i) {
        unsigned char c = (unsigned char)app[i];
        if (c == '/') {
            if (!i || !app[i + 1] || ++slashes > 1) return false;
        } else if (!pr_app_character(c)) {
            return false; // raw-return-ok:pure-character-class-reject
        }
    }
    return slashes == 1;
}

struct zcl_result package_resident_store_open_app(
    struct package_resident_store *store, const char *datadir, const char *app)
{
    if (!pr_app_valid(app)) return ZCL_ERR(-1, "resident-app: bounded publisher/package label required");
    ZCL_CHECK(package_resident_store_open(store, datadir));
    (void)snprintf(store->app, sizeof(store->app), "%s", app);
    return ZCL_OK;
}

static struct zcl_result pr_named_begin(struct package_resident_store *store,
    int64_t ticket, int64_t expected_generation, struct package_resident_record *out)
{
    if (!store || !store->db || !pr_app_valid(store->app) || !out)
        return ZCL_ERR(-1, "resident-pending: named app owner required");
    ZCL_CHECK(pr_sql(store, "BEGIN IMMEDIATE"));
    struct zcl_result result = package_resident_record_read(store, out);
    if (result.ok && (ticket <= out->consumed_ticket || out->revision != ticket || out->generation != expected_generation))
        result = ZCL_ERR(-1, "resident-candidate-superseded: ticket or generation changed");
    if (!result.ok) return pr_finish(store, result);
    return ZCL_OK;
}

struct zcl_result package_resident_record_accept(
    struct package_resident_store *store, int64_t ticket,
    int64_t expected_generation, const struct package_resident_identity *identity,
    const char *nonce, uint64_t start_token, struct package_resident_record *out)
{
    if (!identity || !pr_identity_valid(identity) || !pr_proof_valid(nonce, start_token))
        return ZCL_ERR(-1, "resident-pending: complete accepted identity and completed probe required");
    const struct package_resident_identity target = *identity;
    char proof[65];
    memcpy(proof, nonce, sizeof(proof));
    ZCL_CHECK(pr_named_begin(store, ticket, expected_generation, out));
    if (out->pending_ticket)
        return pr_finish(store, ZCL_ERR(-1, "resident-pending-already-accepted: reserve a fresh ticket"));
    out->pending = target;
    out->pending_ticket = ticket;
    out->pending_generation = expected_generation;
    memcpy(out->pending_nonce, proof, sizeof(proof));
    out->pending_start_token = start_token;
    struct zcl_result result = pr_record_save(store, out) ? ZCL_OK :
        ZCL_ERR(-1, "resident-pending: completed acceptance save refused");
    return pr_finish(store, result);
}

static struct zcl_result pr_named_switch(struct package_resident_store *store,
    const struct package_resident_identity *target, const char *nonce,
    uint64_t start_token, struct package_resident_record *out)
{
    if (out->generation == INT64_MAX)
        return pr_finish(store, ZCL_ERR(-1, "resident-generation-exhausted"));
    const struct package_resident_identity accepted = *target;
    if (!package_resident_identity_equal(&out->current, &accepted))
        out->previous = out->current;
    out->current = accepted;
    ++out->generation;
    out->consumed_ticket = out->revision;
    (void)snprintf(out->current_nonce, sizeof(out->current_nonce), "%s", nonce);
    out->current_start_token = start_token;
    pr_pending_clear(out);
    struct zcl_result result = pr_record_save(store, out) ? ZCL_OK :
        ZCL_ERR(-1, "resident-activation: acceptance save refused");
    return pr_finish(store, result);
}

static struct zcl_result pr_switch_checked(struct package_resident_store *store,
    int64_t ticket, int64_t generation, const char *nonce, uint64_t start_token,
    bool rollback, const struct package_resident_guard *guard,
    struct package_resident_record *out)
{
    if (!out || !pr_proof_valid(nonce, start_token))
        return ZCL_ERR(-1, "resident-switch: output and fresh completed proof required");
    struct package_resident_record row;
    ZCL_CHECK(pr_named_begin(store, ticket, generation, &row));
    if (rollback && !pr_identity_valid(&row.previous))
        return pr_finish(store, ZCL_ERR(-1, "resident-rollback: no exact previous acceptance"));
    if (!rollback && (row.pending_ticket != ticket || row.pending_generation != generation))
        return pr_finish(store, ZCL_ERR(-1, "resident-pending-superseded: no matching accepted candidate"));
    const struct package_resident_identity *target = rollback ? &row.previous : &row.pending;
    if (guard) {
        struct zcl_result checked = guard->check(guard->context, store, target);
        if (!checked.ok) return pr_finish(store, checked);
    }
    struct zcl_result result = pr_named_switch(store, target, nonce, start_token, &row);
    if (result.ok) *out = row;
    return result;
}

struct zcl_result package_resident_record_activate(
    struct package_resident_store *store, int64_t ticket,
    int64_t expected_generation, const char *nonce, uint64_t start_token,
    struct package_resident_record *out)
{
    return pr_switch_checked(store, ticket, expected_generation, nonce,
        start_token, false, NULL, out);
}

struct zcl_result package_resident_record_rollback(
    struct package_resident_store *store, int64_t ticket,
    int64_t expected_generation, const char *nonce, uint64_t start_token,
    struct package_resident_record *out)
{
    return pr_switch_checked(store, ticket, expected_generation, nonce,
        start_token, true, NULL, out);
}

struct zcl_result package_resident_record_activate_checked(
    struct package_resident_store *store, int64_t ticket,
    int64_t expected_generation, const char *nonce, uint64_t start_token,
    const struct package_resident_guard *guard, struct package_resident_record *out)
{
    if (!guard || !guard->check)
        return ZCL_ERR(-1, "resident-activate: current-data compatibility guard required");
    return pr_switch_checked(store, ticket, expected_generation, nonce,
        start_token, false, guard, out);
}

struct zcl_result package_resident_record_rollback_checked(
    struct package_resident_store *store, int64_t ticket,
    int64_t expected_generation, const char *nonce, uint64_t start_token,
    const struct package_resident_guard *guard, struct package_resident_record *out)
{
    if (!guard || !guard->check)
        return ZCL_ERR(-1, "resident-rollback: current-data compatibility guard required");
    return pr_switch_checked(store, ticket, expected_generation, nonce,
        start_token, true, guard, out);
}
