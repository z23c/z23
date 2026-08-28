/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "services/consensus_snapshot_export_service.h"

#include "crypto/sha3.h"
#include "platform/file_metadata.h"
#include "platform/positioned_file.h"
#include "platform/private_file.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <errno.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "platform/allocator_compat.h"

#define LOCAL_EXPORT_PROOF_NAME \
    "consensus_snapshot.db.local-export-v1"
#define LOCAL_EXPORT_PROOF_BYTES 96u
#define LOCAL_EXPORT_PROOF_VERSION 1u

static const uint8_t LOCAL_EXPORT_PROOF_MAGIC[8] = {
    'Z', 'C', 'L', 'X', 'P', 'V', '1', '\0'
};

struct local_export_proof {
    uint64_t body_size;
    uint8_t body_sha3[32];
    int32_t state_height;
    uint8_t state_block_hash[32];
};

struct local_export_cache {
    bool valid;
    char datadir[576];
    struct platform_positioned_file_snapshot body_snapshot;
    struct platform_positioned_file_snapshot proof_snapshot;
    struct local_export_proof proof;
};

static pthread_mutex_t g_local_export_cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct local_export_cache g_local_export_cache;

static void put_u32_le(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)value;
    out[1] = (uint8_t)(value >> 8);
    out[2] = (uint8_t)(value >> 16);
    out[3] = (uint8_t)(value >> 24);
}

static uint32_t get_u32_le(const uint8_t *in)
{
    return (uint32_t)in[0] |
           ((uint32_t)in[1] << 8) |
           ((uint32_t)in[2] << 16) |
           ((uint32_t)in[3] << 24);
}

static void put_u64_le(uint8_t *out, uint64_t value)
{
    for (size_t i = 0; i < 8; i++)
        out[i] = (uint8_t)(value >> (8u * i));
}

static uint64_t get_u64_le(const uint8_t *in)
{
    uint64_t value = 0;
    for (size_t i = 0; i < 8; i++)
        value |= (uint64_t)in[i] << (8u * i);
    return value;
}

static bool export_path(char *out, size_t out_size, const char *datadir,
                        const char *name)
{
    if (!out || out_size == 0 || !datadir || !name)
        return false; /* raw-return-ok:bounded policy reason returned */
    int n = snprintf(out, out_size, "%s/%s", datadir, name);
    return n >= 0 && (size_t)n < out_size;
}

static bool snapshot_identity_equal(
    const struct platform_positioned_file_snapshot *a,
    const struct platform_positioned_file_snapshot *b)
{
    return a && b && a->volume == b->volume &&
           a->file_low == b->file_low && a->file_high == b->file_high &&
           a->size == b->size &&
           a->modified_seconds == b->modified_seconds &&
           a->modified_nanoseconds == b->modified_nanoseconds &&
           a->changed_seconds == b->changed_seconds &&
           a->changed_nanoseconds == b->changed_nanoseconds;
}

static void local_export_cache_invalidate(void)
{
    pthread_mutex_lock(&g_local_export_cache_mutex);
    memset(&g_local_export_cache, 0, sizeof(g_local_export_cache));
    pthread_mutex_unlock(&g_local_export_cache_mutex);
}

static bool hash_regular_file(const char *path, uint8_t out_sha3[32],
    uint64_t *out_size,
    struct platform_positioned_file_snapshot *out_snapshot)
{
    if (!path || !out_sha3 || !out_size)
        return false; /* raw-return-ok:validation predicate rejects input */
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path))
        return false; /* raw-return-ok:bounded policy reason returned */

    struct platform_positioned_file_snapshot before;
    if (!platform_positioned_file_snapshot(&file, &before)) {
        platform_positioned_file_close(&file);
        return false; /* raw-return-ok:bounded policy reason returned */
    }

    enum { HASH_WINDOW = 1u << 20 };
    uint8_t *buf = zcl_malloc(HASH_WINDOW, "snapshot_local_export_hash");
    if (!buf) {
        platform_positioned_file_close(&file);
        return false; /* raw-return-ok:bounded policy reason returned */
    }

    struct sha3_256_ctx sha3;
    sha3_256_init(&sha3);
    uint64_t total = 0;
    bool ok = true;
    while (total < before.size) {
        size_t wanted = before.size - total > HASH_WINDOW
            ? HASH_WINDOW : (size_t)(before.size - total);
        int64_t n = platform_positioned_file_read(&file, buf, wanted, total);
        if (n > 0) {
            sha3_256_write(&sha3, buf, (size_t)n);
            total += (uint64_t)n;
            continue;
        }
        ok = false;
        break;
    }
    struct platform_positioned_file_snapshot after;
    if (!platform_positioned_file_snapshot(&file, &after) ||
        !snapshot_identity_equal(&before, &after) || total != before.size)
        ok = false;
    free(buf);
    platform_positioned_file_close(&file);
    if (!ok)
        return false;

    sha3_256_finalize(&sha3, out_sha3);
    *out_size = total;
    if (out_snapshot) *out_snapshot = before;
    return true;
}

static bool read_local_export_proof(const char *path,
                                    struct local_export_proof *out,
    struct platform_positioned_file_snapshot *out_snapshot)
{
    if (!path || !out)
        return false;
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path))
        return false; /* raw-return-ok:bounded policy reason returned */
    struct platform_positioned_file_snapshot before, after;
    uint8_t raw[LOCAL_EXPORT_PROOF_BYTES];
    bool ok = platform_positioned_file_snapshot(&file, &before) &&
              before.size == sizeof(raw) &&
              platform_positioned_file_read(&file, raw, sizeof(raw), 0) ==
                  (int64_t)sizeof(raw) &&
              platform_positioned_file_snapshot(&file, &after) &&
              snapshot_identity_equal(&before, &after);
    platform_positioned_file_close(&file);
    if (!ok || memcmp(raw, LOCAL_EXPORT_PROOF_MAGIC,
                      sizeof(LOCAL_EXPORT_PROOF_MAGIC)) != 0 ||
        get_u32_le(raw + 8) != LOCAL_EXPORT_PROOF_VERSION ||
        get_u32_le(raw + 12) != LOCAL_EXPORT_PROOF_BYTES)
        return false;
    for (size_t i = 92; i < sizeof(raw); i++) {
        if (raw[i] != 0)
            return false;
    }

    memset(out, 0, sizeof(*out));
    out->body_size = get_u64_le(raw + 16);
    memcpy(out->body_sha3, raw + 24, 32);
    out->state_height = (int32_t)get_u32_le(raw + 56);
    memcpy(out->state_block_hash, raw + 60, 32);
    if (out->state_height < 0 || out->body_size == 0)
        return false;
    if (out_snapshot) *out_snapshot = before;
    return true;
}

static bool snapshot_named_file(
    const char *path, struct platform_positioned_file_snapshot *snapshot)
{
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    bool ok = platform_positioned_file_open(&file, path) &&
              platform_positioned_file_snapshot(&file, snapshot);
    platform_positioned_file_close(&file);
    return ok;
}

static bool sqlite_has_bound_block(const char *db_path, int32_t height,
                                   const uint8_t hash[32])
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    bool found = false;
    if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK ||
        !db)
        goto done;
    if (sqlite3_prepare_v2(db,
            "SELECT 1 FROM blocks WHERE height=? AND hash=? AND status>=3 "
            "LIMIT 1",
            -1, &stmt, NULL) != SQLITE_OK || !stmt)
        goto done;
    if (sqlite3_bind_int(stmt, 1, height) != SQLITE_OK ||
        sqlite3_bind_blob(stmt, 2, hash, 32, SQLITE_STATIC) != SQLITE_OK)
        goto done;
    found = AR_STEP_ROW_READONLY(stmt) == SQLITE_ROW;
done:
    if (stmt)
        sqlite3_finalize(stmt);
    if (db)
        sqlite3_close(db);
    return found;
}

static bool load_verified_local_export(const char *datadir,
                                       struct local_export_proof *out,
                                       char *reason, size_t reason_size)
{
    char body_path[640], proof_path[640];
    if (!export_path(body_path, sizeof(body_path), datadir,
                     "consensus_snapshot.db") ||
        !export_path(proof_path, sizeof(proof_path), datadir,
                     LOCAL_EXPORT_PROOF_NAME)) {
        if (reason && reason_size)
            snprintf(reason, reason_size, "local_export_path_invalid");
        return false; /* raw-return-ok:bounded policy reason returned */
    }

    struct platform_positioned_file_snapshot body_snapshot, proof_snapshot;
    if (!snapshot_named_file(body_path, &body_snapshot) ||
        !snapshot_named_file(proof_path, &proof_snapshot)) {
        if (reason && reason_size)
            snprintf(reason, reason_size, "local_export_proof_missing");
        return false; /* raw-return-ok:missing proof is expected policy */
    }

    pthread_mutex_lock(&g_local_export_cache_mutex);
    bool cached = g_local_export_cache.valid &&
        strcmp(g_local_export_cache.datadir, datadir) == 0 &&
        snapshot_identity_equal(&g_local_export_cache.body_snapshot,
                                &body_snapshot) &&
        snapshot_identity_equal(&g_local_export_cache.proof_snapshot,
                                &proof_snapshot);
    if (cached)
        *out = g_local_export_cache.proof;
    pthread_mutex_unlock(&g_local_export_cache_mutex);
    if (cached)
        return true;

    struct local_export_proof proof;
    struct platform_positioned_file_snapshot opened_proof_snapshot;
    struct platform_positioned_file_snapshot opened_body_snapshot;
    uint8_t got_sha3[32];
    uint64_t got_size = 0;
    if (!read_local_export_proof(proof_path, &proof,
                                 &opened_proof_snapshot)) {
        if (reason && reason_size)
            snprintf(reason, reason_size, "local_export_proof_malformed");
        return false; /* raw-return-ok:bounded policy reason returned */
    }
    if (!hash_regular_file(body_path, got_sha3, &got_size,
                           &opened_body_snapshot) ||
        got_size != proof.body_size ||
        memcmp(got_sha3, proof.body_sha3, 32) != 0) {
        if (reason && reason_size)
            snprintf(reason, reason_size, "local_export_digest_mismatch");
        return false; /* raw-return-ok:bounded policy reason returned */
    }
    if (!sqlite_has_bound_block(body_path, proof.state_height,
                                proof.state_block_hash)) {
        if (reason && reason_size)
            snprintf(reason, reason_size, "local_export_state_mismatch");
        return false; /* raw-return-ok:bounded policy reason returned */
    }
    struct platform_positioned_file_snapshot final_body_snapshot;
    struct platform_positioned_file_snapshot final_proof_snapshot;
    if (!snapshot_named_file(body_path, &final_body_snapshot) ||
        !snapshot_named_file(proof_path, &final_proof_snapshot) ||
        !snapshot_identity_equal(&opened_body_snapshot,
                                 &final_body_snapshot) ||
        !snapshot_identity_equal(&opened_proof_snapshot,
                                 &final_proof_snapshot)) {
        if (reason && reason_size)
            snprintf(reason, reason_size, "local_export_identity_changed");
        return false;
    }

    pthread_mutex_lock(&g_local_export_cache_mutex);
    memset(&g_local_export_cache, 0, sizeof(g_local_export_cache));
    g_local_export_cache.valid = true;
    snprintf(g_local_export_cache.datadir,
             sizeof(g_local_export_cache.datadir), "%s", datadir);
    g_local_export_cache.body_snapshot = opened_body_snapshot;
    g_local_export_cache.proof_snapshot = opened_proof_snapshot;
    g_local_export_cache.proof = proof;
    pthread_mutex_unlock(&g_local_export_cache_mutex);
    *out = proof;
    return true;
}

static struct zcl_result write_local_export_proof(
    const char *datadir, int32_t state_height,
    const uint8_t state_block_hash[32])
{
    char body_path[640], proof_path[640], tmp_path[672];
    if (!datadir || state_height < 0 || !state_block_hash)
        return ZCL_ERR(-20, "local export proof: invalid state binding");
    if (!export_path(body_path, sizeof(body_path), datadir,
                     "consensus_snapshot.db") ||
        !export_path(proof_path, sizeof(proof_path), datadir,
                     LOCAL_EXPORT_PROOF_NAME) ||
        snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", proof_path) < 0 ||
        strlen(tmp_path) >= sizeof(tmp_path) - 1)
        return ZCL_ERR(-21, "local export proof: path too long");

    uint8_t body_sha3[32];
    uint64_t body_size = 0;
    if (!hash_regular_file(body_path, body_sha3, &body_size, NULL))
        return ZCL_ERR(-22, "local export proof: snapshot hash failed");

    uint8_t raw[LOCAL_EXPORT_PROOF_BYTES] = {0};
    memcpy(raw, LOCAL_EXPORT_PROOF_MAGIC, sizeof(LOCAL_EXPORT_PROOF_MAGIC));
    put_u32_le(raw + 8, LOCAL_EXPORT_PROOF_VERSION);
    put_u32_le(raw + 12, LOCAL_EXPORT_PROOF_BYTES);
    put_u64_le(raw + 16, body_size);
    memcpy(raw + 24, body_sha3, 32);
    put_u32_le(raw + 56, (uint32_t)state_height);
    memcpy(raw + 60, state_block_hash, 32);

    (void)platform_private_file_unlink_missing_ok(tmp_path);
    struct platform_private_file staging;
    platform_private_file_init(&staging);
    if (!platform_private_file_create(tmp_path, &staging))
        return ZCL_ERR(-23, "local export proof: open %s failed: %s",
                       tmp_path, strerror(errno));
    bool ok = platform_private_file_write_at(&staging, raw, sizeof(raw), 0) &&
              platform_private_file_flush(&staging);
    if (!ok) {
        (void)platform_private_file_retire(&staging, tmp_path);
        platform_private_file_close(&staging);
        return ZCL_ERR(-24, "local export proof: durable write failed: %s",
                       strerror(errno));
    }
    if (!platform_private_file_replace(&staging, tmp_path, proof_path)) {
        struct zcl_result result = ZCL_ERR(
            -25, "local export proof: rename failed: %s", strerror(errno));
        (void)platform_private_file_retire(&staging, tmp_path);
        platform_private_file_close(&staging);
        return result;
    }
    if (!platform_private_parent_flush(datadir)) {
        (void)platform_private_file_unlink_missing_ok(proof_path);
        return ZCL_ERR(-26, "local export proof: directory fsync failed: %s",
                       strerror(errno));
    }
    local_export_cache_invalidate();
    return ZCL_OK;
}

static bool consensus_snapshot_export_artifact_is_bound(
    const char *datadir, int32_t current_sovereign_height,
    char *reason, size_t reason_size)
{
    if (!datadir || datadir[0] == '\0' || current_sovereign_height < 0) {
        if (reason && reason_size)
            snprintf(reason, reason_size, "local_export_context_invalid");
        return false;
    }

    struct local_export_proof proof;
    if (!load_verified_local_export(datadir, &proof, reason, reason_size))
        return false; /* raw-return-ok:bounded policy reason returned */
    if (proof.state_height > current_sovereign_height) {
        if (reason && reason_size)
            snprintf(reason, reason_size, "local_export_ahead_of_hstar");
        return false;
    }

    char node_path[640];
    if (!export_path(node_path, sizeof(node_path), datadir, "node.db") ||
        !sqlite_has_bound_block(node_path, proof.state_height,
                                proof.state_block_hash)) {
        if (reason && reason_size)
            snprintf(reason, reason_size, "local_export_chain_binding_mismatch");
        return false;
    }
    return true;
}

struct zcl_result consensus_snapshot_export_artifact_check(
    const char *datadir, int32_t current_sovereign_height)
{
    char reason[128] = {0};
    if (!consensus_snapshot_export_artifact_is_bound(
            datadir, current_sovereign_height, reason, sizeof(reason)))
        return ZCL_ERR(-30, "snapshot local-export proof: %s",
                       reason[0] ? reason : "invalid");
    return ZCL_OK;
}

static struct zcl_result export_exec_checked(sqlite3 *db, const char *sql,
                                             const char *label)
{
    if (!db || !sql) {
        return ZCL_ERR(-1, "export exec %s: NULL %s",
                       label ? label : "(unknown)",
                       !db ? "db" : "sql");
    }

    if (sqlite3_exec(db, sql, NULL, NULL, NULL) != SQLITE_OK) {
        return ZCL_ERR(-2, "export exec %s failed: %s",
                       label ? label : "(unknown)",
                       sqlite3_errmsg(db));
    }
    return ZCL_OK;
}

static struct zcl_result export_prepare_checked(sqlite3 *db, const char *sql,
                                                sqlite3_stmt **stmt,
                                                const char *label)
{
    if (!db || !sql || !stmt) {
        return ZCL_ERR(-1, "export prepare %s: NULL %s",
                       label ? label : "(unknown)",
                       !db ? "db" : !sql ? "sql" : "stmt");
    }

    if (sqlite3_prepare_v2(db, sql, -1, stmt, NULL) != SQLITE_OK || !*stmt) {
        return ZCL_ERR(-2, "export prepare %s failed: %s",
                       label ? label : "(unknown)",
                       sqlite3_errmsg(db));
    }
    return ZCL_OK;
}

static struct zcl_result export_step_checked(sqlite3_stmt *stmt, sqlite3 *db,
                                             const char *label)
{
    if (!stmt || !db) {
        return ZCL_ERR(-1, "export step %s: NULL %s",
                       label ? label : "(unknown)",
                       !stmt ? "stmt" : "db");
    }

    /* Snapshot export writes only to a side database owned by this service.
     * AR-managed model writes still go through the normal AR lifecycle. */
    int rc = AR_STEP_ROW_READONLY(stmt);
    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        return ZCL_ERR(-2, "export step %s failed: rc=%d err=%s",
                       label ? label : "(unknown)", rc, sqlite3_errmsg(db));
    }
    return ZCL_OK;
}

static struct zcl_result consensus_snapshot_export_service_run_internal(
    const char *datadir, int32_t state_height,
    const uint8_t state_block_hash[32])
{
    if (!datadir)
        return ZCL_ERR(-1, "export_snapshot: NULL datadir");
    if (state_height < 0 || !state_block_hash)
        return ZCL_ERR(-1, "export_snapshot: invalid state binding");

    char src_path[576], dst_path[576], proof_path[640];
    snprintf(src_path, sizeof(src_path), "%s/node.db", datadir);
    snprintf(dst_path, sizeof(dst_path), "%s/consensus_snapshot.db", datadir);
    if (!export_path(proof_path, sizeof(proof_path), datadir,
                     LOCAL_EXPORT_PROOF_NAME))
        return ZCL_ERR(-1, "export_snapshot: proof path too long");

    struct platform_file_metadata src_metadata;
    if (platform_file_metadata_read(src_path, &src_metadata) !=
            PLATFORM_FILE_METADATA_OK || src_metadata.size < 1000000) {
        return ZCL_ERR(-2, "export_snapshot: %s missing or too small",
                       src_path);
    }

    /* Refuse to clobber a downloaded snapshot with an empty rebuild.
     * On a fresh node, node.db has only the genesis-era UTXOs that
     * block-by-block IBD has produced so far. Exporting that would
     * also unlink the downloaded consensus_snapshot.db that the next
     * boot needs to import, destroying the secure-snapshot fast path
     * for any node that runs file_service and then restarts before
     * full chain catchup. */
    {
        sqlite3 *probe = NULL;
        int64_t src_utxos = 0;
        if (sqlite3_open_v2(src_path, &probe,
                            SQLITE_OPEN_READONLY, NULL) == SQLITE_OK
            && probe) {
            sqlite3_stmt *q = NULL;
            if (sqlite3_prepare_v2(probe,
                    "SELECT COUNT(*) FROM utxos",
                    -1, &q, NULL) == SQLITE_OK && q) {
                if (sqlite3_step(q) == SQLITE_ROW)  // raw-sql-ok:read-only-probe
                    src_utxos = sqlite3_column_int64(q, 0);
                sqlite3_finalize(q);
            }
            sqlite3_close(probe);
        }
        if (src_utxos < 1000) {
            return ZCL_ERR(
                -3,
                "export_snapshot: source utxos=%lld is below the 1000-row "
                "threshold; preserving any downloaded consensus_snapshot.db "
                "so the next boot can import it",
                (long long)src_utxos);
        }
    }

    /* Remove eligibility before touching the body.  A crash at any later
     * boundary leaves either no artifact or an unstamped artifact, neither of
     * which can be advertised by the serving gate. */
    (void)platform_private_file_unlink_missing_ok(proof_path);
    local_export_cache_invalidate();
    (void)platform_private_file_unlink_missing_ok(dst_path);

    sqlite3 *src_db = NULL;
    sqlite3 *dst_db = NULL;
    bool src_db_opened = false;
    bool dst_db_opened = false;
    bool dst_txn_open = false;
    bool src_attached = false;
    struct zcl_result result = ZCL_OK;

    if (sqlite3_open_v2(src_path, &src_db, SQLITE_OPEN_READONLY, NULL)
        != SQLITE_OK || !src_db) {
        result = ZCL_ERR(-4, "export_snapshot: cannot open source db %s",
                         src_path);
        goto export_cleanup;
    }
    src_db_opened = true;

    if (sqlite3_open_v2(dst_path, &dst_db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) != SQLITE_OK ||
        !dst_db) {
        result = ZCL_ERR(-5, "export_snapshot: cannot create destination db %s",
                         dst_path);
        goto export_cleanup;
    }
    dst_db_opened = true;

    struct zcl_result step = export_exec_checked(dst_db,
        "PRAGMA journal_mode=WAL", "set journal_mode WAL");
    if (!step.ok) { result = step; goto export_cleanup; }
    step = export_exec_checked(dst_db, "PRAGMA synchronous=OFF",
                               "set synchronous OFF");
    if (!step.ok) { result = step; goto export_cleanup; }
    step = export_exec_checked(dst_db, "PRAGMA cache_size=-65536",
                               "set cache_size");
    if (!step.ok) { result = step; goto export_cleanup; }
    step = export_exec_checked(dst_db, "PRAGMA temp_store=FILE",
                               "set temp_store FILE");
    if (!step.ok) { result = step; goto export_cleanup; }

    char *attach_sql = sqlite3_mprintf("ATTACH DATABASE '%q' AS src",
                                       src_path);
    if (!attach_sql) {
        result = ZCL_ERR(-12, "export_snapshot: out of memory building ATTACH");
        goto export_cleanup;
    }
    step = export_exec_checked(dst_db, attach_sql, "attach source db");
    sqlite3_free(attach_sql);
    if (!step.ok) { result = step; goto export_cleanup; }
    src_attached = true;

    static const char *safe_tables[] = {
        "blocks", "transactions", "utxos", "addresses",
        "chain_stats", "zslp_tokens", "zslp_balances",
        NULL
    };

    step = export_exec_checked(dst_db, "BEGIN",
                               "begin snapshot transaction");
    if (!step.ok) { result = step; goto export_cleanup; }
    dst_txn_open = true;

    int tables_copied = 0;
    for (int i = 0; safe_tables[i]; i++) {
        char create_sql[512];
        snprintf(create_sql, sizeof(create_sql),
            "CREATE TABLE IF NOT EXISTS %s AS SELECT * FROM src.%s",
            safe_tables[i], safe_tables[i]);
        step = export_exec_checked(dst_db, create_sql,
                                   "copy consensus table");
        if (!step.ok) { result = step; goto export_cleanup; }
        tables_copied++;
    }

    step = export_exec_checked(dst_db,
        "CREATE TABLE IF NOT EXISTS _snapshot_meta "
        "(key TEXT PRIMARY KEY, value TEXT)",
        "create metadata table");
    if (!step.ok) { result = step; goto export_cleanup; }

    sqlite3_stmt *meta = NULL;
    step = export_prepare_checked(
        dst_db,
        "INSERT INTO _snapshot_meta(key,value) VALUES(?,?)",
        &meta, "prepare metadata insert");
    if (!step.ok) { result = step; goto export_cleanup; }

    char value_buf[32];
    snprintf(value_buf, sizeof(value_buf), "%d", state_height);
    if (sqlite3_bind_text(meta, 1, "height", -1, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_text(meta, 2, value_buf, -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        result = ZCL_ERR(-6, "export_snapshot: bind metadata height failed: %s",
                         sqlite3_errmsg(dst_db));
        sqlite3_finalize(meta);
        goto export_cleanup;
    }
    step = export_step_checked(meta, dst_db, "insert metadata height");
    if (!step.ok) {
        result = step;
        sqlite3_finalize(meta);
        goto export_cleanup;
    }

    sqlite3_reset(meta);
    sqlite3_clear_bindings(meta);

    snprintf(value_buf, sizeof(value_buf), "%d", tables_copied);
    if (sqlite3_bind_text(meta, 1, "tables", -1, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_text(meta, 2, value_buf, -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        result = ZCL_ERR(-7, "export_snapshot: bind metadata tables failed: %s",
                         sqlite3_errmsg(dst_db));
        sqlite3_finalize(meta);
        goto export_cleanup;
    }
    step = export_step_checked(meta, dst_db, "insert metadata table count");
    if (!step.ok) {
        result = step;
        sqlite3_finalize(meta);
        goto export_cleanup;
    }
    sqlite3_finalize(meta);
    meta = NULL;

    step = export_exec_checked(dst_db, "COMMIT",
                               "commit snapshot transaction");
    if (!step.ok) { result = step; goto export_cleanup; }
    dst_txn_open = false;
    src_attached = false;
    step = export_exec_checked(dst_db, "DETACH DATABASE src",
                               "detach source db");
    if (!step.ok) { result = step; goto export_cleanup; }

    step = export_exec_checked(dst_db, "PRAGMA synchronous=NORMAL",
                               "restore sync NORMAL");
    if (!step.ok) { result = step; goto export_cleanup; }
    step = export_exec_checked(dst_db, "VACUUM", "vacuum snapshot");
    if (!step.ok) { result = step; goto export_cleanup; }

    struct platform_file_metadata dst_metadata;
    if (platform_file_metadata_read(dst_path, &dst_metadata) !=
        PLATFORM_FILE_METADATA_OK) {
        result = ZCL_ERR(-8, "export_snapshot: destination stat failed: %s",
                         dst_path);
        goto export_cleanup;
    }

    printf("Consensus snapshot: %d tables, height %d, %.0f MB\n",
           tables_copied, state_height,
           (double)dst_metadata.size / (1024.0 * 1024.0));
    if (tables_copied == 0) {
        result = ZCL_ERR(-9, "export_snapshot: no tables exported");
        goto export_cleanup;
    }

export_cleanup:
    if (dst_db_opened && dst_db) {
        if (dst_txn_open && !sqlite3_get_autocommit(dst_db)) {
            step = export_exec_checked(dst_db, "ROLLBACK",
                                       "rollback snapshot tx");
            if (!step.ok && result.ok)
                result = step;
        }
        if (src_attached) {
            step = export_exec_checked(dst_db, "DETACH DATABASE src",
                                       "detach source db");
            if (!step.ok && result.ok)
                result = step;
        }
        sqlite3_close(dst_db);
    }
    if (src_db_opened && src_db)
        sqlite3_close(src_db);

    if (!result.ok) {
        LOG_WARN("consensus_snapshot_export", "%s", result.message);
        (void)platform_private_file_unlink_missing_ok(dst_path);
        (void)platform_private_file_unlink_missing_ok(proof_path);
    } else if (!sqlite_has_bound_block(dst_path, state_height,
                                       state_block_hash)) {
        result = ZCL_ERR(-27, "export_snapshot: exported blocks do not contain "
                              "the bound state h=%d", state_height);
        LOG_WARN("consensus_snapshot_export", "%s", result.message);
        (void)platform_private_file_unlink_missing_ok(dst_path);
        (void)platform_private_file_unlink_missing_ok(proof_path);
    } else {
        struct zcl_result proof_result = write_local_export_proof(
            datadir, state_height, state_block_hash);
        if (!proof_result.ok) {
            result = proof_result;
            LOG_WARN("consensus_snapshot_export", "%s", result.message);
            (void)platform_private_file_unlink_missing_ok(dst_path);
            (void)platform_private_file_unlink_missing_ok(proof_path);
        }
    }
    platform_allocator_release_free_pages();

    return result;
}

struct zcl_result consensus_snapshot_export_service_run_bound(
    const char *datadir, int32_t state_height,
    const uint8_t state_block_hash[32])
{
    return consensus_snapshot_export_service_run_internal(
        datadir, state_height, state_block_hash);
}
