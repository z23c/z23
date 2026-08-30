/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Full-history consensus-state exporter containment tests. */

#define _GNU_SOURCE

#include "test/test_core.h"

#include "config/boot.h"  /* boot_mint_anchor_export_bundle (lane A1 wiring) */
#include "config/consensus_state_snapshot_export.h"
#include "config/consensus_state_snapshot_install.h"
#include "config/consensus_state_bundle_validate.h"
#include "config/consensus_state_producer_receipt.h"
#include "../../../config/src/consensus_state_proof_prefix.h"
#include "jobs/tip_finalize_stage.h"
#include "chain/checkpoints.h"
#include "crypto/sha3.h"
#include "sapling/incremental_merkle_tree.h"
#include "storage/anchor_kv.h"
#include "storage/checkpoint_ladder.h"
#include "storage/checkpoint_rung.h"
#include "storage/coins_kv.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"
#include "services/sync_trust_policy.h"

#include <sqlite3.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

void reducer_frontier_test_set_compiled_anchor(int32_t height);

#define CSE_CHECK(label, expr) do {                                      \
    printf("consensus_state_export: %s... ", (label));                  \
    if (expr) printf("OK\n");                                         \
    else { printf("FAIL\n"); failures++; }                            \
} while (0)

struct cse_parent_swap_fixture {
    char original[512];
    char moved[512];
    char attacker[512];
    bool ran;
    bool ok;
};

static void cse_parent_swap_after_bind(void *opaque)
{
    struct cse_parent_swap_fixture *f = opaque;
    f->ran = true;
    f->ok = rename(f->original, f->moved) == 0 &&
            mkdir(f->attacker, 0700) == 0 &&
            symlink(f->attacker, f->original) == 0;
}

struct cse_final_race_fixture {
    char final[768];
    bool ran;
    bool ok;
};

struct cse_staging_link_fixture {
    int dirfd;
    char alias[128];
    bool ran;
    bool ok;
};

struct cse_retained_writer_fixture {
    int dirfd;
    int writer_fd;
    bool ran;
};

/* Keep the retained alias above the ordinary low-fd set so the production
 * /proc/self/fd scan proves it is unbounded. Some hermetic runners cap
 * RLIMIT_NOFILE at exactly 1024, where F_DUPFD_CLOEXEC(min=1024) cannot
 * succeed; on those hosts use a high valid descriptor below the cap so the
 * same retained-writer refusal is still exercised. */
static int cse_retained_writer_dup_floor(void)
{
    long limit = sysconf(_SC_OPEN_MAX);
    if (limit > 1024)
        return 1024;
    if (limit > 16)
        return (int)(limit / 2);
    return 3;
}

static void cse_final_race_after_create(void *opaque, int staging_fd)
{
    struct cse_final_race_fixture *f = opaque;
    (void)staging_fd;
    f->ran = true;
    int fd = open(f->final,
                  O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW,
                  0600);
    if (fd < 0)
        return;
    static const char marker[] = "attacker final";
    bool wrote = write(fd, marker, sizeof(marker)) == (ssize_t)sizeof(marker);
    bool closed = close(fd) == 0;
    f->ok = wrote && closed;
}

static void cse_staging_link_after_create(void *opaque, int fd)
{
    struct cse_staging_link_fixture *f = opaque;
    f->ran = true;
    struct stat dir_st, st;
    if (fd < 0 || fstat(f->dirfd, &dir_st) != 0 || fstat(fd, &st) != 0 ||
        !S_ISREG(st.st_mode) || st.st_nlink != 0 ||
        st.st_dev != dir_st.st_dev)
        return;
    char source[64];
    int n = snprintf(source, sizeof(source), "/proc/self/fd/%d", fd);
    f->ok = n > 0 && (size_t)n < sizeof(source) &&
        linkat(AT_FDCWD, source, f->dirfd, f->alias,
               AT_SYMLINK_FOLLOW) == 0;
}

static void cse_retain_staging_writer(void *opaque, int fd)
{
    struct cse_retained_writer_fixture *f = opaque;
    f->ran = true;
    struct stat dir_st, st;
    int flags = fd >= 0 ? fcntl(fd, F_GETFL) : -1;
    if (flags < 0 || (flags & O_ACCMODE) != O_RDWR ||
        fstat(f->dirfd, &dir_st) != 0 || fstat(fd, &st) != 0 ||
        !S_ISREG(st.st_mode) || st.st_nlink != 0 ||
        st.st_dev != dir_st.st_dev)
        return;
    f->writer_fd = fcntl(fd, F_DUPFD_CLOEXEC,
                         cse_retained_writer_dup_floor());
}

/* Mirrors log_level_capture() in test_log_level.c / csa_mint_capture() in
 * test_coinbase_subsidy_adversarial.c: redirect stderr to a scratch file for
 * the duration of one consensus_state_snapshot_export() call, then hand back
 * whatever landed in it so the test can grep for the "[export] ..." progress
 * markers (config/src/consensus_state_snapshot_export_proof.c /
 * _write.c) that make the otherwise-silent 30-60+ minute prove/write path
 * observable. Best-effort on capture-plumbing failure: still runs the export
 * (uncaptured) so the caller's status/result assertions remain meaningful. */
static bool cse_capture_export_stderr(
    sqlite3 *db, const struct consensus_state_snapshot_export_request *request,
    struct consensus_state_export_result *result, bool *exported,
    char *out, size_t out_len)
{
    if (out && out_len > 0)
        out[0] = '\0';
    mkdir("./test-tmp", 0755);
    char path[256];
    snprintf(path, sizeof(path), "./test-tmp/cse_export_stderr_%d.log",
             (int)getpid());

    fflush(stderr);
    int saved_fd = dup(STDERR_FILENO);
    FILE *capf = (saved_fd >= 0) ? fopen(path, "w+") : NULL;
    if (!capf) {
        if (saved_fd >= 0)
            close(saved_fd);
        *exported = consensus_state_snapshot_export(db, request, result);
        return false;
    }
    dup2(fileno(capf), STDERR_FILENO);

    *exported = consensus_state_snapshot_export(db, request, result);

    fflush(stderr);
    dup2(saved_fd, STDERR_FILENO);
    close(saved_fd);

    if (out && out_len > 0) {
        long sz = ftell(capf);
        if (sz > 0) {
            rewind(capf);
            size_t want = (size_t)sz < out_len - 1 ? (size_t)sz : out_len - 1;
            size_t got = fread(out, 1, want, capf);
            out[got] = '\0';
        }
    }
    fclose(capf);
    unlink(path);
    return true;
}

static bool cse_exec(sqlite3 *db, const char *sql)
{
    char *error = NULL;
    bool ok = sqlite3_exec(db, sql, NULL, NULL, &error) == SQLITE_OK;
    if (error)
        sqlite3_free(error);
    return ok;
}

static bool cse_insert_hash_row(sqlite3 *db, const char *sql, int height,
                                const uint8_t hash[32])
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    bool ok = sqlite3_bind_int(st, 1, height) == SQLITE_OK &&
              sqlite3_bind_blob(st, 2, hash, 32, SQLITE_STATIC) ==
                  SQLITE_OK &&
              sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return ok;
}

static bool cse_insert_header(sqlite3 *db, int height,
                              const uint8_t hash[32],
                              const uint8_t parent[32])
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO header_admit_log(height,hash,parent_hash) "
            "VALUES(?,?,?)", -1, &st, NULL) != SQLITE_OK)
        return false;
    bool ok = sqlite3_bind_int(st, 1, height) == SQLITE_OK &&
              sqlite3_bind_blob(st, 2, hash, 32, SQLITE_STATIC) == SQLITE_OK;
    if (ok && height == 0)
        ok = sqlite3_bind_null(st, 3) == SQLITE_OK;
    else if (ok)
        ok = sqlite3_bind_blob(st, 3, parent, 32, SQLITE_STATIC) == SQLITE_OK;
    if (ok)
        ok = sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return ok;
}

static void cse_u64(struct sha3_256_ctx *ctx, uint64_t value)
{
    uint8_t le[8];
    for (size_t i = 0; i < sizeof(le); i++)
        le[i] = (uint8_t)(value >> (8u * i));
    sha3_256_write(ctx, le, sizeof(le));
}

static void cse_chain_corpus_digest(uint8_t hash[2][32], uint8_t out[32])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    static const char domain[] =
        "zcl.consensus_state_bundle.v1/source-header-chain";
    sha3_256_write(&ctx, (const uint8_t *)domain, sizeof(domain));
    uint8_t zero[32] = {0};
    cse_u64(&ctx, 0);
    sha3_256_write(&ctx, hash[0], 32);
    sha3_256_write(&ctx, zero, 32);
    cse_u64(&ctx, 1);
    sha3_256_write(&ctx, hash[1], 32);
    sha3_256_write(&ctx, hash[0], 32);
    sha3_256_finalize(&ctx, out);
}

static bool cse_binary_digest(uint8_t out[32])
{
    int fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    uint8_t buffer[32768];
    bool ok = true;
    for (;;) {
        ssize_t n = read(fd, buffer, sizeof(buffer));
        if (n > 0) {
            sha3_256_write(&ctx, buffer, (size_t)n);
            continue;
        }
        if (n == 0)
            break;
        if (errno == EINTR)
            continue;
        ok = false;
        break;
    }
    if (close(fd) != 0)
        ok = false;
    if (ok)
        sha3_256_finalize(&ctx, out);
    return ok;
}

static bool cse_seed_receipt_version(sqlite3 *db, uint8_t hash[2][32],
                                     uint8_t validation_profile, bool corrupt,
                                     uint8_t receipt_version,
                                     const uint8_t *running_binary_override)
{
    if (!cse_exec(db,
            "CREATE TABLE IF NOT EXISTS consensus_state_source_receipt("
            "singleton INTEGER PRIMARY KEY,schema TEXT NOT NULL,"
            "source_epoch_digest BLOB NOT NULL,source_tree_root BLOB NOT NULL,"
            "running_binary_digest BLOB NOT NULL,toolchain_digest BLOB NOT NULL,"
            "build_inputs_digest BLOB NOT NULL,chain_corpus_digest BLOB NOT NULL,"
            "source_clean INTEGER NOT NULL,validation_profile INTEGER NOT NULL,"
            "producer_commit TEXT NOT NULL,fold_cursor INTEGER NOT NULL,"
            "receipt_digest BLOB NOT NULL)"))
        return false;
    struct consensus_state_source_receipt receipt;
    memset(&receipt, 0, sizeof(receipt));
    receipt.schema_version = receipt_version;
    for (size_t i = 0; i < 32; i++) {
        receipt.source_tree_root[i] = (uint8_t)(0x31u + i);
        receipt.toolchain_digest[i] = (uint8_t)(0x71u + i);
        receipt.build_inputs_digest[i] = (uint8_t)(0xb1u + i);
    }
    if (running_binary_override)
        memcpy(receipt.running_binary_digest, running_binary_override, 32);
    else if (!cse_binary_digest(receipt.running_binary_digest))
        return false;
    cse_chain_corpus_digest(hash, receipt.chain_corpus_digest);
    if (receipt_version == CONSENSUS_STATE_SOURCE_RECEIPT_V1) {
        snprintf(receipt.producer_commit, sizeof(receipt.producer_commit),
                 "0123456789abcdef0123456789abcdef01234567");
    }
    receipt.source_clean = true;
    receipt.validation_profile = validation_profile;
    receipt.fold_cursor = 2;
    consensus_state_source_epoch_digest(&receipt,
                                        receipt.source_epoch_digest);
    consensus_state_source_receipt_digest(&receipt, receipt.receipt_digest);
    if (corrupt)
        receipt.receipt_digest[0] ^= 1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO consensus_state_source_receipt VALUES"
            "(1,?,?,?,?,?,?,?,?,?,?,?,?)", -1, &st, NULL) != SQLITE_OK)
        return false;
    int i = 1;
    const char *receipt_schema =
        consensus_state_source_receipt_schema(receipt.schema_version);
    size_t commit_len = strnlen(receipt.producer_commit,
                                sizeof(receipt.producer_commit));
    bool ok = receipt_schema &&
              sqlite3_bind_text(st, i++, receipt_schema, -1,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_blob(st, i++, receipt.source_epoch_digest, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_blob(st, i++, receipt.source_tree_root, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_blob(st, i++, receipt.running_binary_digest, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_blob(st, i++, receipt.toolchain_digest, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_blob(st, i++, receipt.build_inputs_digest, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_blob(st, i++, receipt.chain_corpus_digest, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_int(st, i++, receipt.source_clean ? 1 : 0) ==
                  SQLITE_OK &&
              sqlite3_bind_int(st, i++, receipt.validation_profile) ==
                  SQLITE_OK &&
              sqlite3_bind_text(st, i++, receipt.producer_commit,
                                (int)commit_len,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_int64(st, i++, receipt.fold_cursor) == SQLITE_OK &&
              sqlite3_bind_blob(st, i++, receipt.receipt_digest, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    if (ok)
        ok = progress_meta_set(db, CONSENSUS_STATE_SOURCE_EPOCH_META_KEY,
                               receipt.source_epoch_digest, 32);
    return ok;
}

static bool cse_seed_receipt(sqlite3 *db, uint8_t hash[2][32],
                             uint8_t validation_profile, bool corrupt)
{
    return cse_seed_receipt_version(
        db, hash, validation_profile, corrupt,
        CONSENSUS_STATE_SOURCE_RECEIPT_V2, NULL);
}

static bool cse_insert_tip(sqlite3 *db, int height, const char *status,
                           const uint8_t hash[32])
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO tip_finalize_log(height,ok,status,tip_hash) "
            "VALUES(?,1,?,?)", -1, &st, NULL) != SQLITE_OK)
        return false;
    bool ok = sqlite3_bind_int(st, 1, height) == SQLITE_OK &&
              sqlite3_bind_text(st, 2, status, -1, SQLITE_STATIC) ==
                  SQLITE_OK &&
              sqlite3_bind_blob(st, 3, hash, 32, SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return ok;
}

static bool cse_seed_source(sqlite3 *db, uint8_t hash[2][32], uint8_t nf[32])
{
    static const char schema[] =
        "CREATE TABLE header_admit_log("
        "height INTEGER PRIMARY KEY,hash BLOB NOT NULL,parent_hash BLOB);"
        "CREATE TABLE validate_headers_log("
        "height INTEGER PRIMARY KEY,hash BLOB NOT NULL,ok INTEGER NOT NULL);"
        "CREATE TABLE body_fetch_log("
        "height INTEGER PRIMARY KEY,hash BLOB NOT NULL,ok INTEGER NOT NULL);"
        "CREATE TABLE body_persist_log("
        "height INTEGER PRIMARY KEY,ok INTEGER NOT NULL);"
        "CREATE TABLE script_validate_log("
        "height INTEGER PRIMARY KEY,ok INTEGER NOT NULL,status TEXT NOT NULL,"
        "block_hash BLOB,source_epoch_digest BLOB);"
        "CREATE TABLE proof_validate_log("
        "height INTEGER PRIMARY KEY,ok INTEGER NOT NULL,status TEXT NOT NULL,"
        "block_hash BLOB,source_epoch_digest BLOB);"
        "CREATE TABLE utxo_apply_log("
        "height INTEGER PRIMARY KEY,ok INTEGER NOT NULL,status TEXT NOT NULL);"
        "CREATE TABLE utxo_apply_delta("
        "height INTEGER PRIMARY KEY,branch_hash BLOB NOT NULL,"
        "spent_blob BLOB NOT NULL,added_blob BLOB NOT NULL);"
        "CREATE TABLE tip_finalize_log("
        "height INTEGER PRIMARY KEY,ok INTEGER NOT NULL,status TEXT NOT NULL,"
        "tip_hash BLOB NOT NULL);"
        "INSERT INTO stage_cursor(name,cursor,updated_at) VALUES"
        "('header_admit',2,1),('validate_headers',2,1),"
        "('body_fetch',2,1),('body_persist',2,1),"
        "('script_validate',2,1),('proof_validate',2,1),"
        "('utxo_apply',2,1),('tip_finalize',1,1);"
        "INSERT INTO body_persist_log VALUES(0,1),(1,1);"
        "INSERT INTO utxo_apply_log VALUES(0,1,'verified'),(1,1,'verified');";
    if (!cse_exec(db, schema) || !coins_kv_ensure_schema(db) ||
        !anchor_kv_initialize_history(db, 0) ||
        !nullifier_kv_initialize_history(db, 0))
        return false;

    for (size_t i = 0; i < 32; i++) {
        hash[0][i] = (uint8_t)(0x21u + i);
        hash[1][i] = (uint8_t)(0x61u + i);
        nf[i] = (uint8_t)(0xa1u + i);
    }
    if (!cse_seed_receipt(db, hash, CONSENSUS_STATE_VALIDATION_FULL, false))
        return false;
    if (!cse_insert_header(db, 0, hash[0], NULL) ||
        !cse_insert_header(db, 1, hash[1], hash[0]) ||
        !cse_insert_tip(db, 0, "finalized", hash[1]) ||
        !cse_insert_tip(db, 1, "anchor", hash[1]))
        return false;
    static const char *const hash_sql[] = {
        "INSERT INTO validate_headers_log VALUES(?,?,1)",
        "INSERT INTO body_fetch_log VALUES(?,?,1)",
        "INSERT INTO script_validate_log("
        "height,block_hash,ok,status,source_epoch_digest) "
        "VALUES(?,?,1,'verified',(SELECT value FROM progress_meta WHERE key='"
        CONSENSUS_STATE_SOURCE_EPOCH_META_KEY "'))",
        "INSERT INTO proof_validate_log("
        "height,block_hash,ok,status,source_epoch_digest) "
        "VALUES(?,?,1,'verified',(SELECT value FROM progress_meta WHERE key='"
        CONSENSUS_STATE_SOURCE_EPOCH_META_KEY "'))",
        ("INSERT INTO utxo_apply_delta(height,branch_hash,spent_blob,added_blob) "
         "VALUES(?,?,X'',X'')"),
    };
    for (size_t table = 0; table < sizeof(hash_sql) / sizeof(hash_sql[0]);
         table++) {
        for (int height = 0; height <= 1; height++) {
            if (!cse_insert_hash_row(db, hash_sql[table], height,
                                     hash[height]))
                return false;
        }
    }

    uint8_t txid[32];
    for (size_t i = 0; i < sizeof(txid); i++)
        txid[i] = (uint8_t)(0xc1u + i);
    const uint8_t script[] = {0x51};
    if (!coins_kv_add(db, txid, 0, 5000, 0, true, script,
                      sizeof(script)))
        return false;
    struct incremental_merkle_tree sprout;
    struct incremental_merkle_tree sapling;
    struct uint256 leaf;
    sprout_tree_init(&sprout);
    sapling_tree_init(&sapling);
    for (size_t i = 0; i < sizeof(leaf.data); i++)
        leaf.data[i] = (uint8_t)(0xe1u + i);
    incremental_tree_append(&sprout, &leaf);
    incremental_tree_append(&sapling, &leaf);
    if (!anchor_kv_add_tree(db, ANCHOR_POOL_SPROUT, &sprout, 1) ||
        !anchor_kv_add_tree(db, ANCHOR_POOL_SAPLING, &sapling, 1) ||
        !nullifier_kv_add(db, nf, 0, 1))
        return false;

    /* Stamp the exporter-required authority markers through the SAME production
     * helper the -mint-anchor FULL-profile finalize path uses (config/boot.h), so
     * a passing export here proves that finalize path yields an exporter-
     * admissible source — not just that a hand-stamped fixture does. */
    if (!boot_mint_anchor_stamp_sovereign_markers(db) ||
        !cse_exec(db, "BEGIN IMMEDIATE") ||
        !coins_kv_set_applied_height_in_tx(db, 2) ||
        !cse_exec(db, "COMMIT")) {
        (void)cse_exec(db, "ROLLBACK");
        return false;
    }
    return true;
}

/* ── checkpoint ladder rung/verifier fixtures (lane F1) ───────────── */

static uint8_t g_rung_hook_hash[32];
static bool g_rung_hook_hash_return;
static bool rung_hook_block_hash_at(void *ctx, int32_t height, uint8_t out[32])
{
    (void)ctx;
    (void)height;
    if (!g_rung_hook_hash_return)
        return false;
    memcpy(out, g_rung_hook_hash, 32);
    return true;
}

static struct checkpoint_rung g_rung_hook_rederive;
static bool g_rung_hook_rederive_return;
static bool rung_hook_rederive_at(void *ctx, int32_t height,
                                  struct checkpoint_rung *out)
{
    (void)ctx;
    (void)height;
    if (!g_rung_hook_rederive_return)
        return false;
    *out = g_rung_hook_rederive;
    return true;
}

/* Build a minimal consensus-state bundle sqlite at `path` with a few rows so
 * checkpoint_rung_derive_from_bundle has deterministic input. */
static bool cse_build_rung_bundle(const char *path)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK)
        return false;
    const char *ddl =
        "CREATE TABLE bundle_meta(singleton INTEGER PRIMARY KEY, height INTEGER,"
        " block_hash BLOB);"
        "CREATE TABLE coins(txid BLOB, vout INTEGER, value INTEGER, script BLOB,"
        " height INTEGER, is_coinbase INTEGER);"
        "CREATE TABLE anchors(pool INTEGER, anchor BLOB, height INTEGER,"
        " tree BLOB);"
        "CREATE TABLE nullifiers(pool INTEGER, nf BLOB, height INTEGER);";
    bool ok = sqlite3_exec(db, ddl, NULL, NULL, NULL) == SQLITE_OK;
    uint8_t bh[32];
    for (int i = 0; i < 32; i++)
        bh[i] = (uint8_t)(0x40 + i);
    sqlite3_stmt *st = NULL;
    if (ok && sqlite3_prepare_v2(db,
            "INSERT INTO bundle_meta VALUES(1,?,?)", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(st, 1, 4242);
        sqlite3_bind_blob(st, 2, bh, 32, SQLITE_STATIC);
        ok = ok && sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:test-fixture
        sqlite3_finalize(st);
    } else {
        ok = false;
    }
    /* two coins (strictly increasing txid) */
    for (int r = 0; ok && r < 2; r++) {
        uint8_t txid[32];
        memset(txid, 0, 32);
        txid[0] = (uint8_t)(r + 1);
        uint8_t script[4] = { 0x76, 0xa9, 0x00, 0x88 };
        st = NULL;
        ok = sqlite3_prepare_v2(db, "INSERT INTO coins VALUES(?,?,?,?,?,?)", -1,
                                &st, NULL) == SQLITE_OK;
        if (ok) {
            sqlite3_bind_blob(st, 1, txid, 32, SQLITE_STATIC);
            sqlite3_bind_int64(st, 2, r);
            sqlite3_bind_int64(st, 3, 1000 + r);
            sqlite3_bind_blob(st, 4, script, 4, SQLITE_STATIC);
            sqlite3_bind_int64(st, 5, 10 + r);
            sqlite3_bind_int64(st, 6, r == 0 ? 1 : 0);
            ok = sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:test-fixture
            sqlite3_finalize(st);
        }
    }
    /* one anchor per pool + one nullifier per pool */
    for (int pool = 0; ok && pool < 2; pool++) {
        uint8_t a[32], tree[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
        memset(a, (uint8_t)(0x10 + pool), 32);
        st = NULL;
        ok = sqlite3_prepare_v2(db, "INSERT INTO anchors VALUES(?,?,?,?)", -1,
                                &st, NULL) == SQLITE_OK;
        if (ok) {
            sqlite3_bind_int64(st, 1, pool);
            sqlite3_bind_blob(st, 2, a, 32, SQLITE_STATIC);
            sqlite3_bind_int64(st, 3, 100 + pool);
            sqlite3_bind_blob(st, 4, tree, 8, SQLITE_STATIC);
            ok = sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:test-fixture
            sqlite3_finalize(st);
        }
        uint8_t nf[32];
        memset(nf, (uint8_t)(0x20 + pool), 32);
        if (ok) {
            st = NULL;
            ok = sqlite3_prepare_v2(db, "INSERT INTO nullifiers VALUES(?,?,?)",
                                    -1, &st, NULL) == SQLITE_OK;
            if (ok) {
                sqlite3_bind_int64(st, 1, pool);
                sqlite3_bind_blob(st, 2, nf, 32, SQLITE_STATIC);
                sqlite3_bind_int64(st, 3, 50 + pool);
                ok = sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:test-fixture
                sqlite3_finalize(st);
            }
        }
    }
    sqlite3_close(db);
    return ok;
}

/* Write a rung to <dir>/rung-<height>.rung. */
static bool cse_write_rung_file(const char *dir, struct checkpoint_rung *r)
{
    uint8_t wire[CHECKPOINT_RUNG_WIRE_SIZE];
    if (!checkpoint_rung_serialize(r, wire))
        return false;
    char path[1024];
    snprintf(path, sizeof(path), "%s/rung-%d.rung", dir, r->height);
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    bool ok = fwrite(wire, 1, sizeof(wire), f) == sizeof(wire);
    fclose(f);
    return ok;
}

static void cse_run_rung_ladder_tests(int *failures_ptr)
{
    int failures = *failures_ptr;

    /* (1) GOLDEN fold: the compiled sealed keystone's rom_state_root MUST
     * recompute from its own fields through the rung fold — this pins the rung
     * fold to the byte-exact sealed constant in checkpoints.c. */
    const struct rom_state_checkpoint *cp = get_rom_state_checkpoint();
    CSE_CHECK("rung: compiled keystone present", cp != NULL);
    struct checkpoint_rung baked;
    CSE_CHECK("rung: from_rom_checkpoint",
              cp && checkpoint_rung_from_rom_checkpoint(cp, NULL, &baked));
    CSE_CHECK("rung: fold reproduces sealed rom_state_root byte-for-byte",
              cp && memcmp(baked.rom_state_root, cp->rom_state_root, 32) == 0);
    CSE_CHECK("rung: baked rung is self-consistent",
              checkpoint_rung_self_consistent(&baked));

    /* (1b) determinism + serialize/parse round-trip. */
    uint8_t wire_a[CHECKPOINT_RUNG_WIRE_SIZE];
    uint8_t wire_b[CHECKPOINT_RUNG_WIRE_SIZE];
    struct checkpoint_rung baked2 = baked;
    CSE_CHECK("rung: serialize A", checkpoint_rung_serialize(&baked, wire_a));
    CSE_CHECK("rung: serialize B", checkpoint_rung_serialize(&baked2, wire_b));
    CSE_CHECK("rung: serialize is deterministic",
              memcmp(wire_a, wire_b, sizeof(wire_a)) == 0);
    struct checkpoint_rung parsed;
    CSE_CHECK("rung: parse round-trips",
              checkpoint_rung_parse(wire_a, sizeof(wire_a), &parsed) &&
              memcmp(&parsed, &baked, sizeof(parsed)) == 0);

    /* (1c) parse rejects tampered / foreign bytes. */
    uint8_t tampered[CHECKPOINT_RUNG_WIRE_SIZE];
    memcpy(tampered, wire_a, sizeof(tampered));
    tampered[40] ^= 0xff; /* flip a byte inside the body */
    struct checkpoint_rung junk;
    CSE_CHECK("rung: parse rejects tampered body",
              !checkpoint_rung_parse(tampered, sizeof(tampered), &junk));
    memcpy(tampered, wire_a, sizeof(tampered));
    tampered[0] ^= 0xff; /* break magic */
    CSE_CHECK("rung: parse rejects bad magic",
              !checkpoint_rung_parse(tampered, sizeof(tampered), &junk));
    CSE_CHECK("rung: parse rejects short buffer",
              !checkpoint_rung_parse(wire_a, sizeof(wire_a) - 1, &junk));

    /* (1d) C fragment shape. */
    char frag[8192];
    int fn = checkpoint_rung_emit_c_fragment(&baked, frag, sizeof(frag));
    CSE_CHECK("rung: fragment emits within buffer",
              fn > 0 && (size_t)fn < sizeof(frag));
    CSE_CHECK("rung: fragment carries rom_state_checkpoint literal",
              strstr(frag, "struct rom_state_checkpoint g_rom_state_rung_") !=
                  NULL);
    CSE_CHECK("rung: fragment is labelled candidate_unbaked",
              strstr(frag, "candidate_unbaked") != NULL);

    /* (2) derive-from-bundle plumbing. */
    char bundle_path[] = "/tmp/zcl-rung-bundle-XXXXXX";
    int bfd = mkstemp(bundle_path);
    CSE_CHECK("rung: bundle temp created", bfd >= 0);
    if (bfd >= 0)
        close(bfd);
    CSE_CHECK("rung: bundle built", cse_build_rung_bundle(bundle_path));
    sqlite3 *bdb = NULL;
    CSE_CHECK("rung: bundle opens",
              sqlite3_open(bundle_path, &bdb) == SQLITE_OK);
    struct checkpoint_rung derived;
    bool dok = bdb && checkpoint_rung_derive_from_bundle(bdb, NULL, &derived);
    CSE_CHECK("rung: derive from bundle", dok);
    CSE_CHECK("rung: derived height/counts match inserted rows",
              dok && derived.height == 4242 && derived.utxo_count == 2 &&
                  derived.anchor_count == 2 && derived.nullifier_count == 2 &&
                  derived.sprout_frontier_height == 100 &&
                  derived.sapling_frontier_height == 101);
    CSE_CHECK("rung: derived rung is self-consistent",
              dok && checkpoint_rung_self_consistent(&derived));
    if (bdb)
        sqlite3_close(bdb);
    (void)unlink(bundle_path);

    /* (3) verifier: the baked rung binds and reads VERIFIED. */
    struct checkpoint_ladder_result res[8];
    bool any_mm = false;
    size_t n = checkpoint_ladder_verify(&baked, 1, NULL, res, 8, &any_mm);
    CSE_CHECK("verify: baked rung -> 1 result, no mismatch",
              n == 1 && !any_mm);
    CSE_CHECK("verify: baked rung is bound + VERIFIED + not candidate",
              n == 1 && res[0].bound && !res[0].candidate_unbaked &&
                  res[0].verdict == CHECKPOINT_RUNG_VERIFIED);

    /* (4) tampered rung AT the keystone height conflicts the sealed keystone. */
    struct checkpoint_rung evil = baked;
    evil.anchor_digest[0] ^= 0xff;
    checkpoint_rung_finalize(&evil); /* self-consistent but fields differ */
    any_mm = false;
    n = checkpoint_ladder_verify(&evil, 1, NULL, res, 8, &any_mm);
    CSE_CHECK("verify: divergent keystone-height rung -> MISMATCH",
              n == 1 && any_mm && res[0].verdict == CHECKPOINT_RUNG_MISMATCH &&
                  !res[0].bound);

    /* (5) self-inconsistent artifact (root not refolded) -> MISMATCH. */
    struct checkpoint_rung broken = baked;
    broken.rom_state_root[0] ^= 0xff; /* corrupt WITHOUT re-finalizing */
    any_mm = false;
    n = checkpoint_ladder_verify(&broken, 1, NULL, res, 8, &any_mm);
    CSE_CHECK("verify: self-inconsistent rung -> MISMATCH",
              n == 1 && any_mm && res[0].verdict == CHECKPOINT_RUNG_MISMATCH);

    /* (6) monotonicity on candidate rungs away from the keystone height. */
    struct checkpoint_rung a = {0}, b = {0};
    a.height = 100;
    a.chainwork[31] = 5;
    checkpoint_rung_finalize(&a);
    b.height = 100; /* equal height -> not strictly increasing */
    b.chainwork[31] = 6;
    checkpoint_rung_finalize(&b);
    struct checkpoint_rung pair_eq[2] = { a, b };
    any_mm = false;
    n = checkpoint_ladder_verify(pair_eq, 2, NULL, res, 8, &any_mm);
    CSE_CHECK("verify: equal heights -> second rung MISMATCH",
              n == 2 && any_mm && res[0].verdict != CHECKPOINT_RUNG_MISMATCH &&
                  res[1].verdict == CHECKPOINT_RUNG_MISMATCH);

    struct checkpoint_rung c = {0};
    c.height = 200;
    c.chainwork[31] = 3; /* lower chainwork than a(=5) at a greater height */
    checkpoint_rung_finalize(&c);
    struct checkpoint_rung pair_cw[2] = { a, c };
    any_mm = false;
    n = checkpoint_ladder_verify(pair_cw, 2, NULL, res, 8, &any_mm);
    CSE_CHECK("verify: decreasing chainwork -> MISMATCH",
              n == 2 && any_mm && res[1].verdict == CHECKPOINT_RUNG_MISMATCH);

    /* a lone candidate away from the keystone with no hooks is UNVERIFIABLE and
     * always candidate_unbaked (honesty rule). */
    any_mm = false;
    n = checkpoint_ladder_verify(&a, 1, NULL, res, 8, &any_mm);
    CSE_CHECK("verify: lone candidate -> UNVERIFIABLE, candidate_unbaked",
              n == 1 && !any_mm && res[0].verdict ==
                  CHECKPOINT_RUNG_UNVERIFIABLE && res[0].candidate_unbaked &&
                  !res[0].bound);

    /* (7) hooks: header-chain + rederive witnesses. */
    struct checkpoint_ladder_hooks hooks = {
        .ctx = NULL,
        .block_hash_at = rung_hook_block_hash_at,
        .rederive_at = NULL,
    };
    memcpy(g_rung_hook_hash, a.block_hash, 32);
    g_rung_hook_hash_return = true;
    any_mm = false;
    n = checkpoint_ladder_verify(&a, 1, &hooks, res, 8, &any_mm);
    CSE_CHECK("verify: header hook match -> VERIFIED (still candidate_unbaked)",
              n == 1 && !any_mm && res[0].verdict ==
                  CHECKPOINT_RUNG_VERIFIED && res[0].candidate_unbaked);

    g_rung_hook_hash[0] ^= 0xff; /* header chain disagrees */
    any_mm = false;
    n = checkpoint_ladder_verify(&a, 1, &hooks, res, 8, &any_mm);
    CSE_CHECK("verify: header hook mismatch -> MISMATCH",
              n == 1 && any_mm && res[0].verdict == CHECKPOINT_RUNG_MISMATCH);

    struct checkpoint_ladder_hooks rhooks = {
        .ctx = NULL,
        .block_hash_at = NULL,
        .rederive_at = rung_hook_rederive_at,
    };
    g_rung_hook_rederive = a; /* node re-derives identical roots */
    g_rung_hook_rederive_return = true;
    any_mm = false;
    n = checkpoint_ladder_verify(&a, 1, &rhooks, res, 8, &any_mm);
    CSE_CHECK("verify: rederive hook match -> VERIFIED",
              n == 1 && !any_mm && res[0].verdict == CHECKPOINT_RUNG_VERIFIED);

    g_rung_hook_rederive.anchor_digest[0] ^= 0xff; /* re-derive differs */
    checkpoint_rung_finalize(&g_rung_hook_rederive);
    any_mm = false;
    n = checkpoint_ladder_verify(&a, 1, &rhooks, res, 8, &any_mm);
    CSE_CHECK("verify: rederive hook mismatch -> MISMATCH",
              n == 1 && any_mm && res[0].verdict == CHECKPOINT_RUNG_MISMATCH);
    g_rung_hook_hash_return = false;
    g_rung_hook_rederive_return = false;

    /* (8) end-to-end load: candidate artifacts on disk. */
    char rung_dir[] = "/tmp/zcl-rungdir-XXXXXX";
    char *rd = mkdtemp(rung_dir);
    CSE_CHECK("ladder: rung dir created", rd != NULL);
    if (rd) {
        CSE_CHECK("ladder: write valid candidate", cse_write_rung_file(rd, &a));
        struct checkpoint_rung loaded[8];
        size_t lc = checkpoint_ladder_load_candidates(rd, loaded, 8);
        CSE_CHECK("ladder: load one valid candidate",
                  lc == 1 && loaded[0].height == 100 &&
                      checkpoint_rung_self_consistent(&loaded[0]));
        /* now drop a divergent keystone-height candidate and confirm the
         * whole-ladder verify flags MISMATCH. */
        CSE_CHECK("ladder: write divergent keystone candidate",
                  cse_write_rung_file(rd, &evil));
        lc = checkpoint_ladder_load_candidates(rd, loaded, 8);
        any_mm = false;
        n = checkpoint_ladder_verify(loaded, lc, NULL, res, 8, &any_mm);
        CSE_CHECK("ladder: divergent candidate trips MISMATCH", any_mm);
        char pa[1100], pb[1100];
        snprintf(pa, sizeof(pa), "%s/rung-%d.rung", rd, a.height);
        snprintf(pb, sizeof(pb), "%s/rung-%d.rung", rd, evil.height);
        (void)unlink(pa);
        (void)unlink(pb);
        (void)rmdir(rd);
    }

    *failures_ptr = failures;
}

int test_consensus_state_snapshot_export(void)
{
    int failures = 0;
    char dir_template[] = "/tmp/zcl-cse-XXXXXX";
    char *dir = mkdtemp(dir_template);
    CSE_CHECK("fixture directory", dir != NULL);
    if (!dir)
        return failures;
    /* The export provenance gate (consensus_export_prove_source) now routes its
     * proven/refold check through the central trust table via
     * SYNC_CAP_EXPORT_BUNDLE. Prove the routing is behavior-identical to the old
     * `proven_authority && refold_marker` predicate across all 8 combos before
     * exercising the full DB-driven export path below. */
    {
        bool equiv = true;
        for (int c = 0; c < 8; c++) {
            bool proven = (c >> 2) & 1;
            bool refold = (c >> 1) & 1;
            bool self_d = (c >> 0) & 1;
            bool table_ok = sync_trust_cap_allowed(
                sync_trust_derive(proven, refold, self_d),
                SYNC_CAP_EXPORT_BUNDLE);
            if (table_ok != (proven && refold))
                equiv = false;
        }
        CSE_CHECK("export gate table-routing == proven&&refold (8 combos)",
                  equiv);
    }
    CSE_CHECK("owned progress store opens", progress_store_open(dir));
    sqlite3 *db = progress_store_db();
    uint8_t hash[2][32] = {{0}};
    uint8_t nf[32] = {0};
    CSE_CHECK("complete source generation", db && cse_seed_source(db, hash, nf));
    /* The mint-finalize stamping helper (exercised inside cse_seed_source) yields
     * a source that passes the exact two predicates consensus_export_prove_source
     * gates on at :471-472 — proving the finalize path stamps what the exporter
     * demands, so a fresh full-validation producer's export no longer refuses. */
    CSE_CHECK("finalize helper stamped exporter-admissible markers",
              db && coins_kv_is_proven_authority(db, NULL) &&
                  coins_kv_contains_refold_marker(db));

    char export_dir[512];
    snprintf(export_dir, sizeof(export_dir), "%s/export", dir);
    CSE_CHECK("descriptor-bound output directory",
              mkdir(export_dir, 0700) == 0);
    int output_dir_fd = open(export_dir,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    CSE_CHECK("output directory descriptor", output_dir_fd >= 0);

    char output[512];
    char checkpoint_output[512];
    char legacy_v1_output[512];
    char legacy_backfill_output[512];
    char embedded_status_output[512];
    char embedded_receipt_schema_output[512];
    char utxo_profile_mismatch_output[512];
    char stale_proof_output[512];
    char stale_utxo_output[512];
    char profile_mismatch_output[512];
    char reverse_profile_mismatch_output[512];
    char missing_output[512];
    char malformed_output[512];
    char numeric_text_output[512];
    char real_anchor_output[512];
    char real_nullifier_output[512];
    snprintf(output, sizeof(output), "%s/complete.bundle.db", export_dir);
    snprintf(checkpoint_output, sizeof(checkpoint_output),
             "%s/checkpoint.bundle.db", export_dir);
    snprintf(legacy_v1_output, sizeof(legacy_v1_output),
             "%s/legacy-v1.bundle.db", export_dir);
    snprintf(legacy_backfill_output, sizeof(legacy_backfill_output),
             "%s/legacy-backfill.bundle.db", export_dir);
    snprintf(embedded_status_output, sizeof(embedded_status_output),
             "%s/embedded-status.bundle.db", export_dir);
    snprintf(embedded_receipt_schema_output,
             sizeof(embedded_receipt_schema_output),
             "%s/embedded-receipt-schema.bundle.db", export_dir);
    snprintf(utxo_profile_mismatch_output,
             sizeof(utxo_profile_mismatch_output),
             "%s/utxo-profile-mismatch.bundle.db", export_dir);
    snprintf(stale_proof_output, sizeof(stale_proof_output),
             "%s/stale-proof.bundle.db", export_dir);
    snprintf(stale_utxo_output, sizeof(stale_utxo_output),
             "%s/stale-utxo.bundle.db", export_dir);
    snprintf(profile_mismatch_output, sizeof(profile_mismatch_output),
             "%s/profile-mismatch.bundle.db", export_dir);
    snprintf(reverse_profile_mismatch_output,
             sizeof(reverse_profile_mismatch_output),
             "%s/reverse-profile-mismatch.bundle.db", export_dir);
    snprintf(missing_output, sizeof(missing_output), "%s/missing.bundle.db",
             export_dir);
    snprintf(malformed_output, sizeof(malformed_output),
             "%s/malformed.bundle.db", export_dir);
    snprintf(numeric_text_output, sizeof(numeric_text_output),
             "%s/numeric-text.bundle.db", export_dir);
    snprintf(real_anchor_output, sizeof(real_anchor_output),
             "%s/real-anchor.bundle.db", export_dir);
    snprintf(real_nullifier_output, sizeof(real_nullifier_output),
             "%s/real-nullifier.bundle.db", export_dir);
    struct sha3_utxo_checkpoint checkpoint;
    memset(&checkpoint, 0, sizeof(checkpoint));
    checkpoint.height = 1;
    memcpy(checkpoint.block_hash, hash[1], 32);
    checkpoint.utxo_count = 1;
    checkpoint.total_supply = 5000;
    CSE_CHECK("fixture checkpoint commitment",
              coins_kv_commitment(db, checkpoint.sha3_hash) == 0);
    checkpoints_set_sha3_override_for_test(&checkpoint);
    reducer_frontier_test_set_compiled_anchor(0);
    struct consensus_state_snapshot_export_request request = {
        .output_dir_fd = output_dir_fd,
        .output_name = "complete.bundle.db",
        .expected_height = 1,
    };
    memcpy(request.expected_block_hash, hash[1], 32);
    struct consensus_state_export_result result;
    char export_capture[16384];
    bool exported;
    bool capture_ran = cse_capture_export_stderr(
        db, &request, &result, &exported, export_capture,
        sizeof(export_capture));
    struct stat st;
    CSE_CHECK("complete generation exports", exported &&
              result.status == CONSENSUS_EXPORT_EXPORTED &&
              result.history_complete && result.height == 1 &&
              result.source_clean &&
              result.validation_profile ==
                  CONSENSUS_STATE_VALIDATION_FULL &&
              result.utxo_count == 1 && result.anchor_count == 2 &&
              result.nullifier_count == 1);
    /* Observability: the named prove/write passes each emit a "[export] ..."
     * start marker (config/src/consensus_state_snapshot_export_proof.c's
     * consensus_export_progress_emit() and the copy_coins/copy_anchors/
     * copy_nullifiers passes in _export_write.c) — a human watching a
     * multi-minute -export-consensus-bundle run must never see silence
     * between boot completion and the final verdict. This fixture is far too
     * small to cross the 500k-row progress-line threshold, so this asserts
     * the unconditional start/done pass markers, not the per-500k-row lines. */
    CSE_CHECK("export prove/write passes emit progress markers (never silent)",
              capture_ran &&
              strstr(export_capture,
                     "[export] consensus_export_prove_source start") != NULL &&
              strstr(export_capture, "[export] prove_header_chain start") !=
                  NULL &&
              strstr(export_capture, "[export] prove_header_chain done") !=
                  NULL &&
              strstr(export_capture,
                     "[export] prove_stage_rows(utxo_apply) start") != NULL &&
              strstr(export_capture,
                     "[export] prove_stage_rows(utxo_apply) done") != NULL &&
              strstr(export_capture, "[export] copy_coins start") != NULL &&
              strstr(export_capture, "[export] copy_coins done") != NULL &&
              strstr(export_capture, "[export] copy_anchors start") != NULL &&
              strstr(export_capture, "[export] copy_nullifiers start") !=
                  NULL);
    CSE_CHECK("final artifact is immutable", lstat(output, &st) == 0 &&
              S_ISREG(st.st_mode) &&
              (st.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) == 0);

    struct consensus_state_snapshot_install_request install_request = {
        .bundle_path = output,
        .expected_height = 1,
        .failpoint = CONSENSUS_INSTALL_FAIL_NONE,
    };
    memcpy(install_request.expected_block_hash, hash[1], 32);
    struct consensus_state_install_result install_result;
    CSE_CHECK("production validator reopens artifact",
              !consensus_state_snapshot_install(db, &install_request,
                                                &install_result) &&
              install_result.status == CONSENSUS_INSTALL_VERIFIED_CONTAINED &&
              install_result.history_complete && install_result.source_clean &&
              install_result.validation_profile ==
                  CONSENSUS_STATE_VALIDATION_FULL);

    /* ── lane A1: the -mint-anchor finalize wiring. boot_mint_anchor_export_bundle
     * is exactly what boot_mint_anchor_run calls after the producer receipt is
     * finalized — prove it emits the datadir bundle, that the bundle passes the
     * production validator, and that a re-run of the SAME binary is idempotent
     * (an already-present bundle is treated as done, not re-exported/failed).
     * The complete source generation + checkpoint/compiled-anchor overrides are
     * already installed above, so this exercises the real export path. */
    char wired_bundle[600];
    snprintf(wired_bundle, sizeof(wired_bundle),
             "%s/consensus-state-bundle-1.sqlite", dir);
    (void)unlink(wired_bundle);
    CSE_CHECK("mint finalize wiring exports the datadir bundle",
              boot_mint_anchor_export_bundle(db, dir, 1, hash[1]) &&
              access(wired_bundle, F_OK) == 0);
    struct consensus_state_snapshot_install_request wired_install = {
        .bundle_path = wired_bundle,
        .expected_height = 1,
        .failpoint = CONSENSUS_INSTALL_FAIL_NONE,
    };
    memcpy(wired_install.expected_block_hash, hash[1], 32);
    struct consensus_state_install_result wired_result;
    CSE_CHECK("wired bundle passes production validation "
              "(consensus_state_bundle_validate via install)",
              !consensus_state_snapshot_install(db, &wired_install,
                                                &wired_result) &&
              wired_result.status == CONSENSUS_INSTALL_VERIFIED_CONTAINED &&
              wired_result.history_complete);
    CSE_CHECK("mint finalize wiring is idempotent on re-run (present bundle)",
              boot_mint_anchor_export_bundle(db, dir, 1, hash[1]) &&
              access(wired_bundle, F_OK) == 0);
    (void)unlink(wired_bundle);

    CSE_CHECK("seed self-consistent legacy v1 inspection receipt",
              cse_seed_receipt_version(
                  db, hash, CONSENSUS_STATE_VALIDATION_FULL, false,
                  CONSENSUS_STATE_SOURCE_RECEIPT_V1, NULL));
    request.output_name = "legacy-v1.bundle.db";
    struct consensus_state_export_result legacy_v1_result;
    CSE_CHECK("legacy v1 receipt is inspection-only and publishes nothing",
              !consensus_state_snapshot_export(db, &request,
                                               &legacy_v1_result) &&
              legacy_v1_result.status == CONSENSUS_EXPORT_MISSING_PROOF &&
              access(legacy_v1_output, F_OK) != 0);
    CSE_CHECK("restore authoritative v2 source receipt",
              cse_seed_receipt(db, hash,
                  CONSENSUS_STATE_VALIDATION_FULL, false));

    struct consensus_state_export_result typed_result;
    CSE_CHECK("numeric-prefix TEXT coin fixture writes",
              cse_exec(db,
                  "UPDATE coins SET value=CAST('5000x' AS TEXT)"));
    request.output_name = "numeric-text.bundle.db";
    CSE_CHECK("numeric-prefix TEXT coin cannot enter exported state",
              !consensus_state_snapshot_export(db, &request, &typed_result) &&
              typed_result.status == CONSENSUS_EXPORT_OUTPUT_ERROR &&
              access(numeric_text_output, F_OK) != 0);
    CSE_CHECK("restore exact INTEGER coin value",
              cse_exec(db, "UPDATE coins SET value=5000"));

    CSE_CHECK("REAL anchor-height fixture writes",
              cse_exec(db, "UPDATE sprout_anchors SET height=1.25"));
    request.output_name = "real-anchor.bundle.db";
    CSE_CHECK("REAL anchor height cannot enter exported state",
              !consensus_state_snapshot_export(db, &request, &typed_result) &&
              typed_result.status == CONSENSUS_EXPORT_OUTPUT_ERROR &&
              access(real_anchor_output, F_OK) != 0);
    CSE_CHECK("restore exact INTEGER anchor height",
              cse_exec(db, "UPDATE sprout_anchors SET height=1"));

    CSE_CHECK("REAL nullifier-height fixture writes",
              cse_exec(db, "UPDATE nullifiers SET height=1.25"));
    request.output_name = "real-nullifier.bundle.db";
    CSE_CHECK("REAL nullifier height cannot enter exported state",
              !consensus_state_snapshot_export(db, &request, &typed_result) &&
              typed_result.status == CONSENSUS_EXPORT_OUTPUT_ERROR &&
              access(real_nullifier_output, F_OK) != 0);
    CSE_CHECK("restore exact INTEGER nullifier height",
              cse_exec(db, "UPDATE nullifiers SET height=1"));
    request.output_name = "complete.bundle.db";

    CSE_CHECK("simulate legacy crypto rows without prepared epoch",
              cse_exec(db,
                  "UPDATE script_validate_log SET source_epoch_digest=NULL;"
                  "UPDATE proof_validate_log SET source_epoch_digest=NULL") &&
              cse_seed_receipt(db, hash,
                  CONSENSUS_STATE_VALIDATION_FULL, false));
    request.output_name = "legacy-backfill.bundle.db";
    struct consensus_state_export_result profile_result;
    CSE_CHECK("backfilled receipt cannot authorize legacy crypto rows",
              !consensus_state_snapshot_export(db, &request,
                                               &profile_result) &&
              profile_result.status == CONSENSUS_EXPORT_MISSING_PROOF &&
              access(legacy_backfill_output, F_OK) != 0);
    CSE_CHECK("restore prepared epoch row binding",
              cse_exec(db,
                  "UPDATE script_validate_log SET source_epoch_digest="
                  "(SELECT value FROM progress_meta WHERE key='"
                  CONSENSUS_STATE_SOURCE_EPOCH_META_KEY "');"
                  "UPDATE proof_validate_log SET source_epoch_digest="
                  "(SELECT value FROM progress_meta WHERE key='"
                  CONSENSUS_STATE_SOURCE_EPOCH_META_KEY "')"));

    CSE_CHECK("inject embedded-NUL status suffix",
              cse_exec(db,
                  "UPDATE script_validate_log SET status="
                  "CAST(X'7665726966696564006a756e6b' AS TEXT)"));
    request.output_name = "embedded-status.bundle.db";
    CSE_CHECK("noncanonical status bytes cannot prefix-match",
              !consensus_state_snapshot_export(db, &request,
                                               &profile_result) &&
              profile_result.status == CONSENSUS_EXPORT_MISSING_PROOF &&
              access(embedded_status_output, F_OK) != 0);
    CSE_CHECK("restore canonical full-validation status",
              cse_exec(db,
                  "UPDATE script_validate_log SET status='verified'"));

    CSE_CHECK("inject embedded-NUL receipt schema suffix",
              cse_exec(db,
                  "UPDATE consensus_state_source_receipt SET schema="
                  "schema||char(0)||'junk'"));
    request.output_name = "embedded-receipt-schema.bundle.db";
    CSE_CHECK("receipt schema requires exact bytes",
              !consensus_state_snapshot_export(db, &request,
                                               &profile_result) &&
              profile_result.status == CONSENSUS_EXPORT_MISSING_PROOF &&
              access(embedded_receipt_schema_output, F_OK) != 0);
    CSE_CHECK("restore canonical receipt schema",
              cse_exec(db,
                  "UPDATE consensus_state_source_receipt SET schema='"
                  CONSENSUS_STATE_SOURCE_RECEIPT_SCHEMA_V2 "'"));

    CSE_CHECK("relabel only UTXO evidence as checkpoint-only",
              cse_exec(db,
                  "UPDATE utxo_apply_log SET status='checkpoint_fold'"));
    request.output_name = "utxo-profile-mismatch.bundle.db";
    CSE_CHECK("UTXO profile is bound and cannot be relabeled",
              !consensus_state_snapshot_export(db, &request,
                                               &profile_result) &&
              profile_result.status == CONSENSUS_EXPORT_MISSING_PROOF &&
              access(utxo_profile_mismatch_output, F_OK) != 0);
    CSE_CHECK("restore canonical UTXO evidence",
              cse_exec(db,
                  "UPDATE utxo_apply_log SET status='verified'"));

    CSE_CHECK("relabel crypto rows as checkpoint-only",
              cse_exec(db,
                  "UPDATE script_validate_log SET status='checkpoint_fold';"
                  "UPDATE proof_validate_log SET status='checkpoint_fold';"
                  "UPDATE utxo_apply_log SET status='checkpoint_fold'"));
    request.output_name = "profile-mismatch.bundle.db";
    CSE_CHECK("full receipt cannot export checkpoint-fold rows",
              !consensus_state_snapshot_export(db, &request,
                                               &profile_result) &&
              profile_result.status == CONSENSUS_EXPORT_MISSING_PROOF &&
              access(profile_mismatch_output, F_OK) != 0);
    CSE_CHECK("seed checkpoint-fold receipt",
              cse_seed_receipt(db, hash,
                  CONSENSUS_STATE_VALIDATION_CHECKPOINT_FOLD, false));
    request.output_name = "checkpoint.bundle.db";
    struct consensus_state_export_result checkpoint_result;
    CSE_CHECK("checkpoint fold is never canonically publishable",
              !consensus_state_snapshot_export(db, &request,
                                               &checkpoint_result) &&
              checkpoint_result.status == CONSENSUS_EXPORT_MISSING_PROOF &&
              strstr(checkpoint_result.reason, "non-serving") != NULL &&
              access(checkpoint_output, F_OK) != 0);
    CSE_CHECK("restore full-validation row status",
              cse_exec(db,
                  "UPDATE script_validate_log SET status='verified';"
                  "UPDATE proof_validate_log SET status='verified';"
                  "UPDATE utxo_apply_log SET status='verified'"));
    request.output_name = "reverse-profile-mismatch.bundle.db";
    CSE_CHECK("checkpoint receipt cannot export full-validation rows",
              !consensus_state_snapshot_export(db, &request,
                                               &profile_result) &&
              profile_result.status == CONSENSUS_EXPORT_MISSING_PROOF &&
              access(reverse_profile_mismatch_output, F_OK) != 0);
    CSE_CHECK("restore full-validation receipt",
              cse_seed_receipt(db, hash,
                  CONSENSUS_STATE_VALIDATION_FULL, false));
    request.output_name = "complete.bundle.db";

    struct consensus_state_export_result repeat_result;
    CSE_CHECK("existing final is never replaced",
              !consensus_state_snapshot_export(db, &request, &repeat_result) &&
              repeat_result.status == CONSENSUS_EXPORT_REFUSED);

    struct consensus_state_export_result bad_target_result;
    request.output_dir_fd = -1;
    request.output_name = "bad-fd.bundle.db";
    CSE_CHECK("negative output directory descriptor refuses",
              !consensus_state_snapshot_export(db, &request,
                                               &bad_target_result) &&
              bad_target_result.status == CONSENSUS_EXPORT_REFUSED);
    int nondir_fd = open(output, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    request.output_dir_fd = nondir_fd;
    CSE_CHECK("non-directory output descriptor refuses",
              nondir_fd >= 0 &&
              !consensus_state_snapshot_export(db, &request,
                                               &bad_target_result) &&
              bad_target_result.status == CONSENSUS_EXPORT_REFUSED);
    if (nondir_fd >= 0)
        close(nondir_fd);
    int closed_fd = dup(output_dir_fd);
    if (closed_fd >= 0)
        close(closed_fd);
    request.output_dir_fd = closed_fd;
    CSE_CHECK("closed output descriptor refuses",
              closed_fd >= 0 &&
              !consensus_state_snapshot_export(db, &request,
                                               &bad_target_result) &&
              bad_target_result.status == CONSENSUS_EXPORT_REFUSED);

    request.output_dir_fd = output_dir_fd;
    struct stat link_st;
    request.output_name = "height-overflow.bundle.db";
    request.expected_height = INT32_MAX;
    CSE_CHECK("height whose next cursor overflows int32 refuses",
              !consensus_state_snapshot_export(db, &request,
                                               &bad_target_result) &&
              bad_target_result.status == CONSENSUS_EXPORT_REFUSED &&
              fstatat(output_dir_fd, request.output_name, &link_st,
                      AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT);
    request.expected_height = 1;
    static const char *const bad_names[] = {
        ".", "..", "sub/file", "bad?uri", "progress.kv",
        "Progress.KV.candidate",
    };
    bool bad_names_refused = true;
    for (size_t i = 0; i < sizeof(bad_names) / sizeof(bad_names[0]); i++) {
        request.output_name = bad_names[i];
        if (consensus_state_snapshot_export(db, &request,
                                            &bad_target_result) ||
            bad_target_result.status != CONSENSUS_EXPORT_REFUSED)
            bad_names_refused = false;
    }
    char oversized_name[320];
    memset(oversized_name, 'x', sizeof(oversized_name) - 1);
    oversized_name[sizeof(oversized_name) - 1] = '\0';
    request.output_name = oversized_name;
    if (consensus_state_snapshot_export(db, &request, &bad_target_result) ||
        bad_target_result.status != CONSENSUS_EXPORT_REFUSED)
        bad_names_refused = false;
    CSE_CHECK("active-store/multi-component/dot/URI/oversized names refuse",
              bad_names_refused);

    char symlink_output[512];
    snprintf(symlink_output, sizeof(symlink_output), "%s/link.bundle.db",
             export_dir);
    CSE_CHECK("existing output symlink fixture",
              symlink("complete.bundle.db", symlink_output) == 0);
    request.output_name = "link.bundle.db";
    CSE_CHECK("existing output symlink refuses without replacement",
              !consensus_state_snapshot_export(db, &request,
                                               &bad_target_result) &&
              bad_target_result.status == CONSENSUS_EXPORT_REFUSED &&
              lstat(symlink_output, &link_st) == 0 && S_ISLNK(link_st.st_mode));
    (void)unlink(symlink_output);

    struct cse_final_race_fixture final_race;
    memset(&final_race, 0, sizeof(final_race));
    snprintf(final_race.final, sizeof(final_race.final),
             "%s/final-race.bundle.db", export_dir);
    request.output_name = "final-race.bundle.db";
    consensus_state_snapshot_export_test_set_after_staging_create_hook(
        cse_final_race_after_create, &final_race);
    struct consensus_state_export_result final_race_result;
    CSE_CHECK("late final-name creation is refused without deleting attacker",
              !consensus_state_snapshot_export(db, &request,
                                               &final_race_result) &&
              final_race_result.status == CONSENSUS_EXPORT_OUTPUT_ERROR &&
              final_race.ran && final_race.ok &&
              access(final_race.final, F_OK) == 0);
    (void)unlink(final_race.final);

    struct cse_staging_link_fixture staging_link;
    memset(&staging_link, 0, sizeof(staging_link));
    staging_link.dirfd = output_dir_fd;
    snprintf(staging_link.alias, sizeof(staging_link.alias),
             "captured.alias");
    request.output_name = "staging-link.bundle.db";
    consensus_state_snapshot_export_test_set_after_staging_create_hook(
        cse_staging_link_after_create, &staging_link);
    struct consensus_state_export_result staging_link_result;
    CSE_CHECK("staging hardlink is refused without deleting either name",
              !consensus_state_snapshot_export(db, &request,
                                               &staging_link_result) &&
              staging_link_result.status == CONSENSUS_EXPORT_OUTPUT_ERROR &&
              staging_link.ran && staging_link.ok &&
              fstatat(output_dir_fd, staging_link.alias, &link_st,
                      AT_SYMLINK_NOFOLLOW) == 0 && link_st.st_nlink == 1);
    (void)unlinkat(output_dir_fd, staging_link.alias, 0);

    struct cse_retained_writer_fixture retained_writer = {
        .dirfd = output_dir_fd,
        .writer_fd = -1,
    };
    request.output_name = "retained-writer.bundle.db";
    consensus_state_snapshot_export_test_set_after_staging_create_hook(
        cse_retain_staging_writer, &retained_writer);
    struct consensus_state_export_result retained_writer_result;
    CSE_CHECK("retained writable staging descriptor refuses publication",
              !consensus_state_snapshot_export(db, &request,
                                               &retained_writer_result) &&
              retained_writer_result.status == CONSENSUS_EXPORT_OUTPUT_ERROR &&
              retained_writer.ran && retained_writer.writer_fd >= 0 &&
              fstatat(output_dir_fd, request.output_name, &link_st,
                      AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT);
    if (retained_writer.writer_fd >= 0)
        (void)close(retained_writer.writer_fd);

    struct cse_parent_swap_fixture parent_swap;
    memset(&parent_swap, 0, sizeof(parent_swap));
    snprintf(parent_swap.original, sizeof(parent_swap.original), "%s/bound-parent",
             dir);
    snprintf(parent_swap.moved, sizeof(parent_swap.moved), "%s/bound-parent-moved",
             dir);
    snprintf(parent_swap.attacker, sizeof(parent_swap.attacker), "%s/attacker",
             dir);
    CSE_CHECK("parent rename fixture directory",
              mkdir(parent_swap.original, 0700) == 0);
    int bound_fd = open(parent_swap.original,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    request.output_dir_fd = bound_fd;
    request.output_name = "bound.bundle.db";
    consensus_state_snapshot_export_test_set_after_output_bind_hook(
        cse_parent_swap_after_bind, &parent_swap);
    struct consensus_state_export_result bound_result;
    bool bound_exported = bound_fd >= 0 &&
        consensus_state_snapshot_export(db, &request, &bound_result);
    char moved_output[768];
    char attacker_output[768];
    snprintf(moved_output, sizeof(moved_output), "%s/bound.bundle.db",
             parent_swap.moved);
    snprintf(attacker_output, sizeof(attacker_output), "%s/bound.bundle.db",
             parent_swap.attacker);
    struct stat by_fd;
    struct stat by_path;
    CSE_CHECK("renamed parent stays descriptor-bound",
              bound_exported && parent_swap.ran && parent_swap.ok &&
              fstatat(bound_fd, "bound.bundle.db", &by_fd,
                      AT_SYMLINK_NOFOLLOW) == 0 &&
              lstat(moved_output, &by_path) == 0 &&
              by_fd.st_dev == by_path.st_dev && by_fd.st_ino == by_path.st_ino &&
              access(attacker_output, F_OK) != 0);
    if (bound_fd >= 0)
        close(bound_fd);
    (void)unlink(moved_output);
    (void)unlink(parent_swap.original);
    (void)rmdir(parent_swap.attacker);
    (void)rmdir(parent_swap.moved);

    request.output_dir_fd = output_dir_fd;
    request.output_name = "complete.bundle.db";

    uint8_t stale_proof_hash[32];
    memcpy(stale_proof_hash, hash[1], sizeof(stale_proof_hash));
    stale_proof_hash[0] ^= 0xff;
    CSE_CHECK("corrupt proof receipt block hash",
              cse_insert_hash_row(db,
                  "UPDATE proof_validate_log SET block_hash=?2 WHERE height=?1",
                  1, stale_proof_hash));
    request.output_name = "stale-proof.bundle.db";
    struct consensus_state_export_result stale_proof_result;
    CSE_CHECK("stale proof hash fails named and publishes nothing",
              !consensus_state_snapshot_export(db, &request,
                                               &stale_proof_result) &&
              stale_proof_result.status == CONSENSUS_EXPORT_MISSING_PROOF &&
              access(stale_proof_output, F_OK) != 0);
    CSE_CHECK("restore proof receipt block hash",
              cse_insert_hash_row(db,
                  "UPDATE proof_validate_log SET block_hash=?2 WHERE height=?1",
                  1, hash[1]));

    uint8_t stale_utxo_hash[32];
    memcpy(stale_utxo_hash, hash[1], sizeof(stale_utxo_hash));
    stale_utxo_hash[31] ^= 0xff;
    CSE_CHECK("corrupt UTXO delta branch hash",
              cse_insert_hash_row(db,
                  "UPDATE utxo_apply_delta SET branch_hash=?2 WHERE height=?1",
                  1, stale_utxo_hash));
    request.output_name = "stale-utxo.bundle.db";
    struct consensus_state_export_result stale_utxo_result;
    CSE_CHECK("stale UTXO branch fails named and publishes nothing",
              !consensus_state_snapshot_export(db, &request,
                                               &stale_utxo_result) &&
              stale_utxo_result.status == CONSENSUS_EXPORT_MISSING_PROOF &&
              access(stale_utxo_output, F_OK) != 0);
    CSE_CHECK("restore UTXO delta branch hash",
              cse_insert_hash_row(db,
                  "UPDATE utxo_apply_delta SET branch_hash=?2 WHERE height=?1",
                  1, hash[1]));

    /* ── FOLD-TO-ANCHOR (H+1) PRODUCER SHAPE. A complete full-validation mint
     * producer runs tip_finalize in the STEADY-STATE finalized convention: the
     * cursor sits at anchor+1 and each finalized ok=1 row at h carries the
     * LOOKAHEAD hash(h+1) — there is no anchor seed row at the tip. The old
     * durable-tip check resolved via the cursor and floated one above the served
     * tip (H*), false-rejecting the real producer with
     * "durable served tip does not own expected height/hash". Rebuild the
     * canonical fixture into that exact shape (cursor=2==anchor+1; top finalized
     * row at anchor=1 carrying the successor lookahead; hstar stays 1==anchor)
     * and prove the served-tip binding now admits it without weakening. */
    uint8_t lookahead2[32];
    uint8_t witness_disagree[32];
    for (size_t i = 0; i < 32; i++) {
        lookahead2[i] = (uint8_t)(0x11u + i);          /* hash(anchor+1) */
        witness_disagree[i] = hash[1][i];
    }
    witness_disagree[5] ^= 0xff;
    char mint_output[600];
    char mint_wrong_output[600];
    char mint_disagree_output[600];
    char mint_below_output[600];
    snprintf(mint_output, sizeof(mint_output), "%s/mint-shape.bundle.db",
             export_dir);
    snprintf(mint_wrong_output, sizeof(mint_wrong_output),
             "%s/mint-wrong-hash.bundle.db", export_dir);
    snprintf(mint_disagree_output, sizeof(mint_disagree_output),
             "%s/mint-anchor-disagree.bundle.db", export_dir);
    snprintf(mint_below_output, sizeof(mint_below_output),
             "%s/mint-below-anchor.bundle.db", export_dir);

    CSE_CHECK("rebuild fixture into fold-to-anchor (H+1) producer shape",
              cse_insert_hash_row(db,
                  "UPDATE tip_finalize_log SET status='finalized',tip_hash=?2 "
                  "WHERE height=?1", 1, lookahead2) &&
              cse_exec(db,
                  "UPDATE stage_cursor SET cursor=2 WHERE name='tip_finalize'"));

    int mint_durable_h = -1;
    uint8_t mint_durable_hash[32];
    CSE_CHECK("cursor resolver floats one above the served tip (bug repro)",
              tip_finalize_stage_resolve_durable_tip(db, &mint_durable_h,
                                                     mint_durable_hash) &&
              mint_durable_h == 2 &&
              memcmp(mint_durable_hash, lookahead2, 32) == 0);
    uint8_t mint_served_hash[32];
    CSE_CHECK("convention-aware witness binds the anchor's own hash at H*",
              tip_finalize_stage_block_hash_at(db, 1, mint_served_hash) &&
              memcmp(mint_served_hash, hash[1], 32) == 0);

    request.output_name = "mint-shape.bundle.db";
    struct consensus_state_export_result mint_result;
    CSE_CHECK("fold-to-anchor producer exports (served-tip bound, not floated)",
              consensus_state_snapshot_export(db, &request, &mint_result) &&
              mint_result.status == CONSENSUS_EXPORT_EXPORTED &&
              mint_result.height == 1 &&
              mint_result.validation_profile ==
                  CONSENSUS_STATE_VALIDATION_FULL);
    (void)unlink(mint_output);

    /* NEGATIVE (a): a tampered expected block hash still refuses (the complete
     * genesis→height header proof binds it before the served-tip check). */
    uint8_t saved_expected[32];
    memcpy(saved_expected, request.expected_block_hash, 32);
    request.expected_block_hash[0] ^= 0xff;
    request.output_name = "mint-wrong-hash.bundle.db";
    struct consensus_state_export_result mint_wrong_result;
    CSE_CHECK("tampered expected block hash refuses and publishes nothing",
              !consensus_state_snapshot_export(db, &request,
                                               &mint_wrong_result) &&
              mint_wrong_result.status == CONSENSUS_EXPORT_MISSING_PROOF &&
              access(mint_wrong_output, F_OK) != 0);
    memcpy(request.expected_block_hash, saved_expected, 32);

    /* NEGATIVE (c): the served tip is at the claimed height but its own-hash
     * witness disagrees — the served-tip gate itself must refuse (header chain,
     * receipt, and H* are all still internally consistent). */
    CSE_CHECK("corrupt the anchor's own-hash witness at H*",
              cse_insert_hash_row(db,
                  "UPDATE tip_finalize_log SET tip_hash=?2 WHERE height=?1",
                  0, witness_disagree));
    request.output_name = "mint-anchor-disagree.bundle.db";
    struct consensus_state_export_result mint_disagree_result;
    CSE_CHECK("served tip whose own hash disagrees refuses at the served-tip gate",
              !consensus_state_snapshot_export(db, &request,
                                               &mint_disagree_result) &&
              mint_disagree_result.status == CONSENSUS_EXPORT_MISSING_PROOF &&
              strstr(mint_disagree_result.reason,
                     "durable served tip does not own") != NULL &&
              access(mint_disagree_output, F_OK) != 0);
    CSE_CHECK("served-tip refusal names both the derived and expected hash",
              strstr(mint_disagree_result.reason, "derived=") != NULL &&
              strstr(mint_disagree_result.reason, "expected=") != NULL);
    CSE_CHECK("restore the anchor's own-hash witness",
              cse_insert_hash_row(db,
                  "UPDATE tip_finalize_log SET tip_hash=?2 WHERE height=?1",
                  0, hash[1]));

    /* NEGATIVE (b): the served tip is BELOW the claimed anchor (top finalized
     * row at anchor-1, hstar=anchor-1) — must refuse, never relax height==H* to
     * a >= that would admit a short source. */
    CSE_CHECK("drop the served tip below the claimed anchor",
              cse_exec(db,
                  "DELETE FROM tip_finalize_log WHERE height=1;"
                  "UPDATE stage_cursor SET cursor=1 WHERE name='tip_finalize'"));
    request.output_name = "mint-below-anchor.bundle.db";
    struct consensus_state_export_result mint_below_result;
    CSE_CHECK("served tip below the claimed anchor refuses and publishes nothing",
              !consensus_state_snapshot_export(db, &request,
                                               &mint_below_result) &&
              mint_below_result.status == CONSENSUS_EXPORT_MISSING_PROOF &&
              access(mint_below_output, F_OK) != 0);

    CSE_CHECK("restore canonical anchor-at-cursor tip_finalize shape",
              cse_exec(db, "DELETE FROM tip_finalize_log WHERE height IN (0,1)") &&
              cse_insert_tip(db, 0, "finalized", hash[1]) &&
              cse_insert_tip(db, 1, "anchor", hash[1]) &&
              cse_exec(db,
                  "UPDATE stage_cursor SET cursor=1 WHERE name='tip_finalize'"));
    request.output_name = "complete.bundle.db";

    /* ── CHECKPOINT-CONTENT EXPORT. A finished genesis->checkpoint datadir whose
     * fold binary can no longer be rebuilt: its receipt binds a FOREIGN running
     * binary, so the default export (fold-binary bind) refuses. The
     * checkpoint-content path admits it by a stronger cryptographic content
     * proof instead — coins reproduce the compiled SHA3 UTXO checkpoint AND the
     * Sapling tip frontier Pedersen-roots to the header's committed final root —
     * and emits a byte-identical-shape bundle that validates like a fold bundle.
     * The compiled-checkpoint override + reducer anchor installed above make the
     * fixture reproduce the checkpoint at h=1 by construction. */
    request.output_dir_fd = output_dir_fd;
    request.expected_height = 1;
    memcpy(request.expected_block_hash, hash[1], 32);
    struct incremental_merkle_tree cse_sapling_tip;
    struct uint256 cse_sapling_root;
    int64_t cse_sapling_h = -1;
    CSE_CHECK("read the header-bound Sapling tip frontier root",
              anchor_kv_latest_tree(db, ANCHOR_POOL_SAPLING, &cse_sapling_tip,
                                    &cse_sapling_root, &cse_sapling_h) ==
                  ANCHOR_KV_FOUND);
    uint8_t foreign_binary[32];
    for (size_t i = 0; i < 32; i++)
        foreign_binary[i] = (uint8_t)(0x5au + i);
    CSE_CHECK("seed a receipt bound to a foreign (unrebuildable) fold binary",
              cse_seed_receipt_version(db, hash,
                  CONSENSUS_STATE_VALIDATION_FULL, false,
                  CONSENSUS_STATE_SOURCE_RECEIPT_V2, foreign_binary));

    char foreign_output[600];
    char crypto_output[600];
    char bad_saroot_output[600];
    char bad_sha3_output[600];
    char bad_height_output[600];
    snprintf(foreign_output, sizeof(foreign_output),
             "%s/foreign-binary-fold.bundle.db", export_dir);
    snprintf(crypto_output, sizeof(crypto_output),
             "%s/crypto-checkpoint.bundle.db", export_dir);
    snprintf(bad_saroot_output, sizeof(bad_saroot_output),
             "%s/crypto-bad-saroot.bundle.db", export_dir);
    snprintf(bad_sha3_output, sizeof(bad_sha3_output),
             "%s/crypto-bad-sha3.bundle.db", export_dir);
    snprintf(bad_height_output, sizeof(bad_height_output),
             "%s/crypto-bad-height.bundle.db", export_dir);

    /* (d) NEGATIVE — the DEFAULT (non-checkpoint) path still binds the fold
     * binary: a foreign-binary receipt refuses, behavior UNCHANGED. */
    request.checkpoint_content_export = false;
    request.output_name = "foreign-binary-fold.bundle.db";
    struct consensus_state_export_result foreign_result;
    CSE_CHECK("default export still binds the fold binary (foreign refuses)",
              !consensus_state_snapshot_export(db, &request, &foreign_result) &&
              foreign_result.status == CONSENSUS_EXPORT_MISSING_PROOF &&
              access(foreign_output, F_OK) != 0);

    /* (a) checkpoint-content export admits the same foreign-binary datadir. */
    request.checkpoint_content_export = true;
    memcpy(request.checkpoint_sapling_root, cse_sapling_root.data, 32);
    request.output_name = "crypto-checkpoint.bundle.db";
    struct consensus_state_export_result crypto_result;
    CSE_CHECK("checkpoint-content export admits the foreign-binary datadir",
              consensus_state_snapshot_export(db, &request, &crypto_result) &&
              crypto_result.status == CONSENSUS_EXPORT_EXPORTED &&
              crypto_result.height == 1 &&
              crypto_result.validation_profile ==
                  CONSENSUS_STATE_VALIDATION_FULL);

    /* (e) the checkpoint-content bundle validates byte-identically to a fold
     * bundle through the production validator. */
    struct consensus_state_snapshot_install_request crypto_install = {
        .bundle_path = crypto_output,
        .expected_height = 1,
        .failpoint = CONSENSUS_INSTALL_FAIL_NONE,
    };
    memcpy(crypto_install.expected_block_hash, hash[1], 32);
    struct consensus_state_install_result crypto_install_result;
    CSE_CHECK("checkpoint-content bundle passes the production validator "
              "like a fold bundle",
              !consensus_state_snapshot_install(db, &crypto_install,
                                                &crypto_install_result) &&
              crypto_install_result.status ==
                  CONSENSUS_INSTALL_VERIFIED_CONTAINED &&
              crypto_install_result.history_complete &&
              crypto_install_result.validation_profile ==
                  CONSENSUS_STATE_VALIDATION_FULL);
    (void)unlink(crypto_output);

    /* (f) NEGATIVE — a Sapling frontier not bound to the header root refuses. */
    uint8_t wrong_saroot[32];
    memcpy(wrong_saroot, cse_sapling_root.data, 32);
    wrong_saroot[7] ^= 0xff;
    memcpy(request.checkpoint_sapling_root, wrong_saroot, 32);
    request.output_name = "crypto-bad-saroot.bundle.db";
    struct consensus_state_export_result bad_saroot_result;
    CSE_CHECK("checkpoint-content export refuses a header-inconsistent frontier",
              !consensus_state_snapshot_export(db, &request,
                                               &bad_saroot_result) &&
              bad_saroot_result.status == CONSENSUS_EXPORT_MISSING_PROOF &&
              strstr(bad_saroot_result.reason, "Sapling tip frontier") != NULL &&
              access(bad_saroot_output, F_OK) != 0);
    /* A refusal you cannot debug from its message is a defect: the derived
     * root, the expected (header-committed) root, and the sapling anchor
     * height it used must all be present, in hex, one line. */
    CSE_CHECK("Sapling-root refusal names the derived root, expected root, "
              "and anchor height",
              strstr(bad_saroot_result.reason, "derived=") != NULL &&
              strstr(bad_saroot_result.reason, "expected=") != NULL &&
              strstr(bad_saroot_result.reason, "sapling_anchor_height=") !=
                  NULL);
    memcpy(request.checkpoint_sapling_root, cse_sapling_root.data, 32);

    /* (b) NEGATIVE — coins that miss the compiled checkpoint SHA3 refuse. */
    struct sha3_utxo_checkpoint bad_sha3_cp = checkpoint;
    bad_sha3_cp.sha3_hash[0] ^= 0xff;
    checkpoints_set_sha3_override_for_test(&bad_sha3_cp);
    request.output_name = "crypto-bad-sha3.bundle.db";
    struct consensus_state_export_result bad_sha3_result;
    CSE_CHECK("checkpoint-content export refuses coins that miss the SHA3",
              !consensus_state_snapshot_export(db, &request, &bad_sha3_result) &&
              bad_sha3_result.status == CONSENSUS_EXPORT_MISSING_PROOF &&
              strstr(bad_sha3_result.reason, "reproduce the compiled") != NULL &&
              access(bad_sha3_output, F_OK) != 0);
    CSE_CHECK("coins-checkpoint refusal names both the derived and expected "
              "SHA3 + count",
              strstr(bad_sha3_result.reason, "derived=") != NULL &&
              strstr(bad_sha3_result.reason, "expected=") != NULL);
    checkpoints_set_sha3_override_for_test(&checkpoint);

    /* (c) NEGATIVE — an export height off the compiled checkpoint refuses. */
    struct sha3_utxo_checkpoint bad_height_cp = checkpoint;
    bad_height_cp.height = 2;
    checkpoints_set_sha3_override_for_test(&bad_height_cp);
    request.output_name = "crypto-bad-height.bundle.db";
    struct consensus_state_export_result bad_height_result;
    CSE_CHECK("checkpoint-content export refuses off the checkpoint height",
              !consensus_state_snapshot_export(db, &request,
                                               &bad_height_result) &&
              bad_height_result.status == CONSENSUS_EXPORT_MISSING_PROOF &&
              strstr(bad_height_result.reason,
                     "compiled checkpoint height") != NULL &&
              access(bad_height_output, F_OK) != 0);
    checkpoints_set_sha3_override_for_test(&checkpoint);

    request.checkpoint_content_export = false;
    CSE_CHECK("restore canonical running-binary-bound source receipt",
              cse_seed_receipt(db, hash,
                  CONSENSUS_STATE_VALIDATION_FULL, false));
    request.output_name = "complete.bundle.db";
    (void)unlink(foreign_output);
    (void)unlink(bad_saroot_output);
    (void)unlink(bad_sha3_output);
    (void)unlink(bad_height_output);

    CSE_CHECK("remove required source receipt",
              cse_exec(db, "DELETE FROM consensus_state_source_receipt"));
    request.output_name = "missing.bundle.db";
    struct consensus_state_export_result missing_result;
    CSE_CHECK("missing proof fails named and publishes nothing",
              !consensus_state_snapshot_export(db, &request, &missing_result) &&
              missing_result.status == CONSENSUS_EXPORT_MISSING_PROOF &&
              access(missing_output, F_OK) != 0);

    CSE_CHECK("seed malformed source receipt",
              cse_seed_receipt(db, hash,
                  CONSENSUS_STATE_VALIDATION_FULL, true));
    request.output_name = "malformed.bundle.db";
    struct consensus_state_export_result malformed_result;
    CSE_CHECK("malformed receipt fails named and publishes nothing",
              !consensus_state_snapshot_export(db, &request,
                                               &malformed_result) &&
              malformed_result.status == CONSENSUS_EXPORT_MISSING_PROOF &&
              access(malformed_output, F_OK) != 0);

    /* An admitted bundle is a durable genesis..H prefix, not authority to
     * pretend its deleted source rows are locally present. Retain that exact
     * prefix, remove the local genesis header, prove one new linked suffix
     * height under a fresh producer epoch, and require the emitted artifact to
     * disclose a validator-recomputable composition boundary. */
    sqlite3 *base_bundle = NULL;
    struct consensus_state_bundle_manifest base_manifest;
    struct consensus_state_install_result base_validation;
    memset(&base_manifest, 0, sizeof(base_manifest));
    memset(&base_validation, 0, sizeof(base_validation));
    bool prefix_installed =
        sqlite3_open_v2(output, &base_bundle, SQLITE_OPEN_READONLY, NULL) ==
            SQLITE_OK &&
        consensus_state_bundle_validate(base_bundle, &base_manifest,
                                        &base_validation);
    progress_store_tx_lock();
    if (prefix_installed)
        prefix_installed = cse_exec(db, "BEGIN IMMEDIATE") &&
            consensus_state_proof_prefix_install_in_tx(
                db, base_bundle, &base_manifest) &&
            cse_exec(db, "COMMIT");
    if (!prefix_installed)
        (void)cse_exec(db, "ROLLBACK");
    progress_store_tx_unlock();
    if (base_bundle)
        sqlite3_close(base_bundle);
    CSE_CHECK("composed: admitted base proof retained", prefix_installed);

    static const char composed_source_id[] =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    consensus_state_producer_receipt_test_set_identity(composed_source_id,
                                                       true);
    char producer_error[256] = {0};
    CSE_CHECK("composed: fresh local producer epoch begins",
              cse_exec(db, "DELETE FROM consensus_state_source_receipt") &&
              consensus_state_producer_receipt_begin(
                  db, CONSENSUS_STATE_VALIDATION_FULL, producer_error,
                  sizeof(producer_error)));

    uint8_t composed_hash[32];
    for (size_t i = 0; i < sizeof(composed_hash); i++)
        composed_hash[i] = (uint8_t)(0xd1u + i);
    bool suffix_seeded =
        cse_exec(db, "DELETE FROM header_admit_log WHERE height=0") &&
        cse_insert_header(db, 2, composed_hash, hash[1]) &&
        cse_insert_hash_row(
            db, "INSERT INTO validate_headers_log VALUES(?,?,1)", 2,
            composed_hash) &&
        cse_insert_hash_row(
            db, "INSERT INTO body_fetch_log VALUES(?,?,1)", 2,
            composed_hash) &&
        cse_exec(db, "INSERT INTO body_persist_log VALUES(2,1)") &&
        cse_insert_hash_row(
            db, "INSERT INTO script_validate_log("
                "height,block_hash,ok,status,source_epoch_digest) "
                "VALUES(?,?,1,'verified',(SELECT value FROM progress_meta "
                "WHERE key='" CONSENSUS_STATE_SOURCE_EPOCH_META_KEY "'))",
            2, composed_hash) &&
        cse_insert_hash_row(
            db, "INSERT INTO proof_validate_log("
                "height,block_hash,ok,status,source_epoch_digest) "
                "VALUES(?,?,1,'verified',(SELECT value FROM progress_meta "
                "WHERE key='" CONSENSUS_STATE_SOURCE_EPOCH_META_KEY "'))",
            2, composed_hash) &&
        cse_exec(db, "INSERT INTO utxo_apply_log VALUES(2,1,'verified')") &&
        cse_insert_hash_row(
            db, "INSERT INTO utxo_apply_delta(height,branch_hash,spent_blob,"
                "added_blob) VALUES(?,?,X'',X'')",
            2, composed_hash) &&
        cse_insert_hash_row(
            db, "UPDATE tip_finalize_log SET tip_hash=?2 WHERE height=?1",
            1, composed_hash) &&
        cse_insert_tip(db, 2, "anchor", composed_hash) &&
        cse_exec(db,
            "UPDATE stage_cursor SET cursor=3 WHERE name!='tip_finalize';"
            "UPDATE stage_cursor SET cursor=2 WHERE name='tip_finalize'");
    progress_store_tx_lock();
    bool applied_advanced = suffix_seeded && cse_exec(db, "BEGIN IMMEDIATE") &&
        coins_kv_set_applied_height_in_tx(db, 3) && cse_exec(db, "COMMIT");
    if (!applied_advanced)
        (void)cse_exec(db, "ROLLBACK");
    progress_store_tx_unlock();
    CSE_CHECK("composed: only the linked local suffix is materialized",
              suffix_seeded && applied_advanced);
    CSE_CHECK("composed: receipt finalizes over prefix plus suffix",
              consensus_state_producer_receipt_finalize(
                  db, 2, composed_hash, producer_error,
                  sizeof(producer_error)));

    char composed_output[512];
    snprintf(composed_output, sizeof(composed_output),
             "%s/composed.bundle.db", export_dir);
    request.output_name = "composed.bundle.db";
    request.expected_height = 2;
    memcpy(request.expected_block_hash, composed_hash, 32);
    struct consensus_state_export_result composed_result;
    CSE_CHECK("composed: prefix plus independently proven suffix exports",
              consensus_state_snapshot_export(db, &request,
                                              &composed_result) &&
              composed_result.status == CONSENSUS_EXPORT_EXPORTED &&
              composed_result.height == 2);
    struct consensus_state_snapshot_install_request composed_install = {
        .bundle_path = composed_output,
        .expected_height = 2,
        .failpoint = CONSENSUS_INSTALL_FAIL_NONE,
    };
    memcpy(composed_install.expected_block_hash, composed_hash, 32);
    struct consensus_state_install_result composed_install_result;
    CSE_CHECK("composed: production validator recomputes disclosed lineage",
              !consensus_state_snapshot_install(
                  db, &composed_install, &composed_install_result) &&
              composed_install_result.status ==
                  CONSENSUS_INSTALL_VERIFIED_CONTAINED);
    bool lineage_tampered = chmod(composed_output, 0600) == 0 &&
        sqlite3_open_v2(composed_output, &base_bundle,
                        SQLITE_OPEN_READWRITE, NULL) == SQLITE_OK &&
        cse_insert_hash_row(
            base_bundle,
            "UPDATE proof_parent_component SET suffix_digest=?2 "
            "WHERE ordinal=?1",
            3, composed_hash);
    if (base_bundle)
        sqlite3_close(base_bundle);
    base_bundle = NULL;
    lineage_tampered = lineage_tampered && chmod(composed_output, 0444) == 0;
    CSE_CHECK("composed: exact parent and suffix rows are independently mutable",
              lineage_tampered);
    struct consensus_state_install_result tampered_lineage;
    struct consensus_state_bundle_manifest tampered_manifest;
    memset(&tampered_lineage, 0, sizeof(tampered_lineage));
    memset(&tampered_manifest, 0, sizeof(tampered_manifest));
    bool tampered_open =
        sqlite3_open_v2(composed_output, &base_bundle, SQLITE_OPEN_READONLY,
                        NULL) == SQLITE_OK;
    bool tampered_valid = tampered_open && consensus_state_bundle_validate(
        base_bundle, &tampered_manifest, &tampered_lineage);
    if (base_bundle)
        sqlite3_close(base_bundle);
    base_bundle = NULL;
    CSE_CHECK("composed: changed suffix lineage is refused",
              tampered_open && !tampered_valid &&
              tampered_lineage.status == CONSENSUS_INSTALL_REFUSED &&
              strstr(tampered_lineage.reason, "proof") != NULL);
    consensus_state_producer_receipt_test_set_identity(NULL, false);
    (void)unlink(composed_output);

    reducer_frontier_test_set_compiled_anchor(-1);
    checkpoints_reset_sha3_override_for_test();
    progress_store_close();
    if (output_dir_fd >= 0)
        close(output_dir_fd);
    /* Lane F1: checkpoint ladder rung generator + verifier. */
    cse_run_rung_ladder_tests(&failures);

    (void)unlink(output);
    (void)unlink(checkpoint_output);
    (void)unlink(legacy_v1_output);
    (void)unlink(legacy_backfill_output);
    (void)unlink(embedded_status_output);
    (void)unlink(embedded_receipt_schema_output);
    (void)unlink(utxo_profile_mismatch_output);
    (void)unlink(stale_proof_output);
    (void)unlink(stale_utxo_output);
    (void)unlink(profile_mismatch_output);
    (void)unlink(reverse_profile_mismatch_output);
    (void)unlink(missing_output);
    (void)unlink(malformed_output);
    (void)unlink(numeric_text_output);
    (void)unlink(real_anchor_output);
    (void)unlink(real_nullifier_output);
    (void)rmdir(export_dir);
    (void)rmdir(dir);
    return failures;
}
