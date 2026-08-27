/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Producer-owned source receipt: a freshly-begun producer datadir earns a
 * receipt the contained full-history exporter admits end-to-end, and a
 * missing / tampered / unowned receipt is refused (fail closed). */

#define _GNU_SOURCE

#include "test/test_core.h"

#include "config/consensus_state_producer_receipt.h"
#include "config/consensus_state_snapshot_export.h"
#include "chain/checkpoints.h"
#include "sapling/incremental_merkle_tree.h"
#include "storage/anchor_kv.h"
#include "storage/coins_kv.h"
#include "storage/consensus_state_bundle_codec.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"

#include <sqlite3.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

void reducer_frontier_test_set_compiled_anchor(int32_t height);

/* A deterministic hermetic SHA-256 source identity so the test does not
 * depend on the build's baked worktree identity. */
#define PR_TEST_SOURCE_ID \
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define PR_TEST_LEGACY_COMMIT "0123456789abcdef0123456789abcdef01234567"

#define PR_CHECK(label, expr) do {                                        \
    printf("producer_receipt: %s... ", (label));                         \
    if (expr) printf("OK\n");                                            \
    else { printf("FAIL\n"); failures++; }                               \
} while (0)

static bool pr_exec(sqlite3 *db, const char *sql)
{
    char *error = NULL;
    bool ok = sqlite3_exec(db, sql, NULL, NULL, &error) == SQLITE_OK;
    if (error)
        sqlite3_free(error);
    return ok;
}

static bool pr_scalar_true(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    int rc = sqlite3_step(st); // raw-sql-ok:test-read-only-assertion
    bool ok = rc == SQLITE_ROW &&
              sqlite3_column_type(st, 0) == SQLITE_INTEGER &&
              sqlite3_column_int(st, 0) == 1 &&
              sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:test-read-only-assertion
    sqlite3_finalize(st);
    return ok;
}

static bool pr_read_session_claim(
    sqlite3 *db, struct consensus_state_source_receipt *claim,
    uint8_t source_epoch[32])
{
    sqlite3_stmt *st = NULL;
    memset(claim, 0, sizeof(*claim));
    memset(source_epoch, 0, 32);
    if (sqlite3_prepare_v2(db,
            "SELECT source_tree_root,toolchain_digest,build_inputs_digest,"
            "source_epoch_digest,source_clean,validation_profile,"
            "producer_commit FROM consensus_state_producer_session "
            "WHERE singleton=1", -1, &st, NULL) != SQLITE_OK)
        return false;
    int rc = sqlite3_step(st); // raw-sql-ok:test-read-only-assertion
    bool ok = rc == SQLITE_ROW;
    for (int column = 0; ok && column < 4; column++) {
        ok = sqlite3_column_type(st, column) == SQLITE_BLOB &&
             sqlite3_column_bytes(st, column) == 32;
    }
    if (ok) {
        memcpy(claim->source_tree_root, sqlite3_column_blob(st, 0), 32);
        memcpy(claim->toolchain_digest, sqlite3_column_blob(st, 1), 32);
        memcpy(claim->build_inputs_digest, sqlite3_column_blob(st, 2), 32);
        memcpy(source_epoch, sqlite3_column_blob(st, 3), 32);
        ok = sqlite3_column_type(st, 4) == SQLITE_INTEGER &&
             (sqlite3_column_int(st, 4) == 0 ||
              sqlite3_column_int(st, 4) == 1) &&
             sqlite3_column_type(st, 5) == SQLITE_INTEGER &&
             sqlite3_column_int(st, 5) == CONSENSUS_STATE_VALIDATION_FULL &&
             sqlite3_column_type(st, 6) == SQLITE_TEXT &&
             sqlite3_column_bytes(st, 6) == 0;
    }
    if (ok) {
        claim->schema_version = CONSENSUS_STATE_SOURCE_RECEIPT_V2;
        claim->source_clean = sqlite3_column_int(st, 4) == 1;
        claim->validation_profile = (uint8_t)sqlite3_column_int(st, 5);
    }
    sqlite3_finalize(st);
    return ok;
}

static bool pr_write_session_claim(
    sqlite3 *db, const struct consensus_state_source_receipt *claim,
    const uint8_t source_epoch[32])
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "UPDATE consensus_state_producer_session SET "
            "source_tree_root=?,toolchain_digest=?,build_inputs_digest=?,"
            "source_epoch_digest=?,source_clean=?,validation_profile=?,"
            "producer_commit='' WHERE singleton=1", -1, &st, NULL) !=
        SQLITE_OK)
        return false;
    int i = 1;
    bool ok = sqlite3_bind_blob(st, i++, claim->source_tree_root, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_blob(st, i++, claim->toolchain_digest, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_blob(st, i++, claim->build_inputs_digest, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_blob(st, i++, source_epoch, 32,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_int(st, i++, claim->source_clean ? 1 : 0) ==
                  SQLITE_OK &&
              sqlite3_bind_int(st, i++, claim->validation_profile) ==
                  SQLITE_OK &&
              sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:test-fixture-tamper
    sqlite3_finalize(st);
    return ok;
}

enum pr_claim_mutation {
    PR_MUTATE_SOURCE_ROOT = 0,
    PR_MUTATE_TOOLCHAIN,
    PR_MUTATE_BUILD_INPUTS,
};

static void pr_mutate_claim(struct consensus_state_source_receipt *claim,
                            enum pr_claim_mutation mutation)
{
    if (mutation == PR_MUTATE_SOURCE_ROOT)
        claim->source_tree_root[0] ^= 0x01u;
    else if (mutation == PR_MUTATE_TOOLCHAIN)
        claim->toolchain_digest[0] ^= 0x02u;
    else
        claim->build_inputs_digest[0] ^= 0x04u;
}

static bool pr_self_consistent_claim_tamper_refuses(
    sqlite3 *db, const struct consensus_state_source_receipt *original,
    const uint8_t original_epoch[32], enum pr_claim_mutation mutation,
    char *err, size_t err_size)
{
    struct consensus_state_source_receipt tampered = *original;
    pr_mutate_claim(&tampered, mutation);
    uint8_t tampered_epoch[32];
    consensus_state_source_epoch_digest(&tampered, tampered_epoch);
    if (!pr_write_session_claim(db, &tampered, tampered_epoch))
        return false;

    bool refused =
        !consensus_state_producer_receipt_begin(
            db, CONSENSUS_STATE_VALIDATION_FULL, err, err_size) &&
        strstr(err, "does not exactly match current") != NULL;

    /* Restore the exact fixture regardless of the assertion result, then
     * resume once so progress_meta is also restored if vulnerable code had
     * incorrectly published the attacker-derived epoch. */
    bool restored = pr_write_session_claim(db, original, original_epoch) &&
                    consensus_state_producer_receipt_begin(
                        db, CONSENSUS_STATE_VALIDATION_FULL, err, err_size);
    return refused && restored;
}

static bool pr_self_consistent_claim_tamper_finalize_refuses(
    sqlite3 *db, const struct consensus_state_source_receipt *original,
    const uint8_t original_epoch[32], enum pr_claim_mutation mutation,
    const uint8_t block_hash[32], char *err, size_t err_size)
{
    struct consensus_state_source_receipt tampered = *original;
    pr_mutate_claim(&tampered, mutation);
    uint8_t tampered_epoch[32];
    consensus_state_source_epoch_digest(&tampered, tampered_epoch);
    if (!pr_write_session_claim(db, &tampered, tampered_epoch))
        return false;

    bool refused =
        !consensus_state_producer_receipt_finalize(
            db, 1, block_hash, err, err_size) &&
        strstr(err, "does not own the start session") != NULL;

    /* Vulnerable code may have finalized the attacker claim. Remove that
     * fixture-only evidence, restore the exact session, and republish the
     * genuine epoch so later assertions remain isolated. */
    bool cleaned = pr_exec(
        db, "DROP TABLE IF EXISTS consensus_state_source_receipt");
    bool restored = pr_write_session_claim(db, original, original_epoch) &&
                    consensus_state_producer_receipt_begin(
                        db, CONSENSUS_STATE_VALIDATION_FULL, err, err_size);
    return refused && cleaned && restored;
}

static bool pr_insert_hash_row(sqlite3 *db, const char *sql, int height,
                               const uint8_t hash[32])
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    bool ok = sqlite3_bind_int(st, 1, height) == SQLITE_OK &&
              sqlite3_bind_blob(st, 2, hash, 32, SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return ok;
}

static bool pr_insert_header(sqlite3 *db, int height, const uint8_t hash[32],
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

static bool pr_insert_tip(sqlite3 *db, int height, const char *status,
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

/* Build the tables + cursors that must exist BEFORE the producer begins its
 * fold (begin sets the source-epoch authority the stage rows are stamped
 * with). */
static bool pr_seed_structure(sqlite3 *db)
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
        "height INTEGER PRIMARY KEY,ok INTEGER NOT NULL,status TEXT NOT NULL,"
        "applied_at INTEGER NOT NULL);"
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
        "INSERT INTO utxo_apply_log VALUES(0,1,'verified',1),"
        "(1,1,'verified',1);";
    return pr_exec(db, schema) && coins_kv_ensure_schema(db) &&
           anchor_kv_initialize_history(db, 0) &&
           nullifier_kv_initialize_history(db, 0);
}

/* Seed the fold-produced rows AFTER begin, so the crypto stage rows pick up the
 * source-epoch authority the producer just published (exactly the ordering a
 * real -mint-anchor fold follows). */
static bool pr_seed_fold_rows(sqlite3 *db, uint8_t hash[2][32], uint8_t nf[32])
{
    if (!pr_insert_header(db, 0, hash[0], NULL) ||
        !pr_insert_header(db, 1, hash[1], hash[0]) ||
        !pr_insert_tip(db, 0, "finalized", hash[1]) ||
        !pr_insert_tip(db, 1, "anchor", hash[1]))
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
            if (!pr_insert_hash_row(db, hash_sql[table], height, hash[height]))
                return false;
        }
    }

    uint8_t txid[32];
    for (size_t i = 0; i < sizeof(txid); i++)
        txid[i] = (uint8_t)(0xc1u + i);
    const uint8_t script[] = {0x51};
    if (!coins_kv_add(db, txid, 0, 5000, 0, true, script, sizeof(script)))
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

    const uint8_t one = 1;
    if (!progress_meta_set(db, COINS_KV_MIGRATION_COMPLETE_KEY, &one, 1) ||
        !coins_kv_mark_self_folded(db) ||
        !pr_exec(db, "BEGIN IMMEDIATE") ||
        !coins_kv_set_applied_height_in_tx(db, 2) ||
        !pr_exec(db, "COMMIT")) {
        (void)pr_exec(db, "ROLLBACK");
        return false;
    }
    return true;
}

/* Arm the compiled checkpoint override so the exporter's checkpoint match
 * succeeds for this h=1 fixture generation. */
static bool pr_arm_checkpoint(sqlite3 *db, const uint8_t hash1[32])
{
    static struct sha3_utxo_checkpoint checkpoint;
    memset(&checkpoint, 0, sizeof(checkpoint));
    checkpoint.height = 1;
    memcpy(checkpoint.block_hash, hash1, 32);
    checkpoint.utxo_count = 1;
    checkpoint.total_supply = 5000;
    if (coins_kv_commitment(db, checkpoint.sha3_hash) != 0)
        return false;
    checkpoints_set_sha3_override_for_test(&checkpoint);
    reducer_frontier_test_set_compiled_anchor(0);
    return true;
}

static bool pr_run_export(sqlite3 *db, int output_dir_fd, const char *name,
                          const uint8_t hash1[32],
                          struct consensus_state_export_result *out)
{
    struct consensus_state_snapshot_export_request request = {
        .output_dir_fd = output_dir_fd,
        .output_name = name,
        .expected_height = 1,
    };
    memcpy(request.expected_block_hash, hash1, 32);
    return consensus_state_snapshot_export(db, &request, out);
}

int test_consensus_state_producer_receipt(void)
{
    int failures = 0;
    consensus_state_producer_receipt_test_set_identity(PR_TEST_SOURCE_ID,
                                                        true);

    char dir_template[] = "/tmp/zcl-pr-XXXXXX";
    char *dir = mkdtemp(dir_template);
    PR_CHECK("fixture directory", dir != NULL);
    if (!dir) {
        consensus_state_producer_receipt_test_set_identity(NULL, false);
        return failures;
    }
    PR_CHECK("owned progress store opens", progress_store_open(dir));
    sqlite3 *db = progress_store_db();

    uint8_t hash[2][32] = {{0}};
    uint8_t nf[32] = {0};
    for (size_t i = 0; i < 32; i++) {
        hash[0][i] = (uint8_t)(0x21u + i);
        hash[1][i] = (uint8_t)(0x61u + i);
        nf[i] = (uint8_t)(0xa1u + i);
    }

    PR_CHECK("structural tables seed", db && pr_seed_structure(db));

    /* finalize BEFORE begin fails closed: no start session exists. */
    char err[256] = {0};
    PR_CHECK("finalize without a start session refuses",
             !consensus_state_producer_receipt_finalize(db, 1, hash[1], err,
                                                         sizeof(err)) &&
             strstr(err, "no start session") != NULL);

    /* Producer START ownership. */
    char overlong_source_id[66];
    memset(overlong_source_id, 'a', sizeof(overlong_source_id) - 1u);
    overlong_source_id[sizeof(overlong_source_id) - 1u] = '\0';
    consensus_state_producer_receipt_test_set_identity(overlong_source_id,
                                                        true);
    PR_CHECK("overlong source identity cannot truncate into authority",
             !consensus_state_producer_receipt_begin(
                 db, CONSENSUS_STATE_VALIDATION_FULL, err, sizeof(err)) &&
             strstr(err, "no exact 64-hex") != NULL);
    consensus_state_producer_receipt_test_set_identity(PR_TEST_SOURCE_ID,
                                                        true);
    PR_CHECK("producer begin writes the durable session",
             consensus_state_producer_receipt_begin(
                 db, CONSENSUS_STATE_VALIDATION_FULL, err, sizeof(err)));
    PR_CHECK("new producer session uses source-identity v2 with no Git authority",
             pr_scalar_true(db,
                 "SELECT schema='zcl.consensus_state_producer_session.v2' "
                 "AND typeof(producer_commit)='text' "
                 "AND length(producer_commit)=0 "
                 "FROM consensus_state_producer_session WHERE singleton=1"));
    /* Idempotent resume by the same binary + claim is a no-op success. */
    PR_CHECK("producer begin is idempotent for the same binary",
             consensus_state_producer_receipt_begin(
                 db, CONSENSUS_STATE_VALIDATION_FULL, err, sizeof(err)));

    /* A row can be internally self-consistent yet still be foreign. The old
     * resume path derived its expected epoch from these stored fields and
     * therefore adopted each of these attacker-rewritten claims. */
    struct consensus_state_source_receipt original_claim;
    uint8_t original_epoch[32];
    PR_CHECK("capture exact current v2 session claim",
             pr_read_session_claim(db, &original_claim, original_epoch));
    PR_CHECK("self-consistent stored source-root tamper cannot resume",
             pr_self_consistent_claim_tamper_refuses(
                 db, &original_claim, original_epoch, PR_MUTATE_SOURCE_ROOT,
                 err, sizeof(err)));
    PR_CHECK("self-consistent stored toolchain tamper cannot resume",
             pr_self_consistent_claim_tamper_refuses(
                 db, &original_claim, original_epoch, PR_MUTATE_TOOLCHAIN,
                 err, sizeof(err)));
    PR_CHECK("self-consistent stored build-input tamper cannot resume",
             pr_self_consistent_claim_tamper_refuses(
                 db, &original_claim, original_epoch, PR_MUTATE_BUILD_INPUTS,
                 err, sizeof(err)));

    /* A different validation profile on the same datadir refuses. */
    PR_CHECK("producer begin refuses a conflicting profile",
             !consensus_state_producer_receipt_begin(
                 db, CONSENSUS_STATE_VALIDATION_CHECKPOINT_FOLD, err,
                 sizeof(err)));

    /* A structurally valid legacy row is still readable by diagnostics, but
     * can neither resume a fold nor finalize a new authoritative receipt. */
    PR_CHECK("fixture relabels the durable session as legacy v1",
             pr_exec(db,
                 "UPDATE consensus_state_producer_session "
                 "SET schema='zcl.consensus_state_producer_session.v1',"
                 "producer_commit='" PR_TEST_LEGACY_COMMIT "'"));
    PR_CHECK("legacy v1 producer session cannot resume",
             !consensus_state_producer_receipt_begin(
                 db, CONSENSUS_STATE_VALIDATION_FULL, err, sizeof(err)) &&
             strstr(err, "legacy v1 session") != NULL);
    PR_CHECK("legacy v1 producer session cannot finalize",
             !consensus_state_producer_receipt_finalize(
                 db, 1, hash[1], err, sizeof(err)) &&
             strstr(err, "legacy v1 session") != NULL);
    PR_CHECK("legacy v1 refusal writes no final receipt",
             pr_scalar_true(db,
                 "SELECT count(*)=0 FROM sqlite_master "
                 "WHERE type='table' "
                 "AND name='consensus_state_source_receipt'"));
    PR_CHECK("fixture restores the current v2 session",
             pr_exec(db,
                 "UPDATE consensus_state_producer_session "
                 "SET schema='zcl.consensus_state_producer_session.v2',"
                 "producer_commit=''"));

    /* The fold runs; its crypto rows are stamped with the published epoch. */
    PR_CHECK("fold rows seed with the published source epoch",
             pr_seed_fold_rows(db, hash, nf));

    PR_CHECK("finalize refuses self-consistent stored source-root tamper",
             pr_self_consistent_claim_tamper_finalize_refuses(
                 db, &original_claim, original_epoch, PR_MUTATE_SOURCE_ROOT,
                 hash[1], err, sizeof(err)));
    PR_CHECK("finalize refuses self-consistent stored toolchain tamper",
             pr_self_consistent_claim_tamper_finalize_refuses(
                 db, &original_claim, original_epoch, PR_MUTATE_TOOLCHAIN,
                 hash[1], err, sizeof(err)));
    PR_CHECK("finalize refuses self-consistent stored build-input tamper",
             pr_self_consistent_claim_tamper_finalize_refuses(
                 db, &original_claim, original_epoch, PR_MUTATE_BUILD_INPUTS,
                 hash[1], err, sizeof(err)));

    /* Producer END ownership: finalize binds the receipt to the fold. */
    PR_CHECK("producer finalize writes the source receipt",
             consensus_state_producer_receipt_finalize(db, 1, hash[1], err,
                                                        sizeof(err)));
    PR_CHECK("new final receipt uses source-identity v2 with no Git authority",
             pr_scalar_true(db,
                 "SELECT schema='zcl.consensus_state_source_receipt.v2' "
                 "AND typeof(producer_commit)='text' "
                 "AND length(producer_commit)=0 "
                 "FROM consensus_state_source_receipt WHERE singleton=1"));
    struct producer_status_read producer_status;
    char status_err[256] = {0};
    PR_CHECK("v2 producer status exposes source telemetry",
             consensus_state_producer_status_read(
                 dir, &producer_status, status_err, sizeof(status_err)) &&
             producer_status.receipt_finalized &&
             strcmp(producer_status.receipt_schema,
                    CONSENSUS_STATE_SOURCE_RECEIPT_SCHEMA_V2) == 0 &&
             strcmp(producer_status.source_tree_root,
                    PR_TEST_SOURCE_ID) == 0 &&
             strlen(producer_status.source_epoch_digest) == 64 &&
             producer_status.producer_commit[0] == '\0');
    PR_CHECK("producer status rejects zero toolchain/build-input authority",
             pr_exec(db,
                 "UPDATE consensus_state_source_receipt "
                 "SET toolchain_digest=zeroblob(32),"
                 "build_inputs_digest=zeroblob(32)") &&
             !consensus_state_producer_status_read(
                 dir, &producer_status, status_err, sizeof(status_err)) &&
             !producer_status.receipt_finalized &&
             strstr(status_err, "finalized receipt") != NULL);
    PR_CHECK("producer status fixture restores exact build claims",
             pr_exec(db,
                 "UPDATE consensus_state_source_receipt SET "
                 "toolchain_digest=(SELECT toolchain_digest FROM "
                 "consensus_state_producer_session WHERE singleton=1),"
                 "build_inputs_digest=(SELECT build_inputs_digest FROM "
                 "consensus_state_producer_session WHERE singleton=1)") &&
             consensus_state_producer_status_read(
                 dir, &producer_status, status_err, sizeof(status_err)) &&
             producer_status.receipt_finalized);
    PR_CHECK("producer status rejects an impossible finalized fold cursor",
             pr_exec(db,
                 "UPDATE consensus_state_source_receipt SET fold_cursor=0") &&
             !consensus_state_producer_status_read(
                 dir, &producer_status, status_err, sizeof(status_err)) &&
             !producer_status.receipt_finalized &&
             strstr(status_err, "finalized receipt") != NULL);
    PR_CHECK("producer status fixture restores the finalized fold cursor",
             pr_exec(db,
                 "UPDATE consensus_state_source_receipt SET fold_cursor=2") &&
             consensus_state_producer_status_read(
                 dir, &producer_status, status_err, sizeof(status_err)) &&
             producer_status.receipt_finalized &&
             producer_status.fold_cursor == 2);
    PR_CHECK("producer finalize exact retry is idempotent",
             consensus_state_producer_receipt_finalize(db, 1, hash[1], err,
                                                        sizeof(err)));

    PR_CHECK("compiled checkpoint override arms", pr_arm_checkpoint(db, hash[1]));

    char export_dir[512];
    snprintf(export_dir, sizeof(export_dir), "%s/export", dir);
    PR_CHECK("descriptor-bound output directory",
             mkdir(export_dir, 0700) == 0);
    int output_dir_fd = open(export_dir,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    PR_CHECK("output directory descriptor", output_dir_fd >= 0);

    char accepted_output[640];
    snprintf(accepted_output, sizeof(accepted_output), "%s/accepted.bundle.db",
             export_dir);
    struct consensus_state_export_result accepted;
    bool exported = pr_run_export(db, output_dir_fd, "accepted.bundle.db",
                                  hash[1], &accepted);
    struct stat st;
    PR_CHECK("producer-earned receipt is admitted end-to-end",
             exported && accepted.status == CONSENSUS_EXPORT_EXPORTED &&
             accepted.history_complete && accepted.height == 1 &&
             accepted.source_clean &&
             accepted.validation_profile == CONSENSUS_STATE_VALIDATION_FULL &&
             accepted.utxo_count == 1 && accepted.anchor_count == 2 &&
             accepted.nullifier_count == 1 &&
             lstat(accepted_output, &st) == 0 && S_ISREG(st.st_mode));

    /* TAMPER: flip a byte of the receipt digest — the exporter refuses. */
    char tamper_output[640];
    snprintf(tamper_output, sizeof(tamper_output), "%s/tamper.bundle.db",
             export_dir);
    PR_CHECK("corrupt the finalized receipt digest",
             pr_exec(db,
                 "UPDATE consensus_state_source_receipt "
                 "SET receipt_digest=zeroblob(32)"));
    memset(status_err, 0, sizeof(status_err));
    PR_CHECK("producer status never labels a corrupt receipt finalized",
             !consensus_state_producer_status_read(
                 dir, &producer_status, status_err, sizeof(status_err)) &&
             !producer_status.receipt_finalized &&
             strstr(status_err, "digest verification") != NULL);
    PR_CHECK("finalize refuses to overwrite conflicting durable evidence",
             !consensus_state_producer_receipt_finalize(db, 1, hash[1], err,
                                                         sizeof(err)) &&
             strstr(err, "conflicting finalized receipt") != NULL);
    struct consensus_state_export_result tampered;
    PR_CHECK("tampered receipt is refused and publishes nothing",
             !pr_run_export(db, output_dir_fd, "tamper.bundle.db", hash[1],
                            &tampered) &&
             tampered.status == CONSENSUS_EXPORT_MISSING_PROOF &&
             access(tamper_output, F_OK) != 0);

    /* MISSING: delete the receipt — the exporter refuses. */
    char missing_output[640];
    snprintf(missing_output, sizeof(missing_output), "%s/missing.bundle.db",
             export_dir);
    PR_CHECK("delete the finalized receipt",
             pr_exec(db, "DELETE FROM consensus_state_source_receipt"));
    struct consensus_state_export_result missing;
    PR_CHECK("missing receipt is refused and publishes nothing",
             !pr_run_export(db, output_dir_fd, "missing.bundle.db", hash[1],
                            &missing) &&
             missing.status == CONSENSUS_EXPORT_MISSING_PROOF &&
             access(missing_output, F_OK) != 0);

    /* UNOWNED START SESSION: corrupt the recorded running-binary digest so the
     * running executable no longer owns the session — finalize refuses. */
    PR_CHECK("corrupt the start session's running-binary digest",
             pr_exec(db,
                 "UPDATE consensus_state_producer_session "
                 "SET running_binary_digest=zeroblob(32)"));
    PR_CHECK("finalize refuses a session the running binary does not own",
             !consensus_state_producer_receipt_finalize(db, 1, hash[1], err,
                                                         sizeof(err)) &&
             strstr(err, "does not own the start session") != NULL);

    /* OPERATOR RETIREMENT. The session above is now foreign (zeroblob binary
     * digest): exactly the datadir state a binary upgrade leaves behind, the
     * state that degrades the exporter at every boot. The typed remedy must
     * delete it, audit it, and let begin() start over. */
    struct consensus_state_producer_session_retired retired;
    memset(&retired, 0, sizeof(retired));
    PR_CHECK("retire deletes the foreign session and audits it",
             consensus_state_producer_session_retire(
                 db, &retired, err, sizeof(err)) ==
                 CONSENSUS_STATE_PRODUCER_SESSION_RETIRE_RETIRED &&
             pr_scalar_true(db,
                 "SELECT count(*)=0 "
                 "FROM consensus_state_producer_session") &&
             pr_scalar_true(db,
                 "SELECT count(*)=1 FROM progress_meta "
                 "WHERE key='consensus_state.producer_session_retired_"
                 "binary_digest' AND value=zeroblob(32)"));
    PR_CHECK("retire evidence reports the retired foreign session",
             strspn(retired.running_binary_digest, "0") == 64 &&
             strlen(retired.source_tree_root) == 64 &&
             strlen(retired.source_epoch_digest) == 64 &&
             retired.validation_profile == CONSENSUS_STATE_VALIDATION_FULL &&
             retired.started_us > 0);
    PR_CHECK("retire is idempotent against an empty datadir",
             consensus_state_producer_session_retire(
                 db, &retired, err, sizeof(err)) ==
                 CONSENSUS_STATE_PRODUCER_SESSION_RETIRE_ABSENT);
    PR_CHECK("begin re-mints a fresh session after retirement",
             consensus_state_producer_receipt_begin(
                 db, CONSENSUS_STATE_VALIDATION_FULL, err, sizeof(err)) &&
             pr_scalar_true(db,
                 "SELECT count(*)=1 "
                 "FROM consensus_state_producer_session"));
    PR_CHECK("retire refuses the running build's own session",
             consensus_state_producer_session_retire(
                 db, &retired, err, sizeof(err)) ==
                 CONSENSUS_STATE_PRODUCER_SESSION_RETIRE_CURRENT &&
             strstr(err, "matches this running build") != NULL &&
             pr_scalar_true(db,
                 "SELECT count(*)=1 "
                 "FROM consensus_state_producer_session"));
    PR_CHECK("retire tolerates a datadir with no session table",
             pr_exec(db,
                 "DROP TABLE consensus_state_producer_session") &&
             consensus_state_producer_session_retire(
                 db, &retired, err, sizeof(err)) ==
                 CONSENSUS_STATE_PRODUCER_SESSION_RETIRE_ABSENT);

    reducer_frontier_test_set_compiled_anchor(-1);
    checkpoints_reset_sha3_override_for_test();
    consensus_state_producer_receipt_test_set_identity(NULL, false);
    progress_store_close();
    if (output_dir_fd >= 0)
        close(output_dir_fd);
    (void)unlink(accepted_output);
    (void)rmdir(export_dir);
    (void)rmdir(dir);
    return failures;
}
