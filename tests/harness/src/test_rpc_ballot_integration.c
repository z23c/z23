/* purpose: Check ballot RPC phases against disk blocks and hash-bound validation fixtures. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
/* Exercise the registered ballot RPC against isolated synthetic evidence. */
#if !defined(_WIN32)
#include "base/hex.h"
#include "chain/chainparams.h"
#include "controllers/blockchain_controller.h"
#include "jobs/reducer_frontier.h"
#include "services/miner_signal_catalog_pin.h"
#include "primitives/block.h"
#include "script/script.h"
#include "storage/disk_block_io.h"
#include "storage/progress_store.h"
#include "test/test_core.h"
#include "validation/main_state.h"
#include <errno.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

struct ballot_fixture {
    char dir[256], blocks[512];
    char raw_schedule[96], catalog_hex[65];
    struct main_state ms;
    struct block block;
    struct block_index index[4];
    struct uint256 hash[4];
    struct disk_block_pos pos;
    struct rpc_table table;
    struct miner_signal_catalog_pin pin;
    sqlite3 *db;
    bool ms_ready, store_open;
};

static const char fixture_catalog[] =
    "[\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",1,1,"
    "[[\"1111111111111111111111111111111111111111111111111111111111111111\",4],"
    "[\"2222222222222222222222222222222222222222222222222222222222222222\",5],"
    "[\"3333333333333333333333333333333333333333333333333333333333333333\",6]],0]";

static bool bf_sql(sqlite3 *db, const char *s)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, s, NULL, NULL, &err);
    if (err) {
        fprintf(stderr, "ballot fixture SQL: %s\n", err);
        sqlite3_free(err);
    }
    return rc == SQLITE_OK;
}

static bool bf_hash_row(sqlite3 *db, const char *sql, int h, const struct uint256 *hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    bool ok = sqlite3_bind_int(st, 1, h) == SQLITE_OK &&
              sqlite3_bind_blob(st, 2, hash->data, 32, SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool bf_status(struct ballot_fixture *f, const char *raw, const char *source,
                      const char *phase, int votes)
{
    struct json_value params = {0}, result = {0};
    bool parsed = json_read(&params, raw, strlen(raw));
    bool ok = parsed && rpc_table_execute(&f->table, "getballotstatus", &params, &result);
    const char *actual = json_get_str(json_get(&result, "phase_of_next_block"));
    const char *basis = json_get_str(json_get(&result, "schedule_source"));
    const char *digest = json_get_str(json_get(&result, "catalog"));
    bool pass = parsed && (phase ? ok && actual && strcmp(actual, phase) == 0 &&
                                       basis && !strcmp(basis, source) &&
                                       digest && !strcmp(digest, f->catalog_hex) &&
                                       json_get_int(json_get(&result, "votes")) == votes
                                 : !ok);
    if (!pass)
        fprintf(stderr, "ballot RPC expected %s, got %s (ok=%d)\n", phase ? phase : "refusal",
                actual ? actual : "none", ok);
    json_free(&params);
    json_free(&result);
    return pass;
}

static bool bf_call(struct ballot_fixture *f, const char *phase, int votes)
{
    return bf_status(f, fixture_catalog, "supplied_catalog", phase, votes) &&
           bf_status(f, f->raw_schedule, "raw_parameters", phase, votes) &&
           bf_status(f, "[0]", "pinned_catalog", phase, votes);
}

static bool bf_catalog(struct ballot_fixture *f, uint8_t digest[32])
{
    struct json_value params = {0}, result = {0};
    bool ok = json_read(&params, fixture_catalog, sizeof(fixture_catalog) - 1) &&
              rpc_table_execute(&f->table, "getballotcatalog", &params, &result);
    const char *hex = json_get_str(json_get(&result, "catalog"));
    ok = ok && hex && zcl_hex_decode(hex, digest, 32);
    if (ok) {
        zcl_hex_encode(digest, 32, f->catalog_hex);
        snprintf(f->raw_schedule, sizeof(f->raw_schedule), "[1,1,4,3,0,\"%s\"]", f->catalog_hex);
        ok = miner_signal_catalog_pin_parse(json_at(&params, 0), json_at(&params, 1),
              json_at(&params, 2), json_at(&params, 3),
              chain_params_get()->consensus.hashGenesisBlock.data, &f->pin).ok;
        if (ok) rpc_blockchain_set_ballot_catalog_pin(&f->pin);
    }
    json_free(&params);
    json_free(&result);
    return ok;
}

static bool bf_schema(struct ballot_fixture *f)
{
    return bf_sql(
        f->db, "CREATE TABLE tip_finalize_log(height INTEGER PRIMARY KEY,status TEXT,ok "
               "INTEGER,tip_hash BLOB);"
               "CREATE TABLE script_validate_log(height INTEGER PRIMARY KEY,status TEXT,ok "
               "INTEGER,block_hash BLOB);"
               "CREATE TABLE proof_validate_log(height INTEGER PRIMARY KEY,status TEXT,ok "
               "INTEGER,block_hash BLOB);"
               "CREATE TABLE header_admit_log(height INTEGER PRIMARY KEY,hash BLOB);"
               "CREATE TABLE validate_headers_log(height INTEGER PRIMARY KEY,ok INTEGER,hash BLOB);"
               "CREATE TABLE utxo_apply_log(height INTEGER PRIMARY KEY,ok INTEGER,status TEXT);"
               "CREATE TABLE utxo_apply_delta(height INTEGER PRIMARY KEY,branch_hash BLOB);");
}

static bool bf_body(struct ballot_fixture *f)
{
    struct block *b = &f->block;
    f->hash[0] = chain_params_get()->consensus.hashGenesisBlock;
    b->header.nVersion = 4;
    b->header.nTime = 1234;
    b->header.nBits = 0x2000ffff;
    b->header.hashPrevBlock = f->hash[0];
    b->num_vtx = 1;
    b->vtx = calloc(1, sizeof(*b->vtx));
    if (!b->vtx)
        return false;
    transaction_init(&b->vtx[0]);
    if (!transaction_alloc(&b->vtx[0], 1, 1))
        return false;
    outpoint_set_null(&b->vtx[0].vin[0].prevout);
    b->vtx[0].vin[0].sequence = 0xffffffff;
    b->vtx[0].vout[0].value = 0;
    unsigned char payload[69] = {'Z', '2', '3', 'V', 1};
    if (!bf_catalog(f, payload + 5))
        return false;
    payload[37] = 5;
    struct script *sp = &b->vtx[0].vout[0].script_pub_key;
    if (!script_push_op(sp, OP_RETURN) || !script_push_data(sp, payload, sizeof(payload)))
        return false;
    transaction_compute_hash(&b->vtx[0]);
    b->header.hashMerkleRoot = b->vtx[0].hash;
    block_header_get_hash(&b->header, &f->hash[1]);
    f->hash[2].data[0] = 19;
    f->hash[3].data[0] = 20;
    disk_block_pos_init(&f->pos);
    return write_block_to_disk(b, &f->pos, f->dir, chain_params_get()->pchMessageStart);
}

static bool bf_index(struct ballot_fixture *f)
{
    for (int h = 0; h < 4; h++) {
        block_index_init(&f->index[h]);
        f->index[h].nHeight = h;
        f->index[h].hashBlock = f->hash[h];
        f->index[h].phashBlock = &f->index[h].hashBlock;
        f->index[h].pprev = h ? &f->index[h - 1] : NULL;
        if (!block_map_insert(&f->ms.map_block_index, f->index[h].phashBlock, &f->index[h]) ||
            !bf_hash_row(
                f->db,
                "INSERT INTO tip_finalize_log(height,status,ok,tip_hash) VALUES(?,'anchor',1,?)", h,
                &f->hash[h]))
            return false;
    }
    block_index_disk_pos_store(&f->index[1], f->pos.nFile, f->pos.nPos);
    block_index_status_fetch_or(&f->index[1], BLOCK_HAVE_DATA);
    return true;
}

static bool bf_receipts(struct ballot_fixture *f)
{
    sqlite3 *db = f->db;
    const struct uint256 *hash = &f->hash[1];
    return bf_hash_row(db, "INSERT INTO header_admit_log VALUES(?,?)", 1, hash) &&
           bf_hash_row(db, "INSERT INTO validate_headers_log(height,ok,hash) VALUES(?,1,?)", 1,
                       hash) &&
           bf_hash_row(db, "INSERT INTO utxo_apply_delta VALUES(?,?)", 1, hash) &&
           bf_hash_row(db,
                       "INSERT INTO script_validate_log(height,status,ok,block_hash) "
                       "VALUES(?,'verified',1,?)",
                       1, hash) &&
           bf_hash_row(db,
                       "INSERT INTO proof_validate_log(height,status,ok,block_hash) "
                       "VALUES(?,'verified',1,?)",
                       1, hash) &&
           bf_sql(db, "INSERT INTO utxo_apply_log VALUES(1,1,'verified'); INSERT OR REPLACE INTO "
                      "stage_cursor(name,cursor,updated_at) VALUES('tip_finalize',1,1);");
}

static bool bf_setup(struct ballot_fixture *f)
{
    block_init(&f->block);
    if (progress_store_db())
        return false;
    test_make_tmpdir(f->dir, sizeof(f->dir), "ballot_rpc", "integration");
    snprintf(f->blocks, sizeof(f->blocks), "%s/blocks", f->dir);
    if (mkdir(f->blocks, 0700) || !progress_store_open(f->dir))
        return false;
    f->store_open = true;
    f->db = progress_store_db();
    chain_params_select(CHAIN_REGTEST);
    main_state_init(&f->ms);
    f->ms_ready = true;
    rpc_table_init(&f->table);
    register_blockchain_rpc_commands(&f->table);
    set_rpc_warmup_finished();
    rpc_blockchain_set_state(&f->ms, NULL, f->dir);
    return f->db && bf_schema(f) && bf_body(f) && bf_index(f) && bf_receipts(f);
}

static bool bf_advance(struct ballot_fixture *f, int height)
{
    if (!active_chain_move_window_tip(&f->ms.chain_active, &f->index[height]))
        return false;
    reducer_frontier_provable_tip_set(height);
    char sql[128];
    snprintf(sql, sizeof(sql), "UPDATE stage_cursor SET cursor=%d WHERE name='tip_finalize'",
             height ? height : 1);
    return bf_sql(f->db, sql);
}

static bool bf_positive_cases(struct ballot_fixture *f)
{
    if (!bf_advance(f, 0) || !bf_call(f, "voting", 0) || !bf_advance(f, 1) ||
        !bf_call(f, "locked_in", 1))
        return false;
    /* A finalized row at h0 witnesses h1, not genesis. */
    if (!bf_hash_row(f->db,
                     "UPDATE tip_finalize_log SET status='finalized',tip_hash=?2 WHERE height=?1",
                     0, &f->hash[1]) ||
        !bf_call(f, "locked_in", 1))
        return false;
    return bf_advance(f, 2) && bf_call(f, "locked_in", 1) && bf_advance(f, 3) &&
           bf_call(f, "active", 1);
}

static bool bf_catalog_row_check(const struct json_value *rows, size_t i)
{
    const struct json_value *row = json_at(rows, i);
    const char *phase = json_get_str(json_get(row, "phase_of_next_block"));
    const char *revision = json_get_str(json_get(row, "rule_revision"));
    char expected_revision[65];
    memset(expected_revision, (int)('1' + i), 64);
    expected_revision[64] = '\0';
    return revision && !strcmp(revision, expected_revision) &&
        json_get_int(json_get(row, "slot")) == (int64_t)i &&
        json_get_int(json_get(row, "activation")) == (int64_t)(4 + i) &&
        json_get_int(json_get(row, "votes")) == (i == 1 ? 0 : 1) && phase &&
        !strcmp(phase, i == 0 ? "active" : i == 1 ? "expired" : "locked_in");
}

static bool bf_catalog_status(struct ballot_fixture *f, bool expected)
{
    struct json_value params = {0}, result = {0};
    json_set_array(&params);
    bool ok = rpc_table_execute(&f->table, "getballotstatus", &params, &result);
    bool pass = ok == expected;
    if (expected && ok) {
        const struct json_value *rows = json_get(&result, "proposals");
        pass = rows && json_size(rows) == 3 &&
            json_get_int(json_get(&result, "parent_height")) == 3 &&
            json_get_int(json_get(&result, "next_height")) == 4 &&
            !strcmp(json_get_str(json_get(&result, "catalog")), f->catalog_hex);
        for (size_t i = 0; pass && i < 3; i++)
            pass = bf_catalog_row_check(rows, i);
    }
    json_free(&params); json_free(&result);
    return pass;
}

static bool bf_catalog_limit(struct ballot_fixture *f)
{
    struct miner_signal_catalog_pin pin = f->pin;
    pin.count = 256;
    for (size_t i = 0; i < pin.count; i++) {
        memset(pin.entries[i].rule_revision, 0, 32);
        pin.entries[i].rule_revision[0] = (uint8_t)i;
        pin.entries[i].activation = 4;
    }
    struct miner_signal_catalog catalog = {
        .start = pin.start, .window = pin.window, .count = pin.count, .entries = pin.entries
    };
    memcpy(catalog.network_id, pin.network_id, 32);
    memcpy(catalog.genesis, pin.genesis, 32);
    struct miner_signal_schedule schedule;
    if (!miner_signal_catalog_select(&catalog, 0, &schedule).ok) return false;
    memcpy(pin.digest, schedule.catalog, 32);
    rpc_blockchain_set_ballot_catalog_pin(&pin);
    struct json_value params = {0}, result = {0};
    json_set_array(&params);
    bool ok = rpc_table_execute(&f->table, "getballotstatus", &params, &result);
    const struct json_value *rows = json_get(&result, "proposals");
    ok = ok && rows && json_size(rows) == 256 &&
        json_get_int(json_get(json_at(rows, 255), "slot")) == 255;
    json_free(&result);
    pin.digest[0] ^= 1;
    ok = ok && !rpc_table_execute(&f->table, "getballotstatus", &params, &result);
    pin.count = 257;
    ok = ok && !rpc_table_execute(&f->table, "getballotstatus", &params, &result);
    json_free(&params); json_free(&result);
    rpc_blockchain_set_ballot_catalog_pin(&f->pin);
    return ok;
}

static bool bf_negative_cases(struct ballot_fixture *f)
{
    sqlite3 *db = f->db;
    if (!bf_sql(db, "UPDATE proof_validate_log SET block_hash=zeroblob(32) WHERE height=1") ||
        !bf_call(f, NULL, 0) || !bf_catalog_status(f, false) ||
        !bf_hash_row(db, "UPDATE proof_validate_log SET block_hash=?2 WHERE height=?1", 1,
                     &f->hash[1]) ||
        !bf_sql(db, "DELETE FROM script_validate_log WHERE height=1") ||
        !bf_call(f, NULL, 0) ||
        !bf_hash_row(
            db,
            "INSERT INTO script_validate_log(height,status,ok,block_hash) VALUES(?,'verified',1,?)",
            1, &f->hash[1]))
        return false;
    block_index_disk_pos_store(&f->index[1], 999999, 8);
    if (!bf_call(f, NULL, 0) || !bf_catalog_status(f, false))
        return false;
    block_index_disk_pos_store(&f->index[1], f->pos.nFile, f->pos.nPos + 1);
    return bf_call(f, NULL, 0);
}

static bool bf_cleanup(struct ballot_fixture *f)
{
    rpc_blockchain_set_ballot_catalog_pin(NULL);
    rpc_blockchain_set_state(NULL, NULL, NULL);
    if (f->ms_ready)
        main_state_free(&f->ms);
    if (f->store_open)
        progress_store_close();
    block_free(&f->block);
    bool ok = true;
    if (f->blocks[0]) {
        char path[600];
        snprintf(path, sizeof(path), "%s/blk00000.dat", f->blocks);
        if (unlink(path) && errno != ENOENT)
            ok = false;
        if (rmdir(f->blocks) && errno != ENOENT)
            ok = false;
    }
    if (f->dir[0])
        test_cleanup_tmpdir(f->dir);
    return ok;
}

static int ballot_integration_child(void)
{
    struct ballot_fixture f = {0};
    bool ok = bf_setup(&f) && bf_positive_cases(&f) && bf_catalog_status(&f, true) &&
              bf_catalog_limit(&f) && bf_negative_cases(&f);
    if (!bf_cleanup(&f))
        ok = false;
    return ok ? 0 : 1;
}

int test_rpc_ballot_integration(void)
{
    pid_t child = fork();
    if (child < 0) {
        perror("ballot integration fork");
        return 1;
    }
    if (child == 0)
        _exit(ballot_integration_child() == 0 ? 0 : 1);
    int status = 0;
    if (waitpid(child, &status, 0) != child)
        return 1;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 1;
}
#else
#include <stdio.h>
int test_rpc_ballot_integration(void)
{
    fprintf(stderr, "ballot RPC integration fixture: SKIP (requires fork)\n");
    return 0;
}
#endif
