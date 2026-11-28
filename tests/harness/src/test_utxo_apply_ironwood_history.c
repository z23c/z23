/* purpose: Exercise atomic private Ironwood history reconstruction. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "jobs/utxo_apply_ironwood_history.h"
#include "jobs/utxo_apply_turnstile_seed.h"
#include "storage/shielded_pool_kv.h"
#include "validation/main_state.h"
#include <sqlite3.h>
#include "chain/chainparams.h"
#include "chain/chain.h"
#include "bloom/merkle.h"
#include "core/serialize.h"
#include "primitives/block.h"
#include "primitives/transaction_v6_decode.h"
#include "base/hex.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct history_fixture {
    struct block bodies[2];
    struct block_index index[2];
    bool missing, corrupt_tx, corrupt_prev, corrupt_merkle, oversized;
    unsigned reads_h1;
};
static bool history_reader(struct block *out, const struct block_index *bi,
                           const char *datadir, void *user)
{
    (void)datadir;
    struct history_fixture *f = user;
    if (bi->nHeight == 1) ++f->reads_h1;
    if (f->missing) return false;
    if (!block_clone(out, &f->bodies[bi->nHeight])) return false;
    if (bi->nHeight == 1 && f->corrupt_tx) out->vtx[1].hash.data[0] ^= 1;
    if (bi->nHeight == 1 && f->corrupt_prev) out->header.hashPrevBlock.data[0] ^= 1;
    if (bi->nHeight == 1 && f->corrupt_merkle) out->vtx[1].v6_wire.data[12] ^= 1;
    if (bi->nHeight == 1 && f->oversized) out->header.nSolutionSize = MAX_SOLUTION_SIZE + 1;
    return true;
}

static bool history_fixture_make(struct history_fixture *f)
{
    const struct chain_research_descriptor *d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    if (!d || !chain_research_profile_select(CHAIN_RESEARCH_IRONWOOD)) return false;
    struct byte_stream stream;
    stream_init_from_data(&stream, d->genesis_wire, d->genesis_wire_len);
    if (!block_deserialize(&f->bodies[0], &stream) || stream_remaining(&stream)) return false;
    block_get_hash(&f->bodies[0], &f->index[0].hashBlock);
    f->index[0].phashBlock = &f->index[0].hashBlock;
    if (!block_clone(&f->bodies[1], &f->bodies[0])) return false;
    struct block *b = &f->bodies[1];
    struct transaction *v = realloc(b->vtx, 2 * sizeof *v);
    if (!v) return false;
    b->vtx = v;
    transaction_init(&v[1]);
    b->num_vtx = 2;
    FILE *input = fopen("tests/fixtures/ironwood/postnu63-h1-reward-spend.v6", "rb");
    if (!input) return false;
    uint8_t wire[9313];
    bool ok = fread(wire, 1, sizeof wire, input) == sizeof wire && fgetc(input) == EOF && !ferror(input);
    if (fclose(input) || !ok) return false;
    stream_init_from_data(&stream, wire, sizeof wire);
    if (!transaction_v6_decode_prefix(&v[1], &stream, sizeof wire) || stream_remaining(&stream)) return false;
    struct uint256 ids[2] = { v[0].hash, v[1].hash };
    bool mutated = false;
    b->header.hashMerkleRoot = merkle_root_mutated_in_place(ids, 2, &mutated);
    if (mutated) return false;
    b->header.hashPrevBlock = f->index[0].hashBlock;
    block_get_hash(b, &f->index[1].hashBlock);
    f->index[1].phashBlock = &f->index[1].hashBlock;
    f->index[1].pprev = &f->index[0];
    f->index[1].nHeight = 1;
    return true;
}

static bool history_step_ok(struct ironwood_history_cursor *c, struct history_fixture *f,
                            struct ironwood_history_event *event)
{
    struct ironwood_history_cursor next;
    struct zcl_result r = utxo_ironwood_history_step(c, history_reader, NULL, f, &next, event); if (!r.ok) { fprintf(stderr, "history step: %s\n", r.message); return false; }
    *c = next;
    return true;
}

static bool history_check_failure(struct ironwood_history_cursor *c, struct history_fixture *f)
{
    struct ironwood_history_cursor out, before;
    struct ironwood_history_event event, ebefore;
    memset(&out, 0xa5, sizeof out); memcpy(&before, &out, sizeof out);
    memset(&event, 0x5a, sizeof event); memcpy(&ebefore, &event, sizeof event);
    struct zcl_result r = utxo_ironwood_history_step(c, history_reader, NULL, f, &out, &event);
    return !r.ok && ((r.code == UTXO_IRONWOOD_HISTORY_BODY_MISSING) == f->missing) &&
        !memcmp(&out, &before, sizeof out) && !memcmp(&event, &ebefore, sizeof event);
}

static bool history_refusals(struct ironwood_history_cursor *c, struct history_fixture *f)
{
    f->missing = true;
    if (!history_check_failure(c, f)) return false;
    f->missing = false;
    f->corrupt_tx = true;
    if (!history_check_failure(c, f)) return false;
    f->corrupt_tx = false;
    f->corrupt_prev = true;
    if (!history_check_failure(c, f)) return false;
    f->corrupt_prev = false;
    f->corrupt_merkle = true;
    if (!history_check_failure(c, f)) return false;
    f->corrupt_merkle = false;
    f->oversized = true;
    if (!history_check_failure(c, f)) return false;
    f->oversized = false;
    return true;
}

static bool history_start(struct history_fixture *f, const struct block_index **slots,
                          struct ironwood_history_cursor *c)
{
    struct ironwood_history_event e;
    return utxo_ironwood_history_begin(&f->index[1], slots, 2, c).ok &&
        history_step_ok(c, f, &e) && !e.available &&
        history_step_ok(c, f, &e) && !e.available &&
        history_step_ok(c, f, &e) && e.available && e.height == 0 && e.count == 0;
}

static bool history_positive(struct history_fixture *f)
{
    const struct block_index *slots[2] = {0};
    struct ironwood_history_cursor c;
    struct ironwood_history_event e;
    if (!history_start(f, slots, &c)) return false;
    if (!history_refusals(&c, f)) return false;
    uint8_t expected[32];
    return history_step_ok(&c, f, &e) && e.available && e.height == 1 &&
        e.count == 2 && e.ironwood_delta == 1249985000 && c.complete && zcl_hex_decode(
        "382ccad224a7e382b6e18d38beb6f518ef9a30ea0a0cc259aa9021737d41cf22",
        expected, sizeof expected) && !memcmp(e.root, expected, sizeof expected);
}

static bool history_wrong_genesis(struct history_fixture *f)
{
    const struct block_index *slots[2] = {0};
    struct ironwood_history_cursor c;
    struct ironwood_history_event e;
    if (!utxo_ironwood_history_begin(&f->index[1], slots, 2, &c).ok ||
        !history_step_ok(&c, f, &e)) return false;
    f->index[0].hashBlock.data[0] ^= 1;
    bool refused = history_check_failure(&c, f);
    f->index[0].hashBlock.data[0] ^= 1;
    return refused;
}

static bool history_bad_merkle(struct history_fixture *f)
{
    const struct block_index *slots[2] = {0};
    struct ironwood_history_cursor c;
    struct ironwood_history_event e;
    f->bodies[1].header.hashMerkleRoot.data[0] ^= 1;
    block_get_hash(&f->bodies[1], &f->index[1].hashBlock);
    bool ok = utxo_ironwood_history_begin(&f->index[1], slots, 2, &c).ok &&
        history_step_ok(&c, f, &e) && history_step_ok(&c, f, &e) &&
        history_step_ok(&c, f, &e) && history_check_failure(&c, f);
    f->bodies[1].header.hashMerkleRoot.data[0] ^= 1;
    block_get_hash(&f->bodies[1], &f->index[1].hashBlock);
    return ok;
}

static bool pool_index_exists(sqlite3 *db)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "SELECT 1 FROM sqlite_schema WHERE type='index' AND name='shielded_pool_ironwood_unknown'", -1, &s, NULL) != SQLITE_OK) return false;
    bool found = sqlite3_step(s) == SQLITE_ROW;
    sqlite3_finalize(s);
    return found;
}

static bool pool_cursor_is(sqlite3 *db, int cursor)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "SELECT cursor FROM stage_cursor WHERE name='utxo_apply'", -1, &s, NULL) != SQLITE_OK) return false;
    bool ok = sqlite3_step(s) == SQLITE_ROW && sqlite3_column_int(s, 0) == cursor;
    sqlite3_finalize(s);
    return ok;
}

static bool pool_row(sqlite3 *db, int h, bool expect_known, int64_t expect_total)
{
    int64_t total = 0;
    bool known = false, found = false;
    return shielded_pool_kv_get_ironwood(db, h, &total, &known, &found) && found &&
        known == expect_known && (!known || total == expect_total);
}

static void history_reorg_hook(void *user)
{
    struct history_fixture *f = user;
    f->index[1].hashBlock.data[0] ^= 1;
}

static bool pool_test_start(sqlite3 *db, struct main_state *ms, struct history_fixture *f)
{
    if (pool_index_exists(db)) return false;
    chain_params_select(CHAIN_REGTEST);
    (void)utxo_apply_turnstile_seed_run(db, ms, "", history_reader, f);
    if (pool_index_exists(db) || !chain_research_profile_select(CHAIN_RESEARCH_IRONWOOD)) return false;
    if (sqlite3_exec(db, "BEGIN; UPDATE shielded_pool_totals SET sprout=9 WHERE height=0;", NULL, NULL, NULL) != SQLITE_OK) return false;
    (void)utxo_apply_turnstile_seed_run(db, ms, "", history_reader, f);
    int64_t sp=0, sa=0; bool found=false;
    bool ok = !sqlite3_get_autocommit(db) && shielded_pool_kv_get(db,0,&sp,&sa,&found) && found && sp==9;
    if (sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK || !ok) return false;
    f->corrupt_merkle = true;
    for (int i = 0; i < 20 && !pool_row(db,0,true,0); ++i)
        (void)utxo_apply_turnstile_seed_run(db, ms, "", history_reader, f);
    f->corrupt_merkle = false;
    return pool_index_exists(db) && pool_row(db,0,true,0) && pool_row(db,1,false,0) && pool_cursor_is(db,2);
}
static bool pool_test_reorg(sqlite3 *db, struct main_state *ms, struct history_fixture *f)
{
    utxo_apply_turnstile_seed_set_gap_hook_for_test(history_reorg_hook, f);
    bool ok = !utxo_apply_turnstile_seed_run(db, ms, "", history_reader, f) && pool_row(db,1,false,0);
    utxo_apply_turnstile_seed_set_gap_hook_for_test(NULL, NULL);
    f->index[1].hashBlock.data[0] ^= 1;
    return ok;
}
static bool pool_test_restart(sqlite3 *db, struct main_state *ms, struct history_fixture *f)
{
    utxo_apply_turnstile_seed_reset_for_test();
    f->reads_h1 = 0;
    bool ok = sqlite3_exec(db, "CREATE TRIGGER reject_pool BEFORE UPDATE ON shielded_pool_totals WHEN NEW.height=1 BEGIN SELECT RAISE(ABORT,'test'); END", NULL, NULL, NULL) == SQLITE_OK;
    for (int i = 0; ok && i < 20 && !f->reads_h1; ++i)
        (void)utxo_apply_turnstile_seed_run(db, ms, "", history_reader, f);
    if (ok) ok = f->reads_h1 && pool_row(db,0,true,0) && pool_row(db,1,false,0) && pool_cursor_is(db,2);
    if (sqlite3_exec(db, "DROP TRIGGER reject_pool", NULL, NULL, NULL) != SQLITE_OK) ok = false;
    return ok && utxo_apply_turnstile_seed_run(db, ms, "", history_reader, f) && pool_row(db,1,true,1249985000);
}
static bool history_pool_backfill(struct history_fixture *f)
{
    sqlite3 *db = NULL;
    struct main_state ms;
    main_state_init(&ms);
    active_chain_move_window_tip(&ms.chain_active, &f->index[1]);
    bool ok = sqlite3_open(":memory:", &db) == SQLITE_OK &&
        sqlite3_exec(db, "CREATE TABLE shielded_pool_totals(height INTEGER PRIMARY KEY,sprout INTEGER NOT NULL,sapling INTEGER NOT NULL);"
            "INSERT INTO shielded_pool_totals VALUES(0,7,8),(1,7,8);"
            "CREATE TABLE stage_cursor(name TEXT PRIMARY KEY,cursor INTEGER NOT NULL,updated_at INTEGER NOT NULL);"
            "INSERT INTO stage_cursor VALUES('utxo_apply',2,0);", NULL, NULL, NULL) == SQLITE_OK &&
        shielded_pool_kv_ensure_schema(db);
    utxo_apply_turnstile_seed_reset_for_test();
    if (ok) ok = pool_test_start(db,&ms,f) && pool_test_reorg(db,&ms,f) && pool_test_restart(db,&ms,f);
    int64_t sprout = 0, sapling = 0; bool found = false;
    ok = ok && shielded_pool_kv_get(db, 1, &sprout, &sapling, &found) && found && sprout == 7 && sapling == 8;
    utxo_apply_turnstile_seed_reset_for_test();
    if (db) sqlite3_close(db);
    main_state_free(&ms);
    return ok;
}

#define POOL_LONG_ROWS 147
struct pool_long_fixture {
    struct block *bodies;
    struct block_index *index;
    bool corrupt;
};
static bool pool_long_reader(struct block *out, const struct block_index *bi,
                             const char *datadir, void *user)
{
    (void)datadir;
    struct pool_long_fixture *f = user;
    if (!block_clone(out, &f->bodies[bi->nHeight])) return false;
    if (f->corrupt && bi->nHeight == 145) out->vtx[1].hash.data[0] ^= 1;
    return true;
}
static bool pool_long_withdraw(struct block *b)
{
    uint8_t wire[9200];
    FILE *f = fopen("tests/fixtures/ironwood/postnu63-h1-reward-withdrawal.v6", "rb");
    if (!f) return false;
    bool ok = fread(wire, 1, sizeof wire, f) == sizeof wire && fgetc(f) == EOF && !ferror(f);
    if (fclose(f) || !ok) return false;
    struct transaction *v = &b->vtx[1];
    transaction_free(v);
    struct byte_stream s;
    stream_init_from_data(&s, wire, sizeof wire);
    if (!transaction_v6_decode_prefix(v, &s, sizeof wire) || stream_remaining(&s)) return false;
    struct uint256 ids[2] = {b->vtx[0].hash, v->hash};
    bool mutated = false;
    b->header.hashMerkleRoot = merkle_root_mutated_in_place(ids, 2, &mutated);
    return !mutated;
}
static bool pool_long_build(struct pool_long_fixture *f, struct history_fixture *source)
{
    f->bodies = calloc(POOL_LONG_ROWS, sizeof *f->bodies);
    f->index = calloc(POOL_LONG_ROWS, sizeof *f->index);
    if (!f->bodies || !f->index) return false;
    for (int i = 0; i < POOL_LONG_ROWS; ++i) {
        const struct block *b = i >= 145 ? &source->bodies[1] : &source->bodies[0];
        if (!block_clone(&f->bodies[i], b)) return false;
        if (i == 146 && !pool_long_withdraw(&f->bodies[i])) return false;
        if (i) f->bodies[i].header.hashPrevBlock = f->index[i-1].hashBlock;
        block_get_hash(&f->bodies[i], &f->index[i].hashBlock);
        f->index[i].phashBlock = &f->index[i].hashBlock;
        f->index[i].nHeight = i;
        if (i) f->index[i].pprev = &f->index[i-1];
    }
    return true;
}
static bool pool_long_db(sqlite3 **db)
{
    return sqlite3_open(":memory:", db) == SQLITE_OK &&
        sqlite3_exec(*db, "CREATE TABLE shielded_pool_totals(height INTEGER PRIMARY KEY,sprout INTEGER NOT NULL,sapling INTEGER NOT NULL);"
            "WITH RECURSIVE h(n) AS (VALUES(0) UNION ALL SELECT n+1 FROM h WHERE n<146) INSERT INTO shielded_pool_totals SELECT n,7,8 FROM h;"
            "CREATE TABLE stage_cursor(name TEXT PRIMARY KEY,cursor INTEGER NOT NULL,updated_at INTEGER NOT NULL);"
            "INSERT INTO stage_cursor VALUES('utxo_apply',147,0);", NULL, NULL, NULL) == SQLITE_OK &&
        shielded_pool_kv_ensure_schema(*db);
}
static bool pool_long_replay(sqlite3 *db, struct main_state *ms, struct pool_long_fixture *f)
{
    active_chain_move_window_tip(&ms->chain_active, &f->index[POOL_LONG_ROWS-1]);
    utxo_apply_turnstile_seed_reset_for_test();
    f->corrupt = true;
    for (int i=0; i<100 && !pool_row(db,144,true,0); ++i)
        (void)utxo_apply_turnstile_seed_run(db, ms, "", pool_long_reader, f);
    bool ok = pool_row(db,144,true,0) && pool_row(db,145,false,0);
    f->corrupt = false;
    for (int i=0; ok && i<100 && !pool_row(db,146,true,0); ++i)
        (void)utxo_apply_turnstile_seed_run(db, ms, "", pool_long_reader, f);
    return ok && pool_row(db,145,true,1249985000) && pool_row(db,146,true,0) && pool_cursor_is(db,147);
}
static bool pool_long_case(struct history_fixture *source)
{
    struct pool_long_fixture f = {0};
    struct main_state ms;
    sqlite3 *db = NULL;
    main_state_init(&ms);
    bool ok = pool_long_build(&f, source) && pool_long_db(&db) && pool_long_replay(db, &ms, &f);
    int64_t sp=0, sa=0; bool found=false;
    ok = ok && shielded_pool_kv_get(db,146,&sp,&sa,&found) && found && sp==7 && sa==8;
    utxo_apply_turnstile_seed_reset_for_test();
    if (db) sqlite3_close(db);
    main_state_free(&ms);
    if (f.bodies) for (int i=0; i<POOL_LONG_ROWS; ++i) block_free(&f.bodies[i]);
    free(f.bodies); free(f.index);
    return ok;
}


static bool history_withdraw_delta(struct history_fixture *f)
{
    FILE *input = fopen("tests/fixtures/ironwood/postnu63-h1-reward-withdrawal.v6", "rb");
    if (!input) return false;
    uint8_t wire[9200];
    bool ok = fread(wire, 1, sizeof wire, input) == sizeof wire && fgetc(input) == EOF && !ferror(input);
    if (fclose(input) || !ok) return false;
    struct transaction *v = &f->bodies[1].vtx[1];
    transaction_free(v);
    struct byte_stream s;
    stream_init_from_data(&s, wire, sizeof wire);
    if (!transaction_v6_decode_prefix(v, &s, sizeof wire) || stream_remaining(&s)) return false;
    struct uint256 ids[2] = {f->bodies[1].vtx[0].hash, v->hash};
    bool mutated = false;
    f->bodies[1].header.hashMerkleRoot = merkle_root_mutated_in_place(ids, 2, &mutated);
    block_get_hash(&f->bodies[1], &f->index[1].hashBlock);
    const struct block_index *slots[2] = {0};
    struct ironwood_history_cursor c;
    struct ironwood_history_event event;
    return !mutated && history_start(f, slots, &c) && history_step_ok(&c, f, &event) &&
        event.available && event.ironwood_delta == -1249985000;
}

int test_utxo_apply_ironwood_history(void)
{
    struct history_fixture f = {0};
    bool setup = history_fixture_make(&f); bool positive = setup && history_positive(&f); bool negative = positive && history_wrong_genesis(&f); bool ok = negative && history_bad_merkle(&f) && history_pool_backfill(&f) && pool_long_case(&f) && history_withdraw_delta(&f); if (!ok) fprintf(stderr, "history setup=%d positive=%d negative=%d\n", setup, positive, negative);
    block_free(&f.bodies[0]);
    block_free(&f.bodies[1]);
    chain_params_select(CHAIN_MAIN);
    printf("Ironwood canonical history: %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
