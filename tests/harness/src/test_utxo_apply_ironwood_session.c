/* purpose: Verify private Ironwood session bootstrap, replay and rollback. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "jobs/utxo_apply_ironwood_session.h"
#include "utxo_apply_ironwood_bootstrap_internal.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "bloom/merkle.h"
#include "core/serialize.h"
#include "base/serialize_le.h"
#include "sha3/sha3.h"
#include "primitives/block.h"
#include "primitives/transaction_v6_decode.h"
#include "services/ironwood_resident_params.h"
#include "storage/repair_marker.h"
#include "storage/progress_store.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct session_fixture {
    sqlite3 *db;
    struct block bodies[4];
    struct block_index index[4];
    unsigned reads[4];
    bool corrupt;
    bool missing;
    int missing_height;
    struct block alternate[2];
    struct block_index alt_index[2];
};
static bool session_reader(struct block *out, const struct block_index *bi,
    const char *datadir, void *user)
{
    (void)datadir;
    struct session_fixture *f = user;
    if (bi->nHeight < 0 || bi->nHeight >= 4) return false;
    ++f->reads[bi->nHeight];
    if (f->missing && bi->nHeight == f->missing_height) return false;
    const struct block *source = &f->bodies[bi->nHeight];
    if (bi == &f->alt_index[0]) source = &f->alternate[0];
    if (bi == &f->alt_index[1]) source = &f->alternate[1];
    if (!block_clone(out, source)) return false;
    if (f->corrupt && bi->nHeight == 1) out->vtx[1].hash.data[0] ^= 1;
    return true;
}
static bool read_payment(struct transaction *tx)
{
    uint8_t wire[9313];
    FILE *input = fopen("tests/fixtures/ironwood/postnu63-h1-reward-spend.v6", "rb");
    if (!input) return false;
    bool ok = fread(wire, 1, sizeof wire, input) == sizeof wire && fgetc(input) == EOF && !ferror(input);
    if (fclose(input) || !ok) return false;
    struct byte_stream stream;
    stream_init_from_data(&stream, wire, sizeof wire);
    return transaction_v6_decode_prefix(tx, &stream, sizeof wire) && !stream_remaining(&stream);
}
static bool fixture_payment(struct session_fixture *f)
{
    if (!block_clone(&f->bodies[1], &f->bodies[0])) return false;
    struct block *b = &f->bodies[1];
    struct transaction *v = realloc(b->vtx, 2 * sizeof *v);
    if (!v) return false;
    b->vtx = v; transaction_init(&v[1]); b->num_vtx = 2;
    if (!read_payment(&v[1])) return false;
    struct uint256 ids[2] = {v[0].hash, v[1].hash};
    bool mutated = false;
    b->header.hashMerkleRoot = merkle_root_mutated_in_place(ids, 2, &mutated);
    return !mutated;
}
static bool fixture_init(struct session_fixture *f)
{
    memset(f, 0, sizeof *f);
    f->missing_height = 1;
    const struct chain_research_descriptor *d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    if (!d || !chain_research_profile_select(CHAIN_RESEARCH_IRONWOOD)) return false;
    struct byte_stream stream;
    stream_init_from_data(&stream, d->genesis_wire, d->genesis_wire_len);
    if (!block_deserialize(&f->bodies[0], &stream) || stream_remaining(&stream)) return false;
    block_get_hash(&f->bodies[0], &f->index[0].hashBlock);
    f->index[0].phashBlock = &f->index[0].hashBlock;
    if (!fixture_payment(f)) return false;
    for (int i = 1; i < 4; ++i) {
        if (i > 1 && !block_clone(&f->bodies[i], &f->bodies[1])) return false;
        f->bodies[i].header.hashPrevBlock = f->index[i - 1].hashBlock;
        block_get_hash(&f->bodies[i], &f->index[i].hashBlock);
        f->index[i].phashBlock = &f->index[i].hashBlock;
        f->index[i].pprev = &f->index[i - 1]; f->index[i].nHeight = i;
    }
    return sqlite3_open(":memory:", &f->db) == SQLITE_OK;
}
static bool sql(sqlite3 *db, const char *statement)
{ return sqlite3_exec(db, statement, NULL, NULL, NULL) == SQLITE_OK; }
static enum utxo_ironwood_result session_prepare(struct session_fixture *f, int height,
    struct utxo_ironwood_pending *pending)
{
    return utxo_ironwood_session_prepare(f->db, &f->index[height], &f->bodies[height],
        session_reader, NULL, f, pending);
}
static bool indexed_history_cases(struct session_fixture *f)
{
    size_t size = 0;
    const uint8_t *params = ironwood_resident_merkle_parameters(&size);
    struct ironwood_note_frontier a = {0}, b = {0};
    uint8_t root[32], next_root[32];
    struct uint256 zero = {0}, wrong = {0};
    struct ironwood_history_event event = {0};
    if (!ironwood_note_frontier_extend(&a, NULL, 0, params, size, root).ok) return false;
    if (!utxo_ironwood_history_indexed_step(&f->index[2], 0, &zero, &a, root,
            session_reader, NULL, f, &b, next_root, &event).ok ||
        !event.available || event.height != 0 || b.count != 0) return false;
    a = b; memcpy(root, next_root, 32);
    wrong.data[0] = 1;
    struct ironwood_note_frontier before = b;
    if (utxo_ironwood_history_indexed_step(&f->index[2], 1, &wrong, &a, root,
            session_reader, NULL, f, &b, next_root, &event).ok ||
        memcmp(&b, &before, sizeof b)) return false;
    if (!utxo_ironwood_history_indexed_step(&f->index[2], 1, &f->index[0].hashBlock,
            &a, root, session_reader, NULL, f, &b, next_root, &event).ok ||
        event.height != 1 || b.count != 2) return false;
    struct block_index alternate = f->index[1], alternate_parent = f->index[2];
    alternate.hashBlock.data[0] ^= 1;
    alternate.phashBlock = &alternate.hashBlock;
    alternate_parent.pprev = &alternate;
    alternate_parent.pskip = NULL;
    before = b;
    return !utxo_ironwood_history_indexed_step(&alternate_parent, 1,
        &f->index[0].hashBlock, &a, root, session_reader, NULL, f,
        &b, next_root, &event).ok && !memcmp(&b, &before, sizeof b);
}
static bool pending_bootstrap_refusal(struct session_fixture *f)
{
    const uint8_t zero[32] = {0};
    struct utxo_ironwood_pending p, before;
    memset(&p, 0xa5, sizeof p); before = p;
    if (!sql(f->db, "BEGIN") || !repair_marker_table_ensure(f->db) ||
        !repair_marker_note_in_tx(f->db, "utxo_apply.ironwood_frontier_bootstrap",
                                  0, zero, NULL, 0)) return false;
    bool ok = session_prepare(f, 1, &p) == UTXO_IRONWOOD_HISTORY_INCOMPLETE &&
        !memcmp(&p, &before, sizeof p);
    utxo_ironwood_session_reset();
    return sql(f->db, "ROLLBACK") && ok;
}
static enum ironwood_bootstrap_result test_bootstrap_step(sqlite3 *db, uint64_t epoch,
    const struct block_index *parent, const struct block_index *old_parent,
    struct session_fixture *f, const struct ironwood_bootstrap_cursor *in,
    struct ironwood_bootstrap_cursor *out)
{
    struct ironwood_bootstrap_slice slice = {0};
    const struct block_index *scan = in->retarget ? old_parent : parent;
    if (in->active && scan && scan->phashBlock &&
        uint256_eq(scan->phashBlock, &in->target_hash) &&
        utxo_ironwood_bootstrap_prepare(scan, in, session_reader,
            NULL, f, &slice) == IRONWOOD_BOOTSTRAP_ERROR) return IRONWOOD_BOOTSTRAP_ERROR;
    if (!sql(db, "BEGIN")) return IRONWOOD_BOOTSTRAP_ERROR;
    return utxo_ironwood_bootstrap_step(db, epoch, parent, old_parent, &slice, in, out);
}
static bool bootstrap_prefix(sqlite3 *db, struct session_fixture *f, uint64_t epoch,
                             int stop, struct ironwood_bootstrap_cursor *c)
{
    struct ironwood_bootstrap_cursor next = {0};
    f->missing = true; f->missing_height = stop;
    bool ok = true;
    for (int i = 0; ok && c->next_height < stop && i < 8; ++i) {
        enum ironwood_bootstrap_result r = test_bootstrap_step(db, epoch, &f->index[2], NULL, f, c, &next);
        ok = r == IRONWOOD_BOOTSTRAP_MORE && sql(db, "COMMIT");
        if (ok) *c = next;
    }
    f->missing = false;
    return ok && c->next_height == stop;
}
static bool bootstrap_finish(sqlite3 *db, struct session_fixture *f, uint64_t epoch,
    const struct block_index *parent, const struct block_index *old_parent,
    struct ironwood_bootstrap_cursor *c)
{
    struct ironwood_bootstrap_cursor next = {0};
    enum ironwood_bootstrap_result r = IRONWOOD_BOOTSTRAP_MORE;
    bool ok = true;
    for (int i = 0; ok && r == IRONWOOD_BOOTSTRAP_MORE && i < 16; ++i) {
        r = test_bootstrap_step(db, epoch, parent, old_parent, f, c, &next);
        ok = r != IRONWOOD_BOOTSTRAP_ERROR && sql(db, "COMMIT");
        if (ok) *c = next;
    }
    return ok && r == IRONWOOD_BOOTSTRAP_DONE;
}
static bool bootstrap_handoff(struct session_fixture *f, sqlite3 *db,
                              const struct ironwood_bootstrap_cursor *c)
{
    utxo_ironwood_session_reset();
    utxo_ironwood_bootstrap_publish_for_test(c);
    memset(f->reads, 0, sizeof f->reads);
    struct utxo_ironwood_pending pending;
    bool ok = sql(db, "BEGIN") && utxo_ironwood_session_prepare(db, &f->index[3],
        &f->bodies[3], session_reader, NULL, f, &pending) == UTXO_IRONWOOD_OK &&
        pending.checkpoint.count == 6 && f->reads[0] == 0 && f->reads[1] == 0 &&
        f->reads[2] == 0 && sql(db, "ROLLBACK");
    utxo_ironwood_bootstrap_shutdown();
    utxo_ironwood_session_reset();
    return ok;
}
static bool bootstrap_restart(struct session_fixture *f)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return false;
    struct ironwood_bootstrap_cursor c = {0};
    bool ok = bootstrap_prefix(db, f, 1, 1, &c);
    c = (struct ironwood_bootstrap_cursor){0};
    if (ok) ok = bootstrap_finish(db, f, progress_store_epoch(), &f->index[2], NULL, &c);
    ok = ok && c.next_height == 3 && c.frontier.count == 4;
    if (ok) ok = bootstrap_handoff(f, db, &c);
    if (!ok) (void)sql(db, "ROLLBACK");
    if (sqlite3_close(db) != SQLITE_OK) ok = false;
    return ok;
}
static bool alternate_branch_init(struct session_fixture *f)
{
    for (int i = 0; i < 2; ++i) {
        if (!block_clone(&f->alternate[i], &f->bodies[i + 1])) return false;
        struct block_index *prev = i ? &f->alt_index[0] : &f->index[0];
        f->alternate[i].header.hashPrevBlock = *prev->phashBlock;
        f->alternate[i].header.nTime += 1;
        block_get_hash(&f->alternate[i], &f->alt_index[i].hashBlock);
        f->alt_index[i].phashBlock = &f->alt_index[i].hashBlock;
        f->alt_index[i].pprev = prev; f->alt_index[i].nHeight = i + 1;
    }
    return true;
}
static bool bootstrap_retarget(struct session_fixture *f)
{
    sqlite3 *db = NULL;
    if (!alternate_branch_init(f) || sqlite3_open(":memory:", &db) != SQLITE_OK) return false;
    struct ironwood_bootstrap_cursor c = {0};
    bool ok = bootstrap_prefix(db, f, 3, 2, &c);
    c = (struct ironwood_bootstrap_cursor){0};
    if (ok) ok = bootstrap_finish(db, f, 4, &f->alt_index[1], &f->index[2], &c);
    ok = ok && uint256_eq(&c.last.block_hash, &f->alt_index[1].hashBlock) && c.frontier.count == 4;
    if (!ok) (void)sql(db, "ROLLBACK");
    if (sqlite3_close(db) != SQLITE_OK) ok = false;
    return ok;
}
static bool tamper_payload_with_digest(sqlite3 *db)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "SELECT block,parent,root,leaf_count,payload FROM ironwood_checkpoints WHERE height=1", -1, &s, NULL) != SQLITE_OK) return false;
    uint8_t bytes[120 + IRONWOOD_CHECKPOINT_MAX_BYTES] = {0}, digest[32];
    bool ok = sqlite3_step(s) == SQLITE_ROW && sqlite3_column_bytes(s, 0) == 32 &&
        sqlite3_column_bytes(s, 1) == 32 && sqlite3_column_bytes(s, 2) == 32 &&
        sqlite3_column_int64(s, 3) == 2 && sqlite3_column_bytes(s, 4) == 41; // raw-sql-ok:test-fixture
    if (ok) {
        zcl_write_u64_le(bytes, 1); zcl_write_u64_le(bytes + 8, 2);
        zcl_write_u64_le(bytes + 16, 41);
        for (int i = 0; i < 3; ++i) memcpy(bytes + 24 + i * 32, sqlite3_column_blob(s, i), 32);
        memcpy(bytes + 120, sqlite3_column_blob(s, 4), 41);
        memset(bytes + 129, 0, 32);
        zcl_sha3_256(bytes, 161, digest);
    }
    sqlite3_finalize(s); s = NULL;
    if (!ok || sqlite3_prepare_v2(db, "UPDATE ironwood_checkpoints SET payload=?,digest=? WHERE height=1", -1, &s, NULL) != SQLITE_OK) return false;
    ok = sqlite3_bind_blob(s, 1, bytes + 120, 41, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_bind_blob(s, 2, digest, 32, SQLITE_TRANSIENT) == SQLITE_OK && sqlite3_step(s) == SQLITE_DONE; // raw-sql-ok:test-fixture
    sqlite3_finalize(s); return ok;
}
static bool bootstrap_payload_corruption(struct session_fixture *f)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return false;
    struct ironwood_bootstrap_cursor c = {0}, next = {0};
    enum ironwood_bootstrap_result r = IRONWOOD_BOOTSTRAP_MORE;
    bool ok = bootstrap_prefix(db, f, 5, 2, &c);
    ok = ok && sql(db, "BEGIN") && tamper_payload_with_digest(db) && sql(db, "COMMIT");
    c = (struct ironwood_bootstrap_cursor){0};
    for (int i = 0; ok && r == IRONWOOD_BOOTSTRAP_MORE && i < 8; ++i) {
        r = test_bootstrap_step(db, 6, &f->index[2], NULL, f, &c, &next);
        if (r == IRONWOOD_BOOTSTRAP_ERROR) { ok = sql(db, "ROLLBACK"); break; }
        ok = sql(db, "COMMIT");
        if (ok) c = next;
    }
    ok = ok && r == IRONWOOD_BOOTSTRAP_ERROR;
    if (sqlite3_close(db) != SQLITE_OK) ok = false;
    return ok;
}
static bool table_exists(sqlite3 *db, const char *name);
static int reject_bootstrap_commit(void *unused)
{ (void)unused; return 1; }
static bool bootstrap_rollback_retry(struct session_fixture *f)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return false;
    struct ironwood_bootstrap_cursor c = {0}, staged = {0};
    enum ironwood_bootstrap_result r = test_bootstrap_step(db, 7, &f->index[2], NULL, f, &c, &staged);
    bool ok = r == IRONWOOD_BOOTSTRAP_MORE;
    sqlite3_commit_hook(db, reject_bootstrap_commit, NULL);
    ok = ok && !sql(db, "COMMIT");
    sqlite3_commit_hook(db, NULL, NULL);
    if (!sqlite3_get_autocommit(db)) ok = sql(db, "ROLLBACK") && ok;
    ok = ok && !table_exists(db, "ironwood_checkpoints");
    if (ok) {
        r = test_bootstrap_step(db, 7, &f->index[2], NULL, f, &c, &staged);
        ok = r == IRONWOOD_BOOTSTRAP_MORE && sql(db, "COMMIT") && staged.next_height == 0;
    }
    if (sqlite3_close(db) != SQLITE_OK) ok = false;
    return ok;
}
static bool bootstrap_marker_deleted(struct session_fixture *f)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return false;
    struct ironwood_bootstrap_cursor c = {0}, next = {0};
    enum ironwood_bootstrap_result r = test_bootstrap_step(db, 8, &f->index[2], NULL, f, &c, &next);
    bool ok = r == IRONWOOD_BOOTSTRAP_MORE && sql(db, "COMMIT");
    if (ok) {
        f->missing = true; f->missing_height = 1;
        c = next; r = test_bootstrap_step(db, 8, &f->index[2], NULL, f, &c, &next);
        ok = r == IRONWOOD_BOOTSTRAP_MORE && sql(db, "COMMIT");
    }
    f->missing = false;
    if (ok) ok = sql(db, "BEGIN; DELETE FROM repair_marker; COMMIT");
    if (ok) {
        c = next; r = test_bootstrap_step(db, 8, &f->index[2], NULL, f, &c, &next);
        ok = r == IRONWOOD_BOOTSTRAP_ERROR && sql(db, "ROLLBACK");
    }
    if (sqlite3_close(db) != SQLITE_OK) ok = false;
    return ok;
}
static bool readonly_refusal(struct session_fixture *f)
{
    struct utxo_ironwood_pending p, before;
    memset(&p, 0xa5, sizeof p); memcpy(&before, &p, sizeof p);
    if (!sql(f->db, "PRAGMA query_only=ON; BEGIN")) return false;
    enum utxo_ironwood_result r = session_prepare(f, 0, &p);
    bool ok = r == UTXO_IRONWOOD_LOCAL_ERROR && !memcmp(&p, &before, sizeof p);
    if (!sql(f->db, "ROLLBACK; PRAGMA query_only=OFF")) return false;
    utxo_ironwood_session_reset();
    return ok;
}
static bool genesis_cases(struct session_fixture *f)
{
    struct utxo_ironwood_pending p, before;
    if (!sql(f->db, "BEGIN")) return false;
    memset(&p, 0xa5, sizeof p); memcpy(&before, &p, sizeof p);
    struct transaction *tx = &f->bodies[0].vtx[0];
    tx->hash.data[0] ^= 1;
    enum utxo_ironwood_result r = session_prepare(f, 0, &p);
    tx->hash.data[0] ^= 1;
    if (r != UTXO_IRONWOOD_LOCAL_ERROR || memcmp(&p, &before, sizeof p)) return false;
    tx->ironwood_value_balance = 1;
    r = session_prepare(f, 0, &p);
    tx->ironwood_value_balance = 0;
    if (r != UTXO_IRONWOOD_LOCAL_ERROR || memcmp(&p, &before, sizeof p)) return false;
    struct tx_in *vin = tx->vin;
    tx->vin = NULL;
    r = session_prepare(f, 0, &p);
    tx->vin = vin;
    if (r != UTXO_IRONWOOD_LOCAL_ERROR || memcmp(&p, &before, sizeof p)) return false;
    if (session_prepare(f, 0, &p) != UTXO_IRONWOOD_OK || p.checkpoint.height != 0 ||
        p.checkpoint.count != 0 || !sql(f->db, "ROLLBACK")) return false;
    utxo_ironwood_session_reset();
    return true;
}
static bool rollback_first(struct session_fixture *f)
{
    struct utxo_ironwood_pending p;
    return sql(f->db, "BEGIN") && session_prepare(f, 1, &p) == UTXO_IRONWOOD_OK &&
        p.checkpoint.count == 2 && utxo_ironwood_session_publish(&p) && sql(f->db, "ROLLBACK");
}
static bool first_transaction(struct session_fixture *f)
{
    struct utxo_ironwood_pending p;
    if (!rollback_first(f)) return false;
    if (!sql(f->db, "BEGIN") || ironwood_checkpoint_probe(f->db) != IRONWOOD_CHECKPOINT_PROBE_ERROR ||
        session_prepare(f, 1, &p) != UTXO_IRONWOOD_OK || !utxo_ironwood_session_publish(&p) ||
        !sql(f->db, "COMMIT")) return false;
    if (!sql(f->db, "BEGIN") || session_prepare(f, 2, &p) != UTXO_IRONWOOD_OK ||
        p.checkpoint.count != 4 || !utxo_ironwood_session_publish(&p) || !sql(f->db, "COMMIT")) return false;
    return true;
}
static bool cold_replay_with(struct session_fixture *f, int expected_calls)
{
    utxo_ironwood_session_reset();
    memset(f->reads, 0, sizeof f->reads);
    if (!sql(f->db, "BEGIN")) return false;
    struct utxo_ironwood_pending p, before;
    memset(&p, 0xa5, sizeof p); memcpy(&before, &p, sizeof p);
    enum utxo_ironwood_result r = UTXO_IRONWOOD_HISTORY_INCOMPLETE;
    int calls = 0;
    while (r == UTXO_IRONWOOD_HISTORY_INCOMPLETE && calls++ < 8) {
        r = session_prepare(f, 3, &p);
        if (r != UTXO_IRONWOOD_OK && memcmp(&p, &before, sizeof p)) return false;
    }
    return r == UTXO_IRONWOOD_OK && calls == expected_calls && p.checkpoint.count == 6 &&
        f->reads[0] == 1 && f->reads[1] == 1 && f->reads[2] == 1 &&
        utxo_ironwood_session_publish(&p) && sql(f->db, "ROLLBACK");
}
static bool cold_replay_one_step(struct session_fixture *f)
{
    utxo_ironwood_session_test_step_budget(1);
    return cold_replay_with(f, 6);
}
/* Wall time is not under test in the unit cases: the real-node group
 * measures the default slice. These cases pin the slice open. */
static bool cold_replay_one_call(struct session_fixture *f)
{
    utxo_ironwood_session_test_step_budget(1024);
    utxo_ironwood_session_test_soft_slice_us(INT64_MAX);
    return cold_replay_with(f, 1);
}
static bool cold_replay_zero_slice(struct session_fixture *f)
{
    utxo_ironwood_session_test_soft_slice_us(0);
    return cold_replay_with(f, 6);
}
static bool missing_body_waits(struct session_fixture *f)
{
    utxo_ironwood_session_test_soft_slice_us(INT64_MAX);
    utxo_ironwood_session_test_step_budget(1024);
    utxo_ironwood_session_reset();
    memset(f->reads, 0, sizeof f->reads);
    if (!sql(f->db, "BEGIN")) return false;
    struct utxo_ironwood_pending p, before;
    memset(&p, 0xa5, sizeof p); memcpy(&before, &p, sizeof p);
    f->missing = true; f->missing_height = 2;
    if (session_prepare(f, 3, &p) != UTXO_IRONWOOD_HISTORY_INCOMPLETE ||
        memcmp(&p, &before, sizeof p)) return false;
    f->missing = false;
    /* The reader counts the refused read: height 2 is tried once while
     * missing, then read once. Heights 0 and 1 are not read again. */
    bool ok = session_prepare(f, 3, &p) == UTXO_IRONWOOD_OK &&
        f->reads[0] == 1 && f->reads[1] == 1 && f->reads[2] == 2 &&
        utxo_ironwood_session_publish(&p) && sql(f->db, "ROLLBACK");
    /* later cases must read every body */
    f->missing = false;
    return ok;
}
static bool table_exists(sqlite3 *db, const char *name)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", -1, &s, NULL) != SQLITE_OK) return false;
    bool found = sqlite3_bind_text(s, 1, name, -1, SQLITE_STATIC) == SQLITE_OK &&
        sqlite3_step(s) == SQLITE_ROW; // raw-sql-ok:test-fixture
    sqlite3_finalize(s);
    return found;
}
static bool partial_empty_refused(struct session_fixture *f)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return false;
    bool ok = sql(db, "BEGIN; CREATE TABLE ironwood_checkpoint_state(id INTEGER PRIMARY KEY,tip INTEGER,generation INTEGER)");
    struct utxo_ironwood_pending p, before;
    memset(&p, 0xa5, sizeof p); memcpy(&before, &p, sizeof p);
    utxo_ironwood_session_reset();
    if (ok) ok = utxo_ironwood_session_prepare(db, &f->index[0], &f->bodies[0],
        session_reader, NULL, f, &p) == UTXO_IRONWOOD_LOCAL_ERROR &&
        !memcmp(&p, &before, sizeof p) && !table_exists(db, "ironwood_checkpoints");
    utxo_ironwood_session_reset();
    if (!sql(db, "ROLLBACK") || sqlite3_close(db) != SQLITE_OK) ok = false;
    return ok;
}
static bool four_checkpoint_rows(sqlite3 *db)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "SELECT count(*) FROM ironwood_checkpoints", -1, &s, NULL) != SQLITE_OK) return false;
    bool ok = sqlite3_step(s) == SQLITE_ROW && sqlite3_column_int(s, 0) == 4; // raw-sql-ok:test-fixture
    sqlite3_finalize(s);
    return ok;
}
static bool partial_populated_refused(struct session_fixture *f)
{
    utxo_ironwood_session_reset();
    if (!sql(f->db, "BEGIN; DROP TABLE ironwood_checkpoint_state")) return false;
    struct utxo_ironwood_pending p, before;
    memset(&p, 0xa5, sizeof p); memcpy(&before, &p, sizeof p);
    bool ok = session_prepare(f, 3, &p) == UTXO_IRONWOOD_LOCAL_ERROR &&
        !memcmp(&p, &before, sizeof p) && !table_exists(f->db, "ironwood_checkpoint_state") && four_checkpoint_rows(f->db);
    return sql(f->db, "ROLLBACK") && ok;
}
static bool corruption_refused(struct session_fixture *f)
{
    f->missing = false;
    utxo_ironwood_session_reset();
    if (!sql(f->db, "BEGIN") || !sql(f->db, "UPDATE ironwood_checkpoints SET root=zeroblob(32) WHERE height=1")) return false;
    struct utxo_ironwood_pending p, before;
    memset(&p, 0xa5, sizeof p); memcpy(&before, &p, sizeof p);
    bool refused = session_prepare(f, 3, &p) == UTXO_IRONWOOD_LOCAL_ERROR && !memcmp(&p, &before, sizeof p);
    return sql(f->db, "ROLLBACK") && refused;
}
/* A checkpoint the store wrote itself from a body that is not the canonical
 * block at its height passes the audit. Only the comparison of each replayed
 * step with its row refuses the canonical block above it with a local error;
 * without it the final preparation waits on the store tip instead. */
static bool foreign_row_refused(struct session_fixture *f)
{
    sqlite3 *db = NULL;
    struct block body = {0};
    struct block_index foreign = {0};
    struct uint256 hash = {0};
    struct utxo_ironwood_pending p = {0}, before;
    bool ok = block_clone(&body, &f->bodies[0]);
    if (ok && sqlite3_open(":memory:", &db) != SQLITE_OK) {
        /* A failed open can still leave a handle to close. */
        sqlite3_close(db);
        ok = false;
    }
    if (!ok) { block_free(&body); return false; }
    body.header.hashPrevBlock = f->index[0].hashBlock;
    block_get_hash(&body, &hash);
    foreign.hashBlock = hash; foreign.phashBlock = &foreign.hashBlock;
    foreign.pprev = &f->index[0]; foreign.nHeight = 1;
    ok = sql(db, "BEGIN") &&
        utxo_ironwood_session_prepare(db, &foreign, &body, session_reader, NULL, f, &p) == UTXO_IRONWOOD_OK &&
        p.checkpoint.count == 0 && utxo_ironwood_session_publish(&p) && sql(db, "COMMIT");
    utxo_ironwood_session_reset();
    memset(&p, 0xa5, sizeof p); memcpy(&before, &p, sizeof p);
    ok = ok && sql(db, "BEGIN") &&
        utxo_ironwood_session_prepare(db, &f->index[3], &f->bodies[3], session_reader, NULL, f, &p) == UTXO_IRONWOOD_LOCAL_ERROR &&
        !memcmp(&p, &before, sizeof p);
    if (!sqlite3_get_autocommit(db)) (void)sql(db, "ROLLBACK");
    utxo_ironwood_session_reset();
    if (sqlite3_close(db) != SQLITE_OK) ok = false;
    block_free(&body);
    return ok;
}
int test_utxo_apply_ironwood_session(void)
{
    struct session_fixture f = {0};
    const struct { const char *name; bool (*run)(struct session_fixture *); } cases[] = {
        {"fixture", fixture_init}, {"indexed history", indexed_history_cases}, {"bootstrap restart", bootstrap_restart}, {"bootstrap retarget", bootstrap_retarget}, {"bootstrap corrupted payload", bootstrap_payload_corruption}, {"bootstrap rollback retry", bootstrap_rollback_retry}, {"bootstrap marker deleted", bootstrap_marker_deleted}, {"pending bootstrap", pending_bootstrap_refusal}, {"readonly", readonly_refusal}, {"genesis", genesis_cases},
        {"first transaction", first_transaction},
        {"cold replay one step per call", cold_replay_one_step},
        {"cold replay one call", cold_replay_one_call},
        {"zero slice one step per call", cold_replay_zero_slice},
        {"missing body waits then resumes", missing_body_waits},
        {"partial empty", partial_empty_refused}, {"partial populated", partial_populated_refused},
        {"corruption", corruption_refused},
        {"foreign checkpoint row", foreign_row_refused},
    };
    bool ok = true;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        if (!cases[i].run(&f)) { fprintf(stderr, "Ironwood session: %s failed\n", cases[i].name); ok = false; break; }
    }
    utxo_ironwood_session_test_step_budget(1024);
    utxo_ironwood_session_test_soft_slice_us(100000);
    utxo_ironwood_session_reset();
    if (f.db && sqlite3_close(f.db) != SQLITE_OK) ok = false;
    for (size_t i = 0; i < 4; ++i) block_free(&f.bodies[i]);
    for (size_t i = 0; i < 2; ++i) block_free(&f.alternate[i]);
    chain_params_select(CHAIN_MAIN);
    return ok ? 0 : 1;
}
