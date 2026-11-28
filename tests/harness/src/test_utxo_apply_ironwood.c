/* purpose: Exercise branch-bound, write-free Ironwood checkpoint preparation. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "jobs/utxo_apply_ironwood.h"
#include "chain/chain.h"
#include "base/serialize_le.h"
#include "primitives/block.h"
#include "primitives/transaction_v6_wire.h"
#include "services/ironwood_note_frontier.h"
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

struct ironwood_fixture {
    sqlite3 *db;
    struct ironwood_checkpoint_session session;
    struct block_index h0, h1, h2;
    struct block payment, withdrawal;
    struct transaction pay_tx, withdrawal_tx;
    struct utxo_ironwood_parent parent;
    uint8_t params[IRONWOOD_MERKLE_PARAMETERS_SIZE];
    uint8_t pay_wire[9313], withdrawal_wire[9200];
};
static bool read_fixture(const char *path, uint8_t *out, size_t size)
{
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    bool ok = fread(out, 1, size, f) == size && fgetc(f) == EOF && !ferror(f);
    return fclose(f) == 0 && ok;
}
static void index_block(struct block *block, struct block_index *bi, struct block_index *prev)
{
    bi->nHeight = prev->nHeight + 1;
    bi->pprev = prev;
    block->header.hashPrevBlock = *prev->phashBlock;
    block_header_get_hash(&block->header, &bi->hashBlock);
    bi->phashBlock = &bi->hashBlock;
}
static bool fixture_transaction(struct transaction *tx, uint8_t *wire, size_t size)
{
    struct v6_wire_view view;
    if (v6_core_parse(wire, size, &view) != V6_WIRE_OK) return false;
    tx->overwintered = true; tx->version = IRONWOOD_TX_VERSION;
    tx->version_group_id = IRONWOOD_VERSION_GROUP_ID;
    tx->v6_wire.data = wire; tx->v6_wire.size = size;
    tx->lock_time = zcl_read_u32_le(view.header.data + 12);
    tx->expiry_height = zcl_read_u32_le(view.header.data + 16);
    tx->num_vin = view.inputs; tx->num_vout = view.outputs;
    tx->num_shielded_spend = view.sapling_spends.count;
    tx->num_shielded_output = view.sapling_outputs.count;
    return true;
}
static bool fixture_init(struct ironwood_fixture *f)
{
    memset(f, 0, sizeof *f);
    if (!read_fixture("engine/services/resources/ironwood/sinsemilla-merkle-parameters.bin", f->params, sizeof f->params) ||
        !read_fixture("tests/fixtures/ironwood/postnu63-h1-reward-spend.v6", f->pay_wire, sizeof f->pay_wire) ||
        !read_fixture("tests/fixtures/ironwood/postnu63-h1-reward-withdrawal.v6", f->withdrawal_wire, sizeof f->withdrawal_wire) ||
        sqlite3_open(":memory:", &f->db) != SQLITE_OK) return false;
    struct ironwood_note_frontier empty = {0};
    if (!ironwood_note_frontier_extend(&empty, NULL, 0, f->params, sizeof f->params, f->parent.root).ok ||
        sqlite3_exec(f->db, "BEGIN", NULL, NULL, NULL) != SQLITE_OK ||
        !ironwood_checkpoint_ensure_schema(f->db)) return false;
    uint8_t genesis_parent[32] = {0};
    f->h0.hashBlock.data[0] = 1;
    f->h0.phashBlock = &f->h0.hashBlock;
    if (!ironwood_checkpoint_begin_replay(f->db, genesis_parent, f->parent.root) ||
        !ironwood_checkpoint_audit(f->db, &f->session) ||
        !ironwood_checkpoint_append(&f->session, 0, f->h0.hashBlock.data, genesis_parent,
            f->parent.root, 0, NULL, 0)) return false;
    f->payment.vtx = &f->pay_tx; f->payment.num_vtx = 1;
    if (!fixture_transaction(&f->pay_tx, f->pay_wire, sizeof f->pay_wire)) return false;
    index_block(&f->payment, &f->h1, &f->h0);
    f->withdrawal.vtx = &f->withdrawal_tx; f->withdrawal.num_vtx = 1;
    if (!fixture_transaction(&f->withdrawal_tx, f->withdrawal_wire, sizeof f->withdrawal_wire)) return false;
    index_block(&f->withdrawal, &f->h2, &f->h1);
    return true;
}
static enum utxo_ironwood_result prepare(struct ironwood_fixture *f, struct block_index *bi,
    struct block *block, struct utxo_ironwood_pending *out)
{
    int before = sqlite3_total_changes(f->db);
    enum utxo_ironwood_result r = utxo_apply_ironwood_prepare(&f->session, bi, block,
        &f->parent, f->params, sizeof f->params, out);
    return sqlite3_total_changes(f->db) == before ? r : UTXO_IRONWOOD_LOCAL_ERROR;
}
static bool initial_cases(struct ironwood_fixture *f)
{
    struct utxo_ironwood_pending p, saved;
    struct transaction transactions[2] = {f->pay_tx, f->withdrawal_tx};
    memset(&p, 0xa5, sizeof p); memcpy(&saved, &p, sizeof p);
    f->payment.vtx = transactions; f->payment.num_vtx = 2;
    enum utxo_ironwood_result r = prepare(f, &f->h1, &f->payment, &p);
    f->payment.vtx = &f->pay_tx; f->payment.num_vtx = 1;
    if (r != UTXO_IRONWOOD_ANCHOR_MISSING || memcmp(&p, &saved, sizeof p)) return false;
    struct transaction legacy = {.version = 1};
    f->payment.vtx = &legacy;
    r = prepare(f, &f->h1, &f->payment, &p);
    f->payment.vtx = &f->pay_tx;
    if (r != UTXO_IRONWOOD_OK || p.changed || p.checkpoint.payload_size ||
        p.checkpoint.count != 0 || memcmp(p.checkpoint.root, f->parent.root, 32)) return false;
    f->pay_tx.overwintered = false;
    r = prepare(f, &f->h1, &f->payment, &p);
    f->pay_tx.overwintered = true;
    return r == UTXO_IRONWOOD_MALFORMED;
}
static bool payment_and_withdrawal(struct ironwood_fixture *f)
{
    struct utxo_ironwood_pending p;
    struct v6_wire_view w;
    if (prepare(f, &f->h1, &f->payment, &p) != UTXO_IRONWOOD_OK || !p.changed || p.checkpoint.count != 2 ||
        v6_core_parse(f->withdrawal_wire, sizeof f->withdrawal_wire, &w) != V6_WIRE_OK ||
        memcmp(p.checkpoint.root, w.ironwood.anchor.data, 32) ||
        !ironwood_checkpoint_append(&f->session, p.checkpoint.height, p.checkpoint.block_hash, p.parent_hash,
            p.checkpoint.root, p.checkpoint.count, p.checkpoint.payload, p.checkpoint.payload_size)) return false;
    memcpy(f->parent.root, p.checkpoint.root, 32); f->parent.count = p.checkpoint.count;
    return prepare(f, &f->h2, &f->withdrawal, &p) == UTXO_IRONWOOD_OK && p.changed && p.checkpoint.count == 4;
}
static bool refusals(struct ironwood_fixture *f)
{
    struct utxo_ironwood_pending p, saved;
    memset(&p, 0xa5, sizeof p); memcpy(&saved, &p, sizeof p);
    f->withdrawal_tx.v6_wire.size--;
    enum utxo_ironwood_result r = prepare(f, &f->h2, &f->withdrawal, &p);
    f->withdrawal_tx.v6_wire.size++;
    if (r != UTXO_IRONWOOD_MALFORMED || memcmp(&p, &saved, sizeof p)) return false;
    struct v6_wire_view v;
    if (v6_core_parse(f->withdrawal_wire, sizeof f->withdrawal_wire, &v) != V6_WIRE_OK || v.ironwood.anchor.size != 32) return false;
    size_t offset = (size_t)(v.ironwood.anchor.data - f->withdrawal_wire);
    f->withdrawal_wire[offset] ^= 1;
    r = prepare(f, &f->h2, &f->withdrawal, &p);
    f->withdrawal_wire[offset] ^= 1;
    if (r != UTXO_IRONWOOD_ANCHOR_MISSING || memcmp(&p, &saved, sizeof p)) return false;
    f->parent.root[0] ^= 1;
    r = prepare(f, &f->h2, &f->withdrawal, &p);
    f->parent.root[0] ^= 1;
    return r == UTXO_IRONWOOD_HISTORY_INCOMPLETE && !memcmp(&p, &saved, sizeof p);
}
int test_utxo_apply_ironwood(void)
{
    struct ironwood_fixture f;
    bool ok = fixture_init(&f) && initial_cases(&f) && payment_and_withdrawal(&f) && refusals(&f);
    if (f.db && sqlite3_close(f.db) != SQLITE_OK) ok = false;
    return ok ? 0 : 1;
}
