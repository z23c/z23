/* purpose: Verify private Ironwood session bootstrap, replay and rollback. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "jobs/utxo_apply_ironwood_session.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "bloom/merkle.h"
#include "core/serialize.h"
#include "primitives/block.h"
#include "primitives/transaction_v6_decode.h"
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
};
static bool session_reader(struct block *out, const struct block_index *bi,
    const char *datadir, void *user)
{
    (void)datadir;
    struct session_fixture *f = user;
    if (bi->nHeight < 0 || bi->nHeight >= 4) return false;
    ++f->reads[bi->nHeight];
    if (!block_clone(out, &f->bodies[bi->nHeight])) return false;
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
    return sqlite3_open(":memory:", &f->db) == SQLITE_OK && ironwood_checkpoint_ensure_schema(f->db);
}
static bool sql(sqlite3 *db, const char *statement)
{ return sqlite3_exec(db, statement, NULL, NULL, NULL) == SQLITE_OK; }
static enum utxo_ironwood_result session_prepare(struct session_fixture *f, int height,
    struct utxo_ironwood_pending *pending)
{
    return utxo_ironwood_session_prepare(f->db, &f->index[height], &f->bodies[height],
        session_reader, NULL, f, pending);
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
    if (!sql(f->db, "BEGIN") || ironwood_checkpoint_probe(f->db) != IRONWOOD_CHECKPOINT_UNINITIALIZED ||
        session_prepare(f, 1, &p) != UTXO_IRONWOOD_OK || !utxo_ironwood_session_publish(&p) ||
        !sql(f->db, "COMMIT")) return false;
    if (!sql(f->db, "BEGIN") || session_prepare(f, 2, &p) != UTXO_IRONWOOD_OK ||
        p.checkpoint.count != 4 || !utxo_ironwood_session_publish(&p) || !sql(f->db, "COMMIT")) return false;
    return true;
}
static bool cold_replay(struct session_fixture *f)
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
    return r == UTXO_IRONWOOD_OK && calls == 6 && p.checkpoint.count == 6 &&
        f->reads[0] == 1 && f->reads[1] == 1 && f->reads[2] == 1 &&
        utxo_ironwood_session_publish(&p) && sql(f->db, "ROLLBACK");
}
static bool corruption_refused(struct session_fixture *f)
{
    utxo_ironwood_session_reset();
    if (!sql(f->db, "BEGIN") || !sql(f->db, "UPDATE ironwood_checkpoints SET root=zeroblob(32) WHERE height=1")) return false;
    struct utxo_ironwood_pending p, before;
    memset(&p, 0xa5, sizeof p); memcpy(&before, &p, sizeof p);
    bool refused = session_prepare(f, 3, &p) == UTXO_IRONWOOD_LOCAL_ERROR && !memcmp(&p, &before, sizeof p);
    return sql(f->db, "ROLLBACK") && refused;
}
int test_utxo_apply_ironwood_session(void)
{
    struct session_fixture f = {0};
    bool ok = fixture_init(&f) && genesis_cases(&f) && first_transaction(&f) && cold_replay(&f) && corruption_refused(&f);
    utxo_ironwood_session_reset();
    if (f.db && sqlite3_close(f.db) != SQLITE_OK) ok = false;
    for (size_t i = 0; i < 4; ++i) block_free(&f.bodies[i]);
    chain_params_select(CHAIN_MAIN);
    return ok ? 0 : 1;
}
