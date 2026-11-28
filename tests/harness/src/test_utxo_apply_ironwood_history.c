/* purpose: Exercise atomic private Ironwood history reconstruction. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "jobs/utxo_apply_ironwood_history.h"
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
};
static bool history_reader(struct block *out, const struct block_index *bi,
                           const char *datadir, void *user)
{
    (void)datadir;
    struct history_fixture *f = user;
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

static bool history_positive(struct history_fixture *f)
{
    const struct block_index *slots[2] = {0};
    struct ironwood_history_cursor c;
    struct ironwood_history_event e;
    if (!utxo_ironwood_history_begin(&f->index[1], slots, 2, &c).ok ||
        !history_step_ok(&c, f, &e) || e.available ||
        !history_step_ok(&c, f, &e) || e.available ||
        !history_step_ok(&c, f, &e) || !e.available || e.height != 0 || e.count != 0)
        return false;
    f->missing = true;
    if (!history_check_failure(&c, f)) return false;
    f->missing = false;
    f->corrupt_tx = true;
    if (!history_check_failure(&c, f)) return false;
    f->corrupt_tx = false;
    f->corrupt_prev = true;
    if (!history_check_failure(&c, f)) return false;
    f->corrupt_prev = false;
    f->corrupt_merkle = true;
    if (!history_check_failure(&c, f)) return false;
    f->corrupt_merkle = false;
    f->oversized = true;
    if (!history_check_failure(&c, f)) return false;
    f->oversized = false;
    uint8_t expected[32];
    return history_step_ok(&c, f, &e) && e.available && e.height == 1 &&
        e.count == 2 && c.complete && zcl_hex_decode(
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

int test_utxo_apply_ironwood_history(void)
{
    struct history_fixture f = {0};
    bool setup = history_fixture_make(&f); bool positive = setup && history_positive(&f); bool negative = positive && history_wrong_genesis(&f); bool ok = negative && history_bad_merkle(&f); if (!ok) fprintf(stderr, "history setup=%d positive=%d negative=%d\n", setup, positive, negative);
    block_free(&f.bodies[0]);
    block_free(&f.bodies[1]);
    chain_params_select(CHAIN_MAIN);
    printf("Ironwood canonical history: %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
