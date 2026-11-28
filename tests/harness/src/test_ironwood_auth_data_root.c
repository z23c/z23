/* purpose: Check ZIP 244 authorization roots over real Ironwood wire fixtures. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_auth_data_root.h"
#include "primitives/block.h"
#include "bloom/merkle.h"
#include "core/hash.h"
#include "primitives/transaction_v6_digest.h"
#include "primitives/transaction_v6_decode.h"
#include "core/serialize.h"
#include "base/hex.h"
#include "validation/main_constants.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool load_tx(const char *path, struct transaction *tx)
{
    uint8_t bytes[10000];
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    size_t n = fread(bytes, 1, sizeof bytes, f);
    bool ok = n && feof(f) && !ferror(f);
    fclose(f);
    if (!ok) return false;
    struct byte_stream s;
    stream_init_from_data(&s, bytes, n);
    return transaction_v6_decode_prefix(tx, &s, n) && !stream_remaining(&s);
}

static bool root_is(const struct block *b, const char *hex)
{
    uint8_t root[32], expected[32];
    return zcl_hex_decode(hex, expected, sizeof expected) &&
        ironwood_auth_data_root(b, root).ok && !memcmp(root, expected, sizeof root);
}

static bool rejected(const struct block *b)
{
    uint8_t root[32], before[32];
    memset(root, 0x59, sizeof root);
    memcpy(before, root, sizeof root);
    return !ironwood_auth_data_root(b, root).ok && !memcmp(root, before, sizeof root);
}

/* Independent libsodium BLAKE2b oracle: ordered legacy, payment, withdrawal,
 * legacy, payment. The 3- and 5-leaf cases exercise zero padding. */
static bool shapes(struct block *b)
{
    static const char *expected[] = {
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "50b38ce9188fc866a5ef69d82b094596bf4f08ba333f03aadff692d13f6ae401",
        "3e10eabdb8400b88b2b1456f67bd486bf409441aa0aef590aa7473d9bb81139e",
        "e7883da31484d37fc209cfbd0b960a51547f21de00faaf552fa7e8c554e04de4",
        "0ed74daecfaa41334b79205dfccec60348c76884b0caf7d275485749d82c0f2b"
    };
    for (size_t i = 0; i < 5; ++i) {
        b->num_vtx = i + 1;
        if (!root_is(b, expected[i])) return false;
    }
    return true;
}

static bool widest_tree(void)
{
    struct transaction *tx = calloc(MAX_BLOCK_TRANSACTIONS, sizeof *tx);
    if (!tx) return false;
    for (size_t i = 0; i < MAX_BLOCK_TRANSACTIONS; ++i) tx[i].version = 1;
    struct block b = {.vtx = tx, .num_vtx = MAX_BLOCK_TRANSACTIONS};
    bool ok = root_is(&b, "d78b9d1efeaa30dcdfd4603228b9b7f2844ebbd979d4e8b858d6d8a285dad578");
    free(tx);
    return ok;
}

static bool aggregate_limit(const struct transaction *fixture)
{
    size_t count = MAX_BLOCK_SIZE / fixture->v6_wire.size + 1;
    struct transaction *tx = calloc(count, sizeof *tx);
    if (!tx) return false;
    for (size_t i = 0; i < count; ++i) tx[i] = *fixture;
    struct block b = {.vtx = tx, .num_vtx = count};
    bool ok = rejected(&b);
    free(tx);
    return ok;
}

static bool legacy_version_boundary(void)
{
    struct transaction tx = {.version = 4};
    struct block block = {.vtx = &tx, .num_vtx = 1};
    if (!root_is(&block, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"))
        return false;
    tx.version = 5;
    return rejected(&block);
}

static bool negative_cases(struct block *b)
{
    b->num_vtx = 0;
    if (!rejected(b)) return false;
    b->num_vtx = MAX_BLOCK_TRANSACTIONS + 1;
    if (!rejected(b)) return false;
    b->num_vtx = 2;
    size_t saved_size = b->vtx[1].v6_wire.size;
    b->vtx[1].v6_wire.size = MAX_BLOCK_SIZE + 1;
    bool oversized = rejected(b);
    b->vtx[1].v6_wire.size = saved_size;
    if (!oversized) return false;
    b->vtx[1].version = 5;
    if (!rejected(b)) return false;
    b->vtx[1].version = 6;
    b->vtx[1].hash.data[0] ^= 1;
    bool ok = rejected(b);
    b->vtx[1].hash.data[0] ^= 1;
    return ok;
}

/* Solved private rehearsal H1, retained blocks/001.hex SHA256
 * 741c44b0a1fab52180666e1da67281ed464bacbd776fdcea1cc1f97ab86ef259. */
static const char private_h1[] =
    "04000000e7788cffdd6cf6b0065d7a215345acb895173f319b1a5dd0b877b3420baaad0ee46d7568c0973fff0d0bb1da"
    "af9fcb4ff98e2f91d2e253e9e40d772d5a5223b9fbc2f4300c01f0b7820d00e3347c8da4ee614674376cbc45359daa54"
    "f9b5493e228f0a6b0f0f0f202c000000000000000000000000000000000000000000000000000000000000002407944d"
    "d071b5047b021d7d393dd3ca0d12d50ae08b53f6bfb2b97f296a1bde862f9e1589010400008085202f89010000000000"
    "000000000000000000000000000000000000000000000000000000ffffffff03510101ffffffff01807c814a00000000"
    "1976a91479b000887626b294a914501a4cd226b58b23598388ac00000000000000000000000000000000000000"
;

/* This tag is test data for a proposed commitment, not an activated rule. */
static bool proposed_commitment(struct transaction *coinbase, struct tx_out *output,
                                const uint8_t root[32])
{
    static const uint8_t tag[] = {0x5a,0x32,0x33,0x41,0x55,0x54,0x48};
    output->value = 0;
    script_init(&output->script_pub_key);
    return script_push_op(&output->script_pub_key, OP_RETURN) &&
        script_push_data(&output->script_pub_key, tag, sizeof tag) &&
        script_push_data(&output->script_pub_key, root, 32) &&
        transaction_hash_serialized(coinbase, &coinbase->hash);
}
static bool fixture_merkle(struct block *block, struct uint256 *out)
{
    struct uint256 hashes[2] = {block->vtx[0].hash, block->vtx[1].hash};
    uint8_t joined[64], independent[32];
    memcpy(joined, hashes[0].data, 32); memcpy(joined+32, hashes[1].data, 32);
    hash256(joined, sizeof joined, independent);
    *out = compute_merkle_root(hashes, 2);
    block->header.hashMerkleRoot = *out;
    return memcmp(independent, out->data, 32) == 0;
}
static bool fixture_digests(const struct transaction *tx, struct v6_digests *out)
{
    struct v6_wire_view view;
    return v6_core_parse(tx->v6_wire.data, tx->v6_wire.size, &view) == V6_WIRE_OK &&
        v6_wire_digests(&view, out);
}
struct commitment_observation {
    uint8_t first[32], after[32];
    struct uint256 first_txid, first_merkle;
    struct v6_digests before;
};
static bool commitment_initial(struct block *block, struct tx_out output[2],
                               struct commitment_observation *state)
{
    uint8_t unchanged[32];
    struct uint256 original_txid = block->vtx[0].hash, before_merkle;
    if (!fixture_digests(&block->vtx[1], &state->before) ||
        memcmp(state->before.txid,block->vtx[1].hash.data,32) ||
        !fixture_merkle(block,&before_merkle) ||
        !ironwood_auth_data_root(block,state->first).ok ||
        !root_is(block,"50b38ce9188fc866a5ef69d82b094596bf4f08ba333f03aadff692d13f6ae401")) return false;
    block->vtx[0].num_vout = 2;
    if (!proposed_commitment(&block->vtx[0], &output[1], state->first)) return false;
    state->first_txid = block->vtx[0].hash;
    return !uint256_eq(&original_txid,&state->first_txid) &&
        fixture_merkle(block,&state->first_merkle) &&
        !uint256_eq(&before_merkle,&state->first_merkle) &&
        ironwood_auth_data_root(block,unchanged).ok && !memcmp(state->first,unchanged,32);
}
static bool mutate_binding_signature(struct transaction *tx)
{
    struct v6_wire_view view;
    if (v6_core_parse(tx->v6_wire.data,tx->v6_wire.size,&view) != V6_WIRE_OK ||
        view.ironwood.binding_signature.size != 64 ||
        view.ironwood.binding_signature.data + 64 != tx->v6_wire.data + tx->v6_wire.size)
        return false;
    tx->v6_wire.data[tx->v6_wire.size-1] ^= 1;
    return true;
}
static bool commitment_mutation(struct block *block, const struct tx_out *output,
                                struct commitment_observation *state)
{
    struct uint256 after_merkle; struct v6_digests modified;
    if (!mutate_binding_signature(&block->vtx[1]) ||
        !fixture_digests(&block->vtx[1],&modified) ||
        memcmp(state->before.txid,modified.txid,32) ||
        !memcmp(state->before.auth,modified.auth,32) ||
        !ironwood_auth_data_root(block,state->after).ok ||
        !root_is(block,"5f0b954f48e80f67b2a7739d1c5ec001735985a6b0a8bd7b7b58c072c87a2b5c") ||
        !memcmp(state->first,state->after,32) || !fixture_merkle(block,&after_merkle) ||
        !uint256_eq(&state->first_merkle,&after_merkle)) return false;
    const struct script *script = &output->script_pub_key;
    return script->size >= 32 && !memcmp(script->data+script->size-32,state->first,32) &&
        memcmp(script->data+script->size-32,state->after,32);
}
static bool commitment_cycle(struct block *block, struct tx_out output[2])
{
    struct commitment_observation state = {0};
    if (!commitment_initial(block,output,&state) ||
        !commitment_mutation(block,&output[1],&state) ||
        !proposed_commitment(&block->vtx[0], &output[1], state.after)) return false;
    uint8_t unchanged[32]; struct uint256 changed_merkle;
    const struct script *script = &output[1].script_pub_key;
    return !uint256_eq(&state.first_txid,&block->vtx[0].hash) &&
        fixture_merkle(block,&changed_merkle) &&
        !uint256_eq(&state.first_merkle,&changed_merkle) &&
        script->size >= 32 && !memcmp(script->data+script->size-32,state.after,32) &&
        ironwood_auth_data_root(block,unchanged).ok && !memcmp(state.after,unchanged,32);
}
static bool proposed_commitment_cycle(const struct transaction *payment)
{
    uint8_t raw[(sizeof private_h1-1)/2], wire[10000];
    struct block original; block_init(&original);
    if (!zcl_hex_decode(private_h1, raw, sizeof raw)) return false;
    struct byte_stream stream; stream_init_from_data(&stream,raw,sizeof raw);
    bool ok = block_deserialize(&original,&stream) && !stream_remaining(&stream) &&
        original.num_vtx == 1 && original.vtx[0].version == 4 &&
        transaction_is_coinbase(&original.vtx[0]) && original.vtx[0].num_vout == 1 &&
        uint256_eq(&original.header.hashMerkleRoot,&original.vtx[0].hash) &&
        payment->v6_wire.size <= sizeof wire;
    if (ok) {
        struct transaction tx[2] = {original.vtx[0], *payment};
        struct tx_out output[2] = {0}; output[0] = tx[0].vout[0];
        memcpy(wire,payment->v6_wire.data,payment->v6_wire.size);
        tx[1].v6_wire.data = wire; tx[0].vout = output; tx[0].num_vout = 1;
        struct block block = {.header=original.header,.vtx=tx,.num_vtx=2};
        ok = commitment_cycle(&block,output);
    }
    block_free(&original);
    return ok;
}
int test_ironwood_auth_data_root(void)
{
    struct transaction tx[5] = {{0}};
    if (!load_tx("tests/fixtures/ironwood/postnu63-h1-reward-spend.v6", &tx[1])) return 1;
    if (!load_tx("tests/fixtures/ironwood/postnu63-h1-reward-withdrawal.v6", &tx[2])) {
        transaction_free(&tx[1]);
        return 1;
    }
    tx[0].version = 1;
    tx[3].version = 1;
    tx[4] = tx[1]; /* Borrow the fixture for this read-only fold. */
    struct block b = {.vtx = tx};
    bool ok = proposed_commitment_cycle(&tx[1]) && legacy_version_boundary() && shapes(&b) && negative_cases(&b) &&
              widest_tree() && aggregate_limit(&tx[1]);
    b.num_vtx = 2;
    tx[1].v6_wire.data[tx[1].v6_wire.size - 1] ^= 1;
    ok = ok && root_is(&b, "5f0b954f48e80f67b2a7739d1c5ec001735985a6b0a8bd7b7b58c072c87a2b5c");
    transaction_free(&tx[1]);
    transaction_free(&tx[2]);
    return !ok;
}
