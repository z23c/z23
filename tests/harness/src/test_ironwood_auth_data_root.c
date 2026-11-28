/* purpose: Check ZIP 244 authorization roots over real Ironwood wire fixtures. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_auth_data_root.h"
#include "primitives/block.h"
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
    bool ok = legacy_version_boundary() && shapes(&b) && negative_cases(&b) &&
              widest_tree() && aggregate_limit(&tx[1]);
    b.num_vtx = 2;
    tx[1].v6_wire.data[tx[1].v6_wire.size - 1] ^= 1;
    ok = ok && root_is(&b, "5f0b954f48e80f67b2a7739d1c5ec001735985a6b0a8bd7b7b58c072c87a2b5c");
    transaction_free(&tx[1]);
    transaction_free(&tx[2]);
    return !ok;
}
