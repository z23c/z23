/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * A compact block with several prefilled transactions. The struct holds each
 * one's absolute position and only the wire is differential, so what our
 * encoder sends comes back with every transaction in its original slot and
 * re-encodes to the same bytes. A position that does not fit 16 bits, or a slot
 * named twice, is refused. Called from test_compact_blocks. */

#include "test/test_core.h"

#include "core/serialize.h"
#include "net/compact_blocks.h"
#include "primitives/block.h"
#include "primitives/transaction.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void cbp_header(struct block_header *h)
{
    block_header_init(h);
    h->nVersion = 4;
    h->nTime = 1700000500;
    h->nBits = 0x2100ffffu;
    h->nNonce.data[0] = 7;
}

/* A tx with lock_time naming its slot and a hash short ids can be built from. */
static void cbp_make_tx(struct transaction *tx, uint8_t hash_fill,
                        uint32_t lock_time)
{
    transaction_init(tx);
    tx->version = 4;
    tx->overwintered = true;
    tx->version_group_id = SAPLING_VERSION_GROUP_ID;
    tx->lock_time = lock_time;
    tx->num_vin = 1;
    tx->vin = calloc(1, sizeof(struct tx_in));
    tx_in_init(&tx->vin[0]);
    memset(tx->hash.data, hash_fill, 32);
}

static void cbp_block(struct block *blk, size_t n, uint8_t fill_base)
{
    block_init(blk);
    cbp_header(&blk->header);
    blk->num_vtx = n;
    blk->vtx = calloc(n, sizeof(struct transaction));
    for (size_t i = 0; i < n; i++)
        cbp_make_tx(&blk->vtx[i], (uint8_t)(fill_base + i), (uint32_t)(10 + i));
}

/* Prefill the txs of blk at positions[], short-id the rest. */
static bool cbp_cb_prefilled_at(struct compact_block_msg *cb,
                                const struct block *blk, uint64_t nonce,
                                const uint16_t *positions, size_t npos)
{
    compact_block_msg_init(cb);
    cb->header = blk->header;
    cb->nonce = nonce;
    compact_block_derive_key(&cb->header, nonce, cb->siphash_key);
    cb->num_short_txids = blk->num_vtx - npos;
    cb->short_txids = calloc(cb->num_short_txids + 1, SHORT_TXID_LEN);
    cb->prefilled = calloc(npos, sizeof(struct prefilled_tx));
    if (!cb->short_txids || !cb->prefilled)
        return false;
    cb->num_prefilled = npos;
    size_t next_pos = 0, next_id = 0;
    for (size_t i = 0; i < blk->num_vtx; i++) {
        if (next_pos < npos && positions[next_pos] == i) {
            cb->prefilled[next_pos].index = positions[next_pos];
            if (!transaction_copy(&cb->prefilled[next_pos].tx, &blk->vtx[i]))
                return false;
            next_pos++;
        } else {
            compact_block_short_txid(cb->siphash_key, &blk->vtx[i].hash,
                                     cb->short_txids +
                                         next_id++ * SHORT_TXID_LEN);
        }
    }
    return true;
}

/* Encode, decode, reconstruct with every tx of the block in the mempool, and
 * require each tx in its original slot and the wire to re-encode the same. */
static bool cbp_round_trip(size_t ntx, const uint16_t *positions, size_t npos)
{
    struct block blk;
    cbp_block(&blk, ntx, 0x90);
    struct compact_block_msg sent;
    struct compact_block_msg got;
    compact_block_msg_init(&got);
    struct byte_stream wire, again;
    stream_init(&wire, 1024);
    stream_init(&again, 1024);

    bool ok = cbp_cb_prefilled_at(&sent, &blk, 11, positions, npos) &&
              compact_block_msg_serialize(&sent, &wire);
    wire.read_pos = 0;
    ok = ok && compact_block_msg_deserialize(&got, &wire) &&
         compact_block_msg_serialize(&got, &again) &&
         again.size == wire.size &&
         memcmp(again.data, wire.data, wire.size) == 0;

    struct block out;
    block_init(&out);
    uint64_t *missing = NULL;
    size_t nmiss = 0;
    ok = ok && compact_block_reconstruct(&got, blk.vtx, ntx, NULL, 0, &out,
                                         &missing, &nmiss) &&
         nmiss == 0 && out.num_vtx == ntx;
    for (size_t i = 0; ok && i < ntx; i++)
        ok = out.vtx[i].lock_time == blk.vtx[i].lock_time;

    free(missing);
    block_free(&out);
    compact_block_msg_free(&got);
    compact_block_msg_free(&sent);
    stream_free(&wire);
    stream_free(&again);
    block_free(&blk);
    return ok;
}

static int cbp_test_round_trip(void)
{
    int failures = 0;
    printf("compact block with several prefilled txs round trips in place... ");

    static const struct {
        size_t ntx;
        size_t npos;
        uint16_t positions[3];
    } cases[] = {
        { 2, 2, { 0, 1 } },
        { 4, 2, { 0, 1 } },
        { 4, 2, { 0, 2 } },
        { 5, 2, { 1, 3 } },
        { 3, 3, { 0, 1, 2 } },
        { 5, 3, { 0, 1, 2 } },
        { 7, 3, { 0, 2, 5 } },
        { 8, 3, { 2, 3, 7 } },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        if (!cbp_round_trip(cases[i].ntx, cases[i].positions, cases[i].npos)) {
            printf("\n  case %zu (%zu txs, %zu prefilled) failed", i,
                   cases[i].ntx, cases[i].npos);
            failures++;
        }
    }

    printf(failures ? "FAIL\n" : "OK\n");
    return failures;
}

/* A position that does not fit the struct's 16 bits is refused on the wire
 * rather than wrapped onto an earlier slot. */
static int cbp_test_index_overflow(void)
{
    int failures = 0;
    printf("compact_block_msg_deserialize refuses a prefilled index past 16 bits... ");

    static const struct {
        size_t n;
        uint64_t diffs[2];
    } cases[] = {
        { 1, { 65536, 0 } },
        { 2, { 65535, 0 } },
        { 2, { 0, 65535 } },
    };
    struct block_header h;
    cbp_header(&h);
    struct transaction tx;
    cbp_make_tx(&tx, 0x7A, 5);
    for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        struct byte_stream s;
        stream_init(&s, 1024);
        block_header_serialize(&h, &s);
        stream_write_u64_le(&s, 12);
        stream_write_compact_size(&s, 0);
        stream_write_compact_size(&s, cases[c].n);
        for (size_t i = 0; i < cases[c].n; i++) {
            stream_write_compact_size(&s, cases[c].diffs[i]);
            transaction_serialize(&tx, &s);
        }
        s.read_pos = 0;
        struct compact_block_msg cb;
        bool decoded = compact_block_msg_deserialize(&cb, &s);
        if (decoded || cb.prefilled != NULL || cb.num_prefilled != 0) {
            printf("\n  case %zu decoded", c);
            failures++;
        }
        compact_block_msg_free(&cb);
        stream_free(&s);
    }
    transaction_free(&tx);

    printf(failures ? "FAIL\n" : "OK\n");
    return failures;
}

/* Two prefilled txs naming one slot: the second would overwrite the first. */
static int cbp_test_repeated_slot(void)
{
    int failures = 0;
    printf("compact_block_reconstruct refuses a repeated prefilled slot... ");

    struct block blk;
    cbp_block(&blk, 4, 0xA0);
    struct compact_block_msg cb;
    const uint16_t positions[2] = {1, 2};
    if (!cbp_cb_prefilled_at(&cb, &blk, 13, positions, 2))
        failures++;
    cb.prefilled[1].index = 1;

    struct block out;
    uint64_t *missing = NULL;
    size_t num_missing = 0;
    bool complete = compact_block_reconstruct(&cb, NULL, 0, NULL, 0, &out,
                                              &missing, &num_missing);
    if (complete || missing != NULL || num_missing != 0 || out.vtx != NULL ||
        out.num_vtx != 0)
        failures++;
    free(missing);
    block_free(&out);
    compact_block_msg_free(&cb);
    block_free(&blk);

    printf(failures ? "FAIL\n" : "OK\n");
    return failures;
}

int compact_blocks_prefilled_tests(void)
{
    int failures = 0;
    failures += cbp_test_round_trip();
    failures += cbp_test_index_overflow();
    failures += cbp_test_repeated_slot();
    return failures;
}
