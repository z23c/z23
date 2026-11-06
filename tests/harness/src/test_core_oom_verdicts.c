/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_core_oom_verdicts -- three consensus-path allocations whose failure
 * must stay a local error, never a verdict on the block.
 *
 *   1. block_header_get_hash serializes into a fixed stack buffer. With the
 *      stream allocators refused it still makes no allocation and gives the
 *      same hash as the canonical wire bytes; before, a refused stream_data
 *      hashed zero bytes and check_block scored an honest block "high-hash".
 *   2. update_coins_with_undo that cannot allocate an undo record or a coins
 *      vout array: connect_block ends with out-of-memory and DoS 0, not
 *      bad-txns-utxo-update-failed with DoS 100.
 *   3. connect_block whose block undo cannot be allocated: out-of-memory, not
 *      a false return with no reject state.
 *
 * The block-level cases run connect_block over {coinbase, spend of a seeded
 * coin} at a checkpoint-covered mainnet height, so scripts are not run. */

#include "test/test_core.h"

#include "bloom/merkle.h"
#include "chain/chainparams.h"
#include "chain/checkpoints.h"
#include "coins/coins.h"
#include "coins/coins_view.h"
#include "consensus/validation.h"
#include "core/arith_uint256.h"
#include "core/hash.h"
#include "core/serialize.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "util/safe_alloc.h"
#include "validation/connect_block.h"
#include "validation/contextual_check_tx.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#define COV_CHECK(name, expr) do {                       \
    printf("core_oom_verdicts: %s... ", (name));         \
    if ((expr)) printf("OK\n");                          \
    else { printf("FAIL\n"); failures++; }               \
} while (0)

#define COV_HEIGHT 100
#define COV_FUND_VALUE 50000
#define COV_SPEND_VALUE 40000
#define COV_WIRE_MAX (BLOCK_HEADER_SIZE + 3 + MAX_SOLUTION_SIZE)

/* ── 1. block_header_get_hash ──────────────────────────────────────── */

static void cov_header(struct block_header *h, size_t sol_size)
{
    block_header_init(h);
    h->nVersion = 4;
    memset(h->hashPrevBlock.data, 0x11, 32);
    memset(h->hashMerkleRoot.data, 0x22, 32);
    memset(h->hashFinalSaplingRoot.data, 0x33, 32);
    h->nTime = 1478403829u;
    h->nBits = 0x1f07ffffu;
    for (size_t i = 0; i < 32; i++)
        h->nNonce.data[i] = (unsigned char)(0x40 + i);
    h->nSolutionSize = sol_size;
    for (size_t i = 0; i < sol_size; i++)
        h->nSolution[i] = (unsigned char)(i * 7 + 3);
}

static void cov_le32(unsigned char *p, uint32_t v)
{
    for (int i = 0; i < 4; i++)
        p[i] = (unsigned char)(v >> (8 * i));
}

/* The canonical header wire bytes, laid out by hand. */
static size_t cov_wire(const struct block_header *h, unsigned char *buf)
{
    size_t n = 0;
    cov_le32(buf + n, (uint32_t)h->nVersion);
    n += 4;
    memcpy(buf + n, h->hashPrevBlock.data, 32);
    n += 32;
    memcpy(buf + n, h->hashMerkleRoot.data, 32);
    n += 32;
    memcpy(buf + n, h->hashFinalSaplingRoot.data, 32);
    n += 32;
    cov_le32(buf + n, h->nTime);
    n += 4;
    cov_le32(buf + n, h->nBits);
    n += 4;
    memcpy(buf + n, h->nNonce.data, 32);
    n += 32;
    if (h->nSolutionSize < 253) {
        buf[n++] = (unsigned char)h->nSolutionSize;
    } else {
        buf[n++] = 0xfd;
        buf[n++] = (unsigned char)(h->nSolutionSize & 0xff);
        buf[n++] = (unsigned char)(h->nSolutionSize >> 8);
    }
    memcpy(buf + n, h->nSolution, h->nSolutionSize);
    return n + h->nSolutionSize;
}

/* The hash through a growable heap stream, as the old helper made it. */
static bool cov_stream_hash(const struct block_header *h, struct uint256 *out)
{
    struct byte_stream s;
    stream_init(&s, 0);
    bool ok = block_header_serialize(h, &s) && !s.error;
    if (ok)
        hash256(s.data, s.size, out->data);
    stream_free(&s);
    return ok;
}

/* Hash with `label` armed; true when the label is still armed afterwards,
 * that is, when the hash made no allocation carrying it. */
static bool cov_hash_armed(const struct block_header *h, const char *label,
                           struct uint256 *out)
{
    zcl_alloc_fault_fail_next(label);
    block_header_get_hash(h, out);
    bool untouched = zcl_alloc_fault_armed_label() != NULL;
    zcl_alloc_fault_clear();
    return untouched;
}

static int cov_header_hash_size(size_t sol_size)
{
    int failures = 0;
    struct block_header h;
    cov_header(&h, sol_size);
    unsigned char wire[COV_WIRE_MAX];
    size_t len = cov_wire(&h, wire);
    struct uint256 want, stream_hash, got;
    hash256(wire, len, want.data);
    char name[128];

    snprintf(name, sizeof(name), "solution %zu: wire layout is %zu bytes",
             sol_size, len);
    COV_CHECK(name, len == BLOCK_HEADER_SIZE + (sol_size < 253 ? 1 : 3) +
                           sol_size);
    snprintf(name, sizeof(name), "solution %zu: stream path matches the wire",
             sol_size);
    COV_CHECK(name, cov_stream_hash(&h, &stream_hash) &&
                    uint256_eq(&stream_hash, &want));
    block_header_get_hash(&h, &got);
    snprintf(name, sizeof(name), "solution %zu: get_hash matches the wire",
             sol_size);
    COV_CHECK(name, uint256_eq(&got, &want));

    static const char *const labels[] = { "stream_data", "stream_grow" };
    for (size_t i = 0; i < sizeof(labels) / sizeof(labels[0]); i++) {
        memset(got.data, 0, sizeof(got.data));
        bool untouched = cov_hash_armed(&h, labels[i], &got);
        snprintf(name, sizeof(name), "solution %zu: %s refused, no allocation",
                 sol_size, labels[i]);
        COV_CHECK(name, untouched);
        snprintf(name, sizeof(name), "solution %zu: %s refused, same hash",
                 sol_size, labels[i]);
        COV_CHECK(name, uint256_eq(&got, &want));
    }
    return failures;
}

static int cov_header_hash(void)
{
    int failures = 0;
    /* No solution, regtest (48,5), post-Bubbles (192,7), Sprout (200,9). */
    static const size_t sizes[] = { 0, 36, 400, MAX_SOLUTION_SIZE };
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++)
        failures += cov_header_hash_size(sizes[i]);

    /* A header claiming more solution bytes than it can hold is refused, not
     * hashed: the answer is all ones, which meets no proof-of-work target. */
    struct block_header h;
    cov_header(&h, MAX_SOLUTION_SIZE);
    h.nSolutionSize = MAX_SOLUTION_SIZE + 1;
    struct uint256 got, ones;
    memset(ones.data, 0xff, sizeof(ones.data));
    block_header_get_hash(&h, &got);
    COV_CHECK("oversized solution: refused with an all-ones hash",
              uint256_eq(&got, &ones));
    return failures;
}

/* ── 2 and 3. connect_block ────────────────────────────────────────── */

static const uint8_t k_cov_true[] = { 0x51 };

static void cov_funding_txid(struct uint256 *h)
{
    memset(h->data, 0x5a, sizeof(h->data));
}

static bool cov_txs_build(struct block *blk)
{
    struct transaction *cb = &blk->vtx[0];
    struct transaction *sp = &blk->vtx[1];
    transaction_init(cb);
    transaction_init(sp);
    if (!transaction_alloc(cb, 1, 1) || !transaction_alloc(sp, 1, 1))
        return false;
    const uint8_t cb_sig[] = { 0x04, COV_HEIGHT, 0, 0, 0, 0x11 };
    outpoint_set_null(&cb->vin[0].prevout);
    script_set(&cb->vin[0].script_sig, cb_sig, sizeof(cb_sig));
    cb->vin[0].sequence = UINT32_MAX;
    cb->vout[0].value = 1000;
    script_set(&cb->vout[0].script_pub_key, k_cov_true, sizeof(k_cov_true));
    const uint8_t unlock[] = { 0x01, 0x07 };
    cov_funding_txid(&sp->vin[0].prevout.hash);
    sp->vin[0].prevout.n = 0;
    script_set(&sp->vin[0].script_sig, unlock, sizeof(unlock));
    sp->vin[0].sequence = UINT32_MAX;
    sp->vout[0].value = COV_SPEND_VALUE;
    script_set(&sp->vout[0].script_pub_key, k_cov_true, sizeof(k_cov_true));
    transaction_compute_hash(cb);
    transaction_compute_hash(sp);
    return true;
}

static bool cov_block_build(struct block *blk)
{
    block_init(blk);
    blk->vtx = zcl_calloc(2, sizeof(*blk->vtx), "cov_vtx");
    if (!blk->vtx)
        return false;
    blk->num_vtx = 2;
    if (!cov_txs_build(blk))
        return false;
    struct uint256 txids[2] = { blk->vtx[0].hash, blk->vtx[1].hash };
    blk->header.nVersion = 4;
    blk->header.hashMerkleRoot = compute_merkle_root(txids, 2);
    memset(blk->header.hashPrevBlock.data, 0x33, 32);
    return true;
}

static bool cov_seed_funding(struct coins_view_cache *view)
{
    struct uint256 fund;
    cov_funding_txid(&fund);
    struct coins_cache_entry *e = coins_view_cache_modify_new(view, &fund);
    if (!e || !coins_alloc(&e->coins, 1))
        return false;
    e->coins.height = 1;
    e->coins.version = 1;
    e->coins.is_coinbase = false;
    e->coins.vout[0].value = COV_FUND_VALUE;
    script_set(&e->coins.vout[0].script_pub_key, k_cov_true,
               sizeof(k_cov_true));
    e->flags = COINS_CACHE_DIRTY;
    return true;
}

struct cov_result {
    bool built;
    bool ok;
    bool fired;
    bool error;
    bool invalid;
    int dos;
    char reason[256];
};

/* connect_block over the fixture block with the nth `label` allocation
 * refused (none when label is NULL). */
static void cov_connect(const struct block *blk, const char *label,
                        unsigned nth, struct cov_result *r)
{
    memset(r, 0, sizeof(*r));
    struct checkpoint_entry cp_entry;
    memset(&cp_entry, 0, sizeof(cp_entry));
    cp_entry.height = COV_HEIGHT;
    memset(cp_entry.hash.data, 0x01, 32);
    struct chain_params params = *chain_params_get();
    params.checkpointData.entries = &cp_entry;
    params.checkpointData.nEntries = 1;

    struct uint256 prev_hash = blk->header.hashPrevBlock, block_hash;
    block_header_get_hash(&blk->header, &block_hash);
    struct block_index pprev, pindex;
    block_index_init(&pprev);
    pprev.nHeight = COV_HEIGHT - 1;
    pprev.phashBlock = &prev_hash;
    arith_uint256_set_u64(&pprev.nChainWork, (uint64_t)COV_HEIGHT);
    block_index_init(&pindex);
    pindex.nHeight = COV_HEIGHT;
    pindex.phashBlock = &block_hash;
    pindex.pprev = &pprev;

    struct coins_view null_view;
    memset(&null_view, 0, sizeof(null_view));
    struct coins_view_cache view;
    coins_view_cache_init(&view, &null_view);
    coins_view_cache_set_best_block(&view, &prev_hash);
    r->built = cov_seed_funding(&view);
    if (r->built) {
        struct validation_state vs;
        validation_state_init(&vs);
        if (label)
            zcl_alloc_fault_fail_nth(label, nth);
        r->ok = connect_block(blk, &vs, &pindex, &view, &params, false);
        r->fired = label && zcl_alloc_fault_armed_label() == NULL;
        zcl_alloc_fault_clear();
        r->error = validation_state_is_error(&vs);
        r->invalid = validation_state_is_invalid(&vs);
        r->dos = vs.dos;
        snprintf(r->reason, sizeof(r->reason), "%s", vs.reject_reason);
    }
    coins_view_cache_free(&view);
    printf("core_oom_verdicts: connect %s#%u fired=%d ok=%d error=%d "
           "invalid=%d dos=%d reason=%s\n", label ? label : "-", nth,
           (int)r->fired, (int)r->ok, (int)r->error, (int)r->invalid, r->dos,
           r->reason);
}

static bool cov_is_local_oom(const struct cov_result *r)
{
    return r->built && !r->ok && r->error && !r->invalid && r->dos == 0 &&
           strcmp(r->reason, "out-of-memory") == 0;
}

static int cov_connect_cases(const struct block *blk)
{
    int failures = 0;
    struct cov_result r;
    cov_connect(blk, NULL, 0, &r);
    COV_CHECK("connect: the fixture block connects", r.built && r.ok);

    /* The undo record update_coins_with_undo allocates for the spend. */
    cov_connect(blk, "tx_undo_prevout", 1, &r);
    COV_CHECK("update_coins: tx_undo_prevout refused", r.fired);
    COV_CHECK("update_coins: tx undo out of memory is not a verdict",
              cov_is_local_oom(&r));

    /* The block undo connect_block allocates before any tx. */
    cov_connect(blk, "block_undo_txs", 1, &r);
    COV_CHECK("prepare_undo: block_undo_txs refused", r.fired);
    COV_CHECK("prepare_undo: block undo out of memory is not a verdict",
              cov_is_local_oom(&r));

    /* Every coins vout array connect_block allocates, refused in turn. The
     * ones update_coins_with_undo makes for each tx's new outputs were booked
     * bad-txns-utxo-update-failed. */
    unsigned fired = 0;
    for (unsigned n = 1; n <= 16; n++) {
        cov_connect(blk, "coins_vout", n, &r);
        if (!r.fired)
            break;
        fired++;
        char name[96];
        snprintf(name, sizeof(name), "coins_vout #%u: connects or is a local "
                 "out of memory", n);
        COV_CHECK(name, (r.built && r.ok) || cov_is_local_oom(&r));
    }
    COV_CHECK("coins_vout: both new-output arrays were refused", fired >= 2);
    return failures;
}

int test_core_oom_verdicts(void);
int test_core_oom_verdicts(void)
{
    printf("\n=== core_oom_verdicts: a local out-of-memory is no verdict ===\n");
    int failures = cov_header_hash();

    int deferred = atomic_load(&g_deferred_proof_validation_below_height);
    atomic_store(&g_deferred_proof_validation_below_height, -1);
    struct block blk;
    if (!cov_block_build(&blk)) {
        printf("core_oom_verdicts: fixture block build FAIL\n");
        failures++;
    } else {
        failures += cov_connect_cases(&blk);
    }
    block_free(&blk);
    atomic_store(&g_deferred_proof_validation_below_height, deferred);

    printf("=== core_oom_verdicts: %d failures ===\n", failures);
    return failures;
}
