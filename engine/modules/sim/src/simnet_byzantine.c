/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "sim/simnet_byzantine.h"

#include "bloom/merkle.h"
#include "chain/chainparams.h"
#include "chain/pow.h"
#include "chain/subsidy.h"
#include "coins/coins_view.h"
#include "consensus/validation.h"
#include "core/amount.h"
#include "core/arith_uint256.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "validation/check_block.h"
#include "validation/connect_block.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SIM_BYZ_OWNER "simnet_byz"
#define SIM_BYZ_COINBASE_VALUE 1000000
#define SIM_BYZ_OVERSIZE_VTX ((size_t)MAX_BLOCK_SIZE + 1u)

struct simnet_byzantine_meta {
    enum simnet_byzantine_class kind;
    enum simnet_byzantine_tier tier;
    const char *name;
    const char *reason;
    enum blocker_class cls;
};

static const struct simnet_byzantine_meta g_meta[] = {
    { SIMNET_BYZ_BAD_MERKLE, SIMNET_BYZ_TIER_CONNECT_BLOCK,
      "bad_merkle", "bad-txnmrklroot", BLOCKER_PERMANENT },
    { SIMNET_BYZ_BAD_CB_AMOUNT, SIMNET_BYZ_TIER_CONNECT_BLOCK,
      "bad_cb_amount", "bad-cb-amount", BLOCKER_PERMANENT },
    { SIMNET_BYZ_BIP30_DUP_TXID, SIMNET_BYZ_TIER_CONNECT_BLOCK,
      "bip30_duplicate_txid", "bad-txns-BIP30", BLOCKER_PERMANENT },
    { SIMNET_BYZ_MISSING_SPEND, SIMNET_BYZ_TIER_CONNECT_BLOCK,
      "missing_spend", "bad-txns-inputs-missingorspent",
      BLOCKER_PERMANENT },
    { SIMNET_BYZ_IMMATURE_SPEND, SIMNET_BYZ_TIER_CONNECT_BLOCK,
      "immature_spend", "bad-txns-premature-spend-of-coinbase",
      BLOCKER_PERMANENT },
    { SIMNET_BYZ_NEGATIVE_OUTPUT, SIMNET_BYZ_TIER_CONNECT_BLOCK,
      "negative_output", "bad-txns-vout-negative", BLOCKER_PERMANENT },
    { SIMNET_BYZ_OVERFLOW_OUTPUT, SIMNET_BYZ_TIER_CONNECT_BLOCK,
      "overflow_output", "bad-txns-vout-toolarge", BLOCKER_PERMANENT },
    { SIMNET_BYZ_OVERSIZE_VTX, SIMNET_BYZ_TIER_CONNECT_BLOCK,
      "oversize_vtx", "bad-blk-length", BLOCKER_PERMANENT },
    { SIMNET_BYZ_INVALID_POW, SIMNET_BYZ_TIER_HEADER_ADMISSION,
      "invalid_pow", "invalid-solution", BLOCKER_PERMANENT },
    { SIMNET_BYZ_BAD_BITS, SIMNET_BYZ_TIER_HEADER_ADMISSION,
      "bad_bits", "bad-diffbits", BLOCKER_PERMANENT },
    { SIMNET_BYZ_BAD_TIMESTAMP, SIMNET_BYZ_TIER_HEADER_ADMISSION,
      "bad_timestamp", "time-too-old", BLOCKER_PERMANENT },
};

static const struct simnet_byzantine_meta *meta_for(
    enum simnet_byzantine_class kind)
{
    for (size_t i = 0; i < sizeof(g_meta) / sizeof(g_meta[0]); i++) {
        if (g_meta[i].kind == kind)
            return &g_meta[i];
    }
    return NULL;
}

const char *simnet_byzantine_class_name(enum simnet_byzantine_class kind)
{
    const struct simnet_byzantine_meta *m = meta_for(kind);
    return m ? m->name : "unknown";
}

enum simnet_byzantine_tier
simnet_byzantine_class_tier(enum simnet_byzantine_class kind)
{
    const struct simnet_byzantine_meta *m = meta_for(kind);
    return m ? m->tier : 0;
}

const char *simnet_byzantine_expected_reason(
    enum simnet_byzantine_class kind)
{
    const struct simnet_byzantine_meta *m = meta_for(kind);
    return m ? m->reason : "";
}

enum blocker_class simnet_byzantine_expected_blocker_class(
    enum simnet_byzantine_class kind)
{
    const struct simnet_byzantine_meta *m = meta_for(kind);
    return m ? m->cls : BLOCKER_TRANSIENT;
}

enum blocker_class simnet_byzantine_blocker_class_for_reason(
    const char *reject_reason)
{
    if (!reject_reason || !reject_reason[0])
        return BLOCKER_TRANSIENT;
    for (size_t i = 0; i < sizeof(g_meta) / sizeof(g_meta[0]); i++) {
        if (strcmp(g_meta[i].reason, reject_reason) == 0)
            return g_meta[i].cls;
    }
    return BLOCKER_TRANSIENT;
}

static bool make_coinbase(struct transaction *tx, int height, int64_t value)
{
    if (!tx)
        LOG_FAIL("simnet.byz", "NULL coinbase output");
    transaction_init(tx);
    if (!transaction_alloc(tx, 1, 1))
        LOG_FAIL("simnet.byz", "coinbase allocation failed");

    tx->version = 1;
    uint8_t sig[6] = {
        4,
        (uint8_t)(height & 0xff),
        (uint8_t)((height >> 8) & 0xff),
        (uint8_t)((height >> 16) & 0xff),
        (uint8_t)((height >> 24) & 0xff),
        0x11,
    };
    script_set(&tx->vin[0].script_sig, sig, sizeof(sig));
    uint256_set_null(&tx->vin[0].prevout.hash);
    tx->vin[0].prevout.n = UINT32_MAX;
    tx->vin[0].sequence = UINT32_MAX;
    tx->vout[0].value = value;
    uint8_t pk[] = { 0x76, 0xa9, 0x14 };
    script_set(&tx->vout[0].script_pub_key, pk, sizeof(pk));
    transaction_compute_hash(tx);
    return true;
}

static bool make_spend(struct transaction *tx, const struct uint256 *txid,
                       uint32_t n, int64_t value)
{
    if (!tx || !txid)
        LOG_FAIL("simnet.byz", "invalid spend builder input");
    transaction_init(tx);
    if (!transaction_alloc(tx, 1, 1))
        LOG_FAIL("simnet.byz", "spend allocation failed");

    tx->version = 1;
    tx->vin[0].prevout.hash = *txid;
    tx->vin[0].prevout.n = n;
    uint8_t sig[] = { 0x00, 0x00 };
    script_set(&tx->vin[0].script_sig, sig, sizeof(sig));
    tx->vin[0].sequence = UINT32_MAX;
    tx->vout[0].value = value;
    uint8_t pk[] = { 0x76, 0xa9, 0x14 };
    script_set(&tx->vout[0].script_pub_key, pk, sizeof(pk));
    transaction_compute_hash(tx);
    return true;
}

static bool finish_block(struct simnet *sim,
                         struct simnet_byzantine_block_case *out,
                         enum simnet_byzantine_class kind,
                         struct transaction *txs, size_t ntx)
{
    if (!sim || !sim->initialized || !out || !txs || ntx == 0)
        LOG_FAIL("simnet.byz", "invalid finish_block request");

    memset(out, 0, sizeof(*out));
    out->kind = kind;
    out->height = sim->tip_height + 1;
    block_init(&out->block);
    out->block.num_vtx = ntx;
    out->block.vtx =
        zcl_calloc(ntx, sizeof(*out->block.vtx), "simnet_byz_vtx");
    if (!out->block.vtx)
        LOG_FAIL("simnet.byz", "OOM allocating %zu vtx", ntx);

    struct uint256 *txids =
        zcl_malloc(ntx * sizeof(*txids), "simnet_byz_txids");
    if (!txids) {
        block_free(&out->block);
        LOG_FAIL("simnet.byz", "OOM allocating %zu txids", ntx);
    }

    for (size_t i = 0; i < ntx; i++) {
        out->block.vtx[i] = txs[i];
        txids[i] = txs[i].hash;
        transaction_init(&txs[i]);
    }
    out->block.header.nVersion = 4;
    out->block.header.hashPrevBlock = sim->tip.hashBlock;
    out->block.header.hashMerkleRoot = compute_merkle_root(txids, ntx);
    out->block.header.nTime = (uint32_t)out->height;
    free(txids);
    return true;
}

static bool build_coinbase_only(struct simnet *sim,
                                struct simnet_byzantine_block_case *out,
                                enum simnet_byzantine_class kind,
                                int cb_height,
                                int64_t value)
{
    struct transaction cb;
    if (!make_coinbase(&cb, cb_height, value))
        return false;
    if (!finish_block(sim, out, kind, &cb, 1)) {
        transaction_free(&cb);
        return false;
    }
    return true;
}

bool simnet_byzantine_build_bad_merkle(
    struct simnet *sim, struct simnet_byzantine_block_case *out)
{
    if (!build_coinbase_only(sim, out, SIMNET_BYZ_BAD_MERKLE,
                             sim->tip_height + 1, SIM_BYZ_COINBASE_VALUE))
        return false;
    out->block.header.hashMerkleRoot.data[0] ^= 0x80u;
    return true;
}

bool simnet_byzantine_build_bad_cb_amount(
    struct simnet *sim, struct simnet_byzantine_block_case *out)
{
    int height = sim->tip_height + 1;
    int64_t subsidy = get_block_subsidy(height, &sim->params.consensus);
    if (subsidy < 0 || subsidy == INT64_MAX)
        LOG_FAIL("simnet.byz", "unexpected subsidy at h=%d", height);
    return build_coinbase_only(sim, out, SIMNET_BYZ_BAD_CB_AMOUNT, height,
                               subsidy + 1);
}

bool simnet_byzantine_build_bip30_duplicate_txid(
    struct simnet *sim, struct simnet_byzantine_block_case *out)
{
    struct uint256 ignored;
    if (!simnet_mint_coinbase(sim, &ignored))
        return false;
    return build_coinbase_only(sim, out, SIMNET_BYZ_BIP30_DUP_TXID,
                               sim->tip_height, SIM_BYZ_COINBASE_VALUE);
}

bool simnet_byzantine_build_missing_spend(
    struct simnet *sim, struct simnet_byzantine_block_case *out)
{
    int height = sim->tip_height + 1;
    struct transaction txs[2];
    if (!make_coinbase(&txs[0], height, SIM_BYZ_COINBASE_VALUE))
        return false;
    struct uint256 absent;
    memset(absent.data, 0x42, sizeof(absent.data));
    if (!make_spend(&txs[1], &absent, 0, 1)) {
        transaction_free(&txs[0]);
        return false;
    }
    if (!finish_block(sim, out, SIMNET_BYZ_MISSING_SPEND, txs, 2)) {
        transaction_free(&txs[0]);
        transaction_free(&txs[1]);
        return false;
    }
    return true;
}

bool simnet_byzantine_build_immature_spend(
    struct simnet *sim, struct simnet_byzantine_block_case *out)
{
    struct uint256 cb_txid;
    if (!simnet_mint_coinbase(sim, &cb_txid))
        return false;
    int height = sim->tip_height + 1;
    struct transaction txs[2];
    if (!make_coinbase(&txs[0], height, SIM_BYZ_COINBASE_VALUE))
        return false;
    if (!make_spend(&txs[1], &cb_txid, 0, 1)) {
        transaction_free(&txs[0]);
        return false;
    }
    if (!finish_block(sim, out, SIMNET_BYZ_IMMATURE_SPEND, txs, 2)) {
        transaction_free(&txs[0]);
        transaction_free(&txs[1]);
        return false;
    }
    return true;
}

bool simnet_byzantine_build_negative_output(
    struct simnet *sim, struct simnet_byzantine_block_case *out)
{
    return build_coinbase_only(sim, out, SIMNET_BYZ_NEGATIVE_OUTPUT,
                               sim->tip_height + 1, -1);
}

bool simnet_byzantine_build_overflow_output(
    struct simnet *sim, struct simnet_byzantine_block_case *out)
{
    return build_coinbase_only(sim, out, SIMNET_BYZ_OVERFLOW_OUTPUT,
                               sim->tip_height + 1, MAX_MONEY + 1);
}

bool simnet_byzantine_build_oversize_vtx(
    struct simnet *sim, struct simnet_byzantine_block_case *out)
{
    if (!sim || !sim->initialized || !out)
        LOG_FAIL("simnet.byz", "invalid oversize builder request");

    memset(out, 0, sizeof(*out));
    out->kind = SIMNET_BYZ_OVERSIZE_VTX;
    out->height = sim->tip_height + 1;
    out->direct_vtx_free = true;
    block_init(&out->block);
    out->block.num_vtx = SIM_BYZ_OVERSIZE_VTX;
    out->block.vtx = zcl_calloc(out->block.num_vtx,
                                sizeof(*out->block.vtx),
                                "simnet_byz_oversize_vtx");
    if (!out->block.vtx)
        LOG_FAIL("simnet.byz", "OOM allocating oversize vtx slots");

    struct uint256 *txids =
        zcl_calloc(out->block.num_vtx, sizeof(*txids),
                   "simnet_byz_oversize_txids");
    if (!txids) {
        free(out->block.vtx);
        out->block.vtx = NULL;
        out->block.num_vtx = 0;
        LOG_FAIL("simnet.byz", "OOM allocating oversize txids");
    }
    for (size_t i = 0; i < out->block.num_vtx; i++) {
        uint32_t tag = (uint32_t)(i + 1);
        out->block.vtx[i].hash.data[0] = (uint8_t)(tag & 0xffu);
        out->block.vtx[i].hash.data[1] = (uint8_t)((tag >> 8) & 0xffu);
        out->block.vtx[i].hash.data[2] = (uint8_t)((tag >> 16) & 0xffu);
        out->block.vtx[i].hash.data[3] = (uint8_t)((tag >> 24) & 0xffu);
        txids[i] = out->block.vtx[i].hash;
    }

    out->block.header.nVersion = 4;
    out->block.header.hashPrevBlock = sim->tip.hashBlock;
    out->block.header.hashMerkleRoot =
        compute_merkle_root(txids, out->block.num_vtx);
    out->block.header.nTime = (uint32_t)out->height;
    free(txids);
    return true;
}

static void common_header(const struct simnet *sim, struct block_header *h)
{
    block_header_init(h);
    h->nVersion = 4;
    h->hashPrevBlock = sim->tip.hashBlock;
    h->nTime = (uint32_t)(sim->tip_height + 1);
}

static unsigned int pow_limit_bits(const struct chain_params *params)
{
    struct arith_uint256 pow_limit;
    uint256_to_arith(&pow_limit, &params->consensus.powLimit);
    return arith_uint256_get_compact(&pow_limit, false);
}

bool simnet_byzantine_build_invalid_pow_header(
    const struct simnet *sim, struct simnet_byzantine_header_case *out)
{
    if (!sim || !sim->initialized || !out)
        LOG_FAIL("simnet.byz", "invalid invalid_pow header request");
    memset(out, 0, sizeof(*out));
    out->kind = SIMNET_BYZ_INVALID_POW;
    out->gate = SIMNET_BYZ_HEADER_CHECK_BLOCK;
    out->prev = sim->tip;
    common_header(sim, &out->header);
    out->header.nBits = pow_limit_bits(&sim->params);
    out->header.nSolutionSize = 1;
    out->header.nSolution[0] = 0x23;
    return true;
}

bool simnet_byzantine_build_bad_bits_header(
    const struct simnet *sim, struct simnet_byzantine_header_case *out)
{
    if (!sim || !sim->initialized || !out)
        LOG_FAIL("simnet.byz", "invalid bad_bits header request");
    memset(out, 0, sizeof(*out));
    out->kind = SIMNET_BYZ_BAD_BITS;
    out->gate = SIMNET_BYZ_HEADER_CONTEXTUAL;
    out->prev = sim->tip;
    common_header(sim, &out->header);
    out->expected_bits =
        GetNextWorkRequired(&out->prev, &out->header, &sim->params.consensus);
    out->header.nBits = out->expected_bits ^ 1u;
    if (out->header.nBits == out->expected_bits)
        out->header.nBits++;
    out->prev_mtp = block_index_get_median_time_past(&out->prev);
    return true;
}

bool simnet_byzantine_build_bad_timestamp_header(
    const struct simnet *sim, struct simnet_byzantine_header_case *out)
{
    if (!sim || !sim->initialized || !out)
        LOG_FAIL("simnet.byz", "invalid bad_timestamp header request");
    memset(out, 0, sizeof(*out));
    out->kind = SIMNET_BYZ_BAD_TIMESTAMP;
    out->gate = SIMNET_BYZ_HEADER_CONTEXTUAL;
    out->prev = sim->tip;
    common_header(sim, &out->header);
    out->prev_mtp = block_index_get_median_time_past(&out->prev);
    out->header.nTime = (uint32_t)out->prev_mtp;
    out->expected_bits =
        GetNextWorkRequired(&out->prev, &out->header, &sim->params.consensus);
    out->header.nBits = out->expected_bits;
    return true;
}

void simnet_byzantine_block_case_free(
    struct simnet_byzantine_block_case *c)
{
    if (!c)
        return;
    if (c->direct_vtx_free) {
        free(c->block.vtx);
        c->block.vtx = NULL;
        c->block.num_vtx = 0;
    } else {
        block_free(&c->block);
    }
    memset(c, 0, sizeof(*c));
}

static bool raise_blocker(enum simnet_byzantine_class kind,
                          const char *reject_reason,
                          struct simnet_byzantine_observation *out)
{
    enum blocker_class cls =
        simnet_byzantine_blocker_class_for_reason(reject_reason);
    char id[64];
    /* blocker-id: simnet_byz.* */
    snprintf(id, sizeof(id), "simnet_byz.%s",
             simnet_byzantine_class_name(kind));
    char reason[192];
    snprintf(reason, sizeof(reason), "reject_reason=%s",
             reject_reason ? reject_reason : "");

    struct blocker_record rec;
    if (!blocker_init(&rec, id, SIM_BYZ_OWNER, cls, reason))
        return false;
    int rc = blocker_set(&rec);
    if (rc < 0)
        LOG_FAIL("simnet.byz", "blocker_set failed for %s", id);

    if (out) {
        out->blocker_class = cls;
        snprintf(out->blocker_id, sizeof(out->blocker_id), "%s", id);
    }
    return true;
}

static bool connect_on_scratch(struct simnet *sim,
                               const struct simnet_byzantine_block_case *c,
                               struct validation_state *vs)
{
    if (!sim || !c || !vs)
        LOG_FAIL("simnet.byz", "invalid scratch connect request");

    struct coins_view parent_view;
    coins_view_cache_as_view(&parent_view, &sim->view);
    struct coins_view_cache scratch;
    coins_view_cache_init(&scratch, &parent_view);

    struct uint256 block_hash;
    block_header_get_hash(&c->block.header, &block_hash);
    struct block_index idx;
    block_index_init(&idx);
    idx.hashBlock = block_hash;
    idx.phashBlock = &idx.hashBlock;
    idx.pprev = &sim->tip;
    idx.nHeight = c->height;
    idx.nVersion = c->block.header.nVersion;
    idx.nTime = c->block.header.nTime;
    idx.nBits = c->block.header.nBits;
    idx.hashMerkleRoot = c->block.header.hashMerkleRoot;
    idx.has_chain_sprout_value = false;
    idx.has_chain_sapling_value = false;

    bool ok = connect_block(&c->block, vs, &idx, &scratch, &sim->params,
                            false);
    coins_view_cache_free(&scratch);
    return ok;
}

static bool build_connect_case(enum simnet_byzantine_class kind,
                               struct simnet *sim,
                               struct simnet_byzantine_block_case *out)
{
    switch (kind) {
    case SIMNET_BYZ_BAD_MERKLE:
        return simnet_byzantine_build_bad_merkle(sim, out);
    case SIMNET_BYZ_BAD_CB_AMOUNT:
        return simnet_byzantine_build_bad_cb_amount(sim, out);
    case SIMNET_BYZ_BIP30_DUP_TXID:
        return simnet_byzantine_build_bip30_duplicate_txid(sim, out);
    case SIMNET_BYZ_MISSING_SPEND:
        return simnet_byzantine_build_missing_spend(sim, out);
    case SIMNET_BYZ_IMMATURE_SPEND:
        return simnet_byzantine_build_immature_spend(sim, out);
    case SIMNET_BYZ_NEGATIVE_OUTPUT:
        return simnet_byzantine_build_negative_output(sim, out);
    case SIMNET_BYZ_OVERFLOW_OUTPUT:
        return simnet_byzantine_build_overflow_output(sim, out);
    case SIMNET_BYZ_OVERSIZE_VTX:
        return simnet_byzantine_build_oversize_vtx(sim, out);
    default:
        LOG_FAIL("simnet.byz", "class %d is not a connect_block case",
                 (int)kind);
    }
}

bool simnet_byzantine_run_connect_case(
    enum simnet_byzantine_class kind,
    struct simnet_byzantine_observation *out)
{
    if (!out)
        LOG_FAIL("simnet.byz", "NULL observation");
    memset(out, 0, sizeof(*out));
    out->kind = kind;
    out->tier = SIMNET_BYZ_TIER_CONNECT_BLOCK;
    out->blocker_class = BLOCKER_TRANSIENT;

    struct simnet sim;
    if (!simnet_init(&sim))
        return false;

    struct simnet_byzantine_block_case c;
    bool built = build_connect_case(kind, &sim, &c);
    if (!built) {
        simnet_free(&sim);
        return false;
    }

    out->tip_before = simnet_tip_height(&sim);
    struct validation_state vs;
    validation_state_init(&vs);
    bool accepted = connect_on_scratch(&sim, &c, &vs);
    out->rejected = !accepted;
    if (vs.reject_reason[0])
        snprintf(out->reject_reason, sizeof(out->reject_reason), "%s",
                 vs.reject_reason);
    if (out->rejected)
        (void)raise_blocker(kind, out->reject_reason, out);
    out->tip_after = simnet_tip_height(&sim);
    out->honest_after_accepted = simnet_mint_coinbase(&sim, NULL);
    out->invariant_ok = simnet_byzantine_observation_ok(out);

    simnet_byzantine_block_case_free(&c);
    simnet_free(&sim);
    return true;
}

static bool build_header_case(enum simnet_byzantine_class kind,
                              const struct simnet *sim,
                              struct simnet_byzantine_header_case *out)
{
    switch (kind) {
    case SIMNET_BYZ_INVALID_POW:
        return simnet_byzantine_build_invalid_pow_header(sim, out);
    case SIMNET_BYZ_BAD_BITS:
        return simnet_byzantine_build_bad_bits_header(sim, out);
    case SIMNET_BYZ_BAD_TIMESTAMP:
        return simnet_byzantine_build_bad_timestamp_header(sim, out);
    default:
        LOG_FAIL("simnet.byz", "class %d is not a header case", (int)kind);
    }
}

static bool header_admission_gate(const struct simnet *sim,
                                  const struct simnet_byzantine_header_case *c,
                                  struct validation_state *vs)
{
    if (!sim || !c || !vs)
        LOG_FAIL("simnet.byz", "invalid header gate request");
    if (c->gate == SIMNET_BYZ_HEADER_CHECK_BLOCK)
        return check_block_header(&c->header, vs, &sim->params, true);
    return contextual_check_block_header(&c->header, vs, &sim->params,
                                         &c->prev, false);
}

bool simnet_byzantine_run_header_case(
    enum simnet_byzantine_class kind,
    struct simnet_byzantine_observation *out)
{
    if (!out)
        LOG_FAIL("simnet.byz", "NULL observation");
    memset(out, 0, sizeof(*out));
    out->kind = kind;
    out->tier = SIMNET_BYZ_TIER_HEADER_ADMISSION;
    out->blocker_class = BLOCKER_TRANSIENT;

    struct simnet sim;
    if (!simnet_init(&sim))
        return false;

    struct simnet_byzantine_header_case c;
    bool built = build_header_case(kind, &sim, &c);
    if (!built) {
        simnet_free(&sim);
        return false;
    }

    out->tip_before = simnet_tip_height(&sim);
    struct validation_state vs;
    validation_state_init(&vs);
    bool accepted = header_admission_gate(&sim, &c, &vs);
    out->rejected = !accepted;
    if (vs.reject_reason[0])
        snprintf(out->reject_reason, sizeof(out->reject_reason), "%s",
                 vs.reject_reason);
    if (out->rejected)
        (void)raise_blocker(kind, out->reject_reason, out);
    out->tip_after = simnet_tip_height(&sim);
    out->honest_after_accepted = simnet_mint_coinbase(&sim, NULL);
    out->invariant_ok = simnet_byzantine_observation_ok(out);

    simnet_free(&sim);
    return true;
}

bool simnet_byzantine_observation_ok(
    const struct simnet_byzantine_observation *obs)
{
    if (!obs)
        return false;
    return obs->rejected &&
           obs->reject_reason[0] != '\0' &&
           obs->blocker_id[0] != '\0' &&
           obs->blocker_class ==
               simnet_byzantine_expected_blocker_class(obs->kind) &&
           obs->tip_after == obs->tip_before &&
           obs->honest_after_accepted;
}
