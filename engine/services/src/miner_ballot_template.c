/* purpose: Add a ballot to a bounded temporary mining template. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/miner_ballot_template.h"
#include "services/miner_signal_round.h"
#include "services/miner_signal_catalog_pin.h"
#include "base/hex.h"
#include "json/json.h"
#include "bloom/merkle.h"
#include "chain/chainparams.h"
#include "core/serialize.h"
#include "crypto/equihash.h"
#include "primitives/block.h"
#include "mining/miner.h"
#include "services/research_block_size.h"
#include "services/research_rules_tip.h"
#include "core/amount.h"
#include "primitives/transaction.h"
#include "util/safe_alloc.h"
#include "util/util.h"
#include "validation/main_constants.h"
#include <stdlib.h>
#include <string.h>

static struct zcl_result mining_slot_bitmap(const struct json_value *list, size_t slots,
                                            uint8_t bits[32])
{
    if (list->type != JSON_ARR || json_size(list) > slots)
        return ZCL_ERR(-1, "ballotslots must be a list of distinct pinned slots");
    for (size_t i = 0; i < json_size(list); ++i) {
        const struct json_value *v = json_at(list, i);
        if (!v || v->type != JSON_INT) return ZCL_ERR(-1, "Expected an integer ballot slot");
        int64_t n = json_get_int(v);
        if (n < 0 || (uint64_t)n >= slots) return ZCL_ERR(-1, "Slot outside pinned catalog");
        size_t byte = (size_t)n / 8;
        uint8_t mask = (uint8_t)(1u << ((unsigned)n % 8));
        if (bits[byte] & mask) return ZCL_ERR(-1, "Repeated ballot slot");
        bits[byte] |= mask;
    }
    return ZCL_OK;
}
struct zcl_result miner_ballot_request_bitmap(const struct json_value *request,
    const struct miner_signal_catalog_pin *pin, uint8_t bits[32])
{
    if (request->type != JSON_OBJ)
        return mining_slot_bitmap(request, pin->count, bits);
    const struct json_value *slots = json_get(request, "slots");
    const char *catalog = json_get_str(json_get(request, "catalog"));
    uint8_t expected[32];
    if (json_size(request) != 2 || !slots ||
        !zcl_hex_decode_lower(catalog, expected, sizeof(expected)))
        return ZCL_ERR(-1, "Expected ballotslots object with lowercase catalog digest and slots list");
    if (memcmp(expected, pin->digest, sizeof(expected)))
        return ZCL_ERR(-1, "Requested ballot catalog differs from node pin");
    return mining_slot_bitmap(slots, pin->count, bits);
}
static struct zcl_result ballot_append(struct transaction *cb,
                                        const uint8_t catalog[32],
                                        const uint8_t bitmap[32])
{
    if (!cb->vin || !transaction_is_coinbase(cb) || !cb->vout || !cb->num_vout ||
        cb->num_vout >= MAX_TX_OUTPUTS || cb->vin[0].script_sig.size > 100)
        return ZCL_ERR(-1, "Invalid coinbase output or script size");
    size_t n = cb->num_vout;
    /* The caller may supply ballot bytes from one of the existing payouts. */
    uint8_t ballot[MINER_SIGNAL_SCRIPT_BYTES];
    miner_signal_ballot_script(catalog, bitmap, ballot);
    struct tx_out *outputs = zcl_realloc(cb->vout, (n + 1) * sizeof(*outputs),
                                         "miner ballot outputs");
    if (!outputs) return ZCL_ERR(-2, "Cannot allocate ballot outputs");
    cb->vout = outputs;
    tx_out_set_null(&outputs[n]);
    outputs[n].value = 0;
    outputs[n].script_pub_key.size = MINER_SIGNAL_SCRIPT_BYTES;
    memcpy(outputs[n].script_pub_key.data, ballot, sizeof(ballot));
    cb->num_vout = n + 1;
    return ZCL_OK;
}

static struct zcl_result ballot_check_size(struct block *block, size_t solution_size,
                                            size_t limit, size_t *out)
{
    uint8_t *buf = zcl_malloc(limit, "miner ballot serialization bound");
    if (!buf) return ZCL_ERR(-3, "Cannot allocate bounded block serialization");
    struct byte_stream s = { .data = buf, .capacity = limit, .owns_data = false };
    struct script *script = &block->vtx[0].vin[0].script_sig;
    size_t old_len = script->size;
    memset(script->data + old_len, 0, 100 - old_len);
    script->size = 100;
    /* Input header is unsolved; bytes beyond its zero length have no wire value. */
    memset(block->header.nSolution, 0, solution_size);
    block->header.nSolutionSize = solution_size;
    bool ok = block_serialize(block, &s) && !s.error;
    size_t size = s.size;
    block->header.nSolutionSize = 0;
    script->size = (uint16_t)old_len;
    free(buf);
    if (!ok) return ZCL_ERR(-4, "Reserved block serialization exceeds mining limit or failed");
    *out = size;
    return ZCL_OK;
}

static struct zcl_result ballot_update_merkle(struct block *block)
{
    struct uint256 *txids = zcl_malloc(block->num_vtx * sizeof(*txids), "miner ballot merkle");
    if (!txids) return ZCL_ERR(-5, "Cannot allocate merkle leaves");
    for (size_t i = 0; i < block->num_vtx; i++) {
        if (!transaction_hash_serialized(&block->vtx[i], &txids[i])) {
            free(txids);
            return ZCL_ERR(-6, "Cannot serialize a template transaction for hashing");
        }
    }
    block->vtx[0].hash = txids[0];
    bool mutated = false;
    struct uint256 root = merkle_root_mutated_in_place(txids, block->num_vtx, &mutated);
    free(txids);
    if (mutated) return ZCL_ERR(-7, "Mutated Merkle tree in mining template");
    block->header.hashMerkleRoot = root;
    return ZCL_OK;
}

static bool ballot_unsolved_template(const struct block *block)
{
    return block && block->vtx && block->num_vtx &&
           block->num_vtx <= MAX_BLOCK_TRANSACTIONS && !block->header.nSolutionSize;
}

struct zcl_result miner_ballot_template_apply(struct block *block,
    const uint8_t catalog[32], const uint8_t bitmap[32],
    const struct chain_params *params, int height, size_t mining_limit,
    size_t *reserved_size_out)
{
    if (!ballot_unsolved_template(block) || !catalog || !bitmap || !params ||
        !reserved_size_out || height < 0 || !mining_limit || mining_limit > MAX_BLOCK_SIZE)
        return ZCL_ERR(-8, "Invalid unsolved mining template or policy limit");
    unsigned n = chain_params_equihash_n(params, height);
    unsigned k = chain_params_equihash_k(params, height);
    if (!equihash_params_supported(n, k)) return ZCL_ERR(-9, "Unsupported Equihash parameters");
    struct equihash_params ep;
    equihash_params_init(&ep, n, k);
    if (!ep.solution_width || ep.solution_width > MAX_SOLUTION_SIZE)
        return ZCL_ERR(-10, "Equihash solution width exceeds header capacity");
    struct zcl_result r = ballot_append(&block->vtx[0], catalog, bitmap);
    if (!r.ok) return r;
    size_t reserved = 0;
    r = ballot_check_size(block, ep.solution_width, mining_limit, &reserved);
    if (!r.ok) return r;
    r = ballot_update_merkle(block);
    if (!r.ok) return r;
    *reserved_size_out = reserved;
    return ZCL_OK;
}

/* Reserve a maximum coinbase script and the selected Equihash solution;
 * optional ballot output growth includes the output-count CompactSize. */
static struct zcl_result research_reserved_size(struct block *block,
    size_t solution_size, bool reserve_ballot, size_t limit, size_t *out)
{
    struct transaction *cb = &block->vtx[0];
    size_t extra = reserve_ballot ? 8 + compact_size_sizeof(MINER_SIGNAL_SCRIPT_BYTES) +
        MINER_SIGNAL_SCRIPT_BYTES + compact_size_sizeof(cb->num_vout + 1) -
        compact_size_sizeof(cb->num_vout) : 0;
    unsigned char *bytes = zcl_malloc(limit + 1, "research template bound");
    if (!bytes) return ZCL_ERR(-20, "Cannot allocate research template bound");
    struct byte_stream s = { .data = bytes, .capacity = limit + 1, .owns_data = false };
    struct script *script = &cb->vin[0].script_sig;
    size_t old_len = script->size;
    memset(script->data + old_len, 0, 100 - old_len);
    script->size = 100;
    memset(block->header.nSolution, 0, solution_size);
    block->header.nSolutionSize = solution_size;
    bool ok = block_serialize(block, &s);
    bool overflow = s.error || s.size > limit || extra > limit - s.size;
    size_t size = s.size + (overflow ? 0 : extra);
    block->header.nSolutionSize = 0;
    script->size = old_len;
    free(bytes);
    if (overflow) return ZCL_ERR(-21, "Research template exceeds block limit");
    if (!ok) return ZCL_ERR(-22, "Cannot serialize research template");
    *out = size;
    return ZCL_OK;
}

static bool research_coinbase_valid(const struct transaction *cb, bool reserve_ballot)
{
    return cb->vin && transaction_is_coinbase(cb) && cb->vout && cb->num_vout &&
        cb->vin[0].script_sig.size <= 100 &&
        (!reserve_ballot || cb->num_vout < MAX_TX_OUTPUTS);
}

/* Determine the longest fitting prefix with one bounded buffer and a single
 * serialization per candidate transaction. A final full-block check follows. */
static struct zcl_result research_fitting_prefix(struct block *block,
    size_t solution_size, bool reserve_ballot, size_t limit, size_t *count_out)
{
    struct transaction *cb = &block->vtx[0];
    size_t extra = reserve_ballot ? 8 + compact_size_sizeof(MINER_SIGNAL_SCRIPT_BYTES) +
        MINER_SIGNAL_SCRIPT_BYTES + compact_size_sizeof(cb->num_vout + 1) -
        compact_size_sizeof(cb->num_vout) : 0;
    unsigned char *bytes = zcl_malloc(limit + 1, "research template prefix");
    if (!bytes) return ZCL_ERR(-20, "Cannot allocate research template bound");
    struct byte_stream s = { .data = bytes, .capacity = limit + 1, .owns_data = false };
    struct script *script = &cb->vin[0].script_sig;
    size_t old_len = script->size;
    memset(script->data + old_len, 0, 100 - old_len);
    script->size = 100;
    memset(block->header.nSolution, 0, solution_size);
    block->header.nSolutionSize = solution_size;
    bool ok = block_header_serialize(&block->header, &s) && transaction_serialize(cb, &s);
    block->header.nSolutionSize = 0;
    script->size = old_len;
    if (!ok) {
        bool exceeded = s.error;
        free(bytes);
        return exceeded ? ZCL_ERR(-21, "Research coinbase exceeds block limit")
                        : ZCL_ERR(-22, "Cannot serialize research coinbase");
    }
    size_t total = s.size;
    size_t count = 1;
    if (extra > limit || total > limit - extra ||
        compact_size_sizeof(count) > limit - extra - total) {
        free(bytes);
        return ZCL_ERR(-21, "Research coinbase exceeds block limit");
    }
    for (size_t i = 1; i < block->num_vtx; i++) {
        s.size = 0;
        s.error = false;
        ok = transaction_serialize(&block->vtx[i], &s);
        if (!ok && !s.error) { free(bytes); return ZCL_ERR(-22, "Cannot serialize research transaction"); }
        if (!ok || s.size > limit - extra - total ||
            compact_size_sizeof(count + 1) > limit - extra - total - s.size)
            break;
        total += s.size;
        count++;
    }
    free(bytes);
    *count_out = count;
    return ZCL_OK;
}

static struct zcl_result research_template_validate(const struct block_template *tmpl,
    const struct chain_params *params, int height, bool reserve_ballot)
{
    if (!tmpl || !params || height < 0 ||
        research_block_size_limit(params) != RESEARCH_BLOCK_SIZE_LIMIT ||
        !ballot_unsolved_template(&tmpl->block) || !tmpl->tx_fees ||
        !tmpl->tx_sig_ops || tmpl->num_entries != tmpl->block.num_vtx)
        return ZCL_ERR(-23, "Invalid research mining template");
    const struct transaction *cb = &tmpl->block.vtx[0];
    if (!research_coinbase_valid(cb, reserve_ballot))
        return ZCL_ERR(-24, "Invalid research coinbase");
    return ZCL_OK;
}

static struct zcl_result research_template_drop_last(struct block_template *tmpl)
{
    struct block *block = &tmpl->block;
    struct transaction *cb = &block->vtx[0];
    size_t last = block->num_vtx - 1;
    int64_t fee = tmpl->tx_fees[last];
    if (!MoneyRange(fee) || !MoneyRange(cb->vout[0].value) ||
        cb->vout[0].value < fee || tmpl->tx_fees[0] > 0 ||
        tmpl->tx_fees[0] < -MAX_MONEY || fee > -tmpl->tx_fees[0])
        return ZCL_ERR(-27, "Invalid research template fees");
    cb->vout[0].value -= fee;
    tmpl->tx_fees[0] += fee;
    transaction_free(&block->vtx[last]);
    block->num_vtx--;
    tmpl->num_entries--;
    return ZCL_OK;
}

struct zcl_result miner_research_template_fit(struct block_template *tmpl,
    const struct chain_params *params, int height, bool reserve_ballot, size_t limit, bool freeze)
{
    struct zcl_result valid = research_template_validate(tmpl, params, height, reserve_ballot);
    if (!valid.ok) return valid;
    if (!limit || limit > research_block_size_ceiling(params))
        return ZCL_ERR(-28, "Invalid research template size limit");
    unsigned n = chain_params_equihash_n(params, height);
    unsigned k = chain_params_equihash_k(params, height);
    if (!equihash_params_supported(n, k)) return ZCL_ERR(-25, "Unsupported Equihash parameters");
    struct equihash_params ep;
    equihash_params_init(&ep, n, k);
    if (!ep.solution_width || ep.solution_width > MAX_SOLUTION_SIZE)
        return ZCL_ERR(-26, "Invalid Equihash solution width");
    struct block *block = &tmpl->block;
    size_t keep = 0;
    struct zcl_result r = research_fitting_prefix(block, ep.solution_width, reserve_ballot, limit, &keep);
    if (!r.ok) return r;
    for (size_t i = 1; i < keep; ++i) {
        if (research_tip_deposit_frozen((struct research_tip_rules){ .freeze = freeze }, &block->vtx[i])) {
            LogPrint("mining", "[mining] omitting frozen deposit and template suffix\n");
            keep = i;
            break;
        }
    }
    while (block->num_vtx > keep) {
        r = research_template_drop_last(tmpl);
        if (!r.ok) return r;
    }
    size_t reserved;
    r = research_reserved_size(block, ep.solution_width, reserve_ballot, limit, &reserved);
    if (!r.ok) return r;
    if (research_block_size_check_under(block, limit) != RESEARCH_BLOCK_SIZE_OK)
        return ZCL_ERR(-29, "Cannot verify research template size");
    return ballot_update_merkle(block);
}
