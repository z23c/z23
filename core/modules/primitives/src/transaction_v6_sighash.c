/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Compute ZIP 244 signature hashes from checked v6 transactions.
 */
#include "primitives/transaction_v6_sighash.h"

#include "base/serialize_le.h"
#include "core/amount.h"
#include "crypto/blake2b.h"
#include "primitives/transaction_v6_digest.h"

#include <string.h>

#define V6_CHECK(x) do { if (!(x)) return false; } while (0)

static bool v6_hash_start(struct blake2b_ctx *ctx, const char personal[16])
{
    return blake2b_init_salt_personal(ctx, 32, NULL, 0, NULL,
                                     (const uint8_t *)personal) == 0;
}

static bool v6_hash_add(struct blake2b_ctx *ctx, const void *data, size_t size)
{
    return !size || blake2b_update(ctx, data, size) == 0;
}

static bool v6_hash_finish(struct blake2b_ctx *ctx, uint8_t out[32])
{
    return blake2b_final(ctx, out, 32) == 0;
}

static bool v6_hash_script(struct blake2b_ctx *ctx, const uint8_t *script,
                           size_t size)
{
    uint8_t prefix[3];
    size_t prefix_size;
    if (size > UINT16_MAX) return false;
    if (size < 253) {
        prefix[0] = (uint8_t)size;
        prefix_size = 1;
    } else {
        prefix[0] = 253;
        zcl_write_u16_le(prefix + 1, (uint16_t)size);
        prefix_size = 3;
    }
    return v6_hash_add(ctx, prefix, prefix_size) &&
        v6_hash_add(ctx, script, size);
}

static bool v6_hash_amount(struct blake2b_ctx *ctx, int64_t amount)
{
    uint8_t encoded[8];
    zcl_write_i64_le(encoded, amount);
    return v6_hash_add(ctx, encoded, sizeof encoded);
}

static bool v6_input_at(const struct v6_wire_view *view, size_t index,
                        struct v6_span *item)
{
    struct v6_wire_cursor cursor;
    V6_CHECK(v6_core_cursor_init(view, true, &cursor));
    for (size_t i = 0; i <= index; ++i)
        V6_CHECK(v6_core_cursor_next(&cursor, item));
    return item->size >= 41;
}

struct v6_input_hashes {
    struct blake2b_ctx prevouts, amounts, scripts, sequence, txin;
};

static bool v6_input_hashes_start(struct v6_input_hashes *hashes)
{
    V6_CHECK(v6_hash_start(&hashes->prevouts, "ZTxIdPrevoutHash"));
    V6_CHECK(v6_hash_start(&hashes->amounts, "ZTxTrAmountsHash"));
    V6_CHECK(v6_hash_start(&hashes->scripts, "ZTxTrScriptsHash"));
    V6_CHECK(v6_hash_start(&hashes->sequence, "ZTxIdSequencHash"));
    V6_CHECK(v6_hash_start(&hashes->txin, "Zcash___TxInHash"));
    return true;
}

static bool v6_input_hashes_finish(struct v6_input_hashes *hashes,
                                   uint8_t parts[6][32])
{
    return v6_hash_finish(&hashes->prevouts, parts[0]) &&
        v6_hash_finish(&hashes->amounts, parts[1]) &&
        v6_hash_finish(&hashes->scripts, parts[2]) &&
        v6_hash_finish(&hashes->sequence, parts[3]) &&
        v6_hash_finish(&hashes->txin, parts[5]);
}

static bool v6_hash_global_input(struct v6_input_hashes *hashes,
    const struct v6_span *item, const struct transaction_v6_prevout *prevout)
{
    V6_CHECK(v6_hash_add(&hashes->prevouts, item->data, 36));
    V6_CHECK(v6_hash_amount(&hashes->amounts, prevout->amount));
    V6_CHECK(v6_hash_script(&hashes->scripts, prevout->script,
                            prevout->script_size));
    V6_CHECK(v6_hash_add(&hashes->sequence, item->data + item->size - 4, 4));
    return true;
}

static bool v6_hash_current_input(struct v6_input_hashes *hashes,
    const struct v6_span *item, const struct script *script_code, int64_t amount)
{
    V6_CHECK(v6_hash_add(&hashes->txin, item->data, 36));
    V6_CHECK(v6_hash_amount(&hashes->txin, amount));
    V6_CHECK(v6_hash_script(&hashes->txin, script_code->data, script_code->size));
    V6_CHECK(v6_hash_add(&hashes->txin, item->data + item->size - 4, 4));
    return true;
}

static bool v6_input_digests(const struct v6_wire_view *view,
    const struct transaction_v6_prevout *prevouts, unsigned int n_in,
    const struct script *script_code, int64_t amount, bool anyone_can_pay,
    uint8_t parts[6][32])
{
    struct v6_input_hashes hashes;
    V6_CHECK(v6_input_hashes_start(&hashes));
    for (size_t i = 0; i < view->inputs; ++i) {
        struct v6_span item;
        V6_CHECK(v6_input_at(view, i, &item));
        if (!anyone_can_pay)
            V6_CHECK(v6_hash_global_input(&hashes, &item, &prevouts[i]));
        if (i == n_in)
            V6_CHECK(v6_hash_current_input(&hashes, &item, script_code, amount));
    }
    return v6_input_hashes_finish(&hashes, parts);
}

static bool v6_output_digest(const struct v6_wire_view *view, unsigned int n_in,
                             struct sighash_type hash_type, uint8_t out[32])
{
    struct blake2b_ctx outputs;
    V6_CHECK(v6_hash_start(&outputs, "ZTxIdOutputsHash"));
    struct v6_wire_cursor cursor;
    V6_CHECK(v6_core_cursor_init(view, false, &cursor));
    uint32_t base = sighash_get_base_type(hash_type);
    for (size_t i = 0; i < view->outputs; ++i) {
        struct v6_span item;
        V6_CHECK(v6_core_cursor_next(&cursor, &item));
        if (base == BASE_SIGHASH_ALL || (base == BASE_SIGHASH_SINGLE && i == n_in))
            V6_CHECK(v6_hash_add(&outputs, item.data, item.size));
    }
    return v6_hash_finish(&outputs, out);
}

static bool v6_coinbase(const struct v6_wire_view *view)
{
    if (view->inputs != 1) return false;
    struct v6_span item;
    if (!v6_input_at(view, 0, &item)) return false;
    static const uint8_t null_prevout[36] = {
        [32] = 0xff, [33] = 0xff, [34] = 0xff, [35] = 0xff
    };
    return memcmp(item.data, null_prevout, sizeof null_prevout) == 0;
}

static bool v6_transparent_digest(const struct v6_wire_view *view,
    const struct v6_digests *digests,
    const struct transaction_v6_prevout *prevouts, unsigned int n_in,
    struct sighash_type hash_type, const struct script *script_code,
    int64_t amount, uint8_t out[32])
{
    if (!view->inputs || v6_coinbase(view)) {
        memcpy(out, digests->transparent_effect, 32);
        return true;
    }
    uint8_t parts[6][32];
    bool anyone_can_pay = sighash_has_anyone_can_pay(hash_type);
    V6_CHECK(v6_input_digests(view, prevouts, n_in, script_code, amount,
                              anyone_can_pay, parts));
    V6_CHECK(v6_output_digest(view, n_in, hash_type, parts[4]));
    struct blake2b_ctx transparent;
    V6_CHECK(v6_hash_start(&transparent, "ZTxIdTranspaHash"));
    uint8_t type = (uint8_t)hash_type.raw;
    V6_CHECK(v6_hash_add(&transparent, &type, 1));
    V6_CHECK(v6_hash_add(&transparent, parts, sizeof parts));
    return v6_hash_finish(&transparent, out);
}

static bool v6_checked_view(const struct transaction *tx, uint32_t branch,
                            struct v6_wire_view *view)
{
    if (!tx->overwintered || tx->version != IRONWOOD_TX_VERSION ||
        tx->version_group_id != IRONWOOD_VERSION_GROUP_ID ||
        !tx->v6_wire.data) return false;
    if (v6_core_parse(tx->v6_wire.data, tx->v6_wire.size, view) != V6_WIRE_OK)
        return false;
    if (tx->num_vin != view->inputs || tx->num_vout != view->outputs)
        return false;
    return zcl_read_u32_le(view->header.data + 8) == branch;
}

static bool v6_valid_hash_type(struct sighash_type hash_type)
{
    switch (hash_type.raw) {
        case SIGHASH_ALL:
        case SIGHASH_NONE:
        case SIGHASH_SINGLE:
        case SIGHASH_ALL | SIGHASH_ANYONECANPAY:
        case SIGHASH_NONE | SIGHASH_ANYONECANPAY:
        case SIGHASH_SINGLE | SIGHASH_ANYONECANPAY:
            return true;
        default:
            return false;
    }
}

static bool v6_valid_input(const struct v6_wire_view *view, unsigned int n_in,
                           struct sighash_type hash_type,
                           const struct script *script_code)
{
    if (n_in == NOT_AN_INPUT) return hash_type.raw == SIGHASH_ALL;
    if ((uint64_t)n_in >= view->inputs || !script_code) return false;
    return sighash_get_base_type(hash_type) != BASE_SIGHASH_SINGLE ||
        (uint64_t)n_in < view->outputs;
}

static bool v6_prevout_valid(const struct transaction_v6_prevout *prevout)
{
    return MoneyRange(prevout->amount) &&
        prevout->script_size <= MAX_SCRIPT_SIZE &&
        (!prevout->script_size || prevout->script);
}

static bool v6_valid_prevouts(const struct v6_wire_view *view,
    const struct transaction_v6_prevout *prevouts, size_t prevout_count,
    bool anyone_can_pay)
{
    if (prevout_count && !prevouts) return false;
    if (prevouts && !prevout_count && view->inputs) return false;
    if (prevout_count && prevout_count != view->inputs) return false;
    if (!anyone_can_pay && !v6_coinbase(view) &&
        prevout_count != view->inputs) return false;
    for (size_t i = 0; i < prevout_count; ++i) {
        if (!v6_prevout_valid(&prevouts[i])) return false;
    }
    return true;
}

static bool v6_valid_current(unsigned int n_in, const struct script *script_code,
                             int64_t amount)
{
    return n_in == NOT_AN_INPUT ||
        (MoneyRange(amount) && script_code->size <= MAX_SCRIPT_SIZE);
}

static bool v6_current_prevout_matches(
    const struct transaction_v6_prevout *prevouts, unsigned int n_in,
    const struct script *script_code, int64_t amount)
{
    if (!prevouts) return true;
    const struct transaction_v6_prevout *prevout = &prevouts[n_in];
    if (prevout->amount != amount || prevout->script_size != script_code->size)
        return false;
    return !script_code->size ||
        memcmp(prevout->script, script_code->data, script_code->size) == 0;
}

bool transaction_v6_sighash(const struct transaction *tx,
    const struct transaction_v6_prevout *prevouts, size_t prevout_count,
    unsigned int n_in, struct sighash_type hash_type,
    const struct script *script_code, int64_t amount,
    uint32_t consensus_branch_id, struct uint256 *result)
{
    if (!result || !tx || !v6_valid_hash_type(hash_type)) return false;
    struct v6_wire_view view;
    if (!v6_checked_view(tx, consensus_branch_id, &view) ||
        !v6_valid_input(&view, n_in, hash_type, script_code)) return false;
    bool anyone_can_pay = sighash_has_anyone_can_pay(hash_type);
    if (!v6_valid_current(n_in, script_code, amount) ||
        !v6_valid_prevouts(&view, prevouts, prevout_count, anyone_can_pay))
        return false;
    if (n_in != NOT_AN_INPUT &&
        !v6_current_prevout_matches(prevouts, n_in, script_code, amount))
        return false;

    struct v6_digests digests;
    V6_CHECK(v6_wire_digests(&view, &digests));
    uint8_t transparent[32];
    V6_CHECK(v6_transparent_digest(&view, &digests, prevouts, n_in,
                                   hash_type, script_code, amount, transparent));
    char personal[16] = "ZcashTxHash_";
    memcpy(personal + 12, view.header.data + 8, 4);
    struct blake2b_ctx final;
    V6_CHECK(v6_hash_start(&final, personal));
    V6_CHECK(v6_hash_add(&final, digests.header_effect, 32));
    V6_CHECK(v6_hash_add(&final, transparent, sizeof transparent));
    V6_CHECK(v6_hash_add(&final, digests.sapling_effect, 32));
    V6_CHECK(v6_hash_add(&final, digests.orchard_effect, 32));
    V6_CHECK(v6_hash_add(&final, digests.ironwood_effect, 32));
    uint8_t computed[32];
    V6_CHECK(v6_hash_finish(&final, computed));
    memcpy(result->data, computed, sizeof computed);
    return true;
}
