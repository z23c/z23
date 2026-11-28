/* purpose: Check that all decoded v6 transaction fields agree with the wire. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_checked_wire.h"
#include "base/serialize_le.h"
#include "core/serialize.h"
#include "primitives/transaction.h"
#include "primitives/transaction_v6_digest.h"
#include <string.h>

static bool transparent_items(const struct transaction *tx,
    const struct v6_wire_view *view, bool inputs)
{
    struct v6_wire_cursor cursor;
    if (!v6_core_cursor_init(view, inputs, &cursor)) return false;
    uint8_t bytes[MAX_SCRIPT_SIZE + 64];
    size_t count = inputs ? tx->num_vin : tx->num_vout;
    for (size_t i = 0; i < count; ++i) {
        struct v6_span item;
        if (!v6_core_cursor_next(&cursor, &item)) return false;
        struct byte_stream encoded = {.data = bytes, .capacity = sizeof bytes};
        if (inputs) {
            const struct tx_in *in = &tx->vin[i];
            if (in->script_sig.size > MAX_SCRIPT_SIZE || !tx_in_serialize(in, &encoded)) return false;
        } else {
            const struct tx_out *out = &tx->vout[i];
            if (out->script_pub_key.size > MAX_SCRIPT_SIZE || !tx_out_serialize(out, &encoded)) return false;
        }
        if (encoded.size != item.size || memcmp(bytes, item.data, item.size)) return false;
    }
    return true;
}

static bool consume(struct v6_span *span, const uint8_t *expected, size_t size)
{
    if (span->size < size || memcmp(span->data, expected, size)) return false;
    span->data += size;
    span->size -= size;
    return true;
}

static bool sapling_spends(const struct transaction *tx,
    const struct v6_wire_view *view, struct v6_span *tail)
{
    struct v6_span raw = view->sapling_spends.wire;
    if (!tx->num_shielded_spend) return raw.size == 0;
    const uint8_t *anchor = tail->data;
    if (!consume(tail, tx->v_shielded_spend[0].anchor.data, 32)) return false;
    for (size_t i = 0; i < tx->num_shielded_spend; ++i) {
        const struct spend_description *s = &tx->v_shielded_spend[i];
        if (memcmp(s->anchor.data, anchor, 32) || !consume(&raw, s->cv.data, 32) ||
            !consume(&raw, s->nullifier.data, 32) || !consume(&raw, s->rk.data, 32) ||
            !consume(tail, s->zkproof, sizeof s->zkproof)) return false;
    }
    for (size_t i = 0; i < tx->num_shielded_spend; ++i) {
        const struct spend_description *s = &tx->v_shielded_spend[i];
        if (!consume(tail, s->spend_auth_sig, sizeof s->spend_auth_sig)) return false;
    }
    return raw.size == 0;
}

static bool sapling_outputs(const struct transaction *tx,
    const struct v6_wire_view *view, struct v6_span *tail)
{
    struct v6_span raw = view->sapling_outputs.wire;
    for (size_t i = 0; i < tx->num_shielded_output; ++i) {
        const struct output_description *o = &tx->v_shielded_output[i];
        if (!consume(&raw, o->cv.data, 32) || !consume(&raw, o->cm.data, 32) ||
            !consume(&raw, o->ephemeral_key.data, 32) ||
            !consume(&raw, o->enc_ciphertext, sizeof o->enc_ciphertext) ||
            !consume(&raw, o->out_ciphertext, sizeof o->out_ciphertext) ||
            !consume(tail, o->zkproof, sizeof o->zkproof)) return false;
    }
    return raw.size == 0;
}

static bool sapling_matches(const struct transaction *tx, const struct v6_wire_view *view)
{
    struct v6_span tail = view->sapling_tail;
    if (!tx->num_shielded_spend && !tx->num_shielded_output)
        return !tx->value_balance && tail.size == 0;
    uint8_t balance[8];
    zcl_write_u64_le(balance, (uint64_t)tx->value_balance);
    return consume(&tail, balance, sizeof balance) && sapling_spends(tx, view, &tail) &&
        sapling_outputs(tx, view, &tail) && consume(&tail, tx->binding_sig, sizeof tx->binding_sig) &&
        tail.size == 0;
}

static bool array_matches(uint64_t wire_count, size_t count, size_t limit, const void *data)
{
    return wire_count == count && count <= limit && (!count || data);
}

static bool ironwood_balance_matches(const struct transaction *tx, const struct v6_bundle *bundle)
{
    if (!bundle->count) return tx->ironwood_value_balance == 0;
    return bundle->value_balance.size == sizeof tx->ironwood_value_balance &&
        tx->ironwood_value_balance == zcl_read_i64_le(bundle->value_balance.data);
}

static bool frame_fields(const struct transaction *tx, const struct v6_wire_view *v)
{
    return tx->overwintered && tx->version == IRONWOOD_TX_VERSION &&
        tx->version_group_id == IRONWOOD_VERSION_GROUP_ID && !tx->num_joinsplit &&
        tx->lock_time == zcl_read_u32_le(v->header.data + 12) &&
        tx->expiry_height == zcl_read_u32_le(v->header.data + 16) &&
        array_matches(v->inputs, tx->num_vin, MAX_TX_INPUTS, tx->vin) &&
        array_matches(v->outputs, tx->num_vout, MAX_TX_OUTPUTS, tx->vout) &&
        array_matches(v->sapling_spends.count, tx->num_shielded_spend, MAX_SHIELDED_SPENDS, tx->v_shielded_spend) &&
        array_matches(v->sapling_outputs.count, tx->num_shielded_output, MAX_SHIELDED_OUTPUTS, tx->v_shielded_output);
}

struct zcl_result ironwood_checked_wire(const struct transaction *tx,
    size_t frame_limit, struct v6_wire_view *out)
{
    if (!tx || !out || !tx->v6_wire.data || tx->v6_wire.size > frame_limit)
        return ZCL_ERR(-1, "Ironwood transaction frame unavailable or over limit");
    struct v6_wire_view view;
    if (v6_core_parse(tx->v6_wire.data, tx->v6_wire.size, &view) != V6_WIRE_OK ||
        !frame_fields(tx, &view) || !ironwood_balance_matches(tx, &view.ironwood) ||
        !transparent_items(tx, &view, true) ||
        !transparent_items(tx, &view, false) || !sapling_matches(tx, &view))
        return ZCL_ERR(-1, "Ironwood transaction model differs from its wire frame");
    struct v6_digests digests;
    if (!v6_wire_digests(&view, &digests))
        return ZCL_ERR(-2, "Ironwood transaction digest unavailable");
    if (memcmp(tx->hash.data, digests.txid, sizeof tx->hash.data))
        return ZCL_ERR(-1, "Ironwood cached transaction identity differs from its wire frame");
    *out = view;
    return ZCL_OK;
}
