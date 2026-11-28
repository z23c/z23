/* purpose: Bind v6 transparent wire inputs to the canonical ZIP 244 digest. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "transaction_v6_transparent_internal.h"
#include "primitives/transaction_v6_decode.h"
#include "primitives/transaction_v6_wire.h"
#include "core/serialize.h"
#include "core/amount.h"
#include "script/script.h"
#include <limits.h>
#include <string.h>

bool v6_transparent_prevouts_valid(const struct transaction_v6_prevout *prevouts, size_t count)
{
    for (size_t i = 0; i < count; ++i)
        if (prevouts[i].amount < 0 || prevouts[i].amount > MAX_MONEY ||
            prevouts[i].script_size > MAX_SCRIPT_SIZE ||
            (prevouts[i].script_size && !prevouts[i].script)) return false;
    return true;
}
struct zcl_result v6_transparent_sighash(const uint8_t *wire, size_t length,
    const struct transaction_v6_prevout *prevouts, size_t count, size_t index,
    uint8_t type, uint32_t expected_branch, uint8_t out[32])
{
    struct v6_wire_view view;
    if (!wire || !out || !prevouts || v6_core_parse(wire, length, &view) != V6_WIRE_OK ||
        view.inputs > SIZE_MAX || count > SIZE_MAX / sizeof *prevouts ||
        count != (size_t)view.inputs || index >= count || index > UINT_MAX ||
        !v6_transparent_prevouts_valid(prevouts, count))
        return ZCL_ERR(-1, "Invalid v6 transparent signature inputs");
    struct transaction tx; struct byte_stream stream; struct script script;
    transaction_init(&tx); stream_init_from_data(&stream, wire, length);
    if (!transaction_v6_decode_prefix(&tx, &stream, length) || stream_remaining(&stream)) {
        transaction_free(&tx);
        return ZCL_ERR(-1, "Cannot decode v6 transparent transaction");
    }
    script_init(&script);
    if (prevouts[index].script_size)
        script_set(&script, prevouts[index].script, prevouts[index].script_size);
    struct sighash_type hash_type = {.raw = type}; struct uint256 result;
    bool ok = transaction_v6_sighash(&tx, prevouts, count, (unsigned)index, hash_type, &script,
        prevouts[index].amount, expected_branch, &result);
    transaction_free(&tx);
    if (!ok) return ZCL_ERR(-1, "Cannot compute v6 transparent signature hash");
    memcpy(out, result.data, 32);
    return ZCL_OK;
}
