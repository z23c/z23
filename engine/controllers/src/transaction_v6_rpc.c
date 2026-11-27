/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Render research v6 transaction inspection for the decoder RPC.
 */
#include "controllers/transaction_v6_rpc.h"
#include "controllers/transaction_v6_digest.h"
#include "core/core_io.h"
#include "base/serialize_le.h"
#include "util/safe_alloc.h"
#include "core/serialize.h"
#include "encoding/utilstrencodings.h"
#include "primitives/transaction.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Limit the legacy renderer array allocation independently of wire length. */
enum { V6_WIRE_LIMIT = 2000000, V6_RENDER_MEMORY = 32 * 1024 * 1024 };
static bool field_has_type(const struct json_value *object, const char *name, enum json_type type)
{
    const struct json_value *value = json_get(object, name);
    return value && value->type == type;
}
static bool rendered_input(const struct json_value *item)
{
    if (!field_has_type(item, "sequence", JSON_INT)) return false;
    if (field_has_type(item, "coinbase", JSON_STR)) return true;
    const struct json_value *script = json_get(item, "scriptSig");
    return field_has_type(item, "txid", JSON_STR) &&
        field_has_type(item, "vout", JSON_INT) &&
        field_has_type(script, "asm", JSON_STR) &&
        field_has_type(script, "hex", JSON_STR);
}
static bool rendered_output(const struct json_value *item)
{
    const struct json_value *script = json_get(item, "scriptPubKey");
    return field_has_type(item, "value", JSON_STR) &&
        field_has_type(item, "n", JSON_INT) &&
        field_has_type(script, "asm", JSON_STR) &&
        field_has_type(script, "hex", JSON_STR) &&
        field_has_type(script, "type", JSON_STR);
}
static bool rendered_complete(const struct json_value *entry, const struct v6_wire_view *view)
{
    const struct json_value *vin = json_get(entry, "vin");
    const struct json_value *vout = json_get(entry, "vout");
    if (!vin || vin->type != JSON_ARR || json_size(vin) != view->inputs ||
        !vout || vout->type != JSON_ARR || json_size(vout) != view->outputs ||
        !field_has_type(entry, "locktime", JSON_INT)) return false;
    for (size_t i = 0; i < json_size(vin); ++i)
        if (!rendered_input(json_at(vin, i))) return false;
    for (size_t i = 0; i < json_size(vout); ++i)
        if (!rendered_output(json_at(vout, i))) return false;
    return true;
}

static bool within_render_budget(const struct v6_wire_view *view)
{
    return view->inputs <= V6_RENDER_MEMORY / sizeof(struct tx_in) &&
        view->outputs <= V6_RENDER_MEMORY / sizeof(struct tx_out) &&
        view->inputs * sizeof(struct tx_in) + view->outputs * sizeof(struct tx_out) <= V6_RENDER_MEMORY;
}

static bool render_transparent(const struct v6_wire_view *view, struct json_value *entry)
{
    struct byte_stream wire;
    stream_init(&wire, view->transparent.size + 8);
    bool ok = stream_write_u32_le(&wire, 1) &&
        stream_write(&wire, view->transparent.data, view->transparent.size) &&
        stream_write(&wire, view->header.data + 12, 4);
    struct transaction tx;
    transaction_init(&tx);
    struct byte_stream input;
    stream_init_from_data(&input, wire.data, wire.size);
    if (ok) ok = transaction_deserialize(&tx, &input) && !stream_remaining(&input);
    if (ok) {
        struct uint256 null_hash;
        uint256_set_null(&null_hash);
        tx_to_json(&tx, &null_hash, entry);
        ok = rendered_complete(entry, view);
    }
    transaction_free(&tx);
    stream_free(&wire);
    return ok;
}
static bool add_pool_counts(struct json_value *result, const struct v6_wire_view *view)
{
    return json_push_kv_int(result, "sapling_spends", (int64_t)view->sapling_spends.count) &&
        json_push_kv_int(result, "sapling_outputs", (int64_t)view->sapling_outputs.count) &&
        json_push_kv_int(result, "orchard_actions", (int64_t)view->orchard.count) &&
        json_push_kv_int(result, "ironwood_actions", (int64_t)view->ironwood.count);
}

static bool add_fields(const char *hex, const struct v6_wire_view *view,
                       const struct v6_digests *digests, struct json_value *transparent,
                       struct json_value *result)
{
    struct uint256 hash;
    memcpy(hash.data, digests->txid, sizeof hash.data);
    char txid[65], auth[65];
    char group[9], branch[9];
    (void)snprintf(group, sizeof group, "%08" PRIx32, zcl_read_u32_le(view->header.data + 4));
    (void)snprintf(branch, sizeof branch, "%08" PRIx32, zcl_read_u32_le(view->header.data + 8));
    uint256_get_hex(&hash, txid);
    HexStr(digests->auth, sizeof digests->auth, false, auth, sizeof auth);
    const struct json_value *vin = json_get(transparent, "vin");
    const struct json_value *vout = json_get(transparent, "vout");
    const struct json_value *locktime = json_get(transparent, "locktime");
    if (!vin || !vout || !locktime) return false;
    json_set_object(result);
    return json_push_kv_str(result, "txid", txid) &&
        json_push_kv_str(result, "authdigest", auth) &&
        json_push_kv_int(result, "version", 6) &&
        json_push_kv_str(result, "versiongroupid", group) &&
        json_push_kv_str(result, "consensusbranchid", branch) &&
        json_push_kv_int(result, "expiryheight", zcl_read_u32_le(view->header.data + 16)) &&
        json_push_kv(result, "locktime", locktime) &&
        json_push_kv(result, "vin", vin) && json_push_kv(result, "vout", vout) &&
        json_push_kv_str(result, "hex", hex) && add_pool_counts(result, view);
}
enum v6_rpc_status transaction_v6_rpc_decode(const char *hex, struct json_value *result)
{
    if (!hex || !result) return V6_RPC_INVALID;
    size_t len = strlen(hex);
    if (len > 2 * V6_WIRE_LIMIT) return V6_RPC_RESOURCE;
    if (!len || !IsHex(hex)) return V6_RPC_INVALID;
    size_t size = len / 2;
    uint8_t *bytes = zcl_malloc(size, "v6_rpc_wire");
    if (!bytes) return V6_RPC_RESOURCE;
    struct v6_wire_view view;
    struct v6_digests digests;
    bool ok = ParseHex(hex, bytes, size) == size &&
        v6_wire_parse(bytes, size, &view) == V6_WIRE_OK &&
        v6_wire_digests(&view, &digests);
    if (!ok) {
        free(bytes);
        return V6_RPC_INVALID;
    }
    if (!within_render_budget(&view)) {
        free(bytes);
        return V6_RPC_RESOURCE;
    }
    struct json_value transparent;
    json_init(&transparent);
    if (ok) ok = render_transparent(&view, &transparent);
    if (ok) ok = add_fields(hex, &view, &digests, &transparent, result);
    json_free(&transparent);
    free(bytes);
    return ok ? V6_RPC_OK : V6_RPC_RESOURCE;
}
