/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Token-derived service access. See services/service_token_gate.h for the
 * contract; the short version is that every path here either produces a
 * balance at a stated height that meets a declared threshold, or produces a
 * named denial. There is no third outcome and no "assume granted" branch.
 *
 * This file touches exactly one projection — zslp_ledger — and never the
 * reducer progress lock, the coins store, or any consensus table. That is the
 * ZCL_SERVICE_ISOLATION_NO_CONSENSUS_WRITE / NO_BLOCKING_PROGRESS_LOCK half
 * of the binding contract made structural rather than aspirational: the
 * include list below is the whole authority this evaluator has. */

#include "services/service_token_gate.h"

#include "config/service_binding_catalog.h"
#include "json/json.h"
#include "models/database.h"
#include "models/zslp_ledger.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>

#define GATE_LOG "service.gate"

const char *service_gate_reason_name(enum service_gate_reason reason)
{
    switch (reason) {
    case SERVICE_GATE_REASON_GRANTED: return "granted";
    case SERVICE_GATE_REASON_INVALID_BINDING: return "invalid_binding";
    case SERVICE_GATE_REASON_TOKEN_UNMINTED: return "token_unminted";
    case SERVICE_GATE_REASON_NO_SNAPSHOT: return "no_snapshot";
    case SERVICE_GATE_REASON_LEDGER_UNAVAILABLE: return "ledger_unavailable";
    case SERVICE_GATE_REASON_LEDGER_BEHIND: return "ledger_behind";
    case SERVICE_GATE_REASON_HOLDER_MISSING: return "holder_missing";
    case SERVICE_GATE_REASON_BALANCE_BELOW_THRESHOLD:
        return "balance_below_threshold";
    }
    return "unknown";
}

static void verdict_deny(struct service_gate_verdict *out,
                         enum service_gate_reason reason)
{
    out->granted = false;
    out->reason = reason;
}

static void gate_hex32(const uint8_t in[32], char out[65])
{
    for (size_t i = 0; i < 32; i++)
        (void)snprintf(out + 2 * i, 3, "%02x", in[i]);
    out[64] = '\0';
}

struct zcl_result service_token_gate_evaluate(
    struct node_db *ndb,
    const struct zcl_service_binding_v1 *binding,
    int32_t tip_height,
    const uint8_t address[20],
    struct service_gate_verdict *out)
{
    if (!out)
        return ZCL_ERR(SERVICE_GATE_ERR_ARGUMENT,
                       "gate evaluate: out verdict is NULL");
    memset(out, 0, sizeof(*out));
    out->snapshot_height = -1;
    out->ledger_cursor = -1;
    if (!binding)
        return ZCL_ERR(SERVICE_GATE_ERR_ARGUMENT,
                       "gate evaluate: binding is NULL");
    out->threshold = binding->gate.min_balance;

    if (zcl_service_binding_validate_v1(binding) != ZCL_SERVICE_BINDING_OK) {
        verdict_deny(out, SERVICE_GATE_REASON_INVALID_BINDING);
        return ZCL_OK;
    }
    /* A binding may name a token that does not exist yet — that is a
     * reviewable declaration, never an access grant. */
    if (zcl_service_gate_token_unminted_v1(binding->gate.token_genesis_txid)) {
        verdict_deny(out, SERVICE_GATE_REASON_TOKEN_UNMINTED);
        return ZCL_OK;
    }
    if (!zcl_service_gate_snapshot_height_v1(&binding->gate, tip_height,
                                             &out->snapshot_height)) {
        verdict_deny(out, SERVICE_GATE_REASON_NO_SNAPSHOT);
        return ZCL_OK;
    }
    if (!ndb || !ndb->open) {
        verdict_deny(out, SERVICE_GATE_REASON_LEDGER_UNAVAILABLE);
        return ZCL_OK;
    }

    /* The ledger must have folded PAST the snapshot height, or the balance
     * below is "what has been indexed so far" and not history. */
    int32_t cursor = -1;
    uint8_t digest[32];
    memset(digest, 0, sizeof(digest));
    if (!zslp_ledger_get_cursor(ndb, &cursor, digest)) {
        verdict_deny(out, SERVICE_GATE_REASON_LEDGER_UNAVAILABLE);
        return ZCL_OK;
    }
    out->ledger_cursor = cursor;
    if (cursor < out->snapshot_height) {
        verdict_deny(out, SERVICE_GATE_REASON_LEDGER_BEHIND);
        return ZCL_OK;
    }

    if (binding->gate.holder_kind == ZCL_SERVICE_GATE_HOLDER_ADDRESS) {
        if (!address) {
            verdict_deny(out, SERVICE_GATE_REASON_HOLDER_MISSING);
            return ZCL_OK;
        }
        out->balance = zslp_ledger_balance_at_height(
            ndb, binding->gate.token_genesis_txid, address,
            out->snapshot_height);
    } else {
        out->balance = zslp_ledger_wallet_balance_at_height(
            ndb, binding->gate.token_genesis_txid, out->snapshot_height);
    }

    if (out->balance < 0 || (uint64_t)out->balance < out->threshold) {
        verdict_deny(out, SERVICE_GATE_REASON_BALANCE_BELOW_THRESHOLD);
        return ZCL_OK;
    }
    out->granted = true;
    out->reason = SERVICE_GATE_REASON_GRANTED;
    return ZCL_OK;
}

void service_token_gate_verdict_json(const struct service_gate_verdict *v,
                                     struct json_value *out)
{
    if (!v || !out)
        return;
    (void)json_push_kv_bool(out, "granted", v->granted);
    (void)json_push_kv_str(out, "reason", service_gate_reason_name(v->reason));
    (void)json_push_kv_int(out, "snapshot_height", v->snapshot_height);
    (void)json_push_kv_int(out, "ledger_cursor", v->ledger_cursor);
    (void)json_push_kv_int(out, "balance", v->balance);
    (void)json_push_kv_int(out, "threshold", (int64_t)v->threshold);
    (void)json_push_kv_str(out, "ledger", "zslp_ledger");
}

static void gate_declaration_json(const struct zcl_service_binding_v1 *b,
                                  struct json_value *item)
{
    char token_hex[65];
    gate_hex32(b->gate.token_genesis_txid, token_hex);
    (void)json_push_kv_str(item, "service", b->name);
    (void)json_push_kv_str(item, "token_genesis_txid", token_hex);
    (void)json_push_kv_bool(item, "token_unminted",
                            zcl_service_gate_token_unminted_v1(
                                b->gate.token_genesis_txid));
    (void)json_push_kv_int(item, "min_balance", (int64_t)b->gate.min_balance);
    (void)json_push_kv_str(
        item, "snapshot_kind",
        b->gate.snapshot_kind == ZCL_SERVICE_GATE_SNAPSHOT_FIXED_HEIGHT
            ? "fixed_height" : "confirmed_depth");
    (void)json_push_kv_int(item, "snapshot_param", b->gate.snapshot_param);
    (void)json_push_kv_str(
        item, "holder_kind",
        b->gate.holder_kind == ZCL_SERVICE_GATE_HOLDER_ADDRESS
            ? "address" : "wallet");
}

bool service_token_gate_dump_state_json(struct json_value *out,
                                        const char *key)
{
    if (!out)
        LOG_RETURN(false, GATE_LOG, "dump_state: out is NULL");
    json_set_object(out);
    (void)json_push_kv_str(out, "schema", ZCL_SERVICE_BINDING_SCHEMA_NAME);
    (void)json_push_kv_str(out, "ledger", "zslp_ledger");

    size_t count = 0;
    const struct zcl_service_binding_v1 *catalog =
        zcl_service_binding_catalog_v1(&count);
    struct json_value gates;
    json_init(&gates);
    json_set_array(&gates);
    size_t shown = 0;
    for (size_t i = 0; i < count; i++) {
        if (key && key[0] && strcmp(key, catalog[i].name) != 0)
            continue;
        struct json_value item;
        json_init(&item);
        json_set_object(&item);
        gate_declaration_json(&catalog[i], &item);
        (void)json_push_back(&gates, &item);
        json_free(&item);
        shown++;
    }
    (void)json_push_kv(out, "gates", &gates);
    (void)json_push_kv_int(out, "declared", (int64_t)count);
    (void)json_push_kv_int(out, "shown", (int64_t)shown);
    json_free(&gates);
    return true;
}
