/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Nonblocking mesh status request/poll RPC adapter.
 * Mirrors the boot_zcode_dht_rpc.c begin/poll precedent: begin admits a
 * bounded pending request and returns its request id; poll reports the
 * honest state machine and, once terminal, the verified receipt view. */

#include "config/boot_mesh_machines.h"
#include "config/boot_mesh_status.h"
#include "config/db_service.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "net/v2_identity.h"
#include "platform/time_compat.h"
#include "rpc/server.h"
#include "session/mesh_status_proto.h"
#include "util/log_macros.h"

#include <stdlib.h>
#include <string.h>

static struct node_db *g_mesh_status_ndb;
static struct db_service *g_mesh_status_dbsvc;

static const struct json_value *rpc_input(const struct json_value *params)
{
    const struct json_value *first =
        params && json_size(params) ? json_at(params, 0) : NULL;
    return first && first->type == JSON_OBJ ? first : NULL;
}

static const char *input_str(const struct json_value *in, const char *key)
{
    const struct json_value *value = in ? json_get(in, key) : NULL;
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static void rpc_error(struct json_value *result, const char *code,
                      const char *message)
{
    json_set_object(result);
    json_push_kv_bool(result, "ok", false);
    json_push_kv_str(result, "code", code);
    json_push_kv_str(result, "message", message);
}

static bool input_hex32(const struct json_value *in, const char *key,
                        uint8_t out[32])
{
    const char *hex = input_str(in, key);
    memset(out, 0, 32);
    return hex && strlen(hex) == 64 && zcl_hex_decode_lower(hex, out, 32);
}

static bool rpc_mesh_status_request(const struct json_value *params, bool help,
                                    struct json_value *result)
{
    if (help) {
        json_set_str(result,
                     "mesh_status_request {\"pairing_id\":\"<64 lowercase hex>\"}");
        return true;
    }
    const struct json_value *in = rpc_input(params);
    const char *pairing_id = input_str(in, "pairing_id");
    if (!pairing_id || strlen(pairing_id) != 64) {
        rpc_error(result, "INVALID_PAIRING_ID",
                  "pairing_id must be 64 canonical lowercase hex chars");
        return true;
    }
    uint8_t request_id[32];
    enum boot_mesh_status_begin_result began =
        boot_mesh_status_begin(pairing_id, request_id);
    if (began != MESH_STATUS_BEGIN_OK) {
        const char *message;
        switch (began) {
        case MESH_STATUS_BEGIN_NOT_PAIRED:
            message = "no local pairing record authorizes that peer";
            break;
        case MESH_STATUS_BEGIN_REVOKED:
            message = "the pairing is revoked";
            break;
        case MESH_STATUS_BEGIN_EXPIRED:
            message = "the pairing has expired";
            break;
        case MESH_STATUS_BEGIN_PEER_NOT_CONNECTED:
            message = "the paired peer has no established v2 session; no "
                      "dial is attempted";
            break;
        case MESH_STATUS_BEGIN_V2_DISABLED:
            message = "the v2 Noise transport is disabled on this node";
            break;
        case MESH_STATUS_BEGIN_IDENTITY_UNAVAILABLE:
            message = "this node's filed ZID delegation is unavailable";
            break;
        case MESH_STATUS_BEGIN_PEER_IDENTITY_UNAVAILABLE:
            message = "the paired peer has no unique active ZID delegation "
                      "bound to this Noise session";
            break;
        case MESH_STATUS_BEGIN_BUSY:
            message = "the bounded pending-request table is full";
            break;
        case MESH_STATUS_BEGIN_SEND_FAILED:
            message = "the peer send queue refused the request frame";
            break;
        default:
            message = "the mesh status lane is unavailable";
            break;
        }
        rpc_error(result, boot_mesh_status_begin_result_string(began),
                  message);
        return true;
    }
    char request_hex[65];
    zcl_hex_encode(request_id, 32, request_hex);
    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    json_push_kv_str(result, "state", "pending");
    json_push_kv_str(result, "request_id", request_hex);
    json_push_kv_str(result, "pairing_id", pairing_id);
    json_push_kv_int(result, "expires_in_seconds",
                     MESH_STATUS_REQUEST_LIFETIME_SECONDS);
    return true;
}

/* Terminal receipt view: status token, responder identity fingerprints,
 * times, and the decoded capsule JSON. The receipt reached this point only
 * after signature, request-binding, session-binding, and responder-identity
 * verification. Fingerprints come from the lane's one shared implementation
 * so they match the fleet view exactly. */
static void receipt_view_json(struct json_value *result,
                              const struct mesh_status_receipt_v1 *receipt)
{
    char hex[65];
    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    json_push_kv_str(result, "state", receipt->status == MESH_STATUS_RECEIPT_OK
                                          ? "ok"
                                          : "refused");
    json_push_kv_str(result, "status",
                     mesh_status_receipt_status_string(receipt->status));
    zcl_hex_encode(receipt->request_id, 32, hex);
    json_push_kv_str(result, "request_id", hex);
    zcl_hex_encode(receipt->pairing_id, 32, hex);
    json_push_kv_str(result, "pairing_id", hex);
    boot_mesh_status_key_fingerprint("zcl.mesh.master.fingerprint.v1",
                                     receipt->responder_master_pubkey, hex);
    json_push_kv_str(result, "responder_master_fingerprint", hex);
    boot_mesh_status_key_fingerprint("zcl.mesh.online.fingerprint.v1",
                                     receipt->responder_online_pubkey, hex);
    json_push_kv_str(result, "responder_online_fingerprint", hex);
    uint8_t fingerprint[32];
    if (v2_identity_public_fingerprint(receipt->responder_noise_static,
                                       fingerprint)) {
        zcl_hex_encode(fingerprint, 32, hex);
        json_push_kv_str(result, "responder_noise_fingerprint_sha3", hex);
    }
    zcl_hex_encode(receipt->capsule_root, 32, hex);
    json_push_kv_str(result, "capsule_root", hex);
    json_push_kv_int(result, "connection_generation",
                     (int64_t)receipt->connection_generation);
    json_push_kv_int(result, "revocation_generation",
                     (int64_t)receipt->revocation_generation);
    json_push_kv_int(result, "observed_unix", (int64_t)receipt->observed_unix);
    json_push_kv_int(result, "expires_unix", (int64_t)receipt->expires_unix);
    if (receipt->status == MESH_STATUS_RECEIPT_OK && receipt->capsule_len) {
        struct json_value capsule;
        json_init(&capsule);
        if (json_read(&capsule, (const char *)receipt->capsule,
                      receipt->capsule_len)) {
            json_push_kv(result, "capsule", &capsule);
            json_free(&capsule);
        } else {
            json_free(&capsule);
            /* A verified OK receipt whose capsule does not parse is a
             * responder defect; say so rather than dropping the field. */
            json_push_kv_bool(result, "capsule_json_valid", false);
        }
    }
}

#ifdef ZCL_TESTING
void boot_mesh_status_receipt_test_render(
    struct json_value *result, const struct mesh_status_receipt_v1 *receipt)
{
    receipt_view_json(result, receipt);
}

/* The fleet render moved to boot_mesh_machines_rpc.c with the unified
 * surface; this hook forwards with no live-probe sidecar, so tests observe
 * exactly the durable-evidence document. */
void boot_mesh_status_machines_test_render(
    struct node_db *ndb, int64_t now, struct json_value *result)
{
    boot_mesh_machines_render(ndb, now, NULL, result);
}
#endif

static bool rpc_mesh_status_poll(const struct json_value *params, bool help,
                                 struct json_value *result)
{
    if (help) {
        json_set_str(result,
                     "mesh_status_poll {\"request_id\":\"<64 lowercase hex>\"}");
        return true;
    }
    const struct json_value *in = rpc_input(params);
    uint8_t request_id[32];
    if (!input_hex32(in, "request_id", request_id)) {
        rpc_error(result, "INVALID_REQUEST_ID",
                  "request_id must be 64 canonical lowercase hex chars");
        return true;
    }
    struct mesh_status_receipt_v1 receipt;
    switch (boot_mesh_status_poll(request_id, &receipt)) {
    case MESH_STATUS_POLL_UNKNOWN:
        rpc_error(result, "REQUEST_UNKNOWN",
                  "request_id is unknown, expired, or from a previous run");
        return true;
    case MESH_STATUS_POLL_PENDING:
        json_set_object(result);
        json_push_kv_bool(result, "ok", true);
        json_push_kv_str(result, "state", "pending");
        return true;
    case MESH_STATUS_POLL_EXPIRED:
        json_set_object(result);
        json_push_kv_bool(result, "ok", true);
        json_push_kv_str(result, "state", "expired");
        return true;
    case MESH_STATUS_POLL_OK:
    case MESH_STATUS_POLL_REFUSED:
        if (!boot_mesh_status_receipt_persist(g_mesh_status_dbsvc, &receipt)) {
            rpc_error(result, "OBSERVATION_PERSIST_FAILED",
                      "the verified receipt could not be stored durably");
            return true;
        }
        receipt_view_json(result, &receipt);
        return true;
    }
    rpc_error(result, "REQUEST_UNKNOWN", "unreachable poll state");
    return true;
}

void boot_mesh_status_register_rpc(struct rpc_table *table,
                                   struct node_db *ndb,
                                   struct db_service *dbsvc)
{
    if (!table || !ndb || !dbsvc) {
        LOG_ERROR("net.mesh_status",
                  "RPC registration requires node_db and db_service");
        return;
    }
    g_mesh_status_ndb = ndb;
    g_mesh_status_dbsvc = dbsvc;
    const struct rpc_command commands[] = {
        {"mesh", "mesh_status_request", rpc_mesh_status_request, true},
        {"mesh", "mesh_status_poll", rpc_mesh_status_poll, true},
    };
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++)
        rpc_table_must_append(table, &commands[i]);
}
