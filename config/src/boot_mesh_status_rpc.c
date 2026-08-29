/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Nonblocking mesh status request/poll RPC adapter.
 * Mirrors the boot_zcode_dht_rpc.c begin/poll precedent: begin admits a
 * bounded pending request and returns its request id; poll reports the
 * honest state machine and, once terminal, the verified receipt view. */

#include "config/boot_mesh_status.h"
#include "config/db_service.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "crypto/sha3.h"
#include "json/json.h"
#include "models/mesh_machine_observation.h"
#include "net/v2_identity.h"
#include "platform/time_compat.h"
#include "rpc/server.h"
#include "session/mesh_status_proto.h"
#include "util/log_macros.h"

#include <stdlib.h>
#include <string.h>

static struct node_db *g_mesh_status_ndb;
static struct db_service *g_mesh_status_dbsvc;

#define MESH_MACHINES_VIEW_MAX 16u

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
 * verification. */
static void receipt_fingerprint(const char *domain, const uint8_t key[32],
                                char out[65])
{
    struct sha3_256_ctx hash;
    uint8_t digest[32];
    sha3_256_init(&hash);
    sha3_256_write(&hash, (const uint8_t *)domain, strlen(domain));
    sha3_256_write(&hash, key, 32);
    sha3_256_finalize(&hash, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
}

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
    receipt_fingerprint("zcl.mesh.master.fingerprint.v1",
                        receipt->responder_master_pubkey, hex);
    json_push_kv_str(result, "responder_master_fingerprint", hex);
    receipt_fingerprint("zcl.mesh.online.fingerprint.v1",
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

static const char *mesh_pairing_state(const struct db_mesh_pairing *pairing,
                                      int64_t now)
{
    if (pairing->revoked_at != 0)
        return "revoked";
    return now < pairing->expires_at ? "active" : "expired";
}

static void mesh_machine_json(struct json_value *array,
                              const struct db_mesh_machine_view *view,
                              int64_t now, bool *fresh_out)
{
    struct json_value item;
    json_init(&item);
    json_set_object(&item);
    const char *pairing_state = mesh_pairing_state(&view->pairing, now);
    bool fresh = view->has_observation &&
                 strcmp(pairing_state, "active") == 0 &&
                 now < view->observation.expires_unix;
    char hex[65];
    json_push_kv_str(&item, "pairing_id", view->pairing.pairing_id);
    json_push_kv_str(&item, "pairing_state", pairing_state);
    receipt_fingerprint("zcl.mesh.master.fingerprint.v1",
                        view->pairing.peer_master_pubkey, hex);
    json_push_kv_str(&item, "peer_master_fingerprint", hex);
    receipt_fingerprint("zcl.mesh.noise.fingerprint.v1",
                        view->pairing.peer_noise_pubkey, hex);
    json_push_kv_str(&item, "peer_noise_fingerprint", hex);
    json_push_kv_str(&item, "observation_state",
                     !view->has_observation ? "unknown"
                                            : fresh ? "fresh" : "stale");
    if (view->has_observation) {
        json_push_kv_str(
            &item, "receipt_status",
            mesh_status_receipt_status_string(view->observation.status));
        json_push_kv_int(&item, "observed_unix",
                         view->observation.observed_unix);
        json_push_kv_int(&item, "expires_unix",
                         view->observation.expires_unix);
        json_push_kv_int(&item, "received_unix",
                         view->observation.received_unix);
        zcl_hex_encode(view->observation.receipt_root, 32, hex);
        json_push_kv_str(&item, "receipt_root", hex);
    }
    (void)json_push_back(array, &item);
    json_free(&item);
    *fresh_out = fresh;
}

static void mesh_machines_render(struct node_db *ndb, int64_t now,
                                 struct json_value *result)
{
    size_t capacity = MESH_MACHINES_VIEW_MAX;
    struct db_mesh_machine_view *views = zcl_calloc(
        capacity, sizeof(*views), "mesh_machines.views");
    if (!views || !ndb || now <= 0) {
        free(views);
        rpc_error(result, "OBSERVATION_UNAVAILABLE",
                  "the durable machine projection is unavailable");
        return;
    }
    struct db_mesh_pairing_counts pairing_counts;
    int count = db_mesh_machine_observation_list(ndb, views, capacity, now);
    if (count < 0 ||
        !db_mesh_pairing_count_states(ndb, now, &pairing_counts)) {
        free(views);
        rpc_error(result, "OBSERVATION_UNAVAILABLE",
                  "the durable pairing count is unavailable");
        return;
    }
    size_t shown = (size_t)count;
    bool truncated = pairing_counts.total > (int64_t)shown;
    struct json_value machines;
    json_init(&machines);
    json_set_array(&machines);
    int64_t fresh = 0, stale = 0, unknown = 0;
    for (size_t i = 0; i < shown; i++) {
        bool is_fresh = false;
        mesh_machine_json(&machines, &views[i], now, &is_fresh);
        if (!views[i].has_observation)
            unknown++;
        else if (is_fresh)
            fresh++;
        else
            stale++;
    }
    free(views);
    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    json_push_kv_str(result, "schema", "zcl.mesh.machines.v1");
    json_push_kv_int(result, "observed_at", now);
    json_push_kv_int(result, "total", pairing_counts.total);
    json_push_kv_int(result, "active", pairing_counts.active);
    json_push_kv_int(result, "returned", (int64_t)shown);
    json_push_kv_int(result, "returned_fresh", fresh);
    json_push_kv_int(result, "returned_stale", stale);
    json_push_kv_int(result, "returned_unknown", unknown);
    json_push_kv_bool(result, "truncated", truncated);
    json_push_kv(result, "machines", &machines);
    json_free(&machines);
}

static bool rpc_mesh_machines(const struct json_value *params, bool help,
                              struct json_value *result)
{
    if (help) {
        json_set_str(result, "mesh_machines\n");
        return true;
    }
    if (rpc_input(params)) {
        rpc_error(result, "INVALID_ARGUMENT",
                  "mesh_machines accepts no input");
        return true;
    }
    mesh_machines_render(g_mesh_status_ndb,
                         (int64_t)platform_time_wall_time_t(), result);
    return true;
}

#ifdef ZCL_TESTING
void boot_mesh_status_receipt_test_render(
    struct json_value *result, const struct mesh_status_receipt_v1 *receipt)
{
    receipt_view_json(result, receipt);
}

void boot_mesh_status_machines_test_render(
    struct node_db *ndb, int64_t now, struct json_value *result)
{
    mesh_machines_render(ndb, now, result);
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
        {"mesh", "mesh_machines", rpc_mesh_machines, true},
    };
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++)
        rpc_table_must_append(table, &commands[i]);
}
