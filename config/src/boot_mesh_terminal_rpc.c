/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Nonblocking mesh terminal client RPC adapter. Mirrors the
 * boot_mesh_status_rpc.c begin/poll precedent: open reserves one bounded
 * client session and returns its terminal id; poll reports the honest
 * state machine; read drains bounded pending output; write sends bounded
 * keyboard DATA; resize and close are best-effort verbs on a live
 * session. */

#include "config/boot_mesh_terminal.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "rpc/server.h"
#include "util/log_macros.h"

#include <stdlib.h>
#include <string.h>

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

static bool input_u64(const struct json_value *in, const char *key,
                      uint64_t *out)
{
    const struct json_value *value = in ? json_get(in, key) : NULL;
    if (!value || value->type != JSON_INT)
        return false;
    *out = (uint64_t)json_get_int(value);
    return true;
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

static bool rpc_mesh_terminal_open(const struct json_value *params, bool help,
                                   struct json_value *result)
{
    if (help) {
        json_set_str(result,
                     "mesh_terminal_open {\"pairing_id\":\"<64 lowercase "
                     "hex>\",\"cols\":80,\"rows\":24}");
        return true;
    }
    const struct json_value *in = rpc_input(params);
    const char *pairing_id = input_str(in, "pairing_id");
    if (!pairing_id || strlen(pairing_id) != 64) {
        rpc_error(result, "INVALID_PAIRING_ID",
                  "pairing_id must be 64 canonical lowercase hex chars");
        return true;
    }
    uint64_t cols = 0, rows = 0;
    (void)input_u64(in, "cols", &cols);
    (void)input_u64(in, "rows", &rows);
    if (cols > MESH_TERMINAL_MAX_COLS || rows > MESH_TERMINAL_MAX_ROWS) {
        rpc_error(result, "INVALID_GEOMETRY",
                  "cols/rows exceed the protocol geometry ceiling");
        return true;
    }
    uint8_t terminal_id[32];
    enum boot_mesh_terminal_open_result opened =
        boot_mesh_terminal_client_open(pairing_id, (uint16_t)cols,
                                       (uint16_t)rows, terminal_id);
    if (opened != MESH_TERMINAL_OPEN_OK) {
        const char *message;
        switch (opened) {
        case MESH_TERMINAL_OPEN_NOT_PAIRED:
            message = "no local pairing record authorizes that peer";
            break;
        case MESH_TERMINAL_OPEN_REVOKED:
            message = "the pairing is revoked";
            break;
        case MESH_TERMINAL_OPEN_EXPIRED:
            message = "the pairing has expired";
            break;
        case MESH_TERMINAL_OPEN_PEER_NOT_CONNECTED:
            message = "the paired peer has no established Noise session; no "
                      "dial is attempted";
            break;
        case MESH_TERMINAL_OPEN_NOISE_DISABLED:
            message = "the Noise transport is disabled on this node";
            break;
        case MESH_TERMINAL_OPEN_IDENTITY_UNAVAILABLE:
            message = "this node's filed ZID delegation is unavailable";
            break;
        case MESH_TERMINAL_OPEN_PEER_IDENTITY_UNAVAILABLE:
            message = "the paired peer has no unique active ZID delegation "
                      "that authorizes this pairing";
            break;
        case MESH_TERMINAL_OPEN_BUSY:
            message = "the bounded client session table is full";
            break;
        case MESH_TERMINAL_OPEN_SEND_FAILED:
            message = "the peer send queue refused the open frame";
            break;
        default:
            message = "the mesh terminal lane is unavailable";
            break;
        }
        rpc_error(result, boot_mesh_terminal_open_result_string(opened),
                  message);
        return true;
    }
    char terminal_hex[65];
    zcl_hex_encode(terminal_id, 32, terminal_hex);
    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    json_push_kv_str(result, "state", "opening");
    json_push_kv_str(result, "terminal_id", terminal_hex);
    json_push_kv_str(result, "pairing_id", pairing_id);
    json_push_kv_int(result, "receipt_timeout_seconds",
                     MESH_TERMINAL_CLIENT_RECEIPT_TIMEOUT_SECONDS);
    return true;
}

/* Honest state machine view: OPENING waits for the OK receipt inside the
 * answer window; LIVE pumps; REFUSED carries the named receipt verdict;
 * ENDED carries the verdict plus a locally named close reason when one
 * exists (a CLOSED receipt's reason lives in its evidence capsule on the
 * responder). The receipt reached this point only after signature,
 * open-binding, session-binding, and responder-identity verification. */
static void client_view_json(struct json_value *result,
                             enum boot_mesh_terminal_client_state state,
                             const struct boot_mesh_terminal_client_view
                                 *view)
{
    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    json_push_kv_str(result, "state",
                     boot_mesh_terminal_client_state_string(state));
    if (state == MESH_TERMINAL_CLIENT_REFUSED ||
        state == MESH_TERMINAL_CLIENT_ENDED)
        json_push_kv_str(result, "verdict",
                         mesh_terminal_receipt_status_string(view->verdict));
    if (state == MESH_TERMINAL_CLIENT_ENDED && view->close_reason_named)
        json_push_kv_str(result, "close_reason",
                         mesh_terminal_close_reason_string(
                             view->close_reason));
    json_push_kv_int(result, "cols", (int64_t)view->cols);
    json_push_kv_int(result, "rows", (int64_t)view->rows);
    json_push_kv_int(result, "bytes_in", (int64_t)view->bytes_in);
    json_push_kv_int(result, "bytes_out", (int64_t)view->bytes_out);
    json_push_kv_int(result, "output_pending", (int64_t)view->output_pending);
    json_push_kv_int(result, "idle_seconds", (int64_t)view->idle_seconds);
}

static bool rpc_mesh_terminal_poll(const struct json_value *params, bool help,
                                   struct json_value *result)
{
    if (help) {
        json_set_str(result,
                     "mesh_terminal_poll {\"terminal_id\":\"<64 lowercase "
                     "hex>\"}");
        return true;
    }
    const struct json_value *in = rpc_input(params);
    uint8_t terminal_id[32];
    if (!input_hex32(in, "terminal_id", terminal_id)) {
        rpc_error(result, "INVALID_TERMINAL_ID",
                  "terminal_id must be 64 canonical lowercase hex chars");
        return true;
    }
    struct boot_mesh_terminal_client_view view;
    enum boot_mesh_terminal_client_state state =
        boot_mesh_terminal_client_poll(terminal_id, &view);
    switch (state) {
    case MESH_TERMINAL_CLIENT_UNKNOWN:
        rpc_error(result, "TERMINAL_UNKNOWN",
                  "terminal_id is unknown or from a previous run");
        return true;
    default:
        client_view_json(result, state, &view);
        return true;
    }
}

static bool rpc_mesh_terminal_read(const struct json_value *params, bool help,
                                   struct json_value *result)
{
    if (help) {
        json_set_str(result,
                     "mesh_terminal_read {\"terminal_id\":\"<64 lowercase "
                     "hex>\",\"max_bytes\":8192}");
        return true;
    }
    const struct json_value *in = rpc_input(params);
    uint8_t terminal_id[32];
    if (!input_hex32(in, "terminal_id", terminal_id)) {
        rpc_error(result, "INVALID_TERMINAL_ID",
                  "terminal_id must be 64 canonical lowercase hex chars");
        return true;
    }
    uint64_t max_bytes = 8192;
    (void)input_u64(in, "max_bytes", &max_bytes);
    if (max_bytes == 0 || max_bytes > MESH_TERMINAL_CLIENT_OUTPUT_MAX)
        max_bytes = MESH_TERMINAL_CLIENT_OUTPUT_MAX;

    /* Poll first: watchdogs must run even when the reader only drains. */
    struct boot_mesh_terminal_client_view view;
    enum boot_mesh_terminal_client_state state =
        boot_mesh_terminal_client_poll(terminal_id, &view);
    if (state == MESH_TERMINAL_CLIENT_UNKNOWN) {
        rpc_error(result, "TERMINAL_UNKNOWN",
                  "terminal_id is unknown or from a previous run");
        return true;
    }
    uint8_t *buffer = zcl_malloc(max_bytes, "mesh_terminal_rpc.read");
    if (!buffer) {
        rpc_error(result, "READ_ALLOC_FAILED",
                  "the output drain buffer could not be allocated");
        return true;
    }
    size_t moved =
        boot_mesh_terminal_client_drain(terminal_id, buffer,
                                        (size_t)max_bytes);
    char *hex = NULL;
    if (moved) {
        hex = zcl_malloc(moved * 2u + 1u, "mesh_terminal_rpc.read_hex");
        if (hex)
            zcl_hex_encode(buffer, moved, hex);
    }
    free(buffer);
    if (moved && !hex) {
        rpc_error(result, "READ_ALLOC_FAILED",
                  "the output hex buffer could not be allocated");
        return true;
    }
    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    json_push_kv_str(result, "state",
                     boot_mesh_terminal_client_state_string(state));
    json_push_kv_int(result, "output_bytes", (int64_t)moved);
    if (hex) {
        json_push_kv_str(result, "output_hex", hex);
        free(hex);
    }
    json_push_kv_int(result, "output_pending", (int64_t)view.output_pending);
    return true;
}

static bool rpc_mesh_terminal_write(const struct json_value *params,
                                    bool help, struct json_value *result)
{
    if (help) {
        json_set_str(result,
                     "mesh_terminal_write {\"terminal_id\":\"<64 lowercase "
                     "hex>\",\"input_hex\":\"<hex bytes>\"}");
        return true;
    }
    const struct json_value *in = rpc_input(params);
    uint8_t terminal_id[32];
    if (!input_hex32(in, "terminal_id", terminal_id)) {
        rpc_error(result, "INVALID_TERMINAL_ID",
                  "terminal_id must be 64 canonical lowercase hex chars");
        return true;
    }
    const char *input_hex = input_str(in, "input_hex");
    size_t hex_len = input_hex ? strlen(input_hex) : 0;
    if (hex_len % 2u != 0 ||
        hex_len / 2u > MESH_TERMINAL_SERVICE_MAX_BYTES_IN) {
        rpc_error(result, "INVALID_INPUT",
                  "input_hex must be even-length hex within the session "
                  "keyboard budget");
        return true;
    }
    if (hex_len == 0) {
        rpc_error(result, "INVALID_INPUT", "input_hex is empty");
        return true;
    }
    size_t len = hex_len / 2u;
    uint8_t *bytes = zcl_malloc(len, "mesh_terminal_rpc.write");
    if (!bytes || !zcl_hex_decode_lower(input_hex, bytes, len)) {
        free(bytes);
        rpc_error(result, "INVALID_INPUT",
                  "input_hex is not valid lowercase hex");
        return true;
    }
    bool sent = boot_mesh_terminal_client_write(terminal_id, bytes, len);
    free(bytes);
    if (!sent) {
        rpc_error(result, "WRITE_REFUSED",
                  "the session is not live, the peer session is gone, or "
                  "the keyboard budget is exhausted");
        return true;
    }
    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    json_push_kv_int(result, "bytes_sent", (int64_t)len);
    return true;
}

static bool rpc_mesh_terminal_resize(const struct json_value *params,
                                     bool help, struct json_value *result)
{
    if (help) {
        json_set_str(result,
                     "mesh_terminal_resize {\"terminal_id\":\"<64 lowercase "
                     "hex>\",\"cols\":80,\"rows\":24}");
        return true;
    }
    const struct json_value *in = rpc_input(params);
    uint8_t terminal_id[32];
    if (!input_hex32(in, "terminal_id", terminal_id)) {
        rpc_error(result, "INVALID_TERMINAL_ID",
                  "terminal_id must be 64 canonical lowercase hex chars");
        return true;
    }
    uint64_t cols = 0, rows = 0;
    if (!input_u64(in, "cols", &cols) || !input_u64(in, "rows", &rows) ||
        cols == 0 || cols > MESH_TERMINAL_MAX_COLS || rows == 0 ||
        rows > MESH_TERMINAL_MAX_ROWS) {
        rpc_error(result, "INVALID_GEOMETRY",
                  "cols/rows must be within the protocol geometry ceiling");
        return true;
    }
    if (!boot_mesh_terminal_client_resize(terminal_id, (uint16_t)cols,
                                          (uint16_t)rows)) {
        rpc_error(result, "RESIZE_REFUSED",
                  "the session is not live or the peer session is gone");
        return true;
    }
    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    return true;
}

static bool rpc_mesh_terminal_close(const struct json_value *params, bool help,
                                    struct json_value *result)
{
    if (help) {
        json_set_str(result,
                     "mesh_terminal_close {\"terminal_id\":\"<64 lowercase "
                     "hex>\"}");
        return true;
    }
    const struct json_value *in = rpc_input(params);
    uint8_t terminal_id[32];
    if (!input_hex32(in, "terminal_id", terminal_id)) {
        rpc_error(result, "INVALID_TERMINAL_ID",
                  "terminal_id must be 64 canonical lowercase hex chars");
        return true;
    }
    if (!boot_mesh_terminal_client_close(terminal_id)) {
        rpc_error(result, "TERMINAL_UNKNOWN",
                  "terminal_id is unknown or from a previous run");
        return true;
    }
    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    json_push_kv_str(result, "state", "ended");
    return true;
}

void boot_mesh_terminal_register_rpc(struct rpc_table *table)
{
    if (!table) {
        LOG_ERROR("net.mesh_terminal", "RPC registration requires rpc_table");
        return;
    }
    const struct rpc_command commands[] = {
        {"mesh", "mesh_terminal_open", rpc_mesh_terminal_open, true},
        {"mesh", "mesh_terminal_poll", rpc_mesh_terminal_poll, true},
        {"mesh", "mesh_terminal_read", rpc_mesh_terminal_read, true},
        {"mesh", "mesh_terminal_write", rpc_mesh_terminal_write, true},
        {"mesh", "mesh_terminal_resize", rpc_mesh_terminal_resize, true},
        {"mesh", "mesh_terminal_close", rpc_mesh_terminal_close, true},
    };
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++)
        rpc_table_must_append(table, &commands[i]);
}
