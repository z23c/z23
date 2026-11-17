/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The `fleet_board_ingest` RPC — the node-side insertion of one
 * RAW signed board post frame fetched by a first-contact discovery client
 * (`app discover --offer`). There is exactly one write path here: the frame
 * is decoded and its signature is verified by the frame decoder, the PUBLIC
 * scope is refused up front, and the post is inserted ONLY through
 * db_fleet_board_post_ingest, whose chain re-checks shape, time window,
 * signature, role, held-id and quota. No raw store insert, no second path.
 *
 * The gossip engine never touches this file: frames reach it only from an
 * explicit local client that already fetched them over its own transport.
 */

#include "config/boot_fleet_board.h"
#include "boot_fleet_board_rpc_internal.h"

#include "config/runtime.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "models/fleet_board_post.h"
#include "platform/time_compat.h"
#include "rpc/server.h"
#include "session/fleet_board_proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ZFB1 magic + type byte + one canonical body + signature. */
#define FBI_FRAME_MAX (FLEET_BOARD_FRAME_MAGIC_BYTES + 1u + \
                       FLEET_BOARD_BODY_MAX + FLEET_BOARD_SIG_BYTES)

static const char *fbi_frame_hex(const struct json_value *params)
{
    const struct json_value *first =
        params && json_size(params) ? json_at(params, 0) : NULL;
    const char *frame =
        first && first->type == JSON_OBJ ? json_get_str(json_get(first, "frame")) : NULL;
    return frame && frame[0] ? frame : NULL;
}

/* Decode + verify the frame bytes themselves; nothing is stored here. */
static bool fbi_decode(const char *hex, struct fleet_board_post *post,
                       uint8_t *wire, size_t len)
{
    return zcl_hex_decode_lower(hex, wire, len) &&
        fleet_board_frame_decode_post(wire, len, post) == FLEET_BOARD_OK;
}

static void fbi_inserted(struct json_value *result,
                         const struct fleet_board_post *post, bool stored)
{
    char hex[65];
    fleet_board_id_to_hex(post->id, hex);
    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    json_push_kv_str(result, "id", hex);
    json_push_kv_bool(result, "stored", stored);
    json_push_kv_str(result, "kind", fleet_board_kind_name(post->kind));
    json_push_kv_str(result, "room", post->room);
    json_push_kv_int(result, "created_at", (int64_t)post->created_at);
}

static bool rpc_fleet_board_ingest(const struct json_value *params, bool help,
                                   struct json_value *result)
{
    if (help) {
        json_set_str(result,
                     "fleet_board_ingest {frame} — insert one RAW signed "
                     "board post frame (hex) fetched by first-contact "
                     "discovery. The frame is decoded and signature-verified, "
                     "non-PUBLIC scope is refused, and the post is inserted "
                     "only through the board's own ingest chain (time window, "
                     "role, held-id, quota). Discovery's only write path.");
        return true;
    }
    struct node_db *ndb = app_runtime_node_db();
    if (!ndb || !ndb->open) {
        fb_error(result, "NODE_DB_UNAVAILABLE",
                 "the node database is not open; the board lives in it");
        return true;
    }
    const char *hex = fbi_frame_hex(params);
    size_t chars = hex ? strlen(hex) : 0;
    if (!hex || (chars & 1u) || chars / 2u > FBI_FRAME_MAX) {
        fb_error(result, "BAD_FRAME",
                 "one raw signed post frame as bounded hex is required");
        return true;
    }
    uint8_t *wire = zcl_malloc(chars / 2u, "fleet_board.ingest.frame");
    if (!wire) {
        fb_error(result, "BOARD_BUSY", "frame allocation failed");
        return true;
    }
    struct fleet_board_post post;
    bool decoded = fbi_decode(hex, &post, wire, chars / 2u);
    free(wire);
    if (!decoded) {
        fb_error(result, "FRAME_INVALID",
                 "the frame is not a verifiable signed board post");
        return true;
    }
    if (post.scope != FLEET_BOARD_SCOPE_PUBLIC) {
        fb_error(result, "NOT_PUBLIC",
                 "discovery ingests PUBLIC posts only");
        return true;
    }
    bool stored = false;
    enum fleet_board_result r =
        db_fleet_board_post_ingest(ndb, &post,
                                   (int64_t)platform_time_wall_time_t(),
                                   &stored);
    if (r != FLEET_BOARD_OK && !stored) {
        char message[640];
        fb_error(result, r == FLEET_BOARD_ERR_BUSY ? "BOARD_BUSY" : "BOARD_REFUSED",
                 boot_fleet_board_write_message(r, message, sizeof(message)));
        return true;
    }
    fbi_inserted(result, &post, stored);
    return true;
}

void boot_fleet_board_ingest_register_rpc(struct rpc_table *table)
{
    const struct rpc_command commands[] = {
        {"fleet", "fleet_board_ingest", rpc_fleet_board_ingest, true},
    };
    rpc_table_must_append(table, &commands[0]);
}
