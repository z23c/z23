/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Route package store writes (publish commit, pin, carrier export)
 * through the resident store owner, and read its swarm state. */

#include "config/boot_zcode_dht.h"

#include "command/native_command.h"
#include "base/hex.h"
#include "json/json.h"
#include "rpc/server.h"
#include "vcs/package_public_shape.h"
#include "vcs/package_store.h"
#include "vcs/package_swarm_node.h"

#include <string.h>

/* Row ceilings for zcode_swarm_status. Small on purpose: this is an
 * operator's diagnostic, not a catalog — the first screenful must name
 * the refusing rule, and `truncated` says when a bigger store needs a
 * per-root zcode_package_status probe instead. */
#define SWARM_STATUS_MAX_ROOTS 32u
#define SWARM_STATUS_MAX_PEERS 32u

/* Same ceiling the package store gives its own root path. */
#define PACKAGE_RPC_DATADIR_MAX 4400u

static const struct json_value *package_rpc_input(
    const struct json_value *params)
{
    const struct json_value *first =
        params && json_size(params) ? json_at(params, 0) : NULL;
    return first && first->type == JSON_OBJ ? first : NULL;
}

/* This node's own datadir, derived from the store root the resident handle
 * was opened with ("<datadir>/zcode"). Derived rather than re-read from the
 * configuration on purpose: a handler decides "resident or one-shot" by
 * comparing its computed <datadir>/zcode against that same store root, so a
 * datadir spelled any other way would silently pick the one-shot path this
 * routing exists to avoid. False when no store is open. */
static bool package_resident_datadir(char *out, size_t out_size)
{
    static const char suffix[] = "/zcode";
    const size_t suffix_len = sizeof(suffix) - 1u;
    const char *root = vcs_package_store_root_dir(vcs_package_store_global());
    size_t len = root ? strlen(root) : 0;
    if (len <= suffix_len || strcmp(root + len - suffix_len, suffix) != 0)
        return false;
    size_t keep = len - suffix_len;
    if (keep >= out_size)
        return false;
    memcpy(out, root, keep);
    out[keep] = '\0';
    return true;
}

/* Recovery includes orphan GC, so one-shot clients must not open the live
 * files behind the daemon's in-memory CAS view. Execute pin work here. */
static bool package_pin_rpc(const struct json_value *params, bool help,
                            struct json_value *result, bool pinned)
{
    if (help) {
        json_set_str(result,
                     pinned ? "zcode_package_pin {root,mode,plan_token?}"
                            : "zcode_package_unpin {root,mode,plan_token?}");
        return true;
    }
    const struct json_value *input = package_rpc_input(params);
    if (!input || json_get(input, "datadir")) {
        json_set_object(result);
        json_push_kv_bool(result, "ok", false);
        json_push_kv_str(result, "code", "INVALID_INPUT");
        json_push_kv_str(result, "phase", "validate");
        json_push_kv_str(result, "message",
                         "one input object without datadir is required");
        return true;
    }

    struct zcl_command_request request = { .input = input };
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.zcode_package_pin.v1");
    if (pinned)
        zcl_native_handle_zcode_package_pin(&request, &reply);
    else
        zcl_native_handle_zcode_package_unpin(&request, &reply);

    bool passed = reply.status == ZCL_COMMAND_STATUS_PASSED &&
                  reply.exit_code == ZCL_COMMAND_EXIT_OK;
    json_set_object(result);
    json_push_kv_bool(result, "ok", passed);
    if (passed) {
        json_push_kv(result, "data", &reply.data);
    } else {
        json_push_kv_str(result, "code", reply.error.code[0]
                                            ? reply.error.code
                                            : "PIN_REFUSED");
        json_push_kv_str(result, "phase", reply.error.phase[0]
                                             ? reply.error.phase
                                             : "execute");
        json_push_kv_str(result, "message", reply.error.message[0]
                                               ? reply.error.message
                                               : "resident pin failed");
        json_push_kv_bool(result, "retryable", reply.error.retryable);
        json_push_kv_bool(result, "mutated", reply.error.mutated);
    }
    zcl_command_reply_free(&reply);
    return true;
}

static bool package_pin(const struct json_value *params, bool help,
                        struct json_value *result)
{
    return package_pin_rpc(params, help, result, true);
}

static bool package_unpin(const struct json_value *params, bool help,
                          struct json_value *result)
{
    return package_pin_rpc(params, help, result, false);
}

/* The fastobj carrier export writes the store, and a serving engine
 * answers from its in-memory table: an export executed outside the
 * resident would leave the daemon announcing-by-record a root it refuses
 * as not-tracked until restart. The export executes here, on the same
 * store object the engine borrows. */
static bool package_fastobj_export(const struct json_value *params,
                                   bool help, struct json_value *result)
{
    if (help) {
        json_set_str(result,
                     "zcode_package_fastobj_export {cache_dir}");
        return true;
    }
    const struct json_value *input = package_rpc_input(params);
    if (!input || json_get(input, "datadir")) {
        json_set_object(result);
        json_push_kv_bool(result, "ok", false);
        json_push_kv_str(result, "code", "INVALID_INPUT");
        json_push_kv_str(result, "phase", "validate");
        json_push_kv_str(result, "message",
                         "one input object without datadir is required "
                         "(cache_dir; the resident datadir is implicit)");
        return true;
    }

    struct zcl_command_request request = { .input = input };
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.zcode_package_fastobj_export.v1");
    zcl_native_handle_zcode_package_fastobj_export(&request, &reply);

    bool passed = reply.status == ZCL_COMMAND_STATUS_PASSED &&
                  reply.exit_code == ZCL_COMMAND_EXIT_OK;
    json_set_object(result);
    json_push_kv_bool(result, "ok", passed);
    if (passed) {
        json_push_kv(result, "data", &reply.data);
    } else {
        json_push_kv_str(result, "code", reply.error.code[0]
                                            ? reply.error.code
                                            : "EXPORT_REFUSED");
        json_push_kv_str(result, "phase", reply.error.phase[0]
                                             ? reply.error.phase
                                             : "execute");
        json_push_kv_str(result, "message", reply.error.message[0]
                                               ? reply.error.message
                                               : "resident export failed");
        json_push_kv_bool(result, "retryable", reply.error.retryable);
        json_push_kv_bool(result, "mutated", reply.error.mutated);
    }
    zcl_command_reply_free(&reply);
    return true;
}

/* Publishing writes the manifest, chunks, signed transport carrier and
 * release into the store, and both the package swarm and the DHT publish
 * gate judge roots from the in-memory table of the resident's store object
 * rather than from the bytes on disk. A one-shot CLI commit opens a second
 * handle: the bytes land correctly and the daemon never hears of them, so
 * it refuses as "not-tracked" the very carrier its own pointer record would
 * advertise, until it is restarted. The commit executes here, on the store
 * object the engine serves from. */
static bool package_publish_commit(const struct json_value *params, bool help,
                                   struct json_value *result)
{
    if (help) {
        json_set_str(result,
                     "zcode_package_publish_commit "
                     "{release_hex,manifest_hex,recipe_hex,dir,day?}");
        return true;
    }
    const struct json_value *input = package_rpc_input(params);
    if (!input || json_get(input, "datadir")) {
        json_set_object(result);
        json_push_kv_bool(result, "ok", false);
        json_push_kv_str(result, "code", "INVALID_INPUT");
        json_push_kv_str(result, "phase", "validate");
        json_push_kv_str(result, "message",
                         "one input object without datadir is required "
                         "(the resident datadir is implicit)");
        return true;
    }
    char datadir[PACKAGE_RPC_DATADIR_MAX];
    if (!package_resident_datadir(datadir, sizeof(datadir))) {
        json_set_object(result);
        json_push_kv_bool(result, "ok", false);
        json_push_kv_str(result, "code", "NO_PACKAGE_STORE");
        json_push_kv_str(result, "phase", "validate");
        json_push_kv_str(result, "message",
                         "package hosting is disabled on this node; publish "
                         "against the datadir directly");
        return true;
    }

    /* The caller's whole input plus the one key only this process can
     * supply. Copying instead of rebuilding a key list keeps a future
     * publish input from needing a second place to be updated. */
    struct json_value forwarded;
    json_init(&forwarded);
    json_copy(&forwarded, input);
    json_push_kv_str(&forwarded, "datadir", datadir);

    struct zcl_command_request request = { .input = &forwarded };
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.zcode_publish_commit.v1");
    zcl_native_handle_zcode_package_publish_commit(&request, &reply);
    json_free(&forwarded);

    bool passed = reply.status == ZCL_COMMAND_STATUS_PASSED &&
                  reply.exit_code == ZCL_COMMAND_EXIT_OK;
    json_set_object(result);
    json_push_kv_bool(result, "ok", passed);
    if (passed) {
        json_push_kv(result, "data", &reply.data);
        /* A redelivered release commits nothing new; the caller's own reply
         * must say so exactly as a local commit would. */
        json_push_kv_bool(result, "mutated", reply.error.mutated);
    } else {
        json_push_kv_str(result, "code",
                         reply.error.code[0] ? reply.error.code
                                             : "PUBLISH_COMMIT_REFUSED");
        json_push_kv_str(result, "phase",
                         reply.error.phase[0] ? reply.error.phase : "execute");
        json_push_kv_str(result, "message",
                         reply.error.message[0]
                             ? reply.error.message
                             : "resident publish commit failed");
        json_push_kv_str(result, "evidence", reply.error.evidence);
        json_push_kv_bool(result, "retryable", reply.error.retryable);
        json_push_kv_bool(result, "mutated", reply.error.mutated);
    }
    zcl_command_reply_free(&reply);
    return true;
}

/* Read-only exact-root observation for native instruments.  This reuses the
 * resident store and swarm engine; it neither starts a fetch nor opens the
 * live store from a second process. */
static bool package_status(const struct json_value *params, bool help,
                           struct json_value *result)
{
    if (help) {
        json_set_str(result,
                     "zcode_package_status {package_root,transport_root}");
        return true;
    }
    const struct json_value *input = package_rpc_input(params);
    const char *package_hex = input
        ? json_get_str(json_get(input, "package_root")) : NULL;
    const char *transport_hex = input
        ? json_get_str(json_get(input, "transport_root")) : NULL;
    uint8_t package_root[32], transport_root[32];
    if (!package_hex || !transport_hex || strlen(package_hex) != 64u ||
        strlen(transport_hex) != 64u ||
        !zcl_hex_decode_lower(package_hex, package_root, sizeof(package_root)) ||
        !zcl_hex_decode_lower(transport_hex, transport_root,
                              sizeof(transport_root))) {
        json_set_object(result);
        json_push_kv_bool(result, "ok", false);
        json_push_kv_str(result, "code", "INVALID_ROOTS");
        json_push_kv_str(result, "message",
                         "package_root and transport_root must be canonical 64-hex roots");
        return true;
    }

    struct vcs_swarm_engine *engine = vcs_swarm_engine_global();
    struct vcs_swarm_download_status download = {0};
    bool download_found = engine && vcs_swarm_engine_download_status(
                                        engine, transport_root, &download);

    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    json_push_kv_str(result, "schema", "zcl.package_download_observation.v1");
    json_push_kv_str(result, "package_root", package_hex);
    json_push_kv_str(result, "transport_root", transport_hex);
    json_push_kv_bool(result, "swarm_enabled", engine != NULL);
    json_push_kv_bool(result, "download_found", download_found);
    if (download_found)
        boot_zcode_package_download_render(result, &download);
    return true;
}

/* Whole-engine observation for the operator. package_status answers "is
 * THIS root downloading"; it cannot answer "why is nothing moving" — the
 * refusing decision (no eligible peers joined, or a root the announcer
 * filters out) lives in state no other surface renders, and a CLI probe
 * opens a one-shot engine that sees none of it. Everything here reads the
 * resident engine and the resident store; nothing mutates. */
static bool swarm_status(const struct json_value *params, bool help,
                         struct json_value *result)
{
    (void)params;
    if (help) {
        json_set_str(result, "zcode_swarm_status {}");
        return true;
    }
    struct vcs_swarm_engine *engine = vcs_swarm_engine_global();
    struct vcs_package_store *store = vcs_package_store_global();

    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    json_push_kv_str(result, "schema", "zcl.zcode_swarm_observation.v1");
    json_push_kv_bool(result, "swarm_enabled", engine != NULL);

    if (engine) {
        uint64_t ids[SWARM_STATUS_MAX_PEERS];
        size_t peers = vcs_swarm_engine_peer_ids(
            engine, ids, SWARM_STATUS_MAX_PEERS);
        json_push_kv_int(result, "engine_peers", (int64_t)peers);
        json_push_kv_bool(result, "peers_truncated",
                          peers == SWARM_STATUS_MAX_PEERS);
        json_push_kv_int(result, "active_downloads",
                         (int64_t)vcs_swarm_engine_active_downloads(engine));

        /* Roots peers ANNOUNCEd to this engine this session — the mesh's
         * answer to "does anyone out there have anything". */
        struct vcs_swarm_advertised ads[SWARM_STATUS_MAX_ROOTS];
        size_t ad_n = vcs_swarm_engine_advertised(
            engine, ads, SWARM_STATUS_MAX_ROOTS);
        struct json_value advertised;
        json_init(&advertised);
        json_set_array(&advertised);
        for (size_t i = 0; i < ad_n; i++) {
            char hex[65];
            zcl_hex_encode(ads[i].root, 32, hex);
            struct json_value row;
            json_init(&row);
            json_set_object(&row);
            json_push_kv_str(&row, "root", hex);
            json_push_kv_int(&row, "advertisers",
                             (int64_t)ads[i].advertisers);
            json_push_back(&advertised, &row);
            json_free(&row);
        }
        json_push_kv(result, "advertised_to_us", &advertised);
        json_free(&advertised);
        json_push_kv_bool(result, "advertised_truncated",
                          ad_n == SWARM_STATUS_MAX_ROOTS);
    }

    /* What this resident would announce: every complete store root with
     * the announcer's own verdict. A root absent from the mesh despite
     * sitting complete in the store answers here, by rule name. */
    if (store) {
        struct vcs_package_store_summary summaries[SWARM_STATUS_MAX_ROOTS];
        size_t roots = vcs_package_store_list_summaries(
            store, true, summaries, SWARM_STATUS_MAX_ROOTS);
        struct json_value local;
        json_init(&local);
        json_set_array(&local);
        for (size_t i = 0; i < roots; i++) {
            struct vcs_package_public_verdict verdict;
            enum vcs_package_public_shape shape =
                vcs_package_public_shape_classify(
                    store, summaries[i].root, &verdict);
            char hex[65];
            zcl_hex_encode(summaries[i].root, 32, hex);
            struct json_value row;
            json_init(&row);
            json_set_object(&row);
            json_push_kv_str(&row, "root", hex);
            json_push_kv_str(&row, "public_shape",
                             vcs_package_public_shape_string(shape));
            json_push_kv_str(&row, "serve_rule",
                             verdict.rule ? verdict.rule : "null-input");
            json_push_kv_bool(&row, "would_announce",
                              shape != VCS_PACKAGE_PUBLIC_REFUSED);
            json_push_kv_int(&row, "total_bytes",
                             (int64_t)summaries[i].total_bytes);
            json_push_back(&local, &row);
            json_free(&row);
        }
        json_push_kv(result, "local_roots", &local);
        json_free(&local);
        json_push_kv_bool(result, "local_truncated",
                          roots == SWARM_STATUS_MAX_ROOTS);
    }
    return true;
}

void boot_zcode_package_register_rpc(struct rpc_table *table)
{
    const struct rpc_command commands[] = {
        { "zcode", "zcode_package_pin", package_pin, true },
        { "zcode", "zcode_package_unpin", package_unpin, true },
        { "zcode", "zcode_package_fastobj_export", package_fastobj_export, true },
        { "zcode", "zcode_package_publish_commit", package_publish_commit, true },
        { "zcode", "zcode_package_status", package_status, true },
        { "zcode", "zcode_swarm_status", swarm_status, true },
    };
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++)
        rpc_table_must_append(table, &commands[i]);
}
