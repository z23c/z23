/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * `sourcebundle_publish` — the RPC that makes a local C23 workspace fetchable
 * by its content root, executed INSIDE the running node.
 *
 * WHY THIS HAS TO BE AN RPC AT ALL. The artifact registry
 * (lib/net/src/rom_seed.c) is process-global memory owned by the daemon that
 * holds the listening file service. A native CLI invocation is a separate
 * one-shot process with no app_init() (see the same note on
 * tools/command/native_telemetry_storage_command.c), so a registration
 * performed there would land in a registry nobody serves from and vanish at
 * exit — a publish that reported success and offered nothing. The workspace
 * capture and the bundle bytes could be produced anywhere; the OFFER can only
 * be produced here.
 *
 * The datadir is the NODE'S OWN (GetDataDir), never a caller argument. That is
 * the whole path-safety story for this surface: a caller chooses which
 * workspace to publish and nothing about where the bytes land, so no input can
 * steer a write outside the seeded directory this node already owns.
 *
 * Everything else — capture, bundle, atomic landing, by-name registration and
 * the registry re-read that proves the offer exists — is
 * app/services/src/source_bundle_publish.c. This file is parse, call one
 * service, render. */

#include "controllers/file_market_controller.h"

#include "base/hex.h"
#include "json/json.h"
#include "rpc/server.h"
#include "services/source_bundle_publish.h"
#include "util/util.h"

#include <stdio.h>
#include <string.h>

/* Render one 32-byte root as lower-case hex under `key`. */
static void sbpr_hex(struct json_value *result, const char *key,
                     const uint8_t root[32])
{
    char hex[65];
    zcl_hex_encode(root, 32, hex);
    json_push_kv_str(result, key, hex);
}

static bool rpc_sourcebundle_publish(const struct json_value *params, bool help,
                                     struct json_value *result)
{
    if (help || !params || json_size(params) < 1) {
        json_set_str(result,
            "sourcebundle_publish \"workspace\" ( \"source_root\" )\n"
            "\nCapture a local source tree, bundle it, and offer it to peers\n"
            "by its ZVCS tree root — no restart and no directory sweep.\n"
            "\nArguments:\n"
            "1. workspace   (string, required) Source tree to capture.\n"
            "2. source_root (string, optional) 64-hex root the caller expects;\n"
            "               the call is refused before publication writes if the\n"
            "               captured tree is a different one.\n"
            "\nThe bundle lands under <datadir>/bundles/<root>.zvsb and is\n"
            "registered by name, so how many entries share that directory\n"
            "cannot hide it. Result reports status \"published\" only after the\n"
            "registry confirms, by root, that the artifact is offered.\n");
        return true;
    }

    const struct json_value *arg0 = json_at(params, 0);
    const char *workspace = arg0 ? json_get_str(arg0) : NULL;
    if (!workspace || !workspace[0]) {
        json_set_str(result, "Missing workspace");
        return false;
    }

    uint8_t pinned[32];
    const uint8_t *pinned_root = NULL;
    const struct json_value *arg1 =
        json_size(params) > 1 ? json_at(params, 1) : NULL;
    const char *pin_hex = arg1 ? json_get_str(arg1) : NULL;
    if (pin_hex && pin_hex[0]) {
        if (strlen(pin_hex) != 64 || !zcl_hex_decode_lower(pin_hex, pinned, 32)) {
            json_set_str(result, "source_root must be 64 lower-case hex chars");
            return false;
        }
        pinned_root = pinned;
    }

    char datadir[1024];
    GetDataDir(true, datadir, sizeof(datadir));

    struct source_bundle_publish_report report;
    enum source_bundle_publish_result rc =
        source_bundle_publish(workspace, datadir, pinned_root, &report);

    json_set_object(result);
    json_push_kv_str(result, "result",
                     source_bundle_publish_result_string(rc));
    if (rc != SOURCE_BUNDLE_PUBLISH_OK) {
        /* A refusal is a complete answer, not an RPC transport failure: the
         * caller gets the closed reason string and nothing that looks like a
         * partially published artifact. */
        json_push_kv_str(result, "status", "refused");
        json_push_kv_bool(result, "offered", false);
        return true;
    }

    json_push_kv_str(result, "status", "published");
    json_push_kv_bool(result, "offered", true);
    sbpr_hex(result, "source_root", report.source_root);
    sbpr_hex(result, "artifact_digest", report.artifact_root);
    json_push_kv_str(result, "filename", report.filename);
    json_push_kv_str(result, "path", report.path);
    json_push_kv_int(result, "wire_bytes", (int64_t)report.wire_bytes);
    json_push_kv_int(result, "chunks", (int64_t)report.num_chunks);
    json_push_kv_int(result, "file_service_port",
                     (int64_t)report.file_service_port);
    json_push_kv_bool(result, "republished", report.republished);
    json_push_kv_int(result, "seed_directory_entries",
                     (int64_t)report.seed_directory_entries);
    json_push_kv_bool(result, "rescan_guaranteed", report.rescan_guaranteed);
    json_push_kv_int(result, "source_bytes",
                     (int64_t)report.bundle.source_bytes);
    json_push_kv_int(result, "file_count", (int64_t)report.bundle.file_count);
    return true;
}

void register_source_bundle_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmds[] = {
        { "market", "sourcebundle_publish", rpc_sourcebundle_publish, true },
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
}
