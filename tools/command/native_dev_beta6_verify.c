/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: dev.beta6.verify — preflight a beta6 bootstrap serve tree.
 *
 * Runs the REAL beta6_bs_arm() preflight (engine/services/src/
 * beta6_bootstrap_serve.c) against a candidate serve directory, prints what
 * it would publish, then disarms — all inside THIS invocation's own process.
 * It calls beta6_bs_arm() exactly the way boot does
 * (engine/composition/src/boot_beta6_bootstrap.c:boot_beta6_bootstrap_start),
 * so this command can never drift from what arming a real node does: there
 * is one arming path, and this leaf is a second caller of it, not a second
 * implementation.
 *
 * SAFE WHILE A NODE IS RUNNING. beta6_bs_arm()'s cached manifest is a
 * file-scope `static` inside beta6_bootstrap_serve.c — process-private
 * state, not a file or a shared segment. This leaf is invoked as its own
 * `z23` process, so its arm/disarm cycle lives and dies in memory a running
 * node process never shares; the node's own armed state (if any) is a
 * completely separate copy of that same static in a separate address space
 * and is never read or written here.
 *
 * ONE CHECK BEFORE ARMING THAT beta6_bs_arm() ITSELF DOES NOT MAKE:
 * beta6_bs_require_source_paths() only proves blocks/, blocks/index/ and
 * chainstate/ exist; it says nothing about what ELSE sits beside them. A
 * live datadir (wallet.dat, debug.log, peers.dat, banlist.dat, a live
 * progress.kv/WAL...) satisfies that check just as well as a real serve
 * tree, and beta6_bs_collect_files() then walks and hashes the WHOLE tree
 * under blocks/ and chainstate/ regardless of what else is present — so
 * pointing this at a live datadir by name-collision would silently start
 * hashing gigabytes of live node state. dev_beta6_verify_top_level() below
 * is the one check that turns that mistake into a same-second, by-name
 * refusal, before a single byte is hashed.
 */
#include "command/native_command.h"

#include "json/json.h"
#include "platform/directory_compat.h"
#include "services/beta6_bootstrap.h"

#include <string.h>

#define DBV_LEAF "dev.beta6.verify"

/* Refuse, before arming, any top-level entry beside "blocks" and
 * "chainstate" — see the file header. Returns ok when the top level holds
 * nothing else (an empty directory is fine here; beta6_bs_require_source_paths
 * inside beta6_bs_arm() is what demands blocks/, blocks/index/ and
 * chainstate/ actually exist and refuses by that name if not). */
static struct zcl_result dev_beta6_verify_top_level(const char *dir)
{
    struct platform_directory_list dirs = { 0 };
    struct platform_directory_list files = { 0 };
    if (!platform_directory_list_children_sorted(dir, &dirs, &files))
        return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                       "beta6 verify could not list the top level of %s", dir);

    struct zcl_result bad = ZCL_OK;
    for (size_t i = 0; bad.ok && i < dirs.count; i++) {
        const char *name = dirs.entries[i].name;
        if (strcmp(name, "blocks") != 0 && strcmp(name, "chainstate") != 0)
            bad = ZCL_ERR(BETA6_BS_ERR_REFUSED,
                          "this is a datadir, not a serve tree: unexpected "
                          "entry %s",
                          name);
    }
    for (size_t i = 0; bad.ok && i < files.count; i++)
        bad = ZCL_ERR(BETA6_BS_ERR_REFUSED,
                      "this is a datadir, not a serve tree: unexpected entry %s",
                      files.entries[i].name);

    platform_directory_list_free(&dirs);
    platform_directory_list_free(&files);
    return bad;
}

/* build_manifest() in beta6_bootstrap_serve.c picks a v2 self-snapshot
 * ".meta" sidecar over a ".anchor" one when both could apply, and a v2
 * manifest is the only version number that sidecar produces (a ".anchor"
 * copy is v1, or v3 once a ".blocktip" sidecar extends it) — so the
 * manifest's own version number already says, without any new export,
 * which sidecar this copy was resolved from. */
static const char *dev_beta6_verify_sidecar_used(int32_t manifest_version)
{
    return manifest_version == 2 ? "meta" : "anchor";
}

void zcl_native_handle_dev_beta6_verify(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *source_dir = json_get_str(json_get(request->input, "source_dir"));
    const char *network_in = json_get_str(json_get(request->input, "network"));
    const char *network = (network_in && network_in[0]) ? network_in : "main";

    if (!source_dir || !source_dir[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_SOURCE_DIR",
                               "normalize", false, false,
                               "source_dir is required", "");
        return;
    }

    struct zcl_result top_level = dev_beta6_verify_top_level(source_dir);
    if (!top_level.ok) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "NOT_A_SERVE_TREE",
                               "preflight", false, false, top_level.message,
                               source_dir);
        return;
    }

    struct zcl_result armed = beta6_bs_arm(source_dir, network);
    if (!armed.ok) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "ARM_REFUSED", "arm",
                               false, false, armed.message, source_dir);
        return;
    }

    const struct beta6_bs_manifest *manifest = beta6_bs_manifest();
    struct byte_stream encoded;
    stream_init(&encoded, 4096);
    struct zcl_result wire = beta6_bs_manifest_encode(manifest, &encoded);
    size_t encoded_bytes = wire.ok ? encoded.size : 0;
    stream_free(&encoded);

    (void)json_push_kv_str(&reply->data, "leaf", DBV_LEAF);
    (void)json_push_kv_str(&reply->data, "source_dir", source_dir);
    (void)json_push_kv_str(&reply->data, "network", network);
    (void)json_push_kv_int(&reply->data, "manifest_version",
                           (int64_t)manifest->version);
    (void)json_push_kv_str(&reply->data, "sidecar_used",
                           dev_beta6_verify_sidecar_used(manifest->version));
    (void)json_push_kv_int(&reply->data, "height", (int64_t)manifest->height);
    (void)json_push_kv_int(&reply->data, "block_tip_height",
                           (int64_t)manifest->block_tip_height);
    (void)json_push_kv_int(&reply->data, "file_count",
                           (int64_t)manifest->file_count);
    (void)json_push_kv_int(&reply->data, "snapshot_bytes",
                           (int64_t)manifest->snapshot_bytes);
    (void)json_push_kv_bool(&reply->data, "manifest_encoded", wire.ok);
    (void)json_push_kv_int(&reply->data, "encoded_bytes",
                           (int64_t)encoded_bytes);
    (void)json_push_kv_int(&reply->data, "max_message_bytes",
                           (int64_t)BETA6_BS_MAX_MESSAGE_LEN);
    (void)json_push_kv_bool(
        &reply->data, "fits_one_p2p_message",
        wire.ok && encoded_bytes <= BETA6_BS_MAX_MESSAGE_LEN);
    (void)json_push_kv_str(
        &reply->data, "note",
        "armed and disarmed in this standalone process only; a running "
        "node's own armed state, a separate process, is untouched");

    beta6_bs_disarm();
}
