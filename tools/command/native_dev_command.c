/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native handlers for the registry-owned `dev` tree
 * (docs/NATIVE_COMMAND_INTERFACE.md §7). These bind the registry catalog's dev
 * subtree to the checkout-local read-only producers: App manifest describe /
 * plan / simulate, source-change classification, the Core/App boundary law,
 * the latest native cycle verdict, and dev.vcs.revert. Source-only append-only
 * reverts remain available; generation relinking is contained until immutable
 * source epochs and complete publication proof receipts are transactional.
 *
 * The read-only checkout producers compile into both binaries.  Executors and
 * watcher/generation lifecycle handlers live below ZCL_DEV_BUILD, so a release
 * binary can describe the same grammar but cannot spawn, mutate, or activate
 * anything in the development lane. */

#if !defined(_WIN32)
#define _GNU_SOURCE
#endif
#ifdef ZCL_HOTFORK_NATIVE_DEV_INPUT_CORE
#include "dev_failure_store.h"
#include "devloop.h"
#include "json/json.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#else
#include "command/native_command.h"
#include "command/native_dev_loop_command.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "controllers/rpc_client.h"
#include "crypto/sha3.h"
#include "dev_activation.h"
#include "dev_failure_store.h"
#include "devloop.h"
#include "test_group_catalog.h"
#include "kernel/command_registry.h"
#include "hotswap/hotswap_service.h"
#include "json/json.h"
#include "models/database.h"
#include "models/build_fabric.h"
#include "platform/time_compat.h"
#include "platform/directory_compat.h"
#include "platform/private_directory.h"
#include "platform/process_lock.h"
#include "platform/process_lifecycle.h"
#include "platform/positioned_file.h"
#include "platform/os_proc.h"
#include "platform/state_root.h"
#include "platform/watcher_lease.h"
#include "platform/watcher_record.h"
#include "platform/watcher_store.h"
#ifdef ZCL_DEV_BUILD
#include "dev_activation_internal.h"
#endif
#include "services/dev_reflex_policy_service.h"
#include "services/zcode_lane_service.h"
#include "services/vault_intent_decision_service.h"
#include "vcs/vcs.h"
#include "vcs/vcs_devloop.h"
#include "vcs/vcs_devloop_mirror.h"
#include "vcs/package_mapping.h"
#include "vcs/vcs_seal.h"

#include "encoding/utilstrencodings.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <unistd.h>
#else
#include <io.h>
#include <windows.h>
#endif

#ifdef ZCL_DEV_BUILD
#if !defined(_WIN32)
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#endif
#endif
#endif

#ifndef ZCL_HOTFORK_NATIVE_DEV_INPUT_CORE
#ifdef ZCL_DEV_BUILD
#if defined(_WIN32)
static int dev_fd_dup(int fd) { return _dup(fd); }
static int dev_fd_dup2(int from, int to) { return _dup2(from, to); }
static int dev_fd_close(int fd) { return _close(fd); }
#else
static int dev_fd_dup(int fd) { return dup(fd); }
static int dev_fd_dup2(int from, int to) { return dup2(from, to); }
static int dev_fd_close(int fd) { return close(fd); }
#endif
#endif

static bool dev_canonical_directory(const char *path, char out[PATH_MAX])
{
    return platform_directory_canonical_real(path, out, PATH_MAX);
}
#endif

/* Pure, caller-owned input policy shared by the static command shell and the
 * development-only HOT_FORK capsule.  Keeping these definitions in the owner
 * TU makes the capsule execute the exact candidate bytes while the compile
 * guard below excludes every process, filesystem, RPC, service, and
 * generation-authority path. */
static bool dev_request_files(const struct json_value *input, bool allow_empty,
                              const char **files, size_t *count,
                              char *why, size_t why_size)
{
    const struct json_value *array = json_get(input, "files");
    *count = 0;
    if (!array || array->type == JSON_NULL)
        return allow_empty;
    if (array->type != JSON_ARR ||
        (!allow_empty && array->num_children == 0) ||
        array->num_children > ZCL_DEVLOOP_MAX_FILES) {
        (void)snprintf(why, why_size,
                       "files must be a bounded string array%s",
                       allow_empty ? "" : " with at least one item");
        return false;
    }
    for (size_t i = 0; i < array->num_children; i++) {
        const struct json_value *item = &array->children[i];
        const char *path = json_get_str(item);
        if (item->type != JSON_STR || !path || !path[0] ||
            strlen(path) >= ZCL_DEVLOOP_PATH_MAX || path[0] == '/' ||
            strstr(path, "..")) {
            (void)snprintf(why, why_size,
                           "files[%zu] must be a confined relative path", i);
            return false;
        }
        files[i] = path;
    }
    *count = array->num_children;
    return true;
}

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING) || \
    defined(ZCL_HOTFORK_NATIVE_DEV_INPUT_CORE)
static bool dev_drive_input_int(const struct json_value *input,
                                const char *key, int64_t fallback,
                                int64_t *out)
{
    const struct json_value *v = input ? json_get(input, key) : NULL;
    if (!v || v->type == JSON_NULL) {
        *out = fallback;
        return true;
    }
    if (v->type != JSON_INT)
        return false;
    *out = json_get_int(v);
    return true;
}
#endif

#if defined(ZCL_DEV_BUILD) || defined(ZCL_HOTFORK_NATIVE_DEV_INPUT_CORE)
static bool dev_event_interrupting(const struct json_value *cycle)
{
    const char *phase = cycle && cycle->type == JSON_OBJ
        ? json_get_str(json_get(cycle, "phase")) : NULL;
    const char *status = cycle && cycle->type == JSON_OBJ
        ? json_get_str(json_get(cycle, "status")) : NULL;
    return (phase && (strcmp(phase, "STORY_RED") == 0 ||
                      strcmp(phase, "COMPILE_RED") == 0 ||
                      strcmp(phase, "FOCUSED_RED") == 0)) ||
           (status && (strcmp(status, "story_red") == 0 ||
                       strcmp(status, "compile_red") == 0 ||
                       strcmp(status, "focused_red") == 0 ||
                       strcmp(status, "rejected") == 0));
}

static bool dev_group_valid(const char *group)
{
    return group && group[0] && strlen(group) < 128 &&
        strspn(group,
               "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_") ==
            strlen(group);
}

static bool dev_generation_name_valid(const char *name)
{
    if (!name || strchr(name, '/') || strlen(name) >= 96)
        return false;
    const char *hex = NULL;
    if (strncmp(name, "gen-", 4) == 0)
        hex = name + 4;
    else if (strncmp(name, "legacy-", 7) == 0)
        hex = name + 7;
    if (!hex || strlen(hex) != 64)
        return false;
    return strspn(hex, "0123456789abcdef") == 64;
}
#endif

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING) || \
    defined(ZCL_HOTFORK_NATIVE_DEV_INPUT_CORE)
static bool dev_failure_id_valid(const char *failure_id)
{
    if (!failure_id || strlen(failure_id) != ZCL_DEV_FAILURE_HEX_LEN)
        return false;
    return strspn(failure_id, "0123456789abcdef") ==
           ZCL_DEV_FAILURE_HEX_LEN;
}
#endif

#ifndef ZCL_HOTFORK_NATIVE_DEV_INPUT_CORE

/* Copy a produced JSON document (buffer producer output) into reply->data.
 * On any failure, fail the reply with an INTERNAL contract error. */
static void dev_reply_from_json(struct zcl_command_reply *reply,
                                const char *body, size_t n, const char *what)
{
    struct json_value doc;
    json_init(&doc);
    if (n == 0 || !json_read(&doc, body, n) || doc.type != JSON_OBJ) {
        json_free(&doc);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "DEV_RENDER_FAILED",
                               "serialize", false, false,
                               "read-only dev producer returned no document",
                               what ? what : "");
        return;
    }
    json_free(&reply->data);
    json_init(&reply->data);
    json_copy(&reply->data, &doc);
    json_free(&doc);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

static const char *dev_source_root(const struct zcl_command_request *request)
{
    if (request && request->context && request->context->source_root &&
        request->context->source_root[0])
        return request->context->source_root;
    const char *env = getenv("ZCL_DEV_SOURCE_ROOT");
    return env && env[0] ? env : ".";
}

/* ── dev.status ────────────────────────────────────────────────────────── */
void zcl_native_handle_dev_status(const struct zcl_command_request *request,
                                  struct zcl_command_reply *reply)
{
    char body[16384], why[160] = {0};
    size_t len = 0;
    enum zcl_devloop_state_lookup lookup = zcl_devloop_cycle_state_read(
        dev_source_root(request), body, sizeof(body), &len, NULL,
        why, sizeof(why));
    if (lookup == ZCL_DEVLOOP_STATE_FOUND) {
        struct json_value doc;
        json_init(&doc);
        if (json_read(&doc, body, len) && doc.type == JSON_OBJ) {
            json_free(&reply->data);
            json_init(&reply->data);
            json_copy(&reply->data, &doc);
            json_free(&doc);
            return;
        }
        json_free(&doc);
        lookup = ZCL_DEVLOOP_STATE_INVALID;
        (void)snprintf(why, sizeof(why), "%s", "cycle_state_decode_failed");
    }
    if (lookup == ZCL_DEVLOOP_STATE_INVALID) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
            "DEV_CYCLE_STATE_INVALID", "read", false, false,
            "workspace cycle state failed schema, SHA3, or inode validation",
            why[0] ? why : "cycle_state_invalid");
        return;
    }
    /* No durable verdict yet — a bounded, honest "unavailable" is passing. */
    (void)json_push_kv_str(&reply->data, "schema", "zcl.dev_cycle.v1");
    (void)json_push_kv_str(&reply->data, "status", "unavailable");
    (void)json_push_kv_str(&reply->data, "agent_next_action",
                           "keep editing; the native watcher records verdicts");
}

/* ── dev.ff ────────────────────────────────────────────────────────────
 * Thin wrapper around `make ff` (Makefile: compile -> focused tests ->
 * lint-fast, cost-ordered and short-circuiting). Runs via the same
 * zcl_devloop_process_run() subprocess primitive the reload/redeploy path
 * uses (see dev_vcs_shell_fallback_activate() above), which is DEV_ONLY
 * linked (Makefile DEV_ONLY_SRCS) — so a release build never spawns this. */
void zcl_native_handle_dev_ff(const struct zcl_command_request *request,
                              struct zcl_command_reply *reply)
{
#ifndef ZCL_DEV_BUILD
    (void)request;
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
        "DEV_BUILD_REQUIRED", "dispatch", false, false,
        "the fail-fast ladder requires a dev build",
        "make dev-bin, or z23-dev dev ff");
#else
    char root[PATH_MAX];
    const char *src_root = dev_source_root(request);
    if (!dev_canonical_directory(src_root, root)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ROOT_RESOLVE_FAILED",
                               "normalize", false, false,
                               "could not resolve the checkout root", src_root);
        return;
    }
    struct dev_source_record source_before = {0};
    char source_why[256] = {0};
    if (!zcl_dev_source_identity_capture(root, &source_before,
                                         source_why,
                                         sizeof(source_why))) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
            "SOURCE_IDENTITY_FAILED", "capture", true, false,
            "could not capture the exact source identity before proof",
            source_why);
        return;
    }
    const char *argv[] = { "make", "--no-print-directory", "ff", NULL };
    struct zcl_devloop_process_result result;
    if (!zcl_devloop_process_run(root, argv, 600000, &result)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "FF_EXEC_FAILED",
                               "execute", true, false,
                               "could not execute the fail-fast ladder", "");
        return;
    }
    bool ok = result.exit_code == 0 && result.term_signal == 0 &&
              !result.timed_out;
    if (ok && !zcl_dev_source_identity_verify(
                  root, &source_before, source_why,
                  sizeof(source_why))) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "SOURCE_EPOCH_SUPERSEDED", "verify", true, false,
            "source changed during the complete proof; no ZVCS commit or publication job was created",
            source_why);
        return;
    }
    (void)json_push_kv_str(&reply->data, "schema", "zcl.dev_ff.v1");
    (void)json_push_kv_bool(&reply->data, "passed", ok);
    (void)json_push_kv_bool(&reply->data, "proof_complete", ok);
    (void)json_push_kv_int(&reply->data, "elapsed_ms", result.elapsed_ms);
    (void)json_push_kv_int(&reply->data, "exit_code", result.exit_code);
    (void)json_push_kv_bool(&reply->data, "timed_out", result.timed_out);
    if (ok) {
        struct vcs_devloop_verdict verdict = {
            .verdict_status = 0,
            .phase = "verify",
            .elapsed_ms = result.elapsed_ms,
            .defer_initial_snapshot = true,
            .proof_complete = true,
            .proof_scope = "source_wide_compile_tests_lint_fast",
            .source_identity_hex = source_before.source_id,
            .source_cas_hex = source_before.cas_present
                ? source_before.cas_root_sha3 : NULL,
        };
        struct vcs_devloop_anchor_result anchor;
        vcs_devloop_anchor_cycle(root, &verdict, &anchor);
        if (anchor.status == VCS_DEVLOOP_ANCHOR_OK) {
            char hex[65];
            zcl_hex_encode(anchor.commit_id, 32, hex);
            (void)json_push_kv_str(&reply->data, "vcs_commit", hex);
            const char *publication =
                anchor.publication_status == VCS_DEVLOOP_PUBLICATION_QUEUED
                    ? "QUEUED"
                    : anchor.publication_status ==
                          VCS_DEVLOOP_PUBLICATION_ERROR
                        ? "ERROR" : "NOT_ELIGIBLE";
            (void)json_push_kv_str(&reply->data, "publication_status",
                                   publication);
            if (anchor.publication_status ==
                VCS_DEVLOOP_PUBLICATION_QUEUED) {
                zcl_hex_encode(anchor.proof_receipt_root, 32, hex);
                (void)json_push_kv_str(&reply->data,
                                       "proof_receipt_root", hex);
                zcl_hex_encode(anchor.publication_job_root, 32, hex);
                (void)json_push_kv_str(&reply->data,
                                       "publication_job_root", hex);
                (void)json_push_kv_int(&reply->data,
                                       "publication_enqueue_us",
                                       anchor.publication_enqueue_us);
                (void)json_push_kv_bool(&reply->data,
                                        "publication_reused",
                                        anchor.publication_reused);
                char next_command[256];
                (void)snprintf(
                    next_command, sizeof(next_command),
                    "z23-dev dev publication status --input='"
                    "{\"job_root\":\"%s\"}'",
                    hex);
                (void)json_push_kv_str(
                    &reply->data, "publication_next_command",
                    next_command);
            }
            if (anchor.publication_error[0])
                (void)json_push_kv_str(&reply->data, "publication_error",
                                       anchor.publication_error);
        } else {
            (void)json_push_kv_str(&reply->data, "vcs_error",
                                   anchor.error[0]
                                       ? anchor.error
                                       : "ZVCS anchor unavailable");
            (void)json_push_kv_bool(&reply->data, "vcs_deferred",
                                    anchor.status ==
                                        VCS_DEVLOOP_ANCHOR_DEFERRED);
        }
        (void)json_push_kv_str(&reply->data, "source_identity_sha256",
                               source_before.source_id);
        if (source_before.cas_present)
            (void)json_push_kv_str(&reply->data, "source_cas_sha3",
                                   source_before.cas_root_sha3);
    }
    if (!ok) {
        const char *tail = result.output;
        if (result.output_len > 2048)
            tail += result.output_len - 2048;
        (void)json_push_kv_str(&reply->data, "output_tail", tail);
        /* The failing envelope drops reply->data (see serialize_reply()), so
         * carry the ladder's own dense "FIRST-ERROR[<rung>]: ..." line (see
         * tools/agent_fast_ci.sh) in the error evidence, where it is
         * actually rendered. Falls back to a short output tail if the
         * marker was not printed (e.g. a killed/timed-out subprocess). */
        char evidence[256];
        const char *marker = strstr(result.output, "FIRST-ERROR[");
        if (marker) {
            const char *eol = strchr(marker, '\n');
            size_t len = eol ? (size_t)(eol - marker) : strlen(marker);
            if (len >= sizeof(evidence))
                len = sizeof(evidence) - 1;
            memcpy(evidence, marker, len);
            evidence[len] = 0;
        } else {
            (void)snprintf(evidence, sizeof(evidence), "%s",
                           result.output_len > sizeof(evidence) - 1
                               ? result.output +
                                     (result.output_len - (sizeof(evidence) - 1))
                               : result.output);
        }
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "FF_LADDER_FAILED",
                               "prove", true, false,
                               "fail-fast ladder failed", evidence);
    }
#endif
}

/* ── dev.core.boundary ─────────────────────────────────────────────────── */
/* Read-only, bounded view of one immutable proof-to-publication job. The
 * queue grants no package, signing, network, wallet, or acceptance authority;
 * later phases remain explicit blockers until their existing owners produce
 * durable receipts. */
void zcl_native_handle_dev_publication_status(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *job_hex = json_get_str(json_get(request->input, "job_root"));
    uint8_t job_root[32];
    char job_root_err[128];
    if (!zcl_native_require_hex64("job_root", job_hex, job_root, job_root_err,
                                  sizeof(job_root_err))) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "INVALID_JOB_ROOT", "normalize", false, false, job_root_err,
            job_hex ? job_hex : "missing job_root");
        return;
    }

    struct vcs_devloop_publication_job job;
    const char *root = dev_source_root(request);
    if (!vcs_devloop_publication_job_load(root, job_root, &job)) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "PUBLICATION_JOB_UNAVAILABLE", "load", false, false,
            "the immutable publication job is absent or noncanonical",
            job_hex);
        return;
    }
    bool queued = vcs_devloop_publication_job_is_queued(root, job_root);
    struct vcs_devloop_publication_receipt progress;
    uint8_t progress_root[32];
    bool advanced = queued && vcs_devloop_publication_progress_load(
        root, job_root, &progress, progress_root);
    bool source_reproduced = advanced && progress.phase ==
        VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED;
    struct vcs_devloop_publication_receipt storage_receipt = {0};
    bool storage_acknowledged = advanced && progress.phase ==
        VCS_DEVLOOP_PUBLICATION_PHASE_STORAGE_ACKNOWLEDGED;
    if (source_reproduced) {
        storage_acknowledged = vcs_devloop_publication_receipt_load(
                root, progress.predecessor_receipt_root,
                &storage_receipt) &&
            storage_receipt.phase ==
                VCS_DEVLOOP_PUBLICATION_PHASE_STORAGE_ACKNOWLEDGED &&
            memcmp(storage_receipt.job_root, job_root, 32) == 0;
        if (!storage_acknowledged) {
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "PUBLICATION_REPRODUCTION_CHAIN_INVALID", "load", true,
                false,
                "the source reproduction phase has no verified storage ACK predecessor",
                job_hex);
            return;
        }
    } else if (storage_acknowledged) {
        storage_receipt = progress;
    }
    struct vcs_devloop_publication_receipt provider_receipt = {0};
    bool provider_announced = advanced && progress.phase ==
        VCS_DEVLOOP_PUBLICATION_PHASE_PROVIDER_ANNOUNCED;
    if (storage_acknowledged) {
        provider_announced = vcs_devloop_publication_receipt_load(
                root, storage_receipt.predecessor_receipt_root,
                &provider_receipt) &&
            provider_receipt.phase ==
                VCS_DEVLOOP_PUBLICATION_PHASE_PROVIDER_ANNOUNCED &&
            memcmp(provider_receipt.job_root, job_root, 32) == 0;
        if (!provider_announced) {
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "PUBLICATION_ACK_CHAIN_INVALID", "load", true, false,
                "the storage ACK phase has no verified provider predecessor",
                job_hex);
            return;
        }
    } else if (provider_announced) {
        provider_receipt = progress;
    }
    struct vcs_devloop_publication_receipt workspace_receipt = {0};
    bool workspace_published = advanced && progress.phase ==
        VCS_DEVLOOP_PUBLICATION_PHASE_WORKSPACE_PUBLISHED;
    if (provider_announced) {
        workspace_published = vcs_devloop_publication_receipt_load(
                root, provider_receipt.predecessor_receipt_root,
                &workspace_receipt) &&
            workspace_receipt.phase ==
                VCS_DEVLOOP_PUBLICATION_PHASE_WORKSPACE_PUBLISHED &&
            memcmp(workspace_receipt.job_root, job_root, 32) == 0;
        if (!workspace_published) {
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "PUBLICATION_PROVIDER_CHAIN_INVALID", "load", true, false,
                "the provider phase has no verified workspace predecessor",
                job_hex);
            return;
        }
    } else if (workspace_published) {
        workspace_receipt = progress;
    }
    struct vcs_devloop_publication_receipt passport_receipt = {0};
    bool passport_published = advanced && progress.phase ==
        VCS_DEVLOOP_PUBLICATION_PHASE_PASSPORT_PUBLISHED;
    if (workspace_published) {
        passport_published = vcs_devloop_publication_receipt_load(
                root, workspace_receipt.predecessor_receipt_root,
                &passport_receipt) &&
            passport_receipt.phase ==
                VCS_DEVLOOP_PUBLICATION_PHASE_PASSPORT_PUBLISHED &&
            memcmp(passport_receipt.job_root, job_root, 32) == 0;
        if (!passport_published) {
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "PUBLICATION_WORKSPACE_CHAIN_INVALID", "load", true, false,
                "the durable workspace phase has no verified Passport predecessor",
                job_hex);
            return;
        }
    } else if (passport_published) {
        passport_receipt = progress;
    }
    struct vcs_devloop_publication_receipt release_receipt = {0};
    bool release_published = advanced && progress.phase ==
        VCS_DEVLOOP_PUBLICATION_PHASE_RELEASE_PUBLISHED;
    if (passport_published) {
        release_published = vcs_devloop_publication_receipt_load(
                root, passport_receipt.predecessor_receipt_root,
                &release_receipt) &&
            release_receipt.phase ==
                VCS_DEVLOOP_PUBLICATION_PHASE_RELEASE_PUBLISHED &&
            memcmp(release_receipt.job_root, job_root, 32) == 0;
        if (!release_published) {
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "PUBLICATION_PASSPORT_CHAIN_INVALID", "load", true, false,
                "the durable Passport phase has no verified release predecessor",
                job_hex);
            return;
        }
    } else if (release_published) {
        release_receipt = progress;
    }
    struct vcs_devloop_publication_receipt mapping_receipt = {0};
    bool mapping_ready = advanced && progress.phase ==
        VCS_DEVLOOP_PUBLICATION_PHASE_PACKAGE_MAPPING_READY;
    if (release_published) {
        mapping_ready = vcs_devloop_publication_receipt_load(
                root, release_receipt.predecessor_receipt_root,
                &mapping_receipt) &&
            mapping_receipt.phase ==
                VCS_DEVLOOP_PUBLICATION_PHASE_PACKAGE_MAPPING_READY;
        if (!mapping_ready) {
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "PUBLICATION_RELEASE_CHAIN_INVALID", "load", true, false,
                "the durable release phase has no verified mapping predecessor",
                job_hex);
            return;
        }
    }
    bool accepted = advanced &&
        (progress.phase ==
             VCS_DEVLOOP_PUBLICATION_PHASE_ACCEPTED_LANE_BOUND ||
         mapping_ready || release_published || passport_published ||
         workspace_published || provider_announced ||
         storage_acknowledged || source_reproduced);
    struct vcs_package_mapping_set mapping;
    vcs_package_mapping_set_init(&mapping);
    const uint8_t *mapping_root = release_published
        ? mapping_receipt.artifact_root : progress.artifact_root;
    if (mapping_ready && !vcs_package_mapping_set_load(
            root, mapping_root, &mapping)) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "PUBLICATION_MAPPING_UNAVAILABLE", "load", true, false,
            "the durable mapping phase references missing or corrupt evidence",
            job_hex);
        return;
    }
    struct vcs_devloop_mirror_receipt mirror = {0};
    uint8_t mirror_root[32] = {0};
    enum vcs_devloop_mirror_lookup mirror_lookup = provider_announced
        ? vcs_devloop_mirror_load_for_job(
              root, job_root, &mirror, mirror_root)
        : VCS_DEVLOOP_MIRROR_ABSENT;
    if (mirror_lookup == VCS_DEVLOOP_MIRROR_INVALID ||
        (mirror_lookup == VCS_DEVLOOP_MIRROR_FOUND &&
         (memcmp(mirror.job_root, job_root, 32) != 0 ||
          memcmp(mirror.vcs_commit_root, job.vcs_commit_root, 32) != 0 ||
          memcmp(mirror.source_identity_sha256,
                 job.source_identity_sha256, 32) != 0 ||
          memcmp(mirror.proof_receipt_root,
                 job.proof_receipt_root, 32) != 0 ||
          memcmp(mirror.release_root,
                 release_receipt.artifact_root, 32) != 0 ||
          memcmp(mirror.workspace_root,
                 workspace_receipt.artifact_root, 32) != 0 ||
          memcmp(mirror.provider_record_root,
                 provider_receipt.artifact_root, 32) != 0))) {
        vcs_package_mapping_set_free(&mapping);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "MIRROR_EVIDENCE_INVALID", "load", false, false,
            "optional mirror evidence is corrupt, ambiguous, or disagrees with the verified P2P publication chain",
            job_hex);
        return;
    }
    char hex[65], next_command[256], collect_command[256];
    int next_len = snprintf(
        next_command, sizeof(next_command),
        "z23-dev dev publication advance --input='"
        "{\"job_root\":\"%s\"}'",
        job_hex);
    int collect_len = snprintf(
        collect_command, sizeof(collect_command),
        "z23-dev dev publication collect --input='"
        "{\"job_root\":\"%s\"}'",
        job_hex);
    if (next_len <= 0 || (size_t)next_len >= sizeof(next_command) ||
        collect_len <= 0 ||
        (size_t)collect_len >= sizeof(collect_command)) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
            "PUBLICATION_STATUS_RENDER_FAILED", "render", false, false,
            "the exact next command exceeded its fixed output bound",
            job_hex);
        return;
    }
    (void)json_push_kv_str(&reply->data, "schema",
                           "zcl.dev_publication_status.v1");
    (void)json_push_kv_str(
        &reply->data, "status",
        source_reproduced ? "SOURCE_REPRODUCED" :
        storage_acknowledged ? "STORAGE_ACKNOWLEDGED" :
        provider_announced ? "PROVIDER_ANNOUNCED" :
        workspace_published ? "WORKSPACE_PUBLISHED" :
        passport_published ? "PASSPORT_PUBLISHED" :
        release_published ? "RELEASE_PUBLISHED" :
        mapping_ready ? "PACKAGE_MAPPING_READY" :
        accepted ? "PROVEN_WORK_BOUND" :
        advanced ? "WAITING_ACCEPTANCE" : queued ? "QUEUED" : "NOT_QUEUED");
    (void)json_push_kv_bool(&reply->data, "proof_complete", true);
    (void)json_push_kv_str(&reply->data, "publication_job_root", job_hex);
#define DEV_PUBLICATION_ROOT(key_, field_)                                  \
    do {                                                                     \
        zcl_hex_encode((field_), 32, hex);                                   \
        (void)json_push_kv_str(&reply->data, (key_), hex);                   \
    } while (0)
    DEV_PUBLICATION_ROOT("zvcs_commit_root", job.vcs_commit_root);
    DEV_PUBLICATION_ROOT("source_tree_root", job.source_tree_root);
    DEV_PUBLICATION_ROOT("proof_receipt_root", job.proof_receipt_root);
    DEV_PUBLICATION_ROOT("source_identity_sha256",
                         job.source_identity_sha256);
    DEV_PUBLICATION_ROOT("source_cas_sha3", job.source_cas_sha3);
    DEV_PUBLICATION_ROOT("generation_sha256", job.generation_sha256);
    if (advanced)
        DEV_PUBLICATION_ROOT("progress_receipt_root", progress_root);
    if (accepted)
        DEV_PUBLICATION_ROOT(
            "lane_receipt_root",
            mapping_ready ? mapping.lane_receipt_root
                          : progress.artifact_root);
    if (mapping_ready) {
        DEV_PUBLICATION_ROOT("package_mapping_root", mapping_root);
        (void)json_push_kv_int(&reply->data, "bytes_scanned",
                               (int64_t)progress.bytes_scanned);
        (void)json_push_kv_int(&reply->data, "new_chunks",
                               progress.new_chunks);
        (void)json_push_kv_int(&reply->data, "reused_chunks",
                               progress.reused_chunks);
    }
    if (release_published)
        DEV_PUBLICATION_ROOT("release_root", release_receipt.artifact_root);
    if (passport_published)
        DEV_PUBLICATION_ROOT("passport_root", passport_receipt.artifact_root);
    if (workspace_published)
        DEV_PUBLICATION_ROOT("workspace_root",
                             workspace_receipt.artifact_root);
    if (provider_announced)
        DEV_PUBLICATION_ROOT("provider_record_root",
                             provider_receipt.artifact_root);
    if (storage_acknowledged)
        DEV_PUBLICATION_ROOT("storage_ack_set_root",
                             source_reproduced
                                 ? storage_receipt.artifact_root
                                 : progress.artifact_root);
    if (source_reproduced)
        DEV_PUBLICATION_ROOT("source_reproduction_record_root",
                             progress.artifact_root);
#undef DEV_PUBLICATION_ROOT
    (void)json_push_kv_str(
        &reply->data, "workspace_state",
        provider_announced ? "manifest_persisted_announced" :
        workspace_published ? "manifest_persisted_not_announced" :
        passport_published ? "passport_published_manifest_not_created" :
        release_published ? "release_published_manifest_not_created"
                          : "not_created");
    (void)json_push_kv_str(&reply->data, "p2p",
                           provider_announced ? "announced"
                                              : "not_announced");
    (void)json_push_kv_int(&reply->data, "providers",
                           provider_announced ? progress.providers : 0);
    char storage_ack_status[16];
    int storage_ack_len = snprintf(
        storage_ack_status, sizeof(storage_ack_status), "%u/2",
        advanced ? progress.storage_acks : 0u);
    if (storage_ack_len > 0 &&
        (size_t)storage_ack_len < sizeof(storage_ack_status))
        (void)json_push_kv_str(&reply->data, "storage_ack",
                               storage_ack_status);
    (void)json_push_kv_str(
        &reply->data, "reproduced",
        source_reproduced ? "signed_distinct_source_reconstruction"
                          : "no_record");
    (void)json_push_kv_bool(&reply->data,
                            "physical_independence_attested", false);
    (void)json_push_kv_str(
        &reply->data, "github_mirror",
        mirror_lookup == VCS_DEVLOOP_MIRROR_FOUND
            ? "recorded_declared" : "mirror_pending");
    if (mirror_lookup == VCS_DEVLOOP_MIRROR_FOUND) {
        zcl_hex_encode(mirror_root, 32, hex);
        (void)json_push_kv_str(&reply->data, "mirror_receipt_root", hex);
        if (mirror.git_oid_len > 0) {
            zcl_hex_encode(mirror.git_oid, mirror.git_oid_len, hex);
            (void)json_push_kv_str(&reply->data, "mirror_git_oid", hex);
        }
    }
    (void)json_push_kv_str(
        &reply->data, "blocker",
        source_reproduced ? "physical_off_host_attestation_not_represented" :
        storage_acknowledged ? "remote_reproduction_required" :
        provider_announced ? "storage_ack_required" :
        workspace_published ? "provider_announcement_required" :
        passport_published ? "workspace_manifest_signature_required" :
        release_published ? "passport_and_workspace_manifest_signature_required" :
        mapping_ready ? "offline_publisher_metadata_and_signature_required" :
        accepted ? "package_mapping_worker_advance_required" :
        queued ? "human_proven_work_and_offline_publisher_signature_required"
               : "durable_publication_queue_record_missing");
    (void)json_push_kv_str(
        &reply->data, "next_command",
        source_reproduced ? next_command :
        storage_acknowledged ? collect_command :
        provider_announced ?
            collect_command :
        workspace_published ?
            "z23 discover search provider" :
        passport_published ?
            "z23 discover schema zcode.workspace.manifest.plan" :
        release_published ?
            "z23 discover schema zcode.passport.plan" :
        mapping_ready ?
            "z23 discover schema zcode.package.dev.publish.plan" :
        accepted ? next_command :
        advanced ? "z23 zcode guide" : queued ? next_command : "dev ff");
    vcs_package_mapping_set_free(&mapping);
}

static bool dev_publication_lane_lookup(
    const char *workspace, const char *datadir, const uint8_t source_root[32],
    uint8_t lane_root[32], char proof_set_hex[65], char lane_name[16],
    bool *projection_rebuilt)
{
    enum { DEV_PUBLICATION_ACTION_MAX = 64, DEV_PUBLICATION_WORKER_MAX = 256 };
    char source_hex[65];
    zcl_hex_encode(source_root, 32, source_hex);
    sqlite3 *db = NULL;
    struct node_db ndb = {0};
    if (zcl_native_node_db_open_readonly(
            datadir, &db, &ndb, NULL, 0) != ZCL_NODE_DB_RO_OK)
        return false;
    int64_t now = (int64_t)platform_time_wall_unix();
    struct zcode_lane_status status;
    struct zcl_result found = zcode_lane_find(
        &ndb, workspace, source_hex, &status);
    uint8_t accepted_root[32];
    struct vcs_zcode_accepted_work_v1 accepted;
    bool accepted_ok = found.ok && status.lane == VCS_ZCODE_LANE_PROVEN &&
        zcl_hex_decode_lower(status.receipt_root_sha3, accepted_root, 32) &&
        vcs_zcode_accepted_work_resolve(
            workspace, accepted_root, now, &accepted) &&
        memcmp(accepted.candidate.candidate_source_root, source_root, 32) == 0 &&
        memcmp(accepted.accepted_work_root, accepted_root, 32) == 0;
    struct db_build_action actions[DEV_PUBLICATION_ACTION_MAX + 1];
    int action_count = accepted_ok ? db_build_candidate_actions(
        &ndb, status.task_root_sha3, status.candidate_root_sha3,
        status.proof_policy_root_sha3, actions,
        DEV_PUBLICATION_ACTION_MAX + 1) : 0;
    struct db_build_worker workers[DEV_PUBLICATION_WORKER_MAX + 1];
    int worker_count = accepted_ok ? db_build_workers_list(
        &ndb, workers, DEV_PUBLICATION_WORKER_MAX + 1) : 0;
    char expected_signer[65];
    if (accepted_ok)
        zcl_hex_encode(accepted.expected_signer, 32, expected_signer);
    bool signer_current = false;
    for (int i = 0; accepted_ok && i < worker_count; i++)
        if (strcmp(workers[i].signer_pubkey, expected_signer) == 0 &&
            workers[i].approved && !workers[i].revoked &&
            (workers[i].expires_at == 0 || now < workers[i].expires_at))
            signer_current = true;
    zcl_native_node_db_close_readonly(&db, &ndb);
    if (!accepted_ok || action_count <= 0 ||
        action_count > DEV_PUBLICATION_ACTION_MAX || worker_count <= 0 ||
        worker_count > DEV_PUBLICATION_WORKER_MAX || !signer_current)
        return false;

    bool proof_verified = false;
    for (int i = 0; i < action_count && !proof_verified; i++) {
        struct json_value input;
        json_init(&input); json_set_object(&input);
        bool input_ok = json_push_kv_str(&input, "workspace", workspace) &&
            json_push_kv_str(&input, "datadir", datadir) &&
            json_push_kv_str(&input, "action_id", actions[i].action_id);
        struct zcl_command_request evidence_request = { .input = &input };
        struct zcl_command_reply evidence_reply;
        zcl_command_reply_init(&evidence_reply, "zcl.zcode_evidence.v1");
        if (input_ok)
            zcl_native_handle_zcode_evidence(
                &evidence_request, &evidence_reply);
        const char *evaluated_proof = json_get_str(
            json_get(&evidence_reply.data, "proof_set_root"));
        const struct json_value *policy_value = json_get(
            &evidence_reply.data, "policy_satisfied");
        proof_verified = evidence_reply.status == ZCL_COMMAND_STATUS_PASSED &&
            evidence_reply.exit_code == ZCL_COMMAND_EXIT_OK &&
            policy_value && policy_value->type == JSON_BOOL &&
            json_get_bool(policy_value) && evaluated_proof &&
            strcmp(evaluated_proof, status.proof_set_root_sha3) == 0;
        zcl_command_reply_free(&evidence_reply);
        json_free(&input);
    }
    if (!proof_verified) return false;
    memcpy(lane_root, accepted.accepted_work_root, 32);
    zcl_hex_encode(accepted.proof_set_root, 32, proof_set_hex);
    (void)snprintf(lane_name, 16, "PROVEN");
    if (projection_rebuilt) *projection_rebuilt = false;
    return true;
}

void zcl_native_handle_dev_publication_advance(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *job_hex = json_get_str(json_get(request->input, "job_root"));
    bool details = json_get_bool(json_get(request->input, "details"));
    uint8_t job_root[32];
    char job_root_err[128];
    if (!zcl_native_require_hex64("job_root", job_hex, job_root, job_root_err,
                                  sizeof(job_root_err))) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "INVALID_JOB_ROOT", "normalize", false, false, job_root_err,
            job_hex ? job_hex : "missing job_root");
        return;
    }
    char resolved_workspace[PATH_MAX];
    const char *workspace = json_get_str(json_get(request->input,
                                                   "workspace"));
    const char *repo_root = dev_source_root(request);
    if (workspace && workspace[0]) {
        if (!dev_canonical_directory(workspace, resolved_workspace)) {
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "PUBLICATION_WORKSPACE_INVALID", "normalize", false, false,
                "workspace must resolve to the existing exact source store",
                workspace);
            return;
        }
        repo_root = resolved_workspace;
    }
    uint8_t receipt_root[32];
    bool reused = false;
    if (!vcs_devloop_publication_advance_waiting_acceptance(
            repo_root, job_root, receipt_root, &reused)) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "PUBLICATION_ADVANCE_FAILED", "advance", true, false,
            "the immutable job or durable queue record is unavailable",
            job_hex);
        return;
    }
    struct vcs_devloop_publication_job job;
    struct vcs_devloop_publication_receipt progress;
    uint8_t loaded_progress_root[32];
    bool have_job = vcs_devloop_publication_job_load(
        repo_root, job_root, &job);
    bool have_progress = vcs_devloop_publication_progress_load(
        repo_root, job_root, &progress, loaded_progress_root);
    const char *datadir = json_get_str(json_get(request->input, "datadir"));
    uint8_t lane_root[32];
    char proof_set_hex[65] = "", lane_name[16] = "";
    bool source_reproduced = have_progress && progress.phase ==
        VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED;
    struct vcs_devloop_publication_receipt storage_receipt = {0};
    bool storage_acknowledged = have_progress && progress.phase ==
        VCS_DEVLOOP_PUBLICATION_PHASE_STORAGE_ACKNOWLEDGED;
    if (source_reproduced) {
        storage_acknowledged = vcs_devloop_publication_receipt_load(
                repo_root, progress.predecessor_receipt_root,
                &storage_receipt) &&
            storage_receipt.phase ==
                VCS_DEVLOOP_PUBLICATION_PHASE_STORAGE_ACKNOWLEDGED &&
            memcmp(storage_receipt.job_root, job_root, 32) == 0;
        if (!storage_acknowledged) {
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "PUBLICATION_REPRODUCTION_CHAIN_INVALID", "load", true,
                false,
                "the source reproduction phase has no verified storage ACK predecessor",
                job_hex);
            return;
        }
    } else if (storage_acknowledged) {
        storage_receipt = progress;
    }
    struct vcs_devloop_publication_receipt provider_receipt = {0};
    bool provider_announced = have_progress && progress.phase ==
        VCS_DEVLOOP_PUBLICATION_PHASE_PROVIDER_ANNOUNCED;
    if (storage_acknowledged) {
        provider_announced = vcs_devloop_publication_receipt_load(
                repo_root, storage_receipt.predecessor_receipt_root,
                &provider_receipt) &&
            provider_receipt.phase ==
                VCS_DEVLOOP_PUBLICATION_PHASE_PROVIDER_ANNOUNCED &&
            memcmp(provider_receipt.job_root, job_root, 32) == 0;
        if (!provider_announced) {
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "PUBLICATION_ACK_CHAIN_INVALID", "load", true, false,
                "the storage ACK phase has no verified provider predecessor",
                job_hex);
            return;
        }
    } else if (provider_announced) {
        provider_receipt = progress;
    }
    struct vcs_devloop_publication_receipt workspace_receipt = {0};
    bool workspace_published = have_progress && progress.phase ==
        VCS_DEVLOOP_PUBLICATION_PHASE_WORKSPACE_PUBLISHED;
    if (provider_announced) {
        workspace_published = vcs_devloop_publication_receipt_load(
                repo_root, provider_receipt.predecessor_receipt_root,
                &workspace_receipt) &&
            workspace_receipt.phase ==
                VCS_DEVLOOP_PUBLICATION_PHASE_WORKSPACE_PUBLISHED &&
            memcmp(workspace_receipt.job_root, job_root, 32) == 0;
        if (!workspace_published) {
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "PUBLICATION_PROVIDER_CHAIN_INVALID", "load", true, false,
                "the provider phase has no verified workspace predecessor",
                job_hex);
            return;
        }
    } else if (workspace_published) {
        workspace_receipt = progress;
    }
    struct vcs_devloop_publication_receipt passport_receipt = {0};
    bool passport_published = have_progress && progress.phase ==
        VCS_DEVLOOP_PUBLICATION_PHASE_PASSPORT_PUBLISHED;
    if (workspace_published) {
        passport_published = vcs_devloop_publication_receipt_load(
                repo_root, workspace_receipt.predecessor_receipt_root,
                &passport_receipt) &&
            passport_receipt.phase ==
                VCS_DEVLOOP_PUBLICATION_PHASE_PASSPORT_PUBLISHED &&
            memcmp(passport_receipt.job_root, job_root, 32) == 0;
        if (!passport_published) {
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "PUBLICATION_WORKSPACE_CHAIN_INVALID", "load", true, false,
                "the durable workspace phase has no verified Passport predecessor",
                job_hex);
            return;
        }
    } else if (passport_published) {
        passport_receipt = progress;
    }
    struct vcs_devloop_publication_receipt release_receipt = {0};
    bool release_published = have_progress && progress.phase ==
        VCS_DEVLOOP_PUBLICATION_PHASE_RELEASE_PUBLISHED;
    if (passport_published) {
        release_published = vcs_devloop_publication_receipt_load(
                repo_root, passport_receipt.predecessor_receipt_root,
                &release_receipt) &&
            release_receipt.phase ==
                VCS_DEVLOOP_PUBLICATION_PHASE_RELEASE_PUBLISHED &&
            memcmp(release_receipt.job_root, job_root, 32) == 0;
    } else if (release_published) {
        release_receipt = progress;
    }
    struct vcs_devloop_publication_receipt mapping_receipt = {0};
    bool projection_rebuilt = false;
    if (passport_published && !release_published) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "PUBLICATION_PASSPORT_CHAIN_INVALID", "load", true, false,
            "the durable Passport phase has no verified release predecessor",
            job_hex);
        return;
    }
    bool mapping_ready = have_progress && progress.phase ==
        VCS_DEVLOOP_PUBLICATION_PHASE_PACKAGE_MAPPING_READY;
    if (release_published)
        mapping_ready = vcs_devloop_publication_receipt_load(
                repo_root, release_receipt.predecessor_receipt_root,
                &mapping_receipt) &&
            mapping_receipt.phase ==
                VCS_DEVLOOP_PUBLICATION_PHASE_PACKAGE_MAPPING_READY;
    if (release_published && !mapping_ready) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "PUBLICATION_RELEASE_CHAIN_INVALID", "load", true, false,
            "the durable release phase has no verified mapping predecessor",
            job_hex);
        return;
    }
    bool lane_bound = have_progress &&
        (progress.phase ==
             VCS_DEVLOOP_PUBLICATION_PHASE_ACCEPTED_LANE_BOUND ||
         mapping_ready || release_published || passport_published ||
         workspace_published || provider_announced ||
         storage_acknowledged || source_reproduced);
    bool acceptance_verified = false;
    if (datadir && datadir[0] && have_job) {
        char workspace[PATH_MAX];
        bool lane_found = dev_canonical_directory(repo_root, workspace) &&
            dev_publication_lane_lookup(
                workspace, datadir, job.source_tree_root, lane_root,
                proof_set_hex, lane_name, &projection_rebuilt);
        if (lane_found && lane_bound) {
            struct vcs_package_mapping_set mapping;
            vcs_package_mapping_set_init(&mapping);
            const uint8_t *mapping_set_root = release_published
                ? mapping_receipt.artifact_root : progress.artifact_root;
            bool loaded = !mapping_ready || vcs_package_mapping_set_load(
                repo_root, mapping_set_root, &mapping);
            const uint8_t *bound_root = mapping_ready
                ? mapping.lane_receipt_root : progress.artifact_root;
            acceptance_verified = loaded &&
                memcmp(bound_root, lane_root, 32) == 0;
            vcs_package_mapping_set_free(&mapping);
        } else if (lane_found) {
            lane_bound = vcs_devloop_publication_advance_proven_work(
                repo_root, job_root, lane_root,
                (int64_t)platform_time_wall_unix(), receipt_root, &reused);
            acceptance_verified = lane_bound;
            have_progress = lane_bound &&
                vcs_devloop_publication_progress_load(
                    repo_root, job_root, &progress, loaded_progress_root);
        }
    }
    bool mapping_failed = false;
    if (lane_bound && acceptance_verified && !mapping_ready && have_job &&
        have_progress) {
        uint8_t mapping_root[32];
        struct vcs_package_mapping_metrics metrics;
        bool mapped = vcs_package_mapping_set_build(
            repo_root, job.source_tree_root, progress.artifact_root,
            &metrics, mapping_root);
        if (mapped)
            mapping_ready =
                vcs_devloop_publication_advance_package_mapping(
                    repo_root, job_root, mapping_root,
                    metrics.bytes_scanned, metrics.new_chunks,
                    metrics.reused_chunks, receipt_root, &reused);
        mapping_failed = !mapped || !mapping_ready;
        have_progress = !mapping_failed &&
            vcs_devloop_publication_progress_load(
                repo_root, job_root, &progress, loaded_progress_root);
    }
    char receipt_hex[65];
    zcl_hex_encode(have_progress ? loaded_progress_root : receipt_root,
                   32, receipt_hex);
    char retry_command[256], collect_command[256];
    int retry_len = snprintf(
        retry_command, sizeof(retry_command),
        "z23-dev dev publication advance --input='"
        "{\"job_root\":\"%s\"}'", job_hex);
    int collect_len = snprintf(
        collect_command, sizeof(collect_command),
        "z23-dev dev publication collect --input='"
        "{\"job_root\":\"%s\"}'",
        job_hex);
    if (retry_len <= 0 || (size_t)retry_len >= sizeof(retry_command) ||
        collect_len <= 0 ||
        (size_t)collect_len >= sizeof(collect_command)) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
            "PUBLICATION_ADVANCE_RENDER_FAILED", "render", false, false,
            "the exact retry command exceeded its fixed output bound",
            job_hex);
        return;
    }
    const char *status = source_reproduced ? "SOURCE_REPRODUCED" :
        storage_acknowledged ? "STORAGE_ACKNOWLEDGED" :
        provider_announced ? "PROVIDER_ANNOUNCED" :
        workspace_published ? "WORKSPACE_PUBLISHED" :
        passport_published ? "PASSPORT_PUBLISHED" :
        release_published ? "RELEASE_PUBLISHED" :
        mapping_ready ? "PACKAGE_MAPPING_READY" :
        lane_bound ? "PROVEN_WORK_BOUND" : "WAITING_ACCEPTANCE";
    const char *next_action = source_reproduced
        ? "Keep this accepted package available to other nodes." :
        storage_acknowledged
        ? "Collect independent source reproduction." :
        provider_announced
        ? "Collect independent storage acknowledgements." :
        workspace_published
        ? "Announce the exact package from the existing node." :
        passport_published
        ? "Create the durable package workspace." :
        release_published
        ? "Publish the package identity and workspace." :
        mapping_ready
        ? "Choose the publisher identity and prepare offline signing." :
        lane_bound
        ? "Continue mapping the accepted source." :
          "Wait for exact human acceptance.";
    const char *next_safe_command = source_reproduced
        ? "dev publication status" :
        storage_acknowledged || provider_announced
        ? "dev publication collect" :
        workspace_published ? "zcode network publish" :
        passport_published ? "zcode workspace manifest plan" :
        release_published ? "zcode passport plan" :
        mapping_ready ? "zcode package dev publish plan" :
        lane_bound ? "dev publication advance" : "zcode work status";
    (void)json_push_kv_str(&reply->data, "schema",
                           "zcl.dev_publication_advance.v1");
    (void)json_push_kv_str(&reply->data, "status", status);
    (void)json_push_kv_str(&reply->data, "stage", "Publishing");
    (void)json_push_kv_str(&reply->data, "next_action", next_action);
    (void)json_push_kv_str(&reply->data, "next_safe_command",
                           next_safe_command);
    (void)json_push_kv_bool(&reply->data, "details_available", true);
    if (details) {
        (void)json_push_kv_str(&reply->data, "publication_job_root",
                               job_hex);
        (void)json_push_kv_str(&reply->data, "progress_receipt_root",
                               receipt_hex);
    }
    (void)json_push_kv_bool(&reply->data, "receipt_reused", reused);
    (void)json_push_kv_bool(&reply->data, "acceptance_reverified",
                            acceptance_verified);
    (void)json_push_kv_bool(&reply->data, "lane_projection_rebuilt",
                            projection_rebuilt);
    if (lane_bound) {
        struct vcs_package_mapping_set mapping;
        vcs_package_mapping_set_init(&mapping);
        bool mapping_loaded = mapping_ready &&
            vcs_package_mapping_set_load(
                repo_root,
                release_published ? mapping_receipt.artifact_root
                                  : progress.artifact_root,
                &mapping);
        if (mapping_ready && !mapping_loaded) {
            vcs_package_mapping_set_free(&mapping);
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "PUBLICATION_MAPPING_UNAVAILABLE", "load", true, false,
                "the durable mapping phase references missing or corrupt evidence",
                job_hex);
            return;
        }
        const uint8_t *lane_receipt = mapping_loaded
            ? mapping.lane_receipt_root : progress.artifact_root;
        char lane_hex[65];
        zcl_hex_encode(lane_receipt, 32, lane_hex);
        if (details)
            (void)json_push_kv_str(&reply->data, "lane_receipt_root",
                                   lane_hex);
        if (mapping_ready) {
            char mapping_hex[65];
            zcl_hex_encode(
                release_published ? mapping_receipt.artifact_root
                                  : progress.artifact_root,
                32, mapping_hex);
            if (details) {
                (void)json_push_kv_str(&reply->data,
                                       "package_mapping_root",
                                       mapping_hex);
                (void)json_push_kv_int(&reply->data, "bytes_scanned",
                                       (int64_t)progress.bytes_scanned);
                (void)json_push_kv_int(&reply->data, "new_chunks",
                                       progress.new_chunks);
                (void)json_push_kv_int(&reply->data, "reused_chunks",
                                       progress.reused_chunks);
            }
        }
        if (release_published) {
            char release_hex[65];
            zcl_hex_encode(release_receipt.artifact_root, 32, release_hex);
            if (details)
                (void)json_push_kv_str(&reply->data, "release_root",
                                       release_hex);
        }
        if (passport_published) {
            char passport_hex[65];
            zcl_hex_encode(passport_receipt.artifact_root, 32, passport_hex);
            if (details)
                (void)json_push_kv_str(&reply->data, "passport_root",
                                       passport_hex);
        }
        if (workspace_published) {
            char workspace_hex[65];
            zcl_hex_encode(workspace_receipt.artifact_root, 32,
                           workspace_hex);
            if (details)
                (void)json_push_kv_str(&reply->data, "workspace_root",
                                       workspace_hex);
        }
        if (provider_announced) {
            char provider_hex[65];
            zcl_hex_encode(provider_receipt.artifact_root, 32, provider_hex);
            if (details) {
                (void)json_push_kv_str(&reply->data,
                                       "provider_record_root",
                                       provider_hex);
                (void)json_push_kv_int(&reply->data, "providers",
                                       progress.providers);
            }
        }
        if (storage_acknowledged) {
            char ack_set_hex[65];
            zcl_hex_encode(source_reproduced
                               ? storage_receipt.artifact_root
                               : progress.artifact_root,
                           32, ack_set_hex);
            if (details) {
                (void)json_push_kv_str(&reply->data,
                                       "storage_ack_set_root", ack_set_hex);
                (void)json_push_kv_int(&reply->data, "storage_acks",
                                       progress.storage_acks);
            }
        }
        if (source_reproduced) {
            char reproduction_hex[65];
            zcl_hex_encode(progress.artifact_root, 32, reproduction_hex);
            if (details)
                (void)json_push_kv_str(
                    &reply->data, "source_reproduction_record_root",
                    reproduction_hex);
            (void)json_push_kv_str(
                &reply->data, "reproduced",
                "signed_distinct_source_reconstruction");
            (void)json_push_kv_bool(
                &reply->data, "physical_independence_attested", false);
        }
        if (details && lane_name[0])
            (void)json_push_kv_str(&reply->data, "lane", lane_name);
        if (details && proof_set_hex[0])
            (void)json_push_kv_str(&reply->data, "proof_set_root",
                                   proof_set_hex);
        vcs_package_mapping_set_free(&mapping);
    }
    if (details) (void)json_push_kv_str(
        &reply->data, "blocker",
        lane_bound && !acceptance_verified
            ? "proven_work_datadir_reverification_required" :
        source_reproduced ? "physical_off_host_attestation_not_represented" :
        storage_acknowledged ? "remote_reproduction_required" :
        provider_announced ? "storage_ack_required" :
        workspace_published ? "provider_announcement_required" :
        passport_published ? "workspace_manifest_signature_required" :
        release_published ? "passport_and_workspace_manifest_signature_required" :
        mapping_ready ? "offline_publisher_metadata_and_signature_required" :
        mapping_failed ? "package_mapping_retry_required" :
        lane_bound ? "package_mapping_worker_advance_required"
                   : "human_proven_work_and_offline_publisher_signature_required");
    (void)json_push_kv_bool(&reply->data, "package_written", false);
    (void)json_push_kv_bool(&reply->data, "mapping_cache_written",
                            mapping_ready && !release_published && !reused);
    (void)json_push_kv_bool(&reply->data, "network_called", false);
    (void)json_push_kv_bool(&reply->data, "wallet_called", false);
    if (details) (void)json_push_kv_str(
        &reply->data, "next_command",
        lane_bound && !acceptance_verified
            ? "z23 discover schema dev.publication.advance" :
        source_reproduced ? retry_command :
        storage_acknowledged ? collect_command :
        provider_announced ?
            collect_command :
        workspace_published ?
            "z23 discover search provider" :
        passport_published ?
            "z23 discover schema zcode.workspace.manifest.plan" :
        release_published ?
            "z23 discover schema zcode.passport.plan" :
        mapping_ready ?
            "z23 discover schema zcode.package.dev.publish.plan" :
        lane_bound ? retry_command :
            "z23 zcode guide");
}

void zcl_native_handle_dev_publication_collect(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *job_hex = json_get_str(json_get(request->input, "job_root"));
    uint8_t job_root[32];
    char job_root_err[128];
    if (!zcl_native_require_hex64("job_root", job_hex, job_root, job_root_err,
                                  sizeof(job_root_err))) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "INVALID_JOB_ROOT", "normalize", false, false, job_root_err,
            job_hex ? job_hex : "missing job_root");
        return;
    }

    struct vcs_zcode_dht_record_verify_context verify = {
        .now_unix = (uint64_t)platform_time_wall_time_t(),
    };
    if (!zcl_native_zcode_network_genesis(verify.network_genesis)) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
            "PUBLICATION_NODE_UNAVAILABLE", "network", true, false,
            "the authenticated local node could not resolve network genesis",
            "getblockhash(0)");
        return;
    }
    const char *repo_root = dev_source_root(request);
    struct vcs_devloop_publication_ack_target target;
    bool collecting_reproduction =
        vcs_devloop_publication_source_reproduction_target(
            repo_root, job_root, &verify, &target);
    if (!collecting_reproduction &&
        !vcs_devloop_publication_storage_ack_target(
            repo_root, job_root, &verify, &target)) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
            "STORAGE_ACK_TARGET_UNAVAILABLE", "load", true, false,
            "the job has no verified provider-announced package target",
            job_hex);
        return;
    }

    (void)json_push_kv_str(&reply->data, "schema",
                           "zcl.dev_publication_collect.v1");
    (void)json_push_kv_str(&reply->data, "publication_job_root", job_hex);
    (void)json_push_kv_int(&reply->data, "required_storage_acks",
                           VCS_DEVLOOP_PUBLICATION_ACK_MIN);
    (void)json_push_kv_int(&reply->data,
                           "required_source_reproduction_acks", 1);
    (void)json_push_kv_bool(&reply->data, "network_called", true);
    (void)json_push_kv_bool(&reply->data, "discovery_called",
                            collecting_reproduction
                                ? !target.already_reproduced
                                : !target.already_acknowledged);
    (void)json_push_kv_str(
        &reply->data, "chain_authority",
        "authenticated_local_node_discovery_plus_local_signature_recheck");
    if (collecting_reproduction && target.already_reproduced) {
        (void)json_push_kv_str(&reply->data, "status",
                               "SOURCE_REPRODUCED");
        (void)json_push_kv_int(&reply->data, "storage_acks",
                               target.existing_acks);
        (void)json_push_kv_str(
            &reply->data, "reproduced",
            "signed_distinct_source_reconstruction");
        (void)json_push_kv_bool(
            &reply->data, "physical_independence_attested", false);
        (void)json_push_kv_bool(&reply->data, "receipt_reused", true);
        (void)json_push_kv_bool(&reply->data, "receipt_written", false);
        (void)json_push_kv_str(&reply->data, "blocker",
                               "physical_off_host_attestation_not_represented");
        return;
    }

    char transport_hex[65];
    zcl_hex_encode(target.transport_root, 32, transport_hex);
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(
        &input, "kind", collecting_reproduction
                            ? "source_reproduction_ack" : "storage_ack");
    (void)json_push_kv_str(&input, "namespace", target.namespace_name);
    (void)json_push_kv_str(&input, "transport_root", transport_hex);
    (void)json_push_kv_bool(&input, "include_evidence_wires", true);
    struct zcl_command_request discovery_request = *request;
    discovery_request.input = &input;
    struct zcl_command_reply discovery;
    zcl_command_reply_init(&discovery, "zcl.zcode_network_records.v1");
    zcl_native_handle_zcode_network_records(&discovery_request, &discovery);
    json_free(&input);
    if (discovery.exit_code != ZCL_COMMAND_EXIT_OK) {
        zcl_command_reply_fail(
            reply, discovery.status, discovery.exit_code,
            discovery.error.code[0] ? discovery.error.code
                                    : collecting_reproduction
                                        ? "SOURCE_REPRODUCTION_DISCOVERY_FAILED"
                                        : "STORAGE_ACK_DISCOVERY_FAILED",
            discovery.error.phase[0] ? discovery.error.phase : "network",
            discovery.error.retryable, false,
            discovery.error.message[0]
                ? discovery.error.message
                : collecting_reproduction
                    ? "source reproduction discovery failed"
                    : "storage ACK discovery failed",
            discovery.error.evidence);
        zcl_command_reply_free(&discovery);
        return;
    }

    uint8_t wires[VCS_DEVLOOP_PUBLICATION_ACK_MAX]
                 [VCS_ZCODE_DHT_RECORD_WIRE_BYTES];
    const uint8_t *wire_ptrs[VCS_DEVLOOP_PUBLICATION_ACK_MAX];
    size_t wire_lengths[VCS_DEVLOOP_PUBLICATION_ACK_MAX];
    size_t wire_count = 0;
    const struct json_value *rows = json_get(&discovery.data, "records");
    size_t row_count = rows && rows->type == JSON_ARR ? json_size(rows) : 0;
    for (size_t i = 0;
         i < row_count && wire_count < VCS_DEVLOOP_PUBLICATION_ACK_MAX; i++) {
        const struct json_value *row = json_at(rows, i);
        const char *wire_hex = row
            ? json_get_str(json_get(row, "record_wire")) : NULL;
        if (!wire_hex ||
            strlen(wire_hex) != VCS_ZCODE_DHT_RECORD_WIRE_BYTES * 2u ||
            !zcl_hex_decode_lower(
                wire_hex, wires[wire_count], sizeof(wires[wire_count])))
            continue;
        wire_ptrs[wire_count] = wires[wire_count];
        wire_lengths[wire_count] = sizeof(wires[wire_count]);
        wire_count++;
    }
    (void)json_push_kv_int(&reply->data, "records_seen", (int64_t)row_count);
    (void)json_push_kv_int(&reply->data, "evidence_wires",
                           (int64_t)wire_count);
    size_t required = collecting_reproduction
        ? 1u : VCS_DEVLOOP_PUBLICATION_ACK_MIN;
    if (wire_count < required) {
        (void)json_push_kv_str(
            &reply->data, "status",
            collecting_reproduction
                ? "SOURCE_REPRODUCTION_PENDING" : "ACKS_PENDING");
        (void)json_push_kv_int(&reply->data, "storage_acks",
                               collecting_reproduction
                                   ? target.existing_acks
                                   : (int64_t)wire_count);
        (void)json_push_kv_bool(&reply->data, "receipt_reused", false);
        (void)json_push_kv_bool(&reply->data, "receipt_written", false);
        (void)json_push_kv_str(
            &reply->data, "blocker",
            collecting_reproduction
                ? "distinct_signed_source_reconstruction_required"
                : "independent_storage_acks_required");
        char next[256];
        int n = snprintf(
            next, sizeof(next),
            "z23-dev dev publication collect --input='"
            "{\"job_root\":\"%s\"}'", job_hex);
        if (collecting_reproduction && n > 0 &&
            (size_t)n < sizeof(next))
            (void)json_push_kv_str(
                &reply->data, "after_reproduction_command", next);
        if (collecting_reproduction) {
            char reproduce[384];
            int rn = snprintf(
                reproduce, sizeof(reproduce),
                "z23 zcode package source reproduce --input='"
                "{\"mode\":\"plan\",\"root\":\"%s\","
                "\"namespace\":\"%s\"}'",
                transport_hex, target.namespace_name);
            if (rn > 0 && (size_t)rn < sizeof(reproduce))
                (void)json_push_kv_str(
                    &reply->data, "next_command", reproduce);
        } else if (n > 0 && (size_t)n < sizeof(next)) {
            (void)json_push_kv_str(&reply->data, "next_command", next);
        }
        zcl_command_reply_free(&discovery);
        return;
    }

    uint8_t receipt_root[32];
    bool reused = false;
    bool advanced = false;
    if (collecting_reproduction) {
        for (size_t i = 0; i < wire_count && !advanced; i++)
            advanced =
                vcs_devloop_publication_advance_source_reproduction_ack(
                    repo_root, job_root, wire_ptrs[i], wire_lengths[i],
                    &verify, receipt_root, &reused);
    } else {
        advanced = vcs_devloop_publication_advance_storage_acks(
            repo_root, job_root, wire_ptrs, wire_lengths, wire_count,
            &verify, receipt_root, &reused);
    }
    zcl_command_reply_free(&discovery);
    if (!advanced) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            collecting_reproduction ? "SOURCE_REPRODUCTION_BIND_FAILED"
                                   : "STORAGE_ACK_BIND_FAILED",
            "verify", true, false,
            collecting_reproduction
                ? "the signed reconstruction failed exact source/package/witness-distinct verification"
                : "discovered ACK wires failed exact job/package/diversity verification",
            job_hex);
        return;
    }
    char receipt_hex[65];
    zcl_hex_encode(receipt_root, 32, receipt_hex);
    (void)json_push_kv_str(
        &reply->data, "status",
        collecting_reproduction ? "SOURCE_REPRODUCED"
                               : "STORAGE_ACKNOWLEDGED");
    (void)json_push_kv_int(&reply->data, "storage_acks",
                           collecting_reproduction
                               ? target.existing_acks
                               : (int64_t)wire_count);
    (void)json_push_kv_str(&reply->data, "progress_receipt_root",
                           receipt_hex);
    (void)json_push_kv_bool(&reply->data, "receipt_reused", reused);
    (void)json_push_kv_bool(&reply->data, "receipt_written", !reused);
    if (collecting_reproduction) {
        (void)json_push_kv_str(
            &reply->data, "reproduced",
            "signed_distinct_source_reconstruction");
        (void)json_push_kv_bool(
            &reply->data, "physical_independence_attested", false);
        (void)json_push_kv_str(
            &reply->data, "blocker",
            "physical_off_host_attestation_not_represented");
    } else {
        char reproduce[384];
        int rn = snprintf(
            reproduce, sizeof(reproduce),
            "z23 zcode package source reproduce --input='"
            "{\"mode\":\"plan\",\"root\":\"%s\","
            "\"namespace\":\"%s\"}'",
            transport_hex, target.namespace_name);
        (void)json_push_kv_str(&reply->data, "blocker",
                               "remote_reproduction_required");
        if (rn > 0 && (size_t)rn < sizeof(reproduce))
            (void)json_push_kv_str(
                &reply->data, "next_command", reproduce);
    }
}

void zcl_native_handle_dev_core_boundary(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    (void)request;
    static const char *const core[] = {
        "consensus", "validation", "chain_mutation", "wallet_keys",
        "raw_storage", "sockets", "boot"
    };
    static const char *const apps[] = {
        "resources", "signed_events", "services", "projections", "web",
        "onion", "znam", "p2p_topics"
    };
    (void)json_push_kv_str(&reply->data, "schema", "zcl.core_app_boundary.v1");
    (void)json_push_kv_str(&reply->data, "rule",
                           "core_owns_truth_apps_consume_capabilities");
    struct json_value core_arr, app_arr;
    json_init(&core_arr);
    json_init(&app_arr);
    json_set_array(&core_arr);
    json_set_array(&app_arr);
    for (size_t i = 0; i < sizeof(core) / sizeof(core[0]); i++) {
        struct json_value it;
        json_init(&it);
        json_set_str(&it, core[i]);
        (void)json_push_back(&core_arr, &it);
        json_free(&it);
    }
    for (size_t i = 0; i < sizeof(apps) / sizeof(apps[0]); i++) {
        struct json_value it;
        json_init(&it);
        json_set_str(&it, apps[i]);
        (void)json_push_back(&app_arr, &it);
        json_free(&it);
    }
    (void)json_push_kv(&reply->data, "core", &core_arr);
    (void)json_push_kv(&reply->data, "apps", &app_arr);
    (void)json_push_kv_str(&reply->data, "core_change", "guarded_reload");
    (void)json_push_kv_str(&reply->data, "app_change",
                           "simulate_then_atomic_publish");
    json_free(&core_arr);
    json_free(&app_arr);
}

/* ── dev.app.describe ──────────────────────────────────────────────────── */
void zcl_native_handle_dev_app_describe(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *app_id = json_get_str(json_get(request->input, "app_id"));
    if (!app_id || !app_id[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_APP_ID",
                               "normalize", false, false,
                               "app_id is required", "");
        return;
    }
    char body[8192];
    size_t n = zcl_devloop_app_describe_json(dev_source_root(request), app_id,
                                             body, sizeof(body));
    if (n == 0) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "INVALID_APP",
                               "resolve", false, false,
                               "unknown App or checkout root", app_id);
        return;
    }
    dev_reply_from_json(reply, body, n, app_id);
}

/* ── dev.app.plan ──────────────────────────────────────────────────────── */
void zcl_native_handle_dev_app_plan(const struct zcl_command_request *request,
                                    struct zcl_command_reply *reply)
{
    const char *app_id = json_get_str(json_get(request->input, "app_id"));
    const char *resource = json_get_str(json_get(request->input, "resource"));
    if (!app_id || !app_id[0] || !resource || !resource[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_ARGS",
                               "normalize", false, false,
                               "app_id and resource are required", "");
        return;
    }
    char body[4096];
    size_t n = zcl_devloop_app_plan_json(dev_source_root(request), app_id,
                                         resource, body, sizeof(body));
    if (n == 0) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "INVALID_ARGS",
                               "resolve", false, false,
                               "invalid App, resource, or checkout root",
                               app_id);
        return;
    }
    dev_reply_from_json(reply, body, n, app_id);
}

/* ── dev.app.simulate ──────────────────────────────────────────────────── */
void zcl_native_handle_dev_app_simulate(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *app_id = json_get_str(json_get(request->input, "app_id"));
    if (!app_id || !app_id[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_APP_ID",
                               "normalize", false, false,
                               "app_id is required", "");
        return;
    }
    uint64_t seed = UINT64_C(0x534f4349414c0001);
    const struct json_value *seed_v = json_get(request->input, "seed");
    if (seed_v && !json_is_null(seed_v)) {
        if (seed_v->type == JSON_STR) {
            char *end = NULL;
            errno = 0;
            seed = strtoull(json_get_str(seed_v), &end, 0);
            if (errno != 0 || !end || *end || seed == 0) {
                zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                       ZCL_COMMAND_EXIT_INVALID, "INVALID_SEED",
                                       "normalize", false, false,
                                       "seed must be a nonzero uint64 integer or string",
                                       "seed");
                return;
            }
        } else if (seed_v->type == JSON_INT && json_get_int(seed_v) > 0) {
            seed = (uint64_t)json_get_int(seed_v);
        } else {
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INVALID, "INVALID_SEED",
                                   "normalize", false, false,
                                   "seed must be a nonzero uint64 integer or string",
                                   "seed");
            return;
        }
    }
    const struct json_value *scenario_v = json_get(request->input, "scenario");
    if (scenario_v && !json_is_null(scenario_v) &&
        (scenario_v->type != JSON_STR ||
         (strcmp(json_get_str(scenario_v), "default") != 0 &&
          strcmp(json_get_str(scenario_v), "network") != 0))) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "INVALID_SCENARIO",
                               "normalize", false, false,
                               "scenario must be 'default' or 'network'",
                               "scenario");
        return;
    }
    char body[4096];
    size_t n = zcl_devloop_app_simulate_json(app_id, seed, body, sizeof(body));
    if (n == 0) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "INVALID_SIM",
                               "resolve", false, false,
                               "unknown App or invalid seed", app_id);
        return;
    }
    dev_reply_from_json(reply, body, n, app_id);
}

/* ── dev.change.plan ───────────────────────────────────────────────────── */

void zcl_native_handle_dev_change_plan(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *file_ptrs[ZCL_DEVLOOP_MAX_FILES];
    size_t count = 0;
    char why[160];
    if (!dev_request_files(request->input, true, file_ptrs, &count,
                           why, sizeof(why))) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "INVALID_FILE_SET",
                               "normalize", false, false, why, "files");
        return;
    }
    char body[16384];
    /* Path-glob floor + symbol-closure additions (F3). The closure is
     * best-effort: an unavailable/failed index degrades to the path floor, so
     * the reply is always a valid plan. repo_root is the process cwd. */
    size_t n = zcl_devloop_plan_json_closure(".", file_ptrs, count, body,
                                             sizeof(body));
    if (n == 0) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "INVALID_FILE_SET",
                               "normalize", false, false,
                               "invalid or oversized file set", "");
        return;
    }
    dev_reply_from_json(reply, body, n, "change.plan");
}

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)

static bool dev_drive_copy(const struct json_value *from,
                           struct json_value *to, const char *from_key,
                           const char *to_key)
{
    const struct json_value *value = json_get(from, from_key);
    return !value || json_push_kv(to, to_key, value);
}

static bool dev_drive_wait_cycle(
    const struct zcl_command_request *request, struct json_value *cycle,
    int64_t *epoch_out, struct zcl_command_reply *reply)
{
    int64_t after = 0, timeout_ms = 30000;
    const struct json_value *wait_v = request && request->input
        ? json_get(request->input, "wait_for_edit") : NULL;
    bool wait_for_edit = wait_v && wait_v->type == JSON_BOOL
        ? json_get_bool(wait_v) : false;
    if (!dev_drive_input_int(request->input, "after_epoch", 0, &after) ||
        after < 0 ||
        !dev_drive_input_int(request->input, "timeout_ms", 30000,
                             &timeout_ms) ||
        timeout_ms < 1 || timeout_ms > 300000 ||
        (wait_v && wait_v->type != JSON_BOOL)) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "INVALID_DRIVE", "normalize", false, false,
            "after_epoch must be nonnegative, timeout_ms 1..300000, and wait_for_edit boolean",
            "after_epoch,timeout_ms,wait_for_edit");
        return false;
    }
    int64_t deadline_us = platform_time_monotonic_us() + timeout_ms * 1000;
    int64_t current_epoch = after;
    bool edit_seen = !wait_for_edit;
    char target_edit_epoch[65] = {0};
    for (;;) {
        int64_t remaining_us = deadline_us - platform_time_monotonic_us();
        if (remaining_us <= 0)
            break;
        int64_t remaining_ms = (remaining_us + 999) / 1000;
        char body[16384], why[160] = {0};
        size_t body_len = 0;
        enum zcl_devloop_state_lookup lookup =
            zcl_devloop_cycle_state_wait_after(
                dev_source_root(request), current_epoch, (int)remaining_ms,
                body, sizeof(body), &body_len, &current_epoch,
                why, sizeof(why));
        if (lookup == ZCL_DEVLOOP_STATE_INVALID) {
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                "DEV_CYCLE_STATE_INVALID", "read", false, false,
                "workspace cycle state failed schema, SHA3, inode, or event-watch validation",
                why[0] ? why : "cycle_state_invalid");
            return false;
        }
        if (lookup != ZCL_DEVLOOP_STATE_FOUND)
            break;
        if (!json_read(cycle, body, body_len) || cycle->type != JSON_OBJ) {
            json_free(cycle);
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_FAILED,
                ZCL_COMMAND_EXIT_INTERNAL, "DEV_CYCLE_STATE_INVALID",
                "decode", false, false,
                "workspace cycle state is not one canonical object",
                "cycle_state_decode_failed");
            return false;
        }
        const char *status = json_get_str(json_get(cycle, "status"));
        const char *source = json_get_str(json_get(cycle, "source_tu"));
        const char *event_edit_epoch =
            json_get_str(json_get(cycle, "edit_epoch"));
        if (!edit_seen) {
            if (status && strcmp(status, "edit_seen") == 0)
                edit_seen = true;
            json_free(cycle);
            json_init(cycle);
            continue;
        }
        /* SUPERSEDED names work from the prior edit. It is part of the exact
         * stream, but must never bind a new drive to that prior epoch or
         * become the one-command result for the newer save. */
        if (wait_for_edit && status && strcmp(status, "superseded") == 0) {
            json_free(cycle);
            json_init(cycle);
            continue;
        }
        if (!target_edit_epoch[0] && event_edit_epoch &&
            strlen(event_edit_epoch) == 64)
            (void)snprintf(target_edit_epoch, sizeof(target_edit_epoch), "%s",
                           event_edit_epoch);
        if (target_edit_epoch[0] && event_edit_epoch &&
            strcmp(target_edit_epoch, event_edit_epoch) != 0) {
            json_free(cycle);
            json_init(cycle);
            continue;
        }
        const struct dev_reflex_policy_service_v1 *policy =
            dev_reflex_policy_service_builtin();
        if (policy->action_changing(status, source)) {
            *epoch_out = current_epoch;
            return true;
        }
        /* `dev.loop.wait` exposes every stage. The normal one-command drive
         * consumes acknowledgements internally and returns the first result
         * that can change the next edit: a diagnostic, or this owner's exact
         * HOT_SHADOW behavior story. */
        json_free(cycle);
        json_init(cycle);
    }
    char evidence[128];
    (void)snprintf(evidence, sizeof(evidence), "current_epoch=%lld",
                   (long long)current_epoch);
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
        "DRIVE_TIMEOUT", "wait", true, false,
        "no newer exact cycle verdict before timeout", evidence);
    /* Never point a command's next[] back to itself: the registry rejects
     * self-loops and would replace this useful timeout with the generic
     * RESPONSE_BUDGET_EXCEEDED fallback. */
    (void)zcl_command_reply_add_next(
        reply, "dev.loop.status", "{}",
        "confirm the warm service state before waiting for another edit");
    return false;
}

static void dev_drive_merge_publication(
    const struct zcl_command_request *request, const char *job_root,
    struct json_value *out)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "job_root", job_root);
    struct zcl_command_request status_request = *request;
    status_request.input = &input;
    struct zcl_command_reply status_reply;
    zcl_command_reply_init(&status_reply, "zcl.dev_publication_status.v1");
    zcl_native_handle_dev_publication_status(&status_request, &status_reply);
    if (status_reply.exit_code == ZCL_COMMAND_EXIT_OK) {
        static const struct {
            const char *from;
            const char *to;
        } fields[] = {
            { "status", "publication_stage" },
            { "progress_receipt_root", "progress_receipt_root" },
            { "lane_receipt_root", "lane_receipt_root" },
            { "package_mapping_root", "package_mapping_root" },
            { "release_root", "release_root" },
            { "passport_root", "passport_root" },
            { "workspace_root", "workspace_root" },
            { "provider_record_root", "provider_record_root" },
            { "bytes_scanned", "bytes_scanned" },
            { "new_chunks", "new_chunks" },
            { "reused_chunks", "reused_chunks" },
            { "p2p", "p2p" },
            { "providers", "providers" },
            { "storage_ack", "storage_ack" },
            { "reproduced", "reproduced" },
            { "github_mirror", "github_mirror" },
            { "mirror_receipt_root", "mirror_receipt_root" },
            { "mirror_git_oid", "mirror_git_oid" },
            { "blocker", "blocker" },
            { "next_command", "next_command" },
        };
        for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++)
            (void)dev_drive_copy(&status_reply.data, out, fields[i].from,
                                 fields[i].to);
    } else {
        char next[256];
        (void)json_push_kv_str(out, "publication_stage", "ERROR");
        (void)json_push_kv_str(
            out, "blocker", status_reply.error.code[0]
                ? status_reply.error.code : "publication_receipt_invalid");
        int n = snprintf(
            next, sizeof(next),
            "z23-dev dev publication status --input='"
            "{\"job_root\":\"%s\"}'", job_root);
        if (n > 0 && (size_t)n < sizeof(next))
            (void)json_push_kv_str(out, "next_command", next);
    }
    zcl_command_reply_free(&status_reply);
    json_free(&input);
}

void zcl_native_handle_dev_drive(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    struct json_value cycle;
    json_init(&cycle);
    int64_t epoch = 0;
    if (!dev_drive_wait_cycle(request, &cycle, &epoch, reply))
        return;

    struct json_value compact;
    const struct dev_reflex_policy_service_v1 *policy =
        dev_reflex_policy_service_builtin();
    if (!policy->project_cycle(&cycle, epoch, &compact)) {
        json_free(&cycle);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
            "DEV_DRIVE_PROJECTION_INVALID", "project", false, false,
            "pure reflex policy could not project the cycle", "cycle");
        return;
    }

    const char *job_root =
        json_get_str(json_get(&cycle, "publication_job_root"));
    if (job_root && job_root[0]) {
        dev_drive_merge_publication(request, job_root, &compact);
    } else {
        const char *status = json_get_str(json_get(&cycle, "status"));
        bool passed = status && strcmp(status, "passed") == 0;
        bool edit_seen = status && strcmp(status, "edit_seen") == 0;
        bool impact_ready = status && strcmp(status, "impact_ready") == 0;
        bool reflex_ready = status && strcmp(status, "reflex_ready") == 0;
        bool compile_only = status && strcmp(status, "compile_only") == 0;
        bool story_green = status && strcmp(status, "story_green") == 0;
        bool story_red = status && strcmp(status, "story_red") == 0;
        bool explicit_proof_pending =
            status && strcmp(status, "proof_pending") == 0;
        bool reactor_pending = edit_seen || impact_ready;
        bool proof_pending = explicit_proof_pending || reflex_ready ||
            story_green ||
            (status &&
             ((strcmp(status, "feedback_ready") == 0 &&
               json_get_bool(json_get(&cycle,
                                      "immediate_proof_complete"))) ||
              strcmp(status, "fallback_ready") == 0) &&
             json_get_bool(json_get(&cycle, "integration_proof_deferred")));
        bool proof_complete =
            json_get_bool(json_get(&cycle, "proof_complete"));
        (void)json_push_kv_str(
            &compact, "publication_stage",
            reactor_pending ? "REFLEX" :
            (reflex_ready || story_green) ? "ASYNC_PROOF" :
            compile_only ? "PROOF_PENDING" :
            proof_pending ? "PROOF_PENDING" : "NOT_QUEUED");
        (void)json_push_kv_str(
            &compact, "blocker",
            edit_seen ? "impact_analysis_running" :
            impact_ready ? "candidate_diagnostics_running" :
            (reflex_ready || story_green) ? "affected_proof_running" :
            compile_only ? "candidate_story_not_available" :
            story_red ? "behavior_story_failed" :
            proof_pending ? "integration_proof_pending" :
            proof_complete ? "publication_job_missing" :
            passed ? "complete_reusable_proof_required" : "proof_failed");
        char next[192];
        if (reactor_pending || proof_pending)
            (void)snprintf(
                next, sizeof(next),
                "z23-dev dev drive --input='{\"after_epoch\":%lld}'",
                (long long)epoch);
        else
            (void)snprintf(
                next, sizeof(next), "%s",
                passed ? "z23-dev dev ff"
                       : "z23-dev dev diagnose latest");
        (void)json_push_kv_str(&compact, "next_command", next);
    }
    json_free(&reply->data);
    json_init(&reply->data);
    json_copy(&reply->data, &compact);
    json_free(&compact);
    json_free(&cycle);
}

#endif /* ZCL_DEV_BUILD || ZCL_TESTING */

#ifdef ZCL_DEV_BUILD

static bool dev_reflex_policy_frozen_kat(const void *vtable,
                                         char *why, size_t why_size)
{
    const struct dev_reflex_policy_service_v1 *service = vtable;
    if (!service || !service->progress_phase || !service->action_changing ||
        !service->project_cycle || !service->handoff_validate) {
        if (why && why_size)
            (void)snprintf(why, why_size, "%s", "reflex policy vtable incomplete");
        return false;
    }
    if (strcmp(service->progress_phase("story_red", "service_story"),
               "STORY_RED") != 0 ||
        service->action_changing("impact_ready", NULL) ||
        service->action_changing("reflex_ready", "candidate.c") ||
        !service->action_changing("story_red", "candidate.c")) {
        if (why && why_size)
            (void)snprintf(why, why_size, "%s", "event policy vector changed");
        return false;
    }
    struct json_value cycle, projected;
    json_init(&cycle); json_set_object(&cycle);
    bool built = json_push_kv_str(&cycle, "status", "story_green") &&
        json_push_kv_str(&cycle, "phase", "STORY_GREEN") &&
        json_push_kv_str(&cycle, "action", "hotswap") &&
        json_push_kv_str(&cycle, "edit_epoch",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") &&
        json_push_kv_str(&cycle, "loaded_mapping_root",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") &&
        json_push_kv_str(&cycle, "story_detail", "checks=4/5;failed_mask=0x4") &&
        json_push_kv_int(&cycle, "elapsed_us", 73) &&
        json_push_kv_bool(&cycle, "runtime_published", false) &&
        json_push_kv_bool(&cycle, "proof_complete", false);
    bool projected_ok = built && service->project_cycle(&cycle, 9, &projected);
    const char *lane = projected_ok
        ? json_get_str(json_get(&projected, "lane")) : NULL;
    bool vector_ok = projected_ok && lane && strcmp(lane, "REFLEX") == 0 &&
        json_get_int(json_get(&projected, "feedback_us")) == 73 &&
        strcmp(json_get_str(json_get(&projected, "loaded_mapping_root")),
               "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") == 0 &&
        strcmp(json_get_str(json_get(&projected, "story_detail")),
               "checks=4/5;failed_mask=0x4") == 0 &&
        !json_get_bool(json_get(&projected, "runtime_published"));
    if (projected_ok) json_free(&projected);
    json_free(&cycle);
    struct dev_reflex_proof_handoff_v2 handoff = {
        .candidate_epoch =
            "1111111111111111111111111111111111111111111111111111111111111111",
        .source_epoch =
            "2222222222222222222222222222222222222222222222222222222222222222",
        .affected_component = "tools/dev",
        .action = "verify",
        .proof_inputs_sha3 =
            "3333333333333333333333333333333333333333333333333333333333333333",
        .focused_evidence_sha3 =
            "4444444444444444444444444444444444444444444444444444444444444444",
        .feedback_class = "HOT_SHADOW_CORE",
        .candidate_object_root =
            "5555555555555555555555555555555555555555555555555555555555555555",
        .candidate_module_root =
            "6666666666666666666666666666666666666666666666666666666666666666",
        .story_root =
            "7777777777777777777777777777777777777777777777777777777777777777",
        .story_fixture_root =
            "8888888888888888888888888888888888888888888888888888888888888888",
        .observation_root =
            "9999999999999999999999999999999999999999999999999999999999999999",
        .affected_file_count = 1,
        .compile_green = true,
        .story_obtained = true,
    };
    if (!vector_ok || !service->handoff_validate(&handoff, why, why_size)) {
        if (!vector_ok && why && why_size)
            (void)snprintf(why, why_size, "%s", "projection vector changed");
        return false;
    }
    handoff.compile_green = false;
    if (service->handoff_validate(&handoff, NULL, 0)) {
        if (why && why_size)
            (void)snprintf(why, why_size, "%s", "red compile crossed proof boundary");
        return false;
    }
    return true;
}

static const struct zcl_hotswap_service_contract k_dev_reflex_contract = {
    .service_id = DEV_REFLEX_POLICY_SERVICE_ID,
    .source_tu = "cognition/services/src/dev_reflex_policy_service.c",
    .abi_version = ZCL_HOTSWAP_SERVICE_ABI_V1,
    .vtable_size = sizeof(struct dev_reflex_policy_service_v1),
    .abi_fingerprint = DEV_REFLEX_POLICY_ABI,
    .schema_fingerprint = DEV_REFLEX_POLICY_SCHEMA,
    .wire_fingerprint = DEV_REFLEX_POLICY_WIRE,
    .kat_fingerprint = DEV_REFLEX_POLICY_KAT,
    .frozen_kat = dev_reflex_policy_frozen_kat,
};

const struct zcl_hotswap_service_contract *
zcl_native_dev_reflex_policy_service_contract(void)
{
    return &k_dev_reflex_contract;
}

/* The registry is the public grammar.  These helpers adapt the existing
 * bounded native devloop engine without letting its legacy stdout document
 * escape ahead of the registry's single zcl.result.v1 envelope. */
typedef int (*dev_captured_fn)(void *arg);

static bool dev_capture_stdout(dev_captured_fn fn, void *arg, char *out,
                               size_t out_size, int *call_rc)
{
    if (!fn || !out || out_size < 2 || !call_rc)
        return false;
    FILE *tmp = tmpfile();
    if (!tmp)
        return false;
    int saved = dev_fd_dup(STDOUT_FILENO);
    if (saved < 0) {
        fclose(tmp);
        return false;
    }
    fflush(stdout);
    if (dev_fd_dup2(fileno(tmp), STDOUT_FILENO) < 0) {
        dev_fd_close(saved);
        fclose(tmp);
        return false;
    }
    *call_rc = fn(arg);
    fflush(stdout);
    bool restored = dev_fd_dup2(saved, STDOUT_FILENO) >= 0;
    dev_fd_close(saved);
    if (!restored || fseek(tmp, 0, SEEK_SET) != 0) {
        fclose(tmp);
        return false;
    }
    size_t n = fread(out, 1, out_size - 1, tmp);
    bool complete = !ferror(tmp) && fgetc(tmp) == EOF;
    fclose(tmp);
    out[n] = 0;
    return complete && n > 0;
}

struct dev_cycle_call {
    const char *root;
    const char *const *files;
    size_t count;
};

static int dev_call_cycle(void *opaque)
{
    struct dev_cycle_call *call = opaque;
    return zcl_devloop_run_cycle(call->root, call->files, call->count);
}

static int dev_call_sim(void *opaque)
{
    return zcl_devloop_run_sim((const char *)opaque);
}

static void dev_fail_with_data(struct zcl_command_reply *reply, int rc,
                               const char *code, const char *phase,
                               bool mutated, const char *message)
{
    enum zcl_command_status status = rc == ZCL_COMMAND_EXIT_BLOCKED
        ? ZCL_COMMAND_STATUS_BLOCKED : ZCL_COMMAND_STATUS_FAILED;
    enum zcl_command_exit exit_code = rc == ZCL_COMMAND_EXIT_BLOCKED
        ? ZCL_COMMAND_EXIT_BLOCKED : ZCL_COMMAND_EXIT_FAILED;
    zcl_command_reply_fail(reply, status, exit_code, code, phase, false,
                           mutated, message,
                           "run dev status for the persisted bounded verdict");
    (void)zcl_command_reply_add_next(
        reply, "dev.status", "{}",
        "read the persisted cycle verdict and executable next action");
}

void zcl_native_handle_dev_change_apply(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    (void)request;
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
        "RUNTIME_PUBLICATION_CONTAINED", "authority", false, false,
        "development generation publication is contained until immutable "
        "source epochs, complete proof receipts, resident CAS, and rollback "
        "are one durable transaction",
        "use dev.change.plan and the verify-only watcher to produce candidate evidence");
    return;

    /* Future transaction body. The unconditional authority gate above reaches
     * no build, loader, service-control, or generation-activation side effect. */
    const char *files[ZCL_DEVLOOP_MAX_FILES];
    size_t count = 0;
    char why[160];
    if (!dev_request_files(request->input, false, files, &count,
                           why, sizeof(why))) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "INVALID_FILE_SET",
                               "normalize", false, false, why, "files");
        return;
    }
    struct dev_cycle_call call = {
        .root = dev_source_root(request), .files = files, .count = count,
    };
    char body[16384];
    int rc = ZCL_COMMAND_EXIT_INTERNAL;
    if (!dev_capture_stdout(dev_call_cycle, &call, body, sizeof(body), &rc)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "CYCLE_CAPTURE_FAILED",
                               "execute", false, true,
                               "native cycle produced no bounded verdict", "");
        return;
    }
    dev_reply_from_json(reply, body, strlen(body), "change.apply");
    if (reply->exit_code == ZCL_COMMAND_EXIT_OK && rc != 0)
        dev_fail_with_data(reply, rc, "DEV_CYCLE_REJECTED", "prove_publish",
                           true, "development cycle did not publish");
}

static bool dev_state_dir(char out[PATH_MAX])
{
#if defined(_WIN32)
    return platform_state_root(out, PATH_MAX);
#else
    const char *home = getenv("HOME");
    int n = home && home[0]
        ? snprintf(out, PATH_MAX, "%s/.local/state/zclassic23-dev", home) : -1;
    return n > 0 && n < PATH_MAX;
#endif
}

static bool dev_mkdirs(const char *path)
{
#if defined(_WIN32)
    char state[PATH_MAX];
    return path && platform_state_root(state, sizeof(state)) &&
           strcmp(path, state) == 0;
#else
    char copy[PATH_MAX];
    if (!path || !path[0] || strlen(path) >= sizeof(copy))
        return false;
    (void)snprintf(copy, sizeof(copy), "%s", path);
    for (char *p = copy + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = 0;
        if (mkdir(copy, 0700) != 0 && errno != EEXIST)
            return false;
        *p = '/';
    }
    return mkdir(copy, 0700) == 0 || errno == EEXIST;
#endif
}

static bool dev_watch_paths(const char *repo_root,
                            char lock[PATH_MAX], char log[PATH_MAX])
{
    char dir[PATH_MAX];
    if (!repo_root || !repo_root[0] || !dev_state_dir(dir) ||
        !zcl_devloop_watch_lock_path(repo_root, lock, PATH_MAX))
        return false;
    int on = snprintf(log, PATH_MAX, "%s/native-watch.log", dir);
    return on > 0 && on < PATH_MAX;
}

typedef uint64_t dev_pid_t;

#if !defined(_WIN32)
static bool dev_legacy_watch_lock_path(char lock[PATH_MAX])
{
    char dir[PATH_MAX];
    if (!dev_state_dir(dir))
        return false;
    int n = snprintf(lock, PATH_MAX, "%s/native-watch.lock", dir);
    return n > 0 && n < PATH_MAX;
}
#endif

static bool dev_pid_is_watcher(dev_pid_t pid)
{
#if defined(_WIN32)
    char exe[PATH_MAX];
    if (pid <= 1 || os_proc_pid_liveness(pid) != OS_PROC_LIVENESS_RUNNING ||
        !os_proc_pid_exe_path(pid, exe, sizeof(exe))) return false;
    const char *base = strrchr(exe, '\\');
    if (!base) base = strrchr(exe, '/');
    return base && (_stricmp(base + 1, "zclassic23-dev.exe") == 0 ||
                    _stricmp(base + 1, "zclassic23-dev") == 0 ||
                    _stricmp(base + 1, "z23-dev.exe") == 0 ||
                    _stricmp(base + 1, "z23-dev") == 0);
#else
    if (pid <= 1 || (kill(pid, 0) != 0 && errno != EPERM))
        return false;
    char exe[PATH_MAX];
    if (!os_proc_pid_exe_path(pid, exe, sizeof(exe)))
        return false;
    /* A live watcher whose on-disk binary was replaced (every rebuild of
     * build/bin/zclassic23-dev does exactly this while the watcher runs)
     * shows up as "<path> (deleted)" in /proc/<pid>/exe. Strip that suffix
     * before the basename compare so the watcher stays recognized across a
     * dev-binary rebuild — otherwise `dev loop status` reports active:false
     * and `dev loop ensure` tries to spawn a duplicate against the held
     * singleton lock. */
    static const char kDeleted[] = " (deleted)";
    size_t dlen = sizeof(kDeleted) - 1;
    size_t exe_len = strlen(exe);
    if (exe_len >= dlen && strcmp(exe + exe_len - dlen, kDeleted) == 0)
        exe[exe_len - dlen] = 0;
    const char *base = strrchr(exe, '/');
    return base && (strcmp(base + 1, "zclassic23-dev") == 0 ||
                    strcmp(base + 1, "z23-dev") == 0);
#endif
}

#if !defined(_WIN32)
static bool dev_pid_cwd_matches_root(dev_pid_t pid, const char *repo_root)
{
    if (pid <= 1 || !repo_root || !repo_root[0])
        return false;
    char proc[64], cwd[PATH_MAX], root[PATH_MAX];
    int n = snprintf(proc, sizeof(proc), "/proc/%ld/cwd", (long)pid);
    if (n <= 0 || n >= (int)sizeof(proc) ||
        !dev_canonical_directory(repo_root, root))
        return false;
    ssize_t got = readlink(proc, cwd, sizeof(cwd) - 1);
    if (got <= 0 || (size_t)got >= sizeof(cwd))
        return false;
    cwd[got] = 0;
    return strcmp(cwd, root) == 0;
}
#endif

struct dev_watcher_info {
    dev_pid_t pid;
    enum zcl_devloop_publish_mode publish_mode;
    char mode_name[16];
    bool ready;
    bool proof_queue_ready;
#if defined(_WIN32)
    uint64_t start_token;
    char nonce[65];
    char image[PATH_MAX];
#endif
};

/* A busy advisory lock is the ownership proof; the PID is diagnostic and is
 * executable-checked only before stop ever sends a signal.  This deliberately
 * recognizes both the native watcher and the shell compatibility watcher so
 * either owner excludes the other.  New lock records bind the watcher mode
 * (`pid verify|auto ready|starting [proofq1]`). A pid-only record is an
 * already-running
 * pre-containment watcher, whose historical behavior was auto publication, so
 * it is reported truthfully as legacy-auto. */
#if !defined(_WIN32)
static bool dev_watcher_active_at(const char *lock,
                                  struct dev_watcher_info *info_out)
{
    char buf[64] = {0};
    if (info_out)
        memset(info_out, 0, sizeof(*info_out));
    if (!lock || !lock[0])
        return false;
    int fd = open(lock, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0)
        return false;
    if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
        (void)flock(fd, LOCK_UN);
        close(fd);
        return false;
    }
    if (errno != EWOULDBLOCK && errno != EAGAIN) {
        close(fd);
        return false;
    }
    ssize_t n = pread(fd, buf, sizeof(buf) - 1, 0);
    close(fd);
    if (n <= 0)
        return false;
    char *end = NULL;
    long value = strtol(buf, &end, 10);
    if (!end || value <= 1)
        return false;
    while (*end == ' ' || *end == '\t')
        end++;
    enum zcl_devloop_publish_mode publish_mode = ZCL_DEVLOOP_PUBLISH_APPLY;
    const char *mode_name = "legacy-auto";
    bool ready = true;
    if (*end != '\n' && *end != 0) {
        char *mode_end = end;
        while (*mode_end && *mode_end != '\n' && *mode_end != ' ' &&
               *mode_end != '\t')
            mode_end++;
        size_t mode_len = (size_t)(mode_end - end);
        if (mode_len == strlen("verify") &&
            memcmp(end, "verify", mode_len) == 0) {
            publish_mode = ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY;
            mode_name = "verify";
        } else if (mode_len == strlen("auto") &&
                   memcmp(end, "auto", mode_len) == 0) {
            publish_mode = ZCL_DEVLOOP_PUBLISH_APPLY;
            mode_name = "auto";
        } else {
            return false;
        }
        while (*mode_end == ' ' || *mode_end == '\t')
            mode_end++;
        if (*mode_end != '\n' && *mode_end != 0) {
            char *state_end = mode_end;
            while (*state_end && *state_end != '\n' &&
                   *state_end != ' ' && *state_end != '\t')
                state_end++;
            size_t state_len = (size_t)(state_end - mode_end);
            if (state_len == strlen("starting") &&
                memcmp(mode_end, "starting", state_len) == 0)
                ready = false;
            else if (state_len == strlen("ready") &&
                     memcmp(mode_end, "ready", state_len) == 0)
                ready = true;
            else
                return false;
            while (*state_end == ' ' || *state_end == '\t')
                state_end++;
            if (*state_end != '\n' && *state_end != 0) {
                static const char capability[] = "proofq1";
                char *cap_end = state_end;
                while (*cap_end && *cap_end != '\n' &&
                       *cap_end != ' ' && *cap_end != '\t')
                    cap_end++;
                if ((size_t)(cap_end - state_end) != sizeof(capability) - 1 ||
                    memcmp(state_end, capability, sizeof(capability) - 1) != 0)
                    return false;
                if (info_out) info_out->proof_queue_ready = true;
                while (*cap_end == ' ' || *cap_end == '\t') cap_end++;
                if (*cap_end != '\n' && *cap_end != 0) return false;
            }
        }
    }
    dev_pid_t pid = (dev_pid_t)value;
    if (info_out) {
        info_out->pid = pid;
        info_out->publish_mode = publish_mode;
        info_out->ready = ready;
        (void)snprintf(info_out->mode_name, sizeof(info_out->mode_name), "%s",
                       mode_name);
    }
    return true;
}
#endif

#if defined(_WIN32)
static bool dev_root_identity(const char *root,
                              struct platform_watcher_file_identity *id)
{
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, root, -1,
                                NULL, 0);
    wchar_t *wide = n > 0
        ? zcl_malloc((size_t)n * sizeof(*wide), "dev-watcher-root-path")
        : NULL;
    if (!wide || MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, root, -1,
                                     wide, n) != n) { free(wide); return false; }
    HANDLE h = CreateFileW(wide, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        NULL);
    free(wide);
    BY_HANDLE_FILE_INFORMATION info = {0};
    bool ok = h != INVALID_HANDLE_VALUE &&
        GetFileInformationByHandle(h, &info) &&
        (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
    if (ok) *id = (struct platform_watcher_file_identity){
        info.dwVolumeSerialNumber, info.nFileIndexLow, info.nFileIndexHigh};
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    return ok;
}

static bool dev_watcher_active_windows(const char *repo_root,
                                       struct dev_watcher_info *out)
{
    char root[PATH_MAX], state[PATH_MAX], workspace[65], lock_leaf[96],
         record_leaf[96], encoded[PLATFORM_WATCHER_RECORD_ENCODED_MAX];
    size_t length = 0;
    struct platform_watcher_store store;
    struct platform_watcher_record record;
    platform_watcher_store_init(&store);
    if (out) memset(out, 0, sizeof(*out));
    bool names = dev_canonical_directory(repo_root, root) &&
        platform_state_root(state, sizeof(state)) &&
        zcl_devloop_workspace_id(root, workspace) &&
        snprintf(lock_leaf, sizeof(lock_leaf), "watch-%s.lock", workspace) > 0 &&
        snprintf(record_leaf, sizeof(record_leaf), "watch-%s.record", workspace) > 0;
    enum platform_watcher_store_result read = names &&
        platform_watcher_store_open(&store, state) == PLATFORM_WATCHER_STORE_OK
        ? platform_watcher_store_read_while_busy(
              &store, lock_leaf, record_leaf, encoded, sizeof(encoded),
              &length, NULL)
        : PLATFORM_WATCHER_STORE_INVALID;
    platform_watcher_store_close(&store);
    if (read != PLATFORM_WATCHER_STORE_OK ||
        !platform_watcher_record_parse(encoded, length, &record) ||
        strcmp(record.canonical_root, root) != 0 ||
        record.pid <= 1 || os_proc_pid_liveness(record.pid) !=
                              OS_PROC_LIVENESS_RUNNING)
        return false;
    uint64_t start = 0;
    char process_image[PATH_MAX], current_image[PATH_MAX], current_hash[65];
    struct platform_watcher_file_identity root_id;
    struct platform_positioned_file image_file;
    struct platform_positioned_file_snapshot image_info;
    platform_positioned_file_init(&image_file);
    bool valid = os_proc_pid_start_token(record.pid, &start) &&
        start == record.start_token &&
        os_proc_pid_exe_path(record.pid, process_image, sizeof(process_image)) &&
        strcmp(process_image, record.canonical_image) == 0 &&
        os_proc_exe_path(current_image, sizeof(current_image)) &&
        strcmp(current_image, record.canonical_image) == 0 &&
        dev_activation_sha256_file(current_image, current_hash) &&
        strcmp(current_hash, record.image_sha256) == 0 &&
        dev_root_identity(root, &root_id) &&
        root_id.volume == record.root_identity.volume &&
        root_id.file_low == record.root_identity.file_low &&
        root_id.file_high == record.root_identity.file_high &&
        platform_positioned_file_open(&image_file, current_image) &&
        platform_positioned_file_snapshot(&image_file, &image_info) &&
        image_info.volume == record.image_identity.volume &&
        image_info.file_low == record.image_identity.file_low &&
        image_info.file_high == record.image_identity.file_high &&
        image_info.size == record.image_size;
    platform_positioned_file_close(&image_file);
    if (!valid) return false;
    if (out) {
        out->pid = record.pid; out->start_token = record.start_token;
        out->publish_mode = record.mode == PLATFORM_WATCHER_MODE_AUTO
            ? ZCL_DEVLOOP_PUBLISH_APPLY : ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY;
        out->ready = record.state == PLATFORM_WATCHER_STATE_READY;
        (void)snprintf(out->mode_name, sizeof(out->mode_name), "%s",
                       record.mode == PLATFORM_WATCHER_MODE_AUTO ? "auto" : "verify");
        memcpy(out->nonce, record.nonce, sizeof(out->nonce));
        memcpy(out->image, record.canonical_image, sizeof(out->image));
    }
    return true;
}
#endif

static bool dev_watcher_active(const char *repo_root,
                               struct dev_watcher_info *info_out)
{
#if defined(_WIN32)
    return dev_watcher_active_windows(repo_root, info_out);
#else
    char lock[PATH_MAX], log[PATH_MAX], legacy[PATH_MAX];
    bool have_worktree_lock = dev_watch_paths(repo_root, lock, log);
    if (have_worktree_lock && dev_watcher_active_at(lock, info_out))
        return true;
    /* Transitional compatibility for a watcher started by a pre-singleflight
     * binary.  Scope the legacy HOME-global lease back to that process's
     * actual cwd so it cannot serialize unrelated worktrees.  New watchers
     * never take the legacy lock. */
    struct dev_watcher_info old = {0};
    if (!dev_legacy_watch_lock_path(legacy) ||
        (have_worktree_lock && strcmp(legacy, lock) == 0) ||
        !dev_watcher_active_at(legacy, &old) ||
        !dev_pid_is_watcher(old.pid) ||
        !dev_pid_cwd_matches_root(old.pid, repo_root))
        return false;
    if (info_out)
        *info_out = old;
    return true;
#endif
}

bool zcl_native_dev_loop_proof_queue_ready(const char *repo_root)
{
    struct dev_watcher_info info = {0};
    return dev_watcher_active(repo_root, &info) && info.ready &&
           info.proof_queue_ready;
}

static enum zcl_devloop_state_lookup dev_read_cycle(
    const char *repo_root, struct json_value *out, int64_t *epoch_out,
    char *why, size_t why_len)
{
    char body[16384];
    size_t len = 0;
    json_init(out);
    enum zcl_devloop_state_lookup lookup = zcl_devloop_cycle_state_read(
        repo_root, body, sizeof(body), &len, epoch_out, why, why_len);
    if (lookup != ZCL_DEVLOOP_STATE_FOUND)
        return lookup;
    if (!json_read(out, body, len) || out->type != JSON_OBJ) {
        json_free(out);
        if (why && why_len)
            (void)snprintf(why, why_len, "%s", "cycle_state_decode_failed");
        return ZCL_DEVLOOP_STATE_INVALID;
    }
    return ZCL_DEVLOOP_STATE_FOUND;
}

static bool dev_publication_target_ready(void)
{
    if (!zcl_devloop_publication_target_port_supported(
            zcl_native_command_rpc_port()))
        return false;
    zcl_native_bridge_ensure_rpc();
    char *raw = node_rpc_call_deadline("getblockcount", NULL, 15, 40);
    if (!raw)
        return false;
    struct json_value value;
    json_init(&value);
    bool ready = json_read(&value, raw, strlen(raw)) &&
                 value.type == JSON_INT && json_get_int(&value) >= 0;
    json_free(&value);
    free(raw);
    return ready;
}

/* `dev.loop.wait` declares zcl.dev_cycle.v1, so return that cycle directly.
 * Loop identity belongs to `dev.loop.status`; nesting the cycle in a
 * zcl.dev_loop_status.v1 document made callers violate the declared schema
 * and spend an extra parse step to reach the verdict.  The file-generation
 * epoch is appended so the returned document can feed the next wait without
 * another status round trip. */
static void dev_emit_cycle_verdict(struct zcl_command_reply *reply,
                                   struct json_value *cycle, int64_t epoch)
{
    json_free(&reply->data);
    json_init(&reply->data);
    json_copy(&reply->data, cycle);
    if (!json_get(&reply->data, "epoch"))
        (void)json_push_kv_int(&reply->data, "epoch", epoch);
}

static void dev_emit_loop_status(const char *repo_root,
                                 struct zcl_command_reply *reply)
{
    struct dev_watcher_info info = {0};
    bool active = dev_watcher_active(repo_root, &info);
    bool publication_required = active && info.ready &&
        zcl_devloop_publish_mode_applies(info.publish_mode);
    bool publication_target_ready = publication_required
        ? dev_publication_target_ready() : active && info.ready;
    bool watcher_ready = active && info.ready && publication_target_ready;
    (void)json_push_kv_str(&reply->data, "schema", "zcl.dev_loop_status.v1");
    (void)json_push_kv_bool(&reply->data, "active", active);
    (void)json_push_kv_int(&reply->data, "watcher_id", (int64_t)info.pid);
    (void)json_push_kv_str(&reply->data, "mode",
                           active ? info.mode_name : "");
    (void)json_push_kv_bool(&reply->data, "source_snapshot_ready",
                            active && info.ready);
    (void)json_push_kv_int(&reply->data, "proof_queue_version",
                           active && info.proof_queue_ready ? 1 : 0);
    (void)json_push_kv_bool(&reply->data, "publication_target_required",
                            publication_required);
    (void)json_push_kv_int(&reply->data, "publication_target_rpc_port",
                           zcl_native_command_rpc_port());
    (void)json_push_kv_int(&reply->data, "required_publication_rpc_port",
                           18252);
    (void)json_push_kv_bool(&reply->data, "publication_target_ready",
                            publication_target_ready);
    (void)json_push_kv_bool(&reply->data, "watcher_ready", watcher_ready);
    (void)json_push_kv_bool(
        &reply->data, "runtime_publication",
        watcher_ready &&
        zcl_devloop_publish_mode_applies(info.publish_mode));
    (void)json_push_kv_str(&reply->data, "freshness",
                           zcl_devloop_watcher_freshness(
                               active, info.ready, publication_target_ready));
    (void)json_push_kv_str(
        &reply->data, "agent_next_action",
        zcl_devloop_watcher_next_action(active, info.ready,
                                        publication_target_ready,
                                        info.publish_mode));
    int64_t epoch = 0;
    struct json_value cycle;
    char why[160] = {0};
    enum zcl_devloop_state_lookup lookup =
        dev_read_cycle(repo_root, &cycle, &epoch, why, sizeof(why));
    if (lookup == ZCL_DEVLOOP_STATE_INVALID) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
            "DEV_CYCLE_STATE_INVALID", "read", false, false,
            "workspace cycle state failed schema, SHA3, or inode validation",
            why[0] ? why : "cycle_state_invalid");
        return;
    }
    (void)json_push_kv_int(&reply->data, "epoch", epoch);
    if (lookup == ZCL_DEVLOOP_STATE_FOUND) {
        /* Loop ownership/status has a deliberately small response budget.
         * Activation receipts may contain a full behavioral probe (several
         * KiB), so nesting the durable cycle verbatim made `ensure` start the
         * watcher and then fail serialization. Keep the decision fields here;
         * `dev.status` / `dev.loop.wait` remain the full receipt surfaces. */
        static const char *const summary_fields[] = {
            "schema", "producer", "status", "action", "reason", "phase",
            "runtime_published", "elapsed_us", "elapsed_ms", "source_tu",
            "file_count", "proof_complete", "immediate_proof_complete",
            "integration_proof_deferred", "bounded_proof_deferred",
            "closure_refresh_deferred",
            "feedback_parallel", "source_guard_us",
            "source_guard_captures", "source_guard_bytes_read",
            "source_bytes_total", "changed_source_bytes",
            "source_byte_accounting_complete", "closure_us", "failure_capsule",
            "why_not_live", "contract_path", "service_source",
            "agent_next_action",
        };
        struct json_value summary;
        json_init(&summary);
        json_set_object(&summary);
        for (size_t i = 0;
             i < sizeof(summary_fields) / sizeof(summary_fields[0]); i++) {
            const struct json_value *value = json_get(&cycle, summary_fields[i]);
            if (value)
                (void)json_push_kv(&summary, summary_fields[i], value);
        }
        (void)json_push_kv(&reply->data, "latest_verdict", &summary);
        json_free(&summary);
        json_free(&cycle);
    } else
        json_free(&cycle);
}

static bool dev_requested_watch_mode(const struct json_value *input,
                                     enum zcl_devloop_publish_mode *mode_out,
                                     const char **name_out)
{
    const struct json_value *mode_v = json_get(input, "mode");
    const char *mode = mode_v && mode_v->type == JSON_STR
        ? json_get_str(mode_v) : "verify";
    if (strcmp(mode, "verify") == 0) {
        *mode_out = ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY;
        *name_out = "verify";
        return true;
    }
    if (strcmp(mode, "auto") == 0 || strcmp(mode, "apply") == 0) {
        *mode_out = ZCL_DEVLOOP_PUBLISH_APPLY;
        *name_out = "auto";
        return true;
    }
    return false;
}

void zcl_native_handle_dev_begin(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    struct json_value input;
    json_init(&input);
    if (request->input && request->input->type == JSON_OBJ)
        json_copy(&input, request->input);
    else
        json_set_object(&input);
    /* The one-command warm-feedback path inherits the fail-closed default.
     * Runtime publication remains an explicit request, never an accidental
     * consequence of asking for warm feedback. */
    if (!json_get(&input, "mode")) {
        const char *default_mode = zcl_devloop_publish_mode_name(
            zcl_devloop_default_watch_publish_mode());
        (void)json_push_kv_str(&input, "mode",
                               default_mode ? default_mode : "verify");
    }
    struct zcl_command_request ensure_request = *request;
    ensure_request.input = &input;
    zcl_native_handle_dev_loop_ensure(&ensure_request, reply);
    json_free(&input);
    if (reply->exit_code != ZCL_COMMAND_EXIT_OK)
        return;
    (void)json_push_kv_str(&reply->data, "begin_mode", "warm_service");
    const char *action =
        json_get_str(json_get(&reply->data, "agent_next_action"));
    if (action && action[0])
        (void)json_push_kv_str(&reply->data, "next_action", action);
    char next[192] = "z23-dev dev drive";
    const struct json_value *epoch_v = json_get(&reply->data, "epoch");
    if (epoch_v && epoch_v->type == JSON_INT) {
        int n = snprintf(
            next, sizeof(next),
            "edit source, then run z23-dev dev drive --input='"
            "{\"after_epoch\":%lld,\"wait_for_edit\":true}'",
            (long long)json_get_int(epoch_v));
        if (n <= 0 || (size_t)n >= sizeof(next))
            (void)snprintf(next, sizeof(next), "%s",
                           "z23-dev dev drive");
    }
    (void)json_push_kv_str(&reply->data, "next_command", next);
}

static void dev_loop_ensure(
    const struct zcl_command_request *request, struct zcl_command_reply *reply,
    bool wait_ready)
{
    enum zcl_devloop_publish_mode requested_mode;
    const char *requested_mode_name = NULL;
    if (!dev_requested_watch_mode(request->input, &requested_mode,
                                  &requested_mode_name)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "INVALID_WATCH_MODE",
                               "normalize", false, false,
                               "mode must be verify or auto",
                               "mode");
        return;
    }
    const struct json_value *root_v = json_get(request->input, "root");
    const char *requested = root_v && root_v->type == JSON_STR
        ? json_get_str(root_v) : dev_source_root(request);
    char root[PATH_MAX], makefile[PATH_MAX], lock[PATH_MAX], log[PATH_MAX];
    if (!requested || !dev_canonical_directory(requested, root) ||
        snprintf(makefile, sizeof(makefile), "%s/Makefile", root) <= 0 ||
        access(makefile, R_OK) != 0 || !dev_watch_paths(root, lock, log)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "INVALID_WATCH_ROOT",
                               "confinement", false, false,
                               "watch root must be a zclassic23 checkout", "root");
        return;
    }
    struct dev_watcher_info existing = {0};
    if (dev_watcher_active(root, &existing)) {
        if (existing.publish_mode != requested_mode) {
            char evidence[96];
            (void)snprintf(evidence, sizeof(evidence),
                           "running_mode=%s requested_mode=%s watcher_id=%ld",
                           existing.mode_name, requested_mode_name,
                           (long)existing.pid);
            dev_emit_loop_status(root, reply);
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                "WATCHER_MODE_MISMATCH", "ownership", false, false,
                "existing watcher must be stopped before changing publication mode",
                evidence);
            return;
        }
        for (int i = 0; wait_ready && i < 250 && !existing.ready; i++) {
            platform_sleep_ms(20);
            if (!dev_watcher_active(root, &existing))
                break;
        }
        if (existing.pid > 1 && (existing.ready || !wait_ready)) {
            dev_emit_loop_status(root, reply);
            (void)json_push_kv_bool(&reply->data, "created", false);
            return;
        }
        if (existing.pid > 1) {
            dev_emit_loop_status(root, reply);
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                "WATCH_STARTING", "start", true, false,
                "watcher did not finish source reconciliation within 5 seconds",
                "watcher_ready=false");
            return;
        }
    }
    char state_dir[PATH_MAX];
    if (!dev_state_dir(state_dir) || !dev_mkdirs(state_dir)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "STATE_DIR_FAILED",
                               "start", false, false,
                               "could not prepare watcher state directory", "");
        return;
    }
#if defined(_WIN32)
    char image[PATH_MAX];
    char image_hash[65], inherited_text[32];
    struct platform_watcher_launch launch;
    platform_watcher_launch_init(&launch);
    const char *worker_argv[] = {NULL, "--z23-internal-watch-worker",
                                 inherited_text, root, requested_mode_name,
                                 image_hash, NULL};
    struct platform_process child;
    platform_process_init(&child);
    if (!os_proc_exe_path(image, sizeof(image)) ||
        !dev_activation_sha256_file(image, image_hash) ||
        !platform_watcher_launch_prepare(&launch, root, image, image_hash)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "WATCH_IMAGE_FAILED",
                               "start", false, false,
                               "could not resolve the exact watcher image", "");
        return;
    }
    (void)snprintf(inherited_text, sizeof(inherited_text), "%llu",
        (unsigned long long)platform_watcher_launch_inherited(&launch));
    worker_argv[0] = image;
    uintptr_t inherited[] = {platform_watcher_launch_inherited(&launch)};
    static const char *const watcher_environment[] = {NULL};
    struct platform_process_options options = {
        .image = image, .argv = worker_argv, .cwd = root,
        .env = watcher_environment, .inherited = inherited,
        .inherited_count = 1};
    if (!platform_process_start_hidden(&child, &options) ||
        !platform_watcher_launch_publish(&launch)) {
        platform_watcher_launch_close(&launch);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "WATCH_START_FAILED",
                               "start", false, false,
                               "could not start native watcher", "CreateProcessW");
        return;
    }
    platform_watcher_launch_close(&launch);
#else
    pid_t child = fork();
    if (child < 0) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "WATCH_FORK_FAILED",
                               "start", false, false,
                               "could not start native watcher", strerror(errno));
        return;
    }
    if (child == 0) {
        (void)setsid();
        int null_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        int log_fd = open(log, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
        if (null_fd >= 0) {
            (void)dup2(null_fd, STDIN_FILENO);
            close(null_fd);
        }
        if (log_fd >= 0) {
            (void)dup2(log_fd, STDOUT_FILENO);
            (void)dup2(log_fd, STDERR_FILENO);
            close(log_fd);
        }
        int rc = zcl_devloop_watch_mode(root, requested_mode);
        _exit(rc == 0 ? 0 : 1);
    }
#endif
    if (!wait_ready) {
#if defined(_WIN32)
        if (!platform_process_detach(&child)) {
            (void)platform_process_terminate(&child, 1);
            platform_process_close(&child);
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                "WATCH_DETACH_FAILED", "start", false, false,
                "could not transfer native watcher containment", "DuplicateHandle");
            return;
        }
#endif
        (void)json_push_kv_str(&reply->data, "schema",
                               "zcl.dev_loop_start.v1");
        (void)json_push_kv_bool(&reply->data, "created", true);
        (void)json_push_kv_str(&reply->data, "root", root);
        return;
    }
    struct dev_watcher_info started = {0};
    for (int i = 0; i < 250 &&
         (!dev_watcher_active(root, &started) || !started.ready); i++)
        platform_sleep_ms(20);
    if (started.pid <= 1 || !started.ready ||
        started.publish_mode != requested_mode ||
        !dev_pid_is_watcher(started.pid)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "WATCH_START_FAILED",
                               "start", true, false,
                               "watcher did not acquire its singleton lock", log);
#if defined(_WIN32)
        (void)platform_process_terminate(&child, 1);
        platform_process_close(&child);
#endif
        return;
    }
#if defined(_WIN32)
    if (!platform_process_detach(&child)) {
        (void)platform_process_terminate(&child, 1);
        platform_process_close(&child);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
            "WATCH_DETACH_FAILED", "start", false, false,
            "could not transfer native watcher containment", "DuplicateHandle");
        return;
    }
#endif
    dev_emit_loop_status(root, reply);
    (void)json_push_kv_bool(&reply->data, "created", true);
    (void)json_push_kv_str(&reply->data, "root", root);
}

void zcl_native_handle_dev_loop_ensure(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    dev_loop_ensure(request, reply, true);
}

void zcl_native_handle_dev_loop_start_async(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    dev_loop_ensure(request, reply, false);
}

void zcl_native_handle_dev_loop_status(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    dev_emit_loop_status(dev_source_root(request), reply);
}

static bool dev_input_int(const struct json_value *input, const char *key,
                          int64_t default_value, int64_t *out)
{
    const struct json_value *v = json_get(input, key);
    if (!v || v->type == JSON_NULL) {
        *out = default_value;
        return true;
    }
    if (v->type != JSON_INT)
        return false;
    *out = json_get_int(v);
    return true;
}

void zcl_native_handle_dev_loop_wait(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    int64_t after = 0, timeout_ms = 30000;
    if (!dev_input_int(request->input, "after_epoch", 0, &after) || after < 0 ||
        !dev_input_int(request->input, "timeout_ms", 30000, &timeout_ms) ||
        timeout_ms < 1 || timeout_ms > 300000) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "INVALID_WAIT",
                               "normalize", false, false,
                               "after_epoch must be nonnegative and timeout_ms 1..300000",
                               "after_epoch,timeout_ms");
        return;
    }
    const char *repo_root = dev_source_root(request);
    int64_t current_epoch = after;
    char body[16384], why[160] = {0};
    size_t body_len = 0;
    enum zcl_devloop_state_lookup lookup =
        zcl_devloop_cycle_state_wait_after(
            repo_root, after, (int)timeout_ms, body, sizeof(body), &body_len,
            &current_epoch, why, sizeof(why));
    if (lookup == ZCL_DEVLOOP_STATE_INVALID) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
            "DEV_CYCLE_STATE_INVALID", "read", false, false,
            "workspace cycle state failed schema, SHA3, inode, or event-watch validation",
            why[0] ? why : "cycle_state_invalid");
        return;
    }
    if (lookup == ZCL_DEVLOOP_STATE_FOUND && current_epoch > after) {
        struct json_value cycle;
        json_init(&cycle);
        if (!json_read(&cycle, body, body_len) || cycle.type != JSON_OBJ) {
            json_free(&cycle);
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                "DEV_CYCLE_STATE_INVALID", "decode", false, false,
                "workspace cycle state is not one canonical object",
                "cycle_state_decode_failed");
            return;
        }
        dev_emit_cycle_verdict(reply, &cycle, current_epoch);
        json_free(&cycle);
        return;
    }
    char evidence[128];
    (void)snprintf(evidence, sizeof(evidence), "current_epoch=%lld",
                   (long long)current_epoch);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                           ZCL_COMMAND_EXIT_BLOCKED, "WAIT_TIMEOUT", "wait",
                           true, false, "no newer cycle verdict before timeout",
                           evidence);
    (void)zcl_command_reply_add_next(
        reply, "dev.loop.status", "{}",
        "inspect the latest epoch before deciding whether to wait again");
}

void zcl_native_handle_dev_loop_events(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    int64_t after = 0, heartbeat_ms = 15000;
    if (!dev_input_int(request->input, "after", 0, &after) || after < 0 ||
        !dev_input_int(request->input, "heartbeat_ms", 15000,
                       &heartbeat_ms) ||
        heartbeat_ms < 100 || heartbeat_ms > 300000) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "INVALID_SUBSCRIPTION_CURSOR", "normalize", false, false,
            "after must be nonnegative and heartbeat_ms 100..300000",
            "after,heartbeat_ms");
        return;
    }
    char body[16384], why[160] = {0};
    size_t body_len = 0;
    int64_t cursor = after;
    enum zcl_devloop_state_lookup lookup =
        zcl_devloop_cycle_state_wait_after(
            dev_source_root(request), after, (int)heartbeat_ms,
            body, sizeof(body), &body_len, &cursor, why, sizeof(why));
    if (lookup != ZCL_DEVLOOP_STATE_FOUND)
        cursor = after;
    if (lookup == ZCL_DEVLOOP_STATE_INVALID) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
            "DEV_EVENT_STREAM_INVALID", "read", false, false,
            "event stream failed cursor, schema, SHA3, or inode validation",
            why[0] ? why : "event_stream_invalid");
        return;
    }
    (void)json_push_kv_str(&reply->data, "schema", "zcl.dev_loop_event.v1");
    (void)json_push_kv_int(&reply->data, "cursor", cursor);
    if (lookup != ZCL_DEVLOOP_STATE_FOUND) {
        (void)json_push_kv_str(&reply->data, "kind", "HEARTBEAT");
        (void)json_push_kv_bool(&reply->data, "interrupting", false);
        (void)json_push_kv_str(&reply->data, "subscription", "attached");
        return;
    }
    struct json_value cycle;
    json_init(&cycle);
    if (!json_read(&cycle, body, body_len) || cycle.type != JSON_OBJ) {
        json_free(&cycle);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
            "DEV_EVENT_STREAM_INVALID", "decode", false, false,
            "event stream yielded a non-object cycle", "cycle_decode");
        return;
    }
    const char *phase = json_get_str(json_get(&cycle, "phase"));
    bool interrupting = dev_event_interrupting(&cycle);
    (void)json_push_kv_str(&reply->data, "kind",
                           phase && phase[0] ? phase : "CYCLE_EVENT");
    (void)json_push_kv_bool(&reply->data, "interrupting", interrupting);
    if (interrupting) {
        struct json_value capsule;
        json_init(&capsule); json_set_object(&capsule);
        (void)json_push_kv_str(&capsule, "schema",
                               "zcl.dev_diagnostic_capsule.v1");
        (void)dev_drive_copy(&cycle, &capsule, "phase", "phase");
        (void)dev_drive_copy(&cycle, &capsule, "edit_epoch", "edit_epoch");
        (void)dev_drive_copy(&cycle, &capsule, "source_tu", "source_tu");
        (void)dev_drive_copy(&cycle, &capsule, "failure_capsule", "message");
        (void)dev_drive_copy(&cycle, &capsule, "compiler_output", "detail");
        (void)json_push_kv(&reply->data, "diagnostic", &capsule);
        json_free(&capsule);
    }
    (void)json_push_kv(&reply->data, "event", &cycle);
    json_free(&cycle);
}

void zcl_native_handle_dev_loop_stop(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    int64_t requested = 0;
    if (!dev_input_int(request->input, "watcher_id", 0, &requested) ||
        requested <= 1) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "INVALID_WATCHER_ID",
                               "normalize", false, false,
                               "watcher_id must be the positive id returned by status",
                               "watcher_id");
        return;
    }
    struct dev_watcher_info active = {0};
    const char *repo_root = dev_source_root(request);
    if (!dev_watcher_active(repo_root, &active)) {
        dev_emit_loop_status(repo_root, reply);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED, "WATCHER_NOT_RUNNING",
                               "stop", false, false,
                               "no native watcher owns the singleton lock", "");
        return;
    }
    if ((int64_t)active.pid != requested || !dev_pid_is_watcher(active.pid)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED, "WATCHER_ID_MISMATCH",
                               "confinement", false, false,
                               "refusing to signal a different process", "watcher_id");
        return;
    }
#if defined(_WIN32)
    struct platform_process watcher;
    platform_process_init(&watcher);
    uint64_t start = 0;
    bool authorized = os_proc_pid_start_token(active.pid, &start) &&
        start == active.start_token &&
        platform_process_open_existing(&watcher, active.pid, active.image);
    bool signaled = authorized && platform_watcher_lease_signal_stop(active.nonce);
    uint32_t exit_code = 0;
    enum platform_process_wait_result waited = signaled
        ? platform_process_wait(&watcher, 5000, &exit_code)
        : PLATFORM_PROCESS_WAIT_FAILED;
    bool stopped = waited == PLATFORM_PROCESS_WAIT_EXITED;
    if (!stopped && authorized)
        stopped = platform_process_terminate(&watcher, 1) &&
                  platform_process_wait(&watcher, 5000, &exit_code) ==
                      PLATFORM_PROCESS_WAIT_EXITED;
    platform_process_close(&watcher);
    if (!stopped) {
#else
    if (kill((pid_t)active.pid, SIGTERM) != 0) {
#endif
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "WATCHER_STOP_FAILED",
                               "stop", true, false,
                               "SIGTERM could not be delivered", strerror(errno));
        return;
    }
    struct dev_watcher_info still = {0};
    for (int i = 0; i < 250; i++) {
        if (!dev_watcher_active(repo_root, &still))
            break;
        platform_sleep_ms(20);
    }
    dev_emit_loop_status(repo_root, reply);
    if (dev_watcher_active(repo_root, &still))
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "WATCHER_STOP_TIMEOUT",
                               "stop", true, false,
                               "watcher retained its lock after SIGTERM", "");
    else
        (void)json_push_kv_bool(&reply->data, "stopped", true);
}

#if !defined(_WIN32)
static bool dev_test_phase_receipt_parse(
    const struct zcl_devloop_process_result *result,
    int64_t *startup_ms, int64_t *test_body_ms)
{
    static const char marker[] =
        "{\"schema\":\"zcl.test_phase_receipt.v1\",\"startup_ms\":";
    if (!result || !startup_ms || !test_body_ms)
        return false;
    const char *row = strstr(result->output, marker);
    long long startup = -1, body = -1;
    if (!row || sscanf(row,
                       "{\"schema\":\"zcl.test_phase_receipt.v1\","
                       "\"startup_ms\":%lld,\"test_body_ms\":%lld}",
                       &startup, &body) != 2 || startup < 0 || body < 0)
        return false;
    *startup_ms = startup;
    *test_body_ms = body;
    return true;
}
#endif

void zcl_native_handle_dev_test_run(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    int64_t handler_started_us = platform_time_monotonic_us();
    int64_t graph_started_us = handler_started_us;
    const struct json_value *group_v = json_get(request->input, "group");
    const char *group = group_v && group_v->type == JSON_STR
        ? json_get_str(group_v) : NULL;
    char full_group[ZCL_TEST_GROUP_FULL_MAX];
    if (!dev_group_valid(group) ||
        !zcl_test_group_resolve_exact(group, full_group)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "INVALID_TEST_GROUP",
                               "normalize", false, false,
                               "group must resolve to one canonical registered test group",
                               "group");
        return;
    }
    int64_t graph_load_us = platform_time_monotonic_us() - graph_started_us;
#if defined(_WIN32)
    (void)graph_load_us;
#endif
    char root[PATH_MAX], bin[PATH_MAX], selector[160];
    if (!dev_canonical_directory(dev_source_root(request), root) ||
#if defined(_WIN32)
        snprintf(bin, sizeof(bin), "%s/build/bin/test_parallel_fast.exe", root) <= 0 ||
#else
        snprintf(bin, sizeof(bin), "%s/build/bin/test_parallel_fast", root) <= 0 ||
#endif
        snprintf(selector, sizeof(selector), "--exact=%s", full_group) <= 0) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED, "TEST_RUNNER_MISSING",
                               "precondition", true, false,
                               "prebuilt focused test runner is unavailable",
                               "run make test_parallel_fast");
        return;
    }
#if defined(_WIN32)
    (void)graph_load_us;
    (void)handler_started_us;
    struct platform_positioned_file runner;
    platform_positioned_file_init(&runner);
    if (!platform_positioned_file_open(&runner, bin) ||
        !platform_positioned_file_is_executable(&runner)) {
        platform_positioned_file_close(&runner);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED, "TEST_RUNNER_MISSING",
                               "precondition", true, false,
                               "prebuilt focused test runner is unavailable",
                               "run make test_parallel_fast");
        return;
    }
    platform_positioned_file_close(&runner);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                           ZCL_COMMAND_EXIT_BLOCKED,
                           "TEST_RUNNER_EXECUTION_UNAVAILABLE", "precondition",
                           true, false,
                           "Windows descriptor-bound focused runner execution is unavailable",
                           "use the Linux or macOS native lane until Windows execution is ported");
    return;
#else
    int runner_fd = open(bin, O_RDONLY);
    struct stat runner_stat;
    if (runner_fd < 0 || fstat(runner_fd, &runner_stat) != 0 ||
        !S_ISREG(runner_stat.st_mode) ||
        !(runner_stat.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
        if (runner_fd >= 0)
            close(runner_fd);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED, "TEST_RUNNER_MISSING",
                               "precondition", true, false,
                               "prebuilt focused test runner is unavailable",
                               "run make test_parallel_fast");
        return;
    }
    struct dev_source_record source = {0};
    char identity_why[192] = {0};
    int64_t identity_started_us = platform_time_monotonic_us();
    enum zcl_dev_source_admission source_admission =
        zcl_dev_executable_source_admit(root, runner_fd, bin, &source,
                                        identity_why,
                                        sizeof(identity_why));
    int64_t identity_us = platform_time_monotonic_us() - identity_started_us;
    if (source_admission == ZCL_DEV_SOURCE_ADMISSION_ERROR) {
        close(runner_fd);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL,
                               "SOURCE_IDENTITY_UNAVAILABLE", "precondition",
                               true, false,
                               "current source identity could not be captured",
                               identity_why);
        return;
    }
    if (source_admission == ZCL_DEV_SOURCE_ADMISSION_STALE) {
        close(runner_fd);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED, "TEST_RUNNER_STALE",
                               "precondition", true, false,
                               "focused runner was built from a different source epoch",
                               identity_why[0] ? identity_why
                                               : "run make test_parallel_fast");
        return;
    }
    const char *argv[] = {bin, selector, NULL};
    struct zcl_devloop_process_result result;
    if (!zcl_devloop_process_run_fd(root, runner_fd, argv, 300000, &result)) {
        close(runner_fd);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "TEST_EXEC_FAILED",
                               "execute", true, false,
                               "could not execute focused test runner", full_group);
        return;
    }
    close(runner_fd);
    if (!zcl_dev_source_mutation_verify(root, &source, identity_why,
                                        sizeof(identity_why))) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED,
                               "SOURCE_EPOCH_SUPERSEDED", "prove", true,
                               false,
                               "source changed while the focused proof ran",
                               identity_why);
        return;
    }
    bool ok = result.exit_code == 0 && result.term_signal == 0 &&
              !result.timed_out;
    int64_t test_startup_ms = 0, test_body_ms = result.elapsed_ms;
    bool runner_phase_receipt = dev_test_phase_receipt_parse(
        &result, &test_startup_ms, &test_body_ms);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.dev_focused_test.v1");
    (void)json_push_kv_str(&reply->data, "group", full_group);
    (void)json_push_kv_str(&reply->data, "selector", "exact");
    (void)json_push_kv_str(&reply->data, "source_id_sha256",
                           source.source_id);
    (void)json_push_kv_str(&reply->data, "source_mutation_sha256",
                           source.mutation_id);
    if (source.cas_present) {
        (void)json_push_kv_str(&reply->data, "source_cas_sha3",
                               source.cas_root_sha3);
        (void)json_push_kv_str(&reply->data, "source_cas_scope",
                               "public_c23_source_roots.v1");
        (void)json_push_kv_str(&reply->data, "source_cas_authority",
                               "shadow");
        struct json_value cas_work;
        json_init(&cas_work);
        json_set_object(&cas_work);
        (void)json_push_kv_int(&cas_work, "files_total",
                               source.cas_files_total);
        (void)json_push_kv_int(&cas_work, "files_read",
                               source.cas_files_read);
        (void)json_push_kv_int(&cas_work, "nodes_hashed",
                               source.cas_nodes_hashed);
        (void)json_push_kv_int(&cas_work, "elapsed_us",
                               source.cas_elapsed_us);
        (void)json_push_kv(&reply->data, "source_cas_work", &cas_work);
        json_free(&cas_work);
    }
    (void)json_push_kv_str(&reply->data, "source_admission",
                           zcl_dev_source_admission_name(source_admission));
    (void)json_push_kv_bool(&reply->data, "passed", ok);
    (void)json_push_kv_int(&reply->data, "elapsed_ms", result.elapsed_ms);
    (void)json_push_kv_int(&reply->data, "exit_code", result.exit_code);
    (void)json_push_kv_bool(&reply->data, "timed_out", result.timed_out);
    struct json_value phases;
    json_init(&phases);
    json_set_object(&phases);
    (void)json_push_kv_int(&phases, "identity", identity_us);
    int64_t oracle_identity_us = identity_us - source.cas_elapsed_us;
    if (oracle_identity_us < 0)
        oracle_identity_us = 0;
    (void)json_push_kv_int(&phases, "identity_sha256_oracle",
                           oracle_identity_us);
    (void)json_push_kv_int(&phases, "identity_cas_sha3",
                           source.cas_elapsed_us);
    (void)json_push_kv_int(&phases, "graph_load", graph_load_us);
    /* This command deliberately consumes an immutable prebuilt runner.  Zero
     * means no compile/link action ran, not an unmeasured duration. */
    (void)json_push_kv_int(&phases, "compile", 0);
    (void)json_push_kv_int(&phases, "link", 0);
    (void)json_push_kv_int(&phases, "test_startup",
                           test_startup_ms * 1000);
    (void)json_push_kv_int(&phases, "test_body", test_body_ms * 1000);
    (void)json_push_kv_int(&phases, "total",
                           platform_time_monotonic_us() - handler_started_us);
    (void)json_push_kv(&reply->data, "phases_us", &phases);
    json_free(&phases);
    (void)json_push_kv_bool(&reply->data, "runner_phase_receipt",
                            runner_phase_receipt);
    (void)json_push_kv_str(&reply->data, "compile_outcome", "PREBUILT_REUSE");
    (void)json_push_kv_str(&reply->data, "link_outcome", "PREBUILT_REUSE");
    if (!ok) {
        const char *tail = result.output;
        if (result.output_len > 2048)
            tail += result.output_len - 2048;
        (void)json_push_kv_str(&reply->data, "output_tail", tail);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "FOCUSED_TEST_FAILED",
                               "prove", true, false,
                               "focused test group failed", full_group);
    }
#endif
}

struct dev_vault_story_case {
    const char *name;
    struct vault_intent_plan_snapshot snapshot;
    enum vault_intent_decision_code expected_code;
    int64_t expected_reservation;
    int64_t expected_spendable;
};

static const struct dev_vault_story_case k_dev_vault_story_cases[] = {
    {
        .name = "allow",
        .snapshot = {
            .money_result_ok = true, .money_complete = true,
            .money_current = true, .development_scope = true,
            .target_zat = 150000000, .fee_zat = 10000,
            .confirmed_zat = 500000000,
            .already_reserved_zat = 100000000,
            .agent_available_zat = 200000000,
        },
        .expected_code = VAULT_INTENT_DECISION_ALLOW,
        .expected_reservation = 150010000,
        .expected_spendable = 400000000,
    },
    {
        .name = "dev_cap",
        .snapshot = {
            .money_result_ok = true, .money_complete = true,
            .money_current = true, .development_scope = true,
            .target_zat = 150000000, .fee_zat = 10000,
            .confirmed_zat = 500000000,
            .already_reserved_zat = 100000000,
            .agent_available_zat = 150000000,
        },
        .expected_code = VAULT_INTENT_DECISION_DEVELOPMENT_CAP,
        .expected_reservation = 150010000,
        .expected_spendable = 400000000,
    },
    {
        .name = "stale",
        .snapshot = {
            .money_result_ok = true, .money_complete = true,
            .money_current = false, .development_scope = true,
            .target_zat = 150000000, .fee_zat = 10000,
            .confirmed_zat = 500000000,
            .already_reserved_zat = 100000000,
            .agent_available_zat = 200000000,
        },
        .expected_code = VAULT_INTENT_DECISION_MONEY_NOT_CURRENT,
        .expected_reservation = 150010000,
        .expected_spendable = 0,
    },
    {
        .name = "prod_insufficient",
        .snapshot = {
            .money_result_ok = true, .money_complete = true,
            .money_current = true, .development_scope = false,
            .target_zat = 150000000, .fee_zat = 10000,
            .confirmed_zat = 100000000, .already_reserved_zat = 0,
            .agent_available_zat = 0,
        },
        .expected_code = VAULT_INTENT_DECISION_INSUFFICIENT_FUNDS,
        .expected_reservation = 150010000,
        .expected_spendable = 100000000,
    },
    {
        .name = "overflow",
        .snapshot = {
            .money_result_ok = true, .money_complete = true,
            .money_current = true, .development_scope = false,
            .target_zat = INT64_MAX, .fee_zat = 1,
            .confirmed_zat = INT64_MAX, .already_reserved_zat = 0,
            .agent_available_zat = 0,
        },
        .expected_code = VAULT_INTENT_DECISION_FEE_INVALID,
        .expected_reservation = 0,
        .expected_spendable = 0,
    },
};

static bool dev_vault_story_run(
    const struct vault_intent_decision_service_v1 *service,
    struct json_value *case_rows, char digest_hex[65],
    char *why, size_t why_size)
{
    if (!service || !service->decide || !service->code_name || !digest_hex) {
        if (why && why_size)
            (void)snprintf(why, why_size, "%s", "decision vtable incomplete");
        return false;
    }
    struct sha3_256_ctx sha;
    uint8_t digest[32];
    sha3_256_init(&sha);
    for (size_t i = 0;
         i < sizeof(k_dev_vault_story_cases) /
                 sizeof(k_dev_vault_story_cases[0]); i++) {
        const struct dev_vault_story_case *test = &k_dev_vault_story_cases[i];
        struct vault_intent_plan_decision decision;
        if (!service->decide(&test->snapshot, &decision)) {
            if (why && why_size)
                (void)snprintf(why, why_size, "%s: decision refused input",
                               test->name);
            return false;
        }
        const char *code = service->code_name(decision.code);
        if (decision.code != test->expected_code ||
            decision.reservation_zat != test->expected_reservation ||
            decision.spendable_after_reservations_zat !=
                test->expected_spendable) {
            if (why && why_size)
                (void)snprintf(why, why_size,
                               "%s: expected decision vector changed",
                               test->name);
            return false;
        }
        char row[256];
        int n = snprintf(row, sizeof(row), "%s|%s|%lld|%lld\n",
                         test->name, code,
                         (long long)decision.reservation_zat,
                         (long long)decision.spendable_after_reservations_zat);
        if (n <= 0 || (size_t)n >= sizeof(row)) {
            if (why && why_size)
                (void)snprintf(why, why_size, "%s", "story row overflow");
            return false;
        }
        sha3_256_write(&sha, (const uint8_t *)row, (size_t)n);
        if (case_rows) {
            struct json_value item;
            json_init(&item); json_set_object(&item);
            bool pushed = json_push_kv_str(&item, "case", test->name) &&
                json_push_kv_str(&item, "decision", code) &&
                json_push_kv_int(&item, "reservation_zat",
                                 decision.reservation_zat) &&
                json_push_kv_int(&item, "spendable_zat",
                    decision.spendable_after_reservations_zat) &&
                json_push_back(case_rows, &item);
            json_free(&item);
            if (!pushed) {
                if (why && why_size)
                    (void)snprintf(why, why_size, "%s",
                                   "story result exceeded JSON bound");
                return false;
            }
        }
    }
    sha3_256_finalize(&sha, digest);
    zcl_hex_encode(digest, sizeof(digest), digest_hex);
    if (strcmp(digest_hex, VAULT_INTENT_DECISION_KAT) != 0) {
        if (why && why_size)
            (void)snprintf(why, why_size,
                           "story KAT mismatch: got %.64s", digest_hex);
        return false;
    }
    return true;
}

static bool dev_vault_story_frozen_kat(const void *vtable,
                                       char *why, size_t why_size)
{
    char digest[65];
    return dev_vault_story_run(vtable, NULL, digest, why, why_size);
}

static const struct zcl_hotswap_service_contract k_vault_story_contract = {
    .service_id = VAULT_INTENT_DECISION_SERVICE_ID,
    .source_tu = "contexts/wallet/services/src/vault_intent_decision_service.c",
    .abi_version = ZCL_HOTSWAP_SERVICE_ABI_V1,
    .vtable_size = sizeof(struct vault_intent_decision_service_v1),
    .abi_fingerprint = VAULT_INTENT_DECISION_ABI,
    .schema_fingerprint = VAULT_INTENT_DECISION_SCHEMA,
    .wire_fingerprint = VAULT_INTENT_DECISION_WIRE,
    .kat_fingerprint = VAULT_INTENT_DECISION_KAT,
    .frozen_kat = dev_vault_story_frozen_kat,
};

const struct zcl_hotswap_service_contract *
zcl_native_vault_intent_decision_service_contract(void)
{
    return &k_vault_story_contract;
}

void zcl_native_handle_dev_test_story(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const struct json_value *owner_v = request && request->input
        ? json_get(request->input, "owner") : NULL;
    const char *owner = owner_v && owner_v->type == JSON_STR
        ? json_get_str(owner_v) : NULL;
    if (!request || !request->input || request->input->type != JSON_OBJ ||
        request->input->num_children != 1 || !owner ||
        strcmp(owner, "transaction_intent") != 0) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "STORY_OWNER_INVALID", "validate", false, false,
            "owner must be exactly transaction_intent", "owner");
        return;
    }
    struct json_value cases, capabilities;
    json_init(&cases); json_set_array(&cases);
    char digest[65] = {0}, why[192] = {0};
    bool ok = dev_vault_story_run(vault_intent_decision_service_builtin(),
                                  &cases, digest, why, sizeof(why));
    (void)json_push_kv_str(&reply->data, "schema",
                           VAULT_INTENT_DECISION_SCHEMA);
    (void)json_push_kv_str(&reply->data, "owner", owner);
    (void)json_push_kv_str(&reply->data, "mode", "HOT_SHADOW");
    (void)json_push_kv_str(&reply->data, "status", ok ? "green" : "red");
    (void)json_push_kv_int(&reply->data, "case_count",
        (int64_t)(sizeof(k_dev_vault_story_cases) /
                  sizeof(k_dev_vault_story_cases[0])));
    (void)json_push_kv_str(&reply->data, "kat_sha3", digest);
    (void)json_push_kv_str(&reply->data, "kat_expected",
                           VAULT_INTENT_DECISION_KAT);
    (void)json_push_kv_str(&reply->data, "authority_shell",
                           "contexts/wallet/controllers/src/vault_intent_controller.c");
    (void)json_push_kv_str(&reply->data, "decision_core",
                           "contexts/wallet/services/src/vault_intent_decision_service.c");
    (void)json_push_kv_str(&reply->data, "authority", "proposal_only");
    (void)json_push_kv_bool(&reply->data, "forbidden_effects_absent", true);
    json_init(&capabilities); json_set_array(&capabilities);
    (void)json_push_kv(&reply->data, "effect_capabilities", &capabilities);
    json_free(&capabilities);
    (void)json_push_kv(&reply->data, "cases", &cases);
    json_free(&cases);
    if (!ok)
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "STORY_RED", "shadow", false, false,
            why[0] ? why : "vault intent behavior story failed",
            "transaction_intent");
}

void zcl_native_handle_dev_test_sim(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    char body[8192];
    int rc = ZCL_COMMAND_EXIT_INTERNAL;
    if (!dev_capture_stdout(dev_call_sim, (void *)dev_source_root(request),
                            body, sizeof(body), &rc)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "SIM_CAPTURE_FAILED",
                               "execute", false, false,
                               "native simulation produced no bounded result", "");
        return;
    }
    dev_reply_from_json(reply, body, strlen(body), "test.sim");
    if (reply->exit_code == ZCL_COMMAND_EXIT_OK && rc != 0)
        dev_fail_with_data(reply, rc, "SIM_FAILED", "prove", false,
                           "hot-swap simulation failed");
}

static bool dev_generation_root(char out[PATH_MAX])
{
    const char *override = getenv("ZCL_DEV_GENERATION_ROOT");
#if defined(_WIN32)
    if (override && override[0]) {
        int n = snprintf(out, PATH_MAX, "%s", override);
        return n > 2 && n < PATH_MAX && out[1] == ':' &&
               (out[2] == '/' || out[2] == '\\') && !strstr(out, "..");
    }
    char state[PATH_MAX];
    if (!platform_state_root(state, sizeof(state))) return false;
    int n = snprintf(out, PATH_MAX, "%s/generations", state);
    return n > 0 && n < PATH_MAX;
#else
    const char *home = getenv("HOME");
    int n = override && override[0]
        ? snprintf(out, PATH_MAX, "%s", override)
        : home && home[0]
            ? snprintf(out, PATH_MAX, "%s/.local/lib/zclassic23-dev", home)
            : -1;
    return n > 0 && n < PATH_MAX && out[0] == '/' && !strstr(out, "..");
#endif
}

static bool dev_read_generation_link(const char *root, const char *link_name,
                                     char out[96])
{
#if defined(_WIN32)
    struct platform_directory_transaction directory;
    struct platform_directory_child selection;
    platform_directory_transaction_init(&directory);
    platform_directory_child_init(&selection);
    char blob[256];
    struct platform_directory_child_info info;
    bool ok = platform_directory_transaction_open(&directory, root) &&
        platform_directory_child_open(&directory, link_name, &selection) &&
        platform_directory_child_info(&selection, &info) &&
        info.current_user_only && info.size > 0 && info.size < sizeof(blob) &&
        platform_directory_child_read_exact(&selection, blob,
                                             (size_t)info.size, 0);
    if (ok) {
        blob[info.size] = 0;
        ok = dev_activation_json_first_string(blob, "generation", out, 96) &&
             dev_generation_name_valid(out);
    }
    platform_directory_child_close(&selection);
    platform_directory_transaction_close(&directory);
    if (!ok) return false;
    char binary[PATH_MAX];
    int n = snprintf(binary, sizeof(binary), "%s/%s/zclassic23-dev.exe",
                     root, out);
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    ok = n > 0 && n < (int)sizeof(binary) &&
         platform_positioned_file_open(&file, binary) &&
         platform_positioned_file_is_executable(&file);
    platform_positioned_file_close(&file);
    return ok;
#else
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", root, link_name);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return false;
    ssize_t got = readlink(path, out, 95);
    if (got <= 0 || got >= 95)
        return false;
    out[got] = 0;
    return dev_generation_name_valid(out);
#endif
}

void zcl_native_handle_dev_generation_current(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    (void)request;
    char root[PATH_MAX], current[96] = {0}, last_good[96] = {0}, staged[96] = {0};
    if (!dev_generation_root(root)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "GENERATION_ROOT_INVALID",
                               "read", false, false,
                               "development generation root is unavailable", "");
        return;
    }
    (void)dev_read_generation_link(root, "current", current);
    (void)dev_read_generation_link(root, "last-good", last_good);
    (void)dev_read_generation_link(root, "staged", staged);
    (void)json_push_kv_str(&reply->data, "schema",
                           "zcl.dev_generation_status.v1");
    (void)json_push_kv_str(&reply->data, "root", root);
    (void)json_push_kv_str(&reply->data, "current_generation", current);
    (void)json_push_kv_str(&reply->data, "last_good_generation", last_good);
    (void)json_push_kv_str(&reply->data, "staged_generation", staged);
    (void)json_push_kv_bool(&reply->data, "rollback_available",
                            last_good[0] && strcmp(current, last_good) != 0);
}

struct dev_generation_entry {
    char name[96];
    char disposition[16];
};

static int dev_generation_entry_cmp(const void *a, const void *b)
{
    const struct dev_generation_entry *ea = a;
    const struct dev_generation_entry *eb = b;
    int by_name = strcmp(eb->name, ea->name);
    return by_name ? by_name : strcmp(ea->disposition, eb->disposition);
}

static void dev_scan_generation_markers(const char *root, const char *subdir,
                                        const char *disposition,
                                        struct dev_generation_entry *entries,
                                        size_t capacity, size_t *count)
{
#if defined(_WIN32)
    struct platform_directory_transaction parent, directory;
    struct platform_directory_names names = {0};
    platform_directory_transaction_init(&parent);
    platform_directory_transaction_init(&directory);
    bool ok = platform_directory_transaction_open(&parent, root) &&
        platform_directory_transaction_open_child(&parent, subdir, false,
                                                   &directory) ==
            PLATFORM_DIRECTORY_OK &&
        platform_directory_transaction_list_regular(&directory, &names);
    if (ok) for (size_t i = 0; i < names.count && *count < capacity; i++) {
        size_t len = strlen(names.items[i]);
        if (len <= 5 || strcmp(names.items[i] + len - 5, ".json") != 0 ||
            len - 5 >= sizeof(entries[*count].name)) continue;
        memcpy(entries[*count].name, names.items[i], len - 5);
        entries[*count].name[len - 5] = 0;
        if (!dev_generation_name_valid(entries[*count].name)) continue;
        (void)snprintf(entries[*count].disposition,
                       sizeof(entries[*count].disposition), "%s", disposition);
        (*count)++;
    }
    platform_directory_names_free(&names);
    platform_directory_transaction_close(&directory);
    platform_directory_transaction_close(&parent);
#else
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/%s", root, subdir) <= 0)
        return;
    DIR *dir = opendir(path);
    if (!dir)
        return;
    struct dirent *item;
    while (*count < capacity && (item = readdir(dir)) != NULL) {
        size_t len = strlen(item->d_name);
        if (len <= 5 || strcmp(item->d_name + len - 5, ".json") != 0 ||
            len - 5 >= sizeof(entries[*count].name))
            continue;
        memcpy(entries[*count].name, item->d_name, len - 5);
        entries[*count].name[len - 5] = 0;
        if (!dev_generation_name_valid(entries[*count].name))
            continue;
        (void)snprintf(entries[*count].disposition,
                       sizeof(entries[*count].disposition), "%s", disposition);
        (*count)++;
    }
    closedir(dir);
#endif
}

void zcl_native_handle_dev_generation_history(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    char root[PATH_MAX];
    if (!dev_generation_root(root)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "GENERATION_ROOT_INVALID",
                               "read", false, false,
                               "development generation root is unavailable", "");
        return;
    }
    struct dev_generation_entry entries[512];
    size_t count = 0;
    dev_scan_generation_markers(root, "accepted", "accepted", entries,
                                512, &count);
    dev_scan_generation_markers(root, "rejected", "rejected", entries,
                                512, &count);
    qsort(entries, count, sizeof(entries[0]), dev_generation_entry_cmp);
    size_t offset = 0;
    if (request->cursor && request->cursor[0]) {
        char *end = NULL;
        unsigned long long parsed = strtoull(request->cursor, &end, 10);
        if (!end || *end || parsed > count) {
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INVALID, "INVALID_CURSOR",
                                   "normalize", false, false,
                                   "cursor must be a valid numeric history offset",
                                   request->cursor);
            return;
        }
        offset = (size_t)parsed;
    }
    size_t limit = request->max_items ? request->max_items : 50;
    if (limit > 100)
        limit = 100;
    size_t end = offset + limit < count ? offset + limit : count;
    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    for (size_t i = offset; i < end; i++) {
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        (void)json_push_kv_str(&row, "generation", entries[i].name);
        (void)json_push_kv_str(&row, "disposition", entries[i].disposition);
        (void)json_push_back(&rows, &row);
        json_free(&row);
    }
    (void)json_push_kv_str(&reply->data, "schema",
                           "zcl.dev_generation_history.v1");
    (void)json_push_kv(&reply->data, "generations", &rows);
    json_free(&rows);
    (void)json_push_kv_int(&reply->data, "total", (int64_t)count);
    (void)json_push_kv_bool(&reply->data, "has_more", end < count);
    if (end < count) {
        char next[32];
        (void)snprintf(next, sizeof(next), "%zu", end);
        (void)json_push_kv_str(&reply->data, "next_cursor", next);
    }
}

#endif /* ZCL_DEV_BUILD */

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)

void zcl_native_handle_dev_diagnose_latest(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!reply)
        return;
    struct zcl_dev_failure_record record;
    char why[192] = {0};
    enum zcl_dev_failure_lookup lookup =
        zcl_dev_failure_read_latest(dev_source_root(request), &record,
                                    why, sizeof(why));
    if (lookup == ZCL_DEV_FAILURE_LOOKUP_ABSENT) {
        (void)json_push_kv_str(&reply->data, "schema",
                               "zcl.dev_failure_latest_result.v1");
        (void)json_push_kv_bool(&reply->data, "found", false);
        return;
    }
    if (lookup != ZCL_DEV_FAILURE_LOOKUP_FOUND) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
            "FAILURE_STORE_INVALID", "read", false, false,
            "latest failure state failed inode or SHA3 validation",
            why[0] ? why : "latest_failure_invalid");
        return;
    }
    (void)json_push_kv_str(&reply->data, "schema",
                           "zcl.dev_failure_latest_result.v1");
    (void)json_push_kv_bool(&reply->data, "found", true);
    (void)json_push_kv_str(&reply->data, "failure_id", record.failure_id);
    (void)json_push_kv_str(&reply->data, "phase", record.phase);
    (void)json_push_kv_str(&reply->data, "first_error", record.first_error);
    (void)json_push_kv_int(
        &reply->data, "repeat_count",
        record.repeat_count > INT64_MAX ? INT64_MAX
                                        : (int64_t)record.repeat_count);
    char input[96];
    (void)snprintf(input, sizeof(input), "{\"failure_id\":\"%s\"}",
                   record.failure_id);
    (void)zcl_command_reply_add_next(
        reply, "dev.diagnose.show", input,
        "inspect the most recently recorded deterministic compiler failure");
}

void zcl_native_handle_dev_diagnose_show(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!reply)
        return;
    const struct json_value *id_value =
        request && request->input ? json_get(request->input, "failure_id")
                                  : NULL;
    const char *failure_id =
        id_value && id_value->type == JSON_STR ? json_get_str(id_value) : NULL;
    if (!dev_failure_id_valid(failure_id)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "INVALID_FAILURE_ID",
                               "normalize", false, false,
                               "failure_id must be 64 lowercase hex "
                               "characters, e.g. 3f9a... (32 bytes "
                               "hex-encoded)",
                               "failure_id");
        return;
    }
    struct zcl_dev_failure_record record;
    char why[192] = {0};
    enum zcl_dev_failure_lookup lookup =
        zcl_dev_failure_read(dev_source_root(request), failure_id, &record,
                             why, sizeof(why));
    if (lookup == ZCL_DEV_FAILURE_LOOKUP_ABSENT) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "FAILURE_NOT_FOUND", "read", false, false,
            "no durable failure exists for this workspace-scoped ID",
            failure_id);
        (void)snprintf(reply->error.failure_id,
                       sizeof(reply->error.failure_id), "%s", failure_id);
        (void)zcl_command_reply_add_next(
            reply, "dev.diagnose.latest", "{}",
            "inspect the most recently recorded failure for this workspace");
        return;
    }
    if (lookup != ZCL_DEV_FAILURE_LOOKUP_FOUND) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
            "FAILURE_STORE_INVALID", "read", false, false,
            "durable failure failed inode or SHA3 validation",
            why[0] ? why : "failure_record_invalid");
        (void)snprintf(reply->error.failure_id,
                       sizeof(reply->error.failure_id), "%s", failure_id);
        return;
    }
    const char *view = request && request->view && request->view[0]
                           ? request->view : "normal";
    bool summary = strcmp(view, "summary") == 0;
    bool full = strcmp(view, "full") == 0;
    (void)json_push_kv_str(&reply->data, "schema",
                           "zcl.dev_failure_show.v1");
    (void)json_push_kv_bool(&reply->data, "found", true);
    (void)json_push_kv_str(&reply->data, "failure_id", record.failure_id);
    (void)json_push_kv_str(&reply->data, "phase", record.phase);
    (void)json_push_kv_str(&reply->data, "first_error", record.first_error);
    (void)json_push_kv_int(
        &reply->data, "repeat_count",
        record.repeat_count > INT64_MAX ? INT64_MAX
                                        : (int64_t)record.repeat_count);
    if (!summary) {
        (void)json_push_kv_str(&reply->data, "record_sha3",
                               record.record_digest);
        (void)json_push_kv_str(&reply->data, "workspace_id",
                               record.workspace_id);
        (void)json_push_kv_str(&reply->data, "source_id_sha256",
                               record.source_id);
        (void)json_push_kv_str(&reply->data,
                               "first_source_mutation_sha256",
                               record.first_source_mutation);
        (void)json_push_kv_str(&reply->data, "first_execution_id_sha3",
                               record.first_execution_id);
        (void)json_push_kv_int(&reply->data, "first_seen_unix_ms",
                               record.first_seen_unix_ms);
        (void)json_push_kv_bool(&reply->data, "capsule_available",
                                record.capsule[0] != 0);
    }
    if (full) {
        (void)json_push_kv_str(&reply->data, "failure_capsule",
                               record.capsule);
        (void)json_push_kv_str(&reply->data, "retry_command",
                               record.retry_command);
    }
    (void)zcl_command_reply_add_next(
        reply, "dev.ff", "{}",
        "rerun the current checkout's fail-fast ladder without coalescing");
}

#endif /* ZCL_DEV_BUILD || ZCL_TESTING */

/* ── dev.vcs.revert — relink activator seam ──────────────────────────
 * These activators are retained for the future transactional implementation,
 * but deliberately have no caller: relink_generation is refused before VCS
 * mutation below.
 *
 *   - dev_vcs_shell_fallback_activate() (wave 3.3, the long-standing
 *     default): rebuilds the binary from the just-reverted source tree and
 *     redeploys it via the same fixed argv devloop's transactional-reload
 *     path uses (tools/dev/devloop_cycle.c: `make agent-deploy-fast`) —
 *     never a shell string, never touching contexts/commons/modules/vcs/. It cannot tell a full
 *     binary-generation hash apart from a bare hotswap .so hash, so it
 *     always issues a full rebuild+redeploy from the now-reverted source
 *     tree: always a safe way to activate ANY generation, just not the
 *     minimal one for a hotswap-only generation.
 *
 *   - dev_vcs_native_activate() (wave 3.2 engine, ZCL_DEV_NATIVE_ACTIVATION
 *     opt-in): calls dev_activation_activate_generation() directly against
 *     the already-staged gen-<sha> directory — no rebuild, no redeploy
 *     shell-out. Unlike the shell fallback it DOES tell the two hash kinds
 *     apart: dev_activation_activate_generation() requires
 *     gen_root/gen-<sha>/zclassic23-dev to already exist and match the
 *     requested sha, so a hotswap-anchored commit (whose generation_sha256
 *     addresses a standalone .so, never staged as a full binary directory)
 *     correctly fails staging and this function returns false — vcs_revert
 *     then reports VCS_EPARTIAL exactly per vcs.h's documented contract,
 *     rather than the shell fallback's blunter "always rebuild" guess.
 *
 * The dormant selector picks between them at call time via
 * dev_activation_native_enabled() (the same runtime env switch
 * devloop_cycle.c's transactional-reload site uses) — default OFF, so
 * today's shell-fallback behavior is unchanged unless the dev lane opts in. */
#ifdef ZCL_DEV_BUILD
static bool dev_capture_source_identity(const char *root, char out[65])
{
    char tool[PATH_MAX];
    int n = snprintf(tool, sizeof(tool), "%s/tools/dev/source-identity.sh",
                     root);
    if (n <= 0 || (size_t)n >= sizeof(tool))
        return false;
    const char *argv[] = { tool, "capture", NULL };
    struct zcl_devloop_process_result result = {0};
    if (!zcl_devloop_process_run(root, argv, 30000, &result) ||
        result.exit_code != 0 || result.timed_out || result.term_signal != 0 ||
        result.output_truncated)
        return false;
    size_t len = result.output_len;
    while (len > 0 && (result.output[len - 1] == '\n' ||
                       result.output[len - 1] == '\r'))
        len--;
    if (len != 64 || strspn(result.output, "0123456789abcdefABCDEF") < len)
        return false;
    memcpy(out, result.output, len);
    out[len] = 0;
    return true;
}

static bool dev_verify_source_identity(const char *root,
                                       const char identity[65])
{
    char tool[PATH_MAX];
    int n = snprintf(tool, sizeof(tool), "%s/tools/dev/source-identity.sh",
                     root);
    if (n <= 0 || (size_t)n >= sizeof(tool))
        return false;
    const char *argv[] = { tool, "verify", identity, NULL };
    struct zcl_devloop_process_result result = {0};
    return zcl_devloop_process_run(root, argv, 30000, &result) &&
           result.exit_code == 0 && !result.timed_out &&
           result.term_signal == 0;
}

static bool dev_vcs_shell_fallback_activate(const uint8_t gen_sha256[32],
                                            void *ctx)
{
    (void)ctx;
    (void)gen_sha256; /* vcs_revert() already skips an all-zero hash; the
                       * shell fallback rebuilds from source regardless of
                       * which non-zero generation is bound. */
    const char *root = getenv("ZCL_DEV_SOURCE_ROOT");
    if (!root || !root[0])
        root = ".";
    char identity[65], source_arg[96];
    if (!dev_capture_source_identity(root, identity))
        return false;
    int n = snprintf(source_arg, sizeof(source_arg), "ZCL_DEV_SOURCE_ID=%s",
                     identity);
    if (n <= 0 || (size_t)n >= sizeof(source_arg))
        return false;
    const char *argv[] = {
        "make", "--no-print-directory", "agent-deploy-fast", source_arg,
        NULL
    };
    struct zcl_devloop_process_result result;
    if (!zcl_devloop_process_run(root, argv, 900000, &result))
        return false;
    return result.exit_code == 0 && !result.timed_out &&
           result.term_signal == 0;
}

static bool dev_vcs_native_activate(const uint8_t gen_sha256[32], void *ctx)
{
    (void)ctx;
    const char *root = getenv("ZCL_DEV_SOURCE_ROOT");
    if (!root || !root[0])
        root = ".";
    /* No build/rebuild here — dev_activation_activate_generation() never
     * builds, it only relinks an already-staged generation. build_commit is
     * "" (not NULL): the staged generation's own manifest already carries
     * its build_commit, and dev_op_preflight() skips the expected-commit
     * comparison entirely when passed an empty string (see
     * tools/dev/dev_activation_ops.c). */
    struct dev_activation_cycle_request creq;
    if (!dev_activation_request_from_cycle(root, "", &creq))
        return false;
    char identity[65];
    if (!dev_capture_source_identity(root, identity))
        return false;
    creq.req.source_identity = identity;
    struct dev_activation_ops ops;
    dev_activation_default_ops(&creq.req, &ops);
    struct dev_activation_result result = {0};
    if (!dev_verify_source_identity(root, identity))
        return false;
    int rc = dev_activation_activate_generation(gen_sha256, &creq.req, &ops,
                                                &result);
    return rc == DEV_ACTIVATION_OK;
}

static __attribute__((unused)) struct vcs_revert_relink_ops
dev_vcs_revert_relink_ops(void)
{
    if (dev_activation_native_enabled())
        return (struct vcs_revert_relink_ops){
            .activate_generation = dev_vcs_native_activate,
            .ctx = NULL,
        };
    return (struct vcs_revert_relink_ops){
        .activate_generation = dev_vcs_shell_fallback_activate,
        .ctx = NULL,
    };
}
#endif /* ZCL_DEV_BUILD */

void zcl_native_handle_dev_vcs_revert(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
#ifndef ZCL_DEV_BUILD
    (void)request;
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
        "DEV_BUILD_REQUIRED", "dispatch", false, false,
        "one-command source+binary revert requires a dev build",
        "make dev-bin, or zclassic23-dev");
#else
    if (!reply)
        return;
    if (!request || !request->input) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "BAD_REQUEST",
                               "normalize", false, false,
                               "missing request input", "");
        return;
    }

    const char *to_hex = json_get_str(json_get(request->input, "to"));
    bool relink_generation =
        json_get_bool(json_get(request->input, "relink_generation"));
    if (relink_generation) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
            "RUNTIME_PUBLICATION_CONTAINED", "authority", false, false,
            "source revert with generation relinking is contained until "
            "immutable source epochs, proof receipts, resident CAS, and "
            "rollback are one durable transaction",
            "retry with relink_generation=false to create only the append-only source revert");
        return;
    }

    uint8_t target[32];
    if (!to_hex || strlen(to_hex) != 64 || !IsHex(to_hex) ||
        ParseHex(to_hex, target, sizeof(target)) != sizeof(target)) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "BAD_COMMIT_ID", "normalize", false, false,
            "'to' must be a 64-char hex ZVCS commit id",
            to_hex ? to_hex : "");
        return;
    }

    const char *root = (request->context && request->context->source_root &&
                        request->context->source_root[0])
                           ? request->context->source_root
                           : ".";
    struct vcs_repo *r = vcs_open(root);
    if (!r) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "VCS_OPEN_FAILED",
                               "execute", false, false,
                               "could not open the ZVCS repo at source_root",
                               root);
        return;
    }

    uint8_t new_commit[32] = {0};
    int rc = vcs_revert(r, target, NULL, new_commit);
    vcs_close(r);

    /* Only VCS_OK / VCS_EPARTIAL actually write out_new_commit (vcs_revert
     * forwards VCS_REFUSED / VCS_ERR before the forward commit lands), so
     * the hex form is computed lazily per-branch below, never over an
     * unwritten buffer. */
    char new_hex[65];

    switch (rc) {
    case VCS_OK:
        zcl_hex_encode(new_commit, 32, new_hex);
        (void)json_push_kv_str(&reply->data, "to", to_hex);
        (void)json_push_kv_str(&reply->data, "forward_commit", new_hex);
        (void)json_push_kv_bool(&reply->data, "relink_generation",
                                relink_generation);
        (void)json_push_kv_str(&reply->data, "status", "reverted");
        return;
    case VCS_EPARTIAL:
        zcl_hex_encode(new_commit, 32, new_hex);
        (void)json_push_kv_str(&reply->data, "to", to_hex);
        (void)json_push_kv_str(&reply->data, "forward_commit", new_hex);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
            "RELINK_ACTIVATION_FAILED", "execute", true, true,
            "source revert + forward commit landed (append-only, never "
            "undone), but binary-generation activation failed",
            new_hex);
        return;
    case VCS_REFUSED:
        (void)json_push_kv_str(&reply->data, "to", to_hex);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
            "SEALED_PATH_REFUSED", "execute", false, true,
            "revert would change a sealed path; run the owner-gated "
            "unseal ritual first",
            to_hex);
        return;
    default:
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "REVERT_FAILED",
                               "execute", false, false,
                               "vcs_revert failed (bad commit id or a "
                               "worktree I/O error)",
                               to_hex);
        return;
    }
#endif
}

/* ── dev.vcs.seal.grant — owner-run ZVCS unseal-token ritual ─────────
 * ZVCS's seal pin (contexts/commons/modules/vcs/src/vcs_seal.c: pin in index.kv, one-shot token
 * via vcs_seal_grant_unseal(), VCS_SEAL_TOKEN_KEY) has NO operator surface —
 * vcs_seal_grant_unseal() has zero callers outside lib/test. This executor
 * IS that surface, mirroring the core-unseal Makefile ritual's shape
 * (mandatory reason, append-only record, one-shot token, "no agent source
 * edit can produce this — owner make target") but for the ZVCS pin instead
 * of core/MANIFEST.sha3.
 *
 * contexts/commons/modules/vcs/ stays git-free and process-spawn-free (the ZVCS sovereignty
 * gate): this file computes the CURRENT worktree's sealset with the exact
 * same primitives vcs_snapshot() itself uses (vcs_manifest_build +
 * vcs_seal_load_globs + vcs_sealset_hash), calls vcs_seal_grant_unseal() to
 * mint the one-shot token, then appends an audit record (reason + old/new
 * sealset hex + timestamp) into index.kv's meta table. meta is a flat
 * key->value store with no native append primitive (vcs_index.h), so the
 * append-safe idiom is one key per grant — "seal_grant_log_<N>" — with
 * "seal_grant_count" tracking N, written in one begin/commit transaction. */
#ifdef ZCL_DEV_BUILD
static void dev_vcs_seal_iso_utc_now(char out[32])
{
    time_t t = platform_time_wall_time_t();
    struct tm tmv;
    if (platform_time_utc_tm(t, &tmv))
        strftime(out, 32, "%Y-%m-%dT%H:%M:%SZ", &tmv);
    else
        snprintf(out, 32, "1970-01-01T00:00:00Z");
}

static uint64_t dev_vcs_seal_grant_count(struct vcs_index *idx)
{
    uint8_t buf[8] = {0};
    size_t len = 0;
    bool found = false;
    if (!vcs_index_meta_get(idx, "seal_grant_count", buf, sizeof(buf), &len,
                            &found) ||
        !found || len != sizeof(buf))
        return 0;
    uint64_t n = 0;
    for (int i = 0; i < 8; i++)
        n |= (uint64_t)buf[i] << (8 * i);
    return n;
}

/* Append one audit record and advance the counter in a single txn. Returns
 * false on any write failure (the token itself is already granted by this
 * point — a logging failure is reported to the caller as a partial-mutation
 * BLOCKED result, never silently dropped). */
static bool dev_vcs_seal_grant_log(struct vcs_index *idx, const char *reason,
                                   const char *old_hex, const char *new_hex,
                                   const char *ts, char *out_key,
                                   size_t out_key_sz)
{
    uint64_t n = dev_vcs_seal_grant_count(idx);
    if (snprintf(out_key, out_key_sz, "seal_grant_log_%llu",
                (unsigned long long)n) <= 0)
        return false;

    char record[1024];
    int rn = snprintf(record, sizeof(record),
                      "ts=%s\nreason=%s\nold_sealset=%s\nnew_sealset=%s\n",
                      ts, reason, old_hex, new_hex);
    if (rn <= 0)
        return false;
    size_t rlen = (size_t)rn < sizeof(record) ? (size_t)rn : sizeof(record) - 1;

    uint8_t next[8];
    uint64_t nn = n + 1;
    for (int i = 0; i < 8; i++)
        next[i] = (uint8_t)((nn >> (8 * i)) & 0xff);

    if (!vcs_index_begin(idx))
        return false;
    if (!vcs_index_meta_set_in_tx(idx, out_key, record, rlen) ||
        !vcs_index_meta_set_in_tx(idx, "seal_grant_count", next,
                                  sizeof(next))) {
        vcs_index_rollback(idx);
        return false;
    }
    return vcs_index_commit(idx);
}
#endif /* ZCL_DEV_BUILD */

void zcl_native_handle_dev_vcs_seal_grant(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
#ifndef ZCL_DEV_BUILD
    (void)request;
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
        "DEV_BUILD_REQUIRED", "dispatch", false, false,
        "granting a ZVCS unseal token requires a dev build",
        "make dev-bin, or zclassic23-dev");
#else
    if (!reply)
        return;
    if (!request || !request->input) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "BAD_REQUEST",
                               "normalize", false, false,
                               "missing request input", "");
        return;
    }

    const char *reason = json_get_str(json_get(request->input, "reason"));
    bool confirm = json_get_bool(json_get(request->input, "confirm"));

    if (!reason || !reason[0]) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "REASON_REQUIRED", "normalize", true, false,
            "'reason' is required — record why this sealed-path change is "
            "authorized",
            "");
        return;
    }
    if (!confirm) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
            "CONFIRM_REQUIRED", "normalize", true, false,
            "granting a ZVCS unseal token requires 'confirm':true — this "
            "authorizes exactly the CURRENT tree's sealed content for the "
            "next green-cycle anchor",
            reason);
        return;
    }

    const char *root = (request->context && request->context->source_root &&
                        request->context->source_root[0])
                           ? request->context->source_root
                           : ".";
    struct vcs_repo *r = vcs_open(root);
    if (!r) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "VCS_OPEN_FAILED",
                               "execute", false, false,
                               "could not open the ZVCS repo at source_root",
                               root);
        return;
    }
    struct vcs_index *idx = vcs_repo_index(r);

    /* Compute the sealset the worktree would produce right now — the exact
     * same computation vcs_snapshot() performs before its own seal check. */
    struct vcs_manifest m;
    if (!vcs_manifest_build(root, idx, &m)) {
        vcs_close(r);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL,
                               "MANIFEST_BUILD_FAILED", "execute", false,
                               false,
                               "could not build the current worktree manifest",
                               "");
        return;
    }
    char **globs = NULL;
    size_t nglobs = 0;
    if (!vcs_seal_load_globs(root, &globs, &nglobs)) {
        vcs_manifest_free(&m);
        vcs_close(r);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL,
                               "SEAL_GLOBS_FAILED", "execute", false, false,
                               "could not load the sealed-path glob set", "");
        return;
    }
    uint8_t new_sealset[32];
    bool sh = vcs_sealset_hash(&m, globs, nglobs, new_sealset);
    vcs_seal_free_globs(globs, nglobs);
    vcs_manifest_free(&m);
    if (!sh) {
        vcs_close(r);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL,
                               "SEALSET_HASH_FAILED", "execute", false, false,
                               "could not compute the current sealset hash",
                               "");
        return;
    }

    uint8_t old_pin[32] = {0};
    bool have_old = false;
    (void)vcs_index_seal_pin_get(idx, old_pin, &have_old);

    if (!vcs_seal_grant_unseal(idx, new_sealset)) {
        vcs_close(r);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "GRANT_FAILED",
                               "execute", false, false,
                               "vcs_seal_grant_unseal failed", "");
        return;
    }

    char new_hex[65];
    HexStr(new_sealset, sizeof(new_sealset), false, new_hex, sizeof(new_hex));
    char old_hex[65];
    if (have_old)
        HexStr(old_pin, sizeof(old_pin), false, old_hex, sizeof(old_hex));
    else
        snprintf(old_hex, sizeof(old_hex), "none");

    char ts[32];
    dev_vcs_seal_iso_utc_now(ts);

    char log_key[64];
    bool logged = dev_vcs_seal_grant_log(idx, reason, old_hex, new_hex, ts,
                                         log_key, sizeof(log_key));
    vcs_close(r);

    (void)json_push_kv_str(&reply->data, "reason", reason);
    (void)json_push_kv_str(&reply->data, "old_sealset", old_hex);
    (void)json_push_kv_str(&reply->data, "granted_sealset", new_hex);
    (void)json_push_kv_str(&reply->data, "granted_at", ts);
    (void)json_push_kv_str(&reply->data, "log_key", logged ? log_key : "");
    (void)json_push_kv_str(&reply->data, "status", "granted");
    (void)json_push_kv_str(
        &reply->data, "note",
        "one-shot: the next green-cycle anchor (vcs_snapshot, e.g. via the "
        "dev change/apply cycle) consumes this token and re-pins the "
        "sealset; a FURTHER sealed-path change after that requires a new "
        "grant");

    if (!logged) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
            "LOG_WRITE_FAILED", "execute", true, true,
            "token was granted but the audit-log record failed to write",
            new_hex);
    }
#endif
}

#endif /* !ZCL_HOTFORK_NATIVE_DEV_INPUT_CORE */
