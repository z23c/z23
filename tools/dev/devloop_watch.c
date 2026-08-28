/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#define _GNU_SOURCE
#ifdef ZCL_HOTFORK_DEVLOOP_WATCH_CORE
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#else
#include "devloop.h"

#include "base/serialize_le.h"
#include "codeindex/codeindex.h"
#include "codeindex/codeindex_merkle.h"
#include "crypto/sha3.h"
#include "hotswap/hotswap_service.h"
#include "json/json.h"
#include "platform/file_watch_compat.h"
#include "platform/time_compat.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#if defined(ZCL_DEV_BUILD) || defined(ZCL_HOTFORK_DEVLOOP_WATCH_CORE)
static bool watch_c_source(const char *path)
{
    size_t n = path ? strlen(path) : 0;
    return n > 2 && path[n - 2] == '.' && path[n - 1] == 'c';
}

static bool watch_epoch_all_c(const char *const *paths, size_t path_count)
{
    if (!paths || path_count == 0)
        return false;
    for (size_t i = 0; i < path_count; i++)
        if (!watch_c_source(paths[i]))
            return false;
    return true;
}

static void watch_component_for_files(const char *const *files, size_t count,
                                      char out[128])
{
    out[0] = 0;
    for (size_t i = 0; i < count; i++) {
        char component[128];
        const char *first = strchr(files[i], '/');
        const char *second = first ? strchr(first + 1, '/') : NULL;
        size_t len = second ? (size_t)(second - files[i]) : strlen(files[i]);
        if (len >= sizeof(component))
            len = sizeof(component) - 1;
        memcpy(component, files[i], len);
        component[len] = 0;
        if (i == 0)
            (void)snprintf(out, 128, "%s", component);
        else if (strcmp(out, component) != 0) {
            (void)snprintf(out, 128, "%s", "mixed");
            return;
        }
    }
}
#endif

#ifndef ZCL_HOTFORK_DEVLOOP_WATCH_CORE

#ifdef ZCL_DEV_BUILD

#define DEVLOOP_MAX_WATCHES 512
#define DEVLOOP_EDIT_EPOCH_MAX_FILES 16
#define DEVLOOP_EDIT_QUIET_US 1000
#define DEVLOOP_MUTATION_MASK                                                \
    (IN_CLOSE_WRITE | IN_MOVED_TO | IN_MOVED_FROM | IN_CREATE | IN_DELETE)

struct watched_dir {
    int wd;
    char rel[ZCL_DEVLOOP_PATH_MAX];
};

struct watch_blob_state {
    char path[256];
    struct zcl_sha3_digest digest;
    uint64_t size;
    bool present;
};

struct watch_edit_blob {
    char path[256];
    struct zcl_sha3_digest previous_digest;
    struct zcl_sha3_digest new_digest;
    uint64_t previous_size;
    uint64_t new_size;
    bool previous_present;
    bool previous_known;
    bool new_present;
};

struct watch_edit_epoch {
    uint64_t sequence;
    int64_t seen_us;
    int64_t impact_ready_us;
    int64_t immutable_epoch_creation_us;
    int64_t impact_calculation_us;
    uint64_t changed_bytes_read;
    char id[65];
    char parent[65];
    char dependency_generation[65];
    char dependency_generation_kind[32];
    char owner[ZCL_DEVLOOP_GROUP_MAX];
    char component[128];
    size_t blob_count;
    struct watch_edit_blob blobs[DEVLOOP_EDIT_EPOCH_MAX_FILES];
};

struct watch_pending_event {
    int64_t epoch;
    size_t len;
    char body[ZCL_DEVLOOP_CYCLE_JSON_MAX];
};

struct watch_context {
    int fd;
    char root[PATH_MAX];
    struct watched_dir dirs[DEVLOOP_MAX_WATCHES];
    size_t dir_count;
    char changed[ZCL_DEVLOOP_MAX_FILES][ZCL_DEVLOOP_PATH_MAX];
    size_t changed_count;
    struct zcl_devloop_restart_source_set restart_sources;
    bool force_full_source_rescan;
    uint64_t mutation_sequence;
    int64_t first_mutation_us;
    bool edit_seen_emitted;
    struct ci_merkle *verified_tree;
    char verified_root[65];
    char dependency_generation[65];
    char dependency_generation_kind[32];
    char parent_edit_epoch[65];
    uint64_t edit_epoch_sequence;
    bool snapshot_raced;
    bool snapshot_exact;
    struct watch_blob_state overlay[ZCL_DEVLOOP_MAX_FILES];
    size_t overlay_count;
    struct watch_pending_event pending[4];
    size_t pending_count;
    struct watch_edit_epoch prepared_epoch;
    bool prepared_epoch_ready;
    bool prepared_full_rescan;
    pid_t proof_worker_pid;
    char proof_pending[ZCL_DEVLOOP_RESTART_SOURCE_MAX]
                      [ZCL_DEVLOOP_PATH_MAX];
    size_t proof_pending_count;
    enum zcl_devloop_publish_mode proof_pending_mode;
};

static volatile sig_atomic_t g_watch_stop;

/* A public service contract header is intentionally outside the live island:
 * changing ABI/schema/wire/KAT bytes invalidates the resident frozen contract.
 * Persist a typed DEV_RESTART selection without falling through to the legacy
 * make/shell proof path.  No proof is claimed and no node is restarted here. */
static int service_contract_restart_event(
    const char *root, const char *const *files, size_t count)
{
    const char *contract_path = NULL;
    const char *service_source = NULL;
    for (size_t i = 0; i < count && !service_source; i++) {
        service_source =
            zcl_hotswap_service_contract_source_for_path(files[i]);
        if (service_source) contract_path = files[i];
    }
    if (!service_source)
        return 0;
    char body[4096];
    int n = snprintf(
        body, sizeof(body),
        "{\"schema\":\"zcl.dev_cycle.v1\","
        "\"producer\":\"resident-build-authority\","
        "\"status\":\"blocked\",\"action\":\"reload\","
        "\"reload_lane\":\"DEV_RESTART\","
        "\"reason\":\"service_contract_changed\","
        "\"phase\":\"dev_restart_selected\","
        "\"runtime_published\":false,\"dev_restart\":true,"
        "\"proof_complete\":false,\"immediate_proof_complete\":false,"
        "\"integration_proof_deferred\":true,"
        "\"bounded_proof_deferred\":true,"
        "\"make_processes\":0,\"shell_processes\":0,"
        "\"lto_processes\":0,\"compiler_processes\":0,"
        "\"linker_processes\":0,\"test_processes\":0,"
        "\"contract_path\":\"%s\",\"service_source\":\"%s\","
        "\"failure_capsule\":\"frozen ABI/schema/wire/KAT contract changed; live service publication refused\","
        "\"why_not_live\":\"frozen ABI/schema/wire/KAT contract changed; live service publication refused\","
        "\"agent_next_action\":\"run make dev-bin to refresh the bounded DEV_RESTART plan, then rerun mapped proofs\"}",
        contract_path, service_source);
    if (n <= 0 || n >= (int)sizeof(body))
        return -1;
    char why[160] = {0};
    if (!zcl_devloop_cycle_state_write(root, body, (size_t)n, why,
                                       sizeof(why))) {
        fprintf(stderr, "[devloop] contract restart receipt failed: %s\n",
                why[0] ? why : "unknown");
        return -1;
    }
    (void)fwrite(body, 1, (size_t)n, stdout);
    (void)fputc('\n', stdout);
    (void)fflush(stdout);
    return 1;
}

static void mutation_sequence_advance(struct watch_context *ctx)
{
    if (ctx && ctx->mutation_sequence < UINT64_MAX)
        ctx->mutation_sequence++;
}

static void watch_signal(int sig)
{
    (void)sig;
    g_watch_stop = 1;
    zcl_devloop_process_cancel_request();
}

/* Complete proof is deliberately downstream of the reflex verdict. Run it
 * in a sibling worker so source event ingestion never depends on where that
 * slower cycle happens to reach its next cooperative process poll. The child
 * closes both watcher-owned descriptors: it can neither consume source
 * events nor retain singleton ownership after the reactor exits. */
static void proof_worker_signal(int sig)
{
    (void)sig;
    zcl_devloop_process_cancel_request();
}

static void watch_proof_reap(struct watch_context *ctx)
{
    if (!ctx || ctx->proof_worker_pid <= 1)
        return;
    int status = 0;
    pid_t got = waitpid(ctx->proof_worker_pid, &status, WNOHANG);
    if (got == ctx->proof_worker_pid || (got < 0 && errno == ECHILD))
        ctx->proof_worker_pid = 0;
}

static void watch_proof_cancel(struct watch_context *ctx)
{
    if (!ctx)
        return;
    ctx->proof_pending_count = 0;
    watch_proof_reap(ctx);
    if (ctx->proof_worker_pid <= 1)
        return;

    /* Cancellation is a priority boundary, not a best-effort notification.
     * The worker's handler immediately signals its exact active child session
     * through devloop_process. Do not wait here: this function also runs on
     * the first byte of a newer edit, whose reflex must start immediately. */
    (void)kill(ctx->proof_worker_pid, SIGTERM);
}

static void watch_proof_join(struct watch_context *ctx)
{
    if (!ctx || ctx->proof_worker_pid <= 1)
        return;
    pid_t worker = ctx->proof_worker_pid;
    int status = 0;
    pid_t got;
    do {
        got = waitpid(worker, &status, 0);
    } while (got < 0 && errno == EINTR);
    if (got == worker || (got < 0 && errno == ECHILD))
        ctx->proof_worker_pid = 0;
}

static bool watch_proof_start(struct watch_context *ctx, int watcher_lock_fd)
{
    if (!ctx)
        return false;
    watch_proof_reap(ctx);
    if (ctx->proof_worker_pid > 1 || ctx->proof_pending_count == 0)
        return true;
    pid_t child = fork();
    if (child < 0)
        return false;
    if (child == 0) {
        close(ctx->fd);
        close(watcher_lock_fd);
        zcl_devloop_process_cancel_clear();
        zcl_devloop_process_cancel_poll_clear();
        signal(SIGINT, proof_worker_signal);
        signal(SIGTERM, proof_worker_signal);
        const char *files[ZCL_DEVLOOP_RESTART_SOURCE_MAX];
        for (size_t i = 0; i < ctx->proof_pending_count; i++)
            files[i] = ctx->proof_pending[i];
        int rc = zcl_devloop_run_cycle_mode(
            ctx->root, files, ctx->proof_pending_count,
            ctx->proof_pending_mode);
        _exit(rc == 0 ? 0 : 1);
    }
    ctx->proof_worker_pid = child;
    ctx->proof_pending_count = 0;
    return true;
}

static bool watch_proof_schedule(
    struct watch_context *ctx, const char *const *files, size_t count,
    enum zcl_devloop_publish_mode publish_mode, int watcher_lock_fd)
{
    if (!ctx || !files || count == 0 ||
        count > ZCL_DEVLOOP_RESTART_SOURCE_MAX)
        return false;
    for (size_t i = 0; i < count; i++) {
        if (!files[i] || strlen(files[i]) >= ZCL_DEVLOOP_PATH_MAX)
            return false;
        (void)snprintf(ctx->proof_pending[i],
                       sizeof(ctx->proof_pending[i]), "%s", files[i]);
    }
    ctx->proof_pending_count = count;
    ctx->proof_pending_mode = publish_mode;
    return watch_proof_start(ctx, watcher_lock_fd);
}

static void print_json_string(FILE *stream, const char *value)
{
    (void)fputc('"', stream);
    for (const unsigned char *p =
             (const unsigned char *)(value ? value : ""); *p; p++) {
        if (*p == '"' || *p == '\\')
            (void)fprintf(stream, "\\%c", *p);
        else if (*p < 0x20)
            (void)fprintf(stream, "\\u%04x", *p);
        else
            (void)fputc(*p, stream);
    }
    (void)fputc('"', stream);
}

static void watch_hash_cstr(struct sha3_256_ctx *sha, const char *value)
{
    const char *text = value ? value : "";
    sha3_256_write(sha, (const unsigned char *)text, strlen(text) + 1);
}

static void watch_hash_bool(struct sha3_256_ctx *sha, bool value)
{
    const unsigned char byte = value ? 1 : 0;
    sha3_256_write(sha, &byte, 1);
}

static void watch_hash_u64(struct sha3_256_ctx *sha, uint64_t value)
{
    unsigned char bytes[8];
    zcl_write_u64_le(bytes, value);
    sha3_256_write(sha, bytes, sizeof(bytes));
}

static void watch_digest_hex(struct sha3_256_ctx *sha, char out[65])
{
    struct zcl_sha3_digest digest;
    sha3_256_finalize(sha, digest.bytes);
    ci_merkle_hex(&digest, out);
}

static struct watch_blob_state *watch_overlay_find(
    struct watch_context *ctx, const char *path)
{
    for (size_t i = 0; i < ctx->overlay_count; i++)
        if (strcmp(ctx->overlay[i].path, path) == 0)
            return &ctx->overlay[i];
    return NULL;
}

static bool watch_previous_blob(struct watch_context *ctx, const char *path,
                                struct watch_edit_blob *blob)
{
    struct watch_blob_state *overlay = watch_overlay_find(ctx, path);
    if (overlay) {
        blob->previous_digest = overlay->digest;
        blob->previous_size = overlay->size;
        blob->previous_present = overlay->present;
        blob->previous_known = true;
        return true;
    }
    struct ci_merkle_leaf base;
    bool found = false;
    if (!ctx->verified_tree ||
        !ci_merkle_leaf(ctx->verified_tree, path, &base, &found))
        return false;
    if (found) {
        blob->previous_digest = base.digest;
        blob->previous_size = base.size;
        blob->previous_present = true;
    }
    /* Exact absence is knowledge too. A newly-created path has no prior blob,
     * but the reconciled inventory proves that absence just as strongly as it
     * proves a present leaf's digest. */
    blob->previous_known = ctx->snapshot_exact && !ctx->snapshot_raced;
    return true;
}

static bool watch_build_edit_epoch(struct watch_context *ctx,
                                   const char *const *files, size_t count,
                                   int64_t seen_us,
                                   struct watch_edit_epoch *epoch)
{
    if (!ctx || !files || count == 0 ||
        count > DEVLOOP_EDIT_EPOCH_MAX_FILES || !epoch)
        return false;
    const int64_t epoch_started_us = platform_time_monotonic_us();
    memset(epoch, 0, sizeof(*epoch));
    epoch->sequence = ctx->edit_epoch_sequence + 1;
    epoch->seen_us = seen_us;
    epoch->blob_count = count;
    (void)snprintf(epoch->parent, sizeof(epoch->parent), "%s",
                   ctx->parent_edit_epoch);
    (void)snprintf(epoch->dependency_generation,
                   sizeof(epoch->dependency_generation), "%s",
                   ctx->dependency_generation);
    (void)snprintf(epoch->dependency_generation_kind,
                   sizeof(epoch->dependency_generation_kind), "%s",
                   ctx->dependency_generation_kind);

    struct zcl_devloop_plan plan;
    const int64_t impact_started_us = platform_time_monotonic_us();
    if (!zcl_devloop_plan_files(files, count, &plan))
        return false;
    epoch->impact_calculation_us =
        platform_time_monotonic_us() - impact_started_us;
    (void)snprintf(epoch->owner, sizeof(epoch->owner), "%s",
                   plan.proof_group ? plan.proof_group : "make_lint_gates");
    watch_component_for_files(files, count, epoch->component);

    size_t new_overlay_slots = 0;
    for (size_t i = 0; i < count; i++) {
        struct watch_edit_blob *blob = &epoch->blobs[i];
        if (strlen(files[i]) >= sizeof(blob->path))
            return false;
        (void)snprintf(blob->path, sizeof(blob->path), "%s", files[i]);
        if (!watch_previous_blob(ctx, files[i], blob))
            return false;
        struct ci_merkle_leaf current;
        bool found = false;
        if (!ci_merkle_hash_changed_leaf(ctx->root, files[i], &current,
                                         &found))
            return false;
        blob->new_present = found;
        if (found) {
            blob->new_digest = current.digest;
            blob->new_size = current.size;
            epoch->changed_bytes_read += current.size;
        }
        if (!watch_overlay_find(ctx, files[i]))
            new_overlay_slots++;
    }
    if (new_overlay_slots > ZCL_DEVLOOP_MAX_FILES - ctx->overlay_count)
        return false;

    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    static const char domain[] = "zcl.dev_edit_epoch.v1";
    watch_hash_cstr(&sha, domain);
    watch_hash_u64(&sha, epoch->sequence);
    watch_hash_cstr(&sha, epoch->parent);
    watch_hash_cstr(&sha, epoch->dependency_generation);
    watch_hash_cstr(&sha, epoch->owner);
    watch_hash_cstr(&sha, epoch->component);
    watch_hash_u64(&sha, epoch->blob_count);
    for (size_t i = 0; i < count; i++) {
        const struct watch_edit_blob *blob = &epoch->blobs[i];
        watch_hash_cstr(&sha, blob->path);
        watch_hash_bool(&sha, blob->previous_known);
        watch_hash_bool(&sha, blob->previous_present);
        sha3_256_write(&sha, blob->previous_digest.bytes, 32);
        watch_hash_u64(&sha, blob->previous_size);
        watch_hash_bool(&sha, blob->new_present);
        sha3_256_write(&sha, blob->new_digest.bytes, 32);
        watch_hash_u64(&sha, blob->new_size);
    }
    watch_digest_hex(&sha, epoch->id);
    epoch->impact_ready_us = platform_time_monotonic_us();
    epoch->immutable_epoch_creation_us =
        epoch->impact_ready_us - epoch_started_us;

    /* Commit the already-complete immutable epoch to the resident overlay.
     * No repository discovery occurs here: one slot per known changed path. */
    for (size_t i = 0; i < count; i++) {
        const struct watch_edit_blob *blob = &epoch->blobs[i];
        struct watch_blob_state *state = watch_overlay_find(ctx, blob->path);
        if (!state) {
            state = &ctx->overlay[ctx->overlay_count++];
            memset(state, 0, sizeof(*state));
            (void)snprintf(state->path, sizeof(state->path), "%s",
                           blob->path);
        }
        state->digest = blob->new_digest;
        state->size = blob->new_size;
        state->present = blob->new_present;
    }
    ctx->edit_epoch_sequence = epoch->sequence;
    (void)snprintf(ctx->parent_edit_epoch, sizeof(ctx->parent_edit_epoch),
                   "%s", epoch->id);
    ctx->snapshot_raced = false;
    return true;
}

static bool watch_stream_enqueue(struct watch_context *ctx, const char *body,
                                 size_t len)
{
    if (!ctx || !body || len == 0 || len >= ZCL_DEVLOOP_CYCLE_JSON_MAX ||
        ctx->pending_count >= sizeof(ctx->pending) / sizeof(ctx->pending[0]))
        return false;
    struct watch_pending_event *event = &ctx->pending[ctx->pending_count];
    char why[160] = {0};
    if (!zcl_devloop_cycle_stream_publish(ctx->root, body, len,
                                          &event->epoch, why, sizeof(why))) {
        fprintf(stderr, "[devloop] volatile event publication failed: %s\n",
                why[0] ? why : "unknown");
        return false;
    }
    memcpy(event->body, body, len);
    event->body[len] = 0;
    event->len = len;
    ctx->pending_count++;
    return true;
}

static bool watch_stream_flush(struct watch_context *ctx)
{
    if (!ctx)
        return false;
    if (ctx->pending_count == 0)
        return true;
    int64_t through = ctx->pending[ctx->pending_count - 1].epoch;
    char why[160] = {0};
    if (!zcl_devloop_cycle_stream_flush_through(
            ctx->root, through, why, sizeof(why))) {
        fprintf(stderr,
                "[devloop] async event journal flush failed through=%lld: %s\n",
                (long long)through, why[0] ? why : "unknown");
        return false;
    }
    ctx->pending_count = 0;
    return true;
}

static bool watch_emit_edit_seen(struct watch_context *ctx)
{
    if (!ctx || ctx->changed_count == 0)
        return false;
    struct json_value doc, files;
    json_init(&doc); json_set_object(&doc);
    json_init(&files); json_set_array(&files);
    bool ok = json_push_kv_str(&doc, "schema", "zcl.dev_cycle.v1") &&
        json_push_kv_str(&doc, "producer", "reflex-reactor") &&
        json_push_kv_str(&doc, "status", "edit_seen") &&
        json_push_kv_str(&doc, "action", "reflex") &&
        json_push_kv_str(&doc, "reason", "source_mutation_observed") &&
        json_push_kv_str(&doc, "phase", "EDIT_SEEN") &&
        json_push_kv_bool(&doc, "runtime_published", false) &&
        json_push_kv_bool(&doc, "proof_complete", false) &&
        json_push_kv_int(
            &doc, "elapsed_us",
            ctx->first_mutation_us > 0
                ? platform_time_monotonic_us() - ctx->first_mutation_us : 0) &&
        json_push_kv_int(&doc, "file_count",
                         (int64_t)ctx->changed_count);
    for (size_t i = 0; ok && i < ctx->changed_count; i++) {
        struct json_value item;
        json_init(&item); json_set_str(&item, ctx->changed[i]);
        ok = json_push_back(&files, &item);
        json_free(&item);
    }
    ok = ok && json_push_kv(&doc, "files", &files) &&
        json_push_kv_str(&doc, "agent_next_action",
                         "impact analysis is running in the resident reactor");
    json_free(&files);
    char body[16384];
    size_t n = ok ? json_write(&doc, body, sizeof(body) - 1) : 0;
    json_free(&doc);
    if (!n)
        return false;
    body[n] = 0;
    if (!watch_stream_enqueue(ctx, body, n)) {
        fprintf(stderr, "[devloop] EDIT_SEEN stream publication failed\n");
        return false;
    }
    (void)fwrite(body, 1, n, stdout);
    (void)fputc('\n', stdout);
    (void)fflush(stdout);
    ctx->edit_seen_emitted = true;
    return true;
}

static bool watch_emit_impact_ready(struct watch_context *ctx,
                                    const struct watch_edit_epoch *epoch)
{
    if (!ctx || !epoch || epoch->blob_count == 0)
        return false;
    struct json_value doc, files, blobs;
    json_init(&doc); json_set_object(&doc);
    json_init(&files); json_set_array(&files);
    json_init(&blobs); json_set_array(&blobs);
    bool ok = json_push_kv_str(&doc, "schema", "zcl.dev_cycle.v1") &&
        json_push_kv_str(&doc, "producer", "reflex-reactor") &&
        json_push_kv_str(&doc, "status", "impact_ready") &&
        json_push_kv_str(&doc, "action", "reflex") &&
        json_push_kv_str(&doc, "reason", "immutable_edit_epoch") &&
        json_push_kv_str(&doc, "phase", "IMPACT_READY") &&
        json_push_kv_bool(&doc, "runtime_published", false) &&
        json_push_kv_bool(&doc, "proof_complete", false) &&
        json_push_kv_int(&doc, "elapsed_us",
                         epoch->impact_ready_us - epoch->seen_us) &&
        json_push_kv_int(&doc, "immutable_epoch_creation_us",
                         epoch->immutable_epoch_creation_us) &&
        json_push_kv_int(&doc, "impact_calculation_us",
                         epoch->impact_calculation_us) &&
        json_push_kv_int(&doc, "changed_bytes_read",
                         (int64_t)epoch->changed_bytes_read) &&
        json_push_kv_int(&doc, "file_count", (int64_t)epoch->blob_count) &&
        json_push_kv_str(&doc, "edit_epoch", epoch->id) &&
        json_push_kv_str(&doc, "parent_epoch", epoch->parent) &&
        json_push_kv_str(&doc, "dependency_generation",
                         epoch->dependency_generation) &&
        json_push_kv_str(&doc, "dependency_generation_kind",
                         epoch->dependency_generation_kind) &&
        json_push_kv_str(&doc, "affected_owner", epoch->owner) &&
        json_push_kv_str(&doc, "affected_component", epoch->component) &&
        json_push_kv_int(&doc, "make_processes", 0) &&
        json_push_kv_int(&doc, "shell_processes", 0) &&
        json_push_kv_int(&doc, "git_operations", 0) &&
        json_push_kv_int(&doc, "publication_operations", 0) &&
        json_push_kv_int(&doc, "remote_operations", 0) &&
        json_push_kv_int(&doc, "storage_ack_waits", 0) &&
        json_push_kv_int(&doc, "full_program_links", 0) &&
        json_push_kv_int(&doc, "network_operations", 0) &&
        json_push_kv_int(&doc, "sqlite_operations", 0) &&
        json_push_kv_int(&doc, "full_tree_scans", 0);
    for (size_t i = 0; ok && i < epoch->blob_count; i++) {
        const struct watch_edit_blob *blob = &epoch->blobs[i];
        char previous_hex[65] = {0}, new_hex[65] = {0};
        if (blob->previous_present)
            ci_merkle_hex(&blob->previous_digest, previous_hex);
        if (blob->new_present)
            ci_merkle_hex(&blob->new_digest, new_hex);
        struct json_value file, item;
        json_init(&file); json_set_str(&file, blob->path);
        ok = json_push_back(&files, &file);
        json_free(&file);
        json_init(&item); json_set_object(&item);
        ok = ok && json_push_kv_str(&item, "path", blob->path) &&
            json_push_kv_bool(&item, "previous_known",
                              blob->previous_known) &&
            json_push_kv_bool(&item, "previous_present",
                              blob->previous_present) &&
            json_push_kv_str(&item, "previous_blob_sha3", previous_hex) &&
            json_push_kv_int(&item, "previous_size",
                             (int64_t)blob->previous_size) &&
            json_push_kv_bool(&item, "new_present", blob->new_present) &&
            json_push_kv_str(&item, "new_blob_sha3", new_hex) &&
            json_push_kv_int(&item, "new_size", (int64_t)blob->new_size) &&
            json_push_back(&blobs, &item);
        json_free(&item);
    }
    ok = ok && json_push_kv(&doc, "files", &files) &&
        json_push_kv(&doc, "blobs", &blobs) &&
        json_push_kv_str(&doc, "agent_next_action",
                         "compile diagnostics are running in the resident reactor");
    json_free(&files);
    json_free(&blobs);
    char body[ZCL_DEVLOOP_CYCLE_JSON_MAX];
    size_t n = ok ? json_write(&doc, body, sizeof(body) - 1) : 0;
    json_free(&doc);
    if (!n)
        return false;
    body[n] = 0;
    if (!watch_stream_enqueue(ctx, body, n)) {
        fprintf(stderr, "[devloop] IMPACT_READY stream publication failed\n");
        return false;
    }
    (void)fwrite(body, 1, n, stdout);
    (void)fputc('\n', stdout);
    (void)fflush(stdout);
    return true;
}

static bool watch_emit_proof_pending(struct watch_context *ctx,
                                     const char *const *files, size_t count)
{
    if (!ctx || !files || count == 0)
        return false;
    struct json_value doc, paths;
    json_init(&doc); json_set_object(&doc);
    json_init(&paths); json_set_array(&paths);
    bool ok = json_push_kv_str(&doc, "schema", "zcl.dev_cycle.v1") &&
        json_push_kv_str(&doc, "producer", "reflex-reactor") &&
        json_push_kv_str(&doc, "status", "proof_pending") &&
        json_push_kv_str(&doc, "action", "verify") &&
        json_push_kv_str(&doc, "reason", "integration_proof_deferred") &&
        json_push_kv_str(&doc, "phase", "PROOF_PENDING") &&
        json_push_kv_bool(&doc, "runtime_published", false) &&
        json_push_kv_bool(&doc, "proof_complete", false) &&
        json_push_kv_str(&doc, "edit_epoch",
                         zcl_devloop_event_edit_epoch()) &&
        json_push_kv_int(&doc, "file_count", (int64_t)count);
    for (size_t i = 0; ok && i < count; i++) {
        struct json_value item;
        json_init(&item); json_set_str(&item, files[i]);
        ok = json_push_back(&paths, &item);
        json_free(&item);
    }
    ok = ok && json_push_kv(&doc, "files", &paths) &&
        json_push_kv_str(&doc, "agent_next_action",
                         "keep editing; complete reusable proof is running asynchronously");
    json_free(&paths);
    char body[ZCL_DEVLOOP_CYCLE_JSON_MAX];
    size_t n = ok ? json_write(&doc, body, sizeof(body) - 1) : 0;
    json_free(&doc);
    if (!n)
        return false;
    body[n] = 0;
    if (!watch_stream_enqueue(ctx, body, n))
        return false;
    (void)fwrite(body, 1, n, stdout);
    (void)fputc('\n', stdout);
    (void)fflush(stdout);
    return watch_stream_flush(ctx);
}

static bool watch_emit_superseded(struct watch_context *ctx)
{
    if (!ctx || ctx->changed_count == 0)
        return false;
    struct json_value doc, paths;
    json_init(&doc); json_set_object(&doc);
    json_init(&paths); json_set_array(&paths);
    bool ok = json_push_kv_str(&doc, "schema", "zcl.dev_cycle.v1") &&
        json_push_kv_str(&doc, "producer", "reflex-reactor") &&
        json_push_kv_str(&doc, "status", "superseded") &&
        json_push_kv_str(&doc, "action", "cancel") &&
        json_push_kv_str(&doc, "reason", "newer_edit_epoch") &&
        json_push_kv_str(&doc, "phase", "SUPERSEDED") &&
        json_push_kv_bool(&doc, "runtime_published", false) &&
        json_push_kv_bool(&doc, "proof_complete", false) &&
        json_push_kv_int(&doc, "queued_file_count",
                         (int64_t)ctx->changed_count);
    if (ok && zcl_devloop_event_edit_epoch()[0])
        ok = json_push_kv_str(&doc, "edit_epoch",
                              zcl_devloop_event_edit_epoch());
    for (size_t i = 0; ok && i < ctx->changed_count; i++) {
        struct json_value item;
        json_init(&item); json_set_str(&item, ctx->changed[i]);
        ok = json_push_back(&paths, &item);
        json_free(&item);
    }
    ok = ok && json_push_kv(&doc, "queued_files", &paths) &&
        json_push_kv_str(&doc, "agent_next_action",
                         "ignore obsolete foreground work; latest edit starts next");
    json_free(&paths);
    char body[ZCL_DEVLOOP_CYCLE_JSON_MAX];
    size_t n = ok ? json_write(&doc, body, sizeof(body) - 1) : 0;
    json_free(&doc);
    if (!n)
        return false;
    body[n] = 0;
    if (!watch_stream_enqueue(ctx, body, n))
        return false;
    (void)fwrite(body, 1, n, stdout);
    (void)fputc('\n', stdout);
    (void)fflush(stdout);
    return true;
}

static bool mkdirs(const char *path)
{
    char tmp[PATH_MAX];
    if (!path || !path[0] || strlen(path) >= sizeof(tmp))
        return false;
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = 0;
        if (mkdir(tmp, 0700) != 0 && errno != EEXIST)
            return false;
        *p = '/';
    }
    return mkdir(tmp, 0700) == 0 || errno == EEXIST;
}

static bool ignored_dir(const char *name)
{
    return zcl_devloop_watch_dir_is_ignored(name);
}

static bool relevant_file(const char *path)
{
    /* Shared with the dev-platform unit test — see
     * zcl_devloop_path_is_relevant() in devloop_plan.c. Keeps the watcher's
     * change filter (including the transient lint-fixture exclusion) in one
     * testable, pure place. */
    return zcl_devloop_path_is_relevant(path);
}

static struct watched_dir *find_watch(struct watch_context *ctx, int wd)
{
    for (size_t i = 0; i < ctx->dir_count; i++) {
        if (ctx->dirs[i].wd == wd)
            return &ctx->dirs[i];
    }
    return NULL;
}

static bool add_watch_recursive(struct watch_context *ctx, const char *rel)
{
    if (!ctx || ctx->dir_count >= DEVLOOP_MAX_WATCHES)
        return false;
    char full[PATH_MAX];
    int n = rel && rel[0]
        ? snprintf(full, sizeof(full), "%s/%s", ctx->root, rel)
        : snprintf(full, sizeof(full), "%s", ctx->root);
    if (n <= 0 || (size_t)n >= sizeof(full))
        return false;

    int wd = inotify_add_watch(ctx->fd, full,
        DEVLOOP_MUTATION_MASK | IN_DELETE_SELF | IN_MOVE_SELF);
    if (wd < 0)
        return false;
    struct watched_dir *slot = &ctx->dirs[ctx->dir_count++];
    slot->wd = wd;
    snprintf(slot->rel, sizeof(slot->rel), "%s", rel ? rel : "");

    DIR *dir = opendir(full);
    if (!dir)
        return true;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (ignored_dir(entry->d_name))
            continue;
        char child_full[PATH_MAX], child_rel[ZCL_DEVLOOP_PATH_MAX];
        int fn = snprintf(child_full, sizeof(child_full), "%s/%s",
                          full, entry->d_name);
        int rn = rel && rel[0]
            ? snprintf(child_rel, sizeof(child_rel), "%s/%s", rel,
                       entry->d_name)
            : snprintf(child_rel, sizeof(child_rel), "%s", entry->d_name);
        if (fn <= 0 || (size_t)fn >= sizeof(child_full) ||
            rn <= 0 || (size_t)rn >= sizeof(child_rel))
            continue;
        struct stat st;
        if (lstat(child_full, &st) == 0 && S_ISDIR(st.st_mode) &&
            !S_ISLNK(st.st_mode)) {
            if (!add_watch_recursive(ctx, child_rel)) {
                closedir(dir);
                return false;
            }
        }
    }
    closedir(dir);
    return true;
}

static void add_changed(struct watch_context *ctx, const char *path)
{
    if (!ctx || !relevant_file(path))
        return;
    for (size_t i = 0; i < ctx->changed_count; i++) {
        if (strcmp(ctx->changed[i], path) == 0)
            return;
    }
    if (ctx->changed_count >= ZCL_DEVLOOP_MAX_FILES) {
        /* A broad/overflowing edit must fail toward reload, never silently
         * drop paths and accidentally qualify for hot-swap. */
        ctx->changed_count = 1;
        snprintf(ctx->changed[0], sizeof(ctx->changed[0]), "%s", "Makefile");
        return;
    }
    if (ctx->changed_count == 0) {
        /* The first mutation after a reflex verdict invalidates any queued
         * complete proof and cooperatively cancels its isolated worker. The
         * watcher remains the sole producer of the replacement epoch. */
        watch_proof_cancel(ctx);
        ctx->first_mutation_us = platform_time_monotonic_us();
    }
    snprintf(ctx->changed[ctx->changed_count],
             sizeof(ctx->changed[ctx->changed_count]), "%s", path);
    ctx->changed_count++;
}

static bool collect_events(struct watch_context *ctx)
{
    char buffer[64 * 1024];
    bool saw = false;
    for (;;) {
        ssize_t n = read(ctx->fd, buffer, sizeof(buffer));
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            break;
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        for (char *p = buffer; p < buffer + n; ) {
            struct inotify_event *ev = (struct inotify_event *)p;
            p += sizeof(*ev) + ev->len;
            if (ev->mask & IN_Q_OVERFLOW) {
                mutation_sequence_advance(ctx);
                ctx->force_full_source_rescan = true;
                add_changed(ctx, "Makefile");
                saw = true;
                continue;
            }
            struct watched_dir *dir = find_watch(ctx, ev->wd);
            if (!dir)
                continue;
            if (ev->mask & (IN_IGNORED | IN_DELETE_SELF | IN_MOVE_SELF)) {
                mutation_sequence_advance(ctx);
                ctx->force_full_source_rescan = true;
                add_changed(ctx, "Makefile");
                saw = true;
            }
            if (ev->len == 0)
                continue;
            char rel[ZCL_DEVLOOP_PATH_MAX];
            int rn = dir->rel[0]
                ? snprintf(rel, sizeof(rel), "%s/%s", dir->rel, ev->name)
                : snprintf(rel, sizeof(rel), "%s", ev->name);
            if (rn <= 0 || (size_t)rn >= sizeof(rel))
                continue;
            if (ev->mask & IN_ISDIR) {
                /* The recursive watch deliberately never enters generated,
                 * dependency, or dot-prefixed scratch directories. Their
                 * create/remove traffic is equally irrelevant: treating it
                 * as a synthetic Makefile edit cancels the exact proof that
                 * created a test scratch directory in the first place. */
                if (ignored_dir(ev->name))
                    continue;
                mutation_sequence_advance(ctx);
                add_changed(ctx, "Makefile");
                saw = true;
                if ((ev->mask & (IN_CREATE | IN_MOVED_TO)) &&
                    !add_watch_recursive(ctx, rel)) {
                    ctx->force_full_source_rescan = true;
                }
                if (ev->mask & (IN_DELETE | IN_MOVED_FROM))
                    ctx->force_full_source_rescan = true;
                continue;
            }
            if (!(ev->mask & IN_ISDIR) &&
                zcl_devloop_watch_event_is_mutation(ev->mask)) {
                mutation_sequence_advance(ctx);
                size_t before = ctx->changed_count;
                add_changed(ctx, rel);
                saw = saw || ctx->changed_count != before;
            }
        }
    }
    return saw;
}

/* Watches are armed before this runs. The reconciled refresh validates the
 * SHA3 seal, enumerates and stats the current policy inventory, and performs a
 * complete byte pass only when the prior image is absent/invalid or its
 * inventory moved. Any mutation racing that work is already queued in inotify
 * and is drained before the image can be described as trusted. */
static bool prime_source_snapshot(struct watch_context *ctx)
{
    int64_t started_us = platform_time_monotonic_us();
    struct ci_merkle_cost cost = {0};
    struct ci_merkle *tree =
        ci_merkle_refresh_reconciled(ctx->root, &cost);
    if (!tree)
        return false;
    struct ci_merkle_node root = {0};
    bool ok = ci_merkle_root(tree, &root);
    char root_hex[65] = {0};
    if (ok)
        ci_merkle_hex(&root.digest, root_hex);
    if (!ok)
        ci_merkle_free(tree);
    if (!ok)
        return false;

    struct zcl_sha3_digest dependency_digest;
    bool have_dependency_generation = false;
    struct codeindex *dependency_index = codeindex_open_existing(ctx->root);
    if (dependency_index) {
        have_dependency_generation = codeindex_source_root_sha3(
            dependency_index, dependency_digest.bytes);
        codeindex_close(dependency_index);
    }
    if (have_dependency_generation) {
        ci_merkle_hex(&dependency_digest, ctx->dependency_generation);
        (void)snprintf(ctx->dependency_generation_kind,
                       sizeof(ctx->dependency_generation_kind), "%s",
                       "codeindex_source_root");
    } else {
        (void)snprintf(ctx->dependency_generation,
                       sizeof(ctx->dependency_generation), "%s", root_hex);
        (void)snprintf(ctx->dependency_generation_kind,
                       sizeof(ctx->dependency_generation_kind), "%s",
                       "source_merkle_fallback");
    }
    if (ctx->verified_tree)
        ci_merkle_free(ctx->verified_tree);
    ctx->verified_tree = tree;
    ctx->snapshot_exact = true;
    (void)snprintf(ctx->verified_root, sizeof(ctx->verified_root), "%s",
                   root_hex);
    if (ctx->edit_epoch_sequence == 0) {
        struct sha3_256_ctx parent_sha;
        sha3_256_init(&parent_sha);
        watch_hash_cstr(&parent_sha, "zcl.dev_edit_epoch.base.v1");
        watch_hash_cstr(&parent_sha, ctx->verified_root);
        watch_hash_cstr(&parent_sha, ctx->dependency_generation);
        watch_digest_hex(&parent_sha, ctx->parent_edit_epoch);
    }

    (void)collect_events(ctx);
    ctx->snapshot_raced = ctx->changed_count > 0;
    int64_t elapsed_us = platform_time_monotonic_us() - started_us;
    printf("{\"schema\":\"zcl.dev_source_snapshot.v1\","
           "\"status\":\"reconciled\",\"inotify_armed\":true,"
           "\"seal_verified\":%s,\"snapshot_used\":%s,"
           "\"full_rescan\":%s,\"inventory_changed\":%s,"
           "\"files_total\":%u,\"files_read\":%u,"
           "\"bytes_read\":%llu,\"queued_paths\":%zu,"
           "\"mutation_sequence\":%llu,\"elapsed_us\":%lld,"
           "\"source_root\":\"%s\"}\n",
           cost.snapshot_used ? "true" : "false",
           cost.snapshot_used ? "true" : "false",
           cost.full_rescan ? "true" : "false",
           cost.inventory_changed ? "true" : "false",
           (unsigned)cost.files_total, (unsigned)cost.files_read,
           (unsigned long long)cost.bytes_read, ctx->changed_count,
           (unsigned long long)ctx->mutation_sequence,
           (long long)elapsed_us, root_hex);
    fflush(stdout);
    return true;
}

static bool watch_cancel_poll(void *opaque)
{
    struct watch_context *ctx = opaque;
    if (g_watch_stop)
        return true;
    bool changed = collect_events(ctx) && ctx->changed_count > 0;
    if (changed && !ctx->edit_seen_emitted && !watch_emit_edit_seen(ctx)) {
        g_watch_stop = 1;
        return true;
    }
    if (changed && !ctx->prepared_epoch_ready) {
        const char *files[ZCL_DEVLOOP_MAX_FILES];
        size_t count = ctx->changed_count;
        int64_t seen_us = ctx->first_mutation_us > 0
            ? ctx->first_mutation_us : platform_time_monotonic_us();
        for (size_t i = 0; i < count; i++)
            files[i] = ctx->changed[i];
        struct watch_edit_epoch epoch;
        if (watch_build_edit_epoch(ctx, files, count, seen_us, &epoch)) {
            /* This event names the old foreground epoch. The new immutable
             * epoch becomes current only after obsolete work is visibly
             * superseded, so a drive consumer cannot confuse the two. */
            if (!watch_emit_superseded(ctx) ||
                !zcl_devloop_event_edit_epoch_set(epoch.id) ||
                !watch_emit_impact_ready(ctx, &epoch)) {
                g_watch_stop = 1;
                return true;
            }
            ctx->prepared_epoch = epoch;
            ctx->prepared_epoch_ready = true;
            ctx->prepared_full_rescan = ctx->force_full_source_rescan;
            ctx->changed_count = 0;
            ctx->first_mutation_us = 0;
            ctx->edit_seen_emitted = false;
            ctx->force_full_source_rescan = false;
        }
    }
    return changed;
}

static bool watch_start_event_stream(struct watch_context *ctx)
{
    char latest[ZCL_DEVLOOP_CYCLE_JSON_MAX], why[160] = {0};
    size_t latest_len = 0;
    int64_t durable_epoch = 0;
    enum zcl_devloop_state_lookup state = zcl_devloop_cycle_state_read(
        ctx->root, latest, sizeof(latest), &latest_len, &durable_epoch,
        why, sizeof(why));
    if (state == ZCL_DEVLOOP_STATE_INVALID) {
        fprintf(stderr, "[devloop] event stream anchor invalid: %s\n",
                why[0] ? why : "unknown");
        return false;
    }
    if (state == ZCL_DEVLOOP_STATE_ABSENT)
        durable_epoch = 0;
    if (!zcl_devloop_cycle_stream_reset(ctx->root, durable_epoch,
                                        why, sizeof(why))) {
        fprintf(stderr, "[devloop] event stream reset failed: %s\n",
                why[0] ? why : "unknown");
        return false;
    }
    return true;
}

static int open_singleton_lock(const char *repo_root,
                               enum zcl_devloop_publish_mode publish_mode)
{
    char dir[PATH_MAX], path[PATH_MAX];
    int dn = snprintf(dir, sizeof(dir), "%s/.cache", repo_root);
    if (dn <= 0 || (size_t)dn >= sizeof(dir) ||
        !zcl_devloop_watch_lock_path(repo_root, path, sizeof(path)))
        return -1;
    if (!mkdirs(dir))
        return -1;
    int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0 || flock(fd, LOCK_EX | LOCK_NB) != 0) {
        if (fd >= 0)
            close(fd);
        return -1;
    }
    if (ftruncate(fd, 0) == 0)
        dprintf(fd, "%ld %s starting\n", (long)getpid(),
                zcl_devloop_publish_mode_name(publish_mode));
    return fd;
}

static bool mark_singleton_ready(
    int fd, enum zcl_devloop_publish_mode publish_mode)
{
    if (fd < 0 || ftruncate(fd, 0) != 0 || lseek(fd, 0, SEEK_SET) < 0)
        return false;
    return dprintf(fd, "%ld %s ready\n", (long)getpid(),
                   zcl_devloop_publish_mode_name(publish_mode)) > 0;
}

int zcl_devloop_watch_mode_until(const char *repo_root,
    enum zcl_devloop_publish_mode publish_mode,
    zcl_devloop_stop_predicate stop, void *stop_opaque)
{
    struct watch_context ctx = {0};
    const char *root = repo_root && repo_root[0] ? repo_root : ".";
    const char *mode_name = zcl_devloop_publish_mode_name(publish_mode);
    if (!mode_name) {
        fprintf(stderr, "[devloop] watch: invalid publication mode\n");
        return 2;
    }
    if (!realpath(root, ctx.root)) {
        fprintf(stderr, "[devloop] watch: cannot resolve repository root: %s\n",
                strerror(errno));
        return 2;
    }
    /* The resident compiler must not share eviction/cleanup state with full
     * builds on the host. A saturated global ccache inflated the protected
     * story from ~90 ms to ~500 ms even though impact and the candidate were
     * unchanged. This checkout-local bounded cache is warm-service state,
     * outside Git and outside the immutable source epoch. */
    char reflex_ccache[PATH_MAX];
    int cache_n = snprintf(reflex_ccache, sizeof(reflex_ccache),
                           "%s/.cache/devloop-ccache-v1", ctx.root);
    if (cache_n <= 0 || (size_t)cache_n >= sizeof(reflex_ccache) ||
        setenv("CCACHE_DIR", reflex_ccache, 1) != 0 ||
        setenv("CCACHE_MAXSIZE", "512M", 1) != 0) {
        fprintf(stderr,
                "[devloop] watch: compiler cache isolation failed\n");
        return 1;
    }
    char makefile[PATH_MAX];
    snprintf(makefile, sizeof(makefile), "%s/Makefile", ctx.root);
    if (access(makefile, R_OK) != 0) {
        fprintf(stderr, "[devloop] watch: root has no readable Makefile\n");
        return 2;
    }
    int lock_fd = open_singleton_lock(ctx.root, publish_mode);
    if (lock_fd < 0) {
        fprintf(stderr,
                "[devloop] watch: another watcher owns this worktree lane\n");
        return 1;
    }
    ctx.fd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
    if (ctx.fd < 0 || !add_watch_recursive(&ctx, "")) {
        fprintf(stderr, "[devloop] watch: recursive inotify setup failed: %s\n",
                strerror(errno));
        if (ctx.fd >= 0)
            close(ctx.fd);
        close(lock_fd);
        return 1;
    }
    if (!prime_source_snapshot(&ctx)) {
        fprintf(stderr,
                "[devloop] watch: source snapshot reconciliation failed\n");
        close(ctx.fd);
        close(lock_fd);
        return 1;
    }
    if (!watch_start_event_stream(&ctx)) {
        fprintf(stderr,
                "[devloop] watch: bounded local event stream unavailable\n");
        ci_merkle_free(ctx.verified_tree);
        close(ctx.fd);
        close(lock_fd);
        return 1;
    }
    if (!mark_singleton_ready(lock_fd, publish_mode)) {
        fprintf(stderr,
                "[devloop] watch: could not publish ready ownership\n");
        close(ctx.fd);
        close(lock_fd);
        return 1;
    }

    g_watch_stop = 0;
    zcl_devloop_process_cancel_clear();
    zcl_devloop_process_cancel_poll_clear();
    signal(SIGINT, watch_signal);
    signal(SIGTERM, watch_signal);
    printf("{\"schema\":\"zcl.dev_watch_heartbeat.v1\","
           "\"status\":\"watching\",\"pid\":%ld,\"directories\":%zu,"
           "\"root\":\"%s\",\"mode\":\"%s\","
           "\"runtime_publication\":%s,"
           "\"agent_next_action\":\"edit code\"}\n",
           (long)getpid(), ctx.dir_count, ctx.root, mode_name,
           zcl_devloop_publish_mode_applies(publish_mode) ? "true" : "false");
    fflush(stdout);

    while (!g_watch_stop && !(stop && stop(stop_opaque))) {
        if (!watch_proof_start(&ctx, lock_fd)) {
            fprintf(stderr, "[devloop] complete proof worker start failed\n");
            break;
        }
        if (ctx.changed_count == 0 && !ctx.prepared_epoch_ready) {
            struct pollfd pfd = { .fd = ctx.fd, .events = POLLIN };
            int prc = poll(&pfd, 1, stop ? 100 : 1000);
            if (prc < 0 && errno == EINTR)
                continue;
            if (prc < 0) {
                fprintf(stderr, "[devloop] watch: poll failed: %s\n",
                        strerror(errno));
                break;
            }
            if (prc == 0)
                continue;
            if (!collect_events(&ctx) || ctx.changed_count == 0)
                continue;
        }

        char epoch_changed[ZCL_DEVLOOP_MAX_FILES][ZCL_DEVLOOP_PATH_MAX];
        const char *files[ZCL_DEVLOOP_MAX_FILES];
        struct watch_edit_epoch edit_epoch;
        bool impact_already_emitted = ctx.prepared_epoch_ready;
        bool full_rescan = false;
        size_t epoch_count = 0;
        bool edit_epoch_ready = false;
        if (ctx.prepared_epoch_ready) {
            edit_epoch = ctx.prepared_epoch;
            epoch_count = edit_epoch.blob_count;
            full_rescan = ctx.prepared_full_rescan;
            for (size_t i = 0; i < epoch_count; i++) {
                snprintf(epoch_changed[i], sizeof(epoch_changed[i]), "%s",
                         edit_epoch.blobs[i].path);
                files[i] = epoch_changed[i];
            }
            ctx.prepared_epoch_ready = false;
            ctx.prepared_full_rescan = false;
            edit_epoch_ready = true;
        } else {
            if (!ctx.edit_seen_emitted && !watch_emit_edit_seen(&ctx))
                break;

            /* Coalesce one editor's temp-file events into one save epoch.
             * Separate saves may remain separate; supersession makes that
             * cheaper and more exact than delaying their first impact. */
            int64_t quiet_until =
                platform_time_monotonic_us() + DEVLOOP_EDIT_QUIET_US;
            while (!g_watch_stop && !(stop && stop(stop_opaque))) {
                int64_t remain_us =
                    quiet_until - platform_time_monotonic_us();
                if (remain_us <= 0)
                    break;
                int wait_ms = (int)((remain_us + 999) / 1000);
                if (stop && wait_ms > 100) wait_ms = 100;
                struct pollfd debounce = { .fd = ctx.fd, .events = POLLIN };
                int drc = poll(&debounce, 1, wait_ms);
                if (drc > 0 && collect_events(&ctx))
                    quiet_until = platform_time_monotonic_us() +
                        DEVLOOP_EDIT_QUIET_US;
                else if (drc < 0 && errno != EINTR)
                    break;
            }

            epoch_count = ctx.changed_count;
            int64_t epoch_seen_us = ctx.first_mutation_us > 0
                ? ctx.first_mutation_us : platform_time_monotonic_us();
            for (size_t i = 0; i < epoch_count; i++) {
                snprintf(epoch_changed[i], sizeof(epoch_changed[i]), "%s",
                         ctx.changed[i]);
                files[i] = epoch_changed[i];
            }
            ctx.changed_count = 0;
            ctx.first_mutation_us = 0;
            ctx.edit_seen_emitted = false;
            full_rescan = ctx.force_full_source_rescan;
            ctx.force_full_source_rescan = false;
            edit_epoch_ready = watch_build_edit_epoch(
                &ctx, files, epoch_count, epoch_seen_us, &edit_epoch);
        }
        if (edit_epoch_ready) {
            if (!zcl_devloop_event_edit_epoch_set(edit_epoch.id))
                break;
            if (!impact_already_emitted &&
                !watch_emit_impact_ready(&ctx, &edit_epoch))
                break;
        } else {
            (void)zcl_devloop_event_edit_epoch_set("");
            fprintf(stderr,
                    "[devloop] immutable edit epoch deferred; conservative "
                    "source reconciliation required\n");
        }
        /* The volatile events are now sufficient to start the reflex. Their
         * ordered sealed copies are flushed only after useful feedback is
         * visible, so storage acknowledgement is not a candidate prerequisite. */
        if (full_rescan) {
            ctx.snapshot_exact = false;
            (void)ci_merkle_forget(ctx.root);
        }
        printf("{\"schema\":\"zcl.dev_source_epoch.v1\","
               "\"mutation_sequence\":%llu,\"full_rescan\":%s,"
               "\"changed_paths\":%zu,\"first_path\":",
               (unsigned long long)ctx.mutation_sequence,
               full_rescan ? "true" : "false", epoch_count);
        print_json_string(stdout, epoch_changed[0]);
        printf("}\n");
        fflush(stdout);
        zcl_devloop_process_cancel_poll_set(watch_cancel_poll, &ctx);
        bool restart_union_ok = zcl_devloop_restart_source_set_add(
            &ctx.restart_sources, files, epoch_count);
        const char *restart_files[ZCL_DEVLOOP_RESTART_SOURCE_MAX];
        const char *const *proof_files = files;
        size_t proof_count = epoch_count;
        int fast = zcl_devloop_hotfork_batch_event(
            ctx.root, files, epoch_count, publish_mode);
        if (fast == 0)
            fast = zcl_devloop_hotswap_batch_event(
                ctx.root, files, epoch_count, publish_mode);
        if (fast == 0)
            fast = service_contract_restart_event(ctx.root, files,
                                                  epoch_count);
        if (fast == 0) {
            if (restart_union_ok && watch_epoch_all_c(files, epoch_count) &&
                ctx.restart_sources.count > 0) {
                proof_count = ctx.restart_sources.count;
                for (size_t i = 0; i < proof_count; i++)
                    restart_files[i] = ctx.restart_sources.sources[i];
                proof_files = restart_files;
            }
            fast = zcl_devloop_restart_event(
                ctx.root, proof_files, proof_count, publish_mode);
        }
        /* Candidate emitters seal through their already-visible terminal
         * reflex event. Retire the watcher's matching queue entries now so a
         * save during asynchronous proof has the full bounded queue. */
        if (fast != 0 && !watch_stream_flush(&ctx)) {
            g_watch_stop = 1;
            fast = ZCL_DEVLOOP_RESTART_EVENT_FINAL;
        }
        /* A green HOT_SHADOW story is already useful foreground knowledge.
         * Only after publishing it do we build/run the exact affected proof.
         * The ordinary restart lane reaches this same state after its focused
         * receipt, so both converge here without duplicating scheduling. */
        if (fast == ZCL_DEVLOOP_RESTART_EVENT_PROOF_PENDING &&
            epoch_count == 1 &&
            strcmp(files[0],
                   "app/services/src/vault_intent_decision_service.c") == 0) {
            fast = zcl_devloop_restart_story_prove_event(
                ctx.root, files, epoch_count, publish_mode);
        }
        /* Keep the same warm owner moving through conservative complete proof
         * after focused feedback. New filesystem activity cancels this work;
         * stale epochs never anchor. */
        if (fast == ZCL_DEVLOOP_RESTART_EVENT_PROOF_PENDING ||
            fast == ZCL_DEVLOOP_RESTART_EVENT_FALLBACK_PENDING) {
            if (!watch_emit_proof_pending(&ctx, proof_files, proof_count)) {
                fprintf(stderr,
                        "[devloop] PROOF_PENDING event publication failed\n");
                g_watch_stop = 1;
            } else {
                if (!watch_proof_schedule(
                        &ctx, proof_files, proof_count,
                        ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY, lock_fd)) {
                    fprintf(stderr,
                            "[devloop] complete proof worker schedule failed\n");
                    g_watch_stop = 1;
                }
            }
            fast = ZCL_DEVLOOP_RESTART_EVENT_FINAL;
        }
        if (fast == 0) {
            /* APPLY authority is intentionally narrower than the generic
             * cycle: only one compiled-allowlist island may publish live.
             * Storage/reducers/network/consensus and ordinary reload edits
             * remain on the verify-only contained path. */
            (void)zcl_devloop_run_cycle_mode(
                ctx.root, files, epoch_count,
                ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY);
        }
        zcl_devloop_process_cancel_poll_clear();
        if (g_watch_stop || (stop && stop(stop_opaque)))
            break;
        bool superseded = ctx.changed_count > 0;
        zcl_devloop_process_cancel_clear();
        if (superseded) {
            if (!watch_emit_superseded(&ctx) || !watch_stream_flush(&ctx)) {
                fprintf(stderr,
                        "[devloop] SUPERSEDED event publication failed\n");
                break;
            }
            printf("{\"schema\":\"zcl.dev_source_epoch.v1\","
                   "\"status\":\"superseded\","
                   "\"queued_paths\":%zu,\"first_queued_path\":",
                   ctx.changed_count);
            print_json_string(stdout, ctx.changed[0]);
            printf(",\"agent_next_action\":\"wait for latest verdict\"}\n");
            fflush(stdout);
        }
    }

    watch_proof_cancel(&ctx);
    zcl_devloop_process_cancel_poll_clear();
    printf("{\"schema\":\"zcl.dev_watch_heartbeat.v1\","
           "\"status\":\"stopped\",\"pid\":%ld}\n", (long)getpid());
    close(ctx.fd);
    /* Release singleton ownership after the obsolete proof's active child
     * session has been signalled. Reaping the already-cancelled worker cannot
     * delay the next resident reactor from attaching to this checkout. */
    close(lock_fd);
    watch_proof_join(&ctx);
    ci_merkle_free(ctx.verified_tree);
    return 0;
}

int zcl_devloop_watch_mode(const char *repo_root,
                           enum zcl_devloop_publish_mode publish_mode)
{ return zcl_devloop_watch_mode_until(repo_root, publish_mode, NULL, NULL); }

int zcl_devloop_watch(const char *repo_root)
{
    return zcl_devloop_watch_mode(repo_root,
                                  zcl_devloop_default_watch_publish_mode());
}

#else

int zcl_devloop_watch_mode(const char *repo_root,
                           enum zcl_devloop_publish_mode publish_mode)
{
    (void)repo_root;
    (void)publish_mode;
    fprintf(stderr, "[devloop] watch is compiled out of release builds\n");
    return 2;
}
int zcl_devloop_watch_mode_until(const char *repo_root,
    enum zcl_devloop_publish_mode publish_mode,
    zcl_devloop_stop_predicate stop, void *opaque)
{ (void)stop; (void)opaque; return zcl_devloop_watch_mode(repo_root, publish_mode); }

int zcl_devloop_watch(const char *repo_root)
{
    return zcl_devloop_watch_mode(repo_root,
                                  zcl_devloop_default_watch_publish_mode());
}

#endif
#endif
