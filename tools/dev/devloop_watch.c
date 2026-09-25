/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#define _GNU_SOURCE
#include "devloop.h"
#include "dev_proof.h"
#include "devloop_watch_classify.h"

#include "base/safe_alloc.h"
#include "base/hex.h"
#include "base/serialize_le.h"
#include "codeindex/codeindex.h"
#include "codeindex/codeindex_merkle.h"
#include "crypto/sha3.h"
#include "hotswap/hotswap_service.h"
#include "json/json.h"
#include "platform/file_watch_compat.h"
#include "platform/directory_compat.h"
#include "platform/directory_watcher.h"
#include "platform/os_proc.h"
#include "platform/private_directory.h"
#include "platform/process_lock.h"
#include "platform/os_proc.h"
#include "platform/rng.h"
#include "platform/time_compat.h"
#include "platform/clock.h"

#if !defined(_WIN32)
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#else
#include <process.h>
#endif

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)

#if defined(_WIN32)

/* ReadDirectoryChangesW intentionally reports only that the retained tree
 * changed.  Until the backend exposes a trustworthy relative-name batch,
 * treat every notification as the conservative Makefile/full-source lane.
 * This costs more work but cannot incorrectly qualify an unsafe hot swap. */
static bool watch_windows_stop(void *opaque)
{
    struct {
        zcl_devloop_stop_predicate stop;
        void *opaque;
    } *state = opaque;
    return state && state->stop && state->stop(state->opaque);
}

int zcl_devloop_watch_mode_until(const char *repo_root,
    enum zcl_devloop_publish_mode publish_mode,
    zcl_devloop_stop_predicate stop, void *stop_opaque)
{
    char root[ZCL_DEVLOOP_PATH_MAX], cache[ZCL_DEVLOOP_PATH_MAX];
    char lock_path[ZCL_DEVLOOP_PATH_MAX];
    const char *requested = repo_root && repo_root[0] ? repo_root : ".";
    const char *mode = zcl_devloop_publish_mode_name(publish_mode);
    if (!mode || !platform_directory_canonical_real(requested, root,
                                                     sizeof(root)))
        return 2;
    int n = snprintf(cache, sizeof(cache), "%s/.cache", root);
    if (n <= 0 || (size_t)n >= sizeof(cache) ||
        !platform_private_directory_ensure(cache) ||
        !zcl_devloop_watch_lock_path(root, lock_path, sizeof(lock_path)))
        return 1;
    struct platform_process_lock lock;
    platform_process_lock_init(&lock);
    if (!platform_process_lock_try_acquire(&lock, lock_path, true))
        return 1;
    struct platform_directory_watcher watcher;
    platform_directory_watcher_init(&watcher);
    if (!platform_directory_watcher_open(&watcher, root)) {
        platform_process_lock_release(&lock);
        return 1;
    }
    struct { zcl_devloop_stop_predicate stop; void *opaque; } stop_state = {
        stop, stop_opaque};
    printf("{\"schema\":\"zcl.dev_watch_heartbeat.v1\","
           "\"status\":\"watching\",\"pid\":%ld,\"root\":\"%s\","
           "\"mode\":\"%s\",\"watch_backend\":\"ReadDirectoryChangesW\"}\n",
           (long)_getpid(), root, mode);
    fflush(stdout);
    int rc = 0;
    for (;;) {
        enum platform_directory_watch_result changed =
            platform_directory_watcher_wait(&watcher, 1000,
                stop ? watch_windows_stop : NULL, &stop_state);
        if (changed == PLATFORM_DIRECTORY_WATCH_TIMEOUT)
            continue;
        if (changed == PLATFORM_DIRECTORY_WATCH_STOPPED)
            break;
        if (changed == PLATFORM_DIRECTORY_WATCH_ERROR) {
            rc = 1;
            break;
        }
        const char *files[] = {"Makefile"};
        (void)ci_merkle_forget(root);
        if (zcl_devloop_run_cycle_mode(root, files, 1,
                                      ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY) != 0) {
            rc = 1;
            break;
        }
    }
    printf("{\"schema\":\"zcl.dev_watch_heartbeat.v1\","
           "\"status\":\"stopped\",\"pid\":%ld}\n", (long)_getpid());
    fflush(stdout);
    platform_directory_watcher_close(&watcher);
    platform_process_lock_release(&lock);
    return rc;
}

int zcl_devloop_watch_mode(const char *repo_root,
                           enum zcl_devloop_publish_mode publish_mode)
{ return zcl_devloop_watch_mode_until(repo_root, publish_mode, NULL, NULL); }

int zcl_devloop_watch(const char *repo_root)
{ return zcl_devloop_watch_mode(repo_root,
                                zcl_devloop_default_watch_publish_mode()); }

#else

#define DEVLOOP_INITIAL_WATCHES 512
#define DEVLOOP_EDIT_EPOCH_MAX_FILES 16
#if defined(__APPLE__)
/* kqueue reports a directory mutation rather than one final child pathname.
 * Give an editor's vnode burst one scheduler quantum to settle before the
 * conservative full-source epoch starts, so its rename/write pair cannot
 * supersede itself while the first impact event is still unflushed. */
#define DEVLOOP_EDIT_QUIET_US 50000
#else
#define DEVLOOP_EDIT_QUIET_US 1000
#endif
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

enum watch_proof_worker_kind {
    WATCH_PROOF_WORKER_NONE = 0,
    WATCH_PROOF_WORKER_EDIT,
    WATCH_PROOF_WORKER_COMMIT,
};

/* CPU accounting for one reflex cycle: the watcher itself, children it
 * reaped (compiler, linker, story fork, proof worker), and CFS throttling of
 * its cgroup and ancestors (Linux; zero elsewhere). */
struct watch_cpu_sample {
    int64_t self_user_us;
    int64_t self_sys_us;
    int64_t children_user_us;
    int64_t children_sys_us;
    int64_t throttled_us;
    int64_t throttled_periods;
};

/* Monotonic stage marks of one reflex cycle, from the first relevant source
 * event the watcher reads to its return to the idle wait. The cycle is
 * reported on the next IMPACT_READY because its tail (journal flush, proof
 * scheduling) runs after the story reply is already visible. */
struct watch_cycle_trace {
    char edit_epoch[65];
    int64_t idle_wait_us;
    int64_t fs_event_us;
    int64_t impact_ready_us;
    int64_t reflex_return_us;
    int64_t stream_flushed_us;
    int64_t proof_scheduled_us;
    int64_t cycle_end_us;
    struct watch_cpu_sample start;
    struct watch_cpu_sample end;
    uint32_t proof_workers_spawned;
    int64_t sealer_pid;
    uint32_t seals_deferred;
    uint32_t seals_inline;
    bool active;
    bool complete;
};

/* The watcher's one persistent journal sealer child. Producers inside the
 * watcher hand it epochs over a pipe instead of waiting on journal fsyncs.
 * The watcher keeps its own read end open so a sealer that died turns a
 * request into a full pipe (EAGAIN), never SIGPIPE. */
struct watch_sealer {
    pid_t owner;
    pid_t pid;
    int fd;
    int read_fd;
    int64_t requested;
    uint32_t deferred;
    uint32_t inline_backlog;
    uint32_t inline_down;
};

/* One exited downstream proof worker, with its own rusage from wait4. */
struct watch_proof_record {
    char edit_epoch[65];
    int64_t spawned_us;
    int64_t cancel_us;
    int64_t reaped_us;
    int64_t user_us;
    int64_t sys_us;
    int exit_code;
    int signal;
};

struct watch_context {
    int fd;
    int singleton_lock_fd;
    int stop_fd;
    bool stop_endpoint_ready;
    char stop_nonce[65];
    char stop_workspace[65];
    uint64_t stop_start_token;
#if defined(__APPLE__)
    struct platform_directory_watcher directory_watcher;
    bool watch_backend_failed;
#endif
    char root[PATH_MAX];
    struct watched_dir *dirs;
    size_t dir_count;
    size_t dir_capacity;
    char changed[ZCL_DEVLOOP_WATCH_MAX_FILES][ZCL_DEVLOOP_PATH_MAX];
    size_t changed_count;
    struct zcl_devloop_restart_source_set restart_sources;
    bool force_full_source_rescan;
    uint64_t mutation_sequence;
    int64_t first_mutation_us;
    int64_t idle_since_us;
    bool edit_seen_emitted;
    struct ci_merkle *verified_tree;
    char verified_root[65];
    char dependency_generation[65];
    char dependency_generation_kind[32];
    char parent_edit_epoch[65];
    uint64_t edit_epoch_sequence;
    bool snapshot_raced;
    bool snapshot_exact;
    struct watch_blob_state overlay[ZCL_DEVLOOP_WATCH_MAX_FILES];
    size_t overlay_count;
    struct watch_pending_event pending[4];
    size_t pending_count;
    struct watch_edit_epoch prepared_epoch;
    bool prepared_epoch_ready;
    bool prepared_full_rescan;
    pid_t proof_worker_pid;
    enum watch_proof_worker_kind proof_worker_kind;
    char proof_pending[ZCL_DEVLOOP_RESTART_SOURCE_MAX]
                      [ZCL_DEVLOOP_PATH_MAX];
    size_t proof_pending_count;
    enum zcl_devloop_publish_mode proof_pending_mode;
    bool proof_pending_story;
    char proof_worker_epoch[65];
    int64_t proof_worker_spawned_us;
    int64_t proof_worker_cancel_us;
    struct watch_proof_record proof_reaped[4];
    size_t proof_reaped_count;
    struct watch_cycle_trace trace;
    struct watch_cycle_trace trace_prior;
    int64_t trace_next_fs_event_us;
    struct watch_sealer sealer;
    /* This iteration's exact-commit verdict, established at the reactor
     * loop head and read (never recomputed) by the cancel poll. */
    bool commit_preempts;
    /* A request arriving during a synchronous edit cycle must get the loop
     * head back. This is only a wake hint; the loop head still checks the
     * exact pair, source cleanliness and ordinary proof locks. */
    char request_hint_dir[PATH_MAX];
    struct timespec request_hint_mtime;
    bool request_hint_present;
    bool request_hint_armed;
    bool request_hint_changed;
    int64_t request_hint_next_us;
};

static volatile sig_atomic_t g_watch_stop;

static int64_t watch_timeval_us(struct timeval tv)
{
    return (int64_t)tv.tv_sec * 1000000 + (int64_t)tv.tv_usec;
}

#if defined(__linux__)
#define WATCH_CGROUP_LEVELS 8

/* cgroup v2 reports CFS throttling in the cgroup whose cpu.max bound it, so
 * sum own and ancestor cpu.stat. Resolved once; forked workers inherit. */
static size_t watch_cgroup_stat_paths(char paths[][PATH_MAX], size_t cap)
{
    static const char mount[] = "/sys/fs/cgroup";
    char dir[PATH_MAX];
    if (!os_proc_cgroup_dir(dir, sizeof(dir)) ||
        strncmp(dir, mount, sizeof(mount) - 1) != 0)
        return 0;
    size_t count = 0;
    while (count < cap && strlen(dir) > sizeof(mount) - 1) {
        int n = snprintf(paths[count], PATH_MAX, "%s/cpu.stat", dir);
        count += n > 0 && n < PATH_MAX;
        *strrchr(dir, '/') = 0;
    }
    return count;
}

static int64_t watch_cpu_stat_field(const char *text, const char *key)
{
    const char *at = strstr(text, key);
    long long value = 0;
    return at && sscanf(at + strlen(key), "%lld", &value) == 1
        ? (int64_t)value : 0;
}

static void watch_cgroup_throttle(struct watch_cpu_sample *sample)
{
    static char paths[WATCH_CGROUP_LEVELS][PATH_MAX];
    static size_t count;
    static bool resolved;
    if (!resolved) {
        count = watch_cgroup_stat_paths(paths, WATCH_CGROUP_LEVELS);
        resolved = true;
    }
    for (size_t i = 0; i < count; i++) {
        char text[1024];
        FILE *f = fopen(paths[i], "re");
        size_t n = f ? fread(text, 1, sizeof(text) - 1, f) : 0;
        if (f)
            fclose(f);
        text[n] = 0;
        sample->throttled_us += watch_cpu_stat_field(text, "\nthrottled_usec ");
        sample->throttled_periods +=
            watch_cpu_stat_field(text, "\nnr_throttled ");
    }
}
#endif

static void watch_cpu_sample_take(struct watch_cpu_sample *sample)
{
    memset(sample, 0, sizeof(*sample));
    struct rusage self, children;
    if (getrusage(RUSAGE_SELF, &self) == 0) {
        sample->self_user_us = watch_timeval_us(self.ru_utime);
        sample->self_sys_us = watch_timeval_us(self.ru_stime);
    }
    if (getrusage(RUSAGE_CHILDREN, &children) == 0) {
        sample->children_user_us = watch_timeval_us(children.ru_utime);
        sample->children_sys_us = watch_timeval_us(children.ru_stime);
    }
#if defined(__linux__)
    watch_cgroup_throttle(sample);
#endif
}

static void watch_trace_start(struct watch_context *ctx, int64_t fs_event_us)
{
    int64_t idle_wait_us = ctx->trace.idle_wait_us;
    memset(&ctx->trace, 0, sizeof(ctx->trace));
    ctx->trace.idle_wait_us = idle_wait_us;
    ctx->trace.fs_event_us = fs_event_us;
    ctx->trace.active = true;
    watch_cpu_sample_take(&ctx->trace.start);
}

/* The first relevant mutation after a reset opens a cycle trace; one that
 * arrives while a cycle is still running opens the next trace at its end. */
static void watch_trace_event(struct watch_context *ctx, int64_t event_us)
{
    if (!ctx->trace.active)
        watch_trace_start(ctx, event_us);
    else if (ctx->trace_next_fs_event_us == 0)
        ctx->trace_next_fs_event_us = event_us;
}

static void watch_trace_idle(struct watch_context *ctx)
{
    if (!ctx->trace.active && ctx->trace.idle_wait_us == 0)
        ctx->trace.idle_wait_us = platform_time_monotonic_us();
}

static void watch_trace_mark(int64_t *mark)
{
    *mark = platform_time_monotonic_us();
}

static void watch_trace_end(struct watch_context *ctx)
{
    if (!ctx->trace.active)
        return;
    ctx->trace.cycle_end_us = platform_time_monotonic_us();
    ctx->trace.sealer_pid = ctx->sealer.pid;
    watch_cpu_sample_take(&ctx->trace.end);
    (void)snprintf(ctx->trace.edit_epoch, sizeof(ctx->trace.edit_epoch),
                   "%s", zcl_devloop_event_edit_epoch());
    ctx->trace.active = false;
    ctx->trace.complete = true;
    ctx->trace_prior = ctx->trace;
    int64_t next_event_us = ctx->trace_next_fs_event_us;
    memset(&ctx->trace, 0, sizeof(ctx->trace));
    ctx->trace_next_fs_event_us = 0;
    if (next_event_us > 0)
        watch_trace_start(ctx, next_event_us);
}

static void watch_proof_record_exit(struct watch_context *ctx, int status,
                                    const struct rusage *usage)
{
    if (ctx->proof_worker_kind != WATCH_PROOF_WORKER_EDIT)
        return;
    size_t cap = sizeof(ctx->proof_reaped) / sizeof(ctx->proof_reaped[0]);
    if (ctx->proof_reaped_count == cap) {
        memmove(&ctx->proof_reaped[0], &ctx->proof_reaped[1],
                (cap - 1) * sizeof(ctx->proof_reaped[0]));
        ctx->proof_reaped_count--;
    }
    struct watch_proof_record *record =
        &ctx->proof_reaped[ctx->proof_reaped_count++];
    memset(record, 0, sizeof(*record));
    (void)snprintf(record->edit_epoch, sizeof(record->edit_epoch), "%s",
                   ctx->proof_worker_epoch);
    record->spawned_us = ctx->proof_worker_spawned_us;
    record->cancel_us = ctx->proof_worker_cancel_us;
    record->reaped_us = platform_time_monotonic_us();
    record->user_us = usage ? watch_timeval_us(usage->ru_utime) : -1;
    record->sys_us = usage ? watch_timeval_us(usage->ru_stime) : -1;
    record->exit_code = usage && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    record->signal = usage && WIFSIGNALED(status) ? WTERMSIG(status) : 0;
}

static bool watch_trace_push_cpu(struct json_value *doc,
                                 const struct watch_cycle_trace *t)
{
    return json_push_kv_int(doc, "watcher_user_us",
                            t->end.self_user_us - t->start.self_user_us) &&
        json_push_kv_int(doc, "watcher_sys_us",
                         t->end.self_sys_us - t->start.self_sys_us) &&
        json_push_kv_int(doc, "children_user_us",
                         t->end.children_user_us - t->start.children_user_us) &&
        json_push_kv_int(doc, "children_sys_us",
                         t->end.children_sys_us - t->start.children_sys_us) &&
        json_push_kv_int(doc, "cgroup_throttled_us",
                         t->end.throttled_us - t->start.throttled_us) &&
        json_push_kv_int(doc, "cgroup_throttled_periods",
                         t->end.throttled_periods -
                             t->start.throttled_periods);
}

/* Which process sealed this cycle's events: the sealer (its pid lets a
 * measurement read its CPU and I/O) or the watcher itself on fallback. */
static bool watch_trace_push_seal(struct json_value *doc,
                                  const struct watch_cycle_trace *t)
{
    return json_push_kv_int(doc, "sealer_pid", t->sealer_pid) &&
        json_push_kv_int(doc, "seals_deferred", (int64_t)t->seals_deferred) &&
        json_push_kv_int(doc, "seals_inline", (int64_t)t->seals_inline);
}

static bool watch_trace_push_cycle(struct json_value *doc,
                                   const struct watch_cycle_trace *t)
{
    struct json_value cycle;
    json_init(&cycle);
    json_set_object(&cycle);
    bool ok = json_push_kv_str(&cycle, "edit_epoch", t->edit_epoch) &&
        json_push_kv_int(&cycle, "idle_wait_us", t->idle_wait_us) &&
        json_push_kv_int(&cycle, "fs_event_us", t->fs_event_us) &&
        json_push_kv_int(&cycle, "impact_ready_us", t->impact_ready_us) &&
        json_push_kv_int(&cycle, "reflex_return_us", t->reflex_return_us) &&
        json_push_kv_int(&cycle, "stream_flushed_us", t->stream_flushed_us) &&
        json_push_kv_int(&cycle, "proof_scheduled_us",
                         t->proof_scheduled_us) &&
        json_push_kv_int(&cycle, "cycle_end_us", t->cycle_end_us) &&
        json_push_kv_int(&cycle, "proof_workers_spawned",
                         (int64_t)t->proof_workers_spawned) &&
        watch_trace_push_seal(&cycle, t) &&
        watch_trace_push_cpu(&cycle, t) &&
        json_push_kv(doc, "prior_cycle", &cycle);
    json_free(&cycle);
    return ok;
}

static bool watch_trace_push_proofs(struct json_value *doc,
                                    const struct watch_context *ctx)
{
    struct json_value list;
    json_init(&list);
    json_set_array(&list);
    bool ok = true;
    for (size_t i = 0; ok && i < ctx->proof_reaped_count; i++) {
        const struct watch_proof_record *r = &ctx->proof_reaped[i];
        struct json_value item;
        json_init(&item);
        json_set_object(&item);
        ok = json_push_kv_str(&item, "edit_epoch", r->edit_epoch) &&
            json_push_kv_int(&item, "spawned_us", r->spawned_us) &&
            json_push_kv_int(&item, "cancel_us", r->cancel_us) &&
            json_push_kv_int(&item, "reaped_us", r->reaped_us) &&
            json_push_kv_int(&item, "user_us", r->user_us) &&
            json_push_kv_int(&item, "sys_us", r->sys_us) &&
            json_push_kv_int(&item, "exit_code", r->exit_code) &&
            json_push_kv_int(&item, "signal", r->signal) &&
            json_push_back(&list, &item);
        json_free(&item);
    }
    ok = ok && json_push_kv(doc, "proof_workers_reaped", &list);
    json_free(&list);
    return ok;
}

/* Attach the last completed cycle and any reaped downstream proof workers
 * to the next IMPACT_READY exactly once. */
static bool watch_trace_emit(struct watch_context *ctx,
                             struct json_value *doc, bool ok)
{
    if (!ok)
        return false;
    if (ctx->trace_prior.complete &&
        !watch_trace_push_cycle(doc, &ctx->trace_prior))
        return false;
    if (ctx->proof_reaped_count > 0 && !watch_trace_push_proofs(doc, ctx))
        return false;
    ctx->trace_prior.complete = false;
    ctx->proof_reaped_count = 0;
    return true;
}

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

/* Sealing ring events into the append-only journal costs several fsyncs per
 * batch. Producers still request it right after their event is visible, but
 * inside the watcher the request goes to one persistent sealer child, so the
 * next source event is read without waiting on storage. The sealer is forked
 * once at startup and runs until the watcher closes the request pipe. A
 * backlog near the ring's capacity, or a sealer that has exited, seals in
 * the watcher instead; the seal lock and the journal's gap refusal keep every
 * epoch sealed exactly once, in order, whoever seals it. */
#define WATCH_SEAL_BACKLOG_MAX 32

static void watch_sealer_init(struct watch_sealer *s)
{
    memset(s, 0, sizeof(*s));
    s->fd = -1;
    s->read_fd = -1;
}

static void watch_sealer_close_fds(struct watch_sealer *s)
{
    if (s->fd >= 0)
        (void)close(s->fd);
    if (s->read_fd >= 0)
        (void)close(s->read_fd);
    s->fd = -1;
    s->read_fd = -1;
}

/* Reaps a sealer that exited; from then on the watcher seals inline. */
static bool watch_sealer_alive(struct watch_sealer *s)
{
    if (s->pid <= 0)
        return false;
    int status = 0;
    pid_t got = waitpid(s->pid, &status, WNOHANG);
    if (got == 0 || (got < 0 && errno == EINTR))
        return true;
    fprintf(stderr,
            "[devloop] event journal sealer %ld exited (wait status %d); "
            "sealing in the watcher\n",
            (long)s->pid, got > 0 ? status : -1);
    s->pid = 0;
    watch_sealer_close_fds(s);
    return false;
}

/* Hands `through` to the sealer while the unsealed backlog stays well inside
 * the 64-slot ring. A full pipe also declines, so the caller seals now. */
static bool watch_sealer_request(const char *root, struct watch_sealer *s,
                                 int64_t through)
{
    int64_t latest = 0, durable = 0;
    unsigned char message[8];
    zcl_write_u64_le(message, (uint64_t)through);
    bool accepted = zcl_devloop_cycle_stream_marks(root, &latest, &durable) &&
        through - durable <= WATCH_SEAL_BACKLOG_MAX &&
        write(s->fd, message, sizeof(message)) == (ssize_t)sizeof(message);
    if (!accepted) {
        s->inline_backlog++;
        return false;
    }
    if (through > s->requested)
        s->requested = through;
    s->deferred++;
    return true;
}

static bool watch_seal_defer(void *opaque, const char *repo_root,
                             int64_t through)
{
    struct watch_context *ctx = opaque;
    struct watch_sealer *s = &ctx->sealer;
    /* A forked child inherits this hook's memory image; it seals itself, as
     * does any producer for a workspace this watcher does not own. */
    if (s->owner != getpid() || !repo_root ||
        strcmp(repo_root, ctx->root) != 0)
        return false;
    bool alive = watch_sealer_alive(s);
    if (!alive)
        s->inline_down++;
    bool deferred = alive && watch_sealer_request(ctx->root, s, through);
    if (deferred)
        ctx->trace.seals_deferred++;
    else
        ctx->trace.seals_inline++;
    return deferred;
}

static bool watch_sealer_take(const unsigned char *bytes, ssize_t n,
                              int64_t *want)
{
    if (n <= 0 || n % 8 != 0)
        return false;
    for (ssize_t at = 0; at < n; at += 8) {
        uint64_t epoch = zcl_read_u64_le(bytes + at);
        if (epoch == 0 || epoch > INT64_MAX)
            return false;
        if ((int64_t)epoch > *want)
            *want = (int64_t)epoch;
    }
    return true;
}

/* Blocks for the next request, then coalesces every request already queued
 * to the highest epoch. EOF means the watcher closed its end. */
static bool watch_sealer_collect(int fd, int64_t *want, bool *eof)
{
    unsigned char bytes[512];
    int timeout_ms = -1;
    for (;;) {
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        int ready = poll(&pfd, 1, timeout_ms);
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready <= 0)
            return ready == 0;
        ssize_t n = read(fd, bytes, sizeof(bytes));
        if (n < 0 && errno == EINTR)
            continue;
        if (n == 0) {
            *eof = true;
            return true;
        }
        if (!watch_sealer_take(bytes, n, want))
            return false;
        timeout_ms = 0;
    }
}

static int watch_sealer_loop(const char *root, int fd)
{
    bool eof = false;
    while (!eof) {
        int64_t want = 0;
        char why[160] = {0};
        if (!watch_sealer_collect(fd, &want, &eof)) {
            fprintf(stderr, "[devloop] event journal sealer request read "
                            "failed: %s\n", strerror(errno));
            return 1;
        }
        if (want > 0 && !zcl_devloop_cycle_stream_flush_through(
                            root, want, why, sizeof(why))) {
            fprintf(stderr, "[devloop] event journal sealer failed "
                            "through=%lld: %s\n",
                    (long long)want, why[0] ? why : "unknown");
            return 1;
        }
    }
    return 0;
}

/* The sealer keeps nothing the watcher owns: no source watch, no singleton
 * lock, no request write end (its EOF is the stop signal). An interactive
 * interrupt reaches the watcher, whose stop then drains this child. */
static void watch_sealer_child(struct watch_context *ctx, int watcher_lock_fd,
                               const int fds[2])
{
#if defined(__APPLE__)
    platform_directory_watcher_close(&ctx->directory_watcher);
#else
    if (ctx->fd >= 0)
        (void)close(ctx->fd);
#endif
    if (ctx->stop_endpoint_ready)
        (void)close(ctx->stop_fd);
    if (watcher_lock_fd >= 0)
        (void)close(watcher_lock_fd);
    (void)close(fds[1]);
    (void)signal(SIGINT, SIG_IGN);
    (void)signal(SIGTERM, SIG_DFL);
    zcl_devloop_cycle_stream_seal_defer(NULL, NULL);
    _exit(watch_sealer_loop(ctx->root, fds[0]));
}

static bool watch_sealer_pipe(int fds[2])
{
    if (pipe(fds) != 0)
        return false;
    int flags = fcntl(fds[1], F_GETFL);
    if (fcntl(fds[0], F_SETFD, FD_CLOEXEC) == 0 &&
        fcntl(fds[1], F_SETFD, FD_CLOEXEC) == 0 && flags >= 0 &&
        fcntl(fds[1], F_SETFL, flags | O_NONBLOCK) == 0)
        return true;
    int saved = errno;
    (void)close(fds[0]);
    (void)close(fds[1]);
    errno = saved;
    return false;
}

/* Without a sealer every seal stays synchronous in the watcher. */
static bool watch_sealer_start(struct watch_context *ctx, int watcher_lock_fd)
{
    int fds[2] = {-1, -1};
    if (!watch_sealer_pipe(fds)) {
        fprintf(stderr, "[devloop] event journal sealer pipe failed: %s; "
                        "sealing in the watcher\n", strerror(errno));
        return false;
    }
    pid_t child = fork();
    if (child == 0)
        watch_sealer_child(ctx, watcher_lock_fd, fds);
    if (child < 0) {
        fprintf(stderr, "[devloop] event journal sealer fork failed: %s; "
                        "sealing in the watcher\n", strerror(errno));
        (void)close(fds[0]);
        (void)close(fds[1]);
        return false;
    }
    ctx->sealer.owner = getpid();
    ctx->sealer.pid = child;
    ctx->sealer.read_fd = fds[0];
    ctx->sealer.fd = fds[1];
    zcl_devloop_cycle_stream_seal_defer(watch_seal_defer, ctx);
    return true;
}

/* Stop owns every published event: closing the request pipe lets the sealer
 * drain what it was handed and exit, then anything still unsealed (a failed
 * sealer's range, or an event published without a flush) is sealed here
 * before the watcher reports itself stopped. */
static void watch_sealer_join(struct watch_sealer *s)
{
    if (s->fd >= 0)
        (void)close(s->fd);
    s->fd = -1;
    if (s->pid <= 0)
        return;
    int status = 0;
    pid_t got;
    do {
        got = waitpid(s->pid, &status, 0);
    } while (got < 0 && errno == EINTR);
    if (got != s->pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        fprintf(stderr, "[devloop] event journal sealer %ld ended with wait "
                        "status %d; sealing the remainder in the watcher\n",
                (long)s->pid, got == s->pid ? status : -1);
    s->pid = 0;
}

static void watch_sealer_finish(struct watch_context *ctx)
{
    zcl_devloop_cycle_stream_seal_defer(NULL, NULL);
    watch_sealer_join(&ctx->sealer);
    watch_sealer_close_fds(&ctx->sealer);
    int64_t latest = 0, durable = 0;
    char why[160] = {0};
    if (!zcl_devloop_cycle_stream_marks(ctx->root, &latest, &durable))
        fprintf(stderr, "[devloop] event stream unavailable at stop; "
                        "nothing left to seal\n");
    else if (latest > durable && !zcl_devloop_cycle_stream_flush_through(
                                     ctx->root, latest, why, sizeof(why)))
        fprintf(stderr, "[devloop] event journal seal at stop failed "
                        "through=%lld: %s\n",
                (long long)latest, why[0] ? why : "unknown");
}

/* A forked proof worker neither keeps the request pipe nor defers: it seals
 * synchronously, and first seals what the watcher already handed to the
 * sealer, so the journal it reads is the one an inline flush gave it. */
static bool watch_sealer_detach_worker(struct watch_context *ctx)
{
    struct watch_sealer *s = &ctx->sealer;
    int64_t handed = s->pid > 0 ? s->requested : 0;
    if (s->pid > 0)
        watch_sealer_close_fds(s);
    s->pid = 0;
    s->owner = 0;
    zcl_devloop_cycle_stream_seal_defer(NULL, NULL);
    char why[160] = {0};
    if (handed <= 0 || zcl_devloop_cycle_stream_flush_through(
                           ctx->root, handed, why, sizeof(why)))
        return true;
    fprintf(stderr, "[devloop] proof worker journal catch-up failed "
                    "through=%lld: %s\n",
            (long long)handed, why[0] ? why : "unknown");
    return false;
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

/* Stop and supersede signal a worker the moment fork() returns, usually
 * before the child has run: a signal delivered there reached the inherited
 * watcher handler, and the child's own cancel reset then erased it, so the
 * obsolete proof ran to completion while the stopping reactor blocked in
 * watch_proof_join(). Hold SIGINT/SIGTERM across fork() until the child has
 * reset its cancel state and installed its own handler; a signal sent at any
 * point after fork() then cancels the worker. Returns fork()'s result. */
static pid_t watch_proof_worker_fork(struct watch_context *ctx,
                                     int watcher_lock_fd)
{
    sigset_t stop_signals, previous;
    (void)sigemptyset(&stop_signals);
    (void)sigaddset(&stop_signals, SIGINT);
    (void)sigaddset(&stop_signals, SIGTERM);
    if (pthread_sigmask(SIG_BLOCK, &stop_signals, &previous) != 0)
        return -1;
    pid_t child = fork();
    if (child == 0) {
#if defined(__APPLE__)
        platform_directory_watcher_close(&ctx->directory_watcher);
#else
        close(ctx->fd);
#endif
        if (ctx->stop_endpoint_ready) close(ctx->stop_fd);
        close(watcher_lock_fd);
        zcl_devloop_process_cancel_clear();
        zcl_devloop_process_cancel_poll_clear();
        signal(SIGINT, proof_worker_signal);
        signal(SIGTERM, proof_worker_signal);
    }
    (void)pthread_sigmask(SIG_SETMASK, &previous, NULL);
    if (child == 0 && !watch_sealer_detach_worker(ctx))
        _exit(1);
    return child;
}

static void watch_proof_reap(struct watch_context *ctx)
{
    if (!ctx || ctx->proof_worker_pid <= 1)
        return;
    int status = 0;
    struct rusage usage;
    memset(&usage, 0, sizeof(usage));
    pid_t got = wait4(ctx->proof_worker_pid, &status, WNOHANG, &usage);
    if (got == ctx->proof_worker_pid || (got < 0 && errno == ECHILD)) {
        watch_proof_record_exit(ctx, status,
                                got == ctx->proof_worker_pid ? &usage : NULL);
        ctx->proof_worker_pid = 0;
        ctx->proof_worker_kind = WATCH_PROOF_WORKER_NONE;
    }
}

static void watch_proof_cancel(struct watch_context *ctx)
{
    if (!ctx)
        return;
    ctx->proof_pending_count = 0;
    watch_proof_reap(ctx);
    if (ctx->proof_worker_pid <= 1 ||
        ctx->proof_worker_kind == WATCH_PROOF_WORKER_COMMIT)
        return;

    /* Cancellation is a priority boundary, not a best-effort notification.
     * The worker's handler immediately signals its exact active child session
     * through devloop_process. Do not wait here: this function also runs on
     * the first byte of a newer edit, whose reflex must start immediately. */
    (void)kill(ctx->proof_worker_pid, SIGTERM);
    ctx->proof_worker_cancel_us = platform_time_monotonic_us();
}

static void watch_proof_stop(struct watch_context *ctx)
{
    if (!ctx) return;
    ctx->proof_pending_count = 0;
    watch_proof_reap(ctx);
    if (ctx->proof_worker_pid > 1)
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
    if (got == worker || (got < 0 && errno == ECHILD)) {
        ctx->proof_worker_pid = 0;
        ctx->proof_worker_kind = WATCH_PROOF_WORKER_NONE;
    }
}

static bool watch_commit_request_current_clean(struct watch_context *ctx)
{
    if (!ctx || !zcl_dev_proof_queue_has_pending(ctx->root))
        return false;
    char local[65], base[65], why[160] = {0};
    struct zcl_dev_proof_status status = {0};
    if (!zcl_dev_proof_resolve_pair(ctx->root, NULL, NULL, local, base,
                                    why, sizeof(why)) ||
        !zcl_dev_proof_status_read(ctx->root, local, base, &status) ||
        status.state != ZCL_DEV_PROOF_STATE_RUNNING ||
        strcmp(status.detail, "resident_proof_request_queued") != 0)
        return false;

    const char *argv[] = {
        "git", "status", "--porcelain=v1", "--untracked-files=normal", NULL};
    struct zcl_devloop_process_result result = {0};
    return zcl_devloop_process_run(ctx->root, argv, 30000, &result) &&
        !result.timed_out && !result.output_truncated &&
        result.term_signal == 0 && result.exit_code == 0 &&
        result.output_len == 0;
}

/* An exact commit receipt subsumes the edit proof that led to the commit, but
 * only after the request names current HEAD and the submitting worktree is
 * clean enough for proof_worker() to admit it.  Drop an unstarted edit proof
 * or signal its bounded worker; never disturb an already-running commit proof
 * and never trade away feedback for newer dirty edits. */
static void watch_commit_priority_apply(struct watch_context *ctx,
                                        bool request_current_clean)
{
    if (!ctx || !request_current_clean)
        return;
    ctx->proof_pending_count = 0;
    watch_proof_reap(ctx);
    if (ctx->proof_worker_pid > 1 &&
        ctx->proof_worker_kind == WATCH_PROOF_WORKER_EDIT) {
        (void)kill(ctx->proof_worker_pid, SIGTERM);
        watch_proof_join(ctx);
    }
}

static bool watch_commit_proof_claimable(const struct watch_context *ctx)
{
    return ctx && ctx->proof_worker_pid <= 1 &&
        ctx->proof_pending_count == 0;
}

static bool watch_root_is_landing(const char *root);

/* True when the synchronous edit cycle at the bottom of the reactor must
 * yield: an exact commit-proof request is queued for current HEAD on a tree
 * clean enough for proof_worker() to admit, so the edit epoch this cycle is
 * proving is already subsumed by the commit whose proof is waiting.
 *
 * The FORKED edit worker has had this rule since watch_commit_priority_apply().
 * The foreground cycle did not, and it is the one that holds the reactor:
 * while it runs, the loop head that reaps a deferred queue worker and starts
 * the commit proof is not reached at all. A landing worktree's own
 * preparation writes enough files to schedule exactly such a cycle, so a
 * queued landing proof waited behind work that could no longer matter.
 *
 * The verdict is established HERE, at the loop head, and nowhere else. The
 * probe opens the request directory, reads its files and runs bounded git
 * children; the cancel poll may do none of that, because the process runner
 * invokes a poll while holding its own non-recursive cancel-poll mutex
 * (devloop_process.c) — a poll that ran a child would re-enter that mutex and
 * wedge the watcher for good, which is permanently worse than the scheduling
 * delay this rule removes. The loop head is also the only place that can act
 * on the answer, so establishing it once per iteration loses nothing. */
static bool watch_commit_proof_prioritize(struct watch_context *ctx)
{
    bool request_current_clean = watch_commit_request_current_clean(ctx);
    watch_commit_priority_apply(ctx, request_current_clean);
    if (ctx) {
        ctx->commit_preempts = request_current_clean;
        ctx->request_hint_armed = false;
        ctx->request_hint_changed = false;
    }
    return request_current_clean;
}

/* Arm only on a clean landing tree. A request-directory mtime is cheap to
 * observe from the process cancel poll and carries no proof authority. The
 * later loop-head predicate remains the sole admission decision. */
static void watch_request_hint_arm(struct watch_context *ctx)
{
    const char *argv[] = {
        "git", "status", "--porcelain=v1", "--untracked-files=normal", NULL};
    struct zcl_devloop_process_result result = {0};
    struct stat st;
    int n;
    if (!ctx)
        return;
    ctx->request_hint_armed = false;
    ctx->request_hint_changed = false;
    if (!watch_root_is_landing(ctx->root))
        return;
    n = snprintf(ctx->request_hint_dir, sizeof(ctx->request_hint_dir),
                 "%s/.cache/zcl-dev-proof/requests", ctx->root);
    if (n <= 0 || (size_t)n >= sizeof(ctx->request_hint_dir) ||
        !zcl_devloop_process_run(ctx->root, argv, 30000, &result) ||
        result.timed_out || result.output_truncated || result.term_signal != 0 ||
        result.exit_code != 0 || result.output_len != 0)
        return;
    ctx->request_hint_present = stat(ctx->request_hint_dir, &st) == 0 &&
                                S_ISDIR(st.st_mode);
    if (ctx->request_hint_present)
        ctx->request_hint_mtime = st.st_mtim;
    ctx->request_hint_next_us = 0;
    ctx->request_hint_armed = true;
    /* Close the gap between the loop-head decision and arming this hint.
     * This full predicate runs before the cancel poll is installed. */
    if (zcl_dev_proof_queue_has_pending(ctx->root) &&
        watch_commit_request_current_clean(ctx))
        ctx->request_hint_changed = true;
}

static bool watch_request_hint_poll(struct watch_context *ctx)
{
    struct stat st;
    int64_t now;
    bool present;
    if (!ctx || !ctx->request_hint_armed)
        return false;
    if (ctx->request_hint_changed)
        return true;
    now = platform_time_monotonic_us();
    if (now < ctx->request_hint_next_us)
        return false;
    ctx->request_hint_next_us = now + 50000;
    present = stat(ctx->request_hint_dir, &st) == 0 && S_ISDIR(st.st_mode);
    if (present != ctx->request_hint_present ||
        (present &&
         (st.st_mtim.tv_sec != ctx->request_hint_mtime.tv_sec ||
          st.st_mtim.tv_nsec != ctx->request_hint_mtime.tv_nsec)))
        ctx->request_hint_changed = true;
    return ctx->request_hint_changed;
}

/* The foreground cycle yields for newer source events, an exact commit seen
 * at the loop head, or a request-directory change observed by stat(2). The
 * hint never parses a request or admits proof; the next loop head does that.
 * The cancel poll runs under the process runner's non-recursive mutex, so it
 * may not launch a child or run the full request predicate there. */
static bool watch_cycle_should_yield(const struct watch_context *ctx,
                                     bool changed)
{
    return changed || (ctx && (ctx->commit_preempts ||
                               ctx->request_hint_changed));
}

static bool mkdirs(const char *path);

/* A landing worktree is <state_root>/land/wt; queue.lock lives in
 * <state_root>/land, one segment above the watched root. Presence of that
 * sibling lock is the exact land-state signal — not a "wt" name guess. */
static bool watch_root_is_landing(const char *root)
{
    char lock_path[PATH_MAX];
    int n;

    if (!root || !root[0])
        return false;
    n = snprintf(lock_path, sizeof(lock_path), "%s/../queue.lock", root);
    if (n <= 0 || (size_t)n >= sizeof(lock_path))
        return true;
    return access(lock_path, F_OK) == 0;
}

static void watch_idle_touch(struct watch_context *ctx)
{
    if (!ctx)
        return;
    ctx->idle_since_us = platform_time_monotonic_us();
}

/* True only when the idle wait observed no source work, no queued proof, no
 * in-flight proof worker, and a non-landing root past the idle budget. */
static bool watch_idle_poll_should_exit(struct watch_context *ctx)
{
    if (!ctx)
        return false;
    if (zcl_dev_proof_queue_has_pending(ctx->root) ||
        ctx->proof_worker_pid > 1) {
        watch_idle_touch(ctx);
        return false;
    }
    if (watch_root_is_landing(ctx->root))
        return false;
    return platform_time_monotonic_us() - ctx->idle_since_us >=
        (int64_t)ZCL_DEVLOOP_WATCH_IDLE_BUDGET_MS * 1000;
}

static bool watch_stopped_heartbeat_line(char *buf, size_t len, bool idle_exit)
{
    int n;

    if (!buf || len == 0) {
        fprintf(stderr,
                "[devloop] watch: stopped heartbeat buffer missing\n");
        return false;
    }
    if (idle_exit)
        n = snprintf(buf, len,
                     "{\"schema\":\"zcl.dev_watch_heartbeat.v1\","
                     "\"status\":\"stopped\",\"pid\":%ld,"
                     "\"reason\":\"idle_exit\"}\n",
                     (long)getpid());
    else
        n = snprintf(buf, len,
                     "{\"schema\":\"zcl.dev_watch_heartbeat.v1\","
                     "\"status\":\"stopped\",\"pid\":%ld}\n",
                     (long)getpid());
    if (n < 0 || (size_t)n >= len) {
        fprintf(stderr,
                "[devloop] watch: stopped heartbeat could not be formatted\n");
        return false;
    }
    return true;
}

static void watch_emit_stopped_heartbeat(bool idle_exit)
{
    char line[192];

    if (!watch_stopped_heartbeat_line(line, sizeof(line), idle_exit))
        return;
    fputs(line, stdout);
}

#if defined(ZCL_TESTING)
bool zcl_devloop_watch_commit_preemption_selftest(void)
{
    struct watch_context ctx = {0};
    ctx.proof_pending_count = 1;
    pid_t edit = fork();
    if (edit < 0)
        return false;
    if (edit == 0) {
        signal(SIGTERM, SIG_DFL);
        for (;;) pause();
    }
    ctx.proof_worker_pid = edit;
    ctx.proof_worker_kind = WATCH_PROOF_WORKER_EDIT;
    watch_commit_priority_apply(&ctx, true);
    bool edit_retired = ctx.proof_pending_count == 0 &&
        ctx.proof_worker_pid == 0 &&
        ctx.proof_worker_kind == WATCH_PROOF_WORKER_NONE &&
        watch_commit_proof_claimable(&ctx);

    ctx.proof_pending_count = 1;
    pid_t commit = fork();
    if (commit < 0)
        return false;
    if (commit == 0) {
        signal(SIGTERM, SIG_DFL);
        for (;;) pause();
    }
    ctx.proof_worker_pid = commit;
    ctx.proof_worker_kind = WATCH_PROOF_WORKER_COMMIT;
    watch_commit_priority_apply(&ctx, true);
    bool commit_preserved = kill(commit, 0) == 0 &&
        ctx.proof_worker_pid == commit &&
        ctx.proof_worker_kind == WATCH_PROOF_WORKER_COMMIT;
    (void)kill(commit, SIGTERM);
    watch_proof_join(&ctx);

    ctx.proof_pending_count = 1;
    pid_t dirty_edit = fork();
    if (dirty_edit < 0)
        return false;
    if (dirty_edit == 0) {
        signal(SIGTERM, SIG_DFL);
        for (;;) pause();
    }
    ctx.proof_worker_pid = dirty_edit;
    ctx.proof_worker_kind = WATCH_PROOF_WORKER_EDIT;
    watch_commit_priority_apply(&ctx, false);
    bool dirty_preserved = kill(dirty_edit, 0) == 0 &&
        ctx.proof_pending_count == 1 &&
        ctx.proof_worker_pid == dirty_edit &&
        ctx.proof_worker_kind == WATCH_PROOF_WORKER_EDIT;
    (void)kill(dirty_edit, SIGTERM);
    watch_proof_join(&ctx);
    return edit_retired && commit_preserved && dirty_preserved;
}

bool zcl_devloop_watch_root_is_landing(const char *root)
{
    return watch_root_is_landing(root);
}

struct watch_idle_clock {
    int64_t mono_us;
};

static int64_t watch_idle_clock_mono_ns(void *self)
{
    struct watch_idle_clock *clock = self;
    return clock ? clock->mono_us * 1000 : 0;
}

static int64_t watch_idle_clock_wall_ms(void *self)
{
    (void)self;
    return 0;
}

static bool watch_idle_selftest_write_request(const char *root)
{
    char dir[PATH_MAX], path[PATH_MAX];
    int n;
    int fd;
    ssize_t wrote;
    static const char body[] =
        "zcl.dev_proof_request.v1\n"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "1111111111111111111111111111111111111111\n"
        "1\n"
        "1\n";

    if (!root)
        return false;
    n = snprintf(dir, sizeof(dir), "%s/.cache/zcl-dev-proof/requests", root);
    if (n <= 0 || (size_t)n >= sizeof(dir) || !mkdirs(dir))
        return false;
    n = snprintf(path, sizeof(path),
                 "%s/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-"
                 "1111111111111111111111111111111111111111.request",
                 dir);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return false;
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return false;
    wrote = write(fd, body, sizeof(body) - 1);
    if (close(fd) != 0 || wrote != (ssize_t)(sizeof(body) - 1))
        return false;
    return zcl_dev_proof_queue_has_pending(root);
}

static void watch_idle_selftest_clear_request(const char *root)
{
    char path[PATH_MAX];
    int n;

    if (!root)
        return;
    n = snprintf(path, sizeof(path),
                 "%s/.cache/zcl-dev-proof/requests/"
                 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-"
                 "1111111111111111111111111111111111111111.request",
                 root);
    if (n > 0 && (size_t)n < sizeof(path))
        (void)unlink(path);
}

bool zcl_devloop_watch_idle_exit_selftest(void)
{
    struct watch_idle_clock clock = { .mono_us = 1000 };
    const clock_iface_t iface = {
        .now_monotonic_ns = watch_idle_clock_mono_ns,
        .now_wall_ms = watch_idle_clock_wall_ms,
        .self = &clock,
    };
    const int64_t budget_us = (int64_t)ZCL_DEVLOOP_WATCH_IDLE_BUDGET_MS * 1000;
    char base[PATH_MAX], plain[PATH_MAX], land_parent[PATH_MAX],
        land_wt[PATH_MAX], queue_lock[PATH_MAX];
    char heartbeat[192];
    struct watch_context ctx = {0};
    bool ok = true;
    int n;
    int lock_fd;

    n = snprintf(base, sizeof(base), "test-tmp/devloop_idle_%ld",
                 (long)getpid());
    if (n <= 0 || (size_t)n >= sizeof(base))
        return false;
    n = snprintf(plain, sizeof(plain), "%s/plain", base);
    if (n <= 0 || (size_t)n >= sizeof(plain))
        return false;
    n = snprintf(land_parent, sizeof(land_parent), "%s/land", base);
    if (n <= 0 || (size_t)n >= sizeof(land_parent))
        return false;
    n = snprintf(land_wt, sizeof(land_wt), "%s/wt", land_parent);
    if (n <= 0 || (size_t)n >= sizeof(land_wt))
        return false;
    n = snprintf(queue_lock, sizeof(queue_lock), "%s/queue.lock", land_parent);
    if (n <= 0 || (size_t)n >= sizeof(queue_lock))
        return false;
    if (!mkdirs(plain) || !mkdirs(land_wt))
        return false;
    lock_fd = open(queue_lock, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (lock_fd < 0)
        return false;
    if (close(lock_fd) != 0)
        return false;
    if (!realpath(plain, ctx.root))
        return false;

    clock_set_default(&iface);

    if (!watch_root_is_landing(land_wt) || watch_root_is_landing(plain) ||
        watch_root_is_landing(ctx.root) || watch_root_is_landing(NULL) ||
        watch_root_is_landing(""))
        ok = false;

    ctx.idle_since_us = platform_time_monotonic_us();
    ctx.proof_worker_pid = 0;
    clock.mono_us = 1000 + budget_us;
    if (!watch_idle_poll_should_exit(&ctx))
        ok = false;
    if (!watch_stopped_heartbeat_line(heartbeat, sizeof(heartbeat), true) ||
        !strstr(heartbeat, "\"schema\":\"zcl.dev_watch_heartbeat.v1\"") ||
        !strstr(heartbeat, "\"status\":\"stopped\"") ||
        !strstr(heartbeat, "\"reason\":\"idle_exit\""))
        ok = false;

    clock.mono_us = 1000;
    ctx.idle_since_us = platform_time_monotonic_us();
    clock.mono_us = 1000 + budget_us / 2;
    watch_idle_touch(&ctx);
    clock.mono_us = 1000 + budget_us;
    if (watch_idle_poll_should_exit(&ctx))
        ok = false;

    clock.mono_us = 1000;
    ctx.idle_since_us = platform_time_monotonic_us();
    clock.mono_us = 1000 + budget_us / 2;
    if (!watch_idle_selftest_write_request(ctx.root) ||
        !zcl_dev_proof_queue_has_pending(ctx.root) ||
        watch_idle_poll_should_exit(&ctx))
        ok = false;
    watch_idle_selftest_clear_request(ctx.root);
    clock.mono_us = 1000 + budget_us;
    if (zcl_dev_proof_queue_has_pending(ctx.root) ||
        watch_idle_poll_should_exit(&ctx))
        ok = false;

    clock.mono_us = 1000;
    ctx.idle_since_us = platform_time_monotonic_us();
    ctx.proof_worker_pid = 2;
    clock.mono_us = 1000 + budget_us;
    if (watch_idle_poll_should_exit(&ctx))
        ok = false;
    ctx.proof_worker_pid = 0;

    if (!realpath(land_wt, ctx.root))
        ok = false;
    clock.mono_us = 1000;
    ctx.idle_since_us = platform_time_monotonic_us();
    clock.mono_us = 1000 + budget_us * 2;
    if (!watch_root_is_landing(ctx.root) ||
        watch_idle_poll_should_exit(&ctx))
        ok = false;

    clock_reset_default();
    watch_idle_selftest_clear_request(plain);
    (void)unlink(queue_lock);
    return ok;
}

/* One bounded git command in `root`, succeeding only on a clean exit. */
static bool watch_fg_git(const char *root, const char *const *argv,
                         char *out, size_t out_cap)
{
    struct zcl_devloop_process_result result = {0};
    if (out && out_cap)
        out[0] = '\0';
    if (!zcl_devloop_process_run(root, argv, 60000, &result) ||
        result.timed_out || result.term_signal != 0 || result.exit_code != 0 ||
        result.output_truncated)
        return false;
    if (out && out_cap) {
        size_t len = result.output_len;
        while (len > 0 && (result.output[len - 1] == '\n' ||
                           result.output[len - 1] == '\r'))
            len--;
        if (len >= out_cap)
            return false;
        memcpy(out, result.output, len);
        out[len] = '\0';
    }
    return true;
}

static bool watch_fg_write(const char *root, const char *rel,
                           const char *body)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", root, rel);
    ssize_t wrote;
    int fd;
    if (n <= 0 || (size_t)n >= sizeof(path))
        return false;
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return false;
    wrote = write(fd, body, strlen(body));
    return close(fd) == 0 && wrote == (ssize_t)strlen(body);
}

/* A repository with one commit, an origin/main ref on it, and the proof
 * cache ignored so a queued request never dirties the tree. */
static const char *watch_fg_repo(const char *root, char head[65])
{
    const char *init[] = {"git", "init", "--quiet", "--initial-branch=main",
                          ".", NULL};
    const char *add[] = {"git", "add", "-A", NULL};
    const char *commit[] = {"git", "-c", "user.name=watch", "-c",
                            "user.email=watch@z23.invalid", "commit",
                            "--quiet", "--no-verify", "--no-gpg-sign", "-m",
                            "seed", NULL};
    const char *rev[] = {"git", "rev-parse", "HEAD", NULL};
    char ref[65];
    if (!watch_fg_git(root, init, NULL, 0))
        return "git init";
    if (!watch_fg_write(root, ".gitignore", ".cache/\n") ||
        !watch_fg_write(root, "seed.c", "int seed(void){return 0;}\n"))
        return "seed files";
    if (!watch_fg_git(root, add, NULL, 0))
        return "git add";
    if (!watch_fg_git(root, commit, NULL, 0))
        return "git commit";
    if (!watch_fg_git(root, rev, head, 65) || strlen(head) != 40)
        return "git rev-parse";
    (void)snprintf(ref, sizeof(ref), "%s", head);
    {
        const char *update[] = {"git", "update-ref",
                                "refs/remotes/origin/main", ref, NULL};
        if (!watch_fg_git(root, update, NULL, 0))
            return "git update-ref";
    }
    return NULL;
}

/* The queued exact request the landing step leaves behind for the resident
 * watcher: same shape proof_request_read() parses. */
static bool watch_fg_request(const char *root, const char *pair)
{
    char dir[PATH_MAX], path[PATH_MAX], body[320], rel[PATH_MAX];
    int n = snprintf(dir, sizeof(dir), "%s/.cache/zcl-dev-proof/requests",
                     root);
    if (n <= 0 || (size_t)n >= sizeof(dir) || !mkdirs(dir))
        return false;
    n = snprintf(path, sizeof(path), "%s/%s-%s.request", dir, pair, pair);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return false;
    n = snprintf(body, sizeof(body),
                 "zcl.dev_proof_request.v1\n%s\n%s\n1\n1\n", pair, pair);
    if (n <= 0 || (size_t)n >= (int)sizeof(body))
        return false;
    n = snprintf(rel, sizeof(rel), ".cache/zcl-dev-proof/requests/%s-%s.request",
                 pair, pair);
    if (n <= 0 || (size_t)n >= (int)sizeof(rel))
        return false;
    return watch_fg_write(root, rel, body) &&
           zcl_dev_proof_queue_has_pending(root);
}

/* The poll the reactor actually installs. Declared here so the seam phase
 * below can install the real one rather than a stand-in. */
static bool watch_cancel_poll(void *opaque);

/* With an exact request queued for current HEAD on a clean tree, the loop
 * head establishes the verdict and the cycle yields on it. */
static const char *watch_fg_queued_phase(struct watch_context *ctx,
                                         const char *head)
{
    if (!watch_fg_request(ctx->root, head))
        return "queued request fixture";
    if (!watch_commit_proof_prioritize(ctx) || !ctx->commit_preempts)
        return "the loop head must see a runnable exact commit";
    if (!watch_cycle_should_yield(ctx, false))
        return "a runnable exact commit must cancel the cycle";
    return NULL;
}

/* Exercise the real bounded process poll while the request arrives after
 * the loop-head verdict. The disabled run is the old behavior on the same
 * fixture: the child times out before the watcher gets back to the queue. */
static bool watch_fg_midcycle_prepare(struct watch_context *ctx,
                                      const char *head, bool hint)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path),
                     "%s/.cache/zcl-dev-proof/requests/%s-%s.request",
                     ctx->root, head, head);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return false;
    (void)unlink(path);
    watch_request_hint_arm(ctx);
    if (!ctx->request_hint_armed)
        return false;
    if (!hint)
        ctx->request_hint_armed = false;
    return true;
}

static const char *watch_fg_midcycle_result(bool ran, bool hint,
                                            const struct zcl_devloop_process_result *result)
{
    if (!ran || (hint && (!result->cancelled || result->timed_out)) ||
        (!hint && (!result->timed_out || result->cancelled)))
        return hint ? "new request must cancel the obsolete cycle"
                    : "old cycle must time out before seeing the request";
    return NULL;
}

static const char *watch_fg_midcycle_once(struct watch_context *ctx,
                                          const char *head, bool hint,
                                          int64_t *elapsed_us)
{
    const char *argv[] = {"sleep", "30", NULL};
    struct zcl_devloop_process_result result = {0};
    int status = 0, saved_fd = ctx->fd;
    if (!watch_fg_midcycle_prepare(ctx, head, hint))
        return "clean landing hint arm";
    pid_t writer = fork();
    if (writer < 0)
        return "request writer fork";
    if (writer == 0) {
        platform_sleep_ms(100);
        _exit(watch_fg_request(ctx->root, head) ? 0 : 1);
    }
    ctx->fd = -1;
    zcl_devloop_process_cancel_poll_set(watch_cancel_poll, ctx);
    int64_t start = platform_time_monotonic_us();
    bool ran = zcl_devloop_process_run(ctx->root, argv, 1500, &result);
    *elapsed_us = platform_time_monotonic_us() - start;
    zcl_devloop_process_cancel_poll_clear();
    zcl_devloop_process_cancel_clear();
    ctx->fd = saved_fd;
    if (waitpid(writer, &status, 0) != writer || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0)
        return "request writer";
    return watch_fg_midcycle_result(ran, hint, &result);
}

static const char *watch_fg_midcycle_phase(struct watch_context *ctx,
                                           const char *head)
{
    char parent[PATH_MAX], dir[PATH_MAX];
    int64_t before_us = 0, after_us = 0;
    int n = snprintf(parent, sizeof(parent), "%s/..", ctx->root);
    if (n <= 0 || (size_t)n >= sizeof(parent) ||
        !watch_fg_write(parent, "queue.lock", ""))
        return "landing marker";
    n = snprintf(dir, sizeof(dir), "%s/.cache/zcl-dev-proof/requests",
                 ctx->root);
    if (n <= 0 || (size_t)n >= sizeof(dir) || !mkdirs(dir))
        return "request directory";
    const char *failed = watch_fg_midcycle_once(ctx, head, false, &before_us);
    if (!failed)
        failed = watch_fg_midcycle_once(ctx, head, true, &after_us);
    if (!failed && (after_us >= before_us || after_us > 1200000))
        failed = "request hint did not shorten the same cycle";
    fprintf(stderr,
            "[devloop] midcycle request: before=%lld ms after=%lld ms\n",
            (long long)(before_us / 1000), (long long)(after_us / 1000));
    return failed;
}

/* A dirty checkout keeps its edit feedback: the queued proof could not be
 * admitted there, so cancelling would trade feedback for nothing. */
static const char *watch_fg_dirty_phase(struct watch_context *ctx)
{
    if (!watch_fg_write(ctx->root, "dirty.c",
                        "int dirty(void){return 1;}\n"))
        return "dirty fixture";
    if (watch_commit_proof_prioritize(ctx) || ctx->commit_preempts)
        return "a dirty checkout must clear the verdict";
    if (watch_cycle_should_yield(ctx, false))
        return "a dirty checkout must keep its edit feedback";
    return NULL;
}

/* THE SEAM. zcl_devloop_process_run() calls the installed poll while it holds
 * its own non-recursive cancel-poll mutex, so a poll that opened a directory,
 * read a file or ran a child would re-enter that mutex and never return. This
 * phase installs the real watch_cancel_poll through the real seam with the
 * verdict already set and runs one bounded child: a poll that probes hangs
 * here instead of answering, and the group's timeout reports it. ctx->fd is
 * -1 and the Darwin directory watcher stays at its closed sentinel, so
 * collect_events() observes no source events without touching a real
 * descriptor. */
static const char *watch_fg_seam_phase(struct watch_context *ctx)
{
    /* Long enough that the runner is guaranteed to poll before the child
     * would exit on its own, so the assertion below is about the poll and
     * not about a race the child happened to win. */
    const char *argv[] = {"sleep", "30", NULL};
    struct zcl_devloop_process_result result = {0};
    int saved_fd = ctx->fd;
    bool ran;
    ctx->fd = -1;
    ctx->commit_preempts = true;
    zcl_devloop_process_cancel_poll_set(watch_cancel_poll, ctx);
    ran = zcl_devloop_process_run(ctx->root, argv, 10000, &result);
    zcl_devloop_process_cancel_poll_clear();
    /* The cancellation this phase asked for is process-wide state; leaving it
     * set would cancel the next unrelated bounded child in this binary. */
    zcl_devloop_process_cancel_clear();
    ctx->fd = saved_fd;
    ctx->commit_preempts = false;
    if (!ran || !result.cancelled || result.timed_out)
        return "the installed poll must cancel the bounded child";
    return NULL;
}

bool zcl_devloop_watch_foreground_yield_selftest(const char *repo_root)
{
    /* No injected clock here: the seam phase runs a real bounded child, and
     * a frozen monotonic clock would stop the runner's own timeout from ever
     * expiring. Nothing this selftest asserts is time dependent. */
    struct watch_context ctx = {0};
    char head[65] = {0};
#if defined(__APPLE__)
    /* The zeroed watcher is not the closed sentinel; collect_events() reads
     * it through the real seam phase below. Give the context the same init
     * the production watch entry point performs. */
    platform_directory_watcher_init(&ctx.directory_watcher);
#endif
    const char *failed = NULL;

    if (!repo_root || !realpath(repo_root, ctx.root))
        failed = "fixture path";
    else
        failed = watch_fg_repo(ctx.root, head);
    if (failed) {
        fprintf(stderr, "[devloop] foreground-yield selftest: %s\n", failed);
        return false;
    }

    /* Nothing is queued: the loop head establishes no verdict and the cycle
     * runs. */
    if (watch_commit_proof_prioritize(&ctx) || ctx.commit_preempts ||
        watch_cycle_should_yield(&ctx, false))
        failed = "an empty queue must not cancel the cycle";
    /* A newer edit still cancels, whatever the verdict says. */
    else if (!watch_cycle_should_yield(&ctx, true))
        failed = "a newer edit must cancel the cycle";
    /* THE PROPERTY: a queued exact commit proof for current HEAD on a clean
     * tree cancels the obsolete foreground cycle, so the reactor reaches the
     * loop head that starts it. */
    else
        failed = watch_fg_midcycle_phase(&ctx, head);
    if (!failed)
        failed = watch_fg_queued_phase(&ctx, head);
    if (!failed)
        failed = watch_fg_dirty_phase(&ctx);
    if (!failed)
        failed = watch_fg_seam_phase(&ctx);
    if (failed)
        fprintf(stderr, "[devloop] foreground-yield selftest: %s\n", failed);
    return failed == NULL;
}
#endif

#if defined(ZCL_TESTING)
static int watch_test_edit_ready = -1;
static int watch_test_edit_release = -1;
#endif

static int watch_edit_cycle(struct watch_context *ctx)
{
#if defined(ZCL_TESTING)
    if (watch_test_edit_ready >= 0) {
        char release = 0;
        bool ok = write(watch_test_edit_ready, "r", 1) == 1 &&
                  read(watch_test_edit_release, &release, 1) == 1;
        /* Report whether a stop signal reached this worker's cancel state. */
        const char *cancel = zcl_devloop_process_cancel_requested() ? "c" : "n";
        return ok && write(watch_test_edit_ready, cancel, 1) == 1 ? 0 : 1;
    }
#endif
    const char *files[ZCL_DEVLOOP_RESTART_SOURCE_MAX];
    for (size_t i = 0; i < ctx->proof_pending_count; i++)
        files[i] = ctx->proof_pending[i];
    if (ctx->proof_pending_story) {
        int ready = zcl_devloop_restart_story_prove_event(
            ctx->root, files, ctx->proof_pending_count,
            ctx->proof_pending_mode);
        if (ready != ZCL_DEVLOOP_RESTART_EVENT_PROOF_PENDING &&
            ready != ZCL_DEVLOOP_RESTART_EVENT_FALLBACK_PENDING)
            return ready == ZCL_DEVLOOP_RESTART_EVENT_FINAL ? 0 : 1;
    }
    return zcl_devloop_run_cycle_mode(ctx->root, files, ctx->proof_pending_count,
                                      ctx->proof_pending_mode);
}

static bool watch_proof_start(struct watch_context *ctx, int watcher_lock_fd)
{
    if (!ctx)
        return false;
    watch_proof_reap(ctx);
    /* A stop that arrived during the reflex (for example while the journal
     * flush waited on storage) must not be answered by forking the proof it
     * is about to cancel. */
    if (g_watch_stop || ctx->proof_worker_pid > 1 ||
        ctx->proof_pending_count == 0)
        return true;
    int execution = -1;
    char why[160] = {0};
    int ready = zcl_dev_proof_execution_acquire(ctx->root, &execution,
                                                why, sizeof(why));
    if (ready <= 0) return ready == 0;
    pid_t child = watch_proof_worker_fork(ctx, watcher_lock_fd);
    if (child < 0) {
        zcl_dev_proof_execution_release(execution);
        return false;
    }
    if (child == 0) {
        int rc = watch_edit_cycle(ctx);
        zcl_dev_proof_execution_release(execution);
        _exit(rc == 0 ? 0 : 1);
    }
    /* The child owns the inherited open description until cycle cleanup. */
    (void)close(execution);
    ctx->proof_worker_pid = child;
    ctx->proof_worker_kind = WATCH_PROOF_WORKER_EDIT;
    ctx->proof_worker_spawned_us = platform_time_monotonic_us();
    ctx->proof_worker_cancel_us = 0;
    (void)snprintf(ctx->proof_worker_epoch, sizeof(ctx->proof_worker_epoch),
                   "%s", zcl_devloop_event_edit_epoch());
    ctx->trace.proof_workers_spawned++;
    ctx->proof_pending_count = 0;
    ctx->proof_pending_story = false;
    return true;
}

#if defined(ZCL_TESTING)
bool zcl_dev_proof_test_edit_busy(const char *root)
{
    struct watch_context ctx = {0};
#if defined(__APPLE__)
    /* The forked proof child closes the inherited watcher; a zeroed native
     * handle is not the closed sentinel and crashes that close. */
    platform_directory_watcher_init(&ctx.directory_watcher);
#endif
    if (!root || snprintf(ctx.root, sizeof(ctx.root), "%s", root) >=
                     (int)sizeof(ctx.root)) return false;
    ctx.proof_pending_count = 1;
    return watch_proof_start(&ctx, -1) && ctx.proof_pending_count == 1 &&
           ctx.proof_worker_pid == 0;
}

static bool watch_test_edit_observe(const char *root, pid_t child,
                                      int ready, int release)
{
    struct pollfd channel = {.fd = ready, .events = POLLIN};
    bool observed = poll(&channel, 1, 5000) == 1;
    int guard = -1;
    char why[160] = {0};
    int held = zcl_dev_proof_execution_acquire(root, &guard, why, sizeof(why));
    if (held > 0) zcl_dev_proof_execution_release(guard);
    bool released = write(release, "r", 1) == 1;
    int status = 0;
    bool settled = waitpid(child, &status, 0) == child;
    int after = zcl_dev_proof_execution_acquire(root, &guard, why, sizeof(why));
    if (after > 0) zcl_dev_proof_execution_release(guard);
    return observed && held == 0 && released && settled &&
           WIFEXITED(status) && WEXITSTATUS(status) == 0 && after == 1;
}

bool zcl_dev_proof_test_edit_lifetime(const char *root)
{
    struct watch_context ctx = {.fd = -1};
#if defined(__APPLE__)
    platform_directory_watcher_init(&ctx.directory_watcher);
#endif
    if (!root || snprintf(ctx.root, sizeof(ctx.root), "%s", root) >=
                     (int)sizeof(ctx.root)) return false;
    int ready[2], release[2];
    if (pipe(ready) != 0) return false;
    if (pipe(release) != 0) {
        (void)close(ready[0]);
        (void)close(ready[1]);
        return false;
    }
    watch_test_edit_ready = ready[1];
    watch_test_edit_release = release[0];
    ctx.proof_pending_count = 1;
    bool started = watch_proof_start(&ctx, -1);
    watch_test_edit_ready = watch_test_edit_release = -1;
    bool ok = started && ctx.proof_worker_pid > 1 && ctx.proof_pending_count == 0;
    if (ok) ok = watch_test_edit_observe(root, ctx.proof_worker_pid, ready[0], release[1]);
    (void)close(ready[0]);
    (void)close(ready[1]);
    (void)close(release[0]);
    (void)close(release[1]);
    return ok;
}

/* One round of the stop race: start a worker under the watcher's own SIGTERM
 * handler, signal it the instant fork() returns exactly as watch_proof_stop()
 * does, and require the worker to report that the cancel reached it. */
static bool watch_test_edit_stop_round(struct watch_context *ctx)
{
    int ready[2], release[2];
    if (pipe(ready) != 0) return false;
    if (pipe(release) != 0) {
        (void)close(ready[0]);
        (void)close(ready[1]);
        return false;
    }
    watch_test_edit_ready = ready[1];
    watch_test_edit_release = release[0];
    ctx->proof_pending_count = 1;
    bool ok = watch_proof_start(ctx, -1) && ctx->proof_worker_pid > 1;
    watch_test_edit_ready = watch_test_edit_release = -1;
    if (ok) {
        watch_proof_stop(ctx);
        struct pollfd channel = {.fd = ready[0], .events = POLLIN};
        char first = 0, cancel = 0;
        bool observed = poll(&channel, 1, 5000) == 1 &&
                        read(ready[0], &first, 1) == 1;
        bool released = write(release[1], "r", 1) == 1;
        bool reported = poll(&channel, 1, 5000) == 1 &&
                        read(ready[0], &cancel, 1) == 1;
        watch_proof_join(ctx);
        ok = observed && released && reported && cancel == 'c' &&
             ctx->proof_worker_pid == 0;
    }
    (void)close(ready[0]);
    (void)close(ready[1]);
    (void)close(release[0]);
    (void)close(release[1]);
    return ok;
}

bool zcl_dev_proof_test_edit_stop_cancels(const char *root)
{
    struct watch_context ctx = {.fd = -1};
#if defined(__APPLE__)
    platform_directory_watcher_init(&ctx.directory_watcher);
#endif
    if (!root || snprintf(ctx.root, sizeof(ctx.root), "%s", root) >=
                     (int)sizeof(ctx.root)) return false;
    /* A stop requested before the fork starts no worker at all. */
    ctx.proof_pending_count = 1;
    g_watch_stop = 1;
    bool ok = watch_proof_start(&ctx, -1) && ctx.proof_worker_pid == 0;
    g_watch_stop = 0;
    struct sigaction watcher = {.sa_handler = watch_signal}, previous;
    (void)sigemptyset(&watcher.sa_mask);
    watcher.sa_flags = SA_RESTART;
    if (sigaction(SIGTERM, &watcher, &previous) != 0) return false;
    for (int round = 0; ok && round < 16; round++)
        ok = watch_test_edit_stop_round(&ctx);
    (void)sigaction(SIGTERM, &previous, NULL);
    zcl_devloop_process_cancel_clear();
    return ok;
}
#endif

static bool watch_commit_proof_start(struct watch_context *ctx,
                                     int watcher_lock_fd)
{
    if (!ctx) return false;
    watch_proof_reap(ctx);
    if (g_watch_stop || !watch_commit_proof_claimable(ctx) ||
        !zcl_dev_proof_queue_has_pending(ctx->root))
        return true;
    pid_t child = watch_proof_worker_fork(ctx, watcher_lock_fd);
    if (child < 0) return false;
    if (child == 0) {
        char why[256] = {0};
        int rc = zcl_dev_proof_queue_run_next(ctx->root, why, sizeof(why));
        if (rc < 0)
            fprintf(stderr, "[devloop] commit proof queue failed: %s\n",
                    why[0] ? why : "unknown");
        _exit(rc < 0 ? 1 : 0);
    }
    ctx->proof_worker_pid = child;
    ctx->proof_worker_kind = WATCH_PROOF_WORKER_COMMIT;
    return true;
}

static bool watch_proof_schedule(
    struct watch_context *ctx, const char *const *files, size_t count,
    enum zcl_devloop_publish_mode publish_mode, bool story_proof,
    int watcher_lock_fd)
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
    ctx->proof_pending_story = story_proof;
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
    zcl_devloop_watch_component_for_files(files, count, epoch->component);

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
    if (new_overlay_slots > ZCL_DEVLOOP_WATCH_MAX_FILES - ctx->overlay_count)
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

static bool watch_stream_flush(struct watch_context *ctx);

static bool watch_stream_enqueue(struct watch_context *ctx, const char *body,
                                 size_t len)
{
    if (!ctx || !body || len == 0 || len >= ZCL_DEVLOOP_CYCLE_JSON_MAX ||
        ctx->pending_count > sizeof(ctx->pending) / sizeof(ctx->pending[0]))
        return false;
    /* Local buffer pressure is not stream corruption. Seal the already
     * visible epochs in order before reserving another bounded slot. */
    if (ctx->pending_count == sizeof(ctx->pending) / sizeof(ctx->pending[0]) &&
        !watch_stream_flush(ctx))
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
    if (!zcl_devloop_cycle_stream_seal(
            ctx->root, through, why, sizeof(why))) {
        fprintf(stderr,
                "[devloop] async event journal flush failed through=%lld: %s\n",
                (long long)through, why[0] ? why : "unknown");
        return false;
    }
    ctx->pending_count = 0;
    return true;
}

#if defined(ZCL_TESTING)
bool zcl_devloop_watch_stream_backpressure_selftest(const char *repo_root)
{
    if (!repo_root || !repo_root[0])
        return false;
    struct watch_context ctx = {0};
    if (snprintf(ctx.root, sizeof(ctx.root), "%s", repo_root) <= 0 ||
        strlen(repo_root) >= sizeof(ctx.root))
        return false;
    char why[160] = {0};
    if (!zcl_devloop_cycle_stream_reset(repo_root, 0, why, sizeof(why)))
        return false;

    char events[5][256];
    size_t lengths[5];
    for (size_t i = 0; i < 5; i++) {
        int n = snprintf(
            events[i], sizeof(events[i]),
            "{\"schema\":\"zcl.dev_cycle.v1\",\"producer\":\"watch-test\","
            "\"status\":\"impact_ready\",\"action\":\"reflex\","
            "\"reason\":\"event-%zu\",\"phase\":\"IMPACT_READY\","
            "\"runtime_published\":false,\"elapsed_ms\":%zu,\"files\":[]}",
            i + 1, i + 1);
        if (n <= 0 || (size_t)n >= sizeof(events[i]))
            return false;
        lengths[i] = (size_t)n;
    }
    for (size_t i = 0; i < 4; i++)
        if (!watch_stream_enqueue(&ctx, events[i], lengths[i]))
            return false;

    /* The fifth event is the born-red assertion: a full local queue must seal
     * its first four exact epochs and retain the new event, not stop watching. */
    if (!watch_stream_enqueue(&ctx, events[4], lengths[4]) ||
        ctx.pending_count != 1)
        return false;
    char out[512];
    size_t out_len = 0;
    int64_t epoch = 0, after = 0;
    if (zcl_devloop_cycle_state_read(
            repo_root, out, sizeof(out), &out_len, &epoch, why,
            sizeof(why)) != ZCL_DEVLOOP_STATE_FOUND || epoch != 4 ||
        out_len != lengths[3] || memcmp(out, events[3], out_len) != 0)
        return false;
    for (size_t i = 0; i < 4; i++) {
        if (zcl_devloop_cycle_state_read_after(
                repo_root, after, out, sizeof(out), &out_len, &epoch,
                why, sizeof(why)) != ZCL_DEVLOOP_STATE_FOUND ||
            epoch != after + 1 || out_len != lengths[i] ||
            memcmp(out, events[i], out_len) != 0)
            return false;
        after = epoch;
    }
    if (zcl_devloop_cycle_state_read_after(
            repo_root, after, out, sizeof(out), &out_len, &epoch,
            why, sizeof(why)) != ZCL_DEVLOOP_STATE_FOUND ||
        epoch != 5 || out_len != lengths[4] ||
        memcmp(out, events[4], out_len) != 0 ||
        !watch_stream_flush(&ctx) || ctx.pending_count != 0)
        return false;
    if (zcl_devloop_cycle_state_read(
            repo_root, out, sizeof(out), &out_len, &epoch, why,
            sizeof(why)) != ZCL_DEVLOOP_STATE_FOUND || epoch != 5 ||
        out_len != lengths[4] || memcmp(out, events[4], out_len) != 0)
        return false;

    /* Losing the volatile generation underneath a full pending queue makes
     * the fifth enqueue's automatic flush fail closed. No pending body drops. */
    for (size_t i = 0; i < 4; i++)
        if (!watch_stream_enqueue(&ctx, events[i], lengths[i]))
            return false;
    if (ctx.pending_count != 4 ||
        !zcl_devloop_cycle_stream_reset(repo_root, 5, why, sizeof(why)) ||
        watch_stream_enqueue(&ctx, events[4], lengths[4]) ||
        ctx.pending_count != 4)
        return false;
    if (zcl_devloop_cycle_state_read(
            repo_root, out, sizeof(out), &out_len, &epoch, why,
            sizeof(why)) != ZCL_DEVLOOP_STATE_FOUND || epoch != 5)
        return false;
    size_t pending_before = ctx.pending_count;
    if (watch_stream_enqueue(&ctx, "{}", ZCL_DEVLOOP_CYCLE_JSON_MAX) ||
        ctx.pending_count != pending_before ||
        zcl_devloop_cycle_state_read(
            repo_root, out, sizeof(out), &out_len, &epoch, why,
            sizeof(why)) != ZCL_DEVLOOP_STATE_FOUND || epoch != 5)
        return false;
    ctx.pending_count = 5; /* impossible live state: guard before slot access */
    if (watch_stream_enqueue(&ctx, events[4], lengths[4]) ||
        ctx.pending_count != 5 ||
        zcl_devloop_cycle_state_read(
            repo_root, out, sizeof(out), &out_len, &epoch, why,
            sizeof(why)) != ZCL_DEVLOOP_STATE_FOUND || epoch != 5)
        return false;
    return true;
}
#endif

static bool watch_edit_seen_header(struct json_value *doc,
                                   const struct watch_context *ctx)
{
    return json_push_kv_str(doc, "schema", "zcl.dev_cycle.v1") &&
        json_push_kv_str(doc, "producer", "reflex-reactor") &&
        json_push_kv_str(doc, "status", "edit_seen") &&
        json_push_kv_str(doc, "action", "reflex") &&
        json_push_kv_str(doc, "reason", "source_mutation_observed") &&
        json_push_kv_str(doc, "phase", "EDIT_SEEN") &&
        json_push_kv_bool(doc, "runtime_published", false) &&
        json_push_kv_bool(doc, "proof_complete", false) &&
        json_push_kv_int(doc, "event_monotonic_us",
                         platform_time_monotonic_us()) &&
        json_push_kv_int(
            doc, "elapsed_us",
            ctx->first_mutation_us > 0
                ? platform_time_monotonic_us() - ctx->first_mutation_us : 0) &&
        json_push_kv_int(doc, "file_count", (int64_t)ctx->changed_count);
}

static bool watch_emit_edit_seen(struct watch_context *ctx)
{
    if (!ctx || ctx->changed_count == 0)
        return false;
    struct json_value doc, files;
    json_init(&doc); json_set_object(&doc);
    json_init(&files); json_set_array(&files);
    bool ok = watch_edit_seen_header(&doc, ctx);
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
    watch_idle_touch(ctx);
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
    ok = watch_trace_emit(ctx, &doc, ok);
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

#if !defined(__APPLE__)
static struct watched_dir *find_watch(struct watch_context *ctx, int wd)
{
    for (size_t i = 0; i < ctx->dir_count; i++) {
        if (ctx->dirs[i].wd == wd)
            return &ctx->dirs[i];
    }
    return NULL;
}

static bool reserve_watch(struct watch_context *ctx)
{
    if (!ctx)
        return false;
    if (ctx->dir_count < ctx->dir_capacity)
        return true;
    size_t capacity = ctx->dir_capacity
        ? ctx->dir_capacity * 2u : DEVLOOP_INITIAL_WATCHES;
    if (capacity < ctx->dir_capacity ||
        capacity > SIZE_MAX / sizeof(*ctx->dirs))
        return false;
    struct watched_dir *dirs = zcl_realloc(
        ctx->dirs, capacity * sizeof(*ctx->dirs), "devloop watcher table");
    if (!dirs)
        return false;
    ctx->dirs = dirs;
    ctx->dir_capacity = capacity;
    return true;
}

static bool add_watch_recursive(struct watch_context *ctx, const char *rel)
{
    if (!reserve_watch(ctx))
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
#endif

static void add_changed(struct watch_context *ctx, const char *path)
{
    if (!ctx || !relevant_file(path))
        return;
    watch_idle_touch(ctx);
    for (size_t i = 0; i < ctx->changed_count; i++) {
        if (strcmp(ctx->changed[i], path) == 0)
            return;
    }
    if (ctx->changed_count >= ZCL_DEVLOOP_WATCH_MAX_FILES) {
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
        watch_trace_event(ctx, ctx->first_mutation_us);
    }
    snprintf(ctx->changed[ctx->changed_count],
             sizeof(ctx->changed[ctx->changed_count]), "%s", path);
    ctx->changed_count++;
}

#if defined(__APPLE__)
#define DEVLOOP_MACOS_WATCH_FD_BUDGET 16384u

static bool watch_macos_ensure_fd_budget(void)
{
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0)
        return false;
    rlim_t target = (rlim_t)DEVLOOP_MACOS_WATCH_FD_BUDGET;
    if (limit.rlim_cur >= target)
        return true;
    if (limit.rlim_max != RLIM_INFINITY && target > limit.rlim_max)
        target = limit.rlim_max;
    if (target <= limit.rlim_cur)
        return true;
    struct rlimit raised = limit;
    raised.rlim_cur = target;
    return setrlimit(RLIMIT_NOFILE, &raised) == 0;
}

static bool watch_macos_descend(const char *name, void *opaque)
{
    (void)opaque;
    return !ignored_dir(name);
}

static bool watch_macos_include_file(const char *path, void *opaque)
{
    const struct watch_context *ctx = opaque;
    size_t root_len = ctx ? strlen(ctx->root) : 0;
    if (!ctx || root_len == 0 || strncmp(path, ctx->root, root_len) != 0 ||
        path[root_len] != '/')
        return false;
    return relevant_file(path + root_len + 1);
}

static bool watch_macos_record_result(
    struct watch_context *ctx, enum platform_directory_watch_result result)
{
    if (result == PLATFORM_DIRECTORY_WATCH_TIMEOUT ||
        result == PLATFORM_DIRECTORY_WATCH_STOPPED)
        return false;
    if (result == PLATFORM_DIRECTORY_WATCH_ERROR) {
        ctx->watch_backend_failed = true;
        return false;
    }
    mutation_sequence_advance(ctx);
    ctx->force_full_source_rescan = true;
    size_t before = ctx->changed_count;
    add_changed(ctx, "Makefile");
    return ctx->changed_count != before;
}
#endif

#if defined(__APPLE__)
/* A watcher still at its closed sentinel is the fd=-1 case the Linux half
 * below already has: no open backend, so no events and no failure. The
 * foreground-yield seam phase runs the real cancel poll on exactly such a
 * context. */
static bool collect_events_macos(struct watch_context *ctx)
{
    if (ctx->directory_watcher.native == UINTPTR_MAX)
        return false;
    return watch_macos_record_result(
        ctx, platform_directory_watcher_wait(&ctx->directory_watcher, 0,
                                             NULL, NULL));
}
#endif

static bool collect_events(struct watch_context *ctx)
{
#if defined(__APPLE__)
    return collect_events_macos(ctx);
#else
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
#endif
}

static bool watch_owns_current_lock(const struct watch_context *ctx)
{
    char path[PATH_MAX];
    struct stat held, current;
    return ctx && ctx->singleton_lock_fd >= 0 &&
        zcl_devloop_watch_lock_path(ctx->root, path, sizeof(path)) &&
        fstat(ctx->singleton_lock_fd, &held) == 0 &&
        lstat(path, &current) == 0 && S_ISREG(current.st_mode) &&
        held.st_dev == current.st_dev && held.st_ino == current.st_ino;
}

static bool watch_stop_request_poll(struct watch_context *ctx)
{
    if (!ctx || !ctx->stop_endpoint_ready) return false;
    if (!watch_owns_current_lock(ctx)) {
        /* A replaced lock retires its former watcher independently of the
         * stop request. The new lock owner is a separate session. */
        watch_signal(SIGTERM);
        return true;
    }
    char body[192], expected[192];
    ssize_t got = read(ctx->stop_fd, body, sizeof(body));
    int n = snprintf(expected, sizeof(expected), "%ld %llu %s %s\n",
                     (long)getpid(),
                     (unsigned long long)ctx->stop_start_token,
                     ctx->stop_nonce, ctx->stop_workspace);
    if (got > 0 && n > 0 && n < (int)sizeof(expected) &&
        got == n && memcmp(body, expected, (size_t)n) == 0) {
        watch_signal(SIGTERM);
        return true;
    }
    return false;
}

static int watch_wait_for_events(struct watch_context *ctx, int timeout_ms)
{
#if defined(__APPLE__)
    if (watch_stop_request_poll(ctx)) return 0;
    if (ctx->stop_endpoint_ready && timeout_ms > 100) timeout_ms = 100;
    enum platform_directory_watch_result result =
        platform_directory_watcher_wait(
            &ctx->directory_watcher,
            timeout_ms > 0 ? (uint32_t)timeout_ms : 0, NULL, NULL);
    bool changed = watch_macos_record_result(ctx, result);
    (void)watch_stop_request_poll(ctx);
    return ctx->watch_backend_failed ? -1 : (changed ? 1 : 0);
#else
    if (watch_stop_request_poll(ctx)) return 0;
    struct pollfd pfd[2] = {
        {.fd = ctx->fd, .events = POLLIN},
        {.fd = ctx->stop_endpoint_ready ? ctx->stop_fd : -1,
         .events = POLLIN}
    };
    int rc;
    do { rc = poll(pfd, 2, timeout_ms); }
    while (rc < 0 && errno == EINTR);
    if (rc <= 0)
        return rc;
    if (pfd[1].revents & POLLIN) {
        (void)watch_stop_request_poll(ctx);
        if (g_watch_stop) return 0;
    }
    return collect_events(ctx) ? 1 : 0;
#endif
}

static void watch_backend_close(struct watch_context *ctx)
{
    if (!ctx) return;
#if defined(__APPLE__)
    platform_directory_watcher_close(&ctx->directory_watcher);
#else
    if (ctx->fd >= 0)
        close(ctx->fd);
    ctx->fd = -1;
#endif
}

/* Native watches are armed before this runs. The reconciled refresh validates the
 * SHA3 seal, enumerates and stats the current policy inventory, and performs a
 * complete byte pass only when the prior image is absent/invalid or its
 * inventory moved. Any mutation racing that work is already queued by the
 * platform backend and is drained before the image can be described as
 * trusted. */
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
#if defined(__APPLE__)
    if (ctx->watch_backend_failed)
        return false;
#endif
    ctx->snapshot_raced = ctx->changed_count > 0;
    int64_t elapsed_us = platform_time_monotonic_us() - started_us;
#if defined(__APPLE__)
    const char *watch_backend = "kqueue";
    const char *inotify_armed = "false";
#else
    const char *watch_backend = "inotify";
    const char *inotify_armed = "true";
#endif
    printf("{\"schema\":\"zcl.dev_source_snapshot.v1\","
           "\"status\":\"reconciled\",\"inotify_armed\":%s,"
           "\"watch_backend\":\"%s\","
           "\"seal_verified\":%s,\"snapshot_used\":%s,"
           "\"full_rescan\":%s,\"inventory_changed\":%s,"
           "\"files_total\":%u,\"files_read\":%u,"
           "\"bytes_read\":%llu,\"queued_paths\":%zu,"
           "\"mutation_sequence\":%llu,\"elapsed_us\":%lld,"
           "\"source_root\":\"%s\"}\n",
           inotify_armed, watch_backend,
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
    g_watch_stop |= watch_stop_request_poll(ctx);
    if (g_watch_stop)
        return true;
    bool changed = collect_events(ctx) && ctx->changed_count > 0;
#if defined(__APPLE__)
    if (ctx->watch_backend_failed) {
        g_watch_stop = 1;
        return true;
    }
#endif
    if (changed && !ctx->edit_seen_emitted && !watch_emit_edit_seen(ctx)) {
        g_watch_stop = 1;
        return true;
    }
    if (changed && !ctx->prepared_epoch_ready) {
        const char *files[ZCL_DEVLOOP_WATCH_MAX_FILES];
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
    (void)watch_request_hint_poll(ctx);
    return watch_cycle_should_yield(ctx, changed);
}

static bool watch_start_event_stream(struct watch_context *ctx)
{
    char latest[ZCL_DEVLOOP_CYCLE_JSON_MAX], why[160] = {0};
    size_t latest_len = 0;
    int64_t durable_epoch = 0;
    /* The ring restarts after the pointer's epoch, so the pointer must first
     * reach the journal tail a killed flusher may have left it behind. */
    if (!zcl_devloop_cycle_state_heal(ctx->root, why, sizeof(why))) {
        fprintf(stderr, "[devloop] event stream anchor heal failed: %s\n",
                why[0] ? why : "unknown");
        return false;
    }
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

#if defined(ZCL_TESTING)
static int watch_sealer_test_fd_count(void)
{
    DIR *dir = opendir("/dev/fd");
    if (!dir)
        return -1;
    int count = 0;
    while (readdir(dir))
        count++;
    (void)closedir(dir);
    return count;
}

static const char *watch_sealer_test_open(struct watch_context *ctx,
                                          const char *root)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->fd = -1;
    watch_sealer_init(&ctx->sealer);
#if defined(__APPLE__)
    platform_directory_watcher_init(&ctx->directory_watcher);
#endif
    (void)snprintf(ctx->root, sizeof(ctx->root), "%s", root);
    /* The watcher's own startup: heal the pointer, reset the ring from it. */
    return watch_start_event_stream(ctx) ? NULL : "event stream start";
}

/* Publishes and seals `count` events exactly as the reflex producers do. */
static const char *watch_sealer_test_publish(struct watch_context *ctx,
                                             size_t count)
{
    for (size_t i = 0; i < count; i++) {
        char body[256];
        int n = snprintf(
            body, sizeof(body),
            "{\"schema\":\"zcl.dev_cycle.v1\",\"producer\":\"watch-test\","
            "\"status\":\"impact_ready\",\"action\":\"reflex\","
            "\"reason\":\"save-%zu\",\"phase\":\"IMPACT_READY\","
            "\"runtime_published\":false,\"elapsed_ms\":%zu,\"files\":[]}",
            i + 1, i + 1);
        if (n <= 0 || (size_t)n >= sizeof(body))
            return "event fixture";
        if (!watch_stream_enqueue(ctx, body, (size_t)n) ||
            !watch_stream_flush(ctx))
            return "a published event could not be sealed";
    }
    return NULL;
}

static int64_t watch_sealer_test_journal_files(const char *root)
{
    char dir[PATH_MAX], events[PATH_MAX];
    if (!zcl_devloop_workspace_state_dir(root, dir, sizeof(dir)) ||
        snprintf(events, sizeof(events), "%s/cycle-events", dir) >=
            (int)sizeof(events))
        return -1;
    DIR *d = opendir(events);
    if (!d)
        return -1;
    int64_t count = 0;
    for (struct dirent *e = readdir(d); e; e = readdir(d))
        count += e->d_name[0] != '.';
    (void)closedir(d);
    return count;
}

/* Every epoch 1..latest is sealed exactly once and in order, the ring is
 * wholly durable, and the pointer names the journal tail. */
static const char *watch_sealer_test_contiguous(const char *root)
{
    char out[ZCL_DEVLOOP_CYCLE_JSON_MAX], why[160] = {0};
    size_t len = 0;
    int64_t latest = 0, durable = 0, pointer = 0, epoch = 0;
    if (!zcl_devloop_cycle_stream_marks(root, &latest, &durable) ||
        durable != latest)
        return "a published event is not sealed";
    if (zcl_devloop_cycle_state_read(root, out, sizeof(out), &len, &pointer,
                                     why, sizeof(why)) !=
            ZCL_DEVLOOP_STATE_FOUND || pointer != latest)
        return "the latest pointer is not the journal tail";
    for (int64_t after = 0; after < latest; after++)
        if (zcl_devloop_cycle_state_read_after(
                root, after, out, sizeof(out), &len, &epoch, why,
                sizeof(why)) != ZCL_DEVLOOP_STATE_FOUND ||
            epoch != after + 1)
            return "the journal has a gap";
    if (zcl_devloop_cycle_state_read_after(
            root, latest, out, sizeof(out), &len, &epoch, why,
            sizeof(why)) != ZCL_DEVLOOP_STATE_ABSENT)
        return "the journal runs past the ring";
    return watch_sealer_test_journal_files(root) == latest
        ? NULL : "the journal does not hold each epoch exactly once";
}

static const char *watch_sealer_test_stop(struct watch_context *ctx)
{
    watch_sealer_finish(ctx);
    if (ctx->sealer.pid != 0 || ctx->sealer.fd != -1 ||
        ctx->sealer.read_fd != -1)
        return "stop left the sealer or its pipe behind";
    return watch_sealer_test_contiguous(ctx->root);
}

/* Handed-off seals are deferred, and stop returns only once they are all
 * sealed. */
static const char *watch_sealer_test_drain(struct watch_context *ctx,
                                           const char *root)
{
    const char *failed = watch_sealer_test_open(ctx, root);
    if (!failed && !watch_sealer_start(ctx, -1))
        failed = "sealer start";
    if (!failed)
        failed = watch_sealer_test_publish(ctx, 8);
    if (!failed && (ctx->sealer.deferred != 8 || ctx->sealer.inline_backlog ||
                    ctx->sealer.inline_down || ctx->trace.seals_inline))
        failed = "a seal inside the bound was not handed to the sealer";
    const char *stopped = watch_sealer_test_stop(ctx);
    return failed ? failed : stopped;
}

/* Rapid saves past the ring's capacity with a stalled sealer: the backlog
 * bound seals inline before the ring could evict an unsealed event. */
static const char *watch_sealer_test_backlog(struct watch_context *ctx,
                                             const char *root)
{
    const char *failed = watch_sealer_test_open(ctx, root);
    if (!failed && !watch_sealer_start(ctx, -1))
        failed = "sealer start";
    if (!failed && kill(ctx->sealer.pid, SIGSTOP) != 0)
        failed = "sealer stall";
    if (!failed)
        failed = watch_sealer_test_publish(ctx, 100);
    if (!failed && (ctx->sealer.inline_backlog == 0 ||
                    ctx->trace.seals_inline == 0 ||
                    ctx->sealer.deferred == 0))
        failed = "a backlog over the bound did not seal inline";
    if (ctx->sealer.pid > 0)
        (void)kill(ctx->sealer.pid, SIGCONT);
    const char *stopped = watch_sealer_test_stop(ctx);
    return failed ? failed : stopped;
}

/* Waits for the child to die of `signal_number` without reaping it. */
static bool watch_sealer_test_await_death(pid_t pid, int signal_number)
{
    siginfo_t info;
    memset(&info, 0, sizeof(info));
    int rc;
    do {
        rc = waitid(P_PID, (id_t)pid, &info, WEXITED | WNOWAIT);
    } while (rc != 0 && errno == EINTR);
    return rc == 0 && info.si_pid == pid && info.si_code == CLD_KILLED &&
           info.si_status == signal_number;
}

/* A sealer that died turns every later seal into an inline one. */
static const char *watch_sealer_test_dead(struct watch_context *ctx,
                                          const char *root)
{
    const char *failed = watch_sealer_test_open(ctx, root);
    if (!failed && !watch_sealer_start(ctx, -1))
        failed = "sealer start";
    if (!failed && (kill(ctx->sealer.pid, SIGKILL) != 0 ||
                    !watch_sealer_test_await_death(ctx->sealer.pid, SIGKILL)))
        failed = "sealer kill";
    if (!failed)
        failed = watch_sealer_test_publish(ctx, 2);
    int64_t latest = 0, durable = -1;
    if (!failed && (ctx->sealer.inline_down != 2 || ctx->sealer.pid != 0 ||
                    ctx->sealer.fd != -1 || ctx->trace.seals_inline != 2 ||
                    !zcl_devloop_cycle_stream_marks(root, &latest,
                                                    &durable) ||
                    durable != latest))
        failed = "a dead sealer did not force synchronous sealing";
    const char *stopped = watch_sealer_test_stop(ctx);
    return failed ? failed : stopped;
}

/* Runs in a forked proof worker: the pipe is gone, what the watcher handed
 * the sealer is already sealed, and its own seal is synchronous. */
static int watch_sealer_test_worker(const char *root, int write_fd,
                                    int read_fd)
{
    int64_t latest = 0, durable = -1, epoch = 0;
    char why[160] = {0};
    static const char body[] =
        "{\"schema\":\"zcl.dev_cycle.v1\",\"producer\":\"watch-test\","
        "\"status\":\"passed\",\"action\":\"verify\",\"reason\":\"worker\","
        "\"phase\":\"verify\",\"runtime_published\":false,\"files\":[]}";
    if (fcntl(write_fd, F_GETFD) != -1 || fcntl(read_fd, F_GETFD) != -1)
        return 10;
    if (!zcl_devloop_cycle_stream_marks(root, &latest, &durable) ||
        durable != latest)
        return 11;
    if (!zcl_devloop_cycle_stream_publish(root, body, sizeof(body) - 1,
                                          &epoch, why, sizeof(why)) ||
        !zcl_devloop_cycle_stream_seal(root, epoch, why, sizeof(why)) ||
        !zcl_devloop_cycle_stream_marks(root, &latest, &durable) ||
        durable != epoch)
        return 12;
    return 0;
}

static const char *watch_sealer_test_worker_fork(struct watch_context *ctx,
                                                 const char *root)
{
    const char *failed = watch_sealer_test_open(ctx, root);
    if (!failed && !watch_sealer_start(ctx, -1))
        failed = "sealer start";
    if (!failed)
        failed = watch_sealer_test_publish(ctx, 3);
    int write_fd = ctx->sealer.fd, read_fd = ctx->sealer.read_fd;
    pid_t worker = failed ? -1 : watch_proof_worker_fork(ctx, -1);
    if (worker == 0)
        _exit(watch_sealer_test_worker(root, write_fd, read_fd));
    int status = 0;
    if (!failed && (worker < 0 || waitpid(worker, &status, 0) != worker ||
                    !WIFEXITED(status) || WEXITSTATUS(status) != 0))
        failed = "a proof worker inherited the sealer pipe or deferral";
    const char *stopped = watch_sealer_test_stop(ctx);
    return failed ? failed : stopped;
}

/* Five ring events, then one producer seal request covering all of them. */
static const char *watch_sealer_test_batch(struct watch_context *ctx)
{
    static const char body[] =
        "{\"schema\":\"zcl.dev_cycle.v1\",\"producer\":\"watch-test\","
        "\"status\":\"impact_ready\",\"action\":\"reflex\","
        "\"reason\":\"crash\",\"phase\":\"IMPACT_READY\","
        "\"runtime_published\":false,\"files\":[]}";
    int64_t epoch = 0;
    char why[160] = {0};
    for (int i = 0; i < 5; i++)
        if (!zcl_devloop_cycle_stream_publish(ctx->root, body,
                                              sizeof(body) - 1, &epoch, why,
                                              sizeof(why)))
            return "crash batch publication";
    if (!zcl_devloop_cycle_stream_seal(ctx->root, epoch, why, sizeof(why)) ||
        ctx->sealer.deferred != 1)
        return "the crash batch was not handed to the sealer";
    return NULL;
}

/* The crash a restart must survive: the watcher, and a sealer killed two
 * events into a five-event batch, so the pointer still lags the journal. */
static const char *watch_sealer_test_crash(struct watch_context *ctx,
                                           const char *root, int64_t *tail)
{
    int64_t base = 0, latest = 0, pointer = 0;
    char out[ZCL_DEVLOOP_CYCLE_JSON_MAX], why[160] = {0};
    size_t len = 0;
    const char *failed = watch_sealer_test_open(ctx, root);
    if (!failed && !zcl_devloop_cycle_stream_marks(root, &latest, &base))
        failed = "ring marks";
    zcl_devloop_cycle_stream_test_kill_after(2);
    if (!failed && !watch_sealer_start(ctx, -1))
        failed = "sealer start";
    zcl_devloop_cycle_stream_test_kill_after(0);
    if (!failed)
        failed = watch_sealer_test_batch(ctx);
    if (!failed && !watch_sealer_test_await_death(ctx->sealer.pid, SIGKILL))
        failed = "the sealer did not die inside its batch";
    /* The watcher dies too: nothing it owned seals anything more. */
    zcl_devloop_cycle_stream_seal_defer(NULL, NULL);
    if (ctx->sealer.pid > 0)
        (void)waitpid(ctx->sealer.pid, NULL, 0);
    ctx->sealer.pid = 0;
    watch_sealer_close_fds(&ctx->sealer);
    if (!failed && (zcl_devloop_cycle_state_read(
                        root, out, sizeof(out), &len, &pointer, why,
                        sizeof(why)) != ZCL_DEVLOOP_STATE_FOUND ||
                    pointer != base))
        failed = "the killed batch moved the pointer";
    *tail = base + 2;
    return failed;
}

/* A restart after that crash: the pointer heals onto the journal tail, the
 * fresh ring continues from it, and new saves seal with no gap refusal. */
static const char *watch_sealer_test_restart(struct watch_context *ctx,
                                             const char *root, int64_t tail)
{
    int64_t latest = 0, durable = 0;
    const char *failed = watch_sealer_test_open(ctx, root);
    if (!failed && (!zcl_devloop_cycle_stream_marks(root, &latest,
                                                    &durable) ||
                    latest != tail || durable != tail))
        failed = "the restarted ring does not continue the journal tail";
    if (!failed && !watch_sealer_start(ctx, -1))
        failed = "sealer restart";
    if (!failed)
        failed = watch_sealer_test_publish(ctx, 3);
    const char *stopped = watch_sealer_test_stop(ctx);
    return failed ? failed : stopped;
}

static const char *watch_sealer_test_phases(struct watch_context *ctx,
                                            const char *root)
{
    int64_t tail = 0;
    const char *failed = watch_sealer_test_drain(ctx, root);
    if (!failed)
        failed = watch_sealer_test_backlog(ctx, root);
    if (!failed)
        failed = watch_sealer_test_dead(ctx, root);
    if (!failed)
        failed = watch_sealer_test_worker_fork(ctx, root);
    if (!failed)
        failed = watch_sealer_test_crash(ctx, root, &tail);
    if (!failed)
        failed = watch_sealer_test_restart(ctx, root, tail);
    return failed;
}

const char *zcl_devloop_watch_sealer_selftest(const char *repo_root)
{
    char root[PATH_MAX];
    if (!repo_root || !realpath(repo_root, root))
        return "fixture path";
    int fds_before = watch_sealer_test_fd_count();
    struct watch_context *ctx =
        zcl_calloc(1, sizeof(*ctx), "devloop.watch.sealer_selftest");
    if (!ctx)
        return "watch context allocation";
    const char *failed = watch_sealer_test_phases(ctx, root);
    free(ctx);
    if (!failed && (fds_before < 0 ||
                    watch_sealer_test_fd_count() != fds_before))
        failed = "a sealer descriptor outlived its watcher";
    if (!failed && (waitpid(-1, NULL, WNOHANG) != -1 || errno != ECHILD))
        failed = "a child process outlived its watcher";
    return failed;
}
#endif

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
        dprintf(fd, "%ld %s starting proofq1\n", (long)getpid(),
                zcl_devloop_publish_mode_name(publish_mode));
    return fd;
}

static bool watch_stop_endpoint_open(struct watch_context *ctx,
                                     char path[320])
{
    uint8_t bytes[32];
    if (!ctx || !path ||
        !rng_fill(bytes, sizeof(bytes)) ||
        !os_proc_pid_start_token((uint64_t)getpid(),
                                 &ctx->stop_start_token) ||
        !zcl_devloop_workspace_id(ctx->root, ctx->stop_workspace))
        return false;
    zcl_hex_encode(bytes, sizeof(bytes), ctx->stop_nonce);
    int n = snprintf(path, 320, "/tmp/z23-watch-stop-%lu-%s",
                     (unsigned long)geteuid(), ctx->stop_nonce);
    if (n <= 0 || n >= 320 || mkfifo(path, 0600) != 0)
        return false;
    int fd = open(path, O_RDWR | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    bool ok = fd >= 0 && fstat(fd, &st) == 0 && S_ISFIFO(st.st_mode) &&
              st.st_uid == geteuid() && (st.st_mode & 0777) == 0600;
    if (!ok) {
        if (fd >= 0) close(fd);
        (void)unlink(path);
        return false;
    }
    ctx->stop_fd = fd;
    ctx->stop_endpoint_ready = true;
    return true;
}

static void watch_stop_endpoint_close(struct watch_context *ctx,
                                      const char *path)
{
    if (!ctx || !ctx->stop_endpoint_ready) return;
    (void)close(ctx->stop_fd);
    ctx->stop_endpoint_ready = false;
    if (path && path[0]) (void)unlink(path);
}

static bool mark_singleton_ready(
    int fd, enum zcl_devloop_publish_mode publish_mode,
    const struct watch_context *ctx)
{
    if (fd < 0 || !ctx || !ctx->stop_endpoint_ready ||
        ftruncate(fd, 0) != 0 || lseek(fd, 0, SEEK_SET) < 0)
        return false;
    return dprintf(fd, "%ld %s ready proofq1 %llu %s\n",
                            (long)getpid(),
                            zcl_devloop_publish_mode_name(publish_mode),
                            (unsigned long long)ctx->stop_start_token,
                            ctx->stop_nonce) > 0;
}

static int watch_prepare_root(struct watch_context *ctx,
                              const char *repo_root)
{
    const char *root = repo_root && repo_root[0] ? repo_root : ".";
    if (!realpath(root, ctx->root)) {
        fprintf(stderr, "[devloop] watch: cannot resolve repository root: %s\n",
                strerror(errno));
        return 2;
    }
    char reflex_ccache[PATH_MAX];
    int cache_n = snprintf(reflex_ccache, sizeof(reflex_ccache),
                           "%s/.cache/devloop-ccache-v1", ctx->root);
    if (cache_n <= 0 || (size_t)cache_n >= sizeof(reflex_ccache) ||
        setenv("CCACHE_DIR", reflex_ccache, 1) != 0 ||
        setenv("CCACHE_MAXSIZE", "512M", 1) != 0) {
        fprintf(stderr, "[devloop] watch: compiler cache isolation failed\n");
        return 1;
    }
    char makefile[PATH_MAX];
    snprintf(makefile, sizeof(makefile), "%s/Makefile", ctx->root);
    if (access(makefile, R_OK) != 0) {
        fprintf(stderr, "[devloop] watch: root has no readable Makefile\n");
        return 2;
    }
    return 0;
}

int zcl_devloop_watch_mode_until(const char *repo_root,
    enum zcl_devloop_publish_mode publish_mode,
    zcl_devloop_stop_predicate stop, void *stop_opaque)
{
    struct watch_context ctx = {0};
    ctx.fd = -1;
    ctx.singleton_lock_fd = -1;
    char stop_path[320] = {0};
    watch_sealer_init(&ctx.sealer);
#if defined(__APPLE__)
    platform_directory_watcher_init(&ctx.directory_watcher);
#endif
    const char *mode_name = zcl_devloop_publish_mode_name(publish_mode);
    if (!mode_name) {
        fprintf(stderr, "[devloop] watch: invalid publication mode\n");
        return 2;
    }
    /* The resident compiler must not share eviction/cleanup state with full
     * builds on the host. A saturated global ccache inflated the protected
     * story from ~90 ms to ~500 ms even though impact and the candidate were
     * unchanged. This checkout-local bounded cache is warm-service state,
     * outside Git and outside the immutable source epoch. */
    int prepared = watch_prepare_root(&ctx, repo_root);
    if (prepared != 0) return prepared;
    int lock_fd = open_singleton_lock(ctx.root, publish_mode);
    if (lock_fd < 0) {
        fprintf(stderr,
                "[devloop] watch: another watcher owns this worktree lane\n");
        return 1;
    }
    ctx.singleton_lock_fd = lock_fd;
    if (!watch_stop_endpoint_open(&ctx, stop_path)) {
        fprintf(stderr, "[devloop] watch: stop endpoint unavailable\n");
        close(lock_fd);
        return 1;
    }
#if defined(__APPLE__)
    if (!watch_macos_ensure_fd_budget()) {
        fprintf(stderr,
                "[devloop] watch: cannot raise bounded kqueue descriptor "
                "budget: %s\n", strerror(errno));
        watch_stop_endpoint_close(&ctx, stop_path);
        close(lock_fd);
        return 1;
    }
    if (!platform_directory_watcher_open_filtered(
            &ctx.directory_watcher, ctx.root, watch_macos_descend,
            watch_macos_include_file, &ctx)) {
        fprintf(stderr, "[devloop] watch: recursive kqueue setup failed: %s\n",
                strerror(errno));
        watch_stop_endpoint_close(&ctx, stop_path);
        close(lock_fd);
        return 1;
    }
#else
    ctx.fd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
    if (ctx.fd < 0 || !add_watch_recursive(&ctx, "")) {
        fprintf(stderr, "[devloop] watch: recursive inotify setup failed: %s\n",
                strerror(errno));
        watch_backend_close(&ctx);
        free(ctx.dirs);
        watch_stop_endpoint_close(&ctx, stop_path);
        close(lock_fd);
        return 1;
    }
#endif
    if (!prime_source_snapshot(&ctx)) {
        fprintf(stderr,
                "[devloop] watch: source snapshot reconciliation failed\n");
        watch_backend_close(&ctx);
        free(ctx.dirs);
        watch_stop_endpoint_close(&ctx, stop_path);
        close(lock_fd);
        return 1;
    }
    if (!watch_start_event_stream(&ctx)) {
        fprintf(stderr,
                "[devloop] watch: bounded local event stream unavailable\n");
        ci_merkle_free(ctx.verified_tree);
        watch_backend_close(&ctx);
        free(ctx.dirs);
        watch_stop_endpoint_close(&ctx, stop_path);
        close(lock_fd);
        return 1;
    }
    if (!mark_singleton_ready(lock_fd, publish_mode, &ctx)) {
        fprintf(stderr,
                "[devloop] watch: could not publish ready ownership\n");
        watch_backend_close(&ctx);
        free(ctx.dirs);
        watch_stop_endpoint_close(&ctx, stop_path);
        close(lock_fd);
        return 1;
    }
    /* After the ring reset and before any producer runs, and before the stop
     * handlers exist: the sealer's lifetime is the request pipe's. */
    (void)watch_sealer_start(&ctx, lock_fd);

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

    bool idle_exit = false;
    ctx.idle_since_us = platform_time_monotonic_us();
    while (!g_watch_stop && !(stop && stop(stop_opaque))) {
        if (watch_stop_request_poll(&ctx)) break;
        watch_commit_proof_prioritize(&ctx);
        if (!watch_proof_start(&ctx, lock_fd)) {
            fprintf(stderr, "[devloop] complete proof worker start failed\n");
            break;
        }
        if (!watch_commit_proof_start(&ctx, lock_fd)) {
            fprintf(stderr, "[devloop] commit proof worker start failed\n");
            break;
        }
        if (zcl_dev_proof_queue_has_pending(ctx.root) ||
            ctx.proof_worker_pid > 1)
            watch_idle_touch(&ctx);
        if (ctx.changed_count == 0 && !ctx.prepared_epoch_ready) {
            watch_trace_idle(&ctx);
            int prc = watch_wait_for_events(&ctx, stop ? 100 : 1000);
            if (g_watch_stop) break;
            if (prc < 0) {
                fprintf(stderr, "[devloop] watch: event wait failed: %s\n",
                        strerror(errno));
                break;
            }
            if (prc == 0) {
                if (watch_idle_poll_should_exit(&ctx)) {
                    idle_exit = true;
                    break;
                }
                continue;
            }
            if (ctx.changed_count == 0)
                continue;
        }
        watch_idle_touch(&ctx);

#if defined(__APPLE__)
        /* EVFILT_VNODE identifies the directory that moved, not the final
         * child pathname. Feeding a synthetic path into the path-qualified
         * hot-reflex reactor would mint false blob evidence. Coalesce the
         * vnode burst, then use the established conservative full-source
         * cycle (the same safety posture as ReadDirectoryChangesW) until a
         * filename-bearing Darwin backend exists. Proof-queue workers remain
         * exact commit/base jobs and are started above this branch. */
        if (ctx.changed_count > 0) {
            if (!ctx.edit_seen_emitted &&
                (!watch_emit_edit_seen(&ctx) || !watch_stream_flush(&ctx))) {
                fprintf(stderr,
                        "[devloop] watch: macOS edit acknowledgement failed\n");
                break;
            }
            int64_t quiet_until =
                platform_time_monotonic_us() + DEVLOOP_EDIT_QUIET_US;
            while (!g_watch_stop && !(stop && stop(stop_opaque))) {
                int64_t remain_us =
                    quiet_until - platform_time_monotonic_us();
                if (remain_us <= 0)
                    break;
                int wait_ms = (int)((remain_us + 999) / 1000);
                if (stop && wait_ms > 100) wait_ms = 100;
                int drc = watch_wait_for_events(&ctx, wait_ms);
                if (drc > 0)
                    quiet_until = platform_time_monotonic_us() +
                        DEVLOOP_EDIT_QUIET_US;
                else if (drc < 0)
                    break;
            }
            if (g_watch_stop) break;
            /* A commit can arrive while the Darwin vnode burst is being
             * coalesced.  Do not enter the synchronous conservative EDIT
             * cycle after that exact clean request becomes claimable: the
             * top of the next loop iteration will start its stronger bound
             * proof. */
            if (watch_commit_proof_prioritize(&ctx)) {
                ctx.changed_count = 0;
                ctx.first_mutation_us = 0;
                ctx.force_full_source_rescan = false;
                ctx.edit_seen_emitted = false;
                continue;
            }
            ctx.changed_count = 0;
            ctx.first_mutation_us = 0;
            ctx.force_full_source_rescan = false;
            ctx.edit_seen_emitted = false;
            const char *files[] = {"Makefile"};
            if (!watch_proof_schedule(
                    &ctx, files, 1, ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY,
                    false, lock_fd)) {
                fprintf(stderr,
                        "[devloop] watch: conservative macOS cycle could not "
                        "be scheduled\n");
                break;
            }
            continue;
        }
#endif

        char epoch_changed[ZCL_DEVLOOP_WATCH_MAX_FILES][ZCL_DEVLOOP_PATH_MAX];
        const char *files[ZCL_DEVLOOP_WATCH_MAX_FILES];
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
                int drc = watch_wait_for_events(&ctx, wait_ms);
                if (drc > 0)
                    quiet_until = platform_time_monotonic_us() +
                        DEVLOOP_EDIT_QUIET_US;
                else if (drc < 0)
                    break;
            }
            if (g_watch_stop) break;

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
            watch_trace_mark(&ctx.trace.impact_ready_us);
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
        watch_request_hint_arm(&ctx);
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
            if (restart_union_ok &&
                zcl_devloop_watch_epoch_all_c(files, epoch_count) &&
                ctx.restart_sources.count > 0) {
                proof_count = ctx.restart_sources.count;
                for (size_t i = 0; i < proof_count; i++)
                    restart_files[i] = ctx.restart_sources.sources[i];
                proof_files = restart_files;
            }
            fast = zcl_devloop_restart_event(
                ctx.root, proof_files, proof_count, publish_mode);
        }
        watch_trace_mark(&ctx.trace.reflex_return_us);
        /* Candidate emitters seal through their already-visible terminal
         * reflex event. Retire the watcher's matching queue entries now so a
         * save during asynchronous proof has the full bounded queue. */
        if (fast != 0 && !watch_stream_flush(&ctx)) {
            g_watch_stop = 1;
            fast = ZCL_DEVLOOP_RESTART_EVENT_FINAL;
        }
        watch_trace_mark(&ctx.trace.stream_flushed_us);
        /* A green HOT_SHADOW story is already useful foreground knowledge.
         * Only after publishing it do we build/run the exact affected proof.
         * The ordinary restart lane reaches this same state after its focused
         * receipt, so both converge here without duplicating scheduling. */
        bool story_proof = fast == ZCL_DEVLOOP_RESTART_EVENT_PROOF_PENDING &&
            epoch_count == 1 &&
            strcmp(files[0],
                   "contexts/wallet/services/src/vault_intent_decision_service.c") == 0;
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
                        ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY,
                        story_proof, lock_fd)) {
                    fprintf(stderr,
                            "[devloop] complete proof worker schedule failed\n");
                    g_watch_stop = 1;
                }
            }
            fast = ZCL_DEVLOOP_RESTART_EVENT_FINAL;
        }
        watch_trace_mark(&ctx.trace.proof_scheduled_us);
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
        watch_trace_end(&ctx);
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

    watch_proof_stop(&ctx);
    zcl_devloop_process_cancel_poll_clear();
    watch_sealer_finish(&ctx);
    watch_emit_stopped_heartbeat(idle_exit);
    watch_backend_close(&ctx);
    /* Release singleton ownership after the obsolete proof's active child
     * session has been signalled. Reaping the already-cancelled worker cannot
     * delay the next resident reactor from attaching to this checkout. */
    close(lock_fd);
    watch_proof_join(&ctx);
    watch_stop_endpoint_close(&ctx, stop_path);
    ci_merkle_free(ctx.verified_tree);
    free(ctx.dirs);
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

#endif /* _WIN32 */

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
