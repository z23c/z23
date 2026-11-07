/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: confine preview execution and atomically admit compatible programs. */
#include "services/task_update.h"
#include "services/package_resident.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "platform/os_proc.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/spawn.h"
#include "util/thread_registry.h"
#include "util/thread_qos.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

/* One joined, finite worker per owner. No background service or detached job. */
struct task_update_images {
    struct package_resident slots[2];
    unsigned next;
};

// supervisor-ok:window-owned-bounded-preview
struct task_update_job {
    pthread_t thread;
    atomic_bool completed, cancelled;
    bool go_back, keep, refresh;
    char directory[4096], app[256], verifier[4096], scratch[128], nonce[65];
    struct package_resident_identity target;
    struct task_document_checkpoint checkpoint;
    struct package_resident_record record;
    uint64_t token;
    char view[4096];
    struct zcl_result result;
    int64_t elapsed_us, step_started_us, helper_startup_us, confined_us;
    atomic_uint step;
    int64_t step_us[TASK_UPDATE_STEP_COUNT];
    struct task_update_images *images;
};

static struct zcl_result tu_image(struct task_update_job *job,
    const struct package_resident_artifact *artifact, struct package_resident **out)
{
    for (unsigned i = 0; i < 2; ++i) {
        struct package_resident *image = &job->images->slots[i];
        if (image->snapshot_image[0] &&
            strcmp(image->artifact.accepted.image_sha3_hex, artifact->accepted.image_sha3_hex) == 0) {
            *out = image;
            return package_resident_prepare_reuse(image, artifact);
        }
    }
    *out = &job->images->slots[job->images->next++ % 2u];
    ZCL_CHECK(package_resident_close(*out));
    package_resident_init(*out);
    return package_resident_prepare(*out, artifact);
}

/* Only the worker writes timings. The UI reads the published stage, then
 * receives the completed timing values after the worker's release store. */
static void tu_stage(struct task_update_job *job, enum task_update_step step)
{
    int64_t now = platform_time_monotonic_us();
    unsigned previous = atomic_load_explicit(&job->step, memory_order_relaxed);
    if (previous < TASK_UPDATE_STEP_COUNT)
        job->step_us[previous] += now - job->step_started_us;
    job->step_started_us = now;
    atomic_store_explicit(&job->step, (unsigned)step, memory_order_release);
}

static struct zcl_result tu_progress(struct task_update *update,
    const struct task_update_job *job, bool *changed)
{
    if (!job || atomic_load_explicit(&job->cancelled, memory_order_relaxed)) return ZCL_OK;
    unsigned step = atomic_load_explicit(&job->step, memory_order_acquire);
    if (step > TASK_UPDATE_STEP_COUNT || step == (unsigned)update->step) return ZCL_OK;
    static const char *const messages[] = {
        "Opening saved task data...", "Verifying the installed program...",
        "Copying current tasks and undo...", "Preparing the isolated program...",
        "Preparing private preview data...", "Running the confined preview...",
        "Checking current-data compatibility...", "Releasing the preview process...",
        "Saving program selection...", "Finishing update..."
    };
    update->step = (enum task_update_step)step;
    (void)snprintf(update->message, sizeof(update->message), "%s", messages[step]);
    *changed = true;
    return ZCL_OK;
}

static struct zcl_result tu_failure(struct task_update *update, struct zcl_result result)
{
    update->phase = TASK_UPDATE_FAILED;
    (void)snprintf(update->message, sizeof(update->message), "%.255s", result.message);
    LOG_ERROR("task-update", "%s", result.message);
    return result;
}

#if !defined(_WIN32)
static struct zcl_result tu_write(const char *directory, const char *name,
                                  const unsigned char *bytes, size_t size)
{
    char path[256];
    (void)snprintf(path, sizeof(path), "%s/%s", directory, name);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return ZCL_ERR(-1, "Preview file could not be created.");
    size_t offset = 0;
    while (offset < size) {
        ssize_t n = write(fd, bytes + offset, size - offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        offset += (size_t)n;
    }
    bool ok = offset == size && fsync(fd) == 0;
    if (close(fd) != 0) ok = false;
    if (!ok) return ZCL_ERR(-1, "Preview file could not be completed.");
    return ZCL_OK;
}

static struct zcl_result tu_read(const char *directory, const char *name,
                                 unsigned char *bytes, size_t capacity, size_t *size)
{
    char path[256];
    (void)snprintf(path, sizeof(path), "%s/%s", directory, name);
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return ZCL_ERR(-1, "Preview output is missing.");
    struct stat st;
    bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_nlink == 1 &&
        st.st_uid == geteuid() && st.st_size >= 0 && (uint64_t)st.st_size < capacity;
    size_t offset = 0, length = ok ? (size_t)st.st_size : 0;
    while (ok && offset < length) {
        ssize_t n = read(fd, bytes + offset, length - offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { ok = false; break; }
        offset += (size_t)n;
    }
    if (close(fd) != 0) ok = false;
    if (!ok) return ZCL_ERR(-1, "Preview output is not a bounded private file.");
    bytes[length] = 0;
    *size = length;
    return ZCL_OK;
}

static void tu_remove(struct task_update_job *job)
{
    if (!job->scratch[0]) return;
    static const char *const names[] = { "state", "undo", "state.out", "undo.out",
        "view", "child", "cancel" };
    char path[256];
    for (size_t i = 0; i < sizeof(names)/sizeof(names[0]); ++i) {
        (void)snprintf(path, sizeof(path), "%s/%s", job->scratch, names[i]);
        if (unlink(path) != 0 && errno != ENOENT) LOG_ERROR("task-update", "preview cleanup failed");
    }
    if (rmdir(job->scratch) != 0) LOG_ERROR("task-update", "preview directory cleanup failed");
    job->scratch[0] = 0;
}

/* Ask the live supervisor to kill and reap its exact child. Returning false
 * keeps capture alive until the supervisor confirms exit (or its outer bound).
 * Candidate code has no write grant for this control file. */
static bool tu_cancel_probe(void *context)
{
    struct task_update_job *job = context;
    if (atomic_load_explicit(&job->cancelled, memory_order_relaxed)) {
        char path[256];
        (void)snprintf(path, sizeof(path), "%s/cancel", job->scratch);
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0400);
        if (fd >= 0) (void)close(fd);
        else if (errno != EEXIST) LOG_ERROR("task-update", "could not notify preview cancellation");
    }
    return false; // raw-return-ok:supervisor-reaps-before-capture-completes
}

static struct zcl_result tu_inputs(struct task_update_job *job)
{
    (void)snprintf(job->scratch, sizeof(job->scratch), "/tmp/z23-task-preview-XXXXXX");
    if (!mkdtemp(job->scratch)) { job->scratch[0] = 0; return ZCL_ERR(-1, "Preview storage unavailable."); }
    unsigned char bytes[TA_PAYLOAD];
    uint32_t length;
    if (!ta_state_encode(&job->checkpoint.document.state, bytes, &length))
        return ZCL_ERR(-1, "Current tasks cannot be previewed.");
    ZCL_CHECK(tu_write(job->scratch, "state", bytes, length));
    if (!ta_state_encode(&job->checkpoint.document.undo, bytes, &length))
        return ZCL_ERR(-1, "Current undo cannot be previewed.");
    ZCL_CHECK(tu_write(job->scratch, "undo", bytes, length));
    ZCL_CHECK(tu_write(job->scratch, "state.out", NULL, 0));
    ZCL_CHECK(tu_write(job->scratch, "undo.out", NULL, 0));
    return tu_write(job->scratch, "view", NULL, 0);
}

static struct zcl_result tu_view(struct task_update_job *job)
{
    size_t size = 0;
    ZCL_CHECK(tu_read(job->scratch, "view", (unsigned char *)job->view, sizeof(job->view), &size));
    if (!size) return ZCL_ERR(-1, "Preview returned an empty view.");
    for (size_t i = 0; i < size; ++i)
        if (job->view[i] != '\n' && ((unsigned char)job->view[i] < 32 || (unsigned char)job->view[i] > 126))
            return ZCL_ERR(-1, "Preview returned unsupported display text.");
    const char *line = job->view;
    for (uint32_t i = 0; i < job->checkpoint.document.state.count; ++i) {
        const char *end = strchr(line, '\n');
        unsigned long long id = 0;
        int consumed = 0;
        if (!end || sscanf(line, "%llu %n", &id, &consumed) != 1 || consumed <= 0 ||
            line + consumed >= end || id != job->checkpoint.document.state.tasks[i].id)
            return ZCL_ERR(-1, "Preview task rows do not match current task identities.");
        line = end + 1;
    }
    if (job->checkpoint.document.state.count && *line)
        return ZCL_ERR(-1, "Preview returned unexpected task rows.");
    return ZCL_OK;
}

static struct zcl_result tu_compatible(struct task_update_job *job)
{
    unsigned char expected[TA_PAYLOAD], actual[TA_PAYLOAD + 1u];
    const struct ta_state *states[] = { &job->checkpoint.document.state, &job->checkpoint.document.undo };
    const char *names[] = { "state.out", "undo.out" };
    for (size_t i = 0; i < 2; ++i) {
        uint32_t length = 0;
        size_t received = 0;
        if (!ta_state_encode(states[i], expected, &length)) return ZCL_ERR(-1, "Task codec failed.");
        ZCL_CHECK(tu_read(job->scratch, names[i], actual, sizeof(actual), &received));
        if (received != length || memcmp(expected, actual, length) != 0)
            return ZCL_ERR(-1, "This program cannot preserve current tasks and undo. Working version retained.");
    }
    return tu_view(job);
}

/* This supervisor-owned record is published before candidate release. A dead
 * helper cannot strand a live leaf merely by losing its process group. Never
 * signal a recycled PID whose kernel birth token differs. */
static struct zcl_result tu_stop_orphan(struct task_update_job *job)
{
    unsigned char record[128];
    size_t length = 0;
    struct zcl_result read = tu_read(job->scratch, "child", record, sizeof(record), &length);
    if (!read.ok) {
        char path[256];
        struct stat st;
        (void)snprintf(path, sizeof(path), "%s/child", job->scratch);
        if (lstat(path, &st) != 0 && errno == ENOENT) return ZCL_OK;
        return ZCL_ERR(-1, "Preview cleanup could not read the supervisor identity.");
    }
    unsigned long long pid = 0, token = 0;
    char extra;
    if (sscanf((const char *)record, "%llu %llu %c", &pid, &token, &extra) != 2 ||
        !pid || pid > INT32_MAX || !token)
        return ZCL_ERR(-1, "Preview supervisor record is invalid; execution was refused.");
    uint64_t actual = 0;
    if (os_proc_pid_liveness(pid) == OS_PROC_LIVENESS_DEAD) return ZCL_OK;
    if (!os_proc_pid_start_token(pid, &actual))
        return ZCL_ERR(-1, "Preview cleanup could not verify the child identity.");
    if (actual != token) return ZCL_OK;
    if (kill((pid_t)pid, SIGKILL) != 0 && errno != ESRCH)
        return ZCL_ERR(-1, "Preview cleanup could not stop the interrupted child.");
    return ZCL_OK;
}

static struct zcl_result tu_execute(struct task_update_job *job, struct package_resident *image)
{
    tu_stage(job, TASK_UPDATE_INPUTS);
    ZCL_CHECK(tu_inputs(job));
    char directory[256], locator[256], nonce[80], reply[256];
    (void)snprintf(directory, sizeof(directory), "--app-preview=%s", job->scratch);
    (void)snprintf(locator, sizeof(locator), "--image=%s", image->snapshot_image);
    (void)snprintf(job->nonce, sizeof(job->nonce), "%s", image->launch.nonce);
    (void)snprintf(nonce, sizeof(nonce), "--nonce=%s", job->nonce);
    const char *const argv[] = { job->verifier, directory, locator, nonce,
        "--require-full-isolation", "--accept-execution", NULL };
    bool cancelled = false;
    tu_stage(job, TASK_UPDATE_EXECUTE);
    int rc = zcl_spawn_capture_cancelable(argv, reply, sizeof(reply), 10000,
        tu_cancel_probe, job, &cancelled);
    ZCL_CHECK(tu_stop_orphan(job));
    if (atomic_load_explicit(&job->cancelled, memory_order_relaxed))
        return ZCL_ERR(-1, "Preview cancelled. Working version and data retained.");
    unsigned long long pid = 0, token = 0, confined_us = 0;
    long long entered_us = 0;
    char returned_nonce[65], trailing;
    if (rc != 0 || sscanf(reply, "app-preview-ok %llu %llu %64s %lld %llu %c", &pid, &token, returned_nonce, &entered_us, &confined_us, &trailing) != 5 ||
        !pid || !token || token > INT64_MAX || strcmp(returned_nonce, job->nonce) != 0 ||
        entered_us < job->step_started_us || entered_us > platform_time_monotonic_us() || confined_us > UINT64_C(10000000))
        return ZCL_ERR(-1, "Program did not demonstrate compatibility with current tasks and undo. Working version retained.");
    job->token = (uint64_t)token;
    job->helper_startup_us = entered_us - job->step_started_us;
    job->confined_us = (int64_t)confined_us;
    tu_stage(job, TASK_UPDATE_COMPATIBILITY);
    return tu_compatible(job);
}
#else
static void tu_remove(struct task_update_job *job) { (void)job; }
static struct zcl_result tu_execute(struct task_update_job *job, struct package_resident *image)
{
    (void)job; (void)image;
    return ZCL_ERR(-1, "Confined task previews are unavailable on this platform.");
}
#endif

static struct zcl_result tu_guard(void *context, struct package_resident_store *store,
                                  const struct package_resident_identity *target)
{
    struct task_update_job *job = context;
    if (!package_resident_identity_equal(target, &job->target))
        return ZCL_ERR(-1, "Program changed. Start a fresh preview.");
    return task_document_check_current(store, &job->checkpoint);
}

static struct zcl_result tu_switch(struct task_update_job *job, struct package_resident_store *store)
{
    if (atomic_load_explicit(&job->cancelled, memory_order_relaxed))
        return ZCL_ERR(-1, "Update cancelled. Working version retained.");
    tu_stage(job, TASK_UPDATE_COMMIT);
    struct package_resident_guard guard = { .context = job, .check = tu_guard };
    if (job->go_back)
        return package_resident_record_rollback_checked(store, job->record.revision,
            job->record.generation, job->nonce, job->token, &guard, &job->record);
    return package_resident_record_activate_checked(store, job->record.revision,
        job->record.generation, job->nonce, job->token, &guard, &job->record);
}

static struct zcl_result tu_probe(struct task_update_job *job, struct package_resident_store *store)
{
    ZCL_CHECK(package_resident_record_read(store, &job->record));
    if (job->go_back) job->target = job->record.previous;
    if (job->refresh) job->target = job->record.current;
    uint8_t root[32], receipt[32];
    if (!zcl_hex_decode_lower(job->target.package_root, root, 32) ||
        !zcl_hex_decode_lower(job->target.receipt_id, receipt, 32))
        return ZCL_ERR(-1, "No exact program is available for this action.");
    tu_stage(job, TASK_UPDATE_VERIFY);
    struct package_resident_artifact artifact;
    ZCL_CHECK(package_resident_artifact_read(job->directory, root, receipt, job->target.program, &artifact));
    if (job->target.artifact_sha3[0] && strcmp(job->target.artifact_sha3, artifact.accepted.image_sha3_hex) != 0)
        return ZCL_ERR(-1, "Installed program differs from the accepted version.");
    (void)snprintf(job->target.artifact_sha3, sizeof(job->target.artifact_sha3), "%s", artifact.accepted.image_sha3_hex);
    if (!job->target.configuration_generation) job->target.configuration_generation = 1;
    tu_stage(job, TASK_UPDATE_DATA);
    ZCL_CHECK(task_document_capture(store, &job->checkpoint));
    if (!job->refresh) ZCL_CHECK(package_resident_record_begin(store, job->record.generation, &job->record));
    struct package_resident *image = NULL;
    tu_stage(job, TASK_UPDATE_SNAPSHOT);
    struct zcl_result result = tu_image(job, &artifact, &image);
    if (result.ok) result = tu_execute(job, image);
    tu_stage(job, TASK_UPDATE_CLEANUP);
    tu_remove(job);
    if (!result.ok || job->refresh) return result;
    if (job->go_back) return tu_switch(job, store);
    tu_stage(job, TASK_UPDATE_COMMIT);
    return package_resident_record_accept(store, job->record.revision, job->record.generation,
        &job->target, job->nonce, job->token, &job->record);
}

static void *tu_work(void *context)
{
    struct task_update_job *job = context;
    (void)zcl_thread_qos_background();
    int64_t began = platform_time_monotonic_us();
    job->step_started_us = began;
    struct package_resident_store store = {0};
    job->result = package_resident_store_open_app(&store, job->directory, job->app);
    if (job->result.ok) job->result = job->keep ? tu_switch(job, &store) : tu_probe(job, &store);
    struct zcl_result closed = package_resident_store_close(&store);
    if (job->result.ok && !closed.ok) job->result = closed;
    tu_stage(job, TASK_UPDATE_STEP_COUNT);
    job->elapsed_us = platform_time_monotonic_us() - began;
    atomic_store_explicit(&job->completed, true, memory_order_release);
    return NULL;
}

static struct zcl_result tu_start(struct task_update *update, struct task_update_job *job)
{
    atomic_init(&job->step, TASK_UPDATE_STORAGE);
    memset(job->step_us, 0, sizeof(job->step_us));
    job->helper_startup_us = job->confined_us = 0;
    update->step = TASK_UPDATE_STORAGE;
    atomic_init(&job->completed, false);
    atomic_init(&job->cancelled, false);
    // thread-supervision-ok:bounded-one-shot owner joins verifier and durable transition
    int rc = thread_registry_spawn("task-preview", tu_work, job, &job->thread);
    if (rc) { free(job); return tu_failure(update, ZCL_ERR(rc, "Could not start preview worker.")); }
    update->pending = job;
    update->phase = job->keep ? TASK_UPDATE_KEEPING : TASK_UPDATE_RUNNING;
    (void)snprintf(update->message, sizeof(update->message), "%s",
        job->keep ? "Keeping..." : job->go_back ? "Checking previous program against current data..." : "Preparing isolated preview...");
    return ZCL_OK;
}

struct zcl_result task_update_open(struct task_update *update, const char *directory,
    const char *app, const char *verifier, const struct package_resident_identity *candidate)
{
    if (!update || !directory || !app || !verifier || directory[0] != '/' || verifier[0] != '/' ||
        strlen(directory) >= sizeof(update->directory) || strlen(app) >= sizeof(update->app) ||
        strlen(verifier) >= sizeof(update->verifier)) return ZCL_ERR(-1, "Task update needs bounded private paths.");
    *update = (struct task_update){0};
    (void)snprintf(update->directory, sizeof(update->directory), "%s", directory);
    (void)snprintf(update->app, sizeof(update->app), "%s", app);
    (void)snprintf(update->verifier, sizeof(update->verifier), "%s", verifier);
    if (candidate) update->candidate = *candidate;
    update->candidate_explicit = candidate && candidate->package_root[0];
    (void)snprintf(update->message, sizeof(update->message), "Try runs this program separately with copies of your tasks. Keep never imports preview data.");
    return ZCL_OK;
}

static struct zcl_result tu_new(struct task_update *update, bool go_back, bool refresh)
{
    if (update->pending) return tu_failure(update, ZCL_ERR(-1, "A preview or update is still running."));
    if (!update->images) {
        update->images = zcl_calloc(1, sizeof(*update->images), "task.preview.images");
        if (!update->images) return tu_failure(update, ZCL_ERR(-1, "Preview image allocation failed."));
        for (unsigned i = 0; i < 2; ++i) package_resident_init(&update->images->slots[i]);
    }
    struct task_update_job *job = zcl_calloc(1, sizeof(*job), "task.preview");
    if (!job) return tu_failure(update, ZCL_ERR(-1, "Preview allocation failed."));
    (void)snprintf(job->directory, sizeof(job->directory), "%s", update->directory);
    (void)snprintf(job->app, sizeof(job->app), "%s", update->app);
    (void)snprintf(job->verifier, sizeof(job->verifier), "%s", update->verifier);
    job->target = update->candidate;
    job->images = update->images;
    job->go_back = go_back;
    job->refresh = refresh;
    if (!refresh) { free(update->ready); update->ready = NULL; update->preview[0] = 0; }
    return tu_start(update, job);
}

struct zcl_result task_update_try(struct task_update *update, bool permission, bool go_back)
{
    if (!update) return ZCL_ERR(-1, "Task update owner required.");
    if (!permission) return tu_failure(update, ZCL_ERR(-1, "Permission required before preview execution."));
    return tu_new(update, go_back, false);
}

struct zcl_result task_update_refresh(struct task_update *update)
{
    if (!update) return ZCL_ERR(-1, "Task update owner required.");
    return tu_new(update, false, true);
}

struct zcl_result task_update_keep(struct task_update *update)
{
    if (!update || update->pending || !update->ready)
        return ZCL_ERR(-1, "Wait for a successful preview before choosing Keep.");
    struct task_update_job *job = update->ready;
    update->ready = NULL;
    job->keep = true;
    return tu_start(update, job);
}

void task_update_cancel(struct task_update *update)
{
    if (!update) { LOG_ERROR("task-update", "cancel requires owner"); return; }
    update->offer_locked = false;
    free(update->ready);
    update->ready = NULL;
    if (update->pending) {
        atomic_store_explicit(&update->pending->cancelled, true, memory_order_relaxed);
        (void)snprintf(update->message, sizeof(update->message), "Cancelling...");
    } else {
        update->phase = TASK_UPDATE_CANCELLED;
        (void)snprintf(update->message, sizeof(update->message), "Preview cancelled. Working version and data retained.");
    }
}

static struct zcl_result tu_kept(struct task_update *update, const struct task_update_job *job)
{
    (void)snprintf(update->active, sizeof(update->active), "%s", job->view);
    update->active_revision = job->checkpoint.document.state.revision;
    update->active_valid = true;
    update->phase = TASK_UPDATE_KEPT;
    (void)snprintf(update->message, sizeof(update->message), "%s",
        job->go_back ? "Previous program restored. Current tasks and undo preserved." : "Current program is ready. Your task data is unchanged.");
    if (!job->keep) return ZCL_OK;
    struct zcl_result result = task_update_acknowledge_offer(update);
    if (!result.ok) {
        result = ZCL_ERR(result.code, "Program kept. Update notice could not be cleared: %.150s", result.message);
        (void)snprintf(update->message, sizeof(update->message), "%s", result.message);
    }
    return result;
}

struct zcl_result task_update_poll(struct task_update *update, bool *changed)
{
    if (!update || !changed) return ZCL_ERR(-1, "Task update owner and changed output required.");
    *changed = false;
    struct task_update_job *job = update->pending;
    if (!job || !atomic_load_explicit(&job->completed, memory_order_acquire)) return tu_progress(update, job, changed);
    int rc = pthread_join(job->thread, NULL);
    if (rc) return tu_failure(update, ZCL_ERR(rc, "Preview worker release failed."));
    update->pending = NULL;
    *changed = true;
    update->elapsed_us = job->elapsed_us;
    update->helper_startup_us = job->helper_startup_us;
    update->confined_us = job->confined_us;
    memcpy(update->step_us, job->step_us, sizeof(update->step_us));
    struct zcl_result result = job->result;
    if (result.ok && (job->keep || job->go_back || job->refresh)) {
        result = tu_kept(update, job);
    } else if (result.ok) {
        (void)snprintf(update->preview, sizeof(update->preview), "%s", job->view);
        update->phase = TASK_UPDATE_READY;
        update->ready = job;
        (void)snprintf(update->message, sizeof(update->message), "Preview ready. Keep checks for edits made since it started.");
    } else {
        if (job->refresh) update->active_valid = false;
        (void)tu_failure(update, result);
        if (atomic_load_explicit(&job->cancelled, memory_order_relaxed)) update->phase = TASK_UPDATE_CANCELLED;
    }
    if (update->ready != job) free(job);
    return result;
}

struct zcl_result task_update_finish(struct task_update *update)
{
    if (!update) return ZCL_ERR(-1, "Task update owner required.");
    task_update_cancel(update);
    if (update->pending) {
        int rc = pthread_join(update->pending->thread, NULL);
        if (rc) return ZCL_ERR(rc, "Preview worker release failed.");
        free(update->pending);
        update->pending = NULL;
    }
    struct zcl_result result = ZCL_OK;
    if (update->images) {
        for (unsigned i = 0; i < 2; ++i) {
            struct zcl_result closed = package_resident_close(&update->images->slots[i]);
            if (!closed.ok) result = closed;
        }
        if (result.ok) { free(update->images); update->images = NULL; }
    }
    return result;
}
