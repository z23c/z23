/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_status — pre-RPC boot-progress beacon. See util/boot_status.h for the
 * contract and rationale. This file owns the writer's small global state, the
 * canonical JSON serialization, and the node-free reader. */

#include "util/boot_status.h"
#include "util/boot_phase.h"   /* enum boot_stage (writer-side derivation only) */
#include "util/log_macros.h"
#include "platform/time_compat.h"
#include "json/json.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ── Writer state ─────────────────────────────────────────────────────
 * Boot is single-threaded through app_init, but the stage machine and the
 * height setter are separate call sites, so a small mutex keeps every file
 * rewrite atomic and the shared fields consistent. */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static char    g_datadir[512];      /* empty => writer disarmed */
static int     g_stage_ordinal = (int)BOOT_STAGE_INIT;
static int64_t g_height = -1;
static int64_t g_started_unix;
static int64_t g_started_mono_ms;
static int64_t g_last_heartbeat_unix;
static char    g_activity[64];
static int64_t g_progress_current = -1;
static int64_t g_progress_target = -1;
static int64_t g_progress_published_mono_ms;
/* blocker-ok:boot_status_beacon — this is not a blocker recorder, it is the
 * on-disk beacon a blocker gets COPIED into. The typed registry
 * (lib/util/blocker.h) lives in RAM and dies with the process, so a boot
 * that names a blocker and then exits would leave the file reading
 * phase=loading with no reason in it — indistinguishable from a hang. The
 * raise site is still a real blocker_set(); these two strings only carry its
 * id and reason across the exit. Nothing here decides, rate-limits or
 * escapes anything. */
static char    g_blocker[64];
static char    g_blocker_reason[256];

/* ── Phase derivation (pure) ─────────────────────────────────────────── */
const char *boot_status_phase_for_stage(int stage, bool *rpc_bound,
                                         bool *serving)
{
    bool rb = false, sv = false;
    const char *phase;

    switch ((enum boot_stage)stage) {
    case BOOT_STAGE_INIT:
    case BOOT_STAGE_DATADIR_LOCKED:
        phase = "starting";
        break;
    case BOOT_STAGE_CRYPTO_READY:
    case BOOT_STAGE_DB_OPEN:
    case BOOT_STAGE_WALLET_LOADED:
        phase = "loading";
        break;
    case BOOT_STAGE_BLOCK_INDEX_LOADED:
    case BOOT_STAGE_CHAIN_TIP_RESOLVED:
        phase = "chain";
        break;
    case BOOT_STAGE_NETWORK_READY:
    case BOOT_STAGE_SERVICES_RUNNING:
        phase = "network";
        break;
    case BOOT_STAGE_READY:
        phase = "serving";
        rb = true;
        sv = true;
        break;
    case BOOT_STAGE_SHUTDOWN_REQUESTED:
    case BOOT_STAGE_SHUTDOWN_COMPLETE:
        phase = "shutdown";
        break;
    default:
        phase = "unknown";
        break;
    }
    if (rpc_bound)
        *rpc_bound = rb;
    if (serving)
        *serving = sv;
    return phase;
}

/* ── Serialization (pure) ────────────────────────────────────────────── */
size_t boot_status_write_json(const struct boot_status_snapshot *snap,
                              char *buf, size_t buflen)
{
    if (!snap || !buf || buflen == 0)
        return 0;

    struct json_value root;
    json_init(&root);
    json_set_object(&root);
    (void)json_push_kv_str(&root, "schema", ZCL_BOOT_STATUS_SCHEMA);
    (void)json_push_kv_str(&root, "phase", snap->phase);
    (void)json_push_kv_str(&root, "stage", snap->stage);
    (void)json_push_kv_int(&root, "stage_ordinal", snap->stage_ordinal);
    (void)json_push_kv_int(&root, "height", snap->height);
    (void)json_push_kv_bool(&root, "rpc_bound", snap->rpc_bound);
    (void)json_push_kv_bool(&root, "serving", snap->serving);
    (void)json_push_kv_int(&root, "started_unix", snap->started_unix);
    (void)json_push_kv_int(&root, "updated_unix", snap->updated_unix);
    (void)json_push_kv_int(&root, "elapsed_s", snap->elapsed_s);
    if (snap->activity[0]) {
        (void)json_push_kv_str(&root, "activity", snap->activity);
        (void)json_push_kv_int(&root, "progress_current",
                               snap->progress_current);
        (void)json_push_kv_int(&root, "progress_target",
                               snap->progress_target);
    }
    /* Emitted only once a boot has named why it stopped, so an ordinary
     * beacon keeps exactly the v1 field set and a reader can tell "still
     * climbing" from "stopped, and here is the reason" by presence. */
    if (snap->blocker[0]) {
        (void)json_push_kv_str(&root, "blocker", snap->blocker);
        (void)json_push_kv_str(&root, "blocker_reason", snap->blocker_reason);
    }

    size_t n = json_write(&root, buf, buflen);
    json_free(&root);
    if (n == 0 || n >= buflen)
        return 0;
    return n;
}

/* Build a snapshot from the current (locked) writer state. */
static void boot_status_snapshot_locked(struct boot_status_snapshot *out)
{
    memset(out, 0, sizeof(*out));
    bool rb = false, sv = false;
    const char *phase = boot_status_phase_for_stage(g_stage_ordinal, &rb, &sv);
    snprintf(out->phase, sizeof(out->phase), "%s", phase);
    snprintf(out->stage, sizeof(out->stage), "%s",
             boot_stage_name((enum boot_stage)g_stage_ordinal));
    out->stage_ordinal = g_stage_ordinal;
    out->height = g_height;
    out->rpc_bound = rb;
    out->serving = sv;
    out->started_unix = g_started_unix;
    out->updated_unix = platform_time_wall_unix();
    out->elapsed_s = out->updated_unix - g_started_unix;
    if (out->elapsed_s < 0)
        out->elapsed_s = 0;
    snprintf(out->activity, sizeof(out->activity), "%s", g_activity);
    out->progress_current = g_progress_current;
    out->progress_target = g_progress_target;
    snprintf(out->blocker, sizeof(out->blocker), "%s", g_blocker);
    snprintf(out->blocker_reason, sizeof(out->blocker_reason), "%s",
             g_blocker_reason);
}

/* Atomically publish the beacon: write to a tmp sibling then rename over the
 * target. A reader thus always sees a complete document — the old one or the
 * new one, never a torn write. Best-effort: logs a warning and continues on
 * failure so boot never depends on observability succeeding. Caller holds
 * g_lock. */
static void boot_status_publish_locked(void)
{
    if (g_datadir[0] == '\0')
        return;

    struct boot_status_snapshot snap;
    boot_status_snapshot_locked(&snap);

    /* Sized for the base document PLUS a named blocker's id and its
     * 256-byte reason: a beacon that could not serialize is dropped, and
     * dropping the one write that explains why the node stopped is the
     * exact failure this field was added to remove. */
    char json[2048];
    size_t n = boot_status_write_json(&snap, json, sizeof(json));
    if (n == 0) {
        LOG_WARN("boot_status", "serialize failed (stage=%s)", snap.stage);
        return;
    }

    char final_path[600];
    char tmp_path[640];
    snprintf(final_path, sizeof(final_path), "%s/%s", g_datadir,
             ZCL_BOOT_STATUS_FILENAME);
    snprintf(tmp_path, sizeof(tmp_path), "%s/%s.tmp.%ld", g_datadir,
             ZCL_BOOT_STATUS_FILENAME, (long)getpid());

    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        LOG_WARN("boot_status", "open(%s) failed: %s", tmp_path,
                 strerror(errno));
        return;
    }
    ssize_t w = write(fd, json, n);
    if (w < 0 || (size_t)w != n) {
        LOG_WARN("boot_status", "short write to %s (%zd/%zu)", tmp_path, w, n);
        close(fd);
        (void)unlink(tmp_path);
        return;
    }
    (void)fsync(fd);
    if (close(fd) != 0) {
        LOG_WARN("boot_status", "close(%s) failed: %s", tmp_path,
                 strerror(errno));
        (void)unlink(tmp_path);
        return;
    }
    if (rename(tmp_path, final_path) != 0) {
        LOG_WARN("boot_status", "rename(%s -> %s) failed: %s", tmp_path,
                 final_path, strerror(errno));
        (void)unlink(tmp_path);
    }
}

/* ── Public writer API ───────────────────────────────────────────────── */
void boot_status_init(const char *datadir)
{
    pthread_mutex_lock(&g_lock);
    if (!datadir || !datadir[0]) {
        g_datadir[0] = '\0';       /* disarm */
        pthread_mutex_unlock(&g_lock);
        return;
    }
    snprintf(g_datadir, sizeof(g_datadir), "%s", datadir);
    g_stage_ordinal = (int)boot_stage_current();
    g_height = -1;
    g_activity[0] = '\0';
    g_progress_current = -1;
    g_progress_target = -1;
    g_progress_published_mono_ms = 0;
    g_blocker[0] = '\0';
    g_blocker_reason[0] = '\0';
    g_started_unix = platform_time_wall_unix();
    g_started_mono_ms = platform_time_monotonic_ms();
    g_last_heartbeat_unix = 0;
    boot_status_publish_locked();
    pthread_mutex_unlock(&g_lock);
}

void boot_status_note_stage(int stage)
{
    pthread_mutex_lock(&g_lock);
    if (g_datadir[0] != '\0') {
        g_stage_ordinal = stage;
        boot_status_publish_locked();
    }
    pthread_mutex_unlock(&g_lock);
}

void boot_status_set_height(int64_t height)
{
    pthread_mutex_lock(&g_lock);
    if (g_datadir[0] != '\0') {
        g_height = height;
        boot_status_publish_locked();
    }
    pthread_mutex_unlock(&g_lock);
}

void boot_status_heartbeat(void)
{
    pthread_mutex_lock(&g_lock);
    if (g_datadir[0] != '\0') {
        int64_t now = platform_time_wall_unix();
        if (now != g_last_heartbeat_unix) {
            g_last_heartbeat_unix = now;
            boot_status_publish_locked();
        }
    }
    pthread_mutex_unlock(&g_lock);
}

void boot_status_set_progress(const char *activity, int64_t current,
                              int64_t target)
{
    pthread_mutex_lock(&g_lock);
    if (g_datadir[0] == '\0') {
        pthread_mutex_unlock(&g_lock);
        return;
    }

    if (!activity || !activity[0]) {
        g_activity[0] = '\0';
        g_progress_current = -1;
        g_progress_target = -1;
        g_progress_published_mono_ms = 0;
        boot_status_publish_locked();
        pthread_mutex_unlock(&g_lock);
        return;
    }
    if (current < 0 || target < current) {
        LOG_WARN("boot_status",
                 "invalid progress activity=%s current=%lld target=%lld",
                 activity, (long long)current, (long long)target);
        pthread_mutex_unlock(&g_lock);
        return;
    }

    bool activity_changed = strcmp(g_activity, activity) != 0;
    snprintf(g_activity, sizeof(g_activity), "%s", activity);
    g_progress_current = current;
    g_progress_target = target;
    int64_t now = platform_time_monotonic_ms();
    if (activity_changed || current == target ||
        g_progress_published_mono_ms == 0 ||
        now - g_progress_published_mono_ms >= 1000) {
        boot_status_publish_locked();
        g_progress_published_mono_ms = now;
    }
    pthread_mutex_unlock(&g_lock);
}

void boot_status_set_blocker(const char *id, const char *reason)
{
    pthread_mutex_lock(&g_lock);
    if (!id || !id[0]) {
        g_blocker[0] = '\0';
        g_blocker_reason[0] = '\0';
    } else {
        snprintf(g_blocker, sizeof(g_blocker), "%s", id);
        snprintf(g_blocker_reason, sizeof(g_blocker_reason), "%s",
                 reason ? reason : "");
    }
    if (g_datadir[0] != '\0')
        boot_status_publish_locked();
    pthread_mutex_unlock(&g_lock);
}

/* ── Reader (node-free) ──────────────────────────────────────────────── */
bool boot_status_read(const char *datadir, struct boot_status_snapshot *out,
                      char *err, size_t errlen)
{
    if (err && errlen)
        err[0] = '\0';
    if (!datadir || !datadir[0] || !out)
        LOG_FAIL("boot_status", "read: datadir/out required");
    memset(out, 0, sizeof(*out));
    out->stage_ordinal = -1;
    out->height = -1;
    out->progress_current = -1;
    out->progress_target = -1;

    char path[600];
    snprintf(path, sizeof(path), "%s/%s", datadir, ZCL_BOOT_STATUS_FILENAME);

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        if (err && errlen)
            snprintf(err, errlen, "no boot_status.json at %s (%s)", path,
                     strerror(errno));
        return false;
    }
    char raw[4096];
    ssize_t r = read(fd, raw, sizeof(raw) - 1);
    close(fd);
    if (r <= 0) {
        if (err && errlen)
            snprintf(err, errlen, "boot_status.json empty or unreadable");
        return false;
    }
    raw[r] = '\0';

    struct json_value doc;
    if (!json_read(&doc, raw, (size_t)r) || doc.type != JSON_OBJ) {
        json_free(&doc);
        if (err && errlen)
            snprintf(err, errlen, "boot_status.json is not a JSON object");
        return false;
    }

    const struct json_value *schema = json_get(&doc, "schema");
    const struct json_value *phase = json_get(&doc, "phase");
    const struct json_value *stage = json_get(&doc, "stage");
    const struct json_value *ord = json_get(&doc, "stage_ordinal");
    const struct json_value *h = json_get(&doc, "height");
    const struct json_value *rpc_bound = json_get(&doc, "rpc_bound");
    const struct json_value *serving = json_get(&doc, "serving");
    const struct json_value *started = json_get(&doc, "started_unix");
    const struct json_value *updated = json_get(&doc, "updated_unix");
    const struct json_value *elapsed = json_get(&doc, "elapsed_s");
    if (!schema || schema->type != JSON_STR ||
        strcmp(json_get_str(schema), ZCL_BOOT_STATUS_SCHEMA) != 0 ||
        !phase || phase->type != JSON_STR ||
        !stage || stage->type != JSON_STR ||
        !ord || ord->type != JSON_INT || !h || h->type != JSON_INT ||
        !rpc_bound || rpc_bound->type != JSON_BOOL ||
        !serving || serving->type != JSON_BOOL ||
        !started || started->type != JSON_INT ||
        !updated || updated->type != JSON_INT ||
        !elapsed || elapsed->type != JSON_INT) {
        json_free(&doc);
        if (err && errlen)
            snprintf(err, errlen, "boot_status.json schema or required field type is invalid");
        return false;
    }

    int64_t ord64 = json_get_int(ord);
    int64_t started64 = json_get_int(started);
    int64_t updated64 = json_get_int(updated);
    int64_t elapsed64 = json_get_int(elapsed);
    if (ord64 < 0 || ord64 >= BOOT_STAGE__MAX || json_get_int(h) < -1 ||
        started64 < 0 || updated64 < 0 || elapsed64 < 0 ||
        elapsed64 != (updated64 >= started64 ? updated64 - started64 : 0)) {
        json_free(&doc);
        if (err && errlen)
            snprintf(err, errlen, "boot_status.json numeric invariant is invalid");
        return false;
    }
    bool expected_rpc = false, expected_serving = false;
    const char *expected_phase = boot_status_phase_for_stage(
        (int)ord64, &expected_rpc, &expected_serving);
    const char *expected_stage = boot_stage_name((enum boot_stage)ord64);
    if (strcmp(json_get_str(phase), expected_phase) != 0 ||
        strcmp(json_get_str(stage), expected_stage) != 0 ||
        json_get_bool(rpc_bound) != expected_rpc ||
        json_get_bool(serving) != expected_serving) {
        json_free(&doc);
        if (err && errlen)
            snprintf(err, errlen, "boot_status.json stage/phase state is contradictory");
        return false;
    }

    snprintf(out->phase, sizeof(out->phase), "%s", json_get_str(phase));
    snprintf(out->stage, sizeof(out->stage), "%s", json_get_str(stage));
    out->stage_ordinal = (int32_t)ord64;
    out->height = json_get_int(h);
    out->rpc_bound = json_get_bool(rpc_bound);
    out->serving = json_get_bool(serving);
    out->started_unix = started64;
    out->updated_unix = updated64;
    out->elapsed_s = elapsed64;

    const struct json_value *activity = json_get(&doc, "activity");
    const struct json_value *progress_current =
        json_get(&doc, "progress_current");
    const struct json_value *progress_target =
        json_get(&doc, "progress_target");
    if (activity || progress_current || progress_target) {
        if (!activity || activity->type != JSON_STR ||
            !progress_current || progress_current->type != JSON_INT ||
            !progress_target || progress_target->type != JSON_INT ||
            !json_get_str(activity)[0] ||
            strlen(json_get_str(activity)) >= sizeof(out->activity) ||
            json_get_int(progress_current) < 0 ||
            json_get_int(progress_target) < json_get_int(progress_current) ||
            expected_serving) {
            json_free(&doc);
            if (err && errlen)
                snprintf(err, errlen, "boot_status.json progress fields are invalid");
            return false;
        }
        snprintf(out->activity, sizeof(out->activity), "%s",
                 json_get_str(activity));
        out->progress_current = json_get_int(progress_current);
        out->progress_target = json_get_int(progress_target);
    }
    /* Optional: absent on every boot that has not stopped on purpose. Read
     * through a NULL-guard because json_get_str of a missing key is not a
     * string and printing it would be the reader's own silent lie. */
    {
        const struct json_value *bv = json_get(&doc, "blocker");
        const struct json_value *brv = json_get(&doc, "blocker_reason");
        if ((bv || brv) &&
            (!bv || bv->type != JSON_STR || !brv || brv->type != JSON_STR ||
             !json_get_str(bv)[0] ||
             strlen(json_get_str(bv)) >= sizeof(out->blocker) ||
             strlen(json_get_str(brv)) >= sizeof(out->blocker_reason))) {
            json_free(&doc);
            if (err && errlen)
                snprintf(err, errlen, "boot_status.json blocker fields are invalid");
            return false;
        }
        snprintf(out->blocker, sizeof(out->blocker), "%s",
                 bv ? json_get_str(bv) : "");
        snprintf(out->blocker_reason, sizeof(out->blocker_reason), "%s",
                 brv ? json_get_str(brv) : "");
    }

    json_free(&doc);
    return true;
}
