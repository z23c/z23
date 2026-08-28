/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * canary_sentinel_watch — see services/canary_sentinel_watch.h for the
 * contract (sentinel format, absence/staleness policy). This file is a pure
 * file-scan observer: no DB writes, no threads, no chain locks. */

// one-result-type-ok:canary-watch-observer-no-fallible-surface
//
// This is a read-only sentinel observer, not a fallible service executor.
// Its surfaces are: a void tick (absence of dir/files is a documented quiet
// no-op, never an error a caller branches on), bool predicates/probes
// (fail_active, resolve_dir), and the project-wide bool dump_state_json
// convention. Failure detail travels via the Condition's LOG_WARN + the
// dump, not a result object.

#include "services/canary_sentinel_watch.h"

#include "crypto/sha256.h"
#include "framework/condition.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "platform/file_metadata.h"
#include "platform/os_proc.h"
#include "platform/positioned_file.h"
#include "platform/time_compat.h"
#include "util/clientversion.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CANARY_WATCH_MAX_KINDS     8
#define CANARY_KIND_NAME_MAX       32
#define CANARY_VERDICT_MAX         16
#define CANARY_REASON_MAX          96
#define CANARY_COMMIT_MAX          128
#define CANARY_SOURCE_ID_MAX       65
#define CANARY_ARTIFACT_ID_MAX     65
#define CANARY_PATH_MAX          4096
/* A sentinel is one flat JSON object (~400 bytes); anything larger than this
 * is not a canary verdict and is treated as unreadable. */
#define CANARY_SENTINEL_MAX_BYTES  8192

#define CANARY_SENTINEL_PREFIX     "replay_canary_"
#define CANARY_SENTINEL_SUFFIX     ".json"

struct canary_kind_slot {
    bool    used;
    bool    fail;                       /* latched: latest verdict == FAIL */
    char    kind[CANARY_KIND_NAME_MAX];
    char    from[CANARY_KIND_NAME_MAX]; /* sentinel's own `from` — display only */
    char    verdict[CANARY_VERDICT_MAX];
    char    reason[CANARY_REASON_MAX];
    char    latched_reason[CANARY_REASON_MAX]; /* last authoritative FAIL */
    char    source_id_sha256[CANARY_SOURCE_ID_MAX];
    char    artifact_sha256[CANARY_ARTIFACT_ID_MAX];
    char    build_commit[CANARY_COMMIT_MAX]; /* display-only Git trace */
    bool    stale_build;                /* source ID differs → no mutation */
    bool    stale_run;                  /* run predates process → no mutation */
    bool    clear_rejected;              /* PASS/unknown lacked exact authority */
    int64_t ts;                         /* sentinel's own write-time epoch */
    int64_t started_ts;                 /* sentinel's own run-start epoch */
    int64_t latched_ts;                 /* last authoritative FAIL write time */
    int64_t parse_fail_logged_mtime;    /* log-once-per-mtime for torn JSON */
    int64_t stale_build_logged_mtime;   /* log-once-per-mtime for stale-build */
    int64_t stale_run_logged_mtime;     /* log-once-per-mtime for stale-run */
    int64_t clear_rejected_logged_mtime;/* log-once for untrusted clear */
};

static struct {
    pthread_mutex_t lock;
    struct canary_kind_slot slots[CANARY_WATCH_MAX_KINDS];
    _Atomic int64_t last_scan_unix;
    _Atomic int64_t scans_total;
    _Atomic int64_t files_seen_last;
    _Atomic int64_t parse_failures_logged;
    _Atomic int64_t process_start_unix;
    _Atomic bool    fail_latched;
} g_watch = { .lock = PTHREAD_MUTEX_INITIALIZER };

static pthread_once_t g_artifact_once = PTHREAD_ONCE_INIT;
static char g_running_artifact_sha256[CANARY_ARTIFACT_ID_MAX];

static void capture_running_artifact_sha256(void)
{
    FILE *image = os_proc_open_self_exe();
    if (!image)
        return;
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    uint8_t buf[32768];
    bool ok = true;
    for (;;) {
        size_t n = fread(buf, 1, sizeof(buf), image);
        if (n > 0) {
            sha256_write(&ctx, buf, n);
            continue;
        }
        if (feof(image))
            break;
        ok = false;
        break;
    }
    if (fclose(image) != 0)
        ok = false;
    if (!ok)
        return;
    uint8_t digest[32];
    static const char hex[] = "0123456789abcdef";
    sha256_finalize(&ctx, digest);
    for (size_t i = 0; i < sizeof(digest); i++) {
        g_running_artifact_sha256[i * 2] = hex[digest[i] >> 4];
        g_running_artifact_sha256[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    g_running_artifact_sha256[64] = '\0';
}

static const char *running_artifact_sha256(void)
{
    (void)pthread_once(&g_artifact_once, capture_running_artifact_sha256);
    return g_running_artifact_sha256;
}

__attribute__((constructor))
static void canary_sentinel_watch_init_process_start(void)
{
    int64_t now = platform_time_wall_unix();
    if (now > 0)
        atomic_store(&g_watch.process_start_unix, now);
}

bool canary_sentinel_watch_resolve_dir(char *out, size_t cap)
{
    if (!out || cap == 0)
        return false;
    out[0] = '\0';
    const char *env = getenv("ZCL_CANARY_VERDICT_DIR");
    if (env && env[0])
        return snprintf(out, cap, "%s", env) < (int)cap;
#if defined(_WIN32)
    const char *local_app_data = getenv("LOCALAPPDATA");
    if (!local_app_data || !local_app_data[0])
        return false;
    return snprintf(out, cap, "%s/z23/dev/canary", local_app_data) <
           (int)cap;
#else
    const char *home = getenv("HOME");
    if (!home || !home[0])
        return false; /* quiet: no env, no HOME — nothing to watch */
    return snprintf(out, cap, "%s/.local/state/zclassic23-canary", home) <
           (int)cap;
#endif
}

/* Find (or claim) the slot for `kind`. Caller holds g_watch.lock. */
static struct canary_kind_slot *slot_for_kind_locked(const char *kind)
{
    struct canary_kind_slot *free_slot = NULL;
    for (int i = 0; i < CANARY_WATCH_MAX_KINDS; i++) {
        struct canary_kind_slot *s = &g_watch.slots[i];
        if (s->used && strcmp(s->kind, kind) == 0)
            return s;
        if (!s->used && !free_slot)
            free_slot = s;
    }
    if (free_slot) {
        memset(free_slot, 0, sizeof(*free_slot));
        free_slot->used = true;
        snprintf(free_slot->kind, sizeof(free_slot->kind), "%s", kind);
    }
    return free_slot; /* NULL when all slots taken (logged by caller) */
}

/* "replay_canary_<kind>.json" → <kind> into out. False for non-sentinels
 * (wrong prefix/suffix, or an atomic-writer ".tmp." leftover). */
static bool kind_from_filename(const char *name, char *out, size_t cap)
{
    size_t prefix_len = strlen(CANARY_SENTINEL_PREFIX);
    size_t suffix_len = strlen(CANARY_SENTINEL_SUFFIX);
    size_t name_len = strlen(name);
    if (name_len <= prefix_len + suffix_len)
        return false;
    if (strncmp(name, CANARY_SENTINEL_PREFIX, prefix_len) != 0)
        return false;
    if (strcmp(name + name_len - suffix_len, CANARY_SENTINEL_SUFFIX) != 0)
        return false;
    if (strstr(name, ".tmp."))
        return false; /* in-flight atomic-writer temp, never a verdict */
    size_t kind_len = name_len - prefix_len - suffix_len;
    if (kind_len >= cap)
        kind_len = cap - 1;
    memcpy(out, name + prefix_len, kind_len);
    out[kind_len] = '\0';
    return true;
}

/* Read the whole sentinel into a caller buffer (it is a single small JSON
 * line). Returns false on any I/O trouble or oversize. */
static bool read_sentinel(const char *path, char *buf, size_t cap,
                          size_t *out_len)
{
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path))
        return false; /* raced with the harness's rm/rename: not an error */
    uint64_t size = 0;
    if (!platform_positioned_file_size(&file, &size) || size >= cap) {
        platform_positioned_file_close(&file);
        return false;
    }
    int64_t got = platform_positioned_file_read(&file, buf, (size_t)size, 0);
    platform_positioned_file_close(&file);
    if (got < 0 || (uint64_t)got != size)
        return false;
    buf[(size_t)got] = '\0';
    *out_len = (size_t)got;
    return true;
}

static bool canary_source_id_valid(const char *source_id)
{
    if (!source_id || strlen(source_id) != 64)
        return false;
    for (size_t i = 0; i < 64; i++) {
        if (!((source_id[i] >= '0' && source_id[i] <= '9') ||
              (source_id[i] >= 'a' && source_id[i] <= 'f')))
            return false;
    }
    return true;
}

/* Parse one sentinel and fold its verdict into the kind slot. Corrupt/torn
 * JSON is skipped and logged once per file mtime — it NEVER raises alone. */
static void process_sentinel(const char *dir, const char *name)
{
    char kind[CANARY_KIND_NAME_MAX];
    if (!kind_from_filename(name, kind, sizeof(kind)))
        return;

    char path[CANARY_PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/%s", dir, name) >= (int)sizeof(path))
        return;

    struct platform_file_metadata metadata;
    int64_t mtime =
        platform_file_metadata_read(path, &metadata) == PLATFORM_FILE_METADATA_OK
        ? metadata.modified_seconds : 0;

    char raw[CANARY_SENTINEL_MAX_BYTES];
    size_t raw_len = 0;
    bool readable = read_sentinel(path, raw, sizeof(raw), &raw_len);

    struct json_value v;
    json_init(&v);
    bool parsed = readable && json_read(&v, raw, raw_len) &&
                  v.type == JSON_OBJ;

    pthread_mutex_lock(&g_watch.lock);
    struct canary_kind_slot *slot = slot_for_kind_locked(kind);
    if (!slot) {
        pthread_mutex_unlock(&g_watch.lock);
        json_free(&v);
        LOG_WARN("canary_watch", "[canary_watch] kind table full (%d), "
                 "ignoring sentinel %s", CANARY_WATCH_MAX_KINDS, name);
        return;
    }

    if (!parsed) {
        /* Keep the slot's previous verdict — a torn read is transport noise,
         * never a page and never a clear. Log once per mtime, not per tick. */
        bool log_it = slot->parse_fail_logged_mtime != mtime;
        if (log_it)
            slot->parse_fail_logged_mtime = mtime;
        pthread_mutex_unlock(&g_watch.lock);
        json_free(&v);
        if (log_it) {
            atomic_fetch_add(&g_watch.parse_failures_logged, 1);
            LOG_WARN("canary_watch", "[canary_watch] unreadable/corrupt "
                     "sentinel %s (mtime=%lld) — skipped, will not page",
                     name, (long long)mtime);
        }
        return;
    }

    const char *verdict = json_get_str(json_get(&v, "verdict"));
    const char *from    = json_get_str(json_get(&v, "from"));
    const char *reason  = json_get_str(json_get(&v, "reason"));
    const char *sentinel_source_id =
        json_get_str(json_get(&v, "source_id_sha256"));
    const char *sentinel_artifact =
        json_get_str(json_get(&v, "artifact_sha256"));
    const char *scommit = json_get_str(json_get(&v, "build_commit"));
    int64_t ts          = json_get_int(json_get(&v, "ts"));
    int64_t started_ts  = json_get_int(json_get(&v, "started_ts"));

    /* A syntactically valid JSON object is not necessarily a typed sentinel.
     * Normalize every optional/malformed string to empty before strcmp/copy:
     * an unknown verdict then follows the fail-closed clear path, while a
     * missing display field can never become a NULL `%s` argument. */
    if (!verdict) verdict = "";
    if (!from) from = "";
    if (!reason) reason = "";
    if (!sentinel_source_id) sentinel_source_id = "";
    if (!sentinel_artifact) sentinel_artifact = "";
    if (!scommit) scommit = "";

    /* The verdict dir is shared across builds. Only the exact SHA-256 source
     * identity participates in the staleness decision; build_commit is
     * display-only GitHub trace metadata. A legacy sentinel without a valid
     * source ID retains the pre-migration behavior and is not silently
     * discarded. */
    const char *running_source_id = zcl_build_source_id_sha256();
    const char *running_artifact = running_artifact_sha256();
    bool sentinel_source_valid = canary_source_id_valid(sentinel_source_id);
    bool running_source_valid = canary_source_id_valid(running_source_id);
    bool source_ids_comparable = sentinel_source_valid &&
                                 running_source_valid;
    bool exact_source = source_ids_comparable &&
                        strcmp(sentinel_source_id, running_source_id) == 0;
    bool cross_build = source_ids_comparable && !exact_source;
    bool artifact_ids_comparable =
        canary_source_id_valid(sentinel_artifact) &&
        canary_source_id_valid(running_artifact);
    bool exact_artifact = artifact_ids_comparable &&
                          strcmp(sentinel_artifact, running_artifact) == 0;
    bool cross_artifact = artifact_ids_comparable && !exact_artifact;
    int64_t process_start =
        atomic_load_explicit(&g_watch.process_start_unix,
                             memory_order_relaxed);
    bool stale_run = started_ts > 0 && process_start > 0 &&
                     started_ts < process_start;
    bool is_fail = strcmp(verdict, "FAIL") == 0;
    bool is_pass = strcmp(verdict, "PASS") == 0;
    bool current_run = started_ts > 0 && process_start > 0 &&
                       started_ts >= process_start;
    bool authoritative_clear = is_pass && exact_source && exact_artifact &&
                               current_run;
    bool rejected_clear = !is_fail && !authoritative_clear;

    snprintf(slot->verdict, sizeof(slot->verdict), "%s", verdict);
    snprintf(slot->reason, sizeof(slot->reason), "%s", reason);
    snprintf(slot->source_id_sha256, sizeof(slot->source_id_sha256), "%s",
             sentinel_source_id);
    snprintf(slot->artifact_sha256, sizeof(slot->artifact_sha256), "%s",
             sentinel_artifact);
    snprintf(slot->build_commit, sizeof(slot->build_commit), "%s", scommit);
    /* The slot key is the filename-derived kind, ALWAYS. Renaming the slot
     * from the sentinel's `from` field would orphan a FAILed slot if the
     * two ever disagreed (the PASS that should clear it would land in a
     * fresh slot, leaving an un-clearable page). `from` is recorded for
     * display only. */
    snprintf(slot->from, sizeof(slot->from), "%s", from);
    slot->ts = ts;
    slot->started_ts = started_ts;
    slot->stale_build = cross_build || cross_artifact;
    slot->stale_run = stale_run;
    slot->clear_rejected = rejected_clear;
    if (is_fail && !cross_build && !cross_artifact && !stale_run) {
        /* A legacy/malformed identity may conservatively raise, but it can
         * never clear a source-bound latch. Known stale evidence is ignored. */
        slot->fail = true;
        snprintf(slot->latched_reason, sizeof(slot->latched_reason), "%s",
                 reason);
        slot->latched_ts = ts;
    } else if (authoritative_clear && !cross_build && !cross_artifact &&
               !stale_run) {
        slot->fail = false;
        slot->latched_reason[0] = '\0';
        slot->latched_ts = 0;
    }
    slot->parse_fail_logged_mtime = 0; /* readable again: re-arm log-once */

    /* A dropped cross-build FAIL must never be a SILENT swallow (fail-loud
     * doctrine): say so once per mtime, with the build mismatch named. */
    bool log_stale_build = slot->stale_build &&
                           slot->stale_build_logged_mtime != mtime;
    bool log_stale_run = slot->stale_run &&
                         slot->stale_run_logged_mtime != mtime;
    bool log_rejected_clear = slot->clear_rejected &&
        slot->clear_rejected_logged_mtime != mtime;
    char log_kind[CANARY_KIND_NAME_MAX] = {0};
    char log_reason[CANARY_REASON_MAX] = {0};
    char log_source_id[CANARY_SOURCE_ID_MAX] = {0};
    char log_artifact[CANARY_ARTIFACT_ID_MAX] = {0};
    int64_t log_started_ts = 0;
    int64_t log_process_start = 0;
    if (log_stale_build || log_stale_run || log_rejected_clear) {
        if (log_stale_build)
            slot->stale_build_logged_mtime = mtime;
        if (log_stale_run)
            slot->stale_run_logged_mtime = mtime;
        if (log_rejected_clear)
            slot->clear_rejected_logged_mtime = mtime;
        snprintf(log_kind, sizeof(log_kind), "%s", slot->kind);
        snprintf(log_reason, sizeof(log_reason), "%s", slot->reason);
        snprintf(log_source_id, sizeof(log_source_id), "%s",
                 slot->source_id_sha256);
        snprintf(log_artifact, sizeof(log_artifact), "%s",
                 slot->artifact_sha256);
        log_started_ts = slot->started_ts;
        log_process_start = process_start;
    }
    pthread_mutex_unlock(&g_watch.lock);
    json_free(&v);

    if (log_stale_build)
        LOG_INFO("canary_watch", "[canary_watch] ignoring STALE cross-binary "
                 "verdict kind=%s source_id=%s (running=%s) artifact=%s "
                 "(running_artifact=%s) reason=%s "
                 "— latch unchanged", log_kind, log_source_id,
                 running_source_id ? running_source_id : "-", log_artifact,
                 running_artifact && running_artifact[0]
                     ? running_artifact : "-", log_reason);
    if (log_stale_run)
        LOG_INFO("canary_watch", "[canary_watch] ignoring STALE pre-start "
                 "verdict kind=%s started_ts=%lld process_start=%lld "
                 "reason=%s — latch unchanged", log_kind,
                 (long long)log_started_ts, (long long)log_process_start,
                 log_reason);
    if (log_rejected_clear)
        LOG_WARN("canary_watch", "[canary_watch] rejected non-authoritative "
                 "clear/unknown verdict kind=%s source_id=%s artifact=%s "
                 "started_ts=%lld "
                 "process_start=%lld — FAIL latch preserved", log_kind,
                 log_source_id[0] ? log_source_id : "-",
                 log_artifact[0] ? log_artifact : "-",
                 (long long)log_started_ts, (long long)log_process_start);
}

/* Recompute the OR of all per-kind FAIL latches. */
static void recompute_latch(void)
{
    bool any_fail = false;
    pthread_mutex_lock(&g_watch.lock);
    for (int i = 0; i < CANARY_WATCH_MAX_KINDS; i++) {
        if (g_watch.slots[i].used && g_watch.slots[i].fail)
            any_fail = true;
    }
    pthread_mutex_unlock(&g_watch.lock);
    atomic_store(&g_watch.fail_latched, any_fail);
}

void canary_sentinel_watch_tick_once(void)
{
    atomic_store(&g_watch.last_scan_unix, platform_time_wall_unix());
    atomic_fetch_add(&g_watch.scans_total, 1);

    char dir[CANARY_PATH_MAX];
    if (!canary_sentinel_watch_resolve_dir(dir, sizeof(dir))) {
        atomic_store(&g_watch.files_seen_last, 0);
        return; /* quiet: nowhere to look (no env, no HOME) */
    }

    struct platform_directory_list entries;
    if (!platform_directory_list_regular_sorted(dir, &entries)) {
        /* Fresh install / canary never ran: stay silent (no log spam, no
         * health impact). Absence never transitions the latch (header). */
        atomic_store(&g_watch.files_seen_last, 0);
        return;
    }

    int64_t files_seen = 0;
    for (size_t i = 0; i < entries.count; i++) {
        const char *name = entries.entries[i].name;
        char kind[CANARY_KIND_NAME_MAX];
        if (!kind_from_filename(name, kind, sizeof(kind)))
            continue;
        process_sentinel(dir, name);
        files_seen++;
    }
    platform_directory_list_free(&entries);

    atomic_store(&g_watch.files_seen_last, files_seen);
    recompute_latch();
}

bool canary_sentinel_watch_fail_active(void)
{
    return atomic_load(&g_watch.fail_latched);
}

int canary_sentinel_watch_fail_detail(char *out, size_t cap)
{
    int fails = 0;
    size_t pos = 0;
    if (out && cap > 0)
        out[0] = '\0';
    pthread_mutex_lock(&g_watch.lock);
    for (int i = 0; i < CANARY_WATCH_MAX_KINDS; i++) {
        const struct canary_kind_slot *s = &g_watch.slots[i];
        if (!s->used || !s->fail)
            continue;
        fails++;
        if (out && pos < cap) {
            int n = snprintf(out + pos, cap - pos,
                             "%skind=%s reason=%s ts=%lld",
                             pos ? "; " : "", s->kind,
                             s->latched_reason[0] ? s->latched_reason : "-",
                             (long long)s->latched_ts);
            if (n > 0)
                pos += (size_t)n < cap - pos ? (size_t)n : cap - pos;
        }
    }
    pthread_mutex_unlock(&g_watch.lock);
    return fails;
}

/* ── State dump (see CLAUDE.md "Adding state introspection") ───── */

bool canary_watch_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    char dir[CANARY_PATH_MAX];
    if (!canary_sentinel_watch_resolve_dir(dir, sizeof(dir)))
        dir[0] = '\0';
    json_push_kv_str(out, "verdict_dir", dir[0] ? dir : "unresolved");
    json_push_kv_int(out, "last_scan_unix",
                     atomic_load(&g_watch.last_scan_unix));
    json_push_kv_int(out, "scans_total", atomic_load(&g_watch.scans_total));
    json_push_kv_int(out, "files_seen_last",
                     atomic_load(&g_watch.files_seen_last));
    json_push_kv_int(out, "parse_failures_logged",
                     atomic_load(&g_watch.parse_failures_logged));
    json_push_kv_bool(out, "fail_latched",
                      atomic_load(&g_watch.fail_latched));
    json_push_kv_str(out, "staleness_authority", "source_id_sha256");
    json_push_kv_str(out, "running_source_id_sha256",
                     zcl_build_source_id_sha256());
    json_push_kv_str(out, "running_artifact_sha256",
                     running_artifact_sha256());

    /* The Condition engine's view of replay_canary_failed (the pager). */
    struct condition_runtime_snapshot snap;
    bool cond_active =
        condition_engine_get_registered_snapshot("replay_canary_failed",
                                                 &snap) &&
        snap.currently_active;
    json_push_kv_bool(out, "condition_active", cond_active);

    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    pthread_mutex_lock(&g_watch.lock);
    for (int i = 0; i < CANARY_WATCH_MAX_KINDS; i++) {
        const struct canary_kind_slot *s = &g_watch.slots[i];
        if (!s->used)
            continue;
        struct json_value obj;
        json_init(&obj);
        json_set_object(&obj);
        json_push_kv_str(&obj, "kind", s->kind);
        json_push_kv_str(&obj, "from", s->from[0] ? s->from : "-");
        json_push_kv_str(&obj, "verdict", s->verdict[0] ? s->verdict : "-");
        json_push_kv_str(&obj, "reason", s->reason);
        json_push_kv_str(&obj, "latched_reason", s->latched_reason);
        json_push_kv_str(&obj, "source_id_sha256",
                         s->source_id_sha256[0]
                             ? s->source_id_sha256 : "-");
        json_push_kv_str(&obj, "artifact_sha256",
                         s->artifact_sha256[0]
                             ? s->artifact_sha256 : "-");
        json_push_kv_str(&obj, "build_commit",
                         s->build_commit[0] ? s->build_commit : "-");
        json_push_kv_int(&obj, "ts", s->ts);
        json_push_kv_int(&obj, "started_ts", s->started_ts);
        json_push_kv_int(&obj, "latched_ts", s->latched_ts);
        json_push_kv_bool(&obj, "fail", s->fail);
        json_push_kv_bool(&obj, "stale_build", s->stale_build);
        json_push_kv_bool(&obj, "stale_run", s->stale_run);
        json_push_kv_bool(&obj, "clear_rejected", s->clear_rejected);
        json_push_back(&arr, &obj);
        json_free(&obj);
    }
    pthread_mutex_unlock(&g_watch.lock);
    bool ok = json_push_kv(out, "kinds", &arr);
    json_free(&arr);
    return ok;
}

#ifdef ZCL_TESTING
void canary_sentinel_watch_test_reset(void)
{
    pthread_mutex_lock(&g_watch.lock);
    memset(g_watch.slots, 0, sizeof(g_watch.slots));
    pthread_mutex_unlock(&g_watch.lock);
    atomic_store(&g_watch.last_scan_unix, 0);
    atomic_store(&g_watch.scans_total, 0);
    atomic_store(&g_watch.files_seen_last, 0);
    atomic_store(&g_watch.parse_failures_logged, 0);
    atomic_store(&g_watch.fail_latched, false);
    canary_sentinel_watch_init_process_start();
}

void canary_sentinel_watch_test_set_process_start(int64_t start_unix)
{
    atomic_store(&g_watch.process_start_unix, start_unix);
}
#endif
