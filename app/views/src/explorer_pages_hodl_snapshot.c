/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Explorer HODL-wave VIEW — verified-snapshot cache + background refresh.
 *
 * Part of the HODL-wave page split (see views/explorer_pages_hodl_internal.h):
 * this TU owns the in-memory + on-disk verified snapshot cache, the served-tip
 * cap, and the one-shot background refresh thread. The page assembly lives in
 * explorer_pages_hodl.c; the survival-row model in explorer_pages_hodl_rows.c;
 * the SVG chart emitters in explorer_pages_hodl_chart.c. */

#include "platform/time_compat.h"
#include "views/explorer_pages_view.h"
#include "views/explorer_pages_hodl_internal.h"
#include "controllers/explorer_internal.h"
#include "jobs/reducer_frontier.h"
#include "models/hodl_wave.h"
#include "platform/directory_compat.h"
#include "platform/positioned_file.h"
#include "platform/private_file.h"
#include "platform/rng.h"
#include "util/safe_alloc.h"
#include "util/thread_registry.h"

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int64_t hodl_view_cap_to_served_tip(int64_t index_tip)
{
    if (index_tip < 0)
        return index_tip;
    if (!reducer_frontier_provable_tip_is_published())
        return 0;

    int32_t served_tip = reducer_frontier_provable_tip_cached();
    if (served_tip >= 0 && index_tip > served_tip)
        return served_tip;
    return index_tip;
}

#define HODL_VIEW_DISK_CACHE_PATH_MAX 1200
#define HODL_VIEW_DISK_CACHE_MAGIC "zcl_hodl_snapshot_v1"
#define HODL_VIEW_DISK_CACHE_FILE "hodl-current-v1.cache"
#define HODL_VIEW_DISK_CACHE_BYTES_MAX 4096
#define HODL_VIEW_SYNC_SCAN_DB_BYTES_MAX (128LL * 1024LL * 1024LL)

struct hodl_view_cache_entry {
    bool valid;
    char datadir[HODL_VIEW_CACHE_DATADIR_MAX];
    int64_t tip_height;
    char tip_hash[HODL_VIEW_CACHE_HASH_MAX];
    struct hodl_wave_snapshot snapshot;
};

struct hodl_view_refresh_task {
    char datadir[HODL_VIEW_CACHE_DATADIR_MAX];
    char datadir_key[HODL_VIEW_CACHE_DATADIR_MAX];
    int64_t tip_height;
    char tip_hash[HODL_VIEW_CACHE_HASH_MAX];
};

static pthread_mutex_t g_hodl_view_cache_lock = PTHREAD_MUTEX_INITIALIZER;
static struct hodl_view_cache_entry g_hodl_view_cache;
static pthread_mutex_t g_hodl_view_refresh_lock = PTHREAD_MUTEX_INITIALIZER;
static bool g_hodl_view_refresh_active;

bool hodl_view_datadir_key(const char *datadir, char out[HODL_VIEW_CACHE_DATADIR_MAX])
{
    if (!datadir)
        return false;
    int n = snprintf(out, HODL_VIEW_CACHE_DATADIR_MAX, "%s", datadir);
    return n >= 0 && n < HODL_VIEW_CACHE_DATADIR_MAX;
}

void hodl_view_tip_hash(sqlite3 *db, int64_t tip, char out[HODL_VIEW_CACHE_HASH_MAX])
{
    char sql[128];
    out[0] = '\0';
    if (db && tip >= 0) {
        snprintf(sql, sizeof(sql),
                 "SELECT hex(hash) FROM blocks WHERE height=%" PRId64, tip);
        (void)sql_query_text(db, sql, out, HODL_VIEW_CACHE_HASH_MAX);
    }
    if (out[0] == '\0')
        snprintf(out, HODL_VIEW_CACHE_HASH_MAX, "height:%" PRId64 ":nohash", tip);
}

static bool hodl_view_hash_matches(sqlite3 *db, int64_t tip,
                                   const char *expected_hash)
{
    char actual_hash[HODL_VIEW_CACHE_HASH_MAX];
    if (!expected_hash || !expected_hash[0])
        return false; // raw-return-ok:cache-key-miss
    hodl_view_tip_hash(db, tip, actual_hash);
    return strcmp(actual_hash, expected_hash) == 0;
}

bool hodl_view_cache_get_verified(sqlite3 *db, const char *datadir_key,
                                  int64_t tip,
                                  struct hodl_wave_snapshot *out,
                                  bool *cached_snapshot)
{
    bool hit = false;
    struct hodl_view_cache_entry local;
    memset(&local, 0, sizeof(local));

    pthread_mutex_lock(&g_hodl_view_cache_lock);
    if (g_hodl_view_cache.valid &&
        strcmp(g_hodl_view_cache.datadir, datadir_key) == 0 &&
        g_hodl_view_cache.tip_height <= tip) {
        local = g_hodl_view_cache;
        hit = true;
    }
    pthread_mutex_unlock(&g_hodl_view_cache_lock);
    if (!hit)
        return false;
    if (!hodl_view_hash_matches(db, local.tip_height, local.tip_hash))
        return false; // raw-return-ok:stale-cache-rejected

    *out = local.snapshot;
    if (cached_snapshot)
        *cached_snapshot = local.tip_height != tip;
    return hit;
}

void hodl_view_cache_put(const char *datadir_key, int64_t tip,
                         const char *tip_hash,
                         const struct hodl_wave_snapshot *snapshot)
{
    pthread_mutex_lock(&g_hodl_view_cache_lock);
    snprintf(g_hodl_view_cache.datadir, sizeof(g_hodl_view_cache.datadir),
             "%s", datadir_key);
    snprintf(g_hodl_view_cache.tip_hash, sizeof(g_hodl_view_cache.tip_hash),
             "%s", tip_hash);
    g_hodl_view_cache.tip_height = tip;
    g_hodl_view_cache.snapshot = *snapshot;
    g_hodl_view_cache.valid = true;
    pthread_mutex_unlock(&g_hodl_view_cache_lock);
}

#ifdef ZCL_TESTING
void explorer_test_reset_hodl_view_cache(void)
{
    pthread_mutex_lock(&g_hodl_view_cache_lock);
    memset(&g_hodl_view_cache, 0, sizeof(g_hodl_view_cache));
    pthread_mutex_unlock(&g_hodl_view_cache_lock);
}

bool explorer_test_hodl_view_refresh_active(void)
{
    bool active;
    pthread_mutex_lock(&g_hodl_view_refresh_lock);
    active = g_hodl_view_refresh_active;
    pthread_mutex_unlock(&g_hodl_view_refresh_lock);
    return active;
}
#endif

static bool hodl_view_disk_cache_paths(
    const char *datadir,
    char path[HODL_VIEW_DISK_CACHE_PATH_MAX],
    char parent[HODL_VIEW_DISK_CACHE_PATH_MAX])
{
    char dir[HODL_VIEW_DISK_CACHE_PATH_MAX];
    int n;

    if (!datadir || !path)
        return false;

    n = snprintf(dir, sizeof(dir), "%s/explorer", datadir);
    if (n < 0 || (size_t)n >= sizeof(dir))
        return false;
    if (!platform_directory_ensure(dir, 0700))
        return false;

    char requested[HODL_VIEW_DISK_CACHE_PATH_MAX];
    n = snprintf(requested, sizeof(requested), "%s/%s",
                 dir, HODL_VIEW_DISK_CACHE_FILE);
    if (n < 0 || n >= HODL_VIEW_DISK_CACHE_PATH_MAX)
        return false;
    char ignored_parent[HODL_VIEW_DISK_CACHE_PATH_MAX];
    return platform_private_path_resolve(
        requested, path, HODL_VIEW_DISK_CACHE_PATH_MAX,
        parent ? parent : ignored_parent, HODL_VIEW_DISK_CACHE_PATH_MAX);
}

static char *hodl_view_next_line(char **cursor)
{
    if (!cursor || !*cursor || !**cursor)
        return NULL;
    char *line = *cursor;
    char *newline = strchr(line, '\n');
    if (!newline)
        return NULL;
    *newline = '\0';
    *cursor = newline + 1;
    return line;
}

void hodl_view_snapshot_base(struct hodl_wave_snapshot *out, int64_t tip)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    out->tip_height = tip;
    memcpy(out->buckets, hodl_wave_bucket_defs(), sizeof(out->buckets));
    snprintf(out->source, sizeof(out->source),
             "current_transparent_utxo_set");
    snprintf(out->metric, sizeof(out->metric), "utxo_age_distribution");
    snprintf(out->status, sizeof(out->status), "ok");
}

static bool hodl_view_disk_cache_read(
    const char *datadir,
    struct hodl_wave_snapshot *out,
    char cached_hash[HODL_VIEW_CACHE_HASH_MAX])
{
    char path[HODL_VIEW_DISK_CACHE_PATH_MAX];
    char bytes[HODL_VIEW_DISK_CACHE_BYTES_MAX + 1];
    int64_t cached_tip = 0;
    int64_t total_value = 0;
    int64_t total_count = 0;
    int64_t skipped_rows = 0;
    int64_t older_value = 0;
    int64_t older_count = 0;
    struct platform_positioned_file file;

    if (!out || !cached_hash ||
        !hodl_view_disk_cache_paths(datadir, path, NULL))
        return false; // raw-return-ok:cache-miss-not-error
    cached_hash[0] = '\0';

    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path))
        return false;
    uint64_t size = 0;
    bool ok = false;
    if (!platform_positioned_file_size(&file, &size) || size == 0 ||
        size > HODL_VIEW_DISK_CACHE_BYTES_MAX ||
        platform_positioned_file_read(&file, bytes, (size_t)size, 0) !=
            (int64_t)size)
        goto done;
    bytes[size] = '\0';
    char *cursor = bytes;
    char *line = hodl_view_next_line(&cursor);
    if (!line || strcmp(line, HODL_VIEW_DISK_CACHE_MAGIC) != 0)
        goto done;
    line = hodl_view_next_line(&cursor);
    if (!line ||
        sscanf(line, "tip_height=%" SCNd64, &cached_tip) != 1 ||
        cached_tip < 0)
        goto done;
    line = hodl_view_next_line(&cursor);
    if (!line ||
        sscanf(line, "tip_hash=%79s", cached_hash) != 1 ||
        !cached_hash[0])
        goto done;
    line = hodl_view_next_line(&cursor);
    if (!line ||
        sscanf(line, "total_value=%" SCNd64, &total_value) != 1)
        goto done;
    line = hodl_view_next_line(&cursor);
    if (!line ||
        sscanf(line, "total_count=%" SCNd64, &total_count) != 1)
        goto done;
    line = hodl_view_next_line(&cursor);
    if (!line ||
        sscanf(line, "skipped_rows=%" SCNd64, &skipped_rows) != 1)
        goto done;
    line = hodl_view_next_line(&cursor);
    if (!line ||
        sscanf(line, "older_than_1y_value=%" SCNd64, &older_value) != 1)
        goto done;
    line = hodl_view_next_line(&cursor);
    if (!line ||
        sscanf(line, "older_than_1y_count=%" SCNd64, &older_count) != 1)
        goto done;

    hodl_view_snapshot_base(out, cached_tip);
    out->total_value = total_value;
    out->total_count = total_count;
    out->skipped_rows = skipped_rows;
    out->older_than_1y_value = older_value;
    out->older_than_1y_count = older_count;

    for (int i = 0; i < HODL_WAVE_BUCKETS; i++) {
        int idx = -1;
        int64_t value = 0;
        int64_t count = 0;
        line = hodl_view_next_line(&cursor);
        if (!line ||
            sscanf(line, "bucket %d value=%" SCNd64 " count=%" SCNd64,
                   &idx, &value, &count) != 3 ||
            idx != i || value < 0 || count < 0)
            goto done;
        out->buckets[i].value = value;
        out->buckets[i].count = count;
    }

    struct ar_errors errors;
    ok = hodl_wave_validate(out, &errors);
done:
    platform_positioned_file_close(&file);
    return ok;
}

bool hodl_view_disk_cache_load_verified(
    const char *datadir, sqlite3 *db, int64_t tip,
    struct hodl_wave_snapshot *out,
    char cached_hash[HODL_VIEW_CACHE_HASH_MAX],
    bool *cached_snapshot)
{
    if (!hodl_view_disk_cache_read(datadir, out, cached_hash))
        return false; // raw-return-ok:cache-miss-not-error
    if (out->tip_height > tip)
        return false;
    if (!hodl_view_hash_matches(db, out->tip_height, cached_hash))
        return false; // raw-return-ok:stale-cache-rejected
    if (cached_snapshot)
        *cached_snapshot = out->tip_height != tip;
    return true;
}

static bool hodl_view_cache_append(char *bytes, size_t bytes_size,
                                   size_t *used, const char *format, ...)
{
    if (!bytes || !used || *used >= bytes_size)
        return false;
    va_list args;
    va_start(args, format);
    int n = vsnprintf(bytes + *used, bytes_size - *used, format, args);
    va_end(args);
    if (n < 0 || (size_t)n >= bytes_size - *used)
        return false;
    *used += (size_t)n;
    return true;
}

void hodl_view_disk_cache_save(const char *datadir, int64_t tip,
                               const char *tip_hash,
                               const struct hodl_wave_snapshot *h)
{
    char path[HODL_VIEW_DISK_CACHE_PATH_MAX];
    char parent[HODL_VIEW_DISK_CACHE_PATH_MAX];
    char tmp_path[HODL_VIEW_DISK_CACHE_PATH_MAX];
    char bytes[HODL_VIEW_DISK_CACHE_BYTES_MAX];
    size_t used = 0;

    if (!h || !tip_hash || !tip_hash[0] ||
        !hodl_view_disk_cache_paths(datadir, path, parent))
        return;

    bool ok = hodl_view_cache_append(bytes, sizeof(bytes), &used, "%s\n",
                                     HODL_VIEW_DISK_CACHE_MAGIC) &&
        hodl_view_cache_append(bytes, sizeof(bytes), &used,
                               "tip_height=%" PRId64 "\n", tip) &&
        hodl_view_cache_append(bytes, sizeof(bytes), &used, "tip_hash=%s\n",
                               tip_hash) &&
        hodl_view_cache_append(bytes, sizeof(bytes), &used,
                               "total_value=%" PRId64 "\n", h->total_value) &&
        hodl_view_cache_append(bytes, sizeof(bytes), &used,
                               "total_count=%" PRId64 "\n", h->total_count) &&
        hodl_view_cache_append(bytes, sizeof(bytes), &used,
                               "skipped_rows=%" PRId64 "\n", h->skipped_rows) &&
        hodl_view_cache_append(bytes, sizeof(bytes), &used,
                               "older_than_1y_value=%" PRId64 "\n",
                               h->older_than_1y_value) &&
        hodl_view_cache_append(bytes, sizeof(bytes), &used,
                               "older_than_1y_count=%" PRId64 "\n",
                               h->older_than_1y_count);
    for (int i = 0; ok && i < HODL_WAVE_BUCKETS; i++) {
        ok = hodl_view_cache_append(
            bytes, sizeof(bytes), &used,
            "bucket %d value=%" PRId64 " count=%" PRId64 "\n", i,
            h->buckets[i].value, h->buckets[i].count);
    }
    if (!ok) {
        LOG_WARN("explorer", "hodl disk cache serialization overflow");
        return;
    }

    struct platform_private_file file;
    platform_private_file_init(&file);
    bool created = false;
    for (unsigned attempt = 0; attempt < 16 && !created; ++attempt) {
        uint8_t nonce[16];
        if (!rng_fill(nonce, sizeof(nonce)))
            break;
        char suffix[2 * sizeof(nonce) + 1];
        for (size_t i = 0; i < sizeof(nonce); ++i)
            (void)snprintf(suffix + 2 * i, 3, "%02x", nonce[i]);
        int n = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%s", path,
                         suffix);
        if (n <= 0 || (size_t)n >= sizeof(tmp_path))
            break;
        created = platform_private_file_create(tmp_path, &file);
    }
    if (!created || !platform_private_file_write_at(&file, bytes, used, 0) ||
        !platform_private_file_flush(&file) ||
        !platform_private_file_replace(&file, tmp_path, path) ||
        !platform_private_parent_flush(parent)) {
        LOG_WARN("explorer", "hodl disk cache atomic write(%s) failed",
                 path);
        if (created)
            (void)platform_private_file_retire(&file, tmp_path);
        platform_private_file_close(&file);
    }
}

bool hodl_view_allow_sync_scan(const char *datadir)
{
    char dbpath[HODL_VIEW_DISK_CACHE_PATH_MAX];
    struct platform_positioned_file file;
    int n;

    if (!datadir)
        return true;
    n = snprintf(dbpath, sizeof(dbpath), "%s/node.db", datadir);
    if (n < 0 || (size_t)n >= sizeof(dbpath))
        return false;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, dbpath))
        return true;
    uint64_t size = 0;
    bool ok = platform_positioned_file_size(&file, &size);
    platform_positioned_file_close(&file);
    return ok && size <= HODL_VIEW_SYNC_SCAN_DB_BYTES_MAX;
}

static void hodl_view_refresh_mark_done(void)
{
    pthread_mutex_lock(&g_hodl_view_refresh_lock);
    g_hodl_view_refresh_active = false;
    pthread_mutex_unlock(&g_hodl_view_refresh_lock);
}

static void *hodl_view_refresh_thread(void *arg)
{
    struct hodl_view_refresh_task *task = arg;
    sqlite3 *db = NULL;
    struct hodl_wave_snapshot hodl;
    bool ok = false;

    if (!task) {
        hodl_view_refresh_mark_done();
        return NULL;
    }

    if (explorer_open_readonly_db(task->datadir, &db)) {
        ok = hodl_wave_scan_current_utxos(db, task->tip_height, &hodl);
        sqlite3_close(db);
    } else {
        memset(&hodl, 0, sizeof(hodl));
        snprintf(hodl.status, sizeof(hodl.status),
                 "sqlite database unavailable");
    }

    if (ok) {
        hodl_view_cache_put(task->datadir_key, task->tip_height,
                            task->tip_hash, &hodl);
        hodl_view_disk_cache_save(task->datadir, task->tip_height,
                                  task->tip_hash, &hodl);
    } else {
        LOG_WARN("explorer", "hodl background refresh failed at height %" PRId64
                 ": %s", task->tip_height,
                 hodl.status[0] ? hodl.status : "unknown error");
    }

    free(task);
    hodl_view_refresh_mark_done();
    return NULL;
}

bool hodl_view_refresh_start(const char *datadir,
                             const char *datadir_key,
                             int64_t tip,
                             const char *tip_hash)
{
    int rc;
    struct hodl_view_refresh_task *task;

    if (!datadir || !datadir_key || !tip_hash || !tip_hash[0] || tip < 1)
        return false;

    pthread_mutex_lock(&g_hodl_view_refresh_lock);
    if (g_hodl_view_refresh_active) {
        pthread_mutex_unlock(&g_hodl_view_refresh_lock);
        return false;
    }
    g_hodl_view_refresh_active = true;
    pthread_mutex_unlock(&g_hodl_view_refresh_lock);

    task = zcl_calloc(1, sizeof(*task), "hodl_view_refresh_task");
    if (!task) {
        hodl_view_refresh_mark_done();
        return false;
    }
    snprintf(task->datadir, sizeof(task->datadir), "%s", datadir);
    snprintf(task->datadir_key, sizeof(task->datadir_key), "%s", datadir_key);
    task->tip_height = tip;
    snprintf(task->tip_hash, sizeof(task->tip_hash), "%s", tip_hash);

    rc = thread_registry_spawn("zcl_hodl_ref", hodl_view_refresh_thread, task, NULL);
    if (rc != 0) {
        LOG_WARN("explorer",
                 "hodl background refresh thread_registry_spawn failed: %d",
                 rc);
        free(task);
        hodl_view_refresh_mark_done();
        return false;
    }
    return true;
}
