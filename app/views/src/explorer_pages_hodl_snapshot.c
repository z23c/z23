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
#include "util/safe_alloc.h"
#include "util/thread_registry.h"

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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
    char tmp_path[HODL_VIEW_DISK_CACHE_PATH_MAX])
{
    char dir[HODL_VIEW_DISK_CACHE_PATH_MAX];
    int n;

    if (!datadir || !path)
        return false;

    n = snprintf(dir, sizeof(dir), "%s/explorer", datadir);
    if (n < 0 || (size_t)n >= sizeof(dir))
        return false;
    if (mkdir(dir, 0755) != 0 && errno != EEXIST)
        return false;

    n = snprintf(path, HODL_VIEW_DISK_CACHE_PATH_MAX, "%s/%s",
                 dir, HODL_VIEW_DISK_CACHE_FILE);
    if (n < 0 || n >= HODL_VIEW_DISK_CACHE_PATH_MAX)
        return false;
    if (tmp_path) {
        n = snprintf(tmp_path, HODL_VIEW_DISK_CACHE_PATH_MAX,
                     "%s/%s.tmp.%ld", dir, HODL_VIEW_DISK_CACHE_FILE,
                     (long)getpid());
        if (n < 0 || n >= HODL_VIEW_DISK_CACHE_PATH_MAX)
            return false;
    }
    return true;
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
    char line[256];
    int64_t cached_tip = 0;
    int64_t total_value = 0;
    int64_t total_count = 0;
    int64_t skipped_rows = 0;
    int64_t older_value = 0;
    int64_t older_count = 0;
    FILE *f;

    if (!out || !cached_hash ||
        !hodl_view_disk_cache_paths(datadir, path, NULL))
        return false; // raw-return-ok:cache-miss-not-error
    cached_hash[0] = '\0';

    f = fopen(path, "r");
    if (!f)
        return false;
    bool ok = false;
    if (!fgets(line, sizeof(line), f) ||
        strncmp(line, HODL_VIEW_DISK_CACHE_MAGIC,
                strlen(HODL_VIEW_DISK_CACHE_MAGIC)) != 0)
        goto done;
    if (!fgets(line, sizeof(line), f) ||
        sscanf(line, "tip_height=%" SCNd64, &cached_tip) != 1 ||
        cached_tip < 0)
        goto done;
    if (!fgets(line, sizeof(line), f) ||
        sscanf(line, "tip_hash=%79s", cached_hash) != 1 ||
        !cached_hash[0])
        goto done;
    if (!fgets(line, sizeof(line), f) ||
        sscanf(line, "total_value=%" SCNd64, &total_value) != 1)
        goto done;
    if (!fgets(line, sizeof(line), f) ||
        sscanf(line, "total_count=%" SCNd64, &total_count) != 1)
        goto done;
    if (!fgets(line, sizeof(line), f) ||
        sscanf(line, "skipped_rows=%" SCNd64, &skipped_rows) != 1)
        goto done;
    if (!fgets(line, sizeof(line), f) ||
        sscanf(line, "older_than_1y_value=%" SCNd64, &older_value) != 1)
        goto done;
    if (!fgets(line, sizeof(line), f) ||
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
        if (!fgets(line, sizeof(line), f) ||
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
    fclose(f);
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

void hodl_view_disk_cache_save(const char *datadir, int64_t tip,
                               const char *tip_hash,
                               const struct hodl_wave_snapshot *h)
{
    char path[HODL_VIEW_DISK_CACHE_PATH_MAX];
    char tmp_path[HODL_VIEW_DISK_CACHE_PATH_MAX];
    FILE *f;
    bool ok = false;

    if (!h || !tip_hash || !tip_hash[0] ||
        !hodl_view_disk_cache_paths(datadir, path, tmp_path))
        return;

    f = fopen(tmp_path, "w");
    if (!f) {
        LOG_WARN("explorer", "hodl disk cache fopen(%s) failed: %s",
                 tmp_path, strerror(errno));
        return;
    }

    ok = fprintf(f, "%s\n", HODL_VIEW_DISK_CACHE_MAGIC) > 0 &&
         fprintf(f, "tip_height=%" PRId64 "\n", tip) > 0 &&
         fprintf(f, "tip_hash=%s\n", tip_hash) > 0 &&
         fprintf(f, "total_value=%" PRId64 "\n", h->total_value) > 0 &&
         fprintf(f, "total_count=%" PRId64 "\n", h->total_count) > 0 &&
         fprintf(f, "skipped_rows=%" PRId64 "\n", h->skipped_rows) > 0 &&
         fprintf(f, "older_than_1y_value=%" PRId64 "\n",
                 h->older_than_1y_value) > 0 &&
         fprintf(f, "older_than_1y_count=%" PRId64 "\n",
                 h->older_than_1y_count) > 0;
    for (int i = 0; ok && i < HODL_WAVE_BUCKETS; i++) {
        ok = fprintf(f, "bucket %d value=%" PRId64 " count=%" PRId64 "\n",
                     i, h->buckets[i].value, h->buckets[i].count) > 0;
    }
    ok = ok && fflush(f) == 0 && fsync(fileno(f)) == 0;
    if (fclose(f) != 0)
        ok = false;
    if (!ok) {
        LOG_WARN("explorer", "hodl disk cache write(%s) failed: %s",
                 tmp_path, strerror(errno));
        unlink(tmp_path);
        return;
    }
    if (rename(tmp_path, path) != 0) {
        LOG_WARN("explorer", "hodl disk cache rename(%s -> %s) failed: %s",
                 tmp_path, path, strerror(errno));
        unlink(tmp_path);
    }
}

bool hodl_view_allow_sync_scan(const char *datadir)
{
    char dbpath[HODL_VIEW_DISK_CACHE_PATH_MAX];
    struct stat st;
    int n;

    if (!datadir)
        return true;
    n = snprintf(dbpath, sizeof(dbpath), "%s/node.db", datadir);
    if (n < 0 || (size_t)n >= sizeof(dbpath))
        return false;
    if (stat(dbpath, &st) != 0)
        return true;
    return st.st_size <= HODL_VIEW_SYNC_SCAN_DB_BYTES_MAX;
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
