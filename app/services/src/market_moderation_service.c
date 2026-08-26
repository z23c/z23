/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Per-node community content moderation for the marketplace: the local
 * visibility profile, its per-datadir persistence, the local-only
 * review_state store, and the serving gate every surface that hands
 * content to another party asks. Ingest and storage are untouched and
 * nothing is ever deleted; consensus is never consulted (see header). */

#include "services/market_moderation_service.h"
#include "services/market_moderation_view_service.h"

#include "models/database.h"
#include "models/file_offer.h"
#include "base/log_macros.h"
#include "util/write_all.h"
#include "json/json.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MM_TAG "market.moderation"
#define MM_POLICY_MAGIC "zcl.market.moderation.v1"
#define MM_POLICY_MAX_BYTES 4096

const char *market_moderation_profile_string(
    enum market_moderation_profile profile)
{
    switch (profile) {
    case MARKET_MODERATION_PROFILE_DEFAULT:
        return MARKET_MODERATION_PROFILE_GENERAL_AUDIENCE_V1;
    case MARKET_MODERATION_PROFILE_OPEN:
        return MARKET_MODERATION_PROFILE_OPEN_VIEW;
    default: return "unknown";
    }
}

int market_moderation_profile_from_string(const char *name)
{
    if (!name) return -1; // raw-return-ok:null-parse-input-is-a-sentinel-not-an-error
    if (strcmp(name, MARKET_MODERATION_PROFILE_GENERAL_AUDIENCE_V1) == 0)
        return MARKET_MODERATION_PROFILE_DEFAULT;
    if (strcmp(name, MARKET_MODERATION_PROFILE_OPEN_VIEW) == 0)
        return MARKET_MODERATION_PROFILE_OPEN;
    return -1; // raw-return-ok:unknown-profile-name-is-a-sentinel-caller-logs
}

/* ── Per-datadir policy persistence ─────────────────────────────── */

static bool mm_policy_paths(const char *datadir, char directory[1400],
                            char path[1500], bool create_directories,
                            char *error, size_t error_capacity)
{
    if (error && error_capacity) error[0] = '\0';
    if (!datadir || !datadir[0]) {
        if (error && error_capacity)
            snprintf(error, error_capacity, "moderation datadir is missing");
        LOG_ERROR(MM_TAG, "policy path: datadir is missing");
        return false;
    }
    int n = snprintf(directory, 1400, "%s/market", datadir);
    if (n <= 0 || n >= 1400 ||
        (create_directories && mkdir(directory, 0700) != 0 &&
         errno != EEXIST)) {
        if (error && error_capacity)
            snprintf(error, error_capacity,
                     "cannot create market policy directory");
        LOG_ERROR(MM_TAG, "policy path: cannot prepare %s/market: %s",
                  datadir, strerror(errno));
        return false;
    }
    n = snprintf(path, 1500, "%s/%s", datadir, MARKET_MODERATION_POLICY_FILE);
    if (n <= 0 || n >= 1500) {
        if (error && error_capacity)
            snprintf(error, error_capacity, "moderation policy path too long");
        LOG_ERROR(MM_TAG, "policy path: path too long under %s", datadir);
        return false;
    }
    return true;
}

enum market_moderation_profile market_moderation_profile_load(
    const char *datadir, bool *ok_out, char *error, size_t error_capacity)
{
    if (ok_out) *ok_out = false;
    char directory[1400], path[1500];
    if (!mm_policy_paths(datadir, directory, path, false, error,
                         error_capacity))
        return MARKET_MODERATION_PROFILE_DEFAULT;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        if (errno == ENOENT) {
            /* First boot / never configured: the immutable default. */
            if (ok_out) *ok_out = true;
            return MARKET_MODERATION_PROFILE_DEFAULT;
        }
        if (error && error_capacity)
            snprintf(error, error_capacity,
                     "cannot open moderation policy: %s", strerror(errno));
        LOG_ERROR(MM_TAG, "policy load: open %s failed: %s", path,
                  strerror(errno));
        return MARKET_MODERATION_PROFILE_DEFAULT;
    }
    struct stat st;
    char buf[MM_POLICY_MAX_BYTES + 1];
    ssize_t got = -1;
    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
        (st.st_mode & 0777) == 0600 && st.st_size > 0 &&
        st.st_size <= MM_POLICY_MAX_BYTES) {
        got = 0;
        while (got < st.st_size) {
            ssize_t n = read(fd, buf + got, (size_t)(st.st_size - got));
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) { got = -1; break; }
            got += n;
        }
    }
    (void)close(fd);
    if (got < 0) {
        if (error && error_capacity)
            snprintf(error, error_capacity,
                     "moderation policy size or mode is invalid");
        LOG_ERROR(MM_TAG, "policy load: %s size/mode/read invalid", path);
        return MARKET_MODERATION_PROFILE_DEFAULT;
    }
    buf[got] = '\0';
    char expected[96];
    int profile = -1;
    for (int i = 0; i < MARKET_MODERATION_PROFILE_COUNT; i++) {
        snprintf(expected, sizeof(expected), "%s\nprofile=%s\n",
                 MM_POLICY_MAGIC,
                 market_moderation_profile_string(
                     (enum market_moderation_profile)i));
        if (strcmp(buf, expected) == 0) {
            profile = i;
            break;
        }
    }
    if (profile < 0) {
        if (error && error_capacity)
            snprintf(error, error_capacity,
                     "moderation policy content is not a known profile");
        LOG_ERROR(MM_TAG, "policy load: %s content rejected", path);
        return MARKET_MODERATION_PROFILE_DEFAULT;
    }
    if (ok_out) *ok_out = true;
    return (enum market_moderation_profile)profile;
}

struct zcl_result market_moderation_profile_save(
    const char *datadir, enum market_moderation_profile profile)
{
    if (!market_moderation_profile_valid(profile)) {
        LOG_ERROR(MM_TAG, "policy save: unknown profile %d", profile);
        return ZCL_ERR(-1, "unknown moderation profile %d", profile);
    }
    char error[192];
    char directory[1400], path[1500];
    if (!mm_policy_paths(datadir, directory, path, true, error,
                         sizeof(error)))
        return ZCL_ERR(-2, "%s", error[0] ? error : "policy path failed");
    char body[96];
    int body_len = snprintf(body, sizeof(body), "%s\nprofile=%s\n",
                            MM_POLICY_MAGIC,
                            market_moderation_profile_string(profile));
    if (body_len <= 0 || (size_t)body_len >= sizeof(body)) {
        LOG_ERROR(MM_TAG, "policy save: encode failed");
        return ZCL_ERR(-3, "moderation policy encode failed");
    }
    static _Atomic unsigned long long g_temp_sequence = 0;
    unsigned long long sequence =
        atomic_fetch_add_explicit(&g_temp_sequence, 1, memory_order_relaxed);
    char temporary[1600];
    int n = snprintf(temporary, sizeof(temporary), "%s.tmp.%ld.%llu", path,
                     (long)getpid(), sequence);
    if (n <= 0 || (size_t)n >= sizeof(temporary)) {
        LOG_ERROR(MM_TAG, "policy save: temp path too long");
        return ZCL_ERR(-4, "moderation policy temp path too long");
    }
    int fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    bool wrote = fd >= 0 &&
                 zcl_write_all(fd, body, (size_t)body_len) && fsync(fd) == 0;
    if (fd >= 0 && close(fd) != 0)
        wrote = false;
    if (!wrote) {
        (void)unlink(temporary);
        LOG_ERROR(MM_TAG, "policy save: temp write failed for %s", path);
        return ZCL_ERR(-5, "moderation policy temp write failed for %s",
                       path);
    }
    if (rename(temporary, path) != 0) {
        (void)unlink(temporary);
        LOG_ERROR(MM_TAG, "policy save: rename to %s failed: %s", path,
                  strerror(errno));
        return ZCL_ERR(-6, "moderation policy rename failed: %s",
                       strerror(errno));
    }
    int dfd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dfd < 0 || fsync(dfd) != 0) {
        if (dfd >= 0) (void)close(dfd);
        LOG_ERROR(MM_TAG, "policy save: directory fsync failed");
        return ZCL_ERR(-7, "moderation policy directory fsync failed");
    }
    (void)close(dfd);
    return ZCL_OK;
}

/* ── Node-process context ───────────────────────────────────────── */

static pthread_mutex_t g_mm_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct node_db *g_mm_ndb = NULL;
static char g_mm_datadir[1024] = "";
static _Atomic int g_mm_active_profile = MARKET_MODERATION_PROFILE_DEFAULT;

void market_moderation_set_context(struct node_db *ndb, const char *datadir)
{
    pthread_mutex_lock(&g_mm_mutex);
    g_mm_ndb = ndb;
    if (datadir) {
        snprintf(g_mm_datadir, sizeof(g_mm_datadir), "%s", datadir);
        char error[192] = {0};
        bool ok = false;
        enum market_moderation_profile profile =
            market_moderation_profile_load(datadir, &ok, error, sizeof(error));
        if (!ok)
            LOG_WARN(MM_TAG,
                     "moderation policy unreadable (%s); boot default %s in "
                     "force", error[0] ? error : "unknown",
                     MARKET_MODERATION_PROFILE_GENERAL_AUDIENCE_V1);
        atomic_store_explicit(&g_mm_active_profile, profile,
                              memory_order_release);
    }
    pthread_mutex_unlock(&g_mm_mutex);
}

enum market_moderation_profile market_moderation_active_profile(void)
{
    return (enum market_moderation_profile)atomic_load_explicit(
        &g_mm_active_profile, memory_order_acquire);
}

struct zcl_result market_moderation_set_active_profile(
    enum market_moderation_profile profile)
{
    if (!market_moderation_profile_valid(profile)) {
        LOG_ERROR(MM_TAG, "set active profile: unknown profile %d", profile);
        return ZCL_ERR(-1, "unknown moderation profile %d", profile);
    }
    pthread_mutex_lock(&g_mm_mutex);
    const char *datadir = g_mm_datadir[0] ? g_mm_datadir : NULL;
    if (datadir) {
        struct zcl_result saved =
            market_moderation_profile_save(datadir, profile);
        if (!saved.ok) {
            pthread_mutex_unlock(&g_mm_mutex);
            LOG_ERROR(MM_TAG, "set active profile: save failed: %s",
                      saved.message);
            return saved;
        }
    }
    atomic_store_explicit(&g_mm_active_profile, profile,
                          memory_order_release);
    pthread_mutex_unlock(&g_mm_mutex);
    LOG_INFO(MM_TAG, "moderation profile set: %s",
             market_moderation_profile_string(profile));
    return ZCL_OK;
}

/* ── Local-only review_state store ──────────────────────────────── */

int market_moderation_review_state_for_root(const uint8_t root_hash[32])
{
    if (!root_hash) return MARKET_REVIEW_UNREVIEWED;
    pthread_mutex_lock(&g_mm_mutex);
    struct node_db *ndb = g_mm_ndb;
    pthread_mutex_unlock(&g_mm_mutex);
    if (!ndb || !ndb->open) return MARKET_REVIEW_UNREVIEWED;
    char text[16] = {0};
    if (!db_file_offer_get_review_state(ndb, root_hash, text, sizeof(text)))
        return MARKET_REVIEW_UNREVIEWED;
    int state = market_review_state_from_string(text);
    return state >= 0 ? state : MARKET_REVIEW_UNREVIEWED;
}

int market_moderation_review_state_for_offer_id(const uint8_t offer_id[32])
{
    if (!offer_id) return MARKET_REVIEW_UNREVIEWED; // raw-return-ok:absent-id-is-unreviewed-which-the-default-profile-hides
    pthread_mutex_lock(&g_mm_mutex);
    struct node_db *ndb = g_mm_ndb;
    pthread_mutex_unlock(&g_mm_mutex);
    if (!ndb || !ndb->open) return MARKET_REVIEW_UNREVIEWED; // raw-return-ok:no-db-is-unreviewed-not-an-error
    struct file_offer offer;
    if (!db_file_offer_find_by_id(ndb, offer_id, &offer))
        return MARKET_REVIEW_UNREVIEWED; // raw-return-ok:unknown-offer-is-unreviewed
    return market_moderation_review_state_for_root(offer.root_hash);
}

/* ── The serving gate ───────────────────────────────────────────── */

/* The single decision both public entry points share. Every failure
 * path below answers false; there is no branch on which an error, an
 * absent dependency, or an out-of-range value yields "serve". */
static bool mm_may_serve_with_review(int review_state)
{
    int profile = (int)market_moderation_active_profile();
    if (!market_moderation_profile_valid(profile)) {
        LOG_ERROR(MM_TAG,
                  "serving gate: active profile %d is out of range — hiding",
                  profile);
        return false;
    }
    const struct market_moderation_view_service_v1 *view =
        market_moderation_view_service_builtin();
    if (!view || !view->decide) {
        LOG_ERROR(MM_TAG, "serving gate: view service unavailable — hiding");
        return false;
    }
    struct market_moderation_decision_result_v1 decision;
    if (!view->decide(profile, review_state, &decision)) {
        LOG_ERROR(MM_TAG, "serving gate: decide() refused — hiding");
        return false;
    }
    return decision.valid && decision.visible;
}

bool market_moderation_may_serve_root(const uint8_t root_hash[32])
{
    if (!root_hash) return false; // raw-return-ok:null-id-hides-fail-closed
    return mm_may_serve_with_review(
        market_moderation_review_state_for_root(root_hash));
}

bool market_moderation_may_serve_offer_id(const uint8_t offer_id[32])
{
    if (!offer_id) return false; // raw-return-ok:null-id-hides-fail-closed
    return mm_may_serve_with_review(
        market_moderation_review_state_for_offer_id(offer_id));
}

struct zcl_result market_moderation_review_counts(
    int64_t counts[MARKET_REVIEW_STATE_COUNT])
{
    if (!counts) {
        LOG_ERROR(MM_TAG, "review counts: out is NULL");
        return ZCL_ERR(-1, "review counts: out is NULL");
    }
    counts[0] = counts[1] = counts[2] = 0;
    pthread_mutex_lock(&g_mm_mutex);
    struct node_db *ndb = g_mm_ndb;
    pthread_mutex_unlock(&g_mm_mutex);
    if (!ndb || !ndb->open) {
        LOG_ERROR(MM_TAG, "review counts: node db unavailable");
        return ZCL_ERR(-2, "review counts: node db unavailable");
    }
    if (!db_file_offer_review_counts(ndb, counts)) {
        LOG_ERROR(MM_TAG, "review counts: query failed");
        return ZCL_ERR(-3, "review counts: query failed");
    }
    return ZCL_OK;
}

struct zcl_result market_moderation_set_review_state(
    const uint8_t offer_id[32], enum market_review_state state)
{
    if (!offer_id) {
        LOG_ERROR(MM_TAG, "set review state: offer_id is NULL");
        return ZCL_ERR(-1, "set review state: offer_id is NULL");
    }
    if (!market_review_state_valid(state)) {
        LOG_ERROR(MM_TAG, "set review state: invalid state %d", state);
        return ZCL_ERR(-2, "set review state: invalid state %d", state);
    }
    pthread_mutex_lock(&g_mm_mutex);
    struct node_db *ndb = g_mm_ndb;
    pthread_mutex_unlock(&g_mm_mutex);
    if (!ndb || !ndb->open) {
        LOG_ERROR(MM_TAG, "set review state: node db unavailable");
        return ZCL_ERR(-3, "set review state: node db unavailable");
    }
    if (!db_file_offer_set_review_state(
            ndb, offer_id, market_review_state_string(state))) {
        LOG_ERROR(MM_TAG, "set review state: no signed offer matched");
        return ZCL_ERR(-4,
                       "set review state: no signed offer carries that id");
    }
    return ZCL_OK;
}

/* ── dumpstate dumper ───────────────────────────────────────────── */

bool market_moderation_dump_state_json(struct json_value *out,
                                       const char *key)
{
    if (!out)
        LOG_FAIL(MM_TAG, "dump state: out is NULL");
    (void)key;
    json_set_object(out);
    enum market_moderation_profile active =
        market_moderation_active_profile();
    json_push_kv_str(out, "active_profile",
                     market_moderation_profile_string(active));
    struct json_value profiles;
    json_init(&profiles);
    json_set_array(&profiles);
    for (int i = 0; i < MARKET_MODERATION_PROFILE_COUNT; i++) {
        struct json_value p;
        json_init(&p);
        json_set_str(&p, market_moderation_profile_string(
                             (enum market_moderation_profile)i));
        json_push_back(&profiles, &p);
        json_free(&p);
    }
    json_push_kv(out, "available_profiles", &profiles);
    json_free(&profiles);

    pthread_mutex_lock(&g_mm_mutex);
    bool have_datadir = g_mm_datadir[0] != '\0';
    pthread_mutex_unlock(&g_mm_mutex);
    json_push_kv_bool(out, "datadir_bound", have_datadir);
    json_push_kv_str(out, "policy_file", MARKET_MODERATION_POLICY_FILE);

    int64_t counts[MARKET_REVIEW_STATE_COUNT] = {0, 0, 0};
    struct zcl_result counted = market_moderation_review_counts(counts);
    struct json_value by_state;
    json_init(&by_state);
    json_set_object(&by_state);
    for (int i = 0; i < MARKET_REVIEW_STATE_COUNT; i++)
        json_push_kv_int(&by_state,
                         market_review_state_string(
                             (enum market_review_state)i),
                         counted.ok ? counts[i] : 0);
    json_push_kv(out, "review_counts", &by_state);
    json_free(&by_state);
    json_push_kv_bool(out, "review_counts_live", counted.ok);
    /* See the same key on zmarket_moderation_status: the profile now also
     * gates what this node hands to another party, so reporting
     * view-filtering-only would understate its effect. */
    json_push_kv_bool(out, "view_filter_only", false);
    json_push_kv_bool(out, "serving_gated", true);
    return true;
}
