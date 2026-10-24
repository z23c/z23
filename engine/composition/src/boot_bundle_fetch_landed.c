// supervisor-ok:bounded-reseed — one-shot worker, registry-owned and joined by thread_registry_join_all at shutdown; no resident service
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: warm-boot support for an already-landed checkpoint bundle.
 *
 * Before: every restart re-hashed the 514 MB bundle (rom_fetch_verify_file) and
 * then rom_seed_register hashed it again, ~3 s with no [boot] timer, before RPC
 * and P2P start. Now (a) a stamp recorded after a successful full verify lets
 * the next boot skip the first pass when size, mtime, inode and chunk root are
 * unchanged, and (b) the rom_seed registration runs on a tracked background
 * thread. The registration passes the manifest's whole-file SHA3, so the bundle
 * is registered (served) only if its bytes verify; a corrupt file is logged and
 * never served. Joined by thread_registry_join_all in the shutdown worker
 * drain; the thread owns copies of everything it reads.
 */

#include "boot_bundle_fetch_landed_internal.h"
#include "boot_timing_marks_internal.h"
#include "config/boot_bundle_fetch.h"
#include "encoding/utilstrencodings.h"
#include "net/rom_seed.h"
#include "platform/private_file.h"
#include "platform/time_compat.h"
#include "platform/safe_root_read.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/thread_registry.h"

#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BBF_SUBSYS "bundle-fetch"
#define BBF_STAMP_MAX 512

static pthread_mutex_t g_reseed_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_reseed_cv = PTHREAD_COND_INITIALIZER;
static unsigned g_reseed_pending;
static atomic_bool g_reseed_hold;

struct bbf_reseed_job {
    char datadir[PATH_MAX];
    struct rom_fetch_manifest m;
};

void bbf_reseed_landed(const char *datadir, const struct rom_fetch_manifest *m)
{
    char reseed_name[ROM_SEED_NAME_MAX];
    int rnn = snprintf(reseed_name, sizeof(reseed_name), "%s/%s",
                       ROM_SEED_BUNDLES_SUBDIR, m->filename);
    if (rnn > 0 && (size_t)rnn < sizeof(reseed_name)) {
        enum rom_register_result rrc =
            rom_seed_register(datadir, reseed_name, m->whole_sha3, NULL);
        if (rrc == ROM_REG_OK)
            LOG_INFO(BBF_SUBSYS,
                     "reseed: registered fetched bundle '%s' with rom_seed — "
                     "this node now serves it to the swarm", reseed_name);
        else
            LOG_WARN(BBF_SUBSYS,
                     "reseed: could not register fetched bundle '%s' (rc=%d) "
                     "— not served; the next rom_seed scan re-checks it",
                     reseed_name, (int)rrc);
    } else {
        LOG_WARN(BBF_SUBSYS,
                 "reseed: bundle relative name overflow — the next rom_seed "
                 "scan will pick it up");
    }
}

static void bbf_reseed_finish(void)
{
    pthread_mutex_lock(&g_reseed_mu);
    if (g_reseed_pending > 0)
        g_reseed_pending--;
    pthread_cond_broadcast(&g_reseed_cv);
    pthread_mutex_unlock(&g_reseed_mu);
}

static void *bbf_reseed_main(void *arg)
{
    struct bbf_reseed_job *job = arg;
    while (atomic_load(&g_reseed_hold) &&
           !thread_registry_shutdown_requested())
        platform_sleep_ms(5);
    int64_t t0 = boot_clock_ms();
    bbf_reseed_landed(job->datadir, &job->m);
    (void)boot_submark("bundle.reseed (background)", t0);
    free(job);
    bbf_reseed_finish();
    return NULL;
}

void bbf_reseed_landed_async(const char *datadir,
                             const struct rom_fetch_manifest *m)
{
    struct bbf_reseed_job *job = zcl_malloc(sizeof(*job), "bbf_reseed_job");
    if (!job || snprintf(job->datadir, sizeof(job->datadir), "%s", datadir) >=
                    (int)sizeof(job->datadir)) {
        free(job);
        bbf_reseed_landed(datadir, m);
        return;
    }
    job->m = *m;
    pthread_mutex_lock(&g_reseed_mu);
    g_reseed_pending++;
    pthread_mutex_unlock(&g_reseed_mu);
    // thread-supervision-ok: registry-owned worker, reaped by thread_registry_join_all at shutdown; owns copies only
    if (thread_registry_spawn("zcl_bbf_reseed", bbf_reseed_main, job, NULL) ==
        0)
        return;
    (void)bbf_reseed_main(job);
}

void boot_bundle_fetch_reseed_wait(void)
{
    pthread_mutex_lock(&g_reseed_mu);
    while (g_reseed_pending > 0)
        pthread_cond_wait(&g_reseed_cv, &g_reseed_mu);
    pthread_mutex_unlock(&g_reseed_mu);
}

void boot_bundle_fetch_reseed_test_hold(bool hold)
{
    atomic_store(&g_reseed_hold, hold);
}

/* ── Verified stamp ─────────────────────────────────────────────────────── */

static long long bbf_mtime_ns(const struct stat *st)
{
#if defined(__APPLE__)
    return (long long)st->st_mtimespec.tv_sec * 1000000000LL +
           st->st_mtimespec.tv_nsec;
#elif defined(_WIN32)
    return (long long)st->st_mtime * 1000000000LL;
#else
    return (long long)st->st_mtim.tv_sec * 1000000000LL + st->st_mtim.tv_nsec;
#endif
}

static bool bbf_stamp_text(const struct stat *st,
                           const struct rom_fetch_manifest *m, char *out,
                           size_t cap)
{
    char root[65];
    HexStr(m->chunk_root, 32, false, root, sizeof(root));
    int n = snprintf(out, cap, "zcl-bbf-verified-v1 size=%llu mtime_ns=%lld "
                     "ino=%llu root=%s\n", (unsigned long long)st->st_size,
                     bbf_mtime_ns(st), (unsigned long long)st->st_ino, root);
    return n > 0 && (size_t)n < cap;
}

static bool bbf_stamp_path(const char *path, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s.verified", path);
    return n > 0 && (size_t)n < cap;
}

bool bbf_landed_stamp_matches(const char *path, const struct stat *st,
                              const struct rom_fetch_manifest *m)
{
    char sp[PATH_MAX], want[BBF_STAMP_MAX];
    if (!bbf_stamp_path(path, sp, sizeof(sp)) ||
        !bbf_stamp_text(st, m, want, sizeof(want)))
        return false;
    uint8_t *bytes = NULL;
    size_t size = 0;
    const char *slash = strrchr(sp, '/');
    if (!slash)
        return false;
    char root[PATH_MAX];
    snprintf(root, sizeof(root), "%.*s", (int)(slash - sp), sp);
    bool ok = platform_safe_root_read(root, slash + 1, BBF_STAMP_MAX, &bytes,
                                      &size) == PLATFORM_SAFE_ROOT_READ_OK &&
              size == strlen(want) && memcmp(bytes, want, size) == 0;
    free(bytes);
    return ok;
}

void bbf_landed_stamp_write(const char *path, const struct stat *st,
                            const struct rom_fetch_manifest *m)
{
    char sp[PATH_MAX], tmp[PATH_MAX + 8], text[BBF_STAMP_MAX];
    if (!bbf_stamp_path(path, sp, sizeof(sp)) ||
        !bbf_stamp_text(st, m, text, sizeof(text)) ||
        snprintf(tmp, sizeof(tmp), "%s.tmp", sp) >= (int)sizeof(tmp))
        return;
    (void)platform_private_file_unlink_missing_ok(tmp);
    struct platform_private_file f;
    platform_private_file_init(&f);
    if (!platform_private_file_create(tmp, &f) ||
        !platform_private_file_write_at(&f, text, strlen(text), 0) ||
        !platform_private_file_flush(&f) ||
        !platform_private_file_replace(&f, tmp, sp))
        (void)platform_private_file_retire(&f, tmp);
    platform_private_file_close(&f);
}
