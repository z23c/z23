/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Run the per-node mind: hold the singleton lock, own every
 * registered checkout's index rebuild, and retire when its state file goes. */

#include "mind.h"

#include "codeindex/codeindex.h"
#include "codeindex/codeindex_build.h"
#include "base/hex.h"
#include "platform/directory_watcher.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>

/* The resident is a POSIX service: it holds a flock singleton and retires on
 * SIGTERM under systemd. Windows gets an honest refusal rather than a
 * half-built resident that cannot be stopped or made exclusive. Naming
 * _WIN32 here deliberately puts this file in the mingw cross-syntax sweep,
 * so the guard itself is compiled rather than assumed. */
#if !defined(_WIN32)
#include <fcntl.h>
#include <signal.h>
#include <sys/file.h>
#include <unistd.h>

/* One slice per registered checkout per cycle. The watcher wakes early on a
 * real edit; the slice only bounds how long a quiet cycle takes, and the
 * whole cycle is bounded by ZCL_MIND_CHECKOUTS_MAX slices. */
#define MIND_WATCH_SLICE_MS 500u
/* Well inside CODEINDEX_OWNER_HEARTBEAT_MAX_AGE_S: a claim must not lapse
 * because a cycle spent its whole time rebuilding a large tree. */
#define MIND_HEARTBEAT_INTERVAL_S 20

static volatile sig_atomic_t g_mind_stop;

static void mind_signal(int sig)
{
    (void)sig;
    g_mind_stop = 1;
}

/* The lock record. One line, replaced whole, exactly the shape the devloop
 * watcher uses for its singleton: "<pid> <state> <tag>". A reader learns who
 * holds the mind on this node without asking systemd. */
static int mind_lock_acquire(const char *path)
{
    int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        (void)close(fd);
        return -1;                        /* another mind already owns it */
    }
    if (ftruncate(fd, 0) == 0)
        (void)dprintf(fd, "%ld starting mind1\n", (long)getpid());
    return fd;
}

static bool mind_lock_ready(int fd)
{
    if (fd < 0 || ftruncate(fd, 0) != 0 || lseek(fd, 0, SEEK_SET) < 0)
        return false;
    return dprintf(fd, "%ld ready mind1\n", (long)getpid()) > 0;
}

/* Read what the published generation says about itself, without rebuilding
 * anything: this is the mind deciding whether it has work, and a decision
 * that rebuilt in order to be made would defeat the whole unit. */
static void mind_observe(struct zcl_mind_checkout *c, long long now)
{
    bool stale = true;
    struct codeindex *ci = codeindex_open_readonly(c->root, &stale);
    c->indexed = ci != NULL;
    c->stale = ci ? stale : true;
    c->index_age_s = codeindex_generation_age_s(c->root, now);
    c->index_bytes = codeindex_generation_bytes(c->root);
    c->index_root[0] = '\0';
    c->group_count = 0;
    c->files = c->symbols = c->includes = c->refs = 0;
    c->build_cold_ms = c->build_cold_files = 0;
    if (!ci)
        return;
    /* The metrics nobody else measures. They come from the store the mind
     * just published, under one lock, so the numbers describe one generation
     * rather than several taken as the tree moved. */
    struct ci_row_counts counts;
    if (codeindex_row_counts(ci, &counts)) {
        c->files = counts.files;
        c->symbols = counts.symbols;
        c->includes = counts.includes;
        c->refs = counts.refs;
    }
    /* Absent on a store built before the receipt existed. Absence stays zero
     * and is reported as zero; it is never filled in from this run's timing,
     * which measured a different build. */
    (void)codeindex_build_cold_ms(ci, &c->build_cold_ms, &c->build_cold_files);
    uint8_t root_sha3[32];
    if (codeindex_source_root_sha3(ci, root_sha3))
        zcl_hex_encode(root_sha3, sizeof(root_sha3), c->index_root);
    struct ci_group groups[ZCL_MIND_GROUPS_MAX];
    int n = codeindex_groups(ci, groups, ZCL_MIND_GROUPS_MAX);
    for (int i = 0; i < n && c->group_count < ZCL_MIND_GROUPS_MAX; i++) {
        int files = codeindex_count_files_in_group(ci, groups[i].path, true);
        if (files < 0)
            continue;                     /* an unanswerable count is absent */
        struct zcl_mind_group_row *row = &c->groups[c->group_count++];
        snprintf(row->name, sizeof(row->name), "%s", groups[i].path);
        row->files = files;
    }
    codeindex_close(ci);
}

/* The ONE call to codeindex_rebuild outside the codeindex module itself.
 * check-mind-owns-rebuild exists to keep that true. */
static bool mind_rebuild(struct zcl_mind_checkout *c, long long now)
{
    int64_t start = platform_time_monotonic_ms();
    /* Drop the claim for the duration of the mind's own rebuild: the marker
     * is what makes readers refuse, and the writer must not be refused by
     * its own claim when it opens the store to rebuild it. */
    (void)codeindex_owner_release(c->root, (long long)getpid());
    struct codeindex *ci = codeindex_open_readonly(c->root, NULL);
    bool ok = false;
    if (ci) {
        ok = codeindex_rebuild(ci);
        codeindex_close(ci);
    } else {
        /* No store yet: codeindex_open builds the first generation, and with
         * no live claim it is this process doing it. */
        ci = codeindex_open(c->root);
        ok = ci != NULL;
        codeindex_close(ci);
    }
    int64_t elapsed = platform_time_monotonic_ms() - start;
    c->last_rebuild_ms = elapsed < 0 ? 0 : (long long)elapsed;
    if (ok) {
        c->last_rebuild_unix = now;
        c->rebuilds++;
    }
    return ok;
}

static int mind_serve_posix(zcl_mind_stop_predicate stop, void *stop_opaque,
                            long long max_cycles)
{
    char lock_path[ZCL_MIND_PATH_MAX];
    struct zcl_mind_registry reg;
    if (!zcl_mind_lock_path(lock_path, sizeof(lock_path))) {
        LOG_ERROR("mind", "serve: cannot resolve the mind state directory");
        return 1;
    }
    if (!zcl_mind_registry_load(&reg) || reg.count == 0) {
        /* A mind with no registered checkout owns nothing. Starting anyway
         * would publish a heartbeat that claims a node is covered when no
         * index on it has an owner. */
        LOG_ERROR("mind", "serve: no checkout registered; nothing to own");
        return 1;
    }
    int lock_fd = mind_lock_acquire(lock_path);
    if (lock_fd < 0) {
        LOG_ERROR("mind", "serve: another mind already holds this node");
        return 1;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = mind_signal;
    (void)sigaction(SIGTERM, &sa, NULL);
    (void)sigaction(SIGINT, &sa, NULL);
    g_mind_stop = 0;

    struct zcl_mind_heartbeat beat;
    memset(&beat, 0, sizeof(beat));
    beat.pid = (long long)getpid();
    beat.started_unix = (long long)platform_time_wall_time_t();
    beat.checkout_count = reg.count;
    for (size_t i = 0; i < reg.count; i++)
        snprintf(beat.checkouts[i].root, sizeof(beat.checkouts[i].root), "%s",
                 reg.roots[i]);

    struct platform_directory_watcher watchers[ZCL_MIND_CHECKOUTS_MAX];
    bool watching[ZCL_MIND_CHECKOUTS_MAX];
    for (size_t i = 0; i < reg.count; i++) {
        platform_directory_watcher_init(&watchers[i]);
        watching[i] = platform_directory_watcher_open(&watchers[i],
                                                      reg.roots[i]);
        if (!watching[i])
            LOG_WARN("mind", "serve: cannot watch %s; polling it instead",
                     reg.roots[i]);
    }

    if (!mind_lock_ready(lock_fd))
        LOG_WARN("mind", "serve: lock record not updated to ready");

    int rc = 0;
    long long cycles = 0;
    long long last_beat = 0;
    for (;;) {
        long long now = (long long)platform_time_wall_time_t();
        for (size_t i = 0; i < beat.checkout_count; i++) {
            struct zcl_mind_checkout *c = &beat.checkouts[i];
            mind_observe(c, now);
            if (c->stale && !mind_rebuild(c, now))
                LOG_WARN("mind", "serve: rebuild refused for %s", c->root);
            if (c->stale)
                mind_observe(c, now);
            /* Claim last: the marker means "a live owner has this checkout
             * in hand", so it is written after the work, never before it. */
            (void)codeindex_owner_claim(c->root, beat.pid, now);
            if (c->last_rebuild_ms > beat.last_rebuild_ms)
                beat.last_rebuild_ms = c->last_rebuild_ms;
        }
        beat.beat_unix = now;
        if (!zcl_mind_heartbeat_write(&beat))
            LOG_WARN("mind", "serve: heartbeat not published");
        last_beat = now;
        cycles++;
        if (max_cycles >= 0 && cycles >= max_cycles)
            break;

        /* Wait for an edit. Each registered checkout gets one slice; a quiet
         * node therefore wakes at most every count*slice ms, which is what
         * keeps the claim fresh without a timer of its own. */
        bool changed = false;
        while (!changed) {
            if (g_mind_stop || (stop && stop(stop_opaque)))
                goto retire;
            for (size_t i = 0; i < beat.checkout_count && !changed; i++) {
                if (!watching[i]) continue;
                enum platform_directory_watch_result r =
                    platform_directory_watcher_wait(&watchers[i],
                                                    MIND_WATCH_SLICE_MS, NULL,
                                                    NULL);
                if (r == PLATFORM_DIRECTORY_WATCH_CHANGED ||
                    r == PLATFORM_DIRECTORY_WATCH_OVERFLOW)
                    changed = true;
                else if (r == PLATFORM_DIRECTORY_WATCH_ERROR) {
                    watching[i] = false;
                    LOG_WARN("mind", "serve: watch lost on %s",
                             beat.checkouts[i].root);
                }
            }
            /* The registry is the retirement switch, so it is re-read on
             * every wait pass and not only when something changed. */
            struct zcl_mind_registry current;
            if (!zcl_mind_registry_load(&current) || current.count == 0)
                goto retire;
            long long now_s = (long long)platform_time_wall_time_t();
            if (!changed && now_s - last_beat >= MIND_HEARTBEAT_INTERVAL_S)
                break;                     /* refresh the claim on a quiet box */
        }
    }

retire:
    for (size_t i = 0; i < beat.checkout_count; i++) {
        if (watching[i])
            platform_directory_watcher_close(&watchers[i]);
        /* Retiring means releasing the claim. A marker left behind by a dead
         * mind would refuse every query for two more minutes for nothing. */
        (void)codeindex_owner_release(beat.checkouts[i].root, beat.pid);
    }
    (void)close(lock_fd);
    (void)remove(lock_path);
    return rc;
}

#else /* _WIN32 */

static int mind_serve_posix(zcl_mind_stop_predicate stop, void *stop_opaque,
                            long long max_cycles)
{
    (void)stop; (void)stop_opaque; (void)max_cycles;
    LOG_ERROR("mind", "serve: the mind resident is POSIX-only on this build");
    return 1;
}

#endif /* _WIN32 */

/* ONE definition of the public entry point, above the platform split: the
 * arms differ only in how the singleton and the watch are held, and two
 * non-static bodies for one name is exactly what check-arm-symbol-single
 * refuses — the strictest arm would otherwise be invisible to the other. */
int zcl_mind_serve(zcl_mind_stop_predicate stop, void *stop_opaque,
                   long long max_cycles)
{
    return mind_serve_posix(stop, stop_opaque, max_cycles);
}
