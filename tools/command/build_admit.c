/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: build admission — lanes, FIFO tickets, landing markers and the
 *          heavy lock, in the on-disk format of the installed devbuild
 *          wrapper's z23 project (see command/build_admit.h).
 */

#include "command/build_admit.h"

#ifndef _WIN32

#include "base/safe_alloc.h"
#include "util/file_tree_ops.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop;

void ba_request_stop(int signo)
{
    g_stop = signo;
}

int ba_stop_signal(void)
{
    return g_stop;
}

static bool ba_join(char *out, size_t cap, const char *dir, const char *name)
{
    int n = snprintf(out, cap, "%s/%s", dir, name);
    return n > 0 && (size_t)n < cap;
}

static void ba_nap(unsigned ms)
{
    struct timespec ts = { .tv_sec = ms / 1000u,
                           .tv_nsec = (long)(ms % 1000u) * 1000000L };
    (void)nanosleep(&ts, NULL);
}

/* Take `op` on `fd`; true when held. A pending stop request ends a blocking
 * wait early so a signalled job can leave the queue. */
static bool ba_flock(int fd, int op, bool wait)
{
    for (;;) {
        if (flock(fd, wait ? op : (op | LOCK_NB)) == 0)
            return true;
        if (errno != EINTR || g_stop)
            return false;
    }
}

static int ba_open_lock(const char *path)
{
    return open(path, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
}

/* A waiter file is live while any process holds a shared flock on it. */
static bool ba_alive(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    bool busy = flock(fd, LOCK_EX | LOCK_NB) != 0 && errno == EWOULDBLOCK;
    close(fd);
    return busy;
}

static int ba_name_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static bool ba_names_push(char (**names)[BA_NAME_MAX], size_t *n, size_t *cap,
                          const char *name)
{
    if (*n == *cap) {
        size_t grown = *cap ? *cap * 2u : 64u;
        char (*bigger)[BA_NAME_MAX] =
            zcl_realloc(*names, grown * sizeof(**names), "build_queue_names");
        if (!bigger)
            return false;
        *names = bigger;
        *cap = grown;
    }
    memcpy((*names)[(*n)++], name, strlen(name) + 1u);
    return true;
}

bool ba_list_names(const char *dir, char (**names)[BA_NAME_MAX], size_t *count)
{
    DIR *d = opendir(dir);
    size_t cap = 0;
    *names = NULL;
    *count = 0;
    if (!d)
        return true;
    for (struct dirent *e = readdir(d); e; e = readdir(d)) {
        if (e->d_name[0] == '.' || strlen(e->d_name) >= BA_NAME_MAX)
            continue;
        if (!ba_names_push(names, count, &cap, e->d_name)) {
            closedir(d);
            free(*names);
            *names = NULL;
            *count = 0;
            return false;
        }
    }
    closedir(d);
    qsort(*names, *count, BA_NAME_MAX, ba_name_cmp);
    return true;
}

/* A waiter in `dir`, older than `self` when given, still holds its flock.
 * Dead entries met on the way are removed. A queue that cannot be read is
 * treated as occupied so a job never overtakes waiters it cannot see. */
static bool ba_other_live(const char *dir, const char *self)
{
    char (*names)[BA_NAME_MAX];
    size_t n;
    bool live = false;
    if (!ba_list_names(dir, &names, &n)) {
        (void)fprintf(stderr, "devbuild: out of memory reading %s\n", dir);
        return true;
    }
    for (size_t i = 0; i < n && !live; i++) {
        char path[BA_PATH_MAX];
        if (self && strcmp(names[i], self) >= 0)
            continue;
        if (!ba_join(path, sizeof(path), dir, names[i]))
            continue;
        live = ba_alive(path);
        if (!live)
            (void)unlink(path);
    }
    free(names);
    return live;
}

struct ba_wait {
    char path[BA_PATH_MAX];
    char name[BA_NAME_MAX];
    int fd;
};

static void ba_wait_init(struct ba_wait *w)
{
    w->path[0] = w->name[0] = '\0';
    w->fd = -1;
}

static void ba_wait_drop(struct ba_wait *w)
{
    if (w->path[0])
        (void)unlink(w->path);
    if (w->fd >= 0)
        close(w->fd);
    ba_wait_init(w);
}

/* Create `<dir>/<ns>-<pid>` already holding its shared flock: it is built
 * under a dot name the scanners skip and renamed into place, so a scanner
 * never sees it unlocked. */
static bool ba_wait_register(const char *dir, struct ba_wait *w)
{
    struct timespec ts;
    char hidden[BA_PATH_MAX];
    (void)mkdir(dir, 0700);
    (void)clock_gettime(CLOCK_REALTIME, &ts); // platform-ok: ticket names carry the wrapper's wall-clock nanosecond format
    (void)snprintf(w->name, sizeof(w->name), "%lld%09ld-%d",
                   (long long)ts.tv_sec, ts.tv_nsec, (int)getpid());
    if (!ba_join(w->path, sizeof(w->path), dir, w->name) ||
        snprintf(hidden, sizeof(hidden), "%s/.pending-%d", dir,
                 (int)getpid()) >= (int)sizeof(hidden))
        return false;
    w->fd = open(hidden, O_RDONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (w->fd < 0 || flock(w->fd, LOCK_SH) != 0 ||
        rename(hidden, w->path) != 0) {
        if (w->fd >= 0)
            close(w->fd);
        (void)unlink(hidden);
        ba_wait_init(w);
        return false;
    }
    return true;
}

void ba_slot_release(struct ba_slot *slot)
{
    for (int i = 0; i < BA_MAX_LANES; i++) {
        if (slot->lane_fd[i] >= 0)
            close(slot->lane_fd[i]);
        slot->lane_fd[i] = -1;
    }
    if (slot->heavy_fd >= 0)
        close(slot->heavy_fd);
    slot->heavy_fd = -1;
    slot->lane = 0;
}

struct ba_queue {
    const struct ba_config *cfg;
    char prio_dir[BA_PATH_MAX];
    char fifo_dir[BA_PATH_MAX];
    struct ba_wait marker;
    struct ba_wait ticket;
};

static bool ba_queue_open(struct ba_queue *q, const struct ba_config *cfg)
{
    q->cfg = cfg;
    ba_wait_init(&q->marker);
    ba_wait_init(&q->ticket);
    if (!ba_join(q->prio_dir, sizeof(q->prio_dir), cfg->state_dir, "z23.prio") ||
        !ba_join(q->fifo_dir, sizeof(q->fifo_dir), cfg->state_dir, "z23.fifo"))
        return false;
    (void)mkdir(q->prio_dir, 0700);
    if (cfg->priority)
        return ba_wait_register(q->prio_dir, &q->marker);
    return !cfg->wait || ba_wait_register(q->fifo_dir, &q->ticket);
}

static void ba_queue_close(struct ba_queue *q)
{
    ba_wait_drop(&q->marker);
    ba_wait_drop(&q->ticket);
}

/* Only the FIFO head, or a landing job, may take a lane. */
static bool ba_is_head(const struct ba_queue *q)
{
    if (!q->cfg->priority && ba_other_live(q->prio_dir, NULL))
        return false;
    if (q->ticket.fd >= 0 && ba_other_live(q->fifo_dir, q->ticket.name))
        return false;
    return true;
}

static int ba_stopped(void)
{
    return 128 + g_stop;
}

static bool ba_open_lanes(const struct ba_config *cfg, struct ba_slot *slot)
{
    static const char *const name[BA_MAX_LANES] = {
        "z23.lock", "z23.lock.1", "z23.lock.2", "z23.lock.3"
    };
    for (unsigned i = 0; i < cfg->lanes; i++) {
        char path[BA_PATH_MAX];
        if (!ba_join(path, sizeof(path), cfg->state_dir, name[i]))
            return false;
        slot->lane_fd[i] = ba_open_lock(path);
        if (slot->lane_fd[i] < 0)
            return false;
    }
    return true;
}

static int ba_busy(const char *what)
{
    (void)fprintf(stderr, "devbuild: z23 %s; use --wait\n", what);
    return BA_EXIT_DEFERRED;
}

/* Several lanes: poll for the head position and a free lane. */
static int ba_take_lane(const struct ba_queue *q, struct ba_slot *slot)
{
    const struct ba_config *cfg = q->cfg;
    for (;;) {
        if (g_stop)
            return ba_stopped();
        if (ba_is_head(q)) {
            for (unsigned i = 0; i < cfg->lanes; i++) {
                if (ba_flock(slot->lane_fd[i], LOCK_EX, false)) {
                    slot->lane = (int)i + 1;
                    return 0;
                }
            }
        }
        if (!cfg->wait)
            return ba_busy("build lanes busy");
        ba_nap(cfg->poll_ms);
    }
}

/* One lane: hold the lock, then hand it back while an older waiter lives. */
static int ba_take_single(const struct ba_queue *q, struct ba_slot *slot)
{
    const struct ba_config *cfg = q->cfg;
    for (;;) {
        if (!ba_flock(slot->lane_fd[0], LOCK_EX, cfg->wait))
            return g_stop ? ba_stopped() : ba_busy("build slot busy");
        if (q->ticket.fd < 0 || ba_is_head(q))
            return 0;
        (void)flock(slot->lane_fd[0], LOCK_UN);
        ba_nap(cfg->poll_ms);
    }
}

static int ba_admit_lane(const struct ba_config *cfg, struct ba_slot *slot)
{
    struct ba_queue q;
    int rc;
    if (!ba_queue_open(&q, cfg) || !ba_open_lanes(cfg, slot)) {
        (void)fprintf(stderr, "devbuild: cannot open queue state in %s: %s\n",
                      cfg->state_dir, strerror(errno));
        ba_queue_close(&q);
        return BA_EXIT_DEFERRED;
    }
    rc = cfg->lanes > 1 ? ba_take_lane(&q, slot) : ba_take_single(&q, slot);
    ba_queue_close(&q);
    return rc;
}

/* The heavy lock is shared by every admitted job, so an exclusive holder in
 * the wrapper (a whole-host build) still excludes this one. */
static int ba_take_heavy(const struct ba_config *cfg, struct ba_slot *slot)
{
    char path[BA_PATH_MAX];
    if (!ba_join(path, sizeof(path), cfg->state_dir, "heavy.lock") ||
        (slot->heavy_fd = ba_open_lock(path)) < 0) {
        (void)fprintf(stderr, "devbuild: cannot open %s\n", path);
        return BA_EXIT_DEFERRED;
    }
    if (ba_flock(slot->heavy_fd, LOCK_SH, cfg->wait))
        return 0;
    if (g_stop)
        return ba_stopped();
    (void)fprintf(stderr, "devbuild: exclusive build running; use --wait\n");
    return BA_EXIT_DEFERRED;
}

int ba_admit(const struct ba_config *cfg, struct ba_slot *slot)
{
    int rc;
    slot->lane = 0;
    slot->heavy_fd = -1;
    for (int i = 0; i < BA_MAX_LANES; i++)
        slot->lane_fd[i] = -1;
    if (!zcl_mkdir_p(cfg->state_dir, 0700).ok) {
        (void)fprintf(stderr, "devbuild: cannot create %s\n", cfg->state_dir);
        return BA_EXIT_DEFERRED;
    }
    rc = ba_admit_lane(cfg, slot);
    if (rc == 0)
        rc = ba_take_heavy(cfg, slot);
    if (rc != 0)
        ba_slot_release(slot);
    return rc;
}

#endif /* _WIN32 */
