/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: exclusive process ownership of a canonical node database.
 * ar-validate-skip:connection-ownership-not-a-row */

#include "models/database_owner_lease.h"

#include "models/database.h"
#include "platform/file_compat.h"
#include "platform/path_compat.h"
#include "util/log_macros.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

enum { NODE_DB_OWNER_LEASES = 128 };
enum { NODE_DB_OWNER_PATH_MAX = 1100 };

/* ── Lease lock mechanism ──────────────────────────────────────────────
 * The lease is an advisory exclusive lock on ONE byte of node.db itself
 * (no sidecar artifacts; independent scratch databases stay independent).
 *
 * Linux keeps the historical flock(LOCK_EX). Darwin cannot: flock and POSIX
 * fcntl record locks share one kernel lock space there, so a held flock
 * blocks this same process's SQLite byte-range locks on the very inode the
 * lease protects (measured: hold flock(EX), then fcntl(F_SETLK, WRLCK) on a
 * second descriptor of the same process fails with EAGAIN). Every boot
 * would race its own lease. On that host the identical mutual exclusion is
 * carried by one fcntl record at an offset far above every byte SQLite can
 * address for its own locking region, so lease and database locks stay
 * disjoint advisory states on the exact inode — same ownership contract,
 * same fail-closed probes. */

#if defined(__APPLE__)
#define NODE_DB_OWNER_LEASE_LOCK_START ((off_t)0x0000F00000000000ULL)

static int owner_lease_apply(int fd, short type)
{
    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type = type;
    fl.l_whence = SEEK_SET;
    fl.l_start = NODE_DB_OWNER_LEASE_LOCK_START;
    fl.l_len = 1;
    return fcntl(fd, F_SETLK, &fl);
}

static int owner_lease_lock(int fd)
{
    return owner_lease_apply(fd, F_WRLCK);
}

static int owner_lease_unlock(int fd)
{
    return owner_lease_apply(fd, F_UNLCK);
}
#else
static int owner_lease_lock(int fd)
{
    return platform_file_lock_exclusive(fd);
}

static int owner_lease_unlock(int fd)
{
    return platform_file_unlock(fd);
}
#endif

struct node_db_owner_lease {
    char path[1024];
    int fd;
    unsigned refs;
    pid_t pid;
};

static pthread_mutex_t g_owner_lease_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct node_db_owner_lease g_owner_leases[NODE_DB_OWNER_LEASES];

static bool node_db_owner_lock_path(char out[NODE_DB_OWNER_PATH_MAX],
                                    const char *db_path)
{
#if defined(__APPLE__) || defined(_WIN32)
    int written = snprintf(out, NODE_DB_OWNER_PATH_MAX, "%s.owner-lock",
                           db_path);
    return written >= 0 && written < NODE_DB_OWNER_PATH_MAX;
#else
    int written = snprintf(out, NODE_DB_OWNER_PATH_MAX, "%s", db_path);
    return written >= 0 && written < NODE_DB_OWNER_PATH_MAX;
#endif
}

enum node_db_owner_lease_probe node_db_owner_lease_probe(const char *path)
{
    char identity[NODE_DB_OWNER_PATH_MAX];
    char lock_path[NODE_DB_OWNER_PATH_MAX];
    if (!path || !path[0]) return NODE_DB_OWNER_LEASE_PROBE_ERROR;
    if (strcmp(path, ":memory:") == 0) return NODE_DB_OWNER_LEASE_UNOWNED;
    if (!platform_path_identity(identity, sizeof(identity), path))
        return NODE_DB_OWNER_LEASE_PROBE_ERROR;
    pthread_mutex_lock(&g_owner_lease_mutex);
    for (int i = 0; i < NODE_DB_OWNER_LEASES; i++) {
        struct node_db_owner_lease *lease = &g_owner_leases[i];
        if (lease->refs > 0 && lease->pid == getpid() &&
            strcmp(lease->path, identity) == 0) {
            pthread_mutex_unlock(&g_owner_lease_mutex);
            return NODE_DB_OWNER_LEASE_OWNED_SELF;
        }
    }
    pthread_mutex_unlock(&g_owner_lease_mutex);
    if (!node_db_owner_lock_path(lock_path, identity))
        return NODE_DB_OWNER_LEASE_PROBE_ERROR;
#if defined(__APPLE__) || defined(_WIN32)
    if (access(path, F_OK) != 0)
        return errno == ENOENT ? NODE_DB_OWNER_LEASE_UNOWNED
                               : NODE_DB_OWNER_LEASE_PROBE_ERROR;
#endif
    int fd = platform_file_open_nofollow(lock_path, O_RDONLY, 0);
    if (fd < 0)
        return errno == ENOENT ? NODE_DB_OWNER_LEASE_UNOWNED
                               : NODE_DB_OWNER_LEASE_PROBE_ERROR;
#if defined(__APPLE__)
    /* The read-only probe descriptor cannot carry F_SETLK write attempts, so
     * the lease byte is interrogated instead: F_GETLK reports whichever
     * process, if any, currently owns the record. */
    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = NODE_DB_OWNER_LEASE_LOCK_START;
    fl.l_len = 1;
    int rc = fcntl(fd, F_GETLK, &fl);
    (void)close(fd);
    if (rc != 0)
        return NODE_DB_OWNER_LEASE_PROBE_ERROR;
    if (fl.l_type == F_UNLCK)
        return NODE_DB_OWNER_LEASE_UNOWNED;
    return fl.l_pid == getpid() ? NODE_DB_OWNER_LEASE_OWNED_SELF
                                : NODE_DB_OWNER_LEASE_LIVE;
#else
    if (owner_lease_lock(fd) == 0) {
        int unlock_rc = owner_lease_unlock(fd);
        int close_rc = close(fd);
        return unlock_rc == 0 && close_rc == 0
            ? NODE_DB_OWNER_LEASE_UNOWNED
            : NODE_DB_OWNER_LEASE_PROBE_ERROR;
    }
    int saved = errno;
    (void)close(fd);
    return saved == EWOULDBLOCK || saved == EAGAIN
        ? NODE_DB_OWNER_LEASE_LIVE : NODE_DB_OWNER_LEASE_PROBE_ERROR;
#endif
}

void node_db_owner_lease_release(struct node_db *ndb)
{
    char identity[NODE_DB_OWNER_PATH_MAX];
    if (!ndb || ndb->lifetime_owner_lease_slot < 0) return;
    if (!platform_path_identity(identity, sizeof(identity), ndb->path))
        return;
    pthread_mutex_lock(&g_owner_lease_mutex);
    int slot = ndb->lifetime_owner_lease_slot;
    struct node_db_owner_lease *lease =
        slot < NODE_DB_OWNER_LEASES ? &g_owner_leases[slot] : NULL;
    if (lease && lease->pid == getpid() && lease->refs > 0 &&
        strcmp(lease->path, identity) == 0) {
        lease->refs--;
        if (lease->refs == 0) {
            if (owner_lease_unlock(lease->fd) != 0)
                LOG_WARN("db", "database owner lease unlock failed for %s: %s",
                         ndb->path, strerror(errno));
            if (close(lease->fd) != 0)
                LOG_WARN("db", "database owner lease close failed for %s: %s",
                         ndb->path, strerror(errno));
            memset(lease, 0, sizeof(*lease));
            lease->fd = -1;
        }
    }
    pthread_mutex_unlock(&g_owner_lease_mutex);
    ndb->lifetime_owner_lease_slot = -1;
}

bool node_db_owner_lease_acquire(struct node_db *ndb, bool create_if_missing)
{
    char identity[NODE_DB_OWNER_PATH_MAX];
    char lock_path[NODE_DB_OWNER_PATH_MAX];
    if (!ndb || !ndb->path[0])
        LOG_FAIL("db", "database owner lease requires a path");
    if (strcmp(ndb->path, ":memory:") == 0) return true;
    if (!platform_path_identity(identity, sizeof(identity), ndb->path) ||
        !node_db_owner_lock_path(lock_path, identity))
        LOG_FAIL("db", "database owner lease path is too long: %s", ndb->path);
#if defined(__APPLE__) || defined(_WIN32)
    if (!create_if_missing && access(ndb->path, F_OK) != 0)
        LOG_FAIL("db", "database owner lease open failed for %s: %s",
                 ndb->path, strerror(errno));
#endif
    pthread_mutex_lock(&g_owner_lease_mutex);
    int free_slot = -1;
    for (int i = 0; i < NODE_DB_OWNER_LEASES; i++) {
        struct node_db_owner_lease *lease = &g_owner_leases[i];
        if (lease->refs > 0 && lease->pid != getpid()) {
            (void)close(lease->fd);
            memset(lease, 0, sizeof(*lease));
            lease->fd = -1;
        }
        if (lease->refs > 0 && lease->pid == getpid() &&
            strcmp(lease->path, identity) == 0) {
            lease->refs++;
            ndb->lifetime_owner_lease_slot = i;
            pthread_mutex_unlock(&g_owner_lease_mutex);
            return true;
        }
        if (lease->refs == 0 && free_slot < 0) free_slot = i;
    }
    if (free_slot < 0) {
        pthread_mutex_unlock(&g_owner_lease_mutex);
        LOG_FAIL("db", "database owner lease registry is full for %s", ndb->path);
    }
    /* Linux flock and SQLite's POSIX byte locks are independent, so the
     * database inode is the lease. Darwin implements flock through fcntl and
     * would make SQLite conflict with its own process; use one persistent
     * per-database lock inode there. Independent databases remain independent. */
    int open_flags = O_RDWR;
#if defined(__APPLE__) || defined(_WIN32)
    open_flags |= O_CREAT;
#else
    if (create_if_missing) open_flags |= O_CREAT;
#endif
    int fd = platform_file_open_nofollow(lock_path, open_flags, 0600);
    if (fd < 0) goto fail_locked;
    if (owner_lease_lock(fd) != 0) {
        int saved = errno;
        (void)close(fd);
        pthread_mutex_unlock(&g_owner_lease_mutex);
        LOG_FAIL("db", "DATABASE_OWNERSHIP_CONFLICT: canonical database owner "
                 "already holds path=%s (error=%s)", ndb->path,
                 strerror(saved));
    }
    struct node_db_owner_lease *lease = &g_owner_leases[free_slot];
    (void)snprintf(lease->path, sizeof(lease->path), "%s", identity);
    lease->fd = fd;
    lease->refs = 1;
    lease->pid = getpid();
    ndb->lifetime_owner_lease_slot = free_slot;
    pthread_mutex_unlock(&g_owner_lease_mutex);
    return true;

fail_locked:
    {
        int saved = errno;
        pthread_mutex_unlock(&g_owner_lease_mutex);
        LOG_FAIL("db", "database owner lease open failed for %s: %s",
                 ndb->path, strerror(saved));
    }
}

bool node_db_owner_lease_rebind(struct node_db *ndb)
{
    if (!ndb || ndb->lifetime_owner_lease_slot < 0)
        LOG_FAIL("db", "database owner lease rebind requires ownership");
#if defined(__APPLE__) || defined(_WIN32)
    char identity[NODE_DB_OWNER_PATH_MAX];
    if (!platform_path_identity(identity, sizeof(identity), ndb->path))
        LOG_FAIL("db", "database owner rebind path is invalid");
    pthread_mutex_lock(&g_owner_lease_mutex);
    int slot = ndb->lifetime_owner_lease_slot;
    struct node_db_owner_lease *lease =
        slot < NODE_DB_OWNER_LEASES ? &g_owner_leases[slot] : NULL;
    bool valid = lease && lease->pid == getpid() && lease->refs == 1 &&
                 strcmp(lease->path, identity) == 0;
    pthread_mutex_unlock(&g_owner_lease_mutex);
    if (!valid)
        LOG_FAIL("db", "database owner rebind found ambiguous ownership");
    return true;
#else
    int replacement = platform_file_open_nofollow(
        ndb->path, O_RDWR | O_CREAT, 0600);
    if (replacement < 0)
        LOG_FAIL("db", "database owner rebind open failed for %s: %s",
                 ndb->path, strerror(errno));
    if (owner_lease_lock(replacement) != 0) {
        int saved = errno;
        (void)close(replacement);
        LOG_FAIL("db", "DATABASE_OWNERSHIP_CONFLICT: replacement path=%s "
                 "was acquired during quarantine (error=%s)", ndb->path,
                 strerror(saved));
    }
    pthread_mutex_lock(&g_owner_lease_mutex);
    int slot = ndb->lifetime_owner_lease_slot;
    struct node_db_owner_lease *lease =
        slot < NODE_DB_OWNER_LEASES ? &g_owner_leases[slot] : NULL;
    if (!lease || lease->pid != getpid() || lease->refs != 1 ||
        strcmp(lease->path, ndb->path) != 0) {
        pthread_mutex_unlock(&g_owner_lease_mutex);
        (void)owner_lease_unlock(replacement);
        (void)close(replacement);
        LOG_FAIL("db", "database owner rebind found ambiguous ownership");
    }
    int retired = lease->fd;
    lease->fd = replacement;
    pthread_mutex_unlock(&g_owner_lease_mutex);
    (void)owner_lease_unlock(retired);
    (void)close(retired);
    return true;
#endif
}
