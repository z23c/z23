/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: resident-watcher launch identity and whole-session stop (POSIX). */

#ifndef ZCL_TOOLS_DEVLOOP_WATCH_SESSION_H
#define ZCL_TOOLS_DEVLOOP_WATCH_SESSION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The singleton lock (ZCL_DEVLOOP_WATCH_LOCK_REL) says which watcher owns a
 * checkout right now. It cannot say which processes a launcher started for
 * that checkout: a watcher that leaves its loop releases the lock before its
 * proof worker has exited, and a watcher killed outright leaves that worker
 * running with no lock at all. Every launcher therefore records the session
 * it forks — the child is a setsid() session and process-group leader that
 * works from the checkout root — as
 * <root>/ZCL_DEVLOOP_WATCH_SESSION_DIR_REL/<pid>: the pid, its kernel birth
 * token, the boot it was born in, and the device and inode of the image it
 * runs. The watcher removes its own record when it exits cleanly.
 *
 * A record is a claim, not a proof: a recycled pid, a record left by a
 * crash or a reboot, or a record forged by anything that can write the
 * checkout all look alike on disk. A record names a watcher only while the
 * running processes still satisfy it (Linux, from /proc):
 *   - the record is a regular, single-link file in a directory owned by
 *     this user and writable by no one else, and it was written this boot;
 *   - LIVE: the leader is running with the recorded birth token, runs the
 *     recorded image, that image is a dev binary (this process's own image,
 *     or a file named z23-dev, zclassic23-dev, z23.dev or *-z23-dev,
 *     *-zclassic23-dev), and its working directory is the checkout root;
 *   - ORPHANED: the leader is dead or exiting, and every surviving member
 *     of its session whose image can still be read runs that recorded dev
 *     image, at least one of them from the checkout root.
 * A record is pruned only when it is disproven: it is not trusted as above,
 * it was written in another boot, its pid now has another birth token, a
 * surviving member (or the leader) runs another image, or nothing of its
 * session is left. A trusted record that can be neither proven nor
 * disproven right now (the boot id cannot be read, the session is too large
 * to list whole, no surviving member's image and root can be read) is
 * UNPROVEN: it is kept, it is never signalled, and a launcher treats it as
 * a watcher still retiring, so it never forks beside it.
 *
 * Other POSIX systems (macOS) have no /proc: nothing is recorded, only the
 * lock owner whose image is a dev binary can be stopped, and "gone" means
 * its process group is gone — members that left the group are not seen. */
#define ZCL_DEVLOOP_WATCH_SESSION_DIR_REL ".cache/zcl-dev-watch.d"

enum zcl_devloop_watch_session_state {
    /* No record, or a record the running processes do not satisfy. */
    ZCL_DEVLOOP_WATCH_SESSION_ABSENT = 0,
    /* The recorded leader is running and proven. */
    ZCL_DEVLOOP_WATCH_SESSION_LIVE,
    /* The leader is gone; its surviving session members are proven. */
    ZCL_DEVLOOP_WATCH_SESSION_ORPHANED,
    /* Recorded this boot, and nothing of the session is left. */
    ZCL_DEVLOOP_WATCH_SESSION_GONE,
    /* A trusted record that cannot be proven or disproven right now: kept,
     * never signalled, and counted as retiring. */
    ZCL_DEVLOOP_WATCH_SESSION_UNPROVEN,
};

enum zcl_devloop_watch_stop_result {
    ZCL_DEVLOOP_WATCH_STOPPED = 0,
    ZCL_DEVLOOP_WATCH_STOP_NOT_RUNNING,
    ZCL_DEVLOOP_WATCH_STOP_ID_MISMATCH,
    ZCL_DEVLOOP_WATCH_STOP_SIGNAL_FAILED,
    ZCL_DEVLOOP_WATCH_STOP_TIMEOUT,
    /* The requested session is recorded but cannot be proven right now:
     * nothing was signalled and the record is kept. */
    ZCL_DEVLOOP_WATCH_STOP_UNPROVEN,
};

struct zcl_devloop_watch_stop {
    /* in: pid named by the held singleton lock, 0 when the lock is free */
    int64_t owner_pid;
    /* in: when nonzero, the birth token the caller's own identity names
     * (the lock owner's start token from a status receipt); a record
     * carrying another birth is refused untouched */
    uint64_t expect_born;
    /* in: cooperative SIGTERM phase; escalation adds a bounded tail */
    int64_t budget_ms;
    /* out: the requested watcher had already given up the lock */
    bool retired;
    /* out: 0 cooperative exit, 1 session SIGTERM, 2 session SIGKILL */
    int escalation;
    /* out: processes of the session still running when stop returned */
    size_t members_left;
};

/* Record a just-forked watcher leader. Called by the launching parent. */
bool zcl_devloop_watch_session_record(const char *root, int64_t pid);

/* Remove the record naming `pid` if it still names that very process. The
 * watcher calls this for itself on a clean exit. */
void zcl_devloop_watch_session_release(const char *root, int64_t pid);

enum zcl_devloop_watch_session_state zcl_devloop_watch_session_probe(
    const char *root, int64_t pid);

/* A recorded session other than `owner_pid` that is still running (a
 * watcher starting up, or one retiring without the lock), or 0: a proven
 * one, or an UNPROVEN one that is kept until it can be decided. Records
 * that are gone or disproven are pruned. A launcher must not start a new
 * watcher while this is nonzero: that is how duplicates were born. */
int64_t zcl_devloop_watch_session_retiring(const char *root,
                                           int64_t owner_pid);

/* A launcher's admission: 0 when it may attach to the watcher that owns
 * the lock (`owner_active`) or start one, else the pid of a proven session
 * still running without the lock after waiting up to `budget_ms` for it to
 * take the lock or finish. The launcher must then refuse, naming that pid;
 * it never forks beside it. */
int64_t zcl_devloop_watch_session_admit(const char *root,
                                        bool (*owner_active)(const char *root),
                                        int64_t budget_ms);

/* Stop exactly the watcher `requested`, and only while a proven record
 * (carrying `expect_born` when the caller names one) confirms it: the lock
 * owner, or a session that no longer owns the lock. A lock owner with no
 * record is refused: `dev loop stop` asks it to stop through its bound
 * session endpoint instead, then passes its leaderless remainder here.
 * Returns STOPPED only after that session has no process left (on macOS:
 * its process group), escalating to a session-wide SIGTERM and then
 * repeated SIGKILL, re-proving the session before every escalation. A
 * caller inside that session signals only the leader. Anything unproven is
 * refused untouched. */
enum zcl_devloop_watch_stop_result zcl_devloop_watch_session_stop(
    const char *root, int64_t requested, struct zcl_devloop_watch_stop *io);

#if defined(ZCL_TESTING) && !defined(_WIN32)
/* Deterministic stand-ins for what a test cannot stage: another user's
 * process behind a reused pid, and a record rewritten while it is judged. */
struct zcl_devloop_watch_session_test_hooks {
    /* kill(pid, 0) reports EPERM for this pid (0: none). */
    int64_t signal0_denied_pid;
    /* Runs just before a record is removed. */
    void (*before_forget)(const char *root, int64_t pid, void *opaque);
    void *opaque;
};
/* NULL restores the defaults. */
void zcl_devloop_watch_session_test_hooks_set(
    const struct zcl_devloop_watch_session_test_hooks *hooks);
#endif

#endif
