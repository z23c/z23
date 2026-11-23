/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: lifecycle of the test runner's tmpfs scratch roots under
 *          /dev/shm/z23-scratch/<hash>.<rand>. A live runner holds an flock
 *          on <root>/.z23-runner.lock for its whole life, so a root is
 *          provably dead when that lock can be taken, not guessed from age.
 *          Evidence the runner means to keep carries <root>/.z23-keep, which
 *          protects the root for TSR_KEEP_SECONDS and then lets it be reaped.
 *          Every walk is descriptor-relative: no path-length limit, symlinks
 *          are unlinked and never followed, and the walk never leaves the
 *          root's filesystem. The host janitor (tools/scripts/host_gc.sh)
 *          applies the same proof with flock(1).
 */
#ifndef TEST_SCRATCH_REAP_H
#define TEST_SCRATCH_REAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define TSR_LOCK_NAME ".z23-runner.lock"
#define TSR_KEEP_NAME ".z23-keep"
/* A root younger than this may be a runner between mkdtemp and its lock. */
#define TSR_GRACE_SECONDS 120
/* Roots without a lock file (older runners) need this age and no user. */
#define TSR_LEGACY_AGE_SECONDS (6 * 3600)
#define TSR_KEEP_SECONDS (24 * 3600)

struct tsr_report {
    size_t live;      /* lock held, or a process has a cwd/fd inside */
    size_t kept;      /* unexpired keep marker */
    size_t young;     /* inside the grace or legacy age floor */
    size_t foreign;   /* wrong name shape, not a directory, or another uid */
    size_t dead;      /* provably dead: reapable */
    size_t reaped;
    size_t failed;
    uint64_t dead_bytes;
    uint64_t reaped_bytes;
};

/* Remove parent/name through descriptors, making read-only directories
 * writable first. Adds the allocated bytes it saw to *bytes. With apply false
 * nothing is changed and only the bytes are measured. 0 on success. */
int tsr_remove_tree(int parentfd, const char *name, bool apply, uint64_t *bytes);

/* mkdtemp-shaped name: 8 lowercase hex digits, '.', 6 more characters. */
bool tsr_name_is_root(const char *name);

/* Create and exclusively lock <root>/.z23-runner.lock. Returns the open
 * descriptor (hold it until exit) or -1. */
int tsr_lock_root(const char *root);

/* Mark <root> as evidence to keep for TSR_KEEP_SECONDS. */
bool tsr_keep_mark(const char *root);

/* Classify every root under parent and, with apply, remove the dead ones.
 * uid is the owner whose roots may be reaped; the parent itself must belong
 * to the caller and be closed to group and world writes. Returns 0, or -1 when the
 * parent is unreadable or unsafe (a missing parent is 0 with nothing found). */
int tsr_reap_parent(const char *parent, uid_t uid, int64_t now, bool apply,
                    struct tsr_report *report);

/* Cases proven by the test_group_selector group
 * (tests/harness/src/test_scratch_reap_cases.c); returns the failure count. */
int scratch_reap_run_cases(void);

#endif
