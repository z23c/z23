/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fixture tests for the node.db foreign-writer watch:
 *   - os_proc_foreign_writer_find: a same-uid child holding the database or
 *     its -wal read-write is reported; a read-only holder and a -shm holder
 *     are not; a symlinked path resolves to the same inode; the scan stops
 *     at its pid bound and says so.
 *   - invariant_sentinel_node_db_writer_report: the report never latches
 *     EV_OPERATOR_NEEDED (the terminal=0 form), and a repeat from the same
 *     pid inside the window is suppressed.
 */

#include "test/test_core.h"
#include "platform/os_proc.h"
#include "event/alerts.h"
#include "event/event.h"
#include "services/invariant_sentinel.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define FWRITER_CHECK(name, expr) do { \
    printf("node_db_foreign_writer: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* A fixture directory with node.db and its sidecars, all as real files, so
 * the scan has inodes to match. */
struct writer_fixture {
    char dir[PATH_MAX];
    char path[PATH_MAX];
    char wal[PATH_MAX];
    char shm[PATH_MAX];
    char link[PATH_MAX];
};

static bool writer_touch(const char *path)
{
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return false;
    return close(fd) == 0;
}

static bool writer_fixture_make(struct writer_fixture *fx)
{
    /* test_mkdtemp spells the cwd (getcwd, already canonical) plus test-tmp. */
    if (!test_mkdtemp(fx->dir, sizeof fx->dir, "node_db_fwriter"))
        return false;
    int n = snprintf(fx->path, sizeof fx->path, "%s/node.db", fx->dir);
    if (n <= 0 || (size_t)n >= sizeof fx->path)
        return false;
    n = snprintf(fx->wal, sizeof fx->wal, "%s-wal", fx->path);
    if (n <= 0 || (size_t)n >= sizeof fx->wal)
        return false;
    n = snprintf(fx->shm, sizeof fx->shm, "%s-shm", fx->path);
    if (n <= 0 || (size_t)n >= sizeof fx->shm)
        return false;
    n = snprintf(fx->link, sizeof fx->link, "%s/alias.db", fx->dir);
    if (n <= 0 || (size_t)n >= sizeof fx->link)
        return false;
    return writer_touch(fx->path) && writer_touch(fx->wal) &&
           writer_touch(fx->shm);
}

static void writer_fixture_remove(const struct writer_fixture *fx)
{
    unlink(fx->link);
    unlink(fx->shm);
    unlink(fx->wal);
    unlink(fx->path);
    rmdir(fx->dir);
}

/* Child: open `path` with `flags`, report readiness on `ready_fd`, then block
 * until the parent closes `hold_fd`. Never returns. */
static void writer_child_hold(const char *path, int flags, int ready_fd,
                              int hold_fd)
{
    int fd = open(path, flags);
    char ok = fd >= 0 ? 'r' : 'x';
    if (write(ready_fd, &ok, 1) != 1)
        _exit(2);
    if (fd >= 0) {
        char byte;
        ssize_t got = read(hold_fd, &byte, 1);
        (void)got;
    }
    _exit(fd >= 0 ? 0 : 3);
}

struct writer_child {
    pid_t pid;
    int hold_wr;
};

/* Fork a holder and wait until it has opened the file (or failed). */
static bool writer_child_spawn(struct writer_child *c, const char *path,
                               int flags)
{
    int ready[2], hold[2];
    if (pipe(ready) != 0)
        return false;
    if (pipe(hold) != 0) {
        close(ready[0]);
        close(ready[1]);
        return false;
    }
    fflush(stdout);
    fflush(stderr);
    c->pid = fork();
    if (c->pid == 0) {
        close(ready[0]);
        close(hold[1]);
        writer_child_hold(path, flags, ready[1], hold[0]);
    }
    close(ready[1]);
    close(hold[0]);
    c->hold_wr = hold[1];
    char status = 0;
    bool opened = c->pid > 0 && read(ready[0], &status, 1) == 1 &&
                  status == 'r';
    close(ready[0]);
    return opened;
}

static void writer_child_release(struct writer_child *c)
{
    if (c->hold_wr >= 0)
        close(c->hold_wr);
    c->hold_wr = -1;
    if (c->pid > 0) {
        int st = 0;
        while (waitpid(c->pid, &st, 0) < 0 && errno == EINTR)
            ;
    }
    c->pid = 0;
}

/* Hold `path` read-write in a child, scan for `scan_path`, and assert the
 * expected verdict. Returns the number of failed checks. */
static int writer_expect_holder(const char *label, const char *hold_path,
                                const char *scan_path, bool expect_found)
{
    int failures = 0;
    struct writer_child c = { .pid = 0, .hold_wr = -1 };
    struct os_proc_foreign_writer found;
    memset(&found, 0, sizeof found);
    bool spawned = writer_child_spawn(&c, hold_path, O_RDWR);
    FWRITER_CHECK(label, spawned);
    enum os_proc_writer_result rc =
        os_proc_foreign_writer_find(scan_path, &found);
    if (expect_found) {
        FWRITER_CHECK("  scan reports the read-write holder",
                      rc == OS_PROC_WRITER_FOUND &&
                      found.pid == (uint64_t)c.pid);
    } else {
        FWRITER_CHECK("  scan reports nothing for this holder",
                      rc == OS_PROC_WRITER_NONE && found.pid == 0);
    }
    writer_child_release(&c);
    return failures;
}

static int writer_scan_checks(struct writer_fixture *fx)
{
    int failures = 0;
    failures += writer_expect_holder(
        "read-write child holds node.db open", fx->path, fx->path, true);
    failures += writer_expect_holder(
        "read-write child holds node.db-wal open", fx->wal, fx->path, true);
    failures += writer_expect_holder(
        "read-write child holds node.db-shm open (not a target)", fx->shm,
        fx->path, false);

    if (symlink(fx->path, fx->link) == 0) {
        failures += writer_expect_holder(
            "read-write child holds node.db open, scan by symlink", fx->path,
            fx->link, true);
    } else {
        printf("node_db_foreign_writer: symlink fixture FAIL\n");
        failures++;
    }

    struct writer_child ro = { .pid = 0, .hold_wr = -1 };
    struct os_proc_foreign_writer found;
    memset(&found, 0, sizeof found);
    bool spawned = writer_child_spawn(&ro, fx->path, O_RDONLY);
    FWRITER_CHECK("read-only child holds node.db open", spawned);
    enum os_proc_writer_result rc =
        os_proc_foreign_writer_find(fx->path, &found);
    FWRITER_CHECK("scan reports nothing for a read-only holder",
                  rc == OS_PROC_WRITER_NONE && found.pid == 0);
    writer_child_release(&ro);

    struct os_proc_foreign_writer none;
    memset(&none, 0, sizeof none);
    rc = os_proc_foreign_writer_find(fx->path, &none);
    FWRITER_CHECK("scan is clean once every holder has exited",
                  rc == OS_PROC_WRITER_NONE);
    return failures;
}

static int writer_bound_checks(const struct writer_fixture *fx)
{
    int failures = 0;
    struct os_proc_foreign_writer out;
    memset(&out, 0, sizeof out);
    /* A zero bound stops at the first other pid (pid 1 always exists), so
     * the scan must say INCOMPLETE rather than claim the tree is clean. */
    enum os_proc_writer_result rc =
        os_proc_foreign_writer_find_bounded(fx->path, &out, 0);
    FWRITER_CHECK("bounded scan says INCOMPLETE when it stops early",
                  rc == OS_PROC_WRITER_INCOMPLETE);
    return failures;
}

/* The sentinel report: a control emit without the marker latches (so the
 * latch check can fail), the report never latches, and a repeat from the
 * same pid inside the window is suppressed while a later one fires. */
static int writer_report_checks(void)
{
    int failures = 0;
    alerts_shutdown();
    unsetenv("ZCL_ALERTS_DISABLE");
    unsetenv("ZCL_ALERT_WEBHOOK_URL");
    alerts_init();
    alerts_reset();
    alerts_operator_needed_clear();

    event_emitf(EV_OPERATOR_NEEDED, 0, "condition=writer_control attempts=1");
    FWRITER_CHECK("control: a page without terminal=0 latches",
                  alerts_operator_needed(NULL, 0, NULL));
    alerts_operator_needed_clear();

    const uint64_t pid = 424242;
    const int64_t t0 = 1000000;
    FWRITER_CHECK("report: first sighting of a pid is reported",
                  invariant_sentinel_node_db_writer_report(pid, "zcld",
                                                           "/x/node.db", t0));
    FWRITER_CHECK("report: the terminal=0 alert does not latch",
                  !alerts_operator_needed(NULL, 0, NULL));
    FWRITER_CHECK("report: a repeat inside the window is suppressed",
                  !invariant_sentinel_node_db_writer_report(pid, "zcld",
                                                            "/x/node.db",
                                                            t0 + 10));
    FWRITER_CHECK("report: the same pid after the window is reported again",
                  invariant_sentinel_node_db_writer_report(pid, "zcld",
                                                           "/x/node.db",
                                                           t0 + 601));
    FWRITER_CHECK("report: still no latch after repeats",
                  !alerts_operator_needed(NULL, 0, NULL));
    alerts_shutdown();
    return failures;
}

static int node_db_foreign_writer_checks(void)
{
    int failures = 0;
    struct writer_fixture fx;
    if (!writer_fixture_make(&fx)) {
        printf("node_db_foreign_writer: fixture setup FAIL\n");
        return 1;
    }
    /* The scan reads /proc, so off Linux it answers UNSUPPORTED by design
     * rather than guess. That answer is the assertion there; the holder
     * scenarios cannot be observed, and say so instead of failing. */
    struct os_proc_foreign_writer probe;
    memset(&probe, 0, sizeof probe);
    enum os_proc_writer_result probed =
        os_proc_foreign_writer_find(fx.path, &probe);
#if defined(__linux__)
    FWRITER_CHECK("the scan is supported on Linux",
                  probed != OS_PROC_WRITER_UNSUPPORTED);
#else
    FWRITER_CHECK("off Linux the scan says UNSUPPORTED and reports no pid",
                  probed == OS_PROC_WRITER_UNSUPPORTED && probe.pid == 0);
#endif
    if (probed == OS_PROC_WRITER_UNSUPPORTED) {
        printf("UNOBSERVED (node_db_foreign_writer: the holder scan needs "
               "/proc, a Linux host)\n");
    } else {
        failures += writer_scan_checks(&fx);
        failures += writer_bound_checks(&fx);
    }
    failures += writer_report_checks();
    writer_fixture_remove(&fx);
    return failures;
}

int test_node_db_foreign_writer(void);
int test_node_db_foreign_writer(void)
{
    printf("\n=== node.db foreign writer tests ===\n");
    int failures = node_db_foreign_writer_checks();
    if (failures == 0) {
        printf("=== node.db foreign writer tests: ALL PASS ===\n\n");
    } else {
        printf("=== node.db foreign writer tests: %d FAILURE(S) ===\n\n",
               failures);
    }
    return failures;
}
