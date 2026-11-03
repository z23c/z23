/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fixture tests for os_proc_foreign_writer_find (platform/os_proc.h): a
 * same-uid child that holds a temp database file open read-write must be
 * reported as the writer; a child that holds it read-only must not be, and
 * the scan must report nothing once no writer is left.
 */

#include "test/test_core.h"
#include "platform/os_proc.h"

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

/* A fixture file under a canonical directory, so the kernel's fd link text
 * equals the path the scan is given (a symlinked TMPDIR would not). */
struct writer_fixture {
    char dir[PATH_MAX];
    char path[PATH_MAX];
};

static bool writer_fixture_make(struct writer_fixture *fx)
{
    /* test_mkdtemp spells the cwd (getcwd, already canonical) plus test-tmp. */
    if (!test_mkdtemp(fx->dir, sizeof fx->dir, "node_db_fwriter"))
        return false;
    int n = snprintf(fx->path, sizeof fx->path, "%s/node.db", fx->dir);
    if (n <= 0 || (size_t)n >= sizeof fx->path)
        return false;
    int fd = open(fx->path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return false;
    return close(fd) == 0;
}

static void writer_fixture_remove(const struct writer_fixture *fx)
{
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
    char byte;
    if (fd >= 0) {
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

static int node_db_foreign_writer_checks(void)
{
    int failures = 0;
    struct writer_fixture fx;
    if (!writer_fixture_make(&fx)) {
        printf("node_db_foreign_writer: fixture setup FAIL\n");
        return 1;
    }

    struct writer_child rw = { .pid = 0, .hold_wr = -1 };
    struct os_proc_foreign_writer found;
    memset(&found, 0, sizeof found);
    bool spawned = writer_child_spawn(&rw, fx.path, O_RDWR);
    FWRITER_CHECK("read-write child holds the fixture open", spawned);
    enum os_proc_writer_result rc = os_proc_foreign_writer_find(fx.path, &found);
    FWRITER_CHECK("scan reports the O_RDWR child as the writer",
                  rc == OS_PROC_WRITER_FOUND && found.pid == (uint64_t)rw.pid);
    writer_child_release(&rw);

    struct writer_child ro = { .pid = 0, .hold_wr = -1 };
    spawned = writer_child_spawn(&ro, fx.path, O_RDONLY);
    FWRITER_CHECK("read-only child holds the fixture open", spawned);
    memset(&found, 0, sizeof found);
    rc = os_proc_foreign_writer_find(fx.path, &found);
    FWRITER_CHECK("scan reports nothing for an O_RDONLY child",
                  rc == OS_PROC_WRITER_NONE && found.pid == 0);
    writer_child_release(&ro);

    memset(&found, 0, sizeof found);
    rc = os_proc_foreign_writer_find(fx.path, &found);
    FWRITER_CHECK("scan is clean once every holder has exited",
                  rc == OS_PROC_WRITER_NONE);

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
