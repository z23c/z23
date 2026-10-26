/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: proves platform_directory_watcher_* observes real change on a
 * directory it opened: the stop predicate is honoured, a file created inside
 * the root reports CHANGED, and a rename followed by an unlink reports
 * CHANGED again.
 *
 * Rehomed from platform/modules/platform/tests/. The native resident
 * development watcher also drives this module on macOS through the filtered
 * kqueue recursion path. The watched root comes from test_make_tmpdir()
 * under test-tmp/ so parallel groups cannot collide and the tree is cleaned
 * up on failure. The final rmdir/RemoveDirectory assertion proves the
 * watcher released the directory. */
#include "test/test_core.h"

#include "platform/directory_watcher.h"

#include <stdio.h>
#include <string.h>
#if defined(_WIN32)
#include <windows.h>
#else
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <errno.h>
#include <sys/wait.h>
#endif
#endif

static bool stop_now(void *opaque) { (void)opaque; return true; }

static int directory_watcher_probe(const char *root)
{
    char first[1200], second[1200];
    (void)snprintf(first,sizeof(first),"%s/%s",root,"edit.tmp");
    (void)snprintf(second,sizeof(second),"%s/%s",root,"renamed.tmp");
    struct platform_directory_watcher watcher; platform_directory_watcher_init(&watcher);
    if(!platform_directory_watcher_open(&watcher,root) ||
       platform_directory_watcher_wait(&watcher,10,stop_now,NULL)!=PLATFORM_DIRECTORY_WATCH_STOPPED) return 1;
#if defined(_WIN32)
    HANDLE f=CreateFileA(first,GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    if(f==INVALID_HANDLE_VALUE) return 1; DWORD wrote=0; (void)WriteFile(f,"x",1,&wrote,NULL); CloseHandle(f);
#else
    int f=open(first,O_CREAT|O_EXCL|O_WRONLY,0600); if(f<0) return 1;  TEST_DISCARD(write(f,"x",1)); close(f);
#endif
    if(platform_directory_watcher_wait(&watcher,2000,NULL,NULL)!=PLATFORM_DIRECTORY_WATCH_CHANGED) return 1;
#if defined(_WIN32)
    if(!MoveFileA(first,second)||!DeleteFileA(second)) return 1;
#else
    if(rename(first,second)||unlink(second)) return 1;
#endif
    if(platform_directory_watcher_wait(&watcher,2000,NULL,NULL)!=PLATFORM_DIRECTORY_WATCH_CHANGED) return 1;
    platform_directory_watcher_close(&watcher);
#if defined(_WIN32)
    if(!RemoveDirectoryA(root)) return 1;
#else
    if(rmdir(root)) return 1;
#endif
    return 0;
}

#if defined(__APPLE__)
static bool skip_ignored(const char *name, void *opaque)
{
    (void)opaque;
    return strcmp(name, "ignored") != 0;
}

static bool include_source_file(const char *path, void *opaque)
{
    (void)opaque;
    const char *name = strrchr(path, '/');
    return !name || strcmp(name + 1, "excluded.tmp") != 0;
}
#endif

#if !defined(_WIN32)
static bool watcher_write(const char *path)
{
    int fd = open(path, O_CREAT | O_WRONLY | O_APPEND, 0600);
    if (fd < 0) { perror("directory_watcher: open document"); return false; }
    bool wrote = write(fd, "x", 1) == 1;
    bool closed = close(fd) == 0;
    if (!wrote || !closed) perror("directory_watcher: write document");
    return wrote && closed;
}

static void watcher_observation(const char *label, bool ok)
{
    printf("directory_watcher: %s... %s\n", label, ok ? "OK" : "FAIL");
}

static int directory_watcher_access_replace(const char *root)
{
    char child[1200], retired[1200], document[1200];
    (void)snprintf(child, sizeof(child), "%s/current", root);
    (void)snprintf(retired, sizeof(retired), "%s/retired", root);
    (void)snprintf(document, sizeof(document), "%s/current/task.txt", root);
    struct platform_directory_watcher watcher;
    platform_directory_watcher_init(&watcher);
    bool ok = mkdir(child, 0700) == 0 && watcher_write(document) &&
        platform_directory_watcher_open(&watcher, root);
    ok = ok && chmod(document, 0400) == 0 &&
        platform_directory_watcher_wait(&watcher, 2000, NULL, NULL) ==
            PLATFORM_DIRECTORY_WATCH_CHANGED;
    watcher_observation("document access change observed", ok);
    ok = ok && rename(child, retired) == 0 && mkdir(child, 0700) == 0 &&
        watcher_write(document) &&
        platform_directory_watcher_wait(&watcher, 2000, NULL, NULL) ==
            PLATFORM_DIRECTORY_WATCH_CHANGED;
    watcher_observation("replaced nested document directory observed", ok);
    ok = ok && platform_directory_watcher_wait(&watcher, 50, NULL, NULL) ==
        PLATFORM_DIRECTORY_WATCH_TIMEOUT && watcher_write(document) &&
        platform_directory_watcher_wait(&watcher, 2000, NULL, NULL) ==
            PLATFORM_DIRECTORY_WATCH_CHANGED;
    watcher_observation("later edit in replacement observed", ok);
    platform_directory_watcher_close(&watcher);
    return ok ? 0 : 1;
}
#endif

#if defined(__APPLE__)
/* The first watcher descriptor is its kqueue. Reserve its lowest-free number
 * and verify it vanished in the child before reusing it, without private ABI. */
static int directory_watcher_child_reused_fd(
    struct platform_directory_watcher *watcher, int expected_kq)
{
    errno = 0;
    if (fcntl(expected_kq, F_GETFD) != -1 || errno != EBADF) return 2;
    int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 3;
    if (fd != expected_kq) {
        if (dup2(fd, expected_kq) != expected_kq) return 4;
        close(fd);
    }
    if (platform_directory_watcher_wait(watcher, 0, NULL, NULL) !=
        PLATFORM_DIRECTORY_WATCH_ERROR) return 5;
    platform_directory_watcher_close(watcher);
    bool preserved = fcntl(expected_kq, F_GETFD) >= 0;
    close(expected_kq);
    return preserved ? 0 : 6;
}

static int directory_watcher_fork_reused_fd(const char *root)
{
    struct platform_directory_watcher watcher;
    platform_directory_watcher_init(&watcher);
    int expected_kq = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (expected_kq < 0) return 1;
    if (close(expected_kq) != 0) return 1;
    if (!platform_directory_watcher_open(&watcher, root)) return 1;
    pid_t child = fork();
    if (child == 0)
        _exit(directory_watcher_child_reused_fd(&watcher, expected_kq));
    int status = 0;
    pid_t waited = -1;
    if (child > 0) {
        do { waited = waitpid(child, &status, 0); }
        while (waited < 0 && errno == EINTR);
    }
    bool ok = child > 0 && waited == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0 &&
        platform_directory_watcher_wait(&watcher, 0, NULL, NULL) ==
            PLATFORM_DIRECTORY_WATCH_TIMEOUT;
    char document[1200];
    (void)snprintf(document, sizeof(document), "%s/after-fork", root);
    ok = ok && watcher_write(document) &&
        platform_directory_watcher_wait(&watcher, 2000, NULL, NULL) ==
            PLATFORM_DIRECTORY_WATCH_CHANGED;
    platform_directory_watcher_close(&watcher);
    watcher_observation("fork cleanup preserves reused fd and parent watch", ok);
    return ok ? 0 : 1;
}

/* Writes one byte through a fresh descriptor opened with the probe's flags,
 * preserving the open/write/close short-circuit order of the original chains.
 * Returns 0 when every step succeeded, 1 on the first failure. */
static int directory_watcher_filtered_write_file(
    const char *path, int flags, const char *data)
{
    int fd = open(path, flags, 0600);
    if (fd < 0)
        return 1;
    if (write(fd, data, 1) != 1)
        return 1;
    if (close(fd) != 0)
        return 1;
    return 0;
}

/* Writes one byte and then requires the watcher to report expected within
 * timeout_ms; returns 0 only when both steps behaved as the probe needs. */
static int directory_watcher_filtered_write_and_wait(
    struct platform_directory_watcher *watcher, const char *path, int flags,
    const char *data, int timeout_ms, int expected)
{
    if (directory_watcher_filtered_write_file(path, flags, data) != 0)
        return 1;
    if (platform_directory_watcher_wait(watcher, timeout_ms, NULL, NULL) !=
        expected)
        return 1;
    return 0;
}

/* Removes the probe's files and directories in the original order; returns 0
 * only when every unlink and rmdir succeeded. */
static int directory_watcher_filtered_cleanup(
    const char *hidden, const char *excluded, const char *visible,
    const char *ignored, const char *root)
{
    return unlink(hidden) == 0 && unlink(excluded) == 0 &&
           unlink(visible) == 0 &&
           rmdir(ignored) == 0 && rmdir(root) == 0 ? 0 : 1;
}

static int directory_watcher_filtered_probe(const char *root)
{
    char ignored[1200], hidden[1200], excluded[1200], visible[1200], swap[1200];
    (void)snprintf(ignored, sizeof(ignored), "%s/ignored", root);
    (void)snprintf(hidden, sizeof(hidden), "%s/hidden.tmp", ignored);
    (void)snprintf(excluded, sizeof(excluded), "%s/excluded.tmp", root);
    (void)snprintf(visible, sizeof(visible), "%s/visible.tmp", root);
    (void)snprintf(swap, sizeof(swap), "%s/swap.tmp", root);
    if (mkdir(ignored, 0700) != 0)
        return 1;
    if (directory_watcher_filtered_write_file(
            excluded, O_CREAT | O_EXCL | O_WRONLY, "x") != 0)
        return 1;

    struct platform_directory_watcher watcher;
    platform_directory_watcher_init(&watcher);
    if (!platform_directory_watcher_open_filtered(
            &watcher, root, skip_ignored, include_source_file, NULL))
        return 1;

    if (directory_watcher_filtered_write_and_wait(
            &watcher, hidden, O_CREAT | O_EXCL | O_WRONLY, "x", 100,
            PLATFORM_DIRECTORY_WATCH_TIMEOUT) != 0)
        return 1;

    if (directory_watcher_filtered_write_and_wait(
            &watcher, excluded, O_WRONLY | O_APPEND, "y", 100,
            PLATFORM_DIRECTORY_WATCH_TIMEOUT) != 0)
        return 1;

    if (directory_watcher_filtered_write_and_wait(
            &watcher, visible, O_CREAT | O_EXCL | O_WRONLY, "x", 2000,
            PLATFORM_DIRECTORY_WATCH_CHANGED) != 0)
        return 1;
    if (directory_watcher_filtered_write_file(
            swap, O_CREAT | O_EXCL | O_WRONLY, "z") != 0 ||
        rename(swap, visible) != 0)
        return 1;
    if (platform_directory_watcher_wait(&watcher, 2000, NULL, NULL) !=
        PLATFORM_DIRECTORY_WATCH_CHANGED)
        return 1;
    if (directory_watcher_filtered_write_and_wait(
            &watcher, visible, O_WRONLY | O_APPEND, "y", 2000,
            PLATFORM_DIRECTORY_WATCH_CHANGED) != 0)
        return 1;
    platform_directory_watcher_close(&watcher);
    return directory_watcher_filtered_cleanup(
        hidden, excluded, visible, ignored, root);
}
#endif

int test_directory_watcher(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "directory_watcher", "recursive");
    printf("directory_watcher: stop predicate honoured, create and "
           "rename+unlink each report CHANGED... ");
    if (directory_watcher_probe(dir) == 0) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        failures++;
    }
    (void)test_rm_rf_recursive(dir);
#if !defined(_WIN32)
    test_make_tmpdir(dir, sizeof(dir), "directory_watcher", "access-replace");
    failures += directory_watcher_access_replace(dir);
    (void)test_rm_rf_recursive(dir);
#endif
#if defined(__APPLE__)
    test_make_tmpdir(dir, sizeof(dir), "directory_watcher", "fork");
    failures += directory_watcher_fork_reused_fd(dir);
    (void)test_rm_rf_recursive(dir);
    test_make_tmpdir(dir, sizeof(dir), "directory_watcher", "filtered");
    printf("directory_watcher: filtered kqueue recursion ignores generated "
           "subtrees/files but observes source-root creates and writes... ");
    if (directory_watcher_filtered_probe(dir) == 0) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        failures++;
    }
    (void)test_rm_rf_recursive(dir);
#endif
    return failures;
}
