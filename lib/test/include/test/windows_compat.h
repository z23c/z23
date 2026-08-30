/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Windows compatibility shims for the TEST build only.
 *
 * The suite's test corpus was written against POSIX libc spellings that the
 * UCRT/MinGW toolchain does not provide: two-argument mkdir, setenv/unsetenv,
 * lstat, pread/pwrite, realpath, the O_CLOEXEC family of open(2) flags, and
 * sysconf(_SC_NPROCESSORS_ONLN). The production tree routes every one of
 * those through lib/platform compat modules; the tests predate that
 * discipline and call the C library directly.
 *
 * This header is force-included (-include test/windows_compat.h) into the
 * test-fast profile's translation units on Windows hosts ONLY (Makefile
 * ZCL_TEST_WINDOWS_COMPAT_FLAGS). It is not a production header, it changes
 * no gate semantics, and where a POSIX capability genuinely does not exist
 * (symlink, readlink) the shim FAILS the call (ENOSYS) rather than faking
 * success — a test that depends on the real capability then fails loudly,
 * which is the honest outcome.
 *
 * Deliberately does NOT include <windows.h>: force-inclusion reaches every
 * test TU, and windows.h's object-like macros (far, near, small, min/max in
 * some configurations) would collide with test-local identifiers. Everything
 * below is pure CRT. */

#ifndef ZCL_TEST_WINDOWS_COMPAT_H
#define ZCL_TEST_WINDOWS_COMPAT_H

#if defined(_WIN32)

#include <direct.h>
#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <limits.h>
#include <process.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

/* POSIX mkdir(path, mode): Windows has no mode bits (the private-directory
 * contract on Windows is carried by ACLs in platform/private_directory.c).
 * Call sites pass a constant mode with no side effects, so it is dropped. */
#define mkdir(path, mode) _mkdir(path)

/* mkdtemp: no UCRT analogue. Test templates end in "XXXXXX"; fill the six
 * Xs from a per-process counter mixed with the pid and create the directory
 * atomically via _mkdir (which fails on an existing name), retrying a few
 * times. Returns the template on success, NULL with errno set otherwise. */
static inline char *zcl_win_mkdtemp(char *tmpl)
{
    static unsigned int zcl_win_mkdtemp_seq;
    if (!tmpl) {
        errno = EINVAL;
        return NULL;
    }
    size_t len = strlen(tmpl);
    if (len < 6 || strcmp(tmpl + len - 6, "XXXXXX") != 0) {
        errno = EINVAL;
        return NULL;
    }
    static const char digits[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    for (int attempt = 0; attempt < 64; attempt++) {
        unsigned int v = (unsigned int)_getpid() * 747796405u +
                         zcl_win_mkdtemp_seq++ * 2891336453u;
        for (int i = 0; i < 6; i++) {
            tmpl[len - 6 + i] = digits[v % 36u];
            v /= 36u;
        }
        if (_mkdir(tmpl) == 0)
            return tmpl;
        if (errno != EEXIST)
            return NULL;
    }
    errno = EEXIST;
    return NULL;
}
#define mkdtemp(tmpl) zcl_win_mkdtemp((tmpl))

/* pipe(2): the UCRT has _pipe(fds, psize, textmode); binary mode matches the
 * byte-stream contract the test fixtures assume. */
static inline int zcl_win_pipe(int fds[2])
{
    return _pipe(fds, 4096, _O_BINARY);
}
#define pipe(fds) zcl_win_pipe((fds))

/* setenv/unsetenv over the UCRT _putenv_s, which copies its inputs. */
static inline int zcl_win_setenv(const char *name, const char *value,
                                 int overwrite)
{
    if (!name || !name[0] || strchr(name, '=') != NULL || !value) {
        errno = EINVAL;
        return -1;
    }
    if (!overwrite && getenv(name) != NULL)
        return 0;
    return _putenv_s(name, value) == 0 ? 0 : -1;
}
static inline int zcl_win_unsetenv(const char *name)
{
    if (!name || !name[0] || strchr(name, '=') != NULL) {
        errno = EINVAL;
        return -1;
    }
    return _putenv_s(name, "") == 0 ? 0 : -1;
}
#define setenv(name, value, overwrite) zcl_win_setenv((name), (value), (overwrite))
#define unsetenv(name) zcl_win_unsetenv((name))

/* No symlink fixtures exist on the Windows lane; lstat is stat there. */
#define lstat stat

#ifndef S_ISLNK
#define S_ISLNK(mode) 0
#endif

/* open(2) flags the tests pass through. None has a Windows analogue; 0 keeps
 * the call sites compiling with no semantic change (Windows CRT open() has no
 * exec to close across, no symlinks to follow, and refuses directories on its
 * own). */
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif
#ifndef O_NOCTTY
#define O_NOCTTY 0
#endif
#ifndef O_SYNC
#define O_SYNC 0
#endif
#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif

/* SIGBUS has no Windows delivery mechanism; handler-registration tests map
 * it onto the access-violation signal. */
#ifndef SIGBUS
#define SIGBUS SIGSEGV
#endif
#ifndef SIGKILL
#define SIGKILL 9
#endif
#ifndef SIGTERM
#define SIGTERM 15
#endif

/* sysconf: only the processor-count query is used by the test tree. */
#ifndef _SC_NPROCESSORS_ONLN
#define _SC_NPROCESSORS_ONLN 84
static inline long zcl_win_sysconf(int name)
{
    if (name == _SC_NPROCESSORS_ONLN) {
        const char *env = getenv("NUMBER_OF_PROCESSORS");
        if (env && env[0]) {
            long v = strtol(env, NULL, 10);
            if (v > 0) return v;
        }
        return 1;
    }
    errno = EINVAL;
    return -1;
}
#define sysconf(name) zcl_win_sysconf(name)
#endif

/* rand_r: not in the UCRT. The tests use it only as a per-cycle delay
 * randomiser, so the classic LCG is faithful to the contract. */
static inline int zcl_win_rand_r(unsigned int *seed)
{
    if (!seed) {
        errno = EINVAL;
        return -1;
    }
    *seed = *seed * 1103515245u + 12345u;
    return (int)((*seed >> 16) & 0x7FFF);
}
#define rand_r(seed) zcl_win_rand_r((seed))

/* fsync: _commit is the UCRT flush-to-disk analogue on an open fd. */
#define fsync(fd) _commit(fd)

/* kill(pid, 0) process-liveness probe: OpenProcess succeeds iff the PID
 * names a live process (or one the caller may query). Declared against the
 * raw Win32 entry points so this header stays free of <windows.h> object
 * macros; the signatures match windows.h, so a later include is compatible.
 * A nonzero signal has no Windows delivery here and fails loudly (ENOSYS). */
__declspec(dllimport) void *__stdcall OpenProcess(unsigned long access,
                                                  int inherit,
                                                  unsigned long pid);
__declspec(dllimport) int __stdcall CloseHandle(void *handle);
static inline int zcl_win_kill(long pid, int sig)
{
    if (sig == 0) {
        void *h = OpenProcess(0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */,
                              0, (unsigned long)pid);
        if (!h) {
            errno = ESRCH;
            return -1;
        }
        CloseHandle(h);
        return 0;
    }
    errno = ENOSYS;
    return -1;
}
#define kill(pid, sig) zcl_win_kill((long)(pid), (sig))

/* Suppress the UCRT abort() diagnostic and the Windows Error Reporting
 * fault report. Spawned test children that are EXPECTED to abort (the
 * signal-death lanes POSIX runs through fork+WTERMSIG) must not pop a WER
 * dialog or stall in WerFault; with both flags cleared abort() proceeds
 * directly to exit code 3. */
static inline void zcl_win_suppress_abort_dialog(void)
{
    (void)_set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
}

/* pread/pwrite: the test fixtures are single-threaded against the file at
 * the call site, so a seek+read/write pair is faithful enough. */
static inline ssize_t zcl_win_pread(int fd, void *buf, size_t count,
                                    off_t offset)
{
    off_t saved = lseek(fd, 0, SEEK_CUR);
    if (saved == (off_t)-1) return -1;
    if (lseek(fd, offset, SEEK_SET) == (off_t)-1) return -1;
    int n = read(fd, buf, (unsigned int)count);
    (void)lseek(fd, saved, SEEK_SET);
    return (ssize_t)n;
}
static inline ssize_t zcl_win_pwrite(int fd, const void *buf, size_t count,
                                     off_t offset)
{
    off_t saved = lseek(fd, 0, SEEK_CUR);
    if (saved == (off_t)-1) return -1;
    if (lseek(fd, offset, SEEK_SET) == (off_t)-1) return -1;
    int n = write(fd, buf, (unsigned int)count);
    (void)lseek(fd, saved, SEEK_SET);
    return (ssize_t)n;
}
#define pread(fd, buf, count, offset) zcl_win_pread((fd), (buf), (count), (offset))
#define pwrite(fd, buf, count, offset) zcl_win_pwrite((fd), (buf), (count), (offset))

/* realpath: _fullpath covers the absolute-path resolution the tests use;
 * the NULL-out (allocating) form mallocs, matching POSIX.1-2008. */
static inline char *zcl_win_realpath(const char *path, char *resolved)
{
    if (!path) {
        errno = EINVAL;
        return NULL;
    }
    if (resolved)
        return _fullpath(resolved, path, PATH_MAX) ? resolved : NULL;
    char *buf = (char *)malloc(PATH_MAX);
    if (!buf) {
        errno = ENOMEM;
        return NULL;
    }
    if (!_fullpath(buf, path, PATH_MAX)) {
        free(buf);
        return NULL;
    }
    return buf;
}
#define realpath(path, resolved) zcl_win_realpath((path), (resolved))

/* Capabilities that genuinely do not exist on the Windows lane: fail the
 * call loudly (ENOSYS) so a dependent test reports a real failure instead of
 * a faked success. */
static inline int zcl_win_symlink(const char *target, const char *linkpath)
{
    (void)target;
    (void)linkpath;
    errno = ENOSYS;
    return -1;
}
#define symlink(target, linkpath) zcl_win_symlink((target), (linkpath))

static inline ssize_t zcl_win_readlink(const char *path, char *buf,
                                       size_t bufsiz)
{
    (void)path;
    (void)buf;
    (void)bufsiz;
    errno = ENOSYS;
    return -1;
}
#define readlink(path, buf, bufsiz) zcl_win_readlink((path), (buf), (bufsiz))

#endif /* _WIN32 */

#endif /* ZCL_TEST_WINDOWS_COMPAT_H */
