/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fixture plugin for test_plugin_run.c (built by the Makefile into
 * build/fixtures/, never linked into a product binary). It speaks the plugin
 * protocol of docs/dev/PLUGINS.md: argv is `<image> --resident <launch nonce>`,
 * Z23_PLUGIN_FDS names the granted descriptors, the control socket carries
 * 81-byte supervisor frames (ping or stop) and the plugin answers each ping
 * with one z23-res-run-v1 frame whose payload is the ping token.
 *
 * The behaviour is a 16-byte field inside the image so the test can derive
 * images with distinct SHA3-512 generations by patching bytes:
 *   normal         report, log one line, answer pings, exit on stop
 *   crash          exit 3 at once
 *   hang           report, then never answer a ping
 *   try-socket     call socket(2); the sandbox kills the process (SIGSYS)
 *   write-outside  try to write and read outside data.dir, record the errno
 *                  values in the report, then behave as normal
 *   truncate       truncate a file outside data.dir; the errno goes to the
 *                  report, then behave as normal
 *   ptrace mount unshare bpf uring keyctl kill chmod pidfd
 *                  call one forbidden system call; the sandbox kills the
 *                  process (SIGSYS), and a survivor exits 7
 *   tkill tgkill vmread setxattr utimensat fchmodat2 fork vfork abort
 *                  more forbidden calls (abort() raises through tgkill)
 *   sigstate       report the signal mask, the SIGPIPE and SIGINT dispositions
 *                  and the parent-death signal, then behave as normal
 *   logctl         log a line holding ESC, BEL and CR, then behave as normal
 *   readonly       exit with the errno of a write inside data.dir
 *   nofs           exit 21 when Z23_PLUGIN_FDS is control=3,log=4 and
 *                  descriptor 5 is closed, otherwise 22
 *   logonly        write A to descriptor 4 and B to descriptor 5
 * The report (data.dir/report.txt) lists the open descriptors, the announced
 * Z23_PLUGIN_FDS and the outcome of the confinement probes. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "platform/resident_launch.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>

/* Patched by the test; the marker is found by scanning the image. */
__attribute__((used)) static volatile const char prc_variant[] =
    "PRC-VARIANT:normal          ;";
#define PRC_MARKER_LEN 12

#define PRC_FRAME 81

static bool prc_io(int fd, void *buffer, size_t size, bool sending)
{
    unsigned char *bytes = buffer;
    for (size_t done = 0; done < size;) {
        ssize_t n = sending ? write(fd, bytes + done, size - done)
                            : read(fd, bytes + done, size - done);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        done += (size_t)n;
    }
    return true;
}

static bool prc_mode_is(const char *mode)
{
    return strncmp((const char *)prc_variant + PRC_MARKER_LEN, mode, strlen(mode)) == 0;
}

/* The descriptor number announced for name in Z23_PLUGIN_FDS, or -1. */
static int prc_fd_of(const char *name)
{
    const char *env = getenv("Z23_PLUGIN_FDS");
    size_t len = strlen(name);
    for (const char *p = env; p && *p;) {
        if (strncmp(p, name, len) == 0 && p[len] == '=')
            return atoi(p + len + 1);
        p = strchr(p, ',');
        if (p)
            p++;
    }
    return -1;
}

static void prc_open_list(char *out, size_t cap)
{
    size_t n = 0;
    out[0] = '\0';
    for (int fd = 0; fd < 64; fd++)
        if (fcntl(fd, F_GETFD) != -1 && n + 8 < cap)
            n += (size_t)snprintf(out + n, cap - n, "%s%d", n ? "," : "", fd);
}

static bool prc_stdio_null(void)
{
    struct stat st;
    for (int fd = 0; fd <= 2; fd++)
        if (fstat(fd, &st) != 0 || !S_ISCHR(st.st_mode) ||
            major(st.st_rdev) != 1 || minor(st.st_rdev) != 3)
            return false;
    return true;
}

/* The plugin directory's victim.txt, found from the data directory's
 * descriptor; readlink on /proc is not a Landlock-governed access. */
static bool prc_victim(int data_fd, char *out, size_t cap)
{
    char link[64], dir[512];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", data_fd);
    ssize_t n = readlink(link, dir, sizeof(dir) - 1);
    if (n <= 0)
        return false;
    dir[n] = '\0';
    char *slash = strrchr(dir, '/');
    if (!slash)
        return false;
    *slash = '\0';
    return snprintf(out, cap, "%s/victim.txt", dir) < (int)cap;
}

/* The kernel entry point, called through a pointer. The fixture exists to issue
 * each forbidden system call once, outside any product binary; it is built
 * by the Makefile and has no object in the capability scan. */
static long (*const prc_kernel)(long, ...) = syscall;

#ifndef SYS_fchmodat2
#define SYS_fchmodat2 452
#endif

/* The calls that take the plugin directory's victim.txt. */
static bool prc_forbidden_path(int data_fd)
{
    char v[600];
    if (!prc_victim(data_fd, v, sizeof(v)))
        return false;
    if (prc_mode_is("setxattr"))
        prc_kernel(SYS_setxattr, v, "user.z23", "x", 1, 0);
    else if (prc_mode_is("utimensat"))
        prc_kernel(SYS_utimensat, AT_FDCWD, v, NULL, 0);
    else if (prc_mode_is("fchmodat2"))
        prc_kernel(SYS_fchmodat2, AT_FDCWD, v, 0600, 0);
    else
        return false;
    return true;
}

/* The calls that signal or inspect other processes. */
static bool prc_forbidden_process(void)
{
    if (prc_mode_is("kill"))
        kill(getppid(), 0);
    else if (prc_mode_is("pidfd"))
        prc_kernel(SYS_pidfd_open, getpid(), 0);
    else if (prc_mode_is("tkill"))
        prc_kernel(SYS_tkill, getpid(), 0);
    else if (prc_mode_is("tgkill"))
        prc_kernel(SYS_tgkill, getpid(), getpid(), 0);
    else if (prc_mode_is("vmread"))
        prc_kernel(SYS_process_vm_readv, getppid(), NULL, 0, NULL, 0, 0);
    else if (prc_mode_is("abort"))
        abort();
#ifdef SYS_fork
    else if (prc_mode_is("fork"))
        prc_kernel(SYS_fork);
#endif
#ifdef SYS_vfork
    else if (prc_mode_is("vfork"))
        prc_kernel(SYS_vfork);
#endif
    else
        return false;
    return true;
}

/* One forbidden call per mode. Returns only when the sandbox let it pass. */
static void prc_forbidden(int data_fd)
{
    char victim[600];
    if (prc_forbidden_process())
        return;
    if (prc_mode_is("ptrace"))
        prc_kernel(SYS_ptrace, 0, 0, 0, 0);
    else if (prc_mode_is("mount"))
        prc_kernel(SYS_mount, "none", "/", "tmpfs", 0, NULL);
    else if (prc_mode_is("unshare"))
        unshare(CLONE_NEWNS);
    else if (prc_mode_is("bpf"))
        prc_kernel(SYS_bpf, 0, NULL, 0);
    else if (prc_mode_is("uring"))
        prc_kernel(SYS_io_uring_setup, 1, NULL);
    else if (prc_mode_is("keyctl"))
        prc_kernel(SYS_keyctl, 0, 0, 0, 0, 0);
    else if (prc_forbidden_path(data_fd))
        return;
    else if (prc_mode_is("chmod") && prc_victim(data_fd, victim, sizeof(victim)))
        chmod(victim, 0600);
}

static bool prc_forbidden_mode(void)
{
    static const char *const modes[] = {
        "ptrace", "mount", "unshare", "bpf", "uring", "keyctl", "kill", "pidfd", "chmod",
        "tkill", "tgkill", "vmread", "setxattr", "utimensat", "fchmodat2", "fork", "vfork",
        "abort"};
    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++)
        if (prc_mode_is(modes[i]))
            return true;
    return false;
}

static int prc_probe_truncate(int data_fd)
{
    char victim[600];
    if (!prc_victim(data_fd, victim, sizeof(victim)))
        return -1;
    return truncate(victim, 0) == 0 ? 0 : errno;
}

static int prc_probe_write(int data_fd)
{
    int fd = openat(data_fd, "../outside.txt", O_WRONLY | O_CREAT, 0600);
    int err = fd < 0 ? errno : 0;
    if (fd >= 0)
        close(fd);
    return err;
}

static int prc_probe_absolute(const char *path, int flags)
{
    int fd = open(path, flags, 0600);
    int err = fd < 0 ? errno : 0;
    if (fd >= 0)
        close(fd);
    return err;
}

static int prc_disposition(int sig)
{
    struct sigaction old;
    if (sigaction(sig, NULL, &old) != 0)
        return -1;
    return old.sa_handler == SIG_DFL ? 0 : old.sa_handler == SIG_IGN ? 1 : 2;
}

/* Blocked signal count, SIGPIPE and SIGINT disposition (0 default, 1 ignored,
 * 2 handler) and the parent-death signal. */
static int prc_sigstate(char *out, size_t cap)
{
    sigset_t mask;
    int blocked = 0, pdeath = -1;
    sigprocmask(SIG_BLOCK, NULL, &mask);
    for (int sig = 1; sig < 32; sig++)
        blocked += sigismember(&mask, sig) == 1;
    prctl(PR_GET_PDEATHSIG, &pdeath);
    return snprintf(out, cap, "sigblocked=%d\nsigpipe=%d\nsigint=%d\npdeathsig=%d\n",
                    blocked, prc_disposition(SIGPIPE), prc_disposition(SIGINT), pdeath);
}

static void prc_report(int data_fd)
{
    char fds[256], text[640];
    prc_open_list(fds, sizeof(fds));
    bool probe = prc_mode_is("write-outside");
    const char *env = getenv("Z23_PLUGIN_FDS");
    int len = snprintf(text, sizeof(text), "fds=%s\nenv=%s\nstdio_null=%d\nnnp=%d\n", fds,
                       env ? env : "", prc_stdio_null() ? 1 : 0,
                       prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0));
    if (prc_mode_is("sigstate"))
        len += prc_sigstate(text + len, sizeof(text) - (size_t)len);
    if (prc_mode_is("truncate"))
        len += snprintf(text + len, sizeof(text) - (size_t)len, "truncate_outside=%d\n",
                        prc_probe_truncate(data_fd));
    if (probe)
        len += snprintf(text + len, sizeof(text) - (size_t)len,
                        "write_outside=%d\nwrite_shm=%d\nread_passwd=%d\n",
                        prc_probe_write(data_fd),
                        prc_probe_absolute("/dev/shm/z23-plugin-run-outside", O_WRONLY | O_CREAT),
                        prc_probe_absolute("/etc/passwd", O_RDONLY));
    int out = openat(data_fd, "report.txt", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (out >= 0) {
        (void)prc_io(out, text, (size_t)len, true);
        close(out);
    }
}

static bool prc_reply(const char *nonce, const char *token)
{
    struct resident_result_header header;
    memset(&header, 0, sizeof(header));
    snprintf(header.magic, sizeof(header.magic), "%s", "z23-res-run-v1");
    snprintf(header.nonce, sizeof(header.nonce), "%s", nonce);
    header.payload_len = 64;
    return prc_io(RESIDENT_LAUNCH_CHILD_FD, &header, sizeof(header), true) &&
           prc_io(RESIDENT_LAUNCH_CHILD_FD, (void *)token, 64, true);
}

static int prc_serve(const char *nonce)
{
    char frame[PRC_FRAME];
    while (prc_io(RESIDENT_LAUNCH_CHILD_FD, frame, sizeof(frame), false)) {
        if (strcmp(frame, "z23-res-stop-v1") == 0)
            return 0;
        if (strcmp(frame, "z23-plg-ping-v1") == 0 && !prc_reply(nonce, frame + 16))
            return 5;
    }
    return 0;
}

/* Modes that decide the exit status before any report; -1 means serve. */
static int prc_special(int data_fd)
{
    if (prc_forbidden_mode()) {
        prc_forbidden(data_fd);
        return 7;
    }
    if (prc_mode_is("logonly"))
        return prc_io(4, "A", 1, true) && prc_io(5, "B", 1, true) ? 0 : 8;
    if (prc_mode_is("nofs")) {
        const char *env = getenv("Z23_PLUGIN_FDS");
        bool ok = env && strcmp(env, "control=3,log=4") == 0 && fcntl(5, F_GETFD) == -1;
        return ok ? 21 : 22;
    }
    if (prc_mode_is("readonly")) {
        int fd = openat(data_fd, "w.txt", O_WRONLY | O_CREAT, 0600);
        return fd < 0 ? errno : 0;
    }
    if (prc_mode_is("crash"))
        return 3;
    if (prc_mode_is("try-socket"))
        return socket(AF_INET, SOCK_STREAM, 0) < 0 ? 4 : 6;
    return -1;
}

int main(int argc, char **argv)
{
    if (argc < 3 || strcmp(argv[1], "--resident") != 0)
        return 2;
    int data_fd = prc_fd_of("data.dir"), log_fd = prc_fd_of("log");
    int special = prc_special(data_fd);
    if (special >= 0)
        return special;
    if (data_fd >= 0)
        prc_report(data_fd);
    if (log_fd >= 0)
        (void)prc_io(log_fd, "fixture started\n", 16, true);
    if (log_fd >= 0 && prc_mode_is("logctl"))
        (void)prc_io(log_fd, "a\033[31m\007b\rc\n", 11, true);
    if (prc_mode_is("hang"))
        for (;;)
            pause();
    return prc_serve(argv[2]);
}
