/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Fixed PUBLIC bootstrap fixture. Never accepts private credential material. */
#if !defined(__FreeBSD__)
#define _DEFAULT_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "guest_port.h"
#if defined(__FreeBSD__)
#include <sys/capsicum.h>
#include <sys/disk.h>
#include <sys/ioctl.h>
#endif
#if defined(__FreeBSD__) && (!defined(IMAXBEL) || !defined(PENDIN))
#error "FreeBSD bootstrap needs the qualified native raw flags"
#endif
#define GB_BYTES 32u
#define GB_LIMIT_MS 20000
static bool gb_observe_kill;
static unsigned gb_kill_attempts;
static unsigned gb_reap_clock_control; /* Armed only by fixed PUBLIC controls. */
static int gb_signal(pid_t child)
{
    ++gb_kill_attempts;
    if (gb_observe_kill) { errno = EPERM; return -1; }
    return kill(child, SIGKILL);
}

static int64_t gb_now(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) return -1;
    if (t.tv_sec < 0 || (uintmax_t)t.tv_sec > (uintmax_t)(INT64_MAX - 999) / 1000 ||
        t.tv_nsec < 0 || t.tv_nsec >= 1000000000) return -1;
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static bool gb_wait(int fd, short events, int64_t end)
{
    for (;;) {
        int64_t now = gb_now();
        if (now < 0 || now >= end) return false;
        struct pollfd p = {fd, events, 0};
        int rc = poll(&p, 1, (int)(end - now));
        if (rc < 0 && errno == EINTR) continue;
        return rc > 0 && (p.revents & events) &&
               !(p.revents & (POLLERR | POLLNVAL));
    }
}
static bool gb_diag(const char *text, int64_t end)
{
    size_t off = 0, len = strlen(text);
    while (off < len) {
        if (!gb_wait(STDERR_FILENO, POLLOUT, end)) return false;
        ssize_t n = write(STDERR_FILENO, text + off, len - off);
        if (n > 0) off += (size_t)n;
        else if (n == 0 || (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)) return false;
    }
    return true;
}
static bool gb_output(int fd)
{
    int flags = fcntl(fd, F_GETFL);
    return flags >= 0 && (flags & O_ACCMODE) != O_RDONLY &&
        fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}
static bool gb_io(int fd, uint8_t *bytes, size_t length, bool writing, int64_t end)
{
    size_t off = 0;
    while (off < length) {
        if (!gb_wait(fd, writing ? POLLOUT : POLLIN, end)) return false;
        ssize_t n = writing ? write(fd, bytes + off, length - off) :
                              read(fd, bytes + off, length - off);
        if (n > 0) off += (size_t)n;
        else if (n == 0 || (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK))
            return false;
    }
    return true;
}
static void gb_pattern(uint8_t bytes[GB_BYTES])
{
    for (size_t i = 0; i < GB_BYTES; ++i) bytes[i] = (uint8_t)(i + 1);
}
static bool gb_reap(pid_t child, int64_t end, int *status, bool *timely)
{
    *timely = false;
    for (;;) {
        pid_t got = waitpid(child, status, WNOHANG);
        if (got == child) {
            int64_t observed = gb_reap_clock_control == 8 ? end :
                               gb_reap_clock_control == 9 ? -1 : gb_now();
            *timely = observed >= 0 && observed < end;
            return true; /* Preserve known custody even for a late observation. */
        }
        if (got < 0 && errno != EINTR) return false;
        int64_t now = gb_now();
        if (now < 0 || now >= end) return false;
        /* No wall-clock success predicate: this bounds the owned child wait. */
        if (poll(NULL, 0, 1) < 0 && errno != EINTR) return false;
    }
}
static bool gb_cancel(pid_t child, int64_t end)
{
    int status;
    pid_t got;
    for (;;) {
        int64_t now = gb_now();
        if (now < 0 || now >= end) return false;
        got = waitpid(child, &status, WNOHANG);
        if (got >= 0 || errno != EINTR) break;
    }
    if (got == child) return true;
    if (got != 0) return false; /* Lost custody: never signal a numeric PID. */
    if (gb_signal(child) != 0 && errno != ESRCH) return false;
    bool timely = false;
    return gb_reap(child, end, &status, &timely) && timely;
}
static int gb_prepare_open(const char *path, int flags)
{
    /* Called only after successful attach, reap, key wipe and port/pipe close. */
    closefrom(3);
    return open(path,flags);
}
static int gb_prepare_size(int fd, off_t *size)
{
#if defined(__FreeBSD__)
    return ioctl(fd,DIOCGMEDIASIZE,size);
#else
    (void)fd; (void)size;
    errno=ENOTSUP;
    return -1;
#endif
}
static bool gb_prepare_confine(int fd)
{
#if defined(__FreeBSD__)
    cap_rights_t rights;
    cap_rights_init(&rights,CAP_PWRITE,CAP_FSYNC);
    if (cap_rights_limit(fd,&rights)!=0) return false;
    cap_rights_init(&rights);
    if (cap_rights_limit(STDIN_FILENO,&rights)!=0 ||
        cap_rights_limit(STDOUT_FILENO,&rights)!=0) return false;
    cap_rights_init(&rights,CAP_WRITE,CAP_EVENT);
    return cap_rights_limit(STDERR_FILENO,&rights)==0 && cap_enter()==0;
#else
    (void)fd;
    return false;
#endif
}
#define GB_PREP_OPEN gb_prepare_open
#define GB_PREP_STAT fstat
#define GB_PREP_SIZE gb_prepare_size
#define GB_PREP_CONFINE gb_prepare_confine
#define GB_PREP_WRITE pwrite
#define GB_PREP_SYNC fsync
#define GB_PREP_CLOSE close
#define GB_PREP_NOW gb_now
#define GB_PREP_DIAG gb_diag
#include "geli_public_prepare.inc"
#undef GB_PREP_OPEN
#undef GB_PREP_STAT
#undef GB_PREP_SIZE
#undef GB_PREP_CONFINE
#undef GB_PREP_WRITE
#undef GB_PREP_SYNC
#undef GB_PREP_CLOSE
#undef GB_PREP_NOW
#undef GB_PREP_DIAG
static bool gb_fd(int fd, int flags)
{
    int current = fcntl(fd, F_GETFD);
    return current >= 0 && fcntl(fd, F_SETFD, current | flags) == 0;
}
static void gb_child_verify(void)
{
    uint8_t bytes[GB_BYTES], expected[GB_BYTES];
    gb_pattern(expected);
    size_t used = 0;
    while (used < GB_BYTES) {
        ssize_t n = read(STDIN_FILENO, bytes + used, GB_BYTES - used);
        if (n > 0) used += (size_t)n;
        else if (n == 0 || errno != EINTR) _exit(93);
    }
    uint8_t extra;
    ssize_t n;
    do { n = read(STDIN_FILENO, &extra, 1); } while (n < 0 && errno == EINTR);
    bool exact = n == 0 && memcmp(bytes, expected, GB_BYTES) == 0;
    explicit_bzero(bytes, sizeof(bytes));
    _exit(exact ? 0 : 94);
}
static void gb_child(int read_fd, int write_fd, unsigned mode)
{
    if (close(write_fd) != 0 || dup2(read_fd, STDIN_FILENO) < 0) _exit(90);
    if (read_fd != STDIN_FILENO && close(read_fd) != 0) _exit(91);
    closefrom(3); /* Fixed fixture inherits only stdin and public console output. */
    if (mode == 0) {
        execl("/sbin/geli", "geli", "attach", "-p", "-k", "-", "/dev/vtbd0", (char *)NULL);
        _exit(92);
    }
    if (mode == 5 || mode == 7) _exit(95);
    if (mode == 6) for (;;) (void)poll(NULL, 0, 1000);
    gb_child_verify();
}
static int gb_lost_custody(pid_t child, int write_fd, bool ok, int64_t end, int64_t cleanup_end)
{
    int status = 0;
    bool timely = false;
    bool reaped = gb_reap(child, end, &status, &timely);
    bool closed = close(write_fd) == 0;
    if (!reaped) {
        (void)gb_cancel(child, cleanup_end);
        return 7;
    }
    /* This control's observer blocks every signal before syscall, including
     * a mutation which signals the already-reaped numeric PID. */
    gb_observe_kill = true;
    bool refused = !gb_cancel(child, cleanup_end);
    bool proved = ok && timely && closed && WIFEXITED(status) && WEXITSTATUS(status) == 95 &&
                  refused && gb_kill_attempts == 0;
    if (proved) proved = gb_diag("PUBLIC_LOST_CUSTODY_NO_SIGNAL\n", cleanup_end);
    return proved ? 0 : 7;
}

static int gb_postreap_control(pid_t child, bool reaped, bool timely, int status, int64_t cleanup_end)
{
    bool proved = reaped && !timely && WIFEXITED(status) &&
                  WEXITSTATUS(status) == 0 && gb_kill_attempts == 0;
    if (!reaped) (void)gb_cancel(child, cleanup_end);
    if (proved) proved = gb_diag("PUBLIC_POSTREAP_REFUSED_CUSTODY_PRESERVED\n", cleanup_end);
    return proved ? 0 : 7;
}

static bool gb_deliver(unsigned mode, bool control, bool wrong_key, bool ok, int write_fd,
                       int64_t end, bool *delivered_out, bool *eof_out)
{
    uint8_t bytes[GB_BYTES + 1] = {0}, expected[GB_BYTES];
    gb_pattern(expected);
    if (wrong_key) for (size_t i = 0; i < GB_BYTES; ++i) expected[i] += 32;
    int port = -1;
    if (control) {
        memcpy(bytes, expected, GB_BYTES); bytes[GB_BYTES] = 33;
        if (mode == 4) bytes[0] ^= 0x80;
    }
    else if (ok) {
        port = open_raw("/dev/vtcon/z23.bootstrap.keyfile");
        ok = port >= 0;
        if (ok) ok = gb_diag("PUBLIC_BOOTSTRAP_RAW_READY\n", end);
        if (ok) ok = gb_io(port, bytes, GB_BYTES, false, end);
    }
    /* Foreign material is refused; this fixture is never a credential API. */
    ok = ok && memcmp(bytes, expected, GB_BYTES) == 0;
    explicit_bzero(expected, sizeof(expected));
    bool delivered = false;
    if (ok) {
        delivered = gb_io(write_fd, bytes, mode == 2 ? GB_BYTES - 1 : mode == 3 ? GB_BYTES + 1 : GB_BYTES, true, end);
        ok = delivered;
    }
    explicit_bzero(bytes, sizeof(bytes));
    if (port >= 0 && close(port) != 0) ok = false;
    bool eof_closed = close(write_fd) == 0; /* Actual EOF for GELI keyfile stdin. */
    if (!eof_closed) ok = false;
    *delivered_out = delivered;
    *eof_out = eof_closed;
    return ok;
}

static bool gb_evidence(bool control, bool ok, bool delivered, bool eof_closed,
                        bool reaped, bool timely, int status, int64_t cleanup_end)
{
    if (!control) {
        char evidence[160];
        int n = snprintf(evidence, sizeof(evidence),
            "PUBLIC_BOOTSTRAP_CHILD delivered32=%u eof=%u reaped=%u timely=%u exited=%u status=%d\n",
            delivered ? 1u : 0u, eof_closed ? 1u : 0u, reaped ? 1u : 0u,
            timely ? 1u : 0u, reaped && WIFEXITED(status) ? 1u : 0u,
            reaped && WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        if (n <= 0 || (size_t)n >= sizeof(evidence) || !gb_diag(evidence, cleanup_end)) ok = false;
    }
    return ok;
}

static bool gb_finish_custody(unsigned mode, bool *ok, bool reaped, pid_t child, int64_t cleanup_end)
{
    bool custody = true;
    if (!reaped) {
        *ok = false; custody = gb_cancel(child, cleanup_end);
        if (mode == 6 && custody && gb_kill_attempts == 1)
            custody = gb_diag("PUBLIC_OWNED_CHILD_CANCELLED_REAPED\n", cleanup_end);
        if (!custody) {
            gb_diag("PUBLIC_BOOTSTRAP_UNOBSERVED_CHILD_CUSTODY\n", cleanup_end);
        }
    }
    return custody;
}

static int gb_finish(unsigned mode, bool control, bool initial_prepare, bool ok,
                     bool delivered, bool eof_closed, bool reaped, bool timely,
                     int status, pid_t child, int64_t cleanup_end)
{
    bool custody = gb_finish_custody(mode, &ok, reaped, child, cleanup_end);
    ok = gb_evidence(control, ok, delivered, eof_closed, reaped, timely, status, cleanup_end);
    ok = ok && reaped && timely && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    if (ok) ok = gb_diag(control ? "PUBLIC_PIPE_CONTROL_EXACT32\n" :
                                  "PUBLIC_BOOTSTRAP_ATTACH_EXACT32\n", cleanup_end);
    ok = gb_prepare_finish(initial_prepare,ok,cleanup_end);
    if (ok && initial_prepare) ok = gb_diag("PUBLIC_BOOTSTRAP_PREPARED20K\n",cleanup_end);
    return !custody ? 7 : ok ? 0 : 6;
}

static unsigned gb_mode(int argc, char **argv)
{
    static const char *const options[] = {
        "--public-pipe-control", "--public-pipe-short", "--public-pipe-extra",
        "--public-pipe-wrong", "--public-child-failure",
        "--public-child-cancel", "--public-lost-custody",
        "--public-postreap-expired", "--public-postreap-clockfail"
    };
    unsigned mode = 0;
    if (argc == 2) {
        for (size_t i = 0; i < sizeof(options) / sizeof(options[0]); ++i)
            if (strcmp(argv[1], options[i]) == 0) mode = (unsigned)i + 1;
    }
    return mode;
}

static int gb_start(unsigned mode, int64_t end, int p[2], pid_t *child_out, bool *ok_out)
{
    if (pipe(p) != 0) { gb_diag("PUBLIC_BOOTSTRAP_PIPE\n", end); return 3; }
    /* Refuse low-FD aliasing instead of changing inherited stdio authority. */
    if (p[0] < 3 || p[1] < 3 || !gb_fd(p[0], FD_CLOEXEC) || !gb_fd(p[1], FD_CLOEXEC)) {
        close(p[0]); close(p[1]); return 4;
    }
    pid_t child = fork(); /* Happens before any port read or PUBLIC key staging. */
    if (child == 0) gb_child(p[0], p[1], mode);
    if (child < 0) { gb_diag("PUBLIC_BOOTSTRAP_FORK\n", end); close(p[0]); close(p[1]); return 5; }
    bool ok = close(p[0]) == 0;
    int flags = fcntl(p[1], F_GETFL);
    ok = ok && flags >= 0 && fcntl(p[1], F_SETFL, flags | O_NONBLOCK) == 0;
    struct sigaction sa = {0};
    sa.sa_handler = SIG_IGN;
    ok = ok && sigemptyset(&sa.sa_mask) == 0 && sigaction(SIGPIPE, &sa, NULL) == 0;
    *child_out = child;
    *ok_out = ok;
    return 0;
}

static bool gb_arguments_valid(int argc, bool control, bool wrong_key, bool initial_prepare)
{
    return !((!control && argc != 1 && !wrong_key && !initial_prepare) ||
             !gb_output(STDOUT_FILENO) || !gb_output(STDERR_FILENO));
}

int main(int argc, char **argv)
{
    unsigned mode = gb_mode(argc, argv);
    bool control = mode != 0;
    if (mode == 8 || mode == 9) gb_reap_clock_control = mode;
    bool wrong_key = argc == 2 && strcmp(argv[1], "--public-wrong-key") == 0;
    bool initial_prepare = argc == 2 && strcmp(argv[1], "--public-initial-prepare") == 0;
    if (!gb_arguments_valid(argc, control, wrong_key, initial_prepare)) return 1;
    int64_t begin = gb_now();
    if (begin <= 0 || begin > INT64_MAX - GB_LIMIT_MS) return 2;
    int64_t cleanup_end = begin + (control ? 3000 : GB_LIMIT_MS);
    int64_t end = cleanup_end - (control ? 1000 : 2000);
    int p[2];
    pid_t child;
    bool ok;
    int started = gb_start(mode, end, p, &child, &ok);
    if (started) return started;
    if (mode == 7) return gb_lost_custody(child, p[1], ok, end, cleanup_end);
    bool delivered, eof_closed;
    ok = gb_deliver(mode, control, wrong_key, ok, p[1], end, &delivered, &eof_closed);
    int status = 0;
    bool timely = false;
    bool reaped = gb_reap(child, end, &status, &timely);
    if (mode == 8 || mode == 9)
        return gb_postreap_control(child, reaped, timely, status, cleanup_end);
    return gb_finish(mode, control, initial_prepare, ok, delivered, eof_closed,
                     reaped, timely, status, child, cleanup_end);
}
