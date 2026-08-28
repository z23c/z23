/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#define _GNU_SOURCE
#include "devloop.h"

#include "platform/time_compat.h"
#include "platform/process_compat.h"
#include "platform/process_lifecycle.h"

#if defined(_WIN32)

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

static _Atomic bool g_process_cancel_requested;
static zcl_devloop_process_cancel_poll_fn g_process_cancel_poll;
static void *g_process_cancel_poll_opaque;

void zcl_devloop_process_cancel_request(void)
{
    atomic_store_explicit(&g_process_cancel_requested, true,
                          memory_order_release);
}

void zcl_devloop_process_cancel_clear(void)
{ atomic_store_explicit(&g_process_cancel_requested, false,
                        memory_order_release); }

bool zcl_devloop_process_cancel_requested(void)
{ return atomic_load_explicit(&g_process_cancel_requested,
                              memory_order_acquire); }

void zcl_devloop_process_cancel_poll_set(
    zcl_devloop_process_cancel_poll_fn poll_fn, void *opaque)
{ g_process_cancel_poll = poll_fn; g_process_cancel_poll_opaque = opaque; }

void zcl_devloop_process_cancel_poll_clear(void)
{ g_process_cancel_poll = NULL; g_process_cancel_poll_opaque = NULL; }

static bool process_run_impl(const char *cwd, int exec_fd,
                             const char *const argv[], int timeout_ms,
                             bool raise_stack,
                             struct zcl_devloop_process_result *out)
{
    (void)raise_stack;
    size_t image_len = argv && argv[0] ? strlen(argv[0]) : 0u;
    if (!cwd || !cwd[0] || !argv || !argv[0] || !out || timeout_ms <= 0 ||
        exec_fd >= 0 ||
        !((image_len >= 3u && argv[0][1] == ':' &&
           (argv[0][2] == '\\' || argv[0][2] == '/')) ||
          (image_len >= 2u && argv[0][0] == '\\' && argv[0][1] == '\\'))) {
        if (out) { memset(out, 0, sizeof(*out)); out->exit_code = -1; }
        fprintf(stderr, "[devloop] process: Windows requires an absolute "
                        "native executable path; descriptor execution is unavailable\n");
        return false;
    }
    memset(out, 0, sizeof(*out)); out->exit_code = -1;
#if !defined(ZCL_DEV_BUILD) && !defined(ZCL_TESTING)
    fprintf(stderr, "[devloop] process execution is disabled outside a dev build\n");
    return false;
#else
    static const char *const empty_environment[] = {NULL};
    struct platform_process child;
    platform_process_init(&child);
    struct platform_process_options options = {
        .image = argv[0], .argv = argv, .cwd = cwd,
        .env = empty_environment, .inherited = NULL, .inherited_count = 0};
    int64_t started = platform_time_monotonic_us();
    if (!platform_process_start_hidden(&child, &options))
        return false;
    out->startup_us = platform_time_monotonic_us() - started;
    uint32_t code = 0;
    enum platform_process_wait_result waited = PLATFORM_PROCESS_WAIT_RUNNING;
    while (waited == PLATFORM_PROCESS_WAIT_RUNNING) {
        if (!zcl_devloop_process_cancel_requested() && g_process_cancel_poll &&
            g_process_cancel_poll(g_process_cancel_poll_opaque))
            zcl_devloop_process_cancel_request();
        int64_t elapsed = platform_time_monotonic_us() - started;
        if (zcl_devloop_process_cancel_requested() ||
            elapsed >= (int64_t)timeout_ms * 1000) {
            out->cancelled = zcl_devloop_process_cancel_requested();
            out->timed_out = !out->cancelled;
            (void)platform_process_terminate(&child,
                                             out->cancelled ? 125u : 124u);
        }
        waited = platform_process_wait(&child, 5u, &code);
    }
    int64_t elapsed = platform_time_monotonic_us() - started;
    out->elapsed_ms = elapsed / 1000;
    out->body_us = elapsed > out->startup_us ? elapsed - out->startup_us : 0;
    bool ok = waited == PLATFORM_PROCESS_WAIT_EXITED;
    if (ok) out->exit_code = (int)code;
    platform_process_close(&child);
    return ok;
#endif
}

bool zcl_devloop_process_run(const char *cwd, const char *const argv[],
                             int timeout_ms,
                             struct zcl_devloop_process_result *out)
{ return process_run_impl(cwd, -1, argv, timeout_ms, false, out); }

bool zcl_devloop_process_run_test(const char *cwd, const char *const argv[],
                                  int timeout_ms,
                                  struct zcl_devloop_process_result *out)
{ return process_run_impl(cwd, -1, argv, timeout_ms, true, out); }

bool zcl_devloop_process_run_fd(const char *cwd, int exec_fd,
                                const char *const argv[], int timeout_ms,
                                struct zcl_devloop_process_result *out)
{ return process_run_impl(cwd, exec_fd, argv, timeout_ms, false, out); }

#else

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t g_process_cancel_requested;
static volatile sig_atomic_t g_process_active_leader;
static zcl_devloop_process_cancel_poll_fn g_process_cancel_poll;
static void *g_process_cancel_poll_opaque;
static pthread_mutex_t g_process_cancel_poll_mu = PTHREAD_MUTEX_INITIALIZER;

void zcl_devloop_process_cancel_request(void)
{
    g_process_cancel_requested = 1;
    /* This entry point is called from watcher/proof signal handlers. kill(2)
     * is async-signal-safe; wake the exact bounded child immediately instead
     * of waiting for the proof worker's next 5 ms control-loop poll. The
     * ordinary reap path below still performs the complete session sweep. */
    sig_atomic_t leader = g_process_active_leader;
    if (leader > 1) {
        (void)kill(-(pid_t)leader, SIGTERM);
        (void)kill((pid_t)leader, SIGTERM);
    }
}


void zcl_devloop_process_cancel_clear(void)
{
    g_process_cancel_requested = 0;
}

bool zcl_devloop_process_cancel_requested(void)
{
    return g_process_cancel_requested != 0;
}

void zcl_devloop_process_cancel_poll_set(
    zcl_devloop_process_cancel_poll_fn poll_fn, void *opaque)
{
    pthread_mutex_lock(&g_process_cancel_poll_mu);
    g_process_cancel_poll = poll_fn;
    g_process_cancel_poll_opaque = opaque;
    pthread_mutex_unlock(&g_process_cancel_poll_mu);
}

void zcl_devloop_process_cancel_poll_clear(void)
{
    pthread_mutex_lock(&g_process_cancel_poll_mu);
    g_process_cancel_poll = NULL;
    g_process_cancel_poll_opaque = NULL;
    pthread_mutex_unlock(&g_process_cancel_poll_mu);
}

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
static pid_t proc_session_id(pid_t pid)
{
    char path[64], body[1024];
    int n = snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return -1;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    ssize_t got;
    do {
        got = read(fd, body, sizeof(body) - 1);
    } while (got < 0 && errno == EINTR);
    close(fd);
    if (got <= 0)
        return -1;
    body[got] = 0;
    char *fields = strrchr(body, ')');
    char state = 0;
    long parent = 0, group = 0, session = 0;
    if (!fields || sscanf(fields + 1, " %c %ld %ld %ld", &state, &parent,
                          &group, &session) != 4 || session <= 0)
        return -1;
    return (pid_t)session;
}

static void signal_session_members(pid_t session, int sig)
{
    DIR *proc = opendir("/proc");
    if (!proc)
        return;
    struct dirent *entry;
    while ((entry = readdir(proc)) != NULL) {
        const unsigned char *p = (const unsigned char *)entry->d_name;
        if (!*p)
            continue;
        bool digits = true;
        for (; *p; p++)
            if (!isdigit(*p)) {
                digits = false;
                break;
            }
        if (!digits)
            continue;
        char *end = NULL;
        long value = strtol(entry->d_name, &end, 10);
        if (!end || *end || value <= 1 || value > INT_MAX)
            continue;
        pid_t member = (pid_t)value;
        if (proc_session_id(member) == session)
            (void)kill(member, sig);
    }
    closedir(proc);
}

static void terminate_child_session(pid_t leader, int sig)
{
    /* The leader may have spawned grandchildren into distinct process groups.
     * Stop its own group first so it cannot race the /proc session sweep. */
    (void)kill(-leader, sig);
    signal_session_members(leader, sig);
}
#endif

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
static void capture_tail(struct zcl_devloop_process_result *out,
                         const char *data, size_t len)
{
    const size_t cap = sizeof(out->output) - 1;
    if (len >= cap) {
        out->output_truncated = true;
        memcpy(out->output, data + len - cap, cap);
        out->output_len = cap;
    } else {
        size_t overflow = out->output_len + len > cap
            ? out->output_len + len - cap : 0;
        if (overflow > 0) {
            out->output_truncated = true;
            memmove(out->output, out->output + overflow,
                    out->output_len - overflow);
            out->output_len -= overflow;
        }
        memcpy(out->output + out->output_len, data, len);
        out->output_len += len;
    }
    out->output[out->output_len] = 0;
}

static void drain_output(int fd, struct zcl_devloop_process_result *out)
{
    char buf[4096];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 0) {
            if ((size_t)n > sizeof(buf))
                break;
            capture_tail(out, buf, (size_t)n);
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        break;
    }
}
#endif

static bool process_run_impl(const char *cwd, int exec_fd,
                             const char *const argv[], int timeout_ms,
                             bool raise_stack,
                             struct zcl_devloop_process_result *out)
{
    if (!cwd || !cwd[0] || !argv || !argv[0] || !out || timeout_ms <= 0) {
        fprintf(stderr, "[devloop] process: invalid bounded invocation\n");
        return false;
    }
    memset(out, 0, sizeof(*out));
    out->exit_code = -1;

#if !defined(ZCL_DEV_BUILD) && !defined(ZCL_TESTING)
    (void)exec_fd;
    (void)raise_stack;
    fprintf(stderr, "[devloop] process execution is disabled outside a dev build\n");
    return false;
#else
#ifdef ZCL_TESTING
    if (!getenv("ZCL_DEVLOOP_TEST_PROCESS") ||
        strcmp(getenv("ZCL_DEVLOOP_TEST_PROCESS"), "1") != 0) {
        (void)exec_fd;
        fprintf(stderr,
                "[devloop] process execution is disabled in tests unless the "
                "isolated fixture opts in\n");
        return false;
    }
#endif
    int fds[2] = {-1, -1}, ready_fds[2] = {-1, -1};
    if (pipe(fds) != 0 || pipe(ready_fds) != 0) {
        fprintf(stderr, "[devloop] process: pipe failed: %s\n",
                strerror(errno));
        if (fds[0] >= 0) close(fds[0]);
        if (fds[1] >= 0) close(fds[1]);
        if (ready_fds[0] >= 0) close(ready_fds[0]);
        if (ready_fds[1] >= 0) close(ready_fds[1]);
        return false;
    }
    (void)fcntl(fds[0], F_SETFD, FD_CLOEXEC);
    (void)fcntl(fds[1], F_SETFD, FD_CLOEXEC);
    (void)fcntl(ready_fds[0], F_SETFD, FD_CLOEXEC);
    (void)fcntl(ready_fds[1], F_SETFD, FD_CLOEXEC);

    int64_t started_us = platform_time_monotonic_us();
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "[devloop] process: fork failed: %s\n",
                strerror(errno));
        close(fds[0]);
        close(fds[1]);
        close(ready_fds[0]);
        close(ready_fds[1]);
        return false;
    }
    if (pid == 0) {
        close(ready_fds[0]);
        if (setsid() < 0)
            _exit(126);
        char ready = '1';
        if (write(ready_fds[1], &ready, 1) != 1)
            _exit(126);
        /* Keep the CLOEXEC descriptor open through setup. The parent sees
         * EOF exactly when exec succeeds (or the child exits), separating
         * process startup from command body time without a wrapper. */
        close(fds[0]);
        if (raise_stack) {
            struct rlimit limit;
            if (getrlimit(RLIMIT_STACK, &limit) != 0)
                _exit(126);
            if (limit.rlim_cur != limit.rlim_max) {
                limit.rlim_cur = limit.rlim_max;
                if (setrlimit(RLIMIT_STACK, &limit) != 0)
                    _exit(126);
            }
        }
        if (chdir(cwd) != 0)
            _exit(126);
        if (dup2(fds[1], STDOUT_FILENO) < 0 ||
            dup2(fds[1], STDERR_FILENO) < 0)
            _exit(126);
        close(fds[1]);
        if (exec_fd >= 0) {
            extern char **environ;
            platform_execve_fd(exec_fd, (char *const *)argv, environ);
        } else {
            execvp(argv[0], (char *const *)argv);
        }
        _exit(127);
    }
    g_process_active_leader = (sig_atomic_t)pid;

    close(fds[1]);
    close(ready_fds[1]);
    char ready = 0;
    ssize_t ready_got;
    do {
        ready_got = read(ready_fds[0], &ready, 1);
    } while (ready_got < 0 && errno == EINTR);
    if (ready_got != 1 || ready != '1') {
        close(ready_fds[0]);
        (void)kill(pid, SIGKILL);
        (void)waitpid(pid, NULL, 0);
        close(fds[0]);
        if (g_process_active_leader == (sig_atomic_t)pid)
            g_process_active_leader = 0;
        fprintf(stderr, "[devloop] process: child session setup failed\n");
        return false;
    }
    do {
        ready_got = read(ready_fds[0], &ready, 1);
    } while (ready_got < 0 && errno == EINTR);
    out->startup_us = platform_time_monotonic_us() - started_us;
    close(ready_fds[0]);
    if (ready_got != 0) {
        (void)kill(pid, SIGKILL);
        (void)waitpid(pid, NULL, 0);
        close(fds[0]);
        if (g_process_active_leader == (sig_atomic_t)pid)
            g_process_active_leader = 0;
        fprintf(stderr, "[devloop] process: exec boundary failed\n");
        return false;
    }
    int flags = fcntl(fds[0], F_GETFL, 0);
    if (flags >= 0)
        (void)fcntl(fds[0], F_SETFL, flags | O_NONBLOCK);

    int status = 0;
    bool finished = false;
    int64_t deadline_us = started_us + (int64_t)timeout_ms * 1000;
    while (!finished) {
        if (!g_process_cancel_requested) {
            pthread_mutex_lock(&g_process_cancel_poll_mu);
            zcl_devloop_process_cancel_poll_fn poll_fn =
                g_process_cancel_poll;
            void *poll_opaque = g_process_cancel_poll_opaque;
            bool requested = poll_fn && poll_fn(poll_opaque);
            pthread_mutex_unlock(&g_process_cancel_poll_mu);
            if (requested) zcl_devloop_process_cancel_request();
        }
        size_t output_before = out->output_len;
        drain_output(fds[0], out);
        if (out->first_output_us == 0 && out->output_len > output_before)
            out->first_output_us =
                platform_time_monotonic_us() - started_us;
        pid_t waited = waitpid(pid, &status, WNOHANG);
        if (waited == pid) {
            finished = true;
            /* Cancellation armed before this reap owns the child's death:
             * cancel_request() signals the leader synchronously, so under
             * CPU saturation waitpid can reap the terminated child in the
             * SAME iteration, before the cancel/deadline branch below runs.
             * Attribute the cancellation here or the receipt lies about why
             * the child died. */
            if (g_process_cancel_requested != 0)
                out->cancelled = true;
            break;
        }
        if (waited < 0 && errno != EINTR) {
            fprintf(stderr, "[devloop] process: waitpid failed for %s: %s\n",
                    argv[0], strerror(errno));
            terminate_child_session(pid, SIGKILL);
            (void)waitpid(pid, &status, 0);
            close(fds[0]);
            if (g_process_active_leader == (sig_atomic_t)pid)
                g_process_active_leader = 0;
            return false;
        }
        bool cancelled = g_process_cancel_requested != 0;
        if (cancelled || platform_time_monotonic_us() >= deadline_us) {
            out->cancelled = cancelled;
            out->timed_out = !cancelled;
            terminate_child_session(pid, SIGTERM);
            for (int i = 0; i < 20; i++) {
                if (waitpid(pid, &status, WNOHANG) == pid) {
                    finished = true;
                    break;
                }
                struct pollfd exit_event = {
                    .fd = fds[0], .events = POLLIN | POLLHUP
                };
                (void)poll(&exit_event, 1, 1);
            }
            if (!finished) {
                terminate_child_session(pid, SIGKILL);
                while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
                finished = true;
            }
            break;
        }
        struct pollfd pfd = { .fd = fds[0], .events = POLLIN };
        (void)poll(&pfd, 1, 5);
    }
    /* A bounded command may not daemonize work past its receipt. Reap any
     * descendant process group that stayed in the command's private session. */
    signal_session_members(pid, SIGTERM);
    signal_session_members(pid, SIGKILL);
    size_t output_before = out->output_len;
    drain_output(fds[0], out);
    if (out->first_output_us == 0 && out->output_len > output_before)
        out->first_output_us = platform_time_monotonic_us() - started_us;
    close(fds[0]);
    if (g_process_active_leader == (sig_atomic_t)pid)
        g_process_active_leader = 0;

    if (WIFEXITED(status))
        out->exit_code = WEXITSTATUS(status);
    else if (WIFSIGNALED(status))
        out->term_signal = WTERMSIG(status);
    int64_t elapsed_us = platform_time_monotonic_us() - started_us;
    out->elapsed_ms = elapsed_us / 1000;
    out->body_us = elapsed_us > out->startup_us
        ? elapsed_us - out->startup_us : 0;
    return true;
#endif
}

bool zcl_devloop_process_run(const char *cwd,
                             const char *const argv[],
                             int timeout_ms,
                             struct zcl_devloop_process_result *out)
{
    return process_run_impl(cwd, -1, argv, timeout_ms, false, out);
}

bool zcl_devloop_process_run_test(const char *cwd,
                                  const char *const argv[], int timeout_ms,
                                  struct zcl_devloop_process_result *out)
{
    return process_run_impl(cwd, -1, argv, timeout_ms, true, out);
}

bool zcl_devloop_process_run_fd(const char *cwd, int exec_fd,
                                const char *const argv[], int timeout_ms,
                                struct zcl_devloop_process_result *out)
{
    if (exec_fd < 0) {
        fprintf(stderr, "[devloop] process: invalid executable fd\n");
        return false;
    }
    return process_run_impl(cwd, exec_fd, argv, timeout_ms, false, out);
}

#endif /* _WIN32 */
