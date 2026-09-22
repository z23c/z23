/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: smallest C23 MSP client around the installed `muse serve` host. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "services/muse_session.h"

/* POSIX-only, the whole file: an MSP session IS a fork/execvp'd `muse serve`
 * child with its stdio on two pipes and a poll loop over them, and mingw has
 * none of fork, waitpid, poll or <sys/wait.h>. Guarding the body — rather
 * than growing a second Windows arm per entry point — is the shape
 * contexts/commons/services/src/zcode_benchmark_executor.c already uses for
 * its own forking executor, and it keeps one definition per function so two
 * bodies under one name can never drift apart. On Windows this compiles to
 * an empty translation unit; there is no Muse host to adapt there. */
#if !defined(_WIN32)

#include "muse_session_internal.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/clock.h"
#include "platform/os_proc.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static struct muse_session *ms_alloc(pid_t child, int to_fd, int from_fd,
    const struct muse_session_limits *limits);
static bool ms_handshake(struct muse_session *s);

void ms_fail(struct muse_session *s, const char *kind,
    bool retryable, const char *fmt, ...)
{
    if (!s) return;
    (void)snprintf(s->kind, sizeof(s->kind), "%s", kind ? kind : "internal");
    s->retryable = retryable;
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(s->err, sizeof(s->err), fmt, ap);
    va_end(ap);
}

int64_t ms_monotonic_ms(void)
{
    return clock_now_monotonic_ns() / 1000000;
}

bool muse_session_command_id(char out[MUSE_COMMAND_ID_MAX])
{
    uint8_t rnd[10];
    /* The platform wall seam reports a failed CLOCK_REALTIME read as 0
     * (platform/modules/platform/src/clock.c:43), and a genuine reading is
     * never 0 — that is 1970-01-01T00:00:00Z. Treating 0 as the failure
     * keeps the original refusal: no timestamp, no handle. */
    int64_t wall_ms = clock_now_wall_ms();
    if (!out || wall_ms <= 0) return false;
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t got = 0;
        while (got < 10) {
            ssize_t k = read(fd, rnd + got, (size_t)(10 - got));
            if (k <= 0) break;
            got += k;
        }
        close(fd);
        if (got < 10) return false;
    } else {
        return false;
    }
    uint64_t ms = (uint64_t)wall_ms;
    unsigned a = (unsigned)((ms >> 32) & 0xffffffffu);
    unsigned b = (unsigned)((ms >> 16) & 0xffffu);
    unsigned c = (unsigned)(0x7000u | (ms & 0x0fffu));
    /* variant 10xxxxxx on the clock_seq_hi octet. */
    unsigned d = (unsigned)(0x8000u | (((unsigned)rnd[0] << 8 | rnd[1]) & 0x3fffu));
    int n = snprintf(out, MUSE_COMMAND_ID_MAX, "%08x-%04x-%04x-%04x-%02x%02x%02x%02x%02x%02x",
        a, b & 0xffffu, c & 0xffffu, d & 0xffffu,
        rnd[2], rnd[3], rnd[4], rnd[5], rnd[6], rnd[7]);
    return n > 0 && (size_t)n < MUSE_COMMAND_ID_MAX;
}

static bool ms_write_all(struct muse_session *s, const char *buf, size_t len)
{
    size_t done = 0;
    while (done < len) {
        ssize_t k = write(s->to_child, buf + done, len - done);
        if (k < 0) {
            if (errno == EINTR) continue;
            ms_fail(s, "transport", true, "serve stdin write: %s",
                strerror(errno));
            return false;
        }
        done += (size_t)k;
    }
    return true;
}



/* The integer after a "max " line, or -1 when the file has none. */
static long long ms_events_max_value(FILE *f)
{
    char buf[256];
    while (fgets(buf, sizeof(buf), f)) {
        long long v = 0;
        const char *p;
        if (strncmp(buf, "max ", 4) != 0)
            continue;
        p = buf + 4;
        if (*p < '0' || *p > '9')
            break;
        while (*p >= '0' && *p <= '9') {
            if (v > (LLONG_MAX - 9) / 10)
                break;
            v = v * 10 + (*p - '0');
            p++;
        }
        return v;
    }
    return -1;
}

/* memory.events "max" for this process's cgroup, or -1 if unreadable.
 * Hitting memory.max fails the page charge. The muse host then aborts
 * itself, so oom_kill stays 0 and the parent only sees stdout EOF. */
static long long ms_cgroup_max_events(void)
{
    char dir[512];
    char path[700];
    FILE *f;
    long long v;
    if (!os_proc_cgroup_dir(dir, sizeof(dir)))
        return -1;
    if (snprintf(path, sizeof(path), "%s/memory.events", dir) >=
        (int)sizeof(path))
        return -1;
    f = fopen(path, "r");
    if (!f)
        return -1;
    v = ms_events_max_value(f);
    fclose(f);
    return v;
}

/* Stdout EOF is not a reason by itself. The serve child has usually
 * already exited: a Rust host abort under the worker cgroup prints
 * "memory allocation failed" and then closes the pipe. Reap it here so
 * the recorded reason names the exit or signal instead of a bare close.
 * A child that is still alive keeps the bare close; close() still owns
 * the grace-period kill. When memory.events max moved, the charge failed
 * and the host aborted itself, so oom_kill stays 0. That is not retryable. */
/* EOF can be observed before the exiting child is a zombie. Bound the
 * reap so a child that closed stdout and kept running is not waited
 * out for the whole turn. */
static pid_t ms_reap_soon(struct muse_session *s, int *st)
{
    int64_t deadline = ms_monotonic_ms() + 1000;
    pid_t r = 0;
    *st = 0;
    while (s && s->child > 0) {
        r = waitpid(s->child, st, WNOHANG);
        if (r == s->child || (r < 0 && errno != EINTR))
            break;
        if (ms_monotonic_ms() >= deadline)
            break;
        {
            struct timespec rest = {.tv_sec = 0, .tv_nsec = 2000000};
            (void)nanosleep(&rest, NULL);
        }
    }
    return r;
}

static void ms_stdout_how(char *how, size_t cap, pid_t r, int st)
{
    if (r > 0 && WIFSIGNALED(st))
        (void)snprintf(how, cap, "closed, child signal %d", WTERMSIG(st));
    else if (r > 0 && WIFEXITED(st))
        (void)snprintf(how, cap, "closed, child exit %d", WEXITSTATUS(st));
    else
        (void)snprintf(how, cap, "closed");
}

/* True when the child died on SIGABRT or SIGKILL and memory.events max
 * moved. That charge is not retryable. oom_kill stays 0. */
static bool ms_charge_killed(struct muse_session *s, pid_t r, int st)
{
    long long now;
    if (!s || r <= 0 || !WIFSIGNALED(st))
        return false;
    if (WTERMSIG(st) != SIGABRT && WTERMSIG(st) != SIGKILL)
        return false;
    now = ms_cgroup_max_events();
    return s->mem_max_events >= 0 && now > s->mem_max_events;
}

static void ms_fail_stdout_closed(struct muse_session *s)
{
    int st = 0;
    pid_t r = ms_reap_soon(s, &st);
    char how[64];
    ms_stdout_how(how, sizeof(how), r, st);
    if (r > 0 && s)
        s->child = -1;
    if (ms_charge_killed(s, r, st)) {
        ms_fail(s, "memoryMax", false,
                "memory.max charge failed, child signal %d", WTERMSIG(st));
        return;
    }
    ms_fail(s, "transport", true, "serve stdout %s", how);
}

/* Reads one newline-terminated frame, bounded by MUSE_LINE_MAX. Returns 1 on
 * a frame, 0 on timeout, -1 on EOF/error. */
int ms_read_line(struct muse_session *s, char *buf, size_t cap,
    int64_t deadline_ms)
{
    size_t n = 0;
    for (;;) {
        int64_t now = ms_monotonic_ms();
        if (now >= deadline_ms) return 0;
        int64_t wait_ms = deadline_ms - now;
        if (wait_ms > INT_MAX) wait_ms = INT_MAX;
        struct pollfd pfd = {
            .fd = s->from_child,
            .events = POLLIN,
            .revents = 0,
        };
        int r = poll(&pfd, 1, (int)wait_ms);
        if (r < 0) {
            if (errno == EINTR) continue;
            ms_fail(s, "transport", true, "serve stdout poll: %s",
                strerror(errno));
            return -1;
        }
        if (r == 0) return 0;
        char c;
        ssize_t k = read(s->from_child, &c, 1);
        if (k <= 0) {
            if (k < 0 && errno == EINTR) continue;
            if (k == 0)
                ms_fail_stdout_closed(s);
            else
                ms_fail(s, "transport", true, "serve stdout %s",
                    strerror(errno));
            return -1;
        }
        if (c == '\n') {
            buf[n] = '\0';
            return 1;
        }
        if (n + 1 >= cap) {
            ms_fail(s, "frameTooLarge", false,
                "serve frame exceeds %u bytes", MUSE_LINE_MAX);
            return -1;
        }
        buf[n++] = c;
    }
}

/* Copies a quoted `"..."` id token verbatim, escapes included. Advances the
 * cursor and the write index; false when the token does not fit. */
static bool ms_raw_id_quoted(const char **pp, char *out, size_t cap,
    size_t *np)
{
    const char *p = *pp;
    size_t n = *np;
    if (n + 1 >= cap) return false;
    out[n++] = *p++;
    while (*p && *p != '"' && n + 1 < cap) {
        if (*p == '\\' && p[1]) {
            out[n++] = *p++;
            if (n + 1 >= cap) return false;
        }
        out[n++] = *p++;
    }
    if (*p != '"' || n + 1 >= cap) return false;
    out[n++] = *p++;
    *pp = p;
    *np = n;
    return true;
}

/* Copies a bare numeric id token. False when there is no digit at all. */
static bool ms_raw_id_number(const char **pp, char *out, size_t cap,
    size_t *np)
{
    const char *p = *pp;
    size_t n = *np;
    while (((*p >= '0' && *p <= '9') || *p == '-') && n + 1 < cap)
        out[n++] = *p++;
    if (n == 0) return false;
    *pp = p;
    *np = n;
    return true;
}

/* Copies the raw `"id":<token>` value token (number or quoted string) so a
 * server-initiated request can be answered with the identical id. */
bool ms_raw_id(const char *line, char *out, size_t cap)
{
    const char *p = strstr(line, "\"id\":");
    if (!p || cap == 0) return false;
    p += 5;
    while (*p == ' ' || *p == '\t') p++;
    size_t n = 0;
    if (*p == '"') {
        if (!ms_raw_id_quoted(&p, out, cap, &n)) return false;
    } else {
        if (!ms_raw_id_number(&p, out, cap, &n)) return false;
    }
    out[n] = '\0';
    return true;
}

bool ms_send(struct muse_session *s, int id, const char *method,
    const char *params_json)
{
    char head[256];
    int n = snprintf(head, sizeof(head),
        "{\"jsonrpc\":\"2.0\",\"id\":%d,\"method\":\"%s\",\"params\":",
        id, method);
    if (n <= 0 || (size_t)n >= sizeof(head)) {
        ms_fail(s, "internal", false, "request head overflow");
        return false;
    }
    return ms_write_all(s, head, (size_t)n) &&
        ms_write_all(s, params_json, strlen(params_json)) &&
        ms_write_all(s, "}\n", 2);
}

bool ms_send_raw(struct muse_session *s, const char *frame)
{
    return ms_write_all(s, frame, strlen(frame)) &&
        ms_write_all(s, "\n", 1);
}

const char *muse_session_last_error(const struct muse_session *s)
{
    return s ? s->err : "no session";
}

const char *muse_session_last_kind(const struct muse_session *s)
{
    return s ? s->kind : "internal";
}

bool muse_session_last_retryable(const struct muse_session *s)
{
    return s ? s->retryable : false;
}

/* A symlink is unlinked, never walked. The real catalog stays put. */
static void ms_rm_rf(const char *path)
{
    DIR *d;
    struct dirent *de;
    if (!path || !path[0])
        return;
    d = opendir(path);
    if (!d) {
        (void)unlink(path);
        return;
    }
    while ((de = readdir(d)) != NULL) {
        char child[512];
        struct stat st;
        int n;
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        n = snprintf(child, sizeof(child), "%s/%s", path, de->d_name);
        if (n <= 0 || (size_t)n >= sizeof(child))
            continue;
        if (lstat(child, &st) == 0 && S_ISDIR(st.st_mode))
            ms_rm_rf(child);
        else
            (void)unlink(child);
    }
    closedir(d);
    (void)rmdir(path);
}

static void ms_link_if_present(const char *from, const char *to)
{
    struct stat st;
    if (from && to && lstat(from, &st) == 0)
        (void)symlink(from, to);
}

/* The operator muse home, if one is configured. Sessions are not copied. */
static int ms_real_muse_home(char *out, size_t cap)
{
    const char *xdg = getenv("XDG_DATA_HOME");
    const char *home;
    int n;
    if (xdg && xdg[0])
        n = snprintf(out, cap, "%s/muse", xdg);
    else {
        home = getenv("HOME");
        if (!home || !home[0])
            return -1;
        n = snprintf(out, cap, "%s/.local/share/muse", home);
    }
    return (n > 0 && (size_t)n < cap) ? 0 : -1;
}

/* One empty data home for this serve. The host loads every session under
 * the operator muse home; that tree is large enough to hit the worker
 * cgroup's memory.max during a turn. Model catalog and feature config are
 * linked when present. Session history is not. */
static int ms_isolate_data(char *dir, size_t cap)
{
    const char *tmp = getenv("TMPDIR");
    char tmpl[128], muse[160], real[512], from[576], to[192];
    if (!tmp || !tmp[0])
        tmp = "/tmp";
    if (snprintf(tmpl, sizeof(tmpl), "%s/z23-muse-XXXXXX", tmp) >=
        (int)sizeof(tmpl))
        return -1;
    if (!mkdtemp(tmpl))
        return -1;
    if (snprintf(dir, cap, "%s", tmpl) >= (int)cap ||
        snprintf(muse, sizeof(muse), "%s/muse", dir) >= (int)sizeof(muse) ||
        mkdir(muse, 0700) != 0) {
        ms_rm_rf(tmpl);
        return -1;
    }
    if (ms_real_muse_home(real, sizeof(real)) == 0) {
        if (snprintf(from, sizeof(from), "%s/model-catalog", real) <
                (int)sizeof(from) &&
            snprintf(to, sizeof(to), "%s/model-catalog", muse) <
                (int)sizeof(to))
            ms_link_if_present(from, to);
        if (snprintf(from, sizeof(from), "%s/feature-config", real) <
                (int)sizeof(from) &&
            snprintf(to, sizeof(to), "%s/feature-config", muse) <
                (int)sizeof(to))
            ms_link_if_present(from, to);
    }
    return 0;
}

static void ms_remember_data(char *old, size_t cap, int *had_old)
{
    const char *prev = getenv("XDG_DATA_HOME");
    *had_old = 0;
    old[0] = '\0';
    if (!prev || !prev[0])
        return;
    if (snprintf(old, cap, "%s", prev) < (int)cap)
        *had_old = 1;
}

/* 1 when the child should inherit a fresh data home. The parent keeps
 * old so it can put its own home back after fork. */
static int ms_apply_data_home(char *data_home, size_t cap, char *old,
                              size_t oldcap, int *had_old)
{
    data_home[0] = '\0';
    if (ms_isolate_data(data_home, cap) != 0)
        return 0;
    ms_remember_data(old, oldcap, had_old);
    if (setenv("XDG_DATA_HOME", data_home, 1) == 0)
        return 1;
    ms_rm_rf(data_home);
    data_home[0] = '\0';
    return 0;
}

static void ms_restore_data_home(int isolated, int had_old, const char *old)
{
    if (!isolated)
        return;
    if (had_old)
        (void)setenv("XDG_DATA_HOME", old, 1);
    else
        unsetenv("XDG_DATA_HOME");
}

static bool ms_open_pipes(int to_child[2], int from_child[2])
{
    if (pipe(to_child) != 0)
        return false;
    if (pipe(from_child) != 0) {
        int saved = errno;
        close(to_child[0]);
        close(to_child[1]);
        errno = saved;
        return false;
    }
    return true;
}

static void ms_cloexec_pair(const int fd[2])
{
    (void)fcntl(fd[0], F_SETFD, FD_CLOEXEC);
    (void)fcntl(fd[1], F_SETFD, FD_CLOEXEC);
}

/* Async-signal-safe only between fork and exec — the same contract
 * platform/modules/util/src/spawn.c:143 keeps in its own child arm.
 * No shell: argv[0] goes straight to execvp(). */
static void ms_child_serve(int to_child[2], int from_child[2],
                           const char *serve_argv0)
{
    const char *host = serve_argv0 ? serve_argv0 : "muse";
    const char *argv[] = {"muse", "serve", NULL};
    (void)dup2(to_child[0], STDIN_FILENO);
    (void)dup2(from_child[1], STDOUT_FILENO);
    close(to_child[0]);
    close(to_child[1]);
    close(from_child[0]);
    close(from_child[1]);
    execvp(host, (char *const *)argv);
    _exit(127);
}

static struct muse_session *ms_open_fork_fail(int to_child[2],
                                              int from_child[2],
                                              const char *data_home,
                                              char err[MUSE_ERROR_MAX])
{
    if (err)
        (void)snprintf(err, MUSE_ERROR_MAX, "fork: %s", strerror(errno));
    close(to_child[0]);
    close(to_child[1]);
    close(from_child[0]);
    close(from_child[1]);
    if (data_home[0])
        ms_rm_rf(data_home);
    return NULL;
}

struct muse_session *muse_session_open(const char *serve_argv0,
    const struct muse_session_limits *limits, char err[MUSE_ERROR_MAX])
{
    int to_child[2], from_child[2];
    char data_home[256];
    char old_data[512];
    int isolated;
    int had_old = 0;
    pid_t pid;
    struct muse_session *s;
    isolated = ms_apply_data_home(data_home, sizeof(data_home), old_data,
                                  sizeof(old_data), &had_old);
    if (!ms_open_pipes(to_child, from_child)) {
        ms_restore_data_home(isolated, had_old, old_data);
        if (isolated)
            ms_rm_rf(data_home);
        if (err)
            (void)snprintf(err, MUSE_ERROR_MAX, "pipe: %s", strerror(errno));
        return NULL;
    }
    ms_cloexec_pair(to_child);
    ms_cloexec_pair(from_child);
    pid = fork();
    if (pid != 0)
        ms_restore_data_home(isolated, had_old, old_data);
    if (pid < 0)
        return ms_open_fork_fail(to_child, from_child, data_home, err);
    if (pid == 0)
        ms_child_serve(to_child, from_child, serve_argv0);
    close(to_child[0]);
    close(from_child[1]);
    s = ms_alloc(pid, to_child[1], from_child[0], limits);
    if (!s) {
        if (data_home[0])
            ms_rm_rf(data_home);
        close(to_child[1]);
        close(from_child[0]);
        if (err)
            (void)snprintf(err, MUSE_ERROR_MAX, "out of memory");
        return NULL;
    }
    if (data_home[0])
        (void)snprintf(s->data_home, sizeof(s->data_home), "%s", data_home);
    if (!ms_handshake(s)) {
        if (err)
            (void)snprintf(err, MUSE_ERROR_MAX, "%s", s->err);
        muse_session_close(s);
        return NULL;
    }
    return s;
}

static struct muse_session *ms_alloc(pid_t child, int to_fd, int from_fd,
    const struct muse_session_limits *limits)
{
    struct muse_session *s = zcl_calloc(1, sizeof(*s), "muse_session");
    if (!s) return NULL;
    s->child = child;
    s->to_child = to_fd;
    s->from_child = from_fd;
    s->next_id = 1;
    s->open_timeout_ms = limits && limits->open_timeout_ms > 0
        ? limits->open_timeout_ms : MUSE_OPEN_DEFAULT_MS;
    s->turn_timeout_ms = limits && limits->turn_timeout_ms > 0
        ? limits->turn_timeout_ms : MUSE_TURN_DEFAULT_MS;
    s->max_total_tokens = limits ? limits->max_total_tokens : 0;
    s->max_text_bytes =
        limits && limits->max_text_bytes > 0 ? limits->max_text_bytes
                                             : MUSE_TEXT_DEFAULT;
    s->mem_max_events = ms_cgroup_max_events();
    (void)snprintf(s->kind, sizeof(s->kind), "%s", "ok");
    return s;
}

/* Folds one handshake frame. 1 = this was the initialize ack, 0 = unrelated
 * traffic to keep reading past, -1 = the host rejected initialize. */
static int ms_handshake_frame(struct muse_session *s, const char *line,
    int id)
{
    struct json_value v = {0};
    bool ok = json_read(&v, line, strlen(line));
    const struct json_value *rid = ok ? json_get(&v, "id") : NULL;
    if (!(ok && rid && rid->type == JSON_INT &&
            json_get_int(rid) == (int64_t)id)) {
        json_free(&v);
        return 0;
    }
    ok = json_get(&v, "result") != NULL;
    if (!ok) {
        const struct json_value *e = json_get(&v, "error");
        const struct json_value *m = e ? json_get(e, "message") : NULL;
        ms_fail(s, "error", false, "initialize: %s",
            m ? json_get_str(m) : "rejected");
    }
    json_free(&v);
    return ok ? 1 : -1;
}

/* initialize + initialized handshake. Fails with s->err set. */
static bool ms_handshake(struct muse_session *s)
{
    int id = s->next_id++;
    if (!ms_send(s, id,
            "initialize",
            "{\"clientInfo\":{\"name\":\"z23_muse_session\",\"version\":\"1\"}}"))
        return false;
    char *line = zcl_malloc(MUSE_LINE_MAX, "muse_session.frame");
    if (!line) {
        ms_fail(s, "internal", false, "out of memory");
        return false;
    }
    int64_t deadline = ms_monotonic_ms() + s->open_timeout_ms;
    bool initialized = false;
    for (;;) {
        int rc = ms_read_line(s, line, MUSE_LINE_MAX, deadline);
        if (rc != 1) {
            if (rc == 0)
                ms_fail(s, "timeout", true, "initialize timed out");
            free(line);
            return false;
        }
        int seen = ms_handshake_frame(s, line, id);
        if (seen < 0) {
            free(line);
            return false;
        }
        if (seen > 0) {
            initialized = true;
            break;
        }
    }
    free(line);
    if (!initialized) {
        ms_fail(s, "internal", false, "no initialize ack");
        return false;
    }
    if (!ms_send_raw(s,
            "{\"jsonrpc\":\"2.0\",\"method\":\"initialized\",\"params\":{}}"))
        return false;
    return true;
}

#ifdef ZCL_TESTING
struct muse_session *muse_session_attach(pid_t child, int to_fd, int from_fd,
    const struct muse_session_limits *limits)
{
    struct muse_session *s = ms_alloc(child, to_fd, from_fd, limits);
    if (!s) return NULL;
    if (!ms_handshake(s)) {
        muse_session_close(s);
        return NULL;
    }
    return s;
}
#endif

void muse_session_close(struct muse_session *s)
{
    if (!s) return;
    if (s->to_child >= 0) {
        close(s->to_child);
        s->to_child = -1;
    }
    if (s->child > 0) {
        int64_t deadline = ms_monotonic_ms() + MUSE_CLOSE_GRACE_MS;
        int status = 0;
        for (;;) {
            pid_t r = waitpid(s->child, &status, WNOHANG);
            if (r == s->child || (r < 0 && errno != EINTR)) break;
            if (r < 0) break;
            if (ms_monotonic_ms() >= deadline) {
                (void)kill(s->child, SIGKILL);
                (void)waitpid(s->child, &status, 0);
                break;
            }
            struct timespec rest = {.tv_sec = 0, .tv_nsec = 50000000};
            (void)nanosleep(&rest, NULL);
        }
        s->child = -1;
    }
    if (s->from_child >= 0) {
        close(s->from_child);
        s->from_child = -1;
    }
    if (s->data_home[0])
        ms_rm_rf(s->data_home);
    free(s);
}

/* Awaits the response bearing id, ignoring unrelated async traffic. The raw
 * response line is returned malloc'd (caller frees) or NULL on timeout/EOF. */
char *ms_await(struct muse_session *s, int id, int64_t deadline_ms)
{
    char *line = zcl_malloc(MUSE_LINE_MAX, "muse_session.frame");
    if (!line) {
        ms_fail(s, "internal", false, "out of memory");
        return NULL;
    }
    for (;;) {
        int rc = ms_read_line(s, line, MUSE_LINE_MAX, deadline_ms);
        if (rc != 1) {
            if (rc == 0)
                ms_fail(s, "timeout", true, "serve response timed out");
            free(line);
            return NULL;
        }
        struct json_value v = {0};
        bool ok = json_read(&v, line, strlen(line));
        const struct json_value *rid = ok ? json_get(&v, "id") : NULL;
        bool mine = ok && rid && rid->type == JSON_INT &&
            json_get_int(rid) == (int64_t)id &&
            json_get(&v, "method") == NULL;
        json_free(&v);
        if (mine) return line;
        /* Unrelated async traffic is folded by wait(); bare rpc calls drop
         * it: approvals stay pending and are re-issued on subscribe. */
    }
}

/* Splits a result/error response. Returns true on result (err untouched),
 * false on error with kind/retryable/message recorded. */
bool ms_split(struct muse_session *s, const char *line,
    const struct json_value **result_out, struct json_value *doc)
{
    if (!json_read(doc, line, strlen(line))) {
        ms_fail(s, "parseError", false, "serve sent unparsable JSON");
        return false;
    }
    const struct json_value *err = json_get(doc, "error");
    if (err) {
        const struct json_value *code = json_get(err, "code");
        const struct json_value *msg = json_get(err, "message");
        const struct json_value *data = json_get(err, "data");
        const struct json_value *kind = data ? json_get(data, "kind") : NULL;
        const struct json_value *retry =
            data ? json_get(data, "retryable") : NULL;
        (void)code;
        ms_fail(s, kind ? json_get_str(kind) : "error",
            retry ? json_get_bool(retry) : false, "%s",
            msg ? json_get_str(msg) : "serve command failed");
        return false;
    }
    const struct json_value *result = json_get(doc, "result");
    if (!result) {
        ms_fail(s, "internal", false, "serve response has no result");
        return false;
    }
    if (result_out) *result_out = result;
    return true;
}

bool ms_copy_str(char *dst, size_t cap, const char *src)
{
    if (!dst || cap == 0 || !src) return false;
    size_t n = strlen(src);
    if (n >= cap) return false;
    memcpy(dst, src, n + 1);
    return true;
}

static const char *ms_approval_mode(const struct muse_session_policy *policy)
{
    const char *mode = policy ? policy->approval_mode : NULL;
    return mode && mode[0] ? mode : "denyUnmatched";
}

/* Serializes a params object and frees it either way. `ok` carries the
 * result of the field pushes. NULL when the build failed or memory ran
 * out, with the failure recorded. */
static char *ms_render_params(struct muse_session *s, struct json_value *v,
    bool ok)
{
    size_t need = ok ? json_write(v, NULL, 0) + 1 : 0;
    char *text = ok && need > 0 ? zcl_malloc(need, "muse_session.params")
                                : NULL;
    if (!text) {
        json_free(v);
        ms_fail(s, "internal", false, "out of memory");
        return NULL;
    }
    (void)json_write(v, text, need);
    json_free(v);
    return text;
}

/* Sends one request (taking ownership of its rendered params) and splits
 * the response bearing its id. Returns the malloc'd response line — the
 * caller frees it and json_free()s doc — or NULL with the failure
 * recorded and doc already released. */
static char *ms_call(struct muse_session *s, const char *method, char *text,
    const struct json_value **result_out, struct json_value *doc)
{
    if (!text) return NULL;
    int id = s->next_id++;
    bool ok = ms_send(s, id, method, text);
    free(text);
    if (!ok) return NULL;
    char *line = ms_await(s, id, ms_monotonic_ms() + s->open_timeout_ms);
    if (!line) return NULL;
    if (!ms_split(s, line, result_out, doc)) {
        free(line);
        json_free(doc);
        return NULL;
    }
    return line;
}

/* The worker never selects allowAll; the rest is the closed host
 * vocabulary. False with the policy refusal recorded. */
static bool ms_start_mode_ok(struct muse_session *s, const char *mode)
{
    if (strcmp(mode, "allowAll") == 0) {
        ms_fail(s, "policy", false,
            "allowAll is never selected by the Z23 worker");
        return false;
    }
    if (strcmp(mode, "denyUnmatched") != 0 &&
        strcmp(mode, "onRequest") != 0 &&
        strcmp(mode, "promptUnmatched") != 0) {
        ms_fail(s, "policy", false, "unknown approval mode");
        return false;
    }
    return true;
}

/* The workspace root rides a JSON string field, so a quote or backslash in
 * it could never be framed: refuse rather than emit a forged field. */
static bool ms_start_workspace_ok(struct muse_session *s,
    const char *workspace_root, size_t ws)
{
    if (ws == 0 || ws >= sizeof(s->workspace) ||
        strchr(workspace_root, '"') || strchr(workspace_root, '\\')) {
        ms_fail(s, "policy", false, "unusable workspace root");
        return false;
    }
    return true;
}

/* session/start params: the command id, the workspace root, and the
 * approval mode the policy settled. */
static char *ms_start_params(struct muse_session *s, const char *command_id,
    const char *workspace_root, const char *mode)
{
    struct json_value params = {0};
    json_init(&params);
    json_set_object(&params);
    bool ok = json_push_kv_str(&params, "commandId", command_id) &&
        json_push_kv_str(&params, "workspaceRoot", workspace_root) &&
        json_push_kv_str(&params, "approvalMode", mode);
    return ms_render_params(s, &params, ok);
}

/* Copies the started session's identity out of the result and adopts the
 * workspace. False when the host hid the session id. */
static bool ms_start_identity(struct muse_session *s,
    const struct json_value *result, const char *workspace_root, size_t ws,
    char session_id[MUSE_SESSION_ID_MAX], char provider_out[64],
    char model_out[128])
{
    const struct json_value *sess = json_get(result, "session");
    const struct json_value *sid =
        sess ? json_get(sess, "sessionId") : NULL;
    if (!(sid && sid->type == JSON_STR && ms_copy_str(session_id,
            MUSE_SESSION_ID_MAX, json_get_str(sid)))) {
        ms_fail(s, "internal", false, "session/start hid the session id");
        return false;
    }
    memcpy(s->workspace, workspace_root, ws + 1);
    const struct json_value *prov =
        sess ? json_get(sess, "providerId") : NULL;
    const struct json_value *model = sess ? json_get(sess, "modelId")
                                          : NULL;
    if (provider_out)
        (void)ms_copy_str(provider_out, 64,
            prov && prov->type == JSON_STR ? json_get_str(prov) : "");
    if (model_out)
        (void)ms_copy_str(model_out, 128,
            model && model->type == JSON_STR ? json_get_str(model) : "");
    return true;
}

/* The authorizing task names the model; anything else keeps the host
 * default. A rejected selection fails the start loudly. */
static bool ms_start_set_model(struct muse_session *s,
    const char *session_id, const char *model)
{
    char mc[MUSE_COMMAND_ID_MAX];
    if (!muse_session_command_id(mc)) {
        ms_fail(s, "internal", false, "command id unavailable");
        return false;
    }
    struct json_value mp = {0}, selection = {0};
    json_init(&mp);
    json_init(&selection);
    json_set_object(&mp);
    json_set_object(&selection);
    bool ok = json_push_kv_str(&selection, "modelId", model) &&
        json_push_kv_str(&mp, "sessionId", session_id) &&
        json_push_kv(&mp, "model", &selection) &&
        json_push_kv_str(&mp, "commandId", mc);
    json_free(&selection);
    char *mtext = ms_render_params(s, &mp, ok);
    if (!mtext) return false;
    int mid = s->next_id++;
    ok = ms_send(s, mid, "session/setModel", mtext);
    free(mtext);
    if (ok) {
        char *mline =
            ms_await(s, mid, ms_monotonic_ms() + s->open_timeout_ms);
        struct json_value mdoc = {0};
        ok = mline && ms_split(s, mline, NULL, &mdoc);
        free(mline);
        json_free(&mdoc);
    }
    return ok;
}

int muse_session_start(struct muse_session *s, const char *command_id,
    const char *workspace_root, const struct muse_session_policy *policy,
    char session_id[MUSE_SESSION_ID_MAX],
    char provider_out[64], char model_out[128])
{
    if (!s || !command_id || !workspace_root || !session_id)
        return -1;
    const char *mode = ms_approval_mode(policy);
    if (!ms_start_mode_ok(s, mode)) return -1;
    size_t ws = strlen(workspace_root);
    if (!ms_start_workspace_ok(s, workspace_root, ws)) return -1;
    char *text = ms_start_params(s, command_id, workspace_root, mode);
    struct json_value doc = {0};
    const struct json_value *result = NULL;
    char *line = ms_call(s, "session/start", text, &result, &doc);
    if (!line) return -1;
    bool ok = ms_start_identity(s, result, workspace_root, ws, session_id,
        provider_out, model_out);
    free(line);
    json_free(&doc);
    if (ok && policy && policy->model && policy->model[0])
        ok = ms_start_set_model(s, session_id, policy->model);
    return ok ? 0 : -1;
}

/* turn/start params: one text input part carrying the prompt. */
static char *ms_turn_params(struct muse_session *s, const char *command_id,
    const char *session_id, const char *prompt)
{
    struct json_value params = {0}, input = {0}, part = {0};
    json_init(&params);
    json_init(&input);
    json_init(&part);
    json_set_object(&params);
    json_set_array(&input);
    json_set_object(&part);
    bool ok = json_push_kv_str(&part, "type", "text") &&
        json_push_kv_str(&part, "text", prompt) &&
        json_push_back(&input, &part) &&
        json_push_kv_str(&params, "commandId", command_id) &&
        json_push_kv_str(&params, "sessionId", session_id) &&
        json_push_kv(&params, "input", &input);
    json_free(&part);
    json_free(&input);
    return ms_render_params(s, &params, ok);
}

int muse_session_turn(struct muse_session *s, const char *command_id,
    const char *session_id, const char *prompt,
    char turn_id[MUSE_TURN_ID_MAX])
{
    if (!s || !command_id || !session_id || !prompt || !turn_id) return -1;
    if (s->usage_unresolved) {
        ms_fail(s, "usageMismatch", false,
            "session usage is unresolved; further turns are refused");
        return -1;
    }
    if (s->max_total_tokens > 0 && s->tokens_used >= s->max_total_tokens) {
        ms_fail(s, "tokenBudget", false,
            "token budget spent: %llu of %llu",
            (unsigned long long)s->tokens_used,
            (unsigned long long)s->max_total_tokens);
        return -1;
    }
    char *text = ms_turn_params(s, command_id, session_id, prompt);
    struct json_value doc = {0};
    const struct json_value *result = NULL;
    char *line = ms_call(s, "turn/start", text, &result, &doc);
    if (!line) return -1;
    const struct json_value *tid = json_get(result, "turnId");
    bool ok = tid && tid->type == JSON_STR &&
        ms_copy_str(turn_id, MUSE_TURN_ID_MAX, json_get_str(tid));
    if (!ok)
        ms_fail(s, "internal", false, "turn/start hid the turn id");
    free(line);
    json_free(&doc);
    return ok ? 0 : -1;
}


void muse_turn_outcome_free(struct muse_turn_outcome *out)
{
    if (!out) return;
    free(out->text);
    out->text = NULL;
}

pid_t muse_session_host_pid(const struct muse_session *s)
{
    return s ? s->child : -1;
}

#endif /* !_WIN32 */
