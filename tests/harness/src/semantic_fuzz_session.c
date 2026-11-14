/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Bounded test-only client for one persistent cold sensor session. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#include "test/semantic_fuzz_session.h"
#include "semantic_fuzz_case_priv.h"
#include "base/hex.h"
#include "json/json.h"
#include "platform/clock.h"
#include "vcs/semantic_manifest.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#define SFZ_SESSION_REQUEST_MAX (256u * 1024u)
#if defined(__linux__)
#include <sys/prctl.h>
#endif

static bool ss_pipe(int fd[2])
{
    if (pipe(fd)) return false;
    if (fcntl(fd[0], F_SETFD, FD_CLOEXEC) || fcntl(fd[1], F_SETFD, FD_CLOEXEC)) {
        close(fd[0]); close(fd[1]); return false;
    }
    return true;
}
static void ss_child(int in[2], int out[2], const char *binary, const char *cwd,
                     const char *const *env, const char *log, pid_t parent)
{
#if defined(__linux__)
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent) _exit(125);
#else
    (void)parent;
#endif
    int fd = open(log, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0 || dup2(in[0], 0) < 0 || dup2(out[1], 1) < 0 || dup2(fd, 2) < 0 || chdir(cwd)) _exit(126);
    close(in[0]); close(in[1]); close(out[0]); close(out[1]); close(fd);
    const char *argv[] = {binary, "session", "--no-warm", NULL};
    execve(binary, (char *const *)argv, (char *const *)env); _exit(127);
}
static void ss_close_peers(const struct sfz_session *peers)
{
    for (int i = 0; i < 2; ++i) if (peers[i].pid > 0) {
        close(peers[i].input); close(peers[i].output); close(peers[i].owner);
    }
}
static void ss_guard_reap(pid_t child)
{
    (void)kill(child, SIGKILL);
    int64_t now = clock_now_monotonic_ns(), until = now > 0 ? now + 1000000000 : 0;
    pid_t got = 0; int st;
    while (got == 0 && now > 0 && now < until) {
        do { got = waitpid(child, &st, WNOHANG); } while (got < 0 && errno == EINTR);
        if (!got) (void)poll(NULL, 0, 10);
        now = clock_now_monotonic_ns();
    }
}
static void ss_guard_loop(pid_t child, int owner)
{
    int st; pid_t got = 0;
    while (got == 0) {
        if (owner < 0) break;
        struct pollfd p = {.fd = owner, .events = POLLIN};
        int rc = poll(&p, 1, 100);
        if (rc > 0 || (rc < 0 && errno != EINTR)) break;
        do { got = waitpid(child, &st, WNOHANG); } while (got < 0 && errno == EINTR);
    }
    if (got == 0) ss_guard_reap(child);
    close(owner);
    (void)kill(-getpgrp(), SIGKILL); _exit(1);
}
static void ss_guard(int in[2], int out[2], int owner[2], int ack[2],
                     const struct sfz_session *peers, const char *binary,
                     const char *cwd, const char *const *env, const char *log, int outcome_fd)
{
    (void)signal(SIGPIPE, SIG_IGN);
    if (outcome_fd > 2) close(outcome_fd);
    close(owner[1]); close(ack[0]); ss_close_peers(peers);
    if (setpgid(0, 0) != 0) _exit(125);
    pid_t parent = getpid(), child = fork();
    if (!child) { close(owner[0]); close(ack[1]); (void)signal(SIGPIPE, SIG_DFL); ss_child(in, out, binary, cwd, env, log, parent); }
    close(in[0]); close(in[1]); close(out[0]); close(out[1]);
    if (child < 0) _exit(125);
    bool acked = write(ack[1], "1", 1) == 1; close(ack[1]);
    if (!acked) { close(owner[0]); ss_guard_loop(child, -1); }
    close(0); close(1); close(2);
    ss_guard_loop(child, owner[0]);
}
static bool ss_wait(int fd, short events, int64_t deadline);
/* 1 reaped, 0 deadline, -1 clock or wait failure. */
static int ss_reap(pid_t pid, int64_t duration)
{
    int64_t now = clock_now_monotonic_ns(), until = now > 0 ? now + duration : 0;
    while (now > 0 && now < until) {
        int st; pid_t got = waitpid(pid, &st, WNOHANG);
        if (got == pid) return 1;
        if (got < 0 && errno != EINTR) return -1;
        (void)poll(NULL, 0, 10); now = clock_now_monotonic_ns();
    }
    return now > 0 ? 0 : -1;
}
bool sfz_session_start(struct sfz_session *s, const struct sfz_session *peers, const char *binary, const char *cwd,
                       const char *const *env, const char *log, int64_t deadline, int outcome_fd)
{
    int in[2], out[2], owner[2], ack[2];
    if (!ss_pipe(in)) return false;
    if (!ss_pipe(out)) { close(in[0]); close(in[1]); return false; }
    if (!ss_pipe(owner)) { close(in[0]); close(in[1]); close(out[0]); close(out[1]); return false; }
    if (!ss_pipe(ack)) { close(in[0]); close(in[1]); close(out[0]); close(out[1]); close(owner[0]); close(owner[1]); return false; }
    pid_t pid = fork();
    if (!pid) ss_guard(in, out, owner, ack, peers, binary, cwd, env, log, outcome_fd);
    close(in[0]); close(out[1]); close(owner[0]); close(ack[1]);
    if (pid < 0) { close(in[1]); close(out[0]); close(owner[1]); close(ack[0]); return false; }
    s->pid = pid; s->input = in[1]; s->output = out[0]; s->owner = owner[1]; s->seq = 0; s->busy = false;
    if (setpgid(pid, pid) != 0 && getpgid(pid) != pid) {
        (void)kill(pid, SIGKILL);
        if (ss_reap(pid, 2000000000) == 1) s->pid = 0;
        else fprintf(stderr, "sfz session: startup guard unreaped pid=%ld\n", (long)pid);
        close(s->input); close(s->output); close(s->owner); close(ack[0]);
        s->input = s->output = s->owner = -1; return false;
    }
    char ready = 0;
    bool ok = ss_wait(ack[0], POLLIN, deadline) && read(ack[0], &ready, 1) == 1 && ready == '1';
    close(ack[0]); if (!ok) (void)sfz_session_stop(s); return ok;
}
bool sfz_session_stop(struct sfz_session *s)
{
    if (s->pid <= 0) return true;
    if (s->input >= 0) close(s->input);
    if (s->output >= 0) close(s->output);
    if (s->owner >= 0) close(s->owner);
    s->input = s->output = s->owner = -1;
    int reaped = ss_reap(s->pid, 2000000000);
    if (reaped == 0) { (void)kill(-s->pid, SIGKILL); (void)kill(s->pid, SIGKILL); reaped = ss_reap(s->pid, 2000000000); }
    if (reaped != 1) { fprintf(stderr, "sfz session: guard unreaped pid=%ld\n", (long)s->pid); return false; }
    s->pid = 0; s->busy = false; return true;
}
static bool ss_wait(int fd, short events, int64_t deadline)
{
    for (;;) {
        int64_t now = clock_now_monotonic_ns();
        if (now <= 0 || now >= deadline) { fputs("sfz session: deadline or clock failure\n", stderr); return false; }
        int64_t left = (deadline - now + 999999) / 1000000;
        struct pollfd p = {.fd = fd, .events = events};
        int rc = poll(&p, 1, left > 1000 ? 1000 : (int)left);
        if (rc > 0) return (p.revents & events) != 0 && !(p.revents & (POLLERR | POLLNVAL));
        if (rc < 0 && errno != EINTR) return false;
    }
}
static bool ss_write(int fd, const char *p, size_t n, int64_t deadline)
{
    while (n) {
        if (!ss_wait(fd, POLLOUT, deadline)) return false;
        ssize_t k = write(fd, p, n);
        if (k < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (k <= 0) return false;
        p += k; n -= (size_t)k;
    }
    return true;
}
static bool ss_reply(int fd, char *out, size_t cap, int64_t deadline)
{
    size_t n = 0;
    while (n + 1 < cap) {
        if (!ss_wait(fd, POLLIN, deadline)) return false;
        ssize_t k = read(fd, out + n, 1);
        if (k < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (k != 1 || out[n] == '\0') return false;
        if (out[n++] == '\n') { out[n] = '\0'; return true; }
    }
    return false;
}

static bool ss_no_pending(int fd)
{
    struct pollfd p = {.fd = fd, .events = POLLIN};
    int rc;
    do { rc = poll(&p, 1, 0); } while (rc < 0 && errno == EINTR);
    return rc == 0;
}
static bool ss_unique(const struct json_value *v)
{
    for (size_t i = 0; i < v->num_children; ++i) {
        if (!ss_unique(&v->children[i])) return false;
        if (v->type == JSON_OBJ)
            for (size_t j = 0; j < i; ++j) if (!strcmp(v->keys[i], v->keys[j])) return false;
    }
    return true;
}
static bool ss_string(const struct json_value *v, const char *want)
{ return v && v->type == JSON_STR && !strcmp(json_get_str(v), want); }
static bool ss_manifest(const struct json_value *v, const char *path)
{
    struct stat st; uint8_t *bytes = NULL, root[32]; size_t n = 0; char hex[65], why[128];
    const struct json_value *count = json_get(v, "bytes");
    bool ok = count && count->type == JSON_INT && json_get_int(count) > 0 &&
        stat(path, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0 &&
        (uint64_t)st.st_size <= VCS_SEMANTIC_MANIFEST_V1_MAX_BYTES &&
        (int64_t)st.st_size == json_get_int(count) && sfz_slurp(path, &bytes, &n) &&
        n == (size_t)st.st_size && vcs_semantic_root_v1(bytes, n, root, why, sizeof(why));
    if (ok) { zcl_hex_encode(root, 32, hex); ok = ss_string(json_get(v, "root"), hex); }
    free(bytes); return ok;
}
static bool ss_validate(const char *line, const char *source, const char *out, unsigned seq)
{
    struct json_value v; json_init(&v);
    bool ok = !strstr(line, "\\u0000") && json_read(&v, line, strlen(line)) && v.type == JSON_OBJ && ss_unique(&v);
    const struct json_value *n = json_get(&v, "seq"), *passed = json_get(&v, "ok");
    ok = ok && n && n->type == JSON_INT && json_get_int(n) == seq && passed &&
        passed->type == JSON_BOOL && json_get_bool(passed) &&
        ss_string(json_get(&v, "source"), source) && ss_string(json_get(&v, "out"), out) &&
        ss_string(json_get(&v, "written"), "cold") && ss_string(json_get(&v, "trust"), "cold") && ss_manifest(&v, out);
    json_free(&v); return ok;
}
bool sfz_session_exchange(struct sfz_session *s, const char *const *argv, unsigned seq, int64_t deadline)
{
    char request[SFZ_SESSION_REQUEST_MAX], reply[16384]; size_t used = 0;
    for (size_t i = 1; argv[i]; ++i) {
        size_t n = strlen(argv[i]);
        if (strpbrk(argv[i], "\t\r\n") || n + 2 > sizeof(request) - used) return false;
        if (i > 1) request[used++] = '\t';
        memcpy(request + used, argv[i], n); used += n;
    }
    request[used++] = '\n';
    if (fcntl(s->input, F_SETFL, O_NONBLOCK) || fcntl(s->output, F_SETFL, O_NONBLOCK)) return false;
    if (!ss_no_pending(s->output)) { fputs("sfz session: unexpected pending frame\n", stderr); return false; }
    if (!ss_write(s->input, request, used, deadline)) { fputs("sfz session: request write failed\n", stderr); return false; }
    if (!ss_reply(s->output, reply, sizeof(reply), deadline)) { fputs("sfz session: response incomplete\n", stderr); return false; }
    if (!ss_no_pending(s->output) || !ss_validate(reply, argv[5], argv[7], seq)) {
        fputs("sfz session: response frame or manifest identity invalid\n", stderr); return false;
    }
    return true;
}
