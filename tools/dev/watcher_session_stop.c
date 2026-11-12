/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Drive dev begin/status/stop against recorded watcher stand-ins.
 *          A launch refuses beside a killed watcher's surviving worker, a
 *          bound stop leaves no process of the session, and a leaderless
 *          session is retired only by its exact birth. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "watcher_session_stop.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum { WSS_HOLD = 8, WSS_OUT = 65536 };

struct wss_hold {
    long pid;
};

struct wss_run {
    char scratch[1024];
    char holder[1100];
    char session[80];
    const char *bin;
    long pid;
    long worker;
    unsigned long long born;
    struct wss_hold hold[WSS_HOLD];
    char endpoint[WSS_HOLD][320];
    int nhold;
    int nend;
};

static struct wss_run g;
static char g_out[WSS_OUT];

static int wss_fail(const char *msg)
{
    fprintf(stderr, "watcher session selftest: %s\n", msg);
    return 1;
}

static int wss_fail_out(const char *prefix, const char *detail)
{
    fprintf(stderr, "watcher session selftest: %s: %s\n", prefix,
            detail == NULL ? "" : detail);
    return 1;
}

static int wss_join(char *out, size_t cap, const char *a, const char *b)
{
    int n = snprintf(out, cap, "%s%s", a, b);
    if (n < 0 || (size_t)n >= cap)
        return -1;
    return 0;
}

static void wss_reap_quiet(pid_t child)
{
    int status = 0;
    if (child <= 0)
        return;
    while (waitpid(child, &status, 0) < 0 && errno == EINTR)
        ;
}

static int wss_rm(const char *path)
{
    char *argv[] = {"rm", "-rf", "--", (char *)path, NULL};
    pid_t child = fork();
    if (child < 0)
        return -1;
    if (child == 0) {
        execvp(argv[0], argv);
        _exit(127);
    }
    wss_reap_quiet(child);
    return 0;
}

static void wss_cleanup(void)
{
    int i;
    for (i = 0; i < g.nhold; i++) {
        if (g.hold[i].pid > 1)
            kill(-g.hold[i].pid, SIGKILL);
    }
    for (i = 0; i < g.nend; i++)
        unlink(g.endpoint[i]);
    if (g.scratch[0] != '\0')
        wss_rm(g.scratch);
    g.scratch[0] = '\0';
    g.nhold = 0;
    g.nend = 0;
}

static int wss_read(const char *path, char *buf, size_t cap)
{
    FILE *fp = fopen(path, "r");
    size_t n;
    if (fp == NULL || cap < 2)
        return -1;
    n = fread(buf, 1, cap - 1, fp);
    fclose(fp);
    buf[n] = '\0';
    return 0;
}

static int wss_alive(long pid)
{
    char path[64];
    char line[4096];
    if (snprintf(path, sizeof path, "/proc/%ld/stat", pid) >= (int)sizeof path)
        return 0;
    if (wss_read(path, line, sizeof line) != 0)
        return 0;
    return strstr(line, ") Z ") == NULL;
}

static int wss_gone(long pid)
{
    struct timespec pause = {.tv_nsec = 10000000L};
    int i;
    for (i = 0; i < 300; i++) {
        if (!wss_alive(pid))
            return 0;
        nanosleep(&pause, NULL);
    }
    return 1;
}

static int wss_field(const char *text, int index, char *out, size_t cap)
{
    int i = 0;
    size_t n;
    while (*text == ' ')
        text++;
    while (i < index) {
        text = strchr(text, ' ');
        if (text == NULL)
            return -1;
        text++;
        i++;
    }
    n = strcspn(text, " \n");
    if (n == 0 || n + 1 > cap)
        return -1;
    memcpy(out, text, n);
    out[n] = '\0';
    return 0;
}

static int wss_members(long sid)
{
    DIR *dir = opendir("/proc");
    struct dirent *ent;
    char want[32];
    int count = 0;
    if (dir == NULL)
        return -1;
    snprintf(want, sizeof want, "%ld", sid);
    while ((ent = readdir(dir)) != NULL) {
        char path[64];
        char line[4096];
        char state[8];
        char got[32];
        const char *rest;
        if (ent->d_name[0] < '1' || ent->d_name[0] > '9')
            continue;
        if (snprintf(path, sizeof path, "/proc/%s/stat", ent->d_name) >=
            (int)sizeof path)
            continue;
        if (wss_read(path, line, sizeof line) != 0)
            continue;
        rest = strrchr(line, ')');
        if (rest == NULL || rest[1] != ' ')
            continue;
        if (wss_field(rest + 2, 0, state, sizeof state) != 0)
            continue;
        if (wss_field(rest + 2, 3, got, sizeof got) != 0)
            continue;
        if (strcmp(got, want) == 0 && strcmp(state, "Z") != 0)
            count++;
    }
    closedir(dir);
    return count;
}

static int wss_scratch(void)
{
    char tmpl[PATH_MAX];
    char resolved[PATH_MAX];
    const char *tmp = getenv("TMPDIR");
    if (tmp == NULL || tmp[0] == '\0')
        tmp = "/tmp";
    if (snprintf(tmpl, sizeof tmpl, "%s/z23-watch-session.XXXXXX", tmp) >=
        (int)sizeof tmpl)
        return -1;
    if (mkdtemp(tmpl) == NULL)
        return -1;
    if (realpath(tmpl, resolved) == NULL ||
        strlen(resolved) + 1 > sizeof g.scratch) {
        wss_rm(tmpl);
        return -1;
    }
    memcpy(g.scratch, resolved, strlen(resolved) + 1);
    return 0;
}

static int wss_root(const char *name, char *out, size_t cap)
{
    char path[1100];
    int fd;
    if (snprintf(out, cap, "%s/%s", g.scratch, name) >= (int)cap)
        return -1;
    if (mkdir(out, 0700) != 0)
        return -1;
    if (snprintf(path, sizeof path, "%s/.cache", out) >= (int)sizeof path)
        return -1;
    if (mkdir(path, 0700) != 0 && errno != EEXIST)
        return -1;
    if (chmod(path, 0700) != 0)
        return -1;
    if (snprintf(path, sizeof path, "%s/Makefile", out) >= (int)sizeof path)
        return -1;
    fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0)
        return -1;
    close(fd);
    return 0;
}

static int wss_compile(const char *fixture)
{
    char *argv[] = {"cc", "-std=c23", "-O2", "-Wall", "-Wextra", "-Werror",
                    "-pedantic", (char *)fixture, "-o", g.holder, NULL};
    pid_t child = fork();
    int status = 0;
    if (child < 0)
        return 127;
    if (child == 0) {
        execvp(argv[0], argv);
        _exit(127);
    }
    while (waitpid(child, &status, 0) < 0 && errno == EINTR)
        ;
    if (!WIFEXITED(status))
        return 1;
    return WEXITSTATUS(status);
}

static int wss_ready(const char *path)
{
    FILE *fp = fopen(path, "r");
    char session[80];
    int n;
    if (fp == NULL)
        return -1;
    n = fscanf(fp, "%ld %ld %llu %79s", &g.pid, &g.worker, &g.born, session);
    fclose(fp);
    if (n != 4)
        return -1;
    memcpy(g.session, session, strlen(session) + 1);
    return 0;
}

static int wss_note_holder(void)
{
    char endp[320];
    int n;
    if (g.nhold >= WSS_HOLD || g.nend >= WSS_HOLD)
        return -1;
    g.hold[g.nhold].pid = g.pid;
    g.nhold++;
    n = snprintf(endp, sizeof endp, "/tmp/z23-watch-stop-%lu-%s",
                 (unsigned long)geteuid(), g.session);
    if (n < 0 || (size_t)n >= sizeof endp)
        return -1;
    memcpy(g.endpoint[g.nend], endp, (size_t)n + 1);
    g.nend++;
    return 0;
}

static int wss_wait_ready(const char *ready)
{
    struct timespec pause = {.tv_nsec = 10000000L};
    struct stat st;
    int i;
    for (i = 0; i < 300; i++) {
        if (stat(ready, &st) == 0 && st.st_size > 0)
            return 0;
        nanosleep(&pause, NULL);
    }
    return -1;
}

static int wss_start(const char *mode, const char *root)
{
    char ready[1100];
    char why[80];
    pid_t child;
    if (snprintf(ready, sizeof ready, "%s/holder.ready", root) >= (int)sizeof ready)
        return wss_fail("ready path does not fit");
    unlink(ready);
    child = fork();
    if (child < 0)
        return wss_fail("could not fork the holder");
    if (child == 0) {
        pid_t holder = fork();
        if (holder != 0)
            _exit(holder < 0 ? 127 : 0);
        if (chdir(root) != 0)
            _exit(127);
        execl(g.holder, g.holder, mode, root, ready, (char *)NULL);
        _exit(127);
    }
    wss_reap_quiet(child);
    if (wss_wait_ready(ready) != 0) {
        snprintf(why, sizeof why, "%s holder did not become ready", mode);
        return wss_fail(why);
    }
    if (wss_ready(ready) != 0)
        return wss_fail("holder ready file is unreadable");
    if (wss_note_holder() != 0)
        return wss_fail("too many holders");
    return 0;
}

static void wss_child_env(const char *root, const char *stall)
{
    if (setenv("HOME", g.scratch, 1) != 0)
        _exit(127);
    if (setenv("ZCL_DEV_SOURCE_ROOT", root, 1) != 0)
        _exit(127);
    if (stall == NULL)
        return;
    if (setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1) != 0)
        _exit(127);
    if (setenv("ZCL_DEVLOOP_TEST_WATCH_STALL", stall, 1) != 0)
        _exit(127);
}

static void wss_drain(int fd)
{
    char junk[1024];
    for (;;) {
        ssize_t n = read(fd, junk, sizeof junk);
        if (n == 0)
            return;
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0)
            return;
    }
}

static int wss_capture(const char *root, const char *stall, char *const argv[])
{
    int fds[2];
    pid_t child;
    size_t used = 0;
    if (pipe(fds) != 0)
        return wss_fail("could not capture the dev binary");
    fflush(stdout);
    fflush(stderr);
    child = fork();
    if (child < 0) {
        close(fds[0]);
        close(fds[1]);
        return wss_fail("could not run the dev binary");
    }
    if (child == 0) {
        if (chdir(root) != 0)
            _exit(127);
        wss_child_env(root, stall);
        if (dup2(fds[1], STDOUT_FILENO) < 0 || dup2(fds[1], STDERR_FILENO) < 0)
            _exit(127);
        close(fds[0]);
        close(fds[1]);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(fds[1]);
    while (used + 1 < sizeof g_out) {
        ssize_t n = read(fds[0], g_out + used, sizeof g_out - 1 - used);
        if (n == 0)
            break;
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0)
            break;
        used += (size_t)n;
    }
    g_out[used] = '\0';
    wss_drain(fds[0]);
    close(fds[0]);
    wss_reap_quiet(child);
    return 0;
}

static int wss_evidence(const char *text)
{
    const char *mark = "\"evidence\":\"";
    const char *tail = "/native-watch.log";
    const char *start = strstr(text, mark);
    const char *end;
    size_t n;
    if (start == NULL)
        return 0;
    start += strlen(mark);
    end = strchr(start, '"');
    if (end == NULL)
        return 0;
    n = strlen(tail);
    return (size_t)(end - start) >= n && memcmp(end - n, tail, n) == 0;
}

static void wss_dev(char **argv, const char *verb, const char *noun, char *input)
{
    argv[0] = (char *)g.bin;
    argv[1] = "dev";
    argv[2] = (char *)verb;
    argv[3] = (char *)noun;
    argv[4] = input;
    argv[5] = NULL;
}

static int wss_orphan_begin(const char *root)
{
    char input[1200];
    char *argv[6];
    if (wss_start("orphan", root) != 0)
        return 1;
    if (kill(g.pid, SIGKILL) != 0 && errno != ESRCH)
        return wss_fail("could not kill the orphan leader");
    if (wss_gone(g.pid) != 0)
        return wss_fail("orphan leader did not die");
    if (snprintf(input, sizeof input, "--input={\"root\":\"%s\"}", root) >=
        (int)sizeof input)
        return wss_fail("begin input does not fit");
    wss_dev(argv, "begin", input, NULL);
    if (wss_capture(root, NULL, argv) != 0)
        return 1;
    if (strstr(g_out, "\"WATCHER_RETIRING\"") == NULL)
        return wss_fail_out("begin beside an orphan", g_out);
    if (!wss_alive(g.worker))
        return wss_fail("begin touched the orphaned worker");
    return 0;
}

static int wss_orphan_status(const char *root)
{
    char needle[80];
    char *argv[6];
    wss_dev(argv, "loop", "status", NULL);
    if (wss_capture(root, NULL, argv) != 0)
        return 1;
    snprintf(needle, sizeof needle, "\"pid\":%ld,\"born\":%llu", g.pid, g.born);
    if (strstr(g_out, needle) == NULL)
        return wss_fail_out("status does not list the orphan", g_out);
    return 0;
}

static int wss_one_stop(const char *root, const char *born_text, const char *needle,
                        const char *why)
{
    char input[1200];
    char *argv[6];
    if (snprintf(input, sizeof input,
                 "--input={\"watcher_id\":%ld,\"watcher_born\":%s}", g.pid,
                 born_text) >= (int)sizeof input)
        return wss_fail("stop input does not fit");
    wss_dev(argv, "loop", "stop", input);
    if (wss_capture(root, NULL, argv) != 0)
        return 1;
    if (strstr(g_out, needle) == NULL)
        return wss_fail_out(why, g_out);
    return 0;
}

static int wss_orphan(const char *root)
{
    char born_text[32];
    if (wss_orphan_begin(root) != 0)
        return 1;
    if (wss_orphan_status(root) != 0)
        return 1;
    snprintf(born_text, sizeof born_text, "%llu", g.born + 1);
    if (wss_one_stop(root, born_text, "\"WATCHER_ID_MISMATCH\"",
                     "another birth accepted") != 0)
        return 1;
    if (!wss_alive(g.worker))
        return wss_fail("a refused stop signalled the worker");
    snprintf(born_text, sizeof born_text, "%llu", g.born);
    if (wss_one_stop(root, born_text, "\"session_retired\":\"retired\"",
                     "orphan not retired") != 0)
        return 1;
    if (wss_gone(g.worker) != 0)
        return wss_fail("orphaned worker survived its stop");
    return 0;
}

static int wss_bound(const char *root)
{
    char input[1200];
    char *argv[6];
    if (wss_start("fifo", root) != 0)
        return 1;
    if (snprintf(input, sizeof input,
                 "--input={\"watcher_id\":%ld,\"watcher_session\":\"%s\"}",
                 g.pid, g.session) >= (int)sizeof input)
        return wss_fail("bound stop input does not fit");
    argv[0] = (char *)g.bin;
    argv[1] = "dev";
    argv[2] = "loop";
    argv[3] = "stop";
    argv[4] = input;
    argv[5] = NULL;
    if (wss_capture(root, NULL, argv) != 0)
        return 1;
    if (strstr(g_out, "\"stopped\":true") == NULL)
        return wss_fail_out("bound stop failed", g_out);
    if (strstr(g_out, "\"session_retired\":\"retired\"") == NULL)
        return wss_fail_out("leaked worker not retired", g_out);
    if (wss_gone(g.pid) != 0)
        return wss_fail("leader survived its stop");
    if (wss_gone(g.worker) != 0)
        return wss_fail("worker survived its session stop");
    return 0;
}

static int wss_stall(const char *root)
{
    char input[1200];
    char stall[1100];
    char record[1200];
    char *argv[5];
    long pid = 0;
    long worker = 0;
    int members;
    FILE *fp;
    if (snprintf(stall, sizeof stall, "%s/stall.pids", root) >= (int)sizeof stall)
        return wss_fail("stall path does not fit");
    if (snprintf(input, sizeof input, "--input={\"root\":\"%s\"}", root) >=
        (int)sizeof input)
        return wss_fail("stall input does not fit");
    argv[0] = (char *)g.bin;
    argv[1] = "dev";
    argv[2] = "begin";
    argv[3] = input;
    argv[4] = NULL;
    if (wss_capture(root, stall, argv) != 0)
        return 1;
    if (strstr(g_out, "\"WATCH_START_FAILED\"") == NULL)
        return wss_fail_out("stalled begin", g_out);
    if (!wss_evidence(g_out))
        return wss_fail_out("failed begin did not retire its watcher", g_out);
    fp = fopen(stall, "r");
    if (fp == NULL)
        return wss_fail("stalled watcher did not report");
    if (fscanf(fp, "%ld %ld", &pid, &worker) != 2) {
        fclose(fp);
        return wss_fail("stalled watcher did not report");
    }
    fclose(fp);
    (void)worker;
    members = wss_members(pid);
    if (members != 0) {
        if (g.nhold < WSS_HOLD) {
            g.hold[g.nhold].pid = pid;
            g.nhold++;
        }
        fprintf(stderr,
                "watcher session selftest: failed begin left its watcher "
                "session running (watcher %ld)\n",
                pid);
        return 1;
    }
    if (snprintf(record, sizeof record, "%s/.cache/zcl-dev-watch.d/%ld", root,
                 pid) >= (int)sizeof record)
        return wss_fail("launch record path does not fit");
    if (access(record, F_OK) == 0) {
        fprintf(stderr,
                "watcher session selftest: failed begin left its launch "
                "record (watcher %ld)\n",
                pid);
        return 1;
    }
    return 0;
}

static int wss_paths(const char *repo, const char *bin, const char *fixture,
                     const char **bin_out, const char **fixture_out)
{
    static char def_bin[1100];
    static char def_fix[1100];
    if (bin == NULL || bin[0] == '\0') {
        if (repo == NULL || wss_join(def_bin, sizeof def_bin, repo,
                                     "/build/bin/z23-dev") != 0)
            return -1;
        bin = def_bin;
    }
    if (fixture == NULL || fixture[0] == '\0') {
        if (repo == NULL || wss_join(def_fix, sizeof def_fix, repo,
                                     "/tools/dev/fixtures/watcher_session_holder.c") != 0)
            return -1;
        fixture = def_fix;
    }
    *bin_out = bin;
    *fixture_out = fixture;
    return 0;
}

static int wss_go(const char *bin, const char *fixture)
{
    char begin_root[1100];
    char stop_root[1100];
    char stall_root[1100];
    memset(&g, 0, sizeof g);
    if (access(bin, X_OK) != 0) {
        fprintf(stderr, "missing dev binary: %s\n", bin);
        return 2;
    }
    if (wss_scratch() != 0)
        return wss_fail("could not make a scratch directory");
    if (wss_join(g.holder, sizeof g.holder, g.scratch, "/z23-dev") != 0) {
        wss_cleanup();
        return wss_fail("holder path does not fit");
    }
    {
        int built = wss_compile(fixture);
        if (built != 0) {
            wss_cleanup();
            return built;
        }
    }
    g.bin = bin;
    if (wss_root("begin", begin_root, sizeof begin_root) != 0 ||
        wss_orphan(begin_root) != 0) {
        wss_cleanup();
        return 1;
    }
    if (wss_root("stop", stop_root, sizeof stop_root) != 0 ||
        wss_bound(stop_root) != 0) {
        wss_cleanup();
        return 1;
    }
    if (wss_root("stall", stall_root, sizeof stall_root) != 0 ||
        wss_stall(stall_root) != 0) {
        wss_cleanup();
        return 1;
    }
    printf("watcher session stop: begin refuses beside an orphan; "
           "orphan retired only by its birth; bound stop leaves no process; "
           "failed begin leaves no watcher\n");
    wss_cleanup();
    return 0;
}

#endif /* !_WIN32 */

int zcl_watcher_session_stop(const char *repo, const char *bin,
                             const char *fixture)
{
#if defined(_WIN32)
    (void)repo;
    (void)bin;
    (void)fixture;
    fputs("watcher session selftest: unavailable on Windows\n", stdout);
    return 2;
#else
    const char *use_bin = NULL;
    const char *use_fix = NULL;
    if (wss_paths(repo, bin, fixture, &use_bin, &use_fix) != 0) {
        fprintf(stderr, "watcher session selftest: repo is required\n");
        return 2;
    }
    return wss_go(use_bin, use_fix);
#endif
}
