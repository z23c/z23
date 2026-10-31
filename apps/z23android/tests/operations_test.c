/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "operations.h"
#include "params.h"
#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>

int __real_clock_gettime(clockid_t id, struct timespec *out);
int __wrap_clock_gettime(clockid_t id, struct timespec *out)
{
    if (getenv("ZAPP_TEST_CLOCK_FAIL")) return -1;
    return __real_clock_gettime(id, out);
}

extern char **environ;

/* The fixed entries the app gives the child: the drain budget, the page cache and TMPDIR. */
static bool child_fixed_environment(void)
{
    const char *batch = getenv("ZCL_CATCHUP_DRAIN_BUDGET_MS");
    if (!batch || strcmp(batch, "100")) return false;
    size_t cache_entries = 0;
    for (char **e = environ; *e; ++e)
        if (!strncmp(*e, "ZCL_BIP_PAGE_CACHE_KIB=", sizeof("ZCL_BIP_PAGE_CACHE_KIB=") - 1))
            ++cache_entries;
    const char *cache = getenv("ZCL_BIP_PAGE_CACHE_KIB");
    if (cache_entries != 1 || !cache || strcmp(cache, "32768")) return false;
    const char *temp = getenv("TMPDIR");
    return temp && !strcmp(temp, "/tmp/private-tmp");
}

/* The state root, and HOME: the parent's HOME when one is inherited, else the state root. */
/* Exactly one HOME= entry in the child environment, counted the way the fixed entries are. */
static bool single_home_entry(void)
{
    size_t home_entries = 0;
    for (char **e = environ; *e; ++e)
        if (!strncmp(*e, "HOME=", sizeof("HOME=") - 1)) ++home_entries;
    return home_entries == 1;
}

static bool child_root_environment(void)
{
    const char *state = getenv("XDG_STATE_HOME");
    const char *preserved = getenv("ZAPP_TEST_PRESERVED");
    const char *want = getenv("ZAPP_TEST_STATE");
    const char *home = getenv("HOME");
    const char *home_want = getenv("ZAPP_TEST_HOME");
    if (!single_home_entry() || !home || !want || strcmp(home, home_want ? home_want : want)) return false;
    return state && !strcmp(state, want) && preserved && !strcmp(preserved, "yes");
}

static bool child_environment(void)
{
    return child_fixed_environment() && child_root_environment();
}

static volatile sig_atomic_t interrupted;
static void on_interrupt(int signal) { (void)signal; interrupted = 1; }
/* A stand-in for a node left by an earlier app: "orphan" dies on SIGINT, "saving" takes a moment
 * to save after SIGINT, as a node does, and marks itself ready once it handles SIGINT. */
static int orphan(const char *mode, const char *data)
{
    alarm(30);
    sigset_t blocked, waiting;
    sigemptyset(&blocked); sigaddset(&blocked, SIGINT);
    if (sigprocmask(SIG_BLOCK, &blocked, &waiting)) return 6;
    sigdelset(&waiting, SIGINT);
    if (!strcmp(mode, "saving")) {
        char ready[300];
        signal(SIGINT, on_interrupt);
        snprintf(ready, sizeof(ready), "%s/ready", data + strlen("-datadir="));
        FILE *f = fopen(ready, "w");
        if (!f || fclose(f)) return 5;
    }
    while (!interrupted) sigsuspend(&waiting);
    struct timespec save = {.tv_sec = 2}; nanosleep(&save, NULL);
    return 0;
}

/* The node arguments the app builds. ZAPP_TEST_PARAMS_ARG is the one extra argument it must add;
 * "none" or unset means none. Returns 0 when they are right. */
static int node_arguments(int argc, char **argv)
{
    const char *want = getenv("ZAPP_TEST_PARAMS_ARG");
    bool with_params = want && strcmp(want, "none") != 0;
    if (strcmp(argv[2], "-operator-lane=canonical") || strcmp(argv[3], "-tor") ||
        strcmp(argv[4], "-onion-persist")) return 4;
    if (argc != (with_params ? 6 : 5) || (with_params && strcmp(argv[5], want) != 0)) return 7;
    return 0;
}

static int child(int argc, char **argv)
{
    if (!child_environment()) return 3;
    if ((argc == 5 || argc == 6) && !strncmp(argv[1], "-datadir=", 9)) {
        int bad = node_arguments(argc, argv);
        if (bad) return bad;
        puts("full node arguments accepted");
        return 0;
    }
    if (argc > 2 && strcmp(argv[1], "core") == 0 && strcmp(argv[2], "status") == 0) {
        for (int i = 0; i < 5000; ++i) putchar('x');
        return 0;
    }
    if (argc > 2 && strcmp(argv[1], "fleet") == 0 && strcmp(argv[2], "join") == 0) {
        char body[16384];
        size_t n = fread(body, 1, sizeof(body) - 1, stdin);
        body[n] = 0;
        if (!strstr(body, "\"token\":\"invitation\"")) return 1;
        puts("receipt");
        return 0;
    }
    return 2;
}

static void plain_text_tests(void)
{
    char failed[128] = "{\"ok\":false,\"error\":{\"code\":\"E\",\"message\":\"The manager is offline.\"}}";
    zapp_plain_text(failed, sizeof(failed));
    assert(!strcmp(failed, "The manager is offline."));
    char bare[64] = "{\"ok\":false}";
    zapp_plain_text(bare, sizeof(bare));
    assert(!strcmp(bare, "The command did not return a readable result."));
    char warned[160] = "warning: slow disk\n{\"ok\":false,\"error\":{\"message\":\"Join refused.\"}}";
    assert(zapp_json_object(warned) == strchr(warned, '{') && !zapp_json_object("Node starting."));
    zapp_plain_text(warned, sizeof(warned));
    assert(!strcmp(warned, "Join refused."));
    char words[32] = "Node starting.";
    zapp_plain_text(words, sizeof(words));
    assert(!strcmp(words, "Node starting."));
}

static pid_t spawn_orphan(const char *self, const char *first, const char *second, const char *pidfile)
{
    pid_t other = fork();
    assert(other >= 0);
    if (!other) {
        /* A non-interactive shell starts background jobs with SIGINT ignored, and exec keeps that. */
        if (signal(SIGINT, SIG_DFL) != SIG_ERR) execl(self, self, first, second, (char *)NULL);
        _exit(127);
    }
    FILE *f = fopen(pidfile, "w");
    assert(f && fprintf(f, "%d\n", (int)other) > 0 && fclose(f) == 0);
    return other;
}
static void await_exec(pid_t pid, const char *first)
{
    char file[64], args[256];
    snprintf(file, sizeof(file), "/proc/%d/cmdline", (int)pid);
    for (int i = 0; i < 500; ++i) {
        FILE *f = fopen(file, "r");
        size_t n = f ? fread(args, 1, sizeof(args) - 1, f) : 0;
        if (f) fclose(f);
        args[n] = 0;
        if (n > strlen(args) + 1 && !strcmp(args + strlen(args) + 1, first)) return;
        struct timespec pause = {.tv_nsec = 10000000}; nanosleep(&pause, NULL);
    }
    assert(!"the child never ran");
}
static void await_running(struct zapp_runtime *r)
{
    for (int i = 0; i < 500 && !zapp_node_running(r); ++i) {
        struct timespec pause = {.tv_nsec = 10000000}; nanosleep(&pause, NULL);
    }
    assert(zapp_node_running(r));
}
/* A node that takes time to save after SIGINT reads as stopping until it exits. */
static void saving_cases(struct zapp_runtime *r, const char *self, const char *data, const char *directory,
                         const char *pidfile)
{
    char ready[300], out[128];
    int status;
    assert(snprintf(ready, sizeof(ready), "%s/ready", directory) > 0);
    pid_t other = spawn_orphan(self, data, "saving", pidfile);
    for (int i = 0; i < 500 && access(ready, F_OK); ++i) {
        struct timespec pause = {.tv_nsec = 10000000}; nanosleep(&pause, NULL);
    }
    assert(unlink(ready) == 0 && zapp_node_running(r) && !zapp_node_stopping(r));
    assert(zapp_node_stop(r, out, sizeof(out)) && zapp_node_stopping(r));
    assert(waitpid(other, &status, 0) == other && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(!zapp_node_stopping(r));
}
/* A node left by an earlier app process is found through its pid file and its first argument. */
static void earlier_cases(struct zapp_runtime *r, const char *self, const char *directory)
{
    char data[300], pidfile[300], out[128];
    assert(snprintf(data, sizeof(data), "-datadir=%s", directory) > 0);
    assert(snprintf(pidfile, sizeof(pidfile), "%s/zclassic23.pid", directory) > 0);
    pid_t other = spawn_orphan(self, data, "orphan", pidfile);
    await_running(r);
    assert(!zapp_node_start(r, out, sizeof(out)) && !strcmp(out, "The local node is already running."));
    assert(zapp_node_stop(r, out, sizeof(out)) && !strcmp(out, "Node stopping. It saves its data first."));
    int status;
    assert(waitpid(other, &status, 0) == other && WIFSIGNALED(status) && WTERMSIG(status) == SIGINT);
    assert(!zapp_node_running(r) && !zapp_node_stopping(r));
    saving_cases(r, self, data, directory, pidfile);
    /* One of the app's own commands, -datadir last, under a pid the node file still names. */
    other = spawn_orphan(self, "command", data, pidfile);
    await_exec(other, "command");
    assert(!zapp_node_running(r));
    assert(kill(other, SIGINT) == 0 && waitpid(other, &status, 0) == other);
    FILE *f = fopen(pidfile, "w");
    assert(f && fprintf(f, "%d\n", (int)getpid()) > 0 && fclose(f) == 0);
    assert(!zapp_node_running(r) && unlink(pidfile) == 0);
}
/* With the owner's Start choice saved, the preview package still neither starts a node nor reads
 * the choice. */
static void preview_cases(struct zapp_runtime *r)
{
    char out[128];
    assert(zapp_node_wanted(r));
    r->preview = true;
    assert(!zapp_node_start(r, out, sizeof(out)) && strstr(out, "preview app does not run a node"));
    assert(!zapp_node_wanted(r) && r->node == 0);
    r->preview = false;
    assert(zapp_node_wanted(r));
}
static void command_cases(struct zapp_runtime *r)
{
    char out[128];
    assert(!zapp_operation_run(r, "not-allowed", out, sizeof(out)));
    assert(!zapp_operation_run(r, "fleet_doctor", out, sizeof(out)) && strstr(out, "not available"));
    assert(!zapp_operation_run(r, "status", out, sizeof(out)));
    assert(strstr(out, "[Output limit reached]"));
    assert(zapp_fleet_join_run(r, "invitation", out, sizeof(out)));
    assert(strstr(out, "receipt"));
    assert(strcmp(getenv("XDG_STATE_HOME"), "/tmp/parent-state") == 0);
    assert(strcmp(getenv("ZCL_CATCHUP_DRAIN_BUDGET_MS"), "77") == 0);
    assert(setenv("ZAPP_TEST_CLOCK_FAIL", "1", 1) == 0);
    assert(!zapp_operation_run(r, "status", out, sizeof(out)));
    assert(strstr(out, "timed out"));
    assert(unsetenv("ZAPP_TEST_CLOCK_FAIL") == 0);
}
/* Start records the owner's choice and Stop clears it; a choice that cannot be saved is reported. */
static void sized_file(const char *dir, int index, uint64_t size)
{
    char file[500];
    assert(snprintf(file, sizeof(file), "%s/%s", dir, zapp_param_files[index].name) > 0);
    int fd = open(file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    assert(fd >= 0 && ftruncate(fd, (off_t)size) == 0 && close(fd) == 0);
}
static void start_expecting(struct zapp_runtime *r, const char *argument)
{
    char out[128];
    int status;
    assert(setenv("ZAPP_TEST_PARAMS_ARG", argument, 1) == 0);
    assert(zapp_node_start(r, out, sizeof(out)));
    assert(waitpid(r->node, &status, 0) == r->node && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    r->node = 0;
}
/* The node gets -paramsdir only once both files of the pinned size are in files/params. */
static void params_argument_cases(struct zapp_runtime *r, const char *directory)
{
    char dir[400], file[500], expect[450];
    assert(snprintf(r->files, sizeof(r->files), "%s", directory) > 0);
    assert(snprintf(dir, sizeof(dir), "%s/params", directory) > 0 && mkdir(dir, 0700) == 0);
    start_expecting(r, "none");                                   /* no files */
    sized_file(dir, 0, zapp_param_files[0].size);
    start_expecting(r, "none");                                   /* one of two */
    sized_file(dir, 1, zapp_param_files[1].size - 1);
    start_expecting(r, "none");                                   /* wrong size */
    sized_file(dir, 1, zapp_param_files[1].size);
    assert(snprintf(expect, sizeof(expect), "-paramsdir=%s", dir) > 0);
    start_expecting(r, expect);                                   /* complete */
    for (int i = 0; i < ZAPP_PARAMS_COUNT; i++) {
        assert(snprintf(file, sizeof(file), "%s/%s", dir, zapp_param_files[i].name) > 0 && unlink(file) == 0);
    }
    assert(rmdir(dir) == 0);
    start_expecting(r, "none");
}
static void node_cases(struct zapp_runtime *r, const char *self, const char *directory)
{
    char out[128];
    assert(snprintf(r->directory, sizeof(r->directory), "%s", directory) > 0);
    assert(snprintf(r->state_root, sizeof(r->state_root), "%s/missing", directory) > 0);
    assert(setenv("ZAPP_TEST_STATE", r->state_root, 1) == 0);
    assert(zapp_node_start(r, out, sizeof(out)) && strstr(out, "could not save") && !zapp_node_wanted(r));
    int status;
    assert(waitpid(r->node, &status, 0) == r->node && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    r->node = 0;
    assert(snprintf(r->state_root, sizeof(r->state_root), "%s", directory) > 0);
    assert(setenv("ZAPP_TEST_STATE", r->state_root, 1) == 0);
    assert(!zapp_node_wanted(r));
    assert(zapp_node_start(r, out, sizeof(out)) && zapp_node_wanted(r));
    assert(waitpid(r->node, &status, 0) == r->node && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    r->node = 0;
    params_argument_cases(r, directory);
    preview_cases(r);
    assert(zapp_node_stop(r, out, sizeof(out)) && !strcmp(out, "The local node is stopped.") && !zapp_node_wanted(r));
    earlier_cases(r, self, directory);
}
static bool pace_file_is(const char *directory, const char *word)
{
    char file[300], got[16] = "";
    snprintf(file, sizeof(file), "%s/pace", directory);
    FILE *f = fopen(file, "r");
    if (!f) return false;
    size_t n = fread(got, 1, sizeof(got) - 1, f);
    fclose(f);
    return n == strlen(word) && !strcmp(got, word);
}
static void pace_failure_tests(struct zapp_runtime *r, const char *directory)
{
    char temporary[300];
    snprintf(temporary, sizeof(temporary), "%s/pace.tmp", directory);
    /* A planted symlink at the temporary name is refused and the recorded pace is kept. */
    assert(symlink("/nonexistent", temporary) == 0);
    assert(!zapp_node_pace_write(r, ZAPP_PACE_NORMAL) && zapp_node_pace(r) == ZAPP_PACE_PAUSE);
    assert(pace_file_is(directory, "pause") && unlink(temporary) == 0);
    /* A read-only directory fails without changing the recorded pace or the file. */
    assert(chmod(directory, 0500) == 0);
    if (geteuid() != 0) {
        assert(!zapp_node_pace_write(r, ZAPP_PACE_NORMAL) && zapp_node_pace(r) == ZAPP_PACE_PAUSE);
        assert(pace_file_is(directory, "pause"));
    }
    assert(chmod(directory, 0700) == 0);
    struct zapp_runtime missing = {0};
    assert(snprintf(missing.directory, sizeof(missing.directory), "%s/absent", directory) > 0);
    assert(!zapp_node_pace_write(&missing, ZAPP_PACE_GENTLE));
    assert(zapp_node_pace(&missing) == ZAPP_PACE_NORMAL);
}
static void pace_tests(void)
{
    char directory[] = "/tmp/zapp-pace-test-XXXXXX", file[300], temporary[300];
    assert(mkdtemp(directory));
    struct zapp_runtime r = {0};
    assert(snprintf(r.directory, sizeof(r.directory), "%s", directory) > 0);
    snprintf(file, sizeof(file), "%s/pace", directory);
    snprintf(temporary, sizeof(temporary), "%s/pace.tmp", directory);
    assert(zapp_node_pace(&r) == ZAPP_PACE_NORMAL && access(file, F_OK) != 0);
    /* A file left by an earlier run is replaced by the first write even when it says normal. */
    FILE *stale = fopen(file, "w");
    assert(stale && fputs("pause", stale) >= 0 && fclose(stale) == 0);
    assert(zapp_node_pace_write(&r, ZAPP_PACE_NORMAL) && pace_file_is(directory, "normal"));
    assert(zapp_node_pace_write(&r, ZAPP_PACE_GENTLE) && pace_file_is(directory, "gentle"));
    assert(zapp_node_pace(&r) == ZAPP_PACE_GENTLE && access(temporary, F_OK) != 0);
    struct stat st;
    assert(stat(file, &st) == 0 && (st.st_mode & 0777) == 0600);
    /* An unchanged pace does not touch the file. */
    assert(unlink(file) == 0);
    assert(zapp_node_pace_write(&r, ZAPP_PACE_GENTLE) && access(file, F_OK) != 0);
    assert(zapp_node_pace_write(&r, ZAPP_PACE_PAUSE) && pace_file_is(directory, "pause"));
    assert(!zapp_node_pace_write(&r, (enum zapp_pace)7) && zapp_node_pace(&r) == ZAPP_PACE_PAUSE);
    pace_failure_tests(&r, directory);
    assert(zapp_node_pace_write(&r, ZAPP_PACE_NORMAL) && pace_file_is(directory, "normal"));
    assert(unlink(file) == 0 && rmdir(directory) == 0);
}
static int waiting_calls;
static void count_waiting(void *arg) { (void)arg; ++waiting_calls; }
static void write_hostname(const char *directory, const char *text)
{
    char dir[400], file[420];
    snprintf(dir, sizeof(dir), "%s/tor_data", directory); (void)mkdir(dir, 0700);
    snprintf(dir, sizeof(dir), "%s/tor_data/onion_service", directory); (void)mkdir(dir, 0700);
    snprintf(file, sizeof(file), "%s/hostname", dir);
    FILE *f = fopen(file, "w");
    assert(f && fputs(text, f) >= 0 && fclose(f) == 0);
}
static void onion_tests(void)
{
    static const char good[] = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";
    char directory[] = "/tmp/zapp-onion-test-XXXXXX", file[420], dir[400];
    assert(mkdtemp(directory));
    struct zapp_runtime r = {0};
    assert(pthread_mutex_init(&r.mutex, NULL) == 0);
    assert(snprintf(r.directory, sizeof(r.directory), "%s", directory) > 0);
    /* No file, an empty file and malformed hostnames are never ready. */
    assert(!zapp_onion_ready(&r));
    write_hostname(directory, "");
    assert(!zapp_onion_ready(&r));
    write_hostname(directory, "short.onion\n");
    assert(!zapp_onion_ready(&r));
    write_hostname(directory, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWX.onion\n");
    assert(!zapp_onion_ready(&r));
    write_hostname(directory, "abcdefghijklmnopqrstuvwxyz234561abcdefghijklmnopqrstuvwx.onion\n");
    assert(!zapp_onion_ready(&r));
    write_hostname(directory, "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onionx\n");
    assert(!zapp_onion_ready(&r));
    /* A stopped node never waits. */
    assert(zapp_onion_wait(&r, 5, count_waiting, NULL) == ZAPP_ONION_NODE_STOPPED && waiting_calls == 0);
    pid_t node = fork();
    assert(node >= 0);
    if (node == 0) { sleep(30); _exit(0); }
    r.node = node;
    /* A running node whose address never appears times out after reporting the wait once. */
    assert(zapp_onion_wait(&r, 2, count_waiting, NULL) == ZAPP_ONION_TIMEOUT && waiting_calls == 1);
    write_hostname(directory, good);
    assert(zapp_onion_ready(&r));
    write_hostname(directory, "");
    pid_t writer = fork();
    assert(writer >= 0);
    if (writer == 0) { sleep(1); write_hostname(directory, good); _exit(0); }
    waiting_calls = 0;
    assert(zapp_onion_wait(&r, 10, count_waiting, NULL) == ZAPP_ONION_READY && waiting_calls == 1);
    assert(waitpid(writer, NULL, 0) == writer);
    assert(kill(node, SIGKILL) == 0 && waitpid(node, NULL, 0) == node);
    r.node = 0;
    snprintf(file, sizeof(file), "%s/tor_data/onion_service/hostname", directory);
    snprintf(dir, sizeof(dir), "%s/tor_data/onion_service", directory);
    assert(unlink(file) == 0 && rmdir(dir) == 0);
    snprintf(dir, sizeof(dir), "%s/tor_data", directory);
    assert(rmdir(dir) == 0 && rmdir(directory) == 0);
    pthread_mutex_destroy(&r.mutex);
}

int main(int argc, char **argv)
{
    if (argc == 3 && (!strcmp(argv[2], "orphan") || !strcmp(argv[2], "saving"))) return orphan(argv[2], argv[1]);
    if (argc == 3 && !strcmp(argv[1], "command")) return orphan("orphan", argv[2]);
    if (argc > 1) return child(argc, argv);
    plain_text_tests();
    pace_tests();
    onion_tests();
    struct zapp_runtime r = {0};
    assert(pthread_mutex_init(&r.mutex, NULL) == 0);
    assert(snprintf(r.executable, sizeof(r.executable), "%s", argv[0]) > 0);
    assert(snprintf(r.directory, sizeof(r.directory), "%s", "/tmp") > 0);
    assert(snprintf(r.state_root, sizeof(r.state_root), "%s", "/tmp/private-state") > 0);
    assert(snprintf(r.temporary_root, sizeof(r.temporary_root), "%s", "/tmp/private-tmp") > 0);
    assert(setenv("XDG_STATE_HOME", "/tmp/parent-state", 1) == 0);
    assert(setenv("ZAPP_TEST_PRESERVED", "yes", 1) == 0);
    assert(setenv("ZAPP_TEST_STATE", "/tmp/private-state", 1) == 0);
    assert(setenv("ZCL_CATCHUP_DRAIN_BUDGET_MS", "77", 1) == 0);
    assert(setenv("ZCL_BIP_PAGE_CACHE_KIB", "999", 1) == 0);
    char *runner_home = getenv("HOME") ? strdup(getenv("HOME")) : NULL;
    assert(setenv("HOME", "/tmp/parent-home", 1) == 0);
    assert(setenv("ZAPP_TEST_HOME", "/tmp/parent-home", 1) == 0);
    command_cases(&r);
    assert(unsetenv("HOME") == 0 && unsetenv("ZAPP_TEST_HOME") == 0);
    char directory[] = "/tmp/zapp-ops-test-XXXXXX", log[256], out[128];
    assert(mkdtemp(directory));
    node_cases(&r, argv[0], directory);
    if (runner_home) assert(setenv("HOME", runner_home, 1) == 0);
    else assert(unsetenv("HOME") == 0);
    free(runner_home);
    assert(snprintf(log, sizeof(log), "%s/app-console.log", directory) > 0);
    assert(unlink(log) == 0 && rmdir(directory) == 0);
    zapp_runtime_signal_stop(&r);
    assert(!zapp_operation_run(&r, "status", out, sizeof(out)));
    assert(strstr(out, "Unable to run native Z23"));
    pthread_mutex_destroy(&r.mutex);
    puts("operation tests passed");
    return 0;
}
