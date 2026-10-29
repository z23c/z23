/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "operations.h"
#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>

int __real_clock_gettime(clockid_t id, struct timespec *out);
int __wrap_clock_gettime(clockid_t id, struct timespec *out)
{
    if (getenv("ZAPP_TEST_CLOCK_FAIL")) return -1;
    return __real_clock_gettime(id, out);
}

static bool child_environment(void)
{
    const char *batch = getenv("ZCL_CATCHUP_DRAIN_BUDGET_MS");
    if (!batch || strcmp(batch, "100")) return false;
    const char *temp = getenv("TMPDIR");
    if (!temp || strcmp(temp, "/tmp/private-tmp")) return false;
    const char *state = getenv("XDG_STATE_HOME");
    const char *preserved = getenv("ZAPP_TEST_PRESERVED");
    const char *want = getenv("ZAPP_TEST_STATE");
    return state && want && !strcmp(state, want) && preserved && !strcmp(preserved, "yes");
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

static int child(int argc, char **argv)
{
    if (!child_environment()) return 3;
    if (argc == 5 && !strncmp(argv[1], "-datadir=", 9)) {
        if (strcmp(argv[2], "-operator-lane=canonical") || strcmp(argv[3], "-tor") ||
            strcmp(argv[4], "-onion-persist")) return 4;
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

static void balance_tests(void)
{
    char out[512];
    const char *valid = "{\"ok\":true,\"data\":{\"total\":\"1.25000000\","
        "\"transparent\":\"0.25000000\",\"private\":\"1.00000000\","
        "\"encumbered\":\"0.00000000\",\"transparent_source\":\"wallet\","
        "\"transparent_sources_agree\":true,\"wallet_height\":20,\"chain_height\":20}}";
    assert(zapp_balance_format(valid, out, sizeof(out)));
    assert(strstr(out, "1.25000000") && strstr(out, "Shielded: 1.00000000"));
    const char *stale = "{\"ok\":true,\"data\":{\"total\":\"0.00000000\","
        "\"transparent\":\"0.00000000\",\"private\":\"0.00000000\","
        "\"encumbered\":\"0.00000000\",\"transparent_source\":\"wallet\","
        "\"transparent_sources_agree\":true,\"wallet_height\":19,\"chain_height\":20}}";
    assert(zapp_balance_format(stale, out, sizeof(out)) && strstr(out, "may be stale"));
    assert(!zapp_balance_format("{\"ok\":false,\"data\":{}}", out, sizeof(out)) && !out[0]);
    assert(!zapp_balance_format("{\"ok\":true,\"data\":{\"total\":\"0\"}}", out, sizeof(out)));
    assert(!zapp_balance_format(valid, out, 8));
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
    preview_cases(r);
    assert(zapp_node_stop(r, out, sizeof(out)) && !strcmp(out, "The local node is stopped.") && !zapp_node_wanted(r));
    earlier_cases(r, self, directory);
}
int main(int argc, char **argv)
{
    if (argc == 3 && (!strcmp(argv[2], "orphan") || !strcmp(argv[2], "saving"))) return orphan(argv[2], argv[1]);
    if (argc == 3 && !strcmp(argv[1], "command")) return orphan("orphan", argv[2]);
    if (argc > 1) return child(argc, argv);
    balance_tests();
    plain_text_tests();
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
    command_cases(&r);
    char directory[] = "/tmp/zapp-ops-test-XXXXXX", log[256], out[128];
    assert(mkdtemp(directory));
    node_cases(&r, argv[0], directory);
    assert(snprintf(log, sizeof(log), "%s/app-console.log", directory) > 0);
    assert(unlink(log) == 0 && rmdir(directory) == 0);
    zapp_runtime_signal_stop(&r);
    assert(!zapp_operation_run(&r, "status", out, sizeof(out)));
    assert(strstr(out, "Unable to run native Z23"));
    pthread_mutex_destroy(&r.mutex);
    puts("operation tests passed");
    return 0;
}
