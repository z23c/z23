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

static void doctor_tests(void)
{
    char out[256];
    const char *json = "{\"ok\":true,\"data\":{\"state\":\"missing\",\"checks\":["
        "{\"name\":\"node\",\"state\":\"ok\",\"detail\":\"A node is running and answered.\",\"next\":\"\"},"
        "{\"name\":\"identity\",\"state\":\"ok\"},"
        "{\"name\":\"membership\",\"state\":\"missing\",\"detail\":\"This box is not in a fleet.\","
        "\"next\":\"z23 fleet invite --name=<box>\"}]}}";
    assert(zapp_fleet_doctor_format(json, out, sizeof(out)));
    assert(!strcmp(out, "Node: A node is running and answered.\nMembership: This box is not in a fleet."));
    assert(zapp_fleet_doctor_format(json, out, 40) && !strcmp(out, "Node: A node is running and answered."));
    assert(!zapp_fleet_doctor_format(json, out, 20) && !out[0]);
    const char *shared = "{\"ok\":true,\"data\":{\"checks\":["
        "{\"name\":\"node\",\"detail\":\"No node answered.\"},{\"name\":\"identity\",\"detail\":\"Needs a node.\"},"
        "{\"name\":\"membership\",\"detail\":\"Not in a fleet.\"},{\"name\":\"transport\",\"detail\":\"Needs a node.\"},"
        "{\"name\":\"mail\",\"detail\":\"Developer tool.\",\"informational\":true},"
        "{\"name\":\"wiki\",\"detail\":\"Needs a node.\"}]}}";
    assert(zapp_fleet_doctor_format(shared, out, sizeof(out)));
    assert(!strcmp(out, "Node: No node answered.\nIdentity, transport and wiki: Needs a node.\nMembership: Not in a fleet."));
    assert(!zapp_fleet_doctor_format("{\"ok\":false,\"data\":{\"checks\":[]}}", out, sizeof(out)));
    assert(!zapp_fleet_doctor_format("not json", out, sizeof(out)) && !out[0]);
    char failed[128] = "{\"ok\":false,\"error\":{\"code\":\"E\",\"message\":\"The manager is offline.\"}}";
    zapp_plain_text(failed, sizeof(failed));
    assert(!strcmp(failed, "The manager is offline."));
    char bare[64] = "{\"ok\":false}";
    zapp_plain_text(bare, sizeof(bare));
    assert(!strcmp(bare, "The command did not return a readable result."));
    char words[32] = "Node starting.";
    zapp_plain_text(words, sizeof(words));
    assert(!strcmp(words, "Node starting."));
}

/* A node left by an earlier app process is found through its pid file and its -datadir argument. */
static void earlier_cases(struct zapp_runtime *r, const char *self, const char *directory)
{
    char data[300], pidfile[300], out[128];
    assert(snprintf(data, sizeof(data), "-datadir=%s", directory) > 0);
    assert(snprintf(pidfile, sizeof(pidfile), "%s/zclassic23.pid", directory) > 0);
    pid_t other = fork();
    assert(other >= 0);
    if (!other) { execl(self, self, data, "orphan", (char *)NULL); _exit(127); }
    FILE *f = fopen(pidfile, "w");
    assert(f && fprintf(f, "%d\n", (int)other) > 0 && fclose(f) == 0);
    for (int i = 0; i < 500 && !zapp_node_running(r); ++i) {
        struct timespec pause = {.tv_nsec = 10000000}; nanosleep(&pause, NULL);
    }
    assert(zapp_node_running(r));
    assert(!zapp_node_start(r, out, sizeof(out)) && !strcmp(out, "The local node is already running."));
    assert(zapp_node_stop(r, out, sizeof(out)) && !strcmp(out, "Node stopping. It saves its data first."));
    int status;
    assert(waitpid(other, &status, 0) == other && WIFSIGNALED(status) && WTERMSIG(status) == SIGINT);
    assert(!zapp_node_running(r));
    f = fopen(pidfile, "w");
    assert(f && fprintf(f, "%d\n", (int)getpid()) > 0 && fclose(f) == 0);
    assert(!zapp_node_running(r) && unlink(pidfile) == 0);
}
int main(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[2], "orphan")) { alarm(30); pause(); return 0; }
    if (argc > 1) return child(argc, argv);
    balance_tests();
    doctor_tests();
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
    char out[128];
    assert(!zapp_operation_run(&r, "not-allowed", out, sizeof(out)));
    assert(!zapp_operation_run(&r, "status", out, sizeof(out)));
    assert(strstr(out, "[Output limit reached]"));
    assert(zapp_fleet_join_run(&r, "invitation", out, sizeof(out)));
    assert(strstr(out, "receipt"));
    assert(strcmp(getenv("XDG_STATE_HOME"), "/tmp/parent-state") == 0);
    assert(strcmp(getenv("ZCL_CATCHUP_DRAIN_BUDGET_MS"), "77") == 0);
    assert(setenv("ZAPP_TEST_CLOCK_FAIL", "1", 1) == 0);
    assert(!zapp_operation_run(&r, "status", out, sizeof(out)));
    assert(strstr(out, "timed out"));
    assert(unsetenv("ZAPP_TEST_CLOCK_FAIL") == 0);
    char directory[] = "/tmp/zapp-ops-test-XXXXXX";
    assert(mkdtemp(directory));
    assert(snprintf(r.directory, sizeof(r.directory), "%s", directory) > 0);
    assert(snprintf(r.state_root, sizeof(r.state_root), "%s/missing", directory) > 0);
    assert(setenv("ZAPP_TEST_STATE", r.state_root, 1) == 0);
    assert(zapp_node_start(&r, out, sizeof(out)) && strstr(out, "could not save") && !zapp_node_wanted(&r));
    int status;
    assert(waitpid(r.node, &status, 0) == r.node && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    r.node = 0;
    assert(snprintf(r.state_root, sizeof(r.state_root), "%s", directory) > 0);
    assert(setenv("ZAPP_TEST_STATE", r.state_root, 1) == 0);
    assert(!zapp_node_wanted(&r));
    assert(zapp_node_start(&r, out, sizeof(out)) && zapp_node_wanted(&r));
    assert(waitpid(r.node, &status, 0) == r.node && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    r.node = 0;
    assert(zapp_node_stop(&r, out, sizeof(out)) && !strcmp(out, "The local node is stopped.") && !zapp_node_wanted(&r));
    earlier_cases(&r, argv[0], directory);
    char log[256];
    assert(snprintf(log, sizeof(log), "%s/app-console.log", directory) > 0);
    assert(unlink(log) == 0 && rmdir(directory) == 0);
    zapp_runtime_signal_stop(&r);
    assert(!zapp_operation_run(&r, "status", out, sizeof(out)));
    assert(strstr(out, "Unable to run native Z23"));
    pthread_mutex_destroy(&r.mutex);
    puts("operation tests passed");
    return 0;
}
