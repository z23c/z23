/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_mcp_serve_apps - the apps_list and apps_open tools of `z23 mcp serve`
 * (tools/mcp/mcp_serve.c), driven over real pipes against the built dev
 * binary with a temporary HOME. A stand-in app (build/bin/
 * z23-app-launch-fixture) is registered through a temporary apps.tsv, so no
 * display is needed: DISPLAY is set to a name the fixture never opens.
 *
 * Also proves the apps_open allowance is a named exemption, not a weaker
 * z23_run policy: z23_run still refuses app.open, and the in-process policy
 * refuses every other mutation that has no confirmation flow.
 *
 * make t-fast-exact ONLY=mcp_serve_apps */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_core.h"

#include "config/command_catalog.h"
#include "kernel/command_registry.h"
#include "mcp/mcp_policy.h"
#include "platform/time_compat.h"

#if !defined(_WIN32)
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define MA_BIN "build/bin/z23-dev"
#define MA_FIXTURE "build/bin/z23-app-launch-fixture"
#define MA_LINE 65536

struct ma {
    pid_t pid;
    int to_child, from_child;
    char line[MA_LINE];
    char root[PATH_MAX];
    char raised[PATH_MAX];
};

static bool ma_spawn(struct ma *m)
{
    int in[2], out[2];
    char bin[PATH_MAX], home[PATH_MAX + 8], cfg[PATH_MAX + 24],
        state[PATH_MAX + 24];
    snprintf(home, sizeof(home), "HOME=%s", m->root);
    snprintf(cfg, sizeof(cfg), "XDG_CONFIG_HOME=%s/cfg", m->root);
    snprintf(state, sizeof(state), "XDG_STATE_HOME=%s/state", m->root);
    char *envp[] = {home, cfg, state,
                    (char *)"PATH=/usr/bin:/bin:/usr/local/bin",
                    (char *)"DISPLAY=:app-launch-fixture",
                    (char *)"ZCL_CLI_TEST_NO_SERVICE_LOOKUP=1", NULL};
    char *argv[] = {(char *)MA_BIN, (char *)"mcp", (char *)"serve", NULL};
    if (!realpath(MA_BIN, bin) || pipe(in) != 0 || pipe(out) != 0)
        return false;
    m->pid = fork();
    if (m->pid < 0)
        return false;
    if (m->pid == 0) {
        int err = open("/dev/null", O_WRONLY);
        dup2(in[0], STDIN_FILENO);
        dup2(out[1], STDOUT_FILENO);
        if (err >= 0)
            dup2(err, STDERR_FILENO);
        close(in[0]); close(in[1]); close(out[0]); close(out[1]);
        execve(bin, argv, envp);
        _exit(127);
    }
    close(in[0]);
    close(out[1]);
    m->to_child = in[1];
    m->from_child = out[0];
    return true;
}

/* Send one frame, read one reply line (30 s deadline). */
static bool ma_call(struct ma *m, const char *req)
{
    size_t n = strlen(req), used = 0;
    if (write(m->to_child, req, n) != (ssize_t)n ||
        write(m->to_child, "\n", 1) != 1)
        return false;
    for (;;) {
        struct pollfd p = {.fd = m->from_child, .events = POLLIN};
        char c;
        if (poll(&p, 1, 30000) <= 0 || read(m->from_child, &c, 1) != 1)
            return false;
        if (c == '\n') {
            m->line[used] = '\0';
            return true;
        }
        if (used + 1 < sizeof(m->line))
            m->line[used++] = c;
    }
}

static bool ma_has(const struct ma *m, const char *needle)
{
    return strstr(m->line, needle) != NULL;
}

static bool ma_tool(struct ma *m, int id, const char *name, const char *args)
{
    char req[2048];
    snprintf(req, sizeof(req),
             "{\"jsonrpc\":\"2.0\",\"id\":%d,\"method\":\"tools/call\","
             "\"params\":{\"name\":\"%s\",\"arguments\":%s}}", id, name, args);
    return ma_call(m, req);
}

static bool ma_init(struct ma *m)
{
    static const char init[] =
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{"
        "\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},"
        "\"clientInfo\":{\"name\":\"mcp-apps-test\",\"version\":\"1\"}}}";
    static const char done[] =
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n";
    return ma_call(m, init) && ma_has(m, "\"serverInfo\"") &&
           write(m->to_child, done, sizeof(done) - 1) ==
               (ssize_t)(sizeof(done) - 1);
}

static int ma_finish(struct ma *m)
{
    int status = 0;
    close(m->to_child);
    close(m->from_child);
    if (waitpid(m->pid, &status, 0) != m->pid)
        return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* A private 0700 copy of the fixture binary. */
static bool ma_copy_exe(const char *from, const char *to)
{
    static char buf[65536];
    int in = open(from, O_RDONLY | O_CLOEXEC);
    if (in < 0)
        return false;
    int out = open(to, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0700);
    bool ok = out >= 0;
    ssize_t n = 0;
    while (ok && (n = read(in, buf, sizeof(buf))) > 0)
        ok = write(out, buf, (size_t)n) == n;
    close(in);
    if (out >= 0 && close(out) != 0)
        ok = false;
    return ok && n == 0;
}

/* <root>/cfg/z23/apps.tsv registering a private copy of the fixture. */
static bool ma_fixture(struct ma *m)
{
    char fixture[PATH_MAX], path[PATH_MAX + 32], exe[PATH_MAX + 16];
    if (!realpath(MA_FIXTURE, fixture) ||
        !test_mkdtemp(m->root, sizeof(m->root), "mcp_apps"))
        return false;
    snprintf(m->raised, sizeof(m->raised), "%s/raised", m->root);
    snprintf(exe, sizeof(exe), "%s/app-ready", m->root);
    bool ok = ma_copy_exe(fixture, exe);
    snprintf(path, sizeof(path), "%s/cfg", m->root);
    ok = ok && mkdir(path, 0700) == 0;
    snprintf(path, sizeof(path), "%s/cfg/z23", m->root);
    ok = ok && mkdir(path, 0700) == 0;
    snprintf(path, sizeof(path), "%s/cfg/z23/apps.tsv", m->root);
    FILE *f = ok ? fopen(path, "w") : NULL;
    if (!f)
        return false;
    ok = fprintf(f, "fixtureapp\tfx\t%s\tFIXTURE: Device initialized "
                 "successfully\tsigusr1\tready\t%s\n", exe, m->raised) > 0;
    return fclose(f) == 0 && ok && chmod(path, 0600) == 0;
}

/* The integer after "\"pid\":" in the reply text (escaped JSON inside the
 * MCP text field), or 0. */
static long ma_pid(const struct ma *m)
{
    const char *p = strstr(m->line, "\\\"pid\\\":");
    return p ? strtol(p + 8, NULL, 10) : 0;
}

static bool ma_wait_raised(const char *path)
{
    int64_t stop = platform_time_monotonic_ms() + 3000;
    for (;;) {
        char buf[64] = {0};
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            close(fd);
            if (n > 0 && strstr(buf, "raised"))
                return true;
        }
        if (platform_time_monotonic_ms() > stop)
            return false;
        platform_sleep_ms(20); /* real-clock: waiting on a real child's signal */
    }
}

/* The app outlives the server (new session); stop it by pid. */
static void ma_stop_app(long pid)
{
    if (pid <= 1)
        return;
    (void)kill((pid_t)pid, SIGTERM);
    int64_t stop = platform_time_monotonic_ms() + 3000;
    while (kill((pid_t)pid, 0) == 0 && platform_time_monotonic_ms() < stop) {
        int status;
        (void)waitpid((pid_t)pid, &status, WNOHANG);
        platform_sleep_ms(10); /* real-clock: waiting for a real exit */
    }
    if (kill((pid_t)pid, 0) == 0)
        (void)kill((pid_t)pid, SIGKILL);
}

static int case_apps_tools(struct ma *m, long *app_pid)
{
    int failures = 0;
    TEST("tools/list carries apps_list and apps_open with a name schema") {
        ASSERT(ma_call(m, "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":"
                          "\"tools/list\"}"));
        ASSERT(ma_has(m, "\"name\":\"apps_list\""));
        ASSERT(ma_has(m, "\"name\":\"apps_open\""));
        ASSERT(ma_has(m, "\"required\":[\"name\"]"));
    PASS(); }
    TEST("apps_list returns the launchable section") {
        ASSERT(ma_tool(m, 3, "apps_list", "{}"));
        ASSERT(ma_has(m, "\"isError\":false"));
        ASSERT(ma_has(m, "launchable"));
        ASSERT(ma_has(m, "fixtureapp"));
        ASSERT(ma_has(m, "skycombat"));
    PASS(); }
    TEST("apps_open opens the app and waits for ready") {
        ASSERT(ma_tool(m, 4, "apps_open", "{\"name\":\"fixtureapp\"}"));
        ASSERT(ma_has(m, "\"isError\":false"));
        ASSERT(ma_has(m, "\\\"status\\\":\\\"opened\\\""));
        *app_pid = ma_pid(m);
        ASSERT(*app_pid > 1);
    PASS(); }
    TEST("apps_open again raises the same pid (the fixture declares raise)") {
        ASSERT(ma_tool(m, 5, "apps_open", "{\"name\":\"fx\"}"));
        ASSERT(ma_has(m, "\\\"status\\\":\\\"already_open\\\""));
        ASSERT(ma_has(m, "\\\"raise\\\":\\\"delivered\\\""));
        ASSERT_EQ(ma_pid(m), *app_pid);
        ASSERT(ma_wait_raised(m->raised));
    PASS(); }
    TEST("apps_open of an unknown name lists the known names") {
        ASSERT(ma_tool(m, 6, "apps_open", "{\"name\":\"nosuchapp\"}"));
        ASSERT(ma_has(m, "\"isError\":true"));
        ASSERT(ma_has(m, "UNKNOWN_APP"));
        ASSERT(ma_has(m, "known apps: skycombat, fixtureapp"));
    PASS(); }
    TEST("apps_open without a name is a bad argument") {
        ASSERT(ma_tool(m, 7, "apps_open", "{}"));
        ASSERT(ma_has(m, "\"isError\":true"));
        ASSERT(ma_has(m, "BAD_ARGUMENT"));
    PASS(); }
    TEST("z23_run still refuses app.open: the allowance is apps_open only") {
        ASSERT(ma_tool(m, 8, "z23_run", "{\"path\":\"app.open\",\"input\":"
                                        "{\"name\":\"fixtureapp\"}}"));
        ASSERT(ma_has(m, "\"isError\":true"));
        ASSERT(ma_has(m, "MUTATION_NO_CONFIRMATION_FLOW"));
    PASS(); }
_test_next:;
    return failures;
}

/* In process: the exemption names exactly app.open. */
static int case_policy_exact(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    TEST("mcp_policy_app_open holds for app.open and no other mutation") {
        bool alias = false;
        const struct zcl_command_spec *open =
            zcl_command_registry_find(reg, "app.open", &alias);
        ASSERT(open != NULL);
        ASSERT(mcp_policy_app_open(open));
        size_t others = 0;
        for (size_t i = 0; i < reg->count; i++) {
            const struct zcl_command_spec *spec = &reg->commands[i];
            if (spec == open || spec->effect == ZCL_COMMAND_EFFECT_READ)
                continue;
            others++;
            ASSERT(!mcp_policy_app_open(spec));
        }
        ASSERT(others > 10u);
        const struct zcl_command_spec *qr =
            zcl_command_registry_find(reg, "app.qr.show", &alias);
        struct mcp_refusal why = {0};
        struct json_value empty;
        json_init(&empty);
        json_set_object(&empty);
        ASSERT(qr != NULL);
        ASSERT(!mcp_policy_allows(qr, reg, &empty, &why));
        ASSERT_STR_EQ(why.code, "MUTATION_NO_CONFIRMATION_FLOW");
        ASSERT(!mcp_policy_allows(open, reg, &empty, &why));
        ASSERT_STR_EQ(why.code, "MUTATION_NO_CONFIRMATION_FLOW");
        json_free(&empty);
    PASS(); }
_test_next:;
    return failures;
}

int test_mcp_serve_apps(void);
int test_mcp_serve_apps(void)
{
    int failures = 0;
    static struct ma m;
    long app_pid = 0;
    bool started = false;
    failures += case_policy_exact();
    TEST("fixture: a temporary HOME, apps.tsv and a running server") {
        ASSERT(ma_fixture(&m));
        ASSERT(ma_spawn(&m));
        started = true;
        ASSERT(ma_init(&m));
    PASS(); }
    failures += case_apps_tools(&m, &app_pid);
_test_next:;
    ma_stop_app(app_pid);
    if (started)
        TEST_DISCARD(ma_finish(&m));
    return failures;
}

#else

int test_mcp_serve_apps(void);
int test_mcp_serve_apps(void)
{
    printf("SKIP (mcp_serve_apps: the MCP adapter needs a POSIX host)\n");
    return 0;
}

#endif
