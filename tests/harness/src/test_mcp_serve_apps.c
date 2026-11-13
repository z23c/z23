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
        ASSERT(ma_has(m, "\"name\":\"apps_adopt\""));
        ASSERT(ma_has(m, "\"name\":\"apps_receive\""));
        ASSERT(ma_has(m, "\"name\":\"apps_share\""));
        ASSERT(ma_has(m, "\"name\":\"apps_personalize\""));
        ASSERT(ma_has(m, "\"required\":[\"name\"]"));
        ASSERT(ma_has(m, "\"required\":[\"name\"],\"additionalProperties\":false}"));
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

static int case_selected_forwarding(struct ma *m)
{
    int failures = 0;
    TEST("apps_open forwards selection and consent instead of opening the default") {
        ASSERT(ma_tool(m, 9, "apps_open", "{\"name\":\"fixtureapp\",\"copy\":\"/missing\",\"accept_execution\":false}"));
        ASSERT(ma_has(m, "EXECUTION_CONFIRMATION_REQUIRED"));
        ASSERT(ma_tool(m, 10, "apps_open", "{\"name\":\"fixtureapp\",\"copy\":\"/missing\",\"accept_execution\":true}"));
        ASSERT(ma_has(m, "BAD_SELECTED_APP"));
        ASSERT(ma_tool(m, 11, "apps_open", "{\"name\":\"fixtureapp\",\"image_sha3\":\"invalid\"}"));
        ASSERT(ma_has(m, "EXECUTION_CONFIRMATION_REQUIRED"));
        PASS();
    } _test_next:;
    return failures;
}

/* apps_open with extra keys injected after name: refused before dispatch,
 * so no app is launched and the reply never carries a pid. */
static bool ma_open_injection(struct ma *m, unsigned id, const char *body)
{
    char args[512];
    int n = snprintf(args, sizeof(args), "{\"name\":\"fixtureapp\",%s}", body);
    return n > 0 && (size_t)n < sizeof(args) &&
        ma_tool(m, (int)id, "apps_open", args) &&
        ma_has(m, "\"isError\":true") && ma_has(m, "BAD_ARGUMENT") &&
        !ma_has(m, "\\\"pid\\\"");
}
static int case_open_list_gates(struct ma *m)
{
    int failures = 0;
    TEST("apps_open refuses misspelled, undeclared, duplicate and mistyped keys; apps_list takes none") {
        ASSERT(ma_open_injection(m, 40, "\"accept_execution\":true,\"cop\":\"/missing\""));
        ASSERT(ma_has(m, "duplicate key cop\\\""));
        ASSERT(ma_has(m, "image_sha3, record_id, accept_execution"));
        ASSERT(ma_open_injection(m, 41, "\"accept_execution\":true,\"expected_revision\":1"));
        ASSERT(ma_has(m, "duplicate key expected_revision"));
        ASSERT(ma_open_injection(m, 42, "\"accept_execution\":true,\"name\":\"fixtureapp\""));
        ASSERT(ma_has(m, "duplicate key name"));
        ASSERT(ma_open_injection(m, 43, "\"accept_execution\":true,\"copy\":5"));
        ASSERT(ma_has(m, "key copy must be a string"));
        ASSERT(ma_open_injection(m, 44, "\"copy\":\"/c\",\"accept_execution\":\"yes\""));
        ASSERT(ma_has(m, "key accept_execution must be a boolean"));
        ASSERT(ma_tool(m, 45, "apps_list", "{\"datadir\":\"/other\"}"));
        ASSERT(ma_has(m, "\"isError\":true") && ma_has(m, "BAD_ARGUMENT"));
        ASSERT(ma_tool(m, 46, "apps_list", "{\"name\":\"fixtureapp\"}"));
        ASSERT(ma_has(m, "\"isError\":true") && ma_has(m, "BAD_ARGUMENT"));
        ASSERT(ma_tool(m, 47, "apps_list", "{}"));
        ASSERT(ma_has(m, "\"isError\":false") && ma_has(m, "launchable"));
        PASS();
    } _test_next:;
    return failures;
}

static int case_keep_forwarding(struct ma *m)
{
    int failures = 0;
    char args[PATH_MAX + 1024];
    TEST("apps_keep forwards a typed revision and cannot create copy trust") {
        int n = snprintf(args, sizeof(args),
            "{\"name\":\"fixtureapp\",\"copy\":\"/missing-copy\","
            "\"version\":\"%064d\",\"env_root\":\"%064d\","
            "\"dependency_root\":\"%064d\",\"image_sha3\":\"%064d\","
            "\"record_id\":\"%064d\",\"accept_execution\":false,\"expected_revision\":0}",
            1, 1, 1, 1, 1);
        ASSERT(n > 0 && (size_t)n < sizeof(args));
        ASSERT(ma_tool(m, 12, "apps_keep", args));
        ASSERT(ma_has(m, "\"isError\":true"));
        ASSERT(ma_has(m, "EXECUTION_CONFIRMATION_REQUIRED"));
        n = snprintf(args, sizeof(args),
            "{\"name\":\"fixtureapp\",\"copy\":\"/missing-copy\","
            "\"version\":\"%064d\",\"env_root\":\"%064d\","
            "\"dependency_root\":\"%064d\",\"image_sha3\":\"%064d\","
            "\"record_id\":\"%064d\",\"accept_execution\":true,\"expected_revision\":0,"
            "\"datadir\":\"%s\"}",
            1, 1, 1, 1, 1, m->root);
        ASSERT(n > 0 && (size_t)n < sizeof(args));
        ASSERT(ma_tool(m, 13, "apps_keep", args));
        ASSERT(ma_has(m, "\"isError\":true") && ma_has(m, "COPY_MISSING"));
        n = snprintf(args, sizeof(args),
            "{\"name\":\"fixtureapp\",\"copy\":\"/missing-copy\","
            "\"version\":\"%064d\",\"env_root\":\"%064d\","
            "\"dependency_root\":\"%064d\",\"image_sha3\":\"%064d\","
            "\"record_id\":\"%064d\",\"accept_execution\":false,\"expected_revision\":\"0\"}",
            1, 1, 1, 1, 1);
        ASSERT(n > 0 && (size_t)n < sizeof(args));
        ASSERT(ma_tool(m, 14, "apps_keep", args));
        ASSERT(ma_has(m, "\"isError\":true") && !ma_has(m, "EXECUTION_CONFIRMATION_REQUIRED"));
        ASSERT(ma_tool(m, 15, "z23_run", "{\"path\":\"app.keep\",\"input\":{}}"));
        ASSERT(ma_has(m, "\"isError\":true") && ma_has(m, "KEEP_NATIVE_CONFIRMATION_REQUIRED"));
        PASS();
    } _test_next:;
    return failures;
}

static bool ma_keep_injection(struct ma *m, unsigned id, const char *extra)
{
    char args[2048];
    int n = snprintf(args, sizeof(args),
        "{\"name\":\"fixtureapp\",\"copy\":\"/missing-copy\","
        "\"version\":\"%064d\",\"env_root\":\"%064d\",\"dependency_root\":\"%064d\","
        "\"image_sha3\":\"%064d\",\"record_id\":\"%064d\","
        "\"accept_execution\":true,\"expected_revision\":0,%s}", 1, 1, 1, 1, 1, extra);
    return n > 0 && (size_t)n < sizeof(args) && ma_tool(m, (int)id, "apps_keep", args) &&
        ma_has(m, "\"isError\":true") && ma_has(m, "BAD_ARGUMENT") && !ma_has(m, "COPY_MISSING");
}
static int case_keep_decisions(struct ma *m)
{
    int failures = 0;
    TEST("MCP Keep rejects caller decisions and duplicate identity before native dispatch") {
        ASSERT(ma_keep_injection(m, 240, "\"confirm\":true"));
        ASSERT(ma_keep_injection(m, 241, "\"action\":\"keep\""));
        ASSERT(ma_keep_injection(m, 242, "\"presenter\":\"approve\""));
        ASSERT(ma_keep_injection(m, 243, "\"expected_revision\":1"));
        ASSERT(ma_keep_injection(m, 244, "\"name\":\"other\""));
        ASSERT(ma_keep_injection(m, 245, "\"unknown\":true"));
        ASSERT(ma_keep_injection(m, 247, "\"image_sha\":\"deadbeef\""));
        ASSERT(ma_has(m, "duplicate key image_sha\\\""));
        ASSERT(ma_has(m, "image_sha3, record_id"));
        ASSERT(ma_tool(m, 248, "apps_keep",
            "{\"name\":\"fixtureapp\",\"copy\":\"/missing-copy\",\"version\":\"v\","
            "\"env_root\":\"e\",\"dependency_root\":\"d\",\"image_sha3\":\"i\","
            "\"accept_execution\":true,\"expected_revision\":0}"));
        ASSERT(ma_has(m, "\"isError\":true") && ma_has(m, "BAD_ARGUMENT"));
        ASSERT(ma_has(m, "missing required key(s): record_id"));
        ASSERT(ma_has(m, "image_sha3, record_id"));
        ASSERT(ma_tool(m, 246, "z23_run",
            "{\"path\":\"app keep\",\"input\":{\"confirm\":true,\"plan_id\":\"invented\",\"accept_execution\":true}}"));
        ASSERT(ma_has(m, "\"isError\":true") && ma_has(m, "KEEP_NATIVE_CONFIRMATION_REQUIRED"));
        PASS();
    } _test_next:;
    return failures;
}
static int case_keep_policy_stable(void)
{
    int failures = 0;
    struct json_value input; json_init(&input); json_set_object(&input);
    TEST("generic Keep refusal survives catalog confirmation and effect changes") {
        const struct zcl_command_registry *reg = zcl_command_catalog();
        const struct zcl_command_spec *keep = zcl_command_registry_find(reg, "app.keep", NULL);
        ASSERT(keep);
        struct zcl_command_spec altered = *keep; struct mcp_refusal why = {0};
        ASSERT(json_push_kv_bool(&input, "confirm", true));
        ASSERT(json_push_kv_str(&input, "plan_id", "invented"));
        altered.confirmation = ZCL_COMMAND_CONFIRM_PLAN_COMMIT;
        altered.input_keys = "confirm,plan_id";
        ASSERT(!mcp_policy_allows(&altered, reg, &input, &why));
        ASSERT_STR_EQ(why.code, "KEEP_NATIVE_CONFIRMATION_REQUIRED");
        altered.effect = ZCL_COMMAND_EFFECT_READ;
        ASSERT(!mcp_policy_allows(&altered, reg, &input, &why));
        ASSERT_STR_EQ(why.code, "KEEP_NATIVE_CONFIRMATION_REQUIRED");
        PASS();
    } _test_next:;
    json_free(&input); return failures;
}

static int case_adopt_request(struct ma *m)
{
    int failures = 0; char args[PATH_MAX + 256];
    TEST("apps_adopt can request only the local owner dialog") {
        int n = snprintf(args, sizeof(args),
            "{\"release_root\":\"%064d\",\"datadir\":\"%s\"}", 1, m->root);
        ASSERT(n > 0 && (size_t)n < sizeof(args));
        ASSERT(ma_tool(m, 16, "apps_adopt", args));
        ASSERT(ma_has(m, "\"isError\":true"));
        ASSERT(ma_has(m, "FORK_ROOT_UNKNOWN") || ma_has(m, "RELEASES_UNREADABLE"));
        ASSERT(ma_tool(m, 17, "apps_adopt", "{\"release_root\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"confirm\":true}"));
        ASSERT(ma_has(m, "\"isError\":true") && ma_has(m, "BAD_ARGUMENT"));
        ASSERT(ma_tool(m, 171, "apps_adopt", "{\"name\":\"skycombat\",\"confirm\":true}"));
        ASSERT(ma_has(m, "\"isError\":true") && ma_has(m, "BAD_ARGUMENT"));
        ASSERT(ma_tool(m, 172, "apps_adopt", "{\"name\":\"skycombat\",\"release_root\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}"));
        ASSERT(ma_has(m, "\"isError\":true") && ma_has(m, "BAD_ARGUMENT"));
        ASSERT(ma_tool(m, 173, "apps_adopt", "{\"name\":\"skycombat\"}"));
        ASSERT(ma_has(m, "\"isError\":true") && ma_has(m, "INSTALLED_SOURCE_UNAVAILABLE"));
        ASSERT(ma_tool(m, 18, "z23_run", "{\"path\":\"app.adopt\",\"input\":{}}"));
        ASSERT(ma_has(m, "\"isError\":true") && ma_has(m, "MUTATION_REFUSED_OWNER_AUTHORITY"));
        ASSERT(ma_tool(m, 19, "z23_run", "{\"path\":\"zcode.package.adopt\",\"input\":{}}"));
        ASSERT(ma_has(m, "\"isError\":true") && ma_has(m, "MUTATION_REFUSED_OWNER_AUTHORITY"));
        ASSERT(ma_tool(m, 20, "z23_run", "{\"path\":\"zcode.package.bundle.sign\",\"input\":{}}"));
        ASSERT(ma_has(m, "\"isError\":true") && ma_has(m, "MUTATION_REFUSED_OWNER_AUTHORITY"));
        ASSERT(ma_tool(m, 21, "z23_run", "{\"path\":\"zcode.package.bundle.receive\",\"input\":{}}"));
        ASSERT(ma_has(m, "\"isError\":true") && ma_has(m, "MUTATION_REFUSED_OWNER_AUTHORITY"));
        PASS();
    } _test_next:;
    return failures;
}

static int case_receive_request(struct ma *m)
{
    int failures = 0; char args[PATH_MAX * 3 + 512];
    TEST("apps_receive forwards only paths to the local owner dialog") {
        int n = snprintf(args, sizeof(args),
            "{\"file\":\"%s/missing.z23share\",\"datadir\":\"%s/data\",\"destination\":\"%s/copy\"}",
            m->root, m->root, m->root);
        ASSERT(n > 0 && (size_t)n < sizeof(args));
        ASSERT(ma_tool(m, 22, "apps_receive", args));
        ASSERT(ma_has(m, "\"isError\":true") && ma_has(m, "BUNDLE_UNREADABLE"));
        ASSERT(ma_tool(m, 29, "z23_run", "{\"path\":\"app.receive\",\"input\":{}}"));
        ASSERT(ma_has(m, "\"isError\":true") && ma_has(m, "MUTATION_REFUSED_OWNER_AUTHORITY"));
        ASSERT(ma_tool(m, 30, "z23_run", "{\"path\":\"zcode.package.bundle.receive\",\"input\":{}}"));
        ASSERT(ma_has(m, "\"isError\":true") && ma_has(m, "MUTATION_REFUSED_OWNER_AUTHORITY"));
        PASS();
    } _test_next:;
    return failures;
}
static int case_receive_injections(struct ma *m)
{
    int failures = 0; char args[PATH_MAX * 3 + 512]; int n;
    TEST("apps_receive rejects caller trust, confirmation and malformed paths") {
        const char *const extras[] = {"\"confirm\":true", "\"trust_publisher\":\"x\"",
                                      "\"trust_root\":\"x\"", "\"day\":1",
                                      "\"preview\":true", "\"preview\":false"};
        for (size_t i = 0; i < sizeof(extras)/sizeof(extras[0]); ++i) {
            n = snprintf(args, sizeof(args),
                "{\"file\":\"%s/missing\",\"datadir\":\"%s/data\",\"destination\":\"%s/copy\",%s}",
                m->root, m->root, m->root, extras[i]);
            ASSERT(n > 0 && (size_t)n < sizeof(args));
            ASSERT(ma_tool(m, 23 + (int)i, "apps_receive", args));
            ASSERT(ma_has(m, "\"isError\":true") && ma_has(m, "BAD_ARGUMENT"));
        }
        n = snprintf(args, sizeof(args),
            "{\"file\":\"relative\",\"datadir\":\"%s/data\",\"destination\":\"%s/copy\"}",
            m->root, m->root);
        ASSERT(n > 0 && (size_t)n < sizeof(args));
        ASSERT(ma_tool(m, 28, "apps_receive", args));
        ASSERT(ma_has(m, "\"isError\":true") && ma_has(m, "BAD_ARGUMENT"));
        n = snprintf(args, sizeof(args),
            "{\"file\":true,\"datadir\":\"%s/data\",\"destination\":\"%s/copy\"}",
            m->root, m->root);
        ASSERT(n > 0 && (size_t)n < sizeof(args));
        ASSERT(ma_tool(m, 31, "apps_receive", args));
        ASSERT(ma_has(m, "\"isError\":true") && ma_has(m, "BAD_ARGUMENT"));
        n = snprintf(args, sizeof(args),
            "{\"file\":\"%s/missing\",\"datadir\":\"%s/data\",\"destination\":\"%s/copy\","
            "\"preview\":true}", m->root, m->root, m->root);
        ASSERT(n > 0 && (size_t)n < sizeof(args));
        ASSERT(ma_tool(m, 32, "apps_receive", args));
        ASSERT(ma_has(m, "\"isError\":true") && ma_has(m, "BAD_ARGUMENT"));
        ASSERT(ma_has(m, "refuses preview"));
        ASSERT(ma_has(m, "z23_run app.build plan/confirm"));
        ASSERT(ma_has(m, "preview it with apps_open"));
        n = snprintf(args, sizeof(args),
            "{\"file\":\"%s/missing\",\"datadir\":\"%s/data\",\"destination\":\"%s/copy\","
            "\"confirm\":true}", m->root, m->root, m->root);
        ASSERT(n > 0 && (size_t)n < sizeof(args));
        ASSERT(ma_tool(m, 33, "apps_receive", args));
        ASSERT(ma_has(m, "\"isError\":true") && ma_has(m, "BAD_ARGUMENT"));
        ASSERT(ma_has(m, "accepts only file, datadir and destination"));
        ASSERT(!ma_has(m, "app.build"));
        PASS();
    } _test_next:;
    return failures;
}
static bool ma_receive_schema(struct ma *m)
{
    struct json_value doc; json_init(&doc);
    bool ok = json_read(&doc, m->line, strlen(m->line));
    const struct json_value *tools = json_get(json_get(&doc, "result"), "tools");
    bool found = false;
    for (size_t i = 0; ok && i < json_size(tools); ++i) {
        const struct json_value *tool = json_at(tools, i);
        const char *name = json_get_str(json_get(tool, "name"));
        if (!name || strcmp(name, "apps_receive")) continue;
        const struct json_value *schema = json_get(tool, "inputSchema");
        const struct json_value *required = json_get(schema, "required");
        const struct json_value *extra = json_get(schema, "additionalProperties");
        const char *first = json_get_str(json_at(required, 0));
        found = json_size(required) == 1 && first && !strcmp(first, "file") &&
            json_size(json_get(schema, "properties")) == 3 &&
            extra && extra->type == JSON_BOOL && !json_get_bool(extra);
        break;
    }
    json_free(&doc); return ok && found;
}
static int case_receive_defaults(struct ma *m)
{
    int failures = 0; char args[PATH_MAX * 3 + 512];
    TEST("apps_receive advertises file-only and forwards independent optional paths") {
        ASSERT(ma_call(m, "{\"jsonrpc\":\"2.0\",\"id\":70,\"method\":\"tools/list\"}"));
        ASSERT(ma_receive_schema(m));
        static const char *const keys[] = {"", "datadir", "destination"};
        for (size_t i = 0; i < sizeof(keys)/sizeof(keys[0]); ++i) {
            char extra[PATH_MAX + 64] = {0};
            if (i) {
                int added = snprintf(extra, sizeof(extra), ",\"%s\":\"%s/optional\"", keys[i], m->root);
                ASSERT(added > 0 && (size_t)added < sizeof(extra));
            }
            int n = snprintf(args, sizeof(args), "{\"file\":\"%s/missing.z23share\"%s}", m->root, extra);
            ASSERT(n > 0 && (size_t)n < sizeof(args));
            ASSERT(ma_tool(m, 71 + (int)i, "apps_receive", args));
            ASSERT(ma_has(m, "\"isError\":true") && ma_has(m, "BUNDLE_UNREADABLE"));
        }
        PASS();
    } _test_next:;
    return failures;
}
static int case_receive_default_refusals(struct ma *m)
{
    int failures = 0;
    static const char *const bad[] = {"{}", "{\"destination\":\"/missing\"}",
        "{\"file\":\"\"}", "{\"file\":false}", "{\"file\":\"relative\"}",
        "{\"file\":\"/missing\",\"datadir\":null}", "{\"file\":\"/missing\",\"datadir\":\"\"}",
        "{\"file\":\"/missing\",\"destination\":false}", "{\"file\":\"/missing\",\"destination\":\"\"}",
        "{\"file\":\"/missing\",\"file\":\"/again\"}",
        "{\"file\":\"/missing\",\"confirm\":true}",
        "{\"file\":\"/missing\",\"trust_root\":\"x\"}",
        "{\"file\":\"/missing\",\"trust_publisher\":\"x\"}",
        "{\"file\":\"/missing\",\"day\":1}"};
    TEST("apps_receive defaults never admit duplicate, empty, mistyped or owner authority arguments") {
        for (size_t i = 0; i < sizeof(bad)/sizeof(bad[0]); ++i) {
            ASSERT(ma_tool(m, 80 + (int)i, "apps_receive", bad[i]));
            ASSERT(ma_has(m, "\"isError\":true") && ma_has(m, "BAD_ARGUMENT"));
        }
        PASS();
    } _test_next:;
    return failures;
}

static int case_receive_policy(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    TEST("receive exemption is limited to native owner-local app.receive") {
        const struct zcl_command_spec *receive = zcl_command_registry_find(reg, "app.receive", NULL);
        const struct zcl_command_spec *adopt = zcl_command_registry_find(reg, "app.adopt", NULL);
        ASSERT(receive && adopt && mcp_policy_app_receive(receive));
        ASSERT(!mcp_policy_app_receive(adopt) && mcp_policy_app_adopt(adopt));
        struct zcl_command_spec altered = *receive;
        altered.authority = ZCL_COMMAND_AUTH_PUBLIC; ASSERT(!mcp_policy_app_receive(&altered));
        altered = *receive; altered.scope = ZCL_COMMAND_SCOPE_NODE; ASSERT(!mcp_policy_app_receive(&altered));
        altered = *receive; altered.transports = 0; ASSERT(!mcp_policy_app_receive(&altered));
        altered = *receive; altered.transports |= ZCL_COMMAND_TRANSPORT_RPC; ASSERT(!mcp_policy_app_receive(&altered));
        struct mcp_refusal why = {0}; struct json_value empty;
        json_init(&empty); json_set_object(&empty);
        bool allowed = mcp_policy_allows(receive, reg, &empty, &why);
        json_free(&empty);
        ASSERT(!allowed && !strcmp(why.code, "MUTATION_REFUSED_OWNER_AUTHORITY"));
        PASS();
    } _test_next:;
    return failures;
}

static int case_share_request(struct ma *m)
{
    int failures = 0; char args[PATH_MAX + 256];
    TEST("apps_share reaches the owner leaf without caller approval") {
        int n = snprintf(args, sizeof(args), "{\"name\":\"kept:missing\",\"output\":\"%s/share.z23share\"}", m->root);
        ASSERT(n > 0 && (size_t)n < sizeof(args));
        ASSERT(ma_tool(m, 81, "apps_share", args));
        ASSERT(ma_has(m, "\"isError\":true") && ma_has(m, "SELECTION_UNAVAILABLE"));
        ASSERT(ma_tool(m, 82, "z23_run", "{\"path\":\"app.share\",\"input\":{}}"));
        ASSERT(ma_has(m, "\"isError\":true") && ma_has(m, "MUTATION_REFUSED_OWNER_AUTHORITY"));
        PASS();
    } _test_next:;
    return failures;
}
static int case_share_injections(struct ma *m)
{
    int failures = 0; char args[PATH_MAX + 512];
    TEST("apps_share rejects caller decisions and malformed inputs") {
        const char *const extras[] = {"\"confirm\":true", "\"trust\":true", "\"day\":1",
                                      "\"plan_id\":\"x\"", "\"expected_publisher_pubkey\":\"x\""};
        for (size_t i = 0; i < sizeof(extras)/sizeof(extras[0]); ++i) {
            int n = snprintf(args, sizeof(args), "{\"name\":\"skycombat\",\"output\":\"%s/share\",%s}", m->root, extras[i]);
            ASSERT(n > 0 && (size_t)n < sizeof(args));
            ASSERT(ma_tool(m, 83 + (int)i, "apps_share", args));
            ASSERT(ma_has(m, "\"isError\":true") && ma_has(m, "BAD_ARGUMENT"));
        }
        ASSERT(ma_tool(m, 89, "apps_share", "{\"name\":\"skycombat\",\"output\":\"relative\"}"));
        ASSERT(ma_has(m, "\"isError\":true") && ma_has(m, "BAD_ARGUMENT"));
        int n = snprintf(args, sizeof(args),
            "{\"name\":true,\"output\":\"%s/share\"}", m->root);
        ASSERT(n > 0 && (size_t)n < sizeof(args));
        ASSERT(ma_tool(m, 90, "apps_share", args));
        ASSERT(ma_has(m, "\"isError\":true") && ma_has(m, "BAD_ARGUMENT"));
        n = snprintf(args, sizeof(args),
            "{\"name\":\"one\",\"name\":\"two\",\"output\":\"%s/share\"}", m->root);
        ASSERT(n > 0 && (size_t)n < sizeof(args));
        ASSERT(ma_tool(m, 91, "apps_share", args));
        ASSERT(ma_has(m, "\"isError\":true") && ma_has(m, "BAD_ARGUMENT"));
        PASS();
    } _test_next:;
    return failures;
}
static int case_share_policy(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    TEST("share exemption is limited to native owner-local app.share") {
        const struct zcl_command_spec *share = zcl_command_registry_find(reg, "app.share", NULL);
        const struct zcl_command_spec *receive = zcl_command_registry_find(reg, "app.receive", NULL);
        ASSERT(share && receive && mcp_policy_app_share(share));
        ASSERT(!mcp_policy_app_share(receive) && mcp_policy_app_receive(receive));
        struct zcl_command_spec altered = *share;
        altered.authority = ZCL_COMMAND_AUTH_PUBLIC; ASSERT(!mcp_policy_app_share(&altered));
        altered = *share; altered.scope = ZCL_COMMAND_SCOPE_NODE; ASSERT(!mcp_policy_app_share(&altered));
        altered = *share; altered.transports = 0; ASSERT(!mcp_policy_app_share(&altered));
        altered = *share; altered.transports |= ZCL_COMMAND_TRANSPORT_RPC; ASSERT(!mcp_policy_app_share(&altered));
        PASS();
    } _test_next:;
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
        const struct zcl_command_spec *keep = zcl_command_registry_find(reg, "app.keep", NULL);
        ASSERT(keep && mcp_policy_app_keep(keep) && !mcp_policy_app_keep(open));
        const struct zcl_command_spec *adopt = zcl_command_registry_find(reg, "app.adopt", NULL);
        ASSERT(adopt && mcp_policy_app_adopt(adopt) && !mcp_policy_app_adopt(open));
        struct zcl_command_spec altered = *adopt;
        altered.authority = ZCL_COMMAND_AUTH_PUBLIC;
        ASSERT(!mcp_policy_app_adopt(&altered));
        altered = *adopt; altered.scope = ZCL_COMMAND_SCOPE_NODE;
        ASSERT(!mcp_policy_app_adopt(&altered));
        ASSERT(!mcp_policy_allows(adopt, reg, &empty, &why));
        ASSERT_STR_EQ(why.code, "MUTATION_REFUSED_OWNER_AUTHORITY");
        ASSERT(!mcp_policy_allows(keep, reg, &empty, &why));
        ASSERT_STR_EQ(why.code, "KEEP_NATIVE_CONFIRMATION_REQUIRED");
        json_free(&empty);
    PASS(); }
_test_next:;
    return failures;
}

/* These requests use the real MCP child above, not a presenter shortcut.
 * The missing kept choice deterministically stops before a native window. */
static bool ma_no_personalize_key(const struct ma *m)
{
    char path[PATH_MAX + 64]; struct stat st;
    int n = snprintf(path, sizeof(path), "%s/.z23/zcode_publisher.key", m->root);
    return n > 0 && (size_t)n < sizeof(path) &&
        lstat(path, &st) != 0 && errno == ENOENT;
}
static int case_personalize_request(struct ma *m)
{
    int failures = 0;
    TEST("apps_personalize reaches the exact native owner handler without creating identity") {
        ASSERT(ma_no_personalize_key(m));
        ASSERT(ma_tool(m, 200, "apps_personalize",
            "{\"name\":\"kept:missing\",\"expected_revision\":1}"));
        ASSERT(ma_has(m, "\"isError\":true"));
        ASSERT(ma_has(m, "\\\"command\\\":\\\"app.personalize\\\""));
        ASSERT(ma_has(m, "SELECTION_UNAVAILABLE"));
        ASSERT(!ma_has(m, "MUTATION_REFUSED_OWNER_AUTHORITY"));
        ASSERT(ma_no_personalize_key(m));
        PASS();
    } _test_next:;
    return failures;
}
static int case_personalize_refusals(struct ma *m)
{
    static const char *const bad[] = {
        "{}", "{\"name\":\"kept:missing\"}", "{\"expected_revision\":1}",
        "{\"name\":true,\"expected_revision\":1}",
        "{\"name\":\"\",\"expected_revision\":1}",
        "{\"name\":\"kept:missing\",\"expected_revision\":\"1\"}",
        "{\"name\":\"kept:missing\",\"expected_revision\":true}",
        "{\"name\":\"kept:missing\",\"expected_revision\":0}",
        "{\"name\":\"kept:missing\",\"expected_revision\":-1}",
        "{\"name\":\"kept:missing\",\"expected_revision\":1,\"confirm\":true}",
        "{\"name\":\"kept:missing\",\"expected_revision\":1,\"confirm\":false}",
        "{\"name\":\"kept:missing\",\"expected_revision\":1,\"plan_id\":\"forged\"}",
        "{\"name\":\"kept:missing\",\"expected_revision\":1,\"copy\":\"forbidden\"}",
        "{\"name\":\"kept:missing\",\"expected_revision\":1,\"datadir\":\"forbidden\"}",
        "{\"name\":\"kept:missing\",\"expected_revision\":1,\"version\":\"forged\"}",
        "{\"name\":\"kept:missing\",\"expected_revision\":1,\"expected_head\":\"forged\"}",
        "{\"name\":\"kept:missing\",\"expected_revision\":1,\"unknown\":true}",
        "{\"name\":\"kept:missing\",\"name\":\"kept:other\",\"expected_revision\":1}",
        "{\"name\":\"kept:missing\",\"expected_revision\":1,\"expected_revision\":2}",
        "{\"name\":\"kept:missing\",\"name\":\"kept:other\"}"
    };
    int failures = 0;
    TEST("apps_personalize rejects malformed, mixed, duplicate and caller decision inputs") {
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
            ASSERT(ma_tool(m, 201 + (int)i, "apps_personalize", bad[i]));
            ASSERT(ma_has(m, "\"isError\":true") && ma_has(m, "BAD_ARGUMENT"));
            ASSERT(!ma_has(m, "SELECTION_UNAVAILABLE"));
        }
        ASSERT(ma_no_personalize_key(m));
        PASS();
    } _test_next:;
    return failures;
}
static int case_personalize_rpc_shape(struct ma *m)
{
    int failures = 0;
    TEST("apps_personalize non-object arguments are a protocol error before dispatch") {
        ASSERT(ma_tool(m, 229, "apps_personalize", "[]"));
        ASSERT(ma_has(m, "\"code\":-32602"));
        ASSERT(ma_has(m, "arguments must be an object"));
        ASSERT(!ma_has(m, "SELECTION_UNAVAILABLE"));
        ASSERT(ma_no_personalize_key(m));
        PASS();
    } _test_next:;
    return failures;
}
static int case_personalize_generic_refusal(struct ma *m)
{
    int failures = 0;
    TEST("z23_run cannot use the native personalization allowance") {
        ASSERT(ma_tool(m, 230, "z23_run",
            "{\"path\":\"app.personalize\",\"input\":{\"name\":\"kept:missing\",\"expected_revision\":1}}"));
        ASSERT(ma_has(m, "\"isError\":true") &&
            ma_has(m, "MUTATION_REFUSED_OWNER_AUTHORITY"));
        ASSERT(!ma_has(m, "SELECTION_UNAVAILABLE"));
        ASSERT(ma_no_personalize_key(m));
        PASS();
    } _test_next:;
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
    failures += case_keep_policy_stable();
    failures += case_receive_policy();
    failures += case_share_policy();
    TEST("fixture: a temporary HOME, apps.tsv and a running server") {
        ASSERT(ma_fixture(&m));
        ASSERT(ma_spawn(&m));
        started = true;
        ASSERT(ma_init(&m));
    PASS(); }
    failures += case_apps_tools(&m, &app_pid);
    failures += case_selected_forwarding(&m);
    failures += case_open_list_gates(&m);
    failures += case_keep_forwarding(&m);
    failures += case_keep_decisions(&m);
    failures += case_adopt_request(&m);
    failures += case_receive_request(&m);
    failures += case_receive_injections(&m);
    failures += case_receive_defaults(&m);
    failures += case_receive_default_refusals(&m);
    failures += case_share_request(&m);
    failures += case_share_injections(&m);
    failures += case_personalize_request(&m);
    failures += case_personalize_refusals(&m);
    failures += case_personalize_rpc_shape(&m);
    failures += case_personalize_generic_refusal(&m);
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
