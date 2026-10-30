/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_ops_node_restart - `ops node restart`
 * (tools/command/native_ops_node_restart.c).
 *
 * The property under test: the node unit is restarted only by a confirm call
 * that carries the plan_id of a live, unused plan, and only the unit that the
 * plan reported; a plan, a wrong, used or expired plan_id and a destructive
 * option never restart it; a node that stays silent is reported as a failure
 * within the wait bound; and a host with no single, unambiguous node unit is
 * refused before anything restarts.
 *
 *   a. plan changes nothing, names the unit and returns a plan_id with the
 *      current height
 *   b. confirm runs exactly one restart of the planned unit and reports the
 *      height and uptime before and after; the plan_id is single use
 *   c. a wrong, missing or mismatched plan_id and plan_id without confirm
 *      are refused
 *   d. an expired plan is refused
 *   e. a silent node is NODE_NOT_ANSWERING within wait_s; an uptime that did
 *      not reset is NOT_RESTARTED; a failing systemctl is RESTART_FAILED
 *   f. reindex, datadir and other options, and a bad wait_s, are refused
 *   g. only zclassic23.service active selects it; only z23-node.service
 *      active selects it
 *   h. both units active is NODE_UNIT_AMBIGUOUS; neither active, or an
 *      unrecognised answer, is NODE_UNIT_NOT_FOUND; none restarts anything
 *   i. a unit that stopped being the only active one between plan and confirm
 *      is NODE_UNIT_CHANGED and nothing restarts
 *
 * Hermetic: a fake systemctl script that answers is-active from per-unit
 * answer files and only appends restarts to a log, a stubbed node RPC and
 * per-pid ./test-tmp directories. The real systemctl and a real node are
 * never reached.
 */

#include "test/test_core.h"

#include "command/native_command.h"

#include "controllers/rpc_client.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/time_compat.h"

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ONR_NEW "z23-node.service"
#define ONR_LEGACY "zclassic23.service"

enum onr_mode { ONR_NORMAL, ONR_SILENT_AFTER, ONR_SAME_UPTIME };

static struct {
    char dir[PATH_MAX], state[PATH_MAX], fake[PATH_MAX], calls[PATH_MAX];
    enum onr_mode mode;
} onr;

struct onr_cmd {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static int onr_check(bool ok, const char *what)
{
    printf("ops_node_restart: %s... %s\n", what, ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static bool onr_put(const char *path, const char *text, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    bool ok;
    if (fd < 0)
        return false;
    ok = write(fd, text, strlen(text)) == (ssize_t)strlen(text);
    close(fd);
    return ok && chmod(path, mode) == 0;
}

static long onr_get(const char *path, char *buf, size_t cap)
{
    int fd = open(path, O_RDONLY);
    ssize_t n;
    if (fd < 0)
        return -1;
    n = read(fd, buf, cap - 1);
    close(fd);
    if (n < 0)
        return -1;
    buf[n] = '\0';
    return (long)n;
}

/* Number of systemctl invocations that were a restart. */
static int onr_restarts(void)
{
    char buf[4096];
    int n = 0;
    if (onr_get(onr.calls, buf, sizeof(buf)) < 0)
        return 0;
    for (const char *p = buf; (p = strstr(p, " restart ")) != NULL; p++)
        n++;
    return n;
}

/* True when the restart log holds exactly one restart, of this unit. */
static bool onr_restarted_only(const char *unit)
{
    char buf[4096], want[PATH_MAX + 32];
    snprintf(want, sizeof(want), "--user restart %s\n", unit);
    return onr_get(onr.calls, buf, sizeof(buf)) > 0 &&
           strcmp(buf, want) == 0;
}

/* A node that answers before the fake restart ran and, per mode, after it. */
static char *onr_rpc(const char *method, const char *params)
{
    bool after = onr_restarts() > 0;
    (void)params;
    if (after && onr.mode == ONR_SILENT_AFTER)
        return strdup("{\"error\":{\"code\":-1,\"message\":\"down\"}}");
    if (strcmp(method, "getblockcount") == 0)
        return strdup(after ? "101" : "100");
    if (strcmp(method, "healthcheck") == 0)
        return strdup(!after ? "{\"checks\":{\"uptime_seconds\":5000}}"
                      : onr.mode == ONR_SAME_UPTIME
                          ? "{\"checks\":{\"uptime_seconds\":6000}}"
                          : "{\"checks\":{\"uptime_seconds\":3}}");
    return strdup("null");
}

/* Sets what the fake systemctl answers to `is-active <unit>`. */
static bool onr_answer(const char *unit, const char *state)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/answer.%s", onr.dir, unit);
    return onr_put(path, state, 0644);
}

static bool onr_init(const char *name)
{
    char cwd[PATH_MAX], rm[PATH_MAX + 16];
    memset(&onr, 0, sizeof(onr));
    if (!getcwd(cwd, sizeof(cwd)))
        return false;
    snprintf(onr.dir, sizeof(onr.dir), "%s/test-tmp/%d_onr_%s", cwd,
             (int)getpid(), name);
    snprintf(rm, sizeof(rm), "rm -rf '%s'", onr.dir);
    TEST_DISCARD(system(rm));
    mkdir("./test-tmp", 0755);
    snprintf(onr.state, sizeof(onr.state), "%s/state", onr.dir);
    snprintf(onr.fake, sizeof(onr.fake), "%s/systemctl", onr.dir);
    snprintf(onr.calls, sizeof(onr.calls), "%s/calls.log", onr.dir);
    if (mkdir(onr.dir, 0755) != 0 ||
        !onr_put(onr.fake,
                 "#!/bin/sh\n"
                 "case \"$1 $2\" in\n"
                 "\"--user is-active\")\n"
                 "  cat \"$FAKE_DIR/answer.$3\" 2>/dev/null || echo inactive\n"
                 "  exit 0 ;;\n"
                 "esac\n"
                 "echo \"$*\" >> \"$FAKE_DIR/calls.log\"\n"
                 "[ -f \"$FAKE_DIR/fail\" ] && exit 1\n"
                 "exit 0\n", 0755) ||
        !onr_answer(ONR_NEW, "active\n") ||
        !onr_answer(ONR_LEGACY, "inactive\n"))
        return false;
    setenv("ZCL_SLOT_STATE_DIR", onr.state, 1);
    setenv("ZCL_SLOT_SYSTEMCTL_BIN", onr.fake, 1);
    setenv("FAKE_DIR", onr.dir, 1);
    node_rpc_client_set_test_hook(onr_rpc);
    return true;
}

static void onr_done(void)
{
    char rm[PATH_MAX + 16];
    node_rpc_client_set_test_hook(NULL);
    snprintf(rm, sizeof(rm), "rm -rf '%s'", onr.dir);
    TEST_DISCARD(system(rm));
}

static void oc_run(struct onr_cmd *c, const char *json)
{
    json_init(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    TEST_DISCARD(json_read(&c->input, json, strlen(json)));
    c->request.input = &c->input;
    zcl_command_reply_init(&c->reply, "zcl.ops_node_restart_test.v1");
    zcl_native_handle_ops_node_restart(&c->request, &c->reply);
}

static void oc_free(struct onr_cmd *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static bool oc_ok(const struct onr_cmd *c)
{
    return c->reply.status == ZCL_COMMAND_STATUS_PASSED &&
           c->reply.exit_code == ZCL_COMMAND_EXIT_OK;
}

static bool oc_code(const struct onr_cmd *c, const char *code)
{
    return c->reply.status != ZCL_COMMAND_STATUS_PASSED &&
           strcmp(c->reply.error.code, code) == 0;
}

static bool oc_unit_is(const struct onr_cmd *c, const char *unit)
{
    const char *u = json_get_str(json_get(&c->reply.data, "unit"));
    return u && strcmp(u, unit) == 0;
}

static int64_t oc_int(const struct onr_cmd *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_INT ? json_get_int(v) : -1;
}

/* Run a plan and copy its plan_id out. */
static bool onr_plan(char id[65], const char *extra)
{
    struct onr_cmd c;
    char json[128];
    bool ok;
    snprintf(json, sizeof(json), "{%s}", extra);
    oc_run(&c, json);
    ok = oc_ok(&c) && json_get_str(json_get(&c.reply.data, "plan_id"))[0];
    if (ok)
        snprintf(id, 65, "%s", json_get_str(json_get(&c.reply.data, "plan_id")));
    oc_free(&c);
    return ok;
}

static void onr_confirm(struct onr_cmd *c, const char *id, const char *extra)
{
    char json[256];
    snprintf(json, sizeof(json), "{\"plan_id\":\"%s\",\"confirm\":true%s%s}",
             id, extra[0] ? "," : "", extra);
    oc_run(c, json);
}

static int test_onr_plan_and_confirm(void)
{
    struct onr_cmd c;
    char id[65] = "";
    int failures = 0;
    bool planned;
    if (!onr_init("flow"))
        return onr_check(false, "fixture");
    oc_run(&c, "{}");
    planned = oc_ok(&c) && strlen(json_get_str(json_get(&c.reply.data,
                                                        "plan_id"))) == 32;
    failures += onr_check(planned && oc_int(&c, "height_now") == 100 &&
                          oc_int(&c, "uptime_s_now") == 5000 &&
                          !json_get_bool(json_get(&c.reply.data, "mutated")),
                          "plan reports the node and a plan_id");
    failures += onr_check(oc_unit_is(&c, ONR_NEW),
                          "plan names z23-node.service");
    failures += onr_check(onr_restarts() == 0 && access(onr.calls, F_OK) != 0,
                          "plan runs no restart");
    oc_free(&c);
    failures += onr_check(onr_plan(id, ""), "second plan");
    onr_confirm(&c, id, "");
    failures += onr_check(oc_ok(&c) && onr_restarts() == 1 &&
                          onr_restarted_only(ONR_NEW),
                          "confirm runs exactly one restart of the node unit");
    failures += onr_check(oc_int(&c, "height_before") == 100 &&
                          oc_int(&c, "height_after") == 101 &&
                          oc_int(&c, "uptime_s_before") == 5000 &&
                          oc_int(&c, "uptime_s_after") == 3 &&
                          strcmp(json_get_str(json_get(&c.reply.data, "note")),
                                 "restarted, answering at height 101") == 0,
                          "reply reports before and after");
    oc_free(&c);
    onr_confirm(&c, id, "");
    failures += onr_check(oc_code(&c, "PLAN_MISMATCH") && onr_restarts() == 1,
                          "a used plan_id is refused and nothing restarts");
    oc_free(&c);
    onr_done();
    return failures;
}

static int test_onr_refusals(void)
{
    struct onr_cmd c;
    char id[65] = "";
    int failures = 0;
    if (!onr_init("refuse") || !onr_plan(id, ""))
        return onr_check(false, "fixture");
    onr_confirm(&c, "00000000000000000000000000000000", "");
    failures += onr_check(oc_code(&c, "PLAN_MISMATCH"), "wrong plan_id");
    oc_free(&c);
    oc_run(&c, "{\"confirm\":true}");
    failures += onr_check(oc_code(&c, "PLAN_MISMATCH"),
                          "confirm without plan_id");
    oc_free(&c);
    onr_confirm(&c, id, "\"wait_s\":30");
    failures += onr_check(oc_code(&c, "PLAN_MISMATCH"),
                          "confirm with another wait_s than planned");
    oc_free(&c);
    {
        char json[128];
        snprintf(json, sizeof(json), "{\"plan_id\":\"%s\"}", id);
        oc_run(&c, json);
        failures += onr_check(oc_code(&c, "CONFIRM_REQUIRED"),
                              "plan_id without confirm");
        oc_free(&c);
    }
    failures += onr_check(onr_restarts() == 0, "no refusal restarted");
    onr_confirm(&c, id, "");
    failures += onr_check(oc_ok(&c) && onr_restarts() == 1,
                          "the live plan still works after refusals");
    oc_free(&c);
    onr_done();
    return failures;
}

static int test_onr_expired(void)
{
    struct onr_cmd c;
    char path[PATH_MAX];
    int failures = 0;
    if (!onr_init("expired"))
        return onr_check(false, "fixture");
    mkdir(onr.state, 0755);
    snprintf(path, sizeof(path), "%s/node-restart.plan", onr.state);
    onr_put(path, "0123456789abcdef0123456789abcdef 1 120 " ONR_NEW "\n", 0600);
    onr_confirm(&c, "0123456789abcdef0123456789abcdef", "");
    failures += onr_check(oc_code(&c, "PLAN_EXPIRED") && onr_restarts() == 0,
                          "an expired plan_id is refused, nothing restarts");
    oc_free(&c);
    onr_confirm(&c, "0123456789abcdef0123456789abcdef", "");
    failures += onr_check(oc_code(&c, "PLAN_MISMATCH"),
                          "an expired plan is dropped");
    oc_free(&c);
    onr_done();
    return failures;
}

static int test_onr_failures(void)
{
    struct onr_cmd c;
    char id[65] = "", path[PATH_MAX];
    int64_t t0, took;
    int failures = 0;
    if (!onr_init("fail") || !onr_plan(id, "\"wait_s\":1"))
        return onr_check(false, "fixture");
    onr.mode = ONR_SILENT_AFTER;
    t0 = platform_time_monotonic_ms();
    onr_confirm(&c, id, "\"wait_s\":1");
    took = platform_time_monotonic_ms() - t0;
    failures += onr_check(oc_code(&c, "NODE_NOT_ANSWERING") && took < 6000 &&
                          onr_restarts() == 1,
                          "a silent node fails within the wait bound");
    oc_free(&c);
    onr.mode = ONR_SAME_UPTIME;
    snprintf(path, sizeof(path), "%s/calls.log", onr.dir);
    unlink(path);
    failures += onr_check(onr_plan(id, ""), "plan");
    onr_confirm(&c, id, "");
    failures += onr_check(oc_code(&c, "NOT_RESTARTED"),
                          "an uptime that did not reset is not a restart");
    oc_free(&c);
    onr.mode = ONR_NORMAL;
    snprintf(path, sizeof(path), "%s/fail", onr.dir);
    onr_put(path, "", 0644);
    unlink(onr.calls);
    failures += onr_check(onr_plan(id, ""), "plan");
    onr_confirm(&c, id, "");
    failures += onr_check(oc_code(&c, "RESTART_FAILED"),
                          "a failing systemctl is RESTART_FAILED");
    oc_free(&c);
    onr_done();
    return failures;
}

static int test_onr_options(void)
{
    static const char *const bad[] = {
        "{\"reindex\":true}", "{\"datadir\":\"/srv/other\"}",
        "{\"exec_args\":\"-reindex\",\"confirm\":true}", "{\"wipe\":1}"
    };
    struct onr_cmd c;
    int failures = 0;
    if (!onr_init("options"))
        return onr_check(false, "fixture");
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        oc_run(&c, bad[i]);
        failures += onr_check(oc_code(&c, "UNKNOWN_OPTION"), bad[i]);
        oc_free(&c);
    }
    oc_run(&c, "{\"wait_s\":0}");
    failures += onr_check(oc_code(&c, "BAD_WAIT"), "wait_s 0");
    oc_free(&c);
    oc_run(&c, "{\"wait_s\":121}");
    failures += onr_check(oc_code(&c, "BAD_WAIT"), "wait_s 121");
    oc_free(&c);
    failures += onr_check(onr_restarts() == 0 && access(onr.calls, F_OK) != 0,
                          "no refused option reached systemctl");
    onr_done();
    return failures;
}

static int test_onr_legacy_only(void)
{
    struct onr_cmd c;
    char id[65] = "";
    int failures = 0;
    if (!onr_init("legacy") || !onr_answer(ONR_NEW, "inactive\n") ||
        !onr_answer(ONR_LEGACY, "active\n"))
        return onr_check(false, "fixture");
    oc_run(&c, "{}");
    failures += onr_check(oc_ok(&c) && oc_unit_is(&c, ONR_LEGACY),
                          "only zclassic23.service active: plan selects it");
    snprintf(id, sizeof(id), "%s",
             json_get_str(json_get(&c.reply.data, "plan_id")));
    oc_free(&c);
    onr_confirm(&c, id, "");
    failures += onr_check(oc_ok(&c) && onr_restarted_only(ONR_LEGACY) &&
                          oc_unit_is(&c, ONR_LEGACY),
                          "confirm restarts only zclassic23.service");
    oc_free(&c);
    onr_done();
    return failures;
}

static int test_onr_new_only(void)
{
    struct onr_cmd c;
    char id[65] = "";
    int failures = 0;
    if (!onr_init("newonly") || !onr_answer(ONR_LEGACY, "inactive\n"))
        return onr_check(false, "fixture");
    oc_run(&c, "{}");
    failures += onr_check(oc_ok(&c) && oc_unit_is(&c, ONR_NEW),
                          "only z23-node.service active: plan selects it");
    snprintf(id, sizeof(id), "%s",
             json_get_str(json_get(&c.reply.data, "plan_id")));
    oc_free(&c);
    onr_confirm(&c, id, "");
    failures += onr_check(oc_ok(&c) && onr_restarted_only(ONR_NEW),
                          "confirm restarts only z23-node.service");
    oc_free(&c);
    onr_done();
    return failures;
}

static int test_onr_ambiguous(void)
{
    struct onr_cmd c;
    int failures = 0;
    if (!onr_init("both") || !onr_answer(ONR_LEGACY, "active\n"))
        return onr_check(false, "fixture");
    oc_run(&c, "{}");
    failures += onr_check(oc_code(&c, "NODE_UNIT_AMBIGUOUS"),
                          "both units active is refused at plan");
    oc_free(&c);
    failures += onr_check(onr_restarts() == 0 && access(onr.calls, F_OK) != 0,
                          "both active: no restart call");
    onr_done();
    return failures;
}

static int test_onr_not_found(void)
{
    struct onr_cmd c;
    int failures = 0;
    if (!onr_init("none") || !onr_answer(ONR_NEW, "inactive\n"))
        return onr_check(false, "fixture");
    oc_run(&c, "{}");
    failures += onr_check(oc_code(&c, "NODE_UNIT_NOT_FOUND"),
                          "neither unit active is refused at plan");
    oc_free(&c);
    failures += onr_check(onr_restarts() == 0 && access(onr.calls, F_OK) != 0,
                          "neither active: no restart call");
    onr_done();
    if (!onr_init("unknown") || !onr_answer(ONR_NEW, "bogus\n"))
        return failures + onr_check(false, "fixture");
    oc_run(&c, "{}");
    failures += onr_check(oc_code(&c, "NODE_UNIT_NOT_FOUND"),
                          "an unrecognised answer is refused, never clear");
    oc_free(&c);
    failures += onr_check(onr_restarts() == 0 && access(onr.calls, F_OK) != 0,
                          "unrecognised answer: no restart call");
    onr_done();
    return failures;
}

static int test_onr_unit_changed(void)
{
    struct onr_cmd c;
    char id[65] = "";
    int failures = 0;
    if (!onr_init("changed") || !onr_plan(id, ""))
        return onr_check(false, "fixture");
    if (!onr_answer(ONR_NEW, "inactive\n") || !onr_answer(ONR_LEGACY, "active\n"))
        return failures + onr_check(false, "fixture");
    onr_confirm(&c, id, "");
    failures += onr_check(oc_code(&c, "NODE_UNIT_CHANGED") &&
                          onr_restarts() == 0 && access(onr.calls, F_OK) != 0,
                          "active unit changed since plan: refused, no restart");
    oc_free(&c);
    onr_done();
    return failures;
}

/* A plan file in the pre-unit format (three fields, no unit) is not a plan
 * this build recorded: it must be refused and must not restart anything. */
static int test_onr_old_plan_format(void)
{
    struct onr_cmd c;
    char path[PATH_MAX];
    int failures = 0;
    if (!onr_init("oldplan"))
        return onr_check(false, "fixture");
    mkdir(onr.state, 0755);
    snprintf(path, sizeof(path), "%s/node-restart.plan", onr.state);
    onr_put(path, "0123456789abcdef0123456789abcdef 4102444800 120\n", 0600);
    onr_confirm(&c, "0123456789abcdef0123456789abcdef", "");
    failures += onr_check(oc_code(&c, "PLAN_MISMATCH") && onr_restarts() == 0 &&
                          access(onr.calls, F_OK) != 0,
                          "a three-field plan file is refused, no restart");
    oc_free(&c);
    onr_done();
    return failures;
}

int test_ops_node_restart(void)
{
    int failures = 0;
    printf("\n=== ops node restart tests ===\n");
    failures += test_onr_plan_and_confirm();
    failures += test_onr_refusals();
    failures += test_onr_expired();
    failures += test_onr_failures();
    failures += test_onr_options();
    failures += test_onr_legacy_only();
    failures += test_onr_new_only();
    failures += test_onr_ambiguous();
    failures += test_onr_not_found();
    failures += test_onr_old_plan_format();
    failures += test_onr_unit_changed();
    printf("=== OPS_NODE_RESTART: %d failure(s) ===\n", failures);
    return failures;
}
