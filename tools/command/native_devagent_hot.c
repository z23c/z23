/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.agent.hot — rung one of the evidence ladder: one saved file
 *          to the verdict of its owning test group, hot-swapped when a
 *          resident dev loop exists and rebuilt otherwise.
 *
 * ── CONTRACT (this file is the whole implementation) ──────────────────────
 *
 * WHY. After saving a file an agent needs the cheapest check that can refute
 * the change, and composing it by hand means remembering the file-to-proof
 * route, the exact runner argv, and the SUITE VERDICT line. This leaf runs
 * that one check: resolve the owning group exactly the way code.tests does,
 * run it through build/bin/test_parallel --no-cache, and report the
 * verdict with an honest wall clock.
 *
 * INPUT (zcl.agent_hot_input.v1)
 *   path   required string. Repo-relative source file, e.g.
 *          "tools/command/native_devagent_hot.c". Absolute paths and any
 *          path containing ".." are refused: the leaf inspects one file
 *          inside the directory it was asked about.
 *   group  optional string. Explicit owning group; must resolve to exactly
 *          one registered group (full or legacy prefixless id). An unknown
 *          name is UNRESOLVED, never a run of something nearby.
 *   cwd    optional string. Directory to inspect instead of the process
 *          working directory. Exists so a fixture repository can be
 *          inspected; the owning-group route itself is pure and needs no
 *          checkout.
 *
 * OUTPUT (zcl.agent_hot.v1) on every verdict — PASS, FAIL, NOSHA and
 * UNRESOLVED alike are ok=true, because a verdict IS the answer
 *   leaf        "dev.agent.hot"
 *   path        the input path, verbatim
 *   group       the owning group exactly as code.tests routes it (or the
 *               override verbatim); "" when no owning group exists
 *   mode        "hotswap" when a resident dev loop owned the checkout (the
 *               rebuild is skipped because the loop already built the
 *               changed module and hot-swapped it), "rebuild" when the
 *               group ran through the test runner without a loop,
 *               "unresolved" when no owning group exists
 *   hotswapped  whether the executed run actually ran against a
 *               hot-swapped module, as the runner's own SUITE VERDICT
 *               line reports it — kept apart from mode, which only says
 *               which path the leaf took
 *   groups_ran, groups_failed, self_skips
 *               ints from the runner's SUITE VERDICT line (0,0,0 when no
 *               group ran); groups_ran is the only field that proves
 *               execution
 *   elapsed_ms  wall clock of the whole leaf, first clock read to reply
 *   verdict     "PASS" (groups_ran>=1 and groups_failed==0), "FAIL"
 *               (groups_failed>0), "NOSHA" (nothing executed),
 *               "UNRESOLVED" (no owning group)
 *   next        exactly one command: ["make lint-fast"] on PASS,
 *               ["ulimit -s unlimited; make -s t-fast ONLY=<group>"] on
 *               FAIL, the gated opt-in rerun on NOSHA, and
 *               ["build/bin/z23-dev code tests
 *               --input='{\"path\":\"<path>\"}'"] on UNRESOLVED
 *
 * FAILURE. ok=false only when no verdict exists:
 *   BAD_INPUT    path missing, empty, absolute, escaping, or longer than
 *                the transport admits
 *   FILE_NOT_FOUND  path not readable under the inspected directory
 *   RUNNER_FAILED   no checkout root above the inspected directory, the
 *                rebuild failed, the runner could not start, or its
 *                transcript carried no SUITE VERDICT line; the message
 *                always names the argv so the reader can rerun it
 *
 * PROCESS RULE. The group runs only through zcl_devagent_run_group() and
 * the rebuild only through zcl_devagent_run_make() from
 * command/native_devagent.h — the same code path dev.agent.test and
 * dev.agent.mutate use. No second runner, no shell, no popen()/system().
 * Dev builds read residency through the watcher's own probe. Other builds
 * do not link the watcher and always take the rebuild path.
 * The leaf starts no node, touches no datadir, and writes nothing itself;
 * make and the runner write only under the checkout's build/.
 *
 * Implement this file only; the test
 * tests/harness/src/test_devagent_hot.c is the acceptance bar and must
 * not be edited.
 */

#include "command/native_command.h"
#include "command/native_dev_loop_command.h"
#include "command/native_devagent.h"

#include "controllers/agent_impact_rules.h"
#include "dev/test_group_catalog.h"
#include "json/json.h"
#include "platform/time_compat.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define DVH_LEAF "dev.agent.hot"

/* The leaf answers "did it run NOW", so a stale runner binary is refused,
 * not run. Same ceilings dev.agent.mutate rebuilds and runs under. */
#define DVH_BUILD_TIMEOUT_MS 1200000
#define DVH_TEST_TIMEOUT_MS  900000

/* The resident-loop probe lives in the dev-only watcher section of
 * native_dev_command.c, so release and test binaries link no such symbol.
 * Guard the reference with the definition's build flag so non-dev links
 * require no watcher symbol. Without that probe the leaf must rebuild. */
static bool dvh_loop_resident(const char *root)
{
#ifdef ZCL_DEV_BUILD
    return zcl_native_dev_loop_proof_queue_ready(root);
#else
    (void)root;
    return false;
#endif
}

/* A refusal that does not name the command that fixes it is a dead end. */
static void dvh_refuse(struct zcl_command_reply *reply,
                       enum zcl_command_status status,
                       enum zcl_command_exit exit_code, const char *code,
                       const char *phase, const char *message,
                       const char *evidence, const char *next_action)
{
    zcl_command_reply_fail(reply, status, exit_code, code, phase, false, false,
                           message, evidence);
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                   "%s", next_action ? next_action : "");
    reply->error.human_action_required = true;
}

static const char *dvh_str(const struct json_value *input, const char *key)
{
    const struct json_value *v = input ? json_get(input, key) : NULL;
    return v && v->type == JSON_STR ? json_get_str(v) : NULL;
}

static int64_t dvh_elapsed_ms(int64_t t0_ms)
{
    int64_t now_ms = platform_time_monotonic_ms();
    return now_ms >= t0_ms ? now_ms - t0_ms : 0;
}

static void dvh_push_next(struct json_value *data, const char *command)
{
    struct json_value arr;
    struct json_value item;
    json_init(&arr);
    json_set_array(&arr);
    json_init(&item);
    json_set_str(&item, command ? command : "");
    (void)json_push_back(&arr, &item);
    json_free(&item);
    (void)json_push_kv(data, "next", &arr);
    json_free(&arr);
}

/* The UNRESOLVED verdict: the file exists but no rule owns it, or the
 * override names no registered group. No checkout root is needed — the
 * route is pure — and nothing runs. */
static void dvh_emit_unresolved(struct zcl_command_reply *reply,
                                const char *path, int64_t t0_ms)
{
    char next[512];
    (void)snprintf(next, sizeof(next),
                   "build/bin/z23-dev code tests --input='{\"path\":\"%s\"}'",
                   path ? path : "");
    (void)json_push_kv_str(&reply->data, "leaf", DVH_LEAF);
    (void)json_push_kv_str(&reply->data, "path", path ? path : "");
    (void)json_push_kv_str(&reply->data, "group", "");
    (void)json_push_kv_str(&reply->data, "mode", "unresolved");
    (void)json_push_kv_bool(&reply->data, "hotswapped", false);
    (void)json_push_kv_int(&reply->data, "groups_ran", 0);
    (void)json_push_kv_int(&reply->data, "groups_failed", 0);
    (void)json_push_kv_int(&reply->data, "self_skips", 0);
    (void)json_push_kv_int(&reply->data, "elapsed_ms",
                           dvh_elapsed_ms(t0_ms));
    (void)json_push_kv_str(&reply->data, "verdict", "UNRESOLVED");
    dvh_push_next(&reply->data, next);
}

/* First matched shared-rule group that is a registered group, in route
 * order. A rule hit that names nothing registered is not ownership — the
 * floor the router falls back to is the absence of a signal, not a group. */
static bool dvh_owned_route_group(const struct agent_impact_acc *acc,
                                  char out[ZCL_TEST_GROUP_FULL_MAX])
{
    if (!acc || !out)
        return false;
    for (size_t i = 0; i < acc->groups_len; i++) {
        if (acc->groups[i] &&
            zcl_test_group_resolve_exact(acc->groups[i], out))
            return true;
    }
    return false;
}

void zcl_native_handle_dev_agent_hot(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    int64_t t0_ms = platform_time_monotonic_ms();
    const struct json_value *input = request->input;

    const char *path = dvh_str(input, "path");
    if (!path || !path[0]) {
        dvh_refuse(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                   "BAD_INPUT", "validate",
                   "dev.agent.hot requires a repo-relative source file in "
                   "`path`",
                   "path", "z23 dev agent hot --path=<repo-relative file>");
        return;
    }
    if (path[0] == '/' || strstr(path, "..") != NULL ||
        strlen(path) >= (size_t)PATH_MAX) {
        dvh_refuse(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                   "BAD_INPUT", "validate",
                   "path must be a repo-relative source file inside the "
                   "inspected directory",
                   path, "z23 dev agent hot --path=<repo-relative file>");
        return;
    }

    const char *cwd = dvh_str(input, "cwd");
    char dir[PATH_MAX];
    if (cwd && cwd[0])
        (void)snprintf(dir, sizeof(dir), "%s", cwd);
    else if (!getcwd(dir, sizeof(dir)))
        (void)snprintf(dir, sizeof(dir), "%s", ".");

    char full[PATH_MAX];
    int joined = snprintf(full, sizeof(full), "%s/%s", dir, path);
    if (joined <= 0 || (size_t)joined >= sizeof(full) ||
        access(full, R_OK) != 0) {
        char next[512];
        (void)snprintf(next, sizeof(next),
                       "save the file first, then rerun: z23 dev agent hot "
                       "--path=%s",
                       path);
        dvh_refuse(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                   "FILE_NOT_FOUND", "resolve",
                   "the saved file is not readable under the inspected "
                   "directory",
                   full[0] ? full : path, next);
        return;
    }

    /* ── owning group: the override, or the code.tests route ─────────── */
    char wanted[ZCL_TEST_GROUP_FULL_MAX];
    char group[ZCL_TEST_GROUP_FULL_MAX];
    const char *override = dvh_str(input, "group");
    if (override && override[0]) {
        if (!zcl_test_group_resolve_exact(override, wanted)) {
            dvh_emit_unresolved(reply, path, t0_ms);
            return;
        }
        (void)snprintf(group, sizeof(group), "%s", override);
    } else {
        struct agent_impact_acc acc;
        bool consensus_risk = false;
        const char *route = NULL;
        memset(&acc, 0, sizeof(acc));
        route = zcl_native_code_route_for_path(path, &acc, &consensus_risk);
        if (!route)
            route = "";
        if (consensus_risk) {
            if (!zcl_test_group_resolve_exact(route, wanted)) {
                dvh_emit_unresolved(reply, path, t0_ms);
                return;
            }
        } else if (!dvh_owned_route_group(&acc, wanted)) {
            dvh_emit_unresolved(reply, path, t0_ms);
            return;
        }
        (void)snprintf(group, sizeof(group), "%s", route);
    }

    /* ── resident loop or rebuild ──────────────────────────────────────
     * A resident dev loop already built the changed module and hot-swapped
     * it, so the group runs as-is. Without one the runner is rebuilt
     * first: a verdict off a stale binary is a refusal, not a shortcut. */
    char root[PATH_MAX];
    if (!zcl_devagent_checkout_root(cwd && cwd[0] ? cwd : NULL, root,
                                    sizeof(root))) {
        char msg[640];
        (void)snprintf(msg, sizeof(msg),
                       "no Z23 checkout root above '%s'; cannot locate "
                       "build/bin/test_parallel --exact=%s --no-cache",
                       dir, wanted);
        dvh_refuse(reply, ZCL_COMMAND_STATUS_BLOCKED,
                   ZCL_COMMAND_EXIT_BLOCKED, "RUNNER_FAILED", "precondition",
                   "the owning group is known but no checkout here can run "
                   "it",
                   msg, "cd into a Z23 checkout, then rerun");
        return;
    }
    bool loop_resident = dvh_loop_resident(root);
    if (!loop_resident) {
        int build_rc = zcl_devagent_run_make(root, "test_parallel",
                                             DVH_BUILD_TIMEOUT_MS);
        if (build_rc != 0) {
            char msg[640];
            (void)snprintf(msg, sizeof(msg),
                           "make --no-print-directory test_parallel exited "
                           "%d in '%s'; rerun it by hand, then rerun this "
                           "leaf",
                           build_rc, root);
            dvh_refuse(reply, ZCL_COMMAND_STATUS_FAILED,
                       ZCL_COMMAND_EXIT_FAILED, "RUNNER_FAILED", "build", msg,
                       msg, "make -j\"$(getconf _NPROCESSORS_ONLN)\" "
                       "test_parallel");
            return;
        }
    }

    char selector[128];
    char command_line[512];
    (void)snprintf(selector, sizeof(selector), "--exact=%s", wanted);
    (void)snprintf(command_line, sizeof(command_line),
                   "%s/build/bin/test_parallel %s --no-cache", root,
                   selector);
    struct zcl_devagent_verdict vd;
    bool truncated = false;
    int run_rc = zcl_devagent_run_group(root, selector, DVH_TEST_TIMEOUT_MS,
                                        &vd, &truncated);
    if (run_rc < 0 || !vd.present) {
        char msg[640];
        (void)snprintf(msg, sizeof(msg),
                       run_rc < 0
                           ? "the runner could not start: %s (exit %d)"
                           : "the runner printed no SUITE VERDICT line: %s "
                             "(exit %d); nothing about this run may be read "
                             "as a pass",
                       command_line, run_rc);
        dvh_refuse(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                   "RUNNER_FAILED", "verify", msg, command_line,
                   command_line);
        return;
    }

    long long ran = vd.groups_ran < 0 ? 0 : vd.groups_ran;
    long long failed = vd.groups_failed < 0 ? 0 : vd.groups_failed;
    long long skips = vd.self_skips < 0 ? 0 : vd.self_skips;
    const char *verdict = failed > 0 ? "FAIL" : ran >= 1 ? "PASS" : "NOSHA";
    char next[512];
    if (verdict[0] == 'P')
        (void)snprintf(next, sizeof(next), "%s", "make lint-fast");
    else if (verdict[0] == 'F')
        (void)snprintf(next, sizeof(next),
                       "ulimit -s unlimited; make -s t-fast ONLY=%s", group);
    else
        (void)snprintf(next, sizeof(next),
                       "ZCL_STRESS_TESTS=1 ZCL_PARAMS_TESTS=1 z23 dev agent "
                       "test --group=%s --exact=true",
                       group);

    (void)json_push_kv_str(&reply->data, "leaf", DVH_LEAF);
    (void)json_push_kv_str(&reply->data, "path", path);
    (void)json_push_kv_str(&reply->data, "group", group);
    (void)json_push_kv_str(&reply->data, "mode",
                           loop_resident ? "hotswap" : "rebuild");
    (void)json_push_kv_bool(&reply->data, "hotswapped", vd.hotswap);
    (void)json_push_kv_int(&reply->data, "groups_ran", ran);
    (void)json_push_kv_int(&reply->data, "groups_failed", failed);
    (void)json_push_kv_int(&reply->data, "self_skips", skips);
    (void)json_push_kv_int(&reply->data, "elapsed_ms",
                           dvh_elapsed_ms(t0_ms));
    (void)json_push_kv_str(&reply->data, "verdict", verdict);
    dvh_push_next(&reply->data, next);
}
