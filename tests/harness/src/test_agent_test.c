/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the agenttest native contract
 * (cognition/controllers/src/agent_test_controller.c) and the backing
 * tools/agent_test_runner.sh, cloned from tests/harness/src/test_agent_copy_prove.c.
 *
 * Entirely hermetic: every fixture lives under ./test-tmp/, the status dir
 * is always overridden to an isolated tmp dir, and the runner script is
 * swapped for a tiny stub in the launch+poll test so no real
 * test_parallel/zclassic23-chaos process is ever spawned by this file
 * except in the one real-script sub-test. Cover:
 *   - rpc_agent_test() param validation / refusal paths for both kind
 *     values: invalid kind, invalid name charset (path traversal / shell
 *     metacharacters / too long), a missing scenario file (no subprocess
 *     ever spawned for these — validation fails first)
 *   - rpc_agent_test() successful async launch against a tiny stub
 *     script standing in for tools/agent_test_runner.sh, then polling the
 *     result back out through agent_test_dump_state_json()
 *   - the real tools/agent_test_runner.sh against a synthetic scenario
 *     fixture (no test_parallel/chaos binary needed — the scenario-not-
 *     found path is exercised directly, exit code + JSON schema checked)
 */

#include "test/test_core.h"
#include "controllers/agent_test_controller.h"
#include "json/json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define AT_CHECK(name, expr) do { \
    printf("%s... ", (name)); \
    if (expr) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* ── env save/restore ─────────────────────────────────────────────── */

struct at_saved_env {
    const char *name;
    char value[1200];
    bool was_set;
};

static void at_env_save(struct at_saved_env *s, const char *name)
{
    s->name = name;
    const char *v = getenv(name);
    s->was_set = v != NULL;
    if (v) snprintf(s->value, sizeof(s->value), "%s", v);
}

static void at_env_restore(const struct at_saved_env *s)
{
    if (s->was_set) setenv(s->name, s->value, 1);
    else unsetenv(s->name);
}

/* ── small helpers ────────────────────────────────────────────────── */

static bool at_write_file(const char *path, const char *content)
{
    FILE *f = fopen(path, "w");
    if (!f) return false;
    fputs(content, f);
    fclose(f);
    return true;
}

static void at_push_str(struct json_value *arr, const char *s)
{
    struct json_value v;
    json_init(&v);
    json_set_str(&v, s);
    json_push_back(arr, &v);
    json_free(&v);
}

static void at_build_params(struct json_value *params, const char *kind,
                            const char *name)
{
    json_init(params);
    json_set_array(params);
    at_push_str(params, kind);
    at_push_str(params, name);
}

/* ── A: rpc_agent_test() refusal paths — no subprocess spawned ──────── */

static int test_at_rpc_refusals(void)
{
    int failures = 0;
    printf("[test_agent_test] rpc_agent_test refusal paths\n");

    struct at_saved_env status_dir_env;
    at_env_save(&status_dir_env, "ZCL_AGENT_TEST_STATUS_DIR");
    char work[512];
    test_make_tmpdir(work, sizeof(work), "at_refuse", "status");
    setenv("ZCL_AGENT_TEST_STATUS_DIR", work, 1);

    struct { const char *kind; const char *name;
             const char *expect_err; } cases[] = {
        { "",              "foo",        "invalid_kind" },
        { "bogus",         "foo",        "invalid_kind" },
        { "TEST_GROUP",    "foo",        "invalid_kind" },
        { "test_group ",   "foo",        "invalid_kind" },
        { "test_group",    "",           "invalid_name" },
        { "test_group",    "Bad-Name",   "invalid_name" },
        { "test_group",    "has space",  "invalid_name" },
        { "test_group",    "../etc",     "invalid_name" },
        { "test_group",    "a/b",        "invalid_name" },
        { "test_group",    "a.b",        "invalid_name" },
        { "test_group",    "semicolon;x","invalid_name" },
        { "test_group",    "dollar$x",   "invalid_name" },
        { "test_group",    "backtick`x", "invalid_name" },
        { "test_group",    "way-too-long-way-too-long-way-too-long-way-too-long-way-too-long-x",
                                         "invalid_name" },
        /* Well-formed name, but this is a fictitious scenario that cannot
         * exist under tools/sim/scenarios/ — proves the existence check
         * runs and refuses before any launch. */
        { "scenario",      "definitely_not_a_real_scenario_abcxyz",
                                         "scenario_not_found" },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        struct json_value params, result;
        at_build_params(&params, cases[i].kind, cases[i].name);
        json_init(&result);
        bool rc = rpc_agent_test(&params, false, &result);

        char label[200];
        snprintf(label, sizeof(label), "case[%zu] kind=%s name=%s -> %s",
                 i, cases[i].kind, cases[i].name, cases[i].expect_err);
        bool ok = rc == true && result.type == JSON_OBJ &&
            strcmp(json_get_str(json_get(&result, "status")),
                  "error") == 0 &&
            strcmp(json_get_str(json_get(&result, "error")),
                  cases[i].expect_err) == 0;
        AT_CHECK(label, ok);
        json_free(&params);
        json_free(&result);
    }

    /* Genuinely missing required params: strong_params rejects before any
     * of our own validation runs, returning false with a plain string
     * error. */
    {
        struct json_value params, result;
        json_init(&params);
        json_set_array(&params);
        json_init(&result);
        bool rc = rpc_agent_test(&params, false, &result);
        AT_CHECK("zero-length params -> rpc returns false", rc == false);
        json_free(&params);
        json_free(&result);
    }

    /* No status file should exist for any refused (kind, name) — refusal
     * must happen strictly before the queued-status pre-write. */
    char maybe[700];
    snprintf(maybe, sizeof(maybe), "%s/test_group-foo.json", work);
    AT_CHECK("refused calls never created a status file",
             access(maybe, F_OK) != 0);

    test_rm_rf_recursive(work);
    at_env_restore(&status_dir_env);
    return failures;
}

/* ── B: successful async launch against a stub script + poll-back ──── */

static int test_at_rpc_launch_and_poll(void)
{
    int failures = 0;
    printf("[test_agent_test] rpc_agent_test launch + poll\n");

    char work[512], status_dir[560], stub[600];
    test_make_tmpdir(work, sizeof(work), "at_launch", "poll");
    snprintf(status_dir, sizeof(status_dir), "%s/status", work);
    mkdir(status_dir, 0700);
    snprintf(stub, sizeof(stub), "%s/stub_runner.sh", work);

    /* Minimal stand-in for tools/agent_test_runner.sh's --status-file
     * contract: find --status-file= and write a plausible "done" row. */
    const char *stub_body =
        "#!/bin/sh\n"
        "STATUS_FILE=\"\"; KIND=\"\"; NAME=\"\"\n"
        "while [ $# -gt 0 ]; do\n"
        "  case \"$1\" in\n"
        "    --status-file=*) STATUS_FILE=\"${1#--status-file=}\" ;;\n"
        "    --kind=*) KIND=\"${1#--kind=}\" ;;\n"
        "    --name=*) NAME=\"${1#--name=}\" ;;\n"
        "    *) ;;\n"
        "  esac\n"
        "  shift\n"
        "done\n"
        "[ -n \"$STATUS_FILE\" ] || exit 0\n"
        "printf '{\"schema\":\"zcl.agent_test_result.v1\",\"state\":\"done\","
        "\"kind\":\"%s\",\"name\":\"%s\",\"verdict\":\"PASS\","
        "\"exit_code\":0,\"log_path\":\"\",\"command\":\"stub\","
        "\"tail\":\"\",\"generated_at\":0}\\n' \"$KIND\" \"$NAME\" "
        "> \"$STATUS_FILE.tmp\"\n"
        "mv -f \"$STATUS_FILE.tmp\" \"$STATUS_FILE\"\n";
    AT_CHECK("wrote stub script", at_write_file(stub, stub_body));
    chmod(stub, 0755);

    /* Point the scenario existence check at an isolated fixture dir (never
     * the real tracked tools/sim/scenarios/) so kind=scenario validation
     * passes before the (stubbed) launch without touching the source tree. */
    char scen_dir[600], scen_path[700];
    snprintf(scen_dir, sizeof(scen_dir), "%s/scenarios", work);
    mkdir(scen_dir, 0700);
    snprintf(scen_path, sizeof(scen_path),
             "%s/at_poll_fixture_zzz.scenario", scen_dir);
    bool wrote_scenario = at_write_file(scen_path, "# test fixture\nexpect no_crash\n");
    AT_CHECK("wrote throwaway scenario fixture under an isolated dir",
             wrote_scenario);

    struct at_saved_env status_dir_env, script_env, scen_dir_env;
    at_env_save(&status_dir_env, "ZCL_AGENT_TEST_STATUS_DIR");
    at_env_save(&script_env, "ZCL_AGENT_TEST_RUNNER_SCRIPT");
    at_env_save(&scen_dir_env, "ZCL_AGENT_TEST_SCENARIOS_DIR");
    setenv("ZCL_AGENT_TEST_STATUS_DIR", status_dir, 1);
    setenv("ZCL_AGENT_TEST_RUNNER_SCRIPT", stub, 1);
    setenv("ZCL_AGENT_TEST_SCENARIOS_DIR", scen_dir, 1);

    struct json_value params, result;
    at_build_params(&params, "scenario", "at_poll_fixture_zzz");
    json_init(&result);
    bool rc = rpc_agent_test(&params, false, &result);
    AT_CHECK("launch returns true", rc == true);
    AT_CHECK("status == started",
             result.type == JSON_OBJ &&
             strcmp(json_get_str(json_get(&result, "status")),
                   "started") == 0);
    AT_CHECK("key == scenario-at_poll_fixture_zzz",
             strcmp(json_get_str(json_get(&result, "key")),
                   "scenario-at_poll_fixture_zzz") == 0);
    const char *status_file = json_get_str(json_get(&result, "status_file"));
    AT_CHECK("status_file under the isolated status dir",
             strncmp(status_file, status_dir, strlen(status_dir)) == 0);
    json_free(&params);
    json_free(&result);

    /* Poll agent_test_dump_state_json() until the stub has overwritten the
     * synchronous "queued" pre-write with "done", or time out. */
    bool saw_done = false;
    struct json_value dump;
    for (int i = 0; i < 100; i++) {
        json_init(&dump);
        agent_test_dump_state_json(&dump, "scenario-at_poll_fixture_zzz");
        const struct json_value *res = json_get(&dump, "result");
        const char *state = res ? json_get_str(json_get(res, "state")) : "";
        if (strcmp(state, "done") == 0) { saw_done = true; break; }
        json_free(&dump);
        struct timespec ts = { 0, 20 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    AT_CHECK("poll observed state==done within budget", saw_done);
    if (saw_done) {
        AT_CHECK("dump status == ok",
                 strcmp(json_get_str(json_get(&dump, "status")), "ok") == 0);
        const struct json_value *res = json_get(&dump, "result");
        AT_CHECK("dump verdict == PASS",
                 res && strcmp(json_get_str(json_get(res, "verdict")),
                              "PASS") == 0);
        json_free(&dump);
    }

    at_env_restore(&scen_dir_env);
    at_env_restore(&script_env);
    at_env_restore(&status_dir_env);
    if (wrote_scenario) unlink(scen_path);
    test_rm_rf_recursive(work);
    return failures;
}

/* ── C: real tools/agent_test_runner.sh, scenario-not-found path ────── */

static int test_at_real_script_scenario_not_found(void)
{
    int failures = 0;
    printf("[test_agent_test] real agent_test_runner.sh scenario-not-found\n");

    char work[512], status_file[700], log_file[700];
    test_make_tmpdir(work, sizeof(work), "at_script", "notfound");
    snprintf(status_file, sizeof(status_file), "%s/status.json", work);
    snprintf(log_file, sizeof(log_file), "%s/status.log", work);

    char cmd[2200];
    snprintf(cmd, sizeof(cmd),
        "tools/agent_test_runner.sh --kind=scenario "
        "--name=definitely_not_a_real_scenario_abcxyz "
        "--status-file=%s --log-file=%s 2>%s/stderr.log",
        status_file, log_file, work);
    int rc = system(cmd);
    AT_CHECK("script exited nonzero (scenario not found)", rc != 0);

    FILE *f = fopen(status_file, "r");
    AT_CHECK("status file was written", f != NULL);
    if (f) {
        char buf[4096];
        size_t used = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);
        buf[used] = '\0';

        struct json_value parsed;
        json_init(&parsed);
        bool read_ok = json_read(&parsed, buf, used);
        AT_CHECK("status file parses as JSON", read_ok);
        if (read_ok) {
            AT_CHECK("schema",
                     strcmp(json_get_str(json_get(&parsed, "schema")),
                           "zcl.agent_test_result.v1") == 0);
            AT_CHECK("state == done",
                     strcmp(json_get_str(json_get(&parsed, "state")),
                           "done") == 0);
            AT_CHECK("verdict == ERROR",
                     strcmp(json_get_str(json_get(&parsed, "verdict")),
                           "ERROR") == 0);
        }
        json_free(&parsed);
    }

    test_rm_rf_recursive(work);
    return failures;
}

/* ── D: dumper not_found / invalid-key refusals ──────────────────────── */

static int test_at_dumper_refusals(void)
{
    int failures = 0;
    printf("[test_agent_test] dumper refusal paths\n");

    struct at_saved_env status_dir_env;
    at_env_save(&status_dir_env, "ZCL_AGENT_TEST_STATUS_DIR");
    char work[512];
    test_make_tmpdir(work, sizeof(work), "at_dump", "refuse");
    setenv("ZCL_AGENT_TEST_STATUS_DIR", work, 1);

    struct json_value dump;
    json_init(&dump);
    agent_test_dump_state_json(&dump, "test_group-never-seen");
    AT_CHECK("unseen key reports not_found",
             strcmp(json_get_str(json_get(&dump, "status")),
                   "not_found") == 0);
    json_free(&dump);

    json_init(&dump);
    agent_test_dump_state_json(&dump, NULL);
    AT_CHECK("NULL key reports missing_key",
             strcmp(json_get_str(json_get(&dump, "error")),
                   "missing_key") == 0);
    json_free(&dump);

    json_init(&dump);
    agent_test_dump_state_json(&dump, "Not Valid!");
    AT_CHECK("malformed key reports invalid_key",
             strcmp(json_get_str(json_get(&dump, "error")),
                   "invalid_key") == 0);
    json_free(&dump);

    at_env_restore(&status_dir_env);
    test_rm_rf_recursive(work);
    return failures;
}

int test_agent_test(void)
{
    int failures = 0;
    printf("[test_agent_test] starting\n");
    failures += test_at_rpc_refusals();
    failures += test_at_rpc_launch_and_poll();
    failures += test_at_real_script_scenario_not_found();
    failures += test_at_dumper_refusals();
    printf("[test_agent_test] %d failure(s)\n", failures);
    return failures;
}
