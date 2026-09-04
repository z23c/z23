/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the agentcopyprove native contract
 * (cognition/controllers/src/agent_copy_prove_controller.c) and the --json /
 * --status-file additions to tools/repro_on_copy.sh.
 *
 * Entirely hermetic: every fixture lives under ./test-tmp/, HOME is
 * always overridden to an isolated tmp dir before the real script is
 * ever exec'd, and the live datadir is never touched or referenced by
 * path. Cover:
 *   - repro_on_copy.sh --no-run --json against a synthetic src dir:
 *     real script, real JSON emission, no node boot (fast + deterministic)
 *   - rpc_agent_copy_prove() param validation / refusal paths (no
 *     subprocess ever spawned for these — validation fails first)
 *   - rpc_agent_copy_prove() successful async launch against a tiny
 *     stub script standing in for repro_on_copy.sh, then polling the
 *     result back out through agent_copy_prove_dump_state_json()
 *   - the dumper's copy-target safety-invariant refusal (a status file
 *     whose copy_path is not a throwaway *-COPY-* path, or aliases a
 *     live datadir, must never be reported as ok)
 */

#include "test/test_core.h"
#include "controllers/agent_copy_prove_controller.h"
#include "json/json.h"
#include "platform/directory_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define ACP_CHECK(name, expr) do { \
    printf("%s... ", (name)); \
    if (expr) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* ── env save/restore ─────────────────────────────────────────────── */

struct acp_saved_env {
    const char *name;
    char value[1200];
    bool was_set;
};

static void acp_env_save(struct acp_saved_env *s, const char *name)
{
    s->name = name;
    const char *v = getenv(name);
    s->was_set = v != NULL;
    if (v) snprintf(s->value, sizeof(s->value), "%s", v);
}

static void acp_env_restore(const struct acp_saved_env *s)
{
    if (s->was_set) setenv(s->name, s->value, 1);
    else unsetenv(s->name);
}

/* ── small helpers ─────────────────────────────────────────────────── */

static bool acp_write_file(const char *path, const char *content)
{
    FILE *f = fopen(path, "w");
    if (!f) return false;
    fputs(content, f);
    fclose(f);
    return true;
}

static bool acp_read_file(const char *path, char *out, size_t out_len)
{
    if (!out || out_len == 0)
        return false;
    FILE *f = fopen(path, "r");
    if (!f) {
        out[0] = '\0';
        return false;
    }
    size_t used = fread(out, 1, out_len - 1, f);
    out[used] = '\0';
    bool ok = !ferror(f);
    fclose(f);
    return ok;
}

static void acp_push_str(struct json_value *arr, const char *s)
{
    struct json_value v;
    json_init(&v);
    json_set_str(&v, s);
    json_push_back(arr, &v);
    json_free(&v);
}

static void acp_push_int(struct json_value *arr, int64_t i)
{
    struct json_value v;
    json_init(&v);
    json_set_int(&v, i);
    json_push_back(arr, &v);
    json_free(&v);
}

static void acp_push_bool(struct json_value *arr, bool b)
{
    struct json_value v;
    json_init(&v);
    json_set_bool(&v, b);
    json_push_back(arr, &v);
    json_free(&v);
}

/* Build the standard 7-positional-arg params array this contract expects. */
static void acp_build_params(struct json_value *params, const char *slug,
                             const char *src, const char *args,
                             int64_t expect_climb_past,
                             int64_t deadline_secs, bool full, bool no_run)
{
    json_init(params);
    json_set_array(params);
    acp_push_str(params, slug);
    acp_push_str(params, src);
    acp_push_str(params, args);
    acp_push_int(params, expect_climb_past);
    acp_push_int(params, deadline_secs);
    acp_push_bool(params, full);
    acp_push_bool(params, no_run);
}

static bool acp_parse_agentbuild_fixture(const char *fixture,
                                         char *out, size_t out_len)
{
    char cmd[1600];
    snprintf(cmd, sizeof(cmd),
        ". tools/scripts/source_identity_lib.sh; body=\"$(cat %s)\"; "
        "source_id=\"$(zcl_agentbuild_v2_top_source_id \"$body\")\"; "
        "build_commit=\"$(zcl_agentbuild_v2_top_build_commit \"$body\")\"; "
        "printf '%%s\\n%%s\\n' \"$source_id\" \"$build_commit\"",
        fixture);
    FILE *p = popen(cmd, "r");
    if (!p)
        return false;
    size_t used = fread(out, 1, out_len - 1, p);
    out[used] = '\0';
    return pclose(p) == 0;
}

/* ── A: real script, --no-run --json, synthetic src, isolated HOME ── */

static int test_acp_agentbuild_identity_parser(void)
{
    int failures = 0;
    printf("[test_agent_copy_prove] top-level agentbuild identity parser\n");

    char work[512], fixture[600], out[256];
    test_make_tmpdir(work, sizeof(work), "acp_script", "identity");
    snprintf(fixture, sizeof(fixture), "%s/agentbuild.json", work);
    const char *top_source =
        "1111111111111111111111111111111111111111111111111111111111111111";
    const char *nested_source =
        "2222222222222222222222222222222222222222222222222222222222222222";
    char body[1400];
    snprintf(body, sizeof(body),
        "{\"schema\":\"zcl.agent_build.v2\",\"api_version\":\"v1\","
        "\"status\":\"ok\",\"source_id_sha256\":\"%s\","
        "\"build_commit\":\"top-commit\",\"background\":{"
        "\"source_id_sha256\":\"%s\",\"build_commit\":\"nested-stale\"}}\n",
        top_source, nested_source);
    ACP_CHECK("wrote nested-field identity fixture",
              acp_write_file(fixture, body));

    ACP_CHECK("identity parser exited 0",
              acp_parse_agentbuild_fixture(fixture, out, sizeof(out)));

    char expected[192];
    snprintf(expected, sizeof(expected), "%s\ntop-commit\n", top_source);
    ACP_CHECK("parser binds top-level source and commit, not nested fields",
              strcmp(out, expected) == 0);

    const char *refusals[] = {
        /* Missing top-level source, despite a valid nested source. */
        "{\"schema\":\"zcl.agent_build.v2\",\"api_version\":\"v1\","
        "\"status\":\"ok\",\"background\":{\"source_id_sha256\":"
        "\"2222222222222222222222222222222222222222222222222222222222222222\"}}\n",
        /* Invalid top-level source, despite a valid nested source. */
        "{\"schema\":\"zcl.agent_build.v2\",\"api_version\":\"v1\","
        "\"status\":\"ok\",\"source_id_sha256\":\"bad\","
        "\"background\":{\"source_id_sha256\":"
        "\"2222222222222222222222222222222222222222222222222222222222222222\"}}\n",
        "{\"schema\":\"wrong.schema\",\"api_version\":\"v1\","
        "\"status\":\"ok\",\"source_id_sha256\":"
        "\"1111111111111111111111111111111111111111111111111111111111111111\"}\n",
        "{\"schema\":\"zcl.agent_build.v2\",\"api_version\":\"v2\","
        "\"status\":\"ok\",\"source_id_sha256\":"
        "\"1111111111111111111111111111111111111111111111111111111111111111\"}\n",
        "{\"schema\":\"zcl.agent_build.v2\",\"api_version\":\"v1\","
        "\"status\":\"blocked\",\"source_id_sha256\":"
        "\"1111111111111111111111111111111111111111111111111111111111111111\"}\n",
        /* Truncated immediately after otherwise-valid source bytes. */
        "{\"schema\":\"zcl.agent_build.v2\",\"api_version\":\"v1\","
        "\"status\":\"ok\",\"source_id_sha256\":\""
        "1111111111111111111111111111111111111111111111111111111111111111",
        /* Closing quote followed by noncanonical garbage. */
        "{\"schema\":\"zcl.agent_build.v2\",\"api_version\":\"v1\","
        "\"status\":\"ok\",\"source_id_sha256\":\""
        "1111111111111111111111111111111111111111111111111111111111111111"
        "\"garbage}",
        /* A different next field cannot establish the canonical prefix. */
        "{\"schema\":\"zcl.agent_build.v2\",\"api_version\":\"v1\","
        "\"status\":\"ok\",\"source_id_sha256\":\""
        "1111111111111111111111111111111111111111111111111111111111111111"
        "\",\"wrong_next\":\"x\"}\n",
    };
    const char *labels[] = {
        "nested-only source is refused",
        "invalid top-level source cannot fall through to nested source",
        "wrong agentbuild schema is refused",
        "wrong agentbuild API version is refused",
        "non-ok agentbuild status is refused",
        "source truncated before closing quote is refused",
        "garbage after source is refused",
        "wrong field after source is refused",
    };
    for (size_t i = 0; i < sizeof(refusals) / sizeof(refusals[0]); i++) {
        ACP_CHECK("rewrote refusal identity fixture",
                  acp_write_file(fixture, refusals[i]));
        bool parsed = acp_parse_agentbuild_fixture(fixture, out, sizeof(out));
        ACP_CHECK(labels[i], parsed && strcmp(out, "\n\n") == 0);
    }

    /* A canonical source followed by a truncated build_commit still admits
     * the source identity, but must not publish partial trace metadata. */
    const char *truncated_commit =
        "{\"schema\":\"zcl.agent_build.v2\",\"api_version\":\"v1\","
        "\"status\":\"ok\",\"source_id_sha256\":\""
        "1111111111111111111111111111111111111111111111111111111111111111"
        "\",\"build_commit\":\"truncated";
    ACP_CHECK("rewrote truncated-commit fixture",
              acp_write_file(fixture, truncated_commit));
    bool parsed = acp_parse_agentbuild_fixture(fixture, out, sizeof(out));
    snprintf(expected, sizeof(expected), "%s\n\n", top_source);
    ACP_CHECK("truncated build commit is not returned as trace metadata",
              parsed && strcmp(out, expected) == 0);

    test_rm_rf_recursive(work);
    return failures;
}

static int test_acp_script_no_run_json(void)
{
    int failures = 0;
    printf("[test_agent_copy_prove] script --no-run --json\n");

    char work[512], home[560], src[600];
    test_make_tmpdir(work, sizeof(work), "acp_script", "norun");
    snprintf(home, sizeof(home), "%s/home", work);
    snprintf(src, sizeof(src), "%s/src", work);
    platform_directory_create(home, 0700);
    platform_directory_create(src, 0700);
    /* A couple of tiny files so the light-copy loop has something to
     * (successfully) skip past; content is irrelevant to --no-run. */
    char marker[700];
    snprintf(marker, sizeof(marker), "%s/progress.kv", src);
    acp_write_file(marker, "fixture\n");

    /* NODE_BIN/RPC_BIN resolve to the real repo's build/bin binaries via
     * the script's own dirname-relative default (SCRIPT_DIR/REPO_ROOT at
     * the top of tools/repro_on_copy.sh) — no override needed here, only
     * HOME is isolated so the throwaway -COPY- destination lands under
     * work/home instead of the real $HOME. */
    char cmd[2200];
    snprintf(cmd, sizeof(cmd),
        "env HOME=%s tools/repro_on_copy.sh acp-fixture-slug --src=%s "
        "--no-run --json 2>%s/stderr.log",
        home, src, work);
    FILE *p = popen(cmd, "r");
    ACP_CHECK("popen script", p != NULL);
    if (!p) return failures + 1;

    char out[4096];
    size_t used = fread(out, 1, sizeof(out) - 1, p);
    out[used] = '\0';
    int rc = pclose(p);

    ACP_CHECK("script exited 0 (--no-run is always success)",
             rc == 0);
    ACP_CHECK("stdout is non-empty JSON", used > 0 && out[0] == '{');

    struct json_value parsed;
    json_init(&parsed);
    bool read_ok = json_read(&parsed, out, used);
    ACP_CHECK("stdout parses as JSON", read_ok);
    if (read_ok) {
        ACP_CHECK("schema", parsed.type == JSON_OBJ &&
                  strcmp(json_get_str(json_get(&parsed, "schema")),
                        "zcl.copy_prove_result.v1") == 0);
        ACP_CHECK("state == done", strcmp(json_get_str(json_get(&parsed,
                                                                "state")),
                                          "done") == 0);
        ACP_CHECK("verdict == NO_RUN", strcmp(json_get_str(json_get(&parsed,
                                                                    "verdict")),
                                              "NO_RUN") == 0);
        ACP_CHECK("slug echoed", strcmp(json_get_str(json_get(&parsed,
                                                               "slug")),
                                        "acp-fixture-slug") == 0);
        const char *copy_path = json_get_str(json_get(&parsed, "copy_path"));
        ACP_CHECK("copy_path carries the throwaway marker",
                 strstr(copy_path, "/.zclassic-c23-COPY-") != NULL);
        ACP_CHECK("copy_path is under the isolated HOME, not the real one",
                 strncmp(copy_path, home, strlen(home)) == 0);
        ACP_CHECK("exit_code == 0", json_get_int(json_get(&parsed,
                                                          "exit_code")) == 0);
        ACP_CHECK("static spend gate not requested",
                  !json_get_bool(json_get(&parsed,
                                          "expect_static_spend_ready")));
        ACP_CHECK("static spend readiness not claimed on no-run",
                  !json_get_bool(json_get(&parsed, "static_spend_ready")));
    }
    json_free(&parsed);

    /* A remote mainnet peer's destination port is not a local bind. The
     * harness must allow the standard ZClassic 8033 peer port while still
     * refusing the same port on loopback and every protected local RPC bind. */
    snprintf(cmd, sizeof(cmd),
        "env HOME=%s tools/repro_on_copy.sh acp-remote-peer --src=%s "
        "--connect=198.51.100.7:8033 --no-run --json 2>%s/remote.stderr",
        home, src, work);
    p = popen(cmd, "r");
    ACP_CHECK("popen remote-standard-port proof", p != NULL);
    used = p ? fread(out, 1, sizeof(out) - 1, p) : 0;
    out[used] = '\0';
    rc = p ? pclose(p) : -1;
    ACP_CHECK("remote standard P2P destination port is admitted", rc == 0);

    snprintf(cmd, sizeof(cmd),
        "env HOME=%s tools/repro_on_copy.sh acp-loopback-peer --src=%s "
        "--connect=127.0.0.1:8033 --no-run >/dev/null 2>&1",
        home, src);
    ACP_CHECK("loopback protected P2P destination is refused",
              system(cmd) != 0);

    snprintf(cmd, sizeof(cmd),
        "env HOME=%s tools/repro_on_copy.sh acp-mac-rpc --src=%s "
        "--port=18233 --no-run >/dev/null 2>&1",
        home, src);
    ACP_CHECK("macOS canonical RPC bind port is refused", system(cmd) != 0);

    test_rm_rf_recursive(work);
    return failures;
}

static int test_acp_launchd_like_live(void)
{
    int failures = 0;
    printf("[test_agent_copy_prove] launchd --like-live parity\n");

    char work[512], home[560], src[600], fakebin[600], plist[700];
    char plutil[700], marker[700], stderr_path[700];
    test_make_tmpdir(work, sizeof(work), "acp_script", "launchd");
    snprintf(home, sizeof(home), "%s/home", work);
    snprintf(src, sizeof(src), "%s/src", work);
    snprintf(fakebin, sizeof(fakebin), "%s/bin", work);
    platform_directory_create(home, 0700);
    platform_directory_create(src, 0700);
    platform_directory_create(fakebin, 0700);
    snprintf(marker, sizeof(marker), "%s/progress.kv", src);
    ACP_CHECK("wrote launchd source fixture", acp_write_file(marker, "fixture\n"));
    snprintf(plist, sizeof(plist), "%s/live.plist", work);
    ACP_CHECK("wrote launchd plist fixture", acp_write_file(plist, "fixture\n"));
    snprintf(plutil, sizeof(plutil), "%s/plutil", fakebin);
    const char *plutil_body =
        "#!/bin/sh\n"
        "[ \"$1\" = -extract ] || exit 2\n"
        "case \"$2\" in\n"
        "  ProgramArguments) echo 8 ;;\n"
        "  ProgramArguments.0) echo /fixture/z23 ;;\n"
        "  ProgramArguments.1) echo -datadir=/fixture/live ;;\n"
        "  ProgramArguments.2) echo -operator-lane=canonical ;;\n"
        "  ProgramArguments.3) echo -listen ;;\n"
        "  ProgramArguments.4) echo -txindex ;;\n"
        "  ProgramArguments.5) echo -rpcport=18233 ;;\n"
        "  ProgramArguments.6) echo -addnode=198.51.100.7:8033 ;;\n"
        "  ProgramArguments.7) echo -allow-clearnet-snapshot-fetch ;;\n"
        "  EnvironmentVariables) printf 'ZCL_DEPLOY_ALLOW_CANONICAL\\nOSLogRateLimit\\n' ;;\n"
        "  EnvironmentVariables.ZCL_DEPLOY_ALLOW_CANONICAL) echo 1 ;;\n"
        "  EnvironmentVariables.OSLogRateLimit) echo 64 ;;\n"
        "  *) exit 1 ;;\n"
        "esac\n";
    ACP_CHECK("wrote launchd plutil fixture", acp_write_file(plutil, plutil_body));
    chmod(plutil, 0755);
    snprintf(stderr_path, sizeof(stderr_path), "%s/launchd.stderr", work);

    char cmd[3000];
    snprintf(cmd, sizeof(cmd),
        "env HOME=%s PATH=%s:/usr/bin:/bin ZCL_REPRO_HOST_OS=Darwin "
        "ZCL_REPRO_LIVE_PLIST=%s tools/repro_on_copy.sh acp-launchd "
        "--src=%s --like-live --no-run --json 2>%s",
        home, fakebin, plist, src, stderr_path);
    FILE *p = popen(cmd, "r");
    ACP_CHECK("popen launchd like-live proof", p != NULL);
    char out[4096];
    size_t used = p ? fread(out, 1, sizeof(out) - 1, p) : 0;
    out[used] = '\0';
    int rc = p ? pclose(p) : -1;
    ACP_CHECK("launchd like-live proof exited 0", rc == 0);

    struct json_value parsed;
    json_init(&parsed);
    bool read_ok = json_read(&parsed, out, used);
    ACP_CHECK("launchd like-live result parses", read_ok);
    if (read_ok) {
        const char *copy_path = json_get_str(json_get(&parsed, "copy_path"));
        char manifest_path[1200], manifest[8192];
        snprintf(manifest_path, sizeof(manifest_path),
                 "%s/REPRO_MANIFEST.txt", copy_path);
        bool manifest_ok = acp_read_file(manifest_path, manifest,
                                         sizeof(manifest));
        ACP_CHECK("launchd like-live manifest readable", manifest_ok);
        if (manifest_ok) {
            ACP_CHECK("safe launchd behavior flags are preserved",
                      strstr(manifest, "-listen") != NULL &&
                      strstr(manifest, "-txindex") != NULL &&
                      strstr(manifest, "-allow-clearnet-snapshot-fetch") != NULL);
            ACP_CHECK("launchd network identity is stripped",
                      strstr(manifest, "-rpcport=18233") == NULL &&
                      strstr(manifest, "-addnode=") == NULL);
            ACP_CHECK("copied wallet operator lane is preserved",
                      strstr(manifest, "-operator-lane=canonical") != NULL);
            ACP_CHECK("non-authority launchd environment is preserved",
                      strstr(manifest, "OSLogRateLimit=64") != NULL);
            ACP_CHECK("canonical deployment authority is never copied",
                      strstr(manifest, "ZCL_DEPLOY_ALLOW_CANONICAL") == NULL);
        }
    }
    json_free(&parsed);
    test_rm_rf_recursive(work);
    return failures;
}

/* ── B: rpc_agent_copy_prove() refusal paths — no subprocess spawned ── */

static int test_acp_rpc_refusals(void)
{
    int failures = 0;
    printf("[test_agent_copy_prove] rpc_agent_copy_prove refusal paths\n");

    struct acp_saved_env status_dir_env;
    acp_env_save(&status_dir_env, "ZCL_COPY_PROVE_STATUS_DIR");
    char work[512];
    test_make_tmpdir(work, sizeof(work), "acp_refuse", "status");
    setenv("ZCL_COPY_PROVE_STATUS_DIR", work, 1);

    struct { const char *slug; const char *src; const char *args;
             const char *expect_err; } cases[] = {
        { "",              "",           "",       "invalid_slug" /* empty
                                    string IS present+correctly-typed per
                                    strong_params, so it reaches our own
                                    charset check, not the missing-param
                                    path — see the dedicated
                                    missing-param case below */ },
        { "Bad-Slug",      "",           "",       "invalid_slug" },
        { "-leading-dash", "",           "",       "invalid_slug" },
        { "trailing-",     "",           "",       "invalid_slug" },
        { "way-too-long-way-too-long-way-too-long-way-too-long-way-too-long-x",
                           "",           "",       "invalid_slug" },
        { "has space",     "",           "",       "invalid_slug" },
        { "semicolon;x",   "",           "",       "invalid_slug" },
        { "ok-slug",       "relative",   "",       "invalid_src" },
        { "ok-slug",       "/tmp/ok; rm -rf /", "",       "invalid_src" },
        { "ok-slug",       "/tmp/ok`x`", "",       "invalid_src" },
        { "ok-slug",       "",           "noflag", "invalid_args" },
        { "ok-slug",       "",           "-ok $(x)", "invalid_args" },
        { "ok-slug",       "",           "-ok|bad", "invalid_args" },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        struct json_value params, result;
        acp_build_params(&params, cases[i].slug, cases[i].src,
                         cases[i].args, -1, 180, false, true /* no_run:
                         belt-and-suspenders — even if validation had a
                         bug, no_run keeps any accidental real launch
                         cheap */);
        json_init(&result);
        bool rc = rpc_agent_copy_prove(&params, false, &result);

        char label[160];
        snprintf(label, sizeof(label), "case[%zu] slug=%s src=%s "
                "args=%s -> %s", i, cases[i].slug, cases[i].src,
                cases[i].args, cases[i].expect_err);
        bool ok = rc == true && result.type == JSON_OBJ &&
            strcmp(json_get_str(json_get(&result, "status")),
                  "error") == 0 &&
            strcmp(json_get_str(json_get(&result, "error")),
                  cases[i].expect_err) == 0;
        ACP_CHECK(label, ok);
        json_free(&params);
        json_free(&result);
    }

    /* Genuinely missing required slug (a zero-length params array, not
     * an empty-string slug): strong_params rejects it before any of our
     * own validation runs, returning false with a plain string error. */
    {
        struct json_value params, result;
        json_init(&params);
        json_set_array(&params);
        json_init(&result);
        bool rc = rpc_agent_copy_prove(&params, false, &result);
        ACP_CHECK("zero-length params -> rpc returns false", rc == false);
        json_free(&params);
        json_free(&result);
    }

    /* No status file should exist for any refused slug — refusal must
     * happen strictly before the queued-status pre-write. */
    char maybe[700];
    snprintf(maybe, sizeof(maybe), "%s/ok-slug.json", work);
    ACP_CHECK("refused calls never created a status file for ok-slug",
             access(maybe, F_OK) != 0);

    test_rm_rf_recursive(work);
    acp_env_restore(&status_dir_env);
    return failures;
}

/* ── C: successful async launch against a stub script + poll-back ──── */

static int test_acp_rpc_launch_and_poll(void)
{
    int failures = 0;
    printf("[test_agent_copy_prove] rpc_agent_copy_prove launch + poll\n");

    char work[512], status_dir[560], stub[600];
    test_make_tmpdir(work, sizeof(work), "acp_launch", "poll");
    snprintf(status_dir, sizeof(status_dir), "%s/status", work);
    platform_directory_create(status_dir, 0700);
    snprintf(stub, sizeof(stub), "%s/stub_repro.sh", work);

    /* Minimal stand-in for repro_on_copy.sh's --status-file contract:
     * find the slug (first non-flag arg) and --status-file=, then write
     * a plausible "done" row bearing the throwaway *-COPY-* marker so
     * the safety check accepts it. */
    const char *stub_body =
        "#!/bin/sh\n"
        "SLUG=\"\"; STATUS_FILE=\"\"\n"
        "while [ $# -gt 0 ]; do\n"
        "  case \"$1\" in\n"
        "    --status-file=*) STATUS_FILE=\"${1#--status-file=}\" ;;\n"
        "    --) shift; break ;;\n"
        "    --*) ;;\n"
        "    *) [ -z \"$SLUG\" ] && SLUG=\"$1\" ;;\n"
        "  esac\n"
        "  shift\n"
        "done\n"
        "[ -n \"$STATUS_FILE\" ] || exit 0\n"
        "printf '{\"schema\":\"zcl.copy_prove_result.v1\",\"state\":\"done\","
        "\"verdict\":\"PASS\",\"exit_code\":0,\"slug\":\"%s\","
        "\"copy_path\":\"%s/.zclassic-c23-COPY-20260101-000000-%s\","
        "\"src\":\"\",\"h_star_before\":10,\"h_star_after\":20,"
        "\"max_tip\":20,\"expect_climb_past\":null,\"climbed_past\":true,"
        "\"tip_regression\":false,\"body_read_fails\":0,"
        "\"refold_requested\":false,\"refold_snapshot_loaded\":false,"
        "\"duration_secs\":0,\"log_path\":\"\",\"node_pid\":1,"
        "\"generated_at\":0}\\n' \"$SLUG\" \"$HOME\" \"$SLUG\" "
        "> \"$STATUS_FILE.tmp\"\n"
        "mv -f \"$STATUS_FILE.tmp\" \"$STATUS_FILE\"\n";
    ACP_CHECK("wrote stub script", acp_write_file(stub, stub_body));
    chmod(stub, 0755);

    struct acp_saved_env status_dir_env, script_env;
    acp_env_save(&status_dir_env, "ZCL_COPY_PROVE_STATUS_DIR");
    acp_env_save(&script_env, "ZCL_AGENT_COPY_PROVE_SCRIPT");
    setenv("ZCL_COPY_PROVE_STATUS_DIR", status_dir, 1);
    setenv("ZCL_AGENT_COPY_PROVE_SCRIPT", stub, 1);

    struct json_value params, result;
    acp_build_params(&params, "poll-slug", "", "", -1, 30, false, false);
    json_init(&result);
    bool rc = rpc_agent_copy_prove(&params, false, &result);
    ACP_CHECK("launch returns true", rc == true);
    ACP_CHECK("status == started",
             result.type == JSON_OBJ &&
             strcmp(json_get_str(json_get(&result, "status")),
                   "started") == 0);
    ACP_CHECK("slug echoed", strcmp(json_get_str(json_get(&result, "slug")),
                                    "poll-slug") == 0);
    const char *status_file = json_get_str(json_get(&result, "status_file"));
    ACP_CHECK("status_file under the isolated status dir",
             strncmp(status_file, status_dir, strlen(status_dir)) == 0);
    json_free(&params);
    json_free(&result);

    /* Poll agent_copy_prove_dump_state_json() until the stub has
     * overwritten the synchronous "queued" pre-write with "done", or
     * time out. Bounded to a few seconds — the stub does no real work. */
    bool saw_done = false;
    struct json_value dump;
    for (int i = 0; i < 100; i++) {
        json_init(&dump);
        agent_copy_prove_dump_state_json(&dump, "poll-slug");
        const struct json_value *res = json_get(&dump, "result");
        const char *state = res ? json_get_str(json_get(res, "state")) : "";
        if (strcmp(state, "done") == 0) { saw_done = true; break; }
        json_free(&dump);
        struct timespec ts = { 0, 20 * 1000 * 1000 };
        nanosleep(&ts, NULL); /* real-clock: pre-existing bounded poll loop, seeded when check_no_real_clock_test_deadline.sh was introduced */
    }
    ACP_CHECK("poll observed state==done within budget", saw_done);
    if (saw_done) {
        ACP_CHECK("dump status == ok",
                 strcmp(json_get_str(json_get(&dump, "status")), "ok") == 0);
        const struct json_value *res = json_get(&dump, "result");
        ACP_CHECK("dump verdict == PASS",
                 res && strcmp(json_get_str(json_get(res, "verdict")),
                              "PASS") == 0);
        json_free(&dump);
    }

    acp_env_restore(&script_env);
    acp_env_restore(&status_dir_env);
    test_rm_rf_recursive(work);
    return failures;
}

/* ── D: dumper safety-invariant + not_found/invalid-key refusals ───── */

static int test_acp_dumper_safety_invariant(void)
{
    int failures = 0;
    printf("[test_agent_copy_prove] dumper safety invariant\n");

    char work[512];
    test_make_tmpdir(work, sizeof(work), "acp_dump", "safety");

    struct acp_saved_env status_dir_env;
    acp_env_save(&status_dir_env, "ZCL_COPY_PROVE_STATUS_DIR");
    setenv("ZCL_COPY_PROVE_STATUS_DIR", work, 1);

    /* Hand-write a status row whose copy_path does NOT carry the
     * throwaway marker (as if a future script regression pointed the
     * copy at something else entirely) — the dumper must refuse it. */
    char bad_file[700];
    snprintf(bad_file, sizeof(bad_file), "%s/bad-slug.json", work);
    acp_write_file(bad_file,
        "{\"schema\":\"zcl.copy_prove_result.v1\",\"state\":\"done\","
        "\"verdict\":\"PASS\",\"copy_path\":\"/some/other/path\"}\n");

    struct json_value dump;
    json_init(&dump);
    agent_copy_prove_dump_state_json(&dump, "bad-slug");
    ACP_CHECK("non-COPY-marked copy_path is refused",
             strcmp(json_get_str(json_get(&dump, "status")), "error") == 0 &&
             strcmp(json_get_str(json_get(&dump, "error")),
                   "safety_invariant_violated") == 0);
    json_free(&dump);

    /* And a row that DOES alias a live datadir, even with the marker
     * missing from the check target (belt and suspenders: exact-equal
     * live path is refused outright regardless of any marker). */
    const char *home = getenv("HOME");
    char live_like[700], live_file[700];
    snprintf(live_like, sizeof(live_like), "%s/.zclassic-c23",
             home && home[0] ? home : "/nonexistent-home");
    snprintf(live_file, sizeof(live_file), "%s/live-slug.json", work);
    char body[900];
    snprintf(body, sizeof(body),
             "{\"schema\":\"zcl.copy_prove_result.v1\",\"state\":\"done\","
             "\"verdict\":\"PASS\",\"copy_path\":\"%s\"}\n", live_like);
    acp_write_file(live_file, body);
    json_init(&dump);
    agent_copy_prove_dump_state_json(&dump, "live-slug");
    ACP_CHECK("live-datadir-aliasing copy_path is refused",
             strcmp(json_get_str(json_get(&dump, "status")), "error") == 0 &&
             strcmp(json_get_str(json_get(&dump, "error")),
                   "safety_invariant_violated") == 0);
    json_free(&dump);

    /* not_found: valid slug shape, no file on disk. */
    json_init(&dump);
    agent_copy_prove_dump_state_json(&dump, "never-seen-slug");
    ACP_CHECK("unseen slug reports not_found",
             strcmp(json_get_str(json_get(&dump, "status")),
                   "not_found") == 0);
    json_free(&dump);

    /* missing / invalid key. */
    json_init(&dump);
    agent_copy_prove_dump_state_json(&dump, NULL);
    ACP_CHECK("NULL key reports missing_slug_key",
             strcmp(json_get_str(json_get(&dump, "error")),
                   "missing_slug_key") == 0);
    json_free(&dump);

    json_init(&dump);
    agent_copy_prove_dump_state_json(&dump, "Not Valid!");
    ACP_CHECK("malformed key reports invalid_slug_key",
             strcmp(json_get_str(json_get(&dump, "error")),
                   "invalid_slug_key") == 0);
    json_free(&dump);

    acp_env_restore(&status_dir_env);
    test_rm_rf_recursive(work);
    return failures;
}

int test_agent_copy_prove(void)
{
    int failures = 0;
    printf("[test_agent_copy_prove] starting\n");
    failures += test_acp_agentbuild_identity_parser();
    failures += test_acp_script_no_run_json();
    failures += test_acp_launchd_like_live();
    failures += test_acp_rpc_refusals();
    failures += test_acp_rpc_launch_and_poll();
    failures += test_acp_dumper_safety_invariant();
    printf("[test_agent_copy_prove] %d failure(s)\n", failures);
    return failures;
}
