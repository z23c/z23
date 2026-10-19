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
#include "util/spawn.h"

#include <dirent.h>
#include <stdio.h>
#include <fcntl.h>
#include <poll.h>
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

static bool acp_home_has_copy(const char *home)
{
    DIR *dir = opendir(home);
    if (!dir)
        return false;
    bool found = false;
    struct dirent *entry = NULL;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, ".zclassic-c23-COPY-",
                    strlen(".zclassic-c23-COPY-")) == 0) {
            found = true;
            break;
        }
    }
    closedir(dir);
    return found;
}

static bool acp_repro_dest_space_case(const char *label,
                                      int src_avail_kb, int dest_avail_kb,
                                      bool expect_success, bool expect_copy)
{
    char work[512], home[560], src[600], fakebin[600];
    char df[700], cp[700], marker[700], stdout_path[700], stderr_path[700];
    test_make_tmpdir(work, sizeof(work), "acp_dest_space", label);
    snprintf(home, sizeof(home), "%s/home", work);
    snprintf(src, sizeof(src), "%s/src", work);
    snprintf(fakebin, sizeof(fakebin), "%s/bin", work);
    platform_directory_create(home, 0700);
    platform_directory_create(src, 0700);
    platform_directory_create(fakebin, 0700);

    char progress[700];
    snprintf(progress, sizeof(progress), "%s/progress.kv", src);
    bool ok = acp_write_file(progress, "fixture\n");
    snprintf(df, sizeof(df), "%s/df", fakebin);
    const char *df_body =
        "#!/bin/sh\n"
        "last=''\n"
        "for arg in \"$@\"; do last=\"$arg\"; done\n"
        "if [ \"$last\" = \"$ACP_DF_SRC\" ]; then\n"
        "  avail=$ACP_DF_SRC_AVAIL\n"
        "else\n"
        "  avail=$ACP_DF_DEST_AVAIL\n"
        "fi\n"
        "printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n'\n"
        "printf 'fake 100000 0 %s 0%% /fake\\n' \"$avail\"\n";
    ok = ok && acp_write_file(df, df_body) && chmod(df, 0755) == 0;
    snprintf(cp, sizeof(cp), "%s/cp", fakebin);
    const char *cp_body =
        "#!/bin/sh\n"
        "printf copied > \"$ACP_DF_COPY_MARKER\"\n"
        "exec /bin/cp \"$@\"\n";
    ok = ok && acp_write_file(cp, cp_body) && chmod(cp, 0755) == 0;
    snprintf(marker, sizeof(marker), "%s/copied", work);
    snprintf(stdout_path, sizeof(stdout_path), "%s/stdout", work);
    snprintf(stderr_path, sizeof(stderr_path), "%s/stderr", work);

    char cmd[4000];
    snprintf(cmd, sizeof(cmd),
        "env PATH=%s:/usr/bin:/bin HOME=%s ACP_DF_SRC=%s "
        "ACP_DF_SRC_AVAIL=%d ACP_DF_DEST_AVAIL=%d "
        "ACP_DF_COPY_MARKER=%s tools/repro_on_copy.sh %s --src=%s "
        "--no-run >%s 2>%s",
        fakebin, home, src, src_avail_kb, dest_avail_kb, marker, label,
        src, stdout_path, stderr_path);
    int rc = ok ? system(cmd) : -1;
    bool copied = access(marker, F_OK) == 0;
    bool created = acp_home_has_copy(home);
    ok = ok && ((rc == 0) == expect_success) && copied == expect_copy &&
         created == expect_copy;
    test_rm_rf_recursive(work);
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

static int test_acp_destination_space_admission(void)
{
    int failures = 0;
    printf("[test_agent_copy_prove] destination filesystem admission\n");
    ACP_CHECK("destination shortage refuses before copy",
              acp_repro_dest_space_case("dest-low", 999999, 0,
                                        false, false));
    ACP_CHECK("source shortage does not reject a roomy destination",
              acp_repro_dest_space_case("src-low", 0, 999999,
                                        true, true));
    ACP_CHECK("same-filesystem admission remains unchanged",
              acp_repro_dest_space_case("same-fs", 999999, 999999,
                                        true, true));
    return failures;
}

static int test_acp_launchd_like_live(void)
{
    int failures = 0;
    printf("[test_agent_copy_prove] launchd --like-live parity\n");

    char work[512], home[560], src[600], fakebin[600], plist[700];
    char plutil[700], marker[700], stderr_path[700], candidate[700];
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
    snprintf(candidate, sizeof(candidate), "%s/candidate", fakebin);
    const char *candidate_body =
        "#!/bin/sh\n"
        "[ \"$1\" = agentbuild ] || exit 2\n"
        "printf '%s\\n' '{\"schema\":\"zcl.agent_build.v2\","
        "\"api_version\":\"v1\",\"status\":\"ok\","
        "\"source_id_sha256\":\"1111111111111111111111111111111111111111111111111111111111111111\","
        "\"build_commit\":\"launchd-fixture\"}'\n";
    ACP_CHECK("wrote launchd candidate identity fixture",
              acp_write_file(candidate, candidate_body));
    chmod(candidate, 0755);
    snprintf(stderr_path, sizeof(stderr_path), "%s/launchd.stderr", work);

    char cmd[4000];
    snprintf(cmd, sizeof(cmd),
        "env HOME=%s PATH=%s:/usr/bin:/bin ZCL_REPRO_HOST_OS=Darwin "
        "ZCL_REPRO_LIVE_PLIST=%s ZCL_NODE_BIN=%s tools/repro_on_copy.sh acp-launchd "
        "--src=%s --like-live --no-run --json 2>%s",
        home, fakebin, plist, candidate, src, stderr_path);
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
            ACP_CHECK("launchd manifest binds the candidate source identity",
                      strstr(manifest, "candidate_source_id_sha256: "
                             "1111111111111111111111111111111111111111111111111111111111111111\n") != NULL);
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

struct acp_argv_fixture {
    char work[512], status[600], log[650];
    int fd;
};

/* Wait for recorder output; a missing notification fails the row. */
static bool acp_argv_receive(int fd, char *out, size_t capacity)
{
    size_t used = 0;
    while (used + 1 < capacity) {
        struct pollfd ready = { .fd = fd, .events = POLLIN };
        if (poll(&ready, 1, 5000) != 1) return false;
        ssize_t n = read(fd, out + used, capacity - used - 1);
        if (n <= 0) return false;
        used += (size_t)n;
        out[used] = '\0';
        if (out[used - 1] == '\n') return true;
    }
    return false;
}

static int acp_argv_request(struct acp_argv_fixture *fx, unsigned mask,
                            const char *args, bool refuse)
{
    int failures = 0;
    char observed[2020], expected[2020], body[100], label[100];
    ACP_CHECK("seed prior status", acp_write_file(fx->status, "{\"state\":\"done\"}\n"));
    struct json_value params, result;
    acp_build_params(&params, "capacity", (mask & 4) ? fx->work : "", args,
                     (mask & 8) ? 1 : -1, 30, mask & 1, mask & 2);
    json_init(&result);
    uint64_t launches = zcl_spawn_thread_launch_count();
    bool rc = rpc_agent_copy_prove(&params, false, &result);
    snprintf(label, sizeof(label), "argv mask=%u bytes=%zu refusal=%d", mask,
             strlen(args), refuse);
    ACP_CHECK("argv request handled", rc);
    if (refuse) {
        ACP_CHECK(label, strcmp(json_get_str(json_get(&result, "error")),
                               "invalid_args") == 0);
        ACP_CHECK("refusal preserves prior status", acp_read_file(fx->status, body,
                  sizeof(body)) && strcmp(body, "{\"state\":\"done\"}\n") == 0);
        ACP_CHECK("refusal creates no launch log", access(fx->log, F_OK) != 0);
        ACP_CHECK("refusal never launches", zcl_spawn_thread_launch_count() == launches);
    } else {
        bool started = strcmp(json_get_str(json_get(&result, "status")),
                              "started") == 0;
        ACP_CHECK(label, started);
        unsigned tokens = 1;
        for (const char *p = args; *p; p++) tokens += *p == ' ';
        snprintf(expected, sizeof(expected), "%u|%s\n", tokens, args);
        bool received = started &&
                        acp_argv_receive(fx->fd, observed, sizeof(observed));
        ACP_CHECK("runner receives every exact token", received &&
                  strcmp(observed, expected) == 0);
        ACP_CHECK("remove launch log", unlink(fx->log) == 0);
    }
    json_free(&result);
    json_free(&params);
    return failures;
}

static int acp_argv_count_rows(struct acp_argv_fixture *fx)
{
    int failures = 0;
    for (unsigned mask = 0; mask < 16; mask++) {
        unsigned limit = 122 - ((mask & 1) != 0) - ((mask & 2) != 0) -
                               ((mask & 4) != 0) - ((mask & 8) != 0);
        for (unsigned extra = 0; extra < 2; extra++) {
            char args[400];
            unsigned count = limit + extra;
            for (unsigned i = 0; i < count; i++) memcpy(args + i * 3, "-a ", 3);
            args[count * 3 - 1] = '\0';
            failures += acp_argv_request(fx, mask, args, extra != 0);
        }
    }
    return failures;
}

static int acp_argv_byte_rows(struct acp_argv_fixture *fx)
{
    int failures = 0;
    const size_t lengths[] = {1023, 1024, 2000, 2001};
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        char args[2002];
        memset(args, 'a', lengths[i]);
        args[0] = '-';
        args[lengths[i]] = '\0';
        failures += acp_argv_request(fx, 0, args, lengths[i] > 2000);
    }
    return failures;
}

static int test_acp_argv_capacity(void)
{
    int failures = 0;
    struct acp_argv_fixture fx;
    char stub[600], fifo[600], body[1800];
    test_make_tmpdir(fx.work, sizeof(fx.work), "acp_argv", "capacity");
    snprintf(stub, sizeof(stub), "%s/runner.sh", fx.work);
    snprintf(fifo, sizeof(fifo), "%s/argv.fifo", fx.work);
    snprintf(fx.status, sizeof(fx.status), "%s/capacity.json", fx.work);
    snprintf(fx.log, sizeof(fx.log), "%s.launch.log", fx.status);
    snprintf(body, sizeof(body),
        "#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do\n"
        "  [ \"$1\" = -- ] && { shift; break; }\n  shift\ndone\n"
        "IFS=' '\nprintf '%%s|%%s\\n' \"$#\" \"$*\" > \"%s\"\n", fifo);
    bool setup = acp_write_file(stub, body) && chmod(stub, 0700) == 0 &&
                 mkfifo(fifo, 0600) == 0;
    fx.fd = setup ? open(fifo, O_RDWR | O_NONBLOCK | O_CLOEXEC) : -1;
    ACP_CHECK("argv recorder setup", fx.fd >= 0);
    if (fx.fd < 0) { test_rm_rf_recursive(fx.work); return failures; }
    struct acp_saved_env dir_env, script_env;
    acp_env_save(&dir_env, "ZCL_COPY_PROVE_STATUS_DIR");
    acp_env_save(&script_env, "ZCL_AGENT_COPY_PROVE_SCRIPT");
    bool env_ok = setenv("ZCL_COPY_PROVE_STATUS_DIR", fx.work, 1) == 0 &&
                  setenv("ZCL_AGENT_COPY_PROVE_SCRIPT", stub, 1) == 0;
    ACP_CHECK("set recorder environment", env_ok);
    if (env_ok) {
        failures += acp_argv_count_rows(&fx);
        failures += acp_argv_byte_rows(&fx);
    }
    ACP_CHECK("close recorder", close(fx.fd) == 0);
    acp_env_restore(&script_env);
    acp_env_restore(&dir_env);
    test_rm_rf_recursive(fx.work);
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

static int test_acp_dumper_complete_file(void)
{
    int failures = 0;
    char work[512], path[700], bytes[16384];
    test_make_tmpdir(work, sizeof(work), "acp_dump", "complete");
    snprintf(path, sizeof(path), "%s/span.json", work);
    struct acp_saved_env saved;
    acp_env_save(&saved, "ZCL_COPY_PROVE_STATUS_DIR");
    ACP_CHECK("set isolated status directory",
              setenv("ZCL_COPY_PROVE_STATUS_DIR", work, 1) == 0);
    const struct { const char *label; size_t length; int tail; bool valid; } cases[] = {
        { "complete empty object", 2, -1, true },
        { "complete exact-cap object", 16383, -1, true },
        { "exact-cap prefix with unread X", 16384, 'X', false },
        { "cap plus one whitespace byte", 16384, ' ', false },
        { "raw NUL and suffix", 4, 0, false },
        { "escaped NUL", 14, -1, false },
        { "incomplete object", 1, -1, false },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        memset(bytes, ' ', sizeof(bytes));
        memcpy(bytes, "{}", 2);
        if (cases[i].tail >= 0) bytes[cases[i].length - 1] = (char)cases[i].tail;
        if (cases[i].length == 4) { bytes[2] = '\0'; bytes[3] = 'X'; }
        if (cases[i].length == 14) memcpy(bytes, "{\"s\":\"\\u0000\"}", 14);
        FILE *f = fopen(path, "wb");
        ACP_CHECK("open status fixture", f != NULL);
        if (!f) continue;
        ACP_CHECK("write entire status fixture",
                  fwrite(bytes, 1, cases[i].length, f) == cases[i].length);
        ACP_CHECK("close status fixture", fclose(f) == 0);
        struct json_value dump;
        json_init(&dump);
        ACP_CHECK("read status fixture", agent_copy_prove_dump_state_json(&dump, "span"));
        ACP_CHECK(cases[i].label,
                  strcmp(json_get_str(json_get(&dump, "status")),
                         cases[i].valid ? "ok" : "error") == 0 &&
                  (cases[i].valid ||
                   (strcmp(json_get_str(json_get(&dump, "error")),
                           "status_file_invalid_json") == 0 &&
                    json_get(&dump, "result") == NULL)));
        json_free(&dump);
    }
#ifndef _WIN32
    ACP_CHECK("remove regular fixture", unlink(path) == 0);
    ACP_CHECK("create unreadable directory fixture", platform_directory_create(path, 0700) == 0);
    struct json_value dump;
    json_init(&dump);
    ACP_CHECK("read error refuses status",
              agent_copy_prove_dump_state_json(&dump, "span") &&
              strcmp(json_get_str(json_get(&dump, "error")),
                     "status_file_invalid_json") == 0 && json_get(&dump, "result") == NULL);
    json_free(&dump);
#endif
    acp_env_restore(&saved);
    test_rm_rf_recursive(work);
    return failures;
}

/* Exercise the diagnostic boundary, rather than the validator in isolation. */
static int acp_check_utf8_status(const char *path, const char *label,
                                 const char *payload, bool valid)
{
    int failures = 0;
    char bytes[64];
    int length = snprintf(bytes, sizeof(bytes), "{\"s\":\"%s\"}", payload);
    ACP_CHECK("bounded UTF-8 fixture", length > 0 && (size_t)length < sizeof(bytes));
    if (length <= 0 || (size_t)length >= sizeof(bytes)) return failures;
    FILE *f = fopen(path, "wb");
    ACP_CHECK("open UTF-8 status fixture", f != NULL);
    if (!f) return failures;
    ACP_CHECK("write UTF-8 status fixture",
              fwrite(bytes, 1, (size_t)length, f) == (size_t)length);
    ACP_CHECK("close UTF-8 status fixture", fclose(f) == 0);
    struct json_value dump;
    json_init(&dump);
    ACP_CHECK("read UTF-8 status fixture", agent_copy_prove_dump_state_json(&dump, "utf8"));
    ACP_CHECK(label, strcmp(json_get_str(json_get(&dump, "status")),
                            valid ? "ok" : "error") == 0);
    if (valid) {
        ACP_CHECK("preserve valid multibyte result",
                  strcmp(json_get_str(json_get(json_get(&dump, "result"), "s")),
                         payload) == 0);
    } else {
        ACP_CHECK("invalid UTF-8 has no adopted result",
                  strcmp(json_get_str(json_get(&dump, "error")),
                         "status_file_invalid_json") == 0 &&
                  json_get(&dump, "result") == NULL);
    }
    json_free(&dump);
    return failures;
}

static int test_acp_dumper_utf8(void)
{
    int failures = 0;
    char work[512], path[700];
    test_make_tmpdir(work, sizeof(work), "acp_dump", "utf8");
    snprintf(path, sizeof(path), "%s/utf8.json", work);
    struct acp_saved_env saved;
    acp_env_save(&saved, "ZCL_COPY_PROVE_STATUS_DIR");
    ACP_CHECK("set isolated UTF-8 status directory",
              setenv("ZCL_COPY_PROVE_STATUS_DIR", work, 1) == 0);
    const struct { const char *label; const char *payload; bool valid; } cases[] = {
        { "reject FF lead", "\xff", false },
        { "reject lone continuation", "\x80", false },
        { "reject overlong encoding", "\xc0\xaf", false },
        { "reject bad continuation", "\xc2" "A", false },
        { "reject truncated sequence", "\xe2\x82", false },
        { "reject surrogate encoding", "\xed\xa0\x80", false },
        { "reject above Unicode maximum", "\xf4\x90\x80\x80", false },
        { "accept two-byte scalar", "\xc2\xa2", true },
        { "accept three-byte scalar", "\xe2\x82\xac", true },
        { "accept four-byte scalar", "\xf4\x8f\xbf\xbf", true },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        failures += acp_check_utf8_status(path, cases[i].label,
                                          cases[i].payload, cases[i].valid);
    acp_env_restore(&saved);
    test_rm_rf_recursive(work);
    return failures;
}

/* A failed path resolver must refuse before the proof can start the node.
 * The alias points at a synthetic datadir directory; no live node
 * path or database is used. */
static int test_acp_refold_proof_realpath_failure(void)
{
    int failures = 0;
    printf("[test_agent_copy_prove] refold proof realpath failure refusal\n");

    char work[512], fakebin[600], fake_root[700], protected_dir[760];
    char home[700], datadir[760], realpath_stub[760], node_stub[760];
    char call_log[760], node_marker[760], proof_work[760];
    char command[8192], output[4096], calls[512];
    test_make_tmpdir(work, sizeof(work), "acp_refold", "realpath");
    snprintf(fakebin, sizeof(fakebin), "%s/bin", work);
    snprintf(fake_root, sizeof(fake_root), "%s/fake", work);
    snprintf(protected_dir, sizeof(protected_dir), "%s/protected-datadir",
             fake_root);
    snprintf(home, sizeof(home), "%s/home", work);
    snprintf(datadir, sizeof(datadir), "%s/datadir-alias", work);
    snprintf(realpath_stub, sizeof(realpath_stub), "%s/realpath", fakebin);
    snprintf(node_stub, sizeof(node_stub), "%s/node", fakebin);
    snprintf(call_log, sizeof(call_log), "%s/realpath.calls", work);
    snprintf(node_marker, sizeof(node_marker), "%s/node.started", work);
    snprintf(proof_work, sizeof(proof_work), "%s/proof", work);

    bool setup = platform_directory_create(fakebin, 0700) == 0 &&
        platform_directory_create(fake_root, 0700) == 0 &&
        platform_directory_create(protected_dir, 0700) == 0 &&
        platform_directory_create(home, 0700) == 0 &&
        symlink(protected_dir, datadir) == 0;
    ACP_CHECK("isolated protected-looking datadir alias created", setup);
    if (setup) {
        ACP_CHECK("write failing realpath stub",
                  acp_write_file(realpath_stub,
                    "#!/bin/sh\nprintf 'called\\n' >> \"$ZCL_REALPATH_CALLS\"\nexit 1\n"));
        ACP_CHECK("write harmless node-launch marker stub",
                  acp_write_file(node_stub,
                    "#!/bin/sh\nprintf 'started\\n' > \"$ZCL_REFOLD_NODE_MARKER\"\nexit 0\n"));
        ACP_CHECK("make resolver and node stubs executable",
                  chmod(realpath_stub, 0755) == 0 &&
                  chmod(node_stub, 0755) == 0);

        int command_len = snprintf(command, sizeof(command),
            "env PATH='%s:/usr/bin:/bin' HOME='%s' ZCL_REAL_HOME='%s' "
            "ZCL_REALPATH_CALLS='%s' ZCL_REFOLD_NODE_MARKER='%s' "
            "bash tools/scripts/step1_refold_rate_proof.sh --bin '%s' "
            "--datadir '%s' --workdir '%s' --budget-secs 1 "
            "--sample-secs 1 --ready-grace-secs 1 2>&1",
            fakebin, home, home, call_log, node_marker, node_stub,
            datadir, proof_work);
        ACP_CHECK("bounded preflight command assembled",
                  command_len > 0 && (size_t)command_len < sizeof(command));
        FILE *pipe = command_len > 0 &&
            (size_t)command_len < sizeof(command) ? popen(command, "r") : NULL;
        ACP_CHECK("launch isolated refold preflight", pipe != NULL);
        if (pipe) {
            size_t used = fread(output, 1, sizeof(output) - 1, pipe);
            output[used] = '\0';
            int rc = pclose(pipe);
            ACP_CHECK("resolver failure exits nonzero", rc != 0);
            ACP_CHECK("canonicalization refusal is named",
                      strstr(output, "cannot canonicalize datadir") != NULL);
            ACP_CHECK("refusal happens before proof workdir creation",
                      access(proof_work, F_OK) != 0);
            ACP_CHECK("node was not launched",
                      access(node_marker, F_OK) != 0);
        }
        ACP_CHECK("failing resolver stub was exercised",
                  acp_read_file(call_log, calls, sizeof(calls)) &&
                  strstr(calls, "called") != NULL);
    }
    test_rm_rf_recursive(work);
    return failures;
}

int test_agent_copy_prove(void)
{
    int failures = 0;
    printf("[test_agent_copy_prove] starting\n");
    failures += test_acp_agentbuild_identity_parser();
    failures += test_acp_script_no_run_json();
    failures += test_acp_destination_space_admission();
    failures += test_acp_launchd_like_live();
    failures += test_acp_rpc_refusals();
    failures += test_acp_rpc_launch_and_poll();
    failures += test_acp_argv_capacity();
    failures += test_acp_dumper_safety_invariant();
    failures += test_acp_dumper_complete_file();
    failures += test_acp_dumper_utf8();
    failures += test_acp_refold_proof_realpath_failure();
    printf("[test_agent_copy_prove] %d failure(s)\n", failures);
    return failures;
}
