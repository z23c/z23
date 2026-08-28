/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * agenttest — native agent contract wrapping tools/agent_test_runner.sh,
 * which in turn runs ONE allowlisted test surface:
 *   kind=test_group -> build/bin/test_parallel --only=<name>
 *   kind=scenario   -> build/bin/zclassic23-chaos --scenario=tools/sim/scenarios/<name>.scenario
 *
 * Cloned end-to-end from the agentcopyprove pattern
 * (app/controllers/src/agent_copy_prove_controller.c) — same async-by-design
 * rationale (a real test_parallel run or full sweep can outlive any synchronous
 * native-command budget),
 * same "no dest/target field the caller controls" posture (the only two
 * inputs are `kind` and `name`, both allowlist-validated below before they
 * ever reach a command line), same detached-launch + poll-via-diagnostics-
 * registry shape.
 *
 * Safety invariants (enforced in code, not comments):
 *   - `kind` must equal exactly "test_group" or "scenario" (plain strcmp);
 *     the matched literal constant is used downstream, never the caller's
 *     raw pointer, so there is no path by which an unexpected kind string
 *     reaches a command line.
 *   - `name` must match ^[a-z0-9_]{1,64}$ — no slash, no dot, no shell
 *     metacharacter of any kind can survive that charset. No arbitrary
 *     `make` targets are ever invoked; the only two binaries this contract
 *     can launch are build/bin/test_parallel and build/bin/zclassic23-chaos.
 *   - test_group additionally cross-checks `name` against the COMPILED
 *     group registry via `test_parallel --list` (exact line match) when
 *     that binary is reachable — not a substring match, so this contract's
 *     notion of "matches an existing registered group" is strictly tighter
 *     than test_parallel's own `--only=SUBSTR` semantics. When the binary
 *     is not yet built, this pre-check is skipped and the launch is still
 *     safe: the underlying `--only=<name>` run itself reports "matched no
 *     groups" (exit 2) if `name` was never registered, which the runner
 *     script surfaces as verdict=NO_MATCH — never a silently-wrong result.
 *   - scenario requires `name.scenario` to already exist as a regular file
 *     under tools/sim/scenarios/ — no new scenario content is ever created
 *     or written by this contract.
 *   - the runner is launched via zcl_spawn_detached (no shell): each value
 *     is passed as an exact argv word, so no shell metacharacter can be
 *     interpreted at all — the allowlists above remain as defense in depth.
 */

#include "controllers/agent_test_controller.h"
#include "controllers/agent_controller.h"
#include "controllers/strong_params.h"

#include "json/json.h"
#include "platform/time_compat.h"
#include "util/safe_alloc.h"
#include "util/spawn.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define AGENT_TEST_CONTRACT_SCHEMA "zcl.agent_test.v2"
#define AGENT_TEST_RESULT_SCHEMA   "zcl.agent_test_result.v1"
#define AGENT_TEST_STATE_SCHEMA    "zcl.agent_test_state.v1"

#define AT_KIND_TEST_GROUP "test_group"
#define AT_KIND_SCENARIO   "scenario"

/* ── input allowlists ────────────────────────────────────────────────
 *
 * The ONLY gate between agent-supplied strings and a shell command line
 * (see at_launch below). Deliberately conservative: lowercase alnum plus
 * underscore, nothing else — no hyphen even, tighter than agentcopyprove's
 * slug charset. */

static bool at_name_valid(const char *s)
{
    if (!s || !s[0]) return false;
    size_t n = strlen(s);
    if (n > 64) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!(islower(c) || isdigit(c) || c == '_'))
            return false;
    }
    return true;
}

/* The dump-state key is caller-formed as "<kind>-<name>"; kind is one of
 * two fixed literals (no dash) and name carries no dash either, so a dash
 * additionally permitted here cannot introduce ambiguity or traversal. */
static bool at_key_valid(const char *s)
{
    if (!s || !s[0]) return false;
    size_t n = strlen(s);
    if (n > 140) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!(islower(c) || isdigit(c) || c == '_' || c == '-'))
            return false;
    }
    return true;
}

/* ── status dir / file resolution ────────────────────────────────────
 *
 * ZCL_AGENT_TEST_STATUS_DIR lets tests point this at an isolated temp dir;
 * production default lives beside the copy-prove convention under $HOME. */

static void at_status_dir(char *out, size_t out_sz)
{
    const char *override = getenv("ZCL_AGENT_TEST_STATUS_DIR");
    if (override && override[0]) {
        snprintf(out, out_sz, "%s", override);
        return;
    }
    const char *home = getenv("HOME");
    snprintf(out, out_sz, "%s/.zclassic-c23-agent-test-status",
             home && home[0] ? home : "/tmp");
}

static void at_status_file(const char *key, char *out, size_t out_sz)
{
    char dir[900];
    at_status_dir(dir, sizeof(dir));
    snprintf(out, out_sz, "%s/%s.json", dir, key);
}

static void at_mkdir_p(const char *path)
{
    char tmp[900];
    snprintf(tmp, sizeof(tmp), "%s", path);
    size_t len = strlen(tmp);
    if (len == 0) return;
    if (tmp[len - 1] == '/') tmp[len - 1] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0700);
            *p = '/';
        }
    }
    mkdir(tmp, 0700);
}

/* ── test_group registry cross-check ─────────────────────────────────
 *
 * `test_parallel --list` prints one registered group name per line and
 * exits 0 (see lib/test/src/test_parallel.c). This command line carries
 * no caller-supplied data, so it needs none of the allowlisting above.
 * Returns true when `name` is found as an EXACT line, false otherwise.
 * `*reachable` is set to false when the binary itself could not be run
 * (not built yet) so the caller can fall back to regex-only validation
 * instead of refusing every request. */
static bool at_test_group_registered(const char *bin, const char *name,
                                     bool *reachable)
{
    *reachable = false;
    if (access(bin, X_OK) != 0)
        return false;

    /* `bin --list` — capture stdout via the no-shell spawn primitive (stderr
     * discarded, matching the old `2>/dev/null`), then match `name` as an
     * exact line. bin was already confirmed X_OK above. */
    const char *const argv[] = { bin, "--list", NULL };
    size_t cap = 65536;
    char *out = zcl_malloc(cap, "agent_test.list");
    if (!out)
        return false;
    int rc = zcl_spawn_capture(argv, out, cap, 30000);
    *reachable = (rc != -1);   /* -1 == launch failed before the binary ran */

    bool found = false;
    char *save = NULL;
    for (char *line = strtok_r(out, "\r\n", &save);
         line && !found;
         line = strtok_r(NULL, "\r\n", &save)) {
        if (strcmp(line, name) == 0)
            found = true;
    }
    free(out);
    return found;
}

/* ── synchronous "queued" pre-write ──────────────────────────────────
 *
 * Closes the staleness window between "RPC accepted the request" and the
 * runner script's first --status-file write, exactly like agentcopyprove's
 * cp_write_queued_status. */

static bool at_write_queued_status(const char *status_file, const char *kind,
                                   const char *name)
{
    struct json_value obj;
    json_init(&obj);
    json_set_object(&obj);
    json_push_kv_str(&obj, "schema", AGENT_TEST_RESULT_SCHEMA);
    json_push_kv_str(&obj, "state", "queued");
    json_push_kv_str(&obj, "kind", kind);
    json_push_kv_str(&obj, "name", name);
    json_push_kv_int(&obj, "queued_at", platform_time_wall_unix());

    size_t need = json_write(&obj, NULL, 0) + 1;
    char *buf = zcl_malloc(need, "agent_test_queued_json");
    bool ok = false;
    if (buf) {
        json_write(&obj, buf, need);
        char tmp_path[1200];
        snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", status_file);
        FILE *f = fopen(tmp_path, "w");
        if (f) {
            fputs(buf, f);
            fputc('\n', f);
            fclose(f);
            ok = (rename(tmp_path, status_file) == 0);
            if (!ok)
                // obs-ok:agent-test-diagnostic-stderr (best-effort status telemetry / request refusal returns JSON error)
                fprintf(stderr, "[agent_test] %s:%d %s(): rename %s -> %s "
                        "failed: %s\n", __FILE__, __LINE__, __func__,
                        tmp_path, status_file, strerror(errno));
        } else {
            // obs-ok:agent-test-diagnostic-stderr (best-effort status telemetry / request refusal returns JSON error)
            fprintf(stderr, "[agent_test] %s:%d %s(): fopen %s failed: "
                    "%s\n", __FILE__, __LINE__, __func__, tmp_path,
                    strerror(errno));
        }
        free(buf);
    } else {
        // obs-ok:agent-test-diagnostic-stderr (best-effort status telemetry / request refusal returns JSON error)
        fprintf(stderr, "[agent_test] %s:%d %s(): zcl_malloc(%zu) failed "
                "for kind=%s name=%s\n", __FILE__, __LINE__, __func__,
                need, kind, name);
    }
    json_free(&obj);
    return ok;
}

/* ── RPC: agenttest ───────────────────────────────────────────────── */

bool rpc_agent_test(const struct json_value *params, bool help,
                    struct json_value *result)
{
    RPC_HELP(help, result,
        "agenttest ( kind name )\n"
        "\nKick off ONE allowlisted test surface in the background and\n"
        "return immediately without blocking for the run. There is no\n"
        "arbitrary-command field — the two inputs (kind, name) are\n"
        "allowlist-validated below and can only ever select build/bin/\n"
        "test_parallel --only=<name> or build/bin/zclassic23-chaos\n"
        "--scenario=tools/sim/scenarios/<name>.scenario.\n"
        "\nParams:\n"
        "  kind (string, required)  \"test_group\" or \"scenario\"\n"
        "  name (string, required)  lowercase alnum + '_', <= 64 chars;\n"
        "                           test_group must be a compiled group\n"
        "                           name, scenario must name an existing\n"
        "                           tools/sim/scenarios/<name>.scenario\n"
        "\nPoll a run with: z23 dumpstate agent_test <kind>-<name>.\n"
        "This\n"
        "call never blocks for the run duration.\n"
        "\nResult:\n"
        "  { \"schema\":\"zcl.agent_test.v2\", \"status\":\"started\", ... }\n");

    struct rpc_params p;
    rpc_params_init(&p, params);
    const char *kind = rpc_require_str(&p, 0, "kind");
    const char *name = rpc_require_str(&p, 1, "name");
    if (rpc_params_invalid(&p)) {
        rpc_params_error(&p, result);
        return false;
    }

    json_set_object(result);
    json_push_kv_str(result, "schema", AGENT_TEST_CONTRACT_SCHEMA);
    json_push_kv_str(result, "api_version", "v1");
    json_push_kv_str(result, "native_command", "z23 agenttest");

    const char *kind_lit = NULL;
    bool at_is_test_group = false;
    if (kind && strcmp(kind, AT_KIND_TEST_GROUP) == 0) {
        kind_lit = AT_KIND_TEST_GROUP;
        at_is_test_group = true;
    } else if (kind && strcmp(kind, AT_KIND_SCENARIO) == 0) {
        kind_lit = AT_KIND_SCENARIO;
    }
    if (!kind_lit) {
        json_push_kv_str(result, "status", "error");
        json_push_kv_str(result, "error", "invalid_kind");
        json_push_kv_str(result, "detail",
            "kind must be exactly \"test_group\" or \"scenario\"");
        // obs-ok:agent-test-diagnostic-stderr (best-effort status telemetry / request refusal returns JSON error)
        fprintf(stderr, "[agent_test] %s:%d %s(): refused invalid kind=%s\n",
                __FILE__, __LINE__, __func__, kind ? kind : "(null)");
        return true;
    }

    if (!at_name_valid(name)) {
        json_push_kv_str(result, "status", "error");
        json_push_kv_str(result, "error", "invalid_name");
        json_push_kv_str(result, "detail",
            "name must match ^[a-z0-9_]{1,64}$");
        // obs-ok:agent-test-diagnostic-stderr (best-effort status telemetry / request refusal returns JSON error)
        fprintf(stderr, "[agent_test] %s:%d %s(): refused invalid name for "
                "kind=%s\n", __FILE__, __LINE__, __func__, kind_lit);
        return true;
    }

    /* ── kind-specific existence checks BEFORE ever launching anything ── */
    bool registry_precheck_skipped = false;
    if (at_is_test_group) {
        const char *bin = getenv("ZCL_AGENT_TEST_PARALLEL_BIN");
        if (!bin || !bin[0]) bin = "build/bin/test_parallel";
        bool reachable = false;
        bool registered = at_test_group_registered(bin, name, &reachable);
        if (reachable && !registered) {
            json_push_kv_str(result, "status", "error");
            json_push_kv_str(result, "error", "test_group_not_registered");
            json_push_kv_str(result, "detail",
                "name did not appear in `test_parallel --list`");
            // obs-ok:agent-test-diagnostic-stderr (best-effort status telemetry / request refusal returns JSON error)
            fprintf(stderr, "[agent_test] %s:%d %s(): refused unregistered "
                    "test_group name=%s\n", __FILE__, __LINE__, __func__,
                    name);
            return true;
        }
        registry_precheck_skipped = !reachable;
    } else {
        const char *scen_dir = getenv("ZCL_AGENT_TEST_SCENARIOS_DIR");
        if (!scen_dir || !scen_dir[0]) scen_dir = "tools/sim/scenarios";
        char scen_path[1024];
        snprintf(scen_path, sizeof(scen_path),
                 "%s/%s.scenario", scen_dir, name);
        struct stat st;
        if (stat(scen_path, &st) != 0 || !S_ISREG(st.st_mode)) {
            json_push_kv_str(result, "status", "error");
            json_push_kv_str(result, "error", "scenario_not_found");
            json_push_kv_str(result, "detail", scen_path);
            // obs-ok:agent-test-diagnostic-stderr (best-effort status telemetry / request refusal returns JSON error)
            fprintf(stderr, "[agent_test] %s:%d %s(): refused missing "
                    "scenario=%s\n", __FILE__, __LINE__, __func__,
                    scen_path);
            return true;
        }
    }

    char key[160];
    snprintf(key, sizeof(key), "%s-%s", kind_lit, name);

    char status_dir[900];
    at_status_dir(status_dir, sizeof(status_dir));
    at_mkdir_p(status_dir);
    char status_file[1100];
    at_status_file(key, status_file, sizeof(status_file));
    char log_file[1150];
    snprintf(log_file, sizeof(log_file), "%s.log", status_file);

    if (!at_write_queued_status(status_file, kind_lit, name)) {
        json_push_kv_str(result, "status", "error");
        json_push_kv_str(result, "error", "status_file_write_failed");
        json_push_kv_str(result, "status_file", status_file);
        // obs-ok:agent-test-diagnostic-stderr (best-effort status telemetry / request refusal returns JSON error)
        fprintf(stderr, "[agent_test] %s:%d %s(): could not write queued "
                "status for key=%s at %s\n", __FILE__, __LINE__, __func__,
                key, status_file);
        return true;
    }

    const char *script = getenv("ZCL_AGENT_TEST_RUNNER_SCRIPT");
    if (!script || !script[0]) script = "tools/agent_test_runner.sh";
    if (access(script, X_OK) != 0) {
        json_push_kv_str(result, "status", "error");
        json_push_kv_str(result, "error", "script_not_found");
        json_push_kv_str(result, "detail", script);
        // obs-ok:agent-test-diagnostic-stderr (best-effort status telemetry / request refusal returns JSON error)
        fprintf(stderr, "[agent_test] %s:%d %s(): script not executable: "
                "%s (%s)\n", __FILE__, __LINE__, __func__, script,
                strerror(errno));
        return true;
    }

    char launch_log[1200];
    snprintf(launch_log, sizeof(launch_log), "%s.launch.log", status_file);

    /* argv for the detached runner — no shell, no quoting, no `nohup ... &`.
     * zcl_spawn_detached double-forks + setsid()s and redirects the
     * grandchild's stdout+stderr to launch_log (replacing the old
     * `> launch_log 2>&1 < /dev/null &`). kind_lit is one of two fixed
     * C-string literals; name/status_file/log_file are exact argv words. */
    char opt_kind[64], opt_name[200], opt_status_file[1200], opt_log[1200];
    snprintf(opt_kind, sizeof(opt_kind), "--kind=%s", kind_lit);
    snprintf(opt_name, sizeof(opt_name), "--name=%s", name);
    snprintf(opt_status_file, sizeof(opt_status_file), "--status-file=%s",
             status_file);
    snprintf(opt_log, sizeof(opt_log), "--log-file=%s", log_file);
    const char *argv[] = {
        script, opt_kind, opt_name, opt_status_file, opt_log, NULL
    };

    struct zcl_result sp = zcl_spawn_detached(argv, launch_log);
    if (!sp.ok) {
        json_push_kv_str(result, "status", "error");
        json_push_kv_str(result, "error", "spawn_failed");
        json_push_kv_str(result, "detail", sp.message);
        // obs-ok:agent-test-diagnostic-stderr (best-effort status telemetry / request refusal returns JSON error)
        fprintf(stderr, "[agent_test] %s:%d %s(): spawn_detached failed "
                "for key=%s: %s\n", __FILE__, __LINE__, __func__,
                key, sp.message);
        return true;
    }

    json_push_kv_str(result, "status", "started");
    json_push_kv_bool(result, "async", true);
    json_push_kv_str(result, "kind", kind_lit);
    json_push_kv_str(result, "name", name);
    json_push_kv_str(result, "key", key);
    json_push_kv_str(result, "status_file", status_file);
    json_push_kv_str(result, "launch_log", launch_log);
    json_push_kv_bool(result, "registry_precheck_skipped",
                      registry_precheck_skipped);
    json_push_kv_str(result, "poll_native", "z23 dumpstate agent_test");
    json_push_kv_str(result, "budget_note",
        "detached background run; does not hold an RPC worker thread. "
        "Poll status_file via dumpstate instead of waiting on "
        "this call.");
    return true;
}

/* ── diagnostics registry: subsystem=agent_test ──────────────────────
 *
 * See CLAUDE.md "Adding state introspection". Reentrant-safe: reads a
 * file, allocates nothing the caller doesn't own, takes no lock. */

bool agent_test_dump_state_json(struct json_value *out, const char *key)
{
    if (!out) return false;
    json_set_object(out);
    json_push_kv_str(out, "schema", AGENT_TEST_STATE_SCHEMA);

    char status_dir[900];
    at_status_dir(status_dir, sizeof(status_dir));

    if (!key || !key[0]) {
        json_push_kv_str(out, "status", "error");
        json_push_kv_str(out, "error", "missing_key");
        json_push_kv_str(out, "detail",
            "pass the \"<kind>-<name>\" key, e.g. dumpstate agent_test "
            "test_group-wallet");
        json_push_kv_str(out, "status_dir", status_dir);
        return true;
    }
    if (!at_key_valid(key)) {
        json_push_kv_str(out, "status", "error");
        json_push_kv_str(out, "error", "invalid_key");
        return true;
    }

    char status_file[1100];
    at_status_file(key, status_file, sizeof(status_file));

    FILE *f = fopen(status_file, "r");
    if (!f) {
        json_push_kv_str(out, "status", "not_found");
        json_push_kv_str(out, "key", key);
        json_push_kv_str(out, "status_file", status_file);
        return true;
    }
    char buf[32768];
    size_t used = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[used] = '\0';

    struct json_value parsed;
    json_init(&parsed);
    if (!json_read(&parsed, buf, used) || parsed.type != JSON_OBJ) {
        json_free(&parsed);
        json_push_kv_str(out, "status", "error");
        json_push_kv_str(out, "error", "status_file_invalid_json");
        json_push_kv_str(out, "key", key);
        json_push_kv_str(out, "status_file", status_file);
        // obs-ok:agent-test-diagnostic-stderr (best-effort status telemetry / request refusal returns JSON error)
        fprintf(stderr, "[agent_test] %s:%d %s(): status file did not "
                "parse as a JSON object: %s\n", __FILE__, __LINE__,
                __func__, status_file);
        return true;
    }

    json_push_kv_str(out, "status", "ok");
    json_push_kv_str(out, "key", key);
    json_push_kv_str(out, "status_file", status_file);
    json_push_kv(out, "result", &parsed);
    json_free(&parsed);
    return true;
}
