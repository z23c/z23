/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: fixed confined Codex adapter readiness for the native `zcode work`
 * commands — finding the one runner image beside this executable, probing its
 * identity, binding, credential, sandbox and bounded packet, and rendering
 * `zcode work preflight` — split out of native_zcode_work_run_command.c so
 * each function stays under the cyclomatic-complexity cap; sibling
 * declarations live in native_zcode_work_run_priv.h. */

#include "command/native_command.h"
#include "native_zcode_work_run_priv.h"

#include "json/json.h"
#include "platform/directory_compat.h"
#include "platform/os_proc.h"
#include "platform/positioned_file.h"
#include "platform/time_compat.h"
#include "util/clientversion.h"
#include "util/file_tree_ops.h"
#include "util/spawn.h"
#include "vcs/zcode_agent_context.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_task_index.h"
#include "vcs/zcode_write_scope.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct run_adapter_preflight {
    bool runner_structural;
    bool runner_identity;
    bool codex_binding;
    bool credential;
    bool sandbox;
    bool packet;
    int64_t packet_bytes;
    char codex_artifact_sha3[65];
    char packet_detail[256];
};

/* Both the run adapter and preflight look for exactly one runner image beside
 * the running executable under the same fixed name; only the admissibility
 * question asked of that image differs. */
static bool run_runner_image_path(char out[ZWORK_RUN_PATH_MAX])
{
    char executable[ZWORK_RUN_PATH_MAX];
    if (!os_proc_exe_path(executable, sizeof(executable)))
        return false;
    char *slash = strrchr(executable, '/');
#if defined(_WIN32)
    char *backslash = strrchr(executable, '\\');
    if (!slash || (backslash && backslash > slash)) slash = backslash;
#endif
    if (!slash)
        return false;
    *slash = '\0';
    /* The image suffix is chosen BEFORE the call: _FORTIFY_SOURCE makes
     * snprintf a macro, and a preprocessor directive between a macro's
     * parentheses is undefined behaviour. */
#if defined(_WIN32)
    const char *const runner_ext = ".exe";
#else
    const char *const runner_ext = "";
#endif
    int n = snprintf(out, ZWORK_RUN_PATH_MAX,
                     "%s/zclassic23-zcode-adapter-runner%s", executable,
                     runner_ext);
    return n > 0 && (size_t)n < ZWORK_RUN_PATH_MAX;
}

static bool run_runner_image_executable(const char *path)
{
#if defined(_WIN32)
    struct platform_positioned_file runner;
    platform_positioned_file_init(&runner);
    bool ok = platform_positioned_file_open(&runner, path) &&
        platform_positioned_file_is_executable(&runner) &&
        platform_positioned_file_is_current_user_only(&runner);
    platform_positioned_file_close(&runner);
    return ok;
#else
    return access(path, X_OK) == 0;
#endif
}

/* Exactly one supported single-run Codex credential must be present: neither
 * none nor both. */
static bool run_codex_credential_present(void)
{
    const char *api_key = getenv("CODEX_API_KEY");
    const char *access_token = getenv("CODEX_ACCESS_TOKEN");
    if ((!api_key || !api_key[0]) &&
        (!access_token || !access_token[0]))
        return false;
    if ((api_key && api_key[0]) && (access_token && access_token[0]))
        return false;
    return true;
}

bool run_codex_runner_path(char out[ZWORK_RUN_PATH_MAX])
{
    if (!run_codex_credential_present())
        return false;
    if (!run_runner_image_path(out))
        return false;
    return run_runner_image_executable(out);
}

/* Preflight asks the stricter structural question: the image must be a
 * regular file this user owns, executable by that owner and writable by
 * nobody else. */
static bool run_preflight_runner_path(char out[ZWORK_RUN_PATH_MAX])
{
    if (!run_runner_image_path(out))
        return false;
#if defined(_WIN32)
    return run_runner_image_executable(out);
#else
    struct stat st;
    return lstat(out, &st) == 0 && S_ISREG(st.st_mode) &&
        st.st_uid == getuid() && (st.st_mode & 0100u) != 0 &&
        (st.st_mode & 0022u) == 0;
#endif
}

static bool run_preflight_invoke(const char *runner, const char *verb,
                                 char output[ZWORK_PREFLIGHT_OUTPUT_MAX])
{
#if defined(_WIN32)
    (void)runner; (void)verb;
    memset(output, 0, ZWORK_PREFLIGHT_OUTPUT_MAX);
    return false;
#else
    const char *const argv[] = { runner, verb, NULL };
    memset(output, 0, ZWORK_PREFLIGHT_OUTPUT_MAX);
    return zcl_spawn_capture(argv, output, ZWORK_PREFLIGHT_OUTPUT_MAX,
                             30000) == 0;
#endif
}

static bool run_preflight_runner_identity(const char *runner)
{
    char output[ZWORK_PREFLIGHT_OUTPUT_MAX];
    if (!run_preflight_invoke(runner, "--identity", output)) return false;
    struct json_value document;
    json_init(&document);
    bool ok = json_read(&document, output, strlen(output)) &&
        document.type == JSON_OBJ;
    const char *schema = ok ? run_str(&document, "schema") : NULL;
    const char *source = ok ? run_str(&document, "source_id") : NULL;
    ok = schema && strcmp(schema,
             "zcl.zcode_adapter_runner_identity.v1") == 0 && source &&
         strcmp(source, zcl_build_source_id_sha256()) == 0;
    json_free(&document);
    return ok;
}

static bool run_preflight_codex_binding(
    const char *runner, char artifact_sha3[65])
{
    char output[ZWORK_PREFLIGHT_OUTPUT_MAX];
    artifact_sha3[0] = '\0';
    if (!run_preflight_invoke(runner, "--binding", output)) return false;
    struct json_value document;
    json_init(&document);
    bool ok = json_read(&document, output, strlen(output)) &&
        document.type == JSON_OBJ &&
        json_get_bool(json_get(&document, "ready"));
    const char *digest = ok ? run_str(&document, "artifact_sha3") : NULL;
    ok = digest && strlen(digest) == 64u;
    if (ok) (void)snprintf(artifact_sha3, 65, "%s", digest);
    json_free(&document);
    return ok;
}

static bool run_preflight_credential(void)
{
    const char *api_key = getenv("CODEX_API_KEY");
    const char *access_token = getenv("CODEX_ACCESS_TOKEN");
    bool have_api = api_key && api_key[0];
    bool have_token = access_token && access_token[0];
    const char *value = have_api ? api_key : access_token;
    return have_api != have_token && value && strlen(value) <= 16384u;
}

static bool run_preflight_sandbox(const char *runner)
{
#if defined(_WIN32)
    (void)runner;
    return false;
#else
    char root[] = "/tmp/z23-adapter-preflight.XXXXXX";
    if (!mkdtemp(root)) return false;
    struct json_value packet;
    json_init(&packet); json_set_object(&packet);
    char packet_path[ZWORK_RUN_PATH_MAX] = {0};
    bool staged = run_write_packet(root, &packet, packet_path);
    json_free(&packet);
    char output[ZWORK_PREFLIGHT_OUTPUT_MAX] = {0};
    const char *const argv[] = {
        runner, "--preflight", root, packet_path, NULL,
    };
    int rc = staged ? zcl_spawn_capture(
        argv, output, sizeof(output), 30000) : -1;
    bool started = false;
    struct json_value response;
    json_init(&response);
    if (rc == 0 && json_read(&response, output, strlen(output)) &&
        response.type == JSON_OBJ)
        started = json_get_bool(json_get(&response, "sandbox_started")) &&
            !json_get_bool(json_get(&response, "model_request_attempted"));
    json_free(&response);
    struct zcl_result removed = zcl_tree_remove(root);
    return started && removed.ok;
#endif
}

/* Resolve the two directories the bounded preflight packet is composed from,
 * naming the exact one that could not be resolved. */
static bool run_preflight_directories(
    const struct zcl_command_request *request,
    char workspace[ZWORK_RUN_PATH_MAX], char datadir[ZWORK_RUN_PATH_MAX],
    char detail[256])
{
    const char *workspace_arg = run_str(request->input, "workspace");
    const char *datadir_arg = run_str(request->input, "datadir");
    if (!workspace_arg || !workspace_arg[0]) workspace_arg = ".";
    if (!platform_directory_canonical_real(workspace_arg, workspace,
                                           ZWORK_RUN_PATH_MAX)) {
        (void)snprintf(detail, 256,
                       "workspace must resolve to an existing directory");
        return false;
    }
    if (datadir_arg && datadir_arg[0] &&
        !platform_directory_canonical_real(datadir_arg, datadir,
                                           ZWORK_RUN_PATH_MAX)) {
        (void)snprintf(detail, 256,
                       "datadir must resolve to an existing node directory");
        return false;
    }
    return true;
}

/* Preflight admits only an unambiguous, unexpired task that carries one
 * complete verified expert context; anything else leaves the packet check
 * unavailable rather than composing a packet from partial facts. */
static bool run_preflight_selection(struct run_selection *selection,
                                    const char *workspace, const char *work)
{
    selection->index = vcs_zcode_task_index_build(
        workspace, platform_time_wall_unix());
    selection->entry = selection->index
        ? run_resolve(selection->index, work, &selection->ambiguous) : NULL;
    selection->context_entry = selection->entry
        ? vcs_zcode_task_index_context_for_task(
              selection->index, selection->entry->task_root_hex,
              &selection->context_ambiguous) : NULL;
    return selection->entry && selection->context_entry &&
        !selection->ambiguous && !selection->context_ambiguous &&
        !selection->entry->expired &&
        run_load_task(workspace, selection->entry->task_root_hex,
                      &selection->task) &&
        (selection->goal = run_load_goal(workspace, &selection->task)) !=
            NULL &&
        run_load_context(workspace, selection->context_entry,
                         &selection->task, selection->entry->task_root_hex,
                         &selection->context,
                         &selection->context_admission) &&
        selection->context_admission == VCS_ZCODE_AGENT_CONTEXT_OK &&
        run_load_scope(workspace, &selection->task, &selection->scope);
}

static void run_preflight_selection_detail(
    const struct run_selection *selection, char detail[256])
{
    (void)snprintf(detail, 256, "%s",
        selection->entry && selection->entry->expired
            ? "task expired; start new bounded work" :
        selection->context_ambiguous ? "task has multiple verified contexts" :
        selection->ambiguous ? "work selector is ambiguous" :
        "verified task, goal and unique context are required");
}

static bool run_preflight_packet(
    const struct zcl_command_request *request, int64_t *bytes_out,
    char detail[256])
{
    char workspace[ZWORK_RUN_PATH_MAX], datadir[ZWORK_RUN_PATH_MAX] = {0};
    if (!run_preflight_directories(request, workspace, datadir, detail))
        return false;
    const char *work = run_str(request->input, "work");
    struct run_selection selection;
    run_selection_init(&selection);
    bool loaded = run_preflight_selection(&selection, workspace, work);
    struct json_value packet;
    json_init(&packet);
    bool ready = loaded && run_packet(
        &packet, selection.goal, workspace, datadir, &selection.task,
        &selection.context, &selection.scope, detail);
    size_t bytes = ready ? json_write(&packet, NULL, 0) : 0;
    ready = ready && bytes > 0 && bytes <= ZWORK_ADAPTER_PACKET_MAX;
    if (ready) *bytes_out = (int64_t)bytes;
    if (!loaded)
        run_preflight_selection_detail(&selection, detail);
    json_free(&packet);
    run_selection_free(&selection);
    return ready;
}

static const char *run_preflight_primary(
    const struct run_adapter_preflight *state, const char **current,
    const char **next, bool *human)
{
    *human = true;
    if (!state->runner_structural || !state->runner_identity) {
        *current = state->runner_structural ? "runner_source_mismatch"
                                            : "runner_unavailable";
        *next = "make zclassic23-zcode-adapter-runner";
        return "ADAPTER_RUNNER_UNBOUND";
    }
    if (!state->codex_binding) {
        *current = "codex_executable_unbound";
        *next = "install one owner-approved Codex executable binding, then rerun z23 zcode work preflight";
        return "CODEX_EXECUTABLE_UNBOUND";
    }
    if (!state->credential) {
        *current = "single_run_credential_unavailable";
        *next = "provide exactly one supported single-run Codex credential, then rerun z23 zcode work preflight";
        return "CODEX_CREDENTIAL_UNAVAILABLE";
    }
    if (!state->sandbox) {
        *current = "filesystem_sandbox_start_failed";
        *next = "enable the required unprivileged filesystem sandbox, then rerun z23 zcode work preflight";
        return "FILESYSTEM_SANDBOX_UNAVAILABLE";
    }
    if (!state->packet) {
        *current = "bounded_packet_unavailable";
        *next = "run z23 zcode work start for one exact goal, then rerun z23 zcode work preflight with that work id";
        return "ADAPTER_PACKET_UNAVAILABLE";
    }
    *human = false;
    *current = "ready";
    *next = "z23 zcode work run --input='{\"workspace\":\".\",\"work\":\"latest\",\"adapter\":\"codex\"}'";
    return "NONE";
}


static bool run_preflight_executable_json(
    struct json_value *executable, const struct run_adapter_preflight *state)
{
    return json_push_kv_bool(executable, "ready",
                             state->runner_identity && state->codex_binding) &&
        json_push_kv_bool(executable, "runner_bound",
                          state->runner_identity) &&
        json_push_kv_bool(executable, "codex_bound", state->codex_binding) &&
        (!state->codex_artifact_sha3[0] ||
         json_push_kv_str(executable, "artifact_sha3",
                          state->codex_artifact_sha3));
}

static bool run_preflight_capability_json(
    struct json_value *credential, struct json_value *sandbox,
    struct json_value *packet, const struct run_adapter_preflight *state)
{
    return json_push_kv_bool(credential, "ready", state->credential) &&
        json_push_kv_bool(credential, "value_exposed", false) &&
        json_push_kv_bool(sandbox, "ready", state->sandbox) &&
        json_push_kv_bool(sandbox, "model_request_attempted", false) &&
        json_push_kv_bool(packet, "ready", state->packet) &&
        json_push_kv_int(packet, "bytes", state->packet_bytes) &&
        (!state->packet_detail[0] ||
         json_push_kv_str(packet, "detail", state->packet_detail));
}

static bool run_preflight_checks_json(
    struct json_value *checks, const struct run_adapter_preflight *state)
{
    struct json_value executable, credential, sandbox, packet;
    json_init(&executable); json_set_object(&executable);
    json_init(&credential); json_set_object(&credential);
    json_init(&sandbox); json_set_object(&sandbox);
    json_init(&packet); json_set_object(&packet);
    bool ok = run_preflight_executable_json(&executable, state) &&
        run_preflight_capability_json(&credential, &sandbox, &packet, state) &&
        json_push_kv(checks, "executable_binding", &executable) &&
        json_push_kv(checks, "credential_capability", &credential) &&
        json_push_kv(checks, "filesystem_sandbox", &sandbox) &&
        json_push_kv(checks, "packet", &packet);
    json_free(&packet); json_free(&sandbox); json_free(&credential);
    json_free(&executable);
    return ok;
}

static bool run_preflight_reply_json(
    struct zcl_command_reply *reply, const struct json_value *checks,
    const char *blocker, const char *current, const char *next, bool human,
    bool ready)
{
    return json_push_kv_str(&reply->data, "adapter", "codex") &&
        json_push_kv_bool(&reply->data, "ready", ready) &&
        json_push_kv_bool(&reply->data, "model_request_attempted", false) &&
        json_push_kv(&reply->data, "checks", checks) &&
        json_push_kv_str(&reply->data, "blocker", blocker) &&
        json_push_kv_str(&reply->data, "error_code", blocker) &&
        json_push_kv_str(&reply->data, "current_state", current) &&
        json_push_kv_bool(&reply->data, "retryable", !ready) &&
        json_push_kv_bool(&reply->data, "human_action_required", human) &&
        json_push_kv_str(&reply->data, "next_action", next);
}

/* Every readiness fact is probed before any of them is rendered, so one
 * unavailable capability never hides the state of the others. */
static void run_preflight_probe(const struct zcl_command_request *request,
                                struct run_adapter_preflight *state)
{
    char runner[ZWORK_RUN_PATH_MAX] = {0};
    state->runner_structural = run_preflight_runner_path(runner);
    state->runner_identity = state->runner_structural &&
        run_preflight_runner_identity(runner);
    state->codex_binding = state->runner_structural &&
        run_preflight_codex_binding(runner, state->codex_artifact_sha3);
    state->credential = run_preflight_credential();
    state->sandbox = state->runner_structural && run_preflight_sandbox(runner);
    state->packet = run_preflight_packet(
        request, &state->packet_bytes, state->packet_detail);
}

void zcl_native_handle_zcode_work_preflight(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    struct run_adapter_preflight state = {0};
    run_preflight_probe(request, &state);
    const char *current = NULL, *next = NULL;
    bool human = false;
    const char *blocker = run_preflight_primary(
        &state, &current, &next, &human);
    bool ready = strcmp(blocker, "NONE") == 0;
    struct json_value checks;
    json_init(&checks); json_set_object(&checks);
    bool ok = run_preflight_checks_json(&checks, &state) &&
        run_preflight_reply_json(reply, &checks, blocker, current, next,
                                 human, ready);
    json_free(&checks);
    if (!ok) {
        run_fail(reply, "PREFLIGHT_OUTPUT_FAILED", "render",
                 "adapter readiness could not be rendered", false, false);
        return;
    }
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}
