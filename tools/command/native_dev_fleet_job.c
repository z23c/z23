/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: typed development jobs over an authorized SSH peer. */
#include "command/native_command.h"
#include "command/native_dev_job.h"
#include "base/hex.h"
#include "config/command_catalog.h"
#include "native_dev_fleet_job.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "util/spawn.h"
#include "../dev/test_group_catalog.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(ZCL_TESTING)
static zcl_fleet_job_test_transport fj_transport;
void zcl_fleet_job_set_test_transport(zcl_fleet_job_test_transport fn) { fj_transport = fn; }
#endif

static const char *fj_str(const struct json_value *o, const char *key)
{
    const char *value = zcl_dev_job_str(json_get(o, key));
    return value ? value : "";
}

static bool fj_token(const char *s, size_t max)
{
    size_t n = strlen(s);
    if (!n || n > max || s[0] == '-') return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.')) return false;
    }
    return true;
}

static bool fj_path(const char *s)
{
    if (*s != '/' || strlen(s) >= 1024) return false;
    for (const char *p = s + 1; *p;) {
        const char *end = strchr(p, '/');
        size_t n = end ? (size_t)(end - p) : strlen(p);
        if (!n || n > 255 || (n == 1 && p[0] == '.') ||
            (n == 2 && p[0] == '.' && p[1] == '.')) return false;
        char item[256]; memcpy(item, p, n); item[n] = 0;
        if (!fj_token(item, 255)) return false;
        if (!end) return true;
        p = end + 1;
    }
    return false;
}

static bool fj_head(const char *s)
{
    uint8_t bytes[20];
    return zcl_hex_decode_lower(s, bytes, sizeof bytes);
}

static void fj_fail(struct zcl_command_reply *reply, const char *code, const char *why)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                           code, "validate", false, false, why, "dev.fleet.job");
}

static bool fj_check_source(const char *cwd, const char *head)
{
    const char *rev[] = {"git", "rev-parse", "HEAD", NULL};
    const char *status[] = {"git", "status", "--porcelain", "--untracked-files=no", NULL};
    char text[1024];
    if (zcl_spawn_capture_in_dir_observed(rev, cwd, text, sizeof text, 15000, NULL) != 0) return false;
    text[strcspn(text, "\r\n")] = 0;
    if (strcmp(text, head)) return false;
    if (zcl_spawn_capture_in_dir_observed(status, cwd, text, sizeof text, 15000, NULL) != 0) return false;
    return text[0] == 0;
}

static bool fj_add_arg(struct json_value *arr, const char *text)
{
    struct json_value v; json_init(&v); json_set_str(&v, text);
    bool ok = json_push_back(arr, &v); json_free(&v); return ok;
}

/* A typed subcommand has its own input contract. Never pass the fleet
 * request through to the broader local job handler. */
static void fj_job_invoke(const struct zcl_command_request *parent,
                          const struct json_value *input,
                          struct zcl_command_reply *reply, const char *path,
                          zcl_command_handler_fn handler)
{
    struct zcl_command_request local = *parent;
    char why[256];
    local.input = input;
    local.spec = zcl_command_registry_find(zcl_command_catalog(), path, NULL);
    if (!local.spec ||
        !zcl_command_registry_input_validate(local.spec, input, why, sizeof why)) {
        fj_fail(reply, "JOB_INPUT_FAILED", "local job input contract is unavailable or rejected");
        return;
    }
    handler(&local, reply);
}

static void fj_local_start(const struct zcl_command_request *request,
                           struct zcl_command_reply *reply, const char *cwd,
                           const char *head, const char *task, const char *group)
{
    if (!fj_check_source(cwd, head)) { fj_fail(reply, "SOURCE_MISMATCH", "HEAD differs or tracked files are dirty"); return; }
    char only[256];
    struct json_value input, args; json_init(&input); json_set_object(&input);
    json_init(&args); json_set_array(&args);
    bool ok = fj_add_arg(&args, "devbuild") && fj_add_arg(&args, "--wait") && fj_add_arg(&args, "make");
    if (!strcmp(task, "test")) {
        int n = snprintf(only, sizeof only, "ONLY=%s", group);
        ok = ok && n > 0 && (size_t)n < sizeof only && fj_add_arg(&args, "t-fast-exact") && fj_add_arg(&args, only);
    } else ok = ok && fj_add_arg(&args, !strcmp(task, "build") ? "z23" : "lint");
    ok = ok && json_push_kv(&input, "argv", &args) && json_push_kv_str(&input, "cwd", cwd);
    json_free(&args);
    if (!ok) { json_free(&input); fj_fail(reply, "JOB_INPUT_FAILED", "could not construct job"); return; }
    fj_job_invoke(request, &input, reply, "dev.loop.job.start",
                  zcl_native_handle_dev_job_start);
    if (reply->status == ZCL_COMMAND_STATUS_PASSED) (void)json_push_kv_str(&reply->data, "preflight_head", head);
    json_free(&input);
}

static void fj_local_wait(const struct zcl_command_request *request,
                          struct zcl_command_reply *reply, const char *id, int64_t timeout)
{
    struct json_value input; json_init(&input); json_set_object(&input);
    bool ok = json_push_kv_str(&input, "job_id", id) && json_push_kv_int(&input, "timeout_s", timeout);
    if (!ok) { json_free(&input); fj_fail(reply, "JOB_INPUT_FAILED", "could not construct wait"); return; }
    fj_job_invoke(request, &input, reply, "dev.loop.job.wait",
                  zcl_native_handle_dev_job_wait);
    json_free(&input);
}

static bool fj_remote_state(const char *op, const char *state)
{
    if (!strcmp(op, "start"))
        return !strcmp(state, "started") || !strcmp(state, "attached");
    return !strcmp(state, "running") || !strcmp(state, "passed") ||
           !strcmp(state, "failed") || !strcmp(state, "lost");
}

static bool fj_remote_valid(const struct json_value *root, const char *op,
                            const char *head, const char *id)
{
    const struct json_value *v = json_get(root, "ok");
    const struct json_value *data = json_get(root, "data");
    if (!v || v->type != JSON_BOOL || !json_get_bool(v) || !data || data->type != JSON_OBJ)
        return false;
    if (strcmp(fj_str(root, "schema"), "zcl.result.v1") ||
        strcmp(fj_str(root, "command"), "dev.fleet.job") ||
        !fj_token(fj_str(data, "job_id"), 64) || !fj_remote_state(op, fj_str(data, "state")))
        return false;
    return !strcmp(op, "start") ? !strcmp(fj_str(data, "preflight_head"), head)
                                : !strcmp(fj_str(data, "job_id"), id);
}

/* A native refusal is distinguishable from an unknown transport outcome. */
static bool fj_refusal_unmutated(const struct json_value *root,
                                 const struct json_value *error)
{
    const char *status = fj_str(root, "status");
    const struct json_value *mutated = json_get(error, "mutated");
    return (!strcmp(status, "failed") || !strcmp(status, "blocked")) &&
           mutated && mutated->type == JSON_BOOL && !json_get_bool(mutated);
}

static bool fj_remote_refused(struct zcl_command_reply *reply,
                              const struct json_value *root)
{
    const struct json_value *ok = json_get(root, "ok");
    const struct json_value *error = json_get(root, "error");
    if (!ok || ok->type != JSON_BOOL || json_get_bool(ok) || !error || error->type != JSON_OBJ ||
        strcmp(fj_str(root, "schema"), "zcl.result.v1") ||
        strcmp(fj_str(root, "command"), "dev.fleet.job")) return false;
    if (!fj_refusal_unmutated(root, error)) return false;
    const char *code = fj_str(error, "code"), *message = fj_str(error, "message");
    if (!*code || !*message) return false;
    char evidence[256];
    (void)snprintf(evidence, sizeof evidence, "peer code=%.63s message=%.160s", code, message);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                           "PEER_REFUSED", "peer", false, false,
                           "peer returned a refusal; reconcile before retry", evidence);
    return true;
}

static void fj_remote(struct zcl_command_reply *reply, const char *peer,
                      const char *slot, const char *op, const char *cwd,
                      const char *head, const char *task, const char *group,
                      const char *id, int64_t timeout)
{
    char a[1040], b[1040], c[1040], d[1040], e[1040], t[64], output[65536] = {0};
    snprintf(a, sizeof a, "--operation=%s", op);
    snprintf(b, sizeof b, "--cwd=%s", cwd);
    snprintf(c, sizeof c, "--expected_head=%s", head);
    snprintf(d, sizeof d, "--task=%s", task);
    snprintf(e, sizeof e, "--group=%s", group);
    snprintf(t, sizeof t, "--timeout_s=%lld", (long long)timeout);
    char j[1100]; snprintf(j, sizeof j, "--job_id=%s", id);
    const char *start[] = {"ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "--", peer, slot,
                           "dev", "fleet", "job", a, b, c, d, e, "--json", NULL};
    const char *start_no_group[] = {"ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "--", peer, slot,
                                    "dev", "fleet", "job", a, b, c, d, "--json", NULL};
    const char *wait[] = {"ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "--", peer, slot,
                          "dev", "fleet", "job", a, j, t, "--json", NULL};
    bool timed_out = false;
    const char *const *argv = !strcmp(op, "wait") ? wait : (*group ? start : start_no_group);
    int rc;
#if defined(ZCL_TESTING)
    if (fj_transport) rc = fj_transport(argv, output, sizeof output, 250000, &timed_out);
    else
#endif
        rc = zcl_spawn_capture_observed(argv, output, sizeof output, 250000, &timed_out);
    struct json_value root; json_init(&root);
    const char *start_json = strchr(output, '{');
    bool parsed = !timed_out && rc >= 0 && start_json && json_read(&root, start_json, strlen(start_json));
    if (parsed && fj_remote_refused(reply, &root)) {
        json_free(&root);
        return;
    }
    bool ok = parsed && rc == 0 && fj_remote_valid(&root, op, head, id);
    if (ok) {
        json_free(&reply->data);
        ok = json_copy_checked(&reply->data, json_get(&root, "data"));
    }
    if (!ok)
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "PEER_OUTCOME_UNKNOWN", "peer", false, !strcmp(op, "start"),
            "peer outcome unknown; execution may have started; reconcile before retry", "dev.fleet.job");
    json_free(&root);
}

static bool fj_start_valid(const char *cwd, const char *head, const char *task,
                           const char *group)
{
    if (!fj_path(cwd) || !fj_head(head)) return false;
    if (strcmp(task, "build") && strcmp(task, "test") && strcmp(task, "lint")) return false;
    if (strcmp(task, "test")) return !*group;
    char full[ZCL_TEST_GROUP_FULL_MAX];
    return fj_token(group, 95) && zcl_test_group_resolve_exact(group, full);
}

/* A remote executable and alias are data, never shell syntax. */
static bool fj_peer_valid(const char *peer, const char *slot)
{
    if (!*peer) return true;
    const char *leaf = strrchr(slot, '/');
    return fj_token(peer, 64) && fj_path(slot) && leaf && !strcmp(leaf + 1, "z23-dev");
}

static bool fj_wait_valid(const char *id, int64_t timeout)
{
    return fj_token(id, 64) && timeout >= 1 && timeout <= 230;
}

/* Optional fields must not silently become absent when malformed. */
static bool fj_input_shape(const struct json_value *input)
{
    static const char *const strings[] = {
        "operation", "peer", "peer_binary", "cwd", "expected_head", "task", "group", "job_id"
    };
    if (!input || input->type != JSON_OBJ) return false;
    for (size_t i = 0; i < sizeof strings / sizeof strings[0]; i++) {
        const struct json_value *v = json_get(input, strings[i]);
        if (v && (v->type != JSON_STR || !json_get_str(v)[0])) return false;
    }
    const struct json_value *timeout = json_get(input, "timeout_s");
    if (timeout && timeout->type != JSON_INT) return false;
    return !json_get(input, "peer_binary") || json_get(input, "peer");
}

void zcl_native_handle_dev_fleet_job(const struct zcl_command_request *request,
                                     struct zcl_command_reply *reply)
{
    if (!reply) return;
    if (!request || !fj_input_shape(request->input)) {
        fj_fail(reply, "INVALID_INPUT", "invalid input field shape"); return;
    }
    const struct json_value *in = request->input;
    const char *op = fj_str(in, "operation"), *peer = fj_str(in, "peer"), *slot = fj_str(in, "peer_binary");
    const char *cwd = fj_str(in, "cwd"), *head = fj_str(in, "expected_head"), *task = fj_str(in, "task");
    const char *group = fj_str(in, "group"), *id = fj_str(in, "job_id");
    const struct json_value *tv = json_get(in, "timeout_s");
    int64_t timeout = tv && tv->type == JSON_INT ? json_get_int(tv) : 60;
    if (strcmp(op, "start") && strcmp(op, "wait")) { fj_fail(reply, "INVALID_INPUT", "operation must be start or wait"); return; }
    if (!fj_peer_valid(peer, slot)) {
        fj_fail(reply, "INVALID_INPUT", "invalid peer or executable path"); return;
    }
    if (!strcmp(op, "wait")) {
        if (!fj_wait_valid(id, timeout)) { fj_fail(reply, "INVALID_INPUT", "invalid job id or timeout"); return; }
        if (*peer) fj_remote(reply, peer, slot, op, "", "", "", "", id, timeout);
        else fj_local_wait(request, reply, id, timeout);
        return;
    }
    if (!fj_start_valid(cwd, head, task, group)) {
        fj_fail(reply, "INVALID_INPUT", "invalid workspace, head, task or test group"); return;
    }
    if (*peer) fj_remote(reply, peer, slot, op, cwd, head, task, group, "", timeout);
    else fj_local_start(request, reply, cwd, head, task, group);
}
