/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Typed ZCODE science study/work/review/vote commands over the
 *          CAS-authoritative plan/commit services. */

#include "command/native_command.h"
#include "command/native_zcode_discovery.h"
#include "command/native_zcode_policy.h"

#include "base/hex.h"
#include "controllers/rpc_client.h"
#include "json/json.h"
#include "models/database.h"
#include "platform/directory_compat.h"
#include "platform/time_compat.h"
#include "services/zcode_science_service.h"
#include "util/safe_alloc.h"
#include "vcs/build_action.h"
#include "vcs/package_reward.h"
#include "vcs/package_service.h"
#include "vcs/package_store.h"
#include "vcs/package_swarm_node.h"
#include "vcs/zcode_dht_service.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ZSCI_PATH_MAX 4096
#define ZSCI_WIRE_MAX 422 /* study_spec.v1 is the largest science wire */
#define ZSCI_LIST_MAX 256
#define ZSCI_POINTER_SECONDS INT64_C(86400) /* inside the default delegation */

static const char *zsci_str(const struct json_value *input, const char *key)
{
    const struct json_value *v = input ? json_get(input, key) : NULL;
    return v ? json_get_str(v) : NULL;
}

static int64_t zsci_int(const struct json_value *input, const char *key,
                        int64_t fallback)
{
    const struct json_value *v = input ? json_get(input, key) : NULL;
    return v ? json_get_int(v) : fallback;
}

static bool zsci_confirm(const struct json_value *input)
{
    const struct json_value *v = input ? json_get(input, "confirm") : NULL;
    return v && json_get_bool(v);
}

static void zsci_fail(struct zcl_command_reply *reply, const char *code,
                      const char *detail, const char *leaf)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, "validate", false,
                           false, detail, leaf);
}

static void zsci_fail_service(struct zcl_command_reply *reply,
                              const char *code, const char *message,
                              const char *leaf)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, code, "commit", false,
                           false, message, leaf);
}

static const char *zsci_datadir(const struct json_value *input)
{
    const char *datadir = zsci_str(input, "datadir");
    if (!datadir || !datadir[0])
        datadir = zcl_native_command_datadir();
    return datadir;
}

static bool zsci_policy_allows(
    const struct json_value *input, enum vcs_zcode_sovereignty_action action,
    const char *semantic_hex, const char *transport_hex,
    const char *publisher_hex,
    struct zcl_command_reply *reply, const char *leaf)
{
    struct vcs_zcode_sovereignty_subject subject;
    memset(&subject, 0, sizeof(subject));
    if (semantic_hex &&
        (strlen(semantic_hex) != 64 ||
         !zcl_hex_decode_lower(semantic_hex, subject.semantic_root, 32))) {
        zsci_fail(reply, "BAD_ROOT", "semantic root must be 64 lowercase hex",
                  leaf);
        return false;
    }
    if (transport_hex &&
        (strlen(transport_hex) != 64 ||
         !zcl_hex_decode_lower(transport_hex, subject.transport_root, 32))) {
        zsci_fail(reply, "BAD_BLOB_ROOT",
                  "transport root must be 64 lowercase hex", leaf);
        return false;
    }
    if (publisher_hex &&
        (strlen(publisher_hex) != 64 ||
         !zcl_hex_decode_lower(publisher_hex, subject.publisher_zid, 32))) {
        zsci_fail(reply, "BAD_PUBLISHER_ZID",
                  "publisher ZID must be 64 lowercase hex", leaf);
        return false;
    }
    (void)snprintf(subject.service_type, sizeof(subject.service_type),
                   "science");
    char error[192] = {0};
    if (!zcl_native_zcode_policy_allows(zsci_datadir(input), action, &subject,
                                        error, sizeof(error))) {
        zsci_fail_service(reply, "SOVEREIGNTY_DENIED",
                          error[0] ? error : "local policy denied the action",
                          leaf);
        return false;
    }
    return true;
}

static bool zsci_open_db(const char *datadir, struct node_db *ndb)
{
    char db_path[ZSCI_PATH_MAX];
    int n = datadir
        ? snprintf(db_path, sizeof(db_path), "%s/node.db", datadir) : -1;
    return n > 0 && (size_t)n < sizeof(db_path) &&
           node_db_open(ndb, db_path);
}

static const char *zsci_workspace(const struct json_value *input,
                                  char *resolved, size_t resolved_size)
{
    const char *workspace = zsci_str(input, "workspace");
    if (workspace && workspace[0]) {
        if (platform_directory_canonical_real(workspace, resolved,
                                              resolved_size))
            return resolved;
        return NULL;
    }
    const char *datadir = zsci_datadir(input);
    int n = snprintf(resolved, resolved_size, "%s/zcode", datadir);
    return n > 0 && (size_t)n < resolved_size ? resolved : NULL;
}

static uint8_t *zsci_wire(const struct json_value *input, const char *key,
                          size_t *len_out)
{
    *len_out = 0;
    const char *hex = zsci_str(input, key);
    size_t hex_len = hex ? strlen(hex) : 0;
    if (hex_len == 0 || (hex_len & 1u) != 0 || hex_len > ZSCI_WIRE_MAX * 2u)
        return NULL;
    size_t len = hex_len / 2u;
    uint8_t *wire = zcl_malloc(len, "zcode.science.wire");
    if (!wire || !zcl_hex_decode_lower(hex, wire, len)) {
        free(wire);
        return NULL;
    }
    *len_out = len;
    return wire;
}

static int64_t zsci_now(const struct json_value *input)
{
    return zsci_int(input, "now_unix",
                    (int64_t)platform_time_wall_unix());
}

static void zsci_push_plan(struct json_value *data,
                           const struct zcode_science_plan_out *plan,
                           const char *commit_leaf)
{
    (void)json_push_kv_str(data, "plan_root", plan->plan_root);
    (void)json_push_kv_str(data, "request_hash", plan->request_hash);
    (void)json_push_kv_int(data, "expires_unix", plan->expires_unix);
    (void)json_push_kv_bool(data, "already_planned", plan->already_planned);
    (void)json_push_kv_str(data, "state", "PLANNED");
    (void)json_push_kv_str(data, "commit_command", commit_leaf);
}

static void zsci_push_commit(struct json_value *data,
                             const struct zcode_science_commit_out *commit)
{
    (void)json_push_kv_str(data, "result_root", commit->result_root);
    (void)json_push_kv_bool(data, "already_committed",
                            commit->already_committed);
    (void)json_push_kv_str(data, "state", "COMMITTED");
    (void)json_push_kv_str(data, "authority", "CANONICAL_CAS_WIRE");
}

static void zsci_push_entry(struct json_value *data,
                            const struct db_zcode_science_entry *row,
                            const char *kind)
{
    (void)json_push_kv_str(data, "root", row->root);
    (void)json_push_kv_str(data, "kind", kind);
    if (row->study_root[0])
        (void)json_push_kv_str(data, "study_root", row->study_root);
    if (row->link_root[0])
        (void)json_push_kv_str(data, "link_root", row->link_root);
    if (row->aux_root[0])
        (void)json_push_kv_str(data, "aux_root", row->aux_root);
    if (row->author[0])
        (void)json_push_kv_str(data, "author", row->author);
    (void)json_push_kv_int(data, "code", row->code);
    (void)json_push_kv_int(data, "flags", row->flags);
    (void)json_push_kv_int(data, "sequence", row->sequence);
    (void)json_push_kv_int(data, "created_at", row->created_at);
    (void)json_push_kv_int(data, "expires_at", row->expires_at);
}

/* Build the executed fixed action from input fields. The kind selects the
 * fixed descriptors (workdir, output, resource policy) and the fixed
 * flags/environment roots; the caller pins source/input/toolchain roots and
 * the sequence. Returns false (after setting an error body) on bad input. */
static bool zsci_action(const struct json_value *input,
                        struct vcs_build_action_v1 *action,
                        struct zcl_command_reply *reply, const char *leaf)
{
    const char *kind = zsci_str(input, "action_kind");
    if (!kind || !kind[0])
        kind = VCS_BUILD_ACTION_KIND_BENCHMARK_V1;
    if (vcs_build_action_v1_work_kind(kind) == 0) {
        zsci_fail(reply, "BAD_ACTION_KIND",
                  "action_kind must name a registered fixed action", leaf);
        return false;
    }
    memset(action, 0, sizeof(*action));
    const char *workdir = NULL, *output = NULL, *policy = NULL;
    if (!vcs_build_action_v1_descriptors(kind, &workdir, &output, &policy) ||
        !vcs_build_action_v1_fixed_flags_root_for_kind(kind,
                                                       action->flags_sha3) ||
        !vcs_build_action_v1_fixed_environment_root_for_kind(
            kind, action->environment_sha3)) {
        zsci_fail(reply, "BAD_ACTION_KIND",
                  "action kind has no fixed descriptors", leaf);
        return false;
    }
    (void)snprintf(action->target, sizeof(action->target), "%s",
                   VCS_BUILD_TARGET_V1);
    (void)snprintf(action->virtual_workdir, sizeof(action->virtual_workdir),
                   "%s", workdir);
    (void)snprintf(action->declared_outputs, sizeof(action->declared_outputs),
                   "%s", output);
    (void)snprintf(action->resource_policy, sizeof(action->resource_policy),
                   "%s", policy);
    const char *source_cas = zsci_str(input, "action_source_cas_sha3");
    const char *input_root = zsci_str(input, "action_input_root_sha3");
    const char *capsule = zsci_str(input, "action_toolchain_capsule_sha3");
    if (!source_cas || !input_root || !capsule ||
        !zcl_hex_decode_lower(source_cas, action->source_cas_sha3, 32) ||
        !zcl_hex_decode_lower(input_root, action->input_root_sha3, 32) ||
        !zcl_hex_decode_lower(capsule, action->toolchain_capsule_sha3, 32)) {
        zsci_fail(reply, "BAD_ACTION_ROOTS",
                  "action source/input/toolchain roots must be 64 lowercase hex",
                  leaf);
        return false;
    }
    action->sequence = (uint64_t)zsci_int(input, "action_sequence", 1);
    return true;
}

/* True when the work wire is a reproduction (no action/method/profile
 * inputs are needed for those). */
static bool zsci_wire_is_reproduction(const uint8_t *wire, size_t len)
{
    static const uint8_t magic[8] = {'Z','C','R','E','P','R','\r','\n'};
    return wire && len == 251u && memcmp(wire, magic, sizeof(magic)) == 0;
}

void zcl_native_handle_zcode_science_study_plan(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    size_t wire_len = 0;
    uint8_t *wire = zsci_wire(request->input, "wire_hex", &wire_len);
    if (!wire) {
        zsci_fail(reply, "BAD_WIRE",
                  "wire_hex must be the exact study_spec.v1 wire as even lowercase hex",
                  "zcode.science.study.plan");
        return;
    }
    struct node_db ndb = {0};
    if (!zsci_open_db(zsci_datadir(request->input), &ndb)) {
        free(wire);
        zsci_fail_service(reply, "DATABASE_OPEN_FAILED",
                          "the science plan ledger could not be opened",
                          "zcode.science.study.plan");
        return;
    }
    char ws[ZSCI_PATH_MAX];
    struct zcode_science_plan_out plan;
    struct zcl_result planned = zcode_science_study_plan(
        &ndb, zsci_workspace(request->input, ws, sizeof(ws)), wire, wire_len,
        zsci_now(request->input), &plan);
    node_db_close(&ndb);
    free(wire);
    if (!planned.ok) {
        zsci_fail_service(reply, "STUDY_PLAN_REFUSED", planned.message,
                          "zcode.science.study.plan");
        return;
    }
    zsci_push_plan(&reply->data, &plan, "zcode.science.study.commit");
}

void zcl_native_handle_zcode_science_study_commit(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    size_t wire_len = 0;
    uint8_t *wire = zsci_wire(request->input, "wire_hex", &wire_len);
    if (!wire) {
        zsci_fail(reply, "BAD_WIRE",
                  "wire_hex must repeat the planned study_spec.v1 wire exactly",
                  "zcode.science.study.commit");
        return;
    }
    struct node_db ndb = {0};
    if (!zsci_open_db(zsci_datadir(request->input), &ndb)) {
        free(wire);
        zsci_fail_service(reply, "DATABASE_OPEN_FAILED",
                          "the science plan ledger could not be opened",
                          "zcode.science.study.commit");
        return;
    }
    char ws[ZSCI_PATH_MAX];
    struct zcode_science_commit_out commit;
    struct zcl_result committed = zcode_science_study_commit(
        &ndb, zsci_workspace(request->input, ws, sizeof(ws)), wire, wire_len,
        zsci_confirm(request->input), zsci_now(request->input), &commit);
    node_db_close(&ndb);
    free(wire);
    if (!committed.ok) {
        zsci_fail_service(reply, "STUDY_COMMIT_REFUSED", committed.message,
                          "zcode.science.study.commit");
        return;
    }
    zsci_push_commit(&reply->data, &commit);
    (void)json_push_kv_str(&reply->data, "study_root", commit.result_root);
}

void zcl_native_handle_zcode_science_findings_plan(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    size_t wire_len = 0;
    uint8_t *wire = zsci_wire(request->input, "wire_hex", &wire_len);
    if (!wire) {
        zsci_fail(reply, "BAD_WIRE",
                  "wire_hex must be the exact science_findings.v1 wire as even lowercase hex",
                  "zcode.science.findings.plan");
        return;
    }
    struct node_db ndb = {0};
    if (!zsci_open_db(zsci_datadir(request->input), &ndb)) {
        free(wire);
        zsci_fail_service(reply, "DATABASE_OPEN_FAILED",
                          "the science plan ledger could not be opened",
                          "zcode.science.findings.plan");
        return;
    }
    char ws[ZSCI_PATH_MAX];
    struct zcode_science_plan_out plan;
    struct zcl_result planned = zcode_science_findings_plan(
        &ndb, zsci_workspace(request->input, ws, sizeof(ws)), wire, wire_len,
        zsci_now(request->input), &plan);
    node_db_close(&ndb);
    free(wire);
    if (!planned.ok) {
        zsci_fail_service(reply, "FINDINGS_PLAN_REFUSED", planned.message,
                          "zcode.science.findings.plan");
        return;
    }
    zsci_push_plan(&reply->data, &plan, "zcode.science.findings.commit");
}

void zcl_native_handle_zcode_science_findings_commit(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    size_t wire_len = 0;
    uint8_t *wire = zsci_wire(request->input, "wire_hex", &wire_len);
    if (!wire) {
        zsci_fail(reply, "BAD_WIRE",
                  "wire_hex must repeat the planned science_findings.v1 wire exactly",
                  "zcode.science.findings.commit");
        return;
    }
    struct node_db ndb = {0};
    if (!zsci_open_db(zsci_datadir(request->input), &ndb)) {
        free(wire);
        zsci_fail_service(reply, "DATABASE_OPEN_FAILED",
                          "the science plan ledger could not be opened",
                          "zcode.science.findings.commit");
        return;
    }
    char ws[ZSCI_PATH_MAX];
    struct zcode_science_commit_out commit;
    struct zcl_result committed = zcode_science_findings_commit(
        &ndb, zsci_workspace(request->input, ws, sizeof(ws)), wire, wire_len,
        zsci_confirm(request->input), zsci_now(request->input), &commit);
    node_db_close(&ndb);
    free(wire);
    if (!committed.ok) {
        zsci_fail_service(reply, "FINDINGS_COMMIT_REFUSED", committed.message,
                          "zcode.science.findings.commit");
        return;
    }
    zsci_push_commit(&reply->data, &commit);
    (void)json_push_kv_str(&reply->data, "findings_root", commit.result_root);
}

void zcl_native_handle_zcode_science_study_show(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *study_root = zsci_str(request->input, "study_root");
    if (!study_root || strlen(study_root) != 64) {
        zsci_fail(reply, "BAD_ROOT", "study_root must be 64 lowercase hex",
                  "zcode.science.study.show");
        return;
    }
    struct node_db ndb = {0};
    struct sqlite3 *db = NULL;
    if (!zcl_native_node_db_require_readonly(
            zsci_datadir(request->input), reply, "the science projection",
            &db, &ndb))
        return;
    struct db_zcode_science_entry row;
    bool found = false;
    struct zcl_result shown =
        zcode_science_study_show(&ndb, study_root, &row, &found);
    zcl_native_node_db_close_readonly(&db, &ndb);
    if (!shown.ok) {
        zsci_fail_service(reply, "STUDY_SHOW_FAILED", shown.message,
                          "zcode.science.study.show");
        return;
    }
    (void)json_push_kv_bool(&reply->data, "found", found);
    if (found) {
        zsci_push_entry(&reply->data, &row, "study");
        (void)json_push_kv_int(&reply->data, "required_reproductions",
                               row.code);
        (void)json_push_kv_int(&reply->data, "required_reviews", row.flags);
        (void)json_push_kv_str(&reply->data, "hypothesis_root", row.link_root);
        (void)json_push_kv_str(&reply->data, "null_hypothesis_root",
                               row.aux_root);
    }
}

void zcl_native_handle_zcode_science_study_list(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    int max = (int)zsci_int(request->input, "max", 32);
    if (max <= 0 || max > ZSCI_LIST_MAX)
        max = ZSCI_LIST_MAX;
    struct node_db ndb = {0};
    struct sqlite3 *db = NULL;
    if (!zcl_native_node_db_require_readonly(
            zsci_datadir(request->input), reply, "the science projection",
            &db, &ndb))
        return;
    struct db_zcode_science_entry *rows =
        zcl_malloc(sizeof(*rows) * (size_t)max, "zcode.science.study_rows");
    int count = 0;
    struct zcl_result listed =
        rows ? zcode_science_study_list(&ndb, rows, max, &count)
             : ZCL_ERR(-1, "study-rows-alloc");
    zcl_native_node_db_close_readonly(&db, &ndb);
    if (!listed.ok) {
        free(rows);
        zsci_fail_service(reply, "STUDY_LIST_FAILED", listed.message,
                          "zcode.science.study.list");
        return;
    }
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    for (int i = 0; i < count; i++) {
        struct json_value entry;
        json_init(&entry);
        json_set_object(&entry);
        (void)json_push_kv_str(&entry, "study_root", rows[i].root);
        (void)json_push_kv_str(&entry, "hypothesis_root", rows[i].link_root);
        (void)json_push_kv_int(&entry, "required_reproductions",
                               rows[i].code);
        (void)json_push_kv_int(&entry, "required_reviews", rows[i].flags);
        (void)json_push_kv_int(&entry, "created_at", rows[i].created_at);
        (void)json_push_kv_int(&entry, "expires_at", rows[i].expires_at);
        (void)json_push_back(&arr, &entry);
        json_free(&entry);
    }
    free(rows);
    (void)json_push_kv(&reply->data, "studies", &arr);
    json_free(&arr);
    (void)json_push_kv_int(&reply->data, "count", count);
}

void zcl_native_handle_zcode_science_work_plan(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    size_t wire_len = 0, method_len = 0, profile_len = 0;
    uint8_t *wire = zsci_wire(request->input, "wire_hex", &wire_len);
    if (!wire) {
        zsci_fail(reply, "BAD_WIRE",
                  "wire_hex must be a benchmark_result.v2 or reproduction.v1 wire",
                  "zcode.science.work.plan");
        return;
    }
    struct vcs_build_action_v1 action;
    struct vcs_build_action_v1 *action_p = NULL;
    uint8_t *method = NULL, *profile = NULL;
    if (!zsci_wire_is_reproduction(wire, wire_len)) {
        if (!zsci_action(request->input, &action, reply,
                         "zcode.science.work.plan")) {
            free(wire);
            return;
        }
        action_p = &action;
        method = zsci_wire(request->input, "method_hex", &method_len);
        profile = zsci_wire(request->input, "profile_hex", &profile_len);
        if (!method || !profile) {
            free(profile);
            free(method);
            free(wire);
            zsci_fail(reply, "BAD_AUX_WIRES",
                      "a result plan requires method_hex and profile_hex wires",
                      "zcode.science.work.plan");
            return;
        }
    }
    struct node_db ndb = {0};
    if (!zsci_open_db(zsci_datadir(request->input), &ndb)) {
        free(profile);
        free(method);
        free(wire);
        zsci_fail_service(reply, "DATABASE_OPEN_FAILED",
                          "the science plan ledger could not be opened",
                          "zcode.science.work.plan");
        return;
    }
    char ws[ZSCI_PATH_MAX];
    struct zcode_science_plan_out plan;
    struct zcl_result planned = zcode_science_work_plan(
        &ndb, zsci_workspace(request->input, ws, sizeof(ws)), wire, wire_len,
        method, method_len, profile, profile_len, action_p,
        zsci_now(request->input), &plan);
    node_db_close(&ndb);
    free(profile);
    free(method);
    free(wire);
    if (!planned.ok) {
        zsci_fail_service(reply, "WORK_PLAN_REFUSED", planned.message,
                          "zcode.science.work.plan");
        return;
    }
    zsci_push_plan(&reply->data, &plan, "zcode.science.work.commit");
}

void zcl_native_handle_zcode_science_work_commit(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    size_t wire_len = 0;
    uint8_t *wire = zsci_wire(request->input, "wire_hex", &wire_len);
    if (!wire) {
        zsci_fail(reply, "BAD_WIRE",
                  "wire_hex must repeat the planned evidence wire exactly",
                  "zcode.science.work.commit");
        return;
    }
    struct vcs_build_action_v1 action;
    struct vcs_build_action_v1 *action_p = NULL;
    if (!zsci_wire_is_reproduction(wire, wire_len)) {
        if (!zsci_action(request->input, &action, reply,
                         "zcode.science.work.commit")) {
            free(wire);
            return;
        }
        action_p = &action;
    }
    struct node_db ndb = {0};
    if (!zsci_open_db(zsci_datadir(request->input), &ndb)) {
        free(wire);
        zsci_fail_service(reply, "DATABASE_OPEN_FAILED",
                          "the science plan ledger could not be opened",
                          "zcode.science.work.commit");
        return;
    }
    char ws[ZSCI_PATH_MAX];
    struct zcode_science_commit_out commit;
    struct zcl_result committed = zcode_science_work_commit(
        &ndb, zsci_workspace(request->input, ws, sizeof(ws)), wire, wire_len,
        action_p, zsci_confirm(request->input), zsci_now(request->input),
        &commit);
    node_db_close(&ndb);
    free(wire);
    if (!committed.ok) {
        zsci_fail_service(reply, "WORK_COMMIT_REFUSED", committed.message,
                          "zcode.science.work.commit");
        return;
    }
    zsci_push_commit(&reply->data, &commit);
}

void zcl_native_handle_zcode_science_work_status(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *root = zsci_str(request->input, "root");
    if (!root || strlen(root) != 64) {
        zsci_fail(reply, "BAD_ROOT", "root must be 64 lowercase hex",
                  "zcode.science.work.status");
        return;
    }
    struct node_db ndb = {0};
    struct sqlite3 *db = NULL;
    if (!zcl_native_node_db_require_readonly(
            zsci_datadir(request->input), reply, "the science projection",
            &db, &ndb))
        return;
    struct db_zcode_science_entry row;
    const char *kind = NULL;
    bool found = false;
    struct zcl_result status =
        zcode_science_work_status(&ndb, root, &row, &kind, &found);
    zcl_native_node_db_close_readonly(&db, &ndb);
    if (!status.ok) {
        zsci_fail_service(reply, "WORK_STATUS_FAILED", status.message,
                          "zcode.science.work.status");
        return;
    }
    (void)json_push_kv_bool(&reply->data, "found", found);
    if (found)
        zsci_push_entry(&reply->data, &row, kind);
}

void zcl_native_handle_zcode_science_work_receipt(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *root = zsci_str(request->input, "root");
    if (!root || strlen(root) != 64) {
        zsci_fail(reply, "BAD_ROOT", "root must be 64 lowercase hex",
                  "zcode.science.work.receipt");
        return;
    }
    struct node_db ndb = {0};
    struct sqlite3 *db = NULL;
    if (!zcl_native_node_db_require_readonly(
            zsci_datadir(request->input), reply, "the science projection",
            &db, &ndb))
        return;
    char ws[ZSCI_PATH_MAX];
    struct db_zcode_science_entry row;
    const char *kind = NULL;
    struct zcl_result receipt = zcode_science_work_receipt(
        &ndb, zsci_workspace(request->input, ws, sizeof(ws)), root, &row,
        &kind);
    zcl_native_node_db_close_readonly(&db, &ndb);
    if (!receipt.ok) {
        zsci_fail_service(reply, "WORK_RECEIPT_FAILED", receipt.message,
                          "zcode.science.work.receipt");
        return;
    }
    zsci_push_entry(&reply->data, &row, kind);
    (void)json_push_kv_bool(&reply->data, "cas_verified", true);
}

void zcl_native_handle_zcode_science_review_submit(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    size_t wire_len = 0;
    uint8_t *wire = zsci_wire(request->input, "wire_hex", &wire_len);
    if (!wire) {
        zsci_fail(reply, "BAD_WIRE",
                  "wire_hex must be the exact review.v1 wire",
                  "zcode.science.review.submit");
        return;
    }
    struct node_db ndb = {0};
    if (!zsci_open_db(zsci_datadir(request->input), &ndb)) {
        free(wire);
        zsci_fail_service(reply, "DATABASE_OPEN_FAILED",
                          "the science plan ledger could not be opened",
                          "zcode.science.review.submit");
        return;
    }
    char ws[ZSCI_PATH_MAX];
    struct zcode_science_plan_out plan;
    struct zcode_science_commit_out commit;
    struct zcl_result submitted = zcode_science_review_submit(
        &ndb, zsci_workspace(request->input, ws, sizeof(ws)), wire, wire_len,
        zsci_confirm(request->input), zsci_now(request->input), &plan,
        &commit);
    node_db_close(&ndb);
    free(wire);
    if (!submitted.ok) {
        zsci_fail_service(reply, "REVIEW_SUBMIT_REFUSED", submitted.message,
                          "zcode.science.review.submit");
        return;
    }
    if (commit.result_root[0]) {
        zsci_push_commit(&reply->data, &commit);
        (void)json_push_kv_str(&reply->data, "review_root",
                               commit.result_root);
    } else {
        zsci_push_plan(&reply->data, &plan, "zcode.science.review.submit");
    }
}

void zcl_native_handle_zcode_science_vote_submit(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    size_t wire_len = 0;
    uint8_t *wire = zsci_wire(request->input, "wire_hex", &wire_len);
    if (!wire) {
        zsci_fail(reply, "BAD_WIRE",
                  "wire_hex must be the exact sealed curation_vote.v1 wire",
                  "zcode.science.vote.submit");
        return;
    }
    uint8_t genesis[32], voter[32], signer[32];
    const char *genesis_hex = zsci_str(request->input, "network_genesis_root");
    const char *voter_hex = zsci_str(request->input, "voter_zid_root");
    const char *signer_hex = zsci_str(request->input, "signer_pubkey");
    if (!genesis_hex || !voter_hex || !signer_hex ||
        !zcl_hex_decode_lower(genesis_hex, genesis, 32) ||
        !zcl_hex_decode_lower(voter_hex, voter, 32) ||
        !zcl_hex_decode_lower(signer_hex, signer, 32)) {
        free(wire);
        zsci_fail(reply, "BAD_IDENTITY",
                  "network_genesis_root, voter_zid_root, and signer_pubkey must be 64 lowercase hex",
                  "zcode.science.vote.submit");
        return;
    }
    struct node_db ndb = {0};
    if (!zsci_open_db(zsci_datadir(request->input), &ndb)) {
        free(wire);
        zsci_fail_service(reply, "DATABASE_OPEN_FAILED",
                          "the science plan ledger could not be opened",
                          "zcode.science.vote.submit");
        return;
    }
    char ws[ZSCI_PATH_MAX];
    struct zcode_science_plan_out plan;
    struct zcode_science_commit_out commit;
    struct zcl_result submitted = zcode_science_vote_submit(
        &ndb, zsci_workspace(request->input, ws, sizeof(ws)), wire, wire_len,
        genesis, voter, signer, zsci_confirm(request->input),
        zsci_now(request->input), &plan, &commit);
    node_db_close(&ndb);
    free(wire);
    if (!submitted.ok) {
        zsci_fail_service(reply, "VOTE_SUBMIT_REFUSED", submitted.message,
                          "zcode.science.vote.submit");
        return;
    }
    if (commit.result_root[0]) {
        zsci_push_commit(&reply->data, &commit);
        (void)json_push_kv_str(&reply->data, "vote_id", commit.result_root);
    } else {
        zsci_push_plan(&reply->data, &plan, "zcode.science.vote.submit");
    }
}

void zcl_native_handle_zcode_science_rebuild(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    struct node_db ndb = {0};
    if (!zsci_open_db(zsci_datadir(request->input), &ndb)) {
        zsci_fail_service(reply, "DATABASE_OPEN_FAILED",
                          "the science projection could not be opened",
                          "zcode.science.rebuild");
        return;
    }
    char ws[ZSCI_PATH_MAX];
    const char *workspace = zsci_workspace(request->input, ws, sizeof(ws));
    struct zcode_science_rebuild_out rebuilt;
    struct zcl_result result =
        workspace ? zcode_science_rebuild(&ndb, workspace,
                                          zsci_now(request->input), &rebuilt)
                  : ZCL_ERR(-1, "science-rebuild-workspace-invalid");
    node_db_close(&ndb);
    if (!result.ok) {
        zsci_fail_service(reply, "REBUILD_FAILED", result.message,
                          "zcode.science.rebuild");
        return;
    }
    (void)json_push_kv_int(&reply->data, "studies", (int64_t)rebuilt.studies);
    (void)json_push_kv_int(&reply->data, "results", (int64_t)rebuilt.results);
    (void)json_push_kv_int(&reply->data, "reproductions",
                           (int64_t)rebuilt.reproductions);
    (void)json_push_kv_int(&reply->data, "findings", (int64_t)rebuilt.findings);
    (void)json_push_kv_int(&reply->data, "votes", (int64_t)rebuilt.votes);
    (void)json_push_kv_int(&reply->data, "reviews", (int64_t)rebuilt.reviews);
    (void)json_push_kv_str(&reply->data, "authority", "CANONICAL_CAS_WIRE");
}

/* ── G1 carrier: publish / fetch over the blob swarm ───────────────── */

static bool zsci_store_for(const char *datadir, bool *live,
                           struct vcs_package_store **out)
{
    *out = vcs_package_store_global();
    *live = *out != NULL;
    if (*out)
        return true;
    *out = vcs_package_store_open(datadir, vcs_package_store_quota_bytes());
    return *out != NULL;
}

static bool zsci_discovery_record(const char *kind, const char *science_root,
                                  const char *blob_root, int64_t now,
                                  int64_t expiry, char token_out[65],
                                  char error_out[64])
{
    return zcl_native_zcode_publish_record(
        kind, "science", strcmp(kind, "pointer") == 0 ? science_root : NULL,
        blob_root, now > 0 ? now : 1, now, expiry, token_out, error_out, 64);
}

static bool zsci_records_discover(struct json_value *input,
                                  struct json_value *result)
{
    return zcl_native_zcode_records_discover(input, result);
}

struct zsci_pointer_candidate {
    char blob_root[65];
    char publisher_zid[65];
    char provider_node_id[65];
    uint64_t sequence;
    bool provider_authenticated;
    uint32_t source_index;
};

struct zsci_pointer_choice {
    struct zsci_pointer_candidate
        candidate[VCS_ZCODE_DHT_RECORD_DISCOVERY_MAX_RESULTS];
    uint32_t candidate_count;
    uint32_t records_seen;
    uint32_t conflicts;
    uint32_t superseded;
    uint32_t policy_denied;
    uint32_t candidate_truncated;
};

static bool zsci_candidate_policy_allows(
    const struct json_value *input, const char *semantic_hex,
    const struct zsci_pointer_candidate *candidate)
{
    struct vcs_zcode_sovereignty_subject subject;
    memset(&subject, 0, sizeof(subject));
    if (!semantic_hex || !candidate ||
        !zcl_hex_decode_lower(semantic_hex, subject.semantic_root, 32) ||
        !zcl_hex_decode_lower(candidate->blob_root,
                              subject.transport_root, 32) ||
        !zcl_hex_decode_lower(candidate->publisher_zid,
                              subject.publisher_zid, 32))
        return false;
    (void)snprintf(subject.service_type, sizeof(subject.service_type),
                   "science");
    static const enum vcs_zcode_sovereignty_action actions[] = {
        VCS_ZCODE_SOVEREIGNTY_FETCH,
        VCS_ZCODE_SOVEREIGNTY_STORE,
        VCS_ZCODE_SOVEREIGNTY_INDEX,
    };
    for (size_t i = 0; i < sizeof(actions) / sizeof(actions[0]); i++)
        if (!zcl_native_zcode_policy_allows(
                zsci_datadir(input), actions[i], &subject, NULL, 0))
            return false;
    return true;
}

static bool zsci_pointer_better(
    const struct zsci_pointer_candidate *candidate,
    const struct zsci_pointer_candidate *other)
{
    if (candidate->provider_authenticated !=
        other->provider_authenticated)
        return candidate->provider_authenticated;
    int compared = strcmp(candidate->blob_root, other->blob_root);
    if (compared != 0)
        return compared < 0;
    compared = strcmp(candidate->publisher_zid, other->publisher_zid);
    return compared != 0 ? compared < 0
                         : strcmp(candidate->provider_node_id,
                                  other->provider_node_id) < 0;
}

static void zsci_pointer_insert(
    struct zsci_pointer_choice *choice,
    const struct zsci_pointer_candidate *candidate)
{
    if (choice->candidate_count ==
        VCS_ZCODE_DHT_RECORD_DISCOVERY_MAX_RESULTS)
        return;
    uint32_t at = choice->candidate_count;
    while (at > 0 && zsci_pointer_better(
                         candidate, &choice->candidate[at - 1])) {
        choice->candidate[at] = choice->candidate[at - 1];
        at--;
    }
    choice->candidate[at] = *candidate;
    choice->candidate_count++;
}

static void zsci_pointer_diversify(struct zsci_pointer_choice *choice)
{
    struct zsci_pointer_candidate diverse[
        VCS_ZCODE_DHT_RECORD_DISCOVERY_MAX_RESULTS];
    bool selected[VCS_ZCODE_DHT_RECORD_DISCOVERY_MAX_RESULTS] = {false};
    uint32_t diverse_count = 0;
    for (uint32_t i = 0; i < choice->candidate_count; i++) {
        bool root_seen = false;
        for (uint32_t j = 0; j < diverse_count; j++)
            root_seen |= strcmp(diverse[j].blob_root,
                                choice->candidate[i].blob_root) == 0;
        if (!root_seen) {
            diverse[diverse_count++] = choice->candidate[i];
            selected[i] = true;
        }
    }
    for (uint32_t i = 0; i < choice->candidate_count; i++)
        if (!selected[i])
            diverse[diverse_count++] = choice->candidate[i];
    memcpy(choice->candidate, diverse,
           diverse_count * sizeof(*diverse));
}

#ifdef ZCL_TESTING
size_t zcl_native_zcode_science_test_rank_pointers(
    const struct zcl_science_pointer_test_observation *observations,
    size_t count, uint32_t *source_indices, size_t max,
    uint32_t *conflicts_out, uint32_t *superseded_out)
{
    struct zsci_pointer_choice choice;
    memset(&choice, 0, sizeof(choice));
    if (!observations || (!source_indices && max))
        return 0;
    if (count > VCS_ZCODE_DHT_RECORD_DISCOVERY_MAX_RESULTS)
        count = VCS_ZCODE_DHT_RECORD_DISCOVERY_MAX_RESULTS;
    for (size_t i = 0; i < count; i++) {
        choice.records_seen++;
        if (observations[i].conflicted || observations[i].superseded) {
            choice.conflicts += observations[i].conflicted;
            choice.superseded += observations[i].superseded;
            continue;
        }
        struct zsci_pointer_candidate candidate;
        memset(&candidate, 0, sizeof(candidate));
        zcl_hex_encode(observations[i].transport_root, 32,
                       candidate.blob_root);
        zcl_hex_encode(observations[i].publisher_zid, 32,
                       candidate.publisher_zid);
        zcl_hex_encode(observations[i].provider_node_id, 32,
                       candidate.provider_node_id);
        candidate.sequence = observations[i].sequence;
        candidate.provider_authenticated =
            observations[i].provider_authenticated;
        candidate.source_index = (uint32_t)i;
        zsci_pointer_insert(&choice, &candidate);
    }
    zsci_pointer_diversify(&choice);
    size_t copied = choice.candidate_count < max
                        ? choice.candidate_count : max;
    for (size_t i = 0; i < copied; i++)
        source_indices[i] = choice.candidate[i].source_index;
    if (conflicts_out)
        *conflicts_out = choice.conflicts;
    if (superseded_out)
        *superseded_out = choice.superseded;
    return choice.candidate_count;
}

bool zcl_native_zcode_science_test_candidate_allowed(
    const char *datadir, const uint8_t semantic_root[32],
    const uint8_t transport_root[32], const uint8_t publisher_zid[32])
{
    if (!datadir || !semantic_root || !transport_root || !publisher_zid)
        return false;
    char semantic[65];
    struct zsci_pointer_candidate candidate;
    memset(&candidate, 0, sizeof(candidate));
    zcl_hex_encode(semantic_root, 32, semantic);
    zcl_hex_encode(transport_root, 32, candidate.blob_root);
    zcl_hex_encode(publisher_zid, 32, candidate.publisher_zid);
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    json_push_kv_str(&input, "datadir", datadir);
    bool allowed = zsci_candidate_policy_allows(
        &input, semantic, &candidate);
    json_free(&input);
    return allowed;
}
#endif

static bool zsci_resolve_pointer(const char *science_root,
                                 struct zsci_pointer_choice *choice)
{
    struct json_value input, result;
    memset(choice, 0, sizeof(*choice));
    json_init(&input);
    json_set_object(&input);
    json_push_kv_str(&input, "kind", "pointer");
    json_push_kv_str(&input, "namespace", "science");
    json_push_kv_str(&input, "semantic_root", science_root);
    if (!zsci_records_discover(&input, &result)) {
        json_free(&result);
        json_free(&input);
        return false;
    }
    const struct json_value *records = json_get(&result, "records");
    size_t count = records ? json_size(records) : 0;
    for (size_t i = 0; i < count; i++) {
        const struct json_value *row = json_at(records, i);
        const char *transport = json_get_str(json_get(row, "transport_root"));
        const char *publisher = json_get_str(json_get(row, "publisher_zid"));
        const char *provider = json_get_str(json_get(row, "provider_node_id"));
        int64_t sequence = json_get_int(json_get(row, "sequence"));
        bool conflicted = json_get_bool_or(row, "conflicted", false);
        bool superseded = json_get_bool_or(row, "superseded", false);
        uint8_t decoded[32];
        if (!transport || !publisher || !provider || sequence < 1 ||
            strlen(transport) != 64 || strlen(publisher) != 64 ||
            strlen(provider) != 64 ||
            !zcl_hex_decode_lower(transport, decoded, 32) ||
            !zcl_hex_decode_lower(publisher, decoded, 32) ||
            !zcl_hex_decode_lower(provider, decoded, 32))
            continue;
        choice->records_seen++;
        if (conflicted || superseded) {
            choice->conflicts += conflicted;
            choice->superseded += superseded;
            continue;
        }
        struct zsci_pointer_candidate candidate;
        memset(&candidate, 0, sizeof(candidate));
        memcpy(candidate.blob_root, transport, 65);
        memcpy(candidate.publisher_zid, publisher, 65);
        memcpy(candidate.provider_node_id, provider, 65);
        candidate.sequence = (uint64_t)sequence;
        candidate.provider_authenticated =
            json_get_bool_or(row, "provider_authenticated", false);
        candidate.source_index = (uint32_t)i;
        zsci_pointer_insert(choice, &candidate);
    }
    /* Give distinct transport roots the whole first pass. Duplicate roots
     * remain as independent publisher-policy alternatives in pass two. */
    zsci_pointer_diversify(choice);
    json_free(&result);
    json_free(&input);
    return choice->candidate_count > 0;
}

static bool zsci_route_providers(const char *blob_root,
                                 uint32_t *records_out,
                                 uint32_t *authenticated_out,
                                 uint32_t *pending_out)
{
    struct json_value input, route;
    json_init(&input);
    json_init(&route);
    json_set_object(&input);
    json_push_kv_str(&input, "kind", "provider");
    json_push_kv_str(&input, "namespace", "science");
    json_push_kv_str(&input, "transport_root", blob_root);
    uint32_t record_count = 0;
    bool routed = zcl_native_zcode_provider_discover_and_route(
        &input, &route, &record_count);
    if (!routed) {
        json_free(&route);
        json_free(&input);
        return false;
    }
    int64_t authenticated =
        json_get_int(json_get(&route, "authenticated_providers"));
    int64_t pending = json_get_int(json_get(&route, "reachability_pending"));
    *records_out = record_count;
    *authenticated_out = authenticated > 0 ? (uint32_t)authenticated : 0;
    *pending_out = pending > 0 ? (uint32_t)pending : 0;
    json_free(&route);
    json_free(&input);
    return true;
}

void zcl_native_handle_zcode_science_publish(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *root_hex = zsci_str(request->input, "root");
    if (!root_hex || strlen(root_hex) != 64) {
        zsci_fail(reply, "BAD_ROOT",
                  "root must be the 64-lowercase-hex science root of a "
                  "committed object in the workspace CAS",
                  "zcode.science.publish");
        return;
    }
    const char *datadir = zsci_datadir(request->input);
    char ws[ZSCI_PATH_MAX];
    const char *workspace = zsci_workspace(request->input, ws, sizeof(ws));
    if (!datadir || !workspace) {
        zsci_fail(reply, "BAD_WORKSPACE",
                  "datadir/workspace could not be resolved",
                  "zcode.science.publish");
        return;
    }
    if (!zsci_policy_allows(request->input, VCS_ZCODE_SOVEREIGNTY_STORE,
                            root_hex, NULL, NULL, reply,
                            "zcode.science.publish") ||
        !zsci_policy_allows(request->input, VCS_ZCODE_SOVEREIGNTY_INDEX,
                            root_hex, NULL, NULL, reply,
                            "zcode.science.publish") ||
        !zsci_policy_allows(request->input, VCS_ZCODE_SOVEREIGNTY_SERVE,
                            root_hex, NULL, NULL, reply,
                            "zcode.science.publish") ||
        !zsci_policy_allows(request->input, VCS_ZCODE_SOVEREIGNTY_FORWARD,
                            root_hex, NULL, NULL, reply,
                            "zcode.science.publish"))
        return;
    bool live = false;
    struct vcs_package_store *store = NULL;
    if (!zsci_store_for(datadir, &live, &store)) {
        zsci_fail_service(reply, "NO_STORE",
                          "the package store failed to open",
                          "zcode.science.publish");
        return;
    }
    char blob_hex[65], kind[ZCODE_SCIENCE_KIND_CAP];
    struct zcl_result published =
        zcode_science_publish(store, workspace, root_hex, blob_hex, kind);
    if (!live)
        vcs_package_store_close(store);
    if (!published.ok) {
        zsci_fail_service(reply, "PUBLISH_REFUSED", published.message,
                          "zcode.science.publish");
        return;
    }
    int64_t now = platform_time_wall_unix();
    char pointer_token[65], provider_token[65];
    char pointer_error[64] = {0}, provider_error[64] = {0};
    bool pointer = now > 0 && now <= INT64_MAX - ZSCI_POINTER_SECONDS &&
        zsci_discovery_record("pointer", root_hex, blob_hex, now,
                              now + ZSCI_POINTER_SECONDS, pointer_token,
                              pointer_error);
    bool provider = now > 0 && now <= INT64_MAX - 7200 &&
        zsci_discovery_record("provider", root_hex, blob_hex, now,
                              now + 7200, provider_token, provider_error);
    if (!pointer || !provider) {
        char detail[256];
        const char *pointer_status = pointer ? "published" :
            (pointer_error[0] ? pointer_error : "not_attempted");
        const char *provider_status = provider ? "published" :
            (provider_error[0] ? provider_error : "not_attempted");
        (void)snprintf(
            detail, sizeof(detail),
            "transport object exists but signed pointer/provider publication "
            "did not complete (pointer=%s provider=%s)",
            pointer_status, provider_status);
        json_push_kv_str(&reply->data, "science_root", root_hex);
        json_push_kv_str(&reply->data, "blob_root", blob_hex);
        json_push_kv_bool(&reply->data, "transport_object_committed", true);
        json_push_kv_bool(&reply->data, "pointer_published", pointer);
        json_push_kv_bool(&reply->data, "provider_published", provider);
        if (!pointer && pointer_error[0])
            json_push_kv_str(&reply->data, "pointer_error", pointer_error);
        if (!provider && provider_error[0])
            json_push_kv_str(&reply->data, "provider_error", provider_error);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_TRANSIENT,
                               "DISCOVERY_PUBLICATION_INCOMPLETE", "commit",
                               true, true,
                               detail,
                               "zcode.science.publish");
        return;
    }
    (void)json_push_kv_str(&reply->data, "science_root", root_hex);
    (void)json_push_kv_str(&reply->data, "blob_root", blob_hex);
    (void)json_push_kv_str(&reply->data, "kind", kind);
    (void)json_push_kv_bool(&reply->data, "live", live);
    (void)json_push_kv_bool(&reply->data, "pointer_published", true);
    (void)json_push_kv_bool(&reply->data, "provider_published", true);
    if (!live)
        (void)json_push_kv_str(
            &reply->data, "note",
            "persisted to the on-disk package store; a hosting node picks "
            "the blob package into its announce set the next time its "
            "store opens (boot), then the clock-driven swarm carries it "
            "to every connected peer");
}

void zcl_native_handle_zcode_science_fetch(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *requested_root = zsci_str(request->input, "root");
    const char *explicit_blob = zsci_str(request->input, "blob_root");
    bool cancel = json_get_bool_or(request->input, "cancel", false);
    bool root_only = !explicit_blob || !explicit_blob[0];
    struct zsci_pointer_choice choice;
    memset(&choice, 0, sizeof(choice));
    if (root_only && (!requested_root || strlen(requested_root) != 64)) {
        zsci_fail(reply, "BAD_BLOB_ROOT",
                  "provide a 64-lowercase-hex blob_root, or a science root "
                  "resolvable through iterative signed POINTER discovery",
                  "zcode.science.fetch");
        return;
    }
    if (root_only && !zsci_resolve_pointer(requested_root, &choice)) {
        if (choice.conflicts || choice.superseded) {
            (void)json_push_kv_int(&reply->data, "pointer_records",
                                   choice.records_seen);
            (void)json_push_kv_int(&reply->data, "pointer_conflicts",
                                   choice.conflicts);
            (void)json_push_kv_int(&reply->data, "pointer_superseded",
                                   choice.superseded);
            zsci_fail_service(
                reply, "POINTER_EVIDENCE_UNUSABLE",
                "signed pointer evidence exists, but every stream is "
                "conflicted or superseded",
                "zcode.science.fetch");
        } else {
            zsci_fail(reply, "BAD_BLOB_ROOT",
                      "science root has no usable signed POINTER evidence",
                      "zcode.science.fetch");
        }
        return;
    }
    if (!root_only) {
        uint8_t decoded[32];
        if (strlen(explicit_blob) != 64 ||
            !zcl_hex_decode_lower(explicit_blob, decoded, 32)) {
            zsci_fail(reply, "BAD_BLOB_ROOT",
                      "blob_root must be 64 lowercase hex",
                      "zcode.science.fetch");
            return;
        }
        choice.candidate_count = 1;
        choice.records_seen = 1;
        memcpy(choice.candidate[0].blob_root, explicit_blob, 65);
    }
    if (cancel && root_only) {
        zsci_fail(reply, "BAD_BLOB_ROOT",
                  "cancel requires the exact 64-lowercase-hex blob_root",
                  "zcode.science.fetch");
        return;
    }
    if (root_only) {
        uint32_t allowed = 0;
        for (uint32_t i = 0; i < choice.candidate_count; i++) {
            if (!zsci_candidate_policy_allows(
                    request->input, requested_root, &choice.candidate[i])) {
                choice.policy_denied++;
                continue;
            }
            choice.candidate[allowed++] = choice.candidate[i];
        }
        choice.candidate_count = allowed;
        if (!allowed) {
            zsci_fail_service(
                reply, "SOVEREIGNTY_DENIED",
                "local sovereignty policy denied every signed pointer candidate",
                "zcode.science.fetch");
            return;
        }
        if (choice.candidate_count > VCS_ZCODE_DHT_K) {
            choice.candidate_truncated =
                choice.candidate_count - VCS_ZCODE_DHT_K;
            choice.candidate_count = VCS_ZCODE_DHT_K;
        }
    } else if (!cancel && (!zsci_policy_allows(
                   request->input, VCS_ZCODE_SOVEREIGNTY_FETCH,
                   requested_root, choice.candidate[0].blob_root, NULL,
                   reply, "zcode.science.fetch") ||
               !zsci_policy_allows(
                   request->input, VCS_ZCODE_SOVEREIGNTY_STORE,
                   requested_root, choice.candidate[0].blob_root, NULL,
                   reply, "zcode.science.fetch") ||
               !zsci_policy_allows(
                   request->input, VCS_ZCODE_SOVEREIGNTY_INDEX,
                   requested_root, choice.candidate[0].blob_root, NULL,
                   reply, "zcode.science.fetch"))) {
        return;
    }
    const char *datadir = zsci_datadir(request->input);
    char ws[ZSCI_PATH_MAX];
    const char *workspace = cancel ? NULL
                                   : zsci_workspace(request->input, ws,
                                                    sizeof(ws));
    if (!datadir || (!cancel && !workspace)) {
        zsci_fail(reply, "BAD_WORKSPACE",
                  "datadir/workspace could not be resolved",
                  "zcode.science.fetch");
        return;
    }
    char zcode_dir[ZSCI_PATH_MAX];
    int zn = snprintf(zcode_dir, sizeof(zcode_dir), "%s/zcode", datadir);
    if (zn <= 0 || (size_t)zn >= sizeof(zcode_dir)) {
        zsci_fail(reply, "BAD_WORKSPACE", "datadir path too long",
                  "zcode.science.fetch");
        return;
    }
    bool live_store = false;
    struct vcs_package_store *store = NULL;
    if (!zsci_store_for(datadir, &live_store, &store)) {
        zsci_fail_service(reply, "NO_STORE",
                          "the package store failed to open",
                          "zcode.science.fetch");
        return;
    }
    if (cancel) {
        struct vcs_swarm_engine *cancel_engine = vcs_swarm_engine_global();
        struct vcs_service_book *cancel_book = NULL;
        bool temporary_engine = cancel_engine == NULL;
        if (temporary_engine) {
            cancel_book = vcs_service_book_load(zcode_dir);
            cancel_engine = vcs_swarm_engine_create(
                store, cancel_book, zcode_dir, NULL, NULL);
        }
        uint8_t transport[32];
        (void)zcl_hex_decode_lower(choice.candidate[0].blob_root,
                                   transport, 32);
        bool canceled = cancel_engine && vcs_swarm_engine_cancel(
                                             cancel_engine, transport,
                                             (uint64_t)zsci_now(request->input));
        if (temporary_engine && cancel_engine)
            vcs_swarm_engine_free(cancel_engine);
        vcs_service_book_free(cancel_book);
        if (!live_store)
            vcs_package_store_close(store);
        (void)json_push_kv_str(&reply->data, "blob_root",
                               choice.candidate[0].blob_root);
        (void)json_push_kv_bool(&reply->data, "canceled", canceled);
        (void)json_push_kv_bool(&reply->data, "restriction_widened", false);
        (void)json_push_kv_str(&reply->data, "result",
                               canceled ? "canceled" : "not_active");
        return;
    }
    uint32_t provider_records = 0, authenticated_providers = 0;
    uint32_t reachability_pending = 0, routed_candidates = 0;
    if (root_only)
        for (uint32_t i = 0; i < choice.candidate_count; i++) {
            uint32_t records = 0, authenticated = 0, pending = 0;
            if (!zsci_route_providers(choice.candidate[i].blob_root,
                                      &records, &authenticated, &pending))
                continue;
            provider_records += records;
            authenticated_providers += authenticated;
            reachability_pending += pending;
            routed_candidates++;
        }
    /* Explicit transport fetches retain the generic swarm behavior. A
     * root-only fetch is registered as restricted even with zero current
     * providers, so a restart cannot silently widen it before discovery is
     * repeated and fresh Noise sessions are bound. */
    struct vcs_swarm_engine *engine = vcs_swarm_engine_global();
    bool live_engine = engine != NULL || routed_candidates > 0;
    struct vcs_service_book *book = NULL;
    if (!engine && routed_candidates == 0) {
        book = vcs_service_book_load(zcode_dir);
        engine = vcs_swarm_engine_create(store, book, zcode_dir, NULL, NULL);
    }
    enum vcs_swarm_fetch_result fr = routed_candidates > 0
        ? VCS_SWARM_FETCH_OK : VCS_SWARM_FETCH_NO_STORE;
    if (engine && (!root_only || routed_candidates == 0)) {
        int64_t now = zsci_now(request->input);
        for (uint32_t i = 0; i < choice.candidate_count; i++) {
            uint8_t transport[32];
            (void)zcl_hex_decode_lower(choice.candidate[i].blob_root,
                                       transport, 32);
            enum vcs_swarm_fetch_result one = root_only
                ? vcs_swarm_engine_fetch_from(engine, transport,
                                              now / 86400, (uint64_t)now,
                                              NULL, 0)
                : vcs_swarm_engine_fetch(engine, transport,
                                         now / 86400, (uint64_t)now);
            if (one == VCS_SWARM_FETCH_OK ||
                one == VCS_SWARM_FETCH_ALREADY_COMPLETE)
                fr = one;
        }
    }
    if (!vcs_swarm_engine_global() && engine) {
        vcs_swarm_engine_free(engine);
        vcs_service_book_free(book);
    }
    if (fr != VCS_SWARM_FETCH_OK && fr != VCS_SWARM_FETCH_ALREADY_COMPLETE) {
        if (!live_store)
            vcs_package_store_close(store);
        zsci_fail_service(reply, "FETCH_REFUSED",
                          vcs_swarm_fetch_result_string(fr),
                          "zcode.science.fetch");
        return;
    }
    /* Admit whenever the blob's bytes are already local (already complete,
     * or just downloaded by the live engine). Absent is not a failure —
     * the download is scheduled; re-invoke after the swarm delivers. */
    struct node_db ndb = {0};
    bool db_open = zsci_open_db(datadir, &ndb);
    char science_hex[65] = {0}, kind[ZCODE_SCIENCE_KIND_CAP] = {0};
    char admitted_blob[65] = {0};
    bool is_new = false;
    size_t candidate_attempts = 0;
    struct zcl_result admitted = ZCL_ERR(-1, "science-admit-db-unavailable");
    if (db_open) {
        if (root_only) {
            const char *blob_roots[VCS_ZCODE_DHT_K];
            for (uint32_t i = 0; i < choice.candidate_count; i++)
                blob_roots[i] = choice.candidate[i].blob_root;
            admitted = zcode_science_admit_candidates(
                store, &ndb, workspace, requested_root, blob_roots,
                choice.candidate_count, zsci_now(request->input),
                admitted_blob, kind, &is_new, &candidate_attempts);
            if (admitted.ok)
                memcpy(science_hex, requested_root, 65);
        } else {
            admitted = zcode_science_admit(
                store, &ndb, workspace, choice.candidate[0].blob_root,
                zsci_now(request->input), science_hex, kind, &is_new);
            if (admitted.ok)
                memcpy(admitted_blob, choice.candidate[0].blob_root, 65);
        }
        node_db_close(&ndb);
    }
    if (!live_store)
        vcs_package_store_close(store);
    (void)json_push_kv_str(&reply->data, "blob_root",
                           admitted.ok ? admitted_blob
                                       : choice.candidate[0].blob_root);
    (void)json_push_kv_bool(&reply->data, "live", live_engine);
    (void)json_push_kv_str(&reply->data, "result",
                           vcs_swarm_fetch_result_string(fr));
    (void)json_push_kv_bool(&reply->data, "admitted", admitted.ok);
    (void)json_push_kv_bool(&reply->data, "provider_restricted", root_only);
    (void)json_push_kv_int(&reply->data, "pointer_records",
                           choice.records_seen);
    (void)json_push_kv_int(&reply->data, "pointer_candidates",
                           choice.candidate_count);
    (void)json_push_kv_int(&reply->data, "pointer_conflicts",
                           choice.conflicts);
    (void)json_push_kv_int(&reply->data, "pointer_superseded",
                           choice.superseded);
    (void)json_push_kv_int(&reply->data, "pointer_policy_denied",
                           choice.policy_denied);
    (void)json_push_kv_int(&reply->data, "pointer_candidate_truncated",
                           choice.candidate_truncated);
    (void)json_push_kv_int(&reply->data, "provider_records",
                           provider_records);
    (void)json_push_kv_int(&reply->data, "authenticated_providers",
                           authenticated_providers);
    (void)json_push_kv_int(&reply->data, "reachability_pending",
                           reachability_pending);
    (void)json_push_kv_int(&reply->data, "candidate_attempts",
                           candidate_attempts);
    if (admitted.ok && requested_root &&
        strcmp(requested_root, science_hex) != 0) {
        zsci_fail_service(reply, "POINTER_ROOT_MISMATCH",
                          "verified bytes re-derived a different science root",
                          "zcode.science.fetch");
        return;
    }
    if (admitted.ok) {
        (void)json_push_kv_str(&reply->data, "science_root", science_hex);
        (void)json_push_kv_str(&reply->data, "kind", kind);
        (void)json_push_kv_bool(&reply->data, "new", is_new);
    } else {
        (void)json_push_kv_str(&reply->data, "admit_state",
                               admitted.message);
        (void)json_push_kv_str(
            &reply->data, "note",
            live_engine
                ? "download scheduled on the live swarm; re-invoke once the blob completes to admit it"
                : "no live engine: the resumable download record is persisted under <datadir>/zcode/downloads; the next -packagehost=1 boot downloads it, then re-invoke to admit");
    }
}
