/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ops.host.legacy.status / ops.host.legacy.seed: bring up and verify the
 * legacy zclassicd parity oracle and bootstrap-serving datadirs without a
 * shell. See docs/node/LEGACY_LIFECYCLE.md "Seed a legacy node from the
 * parity oracle". */

#define _GNU_SOURCE

#include "command/native_command.h"
#include "command/legacy_seed.h"
#include "command/legacy_status.h"
#include "command/slo_monitor_io.h"

#include "controllers/rpc_client.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/time_compat.h"

#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum { OHL_MAX_INSTANCES = 8, OHL_RPC_MS = 4000 };

static char *(*g_rpc_hook)(const char *datadir, int rpcport, const char *method);

void zcl_native_legacy_status_set_rpc(char *(*fn)(const char *, int, const char *))
{
    g_rpc_hook = fn;
}

static char *ohl_rpc(const char *datadir, int rpcport, const char *method)
{
    return g_rpc_hook ? g_rpc_hook(datadir, rpcport, method)
                      : slo_io_legacy_call(datadir, rpcport, method, OHL_RPC_MS);
}

/* getconnectioncount answer: {"result":N} or a bare integer, else -1. */
static int64_t ohl_connections(const char *raw)
{
    struct json_value doc;
    const struct json_value *r;
    int64_t n = -1;
    json_init(&doc);
    if (raw && json_read(&doc, raw, strlen(raw))) {
        r = doc.type == JSON_OBJ ? json_get(&doc, "result") : &doc;
        if (r && r->type == JSON_INT && json_get_int(r) >= 0)
            n = json_get_int(r);
    }
    json_free(&doc);
    return n;
}

static void ohl_fail(struct zcl_command_reply *reply, enum zcl_command_exit exit_code,
                     const char *code, const char *phase, bool mutated,
                     const char *message, const char *evidence)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, exit_code, code,
                           phase, false, mutated, message, evidence);
}

/* ---- seed ---------------------------------------------------------------- */

static bool ohl_take_str(const struct json_value *in, const char *key, char *out,
                         size_t cap)
{
    const struct json_value *v = json_get(in, key);
    const char *s = v && v->type == JSON_STR ? json_get_str(v) : NULL;
    return s && s[0] && strlen(s) < cap && snprintf(out, cap, "%s", s) > 0;
}

static bool ohl_parse_seed(const struct json_value *in, struct lseed_request *req)
{
    int64_t margin = json_get_int_or(in, "margin_mib", LSEED_DEFAULT_MARGIN_MIB);
    int64_t workers = json_get_int_or(in, "workers", LSEED_DEFAULT_WORKERS);
    lseed_request_defaults(req);
    req->max_gap = json_get_int_or(in, "max_gap", LSEED_DEFAULT_MAX_GAP);
    req->source_height = json_get_int_or(in, "source_height", -1);
    req->z23_height = json_get_int_or(in, "z23_height", -1);
    if (margin < 0 || margin > (1 << 20) || workers < 1 ||
        workers > LSEED_MAX_WORKERS)
        return false;
    req->margin_bytes = (uint64_t)margin << 20;
    req->workers = (int)workers;
    return ohl_take_str(in, "source", req->source, sizeof(req->source)) &&
           ohl_take_str(in, "target", req->target, sizeof(req->target));
}

static void ohl_refuse(struct zcl_command_reply *reply, enum lseed_refusal rc,
                       const char *phase, const char *why)
{
    char code[64];
    (void)snprintf(code, sizeof(code), "legacy_seed.%s", lseed_refusal_name(rc));
    ohl_fail(reply, rc == LSEED_COPY_FAILED || rc == LSEED_RECEIPT_FAILED
                        ? ZCL_COMMAND_EXIT_FAILED : ZCL_COMMAND_EXIT_INVALID,
             code, phase, rc == LSEED_COPY_FAILED || rc == LSEED_RECEIPT_FAILED,
             why, lseed_refusal_name(rc));
}

static void ohl_push_plan(struct zcl_command_reply *reply,
                          const struct lseed_plan *p)
{
    (void)json_push_kv_str(&reply->data, "plan_id", p->plan_id);
    (void)json_push_kv_int(&reply->data, "files", (int64_t)p->files);
    (void)json_push_kv_int(&reply->data, "bytes", (int64_t)p->bytes);
    (void)json_push_kv_int(&reply->data, "immutable_files",
                           (int64_t)p->immutable_files);
    (void)json_push_kv_int(&reply->data, "excluded_files",
                           (int64_t)p->excluded_files);
    (void)json_push_kv_int(&reply->data, "free_bytes", (int64_t)p->free_bytes);
    (void)json_push_kv_int(&reply->data, "tail_pair", p->tail_pair);
    (void)json_push_kv_bool(&reply->data, "source_running", p->source_running);
    (void)json_push_kv_bool(&reply->data, "tmp_present", p->tmp_present);
}

static void ohl_push_result(struct zcl_command_reply *reply,
                            const struct lseed_result *r)
{
    (void)json_push_kv_int(&reply->data, "files", (int64_t)r->files);
    (void)json_push_kv_int(&reply->data, "bytes", (int64_t)r->bytes);
    (void)json_push_kv_int(&reply->data, "copied_files", (int64_t)r->copied_files);
    (void)json_push_kv_int(&reply->data, "resumed_files", (int64_t)r->resumed_files);
    (void)json_push_kv_int(&reply->data, "cloned_files", (int64_t)r->cloned_files);
    (void)json_push_kv_int(&reply->data, "excluded_files",
                           (int64_t)r->excluded_files);
    (void)json_push_kv_int(&reply->data, "stage_ms", (int64_t)r->stage_ms);
    (void)json_push_kv_int(&reply->data, "downtime_ms", (int64_t)r->phase_b_ms);
    (void)json_push_kv_int(&reply->data, "phase_b_files", (int64_t)r->phase_b_files);
    (void)json_push_kv_int(&reply->data, "phase_b_bytes", (int64_t)r->phase_b_bytes);
    (void)json_push_kv_int(&reply->data, "hash_ms", (int64_t)r->hash_ms);
    if (r->manifest_sha3[0]) {
        (void)json_push_kv_str(&reply->data, "manifest_sha3", r->manifest_sha3);
        (void)json_push_kv_str(&reply->data, "receipt", r->receipt_path);
        (void)json_push_kv_str(
            &reply->data, "peer_source",
            "the seeded datadir has no peers.dat: start it with addnode=<local z23 p2p address> (or a dnsseed) or it will sit at the seed height with 0 peers");
    }
}

static bool ohl_commit_authorised(const struct json_value *in,
                                  const struct lseed_request *req,
                                  struct zcl_command_reply *reply)
{
    char want[65];
    const struct json_value *given = json_get(in, "plan_id");
    lseed_plan_id(req, want);
    if (!json_get_bool_or(in, "confirm", false)) {
        ohl_fail(reply, ZCL_COMMAND_EXIT_INVALID, "legacy_seed.confirm_required",
                 "confirm", false,
                 "stage and finish need confirm:true and the plan_id from a "
                 "plan step with the same source, target and max_gap",
                 "confirm");
        return false;
    }
    if (!given || given->type != JSON_STR || strcmp(json_get_str(given), want)) {
        ohl_refuse(reply, LSEED_PLAN_MISMATCH, "confirm",
                   "plan_id does not match this source, target and max_gap");
        return false;
    }
    return true;
}

void zcl_native_handle_ops_host_legacy_seed(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const struct json_value *in = request ? request->input : NULL;
    struct lseed_request req;
    struct lseed_plan plan;
    struct lseed_result res;
    char why[512] = "";
    const struct json_value *sv = json_get(in, "step");
    const char *step = sv && sv->type == JSON_STR ? json_get_str(sv) : "plan";
    enum lseed_refusal rc;

    if (!reply)
        return;
    if (!ohl_parse_seed(in, &req)) {
        ohl_refuse(reply, LSEED_BAD_INPUT, "validate",
                   "source and target (absolute strings) are required; "
                   "margin_mib 0..1048576, workers 1..16");
        return;
    }
    (void)json_push_kv_str(&reply->data, "step", step);
    if (strcmp(step, "plan") == 0) {
        rc = lseed_preflight(&req, false, &plan, why, sizeof(why));
        if (rc != LSEED_OK)
        {
            ohl_refuse(reply, rc, "plan", why);
            return;
        }
        ohl_push_plan(reply, &plan);
    } else if (strcmp(step, "stage") == 0 || strcmp(step, "finish") == 0) {
        if (!ohl_commit_authorised(in, &req, reply))
            return;
        rc = step[0] == 's' ? lseed_stage(&req, &res, why, sizeof(why))
                            : lseed_finish(&req, &res, why, sizeof(why));
        if (rc != LSEED_OK)
        {
            ohl_refuse(reply, rc, step, why);
            return;
        }
        ohl_push_result(reply, &res);
    } else {
        ohl_refuse(reply, LSEED_BAD_INPUT, "validate",
                   "step must be plan, stage or finish");
        return;
    }
    reply->status = ZCL_COMMAND_STATUS_PASSED;
}

/* ---- status -------------------------------------------------------------- */

struct ohl_inst {
    struct lstat_inst id;
    char datadir[LSEED_PATH_MAX];
    char binary[LSEED_PATH_MAX];
    char sha256[80];
    int64_t prev_height, prev_unix;
};

static bool ohl_take_inst(const struct json_value *el, struct ohl_inst *out)
{
    memset(out, 0, sizeof(*out));
    if (!el || el->type != JSON_OBJ ||
        !ohl_take_str(el, "datadir", out->datadir, sizeof(out->datadir)) ||
        !ohl_take_str(el, "name", out->id.name, sizeof(out->id.name)))
        return false;
    (void)ohl_take_str(el, "binary", out->binary, sizeof(out->binary));
    (void)ohl_take_str(el, "sha256", out->sha256, sizeof(out->sha256));
    out->id.port = (int)json_get_int_or(el, "port", 0);
    out->id.rpcport = (int)json_get_int_or(el, "rpcport", 0);
    out->prev_height = json_get_int_or(el, "prev_height", -1);
    out->prev_unix = json_get_int_or(el, "prev_unix", 0);
    return true;
}

static int64_t ohl_height(const char *raw)
{
    struct slo_chain_answer a;
    memset(&a, 0, sizeof(a));
    int64_t h = (raw && slo_io_chain_parse(raw, &a) && a.served.has) ? a.served.v : -1;
    return h;
}

static void ohl_rate_fields(struct json_value *row, const struct ohl_inst *in,
                            int64_t height, int64_t z23, int64_t now)
{
    int64_t gap = (height >= 0 && z23 >= 0) ? z23 - height : -1;
    struct lstat_rate r = lstat_rate(in->prev_height, in->prev_unix, height,
                                     now, gap);
    if (gap >= 0)
        (void)json_push_kv_int(row, "gap", gap);
    if (r.known)
        (void)json_push_kv_real(row, "blocks_per_min",
                                (double)r.blocks_per_min_x100 / 100.0);
    if (r.eta_known)
        (void)json_push_kv_int(row, "eta_seconds", r.eta_seconds);
}

static bool ohl_same_file(const char *a, const char *b)
{
    struct stat sa, sb;
    if (stat(a, &sa) != 0 || stat(b, &sb) != 0)
        return false;
    return memcmp(&sa.st_ino, &sb.st_ino, sizeof(sa.st_ino)) == 0 &&
           memcmp(&sa.st_dev, &sb.st_dev, sizeof(sa.st_dev)) == 0;
}

static void ohl_one_instance(struct json_value *rows, const struct ohl_inst *in,
                             bool rpc, int64_t z23, int64_t now,
                             const char *node_conf, const char *conf_src)
{
    char actual[65];
    long pid = 0;
    struct json_value row;
    enum lstat_identity id = lstat_identity(in->binary, in->sha256, actual);
    bool running = lseed_datadir_in_use(in->datadir, &pid);
    int64_t conns = -1;
    int64_t height = -1;
    if (rpc && running && in->id.rpcport > 0) {
        char *raw = ohl_rpc(in->datadir, in->id.rpcport, "getblockchaininfo");
        height = ohl_height(raw);
        free(raw);
        raw = ohl_rpc(in->datadir, in->id.rpcport, "getconnectioncount");
        conns = ohl_connections(raw);
        free(raw);
    }
    json_init(&row);
    json_set_object(&row);
    (void)json_push_kv_str(&row, "name", in->id.name);
    (void)json_push_kv_str(&row, "datadir", in->datadir);
    (void)json_push_kv_int(&row, "port", in->id.port);
    (void)json_push_kv_int(&row, "rpcport", in->id.rpcport);
    (void)json_push_kv_str(&row, "identity", lstat_identity_name(id));
    if (actual[0])
        (void)json_push_kv_str(&row, "sha256", actual);
    (void)json_push_kv_bool(&row, "running", running);
    char conf[LSEED_PATH_MAX + 20];
    (void)snprintf(conf, sizeof(conf), "%s/zclassic.conf", in->datadir);
    enum lstat_creds creds = lstat_mirror_creds(node_conf, conf);
    (void)json_push_kv_str(&row, "mirror_creds", lstat_creds_name(creds));
    (void)json_push_kv_str(&row, "mirror_conf_source", conf_src);
    (void)json_push_kv_bool(&row, "mirror_conf_is_instance_conf",
                            ohl_same_file(node_conf, conf));
    if (creds == LSTAT_CREDS_MISMATCH)
        (void)json_push_kv_bool(&row, "mirror_creds_mismatch", true);
    if (pid > 0)
        (void)json_push_kv_int(&row, "pid", pid);
    if (height >= 0) {
        (void)json_push_kv_int(&row, "rpc_height", height);
        ohl_rate_fields(&row, in, height, z23, now);
    }
    if (conns >= 0) {
        (void)json_push_kv_int(&row, "connections", conns);
        if (lstat_no_peers(conns, height, z23, in->prev_height))
            (void)json_push_kv_bool(&row, "no_peers", true);
    }
    (void)json_push_back(rows, &row);
    json_free(&row);
}

static void ohl_push_conflicts(struct zcl_command_reply *reply,
                               const struct ohl_inst *in, size_t n)
{
    struct lstat_inst ids[OHL_MAX_INSTANCES];
    char rows[OHL_MAX_INSTANCES * 4][LSTAT_CONFLICT_MAX];
    struct json_value arr;
    for (size_t i = 0; i < n; i++)
        ids[i] = in[i].id;
    size_t c = lstat_port_conflicts(ids, n, rows, OHL_MAX_INSTANCES * 4);
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < c; i++) {
        struct json_value s;
        json_init(&s);
        json_set_str(&s, rows[i]);
        (void)json_push_back(&arr, &s);
        json_free(&s);
    }
    (void)json_push_kv(&reply->data, "port_conflicts", &arr);
    json_free(&arr);
}

/* Identity-only mode for ExecStartPre: no RPC, no datadir, exit != 0 on
 * anything but a pinned match. */
static void ohl_identity_only(const struct json_value *in,
                              struct zcl_command_reply *reply)
{
    char binary[LSEED_PATH_MAX], pin[80] = "", actual[65];
    if (!ohl_take_str(in, "binary", binary, sizeof(binary))) {
        ohl_fail(reply, ZCL_COMMAND_EXIT_INVALID, "legacy_status.binary_required",
                 "validate", false, "identity_only needs binary", "binary");
        return;
    }
    (void)ohl_take_str(in, "sha256", pin, sizeof(pin));
    enum lstat_identity id = lstat_identity(binary, pin, actual);
    (void)json_push_kv_str(&reply->data, "binary", binary);
    (void)json_push_kv_str(&reply->data, "identity", lstat_identity_name(id));
    if (actual[0])
        (void)json_push_kv_str(&reply->data, "sha256", actual);
    if (id != LSTAT_ID_MATCH) {
        ohl_fail(reply, ZCL_COMMAND_EXIT_FAILED, "legacy_status.identity_not_pinned_match",
                 "identity", false,
                 "the legacy binary is missing, unpinned or does not match "
                 "the pinned sha256; refusing to start it",
                 lstat_identity_name(id));
        return;
    }
    reply->status = ZCL_COMMAND_STATUS_PASSED;
}

void zcl_native_handle_ops_host_legacy_status(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const struct json_value *in = request ? request->input : NULL;
    const struct json_value *list = json_get(in, "instances");
    struct ohl_inst inst[OHL_MAX_INSTANCES];
    struct json_value rows;
    char z23dir[LSEED_PATH_MAX] = "", node_conf[LSEED_PATH_MAX];
    const char *conf_src;
    bool rpc = json_get_bool_or(in, "rpc", true);
    int64_t z23 = -1, now = json_get_int_or(in, "now_unix", platform_time_wall_unix());
    size_t n;

    if (!reply)
        return;
    if (json_get_bool_or(in, "identity_only", false))
    {
        ohl_identity_only(in, reply);
        return;
    }
    n = list && list->type == JSON_ARR ? json_size(list) : 0;
    if (n == 0 || n > OHL_MAX_INSTANCES) {
        ohl_fail(reply, ZCL_COMMAND_EXIT_INVALID, "legacy_status.instances_invalid",
                 "validate", false,
                 "instances must be 1..8 objects {name,datadir,port,rpcport,"
                 "binary,sha256}", "instances");
        return;
    }
    for (size_t i = 0; i < n; i++)
        if (!ohl_take_inst(json_at(list, i), &inst[i])) {
            ohl_fail(reply, ZCL_COMMAND_EXIT_INVALID,
                     "legacy_status.instance_invalid", "validate", false,
                     "each instance needs name and datadir", "instances");
            return;
        }
    if (rpc && ohl_take_str(in, "z23_datadir", z23dir, sizeof(z23dir))) {
        char *raw = node_rpc_call_at_deadline(
            z23dir, (int)json_get_int_or(in, "z23_rpcport", 18232),
            "getblockchaininfo", NULL, OHL_RPC_MS, OHL_RPC_MS);
        z23 = ohl_height(raw);
        free(raw);
    }
    z23 = json_get_int_or(in, "z23_height", z23);
    {
        char given[LSEED_PATH_MAX] = "";
        (void)ohl_take_str(in, "node_conf", given, sizeof(given));
        conf_src = lstat_node_conf(given, node_conf, sizeof(node_conf));
    }
    json_init(&rows);
    json_set_array(&rows);
    for (size_t i = 0; i < n; i++)
        ohl_one_instance(&rows, &inst[i], rpc, z23, now, node_conf, conf_src);
    (void)json_push_kv(&reply->data, "instances", &rows);
    json_free(&rows);
    if (z23 >= 0)
        (void)json_push_kv_int(&reply->data, "z23_height", z23);
    ohl_push_conflicts(reply, inst, n);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
}
