/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: ops.mesh.device.pair.renew planner. Reads the current hash-PSK
 * pairing epoch N (expiry, credential, PSK fingerprint, the evidence slot it is
 * bound to), reports renew_due against a documented threshold and returns the
 * exact steps plus a plan_id over everything the execution depends on. The
 * planner mutates nothing; confirm re-derives the plan and refuses any drift. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#include "command/native_pair_renew.h"
#include "config/command_catalog.h"
#if defined(_WIN32)
/* Renewal composes POSIX descriptor-relative file semantics; fail closed elsewhere. */
static void pr_handle(const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    (void)request;
    if (reply)
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED, "UNSUPPORTED_PLATFORM", "normalize",
                               false, false, "pairing renewal needs POSIX file semantics", "ops.mesh.device.pair.renew");
}
#else
#include "crypto/sha256.h"
#include "sha3/sha3.h"
#include "base/hex.h"
#include "services/device_identity.h"
#include "util/authority_receipt.h"
#include "platform/os_proc.h"
#include "util/log_macros.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PR_TAG "native.pair_renew"
#define PR_TEXT_MAX 4096
#define PR_GRANT_DAYS_DEFAULT 7u
#define PR_GRANT_DAYS_MAX 30u

void pr_fail(struct zcl_command_reply *reply, const char *code, const char *phase, const char *message, bool mutated)
{
    LOG_ERROR(PR_TAG, "%s (%s): %s", code, phase, message);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED, code, phase, false, mutated,
                           message, "ops mesh device pair status shows every epoch; the current epoch stays in force");
}

bool pr_leaf(const char *path, const struct json_value *input, struct zcl_command_reply *reply)
{
    zcl_command_reply_init(reply, NULL);
    const struct zcl_command_spec *spec = zcl_command_registry_find(zcl_command_catalog(), path, NULL);
    if (!spec || !spec->handler) return false;
    struct zcl_command_request request = {.spec = spec, .input = input};
    spec->handler(&request, reply);
    return reply->status == ZCL_COMMAND_STATUS_PASSED;
}

void pr_state_free(struct pr_state *state)
{
    json_free(&state->client_route);
    json_free(&state->hub_route);
}

/* ── inputs ──────────────────────────────────────────────────────────── */

static bool pr_path_in(const struct json_value *in, const char *key, char out[PAIR_PATH_MAX], bool *given)
{
    const struct json_value *value = json_get(in, key);
    *given = value != NULL;
    if (!value) return true;
    if (value->type != JSON_STR || !pair_path_ok(json_get_str(value))) return false;
    snprintf(out, PAIR_PATH_MAX, "%s", json_get_str(value));
    return true;
}

static bool pr_bool_in(const struct json_value *in, const char *key, bool *out)
{
    const struct json_value *value = json_get(in, key);
    if (!value) return true;
    if (value->type != JSON_BOOL) return false;
    *out = json_get_bool(value);
    return true;
}

static bool pr_uint_in(const struct json_value *in, const char *key, uint64_t min, uint64_t max, uint64_t *out)
{
    const struct json_value *value = json_get(in, key);
    if (!value) return true;
    if (value->type != JSON_INT || json_get_int(value) < (int64_t)min || json_get_int(value) > (int64_t)max) return false;
    *out = (uint64_t)json_get_int(value);
    return true;
}

static bool pr_plan_id_in(const struct json_value *in, struct pr_cfg *cfg)
{
    const struct json_value *value = json_get(in, "plan_id");
    uint8_t scratch[32];
    if (!value) return true;
    if (value->type != JSON_STR || strlen(json_get_str(value)) != 64 || !zcl_hex_decode(json_get_str(value), scratch, 32)) return false;
    snprintf(cfg->plan_id, sizeof(cfg->plan_id), "%s", json_get_str(value));
    cfg->have_plan_id = true;
    return true;
}

static bool pr_state_dir_in(const struct json_value *in, struct pr_cfg *cfg)
{
    bool given;
    const char *home = getenv("HOME");
    if (!pr_path_in(in, "state_dir", cfg->state, &given)) return false;
    if (given) return true;
    return home && snprintf(cfg->state, sizeof(cfg->state), "%s/.local/state/z23-tunnel", home) < (int)sizeof(cfg->state) &&
           pair_path_ok(cfg->state);
}

/* The peer name must fit its bound whole: a truncated copy could pass the name check as a different peer. */
static bool pr_peer_in(const char *peer, struct pr_cfg *cfg)
{
    if (!peer) peer = "r2";
    if (strlen(peer) >= sizeof(cfg->peer)) return false;
    memcpy(cfg->peer, peer, strlen(peer) + 1);
    return pair_name_ok(cfg->peer);
}

static bool pr_parse(const struct json_value *in, struct pr_cfg *cfg)
{
    bool given;
    uint64_t days = PR_GRANT_DAYS_DEFAULT, before = PAIR_RENEW_BEFORE_DEFAULT_S;
    const char *peer = json_get_str(json_get(in, "peer"));
    memset(cfg, 0, sizeof(*cfg));
    bool ok = pr_peer_in(peer, cfg) && pr_state_dir_in(in, cfg) &&
              pr_path_in(in, "hub_state_dir", cfg->hub_state, &given) && pr_path_in(in, "hub_config_dir", cfg->hub_config, &given) &&
              pr_path_in(in, "evidence_dir", cfg->evidence, &given) && pr_path_in(in, "slot_bin", cfg->slot_bin, &given) &&
              pr_path_in(in, "hub_unit_file", cfg->unit_file, &given) && pr_plan_id_in(in, cfg) &&
              pr_bool_in(in, "confirm", &cfg->confirm) && pr_bool_in(in, "force", &cfg->force) &&
              pr_uint_in(in, "renew_before_s", PAIR_RENEW_BEFORE_MIN_S, PAIR_RENEW_BEFORE_MAX_S, &before) &&
              pr_uint_in(in, "grant_days", 1, PR_GRANT_DAYS_MAX, &days);
#ifdef ZCL_TESTING
    ok = ok && pr_bool_in(in, "test_smoke_fault", &cfg->fault);
#endif
    cfg->before_s = before;
    cfg->grant_days = (uint32_t)days;
    return ok;
}

/* ── evidence and unit binding ───────────────────────────────────────── */

static bool pr_read_text(const char *path, char *out, size_t cap)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NOCTTY);
    if (fd < 0) return false;
    ssize_t got;
    do got = read(fd, out, cap - 1); while (got < 0 && errno == EINTR);
    close(fd);
    /* a file that fills the buffer may be cut mid-line: refuse rather than parse a prefix */
    if (got < 0 || (size_t)got >= cap - 1) { LOG_ERROR(PR_TAG, "%s unreadable or larger than %zu bytes", path, cap - 1); return false; }
    out[got] = 0;
    return true;
}

static bool pr_file_sha256(const char *path, char hex[65])
{
    struct sha256_ctx ctx;
    unsigned char block[65536], digest[SHA256_OUTPUT_SIZE];
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY);
    if (fd < 0) return false;
    sha256_init(&ctx);
    for (;;) {
        ssize_t got = read(fd, block, sizeof(block));
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) { close(fd); if (got < 0) return false; break; }
        sha256_write(&ctx, block, (size_t)got);
    }
    sha256_finalize(&ctx, digest);
    zcl_hex_encode(digest, SHA256_OUTPUT_SIZE, hex);
    return true;
}

static bool pr_env_value(const char *text, const char *key, char *out, size_t cap)
{
    size_t length = strlen(key);
    for (const char *line = text; line && *line; line = strchr(line, '\n') ? strchr(line, '\n') + 1 : NULL) {
        if (strncmp(line, key, length) || line[length] != '=') continue;
        const char *end = strchr(line, '\n');
        size_t n = end ? (size_t)(end - line) - length - 1 : strlen(line + length + 1);
        if (!n || n >= cap) return false;
        memcpy(out, line + length + 1, n);
        out[n] = 0;
        return true;
    }
    return false;
}

static bool pr_slot_name_ok(const char *name)
{
    if (strlen(name) != 19 || strncmp(name, "tunnel-", 7)) return false;
    for (const char *p = name + 7; *p; ++p)
        if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f'))) return false;
    return true;
}

static bool pr_slot_binary(const struct pr_cfg *cfg, char out[PATH_MAX])
{
    char exe[PATH_MAX];
    if (cfg->slot_bin[0]) return realpath(cfg->slot_bin, out) != NULL;
    return os_proc_exe_path(exe, sizeof(exe)) && realpath(exe, out) != NULL;
}

/* The evidence is current when the slot its slot.env names is the slot binary this plan
 * runs from; an older evidence directory names an older digest and is refused. */
static bool pr_check_evidence(const struct pr_cfg *cfg, struct pr_state *st, struct zcl_command_reply *reply)
{
    char path[PAIR_PATH_MAX + 16], text[PR_TEXT_MAX], binary[PATH_MAX], digest[65], want[65], real[PATH_MAX];
    if (!cfg->evidence[0]) return true;
    st->evidence_checked = true;
    snprintf(path, sizeof(path), "%s/slot.env", cfg->evidence);
    if (!realpath(cfg->evidence, real) || strlen(real) >= sizeof(st->evidence_real) || !pr_read_text(path, text, sizeof(text)) ||
        !pr_env_value(text, "SLOT_NAME", st->slot_name, sizeof(st->slot_name)) || !pr_slot_name_ok(st->slot_name) ||
        !pr_env_value(text, "SLOT_SHA256", want, sizeof(want)) || strlen(want) != 64 ||
        !pr_slot_binary(cfg, binary) || !pr_file_sha256(binary, digest)) {
        pr_fail(reply, "RENEW_EVIDENCE_INVALID", "evidence", "evidence_dir needs a slot.env with SLOT_NAME=tunnel-<12hex> and SLOT_SHA256, and a readable slot_bin", false);
        return false;
    }
    memcpy(st->evidence_real, real, strlen(real) + 1);
    memcpy(st->slot_sha, want, sizeof(want));
    st->evidence_current = !strcmp(want, digest);
    return true;
}

static bool pr_check_unit(const struct pr_cfg *cfg, struct pr_state *st, struct zcl_command_reply *reply)
{
    char text[PR_TEXT_MAX], exec[PATH_MAX + 128], binary[PATH_MAX];
    if (!cfg->unit_file[0]) return true;
    st->unit_checked = true;
    if (!pr_read_text(cfg->unit_file, text, sizeof(text)) || !pr_env_value(text, "ExecStart", exec, sizeof(exec)) ||
        !pr_slot_binary(cfg, binary)) {
        pr_fail(reply, "RENEW_UNIT_UNREADABLE", "unit", "hub_unit_file needs a readable ExecStart= line", false);
        return false;
    }
    char *space = strchr(exec, ' ');
    if (space) *space = 0;
    st->unit_match = !strcmp(exec, binary);
    return true;
}

/* ── hub side and plan id ────────────────────────────────────────────── */

static bool pr_hex_in(const struct json_value *obj, const char *key, uint8_t out[32])
{
    const char *text = json_get_str(json_get(obj, key));
    return text && strlen(text) == 64 && zcl_hex_decode(text, out, 32);
}

static bool pr_route_load(const char *dir, const char *name, struct json_value *out)
{
    char path[PAIR_PATH_MAX + 32], text[PR_TEXT_MAX];
    size_t length = 0;
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    return zcl_native_device_host_input_file_read(path, text, sizeof(text), &length) && json_read(out, text, length) &&
           out->type == JSON_OBJ;
}

static bool pr_hub_grant(struct pr_state *st)
{
    struct device_identity identity = {0};
    struct device_identity_publication_report report;
    struct device_pairing_store store;
    struct db_device_pairing row;
    uint8_t root[32], configured[32];
    const char *directory = json_get_str(json_get(&st->hub_route, "directory"));
    if (!directory || !pr_hex_in(&st->hub_route, "peer_key", st->client_key) ||
        !pr_hex_in(&st->hub_route, "expected_root", configured) || strlen(directory) >= sizeof(st->hub_profile)) return false;
    snprintf(st->hub_profile, sizeof(st->hub_profile), "%s", directory);
    if (!device_identity_open(&identity, directory, false, &report).ok) return false;
    bool ok = device_identity_pair_store(&identity, st->client_key, &store).ok &&
              db_device_pairing_inspect(&store, st->client_key, &row, root) && !memcmp(root, configured, 32) &&
              !memcmp(row.host_scope.binding.psk.credential_id, st->cur.row.host_scope.binding.psk.credential_id, 32);
    device_identity_close(&identity);
    if (ok) memcpy(st->hub_root, root, 32);
    return ok;
}

static bool pr_load_hub(const struct pr_cfg *cfg, struct pr_state *st, struct zcl_command_reply *reply)
{
    char dir[PAIR_PATH_MAX];
    if (!cfg->hub_state[0]) return true;
    int dn = snprintf(dir, sizeof(dir), "%s/%s-e%u", cfg->hub_state, st->cur.client, (unsigned)st->cur.epoch);
    snprintf(st->hub_dir, sizeof(st->hub_dir), "%s", dir);
    if (dn < 0 || (size_t)dn >= sizeof(dir) || !pr_route_load(dir, "receiver.json", &st->hub_route) || !pr_hub_grant(st)) {
        pr_fail(reply, "RENEW_GRANT_DRIFT", "hub", "the hub receiver route or its grant is unreadable, or no longer matches epoch N's client grant", false);
        return false;
    }
    st->hub_known = true;
    return true;
}

static void pr_hash_text(struct sha3_256_ctx *ctx, const char *text)
{
    sha3_256_write(ctx, (const unsigned char *)text, strlen(text) + 1);
}

static bool pr_plan_hash(struct pr_state *st)
{
    struct sha3_256_ctx ctx;
    uint8_t digest[32], binary[32];
    char number[32], root[65], hub[65];
    if (!authority_receipt_running_binary_digest(binary)) return false;
    sha3_256_init(&ctx);
    pr_hash_text(&ctx, "z23.pair.renew.plan.v1");
    pr_hash_text(&ctx, st->cur.client);
    pr_hash_text(&ctx, st->cur.route_id);
    snprintf(number, sizeof(number), "%u:%u:%llu", (unsigned)st->cur.epoch, (unsigned)st->next, (unsigned long long)st->cur.row.expires_at);
    pr_hash_text(&ctx, number);
    zcl_hex_encode(st->cur.root, 32, root);
    pr_hash_text(&ctx, root);
    zcl_hex_encode(st->hub_root, 32, hub);
    pr_hash_text(&ctx, st->hub_known ? hub : "no-hub");
    pr_hash_text(&ctx, st->hub_dir);
    pr_hash_text(&ctx, st->evidence_checked ? st->evidence_real : "no-evidence");
    pr_hash_text(&ctx, st->evidence_current ? st->slot_sha : "stale");
    pr_hash_text(&ctx, st->unit_match ? "unit-ok" : "unit-unchecked");
    sha3_256_write(&ctx, binary, sizeof(binary));
    sha3_256_finalize(&ctx, digest);
    zcl_hex_encode(digest, 32, st->plan_id);
    return true;
}

static bool pr_resolve_current(const struct pr_cfg *cfg, struct pr_state *st, struct zcl_command_reply *reply)
{
    uint32_t epochs[PAIR_EPOCH_LIST_MAX];
    size_t count = pair_epoch_list(cfg->state, cfg->peer, epochs, PAIR_EPOCH_LIST_MAX);
    st->now = pair_now();
    if (!count || !pair_epoch_load(cfg->state, cfg->peer, epochs[count - 1], &st->cur) ||
        !pr_route_load(st->cur.dir, "client.json", &st->client_route)) {
        pr_fail(reply, "RENEW_NO_CURRENT_EPOCH", "state", "no readable client route for this peer under state_dir; pair a first epoch", false);
        return false;
    }
    if (pair_epoch_state(&st->cur, st->now) == PAIR_REVOKED) {
        pr_fail(reply, "RENEW_NO_CURRENT_EPOCH", "state", "the newest epoch is revoked; pair a fresh epoch rather than renewing", false);
        return false;
    }
    uint32_t cmax = pair_dir_max(cfg->state, cfg->peer), hmax = cfg->hub_state[0] ? pair_dir_max(cfg->hub_state, st->cur.client) : 0;
    st->next = (cmax > hmax ? cmax : hmax) + 1;
    st->due = pair_renew_due(&st->cur, st->now, cfg->before_s);
    return true;
}

static bool pr_resolve(const struct pr_cfg *cfg, struct pr_state *st, struct zcl_command_reply *reply)
{
    json_init(&st->client_route);
    json_init(&st->hub_route);
    if (!pr_resolve_current(cfg, st, reply) || !pr_load_hub(cfg, st, reply) ||
        !pr_check_evidence(cfg, st, reply) || !pr_check_unit(cfg, st, reply)) return false;
    if (!pr_plan_hash(st)) {
        pr_fail(reply, "RENEW_BINARY_DIGEST_FAILED", "plan", "the running binary could not be digested for the plan binding", false);
        return false;
    }
    return true;
}

/* ── plan emission ───────────────────────────────────────────────────── */

static bool pr_steps(struct json_value *list, const struct pr_state *st)
{
    static const char *const steps[] = {
        "verify the evidence slot digest and the hub unit ExecStart name this binary",
        "create epoch N+1 directories and init a fresh identity on each side",
        "mint the PSK on the client; both commits import that one file, no PSK byte enters this process, reply or log",
        "plan then commit the mirrored host-forward grants and require one matching psk_fingerprint",
        "write the hub receiver route and switch the hub unit environment to epoch N+1",
        "smoke: real receiver and client runtimes round-trip the target banner through epoch N+1",
        "on pass: write the client route, then revoke epoch N on both sides with exact inspected roots",
        "on any failure: revoke epoch N+1, restore the unit environment, burn the epoch and leave epoch N in force",
        "append the renewal receipt through the authority receipt idiom"};
    json_set_array(list);
    for (size_t i = 0; i < sizeof(steps) / sizeof(steps[0]); ++i) {
        struct json_value item = {0};
        json_set_str(&item, steps[i]);
        bool ok = json_push_back(list, &item);
        json_free(&item);
        if (!ok) return false;
    }
    (void)st;
    return true;
}

static bool pr_emit_epoch(struct json_value *data, const struct pr_cfg *cfg, const struct pr_state *st)
{
    return json_push_kv_int(data, "current_epoch", st->cur.epoch) && json_push_kv_int(data, "next_epoch", st->next) &&
           json_push_kv_str(data, "client", st->cur.client) && json_push_kv_str(data, "peer", cfg->peer) &&
           json_push_kv_str(data, "route_id", st->cur.route_id) &&
           json_push_kv_int(data, "expires_at", (int64_t)st->cur.row.expires_at) &&
           json_push_kv_int(data, "expires_in_s", (int64_t)st->cur.row.expires_at - (int64_t)st->now) &&
           json_push_kv_int(data, "renew_before_s", (int64_t)cfg->before_s) &&
           json_push_kv_bool(data, "renew_due", st->due) &&
           json_push_kv_str(data, "credential_id", st->cur.credential) &&
           json_push_kv_str(data, "psk_fingerprint", st->cur.psk_fp) &&
           json_push_kv_int(data, "grant_days", cfg->grant_days);
}

static bool pr_emit_binding(struct json_value *data, const struct pr_state *st)
{
    return json_push_kv_bool(data, "evidence_checked", st->evidence_checked) &&
           json_push_kv_bool(data, "evidence_current", st->evidence_checked ? st->evidence_current : true) &&
           json_push_kv_str(data, "slot_name", st->slot_name) && json_push_kv_str(data, "slot_sha256", st->slot_sha) &&
           json_push_kv_str(data, "evidence_dir", st->evidence_real) &&
           json_push_kv_bool(data, "unit_checked", st->unit_checked) &&
           json_push_kv_bool(data, "unit_slot_match", st->unit_checked ? st->unit_match : true) &&
           json_push_kv_bool(data, "hub_known", st->hub_known);
}

static void pr_emit_plan(const struct pr_cfg *cfg, const struct pr_state *st, struct zcl_command_reply *reply)
{
    struct json_value steps = {0};
    json_set_object(&reply->data);
    bool ok = json_push_kv_str(&reply->data, "schema", "zcl.device.pair.renew.plan.v1") &&
              pr_emit_epoch(&reply->data, cfg, st) && pr_emit_binding(&reply->data, st) &&
              json_push_kv_str(&reply->data, "plan_id", st->plan_id) && json_push_kv_bool(&reply->data, "committed", false) &&
              json_push_kv_bool(&reply->data, "confirm_possible", st->hub_known && (st->due || cfg->force)) && pr_steps(&steps, st) &&
              json_push_kv(&reply->data, "steps", &steps);
    json_free(&steps);
    if (!ok) pr_fail(reply, "RENEW_SERIALIZE_FAILED", "plan", "the renewal plan did not fit the bounded reply", false);
}

/* ── handler ─────────────────────────────────────────────────────────── */

static bool pr_confirm_checks(const struct pr_cfg *cfg, const struct pr_state *st, struct zcl_command_reply *reply)
{
    if (!cfg->have_plan_id) {
        pr_fail(reply, "RENEW_PLAN_REQUIRED", "confirm", "confirm needs the plan_id from a plan of this exact pairing", false);
    } else if (strcmp(cfg->plan_id, st->plan_id)) {
        pr_fail(reply, "RENEW_PLAN_MISMATCH", "confirm", "plan_id does not match the pairing, evidence and binary as they stand now; plan again", false);
    } else if (st->evidence_checked && !st->evidence_current) {
        pr_fail(reply, "RENEW_EVIDENCE_STALE", "confirm", "the evidence slot.env names a different slot digest than the slot binary; use the current evidence", false);
    } else if (st->unit_checked && !st->unit_match) {
        pr_fail(reply, "RENEW_UNIT_SLOT_MISMATCH", "confirm", "the hub unit ExecStart does not name the slot binary; refresh the unit first", false);
    } else if (!st->due && !cfg->force) {
        pr_fail(reply, "RENEW_NOT_DUE", "confirm", "the pairing expires later than renew_before_s; pass force:true to renew early", false);
    } else if (!st->hub_known) {
        pr_fail(reply, "RENEW_HUB_UNREACHABLE", "confirm", "hub_state_dir is required to renew both sides; this leaf only reaches a hub profile reachable as a directory", false);
    } else {
        return true;
    }
    return false;
}

static void pr_handle(const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    struct pr_cfg cfg;
    struct pr_state st;
    if (!reply) return;
    memset(&st, 0, sizeof(st));
    if (!request || !request->input || request->input->type != JSON_OBJ || !pr_parse(request->input, &cfg)) {
        pr_fail(reply, "RENEW_INPUT_REFUSED", "normalize", "state_dir, hub_state_dir, hub_config_dir, evidence_dir, slot_bin and hub_unit_file must be absolute simple paths; peer a short lowercase name; plan_id 64 hex", false);
        return;
    }
    if (pr_resolve(&cfg, &st, reply)) {
        if (!cfg.confirm) pr_emit_plan(&cfg, &st, reply);
        else if (pr_confirm_checks(&cfg, &st, reply)) pair_renew_execute(&cfg, &st, reply);
    }
    pr_state_free(&st);
}
#endif

void zcl_native_handle_ops_mesh_device_pair_renew(const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    pr_handle(request, reply);
}
