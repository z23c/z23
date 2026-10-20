/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: ops.mesh.device.pair.renew executor. Composes the existing device
 * leaves exactly as the rollout's 20-pair.sh and 30-unit.sh did (init, psk new,
 * plan, commit, revoke inspect/confirm) to create epoch N+1, switches the hub
 * unit environment, requires the smoke round trip, and only then retires epoch
 * N. Any failure revokes N+1, restores the environment and leaves N in force.
 * No PSK byte is read, held, printed or logged here: both commits import the
 * one owner-private source file the client mint wrote, which is then removed. */
#include "command/native_pair_renew.h"
#include "config/command_catalog.h"
#include "base/hex.h"
#include "net/v2_identity.h"
#include "services/device_host_runtime_entry.h"
#include "platform/rng.h"
#include "sha3/sha3.h"
#include "util/authority_receipt.h"
#include "util/log_macros.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PRR_TAG "native.pair_renew_run"
#define PRR_TEXT_MAX 4096
#define PRR_SMOKE_MS 15000u

struct prr {
    const struct pr_cfg *cfg;
    const struct pr_state *st;
    struct zcl_command_reply *reply;
    char cdir[PAIR_PATH_MAX], hdir[PAIR_PATH_MAX], cprof[PAIR_PATH_MAX], hprof[PAIR_PATH_MAX];
    char csecret_dir[PAIR_PATH_MAX], csecret[PAIR_PATH_MAX], env_path[PAIR_PATH_MAX], route_id[64];
    uint8_t c_pk[32], h_pk[32], c_root[32], h_root[32];
    char cred[65], psk_fp[17];
    uint64_t expires;
    bool made_dirs, c_committed, h_committed, env_changed, env_had_prev, retired_client, retired_hub;
    char env_prev[PRR_TEXT_MAX];
    struct pair_smoke_out smoke;
    const char *code, *stage;
};

/* ── leaf plumbing ───────────────────────────────────────────────────── */

static bool prr_hex(const struct zcl_command_reply *reply, const char *key, uint8_t out[32])
{
    const char *text = json_get_str(json_get(&reply->data, key));
    return text && strlen(text) == 64 && zcl_hex_decode(text, out, 32);
}

static bool prr_str_is(const struct zcl_command_reply *reply, const char *key, const char *want)
{
    const char *text = json_get_str(json_get(&reply->data, key));
    return text && !strcmp(text, want);
}

static bool prr_bool_is(const struct zcl_command_reply *reply, const char *key, bool want)
{
    const struct json_value *value = json_get(&reply->data, key);
    return value && value->type == JSON_BOOL && json_get_bool(value) == want;
}

static bool prr_in(struct json_value *in, const char *dir, const uint8_t peer[32])
{
    char hex[65];
    json_set_object(in);
    if (!json_push_kv_str(in, "directory", dir)) return false;
    if (!peer) return true;
    zcl_hex_encode(peer, 32, hex);
    return json_push_kv_str(in, "peer_key", hex);
}

/* ── revoke (also the inspection both retire and abort use) ──────────── */

enum prr_revoke { PRR_REVOKED, PRR_ALREADY, PRR_FAILED };

static enum prr_revoke prr_revoke_side(const char *profile, const uint8_t peer[32])
{
    struct json_value in = {0};
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, NULL);
    uint8_t fingerprint[32];
    char root[65], fp[65];
    bool ok = prr_in(&in, profile, peer) && pr_leaf("ops.mesh.device.revoke", &in, &reply);
    if (!ok) { json_free(&in); zcl_command_reply_free(&reply); return PRR_FAILED; }
    const struct json_value *revoked = json_get(&reply.data, "inspected_revoked_at");
    const char *expected = json_get_str(json_get(&reply.data, "expected_root"));
    if (revoked && revoked->type == JSON_INT && json_get_int(revoked) != 0) {
        json_free(&in); zcl_command_reply_free(&reply);
        return PRR_ALREADY;
    }
    ok = expected && strlen(expected) == 64 && v2_identity_public_fingerprint(peer, fingerprint);
    if (ok) { snprintf(root, sizeof(root), "%s", expected); zcl_hex_encode(fingerprint, 32, fp); }
    zcl_command_reply_free(&reply);
    ok = ok && json_push_kv_str(&in, "expected_root", root) && json_push_kv_str(&in, "fingerprint", fp) &&
         pr_leaf("ops.mesh.device.revoke", &in, &reply) && prr_bool_is(&reply, "committed", true);
    json_free(&in);
    zcl_command_reply_free(&reply);
    return ok ? PRR_REVOKED : PRR_FAILED;
}

/* ── file records: validate, write atomically 0600, read back ────────── */

static bool prr_write_checked(const char *dir, const char *name, const char *text, bool receiver)
{
    struct json_value parsed = {0};
    char path[PAIR_PATH_MAX + 32], back[PRR_TEXT_MAX];
    size_t length = strlen(text), got = 0;
    json_init(&parsed);
    bool valid = device_host_runtime_entry_parse(&parsed, text, length, receiver).ok;
    json_free(&parsed);
    if (!valid) { LOG_ERROR(PRR_TAG, "%s refused by the strict runtime parser before writing", name); return false; }
    if (!authority_receipt_write_atomic(dir, name, (const uint8_t *)text, length, path, sizeof(path))) return false;
    return zcl_native_device_host_input_file_read(path, back, sizeof(back), &got) && got == length && !memcmp(back, text, length);
}

/* The epoch N route with this epoch's directory, peer, root and route id swapped in. */
static bool prr_rebind(const struct json_value *old, const char *directory, const uint8_t peer[32],
                       const uint8_t root[32], const char *route_id, char *text, size_t cap)
{
    struct json_value fresh = {0};
    char peer_hex[65], root_hex[65];
    zcl_hex_encode(peer, 32, peer_hex);
    zcl_hex_encode(root, 32, root_hex);
    json_set_object(&fresh);
    bool ok = true;
    for (size_t i = 0; ok && i < old->num_children; ++i) {
        const char *key = old->keys[i];
        if (!strcmp(key, "directory")) ok = json_push_kv_str(&fresh, key, directory);
        else if (!strcmp(key, "peer_key")) ok = json_push_kv_str(&fresh, key, peer_hex);
        else if (!strcmp(key, "expected_root")) ok = json_push_kv_str(&fresh, key, root_hex);
        else if (!strcmp(key, "route_id")) ok = json_push_kv_str(&fresh, key, route_id);
        else ok = json_push_kv(&fresh, key, &old->children[i]);
    }
    ok = ok && json_write(&fresh, text, cap) > 0;
    json_free(&fresh);
    return ok;
}

static bool prr_write_route(struct prr *run, bool receiver)
{
    char text[PRR_TEXT_MAX];
    const struct json_value *old = receiver ? &run->st->hub_route : &run->st->client_route;
    bool ok = receiver ? prr_rebind(old, run->hprof, run->c_pk, run->h_root, run->route_id, text, sizeof(text))
                       : prr_rebind(old, run->cprof, run->h_pk, run->c_root, run->route_id, text, sizeof(text));
    return ok && prr_write_checked(receiver ? run->hdir : run->cdir, receiver ? "receiver.json" : "client.json", text, receiver);
}

/* ── hub unit environment (the 30-unit step) ─────────────────────────── */

static void prr_env_remember(struct prr *run)
{
    int fd = open(run->env_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    ssize_t got = fd >= 0 ? read(fd, run->env_prev, sizeof(run->env_prev) - 1) : -1;
    if (fd >= 0) close(fd);
    run->env_had_prev = got >= 0;
    run->env_prev[got > 0 ? got : 0] = 0;
}

static bool prr_env_switch(struct prr *run)
{
    char text[PRR_TEXT_MAX], dir[PAIR_PATH_MAX], name[PAIR_NAME_MAX + 32];
    if (!run->cfg->hub_config[0]) return true;
    snprintf(dir, sizeof(dir), "%s", run->cfg->hub_config);
    snprintf(name, sizeof(name), "tunnel-receiver-%s.env", run->st->cur.client);
    snprintf(run->env_path, sizeof(run->env_path), "%s/%s", dir, name);
    prr_env_remember(run);
    snprintf(text, sizeof(text), "# z23 tunnel receiver for client %s, epoch %u (written by ops mesh device pair renew)\nZ23_TUNNEL_RECEIVER_INPUT=%s/receiver.json\n",
             run->st->cur.client, (unsigned)run->st->next, run->hdir);
    run->env_changed = authority_receipt_write_atomic(dir, name, (const uint8_t *)text, strlen(text), NULL, 0);
    return run->env_changed;
}

static void prr_env_restore(struct prr *run)
{
    if (!run->env_changed) return;
    char dir[PAIR_PATH_MAX], name[PAIR_NAME_MAX + 32];
    snprintf(dir, sizeof(dir), "%s", run->cfg->hub_config);
    snprintf(name, sizeof(name), "tunnel-receiver-%s.env", run->st->cur.client);
    if (run->env_had_prev) (void)authority_receipt_write_atomic(dir, name, (const uint8_t *)run->env_prev, strlen(run->env_prev), NULL, 0);
    else (void)unlink(run->env_path);
    run->env_changed = false;
}

/* ── abort: epoch N is untouched, N+1 is revoked and burned ──────────── */

static void prr_burn(struct prr *run)
{
    char text[96];
    if (!run->made_dirs) return;
    snprintf(text, sizeof(text), "stage=%s\n", run->stage ? run->stage : "unknown");
    (void)authority_receipt_write_atomic(run->cdir, "burned", (const uint8_t *)text, strlen(text), NULL, 0);
}

static void prr_abort(struct prr *run)
{
    prr_env_restore(run);
    if (run->c_committed) (void)prr_revoke_side(run->cprof, run->h_pk);
    if (run->h_committed) (void)prr_revoke_side(run->hprof, run->c_pk);
    if (run->csecret[0]) (void)unlink(run->csecret);
    prr_burn(run);
}

static void prr_fail(struct prr *run, const char *code, const char *stage, const char *message)
{
    run->code = code;
    run->stage = stage;
    prr_abort(run);
    json_set_object(&run->reply->data);
    (void)json_push_kv_str(&run->reply->data, "stage", stage);
    (void)json_push_kv_int(&run->reply->data, "failed_epoch", run->st->next);
    (void)json_push_kv_int(&run->reply->data, "epoch_in_force", run->st->cur.epoch);
    (void)json_push_kv_bool(&run->reply->data, "previous_in_force", true);
    pr_fail(run->reply, code, stage, message, run->made_dirs);
}

/* ── pairing: the 20-pair.sh steps ───────────────────────────────────── */

static bool prr_paths(struct prr *run)
{
    const struct pr_state *st = run->st;
    char name[48];
    snprintf(run->cdir, sizeof(run->cdir), "%s/%s-e%u", run->cfg->state, run->cfg->peer, (unsigned)st->next);
    snprintf(run->hdir, sizeof(run->hdir), "%s/%s-e%u", run->cfg->hub_state, st->cur.client, (unsigned)st->next);
    snprintf(run->cprof, sizeof(run->cprof), "%s/profile", run->cdir);
    snprintf(run->hprof, sizeof(run->hprof), "%s/profile", run->hdir);
    snprintf(run->csecret_dir, sizeof(run->csecret_dir), "%s/secret", run->cdir);
    snprintf(run->csecret, sizeof(run->csecret), "%s/psk", run->csecret_dir);
    snprintf(name, sizeof(name), "%s-%s-e%u", st->cur.client, run->cfg->peer, (unsigned)st->next);
    snprintf(run->route_id, sizeof(run->route_id), "%s", name);
    return true;
}

static bool prr_make_dirs(struct prr *run)
{
    if (access(run->cdir, F_OK) == 0 || access(run->hdir, F_OK) == 0) {
        prr_fail(run, "RENEW_EPOCH_EXISTS", "preflight", "epoch N+1 already exists on a side; plan again to count past it");
        return false;
    }
    run->made_dirs = mkdir(run->cdir, 0700) == 0;
    if (!run->made_dirs || mkdir(run->hdir, 0700) != 0 || mkdir(run->csecret_dir, 0700) != 0) {
        prr_fail(run, "RENEW_DIRS_FAILED", "init", "epoch N+1 directories could not be created owner-private");
        return false;
    }
    return true;
}

static bool prr_init_side(const char *profile, uint8_t key[32])
{
    struct json_value in = {0};
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, NULL);
    bool ok = prr_in(&in, profile, NULL) && pr_leaf("ops.mesh.device.init", &in, &reply) &&
              prr_str_is(&reply, "identity_publication", "durable") && prr_hex(&reply, "public_key", key);
    json_free(&in);
    zcl_command_reply_free(&reply);
    return ok;
}

static bool prr_psk_new(struct prr *run)
{
    struct json_value in = {0};
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, NULL);
    json_set_object(&in);
    bool ok = json_push_kv_str(&in, "key", run->csecret) && pr_leaf("ops.mesh.device.psk.new", &in, &reply) &&
              prr_str_is(&reply, "secret_publication", "durable");
    const char *fp = json_get_str(json_get(&reply.data, "psk_fingerprint"));
    if (ok && fp && strlen(fp) == 16) snprintf(run->psk_fp, sizeof(run->psk_fp), "%s", fp);
    else ok = false;
    json_free(&in);
    zcl_command_reply_free(&reply);
    return ok;
}

/* Mirrored grant input: client 0/target, hub target/0, one credential, key_epoch 1. */
static bool prr_grant_in(struct prr *run, struct json_value *in, const char *profile, const uint8_t peer[32],
                         unsigned inbound, unsigned outbound)
{
    return prr_in(in, profile, peer) && json_push_kv_str(in, "capability", "host-forward") &&
           json_push_kv_int(in, "backend", 2) && json_push_kv_str(in, "credential_id", run->cred) &&
           json_push_kv_int(in, "key_epoch", 1) && json_push_kv_int(in, "inbound_port", inbound) &&
           json_push_kv_int(in, "outbound_port", outbound) && json_push_kv_int(in, "expires_at", (int64_t)run->expires) &&
           json_push_kv_str(in, "expected_root", "absent");
}

static bool prr_plan_ok(const struct prr *run, const struct zcl_command_reply *reply)
{
    const struct json_value *expires = json_get(&reply->data, "expires_at");
    const struct json_value *paired = json_get(&reply->data, "paired_at");
    return prr_str_is(reply, "credential_id", run->cred) && prr_bool_is(reply, "committed", false) && expires &&
           json_get_int(expires) == (int64_t)run->expires && paired && (uint64_t)json_get_int(paired) + 2592000u >= run->expires;
}

static bool prr_commit_side(struct prr *run, const struct json_value *plan_in, const struct zcl_command_reply *plan, bool *committed)
{
    struct json_value in = {0};
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, NULL);
    const char *proposal = json_get_str(json_get(&plan->data, "proposal_root"));
    json_init(&in);
    json_copy(&in, plan_in);
    bool ok = proposal && json_push_kv_int(&in, "paired_at", json_get_int(json_get(&plan->data, "paired_at"))) &&
              json_push_kv_str(&in, "confirmed_proposal_root", proposal) && json_push_kv_str(&in, "secret_file", run->csecret);
    if (!ok) { json_free(&in); return false; }
    ok = pr_leaf("ops.mesh.device.commit", &in, &reply);
    if (reply.error.mutated || ok) *committed = true;
    ok = ok && prr_bool_is(&reply, "committed", true) && prr_str_is(&reply, "secret_publication", "durable") &&
         prr_str_is(&reply, "grant_publication", "durable") && prr_str_is(&reply, "psk_fingerprint", run->psk_fp);
    json_free(&in);
    zcl_command_reply_free(&reply);
    return ok;
}

static bool prr_plan_commit(struct prr *run)
{
    struct json_value in[2] = {{0}, {0}};
    struct zcl_command_reply plan[2];
    uint8_t cred[32];
    int64_t port = run->st->cur.target_port;
    bool ok = rng_host_fill(cred, sizeof(cred));
    if (ok) zcl_hex_encode(cred, 32, run->cred);
    run->expires = pair_now() + (uint64_t)run->cfg->grant_days * 86400u;
    ok = ok && prr_grant_in(run, &in[0], run->cprof, run->h_pk, 0, (unsigned)port) &&
         prr_grant_in(run, &in[1], run->hprof, run->c_pk, (unsigned)port, 0);
    for (int i = 0; i < 2; ++i) zcl_command_reply_init(&plan[i], NULL);
    for (int i = 0; ok && i < 2; ++i) ok = pr_leaf("ops.mesh.device.plan", &in[i], &plan[i]) && prr_plan_ok(run, &plan[i]);
    ok = ok && prr_str_is(&plan[0], "endpoint_a", json_get_str(json_get(&plan[1].data, "endpoint_a"))) &&
         prr_str_is(&plan[0], "endpoint_b", json_get_str(json_get(&plan[1].data, "endpoint_b")));
    ok = ok && prr_commit_side(run, &in[0], &plan[0], &run->c_committed) && prr_commit_side(run, &in[1], &plan[1], &run->h_committed);
    for (int i = 0; i < 2; ++i) { json_free(&in[i]); zcl_command_reply_free(&plan[i]); }
    return ok;
}

static bool prr_inspect(const char *profile, const uint8_t peer[32], uint8_t root[32])
{
    struct json_value in = {0};
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, NULL);
    bool ok = prr_in(&in, profile, peer) && pr_leaf("ops.mesh.device.revoke", &in, &reply) &&
              prr_bool_is(&reply, "committed", false) && prr_hex(&reply, "expected_root", root) &&
              json_get_int(json_get(&reply.data, "inspected_revoked_at")) == 0;
    json_free(&in);
    zcl_command_reply_free(&reply);
    return ok;
}

/* ── the pairing run ─────────────────────────────────────────────────── */

static bool prr_pair(struct prr *run)
{
    if (!prr_make_dirs(run)) return false;
    if (!prr_init_side(run->cprof, run->c_pk) || !prr_init_side(run->hprof, run->h_pk)) {
        prr_fail(run, "RENEW_PAIR_FAILED", "init", "a fresh epoch identity could not be created durably on a side");
        return false;
    }
    if (!prr_psk_new(run)) {
        prr_fail(run, "RENEW_PAIR_FAILED", "psk", "the epoch PSK source could not be minted");
        return false;
    }
    if (!prr_plan_commit(run)) {
        prr_fail(run, "RENEW_PAIR_FAILED", "commit", "the mirrored grants were refused or the PSK fingerprints disagreed");
        return false;
    }
    (void)unlink(run->csecret); /* the profiles now hold the key */
    if (access(run->csecret, F_OK) == 0) {
        prr_fail(run, "RENEW_PAIR_FAILED", "secret_cleanup", "the PSK source file could not be removed after commit");
        return false;
    }
    run->csecret[0] = 0;
    if (!prr_inspect(run->cprof, run->h_pk, run->c_root) || !prr_inspect(run->hprof, run->c_pk, run->h_root)) {
        prr_fail(run, "RENEW_PAIR_FAILED", "inspect", "the new grants could not be inspected for their roots");
        return false;
    }
    return true;
}

/* ── activate, smoke, retire, receipt ────────────────────────────────── */

static bool prr_activate(struct prr *run)
{
    if (!prr_write_route(run, true)) {
        prr_fail(run, "RENEW_ACTIVATE_FAILED", "route", "the hub receiver route for epoch N+1 failed validation or could not be written");
        return false;
    }
    if (!prr_env_switch(run)) {
        prr_fail(run, "RENEW_ACTIVATE_FAILED", "unit_env", "the hub unit environment could not be switched to epoch N+1");
        return false;
    }
    return true;
}

static bool prr_smoke(struct prr *run)
{
    struct pair_smoke_in in = {.client_profile = run->cprof, .hub_profile = run->hprof, .target_port = run->st->cur.target_port,
                               .budget_ms = PRR_SMOKE_MS, .corrupt = run->cfg->fault};
    memcpy(in.client_key, run->c_pk, 32); memcpy(in.hub_key, run->h_pk, 32);
    memcpy(in.client_root, run->c_root, 32); memcpy(in.hub_root, run->h_root, 32);
    pair_smoke_run(&in, &run->smoke);
    if (!run->smoke.passed) {
        LOG_ERROR(PRR_TAG, "smoke failed: %s", run->smoke.reason);
        prr_fail(run, "RENEW_SMOKE_FAILED", "smoke", "epoch N+1 did not carry the target banner through the tunnel; epoch N stays in force");
    }
    return run->smoke.passed;
}

static bool prr_retire(struct prr *run)
{
    enum prr_revoke client = prr_revoke_side(run->st->cur.profile, run->st->cur.peer_key);
    enum prr_revoke hub = prr_revoke_side(run->st->hub_profile, run->st->client_key);
    run->retired_client = client != PRR_FAILED;
    run->retired_hub = hub != PRR_FAILED;
    return run->retired_client && run->retired_hub;
}

static void prr_receipt(struct prr *run, char name[96], char digest_hex[65])
{
    struct authority_receipt_header header = {0};
    struct sha3_256_ctx ctx;
    char final_path[PAIR_PATH_MAX + 96], epoch[32];
    snprintf(name, 96, "renew-%s-%s-e%u.receipt", run->st->cur.client, run->cfg->peer, (unsigned)run->st->next);
    snprintf(header.schema, sizeof(header.schema), "z23.device.pair.renew.v1");
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)run->cred, 64); sha3_256_write(&ctx, run->c_root, 32); sha3_256_write(&ctx, run->h_root, 32);
    sha3_256_finalize(&ctx, header.artifact_digest);
    snprintf(epoch, sizeof(epoch), "%u->%u", (unsigned)run->st->cur.epoch, (unsigned)run->st->next);
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)run->route_id, strlen(run->route_id)); sha3_256_write(&ctx, (const unsigned char *)epoch, strlen(epoch));
    sha3_256_finalize(&ctx, header.context_anchor);
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)run->st->plan_id, 64); sha3_256_write(&ctx, run->st->cur.root, 32);
    sha3_256_write(&ctx, run->st->hub_root, 32); sha3_256_write(&ctx, (const unsigned char *)run->psk_fp, 16);
    sha3_256_finalize(&ctx, header.detail_digest);
    digest_hex[0] = 0;
    if (authority_receipt_header_seal_and_write(&header, run->cfg->state, name, final_path, sizeof(final_path)))
        zcl_hex_encode(header.receipt_digest, 32, digest_hex);
    else name[0] = 0;
}

static void prr_emit(struct prr *run, bool retired)
{
    char receipt[96], digest[65], cred[65];
    prr_receipt(run, receipt, digest);
    snprintf(cred, sizeof(cred), "%s", run->cred);
    json_set_object(&run->reply->data);
    run->reply->error.mutated = true;
    bool ok = json_push_kv_str(&run->reply->data, "schema", "zcl.device.pair.renew.v1") && json_push_kv_bool(&run->reply->data, "committed", true) &&
              json_push_kv_int(&run->reply->data, "epoch", run->st->next) && json_push_kv_int(&run->reply->data, "previous_epoch", run->st->cur.epoch) &&
              json_push_kv_str(&run->reply->data, "route_id", run->route_id) && json_push_kv_str(&run->reply->data, "credential_id", cred) &&
              json_push_kv_str(&run->reply->data, "psk_fingerprint", run->psk_fp) && json_push_kv_int(&run->reply->data, "expires_at", (int64_t)run->expires) &&
              json_push_kv_bool(&run->reply->data, "smoke_passed", true) && json_push_kv_int(&run->reply->data, "smoke_listen_port", run->smoke.listen_port) &&
              json_push_kv_bool(&run->reply->data, "previous_retired", retired) && json_push_kv_str(&run->reply->data, "receipt", receipt) &&
              json_push_kv_str(&run->reply->data, "receipt_digest", digest);
    if (!ok) pr_fail(run->reply, "RENEW_SERIALIZE_FAILED", "emit", "epoch N+1 is in force but its result did not fit the bounded reply", true);
}

void pair_renew_execute(const struct pr_cfg *cfg, const struct pr_state *state, struct zcl_command_reply *reply)
{
    struct prr run;
    memset(&run, 0, sizeof(run));
    run.cfg = cfg; run.st = state; run.reply = reply;
    prr_paths(&run);
    if (!prr_pair(&run) || !prr_activate(&run) || !prr_smoke(&run)) return;
    if (!prr_write_route(&run, false)) {
        prr_fail(&run, "RENEW_ACTIVATE_FAILED", "client_route", "the client route for epoch N+1 failed validation or could not be written");
        return;
    }
    bool retired = prr_retire(&run);
    prr_emit(&run, retired);
    if (!retired && run.reply->status == ZCL_COMMAND_STATUS_PASSED)
        pr_fail(run.reply, "RENEW_RETIRE_INCOMPLETE", "retire", "epoch N+1 is in force and smoked, but epoch N could not be revoked on every side; revoke it with ops mesh device revoke", true);
}
