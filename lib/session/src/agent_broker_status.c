/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * What the operator reads afterwards: `<dir>/broker.json`, written by the
 * broker and rendered back by `metaverse agent status`.
 *
 * The document reports what the confinement ACHIEVED, never what was asked for
 * — the child's uid posture as it actually landed, whether a Landlock domain
 * was really built, which seccomp install path ran — because a status surface
 * that echoes the request is a surface that cannot tell you it failed. The
 * grant itself is never rendered; only its fingerprint, so an operator can see
 * WHICH authority is live without the document becoming a copy of it.
 *
 * The broker no longer HOLDS a grant either (session/agent_broker.h, struct
 * agent_authority_ref), so this file asks the provider for a labelled status
 * snapshot when it writes. The four fields that decide whether the document
 * can be believed are always present: `authority_source` (where the authority
 * came from), `authority_persistence` (always "ephemeral" — this store dies
 * with the process), `canonical_grant_id`, and `live_authority` (whether every
 * decision re-reads the store rather than a copy).
 */

#include "session/agent_broker.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "json/json.h"
#include "platform/os_proc.h"
#include "platform/positioned_file.h"
#include "platform/private_file.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#define BROKER_TAG "agent.broker"

static _Atomic uint32_t g_broker_stage_seq;

static bool broker_sync_dir(const char *dir)
{
    return platform_private_parent_flush(dir);
}

static void broker_retire_document(const char *dir, const char *name)
{
    char path[512];
    if (!dir || !name)
        return;
    int n = snprintf(path, sizeof(path), "%s/%s", dir, name);
    if (n < 0 || (size_t)n >= sizeof(path))
        return;
    if (platform_private_path_absent(path))
        return;
    struct platform_private_file file;
    struct platform_private_file_identity identity;
    platform_private_file_init(&file);
    if (platform_private_file_open_locked(path, &file) &&
        platform_private_file_identity(&file, &identity) &&
        platform_private_file_retire_if_identity(&file, path, &identity)) {
        if (!broker_sync_dir(dir))
            LOG_WARN(BROKER_TAG, "cannot sync retirement of %s", path);
    } else {
        LOG_WARN(BROKER_TAG, "cannot retire %s: %s", path, strerror(errno));
    }
    platform_private_file_close(&file);
}

static bool broker_write_document(const char *dir, const char *name,
                                  const uint8_t *buf, size_t len)
{
    char path[512], tmp[512];
    int pn = snprintf(path, sizeof(path), "%s/%s", dir, name);
    int tn = snprintf(tmp, sizeof(tmp), "%s/.%s.%llu-%u.tmp", dir, name,
                      (unsigned long long)os_proc_current_pid(),
                      (unsigned)atomic_fetch_add(&g_broker_stage_seq, 1));
    if (pn < 0 || tn < 0 || (size_t)pn >= sizeof(path) ||
        (size_t)tn >= sizeof(tmp)) {
        broker_retire_document(dir, name);
        return false;
    }
    struct platform_private_file file;
    struct platform_private_file_identity identity;
    platform_private_file_init(&file);
    bool created = platform_private_file_create(tmp, &file);
    bool identified = created &&
                      platform_private_file_identity(&file, &identity);
    bool ok = identified &&
              platform_private_file_write_at(&file, buf, len, 0) &&
              platform_private_file_truncate(&file, len) &&
              platform_private_file_flush(&file) &&
              platform_private_file_replace(&file, tmp, path);
    if (ok && !broker_sync_dir(dir))
        ok = false;
    if (!ok) {
        if (identified)
            (void)platform_private_file_retire_if_identity(&file, tmp,
                                                           &identity);
        broker_retire_document(dir, name);
        LOG_WARN(BROKER_TAG, "cannot atomically persist %s", name);
    }
    platform_private_file_close(&file);
    return ok;
}

static void agent_broker_write_private_money_bindings(
    const char *dir, const struct agent_broker_session *s)
{
    const struct agent_authority_ref *a = s ? s->authority : NULL;
    if (!dir)
        return;
    if (!a || !a->bound || !a->provider ||
        !a->provider->money_bindings) {
        broker_retire_document(dir, "money-bindings.json");
        return;
    }
    struct agent_money_binding bindings[AGENT_MONEY_BINDINGS_MAX];
    size_t count = 0;
    memset(bindings, 0, sizeof(bindings));
    if (!a->provider->money_bindings(a->provider_ctx, bindings,
                                     AGENT_MONEY_BINDINGS_MAX, &count)) {
        LOG_WARN(BROKER_TAG, "custody binding provider failed");
        broker_retire_document(dir, "money-bindings.json");
        return;
    }
    struct json_value doc, wallets;
    json_init(&doc); json_set_object(&doc);
    json_init(&wallets); json_set_array(&wallets);
    (void)json_push_kv_str(&doc, "schema", "zcl.agent_money_bindings.v1");
    for (size_t i = 0; i < count; i++) {
        struct json_value w;
        json_init(&w); json_set_object(&w);
        (void)json_push_kv_str(&w, "scope", bindings[i].wallet_scope);
        (void)json_push_kv_str(&w, "wallet_instance_id",
                               bindings[i].wallet_instance_id);
        (void)json_push_kv_str(&w, "network_genesis",
                               bindings[i].network_genesis);
        (void)json_push_kv_str(&w, "node_datadir",
                               bindings[i].node_datadir);
        (void)json_push_kv_int(&w, "rpc_port", bindings[i].rpc_port);
        (void)json_push_back(&wallets, &w);
        json_free(&w);
    }
    (void)json_push_kv(&doc, "wallets", &wallets);
    json_free(&wallets);
    char buf[4096];
    size_t n = json_write(&doc, buf, sizeof(buf));
    json_free(&doc);
    /* json_write reports the WOULD-BE total; anything at or past the
     * buffer size means the buffer holds a truncated prefix. A truncated
     * custody document is not a smaller document — it is a different,
     * false one — so it never reaches the disk. */
    if (n == 0 || n >= sizeof(buf)) {
        LOG_WARN(BROKER_TAG, "private custody bindings did not fit (%zu)",
                 n);
        broker_retire_document(dir, "money-bindings.json");
        return;
    }
    (void)broker_write_document(dir, "money-bindings.json",
                                (const uint8_t *)buf, n);
}

/* ── status document ────────────────────────────────────────────────────── */

void agent_broker_write_status(const char *dir,
                               const struct agent_broker_session *s,
                               pid_t child_pid, const char *socket_path)
{
    if (!dir || !s)
        return;

    /* The endpoint-bearing document is separate and private. broker.json,
     * status, audit, and money output never contain these paths/ports. */
    agent_broker_write_private_money_bindings(dir, s);

    /* THE AUTHORITY SECTION IS PULLED, NOT REMEMBERED. The broker holds no
     * grant to render, so the four fields an operator needs — where the
     * authority came from, how durable it is, which canonical grant it is,
     * and whether decisions consult it live — are asked of the provider at
     * write time. A session that never bound reports ungranted, which is a
     * different document from a bound session with an empty grant. */
    const struct agent_authority_ref *a = s->authority;
    struct agent_authority_status auth;
    memset(&auth, 0, sizeof(auth));
    bool bound = a && a->bound && a->provider;
    bool have_status = false;
    if (bound && a->provider->status)
        have_status = a->provider->status(a->provider_ctx, a, &auth);
    if (bound && !have_status) {
        /* The provider named no status surface. Report what the binding
         * itself proves and nothing more. */
        snprintf(auth.authority_source, sizeof(auth.authority_source), "%s",
                 a->provider->name ? a->provider->name : "(unnamed provider)");
        snprintf(auth.canonical_grant_id, sizeof(auth.canonical_grant_id),
                 "%s", a->canonical_grant_id);
        snprintf(auth.principal, sizeof(auth.principal), "%s", a->principal);
        auth.live_authority = a->provider->authorize != NULL;
        auth.ephemeral = true;
    }
    char fphex[65];
    zcl_hex_encode(auth.fingerprint, 32, fphex);

    struct json_value doc;
    json_init(&doc);
    json_set_object(&doc);
    (void)json_push_kv_int(&doc, "broker_pid",
                           (int64_t)os_proc_current_pid());
    (void)json_push_kv_int(&doc, "agent_pid", (int64_t)child_pid);
    (void)socket_path; /* endpoint remains broker-private */
    (void)json_push_kv_bool(&doc, "granted", bound);
    (void)json_push_kv_str(&doc, "authority_source",
                           bound ? auth.authority_source : "none");
    /* Stated in every document, including an ungranted one: this store does
     * not survive a restart, so nothing here implies durable revocation or a
     * receipt anyone can verify after the process exits. */
    (void)json_push_kv_str(&doc, "authority_persistence", "ephemeral");
    (void)json_push_kv_str(&doc, "canonical_grant_id",
                           bound ? auth.canonical_grant_id : "");
    (void)json_push_kv_bool(&doc, "live_authority",
                            bound && auth.live_authority);
    (void)json_push_kv_str(&doc, "principal", bound ? auth.principal : "");
    (void)json_push_kv_str(&doc, "grant_fingerprint", bound ? fphex : "");
    (void)json_push_kv_bool(&doc, "grant_revoked", auth.revoked);
    (void)json_push_kv_int(&doc, "authority_generation",
                           (int64_t)auth.authority_generation);
    (void)json_push_kv_int(&doc, "budget_zats", (int64_t)auth.budget_zat);
    (void)json_push_kv_int(&doc, "spent_zats", (int64_t)auth.spent_zat);
    (void)json_push_kv_int(&doc, "grant_properties",
                           bound ? (int64_t)a->scope.n_properties : 0);
    (void)json_push_kv_int(&doc, "requests_served",
                           (int64_t)s->requests_served);
    (void)json_push_kv_int(&doc, "requests_denied",
                           (int64_t)s->requests_denied);
    (void)json_push_kv_int(&doc, "receipts_written",
                           (int64_t)s->receipts_written);
    /* Separate from `receipts_written` on purpose: a replay is a request the
     * broker answered from its idempotency ring, having executed nothing, so
     * counting it as a receipt would overstate the work done. A conflict is an
     * id the agent pointed at a second, different request. */
    (void)json_push_kv_int(&doc, "replays_served",
                           (int64_t)s->replays_served);
    (void)json_push_kv_int(&doc, "idempotency_conflicts",
                           (int64_t)s->idempotency_conflicts);
    (void)json_push_kv_int(&doc, "peer_pid", (int64_t)s->peer.pid);
    (void)json_push_kv_int(&doc, "peer_uid", (int64_t)s->peer.uid);
    (void)json_push_kv_int(&doc, "peer_gid", (int64_t)s->peer.gid);

    /* The ACHIEVED confinement, as the child reported it — never the
     * requested one. */
    const char *posture =
        s->child.uid_posture == AGENT_CONFINE_SEPARATE_UID ? "separate_uid"
        : s->child.uid_posture == AGENT_CONFINE_SAME_UID   ? "same_uid"
                                                           : "unknown";
    (void)json_push_kv_str(&doc, "agent_uid_posture", posture);
    (void)json_push_kv_int(&doc, "agent_uid", (int64_t)s->child.ran_as_uid);
    (void)json_push_kv_int(&doc, "agent_landlock_abi",
                           (int64_t)s->child.landlock_abi);
    (void)json_push_kv_bool(&doc, "agent_landlock_applied",
                            s->child.landlock_applied);
    (void)json_push_kv_bool(&doc, "agent_seccomp_applied",
                            s->child.seccomp_applied);
    (void)json_push_kv_bool(&doc, "agent_rlimits_applied",
                            s->child.rlimits_applied);
    (void)json_push_kv_int(&doc, "agent_fs_grants",
                           (int64_t)s->child.fs_grants);
    (void)json_push_kv_str(&doc, "agent_seccomp_method",
                           s->child.seccomp_method);

    char buf[4096];
    size_t n = json_write(&doc, buf, sizeof(buf));
    json_free(&doc);
    /* Same would-be-length contract as the custody writer: at or past the
     * buffer size the buffer holds a truncated prefix, and a truncated
     * status document parses as nothing. Refuse rather than write it. */
    if (n == 0 || n >= sizeof(buf)) {
        LOG_WARN(BROKER_TAG, "broker status did not fit (%zu)", n);
        broker_retire_document(dir, "broker.json");
        return;
    }
    (void)broker_write_document(dir, "broker.json", (const uint8_t *)buf, n);
}

size_t agent_broker_render_status_json(const char *dir, char *out,
                                       size_t out_cap)
{
    if (!dir || !out || out_cap == 0)
        return 0;
    char path[512];
    snprintf(path, sizeof(path), "%s/broker.json", dir);

    struct json_value doc;
    json_init(&doc);
    json_set_object(&doc);
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path)) {
        (void)json_push_kv_bool(&doc, "broker_state_present", false);
        (void)json_push_kv_str(&doc, "reason",
                               "no broker.json in this directory — no confined "
                               "agent broker has run here");
        size_t n = json_write(&doc, out, out_cap);
        json_free(&doc);
        return n;
    }
    char buf[4096];
    bool stable = platform_positioned_file_snapshot(&file, &before) &&
                  before.size < sizeof(buf);
    int64_t read_size = stable
                            ? platform_positioned_file_read(
                                  &file, buf, (size_t)before.size, 0)
                            : -1;
    stable = stable && read_size == (int64_t)before.size &&
             platform_positioned_file_snapshot(&file, &after) &&
             memcmp(&before, &after, sizeof(before)) == 0;
    platform_positioned_file_close(&file);
    size_t got = stable ? (size_t)read_size : 0;
    buf[got] = '\0';

    struct json_value state;
    json_init(&state);
    bool parsed = got > 0 && json_read(&state, buf, got);
    (void)json_push_kv_bool(&doc, "broker_state_present", parsed);
    if (parsed) {
        /* A recorded broker_pid that is no longer alive is reported as such
         * rather than implied by its presence. */
        int64_t bpid = json_get_int(json_get(&state, "broker_pid"));
        (void)json_push_kv_bool(
            &doc, "broker_running",
            bpid > 0 && os_proc_pid_liveness((uint64_t)bpid) ==
                            OS_PROC_LIVENESS_RUNNING);
        (void)json_push_kv(&doc, "state", &state);
    } else {
        (void)json_push_kv_str(&doc, "reason", "broker.json is not valid JSON");
    }
    json_free(&state);

    size_t n = json_write(&doc, out, out_cap);
    json_free(&doc);
    return n;
}
