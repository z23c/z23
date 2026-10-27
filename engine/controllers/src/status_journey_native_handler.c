/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The root `z23 status` money-journey front door.  It composes existing
 * authorities and adds no wallet arithmetic: chain facts come from the lean
 * public status, money and reservations come from wallet_money_service via
 * agentsession custody_current, key/prover posture comes from getwalletinfo,
 * backup posture from walletbackupstatus, and mempool size from
 * getmempoolinfo.  The result is deliberately flat and contains no wallet
 * identity, address, path, key, memo, cookie, grant, or raw error text.
 */

#include "controllers/status_native_handlers.h"

#include "controllers/rpc_client.h"
#include "controllers/operator_needed_policy.h"
#include "controllers/status_native_helpers.h"
#include "json/json.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define JOURNEY_RPC_CONNECT_MS 75L
#define JOURNEY_RPC_TOTAL_MS   300L

enum journey_reason {
    JOURNEY_READY = 0,
    JOURNEY_STATUS_SOURCE_UNAVAILABLE,
    JOURNEY_NODE_TYPED_BLOCKER,
    JOURNEY_NODE_NOT_READY,
    JOURNEY_WALLET_PERSISTENCE_UNHEALTHY,
    JOURNEY_CUSTODY_SNAPSHOT_NOT_CURRENT,
    JOURNEY_WALLET_PLAINTEXT,
    JOURNEY_ENCRYPTED_BACKUP_REQUIRED,
    JOURNEY_WALLET_SPEND_POLICY_BLOCKED,
    JOURNEY_WALLET_LOCKED,
    JOURNEY_NO_SPENDABLE_BALANCE,
    JOURNEY_SAPLING_PROVER_NOT_READY,
    JOURNEY_SAPLING_CHECKPOINT_UNHEALTHY,
    JOURNEY_SAPLING_WITNESS_NOT_READY,
    JOURNEY_MEMPOOL_STATUS_UNAVAILABLE,
    JOURNEY_REASON_COUNT
};

struct journey_reason_row {
    const char *error_code;
    const char *current_state;
    const char *next_action;
    bool retryable;
    enum node_status_reason node_reason;
};

/* Journey-specific recovery stays here, while the shared node-status policy
 * remains the sole authority for operator status, explanation, and whether a
 * human must act.  There is no second verdict ladder. */
static const struct journey_reason_row g_journey_reasons[] = { /* hotswap-static-ok: leaf registration tables are immutable */    [JOURNEY_READY] = {
        "NONE", "READY", "z23 vault intent plan", false,
        ZCL_STATUS_REASON_NONE },
    [JOURNEY_STATUS_SOURCE_UNAVAILABLE] = {
        "STATUS_SOURCE_UNAVAILABLE", "CHAIN_READINESS_UNKNOWN",
        "z23 core status brief", true,
        ZCL_STATUS_REASON_HEALTHCHECK_UNHEALTHY },
    [JOURNEY_NODE_TYPED_BLOCKER] = {
        "NODE_TYPED_BLOCKER", "NODE_BLOCKED", "z23 core sync blockers",
        false, ZCL_STATUS_REASON_TYPED_BLOCKER },
    [JOURNEY_NODE_NOT_READY] = {
        "NODE_NOT_READY", "NODE_BLOCKED", "z23 core sync diagnose", true,
        ZCL_STATUS_REASON_HEALTHCHECK_UNHEALTHY },
    [JOURNEY_WALLET_PERSISTENCE_UNHEALTHY] = {
        "WALLET_PERSISTENCE_UNHEALTHY", "WALLET_NOT_READY",
        "z23 core wallet status", false, ZCL_STATUS_REASON_HEALTH_BLOCKER },
    [JOURNEY_CUSTODY_SNAPSHOT_NOT_CURRENT] = {
        "CUSTODY_SNAPSHOT_NOT_CURRENT", "MONEY_NOT_CURRENT",
        "z23 vault list", true, ZCL_STATUS_REASON_PROJECTION_LAG },
    [JOURNEY_WALLET_PLAINTEXT] = {
        "WALLET_PLAINTEXT", "ENCRYPTION_REQUIRED",
        "z23 core wallet security encrypt --input=-", false,
        ZCL_STATUS_REASON_POSTURE_REVIEW },
    [JOURNEY_ENCRYPTED_BACKUP_REQUIRED] = {
        "ENCRYPTED_BACKUP_REQUIRED", "BACKUP_NOT_READY",
        "z23 core wallet backup now", false,
        ZCL_STATUS_REASON_POSTURE_REVIEW },
    [JOURNEY_WALLET_SPEND_POLICY_BLOCKED] = {
        "WALLET_SPEND_POLICY_BLOCKED", "SPEND_NOT_ALLOWED",
        "z23 core sync blockers", false, ZCL_STATUS_REASON_TYPED_BLOCKER },
    [JOURNEY_WALLET_LOCKED] = {
        "WALLET_LOCKED", "UNLOCK_REQUIRED",
        "z23 core wallet security unlock --input=-", false,
        ZCL_STATUS_REASON_POSTURE_REVIEW },
    [JOURNEY_NO_SPENDABLE_BALANCE] = {
        "NO_SPENDABLE_BALANCE", "READY_TO_RECEIVE",
        "z23 core wallet address new", false, ZCL_STATUS_REASON_NONE },
    [JOURNEY_SAPLING_PROVER_NOT_READY] = {
        "SAPLING_PROVER_NOT_READY", "SHIELDED_SPEND_BLOCKED",
        "z23 vault intent plan", false, ZCL_STATUS_REASON_HEALTH_BLOCKER },
    [JOURNEY_SAPLING_CHECKPOINT_UNHEALTHY] = {
        "SAPLING_CHECKPOINT_UNHEALTHY", "SHIELDED_SPEND_BLOCKED",
        "z23 vault intent plan", false, ZCL_STATUS_REASON_HEALTH_BLOCKER },
    [JOURNEY_SAPLING_WITNESS_NOT_READY] = {
        "WITNESS_RESCAN_REQUIRED", "SHIELDED_WITNESS_NOT_READY",
        "z23 core wallet rescan-witnesses", true,
        ZCL_STATUS_REASON_PROJECTION_LAG },
    [JOURNEY_MEMPOOL_STATUS_UNAVAILABLE] = {
        "MEMPOOL_STATUS_UNAVAILABLE", "NETWORK_ACCEPTANCE_UNKNOWN",
        "z23 core chain mempool status", true,
        ZCL_STATUS_REASON_HEALTHCHECK_UNHEALTHY },
};

_Static_assert(sizeof(g_journey_reasons) / sizeof(g_journey_reasons[0]) ==
                   JOURNEY_REASON_COUNT,
               "status journey reason table is incomplete");

/* Typed blockers are inspected, not repaired, by the first agent command.
 * Snapshot is a composite diagnostic; it is not the first action, and it is
 * never a permission to mutate a live datadir. review_required_* posture
 * names stay owner-reviewed. */
static const char *journey_typed_blocker_next_action(const char *blocker)
{
    (void)blocker;
    return "z23 core sync blockers";
}

static bool journey_owner_review_required(const char *blocker)
{
    return blocker &&
           strncmp(blocker, "review_required_",
                   sizeof("review_required_") - 1) == 0;
}

static bool journey_obj(struct json_value *out, const char *raw)
{
    return status_parse_rpc_json(out, raw, JSON_OBJ);
}

static bool journey_bool(const struct json_value *obj, const char *key,
                         bool *out)
{
    const struct json_value *v = obj ? json_get(obj, key) : NULL;
    if (!v || v->type != JSON_BOOL)
        return false;
    *out = json_get_bool(v);
    return true;
}

static bool journey_nonnegative(const struct json_value *obj, const char *key,
                                int64_t *out)
{
    const struct json_value *v = obj ? json_get(obj, key) : NULL;
    if (!v || v->type != JSON_INT || json_get_int(v) < 0)
        return false;
    *out = json_get_int(v);
    return true;
}

static bool journey_is_obj(const struct json_value *v)
{
    return v && v->type == JSON_OBJ;
}

/* Every fact the journey verdict and rendering read, parsed once from the
 * five status sources. String facts point into the parsed JSON, which
 * outlives the rendering. */
struct journey_facts {
    bool chain_fields, healthy, synced, tip_follow, wallet_view;
    bool wallet_spend_allowed;
    int64_t hstar, header, gap, peers;
    const char *sync_state, *primary_blocker;
    bool wallet_fields, persistence_healthy, encrypted, unlocked;
    bool prover_ready, checkpoint_healthy, witness_ready;
    const char *witness_state;
    bool backup_fields, backup_healthy, encrypted_backup;
    bool mempool_fields;
    int64_t mempool_size;
    bool money_fields, money_complete, money_current;
    const char *money_status;
    int64_t confirmed, transparent, shielded, pending, encumbered, reserved;
    int64_t sendable;
    bool wallet_ready, receive_base;
    bool can_send_transparent, can_send_sapling, can_send;
};

static void journey_read_chain(struct journey_facts *f,
                               const struct json_value *brief, bool brief_ok)
{
    f->chain_fields = brief_ok &&
        journey_nonnegative(brief, "hstar", &f->hstar) &&
        journey_nonnegative(brief, "header_height", &f->header) &&
        journey_nonnegative(brief, "gap", &f->gap) &&
        journey_nonnegative(brief, "peer_count", &f->peers) &&
        journey_bool(brief, "healthy", &f->healthy) &&
        journey_bool(brief, "tip_follow", &f->tip_follow) &&
        journey_bool(brief, "wallet_view_ready", &f->wallet_view) &&
        journey_bool(brief, "wallet_spend_allowed",
                     &f->wallet_spend_allowed);
    f->sync_state = brief_ok
        ? json_get_str(json_get(brief, "sync_state")) : NULL;
    f->primary_blocker = brief_ok
        ? json_get_str(json_get(brief, "primary_blocker")) : NULL;
    /* Payment readiness follows the authoritative served frontier, not the
     * background archive FSM.  A node may keep fetching historical bodies
     * in blocks_download while H* has zero network gap and tip_follow=true. */
    f->synced = f->chain_fields && f->gap == 0 && f->tip_follow;
}

static void journey_read_wallet(struct journey_facts *f,
                                const struct json_value *wallet,
                                bool wallet_ok)
{
    const struct json_value *persistence = wallet_ok
        ? json_get(wallet, "persistence") : NULL;
    const struct json_value *lock = wallet_ok
        ? json_get(wallet, "lock") : NULL;
    const struct json_value *sapling = wallet_ok
        ? json_get(wallet, "sapling") : NULL;
    f->witness_state = journey_is_obj(sapling)
        ? json_get_str(json_get(sapling, "witness_state")) : NULL;
    f->wallet_fields = journey_is_obj(persistence) && journey_is_obj(lock) &&
        journey_is_obj(sapling) &&
        journey_bool(persistence, "healthy", &f->persistence_healthy) &&
        journey_bool(lock, "encrypted_at_rest", &f->encrypted) &&
        journey_bool(lock, "unlocked", &f->unlocked) &&
        journey_bool(sapling, "prover_ready", &f->prover_ready) &&
        journey_bool(sapling, "checkpoint_healthy",
                     &f->checkpoint_healthy) &&
        journey_bool(sapling, "witness_ready", &f->witness_ready) &&
        f->witness_state;
}

static void journey_read_money(struct journey_facts *f,
                               const struct json_value *money, bool money_ok)
{
    const struct json_value *snapshot = money_ok &&
        json_get_bool(json_get(money, "ok"))
        ? json_get(money, "snapshot") : NULL;
    f->money_status = journey_is_obj(snapshot)
        ? json_get_str(json_get(snapshot, "status")) : NULL;
    f->money_fields = journey_is_obj(snapshot) &&
        journey_bool(snapshot, "complete", &f->money_complete) &&
        journey_nonnegative(snapshot, "confirmed_zat", &f->confirmed) &&
        journey_nonnegative(snapshot, "transparent_spendable_zat",
                            &f->transparent) &&
        journey_nonnegative(snapshot, "shielded_spendable_zat",
                            &f->shielded) &&
        journey_nonnegative(snapshot, "pending_zat", &f->pending) &&
        journey_nonnegative(snapshot, "encumbered_zat", &f->encumbered) &&
        journey_nonnegative(snapshot, "intent_reserved_zat", &f->reserved) &&
        journey_nonnegative(snapshot, "agent_available_zat", &f->sendable);
    f->money_current = f->money_fields && f->money_complete &&
                       f->money_status &&
                       strcmp(f->money_status, "CURRENT") == 0;
}

static void journey_derive_ready(struct journey_facts *f)
{
    bool custody_readable = f->wallet_fields && f->persistence_healthy &&
                            f->money_current;
    f->wallet_ready = custody_readable && f->encrypted && f->backup_fields &&
                      f->backup_healthy && f->encrypted_backup;
    f->receive_base = f->chain_fields && f->healthy && f->synced &&
                      f->wallet_view && f->wallet_ready;
}

static void journey_derive_send(struct journey_facts *f)
{
    bool spend_base = f->receive_base && f->wallet_spend_allowed &&
                      f->unlocked && f->sendable > 0;
    f->can_send_transparent = spend_base && f->transparent > 0;
    f->can_send_sapling = spend_base && f->shielded > 0 && f->prover_ready &&
                          f->checkpoint_healthy && f->witness_ready;
    f->can_send = f->can_send_transparent || f->can_send_sapling;
}

/* The reason ladders below run node, then wallet, then spend readiness; the
 * first that names a reason wins and JOURNEY_READY means none did. */
static enum journey_reason journey_reason_node(const struct journey_facts *f)
{
    if (!f->chain_fields)
        return JOURNEY_STATUS_SOURCE_UNAVAILABLE;
    if (!f->healthy || !f->synced)
        return f->primary_blocker && strcmp(f->primary_blocker, "none") != 0
            ? JOURNEY_NODE_TYPED_BLOCKER : JOURNEY_NODE_NOT_READY;
    return JOURNEY_READY;
}

static enum journey_reason journey_reason_wallet(const struct journey_facts *f)
{
    if (!f->wallet_fields || !f->persistence_healthy)
        return JOURNEY_WALLET_PERSISTENCE_UNHEALTHY;
    if (!f->money_current)
        return JOURNEY_CUSTODY_SNAPSHOT_NOT_CURRENT;
    if (!f->encrypted)
        return JOURNEY_WALLET_PLAINTEXT;
    if (!f->backup_fields || !f->backup_healthy || !f->encrypted_backup)
        return JOURNEY_ENCRYPTED_BACKUP_REQUIRED;
    if (!f->wallet_spend_allowed)
        return JOURNEY_WALLET_SPEND_POLICY_BLOCKED;
    if (!f->unlocked)
        return JOURNEY_WALLET_LOCKED;
    return JOURNEY_READY;
}

static enum journey_reason journey_reason_spend(const struct journey_facts *f)
{
    if (f->sendable <= 0 || (f->transparent <= 0 && f->shielded <= 0))
        return JOURNEY_NO_SPENDABLE_BALANCE;
    if (f->shielded > 0 && f->transparent <= 0 &&
        (!f->prover_ready || !f->checkpoint_healthy))
        return !f->prover_ready ? JOURNEY_SAPLING_PROVER_NOT_READY
                                : JOURNEY_SAPLING_CHECKPOINT_UNHEALTHY;
    if (f->shielded > 0 && f->transparent <= 0 && !f->witness_ready)
        return JOURNEY_SAPLING_WITNESS_NOT_READY;
    if (!f->mempool_fields)
        return JOURNEY_MEMPOOL_STATUS_UNAVAILABLE;
    return JOURNEY_READY;
}

static enum journey_reason journey_reason_for(const struct journey_facts *f)
{
    enum journey_reason reason = journey_reason_node(f);
    if (reason == JOURNEY_READY)
        reason = journey_reason_wallet(f);
    if (reason == JOURNEY_READY)
        reason = journey_reason_spend(f);
    return reason;
}

static void journey_render_chain(struct json_value *out,
                                 const struct journey_facts *f)
{
    (void)json_push_kv_bool(out, "status_complete",
                            f->chain_fields && f->wallet_fields &&
                            f->backup_fields && f->money_fields &&
                            f->mempool_fields);
    (void)json_push_kv_bool(out, "node_healthy",
                            f->chain_fields && f->healthy);
    (void)json_push_kv_bool(out, "synced", f->synced);
    (void)json_push_kv_bool(out, "wallet_ready", f->wallet_ready);
    (void)json_push_kv_bool(out, "can_receive", f->receive_base);
    (void)json_push_kv_bool(out, "can_send", f->can_send);
    (void)json_push_kv_bool(out, "can_send_transparent",
                            f->can_send_transparent);
    (void)json_push_kv_bool(out, "can_send_sapling", f->can_send_sapling);
    status_push_int_if_known(out, "hstar", f->chain_fields, f->hstar);
    status_push_int_if_known(out, "header_height", f->chain_fields,
                             f->header);
    status_push_int_if_known(out, "gap", f->chain_fields, f->gap);
    status_push_int_if_known(out, "peer_count", f->chain_fields, f->peers);
    (void)json_push_kv_str(out, "sync_state",
                           f->sync_state ? f->sync_state : "unknown");
    (void)json_push_kv_str(out, "primary_blocker",
                           f->primary_blocker ? f->primary_blocker
                                              : "unknown");
}

static void journey_render_money(struct json_value *out,
                                 const struct journey_facts *f)
{
    status_push_int_if_known(out, "spendable_zat", f->money_fields,
                             f->sendable);
    status_push_int_if_known(out, "confirmed_zat", f->money_fields,
                             f->confirmed);
    status_push_int_if_known(out, "transparent_spendable_zat",
                             f->money_fields, f->transparent);
    status_push_int_if_known(out, "shielded_spendable_zat", f->money_fields,
                             f->shielded);
    status_push_int_if_known(out, "pending_zat", f->money_fields,
                             f->pending);
    status_push_int_if_known(out, "reserved_zat", f->money_fields,
                             f->reserved);
    status_push_int_if_known(out, "encumbered_zat", f->money_fields,
                             f->encumbered);
}

static void journey_render_wallet(struct json_value *out,
                                  const struct journey_facts *f)
{
    (void)json_push_kv_bool(out, "wallet_encrypted",
                            f->wallet_fields && f->encrypted);
    (void)json_push_kv_bool(out, "wallet_unlocked",
                            f->wallet_fields && f->unlocked);
    (void)json_push_kv_bool(out, "encrypted_backup_ready",
                            f->backup_fields && f->backup_healthy &&
                            f->encrypted_backup);
    (void)json_push_kv_bool(out, "sapling_prover_ready",
                            f->wallet_fields && f->prover_ready);
    (void)json_push_kv_bool(out, "sapling_checkpoint_healthy",
                            f->wallet_fields && f->checkpoint_healthy);
    (void)json_push_kv_bool(out, "sapling_witness_ready",
                            f->wallet_fields && f->witness_ready);
    (void)json_push_kv_str(out, "sapling_witness_state",
                           f->witness_state ? f->witness_state
                                            : "unavailable");
    if (f->mempool_fields)
        status_push_int_if_known(out, "mempool_transactions", true,
                                 f->mempool_size);
    else
        status_push_int_if_known(out, "mempool_transactions", false, 0);
}

static void journey_render_reason(struct json_value *out,
                                  const struct journey_facts *f,
                                  enum journey_reason reason)
{
    const struct journey_reason_row *reason_row = &g_journey_reasons[reason];
    (void)json_push_kv_str(out, "error_code", reason_row->error_code);
    (void)json_push_kv_str(out, "current_state",
                           reason == JOURNEY_CUSTODY_SNAPSHOT_NOT_CURRENT &&
                                   f->money_status
                               ? f->money_status : reason_row->current_state);
    (void)json_push_kv_str(
        out, "operator_status",
        node_status_reason_status(reason_row->node_reason));
    (void)json_push_kv_str(
        out, "summary", node_status_reason_summary(reason_row->node_reason));
    (void)json_push_kv_bool(out, "retryable", reason_row->retryable);
    (void)json_push_kv_bool(
        out, "human_action_required",
        node_status_reason_operator_needed(reason_row->node_reason, 0));
    const char *next = reason_row->next_action;
    bool owner_review = false;
    if (reason == JOURNEY_NODE_TYPED_BLOCKER) {
        next = journey_typed_blocker_next_action(f->primary_blocker);
        owner_review = journey_owner_review_required(f->primary_blocker);
    }
    (void)json_push_kv_str(out, "next_action", next);
    (void)json_push_kv_bool(out, "owner_review_required", owner_review);
}

char *zcl_native_status_journey_body(const struct json_value *args,
                                     struct zcl_native_body_err *err)
{
    (void)args;
    struct zcl_native_body_err brief_err = {0};
    char *brief_raw = zcl_native_status_brief_body(NULL, &brief_err);
    char *money_raw = node_rpc_call_deadline(
        "agentsession", "[\"custody_current\",{}]",
        JOURNEY_RPC_CONNECT_MS, JOURNEY_RPC_TOTAL_MS);
    char *wallet_raw = node_rpc_call_deadline(
        "getwalletinfo", NULL, JOURNEY_RPC_CONNECT_MS,
        JOURNEY_RPC_TOTAL_MS);
    char *backup_raw = node_rpc_call_deadline(
        "walletbackupstatus", NULL, JOURNEY_RPC_CONNECT_MS,
        JOURNEY_RPC_TOTAL_MS);
    char *mempool_raw = node_rpc_call_deadline(
        "getmempoolinfo", NULL, JOURNEY_RPC_CONNECT_MS,
        JOURNEY_RPC_TOTAL_MS);

    struct json_value brief, money, wallet, backup, mempool;
    bool brief_ok = brief_raw && journey_obj(&brief, brief_raw);
    bool money_ok = journey_obj(&money, money_raw);
    bool wallet_ok = journey_obj(&wallet, wallet_raw);
    bool backup_ok = journey_obj(&backup, backup_raw);
    bool mempool_ok = journey_obj(&mempool, mempool_raw);

    struct journey_facts f = {0};
    journey_read_chain(&f, &brief, brief_ok);
    journey_read_wallet(&f, &wallet, wallet_ok);
    f.backup_fields = backup_ok &&
        journey_bool(&backup, "healthy", &f.backup_healthy) &&
        journey_bool(&backup, "encrypted_backup_available",
                     &f.encrypted_backup);
    f.mempool_fields = mempool_ok &&
        journey_nonnegative(&mempool, "size", &f.mempool_size);
    journey_read_money(&f, &money, money_ok);
    journey_derive_ready(&f);
    journey_derive_send(&f);
    enum journey_reason reason = journey_reason_for(&f);

    struct json_value out;
    json_init(&out);
    json_set_object(&out);
    journey_render_chain(&out, &f);
    journey_render_money(&out, &f);
    journey_render_wallet(&out, &f);
    journey_render_reason(&out, &f, reason);

    char *body = zcl_json_value_to_body(&out, "status_journey_body");
    json_free(&out);
    if (brief_ok) json_free(&brief);
    if (money_ok) json_free(&money);
    if (wallet_ok) json_free(&wallet);
    if (backup_ok) json_free(&backup);
    if (mempool_ok) json_free(&mempool);
    free(brief_raw); free(money_raw); free(wallet_raw); free(backup_raw);
    free(mempool_raw);
    if (!body) {
        err->status = ZCL_NATIVE_BODY_INTERNAL;
        (void)snprintf(err->message, sizeof(err->message),
                       "could not serialize status journey");
        LOG_NULL("native.status", "could not serialize status journey");
    }
    return body;
}

/* ── Hot-swappable leaf ────────────────────────────────────────────────────
 * `status` is a bridged BODY leaf, not a direct handler: it returns rendered
 * JSON and the kernel's request/reply plumbing comes from
 * zcl_native_bridge_run, so it needs a trampoline.
 *
 * The body being IN THIS FILE is what makes the swap real. A body in another
 * translation unit binds to the resident node at dlopen and the swap reports
 * success while changing nothing. The matching limit:
 * zcl_native_status_journey_render lives in tools/command/native_command.c,
 * so edits to the TEXT rendering are outside this module. */
#if defined(ZCL_HOTSWAP_GEN) || defined(ZCL_HOTSWAP_MODULE_GEN)
#define ZCL_HOTSWAP_PROBE_LEAF "status"
#include "hotswap/hotswap_register.h"
#include "kernel/command_registry.h"
#include "command/native_command.h"
ZCL_HOTSWAP_TRAMPOLINE(tramp_status_journey, zcl_native_status_journey_body)
ZCL_HOTSWAP_LEAVES_BEGIN(status_journey)
ZCL_HOTSWAP_LEAF("status", tramp_status_journey)
ZCL_HOTSWAP_LEAVES_END(status_journey)
#endif
