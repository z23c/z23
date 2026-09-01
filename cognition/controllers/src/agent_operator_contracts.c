/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Small nested contracts used by zcl.public_status. Keeping them here
 * avoids turning the first-call agent summary into a catch-all formatting file.
 */

#include "controllers/agent_operator_contracts.h"

#include "event_agent_readiness.h"        /* agent_tip_follow */
#include "event_agent_summary_internal.h" /* agent_trust_tier_snapshot */

#include "controllers/agent_security_posture.h"
#include "json/json.h"
#include "services/legacy_mirror_sync_service.h"
#include "storage/body_history.h"
#include "util/boot_phase.h"

#include <string.h>

static bool agent_mirror_operator_action_required(
    const struct legacy_mirror_sync_stats *mirror)
{
    if (!mirror)
        return false;
    return legacy_mirror_sync_blocker_is_active(mirror) &&
           legacy_mirror_sync_blocker_should_surface(mirror, false);
}

static bool agent_operator_latch_is_mirror_disagreement(const char *detail)
{
    if (!detail || !detail[0])
        return false;
    return strstr(detail, "chain_advance_hash-disagreement") ||
           strstr(detail, "hash-disagreement") ||
           strstr(detail, "mirror.divergence_located");
}

bool agent_operator_latch_suppressed_by_mirror(
    bool active,
    const char *detail,
    const struct legacy_mirror_sync_stats *mirror)
{
    return active && mirror && mirror->enabled &&
           agent_operator_latch_is_mirror_disagreement(detail) &&
           !agent_mirror_operator_action_required(mirror);
}

void agent_push_operator_latch_contract_json(
    struct json_value *out,
    const struct agent_operator_latch_contract_view *view)
{
    if (!out || !view)
        return;

    struct json_value obj = {0};
    json_set_object(&obj);
    json_push_kv_str(&obj, "schema", "zcl.operator_latch.v2");
    json_push_kv_int(&obj, "schema_version", 2);
    json_push_kv_bool(&obj, "active", view->active);
    json_push_kv_bool(&obj, "operator_action_required",
                      view->operator_action_required);
    json_push_kv_bool(&obj, "recovered_this_call",
                      view->recovered_this_call);
    json_push_kv_bool(&obj, "suppressed_by_mirror_contract",
                      view->suppressed_by_mirror_contract);
    json_push_kv_int(&obj, "since_unix", view->since_unix);
    json_push_kv_str(&obj, "detail", view->detail);
    json_push_kv_str(&obj, "native_state_command",
                     "z23 dumpstate condition_engine");
    json_push_kv_str(&obj, "semantics",
                     "active means EV_OPERATOR_NEEDED is latched; mirror "
                     "classification is advisory and never clears the "
                     "operator-action requirement on an observation path");
    json_push_kv(out, "operator_latch", &obj);
    json_free(&obj);
}

void agent_push_condition_summary_contract_json(
    struct json_value *out,
    const struct agent_condition_summary_contract_view *view)
{
    if (!out || !view)
        return;

    struct json_value obj = {0};
    json_set_object(&obj);
    json_push_kv_str(&obj, "schema", "zcl.condition_engine_summary.v2");
    json_push_kv_int(&obj, "schema_version", 2);
    json_push_kv_int(&obj, "active_count", view->active_count);
    json_push_kv_int(&obj, "unresolved_count", view->unresolved_count);
    json_push_kv_int(&obj, "unresolved_critical_count",
                     view->unresolved_critical_count);
    json_push_kv_str(&obj, "native_state_command",
                     "z23 dumpstate condition_engine");
    json_push_kv_str(&obj, "semantics",
                     "summary only; use native_state_command for the registered "
                     "condition list, attempts, thresholds, and detail");
    json_push_kv(out, "conditions", &obj);
    json_free(&obj);
}

const char *status_archive_completeness_name(enum status_archive_completeness c)
{
    switch (c) {
    case STATUS_ARCHIVE_INCOMPLETE:
        return "incomplete";
    case STATUS_ARCHIVE_COMPLETE:
        return "complete";
    case STATUS_ARCHIVE_UNKNOWN:
    default:
        return "unknown";
    }
}

/* Map the storage layer's body-history census verdict onto the status
 * tri-state. body_history_status_now() is already fail-closed: a node that
 * never ran a census, or whose census could not decide, returns UNKNOWN —
 * so `unknown` here is a real reachable value carrying a real read, never a
 * default papering over a failure. */
static enum status_archive_completeness status_archive_from_body_history(void)
{
    switch (body_history_status_now()) {
    case BODY_HISTORY_COMPLETE:
        return STATUS_ARCHIVE_COMPLETE;
    case BODY_HISTORY_INCOMPLETE:
        return STATUS_ARCHIVE_INCOMPLETE;
    case BODY_HISTORY_UNKNOWN:
    default:
        return STATUS_ARCHIVE_UNKNOWN;
    }
}

/* Wallet readability is a boot-stage fact: STAGE_WALLET_LOADED means the keys
 * were read and the canary self-test passed (BOOT_INVARIANTS.md). Viewing is
 * never gated on spend authority, so a keyless NO-SPEND node reaches this. The
 * shutdown stages are excluded — the wallet is being torn down there. */
static bool status_wallet_view_ready(void)
{
    enum boot_stage stage = boot_stage_current();
    return stage >= BOOT_STAGE_WALLET_LOADED &&
           stage < BOOT_STAGE_SHUTDOWN_REQUESTED;
}

void status_readiness_facts_collect(int tip_gap, int log_head_gap,
                                    const struct agent_security_posture *posture,
                                    struct status_readiness_facts_view *out)
{
    struct agent_trust_tier_snapshot tier;

    if (!out)
        return;
    *out = (struct status_readiness_facts_view){0};

    /* Keeping up with the tip: the ONE definition already used by
     * chain_serving_ready() — proven height vs network tip, no FSM flag and
     * no archive term. */
    out->tip_follow = agent_tip_follow(tip_gap, log_head_gap);

    out->wallet_view_ready = status_wallet_view_ready();

    /* Spend authority: the trust-tier collector already folds the sovereignty
     * guard's wallet_spend decision into one bit, TTL-cached and trylock-only
     * so a busy node.db cannot block this status path. */
    agent_summary_trust_tier_collect_bounded(&tier);
    out->wallet_spend_allowed = !tier.wallet_spend_denied;

    /* INDEPENDENT of tip_follow by design — see the header. */
    out->archive_complete = status_archive_from_body_history();

    out->full_replay_verified =
        posture && posture->full_history_validation_complete;
}

void status_push_readiness_facts_json(
    struct json_value *out, const struct status_readiness_facts_view *view)
{
    if (!out || !view)
        return;
    json_push_kv_bool(out, "tip_follow", view->tip_follow);
    json_push_kv_bool(out, "wallet_view_ready", view->wallet_view_ready);
    json_push_kv_bool(out, "wallet_spend_allowed", view->wallet_spend_allowed);
    json_push_kv_str(out, "archive_complete",
                     status_archive_completeness_name(view->archive_complete));
    json_push_kv_bool(out, "full_replay_verified", view->full_replay_verified);
}
