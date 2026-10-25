/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Pure decision core for shadow-safe vault intent planning. */
// one-result-type-ok:pure-total-decision-no-effect-or-fallible-service-surface
/* ZCL_REFLEX_BENCH: 00000000 */
#include "services/vault_intent_decision_service.h"

#include "core/amount.h"
#include "hotswap/hotswap_service.h"

#include <limits.h>
#include <string.h>

static bool vault_intent_amounts_invalid(
    const struct vault_intent_plan_snapshot *snapshot)
{
    return !MoneyRange(snapshot->target_zat) ||
        !MoneyRange(snapshot->fee_zat) ||
        snapshot->target_zat > MAX_MONEY - snapshot->fee_zat;
}

static bool vault_intent_money_state_not_current(
    const struct vault_intent_plan_snapshot *snapshot)
{
    return !snapshot->money_result_ok || !snapshot->money_complete ||
        !snapshot->money_current;
}

static bool vault_intent_reservations_invalid(
    const struct vault_intent_plan_snapshot *snapshot)
{
    return snapshot->confirmed_zat < 0 ||
        snapshot->already_reserved_zat < 0 ||
        snapshot->already_reserved_zat > snapshot->confirmed_zat;
}

static enum vault_intent_decision_code vault_intent_funds_denial_code(
    const struct vault_intent_plan_snapshot *snapshot)
{
    return snapshot->development_scope
        ? VAULT_INTENT_DECISION_DEVELOPMENT_CAP
        : VAULT_INTENT_DECISION_INSUFFICIENT_FUNDS;
}

static bool vault_intent_development_agent_cap_exceeded(
    const struct vault_intent_plan_snapshot *snapshot,
    const struct vault_intent_plan_decision *decision)
{
    return snapshot->development_scope &&
        (snapshot->agent_available_zat < 0 ||
         decision->reservation_zat > snapshot->agent_available_zat);
}

bool vault_intent_plan_decide(
    const struct vault_intent_plan_snapshot *snapshot,
    struct vault_intent_plan_decision *decision)
{
    if (!snapshot || !decision)
        return false;
    memset(decision, 0, sizeof(*decision));
    if (vault_intent_amounts_invalid(snapshot)) {
        decision->code = VAULT_INTENT_DECISION_FEE_INVALID;
        return true;
    }
    decision->reservation_zat = snapshot->target_zat + snapshot->fee_zat;
    if (vault_intent_money_state_not_current(snapshot)) {
        decision->code = VAULT_INTENT_DECISION_MONEY_NOT_CURRENT;
        return true;
    }
    if (vault_intent_reservations_invalid(snapshot)) {
        decision->code = vault_intent_funds_denial_code(snapshot);
        return true;
    }
    decision->spendable_after_reservations_zat =
        snapshot->confirmed_zat - snapshot->already_reserved_zat;
    if (vault_intent_development_agent_cap_exceeded(snapshot, decision)) {
        decision->code = VAULT_INTENT_DECISION_DEVELOPMENT_CAP;
        return true;
    }
    if (decision->reservation_zat >
        decision->spendable_after_reservations_zat) {
        decision->code = vault_intent_funds_denial_code(snapshot);
        return true;
    }
    decision->code = VAULT_INTENT_DECISION_ALLOW;
    return true;
}

const char *vault_intent_decision_code_name(
    enum vault_intent_decision_code code)
{
    switch (code) {
    case VAULT_INTENT_DECISION_ALLOW:
        return "ALLOW";
    case VAULT_INTENT_DECISION_MONEY_NOT_CURRENT:
        return "MONEY_STATE_NOT_CURRENT";
    case VAULT_INTENT_DECISION_FEE_INVALID:
        return "FEE_INVALID";
    case VAULT_INTENT_DECISION_DEVELOPMENT_CAP:
        return "DEVELOPMENT_RESERVE_OR_LAB_CAP";
    case VAULT_INTENT_DECISION_INSUFFICIENT_FUNDS:
        return "INSUFFICIENT_CONFIRMED_FUNDS";
    }
    return "INVALID_DECISION";
}

static const struct vault_intent_decision_service_v1 k_builtin = {
    .decide = vault_intent_plan_decide,
    .code_name = vault_intent_decision_code_name,
};

ZCL_HOTSWAP_SERVICE_EXPORT(
    VAULT_INTENT_DECISION_SERVICE_ID, k_builtin,
    VAULT_INTENT_DECISION_ABI, VAULT_INTENT_DECISION_SCHEMA,
    VAULT_INTENT_DECISION_WIRE, VAULT_INTENT_DECISION_KAT)

const struct vault_intent_decision_service_v1 *
vault_intent_decision_service_builtin(void)
{
    return &k_builtin;
}
