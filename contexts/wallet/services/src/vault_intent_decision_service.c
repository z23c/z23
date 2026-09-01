/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Pure decision core for shadow-safe vault intent planning. */
// one-result-type-ok:pure-total-decision-no-effect-or-fallible-service-surface
/* ZCL_REFLEX_BENCH: 00000000 */
#include "services/vault_intent_decision_service.h"

#include "hotswap/hotswap_service.h"

#include <limits.h>
#include <string.h>

bool vault_intent_plan_decide(
    const struct vault_intent_plan_snapshot *snapshot,
    struct vault_intent_plan_decision *decision)
{
    if (!snapshot || !decision)
        return false;
    memset(decision, 0, sizeof(*decision));
    if (snapshot->target_zat < 0 || snapshot->fee_zat < 0 ||
        snapshot->target_zat > INT64_MAX - snapshot->fee_zat) {
        decision->code = VAULT_INTENT_DECISION_FEE_INVALID;
        return true;
    }
    decision->reservation_zat = snapshot->target_zat + snapshot->fee_zat;
    if (!snapshot->money_result_ok || !snapshot->money_complete ||
        !snapshot->money_current) {
        decision->code = VAULT_INTENT_DECISION_MONEY_NOT_CURRENT;
        return true;
    }
    if (snapshot->confirmed_zat < 0 ||
        snapshot->already_reserved_zat < 0 ||
        snapshot->already_reserved_zat > snapshot->confirmed_zat) {
        decision->code = snapshot->development_scope
            ? VAULT_INTENT_DECISION_DEVELOPMENT_CAP
            : VAULT_INTENT_DECISION_INSUFFICIENT_FUNDS;
        return true;
    }
    decision->spendable_after_reservations_zat =
        snapshot->confirmed_zat - snapshot->already_reserved_zat;
    if (snapshot->development_scope &&
        (snapshot->agent_available_zat < 0 ||
         decision->reservation_zat > snapshot->agent_available_zat)) {
        decision->code = VAULT_INTENT_DECISION_DEVELOPMENT_CAP;
        return true;
    }
    if (decision->reservation_zat >
        decision->spendable_after_reservations_zat) {
        decision->code = snapshot->development_scope
            ? VAULT_INTENT_DECISION_DEVELOPMENT_CAP
            : VAULT_INTENT_DECISION_INSUFFICIENT_FUNDS;
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
