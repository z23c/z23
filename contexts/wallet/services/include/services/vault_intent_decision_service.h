/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Frozen pure contract for transparent-intent admission decisions. */

#ifndef ZCL_VAULT_INTENT_DECISION_SERVICE_H
#define ZCL_VAULT_INTENT_DECISION_SERVICE_H

#include <stdbool.h>
#include <stdint.h>

#define VAULT_INTENT_DECISION_SERVICE_ID \
    "app.vault.intent.decision.v1"
#define VAULT_INTENT_DECISION_ABI \
    "app.vault.intent.decision.abi.v1:immutable-snapshot"
#define VAULT_INTENT_DECISION_SCHEMA \
    "zcl.vault_intent_decision_story.v1"
#define VAULT_INTENT_DECISION_WIRE \
    "vault-plan-snapshot+proposal-only.v1"
#define VAULT_INTENT_DECISION_KAT \
    "0fa5c1bb3a44554fcc56c759c8dd1ebbbe30af9f5f3762ee76ba843a0a6aa543"

enum vault_intent_decision_code {
    VAULT_INTENT_DECISION_ALLOW = 0,
    VAULT_INTENT_DECISION_MONEY_NOT_CURRENT,
    VAULT_INTENT_DECISION_FEE_INVALID,
    VAULT_INTENT_DECISION_DEVELOPMENT_CAP,
    VAULT_INTENT_DECISION_INSUFFICIENT_FUNDS,
};

/* A copied decision snapshot. It owns no wallet, database, network, reducer,
 * custody, supervisor, or deployment capability. */
struct vault_intent_plan_snapshot {
    bool money_result_ok;
    bool money_complete;
    bool money_current;
    bool development_scope;
    int64_t target_zat;
    int64_t fee_zat;
    int64_t confirmed_zat;
    int64_t already_reserved_zat;
    int64_t agent_available_zat;
};

/* A proposal only. The static controller remains the sole authority allowed
 * to reserve coins, persist a plan, sign, broadcast, or move value. */
struct vault_intent_plan_decision {
    enum vault_intent_decision_code code;
    int64_t reservation_zat;
    int64_t spendable_after_reservations_zat;
};

bool vault_intent_plan_decide(
    const struct vault_intent_plan_snapshot *snapshot,
    struct vault_intent_plan_decision *decision);
const char *vault_intent_decision_code_name(
    enum vault_intent_decision_code code);

struct vault_intent_decision_service_v1 {
    bool (*decide)(const struct vault_intent_plan_snapshot *snapshot,
                   struct vault_intent_plan_decision *decision);
    const char *(*code_name)(enum vault_intent_decision_code code);
};

const struct vault_intent_decision_service_v1 *
vault_intent_decision_service_builtin(void);
struct zcl_hotswap_service_contract;
const struct zcl_hotswap_service_contract *
zcl_native_vault_intent_decision_service_contract(void);

#endif /* ZCL_VAULT_INTENT_DECISION_SERVICE_H */
