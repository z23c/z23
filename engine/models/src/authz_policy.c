/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Authorization policy table (single source of truth). See authz_policy.h
 * for why this lives in models/ rather than services/. The model recompute
 * and the login-session minter both call these two functions, so role ->
 * (caps, ceiling) is defined in exactly one place.
 *
 * ar-validate-skip:pure-total-policy-lookup
 *   Not a row record — a stateless total table lookup (role -> mask /
 *   ceiling) with no DB-backed fields, so the AR validates_* lifecycle does
 *   not apply.
 *
 * one-result-type-ok:pure-total-policy-lookup — these are total, infallible
 * table lookups (role -> mask / ceiling) that cannot fail; a zcl_result would
 * be noise. Unknown roles fail closed to the least-privilege value. */

// one-result-type-ok:pure-total-policy-lookup — total infallible role->mask/
// ceiling table lookups; a zcl_result would be noise (fail closed on unknown).
#include "models/authz_policy.h"

/* Capability mask by role. Every entry is a strict superset of the one below
 * it. These are app-layer overlay capabilities only — none is consensus
 * conditional. */
uint64_t authz_caps_for_role(enum principal_role role)
{
    const uint64_t member = ZCL_COMMAND_CAP_CHAIN_READ |
                            ZCL_COMMAND_CAP_APP_MANIFEST_READ;
    const uint64_t operator_ = member |
                            ZCL_COMMAND_CAP_APP_SIMULATE |
                            ZCL_COMMAND_CAP_CHECKOUT_READ |
                            ZCL_COMMAND_CAP_DEV_STATE_READ;
    switch (role) {
    case PRINCIPAL_ROLE_GUEST:
        return ZCL_COMMAND_CAP_NONE;
    case PRINCIPAL_ROLE_MEMBER:
        return member;
    case PRINCIPAL_ROLE_OPERATOR:
        return operator_;
    case PRINCIPAL_ROLE_OWNER:
        return ~(uint64_t)0;
    }
    return ZCL_COMMAND_CAP_NONE; /* fail closed on an unknown role */
}

enum zcl_command_authority authz_ceiling_for_role(enum principal_role role)
{
    switch (role) {
    case PRINCIPAL_ROLE_GUEST:
    case PRINCIPAL_ROLE_MEMBER:
        return ZCL_COMMAND_AUTH_PUBLIC;
    case PRINCIPAL_ROLE_OPERATOR:
        return ZCL_COMMAND_AUTH_OPERATOR;
    case PRINCIPAL_ROLE_OWNER:
        return ZCL_COMMAND_AUTH_OWNER;
    }
    return ZCL_COMMAND_AUTH_PUBLIC; /* fail closed on an unknown role */
}
