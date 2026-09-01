/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Authorization policy: the SINGLE source of truth mapping a principal role to
 * (capability mask, authority ceiling). Consumed by the principal model's own
 * before_validate recompute (models/principal.c) AND by session minting in
 * the login service (services/auth_login_service.c). Lives under models/, not
 * services/: role -> (caps, ceiling) is a pure function of enum
 * principal_role and is the very invariant db_principal_validate() enforces,
 * so a services/ home would put the dependency backwards (a model reaching UP
 * into services) — exactly what check_shape_include_direction.sh forbids.
 * Keeping one table means role -> caps/ceiling can never diverge between
 * "what we store" and "what we enforce". Pure/deterministic: no clock, RNG,
 * or IO. */

#ifndef ZCL_MODELS_AUTHZ_POLICY_H
#define ZCL_MODELS_AUTHZ_POLICY_H

#include "models/principal.h"
#include "kernel/command_registry.h"

#include <stdint.h>

/* Capability mask granted to `role`. Higher roles are supersets of lower ones.
 * OWNER gets the full mask (~0). Unknown roles fail closed to CAP_NONE. */
uint64_t authz_caps_for_role(enum principal_role role);

/* The highest command authority a session for `role` may exercise. A dispatch
 * fails closed when spec->authority > this ceiling. Unknown roles fail closed
 * to ZCL_COMMAND_AUTH_PUBLIC. */
enum zcl_command_authority authz_ceiling_for_role(enum principal_role role);

#endif
