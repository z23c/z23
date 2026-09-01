/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Runtime lifecycle for declared services: register, start, stop, remove.
 *
 * States are `enum zcl_service_lifecycle_v1` and every transition goes
 * through the pure table in zcl_service_lifecycle_next_v1, so this file holds
 * the bookkeeping and none of the rules. What it adds on top of the table:
 *
 *   register  admits a DECLARED binding into the runtime. Refuses anything
 *             the catalog check does not accept, so a malformed declaration
 *             never reaches STARTING.
 *   start     is where the TOKEN BINDING bites. A service leaves STARTING for
 *             READY only on a granted verdict from service_token_gate. Any
 *             denial drives FAULT -> BLOCKED and records the gate's own
 *             reason string, so a refused start is always named — never a
 *             silent no-op.
 *   stop      drives STOP then EXIT. There is no worker thread to drain, so
 *             STOPPING is passed through in the same call rather than left
 *             as a state nothing will ever advance.
 *   remove    returns an EXITED service to DECLARED. It deliberately does NOT
 *             drop the service's tables: a declaration can be unregistered,
 *             but destroying operator data is a separate, explicit act.
 *
 * BLOCKED is sticky. Only an explicit stop clears it, and the reason survives
 * until then, matching the node's advance-cursor-or-name-a-blocker rule.
 *
 * Concurrency: one small mutex over a fixed table sized to the catalog. This
 * module never takes the reducer progress lock and never blocks on one — it
 * has no access to it, which is the point.
 *
 * Durability: the registry is in-memory and rebuilt from the compiled catalog
 * at init, so every service starts a boot at DECLARED. Persisting runtime
 * lifecycle across restarts belongs to whichever service first owns durable
 * state, not to the contract. */

#ifndef ZCL_SERVICES_SERVICE_LIFECYCLE_H
#define ZCL_SERVICES_SERVICE_LIFECYCLE_H

#include "base/result.h"
#include "kernel/service_binding.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct node_db;
struct json_value;

#define SERVICE_LIFECYCLE_REASON_MAX 128u

enum service_lifecycle_error {
    SERVICE_LIFECYCLE_ERR_CATALOG = -3500,
    SERVICE_LIFECYCLE_ERR_UNINITIALIZED = -3501,
    SERVICE_LIFECYCLE_ERR_UNKNOWN_SERVICE = -3502,
    SERVICE_LIFECYCLE_ERR_TRANSITION = -3503,
    SERVICE_LIFECYCLE_ERR_GATE_DENIED = -3504,
    SERVICE_LIFECYCLE_ERR_ARGUMENT = -3505,
};

/* Seed one DECLARED row per catalog binding. Idempotent; safe to call again
 * (it resets every row back to DECLARED, which is what a fresh boot means).
 * Non-ok if the declared catalog does not check out — a build whose bindings
 * are invalid must not run any of them. */
struct zcl_result service_lifecycle_init(void);

/* DECLARED -> STARTING. */
struct zcl_result service_lifecycle_register(const char *name);

/* STARTING -> READY, gated on the service's own token binding evaluated
 * against `ndb` at `tip_height`. On denial the service lands in BLOCKED with
 * the gate's own reason and this returns SERVICE_LIFECYCLE_ERR_GATE_DENIED
 * carrying the balance, threshold, and snapshot height that produced it. */
struct zcl_result service_lifecycle_start(const char *name,
                                          struct node_db *ndb,
                                          int32_t tip_height);

/* live|BLOCKED -> STOPPING -> EXITED. Clears the blocker reason. */
struct zcl_result service_lifecycle_stop(const char *name);

/* EXITED -> DECLARED. Owned state is left on disk on purpose. */
struct zcl_result service_lifecycle_remove(const char *name);

/* Current state (enum zcl_service_lifecycle_v1) plus the blocker reason, ""
 * when there is none. Non-ok for an unknown service. */
struct zcl_result service_lifecycle_state(const char *name,
                                          uint32_t *out_state,
                                          char *out_reason, size_t reason_sz);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe.
 * key = a service name, or NULL for every declared service. */
bool service_lifecycle_dump_state_json(struct json_value *out,
                                       const char *key);

#endif /* ZCL_SERVICES_SERVICE_LIFECYCLE_H */
