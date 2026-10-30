/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The tools-side half of the ROSTER SEAM (ZRC 0012 step 2): the
 *          provider this box installs into util/fleet_roster_check.h so the
 *          fleet board can ask which root it trusts and whether a roster line
 *          is sealed by it, without the engine including a tools/ header.
 *
 * Nothing here holds a secret past one call: the manager's own fleet key is
 * loaded only to learn its PUBLIC half, and the seed is cleansed before the
 * function returns. No key material is logged. */

#include "fleet_enrol.h"

#include "base/cleanse.h"
#include "base/safe_alloc.h"
#include "util/fleet_roster_check.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert((int)ZCL_FLEET_ROOT_UNCHECKED == (int)FLEET_ANCHOR_UNCHECKED &&
               (int)ZCL_FLEET_ROOT_UNREADABLE == (int)FLEET_ANCHOR_UNREADABLE &&
               (int)ZCL_FLEET_ROOT_NOT_ANCHORED ==
                   (int)FLEET_ANCHOR_NOT_ANCHORED &&
               (int)ZCL_FLEET_ROOT_ACTIVE == (int)FLEET_ANCHOR_ACTIVE &&
               (int)ZCL_FLEET_ROOT_ROTATED == (int)FLEET_ANCHOR_ROTATED &&
               (int)ZCL_FLEET_ROOT_REVOKED == (int)FLEET_ANCHOR_REVOKED,
               "the seam's root states must match the anchor states");

/* Whose roster is this? On a box that joined a fleet, the operator is the
 * key the owner pasted; on the manager before it joins itself, it is this
 * box's own fleet key. A box that has done neither has no fleet root: a
 * state, not an error. The box is the MANAGER (the one that publishes the
 * roster) exactly when the root is its own key, however it came to trust
 * it, so a manager that also joined its own fleet is still the manager. */
static bool gate_root(uint8_t root[32], bool *present, bool *manager,
                      void *ctx)
{
    uint8_t seed[FLEET_ENROL_SEED_BYTES], own_pub[FLEET_ENROL_PUBKEY_BYTES];
    bool joined = false, own = false;
    const char *why = NULL;
    (void)ctx;
    *present = false;
    *manager = false;
    if (!fleet_enrol_operator_read(root, &joined, &why))
        return false;
    bool ok = fleet_enrol_key_load(seed, own_pub, false, &own, &why);
    memory_cleanse(seed, sizeof seed);
    if (!ok && !joined)
        return false;
    if (!ok)
        own = false; /* joined, own key unreadable: root is fine, not manager */
    if (!joined)
        memcpy(root, own_pub, FLEET_ENROL_PUBKEY_BYTES);
    *present = joined || own;
    *manager = own && memcmp(root, own_pub, FLEET_ENROL_PUBKEY_BYTES) == 0;
    return true;
}

static bool gate_verify(const char *line, const uint8_t root[32],
                        enum zcl_fleet_root_state state, bool require,
                        uint8_t signer[32], uint8_t box[32], bool *sealed,
                        const char **why,
                        void *ctx)
{
    struct fleet_anchor_fact fact;
    struct fleet_machine machine;
    const char *reason = NULL;
    (void)ctx;
    memset(&fact, 0, sizeof fact);
    memset(&machine, 0, sizeof machine);
    fact.state = (enum fleet_anchor_state)state;
    bool ok = fleet_root_line_verify(line, root, &fact, require, &machine,
                                     &reason);
    /* `out` is filled on a verified seal even when the anchor verdict
     * refuses, so a refused-but-sealed row is told apart from a forged one. */
    if (sealed)
        *sealed = ok || (reason && strcmp(reason,
                                          FLEET_ENROL_WHY_ROSTER_SIGNATURE) &&
                         strcmp(reason, FLEET_ENROL_WHY_ARGUMENTS));
    if (why)
        *why = reason;
    if (ok) {
        memcpy(signer, machine.receipt.signer_pubkey, 32);
        memcpy(box, machine.receipt.box_pubkey, 32);
    }
    return ok;
}

_Static_assert(ZCL_FLEET_REVOKED_MAX == (unsigned)FLEET_ENROL_HEAD_REVOKED_MAX,
               "the seam's revoked bound must match the head's");

/* The roster head under `root`, copied into the seam's shape. ABSENT is
 * "nothing revoked"; a head that exists and cannot be trusted is FAILED,
 * which the engine turns into "admit nobody". */
static void gate_head(const uint8_t root[32], struct zcl_fleet_head *out,
                      void *ctx)
{
    struct fleet_head *head = zcl_malloc(sizeof *head, "fleet-gate-head");
    enum fleet_head_state state;
    (void)ctx;
    memset(out, 0, sizeof *out);
    if (!head) {
        out->state = ZCL_FLEET_HEAD_FAILED;
        return;
    }
    state = fleet_head_load(root, head, NULL);
    if (state == FLEET_HEAD_OK) {
        out->state = ZCL_FLEET_HEAD_OK;
        out->count = head->n_revoked;
        memcpy(out->revoked, head->revoked,
               (size_t)head->n_revoked * FLEET_ENROL_PUBKEY_BYTES);
    } else if (state == FLEET_HEAD_BAD) {
        out->state = ZCL_FLEET_HEAD_FAILED;
    }
    free(head);
}

static bool gate_each_line(void (*visit)(const char *line, void *user),
                           void *user, void *ctx)
{
    const char *why = NULL;
    (void)ctx;
    return fleet_roster_each_line(visit, user, &why);
}

/* The endpoint one sealed line claims: its receipt's onion and whether the
 * line's box key is this box's own (so a box never dials itself). The key
 * is loaded only for its public half and the seed is cleansed at once. */
static bool gate_endpoint(const char *line, const uint8_t root[32],
                          char *onion, size_t cap, bool *self, void *ctx)
{
    uint8_t seed[FLEET_ENROL_SEED_BYTES], own_pub[FLEET_ENROL_PUBKEY_BYTES];
    struct fleet_machine machine;
    const char *why = NULL;
    bool present = false;
    (void)ctx;
    memset(&machine, 0, sizeof machine);
    if (!fleet_machine_parse(line, root, &machine, &why))
        return false;
    if (strlen(machine.receipt.onion) >= cap)
        return false;
    (void)snprintf(onion, cap, "%s", machine.receipt.onion);
    bool ok = fleet_enrol_key_load(seed, own_pub, false, &present, &why);
    memory_cleanse(seed, sizeof seed);
    if (!ok || !present)
        return false; /* cannot tell whether this line is our own: skip it */
    *self =
            memcmp(machine.receipt.box_pubkey, own_pub,
                   FLEET_ENROL_PUBKEY_BYTES) == 0;
    return true;
}

static const struct zcl_fleet_roster_provider g_provider = {
    .root = gate_root,
    .verify = gate_verify,
    .head = gate_head,
    .each_line = gate_each_line,
    .endpoint = gate_endpoint,
    .ctx = NULL,
    .name = "fleet_enrol_roster",
};

const struct zcl_fleet_roster_provider *zcl_fleet_roster_gate_provider(void)
{
    return &g_provider;
}

void zcl_fleet_roster_gate_start(void)
{
    zcl_fleet_roster_provider_install(&g_provider);
}
