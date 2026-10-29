/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The ROSTER SEAM (ZRC 0012 step 2) — the calls the fleet board
 * makes to learn which fleet root this node trusts and whether one
 * operator-sealed roster line is genuinely sealed by it, and the setter the
 * top layer uses to install what answers.
 *
 * The sealed machine line, its codec and the anchor verdict live in
 * tools/dev (fleet_enrol.h, fleet_enrol_anchor.c). The fleet board that
 * consults them lives under engine/, which may not include a tools/ header.
 * This is the same shape as util/fleet_role_check.h: a function-pointer
 * vtable in a platform module both sides may include, filled in by
 * tools/dev/fleet_roster_gate.c and installed from engine/entry/main.c.
 *
 * Nothing here decides membership. It answers three narrow questions: which
 * key is the root, did that root seal this line, and what is the line's
 * signing key. The engine (config/boot_fleet_roster.h) holds the roster and
 * the verdict.
 *
 * With no provider installed the root is "not present": the roster gate is
 * unarmed and the fleet board behaves exactly as it did before step 2.
 * That is the only default, and it is the old behaviour, never a wider one.
 */

#ifndef ZCL_UTIL_FLEET_ROSTER_CHECK_H
#define ZCL_UTIL_FLEET_ROSTER_CHECK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Longest sealed roster line the board will carry as a roster row. It is the
 * wire ceiling of one fleet_machine line (tools/dev/fleet_enrol.h) rounded
 * up; a longer string is not a roster row. */
#define ZCL_FLEET_ROSTER_LINE_MAX 2400u

/* What the chain's zid_identities projection said about the root. The values
 * match tools/dev's enum fleet_anchor_state one for one (the provider
 * asserts it), so the verdict function there is the only one. */
enum zcl_fleet_root_state {
    ZCL_FLEET_ROOT_UNCHECKED = 0,
    ZCL_FLEET_ROOT_UNREADABLE,
    ZCL_FLEET_ROOT_NOT_ANCHORED,
    ZCL_FLEET_ROOT_ACTIVE,
    ZCL_FLEET_ROOT_ROTATED,
    ZCL_FLEET_ROOT_REVOKED,
};

/* The operator-signed roster HEAD, as the engine needs it: only the revoked
 * box public keys. Loaded once per roster rebuild, never per peer.
 *
 * NONE: this box holds no head, so nothing is revoked (the old behaviour).
 * OK: `revoked` holds `count` box keys, sorted ascending and unique.
 * FAILED: a head file exists and cannot be trusted (unreadable, corrupt, or
 * not sealed by the root). That is NEVER "nothing revoked": the gate admits
 * nobody until the head is repaired. */
#define ZCL_FLEET_REVOKED_MAX 256u

enum zcl_fleet_head_state {
    ZCL_FLEET_HEAD_NONE = 0,
    ZCL_FLEET_HEAD_OK,
    ZCL_FLEET_HEAD_FAILED,
};

struct zcl_fleet_head {
    enum zcl_fleet_head_state state;
    uint32_t count;
    uint8_t revoked[ZCL_FLEET_REVOKED_MAX][32];
};

struct zcl_fleet_roster_provider {
    /* The operator root this node trusts. `present` false means this box
     * has no fleet root, which is a state and not an error; the function
     * returns false only when a recorded root cannot be read. `manager` is
     * true when the root is this box's own key, i.e. the box that admits
     * machines and therefore publishes the roster. */
    bool (*root)(uint8_t root[32], bool *present, bool *manager, void *ctx);
    /* One sealed line against `root` and the root's anchor verdict. True
     * only when the seal verifies AND the anchor verdict (under `require`)
     * accepts; `signer` then holds the line's board signing key (all zero
     * when the receipt named none). On false `why` is the typed token:
     * fleetboard.roster_signature_invalid for a bad seal, else one of the
     * fleet_root_* refusals, and `sealed` says whether the seal itself
     * verified (so a revoked root is not confused with a forged row).
     * `box` receives the line's box public key (the identity the operator
     * admitted, which a roster head revokes), set on a verified seal. */
    bool (*verify)(const char *line, const uint8_t root[32],
                   enum zcl_fleet_root_state state, bool require,
                   uint8_t signer[32], uint8_t box[32], bool *sealed,
                   const char **why, void *ctx);
    /* The roster head under `root`: the revoked box keys. Optional; a
     * provider without it revokes nothing. */
    void (*head)(const uint8_t root[32], struct zcl_fleet_head *out,
                 void *ctx);
    /* Visit every line of this box's own machine roster, in file order.
     * The manager publishes these onto the board. False when unreadable. */
    bool (*each_line)(void (*visit)(const char *line, void *user),
                      void *user, void *ctx);
    /* The dialable endpoint of one line sealed by `root`: `onion` receives
     * the receipt's persistent onion hostname ("" when it names none) and
     * `self` whether the line's box key is this box's own. Optional; a
     * provider without it offers no endpoint. False when the line does not
     * parse or verify under `root`. The onion is the box's own signed
     * claim, not a fact: dialling it is how the claim gets tested. */
    bool (*endpoint)(const char *line, const uint8_t root[32], char *onion,
                     size_t cap, bool *self, void *ctx);
    void *ctx;
    const char *name;
};

/* Install the provider this process asks, copied by value. NULL, or a
 * provider with no `root`, uninstalls and returns the gate to unarmed. */
void zcl_fleet_roster_provider_install(
    const struct zcl_fleet_roster_provider *p);
bool zcl_fleet_roster_provider_installed(void);

/* The wrappers the engine calls. With no provider: root is absent, verify
 * refuses, each_line visits nothing. */
bool zcl_fleet_roster_root(uint8_t root[32], bool *present, bool *manager);
bool zcl_fleet_roster_verify(const char *line, const uint8_t root[32],
                             enum zcl_fleet_root_state state, bool require,
                             uint8_t signer[32], uint8_t box[32], bool *sealed,
                             const char **why);
/* The head under `root`. With no provider, or one without a head callback,
 * the state is NONE: nothing revoked. */
void zcl_fleet_roster_head(const uint8_t root[32],
                           struct zcl_fleet_head *out);
bool zcl_fleet_roster_each_line(void (*visit)(const char *line, void *user),
                                void *user);
/* The endpoint of one line. With no provider, or one without an endpoint
 * callback, false: no endpoint is known. */
bool zcl_fleet_roster_endpoint(const char *line, const uint8_t root[32],
                               char *onion, size_t cap, bool *self);

#endif /* ZCL_UTIL_FLEET_ROSTER_CHECK_H */
