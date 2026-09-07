/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The ROLE-CHECK SEAM — the one call an ingress point makes before
 * it accepts bytes signed by another machine's key, and the setter the top
 * layer uses to install the thing that answers it.
 *
 * The role catalog and the signed grant store live in tools/dev (see
 * tools/dev/fleet_roles.h). Nothing under engine/ may include a tools/
 * header, and the two places foreign-signed bytes enter this node —
 * zcl_fleet_ledger_replicate() and db_fleet_board_post_ingest() — are both
 * under engine/. This file is the seam between them: a function-pointer
 * vtable declared in the lowest layer both ingress points already depend
 * on, filled in by the layer that can see the store. It follows the shape
 * agent_broker_provider_install() already uses in
 * cognition/modules/session/include/session/agent_broker.h:493 — the
 * decision is made by whoever installs, never by the module that asks.
 *
 * FAIL CLOSED. With no checker installed, zcl_fleet_role_allows() REFUSES
 * and says so once. There is no default-permit path and no build in which
 * the absence of a policy means "allow": a node that cannot ask who a key
 * is has not learned that the key is trustworthy.
 */

#ifndef ZCL_BASE_FLEET_ROLE_CHECK_H
#define ZCL_BASE_FLEET_ROLE_CHECK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The two leaves this seam guards, spelled once. They are the exact names
 * engine/composition/roles.def grants. */
#define ZCL_FLEET_LEAF_LEDGER_REPLICATE "fleet.ledger.replicate"
#define ZCL_FLEET_LEAF_BOARD_POST       "fleet.board.post"

/* Enough for the longest refusal the store composes: a fingerprint prefix,
 * a leaf name and a kind. */
#define ZCL_FLEET_ROLE_WHY_MAX 128u

/* Does `key` (a 32-byte Ed25519 public key, NOT a fingerprint) hold a role
 * granting `leaf` and, when the leaf carries one, `kind`? `why` (when
 * non-NULL) receives the exact typed refusal a person reads. */
typedef bool (*zcl_fleet_role_check_fn)(const uint8_t key[32],
                                        const char *leaf, const char *kind,
                                        char *why, size_t why_cap, void *ctx);

/* Where a key's standing came from, for the one log line each grandfathered
 * key gets. Borrowed for the call, never stored. */
#define ZCL_FLEET_ROLE_ORIGIN_LEDGER "ledger"
#define ZCL_FLEET_ROLE_ORIGIN_BOARD  "board"

/* GRANDFATHERING. `key` signed a row or a post THIS NODE ALREADY HOLDS,
 * stored back when nothing asked for a role. Accepting those bytes was this
 * operator's decision to trust that key, so this writes that decision down
 * as a signed grant and the peer keeps replicating across the upgrade
 * instead of stalling at a gate that did not exist when its rows arrived.
 * It is not a default-permit: the only keys it can ever name are ones
 * already inside this node's own stores. True when the key holds the role
 * afterwards, whether this call minted it or found it. */
typedef bool (*zcl_fleet_role_grandfather_fn)(const uint8_t key[32],
                                              const char *origin, void *ctx);

struct zcl_fleet_role_checker {
    zcl_fleet_role_check_fn allow;
    /* Optional. NULL means this process mints nothing, which is a fine
     * state for a checker that only answers questions. */
    zcl_fleet_role_grandfather_fn grandfather;
    void *ctx;
    const char *name; /* named in the log line that says who is deciding */
};

/* Install the checker this process asks. Copied by value, so the caller's
 * struct need not outlive the call; `ctx` and `name` are borrowed and must.
 * A NULL checker (or one with no `allow`) uninstalls, which puts every
 * ingress point back to refusing. */
void zcl_fleet_role_checker_install(const struct zcl_fleet_role_checker *c);

/* True when a checker is installed. For status surfaces only — never as a
 * precondition a caller uses to skip the check. */
bool zcl_fleet_role_checker_installed(void);

/* THE CHOKE POINT. False refuses; `why` (when non-NULL, at least
 * ZCL_FLEET_ROLE_WHY_MAX bytes) is filled with the reason. Returns false
 * when no checker is installed, and logs that fact once per process. */
bool zcl_fleet_role_allows(const uint8_t key[32], const char *leaf,
                           const char *kind, char *why, size_t why_cap);

/* Mint (or find) the grant `key` already earned by having a row or post of
 * its own stored here. False when no checker is installed, when it installed
 * no grandfather, or when the grant could not be written — a node that cannot
 * mint grants keeps refusing, which is the same fail-closed answer as
 * before. */
bool zcl_fleet_role_grandfather(const uint8_t key[32], const char *origin);

#ifdef ZCL_TESTING
/* Test fixture: a checker that allows every key. Present ONLY in a
 * ZCL_TESTING build, so no production binary contains a permit-all path.
 * Groups that exercise the store or the gossip path install it to say "the
 * role gate is open here"; the gate itself is proven in fleet_roles and
 * fleet_role_enforcement, which uninstall it first. */
void zcl_fleet_role_checker_install_permissive_for_testing(void);
#endif

#endif /* ZCL_BASE_FLEET_ROLE_CHECK_H */
