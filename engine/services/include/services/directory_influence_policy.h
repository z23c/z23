/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * directory_influence_policy — DEGRADED MODE for the peer/name directory.
 *
 * What this is for
 * ----------------
 * The directory (peer_directory rows, ZNAM name records, onion endpoints) is
 * how this node learns WHERE to look. Removing Tor's hardcoded authority
 * committee only helps if what replaces it cannot itself become a single
 * point of failure — so the directory here is ADVISORY and ADDITIVE: it can
 * raise a candidate's standing, it can never exclude a candidate, and the
 * always-present roots (compiled seeds + addr gossip) are reachable with the
 * directory contributing nothing at all.
 *
 * When the node suspects it is on the minority side of a network split
 * (services/network_monitor.h, network_monitor_netsplit_suspected()), the
 * directory it can see is the SPLIT's directory. Entries minted after the
 * split are testimony from one side only. So the node enters degraded mode:
 *
 *   - new directory entries gain NO influence;
 *   - entries that were already FINAL before the suspicion began keep
 *     working, unchanged (a split does not retroactively invalidate what the
 *     whole network agreed on);
 *   - discovery falls back to the always-present roots;
 *   - the node SAYS SO by name — the blocker SUSPECTED_NETSPLIT — and keeps
 *     running. It never falls quiet and it never halts.
 *
 * What is NOT gated
 * -----------------
 * Tip-following, block/tx relay, the block explorer, and wallet VIEWING.
 * Degraded mode withholds exactly one capability bit,
 * SYNC_CAP_DIRECTORY_INFLUENCE, and the evidence fact behind it
 * (`network_uncontested`) appears in no other formula in
 * services/sync_trust_policy.h — that is what makes the blast radius
 * provable rather than asserted. Mining and spending are governed by the
 * PROVENANCE bits and are not touched here either way.
 *
 * Layering
 * --------
 * The pure fold at the top has no clock, no IO and no globals. The live
 * surface below it owns one small piece of standing state (the suspicion
 * onset) and is driven by the condition engine
 * (engine/conditions/src/netsplit_degraded_mode.c). lib/ consumers reach this
 * policy through net/directory_influence_port.h, never by including app/.
 */

#ifndef ZCL_SERVICES_DIRECTORY_INFLUENCE_POLICY_H
#define ZCL_SERVICES_DIRECTORY_INFLUENCE_POLICY_H

#include <stdbool.h>
#include <stdint.h>

#include "services/sync_trust_policy.h"

/* The named blocker this policy raises while degraded mode is engaged. The
 * id is the operator-facing name; it is also the prefix
 * network_monitor_netsplit_publish() puts on its evidence string. */
#define DIRECTORY_INFLUENCE_BLOCKER_ID "SUSPECTED_NETSPLIT"

/* "final" here means the directory entry's confirmation depth reached
 * ZCL_FINALITY_DEPTH, i.e. the height at which the fold marked it final.
 * A negative value means "never finalized" and is treated as new. */
#define DIRECTORY_ENTRY_NOT_FINAL (-1)

/* Pure inputs to the per-entry admission fold. */
struct directory_influence_input {
    bool    netsplit_suspected;  /* the standing SUSPECTED_NETSPLIT verdict */
    int32_t split_onset_height;  /* our height when suspicion began; <0 = none */
    int32_t entry_final_height;  /* height the entry became final; <0 = never */
    bool    entry_is_root;       /* compiled seed / addr gossip: always present */
};

/* Stable, operator-facing decision tokens. Never renamed. */
#define DIRECTORY_INFLUENCE_TOKEN_GRANTED       "granted"
#define DIRECTORY_INFLUENCE_TOKEN_ROOT          "always_present_root"
#define DIRECTORY_INFLUENCE_TOKEN_PRE_SPLIT     "pre_split_final"
#define DIRECTORY_INFLUENCE_TOKEN_CONTESTED     "network_contested"
#define DIRECTORY_INFLUENCE_TOKEN_NO_INPUT      "no_input"

struct directory_influence_decision {
    bool        influence_admitted; /* may this entry influence anything? */
    bool        fallback_to_roots;  /* discovery must lean on the roots */
    const char *token;              /* one of the tokens above; never NULL */
};

/* Decide whether ONE directory entry may exert influence right now. Pure and
 * total: `out` NULL is a no-op, `in` NULL fails closed (not admitted, fall
 * back to roots, token "no_input"). Rules, in order:
 *
 *   entry_is_root                     -> admitted ("always_present_root").
 *                                        The roots are never gated; they are
 *                                        what degraded mode falls back TO.
 *   !netsplit_suspected               -> admitted ("granted").
 *   final strictly BEFORE the onset    -> admitted ("pre_split_final").
 *   otherwise                          -> withheld ("network_contested").
 *
 * An unknown onset (<0) with a suspicion standing withholds every non-root,
 * non-final entry: without an onset height there is no way to tell pre-split
 * from post-split, and guessing in the permissive direction is exactly the
 * mistake degraded mode exists to prevent. */
void directory_influence_decide(const struct directory_influence_input *in,
                                struct directory_influence_decision *out);

/* The capability mask for a node whose provenance evidence is `base` and
 * whose network is (un)contested. Pure: copies `base`, overrides the single
 * network fact, and routes through sync_capabilities_from_evidence — so the
 * ONE authorization formula stays the one in sync_trust_policy.c. `base` NULL
 * is the all-false least-privilege tuple. `why` may be NULL. */
uint32_t directory_influence_caps(const struct sync_evidence *base,
                                  bool network_uncontested,
                                  struct sync_capability_denials *why);

/* ── Live surface (standing state; safe from any thread) ──────────────── */

/* Fold the current netsplit verdict into standing state. `our_height` is the
 * node's height now (<0 = unknown) and is recorded as the suspicion ONSET on
 * a false->true edge. Raises the named blocker SUSPECTED_NETSPLIT on the
 * edge and refreshes it while the suspicion stands; clears it on the
 * true->false edge. `reason` may be NULL (a default is used). Returns true
 * iff directory influence is GRANTED after the fold. */
bool directory_influence_observe(bool netsplit_suspected, int32_t our_height,
                                 const char *reason);

/* The standing answer, with no side effects. True when the directory may
 * influence discovery/dialling/resolution. */
bool directory_influence_granted(void);

/* Our height when the standing suspicion began, or <0 when none stands. */
int32_t directory_influence_split_onset_height(void);

/* Admission for one directory entry against the STANDING verdict — the call
 * every directory consumer makes. `out` may be NULL. Returns
 * out->influence_admitted. */
bool directory_influence_admit_entry(int32_t entry_final_height,
                                     bool entry_is_root,
                                     struct directory_influence_decision *out);

/* Install this policy as the implementation behind
 * net/directory_influence_port.h, so lib/ consumers get the same answer
 * without a backwards include. Idempotent; called from the composition
 * root. */
void directory_influence_register_port(void);

#ifdef ZCL_TESTING
/* Drop standing state and clear the blocker. */
void directory_influence_test_reset(void);
#endif

#endif /* ZCL_SERVICES_DIRECTORY_INFLUENCE_POLICY_H */
