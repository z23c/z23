/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Sync trust → capability policy: the SINGLE source of truth mapping the
 * node's self-derivation posture to the set of operations it may perform
 * (serve a validated tip, receive/spend in the wallet, mine, export a state
 * bundle, seed a bundle). Today the same decision is scattered across
 * sovereignty_guard_allow, bx_qualified, boot_snapshot_offer and export_proof,
 * keyed on two ORTHOGONAL provenance bits that genuinely diverge:
 *
 *   S = self_derived                       (mint / spend / offer authority)
 *   X = proven_authority && refold_marker  (export authority)
 *
 * This table derives one `sync_trust_state` from (proven, refold, self_derived)
 * and maps it to a `sync_capability` bitmask, so the provenance-bit portion of
 * every gate resolves in exactly one place. It replaces ONLY that portion —
 * every other local AND a call site applies (cursors, build_commit,
 * coins_ram_active, payload authority, and the SNAPSYNC_ACTIVATION_CONTAINED
 * door) stays exactly where it is and is never weakened.
 *
 * Authorization is a BOOLEAN FORMULA over named evidence facts, never an
 * ordinal over the enum. `struct sync_evidence` names the twelve crypto/replay
 * facts the node can independently establish; `sync_capabilities_from_evidence`
 * derives the SAME capability mask the state table produces, with a stable
 * denial reason per withheld capability. `sync_trust_state` remains as a
 * compact display/derivation label; `enum sync_posture` is the display-only
 * posture that authorizes NOTHING.
 *
 * Pure/deterministic: no clock, RNG, or IO. Mirrors engine/models/authz_policy.h. */

#ifndef ZCL_SERVICES_SYNC_TRUST_POLICY_H
#define ZCL_SERVICES_SYNC_TRUST_POLICY_H

#include <stdbool.h>
#include <stdint.h>

/* These states are ORTHOGONAL provenance facts, NOT a trust ordinal — never
 * compare them with </<=/>/>= (the check-no-trust-state-ordering lint gate
 * forbids exactly that). Two provenance bits diverge independently:
 *   S = self_derived                      (serve / spend / mine / seed authority)
 *   X = proven_authority && refold_marker (export authority)
 * EXPORT_ROOT_REDERIVED (¬S ∧ X) grants EXPORT ONLY; ARTIFACT_VERIFIED (S ∧ ¬X)
 * grants serve/spend/mine/seed but NOT export. Neither state is a superset of
 * the other, so an ordinal comparison of these enumerators is always a bug.
 * Every authorization decision routes through the capability MASK
 * (sync_trust_caps / sync_trust_cap_allowed / sync_capabilities_from_evidence),
 * never a numeric comparison. PEER_ASSISTED_READY is RESERVED — the derive
 * function does not yet return it this slice (peer-provided state is not a
 * distinct readiness tier until the artifact-protocol lands). */
enum sync_trust_state {
    SYNC_TRUST_EMPTY = 0,             /* no usable state */
    SYNC_TRUST_EXPORT_ROOT_REDERIVED, /* ¬S ∧ X: export authority only — export
                                       * root re-derived from checkpoint-bound
                                       * header-chain evidence */
    SYNC_TRUST_ARTIFACT_VERIFIED,     /* S ∧ ¬X: self-derived, no export */
    SYNC_TRUST_RELEASE_ASSISTED_READY,/* ¬S ∧ ¬X ∧ proven: assisted operational */
    SYNC_TRUST_PEER_ASSISTED_READY,   /* reserved (not derived this slice) */
    SYNC_TRUST_SOVEREIGN,             /* S ∧ X: full authority */
    SYNC_TRUST_STATE_COUNT
};

/* Capability bitmask. Each bit is one operator-visible action. */
enum sync_capability {
    SYNC_CAP_NONE               = 0,
    SYNC_CAP_SERVE_VALIDATED_TIP = 1u << 0,
    SYNC_CAP_WALLET_RECEIVE      = 1u << 1,
    SYNC_CAP_WALLET_SPEND        = 1u << 2,
    SYNC_CAP_MINE                = 1u << 3,
    SYNC_CAP_EXPORT_BUNDLE       = 1u << 4,
    SYNC_CAP_SEED_BUNDLE         = 1u << 5,
    /* NETWORK-derived, not provenance-derived (see the note under
     * SYNC_CAP_ALL): may a peer/name DIRECTORY influence what this node
     * discovers, dials, or prefers? Withheld alone puts the node in degraded
     * mode: tip-following, relay, the block explorer and wallet VIEWING are
     * untouched, discovery falls back to the always-present roots (compiled
     * seeds + addr gossip), and directory entries that were already final
     * before the suspicion began keep working. */
    SYNC_CAP_DIRECTORY_INFLUENCE = 1u << 6,
};

/* All six PROVENANCE capabilities — the SOVEREIGN mask.
 *
 * SYNC_CAP_DIRECTORY_INFLUENCE is deliberately NOT a member. The six bits
 * above are functions of what this node has independently DERIVED; directory
 * influence is a function of what the NETWORK currently looks like, which no
 * `sync_trust_state` models. Adding it here would make every SOVEREIGN node
 * grant it unconditionally and would silently entangle a network fact with the
 * provenance table. The state table therefore never grants the bit — only
 * `sync_capabilities_from_evidence` does, off the `network_uncontested` fact —
 * and the exclusion is asserted at compile time in sync_trust_policy.c. */
#define SYNC_CAP_ALL (SYNC_CAP_SERVE_VALIDATED_TIP | SYNC_CAP_WALLET_RECEIVE | \
                      SYNC_CAP_WALLET_SPEND | SYNC_CAP_MINE |                   \
                      SYNC_CAP_EXPORT_BUNDLE | SYNC_CAP_SEED_BUNDLE)

/* Number of defined SYNC_CAP_* bits (bit index 0..SYNC_CAP_BIT_COUNT-1). */
#define SYNC_CAP_BIT_COUNT 7

/* Bit index of the directory-influence capability, for denial-array lookup. */
#define SYNC_CAP_DIRECTORY_INFLUENCE_BIT 6

/* ── The evidence lattice ────────────────────────────────────────────────
 * Every capability grant reduces to a boolean formula over these named,
 * independently-establishable facts (crypto-trust foundation: each fact is a
 * PoW/checkpoint/replay observation, never an operator vouch or an ordinal
 * trust tier). Authorization is `sync_capabilities_from_evidence`, below; the
 * facts are orthogonal (a node can have export-root evidence without a
 * self-derived tip, and vice-versa). All false = the least-privilege floor. */
struct sync_evidence {
    bool header_chain_verified;       /* PoW header chain validated to tip */
    bool competitive_chainwork;       /* the validated chain is most-work */
    bool bundle_bytes_verified;       /* transferred bytes match their commitment */
    bool checkpoint_content_rederived;/* state re-derived from the baked checkpoint */
    bool transparent_state_complete;  /* full UTXO set present at the tip */
    bool sapling_history_complete;    /* Sapling anchors/frontier complete */
    bool sprout_history_complete;     /* Sprout anchors/frontier complete */
    bool nullifier_history_complete;  /* nullifier set complete for both pools */
    bool state_self_derived;          /* tip state folded locally, not borrowed */
    bool full_history_replayed;       /* every block body replayed from checkpoint */
    bool export_root_rederived;       /* export root re-derived from bound content */
    bool active_tip_locally_validated;/* the served tip passed local validation */
    /* The one NETWORK fact in an otherwise all-provenance tuple: no
     * corroborated evidence that this node sits on the minority side of a
     * split (engine/services/include/services/network_monitor.h's
     * network_monitor_netsplit_suspected()). It gates SYNC_CAP_DIRECTORY_
     * INFLUENCE and NOTHING else — it appears in no other formula below, so
     * withholding it can never take away tip-following, relay, the explorer,
     * wallet viewing, spending, mining or export. False (the all-false floor)
     * withholds directory influence, which is the safe direction: the
     * directory is advisory and additive, so falling back to the compiled
     * seeds + addr gossip costs reachability hints, never correctness. */
    bool network_uncontested;
};

/* A stable denial reason per capability bit: reason[i] describes why the bit
 * (1u<<i) is WITHHELD, or NULL when that bit is granted. Reasons are stable
 * lowercase tokens (e.g. "missing_checkpoint_binding",
 * "shielded_history_incomplete", "state_not_self_derived",
 * "export_root_not_rederived", "network_contested") so callers/tests can key
 * on them. Operators key on these too — never rename one. */
struct sync_capability_denials {
    const char *reason[SYNC_CAP_BIT_COUNT];
};

/* Derive the capability mask directly from the evidence facts (the single
 * authorization formula). `why` (may be NULL) is filled with a stable denial
 * reason for every withheld capability bit and NULL for every granted bit.
 * Pure/total: fails closed to SYNC_CAP_NONE. This is behavior-identical to
 * sync_trust_caps(sync_evidence_for_state(st)) for every current state. */
uint32_t sync_capabilities_from_evidence(const struct sync_evidence *e,
                                         struct sync_capability_denials *why);

/* The canonical evidence tuple that a given `sync_trust_state` represents —
 * the documented state→evidence mapping. Feeding this to
 * sync_capabilities_from_evidence reproduces sync_trust_caps(st) exactly (the
 * behavior-preservation guarantee, proven in test_sync_trust_policy). Unknown
 * states return an all-false (least-privilege) tuple. */
struct sync_evidence sync_evidence_for_state(enum sync_trust_state st);

/* ── Display-only posture ────────────────────────────────────────────────
 * A coarse label for status output. It AUTHORIZES NOTHING: there is
 * deliberately no caps-from-posture function — every real gate uses the
 * capability mask. Two distinct provenance states can share one posture. */
enum sync_posture {
    SYNC_POSTURE_EMPTY = 0,
    SYNC_POSTURE_HEADERS_ONLY,
    SYNC_POSTURE_ASSISTED_READY,
    SYNC_POSTURE_SELF_DERIVED_READY,
    SYNC_POSTURE_SOVEREIGN,
};

/* Display posture for `st` (fail closed to SYNC_POSTURE_EMPTY). Display only. */
enum sync_posture sync_posture_from_state(enum sync_trust_state st);

/* Stable lowercase posture name; out-of-range → "?". Display only. */
const char *sync_posture_name(enum sync_posture p);

/* Derive the trust state from the two orthogonal provenance bits. `proven` is
 * proven_authority; `refold` is the refold_marker; `self_derived` is S.
 * X = proven && refold. Total: every combination maps to a defined state.
 * Fails closed to SYNC_TRUST_EMPTY. */
enum sync_trust_state sync_trust_derive(bool proven, bool refold,
                                        bool self_derived);

/* The capability mask granted by `st`. Unknown states fail closed to
 * SYNC_CAP_NONE. */
uint32_t sync_trust_caps(enum sync_trust_state st);

/* True iff `st` grants `cap` (a single SYNC_CAP_* bit). */
bool sync_trust_cap_allowed(enum sync_trust_state st, enum sync_capability cap);

/* Stable lowercase state name; out-of-range → "?". */
const char *sync_trust_state_name(enum sync_trust_state st);

#endif /* ZCL_SERVICES_SYNC_TRUST_POLICY_H */
