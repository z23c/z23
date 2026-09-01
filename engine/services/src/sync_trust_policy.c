/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Sync trust → capability policy table (single source of truth). See
 * services/sync_trust_policy.h.
 *
 * one-result-type-ok:pure-total-policy-lookup — these are total, infallible
 * table lookups (provenance bits -> trust state -> capability mask) that cannot
 * fail; a zcl_result would be noise. Unknown inputs fail closed to the
 * least-privilege value (EMPTY / CAP_NONE).
 *
 * STEP-0 STATUS: the derivation matrix + the capability table are REAL and
 * final; lanes 3B/3C/3D route the existing gate sites through them. */

// one-result-type-ok:pure-total-policy-lookup — total infallible provenance->
// state->capability lookups; a zcl_result would be noise (fail closed).
#include "services/sync_trust_policy.h"

#include <stddef.h>  /* NULL, size_t */

enum sync_trust_state sync_trust_derive(bool proven, bool refold,
                                        bool self_derived)
{
    const bool S = self_derived;
    const bool X = proven && refold;   /* export authority */

    if (S && X)
        return SYNC_TRUST_SOVEREIGN;            /* full authority */
    if (S && !X)
        return SYNC_TRUST_ARTIFACT_VERIFIED;    /* self-derived, no export */
    if (!S && X)
        return SYNC_TRUST_EXPORT_ROOT_REDERIVED; /* export only */
    if (!S && !X && proven)
        return SYNC_TRUST_RELEASE_ASSISTED_READY;
    return SYNC_TRUST_EMPTY;                     /* fail closed */
}

uint32_t sync_trust_caps(enum sync_trust_state st)
{
    switch (st) {
    case SYNC_TRUST_EMPTY:
        return SYNC_CAP_NONE;
    case SYNC_TRUST_EXPORT_ROOT_REDERIVED:
        /* ¬S ∧ X: export authority only. */
        return SYNC_CAP_EXPORT_BUNDLE;
    case SYNC_TRUST_ARTIFACT_VERIFIED:
        /* S ∧ ¬X: self-derived operational — everything but EXPORT. */
        return SYNC_CAP_SERVE_VALIDATED_TIP | SYNC_CAP_WALLET_RECEIVE |
               SYNC_CAP_WALLET_SPEND | SYNC_CAP_MINE | SYNC_CAP_SEED_BUNDLE;
    case SYNC_TRUST_RELEASE_ASSISTED_READY:
        /* Proven but not self-derived: assisted readiness only — serve a
         * validated tip and receive; never mine/spend/export/seed. */
        return SYNC_CAP_SERVE_VALIDATED_TIP | SYNC_CAP_WALLET_RECEIVE;
    case SYNC_TRUST_PEER_ASSISTED_READY:
        /* Reserved: same assisted shape as release-assisted; NEVER mine/seed. */
        return SYNC_CAP_SERVE_VALIDATED_TIP | SYNC_CAP_WALLET_RECEIVE;
    case SYNC_TRUST_SOVEREIGN:
        return SYNC_CAP_ALL;
    case SYNC_TRUST_STATE_COUNT:
        break;
    }
    return SYNC_CAP_NONE; /* fail closed on an unknown state */
}

bool sync_trust_cap_allowed(enum sync_trust_state st, enum sync_capability cap)
{
    return (sync_trust_caps(st) & (uint32_t)cap) != 0u;
}

const char *sync_trust_state_name(enum sync_trust_state st)
{
    switch (st) {
    case SYNC_TRUST_EMPTY:                return "empty";
    case SYNC_TRUST_EXPORT_ROOT_REDERIVED: return "export_root_rederived";
    case SYNC_TRUST_ARTIFACT_VERIFIED:    return "artifact_verified";
    case SYNC_TRUST_RELEASE_ASSISTED_READY: return "release_assisted_ready";
    case SYNC_TRUST_PEER_ASSISTED_READY:  return "peer_assisted_ready";
    case SYNC_TRUST_SOVEREIGN:            return "sovereign";
    case SYNC_TRUST_STATE_COUNT:          break;
    }
    return "?";
}

/* ── Evidence lattice → capability mask (the single authorization formula) ──
 *
 * Three composite facts, each a pure conjunction of the twelve named evidence
 * bits, reproduce the two orthogonal provenance bits plus the assisted base:
 *
 *   proven = header_chain_verified && competitive_chainwork &&
 *            bundle_bytes_verified && checkpoint_content_rederived &&
 *            active_tip_locally_validated       (assisted operational base)
 *   X      = checkpoint_content_rederived && export_root_rederived   (export)
 *   S      = proven && state_self_derived && transparent_state_complete &&
 *            sapling_history_complete && sprout_history_complete &&
 *            nullifier_history_complete && full_history_replayed  (sovereignty)
 *
 * Capability formula (byte-identical to the sync_trust_caps() table for every
 * state's canonical evidence tuple — proven in test_sync_trust_policy):
 *   SERVE/RECEIVE = S || (proven && !X)   SPEND/MINE/SEED = S   EXPORT = X
 *   DIRECTORY_INFLUENCE = network_uncontested
 *
 * DIRECTORY_INFLUENCE stands apart on purpose. It is the only bit whose
 * formula names a NETWORK fact, and `network_uncontested` is the only fact
 * that appears in exactly one formula. That is the degraded-mode contract:
 * suspecting a netsplit removes the directory's influence and provably
 * nothing else — no provenance fact changes, so tip-following, relay, the
 * explorer, wallet viewing, spending, mining and export are untouched.
 * `sync_evidence_for_state()` leaves it FALSE in every canonical tuple, so
 * the provenance state table (sync_trust_caps) never grants it and the
 * behavior-preservation guarantee above holds unchanged.
 */

/* First-missing proven-base fact, as a stable reason token; NULL if proven. */
static const char *proven_denial(const struct sync_evidence *e)
{
    if (!e->checkpoint_content_rederived) return "missing_checkpoint_binding";
    if (!e->header_chain_verified)        return "header_chain_unverified";
    if (!e->competitive_chainwork)        return "insufficient_chainwork";
    if (!e->bundle_bytes_verified)        return "bundle_bytes_unverified";
    if (!e->active_tip_locally_validated) return "active_tip_not_locally_validated";
    return NULL;
}

/* First-missing self-derivation fact past the proven base; NULL if S. */
static const char *self_derived_denial(const struct sync_evidence *e)
{
    const char *p = proven_denial(e);
    if (p) return p;
    if (!e->state_self_derived)      return "state_not_self_derived";
    if (!e->transparent_state_complete) return "transparent_state_incomplete";
    if (!e->sapling_history_complete || !e->sprout_history_complete ||
        !e->nullifier_history_complete)
        return "shielded_history_incomplete";
    if (!e->full_history_replayed)   return "full_history_not_replayed";
    return NULL;
}

/* Reason DIRECTORY_INFLUENCE is withheld; NULL when the network is
 * uncontested. Deliberately a one-fact formula: this capability must be
 * withholdable WITHOUT disturbing any other bit, so it may never consult the
 * provenance facts. "network_contested" is the operator-facing token. */
static const char *directory_influence_denial(const struct sync_evidence *e)
{
    return e->network_uncontested ? NULL : "network_contested";
}

/* Reason EXPORT is withheld; NULL if X holds. */
static const char *export_denial(const struct sync_evidence *e)
{
    if (!e->checkpoint_content_rederived) return "missing_checkpoint_binding";
    if (!e->export_root_rederived)        return "export_root_not_rederived";
    return NULL;
}

uint32_t sync_capabilities_from_evidence(const struct sync_evidence *e,
                                         struct sync_capability_denials *why)
{
    if (why)
        for (int i = 0; i < SYNC_CAP_BIT_COUNT; i++)
            why->reason[i] = NULL;

    if (!e) {
        /* Fail closed: every capability denied for a stable, named reason. */
        if (why)
            for (int i = 0; i < SYNC_CAP_BIT_COUNT; i++)
                why->reason[i] = "no_evidence";
        return SYNC_CAP_NONE;
    }

    const char *proven_why = proven_denial(e);
    const char *self_why = self_derived_denial(e);
    const char *export_why = export_denial(e);
    const char *dir_why = directory_influence_denial(e);
    const bool proven = proven_why == NULL;
    const bool S = self_why == NULL;
    const bool X = export_why == NULL;

    const bool serve = S || (proven && !X);
    const char *serve_why = NULL;
    if (!serve) {
        /* Serve is withheld either because the proven base is incomplete or —
         * in the export-only posture (proven && X && !S) — because the tip is
         * not self-derived. */
        serve_why = proven ? "state_not_self_derived" : proven_why;
    }

    uint32_t mask = SYNC_CAP_NONE;
    struct {
        enum sync_capability cap;
        bool granted;
        const char *deny;
    } bits[] = {
        { SYNC_CAP_SERVE_VALIDATED_TIP, serve, serve_why },
        { SYNC_CAP_WALLET_RECEIVE,      serve, serve_why },
        { SYNC_CAP_WALLET_SPEND,        S,     self_why },
        { SYNC_CAP_MINE,                S,     self_why },
        { SYNC_CAP_EXPORT_BUNDLE,       X,     export_why },
        { SYNC_CAP_SEED_BUNDLE,         S,     self_why },
        { SYNC_CAP_DIRECTORY_INFLUENCE, dir_why == NULL, dir_why },
    };

    for (size_t i = 0; i < sizeof(bits) / sizeof(bits[0]); i++) {
        /* Bit index = trailing-zero position of the single-bit cap. */
        int idx = 0;
        for (uint32_t v = (uint32_t)bits[i].cap; v > 1u; v >>= 1)
            idx++;
        if (bits[i].granted) {
            mask |= (uint32_t)bits[i].cap;
            if (why && idx < SYNC_CAP_BIT_COUNT)
                why->reason[idx] = NULL;
        } else if (why && idx < SYNC_CAP_BIT_COUNT) {
            why->reason[idx] = bits[i].deny ? bits[i].deny : "denied";
        }
    }
    return mask;
}

struct sync_evidence sync_evidence_for_state(enum sync_trust_state st)
{
    /* The proven operational base (assisted readiness) as a reusable tuple. */
    const struct sync_evidence proven_base = {
        .header_chain_verified = true,
        .competitive_chainwork = true,
        .bundle_bytes_verified = true,
        .checkpoint_content_rederived = true,
        .active_tip_locally_validated = true,
    };
    struct sync_evidence e = {0};

    switch (st) {
    case SYNC_TRUST_EMPTY:
        return e;                              /* all false: no evidence */
    case SYNC_TRUST_EXPORT_ROOT_REDERIVED:
        /* ¬S ∧ X: header-chain + re-derived export root, tip not self-derived. */
        e = proven_base;
        e.export_root_rederived = true;
        return e;
    case SYNC_TRUST_ARTIFACT_VERIFIED:
        /* S ∧ ¬X: fully self-derived, export root NOT re-derived. */
        e = proven_base;
        e.state_self_derived = true;
        e.transparent_state_complete = true;
        e.sapling_history_complete = true;
        e.sprout_history_complete = true;
        e.nullifier_history_complete = true;
        e.full_history_replayed = true;
        return e;                              /* export_root_rederived stays false */
    case SYNC_TRUST_RELEASE_ASSISTED_READY:
    case SYNC_TRUST_PEER_ASSISTED_READY:
        /* ¬S ∧ ¬X ∧ proven: assisted operational, borrowed shielded history. */
        return proven_base;
    case SYNC_TRUST_SOVEREIGN:
        /* S ∧ X: every fact established. */
        e = proven_base;
        e.transparent_state_complete = true;
        e.sapling_history_complete = true;
        e.sprout_history_complete = true;
        e.nullifier_history_complete = true;
        e.state_self_derived = true;
        e.full_history_replayed = true;
        e.export_root_rederived = true;
        return e;
    case SYNC_TRUST_STATE_COUNT:
        break;
    }
    return (struct sync_evidence){0};          /* unknown: least privilege */
}

enum sync_posture sync_posture_from_state(enum sync_trust_state st)
{
    switch (st) {
    case SYNC_TRUST_EMPTY:                 return SYNC_POSTURE_EMPTY;
    case SYNC_TRUST_EXPORT_ROOT_REDERIVED: return SYNC_POSTURE_HEADERS_ONLY;
    case SYNC_TRUST_RELEASE_ASSISTED_READY:
    case SYNC_TRUST_PEER_ASSISTED_READY:  return SYNC_POSTURE_ASSISTED_READY;
    case SYNC_TRUST_ARTIFACT_VERIFIED:    return SYNC_POSTURE_SELF_DERIVED_READY;
    case SYNC_TRUST_SOVEREIGN:            return SYNC_POSTURE_SOVEREIGN;
    case SYNC_TRUST_STATE_COUNT:          break;
    }
    return SYNC_POSTURE_EMPTY;                  /* fail closed (display only) */
}

const char *sync_posture_name(enum sync_posture p)
{
    switch (p) {
    case SYNC_POSTURE_EMPTY:            return "empty";
    case SYNC_POSTURE_HEADERS_ONLY:    return "headers_only";
    case SYNC_POSTURE_ASSISTED_READY:  return "assisted_ready";
    case SYNC_POSTURE_SELF_DERIVED_READY: return "self_derived_ready";
    case SYNC_POSTURE_SOVEREIGN:       return "sovereign";
    }
    return "?";
}

/* ── Compile-time bans on impossible capability combinations ─────────── */

/* The per-state masks as compile-time constants (kept byte-identical to the
 * sync_trust_caps() switch arms above) so the invariants below are proven at
 * compile time, not just tested. */
#define ZCL_TRUST_MASK_ARTIFACT                                          \
    (SYNC_CAP_SERVE_VALIDATED_TIP | SYNC_CAP_WALLET_RECEIVE |            \
     SYNC_CAP_WALLET_SPEND | SYNC_CAP_MINE | SYNC_CAP_SEED_BUNDLE)
#define ZCL_TRUST_MASK_ASSISTED                                         \
    (SYNC_CAP_SERVE_VALIDATED_TIP | SYNC_CAP_WALLET_RECEIVE)

/* EMPTY grants nothing; SOVEREIGN uniquely holds the full mask. */
_Static_assert(SYNC_CAP_NONE == 0u, "SYNC_CAP_NONE must be 0");
/* ARTIFACT_VERIFIED must be a strict subset of SOVEREIGN. */
_Static_assert((ZCL_TRUST_MASK_ARTIFACT & ~(unsigned)SYNC_CAP_ALL) == 0u,
               "artifact_verified caps must be a subset of sovereign");
/* MINE ⇒ WALLET_SPEND wherever MINE appears. */
_Static_assert((ZCL_TRUST_MASK_ARTIFACT & SYNC_CAP_MINE) == 0u ||
                   (ZCL_TRUST_MASK_ARTIFACT & SYNC_CAP_WALLET_SPEND) != 0u,
               "MINE must imply WALLET_SPEND (artifact_verified)");
_Static_assert((SYNC_CAP_ALL & SYNC_CAP_MINE) == 0u ||
                   (SYNC_CAP_ALL & SYNC_CAP_WALLET_SPEND) != 0u,
               "MINE must imply WALLET_SPEND (sovereign)");
/* Assisted-ready states never grant MINE or SEED. */
_Static_assert((ZCL_TRUST_MASK_ASSISTED &
                (SYNC_CAP_MINE | SYNC_CAP_SEED_BUNDLE)) == 0u,
               "assisted-ready states must never grant MINE or SEED");
/* SOVEREIGN is the unique holder of EXPORT together with MINE. */
_Static_assert((SYNC_CAP_ALL & SYNC_CAP_EXPORT_BUNDLE) != 0u &&
                   (ZCL_TRUST_MASK_ARTIFACT & SYNC_CAP_EXPORT_BUNDLE) == 0u,
               "only SOVEREIGN combines EXPORT with the self-derived caps");
/* DIRECTORY_INFLUENCE is a NETWORK capability, never a provenance one: no
 * arm of the sync_trust_caps() table may grant it (SYNC_CAP_ALL is the widest
 * arm, so excluding it there excludes it everywhere). */
_Static_assert((SYNC_CAP_ALL & SYNC_CAP_DIRECTORY_INFLUENCE) == 0u,
               "the provenance state table must never grant DIRECTORY_INFLUENCE");
_Static_assert((ZCL_TRUST_MASK_ARTIFACT & SYNC_CAP_DIRECTORY_INFLUENCE) == 0u &&
                   (ZCL_TRUST_MASK_ASSISTED &
                    SYNC_CAP_DIRECTORY_INFLUENCE) == 0u,
               "no trust state grants DIRECTORY_INFLUENCE");
/* The denial array must have a slot for the highest defined bit. */
_Static_assert(SYNC_CAP_DIRECTORY_INFLUENCE_BIT < SYNC_CAP_BIT_COUNT,
               "SYNC_CAP_BIT_COUNT must cover every defined capability bit");
_Static_assert((1u << SYNC_CAP_DIRECTORY_INFLUENCE_BIT) ==
                   (unsigned)SYNC_CAP_DIRECTORY_INFLUENCE,
               "SYNC_CAP_DIRECTORY_INFLUENCE_BIT must index its own bit");

#undef ZCL_TRUST_MASK_ARTIFACT
#undef ZCL_TRUST_MASK_ASSISTED
