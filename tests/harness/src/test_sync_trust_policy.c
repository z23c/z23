/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Sync trust → capability policy (services/sync_trust_policy.h). Step-0
 * contract test: the full 8-combo derivation matrix + per-state capability
 * masks + the impossible-combo bans. WF3 lanes 3B/3C/3D add the per-site
 * equivalence tests (old expr == table answer) as they route each gate. */

#include "test/test_core.h"
#include "services/sync_trust_policy.h"
#include <string.h>

/* Expected trust state for each (proven, refold, self_derived) combo, per the
 * plan's derivation: S=self_derived, X=proven&&refold. */
static enum sync_trust_state expected(bool proven, bool refold, bool S)
{
    bool X = proven && refold;
    if (S && X) return SYNC_TRUST_SOVEREIGN;
    if (S && !X) return SYNC_TRUST_ARTIFACT_VERIFIED;
    if (!S && X) return SYNC_TRUST_EXPORT_ROOT_REDERIVED;
    if (!S && !X && proven) return SYNC_TRUST_RELEASE_ASSISTED_READY;
    return SYNC_TRUST_EMPTY;
}

static int test_trust_derive_matrix(void)
{
    int failures = 0;
    TEST("sync_trust: all 8 (proven,refold,self) combos derive as specified") {
        for (int c = 0; c < 8; c++) {
            bool proven = (c >> 2) & 1;
            bool refold = (c >> 1) & 1;
            bool S      = (c >> 0) & 1;
            enum sync_trust_state got = sync_trust_derive(proven, refold, S);
            ASSERT(got == expected(proven, refold, S));
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_trust_caps(void)
{
    int failures = 0;
    TEST("sync_trust: per-state capability masks match the doctrine") {
        /* SOVEREIGN uniquely holds every capability. */
        ASSERT(sync_trust_caps(SYNC_TRUST_SOVEREIGN) == SYNC_CAP_ALL);
        /* EMPTY holds none. */
        ASSERT(sync_trust_caps(SYNC_TRUST_EMPTY) == SYNC_CAP_NONE);
        /* EXPORT_ROOT_REDERIVED == export only (X path). */
        ASSERT(sync_trust_caps(SYNC_TRUST_EXPORT_ROOT_REDERIVED) ==
               SYNC_CAP_EXPORT_BUNDLE);
        /* ARTIFACT_VERIFIED grants MINE + SEED but NOT EXPORT (S, ¬X). */
        uint32_t art = sync_trust_caps(SYNC_TRUST_ARTIFACT_VERIFIED);
        ASSERT(art & SYNC_CAP_MINE);
        ASSERT(art & SYNC_CAP_SEED_BUNDLE);
        ASSERT(!(art & SYNC_CAP_EXPORT_BUNDLE));
        /* MINE ⇒ WALLET_SPEND. */
        ASSERT(art & SYNC_CAP_WALLET_SPEND);
        /* Assisted-ready never mines or seeds. */
        uint32_t rel = sync_trust_caps(SYNC_TRUST_RELEASE_ASSISTED_READY);
        ASSERT(!(rel & (SYNC_CAP_MINE | SYNC_CAP_SEED_BUNDLE)));
        ASSERT(!(sync_trust_caps(SYNC_TRUST_PEER_ASSISTED_READY) &
                 (SYNC_CAP_MINE | SYNC_CAP_SEED_BUNDLE)));
        PASS();
    } _test_next:;
    return failures;
}

static int test_trust_cap_allowed_and_name(void)
{
    int failures = 0;
    TEST("sync_trust: cap_allowed reflects the mask; names round-trip") {
        ASSERT(sync_trust_cap_allowed(SYNC_TRUST_SOVEREIGN, SYNC_CAP_EXPORT_BUNDLE));
        ASSERT(!sync_trust_cap_allowed(SYNC_TRUST_ARTIFACT_VERIFIED,
                                       SYNC_CAP_EXPORT_BUNDLE));
        ASSERT(!sync_trust_cap_allowed(SYNC_TRUST_EMPTY, SYNC_CAP_MINE));
        for (int s = 0; s < SYNC_TRUST_STATE_COUNT; s++)
            ASSERT(strcmp(sync_trust_state_name((enum sync_trust_state)s), "?") != 0);
        ASSERT(strcmp(sync_trust_state_name((enum sync_trust_state)SYNC_TRUST_STATE_COUNT),
                      "?") == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Per-site equivalence: for ALL 8 combos of (proven, refold, self_derived) the
 * central table answer equals the LITERAL old boolean expression each routed
 * gate site used before centralization. This is the behavior-preservation
 * proof WF3 lanes 3B/3C/3D rely on — the derivation is the single source of
 * truth, and every site's old provenance predicate is exactly reproduced.
 *
 *   EXPORT (sites a+b: bundle_exporter.bx_qualified,
 *           consensus_state_snapshot_export_proof) — old expr: proven && refold
 *           == X, independent of self_derived.
 *   MINE / SPEND (site c: sovereignty_guard_allow) — old expr: self_derived
 *           == S, independent of proven/refold.
 *   SEED (site d: boot_snapshot_offer, lane B2) — old expr: self_derived == S.
 */
static int test_trust_per_site_equivalence(void)
{
    int failures = 0;
    TEST("sync_trust: per-site table answer == old boolean expr (all 8 combos)") {
        for (int c = 0; c < 8; c++) {
            bool proven = (c >> 2) & 1;
            bool refold = (c >> 1) & 1;
            bool S      = (c >> 0) & 1;
            enum sync_trust_state st = sync_trust_derive(proven, refold, S);

            /* Site a/b — EXPORT: old expr was (proven && refold), i.e. X. */
            bool old_export = proven && refold;
            ASSERT(sync_trust_cap_allowed(st, SYNC_CAP_EXPORT_BUNDLE) ==
                   old_export);

            /* Site c — MINE and WALLET_SPEND: old expr was self_derived. */
            ASSERT(sync_trust_cap_allowed(st, SYNC_CAP_MINE) == S);
            ASSERT(sync_trust_cap_allowed(st, SYNC_CAP_WALLET_SPEND) == S);

            /* Site d — SEED_BUNDLE: old expr was self_derived. */
            ASSERT(sync_trust_cap_allowed(st, SYNC_CAP_SEED_BUNDLE) == S);
        }
        PASS();
    } _test_next:;
    return failures;
}

/* Behavior preservation: the evidence lattice reproduces the state table.
 * For EVERY defined state, the caps derived from that state's canonical
 * evidence tuple equal the state table's caps — the guarantee that moving
 * authorization onto named evidence facts changed HOW caps are expressed, not
 * WHAT is granted. */
static int test_evidence_reproduces_table(void)
{
    int failures = 0;
    TEST("sync_trust: caps_from_evidence(evidence_for_state(st)) == caps(st)") {
        for (int s = 0; s < SYNC_TRUST_STATE_COUNT; s++) {
            enum sync_trust_state st = (enum sync_trust_state)s;
            struct sync_evidence e = sync_evidence_for_state(st);
            uint32_t derived = sync_capabilities_from_evidence(&e, NULL);
            ASSERT(derived == sync_trust_caps(st));
        }
        PASS();
    } _test_next:;
    return failures;
}

/* Orthogonality is representable: a state with export-but-not-serve
 * (EXPORT_ROOT_REDERIVED) and one with serve-but-not-export (ARTIFACT_VERIFIED)
 * both exist — neither is a superset, so any ordinal comparison is a bug. */
static int test_orthogonality_representable(void)
{
    int failures = 0;
    TEST("sync_trust: export-not-serve and serve-not-export states both exist") {
        uint32_t exp_only = sync_trust_caps(SYNC_TRUST_EXPORT_ROOT_REDERIVED);
        ASSERT(exp_only & SYNC_CAP_EXPORT_BUNDLE);
        ASSERT(!(exp_only & SYNC_CAP_SERVE_VALIDATED_TIP));

        uint32_t art = sync_trust_caps(SYNC_TRUST_ARTIFACT_VERIFIED);
        ASSERT(art & SYNC_CAP_SERVE_VALIDATED_TIP);
        ASSERT(!(art & SYNC_CAP_EXPORT_BUNDLE));

        /* Neither mask is a subset of the other → orthogonal, not ordinal. */
        ASSERT((exp_only & ~art) != 0u);
        ASSERT((art & ~exp_only) != 0u);
        PASS();
    } _test_next:;
    return failures;
}

/* The display posture authorizes nothing: it is a pure label. There is no
 * caps-from-posture surface (capabilities are a function of state/evidence
 * only), and every state maps to a stable posture name. */
static int test_posture_is_display_only(void)
{
    int failures = 0;
    TEST("sync_trust: posture is display-only and never authorizes") {
        ASSERT(sync_posture_from_state(SYNC_TRUST_EMPTY) == SYNC_POSTURE_EMPTY);
        ASSERT(sync_posture_from_state(SYNC_TRUST_EXPORT_ROOT_REDERIVED) ==
               SYNC_POSTURE_HEADERS_ONLY);
        ASSERT(sync_posture_from_state(SYNC_TRUST_ARTIFACT_VERIFIED) ==
               SYNC_POSTURE_SELF_DERIVED_READY);
        ASSERT(sync_posture_from_state(SYNC_TRUST_RELEASE_ASSISTED_READY) ==
               SYNC_POSTURE_ASSISTED_READY);
        ASSERT(sync_posture_from_state(SYNC_TRUST_PEER_ASSISTED_READY) ==
               SYNC_POSTURE_ASSISTED_READY);
        ASSERT(sync_posture_from_state(SYNC_TRUST_SOVEREIGN) ==
               SYNC_POSTURE_SOVEREIGN);
        /* Two orthogonal states can share a posture (RELEASE/PEER assisted),
         * yet their caps come from the mask, not the shared label. */
        ASSERT(strcmp(sync_posture_name(sync_posture_from_state(
                          SYNC_TRUST_RELEASE_ASSISTED_READY)),
                      "assisted_ready") == 0);
        for (int p = SYNC_POSTURE_EMPTY; p <= SYNC_POSTURE_SOVEREIGN; p++)
            ASSERT(strcmp(sync_posture_name((enum sync_posture)p), "?") != 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Every withheld capability carries a stable, non-empty denial reason, and
 * granted capabilities carry none (NULL). Reasons are stable across calls. */
static int test_denials_have_stable_reasons(void)
{
    int failures = 0;
    TEST("sync_trust: every denial has a stable reason, grants have none") {
        /* All-false floor: every capability denied, each with a reason. */
        struct sync_evidence empty = {0};
        struct sync_capability_denials why = {0};
        uint32_t caps = sync_capabilities_from_evidence(&empty, &why);
        ASSERT(caps == SYNC_CAP_NONE);
        for (int i = 0; i < SYNC_CAP_BIT_COUNT; i++) {
            ASSERT(why.reason[i] != NULL);
            ASSERT(why.reason[i][0] != '\0');
        }
        /* Named, expected tokens on the floor. */
        ASSERT(strcmp(why.reason[4] /* EXPORT_BUNDLE bit */,
                      "missing_checkpoint_binding") == 0);

        /* ARTIFACT tuple: EXPORT withheld (export root not re-derived), all
         * self-derived caps granted (NULL reason). */
        struct sync_evidence art =
            sync_evidence_for_state(SYNC_TRUST_ARTIFACT_VERIFIED);
        struct sync_capability_denials aw = {0};
        uint32_t acaps = sync_capabilities_from_evidence(&art, &aw);
        ASSERT(acaps == sync_trust_caps(SYNC_TRUST_ARTIFACT_VERIFIED));
        ASSERT(aw.reason[4] != NULL); /* EXPORT bit denied */
        ASSERT(strcmp(aw.reason[4], "export_root_not_rederived") == 0);
        ASSERT(aw.reason[2] == NULL); /* WALLET_SPEND granted */
        ASSERT(aw.reason[3] == NULL); /* MINE granted */

        /* Stability: a second call yields identical reason pointers/tokens. */
        struct sync_capability_denials aw2 = {0};
        (void)sync_capabilities_from_evidence(&art, &aw2);
        for (int i = 0; i < SYNC_CAP_BIT_COUNT; i++) {
            if (aw.reason[i] == NULL) {
                ASSERT(aw2.reason[i] == NULL);
            } else {
                ASSERT(aw2.reason[i] != NULL);
                ASSERT(strcmp(aw.reason[i], aw2.reason[i]) == 0);
            }
        }

        /* NULL evidence fails closed with a named reason on every bit. */
        struct sync_capability_denials nw = {0};
        ASSERT(sync_capabilities_from_evidence(NULL, &nw) == SYNC_CAP_NONE);
        for (int i = 0; i < SYNC_CAP_BIT_COUNT; i++)
            ASSERT(nw.reason[i] != NULL);
        PASS();
    } _test_next:;
    return failures;
}

int test_sync_trust_policy(void)
{
    int failures = 0;
    failures += test_trust_derive_matrix();
    failures += test_trust_caps();
    failures += test_trust_cap_allowed_and_name();
    failures += test_trust_per_site_equivalence();
    failures += test_evidence_reproduces_table();
    failures += test_orthogonality_representable();
    failures += test_posture_is_display_only();
    failures += test_denials_have_stable_reasons();
    return failures;
}
