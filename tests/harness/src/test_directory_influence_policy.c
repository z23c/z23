/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Degraded mode + the deep-reorg refusal (T6.2).
 *
 * Two properties this group exists to hold down, both of which are safety
 * claims rather than behaviour details:
 *
 *  1. BLAST RADIUS. Suspecting a netsplit withholds SYNC_CAP_DIRECTORY_
 *     INFLUENCE and provably nothing else. Proven exhaustively over all 2^12
 *     provenance evidence tuples, not by spot-checking a couple of states —
 *     a single formula picking up `network_uncontested` anywhere else would
 *     silently start gating tip-following, relay, the explorer or wallet
 *     viewing, and that is the failure this whole design is arranged to make
 *     impossible.
 *
 *  2. NOTHING FALLS QUIET. The deep-reorg refusal — which with
 *     ZCL_FINALITY_DEPTH = 10 can never resolve itself — raises a named,
 *     stably-identified blocker that resolves to a declared remedy and an
 *     operator decision.
 *
 * Denial and decision TOKENS are asserted verbatim: operators and scripts key
 * on them, so a rename is a break, not a refactor.
 */

#include "test/test_core.h"

#include "conditions/blocker_handoff_registry.h"
#include "jobs/utxo_apply_delta.h"
#include "net/directory_influence_port.h"
#include "services/directory_influence_policy.h"
#include "services/sync_trust_policy.h"
#include "util/blocker.h"
#include "validation/checkpoint.h"
#include "validation/main_constants.h"

#include <string.h>

/* ── 1. An uncontested network grants directory influence ─────────────── */

static int test_uncontested_grants_influence(void)
{
    int failures = 0;
    TEST("directory_influence: an uncontested network grants influence") {
        struct sync_evidence e = sync_evidence_for_state(SYNC_TRUST_SOVEREIGN);
        struct sync_capability_denials why = {0};

        uint32_t caps = directory_influence_caps(&e, true, &why);
        ASSERT((caps & SYNC_CAP_DIRECTORY_INFLUENCE) != 0u);
        ASSERT(why.reason[SYNC_CAP_DIRECTORY_INFLUENCE_BIT] == NULL);

        /* Even an EMPTY-provenance node gets it: directory influence is a
         * network fact, never a reward for provenance. */
        struct sync_evidence bare = {0};
        ASSERT((directory_influence_caps(&bare, true, NULL) &
                SYNC_CAP_DIRECTORY_INFLUENCE) != 0u);

        /* The pure per-entry fold agrees for a brand-new entry. */
        struct directory_influence_input in = {
            .netsplit_suspected = false,
            .split_onset_height = -1,
            .entry_final_height = DIRECTORY_ENTRY_NOT_FINAL,
            .entry_is_root = false,
        };
        struct directory_influence_decision d = {0};
        directory_influence_decide(&in, &d);
        ASSERT(d.influence_admitted);
        ASSERT(!d.fallback_to_roots);
        ASSERT(strcmp(d.token, DIRECTORY_INFLUENCE_TOKEN_GRANTED) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 2. A suspected split withholds ONLY directory influence ──────────── */

static int test_split_withholds_only_directory_influence(void)
{
    int failures = 0;
    TEST("directory_influence: a suspected split withholds ONLY the "
         "directory bit, across every provenance tuple") {
        /* Exhaustive over the twelve provenance facts: 4096 tuples. For each,
         * the ONLY difference between an uncontested and a contested network
         * must be SYNC_CAP_DIRECTORY_INFLUENCE. */
        for (int m = 0; m < (1 << 12); m++) {
            struct sync_evidence e = {0};
            e.header_chain_verified        = (m >>  0) & 1;
            e.competitive_chainwork        = (m >>  1) & 1;
            e.bundle_bytes_verified        = (m >>  2) & 1;
            e.checkpoint_content_rederived = (m >>  3) & 1;
            e.transparent_state_complete   = (m >>  4) & 1;
            e.sapling_history_complete     = (m >>  5) & 1;
            e.sprout_history_complete      = (m >>  6) & 1;
            e.nullifier_history_complete   = (m >>  7) & 1;
            e.state_self_derived           = (m >>  8) & 1;
            e.full_history_replayed        = (m >>  9) & 1;
            e.export_root_rederived        = (m >> 10) & 1;
            e.active_tip_locally_validated = (m >> 11) & 1;

            uint32_t whole = directory_influence_caps(&e, true, NULL);
            uint32_t split = directory_influence_caps(&e, false, NULL);
            ASSERT((whole ^ split) == (uint32_t)SYNC_CAP_DIRECTORY_INFLUENCE);
            /* Every provenance bit survives the split, bit for bit. */
            ASSERT((whole & SYNC_CAP_ALL) == (split & SYNC_CAP_ALL));
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_ungated_capabilities_survive(void)
{
    int failures = 0;
    TEST("directory_influence: tip-serving and wallet-receive survive a "
         "suspected split") {
        /* A fully assisted-ready node: serving a validated tip and receiving
         * in the wallet are granted. Contesting the network must not touch
         * either. Relay, the block explorer and wallet VIEWING are not
         * capability bits at all — they are ungated by construction, which is
         * why no formula in sync_trust_policy.c can reach them. */
        struct sync_evidence e =
            sync_evidence_for_state(SYNC_TRUST_RELEASE_ASSISTED_READY);
        struct sync_capability_denials why = {0};
        uint32_t caps = directory_influence_caps(&e, false, &why);

        ASSERT((caps & SYNC_CAP_SERVE_VALIDATED_TIP) != 0u);
        ASSERT((caps & SYNC_CAP_WALLET_RECEIVE) != 0u);
        ASSERT((caps & SYNC_CAP_DIRECTORY_INFLUENCE) == 0u);
        ASSERT(why.reason[0] == NULL);   /* serve granted */
        ASSERT(why.reason[1] == NULL);   /* receive granted */

        /* Mining and spending are governed by PROVENANCE, not by the network
         * fact: they were already withheld here and stay withheld for the
         * same, unchanged reason. */
        uint32_t whole = directory_influence_caps(&e, true, NULL);
        ASSERT((whole & SYNC_CAP_MINE) == 0u);
        ASSERT((caps & SYNC_CAP_MINE) == 0u);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 3. Stable denial token ───────────────────────────────────────────── */

static int test_denial_token_is_stable(void)
{
    int failures = 0;
    TEST("directory_influence: the denial token is exactly "
         "\"network_contested\" and is stable") {
        struct sync_evidence e = sync_evidence_for_state(SYNC_TRUST_SOVEREIGN);
        struct sync_capability_denials a = {0}, b = {0};

        (void)directory_influence_caps(&e, false, &a);
        (void)directory_influence_caps(&e, false, &b);
        const char *ra = a.reason[SYNC_CAP_DIRECTORY_INFLUENCE_BIT];
        const char *rb = b.reason[SYNC_CAP_DIRECTORY_INFLUENCE_BIT];
        ASSERT(ra != NULL && rb != NULL);
        ASSERT(strcmp(ra, "network_contested") == 0);
        ASSERT(strcmp(ra, rb) == 0);

        /* The all-false floor names it too — no silent denial anywhere. */
        struct sync_evidence floor_e = {0};
        struct sync_capability_denials fw = {0};
        ASSERT(sync_capabilities_from_evidence(&floor_e, &fw) ==
               SYNC_CAP_NONE);
        for (int i = 0; i < SYNC_CAP_BIT_COUNT; i++)
            ASSERT(fw.reason[i] != NULL && fw.reason[i][0] != '\0');
        ASSERT(strcmp(fw.reason[SYNC_CAP_DIRECTORY_INFLUENCE_BIT],
                      "network_contested") == 0);

        /* NULL evidence fails closed with a named reason on the new bit. */
        struct sync_capability_denials nw = {0};
        ASSERT(sync_capabilities_from_evidence(NULL, &nw) == SYNC_CAP_NONE);
        ASSERT(nw.reason[SYNC_CAP_DIRECTORY_INFLUENCE_BIT] != NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 4. Pre-split final entries still resolve; roots always do ────────── */

static int test_pre_split_entries_keep_working(void)
{
    int failures = 0;
    TEST("directory_influence: pre-split final entries resolve, newer ones "
         "gain nothing, roots are never gated") {
        struct directory_influence_input in = {
            .netsplit_suspected = true,
            .split_onset_height = 1000,
            .entry_final_height = 999,
            .entry_is_root = false,
        };
        struct directory_influence_decision d = {0};

        /* Final one block BEFORE the onset: keeps working. */
        directory_influence_decide(&in, &d);
        ASSERT(d.influence_admitted);
        ASSERT(d.fallback_to_roots);
        ASSERT(strcmp(d.token, DIRECTORY_INFLUENCE_TOKEN_PRE_SPLIT) == 0);

        /* Final exactly AT the onset height: not pre-split. The boundary is
         * strict on purpose — the onset height is the first height whose
         * contents we are no longer willing to vouch for. */
        in.entry_final_height = 1000;
        directory_influence_decide(&in, &d);
        ASSERT(!d.influence_admitted);
        ASSERT(strcmp(d.token, DIRECTORY_INFLUENCE_TOKEN_CONTESTED) == 0);

        /* Minted after the split: nothing. */
        in.entry_final_height = 1200;
        directory_influence_decide(&in, &d);
        ASSERT(!d.influence_admitted);
        ASSERT(strcmp(d.token, DIRECTORY_INFLUENCE_TOKEN_CONTESTED) == 0);

        /* Never finalized: nothing. */
        in.entry_final_height = DIRECTORY_ENTRY_NOT_FINAL;
        directory_influence_decide(&in, &d);
        ASSERT(!d.influence_admitted);
        ASSERT(strcmp(d.token, DIRECTORY_INFLUENCE_TOKEN_CONTESTED) == 0);

        /* Unknown onset with a suspicion standing: withhold, never guess. */
        in.split_onset_height = -1;
        in.entry_final_height = 10;
        directory_influence_decide(&in, &d);
        ASSERT(!d.influence_admitted);
        ASSERT(strcmp(d.token, DIRECTORY_INFLUENCE_TOKEN_CONTESTED) == 0);

        /* The always-present roots are what degraded mode falls back TO, so
         * they are admitted in every combination. */
        in.entry_is_root = true;
        directory_influence_decide(&in, &d);
        ASSERT(d.influence_admitted);
        ASSERT(d.fallback_to_roots);
        ASSERT(strcmp(d.token, DIRECTORY_INFLUENCE_TOKEN_ROOT) == 0);

        /* Fail closed on no input, and never write through a NULL out. */
        directory_influence_decide(NULL, &d);
        ASSERT(!d.influence_admitted);
        ASSERT(d.fallback_to_roots);
        ASSERT(strcmp(d.token, DIRECTORY_INFLUENCE_TOKEN_NO_INPUT) == 0);
        directory_influence_decide(&in, NULL); /* must not crash */
        PASS();
    } _test_next:;
    return failures;
}

/* ── 5. The live posture: onset, blocker, restore, port ───────────────── */

static int test_live_posture_and_blocker(void)
{
    int failures = 0;
    TEST("directory_influence: engaging degraded mode names "
         "SUSPECTED_NETSPLIT and restoring clears it") {
        directory_influence_test_reset();
        directory_influence_register_port();

        /* Whole network: influence granted, nothing named. */
        ASSERT(directory_influence_observe(false, 5000, NULL));
        ASSERT(directory_influence_granted());
        ASSERT(directory_influence_split_onset_height() < 0);
        ASSERT(!blocker_exists(DIRECTORY_INFLUENCE_BLOCKER_ID));
        ASSERT(directory_influence_port_verdict() ==
               DIRECTORY_INFLUENCE_GRANTED);

        /* Suspicion: influence withheld, onset recorded, blocker named. */
        ASSERT(!directory_influence_observe(
            true, 5000, "SUSPECTED_NETSPLIT: rival_groups=2 rival_peers=3"));
        ASSERT(!directory_influence_granted());
        ASSERT(directory_influence_split_onset_height() == 5000);
        ASSERT(blocker_exists(DIRECTORY_INFLUENCE_BLOCKER_ID));
        ASSERT(directory_influence_port_verdict() ==
               DIRECTORY_INFLUENCE_WITHHELD);
        ASSERT(!directory_influence_port_admits());

        /* The onset does not drift as the chain advances under suspicion —
         * it is the boundary the pre-split rule is measured against. */
        ASSERT(!directory_influence_observe(true, 5100, NULL));
        ASSERT(directory_influence_split_onset_height() == 5000);

        /* Per-entry admission against the standing verdict. */
        struct directory_influence_decision d = {0};
        ASSERT(directory_influence_admit_entry(4999, false, &d));
        ASSERT(strcmp(d.token, DIRECTORY_INFLUENCE_TOKEN_PRE_SPLIT) == 0);
        ASSERT(!directory_influence_admit_entry(5050, false, &d));
        ASSERT(strcmp(d.token, DIRECTORY_INFLUENCE_TOKEN_CONTESTED) == 0);
        ASSERT(directory_influence_admit_entry(DIRECTORY_ENTRY_NOT_FINAL, true,
                                               &d));
        ASSERT(strcmp(d.token, DIRECTORY_INFLUENCE_TOKEN_ROOT) == 0);
        /* Same answers through the core/modules/net port. */
        ASSERT(directory_influence_port_admits_entry(4999, false));
        ASSERT(!directory_influence_port_admits_entry(5050, false));
        ASSERT(directory_influence_port_admits_entry(5050, true));

        /* Restore: blocker cleared, influence back, onset forgotten. */
        ASSERT(directory_influence_observe(false, 5200, NULL));
        ASSERT(directory_influence_granted());
        ASSERT(!blocker_exists(DIRECTORY_INFLUENCE_BLOCKER_ID));
        ASSERT(directory_influence_split_onset_height() < 0);
        ASSERT(directory_influence_admit_entry(9999, false, &d));
        ASSERT(strcmp(d.token, DIRECTORY_INFLUENCE_TOKEN_GRANTED) == 0);

        /* An unregistered port is UNGOVERNED and admits — a tool or fuzz
         * target that links core/modules/net alone behaves exactly as before. */
        directory_influence_port_set(NULL);
        ASSERT(directory_influence_port_verdict() ==
               DIRECTORY_INFLUENCE_UNGOVERNED);
        ASSERT(directory_influence_port_admits());
        ASSERT(directory_influence_port_admits_entry(1, false));

        directory_influence_test_reset();
        PASS();
    } _test_next:;
    return failures;
}

static int test_netsplit_blocker_declares_its_handoff(void)
{
    int failures = 0;
    TEST("directory_influence: SUSPECTED_NETSPLIT declares an automatic "
         "remedy and an operator decision") {
        const char *remedy = NULL, *decision = NULL;
        bool needs_human = true;
        ASSERT(blocker_handoff_lookup(DIRECTORY_INFLUENCE_BLOCKER_ID, &remedy,
                                      &decision, &needs_human));
        ASSERT(remedy != NULL);
        ASSERT(strcmp(remedy, "netsplit_degraded_mode") == 0);
        ASSERT(!needs_human);   /* the condition self-clears it */
        /* And therefore NO decision text: blocker_handoff_lookup surfaces one
         * only for an OWNER hand-off. The operator-facing sentence rides in
         * the blocker's own reason, which is what `dumpstate blocker` shows. */
        ASSERT(decision != NULL && decision[0] == '\0');

        directory_influence_test_reset();
        (void)directory_influence_observe(true, 4242, NULL);
        struct blocker_snapshot s;
        memset(&s, 0, sizeof(s));
        ASSERT(blocker_find_by_id_prefix(DIRECTORY_INFLUENCE_BLOCKER_ID, &s));
        ASSERT(strstr(s.reason, "DEGRADED") != NULL);
        ASSERT(strstr(s.reason, "h=4242") != NULL);
        /* It must say what is NOT withheld, or an operator reads a halt. */
        ASSERT(strstr(s.reason, "Tip-follow") != NULL);
        ASSERT(strstr(s.reason, "wallet-view unaffected") != NULL);
        directory_influence_test_reset();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 6. The deep-reorg refusal is no longer silent ────────────────────── */

#define REORG_REFUSAL_ID "chain.reorg_refused_below_finality"

static int test_deep_reorg_refusal_fires(void)
{
    int failures = 0;
    TEST("deep_reorg: a refusal below the finality floor raises a named "
         "PERMANENT blocker") {
        blocker_clear(REORG_REFUSAL_ID);
        ASSERT(!blocker_exists(REORG_REFUSAL_ID));

        /* tip 5000, fork 4000: depth 1000, far below the floor. This is the
         * exact call both production refusal paths make. */
        ASSERT(height_is_immutable(5000, 4000));
        utxo_apply_reorg_name_refusal_blocker(5000, 4000);

        ASSERT(blocker_exists(REORG_REFUSAL_ID));
        ASSERT(blocker_class_for(REORG_REFUSAL_ID) == BLOCKER_PERMANENT);

        struct blocker_snapshot s;
        memset(&s, 0, sizeof(s));
        ASSERT(blocker_find_by_id_prefix(REORG_REFUSAL_ID, &s));
        ASSERT(strcmp(s.id, REORG_REFUSAL_ID) == 0);
        ASSERT(strcmp(s.owner_subsystem, "utxo_apply") == 0);
        /* The reason names the class, the heights and the depth. */
        ASSERT(strstr(s.reason, "reorg_below_finality") != NULL);
        ASSERT(strstr(s.reason, "tip=5000") != NULL);
        ASSERT(strstr(s.reason, "fork=4000") != NULL);
        ASSERT(strstr(s.reason, "depth=1000") != NULL);

        /* A fork point that is NOT immutable is a different fault and does
         * not borrow the finality name. height_is_immutable is what decides
         * that, and it is READ, never redefined here. */
        blocker_clear(REORG_REFUSAL_ID);
        ASSERT(!height_is_immutable(5000, 4995));
        utxo_apply_reorg_name_refusal_blocker(5000, 4995);
        memset(&s, 0, sizeof(s));
        ASSERT(blocker_find_by_id_prefix(REORG_REFUSAL_ID, &s));
        ASSERT(strstr(s.reason, "reorg_refused_unclassified") != NULL);
        ASSERT(strstr(s.reason, "reorg_below_finality") == NULL);

        blocker_clear(REORG_REFUSAL_ID);
        PASS();
    } _test_next:;
    return failures;
}

static int test_deep_reorg_refusal_declares_its_handoff(void)
{
    int failures = 0;
    TEST("deep_reorg: the refusal blocker declares a remedy and an operator "
         "decision") {
        const char *remedy = NULL, *decision = NULL;
        bool needs_human = false;
        ASSERT(blocker_handoff_lookup(REORG_REFUSAL_ID, &remedy, &decision,
                                      &needs_human));
        ASSERT(remedy != NULL && strcmp(remedy, "OWNER") == 0);
        ASSERT(needs_human);
        ASSERT(decision != NULL && decision[0] != '\0');
        /* The decision must name both options, or it is not a decision. */
        ASSERT(strstr(decision, "OPTION A") != NULL);
        ASSERT(strstr(decision, "OPTION B") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* The finality constant this whole refusal hangs on, and the two predicates
 * that read it, live where the docs now say they do. A wrong citation cost
 * this task a wrong-file lookup; assert the semantics so the next reader can
 * trust the numbers even if a doc rots. */
static int test_finality_depth_semantics(void)
{
    int failures = 0;
    TEST("deep_reorg: reorg_is_allowed and height_is_immutable agree on "
         "ZCL_FINALITY_DEPTH") {
        const char *why = NULL;
        ASSERT(ZCL_FINALITY_DEPTH == 10);
        /* Exactly at the depth: allowed, and the fork point is immutable. */
        ASSERT(reorg_is_allowed(100, 100 - ZCL_FINALITY_DEPTH, &why));
        ASSERT(height_is_immutable(100, 100 - ZCL_FINALITY_DEPTH));
        /* One deeper: refused, with a reason. */
        why = NULL;
        ASSERT(!reorg_is_allowed(100, 100 - ZCL_FINALITY_DEPTH - 1, &why));
        ASSERT(why != NULL && why[0] != '\0');
        /* Refusal always implies the fork point is already immutable. */
        ASSERT(height_is_immutable(100, 100 - ZCL_FINALITY_DEPTH - 1));
        PASS();
    } _test_next:;
    return failures;
}

int test_directory_influence_policy(void)
{
    int failures = 0;
    failures += test_uncontested_grants_influence();
    failures += test_split_withholds_only_directory_influence();
    failures += test_ungated_capabilities_survive();
    failures += test_denial_token_is_stable();
    failures += test_pre_split_entries_keep_working();
    failures += test_live_posture_and_blocker();
    failures += test_netsplit_blocker_declares_its_handoff();
    failures += test_deep_reorg_refusal_fires();
    failures += test_deep_reorg_refusal_declares_its_handoff();
    failures += test_finality_depth_semantics();
    return failures;
}
