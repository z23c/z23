/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bootstrap.stale_offers_only — LOUD signage for a ZRC-0011 bounded
 * first-boot wait (config/state_offer_store.h) that closed with nothing
 * acceptable: every connected peer's newest offer was more than 576 blocks
 * behind that peer's own tip, or no peer offered a state at all. Raised the
 * instant the caller sees STATE_OFFER_DECIDE_FALL_BACK, carrying the newest
 * height any peer offered; cleared on the honest witness (H* climbs past that
 * height, or the store goes on to choose an acceptable offer after all) —
 * never on wall time. Same self-clearing shape as bootstrap.no_state_source.
 *
 * Scenarios:
 *   (1) a silent peer set (nobody offered anything) → raised, height 0.
 *   (2) peers offered only a non-source height (FALL_BACK still names it) →
 *       raised, and the raise's structured facts carry the newest height —
 *       while the blocker's own STABLE reason never embeds that volatile
 *       number (identity churn would defeat blocker.h's rate-limit/escalation
 *       keying).
 *   (3) witness clears the instant H* climbs past the newest stale height.
 *   (4) witness also clears when the store goes on to choose an acceptable
 *       offer, even before H* has climbed.
 *   (5) nothing raises while the bounded wait is still open.
 *
 * make t-fast ONLY=stale_offers_only
 */

#include "test/test_core.h"

#include "chain/checkpoints.h"
#include "conditions/stale_offers_only.h"
#include "config/state_offer_store.h"
#include "jobs/reducer_frontier.h"
#include "util/blocker.h"

#include <stdio.h>
#include <string.h>

#define SOO_ID "bootstrap.stale_offers_only"

/* ── small offer-construction helpers, mirroring test_state_offer_store.c ── */

static void fill_bytes(uint8_t out[32], uint8_t first)
{
    for (size_t i = 0; i < 32; i++)
        out[i] = (uint8_t)(first + i);
}

static void seed_bytes(uint8_t seed[32], uint8_t first)
{
    for (size_t i = 0; i < 32; i++)
        seed[i] = (uint8_t)(first ^ (uint8_t)(i * 7u + 3u));
}

static void make_offer(struct state_offer_v1 *offer, int32_t bundle_height,
                       int32_t tip_height, uint8_t tag)
{
    memset(offer, 0, sizeof(*offer));
    offer->version = STATE_OFFER_VERSION;
    offer->flags = STATE_OFFER_FLAGS_NONE;
    offer->bundle_height = bundle_height;
    offer->offerer_tip_height = tip_height;
    offer->chunk_size = STATE_OFFER_CHUNK_SIZE_BYTES;
    offer->content_bytes = (uint64_t)STATE_OFFER_CHUNK_SIZE_BYTES * 8u;
    offer->num_chunks = 8u;
    offer->kind = (uint16_t)ROM_ARTIFACT_CONSENSUS_BUNDLE;
    fill_bytes(offer->header_hash, (uint8_t)(0x11u + tag));
    fill_bytes(offer->content_digest, tag);
    fill_bytes(offer->chunk_tree_root, (uint8_t)(0x51u + tag));
    fill_bytes(offer->mmb_peaks_digest, 0x71);
    fill_bytes(offer->producer_receipt_id, 0x91);
    offer->issued_unix = UINT64_C(1800000000);
    memset(offer->filename, 0, sizeof(offer->filename));
    memcpy(offer->filename, "consensus-state-bundle-1.sqlite", 31);
    offer->filename_len = 31;

    uint8_t seed[32];
    seed_bytes(seed, 0x0d);
    (void)state_offer_v1_sign(offer, seed);
}

static void an_ip(uint8_t ip[16], uint8_t last)
{
    memset(ip, 0, 16);
    ip[10] = 0xff; ip[11] = 0xff; /* IPv4-mapped */
    ip[12] = 10; ip[13] = 0; ip[14] = 0; ip[15] = last;
}

/* Snapshot the reason string of the raised blocker (empty if absent). */
static void soo_reason(char *out, size_t cap)
{
    out[0] = '\0';
    struct blocker_snapshot snaps[BLOCKER_CAP];
    int n = blocker_snapshot_all(snaps, BLOCKER_CAP);
    for (int i = 0; i < n; i++) {
        if (strcmp(snaps[i].id, SOO_ID) == 0) {
            snprintf(out, cap, "%s", snaps[i].reason);
            return;
        }
    }
}

/* Fill a facts struct from the store's current status, exactly as the real
 * FALL_BACK caller would. */
static void facts_from_store(struct stale_offers_only_facts *f)
{
    struct state_offer_store_status st;
    state_offer_store_status_get(&st);
    f->newest_height_seen = st.newest_height_seen;
    f->peers_offering = st.peers_offering;
    f->offers_seen = st.offers_seen;
    f->baseline_hstar = reducer_frontier_provable_tip_cached();
}

/* ── (1) a silent peer set → raised, height 0 ──────────────────────────────── */

static int raised_when_nothing_offered(void)
{
    int failures = 0;
    TEST_CASE("raised when a silent peer set offers nothing at all") {
        blocker_module_init();
        stale_offers_only_test_reset();
        reducer_frontier_provable_tip_reset();
        state_offer_store_reset();

        struct state_offer_record chosen;
        state_offer_store_note_first_peer(0);
        ASSERT_EQ(state_offer_store_decide(STATE_OFFER_WAIT_MS, &chosen),
                  STATE_OFFER_DECIDE_FALL_BACK);

        struct stale_offers_only_facts f;
        facts_from_store(&f);
        ASSERT(f.newest_height_seen == 0);
        stale_offers_only_raise(&f);

        ASSERT(blocker_exists(SOO_ID));
        ASSERT(stale_offers_only_test_detect());
        ASSERT(blocker_class_for(SOO_ID) == (int)BLOCKER_DEPENDENCY);

        char reason[BLOCKER_REASON_MAX];
        soo_reason(reason, sizeof(reason));
        ASSERT(strstr(reason, "bundles/") != NULL);
    } TEST_END
    return failures;
}

/* ── (2) peers offered only a non-source height → raised, height named in the
 * structured facts, never in the blocker's own stable reason ────────────── */

static int raised_when_only_stale_offers_seen(void)
{
    int failures = 0;
    TEST_CASE("raised when peers offered only a stale/unusable state, naming "
              "the newest height seen in the structured facts") {
        blocker_module_init();
        stale_offers_only_test_reset();
        reducer_frontier_provable_tip_reset();
        state_offer_store_reset();

        uint8_t ip[16];
        an_ip(ip, 31);
        state_offer_store_note_first_peer(5000);

        /* A peer answered, but not with a state source: a header-seed offer
         * still tells the node a height, and the fallback must name it —
         * same distinction config/state_offer_store.h draws. */
        struct state_offer_v1 header_seed;
        make_offer(&header_seed, 870000, 870100, 0x30);
        header_seed.kind = (uint16_t)ROM_ARTIFACT_HEADER_SEED;
        uint8_t seed[32];
        seed_bytes(seed, 0x0d);
        ASSERT_EQ(state_offer_v1_sign(&header_seed, seed), STATE_OFFER_OK);
        ASSERT_EQ(state_offer_store_record(&header_seed, ip, 18034, 9, 6000),
                  STATE_OFFER_STORE_DROPPED_KIND);

        struct state_offer_record chosen;
        ASSERT_EQ(state_offer_store_decide(5000 + STATE_OFFER_WAIT_MS, &chosen),
                  STATE_OFFER_DECIDE_FALL_BACK);

        struct stale_offers_only_facts f;
        facts_from_store(&f);
        ASSERT(f.newest_height_seen == 870000);
        stale_offers_only_raise(&f);

        ASSERT(blocker_exists(SOO_ID));
        ASSERT(stale_offers_only_test_newest_height_seen() == 870000);

        /* The blocker's own identity-keying reason stays STABLE — the
         * volatile height lives in the structured facts/log, never here. */
        char reason[BLOCKER_REASON_MAX];
        soo_reason(reason, sizeof(reason));
        ASSERT(strstr(reason, "870000") == NULL);
    } TEST_END
    return failures;
}

/* ── (3) witness clears on H* climb past the newest stale height ──────────── */

static int witness_clears_on_hstar_climb(void)
{
    int failures = 0;
    TEST_CASE("witness clears once H* climbs past the newest stale height") {
        blocker_module_init();
        stale_offers_only_test_reset();
        reducer_frontier_provable_tip_reset();
        state_offer_store_reset();

        struct stale_offers_only_facts f = {
            .newest_height_seen = 500,
            .peers_offering = 1,
            .offers_seen = 1,
            .baseline_hstar = 0,
        };
        stale_offers_only_raise(&f);
        ASSERT(blocker_exists(SOO_ID));

        /* Still at (or below) the newest stale height → NOT resolved. */
        reducer_frontier_provable_tip_set(500);
        ASSERT(!stale_offers_only_test_witness());
        ASSERT(blocker_exists(SOO_ID));

        /* Climbed past it → resolved, blocker cleared. */
        reducer_frontier_provable_tip_set(501);
        ASSERT(stale_offers_only_test_witness());
        ASSERT(!blocker_exists(SOO_ID));
        ASSERT(!stale_offers_only_test_detect());
    } TEST_END
    return failures;
}

/* ── (4) witness clears when an acceptable offer is chosen, even before H*
 * has climbed past the stale height ───────────────────────────────────────── */

static int witness_clears_on_offer_chosen(void)
{
    int failures = 0;
    TEST_CASE("witness clears when the store chooses an acceptable offer, "
              "even before H* climbs") {
        blocker_module_init();
        stale_offers_only_test_reset();
        reducer_frontier_provable_tip_reset();
        state_offer_store_reset();

        struct stale_offers_only_facts f = {
            .newest_height_seen = 900100,
            .peers_offering = 1,
            .offers_seen = 1,
            .baseline_hstar = 0,
        };
        stale_offers_only_raise(&f);
        ASSERT(blocker_exists(SOO_ID));

        /* H* stays far below the stale height... */
        reducer_frontier_provable_tip_set(10);
        ASSERT(!stale_offers_only_test_witness());

        /* ...but a fresh offer lands and the store chooses it. */
        uint8_t ip[16];
        an_ip(ip, 44);
        struct state_offer_v1 fresh;
        make_offer(&fresh, 900100, 900100, 0x70);
        ASSERT_EQ(state_offer_store_record(&fresh, ip, 18034, 5, 1000),
                  STATE_OFFER_STORE_KEPT);
        struct state_offer_record chosen;
        ASSERT_EQ(state_offer_store_decide(2000, &chosen),
                  STATE_OFFER_DECIDE_FETCH);

        ASSERT(stale_offers_only_test_witness());
        ASSERT(!blocker_exists(SOO_ID));
    } TEST_END
    return failures;
}

/* ── (6) a checkpoint-height offer, far outside the 576-block window, is
 * chosen rather than falling back — the condition never raises ──────────── */

static int no_raise_for_checkpoint_bundle(void)
{
    int failures = 0;
    TEST_CASE("does not raise when the only offer is the checkpoint bundle, "
              "however old") {
        blocker_module_init();
        stale_offers_only_test_reset();
        reducer_frontier_provable_tip_reset();
        state_offer_store_reset();

        struct sha3_utxo_checkpoint fixture;
        memset(&fixture, 0, sizeof(fixture));
        fixture.height = 700000;
        checkpoints_set_sha3_override_for_test(&fixture);

        int32_t tip = fixture.height + 184000; /* far outside the window */
        uint8_t ip[16];
        an_ip(ip, 55);
        struct state_offer_v1 offer;
        make_offer(&offer, fixture.height, tip, 0x90);
        ASSERT_EQ(state_offer_store_record(&offer, ip, 18034, 7, 1000),
                  STATE_OFFER_STORE_KEPT);

        struct state_offer_record chosen;
        ASSERT_EQ(state_offer_store_decide(2000, &chosen),
                  STATE_OFFER_DECIDE_FETCH);

        ASSERT(!blocker_exists(SOO_ID));
        ASSERT(!stale_offers_only_test_detect());

        checkpoints_reset_sha3_override_for_test();
    } TEST_END
    return failures;
}

/* ── (5) nothing raises while the bounded wait is still open ──────────────── */

static int no_raise_while_wait_open(void)
{
    int failures = 0;
    TEST_CASE("does not raise while the bounded wait is still open") {
        blocker_module_init();
        stale_offers_only_test_reset();
        reducer_frontier_provable_tip_reset();
        state_offer_store_reset();

        struct state_offer_record chosen;
        state_offer_store_note_first_peer(5000);
        ASSERT_EQ(state_offer_store_decide(5000 + STATE_OFFER_WAIT_MS - 1,
                                           &chosen),
                  STATE_OFFER_DECIDE_WAIT);

        /* Nothing calls stale_offers_only_raise() on a WAIT decision. */
        ASSERT(!blocker_exists(SOO_ID));
        ASSERT(!stale_offers_only_test_detect());
    } TEST_END
    return failures;
}

int test_stale_offers_only(void);
int test_stale_offers_only(void)
{
    int failures = 0;

    failures += raised_when_nothing_offered();
    failures += raised_when_only_stale_offers_seen();
    failures += witness_clears_on_hstar_climb();
    failures += witness_clears_on_offer_chosen();
    failures += no_raise_for_checkpoint_bundle();
    failures += no_raise_while_wait_open();

    stale_offers_only_test_reset();
    reducer_frontier_provable_tip_reset();
    state_offer_store_reset();
    return failures;
}
