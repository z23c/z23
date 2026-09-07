/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Acceptance for the first-boot state-offer decision (ZRC-0011).
 *
 * The four things this store must get right, each proved on its own:
 *   1. It picks the NEWEST acceptable offer, and a stale one never becomes
 *      acceptable by arriving later or from a friendlier peer.
 *   2. A bundle that fails verification is discarded, its offerer is struck,
 *      and the NEXT offer is tried — never the same one again.
 *   3. The bounded wait ends by NAMING the newest height it saw, so an operator
 *      reads "your peers are all stale, this stale" instead of watching a
 *      silent genesis fold.
 *   4. Nothing an unauthenticated peer sends can make the store grow. */

#include "test/test_core.h"

#include "config/state_offer_service.h"
#include "config/state_offer_store.h"
#include "chain/checkpoints.h"
#include "vcs/zcode_dht_identity.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

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

/* A signed, in-window consensus-bundle offer whose content digest is keyed by
 * `tag`, so two offers differ exactly where dedup looks. */
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

static int picks_newest_acceptable(void)
{
    int failures = 0;
    TEST_CASE("the store picks the newest acceptable offer") {
        struct state_offer_v1 old_o, new_o, mid_o;
        struct state_offer_record chosen;
        uint8_t ip[16];
        an_ip(ip, 7);
        state_offer_store_reset();

        make_offer(&old_o, 900000, 900100, 0x20);
        make_offer(&mid_o, 900050, 900100, 0x40);
        make_offer(&new_o, 900100, 900100, 0x60);

        /* Deliberately out of order: the choice must not depend on arrival. */
        ASSERT_EQ(state_offer_store_record(&mid_o, ip, 18034, 2, 1000),
                  STATE_OFFER_STORE_KEPT);
        ASSERT_EQ(state_offer_store_record(&new_o, ip, 18034, 3, 1100),
                  STATE_OFFER_STORE_KEPT);
        ASSERT_EQ(state_offer_store_record(&old_o, ip, 18034, 1, 1200),
                  STATE_OFFER_STORE_KEPT);

        ASSERT_EQ(state_offer_store_decide(2000, &chosen),
                  STATE_OFFER_DECIDE_FETCH);
        ASSERT(chosen.offer.bundle_height == 900100);
        ASSERT(memcmp(chosen.offer.content_digest, new_o.content_digest, 32) ==
               0);
        ASSERT(chosen.file_service_port == 18034);
        ASSERT(state_offer_store_newest_height_seen() == 900100);

        /* An offer FETCH is decided on is not handed out twice. */
        state_offer_store_note_fetching(chosen.offer.content_digest);
        struct state_offer_record second;
        ASSERT_EQ(state_offer_store_decide(2000, &second),
                  STATE_OFFER_DECIDE_FETCH);
        ASSERT(second.offer.bundle_height == 900050);
    } TEST_END
    return failures;
}

static int stale_offer_never_chosen(void)
{
    int failures = 0;
    TEST_CASE("a stale offer is refused however it arrives") {
        struct state_offer_v1 stale, fresh;
        struct state_offer_record chosen;
        uint8_t ip[16];
        an_ip(ip, 8);
        state_offer_store_reset();

        /* 577 behind the OFFERING peer's own tip: one block past the rule. It
         * is refused as malformed, so it can never be retained, never be
         * chosen, and never raise the newest-height-seen number a fallback
         * would go on to report. */
        make_offer(&stale, 900100 - 577, 900100, 0x20);
        ASSERT_EQ(state_offer_v1_validate(&stale), STATE_OFFER_STALE);
        ASSERT_EQ(state_offer_store_record(&stale, ip, 18034, 1, 1000),
                  STATE_OFFER_STORE_DROPPED_INVALID);
        ASSERT(state_offer_store_newest_height_seen() == 0);
        ASSERT_EQ(state_offer_store_decide(2000, &chosen),
                  STATE_OFFER_DECIDE_WAIT);

        /* Exactly 576 behind is the last acceptable offer. */
        make_offer(&fresh, 900100 - 576, 900100, 0x40);
        ASSERT_EQ(state_offer_store_record(&fresh, ip, 18034, 1, 1100),
                  STATE_OFFER_STORE_KEPT);
        ASSERT_EQ(state_offer_store_decide(2000, &chosen),
                  STATE_OFFER_DECIDE_FETCH);
        ASSERT(chosen.offer.bundle_height == 900100 - 576);

        /* A peer cannot buy freshness by claiming a bigger tip than it holds:
         * the row is refused for naming a height above its own tip. */
        struct state_offer_v1 above;
        make_offer(&above, 900101, 900100, 0x60);
        ASSERT_EQ(state_offer_store_record(&above, ip, 18034, 2, 1200),
                  STATE_OFFER_STORE_DROPPED_INVALID);
    } TEST_END
    return failures;
}

static int bad_bundle_discards_and_tries_next(void)
{
    int failures = 0;
    TEST_CASE("a bundle that fails verification is dropped and the next tried") {
        struct state_offer_v1 bad, good;
        struct state_offer_record chosen;
        uint8_t ip_bad[16], ip_good[16];
        an_ip(ip_bad, 11);
        an_ip(ip_good, 12);
        state_offer_store_reset();

        make_offer(&bad, 900100, 900100, 0x20);   /* newest — chosen first */
        make_offer(&good, 900090, 900100, 0x40);
        ASSERT_EQ(state_offer_store_record(&bad, ip_bad, 18034, 5, 1000),
                  STATE_OFFER_STORE_KEPT);
        ASSERT_EQ(state_offer_store_record(&good, ip_good, 18035, 6, 1000),
                  STATE_OFFER_STORE_KEPT);

        ASSERT_EQ(state_offer_store_decide(2000, &chosen),
                  STATE_OFFER_DECIDE_FETCH);
        ASSERT(chosen.offer.bundle_height == 900100);
        ASSERT(chosen.peer_id == 5);

        /* The fetched bytes did not match the committed digest. */
        state_offer_store_note_bad(chosen.offer.content_digest, chosen.peer_id);
        ASSERT(state_offer_store_peer_strikes(5) == 1);
        ASSERT(state_offer_store_peer_strikes(6) == 0);
        ASSERT(state_offer_store_digest_is_bad(bad.content_digest));

        /* The NEXT offer is tried, from the other peer, at the other port. */
        ASSERT_EQ(state_offer_store_decide(2100, &chosen),
                  STATE_OFFER_DECIDE_FETCH);
        ASSERT(chosen.offer.bundle_height == 900090);
        ASSERT(chosen.peer_id == 6);
        ASSERT(chosen.file_service_port == 18035);

        /* Re-offering the SAME rejected bundle — even by an innocent third
         * peer — does not resurrect it for this run. */
        ASSERT_EQ(state_offer_store_record(&bad, ip_good, 18035, 6, 2200),
                  STATE_OFFER_STORE_DROPPED_BAD);

        struct state_offer_store_status st;
        state_offer_store_status_get(&st);
        ASSERT(st.offers_rejected == 1);
        ASSERT(st.chosen_height == 900090);
    } TEST_END
    return failures;
}

static int bounded_wait_names_the_newest_height(void)
{
    int failures = 0;
    TEST_CASE("the bounded wait falls back naming the newest height seen") {
        struct state_offer_record chosen;
        struct state_offer_store_status st;
        struct state_offer_v1 header_seed;
        uint8_t ip[16];
        an_ip(ip, 21);
        state_offer_store_reset();

        /* Before any peer there is nobody who could have answered, so the
         * window has not started and the verdict is WAIT however late it is. */
        ASSERT(!state_offer_store_wait_armed());
        ASSERT_EQ(state_offer_store_decide(999999999, &chosen),
                  STATE_OFFER_DECIDE_WAIT);

        state_offer_store_note_first_peer(5000);
        ASSERT(state_offer_store_wait_armed());
        /* A second peer does not restart the clock. */
        state_offer_store_note_first_peer(90000);

        ASSERT_EQ(state_offer_store_decide(5000, &chosen),
                  STATE_OFFER_DECIDE_WAIT);
        /* One millisecond inside the window is still WAIT — the node is doing
         * headers, not stalling, so waiting costs it nothing. */
        ASSERT_EQ(state_offer_store_decide(5000 + STATE_OFFER_WAIT_MS - 1,
                                           &chosen),
                  STATE_OFFER_DECIDE_WAIT);

        /* A peer offered a header seed: not a state source, so it is not
         * retained — but it DID tell us a height, and the fallback must say so
         * rather than claim nothing was offered. */
        make_offer(&header_seed, 870000, 870100, 0x30);
        header_seed.kind = (uint16_t)ROM_ARTIFACT_HEADER_SEED;
        uint8_t seed[32];
        seed_bytes(seed, 0x0d);
        ASSERT_EQ(state_offer_v1_sign(&header_seed, seed), STATE_OFFER_OK);
        ASSERT_EQ(state_offer_store_record(&header_seed, ip, 18034, 9, 6000),
                  STATE_OFFER_STORE_DROPPED_KIND);
        ASSERT(state_offer_store_newest_height_seen() == 870000);

        ASSERT_EQ(state_offer_store_decide(5000 + STATE_OFFER_WAIT_MS, &chosen),
                  STATE_OFFER_DECIDE_FALL_BACK);
        state_offer_store_status_get(&st);
        ASSERT(st.last_decision == STATE_OFFER_DECIDE_FALL_BACK);
        ASSERT(st.newest_height_seen == 870000);
        ASSERT(strstr(st.fallback_reason, "870000") != NULL);
        ASSERT(st.fallback_reason[0] != '\0');

        /* An acceptable offer arriving after the fallback is still taken — the
         * fallback is a verdict about the wait, not a door that locks. */
        struct state_offer_v1 late;
        make_offer(&late, 900100, 900100, 0x50);
        ASSERT_EQ(state_offer_store_record(&late, ip, 18034, 9,
                                           5000 + STATE_OFFER_WAIT_MS + 10),
                  STATE_OFFER_STORE_KEPT);
        ASSERT_EQ(state_offer_store_decide(5000 + STATE_OFFER_WAIT_MS + 20,
                                           &chosen),
                  STATE_OFFER_DECIDE_FETCH);
    } TEST_END
    return failures;
}

static int silent_peer_set_fallback(void)
{
    int failures = 0;
    TEST_CASE("a silent peer set falls back saying nothing was offered") {
        struct state_offer_record chosen;
        struct state_offer_store_status st;
        state_offer_store_reset();
        state_offer_store_note_first_peer(0);
        ASSERT_EQ(state_offer_store_decide(STATE_OFFER_WAIT_MS, &chosen),
                  STATE_OFFER_DECIDE_FALL_BACK);
        state_offer_store_status_get(&st);
        ASSERT(st.newest_height_seen == 0);
        ASSERT(strstr(st.fallback_reason, "no peer offered") != NULL);
    } TEST_END
    return failures;
}

static int store_is_bounded(void)
{
    int failures = 0;
    TEST_CASE("nothing a peer sends can make the store grow") {
        struct state_offer_v1 offer;
        struct state_offer_record chosen;
        struct state_offer_store_status st;
        uint8_t ip[16];
        an_ip(ip, 33);
        state_offer_store_reset();

        /* Far more distinct offers than the table holds, ascending, so every
         * one of them wants a slot. */
        for (uint32_t i = 0; i < STATE_OFFER_STORE_MAX * 4u; i++) {
            make_offer(&offer, 900000 + (int32_t)i, 900000 + (int32_t)i,
                       (uint8_t)(i + 1u));
            (void)state_offer_store_record(&offer, ip, 18034,
                                           (int64_t)(i % 3u), 1000 + i);
        }
        state_offer_store_status_get(&st);
        ASSERT(st.offers_retained <= STATE_OFFER_STORE_MAX);
        ASSERT(st.offers_seen == STATE_OFFER_STORE_MAX * 4u);
        /* Eviction keeps the BEST, so the newest offer survives the flood. */
        ASSERT_EQ(state_offer_store_decide(9999, &chosen),
                  STATE_OFFER_DECIDE_FETCH);
        ASSERT(chosen.offer.bundle_height ==
               900000 + (int32_t)(STATE_OFFER_STORE_MAX * 4u) - 1);

        /* Repeating one bundle does not consume slots — dedup is on content. */
        state_offer_store_reset();
        make_offer(&offer, 900000, 900000, 0x20);
        for (int i = 0; i < 50; i++) {
            enum state_offer_store_result r =
                state_offer_store_record(&offer, ip, 18034, 1, 1000 + i);
            ASSERT(r == STATE_OFFER_STORE_KEPT ||
                   r == STATE_OFFER_STORE_KEPT_REPLACED);
        }
        state_offer_store_status_get(&st);
        ASSERT(st.offers_retained == 1);
        ASSERT(st.peers_offering == 1);
    } TEST_END
    return failures;
}

static int endpoint_required(void)
{
    int failures = 0;
    TEST_CASE("an offer with no dialable endpoint is not kept as a promise") {
        struct state_offer_v1 offer;
        uint8_t ip[16], zero_ip[16];
        an_ip(ip, 44);
        memset(zero_ip, 0, sizeof(zero_ip));
        state_offer_store_reset();
        make_offer(&offer, 900000, 900000, 0x20);

        /* Port zero names no service. */
        ASSERT_EQ(state_offer_store_record(&offer, ip, 0, 1, 1000),
                  STATE_OFFER_STORE_DROPPED_ENDPOINT);
        /* An all-zero address is what an onion peer's connection looks like
         * here, and the phase-1a file-service dial has no route to it. */
        ASSERT_EQ(state_offer_store_record(&offer, zero_ip, 18034, 1, 1000),
                  STATE_OFFER_STORE_DROPPED_ENDPOINT);
        /* It still counted toward what we have HEARD, so a fallback reports a
         * height a peer really did offer. */
        ASSERT(state_offer_store_newest_height_seen() == 900000);
    } TEST_END
    return failures;
}

static int unsigned_offer_refused(void)
{
    int failures = 0;
    TEST_CASE("an unsigned or tampered offer is refused by the store too") {
        struct state_offer_v1 offer;
        uint8_t ip[16];
        an_ip(ip, 55);
        state_offer_store_reset();

        make_offer(&offer, 900000, 900000, 0x20);
        struct state_offer_v1 unsigned_row = offer;
        memset(unsigned_row.signature, 0, sizeof(unsigned_row.signature));
        ASSERT_EQ(state_offer_store_record(&unsigned_row, ip, 18034, 1, 1000),
                  STATE_OFFER_STORE_DROPPED_UNSIGNED);

        struct state_offer_v1 tampered = offer;
        fill_bytes(tampered.content_digest, 0xd0);
        ASSERT_EQ(state_offer_store_record(&tampered, ip, 18034, 1, 1000),
                  STATE_OFFER_STORE_DROPPED_UNSIGNED);

        ASSERT_EQ(state_offer_store_record(NULL, ip, 18034, 1, 1000),
                  STATE_OFFER_STORE_DROPPED_INVALID);
        ASSERT_EQ(state_offer_store_record(&offer, NULL, 18034, 1, 1000),
                  STATE_OFFER_STORE_DROPPED_INVALID);

        for (int r = STATE_OFFER_STORE_KEPT;
             r <= STATE_OFFER_STORE_DROPPED_FULL; r++)
            ASSERT(strcmp(state_offer_store_result_string(
                              (enum state_offer_store_result)r),
                          "unknown") != 0);
        for (int d = STATE_OFFER_DECIDE_WAIT; d <= STATE_OFFER_DECIDE_FALL_BACK;
             d++)
            ASSERT(strcmp(state_offer_decision_string(
                              (enum state_offer_decision)d),
                          "unknown") != 0);
    } TEST_END
    return failures;
}

/* ── first boot, no cached file service, a peer offers after connect ──────
 *
 * The path this proves is the one an operator actually hits: a node whose
 * file_services cache is empty (nothing to arm from — the store starts cold)
 * connects to a peer, the peer appends its offers to the zfileaddr it already
 * sends after the handshake, and the node fetches without anyone passing a
 * flag. The socket is the only piece left out: the producer's bytes are built
 * through the same state_offer_collect_wire the send site calls, and read back
 * through the same state_offer_batch_v1_decode the receive site calls, so the
 * bytes crossing the seam here are byte-for-byte the ones that cross the wire.
 *
 * It also proves the endpoint rule: the offer carries no host, so the address
 * dialled can only be the one the connection came from. */

static struct state_offer_batch_v1 g_advertised;

static uint32_t advertise_provider(struct state_offer_batch_v1 *out, void *ctx)
{
    (void)ctx;
    *out = g_advertised;
    return out->count;
}

static int first_boot_peer_offer_is_consumed(void)
{
    int failures = 0;
    TEST_CASE("a cold node with no cached file service consumes a peer's "
              "offer and fetches without an operator flag") {
        uint8_t ip[16];
        an_ip(ip, 9);
        state_offer_store_reset();

        /* The producer side: what a peer at tip 900100 would advertise —
         * one stale bundle it still holds and one inside the window. */
        memset(&g_advertised, 0, sizeof(g_advertised));
        g_advertised.version = STATE_OFFER_VERSION;
        g_advertised.flags = STATE_OFFER_FLAGS_NONE;
        g_advertised.offerer_tip_height = 900100;
        g_advertised.count = 2;
        make_offer(&g_advertised.offers[0], 900090, 900100, 0x30);
        make_offer(&g_advertised.offers[1], 900100, 900100, 0x50);
        state_offer_set_provider(advertise_provider, NULL);

        uint8_t wire[STATE_OFFER_BATCH_V1_MAX_WIRE_BYTES];
        size_t wire_len = state_offer_collect_wire(wire, sizeof(wire));
        ASSERT(wire_len > 0);
        ASSERT(wire_len <= sizeof(wire));
        state_offer_set_provider(NULL, NULL);

        /* The consumer side, cold: nothing was cached, the first peer has just
         * connected, and the only thing that has happened is this message. */
        state_offer_store_note_first_peer(5000);
        ASSERT(state_offer_store_wait_armed());

        struct state_offer_batch_v1 heard;
        ASSERT_EQ(state_offer_batch_v1_decode(&heard, wire, wire_len),
                  STATE_OFFER_OK);
        ASSERT_EQ(heard.count, 2u);
        for (uint32_t i = 0; i < heard.count; i++) {
            /* 18034 is the port the zfileaddr message itself carried and `ip`
             * is the connection's address — neither came from the offer. */
            ASSERT_EQ(state_offer_store_record(&heard.offers[i], ip, 18034, 42,
                                               5100 + (int64_t)i),
                      STATE_OFFER_STORE_KEPT);
        }

        struct state_offer_record chosen;
        ASSERT_EQ(state_offer_store_decide(5200, &chosen),
                  STATE_OFFER_DECIDE_FETCH);
        ASSERT_EQ(chosen.offer.bundle_height, 900100);
        ASSERT_EQ(chosen.file_service_port, 18034);
        ASSERT(memcmp(chosen.peer_ip, ip, 16) == 0);

        /* And it decided well inside the bounded wait, not after it. */
        struct state_offer_store_status st;
        state_offer_store_status_get(&st);
        ASSERT(5200 - st.wait_started_ms < STATE_OFFER_WAIT_MS);
        ASSERT_EQ(st.newest_height_seen, 900100);
    } TEST_END
    return failures;
}

/* Path of the one durable online identity file a node signs its offers with. */
static void identity_path(const char *datadir, char *out, size_t n)
{
    int wrote = snprintf(out, n,
                         "%s/" VCS_ZCODE_DHT_IDENTITY_DIR
                         "/" VCS_ZCODE_DHT_ONLINE_KEY_FILE, datadir);
    if (wrote < 0 || (size_t)wrote >= n)
        abort();
}

/* THE ADVERTISE RULE. A node mints its offering identity — and therefore can
 * append a state offer to its zfileaddr handshakes — exactly when it holds a
 * bundle it would offer, and never otherwise. Before this rule a hosted node
 * that served a half-gigabyte bundle advertised nothing at all, because the key
 * file only ever appeared as a side effect of using the fleet board. */
static int advertise_only_when_we_hold_a_bundle(void)
{
    int failures = 0;
    TEST_CASE("a node with no bundle mints no identity and advertises nothing") {
        char dir[PATH_MAX], key[PATH_MAX];
        test_make_tmpdir(dir, sizeof(dir), "state_offer_adv", "nobundle");
        identity_path(dir, key, sizeof(key));

        state_offer_service_start(dir, NULL);
        state_offer_service_test_invalidate();
        /* A live tip and no held artifact: the fail-closed half. */
        state_offer_service_test_ensure_identity(3200000);
        ASSERT(!state_offer_service_test_have_identity());
        ASSERT(access(key, F_OK) != 0);
        state_offer_service_shutdown();
        test_rm_rf_recursive(dir);
    } TEST_END
    return failures;
}

static int advertise_when_we_hold_the_checkpoint_bundle(void)
{
    int failures = 0;
    TEST_CASE("a node holding the checkpoint bundle mints and advertises") {
        char dir[PATH_MAX], key[PATH_MAX];
        test_make_tmpdir(dir, sizeof(dir), "state_offer_adv", "checkpoint");
        identity_path(dir, key, sizeof(key));

        state_offer_service_start(dir, NULL);
        ASSERT(!state_offer_service_test_have_identity());
        /* The compiled checkpoint height is exempt from the 576-block
         * freshness window, so a tip far above it still advertises. */
        const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
        ASSERT(cp != NULL);
        state_offer_service_test_hold_artifact(cp->height);
        state_offer_service_test_ensure_identity(cp->height + 100000);
        ASSERT(state_offer_service_test_have_identity());
        ASSERT(access(key, F_OK) == 0);
        state_offer_service_shutdown();
        test_rm_rf_recursive(dir);
    } TEST_END
    return failures;
}

static int no_advertisement_for_a_stale_bundle(void)
{
    int failures = 0;
    TEST_CASE("a node holding only a stale bundle still advertises nothing") {
        char dir[PATH_MAX], key[PATH_MAX];
        test_make_tmpdir(dir, sizeof(dir), "state_offer_adv", "stale");
        identity_path(dir, key, sizeof(key));

        state_offer_service_start(dir, NULL);
        /* Well below the tip and not the checkpoint height: not offerable, so
         * nothing is minted and nothing is written. */
        state_offer_service_test_hold_artifact(900000);
        state_offer_service_test_ensure_identity(3200000);
        ASSERT(!state_offer_service_test_have_identity());
        ASSERT(access(key, F_OK) != 0);
        state_offer_service_shutdown();
        test_rm_rf_recursive(dir);
    } TEST_END
    return failures;
}

int test_state_offer_store(void)
{
    int failures = 0;

    failures += advertise_only_when_we_hold_a_bundle();
    failures += advertise_when_we_hold_the_checkpoint_bundle();
    failures += no_advertisement_for_a_stale_bundle();
    failures += picks_newest_acceptable();
    failures += stale_offer_never_chosen();
    failures += bad_bundle_discards_and_tries_next();
    failures += bounded_wait_names_the_newest_height();
    failures += store_is_bounded();
    failures += silent_peer_set_fallback();
    failures += endpoint_required();
    failures += unsigned_offer_refused();
    failures += first_boot_peer_offer_is_consumed();
    state_offer_store_reset();
    return failures;
}
