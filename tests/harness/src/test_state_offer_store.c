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
#include "config/boot_consensus_bundle_marker.h"
#include "jobs/reducer_frontier.h"
#include "jobs/refold_progress.h"
#include "chain/checkpoints.h"
#include "net/rom_seed.h"
#include "net/state_offer.h"
#include "vcs/zcode_dht_identity.h"

#include <fcntl.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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

/* Run F2: the wait had long closed when every source dropped at once; the
 * resumable .part had just gained bytes. Progress holds the fall-back; with
 * no byte for the progress window the named fall-back stands. */
static int resume_progress_holds_fallback(void)
{
    int failures = 0;
    TEST_CASE("a progressing resumable fetch holds the fall-back") {
        struct state_offer_record chosen;
        struct state_offer_store_status st;
        state_offer_store_reset();
        state_offer_store_note_first_peer(0);
        struct state_offer_need moving = {false, true, 0, true};
        ASSERT_EQ(state_offer_store_decide_for(10 * STATE_OFFER_WAIT_MS, &chosen, &moving),
                  STATE_OFFER_DECIDE_WAIT);
        state_offer_store_status_get(&st);
        ASSERT(st.fallback_reason[0] == '\0');
        struct state_offer_need stalled = {false, true, 0, false};
        ASSERT_EQ(state_offer_store_decide_for(10 * STATE_OFFER_WAIT_MS, &chosen, &stalled),
                  STATE_OFFER_DECIDE_FALL_BACK);
        state_offer_store_status_get(&st);
        ASSERT(strstr(st.fallback_reason, "no peer offered") != NULL);
        /* Progress never makes a node that holds state fetch or wait. */
        struct state_offer_need marker = {true, true, 0, true};
        ASSERT_EQ(state_offer_store_decide_for(10 * STATE_OFFER_WAIT_MS, &chosen, &marker),
                  STATE_OFFER_DECIDE_SATISFIED);
        state_offer_store_reset();
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

/* THE LOG RULE. A node that holds an offerable bundle but cannot mint its online
 * identity says so ONCE for that gap, not once per peer-link tick: a live node
 * logged the same warning 1142 times in 25 minutes. */
static int identity_gap_warns_once(void)
{
    int failures = 0;
    TEST_CASE("an unmintable identity warns once per gap, not once per tick") {
        char dir[PATH_MAX], blocker[PATH_MAX], data[PATH_MAX], key[PATH_MAX];
        test_make_tmpdir(dir, sizeof(dir), "state_offer_adv", "gapwarn");
        ASSERT(snprintf(blocker, sizeof(blocker), "%s/blocker", dir) > 0);
        ASSERT(snprintf(data, sizeof(data), "%s/node", blocker) > 0);
        identity_path(data, key, sizeof(key));
        /* A regular file where the datadir should be: the identity cannot be written. */
        FILE *f = fopen(blocker, "w");
        ASSERT(f != NULL);
        fclose(f);

        state_offer_service_start(data, NULL);
        const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
        ASSERT(cp != NULL);
        state_offer_service_test_hold_artifact(cp->height);
        uint32_t before = state_offer_service_test_identity_gap_warns();
        for (int tick = 0; tick < 5; ++tick)
            state_offer_service_test_ensure_identity(cp->height + 100000);
        ASSERT(!state_offer_service_test_have_identity());
        ASSERT(state_offer_service_test_identity_gap_warns() - before == 1);

        /* Make the identity writable: the next tick mints it and the gap ends. */
        ASSERT(unlink(blocker) == 0 && mkdir(blocker, 0700) == 0 && mkdir(data, 0700) == 0);
        state_offer_service_test_ensure_identity(cp->height + 100000);
        ASSERT(state_offer_service_test_have_identity());
        ASSERT(access(key, F_OK) == 0);
        ASSERT(state_offer_service_test_identity_gap_warns() - before == 1);
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

/* ── Offer-path composition (the "bundles/bundles/" regression) ──────────
 *
 * state_offer_service.c:173 used to build the on-disk path for a registered
 * artifact as "%s/bundles/%s" against `g_datadir` and `a->filename` — but
 * `a->filename` already carries the "bundles/" prefix rom_seed_register
 * stores it under for anything found one level into <datadir>/bundles/
 * (net/rom_seed.c rom_seed_scan_bundles_subdir), so the path built was
 * <datadir>/bundles/bundles/<name>.sqlite, which never exists: the manifest
 * never opened, the bundle was never offered, and the online identity that
 * gates on "do we hold something offerable" never minted. Both a fleet
 * node's OWN checkpoint bundle and a peer-registered one hit this — a fresh
 * node's fast-sync fell back to fold-forward with offers_seen=0 from every
 * peer even though every peer held the exact right bundle.
 *
 * These fixtures use rom_seed's own SQLite-magic-plus-garbage synthetic
 * content (test_rom_seed.c's gen_content pattern) rather than a
 * semantically valid zcl.consensus_state_bundle.v1 — building one needs the
 * ~300-line progress-store fixture test_consensus_state_snapshot_export.c
 * seeds for its own export tests, which is already exercised there and in
 * test_consensus_state_snapshot_install.c. What is unique to THIS bug, and
 * what nothing exercised before, is the path composition itself: does
 * state_offer_service resolve a registered artifact's catalog filename to
 * the SAME file rom_seed's own reader (rom_seed_read_chunk) opens? Proved
 * directly via state_offer_service_test_compose_path() below, plus a
 * round-trip read through rom_seed_read_chunk() at that exact composed
 * path to prove it is not just a string match but a genuinely servable
 * file. */

static void gen_bundle_content(uint8_t *buf, size_t size)
{
    static const uint8_t magic[16] = "SQLite format 3";
    for (size_t i = 0; i < size; i++)
        buf[i] = (uint8_t)((i * 149u + 13u) & 0xffu);
    if (size >= 16)
        memcpy(buf, magic, 16);
}

static bool write_bundle_file(const char *dir, const char *relname,
                              const uint8_t *buf, size_t size)
{
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/%s", dir, relname) >=
        (int)sizeof(path))
        return false;
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return false;
    size_t off = 0;
    while (off < size) {
        ssize_t w = write(fd, buf + off, size - off);
        if (w <= 0) {
            close(fd);
            return false;
        }
        off += (size_t)w;
    }
    close(fd);
    return true;
}

static int catalog_bundles_prefix_resolves(void)
{
    int failures = 0;
    TEST_CASE("a 'bundles/<name>' catalog filename composes to ONE "
              "'bundles/' segment, not two, and the file it names is the "
              "one on disk") {
        char dir[PATH_MAX];
        test_make_tmpdir(dir, sizeof(dir), "state_offer_path", "prefixed");
        char bundles_dir[PATH_MAX];
        snprintf(bundles_dir, sizeof(bundles_dir), "%s/bundles", dir);
        ASSERT(mkdir(bundles_dir, 0700) == 0);

        uint8_t content[64 * 1024];
        gen_bundle_content(content, sizeof(content));
        ASSERT(write_bundle_file(
            bundles_dir, "consensus-state-bundle-777.sqlite", content,
            sizeof(content)));

        struct rom_artifact art;
        ASSERT(rom_seed_register(dir, "bundles/consensus-state-bundle-777.sqlite",
                                 NULL, &art) == ROM_REG_OK);
        ASSERT(strcmp(art.filename, "bundles/consensus-state-bundle-777.sqlite")
               == 0);

        state_offer_service_start(dir, NULL);
        char composed[PATH_MAX], expected[PATH_MAX];
        ASSERT(state_offer_service_test_compose_path(art.filename, composed,
                                                      sizeof(composed)));
        snprintf(expected, sizeof(expected),
                "%s/bundles/consensus-state-bundle-777.sqlite", dir);
        ASSERT(strcmp(composed, expected) == 0);
        /* The regression this guards: the old "%s/bundles/%s" composition
         * would have produced .../bundles/bundles/consensus-state-bundle-
         * 777.sqlite here instead, and that path does not exist. */
        ASSERT(access(composed, F_OK) == 0);

        uint8_t *readback = malloc(ROM_SEED_CHUNK_SIZE);
        ASSERT(readback != NULL);
        uint32_t got = 0;
        ASSERT(readback && rom_seed_read_chunk(&art, dir, 0, readback,
                                               ROM_SEED_CHUNK_SIZE, &got));
        ASSERT(got == sizeof(content));
        ASSERT(readback && memcmp(readback, content, sizeof(content)) == 0);
        free(readback);

        state_offer_service_shutdown();
        rom_seed_reset();
        test_rm_rf_recursive(dir);
    } TEST_END
    return failures;
}

static int catalog_bare_basename_resolves(void)
{
    int failures = 0;
    TEST_CASE("a bare '<name>.sqlite' catalog filename (root-scan shape) "
              "composes to the datadir root, not a phantom 'bundles/'") {
        char dir[PATH_MAX];
        test_make_tmpdir(dir, sizeof(dir), "state_offer_path", "bare");

        uint8_t content[64 * 1024];
        gen_bundle_content(content, sizeof(content));
        ASSERT(write_bundle_file(dir, "consensus-state-bundle-778.sqlite",
                                 content, sizeof(content)));

        struct rom_artifact art;
        ASSERT(rom_seed_register(dir, "consensus-state-bundle-778.sqlite",
                                 NULL, &art) == ROM_REG_OK);
        ASSERT(strcmp(art.filename, "consensus-state-bundle-778.sqlite") == 0);

        state_offer_service_start(dir, NULL);
        char composed[PATH_MAX], expected[PATH_MAX];
        ASSERT(state_offer_service_test_compose_path(art.filename, composed,
                                                      sizeof(composed)));
        snprintf(expected, sizeof(expected),
                "%s/consensus-state-bundle-778.sqlite", dir);
        ASSERT(strcmp(composed, expected) == 0);
        ASSERT(access(composed, F_OK) == 0);

        uint8_t *readback = malloc(ROM_SEED_CHUNK_SIZE);
        ASSERT(readback != NULL);
        uint32_t got = 0;
        ASSERT(readback && rom_seed_read_chunk(&art, dir, 0, readback,
                                               ROM_SEED_CHUNK_SIZE, &got));
        ASSERT(got == sizeof(content));
        ASSERT(readback && memcmp(readback, content, sizeof(content)) == 0);
        free(readback);

        state_offer_service_shutdown();
        rom_seed_reset();
        test_rm_rf_recursive(dir);
    } TEST_END
    return failures;
}

/* Capture stderr (LOG_INFO/LOG_WARN destination — base/log_macros.h
 * ZCL_LOG_RAW) around one call, mirroring
 * test_consensus_state_snapshot_export.c's cse_capture_export_stderr. */
static bool capture_stderr_around_refresh(char *out, size_t out_len,
                                          uint32_t *out_count)
{
    if (out && out_len > 0)
        out[0] = '\0';
    mkdir("./test-tmp", 0755);
    char path[256];
    snprintf(path, sizeof(path), "./test-tmp/state_offer_refresh_%d.log",
             (int)getpid());

    fflush(stderr);
    int saved_fd = dup(STDERR_FILENO);
    FILE *capf = (saved_fd >= 0) ? fopen(path, "w+") : NULL;
    if (!capf) {
        if (saved_fd >= 0)
            close(saved_fd);
        *out_count = state_offer_service_test_refresh_and_count();
        return false;
    }
    dup2(fileno(capf), STDERR_FILENO);

    *out_count = state_offer_service_test_refresh_and_count();

    fflush(stderr);
    dup2(saved_fd, STDERR_FILENO);
    close(saved_fd);

    if (out && out_len > 0) {
        long sz = ftell(capf);
        if (sz > 0) {
            rewind(capf);
            size_t n = (size_t)sz < out_len - 1 ? (size_t)sz : out_len - 1;
            size_t rd = fread(out, 1, n, capf);
            out[rd] = '\0';
        }
    }
    fclose(capf);
    unlink(path);
    return true;
}

static int missing_bundle_file_fails_closed_with_named_log(void)
{
    int failures = 0;
    TEST_CASE("a registered artifact whose backing file vanished yields "
              "zero offers plus one named log line naming the path tried") {
        char dir[PATH_MAX];
        test_make_tmpdir(dir, sizeof(dir), "state_offer_path", "missing");
        char bundles_dir[PATH_MAX];
        snprintf(bundles_dir, sizeof(bundles_dir), "%s/bundles", dir);
        ASSERT(mkdir(bundles_dir, 0700) == 0);

        uint8_t content[64 * 1024];
        gen_bundle_content(content, sizeof(content));
        char relpath[PATH_MAX];
        snprintf(relpath, sizeof(relpath), "%s/consensus-state-bundle-779.sqlite",
                bundles_dir);
        ASSERT(write_bundle_file(bundles_dir,
                                 "consensus-state-bundle-779.sqlite", content,
                                 sizeof(content)));

        struct rom_artifact art;
        ASSERT(rom_seed_register(dir, "bundles/consensus-state-bundle-779.sqlite",
                                 NULL, &art) == ROM_REG_OK);
        /* Registration succeeded (art is in rom_seed's registry); now remove
         * the backing file so the composed path — correct or not — no
         * longer exists, exercising the fail-closed branch. */
        ASSERT(unlink(relpath) == 0);

        state_offer_service_start(dir, NULL);
        char captured[8192];
        uint32_t count = 0;
        ASSERT(capture_stderr_around_refresh(captured, sizeof(captured),
                                             &count));
        ASSERT(count == 0);
        char expected_path[PATH_MAX];
        snprintf(expected_path, sizeof(expected_path),
                "%s/bundles/consensus-state-bundle-779.sqlite", dir);
        ASSERT(strstr(captured, expected_path) != NULL);
        ASSERT(strstr(captured, "consensus-state-bundle-779.sqlite") != NULL);

        state_offer_service_shutdown();
        rom_seed_reset();
        test_rm_rf_recursive(dir);
    } TEST_END
    return failures;
}

/* ── Manifest cache ──────────────────────────────────────────────────────
 * The 5-minute snapshot refresh used to fully validate every registered
 * bundle every time, with g_lock held, on the message thread (4-9 s each).
 * A fixture reader stands in for the validating open so the cache can be
 * driven with cheap files; the counter says how often a refresh went to it. */
static int32_t g_cache_reader_height;

static bool cache_fixture_reader(const char *path, int32_t *out_height,
                                 uint8_t out_block_hash[32],
                                 uint8_t out_receipt_id[32])
{
    if (access(path, R_OK) != 0)
        return false;
    *out_height = g_cache_reader_height;
    memset(out_block_hash, 0x21, 32);
    memset(out_receipt_id, 0x37, 32);
    return true;
}

static bool bump_mtime(const char *path, int seconds)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return false;
    struct timespec ts[2] = {st.st_atim, st.st_mtim};
    ts[1].tv_sec += seconds;
    return utimensat(AT_FDCWD, path, ts, 0) == 0;
}

static int late_registered_bundle_is_offered(void)
{
    int failures = 0;
    TEST_CASE("a bundle registered after the empty snapshot is offered on the next tick") {
        char dir[PATH_MAX], bundles[PATH_MAX];
        test_make_tmpdir(dir, sizeof(dir), "state_offer_cache", "late");
        snprintf(bundles, sizeof(bundles), "%s/bundles", dir);
        ASSERT(mkdir(bundles, 0700) == 0);
        rom_seed_reset();
        const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
        ASSERT(cp != NULL);
        g_cache_reader_height = cp->height;
        int32_t tip = cp->height + 100000;
        state_offer_service_test_set_manifest_reader(cache_fixture_reader);
        state_offer_service_start(dir, NULL);
        state_offer_service_test_ensure_identity(tip);
        ASSERT(!state_offer_service_test_have_identity());
        uint8_t content[64 * 1024];
        gen_bundle_content(content, sizeof(content));
        ASSERT(write_bundle_file(bundles, "consensus-state-bundle-780.sqlite", content, sizeof(content)));
        struct rom_artifact art;
        ASSERT_EQ(rom_seed_register(dir, "bundles/consensus-state-bundle-780.sqlite", NULL, &art), ROM_REG_OK);
        state_offer_service_test_ensure_identity(tip);
        ASSERT(state_offer_service_test_have_identity());
        struct state_offer_batch_v1 batch = {0};
        ASSERT_EQ(state_offer_service_test_provide(&batch, tip), 1u);
        ASSERT_EQ(state_offer_v1_verify(&batch.offers[0]), STATE_OFFER_OK);
        state_offer_service_test_set_manifest_reader(NULL);
        state_offer_service_shutdown();
        rom_seed_reset();
        test_rm_rf_recursive(dir);
    } TEST_END
    return failures;
}

static int manifest_cache_skips_unchanged_bundles(void)
{
    int failures = 0;
    TEST_CASE("an unchanged bundle is not re-opened by the refresh; a changed "
              "one is; the send path never opens; a removed one drops out") {
        char dir[PATH_MAX], file[PATH_MAX], bundles[PATH_MAX];
        test_make_tmpdir(dir, sizeof(dir), "state_offer_cache", "refresh");
        snprintf(bundles, sizeof(bundles), "%s/bundles", dir);
        ASSERT(mkdir(bundles, 0700) == 0);
        snprintf(file, sizeof(file), "%s/bundles/consensus-state-bundle-780.sqlite", dir);
        uint8_t content[64 * 1024];
        gen_bundle_content(content, sizeof(content));
        ASSERT(write_bundle_file(bundles, "consensus-state-bundle-780.sqlite",
                                 content, sizeof(content)));
        struct rom_artifact art;
        ASSERT(rom_seed_register(dir, "bundles/consensus-state-bundle-780.sqlite", NULL,
                                 &art) == ROM_REG_OK);

        const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
        ASSERT(cp != NULL);
        g_cache_reader_height = cp ? cp->height : 1;
        int32_t tip = g_cache_reader_height + 100000;
        state_offer_service_test_set_manifest_reader(cache_fixture_reader);
        state_offer_service_start(dir, NULL);
        uint32_t base = state_offer_service_test_manifest_opens();

        /* First refresh (driven by the tick's identity step) opens it once. */
        state_offer_service_test_ensure_identity(tip);
        ASSERT(state_offer_service_test_have_identity());
        ASSERT_EQ(state_offer_service_test_manifest_opens(), base + 1);

        /* Second refresh: same snapshot, nothing opened. */
        ASSERT_EQ(state_offer_service_test_refresh_and_count(), 1u);
        ASSERT_EQ(state_offer_service_test_manifest_opens(), base + 1);

        /* A rewritten file (new mtime) misses and is opened again. */
        ASSERT(bump_mtime(file, 10));
        ASSERT_EQ(state_offer_service_test_refresh_and_count(), 1u);
        ASSERT_EQ(state_offer_service_test_manifest_opens(), base + 2);

        /* The send path after TTL expiry composes offers from the snapshot and
         * opens nothing, even though the file changed again. */
        ASSERT(bump_mtime(file, 20));
        state_offer_service_test_expire_ttl();
        struct state_offer_batch_v1 batch;
        memset(&batch, 0, sizeof(batch));
        ASSERT_EQ(state_offer_service_test_provide(&batch, tip), 1u);
        ASSERT_EQ(state_offer_service_test_manifest_opens(), base + 2);
        ASSERT(strcmp((const char *)batch.offers[0].filename, "consensus-state-bundle-780.sqlite") == 0);
        ASSERT_EQ(state_offer_v1_verify(&batch.offers[0]), STATE_OFFER_OK);

        /* An artifact gone from rom_seed_list drops out of the snapshot. */
        rom_seed_reset();
        ASSERT_EQ(state_offer_service_test_refresh_and_count(), 0u);
        ASSERT_EQ(state_offer_service_test_manifest_opens(), base + 2);

        state_offer_service_test_set_manifest_reader(NULL);
        state_offer_service_shutdown();
        test_rm_rf_recursive(dir);
    } TEST_END
    return failures;
}

/* A restart is a new process-level state: with the gap still open, the next
 * failed mint warns again rather than staying silent under the old gap. */
static int identity_gap_rewarns_after_restart(void)
{
    int failures = 0;
    TEST_CASE("an open identity gap warns again after a restart") {
        char dir[PATH_MAX], blocker[PATH_MAX], data[PATH_MAX];
        test_make_tmpdir(dir, sizeof(dir), "state_offer_adv", "gaprestart");
        ASSERT(snprintf(blocker, sizeof(blocker), "%s/blocker", dir) > 0);
        ASSERT(snprintf(data, sizeof(data), "%s/node", blocker) > 0);
        FILE *f = fopen(blocker, "w");
        ASSERT(f != NULL);
        fclose(f);
        const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
        ASSERT(cp != NULL);

        state_offer_service_start(data, NULL);
        state_offer_service_test_hold_artifact(cp->height);
        uint32_t before = state_offer_service_test_identity_gap_warns();
        state_offer_service_test_ensure_identity(cp->height + 100000);
        ASSERT(state_offer_service_test_identity_gap_warns() - before == 1);
        state_offer_service_shutdown();

        state_offer_service_start(data, NULL);
        state_offer_service_test_hold_artifact(cp->height);
        uint32_t again = state_offer_service_test_identity_gap_warns();
        state_offer_service_test_ensure_identity(cp->height + 100000);
        ASSERT(state_offer_service_test_identity_gap_warns() - again == 1);
        state_offer_service_shutdown();
        test_rm_rf_recursive(dir);
    } TEST_END
    return failures;
}

static int peer_link_retry(void)
{
    int failures = 0;
    TEST_CASE("live peer offers retain zero-IP routes and transient retry") {
        struct state_offer_v1 offer, tampered;
        struct state_offer_record selected;
        uint8_t zero_ip[16] = {0};
        state_offer_store_reset();
        make_offer(&offer, 900000, 900000, 0x20);
        ASSERT_EQ(state_offer_store_record(&offer, zero_ip, 0, 4, 1000), STATE_OFFER_STORE_DROPPED_ENDPOINT);
        ASSERT_EQ(state_offer_store_record_link(&offer, -1, 1000), STATE_OFFER_STORE_DROPPED_INVALID);
        tampered = offer; tampered.signature[0] ^= 1;
        ASSERT_EQ(state_offer_store_record_link(&tampered, 4, 1000), STATE_OFFER_STORE_DROPPED_UNSIGNED);
        ASSERT_EQ(state_offer_store_record_link(&offer, 4, 1000), STATE_OFFER_STORE_KEPT);
        ASSERT_EQ(state_offer_store_decide(1000, &selected), STATE_OFFER_DECIDE_FETCH);
        ASSERT(selected.peer_link && selected.peer_id == 4 && selected.file_service_port == 0);
        state_offer_store_note_link_fetching(offer.content_digest, 4);
        state_offer_store_note_link_retry(offer.content_digest, 4, 1000);
        ASSERT(!state_offer_store_digest_is_bad(offer.content_digest));
        ASSERT_EQ(state_offer_store_peer_strikes(4), 0u);
        ASSERT_EQ(state_offer_store_decide(30999, &selected), STATE_OFFER_DECIDE_WAIT);
        ASSERT_EQ(state_offer_store_record_link(&offer, 4, 1500), STATE_OFFER_STORE_KEPT_REPLACED);
        ASSERT_EQ(state_offer_store_decide(30999, &selected), STATE_OFFER_DECIDE_WAIT);
        ASSERT_EQ(state_offer_store_decide(31000, &selected), STATE_OFFER_DECIDE_FETCH);
        state_offer_store_note_link_retry(offer.content_digest, 4, 32000);
        ASSERT_EQ(state_offer_store_record_link(&offer, 5, 33000), STATE_OFFER_STORE_KEPT);
        ASSERT_EQ(state_offer_store_decide(33000, &selected), STATE_OFFER_DECIDE_FETCH);
        ASSERT(selected.peer_link && selected.peer_id == 5);
        state_offer_store_note_link_bad(offer.content_digest, 5);
        ASSERT_EQ(state_offer_store_peer_strikes(5), 1u);
        ASSERT(!state_offer_store_digest_is_bad(offer.content_digest));
        ASSERT_EQ(state_offer_store_record_link(&offer, 5, 34000), STATE_OFFER_STORE_DROPPED_BAD);
        ASSERT_EQ(state_offer_store_decide(61999, &selected), STATE_OFFER_DECIDE_WAIT);
        ASSERT_EQ(state_offer_store_decide(62000, &selected), STATE_OFFER_DECIDE_FETCH);
        ASSERT(selected.peer_id == 4);
    } TEST_END
    state_offer_store_reset();
    return failures;
}

static int gone_link_peer_offers_are_purged(void)
{
    int failures = 0;
    TEST_CASE("offers from a gone link peer are purged, a live peer's kept") {
        struct state_offer_v1 gone, live, legacy;
        struct state_offer_record sel;
        struct state_offer_store_status st;
        uint8_t ip[16];
        const int64_t alive[] = {8};
        state_offer_store_reset();
        an_ip(ip, 3);
        make_offer(&gone, 900000, 900000, 0x20);
        make_offer(&live, 800000, 800000, 0x21);
        make_offer(&legacy, 700000, 700000, 0x22);
        ASSERT_EQ(state_offer_store_record_link(&gone, 7, 1000), STATE_OFFER_STORE_KEPT);
        ASSERT_EQ(state_offer_store_record_link(&live, 8, 1000), STATE_OFFER_STORE_KEPT);
        ASSERT_EQ(state_offer_store_record(&legacy, ip, 8033, 9, 1000), STATE_OFFER_STORE_KEPT);
        state_offer_store_note_link_fetching(gone.content_digest, 7);
        state_offer_store_note_link_retry(gone.content_digest, 7, 1000);
        /* Peer 7 is gone; its offer is the newest and would be retried. */
        ASSERT_EQ(state_offer_store_purge_gone_link_peers(alive, 1), 1u);
        state_offer_store_status_get(&st);
        ASSERT_EQ(st.offers_retained, 2u);
        ASSERT_EQ(state_offer_store_decide(31000, &sel), STATE_OFFER_DECIDE_FETCH);
        ASSERT(sel.peer_link && sel.peer_id == 8);
        ASSERT_EQ(sel.offer.bundle_height, 800000);
        /* The freed slot takes a new offer; a second purge finds nothing. */
        ASSERT_EQ(state_offer_store_purge_gone_link_peers(alive, 1), 0u);
        ASSERT_EQ(state_offer_store_record_link(&gone, 7, 32000), STATE_OFFER_STORE_KEPT);
        /* An offer being fetched is never purged under the fetch. */
        state_offer_store_note_link_fetching(gone.content_digest, 7);
        ASSERT_EQ(state_offer_store_purge_gone_link_peers(alive, 1), 0u);
        /* No link peers at all: the link offers go, the legacy one stays. */
        state_offer_store_note_link_retry(gone.content_digest, 7, 32000);
        ASSERT_EQ(state_offer_store_purge_gone_link_peers(NULL, 0), 2u);
        state_offer_store_status_get(&st);
        ASSERT_EQ(st.offers_retained, 1u);
        ASSERT_EQ(state_offer_store_decide(90000, &sel), STATE_OFFER_DECIDE_FETCH);
        ASSERT(!sel.peer_link && sel.peer_id == 9);
    } TEST_END
    state_offer_store_reset();
    return failures;
}

static int peer_link_strike_eviction(void)
{
    int failures = 0;
    TEST_CASE("link strike memory remains bounded without excluding new peers") {
        struct state_offer_v1 offer;
        state_offer_store_reset();
        make_offer(&offer, 900000, 900000, 0x20);
        for (int64_t i = 0; i <= STATE_OFFER_STORE_BAD_MAX; ++i) {
            ASSERT_EQ(state_offer_store_record_link(&offer, i, 1000), STATE_OFFER_STORE_KEPT);
            state_offer_store_note_link_bad(offer.content_digest, i);
        }
        ASSERT_EQ(state_offer_store_record_link(&offer, 0, 1000), STATE_OFFER_STORE_KEPT);
        ASSERT_EQ(state_offer_store_record_link(&offer, STATE_OFFER_STORE_BAD_MAX, 1000), STATE_OFFER_STORE_DROPPED_BAD);
    } TEST_END
    state_offer_store_reset();
    return failures;
}

static int peer_link_inflight(void)
{
    int failures = 0;
    TEST_CASE("in-flight sources are never evicted") {
        struct state_offer_v1 offer, newer;
        uint8_t first[32];
        state_offer_store_reset();
        for (int64_t i = 0; i < STATE_OFFER_STORE_MAX; ++i) {
            make_offer(&offer, 900000 + (int32_t)i, 900000 + (int32_t)i, (uint8_t)(0x20 + i));
            if (!i) memcpy(first, offer.content_digest, sizeof(first));
            ASSERT_EQ(state_offer_store_record_link(&offer, i, 1000), STATE_OFFER_STORE_KEPT);
            state_offer_store_note_link_fetching(offer.content_digest, i);
        }
        make_offer(&newer, 900100, 900100, 0x70);
        ASSERT_EQ(state_offer_store_record_link(&newer, 99, 1000), STATE_OFFER_STORE_DROPPED_FULL);
        state_offer_store_note_link_retry(first, 0, 1000);
        ASSERT_EQ(state_offer_store_record_link(&newer, 99, 1000), STATE_OFFER_STORE_KEPT);
    } TEST_END
    state_offer_store_reset();
    return failures;
}

static int peer_link_replay_rotation(void)
{
    int failures = 0;
    TEST_CASE("replayed offers cannot exclude a later source of the same digest") {
        struct state_offer_v1 offer;
        struct state_offer_record selected;
        struct state_offer_store_status status;
        state_offer_store_reset();
        make_offer(&offer, 900000, 900000, 0x20);
        for (int64_t peer = 0; peer < 64; ++peer)
            ASSERT_EQ(state_offer_store_record_link(&offer, peer, 1000 + peer), STATE_OFFER_STORE_KEPT);
        state_offer_store_status_get(&status);
        ASSERT_EQ(status.offers_retained, 4u);
        ASSERT_EQ(state_offer_store_record_link(&offer, 100, 1064), STATE_OFFER_STORE_KEPT);
        for (int64_t peer = 61; peer <= 63; ++peer)
            state_offer_store_note_link_retry(offer.content_digest, peer, 1064);
        ASSERT_EQ(state_offer_store_decide(1064, &selected), STATE_OFFER_DECIDE_FETCH);
        ASSERT_EQ(selected.peer_id, 100);
        state_offer_store_note_link_fetching(offer.content_digest, 100);
        state_offer_store_note_link_bad(offer.content_digest, 100);
        ASSERT(!state_offer_store_digest_is_bad(offer.content_digest));
        ASSERT_EQ(state_offer_store_record_link(&offer, 101, 1065), STATE_OFFER_STORE_KEPT);
        ASSERT_EQ(state_offer_store_decide(1065, &selected), STATE_OFFER_DECIDE_FETCH);
        ASSERT_EQ(selected.peer_id, 101);
    } TEST_END
    state_offer_store_reset();
    return failures;
}

static int staged_bundle_prevents_repeat_fetch(void)
{
    int failures = 0;
    TEST_CASE("a staged bundle prevents another provider fetch") {
        char dir[PATH_MAX];
        struct state_offer_v1 offer;
        struct state_offer_record selected;
        test_make_tmpdir(dir, sizeof(dir), "state_offer_stage", "repeat");
        state_offer_store_reset();
        state_offer_service_start(dir, NULL);
        make_offer(&offer, 900000, 900000, 0x20);
        ASSERT_EQ(state_offer_store_record_link(&offer, 4, 1000), STATE_OFFER_STORE_KEPT);
        ASSERT_EQ(state_offer_store_record_link(&offer, 5, 1001), STATE_OFFER_STORE_KEPT);
        state_offer_service_test_set_staged(true);
        state_offer_service_tick();
        ASSERT(!state_offer_service_test_fetch_running());
        ASSERT_EQ(state_offer_store_decide(2000, &selected), STATE_OFFER_DECIDE_FETCH);
        state_offer_service_test_set_staged(false);
        state_offer_service_shutdown();
        state_offer_store_reset();
        test_rm_rf_recursive(dir);
    } TEST_END
    return failures;
}

/* A node that already holds state must not fetch an offered bundle. */
static int satisfied_node_does_not_fetch(void)
{
    int failures = 0;
    TEST_CASE("a node with state or a marker decides satisfied, not fetch") {
        struct state_offer_v1 offer;
        struct state_offer_record chosen;
        uint8_t ip[16];
        an_ip(ip, 9);
        make_offer(&offer, 900000, 900100, 0x20);

        /* Fresh node (no marker, height 0, known): still fetches. */
        struct state_offer_need fresh = {false, true, 0, false};
        state_offer_store_reset();
        ASSERT_EQ(state_offer_store_record(&offer, ip, 18034, 1, 1000),
                  STATE_OFFER_STORE_KEPT);
        ASSERT_EQ(state_offer_store_decide_for(2000, &chosen, &fresh),
                  STATE_OFFER_DECIDE_FETCH);
        ASSERT(chosen.offer.bundle_height == 900000);

        /* Marker present: no fetch, and the offer is still counted. */
        struct state_offer_need marker = {true, true, 0, false};
        state_offer_store_reset();
        ASSERT_EQ(state_offer_store_record(&offer, ip, 18034, 1, 1000),
                  STATE_OFFER_STORE_KEPT);
        ASSERT_EQ(state_offer_store_decide_for(2000, &chosen, &marker),
                  STATE_OFFER_DECIDE_SATISFIED);
        struct state_offer_store_status st;
        state_offer_store_status_get(&st);
        ASSERT_EQ(st.offers_seen, 1u);
        ASSERT(st.newest_height_seen == 900000);
        ASSERT_EQ(st.last_decision, STATE_OFFER_DECIDE_SATISFIED);

        /* Height at or above the offer: no fetch. */
        struct state_offer_need at = {false, true, 900000, false};
        struct state_offer_need above = {false, true, 950000, false};
        ASSERT_EQ(state_offer_store_decide_for(2000, &chosen, &at),
                  STATE_OFFER_DECIDE_SATISFIED);
        ASSERT_EQ(state_offer_store_decide_for(2000, &chosen, &above),
                  STATE_OFFER_DECIDE_SATISFIED);

        /* Height below the offer, no marker: fetch. */
        struct state_offer_need below = {false, true, 100, false};
        ASSERT_EQ(state_offer_store_decide_for(2000, &chosen, &below),
                  STATE_OFFER_DECIDE_FETCH);

        /* Unknown height fails towards NOT fetching. */
        struct state_offer_need unknown = {false, false, 0, false};
        ASSERT_EQ(state_offer_store_decide_for(2000, &chosen, &unknown),
                  STATE_OFFER_DECIDE_SATISFIED);

        /* A satisfied node never falls back, even after the wait closes. */
        state_offer_store_reset();
        state_offer_store_note_first_peer(1000);
        ASSERT_EQ(state_offer_store_decide_for(1000 + STATE_OFFER_WAIT_MS + 1,
                                               &chosen, &marker),
                  STATE_OFFER_DECIDE_SATISFIED);

        ASSERT(strcmp(state_offer_decision_string(STATE_OFFER_DECIDE_SATISFIED),
                      "satisfied") == 0);
        state_offer_store_reset();
    } TEST_END
    return failures;
}

/* The service builds the need from the datadir marker, refold state and H*. */
static int service_local_need(void)
{
    int failures = 0;
    TEST_CASE("the service reports marker, refold and fresh need correctly") {
        char dir[PATH_MAX];
        struct state_offer_need n;
        test_make_tmpdir(dir, sizeof(dir), "state_offer_need", "svc");
        state_offer_service_start(dir, NULL);
        /* Publish H*=0: a fresh datadir whose height is known and empty. */
        reducer_frontier_provable_tip_set(0);

        state_offer_service_test_local_need(&n);
        ASSERT(!n.marker_present);
        ASSERT(n.height_known);
        ASSERT(n.local_height == 0);
        struct state_offer_need want = n;
        ASSERT(!want.marker_present && want.height_known &&
               want.local_height < 900000); /* fresh node wants state */

        refold_progress_test_set_cached(true);
        state_offer_service_test_local_need(&n);
        ASSERT(!n.height_known); /* refold: never wants an offered bundle */
        refold_progress_test_set_cached(false);

        uint8_t digest[32] = {0};
        ASSERT(boot_consensus_bundle_marker_write(dir, 5, digest));
        state_offer_service_test_local_need(&n);
        ASSERT(n.marker_present);

        reducer_frontier_provable_tip_reset();
        state_offer_service_shutdown();
        test_rm_rf_recursive(dir);
    } TEST_END
    return failures;
}

static bool test_rung_filter(int32_t height) { return height == 900000; }

static int filtered_retention_at_capacity(void)
{
    int failures = 0;
    TEST_CASE("eligible rung survives a full table and later higher offers") {
        struct state_offer_v1 offer, rung;
        struct state_offer_record chosen;
        uint8_t ip[16]; an_ip(ip, 44);
        state_offer_store_set_height_filter(NULL);
        state_offer_store_reset();
        for (unsigned i = 0; i < STATE_OFFER_STORE_MAX; i++) {
            int32_t h = 900100 + (int32_t)i;
            make_offer(&offer, h, h, (uint8_t)(1 + i));
            ASSERT_EQ(state_offer_store_record(&offer, ip, 18034, (int64_t)i, 1000 + i), STATE_OFFER_STORE_KEPT);
        }
        state_offer_store_set_height_filter(test_rung_filter);
        make_offer(&rung, 900000, 900000, 100);
        ASSERT_EQ(state_offer_store_record(&rung, ip, 18034, 100, 2000), STATE_OFFER_STORE_KEPT);
        for (unsigned i = 0; i < 2 * STATE_OFFER_STORE_MAX; i++) {
            int32_t h = 901000 + (int32_t)i;
            make_offer(&offer, h, h, (uint8_t)(120 + i));
            (void)state_offer_store_record(&offer, ip, 18034, 120 + (int64_t)i, 3000 + i);
        }
        ASSERT_EQ(state_offer_store_decide(5000, &chosen), STATE_OFFER_DECIDE_FETCH);
        ASSERT(memcmp(chosen.offer.content_digest, rung.content_digest, 32) == 0);
        state_offer_store_set_height_filter(NULL);
        ASSERT_EQ(state_offer_store_decide(5000, &chosen), STATE_OFFER_DECIDE_FETCH);
        ASSERT(chosen.offer.bundle_height > 900000);
    } TEST_END
    state_offer_store_set_height_filter(NULL);
    state_offer_store_reset();
    return failures;
}

static int filtered_full_eligible(void)
{
    int failures = 0;
    TEST_CASE("a full eligible table refuses a higher ineligible offer") {
        struct state_offer_v1 offer;
        struct state_offer_record chosen;
        uint8_t ip[16]; an_ip(ip, 45);
        state_offer_store_reset();
        state_offer_store_set_height_filter(test_rung_filter);
        for (unsigned i = 0; i < STATE_OFFER_STORE_MAX; i++) {
            make_offer(&offer, 900000, 900000, (uint8_t)(1 + i));
            ASSERT_EQ(state_offer_store_record(&offer, ip, 18034, (int64_t)i, 1000 + i), STATE_OFFER_STORE_KEPT);
        }
        make_offer(&offer, 901000, 901000, 120);
        ASSERT_EQ(state_offer_store_record(&offer, ip, 18034, 120, 2000), STATE_OFFER_STORE_DROPPED_FULL);
        ASSERT_EQ(state_offer_store_decide(3000, &chosen), STATE_OFFER_DECIDE_FETCH);
        ASSERT(chosen.offer.bundle_height == 900000);
        state_offer_store_set_height_filter(NULL);
        ASSERT_EQ(state_offer_store_record(&offer, ip, 18034, 120, 2000), STATE_OFFER_STORE_KEPT);
        ASSERT_EQ(state_offer_store_decide(3000, &chosen), STATE_OFFER_DECIDE_FETCH);
        ASSERT(chosen.offer.bundle_height == 901000);
    } TEST_END
    state_offer_store_set_height_filter(NULL);
    state_offer_store_reset();
    return failures;
}

static int filtered_same_digest_sources(void)
{
    int failures = 0;
    TEST_CASE("source rotation cannot replace the rung with an ineligible height") {
        struct state_offer_v1 rung, higher;
        struct state_offer_record chosen;
        state_offer_store_reset();
        state_offer_store_set_height_filter(test_rung_filter);
        make_offer(&rung, 900000, 900000, 42);
        for (int64_t peer = 0; peer < 4; peer++)
            ASSERT_EQ(state_offer_store_record_link(&rung, peer, 1000 + peer), STATE_OFFER_STORE_KEPT);
        make_offer(&higher, 901000, 901000, 42);
        ASSERT_EQ(state_offer_store_record_link(&higher, 5, 2000), STATE_OFFER_STORE_DROPPED_FULL);
        ASSERT_EQ(state_offer_store_decide(3000, &chosen), STATE_OFFER_DECIDE_FETCH);
        ASSERT(chosen.offer.bundle_height == 900000);
        state_offer_store_set_height_filter(NULL);
        ASSERT_EQ(state_offer_store_record_link(&higher, 5, 2000), STATE_OFFER_STORE_KEPT);
    } TEST_END
    state_offer_store_set_height_filter(NULL);
    state_offer_store_reset();
    return failures;
}

int test_state_offer_store(void)
{
    int failures = 0;

    failures += service_local_need();
    failures += satisfied_node_does_not_fetch();
    failures += advertise_only_when_we_hold_a_bundle();
    failures += advertise_when_we_hold_the_checkpoint_bundle();
    failures += no_advertisement_for_a_stale_bundle();
    failures += identity_gap_warns_once();
    failures += identity_gap_rewarns_after_restart();
    failures += picks_newest_acceptable();
    failures += filtered_retention_at_capacity();
    failures += filtered_full_eligible();
    failures += filtered_same_digest_sources();
    failures += stale_offer_never_chosen();
    failures += bad_bundle_discards_and_tries_next();
    failures += bounded_wait_names_the_newest_height();
    failures += store_is_bounded();
    failures += silent_peer_set_fallback();
    failures += resume_progress_holds_fallback();
    failures += endpoint_required();
    failures += peer_link_retry();
    failures += peer_link_strike_eviction();
    failures += gone_link_peer_offers_are_purged();
    failures += peer_link_inflight();
    failures += peer_link_replay_rotation();
    failures += staged_bundle_prevents_repeat_fetch();
    failures += unsigned_offer_refused();
    failures += first_boot_peer_offer_is_consumed();
    failures += catalog_bundles_prefix_resolves();
    failures += catalog_bare_basename_resolves();
    failures += missing_bundle_file_fails_closed_with_named_log();
    failures += manifest_cache_skips_unchanged_bundles();
    failures += late_registered_bundle_is_offered();
    state_offer_store_reset();
    return failures;
}
