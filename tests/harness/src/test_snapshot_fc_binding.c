/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The FlyClient gate binds a peer's proof to headers this node validated.
 *
 * ZClassic headers commit no MMB root, and a sample's block_hash and nBits are
 * chosen by the prover, so a value under the target proves no work. Every case
 * here builds a local header chain, has a "peer" prove over leaves derived
 * from it (as snapsync_fc_leaf_from_block_index does, with a non-zero utxo_root
 * at boundary heights), and then tampers with one thing:
 *   - a hash-committed field, or the claimed size: a forgery, and an offence;
 *   - nothing the peer got wrong (our best header is behind, the anchor is on
 *     a chain we have not seen, or only the uncommitted chain_work differs):
 *     no offence, and the service stands down so a later offer is heard.
 * The service owns an open in-memory node_db, so a gate that wrongly passes
 * really does enter RECEIVING. Route cases cross the wire codec, which is where
 * a field the leaf hash covers can get lost. */

#include "test/test_core.h"

#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/mmb.h"
#include "chain/mmr.h"
#include "config/runtime.h"
#include "core/arith_uint256.h"
#include "core/serialize.h"
#include "models/database.h"
#include "net/fast_sync.h"
#include "net/flyclient.h"
#include "net/msg_internal.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/peer_scoring.h"
#include "net/protocol.h"
#include "net/snapshot_sync_contract.h"
#include "platform/clock.h"
#include "sync/sync_state.h"
#include "util/safe_alloc.h"
#include "validation/main_state.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

void mp_zs_on_fc_proofs(struct msg_processor *mp, struct p2p_node *node,
                        struct byte_stream *s);
void mp_zs_on_snapshot_offer(struct msg_processor *mp, struct p2p_node *node,
                             struct byte_stream *s);

/* Long enough for FC_NUM_SAMPLES distinct heights below the anchor, for
 * boundary heights among them, and for an anchor more than the 5000 blocks
 * above our empty active chain that snapshot_manifest_validate_offer requires. */
#define FCB_BLOCKS 5200
#define FCB_ANCHOR_HEIGHT (FCB_BLOCKS - 1)
#define FCB_NBITS 0x1f07ffffu
#define FCB_PEER_ID 77u
#define FCB_LEAF_COUNT_MASK 0xFFFFFFFFFFULL
#define FCB_DEFAULT_SEED 0x5C
/* leaf 108 + leaf_index 8 + leaf_hash 32 + the two counts 8 + mmb_size 8. */
#define FCB_SAMPLE_FIXED_WIRE_BYTES 164u
/* pn[6] set puts bit 200 in the work, far above the mainnet floor. */
#define FCB_WORK_ABOVE_FLOOR 0x100u
#define FCB_WORK_BELOW_FLOOR 0u

enum fcb_field {
    FCB_FIELD_BLOCK_HASH,
    FCB_FIELD_TIMESTAMP,
    FCB_FIELD_NBITS,
    FCB_FIELD_SAPLING_ROOT,
    FCB_FIELD_CHAIN_WORK,
};

static struct {
    struct main_state ms;
    struct block_index idx[FCB_BLOCKS];
    struct mmb m;
    struct mmb_leaf leaves[FCB_BLOCKS];
    uint8_t leaf_hashes[FCB_BLOCKS][32];
    struct fc_challenge challenge;
    struct fc_response resp;
    struct fc_response parsed;
    uint64_t samples[FC_MAX_SAMPLES];
    uint32_t sample_count;
    uint8_t seed;
    struct node_db ndb;
    struct snapshot_sync_service svc;
    struct net_manager nm;
    struct msg_processor mp;
    struct app_runtime_context runtime;
    struct p2p_node *node;
    struct send_segment *sentinel;
} g;

static void fcb_fill_local_chain(uint32_t work_high_limb)
{
    for (uint32_t i = 0; i < FCB_BLOCKS; i++) {
        struct block_index *bi = &g.idx[i];

        memset(bi, 0, sizeof(*bi));
        /* A small value: under the target, as a forger's choice would be. */
        memcpy(bi->hashBlock.data, &i, sizeof(i));
        bi->hashBlock.data[4] = 0xA5;
        bi->phashBlock = &bi->hashBlock;
        bi->nHeight = (int)i;
        bi->nTime = 1600000000u + i * 150u;
        bi->nBits = FCB_NBITS;
        memset(bi->hashFinalSaplingRoot.data, (int)(i + 1), 32);
        bi->nChainWork.pn[0] = i + 1;
        bi->nChainWork.pn[6] = work_high_limb;
        bi->pprev = i > 0 ? &g.idx[i - 1] : NULL;
        block_index_build_skip(bi);
    }
}

/* The heights a prover fills a utxo_root at. */
static bool fcb_is_boundary(uint64_t height)
{
    return height > 0 && height % MMR_COMMITMENT_INTERVAL == 0;
}

static void fcb_leaves_from_local_chain(void)
{
    for (uint32_t i = 0; i < FCB_BLOCKS; i++) {
        const struct block_index *bi = &g.idx[i];
        uint8_t utxo_root[32] = {0};

        if (fcb_is_boundary(i))
            memset(utxo_root, 0x80 | (int)(i / MMR_COMMITMENT_INTERVAL), 32);
        mmb_leaf_from_block(&g.leaves[i], bi->hashBlock.data, bi->nHeight,
                            bi->nTime, bi->nBits, bi->hashFinalSaplingRoot.data,
                            (const uint8_t *)bi->nChainWork.pn, utxo_root);
    }
}

/* The peer's side: an honest MMB and proof over whatever g.leaves now holds. */
static bool fcb_prove(void)
{
    mmb_init(&g.m);
    for (uint32_t i = 0; i < FCB_BLOCKS; i++) {
        mmb_hash_leaf(&g.leaves[i], g.leaf_hashes[i]);
        if (mmb_append(&g.m, &g.leaves[i]) < 0)
            return false;
    }
    mmb_root(&g.m, g.challenge.mmb_root);
    memset(g.challenge.seed, g.seed, sizeof(g.challenge.seed));
    g.challenge.chain_length = FCB_BLOCKS;
    fc_generate_indices(g.challenge.seed, g.challenge.chain_length, g.samples,
                        &g.sample_count);
    if (!fc_build_response(&g.challenge, &g.m, g.leaves,
                           (const uint8_t (*)[32])g.leaf_hashes, &g.resp))
        return false;
    g.svc.fc_challenge = g.challenge;
    memcpy(g.svc.offered_mmb_root, g.challenge.mmb_root, 32);
    return true;
}

/* The offer as snapsync_handle_offer leaves it, naming our own anchor. */
static void fcb_arm_offer(void)
{
    const struct block_index *anchor = &g.idx[FCB_ANCHOR_HEIGHT];

    g.svc.state = SNAPSYNC_NEGOTIATING;
    g.svc.offered_height = FCB_ANCHOR_HEIGHT;
    g.svc.serving_peer_id = FCB_PEER_ID;
    g.svc.start_time_us = 1;
    g.svc.fc_verified = false;
    memcpy(g.svc.offered_block_hash, anchor->hashBlock.data, 32);
    memcpy(g.svc.offered_chain_work, anchor->nChainWork.pn, 32);
    g.ms.pindex_best_header = &g.idx[FCB_ANCHOR_HEIGHT];
}

static bool fcb_setup(uint32_t work_high_limb)
{
    memset(&g, 0, sizeof(g));
    g.seed = FCB_DEFAULT_SEED;
    main_state_init(&g.ms);
    if (!node_db_open(&g.ndb, ":memory:"))
        return false;
    snapsync_init(&g.svc, &g.ndb);
    fcb_fill_local_chain(work_high_limb);
    fcb_leaves_from_local_chain();
    if (!fcb_prove())
        return false;
    fcb_arm_offer();
    return true;
}

/* ── A monotonic clock the cooldown cases control ─────────────────────── */

#define FCB_CLOCK_START_NS (10000LL * 1000000000LL)

static _Atomic int64_t g_fcb_now_ns;
static const clock_iface_t *g_fcb_real_clock;

static int64_t fcb_mono_ns(void *self)
{
    (void)self;
    return atomic_load(&g_fcb_now_ns);
}

static int64_t fcb_wall_ms(void *self)
{
    (void)self;
    return g_fcb_real_clock->now_wall_ms(g_fcb_real_clock->self);
}

static const clock_iface_t g_fcb_clock = { fcb_mono_ns, fcb_wall_ms, NULL };

static void fcb_clock_begin(void)
{
    g_fcb_real_clock = clock_default();
    atomic_store(&g_fcb_now_ns, FCB_CLOCK_START_NS);
    clock_set_default(&g_fcb_clock);
}

static void fcb_clock_advance_secs(int64_t secs)
{
    atomic_fetch_add(&g_fcb_now_ns, secs * 1000000000LL);
}

static void fcb_clock_end(void)
{
    clock_reset_default();
    g_fcb_real_clock = NULL;
}

static void fcb_route_free(void)
{
    if (g.node) {
        while (g.sentinel->next) {
            struct send_segment *seg = g.sentinel->next;
            g.sentinel->next = seg->next;
            send_segment_free(seg);
        }
        send_segment_free(g.sentinel);
        g.node->send_head = NULL;
        g.node->send_tail = NULL;
        p2p_node_free(g.node);
        g.node = NULL;
        net_manager_free(&g.nm);
    }
}

static void fcb_teardown(void)
{
    fcb_route_free();
    if (g.ndb.open) {
        snapsync_reset(&g.svc);
        node_db_close(&g.ndb);
    }
    snapsync_set_anchor(NULL);
    g.ms.pindex_best_header = NULL;
    main_state_free(&g.ms);
    if (sync_get_state() == SYNC_SNAPSHOT_RECEIVE)
        sync_set_state(SYNC_HEADERS_DOWNLOAD, "test teardown");
    if (g_fcb_real_clock)
        fcb_clock_end();
}

static struct zcl_result fcb_verify(void)
{
    return snapsync_verify_flyclient(&g.svc, &g.ms, &g.resp);
}

/* A height the challenge samples other than the anchor; nth counts them. */
static uint32_t fcb_sampled_height(uint32_t nth)
{
    for (uint32_t i = 0; i < g.sample_count; i++) {
        if (g.samples[i] == FCB_ANCHOR_HEIGHT)
            continue;
        if (nth == 0)
            return (uint32_t)g.samples[i];
        nth--;
    }
    return 0;
}

static void fcb_tamper(uint32_t height, enum fcb_field field)
{
    struct mmb_leaf *leaf = &g.leaves[height];

    switch (field) {
    case FCB_FIELD_BLOCK_HASH:
        /* Stays a tiny value, so fc_check_pow is still satisfied. */
        leaf->block_hash[1] ^= 0x5A;
        break;
    case FCB_FIELD_TIMESTAMP:
        leaf->timestamp += 1;
        break;
    case FCB_FIELD_NBITS:
        /* Still at or below powLimit, and the hash is still under it. */
        leaf->nBits = 0x1f07fffeu;
        break;
    case FCB_FIELD_SAPLING_ROOT:
        leaf->sapling_root[0] ^= 0x5A;
        break;
    case FCB_FIELD_CHAIN_WORK:
        leaf->chain_work[0] ^= 0x01;
        break;
    }
}

/* Refused and held as a fault of the peer: the service stays where the
 * negotiation stall path deals with it, and nothing started receiving. */
static bool fcb_refused_as_forgery(struct zcl_result r)
{
    return !r.ok && r.code != SNAPSYNC_FLYCLIENT_UNVERIFIABLE_ERROR_CODE &&
           g.svc.state == SNAPSYNC_NEGOTIATING && !g.svc.fc_verified &&
           !g.svc.turbo_active;
}

/* Refused with no fault of the peer: back to idle, offer cleared. */
static bool fcb_stood_down(struct zcl_result r)
{
    return !r.ok && r.code == SNAPSYNC_FLYCLIENT_UNVERIFIABLE_ERROR_CODE &&
           g.svc.state == SNAPSYNC_IDLE && g.svc.serving_peer_id == 0 &&
           g.svc.offered_height == 0 && !g.svc.fc_verified &&
           !g.svc.turbo_active;
}

static int fcb_case_honest_proof_passes(void)
{
    int failures = 0;

    TEST("fc binding: an honest proof over our own headers passes and starts "
         "the receive") {
        ASSERT(fcb_setup(FCB_WORK_ABOVE_FLOOR));
        struct zcl_result r = fcb_verify();
        ASSERT_RESULT_OK(r);
        ASSERT(g.svc.state == SNAPSYNC_RECEIVING);
        ASSERT(g.svc.fc_verified);
        PASS();
    } _test_next:;
    fcb_teardown();
    return failures;
}

static int fcb_case_tampered_field(const char *name, enum fcb_field field)
{
    int failures = 0;

    TEST(name) {
        ASSERT(fcb_setup(FCB_WORK_ABOVE_FLOOR));
        fcb_tamper(fcb_sampled_height(0), field);
        ASSERT(fcb_prove());
        ASSERT(fcb_refused_as_forgery(fcb_verify()));
        PASS();
    } _test_next:;
    fcb_teardown();
    return failures;
}

static int fcb_case_claimed_size_differs(void)
{
    int failures = 0;

    TEST("fc binding: a proof whose mmb_size differs from the challenge "
         "length is a forgery") {
        ASSERT(fcb_setup(FCB_WORK_ABOVE_FLOOR));
        /* mmb_verify reads only the left/right bits above bit 40. */
        uint64_t size = g.resp.samples[0].proof.mmb_size;
        g.resp.samples[0].proof.mmb_size =
            (size & ~FCB_LEAF_COUNT_MASK) | (FCB_BLOCKS + 1);
        ASSERT(fcb_refused_as_forgery(fcb_verify()));
        PASS();
    } _test_next:;
    fcb_teardown();
    return failures;
}

static int fcb_case_best_header_behind(void)
{
    int failures = 0;

    TEST("fc binding: a node whose best header is behind the anchor stands "
         "down with no fault, keeping the boot anchor hint") {
        ASSERT(fcb_setup(FCB_WORK_ABOVE_FLOOR));
        ASSERT(sync_get_state() == SYNC_SNAPSHOT_RECEIVE ||
               sync_set_state(SYNC_SNAPSHOT_RECEIVE, "test offer"));
        snapsync_set_anchor(&g.idx[5]);
        g.ms.pindex_best_header = &g.idx[FCB_ANCHOR_HEIGHT - 1];
        ASSERT(fcb_stood_down(fcb_verify()));
        ASSERT(snapsync_get_anchor() == &g.idx[5]);
        ASSERT(sync_get_state() == SYNC_HEADERS_DOWNLOAD);
        PASS();
    } _test_next:;
    fcb_teardown();
    return failures;
}

static int fcb_case_no_best_header(void)
{
    int failures = 0;

    TEST("fc binding: a node with no best header stands down") {
        ASSERT(fcb_setup(FCB_WORK_ABOVE_FLOOR));
        g.ms.pindex_best_header = NULL;
        ASSERT(fcb_stood_down(fcb_verify()));
        PASS();
    } _test_next:;
    fcb_teardown();
    return failures;
}

static int fcb_case_anchor_hash_differs(void)
{
    int failures = 0;

    TEST("fc binding: an anchor hash on a chain we have not seen stands down") {
        ASSERT(fcb_setup(FCB_WORK_ABOVE_FLOOR));
        g.svc.offered_block_hash[7] ^= 0x01;
        ASSERT(fcb_stood_down(fcb_verify()));
        PASS();
    } _test_next:;
    fcb_teardown();
    return failures;
}

static int fcb_case_anchor_work_differs(void)
{
    int failures = 0;

    TEST("fc binding: offered chain work above our anchor's stands down, and "
         "the peer's number cannot lift a low local anchor over the floor") {
        ASSERT(fcb_setup(FCB_WORK_BELOW_FLOOR));
        memset(g.svc.offered_chain_work, 0xFF, 32);
        ASSERT(fcb_stood_down(fcb_verify()));
        PASS();
    } _test_next:;
    fcb_teardown();
    return failures;
}

static int fcb_case_sample_work_differs(void)
{
    int failures = 0;

    TEST("fc binding: a sample differing only in chain_work stands down") {
        ASSERT(fcb_setup(FCB_WORK_ABOVE_FLOOR));
        fcb_tamper(fcb_sampled_height(0), FCB_FIELD_CHAIN_WORK);
        ASSERT(fcb_prove());
        ASSERT(fcb_stood_down(fcb_verify()));
        PASS();
    } _test_next:;
    fcb_teardown();
    return failures;
}

static int fcb_case_forgery_outranks_work_difference(void)
{
    int failures = 0;

    TEST("fc binding: a forged sample after a chain_work difference is still "
         "a forgery") {
        ASSERT(fcb_setup(FCB_WORK_ABOVE_FLOOR));
        ASSERT(g.sample_count >= 3);
        /* Samples are checked in challenge order, so the first differs only
         * in work and a later one lies about a committed field. */
        fcb_tamper(fcb_sampled_height(0), FCB_FIELD_CHAIN_WORK);
        fcb_tamper(fcb_sampled_height(1), FCB_FIELD_BLOCK_HASH);
        ASSERT(fcb_prove());
        ASSERT(fcb_refused_as_forgery(fcb_verify()));
        PASS();
    } _test_next:;
    fcb_teardown();
    return failures;
}

static int fcb_case_local_ancestor_missing(void)
{
    int failures = 0;

    TEST("fc binding: a sampled height our index cannot reach stands down") {
        ASSERT(fcb_setup(FCB_WORK_ABOVE_FLOOR));
        /* A snapshot-seeded anchor has no parents below it. */
        g.idx[FCB_ANCHOR_HEIGHT].pprev = NULL;
        g.idx[FCB_ANCHOR_HEIGHT].pskip = NULL;
        ASSERT(fcb_stood_down(fcb_verify()));
        PASS();
    } _test_next:;
    fcb_teardown();
    return failures;
}

static int fcb_case_no_main_state(void)
{
    int failures = 0;

    TEST("fc binding: no main state fails closed and starts nothing") {
        ASSERT(fcb_setup(FCB_WORK_ABOVE_FLOOR));
        ASSERT(!snapsync_verify_flyclient(&g.svc, NULL, &g.resp).ok);
        ASSERT(g.svc.state == SNAPSYNC_NEGOTIATING);
        PASS();
    } _test_next:;
    fcb_teardown();
    return failures;
}

static int fcb_case_local_anchor_below_floor(void)
{
    int failures = 0;

    TEST("fc binding: an anchor whose local work is below the floor is "
         "refused") {
        ASSERT(fcb_setup(FCB_WORK_BELOW_FLOOR));
        ASSERT(fcb_refused_as_forgery(fcb_verify()));
        PASS();
    } _test_next:;
    fcb_teardown();
    return failures;
}

/* ── The route: which refusals score the peer ─────────────────────────── */

static bool fcb_route_setup(void)
{
    struct net_address addr;

    if (!fcb_setup(FCB_WORK_ABOVE_FLOOR))
        return false;
    net_manager_init(&g.nm);
    g.runtime.snapshot_sync = &g.svc;
    g.mp.main_state = &g.ms;
    g.mp.params = chain_params_get();
    g.mp.datadir = ".";
    g.mp.net_mgr = &g.nm;
    g.mp.runtime = &g.runtime;

    memset(&addr, 0, sizeof(addr));
    memcpy(addr.svc.addr.ip, pchIPv4Prefix, 12);
    addr.svc.addr.ip[12] = 9;
    addr.svc.port = 18033;
    g.node = p2p_node_create(&g.nm, ZCL_INVALID_SOCKET, &addr, "peer-fc", false);
    if (!g.node)
        return false;
    g.node->version = 1;
    g.node->services = NODE_ZCL23;
    g.node->state = PEER_SNAPSHOT_RECEIVING;
    /* Queued wire segments stay behind this and are never written. */
    g.sentinel = zcl_calloc(1, sizeof(*g.sentinel), "test_fc_binding_sentinel");
    if (!g.sentinel)
        return false;
    g.node->send_head = g.sentinel;
    g.node->send_tail = g.sentinel;
    return true;
}

static bool fcb_route_deliver(void)
{
    struct byte_stream s;
    bool wrote;

    stream_init(&s, 4096);
    wrote = snapsync_write_fc_response(&s, &g.resp).ok;
    if (wrote)
        mp_zs_on_fc_proofs(&g.mp, g.node, &s);
    stream_free(&s);
    return wrote;
}

static int fcb_case_route_scores_forgery(void)
{
    int failures = 0;

    TEST("fc binding route: a forged sample scores the peer") {
        ASSERT(fcb_route_setup());
        fcb_tamper(fcb_sampled_height(0), FCB_FIELD_BLOCK_HASH);
        ASSERT(fcb_prove());
        ASSERT(fcb_route_deliver());
        ASSERT(g.svc.state == SNAPSYNC_NEGOTIATING);
        ASSERT(atomic_load(&g.node->misbehavior) > 0);
        PASS();
    } _test_next:;
    fcb_teardown();
    return failures;
}

static int fcb_case_route_spares_honest_peer(void)
{
    int failures = 0;

    TEST("fc binding route: a peer ahead of us is not scored and may offer "
         "again") {
        ASSERT(fcb_route_setup());
        g.ms.pindex_best_header = &g.idx[FCB_ANCHOR_HEIGHT - 1];
        ASSERT(fcb_route_deliver());
        ASSERT(g.svc.state == SNAPSYNC_IDLE);
        ASSERT(atomic_load(&g.node->misbehavior) == 0);
        /* msg_should_ignore_snapshot_offer drops offers from a peer still
         * marked as receiving. */
        ASSERT(g.node->state == PEER_ACTIVE);
        PASS();
    } _test_next:;
    fcb_teardown();
    return failures;
}

/* ── Roots on the wire ────────────────────────────────────────────────── */

static uint32_t fcb_sampled_boundaries(void)
{
    uint32_t count = 0;

    for (uint32_t i = 0; i < g.sample_count; i++) {
        if (fcb_is_boundary(g.samples[i]))
            count++;
    }
    return count;
}

/* Re-prove under the first seed whose challenge samples a boundary height, so
 * a case that needs a non-zero root on the wire cannot pass for lack of one. */
static bool fcb_prove_sampling_a_boundary(void)
{
    for (unsigned seed = 0; seed < 256; seed++) {
        g.seed = (uint8_t)seed;
        if (!fcb_prove())
            return false;
        if (fcb_sampled_boundaries() > 0)
            return true;
    }
    return false;
}

/* Length of the samples part of a response, written out here because the
 * section cases below must not depend on where the writer ends it. */
static size_t fcb_samples_wire_size(const struct fc_response *resp)
{
    size_t size = 4;

    for (uint32_t i = 0; i < resp->num_samples; i++) {
        const struct mmb_proof *proof = &resp->samples[i].proof;

        size += FCB_SAMPLE_FIXED_WIRE_BYTES +
                32u * ((size_t)proof->num_siblings + proof->num_peaks);
    }
    return size;
}

/* The response's samples with no root section: the older prover's message. */
static void fcb_wire_samples_only(struct byte_stream *out)
{
    struct byte_stream full;

    stream_init(&full, 4096);
    (void)snapsync_write_fc_response(&full, &g.resp);
    stream_init(out, 4096);
    stream_write_bytes(out, full.data, fcb_samples_wire_size(&g.resp));
    stream_free(&full);
}

static void fcb_wire_append_roots(struct byte_stream *out, uint32_t root_count,
                                  uint32_t roots_written)
{
    static const uint8_t filler[32] = { 0x77 };

    stream_write_u32_le(out, root_count);
    for (uint32_t i = 0; i < roots_written; i++)
        stream_write_bytes(out, filler, 32);
}

static bool fcb_parse_wire(const struct byte_stream *wire, size_t size)
{
    struct byte_stream in;
    bool ok;

    stream_init_from_data(&in, wire->data, size);
    ok = snapsync_parse_fc_response(&g.parsed, &in).ok;
    stream_free(&in);
    return ok;
}

static bool fcb_parsed_roots_match_response(void)
{
    for (uint32_t i = 0; i < g.resp.num_samples; i++) {
        if (memcmp(g.parsed.samples[i].leaf.utxo_root,
                   g.resp.samples[i].leaf.utxo_root, 32) != 0)
            return false;
    }
    return true;
}

static bool fcb_parsed_roots_all_zero(void)
{
    static const uint8_t zero[32];

    for (uint32_t i = 0; i < g.parsed.num_samples; i++) {
        if (memcmp(g.parsed.samples[i].leaf.utxo_root, zero, 32) != 0)
            return false;
    }
    return true;
}

static int fcb_case_root_round_trip(void)
{
    int failures = 0;

    TEST("fc wire: roots survive a round trip, in sample order") {
        struct byte_stream wire;

        ASSERT(fcb_setup(FCB_WORK_ABOVE_FLOOR));
        ASSERT(fcb_prove_sampling_a_boundary());
        stream_init(&wire, 4096);
        ASSERT(snapsync_write_fc_response(&wire, &g.resp).ok);
        bool parsed = fcb_parse_wire(&wire, wire.size);
        stream_free(&wire);
        ASSERT(parsed);
        ASSERT(!fcb_parsed_roots_all_zero());
        ASSERT(fcb_parsed_roots_match_response());
        PASS();
    } _test_next:;
    fcb_teardown();
    return failures;
}

static int fcb_case_root_section_absent(void)
{
    int failures = 0;

    TEST("fc wire: an older prover's message with no section parses, and "
         "every root stays zero") {
        struct byte_stream wire;

        ASSERT(fcb_setup(FCB_WORK_ABOVE_FLOOR));
        ASSERT(fcb_prove_sampling_a_boundary());
        fcb_wire_samples_only(&wire);
        bool parsed = fcb_parse_wire(&wire, wire.size);
        stream_free(&wire);
        ASSERT(parsed);
        ASSERT(g.parsed.num_samples == g.resp.num_samples);
        ASSERT(fcb_parsed_roots_all_zero());
        PASS();
    } _test_next:;
    fcb_teardown();
    return failures;
}

static int fcb_case_root_section_truncated(void)
{
    int failures = 0;

    TEST("fc wire: a section cut short is a parse failure") {
        struct byte_stream wire;

        ASSERT(fcb_setup(FCB_WORK_ABOVE_FLOOR));
        fcb_wire_samples_only(&wire);
        size_t samples_size = wire.size;
        fcb_wire_append_roots(&wire, g.resp.num_samples, g.resp.num_samples);
        bool whole = fcb_parse_wire(&wire, wire.size);
        bool one_root_short = fcb_parse_wire(&wire, wire.size - 32);
        bool one_byte_short = fcb_parse_wire(&wire, wire.size - 1);
        bool partial_count = fcb_parse_wire(&wire, samples_size + 3);
        bool count_only = fcb_parse_wire(&wire, samples_size + 4);
        stream_free(&wire);
        ASSERT(whole);
        ASSERT(!one_root_short);
        ASSERT(!one_byte_short);
        ASSERT(!partial_count);
        ASSERT(!count_only);
        PASS();
    } _test_next:;
    fcb_teardown();
    return failures;
}

/* The section written with root_count, and that many roots behind it. */
static bool fcb_parses_with_root_count(uint32_t root_count)
{
    struct byte_stream wire;
    bool parsed;

    fcb_wire_samples_only(&wire);
    fcb_wire_append_roots(&wire, root_count, root_count);
    parsed = fcb_parse_wire(&wire, wire.size);
    stream_free(&wire);
    return parsed;
}

static int fcb_case_root_section_wrong_count(void)
{
    int failures = 0;

    TEST("fc wire: a root count that is not num_samples is a parse failure") {
        ASSERT(fcb_setup(FCB_WORK_ABOVE_FLOOR));
        ASSERT(fcb_parses_with_root_count(g.resp.num_samples));
        ASSERT(!fcb_parses_with_root_count(g.resp.num_samples - 1));
        ASSERT(!fcb_parses_with_root_count(g.resp.num_samples + 1));
        ASSERT(!fcb_parses_with_root_count(0));
        PASS();
    } _test_next:;
    fcb_teardown();
    return failures;
}

static int fcb_case_route_honest_boundary_proof(void)
{
    int failures = 0;

    TEST("fc binding route: an honest proof with non-zero roots at sampled "
         "boundaries crosses the wire and passes") {
        ASSERT(fcb_route_setup());
        ASSERT(fcb_prove_sampling_a_boundary());
        ASSERT(fcb_route_deliver());
        ASSERT(g.svc.state == SNAPSYNC_RECEIVING);
        ASSERT(g.svc.fc_verified);
        ASSERT(atomic_load(&g.node->misbehavior) == 0);
        PASS();
    } _test_next:;
    fcb_teardown();
    return failures;
}

/* What a root does and does not prove: only the peer's own commitment. */
static int fcb_case_root_commitment_limits(void)
{
    int failures = 0;

    TEST("fc binding: a root changed after proving breaks the peer's leaf "
         "hash, but a root the peer's own MMB commits to is not compared") {
        ASSERT(fcb_setup(FCB_WORK_ABOVE_FLOOR));
        ASSERT(fcb_prove_sampling_a_boundary());
        uint32_t at = 0;
        while (!fcb_is_boundary(g.samples[at]))
            at++;
        uint64_t height = g.samples[at];
        g.resp.samples[at].leaf.utxo_root[0] ^= 0x5A;
        ASSERT(fcb_refused_as_forgery(fcb_verify()));
        g.leaves[height].utxo_root[0] ^= 0x5A;
        ASSERT(fcb_prove());
        ASSERT_RESULT_OK(fcb_verify());
        PASS();
    } _test_next:;
    fcb_teardown();
    return failures;
}

/* ── A serve-built offer through the binding ──────────────────────────── */

/* A datadir as a serving node leaves it, with the validated block row for the
 * anchor. tip_height is seeded by hand: nothing in production writes it, and
 * nothing writes tip_hash, so this fixture does not seed that one at all. */
static bool fcb_seed_datadir(const char *dir, bool with_block_row)
{
    char path[600];
    struct node_db ndb;
    const struct block_index *anchor = &g.idx[FCB_ANCHOR_HEIGHT];
    sqlite3_stmt *st = NULL;
    bool ok;

    memset(&ndb, 0, sizeof(ndb));
    snprintf(path, sizeof(path), "%s/node.db", dir);
    if (!node_db_open(&ndb, path))
        return false;
    ok = node_db_state_set_int(&ndb, "tip_height", FCB_ANCHOR_HEIGHT) &&
         sqlite3_exec(ndb.db,
            "INSERT INTO utxos(txid,vout,value,script,script_type,height,"
            "is_coinbase) VALUES(zeroblob(32),0,5000,X'51',0,1,0)",
            NULL, NULL, NULL) == SQLITE_OK;
    if (ok && with_block_row) {
        ok = sqlite3_prepare_v2(ndb.db,
            "INSERT INTO blocks(hash,height,prev_hash,version,merkle_root,time,"
            "bits,nonce,solution,chain_work,status) VALUES(?,?,zeroblob(32),4,"
            "zeroblob(32),1,1,zeroblob(32),zeroblob(1),?,3)",
            -1, &st, NULL) == SQLITE_OK;
        if (ok) {
            sqlite3_bind_blob(st, 1, anchor->hashBlock.data, 32, SQLITE_STATIC);
            sqlite3_bind_int(st, 2, anchor->nHeight);
            sqlite3_bind_blob(st, 3, anchor->nChainWork.pn, 32, SQLITE_STATIC);
            ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-fixture-setup
        }
        sqlite3_finalize(st);
    }
    node_db_close(&ndb);
    return ok;
}

static void fcb_remove_datadir(const char *dir)
{
    static const char *const suffixes[] = { "", "-wal", "-shm" };
    char path[600];

    for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
        snprintf(path, sizeof(path), "%s/node.db%s", dir, suffixes[i]);
        (void)unlink(path);
    }
    (void)rmdir(dir);
}

/* Send the offer as the serve path does and hand its bytes to the receive
 * route; the queued segment is the framed message. */
static void fcb_offer_over_the_wire(const struct snapshot_offer *offer)
{
    struct byte_stream wire;

    send_snapshot_offer_msg(g.node, offer, g.mp.params->pchMessageStart);
    stream_init_from_data(&wire, g.node->send_tail->data + MSG_HEADER_SIZE,
                          g.node->send_tail->size - MSG_HEADER_SIZE);
    mp_zs_on_snapshot_offer(&g.mp, g.node, &wire);
    stream_free(&wire);
}

/* Answer the challenge the service really issued, over the honest MMB. */
static bool fcb_prove_service_challenge(void)
{
    g.challenge = g.svc.fc_challenge;
    fc_generate_indices(g.challenge.seed, g.challenge.chain_length, g.samples,
                        &g.sample_count);
    return fc_build_response(&g.challenge, &g.m, g.leaves,
                             (const uint8_t (*)[32])g.leaf_hashes, &g.resp);
}

static int fcb_case_serve_built_offer_passes(void)
{
    int failures = 0;
    char dir[512] = {0};

    TEST("fc binding: an offer the serve path builds from a node.db, sent over "
         "the wire, passes the gate") {
        struct snapshot_offer offer;
        const struct block_index *anchor = &g.idx[FCB_ANCHOR_HEIGHT];

        ASSERT(fcb_route_setup());
        snapsync_reset(&g.svc);
        g.node->state = PEER_ACTIVE;
        test_make_tmpdir(dir, sizeof(dir), "fcb_serve", "offer");
        ASSERT(fcb_seed_datadir(dir, true));
        fast_sync_reset_utxo_root_cache();
        ASSERT(fast_sync_build_offer(dir, &offer));
        ASSERT(memcmp(offer.block_hash, anchor->hashBlock.data, 32) == 0);
        ASSERT(memcmp(offer.chain_work, anchor->nChainWork.pn, 32) == 0);
        /* The roots boot embeds before publishing. */
        memcpy(offer.mmb_root, g.challenge.mmb_root, 32);
        memset(offer.mmr_root, 0x32, 32);
        fcb_offer_over_the_wire(&offer);
        ASSERT(g.svc.state == SNAPSYNC_NEGOTIATING);
        ASSERT(fcb_prove_service_challenge());
        ASSERT(fcb_route_deliver());
        ASSERT(g.svc.state == SNAPSYNC_RECEIVING);
        ASSERT(atomic_load(&g.node->misbehavior) == 0);
        PASS();
    } _test_next:;
    fast_sync_reset_utxo_root_cache();
    fcb_remove_datadir(dir);
    fcb_teardown();
    return failures;
}

static int fcb_case_serve_built_manifest_names_anchor(void)
{
    int failures = 0;
    char dir[512] = {0};

    TEST("fc binding: a chunk manifest names the validated block at its "
         "height") {
        struct sync_manifest m;
        const struct block_index *anchor = &g.idx[FCB_ANCHOR_HEIGHT];

        memset(&m, 0, sizeof(m));
        ASSERT(fcb_setup(FCB_WORK_ABOVE_FLOOR));
        test_make_tmpdir(dir, sizeof(dir), "fcb_serve", "manifest");
        ASSERT(fcb_seed_datadir(dir, true));
        ASSERT(fast_sync_build_manifest(dir, &m));
        bool named = memcmp(m.block_hash, anchor->hashBlock.data, 32) == 0 &&
                     memcmp(m.anchor_block_hash, anchor->hashBlock.data, 32) == 0 &&
                     memcmp(m.chain_work, anchor->nChainWork.pn, 32) == 0;
        sync_manifest_free(&m);
        ASSERT(named);
        PASS();
    } _test_next:;
    fcb_remove_datadir(dir);
    fcb_teardown();
    return failures;
}

static int fcb_case_serve_refuses_without_block_row(void)
{
    int failures = 0;
    char dir[512] = {0};

    TEST("fc binding: no validated block at the height refuses the offer and "
         "the manifest, rather than offering zeros") {
        static const uint8_t zero[32];
        struct snapshot_offer offer;
        struct sync_manifest m;

        memset(&m, 0, sizeof(m));
        ASSERT(fcb_setup(FCB_WORK_ABOVE_FLOOR));
        test_make_tmpdir(dir, sizeof(dir), "fcb_serve", "refuse");
        ASSERT(fcb_seed_datadir(dir, false));
        fast_sync_reset_utxo_root_cache();
        ASSERT(!fast_sync_build_offer(dir, &offer));
        ASSERT(memcmp(offer.block_hash, zero, 32) == 0);
        bool manifest_built = fast_sync_build_manifest(dir, &m);
        sync_manifest_free(&m);
        ASSERT(!manifest_built);
        PASS();
    } _test_next:;
    fast_sync_reset_utxo_root_cache();
    fcb_remove_datadir(dir);
    fcb_teardown();
    return failures;
}

/* ── The stand-down cooldown ──────────────────────────────────────────── */

/* A valid offer for our own anchor, far enough above our empty active chain. */
static void fcb_offer_params(struct snapshot_offer_params *p, uint32_t peer_id)
{
    const struct block_index *anchor = &g.idx[FCB_ANCHOR_HEIGHT];

    memset(p, 0, sizeof(*p));
    p->height = FCB_ANCHOR_HEIGHT;
    p->peer_tip_height = FCB_ANCHOR_HEIGHT;
    p->our_height = -1;
    p->peer_id = peer_id;
    p->num_utxos = 1;
    p->total_bytes = 80;
    p->protocol_version = FAST_SYNC_PROTOCOL_VERSION;
    p->snapshot_schema_version = FAST_SYNC_SNAPSHOT_SCHEMA_VERSION;
    memcpy(p->block_hash, anchor->hashBlock.data, 32);
    memcpy(p->chain_work, anchor->nChainWork.pn, 32);
    memcpy(p->mmb_root, g.challenge.mmb_root, 32);
    memset(p->utxo_root, 0x31, 32);
    memset(p->mmr_root, 0x32, 32);
}

static enum snapsync_offer_result fcb_offer_from(uint32_t peer_id)
{
    struct snapshot_offer_params p;

    fcb_offer_params(&p, peer_id);
    return snapsync_handle_offer(&g.svc, &p);
}

/* Set up, then stand the service down against FCB_PEER_ID under the fake
 * clock: our best header is behind its anchor. */
static bool fcb_stand_down_under_fake_clock(void)
{
    if (!fcb_setup(FCB_WORK_ABOVE_FLOOR))
        return false;
    fcb_clock_begin();
    g.ms.pindex_best_header = &g.idx[FCB_ANCHOR_HEIGHT - 1];
    return fcb_stood_down(fcb_verify());
}

static int fcb_case_cooldown_same_peer(void)
{
    int failures = 0;

    TEST("fc cooldown: the peer that stood down is ignored for 60 seconds, "
         "then heard") {
        ASSERT(fcb_stand_down_under_fake_clock());
        ASSERT(fcb_offer_from(FCB_PEER_ID) ==
               SNAPSYNC_OFFER_REJECTED_BLACKLISTED);
        fcb_clock_advance_secs(59);
        ASSERT(fcb_offer_from(FCB_PEER_ID) ==
               SNAPSYNC_OFFER_REJECTED_BLACKLISTED);
        ASSERT(g.svc.state == SNAPSYNC_IDLE);
        fcb_clock_advance_secs(1);
        ASSERT(fcb_offer_from(FCB_PEER_ID) == SNAPSYNC_OFFER_ACCEPTED);
        ASSERT(g.svc.state == SNAPSYNC_NEGOTIATING);
        PASS();
    } _test_next:;
    fcb_teardown();
    return failures;
}

static int fcb_case_cooldown_other_peer(void)
{
    int failures = 0;

    TEST("fc cooldown: a different peer's offer is heard inside the window") {
        ASSERT(fcb_stand_down_under_fake_clock());
        ASSERT(fcb_offer_from(FCB_PEER_ID + 1) == SNAPSYNC_OFFER_ACCEPTED);
        ASSERT(g.svc.state == SNAPSYNC_NEGOTIATING);
        ASSERT(g.svc.serving_peer_id == FCB_PEER_ID + 1);
        PASS();
    } _test_next:;
    fcb_teardown();
    return failures;
}

static int fcb_case_cooldown_keeps_stall_blacklist(void)
{
    int failures = 0;

    TEST("fc cooldown: a stand-down does not shorten a stall blacklist") {
        ASSERT(fcb_setup(FCB_WORK_ABOVE_FLOOR));
        fcb_clock_begin();
        snapsync_blacklist_peer(&g.svc, FCB_PEER_ID);
        g.ms.pindex_best_header = &g.idx[FCB_ANCHOR_HEIGHT - 1];
        ASSERT(fcb_stood_down(fcb_verify()));
        fcb_clock_advance_secs(SNAPSYNC_BLACKLIST_SECS - 1);
        ASSERT(fcb_offer_from(FCB_PEER_ID) ==
               SNAPSYNC_OFFER_REJECTED_BLACKLISTED);
        fcb_clock_advance_secs(1);
        ASSERT(fcb_offer_from(FCB_PEER_ID) == SNAPSYNC_OFFER_ACCEPTED);
        PASS();
    } _test_next:;
    fcb_teardown();
    return failures;
}

int test_snapshot_fc_binding(void)
{
    int failures = 0;

    failures += fcb_case_honest_proof_passes();
    failures += fcb_case_tampered_field(
        "fc binding: a leaf with a different block hash, under target with a "
        "valid MMB proof, is a forgery", FCB_FIELD_BLOCK_HASH);
    failures += fcb_case_tampered_field(
        "fc binding: a leaf with a different timestamp is a forgery",
        FCB_FIELD_TIMESTAMP);
    failures += fcb_case_tampered_field(
        "fc binding: a leaf with different nBits is a forgery",
        FCB_FIELD_NBITS);
    failures += fcb_case_tampered_field(
        "fc binding: a leaf with a different sapling root is a forgery",
        FCB_FIELD_SAPLING_ROOT);
    failures += fcb_case_claimed_size_differs();
    failures += fcb_case_best_header_behind();
    failures += fcb_case_no_best_header();
    failures += fcb_case_anchor_hash_differs();
    failures += fcb_case_anchor_work_differs();
    failures += fcb_case_sample_work_differs();
    failures += fcb_case_forgery_outranks_work_difference();
    failures += fcb_case_local_ancestor_missing();
    failures += fcb_case_local_anchor_below_floor();
    failures += fcb_case_no_main_state();
    failures += fcb_case_route_scores_forgery();
    failures += fcb_case_route_spares_honest_peer();
    failures += fcb_case_root_round_trip();
    failures += fcb_case_root_section_absent();
    failures += fcb_case_root_section_truncated();
    failures += fcb_case_root_section_wrong_count();
    failures += fcb_case_route_honest_boundary_proof();
    failures += fcb_case_root_commitment_limits();
    failures += fcb_case_serve_built_offer_passes();
    failures += fcb_case_serve_built_manifest_names_anchor();
    failures += fcb_case_serve_refuses_without_block_row();
    failures += fcb_case_cooldown_same_peer();
    failures += fcb_case_cooldown_other_peer();
    failures += fcb_case_cooldown_keeps_stall_blacklist();

    printf("test_snapshot_fc_binding: %s\n",
           failures == 0 ? "all passed" : "FAILED");
    return failures;
}
