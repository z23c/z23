/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The FlyClient gate binds a peer's proof to headers this node validated.
 *
 * ZClassic headers commit no MMB root, and a sample's block_hash and nBits are
 * chosen by the prover, so a value under the target proves no work. Every case
 * here builds a local header chain, has a "peer" prove over leaves derived
 * from it (as snapsync_fc_leaf_from_block_index does), and then tampers with
 * one thing:
 *   - a hash-committed field, or the claimed size: a forgery, and an offence;
 *   - nothing the peer got wrong (our best header is behind, the anchor is on
 *     a chain we have not seen, or only the uncommitted chain_work differs):
 *     no offence, and the service stands down so a later offer is heard.
 * The service owns an open in-memory node_db, so a gate that wrongly passes
 * really does enter RECEIVING. */

#include "test/test_core.h"

#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/mmb.h"
#include "config/runtime.h"
#include "core/arith_uint256.h"
#include "core/serialize.h"
#include "models/database.h"
#include "net/flyclient.h"
#include "net/msg_internal.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/peer_scoring.h"
#include "net/snapshot_sync_contract.h"
#include "sync/sync_state.h"
#include "util/safe_alloc.h"
#include "validation/main_state.h"

#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

#ifndef SNAPSYNC_FLYCLIENT_UNVERIFIABLE_ERROR_CODE
#define SNAPSYNC_FLYCLIENT_UNVERIFIABLE_ERROR_CODE (-13)
#endif

void mp_zs_on_fc_proofs(struct msg_processor *mp, struct p2p_node *node,
                        struct byte_stream *s);

/* Long enough for FC_NUM_SAMPLES distinct heights below the anchor. */
#define FCB_BLOCKS 128
#define FCB_ANCHOR_HEIGHT (FCB_BLOCKS - 1)
#define FCB_NBITS 0x1f07ffffu
#define FCB_PEER_ID 77u
#define FCB_LEAF_COUNT_MASK 0xFFFFFFFFFFULL
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
    uint64_t samples[FC_MAX_SAMPLES];
    uint32_t sample_count;
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

static void fcb_leaves_from_local_chain(void)
{
    static const uint8_t zero_utxo_root[32];

    for (uint32_t i = 0; i < FCB_BLOCKS; i++) {
        const struct block_index *bi = &g.idx[i];

        mmb_leaf_from_block(&g.leaves[i], bi->hashBlock.data, bi->nHeight,
                            bi->nTime, bi->nBits, bi->hashFinalSaplingRoot.data,
                            (const uint8_t *)bi->nChainWork.pn, zero_utxo_root);
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
    memset(g.challenge.seed, 0x5C, sizeof(g.challenge.seed));
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
}

static struct zcl_result fcb_verify(void)
{
    return snapsync_verify_flyclient(&g.svc, &g.resp);
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
    failures += fcb_case_route_scores_forgery();
    failures += fcb_case_route_spares_honest_peer();

    printf("test_snapshot_fc_binding: %s\n",
           failures == 0 ? "all passed" : "FAILED");
    return failures;
}
