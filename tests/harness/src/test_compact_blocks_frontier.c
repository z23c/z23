/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * A compact block whose rebuild does not match its header falls back to a
 * full-block request, but never for a height the node already has behind it:
 * the larger of the active chain height and the provable frontier (H*), which
 * runs ahead of the chain on a seeded node. Called from test_compact_blocks. */

#include "test/test_core.h"

#include "bloom/merkle.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "core/arith_uint256.h"
#include "jobs/reducer_frontier.h"
#include "net/compact_blocks.h"
#include "net/download.h"
#include "net/msg_internal.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/peer_scoring.h"
#include "platform/socket_compat.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "sync/sync_state.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "validation/txmempool.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CBF_TIP 100
#define CBF_HSTAR 150

static void cbf_tx(struct transaction *tx, uint32_t lock_time)
{
    transaction_init(tx);
    tx->version = 4;
    tx->overwintered = true;
    tx->version_group_id = SAPLING_VERSION_GROUP_ID;
    tx->lock_time = lock_time;
    tx->num_vin = 1;
    tx->vin = calloc(1, sizeof(struct tx_in));
    tx_in_init(&tx->vin[0]);
    transaction_compute_hash(tx);
}

/* A one-transaction block under an easy header, and the same header over a
 * different transaction: the rebuild is complete and wrong. */
static void cbf_blocks(struct block *real, struct block *bad, uint8_t tag)
{
    block_init(real);
    real->header.nVersion = 4;
    real->header.nTime = 1700000900u;
    struct arith_uint256 easy;
    arith_uint256_set_compact(&easy, 0x2100ffffu, NULL, NULL);
    real->header.nBits = arith_uint256_get_compact(&easy, false);
    real->header.nNonce.data[0] = tag;
    real->num_vtx = 1;
    real->vtx = calloc(1, sizeof(struct transaction));
    cbf_tx(&real->vtx[0], 100);
    real->header.hashMerkleRoot = compute_merkle_root(&real->vtx[0].hash, 1);
    block_init(bad);
    bad->header = real->header;
    bad->num_vtx = 1;
    bad->vtx = calloc(1, sizeof(struct transaction));
    cbf_tx(&bad->vtx[0], 900);
}

static size_t cbf_sent(const struct p2p_node *node, const char *name)
{
    size_t count = 0;
    for (const struct send_segment *seg = node->send_head; seg;
         seg = seg->next)
        if (seg->size >= MSG_HEADER_SIZE &&
            strcmp((const char *)seg->data + MESSAGE_START_SIZE, name) == 0)
            count++;
    return count;
}

/* The mismatched compact block's header sits at `height`, the chain tip at
 * CBF_TIP and H* at `hstar`. True when a full block was asked for. */
static int cbf_run(int height, int hstar, bool expect_request, uint8_t tag)
{
    int failures = 0;
    printf("compact fallback: header at %d, tip %d, frontier %d... ", height,
           CBF_TIP, hstar);

    struct chain_params params = *chain_params_get();
    memset(params.consensus.powLimit.data, 0xff, 32);
    peer_scoring_init();
    dl_free(get_download_mgr());
    dl_init(get_download_mgr());
    (void)sync_set_state(SYNC_IDLE, "frontier setup");
    (void)sync_set_state(SYNC_FINDING_PEERS, "frontier setup");
    (void)sync_set_state(SYNC_HEADERS_DOWNLOAD, "frontier setup");
    (void)sync_set_state(SYNC_BLOCKS_DOWNLOAD, "frontier setup");

    struct main_state ms;
    struct net_manager nm;
    struct tx_mempool pool;
    main_state_init(&ms);
    net_manager_init(&nm);
    tx_mempool_init(&pool, 0);
    struct msg_processor mp;
    memset(&mp, 0, sizeof(mp));
    mp.main_state = &ms;
    mp.params = &params;
    mp.net_mgr = &nm;
    mp.mempool = &pool;

    struct net_address addr;
    net_address_init(&addr);
    unsigned char ip[4] = {198, 51, 100, 21};
    net_addr_set_ipv4(&addr.svc.addr, ip);
    addr.svc.port = 8033;
    struct p2p_node *peer =
        p2p_node_create(&nm, ZCL_INVALID_SOCKET, &addr, "frontier-peer", true);

    struct block real, bad;
    cbf_blocks(&real, &bad, tag);
    struct uint256 hash, tip_hash;
    block_get_hash(&real, &hash);
    memset(&tip_hash, 0xdd, sizeof(tip_hash));
    struct block_index *tip =
        chainstate_insert_block_index((struct chainstate *)&ms, &tip_hash);
    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)&ms, &hash);
    if (!peer || !tip || !bi) {
        printf("FAIL (setup)\n");
        failures = 1;
        goto out;
    }
    tip->nHeight = CBF_TIP;
    tip->nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
    active_chain_move_window_tip(&ms.chain_active, tip);
    ms.pindex_best_header = tip;
    bi->nHeight = height;
    bi->nStatus = 0;
    reducer_frontier_provable_tip_set(hstar);

    struct compact_block_msg cb;
    struct byte_stream s;
    stream_init(&s, 1024);
    bool sent = compact_block_from_block(&cb, &bad, 7) &&
                compact_block_msg_serialize(&cb, &s) &&
                process_cmpctblock(&mp, peer, &s);
    stream_free(&s);
    compact_block_msg_free(&cb);
    if (!sent || (cbf_sent(peer, "getdata") == 1) != expect_request ||
        dl_is_in_flight(get_download_mgr(), &hash) != expect_request ||
        atomic_load(&peer->misbehavior) != 0) {
        printf("FAIL (getdata=%zu in_flight=%d)\n", cbf_sent(peer, "getdata"),
               dl_is_in_flight(get_download_mgr(), &hash));
        failures = 1;
    } else {
        printf("OK\n");
    }
out:
    reducer_frontier_provable_tip_reset();
    (void)sync_set_state(SYNC_IDLE, "frontier teardown");
    block_free(&real);
    block_free(&bad);
    if (peer)
        p2p_node_free(peer);
    tx_mempool_free(&pool);
    net_manager_free(&nm);
    main_state_free(&ms);
    return failures;
}

int compact_blocks_frontier_tests(void)
{
    int failures = 0;
    /* No frontier ahead of the chain: just above the tip still asks. */
    failures += cbf_run(CBF_TIP + 1, 0, true, 91);
    /* Frontier ahead of the chain: at or below it asks for nothing. */
    failures += cbf_run(CBF_TIP + 20, CBF_HSTAR, false, 92);
    failures += cbf_run(CBF_HSTAR, CBF_HSTAR, false, 93);
    failures += cbf_run(CBF_HSTAR + 1, CBF_HSTAR, true, 94);
    return failures;
}

/* A stored block is dropped on re-announcement only once it is on the active
 * chain. HAVE_DATA is set before the reducer finalizes a block, and a stored
 * block not yet connected is retried by its next arrival, so it must still be
 * submitted. */
static int cbf_submits;

static bool cbf_count_submit(struct block *blk, struct validation_state *st,
                             void *ctx)
{
    (void)blk;
    (void)st;
    (void)ctx;
    cbf_submits++;
    return true;
}

static int cbf_held(uint32_t status, bool on_chain, int expect_submits,
                    uint8_t tag)
{
    int failures = 0;
    printf("compact stored block: status %u, %s... ", status,
           on_chain ? "on the active chain" : "not connected");

    struct chain_params params = *chain_params_get();
    memset(params.consensus.powLimit.data, 0xff, 32);
    peer_scoring_init();
    msgprocessor_test_reset_recent_blocks();
    struct main_state ms;
    struct net_manager nm;
    struct tx_mempool pool;
    main_state_init(&ms);
    net_manager_init(&nm);
    tx_mempool_init(&pool, 0);
    struct msg_processor mp;
    memset(&mp, 0, sizeof(mp));
    mp.main_state = &ms;
    mp.params = &params;
    mp.net_mgr = &nm;
    mp.mempool = &pool;
    mp.compact_block_submit = cbf_count_submit;

    struct net_address addr;
    net_address_init(&addr);
    unsigned char ip[4] = {198, 51, 100, 22};
    net_addr_set_ipv4(&addr.svc.addr, ip);
    addr.svc.port = 8033;
    struct p2p_node *peer =
        p2p_node_create(&nm, ZCL_INVALID_SOCKET, &addr, "held-peer", true);

    struct block real, bad;
    cbf_blocks(&real, &bad, tag);
    struct uint256 hash;
    block_get_hash(&real, &hash);
    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)&ms, &hash);
    if (!peer || !bi) {
        printf("FAIL (setup)\n");
        failures = 1;
        goto out;
    }
    bi->nHeight = 5;
    bi->nStatus = status;
    if (on_chain)
        active_chain_move_window_tip(&ms.chain_active, bi);

    cbf_submits = 0;
    struct compact_block_msg cb;
    struct byte_stream s;
    stream_init(&s, 1024);
    bool sent = compact_block_from_block(&cb, &real, 7) &&
                compact_block_msg_serialize(&cb, &s) &&
                process_cmpctblock(&mp, peer, &s);
    stream_free(&s);
    compact_block_msg_free(&cb);
    if (!sent || cbf_submits != expect_submits ||
        atomic_load(&peer->misbehavior) != 0) {
        printf("FAIL (submits=%d, want %d)\n", cbf_submits, expect_submits);
        failures = 1;
    } else {
        printf("OK\n");
    }
out:
    block_free(&real);
    block_free(&bad);
    if (peer)
        p2p_node_free(peer);
    tx_mempool_free(&pool);
    net_manager_free(&nm);
    main_state_free(&ms);
    return failures;
}

int compact_blocks_stored_tests(void)
{
    int failures = 0;
    uint32_t stored = BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
    failures += cbf_held(stored, true, 0, 95);
    failures += cbf_held(stored, false, 1, 96);
    failures += cbf_held(BLOCK_VALID_SCRIPTS, false, 1, 97);
    failures += cbf_held(stored | BLOCK_FAILED_VALID, true, 1, 98);
    return failures;
}
