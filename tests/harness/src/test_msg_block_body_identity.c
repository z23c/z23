/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * A block's hash covers its header. A body that does not match the header's
 * merkle commitment says nothing about the block with that hash, so it must
 * not make this node ignore that block, and the block stays fetchable from
 * any peer. A body that does match keeps the old treatment: when rejected it
 * is marked seen. Called from test_msg_handlers. */

#include "test/test_core.h"

#include "bloom/merkle.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "consensus/validation.h"
#include "core/arith_uint256.h"
#include "core/serialize.h"
#include "core/uint256.h"
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
#include "validation/check_block.h"
#include "validation/main_state.h"
#include "validation/txmempool.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BBI_CHECK(cond) do { \
    if (!(cond)) { \
        printf("FAIL at %s:%d (%s)\n", __FILE__, __LINE__, #cond); \
        failures++; \
    } \
} while (0)

#define BBI_GETDATA_PAYLOAD_SIZE 37 /* compact count(1) + type(4) + hash(32) */

struct bbi_submit {
    _Atomic int calls;
    _Atomic int accepted;
    _Atomic int drains;
    const char *reject_matching; /* a reject for a body that matches */
    const char *reject_all;      /* a reject that needs no merkle check */
};

/* The fixture: one msg_processor, one chain index, two scored peers. */
struct bbi_env {
    struct chain_params params;
    struct main_state ms;
    struct net_manager nm;
    struct tx_mempool pool;
    struct msg_processor mp;
    struct bbi_submit submit;
    struct p2p_node *sender;
    struct p2p_node *honest;
};

static void bbi_make_tx(struct transaction *tx, uint32_t lock_time)
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

/* A block of n transactions numbered from first_lock, under `hdr` as given. */
static void bbi_body(struct block *blk, const struct block_header *hdr,
                     size_t n, uint32_t first_lock)
{
    block_init(blk);
    blk->header = *hdr;
    blk->num_vtx = n;
    blk->vtx = calloc(n, sizeof(struct transaction));
    for (size_t i = 0; i < n; i++)
        bbi_make_tx(&blk->vtx[i], first_lock + (uint32_t)i);
}

/* The real block: its header commits to its n transactions. */
static void bbi_real_block(struct block *blk, size_t n, uint8_t tag)
{
    struct block_header hdr;
    block_header_init(&hdr);
    hdr.nVersion = 4;
    hdr.nTime = 1700000900u;
    struct arith_uint256 easy;
    arith_uint256_set_compact(&easy, 0x2100ffffu, NULL, NULL);
    hdr.nBits = arith_uint256_get_compact(&easy, false);
    hdr.nNonce.data[0] = tag;
    bbi_body(blk, &hdr, n, 100);

    struct uint256 txids[8];
    for (size_t i = 0; i < n && i < 8; i++)
        txids[i] = blk->vtx[i].hash;
    blk->header.hashMerkleRoot = compute_merkle_root(txids, n);
}

/* The real header over different transactions. */
static void bbi_wrong_body(struct block *wrong, const struct block *real)
{
    bbi_body(wrong, &real->header, real->num_vtx, 900);
}

/* The real header and the real transactions with the last one repeated: the
 * merkle root is unchanged, and the block is still not the real one. */
static void bbi_mutated_body(struct block *mutated, const struct block *real)
{
    bbi_body(mutated, &real->header, real->num_vtx + 1, 100);
    transaction_free(&mutated->vtx[real->num_vtx]);
    bbi_make_tx(&mutated->vtx[real->num_vtx],
                100 + (uint32_t)(real->num_vtx - 1));
}

/* What at-tip intake does first: the header, then the merkle commitment. */
static bool bbi_submit_like_tip(struct block *blk, struct validation_state *out,
                                void *ctx)
{
    struct bbi_submit *c = ctx;
    atomic_fetch_add(&c->calls, 1);
    if (c->reject_all) {
        validation_state_dos(out, 10, false, REJECT_INVALID, c->reject_all,
                             false, NULL);
        return false;
    }
    if (!check_block(blk, out, chain_params_get(), false, true, false))
        return false;
    if (c->reject_matching) {
        validation_state_dos(out, 100, false, REJECT_INVALID,
                             c->reject_matching, false, NULL);
        return false;
    }
    atomic_fetch_add(&c->accepted, 1);
    return true;
}

static int bbi_count_drain(void *ctx)
{
    struct bbi_submit *c = ctx;
    atomic_fetch_add(&c->drains, 1);
    return 0;
}

/* Wait on the worker's post-verdict drain; no deadline to lose to a busy host. */
static void bbi_wait_for_drain(struct bbi_submit *c)
{
    while (atomic_load(&c->drains) == 0) {
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000L };
        nanosleep(&ts, NULL);
    }
}

static void bbi_sync_to(enum sync_state target)
{
    (void)sync_set_state(SYNC_IDLE, "body identity setup");
    (void)sync_set_state(SYNC_FINDING_PEERS, "body identity setup");
    (void)sync_set_state(SYNC_HEADERS_DOWNLOAD, "body identity setup");
    (void)sync_set_state(SYNC_BLOCKS_DOWNLOAD, "body identity setup");
    if (target == SYNC_AT_TIP)
        (void)sync_try_transition(SYNC_BLOCKS_DOWNLOAD, SYNC_AT_TIP,
                                  "body identity premise");
}

static struct p2p_node *bbi_peer(struct net_manager *nm, unsigned char last)
{
    struct net_address addr;
    net_address_init(&addr);
    unsigned char ip[4] = {198, 51, 100, last};
    net_addr_set_ipv4(&addr.svc.addr, ip);
    addr.svc.port = 8033;
    return p2p_node_create(nm, ZCL_INVALID_SOCKET, &addr, "body-peer", true);
}

static bool bbi_env_init(struct bbi_env *e, enum sync_state sync)
{
    memset(e, 0, sizeof(*e));
    e->params = *chain_params_get();
    memset(e->params.consensus.powLimit.data, 0xff, 32);
    peer_scoring_init();
    msgprocessor_test_reset_recent_blocks();
    dl_free(get_download_mgr());
    dl_init(get_download_mgr());
    main_state_init(&e->ms);
    net_manager_init(&e->nm);
    tx_mempool_init(&e->pool, 0);
    e->mp.main_state = &e->ms;
    e->mp.params = &e->params;
    e->mp.net_mgr = &e->nm;
    e->mp.mempool = &e->pool;
    e->mp.block_submit = bbi_submit_like_tip;
    e->mp.block_submit_ctx = &e->submit;
    e->mp.compact_block_submit = bbi_submit_like_tip;
    e->mp.compact_block_submit_ctx = &e->submit;
    e->mp.catchup_drain = bbi_count_drain;
    e->mp.catchup_drain_ctx = &e->submit;
    e->sender = bbi_peer(&e->nm, 11);
    e->honest = bbi_peer(&e->nm, 12);
    bbi_sync_to(sync);
    return e->sender && e->honest && sync_get_state() == sync;
}

static void bbi_env_free(struct bbi_env *e)
{
    msg_processor_stop_block_intake(&e->mp);
    (void)sync_set_state(SYNC_IDLE, "body identity teardown");
    if (e->sender)
        p2p_node_free(e->sender);
    if (e->honest)
        p2p_node_free(e->honest);
    tx_mempool_free(&e->pool);
    net_manager_free(&e->nm);
    main_state_free(&e->ms);
}

static bool bbi_deliver_block(struct bbi_env *e, struct p2p_node *from,
                              const struct block *blk)
{
    struct byte_stream s;
    stream_init(&s, 1024);
    bool ok = block_serialize(blk, &s) &&
              process_block_msg(&e->mp, from, &s);
    stream_free(&s);
    return ok;
}

static bool bbi_deliver_compact(struct bbi_env *e, struct p2p_node *from,
                                const struct block *blk)
{
    struct compact_block_msg cb;
    if (!compact_block_from_block(&cb, blk, 7))
        return false;
    struct byte_stream s;
    stream_init(&s, 1024);
    bool ok = compact_block_msg_serialize(&cb, &s) &&
              process_cmpctblock(&e->mp, from, &s);
    stream_free(&s);
    compact_block_msg_free(&cb);
    return ok;
}

/* Answer the sender's pending getblocktxn with blk's non-coinbase txs. */
static bool bbi_deliver_blocktxn(struct bbi_env *e, struct p2p_node *from,
                                 const struct block *blk)
{
    struct block_txn_response resp;
    block_txn_response_init(&resp);
    block_get_hash(blk, &resp.block_hash);
    resp.num_txs = blk->num_vtx - 1;
    resp.txs = calloc(resp.num_txs, sizeof(struct transaction));
    bool ok = resp.txs != NULL;
    for (size_t i = 0; ok && i < resp.num_txs; i++) {
        transaction_init(&resp.txs[i]);
        ok = transaction_copy(&resp.txs[i], &blk->vtx[i + 1]);
    }
    struct byte_stream s;
    stream_init(&s, 1024);
    ok = ok && block_txn_response_serialize(&resp, &s) &&
         process_blocktxn(&e->mp, from, &s);
    stream_free(&s);
    block_txn_response_free(&resp);
    return ok;
}

static int bbi_score(const struct p2p_node *node)
{
    return atomic_load(&node->misbehavior);
}

static void bbi_drop_sends(struct p2p_node *node)
{
    while (node->send_head) {
        struct send_segment *seg = node->send_head;
        node->send_head = seg->next;
        send_segment_free(seg);
    }
    node->send_tail = NULL;
    node->send_size = 0;
}

/* True when node's queue holds a getdata naming `hash` as a full block. */
static bool bbi_sent_getdata(const struct p2p_node *node,
                             const struct uint256 *hash)
{
    for (const struct send_segment *seg = node->send_head; seg;
         seg = seg->next) {
        if (seg->size != MSG_HEADER_SIZE + BBI_GETDATA_PAYLOAD_SIZE)
            continue;
        if (strcmp((const char *)seg->data + MESSAGE_START_SIZE,
                   "getdata") != 0)
            continue;
        const unsigned char *p =
            (const unsigned char *)seg->data + MSG_HEADER_SIZE;
        uint32_t type = (uint32_t)p[1] | ((uint32_t)p[2] << 8) |
                        ((uint32_t)p[3] << 16) | ((uint32_t)p[4] << 24);
        if (p[0] == 1 && type == MSG_BLOCK &&
            memcmp(p + 5, hash->data, 32) == 0)
            return true;
    }
    return false;
}

/* At the tip: the wrong body is rejected and its sender scored, the block
 * index is untouched, the hash stays out of the dedup ring, a fresh request can
 * be made at once, and the real block is then accepted from another peer. */
static int bbi_run_tip_full_block(bool mutated, const char *name)
{
    int failures = 0;
    printf("block body identity: at tip, %s... ", name);

    struct bbi_env e;
    if (!bbi_env_init(&e, SYNC_AT_TIP)) {
        printf("FAIL (setup)\n");
        bbi_env_free(&e);
        return 1;
    }
    struct block real, bad;
    bbi_real_block(&real, 3, 41);
    if (mutated)
        bbi_mutated_body(&bad, &real);
    else
        bbi_wrong_body(&bad, &real);
    struct uint256 hash;
    block_get_hash(&real, &hash);
    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)&e.ms, &hash);
    if (!bi) {
        printf("FAIL (setup index)\n");
        failures = 1;
        goto out;
    }
    bi->nHeight = 1;
    bi->nStatus = 0;

    struct download_manager *dm = get_download_mgr();
    BBI_CHECK(dl_mark_requested(dm, &hash, 1, (uint32_t)e.sender->id));
    BBI_CHECK(bbi_deliver_block(&e, e.sender, &bad));
    BBI_CHECK(atomic_load(&e.submit.calls) == 1);
    BBI_CHECK(atomic_load(&e.submit.accepted) == 0);
    BBI_CHECK(!block_already_seen(&hash));
    BBI_CHECK(bbi_score(e.sender) ==
              peer_offence_weight(PEER_OFFENCE_INVALID_BLOCK));
    BBI_CHECK((bi->nStatus & BLOCK_FAILED_MASK) == 0);

    /* Another peer can be asked straight away. */
    BBI_CHECK(dl_mark_requested(dm, &hash, 1, (uint32_t)e.honest->id));
    BBI_CHECK(bbi_deliver_block(&e, e.honest, &real));
    BBI_CHECK(atomic_load(&e.submit.calls) == 2);
    BBI_CHECK(atomic_load(&e.submit.accepted) == 1);
    BBI_CHECK(bbi_score(e.honest) == 0);
    BBI_CHECK((bi->nStatus & BLOCK_FAILED_MASK) == 0);
    if (!failures)
        printf("OK\n");
out:
    block_free(&real);
    block_free(&bad);
    bbi_env_free(&e);
    return failures;
}

/* A wrong body from a peer we did not ask cannot cancel the request we made of
 * another peer, and that peer's real block is not treated as unrequested. */
static int bbi_test_wrong_body_keeps_other_request(void)
{
    int failures = 0;
    printf("block body identity: a wrong body leaves another peer's request "
           "live... ");

    struct bbi_env e;
    if (!bbi_env_init(&e, SYNC_AT_TIP)) {
        printf("FAIL (setup)\n");
        bbi_env_free(&e);
        return 1;
    }
    struct block real, bad;
    bbi_real_block(&real, 3, 42);
    bbi_wrong_body(&bad, &real);
    struct uint256 hash;
    block_get_hash(&real, &hash);

    struct download_manager *dm = get_download_mgr();
    BBI_CHECK(dl_mark_requested(dm, &hash, 1, (uint32_t)e.honest->id));
    BBI_CHECK(bbi_deliver_block(&e, e.sender, &bad));
    BBI_CHECK(dl_is_in_flight(dm, &hash));
    BBI_CHECK(bbi_deliver_block(&e, e.honest, &real));
    BBI_CHECK(atomic_load(&e.submit.accepted) == 1);
    BBI_CHECK(bbi_score(e.honest) == 0);
    if (!failures)
        printf("OK\n");
    block_free(&real);
    block_free(&bad);
    bbi_env_free(&e);
    return failures;
}

/* A body that matches its header and is rejected keeps the old treatment. */
static int bbi_test_matching_reject_marks_seen(void)
{
    int failures = 0;
    printf("block body identity: a rejected body that matches its header is "
           "marked seen and scored... ");

    struct bbi_env e;
    if (!bbi_env_init(&e, SYNC_AT_TIP)) {
        printf("FAIL (setup)\n");
        bbi_env_free(&e);
        return 1;
    }
    struct block real;
    bbi_real_block(&real, 3, 43);
    struct uint256 hash;
    block_get_hash(&real, &hash);
    e.submit.reject_matching = "bad-txns-inputs-missingorspent";

    struct download_manager *dm = get_download_mgr();
    BBI_CHECK(dl_mark_requested(dm, &hash, 1, (uint32_t)e.sender->id));
    BBI_CHECK(bbi_deliver_block(&e, e.sender, &real));
    BBI_CHECK(atomic_load(&e.submit.calls) == 1);
    BBI_CHECK(block_already_seen(&hash));
    BBI_CHECK(bbi_score(e.sender) ==
              peer_offence_weight(PEER_OFFENCE_INVALID_BLOCK));
    BBI_CHECK(bbi_deliver_block(&e, e.honest, &real));
    BBI_CHECK(atomic_load(&e.submit.calls) == 1);
    if (!failures)
        printf("OK\n");
    block_free(&real);
    bbi_env_free(&e);
    return failures;
}

/* The intake worker's reject may name something other than the merkle root,
 * since catch-up intake leaves that check for later: what decides is whether
 * the body matches its header, not the reason given. */
static int bbi_run_worker_reject(bool wrong, const char *name)
{
    int failures = 0;
    printf("block body identity: intake worker, %s... ", name);

    struct bbi_env e;
    if (!bbi_env_init(&e, SYNC_BLOCKS_DOWNLOAD)) {
        printf("FAIL (setup)\n");
        bbi_env_free(&e);
        return 1;
    }
    struct block real, bad;
    bbi_real_block(&real, 3, wrong ? 44 : 45);
    bbi_wrong_body(&bad, &real);
    struct uint256 hash;
    block_get_hash(&real, &hash);
    e.submit.reject_all = "bad-txns-vin-empty";

    struct validation_state state;
    validation_state_init(&state);
    BBI_CHECK(msg_processor_enqueue_p2p_block(&e.mp, wrong ? &bad : &real,
                                              &hash, 11, &state));
    bbi_wait_for_drain(&e.submit);
    BBI_CHECK(atomic_load(&e.submit.calls) == 1);
    BBI_CHECK(block_already_seen(&hash) == !wrong);
    if (!failures)
        printf("OK\n");
    block_free(&real);
    block_free(&bad);
    bbi_env_free(&e);
    return failures;
}

/* In catch-up a body is staged on disk before its merkle root is looked at, and
 * the body that gets there first stays. So a body that does not match never
 * enters intake, its sender is scored, and the real block still goes through. */
static int bbi_run_catchup_full_block(bool mutated, const char *name)
{
    int failures = 0;
    printf("block body identity: in catch-up, %s... ", name);

    struct bbi_env e;
    if (!bbi_env_init(&e, SYNC_BLOCKS_DOWNLOAD)) {
        printf("FAIL (setup)\n");
        bbi_env_free(&e);
        return 1;
    }
    struct block real, bad;
    bbi_real_block(&real, 3, mutated ? 47 : 46);
    if (mutated)
        bbi_mutated_body(&bad, &real);
    else
        bbi_wrong_body(&bad, &real);
    struct uint256 hash;
    block_get_hash(&real, &hash);

    struct download_manager *dm = get_download_mgr();
    BBI_CHECK(dl_mark_requested(dm, &hash, 1, (uint32_t)e.sender->id));
    BBI_CHECK(bbi_deliver_block(&e, e.sender, &bad));
    struct msg_block_intake_stats stats;
    msg_processor_get_block_intake_stats(&e.mp, &stats);
    BBI_CHECK(stats.enqueued == 0);
    BBI_CHECK(!block_already_seen(&hash));
    BBI_CHECK(bbi_score(e.sender) ==
              peer_offence_weight(PEER_OFFENCE_INVALID_BLOCK));
    BBI_CHECK(dl_mark_requested(dm, &hash, 1, (uint32_t)e.honest->id));

    if (!failures) {
        BBI_CHECK(bbi_deliver_block(&e, e.honest, &real));
        msg_processor_get_block_intake_stats(&e.mp, &stats);
        BBI_CHECK(stats.enqueued == 1);
        BBI_CHECK(bbi_score(e.honest) == 0);
        bbi_wait_for_drain(&e.submit);
        BBI_CHECK(atomic_load(&e.submit.accepted) == 1);
    }
    if (!failures)
        printf("OK\n");
    block_free(&real);
    block_free(&bad);
    bbi_env_free(&e);
    return failures;
}

/* Checks shared by the two compact routes once a reconstruction came out wrong:
 * no submit, no mark, no score, and the full block is asked of the same peer,
 * which then delivers it without being treated as having pushed it. */
static int bbi_expect_compact_fallback(struct bbi_env *e,
                                       const struct block *real)
{
    int failures = 0;
    struct uint256 hash;
    block_get_hash(real, &hash);
    BBI_CHECK(atomic_load(&e->submit.calls) == 0);
    BBI_CHECK(!block_already_seen(&hash));
    BBI_CHECK(bbi_score(e->sender) == 0);
    BBI_CHECK(bbi_sent_getdata(e->sender, &hash));
    BBI_CHECK(dl_is_in_flight(get_download_mgr(), &hash));

    BBI_CHECK(bbi_deliver_block(e, e->sender, real));
    BBI_CHECK(atomic_load(&e->submit.accepted) == 1);
    BBI_CHECK(bbi_score(e->sender) == 0);
    return failures;
}

/* All transactions prefilled: the reconstruction is complete and wrong. */
static int bbi_test_compact_collision_asks_for_full_block(void)
{
    int failures = 0;
    printf("block body identity: a compact block whose reconstruction does not "
           "match asks for the full block... ");

    struct bbi_env e;
    if (!bbi_env_init(&e, SYNC_AT_TIP)) {
        printf("FAIL (setup)\n");
        bbi_env_free(&e);
        return 1;
    }
    struct block real, bad;
    bbi_real_block(&real, 1, 48);
    bbi_wrong_body(&bad, &real);

    BBI_CHECK(bbi_deliver_compact(&e, e.sender, &bad));
    failures += bbi_expect_compact_fallback(&e, &real);
    if (!failures)
        printf("OK\n");
    block_free(&real);
    block_free(&bad);
    bbi_env_free(&e);
    return failures;
}

/* The blocktxn route, with the repeated-transaction form of a wrong body. */
static int bbi_test_blocktxn_mutation_asks_for_full_block(void)
{
    int failures = 0;
    printf("block body identity: a blocktxn reply that repeats a transaction "
           "asks for the full block... ");

    struct bbi_env e;
    if (!bbi_env_init(&e, SYNC_AT_TIP)) {
        printf("FAIL (setup)\n");
        bbi_env_free(&e);
        return 1;
    }
    struct block real, bad;
    bbi_real_block(&real, 3, 49);
    bbi_mutated_body(&bad, &real);

    BBI_CHECK(bbi_deliver_compact(&e, e.sender, &bad));
    BBI_CHECK(e.sender->compact_pending_block != NULL);
    bbi_drop_sends(e.sender);
    BBI_CHECK(bbi_deliver_blocktxn(&e, e.sender, &bad));
    failures += bbi_expect_compact_fallback(&e, &real);
    if (!failures)
        printf("OK\n");
    block_free(&real);
    block_free(&bad);
    bbi_env_free(&e);
    return failures;
}

/* Nothing is asked for when the real body is already here. */
static int bbi_test_compact_wrong_body_have_data_no_request(void)
{
    int failures = 0;
    printf("block body identity: no full-block request for a block already "
           "held... ");

    struct bbi_env e;
    if (!bbi_env_init(&e, SYNC_AT_TIP)) {
        printf("FAIL (setup)\n");
        bbi_env_free(&e);
        return 1;
    }
    struct block real, bad;
    bbi_real_block(&real, 1, 50);
    bbi_wrong_body(&bad, &real);
    struct uint256 hash;
    block_get_hash(&real, &hash);
    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)&e.ms, &hash);
    if (!bi) {
        printf("FAIL (setup index)\n");
        failures = 1;
        goto out;
    }
    bi->nHeight = 1;
    bi->nStatus = BLOCK_HAVE_DATA;

    BBI_CHECK(bbi_deliver_compact(&e, e.sender, &bad));
    BBI_CHECK(atomic_load(&e.submit.calls) == 0);
    BBI_CHECK(!block_already_seen(&hash));
    BBI_CHECK(bbi_score(e.sender) == 0);
    BBI_CHECK(!bbi_sent_getdata(e.sender, &hash));
    BBI_CHECK(!dl_is_in_flight(get_download_mgr(), &hash));
    if (!failures)
        printf("OK\n");
out:
    block_free(&real);
    block_free(&bad);
    bbi_env_free(&e);
    return failures;
}

/* A compact block that matches is submitted; when rejected it is marked seen. */
static int bbi_test_compact_matching_unchanged(void)
{
    int failures = 0;
    printf("block body identity: a compact block that matches is submitted "
           "and marked seen when rejected... ");

    struct bbi_env e;
    if (!bbi_env_init(&e, SYNC_AT_TIP)) {
        printf("FAIL (setup)\n");
        bbi_env_free(&e);
        return 1;
    }
    struct block real;
    bbi_real_block(&real, 1, 51);
    struct uint256 hash;
    block_get_hash(&real, &hash);
    e.submit.reject_matching = "bad-txns-inputs-missingorspent";

    BBI_CHECK(bbi_deliver_compact(&e, e.sender, &real));
    BBI_CHECK(atomic_load(&e.submit.calls) == 1);
    BBI_CHECK(block_already_seen(&hash));
    BBI_CHECK(bbi_score(e.sender) == 0);
    BBI_CHECK(!bbi_sent_getdata(e.sender, &hash));
    if (!failures)
        printf("OK\n");
    block_free(&real);
    bbi_env_free(&e);
    return failures;
}

int msg_block_body_identity_tests(void)
{
    int failures = 0;
    failures += bbi_run_tip_full_block(false, "a wrong body does not stop the "
                                              "real block");
    failures += bbi_run_tip_full_block(true, "a repeated transaction does not "
                                             "stop the real block");
    failures += bbi_test_wrong_body_keeps_other_request();
    failures += bbi_test_matching_reject_marks_seen();
    failures += bbi_run_worker_reject(true, "a wrong body is not marked seen");
    failures += bbi_run_worker_reject(false, "a matching body is marked seen");
    failures += bbi_run_catchup_full_block(false, "a wrong body stays out of "
                                                  "intake");
    failures += bbi_run_catchup_full_block(true, "a repeated transaction stays "
                                                 "out of intake");
    failures += bbi_test_compact_collision_asks_for_full_block();
    failures += bbi_test_blocktxn_mutation_asks_for_full_block();
    failures += bbi_test_compact_wrong_body_have_data_no_request();
    failures += bbi_test_compact_matching_unchanged();
    return failures;
}
