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
#include "sync/sync_planner.h"
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
#define BBI_DRAIN_POLLS 300000      /* at least five minutes of 1 ms sleeps */
#define BBI_FABRICATED_HEADERS 300
#define BBI_TIP_HEIGHT 100
#define BBI_OTHER_PEER_ID 9901u     /* no bbi_peer has this id */

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

/* Wait on the worker's post-verdict drain. False only when no verdict came at
 * all, so a lost item fails the test instead of hanging it. */
static bool bbi_wait_for_drain(struct bbi_submit *c)
{
    for (long i = 0; i < BBI_DRAIN_POLLS; i++) {
        if (atomic_load(&c->drains) != 0)
            return true;
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000L };
        nanosleep(&ts, NULL); /* real-clock: hang guard of at least five minutes, not a timing assertion */
    }
    return false;
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

/* The header of `real` is on the index, with its body not yet held. */
static struct block_index *bbi_known_header(struct bbi_env *e,
                                            const struct block *real,
                                            uint32_t status)
{
    struct uint256 hash;
    block_get_hash(real, &hash);
    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)&e->ms, &hash);
    if (bi) {
        bi->nHeight = 1;
        bi->nStatus = status;
    }
    return bi;
}

/* A chain tip to build a header locator from. */
static bool bbi_genesis_tip(struct bbi_env *e)
{
    struct uint256 gh = chain_params_get()->consensus.hashGenesisBlock;
    struct block_index *gen =
        chainstate_insert_block_index((struct chainstate *)&e->ms, &gh);
    if (!gen)
        return false;
    gen->nHeight = 0;
    gen->nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
    active_chain_move_window_tip(&e->ms.chain_active, gen);
    e->ms.pindex_best_header = gen;
    return true;
}

/* An active chain whose tip is at `height`. */
static bool bbi_tip_at(struct bbi_env *e, int height)
{
    struct uint256 h;
    memset(&h, 0xdd, sizeof(h));
    struct block_index *tip =
        chainstate_insert_block_index((struct chainstate *)&e->ms, &h);
    if (!tip)
        return false;
    tip->nHeight = height;
    tip->nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
    active_chain_move_window_tip(&e->ms.chain_active, tip);
    e->ms.pindex_best_header = tip;
    return active_chain_height(&e->ms.chain_active) == height;
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

/* Messages named `name` in node's send queue. */
static size_t bbi_count_sent(const struct p2p_node *node, const char *name)
{
    size_t count = 0;
    for (const struct send_segment *seg = node->send_head; seg;
         seg = seg->next) {
        if (seg->size >= MSG_HEADER_SIZE &&
            strcmp((const char *)seg->data + MESSAGE_START_SIZE, name) == 0)
            count++;
    }
    return count;
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

/* At the tip: the wrong body is refused before submit and its sender scored, the
 * block index is untouched, the hash stays out of the dedup ring, a fresh request
 * can be made at once, and the real block is then accepted from another peer. */
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
    BBI_CHECK(atomic_load(&e.submit.calls) == 0);
    BBI_CHECK(!block_already_seen(&hash));
    BBI_CHECK(bbi_score(e.sender) ==
              peer_offence_weight(PEER_OFFENCE_INVALID_BLOCK));
    BBI_CHECK((bi->nStatus & BLOCK_FAILED_MASK) == 0);

    /* Another peer can be asked straight away. */
    BBI_CHECK(dl_mark_requested(dm, &hash, 1, (uint32_t)e.honest->id));
    BBI_CHECK(bbi_deliver_block(&e, e.honest, &real));
    BBI_CHECK(atomic_load(&e.submit.calls) == 1);
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
 * another peer, and that peer's real block is not treated as unrequested. Its
 * sender is scored for the body only: a request for that hash is live, so the
 * body is not an unrequested push. */
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
    BBI_CHECK(bbi_score(e.sender) ==
              peer_offence_weight(PEER_OFFENCE_INVALID_BLOCK));
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

/* With no request for that hash anywhere, the wrong body is also an unrequested
 * push, as a matching body from that peer would be. */
static int bbi_test_wrong_body_with_no_request_is_unrequested(void)
{
    int failures = 0;
    printf("block body identity: a wrong body nobody asked for is also scored "
           "as unrequested... ");

    struct bbi_env e;
    if (!bbi_env_init(&e, SYNC_AT_TIP)) {
        printf("FAIL (setup)\n");
        bbi_env_free(&e);
        return 1;
    }
    struct block real, bad;
    bbi_real_block(&real, 3, 61);
    bbi_wrong_body(&bad, &real);
    struct uint256 hash;
    block_get_hash(&real, &hash);

    BBI_CHECK(bbi_deliver_block(&e, e.sender, &bad));
    BBI_CHECK(!block_already_seen(&hash));
    BBI_CHECK(bbi_score(e.sender) ==
              peer_offence_weight(PEER_OFFENCE_INVALID_BLOCK) +
              peer_offence_weight(PEER_OFFENCE_UNREQUESTED));
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
    bool queued = msg_processor_enqueue_p2p_block(&e.mp, wrong ? &bad : &real,
                                                  &hash, 11, &state);
    BBI_CHECK(queued);
    if (queued) {
        BBI_CHECK(bbi_wait_for_drain(&e.submit));
        BBI_CHECK(atomic_load(&e.submit.calls) == 1);
        BBI_CHECK(block_already_seen(&hash) == !wrong);
    }
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
        if (!failures) {
            BBI_CHECK(bbi_wait_for_drain(&e.submit));
            BBI_CHECK(atomic_load(&e.submit.accepted) == 1);
        }
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
    if (!bbi_known_header(&e, &real, 0)) {
        printf("FAIL (setup index)\n");
        failures = 1;
        goto out;
    }

    BBI_CHECK(bbi_deliver_compact(&e, e.sender, &bad));
    failures += bbi_expect_compact_fallback(&e, &real);
    if (!failures)
        printf("OK\n");
out:
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
    if (!bbi_known_header(&e, &real, 0)) {
        printf("FAIL (setup index)\n");
        failures = 1;
        goto out;
    }

    BBI_CHECK(bbi_deliver_compact(&e, e.sender, &bad));
    BBI_CHECK(e.sender->compact_pending_block != NULL);
    bbi_drop_sends(e.sender);
    BBI_CHECK(bbi_deliver_blocktxn(&e, e.sender, &bad));
    failures += bbi_expect_compact_fallback(&e, &real);
    if (!failures)
        printf("OK\n");
out:
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
    if (!bbi_known_header(&e, &real, BLOCK_HAVE_DATA)) {
        printf("FAIL (setup index)\n");
        failures = 1;
        goto out;
    }

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

/* A block whose non-coinbase transactions spend distinct outputs, so they can
 * all sit in the mempool at once; the header commits to them. */
static void bbi_mempool_block(struct block *blk, size_t n, uint8_t tag)
{
    bbi_real_block(blk, n, tag);
    struct uint256 txids[8];
    for (size_t i = 1; i < n; i++) {
        memset(blk->vtx[i].vin[0].prevout.hash.data, (int)(0x60 + i), 32);
        blk->vtx[i].vin[0].prevout.n = 0;
        transaction_compute_hash(&blk->vtx[i]);
    }
    for (size_t i = 0; i < n && i < 8; i++)
        txids[i] = blk->vtx[i].hash;
    blk->header.hashMerkleRoot = compute_merkle_root(txids, n);
}

/* Put a copy of tx in the mempool. */
static bool bbi_pool_add(struct bbi_env *e, const struct transaction *tx)
{
    struct mempool_entry entry;
    mempool_entry_init(&entry, tx, 1000, 1700000000, 1e6, 100, true, false, 0);
    bool added = tx_mempool_add_unchecked(&e->pool, &tx->hash, &entry);
    mempool_entry_free(&entry);
    return added;
}

/* Every transaction is in the mempool among unrelated ones: the block is
 * rebuilt from it and submitted, and no getblocktxn goes out. */
static int bbi_test_compact_rebuilds_from_mempool(void)
{
    int failures = 0;
    printf("block body identity: a compact block is rebuilt from the mempool "
           "and submitted... ");

    struct bbi_env e;
    if (!bbi_env_init(&e, SYNC_AT_TIP)) {
        printf("FAIL (setup)\n");
        bbi_env_free(&e);
        return 1;
    }
    struct block real;
    bbi_mempool_block(&real, 3, 81);
    struct uint256 hash;
    block_get_hash(&real, &hash);
    for (uint32_t i = 0; i < 20; i++) {
        struct transaction noise;
        bbi_make_tx(&noise, 5000 + i);
        memset(noise.vin[0].prevout.hash.data, (int)(0x90 + i), 32);
        transaction_compute_hash(&noise);
        BBI_CHECK(bbi_pool_add(&e, &noise));
        transaction_free(&noise);
    }
    BBI_CHECK(bbi_pool_add(&e, &real.vtx[1]));
    BBI_CHECK(bbi_pool_add(&e, &real.vtx[2]));

    BBI_CHECK(bbi_deliver_compact(&e, e.sender, &real));
    BBI_CHECK(atomic_load(&e.submit.calls) == 1);
    BBI_CHECK(atomic_load(&e.submit.accepted) == 1);
    BBI_CHECK(e.sender->compact_pending_block == NULL);
    BBI_CHECK(bbi_count_sent(e.sender, "getblocktxn") == 0);
    BBI_CHECK(bbi_score(e.sender) == 0);
    if (!failures)
        printf("OK\n");
    block_free(&real);
    bbi_env_free(&e);
    return failures;
}

/* Fabricated headers cost little to make, so one peer sending many of them
 * holds no download slots, queues no work, leaves intake room as it was, and
 * gets one rate-limited header request rather than one for each. */
static int bbi_test_unknown_headers_hold_nothing(void)
{
    int failures = 0;
    printf("block body identity: fabricated headers hold no slots and no intake "
           "room... ");

    struct bbi_env e;
    if (!bbi_env_init(&e, SYNC_BLOCKS_DOWNLOAD) || !bbi_genesis_tip(&e)) {
        printf("FAIL (setup)\n");
        bbi_env_free(&e);
        return 1;
    }
    struct msg_block_intake_stats before, after;
    msg_processor_get_block_intake_stats(&e.mp, &before);

    for (unsigned i = 0; i < BBI_FABRICATED_HEADERS; i++) {
        struct block real, bad;
        bbi_real_block(&real, 1, 52);
        real.header.nNonce.data[1] = (uint8_t)(i & 0xff);
        real.header.nNonce.data[2] = (uint8_t)(i >> 8);
        bbi_wrong_body(&bad, &real);
        BBI_CHECK(bbi_deliver_compact(&e, e.sender, &bad));
        if (i == 0) {
            BBI_CHECK(bbi_count_sent(e.sender, "getheaders") == 1);
            BBI_CHECK(atomic_load(&e.sender->last_reject_probe_time) != 0);
            BBI_CHECK(!atomic_load(&e.sender->reject_probe_pending));
            /* The limit is on a wall clock: hold it shut so a slow host cannot
             * open it during the loop. */
            atomic_store(&e.sender->last_reject_probe_time, INT64_MAX / 2);
        }
        block_free(&real);
        block_free(&bad);
    }

    uint64_t in_flight = 1, queued = 1;
    dl_get_stats(get_download_mgr(), NULL, NULL, NULL, &in_flight, &queued);
    msg_processor_get_block_intake_stats(&e.mp, &after);
    BBI_CHECK(in_flight == 0);
    BBI_CHECK(queued == 0);
    BBI_CHECK(dl_peer_in_flight(get_download_mgr(),
                                (uint32_t)e.sender->id) == 0);
    BBI_CHECK(after.enqueued == before.enqueued);
    BBI_CHECK(after.current_depth == before.current_depth);
    BBI_CHECK(bbi_count_sent(e.sender, "getheaders") == 1);
    BBI_CHECK(bbi_count_sent(e.sender, "getdata") == 0);
    BBI_CHECK(atomic_load(&e.submit.calls) == 0);
    BBI_CHECK(bbi_score(e.sender) == 0);
    /* The closed limit left the probe armed for the send tick to retry. */
    BBI_CHECK(atomic_load(&e.sender->reject_probe_pending));
    if (!failures)
        printf("OK\n");
    bbi_env_free(&e);
    return failures;
}

/* A hash for filling the request table, distinct from any real block's. */
static struct uint256 bbi_filler_hash(size_t i)
{
    struct uint256 h;
    memset(&h, 0xee, sizeof(h));
    memcpy(h.data, &i, sizeof(i));
    return h;
}

/* Hold `count` request slots for `peer_id`. */
static bool bbi_fill_slots(uint32_t peer_id, size_t count)
{
    struct download_manager *dm = get_download_mgr();
    for (size_t i = 0; i < count; i++) {
        struct uint256 h = bbi_filler_hash(i);
        if (!dl_mark_requested(dm, &h, (int32_t)(i + 2), peer_id))
            return false;
    }
    return true;
}

/* Checks shared by the two ways this peer cannot take the request: the hash is
 * left queued for any peer, nothing is asked of this one, and the peer gains no
 * slot. */
static int bbi_expect_compact_queued(struct bbi_env *e, const struct block *real,
                                     size_t sender_slots)
{
    int failures = 0;
    struct uint256 hash;
    block_get_hash(real, &hash);
    struct download_manager *dm = get_download_mgr();
    uint64_t in_flight = 0, queued = 0;
    dl_get_stats(dm, NULL, NULL, NULL, &in_flight, &queued);
    BBI_CHECK(queued == 1);
    BBI_CHECK(!dl_is_in_flight(dm, &hash));
    BBI_CHECK(dl_peer_in_flight(dm, (uint32_t)e->sender->id) == sender_slots);
    BBI_CHECK(!bbi_sent_getdata(e->sender, &hash));
    BBI_CHECK(atomic_load(&e->submit.calls) == 0);
    BBI_CHECK(!block_already_seen(&hash));
    BBI_CHECK(bbi_score(e->sender) == 0);
    return failures;
}

/* A peer at its window does not claim the request: `full_table` false.
 * A full request table refuses a peer under its window: `full_table` true. */
static int bbi_run_compact_cannot_take_slot(bool full_table, const char *name)
{
    int failures = 0;
    printf("block body identity: a compact block that does not match, %s... ",
           name);

    struct bbi_env e;
    if (!bbi_env_init(&e, SYNC_AT_TIP)) {
        printf("FAIL (setup)\n");
        bbi_env_free(&e);
        return 1;
    }
    struct block real, bad;
    bbi_real_block(&real, 1, full_table ? 54 : 53);
    bbi_wrong_body(&bad, &real);

    struct download_manager *dm = get_download_mgr();
    uint32_t sender_id = (uint32_t)e.sender->id;
    size_t window = dl_peer_adaptive_window(dm, sender_id);
    uint32_t holder = full_table ? BBI_OTHER_PEER_ID : sender_id;
    size_t count = full_table ? dl_get_max_in_flight_total() : window;
    if (!bbi_known_header(&e, &real, 0) || !bbi_fill_slots(holder, count) ||
        dl_peer_in_flight(dm, holder) != count) {
        printf("FAIL (setup slots)\n");
        failures = 1;
        goto out;
    }

    BBI_CHECK(bbi_deliver_compact(&e, e.sender, &bad));
    failures += bbi_expect_compact_queued(&e, &real, full_table ? 0 : window);
    if (!failures)
        printf("OK\n");
out:
    block_free(&real);
    block_free(&bad);
    bbi_env_free(&e);
    return failures;
}

/* A request already made of another peer stands. */
static int bbi_test_compact_keeps_request_in_flight(void)
{
    int failures = 0;
    printf("block body identity: a compact block that does not match leaves a "
           "request in flight alone... ");

    struct bbi_env e;
    if (!bbi_env_init(&e, SYNC_AT_TIP)) {
        printf("FAIL (setup)\n");
        bbi_env_free(&e);
        return 1;
    }
    struct block real, bad;
    bbi_real_block(&real, 1, 55);
    bbi_wrong_body(&bad, &real);
    struct uint256 hash;
    block_get_hash(&real, &hash);

    struct download_manager *dm = get_download_mgr();
    if (!bbi_known_header(&e, &real, 0) ||
        !dl_mark_requested(dm, &hash, 1, (uint32_t)e.honest->id)) {
        printf("FAIL (setup request)\n");
        failures = 1;
        goto out;
    }
    BBI_CHECK(bbi_deliver_compact(&e, e.sender, &bad));
    BBI_CHECK(!bbi_sent_getdata(e.sender, &hash));
    BBI_CHECK(dl_peer_in_flight(dm, (uint32_t)e.sender->id) == 0);
    BBI_CHECK(dl_peer_in_flight(dm, (uint32_t)e.honest->id) == 1);
    BBI_CHECK(bbi_deliver_block(&e, e.honest, &real));
    BBI_CHECK(atomic_load(&e.submit.accepted) == 1);
    BBI_CHECK(bbi_score(e.honest) == 0);
    if (!failures)
        printf("OK\n");
out:
    block_free(&real);
    block_free(&bad);
    bbi_env_free(&e);
    return failures;
}

/* Nothing is asked for a block already known to be invalid. */
static int bbi_test_compact_failed_header_no_request(void)
{
    int failures = 0;
    printf("block body identity: no full-block request for a block known to be "
           "invalid... ");

    struct bbi_env e;
    if (!bbi_env_init(&e, SYNC_AT_TIP)) {
        printf("FAIL (setup)\n");
        bbi_env_free(&e);
        return 1;
    }
    struct block real, bad;
    bbi_real_block(&real, 1, 56);
    bbi_wrong_body(&bad, &real);
    struct uint256 hash;
    block_get_hash(&real, &hash);
    if (!bbi_known_header(&e, &real, BLOCK_FAILED_VALID)) {
        printf("FAIL (setup index)\n");
        failures = 1;
        goto out;
    }
    BBI_CHECK(bbi_deliver_compact(&e, e.sender, &bad));
    uint64_t in_flight = 1, queued = 1;
    dl_get_stats(get_download_mgr(), NULL, NULL, NULL, &in_flight, &queued);
    BBI_CHECK(in_flight == 0);
    BBI_CHECK(queued == 0);
    BBI_CHECK(!bbi_sent_getdata(e.sender, &hash));
    BBI_CHECK(atomic_load(&e.submit.calls) == 0);
    if (!failures)
        printf("OK\n");
out:
    block_free(&real);
    block_free(&bad);
    bbi_env_free(&e);
    return failures;
}

/* A blocktxn reply that rebuilds the real block is submitted and nothing more
 * is asked for. */
static int bbi_test_blocktxn_matching_is_accepted(void)
{
    int failures = 0;
    printf("block body identity: a blocktxn reply that rebuilds the real block "
           "is accepted... ");

    struct bbi_env e;
    if (!bbi_env_init(&e, SYNC_AT_TIP)) {
        printf("FAIL (setup)\n");
        bbi_env_free(&e);
        return 1;
    }
    struct block real;
    bbi_real_block(&real, 3, 57);
    struct uint256 hash;
    block_get_hash(&real, &hash);
    if (!bbi_known_header(&e, &real, 0)) {
        printf("FAIL (setup index)\n");
        failures = 1;
        goto out;
    }
    BBI_CHECK(bbi_deliver_compact(&e, e.sender, &real));
    BBI_CHECK(e.sender->compact_pending_block != NULL);
    bbi_drop_sends(e.sender);
    BBI_CHECK(bbi_deliver_blocktxn(&e, e.sender, &real));
    BBI_CHECK(e.sender->compact_pending_block == NULL);
    BBI_CHECK(atomic_load(&e.submit.calls) == 1);
    BBI_CHECK(atomic_load(&e.submit.accepted) == 1);
    BBI_CHECK(bbi_count_sent(e.sender, "getdata") == 0);
    BBI_CHECK(bbi_score(e.sender) == 0);
    if (!failures)
        printf("OK\n");
out:
    block_free(&real);
    bbi_env_free(&e);
    return failures;
}

/* Once the hash is seen, a wrong reconstruction asks for nothing: that hash has
 * already had its verdict, and the wrong body changes nothing about it. */
static int bbi_test_blocktxn_wrong_body_after_seen_no_request(void)
{
    int failures = 0;
    printf("block body identity: no full-block request for a hash already "
           "seen... ");

    struct bbi_env e;
    if (!bbi_env_init(&e, SYNC_AT_TIP)) {
        printf("FAIL (setup)\n");
        bbi_env_free(&e);
        return 1;
    }
    struct block real, bad;
    bbi_real_block(&real, 3, 58);
    bbi_mutated_body(&bad, &real);
    struct uint256 hash;
    block_get_hash(&real, &hash);
    if (!bbi_known_header(&e, &real, 0)) {
        printf("FAIL (setup index)\n");
        failures = 1;
        goto out;
    }
    BBI_CHECK(bbi_deliver_compact(&e, e.sender, &bad));
    BBI_CHECK(e.sender->compact_pending_block != NULL);
    bbi_drop_sends(e.sender);
    block_mark_seen(&hash);
    BBI_CHECK(bbi_deliver_blocktxn(&e, e.sender, &bad));
    BBI_CHECK(!bbi_sent_getdata(e.sender, &hash));
    BBI_CHECK(!dl_is_in_flight(get_download_mgr(), &hash));
    BBI_CHECK(atomic_load(&e.submit.calls) == 0);
    if (!failures)
        printf("OK\n");
out:
    block_free(&real);
    block_free(&bad);
    bbi_env_free(&e);
    return failures;
}

/* A wrong body delivered again, and from another peer, still leaves the hash
 * unmarked and the index clean, and the real block still goes through. */
static int bbi_run_repeat_wrong_body(enum sync_state sync, const char *name)
{
    int failures = 0;
    printf("block body identity: a wrong body delivered repeatedly, %s... ",
           name);

    struct bbi_env e;
    if (!bbi_env_init(&e, sync)) {
        printf("FAIL (setup)\n");
        bbi_env_free(&e);
        return 1;
    }
    struct block real, bad;
    bbi_real_block(&real, 3, sync == SYNC_AT_TIP ? 59 : 60);
    bbi_wrong_body(&bad, &real);
    struct uint256 hash;
    block_get_hash(&real, &hash);
    struct block_index *bi = bbi_known_header(&e, &real, 0);
    struct p2p_node *third = bbi_peer(&e.nm, 13);
    if (!bi || !third) {
        printf("FAIL (setup)\n");
        failures = 1;
        goto out;
    }

    struct download_manager *dm = get_download_mgr();
    BBI_CHECK(dl_mark_requested(dm, &hash, 1, (uint32_t)e.sender->id));
    for (int i = 0; i < 2; i++)
        BBI_CHECK(bbi_deliver_block(&e, e.sender, &bad));
    BBI_CHECK(bbi_deliver_block(&e, third, &bad));
    BBI_CHECK(!block_already_seen(&hash));
    BBI_CHECK((bi->nStatus & BLOCK_FAILED_MASK) == 0);
    BBI_CHECK(atomic_load(&e.submit.calls) == 0);
    BBI_CHECK(bbi_score(e.sender) >=
              peer_offence_weight(PEER_OFFENCE_INVALID_BLOCK));
    BBI_CHECK(bbi_score(third) >=
              peer_offence_weight(PEER_OFFENCE_INVALID_BLOCK));

    BBI_CHECK(dl_mark_requested(dm, &hash, 1, (uint32_t)e.honest->id));
    BBI_CHECK(bbi_deliver_block(&e, e.honest, &real));
    BBI_CHECK(bbi_score(e.honest) == 0);
    if (sync != SYNC_AT_TIP)
        BBI_CHECK(bbi_wait_for_drain(&e.submit));
    BBI_CHECK(atomic_load(&e.submit.accepted) == 1);
    if (!failures)
        printf("OK\n");
out:
    if (third)
        p2p_node_free(third);
    block_free(&real);
    block_free(&bad);
    bbi_env_free(&e);
    return failures;
}

/* A mismatched compact block for a header at or below our tip asks for nothing:
 * a request would count as forward work and go ahead of what the frontier needs.
 * Just above the tip, where a collision on a new block lands, the fallback stands. */
static int bbi_run_compact_relative_to_tip(int offset, const char *name)
{
    int failures = 0;
    printf("block body identity: a compact block that does not match, %s... ",
           name);

    struct bbi_env e;
    if (!bbi_env_init(&e, SYNC_BLOCKS_DOWNLOAD) ||
        !bbi_tip_at(&e, BBI_TIP_HEIGHT)) {
        printf("FAIL (setup)\n");
        bbi_env_free(&e);
        return 1;
    }
    struct block real, bad;
    bbi_real_block(&real, 1, (uint8_t)(70 + offset));
    bbi_wrong_body(&bad, &real);
    struct uint256 hash;
    block_get_hash(&real, &hash);
    struct block_index *bi = bbi_known_header(&e, &real, 0);
    if (!bi) {
        printf("FAIL (setup index)\n");
        failures = 1;
        goto out;
    }
    bi->nHeight = BBI_TIP_HEIGHT + offset;

    BBI_CHECK(bbi_deliver_compact(&e, e.sender, &bad));
    uint64_t in_flight = 2, queued = 2;
    dl_get_stats(get_download_mgr(), NULL, NULL, NULL, &in_flight, &queued);
    bool above = offset > 0;
    BBI_CHECK(in_flight == (above ? 1u : 0u));
    BBI_CHECK(queued == 0);
    BBI_CHECK(bbi_sent_getdata(e.sender, &hash) == above);
    BBI_CHECK(bbi_count_sent(e.sender, "getheaders") == 0);
    BBI_CHECK(atomic_load(&e.submit.calls) == 0);
    BBI_CHECK(!block_already_seen(&hash));
    BBI_CHECK(bbi_score(e.sender) == 0);
    if (!failures)
        printf("OK\n");
out:
    block_free(&real);
    block_free(&bad);
    bbi_env_free(&e);
    return failures;
}

/* Headers are paused during a snapshot, so the budget is not spent and the probe
 * stays armed for the send tick once the snapshot ends. */
static bool bbi_snapshot_is_active(void *ctx)
{
    (void)ctx;
    return true;
}

static int bbi_test_unknown_header_during_snapshot(void)
{
    int failures = 0;
    printf("block body identity: during a snapshot an unknown header arms the "
           "probe without spending its budget... ");

    struct bbi_env e;
    if (!bbi_env_init(&e, SYNC_BLOCKS_DOWNLOAD) || !bbi_genesis_tip(&e)) {
        printf("FAIL (setup)\n");
        bbi_env_free(&e);
        return 1;
    }
    e.mp.snapshot_active = bbi_snapshot_is_active;
    struct block real, bad;
    bbi_real_block(&real, 1, 62);
    bbi_wrong_body(&bad, &real);

    BBI_CHECK(bbi_deliver_compact(&e, e.sender, &bad));
    BBI_CHECK(bbi_count_sent(e.sender, "getheaders") == 0);
    BBI_CHECK(atomic_load(&e.sender->last_reject_probe_time) == 0);
    BBI_CHECK(atomic_load(&e.sender->reject_probe_pending));
    /* The tick's rule: armed, budget never spent, so it fires. */
    BBI_CHECK(syncsvc_should_fire_reject_probe(e.sender, 42));
    if (!failures)
        printf("OK\n");
    block_free(&real);
    block_free(&bad);
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
    failures += bbi_test_compact_rebuilds_from_mempool();
    failures += bbi_test_wrong_body_with_no_request_is_unrequested();
    failures += bbi_test_unknown_headers_hold_nothing();
    failures += bbi_run_compact_cannot_take_slot(false, "a peer at its window "
                                                        "takes no slot");
    failures += bbi_run_compact_cannot_take_slot(true, "a full request table "
                                                       "leaves it queued");
    failures += bbi_test_compact_keeps_request_in_flight();
    failures += bbi_test_compact_failed_header_no_request();
    failures += bbi_test_blocktxn_matching_is_accepted();
    failures += bbi_test_blocktxn_wrong_body_after_seen_no_request();
    failures += bbi_run_repeat_wrong_body(SYNC_AT_TIP, "at the tip");
    failures += bbi_run_repeat_wrong_body(SYNC_BLOCKS_DOWNLOAD, "in catch-up");
    failures += bbi_run_compact_relative_to_tip(-5, "a header below the tip "
                                                    "asks for nothing");
    failures += bbi_run_compact_relative_to_tip(0, "a header at the tip asks "
                                                   "for nothing");
    failures += bbi_run_compact_relative_to_tip(1, "a header just above the "
                                                   "tip still falls back");
    failures += bbi_test_unknown_header_during_snapshot();
    return failures;
}
