/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * A block manifest starts the swarm only when that manifest itself passed
 * validation and anchored. The peer's earlier anchored manifest buys nothing
 * for the next one. Each case below is a peer that already sent one anchored
 * manifest and then sends a manifest that must be refused: the swarm stays off
 * (legacy getdata pauses only while mp_block_swarm_is_active() reads true,
 * msg_send_block_download) and the height the peer anchored stays as it was.
 * The same peer's honest manifest then still starts a swarm. A piece whose body
 * does not match its header is refused the same way a malformed piece is. Wires
 * are built by hand because the encoder never produces these. Called from
 * test_block_swarm_loopback. */

#define _GNU_SOURCE
#include "test/test_core.h"

#include "bloom/merkle.h"
#include "chain/chainparams.h"
#include "coins/coins_view.h"
#include "consensus/validation.h"
#include "core/serialize.h"
#include "net/fast_sync.h"
#include "net/msg_internal.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/peer_scoring.h"
#include "net/protocol.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "util/safe_alloc.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "validation/txmempool.h"

#include <stdint.h>
#include <string.h>

bool mp_block_swarm_is_active(void);
void mp_block_swarm_test_seed_stall(uint32_t complete, uint32_t total,
                                    int64_t last_complete_unix);
int64_t mp_block_swarm_test_reaped_unix(void);

/* Admitted header frontier of the fetcher. */
#define MR_BEST_HEADER 6400
/* Short enough to anchor without arming the swarm: one piece below our_h+64. */
#define MR_FIRST_END 32
/* Above the frontier of an empty chain by far more than one piece. */
#define MR_HONEST_PIECES 100

struct mr_rig {
    struct main_state ms;
    struct tx_mempool mempool;
    struct coins_view null_view;
    struct coins_view_cache coins;
    struct net_manager nm;
    struct msg_processor mp;
};

static bool mr_rig_init(struct mr_rig *r)
{
    memset(r, 0, sizeof(*r));
    main_state_init(&r->ms);
    tx_mempool_init(&r->mempool, 0);
    coins_view_cache_init(&r->coins, &r->null_view);
    net_manager_init(&r->nm);
    r->mp.main_state = &r->ms;
    r->mp.mempool = &r->mempool;
    r->mp.coins_tip = &r->coins;
    r->mp.params = chain_params_get();
    r->mp.datadir = ".";
    r->mp.net_mgr = &r->nm;

    struct uint256 h;
    memset(&h, 0, sizeof(h));
    h.data[0] = 0xB0;
    h.data[1] = 0x0D;
    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)&r->ms, &h);
    if (!bi)
        return false;
    bi->nHeight = MR_BEST_HEADER;
    bi->nStatus = BLOCK_VALID_TREE;
    r->ms.pindex_best_header = bi;
    return true;
}

static void mr_rig_free(struct mr_rig *r)
{
    net_manager_free(&r->nm);
    coins_view_cache_free(&r->coins);
    tx_mempool_free(&r->mempool);
    main_state_free(&r->ms);
}

static struct p2p_node *mr_make_peer(struct net_manager *nm, uint8_t last_octet)
{
    struct net_address addr;
    memset(&addr, 0, sizeof(addr));
    memcpy(addr.svc.addr.ip, pchIPv4Prefix, 12);
    addr.svc.addr.ip[12] = 10;
    addr.svc.addr.ip[13] = 21;
    addr.svc.addr.ip[14] = 31;
    addr.svc.addr.ip[15] = last_octet;
    addr.svc.port = 18033;
    struct p2p_node *n = p2p_node_create(nm, ZCL_INVALID_SOCKET, &addr,
                                         "manifest-peer", false);
    if (!n)
        return NULL;
    n->version = 1;
    n->services = NODE_ZCL23;
    n->state = PEER_HANDSHAKE_COMPLETE;
    return n;
}

/* What the wire carries after the fixed header. */
enum mr_tail {
    MR_NO_HASHES,    /* the header alone */
    MR_ROOT_MATCHES, /* num_pieces hashes under their true merkle root */
    MR_ROOT_WRONG,   /* num_pieces hashes under a different root */
};

struct mr_manifest {
    const char *kind;
    int32_t start_h;
    int32_t end_h;
    uint32_t num_pieces;
    enum mr_tail tail;
};

/* Fill s with the zblkmanfst payload for m. first_piece_hash, when given, replaces
 * the filler hash of piece 0. */
static bool mr_encode(const struct mr_manifest *m,
                      const uint8_t *first_piece_hash, struct byte_stream *s)
{
    uint8_t (*hashes)[32] = NULL;
    uint8_t root[32];
    memset(root, 0x5A, sizeof(root));
    if (m->tail != MR_NO_HASHES) {
        hashes = zcl_calloc(m->num_pieces, 32, "mr_piece_hashes");
        if (!hashes)
            return false;
        for (uint32_t i = 0; i < m->num_pieces; i++)
            memset(hashes[i], (int)(i % 251) + 1, 32);
        if (first_piece_hash)
            memcpy(hashes[0], first_piece_hash, 32);
        fast_sync_merkle_root((const uint8_t (*)[32])hashes, m->num_pieces,
                              root);
        if (m->tail == MR_ROOT_WRONG)
            root[0] ^= 0xFF;
    }
    uint8_t tip[32];
    memset(tip, 0x7C, sizeof(tip));
    bool ok = stream_write_i32_le(s, m->start_h) &&
              stream_write_i32_le(s, m->end_h) &&
              stream_write_u32_le(s, m->num_pieces) &&
              stream_write_bytes(s, tip, 32) &&
              stream_write_bytes(s, root, 32);
    if (ok && hashes)
        ok = stream_write_bytes(s, (const unsigned char *)hashes,
                                (size_t)m->num_pieces * 32);
    free(hashes);
    return ok;
}

/* Frame a payload on a sender and feed the bytes through the real parser and
 * the real dispatcher, the way bs_pump does for the loopback tests. */
static bool mr_deliver_wire(struct mr_rig *r, struct p2p_node *to,
                            const char *command, const struct byte_stream *body)
{
    const struct chain_params *params = chain_params_get();
    struct p2p_node *from = mr_make_peer(&r->nm, 200);
    bool ok = from != NULL;
    if (ok) {
        p2p_node_begin_message(from, command, params->pchMessageStart);
        p2p_node_write_message_data(from, body->data, body->size);
        p2p_node_end_message(from);
        for (struct send_segment *seg = from->send_head; ok && seg;
             seg = seg->next)
            ok = p2p_node_receive_bytes(to, (const char *)seg->data,
                                        (unsigned int)seg->size,
                                        params->pchMessageStart);
    }
    if (ok)
        ok = msg_process_messages(&r->mp, to);
    if (from)
        p2p_node_free(from);
    return ok;
}

static bool mr_deliver_manifest(struct mr_rig *r, struct p2p_node *to,
                                const struct mr_manifest *m,
                                const uint8_t *first_piece_hash)
{
    struct byte_stream body;
    stream_init(&body, 256);
    bool ok = mr_encode(m, first_piece_hash, &body) &&
              mr_deliver_wire(r, to, MSG_BLOCK_MANIFEST, &body);
    stream_free(&body);
    return ok;
}

static bool mr_deliver(struct mr_rig *r, struct p2p_node *to,
                       const struct mr_manifest *m)
{
    return mr_deliver_manifest(r, to, m, NULL);
}

static const struct mr_manifest k_first = {
    "anchored first manifest", 1, MR_FIRST_END, 1, MR_ROOT_MATCHES,
};

static const struct mr_manifest k_refused[] = {
    { "negative start height", -1, 6400, 101, MR_NO_HASHES },
    { "end height below start", 7000, 6400, 100, MR_NO_HASHES },
    { "no pieces", 1, 6400, 0, MR_NO_HASHES },
    { "more pieces than the cap", 1, 6400, 100001, MR_NO_HASHES },
    { "piece count off by one", 1, 6400, 99, MR_NO_HASHES },
    { "piece hashes absent", 1, 6400, 100, MR_NO_HASHES },
    { "merkle root wrong", 1, 6400, 100, MR_ROOT_WRONG },
    { "widest height range", 0, INT32_MAX, 100000, MR_NO_HASHES },
    /* Passes validation; only the anchor gate can refuse it. */
    { "self-consistent, past the frontier", MR_BEST_HEADER + 1,
      MR_BEST_HEADER + 6400, 100, MR_ROOT_MATCHES },
};

/* Run one refused kind on a fresh peer. Returns whether it stayed refused. */
static bool mr_case_stays_refused(struct mr_rig *r, const struct mr_manifest *m,
                                  uint8_t octet)
{
    bool refused = false;
    struct p2p_node *peer = mr_make_peer(&r->nm, octet);
    if (peer && mr_deliver(r, peer, &k_first) && peer->blk_manifest_received &&
        peer->blk_peer_height == MR_FIRST_END && !mp_block_swarm_is_active()) {
        (void)mr_deliver(r, peer, m);
        refused = !mp_block_swarm_is_active() &&
                  mp_block_swarm_test_reaped_unix() == 0 &&
                  peer->blk_peer_height == MR_FIRST_END;
    }
    if (!refused)
        printf("\n  kind not refused: %s", m->kind);
    mp_block_swarm_test_seed_stall(0, 0, 0);
    if (peer)
        p2p_node_free(peer);
    return refused;
}

static int test_refused_manifest_never_arms(void)
{
    int failures = 0;

    TEST("block swarm manifest: a refused manifest after an anchored one "
         "leaves no swarm; the honest one still starts it") {
        struct mr_rig rig;
        ASSERT(mr_rig_init(&rig));
        mp_block_swarm_test_seed_stall(0, 0, 0);

        size_t not_refused = 0;
        const size_t kinds = sizeof(k_refused) / sizeof(k_refused[0]);
        for (size_t i = 0; i < kinds; i++) {
            if (!mr_case_stays_refused(&rig, &k_refused[i], (uint8_t)(10 + i)))
                not_refused++;
        }
        ASSERT(not_refused == 0);

        /* Control: the same posture with an honest manifest arms the swarm,
         * so the cases above were not refused for some unrelated reason. */
        const struct mr_manifest honest = {
            "honest", 1, MR_HONEST_PIECES * BLOCKS_PER_PIECE, MR_HONEST_PIECES,
            MR_ROOT_MATCHES,
        };
        struct p2p_node *peer = mr_make_peer(&rig.nm, 100);
        ASSERT(peer);
        ASSERT(mr_deliver(&rig, peer, &k_first));
        ASSERT(!mp_block_swarm_is_active());
        ASSERT(mr_deliver(&rig, peer, &honest));
        ASSERT(mp_block_swarm_is_active());
        ASSERT(peer->blk_peer_height == honest.end_h);

        mp_block_swarm_test_seed_stall(0, 0, 0);
        ASSERT(!mp_block_swarm_is_active());
        p2p_node_free(peer);
        mr_rig_free(&rig);
        PASS();
    } _test_next:;

    return failures;
}

static bool mr_count_submit(struct block *blk, struct validation_state *out,
                            void *ctx)
{
    (void)blk;
    (*(int *)ctx)++;
    if (out)
        validation_state_init(out);
    return true;
}

static void mr_make_tx(struct transaction *tx, uint32_t lock_time)
{
    transaction_init(tx);
    transaction_alloc(tx, 1, 1);
    tx->lock_time = lock_time;
    transaction_compute_hash(tx);
}

/* A header over `n` txs numbered from `first_lock`, committing to `root`, or to
 * those txs when root is NULL. */
static void mr_make_block(struct block *blk, size_t n, uint32_t first_lock,
                          const struct uint256 *root)
{
    block_init(blk);
    blk->header.nVersion = 4;
    blk->header.nTime = 1500000000u;
    blk->num_vtx = n;
    blk->vtx = zcl_calloc(n, sizeof(struct transaction), "mr_vtx");
    struct uint256 txids[4];
    for (size_t i = 0; i < n; i++) {
        mr_make_tx(&blk->vtx[i], first_lock + (uint32_t)i);
        txids[i] = blk->vtx[i].hash;
    }
    blk->header.hashMerkleRoot = root ? *root : compute_merkle_root(txids, n);
}

/* Deliver blk as the only block of piece 0, its hash taken from `hash`. */
static bool mr_deliver_piece(struct mr_rig *r, struct p2p_node *to,
                             const struct uint256 *hash, const struct block *blk)
{
    struct byte_stream one, body;
    stream_init(&one, 512);
    stream_init(&body, 512);
    bool ok = block_serialize(blk, &one) &&
              stream_write_u32_le(&body, 0) &&
              stream_write_u32_le(&body, 1) &&
              stream_write_bytes(&body, hash->data, 32) &&
              stream_write_compact_size(&body, one.size) &&
              stream_write_bytes(&body, one.data, one.size) &&
              mr_deliver_wire(r, to, MSG_BLOCK_DATA, &body);
    stream_free(&one);
    stream_free(&body);
    return ok;
}

/* The manifest binds only block hashes, so a piece can carry the right hash with
 * the wrong body, or with a transaction repeated under the right root. Neither
 * reaches submit and the sender is scored; the real body then goes through. */
static int test_wrong_body_piece_refused(void)
{
    int failures = 0;

    TEST("block swarm piece: a body that does not match its header is refused "
         "and scored, and the real body is still accepted") {
        struct mr_rig rig;
        ASSERT(mr_rig_init(&rig));
        mp_block_swarm_test_seed_stall(0, 0, 0);
        int submits = 0;
        msg_processor_set_block_submit(&rig.mp, mr_count_submit, &submits);

        struct block real, wrong, repeated;
        mr_make_block(&real, 3, 100, NULL);
        mr_make_block(&wrong, 3, 900, &real.header.hashMerkleRoot);
        mr_make_block(&repeated, 4, 100, &real.header.hashMerkleRoot);
        transaction_free(&repeated.vtx[3]);
        mr_make_tx(&repeated.vtx[3], 102);
        struct uint256 hash;
        block_get_hash(&real, &hash);

        uint8_t piece_hash[32];
        block_piece_hash((const uint8_t (*)[32])hash.data, 1, 0, piece_hash);
        const struct mr_manifest honest = {
            "honest", 1, MR_HONEST_PIECES * BLOCKS_PER_PIECE, MR_HONEST_PIECES,
            MR_ROOT_MATCHES,
        };
        struct p2p_node *peer = mr_make_peer(&rig.nm, 101);
        ASSERT(peer);
        ASSERT(mr_deliver(&rig, peer, &k_first));
        ASSERT(mr_deliver_manifest(&rig, peer, &honest, piece_hash));
        ASSERT(mp_block_swarm_is_active());

        const int weight = peer_offence_weight(PEER_OFFENCE_INVALID_PAYLOAD);
        ASSERT(mr_deliver_piece(&rig, peer, &hash, &wrong));
        ASSERT(submits == 0);
        ASSERT(atomic_load(&peer->misbehavior) == weight);
        ASSERT(mr_deliver_piece(&rig, peer, &hash, &repeated));
        ASSERT(submits == 0);
        ASSERT(atomic_load(&peer->misbehavior) == 2 * weight);
        ASSERT(mr_deliver_piece(&rig, peer, &hash, &real));
        ASSERT(submits == 1);
        ASSERT(atomic_load(&peer->misbehavior) == 2 * weight);

        mp_block_swarm_test_seed_stall(0, 0, 0);
        ASSERT(!mp_block_swarm_is_active());
        block_free(&real);
        block_free(&wrong);
        block_free(&repeated);
        p2p_node_free(peer);
        mr_rig_free(&rig);
        PASS();
    } _test_next:;

    return failures;
}

static int test_swarm_init_piece_cap(void)
{
    int failures = 0;

    TEST("block_swarm_init refuses a piece count past its own cap") {
        struct block_piece_manifest pm;
        memset(&pm, 0, sizeof(pm));
        pm.start_height = 1;

        struct block_swarm over;
        memset(&over, 0, sizeof(over));
        pm.num_pieces = 100001;
        pm.end_height = (int32_t)pm.num_pieces * BLOCKS_PER_PIECE;
        bool over_ok = block_swarm_init(&over, &pm, NULL);
        if (over_ok)
            block_swarm_free(&over);
        ASSERT(!over_ok);

        struct block_swarm at_cap;
        memset(&at_cap, 0, sizeof(at_cap));
        pm.num_pieces = 100000;
        pm.end_height = (int32_t)pm.num_pieces * BLOCKS_PER_PIECE;
        ASSERT(block_swarm_init(&at_cap, &pm, NULL));
        block_swarm_free(&at_cap);
        PASS();
    } _test_next:;

    return failures;
}

int block_swarm_manifest_refusal_tests(void)
{
    int failures = 0;
    failures += test_refused_manifest_never_arms();
    failures += test_swarm_init_piece_cap();
    failures += test_wrong_body_piece_refused();
    return failures;
}
