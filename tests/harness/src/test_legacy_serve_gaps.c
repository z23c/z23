/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * What a peer that cannot wait on us is sent when this node cannot serve all of
 * what it asked for.
 *
 * Headers: zclassicd requires each header in a message to name the one before
 * it as parent and scores a message that does not (main.cpp, "non-continuous
 * headers sequence"), so a reply to a peer without NODE_ZCL23 ends at the first
 * entry this node has no header bytes for. The first entry must be the real
 * successor of the locator's fork point, or the reply is empty. A NODE_ZCL23
 * peer keeps its skip: it rejects an unconnected header with no score and
 * probes for what is missing.
 *
 * Real regtest Equihash (48,5) headers, mined with mine_block_pow. An entry is
 * "unservable" when it has no solution in memory and no store holds its bytes,
 * as an entry below a seed floor has.
 */

#include "test/block_index_ext_fixture.h"
#include "test/test_core.h"

#include "chain/chainparams.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "mining/miner.h"
#include "net/header_serve_repair.h"
#include "net/msg_internal.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/p2p_message.h"
#include "primitives/block.h"
#include "util/safe_alloc.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdio.h>
#include <string.h>

#define LSG_CHAIN_LEN 8
#define LSG_TIP (LSG_CHAIN_LEN - 1)

struct lsg_chain {
    struct block_header hdr[LSG_CHAIN_LEN];
    struct uint256 hash[LSG_CHAIN_LEN];
    struct block_index *bi[LSG_CHAIN_LEN];
};

static struct net_manager g_lsg_nm;

static bool lsg_mine_chain(struct lsg_chain *c, const struct chain_params *cp)
{
    struct arith_uint256 pow_limit;
    struct uint256 prev;

    uint256_to_arith(&pow_limit, &cp->consensus.powLimit);
    uint256_set_null(&prev);
    for (int h = 0; h < LSG_CHAIN_LEN; h++) {
        struct block blk;
        block_init(&blk);
        blk.header.nVersion = 4;
        blk.header.hashPrevBlock = prev;
        uint256_set_null(&blk.header.hashMerkleRoot);
        blk.header.hashMerkleRoot.data[0] = (uint8_t)h;
        uint256_set_null(&blk.header.hashFinalSaplingRoot);
        blk.header.nTime = 1600000000u + (uint32_t)h;
        blk.header.nBits = arith_uint256_get_compact(&pow_limit, false);
        bool mined = mine_block_pow(&blk, h, cp, 0);
        if (mined)
            c->hdr[h] = blk.header;
        block_free(&blk);
        if (!mined)
            return false;
        block_header_get_hash(&c->hdr[h], &c->hash[h]);
        prev = c->hash[h];
    }
    return true;
}

static struct block_index *lsg_seed_entry(struct main_state *ms,
                                          const struct lsg_chain *c, int h,
                                          struct block_index *prev)
{
    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)ms, &c->hash[h]);
    if (!bi)
        return NULL;
    bi->nHeight = h;
    bi->nVersion = c->hdr[h].nVersion;
    tbi_ext(bi)->hashMerkleRoot = c->hdr[h].hashMerkleRoot;
    bi->hashFinalSaplingRoot = c->hdr[h].hashFinalSaplingRoot;
    bi->nTime = c->hdr[h].nTime;
    bi->nBits = c->hdr[h].nBits;
    tbi_ext(bi)->nNonce = c->hdr[h].nNonce;
    bi->nStatus = BLOCK_VALID_TREE | BLOCK_HAVE_DATA;
    bi->pprev = prev;
    return bi;
}

/* H0..H7 connected, every body marked held. Bit h of `unservable`: H<h> has no
 * solution in memory, and the fixture has no store that could supply one. */
static bool lsg_open_chain(struct main_state *ms, struct lsg_chain *c,
                           unsigned unservable)
{
    struct block_index *prev = NULL;

    main_state_init(ms);
    for (int h = 0; h < LSG_CHAIN_LEN; h++) {
        struct block_index *bi = lsg_seed_entry(ms, c, h, prev);
        if (!bi)
            return false;
        if (!(unservable & (1u << h))) {
            size_t len = c->hdr[h].nSolutionSize;
            uint8_t *sol = zcl_malloc(len, "lsg_chain_solution");
            if (!sol)
                return false;
            memcpy(sol, c->hdr[h].nSolution, len);
            tbi_ext(bi)->nSolution = sol;
            tbi_ext(bi)->nSolutionSize = len;
        }
        c->bi[h] = bi;
        prev = bi;
    }
    ms->pindex_best_header = c->bi[LSG_TIP];
    return active_chain_move_window_tip(&ms->chain_active, c->bi[LSG_TIP]);
}

static void lsg_peer_init(struct p2p_node *node, uint64_t services)
{
    memset(node, 0, sizeof(*node));
    node->socket = ZCL_INVALID_SOCKET;
    node->services = services;
    node->starting_height = LSG_TIP;
    snprintf(node->addr_name, sizeof(node->addr_name), "203.0.113.24:8033");
    atomic_store(&node->state, PEER_HANDSHAKE_COMPLETE);
    zcl_mutex_init(&node->cs_send);
}

static void lsg_peer_free(struct p2p_node *node)
{
    struct send_segment *seg = node->send_head;
    while (seg) {
        struct send_segment *next = seg->next;
        send_segment_free(seg);
        seg = next;
    }
    node->send_head = NULL;
    node->send_tail = NULL;
    node->send_size = 0;
    zcl_mutex_destroy(&node->cs_send);
}

static void lsg_send_getheaders(struct msg_processor *mp, struct p2p_node *node,
                                const struct uint256 *locator)
{
    struct uint256 have = *locator;
    struct uint256 stop;
    struct block_locator loc;
    struct byte_stream req;
    struct byte_stream rd;

    uint256_set_null(&stop);
    block_locator_init(&loc);
    loc.vhave = &have;
    loc.num_hashes = 1;
    stream_init(&req, 128);
    getheaders_serialize(&req, &loc, &stop);
    stream_init_from_data(&rd, req.data, req.size);
    process_getheaders(mp, node, &rd);
    stream_free(&rd);
    stream_free(&req);
}

/* The head segment as a headers reply; the count, or -1 if it is not one. */
static int lsg_read_reply(const struct p2p_node *node,
                          struct block_header *out, int max)
{
    const struct send_segment *seg = node->send_head;
    if (!seg || seg->size <= (size_t)MSG_HEADER_SIZE)
        return -1;
    if (strcmp((const char *)seg->data + MESSAGE_START_SIZE, "headers") != 0)
        return -1;
    struct byte_stream wire;
    stream_init_from_data(&wire, seg->data + MSG_HEADER_SIZE,
                          seg->size - MSG_HEADER_SIZE);
    uint64_t count = 0;
    if (!stream_read_compact_size(&wire, &count) || count > (uint64_t)max)
        return -1;
    for (uint64_t i = 0; i < count; i++) {
        uint64_t tx = 1;
        block_header_init(&out[i]);
        if (!block_header_deserialize(&out[i], &wire) ||
            !stream_read_compact_size(&wire, &tx) || tx != 0)
            return -1;
    }
    return (int)count;
}

/* What zclassicd checks: every header names the one before it, and the first
 * names the block the peer already has. */
static bool lsg_reply_contiguous(const struct block_header *got, int count,
                                 const struct uint256 *locator)
{
    struct uint256 parent = *locator;
    for (int i = 0; i < count; i++) {
        if (!uint256_eq(&got[i].hashPrevBlock, &parent))
            return false;
        block_header_get_hash(&got[i], &parent);
    }
    return true;
}

/* -1 ends `want`. */
struct lsg_gap_case {
    const char *name;
    uint64_t services;
    unsigned unservable; /* bit h: no header bytes for H<h> */
    int locator;
    int want[LSG_CHAIN_LEN + 1];
    bool contiguous;
};

static const struct lsg_gap_case lsg_gap_cases[] = {
    {"legacy gaps: with no gap the whole run is sent", NODE_NETWORK, 0, 1,
     {2, 3, 4, 5, 6, 7, -1}, true},
    {"legacy gaps: a reply ends at a gap in the middle", NODE_NETWORK, 1u << 4,
     1, {2, 3, -1}, true},
    {"legacy gaps: a reply ends at the first of two gaps", NODE_NETWORK,
     (1u << 3) | (1u << 5), 1, {2, -1}, true},
    {"legacy gaps: a gap at the tip ends the reply below it", NODE_NETWORK,
     1u << LSG_TIP, 5, {6, -1}, true},
    {"legacy gaps: an unservable successor of the fork point gives an empty "
     "reply", NODE_NETWORK, 1u << 2, 1, {-1}, true},
    {"zcl23 gaps: a reply still skips a gap in the middle",
     NODE_NETWORK | NODE_ZCL23, 1u << 4, 1, {2, 3, 5, 6, 7, -1}, false},
    {"zcl23 gaps: a reply still skips an unservable first entry",
     NODE_NETWORK | NODE_ZCL23, 1u << 2, 1, {3, 4, 5, 6, 7, -1}, false},
};

static bool lsg_reply_matches(const struct lsg_gap_case *tc,
                              const struct lsg_chain *c,
                              const struct block_header *got, int count)
{
    for (int i = 0; i < count; i++) {
        struct uint256 hash;
        if (tc->want[i] < 0)
            return false;
        block_header_get_hash(&got[i], &hash);
        if (!uint256_eq(&hash, &c->hash[tc->want[i]]))
            return false;
    }
    return tc->want[count] < 0;
}

static int lsg_run_gap_case(const struct lsg_gap_case *tc,
                            const struct chain_params *cp, const char *dir,
                            struct lsg_chain *c)
{
    int failures = 0;
    struct main_state ms;
    struct msg_processor mp;
    struct p2p_node node;
    static struct block_header got[LSG_CHAIN_LEN];
    bool opened = lsg_open_chain(&ms, c, tc->unservable);

    lsg_peer_init(&node, tc->services);
    TEST(tc->name) {
        ASSERT(opened);
        msg_processor_init(&mp, &ms, NULL, NULL, cp, dir, &g_lsg_nm, NULL);
        lsg_send_getheaders(&mp, &node, &c->hash[tc->locator]);
        int count = lsg_read_reply(&node, got, LSG_CHAIN_LEN);
        ASSERT(count >= 0);
        ASSERT(lsg_reply_matches(tc, c, got, count));
        if (tc->contiguous)
            ASSERT(lsg_reply_contiguous(got, count, &c->hash[tc->locator]));
        PASS();
    } _test_next:;
    lsg_peer_free(&node);
    main_state_free(&ms);
    header_serve_repair_test_reset();
    return failures;
}

static int lsg_run_gap_cases(const struct chain_params *cp, const char *dir)
{
    int failures = 0;
    static struct lsg_chain chain;

    memset(&chain, 0, sizeof(chain));
    TEST("legacy gaps: the fixture chain mines") {
        ASSERT(lsg_mine_chain(&chain, cp));
        PASS();
    } _test_next:;
    if (failures)
        return failures;
    for (size_t i = 0; i < sizeof(lsg_gap_cases) / sizeof(lsg_gap_cases[0]); i++)
        failures += lsg_run_gap_case(&lsg_gap_cases[i], cp, dir, &chain);
    return failures;
}

int test_legacy_serve_gaps(void);
int test_legacy_serve_gaps(void)
{
    int failures = 0;
    char dir[256];

    printf("\n=== legacy serve gaps ===\n");
    chain_params_select(CHAIN_REGTEST);
    const struct chain_params *cp = chain_params_get();
    test_make_tmpdir(dir, sizeof(dir), "lsg", "gaps");
    failures += lsg_run_gap_cases(cp, dir);
    test_rm_rf(dir);
    chain_params_select(CHAIN_MAIN);
    printf("legacy serve gaps: %s\n", failures ? "FAILED" : "PASSED");
    return failures;
}
