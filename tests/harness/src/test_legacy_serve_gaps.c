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
 *
 * Bodies: see the getdata section below.
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
#include "net/netbase.h"
#include "net/protocol.h"
#include "net/version.h"
#include "primitives/block.h"
#include "storage/disk_block_io.h"
#include "util/safe_alloc.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

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

/* ── getdata past the send budget ─────────────────────────────────────────
 *
 * zclassicd asks for a block once, ignores notfound and leaves the request open
 * until its download timeout, so a request this node stops serving at the send
 * budget has to be finished by this node. A legacy peer has at most 16 blocks in
 * flight. Budget is driven through send_size, which is what it reads; time plays
 * no part. The wire is read cumulatively from the unsent queue, in order. */

#define LSG_BODIES 8
#define LSG_WIRE_MAX 64
#define LSG_LEGACY_IN_FLIGHT 16

struct lsg_body_fixture {
    struct main_state ms;
    struct lsg_chain chain;
    struct net_manager nm;
    struct msg_processor mp;
    struct p2p_node *node;
    struct send_segment *sentinel;
    char dir[256];
    size_t held_bytes;
    bool ms_open;
};

struct lsg_wire {
    struct uint256 blocks[LSG_WIRE_MAX];
    int block_count;
    struct uint256 notfound[LSG_WIRE_MAX];
    int notfound_count;
};

static struct lsg_body_fixture g_lsg;
static struct lsg_chain g_lsg_mined;

static bool lsg_write_body(struct lsg_body_fixture *f, int h,
                           const struct chain_params *cp)
{
    struct block b;
    struct disk_block_pos pos;

    block_init(&b);
    b.header = f->chain.hdr[h];
    b.num_vtx = 1;
    b.vtx = zcl_calloc(1, sizeof(struct transaction), "lsg_body_vtx");
    if (!b.vtx) {
        block_free(&b);
        return false;
    }
    transaction_init(&b.vtx[0]);
    bool ok = transaction_alloc(&b.vtx[0], 1, 1);
    if (ok) {
        b.vtx[0].vin[0].sequence = 0xffffffff;
        b.vtx[0].vout[0].value = 10 * COIN;
        disk_block_pos_init(&pos);
        pos.nFile = -1; /* append: the writer allocates the position */
        ok = write_block_to_disk(&b, &pos, f->dir, cp->pchMessageStart);
    }
    block_free(&b);
    if (ok)
        block_index_disk_pos_store(f->chain.bi[h], pos.nFile, pos.nPos);
    return ok;
}

static bool lsg_body_open(struct lsg_body_fixture *f, uint64_t services,
                          const struct chain_params *cp)
{
    char blocks[300];
    struct net_address addr;
    unsigned char ip[4] = {198, 51, 100, 24};

    memset(f, 0, sizeof(*f));
    f->chain = g_lsg_mined;
    test_make_tmpdir(f->dir, sizeof(f->dir), "lsg", "bodies");
    snprintf(blocks, sizeof(blocks), "%s/blocks", f->dir);
    if (mkdir(blocks, 0755) != 0)
        return false;
    f->ms_open = true;
    if (!lsg_open_chain(&f->ms, &f->chain, 0))
        return false;
    for (int h = 0; h < LSG_BODIES; h++) {
        if (!lsg_write_body(f, h, cp))
            return false;
    }
    net_manager_init(&f->nm);
    msg_processor_init(&f->mp, &f->ms, NULL, NULL, cp, f->dir, &f->nm, NULL);
    net_address_init(&addr);
    net_addr_set_ipv4(&addr.svc.addr, ip);
    addr.svc.port = 8033;
    f->node = p2p_node_create(&f->nm, ZCL_INVALID_SOCKET, &addr, "lsg-peer",
                              true);
    if (!f->node)
        return false;
    f->node->services = services;
    f->node->version = PROTOCOL_VERSION;
    f->node->state = PEER_ACTIVE;
    /* Queued wire segments stay behind this and are never written: a send on
     * the invalid socket would close it and mark the peer as going away. */
    f->sentinel = zcl_calloc(1, sizeof(*f->sentinel), "lsg_send_sentinel");
    if (!f->sentinel)
        return false;
    f->node->send_head = f->sentinel;
    f->node->send_tail = f->sentinel;
    return true;
}

static void lsg_body_close(struct lsg_body_fixture *f)
{
    if (f->node) {
        f->node->send_size -= f->held_bytes;
        if (f->sentinel) {
            f->node->send_head = f->sentinel->next;
            if (!f->node->send_head)
                f->node->send_tail = NULL;
            send_segment_free(f->sentinel);
        }
        p2p_node_free(f->node);
        f->node = NULL;
        net_manager_free(&f->nm);
    }
    if (f->ms_open)
        main_state_free(&f->ms);
    if (f->dir[0])
        test_rm_rf(f->dir);
}

/* Over the per-peer budget without queueing anything: the peer stopped reading. */
static void lsg_stop_reading(struct lsg_body_fixture *f)
{
    f->held_bytes = net_send_peer_bytes_cap() + 1;
    f->node->send_size += f->held_bytes;
}

static void lsg_resume_reading(struct lsg_body_fixture *f)
{
    f->node->send_size -= f->held_bytes;
    f->held_bytes = 0;
}

static bool lsg_getdata(struct lsg_body_fixture *f, const struct inv_item *items,
                        size_t count)
{
    struct byte_stream s;

    stream_init(&s, 64 + count * 36);
    stream_write_compact_size(&s, count);
    for (size_t i = 0; i < count; i++)
        inv_item_serialize(&items[i], &s);
    bool ok = process_getdata(&f->mp, f->node, &s);
    stream_free(&s);
    return ok;
}

static void lsg_inv_body(struct inv_item *out, int h)
{
    inv_item_init_typed(out, MSG_BLOCK, &g_lsg_mined.hash[h]);
}

static void lsg_read_wire_segment(const struct send_segment *seg,
                                  struct lsg_wire *w)
{
    const char *cmd = (const char *)seg->data + MESSAGE_START_SIZE;
    struct byte_stream in;

    stream_init_from_data(&in, seg->data + MSG_HEADER_SIZE,
                          seg->size - MSG_HEADER_SIZE);
    if (strcmp(cmd, "block") == 0 && w->block_count < LSG_WIRE_MAX) {
        struct block_header hdr;
        block_header_init(&hdr);
        if (block_header_deserialize(&hdr, &in))
            block_header_get_hash(&hdr, &w->blocks[w->block_count++]);
    } else if (strcmp(cmd, "notfound") == 0) {
        uint64_t n = 0;
        (void)stream_read_compact_size(&in, &n);
        for (uint64_t i = 0; i < n && w->notfound_count < LSG_WIRE_MAX; i++) {
            struct inv_item inv;
            if (!inv_item_deserialize(&inv, &in))
                break;
            w->notfound[w->notfound_count++] = inv.hash;
        }
    }
    stream_free(&in);
}

static void lsg_read_wire(const struct p2p_node *node, struct lsg_wire *w)
{
    memset(w, 0, sizeof(*w));
    for (const struct send_segment *seg = node->send_head; seg; seg = seg->next) {
        if (seg->size > (size_t)MSG_HEADER_SIZE)
            lsg_read_wire_segment(seg, w);
    }
}

/* The bodies on the wire are exactly the first `count` of `want`, in order. */
static bool lsg_blocks_are(const struct lsg_wire *w,
                           const struct inv_item *want, int count)
{
    if (w->block_count != count)
        return false;
    for (int i = 0; i < count; i++) {
        if (!uint256_eq(&w->blocks[i], &want[i].hash))
            return false;
    }
    return true;
}

/* The send tick, as the message handler thread runs it for this peer. */
static void lsg_tick(struct lsg_body_fixture *f)
{
    (void)msg_send_messages(&f->mp, f->node, false);
}

/* n block requests cycling over the bodies above genesis. */
static void lsg_fill_requests(struct inv_item *items, int n)
{
    for (int i = 0; i < n; i++)
        lsg_inv_body(&items[i], 1 + i % (LSG_BODIES - 1));
}

static int lsg_case_whole_window_served_later(const char *name,
                                              uint64_t services,
                                              const struct chain_params *cp)
{
    int failures = 0;
    static struct lsg_wire w;
    struct inv_item items[LSG_LEGACY_IN_FLIGHT];

    lsg_fill_requests(items, LSG_LEGACY_IN_FLIGHT);
    TEST(name) {
        ASSERT(lsg_body_open(&g_lsg, services, cp));
        lsg_stop_reading(&g_lsg);
        ASSERT(lsg_getdata(&g_lsg, items, LSG_LEGACY_IN_FLIGHT));
        lsg_tick(&g_lsg);
        lsg_read_wire(g_lsg.node, &w);
        ASSERT_EQ(w.block_count, 0);
        ASSERT_EQ(w.notfound_count, 0);
        lsg_resume_reading(&g_lsg);
        lsg_tick(&g_lsg);
        lsg_read_wire(g_lsg.node, &w);
        ASSERT(lsg_blocks_are(&w, items, LSG_LEGACY_IN_FLIGHT));
        ASSERT_EQ(w.notfound_count, 0);
        /* Served once: the next tick has nothing left to send. */
        lsg_tick(&g_lsg);
        lsg_read_wire(g_lsg.node, &w);
        ASSERT_EQ(w.block_count, LSG_LEGACY_IN_FLIGHT);
        PASS();
    } _test_next:;
    lsg_body_close(&g_lsg);
    return failures;
}

static int lsg_case_past_the_bound_gets_notfound(const struct chain_params *cp)
{
    int failures = 0;
    enum { ASKED = LSG_LEGACY_IN_FLIGHT + 4 };
    static struct lsg_wire w;
    struct inv_item items[ASKED];

    lsg_fill_requests(items, ASKED);
    TEST("getdata budget: requests past the bound get notfound at once and the "
         "kept ones are served later") {
        ASSERT(lsg_body_open(&g_lsg, NODE_NETWORK, cp));
        lsg_stop_reading(&g_lsg);
        ASSERT(lsg_getdata(&g_lsg, items, ASKED));
        lsg_read_wire(g_lsg.node, &w);
        ASSERT_EQ(w.block_count, 0);
        ASSERT_EQ(w.notfound_count, ASKED - LSG_LEGACY_IN_FLIGHT);
        for (int i = 0; i < w.notfound_count; i++)
            ASSERT(uint256_eq(&w.notfound[i],
                              &items[LSG_LEGACY_IN_FLIGHT + i].hash));
        lsg_resume_reading(&g_lsg);
        lsg_tick(&g_lsg);
        lsg_read_wire(g_lsg.node, &w);
        ASSERT(lsg_blocks_are(&w, items, LSG_LEGACY_IN_FLIGHT));
        ASSERT_EQ(w.notfound_count, ASKED - LSG_LEGACY_IN_FLIGHT);
        PASS();
    } _test_next:;
    lsg_body_close(&g_lsg);
    return failures;
}

static int lsg_case_budget_trips_mid_request(const struct chain_params *cp)
{
    int failures = 0;
    static struct lsg_wire w;
    struct inv_item items[3];

    lsg_fill_requests(items, 3);
    TEST("getdata budget: a request that crosses the budget part way has the "
         "rest served later") {
        ASSERT(lsg_body_open(&g_lsg, NODE_NETWORK, cp));
        /* At the cap, not over it: the first body takes the peer over. */
        g_lsg.held_bytes = net_send_peer_bytes_cap();
        g_lsg.node->send_size += g_lsg.held_bytes;
        ASSERT(lsg_getdata(&g_lsg, items, 3));
        lsg_read_wire(g_lsg.node, &w);
        ASSERT(lsg_blocks_are(&w, items, 1));
        lsg_resume_reading(&g_lsg);
        lsg_tick(&g_lsg);
        lsg_read_wire(g_lsg.node, &w);
        ASSERT(lsg_blocks_are(&w, items, 3));
        ASSERT_EQ(w.notfound_count, 0);
        PASS();
    } _test_next:;
    lsg_body_close(&g_lsg);
    return failures;
}

static int lsg_case_non_block_items_keep_silence(const struct chain_params *cp)
{
    int failures = 0;
    static struct lsg_wire w;
    struct uint256 other;
    struct inv_item items[3];

    memset(other.data, 0x5c, sizeof(other.data));
    inv_item_init_typed(&items[0], MSG_TX, &other);
    lsg_inv_body(&items[1], 1);
    inv_item_init_typed(&items[2], MSG_FILTERED_BLOCK, &other);
    TEST("getdata budget: other items past the budget get no reply, and the "
         "block between them is still served") {
        ASSERT(lsg_body_open(&g_lsg, NODE_NETWORK, cp));
        lsg_stop_reading(&g_lsg);
        ASSERT(lsg_getdata(&g_lsg, items, 3));
        lsg_resume_reading(&g_lsg);
        lsg_tick(&g_lsg);
        lsg_read_wire(g_lsg.node, &w);
        ASSERT(lsg_blocks_are(&w, &items[1], 1));
        ASSERT_EQ(w.notfound_count, 0);
        PASS();
    } _test_next:;
    lsg_body_close(&g_lsg);
    return failures;
}

static int lsg_case_new_request_waits_its_turn(const struct chain_params *cp)
{
    int failures = 0;
    static struct lsg_wire w;
    struct inv_item items[3];

    lsg_fill_requests(items, 3);
    TEST("getdata budget: a new request under budget is served after the kept "
         "ones") {
        ASSERT(lsg_body_open(&g_lsg, NODE_NETWORK, cp));
        lsg_stop_reading(&g_lsg);
        ASSERT(lsg_getdata(&g_lsg, items, 2));
        lsg_resume_reading(&g_lsg);
        ASSERT(lsg_getdata(&g_lsg, &items[2], 1));
        lsg_read_wire(g_lsg.node, &w);
        ASSERT(lsg_blocks_are(&w, items, 3));
        PASS();
    } _test_next:;
    lsg_body_close(&g_lsg);
    return failures;
}

static int lsg_case_kept_block_we_cannot_read(const struct chain_params *cp)
{
    int failures = 0;
    static struct lsg_wire w;
    struct uint256 unknown;
    struct inv_item items[2];

    memset(unknown.data, 0x5d, sizeof(unknown.data));
    inv_item_init_typed(&items[0], MSG_BLOCK, &unknown);
    lsg_inv_body(&items[1], 1);
    TEST("getdata budget: a kept block this node cannot serve gets notfound "
         "when its turn comes") {
        ASSERT(lsg_body_open(&g_lsg, NODE_NETWORK, cp));
        lsg_stop_reading(&g_lsg);
        ASSERT(lsg_getdata(&g_lsg, items, 2));
        lsg_read_wire(g_lsg.node, &w);
        ASSERT_EQ(w.notfound_count, 0);
        lsg_resume_reading(&g_lsg);
        lsg_tick(&g_lsg);
        lsg_read_wire(g_lsg.node, &w);
        ASSERT(lsg_blocks_are(&w, &items[1], 1));
        ASSERT_EQ(w.notfound_count, 1);
        ASSERT(uint256_eq(&w.notfound[0], &unknown));
        PASS();
    } _test_next:;
    lsg_body_close(&g_lsg);
    return failures;
}

static int lsg_case_disconnecting_peer_is_not_served(const struct chain_params *cp)
{
    int failures = 0;
    static struct lsg_wire w;
    struct inv_item items[1];

    lsg_fill_requests(items, 1);
    TEST("getdata budget: a peer going away is not served what was kept") {
        ASSERT(lsg_body_open(&g_lsg, NODE_NETWORK, cp));
        lsg_stop_reading(&g_lsg);
        ASSERT(lsg_getdata(&g_lsg, items, 1));
        lsg_resume_reading(&g_lsg);
        atomic_store(&g_lsg.node->disconnect, true);
        lsg_tick(&g_lsg);
        lsg_read_wire(g_lsg.node, &w);
        ASSERT_EQ(w.block_count, 0);
        PASS();
    } _test_next:;
    lsg_body_close(&g_lsg);
    return failures;
}

static int lsg_case_whitelisted_peer_is_exempt(const struct chain_params *cp)
{
    int failures = 0;
    static struct lsg_wire w;
    struct inv_item items[2];

    lsg_fill_requests(items, 2);
    TEST("getdata budget: a whitelisted peer is served at once") {
        ASSERT(lsg_body_open(&g_lsg, NODE_NETWORK, cp));
        g_lsg.node->whitelisted = true;
        lsg_stop_reading(&g_lsg);
        ASSERT(lsg_getdata(&g_lsg, items, 2));
        lsg_read_wire(g_lsg.node, &w);
        ASSERT(lsg_blocks_are(&w, items, 2));
        PASS();
    } _test_next:;
    lsg_body_close(&g_lsg);
    return failures;
}

static int lsg_run_getdata_cases(const struct chain_params *cp)
{
    int failures = 0;

    failures += lsg_case_whole_window_served_later(
        "getdata budget: a legacy peer's whole window is served once it reads "
        "again, in order and once", NODE_NETWORK, cp);
    failures += lsg_case_whole_window_served_later(
        "getdata budget: so is a NODE_ZCL23 peer's", NODE_NETWORK | NODE_ZCL23,
        cp);
    failures += lsg_case_past_the_bound_gets_notfound(cp);
    failures += lsg_case_budget_trips_mid_request(cp);
    failures += lsg_case_non_block_items_keep_silence(cp);
    failures += lsg_case_new_request_waits_its_turn(cp);
    failures += lsg_case_kept_block_we_cannot_read(cp);
    failures += lsg_case_disconnecting_peer_is_not_served(cp);
    failures += lsg_case_whitelisted_peer_is_exempt(cp);
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
    TEST("getdata budget: the fixture chain mines") {
        ASSERT(lsg_mine_chain(&g_lsg_mined, cp));
        PASS();
    } _test_next:;
    if (!failures)
        failures += lsg_run_getdata_cases(cp);
    chain_params_select(CHAIN_MAIN);
    printf("legacy serve gaps: %s\n", failures ? "FAILED" : "PASSED");
    return failures;
}
