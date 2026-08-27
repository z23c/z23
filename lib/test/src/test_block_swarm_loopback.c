/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_block_swarm_loopback.c — the BitTorrent-style parallel BLOCK swarm
 * (zblkmanfst / zblkreq / zblkdata) driven end-to-end between two independent
 * message processors over a real wire, plus a measured throughput number and
 * coverage of the event-driven disconnect requeue.
 *
 * Until now the block swarm (lib/net/src/fast_sync.c coordinator +
 * lib/net/src/msgprocessor_snapshot.c wire dispatch + msgprocessor_snapshot_serve.c
 * serve side) had ONLY algorithm-level unit coverage (test_fast_sync.c drives
 * block_swarm_assign_piece / receive_piece / handle_timeouts on an in-memory
 * struct). No test ever pushed real zblkmanfst/zblkreq/zblkdata bytes through
 * the real dispatcher between a seeder that reads block bodies from disk and a
 * fetcher that submits them. This file does that.
 *
 * Architecture (mirrors test_snapshot_serve_loopback.c): two fully independent
 * logical nodes in one process —
 *   A = SEEDER: a real main_state with an active chain of N synthetic blocks
 *       written to real blk*.dat files, a published block-piece manifest, and a
 *       block_hashes_range callback. Serves zblkdata from real disk bodies via
 *       the production mp_serve_block_req path.
 *   B = FETCHER: pindex_best_header at the manifest tip (headers ahead, bodies
 *       behind — the real IBD posture that arms the swarm), an empty active
 *       chain, and a block_submit callback that records every delivered body.
 *
 * The block swarm coordinator (g_block_swarm) is a single process-global; here
 * it is logically owned by B (the seeder never activates its own swarm because
 * the fetcher it sees is behind it). Transport is the same sentinel-guarded
 * send-queue pump test_snapshot_serve_loopback.c uses: p2p_node_begin/write/end
 * queue real wire-framed segments (magic+command+len+checksum), and bs_pump()
 * feeds those raw bytes through the REAL p2p_node_receive_bytes() parser and the
 * REAL msg_process_messages() dispatcher — only the socket syscalls are elided.
 *
 * The per-peer swarm scheduler mp_snapshot_send_tick() (private header, not on
 * the test include path) is forward-declared and called DIRECTLY: it is real
 * production code, and it owns the rarest-first assignment, the contiguous
 * window cap, the bounded piece pipeline, and the zblkreq emission. Driving it is what
 * makes this an integration test of the actual piece dance rather than a
 * re-implementation of it.
 *
 * Two tests:
 *   1. THROUGHPUT — full manifest → request → serve → receive loop to
 *      completion; asserts every block body transferred and prints blk/s + MB/s.
 *   2. DISCONNECT REQUEUE — a peer holds pieces in flight; a second peer can
 *      claim NOTHING while they sit CHUNK_INFLIGHT (the pre-timeout stall);
 *      mp_block_swarm_peer_disconnected() requeues them event-driven, the second
 *      peer immediately picks them up, and the download finishes over the
 *      failover peer. This is the fix wired into connman's disconnect cleanup. */

#define _GNU_SOURCE
#include "test/test_core.h"
#include "consensus/validation.h"

#include "chain/chain.h"
#include "chain/chainparams.h"
#include "coins/coins_view.h"
#include "config/boot_snapshot_offer.h"
#include "core/serialize.h"
#include "core/uint256.h"
#include "net/download.h"
#include "net/fast_sync.h"
#include "net/msg_internal.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "platform/time_compat.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "storage/disk_block_io.h"
#include "util/safe_alloc.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "validation/txmempool.h"

#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Real per-peer swarm scheduler + the block-swarm-active probe — both defined
 * non-static in msgprocessor_snapshot.c, declared only in the private
 * lib/net/src/msgprocessor_internal.h. Forward-declared here so this test drives
 * the genuine assignment/request loop and observes swarm activation.
 * (mp_block_swarm_peer_disconnected is public — net/download.h.) */
void mp_snapshot_send_tick(struct msg_processor *mp, struct p2p_node *node);
bool mp_block_swarm_is_active(void);

/* Equihash 200,9 solution length — makes each synthetic block ~1.5 KB, so the
 * measured MB/s reflects realistic block bodies, not empty stubs. */
#define BS_SOLUTION_SIZE 1344
#define BS_START_HEIGHT  1

/* ── Fetcher block sink: records every submitted body ────────────────────── */
struct bs_sink {
    uint64_t blocks;
    uint64_t bytes;   /* serialized size of each delivered body */
    uint64_t scope_begins;
    uint64_t scope_ends;
    uint64_t submits_outside_scope;
    uint64_t drains;
    uint64_t drains_inside_scope;
    int transient_submit_failures;
    unsigned scope_depth;
    unsigned scope_max_depth;
    bool scope_open;
};

static bool bs_block_submit(struct block *b, struct validation_state *out,
                            void *ctx)
{
    struct bs_sink *sink = ctx;
    if (!sink->scope_open)
        sink->submits_outside_scope++;
    if (sink->transient_submit_failures > 0) {
        const char *reason = sink->transient_submit_failures == 1
            ? "p2p-block-intake-full"
            : "header-admit-inbox-full";
        sink->transient_submit_failures--;
        return validation_state_error(out, reason);
    }
    struct byte_stream s;
    stream_init(&s, 4096);
    if (block_serialize(b, &s))
        sink->bytes += s.size;
    stream_free(&s);
    sink->blocks++;
    if (out)
        validation_state_init(out);   /* valid = accepted */
    return true;
}

static void bs_scope_begin(void *ctx)
{
    struct bs_sink *sink = ctx;
    sink->scope_begins++;
    sink->scope_depth++;
    if (sink->scope_depth > sink->scope_max_depth)
        sink->scope_max_depth = sink->scope_depth;
    sink->scope_open = true;
}

static void bs_scope_end(void *ctx)
{
    struct bs_sink *sink = ctx;
    sink->scope_ends++;
    if (sink->scope_depth > 0)
        sink->scope_depth--;
    sink->scope_open = sink->scope_depth > 0;
}

static int bs_catchup_drain(void *ctx)
{
    struct bs_sink *sink = ctx;
    sink->drains++;
    if (sink->scope_open)
        sink->drains_inside_scope++;
    return 1;
}

/* ── Seeder fixture ──────────────────────────────────────────────────────── */
struct bs_seeder {
    struct main_state       ms;
    struct tx_mempool       mempool;
    struct coins_view       null_view;
    struct coins_view_cache coins;
    struct net_manager      nm;
    struct msg_processor    mp;
    char                    datadir[256];
    int32_t                 end_height;
    struct uint256         *hashes;   /* [0..end_height] real block hashes */
    struct block_index    **idx;      /* [0..end_height] chain entries */
};

/* block_hashes_range serve callback: copy the seeder's real block hashes for
 * [start,end] into hashes_out. Returns count written. */
static int bs_block_hashes_range(int32_t start, int32_t end,
                                 uint8_t (*hashes_out)[32], size_t max,
                                 void *ctx)
{
    struct bs_seeder *s = ctx;
    int n = 0;
    for (int32_t h = start; h <= end && (size_t)n < max; h++) {
        if (h < 0 || h > s->end_height)
            return n;
        memcpy(hashes_out[n], s->hashes[h].data, 32);
        n++;
    }
    return n;
}

/* Build one well-formed synthetic block at height h on prev. Deterministic and
 * globally unique (salt distinguishes fixtures across test cases in the same
 * process). Fills a full Equihash-sized solution so bodies are realistically
 * sized. Caller owns *out (block_free). */
static void bs_make_block(int32_t h, const struct uint256 *prev, uint32_t salt,
                          struct block *out)
{
    block_init(out);
    out->header.nVersion = 4;
    out->header.nTime = 1500000000u + (uint32_t)h + salt * 7u;
    out->header.nBits = 0x2000ffff;
    out->header.hashPrevBlock = *prev;
    memset(&out->header.hashMerkleRoot, 0, sizeof(out->header.hashMerkleRoot));
    out->header.hashMerkleRoot.data[0] = (uint8_t)(h & 0xFF);
    out->header.hashMerkleRoot.data[1] = (uint8_t)((h >> 8) & 0xFF);
    out->header.hashMerkleRoot.data[2] = (uint8_t)(salt & 0xFF);
    out->header.hashMerkleRoot.data[3] = 0x5A;
    memset(&out->header.hashFinalSaplingRoot, 0,
           sizeof(out->header.hashFinalSaplingRoot));
    memset(&out->header.nNonce, 0, sizeof(out->header.nNonce));
    out->header.nSolutionSize = BS_SOLUTION_SIZE;
    for (size_t i = 0; i < BS_SOLUTION_SIZE; i++)
        out->header.nSolution[i] = (uint8_t)((i * 131u) + (uint32_t)h + salt);

    out->num_vtx = 1;
    out->vtx = calloc(1, sizeof(struct transaction)); // raw-alloc-ok:test-fixture
    transaction_init(&out->vtx[0]);
    transaction_alloc(&out->vtx[0], 1, 1);
    out->vtx[0].vin[0].sequence = 0xffffffff;
    out->vtx[0].vout[0].value = 10 * COIN;
}

/* Build the seeder: N blocks (1..end) written to real blk*.dat, an active chain
 * with disk positions + BLOCK_HAVE_DATA, and a published block-piece manifest.
 * Returns false on any failure. */
static bool bs_seeder_build(struct bs_seeder *s, int32_t end_height,
                            uint32_t salt, const char *tag)
{
    const struct chain_params *params = chain_params_get();
    memset(s, 0, sizeof(*s));
    s->end_height = end_height;

    snprintf(s->datadir, sizeof(s->datadir), "./test-tmp/%d_%s_seed",
             (int)getpid(), tag);
    mkdir("./test-tmp", 0755);
    mkdir(s->datadir, 0755);
    char blocks[512];
    snprintf(blocks, sizeof(blocks), "%s/blocks", s->datadir);
    mkdir(blocks, 0755);

    main_state_init(&s->ms);
    tx_mempool_init(&s->mempool, 0);
    coins_view_cache_init(&s->coins, &s->null_view);
    net_manager_init(&s->nm);

    s->hashes = zcl_calloc((size_t)end_height + 1, sizeof(*s->hashes),
                           "bs_hashes");
    s->idx = zcl_calloc((size_t)end_height + 1, sizeof(*s->idx), "bs_idx");
    if (!s->hashes || !s->idx)
        return false;

    /* Deferred fdatasync: N per-block journal barriers would dominate build
     * time; one sync_pending() at the end is durable enough for a fixture. */
    disk_block_io_set_deferred_sync(true);

    struct uint256 prev;
    memset(&prev, 0, sizeof(prev));
    struct block_index *prev_idx = NULL;

    for (int32_t h = 0; h <= end_height; h++) {
        struct block b;
        bs_make_block(h, &prev, salt, &b);

        struct uint256 hash;
        block_get_hash(&b, &hash);

        struct disk_block_pos pos;
        disk_block_pos_init(&pos);
        bool wrote = write_block_to_disk(&b, &pos, s->datadir,
                                         params->pchMessageStart);
        block_free(&b);
        if (!wrote)
            return false;

        s->hashes[h] = hash;

        struct block_index *bi =
            chainstate_insert_block_index((struct chainstate *)&s->ms, &hash);
        if (!bi)
            return false;
        bi->nHeight = h;
        bi->nBits = 0x2000ffff;
        bi->nTime = 1500000000u + (uint32_t)h;
        bi->nVersion = 4;
        bi->nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
        bi->nFile = pos.nFile;
        bi->nDataPos = pos.nPos;
        bi->nTx = 1;
        bi->pprev = prev_idx;
        s->idx[h] = bi;

        prev = hash;
        prev_idx = bi;
    }

    disk_block_io_sync_pending();
    disk_block_io_set_deferred_sync(false);

    if (!active_chain_move_window_tip(&s->ms.chain_active, s->idx[end_height]))
        return false;

    s->mp.main_state = &s->ms;
    s->mp.mempool = &s->mempool;
    s->mp.coins_tip = &s->coins;
    s->mp.params = params;
    s->mp.datadir = s->datadir;
    s->mp.net_mgr = &s->nm;
    msg_processor_set_block_hashes_range(&s->mp, bs_block_hashes_range, s);

    /* Publish the block-piece manifest from the trusted active chain (real
     * production builder). publish takes ownership of piece_hashes. */
    struct block_piece_manifest pm;
    if (!block_piece_manifest_build_active_chain(&s->ms.chain_active,
                                                 BS_START_HEIGHT, end_height,
                                                 &pm))
        return false;
    if (!msg_processor_publish_block_manifest(&pm, end_height)) {
        block_piece_manifest_free(&pm);
        return false;
    }
    return true;
}

static void bs_seeder_free(struct bs_seeder *s)
{
    msg_processor_invalidate_block_manifest();
    if (s->idx)
        free(s->idx);
    if (s->hashes)
        free(s->hashes);
    net_manager_free(&s->nm);
    coins_view_cache_free(&s->coins);
    tx_mempool_free(&s->mempool);
    main_state_free(&s->ms);

    char cmd[600];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", s->datadir);
    (void)system(cmd);
}

/* ── Loopback transport (sentinel-guarded pump, per test_snapshot_serve_loopback) ── */
static struct send_segment *bs_install_sentinel(struct p2p_node *node)
{
    struct send_segment *sentinel =
        zcl_calloc(1, sizeof(*sentinel), "bs_loopback_sentinel");
    node->send_head = sentinel;
    node->send_tail = sentinel;
    node->send_offset = 0;
    return sentinel;
}

/* Number of wire messages queued behind the sentinel (each begin/write/end is
 * one framed segment for the small messages this test emits). */
static size_t bs_queue_depth(const struct send_segment *sentinel)
{
    size_t n = 0;
    for (const struct send_segment *s = sentinel->next; s; s = s->next)
        n++;
    return n;
}

/* Drop everything queued behind the sentinel WITHOUT delivering it — models a
 * peer that received our requests and then vanished. */
static void bs_drop_queue(struct p2p_node *from, struct send_segment *sentinel)
{
    while (sentinel->next) {
        struct send_segment *seg = sentinel->next;
        sentinel->next = seg->next;
        if (from->send_size >= seg->size)
            from->send_size -= seg->size;
        else
            from->send_size = 0;
        send_segment_free(seg);
    }
    from->send_head = sentinel;
    from->send_tail = sentinel;
    from->send_offset = 0;
}

/* Drain every segment queued behind `sentinel` on `from`, feed the raw wire
 * bytes to `to` through the real parser, then run the real dispatcher on `to`.
 * Returns bytes delivered (0 if nothing was queued). */
static size_t bs_pump(struct p2p_node *from, struct send_segment *sentinel,
                      struct msg_processor *to_mp, struct p2p_node *to,
                      const unsigned char msgstart[MESSAGE_START_SIZE],
                      bool *ok_out)
{
    size_t bytes = 0;
    bool any = false, ok = true;

    while (sentinel->next) {
        struct send_segment *seg = sentinel->next;
        sentinel->next = seg->next;
        if (from->send_tail == seg)
            from->send_tail = sentinel;
        if (from->send_size >= seg->size)
            from->send_size -= seg->size;
        else
            from->send_size = 0;

        bytes += seg->size;
        if (!p2p_node_receive_bytes(to, (const char *)seg->data,
                                    (unsigned int)seg->size, msgstart)) {
            send_segment_free(seg);
            ok = false;
            break;
        }
        any = true;
        send_segment_free(seg);
    }
    from->send_head = sentinel;
    from->send_tail = sentinel;
    from->send_offset = 0;

    if (ok && any)
        ok = msg_process_messages(to_mp, to);
    if (ok_out)
        *ok_out = ok;
    return bytes;
}

/* Create a fetcher-side peer node representing a seeder connection. */
static struct p2p_node *bs_make_peer(struct net_manager *nm, uint8_t last_octet)
{
    struct net_address addr;
    memset(&addr, 0, sizeof(addr));
    memcpy(addr.svc.addr.ip, pchIPv4Prefix, 12);
    addr.svc.addr.ip[12] = 10; addr.svc.addr.ip[13] = 20;
    addr.svc.addr.ip[14] = 30; addr.svc.addr.ip[15] = last_octet;
    addr.svc.port = 18033;

    struct p2p_node *n = p2p_node_create(nm, ZCL_INVALID_SOCKET, &addr,
                                         "seed-peer", false);
    if (!n)
        return NULL;
    n->version = 1;
    n->services = NODE_ZCL23;
    n->state = PEER_HANDSHAKE_COMPLETE;
    return n;
}

/* ══════════════════════ Test 1: throughput ══════════════════════════════ */
static int test_block_swarm_throughput(void)
{
    int failures = 0;

    TEST("block swarm loopback: manifest->request->serve->receive to "
         "completion over a real wire, every body transferred, throughput "
         "measured") {
        const struct chain_params *params = chain_params_get();
        const int32_t end_height = 2560;            /* 40 pieces of 64 */
        struct bs_seeder seed;

        ASSERT(!mp_block_swarm_is_active());        /* clean process precondition */
        ASSERT(bs_seeder_build(&seed, end_height, 1u, "thru"));

        /* Fetcher B: IBD posture — headers at the tip, bodies behind. */
        struct main_state ms_b;
        struct tx_mempool mempool_b;
        struct coins_view null_view_b;
        struct coins_view_cache coins_b;
        struct net_manager nm_b;
        struct msg_processor mp_b;
        struct bs_sink sink = { .transient_submit_failures = 2 };

        main_state_init(&ms_b);
        tx_mempool_init(&mempool_b, 0);
        coins_view_cache_init(&coins_b, &null_view_b);
        net_manager_init(&nm_b);
        memset(&mp_b, 0, sizeof(mp_b));
        mp_b.main_state = &ms_b;
        mp_b.mempool = &mempool_b;
        mp_b.coins_tip = &coins_b;
        mp_b.params = params;
        mp_b.datadir = ".";
        mp_b.net_mgr = &nm_b;
        msg_processor_set_block_submit(&mp_b, bs_block_submit, &sink);
        msg_processor_set_catchup_drain(&mp_b, bs_catchup_drain, &sink);
        msg_processor_set_catchup_batch_scope(
            &mp_b, bs_scope_begin, bs_scope_end, &sink);

        /* B's best header = manifest tip (arms piece assignment); active chain
         * empty (arms swarm start: end_h > our_h + BLOCKS_PER_PIECE). */
        struct uint256 bhh;
        memset(&bhh, 0, sizeof(bhh));
        bhh.data[0] = 0xB0; bhh.data[1] = 0x0B; bhh.data[2] = 0x11;
        struct block_index *b_besthdr =
            chainstate_insert_block_index((struct chainstate *)&ms_b, &bhh);
        ASSERT(b_besthdr != NULL);
        b_besthdr->nHeight = end_height;
        b_besthdr->nStatus = BLOCK_VALID_TREE;
        ms_b.pindex_best_header = b_besthdr;

        /* Peers: A-side sees B; B-side sees A. */
        struct p2p_node *a_node = bs_make_peer(&seed.nm, 1);
        struct p2p_node *b_node = bs_make_peer(&nm_b, 2);
        ASSERT(a_node && b_node);
        struct send_segment *sent_a = bs_install_sentinel(a_node);
        struct send_segment *sent_b = bs_install_sentinel(b_node);

        /* Step 1: A pushes the block manifest; B ingests it → g_block_swarm. */
        push_block_manifest(&seed.mp, a_node);
        bool ok = true;
        bs_pump(a_node, sent_a, &mp_b, b_node, params->pchMessageStart, &ok);
        ASSERT(ok);
        ASSERT(b_node->blk_manifest_received);
        ASSERT(mp_block_swarm_is_active());

        /* Step 2: drive the real piece dance to completion, measuring only the
         * transfer loop. Each round: B assigns+requests (real scheduler) → A
         * serves from disk (real mp_serve_block_req) → B verifies+submits. */
        int64_t t0 = platform_time_monotonic_us();
        int rounds = 0;
        while (mp_block_swarm_is_active() && rounds < 64) {
            mp_snapshot_send_tick(&mp_b, b_node);      /* B: assign + zblkreq   */
            size_t reqbytes = bs_pump(b_node, sent_b, &seed.mp, a_node,
                                      params->pchMessageStart, &ok);
            ASSERT(ok);
            if (reqbytes == 0)
                break;                                 /* nothing left to ask   */
            bs_pump(a_node, sent_a, &mp_b, b_node,
                    params->pchMessageStart, &ok);     /* A serve → B receive   */
            ASSERT(ok);
            rounds++;
        }
        int64_t elapsed_us = platform_time_monotonic_us() - t0;
        if (elapsed_us <= 0)
            elapsed_us = 1;

        /* Every body in the manifest range (1..end) transferred exactly once. */
        ASSERT(!mp_block_swarm_is_active());           /* swarm completed+freed */
        ASSERT(sink.blocks == (uint64_t)end_height);
        ASSERT(sink.scope_begins == 40); /* one bounded scope per 64-body piece */
        ASSERT(sink.scope_ends == sink.scope_begins);   /* exactly paired */
        ASSERT(sink.scope_max_depth == 1);              /* never chain-wide */
        ASSERT(!sink.scope_open);                       /* no scope leak */
        ASSERT(sink.submits_outside_scope == 0);        /* every body batched */
        ASSERT(sink.drains == 2); /* header inbox + block intake backpressure */
        ASSERT(sink.drains_inside_scope == 2);          /* flush-before-retry */
        const int expected_pieces =
            (end_height + (int)BLOCKS_PER_PIECE - 1) /
            (int)BLOCKS_PER_PIECE;
        const int expected_rounds =
            (expected_pieces + PIECE_PIPELINE_DEPTH - 1) /
            PIECE_PIPELINE_DEPTH;
        ASSERT(rounds == expected_rounds);

        double secs = (double)elapsed_us / 1e6;
        double blks = (double)sink.blocks / secs;
        double mbps = ((double)sink.bytes / (1024.0 * 1024.0)) / secs;
        printf("(swarm throughput: %llu blocks / %llu bytes in %lldus over "
               "%d rounds -> %.0f blk/s, %.1f MB/s) ",
               (unsigned long long)sink.blocks,
               (unsigned long long)sink.bytes,
               (long long)elapsed_us, rounds, blks, mbps);

        send_segment_free(sent_a);
        send_segment_free(sent_b);
        a_node->send_head = a_node->send_tail = NULL;
        b_node->send_head = b_node->send_tail = NULL;
        p2p_node_free(a_node);
        p2p_node_free(b_node);
        net_manager_free(&nm_b);
        coins_view_cache_free(&coins_b);
        tx_mempool_free(&mempool_b);
        main_state_free(&ms_b);
        bs_seeder_free(&seed);
        PASS();
    } _test_next:;

    return failures;
}

/* ══════════════════════ Test 2: disconnect requeue ══════════════════════ */
static int test_block_swarm_disconnect_requeue(void)
{
    int failures = 0;

    TEST("block swarm loopback: a dead peer's in-flight pieces are event-"
         "driven requeued (pre-timeout) and picked up by a failover peer") {
        const struct chain_params *params = chain_params_get();
        const int32_t end_height = 2560;            /* 40 pieces of 64 */
        struct bs_seeder seed;

        ASSERT(!mp_block_swarm_is_active());
        ASSERT(bs_seeder_build(&seed, end_height, 2u, "disc"));

        struct main_state ms_b;
        struct tx_mempool mempool_b;
        struct coins_view null_view_b;
        struct coins_view_cache coins_b;
        struct net_manager nm_b;
        struct msg_processor mp_b;
        struct bs_sink sink = {0};

        main_state_init(&ms_b);
        tx_mempool_init(&mempool_b, 0);
        coins_view_cache_init(&coins_b, &null_view_b);
        net_manager_init(&nm_b);
        memset(&mp_b, 0, sizeof(mp_b));
        mp_b.main_state = &ms_b;
        mp_b.mempool = &mempool_b;
        mp_b.coins_tip = &coins_b;
        mp_b.params = params;
        mp_b.datadir = ".";
        mp_b.net_mgr = &nm_b;
        msg_processor_set_block_submit(&mp_b, bs_block_submit, &sink);
        msg_processor_set_catchup_drain(&mp_b, bs_catchup_drain, &sink);
        msg_processor_set_catchup_batch_scope(
            &mp_b, bs_scope_begin, bs_scope_end, &sink);

        struct uint256 bhh;
        memset(&bhh, 0, sizeof(bhh));
        bhh.data[0] = 0xB0; bhh.data[1] = 0x0B; bhh.data[2] = 0x22;
        struct block_index *b_besthdr =
            chainstate_insert_block_index((struct chainstate *)&ms_b, &bhh);
        ASSERT(b_besthdr != NULL);
        b_besthdr->nHeight = end_height;
        b_besthdr->nStatus = BLOCK_VALID_TREE;
        ms_b.pindex_best_header = b_besthdr;

        /* A-side serve node, plus TWO fetcher-side peers: p1 (fails) + p2. */
        struct p2p_node *a_node = bs_make_peer(&seed.nm, 1);
        struct p2p_node *p1 = bs_make_peer(&nm_b, 2);
        struct p2p_node *p2 = bs_make_peer(&nm_b, 3);
        ASSERT(a_node && p1 && p2);
        struct send_segment *sent_a = bs_install_sentinel(a_node);
        struct send_segment *sent_p1 = bs_install_sentinel(p1);
        struct send_segment *sent_p2 = bs_install_sentinel(p2);

        /* Manifest → both fetcher peers. First reception arms g_block_swarm;
         * the second only flags p2->blk_manifest_received (swarm already up). */
        bool ok = true;
        push_block_manifest(&seed.mp, a_node);
        bs_pump(a_node, sent_a, &mp_b, p1, params->pchMessageStart, &ok);
        ASSERT(ok && p1->blk_manifest_received);
        ASSERT(mp_block_swarm_is_active());

        a_node->blk_manifest_sent = false;             /* re-send to p2         */
        push_block_manifest(&seed.mp, a_node);
        bs_pump(a_node, sent_a, &mp_b, p2, params->pchMessageStart, &ok);
        ASSERT(ok && p2->blk_manifest_received);

        /* p1 grabs its window of pieces (marked CHUNK_INFLIGHT, owned by p1 in
         * g_block_swarm), then goes dark: the zblkreq segments are dropped and
         * never served, so those pieces would sit in flight until the 8 s
         * BLOCK_PIECE_TIMEOUT sweep expired them. */
        bs_drop_queue(p1, sent_p1);                    /* isolate this tick     */
        mp_snapshot_send_tick(&mp_b, p1);
        size_t p1_reqs = bs_queue_depth(sent_p1);
        printf("(dead peer held %zu in-flight pieces) ", p1_reqs);
        const size_t expected_pieces =
            (size_t)(end_height + (int)BLOCKS_PER_PIECE - 1) /
            BLOCKS_PER_PIECE;
        const size_t expected_owned =
            expected_pieces < PIECE_PIPELINE_DEPTH
                ? expected_pieces : PIECE_PIPELINE_DEPTH;
        ASSERT(p1_reqs == expected_owned);             /* all bounded work owned */
        bs_drop_queue(p1, sent_p1);                    /* p1 vanishes mid-flight */

        /* THE FIX (wired into connman's disconnect cleanup): reclaim exactly the
         * pieces the dead peer held, EVENT-DRIVEN. This whole test runs in well
         * under a second, so a timeout-based sweep (block_swarm_handle_timeouts,
         * 8 s) would reclaim NOTHING here — a non-zero return proves the requeue
         * is driven by the disconnect, not by elapsed time. */
        size_t requeued = mp_block_swarm_peer_disconnected((uint32_t)p1->id);
        ASSERT(requeued == p1_reqs);                   /* exactly p1's pieces   */
        ASSERT(mp_block_swarm_peer_disconnected((uint32_t)p1->id) == 0); /* idem */

        /* FAILOVER: the requeued pieces are NEEDED again, so a live peer claims
         * and downloads them. Drive p2 to completion and confirm every body of
         * the whole manifest range arrives over the surviving peer. */
        int rounds = 0;
        while (mp_block_swarm_is_active() && rounds < 64) {
            mp_snapshot_send_tick(&mp_b, p2);
            size_t reqbytes = bs_pump(p2, sent_p2, &seed.mp, a_node,
                                      params->pchMessageStart, &ok);
            ASSERT(ok);
            if (reqbytes == 0)
                break;
            bs_pump(a_node, sent_a, &mp_b, p2, params->pchMessageStart, &ok);
            ASSERT(ok);
            rounds++;
        }

        ASSERT(!mp_block_swarm_is_active());           /* finished via failover */
        ASSERT(sink.blocks == (uint64_t)end_height);   /* all bodies delivered  */
        ASSERT(sink.scope_begins == 40); /* one bounded scope per piece */
        ASSERT(sink.scope_ends == sink.scope_begins);   /* exactly paired        */
        ASSERT(sink.scope_max_depth == 1);              /* never chain-wide */
        ASSERT(!sink.scope_open);
        ASSERT(sink.submits_outside_scope == 0);
        ASSERT(sink.drains == 0);                       /* no periodic barrier */
        ASSERT(sink.drains_inside_scope == sink.drains);

        send_segment_free(sent_a);
        send_segment_free(sent_p1);
        send_segment_free(sent_p2);
        a_node->send_head = a_node->send_tail = NULL;
        p1->send_head = p1->send_tail = NULL;
        p2->send_head = p2->send_tail = NULL;
        p2p_node_free(a_node);
        p2p_node_free(p1);
        p2p_node_free(p2);
        net_manager_free(&nm_b);
        coins_view_cache_free(&coins_b);
        tx_mempool_free(&mempool_b);
        main_state_free(&ms_b);
        bs_seeder_free(&seed);
        PASS();
    } _test_next:;

    return failures;
}

/* ══════════════════════ Test 3: stall reap watchdog ══════════════════════
 * The legacy getdata assignment in msg_send_messages is paused while a block
 * swarm is active, and the swarm's only exit used to be full completion — a
 * peer that silently stops answering zblkreq wedged catch-up permanently
 * (queue full, flight zero, frontier body never fetched). The watchdog must
 * abandon a completion-silent swarm (and stay off a healthy or finished one). */
bool mp_block_swarm_reap_if_stalled(struct msg_processor *mp);
void mp_block_swarm_test_seed_stall(uint32_t complete, uint32_t total,
                                    int64_t last_complete_unix);
int64_t mp_block_swarm_test_reaped_unix(void);
bool mp_block_swarm_test_fail_integrity(struct msg_processor *mp,
                                        uint32_t piece_index);

static int test_block_swarm_stall_reap(void)
{
    int failures = 0;

    TEST("block swarm stall watchdog: completion-silent swarm is abandoned, "
         "healthy and finished swarms are left alone") {
        int64_t now = (int64_t)platform_time_wall_time_t();

        /* Healthy swarm (recent completion) → no reap. */
        mp_block_swarm_test_seed_stall(5, 10, now);
        ASSERT(mp_block_swarm_is_active());
        ASSERT(!mp_block_swarm_reap_if_stalled(NULL));
        ASSERT(mp_block_swarm_is_active());
        ASSERT(mp_block_swarm_test_reaped_unix() == 0);

        /* Fully-complete swarm, however old → never reaped (completion is
         * the normal exit path, not a stall). */
        mp_block_swarm_test_seed_stall(10, 10, now - 100000);
        ASSERT(mp_block_swarm_is_active());
        ASSERT(!mp_block_swarm_reap_if_stalled(NULL));
        ASSERT(mp_block_swarm_is_active());
        ASSERT(mp_block_swarm_test_reaped_unix() == 0);

        /* Completion-silent far past the stall threshold → reaped, once. */
        mp_block_swarm_test_seed_stall(5, 10, now - 100000);
        ASSERT(mp_block_swarm_is_active());
        ASSERT(mp_block_swarm_reap_if_stalled(NULL));
        ASSERT(!mp_block_swarm_is_active());
        ASSERT(mp_block_swarm_test_reaped_unix() > 0);
        ASSERT(!mp_block_swarm_reap_if_stalled(NULL));   /* idempotent */

        mp_block_swarm_test_seed_stall(0, 0, 0);         /* teardown */
        ASSERT(!mp_block_swarm_is_active());
        ASSERT(mp_block_swarm_test_reaped_unix() == 0);
        PASS();
    } _test_next:;

    return failures;
}

static int test_block_swarm_integrity_abandon(void)
{
    int failures = 0;

    TEST("block swarm integrity mismatch abandons immediately, clears peer "
         "pipelines, and preserves the silent-stall watchdog separately") {
        int64_t now = (int64_t)platform_time_wall_time_t();
        struct net_manager nm;
        struct msg_processor mp;
        struct p2p_node peer;
        struct p2p_node *nodes[1] = { &peer };
        memset(&nm, 0, sizeof(nm));
        memset(&mp, 0, sizeof(mp));
        memset(&peer, 0, sizeof(peer));
        zcl_mutex_init(&nm.cs_nodes);
        nm.nodes = nodes;
        nm.num_nodes = 1;
        mp.net_mgr = &nm;
        for (int i = 0; i < PIECE_PIPELINE_DEPTH; i++)
            peer.blk_pipeline[i].piece_index = i + 1;

        mp_block_swarm_test_seed_stall(5, 10, now);
        ASSERT(mp_block_swarm_is_active());
        ASSERT(mp_block_swarm_test_fail_integrity(&mp, 6));
        ASSERT(!mp_block_swarm_is_active());
        ASSERT(mp_block_swarm_test_reaped_unix() > 0);
        for (int i = 0; i < PIECE_PIPELINE_DEPTH; i++)
            ASSERT(peer.blk_pipeline[i].piece_index == -1);
        ASSERT(!mp_block_swarm_test_fail_integrity(&mp, 6));
        ASSERT(!mp_block_swarm_reap_if_stalled(&mp));

        mp_block_swarm_test_seed_stall(0, 0, 0);
        zcl_mutex_destroy(&nm.cs_nodes);
        PASS();
    } _test_next:;

    return failures;
}

/* ══════════════ Test 4: duplicate piece delivery never double-credits ════
 * A piece re-requested on BLOCK_PIECE_TIMEOUT_SECS can be answered twice
 * (slow original + re-request). Crediting both deliveries inflates
 * pieces_complete past the genuinely-delivered count, so the swarm can
 * "complete" with pieces never fetched — fold holes behind a complete swarm
 * (the live tail wedge: 67 pieces credited-but-never-delivered). */
struct bs_kept { unsigned char *data; size_t size; };

/* Steal every segment queued behind `sentinel` on `from`, keeping a heap copy
 * of each (caller frees kept[i].data) WITHOUT delivering it. */
static size_t bs_steal_queue(struct p2p_node *from,
                             struct send_segment *sentinel,
                             struct bs_kept *kept, size_t max_kept)
{
    size_t n = 0;
    while (sentinel->next && n < max_kept) {
        struct send_segment *seg = sentinel->next;
        sentinel->next = seg->next;
        if (from->send_tail == seg)
            from->send_tail = sentinel;
        if (from->send_size >= seg->size)
            from->send_size -= seg->size;
        else
            from->send_size = 0;
        kept[n].data = zcl_malloc(seg->size, "bs_kept_seg");
        memcpy(kept[n].data, seg->data, seg->size);
        kept[n].size = seg->size;
        n++;
        send_segment_free(seg);
    }
    from->send_head = sentinel;
    from->send_tail = sentinel;
    from->send_offset = 0;
    return n;
}

static bool bs_deliver(struct msg_processor *to_mp, struct p2p_node *to,
                       const struct bs_kept *k,
                       const unsigned char msgstart[MESSAGE_START_SIZE])
{
    if (!p2p_node_receive_bytes(to, (const char *)k->data,
                                (unsigned int)k->size, msgstart))
        return false;
    return msg_process_messages(to_mp, to);
}

static int test_block_swarm_duplicate_delivery(void)
{
    int failures = 0;

    TEST("block swarm loopback: a piece delivered twice is credited once — "
         "the swarm cannot complete with an unfetched piece") {
        const struct chain_params *params = chain_params_get();
        const int32_t end_height = 128;             /* 2 pieces of 64 */
        struct bs_seeder seed;

        ASSERT(!mp_block_swarm_is_active());
        ASSERT(bs_seeder_build(&seed, end_height, 1u, "dup"));

        struct main_state ms_b;
        struct tx_mempool mempool_b;
        struct coins_view null_view_b;
        struct coins_view_cache coins_b;
        struct net_manager nm_b;
        struct msg_processor mp_b;
        struct bs_sink sink = { .transient_submit_failures = 0 };

        main_state_init(&ms_b);
        tx_mempool_init(&mempool_b, 0);
        coins_view_cache_init(&coins_b, &null_view_b);
        net_manager_init(&nm_b);
        memset(&mp_b, 0, sizeof(mp_b));
        mp_b.main_state = &ms_b;
        mp_b.mempool = &mempool_b;
        mp_b.coins_tip = &coins_b;
        mp_b.params = params;
        mp_b.datadir = ".";
        mp_b.net_mgr = &nm_b;
        msg_processor_set_block_submit(&mp_b, bs_block_submit, &sink);
        msg_processor_set_catchup_drain(&mp_b, bs_catchup_drain, &sink);
        msg_processor_set_catchup_batch_scope(
            &mp_b, bs_scope_begin, bs_scope_end, &sink);

        struct uint256 bhh;
        memset(&bhh, 0, sizeof(bhh));
        bhh.data[0] = 0xB0; bhh.data[1] = 0x0B; bhh.data[2] = 0x11;
        struct block_index *b_besthdr =
            chainstate_insert_block_index((struct chainstate *)&ms_b, &bhh);
        ASSERT(b_besthdr != NULL);
        b_besthdr->nHeight = end_height;
        b_besthdr->nStatus = BLOCK_VALID_TREE;
        ms_b.pindex_best_header = b_besthdr;

        struct p2p_node *a_node = bs_make_peer(&seed.nm, 1);
        struct p2p_node *b_node = bs_make_peer(&nm_b, 2);
        ASSERT(a_node && b_node);
        struct send_segment *sent_a = bs_install_sentinel(a_node);
        struct send_segment *sent_b = bs_install_sentinel(b_node);

        push_block_manifest(&seed.mp, a_node);
        bool ok = true;
        bs_pump(a_node, sent_a, &mp_b, b_node, params->pchMessageStart, &ok);
        ASSERT(ok);
        ASSERT(mp_block_swarm_is_active());

        /* B requests both pieces; A serves both. Capture the two zblkdata
         * replies WITHOUT delivering them. */
        mp_snapshot_send_tick(&mp_b, b_node);
        bs_pump(b_node, sent_b, &seed.mp, a_node, params->pchMessageStart, &ok);
        ASSERT(ok);
        struct bs_kept kept[4] = {0};
        size_t kept_n = bs_steal_queue(a_node, sent_a, kept, 4);
        ASSERT(kept_n == 2);

        /* Deliver piece 0, then a DUPLICATE of piece 0 (the timeout
         * re-request answered twice). The duplicate must not complete the
         * swarm: piece 1 has never been delivered. */
        ASSERT(bs_deliver(&mp_b, b_node, &kept[0], params->pchMessageStart));
        ASSERT(mp_block_swarm_is_active());
        ASSERT(bs_deliver(&mp_b, b_node, &kept[0], params->pchMessageStart));
        ASSERT(mp_block_swarm_is_active());   /* would be freed on double-credit */

        /* The genuine second piece completes the swarm. */
        ASSERT(bs_deliver(&mp_b, b_node, &kept[1], params->pchMessageStart));
        ASSERT(!mp_block_swarm_is_active());
        ASSERT(sink.blocks == 3 * (uint64_t)BLOCKS_PER_PIECE); /* p0 + dup + p1 */
        ASSERT(sink.scope_begins == 3);       /* duplicate still verified+submitted */
        ASSERT(sink.scope_ends == sink.scope_begins);

        free(kept[0].data);
        free(kept[1].data);
        send_segment_free(sent_a);
        send_segment_free(sent_b);
        a_node->send_head = a_node->send_tail = NULL;
        b_node->send_head = b_node->send_tail = NULL;
        p2p_node_free(a_node);
        p2p_node_free(b_node);
        net_manager_free(&nm_b);
        coins_view_cache_free(&coins_b);
        tx_mempool_free(&mempool_b);
        main_state_free(&ms_b);
        bs_seeder_free(&seed);
        PASS();
    } _test_next:;

    return failures;
}

/* ══════════════ Test 5: manifest anchoring ══════════════════════
 * MSG_BLOCK_MANIFEST carries attacker-chosen start/end/tip_hash. Before this
 * pin, receipt alone flagged blk_manifest_received and armed the swarm — a
 * peer could aim body fetchers at a range rooted in nothing. Admission now
 * requires a two-tier anchor against the LOCAL header index: full (the real
 * tip hash resolves at exactly end_height) or fallback (start_height is at or
 * below our admitted header frontier — the catch-up posture every fixture
 * above rides, since their best headers carry fabricated hashes). Anything
 * unrooted is refused and scored. Cases run in contamination order:
 * refuse (nothing resolvable) → fallback (fabricated frontier) → full
 * (real tip indexed, frontier removed so ONLY the full tier can admit). */
static int test_block_swarm_manifest_anchor(void)
{
    int failures = 0;

    TEST("block swarm loopback: zblkmanfst must anchor in the local header "
         "index (full tip match, admitted-frontier fallback, else refuse)") {
        const struct chain_params *params = chain_params_get();
        const int32_t end_height = 320;             /* 5 pieces of 64 */
        struct bs_seeder seed;

        ASSERT(!mp_block_swarm_is_active());
        ASSERT(bs_seeder_build(&seed, end_height, 7u, "anch"));

        struct main_state ms_b;
        struct tx_mempool mempool_b;
        struct coins_view null_view_b;
        struct coins_view_cache coins_b;
        struct net_manager nm_b;
        struct msg_processor mp_b;

        main_state_init(&ms_b);
        tx_mempool_init(&mempool_b, 0);
        coins_view_cache_init(&coins_b, &null_view_b);
        net_manager_init(&nm_b);
        memset(&mp_b, 0, sizeof(mp_b));
        mp_b.main_state = &ms_b;
        mp_b.mempool = &mempool_b;
        mp_b.coins_tip = &coins_b;
        mp_b.params = params;
        mp_b.datadir = ".";
        mp_b.net_mgr = &nm_b;

        /* One seeder-side sender; three fetcher-side receivers, one per
         * verdict. ms_b starts completely EMPTY: no index entries at all and
         * pindex_best_header NULL, so neither tier can resolve yet. */
        struct p2p_node *a_node = bs_make_peer(&seed.nm, 1);
        struct p2p_node *p_refuse = bs_make_peer(&nm_b, 2);
        struct p2p_node *p_fb = bs_make_peer(&nm_b, 3);
        struct p2p_node *p_full = bs_make_peer(&nm_b, 4);
        ASSERT(a_node && p_refuse && p_fb && p_full);
        struct send_segment *sent_a = bs_install_sentinel(a_node);

        bool ok = true;

        /* ── REFUSE: empty index, no frontier → both tiers miss. */
        push_block_manifest(&seed.mp, a_node);
        bs_pump(a_node, sent_a, &mp_b, p_refuse, params->pchMessageStart, &ok);
        ASSERT(ok);
        ASSERT(!p_refuse->blk_manifest_received);
        ASSERT(!mp_block_swarm_is_active());       /* nothing armed */

        /* ── FALLBACK: fabricated frontier AT the manifest end height (the
         * header-synced-bodies-behind posture); the real tip hash is still
         * unknown locally, so only the frontier tier can admit this. */
        struct uint256 bhh;
        memset(&bhh, 0, sizeof(bhh));
        bhh.data[0] = 0xB0; bhh.data[1] = 0x0B; bhh.data[2] = 0x33;
        struct block_index *fb_hdr =
            chainstate_insert_block_index((struct chainstate *)&ms_b, &bhh);
        ASSERT(fb_hdr != NULL);
        fb_hdr->nHeight = end_height;
        fb_hdr->nStatus = BLOCK_VALID_TREE;
        ms_b.pindex_best_header = fb_hdr;

        a_node->blk_manifest_sent = false;
        push_block_manifest(&seed.mp, a_node);
        bs_pump(a_node, sent_a, &mp_b, p_fb, params->pchMessageStart, &ok);
        ASSERT(ok);
        ASSERT(p_fb->blk_manifest_received);       /* fallback tier admits */
        ASSERT(mp_block_swarm_is_active());        /* and the swarm arms    */
        mp_block_swarm_test_seed_stall(0, 0, 0);   /* teardown              */
        ASSERT(!mp_block_swarm_is_active());

        /* ── FULL: index the manifest's REAL tip hash at exactly end_height
         * and drop the frontier, so the fallback tier is UNAVAILABLE and
         * admission can only come from the resolved tip. */
        struct block_index *tip_bi = chainstate_insert_block_index(
            (struct chainstate *)&ms_b, &seed.hashes[end_height]);
        ASSERT(tip_bi != NULL);
        tip_bi->nHeight = end_height;
        tip_bi->nStatus = BLOCK_VALID_TREE;
        ms_b.pindex_best_header = NULL;

        a_node->blk_manifest_sent = false;
        push_block_manifest(&seed.mp, a_node);
        bs_pump(a_node, sent_a, &mp_b, p_full, params->pchMessageStart, &ok);
        ASSERT(ok);
        ASSERT(p_full->blk_manifest_received);     /* full tier admits      */
        ASSERT(mp_block_swarm_is_active());
        mp_block_swarm_test_seed_stall(0, 0, 0);   /* teardown              */
        ASSERT(!mp_block_swarm_is_active());

        send_segment_free(sent_a);
        a_node->send_head = a_node->send_tail = NULL;
        p_refuse->send_head = p_refuse->send_tail = NULL;
        p_fb->send_head = p_fb->send_tail = NULL;
        p_full->send_head = p_full->send_tail = NULL;
        p2p_node_free(a_node);
        p2p_node_free(p_refuse);
        p2p_node_free(p_fb);
        p2p_node_free(p_full);
        net_manager_free(&nm_b);
        coins_view_cache_free(&coins_b);
        tx_mempool_free(&mempool_b);
        main_state_free(&ms_b);
        bs_seeder_free(&seed);
        PASS();
    } _test_next:;

    return failures;
}

/* ══════════ Test 7: the sovereignty gate binds block pieces ══════════ */

/* Private to lib/net/src (msgprocessor_snapshot_internal.h); reached here
 * by extern prototype, the test_addrman_shutdown_race.c precedent. */
extern void mp_serve_block_req(struct msg_processor *mp,
                               struct p2p_node *node, struct byte_stream *s);

/* The snapshot family refuses to advertise or serve while the node is not
 * snapshot-sovereign (msg_snapshot_serving_allowed()). The block-piece
 * family — push_block_manifest and mp_serve_block_req — slipped past that
 * boundary: an assisted node still advertised MSG_BLOCK_MANIFEST and
 * served MSG_BLOCK_DATA out of its cached manifest. Both doors now sit
 * behind the same gate, and this test drives them through the real wire
 * path: the sovereign controls prove the fixture serves, the non-sovereign
 * refusals leave the queue AND the sticky sent-flag untouched, and the
 * recovered serves prove the only thing that changed was the trust state. */
static int test_block_swarm_sovereignty_gate(void)
{
    int failures = 0;

    TEST("block swarm loopback: a non-sovereign node neither advertises "
         "nor serves block pieces, and both recover with the trust state") {
        const int32_t end_height = 128;             /* 2 pieces of 64 */
        struct bs_seeder seed;

        ASSERT(!mp_block_swarm_is_active());
        ASSERT(bs_seeder_build(&seed, end_height, 9u, "sovg"));

        struct p2p_node *a_node = bs_make_peer(&seed.nm, 1);
        ASSERT(a_node);
        struct send_segment *sent_a = bs_install_sentinel(a_node);

        /* ── SOVEREIGN CONTROLS: both doors work. ── */
        boot_snapshot_offer_test_set_trust_override(1);

        push_block_manifest(&seed.mp, a_node);
        ASSERT(a_node->blk_manifest_sent);
        ASSERT(bs_queue_depth(sent_a) == 1);       /* the zblkmanfst itself */
        bs_drop_queue(a_node, sent_a);

        struct byte_stream req;
        stream_init(&req, 16);
        stream_write_u32_le(&req, 0);              /* piece 0: h=1..64 */
        mp_serve_block_req(&seed.mp, a_node, &req);
        stream_free(&req);
        ASSERT(bs_queue_depth(sent_a) == 1);       /* zblkdata on the wire */
        bs_drop_queue(a_node, sent_a);

        /* ── NON-SOVEREIGN: both doors refuse. Nothing may leave the
         * process: not the manifest frame, not one piece, and the sticky
         * sent-flag must stay down so a later honest push is not lost. ── */
        boot_snapshot_offer_test_set_trust_override(0);

        a_node->blk_manifest_sent = false;
        push_block_manifest(&seed.mp, a_node);
        ASSERT(!a_node->blk_manifest_sent);
        ASSERT(bs_queue_depth(sent_a) == 0);

        struct byte_stream req2;
        stream_init(&req2, 16);
        stream_write_u32_le(&req2, 0);
        mp_serve_block_req(&seed.mp, a_node, &req2);
        stream_free(&req2);
        ASSERT(bs_queue_depth(sent_a) == 0);

        /* ── RECOVERED: the same fixture serves again the moment the node
         * is sovereign — the refusal was the trust state, nothing else. ── */
        boot_snapshot_offer_test_set_trust_override(1);

        struct byte_stream req3;
        stream_init(&req3, 16);
        stream_write_u32_le(&req3, 0);
        mp_serve_block_req(&seed.mp, a_node, &req3);
        stream_free(&req3);
        ASSERT(bs_queue_depth(sent_a) == 1);
        bs_drop_queue(a_node, sent_a);

        boot_snapshot_offer_test_set_trust_override(1);   /* group baseline */
        send_segment_free(sent_a);
        a_node->send_head = a_node->send_tail = NULL;
        p2p_node_free(a_node);
        bs_seeder_free(&seed);
        PASS();
    } _test_next:;

    return failures;
}

int test_block_swarm_loopback(void)
{
    int failures = 0;
    /* Every test here advertises and serves block pieces from a fixture
     * that never booted the runtime port, so the live sovereignty
     * predicate reads "port absent" — not sovereign — and the serving
     * gates would refuse each push before the scenario under test even
     * starts. Declare the process sovereign for the group (the same
     * thing test_net.c and the snapshot serve loopback do around their
     * serving tests); the one test that exercises the gate itself
     * (sovereignty_gate) flips the override internally and hands the
     * baseline back. Cleared once, after the last sub-test. */
    boot_snapshot_offer_test_set_trust_override(1);
    failures += test_block_swarm_throughput();
    failures += test_block_swarm_disconnect_requeue();
    failures += test_block_swarm_stall_reap();
    failures += test_block_swarm_integrity_abandon();
    failures += test_block_swarm_duplicate_delivery();
    failures += test_block_swarm_manifest_anchor();
    failures += test_block_swarm_sovereignty_gate();
    boot_snapshot_offer_test_set_trust_override(-1);
    return failures;
}
