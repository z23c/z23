/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Adversarial/DoS coverage for the P2P message-handling path. A hostile
 * peer controls the wire bytes; the handlers that see them first must stay
 * bounded and safe:
 *
 *   A. Oversized declared counts (inv/getdata/addr/notfound) are rejected
 *      before any loop or allocation; the peer is disconnected and scored
 *      via PEER_OFFENCE_FLOOD so the ban score accrues across reconnects.
 *   B. Truncated payloads fail cleanly with no partial mutation.
 *   C. A declared size above MAX_PROTOCOL_MESSAGE_LENGTH is rejected at the
 *      framing layer (net_message_read_data) before any allocation.
 *   D. An unknown command through msg_process_messages is silently ignored
 *      (Bitcoin Core parity); a following `ping` still dispatches.
 *   E. A replayed `headers` batch is idempotent: no duplicate block-tree
 *      entries and no misbehaviour score.
 *   F. A legal-sized `addr` batch of non-routable (RFC1918) addresses is
 *      accepted at the envelope level; addrman inserts none.
 *   G. A `ping` with a wrong checksum is dropped before dispatch at bounded
 *      cost and the connection is not penalized (Core parity, as in D).
 *   H. A `reject` whose msg_type length exceeds the local buffer still reads
 *      the following fields from the correct wire offset; H2 covers a
 *      declared length beyond the remaining bytes.
 *   I. A getdata for more unservable blocks than the notfound batch size
 *      (64) gets a notfound for every item, split across messages.
 *   J. ZMSG telemetry: accepted, duplicate, and acknowledgment frames
 *      increment distinct monotone counters and keep last-event timestamps.
 *
 * Sections A/B/E/F/H/H2 use a stack p2p_node + memset since those paths
 * return before touching any node mutex. Sections C/D/G/I/J use a heap node
 * from p2p_node_create (mutex-initialized). */

#include "test/test_core.h"
#include "util/util.h"

#include "mining/miner.h"
#include "net/msg_internal.h"
#include "net/msgprocessor.h"
#include "net/peer_scoring.h"
#include "net/protocol.h"
#include "net/version.h"
#include "net/zmsg.h"
#include "core/hash.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "validation/chainstate.h"
#include "validation/process_block.h"  /* accept_block_header */

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include "platform/socket_compat.h"
#include <unistd.h>

#define DOS_CHECK(name, expr) do { \
    printf("net_msg_dos: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Non-localhost/non-whitelisted peer so peer_misbehaving() scores it
 * (is_trusted_peer() exempts 127.0.0.0/8 and whitelisted peers). */
static void dos_setup_stack_node(struct p2p_node *node)
{
    memset(node, 0, sizeof(*node));
    snprintf(node->addr_name, sizeof(node->addr_name), "203.0.113.77:8033");
    node->id = 77;
    node->addr.svc.addr.ip[10] = 0xff;
    node->addr.svc.addr.ip[11] = 0xff;
    node->addr.svc.addr.ip[12] = 5;
    node->addr.svc.addr.ip[13] = 6;
    node->addr.svc.addr.ip[14] = 7;
    node->addr.svc.addr.ip[15] = 8;
}

static const struct msg_dispatch_entry *dos_find_entry(const char *cmd)
{
    const struct msg_dispatch_entry *e = msg_get_dispatch_table();
    for (; e->handler; e++) {
        if (strcmp(e->command, cmd) == 0)
            return e;
    }
    return NULL;
}

static int dos_getblocks_have_data_plan(struct msg_processor *mp,
                                        struct block_locator *loc,
                                        const struct uint256 *child_hash);

static int dos_getblocks_active_control(struct msg_processor *mp,
                                        struct p2p_node *node,
                                        struct block_locator *loc,
                                        const struct uint256 *genesis,
                                        const struct chain_params *cp)
{
    int failures = 0;
    struct block ctrl_child;
    struct uint256 child_hash;
    struct byte_stream s;
    unsigned char stop[32] = {0};
    struct arith_uint256 ctrl_pow_limit;
    bool built, ret, ctrl_mined, ctrl_admitted = false;

    block_init(&ctrl_child);
    ctrl_child.header.nVersion = 4;
    ctrl_child.header.hashPrevBlock = *genesis;
    uint256_set_null(&ctrl_child.header.hashMerkleRoot);
    ctrl_child.header.hashMerkleRoot.data[0] = 2;
    uint256_set_null(&ctrl_child.header.hashFinalSaplingRoot);
    ctrl_child.header.nTime = 1700000000u;
    uint256_to_arith(&ctrl_pow_limit, &cp->consensus.powLimit);
    ctrl_child.header.nBits = arith_uint256_get_compact(&ctrl_pow_limit, false);
    ctrl_mined = mine_block_pow(&ctrl_child, 1, cp, 0);
    DOS_CHECK("getblocks control: regtest child mined", ctrl_mined);
    uint256_set_null(&child_hash);
    if (ctrl_mined)
        block_header_get_hash(&ctrl_child.header, &child_hash);
    if (ctrl_mined) {
        struct byte_stream hs;
        stream_init(&hs, 512);
        stream_write_compact_size(&hs, 1);
        block_header_serialize(&ctrl_child.header, &hs);
        stream_write_compact_size(&hs, 0);
        ctrl_admitted = process_headers(mp, node, &hs);
        DOS_CHECK("getblocks control: child admitted via headers",
                  ctrl_admitted);
        stream_free(&hs);
    }
    block_free(&ctrl_child);

    stream_init(&s, 64);
    built = block_locator_serialize(loc, &s);
    built = built && stream_write_bytes(&s, stop, sizeof(stop));
    ret = process_getblocks(mp, node, &s);
    DOS_CHECK("getblocks headers-only child is not announced",
              ctrl_admitted && ret && node->inventory_to_send_count == 0);
    stream_free(&s);
    failures += dos_getblocks_have_data_plan(mp, loc, &child_hash);
    return failures;
}

static int dos_getblocks_have_data_plan(struct msg_processor *mp,
                                        struct block_locator *loc,
                                        const struct uint256 *child_hash)
{
    int failures = 0;
    struct block_index *child_bi;
    struct inv_item planned[GETBLOCKS_INV_LIMIT];
    struct uint256 stop;
    size_t n;

    child_bi = block_map_find(&mp->main_state->map_block_index, child_hash);
    DOS_CHECK("getblocks control: child is indexed", child_bi != NULL);
    if (!child_bi)
        return failures;
    uint256_set_null(&stop);
    n = msg_blocks_plan_getblocks_inv(mp, loc, &stop, planned,
                                      GETBLOCKS_INV_LIMIT);
    DOS_CHECK("getblocks plan: headers-only yields zero invs", n == 0);
    child_bi->nStatus |= BLOCK_HAVE_DATA;
    n = msg_blocks_plan_getblocks_inv(mp, loc, &stop, planned,
                                      GETBLOCKS_INV_LIMIT);
    DOS_CHECK("getblocks plan: HAVE_DATA body is announced",
              n == 1 && uint256_eq(&planned[0].hash, child_hash));
    child_bi->nStatus &= ~BLOCK_HAVE_DATA;
    n = msg_blocks_plan_getblocks_inv(mp, loc, &stop, planned,
                                      GETBLOCKS_INV_LIMIT);
    DOS_CHECK("getblocks plan: dropping HAVE_DATA stops announce", n == 0);
    return failures;
}

static int dos_check_inv_oversized_count(struct msg_processor *mp)
{
    int failures = 0;
    /* ── A1. inv: oversized count -> reject + disconnect + scored ── */
    {
        struct p2p_node node;
        dos_setup_stack_node(&node);
        struct byte_stream s;
        stream_init(&s, 32);
        stream_write_compact_size(&s, 50001); /* MAX_INV_SZ (50000) + 1 */
        /* Tiny payload, huge declared count: the guard must fire before
         * touching a single inv item. */
        bool ret = process_inv(mp, &node, &s);
        DOS_CHECK("inv oversized: handler returns false", ret == false);
        DOS_CHECK("inv oversized: peer disconnected", node.disconnect == true);
        DOS_CHECK("inv oversized: peer scored PEER_OFFENCE_FLOOD (20)",
                 atomic_load(&node.misbehavior) == 20);
        stream_free(&s);
    }
    return failures;
}

static int dos_check_getdata_oversized_count(struct msg_processor *mp)
{
    int failures = 0;
    /* ── A2. getdata: oversized count -> reject + disconnect + scored ── */
    {
        struct p2p_node node;
        dos_setup_stack_node(&node);
        struct byte_stream s;
        stream_init(&s, 32);
        stream_write_compact_size(&s, 50001);
        bool ret = process_getdata(mp, &node, &s);
        DOS_CHECK("getdata oversized: handler returns false", ret == false);
        DOS_CHECK("getdata oversized: peer disconnected",
                 node.disconnect == true);
        DOS_CHECK("getdata oversized: peer scored PEER_OFFENCE_FLOOD (20)",
                 atomic_load(&node.misbehavior) == 20);
        stream_free(&s);
    }
    return failures;
}

static int dos_check_getblocks_pre_handshake(struct msg_processor *mp,
                                             const struct uint256 *gh,
                                             const struct chain_params *cp)
{
    int failures = 0;
    /* ── A2b. getblocks: no service before the handshake completes ──
     * The dispatcher only refuses node->version == 0, so the post-version /
     * pre-verack window is gated here. A post-handshake control serves
     * genesis only. */
    {
        struct block_locator loc;
        block_locator_init(&loc);
        struct uint256 one[1];
        one[0] = cp->consensus.hashGenesisBlock;
        loc.vhave = one;
        loc.num_hashes = 1;

        struct p2p_node node;
        dos_setup_stack_node(&node);
        node.state = PEER_VERSION_RECEIVED;   /* past version==0, not verified */

        struct byte_stream s;
        stream_init(&s, 64);
        bool built = block_locator_serialize(&loc, &s);
        unsigned char stop[32] = {0};
        built = built && stream_write_bytes(&s, stop, sizeof(stop));
        DOS_CHECK("getblocks pre-handshake: payload built", built);
        bool ret = process_getblocks(mp, &node, &s);
        DOS_CHECK("getblocks pre-handshake: dropped quietly", ret == true);
        DOS_CHECK("getblocks pre-handshake: nothing queued",
                  node.inventory_to_send_count == 0);
        DOS_CHECK("getblocks pre-handshake: no penalty",
                  atomic_load(&node.misbehavior) == 0 && !node.disconnect);
        stream_free(&s);

        dos_setup_stack_node(&node);
        node.state = PEER_ACTIVE;
        failures += dos_getblocks_active_control(mp, &node, &loc, gh, cp);
        /* loc.vhave points at stack storage — release only the shell. */
        loc.vhave = NULL;
        loc.num_hashes = 0;
    }
    return failures;
}

static int dos_check_addr_oversized_count(struct msg_processor *mp)
{
    int failures = 0;
    /* ── A3. addr: oversized count -> reject + disconnect + scored ── */
    {
        const struct msg_dispatch_entry *e = dos_find_entry("addr");
        DOS_CHECK("addr dispatch entry found", e != NULL);
        if (e) {
            struct p2p_node node;
            dos_setup_stack_node(&node);
            struct byte_stream s;
            stream_init(&s, 32);
            stream_write_compact_size(&s, 1001); /* MAX_ADDR_TO_SEND (1000) + 1 */
            bool ret = e->handler(mp, &node, &s);
            DOS_CHECK("addr oversized: handler returns false", ret == false);
            DOS_CHECK("addr oversized: peer disconnected",
                     node.disconnect == true);
            DOS_CHECK("addr oversized: peer scored PEER_OFFENCE_FLOOD (20)",
                     atomic_load(&node.misbehavior) == 20);
            stream_free(&s);
        }
    }
    return failures;
}

static int dos_check_notfound_oversized_count(struct msg_processor *mp)
{
    int failures = 0;
    /* ── A4. notfound: oversized count -> reject + disconnect + scored ── */
    {
        const struct msg_dispatch_entry *e = dos_find_entry("notfound");
        DOS_CHECK("notfound dispatch entry found", e != NULL);
        if (e) {
            struct p2p_node node;
            dos_setup_stack_node(&node);
            struct byte_stream s;
            stream_init(&s, 32);
            stream_write_compact_size(&s, 50001);
            bool ret = e->handler(mp, &node, &s);
            DOS_CHECK("notfound oversized: handler returns false",
                     ret == false);
            DOS_CHECK("notfound oversized: peer disconnected",
                     node.disconnect == true);
            DOS_CHECK("notfound oversized: peer scored PEER_OFFENCE_FLOOD (20)",
                     atomic_load(&node.misbehavior) == 20);
            stream_free(&s);
        }
    }
    return failures;
}

static int dos_check_addr_rate_limit(struct msg_processor *mp)
{
    int failures = 0;
    /* ── A5. addr: repeated max-legal-size batches -> rate limited ──
     * Pins the ADDR_RATE_WINDOW_SECS/ADDR_RATE_MAX_PER_WINDOW limiter in
     * msgprocessor_inv.c::process_addr(): three 1000-entry batches (at the
     * cap) are free; the fourth crosses it and scores + disconnects. */
    {
        const struct msg_dispatch_entry *e = dos_find_entry("addr");
        DOS_CHECK("addr dispatch entry found (rate-limit case)", e != NULL);
        if (e) {
            struct p2p_node node;
            dos_setup_stack_node(&node);
            bool saw_disconnect_early = false;

            for (int batch = 0; batch < 4; batch++) {
                struct byte_stream s;
                stream_init(&s, 1000 * 30 + 16);
                stream_write_compact_size(&s, 1000); /* == MAX_ADDR_TO_SEND, legal */
                for (int i = 0; i < 1000; i++) {
                    struct net_address addr;
                    net_address_init(&addr);
                    unsigned char ip4[4] = {10, 1,
                                            (unsigned char)(i >> 8),
                                            (unsigned char)i};
                    net_addr_set_ipv4(&addr.svc.addr, ip4);
                    addr.svc.port = 8033;
                    net_address_serialize(&addr, &s, true);
                }
                bool ret = e->handler(mp, &node, &s);
                stream_free(&s);
                if (batch < 3) {
                    if (!ret || node.disconnect)
                        saw_disconnect_early = true;
                } else {
                    DOS_CHECK("addr rate limit: 4th max-size batch rejected",
                             ret == false);
                    DOS_CHECK("addr rate limit: peer disconnected",
                             node.disconnect == true);
                    DOS_CHECK("addr rate limit: peer scored PEER_OFFENCE_FLOOD (20)",
                             atomic_load(&node.misbehavior) == 20);
                }
            }
            DOS_CHECK("addr rate limit: first three max-size batches were free",
                     !saw_disconnect_early);
        }
    }
    return failures;
}

static int dos_check_inv_truncated(struct msg_processor *mp)
{
    int failures = 0;
    /* ── B1. inv: truncated mid-item -> clean failure, no crash ── */
    {
        struct p2p_node node;
        dos_setup_stack_node(&node);
        struct byte_stream s;
        stream_init(&s, 32);
        stream_write_compact_size(&s, 2); /* promises 2 inv items (72 bytes)... */
        unsigned char garbage[10];
        memset(garbage, 0xab, sizeof(garbage));
        stream_write_bytes(&s, garbage, sizeof(garbage)); /* ...delivers 10B */
        bool ret = process_inv(mp, &node, &s);
        DOS_CHECK("inv truncated: handler returns false", ret == false);
        stream_free(&s);
    }
    return failures;
}

static int dos_check_getdata_truncated(struct msg_processor *mp)
{
    int failures = 0;
    /* ── B2. getdata: truncated mid-item -> clean failure, no crash ── */
    {
        struct p2p_node node;
        dos_setup_stack_node(&node);
        struct byte_stream s;
        stream_init(&s, 32);
        stream_write_compact_size(&s, 2);
        unsigned char garbage[10];
        memset(garbage, 0xcd, sizeof(garbage));
        stream_write_bytes(&s, garbage, sizeof(garbage));
        bool ret = process_getdata(mp, &node, &s);
        DOS_CHECK("getdata truncated: handler returns false", ret == false);
        stream_free(&s);
    }
    return failures;
}

static int dos_check_oversize_framing(void)
{
    int failures = 0;
    /* ── C. framing layer: declared size > MAX_PROTOCOL_MESSAGE_LENGTH
     *      is rejected BEFORE any allocation against the recv budget ── */
    {
        unsigned char magic[MESSAGE_START_SIZE] = {0x24, 0xe9, 0x27, 0x64};
        size_t base = net_recv_total_bytes();

        struct net_message m;
        net_message_init(&m, magic);
        struct msg_header hdr;
        /* 3 MiB: above MAX_PROTOCOL_MESSAGE_LENGTH (2 MiB), below the
         * header-level MAX_SIZE (32 MiB), so the data-phase check fires. */
        msg_header_init_full(&hdr, magic, "block", 3 * 1024 * 1024);
        int hn = net_message_read_header(&m, (const char *)&hdr,
                                         MSG_HEADER_SIZE);
        DOS_CHECK("oversize framing: header parsed",
                 hn == (int)MSG_HEADER_SIZE && m.in_data);

        unsigned char chunk[16];
        memset(chunk, 0x11, sizeof(chunk));
        int dn = net_message_read_data(&m, (const char *)chunk, sizeof(chunk));
        DOS_CHECK("oversize framing: read_data rejects before allocating",
                 dn < 0);
        DOS_CHECK("oversize framing: no allocation happened",
                 m.recv_data == NULL && m.recv_alloc == 0);
        DOS_CHECK("oversize framing: process-wide recv budget untouched",
                 net_recv_total_bytes() == base);
        net_message_free(&m);
    }
    return failures;
}

static int dos_check_unknown_cmd_dispatch(struct msg_processor *mp,
                                          struct net_manager *nm)
{
    int failures = 0;
    /* ── D. unknown/garbage command through the real dispatch loop:
     *      silently ignored, connection untouched, honest traffic after
     *      still works on the SAME connection ── */
    {
        unsigned char magic[MESSAGE_START_SIZE] = {0x24, 0xe9, 0x27, 0x64};
        struct net_address addr;
        net_address_init(&addr);
        unsigned char ip4[4] = {198, 51, 100, 23};
        net_addr_set_ipv4(&addr.svc.addr, ip4);
        addr.svc.port = 8033;

        /* A real connected socketpair: the `ping` handler replies with a
         * `pong` via send(); an invalid fd would close the connection and
         * falsify the "connection intact" assertion. */
        platform_socket_t sv[2];
        bool have_sv = platform_socket_pair(sv);
        DOS_CHECK("dispatch: socketpair created", have_sv);
        struct p2p_node *node = p2p_node_create(
            nm, have_sv ? sv[0] : ZCL_INVALID_SOCKET, &addr,
            "dos-unknown-cmd", true);
        DOS_CHECK("dispatch: node created", node != NULL);
        if (node) {
            /* Bypass "reject any pre-handshake message not in table"
             * (that path is its own, already-correct behaviour, not what
             * this case targets): simulate a post-handshake peer. */
            node->version = PROTOCOL_VERSION;

            /* Build a complete "bogus" command, empty payload, correct
             * checksum (SHA256d of empty payload). */
            struct msg_header hdr;
            msg_header_init_full(&hdr, magic, "bogus", 0);
            unsigned char empty_hash[32];
            hash256((const unsigned char *)"", 0, empty_hash);
            memcpy(&hdr.nChecksum, empty_hash, 4);

            bool recv_ok = p2p_node_receive_bytes(
                node, (const char *)&hdr, MSG_HEADER_SIZE, magic);
            DOS_CHECK("dispatch: unknown-cmd message queued", recv_ok);
            DOS_CHECK("dispatch: message reassembled complete",
                     node->recv_msg_count == 1 &&
                     net_message_complete(&node->recv_msgs[0]));

            bool loop_ok = msg_process_messages(mp, node);
            DOS_CHECK("dispatch: msg_process_messages completes", loop_ok);
            DOS_CHECK("dispatch: unknown cmd consumed (queue drained)",
                     node->recv_msg_count == 0);
            DOS_CHECK("dispatch: unknown cmd NOT treated as misbehaviour "
                     "(Bitcoin Core parity)",
                     atomic_load(&node->misbehavior) == 0);
            DOS_CHECK("dispatch: connection NOT dropped for unknown cmd",
                     node->disconnect == false);

            /* Honest traffic on the SAME connection afterward: a `ping`
             * must still round-trip through the real dispatch loop. */
            uint64_t nonce = 0x1122334455667788ULL;
            unsigned char nonce_le[8];
            for (int i = 0; i < 8; i++)
                nonce_le[i] = (unsigned char)(nonce >> (8 * i));
            struct msg_header ping_hdr;
            msg_header_init_full(&ping_hdr, magic, "ping", 8);
            unsigned char ping_hash[32];
            hash256(nonce_le, 8, ping_hash);
            memcpy(&ping_hdr.nChecksum, ping_hash, 4);

            unsigned char ping_buf[MSG_HEADER_SIZE + 8];
            memcpy(ping_buf, &ping_hdr, MSG_HEADER_SIZE);
            memcpy(ping_buf + MSG_HEADER_SIZE, nonce_le, 8);

            bool ping_recv_ok = p2p_node_receive_bytes(
                node, (const char *)ping_buf, sizeof(ping_buf), magic);
            DOS_CHECK("dispatch: honest ping after unknown cmd queued",
                     ping_recv_ok && node->recv_msg_count == 1);
            bool ping_loop_ok = msg_process_messages(mp, node);
            DOS_CHECK("dispatch: honest ping dispatches normally after "
                     "unknown-cmd noise",
                     ping_loop_ok && node->recv_msg_count == 0 &&
                     !node->disconnect &&
                     atomic_load(&node->misbehavior) == 0);

            p2p_node_free(node);
        }
        if (have_sv)
            platform_socket_close(sv[1]);
    }
    return failures;
}

static int dos_check_headers_replay(struct msg_processor *mp,
                                    struct main_state *ms,
                                    const struct uint256 *gh,
                                    const struct chain_params *cp)
{
    int failures = 0;
    /* ── E. duplicate/replayed `headers` batch: idempotent, no double
     *      block-tree entries, no misbehaviour for replaying old data ── */
    struct block_header h1;
    {
        struct block blk;
        block_init(&blk);
        blk.header.nVersion = 4;
        blk.header.hashPrevBlock = *gh;
        uint256_set_null(&blk.header.hashMerkleRoot);
        blk.header.hashMerkleRoot.data[0] = 1;
        uint256_set_null(&blk.header.hashFinalSaplingRoot);
        blk.header.nTime = 1700000000u;
        struct arith_uint256 pow_limit;
        uint256_to_arith(&pow_limit, &cp->consensus.powLimit);
        blk.header.nBits = arith_uint256_get_compact(&pow_limit, false);
        bool ok_mine = mine_block_pow(&blk, 1, cp, 0);
        DOS_CHECK("replay setup: regtest header mined", ok_mine);
        if (ok_mine)
            h1 = blk.header;
        block_free(&blk);

        if (ok_mine) {
            struct p2p_node node;
            dos_setup_stack_node(&node);

            struct byte_stream s1;
            stream_init(&s1, 512);
            stream_write_compact_size(&s1, 1);
            block_header_serialize(&h1, &s1);
            stream_write_compact_size(&s1, 0); /* tx count */

            size_t map_before_first = ms->map_block_index.size;
            struct msg_headers_stats st_before;
            msg_headers_get_stats(&st_before);
            bool ret1 = process_headers(mp, &node, &s1);
            struct msg_headers_stats st_after1;
            msg_headers_get_stats(&st_after1);
            DOS_CHECK("replay: first delivery accepted", ret1 == true);
            DOS_CHECK("replay: first delivery newly_added +1",
                     st_after1.newly_added == st_before.newly_added + 1);
            DOS_CHECK("replay: first delivery not misbehaviour",
                     atomic_load(&node.misbehavior) == 0 && !node.disconnect);
            stream_free(&s1);

            /* Replay: resend the EXACT same header bytes. */
            struct byte_stream s2;
            stream_init(&s2, 512);
            stream_write_compact_size(&s2, 1);
            block_header_serialize(&h1, &s2);
            stream_write_compact_size(&s2, 0);

            bool ret2 = process_headers(mp, &node, &s2);
            struct msg_headers_stats st_after2;
            msg_headers_get_stats(&st_after2);
            DOS_CHECK("replay: second (duplicate) delivery still returns ok",
                     ret2 == true);
            DOS_CHECK("replay: duplicate counted already-known, "
                     "NOT newly-added",
                     st_after2.newly_added == st_after1.newly_added &&
                     st_after2.already_known == st_after1.already_known + 1);
            DOS_CHECK("replay: no duplicate block-tree entry",
                     ms->map_block_index.size == map_before_first + 1);
            DOS_CHECK("replay: no misbehaviour for replaying old data",
                     atomic_load(&node.misbehavior) == 0 && !node.disconnect);
            stream_free(&s2);
        }
    }
    return failures;
}

static int dos_check_non_routable_addr(struct msg_processor *mp,
                                       struct net_manager *nm)
{
    int failures = 0;
    /* ── F. addr: non-routable batch -> legal envelope (under
     *      MAX_ADDR_TO_SEND, no misbehaviour); addrman_add()'s
     *      net_addr_is_routable() gate filters every entry. ── */
    {
        const struct msg_dispatch_entry *e = dos_find_entry("addr");
        DOS_CHECK("addr dispatch entry found (non-routable case)", e != NULL);
        if (e) {
            struct p2p_node node;
            dos_setup_stack_node(&node);
            size_t before = addrman_size(&nm->addrman);

            struct byte_stream s;
            stream_init(&s, 50 * 30 + 16);
            stream_write_compact_size(&s, 50); /* well under the cap */
            for (int i = 0; i < 50; i++) {
                struct net_address addr;
                net_address_init(&addr);
                /* 10.0.0.0/8 — RFC1918, never routable. */
                unsigned char ip4[4] = {10, 0,
                                        (unsigned char)(i >> 8),
                                        (unsigned char)i};
                net_addr_set_ipv4(&addr.svc.addr, ip4);
                addr.svc.port = 8033;
                net_address_serialize(&addr, &s, true);
            }
            bool ret = e->handler(mp, &node, &s);
            DOS_CHECK("non-routable addr: handler still returns true "
                     "(legal envelope)", ret == true);
            DOS_CHECK("non-routable addr: not treated as misbehaviour",
                     atomic_load(&node.misbehavior) == 0 &&
                     !node.disconnect);
            DOS_CHECK("non-routable addr: none inserted into addrman",
                     addrman_size(&nm->addrman) == before);
            stream_free(&s);
        }
    }
    return failures;
}

static int dos_check_bad_checksum_ping(struct msg_processor *mp,
                                       struct net_manager *nm)
{
    int failures = 0;
    /* ── G. framing: checksum mismatch -> dropped before dispatch, no crash.
     *      Not scored as misbehaviour (Core parity; a bad checksum does not
     *      prove malice, as with D's unknown command). Cost is bounded to
     *      one hash256 over the framing-capped payload; the connection
     *      stays open and honest traffic still dispatches. ── */
    {
        unsigned char magic[MESSAGE_START_SIZE] = {0x24, 0xe9, 0x27, 0x64};
        struct net_address addr;
        net_address_init(&addr);
        unsigned char ip4[4] = {198, 51, 100, 24};
        net_addr_set_ipv4(&addr.svc.addr, ip4);
        addr.svc.port = 8033;

        platform_socket_t sv[2];
        bool have_sv = platform_socket_pair(sv);
        DOS_CHECK("checksum: socketpair created", have_sv);
        struct p2p_node *node = p2p_node_create(
            nm, have_sv ? sv[0] : ZCL_INVALID_SOCKET, &addr,
            "dos-bad-checksum", true);
        DOS_CHECK("checksum: node created", node != NULL);
        if (node) {
            node->version = PROTOCOL_VERSION;

            /* "ping" with an 8-byte nonce payload but a deliberately wrong
             * checksum (all-zero instead of hash256(nonce)). */
            uint64_t nonce = 0xdeadbeefcafef00dULL;
            unsigned char nonce_le[8];
            for (int i = 0; i < 8; i++)
                nonce_le[i] = (unsigned char)(nonce >> (8 * i));
            struct msg_header hdr;
            msg_header_init_full(&hdr, magic, "ping", 8);
            hdr.nChecksum = 0; /* wrong on purpose */

            unsigned char buf[MSG_HEADER_SIZE + 8];
            memcpy(buf, &hdr, MSG_HEADER_SIZE);
            memcpy(buf + MSG_HEADER_SIZE, nonce_le, 8);

            bool recv_ok = p2p_node_receive_bytes(node, (const char *)buf,
                                                  sizeof(buf), magic);
            DOS_CHECK("checksum: bad-checksum message still reassembles "
                     "(framing doesn't check checksum)", recv_ok);

            bool loop_ok = msg_process_messages(mp, node);
            DOS_CHECK("checksum: msg_process_messages completes", loop_ok);
            DOS_CHECK("checksum: message dropped (queue drained, no crash)",
                     node->recv_msg_count == 0);
            DOS_CHECK("checksum: connection NOT penalized "
                     "(intentional, not a gap)",
                     atomic_load(&node->misbehavior) == 0 &&
                     !node->disconnect);

            /* Honest ping (correct checksum) on the SAME connection still
             * dispatches normally afterward. */
            struct msg_header ping_hdr;
            msg_header_init_full(&ping_hdr, magic, "ping", 8);
            unsigned char ping_hash[32];
            hash256(nonce_le, 8, ping_hash);
            memcpy(&ping_hdr.nChecksum, ping_hash, 4);

            unsigned char ping_buf[MSG_HEADER_SIZE + 8];
            memcpy(ping_buf, &ping_hdr, MSG_HEADER_SIZE);
            memcpy(ping_buf + MSG_HEADER_SIZE, nonce_le, 8);

            bool ping_recv_ok = p2p_node_receive_bytes(
                node, (const char *)ping_buf, sizeof(ping_buf), magic);
            DOS_CHECK("checksum: honest ping after bad-checksum noise "
                     "queued", ping_recv_ok && node->recv_msg_count == 1);
            bool ping_loop_ok = msg_process_messages(mp, node);
            DOS_CHECK("checksum: honest ping dispatches normally "
                     "afterward",
                     ping_loop_ok && node->recv_msg_count == 0 &&
                     !node->disconnect &&
                     atomic_load(&node->misbehavior) == 0);

            p2p_node_free(node);
        }
        if (have_sv)
            platform_socket_close(sv[1]);
    }
    return failures;
}

static int dos_check_reject_oversized_msg_type(struct msg_processor *mp)
{
    int failures = 0;
    /* ── H. reject: oversized declared msg_type length -> the fields that
     *      follow (code, reason_len, reason) are read from the correct wire
     *      offset. process_reject never surfaces its parsed fields, so this
     *      pins the read cursor's final position. ── */
    {
        const struct msg_dispatch_entry *e = dos_find_entry("reject");
        DOS_CHECK("reject dispatch entry found", e != NULL);
        if (e) {
            struct p2p_node node;
            dos_setup_stack_node(&node);

            struct byte_stream s;
            stream_init(&s, 1100);
            stream_write_compact_size(&s, 1000); /* msg_type len >= 32 */
            unsigned char filler[1000];
            /* 0xAB reads as a compact-size marker (>=253) if misparsed as a
             * length prefix, so a misparse cannot land on the offset. */
            memset(filler, 0xAB, sizeof(filler));
            stream_write_bytes(&s, filler, sizeof(filler));
            stream_write_u8(&s, 0x42); /* code */
            stream_write_compact_size(&s, 5); /* reason_len */
            stream_write_bytes(&s, (const unsigned char *)"hello", 5);

            bool ret = e->handler(mp, &node, &s);
            DOS_CHECK("reject oversized msg_type: handler returns true "
                     "(advisory, non-fatal)", ret == true);
            /* 3 (compact_size for 1000) + 1000 (skipped msg_type) +
             * 1 (code) + 1 (compact_size for 5) + 5 (reason) = 1010. */
            DOS_CHECK("reject oversized msg_type: read cursor lands "
                     "exactly past the reason field (fields aligned)",
                     s.read_pos == 1010);
            DOS_CHECK("reject oversized msg_type: entire message consumed",
                     stream_remaining(&s) == 0);
            stream_free(&s);
        }
    }
    return failures;
}

static int dos_check_reject_claimed_beyond_actual(struct msg_processor *mp)
{
    int failures = 0;
    /* ── H2. reject: declared msg_type length exceeds the actual message
     *      body ("claimed > actual") -> rejected cleanly, no misparse,
     *      no crash, no allocation proportional to the lie. ── */
    {
        const struct msg_dispatch_entry *e = dos_find_entry("reject");
        if (e) {
            struct p2p_node node;
            dos_setup_stack_node(&node);

            struct byte_stream s;
            stream_init(&s, 16);
            /* Claims a 1000-byte msg_type but delivers only 4 more bytes. */
            stream_write_compact_size(&s, 1000);
            unsigned char short_tail[4] = {0x11, 0x22, 0x33, 0x44};
            stream_write_bytes(&s, short_tail, sizeof(short_tail));

            bool ret = e->handler(mp, &node, &s);
            DOS_CHECK("reject claimed>actual: handler returns true "
                     "(advisory, non-fatal)", ret == true);
            DOS_CHECK("reject claimed>actual: not treated as misbehaviour",
                     atomic_load(&node.misbehavior) == 0 &&
                     !node.disconnect);
            stream_free(&s);
        }
    }
    return failures;
}

static int dos_check_getdata_notfound_batch(struct msg_processor *mp,
                                            struct net_manager *nm)
{
    int failures = 0;
    /* ── I. getdata: 70 unservable blocks in ONE message -> notfound
     *      covers all 70, batched (64 + 6), never silently dropped. ── */
    {
        struct net_address iaddr;
        net_address_init(&iaddr);
        unsigned char iip[4] = {203, 0, 113, 78};
        net_addr_set_ipv4(&iaddr.svc.addr, iip);
        iaddr.svc.port = 8033;

        struct p2p_node *node = p2p_node_create(nm, ZCL_INVALID_SOCKET,
                                                &iaddr, "notfound-batch", true);
        DOS_CHECK("getdata 70-miss: node created", node != NULL);
        if (node) {
            enum { NOTFOUND_TEST_COUNT = 70 };
            struct byte_stream s;
            stream_init(&s, NOTFOUND_TEST_COUNT * 36 + 8);
            stream_write_compact_size(&s, NOTFOUND_TEST_COUNT);
            for (int i = 0; i < NOTFOUND_TEST_COUNT; i++) {
                struct uint256 fake_hash;
                memset(fake_hash.data, 0, sizeof(fake_hash.data));
                /* Distinct, all-unknown-to-block_map hashes. */
                fake_hash.data[0] = (uint8_t)(i & 0xff);
                fake_hash.data[1] = (uint8_t)((i >> 8) & 0xff);
                struct inv_item inv;
                inv_item_init_typed(&inv, MSG_BLOCK, &fake_hash);
                inv_item_serialize(&inv, &s);
            }

            bool ret = process_getdata(mp, node, &s);
            DOS_CHECK("getdata 70-miss: handler returns true", ret == true);

            /* Sum the item count declared in each queued notfound payload
             * (skip the wire header, read the compact-size count). */
            size_t total_notfound_items = 0;
            size_t segment_count = 0;
            for (struct send_segment *seg = node->send_head; seg;
                seg = seg->next) {
                segment_count++;
                DOS_CHECK("getdata 70-miss: segment longer than header",
                         seg->size > MSG_HEADER_SIZE);
                struct byte_stream payload;
                stream_init_from_data(&payload, seg->data + MSG_HEADER_SIZE,
                                      seg->size - MSG_HEADER_SIZE);
                uint64_t item_count = 0;
                bool got_count = stream_read_compact_size(&payload, &item_count);
                DOS_CHECK("getdata 70-miss: segment count field readable",
                         got_count);
                total_notfound_items += item_count;
                stream_free(&payload);
            }
            DOS_CHECK("getdata 70-miss: batched into more than one notfound "
                     "message (64-item batch cap actually exercised)",
                     segment_count >= 2);
            DOS_CHECK("getdata 70-miss: all 70 misses replied, none dropped",
                     total_notfound_items == NOTFOUND_TEST_COUNT);

            stream_free(&s);
            p2p_node_free(node);
        }
    }
    return failures;
}

static int dos_check_zmsg_accepted(struct msg_processor *mp,
                                   struct p2p_node *node,
                                   const struct msg_dispatch_entry *zmsg,
                                   struct zmsg_message *msg)
{
    int failures = 0;
    struct byte_stream first;
    stream_init(&first, 256);
    bool wrote_first = zmsg_serialize(msg, &first);
    bool handled_first = wrote_first &&
        zmsg->handler(mp, node, &first);
    struct msg_zmsg_stats stats;
    msg_processor_get_zmsg_stats(mp, &stats);
    DOS_CHECK("zmsg telemetry: accepted frame counted",
              handled_first && stats.frames_received == 1 &&
              stats.messages_accepted == 1 &&
              stats.duplicates == 0 &&
              stats.last_received_unix > 0);
    stream_free(&first);
    return failures;
}

static int dos_check_zmsg_duplicate(struct msg_processor *mp,
                                    struct p2p_node *node,
                                    const struct msg_dispatch_entry *zmsg,
                                    struct zmsg_message *msg)
{
    int failures = 0;
    struct msg_zmsg_stats stats;
    struct byte_stream duplicate;
    stream_init(&duplicate, 256);
    bool wrote_duplicate = zmsg_serialize(msg, &duplicate);
    bool handled_duplicate = wrote_duplicate &&
        zmsg->handler(mp, node, &duplicate);
    msg_processor_get_zmsg_stats(mp, &stats);
    DOS_CHECK("zmsg telemetry: duplicate frame separated",
              handled_duplicate && stats.frames_received == 2 &&
              stats.messages_accepted == 1 &&
              stats.duplicates == 1);
    stream_free(&duplicate);
    return failures;
}

static int dos_check_zmsg_ack(struct msg_processor *mp,
                              struct p2p_node *node,
                              const struct msg_dispatch_entry *zmsgack,
                              struct zmsg_message *msg)
{
    int failures = 0;
    struct msg_zmsg_stats stats;
    struct byte_stream ack;
    stream_init(&ack, 32);
    bool wrote_ack = stream_write(&ack, msg->msg_id,
                                   sizeof(msg->msg_id));
    bool handled_ack = wrote_ack &&
        zmsgack->handler(mp, node, &ack);
    msg_processor_get_zmsg_stats(mp, &stats);
    DOS_CHECK("zmsg telemetry: acknowledgement counted",
              handled_ack &&
              stats.acknowledgements_received == 1 &&
              stats.last_ack_unix > 0);
    stream_free(&ack);
    return failures;
}

static int dos_check_zmsg_telemetry(struct msg_processor *mp,
                                    struct net_manager *nm)
{
    int failures = 0;
    /* ── J. zmsg: transport counters distinguish accepted/duplicate/ACK. ── */
    {
        const struct msg_dispatch_entry *zmsg = dos_find_entry("zmsg");
        const struct msg_dispatch_entry *zmsgack = dos_find_entry("zmsgack");
        DOS_CHECK("zmsg telemetry: dispatch entries found",
                  zmsg != NULL && zmsgack != NULL);
        if (zmsg && zmsgack) {
            struct net_address zaddr;
            net_address_init(&zaddr);
            unsigned char zip[4] = {203, 0, 113, 79};
            net_addr_set_ipv4(&zaddr.svc.addr, zip);
            zaddr.svc.port = 8033;
            struct p2p_node *node = p2p_node_create(
                nm, ZCL_INVALID_SOCKET, &zaddr, "zmsg-telemetry", true);
            DOS_CHECK("zmsg telemetry: node created", node != NULL);
            if (node) {
                struct zmsg_message msg;
                memset(&msg, 0, sizeof(msg));
                msg.timestamp = 1787463600;
                snprintf(msg.sender, sizeof(msg.sender), "%s", "peer-agent");
                snprintf(msg.recipient, sizeof(msg.recipient), "%s", "self");
                snprintf(msg.body, sizeof(msg.body), "%s",
                         "telemetry-correlation-probe");
                zmsg_compute_id(&msg, msg.msg_id);

                failures += dos_check_zmsg_accepted(mp, node, zmsg, &msg);
                failures += dos_check_zmsg_duplicate(mp, node, zmsg, &msg);
                failures += dos_check_zmsg_ack(mp, node, zmsgack, &msg);
                p2p_node_free(node);
            }
        }
    }
    return failures;
}

static int dos_check_trickle_clamp(struct msg_processor *mp,
                                   struct net_manager *nm)
{
    int failures = 0;
    /* ── K. trickle inv: a queue longer than one frame emits a wire-capped
     *      inv (<= MAX_INV_SZ items) and retains the remainder for the next
     *      tick (msgprocessor.c::msg_send_messages clamp + memmove). ── */
    {
        struct net_address kaddr;
        net_address_init(&kaddr);
        unsigned char kip[4] = {203, 0, 113, 80};
        net_addr_set_ipv4(&kaddr.svc.addr, kip);
        kaddr.svc.port = 8033;
        struct p2p_node *node = p2p_node_create(
            nm, ZCL_INVALID_SOCKET, &kaddr, "trickle-clamp", true);
        DOS_CHECK("trickle clamp: node created", node != NULL);
        if (node) {
            /* Post-handshake so msg_send_messages runs its full body. */
            node->state = PEER_HANDSHAKE_COMPLETE;
            node->version = PROTOCOL_VERSION;

            for (size_t i = 0; i < MAX_INV_SZ + 1; i++) {
                struct uint256 h;
                memset(h.data, 0, sizeof(h.data));
                memcpy(h.data, &i, sizeof(i)); /* distinct, unknown-to-map */
                h.data[31] = 0x7a;
                struct inv_item inv;
                inv_item_init_typed(&inv, MSG_BLOCK, &h);
                p2p_node_push_inventory(node, &inv);
            }
            DOS_CHECK("trickle clamp: queue holds MAX_INV_SZ+1",
                      node->inventory_to_send_count == MAX_INV_SZ + 1);

            bool ok = msg_send_messages(mp, node, true);
            DOS_CHECK("trickle clamp: first tick succeeds", ok == true);

            /* Sum declared item counts across every inv frame queued this
             * tick (command-filtered; other frames may be queued too). */
            size_t inv_frames = 0, items_sent = 0;
            for (struct send_segment *seg = node->send_head; seg;
                seg = seg->next) {
                if (seg->size <= MSG_HEADER_SIZE)
                    continue;
                const struct msg_header *hdr =
                    (const struct msg_header *)(const void *)seg->data;
                if (strcmp(hdr->pchCommand, "inv") != 0)
                    continue;
                struct byte_stream payload;
                stream_init_from_data(&payload, seg->data + MSG_HEADER_SIZE,
                                      seg->size - MSG_HEADER_SIZE);
                uint64_t n = 0;
                if (stream_read_compact_size(&payload, &n)) {
                    items_sent += n;
                    inv_frames++;
                }
                stream_free(&payload);
            }
            DOS_CHECK("trickle clamp: exactly one inv frame emitted",
                      inv_frames == 1);
            DOS_CHECK("trickle clamp: frame capped at MAX_INV_SZ items",
                      items_sent == MAX_INV_SZ);
            DOS_CHECK("trickle clamp: remainder retained for next tick",
                      node->inventory_to_send_count == 1);

            struct send_segment *first_tick_tail = node->send_tail;
            ok = msg_send_messages(mp, node, true);
            DOS_CHECK("trickle clamp: second tick drains remainder",
                      ok && node->inventory_to_send_count == 0);
            size_t second_items = 0;
            size_t second_frames = 0;
            for (struct send_segment *seg = first_tick_tail
                    ? first_tick_tail->next : node->send_head;
                 seg; seg = seg->next) {
                if (seg->size <= MSG_HEADER_SIZE)
                    continue;
                const struct msg_header *hdr =
                    (const struct msg_header *)(const void *)seg->data;
                if (strcmp(hdr->pchCommand, "inv") != 0)
                    continue;
                struct byte_stream payload;
                stream_init_from_data(&payload, seg->data + MSG_HEADER_SIZE,
                                      seg->size - MSG_HEADER_SIZE);
                uint64_t n = 0;
                if (stream_read_compact_size(&payload, &n)) {
                    second_items += n;
                    second_frames++;
                }
                stream_free(&payload);
            }
            DOS_CHECK("trickle clamp: second frame carries retained item",
                      second_frames == 1 && second_items == 1);

            p2p_node_free(node);
        }
    }
    return failures;
}

int test_net_msg_dos(void);
int test_net_msg_dos(void)
{
    int failures = 0;
    printf("\n=== net_msg_dos adversarial tests ===\n");

    chain_params_select(CHAIN_REGTEST);
    const struct chain_params *cp = chain_params_get();
    peer_scoring_init();
    enum sync_state sync0 = sync_get_state();

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "net_msg_dos", "main");
    SetDataDir(dir);

    struct main_state ms;
    main_state_init(&ms);
    struct uint256 gh = cp->consensus.hashGenesisBlock;
    struct block_index *gen =
        chainstate_insert_block_index((struct chainstate *)&ms, &gh);
    DOS_CHECK("genesis block_index inserted", gen != NULL);
    if (gen) {
        gen->nHeight = 0;
        gen->nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
        gen->nTx = 1;
        gen->nChainTx = 1;
        active_chain_move_window_tip(&ms.chain_active, gen);
        ms.pindex_best_header = gen;
    }

    struct net_manager nm;
    net_manager_init(&nm);

    struct msg_processor mp;
    msg_processor_init(&mp, &ms, NULL, NULL, cp, dir, &nm, NULL);

    failures += dos_check_inv_oversized_count(&mp);
    failures += dos_check_getdata_oversized_count(&mp);
    failures += dos_check_getblocks_pre_handshake(&mp, &gh, cp);
    failures += dos_check_addr_oversized_count(&mp);
    failures += dos_check_notfound_oversized_count(&mp);
    failures += dos_check_addr_rate_limit(&mp);
    failures += dos_check_inv_truncated(&mp);
    failures += dos_check_getdata_truncated(&mp);
    failures += dos_check_oversize_framing();
    failures += dos_check_unknown_cmd_dispatch(&mp, &nm);
    failures += dos_check_headers_replay(&mp, &ms, &gh, cp);
    failures += dos_check_non_routable_addr(&mp, &nm);
    failures += dos_check_bad_checksum_ping(&mp, &nm);
    failures += dos_check_reject_oversized_msg_type(&mp);
    failures += dos_check_reject_claimed_beyond_actual(&mp);
    failures += dos_check_getdata_notfound_batch(&mp, &nm);
    failures += dos_check_zmsg_telemetry(&mp, &nm);
    failures += dos_check_trickle_clamp(&mp, &nm);

    net_manager_free(&nm);
    sync_set_state(sync0, "net_msg_dos restore");
    main_state_free(&ms);
    SetDataDir("");
    ClearDataDirCache();
    test_rm_rf(dir);
    chain_params_select(CHAIN_MAIN);

    printf("net_msg_dos adversarial tests: %s\n",
           failures ? "FAILED" : "PASSED");
    return failures;
}

/* ── net_framing_dos ──────────────────────────────────────────────────
 * Framing (net_message_read_header / read_data and the
 * p2p_node_receive_bytes reassembler) sees hostile bytes before dispatch.
 * It has no net_manager back-pointer, so it tags node->framing_offence and
 * the connman receive caller drains and scores it once via
 * p2p_node_score_framing_offence(). These cases pin that tag->drain->score
 * contract (bad start-magic, oversize headers, oversize payloads) plus the
 * handshake violations scored in msg_version.c. */
int test_net_framing_dos(void);
int test_net_framing_dos(void)
{
    int failures = 0;
    printf("\n=== net_framing_dos framing + handshake DoS scoring ===\n");

    chain_params_select(CHAIN_REGTEST);
    const struct chain_params *cp = chain_params_get();
    peer_scoring_init();
    enum sync_state sync0 = sync_get_state();

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "net_framing_dos", "main");
    SetDataDir(dir);

    struct main_state ms;
    main_state_init(&ms);

    struct net_manager nm;
    net_manager_init(&nm);

    struct msg_processor mp;
    msg_processor_init(&mp, &ms, NULL, NULL, cp, dir, &nm, NULL);

    /* Canonical regtest start-magic (matches dos_setup section C). */
    unsigned char magic[MESSAGE_START_SIZE] = {0x24, 0xe9, 0x27, 0x64};

    /* Build a routable, non-localhost peer address: localhost/whitelisted
     * peers are exempt from scoring via is_trusted_peer(), so the score would
     * never move for a 127.x node. */
    struct net_address paddr;
    net_address_init(&paddr);
    unsigned char ip4[4] = {203, 0, 113, 91};
    net_addr_set_ipv4(&paddr.svc.addr, ip4);
    paddr.svc.port = 8033;

    /* ── a) bad start-magic: header-phase offence => INVALID_HEADER (50) ── */
    {
        struct p2p_node *node = p2p_node_create(&nm, ZCL_INVALID_SOCKET,
                                                &paddr, "framing-badmagic",
                                                true);
        DOS_CHECK("badmagic: node created", node != NULL);
        if (node) {
            unsigned char wrong[MESSAGE_START_SIZE] = {0xde, 0xad, 0xbe, 0xef};
            struct msg_header hdr;
            msg_header_init_full(&hdr, wrong, "ping", 0);
            bool ok = p2p_node_receive_bytes(node, (const char *)&hdr,
                                             MSG_HEADER_SIZE, magic);
            DOS_CHECK("badmagic: frame rejected (returns false)", ok == false);
            DOS_CHECK("badmagic: framing_offence tagged INVALID_HEADER",
                     atomic_load(&node->framing_offence) ==
                         (int)PEER_OFFENCE_INVALID_HEADER);
            p2p_node_score_framing_offence(&nm, node);
            DOS_CHECK("badmagic: peer scored +50 (INVALID_HEADER)",
                     atomic_load(&node->misbehavior) == 50);
            DOS_CHECK("badmagic: tag drained to none after scoring",
                     atomic_load(&node->framing_offence) ==
                         (int)PEER_OFFENCE_NONE);
            p2p_node_free(node);
        }
    }

    /* ── b) oversize header (nMessageSize > MAX_SIZE) => INVALID_HEADER (50)  */
    {
        struct p2p_node *node = p2p_node_create(&nm, ZCL_INVALID_SOCKET,
                                                &paddr, "framing-oversize-hdr",
                                                true);
        DOS_CHECK("oversize-hdr: node created", node != NULL);
        if (node) {
            struct msg_header hdr;
            /* One byte over the 32 MiB header ceiling: rejected in
             * net_message_read_header before in_data is set. */
            msg_header_init_full(&hdr, magic, "block", (uint32_t)MAX_SIZE + 1u);
            bool ok = p2p_node_receive_bytes(node, (const char *)&hdr,
                                             MSG_HEADER_SIZE, magic);
            DOS_CHECK("oversize-hdr: frame rejected", ok == false);
            DOS_CHECK("oversize-hdr: tagged INVALID_HEADER",
                     atomic_load(&node->framing_offence) ==
                         (int)PEER_OFFENCE_INVALID_HEADER);
            p2p_node_score_framing_offence(&nm, node);
            DOS_CHECK("oversize-hdr: peer scored +50 (INVALID_HEADER)",
                     atomic_load(&node->misbehavior) == 50);
            p2p_node_free(node);
        }
    }

    /* ── c) oversize payload (2 MiB < size < MAX_SIZE) => INVALID_PAYLOAD (20) */
    {
        struct p2p_node *node = p2p_node_create(&nm, ZCL_INVALID_SOCKET,
                                                &paddr, "framing-oversize-pay",
                                                true);
        DOS_CHECK("oversize-pay: node created", node != NULL);
        if (node) {
            struct msg_header hdr;
            /* 3 MiB: passes the header ceiling but trips the data-phase
             * MAX_PROTOCOL_MESSAGE_LENGTH (2 MiB) check in read_data. */
            msg_header_init_full(&hdr, magic, "block", 3u * 1024 * 1024);
            unsigned char buf[MSG_HEADER_SIZE + 4];
            memcpy(buf, &hdr, MSG_HEADER_SIZE);
            memset(buf + MSG_HEADER_SIZE, 0x11, 4);
            bool ok = p2p_node_receive_bytes(node, (const char *)buf,
                                             sizeof(buf), magic);
            DOS_CHECK("oversize-pay: frame rejected", ok == false);
            DOS_CHECK("oversize-pay: tagged INVALID_PAYLOAD",
                     atomic_load(&node->framing_offence) ==
                         (int)PEER_OFFENCE_INVALID_PAYLOAD);
            p2p_node_score_framing_offence(&nm, node);
            DOS_CHECK("oversize-pay: peer scored +20 (INVALID_PAYLOAD)",
                     atomic_load(&node->misbehavior) == 20);
            p2p_node_free(node);
        }
    }

    /* ── d) duplicate/replayed version => PROTOCOL_VIOLATION (100) => ban ── */
    {
        struct p2p_node node;
        dos_setup_stack_node(&node);
        node.version = PROTOCOL_VERSION; /* nonzero => this is a duplicate */
        struct byte_stream s;
        stream_init(&s, 8); /* body is never read: duplicate check is first */
        bool ok = process_version(&mp, &node, &s);
        DOS_CHECK("dupversion: handler returns false", ok == false);
        DOS_CHECK("dupversion: scored +100 (PROTOCOL_VIOLATION)",
                 atomic_load(&node.misbehavior) == 100);
        DOS_CHECK("dupversion: crosses ban threshold (should_ban)",
                 peer_scoring_should_ban(&node));
        stream_free(&s);
    }

    /* ── e) repeated framing abuse on ONE connection crosses the ban
     *      threshold: two bad-magic frames (50 + 50) => should_ban ── */
    {
        struct net_address baddr;
        net_address_init(&baddr);
        unsigned char bip[4] = {203, 0, 113, 92};
        net_addr_set_ipv4(&baddr.svc.addr, bip);
        baddr.svc.port = 8033;

        struct p2p_node *node = p2p_node_create(&nm, ZCL_INVALID_SOCKET,
                                                &baddr, "framing-ban", true);
        DOS_CHECK("ban-accrual: node created", node != NULL);
        if (node) {
            unsigned char wrong[MESSAGE_START_SIZE] = {0xde, 0xad, 0xbe, 0xef};
            struct msg_header hdr;
            msg_header_init_full(&hdr, wrong, "ping", 0);

            (void)p2p_node_receive_bytes(node, (const char *)&hdr,
                                         MSG_HEADER_SIZE, magic);
            p2p_node_score_framing_offence(&nm, node);
            DOS_CHECK("ban-accrual: after 1 offence score=50, not yet bannable",
                     atomic_load(&node->misbehavior) == 50 &&
                     !peer_scoring_should_ban(node));

            (void)p2p_node_receive_bytes(node, (const char *)&hdr,
                                         MSG_HEADER_SIZE, magic);
            p2p_node_score_framing_offence(&nm, node);
            DOS_CHECK("ban-accrual: after 2 offences score=100, should_ban",
                     atomic_load(&node->misbehavior) == 100 &&
                     peer_scoring_should_ban(node));
            p2p_node_free(node);
        }
    }

    net_manager_free(&nm);
    sync_set_state(sync0, "net_framing_dos restore");
    main_state_free(&ms);
    SetDataDir("");
    ClearDataDirCache();
    test_rm_rf(dir);
    chain_params_select(CHAIN_MAIN);

    printf("net_framing_dos framing + handshake DoS scoring: %s\n",
           failures ? "FAILED" : "PASSED");
    return failures;
}
