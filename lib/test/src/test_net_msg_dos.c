/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Adversarial/DoS coverage for the P2P message-handling path. A hostile
 * peer fully controls the wire bytes; these cases pin the bounded-and-safe
 * contract of the handlers that see them FIRST — before any consensus or
 * business logic runs:
 *
 *   A. Oversized declared counts (inv/getdata/addr/notfound) — the classic
 *      "claim 10M items, send 3 bytes" allocation-bomb shape. Each of
 *      these handlers reads a compact-size element count and must reject
 *      it BEFORE looping/allocating once it exceeds the protocol cap
 *      (MAX_INV_SZ / MAX_ADDR_TO_SEND) — no huge alloc, no unbounded loop,
 *      peer disconnected AND scored via PEER_OFFENCE_FLOOD so the same
 *      peer address still accrues toward the ban threshold across
 *      reconnects (this file's fix: msg_tx.c/msg_blocks.c/
 *      msgprocessor_inv.c previously disconnected without scoring — see
 *      case A which pins the now-added peer_scoring_record calls).
 *   B. Truncated/short payloads (inv/getdata declare N items, deliver
 *      fewer bytes than N requires) — clean failure, no partial mutation.
 *   C. A message whose declared size exceeds MAX_PROTOCOL_MESSAGE_LENGTH
 *      at the framing layer (net_message_read_data) — rejected BEFORE any
 *      allocation against the process-wide recv budget.
 *   D. An unknown/garbage command string through the real dispatch loop
 *      (msg_process_messages) — silently ignored (Bitcoin Core parity:
 *      unknown commands are not misbehaviour), connection untouched, and
 *      a subsequent honest `ping` on the SAME connection still dispatches
 *      normally afterward.
 *   E. A duplicate/replayed `headers` batch — the second delivery of
 *      identical bytes is idempotent: accepted again (not an error) but
 *      counted as already-known (not newly-added), no duplicate block-tree
 *      entries, and no misbehaviour score for replaying old data.
 *   F. A legal-sized `addr` batch entirely of non-routable (RFC1918)
 *      addresses — accepted at the envelope level (under the cap, so no
 *      misbehaviour) but every entry is silently filtered by addrman's own
 *      net_addr_is_routable() gate; none are ever inserted.
 *   G. A `ping` with a deliberately wrong checksum — dropped before
 *      dispatch (bounded cost: one hash256 over the capped payload),
 *      connection NOT penalized. Pins the intentional Bitcoin-Core-parity
 *      choice (same reasoning as case D) rather than leaving it
 *      undocumented/untested.
 *   H. A `reject` message with a declared msg_type length that exceeds
 *      the fixed local buffer — pins that the fields after it (code,
 *      reason_len, reason) are read from the correct wire offset (a
 *      real fix: the old code silently skipped storing the oversized
 *      string but forgot to advance the read cursor past it, misaligning
 *      every field that followed). H2 covers the same field but with a
 *      declared length that exceeds the actual remaining message bytes
 *      ("claimed > actual").
 *   I. getdata requesting more unservable blocks than the notfound
 *      reply-batch size (64) in one message -> every one of them still
 *      gets a notfound reply, split across multiple notfound messages.
 *      Before the fix, process_getdata's not_found accumulator was a
 *      fixed 64-slot array that silently stopped recording past the
 *      64th miss — a legal single getdata (up to MAX_INV_SZ=50000 items)
 *      requesting a longer unservable span got no reply at all for the
 *      items past the 64th, so the requester's download manager sat out
 *      its full per-block timeout instead of the prompt notfound-driven
 *      requeue (net/download.h::dl_mark_notfound).
 *   J. ZMSG transport telemetry — accepted, duplicate, and acknowledgment
 *      frames increment distinct monotone counters and retain last-event
 *      timestamps, so an operator can tell delivery from an inbox echo.
 *
 * Sections A/B/E/F/H/H2 use a stack p2p_node + memset (mirrors
 * test_process_headers_adversarial.c) since the code paths under test
 * return before touching any node mutex. Sections C/D/G/I touch
 * mutex-guarded node/dispatch machinery, and J queues ACK frames; these use
 * a heap node from
 * p2p_node_create (properly mutex-initialized). */

#include "test/test_core.h"
#include "util/util.h"

#include "mining/miner.h"
#include "net/msg_internal.h"
#include "net/msgprocessor.h"
#include "net/peer_scoring.h"
#include "net/version.h"
#include "net/zmsg.h"
#include "core/hash.h"
#include "validation/chainstate.h"
#include "validation/process_block.h"  /* accept_block_header */

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DOS_CHECK(name, expr) do { \
    printf("net_msg_dos: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Non-localhost/non-whitelisted peer so peer_misbehaving() actually
 * scores it (is_trusted_peer() in net.c exempts 127.0.0.0/8 + whitelisted
 * peers from all scoring — using that address would make every
 * misbehavior assertion below vacuously true). */
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

    /* ── A1. inv: oversized count -> reject + disconnect + scored ── */
    {
        struct p2p_node node;
        dos_setup_stack_node(&node);
        struct byte_stream s;
        stream_init(&s, 32);
        stream_write_compact_size(&s, 50001); /* MAX_INV_SZ (50000) + 1 */
        /* Tiny payload: the classic "claim 10M items, send 3 bytes" shape.
         * A vulnerable handler would loop/allocate against the DECLARED
         * count; the guard must fire before touching a single inv item. */
        bool ret = process_inv(&mp, &node, &s);
        DOS_CHECK("inv oversized: handler returns false", ret == false);
        DOS_CHECK("inv oversized: peer disconnected", node.disconnect == true);
        DOS_CHECK("inv oversized: peer scored PEER_OFFENCE_FLOOD (20)",
                 atomic_load(&node.misbehavior) == 20);
        stream_free(&s);
    }

    /* ── A2. getdata: oversized count -> reject + disconnect + scored ── */
    {
        struct p2p_node node;
        dos_setup_stack_node(&node);
        struct byte_stream s;
        stream_init(&s, 32);
        stream_write_compact_size(&s, 50001);
        bool ret = process_getdata(&mp, &node, &s);
        DOS_CHECK("getdata oversized: handler returns false", ret == false);
        DOS_CHECK("getdata oversized: peer disconnected",
                 node.disconnect == true);
        DOS_CHECK("getdata oversized: peer scored PEER_OFFENCE_FLOOD (20)",
                 atomic_load(&node.misbehavior) == 20);
        stream_free(&s);
    }

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
            bool ret = e->handler(&mp, &node, &s);
            DOS_CHECK("addr oversized: handler returns false", ret == false);
            DOS_CHECK("addr oversized: peer disconnected",
                     node.disconnect == true);
            DOS_CHECK("addr oversized: peer scored PEER_OFFENCE_FLOOD (20)",
                     atomic_load(&node.misbehavior) == 20);
            stream_free(&s);
        }
    }

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
            bool ret = e->handler(&mp, &node, &s);
            DOS_CHECK("notfound oversized: handler returns false",
                     ret == false);
            DOS_CHECK("notfound oversized: peer disconnected",
                     node.disconnect == true);
            DOS_CHECK("notfound oversized: peer scored PEER_OFFENCE_FLOOD (20)",
                     atomic_load(&node.misbehavior) == 20);
            stream_free(&s);
        }
    }

    /* ── A5. addr: repeated max-legal-size batches -> rate limited ──
     * A single addr message under MAX_ADDR_TO_SEND (1000) is legal and
     * free of any per-message penalty (see A3 for the oversized-count
     * case). Nothing previously stopped a peer from repeating
     * max-legal-size batches back-to-back forever though — this pins
     * the ADDR_RATE_WINDOW_SECS/ADDR_RATE_MAX_PER_WINDOW fixed-window
     * limiter in msgprocessor_inv.c::process_addr(): the first three
     * 1000-entry batches (3000 total, AT the cap) are free; the fourth
     * (4000 total) crosses ADDR_RATE_MAX_PER_WINDOW and scores +
     * disconnects, same as any other flood category. */
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
                bool ret = e->handler(&mp, &node, &s);
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
        bool ret = process_inv(&mp, &node, &s);
        DOS_CHECK("inv truncated: handler returns false", ret == false);
        stream_free(&s);
    }

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
        bool ret = process_getdata(&mp, &node, &s);
        DOS_CHECK("getdata truncated: handler returns false", ret == false);
        stream_free(&s);
    }

    /* ── C. framing layer: declared size > MAX_PROTOCOL_MESSAGE_LENGTH
     *      is rejected BEFORE any allocation against the recv budget ── */
    {
        unsigned char magic[MESSAGE_START_SIZE] = {0x24, 0xe9, 0x27, 0x64};
        size_t base = net_recv_total_bytes();

        struct net_message m;
        net_message_init(&m, magic);
        struct msg_header hdr;
        /* 3 MiB: above MAX_PROTOCOL_MESSAGE_LENGTH (2 MiB) but below the
         * header-level MAX_SIZE (32 MiB) ceiling, so it reaches the
         * data-phase check inside net_message_read_data. */
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

        /* A real connected socketpair (not ZCL_INVALID_SOCKET): the
         * dispatched `ping` handler replies with a `pong`, which drives a
         * genuine send() — on an invalid fd that send() would fail and
         * socket_send_data() would legitimately close the connection,
         * which would make the "connection intact" assertion below a
         * false negative rather than a real signal. */
        int sv[2];
        bool have_sv = socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0;
        DOS_CHECK("dispatch: socketpair created", have_sv);
        struct p2p_node *node = p2p_node_create(
            &nm, have_sv ? sv[0] : ZCL_INVALID_SOCKET, &addr,
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

            bool loop_ok = msg_process_messages(&mp, node);
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
            bool ping_loop_ok = msg_process_messages(&mp, node);
            DOS_CHECK("dispatch: honest ping dispatches normally after "
                     "unknown-cmd noise",
                     ping_loop_ok && node->recv_msg_count == 0 &&
                     !node->disconnect &&
                     atomic_load(&node->misbehavior) == 0);

            p2p_node_free(node);
        }
        if (have_sv)
            close(sv[1]);
    }

    /* ── E. duplicate/replayed `headers` batch: idempotent, no double
     *      block-tree entries, no misbehaviour for replaying old data ── */
    struct block_header h1;
    {
        struct block blk;
        block_init(&blk);
        blk.header.nVersion = 4;
        blk.header.hashPrevBlock = gh;
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

            size_t map_before_first = ms.map_block_index.size;
            struct msg_headers_stats st_before;
            msg_headers_get_stats(&st_before);
            bool ret1 = process_headers(&mp, &node, &s1);
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

            bool ret2 = process_headers(&mp, &node, &s2);
            struct msg_headers_stats st_after2;
            msg_headers_get_stats(&st_after2);
            DOS_CHECK("replay: second (duplicate) delivery still returns ok",
                     ret2 == true);
            DOS_CHECK("replay: duplicate counted already-known, "
                     "NOT newly-added",
                     st_after2.newly_added == st_after1.newly_added &&
                     st_after2.already_known == st_after1.already_known + 1);
            DOS_CHECK("replay: no duplicate block-tree entry",
                     ms.map_block_index.size == map_before_first + 1);
            DOS_CHECK("replay: no misbehaviour for replaying old data",
                     atomic_load(&node.misbehavior) == 0 && !node.disconnect);
            stream_free(&s2);
        }
    }

    /* ── F. addr: batch of non-routable addresses -> legal envelope
     *      (under MAX_ADDR_TO_SEND, no misbehaviour), but every entry is
     *      silently filtered by addrman_add()'s net_addr_is_routable()
     *      gate — none are ever inserted. A flood of RFC1918/loopback
     *      junk cannot grow addrman or otherwise cost more than the
     *      per-entry deserialize itself. ── */
    {
        const struct msg_dispatch_entry *e = dos_find_entry("addr");
        DOS_CHECK("addr dispatch entry found (non-routable case)", e != NULL);
        if (e) {
            struct p2p_node node;
            dos_setup_stack_node(&node);
            size_t before = addrman_size(&nm.addrman);

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
            bool ret = e->handler(&mp, &node, &s);
            DOS_CHECK("non-routable addr: handler still returns true "
                     "(legal envelope)", ret == true);
            DOS_CHECK("non-routable addr: not treated as misbehaviour",
                     atomic_load(&node.misbehavior) == 0 &&
                     !node.disconnect);
            DOS_CHECK("non-routable addr: none inserted into addrman",
                     addrman_size(&nm.addrman) == before);
            stream_free(&s);
        }
    }

    /* ── G. framing: checksum mismatch -> message dropped BEFORE dispatch,
     *      no crash, no allocation growth. Pins the intentional (Bitcoin
     *      Core parity) choice not to score a checksum failure as
     *      misbehaviour: unlike a bad start-magic or an oversized
     *      declared size, a bad checksum alone does not prove the sender
     *      is malicious rather than corrupt/buggy — same reasoning as
     *      case D's "unknown command is not misbehaviour". The cost is
     *      still bounded: one hash256 over the (already framing-capped)
     *      payload, no allocation beyond the message's own capped
     *      recv_alloc. Connection stays open and honest traffic
     *      afterward on the SAME connection still dispatches. ── */
    {
        unsigned char magic[MESSAGE_START_SIZE] = {0x24, 0xe9, 0x27, 0x64};
        struct net_address addr;
        net_address_init(&addr);
        unsigned char ip4[4] = {198, 51, 100, 24};
        net_addr_set_ipv4(&addr.svc.addr, ip4);
        addr.svc.port = 8033;

        int sv[2];
        bool have_sv = socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0;
        DOS_CHECK("checksum: socketpair created", have_sv);
        struct p2p_node *node = p2p_node_create(
            &nm, have_sv ? sv[0] : ZCL_INVALID_SOCKET, &addr,
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

            bool loop_ok = msg_process_messages(&mp, node);
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
            bool ping_loop_ok = msg_process_messages(&mp, node);
            DOS_CHECK("checksum: honest ping dispatches normally "
                     "afterward",
                     ping_loop_ok && node->recv_msg_count == 0 &&
                     !node->disconnect &&
                     atomic_load(&node->misbehavior) == 0);

            p2p_node_free(node);
        }
        if (have_sv)
            close(sv[1]);
    }

    /* ── H. reject: oversized declared msg_type length -> the fields that
     *      follow (code, reason_len, reason) are read from the CORRECT
     *      wire offset. Before the fix, an oversized msg_type length was
     *      silently skipped WITHOUT advancing the read cursor, so `code`
     *      and `reason` were parsed from the tail of msg_type's own bytes
     *      instead of their real position — a misparse, not just a
     *      truncation. process_reject never surfaces its parsed fields
     *      (advisory-only, printf'd), so this pins the fix via the read
     *      cursor's final position instead. ── */
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
            /* 0xAB decodes as a compact-size marker (>=253) if misread as
             * a length prefix, so an old-code misparse would NOT land on
             * the expected offset by coincidence. */
            memset(filler, 0xAB, sizeof(filler));
            stream_write_bytes(&s, filler, sizeof(filler));
            stream_write_u8(&s, 0x42); /* code */
            stream_write_compact_size(&s, 5); /* reason_len */
            stream_write_bytes(&s, (const unsigned char *)"hello", 5);

            bool ret = e->handler(&mp, &node, &s);
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

            bool ret = e->handler(&mp, &node, &s);
            DOS_CHECK("reject claimed>actual: handler returns true "
                     "(advisory, non-fatal)", ret == true);
            DOS_CHECK("reject claimed>actual: not treated as misbehaviour",
                     atomic_load(&node.misbehavior) == 0 &&
                     !node.disconnect);
            stream_free(&s);
        }
    }

    /* ── I. getdata: 70 unservable blocks in ONE message -> notfound
     *      covers all 70, batched (64 + 6), never silently dropped. ── */
    {
        struct net_address iaddr;
        net_address_init(&iaddr);
        unsigned char iip[4] = {203, 0, 113, 78};
        net_addr_set_ipv4(&iaddr.svc.addr, iip);
        iaddr.svc.port = 8033;

        struct p2p_node *node = p2p_node_create(&nm, ZCL_INVALID_SOCKET,
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

            bool ret = process_getdata(&mp, node, &s);
            DOS_CHECK("getdata 70-miss: handler returns true", ret == true);

            /* Walk the queued send_segments and sum the item count declared
             * in each notfound message's payload (skip the fixed wire
             * header, then read the compact-size count) — proves every one
             * of the 70 misses got a reply, none silently dropped past the
             * old 64-item cap. */
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
                &nm, ZCL_INVALID_SOCKET, &zaddr, "zmsg-telemetry", true);
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

                struct byte_stream first;
                stream_init(&first, 256);
                bool wrote_first = zmsg_serialize(&msg, &first);
                bool handled_first = wrote_first &&
                    zmsg->handler(&mp, node, &first);
                struct msg_zmsg_stats stats;
                msg_processor_get_zmsg_stats(&mp, &stats);
                DOS_CHECK("zmsg telemetry: accepted frame counted",
                          handled_first && stats.frames_received == 1 &&
                          stats.messages_accepted == 1 &&
                          stats.duplicates == 0 &&
                          stats.last_received_unix > 0);
                stream_free(&first);

                struct byte_stream duplicate;
                stream_init(&duplicate, 256);
                bool wrote_duplicate = zmsg_serialize(&msg, &duplicate);
                bool handled_duplicate = wrote_duplicate &&
                    zmsg->handler(&mp, node, &duplicate);
                msg_processor_get_zmsg_stats(&mp, &stats);
                DOS_CHECK("zmsg telemetry: duplicate frame separated",
                          handled_duplicate && stats.frames_received == 2 &&
                          stats.messages_accepted == 1 &&
                          stats.duplicates == 1);
                stream_free(&duplicate);

                struct byte_stream ack;
                stream_init(&ack, 32);
                bool wrote_ack = stream_write(&ack, msg.msg_id,
                                               sizeof(msg.msg_id));
                bool handled_ack = wrote_ack &&
                    zmsgack->handler(&mp, node, &ack);
                msg_processor_get_zmsg_stats(&mp, &stats);
                DOS_CHECK("zmsg telemetry: acknowledgement counted",
                          handled_ack &&
                          stats.acknowledgements_received == 1 &&
                          stats.last_ack_unix > 0);
                stream_free(&ack);
                p2p_node_free(node);
            }
        }
    }

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
 * The message FRAMING layer (net_message_read_header / read_data and the
 * p2p_node_receive_bytes reassembler) sees a hostile peer's bytes before any
 * command dispatch. It runs without a net_manager back-pointer, so it cannot
 * score the peer directly: it TAGS node->framing_offence, and the connman
 * receive caller drains + scores it once via p2p_node_score_framing_offence().
 * These cases pin that tag→drain→score contract for the concrete free abuse
 * vectors (bad start-magic, oversize headers, oversize payloads) plus the
 * handshake-level protocol violations scored in msg_version.c. Before this
 * group these paths disconnected (or not) but never moved the per-connection
 * misbehavior score, so a flooder never crossed the ban threshold. */
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
