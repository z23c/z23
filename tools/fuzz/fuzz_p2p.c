/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * fuzz_p2p — libFuzzer harness for inbound P2P message parsers.
 *
 * Pure wire deserializers are still called directly for cheap broad
 * coverage, but the unfuzzed surface is the msgprocessor dispatch
 * family. The first input byte selects one inbound P2P command; the
 * remaining bytes are wrapped in a real net_message header (including
 * checksum), queued on a synthetic p2p_node, and processed through
 * msg_process_messages(). That keeps command routing, handshake gates,
 * and the ZCL23 z* fallback path identical to the live node while
 * avoiding live sockets, disk mutation, or background block-intake
 * threads.
 */

#include "net/msgprocessor.h"
#include "net/p2p_message.h"
#include "net/protocol.h"
#include "net/netaddr.h"
#include "net/net.h"
#include "net/fast_sync.h"
#include "net/flyclient.h"
#include "net/version.h"
#include "core/serialize.h"
#include "core/hash.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "chain/chainparams.h"
#include "coins/coins_view.h"
#include "sync/sync_state.h"
#include "validation/main_state.h"
#include "validation/txmempool.h"
#include "consensus/validation.h"
#include "util/safe_alloc.h"

#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

volatile sig_atomic_t g_shutdown_requested = 0;

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static const struct chain_params *g_params;

static const unsigned char g_msgstart[MESSAGE_START_SIZE] = {
    0x24, 0xe9, 0x27, 0x64
};

static const char *const g_inbound_commands[] = {
    /* msgprocessor dispatch table */
    "version", "verack", "ping", "pong", "addr", "inv", "getdata",
    "getblocks", "getheaders", "block", "tx", "headers", "getaddr",
    "mempool", "sendheaders", "reject", "feefilter", "notfound",
    "sendcmpct", "cmpctblock", "getblocktxn", "blocktxn",
    "filterload", "filteradd", "filterclear", "zfileaddr",
    "zmsg", "zmsgack", "zfilelist", "zfilechal", "zfileproof",
    "zfilepay", "zgame",
    /* mp_handle_zcl23_sync fallback */
    MSG_SNAPSHOT_OFFER, MSG_SNAPSHOT_REQ, MSG_SNAPSHOT_DATA,
    MSG_SNAPSHOT_END, MSG_FC_CHALLENGE, MSG_FC_PROOFS, MSG_MANIFEST,
    MSG_CHUNK_REQ, MSG_CHUNK_DATA, MSG_BLOCK_MANIFEST, MSG_BLOCK_REQ,
    MSG_BLOCK_DATA, MSG_BLOCK_BITMAP,
};

#define FUZZ_P2P_COMMAND_COUNT \
    (sizeof(g_inbound_commands) / sizeof(g_inbound_commands[0]))

static struct main_state g_ms;
static struct tx_mempool g_mempool;
static struct coins_view g_null_view;
static struct coins_view_cache g_coins_tip;
static struct net_manager g_nm;
static struct msg_processor g_mp;
static struct p2p_node *g_node;
static bool g_dispatch_ready;

static bool fuzz_submit_block(struct block *block,
                              struct validation_state *out,
                              void *ctx);
static void fuzz_init_peer_addr(struct net_address *addr);

static void fuzz_dispatch_cleanup(void)
{
    if (!g_dispatch_ready)
        return;
    p2p_node_free(g_node);
    g_node = NULL;
    net_manager_free(&g_nm);
    coins_view_cache_free(&g_coins_tip);
    tx_mempool_free(&g_mempool);
    main_state_free(&g_ms);
    g_dispatch_ready = false;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    chain_params_select(CHAIN_MAIN);
    g_params = chain_params_get();

    /* Keep the block message path synchronous. When not at tip, valid
     * catch-up blocks are queued onto a worker thread; a stateless fuzzer
     * should not spawn background ingestion workers. */
    (void)sync_set_state(SYNC_HEADERS_DOWNLOAD, "fuzz p2p init");
    (void)sync_set_state(SYNC_AT_TIP, "fuzz p2p init");

    main_state_init(&g_ms);
    tx_mempool_init(&g_mempool, 0);
    memset(&g_null_view, 0, sizeof(g_null_view));
    coins_view_cache_init(&g_coins_tip, &g_null_view);
    net_manager_init(&g_nm);
    memcpy(g_nm.message_start, g_msgstart, sizeof(g_msgstart));

    memset(&g_mp, 0, sizeof(g_mp));
    g_mp.main_state = &g_ms;
    g_mp.mempool = &g_mempool;
    g_mp.coins_tip = &g_coins_tip;
    g_mp.params = g_params;
    g_mp.datadir = "/tmp";
    g_mp.net_mgr = &g_nm;
    g_mp.block_submit = fuzz_submit_block;
    g_mp.compact_block_submit = fuzz_submit_block;

    g_dispatch_ready = true;
    struct net_address addr;
    fuzz_init_peer_addr(&addr);
    g_node = p2p_node_create(&g_nm, ZCL_INVALID_SOCKET, &addr,
                             "203.0.113.9:8033", true);
    if (!g_node) {
        fuzz_dispatch_cleanup();
        return 0;
    }

    atexit(fuzz_dispatch_cleanup);
    return 0;
}

static bool fuzz_submit_block(struct block *block,
                              struct validation_state *out,
                              void *ctx)
{
    (void)block;
    (void)ctx;
    validation_state_error(out, "p2p-block-staged-for-reducer");
    return false;
}

static void fuzz_init_peer_addr(struct net_address *addr)
{
    net_address_init(addr);
    addr->nServices = NODE_NETWORK | NODE_ZCL23;
    addr->svc.port = g_params ? (uint16_t)g_params->nDefaultPort : 8033;
    addr->svc.addr.ip[10] = 0xff;
    addr->svc.addr.ip[11] = 0xff;
    addr->svc.addr.ip[12] = 203;
    addr->svc.addr.ip[13] = 0;
    addr->svc.addr.ip[14] = 113;
    addr->svc.addr.ip[15] = 9;
}

static bool fuzz_frame_payload(struct p2p_node *node,
                               const char *command,
                               const uint8_t *payload,
                               size_t payload_len)
{
    if (!node || !command || payload_len > MAX_PROTOCOL_MESSAGE_LENGTH)
        return false;

    size_t total = MSG_HEADER_SIZE + payload_len;
    uint8_t *frame = zcl_malloc(total, "fuzz_p2p_frame");
    if (!frame)
        return false;

    struct msg_header hdr;
    msg_header_init_full(&hdr, g_msgstart, command,
                         (unsigned int)payload_len);

    struct uint256 checksum;
    hash256(payload_len ? payload : (const uint8_t *)"",
            payload_len, checksum.data);
    memcpy(&hdr.nChecksum, checksum.data, sizeof(hdr.nChecksum));

    memcpy(frame, &hdr, MSG_HEADER_SIZE);
    if (payload_len > 0)
        memcpy(frame + MSG_HEADER_SIZE, payload, payload_len);

    bool ok = p2p_node_receive_bytes(node, (const char *)frame,
                                     (unsigned int)total, g_msgstart);
    free(frame);
    return ok;
}

static void fuzz_reset_node_for_command(const char *command)
{
    struct p2p_node *node = g_node;
    if (!node)
        return;

    zcl_mutex_lock(&node->cs_send);
    while (node->send_head) {
        struct send_segment *seg = node->send_head;
        node->send_head = seg->next;
        send_segment_free(seg);
    }
    node->send_tail = NULL;
    node->send_size = 0;
    node->send_offset = 0;
    zcl_mutex_unlock(&node->cs_send);

    zcl_mutex_lock(&node->cs_recv);
    for (size_t i = 0; i < node->recv_msg_count; i++)
        net_message_free(&node->recv_msgs[i]);
    node->recv_msg_count = 0;
    zcl_mutex_unlock(&node->cs_recv);

    free(node->addr_to_send);
    node->addr_to_send = NULL;
    node->addr_to_send_count = 0;
    node->addr_to_send_cap = 0;
    node->get_addr = false;
    node->sent_addr = false;

    free(node->inventory_to_send);
    node->inventory_to_send = NULL;
    node->inventory_to_send_count = 0;
    node->inventory_to_send_cap = 0;
    free(node->inventory_known_hashes);
    node->inventory_known_hashes = NULL;
    node->inventory_known_count = 0;
    node->inventory_known_cap = 0;

    free(node->askfor_set);
    node->askfor_set = NULL;
    node->askfor_set_count = 0;
    node->askfor_set_cap = 0;
    free(node->askfor_map);
    node->askfor_map = NULL;
    node->askfor_map_count = 0;
    node->askfor_map_cap = 0;

    if (node->compact_pending_block) {
        block_free(node->compact_pending_block);
        free(node->compact_pending_block);
        node->compact_pending_block = NULL;
    }
    free(node->compact_missing_indices);
    node->compact_missing_indices = NULL;
    node->compact_num_missing = 0;
    node->compact_request_time = 0;

    free(node->blk_bitmap);
    node->blk_bitmap = NULL;
    node->blk_bitmap_len = 0;
    node->blk_peer_height = 0;

    node->socket = ZCL_INVALID_SOCKET;
    node->services = NODE_NETWORK | NODE_ZCL23;
    node->recv_version = INIT_PROTO_VERSION;
    node->disconnect = false;
    node->relay_txes = true;
    node->network_node = true;
    node->client = false;
    node->one_shot = false;
    node->whitelisted = false;
    node->starting_height = 0;
    node->ping_nonce_sent = 0;
    node->ping_usec_start = 0;
    node->ping_usec_time = 0;
    node->min_ping_usec_time = INT64_MAX;
    node->ping_queued = false;
    node->prefer_headers = false;
    node->send_compact = false;
    node->swarm_manifest_sent = false;
    node->swarm_manifest_received = false;
    node->swarm_inflight_chunk = -1;
    node->swarm_chunk_req_time = 0;
    node->blk_manifest_sent = false;
    node->blk_manifest_received = false;
    for (int i = 0; i < PIECE_PIPELINE_DEPTH; i++) {
        node->blk_pipeline[i].piece_index = -1;
        node->blk_pipeline[i].request_time = 0;
    }
    node->zsync_offset = 0;
    node->zsync_total = 0;
    node->zsync_sent = 0;
    node->zsync_cursor_valid = false;
    node->zsync_file_offset = 0;
    node->zsync_file_size = 0;
    node->zsync_offered_height = 0;
    node->zsync_offered_count = 0;
    node->zsync_offer_version = 0;
    node->zsync_snapshot_version = 0;
    node->last_block_time = 0;
    node->avg_latency_us = 0;
    node->blocks_received = 0;
    node->total_headers_delivered = 0;
    atomic_store(&node->last_getheaders_time, 0);
    atomic_store(&node->getheaders_stale_count, 0);
    atomic_store(&node->last_useful_headers_time, 0);
    atomic_store(&node->misbehavior, 0);
    atomic_store(&node->peer_score_last_good_ms, 0);
    uint256_set_null(&node->hash_continue);
    memset(node->sub_ver, 0, sizeof(node->sub_ver));
    memset(node->clean_sub_ver, 0, sizeof(node->clean_sub_ver));

    if (strcmp(command, "version") == 0) {
        node->version = 0;
        atomic_store(&node->state, PEER_CONNECTED);
    } else {
        node->version = PROTOCOL_VERSION;
        atomic_store(&node->state, PEER_ACTIVE);
    }
}

static void fuzz_dispatch_payload(const char *command,
                                  const uint8_t *payload,
                                  size_t payload_len)
{
    if (!g_dispatch_ready)
        return;

    fuzz_reset_node_for_command(command);

    if (fuzz_frame_payload(g_node, command, payload, payload_len))
        (void)msg_process_messages(&g_mp, g_node);
}

/* Minimum inbound payload lengths per command, in the original
 * dispatch-check order. Commands absent here fall through to 0. */
static const struct min_dispatch_len {
    const char *command;
    size_t min_len;
} g_min_dispatch_len[] = {
    { "version", 80 },
    { "ping", 8 },
    { "pong", 8 },
    { "getblocks", 33 },
    { "getheaders", 33 },
    { "block", 80 },
    { "tx", 8 },
    { "feefilter", 8 },
    { "sendcmpct", 9 },
    { "cmpctblock", 90 },
    { "getblocktxn", 33 },
    { "blocktxn", 33 },
    { "zfileaddr", 2 },
    { "zmsg", 44 },
    { "zmsgack", 32 },
    { "zfilelist", 1 },
    { "zfilechal", 36 },
    { "zfileproof", 68 },
    { "zfilepay", 72 },
    { "zgame", 2 },
    { MSG_SNAPSHOT_OFFER, 116 },
    { MSG_SNAPSHOT_REQ, 4 },
    { MSG_FC_CHALLENGE, 72 },
    { MSG_FC_PROOFS, 4 },
    { MSG_MANIFEST, 84 },
    { MSG_CHUNK_REQ, 4 },
    { MSG_CHUNK_DATA, 8 },
    { MSG_BLOCK_MANIFEST, 76 },
    { MSG_BLOCK_REQ, 4 },
    { MSG_BLOCK_DATA, 8 },
    { MSG_BLOCK_BITMAP, 4 },
};

static size_t fuzz_min_dispatch_payload(const char *command)
{
    if (!command)
        return SIZE_MAX;
    const size_t entry_count =
        sizeof(g_min_dispatch_len) / sizeof(g_min_dispatch_len[0]);
    for (size_t i = 0; i < entry_count; i++)
        if (strcmp(command, g_min_dispatch_len[i].command) == 0)
            return g_min_dispatch_len[i].min_len;
    return 0;
}

static void fuzz_selected_inbound_message(const uint8_t *data, size_t size)
{
    if (!data || size == 0)
        return;
    const char *command =
        g_inbound_commands[data[0] % FUZZ_P2P_COMMAND_COUNT];
    size_t payload_len = size - 1;
    if (payload_len < fuzz_min_dispatch_payload(command))
        return;
    fuzz_dispatch_payload(command, data + 1, payload_len);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > (1u << 20))
        return 0;

    /* version_message_deserialize is the handshake entry point. A
     * malicious peer can send any sub_version string, nonce, etc.
     * The parser must bound-check the sub_version length and the
     * net_address reads without reading past `size`. */
    if (size >= 80) {
        struct byte_stream s;
        stream_init_from_data(&s, data, size);
        struct version_message v;
        version_message_init(&v);
        (void)version_message_deserialize(&v, &s);
        stream_free(&s);
    }

    /* Raw transaction deserialization — every inbound tx pass
     * through this path, and the ZCL overwintered/sapling format
     * has a lot of optional fields that are easy to get wrong. */
    if (size >= 12) {
        struct byte_stream s;
        stream_init_from_data(&s, data, size);
        struct transaction tx;
        transaction_init(&tx);
        if (transaction_deserialize(&tx, &s)) {
            /* Round-trip check: a successfully-parsed tx should
             * serialize back without blowing up. Mismatches aren't
             * necessarily bugs (we may canonicalise on the way
             * out), but segfaults absolutely are. */
            struct byte_stream out;
            stream_init(&out, 256);
            (void)transaction_serialize(&tx, &out);
            stream_free(&out);
        }
        transaction_free(&tx);
        stream_free(&s);
    }

    /* Raw block deserialize — an inbound `block` message carries
     * one of these. We share the shape with fuzz_block.c but only
     * the parse half, not the validator, so that this harness
     * stays cheap and focused on message boundary bugs. */
    if (size >= 80) {
        struct byte_stream s;
        stream_init_from_data(&s, data, size);
        struct block b;
        block_init(&b);
        (void)block_deserialize(&b, &s);
        block_free(&b);
        stream_free(&s);
    }

    /* Dispatcher-backed coverage. One command per input keeps the CI
     * smoke bounded; libFuzzer's corpus/mutator covers the command
     * selector byte. */
    fuzz_selected_inbound_message(data, size);

    return 0;
}
