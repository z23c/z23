/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_snapshot_serve_loopback.c — MVP C3's missing half, proven hermetically.
 *
 * Every other snapshot-sync test drives ONE side of the wire protocol in
 * isolation: the RECEIVE side (test_snapshot_sync_service.c calls
 * snapsync_handle_offer / snapsync_apply_chunk / snapsync_handle_end
 * directly against a single struct snapshot_sync_service), or wire-format
 * constants only (test_fast_sync.c). No test anywhere constructs the SERVE
 * side and pushes real zsnapshot/zsnapreq/zsnapdata/zsnapend bytes between
 * two independent zclassic23 message processors. This file does that.
 *
 * Architecture: two fully independent "logical nodes" in one process —
 * mp_a (serving, has the UTXO snapshot in RAM) and mp_b (receiving, staging
 * into its own SQLite node_db). Each side gets its own struct msg_processor,
 * struct main_state, struct net_manager, and (for B) struct node_db +
 * struct snapshot_sync_service wired through struct app_runtime_context —
 * NOT the process-global snapsync_global() singleton, so this test can
 * never collide with another snapshot_sync test group sharing the same
 * process (relevant only to the sequential tests/harness/src/test.c runner;
 * make test-parallel forks one process per group anyway).
 *
 * Transport: p2p_node_begin_message/write_message_data/end_message queue
 * real wire-framed segments (magic+command+len+checksum, exactly what a
 * socket would send) onto node->send_head. A "sentinel" node (the same
 * technique engine/modules/sim/src/simnet_wire.c uses for its NUT) is spliced in first
 * so p2p_node_end_message's "first segment on an empty queue" check never
 * fires socket_send_data() against our ZCL_INVALID_SOCKET nodes — sending
 * on an invalid fd would set node->disconnect and silently break the test.
 * lb_pump() then walks the queue, hands the raw bytes to the peer's REAL
 * p2p_node_receive_bytes() parser (checksum verification included), and
 * calls the REAL msg_process_messages() dispatcher. Every message boundary
 * in this test is therefore parsed and dispatched by the same code a live
 * socket would drive — only the socket syscalls are elided.
 *
 * Two deliberate, documented shortcuts (neither touches protocol bytes):
 *
 *   1. FlyClient round trip. snapsync_offer_followup_action() only sends
 *      zsnapreq once svc->fc_verified is true, which normally requires a
 *      real zfcchallenge/zfcproofs exchange against a populated MMB leaf
 *      store spanning thousands of synthetic blocks. FlyClient proof
 *      construction/verification already has dedicated hermetic coverage
 *      (test_snapshot_sync_service.c's verify_flyclient tests, which use
 *      the exact same "set svc.fc_verified = true directly" substitution
 *      this file uses). Skipping it here keeps the fixture to a handful of
 *      lines instead of a multi-thousand-header chain, while every message
 *      this test DOES send (zsnapshot, zsnapreq, zsnapdata, zsnapend) is
 *      real wire traffic dispatched by the real handler.
 *
 *   2. mp_snapshot_send_tick() itself (the per-peer serve-tick scheduler)
 *      lives in core/modules/net/src/msgprocessor_internal.h, a private header not
 *      on the test include path (LIB_INCLUDES only exposes lib/<name>/include).
 *      lb_drive_serve_tick() below reproduces its snapshot-serving loop
 *      verbatim from PUBLIC primitives only (snapsync_prepare_serve_step,
 *      fast_sync_get_snapshot_buf, p2p_node_begin/write/end_message,
 *      MSG_SNAPSHOT_DATA/END) — the same primitives
 *      net/snapshot_sync_contract.h exports specifically so a caller can
 *      drive this loop. Calling the real msg_send_messages() instead was
 *      evaluated and rejected: it is a kitchen-sink per-peer tick (header
 *      sync, download-manager assignment, IBD stall/eviction, ping) built
 *      for a live chain with real headers, and running it against a
 *      two-block fixture chain risks exercising unrelated machinery this
 *      test has no fixture for.
 *
 * HONEST-SERVER CONTAINMENT (asserted below): a fully valid, SHA3-verified
 * snapshot transfer over this wire loop still fails to activate, because
 * runtime activation is deliberately CONTAINED (snapshot_apply.c —
 * SNAPSYNC_ACTIVATION_CONTAINED_ERROR_CODE, "unified installer required"),
 * so snapsync_finalize()/.handle_end() return !ok even when SHA3 verified
 * true. msgprocessor_snapshot.c's zsnapend handler distinguishes that
 * specific containment code from a genuine proof/SHA3 failure: containment
 * records no offence and never bans the honest serving peer, while a
 * genuine corruption (see the second test below) still does. See file:line
 * anchors in the test body below. This is the first coverage of the
 * wire-level zsnapend handler's ban-vs-no-ban branch. */

#include "test/test_core.h"
#include "models/database.h"

#include "chain/chainparams.h"
#include "coins/coins_view.h"
#include "coins/utxo_commitment.h"
#include "config/boot_snapshot_offer.h"
#include "config/runtime.h"
#include "core/serialize.h"
#include "event/event.h"
#include "net/fast_sync.h"
#include "net/msg_internal.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/peer_scoring.h"
#include "net/snapshot_sync_contract.h"
#include "sync/sync_state.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "validation/txmempool.h"

#include <sqlite3.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define LB_ENTRY_COUNT 3

/* ── Fixture: a tiny, deterministic 3-UTXO "snapshot" ────────────────── */

static void lb_write_entry(struct byte_stream *s, int idx)
{
    uint8_t txid[32];
    uint8_t script[6];

    memset(txid, 0xA0 + idx, sizeof(txid));
    script[0] = 0x76; script[1] = 0xa9; script[2] = 0x14;
    script[3] = (uint8_t)idx; script[4] = 0x88; script[5] = 0xac;

    stream_write_bytes(s, txid, 32);
    stream_write_u32_le(s, (uint32_t)idx);           /* vout */
    stream_write_i64_le(s, 1000000000LL + idx);      /* value */
    stream_write_i32_le(s, 100 + idx);               /* height */
    stream_write_u8(s, idx == 0 ? 1 : 0);             /* is_coinbase */
    stream_write_u8(s, (uint8_t)sizeof(script));      /* compact script len */
    stream_write_bytes(s, script, sizeof(script));
}

/* One self-contained "chunk" sub-block: [entries:u32][entry...], exactly
 * the wire format snapsync_apply_chunk_local() parses and
 * snapsync_prepare_serve_step() slices out of the serve buffer. */
static void lb_build_chunk(struct byte_stream *s, int start_idx, int count)
{
    stream_init(s, 128 * (size_t)count + 8);
    stream_write_u32_le(s, (uint32_t)count);
    for (int i = 0; i < count; i++)
        lb_write_entry(s, start_idx + i);
}

/* ── Loopback transport: sentinel-guarded send-queue pump ────────────── */

static struct send_segment *lb_install_sentinel(struct p2p_node *node)
{
    struct send_segment *sentinel =
        zcl_calloc(1, sizeof(*sentinel), "test_loopback_sentinel");
    node->send_head = sentinel;
    node->send_tail = sentinel;
    node->send_offset = 0;
    return sentinel;
}

/* Drain every segment queued behind `sentinel` on `from`, feed the raw
 * wire bytes to `to` through the real p2p_node_receive_bytes() parser,
 * then run the real msg_process_messages() dispatcher on `to`. */
static bool lb_pump(struct p2p_node *from, struct send_segment *sentinel,
                    struct msg_processor *to_mp, struct p2p_node *to,
                    const unsigned char msgstart[MESSAGE_START_SIZE])
{
    bool any = false;

    while (sentinel->next) {
        struct send_segment *seg = sentinel->next;
        sentinel->next = seg->next;
        if (from->send_tail == seg)
            from->send_tail = sentinel;
        if (from->send_size >= seg->size)
            from->send_size -= seg->size;
        else
            from->send_size = 0;

        if (!p2p_node_receive_bytes(to, (const char *)seg->data,
                                    (unsigned int)seg->size, msgstart)) {
            send_segment_free(seg);
            return false;
        }
        any = true;
        send_segment_free(seg);
    }
    from->send_head = sentinel;
    from->send_offset = 0;

    if (any)
        return msg_process_messages(to_mp, to);
    return true;
}

/* Reproduces mp_snapshot_send_tick()'s snapshot-serving loop from PUBLIC
 * primitives only — see the file header "shortcut 2" for why. */
static void lb_drive_serve_tick(struct msg_processor *mp, struct p2p_node *node)
{
    int64_t buf_size = 0;
    const uint8_t *buf = fast_sync_get_snapshot_buf(&buf_size);

    if (!buf || buf_size <= 0)
        return;
    for (int batch = 0; batch < 200; batch++) {
        struct snapsync_serve_step step;

        if (node->send_size > 8 * 1024 * 1024)
            break;
        if (!snapsync_prepare_serve_step(&step, node, buf, buf_size).ok)
            break;
        if (step.action == SNAPSYNC_SERVE_ACTION_NONE)
            break;
        if (step.action == SNAPSYNC_SERVE_ACTION_SEND_END) {
            p2p_node_begin_message(node, MSG_SNAPSHOT_END,
                                   mp->params->pchMessageStart);
            p2p_node_end_message(node);
            peer_set_state_checked((uint32_t)node->id, &node->state,
                                   PEER_ACTIVE, "snapshot serve done (test)");
            break;
        }
        p2p_node_begin_message(node, MSG_SNAPSHOT_DATA,
                               mp->params->pchMessageStart);
        p2p_node_write_message_data(node, buf + step.chunk_offset,
                                    step.chunk_len);
        p2p_node_end_message(node);
    }
}

static int64_t lb_count_rows(sqlite3 *db, const char *table)
{
    char sql[128];
    sqlite3_stmt *st = NULL;
    int64_t count = -1;

    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s", table);
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW)
        count = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return count;
}

/* ── The golden-path (and tampered-chunk) test ───────────────────────
 *
 * offer (zsnapshot) -> [FlyClient bypass glue] -> request (zsnapreq) ->
 * two zsnapdata chunks -> zsnapend.
 *
 * corrupt_chunk == false: staging matches the fixture byte-for-byte, AND
 * the honest-server containment path is observed exactly as it happens on
 * the real wire (activation contained, but NOT scored/banned).
 *
 * corrupt_chunk == true: the served bytes are tampered AFTER the offered
 * SHA3 root is derived from the pristine reference, so B's staged set
 * genuinely fails to hash to the offered root — a real proof failure, not
 * containment. That case must still record the offence and ban the peer,
 * proving the fix distinguishes the two rather than just disabling the
 * ban outright. */
static int test_snapshot_serve_loopback_impl(bool corrupt_chunk)
{
    int failures = 0;

    TEST(corrupt_chunk ?
        "snapshot serve loopback: tampered chunk -> genuine SHA3 failure "
        "-> peer still banned" :
        "snapshot serve loopback: offer->request->chunk->end, two real "
        "message processors over a real wire, staging matches served "
        "bytes exactly") {
        const struct chain_params *params = chain_params_get();
        struct main_state ms_a, ms_b;
        struct tx_mempool mempool_a, mempool_b;
        struct coins_view null_view_a, null_view_b;
        struct coins_view_cache coins_a, coins_b;
        struct net_manager nm_a, nm_b;
        struct msg_processor mp_a, mp_b;
        struct node_db ndb_b;
        struct snapshot_sync_service svc_b;
        struct app_runtime_context runtime_b;
        struct net_address addr_for_a, addr_for_b;
        struct p2p_node *node_a_side = NULL;  /* A's view of the B peer */
        struct p2p_node *node_b_side = NULL;  /* B's view of the A peer */
        struct send_segment *sentinel_a = NULL, *sentinel_b = NULL;
        struct snapshot_offer offer;
        struct byte_stream chunk1, chunk2, snap_buf, req;
        uint8_t sha3_root[32];
        uint64_t utxo_count = 0;
        struct node_db ref_ndb;
        struct snapshot_sync_service ref_svc;
        bool ok;

        memset(&ms_a, 0, sizeof(ms_a));
        memset(&ms_b, 0, sizeof(ms_b));
        memset(&mempool_a, 0, sizeof(mempool_a));
        memset(&mempool_b, 0, sizeof(mempool_b));
        memset(&null_view_a, 0, sizeof(null_view_a));
        memset(&null_view_b, 0, sizeof(null_view_b));
        memset(&nm_a, 0, sizeof(nm_a));
        memset(&nm_b, 0, sizeof(nm_b));
        memset(&mp_a, 0, sizeof(mp_a));
        memset(&mp_b, 0, sizeof(mp_b));
        memset(&runtime_b, 0, sizeof(runtime_b));

        main_state_init(&ms_a);
        main_state_init(&ms_b);
        tx_mempool_init(&mempool_a, 0);
        tx_mempool_init(&mempool_b, 0);
        coins_view_cache_init(&coins_a, &null_view_a);
        coins_view_cache_init(&coins_b, &null_view_b);
        net_manager_init(&nm_a);
        net_manager_init(&nm_b);

        ASSERT(node_db_open(&ndb_b, ":memory:"));
        ASSERT(node_db_open(&ref_ndb, ":memory:"));

        /* Reference computation: apply the exact fixture bytes through the
         * exact same production parser (snapsync_apply_chunk) B will use,
         * against a throwaway DB, purely to derive the SHA3 root/count
         * A's offer must advertise. No hand-rolled hashing. */
        lb_build_chunk(&chunk1, 0, 2);
        lb_build_chunk(&chunk2, 2, 1);
        snapsync_init(&ref_svc, &ref_ndb);
        ref_svc.state = SNAPSYNC_RECEIVING;
        ASSERT(snapsync_apply_chunk(&ref_svc, chunk1.data, chunk1.size) == 2);
        ASSERT(snapsync_apply_chunk(&ref_svc, chunk2.data, chunk2.size) == 1);
        utxo_commitment_sha3_compute_table(ref_ndb.db, "snapshot_staging_utxos",
                                           sha3_root, &utxo_count);
        ASSERT(utxo_count == LB_ENTRY_COUNT);
        node_db_close(&ref_ndb);

        /* mp_a: serving side. No node_db at all — the single-stream serve
         * path only touches the in-RAM snapshot cache + offer cache. */
        mp_a.main_state = &ms_a;
        mp_a.mempool = &mempool_a;
        mp_a.coins_tip = &coins_a;
        mp_a.params = params;
        mp_a.datadir = ".";
        mp_a.net_mgr = &nm_a;

        /* mp_b: receiving side. svc_b is wired through mp_b.runtime, NOT
         * the process-global snapsync_global() singleton — see file header. */
        mp_b.main_state = &ms_b;
        mp_b.mempool = &mempool_b;
        mp_b.coins_tip = &coins_b;
        mp_b.params = params;
        mp_b.datadir = ".";
        mp_b.net_mgr = &nm_b;
        snapsync_init(&svc_b, &ndb_b);
        runtime_b.snapshot_sync = &svc_b;
        mp_b.runtime = &runtime_b;

        memset(&addr_for_a, 0, sizeof(addr_for_a));
        memcpy(addr_for_a.svc.addr.ip, pchIPv4Prefix, 12);
        addr_for_a.svc.addr.ip[12] = 5; addr_for_a.svc.addr.ip[13] = 6;
        addr_for_a.svc.addr.ip[14] = 7; addr_for_a.svc.addr.ip[15] = 8;
        addr_for_a.svc.port = 18033;

        memset(&addr_for_b, 0, sizeof(addr_for_b));
        memcpy(addr_for_b.svc.addr.ip, pchIPv4Prefix, 12);
        addr_for_b.svc.addr.ip[12] = 1; addr_for_b.svc.addr.ip[13] = 2;
        addr_for_b.svc.addr.ip[14] = 3; addr_for_b.svc.addr.ip[15] = 4;
        addr_for_b.svc.port = 18033;

        /* node_a_side lives in A's world and represents "the connection to
         * B"; node_b_side lives in B's world and represents "the
         * connection to A". Neither IP is loopback, so peer_scoring's
         * is_trusted_peer() exemption never masks the finding below. */
        node_a_side = p2p_node_create(&nm_a, ZCL_INVALID_SOCKET,
                                      &addr_for_a, "peer-b", false);
        node_b_side = p2p_node_create(&nm_b, ZCL_INVALID_SOCKET,
                                      &addr_for_b, "peer-a", false);
        ASSERT(node_a_side != NULL && node_b_side != NULL);
        node_a_side->version = 1; node_a_side->services = NODE_ZCL23;
        node_b_side->version = 1; node_b_side->services = NODE_ZCL23;
        node_a_side->state = PEER_HANDSHAKE_COMPLETE;
        node_b_side->state = PEER_HANDSHAKE_COMPLETE;

        sentinel_a = lb_install_sentinel(node_a_side);
        sentinel_b = lb_install_sentinel(node_b_side);

        boot_snapshot_offer_test_set_trust_override(1);
        boot_snapshot_offer_test_set_publication_override(1);

        /* ── Step 1: A serves a real zsnapshot offer (real wire code:
         * send_snapshot_offer_msg, core/modules/net/src/msgprocessor_snapshot.c). */
        memset(&offer, 0, sizeof(offer));
        offer.height = 6000;
        offer.peer_tip_height = 6010;   /* finality-safe: height <= tip-10 */
        offer.protocol_version = FAST_SYNC_PROTOCOL_VERSION;
        offer.snapshot_schema_version = FAST_SYNC_SNAPSHOT_SCHEMA_VERSION;
        memcpy(offer.utxo_root, sha3_root, 32);
        memset(offer.mmr_root, 0x22, 32);
        memset(offer.mmb_root, 0x33, 32);
        memset(offer.chain_work, 0x01, 32);
        offer.num_utxos = utxo_count;
        offer.total_bytes = utxo_count * 80;

        msg_processor_update_offer(&offer);

        stream_init(&snap_buf, 512);
        stream_write_bytes(&snap_buf, chunk1.data, chunk1.size);
        stream_write_bytes(&snap_buf, chunk2.data, chunk2.size);
        {
            uint8_t *cache_copy = zcl_malloc(snap_buf.size, "test_snap_cache");
            ASSERT(cache_copy != NULL);
            memcpy(cache_copy, snap_buf.data, snap_buf.size);
            if (corrupt_chunk) {
                /* Flip the last byte of the served buffer (inside chunk2's
                 * script) AFTER sha3_root was derived from the pristine
                 * reference bytes above. A registers/serves THIS tampered
                 * buffer while still offering the pristine root, exactly
                 * modeling a corrupted-in-transit or malicious serve: the
                 * bytes B receives and stages will genuinely NOT hash to
                 * the offered root. */
                cache_copy[snap_buf.size - 1] ^= 0xFF;
            }
            ASSERT(fast_sync_publish_snapshot_cache(
                cache_copy, (int64_t)snap_buf.size, sha3_root, utxo_count));
        }

        send_snapshot_offer_msg(node_a_side, &offer, mp_a.params->pchMessageStart);

        /* ── Step 2: pump A->B, real receive dispatch. Accepts the offer,
         * transitions NEGOTIATING, auto-queues a real zfcchallenge on
         * node_b_side (harmlessly no-op'd by A below — mp_a.flyclient_proof
         * is unset, exactly like a peer with no MMB data). */
        ASSERT(lb_pump(node_a_side, sentinel_a, &mp_b, node_b_side,
                      params->pchMessageStart));
        ASSERT(svc_b.state == SNAPSYNC_NEGOTIATING);

        /* ── Step 3 (documented FlyClient bypass — file header shortcut 1):
         * begin_receive is real production code; only fc_verified is
         * substituted, matching test_snapshot_sync_service.c's own
         * pattern for the identical primitive. */
        ASSERT(snapsync_begin_receive(&svc_b).ok);
        svc_b.fc_verified = true;
        ASSERT(svc_b.state == SNAPSYNC_RECEIVING);

        /* Pump A's harmless zfcchallenge no-op through, then B sends a
         * real zsnapreq built with the real PoW solver
         * (snapsync_write_snapshot_request -> fast_sync_solve_pow). */
        ASSERT(lb_pump(node_b_side, sentinel_b, &mp_a, node_a_side,
                      params->pchMessageStart));

        stream_init(&req, 52);
        ok = snapsync_write_snapshot_request(
            &req, active_chain_height(&ms_b.chain_active),
            node_b_side->addr.svc.addr.ip).ok;
        ASSERT(ok);
        p2p_node_begin_message(node_b_side, MSG_SNAPSHOT_REQ,
                               mp_b.params->pchMessageStart);
        p2p_node_write_message_data(node_b_side, req.data, req.size);
        p2p_node_end_message(node_b_side);
        stream_free(&req);

        /* ── Step 4: pump B->A, real receive dispatch. Validates PoW +
         * rate limit, transitions node_a_side to PEER_SNAPSHOT_SERVING. */
        struct snapsync_serve_puzzle_census census_before, census_after;
        snapsync_get_serve_puzzle_census(&census_before);
        ASSERT(lb_pump(node_b_side, sentinel_b, &mp_a, node_a_side,
                      params->pchMessageStart));
        ASSERT(node_a_side->state == PEER_SNAPSHOT_SERVING);

        /* The accepted request was fed to the shared client-puzzle gate so
         * its load EWMA sees real serve traffic — and the gate's verdict is
         * NOT allowed to affect admission. The state assertion above is the
         * whole point: this file runs the same loopback twice from one
         * fixed address, and whenever the two runs land in the same wall
         * second the second zsnapreq proof is BYTE-IDENTICAL to the first
         * (peer_id = SHA3(address), whole-second timestamp, nonce walked
         * from zero), so the gate reports a duplicate. An honest peer must
         * still be served. */
        snapsync_get_serve_puzzle_census(&census_after);
        ASSERT(census_after.offered == census_before.offered + 1);
        ASSERT(census_after.first_sight + census_after.duplicates ==
               census_after.offered);

        /* ── Step 5 (documented send-tick substitution — shortcut 2):
         * streams both real zsnapdata chunks + zsnapend from the real
         * in-RAM snapshot buffer via snapsync_prepare_serve_step. */
        lb_drive_serve_tick(&mp_a, node_a_side);

        /* ── Step 6: pump A->B, real receive dispatch. Applies both chunks
         * to snapshot_staging_utxos, then finalizes on zsnapend. */
        ASSERT(lb_pump(node_a_side, sentinel_a, &mp_b, node_b_side,
                      params->pchMessageStart));

        if (!corrupt_chunk) {
        /* ── Assertion 1: the served bytes landed in staging byte-for-byte,
         * proving the full serve->transfer->receive loop moved the exact
         * fixture, not a corrupted or partial one. Active-state promotion
         * is deliberately never reached (see finding below), so "byte-for-
         * byte matches the served snapshot" is proven at the staging
         * layer — the honest scope given that containment. */
        ASSERT(lb_count_rows(ndb_b.db, "snapshot_staging_utxos") ==
              LB_ENTRY_COUNT);
        {
            sqlite3_stmt *st = NULL;
            ASSERT(sqlite3_prepare_v2(ndb_b.db,
                "SELECT txid,vout,value,script,height,is_coinbase "
                "FROM snapshot_staging_utxos ORDER BY txid,vout",
                -1, &st, NULL) == SQLITE_OK);
            for (int i = 0; i < LB_ENTRY_COUNT; i++) {
                uint8_t want_txid[32];
                ASSERT(sqlite3_step(st) == SQLITE_ROW);
                memset(want_txid, 0xA0 + i, sizeof(want_txid));
                ASSERT(sqlite3_column_bytes(st, 0) == 32);
                ASSERT(memcmp(sqlite3_column_blob(st, 0), want_txid, 32) == 0);
                ASSERT(sqlite3_column_int(st, 1) == i);
                ASSERT(sqlite3_column_int64(st, 2) == 1000000000LL + i);
                ASSERT(sqlite3_column_bytes(st, 3) == 6);
                {
                    const uint8_t want_script[6] =
                        {0x76, 0xa9, 0x14, (uint8_t)i, 0x88, 0xac};
                    ASSERT(memcmp(sqlite3_column_blob(st, 3), want_script,
                                 6) == 0);
                }
                ASSERT(sqlite3_column_int(st, 4) == 100 + i);
                ASSERT(sqlite3_column_int(st, 5) == (i == 0 ? 1 : 0));
            }
            ASSERT(sqlite3_step(st) == SQLITE_DONE);
            sqlite3_finalize(st);
        }

        /* ── Assertion 2 (SHA3 self-consistency, real production math):
         * B's own staged set hashes to exactly the root A offered. */
        {
            uint8_t local_root[32];
            uint64_t local_count = 0;
            utxo_commitment_sha3_compute_table(ndb_b.db,
                "snapshot_staging_utxos", local_root, &local_count);
            ASSERT(local_count == LB_ENTRY_COUNT);
            ASSERT(memcmp(local_root, sha3_root, 32) == 0);
            ASSERT(memcmp(local_root, svc_b.offered_utxo_root, 32) == 0);
        }

        /* ── Honest-server containment path, real wire-level behavior
         * (see file header) — snapshot_apply.c:52-75
         * snapsync_stage_promote_active_internal() always returns
         * SNAPSYNC_ACTIVATION_CONTAINED_ERROR_CODE (-12) even on a
         * cryptographically PASSING transfer, because runtime activation
         * is deliberately fail-closed until the unified installer exists.
         * msgprocessor_snapshot.c's zsnapend handler (~line 1376) branches
         * on that specific code: activation-contained is NOT a peer fault,
         * so no offence is recorded and the peer is never banned. The
         * snapshot-sync service itself still lands in FAILED with the
         * containment blocker set (snapshot sync unavailable this cycle),
         * and the receiver falls back to ordinary P2P header/block sync —
         * the honest server is left free to serve (or be reused) again. */
        ASSERT(svc_b.state == SNAPSYNC_FAILED);
        ASSERT(blocker_exists(SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID));
        ASSERT(node_b_side->misbehavior == 0);
        ASSERT(!node_b_side->disconnect);
        } else {
        /* ── Genuine corruption: B's staged set does NOT hash to the
         * offered root (byte flipped in cache_copy above). This is a real
         * proof failure, not activation containment (snapsync_handle_end's
         * result code here is the generic finalize failure, never
         * SNAPSYNC_ACTIVATION_CONTAINED_ERROR_CODE), so
         * msgprocessor_snapshot.c's zsnapend handler must still record the
         * offence and ban the peer — the fix narrows the exemption to
         * containment only, it does not disable scoring altogether. */
        ASSERT(svc_b.state == SNAPSYNC_FAILED);
        ASSERT(!blocker_exists(SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID));
        ASSERT(node_b_side->misbehavior ==
              peer_offence_weight(PEER_OFFENCE_INVALID_PROOF));
        ASSERT(node_b_side->disconnect);  /* auto-banned at the default
                                            * 100-point threshold — genuine
                                            * corruption still bans. */
        }

        blocker_clear(SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID);
        boot_snapshot_offer_test_set_publication_override(-1);
        boot_snapshot_offer_test_set_trust_override(-1);
        msg_processor_invalidate_offer();
        fast_sync_reset_snapshot_cache();
        /* Reset the process-global snapsync FSM (separate from svc_a/
         * svc_b's own .state field) so a second impl() invocation in the
         * same process (corrupt_chunk sub-case) starts from IDLE instead
         * of leaving it wedged at FAILED, which would otherwise reject
         * every subsequent transition as illegal (harmless to this test's
         * assertions, which read svc_b.state directly, but pollutes
         * stderr with spurious "BUG: snapsync illegal ..." lines and
         * would mask a real bug in svc/global sync elsewhere). */
        (void)snapsync_set_state(SNAPSYNC_IDLE, "test reset");

        stream_free(&chunk1);
        stream_free(&chunk2);
        stream_free(&snap_buf);
        send_segment_free(sentinel_a);
        send_segment_free(sentinel_b);
        node_a_side->send_head = NULL; node_a_side->send_tail = NULL;
        node_b_side->send_head = NULL; node_b_side->send_tail = NULL;
        node_a_side->recv_msg_count = 0;
        node_b_side->recv_msg_count = 0;
        p2p_node_free(node_a_side);
        p2p_node_free(node_b_side);
        node_db_close(&ndb_b);
        net_manager_free(&nm_a);
        net_manager_free(&nm_b);
        coins_view_cache_free(&coins_a);
        coins_view_cache_free(&coins_b);
        tx_mempool_free(&mempool_a);
        tx_mempool_free(&mempool_b);
        main_state_free(&ms_a);
        main_state_free(&ms_b);

        PASS();
    } _test_next:;

    return failures;
}

int test_snapshot_serve_loopback(void)
{
    int failures = 0;

    /* Start the serve-side puzzle census from zero — but only ONCE, before
     * both runs. Resetting between them would clear the single-use ring and
     * hide the very thing worth measuring: the two runs use one fixed
     * address, so if they land in the same wall second their zsnapreq proofs
     * are byte-identical and the second is counted as a duplicate. Both are
     * served either way; the impl asserts exactly that. */
    snapsync_reset_serve_puzzle_census();

    failures += test_snapshot_serve_loopback_impl(false);
    failures += test_snapshot_serve_loopback_impl(true);

    {
        struct snapsync_serve_puzzle_census c;
        snapsync_get_serve_puzzle_census(&c);
        printf("snapshot_serve_loopback: serve puzzle census "
               "offered=%llu first_sight=%llu duplicates=%llu "
               "bits_now=%d rate_ewma_milli=%lld... ",
               (unsigned long long)c.offered,
               (unsigned long long)c.first_sight,
               (unsigned long long)c.duplicates,
               c.bits_now, (long long)c.rate_ewma_milli);
        /* Two serves happened, both admitted, and every one is accounted
         * for as either a first sight or a duplicate. */
        bool ok = c.offered == 2 &&
                  c.first_sight + c.duplicates == c.offered &&
                  c.first_sight >= 1;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}
