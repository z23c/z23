/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Proves the mesh terminal requester lane fails closed: an OK receipt is
 * only armed over the live Noise session after the production responder
 * decision and full binding checks (transcript, generation, remote static,
 * delegation-derived responder identity); screen DATA obeys the strictly
 * increasing sequence, the bounded FIFO and the credit window that backs
 * it; watchdogs end sessions by name; refusal and CLOSED receipts and the
 * responder's close end sessions honestly. The lane is a service on the
 * mesh stream primitive, so every frame here is a real stream frame
 * carrying one terminal message, decoded by the production stream ingress
 * (the open/send path needs a live node composition context and is
 * covered by the two-node acceptance lane) with real in-process Noise
 * transports from the shared fixture. */

#include "test/test_core.h"

#include "config/boot_mesh_terminal.h"
#include "config/mesh_stream.h"
#include "../../../engine/composition/src/boot_mesh_terminal_internal.h"
#include "test/mesh_stream_fixture.h"
#include "test/mesh_term_fixture.h"
#include "base/hex.h"
#include "net/net.h"
#include "platform/time_compat.h"

#include <stdio.h>
#include <string.h>

/* A well-formed but fictional pairing id for opens that never reach the
 * production decision: receipt composition hashes the open, and the open
 * root refuses an all-zero pairing id. */
static uint8_t CLIENT_TEST_NO_PAIRING[32];

#define CLIENT_TEST_NOW() ((uint64_t)platform_time_wall_time_t())

/* Fixed clock inside the shared fixture's pairing validity window
 * (2000..3000); used only for the pure decide/compose layer. */
#define CLIENT_TEST_PAIR_NOW 2500u

/* One terminal message plus the stream header it rides in. */
#define CLIENT_TEST_FRAME_MAX (MESH_TERMINAL_MSG_MAX + 64u)

/* Seal one requester-ward stream frame on the responder's transport and
 * hand the plaintext to the production stream ingress, exactly as the net
 * seam does. `stream_close` sends the message on a stream CLOSE (the
 * shape the responder's own ending uses) instead of a DATA. */
static bool client_test_deliver_on(struct mesh_term_fixture *f,
                                   struct noise_transport *from,
                                   struct noise_transport *to,
                                   struct p2p_node *node, uint64_t stream_id,
                                   uint8_t kind, const uint8_t *wire,
                                   size_t wire_len, bool stream_close)
{
    (void)f;
    uint8_t msg[MESH_TERMINAL_MSG_MAX];
    size_t msg_len = boot_mesh_terminal_msg(kind, wire, wire_len, msg,
                                            sizeof(msg));
    if (!msg_len)
        return false;
    uint8_t frame[CLIENT_TEST_FRAME_MAX];
    size_t frame_len =
        stream_close
            ? mesh_stream_test_close_frame(stream_id,
                                           MESH_STREAM_CLOSED_BY_SERVICE, msg,
                                           msg_len, frame, sizeof(frame))
            : mesh_stream_test_data_frame(stream_id, msg, msg_len, frame,
                                          sizeof(frame));
    if (!frame_len)
        return false;
    uint8_t delivered[CLIENT_TEST_FRAME_MAX];
    if (!mesh_term_frame_roundtrip(from, to, frame, frame_len, delivered,
                                   sizeof(delivered)))
        return false;
    return mesh_stream_frame(NULL, node, delivered, frame_len, NULL);
}

/* A terminal message on the requester's own stream. */
static bool client_test_deliver(struct mesh_term_fixture *f,
                                struct p2p_node *cnode, uint64_t stream_id,
                                uint8_t kind, const uint8_t *wire,
                                size_t wire_len)
{
    return client_test_deliver_on(f, f->res_term, f->term_peer.ini, cnode,
                                  stream_id, kind, wire, wire_len, false);
}

/* The responder's ending: the message rides the stream CLOSE. */
static bool client_test_deliver_close(struct mesh_term_fixture *f,
                                      struct p2p_node *cnode,
                                      uint64_t stream_id, uint8_t kind,
                                      const uint8_t *wire, size_t wire_len)
{
    return client_test_deliver_on(f, f->res_term, f->term_peer.ini, cnode,
                                  stream_id, kind, wire, wire_len, true);
}

/* The same message over the WRONG peer transport (the status peer's
 * session, whose remote static is a different identity), handed to
 * ingress on a node bound to that session. Sealed on the status pair's
 * own transports: a valid frame from a different established identity,
 * not a cross-session ciphertext no transport would ever decrypt. */
static bool client_test_deliver_wrong_peer(struct mesh_term_fixture *f,
                                           struct p2p_node *wnode,
                                           uint64_t stream_id, uint8_t kind,
                                           const uint8_t *wire,
                                           size_t wire_len)
{
    return client_test_deliver_on(f, f->res_status, f->status_peer.ini, wnode,
                                  stream_id, kind, wire, wire_len, false);
}

/* A live screen frame from the responder: bounded DATA, given sequence. */
static bool client_test_send_data(struct mesh_term_fixture *f,
                                  struct p2p_node *cnode, uint64_t stream_id,
                                  const uint8_t terminal_id[32], uint64_t seq,
                                  const void *payload, size_t payload_len)
{
    struct mesh_terminal_data_v1 data;
    memset(&data, 0, sizeof(data));
    memcpy(data.terminal_id, terminal_id, 32);
    data.seq = seq;
    data.payload_len = (uint16_t)payload_len;
    if (payload_len)
        memcpy(data.payload, payload, payload_len);
    uint8_t wire[MESH_TERMINAL_DATA_V1_MAX_WIRE_BYTES];
    size_t wire_len = 0;
    if (mesh_terminal_data_v1_encode(&data, wire, sizeof(wire), &wire_len) !=
        MESH_TERMINAL_PROTO_OK)
        return false;
    return client_test_deliver(f, cnode, stream_id, MESH_TERMINAL_MSG_DATA,
                               wire, wire_len);
}

static bool client_test_inject_simple(struct mesh_term_fixture *f,
                                      const struct mesh_terminal_open_v1 *open,
                                      bool open_confirmed, uint8_t tid_out[32],
                                      uint64_t *sid_out)
{
    return boot_mesh_terminal_client_test_inject(
        open, f->resp_master_pub, f->resp_online_pub,
        f->resp_noise_pub, NULL, 0, 0, open_confirmed, tid_out, sid_out);
}

int test_mesh_terminal_client(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "mesh_terminal_client", "lane");
    struct mesh_term_fixture f;
    bool fixture_open = false;
    struct p2p_node cnode;  /* requester side: transport = term_peer.ini */
    struct p2p_node wnode;  /* wrong peer side: transport = status_peer.ini */

    mesh_term_fill32(CLIENT_TEST_NO_PAIRING, 0x5E);

    TEST("mesh terminal client: the session ceiling holds and reset "
         "clears the table") {
        ASSERT(mesh_term_fixture_open(&f, dir));
        fixture_open = true;
        memset(&cnode, 0, sizeof(cnode));
        cnode.transport = f.term_peer.ini;
        memset(&wnode, 0, sizeof(wnode));
        wnode.transport = f.status_peer.ini;
        boot_mesh_terminal_client_test_reset();

        struct mesh_terminal_open_v1
            opens[MESH_TERMINAL_CLIENT_SESSIONS_MAX + 1];
        uint8_t tids[sizeof(opens) / sizeof(opens[0])][32];
        uint64_t sids[sizeof(opens) / sizeof(opens[0])];
        for (size_t i = 0; i < sizeof(opens) / sizeof(opens[0]); i++) {
            mesh_term_compose_open(&f, &f.term_peer, CLIENT_TEST_NO_PAIRING,
                                   CLIENT_TEST_NOW() - 10, CLIENT_TEST_NOW() + 20,
                                   MESH_TERMINAL_CAP_TERMINAL_EXEC, &opens[i]);
            opens[i].terminal_id[0] = (uint8_t)(0x30 + i);
            ASSERT_EQ(client_test_inject_simple(&f, &opens[i], false, tids[i],
                                                &sids[i]),
                      i < MESH_TERMINAL_CLIENT_SESSIONS_MAX);
        }
        /* Every reserved session is OPENING with the requested geometry,
         * and the stream table holds exactly those streams. */
        ASSERT_EQ(mesh_stream_test_live_count(MESH_TERMINAL_SERVICE_NAME),
                  (size_t)MESH_TERMINAL_CLIENT_SESSIONS_MAX);
        struct boot_mesh_terminal_client_view view;
        for (size_t i = 0; i < MESH_TERMINAL_CLIENT_SESSIONS_MAX; i++) {
            ASSERT_EQ(boot_mesh_terminal_client_poll(tids[i], &view),
                      MESH_TERMINAL_CLIENT_OPENING);
            ASSERT_EQ(view.cols, 80);
            ASSERT_EQ(view.rows, 24);
            ASSERT_EQ(view.output_pending, (size_t)0);
        }
        boot_mesh_terminal_client_test_reset();
        ASSERT_EQ(boot_mesh_terminal_client_poll(tids[0], &view),
                  MESH_TERMINAL_CLIENT_UNKNOWN);
        ASSERT_EQ(mesh_stream_test_live_count(MESH_TERMINAL_SERVICE_NAME),
                  (size_t)0);
        PASS();
    }

    TEST("mesh terminal client: an OK receipt earned by the real responder "
         "decision arms the session, bound to the live Noise session") {
        ASSERT(mesh_term_pair_accept(&f, &f.term_peer,
                                     MESH_PAIRING_CAP_STATUS_READ |
                                         MESH_PAIRING_CAP_TERMINAL_EXEC));
        uint8_t pairing_id[32];
        ASSERT(zcl_hex_decode_lower(f.term_peer.pairing.pairing_id,
                                    pairing_id, 32));
        /* decide/compose are pure: run them on a fixed clock inside the
         * fixture's pairing validity window (2000..3000), as the responder
         * group does. The client lane's own watchdogs and injected session
         * times stay on the real clock. */
        uint64_t now = CLIENT_TEST_PAIR_NOW;

        struct mesh_terminal_open_v1 open;
        mesh_term_compose_open(&f, &f.term_peer, pairing_id, now - 10,
                               now + 20, MESH_TERMINAL_CAP_TERMINAL_EXEC,
                               &open);
        uint8_t tid[32];
        uint64_t sid = 0;
        ASSERT(client_test_inject_simple(&f, &open, false, tid, &sid));

        /* Before the receipt: OPENING, and screen data is refused. The
         * frame is delivered (the transport and the stream are real) but
         * nothing is accepted: the FIFO stays empty. */
        struct boot_mesh_terminal_client_view view;
        ASSERT_EQ(boot_mesh_terminal_client_poll(tid, &view),
                  MESH_TERMINAL_CLIENT_OPENING);
        uint8_t early[8];
        ASSERT(client_test_send_data(&f, &cnode, sid, tid, 1, "x", 1));
        ASSERT_EQ(boot_mesh_terminal_client_drain(tid, early, sizeof(early)),
                  (size_t)0);

        /* The production decision says OK; the signed receipt crosses the
         * live Noise record exactly as the wire carries it. */
        uint64_t rg = 99;
        ASSERT_EQ(boot_mesh_terminal_decide(&f.ndb, &open,
                                            &f.term_peer.res_snap,
                                            &f.term_peer.delegation, 1,
                                            f.genesis, now, &rg),
                  MESH_TERMINAL_RECEIPT_OK);
        uint8_t capsule[MESH_TERMINAL_CAPSULE_MAX];
        size_t capsule_len = 0;
        ASSERT(boot_mesh_terminal_render_grant_capsule(capsule,
                                                       &capsule_len));
        struct mesh_terminal_receipt_v1 receipt;
        ASSERT(boot_mesh_terminal_compose_receipt(
            &open, &f.term_peer.res_snap, MESH_TERMINAL_RECEIPT_OK, f.genesis,
            f.resp_master_pub, f.resp_online_pub, f.resp_noise_pub, rg, now,
            capsule, capsule_len, f.resp_online_seed, &receipt));
        uint8_t wire[MESH_TERMINAL_RECEIPT_V1_MAX_WIRE_BYTES];
        size_t wire_len = 0;
        ASSERT_EQ(mesh_terminal_receipt_v1_encode(&receipt, wire, sizeof(wire),
                                                  &wire_len),
                  MESH_TERMINAL_PROTO_OK);
        ASSERT(client_test_deliver(&f, &cnode, sid, MESH_TERMINAL_MSG_RECEIPT,
                                   wire, wire_len));
        ASSERT_EQ(boot_mesh_terminal_client_poll(tid, &view),
                  MESH_TERMINAL_CLIENT_LIVE);
        ASSERT_EQ(view.verdict, MESH_TERMINAL_RECEIPT_OK);
        ASSERT_EQ(view.bytes_in, UINT64_C(0));
        ASSERT_EQ(view.bytes_out, UINT64_C(0));

        /* A duplicate OK is refused, not re-armed or double-counted. */
        ASSERT(client_test_deliver(&f, &cnode, sid, MESH_TERMINAL_MSG_RECEIPT,
                                   wire, wire_len));
        ASSERT_EQ(boot_mesh_terminal_client_poll(tid, &view),
                  MESH_TERMINAL_CLIENT_LIVE);
        ASSERT_EQ(view.verdict, MESH_TERMINAL_RECEIPT_OK);

        /* A second session's receipt arriving over the WRONG peer
         * transport (a different remote static) is refused: the stream
         * ingress does not even find the stream on that session. */
        struct mesh_terminal_open_v1 open2 = open;
        open2.terminal_id[0] ^= 0xFF;
        uint8_t tid2[32];
        uint64_t sid2 = 0;
        ASSERT(client_test_inject_simple(&f, &open2, false, tid2, &sid2));
        struct mesh_terminal_receipt_v1 receipt2;
        uint8_t wire2[MESH_TERMINAL_RECEIPT_V1_MAX_WIRE_BYTES];
        size_t wire2_len = 0;
        ASSERT(boot_mesh_terminal_compose_receipt(
            &open2, &f.term_peer.res_snap, MESH_TERMINAL_RECEIPT_OK,
            f.genesis, f.resp_master_pub, f.resp_online_pub, f.resp_noise_pub,
            rg, now, capsule, capsule_len, f.resp_online_seed, &receipt2));
        ASSERT_EQ(mesh_terminal_receipt_v1_encode(&receipt2, wire2,
                                                  sizeof(wire2), &wire2_len),
                  MESH_TERMINAL_PROTO_OK);
        ASSERT(client_test_deliver_wrong_peer(&f, &wnode, sid2,
                                              MESH_TERMINAL_MSG_RECEIPT,
                                              wire2, wire2_len));
        ASSERT_EQ(boot_mesh_terminal_client_poll(tid2, &view),
                  MESH_TERMINAL_CLIENT_OPENING);
        PASS();
    }

    TEST("mesh terminal client: screen output obeys the sequence, the "
         "bounded FIFO, and the credit window that backs it") {
        boot_mesh_terminal_client_test_reset();
        struct mesh_terminal_open_v1 open;
        uint64_t now = CLIENT_TEST_NOW();
        mesh_term_compose_open(&f, &f.term_peer, CLIENT_TEST_NO_PAIRING,
                               now - 10, now + 20,
                               MESH_TERMINAL_CAP_TERMINAL_EXEC, &open);
        uint8_t tid[32];
        uint64_t sid = 0;
        ASSERT(client_test_inject_simple(&f, &open, true, tid, &sid));
        struct boot_mesh_terminal_client_view view;
        ASSERT_EQ(boot_mesh_terminal_client_poll(tid, &view),
                  MESH_TERMINAL_CLIENT_LIVE);

        ASSERT(client_test_send_data(&f, &cnode, sid, tid, 1, "hello ", 6));
        ASSERT(client_test_send_data(&f, &cnode, sid, tid, 2, "world", 5));
        uint8_t buf[256];
        /* The FIFO is byte-oriented: one drain carries both frames in
         * order, whatever the frame boundaries were. */
        ASSERT_EQ(boot_mesh_terminal_client_drain(tid, buf, sizeof(buf)),
                  (size_t)11);
        ASSERT(memcmp(buf, "hello world", 11) == 0);
        ASSERT_EQ(boot_mesh_terminal_client_drain(tid, buf, sizeof(buf)),
                  (size_t)0);
        ASSERT_EQ(boot_mesh_terminal_client_poll(tid, &view),
                  MESH_TERMINAL_CLIENT_LIVE);
        ASSERT_EQ(view.bytes_out, UINT64_C(11));

        /* A replayed frame is dropped: strictly increasing, not monotone
         * acceptance. */
        ASSERT(client_test_send_data(&f, &cnode, sid, tid, 2, "world", 5));
        ASSERT_EQ(boot_mesh_terminal_client_drain(tid, buf, sizeof(buf)),
                  (size_t)0);
        /* Gaps are accepted (the responder's drain chunks freely); an
         * OLDER frame after a gap is the replay that is dropped — only the
         * gap frame's byte reaches the FIFO. */
        ASSERT(client_test_send_data(&f, &cnode, sid, tid, 5, "!", 1));
        ASSERT(client_test_send_data(&f, &cnode, sid, tid, 3, "x", 1));
        ASSERT_EQ(boot_mesh_terminal_client_drain(tid, buf, sizeof(buf)),
                  (size_t)1);
        ASSERT(buf[0] == '!');

        /* Wrong peer transport: screen data from a different remote static
         * is dropped, whatever id it names. */
        struct mesh_terminal_data_v1 data;
        memset(&data, 0, sizeof(data));
        memcpy(data.terminal_id, tid, 32);
        data.seq = 9;
        data.payload_len = 1;
        data.payload[0] = 'Z';
        uint8_t wire[MESH_TERMINAL_DATA_V1_MAX_WIRE_BYTES];
        size_t wire_len = 0;
        ASSERT_EQ(mesh_terminal_data_v1_encode(&data, wire, sizeof(wire),
                                               &wire_len),
                  MESH_TERMINAL_PROTO_OK);
        ASSERT(client_test_deliver_wrong_peer(&f, &wnode, sid,
                                              MESH_TERMINAL_MSG_DATA, wire,
                                              wire_len));
        ASSERT_EQ(boot_mesh_terminal_client_drain(tid, buf, sizeof(buf)),
                  (size_t)0);

        /* Credit IS the FIFO: the reader's unread bytes are exactly the
         * credit the responder does not hold, so a full FIFO leaves a
         * compliant sender no room at all. Twenty-one whole 3072-byte
         * frames fill it. */
        uint8_t chunk[MESH_TERMINAL_DATA_PAYLOAD_MAX];
        memset(chunk, '.', sizeof(chunk));
        uint64_t seq = 10;
        const size_t full_frames =
            MESH_TERMINAL_CLIENT_OUTPUT_MAX / MESH_TERMINAL_DATA_PAYLOAD_MAX;
        for (size_t i = 0; i < full_frames; i++) {
            ASSERT(client_test_send_data(&f, &cnode, sid, tid, seq, chunk,
                                         sizeof(chunk)));
            seq++;
        }
        ASSERT_EQ(boot_mesh_terminal_client_poll(tid, &view),
                  MESH_TERMINAL_CLIENT_LIVE);
        ASSERT_EQ(view.output_pending,
                  full_frames * MESH_TERMINAL_DATA_PAYLOAD_MAX);
        ASSERT_EQ(view.bytes_out,
                  UINT64_C(12) + full_frames * MESH_TERMINAL_DATA_PAYLOAD_MAX);
        size_t drained = 0;
        for (;;) {
            uint8_t big[16384];
            size_t moved = boot_mesh_terminal_client_drain(tid, big,
                                                           sizeof(big));
            if (!moved)
                break;
            drained += moved;
        }
        ASSERT_EQ(drained, full_frames * MESH_TERMINAL_DATA_PAYLOAD_MAX);
        /* The drain handed the credit back: new output is accepted again. */
        ASSERT(client_test_send_data(&f, &cnode, sid, tid, seq, "ok", 2));
        seq++;
        ASSERT_EQ(boot_mesh_terminal_client_drain(tid, buf, sizeof(buf)),
                  (size_t)2);
        PASS();
    }

    TEST("mesh terminal client: a sender that spends credit it was never "
         "granted ends the stream by name") {
        boot_mesh_terminal_client_test_reset();
        struct mesh_terminal_open_v1 open;
        uint64_t now = CLIENT_TEST_NOW();
        mesh_term_compose_open(&f, &f.term_peer, CLIENT_TEST_NO_PAIRING,
                               now - 10, now + 20,
                               MESH_TERMINAL_CAP_TERMINAL_EXEC, &open);
        uint8_t tid[32];
        uint64_t sid = 0;
        ASSERT(client_test_inject_simple(&f, &open, true, tid, &sid));
        uint8_t chunk[MESH_TERMINAL_DATA_PAYLOAD_MAX];
        memset(chunk, '.', sizeof(chunk));
        uint64_t seq = 1;
        const size_t full_frames =
            MESH_TERMINAL_CLIENT_OUTPUT_MAX / MESH_TERMINAL_DATA_PAYLOAD_MAX;
        for (size_t i = 0; i < full_frames; i++) {
            ASSERT(client_test_send_data(&f, &cnode, sid, tid, seq, chunk,
                                         sizeof(chunk)));
            seq++;
        }
        struct boot_mesh_terminal_client_view view;
        ASSERT_EQ(boot_mesh_terminal_client_poll(tid, &view),
                  MESH_TERMINAL_CLIENT_LIVE);
        /* The reader has read nothing, so the window is spent. One more
         * whole frame is an overrun, and the stream ends by name instead
         * of quietly dropping the bytes. */
        ASSERT(client_test_send_data(&f, &cnode, sid, tid, seq, chunk,
                                     sizeof(chunk)));
        ASSERT_EQ(boot_mesh_terminal_client_poll(tid, &view),
                  MESH_TERMINAL_CLIENT_ENDED);
        ASSERT(view.close_reason_named);
        ASSERT_EQ(view.close_reason, MESH_TERMINAL_CLOSE_BYTE_LIMIT);
        PASS();
    }

    TEST("mesh terminal client: watchdogs end sessions by name") {
        boot_mesh_terminal_client_test_reset();
        struct boot_mesh_terminal_client_view view;
        uint64_t now = CLIENT_TEST_NOW();
        struct mesh_terminal_open_v1 open;
        mesh_term_compose_open(&f, &f.term_peer, CLIENT_TEST_NO_PAIRING,
                               now - 10, now + 20,
                               MESH_TERMINAL_CAP_TERMINAL_EXEC, &open);
        uint8_t tid[32];

        /* a) No receipt inside the answer window: REFUSED with the named
         * expired verdict. */
        open.terminal_id[0] = 0x41;
        ASSERT(boot_mesh_terminal_client_test_inject(
            &open, f.resp_master_pub, f.resp_online_pub,
            f.resp_noise_pub, NULL,
            now - MESH_TERMINAL_CLIENT_RECEIPT_TIMEOUT_SECONDS - 2, 0, false,
            tid, NULL));
        ASSERT_EQ(boot_mesh_terminal_client_poll(tid, &view),
                  MESH_TERMINAL_CLIENT_REFUSED);
        ASSERT_EQ(view.verdict, MESH_TERMINAL_RECEIPT_EXPIRED);

        /* b) A live session past its granted lifetime ends with the named
         * lifetime reason. */
        open.terminal_id[0] = 0x42;
        ASSERT(boot_mesh_terminal_client_test_inject(
            &open, f.resp_master_pub, f.resp_online_pub,
            f.resp_noise_pub, NULL,
            now - MESH_TERMINAL_SERVICE_LIFETIME_SECONDS - 2, 0, true, tid,
            NULL));
        ASSERT_EQ(boot_mesh_terminal_client_poll(tid, &view),
                  MESH_TERMINAL_CLIENT_ENDED);
        ASSERT(view.close_reason_named);
        ASSERT_EQ(view.close_reason, MESH_TERMINAL_CLOSE_LIFETIME_LIMIT);

        /* c) An idle-live session ends with the named idle reason. */
        open.terminal_id[0] = 0x43;
        ASSERT(boot_mesh_terminal_client_test_inject(
            &open, f.resp_master_pub, f.resp_online_pub,
            f.resp_noise_pub, NULL, now - 10,
            now - MESH_TERMINAL_SERVICE_IDLE_SECONDS - 2, true, tid, NULL));
        ASSERT_EQ(boot_mesh_terminal_client_poll(tid, &view),
                  MESH_TERMINAL_CLIENT_ENDED);
        ASSERT(view.close_reason_named);
        ASSERT_EQ(view.close_reason, MESH_TERMINAL_CLOSE_IDLE_TIMEOUT);

        /* d) A fresh live session trips no watchdog. */
        open.terminal_id[0] = 0x44;
        ASSERT(client_test_inject_simple(&f, &open, true, tid, NULL));
        ASSERT_EQ(boot_mesh_terminal_client_poll(tid, &view),
                  MESH_TERMINAL_CLIENT_LIVE);
        PASS();
    }

    TEST("mesh terminal client: refusal and CLOSED receipts and the "
         "responder's close end sessions by name") {
        boot_mesh_terminal_client_test_reset();
        struct boot_mesh_terminal_client_view view;
        uint64_t now = CLIENT_TEST_NOW();
        struct mesh_terminal_open_v1 open;
        mesh_term_compose_open(&f, &f.term_peer, CLIENT_TEST_NO_PAIRING,
                               now - 10, now + 20,
                               MESH_TERMINAL_CAP_TERMINAL_EXEC, &open);
        uint8_t wire[MESH_TERMINAL_RECEIPT_V1_MAX_WIRE_BYTES];
        size_t wire_len = 0;
        struct mesh_terminal_receipt_v1 receipt;
        uint8_t tid[32];
        uint64_t sid = 0;

        /* a) A refusal receipt is armed by the production composition and
         * ends the session as REFUSED with the named verdict. */
        open.terminal_id[0] = 0x51;
        ASSERT(client_test_inject_simple(&f, &open, false, tid, &sid));
        ASSERT(boot_mesh_terminal_compose_receipt(
            &open, &f.term_peer.res_snap, MESH_TERMINAL_RECEIPT_NOT_PAIRED,
            f.genesis, f.resp_master_pub, f.resp_online_pub, f.resp_noise_pub,
            0, now, NULL, 0, f.resp_online_seed, &receipt));
        ASSERT_EQ(mesh_terminal_receipt_v1_encode(&receipt, wire, sizeof(wire),
                                                  &wire_len),
                  MESH_TERMINAL_PROTO_OK);
        ASSERT(client_test_deliver(&f, &cnode, sid, MESH_TERMINAL_MSG_RECEIPT,
                                   wire, wire_len));
        ASSERT_EQ(boot_mesh_terminal_client_poll(tid, &view),
                  MESH_TERMINAL_CLIENT_REFUSED);
        ASSERT_EQ(view.verdict, MESH_TERMINAL_RECEIPT_NOT_PAIRED);

        /* b) A CLOSED receipt ends a LIVE session with the closed verdict
         * and NO locally invented close reason. */
        open.terminal_id[0] = 0x52;
        ASSERT(client_test_inject_simple(&f, &open, false, tid, &sid));
        uint8_t grant[MESH_TERMINAL_CAPSULE_MAX];
        size_t grant_len = 0;
        uint8_t evidence[MESH_TERMINAL_CAPSULE_MAX];
        size_t evidence_len = 0;
        ASSERT(boot_mesh_terminal_render_grant_capsule(grant, &grant_len));
        ASSERT(boot_mesh_terminal_render_close_capsule(
            11, 22, 33, MESH_TERMINAL_CLOSE_WORKER_EXITED, evidence,
            &evidence_len));
        ASSERT(boot_mesh_terminal_compose_receipt(
            &open, &f.term_peer.res_snap, MESH_TERMINAL_RECEIPT_OK, f.genesis,
            f.resp_master_pub, f.resp_online_pub, f.resp_noise_pub, 0, now,
            grant, grant_len, f.resp_online_seed, &receipt));
        ASSERT_EQ(mesh_terminal_receipt_v1_encode(&receipt, wire, sizeof(wire),
                                                  &wire_len),
                  MESH_TERMINAL_PROTO_OK);
        ASSERT(client_test_deliver(&f, &cnode, sid, MESH_TERMINAL_MSG_RECEIPT,
                                   wire, wire_len));
        ASSERT_EQ(boot_mesh_terminal_client_poll(tid, &view),
                  MESH_TERMINAL_CLIENT_LIVE);
        ASSERT(boot_mesh_terminal_compose_receipt(
            &open, &f.term_peer.res_snap, MESH_TERMINAL_RECEIPT_CLOSED,
            f.genesis, f.resp_master_pub, f.resp_online_pub, f.resp_noise_pub,
            0, now + 5, evidence, evidence_len, f.resp_online_seed, &receipt));
        ASSERT_EQ(mesh_terminal_receipt_v1_encode(&receipt, wire, sizeof(wire),
                                                  &wire_len),
                  MESH_TERMINAL_PROTO_OK);
        ASSERT(client_test_deliver(&f, &cnode, sid, MESH_TERMINAL_MSG_RECEIPT,
                                   wire, wire_len));
        ASSERT_EQ(boot_mesh_terminal_client_poll(tid, &view),
                  MESH_TERMINAL_CLIENT_ENDED);
        ASSERT_EQ(view.verdict, MESH_TERMINAL_RECEIPT_CLOSED);
        ASSERT(!view.close_reason_named);

        /* c) The responder's close names the reason locally: the close
         * message rides the stream CLOSE, exactly as the serving lane
         * ends a session. */
        open.terminal_id[0] = 0x53;
        ASSERT(client_test_inject_simple(&f, &open, true, tid, &sid));
        struct mesh_terminal_close_v1 close_frame;
        memset(&close_frame, 0, sizeof(close_frame));
        memcpy(close_frame.terminal_id, tid, 32);
        close_frame.reason = MESH_TERMINAL_CLOSE_WORKER_EXITED;
        uint8_t close_wire[MESH_TERMINAL_CLOSE_V1_WIRE_BYTES];
        ASSERT_EQ(mesh_terminal_close_v1_encode(&close_frame, close_wire),
                  MESH_TERMINAL_PROTO_OK);
        ASSERT(client_test_deliver_close(&f, &cnode, sid,
                                         MESH_TERMINAL_MSG_CLOSE, close_wire,
                                         sizeof(close_wire)));
        ASSERT_EQ(boot_mesh_terminal_client_poll(tid, &view),
                  MESH_TERMINAL_CLIENT_ENDED);
        ASSERT(view.close_reason_named);
        ASSERT_EQ(view.close_reason, MESH_TERMINAL_CLOSE_WORKER_EXITED);

        /* d) A close over the wrong peer transport ends nothing; a
         * foreign terminal id disturbs nothing. */
        open.terminal_id[0] = 0x54;
        ASSERT(client_test_inject_simple(&f, &open, true, tid, &sid));
        struct mesh_terminal_close_v1 junk;
        memset(&junk, 0, sizeof(junk));
        memcpy(junk.terminal_id, tid, 32);
        junk.terminal_id[0] ^= 0xFF; /* unknown id */
        junk.reason = MESH_TERMINAL_CLOSE_REQUESTED;
        uint8_t junk_close[MESH_TERMINAL_CLOSE_V1_WIRE_BYTES];
        ASSERT_EQ(mesh_terminal_close_v1_encode(&junk, junk_close),
                  MESH_TERMINAL_PROTO_OK);
        ASSERT(client_test_deliver_wrong_peer(&f, &wnode, sid,
                                              MESH_TERMINAL_MSG_CLOSE,
                                              junk_close,
                                              sizeof(junk_close)));
        ASSERT(client_test_deliver(&f, &cnode, sid, MESH_TERMINAL_MSG_CLOSE,
                                   junk_close, sizeof(junk_close)));
        ASSERT_EQ(boot_mesh_terminal_client_poll(tid, &view),
                  MESH_TERMINAL_CLIENT_LIVE);

        /* e) Frames with no session context at all (plaintext v1, no
         * transport) are dropped quietly, not trusted. */
        struct p2p_node bare;
        memset(&bare, 0, sizeof(bare));
        uint8_t msg[MESH_TERMINAL_MSG_MAX];
        size_t msg_len = boot_mesh_terminal_msg(MESH_TERMINAL_MSG_CLOSE,
                                                junk_close,
                                                sizeof(junk_close), msg,
                                                sizeof(msg));
        ASSERT(msg_len != 0);
        uint8_t frame[CLIENT_TEST_FRAME_MAX];
        size_t frame_len = mesh_stream_test_data_frame(sid, msg, msg_len,
                                                       frame, sizeof(frame));
        ASSERT(frame_len != 0);
        ASSERT(mesh_stream_frame(NULL, &bare, frame, frame_len, NULL));
        ASSERT_EQ(boot_mesh_terminal_client_poll(tid, &view),
                  MESH_TERMINAL_CLIENT_LIVE);
        PASS();
    }

_test_next:
    boot_mesh_terminal_client_test_reset();
    if (fixture_open)
        mesh_term_fixture_close(&f);
    test_rm_rf_recursive(dir);
    return failures;
}
