/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Proves the mesh terminal wire fails closed: the responder decision is
 * pairing-, capability-, and session-bound; the OK receipt carries the
 * granted session bounds and nothing else answers OK; CLOSED evidence
 * receipts bind the open even after its answer window; and the OPEN admit
 * gate rate-limits and refuses replays. Drives the exact production
 * decision and composition against a real node.db fixture, real Ed25519
 * keys, and real in-process Noise transports driven buffer-to-buffer (no
 * sockets), with two independently paired peers — one status-read only,
 * one carrying the commit-time terminal-exec capability — so the
 * capability gate is exercised at the wire layer AND through the real
 * pairing-service authorization. The terminal rides the mesh stream
 * primitive, so its wire frames are stream frames carrying one terminal
 * message each. The fixture primitives are shared with the requester-lane
 * group (mesh_term_fixture). */

#include "test/test_core.h"

#include "config/boot_mesh_terminal.h"
#include "config/mesh_stream.h"
#include "test/mesh_stream_fixture.h"
#include "test/mesh_term_fixture.h"
#include "base/hex.h"
#include "base/serialize_le.h"
#include "services/mesh_pairing_service.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <fcntl.h>
#include <unistd.h>
#endif

#define TERM_WIRE_NOW 2500

#if !defined(_WIN32)
/* ── Responder keyboard path: a shell that stops reading ───────────────
 * The worker is a fixture: a nonblocking pipe stands in for the pty, so a
 * full pipe is a shell that is not reading and /dev/full is a write that
 * fails for any other reason. The stream is a bare slot with no peer. */

#define KB_TERMINAL_FILL 0x44
#define KB_PAYLOAD 100u

[[maybe_unused]] static void kb_fill_pipe(int wfd)
{
    uint8_t chunk[4096];
    memset(chunk, KB_TERMINAL_FILL, sizeof(chunk));
    while (write(wfd, chunk, sizeof(chunk)) > 0) {}
    /* Single bytes until the kernel itself says the pipe is full: a failed
     * chunk write can leave room (macOS), and only EAGAIN proves it is full. */
    for (;;) {
        ssize_t n = write(wfd, chunk, 1);
        if (n > 0 || (n < 0 && errno == EINTR))
            continue;
        break;
    }
}

[[maybe_unused]] static size_t kb_drain_pipe(int rfd, uint8_t *last, size_t last_cap)
{
    uint8_t buf[4096];
    size_t total = 0;
    ssize_t n;
    while ((n = read(rfd, buf, sizeof(buf))) > 0) {
        total += (size_t)n;
        if (last_cap && (size_t)n >= last_cap)
            memcpy(last, buf + n - last_cap, last_cap);
    }
    return total;
}

/* One keyboard DATA stream message with a recognisable payload. */
[[maybe_unused]] static size_t kb_message(const uint8_t terminal_id[32], uint64_t seq,
                         uint8_t fill, uint8_t *msg, size_t cap)
{
    struct mesh_terminal_data_v1 frame;
    memset(&frame, 0, sizeof(frame));
    memcpy(frame.terminal_id, terminal_id, 32);
    frame.seq = seq;
    frame.payload_len = KB_PAYLOAD;
    memset(frame.payload, fill, KB_PAYLOAD);
    size_t wire_len = 0;
    if (cap < 1 + MESH_TERMINAL_DATA_V1_MAX_WIRE_BYTES ||
        mesh_terminal_data_v1_encode(&frame, msg + 1, cap - 1, &wire_len) !=
            MESH_TERMINAL_PROTO_OK)
        return 0;
    msg[0] = MESH_TERMINAL_MSG_DATA;
    return 1 + wire_len;
}

static void kb_worker(struct mesh_terminal_worker *w, int wfd)
{
    memset(w, 0, sizeof(*w));
    w->master_fd = wfd;
    w->running = true;
    w->max_bytes_in = UINT64_C(1) << 24;
    w->last_activity_unix = 1;
}

#if !defined(__linux__)
/* The terminal worker is the Linux confinement stack: elsewhere its input
 * is an honest refusal (UNSUPPORTED) and no pipe can stand in for a pty, so
 * a stalled shell cannot exist and the two stall cases below do not apply. */
static int kb_unsupported_case(void)
{
    int failures = 0, fds[2] = { -1, -1 };
    struct mesh_terminal_worker w;
    TEST("boot mesh terminal: off Linux the worker refuses keyboard input "
         "as unsupported, so there is no stalled shell to queue for") {
        ASSERT(pipe(fds) == 0);
        ASSERT(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);
        kb_worker(&w, fds[1]);
        w.input_nowait = true;
        uint8_t key = 0x71;
        struct zcl_result r = mesh_terminal_worker_input(&w, &key, 1, 1);
        ASSERT(!r.ok);
        ASSERT_EQ(r.code, (int)MESH_TERMINAL_WORKER_ERR_UNSUPPORTED);
        PASS();
    }
_test_next:
    if (fds[0] >= 0)
        close(fds[0]);
    if (fds[1] >= 0)
        close(fds[1]);
    return failures;
}
#endif

[[maybe_unused]] static int kb_stall_cases(void)
{
    int failures = 0, fds[2] = { -1, -1 };
    uint8_t tid[32], msg[MESH_TERMINAL_MSG_MAX], last[KB_PAYLOAD];
    struct mesh_stream st;
    struct mesh_terminal_worker w;
    memset(&st, 0, sizeof(st));
    memset(tid, 0x61, sizeof(tid));
    TEST("boot mesh terminal: keyboard bytes a stalled shell has not taken "
         "stay queued, their credit is withheld, and the tail drains later") {
        ASSERT(pipe(fds) == 0);
        ASSERT(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
        ASSERT(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);
        kb_worker(&w, fds[1]);
        st.used = true;
        st.service = MESH_STREAM_SERVICES_MAX - 1u; /* no service hooks */
        ASSERT(boot_mesh_terminal_test_attach(&st, &w, tid));
        kb_fill_pipe(fds[1]);
        size_t len = kb_message(tid, 1, 0x71, msg, sizeof(msg));
        ASSERT(len > KB_PAYLOAD);
        boot_mesh_terminal_test_on_data(&st, msg, len, 1000);
        /* Nothing waited, the session lives, the unwritten bytes are held
         * and only the framing overhead was returned. */
        ASSERT(!st.ended);
        ASSERT_EQ(boot_mesh_terminal_test_tail_len(&st), (size_t)KB_PAYLOAD);
        ASSERT_EQ(st.recv_credit, (uint32_t)(len - KB_PAYLOAD));
        /* The shell reads again: the next tick moves the tail in order and
         * returns the rest of the credit. */
        ASSERT(kb_drain_pipe(fds[0], NULL, 0) > 0);
        boot_mesh_terminal_test_retry_tail(&st, 2000);
        ASSERT_EQ(boot_mesh_terminal_test_tail_len(&st), (size_t)0);
        ASSERT_EQ(st.recv_credit, (uint32_t)len);
        ASSERT_EQ(kb_drain_pipe(fds[0], last, sizeof(last)),
                  (size_t)KB_PAYLOAD);
        uint8_t want[KB_PAYLOAD];
        memset(want, 0x71, sizeof(want));
        ASSERT(memcmp(last, want, sizeof(want)) == 0);
        PASS();
    }
_test_next:
    if (fds[0] >= 0)
        close(fds[0]);
    if (fds[1] >= 0)
        close(fds[1]);
    boot_mesh_terminal_test_detach(&st);
    return failures;
}

[[maybe_unused]] static int kb_deadline_cases(void)
{
    int failures = 0, fds[2] = { -1, -1 };
    uint8_t tid[32], msg[MESH_TERMINAL_MSG_MAX];
    struct mesh_stream st;
    struct mesh_terminal_worker w;
    memset(&st, 0, sizeof(st));
    memset(tid, 0x62, sizeof(tid));
    TEST("boot mesh terminal: a tail stuck past the deadline ends the "
         "session as session-lost") {
        ASSERT(pipe(fds) == 0);
        ASSERT(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);
        kb_worker(&w, fds[1]);
        st.used = true;
        st.service = MESH_STREAM_SERVICES_MAX - 1u;
        ASSERT(boot_mesh_terminal_test_attach(&st, &w, tid));
        kb_fill_pipe(fds[1]);
        size_t len = kb_message(tid, 1, 0x72, msg, sizeof(msg));
        ASSERT(len > 0);
        boot_mesh_terminal_test_on_data(&st, msg, len, 10000);
        boot_mesh_terminal_test_retry_tail(
            &st, 10000 + MESH_TERMINAL_INPUT_STALL_MS - 1);
        ASSERT(!st.ended);
        boot_mesh_terminal_test_retry_tail(
            &st, 10000 + MESH_TERMINAL_INPUT_STALL_MS);
        ASSERT(st.ended);
        ASSERT_EQ(boot_mesh_terminal_test_close_reason(&st),
                  (int)MESH_TERMINAL_CLOSE_SESSION_LOST);
        PASS();
    }
_test_next:
    if (fds[0] >= 0)
        close(fds[0]);
    if (fds[1] >= 0)
        close(fds[1]);
    boot_mesh_terminal_test_detach(&st);
    return failures;
}

static int kb_exited_cases(void)
{
    int failures = 0;
#if defined(__APPLE__)
    /* macOS has no /dev/full: a read-only descriptor makes write fail with
     * EBADF, which the worker also reports as a non-stall IO error. */
    int fd = open("/dev/null", O_RDONLY | O_NONBLOCK);
#else
    int fd = open("/dev/full", O_WRONLY | O_NONBLOCK);
#endif
    uint8_t tid[32], msg[MESH_TERMINAL_MSG_MAX];
    struct mesh_stream st;
    struct mesh_terminal_worker w;
    memset(&st, 0, sizeof(st));
    memset(tid, 0x63, sizeof(tid));
    TEST("boot mesh terminal: a write that fails for any reason but a stall "
         "leaves the session to the tick, which names the shell's exit") {
        ASSERT(fd >= 0);
        kb_worker(&w, fd);
        st.used = true;
        st.service = MESH_STREAM_SERVICES_MAX - 1u;
        ASSERT(boot_mesh_terminal_test_attach(&st, &w, tid));
        int reason_before = boot_mesh_terminal_test_close_reason(&st);
        size_t len = kb_message(tid, 1, 0x73, msg, sizeof(msg));
        ASSERT(len > 0);
        boot_mesh_terminal_test_on_data(&st, msg, len, 1000);
        ASSERT(!st.ended);
        ASSERT_EQ(boot_mesh_terminal_test_close_reason(&st), reason_before);
        ASSERT_EQ(boot_mesh_terminal_test_tail_len(&st), (size_t)0);
        ASSERT_EQ(st.recv_credit, (uint32_t)len);
        PASS();
    }
_test_next:
    if (fd >= 0)
        close(fd);
    boot_mesh_terminal_test_detach(&st);
    return failures;
}
#endif

int test_boot_mesh_terminal(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "boot_mesh_terminal", "wire");
    struct mesh_term_fixture f;
    bool fixture_open = false;

#if !defined(_WIN32)
#if defined(__linux__)
    failures += kb_stall_cases();
    failures += kb_deadline_cases();
#else
    failures += kb_unsupported_case();
#endif
    failures += kb_exited_cases();
#endif

    TEST("boot mesh terminal: the flag x shell x platform matrix decides the "
         "lane") {
        static const struct {
            enum mesh_terminal_platform platform;
            const char *shell;
            bool accept;
            bool enabled;
            bool unconfined;
            const char *why;
        } rows[] = {
            { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\Windows\\cmd.exe", false,
              false, false, "windows-shell-identity-unconfined" },
            { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\Windows\\cmd.exe", true,
              true, true, NULL },
            { MESH_TERMINAL_PLATFORM_WINDOWS, "/bin/sh", true, false, false,
              "shell-path-invalid" },
            { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\nul.exe", true, false,
              false, "shell-path-invalid" },
            { MESH_TERMINAL_PLATFORM_WINDOWS, "", true, false, false, NULL },
            { MESH_TERMINAL_PLATFORM_WINDOWS, "", false, false, false, NULL },
            { MESH_TERMINAL_PLATFORM_POSIX, "/bin/sh", false, true, false,
              NULL },
            { MESH_TERMINAL_PLATFORM_POSIX, "/bin/sh", true, false, false,
              "unconfined-opt-in-windows-only" },
            { MESH_TERMINAL_PLATFORM_POSIX, "", true, false, false,
              "unconfined-opt-in-windows-only" },
            { MESH_TERMINAL_PLATFORM_POSIX, "sh", false, false, false,
              "shell-path-invalid" },
            { MESH_TERMINAL_PLATFORM_POSIX, "", false, false, false, NULL },
        };
        for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
            char out[600];
            bool unconfined = true;
            const char *why = "unset";
            bool enabled = boot_mesh_terminal_configure(
                rows[i].platform, rows[i].shell, rows[i].accept, out,
                sizeof(out), &unconfined, &why);
            ASSERT(enabled == rows[i].enabled);
            ASSERT(unconfined == rows[i].unconfined);
            ASSERT((why == NULL) == (rows[i].why == NULL));
            ASSERT(!why || strcmp(why, rows[i].why) == 0);
            ASSERT(enabled ? strcmp(out, rows[i].shell) == 0 : out[0] == 0);
        }
    }

    TEST("boot mesh terminal: stream frame dispatch claims only the stream "
         "namespace") {
        ASSERT(mesh_term_fixture_open(&f, dir));
        fixture_open = true;
        const uint8_t other[] = "ZMSTAT\x01 garbage";
        ASSERT(!mesh_stream_frame(NULL, NULL, other, sizeof(other), NULL));
        const uint8_t ours[] = "ZSTRM\x7f garbage";
        ASSERT(mesh_stream_frame(NULL, NULL, ours, sizeof(ours), NULL));
        /* Prefix alone is shorter than prefix+kind: not a frame. */
        ASSERT(!mesh_stream_frame(NULL, NULL, (const uint8_t *)"ZSTRM",
                                  MESH_STREAM_FRAME_PREFIX_LEN, NULL));
        PASS();
    }

    TEST("boot mesh terminal: an unpaired open is refused by name and the "
         "refusal receipt binds the open") {
        struct mesh_terminal_open_v1 open;
        uint8_t unknown_pairing[32];
        mesh_term_fill32(unknown_pairing, 0xEE);
        mesh_term_compose_open(&f, &f.term_peer, unknown_pairing,
                               TERM_WIRE_NOW - 10,
                               TERM_WIRE_NOW + 20, MESH_TERMINAL_CAP_TERMINAL_EXEC,
                               &open);
        uint64_t rg = 99;
        ASSERT_EQ(boot_mesh_terminal_decide(&f.ndb, &open,
                                            &f.term_peer.res_snap,
                                            &f.term_peer.delegation, 1,
                                            f.genesis, TERM_WIRE_NOW, &rg),
                  MESH_TERMINAL_RECEIPT_NOT_PAIRED);
        ASSERT_EQ(rg, UINT64_C(0));
        struct mesh_terminal_receipt_v1 receipt;
        ASSERT(boot_mesh_terminal_compose_receipt(
            &open, &f.term_peer.res_snap, MESH_TERMINAL_RECEIPT_NOT_PAIRED,
            f.genesis, f.resp_master_pub, f.resp_online_pub,
            f.resp_noise_pub, 0, TERM_WIRE_NOW, NULL, 0, f.resp_online_seed,
            &receipt));
        ASSERT_EQ(receipt.capsule_len, 0);
        ASSERT_EQ(receipt.observed_unix, (uint64_t)TERM_WIRE_NOW);
        ASSERT_EQ(mesh_terminal_receipt_v1_matches_open(&receipt, &open),
                  MESH_TERMINAL_PROTO_OK);
        PASS();
    }

    TEST("boot mesh terminal: a non-terminal capability is refused at the "
         "wire before any pairing work") {
        struct mesh_terminal_open_v1 open;
        uint8_t unknown_pairing[32];
        mesh_term_fill32(unknown_pairing, 0xEE);
        mesh_term_compose_open(&f, &f.term_peer, unknown_pairing,
                               TERM_WIRE_NOW - 10,
                               TERM_WIRE_NOW + 20,
                               UINT64_C(1) /* status-read: this lane grants none */,
                               &open);
        uint64_t rg = 0;
        ASSERT_EQ(boot_mesh_terminal_decide(&f.ndb, &open,
                                            &f.term_peer.res_snap,
                                            &f.term_peer.delegation, 1,
                                            f.genesis, TERM_WIRE_NOW, &rg),
                  MESH_TERMINAL_RECEIPT_CAPABILITY_UNAVAILABLE);
        PASS();
    }

    TEST("boot mesh terminal: the commit-time capability gate holds — a "
         "status-read pairing cannot open a terminal") {
        ASSERT(mesh_term_pair_accept(&f, &f.status_peer,
                                     MESH_PAIRING_CAP_STATUS_READ));
        uint8_t pairing_id[32];
        ASSERT(zcl_hex_decode_lower(f.status_peer.pairing.pairing_id,
                                    pairing_id, 32));
        struct mesh_terminal_open_v1 open;
        mesh_term_compose_open(&f, &f.status_peer, pairing_id,
                               TERM_WIRE_NOW - 10,
                               TERM_WIRE_NOW + 20, MESH_TERMINAL_CAP_TERMINAL_EXEC,
                               &open);
        uint64_t rg = 0;
        ASSERT_EQ(boot_mesh_terminal_decide(&f.ndb, &open,
                                            &f.status_peer.res_snap,
                                            &f.status_peer.delegation, 1,
                                            f.genesis, TERM_WIRE_NOW, &rg),
                  MESH_TERMINAL_RECEIPT_CAPABILITY_UNAVAILABLE);
        PASS();
    }

    TEST("boot mesh terminal: a terminal-capability pairing earns a bound "
         "OK receipt carrying the grant capsule, proven over a live Noise "
         "record") {
        ASSERT(mesh_term_pair_accept(&f, &f.term_peer,
                                     MESH_PAIRING_CAP_STATUS_READ |
                                         MESH_PAIRING_CAP_TERMINAL_EXEC));
        uint8_t pairing_id[32];
        ASSERT(zcl_hex_decode_lower(f.term_peer.pairing.pairing_id,
                                    pairing_id, 32));
        struct mesh_terminal_open_v1 open;
        mesh_term_compose_open(&f, &f.term_peer, pairing_id,
                               TERM_WIRE_NOW - 10,
                               TERM_WIRE_NOW + 20, MESH_TERMINAL_CAP_TERMINAL_EXEC,
                               &open);
        uint64_t rg = 99;
        ASSERT_EQ(boot_mesh_terminal_decide(&f.ndb, &open,
                                            &f.term_peer.res_snap,
                                            &f.term_peer.delegation, 1,
                                            f.genesis, TERM_WIRE_NOW, &rg),
                  MESH_TERMINAL_RECEIPT_OK);
        ASSERT_EQ(rg, UINT64_C(0));

        /* Pairing ids are per-side: the open's pairing_id names the
         * requester's own row, which the responder does not hold. The
         * decision keys the row the live delegation names, so a garbage
         * claim must not flip the verdict — this is the two-node shape,
         * where the two sides' ids legitimately differ. */
        uint8_t requester_side_claim[32];
        mesh_term_fill32(requester_side_claim, 0x77);
        memcpy(open.pairing_id, requester_side_claim, 32);
        ASSERT_EQ(boot_mesh_terminal_decide(&f.ndb, &open,
                                            &f.term_peer.res_snap,
                                            &f.term_peer.delegation, 1,
                                            f.genesis, TERM_WIRE_NOW, &rg),
                  MESH_TERMINAL_RECEIPT_OK);

        uint8_t capsule[MESH_TERMINAL_CAPSULE_MAX];
        size_t capsule_len = 0;
        ASSERT(boot_mesh_terminal_render_grant_capsule(capsule,
                                                       &capsule_len));
        /* The grant is honest compact JSON naming the schema and the exact
         * served budgets. */
        char text[MESH_TERMINAL_CAPSULE_MAX + 1];
        ASSERT(mesh_term_capsule_text(capsule, capsule_len, text,
                                      sizeof(text)));
        ASSERT(strstr(text, "{\"schema\":\"zcl.terminal_grant.v1\"") != NULL);
        ASSERT(strstr(text, "\"max_bytes_in\":16777216") != NULL);
        ASSERT(strstr(text, "\"max_bytes_out\":1073741824") != NULL);
        ASSERT(strstr(text, "terminal_confinement") == NULL);

        /* The owner-accepted marker is additive: same schema prefix, same
         * budgets, one extra key. */
        uint8_t marked[MESH_TERMINAL_CAPSULE_MAX];
        size_t marked_len = 0;
        char marked_text[MESH_TERMINAL_CAPSULE_MAX + 1];
        ASSERT(boot_mesh_terminal_render_grant_capsule_marked(
            MESH_TERMINAL_CONFINEMENT_UNCONFINED, marked, &marked_len));
        ASSERT(mesh_term_capsule_text(marked, marked_len, marked_text,
                                      sizeof(marked_text)));
        ASSERT(strstr(marked_text, "{\"schema\":\"zcl.terminal_grant.v1\"") !=
               NULL);
        ASSERT(strstr(marked_text, "\"max_bytes_in\":16777216") != NULL);
        ASSERT(strstr(marked_text,
                      "\"terminal_confinement\":\"unconfined-owner-accepted\"") !=
               NULL);

        struct mesh_terminal_receipt_v1 receipt;
        ASSERT(boot_mesh_terminal_compose_receipt(
            &open, &f.term_peer.res_snap, MESH_TERMINAL_RECEIPT_OK, f.genesis,
            f.resp_master_pub, f.resp_online_pub, f.resp_noise_pub,
            rg, TERM_WIRE_NOW, capsule, capsule_len, f.resp_online_seed,
            &receipt));
        ASSERT_EQ(receipt.capsule_len, (uint16_t)capsule_len);
        ASSERT_EQ(receipt.observed_unix, (uint64_t)TERM_WIRE_NOW);
        ASSERT(receipt.expires_unix > receipt.observed_unix);
        ASSERT(receipt.expires_unix <= open.expires_unix);
        ASSERT_EQ(mesh_terminal_receipt_v1_matches_open(&receipt, &open),
                  MESH_TERMINAL_PROTO_OK);

        /* The exact wire the responder puts on the link: one stream DATA
         * frame carrying the terminal's receipt message. */
        uint8_t receipt_wire[MESH_TERMINAL_RECEIPT_V1_MAX_WIRE_BYTES];
        size_t receipt_len = 0;
        ASSERT_EQ(mesh_terminal_receipt_v1_encode(&receipt, receipt_wire,
                                                  sizeof(receipt_wire),
                                                  &receipt_len),
                  MESH_TERMINAL_PROTO_OK);
        uint8_t msg[MESH_TERMINAL_MSG_MAX];
        ASSERT(1u + receipt_len <= sizeof(msg));
        msg[0] = MESH_TERMINAL_MSG_RECEIPT;
        memcpy(msg + 1, receipt_wire, receipt_len);
        uint8_t frame[MESH_TERMINAL_MSG_MAX + 64u];
        size_t frame_len = mesh_stream_test_data_frame(2, msg,
                                                       1u + receipt_len,
                                                       frame, sizeof(frame));
        ASSERT(frame_len != 0);
        uint8_t delivered[sizeof(frame)];
        ASSERT(mesh_term_frame_roundtrip(f.res_term, f.term_peer.ini, frame,
                                         frame_len, delivered,
                                         sizeof(delivered)));
        uint8_t kind = 0;
        uint64_t stream_id = 0;
        ASSERT(mesh_stream_test_read_header(delivered, frame_len, &kind,
                                            &stream_id));
        ASSERT_EQ(kind, MESH_STREAM_KIND_DATA);
        ASSERT_EQ(stream_id, UINT64_C(2));
        const uint8_t *body =
            delivered + MESH_STREAM_FRAME_PREFIX_LEN + 1u + 8u;
        ASSERT_EQ((size_t)zcl_read_u16_le(body), 1u + receipt_len);
        ASSERT_EQ(body[2], MESH_TERMINAL_MSG_RECEIPT);
        struct mesh_terminal_receipt_v1 decoded;
        ASSERT_EQ(mesh_terminal_receipt_v1_decode(&decoded, body + 3,
                                                  receipt_len),
                  MESH_TERMINAL_PROTO_OK);
        ASSERT_EQ(mesh_terminal_receipt_v1_matches_open(&decoded, &open),
                  MESH_TERMINAL_PROTO_OK);
        PASS();
    }

    TEST("boot mesh terminal: window, session binding, genesis, and "
         "delegation failures are named") {
        uint8_t pairing_id[32];
        ASSERT(zcl_hex_decode_lower(f.term_peer.pairing.pairing_id,
                                    pairing_id, 32));
        struct mesh_terminal_open_v1 open;
        uint64_t rg;

        /* Expired window (past). */
        mesh_term_compose_open(&f, &f.term_peer, pairing_id,
                               TERM_WIRE_NOW - 55,
                               TERM_WIRE_NOW - 5, MESH_TERMINAL_CAP_TERMINAL_EXEC,
                               &open);
        ASSERT_EQ(boot_mesh_terminal_decide(&f.ndb, &open,
                                            &f.term_peer.res_snap,
                                            &f.term_peer.delegation, 1,
                                            f.genesis, TERM_WIRE_NOW, &rg),
                  MESH_TERMINAL_RECEIPT_EXPIRED);
        /* Not yet issued (future). */
        mesh_term_compose_open(&f, &f.term_peer, pairing_id,
                               TERM_WIRE_NOW + 10,
                               TERM_WIRE_NOW + 30, MESH_TERMINAL_CAP_TERMINAL_EXEC,
                               &open);
        ASSERT_EQ(boot_mesh_terminal_decide(&f.ndb, &open,
                                            &f.term_peer.res_snap,
                                            &f.term_peer.delegation, 1,
                                            f.genesis, TERM_WIRE_NOW, &rg),
                  MESH_TERMINAL_RECEIPT_EXPIRED);
        /* Window above the 60-second ceiling fails validate. */
        mesh_term_compose_open(&f, &f.term_peer, pairing_id,
                               TERM_WIRE_NOW - 10,
                               TERM_WIRE_NOW + 51, MESH_TERMINAL_CAP_TERMINAL_EXEC,
                               &open);
        ASSERT_EQ(boot_mesh_terminal_decide(&f.ndb, &open,
                                            &f.term_peer.res_snap,
                                            &f.term_peer.delegation, 1,
                                            f.genesis, TERM_WIRE_NOW, &rg),
                  MESH_TERMINAL_RECEIPT_BAD_REQUEST);
        /* Session binding: wrong transcript. */
        mesh_term_compose_open(&f, &f.term_peer, pairing_id,
                               TERM_WIRE_NOW - 10,
                               TERM_WIRE_NOW + 20, MESH_TERMINAL_CAP_TERMINAL_EXEC,
                               &open);
        open.transcript_hash[0] ^= 0xFF;
        ASSERT_EQ(boot_mesh_terminal_decide(&f.ndb, &open,
                                            &f.term_peer.res_snap,
                                            &f.term_peer.delegation, 1,
                                            f.genesis, TERM_WIRE_NOW, &rg),
                  MESH_TERMINAL_RECEIPT_SESSION_MISMATCH);
        /* Wrong connection generation. */
        mesh_term_compose_open(&f, &f.term_peer, pairing_id,
                               TERM_WIRE_NOW - 10,
                               TERM_WIRE_NOW + 20, MESH_TERMINAL_CAP_TERMINAL_EXEC,
                               &open);
        open.connection_generation++;
        ASSERT_EQ(boot_mesh_terminal_decide(&f.ndb, &open,
                                            &f.term_peer.res_snap,
                                            &f.term_peer.delegation, 1,
                                            f.genesis, TERM_WIRE_NOW, &rg),
                  MESH_TERMINAL_RECEIPT_SESSION_MISMATCH);
        /* Wrong requester static. */
        mesh_term_compose_open(&f, &f.term_peer, pairing_id,
                               TERM_WIRE_NOW - 10,
                               TERM_WIRE_NOW + 20, MESH_TERMINAL_CAP_TERMINAL_EXEC,
                               &open);
        open.requester_noise_static[0] ^= 0xFF;
        ASSERT_EQ(boot_mesh_terminal_decide(&f.ndb, &open,
                                            &f.term_peer.res_snap,
                                            &f.term_peer.delegation, 1,
                                            f.genesis, TERM_WIRE_NOW, &rg),
                  MESH_TERMINAL_RECEIPT_SESSION_MISMATCH);
        /* Foreign genesis names no authority here. */
        mesh_term_compose_open(&f, &f.term_peer, pairing_id,
                               TERM_WIRE_NOW - 10,
                               TERM_WIRE_NOW + 20, MESH_TERMINAL_CAP_TERMINAL_EXEC,
                               &open);
        uint8_t foreign[32];
        mesh_term_fill32(foreign, 0x42);
        ASSERT_EQ(boot_mesh_terminal_decide(&f.ndb, &open,
                                            &f.term_peer.res_snap,
                                            &f.term_peer.delegation, 1,
                                            foreign, TERM_WIRE_NOW, &rg),
                  MESH_TERMINAL_RECEIPT_NOT_PAIRED);
        /* No held delegation for the session peer. */
        mesh_term_compose_open(&f, &f.term_peer, pairing_id,
                               TERM_WIRE_NOW - 10,
                               TERM_WIRE_NOW + 20, MESH_TERMINAL_CAP_TERMINAL_EXEC,
                               &open);
        ASSERT_EQ(boot_mesh_terminal_decide(&f.ndb, &open,
                                            &f.term_peer.res_snap, NULL, 0,
                                            f.genesis, TERM_WIRE_NOW, &rg),
                  MESH_TERMINAL_RECEIPT_DELEGATION_INVALID);
        /* Two matching delegations are ambiguous. */
        struct vcs_zcode_dht_delegation twice[2] = {
            f.term_peer.delegation,
            f.term_peer.delegation,
        };
        mesh_term_compose_open(&f, &f.term_peer, pairing_id,
                               TERM_WIRE_NOW - 10,
                               TERM_WIRE_NOW + 20, MESH_TERMINAL_CAP_TERMINAL_EXEC,
                               &open);
        ASSERT_EQ(boot_mesh_terminal_decide(&f.ndb, &open,
                                            &f.term_peer.res_snap, twice, 2,
                                            f.genesis, TERM_WIRE_NOW, &rg),
                  MESH_TERMINAL_RECEIPT_DELEGATION_INVALID);
        /* Unestablished session and absent db are internal. */
        mesh_term_compose_open(&f, &f.term_peer, pairing_id,
                               TERM_WIRE_NOW - 10,
                               TERM_WIRE_NOW + 20, MESH_TERMINAL_CAP_TERMINAL_EXEC,
                               &open);
        struct noise_transport_snapshot unestablished = f.term_peer.res_snap;
        unestablished.established = false;
        ASSERT_EQ(boot_mesh_terminal_decide(&f.ndb, &open, &unestablished,
                                            &f.term_peer.delegation, 1,
                                            f.genesis, TERM_WIRE_NOW, &rg),
                  MESH_TERMINAL_RECEIPT_INTERNAL);
        ASSERT_EQ(boot_mesh_terminal_decide(NULL, &open,
                                            &f.term_peer.res_snap,
                                            &f.term_peer.delegation, 1,
                                            f.genesis, TERM_WIRE_NOW, &rg),
                  MESH_TERMINAL_RECEIPT_INTERNAL);
        PASS();
    }

    TEST("boot mesh terminal: CLOSED evidence receipts bind the open after "
         "its answer window, and refusals stay bare") {
        uint8_t pairing_id[32];
        ASSERT(zcl_hex_decode_lower(f.term_peer.pairing.pairing_id,
                                    pairing_id, 32));
        struct mesh_terminal_open_v1 open;
        mesh_term_compose_open(&f, &f.term_peer, pairing_id,
                               TERM_WIRE_NOW - 10,
                               TERM_WIRE_NOW + 20, MESH_TERMINAL_CAP_TERMINAL_EXEC,
                               &open);

        uint8_t capsule[MESH_TERMINAL_CAPSULE_MAX];
        size_t capsule_len = 0;
        ASSERT(boot_mesh_terminal_render_close_capsule(
            1234, 5678, 42, MESH_TERMINAL_CLOSE_REQUESTED, capsule,
            &capsule_len));
        char text[MESH_TERMINAL_CAPSULE_MAX + 1];
        ASSERT(mesh_term_capsule_text(capsule, capsule_len, text,
                                      sizeof(text)));
        ASSERT(strstr(text, "{\"schema\":\"zcl.terminal_close_evidence.v1\"") !=
               NULL);
        ASSERT(strstr(text, "\"bytes_in\":1234") != NULL);
        ASSERT(strstr(text, "\"bytes_out\":5678") != NULL);
        ASSERT(strstr(text, "\"reason\":\"requested\"") != NULL);

        /* A session runs far longer than the open's 60-second answer
         * window: the CLOSED receipt lands past open.expires and still
         * binds on observed >= issued alone. */
        uint64_t late = open.expires_unix + 10;
        struct mesh_terminal_receipt_v1 closed;
        ASSERT(boot_mesh_terminal_compose_receipt(
            &open, &f.term_peer.res_snap, MESH_TERMINAL_RECEIPT_CLOSED,
            f.genesis, f.resp_master_pub, f.resp_online_pub,
            f.resp_noise_pub, 0, late, capsule, capsule_len,
            f.resp_online_seed, &closed));
        ASSERT(closed.observed_unix > open.expires_unix);
        ASSERT_EQ(mesh_terminal_receipt_v1_matches_open(&closed, &open),
                  MESH_TERMINAL_PROTO_OK);

        /* A CLOSED receipt predating the open's issue is TIME. */
        struct mesh_terminal_receipt_v1 mistimed;
        ASSERT(boot_mesh_terminal_compose_receipt(
            &open, &f.term_peer.res_snap, MESH_TERMINAL_RECEIPT_CLOSED,
            f.genesis, f.resp_master_pub, f.resp_online_pub,
            f.resp_noise_pub, 0, (uint64_t)open.issued_unix - 5, capsule,
            capsule_len, f.resp_online_seed, &mistimed));
        ASSERT_EQ(mesh_terminal_receipt_v1_matches_open(&mistimed, &open),
                  MESH_TERMINAL_PROTO_TIME);

        /* A receipt bound to a DIFFERENT open is FIELD, not a match. */
        struct mesh_terminal_open_v1 other_open;
        mesh_term_compose_open(&f, &f.term_peer, pairing_id,
                               TERM_WIRE_NOW - 10,
                               TERM_WIRE_NOW + 20, MESH_TERMINAL_CAP_TERMINAL_EXEC,
                               &other_open);
        other_open.terminal_id[0] ^= 0xFF;
        ASSERT_EQ(mesh_terminal_receipt_v1_matches_open(&closed, &other_open),
                  MESH_TERMINAL_PROTO_FIELD);

        /* OK and CLOSED without a capsule are refused at compose. */
        struct mesh_terminal_receipt_v1 bad;
        ASSERT(!boot_mesh_terminal_compose_receipt(
            &open, &f.term_peer.res_snap, MESH_TERMINAL_RECEIPT_OK, f.genesis,
            f.resp_master_pub, f.resp_online_pub, f.resp_noise_pub, 0,
            TERM_WIRE_NOW, NULL, 0, f.resp_online_seed, &bad));
        ASSERT(!boot_mesh_terminal_compose_receipt(
            &open, &f.term_peer.res_snap, MESH_TERMINAL_RECEIPT_CLOSED,
            f.genesis, f.resp_master_pub, f.resp_online_pub,
            f.resp_noise_pub, 0, late, NULL, 0, f.resp_online_seed, &bad));
        /* A refusal status is composed bare however the caller argues:
         * capsule bytes are dropped, not leaked. */
        const uint8_t junk[] = "{\"attacker\":true}";
        ASSERT(boot_mesh_terminal_compose_receipt(
            &open, &f.term_peer.res_snap, MESH_TERMINAL_RECEIPT_REVOKED,
            f.genesis, f.resp_master_pub, f.resp_online_pub,
            f.resp_noise_pub, 0, TERM_WIRE_NOW, junk, sizeof(junk) - 1,
            f.resp_online_seed, &bad));
        ASSERT_EQ(bad.capsule_len, 0);
        PASS();
    }

    TEST("boot mesh terminal: close evidence carries exactly one remote "
         "status for worker-exited, and the signed receipt verifies "
         "unchanged") {
        uint8_t pairing_id[32];
        ASSERT(zcl_hex_decode_lower(f.term_peer.pairing.pairing_id,
                                    pairing_id, 32));
        struct mesh_terminal_open_v1 open;
        mesh_term_compose_open(&f, &f.term_peer, pairing_id,
                               TERM_WIRE_NOW - 10, TERM_WIRE_NOW + 20,
                               MESH_TERMINAL_CAP_TERMINAL_EXEC, &open);
        uint8_t capsule[MESH_TERMINAL_CAPSULE_MAX];
        uint8_t legacy[MESH_TERMINAL_CAPSULE_MAX];
        size_t capsule_len = 0, legacy_len = 0;
        char text[MESH_TERMINAL_CAPSULE_MAX + 1];

        ASSERT(boot_mesh_terminal_render_close_capsule_status(
            1, 2, 3, MESH_TERMINAL_CLOSE_WORKER_EXITED, 3, 0, capsule,
            &capsule_len));
        ASSERT(mesh_term_capsule_text(capsule, capsule_len, text,
                                      sizeof(text)));
        ASSERT(strstr(text, "\"reason\":\"worker-exited\"") != NULL);
        ASSERT(strstr(text, "\"exit_code\":3") != NULL);
        ASSERT(strstr(text, "\"signal\"") == NULL);
        ASSERT(boot_mesh_terminal_render_close_capsule_status(
            1, 2, 3, MESH_TERMINAL_CLOSE_WORKER_EXITED, -1, 15, capsule,
            &capsule_len));
        ASSERT(mesh_term_capsule_text(capsule, capsule_len, text,
                                      sizeof(text)));
        ASSERT(strstr(text, "\"signal\":15") != NULL);
        ASSERT(strstr(text, "\"exit_code\"") == NULL);

        /* Exactly one status for worker-exited; none for any other reason;
         * ranges are exact. */
        size_t n = 0;
        ASSERT(!boot_mesh_terminal_render_close_capsule_status(
            1, 2, 3, MESH_TERMINAL_CLOSE_WORKER_EXITED, -1, 0, legacy, &n));
        ASSERT(!boot_mesh_terminal_render_close_capsule_status(
            1, 2, 3, MESH_TERMINAL_CLOSE_WORKER_EXITED, 3, 15, legacy, &n));
        ASSERT(!boot_mesh_terminal_render_close_capsule_status(
            1, 2, 3, MESH_TERMINAL_CLOSE_WORKER_EXITED, 256, 0, legacy, &n));
        ASSERT(!boot_mesh_terminal_render_close_capsule_status(
            1, 2, 3, MESH_TERMINAL_CLOSE_WORKER_EXITED, -1, 65, legacy, &n));
        ASSERT(!boot_mesh_terminal_render_close_capsule_status(
            1, 2, 3, MESH_TERMINAL_CLOSE_BYTE_LIMIT, 1, 0, legacy, &n));
        ASSERT(boot_mesh_terminal_render_close_capsule_status(
            1, 2, 3, MESH_TERMINAL_CLOSE_BYTE_LIMIT, -1, 0, legacy, &n));

        /* The pre-status renderer is the exact old capsule. */
        ASSERT(boot_mesh_terminal_render_close_capsule(
            1, 2, 3, MESH_TERMINAL_CLOSE_WORKER_EXITED, legacy, &legacy_len));
        ASSERT(mesh_term_capsule_text(legacy, legacy_len, text, sizeof(text)));
        ASSERT_STR_EQ(text,
                      "{\"schema\":\"zcl.terminal_close_evidence.v1\","
                      "\"bytes_in\":1,\"bytes_out\":2,\"duration_s\":3,"
                      "\"reason\":\"worker-exited\"}");

        /* The capsule is opaque bytes under capsule_root, so the signed
         * receipt layout is unchanged: old and new capsules both compose,
         * encode, decode and bind the open with the same code. */
        const uint8_t *caps[2] = { capsule, legacy };
        size_t lens[2] = { capsule_len, legacy_len };
        for (int i = 0; i < 2; i++) {
            struct mesh_terminal_receipt_v1 r, back;
            uint8_t wire[MESH_TERMINAL_RECEIPT_V1_MAX_WIRE_BYTES];
            size_t wire_len = 0;
            ASSERT(boot_mesh_terminal_compose_receipt(
                &open, &f.term_peer.res_snap, MESH_TERMINAL_RECEIPT_CLOSED,
                f.genesis, f.resp_master_pub, f.resp_online_pub,
                f.resp_noise_pub, 0, open.expires_unix + 10, caps[i], lens[i],
                f.resp_online_seed, &r));
            ASSERT_EQ(mesh_terminal_receipt_v1_encode(&r, wire, sizeof(wire),
                                                      &wire_len),
                      MESH_TERMINAL_PROTO_OK);
            ASSERT_EQ(mesh_terminal_receipt_v1_decode(&back, wire, wire_len),
                      MESH_TERMINAL_PROTO_OK);
            ASSERT_EQ(mesh_terminal_receipt_v1_matches_open(&back, &open),
                      MESH_TERMINAL_PROTO_OK);
        }
        PASS();
    }

    TEST("boot mesh terminal: byte budgets leave room for large sessions "
         "and the output budget arg is range-checked") {
        ASSERT(MESH_TERMINAL_SERVICE_MAX_BYTES_OUT >= UINT64_C(1) << 30);
        ASSERT(MESH_TERMINAL_SERVICE_MAX_BYTES_IN >= UINT64_C(16) << 20);
        ASSERT_EQ(boot_mesh_terminal_max_bytes_out(),
                  MESH_TERMINAL_SERVICE_MAX_BYTES_OUT);
        ASSERT_EQ(boot_mesh_terminal_resolve_max_bytes_out(0),
                  MESH_TERMINAL_SERVICE_MAX_BYTES_OUT);
        ASSERT_EQ(boot_mesh_terminal_resolve_max_bytes_out(-5),
                  MESH_TERMINAL_SERVICE_MAX_BYTES_OUT);
        ASSERT_EQ(boot_mesh_terminal_resolve_max_bytes_out(1048575),
                  MESH_TERMINAL_SERVICE_MAX_BYTES_OUT);
        ASSERT_EQ(boot_mesh_terminal_resolve_max_bytes_out(1048576),
                  UINT64_C(1048576));
        ASSERT_EQ(boot_mesh_terminal_resolve_max_bytes_out(INT64_C(4) << 30),
                  UINT64_C(4) << 30);
        ASSERT_EQ(boot_mesh_terminal_resolve_max_bytes_out(
                      (INT64_C(64) << 30) + 1),
                  MESH_TERMINAL_SERVICE_MAX_BYTES_OUT);
        /* The per-tick rate bound and the memory bound did not move with
         * the budgets: 16 reads of one 4 KiB chunk per drain tick, and one
         * 64 KiB credit window / requester FIFO per session. */
        ASSERT_EQ(MESH_TERMINAL_PUMP_CHUNKS_PER_TICK, 16);
        ASSERT_EQ(MESH_TERMINAL_WORKER_IO_CHUNK, 4096u);
        ASSERT(MESH_TERMINAL_PUMP_CHUNKS_PER_TICK *
                   MESH_TERMINAL_WORKER_IO_CHUNK <= 65536u);
        ASSERT_EQ(MESH_TERMINAL_CLIENT_OUTPUT_MAX, (size_t)65536);
        ASSERT_EQ(MESH_TERMINAL_SESSIONS_MAX, 4u);
        PASS();
    }

    TEST("boot mesh terminal: an open whose requester master is not the "
         "delegation's master is refused before any spawn") {
        uint8_t pairing_id[32];
        ASSERT(zcl_hex_decode_lower(f.term_peer.pairing.pairing_id,
                                    pairing_id, 32));
        struct mesh_terminal_open_v1 open;
        mesh_term_compose_open(&f, &f.term_peer, pairing_id,
                               TERM_WIRE_NOW - 10, TERM_WIRE_NOW + 20,
                               MESH_TERMINAL_CAP_TERMINAL_EXEC, &open);
        uint64_t rg = 0;
        ASSERT_EQ(boot_mesh_terminal_decide(&f.ndb, &open,
                                            &f.term_peer.res_snap,
                                            &f.term_peer.delegation, 1,
                                            f.genesis, TERM_WIRE_NOW, &rg),
                  MESH_TERMINAL_RECEIPT_OK);
        /* The authority that later ticks re-check is keyed by the open's
         * master, so it must be the master that authorized the open. */
        mesh_term_fill32(open.requester_master_pubkey, 0xAB);
        ASSERT_EQ(boot_mesh_terminal_decide(&f.ndb, &open,
                                            &f.term_peer.res_snap,
                                            &f.term_peer.delegation, 1,
                                            f.genesis, TERM_WIRE_NOW, &rg),
                  MESH_TERMINAL_RECEIPT_SESSION_MISMATCH);
        ASSERT_EQ(rg, UINT64_C(0));
        PASS();
    }

    TEST("boot mesh terminal: a terminal id already holding a working "
         "directory cannot open a second one") {
        const char *datadir = dir;
        struct mesh_terminal_open_v1 open;
        memset(&open, 0, sizeof(open));
        mesh_term_fill32(open.terminal_id, 0x31);
        char first[600], second[600];
        ASSERT(boot_mesh_terminal_test_workdir(datadir, &open, first,
                                               sizeof(first)));
        ASSERT(!boot_mesh_terminal_test_workdir(datadir, &open, second,
                                                sizeof(second)));
        /* The refused attempt left the first session's directory alone. */
        struct stat sb;
        ASSERT(stat(first, &sb) == 0 && S_ISDIR(sb.st_mode));
        ASSERT(test_rm_rf_recursive(first) == 0);
        ASSERT(boot_mesh_terminal_test_workdir(datadir, &open, second,
                                               sizeof(second)));
        PASS();
    }

    TEST("boot mesh terminal: one peer cannot use up every replay slot") {
        struct mesh_terminal_open_v1 open;
        uint8_t pairing_id[32];
        ASSERT(zcl_hex_decode_lower(f.term_peer.pairing.pairing_id,
                                    pairing_id, 32));
        mesh_term_compose_open(&f, &f.term_peer, pairing_id,
                               TERM_WIRE_NOW - 10, TERM_WIRE_NOW + 20,
                               MESH_TERMINAL_CAP_TERMINAL_EXEC, &open);
        struct noise_transport_snapshot greedy = f.term_peer.res_snap;
        greedy.connection_generation += 100;
        greedy.transcript_hash[1] ^= 0x7E;
        greedy.remote_static[3] ^= 0x7E;
        unsigned held = 0;
        unsigned attempts = MESH_TERMINAL_OPEN_ADMIT_PER_PEER + 4u;
        for (unsigned i = 0; i < attempts; i++) {
            mesh_term_fill32(open.terminal_id, (uint8_t)(0x80 + i));
            int verdict = boot_mesh_terminal_test_open_admit_verdict(
                &open, &greedy, 500000 + 900u * i);
            if (verdict == MESH_STREAM_OK)
                held++;
            else
                /* Over the per-peer bound the refusal is named. */
                ASSERT_EQ(verdict, (int)MESH_STREAM_REFUSED_RATE);
        }
        ASSERT_EQ(held, MESH_TERMINAL_OPEN_ADMIT_PER_PEER);
        /* Another peer is still served inside the same admit window. */
        uint64_t later = 500000 + 900u * attempts;
        mesh_term_fill32(open.terminal_id, 0x7F);
        ASSERT(boot_mesh_terminal_test_open_admit(
            &open, &f.term_peer.res_snap, later));
        /* A replay from a peer below its bound is refused as a replay
         * (not as rate), so the replay check is what stops it. */
        ASSERT_EQ(boot_mesh_terminal_test_open_admit_verdict(
                      &open, &f.term_peer.res_snap, later + 1),
                  (int)MESH_STREAM_CLOSED_BY_SERVICE);
        PASS();
    }

    TEST("boot mesh terminal: paired peers each at their bound cannot fill "
         "the replay table") {
        struct mesh_terminal_open_v1 open;
        memset(&open, 0, sizeof(open));
        /* Far more identities than any node pairs, each holding its full
         * share inside one admit window; the next identity is still served. */
        enum { PEERS = 40 };
        struct noise_transport_snapshot peer = f.term_peer.res_snap;
        for (unsigned round = 0; round < MESH_TERMINAL_OPEN_ADMIT_PER_PEER;
             round++) {
            for (unsigned p = 0; p < PEERS; p++) {
                peer.connection_generation = 1000 + p;
                peer.remote_static[0] = (uint8_t)(0x10 + p);
                peer.transcript_hash[0] = (uint8_t)(0x10 + p);
                mesh_term_fill32(open.terminal_id, (uint8_t)round);
                open.terminal_id[1] = (uint8_t)p;
                ASSERT_EQ(boot_mesh_terminal_test_open_admit_verdict(
                              &open, &peer, 800000 + 400u * round),
                          (int)MESH_STREAM_OK);
            }
        }
        _Static_assert(PEERS * MESH_TERMINAL_OPEN_ADMIT_PER_PEER <
                           MESH_TERMINAL_OPEN_ADMIT_MAX,
                       "the table outlasts the identities the test pairs");
        peer.connection_generation = 5000;
        peer.remote_static[0] = 0xEE;
        peer.transcript_hash[0] = 0xEE;
        mesh_term_fill32(open.terminal_id, 0xEE);
        ASSERT_EQ(boot_mesh_terminal_test_open_admit_verdict(
                      &open, &peer, 800000 + 400u * 8u),
                  (int)MESH_STREAM_OK);
        PASS();
    }

    TEST("boot mesh terminal: the OPEN admit gate refuses replays and "
         "bounds the per-session cadence") {
        struct mesh_terminal_open_v1 open;
        uint8_t pairing_id[32];
        ASSERT(zcl_hex_decode_lower(f.term_peer.pairing.pairing_id,
                                    pairing_id, 32));
        mesh_term_compose_open(&f, &f.term_peer, pairing_id,
                               TERM_WIRE_NOW - 10,
                               TERM_WIRE_NOW + 20, MESH_TERMINAL_CAP_TERMINAL_EXEC,
                               &open);
        /* First sight is admitted; the exact same open again is a replay,
         * not a second fork. */
        ASSERT(boot_mesh_terminal_test_open_admit(&open,
                                                  &f.term_peer.res_snap,
                                                  1000));
        ASSERT(!boot_mesh_terminal_test_open_admit(&open,
                                                   &f.term_peer.res_snap,
                                                   1000));
        /* Distinct opens share a small per-session cadence: four in the
         * first second (including the first), then refused. */
        bool burst = true;
        for (uint8_t i = 2; i <= 4; i++) {
            mesh_term_fill32(open.terminal_id, (uint8_t)(0x40 + i));
            burst = burst && boot_mesh_terminal_test_open_admit(
                                 &open, &f.term_peer.res_snap, 1000);
        }
        mesh_term_fill32(open.terminal_id, 0x50);
        ASSERT(!boot_mesh_terminal_test_open_admit(&open,
                                                   &f.term_peer.res_snap,
                                                   1000));
        /* Just past that one-second cadence window the cadence resets. */
        ASSERT(boot_mesh_terminal_test_open_admit(&open,
                                                  &f.term_peer.res_snap,
                                                  2001));
        /* Long after the 30-second admit window the replay identity is
         * forgotten: the first open is a fresh admission again. */
        mesh_term_fill32(open.terminal_id, 0x5C);
        ASSERT(boot_mesh_terminal_test_open_admit(&open,
                                                  &f.term_peer.res_snap,
                                                  32001));
        /* A different session (new transcript/generation) has its own
         * cadence and its own replay identity. */
        struct noise_transport_snapshot fresh = f.term_peer.res_snap;
        fresh.connection_generation++;
        fresh.transcript_hash[0] ^= 0x01;
        ASSERT(boot_mesh_terminal_test_open_admit(&open, &fresh, 2000));
        PASS();
    }

    TEST("boot mesh terminal: a revoked, stripped, or expired pairing "
         "fails the mid-session authority check by name") {
        /* The term pairing was accepted above with the terminal-exec
         * capability and the fixture's 2000..3000 validity window. The
         * check derives the responder's own row id from the open's
         * requester identity — the open's pairing_id names the
         * requester-side row and is never the lookup key. */
        uint8_t pairing_id[32];
        ASSERT(zcl_hex_decode_lower(f.term_peer.pairing.pairing_id,
                                    pairing_id, 32));
        struct mesh_terminal_open_v1 open;
        mesh_term_compose_open(&f, &f.term_peer, pairing_id,
                               TERM_WIRE_NOW - 10, TERM_WIRE_NOW + 20,
                               MESH_TERMINAL_CAP_TERMINAL_EXEC, &open);
        enum mesh_terminal_close_reason reason = MESH_TERMINAL_CLOSE_INTERNAL;
        ASSERT(!boot_mesh_terminal_pairing_lost(&f.ndb, &open, 2500,
                                                &reason));

        /* Past the pairing's expiry: named EXPIRED, not REVOKED. */
        ASSERT(boot_mesh_terminal_pairing_lost(&f.ndb, &open, 3001,
                                               &reason));
        ASSERT_EQ(reason, MESH_TERMINAL_CLOSE_EXPIRED);

        /* Revoked mid-window: named REVOKED, and the check stays lost. */
        ASSERT_EQ(mesh_pairing_service_revoke(&f.ndb,
                                              f.term_peer.pairing.pairing_id,
                                              2500),
                  MESH_PAIRING_OK);
        ASSERT(boot_mesh_terminal_pairing_lost(&f.ndb, &open, 2500,
                                               &reason));
        ASSERT_EQ(reason, MESH_TERMINAL_CLOSE_REVOKED);

        /* A requester identity no row was ever accepted for cannot keep
         * a terminal alive either. */
        struct mesh_terminal_open_v1 unknown = open;
        mesh_term_fill32(unknown.requester_master_pubkey, 0xEE);
        ASSERT(boot_mesh_terminal_pairing_lost(&f.ndb, &unknown, 2500,
                                               &reason));
        ASSERT_EQ(reason, MESH_TERMINAL_CLOSE_REVOKED);

        /* Fail closed: an unreadable db refuses the authority question. */
        ASSERT(boot_mesh_terminal_pairing_lost(NULL, &open, 2500,
                                               &reason));
        ASSERT_EQ(reason, MESH_TERMINAL_CLOSE_REVOKED);
        PASS();
    }

_test_next:
    if (fixture_open)
        mesh_term_fixture_close(&f);
    test_rm_rf_recursive(dir);
    return failures;
}
