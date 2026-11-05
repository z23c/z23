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

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define TERM_WIRE_NOW 2500

int test_boot_mesh_terminal(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "boot_mesh_terminal", "wire");
    struct mesh_term_fixture f;
    bool fixture_open = false;

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
        for (unsigned i = 0; i < MESH_TERMINAL_OPEN_ADMIT_MAX; i++) {
            mesh_term_fill32(open.terminal_id, (uint8_t)(0x80 + i));
            if (boot_mesh_terminal_test_open_admit(&open, &greedy,
                                                   500000 + 900u * i))
                held++;
        }
        ASSERT_EQ(held, MESH_TERMINAL_OPEN_ADMIT_PER_PEER);
        /* Another peer is still served inside the same admit window. */
        mesh_term_fill32(open.terminal_id, 0x7F);
        ASSERT(boot_mesh_terminal_test_open_admit(
            &open, &f.term_peer.res_snap,
            500000 + 900u * MESH_TERMINAL_OPEN_ADMIT_MAX));
        /* Replays stay refused for the slots the greedy peer holds. */
        mesh_term_fill32(open.terminal_id, 0x80);
        ASSERT(!boot_mesh_terminal_test_open_admit(
            &open, &greedy, 500000 + 900u * MESH_TERMINAL_OPEN_ADMIT_MAX));
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
