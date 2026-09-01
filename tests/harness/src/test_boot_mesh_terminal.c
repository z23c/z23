/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Proves the mesh terminal wire fails closed: the ZMTERM responder
 * decision is pairing-, capability-, and session-bound; the OK receipt
 * carries the granted session bounds and nothing else answers OK; CLOSED
 * evidence receipts bind the open even after its answer window; and the
 * OPEN admit gate rate-limits and refuses replays. Drives the exact
 * production decision and composition against a real node.db fixture,
 * real Ed25519 keys, and real in-process Noise transports driven
 * buffer-to-buffer (no sockets), with two independently paired peers —
 * one status-read only, one carrying the commit-time terminal-exec
 * capability — so the capability gate is exercised at the wire layer AND
 * through the real pairing-service authorization. The fixture primitives
 * are shared with the requester-lane group (mesh_term_fixture). */

#include "test/test_core.h"

#include "config/boot_mesh_terminal.h"
#include "test/mesh_term_fixture.h"
#include "base/hex.h"
#include "services/mesh_pairing_service.h"

#include <stdio.h>
#include <string.h>

#define TERM_WIRE_NOW 2500

int test_boot_mesh_terminal(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "boot_mesh_terminal", "wire");
    struct mesh_term_fixture f;
    bool fixture_open = false;

    TEST("boot mesh terminal: frame dispatch claims only the ZMTERM "
         "namespace") {
        ASSERT(mesh_term_fixture_open(&f, dir));
        fixture_open = true;
        const uint8_t other[] = "ZMSTAT\x01 garbage";
        ASSERT(!boot_mesh_terminal_frame(NULL, NULL, other, sizeof(other),
                                         NULL));
        const uint8_t ours[] = "ZMTERM\x7f garbage";
        ASSERT(boot_mesh_terminal_frame(NULL, NULL, ours, sizeof(ours),
                                        NULL));
        /* Prefix alone is shorter than prefix+kind: not a frame. */
        ASSERT(!boot_mesh_terminal_frame(NULL, NULL,
                                         (const uint8_t *)"ZMTERM", 6, NULL));
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
        ASSERT(strstr(text, "\"max_bytes_in\":65536") != NULL);
        ASSERT(strstr(text, "\"max_bytes_out\":1048576") != NULL);

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

        /* The exact ZMTERM receipt frame crosses the live Noise session. */
        uint8_t receipt_wire[MESH_TERMINAL_RECEIPT_V1_MAX_WIRE_BYTES];
        size_t receipt_len = 0;
        ASSERT_EQ(mesh_terminal_receipt_v1_encode(&receipt, receipt_wire,
                                                  sizeof(receipt_wire),
                                                  &receipt_len),
                  MESH_TERMINAL_PROTO_OK);
        uint8_t frame[MESH_TERMINAL_FRAME_MAX];
        memcpy(frame, MESH_TERMINAL_FRAME_PREFIX,
               MESH_TERMINAL_FRAME_PREFIX_LEN);
        frame[MESH_TERMINAL_FRAME_PREFIX_LEN] =
            MESH_TERMINAL_FRAME_KIND_RECEIPT;
        memcpy(frame + MESH_TERMINAL_FRAME_PREFIX_LEN + 1u, receipt_wire,
               receipt_len);
        uint8_t delivered[MESH_TERMINAL_FRAME_MAX];
        ASSERT(mesh_term_frame_roundtrip(f.res_term, f.term_peer.ini, frame,
                                         MESH_TERMINAL_FRAME_PREFIX_LEN + 1u +
                                             receipt_len,
                                         delivered, sizeof(delivered)));
        struct mesh_terminal_receipt_v1 decoded;
        ASSERT_EQ(mesh_terminal_receipt_v1_decode(
                      &decoded,
                      delivered + MESH_TERMINAL_FRAME_PREFIX_LEN + 1u,
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
