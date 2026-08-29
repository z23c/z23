/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Proves the mesh status wire fails closed: the responder decision is
 * pairing- and session-bound with sticky revocation, the receipt is signed
 * and request/session-bound, and the requester refuses forged or
 * misdelivered receipts. Uses the real pairing service against a real
 * node.db fixture, real Ed25519 keys, and two real in-process v2 Noise
 * transports driven buffer-to-buffer (no sockets), so the session binding
 * is proven against genuine transcripts. */

#include "test/test_core.h"

#include "config/boot_mesh_status.h"
#include "config/boot_mesh_machines.h"
#include "../../../config/src/boot_mesh_status_internal.h"
#include "base/cleanse.h"
#include "base/hex.h"
#include "crypto/ed25519.h"
#include "json/json.h"
#include "models/mesh_pairing.h"
#include "models/database.h"
#include "models/zid_identity.h"
#include "net/v2_identity.h"
#include "net/v2_transport.h"
#include "platform/private_directory.h"
#include "services/mesh_pairing_service.h"
#include "services/disk_monitor.h"
#include "sync/sync_state.h"
#include "util/mem_pressure.h"
#include "validation/main_constants.h"
#include "vcs/zcode_dht_delegation.h"

#include <stdio.h>
#include <string.h>

#define MESH_WIRE_NOW 2500

static void mesh_fill32(uint8_t out[32], uint8_t value)
{
    memset(out, value, 32);
}

/* raw-sql-ok:test-fixture -- creates only the connected chain rows required
 * to exercise the production chain-bound pairing verifier. */
static bool mesh_seed_block(struct node_db *ndb, int height,
                            const uint8_t hash[32])
{
    sqlite3_stmt *st = NULL;
    static const char sql[] =
        "INSERT INTO blocks(hash,height,prev_hash,version,merkle_root,time,"
        "bits,nonce,solution,chain_work,status,num_tx) "
        "VALUES(?,?,zeroblob(32),4,zeroblob(32),1,1,zeroblob(32),"
        "X'00',zeroblob(32),3,0)";
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_blob(st, 1, hash, 32, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, height);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static const unsigned char MESH_TEST_MAGIC[4] = {0x24, 0xe9, 0x27, 0x64};

/* Full XX handshake between two in-process transports with the given static
 * private keys; both sides ESTABLISHED on return. */
static bool mesh_handshake(const uint8_t ini_priv[32],
                           const uint8_t res_priv[32],
                           struct v2_transport **ini_out,
                           struct v2_transport **res_out)
{
    uint8_t *msg1 = NULL, *w1 = NULL, *w2 = NULL, *w3 = NULL, *p = NULL;
    size_t msg1_len = 0, w1l = 0, w2l = 0, w3l = 0, pl = 0;
    struct v2_transport *ini =
        v2_transport_begin(true, ini_priv, MESH_TEST_MAGIC, &msg1, &msg1_len);
    struct v2_transport *res =
        v2_transport_begin(false, res_priv, MESH_TEST_MAGIC, NULL, NULL);
    bool ok = ini && res && msg1 && msg1_len == 32 &&
              v2_transport_feed(res, msg1, msg1_len, &w2, &w2l, &p, &pl) &&
              w2l == 96 && pl == 0 &&
              v2_transport_feed(ini, w2, w2l, &w3, &w3l, &p, &pl) &&
              w3l == 64 && pl == 0 &&
              v2_transport_feed(res, w3, w3l, &w1, &w1l, &p, &pl) &&
              w1l == 0 && pl == 0 && ini->state == V2_ESTABLISHED &&
              res->state == V2_ESTABLISHED;
    free(msg1);
    free(w1);
    free(w2);
    free(w3);
    free(p);
    if (!ok) {
        v2_transport_free(ini);
        v2_transport_free(res);
        return false;
    }
    *ini_out = ini;
    *res_out = res;
    return true;
}

/* Seal frame bytes on `from` and deliver them to `to`; plaintext must equal
 * the input byte-for-byte with no wire reply. */
static bool mesh_frame_roundtrip(struct v2_transport *from,
                                 struct v2_transport *to,
                                 const uint8_t *frame, size_t frame_len,
                                 uint8_t *delivered, size_t delivered_cap)
{
    uint8_t *ct = NULL, *pt = NULL, *wire = NULL;
    size_t ct_len = 0, pt_len = 0, wire_len = 0;
    bool ok = v2_transport_write(from, frame, frame_len, &ct, &ct_len) &&
              ct_len > 0 &&
              v2_transport_feed(to, ct, ct_len, &wire, &wire_len, &pt,
                                &pt_len) &&
              wire_len == 0 && pt_len == frame_len &&
              pt_len <= delivered_cap &&
              memcmp(pt, frame, frame_len) == 0;
    if (ok)
        memcpy(delivered, pt, pt_len);
    free(ct);
    free(pt);
    free(wire);
    return ok;
}

struct mesh_wire_fixture {
    struct node_db ndb;
    struct vcs_zcode_dht_delegation peer_delegation;
    uint8_t genesis[32];
    uint8_t peer_noise_pub[32];
    uint8_t resp_master_pub[32];
    uint8_t resp_online_seed[32];
    uint8_t resp_online_pub[32];
    uint8_t resp_noise_pub[32];
    struct db_mesh_pairing pairing;
    struct v2_transport *ini;
    struct v2_transport *res;
    struct v2_transport_snapshot ini_snap;
    struct v2_transport_snapshot res_snap;
};

static bool mesh_wire_fixture_open(struct mesh_wire_fixture *f,
                                   const char *dir)
{
    memset(f, 0, sizeof(*f));
    char path[320], reqdir[320], respdir[320];
    snprintf(path, sizeof(path), "%s/node.db", dir);
    snprintf(reqdir, sizeof(reqdir), "%s/req", dir);
    snprintf(respdir, sizeof(respdir), "%s/resp", dir);
    char error[160];
    uint8_t peer_noise_priv[32], resp_noise_priv[32];
    bool loaded = platform_private_directory_create(reqdir) &&
                  platform_private_directory_create(respdir) &&
                  v2_identity_load_or_create(reqdir, peer_noise_priv,
                                             f->peer_noise_pub, error,
                                             sizeof(error)) &&
                  v2_identity_load_or_create(respdir, resp_noise_priv,
                                             f->resp_noise_pub, error,
                                             sizeof(error)) &&
                  mesh_handshake(peer_noise_priv, resp_noise_priv, &f->ini,
                                 &f->res);
    memory_cleanse(peer_noise_priv, sizeof(peer_noise_priv));
    memory_cleanse(resp_noise_priv, sizeof(resp_noise_priv));
    if (!loaded)
        return false;
    if (!v2_transport_snapshot(f->ini, &f->ini_snap) ||
        !v2_transport_snapshot(f->res, &f->res_snap))
        return false;

    if (!node_db_open(&f->ndb, path))
        return false;
    uint8_t beacon[32], tip[32], peer_online[32], peer_master_seed[32];
    mesh_fill32(f->genesis, 0x11);
    mesh_fill32(beacon, 0x22);
    mesh_fill32(tip, 0x33);
    mesh_fill32(peer_online, 0x44);
    mesh_fill32(peer_master_seed, 0x66);
    if (!mesh_seed_block(&f->ndb, 0, f->genesis) ||
        !mesh_seed_block(&f->ndb, ZCL_FINALITY_DEPTH, beacon) ||
        !mesh_seed_block(&f->ndb, 2 * ZCL_FINALITY_DEPTH, tip))
        return false;
    if (vcs_zcode_dht_delegation_sign(
            &f->peer_delegation, f->genesis, peer_online, f->peer_noise_pub,
            ZCL_FINALITY_DEPTH, beacon, 1000, 4000, 7,
            peer_master_seed) != VCS_ZCODE_DHT_DELEGATION_OK)
        return false;
    struct zid_identity identity = {0};
    memcpy(identity.master_pubkey, f->peer_delegation.doc.master_pubkey, 32);
    mesh_fill32(identity.anchor_txid, 0x77);
    identity.anchor_height = 0;
    identity.updated_height = 0;
    snprintf(identity.status, sizeof(identity.status), "%s",
             ZID_IDENTITY_STATUS_ACTIVE);
    snprintf(identity.source, sizeof(identity.source), "%s",
             ZID_IDENTITY_SOURCE_ZID_OVERLAY);
    if (!db_zid_identity_save(&f->ndb, &identity))
        return false;
    uint8_t resp_master_seed[32], secret[32];
    mesh_fill32(resp_master_seed, 0x88);
    mesh_fill32(f->resp_online_seed, 0x99);
    ed25519_keypair(f->resp_master_pub, secret, resp_master_seed);
    memory_cleanse(secret, sizeof(secret));
    ed25519_keypair(f->resp_online_pub, secret, f->resp_online_seed);
    memory_cleanse(secret, sizeof(secret));
    return true;
}

static void mesh_wire_fixture_close(struct mesh_wire_fixture *f)
{
    v2_transport_free(f->ini);
    v2_transport_free(f->res);
    f->ini = NULL;
    f->res = NULL;
    if (f->ndb.open)
        node_db_close(&f->ndb);
}

/* The request as the requester lane composes it: bound to the REQUESTER's
 * session snapshot (the responder verifies the shared transcript/generation
 * evidence; per-side serials left the wire in 2114f5257). */
static void mesh_wire_request(const struct mesh_wire_fixture *f,
                              const uint8_t pairing_id[32],
                              uint64_t issued, uint64_t expires,
                              struct mesh_status_request_v1 *out)
{
    memset(out, 0, sizeof(*out));
    out->version = MESH_STATUS_PROTO_VERSION;
    out->flags = MESH_STATUS_PROTO_FLAGS_NONE;
    out->capability = MESH_STATUS_CAP_STATUS_READ;
    mesh_fill32(out->request_id, 0xA5);
    memcpy(out->network_genesis, f->genesis, 32);
    memcpy(out->target_master_pubkey, f->resp_master_pub, 32);
    memcpy(out->requester_master_pubkey,
           f->peer_delegation.doc.master_pubkey, 32);
    memcpy(out->requester_noise_static, f->peer_noise_pub, 32);
    memcpy(out->pairing_id, pairing_id, 32);
    memcpy(out->transcript_hash, f->res_snap.transcript_hash, 32);
    out->connection_generation = f->res_snap.connection_generation;
    out->issued_unix = issued;
    out->expires_unix = expires;
}

static bool mesh_wire_sign_roundtrip(const struct mesh_wire_fixture *f,
                                     const struct mesh_status_request_v1 *req,
                                     enum mesh_status_receipt_status status,
                                     const char *capsule,
                                     struct mesh_status_receipt_v1 *out)
{
    if (!boot_mesh_status_compose_receipt(
            req, &f->res_snap, status, f->genesis, f->resp_master_pub,
            f->resp_online_pub, f->resp_noise_pub, 0, MESH_WIRE_NOW,
            (const uint8_t *)capsule, capsule ? strlen(capsule) : 0,
            f->resp_online_seed, out))
        return false;
    uint8_t wire[MESH_STATUS_RECEIPT_V1_MAX_WIRE_BYTES];
    size_t wire_len = 0;
    if (mesh_status_receipt_v1_encode(out, wire, sizeof(wire), &wire_len) !=
        MESH_STATUS_PROTO_OK)
        return false;
    struct mesh_status_receipt_v1 decoded;
    if (mesh_status_receipt_v1_decode(&decoded, wire, wire_len) !=
        MESH_STATUS_PROTO_OK)
        return false;
    if (decoded.status != status)
        return false;
    *out = decoded;
    return true;
}

int test_mesh_status_wire(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "mesh_status_wire", "wire");
    struct mesh_wire_fixture f;
    bool fixture_open = false;

    TEST("mesh status wire: unpaired request is refused NOT_PAIRED, signed") {
        ASSERT(mesh_wire_fixture_open(&f, dir));
        fixture_open = true;
        /* The session binding is genuinely shared: transcript and generation
         * match across sides, and each side's snapshot names the other's
         * identity-file public static. */
        ASSERT(f.ini_snap.established && f.res_snap.established);
        ASSERT(memcmp(f.ini_snap.transcript_hash, f.res_snap.transcript_hash,
                      32) == 0);
        ASSERT(f.ini_snap.connection_generation ==
               f.res_snap.connection_generation);
        ASSERT(memcmp(f.res_snap.remote_static, f.peer_noise_pub, 32) == 0);
        ASSERT(memcmp(f.ini_snap.remote_static, f.resp_noise_pub, 32) == 0);

        uint8_t unpaired[32];
        mesh_fill32(unpaired, 0x77);
        struct mesh_status_request_v1 request;
        mesh_wire_request(&f, unpaired, MESH_WIRE_NOW - 10,
                          MESH_WIRE_NOW + 20, &request);
        uint64_t revocation_generation = 99;
        ASSERT_EQ(boot_mesh_status_decide(&f.ndb, &request, &f.res_snap,
                                          &f.peer_delegation, 1, f.genesis,
                                          MESH_WIRE_NOW,
                                          &revocation_generation),
                  MESH_STATUS_RECEIPT_NOT_PAIRED);
        ASSERT_EQ(revocation_generation, 0);
        struct mesh_status_receipt_v1 receipt;
        ASSERT(mesh_wire_sign_roundtrip(&f, &request,
                                        MESH_STATUS_RECEIPT_NOT_PAIRED, NULL,
                                        &receipt));
        ASSERT_EQ(receipt.capsule_len, 0);
        PASS();
    }

    TEST("mesh status wire: accepted pairing earns a bound OK receipt over "
         "live Noise records") {
        uint8_t fingerprint[32];
        ASSERT(v2_identity_public_fingerprint(f.peer_noise_pub, fingerprint));
        ASSERT_EQ(mesh_pairing_service_accept(
                      &f.ndb, &f.peer_delegation, fingerprint,
                      f.peer_noise_pub, true, MESH_PAIRING_CAP_STATUS_READ,
                      2000, 3000, &f.pairing),
                  MESH_PAIRING_OK);
        uint8_t pairing_id[32];
        ASSERT(zcl_hex_decode_lower(f.pairing.pairing_id, pairing_id, 32));
        struct mesh_status_request_v1 request;
        mesh_wire_request(&f, pairing_id, MESH_WIRE_NOW - 10,
                          MESH_WIRE_NOW + 20, &request);

        /* Frame-level roundtrip: the exact "ZMSTAT" frame crosses the live
         * Noise session in both directions before the decision runs. */
        uint8_t request_wire[MESH_STATUS_REQUEST_V1_WIRE_BYTES];
        ASSERT_EQ(mesh_status_request_v1_encode(&request, request_wire),
                  MESH_STATUS_PROTO_OK);
        uint8_t frame[MESH_STATUS_FRAME_MAX];
        memcpy(frame, MESH_STATUS_FRAME_PREFIX, MESH_STATUS_FRAME_PREFIX_LEN);
        frame[MESH_STATUS_FRAME_PREFIX_LEN] = MESH_STATUS_FRAME_KIND_REQUEST;
        memcpy(frame + MESH_STATUS_FRAME_PREFIX_LEN + 1u, request_wire,
               sizeof(request_wire));
        size_t frame_len =
            MESH_STATUS_FRAME_PREFIX_LEN + 1u + sizeof(request_wire);
        uint8_t delivered[MESH_STATUS_FRAME_MAX];
        ASSERT(mesh_frame_roundtrip(f.ini, f.res, frame, frame_len, delivered,
                                    sizeof(delivered)));
        struct mesh_status_request_v1 received;
        ASSERT_EQ(mesh_status_request_v1_decode(
                      &received,
                      delivered + MESH_STATUS_FRAME_PREFIX_LEN + 1u,
                      sizeof(request_wire)),
                  MESH_STATUS_PROTO_OK);

        uint64_t revocation_generation = 99;
        ASSERT_EQ(boot_mesh_status_decide(&f.ndb, &received, &f.res_snap,
                                          &f.peer_delegation, 1, f.genesis,
                                          MESH_WIRE_NOW,
                                          &revocation_generation),
                  MESH_STATUS_RECEIPT_OK);
        ASSERT_EQ(revocation_generation, 0);

        static const char capsule[] =
            "{\"schema\":\"zcl.machine_mesh_identity.v1\",\"test\":true}";
        struct mesh_status_receipt_v1 receipt;
        ASSERT(boot_mesh_status_compose_receipt(
            &received, &f.res_snap, MESH_STATUS_RECEIPT_OK, f.genesis,
            f.resp_master_pub, f.resp_online_pub, f.resp_noise_pub,
            revocation_generation, MESH_WIRE_NOW, (const uint8_t *)capsule,
            sizeof(capsule) - 1, f.resp_online_seed, &receipt));
        ASSERT_EQ(receipt.capsule_len, sizeof(capsule) - 1);
        uint8_t expected_root[32];
        ASSERT_EQ(mesh_status_capsule_v1_root((const uint8_t *)capsule,
                                              sizeof(capsule) - 1,
                                              expected_root),
                  MESH_STATUS_PROTO_OK);
        ASSERT(memcmp(receipt.capsule_root, expected_root, 32) == 0);
        ASSERT_EQ(receipt.observed_unix, MESH_WIRE_NOW);
        ASSERT(receipt.expires_unix > receipt.observed_unix);
        ASSERT(receipt.expires_unix <= received.expires_unix);

        uint8_t receipt_wire[MESH_STATUS_RECEIPT_V1_MAX_WIRE_BYTES];
        size_t receipt_len = 0;
        ASSERT_EQ(mesh_status_receipt_v1_encode(&receipt, receipt_wire,
                                                sizeof(receipt_wire),
                                                &receipt_len),
                  MESH_STATUS_PROTO_OK);
        memcpy(frame, MESH_STATUS_FRAME_PREFIX, MESH_STATUS_FRAME_PREFIX_LEN);
        frame[MESH_STATUS_FRAME_PREFIX_LEN] = MESH_STATUS_FRAME_KIND_RECEIPT;
        memcpy(frame + MESH_STATUS_FRAME_PREFIX_LEN + 1u, receipt_wire,
               receipt_len);
        ASSERT(mesh_frame_roundtrip(f.res, f.ini, frame,
                                    MESH_STATUS_FRAME_PREFIX_LEN + 1u +
                                        receipt_len,
                                    delivered, sizeof(delivered)));
        struct mesh_status_receipt_v1 decoded;
        ASSERT_EQ(mesh_status_receipt_v1_decode(
                      &decoded,
                      delivered + MESH_STATUS_FRAME_PREFIX_LEN + 1u,
                      receipt_len),
                  MESH_STATUS_PROTO_OK);
        ASSERT_EQ(mesh_status_receipt_v1_matches_request(&decoded, &received),
                  MESH_STATUS_PROTO_OK);
        ASSERT(boot_mesh_status_receipt_accept(&decoded, &received,
                                               &f.ini_snap,
                                               f.resp_master_pub,
                                               f.resp_online_pub));

        /* An oversize capsule is refused, never truncated mid-document. */
        uint8_t too_big[MESH_STATUS_CAPSULE_MAX + 1];
        memset(too_big, 'x', sizeof(too_big));
        ASSERT(!boot_mesh_status_compose_receipt(
            &received, &f.res_snap, MESH_STATUS_RECEIPT_OK, f.genesis,
            f.resp_master_pub, f.resp_online_pub, f.resp_noise_pub, 0,
            MESH_WIRE_NOW, too_big, sizeof(too_big), f.resp_online_seed,
            &decoded));
        PASS();
    }

    TEST("mesh status wire: window, capability, and session binding fail "
         "closed with named statuses") {
        uint8_t pairing_id[32];
        ASSERT(zcl_hex_decode_lower(f.pairing.pairing_id, pairing_id, 32));
        struct mesh_status_request_v1 request;
        uint64_t rg;

        /* Expired request window. */
        mesh_wire_request(&f, pairing_id, MESH_WIRE_NOW - 60,
                          MESH_WIRE_NOW - 30, &request);
        ASSERT_EQ(boot_mesh_status_decide(&f.ndb, &request, &f.res_snap,
                                          &f.peer_delegation, 1, f.genesis,
                                          MESH_WIRE_NOW, &rg),
                  MESH_STATUS_RECEIPT_EXPIRED);
        /* Not-yet-issued request window. */
        mesh_wire_request(&f, pairing_id, MESH_WIRE_NOW + 10,
                          MESH_WIRE_NOW + 30, &request);
        ASSERT_EQ(boot_mesh_status_decide(&f.ndb, &request, &f.res_snap,
                                          &f.peer_delegation, 1, f.genesis,
                                          MESH_WIRE_NOW, &rg),
                  MESH_STATUS_RECEIPT_EXPIRED);
        /* Lifetime above the 60-second ceiling is rejected at validate. */
        mesh_wire_request(&f, pairing_id, MESH_WIRE_NOW - 10,
                          MESH_WIRE_NOW + 61, &request);
        uint8_t wire[MESH_STATUS_REQUEST_V1_WIRE_BYTES];
        ASSERT_EQ(mesh_status_request_v1_encode(&request, wire),
                  MESH_STATUS_PROTO_TIME);
        ASSERT_EQ(boot_mesh_status_decide(&f.ndb, &request, &f.res_snap,
                                          &f.peer_delegation, 1, f.genesis,
                                          MESH_WIRE_NOW, &rg),
                  MESH_STATUS_RECEIPT_BAD_REQUEST);
        /* Capability other than status-read. */
        mesh_wire_request(&f, pairing_id, MESH_WIRE_NOW - 10,
                          MESH_WIRE_NOW + 20, &request);
        request.capability = UINT64_C(2);
        ASSERT_EQ(boot_mesh_status_decide(&f.ndb, &request, &f.res_snap,
                                          &f.peer_delegation, 1, f.genesis,
                                          MESH_WIRE_NOW, &rg),
                  MESH_STATUS_RECEIPT_CAPABILITY_UNAVAILABLE);
        /* Session binding: wrong transcript, generation, or static. */
        mesh_wire_request(&f, pairing_id, MESH_WIRE_NOW - 10,
                          MESH_WIRE_NOW + 20, &request);
        request.transcript_hash[0] ^= 1;
        ASSERT_EQ(boot_mesh_status_decide(&f.ndb, &request, &f.res_snap,
                                          &f.peer_delegation, 1, f.genesis,
                                          MESH_WIRE_NOW, &rg),
                  MESH_STATUS_RECEIPT_SESSION_MISMATCH);
        mesh_wire_request(&f, pairing_id, MESH_WIRE_NOW - 10,
                          MESH_WIRE_NOW + 20, &request);
        request.connection_generation++;
        ASSERT_EQ(boot_mesh_status_decide(&f.ndb, &request, &f.res_snap,
                                          &f.peer_delegation, 1, f.genesis,
                                          MESH_WIRE_NOW, &rg),
                  MESH_STATUS_RECEIPT_SESSION_MISMATCH);
        mesh_wire_request(&f, pairing_id, MESH_WIRE_NOW - 10,
                          MESH_WIRE_NOW + 20, &request);
        request.requester_noise_static[0] ^= 1;
        ASSERT_EQ(boot_mesh_status_decide(&f.ndb, &request, &f.res_snap,
                                          &f.peer_delegation, 1, f.genesis,
                                          MESH_WIRE_NOW, &rg),
                  MESH_STATUS_RECEIPT_SESSION_MISMATCH);
        /* No held delegation for the session identity. */
        mesh_wire_request(&f, pairing_id, MESH_WIRE_NOW - 10,
                          MESH_WIRE_NOW + 20, &request);
        ASSERT_EQ(boot_mesh_status_decide(&f.ndb, &request, &f.res_snap, NULL,
                                          0, f.genesis, MESH_WIRE_NOW, &rg),
                  MESH_STATUS_RECEIPT_DELEGATION_INVALID);
        struct vcs_zcode_dht_delegation ambiguous[2] = {
            f.peer_delegation, f.peer_delegation,
        };
        ASSERT_EQ(boot_mesh_status_decide(
                      &f.ndb, &request, &f.res_snap, ambiguous, 2,
                      f.genesis, MESH_WIRE_NOW, &rg),
                  MESH_STATUS_RECEIPT_DELEGATION_INVALID);
        /* Foreign network genesis names no local authority. */
        uint8_t foreign[32];
        mesh_fill32(foreign, 0x42);
        ASSERT_EQ(boot_mesh_status_decide(&f.ndb, &request, &f.res_snap,
                                          &f.peer_delegation, 1, foreign,
                                          MESH_WIRE_NOW, &rg),
                  MESH_STATUS_RECEIPT_NOT_PAIRED);
        PASS();
    }

    TEST("mesh status wire: the requester refuses forged or misdelivered "
         "receipts") {
        uint8_t pairing_id[32];
        ASSERT(zcl_hex_decode_lower(f.pairing.pairing_id, pairing_id, 32));
        struct mesh_status_request_v1 request;
        mesh_wire_request(&f, pairing_id, MESH_WIRE_NOW - 10,
                          MESH_WIRE_NOW + 20, &request);
        static const char capsule[] = "{\"schema\":\"zcl.machine_mesh_identity.v1\"}";
        struct mesh_status_receipt_v1 receipt;
        ASSERT(mesh_wire_sign_roundtrip(&f, &request, MESH_STATUS_RECEIPT_OK,
                                        capsule, &receipt));
        ASSERT(boot_mesh_status_receipt_accept(&receipt, &request,
                                               &f.ini_snap, f.resp_master_pub,
                                               f.resp_online_pub));

        struct json_value receipt_view;
        json_init(&receipt_view);
        boot_mesh_status_receipt_test_render(&receipt_view, &receipt);
        ASSERT(json_get(&receipt_view, "responder_master_fingerprint") != NULL);
        ASSERT(json_get(&receipt_view, "responder_online_fingerprint") != NULL);
        ASSERT(json_get(&receipt_view, "responder_master_pubkey") == NULL);
        ASSERT(json_get(&receipt_view, "responder_online_pubkey") == NULL);
        json_free(&receipt_view);

        /* Wrong responder master. */
        uint8_t wrong_master[32];
        mesh_fill32(wrong_master, 0xEE);
        ASSERT(!boot_mesh_status_receipt_accept(&receipt, &request,
                                                &f.ini_snap, wrong_master,
                                                f.resp_online_pub));
        /* A self-consistent signature under an arbitrary embedded online key
         * is not responder lineage. The expected active delegation key wins. */
        uint8_t wrong_seed[32], wrong_online[32], wrong_secret[32];
        mesh_fill32(wrong_seed, 0xD4);
        ed25519_keypair(wrong_online, wrong_secret, wrong_seed);
        memory_cleanse(wrong_secret, sizeof(wrong_secret));
        struct mesh_status_receipt_v1 wrong_lineage = receipt;
        memcpy(wrong_lineage.responder_online_pubkey, wrong_online, 32);
        ASSERT_EQ(mesh_status_receipt_v1_sign(&wrong_lineage, wrong_seed),
                  MESH_STATUS_PROTO_OK);
        memory_cleanse(wrong_seed, sizeof(wrong_seed));
        ASSERT(!boot_mesh_status_receipt_accept(
            &wrong_lineage, &request, &f.ini_snap, f.resp_master_pub,
            f.resp_online_pub));
        /* Receipt for a different request id. */
        struct mesh_status_request_v1 other;
        mesh_wire_request(&f, pairing_id, MESH_WIRE_NOW - 10,
                          MESH_WIRE_NOW + 20, &other);
        other.request_id[0] ^= 1;
        ASSERT(!boot_mesh_status_receipt_accept(&receipt, &other,
                                                &f.ini_snap,
                                                f.resp_master_pub,
                                                f.resp_online_pub));
        /* Bad signature. */
        struct mesh_status_receipt_v1 tampered = receipt;
        tampered.signature[0] ^= 1;
        ASSERT(!boot_mesh_status_receipt_accept(&tampered, &request,
                                                &f.ini_snap,
                                                f.resp_master_pub,
                                                f.resp_online_pub));
        /* A receipt delivered on a DIFFERENT session never completes the
         * pending entry, even though it verifies against the request. */
        uint8_t other_ini_priv[32], other_res_priv[32], other_pub[32];
        char error[160], other_req[320], other_resp[320];
        snprintf(other_req, sizeof(other_req), "%s/other_req", dir);
        snprintf(other_resp, sizeof(other_resp), "%s/other_resp", dir);
        ASSERT(platform_private_directory_create(other_req) &&
               platform_private_directory_create(other_resp));
        ASSERT(v2_identity_load_or_create(other_req, other_ini_priv,
                                          other_pub, error,
                                          sizeof(error)));
        ASSERT(v2_identity_load_or_create(other_resp, other_res_priv,
                                          other_pub, error,
                                          sizeof(error)));
        struct v2_transport *ini2 = NULL, *res2 = NULL;
        bool second = mesh_handshake(other_ini_priv, other_res_priv, &ini2,
                                     &res2);
        memory_cleanse(other_ini_priv, sizeof(other_ini_priv));
        memory_cleanse(other_res_priv, sizeof(other_res_priv));
        ASSERT(second);
        struct v2_transport_snapshot other_snap;
        ASSERT(v2_transport_snapshot(ini2, &other_snap));
        ASSERT(!boot_mesh_status_receipt_accept(&receipt, &request,
                                                &other_snap,
                                                f.resp_master_pub,
                                                f.resp_online_pub));
        v2_transport_free(ini2);
        v2_transport_free(res2);
        PASS();
    }

    TEST("mesh status wire: a full pending table returns BUSY without "
         "evicting a live request") {
        boot_mesh_status_wire(NULL);
        uint64_t generation = 0;
        (void)mesh_status_service(&generation);
        uint8_t master[32], online[32];
        mesh_fill32(master, 0xB1);
        mesh_fill32(online, 0xB2);
        bool admitted_all = generation != 0;
        struct mesh_status_request_v1 request;
        memset(&request, 0, sizeof(request));
        for (size_t i = 0; i < MESH_STATUS_PENDING_MAX; i++) {
            memset(request.request_id, 0, sizeof(request.request_id));
            request.request_id[0] = (uint8_t)(i + 1u);
            admitted_all = admitted_all && mesh_status_pending_admit(
                &request, master, online, generation);
        }
        memset(request.request_id, 0, sizeof(request.request_id));
        request.request_id[0] = 0xF1;
        bool overflow_admitted = mesh_status_pending_admit(
            &request, master, online, generation);
        uint8_t first_id[32] = {1};
        enum boot_mesh_status_poll_state first_state =
            boot_mesh_status_poll(first_id, NULL);
        enum boot_mesh_status_poll_state overflow_state =
            boot_mesh_status_poll(request.request_id, NULL);
        boot_mesh_status_shutdown();
        ASSERT(admitted_all);
        ASSERT(!overflow_admitted);
        ASSERT_EQ(first_state, MESH_STATUS_POLL_PENDING);
        ASSERT_EQ(overflow_state, MESH_STATUS_POLL_UNKNOWN);
        PASS();
    }

    TEST("mesh status wire: responder replay and cadence are bounded per "
         "authenticated session") {
        boot_mesh_status_wire(NULL);
        struct mesh_status_request_v1 request;
        memset(&request, 0, sizeof(request));
        request.request_id[0] = 1;
        bool first = boot_mesh_status_test_responder_admit(
            &request, &f.res_snap, 1000);
        bool duplicate = boot_mesh_status_test_responder_admit(
            &request, &f.res_snap, 1000);
        bool burst = true;
        for (uint8_t id = 2; id <= 4; id++) {
            request.request_id[0] = id;
            burst = burst && boot_mesh_status_test_responder_admit(
                &request, &f.res_snap, 1000);
        }
        request.request_id[0] = 5;
        bool rate_limited = boot_mesh_status_test_responder_admit(
            &request, &f.res_snap, 1000);
        bool next_window = boot_mesh_status_test_responder_admit(
            &request, &f.res_snap, 2001);
        request.request_id[0] = 1;
        bool after_replay_window = boot_mesh_status_test_responder_admit(
            &request, &f.res_snap, 32001);
        boot_mesh_status_shutdown();
        ASSERT(first);
        ASSERT(!duplicate);
        ASSERT(burst);
        ASSERT(!rate_limited);
        ASSERT(next_window);
        ASSERT(after_replay_window);
        PASS();
    }

    TEST("mesh status refresh yields to chain and resource pressure") {
        struct node_db_status ready = {
            .open = true,
            .tx_open = false,
            .turbo_mode = false,
            .sync_pending_blocks = 0,
        };
        ASSERT(boot_mesh_status_refresh_test_gate(
            true, SYNC_AT_TIP, DISK_MONITOR_OK, MEM_NOMINAL, false, true,
            &ready));
        ASSERT(!boot_mesh_status_refresh_test_gate(
            true, SYNC_BLOCKS_DOWNLOAD, DISK_MONITOR_OK, MEM_NOMINAL, false,
            true, &ready));
        ASSERT(!boot_mesh_status_refresh_test_gate(
            true, SYNC_AT_TIP, DISK_MONITOR_LOW, MEM_NOMINAL, false, true,
            &ready));
        ASSERT(!boot_mesh_status_refresh_test_gate(
            true, SYNC_AT_TIP, DISK_MONITOR_OK, MEM_HIGH, false, true,
            &ready));
        ASSERT(!boot_mesh_status_refresh_test_gate(
            true, SYNC_AT_TIP, DISK_MONITOR_OK, MEM_NOMINAL, true, true,
            &ready));
        ready.tx_open = true;
        ASSERT(!boot_mesh_status_refresh_test_gate(
            true, SYNC_AT_TIP, DISK_MONITOR_OK, MEM_NOMINAL, false, true,
            &ready));
        ready.tx_open = false;
        ready.sync_pending_blocks = 1;
        ASSERT(!boot_mesh_status_refresh_test_gate(
            true, SYNC_AT_TIP, DISK_MONITOR_OK, MEM_NOMINAL, false, true,
            &ready));
        PASS();
    }

    TEST("mesh status wire: revocation is sticky across the wire decision") {
        uint8_t pairing_id[32];
        ASSERT(zcl_hex_decode_lower(f.pairing.pairing_id, pairing_id, 32));
        struct mesh_status_request_v1 request;
        mesh_wire_request(&f, pairing_id, MESH_WIRE_NOW - 10,
                          MESH_WIRE_NOW + 20, &request);
        uint64_t rg;
        ASSERT_EQ(boot_mesh_status_decide(&f.ndb, &request, &f.res_snap,
                                          &f.peer_delegation, 1, f.genesis,
                                          MESH_WIRE_NOW, &rg),
                  MESH_STATUS_RECEIPT_OK);
        /* Revoke AFTER the accept: the same request must now fail closed. */
        ASSERT_EQ(mesh_pairing_service_revoke(&f.ndb, f.pairing.pairing_id,
                                              MESH_WIRE_NOW),
                  MESH_PAIRING_OK);
        ASSERT_EQ(boot_mesh_status_decide(&f.ndb, &request, &f.res_snap,
                                          &f.peer_delegation, 1, f.genesis,
                                          MESH_WIRE_NOW, &rg),
                  MESH_STATUS_RECEIPT_REVOKED);
        struct mesh_status_receipt_v1 receipt;
        ASSERT(mesh_wire_sign_roundtrip(&f, &request, MESH_STATUS_RECEIPT_REVOKED,
                                        NULL, &receipt));
        node_db_close(&f.ndb);
        char path[320];
        snprintf(path, sizeof(path), "%s/node.db", dir);
        ASSERT(node_db_open(&f.ndb, path));
        ASSERT_EQ(boot_mesh_status_decide(&f.ndb, &request, &f.res_snap,
                                          &f.peer_delegation, 1, f.genesis,
                                          MESH_WIRE_NOW, &rg),
                  MESH_STATUS_RECEIPT_REVOKED);
        PASS();
    }

    /* ── Fleet view projection: pure state derivation, probe planning, and
     * tally — the exact production mapping, no sockets or fixture. ── */

    TEST("mesh machines: derive state from record, begin, poll, receipt") {
        const char *detail = NULL;
        /* Expired and revoked durable records are never probed; the begin
         * and poll arguments must be ignored entirely. */
        ASSERT_EQ(mesh_machine_derive_state("expired", MESH_STATUS_BEGIN_OK,
                                            MESH_STATUS_POLL_OK,
                                            MESH_STATUS_RECEIPT_OK, &detail),
                  MESH_MACHINE_EXPIRED);
        ASSERT_STR_EQ(detail, "");
        ASSERT_EQ(mesh_machine_derive_state("revoked", MESH_STATUS_BEGIN_OK,
                                            MESH_STATUS_POLL_REFUSED,
                                            MESH_STATUS_RECEIPT_REVOKED,
                                            &detail),
                  MESH_MACHINE_REVOKED);
        ASSERT_STR_EQ(detail, "");
        ASSERT_EQ(mesh_machine_derive_state("wedged", MESH_STATUS_BEGIN_OK,
                                            MESH_STATUS_POLL_OK,
                                            MESH_STATUS_RECEIPT_OK, &detail),
                  MESH_MACHINE_UNKNOWN);
        ASSERT_STR_EQ(detail, "unrecognized_record_state");
        ASSERT_EQ(mesh_machine_derive_state(NULL, MESH_STATUS_BEGIN_OK,
                                            MESH_STATUS_POLL_OK,
                                            MESH_STATUS_RECEIPT_OK, &detail),
                  MESH_MACHINE_UNKNOWN);
        ASSERT_STR_EQ(detail, "unrecognized_record_state");
        /* Begin verdicts on active records. */
        ASSERT_EQ(mesh_machine_derive_state(
                      "active", MESH_STATUS_BEGIN_PEER_NOT_CONNECTED,
                      MESH_STATUS_POLL_PENDING, MESH_STATUS_RECEIPT_INTERNAL,
                      &detail),
                  MESH_MACHINE_UNREACHABLE);
        ASSERT_STR_EQ(detail, "no_live_v2_session");
        ASSERT_EQ(mesh_machine_derive_state(
                      "active", MESH_STATUS_BEGIN_V2_DISABLED,
                      MESH_STATUS_POLL_PENDING, MESH_STATUS_RECEIPT_INTERNAL,
                      &detail),
                  MESH_MACHINE_UNREACHABLE);
        ASSERT_STR_EQ(detail, "v2_transport_disabled");
        ASSERT_EQ(mesh_machine_derive_state(
                      "active", MESH_STATUS_BEGIN_REVOKED,
                      MESH_STATUS_POLL_PENDING, MESH_STATUS_RECEIPT_INTERNAL,
                      &detail),
                  MESH_MACHINE_REVOKED);
        ASSERT_STR_EQ(detail, "record_revoked_before_probe");
        ASSERT_EQ(mesh_machine_derive_state(
                      "active", MESH_STATUS_BEGIN_EXPIRED,
                      MESH_STATUS_POLL_PENDING, MESH_STATUS_RECEIPT_INTERNAL,
                      &detail),
                  MESH_MACHINE_EXPIRED);
        ASSERT_STR_EQ(detail, "record_expired_before_probe");
        ASSERT_EQ(mesh_machine_derive_state(
                      "active", MESH_STATUS_BEGIN_NOT_PAIRED,
                      MESH_STATUS_POLL_PENDING, MESH_STATUS_RECEIPT_INTERNAL,
                      &detail),
                  MESH_MACHINE_UNKNOWN);
        ASSERT_STR_EQ(detail, "record_vanished_before_probe");
        ASSERT_EQ(mesh_machine_derive_state(
                      "active", MESH_STATUS_BEGIN_BUSY,
                      MESH_STATUS_POLL_PENDING, MESH_STATUS_RECEIPT_INTERNAL,
                      &detail),
                  MESH_MACHINE_UNKNOWN);
        ASSERT_STR_EQ(detail, "pending_table_full");
        ASSERT_EQ(mesh_machine_derive_state(
                      "active", MESH_STATUS_BEGIN_SEND_FAILED,
                      MESH_STATUS_POLL_PENDING, MESH_STATUS_RECEIPT_INTERNAL,
                      &detail),
                  MESH_MACHINE_UNKNOWN);
        ASSERT_STR_EQ(detail, "send_failed");
        ASSERT_EQ(mesh_machine_derive_state(
                      "active", MESH_STATUS_BEGIN_IDENTITY_UNAVAILABLE,
                      MESH_STATUS_POLL_PENDING, MESH_STATUS_RECEIPT_INTERNAL,
                      &detail),
                  MESH_MACHINE_UNKNOWN);
        ASSERT_STR_EQ(detail, "local_identity_unavailable");
        ASSERT_EQ(mesh_machine_derive_state(
                      "active", MESH_STATUS_BEGIN_UNAVAILABLE,
                      MESH_STATUS_POLL_PENDING, MESH_STATUS_RECEIPT_INTERNAL,
                      &detail),
                  MESH_MACHINE_UNKNOWN);
        ASSERT_STR_EQ(detail, "status_lane_unavailable");
        /* Poll outcomes after a successful begin. */
        ASSERT_EQ(mesh_machine_derive_state("active", MESH_STATUS_BEGIN_OK,
                                            MESH_STATUS_POLL_OK,
                                            MESH_STATUS_RECEIPT_OK, &detail),
                  MESH_MACHINE_ONLINE);
        ASSERT_STR_EQ(detail, "");
        ASSERT_EQ(mesh_machine_derive_state(
                      "active", MESH_STATUS_BEGIN_OK, MESH_STATUS_POLL_REFUSED,
                      MESH_STATUS_RECEIPT_SESSION_MISMATCH, &detail),
                  MESH_MACHINE_REFUSED);
        /* The detail is the hyphenated wire token, ready for
         * "refused:<token>" composition. */
        ASSERT_STR_EQ(detail, "session-mismatch");
        ASSERT_EQ(mesh_machine_derive_state(
                      "active", MESH_STATUS_BEGIN_OK,
                      MESH_STATUS_POLL_EXPIRED, MESH_STATUS_RECEIPT_INTERNAL,
                      &detail),
                  MESH_MACHINE_TIMEOUT);
        ASSERT_STR_EQ(detail, "request_expired_unanswered");
        ASSERT_EQ(mesh_machine_derive_state(
                      "active", MESH_STATUS_BEGIN_OK,
                      MESH_STATUS_POLL_PENDING, MESH_STATUS_RECEIPT_INTERNAL,
                      &detail),
                  MESH_MACHINE_TIMEOUT);
        ASSERT_STR_EQ(detail, "collect_budget_exhausted");
        ASSERT_EQ(mesh_machine_derive_state(
                      "active", MESH_STATUS_BEGIN_OK,
                      MESH_STATUS_POLL_UNKNOWN, MESH_STATUS_RECEIPT_INTERNAL,
                      &detail),
                  MESH_MACHINE_UNKNOWN);
        ASSERT_STR_EQ(detail, "request_lost");
        /* Upstream receipt-binding: a connected peer without a unique active
         * delegation is an authority gap, UNKNOWN — never UNREACHABLE, since
         * the session itself is live. */
        ASSERT_EQ(mesh_machine_derive_state(
                      "active", MESH_STATUS_BEGIN_PEER_IDENTITY_UNAVAILABLE,
                      MESH_STATUS_POLL_PENDING, MESH_STATUS_RECEIPT_INTERNAL,
                      &detail),
                  MESH_MACHINE_UNKNOWN);
        ASSERT_STR_EQ(detail, "peer_identity_unavailable");
        PASS();
    }

    TEST("mesh machines: fleet burst always fits the status pending table") {
        /* Upstream admission refuses a still-full pending table instead of
         * evicting the oldest live request; a fleet cap above the table
         * bound would self-congest a machines call into BUSY rows. The
         * compile-time twin of this pin lives in boot_mesh_machines.c. */
        ASSERT(MESH_MACHINES_FLEET_MAX <= MESH_STATUS_PENDING_MAX);
        PASS();
    }

    TEST("mesh machines: probe planning caps actives and flags truncation") {
        const char *ten_active[10] = {
            "active", "active", "active", "active", "active",
            "active", "active", "active", "active", "active",
        };
        bool probes[10];
        bool truncated = false;
        ASSERT_EQ(mesh_machines_plan_probes(ten_active, 10,
                                            MESH_MACHINES_FLEET_MAX, probes,
                                            &truncated),
                  MESH_MACHINES_FLEET_MAX);
        ASSERT(truncated);
        for (size_t i = 0; i < 10; i++)
            ASSERT_EQ(probes[i], i < MESH_MACHINES_FLEET_MAX);

        /* Only active records are ever probed; expired and revoked are
         * durable truths that need no wire round trip. */
        const char *mixed[5] = {
            "active", "expired", "revoked", "active", "wedged",
        };
        bool mixed_probes[5];
        truncated = false;
        ASSERT_EQ(mesh_machines_plan_probes(mixed, 5, MESH_MACHINES_FLEET_MAX,
                                            mixed_probes, &truncated),
                  2);
        ASSERT(!truncated);
        ASSERT(mixed_probes[0] && !mixed_probes[1] && !mixed_probes[2] &&
               mixed_probes[3] && !mixed_probes[4]);

        const char *two_active[2] = { "active", "active" };
        bool two_probes[2];
        truncated = false;
        ASSERT_EQ(mesh_machines_plan_probes(two_active, 2,
                                            MESH_MACHINES_FLEET_MAX,
                                            two_probes, &truncated),
                  2);
        ASSERT(!truncated);
        ASSERT(two_probes[0] && two_probes[1]);
        PASS();
    }

    TEST("mesh machines: tally rolls up every verdict, unknown only totals") {
        struct mesh_machine_row rows[7];
        memset(rows, 0, sizeof(rows));
        rows[0].state = MESH_MACHINE_ONLINE;
        rows[1].state = MESH_MACHINE_REFUSED;
        rows[2].state = MESH_MACHINE_UNREACHABLE;
        rows[3].state = MESH_MACHINE_TIMEOUT;
        rows[4].state = MESH_MACHINE_UNKNOWN;
        rows[5].state = MESH_MACHINE_EXPIRED;
        rows[6].state = MESH_MACHINE_REVOKED;
        struct mesh_machines_counts counts;
        mesh_machines_tally(rows, 7, &counts);
        ASSERT_EQ(counts.total, 7);
        ASSERT_EQ(counts.online, 1);
        ASSERT_EQ(counts.refused, 1);
        ASSERT_EQ(counts.unreachable, 1);
        ASSERT_EQ(counts.timeout, 1);
        ASSERT_EQ(counts.expired, 1);
        ASSERT_EQ(counts.revoked, 1);

        /* Empty fleet: every count is zero, nothing invented. */
        mesh_machines_tally(rows, 0, &counts);
        ASSERT_EQ(counts.total, 0);
        ASSERT_EQ(counts.online, 0);
        ASSERT_EQ(counts.refused, 0);
        ASSERT_EQ(counts.unreachable, 0);
        ASSERT_EQ(counts.timeout, 0);
        ASSERT_EQ(counts.expired, 0);
        ASSERT_EQ(counts.revoked, 0);
        PASS();
    }

_test_next:
    if (fixture_open)
        mesh_wire_fixture_close(&f);
    test_rm_rf_recursive(dir);
    return failures;
}
