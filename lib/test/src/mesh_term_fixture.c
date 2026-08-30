/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared fixture for the mesh terminal lane's test groups (see the header
 * for the contract). Test-only: nothing in production links this file.
 */

#include "test/mesh_term_fixture.h"

#include "base/cleanse.h"
#include "crypto/ed25519.h"
#include "models/zid_identity.h"
#include "net/v2_identity.h"
#include "platform/private_directory.h"
#include "services/mesh_pairing_service.h"
#include "validation/main_constants.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void mesh_term_fill32(uint8_t out[32], uint8_t value)
{
    memset(out, value, 32);
}

/* raw-sql-ok:test-fixture -- creates only the connected chain rows required
 * to exercise the production chain-bound pairing verifier. */
static bool mesh_term_seed_block(struct node_db *ndb, int height,
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

static const unsigned char MESH_TERM_TEST_MAGIC[4] = {0x24, 0xe9, 0x27, 0x64};

/* Full XX handshake between two in-process transports; both sides
 * ESTABLISHED on return. */
static bool mesh_term_handshake(const uint8_t ini_priv[32],
                                const uint8_t res_priv[32],
                                struct noise_transport **ini_out,
                                struct noise_transport **res_out)
{
    uint8_t *msg1 = NULL, *w1 = NULL, *w2 = NULL, *w3 = NULL, *p = NULL;
    size_t msg1_len = 0, w1l = 0, w2l = 0, w3l = 0, pl = 0;
    struct noise_transport *ini =
        noise_transport_begin(true, ini_priv, MESH_TERM_TEST_MAGIC, &msg1,
                              &msg1_len);
    struct noise_transport *res =
        noise_transport_begin(false, res_priv, MESH_TERM_TEST_MAGIC, NULL,
                              NULL);
    bool ok = ini && res && msg1 && msg1_len == 32 &&
              noise_transport_feed(res, msg1, msg1_len, &w2, &w2l, &p,
                                   &pl) &&
              w2l == 96 && pl == 0 &&
              noise_transport_feed(ini, w2, w2l, &w3, &w3l, &p, &pl) &&
              w3l == 64 && pl == 0 &&
              noise_transport_feed(res, w3, w3l, &w1, &w1l, &p, &pl) &&
              w1l == 0 && pl == 0 && ini->state == NOISE_ESTABLISHED &&
              res->state == NOISE_ESTABLISHED;
    free(msg1);
    free(w1);
    free(w2);
    free(w3);
    free(p);
    if (!ok) {
        noise_transport_free(ini);
        noise_transport_free(res);
        return false;
    }
    *ini_out = ini;
    *res_out = res;
    return true;
}

bool mesh_term_frame_roundtrip(struct noise_transport *from,
                               struct noise_transport *to,
                               const uint8_t *frame, size_t frame_len,
                               uint8_t *delivered, size_t delivered_cap)
{
    uint8_t *ct = NULL, *pt = NULL, *wire = NULL;
    size_t ct_len = 0, pt_len = 0, wire_len = 0;
    bool ok = noise_transport_write(from, frame, frame_len, &ct, &ct_len) &&
              ct_len > 0 &&
              noise_transport_feed(to, ct, ct_len, &wire, &wire_len, &pt,
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

bool mesh_term_capsule_text(const uint8_t *capsule, size_t capsule_len,
                            char *text, size_t text_cap)
{
    if (capsule_len + 1u > text_cap)
        return false;
    memcpy(text, capsule, capsule_len);
    text[capsule_len] = '\0';
    return true;
}

bool mesh_term_fixture_open(struct mesh_term_fixture *f, const char *dir)
{
    memset(f, 0, sizeof(*f));
    char path[320], req_a[320], req_b[320], respdir[320];
    snprintf(path, sizeof(path), "%s/node.db", dir);
    snprintf(req_a, sizeof(req_a), "%s/reqA", dir);
    snprintf(req_b, sizeof(req_b), "%s/reqB", dir);
    snprintf(respdir, sizeof(respdir), "%s/resp", dir);
    char error[160];
    uint8_t a_priv[32], b_priv[32], resp_noise_priv[32];

    /* One responder Noise static serves both peer sessions; each handshake
     * is an independent transport pair over it. */
    bool ok = platform_private_directory_create(req_a) &&
              platform_private_directory_create(req_b) &&
              platform_private_directory_create(respdir) &&
              v2_identity_load_or_create(req_a, a_priv,
                                         f->status_peer.noise_pub,
                                         error, sizeof(error)) &&
              v2_identity_load_or_create(req_b, b_priv,
                                         f->term_peer.noise_pub,
                                         error, sizeof(error)) &&
              v2_identity_load_or_create(respdir, resp_noise_priv,
                                         f->resp_noise_pub, error,
                                         sizeof(error)) &&
              mesh_term_handshake(a_priv, resp_noise_priv,
                                  &f->status_peer.ini, &f->res_status) &&
              mesh_term_handshake(b_priv, resp_noise_priv,
                                  &f->term_peer.ini, &f->res_term);
    memory_cleanse(a_priv, sizeof(a_priv));
    memory_cleanse(b_priv, sizeof(b_priv));
    memory_cleanse(resp_noise_priv, sizeof(resp_noise_priv));
    if (!ok)
        return false;
    if (!noise_transport_snapshot(f->res_status,
                                  &f->status_peer.res_snap) ||
        !noise_transport_snapshot(f->res_term, &f->term_peer.res_snap))
        return false;
    /* The session binding is genuinely shared, and each responder-side
     * snapshot names the requesting peer's identity-file static. */
    if (!f->status_peer.res_snap.established ||
        !f->term_peer.res_snap.established ||
        memcmp(f->status_peer.res_snap.remote_static, f->status_peer.noise_pub,
               32) != 0 ||
        memcmp(f->term_peer.res_snap.remote_static, f->term_peer.noise_pub,
               32) != 0)
        return false;

    if (!node_db_open(&f->ndb, path))
        return false;
    uint8_t beacon[32], tip[32];
    mesh_term_fill32(f->genesis, 0x11);
    mesh_term_fill32(beacon, 0x22);
    mesh_term_fill32(tip, 0x33);
    if (!mesh_term_seed_block(&f->ndb, 0, f->genesis) ||
        !mesh_term_seed_block(&f->ndb, ZCL_FINALITY_DEPTH, beacon) ||
        !mesh_term_seed_block(&f->ndb, 2 * ZCL_FINALITY_DEPTH, tip))
        return false;

    struct mesh_term_peer *peers[2] = { &f->status_peer, &f->term_peer };
    for (size_t i = 0; i < 2; i++) {
        uint8_t online[32], master_seed[32];
        mesh_term_fill32(online, 0x44);
        mesh_term_fill32(master_seed, (uint8_t)(0x60 + (int)i));
        if (vcs_zcode_dht_delegation_sign(
                &peers[i]->delegation, f->genesis, online, peers[i]->noise_pub,
                ZCL_FINALITY_DEPTH, beacon, 1000, 4000, 7,
                master_seed) != VCS_ZCODE_DHT_DELEGATION_OK)
            return false;
        memory_cleanse(master_seed, sizeof(master_seed));
        struct zid_identity identity = {0};
        memcpy(identity.master_pubkey, peers[i]->delegation.doc.master_pubkey,
               32);
        mesh_term_fill32(identity.anchor_txid, 0x77);
        identity.anchor_height = 0;
        identity.updated_height = 0;
        snprintf(identity.status, sizeof(identity.status), "%s",
                 ZID_IDENTITY_STATUS_ACTIVE);
        snprintf(identity.source, sizeof(identity.source), "%s",
                 ZID_IDENTITY_SOURCE_ZID_OVERLAY);
        if (!db_zid_identity_save(&f->ndb, &identity))
            return false;
    }
    uint8_t resp_master_seed[32], secret[32];
    mesh_term_fill32(resp_master_seed, 0x88);
    mesh_term_fill32(f->resp_online_seed, 0x99);
    ed25519_keypair(f->resp_master_pub, secret, resp_master_seed);
    memory_cleanse(secret, sizeof(secret));
    ed25519_keypair(f->resp_online_pub, secret, f->resp_online_seed);
    memory_cleanse(secret, sizeof(secret));
    return true;
}

void mesh_term_fixture_close(struct mesh_term_fixture *f)
{
    noise_transport_free(f->res_status);
    noise_transport_free(f->res_term);
    noise_transport_free(f->status_peer.ini);
    noise_transport_free(f->term_peer.ini);
    f->res_status = NULL;
    f->res_term = NULL;
    f->status_peer.ini = NULL;
    f->term_peer.ini = NULL;
    if (f->ndb.open)
        node_db_close(&f->ndb);
}

void mesh_term_compose_open(const struct mesh_term_fixture *f,
                            const struct mesh_term_peer *peer,
                            const uint8_t pairing_id[32], uint64_t issued,
                            uint64_t expires, uint64_t capability,
                            struct mesh_terminal_open_v1 *out)
{
    memset(out, 0, sizeof(*out));
    out->version = MESH_TERMINAL_PROTO_VERSION;
    out->flags = MESH_TERMINAL_PROTO_FLAGS_NONE;
    out->capability = capability;
    mesh_term_fill32(out->terminal_id, 0x5C);
    memcpy(out->network_genesis, f->genesis, 32);
    memcpy(out->target_master_pubkey, f->resp_master_pub, 32);
    memcpy(out->requester_master_pubkey, peer->delegation.doc.master_pubkey,
           32);
    memcpy(out->requester_noise_static, peer->noise_pub, 32);
    memcpy(out->pairing_id, pairing_id, 32);
    memcpy(out->transcript_hash, peer->res_snap.transcript_hash, 32);
    out->connection_generation = peer->res_snap.connection_generation;
    out->issued_unix = issued;
    out->expires_unix = expires;
    out->cols = 80;
    out->rows = 24;
}

bool mesh_term_pair_accept(struct mesh_term_fixture *f,
                           struct mesh_term_peer *peer,
                           uint64_t capability_mask)
{
    uint8_t fingerprint[32];
    if (!v2_identity_public_fingerprint(peer->noise_pub, fingerprint))
        return false;
    return mesh_pairing_service_accept(&f->ndb, &peer->delegation,
                                       fingerprint, peer->noise_pub, true,
                                       capability_mask, 2000, 3000,
                                       &peer->pairing) == MESH_PAIRING_OK;
}
