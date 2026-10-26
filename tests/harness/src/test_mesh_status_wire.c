/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Proves the mesh status wire fails closed: the responder decision is
 * pairing- and session-bound with sticky revocation, the receipt is signed
 * and request/session-bound, and the requester refuses forged or
 * misdelivered receipts. Uses the real pairing service against a real
 * node.db fixture, real Ed25519 keys, and two real in-process Noise
 * transports driven buffer-to-buffer (no sockets), so the session binding
 * is proven against genuine transcripts. */

#include "test/test_core.h"

#include "config/boot_mesh_status.h"
#include "config/boot_mesh_machines.h"
#include "../../../engine/composition/src/boot_mesh_status_internal.h"
#include "base/cleanse.h"
#include "base/hex.h"
#include "crypto/ed25519.h"
#include "json/json.h"
#include "models/mesh_pairing.h"
#include "models/database.h"
#include "models/zid_identity.h"
#include "net/v2_identity.h"
#include "net/noise_transport.h"
#include "platform/private_directory.h"
#include "services/mesh_pairing_service.h"
#include "services/disk_monitor.h"
#include "sync/sync_state.h"
#include "util/mem_pressure.h"
#include "util/util.h"
#include "validation/main_constants.h"
#include "vcs/zcode_dht_delegation.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MESH_WIRE_NOW 2500

/* ── plugins block fixtures ────────────────────────────────────────────── */

/* A 128-hex generation id whose first 16 characters differ per seed. */
static void mpl_gen_id(char out[PLUGIN_HEX_SHA3_512 + 1], unsigned seed)
{
    for (unsigned chunk = 0; chunk < 8; chunk++)
        snprintf(out + chunk * 16, 17, "%016llx",
                 0x0123456789abcdefULL * (seed + 1u) + chunk * 0x1111ULL);
}

static bool mpl_mkdir(const char *path)
{
    return mkdir(path, 0700) == 0 || access(path, F_OK) == 0;
}

/* Lay out HOME/.z23/plugins/NAME with one generation directory per id and
 * the current / last-good links; plugin_store_list reads exactly this. */
static bool mpl_store_plugin(const char *home, const char *name,
                             const char *current, const char *last_good)
{
    char p[PATH_MAX], q[PATH_MAX];
    bool ok = true;
    snprintf(p, sizeof(p), "%s/.z23", home);
    ok = ok && mpl_mkdir(home) && mpl_mkdir(p);
    snprintf(p, sizeof(p), "%s/.z23/plugins", home);
    ok = ok && mpl_mkdir(p);
    snprintf(p, sizeof(p), "%s/.z23/plugins/%s", home, name);
    ok = ok && mpl_mkdir(p);
    snprintf(q, sizeof(q), "%s/generations", p);
    ok = ok && mpl_mkdir(q);
    const char *ids[2] = {current, last_good};
    const char *links[2] = {"current", "last-good"};
    for (int i = 0; ok && i < 2; i++) {
        if (!ids[i])
            continue;
        char dirp[PATH_MAX], target[PATH_MAX];
        snprintf(dirp, sizeof(dirp), "%s/generations/%s", p, ids[i]);
        snprintf(q, sizeof(q), "%s/%s", p, links[i]);
        snprintf(target, sizeof(target), "generations/%s", ids[i]);
        ok = mpl_mkdir(dirp) && symlink(target, q) == 0;
    }
    return ok;
}

/* Identity base padded to `pad` extra bytes, then the plugins block. */
static bool mpl_render(const struct mesh_status_plugins *plugins, size_t pad,
                       uint8_t out[MESH_STATUS_CAPSULE_MAX + 1], size_t *len,
                       char *base, size_t base_cap, size_t *base_len)
{
    int n = snprintf(base, base_cap,
                     "{\"schema\":\"zcl.machine_mesh_identity.v1\","
                     "\"machine\":\"m1\",\"pad\":\"%*s\"}", (int)pad, "");
    if (n <= 0 || (size_t)n >= base_cap)
        return false;
    *base_len = (size_t)n;
    if (!mesh_status_capsule_with_plugins(base, *base_len, plugins, out, len))
        return false;
    out[*len] = '\0';
    return true;
}

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

/* The three XX message exchanges between ini and res, expecting the fixed
 * handshake sizes and no early payload; both sides must end ESTABLISHED.
 * Buffers are allocated into the caller's pointers, which the caller frees. */
static bool mesh_handshake_exchange(struct noise_transport *ini,
                                    struct noise_transport *res,
                                    const uint8_t *msg1, size_t msg1_len,
                                    uint8_t **w1, size_t *w1l,
                                    uint8_t **w2, size_t *w2l,
                                    uint8_t **w3, size_t *w3l,
                                    uint8_t **p, size_t *pl)
{
    return noise_transport_feed(res, msg1, msg1_len, w2, w2l, p, pl) &&
           *w2l == 1200 && *pl == 0 &&
           noise_transport_feed(ini, *w2, *w2l, w3, w3l, p, pl) &&
           *w3l == 64 && *pl == 0 &&
           noise_transport_feed(res, *w3, *w3l, w1, w1l, p, pl) &&
           *w1l == 0 && *pl == 0 && ini->state == NOISE_ESTABLISHED &&
           res->state == NOISE_ESTABLISHED;
}

/* Full XX handshake between two in-process transports with the given static
 * private keys; both sides ESTABLISHED on return. */
static bool mesh_handshake(const uint8_t ini_priv[32],
                           const uint8_t res_priv[32],
                           struct noise_transport **ini_out,
                           struct noise_transport **res_out)
{
    uint8_t *msg1 = NULL, *w1 = NULL, *w2 = NULL, *w3 = NULL, *p = NULL;
    size_t msg1_len = 0, w1l = 0, w2l = 0, w3l = 0, pl = 0;
    struct noise_transport *ini =
        noise_transport_begin(true, ini_priv, MESH_TEST_MAGIC, &msg1, &msg1_len);
    struct noise_transport *res =
        noise_transport_begin(false, res_priv, MESH_TEST_MAGIC, NULL, NULL);
    bool ok = ini && res && msg1 && msg1_len == 1216 &&
              mesh_handshake_exchange(ini, res, msg1, msg1_len,
                                      &w1, &w1l, &w2, &w2l, &w3, &w3l,
                                      &p, &pl);
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

/* Seal frame bytes on `from` and deliver them to `to`; plaintext must equal
 * the input byte-for-byte with no wire reply. */
static bool mesh_frame_roundtrip(struct noise_transport *from,
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
    struct noise_transport *ini;
    struct noise_transport *res;
    struct noise_transport_snapshot ini_snap;
    struct noise_transport_snapshot res_snap;
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
    if (!noise_transport_snapshot(f->ini, &f->ini_snap) ||
        !noise_transport_snapshot(f->res, &f->res_snap))
        return false;

    if (!node_db_open(&f->ndb, path))
        return false;
    uint8_t beacon[32], tip[32], peer_online[32], peer_master_seed[32];
    mesh_fill32(f->genesis, 0x11);
    mesh_fill32(beacon, 0x22);
    mesh_fill32(tip, 0x33);
    mesh_fill32(peer_online, 0x44);
    mesh_fill32(peer_master_seed, 0x66);
    /* No genesis row is seeded: a locally-mining node never persists one,
     * and the authority must bind the caller-supplied genesis instead. */
    if (!mesh_seed_block(&f->ndb, ZCL_FINALITY_DEPTH, beacon) ||
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
    noise_transport_free(f->ini);
    noise_transport_free(f->res);
    f->ini = NULL;
    f->res = NULL;
    if (f->ndb.open)
        node_db_close(&f->ndb);
}

/* The request as the requester composes it: bound to the REQUESTER's
 * session snapshot (the responder verifies shared transcript/generation
 * evidence). */
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


static int mpl_case_absent_and_two(const char *dir)
{
    int failures = 0;
    TEST_CASE("mesh status capsule: plugins block for an absent store and two installed plugins") {
        char home[PATH_MAX], ida[PLUGIN_HEX_SHA3_512 + 1],
            idb[PLUGIN_HEX_SHA3_512 + 1], idc[PLUGIN_HEX_SHA3_512 + 1];
        char base[MESH_STATUS_CAPSULE_MAX + 64];
        uint8_t out[MESH_STATUS_CAPSULE_MAX + 1];
        size_t out_len = 0, base_len = 0;
        struct mesh_status_plugins plugins;
        struct json_value doc;
        const struct json_value *block;


        /* (a) no store: unavailable, never an error, identity untouched. */
        snprintf(home, sizeof(home), "%s/plugins_absent", dir);
        ASSERT(mpl_mkdir(home));
        mesh_status_plugins_read(home, &plugins);
        ASSERT(!plugins.available);
        ASSERT_STR_EQ(plugins.reason, "store_absent");
        ASSERT(mpl_render(&plugins, 0, out, &out_len, base, sizeof(base),
                          &base_len));
        json_init(&doc);
        ASSERT(json_read(&doc, (const char *)out, out_len));
        ASSERT_STR_EQ(json_get_str(json_get(&doc, "schema")),
                      "zcl.machine_mesh_identity.v1");
        ASSERT_STR_EQ(json_get_str(json_get(&doc, "machine")), "m1");
        block = json_get(&doc, "plugins");
        ASSERT(block != NULL);
        ASSERT_STR_EQ(json_get_str(json_get(block, "schema")),
                      "zcl.mesh_status_plugins.v1");
        ASSERT(!json_get_bool(json_get(block, "available")));
        ASSERT_STR_EQ(json_get_str(json_get(block, "reason")), "store_absent");
        json_free(&doc);
        mesh_status_plugins_read(NULL, &plugins);
        ASSERT(!plugins.available);
        ASSERT_STR_EQ(plugins.reason, "home_unset");

        /* (b) two installed plugins: count 2, name order, 16-hex prefixes. */
        snprintf(home, sizeof(home), "%s/plugins_two", dir);
        mpl_gen_id(ida, 1);
        mpl_gen_id(idb, 2);
        mpl_gen_id(idc, 3);
        ASSERT(mpl_store_plugin(home, "beta", idb, ida));
        ASSERT(mpl_store_plugin(home, "alpha", idc, NULL));
        mesh_status_plugins_read(home, &plugins);
        ASSERT(plugins.available);
        ASSERT_EQ(plugins.count, 2u);
        ASSERT(mpl_render(&plugins, 0, out, &out_len, base, sizeof(base),
                          &base_len));
        json_init(&doc);
        ASSERT(json_read(&doc, (const char *)out, out_len));
        block = json_get(&doc, "plugins");
        ASSERT(block != NULL);
        ASSERT(json_get_bool(json_get(block, "available")));
        ASSERT_EQ(json_get_int(json_get(block, "count")), 2);
        ASSERT_EQ(json_get_int(json_get(block, "listed")), 2);
        ASSERT(!json_get_bool(json_get(block, "truncated")));
        const struct json_value *items = json_get(block, "items");
        ASSERT(items != NULL);
        ASSERT_EQ(json_size(items), 2u);
        ASSERT_STR_EQ(json_get_str(json_get(json_at(items, 0), "name")),
                      "alpha");
        ASSERT_EQ(strlen(json_get_str(json_get(json_at(items, 0), "current"))),
                  16u);
        ASSERT(strncmp(json_get_str(json_get(json_at(items, 0), "current")),
                       idc, 16) == 0);
        ASSERT_STR_EQ(json_get_str(json_get(json_at(items, 0), "last_good")),
                      "");
        ASSERT_STR_EQ(json_get_str(json_get(json_at(items, 1), "name")),
                      "beta");
        ASSERT(strncmp(json_get_str(json_get(json_at(items, 1), "current")),
                       idb, 16) == 0);
        ASSERT(strncmp(json_get_str(json_get(json_at(items, 1), "last_good")),
                       ida, 16) == 0);
        json_free(&doc);

        /* (d) corrupt current link: the row must report what the read
         * found ("corrupt"), never an empty prefix — an empty id is a
         * fact only for OK/MISSING slot reads (plugin_store.h contract),
         * and surfacing nothing here is the wrong fact this block exists
         * to avoid. */
        snprintf(home, sizeof(home), "%s/plugins_corrupt", dir);
        mpl_gen_id(ida, 7);
        ASSERT(mpl_store_plugin(home, "alpha", ida, NULL));
        {
            char linkp[PATH_MAX];
            snprintf(linkp, sizeof(linkp),
                     "%s/.z23/plugins/alpha/current", home);
            unlink(linkp);
            ASSERT(symlink("bogus-target", linkp) == 0);
        }
        mesh_status_plugins_read(home, &plugins);
        ASSERT(plugins.available);
        ASSERT_EQ(plugins.count, 1u);
        ASSERT_EQ(plugins.listed, 1u);
        ASSERT_STR_EQ(plugins.items[0].name, "alpha");
        ASSERT_STR_EQ(plugins.items[0].current, "corrupt");
        ASSERT_STR_EQ(plugins.items[0].last_good, "");

    } TEST_END
    return failures;
}

static int mpl_case_squeeze(const char *dir)
{
    int failures = 0;
    TEST_CASE("mesh status capsule: rows shed before identity, nothing fitting leaves the old capsule") {
        char home[PATH_MAX], ida[PLUGIN_HEX_SHA3_512 + 1];
        char base[MESH_STATUS_CAPSULE_MAX + 64];
        uint8_t out[MESH_STATUS_CAPSULE_MAX + 1];
        size_t out_len = 0, base_len = 0;
        struct mesh_status_plugins plugins;
        struct json_value doc;
        const struct json_value *block;

        /* More plugins than the row cap: 8 listed, count says 10. */
        snprintf(home, sizeof(home), "%s/plugins_many", dir);
        for (unsigned i = 0; i < 10; i++) {
            char name[16];
            snprintf(name, sizeof(name), "p%02u", i);
            mpl_gen_id(ida, 10 + i);
            ASSERT(mpl_store_plugin(home, name, ida, NULL));
        }
        mesh_status_plugins_read(home, &plugins);
        ASSERT(plugins.available);
        ASSERT_EQ(plugins.count, 10u);
        ASSERT_EQ(plugins.listed, 8u);
        ASSERT(mpl_render(&plugins, 0, out, &out_len, base, sizeof(base),
                          &base_len));
        json_init(&doc);
        ASSERT(json_read(&doc, (const char *)out, out_len));
        block = json_get(&doc, "plugins");
        ASSERT(block != NULL);
        ASSERT_EQ(json_get_int(json_get(block, "count")), 10);
        ASSERT_EQ(json_size(json_get(block, "items")), 8u);
        ASSERT(json_get_bool(json_get(block, "truncated")));
        json_free(&doc);

        /* (c) squeeze the identity toward the cap: rows are shed from the
         * end with truncated=true and identity intact; once even zero rows do
         * not fit the output is the old capsule byte for byte. */
        bool saw_partial = false, saw_bare = false, saw_full = false;
        for (size_t pad = 2900; pad < 4000; pad++) {
            if (!mpl_render(&plugins, pad, out, &out_len, base, sizeof(base),
                            &base_len))
                break;
            ASSERT(out_len <= MESH_STATUS_CAPSULE_MAX);
            json_init(&doc);
            ASSERT(json_read(&doc, (const char *)out, out_len));
            ASSERT_STR_EQ(json_get_str(json_get(&doc, "machine")), "m1");
            block = json_get(&doc, "plugins");
            if (!block) {
                ASSERT_EQ(out_len, base_len);
                ASSERT(memcmp(out, base, base_len) == 0);
                saw_bare = true;
            } else {
                int64_t listed = json_get_int(json_get(block, "listed"));
                ASSERT_EQ((int64_t)json_size(json_get(block, "items")),
                          listed);
                ASSERT_EQ(json_get_int(json_get(block, "count")), 10);
                ASSERT_EQ(json_get_bool(json_get(block, "truncated")),
                          listed < 10);
                saw_partial = saw_partial || (listed > 0 && listed < 8);
                saw_full = saw_full || listed == 8;
            }
            json_free(&doc);
        }
        ASSERT(saw_full);
        ASSERT(saw_partial);
        ASSERT(saw_bare);

    } TEST_END
    return failures;
}

static int mpl_case_receipt(const char *dir, const struct mesh_wire_fixture *f)
{
    int failures = 0;
    TEST_CASE("mesh status capsule: the signed receipt over a shed capsule verifies") {
        char home[PATH_MAX];
        char base[MESH_STATUS_CAPSULE_MAX + 64];
        uint8_t out[MESH_STATUS_CAPSULE_MAX + 1];
        size_t out_len = 0, base_len = 0;
        struct mesh_status_plugins plugins;
        snprintf(home, sizeof(home), "%s/plugins_many", dir);
        mesh_status_plugins_read(home, &plugins);
        /* (d) the signed receipt over a shed capsule still verifies. */
        uint8_t pairing_id[32];
        ASSERT(zcl_hex_decode_lower(f->pairing.pairing_id, pairing_id, 32));
        struct mesh_status_request_v1 request;
        mesh_wire_request(f, pairing_id, MESH_WIRE_NOW - 10,
                          MESH_WIRE_NOW + 20, &request);
        for (size_t pad = 0; pad < 2; pad++) {
            ASSERT(mpl_render(&plugins, pad ? 3300 : 0, out, &out_len, base,
                              sizeof(base), &base_len));
            struct mesh_status_receipt_v1 receipt;
            ASSERT(mesh_wire_sign_roundtrip(f, &request,
                                            MESH_STATUS_RECEIPT_OK,
                                            (const char *)out, &receipt));
            ASSERT_EQ(receipt.capsule_len, out_len);
            ASSERT(memcmp(receipt.capsule, out, out_len) == 0);
            ASSERT(boot_mesh_status_receipt_accept(
                &receipt, &request, &f->ini_snap, f->resp_master_pub,
                f->resp_online_pub));
        }
    } TEST_END
    return failures;
}
/* The plugins block of finished capsule bytes: count (-1 when the key is
 * absent or the bytes do not parse); reason, when given, receives the
 * unavailable reason (empty when available). */
static int64_t mpl_block_count(const uint8_t *bytes, size_t len,
                               char reason[32])
{
    struct json_value doc;
    json_init(&doc);
    int64_t count = -1;
    if (json_read(&doc, (const char *)bytes, len)) {
        const struct json_value *block = json_get(&doc, "plugins");
        if (block) {
            count = json_get_int(json_get(block, "count"));
            const char *why = json_get_str(json_get(block, "reason"));
            snprintf(reason, 32, "%s", why ? why : "");
        }
    }
    json_free(&doc);
    return count;
}

static void mpl_set_option(bool on)
{
    static const char *const off_argv[] = {"z23"};
    static const char *const on_argv[] = {"z23", "-meshstatusplugins=1"};
    ParseParameters(on ? 2 : 1, on ? on_argv : off_argv);
}

static int mpl_case_option_off(const char *dir)
{
    int failures = 0;
    TEST_CASE("mesh status capsule: option off is exactly the identity render and never reads") {
        char base[MESH_STATUS_CAPSULE_MAX + 64], reason[32] = "";
        uint8_t out[MESH_STATUS_CAPSULE_MAX + 1];
        size_t out_len = 0, base_len = 0;
        struct mesh_status_plugins plugins;
        char home[PATH_MAX];
        snprintf(home, sizeof(home), "%s/plugins_two", dir);
        mpl_set_option(false);
        mesh_status_plugins_cache_reset();
        mesh_status_plugins_read(home, &plugins);
        mesh_status_plugins_cache_set(&plugins, 1000); /* data is cached... */
        snprintf(base, sizeof(base),
                 "{\"schema\":\"zcl.machine_mesh_identity.v1\",\"machine\":\"m1\"}");
        base_len = strlen(base);
        mesh_status_capsule_finish(base, base_len, out, &out_len);
        ASSERT_EQ(out_len, base_len); /* ...yet not one byte is appended */
        ASSERT(memcmp(out, base, base_len) == 0);
        ASSERT_EQ(mpl_block_count(out, out_len, reason), -1);
        /* The refresh tick is inert too: a later store change is not read. */
        mesh_status_plugins_cache_reset();
        mesh_status_plugins_cache_refresh(home, 5000);
        mesh_status_plugins_cache_snapshot(&plugins);
        ASSERT(!plugins.available);
        ASSERT_STR_EQ(plugins.reason, "not_yet_read");
    } TEST_END
    mpl_set_option(false);
    mesh_status_plugins_cache_reset();
    return failures;
}

static int mpl_case_cached_only(const char *dir)
{
    int failures = 0;
    TEST_CASE("mesh status capsule: the responder path serves only the cache; refresh is throttled") {
        char base[MESH_STATUS_CAPSULE_MAX + 64], reason[32] = "";
        uint8_t out[MESH_STATUS_CAPSULE_MAX + 1];
        size_t out_len = 0;
        struct mesh_status_plugins synthetic;
        char home[PATH_MAX], id[PLUGIN_HEX_SHA3_512 + 1];
        snprintf(home, sizeof(home), "%s/plugins_cached", dir);
        snprintf(base, sizeof(base),
                 "{\"schema\":\"zcl.machine_mesh_identity.v1\",\"machine\":\"m1\"}");
        mpl_set_option(true);
        mesh_status_plugins_cache_reset();
        /* Before the first refresh: named, not guessed. */
        mesh_status_capsule_finish(base, strlen(base), out, &out_len);
        out[out_len] = '\0';
        ASSERT_EQ(mpl_block_count(out, out_len, reason), 0);
        ASSERT_STR_EQ(reason, "not_yet_read");
        /* A snapshot set directly is what appears, the store is not read. */
        memset(&synthetic, 0, sizeof(synthetic));
        synthetic.available = true;
        synthetic.count = synthetic.listed = 1;
        snprintf(synthetic.items[0].name, sizeof(synthetic.items[0].name),
                 "synthetic");
        mesh_status_plugins_cache_set(&synthetic, 1000);
        mesh_status_capsule_finish(base, strlen(base), out, &out_len);
        ASSERT_EQ(mpl_block_count(out, out_len, reason), 1);
        ASSERT(strstr((const char *)out, "synthetic") != NULL);
        /* A store change is invisible until a refresh is due (60 s). */
        mesh_status_plugins_cache_reset();
        mpl_gen_id(id, 40);
        ASSERT(mpl_store_plugin(home, "one", id, NULL));
        mesh_status_plugins_cache_refresh(home, 2000);
        mpl_gen_id(id, 41);
        ASSERT(mpl_store_plugin(home, "two", id, NULL));
        mesh_status_capsule_finish(base, strlen(base), out, &out_len);
        ASSERT_EQ(mpl_block_count(out, out_len, reason), 1);
        mesh_status_plugins_cache_refresh(home, 2059);
        mesh_status_capsule_finish(base, strlen(base), out, &out_len);
        ASSERT_EQ(mpl_block_count(out, out_len, reason), 1);
        mesh_status_plugins_cache_refresh(home, 2060);
        mesh_status_capsule_finish(base, strlen(base), out, &out_len);
        ASSERT_EQ(mpl_block_count(out, out_len, reason), 2);
    } TEST_END
    /* Runs even when an ASSERT jumped out of the block above. */
    mpl_set_option(false);
    mesh_status_plugins_cache_reset();
    return failures;
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
        /* Transcript and generation match across sides; each snapshot names
         * the other's identity-file public static. */
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
                      &f.ndb, f.genesis, &f.peer_delegation, fingerprint,
                      f.peer_noise_pub, true, MESH_PAIRING_CAP_STATUS_READ,
                      2000, 3000, &f.pairing),
                  MESH_PAIRING_OK);
        uint8_t pairing_id[32];
        ASSERT(zcl_hex_decode_lower(f.pairing.pairing_id, pairing_id, 32));
        struct mesh_status_request_v1 request;
        mesh_wire_request(&f, pairing_id, MESH_WIRE_NOW - 10,
                          MESH_WIRE_NOW + 20, &request);

        /* The "ZMSTAT" frame crosses the live Noise session both ways before
         * the decision runs. */
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
         * is not responder lineage; the expected active delegation key wins. */
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
         * pending entry. */
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
        struct noise_transport *ini2 = NULL, *res2 = NULL;
        bool second = mesh_handshake(other_ini_priv, other_res_priv, &ini2,
                                     &res2);
        memory_cleanse(other_ini_priv, sizeof(other_ini_priv));
        memory_cleanse(other_res_priv, sizeof(other_res_priv));
        ASSERT(second);
        struct noise_transport_snapshot other_snap;
        ASSERT(noise_transport_snapshot(ini2, &other_snap));
        ASSERT(!boot_mesh_status_receipt_accept(&receipt, &request,
                                                &other_snap,
                                                f.resp_master_pub,
                                                f.resp_online_pub));
        noise_transport_free(ini2);
        noise_transport_free(res2);
        PASS();
    }

    failures += mpl_case_absent_and_two(dir);
    failures += mpl_case_squeeze(dir);
    failures += mpl_case_receipt(dir, &f);
    failures += mpl_case_option_off(dir);
    failures += mpl_case_cached_only(dir);


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

    /* ── Fleet view projection: state derivation, probe planning and tally,
     * with no sockets or fixture. ── */

    TEST("mesh machines: derive state from record, begin, poll, receipt") {
        const char *detail = NULL;
        /* Expired and revoked records are never probed; begin and poll
         * arguments are ignored. */
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
        ASSERT_STR_EQ(detail, "no_live_noise_session");
        ASSERT_EQ(mesh_machine_derive_state(
                      "active", MESH_STATUS_BEGIN_ROUTE_PENDING,
                      MESH_STATUS_POLL_PENDING, MESH_STATUS_RECEIPT_INTERNAL,
                      &detail),
                  MESH_MACHINE_TIMEOUT);
        ASSERT_STR_EQ(detail, "route_acquisition_pending");
        ASSERT_EQ(mesh_machine_derive_state(
                      "active", MESH_STATUS_BEGIN_ROUTE_IDENTITY_MISMATCH,
                      MESH_STATUS_POLL_PENDING, MESH_STATUS_RECEIPT_INTERNAL,
                      &detail),
                  MESH_MACHINE_REFUSED);
        ASSERT_STR_EQ(detail, "route-identity-mismatch");
        ASSERT_EQ(mesh_machine_derive_state(
                      "active", MESH_STATUS_BEGIN_ROUTE_DOWNGRADE,
                      MESH_STATUS_POLL_PENDING, MESH_STATUS_RECEIPT_INTERNAL,
                      &detail),
                  MESH_MACHINE_REFUSED);
        ASSERT_STR_EQ(detail, "route-plaintext-downgrade");
        ASSERT_EQ(mesh_machine_derive_state(
                      "active", MESH_STATUS_BEGIN_NOISE_DISABLED,
                      MESH_STATUS_POLL_PENDING, MESH_STATUS_RECEIPT_INTERNAL,
                      &detail),
                  MESH_MACHINE_UNREACHABLE);
        ASSERT_STR_EQ(detail, "noise_transport_disabled");
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
        /* The detail is the hyphenated wire token for "refused:<token>". */
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
        /* A connected peer without a unique active delegation is an authority
         * gap: UNKNOWN, never UNREACHABLE (the session is live). */
        ASSERT_EQ(mesh_machine_derive_state(
                      "active", MESH_STATUS_BEGIN_PEER_IDENTITY_UNAVAILABLE,
                      MESH_STATUS_POLL_PENDING, MESH_STATUS_RECEIPT_INTERNAL,
                      &detail),
                  MESH_MACHINE_UNKNOWN);
        ASSERT_STR_EQ(detail, "peer_identity_unavailable");
        PASS();
    }

    TEST("mesh machines: fleet burst always fits the status pending table") {
        /* Admission refuses a full pending table instead of evicting the
         * oldest live request; a fleet cap above the table bound would
         * self-congest into BUSY rows (compile-time twin in
         * boot_mesh_machines.c). */
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

        /* Only active records are probed; expired and revoked are durable
         * and need no wire round trip. */
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
