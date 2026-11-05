/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Exercise the peer-reachable package, work-swarm, DHT frame, space
 * manifest and VCS manifest decoders under sanitizers. Each accepted wire must
 * re-encode to identical bytes, each refusal must leave its output as the
 * header documents, and every decoded count must fit the array it describes.
 * Outputs sit between guard bands because ASan cannot see a write that stays
 * inside one struct or lands in a neighbouring field. */

#include "crypto/ed25519.h"
#include "vcs/package_attest.h"
#include "vcs/package_capsule.h"
#include "vcs/package_swarm.h"
#include "vcs/package_swarm_node.h"
#include "vcs/space.h"
#include "vcs/vcs_manifest.h"
#include "vcs/zcode_dht_delegation.h"
#include "vcs/zcode_dht_msgs.h"
#include "vcs/zcode_work_swarm.h"

#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

volatile sig_atomic_t g_shutdown_requested = 0;

#define FUZZ_PW_ARMS 9u
#define FUZZ_PW_MAX_INPUT (VCS_PACKAGE_SWARM_MAX_WIRE_BYTES + 64u)
#define FUZZ_PW_GUARD 64u
#define FUZZ_PW_GUARD_BYTE 0xA5u
#define FUZZ_PW_JUNK_BYTE 0xCCu
#define FUZZ_PW_NOW_UNIX UINT64_C(1500)
#define FUZZ_PW_ENGINE_FRAMES 48u
#define FUZZ_PW_ADV_ROWS 64u

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* One decoder output between two guard bands. */
#define FUZZ_PW_GUARDED(type) \
    struct { uint8_t pre[FUZZ_PW_GUARD]; type v; uint8_t post[FUZZ_PW_GUARD]; }

static void guard_arm(void *pre, void *value, size_t value_len, void *post)
{
    memset(pre, FUZZ_PW_GUARD_BYTE, FUZZ_PW_GUARD);
    memset(value, FUZZ_PW_JUNK_BYTE, value_len);
    memset(post, FUZZ_PW_GUARD_BYTE, FUZZ_PW_GUARD);
}

static void guard_check(const uint8_t *band)
{
    for (size_t i = 0; i < FUZZ_PW_GUARD; i++)
        if (band[i] != FUZZ_PW_GUARD_BYTE)
            abort();
}

#define GUARD_ARM(g) guard_arm((g).pre, &(g).v, sizeof((g).v), (g).post)
#define GUARD_CHECK(g) do { guard_check((g).pre); guard_check((g).post); } while (0)

static void require_zeroed(const void *out, size_t len)
{
    const uint8_t *p = out;
    for (size_t i = 0; i < len; i++)
        if (p[i] != 0)
            abort();
}

static void require_same(const uint8_t *a, size_t a_len, const uint8_t *b,
                         size_t b_len)
{
    if (a_len != b_len || (a_len && memcmp(a, b, a_len) != 0))
        abort();
}

/* A NUL-terminated string must terminate inside its array. */
static void require_terminated(const char *s, size_t capacity)
{
    if (memchr(s, 0, capacity) == NULL)
        abort();
}

/* ------------------------------------------------------------ swarm wire */

static void fuzz_package_swarm(const uint8_t *wire, size_t wire_len)
{
    FUZZ_PW_GUARDED(struct vcs_package_swarm_message) g;
    GUARD_ARM(g);
    bool ok = vcs_package_swarm_parse(wire, wire_len, &g.v);
    GUARD_CHECK(g);
    if (!ok) {
        require_zeroed(&g.v, sizeof(g.v));
        return;
    }
    if (g.v.type == VCS_PACKAGE_SWARM_DATA) {
        const struct vcs_package_swarm_data *d = &g.v.body.data;
        if (d->bytes_len > VCS_PACKAGE_CHUNK_BYTES || d->bytes < wire ||
            d->bytes + d->bytes_len > wire + wire_len)
            abort();
    }
    uint8_t canonical[VCS_PACKAGE_SWARM_MAX_WIRE_BYTES];
    size_t canonical_len = 0;
    if (vcs_package_swarm_wire_size(&g.v) != wire_len ||
        !vcs_package_swarm_serialize(&g.v, canonical, sizeof(canonical),
                                     &canonical_len))
        abort();
    require_same(wire, wire_len, canonical, canonical_len);
}

/* The engine is opaque, so its peer table is exercised through frames only:
 * the input is a run of [peer selector][length][frame] records fed to one
 * engine with no store, book or directory. After the run the public tables
 * must stay inside the caller's row capacity. */
static void engine_feed(struct vcs_swarm_engine *engine, const uint8_t *data,
                        size_t size)
{
    size_t pos = 0;
    for (unsigned i = 0; i < FUZZ_PW_ENGINE_FRAMES && pos + 2u <= size; i++) {
        uint64_t peer = 1u + (data[pos] & 1u);
        size_t take = data[pos + 1u];
        pos += 2u;
        if (take > size - pos)
            take = size - pos;
        struct vcs_swarm_frame_result res = vcs_swarm_engine_handle_frame(
            engine, peer, data + pos, take, 20000, (uint64_t)i * 700u);
        if (res.reply_len != 0 && res.reply == NULL)
            abort();
        free(res.reply);
        pos += take;
    }
}

struct adv_table {
    struct vcs_swarm_advertised row[FUZZ_PW_ADV_ROWS];
};

struct info_table {
    struct vcs_swarm_peer_info row[2];
};

static void engine_check(struct vcs_swarm_engine *engine)
{
    FUZZ_PW_GUARDED(struct adv_table) rows;
    GUARD_ARM(rows);
    size_t n = vcs_swarm_engine_advertised(engine, rows.v.row,
                                           FUZZ_PW_ADV_ROWS);
    GUARD_CHECK(rows);
    if (n > FUZZ_PW_ADV_ROWS)
        abort();
    FUZZ_PW_GUARDED(struct info_table) info;
    GUARD_ARM(info);
    if (n > 0 &&
        vcs_swarm_engine_peers_for(engine, rows.v.row[0].root, info.v.row,
                                   2u) > 2u)
        abort();
    GUARD_CHECK(info);
}

static void fuzz_swarm_engine(const uint8_t *data, size_t size)
{
    struct vcs_swarm_engine *engine =
        vcs_swarm_engine_create(NULL, NULL, NULL, NULL, NULL);
    if (!engine)
        return;
    uint8_t key[33] = {2};
    for (uint64_t peer = 1; peer <= 2; peer++) {
        key[1] = (uint8_t)peer;
        if (!vcs_swarm_engine_peer_add(engine, peer, key))
            abort();
    }
    engine_feed(engine, data, size);
    engine_check(engine);
    vcs_swarm_engine_free(engine);
}

/* ------------------------------------------------------------- work swarm */

static void fuzz_work_swarm(const uint8_t *wire, size_t wire_len)
{
    FUZZ_PW_GUARDED(struct vcs_zcode_work_swarm_message) g;
    GUARD_ARM(g);
    bool ok = vcs_zcode_work_swarm_parse(wire, wire_len, &g.v);
    GUARD_CHECK(g);
    if (!ok) {
        require_zeroed(&g.v, sizeof(g.v));
        return;
    }
    uint8_t canonical[VCS_ZCODE_WORK_SWARM_MAX_WIRE_BYTES];
    size_t canonical_len = 0;
    if (vcs_zcode_work_swarm_wire_size(&g.v) != wire_len ||
        !vcs_zcode_work_swarm_serialize(&g.v, canonical, sizeof(canonical),
                                        &canonical_len))
        abort();
    require_same(wire, wire_len, canonical, canonical_len);
}

/* ----------------------------------------------------------- DHT frames */

struct dht_fixture {
    bool ready;
    uint8_t online_secret[32];
    uint8_t online_pub[32];
    uint8_t online_seed[32];
    uint8_t transcript[32];
    struct vcs_zcode_dht_delegation delegation;
    struct vcs_zcode_dht_msg_verify_context verify;
    uint8_t prefix[VCS_ZCODE_DHT_MSGS_HEADER_BYTES +
                   VCS_ZCODE_DHT_MSGS_AUTH_BYTES];
};

static struct dht_fixture g_dht;

static bool dht_fixture_prefix(struct dht_fixture *f, const uint8_t node_id[32])
{
    struct vcs_zcode_dht_msg_find_node m;
    memset(&m, 0, sizeof(m));
    m.session_generation = 9;
    memcpy(m.sender_node_id, node_id, 32);
    for (size_t i = 0; i < 16; i++)
        m.query_id[i] = (uint8_t)(i + 1u);
    m.delegation = f->delegation;
    memset(m.target_node_id, 0x99, 32);
    uint8_t wire[VCS_ZCODE_DHT_FIND_NODE_WIRE_BYTES];
    size_t len = 0;
    if (vcs_zcode_dht_msg_serialize_find_node(&m, f->transcript,
                                              f->online_seed, wire,
                                              sizeof(wire), &len) !=
        VCS_ZCODE_DHT_OK)
        return false;
    memcpy(f->prefix, wire, sizeof(f->prefix));
    return true;
}

static bool dht_fixture_init(struct dht_fixture *f)
{
    if (f->ready)
        return true;
    uint8_t genesis[32], noise[32], beacon[32], master_seed[32], node_id[32];
    memset(f->online_seed, 0x22, 32);
    memset(genesis, 1, 32);
    memset(noise, 0x33, 32);
    memset(beacon, 0x44, 32);
    memset(master_seed, 0x55, 32);
    memset(f->transcript, 0x77, 32);
    ed25519_keypair(f->online_pub, f->online_secret, f->online_seed);
    if (vcs_zcode_dht_delegation_sign(&f->delegation, genesis, f->online_pub,
                                      noise, 120, beacon, 1000, 2000, 7,
                                      master_seed) !=
            VCS_ZCODE_DHT_DELEGATION_OK ||
        !vcs_zcode_dht_delegation_node_id(node_id, &f->delegation) ||
        !dht_fixture_prefix(f, node_id))
        return false;
    f->verify.noise_established = true;
    memcpy(f->verify.noise_transcript_hash, f->transcript, 32);
    memcpy(f->verify.remote_noise_static, noise, 32);
    memcpy(f->verify.network_genesis, genesis, 32);
    f->verify.session_generation = 9;
    f->verify.now_unix = FUZZ_PW_NOW_UNIX;
    f->ready = true;
    return true;
}

static void dht_sign_frame(const struct dht_fixture *f, uint8_t *frame,
                           size_t frame_len)
{
    uint8_t preimage[sizeof(VCS_ZCODE_DHT_MSG_SIGNATURE_DOMAIN) + 32 +
                     VCS_ZCODE_DHT_MAX_FRAME_BYTES + 64u];
    size_t unsigned_len = frame_len - VCS_ZCODE_DHT_MSG_SIGNATURE_BYTES;
    size_t off = 0;
    memcpy(preimage, VCS_ZCODE_DHT_MSG_SIGNATURE_DOMAIN,
           sizeof(VCS_ZCODE_DHT_MSG_SIGNATURE_DOMAIN));
    off += sizeof(VCS_ZCODE_DHT_MSG_SIGNATURE_DOMAIN);
    memcpy(preimage + off, f->transcript, 32);
    off += 32;
    memcpy(preimage + off, frame, unsigned_len);
    off += unsigned_len;
    ed25519_sign(frame + unsigned_len, preimage, off, f->online_secret,
                 f->online_pub);
}

static void dht_check_counts(const struct vcs_zcode_dht_msg *m)
{
    if (m->kind == VCS_ZCODE_DHT_MSG_NODES &&
        m->nodes.contact_count > VCS_ZCODE_DHT_K)
        abort();
    if (m->kind == VCS_ZCODE_DHT_MSG_RECORDS &&
        m->records.record_count > VCS_ZCODE_DHT_RECORDS_PER_FRAME)
        abort();
}

static enum vcs_zcode_dht_error dht_reserialize(
    const struct dht_fixture *f, const struct vcs_zcode_dht_msg *m,
    uint8_t *wire, size_t cap, size_t *len)
{
    const uint8_t *t = f->transcript, *s = f->online_seed;
    switch (m->kind) {
    case VCS_ZCODE_DHT_MSG_FIND_NODE:
        return vcs_zcode_dht_msg_serialize_find_node(&m->find_node, t, s,
                                                     wire, cap, len);
    case VCS_ZCODE_DHT_MSG_NODES:
        return vcs_zcode_dht_msg_serialize_nodes(&m->nodes, t, s, wire, cap,
                                                 len);
    case VCS_ZCODE_DHT_MSG_FIND_RECORD:
        return vcs_zcode_dht_msg_serialize_find_record(&m->find_record, t, s,
                                                       wire, cap, len);
    case VCS_ZCODE_DHT_MSG_RECORDS:
        return vcs_zcode_dht_msg_serialize_records(&m->records, t, s, wire,
                                                   cap, len);
    case VCS_ZCODE_DHT_MSG_STORE_RECORD:
        return vcs_zcode_dht_msg_serialize_store_record(&m->store_record, t,
                                                        s, wire, cap, len);
    case VCS_ZCODE_DHT_MSG_STORE_RESULT:
        return vcs_zcode_dht_msg_serialize_store_result(&m->store_result, t,
                                                        s, wire, cap, len);
    }
    return VCS_ZCODE_DHT_ERR_WIRE_KIND;
}

/* The first byte is the frame kind, the rest the payload. The fixed prefix
 * (magic, authenticated fields, a valid delegation) and the trailing signature
 * are supplied here so the payload decoders are reachable past the signature
 * gate that blind input cannot pass. */
static void fuzz_dht_frame(const uint8_t *data, size_t size)
{
    if (size == 0 || !dht_fixture_init(&g_dht))
        return;
    size_t plen = size - 1u;
    size_t frame_len = sizeof(g_dht.prefix) + plen +
                       VCS_ZCODE_DHT_MSG_SIGNATURE_BYTES;
    if (frame_len > VCS_ZCODE_DHT_MAX_FRAME_BYTES + 16u)
        return;
    uint8_t frame[VCS_ZCODE_DHT_MAX_FRAME_BYTES + 16u];
    memcpy(frame, g_dht.prefix, sizeof(g_dht.prefix));
    frame[10] = data[0];
    memcpy(frame + sizeof(g_dht.prefix), data + 1, plen);
    dht_sign_frame(&g_dht, frame, frame_len);
    FUZZ_PW_GUARDED(struct vcs_zcode_dht_msg) g;
    GUARD_ARM(g);
    enum vcs_zcode_dht_error e =
        vcs_zcode_dht_msg_parse(frame, frame_len, &g_dht.verify, &g.v);
    GUARD_CHECK(g);
    if (e != VCS_ZCODE_DHT_OK) {
        require_zeroed(&g.v, sizeof(g.v));
        return;
    }
    dht_check_counts(&g.v);
    uint8_t canonical[VCS_ZCODE_DHT_MAX_FRAME_BYTES + 1u];
    size_t canonical_len = 0;
    if (dht_reserialize(&g_dht, &g.v, canonical, sizeof(canonical),
                        &canonical_len) != VCS_ZCODE_DHT_OK)
        abort();
    require_same(frame, frame_len, canonical, canonical_len);
}

/* ----------------------------------------------------------- space manifest */

#define FUZZ_PW_SPACE_MAGIC "ZCSPMF\r\n"
#define FUZZ_PW_SPACE_DOMAIN "zcl.space_manifest.signature.v1"

static void space_check_counts(const struct vcs_space_manifest_v1 *m)
{
    if (m->service_count > VCS_SPACE_SERVICE_MAX ||
        m->object_count > VCS_SPACE_OBJECT_MAX ||
        m->portal_count > VCS_SPACE_PORTAL_MAX)
        abort();
    require_terminated(m->name, sizeof(m->name));
    require_terminated(m->description, sizeof(m->description));
}

/* Fix up the magic, the delegation block and the signature so a frame the
 * fuzzer shaped to the body grammar reaches the accept path. */
static bool space_sign_frame(const struct dht_fixture *f, uint8_t *wire,
                             size_t len)
{
    const size_t tail = 2u + VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES + 64u;
    if (len < 8u + tail || len > VCS_SPACE_MANIFEST_WIRE_MAX)
        return false;
    memcpy(wire, FUZZ_PW_SPACE_MAGIC, 8);
    size_t at = len - tail;
    wire[at] = (uint8_t)(VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES & 0xffu);
    wire[at + 1u] = (uint8_t)(VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES >> 8);
    if (vcs_zcode_dht_delegation_encode(&f->delegation, wire + at + 2u) !=
        VCS_ZCODE_DHT_DELEGATION_OK)
        return false;
    size_t unsigned_len = len - 64u;
    uint8_t preimage[sizeof(FUZZ_PW_SPACE_DOMAIN) +
                     VCS_SPACE_MANIFEST_WIRE_MAX];
    memcpy(preimage, FUZZ_PW_SPACE_DOMAIN, sizeof(FUZZ_PW_SPACE_DOMAIN) - 1u);
    memcpy(preimage + sizeof(FUZZ_PW_SPACE_DOMAIN) - 1u, wire, unsigned_len);
    ed25519_sign(wire + unsigned_len, preimage,
                 sizeof(FUZZ_PW_SPACE_DOMAIN) - 1u + unsigned_len,
                 f->online_secret, f->online_pub);
    return true;
}

static void fuzz_space_decode(const uint8_t *in, size_t len, bool resign)
{
    uint8_t wire[VCS_SPACE_MANIFEST_WIRE_MAX + 1u];
    if (len > sizeof(wire))
        return;
    memcpy(wire, in, len);
    if (resign && (!dht_fixture_init(&g_dht) ||
                   !space_sign_frame(&g_dht, wire, len)))
        return;
    FUZZ_PW_GUARDED(struct vcs_space_manifest_v1) g;
    GUARD_ARM(g);
    enum vcs_space_result r = vcs_space_manifest_decode(&g.v, wire, len);
    GUARD_CHECK(g);
    if (r != VCS_SPACE_OK) {
        require_zeroed(&g.v, sizeof(g.v));
        return;
    }
    space_check_counts(&g.v);
    uint8_t canonical[VCS_SPACE_MANIFEST_WIRE_MAX];
    size_t canonical_len = 0;
    if (vcs_space_manifest_encode(&g.v, canonical, sizeof(canonical),
                                  &canonical_len) != VCS_SPACE_OK)
        abort();
    require_same(wire, len, canonical, canonical_len);
}

/* ------------------------------------------------------- package records */

static void fuzz_capsule(const uint8_t *wire, size_t wire_len)
{
    FUZZ_PW_GUARDED(struct vcs_package_capsule) g;
    GUARD_ARM(g);
    enum vcs_package_capsule_error e =
        vcs_package_capsule_parse(wire, wire_len, &g.v);
    GUARD_CHECK(g);
    if (e != VCS_PACKAGE_CAPSULE_OK) {
        require_zeroed(&g.v, sizeof(g.v));
        return;
    }
    if (g.v.count > VCS_PACKAGE_CAPSULE_MAX_HEADERS)
        abort();
    for (size_t i = 0; i < g.v.count; i++)
        require_terminated(g.v.headers[i].path,
                           sizeof(g.v.headers[i].path));
    uint8_t *canonical = NULL;
    size_t canonical_len = 0;
    if (vcs_package_capsule_serialize(&g.v, &canonical, &canonical_len) !=
        VCS_PACKAGE_CAPSULE_OK)
        abort();
    require_same(wire, wire_len, canonical, canonical_len);
    free(canonical);
}

static void attest_check_fields(const struct vcs_package_attest *a)
{
    if (a->compiler_count > VCS_PACKAGE_ATTEST_MAX_COMPILERS ||
        a->sanitizer_count > VCS_PACKAGE_ATTEST_MAX_SANITIZERS)
        abort();
    require_terminated(a->detail, sizeof(a->detail));
    for (size_t i = 0; i < a->compiler_count; i++) {
        require_terminated(a->compilers[i].id, sizeof(a->compilers[i].id));
        require_terminated(a->compilers[i].version,
                           sizeof(a->compilers[i].version));
    }
    for (size_t i = 0; i < a->sanitizer_count; i++)
        require_terminated(a->sanitizers[i].name,
                           sizeof(a->sanitizers[i].name));
}

static void fuzz_attest(const uint8_t *wire, size_t wire_len)
{
    FUZZ_PW_GUARDED(struct vcs_package_attest) g;
    GUARD_ARM(g);
    enum vcs_package_attest_error e =
        vcs_package_attest_parse(wire, wire_len, &g.v);
    GUARD_CHECK(g);
    if (e != VCS_PACKAGE_ATTEST_OK) {
        require_zeroed(&g.v, sizeof(g.v));
        return;
    }
    attest_check_fields(&g.v);
    uint8_t *canonical = NULL;
    size_t canonical_len = 0;
    if (vcs_package_attest_serialize(&g.v, &canonical, &canonical_len) !=
        VCS_PACKAGE_ATTEST_OK)
        abort();
    require_same(wire, wire_len, canonical, canonical_len);
    free(canonical);
}

/* ---------------------------------------------------------- VCS manifest */

static void fuzz_vcs_manifest(const uint8_t *wire, size_t wire_len)
{
    FUZZ_PW_GUARDED(struct vcs_manifest) g;
    GUARD_ARM(g);
    bool ok = vcs_manifest_parse(wire, wire_len, &g.v);
    GUARD_CHECK(g);
    if (!ok) {
        if (g.v.entries != NULL || g.v.count != 0 || g.v.cap != 0)
            abort();
        return;
    }
    if (g.v.count > g.v.cap)
        abort();
    for (size_t i = 0; i < g.v.count; i++)
        if (g.v.entries[i].path == NULL ||
            strlen(g.v.entries[i].path) > VCS_PATH_MAX)
            abort();
    uint8_t *canonical = NULL;
    size_t canonical_len = 0;
    if (!vcs_manifest_serialize(&g.v, &canonical, &canonical_len))
        abort();
    require_same(wire, wire_len, canonical, canonical_len);
    free(canonical);
    vcs_manifest_free(&g.v);
}

/* The first byte picks the decoder; the rest is its input. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!data || size == 0 || size > FUZZ_PW_MAX_INPUT)
        return 0;

    const uint8_t *in = data + 1;
    size_t in_len = size - 1;
    switch (data[0] % FUZZ_PW_ARMS) {
    case 0: fuzz_package_swarm(in, in_len); break;
    case 1: fuzz_swarm_engine(in, in_len); break;
    case 2: fuzz_work_swarm(in, in_len); break;
    case 3: fuzz_dht_frame(in, in_len); break;
    case 4: fuzz_space_decode(in, in_len, false); break;
    case 5: fuzz_space_decode(in, in_len, true); break;
    case 6: fuzz_capsule(in, in_len); break;
    case 7: fuzz_attest(in, in_len); break;
    default: fuzz_vcs_manifest(in, in_len); break;
    }
    return 0;
}
