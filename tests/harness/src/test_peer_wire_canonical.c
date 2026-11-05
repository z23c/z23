/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Peer wire decoders hold one canonical form: a frame a decoder accepts is
 * the frame its encoder writes, and a refusal leaves no half-filled output.
 * Each case builds a local fixture frame, bends one field away from the
 * canonical encoding, and requires the decoder to refuse it.
 */

#include "test/test_core.h"

#include "config/boot_mesh_game.h"
#include "crypto/ed25519.h"
#include "session/agent_broker_proto.h"
#include "support/cleanse.h"
#include "vcs/package_attest.h"
#include "vcs/zcode_dht_msgs.h"

#include <stdio.h>
#include <string.h>

/* ── package attestation: *out is zero on every rejection ─────────────── */

static int test_attest_zero_on_reject(void)
{
    int failures = 0;
    TEST("peer wire: an attestation parse refusal leaves *out zeroed") {
        static const uint8_t magic[] = { 'Z', 'C', 'L', 'A', 'T', 'T',
                                         0x0d, 0x0a };
        /* a schema version this build does not speak, after the magic */
        uint8_t shortwire[sizeof(magic) + 2];
        memcpy(shortwire, magic, sizeof(magic));
        shortwire[sizeof(magic)] = 0x02;
        shortwire[sizeof(magic) + 1] = 0x00;

        /* the right schema version, then fields that stop making sense */
        uint8_t longwire[sizeof(magic) + 2 + 100];
        memset(longwire, 0x4a, sizeof(longwire));
        memcpy(longwire, magic, sizeof(magic));
        longwire[sizeof(magic)] = 0x01;
        longwire[sizeof(magic) + 1] = 0x00;

        static const struct vcs_package_attest zero;
        struct vcs_package_attest out;
        memset(&out, 0xA5, sizeof(out));
        ASSERT(vcs_package_attest_parse(shortwire, sizeof(shortwire), &out) !=
               VCS_PACKAGE_ATTEST_OK);
        ASSERT(memcmp(&out, &zero, sizeof(out)) == 0);
        memset(&out, 0xA5, sizeof(out));
        ASSERT(vcs_package_attest_parse(longwire, sizeof(longwire), &out) !=
               VCS_PACKAGE_ATTEST_OK);
        ASSERT(memcmp(&out, &zero, sizeof(out)) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ── DHT record selector: one wire form per selector ──────────────────── */

static bool dht_fixture(struct vcs_zcode_dht_delegation *d,
                        struct vcs_zcode_dht_msg_verify_context *v,
                        uint8_t seed[32], uint8_t transcript[32],
                        uint8_t node_id[32])
{
    uint8_t pub[32], secret[32], genesis[32], noise[32], beacon[32], master[32];
    memset(seed, 0x22, 32);
    ed25519_keypair(pub, secret, seed);
    memory_cleanse(secret, sizeof(secret));
    memset(genesis, 1, 32);
    memset(noise, 0x33, 32);
    memset(beacon, 0x44, 32);
    memset(master, 0x55, 32);
    if (vcs_zcode_dht_delegation_sign(d, genesis, pub, noise, 120, beacon,
                                      1000, 2000, 7, master) !=
            VCS_ZCODE_DHT_DELEGATION_OK ||
        !vcs_zcode_dht_delegation_node_id(node_id, d))
        return false;
    memset(transcript, 0x77, 32);
    memset(v, 0, sizeof(*v));
    v->noise_established = true;
    memcpy(v->noise_transcript_hash, transcript, 32);
    memcpy(v->remote_noise_static, noise, 32);
    memcpy(v->network_genesis, genesis, 32);
    v->session_generation = 9;
    v->now_unix = 1500;
    return true;
}

static void dht_resign(uint8_t *wire, size_t len, const uint8_t seed[32],
                       const uint8_t transcript[32])
{
    uint8_t pub[32], secret[32];
    ed25519_keypair(pub, secret, seed);
    uint8_t pre[sizeof(VCS_ZCODE_DHT_MSG_SIGNATURE_DOMAIN) + 32 +
                VCS_ZCODE_DHT_MAX_FRAME_BYTES];
    size_t off = 0, unsigned_len = len - VCS_ZCODE_DHT_MSG_SIGNATURE_BYTES;
    memcpy(pre, VCS_ZCODE_DHT_MSG_SIGNATURE_DOMAIN,
           sizeof(VCS_ZCODE_DHT_MSG_SIGNATURE_DOMAIN));
    off += sizeof(VCS_ZCODE_DHT_MSG_SIGNATURE_DOMAIN);
    memcpy(pre + off, transcript, 32);
    off += 32;
    memcpy(pre + off, wire, unsigned_len);
    off += unsigned_len;
    ed25519_sign(wire + unsigned_len, pre, off, secret, pub);
    memory_cleanse(secret, sizeof(secret));
}

static int test_dht_selector_canonical(void)
{
    int failures = 0;
    TEST("peer wire: a DHT selector whose length byte exceeds the name is refused") {
        struct vcs_zcode_dht_msg_find_record m;
        struct vcs_zcode_dht_msg_verify_context v;
        uint8_t seed[32], transcript[32];
        memset(&m, 0, sizeof(m));
        ASSERT(dht_fixture(&m.delegation, &v, seed, transcript,
                           m.sender_node_id));
        m.session_generation = 9;
        for (size_t i = 0; i < 16; i++) m.query_id[i] = (uint8_t)(i + 1);
        m.selector.kind = VCS_ZCODE_DHT_RECORD_PROVIDER;
        memcpy(m.selector.namespace_name, "ab", 2);
        memset(m.selector.root, 0x5a, 32);
        m.page_offset = 0;

        uint8_t wire[VCS_ZCODE_DHT_FIND_RECORD_WIRE_BYTES];
        size_t len = 0;
        struct vcs_zcode_dht_msg parsed;
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_find_record(
                      &m, transcript, seed, wire, sizeof(wire), &len),
                  VCS_ZCODE_DHT_OK);
        ASSERT_EQ(len, sizeof(wire));
        ASSERT_EQ(vcs_zcode_dht_msg_parse(wire, len, &v, &parsed),
                  VCS_ZCODE_DHT_OK);

        /* The selector sits before the page byte and the signature. */
        size_t sel = len - VCS_ZCODE_DHT_MSG_SIGNATURE_BYTES - 1u -
                     VCS_ZCODE_DHT_RECORD_SELECTOR_BYTES;
        ASSERT_EQ(wire[sel + 1], 2);
        wire[sel + 1] = 4; /* two trailing NULs inside the declared length */
        dht_resign(wire, len, seed, transcript);
        ASSERT_EQ(vcs_zcode_dht_msg_parse(wire, len, &v, &parsed),
                  VCS_ZCODE_DHT_ERR_WIRE_ORDER);
        PASS();
    } _test_next:;
    return failures;
}

/* ── mesh game frames ──────────────────────────────────────────────────── */

static size_t game_roster_wire(uint8_t *buf, uint8_t asset_count,
                               uint8_t rows, uint8_t reachable)
{
    size_t at = 0;
    buf[at++] = MESH_GAME_KIND_ROSTER;
    memset(buf + at, 0x03, 32);
    at += 32;
    buf[at++] = asset_count;
    buf[at++] = rows;
    for (uint8_t i = 0; i < rows; i++) {
        memset(buf + at, 0x04, 32);
        at += 32;
        buf[at++] = reachable;
        memset(buf + at, 0x01, asset_count);
        at += asset_count;
    }
    return at;
}

/* This build's asset vocabulary, found through the codec itself. */
static uint8_t game_vocabulary(void)
{
    uint8_t buf[64];
    struct mesh_game_frame f;
    for (uint8_t n = 1; n <= MESH_GAME_ASSET_MAX; n++) {
        size_t len = game_roster_wire(buf, n, 0, 0);
        if (mesh_game_parse(buf, len, &f) == MESH_GAME_OK)
            return n;
    }
    return 0;
}

static bool game_frame_is_zero(const struct mesh_game_frame *f)
{
    static const struct mesh_game_frame zero;
    return memcmp(f, &zero, sizeof(*f)) == 0;
}

static int test_game_parse_zero_on_refusal(void)
{
    int failures = 0;
    TEST("peer wire: a game frame refusal leaves *out zeroed") {
        uint8_t buf[128];
        struct mesh_game_frame f;
        size_t len;

        /* roster naming a vocabulary this build does not carry */
        len = game_roster_wire(buf, 200, 0, 0);
        memset(&f, 0xA5, sizeof(f));
        ASSERT_EQ(mesh_game_parse(buf, len, &f), MESH_GAME_ASSET_VOCABULARY);
        ASSERT(game_frame_is_zero(&f));

        /* match open past the airship ceiling */
        memset(buf, 0, sizeof(buf));
        buf[0] = MESH_GAME_KIND_MATCH_OPEN;
        buf[1] = 0x11;
        buf[9] = (uint8_t)(MESH_GAME_AIRSHIPS_MAX + 1u);
        memset(&f, 0xA5, sizeof(f));
        ASSERT_EQ(mesh_game_parse(buf, 10, &f), MESH_GAME_STATE_OVERFLOW);
        ASSERT(game_frame_is_zero(&f));

        /* match state past the airship ceiling */
        memset(buf, 0, sizeof(buf));
        buf[0] = MESH_GAME_KIND_MATCH_STATE;
        buf[1] = 0x22;
        buf[5] = (uint8_t)(MESH_GAME_AIRSHIPS_MAX + 1u);
        memset(&f, 0xA5, sizeof(f));
        ASSERT_EQ(mesh_game_parse(buf, 6, &f), MESH_GAME_STATE_OVERFLOW);
        ASSERT(game_frame_is_zero(&f));
        PASS();
    } _test_next:;
    return failures;
}

static int test_game_roster_reachable_canonical(void)
{
    int failures = 0;
    TEST("peer wire: a roster reachable byte other than 0 or 1 is malformed") {
        uint8_t vocab = game_vocabulary();
        ASSERT(vocab > 0);
        uint8_t buf[256];
        struct mesh_game_frame f;
        for (uint8_t r = 0; r <= 1; r++) {
            size_t len = game_roster_wire(buf, vocab, 1, r);
            ASSERT_EQ(mesh_game_parse(buf, len, &f), MESH_GAME_OK);
            ASSERT_EQ(f.body.roster.rows[0].reachable, r == 1);
        }
        const uint8_t bad[] = { 2, 3, 0x80, 255 };
        for (size_t i = 0; i < sizeof(bad); i++) {
            size_t len = game_roster_wire(buf, vocab, 1, bad[i]);
            memset(&f, 0xA5, sizeof(f));
            ASSERT_EQ(mesh_game_parse(buf, len, &f), MESH_GAME_MALFORMED);
            ASSERT(game_frame_is_zero(&f));
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_game_compose_no_partial_write(void)
{
    int failures = 0;
    TEST("peer wire: a game compose that refuses writes nothing") {
        struct mesh_game_frame f;
        memset(&f, 0, sizeof(f));
        f.kind = MESH_GAME_KIND_HELLO;
        uint8_t buf[2] = { 0xA5, 0xC3 };
        ASSERT_EQ(mesh_game_compose(&f, buf, 1), 0);
        ASSERT_EQ(buf[0], 0xA5);
        ASSERT_EQ(buf[1], 0xC3);

        f.kind = (enum mesh_game_kind)0x77; /* no such kind */
        ASSERT_EQ(mesh_game_compose(&f, buf, 1), 0);
        ASSERT_EQ(buf[0], 0xA5);

        f.kind = MESH_GAME_KIND_MATCH_OPEN;
        f.body.match_open.airships = (uint8_t)(MESH_GAME_AIRSHIPS_MAX + 1u);
        uint8_t big[16];
        memset(big, 0xA5, sizeof(big));
        ASSERT_EQ(mesh_game_compose(&f, big, sizeof(big)), 0);
        ASSERT_EQ(big[0], 0xA5);
        PASS();
    } _test_next:;
    return failures;
}

/* ── broker wire: an embedded NUL in a string field is refused ────────── */

static int test_mvap_request_embedded_nul(void)
{
    int failures = 0;
    TEST("peer wire: a broker request param with an embedded NUL is refused") {
        struct mvap_request req;
        memset(&req, 0, sizeof(req));
        req.verb = MVAP_VERB_INSPECT;
        req.request_id = 5;
        snprintf(req.param, sizeof(req.param), "abc");
        uint8_t buf[MVAP_FRAME_PREFIX + MVAP_MAX_FRAME];
        size_t n = mvap_request_encode(&req, buf, sizeof(buf));
        ASSERT(n > MVAP_FRAME_PREFIX);
        struct mvap_request got;
        ASSERT(mvap_request_decode(buf + MVAP_FRAME_PREFIX,
                                   n - MVAP_FRAME_PREFIX, &got));
        buf[MVAP_FRAME_PREFIX + MVAP_REQ_FIXED + 1] = 0; /* "a\0c" */
        ASSERT(!mvap_request_decode(buf + MVAP_FRAME_PREFIX,
                                    n - MVAP_FRAME_PREFIX, &got));
        PASS();
    } _test_next:;
    return failures;
}

static int test_mvap_response_embedded_nul(void)
{
    int failures = 0;
    TEST("peer wire: a broker response body with an embedded NUL is refused") {
        uint8_t buf[MVAP_FRAME_PREFIX + MVAP_MAX_FRAME];
        size_t n;
        struct mvap_response resp;
        memset(&resp, 0, sizeof(resp));
        resp.verb = MVAP_VERB_INSPECT;
        resp.request_id = 5;
        snprintf(resp.body, sizeof(resp.body), "abc");
        n = mvap_response_encode(&resp, buf, sizeof(buf));
        ASSERT(n > MVAP_FRAME_PREFIX);
        struct mvap_response rgot;
        ASSERT(mvap_response_decode(buf + MVAP_FRAME_PREFIX,
                                    n - MVAP_FRAME_PREFIX, &rgot));
        buf[MVAP_FRAME_PREFIX + MVAP_RESP_FIXED + 1] = 0;
        ASSERT(!mvap_response_decode(buf + MVAP_FRAME_PREFIX,
                                     n - MVAP_FRAME_PREFIX, &rgot));
        PASS();
    } _test_next:;
    return failures;
}

int test_peer_wire_canonical(void)
{
    int failures = 0;
    failures += test_attest_zero_on_reject();
    failures += test_dht_selector_canonical();
    failures += test_game_parse_zero_on_refusal();
    failures += test_game_roster_reachable_canonical();
    failures += test_game_compose_no_partial_write();
    failures += test_mvap_request_embedded_nul();
    failures += test_mvap_response_embedded_nul();
    printf("=== peer_wire_canonical: %d failures ===\n", failures);
    return failures;
}
