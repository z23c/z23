/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "vcs/zcode_dht_delegation.h"
#include "vcs/zcode_dht_identity.h"
#include "zid/zendp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void fill32(uint8_t out[32], uint8_t v) { memset(out, v, 32); }

static bool make_delegation(struct vcs_zcode_dht_delegation *d,
                            uint64_t seq, uint64_t not_before,
                            uint64_t expiry, uint8_t online_byte)
{
    uint8_t genesis[32], online[32], noise[32], beacon[32], master[32];
    fill32(genesis, 0x01); fill32(online, online_byte);
    fill32(noise, 0x33); fill32(beacon, 0x44); fill32(master, 0x55);
    return vcs_zcode_dht_delegation_sign(
               d, genesis, online, noise, 120, beacon,
               not_before, expiry, seq, master) ==
           VCS_ZCODE_DHT_DELEGATION_OK;
}

static void hex32(char out[65], const uint8_t in[32])
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; i++) {
        out[2 * i] = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 15];
    }
    out[64] = 0;
}

static void sha3_of(uint8_t out[32], const uint8_t *data, size_t len)
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, data, len);
    sha3_256_finalize(&sha, out);
}

/* Golden: the chain delegation encoding, signed preimage (zid_doc covers the
 * wire prefix) and node_id are frozen field formats. Pinned from the tree
 * before roster mode existed. */
#define GOLDEN_CHAIN_WIRE_SHA3 "0a005cff13d83e54f91cd4b5c0373f5c03e16d973ab826d8ecd69aa4a9a6e2a8"
#define GOLDEN_CHAIN_NODE_ID "e0f491f2a0acfd6b10b03286ee5103421791a01a1f9316c42c3d29b4bb5c6134"

static int test_delegation_chain_golden(void)
{
    int failures = 0;
    TEST("zcode dht delegation: chain encoding and node id are byte-frozen") {
        struct vcs_zcode_dht_delegation d, parsed;
        ASSERT(make_delegation(&d, 7, 1000, 1000 + 3 * 86400, 0x22));
        uint8_t wire[VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES], digest[32], nid[32];
        char hex[65];
        ASSERT_EQ(vcs_zcode_dht_delegation_encode(&d, wire),
                  VCS_ZCODE_DHT_DELEGATION_OK);
        sha3_of(digest, wire, sizeof(wire));
        hex32(hex, digest);
        printf("GOLDEN wire sha3=%s\n", hex);
        ASSERT(strcmp(hex, GOLDEN_CHAIN_WIRE_SHA3) == 0);
        ASSERT(vcs_zcode_dht_delegation_node_id(nid, &d));
        hex32(hex, nid);
        printf("GOLDEN node_id=%s\n", hex);
        ASSERT(strcmp(hex, GOLDEN_CHAIN_NODE_ID) == 0);
        ASSERT_EQ(vcs_zcode_dht_delegation_decode(&parsed, wire, sizeof(wire)),
                  VCS_ZCODE_DHT_DELEGATION_OK);
        uint8_t again[VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_dht_delegation_encode(&parsed, again),
                  VCS_ZCODE_DHT_DELEGATION_OK);
        ASSERT(memcmp(wire, again, sizeof(wire)) == 0);
        ASSERT_EQ(vcs_zcode_dht_delegation_verify(&parsed, NULL, NULL, 0, NULL,
                                                  1000),
                  VCS_ZCODE_DHT_DELEGATION_OK);
        PASS();
    } _test_next:;
    return failures;
}

static bool make_roster(struct vcs_zcode_dht_delegation *d, uint64_t seq,
                        uint64_t not_before, uint64_t expiry,
                        uint8_t online_byte, uint8_t master_byte)
{
    uint8_t genesis[32], online[32], noise[32], master[32];
    fill32(genesis, 0x01); fill32(online, online_byte);
    fill32(noise, 0x33); fill32(master, master_byte);
    return vcs_zcode_dht_delegation_roster_sign(
               d, genesis, online, noise, 0, NULL, not_before, expiry, seq,
               master) == VCS_ZCODE_DHT_DELEGATION_OK;
}

static int test_roster_node_id_and_beacon(void)
{
    int failures = 0;
    TEST("zcode dht delegation: two roster delegations of one master give one "
         "node_id; nonzero beacon refused") {
        struct vcs_zcode_dht_delegation a, b, other, chain, bad;
        ASSERT(make_roster(&a, 1, 1000, 1000 + 3 * 86400, 0x22, 0x55));
        ASSERT(make_roster(&b, 2, 5000, 5000 + 86400, 0x66, 0x55));
        ASSERT(make_roster(&other, 1, 1000, 2000, 0x22, 0x56));
        ASSERT(make_delegation(&chain, 1, 1000, 2000, 0x22));
        uint8_t aid[32], bid[32], oid[32], cid[32];
        ASSERT(vcs_zcode_dht_delegation_node_id(aid, &a));
        ASSERT(vcs_zcode_dht_delegation_node_id(bid, &b));
        ASSERT(vcs_zcode_dht_delegation_node_id(oid, &other));
        ASSERT(vcs_zcode_dht_delegation_node_id(cid, &chain));
        ASSERT(memcmp(aid, bid, 32) == 0);
        ASSERT(memcmp(aid, oid, 32) != 0);
        /* Same master (0x55) as the roster pair: chain id differs. */
        ASSERT(memcmp(aid, cid, 32) != 0);
        uint8_t genesis[32], online[32], noise[32], master[32], beacon[32];
        fill32(genesis, 1); fill32(online, 0x22); fill32(noise, 0x33);
        fill32(master, 0x55); fill32(beacon, 0x44);
        ASSERT_EQ(vcs_zcode_dht_delegation_roster_sign(
                      &bad, genesis, online, noise, 120, NULL, 1000, 2000, 1,
                      master),
                  VCS_ZCODE_DHT_DELEGATION_BEACON);
        ASSERT_EQ(vcs_zcode_dht_delegation_roster_sign(
                      &bad, genesis, online, noise, 0, beacon, 1000, 2000, 1,
                      master),
                  VCS_ZCODE_DHT_DELEGATION_BEACON);
        /* Parse refuses a body that carries beacon fields (chain-length
         * tail appended) even when properly master-signed. */
        uint8_t body[VCS_ZCODE_DHT_DELEGATION_ROSTER_BODY_BYTES + 36];
        memcpy(body, a.doc.body, VCS_ZCODE_DHT_DELEGATION_ROSTER_BODY_BYTES);
        memset(body + VCS_ZCODE_DHT_DELEGATION_ROSTER_BODY_BYTES, 0x44, 36);
        struct zid_doc doc;
        ASSERT(zid_doc_sign(&doc, body, sizeof(body), 1, 2000, master));
        uint8_t wire[ZID_DOC_MAX];
        size_t n = zid_doc_encode(wire, sizeof(wire), &doc);
        ASSERT(n != 0);
        ASSERT_EQ(vcs_zcode_dht_delegation_roster_decode(&bad, wire, n),
                  VCS_ZCODE_DHT_DELEGATION_SIZE);
        /* Same-size struct with beacon fields set is refused by the check. */
        bad = a;
        bad.beacon_height = 120;
        ASSERT_EQ(vcs_zcode_dht_delegation_roster_check(&bad, NULL, NULL, 1000),
                  VCS_ZCODE_DHT_DELEGATION_BEACON);
        bad = a;
        memset(bad.beacon_hash, 0x44, 32);
        ASSERT_EQ(vcs_zcode_dht_delegation_roster_check(&bad, NULL, NULL, 1000),
                  VCS_ZCODE_DHT_DELEGATION_BEACON);
        ASSERT_EQ(vcs_zcode_dht_delegation_roster_check(&a, NULL, NULL, 1000),
                  VCS_ZCODE_DHT_DELEGATION_OK);
        PASS();
    } _test_next:;
    return failures;
}

static int test_roster_cross_mode(void)
{
    int failures = 0;
    TEST("zcode dht delegation: roster and chain modes never cross-verify") {
        struct vcs_zcode_dht_delegation r, c, parsed, graft;
        ASSERT(make_roster(&r, 1, 1000, 1000 + 86400, 0x22, 0x55));
        ASSERT(make_delegation(&c, 1, 1000, 1000 + 86400, 0x22));
        uint8_t rw[VCS_ZCODE_DHT_DELEGATION_ROSTER_WIRE_BYTES];
        uint8_t cw[VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_dht_delegation_roster_encode(&r, rw),
                  VCS_ZCODE_DHT_DELEGATION_OK);
        ASSERT_EQ(vcs_zcode_dht_delegation_encode(&c, cw),
                  VCS_ZCODE_DHT_DELEGATION_OK);
        /* Round trip. */
        ASSERT_EQ(vcs_zcode_dht_delegation_roster_decode(&parsed, rw, sizeof(rw)),
                  VCS_ZCODE_DHT_DELEGATION_OK);
        ASSERT_EQ(parsed.mode, VCS_ZCODE_DHT_DELEGATION_MODE_ROSTER);
        ASSERT_EQ(vcs_zcode_dht_delegation_roster_check(&parsed, NULL, NULL, 1000),
                  VCS_ZCODE_DHT_DELEGATION_OK);
        /* Roster body into the chain parser: refused. */
        ASSERT(vcs_zcode_dht_delegation_decode(&graft, rw, sizeof(rw)) !=
               VCS_ZCODE_DHT_DELEGATION_OK);
        /* Chain wire into the roster parser: refused. */
        ASSERT(vcs_zcode_dht_delegation_roster_decode(&graft, cw, sizeof(cw)) !=
               VCS_ZCODE_DHT_DELEGATION_OK);
        /* Roster doc relabelled as chain: refused by the chain verifier. */
        graft = parsed;
        graft.mode = VCS_ZCODE_DHT_DELEGATION_MODE_CHAIN;
        ASSERT_EQ(vcs_zcode_dht_delegation_verify(&graft, NULL, NULL, 0, NULL, 1000),
                  VCS_ZCODE_DHT_DELEGATION_BODY);
        /* Chain doc relabelled as roster: refused by the roster check. */
        graft = c;
        graft.mode = VCS_ZCODE_DHT_DELEGATION_MODE_ROSTER;
        ASSERT_EQ(vcs_zcode_dht_delegation_roster_check(&graft, NULL, NULL, 1000),
                  VCS_ZCODE_DHT_DELEGATION_BODY);
        /* Signature does not transfer across bodies: chain body under the
         * roster doc's signature fails the master signature. */
        graft = c;
        memcpy(graft.doc.signature, r.doc.signature, 64);
        ASSERT_EQ(vcs_zcode_dht_delegation_verify(&graft, NULL, NULL, 0, NULL, 1000),
                  VCS_ZCODE_DHT_DELEGATION_SIGNATURE);
        /* The chain encoder refuses a roster struct and vice versa. */
        ASSERT(vcs_zcode_dht_delegation_encode(&r, cw) !=
               VCS_ZCODE_DHT_DELEGATION_OK);
        ASSERT(vcs_zcode_dht_delegation_roster_encode(&c, rw) !=
               VCS_ZCODE_DHT_DELEGATION_OK);
        PASS();
    } _test_next:;
    return failures;
}

static int test_unknown_mode_refused(void)
{
    int failures = 0;
    TEST("zcode dht delegation: unknown mode values are refused everywhere") {
        static const uint8_t bad_modes[] = {2, 255};
        for (size_t i = 0; i < sizeof(bad_modes); i++) {
            struct vcs_zcode_dht_delegation c, r;
            uint8_t id[32];
            uint8_t cw[VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES];
            uint8_t rw[VCS_ZCODE_DHT_DELEGATION_ROSTER_WIRE_BYTES];
            ASSERT(make_delegation(&c, 1, 1000, 2000, 0x22));
            ASSERT_EQ(vcs_zcode_dht_delegation_verify(&c, NULL, NULL, 0, NULL,
                                                      1000),
                      VCS_ZCODE_DHT_DELEGATION_OK);
            c.mode = bad_modes[i];
            ASSERT_EQ(vcs_zcode_dht_delegation_verify(&c, NULL, NULL, 0, NULL,
                                                      1000),
                      VCS_ZCODE_DHT_DELEGATION_MODE_UNKNOWN);
            ASSERT(!vcs_zcode_dht_delegation_node_id(id, &c));
            ASSERT_EQ(vcs_zcode_dht_delegation_encode(&c, cw),
                      VCS_ZCODE_DHT_DELEGATION_MODE_UNKNOWN);
            ASSERT_EQ(vcs_zcode_dht_delegation_roster_check(&c, NULL, NULL, 1000),
                      VCS_ZCODE_DHT_DELEGATION_MODE_UNKNOWN);
            ASSERT_EQ(vcs_zcode_dht_delegation_roster_encode(&c, rw),
                      VCS_ZCODE_DHT_DELEGATION_MODE_UNKNOWN);
            ASSERT(make_roster(&r, 1, 1000, 2000, 0x22, 0x55));
            r.mode = bad_modes[i];
            ASSERT_EQ(vcs_zcode_dht_delegation_verify(&r, NULL, NULL, 0, NULL,
                                                      1000),
                      VCS_ZCODE_DHT_DELEGATION_MODE_UNKNOWN);
            ASSERT(!vcs_zcode_dht_delegation_node_id(id, &r));
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_roster_cache_bound_to_body(void)
{
    int failures = 0;
    TEST("zcode dht delegation: roster cached fields must equal the signed body") {
        struct vcs_zcode_dht_delegation base, d;
        ASSERT(make_roster(&base, 1, 1000, 1000 + 86400, 0x22, 0x55));
        ASSERT_EQ(vcs_zcode_dht_delegation_roster_check(&base, NULL, NULL, 1000),
                  VCS_ZCODE_DHT_DELEGATION_OK);
        d = base; d.network_genesis[0] ^= 1;
        ASSERT_EQ(vcs_zcode_dht_delegation_roster_check(&d, NULL, NULL, 1000),
                  VCS_ZCODE_DHT_DELEGATION_PROJECTION);
        d = base; d.online_pubkey[5] ^= 1;
        ASSERT_EQ(vcs_zcode_dht_delegation_roster_check(&d, NULL, NULL, 1000),
                  VCS_ZCODE_DHT_DELEGATION_PROJECTION);
        d = base; d.noise_static_pubkey[31] ^= 1;
        ASSERT_EQ(vcs_zcode_dht_delegation_roster_check(&d, NULL, NULL, 1000),
                  VCS_ZCODE_DHT_DELEGATION_PROJECTION);
        d = base; d.not_before += 1;
        ASSERT_EQ(vcs_zcode_dht_delegation_roster_check(&d, NULL, NULL, 1000),
                  VCS_ZCODE_DHT_DELEGATION_PROJECTION);
        /* master and expiry live only in the signed doc: tampering fails the
         * signature (or the window) instead. */
        d = base; d.doc.master_pubkey[0] ^= 1;
        ASSERT(vcs_zcode_dht_delegation_roster_check(&d, NULL, NULL, 1000) !=
               VCS_ZCODE_DHT_DELEGATION_OK);
        d = base; d.doc.expiry += 1;
        ASSERT(vcs_zcode_dht_delegation_roster_check(&d, NULL, NULL, 1000) !=
               VCS_ZCODE_DHT_DELEGATION_OK);
        PASS();
    } _test_next:;
    return failures;
}

static int test_chain_cache_bound_to_body(void)
{
    int failures = 0;
    TEST("zcode dht delegation: chain cached fields must equal the signed body") {
        struct vcs_zcode_dht_delegation base, d;
        ASSERT(make_delegation(&base, 1, 1000, 1000 + 86400, 0x22));
        ASSERT_EQ(vcs_zcode_dht_delegation_verify(&base, NULL, NULL, 0, NULL, 1000),
                  VCS_ZCODE_DHT_DELEGATION_OK);
        d = base; d.network_genesis[0] ^= 1;
        ASSERT_EQ(vcs_zcode_dht_delegation_verify(&d, NULL, NULL, 0, NULL, 1000),
                  VCS_ZCODE_DHT_DELEGATION_PROJECTION);
        d = base; d.online_pubkey[5] ^= 1;
        ASSERT_EQ(vcs_zcode_dht_delegation_verify(&d, NULL, NULL, 0, NULL, 1000),
                  VCS_ZCODE_DHT_DELEGATION_PROJECTION);
        d = base; d.noise_static_pubkey[31] ^= 1;
        ASSERT_EQ(vcs_zcode_dht_delegation_verify(&d, NULL, NULL, 0, NULL, 1000),
                  VCS_ZCODE_DHT_DELEGATION_PROJECTION);
        d = base; d.beacon_height += 1;
        ASSERT_EQ(vcs_zcode_dht_delegation_verify(&d, NULL, NULL, 0, NULL, 1000),
                  VCS_ZCODE_DHT_DELEGATION_PROJECTION);
        d = base; d.beacon_hash[0] ^= 1;
        ASSERT_EQ(vcs_zcode_dht_delegation_verify(&d, NULL, NULL, 0, NULL, 1000),
                  VCS_ZCODE_DHT_DELEGATION_PROJECTION);
        d = base; d.not_before += 1;
        ASSERT_EQ(vcs_zcode_dht_delegation_verify(&d, NULL, NULL, 0, NULL, 1000),
                  VCS_ZCODE_DHT_DELEGATION_PROJECTION);
        PASS();
    } _test_next:;
    return failures;
}

static int test_roster_validity_window(void)
{
    int failures = 0;
    TEST("zcode dht delegation: roster validity is 0 < window <= 7 days") {
        struct vcs_zcode_dht_delegation d;
        ASSERT(make_roster(&d, 1, 1000, 1000 + 3 * 86400, 0x22, 0x55));
        ASSERT(make_roster(&d, 1, 1000, 1000 + 7 * 86400, 0x22, 0x55));
        ASSERT_EQ(VCS_ZCODE_DHT_DELEGATION_ROSTER_MAX_SECONDS, 7 * 86400);
        ASSERT(!make_roster(&d, 1, 1000, 1000, 0x22, 0x55));
        ASSERT(!make_roster(&d, 1, 1000, 999, 0x22, 0x55));
        ASSERT(!make_roster(&d, 1, 1000, 1000 + 7 * 86400 + 1, 0x22, 0x55));
        PASS();
    } _test_next:;
    return failures;
}

static int test_roster_refused_by_verify_paths(void)
{
    int failures = 0;
    TEST("zcode dht delegation: chain verify (transport and authority) "
         "refuses roster mode") {
        struct vcs_zcode_dht_delegation r;
        ASSERT(make_roster(&r, 1, 1000, 1000 + 86400, 0x22, 0x55));
        /* Every transport_verify and authority_verify site first calls
         * vcs_zcode_dht_delegation_verify; the named reason is shared. */
        ASSERT_EQ(vcs_zcode_dht_delegation_verify(&r, NULL, NULL, 0, NULL, 1000),
                  VCS_ZCODE_DHT_DELEGATION_ROSTER_MODE);
        ASSERT(strcmp(vcs_zcode_dht_delegation_error_string(
                          VCS_ZCODE_DHT_DELEGATION_ROSTER_MODE),
                      "roster-mode-unsupported") == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_delegation_roundtrip(void)
{
    int failures = 0;
    TEST("zcode dht delegation: canonical signed round trip") {
        struct vcs_zcode_dht_delegation d, parsed;
        ASSERT(make_delegation(&d, 7, 1000, 1000 + 3 * 86400, 0x22));
        uint8_t wire[VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_dht_delegation_encode(&d, wire),
                  VCS_ZCODE_DHT_DELEGATION_OK);
        ASSERT_EQ(vcs_zcode_dht_delegation_decode(&parsed, wire, sizeof(wire)),
                  VCS_ZCODE_DHT_DELEGATION_OK);
        uint8_t genesis[32], noise[32], beacon[32];
        fill32(genesis, 0x01); fill32(noise, 0x33); fill32(beacon, 0x44);
        ASSERT_EQ(vcs_zcode_dht_delegation_verify(
                      &parsed, genesis, noise, 120, beacon, 1000),
                  VCS_ZCODE_DHT_DELEGATION_OK);
        ASSERT_EQ(parsed.doc.seq, 7);
        ASSERT_EQ(parsed.not_before, 1000);
        PASS();
    } _test_next:;
    return failures;
}

static int test_delegation_windows_and_binding(void)
{
    int failures = 0;
    TEST("zcode dht delegation: windows and bindings fail closed") {
        struct vcs_zcode_dht_delegation d;
        ASSERT(make_delegation(&d, 1, 1000, 1000 + ZENDP_MAX_WINDOW_SECONDS,
                               0x22));
        struct vcs_zcode_dht_delegation too_long;
        ASSERT(!make_delegation(&too_long, 1, 1000,
                                1001 + ZENDP_MAX_WINDOW_SECONDS, 0x22));
        uint8_t genesis[32], noise[32], beacon[32], wrong[32];
        fill32(genesis, 0x01); fill32(noise, 0x33);
        fill32(beacon, 0x44); fill32(wrong, 0x99);
        ASSERT_EQ(vcs_zcode_dht_delegation_verify(
                      &d, genesis, noise, 120, beacon, 999),
                  VCS_ZCODE_DHT_DELEGATION_NOT_YET_VALID);
        ASSERT_EQ(vcs_zcode_dht_delegation_verify(
                      &d, wrong, noise, 120, beacon, 1000),
                  VCS_ZCODE_DHT_DELEGATION_NETWORK);
        ASSERT_EQ(vcs_zcode_dht_delegation_verify(
                      &d, genesis, wrong, 120, beacon, 1000),
                  VCS_ZCODE_DHT_DELEGATION_NOISE_KEY);
        ASSERT_EQ(vcs_zcode_dht_delegation_verify(
                      &d, genesis, noise, 121, beacon, 1000),
                  VCS_ZCODE_DHT_DELEGATION_BEACON);
        ASSERT_EQ(vcs_zcode_dht_delegation_verify(
                      &d, genesis, noise, 120, wrong, 1000),
                  VCS_ZCODE_DHT_DELEGATION_BEACON);
        /* At exactly the doc's expiry, vcs_zcode_dht_delegation_verify()
         * now reports EXPIRED (a distinct, named lifecycle code) rather
         * than falling through to zid_doc_verify() and reporting the
         * generic SIGNATURE failure that an expired-but-otherwise-valid
         * doc used to produce before that code existed. */
        ASSERT_EQ(vcs_zcode_dht_delegation_verify(
                      &d, genesis, noise, 120, beacon,
                      1000 + ZENDP_MAX_WINDOW_SECONDS),
                  VCS_ZCODE_DHT_DELEGATION_EXPIRED);
        PASS();
    } _test_next:;
    return failures;
}

static int test_delegation_stable_node_id(void)
{
    int failures = 0;
    TEST("zcode dht delegation: renewal and online rotation keep node id") {
        struct vcs_zcode_dht_delegation a, b;
        ASSERT(make_delegation(&a, 1, 1000, 2000, 0x22));
        ASSERT(make_delegation(&b, 2, 1100, 2100, 0x66));
        uint8_t aid[32], bid[32];
        ASSERT(vcs_zcode_dht_delegation_node_id(aid, &a));
        ASSERT(vcs_zcode_dht_delegation_node_id(bid, &b));
        ASSERT(memcmp(aid, bid, 32) == 0);
        b.beacon_hash[0] ^= 1;
        ASSERT(vcs_zcode_dht_delegation_node_id(bid, &b));
        ASSERT(memcmp(aid, bid, 32) != 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_delegation_tamper(void)
{
    int failures = 0;
    TEST("zcode dht delegation: malformed and tampered wires reject") {
        struct vcs_zcode_dht_delegation d, parsed;
        ASSERT(make_delegation(&d, 1, 1000, 2000, 0x22));
        uint8_t wire[VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_dht_delegation_encode(&d, wire),
                  VCS_ZCODE_DHT_DELEGATION_OK);
        ASSERT_EQ(vcs_zcode_dht_delegation_decode(
                      &parsed, wire, sizeof(wire) - 1),
                  VCS_ZCODE_DHT_DELEGATION_SIZE);
        wire[51] ^= 1;
        ASSERT_EQ(vcs_zcode_dht_delegation_decode(&parsed, wire, sizeof(wire)),
                  VCS_ZCODE_DHT_DELEGATION_BODY);
        wire[51] ^= 1;
        wire[80] ^= 1;
        ASSERT_EQ(vcs_zcode_dht_delegation_decode(&parsed, wire, sizeof(wire)),
                  VCS_ZCODE_DHT_DELEGATION_OK);
        ASSERT_EQ(vcs_zcode_dht_delegation_verify(
                      &parsed, NULL, NULL, 0, NULL, 1000),
                  VCS_ZCODE_DHT_DELEGATION_SIGNATURE);
        PASS();
    } _test_next:;
    return failures;
}

static int test_delegation_identity_files(void)
{
    int failures = 0;
    TEST("zcode dht delegation: identity files are atomic and mode-bound") {
        char datadir[] = "/tmp/zcl_dht_identity_XXXXXX";
        ASSERT(mkdtemp(datadir) != NULL);
        uint8_t seed1[32], pub1[32], seed2[32], pub2[32];
        char err[192];
        struct vcs_zcode_dht_delegation loaded;
        char zcode_dir[512];
        snprintf(zcode_dir, sizeof(zcode_dir), "%s/zcode", datadir);
        ASSERT(!vcs_zcode_dht_delegation_load(
            datadir, &loaded, err, sizeof(err)));
        ASSERT(access(zcode_dir, F_OK) != 0);
        ASSERT(!vcs_zcode_dht_online_key_load(
            datadir, seed2, pub2, err, sizeof(err)));
        ASSERT(access(zcode_dir, F_OK) != 0);
        ASSERT(vcs_zcode_dht_online_key_load_or_create(
            datadir, seed1, pub1, err, sizeof(err)));
        ASSERT(vcs_zcode_dht_online_key_load_or_create(
            datadir, seed2, pub2, err, sizeof(err)));
        ASSERT(memcmp(seed1, seed2, 32) == 0);
        ASSERT(memcmp(pub1, pub2, 32) == 0);

        struct vcs_zcode_dht_delegation original;
        ASSERT(make_delegation(&original, 9, 1000, 2000, 0x22));
        ASSERT(vcs_zcode_dht_delegation_save(
            datadir, &original, err, sizeof(err)));
        ASSERT(vcs_zcode_dht_delegation_load(
            datadir, &loaded, err, sizeof(err)));
        ASSERT_EQ(loaded.doc.seq, 9);
        ASSERT(memcmp(loaded.doc.signature, original.doc.signature, 64) == 0);

        char online_path[512], delegation_path[512], dht_dir[512];
        snprintf(dht_dir, sizeof(dht_dir), "%s/zcode/dht", datadir);
        snprintf(online_path, sizeof(online_path), "%s/%s", dht_dir,
                 VCS_ZCODE_DHT_ONLINE_KEY_FILE);
        snprintf(delegation_path, sizeof(delegation_path), "%s/%s", dht_dir,
                 VCS_ZCODE_DHT_DELEGATION_FILE);
        struct stat st;
        ASSERT(stat(online_path, &st) == 0 && (st.st_mode & 0777) == 0600);
        ASSERT(stat(delegation_path, &st) == 0 &&
               (st.st_mode & 0777) == 0600);
        ASSERT(chmod(online_path, 0644) == 0);
        ASSERT(!vcs_zcode_dht_online_key_load_or_create(
            datadir, seed2, pub2, err, sizeof(err)));

        ASSERT(unlink(online_path) == 0);
        ASSERT(unlink(delegation_path) == 0);
        ASSERT(rmdir(dht_dir) == 0);
        ASSERT(rmdir(zcode_dir) == 0);
        ASSERT(rmdir(datadir) == 0);
        PASS();
    } _test_next:;
    return failures;
}

int test_zcode_dht_delegation(void)
{
    int failures = 0;
    failures += test_delegation_chain_golden();
    failures += test_delegation_roundtrip();
    failures += test_roster_node_id_and_beacon();
    failures += test_roster_cross_mode();
    failures += test_roster_validity_window();
    failures += test_unknown_mode_refused();
    failures += test_roster_cache_bound_to_body();
    failures += test_chain_cache_bound_to_body();
    failures += test_roster_refused_by_verify_paths();
    failures += test_delegation_windows_and_binding();
    failures += test_delegation_stable_node_id();
    failures += test_delegation_tamper();
    failures += test_delegation_identity_files();
    printf("=== zcode_dht_delegation: %d failures ===\n", failures);
    return failures;
}
