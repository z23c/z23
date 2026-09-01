/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "crypto/ed25519.h"
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
        ASSERT_EQ(vcs_zcode_dht_delegation_verify(
                      &d, genesis, noise, 120, beacon,
                      1000 + ZENDP_MAX_WINDOW_SECONDS),
                  VCS_ZCODE_DHT_DELEGATION_SIGNATURE);
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
    failures += test_delegation_roundtrip();
    failures += test_delegation_windows_and_binding();
    failures += test_delegation_stable_node_id();
    failures += test_delegation_tamper();
    failures += test_delegation_identity_files();
    printf("=== zcode_dht_delegation: %d failures ===\n", failures);
    return failures;
}
