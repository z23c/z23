/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Hermetic coverage for the key-io Base58Check codec
 * (contexts/wallet/modules/keys/src/key_io.c): encode_destination, decode_destination,
 * encode_secret, decode_secret.
 *
 * These four functions were previously exercised only incidentally
 * (test_keys.c has a legacy printf-style happy-path check, and
 * test_key_hostile_wif.c covers ONLY the decode_secret scalar-range
 * boundary). This group is the focused, TEST()/ASSERT()-style pass over
 * the pure encode/decode surface: happy path, roundtrips, boundary
 * lengths, wrong-prefix rejection, corrupted-checksum rejection, and the
 * two failure predicates the header documents (unsupported destination
 * type; undersized output buffer).
 *
 * Pure and deterministic: no clock, no RNG, no network, no live DB.
 * decode_secret's scalar-range check calls into secp256k1 via
 * privkey_range_check(), which needs the process-wide signing context —
 * test_parallel's per-child harness already calls ecc_start() before
 * running any group (see test_parallel.c), so no setup is needed here. */

#include "test/test_core.h"

#include "core/uint256.h"
#include "domain/encoding/base58.h"
#include "keys/key.h"
#include "keys/key_io.h"
#include "script/standard.h"

#include <string.h>

/* secp256k1 group order n, big-endian — same constant used by
 * test_key_hostile_wif.c for the decode_secret range-check boundary. */
static const unsigned char TKIO_ORDER[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
};

/* Encode prefix||scalar[||0x01] as Base58Check without going through
 * encode_secret — lets tests build a WIF for an out-of-range scalar
 * that encode_secret itself would happily encode (it never validates
 * the payload; only decode_secret's range check does). */
static bool tkio_make_wif(const unsigned char *prefix, size_t pfx_len,
                          const unsigned char scalar[32], bool compressed,
                          char *out, size_t out_size)
{
    unsigned char payload[64];
    memcpy(payload, prefix, pfx_len);
    memcpy(payload + pfx_len, scalar, 32);
    size_t len = pfx_len + 32;
    if (compressed) {
        payload[len] = 0x01;
        len++;
    }
    size_t out_len = 0;
    return domain_encoding_base58check_encode(payload, len, out, out_size, &out_len);
}

int test_test_key_io_codec(void);
int test_test_key_io_codec(void)
{
    int failures = 0;

    const unsigned char pubkey_pfx[] = {0x1C, 0xB8};
    const unsigned char script_pfx[] = {0x1C, 0xBD};
    const unsigned char secret_pfx[] = {0x80};

    /* ── encode_destination / decode_destination ──────────────── */

    TEST("key_io: encode_destination P2PKH roundtrips through decode_destination") {
        struct tx_destination dest;
        dest.type = DEST_KEY_ID;
        memset(dest.id.key.id.data, 0x11, 20);
        char addr[64];
        ASSERT(encode_destination(&dest, pubkey_pfx, 2, script_pfx, 2, addr, sizeof(addr)));
        ASSERT(strlen(addr) > 20);

        struct tx_destination decoded;
        memset(&decoded, 0, sizeof(decoded));
        ASSERT(decode_destination(addr, pubkey_pfx, 2, script_pfx, 2, &decoded));
        ASSERT_EQ(decoded.type, DEST_KEY_ID);
        ASSERT(memcmp(decoded.id.key.id.data, dest.id.key.id.data, 20) == 0);
        PASS();
    }

    TEST("key_io: encode_destination P2SH roundtrips through decode_destination") {
        struct tx_destination dest;
        dest.type = DEST_SCRIPT_ID;
        memset(dest.id.script.hash.data, 0xAB, 20);
        char addr[64];
        ASSERT(encode_destination(&dest, pubkey_pfx, 2, script_pfx, 2, addr, sizeof(addr)));

        struct tx_destination decoded;
        memset(&decoded, 0, sizeof(decoded));
        ASSERT(decode_destination(addr, pubkey_pfx, 2, script_pfx, 2, &decoded));
        ASSERT_EQ(decoded.type, DEST_SCRIPT_ID);
        ASSERT(memcmp(decoded.id.script.hash.data, dest.id.script.hash.data, 20) == 0);
        PASS();
    }

    TEST("key_io: two destinations with different bytes never collide") {
        struct tx_destination a, b;
        a.type = DEST_KEY_ID;
        b.type = DEST_KEY_ID;
        memset(a.id.key.id.data, 0x01, 20);
        memset(b.id.key.id.data, 0x02, 20);
        char addr_a[64], addr_b[64];
        ASSERT(encode_destination(&a, pubkey_pfx, 2, script_pfx, 2, addr_a, sizeof(addr_a)));
        ASSERT(encode_destination(&b, pubkey_pfx, 2, script_pfx, 2, addr_b, sizeof(addr_b)));
        ASSERT(strcmp(addr_a, addr_b) != 0);
        PASS();
    }

    TEST("key_io: encode_destination rejects an unsupported destination type") {
        struct tx_destination dest;
        dest.type = DEST_NONE;
        char addr[64];
        ASSERT(!encode_destination(&dest, pubkey_pfx, 2, script_pfx, 2, addr, sizeof(addr)));
        PASS();
    }

    TEST("key_io: encode_destination fails when the output buffer is too small") {
        struct tx_destination dest;
        dest.type = DEST_KEY_ID;
        memset(dest.id.key.id.data, 0x33, 20);
        char tiny[4];
        ASSERT(!encode_destination(&dest, pubkey_pfx, 2, script_pfx, 2, tiny, sizeof(tiny)));
        PASS();
    }

    TEST("key_io: decode_destination rejects a corrupted checksum") {
        struct tx_destination dest;
        dest.type = DEST_KEY_ID;
        memset(dest.id.key.id.data, 0x44, 20);
        char addr[64];
        ASSERT(encode_destination(&dest, pubkey_pfx, 2, script_pfx, 2, addr, sizeof(addr)));

        /* Flip the last character before the NUL: Base58Check's trailing
         * checksum bytes live at the tail of the encoded string, so this
         * corrupts the checksum (or, rarely, the payload) and must fail
         * either way — decode_destination has no valid path for a mutated
         * string that still passes the checksum by chance across the
         * whole alphabet, so a single-character flip at the tail is a
         * reliable corruption for this fixed-length, deterministic input. */
        size_t n = strlen(addr);
        ASSERT(n > 0);
        addr[n - 1] = (addr[n - 1] == 'A') ? 'B' : 'A';

        /* Note: when the underlying base58check decode itself fails (as
         * here), decode_destination returns false WITHOUT touching
         * dest->type at all — the dest->type = DEST_NONE assignment in
         * the source only runs on the fallthrough path after a
         * successful base58check decode whose prefix matches neither
         * arm (see the "wrong prefix" case below). So this case only
         * asserts the false return, not dest->type. */
        struct tx_destination decoded;
        decoded.type = DEST_KEY_ID;
        ASSERT(!decode_destination(addr, pubkey_pfx, 2, script_pfx, 2, &decoded));
        PASS();
    }

    TEST("key_io: decode_destination rejects a well-formed address under the wrong prefix") {
        struct tx_destination dest;
        dest.type = DEST_KEY_ID;
        memset(dest.id.key.id.data, 0x55, 20);
        char addr[64];
        ASSERT(encode_destination(&dest, pubkey_pfx, 2, script_pfx, 2, addr, sizeof(addr)));

        /* Valid Base58Check payload, but decoded against prefixes that
         * match neither the pubkey nor script version bytes used to
         * encode it. */
        const unsigned char other_pubkey_pfx[] = {0x00, 0x00};
        const unsigned char other_script_pfx[] = {0x05, 0x05};
        struct tx_destination decoded;
        decoded.type = DEST_KEY_ID;
        ASSERT(!decode_destination(addr, other_pubkey_pfx, 2, other_script_pfx, 2, &decoded));
        ASSERT_EQ(decoded.type, DEST_NONE);
        PASS();
    }

    TEST("key_io: decode_destination rejects a plain garbage string") {
        /* "not-a-valid-address" contains characters outside the Base58
         * alphabet ('-', and letters like 'o'/'a' mixed with a hyphen
         * are fine individually, but the string as a whole still fails
         * checksum verification even where every character happens to
         * be in-alphabet) — base58check_decode fails, so (as above)
         * dest->type is left untouched, not forced to DEST_NONE. */
        struct tx_destination dest;
        dest.type = DEST_KEY_ID;
        ASSERT(!decode_destination("not-a-valid-address", pubkey_pfx, 2, script_pfx, 2, &dest));
        PASS();
    }

    TEST("key_io: decode_destination rejects the empty string") {
        /* base58_decode("") succeeds with length 0, but
         * base58check_decode then rejects it (decoded length < 4-byte
         * checksum) before decode_destination ever reaches its own
         * prefix-matching logic, so dest->type is again left untouched. */
        struct tx_destination dest;
        dest.type = DEST_KEY_ID;
        ASSERT(!decode_destination("", pubkey_pfx, 2, script_pfx, 2, &dest));
        PASS();
    }

    TEST("key_io: decode_destination distinguishes same-length pubkey vs script prefixes") {
        /* pubkey_pfx and script_pfx above are both 2 bytes but differ in
         * value — a P2SH-encoded address must decode as DEST_SCRIPT_ID,
         * never silently matched against the pubkey arm. */
        struct tx_destination dest;
        dest.type = DEST_SCRIPT_ID;
        memset(dest.id.script.hash.data, 0x66, 20);
        char addr[64];
        ASSERT(encode_destination(&dest, pubkey_pfx, 2, script_pfx, 2, addr, sizeof(addr)));

        struct tx_destination decoded;
        decoded.type = DEST_KEY_ID;
        ASSERT(decode_destination(addr, pubkey_pfx, 2, script_pfx, 2, &decoded));
        ASSERT_EQ(decoded.type, DEST_SCRIPT_ID);
        PASS();
    }

    TEST("key_io: decode_destination handles unequal-length pubkey/script prefixes") {
        /* Real chain params can use different-length version prefixes for
         * the two address families; exercise pfx_len != spfx_len so the
         * length-gated matching in decode_destination (data_len == 20 +
         * pfx_len vs data_len == 20 + spfx_len) is not accidentally
         * coupled to both prefixes being the same size. */
        const unsigned char pfx1[] = {0x1C, 0xB8};
        const unsigned char pfx3[] = {0x01, 0x02, 0x03};

        struct tx_destination dest;
        dest.type = DEST_KEY_ID;
        memset(dest.id.key.id.data, 0x77, 20);
        char addr[64];
        ASSERT(encode_destination(&dest, pfx1, 2, pfx3, 3, addr, sizeof(addr)));

        struct tx_destination decoded;
        decoded.type = DEST_NONE;
        ASSERT(decode_destination(addr, pfx1, 2, pfx3, 3, &decoded));
        ASSERT_EQ(decoded.type, DEST_KEY_ID);
        ASSERT(memcmp(decoded.id.key.id.data, dest.id.key.id.data, 20) == 0);

        struct tx_destination dest_script;
        dest_script.type = DEST_SCRIPT_ID;
        memset(dest_script.id.script.hash.data, 0x88, 20);
        char addr2[64];
        ASSERT(encode_destination(&dest_script, pfx1, 2, pfx3, 3, addr2, sizeof(addr2)));

        struct tx_destination decoded2;
        decoded2.type = DEST_NONE;
        ASSERT(decode_destination(addr2, pfx1, 2, pfx3, 3, &decoded2));
        ASSERT_EQ(decoded2.type, DEST_SCRIPT_ID);
        ASSERT(memcmp(decoded2.id.script.hash.data, dest_script.id.script.hash.data, 20) == 0);
        PASS();
    }

    /* ── encode_secret / decode_secret ─────────────────────────── */

    TEST("key_io: encode_secret/decode_secret roundtrips a compressed key") {
        struct privkey key;
        privkey_init(&key);
        memset(key.vch, 0x42, 32);
        key.fValid = true;
        key.fCompressed = true;

        char wif[128];
        ASSERT(encode_secret(&key, secret_pfx, 1, wif, sizeof(wif)));

        struct privkey decoded;
        ASSERT(decode_secret(wif, secret_pfx, 1, &decoded));
        ASSERT(decoded.fCompressed);
        ASSERT(decoded.fValid);
        ASSERT(memcmp(decoded.vch, key.vch, 32) == 0);
        PASS();
    }

    TEST("key_io: encode_secret/decode_secret roundtrips an uncompressed key") {
        struct privkey key;
        privkey_init(&key);
        memset(key.vch, 0x24, 32);
        key.fValid = true;
        key.fCompressed = false;

        char wif[128];
        ASSERT(encode_secret(&key, secret_pfx, 1, wif, sizeof(wif)));

        struct privkey decoded;
        ASSERT(decode_secret(wif, secret_pfx, 1, &decoded));
        ASSERT(!decoded.fCompressed);
        ASSERT(decoded.fValid);
        ASSERT(memcmp(decoded.vch, key.vch, 32) == 0);
        PASS();
    }

    TEST("key_io: encode_secret fails when the output buffer is too small") {
        struct privkey key;
        privkey_init(&key);
        memset(key.vch, 0x42, 32);
        key.fValid = true;
        key.fCompressed = true;

        char tiny[4];
        ASSERT(!encode_secret(&key, secret_pfx, 1, tiny, sizeof(tiny)));
        PASS();
    }

    TEST("key_io: decode_secret rejects a WIF under the wrong prefix") {
        struct privkey key;
        privkey_init(&key);
        memset(key.vch, 0x42, 32);
        key.fValid = true;
        key.fCompressed = true;

        char wif[128];
        ASSERT(encode_secret(&key, secret_pfx, 1, wif, sizeof(wif)));

        const unsigned char other_pfx[] = {0xEF};
        struct privkey decoded;
        ASSERT(!decode_secret(wif, other_pfx, 1, &decoded));
        PASS();
    }

    TEST("key_io: decode_secret rejects a corrupted checksum") {
        struct privkey key;
        privkey_init(&key);
        memset(key.vch, 0x42, 32);
        key.fValid = true;
        key.fCompressed = true;

        char wif[128];
        ASSERT(encode_secret(&key, secret_pfx, 1, wif, sizeof(wif)));
        size_t n = strlen(wif);
        ASSERT(n > 0);
        wif[n - 1] = (wif[n - 1] == 'A') ? 'B' : 'A';

        struct privkey decoded;
        ASSERT(!decode_secret(wif, secret_pfx, 1, &decoded));
        PASS();
    }

    TEST("key_io: decode_secret rejects a truncated payload (< 32-byte key)") {
        /* Base58Check-encode prefix + 8 bytes only (well under the
         * 32-byte key body decode_secret requires). */
        unsigned char payload[9];
        payload[0] = secret_pfx[0];
        memset(payload + 1, 0x11, 8);
        char wif[64];
        size_t out_len = 0;
        ASSERT(domain_encoding_base58check_encode(payload, sizeof(payload), wif, sizeof(wif), &out_len));

        struct privkey decoded;
        ASSERT(!decode_secret(wif, secret_pfx, 1, &decoded));
        PASS();
    }

    TEST("key_io: decode_secret rejects the empty string") {
        struct privkey decoded;
        ASSERT(!decode_secret("", secret_pfx, 1, &decoded));
        PASS();
    }

    TEST("key_io: decode_secret rejects a zero scalar (out of secp256k1 range)") {
        unsigned char zero[32] = {0};
        char wif[128];
        ASSERT(tkio_make_wif(secret_pfx, 1, zero, true, wif, sizeof(wif)));

        struct privkey decoded;
        ASSERT(!decode_secret(wif, secret_pfx, 1, &decoded));
        PASS();
    }

    TEST("key_io: decode_secret rejects a scalar equal to the group order") {
        char wif[128];
        ASSERT(tkio_make_wif(secret_pfx, 1, TKIO_ORDER, true, wif, sizeof(wif)));

        struct privkey decoded;
        ASSERT(!decode_secret(wif, secret_pfx, 1, &decoded));
        PASS();
    }

    TEST("key_io: decode_secret accepts the largest valid scalar (order - 1)") {
        unsigned char max_valid[32];
        memcpy(max_valid, TKIO_ORDER, 32);
        max_valid[31] -= 1;
        char wif[128];
        ASSERT(tkio_make_wif(secret_pfx, 1, max_valid, true, wif, sizeof(wif)));

        struct privkey decoded;
        ASSERT(decode_secret(wif, secret_pfx, 1, &decoded));
        ASSERT(decoded.fValid);
        ASSERT(memcmp(decoded.vch, max_valid, 32) == 0);
        PASS();
    }

    TEST("key_io: decode_secret accepts the smallest valid scalar (1)") {
        unsigned char one[32] = {0};
        one[31] = 1;
        char wif[128];
        ASSERT(tkio_make_wif(secret_pfx, 1, one, true, wif, sizeof(wif)));

        struct privkey decoded;
        ASSERT(decode_secret(wif, secret_pfx, 1, &decoded));
        ASSERT(decoded.fValid);
        ASSERT(memcmp(decoded.vch, one, 32) == 0);
        PASS();
    }

_test_next:;
    if (failures == 0)
        printf("test_test_key_io_codec: all passed\n");
    else
        printf("test_test_key_io_codec: %d FAILED\n", failures);
    return failures;
}
