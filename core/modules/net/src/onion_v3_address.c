/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Tor v3 onion address codec — see net/onion_v3_address.h. The
 * checksum rule is the same one network_crawler_probe.c documents for its
 * render path; this module is the shared, decode-capable home for it. */

#include "net/onion_v3_address.h"

#include "base/bytes.h"
#include "crypto/sha3.h"
#include "encoding/utilstrencodings.h"

#include <string.h>

#define ONION_V3_B32_LEN 56u
#define ONION_V3_SUFFIX ".onion"
#define ONION_V3_SUFFIX_LEN 6u
#define ONION_V3_VERSION 0x03u

static void onion_v3_checksum(const uint8_t pubkey[32], uint8_t out[2])
{
    uint8_t pre[15 + 32 + 1];
    memcpy(pre, ".onion checksum", 15);
    memcpy(pre + 15, pubkey, 32);
    pre[15 + 32] = ONION_V3_VERSION;
    uint8_t digest[32];
    sha3_256(pre, sizeof(pre), digest);
    out[0] = digest[0];
    out[1] = digest[1];
}

/* RFC 4648 lowercase base32 (a-z2-7), decode half — EncodeBase32 is the
 * encode half. Returns false on any character outside the alphabet. */
static bool onion_b32_decode(const char *in, size_t in_len,
                             uint8_t *out, size_t out_len)
{
    if (!in || !out || in_len != ONION_V3_B32_LEN || out_len != 35)
        return false;
    memset(out, 0, out_len);
    uint32_t acc = 0;
    unsigned bits = 0;
    size_t written = 0;
    for (size_t i = 0; i < in_len; i++) {
        char c = in[i];
        uint32_t v;
        if (c >= 'a' && c <= 'z')
            v = (uint32_t)(c - 'a');
        else if (c >= '2' && c <= '7')
            v = (uint32_t)(c - '2') + 26u;
        else
            return false;
        acc = (acc << 5) | v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (written >= out_len)
                return false;
            out[written++] = (uint8_t)(acc >> bits);
        }
    }
    /* 56 chars * 5 bits = 280 = 35 bytes exactly; nothing may be left. */
    return written == out_len && bits == 0;
}

bool onion_v3_address_from_pubkey(const uint8_t pubkey[32],
                                  char out[ONION_V3_ADDRESS_LEN + 1])
{
    if (out)
        out[0] = '\0';
    if (!pubkey || !out)
        return false;
    if (!zcl_bytes_any_set(pubkey, 32))
        return false;
    uint8_t blob[35];
    memcpy(blob, pubkey, 32);
    onion_v3_checksum(pubkey, blob + 32);
    blob[34] = ONION_V3_VERSION;
    char b32[ONION_V3_B32_LEN + 1];
    if (EncodeBase32(blob, sizeof(blob), b32, sizeof(b32)) !=
        ONION_V3_B32_LEN)
        return false;
    memcpy(out, b32, ONION_V3_B32_LEN);
    memcpy(out + ONION_V3_B32_LEN, ONION_V3_SUFFIX, ONION_V3_SUFFIX_LEN + 1);
    return true;
}

bool onion_v3_pubkey_from_address(const char *address, uint8_t out[32])
{
    if (out)
        memset(out, 0, 32);
    if (!address || !out)
        return false;
    size_t len = strlen(address);
    if (len == ONION_V3_ADDRESS_LEN) {
        if (memcmp(address + ONION_V3_B32_LEN, ONION_V3_SUFFIX,
                   ONION_V3_SUFFIX_LEN) != 0)
            return false;
    } else if (len != ONION_V3_B32_LEN) {
        return false;
    }
    uint8_t blob[35];
    if (!onion_b32_decode(address, ONION_V3_B32_LEN, blob, sizeof(blob)))
        return false;
    if (blob[34] != ONION_V3_VERSION)
        return false;
    uint8_t expect[2];
    onion_v3_checksum(blob, expect);
    if (blob[32] != expect[0] || blob[33] != expect[1])
        return false;
    memcpy(out, blob, 32);
    return true;
}
