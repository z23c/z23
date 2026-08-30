/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zswap_quote — the zswap_quote.v1 signed quote wire codec
 * (lib/zswap/zswap_quote.*).
 *
 * Pure codec/identity tests: exact KAT wires, malformed/trailing/
 * cross-network rejection, signature verification, expiry + lifetime cap,
 * seal determinism, and root commitment. No datadir, no chainparams
 * dependency. */

#include "test/test_core.h"

#include "base/bytes.h"
#include "crypto/ed25519.h"
#include "zswap/zswap_quote.h"

#include <stdio.h>
#include <string.h>

#define ZSQ_CHECK(name, expr) do {                                    \
    if (expr) { printf("  zswap_quote: %s... OK\n", (name)); }        \
    else { printf("  zswap_quote: %s... FAIL\n", (name));             \
        failures++; }                                                 \
} while (0)

#define ZSQ_ISSUED 1754000000LL
#define ZSQ_EXPIRES (ZSQ_ISSUED + 45LL)
#define ZSQ_NONCE 0x0102030405060708ULL
#define ZSQ_TOKEN_AMOUNT 500000ULL
#define ZSQ_ZCL_AMOUNT 125000000ULL

/* Pinned golden vectors for the fixture below (net[i]=0xA0+i, seller seed
 * 0x11, token[i]=0x40+i, ZSQ_NONCE/ZSQ_TOKEN_AMOUNT/ZSQ_ZCL_AMOUNT,
 * ZSQ_ISSUED/ZSQ_EXPIRES). Empty strings print the computed value and FAIL
 * — a KAT is never a hollow pass. */
#define ZSQ_KAT_BODY_HEX "5a53575154450d0a0100a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfd04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c97787370807060504030201404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f20a1070000000000405973070000000080ea8b6800000000adea8b6800000000"
#define ZSQ_KAT_WIRE_HEX "5a53575154450d0a0100a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfd04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c97787370807060504030201404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f20a1070000000000405973070000000080ea8b6800000000adea8b6800000000bc2c95921ef5f6953a732e39eeb77ec07bd3abda2da973f889f45518a62b9e1feaf45385b01d9ec17a452c372e279168342050375ac5f45276afbd15f6d0540e"
#define ZSQ_KAT_BODY_ROOT_HEX "fdc247fc8c4ccf02b1412daafb7ff55ef4d7948bf5d5c3cacf061e3699d6d3bf"
#define ZSQ_KAT_FULL_ROOT_HEX "e104ed1f04da7980152906ccd88775cf615ba0e3ebccf89f4acb41da7b7dacd8"

static void zsq_hex(const uint8_t *bytes, size_t len, char *out)
{
    static const char hexd[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = hexd[(bytes[i] >> 4) & 0xf];
        out[2 * i + 1] = hexd[bytes[i] & 0xf];
    }
    out[2 * len] = '\0';
}

static bool zsq_kat_pin(const char *name, const char *expect, const char *got)
{
    if (expect[0] == '\0') {
        printf("  zswap_quote: KAT(%s)=%s\n", name, got);
        return false;
    }
    return strcmp(expect, got) == 0;
}

static void zsq_fixture_net(uint8_t net[32])
{
    for (size_t i = 0; i < 32; i++) net[i] = (uint8_t)(0xa0u + i);
}

static void zsq_fixture_token(uint8_t token_id[32])
{
    for (size_t i = 0; i < 32; i++) token_id[i] = (uint8_t)(0x40u + i);
}

static void zsq_fixture_seller(uint8_t pk[32], uint8_t sk[32])
{
    uint8_t seed[32];
    memset(seed, 0x11, sizeof(seed));
    ed25519_keypair(pk, sk, seed);
}

/* An unsigned quote with the canonical fixture fields. */
static bool zsq_quote(struct zswap_quote_v1 *q, const uint8_t net[32],
                      const uint8_t seller_pk[32])
{
    memset(q, 0, sizeof(*q));
    q->schema_version = ZSWAP_QUOTE_VERSION;
    memcpy(q->network_genesis_root, net, 32);
    memcpy(q->seller_pubkey, seller_pk, 32);
    q->nonce = ZSQ_NONCE;
    zsq_fixture_token(q->token_id);
    q->token_amount = ZSQ_TOKEN_AMOUNT;
    q->zcl_amount = ZSQ_ZCL_AMOUNT;
    q->issued_unix = ZSQ_ISSUED;
    q->expires_unix = ZSQ_EXPIRES;
    return true;
}

static bool zsq_seal(struct zswap_quote_v1 *q)
{
    uint8_t seed[32];
    memset(seed, 0x11, sizeof(seed));
    return zswap_quote_seal(q, seed) == ZSWAP_QUOTE_OK;
}

static int t_kat(void)
{
    int failures = 0;
    uint8_t net[32], seller_pk[32], seller_sk[32];
    zsq_fixture_net(net);
    zsq_fixture_seller(seller_pk, seller_sk);
    struct zswap_quote_v1 q;
    ZSQ_CHECK("kat: fixture seals",
              zsq_quote(&q, net, seller_pk) && zsq_seal(&q));

    uint8_t wire[ZSWAP_QUOTE_WIRE_BYTES];
    uint8_t body[ZSWAP_QUOTE_BODY_BYTES];
    uint8_t body_root[32], full_root[32];
    char hex[2 * ZSWAP_QUOTE_WIRE_BYTES + 1];
    bool ok = zswap_quote_encode(&q, wire) == ZSWAP_QUOTE_OK;
    ok = ok && zswap_quote_body_root(&q, body_root) == ZSWAP_QUOTE_OK;
    ok = ok && zswap_quote_root(&q, full_root) == ZSWAP_QUOTE_OK;
    ZSQ_CHECK("kat: encode + roots", ok);
    memcpy(body, wire, ZSWAP_QUOTE_BODY_BYTES);

    zsq_hex(body, sizeof(body), hex);
    ZSQ_CHECK("kat: body wire golden",
              zsq_kat_pin("body", ZSQ_KAT_BODY_HEX, hex));
    zsq_hex(wire, sizeof(wire), hex);
    ZSQ_CHECK("kat: full wire golden",
              zsq_kat_pin("wire", ZSQ_KAT_WIRE_HEX, hex));
    zsq_hex(body_root, sizeof(body_root), hex);
    ZSQ_CHECK("kat: body root golden",
              zsq_kat_pin("body_root", ZSQ_KAT_BODY_ROOT_HEX, hex));
    zsq_hex(full_root, sizeof(full_root), hex);
    ZSQ_CHECK("kat: full root golden",
              zsq_kat_pin("full_root", ZSQ_KAT_FULL_ROOT_HEX, hex));
    return failures;
}

static int t_roundtrip(void)
{
    int failures = 0;
    uint8_t net[32], seller_pk[32], seller_sk[32];
    zsq_fixture_net(net);
    zsq_fixture_seller(seller_pk, seller_sk);
    struct zswap_quote_v1 q;
    ZSQ_CHECK("roundtrip: fixture seals",
              zsq_quote(&q, net, seller_pk) && zsq_seal(&q));
    uint8_t wire[ZSWAP_QUOTE_WIRE_BYTES];
    ZSQ_CHECK("roundtrip: encode",
              zswap_quote_encode(&q, wire) == ZSWAP_QUOTE_OK);

    struct zswap_quote_v1 back;
    ZSQ_CHECK("roundtrip: decode == struct",
              zswap_quote_decode(wire, sizeof(wire), &back) ==
                  ZSWAP_QUOTE_OK &&
              memcmp(&q, &back, sizeof(q)) == 0);
    uint8_t wire2[ZSWAP_QUOTE_WIRE_BYTES];
    ZSQ_CHECK("roundtrip: re-encode == wire",
              zswap_quote_encode(&back, wire2) == ZSWAP_QUOTE_OK &&
              memcmp(wire, wire2, sizeof(wire)) == 0);

    /* Truncated wires are exact-size rejections, never partial parses. */
    static const size_t short_lens[] = {0u, 7u, 8u, 100u, 145u, 146u, 209u};
    bool all_short = true;
    for (size_t i = 0; i < sizeof(short_lens) / sizeof(short_lens[0]); i++)
        all_short = all_short &&
            zswap_quote_decode(wire, short_lens[i], &back) ==
                ZSWAP_QUOTE_ERR_WIRE_SIZE;
    ZSQ_CHECK("roundtrip: truncated wires rejected", all_short);
    /* A trailing byte is a wire-size rejection. */
    uint8_t long_wire[ZSWAP_QUOTE_WIRE_BYTES + 1];
    memcpy(long_wire, wire, sizeof(wire));
    long_wire[sizeof(wire)] = 0x00;
    ZSQ_CHECK("roundtrip: trailing byte rejected",
              zswap_quote_decode(long_wire, sizeof(long_wire), &back) ==
                  ZSWAP_QUOTE_ERR_WIRE_SIZE);
    /* A wrong leading magic is its own error, not a size error. */
    uint8_t bad[ZSWAP_QUOTE_WIRE_BYTES];
    memcpy(bad, wire, sizeof(bad));
    bad[0] ^= 0xff;
    ZSQ_CHECK("roundtrip: bad magic rejected",
              zswap_quote_decode(bad, sizeof(bad), &back) ==
                  ZSWAP_QUOTE_ERR_WIRE_MAGIC);
    /* An unsupported schema version is its own error. */
    memcpy(bad, wire, sizeof(bad));
    bad[8] = 0x02;
    ZSQ_CHECK("roundtrip: bad version rejected",
              zswap_quote_decode(bad, sizeof(bad), &back) ==
                  ZSWAP_QUOTE_ERR_VERSION);
    /* A failed decode zeroes the output struct. */
    memset(&back, 0xaa, sizeof(back));
    ZSQ_CHECK("roundtrip: error zeroes output",
              zswap_quote_decode(wire, 10u, &back) ==
                  ZSWAP_QUOTE_ERR_WIRE_SIZE &&
              zcl_bytes_all_zero((const uint8_t *)&back, sizeof(back)));
    ZSQ_CHECK("roundtrip: NULL rejected",
              zswap_quote_decode(NULL, sizeof(wire), &back) ==
                  ZSWAP_QUOTE_ERR_NULL &&
              zswap_quote_decode(wire, sizeof(wire), NULL) ==
                  ZSWAP_QUOTE_ERR_NULL);
    return failures;
}

static int t_fields(void)
{
    int failures = 0;
    uint8_t net[32], seller_pk[32], seller_sk[32];
    zsq_fixture_net(net);
    zsq_fixture_seller(seller_pk, seller_sk);
    struct zswap_quote_v1 q;
    ZSQ_CHECK("fields: fixture seals",
              zsq_quote(&q, net, seller_pk) && zsq_seal(&q));

    struct zswap_quote_v1 x = q;
    memset(x.network_genesis_root, 0, 32);
    ZSQ_CHECK("fields: zero network root",
              zswap_quote_validate(&x) == ZSWAP_QUOTE_ERR_ROOT_ZERO);
    x = q;
    memset(x.seller_pubkey, 0, 32);
    ZSQ_CHECK("fields: zero seller pubkey",
              zswap_quote_validate(&x) == ZSWAP_QUOTE_ERR_PUBKEY_ZERO);
    x = q;
    memset(x.token_id, 0, 32);
    ZSQ_CHECK("fields: zero token id",
              zswap_quote_validate(&x) == ZSWAP_QUOTE_ERR_TOKEN_ID_ZERO);
    x = q;
    x.nonce = 0;
    ZSQ_CHECK("fields: zero nonce",
              zswap_quote_validate(&x) == ZSWAP_QUOTE_ERR_NONCE);
    x = q;
    x.token_amount = 0;
    ZSQ_CHECK("fields: zero token amount",
              zswap_quote_validate(&x) == ZSWAP_QUOTE_ERR_AMOUNT);
    x = q;
    x.zcl_amount = 0;
    ZSQ_CHECK("fields: zero zcl amount",
              zswap_quote_validate(&x) == ZSWAP_QUOTE_ERR_AMOUNT);
    x = q;
    x.issued_unix = 0;
    ZSQ_CHECK("fields: zero issued",
              zswap_quote_validate(&x) == ZSWAP_QUOTE_ERR_TIME_ORDER);
    x = q;
    x.expires_unix = x.issued_unix;
    ZSQ_CHECK("fields: expiry at issue",
              zswap_quote_validate(&x) == ZSWAP_QUOTE_ERR_TIME_ORDER);
    x = q;
    x.expires_unix = x.issued_unix + ZSWAP_QUOTE_MAX_LIFETIME_SECS + 1;
    ZSQ_CHECK("fields: lifetime over cap",
              zswap_quote_validate(&x) == ZSWAP_QUOTE_ERR_LIFETIME);
    x = q;
    x.expires_unix = x.issued_unix + ZSWAP_QUOTE_MAX_LIFETIME_SECS;
    ZSQ_CHECK("fields: lifetime at cap OK",
              zswap_quote_validate(&x) == ZSWAP_QUOTE_OK);
    x = q;
    memset(x.seller_signature, 0, 64);
    ZSQ_CHECK("fields: zero signature",
              zswap_quote_validate(&x) == ZSWAP_QUOTE_ERR_SIGNATURE);
    x = q;
    x.schema_version = 2;
    ZSQ_CHECK("fields: wrong version",
              zswap_quote_validate(&x) == ZSWAP_QUOTE_ERR_VERSION);
    ZSQ_CHECK("fields: good quote validates",
              zswap_quote_validate(&q) == ZSWAP_QUOTE_OK &&
              zswap_quote_validate(NULL) == ZSWAP_QUOTE_ERR_NULL);
    return failures;
}

static int t_seal(void)
{
    int failures = 0;
    uint8_t net[32], seller_pk[32], seller_sk[32];
    zsq_fixture_net(net);
    zsq_fixture_seller(seller_pk, seller_sk);
    struct zswap_quote_v1 q;
    ZSQ_CHECK("seal: fixture builds", zsq_quote(&q, net, seller_pk));

    uint8_t other_seed[32];
    memset(other_seed, 0x22, sizeof(other_seed));
    ZSQ_CHECK("seal: NULL rejected",
              zswap_quote_seal(NULL, seller_sk) == ZSWAP_QUOTE_ERR_NULL &&
              zswap_quote_seal(&q, NULL) == ZSWAP_QUOTE_ERR_NULL);
    /* A secret that does not derive the embedded seller key must never
     * seal — the wire would be unverifiable under either key. */
    struct zswap_quote_v1 x = q;
    ZSQ_CHECK("seal: wrong secret rejected",
              zswap_quote_seal(&x, other_seed) ==
                  ZSWAP_QUOTE_ERR_KEY_MISMATCH);
    /* A structurally invalid quote is refused before anything is signed. */
    x = q;
    x.token_amount = 0;
    ZSQ_CHECK("seal: invalid fields rejected",
              zswap_quote_seal(&x, seller_sk) == ZSWAP_QUOTE_ERR_AMOUNT);

    ZSQ_CHECK("seal: good quote seals", zsq_seal(&q));
    /* Ed25519 is deterministic: re-sealing a fresh copy of the same quote
     * yields the identical wire. */
    struct zswap_quote_v1 again;
    zsq_quote(&again, net, seller_pk);
    ZSQ_CHECK("seal: deterministic",
              zsq_seal(&again) &&
              memcmp(&q, &again, sizeof(q)) == 0);
    return failures;
}

static int t_verify(void)
{
    int failures = 0;
    uint8_t net[32], seller_pk[32], seller_sk[32];
    zsq_fixture_net(net);
    zsq_fixture_seller(seller_pk, seller_sk);
    struct zswap_quote_v1 q;
    ZSQ_CHECK("verify: fixture seals",
              zsq_quote(&q, net, seller_pk) && zsq_seal(&q));
    ZSQ_CHECK("verify: good quote",
              zswap_quote_verify_at(&q, net, ZSQ_ISSUED) == ZSWAP_QUOTE_OK);

    /* A flipped signature byte fails verification. */
    struct zswap_quote_v1 x = q;
    x.seller_signature[0] ^= 0x01;
    ZSQ_CHECK("verify: signature bit-flip",
              zswap_quote_verify_at(&x, net, ZSQ_ISSUED) ==
                  ZSWAP_QUOTE_ERR_SIGNATURE);
    /* A swapped signer key: the (now unmatching) signature no longer
     * verifies over the changed body. */
    x = q;
    uint8_t other_pk[32], other_sk[32];
    uint8_t other_seed[32];
    memset(other_seed, 0x22, sizeof(other_seed));
    ed25519_keypair(other_pk, other_sk, other_seed);
    memcpy(x.seller_pubkey, other_pk, 32);
    ZSQ_CHECK("verify: wrong signer key",
              zswap_quote_verify_at(&x, net, ZSQ_ISSUED) ==
                  ZSWAP_QUOTE_ERR_SIGNATURE);
    /* Cross-network wires are rejected before any signature math matters. */
    uint8_t other_net[32];
    for (size_t i = 0; i < 32; i++) other_net[i] = (uint8_t)(0xb0u + i);
    ZSQ_CHECK("verify: cross-network",
              zswap_quote_verify_at(&q, other_net, ZSQ_ISSUED) ==
                  ZSWAP_QUOTE_ERR_NETWORK_MISMATCH);
    ZSQ_CHECK("verify: NULL network",
              zswap_quote_verify_at(&q, NULL, ZSQ_ISSUED) ==
                  ZSWAP_QUOTE_ERR_NETWORK_MISMATCH);
    return failures;
}

static int t_expiry(void)
{
    int failures = 0;
    uint8_t net[32], seller_pk[32], seller_sk[32];
    zsq_fixture_net(net);
    zsq_fixture_seller(seller_pk, seller_sk);
    struct zswap_quote_v1 q;
    ZSQ_CHECK("expiry: fixture seals",
              zsq_quote(&q, net, seller_pk) && zsq_seal(&q));

    ZSQ_CHECK("expiry: usable window",
              zswap_quote_validate_at(&q, ZSQ_EXPIRES - 1) ==
                  ZSWAP_QUOTE_OK &&
              zswap_quote_validate_at(&q, ZSQ_ISSUED) == ZSWAP_QUOTE_OK);
    ZSQ_CHECK("expiry: too early",
              zswap_quote_validate_at(&q, ZSQ_ISSUED - 1) ==
                  ZSWAP_QUOTE_ERR_NOT_YET_VALID);
    ZSQ_CHECK("expiry: at expiry",
              zswap_quote_validate_at(&q, ZSQ_EXPIRES) ==
                  ZSWAP_QUOTE_ERR_EXPIRED);
    ZSQ_CHECK("expiry: far future",
              zswap_quote_validate_at(&q, ZSQ_EXPIRES + 1000000LL) ==
                  ZSWAP_QUOTE_ERR_EXPIRED);
    ZSQ_CHECK("expiry: verify gates time too",
              zswap_quote_verify_at(&q, net, ZSQ_EXPIRES) ==
                  ZSWAP_QUOTE_ERR_EXPIRED &&
              zswap_quote_verify_at(&q, net, ZSQ_ISSUED - 1) ==
                  ZSWAP_QUOTE_ERR_NOT_YET_VALID);
    return failures;
}

static int t_root_commitment(void)
{
    int failures = 0;
    uint8_t net[32], seller_pk[32], seller_sk[32];
    zsq_fixture_net(net);
    zsq_fixture_seller(seller_pk, seller_sk);
    struct zswap_quote_v1 q;
    ZSQ_CHECK("root: fixture seals",
              zsq_quote(&q, net, seller_pk) && zsq_seal(&q));
    uint8_t body_root[32], full_root[32];
    ZSQ_CHECK("root: computes",
              zswap_quote_body_root(&q, body_root) == ZSWAP_QUOTE_OK &&
              zswap_quote_root(&q, full_root) == ZSWAP_QUOTE_OK);

    /* body_root signs the BODY only: a flipped signature byte leaves it
     * unchanged (the signature is malleation in transport, not a new
     * statement). */
    struct zswap_quote_v1 x = q;
    x.seller_signature[0] ^= 0x01;
    uint8_t r2[32];
    ZSQ_CHECK("root: body root ignores signature",
              zswap_quote_body_root(&x, r2) == ZSWAP_QUOTE_OK &&
              memcmp(body_root, r2, 32) == 0);
    /* The full root commits the signature, so the same body sealed by a
     * different key — or the same key over a different nonce — is a
     * different quote id. */
    ZSQ_CHECK("root: full root commits signature",
              zswap_quote_root(&x, r2) == ZSWAP_QUOTE_OK &&
              memcmp(full_root, r2, 32) != 0);
    struct zswap_quote_v1 other_nonce;
    zsq_quote(&other_nonce, net, seller_pk);
    other_nonce.nonce = ZSQ_NONCE + 1;
    ZSQ_CHECK("root: nonce distinguishes quotes",
              zsq_seal(&other_nonce) &&
              zswap_quote_root(&other_nonce, r2) == ZSWAP_QUOTE_OK &&
              memcmp(full_root, r2, 32) != 0);
    /* A byte-identical re-gossip dedups on the root: same wire, same id. */
    ZSQ_CHECK("root: identical re-gossip dedups",
              zswap_quote_root(&q, r2) == ZSWAP_QUOTE_OK &&
              memcmp(full_root, r2, 32) == 0);
    ZSQ_CHECK("root: NULL rejected",
              zswap_quote_root(NULL, r2) == ZSWAP_QUOTE_ERR_NULL &&
              zswap_quote_body_root(&q, NULL) == ZSWAP_QUOTE_ERR_NULL);
    return failures;
}

int test_zswap_quote(void)
{
    printf("\n=== zswap_quote: signed quote wire codec ===\n");
    int failures = 0;
    failures += t_kat();
    failures += t_roundtrip();
    failures += t_fields();
    failures += t_seal();
    failures += t_verify();
    failures += t_expiry();
    failures += t_root_commitment();
    printf("=== zswap_quote complete: %d failure(s) ===\n", failures);
    return failures;
}
