/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zssh_packet — layer (a): wire helpers, txq, binary packet, OpenSSH
 * chacha20-poly1305. Expected values come from the DJB ChaCha definition
 * (re-implemented below, independent of core/.../chacha20poly1305.c), RFC
 * 8439 2.5.2 for Poly1305, and a step-by-step construction of
 * PROTOCOL.chacha20poly1305 using only the raw primitives. That construction
 * is SPEC-DERIVED: it is our reading of the spec, not a third-party vector.
 *
 * TODO(interop): capture a real packet from an OpenSSH V_10_0_P2 client or
 * server (key, sequence number, wire bytes) in an interop run and add it as
 * the independent known-answer vector; until then the sealed-packet KAT below
 * proves self-consistency with the spec reading only, not wire compatibility. */

#include "zssh_internal.h"

#include "base/serialize_le.h"

#include <stdio.h>
#include <string.h>

static int g_fail;
static int g_group_fail;

#define CHECK(cond) do { if (!(cond)) { \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
    g_fail++; g_group_fail++; } } while (0)

static void group_begin(void) { g_group_fail = 0; }
static void group_end(const char *name)
{
    printf("%-44s %s\n", name, g_group_fail ? "FAIL" : "ok");
}

/* ---- independent ChaCha20 (DJB layout: 64-bit counter, 64-bit IV) ------ */
static uint32_t rotl(uint32_t v, int c) { return (v << c) | (v >> (32 - c)); }
static uint32_t le32(const uint8_t *p)
{
    return zcl_read_u32_le(p);
}
#define QR(a, b, c, d) \
    do { a += b; d ^= a; d = rotl(d, 16); c += d; b ^= c; b = rotl(b, 12); \
         a += b; d ^= a; d = rotl(d, 8);  c += d; b ^= c; b = rotl(b, 7); } while (0)

/* iv8 as OpenSSH hands it to chacha_ivsetup: input[14..15] = LE32 of the bytes;
 * counter64 in input[12..13]. */
static void ref_chacha_djb(const uint8_t key[32], const uint8_t iv8[8],
                           uint64_t counter, uint8_t out[64])
{
    uint32_t in[16], x[16];
    in[0] = 0x61707865; in[1] = 0x3320646e; in[2] = 0x79622d32; in[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) in[4 + i] = le32(key + 4 * i);
    in[12] = (uint32_t)counter; in[13] = (uint32_t)(counter >> 32);
    in[14] = le32(iv8); in[15] = le32(iv8 + 4);
    memcpy(x, in, sizeof x);
    for (int r = 0; r < 10; r++) {
        QR(x[0], x[4], x[8], x[12]); QR(x[1], x[5], x[9], x[13]);
        QR(x[2], x[6], x[10], x[14]); QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]); QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8], x[13]); QR(x[3], x[4], x[9], x[14]);
    }
    for (int i = 0; i < 16; i++) {
        uint32_t v = x[i] + in[i];
        zcl_write_u32_le(out + 4 * i, v);
    }
}

static void fill_key(uint8_t key[64], uint8_t salt)
{
    for (int i = 0; i < 64; i++) key[i] = (uint8_t)(i * 7 + salt);
}

/* ---- (1) chacha equivalence KAT ---------------------------------------- */
static void test_chacha_equivalence(void)
{
    group_begin();
    /* Published DJB vector: zero key, zero IV, counter 0 starts 76b8e0ad... */
    uint8_t zk[32] = {0}, z8[8] = {0}, blk[64], blk2[64], nonce[12] = {0};
    static const uint8_t first16[16] = {
        0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
        0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28 };
    ref_chacha_djb(zk, z8, 0, blk);
    CHECK(memcmp(blk, first16, 16) == 0);
    chacha20_block(zk, 0, nonce, blk2);
    CHECK(memcmp(blk2, first16, 16) == 0);

    uint8_t key[64];
    fill_key(key, 3);
    static const uint32_t seqs[] = { 0, 1, 2, 255, 256, 65536, 0x01020304u,
                                     0x7ffffffeu, 0x80000000u, 0xffffffffu };
    for (size_t i = 0; i < sizeof seqs / sizeof seqs[0]; i++) {
        uint8_t iv[8], n[12];
        zssh_put_u64(iv, seqs[i]);          /* POKE_U64: big-endian */
        zssh_chacha_nonce(n, seqs[i]);
        CHECK(n[0] == 0 && n[1] == 0 && n[2] == 0 && n[3] == 0);
        CHECK(memcmp(n + 4, iv, 8) == 0);
        for (uint32_t ctr = 0; ctr <= 3; ctr++) {
            for (int half = 0; half < 2; half++) {
                ref_chacha_djb(key + 32 * half, iv, ctr, blk);
                chacha20_block(key + 32 * half, ctr, n, blk2);
                CHECK(memcmp(blk, blk2, 64) == 0);
            }
        }
    }
    /* Control: a nonce with the sequence in the wrong place must differ. */
    uint8_t iv[8], bad[12] = {0};
    zssh_put_u64(iv, 5);
    memcpy(bad, iv, 8);
    ref_chacha_djb(key, iv, 0, blk);
    chacha20_block(key, 0, bad, blk2);
    CHECK(memcmp(blk, blk2, 64) != 0);
    group_end("chacha IETF == OpenSSH 64-bit nonce");
}

static void test_poly_sanity(void)
{
    group_begin();
    /* RFC 8439 2.5.2 */
    static const uint8_t key[32] = {
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe,
        0x42, 0xd5, 0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
        0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b };
    static const uint8_t want[16] = {
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
        0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9 };
    const char *msg = "Cryptographic Forum Research Group";
    uint8_t tag[16];
    poly1305_mac((const uint8_t *)msg, strlen(msg), key, tag);
    CHECK(memcmp(tag, want, 16) == 0);
    group_end("poly1305 RFC 8439 2.5.2");
}

/* ---- helpers for packets ----------------------------------------------- */
static uint8_t g_buf[ZSSH_RX_BUF_SIZE + 64];
static uint8_t g_snap[ZSSH_RX_BUF_SIZE + 64];
static uint8_t g_pay[ZSSH_MAX_PACKET + 64];

static void fill_payload(uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(i * 31 + 7);
}

static void make_pad(uint8_t pad[ZSSH_PAD_RANDOM_MAX])
{
    for (unsigned i = 0; i < ZSSH_PAD_RANDOM_MAX; i++) pad[i] = (uint8_t)(0xa0 + i);
}

static void dir_chacha(struct zssh_pkt_dir *d, uint8_t salt, uint32_t seq)
{
    uint8_t key[64];
    zssh_pkt_dir_init(d);
    fill_key(key, salt);
    CHECK(zssh_pkt_set_cipher(d, ZSSH_CIPHER_CHACHA20_POLY1305, key, true) == ZSSH_E_NONE);
    d->seq = seq;
}

static enum zssh_error seal_payload(struct zssh_pkt_dir *d, size_t n, size_t *total)
{
    uint8_t pad[ZSSH_PAD_RANDOM_MAX];
    make_pad(pad);
    fill_payload(g_buf + ZSSH_PKT_HDR, n);
    return zssh_pkt_seal(d, g_buf, sizeof g_buf, n, pad, total);
}

/* ---- (2) round trips ---------------------------------------------------- */
static void roundtrip_one(bool chacha, uint32_t seq, size_t n)
{
    struct zssh_pkt_dir tx, rx;
    if (chacha) { dir_chacha(&tx, 9, seq); dir_chacha(&rx, 9, seq); }
    else { zssh_pkt_dir_init(&tx); zssh_pkt_dir_init(&rx); tx.seq = rx.seq = seq; }
    size_t total = 0;
    CHECK(seal_payload(&tx, n, &total) == ZSSH_E_NONE);
    CHECK(tx.seq == seq + 1);
    if (chacha) CHECK(total >= 4 + 8 + 16 && (total - 4 - 16) % 8 == 0);
    else CHECK(total % 8 == 0 && total >= 16);
    CHECK(total <= ZSSH_RX_BUF_SIZE);
    if (n == 1)   /* NEWKEYS-sized: packet_length is the per-cipher minimum */
        CHECK(total == (chacha ? ZSSH_LEN_FIELD + ZSSH_MIN_PACKET_LENGTH_AEAD + ZSSH_TAG_LEN
                               : ZSSH_LEN_FIELD + ZSSH_MIN_PACKET_LENGTH_NONE));
    size_t want = 0;
    CHECK(zssh_pkt_peek_total(&rx, g_buf, &want) == ZSSH_E_NONE && want == total);
    if (chacha && n >= 8) {  /* ciphertext must not contain the plaintext run */
        fill_payload(g_pay, n);
        CHECK(memcmp(g_buf + ZSSH_PKT_HDR, g_pay, n) != 0);
    }
    const uint8_t *p = nullptr;
    size_t pn = 99;
    CHECK(zssh_pkt_open(&rx, g_buf, total, &p, &pn) == ZSSH_E_NONE);
    CHECK(pn == n && p == g_buf + ZSSH_PKT_HDR);
    fill_payload(g_pay, n);
    CHECK(p && pn == n && memcmp(p, g_pay, n) == 0);
    CHECK(g_buf[4] >= ZSSH_MIN_PAD && g_buf[4] <= ZSSH_MAX_PAD);
    CHECK(rx.seq == seq + 1);
}

static void test_roundtrip(void)
{
    group_begin();
    static const uint32_t seqs[] = { 0, 1, 255, 256, 65535, 0x01000000u, 0x7ffffffdu };
    static const size_t sizes[] = { 1, 2, 3, 7, 8, 9, 11, 12, 63, 64, 65, 100,
                                    1000, 16384, 16448 };
    for (int c = 0; c < 2; c++)
        for (size_t i = 0; i < sizeof seqs / sizeof seqs[0]; i++)
            for (size_t j = 0; j < sizeof sizes / sizeof sizes[0]; j++)
                roundtrip_one(c == 1, seqs[i], sizes[j]);
    /* maximum: packet_length == ZSSH_MAX_PACKET exactly */
    roundtrip_one(true, 3, ZSSH_MAX_PACKET - 5);   /* 1 + payload + 4 pad == 35000 */
    /* NONE: payload 34991 + 1 + 4 pad -> packet_length 34996 (== 4 mod 8); with
     * the 4-byte length field the wire total is 35000 == ZSSH_MAX_PACKET. */
    roundtrip_one(false, 3, ZSSH_MAX_PACKET - 9);
    struct zssh_pkt_dir d;
    size_t total = 77;
    dir_chacha(&d, 9, 4);
    CHECK(seal_payload(&d, 0, &total) == ZSSH_E_TOO_LARGE && total == 0 && d.seq == 4);
    CHECK(seal_payload(&d, ZSSH_MAX_PACKET - 4, &total) == ZSSH_E_TOO_LARGE && d.seq == 4);
    CHECK(seal_payload(&d, ZSSH_MAX_PACKET + 1, &total) == ZSSH_E_TOO_LARGE && d.seq == 4);
    zssh_pkt_dir_init(&d);
    CHECK(seal_payload(&d, ZSSH_MAX_PACKET - 8, &total) == ZSSH_E_TOO_LARGE && d.seq == 0);
    /* cap too small */
    uint8_t pad[ZSSH_PAD_RANDOM_MAX];
    make_pad(pad);
    dir_chacha(&d, 9, 0);
    CHECK(zssh_pkt_seal(&d, g_buf, ZSSH_PKT_HDR + 10 + ZSSH_PAD_RANDOM_MAX + ZSSH_TAG_LEN - 1,
                        10, pad, &total) == ZSSH_E_INTERNAL && d.seq == 0);
    group_end("seal -> open round trips");
}

/* ---- (3) spec-derived known answer -------------------------------------- */
/* Build the wire bytes of one packet from PROTOCOL.chacha20poly1305 using only
 * chacha20_block and poly1305_mac. Spec-derived (see TODO(interop) above).
 * Returns the total length. */
static size_t kat_build(const uint8_t key[64], uint32_t seq, const uint8_t *payload,
                        size_t n, const uint8_t *pad, uint8_t *out)
{
    const uint8_t *k2 = key, *k1 = key + 32;     /* main = first half */
    uint8_t nonce[12] = {0}, ks[64], polykey[32], tag[16];
    zcl_write_u32_be(nonce + 8, seq);
    size_t padlen = 8 - ((1 + n) % 8);
    if (padlen < 4) padlen += 8;
    size_t plen = 1 + n + padlen;
    uint8_t *body = out + 4;
    body[0] = (uint8_t)padlen;
    memcpy(body + 1, payload, n);
    memcpy(body + 1 + n, pad, padlen);
    for (size_t off = 0, ctr = 1; off < plen; off += 64, ctr++) {
        chacha20_block(k2, (uint32_t)ctr, nonce, ks);
        for (size_t i = 0; i < 64 && off + i < plen; i++) body[off + i] ^= ks[i];
    }
    chacha20_block(k1, 0, nonce, ks);
    uint8_t hdr[4];
    zcl_write_u32_be(hdr, (uint32_t)plen);
    for (int i = 0; i < 4; i++) out[i] = hdr[i] ^ ks[i];
    chacha20_block(k2, 0, nonce, ks);
    memcpy(polykey, ks, 32);
    poly1305_mac(out, 4 + plen, polykey, tag);
    memcpy(out + 4 + plen, tag, 16);
    return 4 + plen + 16;
}

static void test_known_answer(void)
{
    group_begin();
    static const size_t sizes[] = { 1, 5, 27, 59, 60, 123 };
    static const uint32_t seqs[] = { 0, 3, 0x01020304u };
    uint8_t key[64], pad[ZSSH_PAD_RANDOM_MAX], pay[200], want[400];
    fill_key(key, 0x41);
    make_pad(pad);
    for (size_t s = 0; s < 3; s++) {
        for (size_t i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
            size_t n = sizes[i];
            fill_payload(pay, n);
            size_t wl = kat_build(key, seqs[s], pay, n, pad, want);
            struct zssh_pkt_dir d;
            dir_chacha(&d, 0x41, seqs[s]);
            memcpy(g_buf + ZSSH_PKT_HDR, pay, n);
            size_t total = 0;
            CHECK(zssh_pkt_seal(&d, g_buf, sizeof g_buf, n, pad, &total) == ZSSH_E_NONE);
            CHECK(total == wl && memcmp(g_buf, want, wl) == 0);
            /* and the independently built bytes open under the library */
            struct zssh_pkt_dir r;
            dir_chacha(&r, 0x41, seqs[s]);
            memcpy(g_buf, want, wl);
            const uint8_t *p = nullptr; size_t pn = 0;
            CHECK(zssh_pkt_open(&r, g_buf, wl, &p, &pn) == ZSSH_E_NONE);
            CHECK(pn == n && memcmp(p, pay, n) == 0);
        }
    }
    /* Control: a different sequence number yields different bytes. */
    fill_payload(pay, 27);
    size_t a = kat_build(key, 3, pay, 27, pad, want);
    uint8_t other[400];
    size_t b = kat_build(key, 4, pay, 27, pad, other);
    CHECK(a == b && memcmp(want, other, a) != 0);
    group_end("spec-derived sealed-packet known answer");
}

/* ---- (4) tamper controls ------------------------------------------------ */
static size_t make_sealed(uint8_t salt, uint32_t seq, size_t n)
{
    struct zssh_pkt_dir tx;
    size_t total = 0;
    dir_chacha(&tx, salt, seq);
    CHECK(seal_payload(&tx, n, &total) == ZSSH_E_NONE);
    return total;
}

static void expect_refused(struct zssh_pkt_dir *rx, size_t total,
                           enum zssh_error want)
{
    uint32_t seq0 = rx->seq;
    uint64_t pk0 = rx->packets, by0 = rx->bytes;
    memcpy(g_snap, g_buf, total);
    const uint8_t *p = (const uint8_t *)1;
    size_t pn = 5;
    enum zssh_error e = zssh_pkt_open(rx, g_buf, total, &p, &pn);
    CHECK(e == want);
    CHECK(p == nullptr && pn == 0);
    CHECK(rx->seq == seq0 && rx->packets == pk0 && rx->bytes == by0);
    CHECK(memcmp(g_buf, g_snap, total) == 0);
}

static void test_tamper(void)
{
    group_begin();
    const size_t n = 100;
    const uint32_t seq = 41;
    struct zssh_pkt_dir rx;
    size_t total = make_sealed(5, seq, n);

    /* control: pristine packet opens */
    dir_chacha(&rx, 5, seq);
    const uint8_t *p; size_t pn;
    CHECK(zssh_pkt_open(&rx, g_buf, total, &p, &pn) == ZSSH_E_NONE && pn == n);

    /* flipped tag bit (every byte of the tag) */
    for (size_t i = 0; i < ZSSH_TAG_LEN; i++) {
        total = make_sealed(5, seq, n);
        g_buf[total - ZSSH_TAG_LEN + i] ^= 0x01;
        dir_chacha(&rx, 5, seq);
        expect_refused(&rx, total, ZSSH_E_MAC);
    }
    /* flipped payload / padding-length / padding bits */
    static const size_t offs[] = { 4, 5, 6, 50, 4 + 1 + 100 + 3 };
    for (size_t i = 0; i < sizeof offs / sizeof offs[0]; i++) {
        total = make_sealed(5, seq, n);
        g_buf[offs[i]] ^= 0x80;
        dir_chacha(&rx, 5, seq);
        expect_refused(&rx, total, ZSSH_E_MAC);
    }
    /* flipped encrypted length bit: size changes -> refused before the tag */
    total = make_sealed(5, seq, n);
    g_buf[3] ^= 0x01;                         /* length % 8 != 0 */
    dir_chacha(&rx, 5, seq);
    expect_refused(&rx, total, ZSSH_E_PROTOCOL);
    total = make_sealed(5, seq, n);
    g_buf[3] ^= 0x08;                         /* still valid, but size != buffer */
    dir_chacha(&rx, 5, seq);
    expect_refused(&rx, total, ZSSH_E_PROTOCOL);
    total = make_sealed(5, seq, n);
    g_buf[0] ^= 0x80;                         /* absurd length */
    dir_chacha(&rx, 5, seq);
    expect_refused(&rx, total, ZSSH_E_TOO_LARGE);
    /* the same +8 length flip with a caller that honours the new size: the
     * tag covers the length, so it is a MAC failure */
    total = make_sealed(5, seq, n);
    memset(g_buf + total, 0, 16);
    g_buf[3] ^= 0x08;
    dir_chacha(&rx, 5, seq);
    size_t nt = 0;
    CHECK(zssh_pkt_peek_total(&rx, g_buf, &nt) == ZSSH_E_NONE);
    CHECK(nt == total + 8);                   /* plaintext length 112 ^ 8 == 120 */
    expect_refused(&rx, nt, ZSSH_E_MAC);
    /* wrong sequence number on the receiver: refused, typed, untouched */
    total = make_sealed(5, seq, n);
    dir_chacha(&rx, 5, seq + 1);
    memcpy(g_snap, g_buf, total);
    {
        const uint8_t *pp = (const uint8_t *)1; size_t pnn = 5;
        enum zssh_error e = zssh_pkt_open(&rx, g_buf, total, &pp, &pnn);
        CHECK(e == ZSSH_E_MAC || e == ZSSH_E_PROTOCOL || e == ZSSH_E_TOO_LARGE);
        CHECK(pp == nullptr && pnn == 0 && rx.seq == seq + 1);
        CHECK(memcmp(g_buf, g_snap, total) == 0);
    }
    /* wrong sequence number with a valid-looking length: splice the length
     * field of the packet at seq with the body and tag of a packet at seq+1
     * (same size); the tag is bound to the sequence number -> MAC. */
    total = make_sealed(5, seq, n);
    uint8_t len_a[4];
    memcpy(len_a, g_buf, 4);
    total = make_sealed(5, seq + 1, n);
    memcpy(g_buf, len_a, 4);
    dir_chacha(&rx, 5, seq);
    expect_refused(&rx, total, ZSSH_E_MAC);
    /* wrong payload key (K_2 only): the length still decrypts, so the failure
     * is exactly a tag mismatch */
    total = make_sealed(5, seq, n);
    dir_chacha(&rx, 5, seq);
    rx.key[0] ^= 0x01;
    expect_refused(&rx, total, ZSSH_E_MAC);
    /* wrong header key (K_1 only): the length decrypts to garbage, so the
     * refusal comes from the length checks; it must still be typed and clean */
    total = make_sealed(5, seq, n);
    dir_chacha(&rx, 5, seq);
    rx.key[32] ^= 0x01;
    memcpy(g_snap, g_buf, total);
    {
        const uint8_t *pp = (const uint8_t *)1; size_t pnn = 5;
        enum zssh_error e = zssh_pkt_open(&rx, g_buf, total, &pp, &pnn);
        CHECK(e == ZSSH_E_PROTOCOL || e == ZSSH_E_TOO_LARGE || e == ZSSH_E_MAC);
        CHECK(pp == nullptr && pnn == 0 && rx.seq == seq);
        CHECK(memcmp(g_buf, g_snap, total) == 0);
    }
    /* wrong whole key */
    total = make_sealed(5, seq, n);
    dir_chacha(&rx, 6, seq);
    memcpy(g_snap, g_buf, total);
    {
        const uint8_t *pp; size_t pnn;
        enum zssh_error e = zssh_pkt_open(&rx, g_buf, total, &pp, &pnn);
        CHECK(e == ZSSH_E_PROTOCOL || e == ZSSH_E_TOO_LARGE || e == ZSSH_E_MAC);
        CHECK(memcmp(g_buf, g_snap, total) == 0 && rx.seq == seq);
    }
    /* total argument disagreeing with the declared length */
    total = make_sealed(5, seq, n);
    dir_chacha(&rx, 5, seq);
    expect_refused(&rx, total - 8, ZSSH_E_PROTOCOL);
    expect_refused(&rx, 3, ZSSH_E_PROTOCOL);
    group_end("tamper controls (tag/length/payload/seq)");
}

/* A correctly authenticated packet carrying bad padding is refused. */
static void test_bad_padding(void)
{
    group_begin();
    uint8_t key[64], pay[40], out[400];
    fill_key(key, 0x55);
    /* build with kat_build then patch: easier to build by hand w/ chosen padlen */
    for (int variant = 0; variant < 3; variant++) {
        const size_t plen = 16;               /* padlen + payload + padding */
        uint8_t body[16], nonce[12] = {0}, ks[64], pk[32];
        memset(body, 0xee, sizeof body);
        body[0] = variant == 0 ? 3 : variant == 1 ? 15 : 16;   /* <4, no payload, overruns */
        zssh_put_u32(nonce + 8, 12);
        chacha20_block(key, 1, nonce, ks);
        for (size_t i = 0; i < plen; i++) out[4 + i] = body[i] ^ ks[i];
        chacha20_block(key + 32, 0, nonce, ks);
        uint8_t lenb[4];
        zssh_put_u32(lenb, (uint32_t)plen);
        for (int i = 0; i < 4; i++) out[i] = lenb[i] ^ ks[i];
        chacha20_block(key, 0, nonce, ks);
        memcpy(pk, ks, 32);
        poly1305_mac(out, 4 + plen, pk, out + 4 + plen);
        struct zssh_pkt_dir rx;
        zssh_pkt_dir_init(&rx);
        CHECK(zssh_pkt_set_cipher(&rx, ZSSH_CIPHER_CHACHA20_POLY1305, key, true) == ZSSH_E_NONE);
        rx.seq = 12;
        memcpy(g_buf, out, 4 + plen + 16);
        const uint8_t *p = (const uint8_t *)1; size_t pn = 9;
        CHECK(zssh_pkt_open(&rx, g_buf, 4 + plen + 16, &p, &pn) == ZSSH_E_PROTOCOL);
        CHECK(p == nullptr && pn == 0 && rx.seq == 12);
        /* the decrypted (authentic) plaintext must not be left in the buffer:
         * the whole packet region is wiped after the padding refusal */
        bool wiped = true;
        for (size_t i = 0; i < 4 + plen + 16; i++) wiped = wiped && g_buf[i] == 0;
        CHECK(wiped);
    }
    (void)pay;
    group_end("authentic packet with bad padding refused");
}

static void test_none_cipher(void)
{
    group_begin();
    /* NEWKEYS-sized packet: payload {21}; pad bytes as given. total must be 16. */
    struct zssh_pkt_dir tx, rx;
    zssh_pkt_dir_init(&tx); zssh_pkt_dir_init(&rx);
    uint8_t pad[ZSSH_PAD_RANDOM_MAX];
    make_pad(pad);
    size_t total = 0;
    g_buf[ZSSH_PKT_HDR] = 21;
    CHECK(zssh_pkt_seal(&tx, g_buf, sizeof g_buf, 1, pad, &total) == ZSSH_E_NONE);
    static const uint8_t want[16] = { 0, 0, 0, 12, 10, 21, 0xa0, 0xa1, 0xa2, 0xa3,
                                      0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9 };
    CHECK(total == 16 && memcmp(g_buf, want, 16) == 0);
    size_t t2 = 0;
    CHECK(zssh_pkt_peek_total(&rx, g_buf, &t2) == ZSSH_E_NONE && t2 == 16);
    const uint8_t *p; size_t pn;
    CHECK(zssh_pkt_open(&rx, g_buf, total, &p, &pn) == ZSSH_E_NONE && pn == 1 && p[0] == 21);
    /* bad lengths for NONE: not 4 mod 8, too short, too large */
    uint8_t f[4];
    size_t t3 = 9;
    zssh_put_u32(f, 16);
    CHECK(zssh_pkt_peek_total(&rx, f, &t3) == ZSSH_E_PROTOCOL && t3 == 0);
    zssh_put_u32(f, 4);
    CHECK(zssh_pkt_peek_total(&rx, f, &t3) == ZSSH_E_PROTOCOL && t3 == 0);
    zssh_put_u32(f, ZSSH_MIN_PACKET_LENGTH_NONE - 4);     /* 8: below the NONE minimum */
    CHECK(zssh_pkt_peek_total(&rx, f, &t3) == ZSSH_E_PROTOCOL && t3 == 0);
    zssh_put_u32(f, 0);
    CHECK(zssh_pkt_peek_total(&rx, f, &t3) == ZSSH_E_PROTOCOL && t3 == 0);
    zssh_put_u32(f, ZSSH_MIN_PACKET_LENGTH_NONE);         /* 12: accepted */
    CHECK(zssh_pkt_peek_total(&rx, f, &t3) == ZSSH_E_NONE && t3 == 16);
    zssh_put_u32(f, ZSSH_MAX_PACKET + 1);
    CHECK(zssh_pkt_peek_total(&rx, f, &t3) == ZSSH_E_TOO_LARGE && t3 == 0);
    zssh_put_u32(f, 0xffffffffu);
    CHECK(zssh_pkt_peek_total(&rx, f, &t3) == ZSSH_E_TOO_LARGE);
    /* bad padding under none: padding_length 3 */
    uint8_t bad[16];
    memcpy(bad, want, 16); bad[4] = 3;
    rx.seq = 0;
    memcpy(g_buf, bad, 16);
    CHECK(zssh_pkt_open(&rx, g_buf, 16, &p, &pn) == ZSSH_E_PROTOCOL && rx.seq == 0);
    {
        bool wiped = true;
        for (size_t i = 0; i < 16; i++) wiped = wiped && g_buf[i] == 0;
        CHECK(wiped);
    }
    group_end("none cipher framing");
}

/* ---- (5) oversize length refused before the body is needed ------------- */
static void test_oversize(void)
{
    group_begin();
    struct zssh_pkt_dir rx;
    uint8_t key[64], nonce[12], ks[64], f[4], lens[2][4];
    fill_key(key, 0x66);
    dir_chacha(&rx, 0x66, 17);
    zssh_chacha_nonce(nonce, 17);
    chacha20_block(key + 32, 0, nonce, ks);
    static const uint32_t bad[] = { ZSSH_MAX_PACKET + 1, 0x80000000u, 0xffffffffu,
                                    ZSSH_MAX_PACKET + 8 };
    size_t total = 5;
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        zssh_put_u32(f, bad[i]);
        for (int k = 0; k < 4; k++) f[k] ^= ks[k];
        total = 5;
        CHECK(zssh_pkt_peek_total(&rx, f, &total) == ZSSH_E_TOO_LARGE && total == 0);
    }
    /* just-valid maximum is accepted: control */
    zssh_put_u32(f, ZSSH_MAX_PACKET);
    for (int k = 0; k < 4; k++) f[k] ^= ks[k];
    CHECK(zssh_pkt_peek_total(&rx, f, &total) == ZSSH_E_NONE &&
          total == 4 + ZSSH_MAX_PACKET + 16);
    /* below the minimum / misaligned */
    static const uint32_t proto[] = { 0, 1, 4, 7, 9, 15 };
    for (size_t i = 0; i < sizeof proto / sizeof proto[0]; i++) {
        zssh_put_u32(f, proto[i]);
        for (int k = 0; k < 4; k++) f[k] ^= ks[k];
        CHECK(zssh_pkt_peek_total(&rx, f, &total) == ZSSH_E_PROTOCOL && total == 0);
    }
    zssh_put_u32(f, 8);                        /* smallest valid: NEWKEYS-sized */
    for (int k = 0; k < 4; k++) f[k] ^= ks[k];
    CHECK(zssh_pkt_peek_total(&rx, f, &total) == ZSSH_E_NONE && total == 28);
    /* peek does not modify its input and does not advance seq */
    memcpy(lens[0], f, 4);
    (void)zssh_pkt_peek_total(&rx, f, &total);
    memcpy(lens[1], f, 4);
    CHECK(memcmp(lens[0], lens[1], 4) == 0 && rx.seq == 17);
    CHECK(zssh_pkt_need_len() == 4);
    /* open with the 4 bytes of an oversize packet and nothing else */
    const uint8_t *p; size_t pn;
    zssh_put_u32(f, ZSSH_MAX_PACKET + 8);
    for (int k = 0; k < 4; k++) f[k] ^= ks[k];
    memcpy(g_buf, f, 4);
    CHECK(zssh_pkt_open(&rx, g_buf, 4, &p, &pn) == ZSSH_E_TOO_LARGE && p == nullptr);
    group_end("oversize/short length refused up front");
}

/* ---- (6) one byte at a time -------------------------------------------- */
static const size_t incr_sizes[] = { 1, 20, 3, 100, 61 };

/* Seal the five payloads back to back into wire[]; exp_total[] gets the exact
 * wire size of each packet, from the sealed totals of a second sender. */
static size_t incr_seal(struct zssh_pkt_dir *tx, bool chacha, uint8_t *wire,
                        size_t exp_total[5])
{
    size_t wl = 0;
    for (size_t i = 0; i < 5; i++) {
        size_t total = 0;
        CHECK(seal_payload(tx, incr_sizes[i], &total) == ZSSH_E_NONE);
        memcpy(wire + wl, g_buf, total);
        wl += total;
    }
    struct zssh_pkt_dir t2;
    if (chacha) dir_chacha(&t2, 0x77, 0); else zssh_pkt_dir_init(&t2);
    for (size_t i = 0; i < 5; i++)
        CHECK(seal_payload(&t2, incr_sizes[i], &exp_total[i]) == ZSSH_E_NONE);
    return wl;
}

/* Feed the wire one byte at a time and check every packet comes out whole. */
static void incr_feed(struct zssh_pkt_dir *rx, const uint8_t *wire, size_t wl,
                      uint8_t *rxb, const size_t exp_total[5])
{
    size_t have = 0, got = 0, need = 0, consumed = 0;
    CHECK(zssh_pkt_need_len() == 4);
    for (size_t i = 0; i < wl; i++) {
        rxb[have++] = wire[i];
        if (need == 0 && have >= zssh_pkt_need_len()) {
            CHECK(zssh_pkt_peek_total(rx, rxb, &need) == ZSSH_E_NONE);
            /* the API reports exactly the packet's wire size, at the
             * first byte where it can (the 4th) and not before */
            CHECK(have == zssh_pkt_need_len() && need == exp_total[got]);
        }
        if (need == 0) CHECK(have < zssh_pkt_need_len());
        if (need != 0) CHECK(have <= need);
        if (need != 0 && have == need) {
            const uint8_t *p; size_t pn;
            CHECK(zssh_pkt_open(rx, rxb, need, &p, &pn) == ZSSH_E_NONE);
            fill_payload(g_pay, pn);
            CHECK(pn == incr_sizes[got] && memcmp(p, g_pay, pn) == 0);
            consumed += need;
            CHECK(rx->seq == got + 1 && rx->bytes == consumed);
            got++; have = 0; need = 0;
        }
    }
    CHECK(got == 5 && have == 0 && rx->seq == 5 && consumed == wl);
}

static void test_incremental(void)
{
    group_begin();
    for (int chacha = 0; chacha < 2; chacha++) {
        static uint8_t wire[4096], rxb[4096];
        size_t wl = 0;
        struct zssh_pkt_dir tx, rx;
        if (chacha) { dir_chacha(&tx, 0x77, 0); dir_chacha(&rx, 0x77, 0); }
        else { zssh_pkt_dir_init(&tx); zssh_pkt_dir_init(&rx); }
        size_t exp_total[5];
        wl = incr_seal(&tx, chacha, wire, exp_total);
        incr_feed(&rx, wire, wl, rxb, exp_total);
    }
    group_end("byte-at-a-time arrival");
}

/* ---- limits, set_cipher, strict ---------------------------------------- */
static void limits_set_cipher(void);

static void test_limits_and_keys(void)
{
    group_begin();
    struct zssh_pkt_dir d;
    size_t total = 3;
    /* seq at the session packet limit: seal and open refuse */
    dir_chacha(&d, 9, ZSSH_MAX_SESSION_PACKETS - 1);
    CHECK(seal_payload(&d, 10, &total) == ZSSH_E_NONE && d.seq == ZSSH_MAX_SESSION_PACKETS);
    CHECK(seal_payload(&d, 10, &total) == ZSSH_E_REKEY_LIMIT && total == 0 &&
          d.seq == ZSSH_MAX_SESSION_PACKETS);
    struct zssh_pkt_dir rx;
    size_t t = make_sealed(9, ZSSH_MAX_SESSION_PACKETS - 1, 10);
    dir_chacha(&rx, 9, ZSSH_MAX_SESSION_PACKETS - 1);
    const uint8_t *p; size_t pn;
    CHECK(zssh_pkt_open(&rx, g_buf, t, &p, &pn) == ZSSH_E_NONE);
    t = make_sealed(9, ZSSH_MAX_SESSION_PACKETS - 1, 10);
    dir_chacha(&rx, 9, ZSSH_MAX_SESSION_PACKETS);
    expect_refused(&rx, t, ZSSH_E_REKEY_LIMIT);
    /* byte limit */
    dir_chacha(&d, 9, 0);
    d.bytes = ZSSH_MAX_SESSION_BYTES - 10;
    CHECK(seal_payload(&d, 10, &total) == ZSSH_E_REKEY_LIMIT && d.seq == 0);
    /* seal boundary: payload 10 -> 1+10+5 = 16, wire 4+16+16 = 36; reaching
     * the limit exactly is allowed, one byte over is refused */
    dir_chacha(&d, 9, 0);
    d.bytes = ZSSH_MAX_SESSION_BYTES - 36;
    CHECK(seal_payload(&d, 10, &total) == ZSSH_E_NONE && total == 36 &&
          d.bytes == ZSSH_MAX_SESSION_BYTES);
    dir_chacha(&d, 9, 0);
    d.bytes = ZSSH_MAX_SESSION_BYTES - 35;
    CHECK(seal_payload(&d, 10, &total) == ZSSH_E_REKEY_LIMIT && d.seq == 0 &&
          d.bytes == ZSSH_MAX_SESSION_BYTES - 35);
    /* open-side byte limit: same boundary, and a refusal leaves the packet,
     * counters and sequence number untouched */
    t = make_sealed(9, 7, 10);
    CHECK(t == 36);
    dir_chacha(&rx, 9, 7);
    rx.bytes = ZSSH_MAX_SESSION_BYTES - t + 1;
    expect_refused(&rx, t, ZSSH_E_REKEY_LIMIT);
    dir_chacha(&rx, 9, 7);
    rx.bytes = ZSSH_MAX_SESSION_BYTES - t;
    CHECK(zssh_pkt_open(&rx, g_buf, t, &p, &pn) == ZSSH_E_NONE && pn == 10 &&
          rx.bytes == ZSSH_MAX_SESSION_BYTES && rx.seq == 8);
    limits_set_cipher();
    group_end("limits, set_cipher, strict reset");
}

/* set_cipher: strict resets seq, non-strict keeps it; counters reset */
static void limits_set_cipher(void)
{
    struct zssh_pkt_dir d;
    uint8_t key[64];
    fill_key(key, 1);
    dir_chacha(&d, 9, 50);
    d.packets = 50; d.bytes = 999;
    CHECK(zssh_pkt_set_cipher(&d, ZSSH_CIPHER_CHACHA20_POLY1305, key, false) == ZSSH_E_NONE);
    CHECK(d.seq == 50 && d.packets == 0 && d.bytes == 0 && memcmp(d.key, key, 64) == 0);
    CHECK(zssh_pkt_set_cipher(&d, ZSSH_CIPHER_CHACHA20_POLY1305, key, true) == ZSSH_E_NONE);
    CHECK(d.seq == 0);
    CHECK(zssh_pkt_set_cipher(&d, ZSSH_CIPHER_CHACHA20_POLY1305, nullptr, true) == ZSSH_E_INTERNAL);
    CHECK(zssh_pkt_set_cipher(&d, (enum zssh_cipher_kind)7, key, true) == ZSSH_E_INTERNAL);
    /* NONE ignores the key: NULL accepted, and a non-NULL key is not stored */
    uint8_t zero[64] = {0};
    CHECK(zssh_pkt_set_cipher(&d, ZSSH_CIPHER_NONE, nullptr, true) == ZSSH_E_NONE &&
          d.kind == ZSSH_CIPHER_NONE && memcmp(d.key, zero, 64) == 0);
    dir_chacha(&d, 9, 3);
    CHECK(zssh_pkt_set_cipher(&d, ZSSH_CIPHER_NONE, key, false) == ZSSH_E_NONE &&
          d.kind == ZSSH_CIPHER_NONE && memcmp(d.key, zero, 64) == 0 && d.seq == 3);
    zssh_pkt_dir_init(&d);
    CHECK(d.kind == ZSSH_CIPHER_NONE && d.seq == 0 && memcmp(d.key, zero, 64) == 0);
    dir_chacha(&d, 9, 5);
    zssh_pkt_dir_init(&d);
    CHECK(memcmp(d.key, zero, 64) == 0);
}

/* ---- wire helpers ------------------------------------------------------- */
static void wire_check_u32_u64(uint8_t *b)
{
    CHECK(zssh_get_u32((const uint8_t[]){1, 2, 3, 4}) == 0x01020304u);
    zssh_put_u32(b, 0xdeadbeefu);
    CHECK(b[0] == 0xde && b[3] == 0xef);
    zssh_put_u64(b, 0x0102030405060708ull);
    CHECK(b[0] == 1 && b[7] == 8);
    CHECK(zssh_ct_eq(b, b, 8) && zssh_ct_eq(nullptr, nullptr, 0));
}

static void wire_check_ct_eq_pairs(void)
{
    uint8_t x[32], y[32];
    for (int i = 0; i < 32; i++) x[i] = y[i] = (uint8_t)(i * 5 + 1);
    CHECK(zssh_ct_eq(x, y, 1) && zssh_ct_eq(x, y, 32) && zssh_ct_eq(x, y, 0));
    y[31] ^= 1;
    CHECK(!zssh_ct_eq(x, y, 32) && zssh_ct_eq(x, y, 31));
    y[31] ^= 1; y[0] ^= 0x80;
    CHECK(!zssh_ct_eq(x, y, 1) && !zssh_ct_eq(x, y, 32));
}

static void wire_check_ct_eq_flip(const uint8_t *b)
{
    uint8_t cx[8]; memcpy(cx, b, 8);
    for (int i = 0; i < 8; i++) { cx[i] ^= 0x10; CHECK(!zssh_ct_eq(b, cx, 8)); cx[i] ^= 0x10; }
}

static void wire_check_wr_rd_roundtrip(uint8_t *b, size_t cap)
{
    struct zssh_wr w;
    zssh_wr_init(&w, b, cap);
    zssh_wr_u8(&w, 7); zssh_wr_bool(&w, true); zssh_wr_u32(&w, 0x11223344);
    zssh_wr_cstr(&w, "abc,def");
    zssh_wr_string(&w, (const uint8_t *)"xy", 2);
    CHECK(zssh_wr_ok(&w) && w.off == 1 + 1 + 4 + 4 + 7 + 4 + 2);
    struct zssh_rd r;
    zssh_rd_init(&r, b, w.off);
    CHECK(zssh_rd_u8(&r) == 7 && zssh_rd_bool(&r) && zssh_rd_u32(&r) == 0x11223344);
    const uint8_t *s; size_t n;
    zssh_rd_string(&r, &s, &n);
    CHECK(n == 7 && memcmp(s, "abc,def", 7) == 0);
    zssh_rd_string(&r, &s, &n);
    CHECK(n == 2 && zssh_rd_done(&r) && zssh_rd_left(&r) == 0);
    (void)zssh_rd_u8(&r);
    CHECK(!zssh_rd_ok(&r) && zssh_rd_u32(&r) == 0);
}

static void wire_check_rd_overrun(void)
{
    struct zssh_rd r;
    const uint8_t *s; size_t n;
    /* string longer than the input: sticky error */
    uint8_t lie[8] = {0, 0, 0, 100, 1, 2, 3, 4};
    zssh_rd_init(&r, lie, 8);
    zssh_rd_string(&r, &s, &n);
    CHECK(!zssh_rd_ok(&r) && s == nullptr && n == 0);
    uint8_t huge[8] = {0xff, 0xff, 0xff, 0xff};
    zssh_rd_init(&r, huge, 8);
    zssh_rd_string(&r, &s, &n);
    CHECK(!zssh_rd_ok(&r));
    zssh_rd_init(&r, nullptr, 0);
    CHECK(zssh_rd_ok(&r) && zssh_rd_done(&r));
    zssh_rd_bytes(&r, &s, 0);
    CHECK(zssh_rd_ok(&r) && zssh_rd_done(&r) && zssh_rd_left(&r) == 0);
    zssh_rd_bytes(&r, &s, 1);
    CHECK(!zssh_rd_ok(&r));
}

static void wire_check_rd_edge_end(void)
{
    struct zssh_rd r;
    const uint8_t *s;
    /* non-NULL buffer read to its end (offset == len), then a zero-byte read */
    uint8_t edge[2] = {1, 2};
    zssh_rd_init(&r, edge, 2);
    zssh_rd_bytes(&r, &s, 2);
    zssh_rd_bytes(&r, &s, 0);
    CHECK(zssh_rd_ok(&r) && zssh_rd_done(&r) && zssh_rd_left(&r) == 0);
}

static void wire_check_wr_overflow(void)
{
    struct zssh_wr w;
    /* writer overflow: nothing written past the cap, sticky */
    uint8_t small[5] = {0};
    zssh_wr_init(&w, small, 5);
    zssh_wr_u32(&w, 1);
    zssh_wr_u32(&w, 2);
    CHECK(!zssh_wr_ok(&w) && w.off == 4);
    zssh_wr_u8(&w, 9);
    CHECK(!zssh_wr_ok(&w) && small[4] == 0);
}

static void wire_check_mpint(void)
{
    struct zssh_wr w;
    /* mpint (RFC 4251 5 examples) */
    static const struct { uint8_t in[4]; size_t n; uint8_t out[8]; size_t on; } mp[] = {
        { {0}, 0, {0, 0, 0, 0}, 4 },
        { {0, 0}, 2, {0, 0, 0, 0}, 4 },
        { {0x7f}, 1, {0, 0, 0, 1, 0x7f}, 5 },
        { {0x80}, 1, {0, 0, 0, 2, 0, 0x80}, 6 },
        { {0, 0, 0x80, 1}, 4, {0, 0, 0, 3, 0, 0x80, 1}, 7 },
        { {0x09, 0xa3, 0x78, 0xf9}, 4, {0, 0, 0, 4, 9, 0xa3, 0x78, 0xf9}, 8 },
    };
    for (size_t i = 0; i < sizeof mp / sizeof mp[0]; i++) {
        uint8_t o[16];
        zssh_wr_init(&w, o, sizeof o);
        zssh_wr_mpint(&w, mp[i].in, mp[i].n);
        CHECK(zssh_wr_ok(&w) && w.off == mp[i].on && memcmp(o, mp[i].out, mp[i].on) == 0);
    }
}

static void wire_check_null_fail_closed(void)
{
    struct zssh_wr w;
    /* NULL with n > 0 fails closed: sticky, nothing written, no dereference */
    {
        uint8_t o[16];
        memset(o, 0xcc, sizeof o);
        zssh_wr_init(&w, o, sizeof o);
        zssh_wr_bytes(&w, nullptr, 3);
        CHECK(!zssh_wr_ok(&w) && w.off == 0 && o[0] == 0xcc);
        zssh_wr_init(&w, o, sizeof o);
        zssh_wr_string(&w, nullptr, 3);
        CHECK(!zssh_wr_ok(&w) && w.off == 0 && o[0] == 0xcc);
        zssh_wr_init(&w, o, sizeof o);
        zssh_wr_mpint(&w, nullptr, 3);
        CHECK(!zssh_wr_ok(&w) && w.off == 0 && o[0] == 0xcc);
        /* controls: NULL with n == 0 is the empty value, not an error */
        zssh_wr_init(&w, o, sizeof o);
        zssh_wr_string(&w, nullptr, 0);
        zssh_wr_mpint(&w, nullptr, 0);
        CHECK(zssh_wr_ok(&w) && w.off == 8);
    }
}

static void wire_check_namelist(void)
{
    const uint8_t *s; size_t n;
    /* name-lists */
    const char *cl = "a,bb,ccc", *sv = "zz,ccc,bb";
    struct zssh_namelist c = { (const uint8_t *)cl, strlen(cl) };
    struct zssh_namelist sl = { (const uint8_t *)sv, strlen(sv) };
    CHECK(zssh_namelist_has(c, "a") && zssh_namelist_has(c, "bb") &&
          zssh_namelist_has(c, "ccc") && !zssh_namelist_has(c, "b") &&
          !zssh_namelist_has(c, "") && !zssh_namelist_has(c, "cccc") &&
          !zssh_namelist_has(c, "aa"));
    int idx = zssh_namelist_pick(c, sl, &s, &n);
    CHECK(idx == 1 && n == 2 && memcmp(s, "bb", 2) == 0);   /* client order wins */
    struct zssh_namelist none = { (const uint8_t *)"q", 1 };
    CHECK(zssh_namelist_pick(c, none, &s, &n) == -1 && s == nullptr && n == 0);
    struct zssh_namelist empty = { nullptr, 0 };
    CHECK(zssh_namelist_pick(empty, sl, &s, &n) == -1 && !zssh_namelist_has(empty, "a"));
}

static void test_wire(void)
{
    group_begin();
    uint8_t b[64];
    wire_check_u32_u64(b);
    wire_check_ct_eq_pairs();
    wire_check_ct_eq_flip(b);
    wire_check_wr_rd_roundtrip(b, sizeof b);
    wire_check_rd_overrun();
    wire_check_rd_edge_end();
    wire_check_wr_overflow();
    wire_check_mpint();
    wire_check_null_fail_closed();
    wire_check_namelist();
    group_end("wire helpers (rd/wr/mpint/namelist/ct)");
}

/* ---- txq ---------------------------------------------------------------- */
static struct zssh_txq g_q;

static void txq_check_reserve_commit(struct zssh_txq *q)
{
    zssh_txq_init(q);
    CHECK(zssh_txq_pending(q) == 0 && zssh_txq_room(q) == ZSSH_TXQ_SIZE);
    uint8_t *w = zssh_txq_reserve(q, 100);
    CHECK(w != nullptr);
    memset(w, 0x5a, 100);
    const uint8_t *pk; size_t pn;
    zssh_txq_peek(q, &pk, &pn);
    CHECK(pn == 0);                              /* reservation not visible */
    /* commit overrun: more than the reservation is refused and changes nothing */
    CHECK(!zssh_txq_commit(q, 101));
    CHECK(q->head == 0 && q->tail == 0 && q->reserved == 100);
    zssh_txq_peek(q, &pk, &pn);
    CHECK(pn == 0);
    CHECK(zssh_txq_commit(q, 60));
    zssh_txq_peek(q, &pk, &pn);
    CHECK(pn == 60 && pk[0] == 0x5a && q->reserved == 0);
    /* the reservation is spent: a second commit (no open reservation) fails */
    CHECK(!zssh_txq_commit(q, 1) && zssh_txq_pending(q) == 60);
    CHECK(zssh_txq_commit(q, 0) && zssh_txq_pending(q) == 60);
    /* a failed reserve leaves no reservation behind */
    CHECK(zssh_txq_reserve(q, ZSSH_TXQ_SIZE) == nullptr);
    CHECK(!zssh_txq_commit(q, 1) && zssh_txq_pending(q) == 60);
    /* a new reserve replaces the open one: the old size no longer applies */
    CHECK(zssh_txq_reserve(q, 50) != nullptr && zssh_txq_reserve(q, 10) != nullptr);
    CHECK(!zssh_txq_commit(q, 11) && zssh_txq_commit(q, 10) && zssh_txq_pending(q) == 70);
    CHECK(zssh_txq_consume(q, 10) && zssh_txq_pending(q) == 60);
}

static void txq_check_null_drain(struct zssh_txq *q)
{
    /* NULL with n > 0 fails closed and leaves the queue untouched */
    CHECK(!zssh_txq_append(q, nullptr, 5) && zssh_txq_pending(q) == 60 && q->reserved == 0);
    CHECK(zssh_txq_append(q, nullptr, 0) && zssh_txq_pending(q) == 60);
    CHECK(!zssh_txq_consume(q, 61) && zssh_txq_pending(q) == 60);
    CHECK(zssh_txq_consume(q, 10) && zssh_txq_pending(q) == 50);
    CHECK(zssh_txq_consume(q, 50) && q->head == 0 && q->tail == 0);
}

static void txq_check_fill_brim(struct zssh_txq *q)
{
    /* fill to the brim, nothing more fits */
    CHECK(zssh_txq_reserve(q, ZSSH_TXQ_SIZE + 1) == nullptr);
    uint8_t *all = zssh_txq_reserve(q, ZSSH_TXQ_SIZE);
    CHECK(all != nullptr);
    for (size_t i = 0; i < ZSSH_TXQ_SIZE; i++) all[i] = (uint8_t)i;
    CHECK(!zssh_txq_commit(q, ZSSH_TXQ_SIZE + 1) && q->tail == 0);
    CHECK(zssh_txq_commit(q, ZSSH_TXQ_SIZE));
    CHECK(zssh_txq_room(q) == 0 && zssh_txq_reserve(q, 1) == nullptr);
    uint8_t one = 1;
    CHECK(!zssh_txq_append(q, &one, 1));
}

static void txq_check_compact(struct zssh_txq *q, uint8_t *tail)
{
    const uint8_t *pk; size_t pn;
    /* partial consume then compaction keeps order and content */
    CHECK(zssh_txq_consume(q, 1000));
    CHECK(zssh_txq_room(q) == 1000);
    for (int i = 0; i < 1000; i++) tail[i] = (uint8_t)(i ^ 0x33);
    CHECK(zssh_txq_append(q, tail, 1000));       /* forces memmove */
    CHECK(q->head == 0 && zssh_txq_pending(q) == ZSSH_TXQ_SIZE);
    zssh_txq_peek(q, &pk, &pn);
    bool ok = pn == ZSSH_TXQ_SIZE;
    for (size_t i = 0; ok && i < ZSSH_TXQ_SIZE - 1000; i++)
        ok = pk[i] == (uint8_t)(i + 1000);
    CHECK(ok && memcmp(pk + ZSSH_TXQ_SIZE - 1000, tail, 1000) == 0);
    CHECK(zssh_txq_consume(q, ZSSH_TXQ_SIZE) && zssh_txq_pending(q) == 0);
    zssh_txq_peek(q, &pk, &pn);
    CHECK(pn == 0);                              /* drained queue peeks empty */
}

static void txq_check_relocate(struct zssh_txq *q, const uint8_t *tail)
{
    /* emptying the queue relocates the tail, so it drops an open reservation */
    CHECK(zssh_txq_append(q, tail, 10));
    CHECK(zssh_txq_reserve(q, 20) != nullptr && q->reserved == 20);
    CHECK(zssh_txq_consume(q, 10) && q->reserved == 0 && !zssh_txq_commit(q, 1));
}

static void test_txq(void)
{
    group_begin();
    struct zssh_txq *q = &g_q;
    uint8_t tail[1000];
    txq_check_reserve_commit(q);
    txq_check_null_drain(q);
    txq_check_fill_brim(q);
    txq_check_compact(q, tail);
    txq_check_relocate(q, tail);
    group_end("bounded output queue");
}

int main(void)
{
    test_chacha_equivalence();
    test_poly_sanity();
    test_roundtrip();
    test_known_answer();
    test_tamper();
    test_bad_padding();
    test_none_cipher();
    test_oversize();
    test_incremental();
    test_limits_and_keys();
    test_wire();
    test_txq();
    printf("zssh_packet: %s (%d failed checks)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
