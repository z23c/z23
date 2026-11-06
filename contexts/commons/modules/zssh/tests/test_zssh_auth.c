/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zssh_auth — layer (c): ssh-ed25519 blobs/signatures and publickey
 * userauth. Known answers are written out by hand from RFC 8032 7.1 (test
 * vectors 1 and 2), RFC 8709 4/6 and RFC 4252 7, never from the code under
 * test. The wire helpers (zssh_rd_*, zssh_wr_*, zssh_ct_eq) are minimal local
 * test doubles of the contract in zssh_internal.h so this file does not
 * depend on another layer's implementation. */

#include "zssh_internal.h"

#include "base/serialize_le.h"

#include <stdio.h>
#include <string.h>

/* ---- test doubles for the wire helpers (contract: zssh_internal.h W) ---- */
uint32_t zssh_get_u32(const uint8_t p[4])
{ return zcl_read_u32_be(p); }
void zssh_put_u32(uint8_t p[4], uint32_t v)
{ zcl_write_u32_be(p, v); }
bool zssh_ct_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}
void zssh_rd_init(struct zssh_rd *r, const uint8_t *p, size_t len)
{ r->p = p; r->len = len; r->off = 0; r->bad = false; }
static bool rd_need(struct zssh_rd *r, size_t n)
{
    if (r->bad || n > r->len - r->off) { r->bad = true; return false; }
    return true;
}
uint8_t zssh_rd_u8(struct zssh_rd *r)
{ if (!rd_need(r, 1)) return 0; return r->p[r->off++]; }
bool zssh_rd_bool(struct zssh_rd *r) { return zssh_rd_u8(r) != 0; }
uint32_t zssh_rd_u32(struct zssh_rd *r)
{
    uint32_t v;
    if (!rd_need(r, 4)) return 0;
    v = zssh_get_u32(r->p + r->off); r->off += 4; return v;
}
void zssh_rd_bytes(struct zssh_rd *r, const uint8_t **s, size_t n)
{
    if (!rd_need(r, n)) { *s = NULL; return; }
    *s = r->p + r->off; r->off += n;
}
void zssh_rd_string(struct zssh_rd *r, const uint8_t **s, size_t *n)
{
    uint32_t l = zssh_rd_u32(r);
    *s = NULL; *n = 0;
    if (r->bad || l > ZSSH_MAX_PACKET) { r->bad = true; return; }
    zssh_rd_bytes(r, s, l);
    if (!r->bad) *n = l;
}
size_t zssh_rd_left(const struct zssh_rd *r) { return r->len - r->off; }
bool zssh_rd_ok(const struct zssh_rd *r) { return !r->bad; }
bool zssh_rd_done(const struct zssh_rd *r) { return !r->bad && r->off == r->len; }
void zssh_wr_init(struct zssh_wr *w, uint8_t *p, size_t cap)
{ w->p = p; w->cap = cap; w->off = 0; w->bad = false; }
void zssh_wr_bytes(struct zssh_wr *w, const uint8_t *b, size_t n)
{
    if (w->bad || n > w->cap - w->off) { w->bad = true; return; }
    if (n) memcpy(w->p + w->off, b, n);
    w->off += n;
}
void zssh_wr_u8(struct zssh_wr *w, uint8_t v) { zssh_wr_bytes(w, &v, 1); }
void zssh_wr_bool(struct zssh_wr *w, bool v) { zssh_wr_u8(w, v ? 1 : 0); }
void zssh_wr_u32(struct zssh_wr *w, uint32_t v)
{ uint8_t t[4]; zssh_put_u32(t, v); zssh_wr_bytes(w, t, 4); }
void zssh_wr_string(struct zssh_wr *w, const uint8_t *b, size_t n)
{ zssh_wr_u32(w, (uint32_t)n); zssh_wr_bytes(w, b, n); }
void zssh_wr_cstr(struct zssh_wr *w, const char *s)
{ zssh_wr_string(w, (const uint8_t *)s, strlen(s)); }
bool zssh_wr_ok(const struct zssh_wr *w) { return !w->bad; }

/* Link stubs for ed25519.c batch-verify / allocation paths (never called).
 * Define ZSSH_AUTH_TEST_REAL_LIBS when linking the real libraries so these
 * do not collide with the real definitions. */
#ifndef ZSSH_AUTH_TEST_REAL_LIBS
bool zcl_random_secret_bytes(uint8_t *out, size_t n) { (void)out; (void)n; return false; }
bool zcl_alloc_fault_should_fail(const char *label) { (void)label; return false; }
void zcl_alloc_note_failure(void) {}
#endif

/* ---- harness ------------------------------------------------------------ */
static int g_fail;
static int g_checks;
#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)
#define CHECK_E(got, want) do { enum zssh_error g_ = (got); g_checks++; \
    if (g_ != (want)) { g_fail++; fprintf(stderr, "FAIL %s:%d: %s = %d, want %d\n", \
    __FILE__, __LINE__, #got, (int)g_, (int)(want)); } } while (0)

/* RFC 8032 7.1 TEST 1 (empty message) */
static const uint8_t SEED1[32] = {
    0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0xc4,
    0x44,0x49,0xc5,0x69,0x7b,0x32,0x69,0x19,0x70,0x3b,0xac,0x03,0x1c,0xae,0x7f,0x60 };
static const uint8_t PK1[32] = {
    0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,
    0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a };
static const uint8_t SIG1[64] = {
    0xe5,0x56,0x43,0x00,0xc3,0x60,0xac,0x72,0x90,0x86,0xe2,0xcc,0x80,0x6e,0x82,0x8a,
    0x84,0x87,0x7f,0x1e,0xb8,0xe5,0xd9,0x74,0xd8,0x73,0xe0,0x65,0x22,0x49,0x01,0x55,
    0x5f,0xb8,0x82,0x15,0x90,0xa3,0x3b,0xac,0xc6,0x1e,0x39,0x70,0x1c,0xf9,0xb4,0x6b,
    0xd2,0x5b,0xf5,0xf0,0x59,0x5b,0xbe,0x24,0x65,0x51,0x41,0x43,0x8e,0x7a,0x10,0x0b };
/* RFC 8032 7.1 TEST 2 (one byte 0x72) */
static const uint8_t SEED2[32] = {
    0x4c,0xcd,0x08,0x9b,0x28,0xff,0x96,0xda,0x9d,0xb6,0xc3,0x46,0xec,0x11,0x4e,0x0f,
    0x5b,0x8a,0x31,0x9f,0x35,0xab,0xa6,0x24,0xda,0x8c,0xf6,0xed,0x4f,0xb8,0xa6,0xfb };
static const uint8_t PK2[32] = {
    0x3d,0x40,0x17,0xc3,0xe8,0x43,0x89,0x5a,0x92,0xb7,0x0a,0xa7,0x4d,0x1b,0x7e,0xbc,
    0x9c,0x98,0x2c,0xcf,0x2e,0xc4,0x96,0x8c,0xc0,0xcd,0x55,0xf1,0x2a,0xf4,0x66,0x0c };
static const uint8_t SIG2[64] = {
    0x92,0xa0,0x09,0xa9,0xf0,0xd4,0xca,0xb8,0x72,0x0e,0x82,0x0b,0x5f,0x64,0x25,0x40,
    0xa2,0xb2,0x7b,0x54,0x16,0x50,0x3f,0x8f,0xb3,0x76,0x22,0x23,0xeb,0xdb,0x69,0xda,
    0x08,0x5a,0xc1,0xe4,0x3e,0x15,0x99,0x6e,0x45,0x8f,0x36,0x13,0xd0,0xf1,0x1d,0x8c,
    0x38,0x7b,0x2e,0xae,0xb4,0x30,0x2a,0xee,0xb0,0x0d,0x29,0x16,0x12,0xbb,0x0c,0x00 };

static void iota(uint8_t *p, size_t n, uint8_t base)
{ for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(base + i); }

/* 1. RFC 8032 vectors through the sign/verify path */
static void test_rfc8032(void)
{
    uint8_t blob[ZSSH_ED25519_SIGBLOB_LEN];
    const uint8_t m2 = 0x72;
    uint8_t bad[ZSSH_ED25519_SIGBLOB_LEN];

    CHECK_E(zssh_auth_sign(SEED1, PK1, NULL, 0, blob), ZSSH_E_NONE);
    CHECK(memcmp(blob, "\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x40", 19) == 0);
    CHECK(memcmp(blob + 19, SIG1, 64) == 0);
    CHECK_E(zssh_auth_verify(PK1, NULL, 0, blob, sizeof blob, true), ZSSH_E_NONE);
    memcpy(bad, blob, sizeof bad); bad[19 + 7] ^= 1;
    CHECK_E(zssh_auth_verify(PK1, NULL, 0, bad, sizeof bad, true), ZSSH_E_HOST_SIG);
    CHECK_E(zssh_auth_verify(PK1, NULL, 0, bad, sizeof bad, false), ZSSH_E_AUTH_REFUSED);
    CHECK_E(zssh_auth_verify(PK2, NULL, 0, blob, sizeof blob, true), ZSSH_E_HOST_SIG);

    CHECK_E(zssh_auth_sign(SEED2, PK2, &m2, 1, blob), ZSSH_E_NONE);
    CHECK(memcmp(blob + 19, SIG2, 64) == 0);
    CHECK_E(zssh_auth_verify(PK2, &m2, 1, blob, sizeof blob, true), ZSSH_E_NONE);
    CHECK_E(zssh_auth_verify(PK2, NULL, 0, blob, sizeof blob, true), ZSSH_E_HOST_SIG);

    /* seed/pk mismatch: refused, out untouched */
    memset(blob, 0xAA, sizeof blob);
    CHECK_E(zssh_auth_sign(SEED1, PK2, NULL, 0, blob), ZSSH_E_INTERNAL);
    for (size_t i = 0; i < sizeof blob; i++) CHECK(blob[i] == 0xAA);
    puts("auth rfc8032: vectors 1+2 signature bytes, verify, tamper, wrong key");
}

/* 2. blob encodings byte-exact (RFC 8709 4, 6) and strict parse */
static void test_blobs(void)
{
    uint8_t blob[ZSSH_ED25519_BLOB_LEN], pk[32], fp[32];
    uint8_t exp[51] = { 0,0,0,11, 's','s','h','-','e','d','2','5','5','1','9',
                        0,0,0,32 };
    uint8_t big[ZSSH_ED25519_BLOB_LEN + 1];

    memcpy(exp + 19, PK1, 32);
    zssh_auth_blob_encode(PK1, blob);
    CHECK(memcmp(blob, exp, 51) == 0);
    CHECK_E(zssh_auth_blob_parse(blob, 51, pk), ZSSH_E_NONE);
    CHECK(memcmp(pk, PK1, 32) == 0);

    for (size_t n = 0; n < 51; n++) {            /* every truncation */
        memset(pk, 0xAA, 32);
        CHECK_E(zssh_auth_blob_parse(blob, n, pk), ZSSH_E_PROTOCOL);
        for (size_t i = 0; i < 32; i++) CHECK(pk[i] == 0);
    }
    memcpy(big, blob, 51); big[51] = 0;          /* trailing byte */
    memset(pk, 0xAA, 32);
    CHECK_E(zssh_auth_blob_parse(big, 52, pk), ZSSH_E_PROTOCOL);
    CHECK(pk[0] == 0);
    memcpy(big, blob, 51); big[10] = 'x';        /* wrong algorithm name */
    CHECK_E(zssh_auth_blob_parse(big, 51, pk), ZSSH_E_PROTOCOL);
    memcpy(big, blob, 51); big[18] = 31;         /* key length 31 */
    CHECK_E(zssh_auth_blob_parse(big, 51, pk), ZSSH_E_PROTOCOL);
    memcpy(big, blob, 51); big[3] = 12;          /* name length 12 */
    CHECK_E(zssh_auth_blob_parse(big, 51, pk), ZSSH_E_PROTOCOL);
    memcpy(big, blob, 51); big[0] = 0x7f;        /* absurd length */
    CHECK_E(zssh_auth_blob_parse(big, 51, pk), ZSSH_E_PROTOCOL);

    /* signature blob shape: truncated and overlong -> PROTOCOL, not a bad sig */
    {
        uint8_t sb[ZSSH_ED25519_SIGBLOB_LEN + 1];
        CHECK_E(zssh_auth_sign(SEED1, PK1, NULL, 0, sb), ZSSH_E_NONE);
        for (size_t n = 0; n < ZSSH_ED25519_SIGBLOB_LEN; n++)
            CHECK_E(zssh_auth_verify(PK1, NULL, 0, sb, n, true), ZSSH_E_PROTOCOL);
        sb[ZSSH_ED25519_SIGBLOB_LEN] = 0;
        CHECK_E(zssh_auth_verify(PK1, NULL, 0, sb, sizeof sb, true), ZSSH_E_PROTOCOL);
        sb[10] = 'x';
        CHECK_E(zssh_auth_verify(PK1, NULL, 0, sb, ZSSH_ED25519_SIGBLOB_LEN, true),
                ZSSH_E_PROTOCOL);
    }
    /* fingerprint = SHA-256 of the blob (independent: sha256 of the 51 bytes) */
    {
        struct sha256_ctx c;
        uint8_t want[32];
        sha256_init(&c); sha256_write(&c, exp, 51); sha256_finalize(&c, want);
        zssh_auth_fingerprint(blob, fp);
        CHECK(memcmp(fp, want, 32) == 0);
    }
    puts("auth blobs: encode byte-exact, strict parse, all truncations, overlong, sig shape");
}

static const char SID_NOTE[] = "session id = 00 01 .. 1f";

/* 3. userauth signed data byte-exact against a hand-built RFC 4252 7 buffer */
static void test_signed_data(void)
{
    uint8_t sid[32], out[ZSSH_AUTH_SIGDATA_MAX], pkblob[51];
    size_t n = 0;
    static const char tail[] =
        "\x00\x00\x00\x0e" "ssh-connection"
        "\x00\x00\x00\x09" "publickey"
        "\x01"
        "\x00\x00\x00\x0b" "ssh-ed25519"
        "\x00\x00\x00\x33";   /* 51 */
    uint8_t exp[256];
    size_t o = 0;

    (void)SID_NOTE;
    iota(sid, 32, 0);
    memcpy(exp + o, "\x00\x00\x00\x20", 4); o += 4;
    memcpy(exp + o, sid, 32); o += 32;
    exp[o++] = 50;
    memcpy(exp + o, "\x00\x00\x00\x05" "alice", 9); o += 9;
    memcpy(exp + o, tail, sizeof tail - 1); o += sizeof tail - 1;
    memcpy(pkblob, "\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20", 19);
    memcpy(pkblob + 19, PK1, 32);
    memcpy(exp + o, pkblob, 51); o += 51;

    CHECK_E(zssh_auth_signed_data(sid, "alice", PK1, out, sizeof out, &n), ZSSH_E_NONE);
    CHECK(n == o);
    CHECK(n == 4 + 32 + 1 + 9 + (4 + 14) + (4 + 9) + 1 + (4 + 11) + 4 + 51);
    CHECK(memcmp(out, exp, o) == 0);

    /* bounds */
    {
        char longuser[ZSSH_MAX_USER + 2];
        memset(longuser, 'u', sizeof longuser); longuser[ZSSH_MAX_USER + 1] = 0;
        CHECK_E(zssh_auth_signed_data(sid, longuser, PK1, out, sizeof out, &n),
                ZSSH_E_TOO_LARGE);
        CHECK(n == 0);
        longuser[ZSSH_MAX_USER] = 0;              /* exactly the maximum fits */
        CHECK_E(zssh_auth_signed_data(sid, longuser, PK1, out, sizeof out, &n),
                ZSSH_E_NONE);
        CHECK(n <= ZSSH_AUTH_SIGDATA_MAX);
        CHECK_E(zssh_auth_signed_data(sid, "alice", PK1, out, 100, &n),
                ZSSH_E_TOO_LARGE);
        CHECK(n == 0);
    }
    puts("auth signed-data: byte-exact vs hand-built RFC 4252 7 buffer, bounds");
}

/* ---- request builder used by the control tests --------------------------- */
struct reqspec {
    const char *user, *service, *method, *alg;
    bool has_sig;
    const uint8_t *key_pk;          /* key placed in the request */
    const uint8_t *sign_seed, *sign_pk; /* who signs */
    const uint8_t *sign_sid;        /* session id inside the signed data */
    const char *sign_user;          /* user inside the signed data */
};
static size_t mk_req(uint8_t *buf, size_t cap, const struct reqspec *s)
{
    struct zssh_wr w;
    uint8_t blob[51], sd[ZSSH_AUTH_SIGDATA_MAX], sig[83];
    size_t n = 0;
    zssh_auth_blob_encode(s->key_pk, blob);
    zssh_wr_init(&w, buf, cap);
    zssh_wr_u8(&w, 50);
    zssh_wr_cstr(&w, s->user); zssh_wr_cstr(&w, s->service);
    zssh_wr_cstr(&w, s->method); zssh_wr_bool(&w, s->has_sig);
    zssh_wr_cstr(&w, s->alg); zssh_wr_string(&w, blob, 51);
    if (s->has_sig) {
        CHECK_E(zssh_auth_signed_data(s->sign_sid, s->sign_user, s->key_pk, sd,
                                      sizeof sd, &n), ZSSH_E_NONE);
        CHECK_E(zssh_auth_sign(s->sign_seed, s->sign_pk, sd, n, sig), ZSSH_E_NONE);
        zssh_wr_string(&w, sig, 83);
    }
    CHECK(zssh_wr_ok(&w));
    return w.off;
}

static enum zssh_error run_check(const struct reqspec *s, const uint8_t *sid,
                                 const char *expect_user, const uint8_t *auth_pk)
{
    uint8_t buf[512];
    struct zssh_auth_request rq;
    size_t n = mk_req(buf, sizeof buf, s);
    enum zssh_error e = zssh_auth_parse_request(buf, n, &rq);
    if (e != ZSSH_E_NONE) return e;
    return zssh_auth_check_request(&rq, sid, expect_user, auth_pk);
}

/* 4a. server-side controls */
static void test_server_controls(void)
{
    uint8_t sid[32], sid2[32];
    struct reqspec ok = { "alice", "ssh-connection", "publickey", "ssh-ed25519",
                          true, PK1, SEED1, PK1, NULL, "alice" };
    struct reqspec s;
    uint8_t buf[512];
    struct zssh_auth_request rq;

    iota(sid, 32, 0); iota(sid2, 32, 1);
    ok.sign_sid = sid;

    CHECK_E(run_check(&ok, sid, "alice", PK1), ZSSH_E_NONE);          /* positive */
    /* fail closed: no configured user means nobody authenticates */
    CHECK_E(run_check(&ok, sid, NULL, PK1), ZSSH_E_AUTH_REFUSED);
    CHECK_E(run_check(&ok, sid, "", PK1), ZSSH_E_AUTH_REFUSED);
    s = ok; s.user = ""; s.sign_user = "";                            /* empty == empty still refused */
    CHECK_E(run_check(&s, sid, "", PK1), ZSSH_E_AUTH_REFUSED);
    CHECK_E(run_check(&s, sid, NULL, PK1), ZSSH_E_AUTH_REFUSED);
    s = ok; s.user = "alic"; s.sign_user = "alic";                    /* strict prefix of expected */
    CHECK_E(run_check(&s, sid, "alice", PK1), ZSSH_E_AUTH_REFUSED);
    s = ok; s.user = "alicex"; s.sign_user = "alicex";                /* expected is a prefix of user */
    CHECK_E(run_check(&s, sid, "alice", PK1), ZSSH_E_AUTH_REFUSED);
    s = ok; s.user = "alice"; s.sign_user = "alice";
    CHECK_E(run_check(&s, sid, "alic", PK1), ZSSH_E_AUTH_REFUSED);
    s = ok; s.user = "ALICE"; s.sign_user = "ALICE";                  /* case matters */
    CHECK_E(run_check(&s, sid, "alice", PK1), ZSSH_E_AUTH_REFUSED);
    CHECK_E(zssh_auth_check_request(NULL, sid, "alice", PK1), ZSSH_E_INTERNAL);

    s = ok; s.alg = "ssh-rsa";                                        /* alg name */
    CHECK_E(run_check(&s, sid, "alice", PK1), ZSSH_E_AUTH_REFUSED);
    s = ok; s.user = "mallory"; s.sign_user = "mallory";              /* wrong user */
    CHECK_E(run_check(&s, sid, "alice", PK1), ZSSH_E_AUTH_REFUSED);
    s = ok; s.sign_user = "bob";                                      /* sig over other user */
    CHECK_E(run_check(&s, sid, "alice", PK1), ZSSH_E_AUTH_REFUSED);
    s = ok; s.service = "ssh-userauth";                               /* wrong service */
    CHECK_E(run_check(&s, sid, "alice", PK1), ZSSH_E_AUTH_REFUSED);
    s = ok; s.key_pk = PK2; s.sign_seed = SEED2; s.sign_pk = PK2;     /* unauthorized key */
    CHECK_E(run_check(&s, sid, "alice", PK1), ZSSH_E_AUTH_REFUSED);
    s = ok; s.sign_sid = sid2;                                        /* other session id */
    CHECK_E(run_check(&s, sid, "alice", PK1), ZSSH_E_AUTH_REFUSED);
    s = ok; s.key_pk = PK1; s.sign_seed = SEED2; s.sign_pk = PK2;     /* sig by a different key */
    CHECK_E(run_check(&s, sid, "alice", PK1), ZSSH_E_AUTH_REFUSED);
    s = ok; s.method = "password";                                    /* other method */
    {
        size_t n = mk_req(buf, sizeof buf, &s);
        CHECK_E(zssh_auth_parse_request(buf, n, &rq), ZSSH_E_NONE);
        CHECK(rq.kind == ZSSH_AUTH_OTHER);
        CHECK_E(zssh_auth_check_request(&rq, sid, "alice", PK1), ZSSH_E_AUTH_REFUSED);
    }
    /* PK_OK probe (bool FALSE, no signature) is never success */
    s = ok; s.has_sig = false;
    {
        size_t n = mk_req(buf, sizeof buf, &s);
        CHECK_E(zssh_auth_parse_request(buf, n, &rq), ZSSH_E_NONE);
        CHECK(rq.kind == ZSSH_AUTH_PUBLICKEY && !rq.has_signature);
        CHECK_E(zssh_auth_check_request(&rq, sid, "alice", PK1), ZSSH_E_AUTH_REFUSED);
        /* forging has_signature on a probe still fails: no signature bytes */
        rq.has_signature = true;
        CHECK_E(zssh_auth_check_request(&rq, sid, "alice", PK1), ZSSH_E_AUTH_REFUSED);
    }
    /* probe with trailing bytes: parse refuses, and a zeroed request decides FAILURE */
    s = ok; s.has_sig = false;
    {
        size_t n = mk_req(buf, sizeof buf, &s);
        memset(&rq, 0xAA, sizeof rq);
        buf[n] = 0;
        CHECK_E(zssh_auth_parse_request(buf, n + 1, &rq), ZSSH_E_PROTOCOL);
        CHECK(rq.kind == 0 && rq.user.len == 0 && rq.key_blob.len == 0);
        CHECK(zssh_auth_server_decide(&rq, sid, "alice", PK1) == ZSSH_AUTH_V_FAILURE);
        CHECK_E(zssh_auth_parse_request(buf, n, &rq), ZSSH_E_NONE);   /* without the byte it is a probe */
        CHECK(zssh_auth_server_decide(&rq, sid, "alice", PK1) == ZSSH_AUTH_V_PK_OK);
    }
    /* truncated / overlong requests: typed error, struct zeroed */
    {
        size_t n = mk_req(buf, sizeof buf, &ok);
        for (size_t k = 0; k < n; k++) {
            memset(&rq, 0xAA, sizeof rq);
            CHECK_E(zssh_auth_parse_request(buf, k, &rq), ZSSH_E_PROTOCOL);
            CHECK(rq.kind == 0 && rq.user.len == 0 && rq.sig.len == 0);
        }
        buf[n] = 0;
        CHECK_E(zssh_auth_parse_request(buf, n + 1, &rq), ZSSH_E_PROTOCOL);
    }
    puts("auth server controls: alg/user/service/key/session-id/method/probe refused");
}

/* 4b. client-side build + messages */
static void test_client(void)
{
    uint8_t sid[32], buf[512], tiny[40];
    struct zssh_wr w;
    struct zssh_auth_request rq;
    bool succ = true;
    struct zssh_namelist svc;

    iota(sid, 32, 0);
    zssh_wr_init(&w, buf, sizeof buf);
    CHECK_E(zssh_auth_build_request(&w, "alice", sid, SEED1, PK1), ZSSH_E_NONE);
    CHECK_E(zssh_auth_parse_request(buf, w.off, &rq), ZSSH_E_NONE);
    CHECK(rq.has_signature && rq.kind == ZSSH_AUTH_PUBLICKEY);
    CHECK_E(zssh_auth_check_request(&rq, sid, "alice", PK1), ZSSH_E_NONE);
    /* byte-exact header: 50, string alice, string ssh-connection, ... TRUE */
    CHECK(memcmp(buf, "\x32\x00\x00\x00\x05" "alice" "\x00\x00\x00\x0e" "ssh-connection"
                 "\x00\x00\x00\x09" "publickey" "\x01", 1 + 9 + 18 + 13 + 1) == 0);
    CHECK(w.off == 1 + 9 + 18 + 13 + 1 + 15 + 55 + 4 + 83);
    /* wrong session id at the server -> refused */
    sid[0] ^= 1;
    CHECK_E(zssh_auth_check_request(&rq, sid, "alice", PK1), ZSSH_E_AUTH_REFUSED);

    /* writer too small: typed error, offset restored */
    zssh_wr_init(&w, tiny, sizeof tiny);
    CHECK_E(zssh_auth_build_request(&w, "alice", sid, SEED1, PK1), ZSSH_E_TOO_LARGE);
    CHECK(w.off == 0 && !zssh_wr_ok(&w));       /* builder rule: off restored, bad stays set */
    zssh_wr_init(&w, buf, sizeof buf);
    CHECK_E(zssh_auth_build_request(&w, "alice", sid, SEED2, PK1), ZSSH_E_INTERNAL);
    CHECK(w.off == 0);

    /* service messages */
    zssh_wr_init(&w, buf, sizeof buf);
    zssh_auth_build_service_request(&w, ZSSH_SERVICE_USERAUTH);
    CHECK(w.off == 1 + 4 + 12 && buf[0] == 5);
    CHECK(memcmp(buf, "\x05\x00\x00\x00\x0c" "ssh-userauth", 17) == 0);
    CHECK_E(zssh_auth_parse_service(buf, w.off, ZSSH_MSG_SERVICE_REQUEST, &svc), ZSSH_E_NONE);
    CHECK(svc.len == 12 && memcmp(svc.p, "ssh-userauth", 12) == 0);
    CHECK_E(zssh_auth_parse_service(buf, w.off, ZSSH_MSG_SERVICE_ACCEPT, &svc), ZSSH_E_PROTOCOL);
    CHECK(svc.len == 0);
    CHECK_E(zssh_auth_parse_service(buf, w.off - 1, ZSSH_MSG_SERVICE_REQUEST, &svc), ZSSH_E_PROTOCOL);
    buf[w.off] = 0;
    CHECK_E(zssh_auth_parse_service(buf, w.off + 1, ZSSH_MSG_SERVICE_REQUEST, &svc), ZSSH_E_PROTOCOL);
    zssh_wr_init(&w, buf, sizeof buf);
    zssh_auth_build_service_accept(&w, ZSSH_SERVICE_USERAUTH);
    CHECK(buf[0] == 6);
    CHECK_E(zssh_auth_parse_service(buf, w.off, ZSSH_MSG_SERVICE_ACCEPT, &svc), ZSSH_E_NONE);

    /* builder rule on overflow: partway-written payload rolled back to the
     * entry offset (7 here), bad stays set. 10 bytes: SERVICE_* needs 17. */
    {
        uint8_t small[10];
        for (int k = 0; k < 2; k++) {
            zssh_wr_init(&w, small, sizeof small);
            zssh_wr_bytes(&w, (const uint8_t *)"1234567", 7);
            if (k == 0) zssh_auth_build_service_request(&w, ZSSH_SERVICE_USERAUTH);
            else        zssh_auth_build_service_accept(&w, ZSSH_SERVICE_USERAUTH);
            CHECK(w.off == 7 && !zssh_wr_ok(&w));
        }
        zssh_wr_init(&w, small, 7);
        zssh_wr_bytes(&w, (const uint8_t *)"123456", 6);
        zssh_auth_build_failure(&w);                       /* needs 15 */
        CHECK(w.off == 6 && !zssh_wr_ok(&w));
        zssh_wr_init(&w, small, 0);
        zssh_auth_build_success(&w);
        CHECK(w.off == 0 && !zssh_wr_ok(&w));
        zssh_wr_init(&w, small, sizeof small);
        zssh_auth_build_service_request(&w, NULL);         /* NULL service: nothing written */
        CHECK(w.off == 0 && !zssh_wr_ok(&w));
        zssh_auth_build_failure(NULL);                     /* NULL writer: no crash */
        zssh_auth_build_success(NULL);
        zssh_auth_build_service_request(NULL, "x");
        zssh_auth_build_service_accept(NULL, "x");
        zssh_auth_build_pk_ok(NULL, &rq);
    }

    /* result classification */
    zssh_wr_init(&w, buf, sizeof buf);
    zssh_auth_build_success(&w);
    CHECK(w.off == 1 && buf[0] == 52);
    CHECK_E(zssh_auth_client_result(buf, 1, &succ), ZSSH_E_NONE);
    CHECK(succ);
    CHECK_E(zssh_auth_client_result(buf, 0, &succ), ZSSH_E_PROTOCOL);
    CHECK(!succ);
    zssh_wr_init(&w, buf, sizeof buf);
    zssh_auth_build_failure(&w);
    CHECK(memcmp(buf, "\x33\x00\x00\x00\x09" "publickey" "\x00", 15) == 0 && w.off == 15);
    CHECK_E(zssh_auth_client_result(buf, w.off, &succ), ZSSH_E_AUTH_REFUSED);
    CHECK(!succ);
    {   /* PK_OK is never success */
        static const uint8_t pkok[] = { 60, 0,0,0,11,'s','s','h','-','e','d','2','5','5','1','9',
                                        0,0,0,2,'x','y' };
        succ = true;
        CHECK_E(zssh_auth_client_result(pkok, sizeof pkok, &succ), ZSSH_E_PROTOCOL);
        CHECK(!succ);
        CHECK_E(zssh_auth_client_result(pkok, 1, &succ), ZSSH_E_PROTOCOL);
        CHECK(!succ);
    }
    {   /* banner is ignored, not success */
        static const uint8_t ban[] = { 53, 0,0,0,2,'h','i', 0,0,0,0 };
        succ = true;
        CHECK_E(zssh_auth_client_result(ban, sizeof ban, &succ), ZSSH_E_NONE);
        CHECK(!succ);
        CHECK_E(zssh_auth_client_result(ban, sizeof ban - 1, &succ), ZSSH_E_PROTOCOL);
    }
    {   /* SUCCESS with trailing junk and unknown types are protocol errors */
        static const uint8_t junk[] = { 52, 0 };
        static const uint8_t unk[] = { 99 };
        CHECK_E(zssh_auth_client_result(junk, 2, &succ), ZSSH_E_PROTOCOL);
        CHECK(!succ);
        CHECK_E(zssh_auth_client_result(unk, 1, &succ), ZSSH_E_PROTOCOL);
    }
    puts("auth client: request round-trip, service msgs, success/failure/PK_OK/banner");
}

static enum zssh_auth_verdict decide(const struct reqspec *s, const uint8_t *sid,
                                     const char *eu, const uint8_t *apk,
                                     struct zssh_auth_request *rq)
{
    uint8_t buf[512];
    size_t n = mk_req(buf, sizeof buf, s);
    static uint8_t keep[512];           /* slices alias the payload */
    memcpy(keep, buf, n);
    CHECK_E(zssh_auth_parse_request(keep, n, rq), ZSSH_E_NONE);
    return zssh_auth_server_decide(rq, sid, eu, apk);
}

/* 5. probe flow: PK_OK for the authorized key only, never success */
static void test_probe(void)
{
    uint8_t sid[32], sid2[32], out[256];
    struct zssh_auth_request rq;
    struct zssh_wr w;
    struct reqspec p = { "alice", "ssh-connection", "publickey", "ssh-ed25519",
                         false, PK1, SEED1, PK1, NULL, "alice" };
    struct reqspec s;
    bool succ = true, pkok = false;

    iota(sid, 32, 0); iota(sid2, 32, 1);
    p.sign_sid = sid;
    CHECK(decide(&p, sid, "alice", PK1, &rq) == ZSSH_AUTH_V_PK_OK);
    /* the strict signed-only check still refuses the probe: not success */
    CHECK_E(zssh_auth_check_request(&rq, sid, "alice", PK1), ZSSH_E_AUTH_REFUSED);
    zssh_wr_init(&w, out, sizeof out);
    zssh_auth_build_pk_ok(&w, &rq);
    CHECK(w.off == 1 + 15 + 55 && out[0] == 60);
    CHECK(memcmp(out, "\x3c\x00\x00\x00\x0b" "ssh-ed25519\x00\x00\x00\x33", 20) == 0);
    CHECK_E(zssh_auth_client_result_ex(out, w.off, &succ, &pkok), ZSSH_E_NONE);
    CHECK(pkok && !succ);
    CHECK_E(zssh_auth_client_result_ex(out, w.off - 1, &succ, &pkok), ZSSH_E_PROTOCOL);
    CHECK(!pkok && !succ);

    s = p; s.key_pk = PK2; s.sign_seed = SEED2; s.sign_pk = PK2;     /* unauthorized key */
    CHECK(decide(&s, sid, "alice", PK1, &rq) == ZSSH_AUTH_V_FAILURE);
    s = p; s.alg = "ssh-rsa";
    CHECK(decide(&s, sid, "alice", PK1, &rq) == ZSSH_AUTH_V_FAILURE);
    s = p; s.user = "bob";
    CHECK(decide(&s, sid, "alice", PK1, &rq) == ZSSH_AUTH_V_FAILURE);
    s = p; s.service = "ssh-userauth";
    CHECK(decide(&s, sid, "alice", PK1, &rq) == ZSSH_AUTH_V_FAILURE);
    /* user must match exactly; NULL/empty expected_user fails closed */
    CHECK(decide(&p, sid, NULL, PK1, &rq) == ZSSH_AUTH_V_FAILURE);
    CHECK(decide(&p, sid, "", PK1, &rq) == ZSSH_AUTH_V_FAILURE);
    s = p; s.user = "alic";
    CHECK(decide(&s, sid, "alice", PK1, &rq) == ZSSH_AUTH_V_FAILURE);
    CHECK(decide(&p, sid, "alic", PK1, &rq) == ZSSH_AUTH_V_FAILURE);
    s = p; s.has_sig = true;
    CHECK(decide(&s, sid, NULL, PK1, &rq) == ZSSH_AUTH_V_FAILURE);
    CHECK(decide(&s, sid, "", PK1, &rq) == ZSSH_AUTH_V_FAILURE);
    CHECK(decide(&s, sid, "alic", PK1, &rq) == ZSSH_AUTH_V_FAILURE);
    CHECK(zssh_auth_server_decide(NULL, sid, "alice", PK1) == ZSSH_AUTH_V_FAILURE);
    /* build_pk_ok(NULL req): nothing written, writer flagged */
    zssh_wr_init(&w, out, sizeof out);
    zssh_auth_build_pk_ok(&w, NULL);
    CHECK(w.off == 0 && !zssh_wr_ok(&w));
    /* build_pk_ok overflow: rolled back to entry offset */
    {
        uint8_t small[30];
        CHECK(decide(&p, sid, "alice", PK1, &rq) == ZSSH_AUTH_V_PK_OK);
        zssh_wr_init(&w, small, sizeof small);
        zssh_wr_bytes(&w, (const uint8_t *)"abc", 3);
        zssh_auth_build_pk_ok(&w, &rq);                    /* needs 70 */
        CHECK(w.off == 3 && !zssh_wr_ok(&w));
    }

    s = p; s.has_sig = true;                                         /* signed */
    CHECK(decide(&s, sid, "alice", PK1, &rq) == ZSSH_AUTH_V_SUCCESS);
    CHECK(decide(&s, sid2, "alice", PK1, &rq) == ZSSH_AUTH_V_FAILURE); /* wrong session id */
    s.key_pk = PK2; s.sign_seed = SEED2; s.sign_pk = PK2;
    CHECK(decide(&s, sid, "alice", PK1, &rq) == ZSSH_AUTH_V_FAILURE);

    /* a client still reading the old classifier never treats PK_OK as success */
    CHECK_E(zssh_auth_client_result(out, 1, &succ), ZSSH_E_PROTOCOL);
    CHECK(!succ);
    puts("auth probe: authorized probe -> PK_OK, others FAILURE, signed -> SUCCESS");
}

/* 6. integrator sequence: probe -> PK_OK -> signed request -> SUCCESS, and
 * every single-fault variant of the signed step is refused; the client side
 * never reads PK_OK as success and rejects malformed PK_OK. */
static void test_sequence(void)
{
    uint8_t sid[32], sid2[32], pbuf[512], sbuf[512], okb[256];
    static uint8_t pkeep[512], skeep[512];
    struct zssh_auth_request prq, srq;
    struct zssh_wr w;
    bool succ = true, pkok = false;
    size_t pn, i;

    iota(sid, 32, 0); iota(sid2, 32, 9);
    /* step 1: client probe (unsigned) as OpenSSH sends it */
    {
        struct reqspec p = { "alice", "ssh-connection", "publickey", "ssh-ed25519",
                             false, PK1, SEED1, PK1, sid, "alice" };
        pn = mk_req(pbuf, sizeof pbuf, &p);
        memcpy(pkeep, pbuf, pn);
    }
    CHECK_E(zssh_auth_parse_request(pkeep, pn, &prq), ZSSH_E_NONE);
    CHECK(zssh_auth_server_decide(&prq, sid, "alice", PK1) == ZSSH_AUTH_V_PK_OK);
    /* step 2: PK_OK echoes alg and blob; client sees pk_ok, not success */
    zssh_wr_init(&w, okb, sizeof okb);
    zssh_auth_build_pk_ok(&w, &prq);
    CHECK(zssh_wr_ok(&w) && okb[0] == 60);
    CHECK_E(zssh_auth_client_result_ex(okb, w.off, &succ, &pkok), ZSSH_E_NONE);
    CHECK(pkok && !succ);
    /* step 3: signed request from the real client builder -> SUCCESS */
    zssh_wr_init(&w, sbuf, sizeof sbuf);
    CHECK_E(zssh_auth_build_request(&w, "alice", sid, SEED1, PK1), ZSSH_E_NONE);
    memcpy(skeep, sbuf, w.off);
    CHECK_E(zssh_auth_parse_request(skeep, w.off, &srq), ZSSH_E_NONE);
    CHECK(zssh_auth_server_decide(&srq, sid, "alice", PK1) == ZSSH_AUTH_V_SUCCESS);
    CHECK_E(zssh_auth_check_request(&srq, sid, "alice", PK1), ZSSH_E_NONE);
    /* the probe alone never authenticates */
    CHECK(zssh_auth_server_decide(&prq, sid, "alice", PK1) != ZSSH_AUTH_V_SUCCESS);
    /* single faults on the signed step: each refused */
    CHECK(zssh_auth_server_decide(&srq, sid, "bob", PK1) == ZSSH_AUTH_V_FAILURE);      /* wrong user */
    CHECK(zssh_auth_server_decide(&srq, sid2, "alice", PK1) == ZSSH_AUTH_V_FAILURE);   /* wrong session id */
    CHECK(zssh_auth_server_decide(&srq, sid, "alice", PK2) == ZSSH_AUTH_V_FAILURE);    /* wrong key */
    srq.service.p = (const uint8_t *)"ssh-userauth"; srq.service.len = 12;             /* wrong service */
    CHECK(zssh_auth_server_decide(&srq, sid, "alice", PK1) == ZSSH_AUTH_V_FAILURE);
    CHECK_E(zssh_auth_parse_request(skeep, w.off, &srq), ZSSH_E_NONE);
    /* bad signature: flip every byte of the 64-byte signature in turn */
    for (i = w.off - 64; i < w.off; i++) {
        skeep[i] ^= 0x01;
        CHECK_E(zssh_auth_parse_request(skeep, w.off, &srq), ZSSH_E_NONE);
        CHECK(zssh_auth_server_decide(&srq, sid, "alice", PK1) == ZSSH_AUTH_V_FAILURE);
        skeep[i] ^= 0x01;
    }
    CHECK_E(zssh_auth_parse_request(skeep, w.off, &srq), ZSSH_E_NONE);
    CHECK(zssh_auth_server_decide(&srq, sid, "alice", PK1) == ZSSH_AUTH_V_SUCCESS);

    /* client side: a PK_OK is never success. The plain classifier (what CONN
     * uses for a client that never probes) refuses it as unsolicited. */
    zssh_wr_init(&w, okb, sizeof okb);
    zssh_auth_build_pk_ok(&w, &prq);
    succ = true;
    CHECK_E(zssh_auth_client_result(okb, w.off, &succ), ZSSH_E_PROTOCOL);
    CHECK(!succ);
    /* _ex: well-formed PK_OK sets pk_ok only (CONN maps pk_ok to PROTOCOL);
     * success is never set, whatever alg/blob it names */
    {
        static const uint8_t other_alg[] = { 60, 0,0,0,7,'s','s','h','-','r','s','a',
                                             0,0,0,2,'x','y' };
        succ = true; pkok = false;
        CHECK_E(zssh_auth_client_result_ex(other_alg, sizeof other_alg, &succ, &pkok),
                ZSSH_E_NONE);
        CHECK(pkok && !succ);
        succ = true;
        CHECK_E(zssh_auth_client_result(other_alg, sizeof other_alg, &succ), ZSSH_E_PROTOCOL);
        CHECK(!succ);
    }
    /* malformed PK_OK: every truncation and a trailing byte -> PROTOCOL, no pk_ok */
    {
        size_t on;
        zssh_wr_init(&w, okb, sizeof okb);
        zssh_auth_build_pk_ok(&w, &prq);
        on = w.off;
        for (i = 1; i < on; i++) {
            succ = true; pkok = true;
            CHECK_E(zssh_auth_client_result_ex(okb, i, &succ, &pkok), ZSSH_E_PROTOCOL);
            CHECK(!pkok && !succ);
        }
        okb[on] = 0;
        CHECK_E(zssh_auth_client_result_ex(okb, on + 1, &succ, &pkok), ZSSH_E_PROTOCOL);
        CHECK(!pkok && !succ);
    }
    CHECK_E(zssh_auth_client_result_ex(okb, 1, NULL, &pkok), ZSSH_E_INTERNAL);
    puts("auth sequence: probe->PK_OK->signed->SUCCESS, single faults refused, client PK_OK handling");
}

int main(void)
{
    test_sequence();
    test_probe();
    test_rfc8032();
    test_blobs();
    test_signed_data();
    test_server_controls();
    test_client();
    printf("zssh_auth: %d checks, %d failed\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
