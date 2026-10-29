/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zssh_kex — layer (b): KEXINIT, negotiation, curve25519 / hybrid KEX,
 * exchange hash, key derivation.
 *
 * Test doubles (clearly marked): the wire helpers of layer (a) and the
 * ssh-ed25519 blob/sign/verify of layer (c) are replaced by minimal local
 * versions so this file depends on no other layer's implementation. Define
 * ZSSH_KEX_TEST_REAL_WIRE / ZSSH_KEX_TEST_REAL_AUTH and link the real layers
 * to run the same fixtures against them.
 *
 * Known answers: the X25519 vector is RFC 7748 6.1. The exchange hash and the
 * key derivation are recomputed by ref_h()/ref_keys() below straight from
 * RFC 4253 8 / 7.2 and RFC 8731 3.1 using only sha256 and a private
 * encoder; they never call the module's functions. */

#include "zssh_internal.h"
#include "base/serialize_le.h"
#include "base/hex.h"
#ifdef ZSSH_KEX_TEST_REAL_AUTH
#include "crypto/ed25519.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail;
static int g_group_fail;

#define CHECK(cond, ...) do { if (!(cond)) { g_fail++; g_group_fail++; \
    fprintf(stderr, "  FAIL %s:%d: ", __FILE__, __LINE__); \
    fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } } while (0)

static void group_begin(void) { g_group_fail = 0; }
static void group_end(const char *name)
{
    printf("%s: %s\n", name, g_group_fail ? "FAIL" : "ok");
}

/* ======================================================================== *
 * TEST DOUBLE: layer (a) wire helpers                                      *
 * ======================================================================== */
#ifndef ZSSH_KEX_TEST_REAL_WIRE
uint32_t zssh_get_u32(const uint8_t p[4])
{
    return zcl_read_u32_be(p);
}
void zssh_put_u32(uint8_t p[4], uint32_t v)
{
    zcl_write_u32_be(p, v);
}
void zssh_put_u64(uint8_t p[8], uint64_t v)
{
    zcl_write_u64_be(p, v);
}
bool zssh_ct_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}
void zssh_rd_init(struct zssh_rd *r, const uint8_t *p, size_t len)
{ r->p = p; r->len = len; r->off = 0; r->bad = false; }
size_t zssh_rd_left(const struct zssh_rd *r) { return r->len - r->off; }
bool zssh_rd_ok(const struct zssh_rd *r) { return !r->bad; }
bool zssh_rd_done(const struct zssh_rd *r) { return !r->bad && r->off == r->len; }
void zssh_rd_bytes(struct zssh_rd *r, const uint8_t **s, size_t n)
{
    if (r->bad || n > zssh_rd_left(r)) { r->bad = true; *s = nullptr; return; }
    *s = r->p + r->off; r->off += n;
}
uint8_t zssh_rd_u8(struct zssh_rd *r)
{
    const uint8_t *s; zssh_rd_bytes(r, &s, 1); return s ? s[0] : 0;
}
bool zssh_rd_bool(struct zssh_rd *r) { return zssh_rd_u8(r) != 0; }
uint32_t zssh_rd_u32(struct zssh_rd *r)
{
    const uint8_t *s; zssh_rd_bytes(r, &s, 4); return s ? zssh_get_u32(s) : 0;
}
void zssh_rd_string(struct zssh_rd *r, const uint8_t **s, size_t *n)
{
    uint32_t l = zssh_rd_u32(r);
    *s = nullptr; *n = 0;
    if (r->bad || l > ZSSH_MAX_PACKET) { r->bad = true; return; }
    zssh_rd_bytes(r, s, l);
    if (!r->bad) *n = l;
}
void zssh_wr_init(struct zssh_wr *w, uint8_t *p, size_t cap)
{ w->p = p; w->cap = cap; w->off = 0; w->bad = false; }
bool zssh_wr_ok(const struct zssh_wr *w) { return !w->bad; }
void zssh_wr_bytes(struct zssh_wr *w, const uint8_t *b, size_t n)
{
    if (w->bad || n > w->cap - w->off) { w->bad = true; return; }
    if (n) memcpy(w->p + w->off, b, n);
    w->off += n;
}
void zssh_wr_u8(struct zssh_wr *w, uint8_t v) { zssh_wr_bytes(w, &v, 1); }
void zssh_wr_bool(struct zssh_wr *w, bool v) { zssh_wr_u8(w, v ? 1 : 0); }
void zssh_wr_u32(struct zssh_wr *w, uint32_t v)
{ uint8_t b[4]; zssh_put_u32(b, v); zssh_wr_bytes(w, b, 4); }
void zssh_wr_string(struct zssh_wr *w, const uint8_t *b, size_t n)
{ zssh_wr_u32(w, (uint32_t)n); zssh_wr_bytes(w, b, n); }
void zssh_wr_cstr(struct zssh_wr *w, const char *s)
{ zssh_wr_string(w, (const uint8_t *)s, strlen(s)); }
void zssh_wr_mpint(struct zssh_wr *w, const uint8_t *be, size_t n)
{
    while (n > 0 && be[0] == 0) { be++; n--; }
    if (n == 0) { zssh_wr_u32(w, 0); return; }
    bool pad = (be[0] & 0x80) != 0;
    zssh_wr_u32(w, (uint32_t)(n + (pad ? 1 : 0)));
    if (pad) zssh_wr_u8(w, 0);
    zssh_wr_bytes(w, be, n);
}
bool zssh_namelist_has(struct zssh_namelist l, const char *name)
{
    size_t nl = strlen(name), i = 0;
    while (i <= l.len) {
        size_t j = i;
        while (j < l.len && l.p[j] != ',') j++;
        if (j - i == nl && memcmp(l.p + i, name, nl) == 0) return true;
        i = j + 1;
    }
    return false;
}
int zssh_namelist_pick(struct zssh_namelist client, struct zssh_namelist server,
                       const uint8_t **name, size_t *n)
{
    size_t i = 0; int idx = 0;
    while (client.len > 0 && i <= client.len) {
        size_t j = i;
        while (j < client.len && client.p[j] != ',') j++;
        struct zssh_namelist one = { client.p + i, j - i };
        for (size_t t = 0; t < server.len + 1;) {
            size_t u = t;
            while (u < server.len && server.p[u] != ',') u++;
            if (u - t == one.len && one.len > 0 && memcmp(server.p + t, one.p, one.len) == 0) {
                *name = one.p; *n = one.len; return idx;
            }
            t = u + 1;
        }
        i = j + 1; idx++;
    }
    return -1;
}
#endif /* ZSSH_KEX_TEST_REAL_WIRE */

/* ======================================================================== *
 * TEST DOUBLE: layer (c) ssh-ed25519 blobs, sign, verify                   *
 * "signature" = two SHA-256 digests keyed by the public key over the msg,  *
 * which still fails for any change of the signed message (here: H).        *
 * ======================================================================== */
static int g_verify_calls;

#ifndef ZSSH_KEX_TEST_REAL_AUTH
static uint8_t g_verify_msg[64];
static size_t g_verify_msg_len;
void zssh_auth_blob_encode(const uint8_t pk[ZSSH_ED25519_PK_LEN],
                           uint8_t out[ZSSH_ED25519_BLOB_LEN])
{
    static const uint8_t pre[15] = { 0, 0, 0, 11, 's','s','h','-','e','d','2','5','5','1','9' };
    memcpy(out, pre, 15);
    zssh_put_u32(out + 15, 32);
    memcpy(out + 19, pk, 32);
}
enum zssh_error zssh_auth_blob_parse(const uint8_t *blob, size_t len,
                                     uint8_t pk[ZSSH_ED25519_PK_LEN])
{
    uint8_t exp[ZSSH_ED25519_BLOB_LEN];
    memset(pk, 0, ZSSH_ED25519_PK_LEN);
    if (len != sizeof exp) return ZSSH_E_PROTOCOL;
    zssh_auth_blob_encode(blob + 19, exp);
    if (memcmp(exp, blob, sizeof exp) != 0) return ZSSH_E_PROTOCOL;
    memcpy(pk, blob + 19, 32);
    return ZSSH_E_NONE;
}
static void dbl_sig(const uint8_t pk[32], const uint8_t *msg, size_t n, uint8_t out[64])
{
    for (uint8_t t = 1; t <= 2; t++) {
        struct sha256_ctx c;
        sha256_init(&c);
        sha256_write(&c, &t, 1);
        sha256_write(&c, pk, 32);
        sha256_write(&c, msg, n);
        sha256_finalize(&c, out + (t - 1) * 32);
    }
}
enum zssh_error zssh_auth_sign(const uint8_t seed[ZSSH_ED25519_SEED_LEN],
                               const uint8_t pk[ZSSH_ED25519_PK_LEN],
                               const uint8_t *msg, size_t msg_len,
                               uint8_t out[ZSSH_ED25519_SIGBLOB_LEN])
{
    static const uint8_t pre[15] = { 0, 0, 0, 11, 's','s','h','-','e','d','2','5','5','1','9' };
    (void)seed;
    memcpy(out, pre, 15);
    zssh_put_u32(out + 15, 64);
    dbl_sig(pk, msg, msg_len, out + 19);
    return ZSSH_E_NONE;
}
enum zssh_error zssh_auth_verify(const uint8_t pk[ZSSH_ED25519_PK_LEN],
                                 const uint8_t *msg, size_t msg_len,
                                 const uint8_t *sigblob, size_t sigblob_len, bool host)
{
    uint8_t exp[64];
    g_verify_calls++;
    g_verify_msg_len = msg_len < sizeof g_verify_msg ? msg_len : sizeof g_verify_msg;
    memcpy(g_verify_msg, msg, g_verify_msg_len);
    if (sigblob_len != ZSSH_ED25519_SIGBLOB_LEN) return ZSSH_E_PROTOCOL;
    dbl_sig(pk, msg, msg_len, exp);
    if (!zssh_ct_eq(exp, sigblob + 19, 64)) return host ? ZSSH_E_HOST_SIG : ZSSH_E_AUTH_REFUSED;
    return ZSSH_E_NONE;
}
#endif /* ZSSH_KEX_TEST_REAL_AUTH */

/* ======================================================================== *
 * Deterministic RNG with scripted first blocks and scripted failure        *
 * ======================================================================== */
struct rng {
    const uint8_t *fixed[2];   /* contents of call 1 / call 2 (32 bytes) if set */
    unsigned calls;
    unsigned fail_at;          /* 1-based call index that fails; 0 = never */
    uint32_t state;
};
/* One LCG step; the byte is the top byte of the state (a PRNG, not a codec). */
static uint8_t rng_next_byte(struct rng *r)
{
    r->state = r->state * 1664525u + 1013904223u;
    return (uint8_t)(r->state >> 24);
}
static bool rng_fn(void *ctx, uint8_t *out, size_t n)
{
    struct rng *r = ctx;
    r->calls++;
    if (r->fail_at && r->calls == r->fail_at) {
        memset(out, 0xAA, n);          /* garbage a careless caller might keep */
        return false;
    }
    if (r->calls <= 2 && r->fixed[r->calls - 1] && n == 32) {
        memcpy(out, r->fixed[r->calls - 1], 32);
        return true;
    }
    for (size_t i = 0; i < n; i++) {
        out[i] = rng_next_byte(r);
    }
    return true;
}
static void rng_init(struct rng *r, uint32_t seed)
{ memset(r, 0, sizeof *r); r->state = seed; }

static bool is_zero(const void *p, size_t n)
{
    const uint8_t *b = p;
    for (size_t i = 0; i < n; i++) if (b[i]) return false;
    return true;
}

/* Known-answer hex is written by hand in this file; a malformed literal is a
 * test bug and fails the check rather than being silently decoded. */
static void hex2bin(const char *h, uint8_t *out, size_t n)
{
    bool ok = zcl_hex_decode(h, out, n);
    CHECK(ok, "malformed known-answer hex literal (%zu bytes)", n);
}

/* ======================================================================== *
 * Independent reference encoder (RFC 4251 5, RFC 4253 8 / 7.2)             *
 * ======================================================================== */
struct tb { uint8_t b[16384]; size_t n; };
static void tb_raw(struct tb *t, const void *p, size_t n) { memcpy(t->b + t->n, p, n); t->n += n; }
static void tb_u32(struct tb *t, uint32_t v)
{
    uint8_t x[4];
    zcl_write_u32_be(x, v);
    tb_raw(t, x, 4);
}
static void tb_str(struct tb *t, const void *p, size_t n) { tb_u32(t, (uint32_t)n); tb_raw(t, p, n); }
static void tb_mpint(struct tb *t, const uint8_t *be, size_t n)
{
    size_t z = 0;
    while (z < n && be[z] == 0) z++;
    n -= z; be += z;
    if (n == 0) { tb_u32(t, 0); return; }
    if (be[0] & 0x80) { tb_u32(t, (uint32_t)n + 1); uint8_t zero = 0; tb_raw(t, &zero, 1); }
    else tb_u32(t, (uint32_t)n);
    tb_raw(t, be, n);
}
enum kmode { KM_STRING, KM_MPINT, KM_MPINT_REVERSED };
static void tb_k(struct tb *t, enum kmode m, const uint8_t k[32])
{
    uint8_t rev[32];
    switch (m) {
    case KM_STRING: tb_str(t, k, 32); break;
    case KM_MPINT: tb_mpint(t, k, 32); break;
    case KM_MPINT_REVERSED:
        for (int i = 0; i < 32; i++) rev[i] = k[31 - i];
        tb_mpint(t, rev, 32);
        break;
    }
}
static void sha(const struct tb *t, uint8_t out[32])
{
    struct sha256_ctx c; sha256_init(&c); sha256_write(&c, t->b, t->n); sha256_finalize(&c, out);
}
static void ref_h(const struct zssh_kex *k, enum kmode m, uint8_t out[32])
{
    struct tb t = { .n = 0 };
    tb_str(&t, k->v_c, k->v_c_len);
    tb_str(&t, k->v_s, k->v_s_len);
    tb_str(&t, k->i_c, k->i_c_len);
    tb_str(&t, k->i_s, k->i_s_len);
    tb_str(&t, k->host_blob, ZSSH_ED25519_BLOB_LEN);
    tb_str(&t, k->q_c, k->q_c_len);
    tb_str(&t, k->q_s, k->q_s_len);
    tb_k(&t, m, k->k);
    sha(&t, out);
}
static void ref_keys(enum kmode m, const uint8_t K[32], const uint8_t H[32],
                     const uint8_t sid[32], char letter, uint8_t out[64])
{
    struct tb t = { .n = 0 };
    tb_k(&t, m, K); tb_raw(&t, H, 32); tb_raw(&t, &letter, 1); tb_raw(&t, sid, 32);
    sha(&t, out);
    t.n = 0;
    tb_k(&t, m, K); tb_raw(&t, H, 32); tb_raw(&t, out, 32);
    sha(&t, out + 32);
}

/* ======================================================================== *
 * Fixtures                                                                 *
 * ======================================================================== */
static uint8_t HOST_PK[32] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24 };
static const uint8_t HOST_SEED[32] = { 0x99 };

/* Under ZSSH_KEX_TEST_REAL_AUTH the host public key is derived from HOST_SEED
 * at test start: the real zssh_auth_sign checks that the pair matches. The
 * constant above is used only with the double, which ignores the seed. */
static void init_host_key(void)
{
#ifdef ZSSH_KEX_TEST_REAL_AUTH
    uint8_t sk[32];
    zcl_ed25519_keypair(HOST_PK, sk, HOST_SEED);
    memset(sk, 0, sizeof sk);
#endif
}

static struct zssh_kex g_c, g_s;
static uint8_t g_init[2048], g_reply[2048];
static size_t g_init_len, g_reply_len;

static struct zssh_kex_policy pol(enum zssh_role role, uint32_t allowed, bool pq)
{
    struct zssh_kex_policy p = { .role = role, .allowed = allowed, .require_pq = pq };
    return p;
}
#define BOTH (ZSSH_KEX_MLKEM768X25519_SHA256 | ZSSH_KEX_CURVE25519_SHA256)

static size_t build_ki(enum zssh_role role, uint32_t allowed, bool pq, uint8_t *buf, size_t cap)
{
    struct zssh_kex_policy p = pol(role, allowed, pq);
    uint8_t cookie[16];
    struct zssh_wr w;
    for (int i = 0; i < 16; i++) cookie[i] = (uint8_t)(role * 16 + i);
    zssh_wr_init(&w, buf, cap);
    if (zssh_kex_build_kexinit(&p, cookie, &w) != ZSSH_E_NONE) return 0;
    return w.off;
}

/* Fresh pair with shared transcript inputs. */
static void pair_setup(enum zssh_kex_alg alg)
{
    uint32_t allowed = alg == ZSSH_KEXALG_MLKEM768X25519 ? ZSSH_KEX_MLKEM768X25519_SHA256
                                                         : ZSSH_KEX_CURVE25519_SHA256;
    memset(&g_c, 0, sizeof g_c);
    memset(&g_s, 0, sizeof g_s);
    g_c.role = ZSSH_ROLE_CLIENT; g_s.role = ZSSH_ROLE_SERVER;
    g_c.neg.alg = g_s.neg.alg = alg;
    g_c.neg.strict = g_s.neg.strict = true;
    memcpy(g_c.v_c, "SSH-2.0-zssh_1 client", 21); g_c.v_c_len = 21;
    memcpy(g_c.v_s, "SSH-2.0-zssh_1 server", 21); g_c.v_s_len = 21;
    g_c.i_c_len = build_ki(ZSSH_ROLE_CLIENT, allowed, false, g_c.i_c, sizeof g_c.i_c);
    g_c.i_s_len = build_ki(ZSSH_ROLE_SERVER, allowed, false, g_c.i_s, sizeof g_c.i_s);
    memcpy(g_s.v_c, g_c.v_c, g_c.v_c_len); g_s.v_c_len = g_c.v_c_len;
    memcpy(g_s.v_s, g_c.v_s, g_c.v_s_len); g_s.v_s_len = g_c.v_s_len;
    memcpy(g_s.i_c, g_c.i_c, g_c.i_c_len); g_s.i_c_len = g_c.i_c_len;
    memcpy(g_s.i_s, g_c.i_s, g_c.i_s_len); g_s.i_s_len = g_c.i_s_len;
    g_verify_calls = 0;
}

static enum zssh_error do_init(struct rng *r)
{
    struct zssh_wr w;
    zssh_wr_init(&w, g_init, sizeof g_init);
    enum zssh_error e = zssh_kex_client_init(&g_c, rng_fn, r, &w);
    g_init_len = w.off;
    return e;
}
static enum zssh_error do_reply(struct rng *r)
{
    struct zssh_wr w;
    zssh_wr_init(&w, g_reply, sizeof g_reply);
    enum zssh_error e = zssh_kex_server_reply(&g_s, g_init, g_init_len, HOST_PK, HOST_SEED,
                                              rng_fn, r, &w);
    g_reply_len = w.off;
    return e;
}
static enum zssh_error do_finish(void)
{
    return zssh_kex_client_finish(&g_c, g_reply, g_reply_len, HOST_PK);
}

/* ======================================================================== *
 * Groups                                                                   *
 * ======================================================================== */

/* (1) curve25519 through the real code path with the RFC 7748 6.1 vector. */
static void group_curve_kat(void)
{
    uint8_t apriv[32], apub[32], bpriv[32], bpub[32], shared[32], href[32];
    struct rng cr, sr;
    group_begin();
    hex2bin("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", apriv, 32);
    hex2bin("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", apub, 32);
    hex2bin("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", bpriv, 32);
    hex2bin("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", bpub, 32);
    hex2bin("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", shared, 32);
    rng_init(&cr, 1); cr.fixed[0] = apriv;
    rng_init(&sr, 2); sr.fixed[0] = bpriv;
    pair_setup(ZSSH_KEXALG_CURVE25519);
    CHECK(do_init(&cr) == ZSSH_E_NONE, "client_init");
    CHECK(g_init_len == 1 + 4 + 32 && g_init[0] == 30 && zssh_get_u32(g_init + 1) == 32
          && memcmp(g_init + 5, apub, 32) == 0, "INIT is 30 || string(Alice pub)");
    CHECK(do_reply(&sr) == ZSSH_E_NONE, "server_reply");
    CHECK(g_s.q_s_len == 32 && memcmp(g_s.q_s, bpub, 32) == 0, "Q_S is Bob's public key");
    CHECK(g_s.k_len == 32 && memcmp(g_s.k, shared, 32) == 0, "server K is the RFC 7748 secret");
    CHECK(do_finish() == ZSSH_E_NONE, "client_finish");
    CHECK(memcmp(g_c.k, shared, 32) == 0, "client K is the RFC 7748 secret");
    /* H against the independent encoder: mpint, bytes NOT reversed. */
    ref_h(&g_c, KM_MPINT, href);
    CHECK(memcmp(g_c.h, href, 32) == 0 && memcmp(g_s.h, href, 32) == 0, "H matches mpint reference");
    ref_h(&g_c, KM_MPINT_REVERSED, href);
    CHECK(memcmp(g_c.h, href, 32) != 0, "control: reversed-K encoding gives a different H");
#ifndef ZSSH_KEX_TEST_REAL_AUTH
    /* Verify-count checks need the double, which records the verified message;
     * the real verifier is not instrumented. Real-auth runs rely on the
     * successful do_finish() above, which only passes over the honest H. */
    CHECK(g_verify_calls == 1 && g_verify_msg_len == 32 && memcmp(g_verify_msg, g_c.h, 32) == 0,
          "signature is checked over H");
#endif
    CHECK(g_c.have_session_id && memcmp(g_c.session_id, g_c.h, 32) == 0, "session_id == first H");
    group_end("curve25519 RFC7748 vector");
}

/* (2) H and key derivation known answers from the independent encoder. */
static void fill_kat_kex(struct zssh_kex *k, enum zssh_kex_alg alg, const uint8_t K[32])
{
    memset(k, 0, sizeof *k);
    k->neg.alg = alg;
    memcpy(k->v_c, "SSH-2.0-a", 9); k->v_c_len = 9;
    memcpy(k->v_s, "SSH-2.0-bb", 10); k->v_s_len = 10;
    for (size_t i = 0; i < 100; i++) { k->i_c[i] = (uint8_t)(i + 20); k->i_s[i] = (uint8_t)(i * 3); }
    k->i_c[0] = k->i_s[0] = 20; k->i_c_len = 100; k->i_s_len = 91;
    zssh_auth_blob_encode(HOST_PK, k->host_blob);
    k->q_c_len = alg == ZSSH_KEXALG_MLKEM768X25519 ? ZSSH_QC_MLKEM_LEN : 32;
    k->q_s_len = alg == ZSSH_KEXALG_MLKEM768X25519 ? ZSSH_QS_MLKEM_LEN : 32;
    for (size_t i = 0; i < k->q_c_len; i++) k->q_c[i] = (uint8_t)(i * 7 + 1);
    for (size_t i = 0; i < k->q_s_len; i++) k->q_s[i] = (uint8_t)(i * 5 + 2);
    memcpy(k->k, K, 32); k->k_len = 32;
}
static void group_h_keys_kat(void)
{
    struct zssh_kex k;
    struct zssh_keys keys;
    uint8_t K[4][32], href[32], kref[64], sid2[32];
    static const enum zssh_kex_alg algs[2] = { ZSSH_KEXALG_CURVE25519, ZSSH_KEXALG_MLKEM768X25519 };
    group_begin();
    memset(K, 0x5a, sizeof K);
    K[1][0] = 0x80;                                  /* top bit set: mpint needs 00 prefix */
    K[2][0] = 0; K[2][1] = 0; K[2][2] = 0x7f;        /* leading zeros stripped */
    K[3][0] = 0; K[3][1] = 0x01;
    for (int a = 0; a < 2; a++) {
        for (int v = 0; v < 4; v++) {
            enum kmode m = algs[a] == ZSSH_KEXALG_CURVE25519 ? KM_MPINT : KM_STRING;
            fill_kat_kex(&k, algs[a], K[v]);
            CHECK(zssh_kex_compute_h(&k) == ZSSH_E_NONE, "compute_h");
            ref_h(&k, m, href);
            CHECK(memcmp(k.h, href, 32) == 0, "H alg %d K%d matches reference", a, v);
            CHECK(k.have_session_id && memcmp(k.session_id, k.h, 32) == 0, "first H becomes session_id");
            /* second kex (rekey shape): session_id must stay the first H */
            memcpy(sid2, k.session_id, 32);
            k.q_c[0] ^= 1;
            CHECK(zssh_kex_compute_h(&k) == ZSSH_E_NONE, "compute_h #2");
            CHECK(memcmp(k.session_id, sid2, 32) == 0 && memcmp(k.h, sid2, 32) != 0,
                  "session_id keeps the first H");
            ref_h(&k, m, href);
            CHECK(memcmp(k.h, href, 32) == 0, "second H matches reference");
            CHECK(zssh_kex_derive_keys(&k, &keys) == ZSSH_E_NONE, "derive");
            ref_keys(m, k.k, k.h, k.session_id, 'C', kref);
            CHECK(memcmp(keys.c2s, kref, 64) == 0, "key C matches reference (alg %d K%d)", a, v);
            ref_keys(m, k.k, k.h, k.session_id, 'D', kref);
            CHECK(memcmp(keys.s2c, kref, 64) == 0, "key D matches reference (alg %d K%d)", a, v);
            CHECK(memcmp(keys.c2s, keys.s2c, 32) != 0, "C and D differ");
            /* control: the other encoding gives other keys */
            ref_keys(m == KM_MPINT ? KM_STRING : KM_MPINT, k.k, k.h, k.session_id, 'C', kref);
            CHECK(v == 0 || memcmp(keys.c2s, kref, 64) != 0, "control: wrong K encoding changes keys");
            /* control: using H instead of session_id changes keys */
            ref_keys(m, k.k, k.h, k.h, 'C', kref);
            CHECK(memcmp(keys.c2s, kref, 64) != 0, "control: session_id is not H of kex #2");
        }
    }
    /* derive refuses without H / session id and zeroes out */
    fill_kat_kex(&k, ZSSH_KEXALG_CURVE25519, K[0]);
    memset(&keys, 0x77, sizeof keys);
    CHECK(zssh_kex_derive_keys(&k, &keys) == ZSSH_E_INTERNAL && is_zero(&keys, sizeof keys),
          "derive without H -> INTERNAL, out zeroed");
    /* compute_h refuses incomplete transcript */
    k.q_s_len = 31;
    CHECK(zssh_kex_compute_h(&k) == ZSSH_E_INTERNAL, "short Q_S -> INTERNAL");
    group_end("H and key-derivation known answers");
}

/* (3) hybrid round trip. */
static void hybrid_keys_and_wipe(void);

/* combiner computed from the primitives: SHA-256(mlkem_ss || x25519_raw) */
static void hybrid_combiner(const uint8_t *dk_copy, const uint8_t *sk_copy)
{
    uint8_t ss[32], x[32], cmb[32];
    struct sha256_ctx sc;
    CHECK(zcl_mlkem768_decaps(dk_copy, ZCL_MLKEM768_DECAPSULATION_KEY_SIZE, g_c.q_s, 1088, ss) == ZCL_MLKEM_OK,
          "decaps");
    CHECK(x25519_safe(x, sk_copy, g_c.q_s + 1088), "x25519");
    sha256_init(&sc); sha256_write(&sc, ss, 32); sha256_write(&sc, x, 32); sha256_finalize(&sc, cmb);
    CHECK(memcmp(cmb, g_c.k, 32) == 0, "K = SHA-256(mlkem_ss || x25519_ss)");
    sha256_init(&sc); sha256_write(&sc, x, 32); sha256_write(&sc, ss, 32); sha256_finalize(&sc, cmb);
    CHECK(memcmp(cmb, g_c.k, 32) != 0, "control: swapped combiner order differs");
}

static void group_hybrid_roundtrip(void)
{
    struct rng cr, sr;
    uint8_t dk_copy[ZCL_MLKEM768_DECAPSULATION_KEY_SIZE], sk_copy[32];
    group_begin();
    rng_init(&cr, 11); rng_init(&sr, 22);
    pair_setup(ZSSH_KEXALG_MLKEM768X25519);
    CHECK(do_init(&cr) == ZSSH_E_NONE, "hybrid client_init");
    CHECK(g_init_len == 1 + 4 + 1216 && g_init[0] == 30 && zssh_get_u32(g_init + 1) == 1216,
          "INIT blob is 1216 bytes");
    CHECK(g_c.q_c_len == ZSSH_QC_MLKEM_LEN && ZSSH_QC_MLKEM_LEN == 1216, "q_c 1216");
    CHECK(do_reply(&sr) == ZSSH_E_NONE, "hybrid server_reply");
    CHECK(g_reply[0] == 31 && g_s.q_s_len == 1120 && ZSSH_QS_MLKEM_LEN == 1120, "Q_S 1120");
    CHECK(zssh_get_u32(g_reply + 1) == 51 && zssh_get_u32(g_reply + 1 + 4 + 51) == 1120,
          "REPLY: K_S(51) then Q_S(1120)");
    CHECK(g_reply_len == 1 + 4 + 51 + 4 + 1120 + 4 + 83, "REPLY length");
    /* The ephemerals exist before finish; keep copies for the combiner check
     * because client_finish must wipe the fields themselves on success. */
    memcpy(dk_copy, g_c.mlkem_dk, sizeof dk_copy);
    memcpy(sk_copy, g_c.x25519_sk, sizeof sk_copy);
    CHECK(!is_zero(dk_copy, sizeof dk_copy) && !is_zero(sk_copy, 32), "ephemerals set before finish");
    CHECK(is_zero(g_s.x25519_sk, 32) && is_zero(g_s.mlkem_dk, sizeof g_s.mlkem_dk),
          "server reply leaves no ephemeral in the state");
    CHECK(do_finish() == ZSSH_E_NONE, "hybrid client_finish");
    CHECK(is_zero(g_c.x25519_sk, 32) && is_zero(g_c.mlkem_dk, sizeof g_c.mlkem_dk),
          "successful finish wipes the ephemeral sk and dk");
    CHECK(!is_zero(g_c.k, 32) && g_c.have_h, "success keeps K and H for CONN (wipe is CONN's duty)");
    CHECK(memcmp(g_c.k, g_s.k, 32) == 0 && !is_zero(g_c.k, 32), "equal K");
    CHECK(memcmp(g_c.h, g_s.h, 32) == 0 && !is_zero(g_c.h, 32), "equal H");
    CHECK(memcmp(g_c.session_id, g_s.session_id, 32) == 0, "equal session_id");
    hybrid_combiner(dk_copy, sk_copy);
    hybrid_keys_and_wipe();
    group_end("hybrid round trip");
}

static void hybrid_keys_and_wipe(void)
{
    struct zssh_keys kc, ks;
    uint8_t href[32];
    /* K enters H as a string: 00 00 00 20 || K (length prefix 32), not an mpint */
    ref_h(&g_c, KM_STRING, href);
    CHECK(memcmp(href, g_c.h, 32) == 0, "H uses string(K), length prefix 32");
    ref_h(&g_c, KM_MPINT, href);
    CHECK((g_c.k[0] & 0x80) == 0 && g_c.k[0] != 0 ? memcmp(href, g_c.h, 32) == 0 : memcmp(href, g_c.h, 32) != 0, "control: mpint(K) differs from string(K) exactly when K needs mpint padding/stripping");
    CHECK(zssh_kex_derive_keys(&g_c, &kc) == ZSSH_E_NONE && zssh_kex_derive_keys(&g_s, &ks) == ZSSH_E_NONE,
          "derive both");
    CHECK(memcmp(&kc, &ks, sizeof kc) == 0 && !is_zero(&kc, sizeof kc), "both sides derive equal keys");
    uint8_t kref[64];
    ref_keys(KM_STRING, g_c.k, g_c.h, g_c.session_id, 'C', kref);
    CHECK(memcmp(kc.c2s, kref, 64) == 0, "hybrid key C matches reference");
    ref_keys(KM_STRING, g_c.k, g_c.h, g_c.session_id, 'D', kref);
    CHECK(memcmp(kc.s2c, kref, 64) == 0, "hybrid key D matches reference");
    /* wipe */
    zssh_kex_wipe(&g_c);
    CHECK(is_zero(g_c.x25519_sk, 32) && is_zero(g_c.mlkem_dk, sizeof g_c.mlkem_dk) && is_zero(g_c.k, 32)
          && g_c.k_len == 0, "wipe clears secrets");
    CHECK(g_c.have_h && !is_zero(g_c.h, 32), "wipe keeps the transcript");
}

/* (4) KEXINIT build/parse and negotiation. */
static size_t craft_ki(uint8_t *buf, size_t cap, const char *kex, const char *host,
                       const char *enc, const char *comp, bool first)
{
    struct zssh_wr w;
    zssh_wr_init(&w, buf, cap);
    zssh_wr_u8(&w, 20);
    for (int i = 0; i < 16; i++) zssh_wr_u8(&w, (uint8_t)i);
    zssh_wr_cstr(&w, kex); zssh_wr_cstr(&w, host);
    zssh_wr_cstr(&w, enc); zssh_wr_cstr(&w, enc);
    zssh_wr_cstr(&w, "hmac-sha2-256"); zssh_wr_cstr(&w, "hmac-sha2-256");
    zssh_wr_cstr(&w, comp); zssh_wr_cstr(&w, comp);
    zssh_wr_cstr(&w, ""); zssh_wr_cstr(&w, "");
    zssh_wr_bool(&w, first); zssh_wr_u32(&w, 0);
    return w.off;
}
static enum zssh_error negotiate_raw(enum zssh_role role, uint32_t allowed, bool pq,
                                     const uint8_t *peer, size_t peer_len, struct zssh_neg *neg)
{
    struct zssh_kexinit_view v;
    struct zssh_kex_policy p = pol(role, allowed, pq);
    enum zssh_error e = zssh_kex_parse_kexinit(peer, peer_len, &v);
    if (e != ZSSH_E_NONE) return e;
    return zssh_kex_negotiate(&p, &v, neg);
}
static enum zssh_error negotiate_pair(enum zssh_role role, uint32_t allowed, bool pq,
                                      enum zssh_role prole, uint32_t pallowed, bool ppq,
                                      struct zssh_neg *neg)
{
    uint8_t peer[ZSSH_KEXINIT_MAX];
    size_t n = build_ki(prole, pallowed, ppq, peer, sizeof peer);
    CHECK(n > 0, "peer KEXINIT builds");
    return negotiate_raw(role, allowed, pq, peer, n, neg);
}

static bool contains(const uint8_t *h, size_t n, const char *s)
{
    size_t l = strlen(s);
    for (size_t i = 0; i + l <= n; i++) if (memcmp(h + i, s, l) == 0) return true;
    return false;
}

static size_t negotiation_expected_client_kexinit(uint8_t *exp)
{
    size_t en;
    {
        struct tb t = { .n = 0 };
        uint8_t ty = 20, ck[16], zero = 0;
        for (int i = 0; i < 16; i++) ck[i] = (uint8_t)(ZSSH_ROLE_CLIENT * 16 + i);
        tb_raw(&t, &ty, 1); tb_raw(&t, ck, 16);
        const char *l[10] = { "mlkem768x25519-sha256,curve25519-sha256,kex-strict-c-v00@openssh.com",
            "ssh-ed25519", "chacha20-poly1305@openssh.com", "chacha20-poly1305@openssh.com",
            "hmac-sha2-256", "hmac-sha2-256", "none", "none", "", "" };
        for (int i = 0; i < 10; i++) tb_str(&t, l[i], strlen(l[i]));
        tb_raw(&t, &zero, 1); tb_u32(&t, 0);
        en = t.n; memcpy(exp, t.b, t.n);
    }
    return en;
}

static void negotiation_client_kexinit_exact(void)
{
    uint8_t ki[ZSSH_KEXINIT_MAX], exp[ZSSH_KEXINIT_MAX];
    struct zssh_kexinit_view v;
    size_t n, en;
    /* exact bytes of a client KEXINIT, rebuilt independently */
    n = build_ki(ZSSH_ROLE_CLIENT, BOTH, false, ki, sizeof ki);
    en = negotiation_expected_client_kexinit(exp);
    CHECK(n == en && memcmp(ki, exp, en) == 0, "client KEXINIT bytes (hybrid first, strict-c last)");
    CHECK(zssh_kex_parse_kexinit(ki, n, &v) == ZSSH_E_NONE && !v.first_kex_packet_follows
          && zssh_namelist_has(v.list[ZSSH_KI_KEX], "kex-strict-c-v00@openssh.com")
          && !zssh_namelist_has(v.list[ZSSH_KI_KEX], "kex-strict-s-v00@openssh.com"), "parse own client KEXINIT");
}

static void negotiation_kexinit_markers(void)
{
    uint8_t ki[ZSSH_KEXINIT_MAX];
    size_t n;
    n = build_ki(ZSSH_ROLE_SERVER, BOTH, false, ki, sizeof ki);
    CHECK(contains(ki, n, "kex-strict-s-v00@openssh.com") && !contains(ki, n, "kex-strict-c-v00"),
          "server uses the -s- marker");
    n = build_ki(ZSSH_ROLE_CLIENT, BOTH, true, ki, sizeof ki);
    CHECK(n > 0 && !contains(ki, n, "curve25519") && contains(ki, n, "mlkem768x25519-sha256"),
          "require_pq offers no classical name anywhere");
    n = build_ki(ZSSH_ROLE_CLIENT, ZSSH_KEX_CURVE25519_SHA256, false, ki, sizeof ki);
    CHECK(n > 0 && !contains(ki, n, "mlkem"), "curve-only offers no hybrid");
}

static void negotiation_build_errors(void)
{
    uint8_t ki[ZSSH_KEXINIT_MAX];
    /* build errors */
    {
        struct zssh_kex_policy p = pol(ZSSH_ROLE_CLIENT, 0, false);
        uint8_t ck[16] = {0}; struct zssh_wr w; uint8_t small[40];
        zssh_wr_init(&w, ki, sizeof ki);
        CHECK(zssh_kex_build_kexinit(&p, ck, &w) == ZSSH_E_CONFIG, "allowed==0 -> CONFIG");
        p = pol(ZSSH_ROLE_CLIENT, ZSSH_KEX_CURVE25519_SHA256, true);
        zssh_wr_init(&w, ki, sizeof ki);
        CHECK(zssh_kex_build_kexinit(&p, ck, &w) == ZSSH_E_CONFIG, "require_pq without hybrid -> CONFIG");
        p = pol(ZSSH_ROLE_CLIENT, BOTH, false);
        zssh_wr_init(&w, small, sizeof small);
        CHECK(zssh_kex_build_kexinit(&p, ck, &w) == ZSSH_E_TOO_LARGE, "small buffer -> TOO_LARGE");
    }
}

static void negotiation_happy_paths(struct zssh_neg *neg)
{
    uint8_t ki[ZSSH_KEXINIT_MAX];
    size_t n;
    /* happy paths */
    CHECK(negotiate_pair(ZSSH_ROLE_SERVER, BOTH, false, ZSSH_ROLE_CLIENT, BOTH, false, neg) == ZSSH_E_NONE
          && neg->alg == ZSSH_KEXALG_MLKEM768X25519 && neg->strict, "both/both -> hybrid (server view)");
    CHECK(negotiate_pair(ZSSH_ROLE_CLIENT, BOTH, false, ZSSH_ROLE_SERVER, BOTH, false, neg) == ZSSH_E_NONE
          && neg->alg == ZSSH_KEXALG_MLKEM768X25519 && neg->strict, "both/both -> hybrid (client view)");
    CHECK(negotiate_pair(ZSSH_ROLE_CLIENT, ZSSH_KEX_CURVE25519_SHA256, false, ZSSH_ROLE_SERVER, BOTH, false, neg)
          == ZSSH_E_NONE && neg->alg == ZSSH_KEXALG_CURVE25519, "curve-only client / both server -> curve");
    CHECK(negotiate_pair(ZSSH_ROLE_CLIENT, BOTH, true, ZSSH_ROLE_SERVER, BOTH, false, neg) == ZSSH_E_NONE
          && neg->alg == ZSSH_KEXALG_MLKEM768X25519, "require_pq client / capable server -> hybrid");
    /* client order decides: crafted client lists curve first, server allows both */
    n = craft_ki(ki, sizeof ki, "curve25519-sha256,mlkem768x25519-sha256,kex-strict-c-v00@openssh.com",
                 "ssh-ed25519", "chacha20-poly1305@openssh.com", "none", false);
    CHECK(negotiate_raw(ZSSH_ROLE_SERVER, BOTH, false, ki, n, neg) == ZSSH_E_NONE
          && neg->alg == ZSSH_KEXALG_CURVE25519, "client's first supported name wins");
    CHECK(negotiate_raw(ZSSH_ROLE_SERVER, BOTH, true, ki, n, neg) == ZSSH_E_NONE
          && neg->alg == ZSSH_KEXALG_MLKEM768X25519, "server require_pq skips the classical name");
}

static void negotiation_refusals(struct zssh_neg *neg)
{
    uint8_t ki[ZSSH_KEXINIT_MAX];
    size_t n;
    /* refusals */
    CHECK(negotiate_pair(ZSSH_ROLE_CLIENT, ZSSH_KEX_MLKEM768X25519_SHA256, false, ZSSH_ROLE_SERVER,
                         ZSSH_KEX_CURVE25519_SHA256, false, neg) == ZSSH_E_KEX_NO_MATCH
          && neg->alg == ZSSH_KEXALG_NONE && !neg->strict, "no common algorithm -> KEX_NO_MATCH, out zeroed");
    CHECK(negotiate_pair(ZSSH_ROLE_CLIENT, BOTH, true, ZSSH_ROLE_SERVER, ZSSH_KEX_CURVE25519_SHA256, false,
                         neg) == ZSSH_E_KEX_NO_MATCH, "require_pq vs classical-only server -> refused");
    CHECK(negotiate_pair(ZSSH_ROLE_SERVER, BOTH, true, ZSSH_ROLE_CLIENT, ZSSH_KEX_CURVE25519_SHA256, false,
                         neg) == ZSSH_E_KEX_NO_MATCH, "require_pq server vs classical-only client -> refused");
    n = craft_ki(ki, sizeof ki, "mlkem768x25519-sha256,curve25519-sha256",
                 "ssh-ed25519", "chacha20-poly1305@openssh.com", "none", false);
    CHECK(negotiate_raw(ZSSH_ROLE_SERVER, BOTH, false, ki, n, neg) == ZSSH_E_STRICT_KEX_REQUIRED
          && neg->alg == ZSSH_KEXALG_NONE, "no strict marker -> STRICT_KEX_REQUIRED");
    n = craft_ki(ki, sizeof ki, "mlkem768x25519-sha256,kex-strict-s-v00@openssh.com",
                 "ssh-ed25519", "chacha20-poly1305@openssh.com", "none", false);
    CHECK(negotiate_raw(ZSSH_ROLE_SERVER, BOTH, false, ki, n, neg) == ZSSH_E_STRICT_KEX_REQUIRED,
          "wrong-role marker -> STRICT_KEX_REQUIRED");
    n = craft_ki(ki, sizeof ki, "mlkem768x25519-sha256,kex-strict-c-v00@openssh.com",
                 "ssh-ed25519", "chacha20-poly1305@openssh.com", "none", true);
    CHECK(negotiate_raw(ZSSH_ROLE_SERVER, BOTH, false, ki, n, neg) == ZSSH_E_PROTOCOL,
          "first_kex_packet_follows -> PROTOCOL");
    n = craft_ki(ki, sizeof ki, "mlkem768x25519-sha256,kex-strict-c-v00@openssh.com",
                 "ssh-ed25519", "aes128-ctr", "none", false);
    CHECK(negotiate_raw(ZSSH_ROLE_SERVER, BOTH, false, ki, n, neg) == ZSSH_E_KEX_NO_MATCH, "no cipher match");
    n = craft_ki(ki, sizeof ki, "mlkem768x25519-sha256,kex-strict-c-v00@openssh.com",
                 "ssh-rsa", "chacha20-poly1305@openssh.com", "none", false);
    CHECK(negotiate_raw(ZSSH_ROLE_SERVER, BOTH, false, ki, n, neg) == ZSSH_E_KEX_NO_MATCH, "no host key match");
    n = craft_ki(ki, sizeof ki, "mlkem768x25519-sha256,kex-strict-c-v00@openssh.com",
                 "ssh-ed25519", "chacha20-poly1305@openssh.com", "zlib", false);
    CHECK(negotiate_raw(ZSSH_ROLE_SERVER, BOTH, false, ki, n, neg) == ZSSH_E_KEX_NO_MATCH, "no 'none' compression");
    /* OpenSSH-shaped peer: extra names around ours are fine */
    n = craft_ki(ki, sizeof ki,
                 "sntrup761x25519-sha512,mlkem768x25519-sha256,curve25519-sha256,ext-info-c,kex-strict-c-v00@openssh.com",
                 "rsa-sha2-512,ssh-ed25519", "aes256-ctr,chacha20-poly1305@openssh.com", "none,zlib@openssh.com", false);
    CHECK(negotiate_raw(ZSSH_ROLE_SERVER, BOTH, false, ki, n, neg) == ZSSH_E_NONE
          && neg->alg == ZSSH_KEXALG_MLKEM768X25519, "OpenSSH-style client accepted");
}

static void negotiation_parse_errors(void)
{
    uint8_t ki[ZSSH_KEXINIT_MAX];
    struct zssh_kexinit_view v;
    size_t n;
    /* parse errors */
    n = build_ki(ZSSH_ROLE_CLIENT, BOTH, false, ki, sizeof ki);
    for (size_t cut = 0; cut < n; cut++)
        if (zssh_kex_parse_kexinit(ki, cut, &v) != ZSSH_E_PROTOCOL) {
            CHECK(false, "truncation at %zu not PROTOCOL", cut);
            break;
        }
    ki[n] = 0;
    CHECK(zssh_kex_parse_kexinit(ki, n + 1, &v) == ZSSH_E_PROTOCOL, "trailing byte -> PROTOCOL");
    ki[0] = 21;
    CHECK(zssh_kex_parse_kexinit(ki, n, &v) == ZSSH_E_PROTOCOL, "wrong type -> PROTOCOL");
    {
        static uint8_t big[ZSSH_KEXINIT_MAX + 1];
        big[0] = 20;
        CHECK(zssh_kex_parse_kexinit(big, sizeof big, &v) == ZSSH_E_TOO_LARGE, "oversize -> TOO_LARGE");
    }
    CHECK(strcmp(zssh_kex_alg_name(ZSSH_KEXALG_MLKEM768X25519), "mlkem768x25519-sha256") == 0
          && strcmp(zssh_kex_alg_name(ZSSH_KEXALG_CURVE25519), "curve25519-sha256") == 0
          && zssh_kex_alg_name(ZSSH_KEXALG_NONE)[0] == '\0', "alg names");
}

static void negotiation_msg_wait_states(void)
{
    /* message order predicate */
    CHECK(zssh_kex_msg_allowed(20, ZSSH_KP_WAIT_KEXINIT) && !zssh_kex_msg_allowed(2, ZSSH_KP_WAIT_KEXINIT)
          && !zssh_kex_msg_allowed(4, ZSSH_KP_WAIT_KEXINIT) && !zssh_kex_msg_allowed(30, ZSSH_KP_WAIT_KEXINIT)
          && zssh_kex_msg_allowed(1, ZSSH_KP_WAIT_KEXINIT), "WAIT_KEXINIT: only KEXINIT (+DISCONNECT)");
    CHECK(zssh_kex_msg_allowed(30, ZSSH_KP_WAIT_INIT) && !zssh_kex_msg_allowed(31, ZSSH_KP_WAIT_INIT)
          && !zssh_kex_msg_allowed(2, ZSSH_KP_WAIT_INIT), "WAIT_INIT: only 30");
    CHECK(zssh_kex_msg_allowed(31, ZSSH_KP_WAIT_REPLY) && !zssh_kex_msg_allowed(30, ZSSH_KP_WAIT_REPLY)
          && !zssh_kex_msg_allowed(7, ZSSH_KP_WAIT_REPLY), "WAIT_REPLY: only 31");
    CHECK(zssh_kex_msg_allowed(21, ZSSH_KP_WAIT_NEWKEYS) && !zssh_kex_msg_allowed(2, ZSSH_KP_WAIT_NEWKEYS)
          && !zssh_kex_msg_allowed(50, ZSSH_KP_WAIT_NEWKEYS), "WAIT_NEWKEYS: only 21");
}

static void negotiation_msg_done(void)
{
    CHECK(zssh_kex_msg_allowed(50, ZSSH_KP_DONE) && zssh_kex_msg_allowed(94, ZSSH_KP_DONE)
          && zssh_kex_msg_allowed(20, ZSSH_KP_DONE) && zssh_kex_msg_allowed(5, ZSSH_KP_DONE)
          && !zssh_kex_msg_allowed(21, ZSSH_KP_DONE) && !zssh_kex_msg_allowed(30, ZSSH_KP_DONE)
          && !zssh_kex_msg_allowed(31, ZSSH_KP_DONE) && !zssh_kex_msg_allowed(0, ZSSH_KP_DONE),
          "DONE: post-kex set, not 21/30/31");
}

static void negotiation_msg_done_exact(void)
{
    {
        static const uint8_t defined[] = { 2, 3, 4, 5, 6, 7, 20, 50, 51, 52, 53, 60,
                                           80, 81, 82, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100 };
        bool exact = true;
        for (unsigned m = 2; m < 256; m++) {
            bool want = false;
            for (size_t i = 0; i < sizeof defined; i++) want = want || defined[i] == m;
            if (zssh_kex_msg_allowed((uint8_t)m, ZSSH_KP_DONE) != want) exact = false;
        }
        CHECK(exact, "DONE admits exactly the defined numbers (not 83-89, 8-19, 54-59, 101+)");
        CHECK(!zssh_kex_msg_allowed(83, ZSSH_KP_DONE) && !zssh_kex_msg_allowed(89, ZSSH_KP_DONE),
              "DONE refuses undefined 83 and 89");
    }
}

static void group_negotiation(void)
{
    struct zssh_neg neg;
    group_begin();
    negotiation_client_kexinit_exact();
    negotiation_kexinit_markers();
    negotiation_build_errors();
    negotiation_happy_paths(&neg);
    negotiation_refusals(&neg);
    negotiation_parse_errors();
    negotiation_msg_wait_states();
    negotiation_msg_done();
    negotiation_msg_done_exact();
    group_end("KEXINIT, negotiation, message order");
}

/* (5) tampering and malformed input. */
static void tamper_baseline_exchange(uint8_t good_h[32])
{
    struct rng cr, sr;
    rng_init(&cr, 33); rng_init(&sr, 44);
    pair_setup(ZSSH_KEXALG_MLKEM768X25519);
    CHECK(do_init(&cr) == ZSSH_E_NONE && do_reply(&sr) == ZSSH_E_NONE && do_finish() == ZSSH_E_NONE,
          "baseline hybrid exchange");
    memcpy(good_h, g_c.h, 32);
}

static size_t tamper_fresh_reply(void)
{
    struct rng cr, sr;
    /* the successful finish consumed the client's ephemerals: redo the exchange */
    rng_init(&cr, 33); rng_init(&sr, 44);
    pair_setup(ZSSH_KEXALG_MLKEM768X25519);
    CHECK(do_init(&cr) == ZSSH_E_NONE && do_reply(&sr) == ZSSH_E_NONE, "fresh exchange for tamper");
    return g_reply_len;
}

static void tamper_ciphertext_flip(const uint8_t *good_h, size_t gl)
{
    uint8_t tampered[2048];
    size_t off_ct = 1 + 4 + 51 + 4;
    (void)good_h;
    memcpy(tampered, g_reply, gl);
    /* flipped ciphertext byte: implicit rejection -> different H -> signature fails */
    tampered[off_ct + 100] ^= 0x01;
    memcpy(g_reply, tampered, gl);
    g_verify_calls = 0;
    g_c.have_h = false; g_c.have_session_id = false;
    CHECK(do_finish() == ZSSH_E_HOST_SIG, "tampered ciphertext -> HOST_SIG");
#ifndef ZSSH_KEX_TEST_REAL_AUTH
    /* double-only: the real verifier is not instrumented (see the H check above) */
    CHECK(g_verify_calls == 1 && memcmp(g_verify_msg, good_h, 32) != 0, "verified H differs from the honest H");
#endif
    CHECK(is_zero(g_c.k, 32) && is_zero(g_c.h, 32) && is_zero(g_c.host_blob, sizeof g_c.host_blob)
          && !g_c.have_h && !g_c.have_session_id && is_zero(g_c.session_id, 32),
          "failure leaves K, H, session id, host blob zero");
    CHECK(is_zero(g_c.x25519_sk, 32) && is_zero(g_c.mlkem_dk, sizeof g_c.mlkem_dk), "failure wipes ephemerals");
}

static void tamper_other_flips(void)
{
    size_t off_ct = 1 + 4 + 51 + 4;
    /* the same flips elsewhere: X25519 half and signature */
    for (int which = 0; which < 2; which++) {
        struct rng cr2, sr2;
        rng_init(&cr2, 33); rng_init(&sr2, 44);
        pair_setup(ZSSH_KEXALG_MLKEM768X25519);
        CHECK(do_init(&cr2) == ZSSH_E_NONE && do_reply(&sr2) == ZSSH_E_NONE, "re-run");
        if (which == 0) g_reply[off_ct + 1088 + 5] ^= 0x40;       /* Q_S x25519 half */
        else g_reply[g_reply_len - 3] ^= 0x01;                    /* signature */
        CHECK(do_finish() == ZSSH_E_HOST_SIG, "tamper variant %d -> HOST_SIG", which);
    }
}

static void tamper_wrong_host_key(void)
{
    size_t off_ct = 1 + 4 + 51 + 4;
    /* wrong host key: refused BEFORE any key agreement or signature check */
    {
        struct rng cr2, sr2;
        rng_init(&cr2, 33); rng_init(&sr2, 44);
        pair_setup(ZSSH_KEXALG_MLKEM768X25519);
        CHECK(do_init(&cr2) == ZSSH_E_NONE && do_reply(&sr2) == ZSSH_E_NONE, "re-run");
        uint8_t other[32]; memcpy(other, HOST_PK, 32); other[5] ^= 1;
        g_verify_calls = 0;
        CHECK(zssh_kex_client_finish(&g_c, g_reply, g_reply_len, other) == ZSSH_E_HOST_KEY_MISMATCH,
              "pinned key differs -> HOST_KEY_MISMATCH");
        /* ORDER: same wrong pin, but Q_S carries the all-zero X25519 point, which the
         * agreement refuses with KEX_FAILED. If the pin compare ran AFTER the
         * agreement the error would be KEX_FAILED instead of HOST_KEY_MISMATCH. */
        rng_init(&cr2, 33); rng_init(&sr2, 44);
        pair_setup(ZSSH_KEXALG_MLKEM768X25519);
        CHECK(do_init(&cr2) == ZSSH_E_NONE && do_reply(&sr2) == ZSSH_E_NONE, "re-run");
        memset(g_reply + off_ct + 1088, 0, 32);
        CHECK(do_finish() == ZSSH_E_KEX_FAILED, "control: zero Q_S point with the right pin -> KEX_FAILED");
        rng_init(&cr2, 33); rng_init(&sr2, 44);
        pair_setup(ZSSH_KEXALG_MLKEM768X25519);
        CHECK(do_init(&cr2) == ZSSH_E_NONE && do_reply(&sr2) == ZSSH_E_NONE, "re-run");
        memset(g_reply + off_ct + 1088, 0, 32);
        CHECK(zssh_kex_client_finish(&g_c, g_reply, g_reply_len, other) == ZSSH_E_HOST_KEY_MISMATCH,
              "wrong pin is judged BEFORE the agreement (order)");
        rng_init(&cr2, 33); rng_init(&sr2, 44);
        pair_setup(ZSSH_KEXALG_MLKEM768X25519);
        CHECK(do_init(&cr2) == ZSSH_E_NONE && do_reply(&sr2) == ZSSH_E_NONE, "re-run");
        g_verify_calls = 0;
        CHECK(zssh_kex_client_finish(&g_c, g_reply, g_reply_len, other) == ZSSH_E_HOST_KEY_MISMATCH,
              "pinned key differs again -> HOST_KEY_MISMATCH");
        CHECK(g_verify_calls == 0 && g_c.q_s_len == 0 && is_zero(g_c.k, 32) && is_zero(g_c.h, 32) && !g_c.have_h && !g_c.have_session_id && is_zero(g_c.host_blob, sizeof g_c.host_blob), "valid signature but wrong pin: no math, no signature check, no H/K/session id kept");
    }
}

static void tamper_reply_truncation(size_t gl)
{
    /* truncated REPLY at every length, and trailing byte */
    for (size_t cut = 0; cut < gl; cut++) {
        struct rng cr2, sr2;
        rng_init(&cr2, 33); rng_init(&sr2, 44);
        pair_setup(ZSSH_KEXALG_MLKEM768X25519);
        if (do_init(&cr2) != ZSSH_E_NONE || do_reply(&sr2) != ZSSH_E_NONE) { CHECK(false, "re-run"); break; }
        g_reply_len = cut;
        if (do_finish() != ZSSH_E_PROTOCOL) { CHECK(false, "REPLY cut at %zu not PROTOCOL", cut); break; }
        if (cut > 600) cut += 97;   /* sample the bulk of the blob; every boundary near the ends */
    }
}

static void tamper_reply_trailing_byte(void)
{
    {
        struct rng cr2, sr2;
        rng_init(&cr2, 33); rng_init(&sr2, 44);
        pair_setup(ZSSH_KEXALG_MLKEM768X25519);
        CHECK(do_init(&cr2) == ZSSH_E_NONE && do_reply(&sr2) == ZSSH_E_NONE, "re-run");
        g_reply[g_reply_len++] = 0;
        CHECK(do_finish() == ZSSH_E_PROTOCOL, "trailing REPLY byte -> PROTOCOL");
        g_reply_len--; g_reply[0] = 30;
        CHECK(do_finish() == ZSSH_E_PROTOCOL, "REPLY with type 30 -> PROTOCOL");
    }
}

static void tamper_q_s_size(void)
{
    /* well-formed REPLY whose Q_S has the wrong size */
    {
        struct rng cr2, sr2;
        struct tb t = { .n = 0 };
        uint8_t ty = 31;
        rng_init(&cr2, 33); rng_init(&sr2, 44);
        pair_setup(ZSSH_KEXALG_MLKEM768X25519);
        CHECK(do_init(&cr2) == ZSSH_E_NONE && do_reply(&sr2) == ZSSH_E_NONE, "re-run");
        tb_raw(&t, &ty, 1);
        tb_str(&t, g_reply + 5, 51);
        tb_str(&t, g_reply + 1 + 4 + 51 + 4, 1119);
        tb_str(&t, g_reply + g_reply_len - 83, 83);
        memcpy(g_reply, t.b, t.n); g_reply_len = t.n;
        CHECK(do_finish() == ZSSH_E_PROTOCOL, "Q_S of 1119 bytes -> PROTOCOL");
    }
}

static void tamper_server_init(void)
{
    /* server side: malformed INIT */
    {
        struct rng cr2, sr2;
        uint8_t keep[2048]; size_t kl;
        rng_init(&cr2, 33);
        pair_setup(ZSSH_KEXALG_MLKEM768X25519);
        CHECK(do_init(&cr2) == ZSSH_E_NONE, "init");
        memcpy(keep, g_init, g_init_len); kl = g_init_len;
        for (size_t cut = 0; cut < kl; cut += (cut > 8 && cut < kl - 8) ? 211 : 1) {
            rng_init(&sr2, 44);
            struct zssh_wr w; zssh_wr_init(&w, g_reply, sizeof g_reply);
            if (zssh_kex_server_reply(&g_s, keep, cut, HOST_PK, HOST_SEED, rng_fn, &sr2, &w) != ZSSH_E_PROTOCOL
                || w.off != 0 || !is_zero(g_s.k, 32) || g_s.have_session_id) {
                CHECK(false, "INIT cut at %zu", cut); break;
            }
        }
        /* invalid ML-KEM encapsulation key (coefficient 4095 >= q) */
        memcpy(g_init, keep, kl); g_init_len = kl;
        g_init[5] = 0xff; g_init[6] = 0xff;
        rng_init(&sr2, 44);
        CHECK(do_reply(&sr2) == ZSSH_E_KEX_FAILED && g_reply_len == 0 && is_zero(g_s.k, 32)
              && is_zero(g_s.h, 32) && !g_s.have_session_id, "invalid ML-KEM ek -> KEX_FAILED, nothing kept");
        /* all-zero X25519 point inside the hybrid blob */
        memcpy(g_init, keep, kl);
        memset(g_init + 5 + 1184, 0, 32);
        rng_init(&sr2, 44);
        CHECK(do_reply(&sr2) == ZSSH_E_KEX_FAILED && g_reply_len == 0, "hybrid all-zero x25519 -> KEX_FAILED");
        /* wrong type byte */
        memcpy(g_init, keep, kl); g_init[0] = 31;
        rng_init(&sr2, 44);
        CHECK(do_reply(&sr2) == ZSSH_E_PROTOCOL, "INIT type 31 -> PROTOCOL");
    }
}

static void tamper_curve25519(void)
{
    /* curve25519: low-order points give an all-zero secret */
    {
        struct rng cr2, sr2;
        rng_init(&cr2, 5); rng_init(&sr2, 6);
        pair_setup(ZSSH_KEXALG_CURVE25519);
        CHECK(do_init(&cr2) == ZSSH_E_NONE, "curve init");
        memset(g_init + 5, 0, 32);
        CHECK(do_reply(&sr2) == ZSSH_E_KEX_FAILED && g_reply_len == 0, "zero point (server) -> KEX_FAILED");
        pair_setup(ZSSH_KEXALG_CURVE25519);
        rng_init(&cr2, 5); rng_init(&sr2, 6);
        CHECK(do_init(&cr2) == ZSSH_E_NONE && do_reply(&sr2) == ZSSH_E_NONE, "curve exchange");
        memset(g_reply + 1 + 4 + 51 + 4, 0, 32);
        CHECK(do_finish() == ZSSH_E_KEX_FAILED && is_zero(g_c.k, 32), "zero point (client) -> KEX_FAILED");
        pair_setup(ZSSH_KEXALG_CURVE25519);
        rng_init(&cr2, 5);
        CHECK(do_init(&cr2) == ZSSH_E_NONE, "curve init");
        g_init_len -= 1;
        rng_init(&sr2, 6);
        CHECK(do_reply(&sr2) == ZSSH_E_PROTOCOL, "short curve INIT -> PROTOCOL");
    }
}

static void group_tamper(void)
{
    uint8_t good_h[32];
    size_t gl;
    group_begin();
    tamper_baseline_exchange(good_h);
    gl = tamper_fresh_reply();
    tamper_ciphertext_flip(good_h, gl);
    tamper_other_flips();
    tamper_wrong_host_key();
    tamper_reply_truncation(gl);
    tamper_reply_trailing_byte();
    tamper_q_s_size();
    tamper_server_init();
    tamper_curve25519();
    group_end("tamper and malformed input");
}

/* (6) RNG failure fails closed. */
static void group_rng_failure(void)
{
    group_begin();
    for (unsigned at = 1; at <= 2; at++) {
        struct rng cr;
        struct zssh_wr w;
        uint8_t buf[2048];
        rng_init(&cr, 77); cr.fail_at = at;
        pair_setup(ZSSH_KEXALG_MLKEM768X25519);
        zssh_wr_init(&w, buf, sizeof buf);
        CHECK(zssh_kex_client_init(&g_c, rng_fn, &cr, &w) == ZSSH_E_RANDOM, "client rng fail @%u -> RANDOM", at);
        CHECK(w.off == 0 && !w.bad, "client @%u: nothing written to w", at);
        CHECK(is_zero(g_c.x25519_sk, 32) && is_zero(g_c.mlkem_dk, sizeof g_c.mlkem_dk) && g_c.q_c_len == 0,
              "client @%u: no secret retained", at);
    }
    {
        struct rng cr;
        struct zssh_wr w;
        uint8_t buf[2048];
        rng_init(&cr, 78); cr.fail_at = 1;
        pair_setup(ZSSH_KEXALG_CURVE25519);
        zssh_wr_init(&w, buf, sizeof buf);
        CHECK(zssh_kex_client_init(&g_c, rng_fn, &cr, &w) == ZSSH_E_RANDOM && w.off == 0
              && is_zero(g_c.x25519_sk, 32), "curve client rng fail -> RANDOM, sk zero");
    }
    for (unsigned at = 1; at <= 2; at++) {
        struct rng cr, sr;
        rng_init(&cr, 79); rng_init(&sr, 80); sr.fail_at = at;
        pair_setup(ZSSH_KEXALG_MLKEM768X25519);
        CHECK(do_init(&cr) == ZSSH_E_NONE, "init");
        CHECK(do_reply(&sr) == ZSSH_E_RANDOM, "server rng fail @%u -> RANDOM", at);
        CHECK(g_reply_len == 0 && is_zero(g_s.k, 32) && is_zero(g_s.h, 32) && !g_s.have_session_id
              && is_zero(g_s.session_id, 32) && is_zero(g_s.host_blob, sizeof g_s.host_blob),
              "server @%u: nothing secret, no reply, no session id", at);
    }
    group_end("RNG failure fails closed");
}

/* (7) A builder that overflows its writer fails with the typed error, rolls the
 * offset back to its entry value and leaves the writer bad (sticky). */
static void group_builder_overflow(void)
{
    group_begin();
    {
        struct rng cr;
        struct zssh_wr w;
        uint8_t buf[16];
        size_t start;
        enum zssh_error e;
        rng_init(&cr, 91);
        pair_setup(ZSSH_KEXALG_MLKEM768X25519);
        zssh_wr_init(&w, buf, sizeof buf);
        zssh_wr_u8(&w, 0x5A);
        start = w.off;
        e = zssh_kex_client_init(&g_c, rng_fn, &cr, &w);
        CHECK(e == ZSSH_E_TOO_LARGE, "client INIT does not fit -> TOO_LARGE");
        CHECK(w.off == start && !zssh_wr_ok(&w), "client INIT overflow: offset rolled back, writer stays bad");
    }
    {
        struct rng cr, sr;
        struct zssh_wr w;
        uint8_t buf[16];
        size_t start;
        enum zssh_error e;
        rng_init(&cr, 92); rng_init(&sr, 93);
        pair_setup(ZSSH_KEXALG_MLKEM768X25519);
        CHECK(do_init(&cr) == ZSSH_E_NONE, "init for overflow");
        zssh_wr_init(&w, buf, sizeof buf);
        zssh_wr_u8(&w, 0x5A);
        start = w.off;
        e = zssh_kex_server_reply(&g_s, g_init, g_init_len, HOST_PK, HOST_SEED, rng_fn, &sr, &w);
        CHECK(e == ZSSH_E_TOO_LARGE, "server REPLY does not fit -> TOO_LARGE");
        CHECK(w.off == start && !zssh_wr_ok(&w), "server REPLY overflow: offset rolled back, writer stays bad");
    }
    group_end("builder overflow rolls back and stays bad");
}

/* (7) Witness regressions: kex "both" against a classical-only OpenSSH peer. */
static bool kex_list_is(const uint8_t *ki, size_t n, const char *want)
{
    struct zssh_kexinit_view v;
    return zssh_kex_parse_kexinit(ki, n, &v) == ZSSH_E_NONE
        && v.list[ZSSH_KI_KEX].len == strlen(want)
        && memcmp(v.list[ZSSH_KI_KEX].p, want, v.list[ZSSH_KI_KEX].len) == 0;
}

static bool kex_list_has(const uint8_t *ki, size_t n, const char *name)
{
    struct zssh_kexinit_view v;
    return zssh_kex_parse_kexinit(ki, n, &v) == ZSSH_E_NONE
        && zssh_namelist_has(v.list[ZSSH_KI_KEX], name);
}

static void witness_require_pq_refused(void)
{
    struct zssh_neg neg;
    uint8_t ki[ZSSH_KEXINIT_MAX];
    size_t n = build_ki(ZSSH_ROLE_CLIENT, BOTH, true, ki, sizeof ki);
    CHECK(n > 0 && kex_list_is(ki, n, "mlkem768x25519-sha256,kex-strict-c-v00@openssh.com"),
          "witness A: require_pq client kex list is hybrid + strict only");
    CHECK(kex_list_has(ki, n, "mlkem768x25519-sha256")
          && !kex_list_has(ki, n, "curve25519-sha256")
          && !kex_list_has(ki, n, "curve25519-sha256@libssh.org"),
          "witness A: no classical curve25519 name offered");
    CHECK(negotiate_pair(ZSSH_ROLE_CLIENT, BOTH, true, ZSSH_ROLE_SERVER,
                         ZSSH_KEX_CURVE25519_SHA256, false, &neg) == ZSSH_E_KEX_NO_MATCH
          && neg.alg == ZSSH_KEXALG_NONE && !neg.strict,
          "witness A: require_pq vs classical-only peer -> KEX_NO_MATCH");
}

static void witness_classical_fallback(void)
{
    struct zssh_neg neg;
    uint8_t ki[ZSSH_KEXINIT_MAX];
    size_t n = build_ki(ZSSH_ROLE_CLIENT, BOTH, false, ki, sizeof ki);
    CHECK(n > 0 && kex_list_is(ki, n,
              "mlkem768x25519-sha256,curve25519-sha256,kex-strict-c-v00@openssh.com"),
          "witness B: kex both lists hybrid, then curve25519, then strict");
    CHECK(negotiate_pair(ZSSH_ROLE_CLIENT, BOTH, false, ZSSH_ROLE_SERVER,
                         ZSSH_KEX_CURVE25519_SHA256, false, &neg) == ZSSH_E_NONE
          && neg.alg == ZSSH_KEXALG_CURVE25519 && neg.strict
          && neg.alg != ZSSH_KEXALG_MLKEM768X25519
          && strcmp(zssh_kex_alg_name(neg.alg), "curve25519-sha256") == 0,
          "witness B: classical-only peer negotiates curve25519-sha256, not PQ");
}

static void witness_pq_control(void)
{
    struct zssh_neg neg;
    CHECK(negotiate_pair(ZSSH_ROLE_CLIENT, BOTH, true, ZSSH_ROLE_SERVER, BOTH, false, &neg)
              == ZSSH_E_NONE
          && neg.alg == ZSSH_KEXALG_MLKEM768X25519 && neg.strict
          && strcmp(zssh_kex_alg_name(neg.alg), "mlkem768x25519-sha256") == 0,
          "witness control: require_pq vs PQ-capable peer negotiates the hybrid");
}

static void group_witness_pq_policy(void)
{
    group_begin();
    witness_require_pq_refused();
    witness_classical_fallback();
    witness_pq_control();
    group_end("witness: kex both vs classical-only peer");
}

int main(void)
{
    init_host_key();
    group_curve_kat();
    group_h_keys_kat();
    group_hybrid_roundtrip();
    group_negotiation();
    group_witness_pq_policy();
    group_tamper();
    group_rng_failure();
    group_builder_overflow();
    printf("zssh_kex: %s (%d failed checks)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
