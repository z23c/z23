/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zssh — module end-to-end test. Two real engines (client, server) are
 * pumped against each other through in-memory FIFOs with a deterministic RNG.
 * The test links the real layers; nothing is doubled. It reaches inside
 * struct zssh_impl only to (a) seal hand-crafted packets with the real keys of
 * one engine (raw_send / raw_next), (b) snapshot and restore a pair, and
 * (c) assert that secrets are gone.
 *
 * Wire facts used (RFC 4253 6, plaintext framing before NEWKEYS): packet =
 * u32 packet_length | u8 padding_length | payload | padding, (4+len)%8 == 0. */

#include "../src/zssh_internal.h"
#include "base/serialize_le.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail, g_checks;
#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; \
    fprintf(stderr, "CHECK FAILED %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)
#define RUN(fn) do { int f0 = g_fail, c0 = g_checks; fn(); \
    printf("group %-26s %s (%d checks)\n", #fn, g_fail == f0 ? "ok" : "FAILED", \
           g_checks - c0); fflush(stdout); } while (0)

enum { CL = 0, SV = 1 };
#define IMPL(i) zssh_impl_of(&g_conn[i])

/* ---- deterministic RNG --------------------------------------------------- */
struct rng { uint64_t st; unsigned calls, fail_at; };

static bool rng_fn(void *ctx, uint8_t *out, size_t n)
{
    struct rng *r = ctx;
    r->calls++;
    if (r->fail_at != 0 && r->calls == r->fail_at) return false;
    for (size_t i = 0; i < n; i++) {
        uint64_t z = (r->st += 0x9e3779b97f4a7c15ull);
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
        uint8_t be[8];
        zcl_write_u64_be(be, z ^ (z >> 31));
        out[i] = be[4]; /* bits 24..31 of the mixed word */
    }
    return true;
}

/* ---- fixtures ------------------------------------------------------------ */
static uint8_t g_hseed[32], g_hpk[32], g_hseed2[32], g_hpk2[32];
static uint8_t g_useed[32], g_upk[32], g_useed2[32], g_upk2[32];
static struct zssh_conn g_conn[2];
static struct rng g_rng[2];

#define Q_CAP  (1u << 21)
#define OUTBUF 70000u
static uint8_t g_q[2][Q_CAP];
static size_t g_qh[2], g_qt[2];     /* g_q[d]: bytes engine d produced */
static uint8_t g_outbuf[OUTBUF + 512];

enum hmode { HM_NONE, HM_IGN_EARLY, HM_IGN_MID, HM_ZERO_QS, HM_FLIP_SIG, HM_BREAK_STRICT };
static enum hmode g_hm;

struct drive {
    size_t in_chunk, out_chunk;
    uint64_t produced[2], consumed[2], pushed[2];
    unsigned hook_calls[2];
    bool tamper_on; int tamper_dir; uint64_t tamper_at;
    bool rec_on; size_t reclen[2];
    uint8_t rec[2][16384];
};
static struct drive g_d;

static void fill_key(uint8_t *seed, uint8_t pk[32], uint8_t tag)
{
    uint8_t sk[32];
    for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(tag * 37 + i * 11 + 5);
    ed25519_keypair(pk, sk, seed);
}

static bool all_zero(const void *p, size_t n)
{
    const uint8_t *b = p;
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) acc |= b[i];
    return acc == 0;
}

/* ---- plaintext packet helpers (independent of the packet layer) ---------- */
static size_t after_version(const uint8_t *b, size_t n)
{
    if (n < 4 || memcmp(b, "SSH-", 4) != 0) return 0;
    for (size_t i = 0; i < n; i++)
        if (b[i] == '\n') return i + 1;
    return 0;
}

/* Client side: splice one SSH_MSG_IGNORE packet into the first flight. */
static size_t hook_insert_ignore(uint8_t *b, size_t n, size_t cap)
{
    if (g_d.hook_calls[CL]++ != 0) return n;
    size_t off = after_version(b, n);
    if (g_hm == HM_IGN_MID && off + 4 <= n) off += 4u + zssh_get_u32(b + off);
    static const uint8_t ign[16] = { 0, 0, 0, 12, 6, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    if (off > n || n + sizeof ign > cap) return n;
    memmove(b + off + sizeof ign, b + off, n - off);
    memcpy(b + off, ign, sizeof ign);
    return n + sizeof ign;
}

/* Server side: damage the KEX reply (31) in the chosen way. */
static void hook_damage_reply(uint8_t *b, size_t n)
{
    size_t off = after_version(b, n);
    while (off + 6 <= n) {
        uint32_t plen = zssh_get_u32(b + off);
        if (b[off + 5] == 21) break;
        if (b[off + 5] == 31) {
            uint8_t *pl = b + off + 5;
            size_t pn = plen - 1u - b[off + 4];
            size_t qo = 1u + 4u + zssh_get_u32(pl + 1);
            size_t ql = zssh_get_u32(pl + qo);
            if (g_hm == HM_ZERO_QS) memset(pl + qo + 4 + ql - 32, 0, 32);
            else pl[pn - 1] ^= 1;
            break;
        }
        off += 4u + plen;
    }
}

static size_t hook(int who, uint8_t *b, size_t n, size_t cap)
{
    if ((g_hm == HM_IGN_EARLY || g_hm == HM_IGN_MID) && who == CL)
        return hook_insert_ignore(b, n, cap);
    if (who != SV) return n;
    if (g_hm == HM_BREAK_STRICT) {
        static const char s[] = "kex-strict-s-v00@openssh.com";
        for (size_t i = 0; i + sizeof s <= n; i++)
            if (memcmp(b + i, s, sizeof s - 1u) == 0) { b[i + 15] = '1'; break; }
        return n;
    }
    if (g_hm == HM_ZERO_QS || g_hm == HM_FLIP_SIG) hook_damage_reply(b, n);
    return n;
}

/* ---- transport driver ---------------------------------------------------- */
static void q_push(int d, const uint8_t *p, size_t n)
{
    if (g_qh[d] == g_qt[d]) g_qh[d] = g_qt[d] = 0;
    if (g_qt[d] + n > Q_CAP) {
        memmove(g_q[d], g_q[d] + g_qh[d], g_qt[d] - g_qh[d]);
        g_qt[d] -= g_qh[d];
        g_qh[d] = 0;
    }
    CHECK(g_qt[d] + n <= Q_CAP);
    memcpy(g_q[d] + g_qt[d], p, n);
    g_qt[d] += n;
}

/* Apply the hook, tamper and recorder to prod bytes in g_outbuf, then queue. */
static void step_publish(int who, size_t prod)
{
    size_t np = g_hm != HM_NONE ? hook(who, g_outbuf, prod, sizeof g_outbuf) : prod;
    if (g_d.tamper_on && g_d.tamper_dir == who && g_d.tamper_at >= g_d.pushed[who] &&
        g_d.tamper_at < g_d.pushed[who] + np)
        g_outbuf[g_d.tamper_at - g_d.pushed[who]] ^= 0x10;
    if (g_d.rec_on && g_d.reclen[who] + np <= sizeof g_d.rec[who]) {
        memcpy(g_d.rec[who] + g_d.reclen[who], g_outbuf, np);
        g_d.reclen[who] += np;
    }
    g_d.pushed[who] += np;
    q_push(who, g_outbuf, np);
}

/* One pump of engine `who`, with every count of the call checked. */
static bool step(int who)
{
    struct zssh_conn *c = &g_conn[who];
    int peer = 1 - who;
    size_t avail = g_qt[peer] - g_qh[peer];
    size_t inl = avail < g_d.in_chunk ? avail : g_d.in_chunk;
    size_t ocap = g_d.out_chunk < OUTBUF ? g_d.out_chunk : OUTBUF;
    size_t cons = 777777, prod = 777777;
    enum zssh_status st = zssh_pump(c, inl ? g_q[peer] + g_qh[peer] : nullptr, inl, &cons,
                                    g_outbuf, ocap, &prod);
    CHECK(st != ZSSH_STATUS_BAD_CALL);
    CHECK(cons <= inl);
    CHECK(prod <= ocap);
    const uint8_t *pp = nullptr;
    size_t pn = 0;
    CHECK(zssh_output_peek(c, &pp, &pn) == ZSSH_OK && pp != nullptr);
    CHECK(prod == ocap || pn == 0);          /* copy takes min(out_cap, pending) */
    if (cons < inl)
        CHECK(st == ZSSH_NEED_OUTPUT || st == ZSSH_STATUS_FAILED || st == ZSSH_CLOSED);
    if (zssh_state(c) == ZSSH_STATE_FAILED) CHECK(st == ZSSH_STATUS_FAILED);
    g_d.consumed[who] += cons;
    g_d.produced[who] += prod;
    g_qh[peer] += cons;
    if (prod > 0) step_publish(who, prod);
    return cons + prod > 0;
}

static void run_quiet(void)
{
    for (unsigned long i = 0; i < 80000000ul; i++) {
        bool a = step(CL);
        bool b = step(SV);
        if (!a && !b) return;
    }
    CHECK(!"run_quiet did not converge");
}

struct opt {
    uint32_t kc, ks; bool pq_c, pq_s;
    const uint8_t *pin, *useed;
    const char *cuser, *suser, *scomment;
    unsigned salt;
};
static void opt_default(struct opt *o)
{
    memset(o, 0, sizeof *o);
    o->kc = o->ks = ZSSH_KEX_MLKEM768X25519_SHA256 | ZSSH_KEX_CURVE25519_SHA256;
    o->pin = g_hpk; o->useed = g_useed; o->cuser = o->suser = "relay";
}

static int g_arm_who = -1;          /* RNG fault armed before init: engine, call index */
static unsigned g_arm_n;

static void pair_init(const struct opt *o, size_t in_chunk, size_t out_chunk)
{
    memset(&g_d, 0, sizeof g_d);
    g_d.in_chunk = in_chunk;
    g_d.out_chunk = out_chunk;
    g_hm = HM_NONE;
    g_qh[0] = g_qh[1] = g_qt[0] = g_qt[1] = 0;
    g_rng[0] = (struct rng){ 0x1111u + o->salt, 0, 0 };
    g_rng[1] = (struct rng){ 0x2222u + o->salt, 0, 0 };
    if (g_arm_who >= 0) g_rng[g_arm_who].fail_at = g_arm_n;
    struct zssh_config cc = { .role = ZSSH_ROLE_CLIENT, .rand = rng_fn, .rand_ctx = &g_rng[CL],
        .pinned_host_pk = o->pin, .user_seed = o->useed, .user = o->cuser,
        .kex_allowed = o->kc, .require_pq = o->pq_c };
    struct zssh_config sc = { .role = ZSSH_ROLE_SERVER, .rand = rng_fn, .rand_ctx = &g_rng[SV],
        .host_seed = g_hseed, .authorized_user_pk = g_upk, .user = o->suser,
        .kex_allowed = o->ks, .require_pq = o->pq_s, .version_comment = o->scomment };
    enum zssh_result a = zssh_init(&g_conn[CL], &cc);
    enum zssh_result b = zssh_init(&g_conn[SV], &sc);
    CHECK(a == ZSSH_OK || g_arm_who == CL);
    CHECK(b == ZSSH_OK || g_arm_who == SV);
}

static bool both_state(enum zssh_state s)
{
    return zssh_state(&g_conn[CL]) == s && zssh_state(&g_conn[SV]) == s;
}

static bool handshake(const struct opt *o, size_t in_chunk, size_t out_chunk)
{
    pair_init(o, in_chunk, out_chunk);
    run_quiet();
    return both_state(ZSSH_STATE_CHANNEL);
}

static void kex_secrets_gone(int i)
{
    struct zssh_impl *s = IMPL(i);
    CHECK(all_zero(s->kex.x25519_sk, sizeof s->kex.x25519_sk));
    CHECK(all_zero(s->kex.mlkem_dk, sizeof s->kex.mlkem_dk));
    CHECK(all_zero(s->kex.k, sizeof s->kex.k));
}

static void all_secrets_gone(int i)
{
    struct zssh_impl *s = IMPL(i);
    kex_secrets_gone(i);
    CHECK(all_zero(s->host_seed, sizeof s->host_seed));
    CHECK(all_zero(s->user_seed, sizeof s->user_seed));
    CHECK(all_zero(s->tx.key, sizeof s->tx.key));
    CHECK(all_zero(s->rx.key, sizeof s->rx.key));
    CHECK(all_zero(s->rxbuf, sizeof s->rxbuf));
}

/* ---- snapshots (test-only copies of live engines) ------------------------ */
#define SNAPQ 8192u
struct snap {
    struct zssh_conn c[2];
    struct rng r[2];
    uint8_t q[2][SNAPQ];
    size_t ql[2];
};
static struct snap g_snap[2];
static struct drive g_snapdrive[2];

static void snap_take(int k)
{
    struct snap *s = &g_snap[k];
    memcpy(s->c, g_conn, sizeof g_conn);
    memcpy(s->r, g_rng, sizeof g_rng);
    memcpy(&g_snapdrive[k], &g_d, sizeof g_d);
    for (int d = 0; d < 2; d++) {
        s->ql[d] = g_qt[d] - g_qh[d];
        CHECK(s->ql[d] <= SNAPQ);
        if (s->ql[d] <= SNAPQ) memcpy(s->q[d], g_q[d] + g_qh[d], s->ql[d]);
    }
}

static void snap_restore(int k)
{
    const struct snap *s = &g_snap[k];
    memcpy(g_conn, s->c, sizeof g_conn);
    memcpy(g_rng, s->r, sizeof g_rng);
    memcpy(&g_d, &g_snapdrive[k], sizeof g_d);
    for (int d = 0; d < 2; d++) {
        memcpy(g_q[d], s->q[d], s->ql[d]);
        g_qh[d] = 0;
        g_qt[d] = s->ql[d];
    }
    g_hm = HM_NONE;
}

/* ---- raw packets with a real engine's keys ------------------------------- */
static uint8_t g_raw[ZSSH_MAX_PACKET + 64];

static void raw_send(int from, const uint8_t *pl, size_t n)
{
    struct zssh_impl *s = IMPL(from);
    struct zssh_wr w;
    CHECK(zssh_conn_begin(s, &w) == ZSSH_E_NONE);
    zssh_wr_bytes(&w, pl, n);
    CHECK(zssh_conn_commit(s, &w) == ZSSH_E_NONE);
    const uint8_t *p = nullptr;
    size_t pn = 0;
    zssh_txq_peek(&s->txq, &p, &pn);
    q_push(from, p, pn);
    CHECK(zssh_txq_consume(&s->txq, pn));
}

/* Open the next packet of g_q[from] with engine rx_side's receive direction. */
static bool raw_next(int rx_side, int from, size_t *plen)
{
    struct zssh_impl *s = IMPL(rx_side);
    size_t avail = g_qt[from] - g_qh[from];
    size_t total = 0;
    if (avail < 4) return false;
    uint8_t *b = g_q[from] + g_qh[from];
    if (zssh_pkt_peek_total(&s->rx, b, &total) != ZSSH_E_NONE || avail < total) return false;
    const uint8_t *pl = nullptr;
    size_t pn = 0;
    if (zssh_pkt_open(&s->rx, b, total, &pl, &pn) != ZSSH_E_NONE) return false;
    memcpy(g_raw, pl, pn);
    *plen = pn;
    g_qh[from] += total;
    return true;
}

/* ======================================================================== *
 * groups                                                                   *
 * ======================================================================== */

static void g_null_args(void)
{
    struct zssh_conn c;
    struct zssh_config cfg = { 0 };
    size_t n = 5;
    CHECK(zssh_state(nullptr) == ZSSH_STATE_FAILED);
    CHECK(zssh_error(nullptr) == ZSSH_E_INTERNAL);
    CHECK(zssh_init(nullptr, &cfg) == ZSSH_BAD_CALL);
    memset(&c, 0x5a, sizeof c);
    CHECK(zssh_init(&c, nullptr) == ZSSH_BAD_CALL);
    CHECK(((uint8_t *)&c)[0] == 0x5a && ((uint8_t *)&c)[sizeof c - 1] == 0x5a);
    CHECK(zssh_input(nullptr, nullptr, 0, &n) == ZSSH_STATUS_BAD_CALL && n == 0);
    CHECK(zssh_transport_eof(nullptr) == ZSSH_BAD_CALL);
    zssh_wipe(nullptr);
    CHECK(strcmp(zssh_state_name(ZSSH_STATE_CHANNEL), "CHANNEL") == 0);
    CHECK(strcmp(zssh_error_name(ZSSH_E_MAC), "MAC") == 0);
    CHECK(strcmp(zssh_error_name((enum zssh_error)999), "UNKNOWN") == 0);
    CHECK(strcmp(zssh_state_name((enum zssh_state)99), "UNKNOWN") == 0);
}

static void init_expect_config(const struct zssh_config *cfg)
{
    struct zssh_conn *c = &g_conn[0];
    CHECK(zssh_init(c, cfg) == ZSSH_FAILED);
    CHECK(zssh_state(c) == ZSSH_STATE_FAILED);
    CHECK(zssh_error(c) == ZSSH_E_CONFIG);
    const uint8_t *p; size_t n = 9;
    CHECK(zssh_output_peek(c, &p, &n) == ZSSH_OK && n == 0);
    all_secrets_gone(0);
}

static void g_init_refusals(void)
{
    struct zssh_config ok = { .role = ZSSH_ROLE_CLIENT, .rand = rng_fn, .rand_ctx = &g_rng[0],
        .pinned_host_pk = g_hpk, .user_seed = g_useed, .user = "relay", .kex_allowed = 3 };
    struct zssh_config sok = { .role = ZSSH_ROLE_SERVER, .rand = rng_fn, .rand_ctx = &g_rng[0],
        .host_seed = g_hseed, .authorized_user_pk = g_upk, .user = "relay", .kex_allowed = 3 };
    struct zssh_config c;
    char longuser[ZSSH_MAX_USER + 2];
    memset(longuser, 'u', sizeof longuser - 1u);
    longuser[sizeof longuser - 1u] = 0;
    g_rng[0] = (struct rng){ 1, 0, 0 };

    c = ok; c.rand = nullptr; init_expect_config(&c);
    c = ok; c.role = (enum zssh_role)7; init_expect_config(&c);
    c = ok; c.host_seed = g_hseed; init_expect_config(&c);        /* both blocks */
    c = ok; c.pinned_host_pk = nullptr; init_expect_config(&c);
    c = ok; c.user = longuser; init_expect_config(&c);
    c = ok; c.kex_allowed = 0; init_expect_config(&c);
    c = ok; c.kex_allowed = 8; init_expect_config(&c);
    c = ok; c.kex_allowed = ZSSH_KEX_CURVE25519_SHA256; c.require_pq = true; init_expect_config(&c);
    c = ok; c.version_comment = "bad\r\ncomment"; init_expect_config(&c);
    c = sok; c.user_seed = g_useed; init_expect_config(&c);
    c = sok; c.authorized_user_pk = nullptr; init_expect_config(&c);
    c = sok; c.pinned_host_pk = g_hpk; init_expect_config(&c);

    /* empty / NULL user, either role: BAD_CALL, conn untouched; control: a
     * normal user inits OK */
    {
        struct zssh_conn *bc = &g_conn[0];
        const struct zssh_config *cs[2] = { &ok, &sok };
        for (int i = 0; i < 2; i++) {
            struct zssh_config u = *cs[i];
            memset(bc, 0x5a, sizeof *bc);
            u.user = "";
            CHECK(zssh_init(bc, &u) == ZSSH_BAD_CALL);
            CHECK(((uint8_t *)bc)[0] == 0x5a && ((uint8_t *)bc)[sizeof *bc - 1] == 0x5a);
            u.user = nullptr;
            CHECK(zssh_init(bc, &u) == ZSSH_BAD_CALL);
            CHECK(((uint8_t *)bc)[0] == 0x5a && ((uint8_t *)bc)[sizeof *bc - 1] == 0x5a);
            u.user = "relay";
            g_rng[0] = (struct rng){ 1, 0, 0 };
            CHECK(zssh_init(bc, &u) == ZSSH_OK);
        }
        g_rng[0] = (struct rng){ 1, 0, 0 };
    }

    /* success: identification line first, exactly as documented */
    struct zssh_conn *cn = &g_conn[0];
    c = ok; c.version_comment = "cmt 1";
    g_rng[0] = (struct rng){ 1, 0, 0 };
    CHECK(zssh_init(cn, &c) == ZSSH_OK);
    const uint8_t *p = nullptr; size_t n = 0;
    CHECK(zssh_output_peek(cn, &p, &n) == ZSSH_OK);
    static const char want[] = "SSH-2.0-zssh_1 cmt 1\r\n";
    CHECK(n > sizeof want - 1u && memcmp(p, want, sizeof want - 1u) == 0);
    CHECK(zssh_state(cn) == ZSSH_STATE_VERSION && zssh_error(cn) == ZSSH_E_NONE);
    /* RNG failure at init (the cookie) */
    g_rng[0] = (struct rng){ 1, 0, 1 };
    CHECK(zssh_init(cn, &c) == ZSSH_FAILED);
    CHECK(zssh_error(cn) == ZSSH_E_RANDOM && zssh_state(cn) == ZSSH_STATE_FAILED);
    CHECK(zssh_output_peek(cn, &p, &n) == ZSSH_OK && n == 0);
    all_secrets_gone(0);
    g_rng[0] = (struct rng){ 1, 0, 2 };               /* the padding draw */
    CHECK(zssh_init(cn, &c) == ZSSH_FAILED && zssh_error(cn) == ZSSH_E_RANDOM);
    CHECK(zssh_output_peek(cn, &p, &n) == ZSSH_OK && n == 0);
}

/* ---- version exchange ----------------------------------------------------- */
static void fresh(int role_idx, enum zssh_role role)
{
    g_rng[role_idx] = (struct rng){ 77, 0, 0 };
    struct zssh_config cfg = { .role = role, .rand = rng_fn, .rand_ctx = &g_rng[role_idx],
        .kex_allowed = 3, .user = "relay" };
    if (role == ZSSH_ROLE_SERVER) { cfg.host_seed = g_hseed; cfg.authorized_user_pk = g_upk; }
    else { cfg.pinned_host_pk = g_hpk; cfg.user_seed = g_useed; }
    CHECK(zssh_init(&g_conn[role_idx], &cfg) == ZSSH_OK);
}

static enum zssh_status feed_all(int i, const char *s, size_t n, size_t *consumed)
{
    return zssh_input(&g_conn[i], (const uint8_t *)s, n, consumed);
}

static void version_fails(int i, enum zssh_role role, const char *s, size_t n)
{
    size_t c = 0;
    fresh(i, role);
    CHECK(feed_all(i, s, n, &c) == ZSSH_STATUS_FAILED);
    CHECK(zssh_error(&g_conn[i]) == ZSSH_E_VERSION);
    CHECK(c <= n);
    size_t c2 = 99;
    CHECK(feed_all(i, "x", 1, &c2) == ZSSH_STATUS_FAILED && c2 == 0);   /* sticky */
    CHECK(zssh_error(&g_conn[i]) == ZSSH_E_VERSION);
}

static void g_version(void)
{
    char big[600];
    size_t c = 0;
    memset(big, 'A', sizeof big);
    version_fails(SV, ZSSH_ROLE_SERVER, big, 300);                       /* no LF, too long */
    version_fails(SV, ZSSH_ROLE_SERVER, "SSH-1.99-x\r\n", 12);
    version_fails(SV, ZSSH_ROLE_SERVER, "SSH-2.0-x\n", 10);              /* bare LF */
    version_fails(SV, ZSSH_ROLE_SERVER, "hello\r\n", 7);                 /* server: no banner text */
    version_fails(SV, ZSSH_ROLE_SERVER, "SSH-2.0-a\x01z\r\n", 13);       /* control byte */
    version_fails(CL, ZSSH_ROLE_CLIENT, "SSH-2.0-\r\n", 10);             /* empty software */

    /* exactly 255 bytes with CRLF is fine, 256 is not */
    memcpy(big, "SSH-2.0-", 8);
    memset(big + 8, 'a', 245);
    memcpy(big + 253, "\r\n", 2);
    fresh(SV, ZSSH_ROLE_SERVER);
    CHECK(feed_all(SV, big, 255, &c) != ZSSH_STATUS_FAILED && c == 255);
    CHECK(zssh_state(&g_conn[SV]) == ZSSH_STATE_KEX);
    CHECK(IMPL(SV)->peer_version_len == 253);
    memcpy(big + 254, "\r\n", 2);
    version_fails(SV, ZSSH_ROLE_SERVER, big, 256);

    /* client: up to 16 pre-banner lines */
    char lines[17 * 8 + 32];
    size_t o = 0;
    for (int n = 0; n < 16; n++) o += (size_t)snprintf(lines + o, 9, "junk%02d\r\n", n);
    memcpy(lines + o, "SSH-2.0-t\r\n", 11);
    fresh(CL, ZSSH_ROLE_CLIENT);
    CHECK(feed_all(CL, lines, o + 11, &c) != ZSSH_STATUS_FAILED && c == o + 11);
    CHECK(zssh_state(&g_conn[CL]) == ZSSH_STATE_KEX);
    CHECK(strcmp((const char *)IMPL(CL)->peer_version, "SSH-2.0-t") == 0);
    o = 0;
    for (int n = 0; n < 17; n++) o += (size_t)snprintf(lines + o, 9, "junk%02d\r\n", n);
    version_fails(CL, ZSSH_ROLE_CLIENT, lines, o);

    /* one byte at a time gives the same result and exact counts */
    fresh(CL, ZSSH_ROLE_CLIENT);
    const char v[] = "SSH-2.0-OpenSSH_10.0\r\n";
    for (size_t i = 0; i + 1 < sizeof v; i++) {
        CHECK(feed_all(CL, v + i, 1, &c) != ZSSH_STATUS_FAILED && c == 1);
    }
    CHECK(zssh_state(&g_conn[CL]) == ZSSH_STATE_KEX);
    CHECK(strcmp((const char *)IMPL(CL)->peer_version, "SSH-2.0-OpenSSH_10.0") == 0);

    /* first packet with an absurd length: consumed counts up to the fatal byte */
    fresh(SV, ZSSH_ROLE_SERVER);
    const uint8_t junk[] = "SSH-2.0-t\r\nAAAAAAAA";
    c = 0;
    CHECK(zssh_input(&g_conn[SV], junk, sizeof junk - 1u, &c) == ZSSH_STATUS_FAILED);
    CHECK(c == 11 + 4);
    CHECK(zssh_error(&g_conn[SV]) == ZSSH_E_TOO_LARGE);
}

/* ---- handshake matrix ------------------------------------------------------ */
static void expect_session(const char *kexname, bool pq, const char *peer_ver_prefix)
{
    struct zssh_session_info a, b;
    uint8_t blob[ZSSH_ED25519_BLOB_LEN], fp[32];
    struct sha256_ctx h;
    memcpy(blob, "\0\0\0\x0bssh-ed25519\0\0\0\x20", 19);
    memcpy(blob + 19, g_hpk, 32);
    sha256_init(&h); sha256_write(&h, blob, sizeof blob); sha256_finalize(&h, fp);
    CHECK(zssh_session_info_get(&g_conn[CL], &a) == ZSSH_OK && a.valid);
    CHECK(zssh_session_info_get(&g_conn[SV], &b) == ZSSH_OK && b.valid);
    CHECK(strcmp(a.kex_name, kexname) == 0 && strcmp(b.kex_name, kexname) == 0);
    CHECK(a.post_quantum == pq && b.post_quantum == pq);
    CHECK(a.strict_kex && b.strict_kex && a.kex_generation == 0);
    CHECK(memcmp(a.host_key, g_hpk, 32) == 0 && memcmp(b.host_key, g_hpk, 32) == 0);
    CHECK(memcmp(a.host_key_sha256, fp, 32) == 0 && memcmp(b.host_key_sha256, fp, 32) == 0);
    CHECK(strncmp(a.peer_version, peer_ver_prefix, strlen(peer_ver_prefix)) == 0);
    CHECK(strncmp(b.peer_version, "SSH-2.0-zssh_1", 14) == 0);
}

static void ready_checks(void)
{
    for (int i = 0; i < 2; i++) {
        struct zssh_channel_flags f = {0};
        CHECK(zssh_channel_flags_get(&g_conn[i], &f) == ZSSH_OK);
        CHECK(!f.sent_eof && !f.recv_eof && !f.sent_close && !f.recv_close);
        CHECK(f.send_window == ZSSH_CHAN_WINDOW && f.recv_window == ZSSH_CHAN_WINDOW);
        kex_secrets_gone(i);
        CHECK(IMPL(i)->tx.kind == ZSSH_CIPHER_CHACHA20_POLY1305 && IMPL(i)->rx.kind == ZSSH_CIPHER_CHACHA20_POLY1305);
        CHECK(!all_zero(IMPL(i)->tx.key, 64) && !all_zero(IMPL(i)->rx.key, 64));
        /* strict KEX: sequence numbers restarted at NEWKEYS, so after the
         * handshake each side has exchanged exactly three packets under the
         * new keys (SERVICE_*, USERAUTH_*, CHANNEL_OPEN*). */
        CHECK(IMPL(i)->tx.seq == 3);
        CHECK(IMPL(i)->rx.seq == 3);
        size_t c = 9, p = 9;
        CHECK(zssh_pump(&g_conn[i], nullptr, 0, &c, nullptr, 0, &p) == ZSSH_CHANNEL_READY);
        CHECK(c == 0 && p == 0);
    }
    CHECK(IMPL(CL)->authenticated && IMPL(SV)->authenticated);
}

static void g_handshake_matrix(void)
{
    struct opt o;
    const uint32_t H = ZSSH_KEX_MLKEM768X25519_SHA256, C = ZSSH_KEX_CURVE25519_SHA256;
    /* both allowed: hybrid wins */
    opt_default(&o);
    CHECK(handshake(&o, 1u << 20, 65536));
    expect_session("mlkem768x25519-sha256", true, "SSH-2.0-zssh_1");
    ready_checks();
    /* require_pq on both */
    opt_default(&o); o.pq_c = o.pq_s = true;
    CHECK(handshake(&o, 1u << 20, 65536));
    expect_session("mlkem768x25519-sha256", true, "SSH-2.0-zssh_1");
    /* classical only */
    opt_default(&o); o.kc = o.ks = C;
    CHECK(handshake(&o, 1u << 20, 65536));
    expect_session("curve25519-sha256", false, "SSH-2.0-zssh_1");
    ready_checks();
    /* client offers both, server classical only */
    opt_default(&o); o.ks = C;
    CHECK(handshake(&o, 1u << 20, 65536));
    expect_session("curve25519-sha256", false, "SSH-2.0-zssh_1");
    /* comment shows up in the peer version */
    opt_default(&o); o.scomment = "relay-test"; o.kc = o.ks = H;
    CHECK(handshake(&o, 1u << 20, 65536));
    struct zssh_session_info a;
    CHECK(zssh_session_info_get(&g_conn[CL], &a) == ZSSH_OK);
    CHECK(strcmp(a.peer_version, "SSH-2.0-zssh_1 relay-test") == 0);
    /* session info is not valid before the key exchange completed */
    opt_default(&o);
    pair_init(&o, 1u << 20, 65536);
    CHECK(zssh_session_info_get(&g_conn[CL], &a) == ZSSH_OK && !a.valid);
    /* wipe: info gone, state terminal */
    run_quiet();
    zssh_wipe(&g_conn[CL]);
    CHECK(zssh_session_info_get(&g_conn[CL], &a) == ZSSH_OK && !a.valid);
    CHECK(zssh_state(&g_conn[CL]) == ZSSH_STATE_FAILED && zssh_error(&g_conn[CL]) == ZSSH_E_INTERNAL);
    all_secrets_gone(CL);
    const uint8_t *p; size_t n = 5;
    CHECK(zssh_output_peek(&g_conn[CL], &p, &n) == ZSSH_OK && n == 0);
    zssh_wipe(&g_conn[CL]);   /* idempotent */
    CHECK(zssh_error(&g_conn[CL]) == ZSSH_E_INTERNAL);
}

/* fragmentation does not change a single byte of the handshake */
static void g_transcript_equal(void)
{
    static uint8_t keep[2][16384];
    size_t keeplen[2];
    struct opt o;
    opt_default(&o);
    pair_init(&o, 1u << 20, 65536);
    g_d.rec_on = true;
    run_quiet();
    CHECK(both_state(ZSSH_STATE_CHANNEL));
    for (int d = 0; d < 2; d++) {
        keeplen[d] = g_d.reclen[d];
        memcpy(keep[d], g_d.rec[d], keeplen[d]);
        CHECK(keeplen[d] > 0 && keeplen[d] < sizeof keep[d]);
    }
    static const size_t chunks[][2] = { {1, 1}, {1, 65536}, {65536, 1}, {7, 3}, {1000, 13} };
    for (size_t k = 0; k < sizeof chunks / sizeof chunks[0]; k++) {
        pair_init(&o, chunks[k][0], chunks[k][1]);
        g_d.rec_on = true;
        run_quiet();
        CHECK(both_state(ZSSH_STATE_CHANNEL));
        for (int d = 0; d < 2; d++) {
            CHECK(g_d.reclen[d] == keeplen[d]);
            CHECK(memcmp(g_d.rec[d], keep[d], keeplen[d]) == 0);
            /* conservation: everything produced was consumed by the peer */
            CHECK(g_d.produced[d] == g_d.consumed[1 - d]);
        }
    }
}

/* ---- key exchange negatives ------------------------------------------------ */
static void expect_pair_failed(int i, enum zssh_error e)
{
    CHECK(zssh_state(&g_conn[i]) == ZSSH_STATE_FAILED);
    CHECK(zssh_error(&g_conn[i]) == e);
    all_secrets_gone(i);
}

static void g_kex_negative(void)
{
    struct opt o;
    /* require_pq server vs classical-only client: no match on both sides */
    opt_default(&o); o.kc = ZSSH_KEX_CURVE25519_SHA256; o.pq_s = true;
    pair_init(&o, 1u << 20, 65536);
    run_quiet();
    expect_pair_failed(CL, ZSSH_E_KEX_NO_MATCH);
    expect_pair_failed(SV, ZSSH_E_KEX_NO_MATCH);
    CHECK(IMPL(CL)->tx.kind == ZSSH_CIPHER_NONE);

    /* the peer's strict marker is broken -> STRICT_KEX_REQUIRED */
    opt_default(&o);
    pair_init(&o, 1u << 20, 65536);
    g_hm = HM_BREAK_STRICT;
    run_quiet();
    expect_pair_failed(CL, ZSSH_E_STRICT_KEX_REQUIRED);

    /* wrong pin: refused before any math. The reply is also corrupted so the
     * math WOULD fail (control below): the error must still be the pin. */
    opt_default(&o); o.pin = g_hpk2;
    pair_init(&o, 1u << 20, 65536);
    run_quiet();
    expect_pair_failed(CL, ZSSH_E_HOST_KEY_MISMATCH);
    CHECK(IMPL(CL)->tx.kind == ZSSH_CIPHER_NONE && !IMPL(CL)->sent_newkeys);  /* no credential */
    CHECK(!IMPL(SV)->authenticated);
    pair_init(&o, 1u << 20, 65536);
    g_hm = HM_ZERO_QS;
    run_quiet();
    expect_pair_failed(CL, ZSSH_E_HOST_KEY_MISMATCH);
    /* control: right pin, same corruption -> the math is reached and fails */
    opt_default(&o);
    pair_init(&o, 1u << 20, 65536);
    g_hm = HM_ZERO_QS;
    run_quiet();
    expect_pair_failed(CL, ZSSH_E_KEX_FAILED);
    /* same with the classical method */
    opt_default(&o); o.kc = o.ks = ZSSH_KEX_CURVE25519_SHA256;
    pair_init(&o, 1u << 20, 65536);
    g_hm = HM_ZERO_QS;
    run_quiet();
    expect_pair_failed(CL, ZSSH_E_KEX_FAILED);
    opt_default(&o); o.pin = g_hpk2; o.kc = o.ks = ZSSH_KEX_CURVE25519_SHA256;
    pair_init(&o, 1u << 20, 65536);
    g_hm = HM_ZERO_QS;
    run_quiet();
    expect_pair_failed(CL, ZSSH_E_HOST_KEY_MISMATCH);

    /* bad signature under the pinned key */
    opt_default(&o);
    pair_init(&o, 1u << 20, 65536);
    g_hm = HM_FLIP_SIG;
    run_quiet();
    expect_pair_failed(CL, ZSSH_E_HOST_SIG);
    CHECK(IMPL(CL)->tx.kind == ZSSH_CIPHER_NONE);

    /* strict KEX: a non-KEX message (IGNORE) before the first KEXINIT ... */
    opt_default(&o);
    pair_init(&o, 1u << 20, 65536);
    g_hm = HM_IGN_EARLY;
    run_quiet();
    expect_pair_failed(SV, ZSSH_E_STRICT_KEX_REQUIRED);
    CHECK(!IMPL(SV)->recv_newkeys);
    /* ... and between KEXINIT and the key exchange message */
    pair_init(&o, 1u << 20, 65536);
    g_hm = HM_IGN_MID;
    run_quiet();
    expect_pair_failed(SV, ZSSH_E_PROTOCOL);
    /* a DISCONNECT at the same spot is honoured (allowed in every phase) */
    opt_default(&o);
    pair_init(&o, 1u << 20, 65536);
    run_quiet();
    CHECK(both_state(ZSSH_STATE_CHANNEL));
}

/* ---- authentication --------------------------------------------------------- */
static size_t mk_auth(uint8_t *buf, int kind, const uint8_t *seed, const uint8_t *pk)
{
    struct zssh_wr w;
    uint8_t blob[ZSSH_ED25519_BLOB_LEN];
    zssh_wr_init(&w, buf, 600);
    if (kind == 2) {
        CHECK(zssh_auth_build_request(&w, "relay", IMPL(CL)->kex.session_id, seed, pk) == ZSSH_E_NONE);
        return w.off;
    }
    zssh_wr_u8(&w, ZSSH_MSG_USERAUTH_REQUEST);
    zssh_wr_cstr(&w, "relay");
    zssh_wr_cstr(&w, "ssh-connection");
    if (kind == 0) { zssh_wr_cstr(&w, "none"); return w.off; }
    zssh_wr_cstr(&w, "publickey");
    zssh_wr_bool(&w, false);
    zssh_wr_cstr(&w, "ssh-ed25519");
    zssh_auth_blob_encode(pk, blob);
    zssh_wr_string(&w, blob, sizeof blob);
    CHECK(zssh_wr_ok(&w));
    return w.off;
}

/* Client sends one hand-made auth request; returns the type of the server's
 * answer (0 if none). */
static unsigned auth_roundtrip(int kind, const uint8_t *seed, const uint8_t *pk, uint8_t *arg)
{
    uint8_t buf[600];
    size_t n = mk_auth(buf, kind, seed, pk), pl = 0;
    raw_send(CL, buf, n);
    step(SV);
    if (!raw_next(CL, SV, &pl)) return 0;
    if (arg && pl > 1) *arg = g_raw[1];
    return g_raw[0];
}

/* Pair stopped right after the server accepted the service; the client engine
 * is parked and its keys are used to craft requests. */
static void auth_pause(void)
{
    struct opt o;
    size_t pl = 0;
    opt_default(&o);
    pair_init(&o, 1u << 20, 65536);
    for (int i = 0; i < 100000 && !IMPL(SV)->service_accepted; i++) {
        step(CL);
        step(SV);
    }
    CHECK(IMPL(SV)->service_accepted);
    CHECK(raw_next(CL, SV, &pl) && g_raw[0] == ZSSH_MSG_SERVICE_ACCEPT);   /* parks the client */
    CHECK(!IMPL(SV)->authenticated && zssh_state(&g_conn[SV]) == ZSSH_STATE_AUTH);
    snap_take(0);
}

/* g_raw still holds the server's last packet (read by auth_roundtrip). */
static void expect_refused(unsigned reason)
{
    CHECK(zssh_state(&g_conn[SV]) == ZSSH_STATE_FAILED);
    CHECK(zssh_error(&g_conn[SV]) == ZSSH_E_AUTH_REFUSED);
    CHECK(g_raw[0] == ZSSH_MSG_DISCONNECT);
    CHECK(zssh_get_u32(g_raw + 1) == reason);
    CHECK(!IMPL(SV)->authenticated);
    all_secrets_gone(SV);
}

static void g_auth_boundaries(void)
{
    uint8_t arg = 0;
    auth_pause();
    /* exactly ZSSH_MAX_AUTH_ATTEMPTS probes are answered, the next is terminal */
    for (unsigned i = 0; i < ZSSH_MAX_AUTH_ATTEMPTS; i++) {
        CHECK(auth_roundtrip(1, nullptr, g_upk, &arg) == ZSSH_MSG_USERAUTH_PK_OK);
        CHECK(zssh_state(&g_conn[SV]) == ZSSH_STATE_AUTH && !IMPL(SV)->authenticated);
    }
    CHECK(auth_roundtrip(1, nullptr, g_upk, &arg) == ZSSH_MSG_DISCONNECT);
    expect_refused(ZSSH_DISC_NO_MORE_AUTH_METHODS);

    snap_restore(0);
    /* the last allowed attempt can still succeed; the one after never runs */
    for (unsigned i = 0; i + 1 < ZSSH_MAX_AUTH_ATTEMPTS; i++)
        CHECK(auth_roundtrip(2, g_useed2, g_upk2, &arg) == ZSSH_MSG_USERAUTH_FAILURE);
    CHECK(auth_roundtrip(2, g_useed, g_upk, &arg) == ZSSH_MSG_USERAUTH_SUCCESS);
    CHECK(IMPL(SV)->authenticated && zssh_state(&g_conn[SV]) == ZSSH_STATE_OPEN);

    snap_restore(0);
    /* unevaluated: attempts exhausted by wrong signed keys, the correct one is refused */
    for (unsigned i = 0; i < ZSSH_MAX_AUTH_ATTEMPTS; i++)
        CHECK(auth_roundtrip(2, g_useed2, g_upk2, &arg) == ZSSH_MSG_USERAUTH_FAILURE);
    CHECK(auth_roundtrip(2, g_useed, g_upk, &arg) == ZSSH_MSG_DISCONNECT);
    expect_refused(ZSSH_DISC_NO_MORE_AUTH_METHODS);

    snap_restore(0);
    /* "none": exactly ZSSH_MAX_AUTH_NONE answered with FAILURE, the next terminal */
    for (unsigned i = 0; i < ZSSH_MAX_AUTH_NONE; i++) {
        CHECK(auth_roundtrip(0, nullptr, nullptr, &arg) == ZSSH_MSG_USERAUTH_FAILURE);
        CHECK(zssh_state(&g_conn[SV]) == ZSSH_STATE_AUTH);
    }
    CHECK(auth_roundtrip(0, nullptr, nullptr, &arg) == ZSSH_MSG_DISCONNECT);
    expect_refused(ZSSH_DISC_NO_MORE_AUTH_METHODS);

    snap_restore(0);
    /* "none" does not eat publickey attempts (separate counters) */
    for (unsigned i = 0; i < ZSSH_MAX_AUTH_NONE; i++)
        CHECK(auth_roundtrip(0, nullptr, nullptr, &arg) == ZSSH_MSG_USERAUTH_FAILURE);
    CHECK(auth_roundtrip(2, g_useed, g_upk, &arg) == ZSSH_MSG_USERAUTH_SUCCESS);
}

static void g_auth_probe_then_sign(void)
{
    uint8_t arg = 0;
    auth_pause();
    /* an unauthorized key never gets PK_OK */
    CHECK(auth_roundtrip(1, nullptr, g_upk2, &arg) == ZSSH_MSG_USERAUTH_FAILURE);
    snap_restore(0);
    /* probe (PK_OK) then signed request: authenticated only by the signature */
    CHECK(auth_roundtrip(1, nullptr, g_upk, &arg) == ZSSH_MSG_USERAUTH_PK_OK);
    CHECK(!IMPL(SV)->authenticated && zssh_state(&g_conn[SV]) == ZSSH_STATE_AUTH);
    CHECK(auth_roundtrip(2, g_useed, g_upk, &arg) == ZSSH_MSG_USERAUTH_SUCCESS);
    CHECK(IMPL(SV)->authenticated && zssh_state(&g_conn[SV]) == ZSSH_STATE_OPEN);
    CHECK(IMPL(SV)->auth_failures == 2);

    /* first channel open that is not direct-tcpip: OPEN_FAILURE, then the session closes */
    snap_restore(0);
    CHECK(auth_roundtrip(2, g_useed, g_upk, &arg) == ZSSH_MSG_USERAUTH_SUCCESS);
    uint8_t buf[128];
    struct zssh_wr w;
    size_t pl = 0;
    zssh_wr_init(&w, buf, sizeof buf);
    zssh_wr_u8(&w, ZSSH_MSG_CHANNEL_OPEN);
    zssh_wr_cstr(&w, "session");
    zssh_wr_u32(&w, 5); zssh_wr_u32(&w, 1000); zssh_wr_u32(&w, 1000);
    raw_send(CL, buf, w.off);
    step(SV);
    CHECK(raw_next(CL, SV, &pl) && g_raw[0] == ZSSH_MSG_CHANNEL_OPEN_FAILURE);
    CHECK(zssh_get_u32(g_raw + 1) == 5 && zssh_get_u32(g_raw + 5) == ZSSH_OPEN_UNKNOWN_CHANNEL_TYPE);
    CHECK(raw_next(CL, SV, &pl) && g_raw[0] == ZSSH_MSG_DISCONNECT);
    CHECK(zssh_error(&g_conn[SV]) == ZSSH_E_CHANNEL_REFUSED);
}

static void g_wrong_user_key(void)
{
    struct opt o;
    opt_default(&o); o.useed = g_useed2;
    pair_init(&o, 1u << 20, 65536);
    run_quiet();
    expect_pair_failed(CL, ZSSH_E_AUTH_REFUSED);
    CHECK(!IMPL(SV)->authenticated);
    /* the client disconnects after the refusal; the server sees it */
    CHECK(zssh_state(&g_conn[SV]) == ZSSH_STATE_FAILED);
    CHECK(zssh_error(&g_conn[SV]) == ZSSH_E_PEER_DISCONNECT);
    /* wrong user name */
    opt_default(&o); o.cuser = "mallory";
    pair_init(&o, 1u << 20, 65536);
    run_quiet();
    expect_pair_failed(CL, ZSSH_E_AUTH_REFUSED);
    CHECK(!IMPL(SV)->authenticated);
}

/* ---- post-auth raw messages ------------------------------------------------- */
static unsigned raw_roundtrip(const uint8_t *pl, size_t n)
{
    size_t rl = 0;
    raw_send(CL, pl, n);
    step(SV);
    return raw_next(CL, SV, &rl) ? g_raw[0] : 0;
}

/* g_raw holds the server's last packet, which must be its DISCONNECT. */
static void server_failed_with(enum zssh_error e, unsigned disc_reason)
{
    CHECK(zssh_state(&g_conn[SV]) == ZSSH_STATE_FAILED && zssh_error(&g_conn[SV]) == e);
    CHECK(g_raw[0] == ZSSH_MSG_DISCONNECT);
    CHECK(zssh_get_u32(g_raw + 1) == disc_reason);
    all_secrets_gone(SV);
}

static void g_post_auth_messages(void)
{
    struct opt o;
    uint8_t buf[256];
    struct zssh_wr w;
    size_t rl = 0;
    opt_default(&o);
    CHECK(handshake(&o, 1u << 20, 65536));
    snap_take(1);

    /* KEXINIT after NEWKEYS -> REKEY_UNSUPPORTED + DISCONNECT(KEY_EXCHANGE_FAILED) */
    struct zssh_kex_policy pol = { ZSSH_ROLE_CLIENT, 3, false };
    uint8_t cookie[16] = { 0 };
    uint8_t ki[600];
    zssh_wr_init(&w, ki, sizeof ki);
    CHECK(zssh_kex_build_kexinit(&pol, cookie, &w) == ZSSH_E_NONE);
    CHECK(raw_roundtrip(ki, w.off) == ZSSH_MSG_DISCONNECT);
    CHECK(zssh_get_u32(g_raw + 1) == ZSSH_DISC_KEY_EXCHANGE_FAILED);
    CHECK(zssh_state(&g_conn[SV]) == ZSSH_STATE_FAILED && zssh_error(&g_conn[SV]) == ZSSH_E_REKEY_UNSUPPORTED);
    all_secrets_gone(SV);
    /* and from the server side towards the client */
    snap_restore(1);
    pol.role = ZSSH_ROLE_SERVER;
    zssh_wr_init(&w, ki, sizeof ki);
    CHECK(zssh_kex_build_kexinit(&pol, cookie, &w) == ZSSH_E_NONE);
    raw_send(SV, ki, w.off);
    step(CL);
    CHECK(zssh_error(&g_conn[CL]) == ZSSH_E_REKEY_UNSUPPORTED);
    CHECK(raw_next(SV, CL, &rl) && g_raw[0] == ZSSH_MSG_DISCONNECT);

    /* unknown message: UNIMPLEMENTED once (with the packet's sequence number), then ignored */
    snap_restore(1);
    uint32_t seq0 = IMPL(CL)->tx.seq;
    uint8_t unk[1] = { 200 };
    CHECK(raw_roundtrip(unk, 1) == ZSSH_MSG_UNIMPLEMENTED);
    CHECK(zssh_get_u32(g_raw + 1) == seq0);
    CHECK(raw_roundtrip(unk, 1) == 0);
    CHECK(zssh_state(&g_conn[SV]) == ZSSH_STATE_CHANNEL);
    /* IGNORE and DEBUG are dropped silently */
    uint8_t ign[5] = { ZSSH_MSG_IGNORE, 0, 0, 0, 0 };
    uint8_t dbg[10] = { ZSSH_MSG_DEBUG, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    CHECK(raw_roundtrip(ign, 5) == 0 && raw_roundtrip(dbg, 10) == 0);
    /* global request: want_reply -> REQUEST_FAILURE, otherwise silence */
    zssh_wr_init(&w, buf, sizeof buf);
    zssh_wr_u8(&w, ZSSH_MSG_GLOBAL_REQUEST); zssh_wr_cstr(&w, "tcpip-forward");
    zssh_wr_bool(&w, true); zssh_wr_cstr(&w, "0.0.0.0"); zssh_wr_u32(&w, 1234);
    CHECK(raw_roundtrip(buf, w.off) == ZSSH_MSG_REQUEST_FAILURE);
    buf[1 + 4 + 13] = 0;                    /* want_reply = false */
    CHECK(raw_roundtrip(buf, w.off) == 0);
    /* channel request (shell): want_reply -> CHANNEL_FAILURE; env without reply: silence */
    zssh_wr_init(&w, buf, sizeof buf);
    zssh_wr_u8(&w, ZSSH_MSG_CHANNEL_REQUEST); zssh_wr_u32(&w, 0);
    zssh_wr_cstr(&w, "shell"); zssh_wr_bool(&w, true);
    CHECK(raw_roundtrip(buf, w.off) == ZSSH_MSG_CHANNEL_FAILURE);
    buf[1 + 4 + 4 + 5] = 0;
    CHECK(raw_roundtrip(buf, w.off) == 0);
    /* a second channel is refused, the live channel keeps working */
    zssh_wr_init(&w, buf, sizeof buf);
    zssh_wr_u8(&w, ZSSH_MSG_CHANNEL_OPEN); zssh_wr_cstr(&w, "direct-tcpip");
    zssh_wr_u32(&w, 5); zssh_wr_u32(&w, 1000); zssh_wr_u32(&w, 1000);
    zssh_wr_cstr(&w, ZSSH_FWD_HOST); zssh_wr_u32(&w, ZSSH_FWD_PORT);
    zssh_wr_cstr(&w, "0.0.0.0"); zssh_wr_u32(&w, 0);
    CHECK(raw_roundtrip(buf, w.off) == ZSSH_MSG_CHANNEL_OPEN_FAILURE);
    CHECK(zssh_get_u32(g_raw + 5) == ZSSH_OPEN_RESOURCE_SHORTAGE);
    CHECK(zssh_state(&g_conn[SV]) == ZSSH_STATE_CHANNEL);
    size_t acc = 0, got = 0;
    uint8_t rb[16];
    CHECK(zssh_channel_send(&g_conn[CL], (const uint8_t *)"ping", 4, &acc) == ZSSH_OK && acc == 4);
    run_quiet();
    CHECK(zssh_channel_recv(&g_conn[SV], rb, sizeof rb, &got) == ZSSH_OK && got == 4 && memcmp(rb, "ping", 4) == 0);

    /* messages that must fail the session */
    snap_restore(1);
    uint8_t m3[5] = { ZSSH_MSG_UNIMPLEMENTED, 0, 0, 0, 0 };
    CHECK(raw_roundtrip(m3, 5) == ZSSH_MSG_DISCONNECT);
    server_failed_with(ZSSH_E_PROTOCOL, ZSSH_DISC_PROTOCOL_ERROR);
    snap_restore(1);
    uint8_t m7[5] = { ZSSH_MSG_EXT_INFO, 0, 0, 0, 0 };
    CHECK(raw_roundtrip(m7, 5) == ZSSH_MSG_DISCONNECT);
    server_failed_with(ZSSH_E_PROTOCOL, ZSSH_DISC_PROTOCOL_ERROR);
    snap_restore(1);
    uint8_t m95[13] = { ZSSH_MSG_CHANNEL_EXTENDED_DATA, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 };
    CHECK(raw_roundtrip(m95, 13) == ZSSH_MSG_DISCONNECT);
    server_failed_with(ZSSH_E_PROTOCOL, ZSSH_DISC_PROTOCOL_ERROR);
    snap_restore(1);
    uint8_t m52[1] = { ZSSH_MSG_NEWKEYS };
    CHECK(raw_roundtrip(m52, 1) == ZSSH_MSG_DISCONNECT);
    server_failed_with(ZSSH_E_PROTOCOL, ZSSH_DISC_PROTOCOL_ERROR);
    /* DATA beyond the packet bound -> WINDOW */
    snap_restore(1);
    static uint8_t bigdata[ZSSH_CHAN_MAX_PACKET + 64], filler[ZSSH_CHAN_MAX_PACKET + 1u];
    zssh_wr_init(&w, bigdata, sizeof bigdata);
    zssh_wr_u8(&w, ZSSH_MSG_CHANNEL_DATA); zssh_wr_u32(&w, 0);
    zssh_wr_u32(&w, ZSSH_CHAN_MAX_PACKET + 1u);
    zssh_wr_bytes(&w, filler, sizeof filler);
    raw_send(CL, bigdata, w.off);
    step(SV);
    CHECK(raw_next(CL, SV, &rl));
    server_failed_with(ZSSH_E_WINDOW, ZSSH_DISC_PROTOCOL_ERROR);
    /* a peer DISCONNECT fails the session without a reply */
    snap_restore(1);
    uint8_t dis[1 + 4 + 4 + 4] = { ZSSH_MSG_DISCONNECT, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0 };
    CHECK(raw_roundtrip(dis, sizeof dis) == 0);
    CHECK(zssh_state(&g_conn[SV]) == ZSSH_STATE_FAILED && zssh_error(&g_conn[SV]) == ZSSH_E_PEER_DISCONNECT);
}

/* ---- back-pressure ---------------------------------------------------------- */
static uint8_t bp_junk[58000], bp_pkt[4000], bp_data[3000];
static size_t bp_pn;

/* A: the server's queue is nearly full; the packet is not even started */
static void bp_case_a(void)
{
    size_t got = 0, cons = 0;
    uint8_t rb[4000];
    CHECK(zssh_txq_append(&IMPL(SV)->txq, bp_junk, sizeof bp_junk));
    CHECK(zssh_txq_room(&IMPL(SV)->txq) < ZSSH_TXQ_RESERVE);
    enum zssh_status st = zssh_input(&g_conn[SV], bp_pkt, bp_pn, &cons);
    CHECK(st == ZSSH_NEED_OUTPUT && cons == 0);
    CHECK(zssh_channel_recv(&g_conn[SV], rb, sizeof rb, &got) == ZSSH_AGAIN && got == 0);
    CHECK(zssh_output_consume(&g_conn[SV], sizeof bp_junk) == ZSSH_OK);   /* drain the junk */
    st = zssh_input(&g_conn[SV], bp_pkt, bp_pn, &cons);
    CHECK(st != ZSSH_STATUS_FAILED && cons == bp_pn);
    CHECK(zssh_channel_recv(&g_conn[SV], rb, sizeof rb, &got) == ZSSH_OK && got == sizeof bp_data);
    CHECK(memcmp(rb, bp_data, sizeof bp_data) == 0);
}

static void bp_case_b(void);    /* B and C live in test_zssh_e2e.inc */
static void bp_case_c(void);

static void g_backpressure(void)
{
    struct opt o;
    size_t acc = 0;
    opt_default(&o);
    CHECK(handshake(&o, 1u << 20, 65536));
    for (size_t i = 0; i < sizeof bp_data; i++) bp_data[i] = (uint8_t)(i * 3 + 1);
    CHECK(zssh_channel_send(&g_conn[CL], bp_data, sizeof bp_data, &acc) == ZSSH_OK && acc == sizeof bp_data);
    const uint8_t *p;
    CHECK(zssh_output_peek(&g_conn[CL], &p, &bp_pn) == ZSSH_OK && bp_pn > sizeof bp_data);
    memcpy(bp_pkt, p, bp_pn);
    CHECK(zssh_output_consume(&g_conn[CL], bp_pn) == ZSSH_OK);
    snap_take(1);
    bp_case_a();
    bp_case_b();
    bp_case_c();
}

/* ---- half close and close --------------------------------------------------- */
static void drain_all(int i)
{
    const uint8_t *p; size_t n;
    CHECK(zssh_output_peek(&g_conn[i], &p, &n) == ZSSH_OK);
    q_push(i, p, n);
    CHECK(zssh_output_consume(&g_conn[i], n) == ZSSH_OK);
}

static void closed_column(void);
static void half_close_close_phase(void);

static void g_half_close(void)
{
    struct opt o;
    uint8_t rb[64];
    size_t acc = 0, got = 0;
    struct zssh_channel_flags f = {0};
    opt_default(&o);
    CHECK(handshake(&o, 1u << 20, 65536));
    CHECK(zssh_channel_send(&g_conn[CL], (const uint8_t *)"abcde", 5, &acc) == ZSSH_OK && acc == 5);
    CHECK(zssh_channel_send_eof(&g_conn[CL]) == ZSSH_OK);
    CHECK(zssh_channel_send_eof(&g_conn[CL]) == ZSSH_OK);              /* idempotent */
    CHECK(zssh_channel_send(&g_conn[CL], (const uint8_t *)"x", 1, &acc) == ZSSH_BAD_CALL && acc == 0);
    run_quiet();
    /* server: data first, then EOF; its own send side is still open */
    CHECK(zssh_channel_recv(&g_conn[SV], rb, sizeof rb, &got) == ZSSH_OK && got == 5);
    CHECK(zssh_channel_recv(&g_conn[SV], rb, sizeof rb, &got) == ZSSH_EOF && got == 0);
    CHECK(zssh_channel_flags_get(&g_conn[SV], &f) == ZSSH_OK && f.recv_eof && !f.sent_eof && !f.recv_close);
    CHECK(zssh_channel_send(&g_conn[SV], (const uint8_t *)"reply", 5, &acc) == ZSSH_OK && acc == 5);
    run_quiet();
    CHECK(zssh_channel_recv(&g_conn[CL], rb, sizeof rb, &got) == ZSSH_OK && got == 5 && memcmp(rb, "reply", 5) == 0);
    CHECK(zssh_state(&g_conn[CL]) == ZSSH_STATE_CHANNEL && zssh_state(&g_conn[SV]) == ZSSH_STATE_CHANNEL);
    half_close_close_phase();
    closed_column();
}

/* server leaves unread data behind, then the client closes */
static void half_close_close_phase(void)
{
    size_t acc = 0;
    struct zssh_channel_flags f = {0};
    CHECK(zssh_channel_send(&g_conn[CL], nullptr, 0, &acc) == ZSSH_BAD_CALL);
    CHECK(zssh_channel_send(&g_conn[SV], (const uint8_t *)"tail!", 5, &acc) == ZSSH_OK);
    run_quiet();
    CHECK(zssh_channel_close(&g_conn[CL]) == ZSSH_OK);
    CHECK(zssh_channel_close(&g_conn[CL]) == ZSSH_OK);                 /* idempotent */
    CHECK(zssh_channel_flags_get(&g_conn[CL], &f) == ZSSH_OK && f.sent_eof && f.sent_close);
    CHECK(zssh_channel_send(&g_conn[CL], (const uint8_t *)"x", 1, &acc) == ZSSH_BAD_CALL);
    run_quiet();
    /* peer CLOSE answered exactly once, then DISCONNECT, CLOSED on both sides */
    CHECK(both_state(ZSSH_STATE_CLOSED));
    CHECK(zssh_error(&g_conn[CL]) == ZSSH_E_NONE && zssh_error(&g_conn[SV]) == ZSSH_E_NONE);
    for (int i = 0; i < 2; i++) {
        CHECK(zssh_channel_flags_get(&g_conn[i], &f) == ZSSH_OK && f.sent_close && f.recv_close);
        all_secrets_gone(i);
    }
}

/* terminal table, CLOSED column */
static void closed_column(void)
{
    uint8_t rb[64];
    size_t acc = 0, got = 0;
    CHECK(zssh_channel_recv(&g_conn[CL], rb, sizeof rb, &got) == ZSSH_OK && got == 5 && memcmp(rb, "tail!", 5) == 0);
    CHECK(zssh_channel_recv(&g_conn[CL], rb, sizeof rb, &got) == ZSSH_EOF && got == 0);
    CHECK(zssh_channel_send(&g_conn[CL], (const uint8_t *)"x", 1, &acc) == ZSSH_EOF && acc == 0);
    CHECK(zssh_channel_send_eof(&g_conn[CL]) == ZSSH_OK);
    CHECK(zssh_channel_close(&g_conn[CL]) == ZSSH_OK);
    size_t cons = 9;
    CHECK(zssh_input(&g_conn[CL], (const uint8_t *)"abc", 3, &cons) == ZSSH_CLOSED && cons == 0);
    size_t c2 = 9, p2 = 9;
    uint8_t ob[1024];
    enum zssh_status st = zssh_pump(&g_conn[SV], (const uint8_t *)"abc", 3, &c2, ob, sizeof ob, &p2);
    CHECK(st == ZSSH_CLOSED && c2 == 0);
    CHECK(zssh_transport_eof(&g_conn[CL]) == ZSSH_OK);                 /* no-op in CLOSED */
    CHECK(zssh_state(&g_conn[CL]) == ZSSH_STATE_CLOSED && zssh_error(&g_conn[CL]) == ZSSH_E_NONE);
    const uint8_t *p; size_t pn;
    CHECK(zssh_output_peek(&g_conn[CL], &p, &pn) == ZSSH_OK);
    CHECK(zssh_output_consume(&g_conn[CL], pn + 1) == ZSSH_BAD_CALL);
    CHECK(zssh_output_consume(&g_conn[CL], pn) == ZSSH_OK);
    zssh_wipe(&g_conn[CL]);
    CHECK(zssh_state(&g_conn[CL]) == ZSSH_STATE_CLOSED);               /* stays CLOSED */
    drain_all(SV);
    CHECK(zssh_state(&g_conn[SV]) == ZSSH_STATE_CLOSED);
}

/* ---- FAILED column, transport EOF ------------------------------------------- */
static void failed_column(int i, enum zssh_error e)
{
    uint8_t rb[16];
    size_t cons = 9, got = 9, acc = 9;
    struct zssh_channel_flags f = {0};
    CHECK(zssh_input(&g_conn[i], (const uint8_t *)"abc", 3, &cons) == ZSSH_STATUS_FAILED && cons == 0);
    CHECK(zssh_channel_recv(&g_conn[i], rb, sizeof rb, &got) == ZSSH_FAILED && got == 0);
    CHECK(zssh_channel_send(&g_conn[i], (const uint8_t *)"x", 1, &acc) == ZSSH_FAILED && acc == 0);
    CHECK(zssh_channel_send_eof(&g_conn[i]) == ZSSH_FAILED);
    CHECK(zssh_channel_close(&g_conn[i]) == ZSSH_FAILED);
    CHECK(zssh_transport_eof(&g_conn[i]) == ZSSH_FAILED);
    CHECK(zssh_error(&g_conn[i]) == e && zssh_state(&g_conn[i]) == ZSSH_STATE_FAILED);
    CHECK(zssh_channel_flags_get(&g_conn[i], &f) == ZSSH_OK);
    const uint8_t *p; size_t n;
    CHECK(zssh_output_peek(&g_conn[i], &p, &n) == ZSSH_OK);
    zssh_wipe(&g_conn[i]);
    CHECK(zssh_state(&g_conn[i]) == ZSSH_STATE_FAILED && zssh_error(&g_conn[i]) == e);
    all_secrets_gone(i);
}

static void g_transport_eof(void)
{
    struct opt o;
    uint8_t rb[16];
    size_t got = 0, acc = 0;
    opt_default(&o);
    CHECK(handshake(&o, 1u << 20, 65536));
    CHECK(zssh_channel_send(&g_conn[SV], (const uint8_t *)"unread", 6, &acc) == ZSSH_OK);
    run_quiet();                                                       /* data sits in the client ring */
    const uint8_t *p; size_t n0, n1;
    CHECK(zssh_output_peek(&g_conn[CL], &p, &n0) == ZSSH_OK);
    CHECK(zssh_transport_eof(&g_conn[CL]) == ZSSH_FAILED);
    CHECK(zssh_state(&g_conn[CL]) == ZSSH_STATE_FAILED && zssh_error(&g_conn[CL]) == ZSSH_E_TRUNCATED);
    CHECK(zssh_output_peek(&g_conn[CL], &p, &n1) == ZSSH_OK && n1 == n0);   /* no DISCONNECT queued */
    CHECK(zssh_channel_recv(&g_conn[CL], rb, sizeof rb, &got) == ZSSH_FAILED && got == 0);  /* ring wiped */
    all_secrets_gone(CL);
    failed_column(CL, ZSSH_E_TRUNCATED);
    /* first error wins: a failed engine keeps its cause */
    CHECK(zssh_transport_eof(&g_conn[SV]) == ZSSH_FAILED && zssh_error(&g_conn[SV]) == ZSSH_E_TRUNCATED);
    CHECK(zssh_transport_eof(&g_conn[SV]) == ZSSH_FAILED && zssh_error(&g_conn[SV]) == ZSSH_E_TRUNCATED);
    /* a protocol failure keeps its own error through a later transport EOF */
    CHECK(handshake(&o, 1u << 20, 65536));
    uint8_t unk = ZSSH_MSG_UNIMPLEMENTED;
    uint8_t m3[5] = { unk, 0, 0, 0, 0 };
    raw_send(CL, m3, 5);
    step(SV);
    CHECK(zssh_error(&g_conn[SV]) == ZSSH_E_PROTOCOL);
    CHECK(zssh_transport_eof(&g_conn[SV]) == ZSSH_FAILED && zssh_error(&g_conn[SV]) == ZSSH_E_PROTOCOL);
    failed_column(SV, ZSSH_E_PROTOCOL);
    /* eof before the key exchange */
    pair_init(&o, 1u << 20, 65536);
    CHECK(zssh_transport_eof(&g_conn[CL]) == ZSSH_FAILED && zssh_error(&g_conn[CL]) == ZSSH_E_TRUNCATED);
    all_secrets_gone(CL);
    /* a half-delivered packet is dropped at EOF */
    pair_init(&o, 1u << 20, 65536);
    step(CL);
    size_t av = g_qt[CL] - g_qh[CL], c3 = 0;
    CHECK(av > 16);
    CHECK(zssh_input(&g_conn[SV], g_q[CL] + g_qh[CL], av - 3, &c3) != ZSSH_STATUS_FAILED && c3 == av - 3);
    CHECK(zssh_transport_eof(&g_conn[SV]) == ZSSH_FAILED);
    CHECK(zssh_error(&g_conn[SV]) == ZSSH_E_TRUNCATED);
}

/* ---- RNG failure at every call site ------------------------------------------ */
static void rng_scenario(const struct opt *o)
{
    pair_init(o, 1u << 20, 65536);
}

static void rng_run_to_quiet(void)
{
    uint8_t buf[100], rb[100];
    size_t acc = 0, got = 0;
    run_quiet();
    if (both_state(ZSSH_STATE_CHANNEL)) {
        memset(buf, 0xa5, sizeof buf);
        (void)zssh_channel_send(&g_conn[CL], buf, sizeof buf, &acc);
        run_quiet();
        (void)zssh_channel_recv(&g_conn[SV], rb, sizeof rb, &got);
        (void)zssh_channel_send(&g_conn[SV], buf, sizeof buf, &acc);
        run_quiet();
        (void)zssh_channel_recv(&g_conn[CL], rb, sizeof rb, &got);
        (void)zssh_channel_close(&g_conn[CL]);
        run_quiet();
    }
}

static void g_rng_sweep(void)
{
    struct opt o;
    static const uint32_t kexes[2] = { ZSSH_KEX_MLKEM768X25519_SHA256, ZSSH_KEX_CURVE25519_SHA256 };
    for (int k = 0; k < 2; k++) {
        for (int who = 0; who < 2; who++) {
            opt_default(&o); o.kc = o.ks = kexes[k];
            rng_scenario(&o);
            rng_run_to_quiet();
            CHECK(both_state(ZSSH_STATE_CLOSED));
            unsigned total = g_rng[who].calls;
            CHECK(total >= 4);
            unsigned seen = 0;
            for (unsigned n = 1; n <= total; n++) {
                opt_default(&o); o.kc = o.ks = kexes[k];
                g_arm_who = who;               /* armed before init: covers init's draws too */
                g_arm_n = n;
                rng_scenario(&o);
                rng_run_to_quiet();
                g_arm_who = -1;
                if (g_rng[who].calls >= n) {
                    seen++;
                    CHECK(zssh_state(&g_conn[who]) == ZSSH_STATE_FAILED);
                    CHECK(zssh_error(&g_conn[who]) == ZSSH_E_RANDOM);
                    all_secrets_gone(who);
                    CHECK(!both_state(ZSSH_STATE_CLOSED));
                }
            }
            CHECK(seen == total);
        }
    }
}

/* Failing multi-packet send / recv report the exact committed prefix. */
static void g_partial_prefix(void)
{
    struct opt o;
    static uint8_t big[40000], rb[40000];
    size_t acc = 0, got = 0;
    opt_default(&o); o.kc = o.ks = ZSSH_KEX_CURVE25519_SHA256;
    memset(big, 0x42, sizeof big);
    CHECK(handshake(&o, 1u << 20, 65536));
    snap_take(1);
    struct zssh_channel_flags fa = {0}, fb = {0};
    CHECK(zssh_channel_flags_get(&g_conn[CL], &fa) == ZSSH_OK);
    g_rng[CL].fail_at = g_rng[CL].calls + 2;        /* second packet's padding draw */
    CHECK(zssh_channel_send(&g_conn[CL], big, sizeof big, &acc) == ZSSH_FAILED);
    CHECK(acc == ZSSH_CHAN_MAX_PACKET);
    CHECK(zssh_state(&g_conn[CL]) == ZSSH_STATE_FAILED && zssh_error(&g_conn[CL]) == ZSSH_E_RANDOM);
    all_secrets_gone(CL);
    /* the send window was charged for exactly the committed prefix */
    CHECK(zssh_channel_flags_get(&g_conn[CL], &fb) == ZSSH_OK);
    CHECK(fa.send_window - fb.send_window == ZSSH_CHAN_MAX_PACKET);
    /* the failed engine's queue holds that one packet; the peer receives exactly it */
    const uint8_t *pp = nullptr;
    size_t ppn = 0, pcons = 0;
    CHECK(zssh_output_peek(&g_conn[CL], &pp, &ppn) == ZSSH_OK);
    CHECK(ppn > ZSSH_CHAN_MAX_PACKET && ppn < 2u * ZSSH_CHAN_MAX_PACKET);
    CHECK(zssh_input(&g_conn[SV], pp, ppn, &pcons) != ZSSH_STATUS_FAILED && pcons == ppn);
    CHECK(zssh_channel_recv(&g_conn[SV], rb, sizeof rb, &got) == ZSSH_OK && got == ZSSH_CHAN_MAX_PACKET);
    CHECK(memcmp(rb, big, got) == 0);
    /* the committed prefix is still on the wire and arrives intact */
    snap_restore(1);
    CHECK(zssh_channel_send(&g_conn[CL], big, 30000, &acc) == ZSSH_OK && acc == 30000);
    run_quiet();
    g_rng[SV].fail_at = g_rng[SV].calls + 1;        /* the WINDOW_ADJUST's padding draw */
    CHECK(zssh_channel_recv(&g_conn[SV], rb, sizeof rb, &got) == ZSSH_FAILED);
    CHECK(got == 30000 && memcmp(rb, big, got) == 0);   /* copied bytes are reported */
    CHECK(zssh_error(&g_conn[SV]) == ZSSH_E_RANDOM);
    all_secrets_gone(SV);
}

/* ---- tampering ---------------------------------------------------------------- */
/* Flip one bit of the saved packet (t < 8: in the length field) and check the
 * server refuses it and wipes its secrets. */
static void tamper_one(int t, uint64_t r, const uint8_t *pkt, size_t pn)
{
    uint8_t rb[1200];
    size_t got = 0, cons = 0;
    snap_restore(1);
    size_t pos = t < 8 ? (size_t)(t % 4) : 4 + (size_t)((r >> 33) % (pn - 4));
    uint8_t bad[2400];
    memcpy(bad, pkt, pn);
    bad[pos] ^= (uint8_t)(1u << ((r >> 20) & 7));
    enum zssh_status st = zssh_input(&g_conn[SV], bad, pn, &cons);
    CHECK(cons <= pn);
    if (pos >= 4) {
        CHECK(st == ZSSH_STATUS_FAILED && zssh_error(&g_conn[SV]) == ZSSH_E_MAC);
        CHECK(cons == pn);
        size_t rl = 0;
        drain_all(SV);
        CHECK(raw_next(CL, SV, &rl) && g_raw[0] == ZSSH_MSG_DISCONNECT && zssh_get_u32(g_raw + 1) == ZSSH_DISC_MAC_ERROR);
    } else if (st == ZSSH_STATUS_FAILED) {                       /* length field: refused, never delivered */
        enum zssh_error e = zssh_error(&g_conn[SV]);
        CHECK(e == ZSSH_E_MAC || e == ZSSH_E_TOO_LARGE || e == ZSSH_E_PROTOCOL);
    } else {
        CHECK(zssh_transport_eof(&g_conn[SV]) == ZSSH_FAILED);   /* waiting for bytes that never come */
        CHECK(zssh_error(&g_conn[SV]) == ZSSH_E_TRUNCATED);
    }
    CHECK(zssh_state(&g_conn[SV]) == ZSSH_STATE_FAILED);
    CHECK(zssh_channel_recv(&g_conn[SV], rb, sizeof rb, &got) == ZSSH_FAILED && got == 0);
    all_secrets_gone(SV);
}

static void g_tamper(void)
{
    struct opt o;
    uint8_t data[1000], rb[1200];
    static uint8_t pkt[2400];
    uint64_t r = 0x7a11u;
    size_t acc = 0, got = 0, cons = 0, pn = 0;
    opt_default(&o); o.kc = o.ks = ZSSH_KEX_CURVE25519_SHA256;
    CHECK(handshake(&o, 1u << 20, 65536));
    for (size_t i = 0; i < sizeof data; i++) data[i] = (uint8_t)(i ^ 0x5c);
    CHECK(zssh_channel_send(&g_conn[CL], data, sizeof data, &acc) == ZSSH_OK && acc == sizeof data);
    const uint8_t *p;
    CHECK(zssh_output_peek(&g_conn[CL], &p, &pn) == ZSSH_OK);
    CHECK(pn > sizeof data + 4 + 16 && pn < sizeof pkt);
    memcpy(pkt, p, pn);
    CHECK(zssh_output_consume(&g_conn[CL], pn) == ZSSH_OK);
    snap_take(1);
    /* control: untouched packet is delivered */
    CHECK(zssh_input(&g_conn[SV], pkt, pn, &cons) != ZSSH_STATUS_FAILED && cons == pn);
    CHECK(zssh_channel_recv(&g_conn[SV], rb, sizeof rb, &got) == ZSSH_OK && got == sizeof data && memcmp(rb, data, got) == 0);
    for (int t = 0; t < 80; t++) {
        r = r * 6364136223846793005ull + 1442695040888963407ull;
        tamper_one(t, r, pkt, pn);
    }
}

/* ---- misuse ---------------------------------------------------------------------- */
static void unchanged(const struct zssh_conn *saved, int i)
{
    CHECK(memcmp(saved, &g_conn[i], sizeof g_conn[i]) == 0);
}

/* NULL and out-of-range arguments are refused with BAD_CALL and change nothing. */
static void misuse_null_args(struct zssh_conn *c, const struct zssh_conn *saved,
                             size_t pending)
{
    uint8_t d[8] = { 0 }, rb[8], ob[8];
    size_t cons = 9, prod = 9, acc = 9, got = 9, n = 9;
    const uint8_t *p = nullptr;
    struct zssh_channel_flags f = {0};
    struct zssh_session_info si;
    cons = 9; CHECK(zssh_input(c, nullptr, 5, &cons) == ZSSH_STATUS_BAD_CALL && cons == 0);
    CHECK(zssh_input(c, d, 1, nullptr) == ZSSH_STATUS_BAD_CALL);
    cons = 9; prod = 9; CHECK(zssh_pump(c, nullptr, 3, &cons, ob, 8, &prod) == ZSSH_STATUS_BAD_CALL && cons == 0 && prod == 0);
    cons = 9; prod = 9; CHECK(zssh_pump(c, d, 1, &cons, nullptr, 5, &prod) == ZSSH_STATUS_BAD_CALL && cons == 0 && prod == 0);
    cons = 9; CHECK(zssh_pump(c, d, 1, nullptr, ob, 8, &prod) == ZSSH_STATUS_BAD_CALL);
    CHECK(zssh_pump(c, d, 1, &cons, ob, 8, nullptr) == ZSSH_STATUS_BAD_CALL);
    CHECK(zssh_output_peek(nullptr, &p, &n) == ZSSH_BAD_CALL);
    CHECK(zssh_output_peek(c, nullptr, &n) == ZSSH_BAD_CALL);
    CHECK(zssh_output_peek(c, &p, nullptr) == ZSSH_BAD_CALL);
    CHECK(zssh_output_consume(c, pending + 1) == ZSSH_BAD_CALL);
    CHECK(zssh_output_consume(nullptr, 0) == ZSSH_BAD_CALL);
    acc = 9; CHECK(zssh_channel_send(c, nullptr, 1, &acc) == ZSSH_BAD_CALL && acc == 0);
    CHECK(zssh_channel_send(c, d, 1, nullptr) == ZSSH_BAD_CALL);
    acc = 9; CHECK(zssh_channel_send(nullptr, d, 1, &acc) == ZSSH_BAD_CALL && acc == 0);
    got = 9; CHECK(zssh_channel_recv(c, nullptr, 1, &got) == ZSSH_BAD_CALL && got == 0);
    CHECK(zssh_channel_recv(c, rb, 1, nullptr) == ZSSH_BAD_CALL);
    CHECK(zssh_channel_send_eof(nullptr) == ZSSH_BAD_CALL);
    CHECK(zssh_channel_close(nullptr) == ZSSH_BAD_CALL);
    CHECK(zssh_channel_flags_get(c, nullptr) == ZSSH_BAD_CALL);
    CHECK(zssh_channel_flags_get(nullptr, &f) == ZSSH_BAD_CALL);
    CHECK(zssh_session_info_get(nullptr, &si) == ZSSH_BAD_CALL);
    CHECK(zssh_session_info_get(c, nullptr) == ZSSH_BAD_CALL);
    unchanged(saved, CL);
    CHECK(zssh_error(c) == ZSSH_E_NONE && zssh_state(c) == ZSSH_STATE_CHANNEL);
}

static void g_misuse(void)
{
    struct opt o;
    static struct zssh_conn save;
    uint8_t d[8] = { 0 }, rb[8];
    size_t acc = 9, got = 9, cons = 9;
    const uint8_t *p = nullptr;
    struct zssh_channel_flags f = {0};
    struct zssh_session_info si;
    opt_default(&o);
    CHECK(handshake(&o, 1u << 20, 65536));
    CHECK(zssh_channel_send(&g_conn[CL], d, 3, &acc) == ZSSH_OK);        /* some pending output */
    memcpy(&save, &g_conn[CL], sizeof save);
    struct zssh_conn *c = &g_conn[CL];
    size_t pending = 0;
    CHECK(zssh_output_peek(c, &p, &pending) == ZSSH_OK && pending > 0);

    misuse_null_args(c, &save, pending);

    /* send after our own EOF: BAD_CALL, nothing queued; the flags show only the EOF */
    CHECK(zssh_channel_send_eof(c) == ZSSH_OK);
    memcpy(&save, &g_conn[CL], sizeof save);
    acc = 9; CHECK(zssh_channel_send(c, d, 3, &acc) == ZSSH_BAD_CALL && acc == 0);
    unchanged(&save, CL);

    /* operations before the channel exists */
    pair_init(&o, 1u << 20, 65536);
    memcpy(&save, &g_conn[CL], sizeof save);
    acc = 9; CHECK(zssh_channel_send(c, d, 3, &acc) == ZSSH_BAD_CALL && acc == 0);
    got = 9; CHECK(zssh_channel_recv(c, rb, 3, &got) == ZSSH_BAD_CALL && got == 0);
    CHECK(zssh_channel_send_eof(c) == ZSSH_BAD_CALL);
    CHECK(zssh_channel_close(c) == ZSSH_BAD_CALL);
    CHECK(zssh_session_info_get(c, &si) == ZSSH_OK && !si.valid);
    CHECK(zssh_channel_flags_get(c, &f) == ZSSH_OK && !f.sent_eof && f.send_window == 0 && f.recv_window == 0);
    unchanged(&save, CL);
    CHECK(zssh_state(c) == ZSSH_STATE_VERSION && zssh_error(c) == ZSSH_E_NONE);
    /* an uninitialised struct is misuse, not a crash */
    static struct zssh_conn blank;
    CHECK(zssh_input(&blank, d, 1, &cons) == ZSSH_STATUS_BAD_CALL && cons == 0);
    CHECK(zssh_state(&blank) == ZSSH_STATE_FAILED);
}

#include "test_zssh_e2e.inc"  /* bulk-transfer and review-round groups (1500-line ceiling) */

/* ---- main ---------------------------------------------------------------------------- */
int main(void)
{
    fill_key(g_hseed, g_hpk, 1);
    fill_key(g_hseed2, g_hpk2, 2);
    fill_key(g_useed, g_upk, 3);
    fill_key(g_useed2, g_upk2, 4);

    RUN(g_null_args);
    RUN(g_init_refusals);
    RUN(g_version);
    RUN(g_handshake_matrix);
    RUN(g_transcript_equal);
    RUN(g_kex_negative);
    RUN(g_witness_kex_policy);
    RUN(g_auth_boundaries);
    RUN(g_auth_probe_then_sign);
    RUN(g_wrong_user_key);
    RUN(g_post_auth_messages);
    RUN(g_data_large_chunks);
    RUN(g_data_tiny_drains);
    RUN(g_data_one_byte);
    RUN(g_backpressure);
    RUN(g_half_close);
    RUN(g_transport_eof);
    RUN(g_eof_clean);
    RUN(g_rng_sweep);
    RUN(g_partial_prefix);
    RUN(g_tamper);
    RUN(g_misuse);
    RUN(g_reserve_saturation);
    RUN(g_wrong_session);
    RUN(g_misuse_terminal);
    RUN(g_pump_input_stop);
    RUN(g_send_runt_again);
    RUN(g_rekey_limit);
    RUN(g_trailing_and_terminal_pump);
    RUN(g_open_wrong_target);
    RUN(g_send_adjust_again);

    printf("test_zssh: %d checks, %d failed\n", g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
