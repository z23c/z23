/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zssh_channel — layer (d): the single direct-tcpip channel.
 *
 * Standalone: links only zssh_channel.c. The sticky-error wire helpers of the
 * packet layer are replaced by minimal test doubles below (this file must not
 * depend on another layer's implementation). All peer messages in the tests
 * are built with the independent put32()/raw byte arrays here, and the
 * expected encodings are hand-built from RFC 4254 5.1, 5.2, 5.3, 5.4, 7.2. */

#include "zssh_internal.h"

#include "base/serialize_le.h"

#include <stdio.h>
#include <string.h>

/* ---- test doubles for the wire helpers (zssh_packet.c is another lane) --- */

void zssh_rd_init(struct zssh_rd *r, const uint8_t *p, size_t len)
{ r->p = p; r->len = p ? len : 0; r->off = 0; r->bad = (p == nullptr && len != 0); }
size_t zssh_rd_left(const struct zssh_rd *r) { return r->len - r->off; }
bool zssh_rd_ok(const struct zssh_rd *r) { return !r->bad; }
bool zssh_rd_done(const struct zssh_rd *r) { return !r->bad && r->off == r->len; }
void zssh_rd_bytes(struct zssh_rd *r, const uint8_t **s, size_t n)
{
    if (r->bad || n > r->len - r->off) { r->bad = true; *s = nullptr; return; }
    *s = r->p + r->off; r->off += n;
}
uint8_t zssh_rd_u8(struct zssh_rd *r)
{ const uint8_t *s; zssh_rd_bytes(r, &s, 1); return s ? s[0] : 0; }
uint32_t zssh_rd_u32(struct zssh_rd *r)
{
    const uint8_t *s; zssh_rd_bytes(r, &s, 4);
    return s ? zcl_read_u32_be(s) : 0;
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
void zssh_wr_u32(struct zssh_wr *w, uint32_t v)
{
    uint8_t b[4];
    zcl_write_u32_be(b, v);
    zssh_wr_bytes(w, b, 4);
}
void zssh_wr_string(struct zssh_wr *w, const uint8_t *b, size_t n)
{ zssh_wr_u32(w, (uint32_t)n); zssh_wr_bytes(w, b, n); }
void zssh_wr_cstr(struct zssh_wr *w, const char *s)
{ zssh_wr_string(w, (const uint8_t *)s, strlen(s)); }

/* ---- harness ------------------------------------------------------------ */

static int g_fail;
#define CHECK(cond, name) do { if (!(cond)) { \
    fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, (name)); g_fail++; } } while (0)

static void put32(uint8_t *p, uint32_t v)
{ zcl_write_u32_be(p, v); }

/* Peer-message builders, independent of the module's builders. */
static size_t m_hdr(uint8_t *b, uint8_t msg, uint32_t recip)
{ b[0] = msg; put32(b + 1, recip); return 5; }
static size_t m_data(uint8_t *b, uint32_t recip, const uint8_t *d, size_t n)
{
    size_t o = m_hdr(b, ZSSH_MSG_CHANNEL_DATA, recip);
    put32(b + o, (uint32_t)n); o += 4;
    if (n) memcpy(b + o, d, n);
    return o + n;
}
static size_t m_u32msg(uint8_t *b, uint8_t msg, uint32_t recip, uint32_t v)
{ size_t o = m_hdr(b, msg, recip); put32(b + o, v); return o + 4; }
static size_t m_str(uint8_t *b, const char *s)
{ size_t n = strlen(s); put32(b, (uint32_t)n); memcpy(b + 4, s, n); return 4 + n; }
/* CHANNEL_OPEN with arbitrary type/host/port. */
static size_t m_open(uint8_t *b, const char *type, uint32_t sender, uint32_t win,
                     uint32_t maxpkt, const char *host, uint32_t port)
{
    size_t o = 0;
    b[o++] = ZSSH_MSG_CHANNEL_OPEN;
    o += m_str(b + o, type);
    put32(b + o, sender); o += 4;
    put32(b + o, win); o += 4;
    put32(b + o, maxpkt); o += 4;
    o += m_str(b + o, host);
    put32(b + o, port); o += 4;
    o += m_str(b + o, "0.0.0.0");
    put32(b + o, 0); o += 4;
    return o;
}

static bool wr_eq(const struct zssh_wr *w, const uint8_t *exp, size_t n)
{ return zssh_wr_ok(w) && w->off == n && memcmp(w->p, exp, n) == 0; }

static void group(const char *name, int before)
{ printf("zssh_channel %-34s %s\n", name, g_fail == before ? "ok" : "FAILED"); }

/* A confirmed pair: cl = client side, sv = server side. */
static void open_pair(struct zssh_chan *cl, struct zssh_chan *sv, uint32_t cl_win)
{
    uint8_t buf[256];
    struct zssh_wr w;
    zssh_chan_init(cl);
    zssh_chan_init(sv);
    zssh_wr_init(&w, buf, sizeof buf);
    zssh_chan_build_open(&w);
    uint32_t rid = 99, why = 99;
    CHECK(zssh_chan_server_open(sv, buf, w.off, &rid, &why) == ZSSH_E_NONE, "pair open");
    zssh_chan_mark_open_sent(cl);           /* CONN's call once the open is queued */
    CHECK(cl->state == ZSSH_CH_OPEN_SENT, "pair open_sent mark");
    zssh_wr_init(&w, buf, sizeof buf);
    zssh_chan_build_open_confirm(sv, &w);
    CHECK(zssh_chan_client_confirm(cl, buf, w.off) == ZSSH_E_NONE, "pair confirm");
    (void)cl_win;
}

/* Deliver one DATA message from tx to rx; returns the rx error. */
static enum zssh_error push_data(struct zssh_chan *tx, struct zssh_chan *rx,
                                 const uint8_t *d, size_t n)
{
    static uint8_t msg[ZSSH_CHAN_MAX_PACKET + 64];
    struct zssh_wr w;
    zssh_wr_init(&w, msg, sizeof msg);
    enum zssh_error e = zssh_chan_send_build(tx, d, n, &w);
    if (e != ZSSH_E_NONE) return e;
    e = zssh_chan_on_data(rx, msg, w.off);
    if (e == ZSSH_E_NONE)
        zssh_chan_send_commit(tx, n);        /* CONN: after the queue commit */
    return e;
}

/* rx reports freed window to tx if due. Returns the added amount. */
static uint32_t push_adjust(struct zssh_chan *rx, struct zssh_chan *tx)
{
    uint8_t msg[16];
    struct zssh_wr w;
    uint32_t add = zssh_chan_window_adjust_due(rx);
    if (!add) return 0;
    zssh_wr_init(&w, msg, sizeof msg);
    zssh_chan_build_window_adjust(rx, add, &w);
    CHECK(zssh_chan_on_window_adjust(tx, msg, w.off) == ZSSH_E_NONE, "adjust delivered");
    zssh_chan_window_adjust_sent(rx, add);
    return add;
}

/* ---- 1. encodings ------------------------------------------------------- */

static void enc_rollback(struct zssh_chan *c);

static void test_encodings(void)
{
    int before = g_fail;
    uint8_t b[256];
    struct zssh_wr w;
    struct zssh_chan c;
    zssh_chan_init(&c);
    c.remote_id = 0x01020304u;

    /* RFC 4254 7.2 direct-tcpip open: window 0x8000, max packet 0x4000. */
    static const uint8_t open_exp[] = {
        90, 0,0,0,12, 'd','i','r','e','c','t','-','t','c','p','i','p',
        0,0,0,0,  0,0,0x80,0,  0,0,0x40,0,
        0,0,0,14, 'd','e','v','i','c','e','.','i','n','v','a','l','i','d',
        0,0,0,1,
        0,0,0,7, '0','.','0','.','0','.','0',
        0,0,0,0 };
    zssh_wr_init(&w, b, sizeof b);
    zssh_chan_build_open(&w);
    CHECK(wr_eq(&w, open_exp, sizeof open_exp), "open encoding");

    /* RFC 4254 5.1 OPEN_CONFIRMATION: recipient(peer id), sender(0), window, maxpkt. */
    static const uint8_t conf_exp[] = { 91, 1,2,3,4, 0,0,0,0, 0,0,0x80,0, 0,0,0x40,0 };
    zssh_wr_init(&w, b, sizeof b);
    zssh_chan_build_open_confirm(&c, &w);
    CHECK(wr_eq(&w, conf_exp, sizeof conf_exp), "confirm encoding");

    /* RFC 4254 5.1 OPEN_FAILURE: recipient, reason, empty description, empty language. */
    static const uint8_t fail_exp[] = { 92, 0,0,0,7, 0,0,0,3, 0,0,0,0, 0,0,0,0 };
    zssh_wr_init(&w, b, sizeof b);
    zssh_chan_build_open_failure(7, ZSSH_OPEN_UNKNOWN_CHANNEL_TYPE, &w);
    CHECK(wr_eq(&w, fail_exp, sizeof fail_exp), "open failure encoding");

    static const uint8_t adj_exp[] = { 93, 1,2,3,4, 0,0,0x40,0 };
    zssh_wr_init(&w, b, sizeof b);
    zssh_chan_build_window_adjust(&c, 0x4000, &w);
    CHECK(wr_eq(&w, adj_exp, sizeof adj_exp), "window adjust encoding");

    static const uint8_t eof_exp[] = { 96, 1,2,3,4 };
    zssh_wr_init(&w, b, sizeof b);
    zssh_chan_build_eof(&c, &w);
    CHECK(wr_eq(&w, eof_exp, sizeof eof_exp), "eof encoding");

    static const uint8_t close_exp[] = { 97, 1,2,3,4 };
    zssh_wr_init(&w, b, sizeof b);
    zssh_chan_build_close(&c, &w);
    CHECK(wr_eq(&w, close_exp, sizeof close_exp), "close encoding");

    static const uint8_t cf_exp[] = { 100, 1,2,3,4 };
    zssh_wr_init(&w, b, sizeof b);
    zssh_chan_build_request_failure(&c, &w);
    CHECK(wr_eq(&w, cf_exp, sizeof cf_exp), "channel failure encoding");

    /* RFC 4254 5.2 DATA: string "hi". Needs an open channel. */
    struct zssh_chan cl, sv;
    open_pair(&cl, &sv, 0);
    cl.remote_id = 0x01020304u;
    static const uint8_t data_exp[] = { 94, 1,2,3,4, 0,0,0,2, 'h','i' };
    zssh_wr_init(&w, b, sizeof b);
    CHECK(zssh_chan_send_build(&cl, (const uint8_t *)"hi", 2, &w) == ZSSH_E_NONE, "data build");
    CHECK(wr_eq(&w, data_exp, sizeof data_exp), "data encoding");
    /* A refused queue costs no window: build alone never charges. */
    CHECK(cl.send_window == ZSSH_CHAN_WINDOW, "build does not charge window");
    zssh_chan_send_commit(&cl, 2);
    CHECK(cl.send_window == ZSSH_CHAN_WINDOW - 2, "commit charges window");
    zssh_chan_send_commit(&cl, 0xffffffffu);
    CHECK(cl.send_window == 0, "commit never underflows");
    cl.send_window = ZSSH_CHAN_WINDOW - 2;

    /* Truncated output buffer: reported, window not charged, off rolled back,
     * sticky bad left set (builder rule). */
    uint32_t before_win = cl.send_window;
    zssh_wr_init(&w, b, 6);
    zssh_wr_u8(&w, 0xee);                    /* earlier bytes in the writer stay */
    CHECK(zssh_chan_send_build(&cl, (const uint8_t *)"hi", 2, &w) == ZSSH_E_INTERNAL,
          "short writer refused");
    CHECK(cl.send_window == before_win, "short writer does not charge");
    CHECK(w.off == 1 && w.bad && b[0] == 0xee, "short writer rolled back, bad kept");

    enc_rollback(&c);
    /* A builder after a prior successful one rolls back only its own bytes. */
    zssh_wr_init(&w, b, 7);
    zssh_chan_build_eof(&c, &w);
    zssh_chan_build_close(&c, &w);
    CHECK(w.off == 5 && w.bad, "second builder rolled back to first message");

    /* Opening: the server must accept exactly what the client builds and
     * record the peer's parameters. */
    CHECK(sv.state == ZSSH_CH_OPEN && sv.send_window == ZSSH_CHAN_WINDOW &&
          sv.send_maxpkt == ZSSH_CHAN_MAX_PACKET && sv.recv_window == ZSSH_CHAN_WINDOW,
          "server open parameters");
    CHECK(cl.state == ZSSH_CH_OPEN && cl.send_window == ZSSH_CHAN_WINDOW - 2 &&
          cl.recv_window == ZSSH_CHAN_WINDOW, "client confirm parameters");
    group("encodings", before);
}

/* Every builder: failure rolls off back to its start and keeps bad set. */
static void enc_rollback(struct zssh_chan *c)
{
    uint8_t b[256];
    struct zssh_wr w;
    for (size_t cap = 0; cap < 3; cap++) {
        zssh_wr_init(&w, b, cap);
        zssh_chan_build_open(&w);
        CHECK(w.off == 0 && w.bad, "open rollback");
        zssh_wr_init(&w, b, cap);
        zssh_chan_build_open_confirm(c, &w);
        CHECK(w.off == 0 && w.bad, "confirm rollback");
        zssh_wr_init(&w, b, cap);
        zssh_chan_build_open_failure(1, 2, &w);
        CHECK(w.off == 0 && w.bad, "open failure rollback");
        zssh_wr_init(&w, b, cap);
        zssh_chan_build_window_adjust(c, 1, &w);
        CHECK(w.off == 0 && w.bad, "adjust rollback");
        zssh_wr_init(&w, b, cap);
        zssh_chan_build_eof(c, &w);
        CHECK(w.off == 0 && w.bad, "eof rollback");
        zssh_wr_init(&w, b, cap);
        zssh_chan_build_close(c, &w);
        CHECK(w.off == 0 && w.bad, "close rollback");
        zssh_wr_init(&w, b, cap);
        zssh_chan_build_request_failure(c, &w);
        CHECK(w.off == 0 && w.bad, "channel failure rollback");
    }
}

/* ---- 2. transfers ------------------------------------------------------- */

static uint64_t g_rng = 0x9e3779b97f4a7c15ull;
static uint64_t rng_next(void)
{
    g_rng ^= g_rng >> 12; g_rng ^= g_rng << 25; g_rng ^= g_rng >> 27;
    return g_rng * 0x2545f4914f6cdd1dull;
}

#define BIG (1u << 20)
#define REV 300000u
static uint8_t g_src_f[BIG], g_dst_f[BIG], g_src_r[REV], g_dst_r[REV];

static void test_blocked_consumer(void)
{
    int before = g_fail;
    struct zssh_chan cl, sv;
    open_pair(&cl, &sv, 0);
    static uint8_t blk[1000];
    for (size_t i = 0; i < sizeof blk; i++) blk[i] = (uint8_t)(i * 7 + 3);
    size_t sent = 0;
    for (;;) {
        size_t take = zssh_chan_send_plan(&cl, sizeof blk, 16384);
        if (!take) break;
        CHECK(push_data(&cl, &sv, blk, take) == ZSSH_E_NONE, "fill push");
        sent += take;
    }
    CHECK(sent == ZSSH_CHAN_WINDOW, "sender stopped exactly at the window");
    CHECK(cl.send_window == 0 && sv.recv_window == 0, "both window views at 0");
    CHECK(zssh_chan_send_plan(&cl, 1, 16384) == 0, "plan blocked at window 0");
    CHECK(sv.ring_len == ZSSH_CHAN_WINDOW, "ring exactly full");
    /* A byte beyond the window from a misbehaving peer is a typed error. */
    uint8_t m[16];
    size_t ml = m_data(m, 0, (const uint8_t *)"x", 1);
    CHECK(zssh_chan_on_data(&sv, m, ml) == ZSSH_E_WINDOW, "overrun at window 0");
    CHECK(sv.ring_len == ZSSH_CHAN_WINDOW, "overrun leaves ring untouched");
    /* Consumer reads less than half: nothing owed; then more: adjust due. */
    uint8_t rb[20000];
    CHECK(zssh_chan_recv(&sv, rb, 100) == 100, "read 100");
    CHECK(zssh_chan_window_adjust_due(&sv) == 0, "below half: no adjust");
    CHECK(push_adjust(&sv, &cl) == 0 && cl.send_window == 0, "sender still blocked");
    CHECK(zssh_chan_recv(&sv, rb, 16284) == 16284, "read to half");
    CHECK(zssh_chan_window_adjust_due(&sv) == ZSSH_CHAN_WINDOW / 2, "adjust due at half");
    CHECK(push_adjust(&sv, &cl) == ZSSH_CHAN_WINDOW / 2, "adjust delivered");
    CHECK(cl.send_window == ZSSH_CHAN_WINDOW / 2 && sv.recv_window == ZSSH_CHAN_WINDOW / 2,
          "window resumed");
    CHECK(zssh_chan_window_adjust_due(&sv) == 0, "adjust not due twice");
    CHECK(zssh_chan_send_plan(&cl, 5000, 16384) == 5000, "sender resumes");
    CHECK(zssh_chan_send_plan(&cl, 20000, 16384) == 16384, "plan bounded by max packet/room");
    CHECK(zssh_chan_send_plan(&cl, 20000, 100) == 100, "plan bounded by queue room");
    CHECK(sv.recv_window + sv.ring_len + sv.freed_unreported == ZSSH_CHAN_WINDOW, "invariant");
    group("blocked consumer", before);
}

/* Fill both source streams from the PRNG and clear the destinations. */
static void transfer_fill_sources(void)
{
    for (size_t i = 0; i < BIG; i++) g_src_f[i] = (uint8_t)(rng_next() >> 32);
    for (size_t i = 0; i < REV; i++) g_src_r[i] = (uint8_t)(rng_next() >> 40);
    memset(g_dst_f, 0xA5, sizeof g_dst_f);
    memset(g_dst_r, 0x5A, sizeof g_dst_r);
}

/* One client -> server step: send what the window allows. */
static void transfer_forward_step(struct zssh_chan *cl, struct zssh_chan *sv,
                                  size_t *fpos, size_t *stalls)
{
    if (*fpos < BIG) {                                     /* client -> server */
        size_t want = 1 + rng_next() % 5000;
        if (want > BIG - *fpos) want = BIG - *fpos;
        size_t take = zssh_chan_send_plan(cl, want, ZSSH_CHAN_MAX_PACKET);
        if (take) {
            CHECK(push_data(cl, sv, g_src_f + *fpos, take) == ZSSH_E_NONE, "fwd push");
            *fpos += take;
        } else {
            (*stalls)++;
            CHECK(cl->send_window == 0, "forward block only at window 0");
        }
    }
}

/* One server -> client step: send what the window allows. */
static void transfer_reverse_step(struct zssh_chan *sv, struct zssh_chan *cl, size_t *rpos)
{
    if (*rpos < REV) {                                     /* server -> client */
        size_t want = 1 + rng_next() % 3000;
        if (want > REV - *rpos) want = REV - *rpos;
        size_t take = zssh_chan_send_plan(sv, want, ZSSH_CHAN_MAX_PACKET);
        if (take) {
            CHECK(push_data(sv, cl, g_src_r + *rpos, take) == ZSSH_E_NONE, "rev push");
            *rpos += take;
        }
    }
}

/* Slow server-side consumer of the forward stream. */
static void transfer_drain_server(struct zssh_chan *sv, struct zssh_chan *cl, uint8_t *rb,
                                  size_t *frd, size_t *adjusts)
{
    size_t got = zssh_chan_recv(sv, rb, 1 + rng_next() % 7000);
    memcpy(g_dst_f + *frd, rb, got); *frd += got;
    *adjusts += push_adjust(sv, cl) != 0;
}

/* Client-side consumer of the reverse stream. */
static void transfer_drain_client(struct zssh_chan *cl, struct zssh_chan *sv, uint8_t *rb,
                                  size_t *rrd, size_t *adjusts)
{
    size_t got = zssh_chan_recv(cl, rb, 1 + rng_next() % 5000);
    memcpy(g_dst_r + *rrd, rb, got); *rrd += got;
    *adjusts += push_adjust(cl, sv) != 0;
}

/* Half-close: client EOF, then the server EOF, with data still flowing. */
static void transfer_eof_exchange(struct zssh_chan *cl, struct zssh_chan *sv, uint8_t *rb)
{
    uint8_t m[64];
    struct zssh_wr w;
    /* client finishes its sending: EOF. */
    zssh_wr_init(&w, m, sizeof m);
    zssh_chan_build_eof(cl, &w);
    zssh_chan_mark_eof_sent(cl);                             /* CONN marks it sent */
    CHECK(zssh_chan_on_eof(sv, m, w.off) == ZSSH_E_NONE, "server sees EOF");
    CHECK(sv->recv_eof && !sv->recv_close && sv->state == ZSSH_CH_OPEN, "EOF is not CLOSE");
    /* client side: no more data, but it still receives. */
    CHECK(zssh_chan_send_plan(cl, 10, 100) == 0, "no send after our EOF");
    CHECK(push_data(cl, sv, (const uint8_t *)"z", 1) == ZSSH_E_PROTOCOL, "send_build after EOF");
    /* server after recv-EOF can still send until it sends EOF. */
    CHECK(zssh_chan_send_plan(sv, 10, 100) == 10, "server may still send after recv-EOF");
    CHECK(push_data(sv, cl, (const uint8_t *)"tail-data", 9) == ZSSH_E_NONE, "send after recv-EOF");
    CHECK(zssh_chan_recv(cl, rb, 100) == 9 && memcmp(rb, "tail-data", 9) == 0, "client gets tail");
    /* data from client after its EOF reaching the server is refused. */
    size_t ml = m_data(m, 0, (const uint8_t *)"late", 4);
    CHECK(zssh_chan_on_data(sv, m, ml) == ZSSH_E_PROTOCOL, "no data after EOF accepted");
    ml = m_hdr(m, ZSSH_MSG_CHANNEL_EOF, 0);
    CHECK(zssh_chan_on_eof(sv, m, ml) == ZSSH_E_PROTOCOL, "second EOF refused");
    /* server EOF. */
    zssh_wr_init(&w, m, sizeof m);
    zssh_chan_build_eof(sv, &w);
    zssh_chan_mark_eof_sent(sv);
    CHECK(zssh_chan_on_eof(cl, m, w.off) == ZSSH_E_NONE, "client sees EOF");
    CHECK(zssh_chan_send_plan(sv, 10, 100) == 0, "server stops after own EOF");
}

/* CLOSE handshake: client CLOSE, then the server answers once. */
static void transfer_close_exchange(struct zssh_chan *cl, struct zssh_chan *sv)
{
    uint8_t m[64];
    struct zssh_wr w;
    /* client CLOSE; server records it, answers once. */
    zssh_wr_init(&w, m, sizeof m);
    zssh_chan_build_close(cl, &w);
    zssh_chan_mark_close_sent(cl);
    CHECK(cl->sent_close && cl->state == ZSSH_CH_OPEN, "our CLOSE alone does not close");
    /* After our CLOSE the peer may still send data / window until its CLOSE. */
    size_t am = m_u32msg(m + 32, ZSSH_MSG_CHANNEL_WINDOW_ADJUST, 0, 5);
    CHECK(zssh_chan_on_window_adjust(cl, m + 32, am) == ZSSH_E_NONE,
          "window adjust accepted after our CLOSE");
    CHECK(zssh_chan_on_close(sv, m, w.off) == ZSSH_E_NONE, "server sees CLOSE");
    CHECK(sv->recv_close && !sv->sent_close && sv->state == ZSSH_CH_OPEN, "CLOSE awaits our answer");
    CHECK(zssh_chan_on_close(sv, m, w.off) == ZSSH_E_PROTOCOL, "second CLOSE refused");
    zssh_wr_init(&w, m, sizeof m);
    zssh_chan_build_close(sv, &w);
    zssh_chan_mark_close_sent(sv);
    CHECK(sv->state == ZSSH_CH_CLOSED, "mark_close_sent after peer CLOSE closes");
    CHECK(zssh_chan_on_close(cl, m, w.off) == ZSSH_E_NONE, "client sees answer");
    CHECK(cl->state == ZSSH_CH_CLOSED, "client closed (on_close after own CLOSE)");
    CHECK(zssh_chan_window_adjust_due(cl) == 0, "no adjust after close");
}

static void test_big_transfer(void)
{
    int before = g_fail;
    struct zssh_chan cl, sv;
    open_pair(&cl, &sv, 0);
    transfer_fill_sources();
    size_t fpos = 0, frd = 0, rpos = 0, rrd = 0, stalls = 0, adjusts = 0;
    static uint8_t rb[7001];
    for (size_t it = 0; it < 50000000u && (frd < BIG || rrd < REV); it++) {
        transfer_forward_step(&cl, &sv, &fpos, &stalls);
        transfer_reverse_step(&sv, &cl, &rpos);
        if (rng_next() % 4 == 0) {                            /* slow consumers */
            transfer_drain_server(&sv, &cl, rb, &frd, &adjusts);
        }
        if (rng_next() % 2 == 0) {
            transfer_drain_client(&cl, &sv, rb, &rrd, &adjusts);
        }
        CHECK(sv.recv_window + sv.ring_len + sv.freed_unreported == ZSSH_CHAN_WINDOW, "inv sv");
        CHECK(cl.recv_window + cl.ring_len + cl.freed_unreported == ZSSH_CHAN_WINDOW, "inv cl");
    }
    CHECK(fpos == BIG && frd == BIG && rpos == REV && rrd == REV, "all bytes moved");
    CHECK(memcmp(g_src_f, g_dst_f, BIG) == 0, "1 MiB forward stream byte-exact");
    CHECK(memcmp(g_src_r, g_dst_r, REV) == 0, "reverse stream byte-exact");
    CHECK(stalls > 10 && adjusts > 10, "window actually stalled and resumed");

    /* ---- half-close then close (group 4 shares this pair) ---- */
    int b4 = g_fail;
    transfer_eof_exchange(&cl, &sv, rb);
    transfer_close_exchange(&cl, &sv);
    struct zssh_channel_flags f;
    zssh_chan_flags(&sv, &f);
    CHECK(f.sent_eof && f.recv_eof && f.sent_close && f.recv_close, "flags all set");
    group("half-close and close", b4);
    zssh_chan_wipe(&cl);
    CHECK(cl.ring_len == 0 && cl.state == ZSSH_CH_IDLE && cl.ring[0] == 0, "wipe zeroes");
    group("1 MiB transfer", before);
}

/* ---- 3. controls -------------------------------------------------------- */

static void open_malformed_and_valid(uint8_t *m);

static void test_open_controls(void)
{
    int before = g_fail;
    uint8_t m[256];
    uint32_t rid, why;
    struct zssh_chan s;
    size_t n;

    zssh_chan_init(&s);
    n = m_open(m, "session", 7, 1000, 500, ZSSH_FWD_HOST, ZSSH_FWD_PORT);
    CHECK(zssh_chan_server_open(&s, m, n, &rid, &why) == ZSSH_E_CHANNEL_REFUSED, "session refused");
    CHECK(why == ZSSH_OPEN_UNKNOWN_CHANNEL_TYPE && rid == 7, "session reason 3, id echoed");
    CHECK(s.state == ZSSH_CH_IDLE, "state unchanged (type)");
    static const char *const types[] = { "forwarded-tcpip", "x11", "auth-agent@openssh.com",
                                         "direct-tcpi", "direct-tcpipp", "" };
    for (size_t i = 0; i < sizeof types / sizeof *types; i++) {
        n = m_open(m, types[i], 9, 1000, 500, ZSSH_FWD_HOST, ZSSH_FWD_PORT);
        CHECK(zssh_chan_server_open(&s, m, n, &rid, &why) == ZSSH_E_CHANNEL_REFUSED &&
              why == ZSSH_OPEN_UNKNOWN_CHANNEL_TYPE && s.state == ZSSH_CH_IDLE, "other type refused");
    }
    n = m_open(m, "direct-tcpip", 8, 1000, 500, "other.invalid", ZSSH_FWD_PORT);
    CHECK(zssh_chan_server_open(&s, m, n, &rid, &why) == ZSSH_E_CHANNEL_REFUSED, "wrong host refused");
    CHECK(why == ZSSH_OPEN_ADMIN_PROHIBITED && rid == 8 && s.state == ZSSH_CH_IDLE, "wrong host reason 1");
    n = m_open(m, "direct-tcpip", 8, 1000, 500, "device.invali", ZSSH_FWD_PORT);
    CHECK(zssh_chan_server_open(&s, m, n, &rid, &why) == ZSSH_E_CHANNEL_REFUSED, "host prefix refused");
    n = m_open(m, "direct-tcpip", 8, 1000, 500, "device.invalid.", ZSSH_FWD_PORT);
    CHECK(zssh_chan_server_open(&s, m, n, &rid, &why) == ZSSH_E_CHANNEL_REFUSED &&
          why == ZSSH_OPEN_ADMIN_PROHIBITED && rid == 8 && s.state == ZSSH_CH_IDLE,
          "host longer than device.invalid refused");
    n = m_open(m, "direct-tcpip", 8, 1000, 500, "device.invalid.example", ZSSH_FWD_PORT);
    CHECK(zssh_chan_server_open(&s, m, n, &rid, &why) == ZSSH_E_CHANNEL_REFUSED &&
          why == ZSSH_OPEN_ADMIN_PROHIBITED, "host with suffix refused");
    n = m_open(m, "direct-tcpip", 8, 1000, 500, ZSSH_FWD_HOST, ZSSH_FWD_PORT + 1);
    CHECK(zssh_chan_server_open(&s, m, n, &rid, &why) == ZSSH_E_CHANNEL_REFUSED &&
          why == ZSSH_OPEN_ADMIN_PROHIBITED, "wrong port refused");
    n = m_open(m, "direct-tcpip", 8, 1000, 500, "127.0.0.1", 22);
    CHECK(zssh_chan_server_open(&s, m, n, &rid, &why) == ZSSH_E_CHANNEL_REFUSED, "localhost:22 refused");

    open_malformed_and_valid(m);
    group("open controls", before);
}

/* Malformed opens are protocol errors; the valid open is recorded once. */
static void open_malformed_and_valid(uint8_t *m)
{
    uint32_t rid, why;
    struct zssh_chan s;
    size_t n;
    zssh_chan_init(&s);
    /* malformed: truncated, trailing byte, zero max packet, wrong msg byte. */
    n = m_open(m, "direct-tcpip", 8, 1000, 500, ZSSH_FWD_HOST, ZSSH_FWD_PORT);
    CHECK(zssh_chan_server_open(&s, m, n - 1, &rid, &why) == ZSSH_E_PROTOCOL, "truncated open");
    m[n] = 0;
    CHECK(zssh_chan_server_open(&s, m, n + 1, &rid, &why) == ZSSH_E_PROTOCOL, "trailing byte");
    n = m_open(m, "direct-tcpip", 8, 1000, 0, ZSSH_FWD_HOST, ZSSH_FWD_PORT);
    CHECK(zssh_chan_server_open(&s, m, n, &rid, &why) == ZSSH_E_PROTOCOL, "maxpkt 0");
    n = m_open(m, "direct-tcpip", 8, 1000, 500, ZSSH_FWD_HOST, ZSSH_FWD_PORT);
    m[0] = ZSSH_MSG_CHANNEL_DATA;
    CHECK(zssh_chan_server_open(&s, m, n, &rid, &why) == ZSSH_E_PROTOCOL, "wrong msg byte");
    CHECK(zssh_chan_server_open(&s, nullptr, 0, &rid, &why) == ZSSH_E_PROTOCOL, "empty open");
    CHECK(s.state == ZSSH_CH_IDLE, "still idle after all refusals");

    /* success: window / maxpkt recorded, big maxpkt clamped. */
    n = m_open(m, "direct-tcpip", 0xdeadbeefu, 0xffffffffu, 0xffffffffu, ZSSH_FWD_HOST, ZSSH_FWD_PORT);
    CHECK(zssh_chan_server_open(&s, m, n, &rid, &why) == ZSSH_E_NONE, "valid open");
    CHECK(s.state == ZSSH_CH_OPEN && s.remote_id == 0xdeadbeefu && s.send_window == 0xffffffffu &&
          s.send_maxpkt == ZSSH_CHAN_MAX_PACKET && s.recv_window == ZSSH_CHAN_WINDOW, "open recorded");
    /* second channel, even a valid one: refused, state untouched. */
    n = m_open(m, "direct-tcpip", 5, 1000, 500, ZSSH_FWD_HOST, ZSSH_FWD_PORT);
    CHECK(zssh_chan_server_open(&s, m, n, &rid, &why) == ZSSH_E_CHANNEL_REFUSED, "second channel refused");
    CHECK(why == ZSSH_OPEN_RESOURCE_SHORTAGE && rid == 5 && s.remote_id == 0xdeadbeefu, "second reason 4");
    /* ... and after full close too. */
    n = m_hdr(m + 100, ZSSH_MSG_CHANNEL_CLOSE, 0);
    CHECK(zssh_chan_on_close(&s, m + 100, n) == ZSSH_E_NONE, "peer close");
    zssh_chan_mark_close_sent(&s);
    CHECK(s.state == ZSSH_CH_CLOSED, "channel closed");
    n = m_open(m, "direct-tcpip", 5, 1000, 500, ZSSH_FWD_HOST, ZSSH_FWD_PORT);
    CHECK(zssh_chan_server_open(&s, m, n, &rid, &why) == ZSSH_E_CHANNEL_REFUSED, "no reopen after close");
}

static void test_client_controls(void)
{
    int before = g_fail;
    uint8_t m[64];
    struct zssh_chan c;
    size_t o;

    zssh_chan_init(&c);
    zssh_chan_mark_open_sent(&c);
    /* confirmation with a wrong recipient. */
    o = m_hdr(m, ZSSH_MSG_CHANNEL_OPEN_CONFIRMATION, 1);
    put32(m + o, 3); put32(m + o + 4, 1000); put32(m + o + 8, 500);
    CHECK(zssh_chan_client_confirm(&c, m, o + 12) == ZSSH_E_PROTOCOL, "confirm wrong recipient");
    CHECK(c.state == ZSSH_CH_OPEN_SENT, "state unchanged");
    o = m_hdr(m, ZSSH_MSG_CHANNEL_OPEN_CONFIRMATION, 0);
    put32(m + o, 3); put32(m + o + 4, 1000); put32(m + o + 8, 0);
    CHECK(zssh_chan_client_confirm(&c, m, o + 12) == ZSSH_E_PROTOCOL, "confirm maxpkt 0");
    CHECK(zssh_chan_client_confirm(&c, m, o + 11) == ZSSH_E_PROTOCOL, "confirm truncated");
    put32(m + o + 8, 99999);
    CHECK(zssh_chan_client_confirm(&c, m, o + 12) == ZSSH_E_NONE, "confirm ok");
    CHECK(c.remote_id == 3 && c.send_window == 1000 && c.send_maxpkt == ZSSH_CHAN_MAX_PACKET &&
          c.state == ZSSH_CH_OPEN, "confirm recorded and clamped");
    CHECK(zssh_chan_client_confirm(&c, m, o + 12) == ZSSH_E_PROTOCOL, "duplicate confirm refused");

    /* open failure. */
    struct zssh_chan f;
    zssh_chan_init(&f);
    zssh_chan_mark_open_sent(&f);
    struct zssh_wr w;
    zssh_wr_init(&w, m, sizeof m);
    zssh_chan_build_open_failure(0, ZSSH_OPEN_ADMIN_PROHIBITED, &w);
    CHECK(zssh_chan_client_open_failure(&f, m, w.off - 1) == ZSSH_E_PROTOCOL, "failure truncated");
    CHECK(f.state == ZSSH_CH_OPEN_SENT, "truncated failure leaves state");
    CHECK(zssh_chan_client_open_failure(&f, m, w.off) == ZSSH_E_CHANNEL_REFUSED, "failure refused");
    CHECK(f.state == ZSSH_CH_CLOSED, "failure closes");
    zssh_chan_init(&f);                       /* IDLE: unsolicited failure */
    CHECK(zssh_chan_client_open_failure(&f, m, w.off) == ZSSH_E_PROTOCOL, "unsolicited failure");
    /* mark_open_sent only moves IDLE -> OPEN_SENT, never rewinds a later state. */
    zssh_chan_mark_open_sent(&f);
    CHECK(f.state == ZSSH_CH_OPEN_SENT, "idle -> open_sent");
    f.state = ZSSH_CH_OPEN;
    zssh_chan_mark_open_sent(&f);
    CHECK(f.state == ZSSH_CH_OPEN, "mark_open_sent does not rewind");
    group("client controls", before);
}

/* Oversize packets and the receive window bounds. */
static void data_window_limits(struct zssh_chan *sv, uint8_t *m, const uint8_t *big)
{
    /* oversize packet: fits the window (32768) but exceeds max packet. */
    size_t n = m_data(m, 0, big, ZSSH_CHAN_MAX_PACKET + 1);
    CHECK(zssh_chan_on_data(sv, m, n) == ZSSH_E_WINDOW, "oversize packet refused");
    CHECK(sv->ring_len == 0 && sv->recv_window == ZSSH_CHAN_WINDOW, "oversize leaves state");
    n = m_data(m, 0, big, ZSSH_CHAN_MAX_PACKET);
    CHECK(zssh_chan_on_data(sv, m, n) == ZSSH_E_NONE, "max packet accepted");
    CHECK(zssh_chan_on_data(sv, m, n) == ZSSH_E_NONE, "second max packet accepted");
    /* window overrun: window now 0 -> 1 byte is too much. */
    n = m_data(m, 0, big, 1);
    CHECK(zssh_chan_on_data(sv, m, n) == ZSSH_E_WINDOW, "window overrun refused");
    /* partial overrun: free 10 bytes, send 11. */
    uint8_t rb[64];
    CHECK(zssh_chan_recv(sv, rb, 10) == 10, "read 10");
    zssh_chan_window_adjust_sent(sv, 10);
    n = m_data(m, 0, big, 11);
    CHECK(zssh_chan_on_data(sv, m, n) == ZSSH_E_WINDOW, "11 > window 10 refused");
    n = m_data(m, 0, big, 10);
    CHECK(zssh_chan_on_data(sv, m, n) == ZSSH_E_NONE, "exactly the window accepted");
    CHECK(sv->recv_window == 0 && sv->ring_len == ZSSH_CHAN_WINDOW, "window 0, ring full");
    /* ring wrap-around integrity: 10 freed bytes were at the head. */
    CHECK(sv->ring_head == 10, "ring head advanced");
}

/* Malformed DATA messages are protocol errors and store nothing. */
static void data_malformed(struct zssh_chan *cl, struct zssh_chan *sv, uint8_t *m,
                           const uint8_t *big)
{
    /* malformed data. */
    open_pair(cl, sv, 0);
    size_t n = m_data(m, 0, big, 5);
    CHECK(zssh_chan_on_data(sv, m, n - 1) == ZSSH_E_PROTOCOL, "short string body");
    m[n] = 0;
    CHECK(zssh_chan_on_data(sv, m, n + 1) == ZSSH_E_PROTOCOL, "trailing byte");
    CHECK(zssh_chan_on_data(sv, m, 4) == ZSSH_E_PROTOCOL, "header truncated");
    n = m_data(m, 0, big, 1);
    put32(m + 5, 0xffffffffu);
    CHECK(zssh_chan_on_data(sv, m, n) == ZSSH_E_PROTOCOL, "huge string length");
    CHECK(sv->ring_len == 0, "malformed data stored nothing");
    n = m_data(m, 0, big, 0);
    CHECK(zssh_chan_on_data(sv, m, n) == ZSSH_E_NONE, "empty data tolerated");
}

/* unknown recipient on every inbound message. */
static void data_unknown_recipient(struct zssh_chan *sv, uint8_t *m)
{
    uint8_t one[8] = { 0 };
    size_t n = m_data(m, 1, one, 1);
    CHECK(zssh_chan_on_data(sv, m, n) == ZSSH_E_PROTOCOL, "data to channel 1");
    n = m_u32msg(m, ZSSH_MSG_CHANNEL_WINDOW_ADJUST, 1, 10);
    CHECK(zssh_chan_on_window_adjust(sv, m, n) == ZSSH_E_PROTOCOL, "adjust to channel 1");
    n = m_hdr(m, ZSSH_MSG_CHANNEL_EOF, 1);
    CHECK(zssh_chan_on_eof(sv, m, n) == ZSSH_E_PROTOCOL, "eof to channel 1");
    n = m_hdr(m, ZSSH_MSG_CHANNEL_CLOSE, 0xffffffffu);
    CHECK(zssh_chan_on_close(sv, m, n) == ZSSH_E_PROTOCOL, "close to channel -1");
    CHECK(!sv->recv_eof && !sv->recv_close, "unknown recipient changes nothing");
    /* wrong message byte for the handler. */
    n = m_hdr(m, ZSSH_MSG_CHANNEL_CLOSE, 0);
    CHECK(zssh_chan_on_eof(sv, m, n) == ZSSH_E_PROTOCOL, "eof handler rejects close");
}

/* WINDOW_ADJUST may raise the send window to 2^32-1 and no further. */
static void data_adjust_limits(struct zssh_chan *cl, struct zssh_chan *sv, uint8_t *m)
{
    /* adjust overflow. */
    open_pair(cl, sv, 0);
    size_t n = m_u32msg(m, ZSSH_MSG_CHANNEL_WINDOW_ADJUST, 0, 0xffffffffu);
    CHECK(zssh_chan_on_window_adjust(cl, m, n) == ZSSH_E_PROTOCOL, "adjust overflow refused");
    CHECK(cl->send_window == ZSSH_CHAN_WINDOW, "overflow leaves window");
    n = m_u32msg(m, ZSSH_MSG_CHANNEL_WINDOW_ADJUST, 0, 0xffffffffu - ZSSH_CHAN_WINDOW);
    CHECK(zssh_chan_on_window_adjust(cl, m, n) == ZSSH_E_NONE && cl->send_window == 0xffffffffu,
          "adjust to exactly 2^32-1 allowed");
    n = m_u32msg(m, ZSSH_MSG_CHANNEL_WINDOW_ADJUST, 0, 1);
    CHECK(zssh_chan_on_window_adjust(cl, m, n) == ZSSH_E_PROTOCOL, "one more refused");
    CHECK(zssh_chan_on_window_adjust(cl, m, n - 1) == ZSSH_E_PROTOCOL, "adjust truncated");
}

/* messages on a channel that is not open. */
static void data_idle_channel(uint8_t *m)
{
    uint8_t one[8] = { 0 };
    struct zssh_chan idle;
    zssh_chan_init(&idle);
    size_t n = m_data(m, 0, one, 1);
    CHECK(zssh_chan_on_data(&idle, m, n) == ZSSH_E_PROTOCOL, "data on idle channel");
    n = m_hdr(m, ZSSH_MSG_CHANNEL_EOF, 0);
    CHECK(zssh_chan_on_eof(&idle, m, n) == ZSSH_E_PROTOCOL, "eof on idle channel");
    CHECK(zssh_chan_send_plan(&idle, 5, 5) == 0, "no send on idle channel");
}

/* data and adjust after peer CLOSE. */
static void data_after_peer_close(struct zssh_chan *cl, struct zssh_chan *sv, uint8_t *m)
{
    uint8_t one[8] = { 0 };
    open_pair(cl, sv, 0);
    size_t n = m_hdr(m, ZSSH_MSG_CHANNEL_CLOSE, 0);
    CHECK(zssh_chan_on_close(sv, m, n) == ZSSH_E_NONE, "close recorded");
    n = m_data(m, 0, one, 1);
    CHECK(zssh_chan_on_data(sv, m, n) == ZSSH_E_PROTOCOL, "data after CLOSE");
    n = m_u32msg(m, ZSSH_MSG_CHANNEL_WINDOW_ADJUST, 0, 10);
    uint32_t sw = sv->send_window;
    CHECK(zssh_chan_on_window_adjust(sv, m, n) == ZSSH_E_PROTOCOL, "WINDOW_ADJUST after peer CLOSE");
    CHECK(sv->send_window == sw, "refused adjust leaves window");
    n = m_hdr(m, ZSSH_MSG_CHANNEL_EOF, 0);
    CHECK(zssh_chan_on_eof(sv, m, n) == ZSSH_E_PROTOCOL, "EOF after peer CLOSE");
    CHECK(zssh_chan_send_plan(sv, 5, 5) == 0, "no send after peer CLOSE");
}

/* After OUR close (peer CLOSE not yet seen) data and adjust still land. */
static void data_after_our_close(struct zssh_chan *cl, struct zssh_chan *sv, uint8_t *m)
{
    open_pair(cl, sv, 0);
    zssh_chan_mark_close_sent(sv);
    size_t n = m_data(m, 0, (const uint8_t *)"late", 4);
    CHECK(zssh_chan_on_data(sv, m, n) == ZSSH_E_NONE && sv->ring_len == 4,
          "data accepted after our CLOSE");
    n = m_u32msg(m, ZSSH_MSG_CHANNEL_WINDOW_ADJUST, 0, 7);
    CHECK(zssh_chan_on_window_adjust(sv, m, n) == ZSSH_E_NONE &&
          sv->send_window == ZSSH_CHAN_WINDOW + 7, "adjust accepted after our CLOSE");
    n = m_hdr(m, ZSSH_MSG_CHANNEL_CLOSE, 0);
    CHECK(zssh_chan_on_close(sv, m, n) == ZSSH_E_NONE && sv->state == ZSSH_CH_CLOSED,
          "peer CLOSE after ours closes");
    n = m_data(m, 0, (const uint8_t *)"x", 1);
    CHECK(zssh_chan_on_data(sv, m, n) == ZSSH_E_PROTOCOL, "no data once CLOSED");
}

/* Trailing bytes on EOF / CLOSE / WINDOW_ADJUST are protocol errors. */
static void data_trailing_bytes(struct zssh_chan *cl, struct zssh_chan *sv, uint8_t *m)
{
    open_pair(cl, sv, 0);
    size_t n = m_hdr(m, ZSSH_MSG_CHANNEL_EOF, 0); m[n] = 0;
    CHECK(zssh_chan_on_eof(sv, m, n + 1) == ZSSH_E_PROTOCOL && !sv->recv_eof, "EOF trailing byte");
    n = m_hdr(m, ZSSH_MSG_CHANNEL_CLOSE, 0); m[n] = 0;
    CHECK(zssh_chan_on_close(sv, m, n + 1) == ZSSH_E_PROTOCOL && !sv->recv_close, "CLOSE trailing byte");
    n = m_u32msg(m, ZSSH_MSG_CHANNEL_WINDOW_ADJUST, 0, 1); m[n] = 0;
    CHECK(zssh_chan_on_window_adjust(sv, m, n + 1) == ZSSH_E_PROTOCOL &&
          sv->send_window == ZSSH_CHAN_WINDOW, "ADJUST trailing byte");
}

/* window_adjust_sent never credits more than was freed. */
static void data_adjust_sent_clamp(struct zssh_chan *cl, struct zssh_chan *sv)
{
    uint8_t rb[64];
    open_pair(cl, sv, 0);
    CHECK(push_data(cl, sv, (const uint8_t *)"abcdefghij", 10) == ZSSH_E_NONE, "feed ring");
    CHECK(zssh_chan_recv(sv, rb, 5) == 5 && sv->freed_unreported == 5, "free 5");
    zssh_chan_window_adjust_sent(sv, 1000);
    CHECK(sv->freed_unreported == 0 && sv->recv_window == ZSSH_CHAN_WINDOW - 10 + 5,
          "adjust_sent clamped to freed");
    CHECK(sv->recv_window + sv->ring_len + sv->freed_unreported == ZSSH_CHAN_WINDOW,
          "invariant after clamp");
    zssh_chan_window_adjust_sent(sv, 3);
    CHECK(sv->recv_window == ZSSH_CHAN_WINDOW - 10 + 5, "adjust_sent with nothing freed adds nothing");
}

/* scrub: ring bytes and indices zero, state and flags kept. */
static void data_scrub(struct zssh_chan *sv)
{
    zssh_chan_mark_eof_sent(sv);
    CHECK(sv->ring[sv->ring_head] != 0, "ring holds data before scrub");
    zssh_chan_scrub(sv);
    bool zero = true;
    for (size_t i = 0; i < sizeof sv->ring; i++) zero = zero && sv->ring[i] == 0;
    CHECK(zero && sv->ring_len == 0 && sv->ring_head == 0, "scrub zeroes the ring");
    CHECK(sv->state == ZSSH_CH_OPEN && sv->sent_eof, "scrub keeps state and flags");
    CHECK(sv->send_window == ZSSH_CHAN_WINDOW, "scrub keeps windows");
}

/* Data queued before the peer's CLOSE stays readable until drained. */
static void data_queued_before_close(struct zssh_chan *cl, struct zssh_chan *sv, uint8_t *m)
{
    uint8_t rb[64];
    open_pair(cl, sv, 0);
    CHECK(push_data(cl, sv, (const uint8_t *)"queued", 6) == ZSSH_E_NONE, "queue data");
    size_t n = m_hdr(m, ZSSH_MSG_CHANNEL_CLOSE, 0);
    CHECK(zssh_chan_on_close(sv, m, n) == ZSSH_E_NONE, "close after data");
    CHECK(sv->ring_len == 6 && zssh_chan_recv(sv, rb, sizeof rb) == 6 &&
          memcmp(rb, "queued", 6) == 0, "ring readable after CLOSE");
    CHECK(sv->ring_len == 0 && zssh_chan_recv(sv, rb, sizeof rb) == 0, "drained");
}

/* send misuse and bounds. */
static void data_send_misuse(struct zssh_chan *cl, struct zssh_chan *sv, uint8_t *m,
                             size_t mcap, const uint8_t *big)
{
    struct zssh_wr w;
    open_pair(cl, sv, 0);
    zssh_wr_init(&w, m, mcap);
    CHECK(zssh_chan_send_build(cl, nullptr, 0, &w) == ZSSH_E_INTERNAL, "zero-length send refused");
    zssh_wr_init(&w, m, mcap);
    CHECK(zssh_chan_send_build(cl, big, ZSSH_CHAN_MAX_PACKET + 1, &w) == ZSSH_E_INTERNAL,
          "send above max packet refused");
    cl->send_window = 3;
    CHECK(zssh_chan_send_plan(cl, 100, 100) == 3, "plan bounded by window");
    cl->send_window = 1000; cl->send_maxpkt = 7;
    CHECK(zssh_chan_send_plan(cl, 100, 100) == 7, "plan bounded by peer max packet");
    zssh_wr_init(&w, m, mcap);
    CHECK(zssh_chan_send_build(cl, big, 8, &w) == ZSSH_E_INTERNAL && cl->send_window == 1000,
          "send above peer max packet refused");
    zssh_chan_mark_close_sent(cl);
    zssh_wr_init(&w, m, mcap);
    CHECK(zssh_chan_send_build(cl, big, 1, &w) == ZSSH_E_PROTOCOL, "send after our CLOSE");
}

/* Queue refusal: build succeeds but CONN does not commit (queue full) ->
 * the window is unchanged and the same build can be retried. */
static void data_queue_refusal(struct zssh_chan *cl, struct zssh_chan *sv, uint8_t *m,
                               size_t mcap, const uint8_t *big)
{
    struct zssh_wr w;
    open_pair(cl, sv, 0);
    uint32_t win0 = cl->send_window;
    zssh_wr_init(&w, m, mcap);
    CHECK(zssh_chan_send_build(cl, big, 100, &w) == ZSSH_E_NONE, "build for refused queue");
    CHECK(cl->send_window == win0, "queue failure leaves window unchanged");
    zssh_wr_init(&w, m, mcap);
    CHECK(zssh_chan_send_build(cl, big, 100, &w) == ZSSH_E_NONE && cl->send_window == win0,
          "retry after refused queue");
    zssh_chan_send_commit(cl, 100);
    CHECK(cl->send_window == win0 - 100, "commit charges once");
}

/* mark_close_sent closes only when the peer CLOSE was already received. */
static void data_close_ordering(struct zssh_chan *cl, struct zssh_chan *sv, uint8_t *m)
{
    open_pair(cl, sv, 0);
    zssh_chan_mark_close_sent(cl);
    CHECK(cl->sent_close && cl->state == ZSSH_CH_OPEN, "our CLOSE first: still open");
    size_t n = m_hdr(m, ZSSH_MSG_CHANNEL_CLOSE, 0);
    CHECK(zssh_chan_on_close(cl, m, n) == ZSSH_E_NONE && cl->state == ZSSH_CH_CLOSED,
          "peer CLOSE second: closed");
    open_pair(cl, sv, 0);
    CHECK(zssh_chan_on_close(cl, m, n) == ZSSH_E_NONE && cl->state == ZSSH_CH_OPEN,
          "peer CLOSE first: still open");
    zssh_chan_mark_close_sent(cl);
    CHECK(cl->state == ZSSH_CH_CLOSED, "our CLOSE second: closed");
}

static void test_data_controls(void)
{
    int before = g_fail;
    struct zssh_chan cl, sv;
    static uint8_t m[ZSSH_CHAN_MAX_PACKET + 64], big[ZSSH_CHAN_MAX_PACKET + 1];

    memset(big, 0x42, sizeof big);
    open_pair(&cl, &sv, 0);
    data_window_limits(&sv, m, big);
    data_malformed(&cl, &sv, m, big);
    data_unknown_recipient(&sv, m);
    data_adjust_limits(&cl, &sv, m);
    data_idle_channel(m);
    data_after_peer_close(&cl, &sv, m);
    data_after_our_close(&cl, &sv, m);
    data_trailing_bytes(&cl, &sv, m);
    data_adjust_sent_clamp(&cl, &sv);
    data_scrub(&sv);
    data_queued_before_close(&cl, &sv, m);
    data_send_misuse(&cl, &sv, m, sizeof m, big);
    data_queue_refusal(&cl, &sv, m, sizeof m, big);
    data_close_ordering(&cl, &sv, m);
    group("data controls", before);
}

int main(void)
{
    test_encodings();
    test_blocked_consumer();
    test_big_transfer();
    test_open_controls();
    test_client_controls();
    test_data_controls();
    if (g_fail) { printf("zssh_channel: %d FAILED checks\n", g_fail); return 1; }
    printf("zssh_channel: all checks passed\n");
    return 0;
}
