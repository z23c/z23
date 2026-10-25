/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zssh_e2e.inc — the bulk-transfer scenarios of the zssh module test.
 * NOT a standalone translation unit: tests/test_zssh.c #includes it after the
 * fixture (step, pair_init, handshake, CHECK, g_conn, ...) so each source file
 * stays under the 1500-line ceiling. */

/* ---- data transfer ---------------------------------------------------------- */
#define XFER (1u << 20)
static uint8_t g_src[2][XFER], g_dst[2][XFER];

static void fill_pattern(void)
{
    for (int w = 0; w < 2; w++)
        for (size_t i = 0; i < XFER; i++)
            g_src[w][i] = (uint8_t)(i * 131u + (i >> 8) * 7u + (unsigned)w * 55u + (i >> 16));
}

static bool transfer(size_t len, size_t send_chunk, size_t recv_chunk)
{
    size_t sent[2] = { 0, 0 }, got[2] = { 0, 0 };
    unsigned stalled = 0;
    memset(g_dst, 0, sizeof g_dst);
    while ((sent[0] < len || sent[1] < len || got[0] < len || got[1] < len) && stalled < 4) {
        bool moved = false;
        for (int w = 0; w < 2; w++) {
            struct zssh_conn *c = &g_conn[w];
            if (zssh_state(c) != ZSSH_STATE_CHANNEL) continue;
            if (sent[w] < len) {
                size_t n = len - sent[w] < send_chunk ? len - sent[w] : send_chunk, acc = 99;
                enum zssh_result r = zssh_channel_send(c, g_src[w] + sent[w], n, &acc);
                CHECK(r == ZSSH_OK || r == ZSSH_AGAIN);
                CHECK(acc <= n && (r == ZSSH_OK) == (acc > 0));
                sent[w] += acc;
                moved |= acc > 0;
            }
            if (got[w] < len) {
                size_t n = len - got[w] < recv_chunk ? len - got[w] : recv_chunk, g = 99;
                enum zssh_result r = zssh_channel_recv(c, g_dst[w] + got[w], n, &g);
                CHECK(r == ZSSH_OK || r == ZSSH_AGAIN);
                CHECK(g <= n && (r == ZSSH_OK) == (g > 0));
                got[w] += g;
                moved |= g > 0;
            }
        }
        moved |= step(CL);
        moved |= step(SV);
        stalled = moved ? 0 : stalled + 1;
    }
    bool ok = got[0] == len && got[1] == len && sent[0] == len && sent[1] == len;
    CHECK(ok);
    CHECK(memcmp(g_dst[SV], g_src[CL], len) == 0);    /* binary exact, both ways */
    CHECK(memcmp(g_dst[CL], g_src[SV], len) == 0);
    return ok;
}

static void quiesce_checks(void)
{
    run_quiet();
    for (int d = 0; d < 2; d++) {
        const uint8_t *p; size_t n = 9;
        CHECK(zssh_output_peek(&g_conn[d], &p, &n) == ZSSH_OK && n == 0);
        CHECK(g_d.produced[d] == g_d.consumed[1 - d]);       /* exact accounting */
        CHECK(g_qh[d] == g_qt[d]);
        size_t c = 0, pr = 0;
        CHECK(zssh_pump(&g_conn[d], nullptr, 0, &c, nullptr, 0, &pr) == ZSSH_CHANNEL_READY);
    }
}

static void g_data_large_chunks(void)
{
    struct opt o;
    opt_default(&o);
    fill_pattern();
    CHECK(handshake(&o, 1u << 20, 65536));
    transfer(XFER, 200000, 1u << 20);
    quiesce_checks();
    /* the receive window is credited back: send the 1 MiB again */
    transfer(XFER, 5000, 4096);
    quiesce_checks();
}

static void g_data_one_byte(void)
{
    struct opt o;
    opt_default(&o); o.kc = o.ks = ZSSH_KEX_CURVE25519_SHA256;
    fill_pattern();
    pair_init(&o, 1, 1);                       /* 1-byte transport chunks, both ways */
    transfer(XFER, 7777, 3333);
    quiesce_checks();
}

static void g_data_tiny_drains(void)
{
    struct opt o;
    opt_default(&o);
    fill_pattern();
    pair_init(&o, 7, 3);
    transfer(1u << 18, 100000, 61);
    quiesce_checks();
    pair_init(&o, 1, 65536);                   /* 1-byte input, big output */
    transfer(1u << 17, 16384, 65536);
    quiesce_checks();
    pair_init(&o, 65536, 1);                   /* big input, 1-byte drain */
    transfer(1u << 17, 16384, 65536);
    quiesce_checks();
}

/* ---- review-round groups (need the helpers defined above and below the old
 * include point, so tests/test_zssh.c includes this file just before main) ----- */
static size_t take_out(int i, uint8_t *dst, size_t cap)
{
    const uint8_t *p = nullptr;
    size_t n = 0;
    CHECK(zssh_output_peek(&g_conn[i], &p, &n) == ZSSH_OK);
    CHECK(n <= cap);
    if (n > cap) n = cap;
    memcpy(dst, p, n);
    CHECK(zssh_output_consume(&g_conn[i], n) == ZSSH_OK);
    return n;
}

static void fresh_channel(void)
{
    struct opt o;
    opt_default(&o); o.kc = o.ks = ZSSH_KEX_CURVE25519_SHA256;
    CHECK(handshake(&o, 1u << 20, 65536));
}

/* zssh_pump: input stopped for queue room, then the output copy empties the
 * queue. consumed < in_len must still report NEED_OUTPUT (zssh.h status table). */
static void g_pump_input_stop(void)
{
    static uint8_t junk[58000], outb[70000], pkt[4000];
    uint8_t data[3000], rb[4000];
    size_t acc = 0, got = 0, cons = 99, cons2 = 99, prod = 99;
    fresh_channel();
    for (size_t i = 0; i < sizeof data; i++) data[i] = (uint8_t)(i * 5 + 3);
    CHECK(zssh_channel_send(&g_conn[CL], data, sizeof data, &acc) == ZSSH_OK && acc == sizeof data);
    size_t pn = take_out(CL, pkt, sizeof pkt);
    CHECK(zssh_txq_append(&IMPL(SV)->txq, junk, sizeof junk));
    CHECK(zssh_txq_room(&IMPL(SV)->txq) < ZSSH_TXQ_RESERVE);
    enum zssh_status st = zssh_pump(&g_conn[SV], pkt, pn, &cons, outb, sizeof outb, &prod);
    CHECK(cons < pn);
    CHECK(prod == sizeof junk && zssh_txq_pending(&IMPL(SV)->txq) == 0);   /* fully drained */
    CHECK(st == ZSSH_NEED_OUTPUT);
    st = zssh_pump(&g_conn[SV], pkt + cons, pn - cons, &cons2, outb, sizeof outb, &prod);
    CHECK(cons + cons2 == pn && prod == 0 && st == ZSSH_CHANNEL_READY);
    CHECK(zssh_channel_recv(&g_conn[SV], rb, sizeof rb, &got) == ZSSH_OK && got == sizeof data);
    CHECK(memcmp(rb, data, sizeof data) == 0);
}

/* Room for only ~500 payload bytes with more data pending: AGAIN, nothing changed. */
static void g_send_runt_again(void)
{
    static uint8_t junk[70000], data[5000];
    const size_t overhead = ZSSH_TXQ_RESERVE + ZSSH_PKT_HDR + 9u + ZSSH_PAD_RANDOM_MAX + ZSSH_TAG_LEN;
    struct zssh_channel_flags f0 = {0}, f1 = {0};
    size_t acc = 99;
    memset(data, 0x6d, sizeof data);
    fresh_channel();
    size_t room0 = zssh_txq_room(&IMPL(CL)->txq);
    CHECK(room0 > overhead + 500 && room0 - overhead - 500 <= sizeof junk);
    CHECK(zssh_txq_append(&IMPL(CL)->txq, junk, room0 - overhead - 500));
    size_t pend0 = zssh_txq_pending(&IMPL(CL)->txq);
    CHECK(zssh_channel_flags_get(&g_conn[CL], &f0) == ZSSH_OK && f0.send_window >= sizeof data);
    CHECK(zssh_channel_send(&g_conn[CL], data, sizeof data, &acc) == ZSSH_AGAIN && acc == 0);
    CHECK(zssh_channel_flags_get(&g_conn[CL], &f1) == ZSSH_OK);
    CHECK(memcmp(&f0, &f1, sizeof f0) == 0);
    CHECK(zssh_txq_pending(&IMPL(CL)->txq) == pend0);
    CHECK(zssh_state(&g_conn[CL]) == ZSSH_STATE_CHANNEL && zssh_error(&g_conn[CL]) == ZSSH_E_NONE);
    /* when the remaining data itself fits the room, it is sent (no runt rule) */
    CHECK(zssh_channel_send(&g_conn[CL], data, 500, &acc) == ZSSH_OK && acc == 500);
    CHECK(zssh_output_consume(&g_conn[CL], zssh_txq_pending(&IMPL(CL)->txq)) == ZSSH_OK);
    CHECK(zssh_channel_send(&g_conn[CL], data, sizeof data, &acc) == ZSSH_OK && acc == sizeof data);
}

/* Session packet/byte limits (REKEY_LIMIT) are terminal; counters set directly. */
static void g_rekey_limit(void)
{
    static uint8_t big[40000], rb[40000], pkt[4000];
    struct zssh_channel_flags f0 = {0}, f1 = {0};
    size_t acc = 99, got = 99, cons = 0;
    memset(big, 0x5a, sizeof big);
    fresh_channel();
    snap_take(1);
    CHECK(zssh_channel_flags_get(&g_conn[CL], &f0) == ZSSH_OK);
    /* (a) tx packet limit: first packet committed, second refused */
    IMPL(CL)->tx.seq = ZSSH_MAX_SESSION_PACKETS - 1u;
    CHECK(zssh_channel_send(&g_conn[CL], big, sizeof big, &acc) == ZSSH_FAILED);
    CHECK(acc == ZSSH_CHAN_MAX_PACKET);
    CHECK(zssh_channel_flags_get(&g_conn[CL], &f1) == ZSSH_OK && f0.send_window - f1.send_window == acc);
    CHECK(zssh_state(&g_conn[CL]) == ZSSH_STATE_FAILED && zssh_error(&g_conn[CL]) == ZSSH_E_REKEY_LIMIT);
    all_secrets_gone(CL);
    failed_column(CL, ZSSH_E_REKEY_LIMIT);
    /* the very first packet already at the limit: nothing committed */
    snap_restore(1);
    IMPL(CL)->tx.seq = ZSSH_MAX_SESSION_PACKETS;
    CHECK(zssh_channel_send(&g_conn[CL], big, 1000, &acc) == ZSSH_FAILED && acc == 0);
    CHECK(zssh_channel_flags_get(&g_conn[CL], &f1) == ZSSH_OK && f1.send_window == f0.send_window);
    CHECK(zssh_error(&g_conn[CL]) == ZSSH_E_REKEY_LIMIT);
    failed_column(CL, ZSSH_E_REKEY_LIMIT);
    /* tx byte limit: measure one packet, reaching the limit exactly is allowed */
    snap_restore(1);
    CHECK(zssh_channel_send(&g_conn[CL], big, ZSSH_CHAN_MAX_PACKET, &acc) == ZSSH_OK && acc == ZSSH_CHAN_MAX_PACKET);
    size_t wire = zssh_txq_pending(&IMPL(CL)->txq);
    snap_restore(1);
    IMPL(CL)->tx.bytes = ZSSH_MAX_SESSION_BYTES - wire;
    CHECK(zssh_channel_send(&g_conn[CL], big, sizeof big, &acc) == ZSSH_FAILED);
    CHECK(acc == ZSSH_CHAN_MAX_PACKET && zssh_error(&g_conn[CL]) == ZSSH_E_REKEY_LIMIT);
    failed_column(CL, ZSSH_E_REKEY_LIMIT);
    snap_restore(1);
    IMPL(CL)->tx.bytes = ZSSH_MAX_SESSION_BYTES - wire + 1u;
    CHECK(zssh_channel_send(&g_conn[CL], big, sizeof big, &acc) == ZSSH_FAILED && acc == 0);
    CHECK(zssh_error(&g_conn[CL]) == ZSSH_E_REKEY_LIMIT);
    /* (b) rx byte limit: the peer's packet is refused before delivery */
    snap_restore(1);
    CHECK(zssh_channel_send(&g_conn[CL], big, 1000, &acc) == ZSSH_OK && acc == 1000);
    size_t pn = take_out(CL, pkt, sizeof pkt);
    IMPL(SV)->rx.bytes = ZSSH_MAX_SESSION_BYTES - 100u;
    CHECK(zssh_input(&g_conn[SV], pkt, pn, &cons) == ZSSH_STATUS_FAILED && cons == pn);
    CHECK(zssh_error(&g_conn[SV]) == ZSSH_E_REKEY_LIMIT);
    CHECK(zssh_channel_recv(&g_conn[SV], rb, sizeof rb, &got) == ZSSH_FAILED && got == 0);
    failed_column(SV, ZSSH_E_REKEY_LIMIT);
    /* (c) recv: the WINDOW_ADJUST that follows the read hits the tx limit; the
     * bytes already copied are reported, the session fails */
    snap_restore(1);
    CHECK(zssh_channel_send(&g_conn[CL], big, 30000, &acc) == ZSSH_OK && acc == 30000);
    run_quiet();
    IMPL(SV)->tx.seq = ZSSH_MAX_SESSION_PACKETS;
    CHECK(zssh_channel_recv(&g_conn[SV], rb, sizeof rb, &got) == ZSSH_FAILED);
    CHECK(got == 30000 && memcmp(rb, big, got) == 0);
    CHECK(zssh_state(&g_conn[SV]) == ZSSH_STATE_FAILED && zssh_error(&g_conn[SV]) == ZSSH_E_REKEY_LIMIT);
    failed_column(SV, ZSSH_E_REKEY_LIMIT);
}

/* Bytes after the fatal byte / after CLOSE are not consumed; pump output copy in
 * FAILED and CLOSED; NULL conn on wipe / transport_eof. */
static void g_trailing_and_terminal_pump(void)
{
    static uint8_t pkt[4100], bad[4200], outb[4200];
    uint8_t data[1000];
    size_t acc = 0, cons = 99, prod = 99;
    const uint8_t *p = nullptr;
    size_t pn2 = 0;
    fresh_channel();
    for (size_t i = 0; i < sizeof data; i++) data[i] = (uint8_t)(i ^ 0x33);
    CHECK(zssh_channel_send(&g_conn[CL], data, sizeof data, &acc) == ZSSH_OK && acc == sizeof data);
    size_t pn = take_out(CL, pkt, sizeof pkt);
    snap_take(1);
    memcpy(bad, pkt, pn);
    memset(bad + pn, 0xAA, 7);
    bad[pn - 1] ^= 0x01;                                  /* corrupt the tag's last byte */
    CHECK(zssh_input(&g_conn[SV], bad, pn + 7, &cons) == ZSSH_STATUS_FAILED);
    CHECK(cons == pn && zssh_error(&g_conn[SV]) == ZSSH_E_MAC);   /* up to and including the fatal byte */
    /* FAILED column of pump: input untouched, output copy exact in any chunking */
    CHECK(zssh_output_peek(&g_conn[SV], &p, &pn2) == ZSSH_OK && pn2 > 2);
    CHECK(zssh_pump(&g_conn[SV], bad + pn, 7, &cons, outb, pn2 - 1, &prod) == ZSSH_STATUS_FAILED);
    CHECK(cons == 0 && prod == pn2 - 1);
    CHECK(zssh_pump(&g_conn[SV], bad + pn, 7, &cons, outb, 100, &prod) == ZSSH_STATUS_FAILED);
    CHECK(cons == 0 && prod == 1);
    CHECK(zssh_pump(&g_conn[SV], bad + pn, 7, &cons, outb, 100, &prod) == ZSSH_STATUS_FAILED);
    CHECK(cons == 0 && prod == 0);
    CHECK(zssh_pump(&g_conn[SV], nullptr, 0, &cons, nullptr, 0, &prod) == ZSSH_STATUS_FAILED);
    CHECK(cons == 0 && prod == 0);
    /* same fatal byte through pump: consumed stops there, out_cap 0 copies nothing */
    snap_restore(1);
    CHECK(zssh_pump(&g_conn[SV], bad, pn + 7, &cons, nullptr, 0, &prod) == ZSSH_STATUS_FAILED);
    CHECK(cons == pn && prod == 0 && zssh_txq_pending(&IMPL(SV)->txq) == pn2);
    /* peer CLOSE with trailing bytes in one call: the tail is not consumed */
    snap_restore(1);
    CHECK(zssh_input(&g_conn[SV], pkt, pn, &cons) != ZSSH_STATUS_FAILED && cons == pn);  /* keep seq in step */
    CHECK(zssh_channel_close(&g_conn[CL]) == ZSSH_OK);
    pn = take_out(CL, pkt, sizeof pkt);
    memcpy(bad, pkt, pn);
    memset(bad + pn, 0x55, 5);
    CHECK(zssh_input(&g_conn[SV], bad, pn + 5, &cons) == ZSSH_CLOSED);
    CHECK(cons == pn && zssh_state(&g_conn[SV]) == ZSSH_STATE_CLOSED && zssh_error(&g_conn[SV]) == ZSSH_E_NONE);
    CHECK(zssh_input(&g_conn[SV], bad + pn, 5, &cons) == ZSSH_CLOSED && cons == 0);
    /* CLOSED column of pump: final DISCONNECT drains exactly through pump */
    CHECK(zssh_output_peek(&g_conn[SV], &p, &pn2) == ZSSH_OK && pn2 > 5);
    CHECK(zssh_pump(&g_conn[SV], bad + pn, 5, &cons, outb, 5, &prod) == ZSSH_CLOSED);
    CHECK(cons == 0 && prod == 5);
    CHECK(zssh_pump(&g_conn[SV], nullptr, 0, &cons, outb, sizeof outb, &prod) == ZSSH_CLOSED);
    CHECK(cons == 0 && prod == pn2 - 5);
    CHECK(zssh_pump(&g_conn[SV], nullptr, 0, &cons, outb, sizeof outb, &prod) == ZSSH_CLOSED);
    CHECK(prod == 0);
    /* NULL conn */
    zssh_wipe(nullptr);
    CHECK(zssh_transport_eof(nullptr) == ZSSH_BAD_CALL);
}

/* The first CHANNEL_OPEN must be direct-tcpip to exactly ZSSH_FWD_HOST:ZSSH_FWD_PORT. */
static void g_open_wrong_target(void)
{
    static const struct { const char *host; uint32_t port; } t[] = {
        { "other.invalid", ZSSH_FWD_PORT }, { ZSSH_FWD_HOST, ZSSH_FWD_PORT + 1u },
        { ZSSH_FWD_HOST, 0 }, { "127.0.0.1", 22 },
    };
    uint8_t buf[160], arg = 0;
    auth_pause();
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        struct zssh_wr w;
        size_t pl = 0;
        snap_restore(0);
        CHECK(auth_roundtrip(2, g_useed, g_upk, &arg) == ZSSH_MSG_USERAUTH_SUCCESS);
        zssh_wr_init(&w, buf, sizeof buf);
        zssh_wr_u8(&w, ZSSH_MSG_CHANNEL_OPEN); zssh_wr_cstr(&w, "direct-tcpip");
        zssh_wr_u32(&w, 5); zssh_wr_u32(&w, 1000); zssh_wr_u32(&w, 1000);
        zssh_wr_cstr(&w, t[i].host); zssh_wr_u32(&w, t[i].port);
        zssh_wr_cstr(&w, "0.0.0.0"); zssh_wr_u32(&w, 0);
        raw_send(CL, buf, w.off);
        step(SV);
        CHECK(raw_next(CL, SV, &pl) && g_raw[0] == ZSSH_MSG_CHANNEL_OPEN_FAILURE);
        CHECK(zssh_get_u32(g_raw + 1) == 5 && zssh_get_u32(g_raw + 5) == ZSSH_OPEN_ADMIN_PROHIBITED);
        CHECK(raw_next(CL, SV, &pl) && g_raw[0] == ZSSH_MSG_DISCONNECT);
        CHECK(zssh_state(&g_conn[SV]) == ZSSH_STATE_FAILED && zssh_error(&g_conn[SV]) == ZSSH_E_CHANNEL_REFUSED);
    }
}


/* A packet sealed under another session's keys is refused (nothing delivered). */
static void g_wrong_session(void)
{
    static uint8_t pkt[2048];
    uint8_t rb[64];
    struct opt o;
    size_t acc = 0, cons = 0, got = 9;
    fresh_channel();
    CHECK(zssh_channel_send(&g_conn[CL], (const uint8_t *)"secret", 6, &acc) == ZSSH_OK && acc == 6);
    size_t pn = take_out(CL, pkt, sizeof pkt);
    opt_default(&o); o.kc = o.ks = ZSSH_KEX_CURVE25519_SHA256; o.salt = 0x77;
    CHECK(handshake(&o, 1u << 20, 65536));              /* a different session, same seq numbers */
    enum zssh_status st = zssh_input(&g_conn[SV], pkt, pn, &cons);
    CHECK(st == ZSSH_STATUS_FAILED && cons <= pn);
    enum zssh_error e = zssh_error(&g_conn[SV]);
    CHECK(e == ZSSH_E_MAC || e == ZSSH_E_TOO_LARGE || e == ZSSH_E_PROTOCOL);
    CHECK(zssh_channel_recv(&g_conn[SV], rb, sizeof rb, &got) == ZSSH_FAILED && got == 0);
    all_secrets_gone(SV);
}

/* BAD_CALL paths leave the whole object untouched, also in CLOSED and FAILED. */
static void g_misuse_terminal(void)
{
    static struct zssh_conn save;
    static uint8_t pkt[2048];
    uint8_t d[8] = { 0 }, rb[8];
    size_t cons = 9, prod = 9, acc = 9, got = 9, n = 9;
    const uint8_t *p = nullptr;
    for (int phase = 0; phase < 2; phase++) {
        fresh_channel();
        struct zssh_conn *c = &g_conn[SV];
        if (phase == 0) {                                    /* CLOSED */
            CHECK(zssh_channel_close(&g_conn[CL]) == ZSSH_OK);
            size_t pn = take_out(CL, pkt, sizeof pkt);
            CHECK(zssh_input(c, pkt, pn, &cons) == ZSSH_CLOSED);
        } else {                                             /* FAILED */
            CHECK(zssh_transport_eof(c) == ZSSH_FAILED);
        }
        memcpy(&save, c, sizeof save);
        size_t pend = zssh_txq_pending(&IMPL(SV)->txq);
        cons = 9; CHECK(zssh_input(c, nullptr, 3, &cons) == ZSSH_STATUS_BAD_CALL && cons == 0);
        cons = 9; prod = 9;
        CHECK(zssh_pump(c, nullptr, 3, &cons, rb, 8, &prod) == ZSSH_STATUS_BAD_CALL && cons == 0 && prod == 0);
        CHECK(zssh_pump(c, d, 1, &cons, nullptr, 5, &prod) == ZSSH_STATUS_BAD_CALL);
        CHECK(zssh_output_peek(c, nullptr, &n) == ZSSH_BAD_CALL);
        CHECK(zssh_output_consume(c, pend + 1) == ZSSH_BAD_CALL);
        acc = 9; CHECK(zssh_channel_send(c, nullptr, 1, &acc) == ZSSH_BAD_CALL && acc == 0);
        got = 9; CHECK(zssh_channel_recv(c, nullptr, 1, &got) == ZSSH_BAD_CALL && got == 0);
        CHECK(zssh_channel_flags_get(c, nullptr) == ZSSH_BAD_CALL);
        CHECK(zssh_output_peek(nullptr, &p, &n) == ZSSH_BAD_CALL);
        CHECK(memcmp(&save, c, sizeof save) == 0);
    }
}

/* The reply reserve holds at saturation: the queue is filled until free room is
 * just above the reserve while the send window is still open; data sends get
 * AGAIN but the peer's CLOSE is still answered (reply + DISCONNECT fit). */
static void g_reserve_saturation(void)
{
    struct opt o;
    static uint8_t big[16384], junk[ZSSH_TXQ_SIZE], pkt[2048];
    struct zssh_channel_flags f0 = {0}, f1 = {0};
    size_t acc = 0, cons = 0;
    opt_default(&o); o.kc = o.ks = ZSSH_KEX_CURVE25519_SHA256;
    memset(big, 0x17, sizeof big);
    CHECK(handshake(&o, 1u << 20, 65536));
    CHECK(zssh_channel_send(&g_conn[CL], big, sizeof big, &acc) == ZSSH_OK && acc == sizeof big);
    size_t room = zssh_txq_room(&IMPL(CL)->txq);
    CHECK(room > ZSSH_TXQ_RESERVE + 100u);
    CHECK(zssh_txq_append(&IMPL(CL)->txq, junk, room - ZSSH_TXQ_RESERVE - 100u));
    room = zssh_txq_room(&IMPL(CL)->txq);
    CHECK(room == ZSSH_TXQ_RESERVE + 100u && room < ZSSH_TXQ_RESERVE + ZSSH_TX_MAX_WIRE);
    CHECK(zssh_channel_flags_get(&g_conn[CL], &f0) == ZSSH_OK && f0.send_window > 0);
    size_t pend = zssh_txq_pending(&IMPL(CL)->txq);
    CHECK(zssh_channel_send(&g_conn[CL], big, sizeof big, &acc) == ZSSH_AGAIN && acc == 0);
    CHECK(zssh_channel_flags_get(&g_conn[CL], &f1) == ZSSH_OK && f1.send_window == f0.send_window);
    CHECK(zssh_txq_pending(&IMPL(CL)->txq) == pend);
    CHECK(zssh_channel_close(&g_conn[SV]) == ZSSH_OK);
    size_t pn = take_out(SV, pkt, sizeof pkt);
    CHECK(zssh_input(&g_conn[CL], pkt, pn, &cons) == ZSSH_CLOSED && cons == pn);
    CHECK(zssh_state(&g_conn[CL]) == ZSSH_STATE_CLOSED && zssh_error(&g_conn[CL]) == ZSSH_E_NONE);
    CHECK(zssh_txq_pending(&IMPL(CL)->txq) > pend);       /* CLOSE reply and DISCONNECT queued */
}

/* ---- transport EOF as a clean end (peer drops the transport after our CLOSE) ---- */
static void take_all_output(int i)
{
    const uint8_t *p; size_t n;
    CHECK(zssh_output_peek(&g_conn[i], &p, &n) == ZSSH_OK);
    CHECK(zssh_output_consume(&g_conn[i], n) == ZSSH_OK);
}

static bool g_eof_no_close;                         /* case (e): server never queues CLOSE */

/* Server side after: client sent "abc" (+ EOF if peer_eof), server close()d.
 * Client output beyond that is never delivered. */
static void eof_prepare(bool peer_eof, bool take_out)
{
    struct opt o;
    size_t acc = 0;
    opt_default(&o);
    CHECK(handshake(&o, 1u << 20, 65536));
    CHECK(zssh_channel_send(&g_conn[CL], (const uint8_t *)"abc", 3, &acc) == ZSSH_OK && acc == 3);
    if (peer_eof) CHECK(zssh_channel_send_eof(&g_conn[CL]) == ZSSH_OK);
    run_quiet();
    if (!g_eof_no_close) CHECK(zssh_channel_close(&g_conn[SV]) == ZSSH_OK);
    if (take_out) take_all_output(SV);              /* the peer's reply is never sent */
}

static void expect_truncated(void)
{
    CHECK(zssh_transport_eof(&g_conn[SV]) == ZSSH_FAILED);
    CHECK(zssh_state(&g_conn[SV]) == ZSSH_STATE_FAILED && zssh_error(&g_conn[SV]) == ZSSH_E_TRUNCATED);
}

static void g_eof_clean(void)
{
    uint8_t rb[16];
    size_t got = 0;
    /* (a) peer EOF received, our CLOSE taken, peer drops the transport: clean */
    eof_prepare(true, true);
    CHECK(zssh_transport_eof(&g_conn[SV]) == ZSSH_OK);
    CHECK(zssh_state(&g_conn[SV]) == ZSSH_STATE_CLOSED && zssh_error(&g_conn[SV]) == ZSSH_E_NONE);
    CHECK(zssh_channel_recv(&g_conn[SV], rb, sizeof rb, &got) == ZSSH_OK && got == 3);  /* data kept */
    CHECK(zssh_channel_recv(&g_conn[SV], rb, sizeof rb, &got) == ZSSH_EOF && got == 0);
    all_secrets_gone(SV);
    CHECK(zssh_transport_eof(&g_conn[SV]) == ZSSH_OK);                  /* idempotent */
    /* (b) peer never sent EOF: peer data may have been lost */
    eof_prepare(false, true);
    expect_truncated();
    /* (c) our CLOSE queued but not taken by the caller */
    eof_prepare(true, false);
    expect_truncated();
    /* (d) a partial packet is buffered */
    eof_prepare(true, true);
    CHECK(zssh_channel_close(&g_conn[CL]) == ZSSH_OK);
    const uint8_t *p; size_t pn, cons = 0;
    CHECK(zssh_output_peek(&g_conn[CL], &p, &pn) == ZSSH_OK && pn > 16);
    CHECK(zssh_input(&g_conn[SV], p, pn - 3, &cons) != ZSSH_STATUS_FAILED && cons == pn - 3);
    expect_truncated();
    /* (e) peer EOF received but we never queued our CLOSE */
    g_eof_no_close = true;
    eof_prepare(true, true);
    g_eof_no_close = false;
    expect_truncated();
    /* peer CLOSE first, our reply taken: already CLOSED, EOF is a no-op */
    eof_prepare(true, true);
    CHECK(zssh_channel_close(&g_conn[CL]) == ZSSH_OK);
    drain_all(CL);
    step(SV);
    CHECK(zssh_state(&g_conn[SV]) == ZSSH_STATE_CLOSED);
    CHECK(zssh_transport_eof(&g_conn[SV]) == ZSSH_OK && zssh_error(&g_conn[SV]) == ZSSH_E_NONE);
}

/* ---- back-pressure cases B and C (case A and the setup: test_zssh.c) ------- */
/* B: the packet completes while the queue is full: bytes are taken, dispatch waits */
static void bp_case_b(void)
{
    size_t got = 0, cons = 0;
    uint8_t rb[4000];
    snap_restore(1);
    CHECK(zssh_input(&g_conn[SV], bp_pkt, bp_pn - 1, &cons) != ZSSH_STATUS_FAILED && cons == bp_pn - 1);
    CHECK(zssh_txq_append(&IMPL(SV)->txq, bp_junk, sizeof bp_junk));
    enum zssh_status st = zssh_input(&g_conn[SV], bp_pkt + bp_pn - 1, 1, &cons);
    CHECK(st == ZSSH_NEED_OUTPUT && cons == 1);
    CHECK(zssh_channel_recv(&g_conn[SV], rb, sizeof rb, &got) == ZSSH_AGAIN && got == 0);
    st = zssh_input(&g_conn[SV], nullptr, 0, &cons);                    /* still no room */
    CHECK(st == ZSSH_NEED_OUTPUT && cons == 0);
    CHECK(zssh_channel_recv(&g_conn[SV], rb, sizeof rb, &got) == ZSSH_AGAIN);
    CHECK(zssh_output_consume(&g_conn[SV], sizeof bp_junk) == ZSSH_OK);
    st = zssh_input(&g_conn[SV], nullptr, 0, &cons);                    /* resume */
    CHECK(st != ZSSH_STATUS_FAILED && cons == 0);
    CHECK(zssh_channel_recv(&g_conn[SV], rb, sizeof rb, &got) == ZSSH_OK && got == sizeof bp_data);
    CHECK(memcmp(rb, bp_data, sizeof bp_data) == 0);
}

/* C: send honours the reply reserve and the queue room (AGAIN, nothing changed) */
static void bp_case_c(void)
{
    size_t acc = 0;
    snap_restore(1);
    CHECK(zssh_txq_append(&IMPL(CL)->txq, bp_junk, sizeof bp_junk));
    struct zssh_channel_flags f0 = {0}, f1 = {0};
    CHECK(zssh_channel_flags_get(&g_conn[CL], &f0) == ZSSH_OK);
    CHECK(zssh_channel_send(&g_conn[CL], bp_data, sizeof bp_data, &acc) == ZSSH_AGAIN && acc == 0);
    CHECK(zssh_channel_flags_get(&g_conn[CL], &f1) == ZSSH_OK);
    CHECK(f0.send_window == f1.send_window);
    CHECK(zssh_channel_send_eof(&g_conn[CL]) == ZSSH_AGAIN);
    CHECK(zssh_channel_close(&g_conn[CL]) == ZSSH_AGAIN);
    CHECK(zssh_channel_flags_get(&g_conn[CL], &f1) == ZSSH_OK && !f1.sent_eof && !f1.sent_close);
    CHECK(zssh_output_consume(&g_conn[CL], sizeof bp_junk) == ZSSH_OK);
    CHECK(zssh_channel_send(&g_conn[CL], bp_data, sizeof bp_data, &acc) == ZSSH_OK && acc == sizeof bp_data);
}

/* ---- witness: kex "both" against a classical-only OpenSSH-style peer ------------ */
static size_t wit_ki(enum zssh_role role, uint32_t allowed, bool pq, uint8_t *buf, size_t cap)
{
    struct zssh_kex_policy p = { .role = role, .allowed = allowed, .require_pq = pq };
    uint8_t cookie[16] = { 0 };
    struct zssh_wr w;
    zssh_wr_init(&w, buf, cap);
    return zssh_kex_build_kexinit(&p, cookie, &w) == ZSSH_E_NONE ? w.off : 0;
}

static bool wit_kex_list_is(const uint8_t *ki, size_t n, const char *want)
{
    struct zssh_kexinit_view v;
    return zssh_kex_parse_kexinit(ki, n, &v) == ZSSH_E_NONE
        && v.list[ZSSH_KI_KEX].len == strlen(want)
        && memcmp(v.list[ZSSH_KI_KEX].p, want, v.list[ZSSH_KI_KEX].len) == 0;
}

static bool wit_kex_has(const uint8_t *ki, size_t n, const char *name)
{
    struct zssh_kexinit_view v;
    return zssh_kex_parse_kexinit(ki, n, &v) == ZSSH_E_NONE
        && zssh_namelist_has(v.list[ZSSH_KI_KEX], name);
}

/* Client policy (allowed, pq) against a server KEXINIT built from (sallowed). */
static enum zssh_error wit_negotiate(uint32_t allowed, bool pq, uint32_t sallowed,
                                     struct zssh_neg *neg)
{
    uint8_t peer[ZSSH_KEXINIT_MAX];
    struct zssh_kexinit_view v;
    struct zssh_kex_policy p = { .role = ZSSH_ROLE_CLIENT, .allowed = allowed, .require_pq = pq };
    size_t n = wit_ki(ZSSH_ROLE_SERVER, sallowed, false, peer, sizeof peer);
    if (n == 0 || zssh_kex_parse_kexinit(peer, n, &v) != ZSSH_E_NONE) return ZSSH_E_INTERNAL;
    return zssh_kex_negotiate(&p, &v, neg);
}

static void g_witness_kex_policy(void)
{
    const uint32_t H = ZSSH_KEX_MLKEM768X25519_SHA256, C = ZSSH_KEX_CURVE25519_SHA256;
    uint8_t ki[ZSSH_KEXINIT_MAX];
    struct zssh_neg neg;
    size_t n = wit_ki(ZSSH_ROLE_CLIENT, H | C, true, ki, sizeof ki);
    /* A: require_pq offers the hybrid only and refuses a classical-only peer */
    CHECK(n > 0 && wit_kex_list_is(ki, n, "mlkem768x25519-sha256,kex-strict-c-v00@openssh.com"));
    CHECK(wit_kex_has(ki, n, "mlkem768x25519-sha256") && !wit_kex_has(ki, n, "curve25519-sha256")
          && !wit_kex_has(ki, n, "curve25519-sha256@libssh.org"));
    CHECK(wit_negotiate(H | C, true, C, &neg) == ZSSH_E_KEX_NO_MATCH
          && neg.alg == ZSSH_KEXALG_NONE);
    /* B: without require_pq the order is hybrid, curve25519, strict; classical peer gets curve */
    n = wit_ki(ZSSH_ROLE_CLIENT, H | C, false, ki, sizeof ki);
    CHECK(n > 0 && wit_kex_list_is(ki, n,
        "mlkem768x25519-sha256,curve25519-sha256,kex-strict-c-v00@openssh.com"));
    CHECK(wit_negotiate(H | C, false, C, &neg) == ZSSH_E_NONE
          && neg.alg == ZSSH_KEXALG_CURVE25519 && neg.strict);
    /* control: require_pq against a PQ-capable peer negotiates the hybrid */
    CHECK(wit_negotiate(H | C, true, H | C, &neg) == ZSSH_E_NONE
          && neg.alg == ZSSH_KEXALG_MLKEM768X25519 && neg.strict);
}

/* ---- AGAIN means nothing changed, also for a deferred WINDOW_ADJUST ------------
 * Boundary: a real 16384-byte read leaves WINDOW_ADJUST credit deferred (queue
 * room one byte short of adjust + reserve); with room exactly SMALL_WIRE +
 * RESERVE the adjust is admissible but the DATA packet behind it is not
 * (room - SMALL_WIRE == RESERVE <= DATA overhead), so send must be AGAIN
 * without having queued the adjust. */
enum { ADJ_CREDIT = ZSSH_CHAN_WINDOW / 2 };
static struct zssh_conn g_adj_conn;
static struct rng g_adj_rng;

static void adj_snap(void)
{
    memcpy(&g_adj_conn, &g_conn[CL], sizeof g_adj_conn);   /* txq, tx dir, chan, ring, state, error */
    g_adj_rng = g_rng[CL];                                 /* call count and draw cursor */
}

static bool adj_same(void)
{
    return memcmp(&g_adj_conn, &g_conn[CL], sizeof g_adj_conn) == 0 &&
           memcmp(&g_adj_rng, &g_rng[CL], sizeof g_adj_rng) == 0;
}

/* Server sends ADJ_CREDIT bytes; client reads them with its queue one byte
 * short of admitting an adjust, so the credit stays deferred. Then room is
 * raised by one byte to exactly SMALL_WIRE + RESERVE. */
static void adj_defer(void)
{
    static uint8_t blob[ADJ_CREDIT], wire[ADJ_CREDIT + 512], junk[ZSSH_TXQ_SIZE], rb[ADJ_CREDIT];
    struct zssh_impl *c = IMPL(CL);
    size_t acc = 0, cons = 0, got = 0;
    const size_t target = ZSSH_TX_SMALL_WIRE + ZSSH_TXQ_RESERVE;
    fresh_channel();
    take_all_output(CL);
    take_all_output(SV);
    memset(blob, 0x5a, sizeof blob);
    CHECK(zssh_channel_send(&g_conn[SV], blob, sizeof blob, &acc) == ZSSH_OK && acc == sizeof blob);
    size_t wn = take_out(SV, wire, sizeof wire);
    CHECK(zssh_input(&g_conn[CL], wire, wn, &cons) != ZSSH_STATUS_BAD_CALL && cons == wn);
    size_t room = zssh_txq_room(&c->txq);
    CHECK(room > target && room - (target - 1) <= sizeof junk);
    CHECK(zssh_txq_append(&c->txq, junk, room - (target - 1)));
    CHECK(zssh_channel_recv(&g_conn[CL], rb, sizeof rb, &got) == ZSSH_OK && got == sizeof rb);
    CHECK(c->chan.freed_unreported == ADJ_CREDIT);          /* adjust deferred, not queued */
    CHECK(zssh_output_consume(&g_conn[CL], 1) == ZSSH_OK);
    CHECK(zssh_txq_room(&c->txq) == target);
}

static void adj_again_cases(void)
{
    static uint8_t data[5000], rb[64];
    struct zssh_impl *c = IMPL(CL);
    size_t acc = 99, got = 99;
    memset(data, 0x33, sizeof data);
    memset(rb, 0xa5, sizeof rb);
    adj_snap();
    CHECK(zssh_channel_send(&g_conn[CL], data, sizeof data, &acc) == ZSSH_AGAIN && acc == 0);
    CHECK(adj_same());
    CHECK(zssh_channel_send(&g_conn[CL], data, sizeof data, &acc) == ZSSH_AGAIN && acc == 0);
    CHECK(adj_same());                                      /* repeated: no RNG draw, no credit change */
    CHECK(c->chan.freed_unreported == ADJ_CREDIT);
    CHECK(zssh_channel_recv(&g_conn[CL], rb, sizeof rb, &got) == ZSSH_AGAIN && got == 0);
    CHECK(adj_same());                                      /* empty ring: no adjust either */
    for (size_t i = 0; i < sizeof rb; i++) CHECK(rb[i] == 0xa5);
    uint32_t w = c->chan.send_window;                       /* peer TX window at 0 */
    c->chan.send_window = 0;
    adj_snap();
    CHECK(zssh_channel_send(&g_conn[CL], data, sizeof data, &acc) == ZSSH_AGAIN && acc == 0);
    CHECK(adj_same());
    c->chan.send_window = w;
}

static void adj_progress_after_drain(void)
{
    static uint8_t data[5000], wire[16384], rb[8192];
    struct zssh_impl *c = IMPL(CL);
    size_t acc = 0, cons = 0, got = 0;
    const uint32_t rw0 = c->chan.recv_window, sw0 = IMPL(SV)->chan.send_window;
    const uint32_t seq0 = c->tx.seq;
    memset(data, 0x33, sizeof data);
    CHECK(zssh_output_consume(&g_conn[CL], zssh_txq_pending(&c->txq)) == ZSSH_OK);
    CHECK(zssh_channel_send(&g_conn[CL], data, sizeof data, &acc) == ZSSH_OK && acc == sizeof data);
    CHECK(c->tx.seq == seq0 + 2);                           /* exactly one adjust, one DATA */
    CHECK(c->chan.freed_unreported == 0 && c->chan.recv_window == rw0 + ADJ_CREDIT);
    size_t wn = take_out(CL, wire, sizeof wire);
    CHECK(zssh_input(&g_conn[SV], wire, wn, &cons) != ZSSH_STATUS_BAD_CALL && cons == wn);
    CHECK(IMPL(SV)->chan.send_window == sw0 + ADJ_CREDIT);  /* announced == deferred credit, once */
    CHECK(zssh_channel_recv(&g_conn[SV], rb, sizeof rb, &got) == ZSSH_OK && got == sizeof data);
    CHECK(memcmp(rb, data, sizeof data) == 0);
}

static void g_send_adjust_again(void)
{
    adj_defer();
    adj_again_cases();
    adj_progress_after_drain();
}
