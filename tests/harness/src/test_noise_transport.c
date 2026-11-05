/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the secure-session library: x25519_safe (low-order reject +
 * normal-DH accept), the Noise_NK and Noise_XX handshakes (initiator<->
 * responder round-trip with matching transport keys + transcript hashes, and a
 * tampered-message auth failure), and session_transport (per-channel record
 * round-trip, replay/reorder rejection, tamper drop, and a rekey-boundary
 * crossing). No canonical Noise KAT vectors were available in-tree, so the
 * handshake gate is the self-consistent round-trip + transcript-hash
 * equivalence (both parties independently derive identical keys and h);
 * x25519_safe and the RFC-5869 HKDF beneath it are pinned by KAT in test_hkdf. */

#include "test/test_core.h"
#include "crypto/x25519_safe.h"
#include "crypto/curve25519.h"
#include "noise/noise_handshake.h"
#include "noise/session_transport.h"
#include "crypto/chacha20poly1305.h"

/* Deterministic 32-byte scalar from a seed byte (test key material). */
static void mk_scalar(uint8_t out[32], uint8_t seed)
{
    for (int i = 0; i < 32; i++) out[i] = (uint8_t)(seed + i * 7 + 1);
}

int test_x25519_safe(void)
{
    int failures = 0;

    TEST_CASE("x25519_safe: reject low-order, accept normal DH") {
        uint8_t a_priv[32], b_priv[32], a_pub[32], b_pub[32];
        mk_scalar(a_priv, 0x11);
        mk_scalar(b_priv, 0x77);
        ASSERT(curve25519_scalarmult_base(a_pub, a_priv));
        ASSERT(curve25519_scalarmult_base(b_pub, b_priv));

        /* Low-order point: the all-zero u-coordinate yields an all-zero secret
         * that the bare scalarmult accepts but x25519_safe must reject. */
        uint8_t low[32] = {0};
        uint8_t ss[32];
        ASSERT(!x25519_safe(ss, a_priv, low));
        /* out zeroized on reject */
        uint8_t zero[32] = {0};
        ASSERT(memcmp(ss, zero, 32) == 0);

        /* Normal DH: accepted, non-zero, symmetric, and byte-identical to the
         * bare scalarmult it wraps. */
        uint8_t ss_ab[32], ss_ba[32], raw[32];
        ASSERT(x25519_safe(ss_ab, a_priv, b_pub));
        ASSERT(x25519_safe(ss_ba, b_priv, a_pub));
        ASSERT(memcmp(ss_ab, ss_ba, 32) == 0);      /* DH agreement */
        ASSERT(memcmp(ss_ab, zero, 32) != 0);        /* non-zero secret */
        ASSERT(curve25519_scalarmult(raw, a_priv, b_pub));
        ASSERT(memcmp(ss_ab, raw, 32) == 0);         /* matches wrapped fn */
    } TEST_END

    return failures;
}

int test_noise_nk_handshake(void)
{
    int failures = 0;

    TEST_CASE("noise_nk: round-trip keys match + tamper fails") {
        const uint8_t prologue[] = { 'z','c','l','2','3','-','v','2' };

        uint8_t r_priv[32], r_pub[32];
        mk_scalar(r_priv, 0x33);
        ASSERT(curve25519_scalarmult_base(r_pub, r_priv));

        struct noise_handshake init, resp;
        /* initiator knows the responder static (premessage <- s); no own static */
        ASSERT(noise_hs_init(&init, noise_pattern_nk(), true, prologue, sizeof(prologue),
                             NULL, r_pub));
        ASSERT(noise_hs_init(&resp, noise_pattern_nk(), false, prologue, sizeof(prologue),
                             r_priv, NULL));

        uint8_t m1[NOISE_MAX_MESSAGE], m2[NOISE_MAX_MESSAGE];
        uint8_t pin[NOISE_MAX_MESSAGE], pout[NOISE_MAX_MESSAGE];
        size_t m1len = 0, m2len = 0, plen = 0;

        /* msg1: -> e, es  (carry a payload to exercise the AEAD payload path) */
        const uint8_t hello[] = "hello-responder";
        ASSERT(noise_hs_write_message(&init, hello, sizeof(hello), m1, &m1len));
        ASSERT(noise_hs_read_message(&resp, m1, m1len, pout, &plen));
        ASSERT(plen == sizeof(hello) && memcmp(pout, hello, plen) == 0);

        /* msg2: <- e, ee */
        const uint8_t world[] = "hello-initiator";
        ASSERT(noise_hs_write_message(&resp, world, sizeof(world), m2, &m2len));
        ASSERT(noise_hs_read_message(&init, m2, m2len, pout, &plen));
        ASSERT(plen == sizeof(world) && memcmp(pout, world, plen) == 0);

        ASSERT(noise_hs_done(&init) && noise_hs_done(&resp));

        uint8_t i_send[32], i_recv[32], r_send[32], r_recv[32];
        ASSERT(noise_hs_split(&init, i_send, i_recv));
        ASSERT(noise_hs_split(&resp, r_send, r_recv));
        /* directional keys cross over */
        ASSERT(memcmp(i_send, r_recv, 32) == 0);
        ASSERT(memcmp(i_recv, r_send, 32) == 0);
        ASSERT(memcmp(i_send, i_recv, 32) != 0);

        /* transcript hashes must be identical (channel binding) */
        uint8_t hi[32], hr[32];
        ASSERT(noise_hs_transcript_hash(&init, hi));
        ASSERT(noise_hs_transcript_hash(&resp, hr));
        ASSERT(memcmp(hi, hr, 32) == 0);

        /* Tamper: flip one byte of msg1 → responder read must auth-fail. */
        struct noise_handshake init2, resp2;
        ASSERT(noise_hs_init(&init2, noise_pattern_nk(), true, prologue, sizeof(prologue),
                             NULL, r_pub));
        ASSERT(noise_hs_init(&resp2, noise_pattern_nk(), false, prologue, sizeof(prologue),
                             r_priv, NULL));
        (void)pin;
        ASSERT(noise_hs_write_message(&init2, NULL, 0, m1, &m1len));
        m1[m1len - 1] ^= 0x40; /* corrupt the payload tag */
        ASSERT(!noise_hs_read_message(&resp2, m1, m1len, pout, &plen));
    } TEST_END

    return failures;
}

int test_noise_xx_handshake(void)
{
    int failures = 0;

    TEST_CASE("noise_xx: mutual-static round-trip + learned remote statics") {
        uint8_t i_priv[32], i_pub[32], r_priv[32], r_pub[32];
        mk_scalar(i_priv, 0x51);
        mk_scalar(r_priv, 0x99);
        ASSERT(curve25519_scalarmult_base(i_pub, i_priv));
        ASSERT(curve25519_scalarmult_base(r_pub, r_priv));

        struct noise_handshake init, resp;
        ASSERT(noise_hs_init(&init, noise_pattern_xx(), true, NULL, 0, i_priv, NULL));
        ASSERT(noise_hs_init(&resp, noise_pattern_xx(), false, NULL, 0, r_priv, NULL));

        uint8_t m[NOISE_MAX_MESSAGE], pout[NOISE_MAX_MESSAGE];
        size_t mlen = 0, plen = 0;

        /* msg1: -> e */
        ASSERT(noise_hs_write_message(&init, NULL, 0, m, &mlen));
        ASSERT(noise_hs_read_message(&resp, m, mlen, pout, &plen));
        /* msg2: <- e, ee, s, es */
        ASSERT(noise_hs_write_message(&resp, NULL, 0, m, &mlen));
        ASSERT(noise_hs_read_message(&init, m, mlen, pout, &plen));
        /* msg3: -> s, se */
        ASSERT(noise_hs_write_message(&init, NULL, 0, m, &mlen));
        ASSERT(noise_hs_read_message(&resp, m, mlen, pout, &plen));

        ASSERT(noise_hs_done(&init) && noise_hs_done(&resp));

        uint8_t i_send[32], i_recv[32], r_send[32], r_recv[32];
        ASSERT(noise_hs_split(&init, i_send, i_recv));
        ASSERT(noise_hs_split(&resp, r_send, r_recv));
        ASSERT(memcmp(i_send, r_recv, 32) == 0);
        ASSERT(memcmp(i_recv, r_send, 32) == 0);

        /* each side learned the peer's true static key */
        uint8_t got_r[32], got_i[32];
        ASSERT(noise_hs_remote_static(&init, got_r));
        ASSERT(noise_hs_remote_static(&resp, got_i));
        ASSERT(memcmp(got_r, r_pub, 32) == 0);
        ASSERT(memcmp(got_i, i_pub, 32) == 0);
    } TEST_END

    return failures;
}

/* Build a session_transport pair (initiator side, responder side) from an NK
 * handshake so send/recv keys genuinely cross over. */
static bool build_pair(struct session_transport *ts_i, struct session_transport *ts_r)
{
    uint8_t r_priv[32], r_pub[32];
    mk_scalar(r_priv, 0x2b);
    if (!curve25519_scalarmult_base(r_pub, r_priv)) return false;

    struct noise_handshake init, resp;
    if (!noise_hs_init(&init, noise_pattern_nk(), true, NULL, 0, NULL, r_pub)) return false;
    if (!noise_hs_init(&resp, noise_pattern_nk(), false, NULL, 0, r_priv, NULL)) return false;

    uint8_t m[NOISE_MAX_MESSAGE], po[NOISE_MAX_MESSAGE];
    size_t ml = 0, pl = 0;
    if (!noise_hs_write_message(&init, NULL, 0, m, &ml)) return false;
    if (!noise_hs_read_message(&resp, m, ml, po, &pl)) return false;
    if (!noise_hs_write_message(&resp, NULL, 0, m, &ml)) return false;
    if (!noise_hs_read_message(&init, m, ml, po, &pl)) return false;

    uint8_t is[32], ir[32], rs[32], rr[32];
    if (!noise_hs_split(&init, is, ir)) return false;
    if (!noise_hs_split(&resp, rs, rr)) return false;
    session_transport_init(ts_i, is, ir);
    session_transport_init(ts_r, rs, rr);
    return true;
}

static int st_frame_known_answer(void);
static int st_length_edges(void);
static int st_rekey_known_answer(void);
static int st_init_and_cleanse(void);

int test_session_transport(void)
{
    int failures = 0;

    TEST_CASE("session_transport: records, replay/reorder, tamper, rekey") {
        struct session_transport ts_i, ts_r;
        ASSERT(build_pair(&ts_i, &ts_r));

        uint8_t frame[SESSION_FRAME_MAX_WIRE], out[SESSION_MAX_PAYLOAD];
        size_t flen = 0, olen = 0;
        enum session_channel ch;

        /* Round-trip every inner channel tag, initiator -> responder. */
        const enum session_channel tags[] =
            { SESSION_CH_DATA, SESSION_CH_WINCH, SESSION_CH_AUTH, SESSION_CH_CTRL };
        for (size_t i = 0; i < 4; i++) {
            uint8_t payload[64];
            for (int j = 0; j < 64; j++) payload[j] = (uint8_t)(i * 64 + j);
            ASSERT(session_transport_encrypt(&ts_i, tags[i], payload, sizeof(payload),
                                             frame, &flen));
            ASSERT(session_transport_decrypt(&ts_r, &ch, frame, flen, out, &olen));
            ASSERT(ch == tags[i]);
            ASSERT(olen == sizeof(payload) && memcmp(out, payload, olen) == 0);
        }

        /* Reorder + replay on a FRESH pair. */
        struct session_transport s2, r2;
        ASSERT(build_pair(&s2, &r2));
        uint8_t f1[SESSION_FRAME_MAX_WIRE], f2[SESSION_FRAME_MAX_WIRE];
        size_t l1 = 0, l2 = 0;
        const uint8_t p1[] = "frame-one";
        const uint8_t p2[] = "frame-two";
        ASSERT(session_transport_encrypt(&s2, SESSION_CH_DATA, p1, sizeof(p1), f1, &l1));
        ASSERT(session_transport_encrypt(&s2, SESSION_CH_DATA, p2, sizeof(p2), f2, &l2));
        /* out-of-order: deliver frame 2 first → counter mismatch → auth fail */
        ASSERT(!session_transport_decrypt(&r2, &ch, f2, l2, out, &olen));
        /* in-order frame 1 still opens (recv counter did not advance on failure) */
        ASSERT(session_transport_decrypt(&r2, &ch, f1, l1, out, &olen));
        ASSERT(olen == sizeof(p1) && memcmp(out, p1, olen) == 0);
        /* replay frame 1 → now stale → auth fail */
        ASSERT(!session_transport_decrypt(&r2, &ch, f1, l1, out, &olen));
        /* frame 2 now in-order → opens */
        ASSERT(session_transport_decrypt(&r2, &ch, f2, l2, out, &olen));
        ASSERT(olen == sizeof(p2) && memcmp(out, p2, olen) == 0);

        /* Tamper: flip a ciphertext byte → drop. */
        struct session_transport s3, r3;
        ASSERT(build_pair(&s3, &r3));
        ASSERT(session_transport_encrypt(&s3, SESSION_CH_DATA, p1, sizeof(p1), f1, &l1));
        f1[SESSION_FRAME_LEN_BYTES + 2] ^= 0x80;
        ASSERT(!session_transport_decrypt(&r3, &ch, f1, l1, out, &olen));

        /* Rekey boundary: poke both counters to the frame limit so the next
         * record rekeys each direction in lockstep, then confirm it still opens
         * and both epochs advanced. */
        struct session_transport s4, r4;
        ASSERT(build_pair(&s4, &r4));
        s4.send_n = SESSION_REKEY_FRAME_LIMIT;
        r4.recv_n = SESSION_REKEY_FRAME_LIMIT;
        ASSERT(s4.send_epoch == 0 && r4.recv_epoch == 0);
        const uint8_t pr[] = "post-rekey";
        ASSERT(session_transport_encrypt(&s4, SESSION_CH_DATA, pr, sizeof(pr), f1, &l1));
        ASSERT(s4.send_epoch == 1);            /* sender rekeyed */
        ASSERT(session_transport_decrypt(&r4, &ch, f1, l1, out, &olen));
        ASSERT(r4.recv_epoch == 1);            /* receiver rekeyed in lockstep */
        ASSERT(ch == SESSION_CH_DATA);
        ASSERT(olen == sizeof(pr) && memcmp(out, pr, olen) == 0);

        /* Oversize payload is rejected, not truncated. */
        static uint8_t big[SESSION_MAX_PAYLOAD + 1];
        ASSERT(!session_transport_encrypt(&ts_i, SESSION_CH_DATA, big, sizeof(big),
                                          frame, &flen));
    } TEST_END

    failures += st_frame_known_answer();
    failures += st_length_edges();
    failures += st_rekey_known_answer();
    failures += st_init_and_cleanse();
    return failures;
}

/* ---- mutation-sweep closers: spec-built reference frames --------------------
 * These build the expected record independently of session_transport.c, from
 * the documented wire layout: nonce = 4x00 || LE64(n); AAD = LE32(epoch) ||
 * LE24(wire_len); frame = LE24(wire_len) || ChaCha20-Poly1305(inner). */

/* Seal `inner` under (key, epoch, n) the way the transport spec says. */
static bool ref_frame(const uint8_t key[32], uint32_t epoch, uint64_t n,
                      const uint8_t *inner, size_t inner_len,
                      uint8_t *frame, size_t *frame_len)
{
    uint8_t nonce[12] = {0};
    for (int i = 0; i < 8; i++) nonce[4 + i] = (uint8_t)(n >> (8 * i));
    uint32_t wl = (uint32_t)inner_len + 16;
    uint8_t aad[7] = { (uint8_t)epoch, (uint8_t)(epoch >> 8), (uint8_t)(epoch >> 16),
                       (uint8_t)(epoch >> 24), (uint8_t)wl, (uint8_t)(wl >> 8),
                       (uint8_t)(wl >> 16) };
    frame[0] = (uint8_t)wl;
    frame[1] = (uint8_t)(wl >> 8);
    frame[2] = (uint8_t)(wl >> 16);
    *frame_len = 3 + wl;
    return chacha20poly1305_encrypt(inner, inner_len, aad, sizeof(aad), nonce, key,
                                    frame + 3);
}

/* Spec rekey: first 32 bytes of AEAD(k, nonce 4x00||FF*8, no aad, 32x00). */
static bool ref_rekey(const uint8_t key[32], uint8_t next[32])
{
    uint8_t nonce[12] = {0};
    memset(nonce + 4, 0xFF, 8);
    uint8_t zero[32] = {0}, ct[48];
    if (!chacha20poly1305_encrypt(zero, 32, NULL, 0, nonce, key, ct)) return false;
    memcpy(next, ct, 32);
    return true;
}

static void kat_keys(uint8_t a[32], uint8_t b[32])
{
    for (int i = 0; i < 32; i++) { a[i] = (uint8_t)(0x11 + i); b[i] = (uint8_t)(0xE0 - 3 * i); }
}

/* A sender and a receiver over fixed keys (no handshake): s.send == r.recv. */
static void kat_pair(struct session_transport *s, struct session_transport *r)
{
    uint8_t ka[32], kb[32];
    kat_keys(ka, kb);
    session_transport_init(s, ka, kb);
    session_transport_init(r, kb, ka);
}

/* Wire bytes, nonce counter bytes and AAD epoch bytes against the spec frame. */
static int st_frame_known_answer(void)
{
    int failures = 0;
    TEST_CASE("session_transport: frame bytes equal the spec-built reference") {
        static uint8_t pay[300], inner[301], want[SESSION_FRAME_MAX_WIRE];
        static uint8_t got[SESSION_FRAME_MAX_WIRE], back[SESSION_MAX_PAYLOAD];
        for (size_t i = 0; i < sizeof(pay); i++) pay[i] = (uint8_t)(i * 7 + 1);
        inner[0] = SESSION_CH_CTRL;
        memcpy(inner + 1, pay, sizeof(pay));
        struct session_transport s, r;
        kat_pair(&s, &r);
        s.send_epoch = r.recv_epoch = 0x04030201u;   /* four distinct AAD bytes */
        s.send_n = r.recv_n = 0x0A0B0Cu;             /* distinct nonce bytes, < rekey limit */
        size_t wl = 0, gl = 0, bl = 0;
        enum session_channel ch = SESSION_CH_DATA;
        ASSERT(ref_frame(s.send_key, 0x04030201u, 0x0A0B0Cu, inner, sizeof(inner), want, &wl));
        ASSERT(session_transport_encrypt(&s, SESSION_CH_CTRL, pay, sizeof(pay), got, &gl));
        /* wire_len 317 = 0x013D: header 3D 01 00 pins both length bytes */
        ASSERT(gl == 3 + 317 && got[0] == 0x3D && got[1] == 0x01 && got[2] == 0x00);
        ASSERT(gl == wl && memcmp(got, want, wl) == 0);
        ASSERT(s.send_n == 0x0A0B0Dull && s.send_bytes_epoch == 301);
        ASSERT(session_transport_decrypt(&r, &ch, got, gl, back, &bl));
        ASSERT(ch == SESSION_CH_CTRL && bl == sizeof(pay) && memcmp(back, pay, bl) == 0);
        ASSERT(r.recv_n == 0x0A0B0Dull && r.recv_bytes_epoch == 301);
    } TEST_END
    return failures;
}

/* Length edges: empty payload, largest payload, truncated frame, authentic
 * frames whose inner length is out of range. */
static int st_length_edges(void)
{
    int failures = 0;
    TEST_CASE("session_transport: length edges and authentic out-of-range frames") {
        static uint8_t pay[SESSION_MAX_PAYLOAD], back[SESSION_MAX_PAYLOAD];
        static uint8_t fr[SESSION_FRAME_MAX_WIRE + 64], inner[SESSION_FRAME_MAX_PLAINTEXT + 1];
        memset(pay, 0x5A, sizeof(pay));
        struct session_transport s, r;
        kat_pair(&s, &r);
        size_t fl = 0, bl = 99;
        enum session_channel ch = SESSION_CH_DATA;
        /* empty payload: inner length 1 is legal */
        ASSERT(session_transport_encrypt(&s, SESSION_CH_AUTH, pay, 0, fr, &fl));
        ASSERT(fl == 3 + 1 + 16);
        ASSERT(session_transport_decrypt(&r, &ch, fr, fl, back, &bl));
        ASSERT(ch == SESSION_CH_AUTH && bl == 0);
        /* the largest legal payload round-trips (the cap is inclusive) */
        ASSERT(session_transport_encrypt(&s, SESSION_CH_DATA, pay, SESSION_MAX_PAYLOAD,
                                         fr, &fl));
        ASSERT(fl == SESSION_FRAME_MAX_WIRE);
        /* a frame cut one byte short is refused even when the bytes follow in memory */
        ASSERT(!session_transport_decrypt(&r, &ch, fr, fl - 1, back, &bl));
        ASSERT(session_transport_decrypt(&r, &ch, fr, fl, back, &bl));
        ASSERT(bl == SESSION_MAX_PAYLOAD && memcmp(back, pay, bl) == 0);
        /* authentic frame with inner length 1537 (one over the cap) is refused */
        struct session_transport s2, r2;
        kat_pair(&s2, &r2);
        memset(inner, 0x33, sizeof(inner));
        ASSERT(ref_frame(s2.send_key, 0, 0, inner, SESSION_FRAME_MAX_PLAINTEXT + 1, fr, &fl));
        ASSERT(!session_transport_decrypt(&r2, &ch, fr, fl, back, &bl));
        /* authentic frame with inner length 0 (no channel tag) is refused */
        ASSERT(ref_frame(s2.send_key, 0, 0, inner, 0, fr, &fl));
        ASSERT(fl == 19 && !session_transport_decrypt(&r2, &ch, fr, fl, back, &bl));
        ASSERT(r2.recv_n == 0);                      /* refusals never advance the counter */
        /* the same sealed record at the cap itself is accepted */
        ASSERT(ref_frame(s2.send_key, 0, 0, inner, SESSION_FRAME_MAX_PLAINTEXT, fr, &fl));
        ASSERT(session_transport_decrypt(&r2, &ch, fr, fl, back, &bl));
        ASSERT(bl == SESSION_MAX_PAYLOAD && r2.recv_n == 1);
    } TEST_END
    return failures;
}

/* Rekey: spec key derivation, counter/byte reset, and both thresholds inclusive. */
static int st_rekey_known_answer(void)
{
    int failures = 0;
    TEST_CASE("session_transport: rekey key, resets and inclusive thresholds") {
        uint8_t pay[40], inner[41], want[SESSION_FRAME_MAX_WIRE], got[SESSION_FRAME_MAX_WIRE];
        uint8_t back[SESSION_MAX_PAYLOAD], nk[32];
        memset(pay, 0x42, sizeof(pay));
        inner[0] = SESSION_CH_DATA;
        memcpy(inner + 1, pay, sizeof(pay));
        size_t wl = 0, gl = 0, bl = 0;
        enum session_channel ch;
        struct session_transport s, r;
        kat_pair(&s, &r);
        s.send_epoch = r.recv_epoch = 7;
        s.send_n = r.recv_n = SESSION_REKEY_FRAME_LIMIT;
        ASSERT(ref_rekey(s.send_key, nk));
        ASSERT(ref_frame(nk, 8, 0, inner, sizeof(inner), want, &wl));
        ASSERT(session_transport_encrypt(&s, SESSION_CH_DATA, pay, sizeof(pay), got, &gl));
        ASSERT(memcmp(s.send_key, nk, 32) == 0 && s.send_epoch == 8);
        ASSERT(gl == wl && memcmp(got, want, wl) == 0);      /* sealed at nonce 0, epoch 8 */
        ASSERT(s.send_n == 1 && s.send_bytes_epoch == sizeof(inner));
        ASSERT(session_transport_decrypt(&r, &ch, got, gl, back, &bl));
        ASSERT(memcmp(r.recv_key, nk, 32) == 0 && r.recv_epoch == 8);
        ASSERT(r.recv_n == 1 && r.recv_bytes_epoch == sizeof(inner));
        ASSERT(bl == sizeof(pay) && memcmp(back, pay, bl) == 0);

        /* byte threshold is inclusive on both sides; one byte short does not rekey */
        struct session_transport s2, r2, s3, r3;
        kat_pair(&s2, &r2);
        kat_pair(&s3, &r3);
        s2.send_bytes_epoch = r2.recv_bytes_epoch = SESSION_REKEY_BYTE_LIMIT;
        s3.send_bytes_epoch = r3.recv_bytes_epoch = SESSION_REKEY_BYTE_LIMIT - 1;
        ASSERT(session_transport_encrypt(&s2, SESSION_CH_DATA, pay, sizeof(pay), got, &gl));
        ASSERT(s2.send_epoch == 1 && s2.send_bytes_epoch == sizeof(inner));
        ASSERT(session_transport_decrypt(&r2, &ch, got, gl, back, &bl));
        ASSERT(r2.recv_epoch == 1 && r2.recv_bytes_epoch == sizeof(inner));
        ASSERT(session_transport_encrypt(&s3, SESSION_CH_DATA, pay, sizeof(pay), got, &gl));
        ASSERT(s3.send_epoch == 0);
        ASSERT(session_transport_decrypt(&r3, &ch, got, gl, back, &bl));
        ASSERT(r3.recv_epoch == 0);
    } TEST_END
    return failures;
}

/* Init clears stale state; cleanse zeroes both keys and tolerates NULL. */
static int st_init_and_cleanse(void)
{
    int failures = 0;
    TEST_CASE("session_transport: init clears state, cleanse zeroes keys") {
        uint8_t ka[32], kb[32], zero[32] = {0};
        kat_keys(ka, kb);
        struct session_transport t;
        memset(&t, 0xA5, sizeof(t));
        session_transport_init(&t, ka, kb);
        ASSERT(t.send_n == 0 && t.recv_n == 0 && t.send_epoch == 0 && t.recv_epoch == 0);
        ASSERT(t.send_bytes_epoch == 0 && t.recv_bytes_epoch == 0);
        ASSERT(memcmp(t.send_key, ka, 32) == 0 && memcmp(t.recv_key, kb, 32) == 0);
        session_transport_cleanse(&t);
        ASSERT(memcmp(t.send_key, zero, 32) == 0);
        ASSERT(memcmp(t.recv_key, zero, 32) == 0);
        session_transport_cleanse(NULL);
    } TEST_END
    return failures;
}
