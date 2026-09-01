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

    return failures;
}
