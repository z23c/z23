/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Differential tests for the Noise-encrypted P2P transport (net/noise_transport).
 * The load-bearing claim is that the transport transforms bytes ONLY: the
 * plaintext handed up after decrypt is byte-identical to what a v1 peer sent
 * raw. These drive the transport object directly over in-memory buffers (no
 * socket / p2p_node needed):
 *
 *   (1) full hybrid XXhfs handshake completes; the empty-payload message
 *       lengths are the fixed 1216/1200/64 the design pins.
 *   (2) Noise<->Noise message round-trip is byte-identical, including a message
 *       larger than one record (spanning multiple SESSION_MAX_PAYLOAD chunks)
 *       and the reverse direction.
 *   (3) application messages written DURING the handshake are buffered and
 *       flushed sealed on completion, delivered byte-identically.
 *   (4) interop fallback: a responder fed the v1 network magic (even split
 *       across two feeds) falls back to plaintext and surfaces the raw bytes.
 *   (5) hostile input (garbage handshake, tamper, oversize frame) fails closed
 *       with no crash.
 *   (6) the handshake completes from 1-byte and odd-sized feeds, refuses a
 *       corrupted KEM ciphertext and a peer bound to the classical suite
 *       prologue, and runs on a 64 KiB thread stack.
 *
 * All sub-checks live under one TEST_CASE: TEST_END defines a single fixed
 * `_test_next` label, so only one TEST_CASE/TEST_END pair is allowed per test
 * function (see test_connect_node_locked.c for the same convention). */

#include "test/test_core.h"
#include "base/hex.h"
#include "net/v2_identity.h"
#include "net/noise_transport.h"

#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include "noise/noise_handshake.h"

/* Empty-payload message lengths of Noise XXhfs. */
#define HS_MSG1_LEN 1216
#define HS_MSG2_LEN 1200
#define HS_MSG3_LEN 64

/* A representative 4-byte network magic, the same on both sides and chosen
 * not to collide with a random ephemeral prefix. */
static const unsigned char TEST_MAGIC[4] = { 0x24, 0xe9, 0x27, 0x64 };

static void mk_id(uint8_t out[32], uint8_t seed)
{
    for (int i = 0; i < 32; i++)
        out[i] = (uint8_t)(seed + i * 7 + 1);
}

/* Feed `msg1` to responder `r`: true iff the wire reply is exactly msg2-sized
 * and no plaintext surfaced. */
static bool exchange_msg1_for_msg2(struct noise_transport *r, const uint8_t *msg1,
                                   size_t msg1_len, uint8_t **w2, size_t *w2l)
{
    uint8_t *p = NULL;
    size_t pl = 0;
    bool ok = noise_transport_feed(r, msg1, msg1_len, w2, w2l, &p, &pl) &&
              *w2l == HS_MSG2_LEN && pl == 0;
    free(p);
    return ok;
}

/* Feed `w2` to initiator `i`: true iff the wire reply is exactly msg3-sized,
 * no plaintext surfaced and `i` is ESTABLISHED. */
static bool exchange_msg2_for_msg3(struct noise_transport *i, const uint8_t *w2,
                                   size_t w2l, uint8_t **w3, size_t *w3l)
{
    uint8_t *p = NULL;
    size_t pl = 0;
    bool ok = noise_transport_feed(i, w2, w2l, w3, w3l, &p, &pl) &&
              *w3l == HS_MSG3_LEN && pl == 0 && i->state == NOISE_ESTABLISHED;
    free(p);
    return ok;
}

/* Feed `w3` to responder `r`: true iff no wire reply or plaintext surfaces and
 * `r` is ESTABLISHED. */
static bool consume_msg3(struct noise_transport *r, const uint8_t *w3, size_t w3l,
                         uint8_t **w1, size_t *w1l)
{
    uint8_t *p = NULL;
    size_t pl = 0;
    bool ok = noise_transport_feed(r, w3, w3l, w1, w1l, &p, &pl) &&
              *w1l == 0 && pl == 0 && r->state == NOISE_ESTABLISHED;
    free(p);
    return ok;
}

/* Run the full XX handshake, leaving both transports ESTABLISHED. Returns true
 * on success; sets *ini and *res (caller frees). */
static bool run_handshake(struct noise_transport **ini, struct noise_transport **res)
{
    uint8_t ipriv[32], rpriv[32];
    mk_id(ipriv, 0x11);
    mk_id(rpriv, 0x77);

    uint8_t *msg1 = NULL;
    size_t msg1_len = 0;
    struct noise_transport *i =
        noise_transport_begin(true, ipriv, TEST_MAGIC, &msg1, &msg1_len);
    struct noise_transport *r =
        noise_transport_begin(false, rpriv, TEST_MAGIC, NULL, NULL);
    bool ok = false;
    uint8_t *w1 = NULL, *w2 = NULL, *w3 = NULL;
    size_t w1l = 0, w2l = 0, w3l = 0;

    if (!i || !r || !msg1 || msg1_len != HS_MSG1_LEN)
        goto done;

    /* responder consumes msg1 -> emits msg2 */
    if (!exchange_msg1_for_msg2(r, msg1, msg1_len, &w2, &w2l))
        goto done;

    /* initiator consumes msg2 -> emits msg3, becomes ESTABLISHED */
    if (!exchange_msg2_for_msg3(i, w2, w2l, &w3, &w3l))
        goto done;

    /* responder consumes msg3, becomes ESTABLISHED */
    if (!consume_msg3(r, w3, w3l, &w1, &w1l))
        goto done;

    ok = true;
done:
    free(msg1); free(w1); free(w2); free(w3);
    if (ok) { *ini = i; *res = r; }
    else { noise_transport_free(i); noise_transport_free(r); }
    return ok;
}

/* Seal `msg` on `from`, feed the ciphertext to `to`, return true iff the
 * decrypted plaintext equals `msg` byte-for-byte and produced no wire reply. */
static bool roundtrip(struct noise_transport *from, struct noise_transport *to,
                      const uint8_t *msg, size_t len)
{
    uint8_t *ct = NULL, *pt = NULL, *wire = NULL;
    size_t ct_len = 0, pt_len = 0, wire_len = 0;
    bool ok = false;

    if (!noise_transport_write(from, msg, len, &ct, &ct_len))
        goto done;
    if (ct_len == 0)
        goto done;
    if (!noise_transport_feed(to, ct, ct_len, &wire, &wire_len, &pt, &pt_len))
        goto done;
    if (wire_len != 0 || pt_len != len)
        goto done;
    if (len && memcmp(pt, msg, len) != 0)
        goto done;
    ok = true;
done:
    free(ct); free(pt); free(wire);
    return ok;
}

/* Feed `in` to `t` in pieces of at most `chunk` bytes, appending every wire
 * reply to (*wire,*wlen). Fails if any feed fails or yields plaintext. */
static bool feed_chunks(struct noise_transport *t, const uint8_t *in, size_t n,
                        size_t chunk, uint8_t **wire, size_t *wlen)
{
    for (size_t off = 0; off < n; off += chunk) {
        size_t take = n - off < chunk ? n - off : chunk;
        uint8_t *w = NULL, *p = NULL;
        size_t wl = 0, pl = 0;
        bool ok = noise_transport_feed(t, in + off, take, &w, &wl, &p, &pl) &&
                  pl == 0;
        uint8_t *grown = ok ? realloc(*wire, *wlen + wl + 1) : NULL;
        if (grown) {
            memcpy(grown + *wlen, w, wl);
            *wire = grown;
            *wlen += wl;
        }
        free(w);
        free(p);
        if (!grown)
            return false;
    }
    return true;
}

/* Feed one handshake message in `chunk`-byte pieces, the last byte on its
 * own: the transport must still be in `mid` before it and in `end` after it,
 * having produced `want` reply bytes. */
static bool feed_message(struct noise_transport *t, const uint8_t *in, size_t n,
                         size_t chunk, enum noise_hs_state mid,
                         enum noise_hs_state end, size_t want,
                         uint8_t **wire, size_t *wlen)
{
    return feed_chunks(t, in, n - 1, chunk, wire, wlen) && t->state == mid &&
           *wlen == 0 && feed_chunks(t, in + n - 1, 1, 1, wire, wlen) &&
           t->state == end && *wlen == want;
}

/* Complete the handshake feeding every message in `chunk`-byte pieces. */
static bool chunked_handshake(size_t chunk)
{
    uint8_t ipriv[32], rpriv[32];
    mk_id(ipriv, 0x11);
    mk_id(rpriv, 0x77);
    uint8_t *msg1 = NULL, *w2 = NULL, *w3 = NULL, *w4 = NULL;
    size_t msg1_len = 0, w2l = 0, w3l = 0, w4l = 0;
    struct noise_transport *i =
        noise_transport_begin(true, ipriv, TEST_MAGIC, &msg1, &msg1_len);
    struct noise_transport *r =
        noise_transport_begin(false, rpriv, TEST_MAGIC, NULL, NULL);
    bool ok = i && r && msg1 && msg1_len == HS_MSG1_LEN &&
              feed_message(r, msg1, msg1_len, chunk, NOISE_DETECT,
                           NOISE_KEY_RECV, HS_MSG2_LEN, &w2, &w2l) &&
              feed_message(i, w2, w2l, chunk, NOISE_KEY_SENT,
                           NOISE_ESTABLISHED, HS_MSG3_LEN, &w3, &w3l) &&
              feed_chunks(r, w3, w3l, chunk, &w4, &w4l) &&
              r->state == NOISE_ESTABLISHED && w4l == 0 &&
              roundtrip(i, r, msg1, 100);
    free(msg1); free(w2); free(w3); free(w4);
    noise_transport_free(i);
    noise_transport_free(r);
    return ok;
}

/* A peer bound to the classical suite prologue (0x02/0x01) running `pattern`
 * sends its first message to a fresh driver responder. */
static bool old_prologue_first_message(const struct noise_pattern *pattern,
                                       uint8_t *msg, size_t *len,
                                       struct noise_handshake *hs)
{
    uint8_t ipriv[32], pro[6];
    mk_id(ipriv, 0x11);
    memcpy(pro, TEST_MAGIC, 4);
    pro[4] = 0x02;
    pro[5] = 0x01;
    return noise_hs_init(hs, pattern, true, pro, sizeof(pro), ipriv, NULL) &&
           noise_hs_write_message(hs, NULL, 0, msg, len);
}

/* The hybrid driver reaches a failed state against a hybrid peer that binds
 * the classical prologue: the peer's read of msg2 fails. */
static bool refuses_old_prologue_peer(void)
{
    uint8_t rpriv[32], msg[NOISE_MAX_MESSAGE], pt[NOISE_MAX_MESSAGE];
    size_t len = 0, ptl = 0;
    struct noise_handshake hs;
    mk_id(rpriv, 0x77);
    if (!old_prologue_first_message(noise_pattern_xxhfs(), msg, &len, &hs))
        return false;
    struct noise_transport *r =
        noise_transport_begin(false, rpriv, TEST_MAGIC, NULL, NULL);
    uint8_t *w = NULL, *p = NULL;
    size_t wl = 0, pl = 0;
    bool ok = r && len == HS_MSG1_LEN &&
              noise_transport_feed(r, msg, len, &w, &wl, &p, &pl) &&
              wl == HS_MSG2_LEN &&
              !noise_hs_read_message(&hs, w, wl, pt, &ptl) &&
              r->state != NOISE_ESTABLISHED;
    free(w); free(p);
    noise_hs_cleanse(&hs);
    noise_transport_free(r);
    return ok;
}

/* A classical XX first message (32 bytes) never completes a hybrid responder. */
static bool stalls_on_classical_xx_peer(void)
{
    uint8_t rpriv[32], msg[NOISE_MAX_MESSAGE];
    size_t len = 0;
    struct noise_handshake hs;
    mk_id(rpriv, 0x77);
    if (!old_prologue_first_message(noise_pattern_xx(), msg, &len, &hs))
        return false;
    struct noise_transport *r =
        noise_transport_begin(false, rpriv, TEST_MAGIC, NULL, NULL);
    uint8_t *w = NULL, *p = NULL;
    size_t wl = 0, pl = 0;
    bool ok = r && len == 32 &&
              noise_transport_feed(r, msg, len, &w, &wl, &p, &pl) &&
              wl == 0 && pl == 0 && r->state == NOISE_DETECT &&
              !noise_transport_handshake_expired(
                  r, r->hs_started_us + NOISE_HANDSHAKE_TIMEOUT_US - 1) &&
              noise_transport_handshake_expired(
                  r, r->hs_started_us + NOISE_HANDSHAKE_TIMEOUT_US);
    free(w); free(p);
    noise_hs_cleanse(&hs);
    noise_transport_free(r);
    return ok;
}

/* Thread stack region: the static TLS block of the test binary sits at the top
 * of a thread stack, so the region is generous and the depth of the handshake
 * below the thread entry is measured against a canary instead. */
#define PROBE_REGION_BYTES (1024 * 1024)
#define PROBE_BUDGET_BYTES (64 * 1024)
#define PROBE_CANARY 0xA5

struct stack_probe {
    bool ok;
    uintptr_t entry;
};

static void *handshake_thread(void *arg)
{
    struct stack_probe *probe = arg;
    volatile char marker = 0;
    probe->entry = (uintptr_t)&marker;
    struct noise_transport *i = NULL, *r = NULL;
    uint8_t msg[100] = { 1, 2, 3 };
    probe->ok = run_handshake(&i, &r) && roundtrip(i, r, msg, sizeof(msg)) &&
                roundtrip(r, i, msg, sizeof(msg));
    noise_transport_free(i);
    noise_transport_free(r);
    return NULL;
}

/* The whole handshake and a round trip use less than 64 KiB of thread stack. */
static bool handshake_fits_small_stack(void)
{
    uint8_t *base = aligned_alloc(4096, PROBE_REGION_BYTES);
    if (!base)
        return false;
    memset(base, PROBE_CANARY, PROBE_REGION_BYTES);
    struct stack_probe probe = { false, 0 };
    pthread_attr_t attr;
    pthread_t th;
    bool ran = pthread_attr_init(&attr) == 0;
    if (ran) {
        ran = pthread_attr_setstack(&attr, base, PROBE_REGION_BYTES) == 0 &&
              pthread_create(&th, &attr, handshake_thread, &probe) == 0;
        if (ran)
            pthread_join(th, NULL);
        pthread_attr_destroy(&attr);
    }
    size_t clean = 0;
    while (clean < PROBE_REGION_BYTES && base[clean] == PROBE_CANARY)
        clean++;
    uintptr_t lowest = (uintptr_t)base + clean;
    bool fits = ran && probe.ok && clean > 0 && probe.entry > lowest &&
                probe.entry - lowest <= PROBE_BUDGET_BYTES;
    free(base);
    return fits;
}

int test_noise_transport_parity(void)
{
    int failures = 0;

    TEST_CASE("noise_transport: differential plaintext/noise + hostile-input parity") {

        /* (1) XXhfs handshake completes with the design-pinned message sizes;
         * the exported pattern-derived lengths match them. */
        {
            ASSERT(noise_transport_handshake_msg_len(0) == HS_MSG1_LEN);
            ASSERT(noise_transport_handshake_msg_len(1) == HS_MSG2_LEN);
            ASSERT(noise_transport_handshake_msg_len(2) == HS_MSG3_LEN);
            ASSERT(noise_transport_handshake_msg_len(3) == 0);
            ASSERT(noise_transport_handshake_msg_len(-1) == 0);
            struct noise_transport *i = NULL, *r = NULL;
            ASSERT(run_handshake(&i, &r));
            ASSERT(i && r);
            ASSERT(i->state == NOISE_ESTABLISHED);
            ASSERT(r->state == NOISE_ESTABLISHED);
            /* XX authenticates both statics — each side learned the peer's. */
            ASSERT(i->have_peer_static);
            ASSERT(r->have_peer_static);
            struct noise_transport_snapshot isnap, rsnap;
            ASSERT(noise_transport_snapshot(i, &isnap));
            ASSERT(noise_transport_snapshot(r, &rsnap));
            ASSERT(isnap.established && rsnap.established);
            ASSERT(isnap.connection_generation != 0);
            ASSERT(rsnap.connection_generation != 0);
            ASSERT(isnap.connection_generation == rsnap.connection_generation);
            ASSERT(isnap.connection_serial != 0);
            ASSERT(rsnap.connection_serial != 0);
            ASSERT(isnap.connection_serial != rsnap.connection_serial);
            ASSERT(memcmp(isnap.transcript_hash, rsnap.transcript_hash, 32) == 0);
            ASSERT(memcmp(isnap.remote_static, r->hs.s_pub, 32) == 0);
            ASSERT(memcmp(rsnap.remote_static, i->hs.s_pub, 32) == 0);
            noise_transport_free(i);
            noise_transport_free(r);
        }

        /* (2a) Noise<->Noise round-trip byte-identical, both directions. */
        {
            struct noise_transport *i = NULL, *r = NULL;
            ASSERT(run_handshake(&i, &r));

            uint8_t small[100];
            for (int k = 0; k < 100; k++) small[k] = (uint8_t)(k * 3 + 7);
            ASSERT(roundtrip(i, r, small, sizeof(small)));

            uint8_t reply[40];
            for (int k = 0; k < 40; k++) reply[k] = (uint8_t)(0xA0 ^ k);
            ASSERT(roundtrip(r, i, reply, sizeof(reply)));

            noise_transport_free(i);
            noise_transport_free(r);
        }

        /* (2b) a message larger than one record spans chunks and reassembles.
         * 4000 bytes -> 3 DATA records (1535 + 1535 + 930); the receiver's
         * accumulator concatenates decrypted plaintext transparently. */
        {
            struct noise_transport *i = NULL, *r = NULL;
            ASSERT(run_handshake(&i, &r));

            size_t big_len = 4000;
            uint8_t *big = malloc(big_len);
            ASSERT(big != NULL);
            for (size_t k = 0; k < big_len; k++)
                big[k] = (uint8_t)(k * 131 + 17);
            bool ok = roundtrip(i, r, big, big_len);
            free(big);
            ASSERT(ok);

            noise_transport_free(i);
            noise_transport_free(r);
        }

        /* (3) writes during the handshake buffer, then flush sealed on
         * completion, delivered byte-identically. */
        {
            uint8_t ipriv[32], rpriv[32];
            mk_id(ipriv, 0x11);
            mk_id(rpriv, 0x77);

            uint8_t *msg1 = NULL;
            size_t msg1_len = 0;
            struct noise_transport *i =
                noise_transport_begin(true, ipriv, TEST_MAGIC, &msg1, &msg1_len);
            struct noise_transport *r =
                noise_transport_begin(false, rpriv, TEST_MAGIC, NULL, NULL);
            ASSERT(i && r && msg1 && msg1_len == HS_MSG1_LEN);

            /* Application message assembled while the initiator is still in
             * NOISE_KEY_SENT: it must buffer (ct_len == 0), not go on the wire. */
            uint8_t app[64];
            for (int k = 0; k < 64; k++) app[k] = (uint8_t)(k + 1);
            uint8_t *ct = NULL; size_t ct_len = 0;
            ASSERT(noise_transport_write(i, app, sizeof(app), &ct, &ct_len));
            ASSERT(ct_len == 0);
            free(ct); ct = NULL;

            uint8_t *w2 = NULL, *w3 = NULL, *p = NULL;
            size_t w2l = 0, w3l = 0, pl = 0;
            ASSERT(noise_transport_feed(r, msg1, msg1_len, &w2, &w2l, &p, &pl));
            free(p); p = NULL; pl = 0;
            /* initiator consumes msg2 -> wire is msg3 FOLLOWED BY the sealed
             * buffered app message. */
            ASSERT(noise_transport_feed(i, w2, w2l, &w3, &w3l, &p, &pl));
            ASSERT(w3l > HS_MSG3_LEN);   /* msg3 + at least one sealed record */
            ASSERT(pl == 0);
            free(p); p = NULL; pl = 0;

            /* responder consumes msg3 + sealed record -> delivers app text. */
            uint8_t *wout = NULL, *pt = NULL;
            size_t woutl = 0, ptl = 0;
            ASSERT(noise_transport_feed(r, w3, w3l, &wout, &woutl, &pt, &ptl));
            ASSERT(ptl == sizeof(app));
            ASSERT(memcmp(pt, app, sizeof(app)) == 0);

            free(msg1); free(w2); free(w3); free(wout); free(pt);
            noise_transport_free(i);
            noise_transport_free(r);
        }

        /* (4a) responder falls back to plaintext on the v1 network magic. */
        {
            uint8_t rpriv[32];
            mk_id(rpriv, 0x77);
            struct noise_transport *r =
                noise_transport_begin(false, rpriv, TEST_MAGIC, NULL, NULL);
            ASSERT(r != NULL);

            uint8_t v1[24];
            memcpy(v1, TEST_MAGIC, 4);
            for (int k = 4; k < 24; k++) v1[k] = (uint8_t)(k * 5 + 2);

            uint8_t *wire = NULL, *pt = NULL;
            size_t wire_len = 0, pt_len = 0;
            ASSERT(noise_transport_feed(r, v1, sizeof(v1), &wire, &wire_len,
                                     &pt, &pt_len));
            ASSERT(r->state == NOISE_PLAINTEXT_FALLBACK);
            ASSERT(wire_len == 0);
            ASSERT(pt_len == sizeof(v1));
            ASSERT(memcmp(pt, v1, sizeof(v1)) == 0);
            free(wire); free(pt);
            noise_transport_free(r);
        }

        /* (4b) magic split across two feeds still falls back cleanly. */
        {
            uint8_t rpriv[32];
            mk_id(rpriv, 0x77);
            struct noise_transport *r =
                noise_transport_begin(false, rpriv, TEST_MAGIC, NULL, NULL);
            ASSERT(r != NULL);

            uint8_t *wire = NULL, *pt = NULL;
            size_t wire_len = 0, pt_len = 0;
            /* First 2 magic bytes: too few to classify -> buffered, no out. */
            ASSERT(noise_transport_feed(r, TEST_MAGIC, 2, &wire, &wire_len,
                                     &pt, &pt_len));
            ASSERT(r->state == NOISE_DETECT);
            ASSERT(pt_len == 0);
            free(wire); free(pt); wire = NULL; pt = NULL;
            wire_len = pt_len = 0;

            /* Remaining 2 magic bytes complete the classifier -> fallback, and
             * the full 4 buffered bytes surface as plaintext. */
            ASSERT(noise_transport_feed(r, TEST_MAGIC + 2, 2, &wire, &wire_len,
                                     &pt, &pt_len));
            ASSERT(r->state == NOISE_PLAINTEXT_FALLBACK);
            ASSERT(pt_len == 4);
            ASSERT(memcmp(pt, TEST_MAGIC, 4) == 0);
            free(wire); free(pt);
            noise_transport_free(r);
        }

        /* (5a) garbage handshake fails closed: a full-length msg1 whose
         * ephemeral is the low-order point u=1 makes the ee DH yield the
         * all-zero shared secret x25519_safe rejects. */
        {
            uint8_t rpriv[32];
            mk_id(rpriv, 0x77);
            struct noise_transport *r =
                noise_transport_begin(false, rpriv, TEST_MAGIC, NULL, NULL);
            ASSERT(r != NULL);

            uint8_t junk[HS_MSG1_LEN];
            memset(junk, 0, sizeof(junk));
            junk[0] = 0x01;      /* u=1: blacklisted low-order point, not magic */
            uint8_t *wire = NULL, *pt = NULL;
            size_t wire_len = 0, pt_len = 0;
            bool res = noise_transport_feed(r, junk, sizeof(junk), &wire, &wire_len,
                                         &pt, &pt_len);
            free(wire); free(pt);
            ASSERT(!res);
            ASSERT(r->state == NOISE_FAILED);
            noise_transport_free(r);
        }

        /* (5b) a tampered ciphertext record fails closed. */
        {
            struct noise_transport *i = NULL, *r = NULL;
            ASSERT(run_handshake(&i, &r));

            uint8_t msg[80];
            for (int k = 0; k < 80; k++) msg[k] = (uint8_t)(k ^ 0x5a);
            uint8_t *ct = NULL; size_t ct_len = 0;
            ASSERT(noise_transport_write(i, msg, sizeof(msg), &ct, &ct_len));
            ASSERT(ct_len > 3);
            ct[ct_len - 1] ^= 0xff;      /* flip a ciphertext byte */
            uint8_t *wire = NULL, *pt = NULL;
            size_t wire_len = 0, pt_len = 0;
            bool res = noise_transport_feed(r, ct, ct_len, &wire, &wire_len,
                                         &pt, &pt_len);
            free(ct); free(wire); free(pt);
            ASSERT(!res);
            ASSERT(r->state == NOISE_FAILED);
            noise_transport_free(i);
            noise_transport_free(r);
        }

        /* (5c) an oversize frame-length prefix fails closed before decrypt. */
        {
            struct noise_transport *i = NULL, *r = NULL;
            ASSERT(run_handshake(&i, &r));

            uint8_t hdr[3];
            size_t huge = SESSION_FRAME_MAX_WIRE;   /* 3 + huge > MAX_WIRE */
            hdr[0] = (uint8_t)(huge & 0xff);
            hdr[1] = (uint8_t)((huge >> 8) & 0xff);
            hdr[2] = (uint8_t)((huge >> 16) & 0xff);
            uint8_t *wire = NULL, *pt = NULL;
            size_t wire_len = 0, pt_len = 0;
            bool res = noise_transport_feed(r, hdr, sizeof(hdr), &wire, &wire_len,
                                         &pt, &pt_len);
            free(wire); free(pt);
            ASSERT(!res);
            ASSERT(r->state == NOISE_FAILED);
            noise_transport_free(i);
            noise_transport_free(r);
        }

        /* (6) plaintext-magic classifier predicate. */
        {
            ASSERT(noise_transport_is_plaintext_magic(TEST_MAGIC, 4, TEST_MAGIC));
            uint8_t other[4] = { 0, 1, 2, 3 };
            ASSERT(!noise_transport_is_plaintext_magic(other, 4, TEST_MAGIC));
            ASSERT(!noise_transport_is_plaintext_magic(TEST_MAGIC, 3, TEST_MAGIC));
        }

        /* (7) the shared persistent key loader creates atomically, reloads
         * exactly, and refuses an over-permissive existing key. */
        {
            char dir[] = "/tmp/zcl_v2_identity_XXXXXX";
            ASSERT(mkdtemp(dir) != NULL);
            uint8_t priv1[32], pub1[32], priv2[32], pub2[32];
            char err[160];
            ASSERT(v2_identity_load_or_create(dir, priv1, pub1, err,
                                               sizeof(err)));
            ASSERT(v2_identity_load_or_create(dir, priv2, pub2, err,
                                               sizeof(err)));
            ASSERT(memcmp(priv1, priv2, 32) == 0);
            ASSERT(memcmp(pub1, pub2, 32) == 0);
            uint8_t fingerprint1[32], fingerprint2[32], zero[32] = {0};
            ASSERT(v2_identity_public_fingerprint(pub1, fingerprint1));
            ASSERT(v2_identity_public_fingerprint(pub2, fingerprint2));
            ASSERT(memcmp(fingerprint1, fingerprint2, 32) == 0);
            pub2[0] ^= 1;
            ASSERT(v2_identity_public_fingerprint(pub2, fingerprint2));
            ASSERT(memcmp(fingerprint1, fingerprint2, 32) != 0);
            ASSERT(!v2_identity_public_fingerprint(zero, fingerprint2));
            ASSERT(!v2_identity_public_fingerprint(NULL, fingerprint2));
            uint8_t kat_public[32];
            for (size_t i = 0; i < sizeof(kat_public); i++)
                kat_public[i] = (uint8_t)i;
            ASSERT(v2_identity_public_fingerprint(kat_public, fingerprint2));
            char fingerprint_hex[65];
            zcl_hex_encode(fingerprint2, sizeof(fingerprint2),
                           fingerprint_hex);
            ASSERT(strcmp(fingerprint_hex,
                          "69fb527161c541eeceeb9809b9ce40d7"
                          "610cba4a65655bbd3c56bebb5786f34e") == 0);
            char path[256];
            snprintf(path, sizeof(path), "%s/v2_identity.key", dir);
            struct stat st;
            ASSERT(stat(path, &st) == 0);
            ASSERT((st.st_mode & 0777) == 0600);
            ASSERT(chmod(path, 0644) == 0);
            ASSERT(!v2_identity_load_or_create(dir, priv2, pub2, err,
                                                sizeof(err)));
            ASSERT(unlink(path) == 0);
            ASSERT(rmdir(dir) == 0);
        }

        /* (6) chunked feeds, corrupted KEM ciphertext, classical-suite peers,
         * small thread stack. */
        ASSERT(chunked_handshake(1));
        ASSERT(chunked_handshake(7));
        ASSERT(chunked_handshake(500));
        {
            uint8_t ipriv[32], rpriv[32];
            mk_id(ipriv, 0x11);
            mk_id(rpriv, 0x77);
            uint8_t *msg1 = NULL, *w2 = NULL, *w3 = NULL, *p = NULL;
            size_t msg1_len = 0, w2l = 0, w3l = 0, pl = 0;
            struct noise_transport *i =
                noise_transport_begin(true, ipriv, TEST_MAGIC, &msg1, &msg1_len);
            struct noise_transport *r =
                noise_transport_begin(false, rpriv, TEST_MAGIC, NULL, NULL);
            ASSERT(i && r && msg1);
            ASSERT(noise_transport_feed(r, msg1, msg1_len, &w2, &w2l, &p, &pl));
            ASSERT(w2l == HS_MSG2_LEN);
            w2[32 + 100] ^= 0x01;        /* inside the sealed KEM ciphertext */
            ASSERT(!noise_transport_feed(i, w2, w2l, &w3, &w3l, &p, &pl));
            ASSERT(i->state == NOISE_FAILED);
            ASSERT(!i->have_peer_static);
            free(msg1); free(w2); free(w3); free(p);
            noise_transport_free(i);
            noise_transport_free(r);
        }
        ASSERT(refuses_old_prologue_peer());
        ASSERT(stalls_on_classical_xx_peer());
        ASSERT(handshake_fits_small_stack());

        /* Handshake deadline. */
        uint8_t ipriv[32], rpriv[32];
        mk_id(ipriv, 0x11);
        mk_id(rpriv, 0x77);

        /* (a) responder: nothing received, then a partial first message. */
        {
            struct noise_transport *r =
                noise_transport_begin(false, rpriv, TEST_MAGIC, NULL, NULL);
            ASSERT(r != NULL);
            const int64_t deadline = r->hs_started_us + NOISE_HANDSHAKE_TIMEOUT_US;
            ASSERT(!noise_transport_handshake_expired(r, deadline - 1));
            ASSERT(noise_transport_handshake_expired(r, deadline));
            uint8_t part[8] = { 0x99, 1, 2, 3, 4, 5, 6, 7 };
            uint8_t *wire = NULL, *pt = NULL;
            size_t wire_len = 0, pt_len = 0;
            ASSERT(noise_transport_feed(r, part, sizeof(part), &wire, &wire_len,
                                        &pt, &pt_len));
            free(wire); free(pt);
            ASSERT(!noise_transport_handshake_expired(r, deadline - 1));
            ASSERT(noise_transport_handshake_expired(r, deadline));
            noise_transport_free(r);
        }

        /* (b) initiator: msg1 sent, no reply. */
        {
            uint8_t *msg1 = NULL;
            size_t msg1_len = 0;
            struct noise_transport *i =
                noise_transport_begin(true, ipriv, TEST_MAGIC, &msg1, &msg1_len);
            ASSERT(i != NULL);
            free(msg1);
            const int64_t deadline = i->hs_started_us + NOISE_HANDSHAKE_TIMEOUT_US;
            ASSERT(!noise_transport_handshake_expired(i, deadline - 1));
            ASSERT(noise_transport_handshake_expired(i, deadline));
            noise_transport_free(i);
        }

        /* (c) established transports never expire. */
        {
            struct noise_transport *i = NULL, *r = NULL;
            ASSERT(run_handshake(&i, &r));
            ASSERT(!noise_transport_handshake_expired(i, INT64_MAX));
            ASSERT(!noise_transport_handshake_expired(r, INT64_MAX));
            noise_transport_free(i);
            noise_transport_free(r);
        }

        /* (d) NULL transport. */
        ASSERT(!noise_transport_handshake_expired(NULL, INT64_MAX));

        /* (e) clock earlier than the handshake start. */
        {
            struct noise_transport *r =
                noise_transport_begin(false, rpriv, TEST_MAGIC, NULL, NULL);
            ASSERT(r != NULL);
            ASSERT(!noise_transport_handshake_expired(r, r->hs_started_us - 1));
            ASSERT(!noise_transport_handshake_expired(r, INT64_MIN));
            noise_transport_free(r);
        }
    } TEST_END

    return failures;
}
