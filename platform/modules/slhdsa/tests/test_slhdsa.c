/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

/* SLH-DSA tests: NIST ACVP known-answer vectors (key generation, signature
 * generation, signature verification), round trips, single-bit-flip rejection
 * for the signature, message, context and public key, input validation and a
 * printed (never asserted) timing line. */

#define _POSIX_C_SOURCE 200809L

#include "slhdsa/slhdsa.h"
#include "slhdsa/slhdsa_kat.h"
#include "base/hex.h"
#include "../src/slhdsa_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "slhdsa test failed: %s:%d: %s\n", __FILE__, __LINE__, #expr); \
    return 1; \
} } while (0)

enum {
    SLHT_MAX_TOKENS = 16,
    SLHT_MAX_MSG = 8192 + 16,
    SLHT_MAX_SIG = ZCL_SLHDSA_MAX_SIGNATURE_SIZE + 8
};

#include "slhdsa_vectors.h"

/* Per record kind and parameter set: how many vectors passed. */
static unsigned passes[3][2];
static const char *const kind_name[3] = {"keygen", "sign", "verify"};
static const char *const param_name[2] = {"128s", "192s"};

static char *vector_text;

static int load_vectors(void)
{
    size_t total = 1;
    size_t used = 0;
    for (size_t i = 0; i < sizeof(slhdsa_vector_pieces) / sizeof(slhdsa_vector_pieces[0]); i++)
        total += strlen(slhdsa_vector_pieces[i]);
    vector_text = malloc(total);
    CHECK(vector_text != nullptr);
    for (size_t i = 0; i < sizeof(slhdsa_vector_pieces) / sizeof(slhdsa_vector_pieces[0]); i++) {
        const size_t n = strlen(slhdsa_vector_pieces[i]);
        memcpy(vector_text + used, slhdsa_vector_pieces[i], n);
        used += n;
    }
    vector_text[used] = '\0';
    return 0;
}

static bool decode_field(const char *tok, uint8_t *out, size_t cap, size_t *len)
{
    if (strcmp(tok, "-") == 0) {
        *len = 0;
        return true;
    }
    return zcl_hex_decode_n(tok, out, cap, len);
}

static int param_from_token(const char *tok, enum zcl_slhdsa_param *param, int *idx)
{
    if (strcmp(tok, "128s") == 0) {
        *param = ZCL_SLHDSA_SHAKE_128S;
        *idx = 0;
    } else if (strcmp(tok, "192s") == 0) {
        *param = ZCL_SLHDSA_SHAKE_192S;
        *idx = 1;
    } else {
        return 1;
    }
    return 0;
}

static uint8_t fixed_random[ZCL_SLHDSA_MAX_RANDOM_SIZE];

static bool fixed_random_fn(void *context, uint8_t *out, size_t len)
{
    (void)context;
    memcpy(out, fixed_random, len);
    return true;
}

static bool failing_random_fn(void *context, uint8_t *out, size_t len)
{
    (void)context;
    (void)out;
    (void)len;
    return false;
}

static uint64_t prng_state;

static bool prng_fn(void *context, uint8_t *out, size_t len)
{
    (void)context;
    for (size_t i = 0; i < len; i++) {
        uint64_t z = (prng_state += UINT64_C(0x9e3779b97f4a7c15));
        z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
        out[i] = (uint8_t)((z ^ (z >> 31)) >> 24);
    }
    return true;
}

static uint8_t b_seed[3 * 24], b_sk[96], b_pk[48], b_got_sk[96], b_got_pk[48];

static int run_keygen(char **t, int ntok)
{
    enum zcl_slhdsa_param param;
    int pi;
    size_t l[5];
    CHECK(ntok == 8 && param_from_token(t[1], &param, &pi) == 0);
    CHECK(decode_field(t[3], b_seed, 24, &l[0]));
    CHECK(decode_field(t[4], b_seed + l[0], 24, &l[1]));
    CHECK(decode_field(t[5], b_seed + l[0] + l[1], 24, &l[2]));
    CHECK(decode_field(t[6], b_sk, sizeof(b_sk), &l[3]));
    CHECK(decode_field(t[7], b_pk, sizeof(b_pk), &l[4]));
    CHECK(zcl_slhdsa_keygen_internal(param, b_seed, l[0] + l[1] + l[2], b_got_pk,
                                     l[4], b_got_sk, l[3]) == ZCL_SLHDSA_OK);
    if (memcmp(b_got_sk, b_sk, l[3]) != 0 || memcmp(b_got_pk, b_pk, l[4]) != 0) {
        fprintf(stderr, "slhdsa keygen mismatch %s tc %s\n", t[1], t[2]);
        return 1;
    }
    passes[0][pi]++;
    return 0;
}

static uint8_t v_sk[96], v_pk[48], v_rand[24], v_ctx[256], v_msg[SLHT_MAX_MSG],
    v_sig[SLHT_MAX_SIG], v_got[SLHT_MAX_SIG];

struct vec_lens {
    size_t sk, pk, rnd, ctx, msg, sig;
};

static int sign_vector(enum zcl_slhdsa_param param, bool internal, bool det,
                       const struct vec_lens *l)
{
    if (internal)
        return zcl_slhdsa_sign_internal(param, v_sk, l->sk, v_msg, l->msg,
                                        det ? nullptr : v_rand,
                                        det ? 0 : l->rnd, v_got, l->sig) !=
               ZCL_SLHDSA_OK;
    if (det)
        return zcl_slhdsa_sign_deterministic(param, v_sk, l->sk, v_msg, l->msg,
                                             v_ctx, l->ctx, v_got, l->sig) !=
               ZCL_SLHDSA_OK;
    memcpy(fixed_random, v_rand, l->rnd);
    return zcl_slhdsa_sign(param, v_sk, l->sk, v_msg, l->msg, v_ctx, l->ctx,
                           fixed_random_fn, nullptr, v_got, l->sig) !=
           ZCL_SLHDSA_OK;
}

static int run_sign(char **t, int ntok)
{
    enum zcl_slhdsa_param param;
    int pi;
    struct vec_lens l;
    CHECK(ntok == 10 && param_from_token(t[1], &param, &pi) == 0);
    const bool internal = strcmp(t[3], "internal") == 0;
    const bool det = strcmp(t[4], "det") == 0;
    CHECK(decode_field(t[5], v_sk, sizeof(v_sk), &l.sk));
    CHECK(decode_field(t[6], v_rand, sizeof(v_rand), &l.rnd));
    CHECK(decode_field(t[7], v_ctx, sizeof(v_ctx), &l.ctx));
    CHECK(decode_field(t[8], v_msg, sizeof(v_msg), &l.msg));
    CHECK(decode_field(t[9], v_sig, sizeof(v_sig), &l.sig));
    CHECK(sign_vector(param, internal, det, &l) == 0);
    if (memcmp(v_got, v_sig, l.sig) != 0) {
        fprintf(stderr, "slhdsa sign mismatch %s tc %s (%s %s)\n", t[1], t[2], t[3], t[4]);
        return 1;
    }
    passes[1][pi]++;
    return 0;
}

static int run_verify(char **t, int ntok)
{
    enum zcl_slhdsa_param param;
    int pi;
    struct vec_lens l;
    CHECK(ntok == 9 && param_from_token(t[1], &param, &pi) == 0);
    const bool internal = strcmp(t[3], "internal") == 0;
    const bool want = strcmp(t[4], "1") == 0;
    CHECK(decode_field(t[5], v_pk, sizeof(v_pk), &l.pk));
    CHECK(decode_field(t[6], v_ctx, sizeof(v_ctx), &l.ctx));
    CHECK(decode_field(t[7], v_msg, sizeof(v_msg), &l.msg));
    CHECK(decode_field(t[8], v_sig, sizeof(v_sig), &l.sig));
    const enum zcl_slhdsa_status st =
        internal ? zcl_slhdsa_verify_internal(param, v_pk, l.pk, v_msg, l.msg, v_sig, l.sig)
                 : zcl_slhdsa_verify(param, v_pk, l.pk, v_msg, l.msg, v_ctx, l.ctx, v_sig, l.sig);
    const bool ok = st == ZCL_SLHDSA_OK;
    if (ok != want) {
        fprintf(stderr, "slhdsa verify mismatch %s tc %s: want %d status %d\n",
                t[1], t[2], want, (int)st);
        return 1;
    }
    if (!ok) {
        const enum zcl_slhdsa_status expect =
            l.sig == zcl_slhdsa_signature_size(param) ? ZCL_SLHDSA_ERR_VERIFY
                                                      : ZCL_SLHDSA_ERR_LENGTH;
        CHECK(st == expect);
    }
    passes[2][pi]++;
    return 0;
}

static int run_line(char *line)
{
    char *tok[SLHT_MAX_TOKENS];
    int ntok = 0;
    for (char *p = line; *p && ntok < SLHT_MAX_TOKENS;) {
        tok[ntok++] = p;
        while (*p && *p != ' ')
            p++;
        if (*p == ' ')
            *p++ = '\0';
    }
    if (strcmp(tok[0], "keygen") == 0)
        return run_keygen(tok, ntok);
    if (strcmp(tok[0], "sign") == 0)
        return run_sign(tok, ntok);
    if (strcmp(tok[0], "verify") == 0)
        return run_verify(tok, ntok);
    return 1;
}

static int check_vectors(void)
{
    char *line = vector_text;
    unsigned records = 0;
    if (load_vectors())
        return 1;
    line = vector_text;
    while (*line) {
        char *eol = strchr(line, '\n');
        CHECK(eol != nullptr);
        *eol = '\0';
        if (*line != '#' && *line != '\0') {
            if (run_line(line))
                return 1;
            records++;
        }
        line = eol + 1;
    }
    for (int k = 0; k < 3; k++)
        for (int p = 0; p < 2; p++) {
            CHECK(passes[k][p] != 0);
            printf("acvp %-6s SHAKE-%s: %u vectors passed\n", kind_name[k],
                   param_name[p], passes[k][p]);
        }
    CHECK(records == passes[0][0] + passes[0][1] + passes[1][0] + passes[1][1] +
                         passes[2][0] + passes[2][1]);
    free(vector_text);
    return 0;
}

/* Round trips, bit flips, validation --------------------------------- */

static uint8_t g_pk[48], g_sk[96], g_sig[SLHT_MAX_SIG], g_bad[SLHT_MAX_SIG];

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e3 + (double)ts.tv_nsec / 1e6;
}

static int flip_signature(enum zcl_slhdsa_param param, const uint8_t *msg,
                          size_t msg_len, const uint8_t *ctx, size_t ctx_len)
{
    const size_t sl = zcl_slhdsa_signature_size(param);
    const size_t pl = zcl_slhdsa_public_key_size(param);
    /* Every bit of R, a stride across FORS and hypertree, and the last bytes. */
    for (size_t pos = 0; pos < sl; pos += (pos < 32 ? 1 : 97)) {
        memcpy(g_bad, g_sig, sl);
        g_bad[pos] ^= (uint8_t)(1u << (pos % 8));
        CHECK(zcl_slhdsa_verify(param, g_pk, pl, msg, msg_len, ctx, ctx_len,
                                g_bad, sl) == ZCL_SLHDSA_ERR_VERIFY);
    }
    memcpy(g_bad, g_sig, sl);
    g_bad[sl - 1] ^= 0x80;
    CHECK(zcl_slhdsa_verify(param, g_pk, pl, msg, msg_len, ctx, ctx_len, g_bad,
                            sl) == ZCL_SLHDSA_ERR_VERIFY);
    return 0;
}

static int flip_inputs(enum zcl_slhdsa_param param, uint8_t *msg, size_t msg_len,
                       uint8_t *ctx, size_t ctx_len)
{
    const size_t sl = zcl_slhdsa_signature_size(param);
    const size_t pl = zcl_slhdsa_public_key_size(param);
    for (size_t i = 0; i < msg_len * 8; i++) {
        msg[i / 8] ^= (uint8_t)(1u << (i % 8));
        CHECK(zcl_slhdsa_verify(param, g_pk, pl, msg, msg_len, ctx, ctx_len,
                                g_sig, sl) == ZCL_SLHDSA_ERR_VERIFY);
        msg[i / 8] ^= (uint8_t)(1u << (i % 8));
    }
    for (size_t i = 0; i < ctx_len * 8; i++) {
        ctx[i / 8] ^= (uint8_t)(1u << (i % 8));
        CHECK(zcl_slhdsa_verify(param, g_pk, pl, msg, msg_len, ctx, ctx_len,
                                g_sig, sl) == ZCL_SLHDSA_ERR_VERIFY);
        ctx[i / 8] ^= (uint8_t)(1u << (i % 8));
    }
    for (size_t i = 0; i < pl * 8; i++) {
        g_pk[i / 8] ^= (uint8_t)(1u << (i % 8));
        CHECK(zcl_slhdsa_verify(param, g_pk, pl, msg, msg_len, ctx, ctx_len,
                                g_sig, sl) == ZCL_SLHDSA_ERR_VERIFY);
        g_pk[i / 8] ^= (uint8_t)(1u << (i % 8));
    }
    /* A context shifted between ctx and msg must not verify either. */
    CHECK(zcl_slhdsa_verify(param, g_pk, pl, msg, msg_len, nullptr, 0, g_sig,
                            sl) == ZCL_SLHDSA_ERR_VERIFY);
    return 0;
}

static int check_validation(enum zcl_slhdsa_param param, const uint8_t *msg)
{
    const size_t sl = zcl_slhdsa_signature_size(param);
    const size_t pl = zcl_slhdsa_public_key_size(param);
    const size_t kl = zcl_slhdsa_secret_key_size(param);
    uint8_t ctx256[256] = {0};
    CHECK(zcl_slhdsa_verify(param, g_pk, pl - 1, msg, 4, nullptr, 0, g_sig, sl) == ZCL_SLHDSA_ERR_LENGTH);
    CHECK(zcl_slhdsa_verify(param, g_pk, pl, msg, 4, nullptr, 0, g_sig, sl - 1) == ZCL_SLHDSA_ERR_LENGTH);
    CHECK(zcl_slhdsa_verify(param, g_pk, pl, msg, 4, nullptr, 0, g_sig, sl + 1) == ZCL_SLHDSA_ERR_LENGTH);
    CHECK(zcl_slhdsa_verify(param, g_pk, pl, msg, 4, nullptr, 0, g_sig, 0) == ZCL_SLHDSA_ERR_LENGTH);
    CHECK(zcl_slhdsa_verify(param, g_pk, pl, msg, 4, ctx256, 256, g_sig, sl) == ZCL_SLHDSA_ERR_CONTEXT);
    CHECK(zcl_slhdsa_verify(param, nullptr, pl, msg, 4, nullptr, 0, g_sig, sl) == ZCL_SLHDSA_ERR_ARGUMENT);
    CHECK(zcl_slhdsa_verify(param, g_pk, pl, msg, 4, nullptr, 0, nullptr, sl) == ZCL_SLHDSA_ERR_ARGUMENT);
    CHECK(zcl_slhdsa_verify(param, g_pk, pl, nullptr, 4, nullptr, 0, g_sig, sl) == ZCL_SLHDSA_ERR_ARGUMENT);
    CHECK(zcl_slhdsa_verify(param, g_pk, pl, msg, 4, nullptr, 3, g_sig, sl) == ZCL_SLHDSA_ERR_ARGUMENT);
    CHECK(zcl_slhdsa_verify((enum zcl_slhdsa_param)9, g_pk, pl, msg, 4, nullptr, 0, g_sig, sl) == ZCL_SLHDSA_ERR_ARGUMENT);
    memset(g_bad, 0xA5, sl);
    CHECK(zcl_slhdsa_sign_deterministic(param, g_sk, kl, msg, 4, ctx256, 256, g_bad, sl) == ZCL_SLHDSA_ERR_CONTEXT);
    CHECK(g_bad[0] == 0 && g_bad[sl - 1] == 0);
    memset(g_bad, 0xA5, sl);
    CHECK(zcl_slhdsa_sign_deterministic(param, g_sk, kl - 1, msg, 4, nullptr, 0, g_bad, sl) == ZCL_SLHDSA_ERR_LENGTH);
    CHECK(g_bad[0] == 0 && g_bad[sl - 1] == 0);
    memset(g_bad, 0xA5, sl);
    CHECK(zcl_slhdsa_sign_deterministic(param, g_sk, kl, msg, 4, nullptr, 0, g_bad, sl - 1) == ZCL_SLHDSA_ERR_LENGTH);
    CHECK(zcl_slhdsa_sign_deterministic(param, nullptr, kl, msg, 4, nullptr, 0, g_bad, sl) == ZCL_SLHDSA_ERR_ARGUMENT);
    memset(g_bad, 0xA5, sl);
    CHECK(zcl_slhdsa_sign(param, g_sk, kl, msg, 4, nullptr, 0, failing_random_fn, nullptr, g_bad, sl) == ZCL_SLHDSA_ERR_RANDOM);
    CHECK(g_bad[0] == 0 && g_bad[sl - 1] == 0);
    CHECK(zcl_slhdsa_sign(param, g_sk, kl, msg, 4, nullptr, 0, nullptr, nullptr, g_bad, sl) == ZCL_SLHDSA_ERR_ARGUMENT);
    memset(g_bad, 0xA5, 144);
    CHECK(zcl_slhdsa_keygen(param, failing_random_fn, nullptr, g_bad, pl, g_bad + 48, kl) == ZCL_SLHDSA_ERR_RANDOM);
    CHECK(g_bad[0] == 0 && g_bad[48] == 0);
    CHECK(zcl_slhdsa_keygen(param, prng_fn, nullptr, g_bad, pl - 1, g_bad + 48, kl) == ZCL_SLHDSA_ERR_LENGTH);
    CHECK(zcl_slhdsa_keygen_internal(param, g_sk, 5, g_bad, pl, g_bad + 48, kl) == ZCL_SLHDSA_ERR_LENGTH);
    CHECK(zcl_slhdsa_sign_internal(param, g_sk, kl, msg, 4, g_pk, 1, g_bad, sl) == ZCL_SLHDSA_ERR_LENGTH);
    return 0;
}

static int check_param(enum zcl_slhdsa_param param)
{
    static uint8_t msg[40], ctx[20], sig2[SLHT_MAX_SIG];
    const size_t sl = zcl_slhdsa_signature_size(param);
    const size_t pl = zcl_slhdsa_public_key_size(param);
    const size_t kl = zcl_slhdsa_secret_key_size(param);
    CHECK(sl != 0 && pl * 2 == kl);
    CHECK(prng_fn(nullptr, msg, sizeof(msg)) && prng_fn(nullptr, ctx, sizeof(ctx)));
    CHECK(zcl_slhdsa_keygen(param, prng_fn, nullptr, g_pk, pl, g_sk, kl) == ZCL_SLHDSA_OK);
    double t0 = now_ms();
    CHECK(zcl_slhdsa_sign_deterministic(param, g_sk, kl, msg, sizeof(msg), ctx, sizeof(ctx), g_sig, sl) == ZCL_SLHDSA_OK);
    const double sign_ms = now_ms() - t0;
    t0 = now_ms();
    CHECK(zcl_slhdsa_verify(param, g_pk, pl, msg, sizeof(msg), ctx, sizeof(ctx), g_sig, sl) == ZCL_SLHDSA_OK);
    printf("timing SHAKE-%s: sign %.1f ms, verify %.2f ms (printed, not asserted)\n",
           param == ZCL_SLHDSA_SHAKE_128S ? "128s" : "192s", sign_ms, now_ms() - t0);
    /* Deterministic signing repeats; hedged signing differs and verifies. */
    CHECK(zcl_slhdsa_sign_deterministic(param, g_sk, kl, msg, sizeof(msg), ctx, sizeof(ctx), sig2, sl) == ZCL_SLHDSA_OK);
    CHECK(memcmp(sig2, g_sig, sl) == 0);
    CHECK(zcl_slhdsa_sign(param, g_sk, kl, msg, sizeof(msg), ctx, sizeof(ctx), prng_fn, nullptr, sig2, sl) == ZCL_SLHDSA_OK);
    CHECK(memcmp(sig2, g_sig, sl) != 0);
    CHECK(zcl_slhdsa_verify(param, g_pk, pl, msg, sizeof(msg), ctx, sizeof(ctx), sig2, sl) == ZCL_SLHDSA_OK);
    /* Empty message and a maximal 255-byte context round trip. */
    uint8_t big[255];
    CHECK(prng_fn(nullptr, big, sizeof(big)));
    CHECK(zcl_slhdsa_sign_deterministic(param, g_sk, kl, nullptr, 0, big, sizeof(big), sig2, sl) == ZCL_SLHDSA_OK);
    CHECK(zcl_slhdsa_verify(param, g_pk, pl, nullptr, 0, big, sizeof(big), sig2, sl) == ZCL_SLHDSA_OK);
    CHECK(zcl_slhdsa_verify(param, g_pk, pl, nullptr, 0, big, sizeof(big) - 1, sig2, sl) == ZCL_SLHDSA_ERR_VERIFY);
    if (flip_signature(param, msg, sizeof(msg), ctx, sizeof(ctx)) ||
        flip_inputs(param, msg, sizeof(msg), ctx, sizeof(ctx)) ||
        check_validation(param, msg))
        return 1;
    return 0;
}

int main(void)
{
    prng_state = 7;
    if (check_vectors() || check_param(ZCL_SLHDSA_SHAKE_128S) ||
        check_param(ZCL_SLHDSA_SHAKE_192S))
        return 1;
    printf("slhdsa test passed\n");
    return 0;
}
