/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * secp256k1 DIFFERENTIAL ORACLE — the gate a candidate ECDSA implementation
 * must clear before it may be promoted onto the consensus path.
 *
 * WHY THIS EXISTS: secp256k1 signature verification decides transaction
 * validity. A candidate implementation that disagrees with the incumbent on
 * ONE adversarial encoding forks the chain silently — the node accepts (or
 * rejects) a block every other node rejects (or accepts), and nothing in the
 * test suite notices, because the happy path still passes. Parity bugs do not
 * live in "valid signature verifies"; they live in high-S, in r/s at the group
 * order, in non-canonical DER, in the point at infinity, and in length guards.
 *
 * THREE INDEPENDENT LAYERS, weakest to strongest:
 *
 *  L1 DIFFERENTIAL — the CANDIDATE (whatever the crypto registry currently
 *     serves for CRYPTO_SIG_ECDSA_SECP256K1, plus the contexts/wallet/modules/keys entry points
 *     the node actually calls) is run side by side with a REFERENCE built
 *     directly on the vendored libsecp256k1 archive, over every corpus vector.
 *     Any verdict or output-byte disagreement fails. Today both sides bottom
 *     out in the same archive, so L1 is near-tautological — it becomes the
 *     load-bearing layer the moment an in-house implementation is registered,
 *     which is exactly when it is needed. See CAVEATS at the end of the file.
 *
 *  L2 GOLDEN TRANSCRIPT — one SHA3-256 over (vector name, candidate verdict,
 *     candidate output bytes) for the whole corpus, compared to a frozen
 *     digest. This has teeth TODAY: it catches candidate and reference moving
 *     TOGETHER, i.e. a vendored-archive swap or a shared-wrapper edit, which
 *     L1 cannot see by construction.
 *
 *  L3 EXTERNAL GROUND TRUTH — published curve constants (the base point G,
 *     the group order n) and an algebraic identity (scalar-multiplication is
 *     a group homomorphism, checked through pubkey tweak-add) that no single
 *     implementation's own output can satisfy by accident. Non-tautological
 *     regardless of who implements the curve.
 *
 * BOUNDARY: this file changes NOTHING about what the node accepts. It only
 * observes and pins current behaviour. Where the wrapper is deliberately more
 * permissive than a naive reading (it low-S-NORMALISES before verifying, so a
 * malleated high-S encoding still verifies true — BIP62 low-S is enforced at
 * the script layer via SCRIPT_VERIFY_LOW_S, not here), the vector documents
 * that as the CURRENT contract. Tightening it is a consensus change and needs
 * a full-history replay first (CONSENSUS_PARITY_DOCTRINE.md). The same rule
 * that made the non-canonical BLS12-381 infinity encoding an ACCEPTED fact
 * (docs/AGENT_TRAPS.md) applies here: a documented permissive verdict is a
 * pinned fact, not a bug to fix in place.
 *
 * RE-RECORDING THE GOLDEN: never to make a red run green. Only after an
 * INTENTIONAL, replay-approved change. Run with ZCL_SECP_GOLDEN_RECORD=1 to
 * print the digest the current tree produces; paste it below with the reason.
 *
 * SEED EXPORT: ZCL_SECP_DUMP_SEEDS=<dir> writes every vector in the fuzzer's
 * wire form, so tools/fuzz/fuzz_ecdsa.c starts from the adversarial corpus
 * instead of from noise.
 */

#include "test/test_core.h"
#include "test/secp256k1_corpus.h"
#include "crypto_registry/crypto_registry.h"
#include "crypto/sha3.h"
#include "keys/key.h"
#include "keys/pubkey.h"

#include <secp256k1.h>
#include <secp256k1_recovery.h>

/* ── frozen golden ────────────────────────────────────────────────────────
 * SHA3-256 of the L2 transcript. Re-derived 2026-07-31 by running this oracle
 * against the vendored libsecp256k1 archive + the in-tree wrapper stack on
 * main, NOT carried across from where it was first recorded — a golden copied
 * from another tree pins that tree, not this one. It came out byte-identical
 * to the 2026-07-28 recording, which is itself the finding: nothing in the
 * ECDSA wrapper stack has moved since. Changing this line is a
 * consensus-visible act. */
static const char SECP_GOLDEN_SHA3[] =
    "6763a5f7521136880f4b718d3fe61ffbfb648292d7b04d2083d0b0034b684e12";

/* ── the REFERENCE (incumbent) ────────────────────────────────────────────
 * Written from the CONTRACT documented on crypto_sig_verify_fn in
 * crypto_registry/crypto_registry.h, straight onto the vendored archive —
 * not copied from the wrapper's body. It owns its own context so it cannot
 * be perturbed by the candidate's process-wide singletons. */
static secp256k1_context *g_ref_ctx;

static bool ref_ecdsa_verify(const uint8_t *pub, size_t publen,
                             const uint8_t *msg, size_t msglen,
                             const uint8_t *sig, size_t siglen)
{
    if (!pub || !msg || !sig)
        return false;
    if (msglen != 32 || publen == 0 || publen > PUBLIC_KEY_SIZE || siglen == 0)
        return false;
    secp256k1_pubkey p;
    secp256k1_ecdsa_signature s;
    if (!secp256k1_ec_pubkey_parse(g_ref_ctx, &p, pub, publen))
        return false;
    if (!secp256k1_ecdsa_signature_parse_der(g_ref_ctx, &s, sig, siglen))
        return false;
    secp256k1_ecdsa_signature_normalize(g_ref_ctx, &s, &s);
    return secp256k1_ecdsa_verify(g_ref_ctx, &s, msg, &p);
}

static bool ref_is_low_s(const uint8_t *sig, size_t siglen)
{
    secp256k1_ecdsa_signature s;
    if (!secp256k1_ecdsa_signature_parse_der(g_ref_ctx, &s, sig, siglen))
        return false;
    return !secp256k1_ecdsa_signature_normalize(g_ref_ctx, NULL, &s);
}

static bool ref_pubkey_on_curve(const uint8_t *pub, size_t publen)
{
    secp256k1_pubkey p;
    if (publen == 0 || publen > PUBLIC_KEY_SIZE)
        return false;
    return secp256k1_ec_pubkey_parse(g_ref_ctx, &p, pub, publen) == 1;
}

/* ── the CANDIDATE (implementation under test) ────────────────────────────
 * Whatever the registry serves. Swapping in an in-house curve = registering a
 * different scheme fn; this indirection is the promotion seam. */
static crypto_sig_verify_fn candidate_verify_fn(void)
{
    const struct crypto_scheme *s =
        crypto_registry_lookup(CRYPTO_SIG_ECDSA_SECP256K1);
    return (s && s->kind == CRYPTO_KIND_SIG) ? s->fn.sig_verify : NULL;
}

/* ── transcript accumulator (L2) ──────────────────────────────────────── */
struct secp_transcript {
    struct sha3_256_ctx h;
};

static void tr_init(struct secp_transcript *t)
{
    sha3_256_init(&t->h);
}

static void tr_bytes(struct secp_transcript *t, const void *p, size_t n)
{
    uint8_t len8[8];
    for (int i = 0; i < 8; i++)
        len8[i] = (uint8_t)((uint64_t)n >> (8 * i));
    sha3_256_write(&t->h, len8, sizeof(len8));
    if (n)
        sha3_256_write(&t->h, (const unsigned char *)p, n);
}

static void tr_str(struct secp_transcript *t, const char *s)
{
    tr_bytes(t, s, strlen(s));
}

static void tr_bool(struct secp_transcript *t, bool b)
{
    unsigned char v = b ? 1 : 0;
    sha3_256_write(&t->h, &v, 1);
}

/* ── corpus construction ─────────────────────────────────────────────────
 * Every adversarial shape is a MUTATION of a real signature produced by the
 * production signer over a fixed key, so "valid" is genuinely valid. */

struct secp_base {
    struct privkey  key;
    struct pubkey   pub_c;              /* compressed  */
    struct pubkey   pub_u;              /* uncompressed */
    struct uint256  msg;
    uint8_t         sig_der[SIGNATURE_SIZE];
    size_t          sig_len;
    uint8_t         r[32], s[32];       /* big-endian, low-S */
    uint8_t         s_high[32];         /* n - s */
    struct privkey  key2;
    struct pubkey   pub2_c;
    uint8_t         sig2_der[SIGNATURE_SIZE];
    size_t          sig2_len;
};

/* Deterministic private key material: the corpus must be byte-reproducible
 * across runs or the golden transcript is meaningless. */
static void fill_fixed_key(struct privkey *k, uint8_t tag)
{
    for (int i = 0; i < 32; i++)
        k->vch[i] = (uint8_t)(i * 7 + tag + 1);
    k->fValid = true;
    k->fCompressed = true;
}

static bool build_base(struct secp_base *b)
{
    memset(b, 0, sizeof(*b));
    fill_fixed_key(&b->key, 0x11);
    fill_fixed_key(&b->key2, 0x53);
    if (!privkey_range_check(&b->key) || !privkey_range_check(&b->key2))
        return false;
    if (!privkey_get_pubkey(&b->key, &b->pub_c))
        return false;
    b->pub_u = b->pub_c;
    if (!pubkey_decompress(&b->pub_u))
        return false;
    if (!privkey_get_pubkey(&b->key2, &b->pub2_c))
        return false;

    for (int i = 0; i < 32; i++)
        b->msg.data[i] = (uint8_t)(0xA0 ^ (i * 3));

    b->sig_len = sizeof(b->sig_der);
    if (!privkey_sign(&b->key, &b->msg, b->sig_der, &b->sig_len))
        return false;
    b->sig2_len = sizeof(b->sig2_der);
    if (!privkey_sign(&b->key2, &b->msg, b->sig2_der, &b->sig2_len))
        return false;

    /* Recover r/s as fixed-width big-endian through the reference parser. */
    secp256k1_ecdsa_signature parsed;
    if (!secp256k1_ecdsa_signature_parse_der(g_ref_ctx, &parsed,
                                             b->sig_der, b->sig_len))
        return false;
    uint8_t compact[64];
    secp256k1_ecdsa_signature_serialize_compact(g_ref_ctx, compact, &parsed);
    memcpy(b->r, compact, 32);
    memcpy(b->s, compact + 32, 32);
    secp_be256_sub(b->s_high, SECP_ORDER_N, b->s);
    return true;
}

/* Find the smallest x for which 0x02||x is NOT a curve point, by asking the
 * reference parser. Derived, not baked, so it stays true if the constant is
 * ever wrong. */
static bool find_off_curve_x(uint8_t out[32])
{
    uint8_t pub[33];
    pub[0] = 0x02;
    for (unsigned i = 1; i < 4096; i++) {
        memset(pub + 1, 0, 32);
        pub[31] = (uint8_t)(i >> 8);
        pub[32] = (uint8_t)(i & 0xFF);
        if (!ref_pubkey_on_curve(pub, sizeof(pub))) {
            memcpy(out, pub + 1, 32);
            return true;
        }
    }
    return false;
}

static void push_sig_case(struct secp_corpus *c, const struct secp_base *b,
                          const char *name, const uint8_t r[32],
                          const uint8_t s[32], bool pad_r, bool pad_s)
{
    struct secp_vector *v = secp_corpus_push(c, name);
    if (!v) return;
    memcpy(v->pub, b->pub_c.vch, b->pub_c.size);
    v->publen = b->pub_c.size;
    memcpy(v->msg, b->msg.data, 32);
    v->msglen = 32;
    v->siglen = secp_der_encode(v->sig, SECP_VEC_MAX_SIG, r, s, pad_r, pad_s);
}

static void push_pub_case(struct secp_corpus *c, const struct secp_base *b,
                          const char *name, const uint8_t *pub, size_t publen)
{
    struct secp_vector *v = secp_corpus_push(c, name);
    if (!v) return;
    if (publen > SECP_VEC_MAX_PUB) publen = SECP_VEC_MAX_PUB;
    memcpy(v->pub, pub, publen);
    v->publen = publen;
    memcpy(v->msg, b->msg.data, 32);
    v->msglen = 32;
    memcpy(v->sig, b->sig_der, b->sig_len);
    v->siglen = b->sig_len;
}

static void build_corpus(struct secp_corpus *c, const struct secp_base *b)
{
    memset(c, 0, sizeof(*c));
    const uint8_t zero32[32] = {0};
    uint8_t ff32[32];
    memset(ff32, 0xFF, 32);
    uint8_t n_minus_1[32], n_plus_1[32];
    secp_be256_sub(n_minus_1, SECP_ORDER_N, (const uint8_t[32]){
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1});
    secp_be256_add_u8(n_plus_1, SECP_ORDER_N, 1);

    /* ── baselines that MUST verify ─────────────────────────────────── */
    push_pub_case(c, b, "valid/compressed", b->pub_c.vch, b->pub_c.size);
    push_pub_case(c, b, "valid/uncompressed", b->pub_u.vch, b->pub_u.size);
    {   /* hybrid 0x06/0x07 encoding of the same point — libsecp256k1 accepts
         * it; a candidate that does not is a consensus divergence. */
        uint8_t hyb[65];
        memcpy(hyb, b->pub_u.vch, 65);
        hyb[0] = (uint8_t)(0x06 | (hyb[64] & 1));
        push_pub_case(c, b, "valid/hybrid-prefix", hyb, 65);
    }
    /* high-S (malleated) — CURRENT contract: the wrapper normalises, so this
     * still verifies TRUE. Pinned deliberately (see file header). */
    push_sig_case(c, b, "sig/high-S-normalised", b->r, b->s_high, false, false);

    /* ── signature scalar edges ─────────────────────────────────────── */
    push_sig_case(c, b, "sig/r-zero",        zero32,    b->s,      false, false);
    push_sig_case(c, b, "sig/s-zero",        b->r,      zero32,    false, false);
    push_sig_case(c, b, "sig/both-zero",     zero32,    zero32,    false, false);
    push_sig_case(c, b, "sig/r-eq-order",    SECP_ORDER_N, b->s,   false, false);
    push_sig_case(c, b, "sig/s-eq-order",    b->r, SECP_ORDER_N,   false, false);
    push_sig_case(c, b, "sig/r-order-minus1", n_minus_1, b->s,     false, false);
    push_sig_case(c, b, "sig/s-order-minus1", b->r, n_minus_1,     false, false);
    push_sig_case(c, b, "sig/r-order-plus1",  n_plus_1, b->s,      false, false);
    push_sig_case(c, b, "sig/s-order-plus1",  b->r, n_plus_1,      false, false);
    push_sig_case(c, b, "sig/r-all-ff",      ff32,      b->s,      false, false);
    push_sig_case(c, b, "sig/s-all-ff",      b->r,      ff32,      false, false);

    /* ── non-canonical DER ──────────────────────────────────────────── */
    push_sig_case(c, b, "der/noncanon-pad-r", b->r, b->s, true,  false);
    push_sig_case(c, b, "der/noncanon-pad-s", b->r, b->s, false, true);
    push_sig_case(c, b, "der/noncanon-pad-both", b->r, b->s, true, true);
    {
        struct secp_vector *v = secp_corpus_push(c, "der/truncated");
        if (v) {
            memcpy(v->pub, b->pub_c.vch, b->pub_c.size); v->publen = b->pub_c.size;
            memcpy(v->msg, b->msg.data, 32); v->msglen = 32;
            memcpy(v->sig, b->sig_der, b->sig_len - 1); v->siglen = b->sig_len - 1;
        }
        v = secp_corpus_push(c, "der/trailing-garbage");
        if (v) {
            memcpy(v->pub, b->pub_c.vch, b->pub_c.size); v->publen = b->pub_c.size;
            memcpy(v->msg, b->msg.data, 32); v->msglen = 32;
            memcpy(v->sig, b->sig_der, b->sig_len);
            v->sig[b->sig_len] = 0x00;
            v->siglen = b->sig_len + 1;
        }
        v = secp_corpus_push(c, "der/wrong-outer-tag");
        if (v) {
            memcpy(v->pub, b->pub_c.vch, b->pub_c.size); v->publen = b->pub_c.size;
            memcpy(v->msg, b->msg.data, 32); v->msglen = 32;
            memcpy(v->sig, b->sig_der, b->sig_len); v->sig[0] = 0x31;
            v->siglen = b->sig_len;
        }
        v = secp_corpus_push(c, "der/length-lies-long");
        if (v) {
            memcpy(v->pub, b->pub_c.vch, b->pub_c.size); v->publen = b->pub_c.size;
            memcpy(v->msg, b->msg.data, 32); v->msglen = 32;
            memcpy(v->sig, b->sig_der, b->sig_len); v->sig[1] = 0x7F;
            v->siglen = b->sig_len;
        }
        v = secp_corpus_push(c, "der/empty");
        if (v) {
            memcpy(v->pub, b->pub_c.vch, b->pub_c.size); v->publen = b->pub_c.size;
            memcpy(v->msg, b->msg.data, 32); v->msglen = 32;
            v->siglen = 0;
        }
        v = secp_corpus_push(c, "der/all-zero-70");
        if (v) {
            memcpy(v->pub, b->pub_c.vch, b->pub_c.size); v->publen = b->pub_c.size;
            memcpy(v->msg, b->msg.data, 32); v->msglen = 32;
            v->siglen = 70;
        }
    }

    /* ── public-key encodings ───────────────────────────────────────── */
    {
        uint8_t buf[SECP_VEC_MAX_PUB];
        memset(buf, 0, sizeof(buf));
        buf[0] = 0x02;
        push_pub_case(c, b, "pub/compressed-x-zero", buf, 33);
        buf[0] = 0x04;
        push_pub_case(c, b, "pub/uncompressed-all-zero", buf, 65);
        buf[0] = 0x00;
        push_pub_case(c, b, "pub/single-zero-byte", buf, 1);
        push_pub_case(c, b, "pub/empty", buf, 0);

        memset(buf, 0xFF, sizeof(buf));
        buf[0] = 0x02;
        push_pub_case(c, b, "pub/compressed-x-ge-p", buf, 33);

        uint8_t offx[32];
        if (find_off_curve_x(offx)) {
            memset(buf, 0, sizeof(buf));
            buf[0] = 0x02;
            memcpy(buf + 1, offx, 32);
            push_pub_case(c, b, "pub/compressed-not-on-curve", buf, 33);
        }

        memcpy(buf, b->pub_u.vch, 65);
        buf[64] ^= 0x01;                  /* y no longer satisfies the curve */
        push_pub_case(c, b, "pub/uncompressed-bad-y", buf, 65);

        memcpy(buf, b->pub_c.vch, 33);
        buf[0] = 0x01;
        push_pub_case(c, b, "pub/prefix-0x01", buf, 33);
        buf[0] = 0x05;
        push_pub_case(c, b, "pub/prefix-0x05", buf, 33);
        buf[0] = 0x04;
        push_pub_case(c, b, "pub/prefix-0x04-len33", buf, 33);

        push_pub_case(c, b, "pub/truncated-32", b->pub_c.vch, 32);
        push_pub_case(c, b, "pub/truncated-64", b->pub_u.vch, 64);

        memset(buf, 0, sizeof(buf));
        memcpy(buf, b->pub_u.vch, 65);
        push_pub_case(c, b, "pub/oversized-66", buf, 66);

        push_pub_case(c, b, "pub/wrong-key", b->pub2_c.vch, b->pub2_c.size);
        /* the compressed point with the OTHER y-parity — same x, wrong key */
        memcpy(buf, b->pub_c.vch, 33);
        buf[0] = (uint8_t)(buf[0] == 0x02 ? 0x03 : 0x02);
        push_pub_case(c, b, "pub/flipped-parity", buf, 33);
    }

    /* ── message-length and content edges ───────────────────────────── */
    {
        struct secp_vector *v;
        const size_t bad_msg_lens[] = { 0, 1, 31, 33, 64 };
        for (size_t i = 0; i < sizeof(bad_msg_lens) / sizeof(bad_msg_lens[0]); i++) {
            char nm[56];
            snprintf(nm, sizeof(nm), "msg/len-%zu", bad_msg_lens[i]);
            v = secp_corpus_push(c, nm);
            if (!v) continue;
            memcpy(v->pub, b->pub_c.vch, b->pub_c.size); v->publen = b->pub_c.size;
            memcpy(v->msg, b->msg.data, bad_msg_lens[i] > 32 ? 32 : bad_msg_lens[i]);
            v->msglen = bad_msg_lens[i];
            memcpy(v->sig, b->sig_der, b->sig_len); v->siglen = b->sig_len;
        }
        v = secp_corpus_push(c, "msg/one-bit-flipped");
        if (v) {
            memcpy(v->pub, b->pub_c.vch, b->pub_c.size); v->publen = b->pub_c.size;
            memcpy(v->msg, b->msg.data, 32); v->msg[31] ^= 0x01; v->msglen = 32;
            memcpy(v->sig, b->sig_der, b->sig_len); v->siglen = b->sig_len;
        }
        v = secp_corpus_push(c, "sig/from-other-key");
        if (v) {
            memcpy(v->pub, b->pub_c.vch, b->pub_c.size); v->publen = b->pub_c.size;
            memcpy(v->msg, b->msg.data, 32); v->msglen = 32;
            memcpy(v->sig, b->sig2_der, b->sig2_len); v->siglen = b->sig2_len;
        }
    }
}

/* ── seed export for tools/fuzz/fuzz_ecdsa.c ─────────────────────────── */
static void dump_seeds(const struct secp_corpus *c, const char *dir)
{
    uint8_t buf[512];
    char path[512];
    for (size_t i = 0; i < c->n; i++) {
        size_t n = secp_vector_encode(&c->v[i], buf, sizeof(buf));
        if (!n) continue;
        char safe[64];
        snprintf(safe, sizeof(safe), "%s", c->v[i].name);
        for (char *p = safe; *p; p++)
            if (*p == '/') *p = '_';
        snprintf(path, sizeof(path), "%s/%s.bin", dir, safe);
        FILE *f = fopen(path, "wb");
        if (!f) continue;
        fwrite(buf, 1, n, f);
        fclose(f);
    }
    printf("  seeds: wrote %zu vectors to %s\n", c->n, dir);
}

int test_secp256k1_differential(void)
{
    int failures = 0;
    printf("\n=== secp256k1_differential (candidate vs vendored archive) ===\n");

    g_ref_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY |
                                         SECP256K1_CONTEXT_SIGN);
    if (!g_ref_ctx) {
        printf("FAIL: reference context creation failed\n");
        return 1;
    }

    crypto_sig_verify_fn cand = candidate_verify_fn();
    printf("candidate registered... ");
    if (cand) {
        printf("OK\n");
    } else {
        printf("FAIL (no ACTIVE ecdsa-secp256k1 scheme)\n");
        secp256k1_context_destroy(g_ref_ctx);
        return 1;
    }

    /* ── L3: external ground truth ──────────────────────────────────── */
    printf("L3 ground truth: scalar 1 -> published base point G... ");
    {
        struct privkey one;
        memset(one.vch, 0, 32);
        one.vch[31] = 1;
        one.fValid = true;
        one.fCompressed = true;
        struct pubkey p;
        bool ok = privkey_get_pubkey(&one, &p) &&
                  p.size == COMPRESSED_PUBLIC_KEY_SIZE &&
                  memcmp(p.vch, SECP_G_COMPRESSED, 33) == 0;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("L3 ground truth: scalar n-1 -> -G (same x, odd y)... ");
    {
        struct privkey nm1;
        secp_be256_sub(nm1.vch, SECP_ORDER_N, (const uint8_t[32]){
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1});
        nm1.fValid = true;
        nm1.fCompressed = true;
        struct pubkey p;
        bool ok = privkey_get_pubkey(&nm1, &p) &&
                  p.size == COMPRESSED_PUBLIC_KEY_SIZE &&
                  p.vch[0] == 0x03 &&
                  memcmp(p.vch + 1, SECP_G_COMPRESSED + 1, 32) == 0;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("L3 ground truth: scalars 0, n, n+1 rejected as secret keys... ");
    {
        struct privkey z, n, np1;
        memset(z.vch, 0, 32); z.fValid = true; z.fCompressed = true;
        memcpy(n.vch, SECP_ORDER_N, 32); n.fValid = true; n.fCompressed = true;
        secp_be256_add_u8(np1.vch, SECP_ORDER_N, 1);
        np1.fValid = true; np1.fCompressed = true;
        bool ok = !privkey_range_check(&z) && !privkey_range_check(&n) &&
                  !privkey_range_check(&np1);
        struct pubkey p;
        ok = ok && !privkey_get_pubkey(&z, &p) && !privkey_get_pubkey(&n, &p);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("L3 algebraic: pubkey(a) tweaked by b == pubkey(a+b)... ");
    {
        /* (a)G + (b)G == (a+b)G. A homomorphism no implementation can satisfy
         * by accident, and one that does not depend on any baked constant. */
        struct privkey a, sum;
        uint8_t bscalar[32];
        memset(a.vch, 0, 32); a.vch[31] = 5; a.fValid = true; a.fCompressed = true;
        memset(bscalar, 0, 32); bscalar[31] = 9;
        memset(sum.vch, 0, 32); sum.vch[31] = 14;
        sum.fValid = true; sum.fCompressed = true;

        struct pubkey pa, psum;
        bool ok = privkey_get_pubkey(&a, &pa) && privkey_get_pubkey(&sum, &psum);
        secp256k1_pubkey parsed;
        ok = ok && secp256k1_ec_pubkey_parse(g_ref_ctx, &parsed, pa.vch, pa.size);
        ok = ok && secp256k1_ec_pubkey_tweak_add(g_ref_ctx, &parsed, bscalar);
        uint8_t ser[33];
        size_t serlen = sizeof(ser);
        ok = ok && secp256k1_ec_pubkey_serialize(g_ref_ctx, ser, &serlen, &parsed,
                                                 SECP256K1_EC_COMPRESSED);
        ok = ok && serlen == 33 && memcmp(ser, psum.vch, 33) == 0;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── build the corpus ───────────────────────────────────────────── */
    struct secp_base base;
    printf("corpus base (fixed key, production signer)... ");
    if (build_base(&base)) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        secp256k1_context_destroy(g_ref_ctx);
        return failures + 1;
    }

    static struct secp_corpus corpus;
    build_corpus(&corpus, &base);
    printf("corpus vectors: %zu\n", corpus.n);
    if (corpus.n < 40) {
        printf("FAIL: corpus shrank below the 40-vector floor\n");
        failures++;
    }

    /* ── L1 + L2 over the corpus ────────────────────────────────────── */
    struct secp_transcript tr;
    tr_init(&tr);
    int diverged = 0, accepted = 0;
    for (size_t i = 0; i < corpus.n; i++) {
        const struct secp_vector *v = &corpus.v[i];
        bool cv = cand(v->pub, v->publen, v->msg, v->msglen, v->sig, v->siglen);
        bool rv = ref_ecdsa_verify(v->pub, v->publen, v->msg, v->msglen,
                                   v->sig, v->siglen);
        if (cv != rv) {
            printf("  DIVERGENCE [%s]: candidate=%d reference=%d\n",
                   v->name, cv, rv);
            diverged++;
        }
        if (cv) accepted++;

        /* The real consensus entry point must agree with the registry
         * wrapper for every input struct pubkey can represent. */
        if (v->publen > 0 && v->publen <= PUBLIC_KEY_SIZE && v->msglen == 32) {
            struct pubkey pk;
            pubkey_init(&pk);
            pubkey_set(&pk, v->pub, (unsigned int)v->publen);
            struct uint256 h;
            memcpy(h.data, v->msg, 32);
            bool pv = pubkey_verify(&pk, &h, v->sig, v->siglen);
            if (pv != cv) {
                printf("  DIVERGENCE [%s]: pubkey_verify=%d registry=%d\n",
                       v->name, pv, cv);
                diverged++;
            }
        }

        tr_str(&tr, v->name);
        tr_bool(&tr, cv);
        tr_bool(&tr, ref_is_low_s(v->sig, v->siglen));
        tr_bool(&tr, ref_pubkey_on_curve(v->pub, v->publen));
    }
    printf("L1 differential over %zu vectors... ", corpus.n);
    if (diverged == 0) printf("OK (%d accept / %zu)\n", accepted, corpus.n);
    else { printf("FAIL (%d divergences)\n", diverged); failures += diverged; }

    /* At least one vector must ACCEPT and at least one must REJECT, or the
     * corpus is vacuous and an always-false implementation would pass. */
    printf("corpus is non-vacuous (some accept, some reject)... ");
    if (accepted > 0 && (size_t)accepted < corpus.n) printf("OK\n");
    else { printf("FAIL (accepted=%d of %zu)\n", accepted, corpus.n); failures++; }

    /* ── NULL-argument contract (cannot ride in a vector) ───────────── */
    printf("null-argument contract matches reference... ");
    {
        uint8_t m[32] = {0}, s[8] = {0}, p[33] = {0};
        struct { const uint8_t *pub; const uint8_t *msg; const uint8_t *sig; } n3[] = {
            { NULL, m, s }, { p, NULL, s }, { p, m, NULL }, { NULL, NULL, NULL },
        };
        bool ok = true;
        for (size_t i = 0; i < 4; i++) {
            bool cv = cand(n3[i].pub, 33, n3[i].msg, 32, n3[i].sig, 8);
            bool rv = ref_ecdsa_verify(n3[i].pub, 33, n3[i].msg, 32, n3[i].sig, 8);
            ok = ok && !cv && cv == rv;
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── low-S contract split ───────────────────────────────────────── */
    printf("low-S: pubkey_check_low_s rejects high-S, verify still accepts... ");
    {
        uint8_t high[SECP_VEC_MAX_SIG];
        size_t hlen = secp_der_encode(high, sizeof(high), base.r, base.s_high,
                                      false, false);
        bool low_ok  = pubkey_check_low_s(base.sig_der, base.sig_len);
        bool high_ok = pubkey_check_low_s(high, hlen);
        bool verifies = pubkey_verify(&base.pub_c, &base.msg, high, hlen);
        bool ref_low  = ref_is_low_s(base.sig_der, base.sig_len);
        bool ref_high = ref_is_low_s(high, hlen);
        if (low_ok && !high_ok && verifies &&
            low_ok == ref_low && high_ok == ref_high) {
            printf("OK\n");
        } else {
            printf("FAIL (low=%d high=%d verify=%d)\n", low_ok, high_ok, verifies);
            failures++;
        }
        tr_bool(&tr, low_ok); tr_bool(&tr, high_ok); tr_bool(&tr, verifies);
    }

    /* ── deterministic signing: same key+msg -> identical DER bytes ──── */
    printf("RFC6979 determinism: repeated signing is byte-identical... ");
    {
        uint8_t again[SIGNATURE_SIZE];
        size_t alen = sizeof(again);
        bool ok = privkey_sign(&base.key, &base.msg, again, &alen) &&
                  alen == base.sig_len &&
                  memcmp(again, base.sig_der, alen) == 0;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        tr_bytes(&tr, base.sig_der, base.sig_len);
        tr_bytes(&tr, base.pub_c.vch, base.pub_c.size);
        tr_bytes(&tr, base.pub_u.vch, base.pub_u.size);
    }

    /* ── recoverable-signature round trip + adversarial recids ──────── */
    printf("compact recovery round trip + adversarial headers... ");
    {
        uint8_t comp[COMPACT_SIGNATURE_SIZE];
        bool ok = privkey_sign_compact(&base.key, &base.msg, comp);
        struct pubkey rec;
        pubkey_init(&rec);
        ok = ok && pubkey_recover_compact(&rec, &base.msg, comp);
        ok = ok && rec.size == base.pub_c.size &&
             memcmp(rec.vch, base.pub_c.vch, rec.size) == 0;

        /* A recovered key from a WRONG message must not equal the signer. */
        struct uint256 other = base.msg;
        other.data[0] ^= 0xFF;
        struct pubkey wrongrec;
        pubkey_init(&wrongrec);
        bool recovered_other = pubkey_recover_compact(&wrongrec, &other, comp);
        ok = ok && (!recovered_other ||
                    wrongrec.size != base.pub_c.size ||
                    memcmp(wrongrec.vch, base.pub_c.vch, wrongrec.size) != 0);

        /* All-zero compact signature must not recover a usable key. */
        uint8_t zerosig[COMPACT_SIGNATURE_SIZE] = {0};
        zerosig[0] = 27;
        struct pubkey zrec;
        pubkey_init(&zrec);
        bool zok = pubkey_recover_compact(&zrec, &base.msg, zerosig);
        ok = ok && (!zok || !pubkey_is_fully_valid(&zrec));

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        tr_bytes(&tr, comp, sizeof(comp));
    }

    /* ── L2 golden ──────────────────────────────────────────────────── */
    unsigned char digest[32];
    sha3_256_finalize(&tr.h, digest);
    char hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(hex + i * 2, 3, "%02x", digest[i]);
    hex[64] = '\0';

    if (getenv("ZCL_SECP_GOLDEN_RECORD")) {
        printf("L2 golden RECORD MODE: %s\n", hex);
    } else {
        printf("L2 golden transcript... ");
        if (strcmp(hex, SECP_GOLDEN_SHA3) == 0) {
            printf("OK\n");
        } else {
            printf("FAIL\n    expected %s\n    actual   %s\n",
                   SECP_GOLDEN_SHA3, hex);
            printf("    (an intentional change re-records with "
                   "ZCL_SECP_GOLDEN_RECORD=1; a surprise here is a "
                   "consensus-visible divergence)\n");
            failures++;
        }
    }

    const char *seeddir = getenv("ZCL_SECP_DUMP_SEEDS");
    if (seeddir)
        dump_seeds(&corpus, seeddir);

    secp256k1_context_destroy(g_ref_ctx);
    g_ref_ctx = NULL;

    printf("secp256k1_differential: %s (%d failures)\n",
           failures == 0 ? "OK" : "FAIL", failures);
    return failures;
}

/* ── CAVEATS — what this file does NOT prove ──────────────────────────────
 *
 *  - L1 cannot distinguish two implementations that share a bug, and today
 *    both sides call the same vendored archive, so L1's present value is the
 *    WRAPPER layer only (guards, normalisation, entry-point agreement). Its
 *    full value arrives with an in-house candidate.
 *  - L2 pins observed behaviour, not correctness. If the incumbent is wrong
 *    today, the golden freezes the wrong answer — which is the intended
 *    consensus-parity posture (match the chain, not the textbook), but it
 *    means a green run is "unchanged", never "correct".
 *  - The corpus is finite and hand-chosen. tools/fuzz/fuzz_ecdsa.c runs the
 *    same differential over unbounded input; that is where unknown shapes
 *    come from.
 *  - Nothing here observes side channels. That is
 *    tests/harness/src/test_secp256k1_constant_time.c, with its own stated limits.
 */
