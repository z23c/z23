/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 *
 * test_verify_contract — the z23verify.fixed_result.v2 byte contract, from
 * the attacker's side.
 *
 * Every v2 artifact is F(domain) then F(label) F(value) pairs, where F(x)
 * is u64le(len(x)) followed by x. This file re-frames the subject's bytes
 * with its own splitter (never the subject's decoder), changes exactly one
 * thing, and asserts the one stable refusal token. The positives are byte
 * round-trips plus one hand-spelled pins file, so a silent change to field
 * order, labels or framing fails here before any consumer sees it.
 *
 * Key v2 is exercised in the same group against the checked-in fast
 * profile, with its closure vector pinned. */
#define _XOPEN_SOURCE 700

#include "test/test_core.h"
#include "test/verify_contract_fixture.h"

#include "base/hex.h"
#include "crypto/ed25519.h"
#include "sha3/sha3.h"
#include "verify/fixed_result_contract.h"
#include "verify/fixed_result_key_v2.h"
#include "verify_attest.h"
#if !defined(_WIN32)
#include "platform/directory_compat.h"
#include "platform/temp_directory.h"
#include "verify_store.h"
#include <fcntl.h>
#include <ftw.h>
#include <sys/stat.h>
#include <limits.h>
#include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VC_MAX_PIECES 128u
#define VC_BUF 8192u
#define VC_TARGET_REL_OBJ \
    "build/test-rel-obj/epochs/" \
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
    "/platform/modules/base/src/result.o"
#define VC_GCC13_TOOLCHAIN \
    "z23.gcc13.fast_result.v2:" \
    "1313131313131313131313131313131313131313131313131313131313131313"
/* Pinned: key v2 closure for the probe's root fill and the fast profile.
 * tools/verify/fixed_result_key_v2_probe.sh prints the same value. */
/* The physical cwd the compile ran in; @CWD@ in the profile names it. */
#define VC_KEY_CWD "/proof/z23-A"
#define VC_RETIRED_FAST_SHA3 \
    "5e8a1cafce7350ff3c335c6a714f59c75c1e646de82eb03d076f68bdad244e1c"
#define VC_KEY_V2_CLOSURE \
    "d0fe6bd7bd3689b9cf78e87d4afd3d8acfcbc43c151b9e836ea676b97b5e6dd2"

static const uint8_t k_vc_verifier_seed[32] = {0x51};
static const uint8_t k_vc_box_seed[32] = {0x52};

/* ── An independent framing splitter ─────────────────────────────────── */

struct vc_piece {
    const uint8_t *p;
    size_t n;
};

struct vc_frames {
    struct vc_piece piece[VC_MAX_PIECES];
    size_t count;
    uint8_t out[VC_BUF];
    size_t out_len;
};

static uint64_t vc_u64le(const uint8_t *p)
{
    uint64_t v = 0;
    for (size_t i = 0; i < 8u; i++) v |= (uint64_t)p[i] << (8u * i);
    return v;
}

/* Split a well-framed artifact into its frames: piece 0 is the domain,
 * field i's label is piece 1 + 2i and its value piece 2 + 2i. */
static bool vc_split(const uint8_t *b, size_t len, struct vc_frames *f)
{
    size_t at = 0;
    f->count = 0;
    while (at < len) {
        if (len - at < 8u || f->count == VC_MAX_PIECES) return false;
        uint64_t n = vc_u64le(b + at);
        if (n > len - at - 8u) return false;
        f->piece[f->count++] = (struct vc_piece){b + at + 8u, (size_t)n};
        at += 8u + (size_t)n;
    }
    return true;
}

static void vc_put(uint8_t *out, size_t *at, const void *p, size_t n)
{
    for (size_t i = 0; i < 8u; i++)
        out[(*at)++] = (uint8_t)((uint64_t)n >> (8u * i));
    memcpy(out + *at, p, n);
    *at += n;
}

/* Re-frame the pieces into f->out. */
static const uint8_t *vc_join(struct vc_frames *f)
{
    size_t at = 0;
    for (size_t i = 0; i < f->count; i++) {
        if (at + 8u + f->piece[i].n > sizeof(f->out)) return NULL;
        vc_put(f->out, &at, f->piece[i].p, f->piece[i].n);
    }
    f->out_len = at;
    return f->out;
}

static void vc_set(struct vc_frames *f, size_t i, const void *p, size_t n)
{
    f->piece[i] = (struct vc_piece){(const uint8_t *)p, n};
}

static void vc_set_text(struct vc_frames *f, size_t i, const char *s)
{
    vc_set(f, i, s, strlen(s));
}

/* Index of the value piece whose label is `label`, or 0. */
static size_t vc_value_of(const struct vc_frames *f, const char *label)
{
    size_t n = strlen(label);
    for (size_t i = 1; i + 1u < f->count; i += 2u)
        if (f->piece[i].n == n && memcmp(f->piece[i].p, label, n) == 0)
            return i + 1u;
    return 0;
}

static void vc_swap_fields(struct vc_frames *f, size_t a_value,
                           size_t b_value)
{
    struct vc_piece l = f->piece[a_value - 1u], v = f->piece[a_value];
    f->piece[a_value - 1u] = f->piece[b_value - 1u];
    f->piece[a_value] = f->piece[b_value];
    f->piece[b_value - 1u] = l;
    f->piece[b_value] = v;
}

static bool vc_token(const char *why, const char *want)
{
    if (why && strcmp(why, want) == 0) return true;
    printf("[got %s, want %s] ", why ? why : "(accepted)", want);
    return false;
}

/* ── Artifact-specific parse wrappers returning the refusal ──────────── */

static const char *vc_pins_why(const uint8_t *b, size_t n)
{
    struct zcl_fixed_result_v2_roots out;
    const char *why = NULL;
    return zcl_fr_pins_parse(b, n, &out, &why) ? NULL : why;
}

static const char *vc_receipt_why(const uint8_t *b, size_t n)
{
    struct zcl_fr_receipt out;
    const char *why = NULL;
    return zcl_fr_receipt_parse(b, n, &out, &why) ? NULL : why;
}

static const char *vc_packet_why(const uint8_t *b, size_t n)
{
    struct zcl_fr_packet out;
    const char *why = NULL;
    return zcl_fr_packet_parse(b, n, &out, &why) ? NULL : why;
}

static const char *vc_request_why(const uint8_t *b, size_t n)
{
    char target[ZCL_FR_TARGET_LEN + 1u];
    const char *why = NULL;
    return zcl_fr_request_parse(b, n, target, &why) ? NULL : why;
}

static bool vc_pins_bytes(const struct zcl_fixed_result_v2_roots *pins,
                          uint8_t *out, size_t *len)
{
    const char *why = NULL;
    return zcl_fr_pins_encode(pins, out, VC_BUF, len, &why);
}

static void vc_env_root_with(const char *tmpdir, uint8_t out[32])
{
    const char *envp[4] = {"LC_ALL=C", "TZ=UTC", tmpdir, "PATH=/usr/bin:/bin"};
    zcl_fr_env_root(envp, 4u, out);
}

/* ── 1. pins v2 ──────────────────────────────────────────────────────── */

static int test_vc_pins_roundtrip(void)
{
    int failures = 0;
    static const char *const labels[12] = {
        "source_content_sha3", "profile_args_sha3", "source_image_sha3",
        "tool_image_sha3", "worker_sha3", "launcher_sha3",
        "check_image_sha3", "environment_sha3", "policy_sha3",
        "seccomp_filter_sha3", "bwrap_sha3", "tree_checker_sha3"};
    static uint8_t bytes[VC_BUF], want[VC_BUF];
    size_t len = 0, want_len = 0;
    TEST("verify contract: pins v2 are F(domain), F(profile), then the "
         "twelve labeled roots in key v2 order, and round-trip exactly") {
        struct zcl_fixed_result_v2_roots pins, back;
        const char *why = NULL;
        test_vc_pins(&pins);
        ASSERT(vc_pins_bytes(&pins, bytes, &len));
        vc_put(want, &want_len, "z23verify.fixed_result.pins.v2", 30u);
        vc_put(want, &want_len, "profile", 7u);
        vc_put(want, &want_len, "test_fast", 9u);
        for (size_t i = 0; i < 12u; i++) {
            vc_put(want, &want_len, labels[i], strlen(labels[i]));
            vc_put(want, &want_len, zcl_fr_root_at(&pins, i), 32u);
        }
        ASSERT(len == want_len && memcmp(bytes, want, len) == 0);
        ASSERT(zcl_fr_pins_parse(bytes, len, &back, &why));
        ASSERT(memcmp(&back, &pins, sizeof(pins)) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_vc_pins_framing(void)
{
    int failures = 0;
    static uint8_t bytes[VC_BUF], raw[VC_BUF];
    static struct vc_frames f;
    size_t len = 0;
    TEST("verify contract: pins framing faults refuse by name (reordered, "
         "missing tree_checker, truncated, oversize, trailing, NUL/LF "
         "domain, v1, unknown version, wrong artifact)") {
        struct zcl_fixed_result_v2_roots pins;
        test_vc_pins(&pins);
        ASSERT(vc_pins_bytes(&pins, bytes, &len));
        ASSERT(vc_split(bytes, len, &f) && f.count == 27u);
        vc_swap_fields(&f, vc_value_of(&f, "source_image_sha3"),
                       vc_value_of(&f, "tool_image_sha3"));
        ASSERT(vc_join(&f));
        ASSERT(vc_token(vc_pins_why(f.out, f.out_len),
                        ZCL_FR_WHY_FIELD_ORDER));
        ASSERT(vc_split(bytes, len, &f));
        f.count -= 2u; /* drop F("tree_checker_sha3") F(root) */
        ASSERT(vc_join(&f));
        ASSERT(vc_token(vc_pins_why(f.out, f.out_len),
                        ZCL_FR_WHY_FIELD_MISSING));
        ASSERT(vc_token(vc_pins_why(bytes, len - 1u), ZCL_FR_WHY_TRUNCATED));
        ASSERT(vc_token(vc_pins_why(bytes, len - 36u), ZCL_FR_WHY_TRUNCATED));
        memcpy(raw, bytes, len);
        raw[len] = 0x00;
        ASSERT(vc_token(vc_pins_why(raw, len + 1u), ZCL_FR_WHY_TRAILING));
        /* The tree_checker value's length prefix: 33, then 2^63. */
        raw[len - 40u] = 33u;
        ASSERT(vc_token(vc_pins_why(raw, len), ZCL_FR_WHY_OVERSIZE));
        raw[len - 40u] = 32u;
        raw[len - 33u] = 0x80u;
        ASSERT(vc_token(vc_pins_why(raw, len), ZCL_FR_WHY_OVERSIZE));
        PASS();
    } _test_next:;
    return failures;
}

static int test_vc_pins_domains(void)
{
    int failures = 0;
    static uint8_t bytes[VC_BUF], raw[VC_BUF];
    static struct vc_frames f;
    size_t len = 0;
    TEST("verify contract: a NUL- or LF-terminated domain, a v1 header, "
         "a v3 domain and another artifact's domain each refuse by name") {
        struct zcl_fixed_result_v2_roots pins;
        test_vc_pins(&pins);
        ASSERT(vc_pins_bytes(&pins, bytes, &len));
        ASSERT(vc_split(bytes, len, &f));
        vc_set(&f, 0, "z23verify.fixed_result.pins.v2\n", 31u);
        ASSERT(vc_join(&f));
        ASSERT(vc_token(vc_pins_why(f.out, f.out_len),
                        ZCL_FR_WHY_DOMAIN_MALFORMED));
        vc_set(&f, 0, "z23verify.fixed_result.pins.v2\0", 31u);
        ASSERT(vc_join(&f));
        ASSERT(vc_token(vc_pins_why(f.out, f.out_len),
                        ZCL_FR_WHY_DOMAIN_MALFORMED));
        /* The domain as raw text with no length prefix, LF then NUL. */
        size_t at = 0;
        memcpy(raw, "z23verify.fixed_result.pins.v2\n", 31u);
        at = 31u;
        memcpy(raw + at, bytes + 38u, len - 38u);
        ASSERT(vc_token(vc_pins_why(raw, at + len - 38u),
                        ZCL_FR_WHY_DOMAIN_MALFORMED));
        raw[30] = '\0';
        ASSERT(vc_token(vc_pins_why(raw, at + len - 38u),
                        ZCL_FR_WHY_DOMAIN_MALFORMED));
        static const char v1[] = "z23verify.fixed_result.pins.v1\nprofile=x\n";
        ASSERT(vc_token(vc_pins_why((const uint8_t *)v1, sizeof(v1) - 1u),
                        ZCL_FR_WHY_V1_RETIRED));
        vc_set_text(&f, 0, "z23verify.fixed_result.pins.v3");
        ASSERT(vc_join(&f));
        ASSERT(vc_token(vc_pins_why(f.out, f.out_len),
                        ZCL_FR_WHY_VERSION_UNKNOWN));
        vc_set_text(&f, 0, ZCL_FR_DOMAIN_RECEIPT);
        ASSERT(vc_join(&f));
        ASSERT(vc_token(vc_pins_why(f.out, f.out_len),
                        ZCL_FR_WHY_WRONG_ARTIFACT));
        PASS();
    } _test_next:;
    return failures;
}

static int test_vc_pins_values(void)
{
    int failures = 0;
    static uint8_t bytes[VC_BUF];
    static struct vc_frames f;
    size_t len = 0;
    uint8_t strict[32], env_work[32], zero[32] = {0};
    TEST("verify contract: the strict profile, TMPDIR=/work and a zero "
         "tree_checker root refuse in pins, whether encoded or forged") {
        struct zcl_fixed_result_v2_roots pins;
        const char *why = NULL;
        test_vc_pins(&pins);
        ASSERT(vc_pins_bytes(&pins, bytes, &len));
        ASSERT(zcl_hex_decode_lower(ZCL_FR_RETIRED_STRICT_SHA3, strict, 32u));
        vc_env_root_with("TMPDIR=/work", env_work);

        ASSERT(vc_split(bytes, len, &f));
        vc_set(&f, vc_value_of(&f, "profile_args_sha3"), strict, 32u);
        ASSERT(vc_join(&f));
        ASSERT(vc_token(vc_pins_why(f.out, f.out_len), ZCL_FR_WHY_PROFILE));
        ASSERT(zcl_hex_decode_lower(VC_RETIRED_FAST_SHA3, strict, 32u));
        ASSERT(vc_split(bytes, len, &f));
        vc_set(&f, vc_value_of(&f, "profile_args_sha3"), strict, 32u);
        ASSERT(vc_join(&f));
        ASSERT(vc_token(vc_pins_why(f.out, f.out_len), ZCL_FR_WHY_PROFILE));
        ASSERT(vc_split(bytes, len, &f));
        vc_set_text(&f, 2, "test_strict");
        ASSERT(vc_join(&f));
        ASSERT(vc_token(vc_pins_why(f.out, f.out_len), ZCL_FR_WHY_PROFILE));
        ASSERT(vc_split(bytes, len, &f));
        vc_set(&f, vc_value_of(&f, "environment_sha3"), env_work, 32u);
        ASSERT(vc_join(&f));
        ASSERT(vc_token(vc_pins_why(f.out, f.out_len), ZCL_FR_WHY_ENV));
        ASSERT(vc_split(bytes, len, &f));
        vc_set(&f, vc_value_of(&f, "tree_checker_sha3"), zero, 32u);
        ASSERT(vc_join(&f));
        ASSERT(vc_token(vc_pins_why(f.out, f.out_len), ZCL_FR_WHY_HASH_ZERO));

        /* The encoder refuses what the parser refuses. */
        ASSERT(zcl_hex_decode_lower(ZCL_FR_RETIRED_STRICT_SHA3, strict, 32u));
        memcpy(pins.profile_args, strict, 32u);
        ASSERT(!zcl_fr_pins_encode(&pins, bytes, VC_BUF, &len, &why));
        ASSERT(vc_token(why, ZCL_FR_WHY_PROFILE));
        test_vc_pins(&pins);
        memcpy(pins.environment, env_work, 32u);
        ASSERT(!zcl_fr_pins_encode(&pins, bytes, VC_BUF, &len, &why));
        ASSERT(vc_token(why, ZCL_FR_WHY_ENV));
        const char *env_work_p[4] = {"LC_ALL=C", "TZ=UTC", "TMPDIR=/work",
                                     "PATH=/usr/bin:/bin"};
        ASSERT(vc_token(zcl_fr_env_check(env_work_p, 4u), ZCL_FR_WHY_ENV));
        PASS();
    } _test_next:;
    return failures;
}

/* ── 2. launch request v2 ────────────────────────────────────────────── */

static int test_vc_request(void)
{
    int failures = 0;
    static uint8_t bytes[VC_BUF];
    static struct vc_frames f;
    size_t len = 0;
    char target[ZCL_FR_TARGET_LEN + 1u], back[ZCL_FR_TARGET_LEN + 1u];
    TEST("verify contract: the launch request round-trips one epoch target "
         "and refuses a test-rel-obj target and another cwd") {
        const char *why = NULL;
        test_vc_target(target, 'c');
        ASSERT(zcl_fr_request_encode(target, bytes, VC_BUF, &len, &why));
        ASSERT(zcl_fr_request_parse(bytes, len, back, &why));
        ASSERT_STR_EQ(back, target);
        ASSERT(!zcl_fr_request_encode(VC_TARGET_REL_OBJ, bytes + len,
                                      VC_BUF - len, &len, &why));
        ASSERT(vc_token(why, ZCL_FR_WHY_TARGET));
        ASSERT(zcl_fr_request_encode(target, bytes, VC_BUF, &len, &why));
        ASSERT(vc_split(bytes, len, &f) && f.count == 7u);
        vc_set_text(&f, vc_value_of(&f, "target"), VC_TARGET_REL_OBJ);
        ASSERT(vc_join(&f));
        ASSERT(vc_token(vc_request_why(f.out, f.out_len), ZCL_FR_WHY_TARGET));
        ASSERT(vc_split(bytes, len, &f));
        vc_set_text(&f, vc_value_of(&f, "recorded_cwd"), "/work");
        ASSERT(vc_join(&f));
        ASSERT(vc_token(vc_request_why(f.out, f.out_len), ZCL_FR_WHY_CWD));
        ASSERT(vc_split(bytes, len, &f));
        vc_set_text(&f, vc_value_of(&f, "profile"), "test_strict");
        ASSERT(vc_join(&f));
        ASSERT(vc_token(vc_request_why(f.out, f.out_len), ZCL_FR_WHY_PROFILE));
        PASS();
    } _test_next:;
    return failures;
}

/* ── 3. worker result packet v2 ──────────────────────────────────────── */

static bool vc_packet(uint8_t *out, size_t *len)
{
    struct zcl_fr_packet p;
    const char *why = NULL;
    memset(&p, 0, sizeof(p));
    memcpy(p.scratch, "/work/result.Zz0123", ZCL_FR_SCRATCH_LEN);
    test_vc_target(p.target, 'd');
    memset(p.compile_argv_sha3, 0x61, 32u);
    memset(p.preprocess_argv_sha3, 0x62, 32u);
    zcl_fr_env_fixed_root(p.environment_sha3);
    return zcl_fr_packet_encode(&p, out, VC_BUF, len, &why);
}

static int test_vc_packet(void)
{
    int failures = 0;
    static uint8_t bytes[VC_BUF];
    static struct vc_frames f;
    size_t len = 0;
    uint8_t env_work[32];
    TEST("verify contract: the result packet names its four FDs once, in "
         "order, and refuses duplicates, scratch names and TMPDIR=/work") {
        struct zcl_fr_packet back;
        const char *why = NULL;
        ASSERT(vc_packet(bytes, &len));
        ASSERT(zcl_fr_packet_parse(bytes, len, &back, &why));
        ASSERT_STR_EQ(back.scratch, "/work/result.Zz0123");
        ASSERT(vc_split(bytes, len, &f) && f.count == 21u);
        vc_set_text(&f, 18, "object.o"); /* third artifact: stderr.bin */
        ASSERT(vc_join(&f));
        ASSERT(vc_token(vc_packet_why(f.out, f.out_len),
                        ZCL_FR_WHY_ARTIFACT_DUPLICATE));
        vc_set_text(&f, 18, "result.o");
        ASSERT(vc_join(&f));
        ASSERT(vc_token(vc_packet_why(f.out, f.out_len),
                        ZCL_FR_WHY_ARTIFACT_UNKNOWN));
        ASSERT(vc_split(bytes, len, &f));
        vc_swap_fields(&f, 16, 18);
        ASSERT(vc_join(&f));
        ASSERT(vc_token(vc_packet_why(f.out, f.out_len),
                        ZCL_FR_WHY_ARTIFACT_ORDER));
        ASSERT(vc_split(bytes, len, &f));
        vc_set_text(&f, vc_value_of(&f, "scratch"), "/work/result.Zz01_3");
        ASSERT(vc_join(&f));
        ASSERT(vc_token(vc_packet_why(f.out, f.out_len), ZCL_FR_WHY_SCRATCH));
        ASSERT(vc_split(bytes, len, &f));
        vc_env_root_with("TMPDIR=/work", env_work);
        vc_set(&f, vc_value_of(&f, "environment_sha3"), env_work, 32u);
        ASSERT(vc_join(&f));
        ASSERT(vc_token(vc_packet_why(f.out, f.out_len), ZCL_FR_WHY_ENV));
        static const char *const dup[4] = {"object.o", "deps.d", "deps.d",
                                           "preprocessed.i"};
        ASSERT(vc_token(zcl_fr_artifact_names_check(dup, 4u),
                        ZCL_FR_WHY_ARTIFACT_DUPLICATE));
        static const char *const three[3] = {"object.o", "deps.d",
                                             "stderr.bin"};
        ASSERT(vc_token(zcl_fr_artifact_names_check(three, 3u),
                        ZCL_FR_WHY_ARTIFACT_ORDER));
        PASS();
    } _test_next:;
    return failures;
}

/* ── 4. launch receipt v2 ────────────────────────────────────────────── */

static int test_vc_receipt_roundtrip(void)
{
    int failures = 0;
    static struct test_vc_fixture w;
    static uint8_t again[VC_BUF];
    size_t len = 0;
    TEST("verify contract: a launch receipt round-trips byte for byte and "
         "holds 46 labeled fields after its domain") {
        struct zcl_fr_receipt back;
        static struct vc_frames f;
        const char *why = NULL;
        ASSERT(test_vc_fixture_make(&w, 'a'));
        ASSERT(zcl_fr_receipt_parse(w.receipt_bytes, w.receipt_len, &back,
                                    &why));
        ASSERT(memcmp(&back, &w.receipt, sizeof(back)) == 0);
        ASSERT(zcl_fr_receipt_encode(&back, again, VC_BUF, &len, &why));
        ASSERT(len == w.receipt_len &&
               memcmp(again, w.receipt_bytes, len) == 0);
        ASSERT(vc_split(w.receipt_bytes, w.receipt_len, &f));
        ASSERT(f.count == 1u + 2u * 46u);
        ASSERT(f.piece[0].n == strlen(ZCL_FR_DOMAIN_RECEIPT) &&
               memcmp(f.piece[0].p, ZCL_FR_DOMAIN_RECEIPT, f.piece[0].n) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* One receipt with one value replaced by `value`, then parsed. */
static const char *vc_receipt_with(const struct test_vc_fixture *w,
                                   const char *label, const void *value,
                                   size_t n)
{
    static struct vc_frames f;
    if (!vc_split(w->receipt_bytes, w->receipt_len, &f)) return "split";
    size_t at = vc_value_of(&f, label);
    if (!at) return "label";
    vc_set(&f, at, value, n);
    if (!vc_join(&f)) return "join";
    return vc_receipt_why(f.out, f.out_len);
}

static const char *vc_receipt_u64(const struct test_vc_fixture *w,
                                  const char *label, uint64_t v)
{
    uint8_t le[8];
    for (size_t i = 0; i < 8u; i++) le[i] = (uint8_t)(v >> (8u * i));
    return vc_receipt_with(w, label, le, 8u);
}

static int test_vc_receipt_fields(void)
{
    int failures = 0;
    static struct test_vc_fixture w;
    uint8_t env_work[32], strict[32];
    TEST("verify contract: a receipt naming gcc13, a test-rel-obj target, "
         "another cwd, the strict profile, TMPDIR=/work, the developer uid "
         "or a failed worker refuses by name") {
        ASSERT(test_vc_fixture_make(&w, 'a'));
        ASSERT(vc_token(vc_receipt_with(&w, "toolchain_id",
                                        VC_GCC13_TOOLCHAIN,
                                        strlen(VC_GCC13_TOOLCHAIN)),
                        ZCL_FR_WHY_TOOLCHAIN));
        ASSERT(vc_token(vc_receipt_with(&w, "target", VC_TARGET_REL_OBJ,
                                        strlen(VC_TARGET_REL_OBJ)),
                        ZCL_FR_WHY_TARGET));
        ASSERT(vc_token(vc_receipt_with(&w, "recorded_cwd", "/work", 5u),
                        ZCL_FR_WHY_CWD));
        ASSERT(vc_token(vc_receipt_with(&w, "recorded_cwd", "/src", 4u),
                        ZCL_FR_WHY_CWD));
        ASSERT(vc_token(vc_receipt_with(&w, "profile", "test_strict", 11u),
                        ZCL_FR_WHY_PROFILE));
        ASSERT(zcl_hex_decode_lower(ZCL_FR_RETIRED_STRICT_SHA3, strict, 32u));
        ASSERT(vc_token(vc_receipt_with(&w, "profile_args_sha3", strict, 32u),
                        ZCL_FR_WHY_PROFILE));
        vc_env_root_with("TMPDIR=/work", env_work);
        ASSERT(vc_token(vc_receipt_with(&w, "environment_sha3", env_work,
                                        32u),
                        ZCL_FR_WHY_ENV));
        ASSERT(vc_token(vc_receipt_with(&w, "source", "src/main.c", 10u),
                        ZCL_FR_WHY_SOURCE));
        ASSERT(vc_token(vc_receipt_u64(&w, "compiler_euid", 1000u),
                        ZCL_FR_WHY_IDENTITY));
        ASSERT(vc_token(vc_receipt_u64(&w, "cap_effective", 1u),
                        ZCL_FR_WHY_IDENTITY));
        ASSERT(vc_token(vc_receipt_u64(&w, "worker_exit", 1u),
                        ZCL_FR_WHY_WORKER_EXIT));
        ASSERT(vc_token(vc_receipt_u64(&w, "object_size", 0u),
                        ZCL_FR_WHY_FIELD_MALFORMED));
        ASSERT(vc_token(vc_receipt_with(&w, "scratch", "/work/result.AB/1",
                                        17u),
                        ZCL_FR_WHY_SCRATCH));
        PASS();
    } _test_next:;
    return failures;
}

static int test_vc_receipt_framing(void)
{
    int failures = 0;
    static struct test_vc_fixture w;
    static struct vc_frames f;
    static uint8_t raw[VC_BUF];
    TEST("verify contract: a v1 launch receipt, a reordered or missing "
         "tree_checker root, and a trailing byte refuse a v2 receipt parse") {
        static const char v1[] =
            "z23verify.launch.v1\nlaunch_id=0123456789abcdef\n"
            "profile=test_fast\nworker_exit=0\n";
        ASSERT(vc_token(vc_receipt_why((const uint8_t *)v1, sizeof(v1) - 1u),
                        ZCL_FR_WHY_V1_RETIRED));
        ASSERT(test_vc_fixture_make(&w, 'a'));
        ASSERT(vc_split(w.receipt_bytes, w.receipt_len, &f));
        size_t tc = vc_value_of(&f, "tree_checker_sha3");
        ASSERT(tc != 0);
        vc_swap_fields(&f, tc, vc_value_of(&f, "bwrap_sha3"));
        ASSERT(vc_join(&f));
        ASSERT(vc_token(vc_receipt_why(f.out, f.out_len),
                        ZCL_FR_WHY_FIELD_ORDER));
        ASSERT(vc_split(w.receipt_bytes, w.receipt_len, &f));
        memmove(&f.piece[tc - 1u], &f.piece[tc + 1u],
                (f.count - tc - 1u) * sizeof(f.piece[0]));
        f.count -= 2u;
        ASSERT(vc_join(&f));
        ASSERT(vc_token(vc_receipt_why(f.out, f.out_len),
                        ZCL_FR_WHY_FIELD_ORDER));
        memcpy(raw, w.receipt_bytes, w.receipt_len);
        raw[w.receipt_len] = '\n';
        ASSERT(vc_token(vc_receipt_why(raw, w.receipt_len + 1u),
                        ZCL_FR_WHY_TRAILING));
        ASSERT(vc_token(vc_receipt_why(raw, w.receipt_len - 1u),
                        ZCL_FR_WHY_TRUNCATED));
        ASSERT(vc_token(vc_receipt_why(raw, 4u), ZCL_FR_WHY_TRUNCATED));
        PASS();
    } _test_next:;
    return failures;
}

/* ── 5. receipt binding ──────────────────────────────────────────────── */

static const char *vc_bind(const struct test_vc_fixture *w,
                           const struct zcl_fixed_result_v2_roots *pins,
                           const struct zcl_verify_attest_expected *e,
                           struct zcl_fr_binding *out)
{
    const struct zcl_fr_artifact_bytes a = test_vc_artifacts(w);
    const char *why = NULL;
    return zcl_fr_receipt_bind(w->receipt_bytes, w->receipt_len, pins, e, &a,
                               out, &why) ? NULL : why;
}

static int test_vc_bind(void)
{
    int failures = 0;
    static struct test_vc_fixture w;
    static struct zcl_fr_binding b;
    TEST("verify contract: binding yields contract, profile, target and "
         "receipt hash, and refuses other pins, inputs, bytes or -MT target") {
        ASSERT(test_vc_fixture_make(&w, 'a'));
        ASSERT(vc_bind(&w, &w.pins, &w.expected, &b) == NULL);
        ASSERT(b.binding.contract.len == strlen(ZCL_FR_CONTRACT) &&
               memcmp(b.binding.contract.bytes, ZCL_FR_CONTRACT,
                      b.binding.contract.len) == 0);
        ASSERT(memcmp(b.binding.profile_sha3, w.pins.profile_args, 32u) == 0);
        ASSERT_STR_EQ(b.target, w.target);
        ASSERT(memcmp(b.binding.receipt_sha3, w.binding.receipt_sha3, 32u)
               == 0);
        struct zcl_fixed_result_v2_roots pins = w.pins;
        pins.tree_checker[31] ^= 1u;
        ASSERT(vc_token(vc_bind(&w, &pins, &w.expected, &b),
                        ZCL_FR_WHY_PIN_MISMATCH));
        struct zcl_verify_attest_expected e = w.expected;
        e.recorded_cwd = (struct zcl_verify_attest_text){"/src", 4u};
        ASSERT(vc_token(vc_bind(&w, &w.pins, &e, &b),
                        ZCL_FR_WHY_RECEIPT_INPUT));
        e = w.expected;
        e.toolchain_id = (struct zcl_verify_attest_text){
            VC_GCC13_TOOLCHAIN, strlen(VC_GCC13_TOOLCHAIN)};
        ASSERT(vc_token(vc_bind(&w, &w.pins, &e, &b),
                        ZCL_FR_WHY_RECEIPT_INPUT));
        e = w.expected;
        e.pp_sha3[0] ^= 1u;
        ASSERT(vc_token(vc_bind(&w, &w.pins, &e, &b),
                        ZCL_FR_WHY_RECEIPT_INPUT));
        w.dep[w.dep_len - 2u] ^= 1u; /* fetched depfile is not the receipt's */
        ASSERT(vc_token(vc_bind(&w, &w.pins, &w.expected, &b),
                        ZCL_FR_WHY_RECEIPT_ARTIFACT));
        PASS();
    } _test_next:;
    return failures;
}

static int test_vc_bind_depfile_target(void)
{
    int failures = 0;
    static struct test_vc_fixture w;
    static struct zcl_fr_binding b;
    char other[ZCL_FR_TARGET_LEN + 1u];
    TEST("verify contract: a depfile whose -MT rule names another target "
         "refuses contract_depfile_target_mismatch even when the receipt "
         "hashes it") {
        const char *why = NULL;
        ASSERT(test_vc_fixture_make(&w, 'a'));
        test_vc_target(other, 'b');
        int n = snprintf(w.dep, sizeof(w.dep), "%s: %s\n", other,
                         ZCL_FR_SOURCE);
        ASSERT(n > 0 && (size_t)n < sizeof(w.dep));
        w.dep_len = (size_t)n;
        w.receipt.artifacts[1].size = w.dep_len;
        zcl_sha3_256((const uint8_t *)w.dep, w.dep_len,
                     w.receipt.artifacts[1].sha3);
        ASSERT(test_vc_receipt_reencode(&w, &why));
        ASSERT(vc_token(vc_bind(&w, &w.pins, &w.expected, &b),
                        ZCL_FR_WHY_DEPFILE_TARGET));
        ASSERT(vc_token(zcl_fr_depfile_target_check(
                            (const uint8_t *)"result.o: result.c\n", 19u,
                            w.target),
                        ZCL_FR_WHY_DEPFILE_TARGET));
        /* The expected target as a strict prefix of the rule name is
         * another target: result.o.tmp and result.object both refuse. */
        static const char *const suffixes[] = {".tmp", "bject"};
        for (size_t i = 0; i < 2u; i++) {
            ASSERT(test_vc_fixture_make(&w, 'a'));
            n = snprintf(w.dep, sizeof(w.dep), "%s%s: %s\n", w.target,
                         suffixes[i], ZCL_FR_SOURCE);
            ASSERT(n > 0 && (size_t)n < sizeof(w.dep));
            ASSERT(vc_token(zcl_fr_depfile_target_check(
                                (const uint8_t *)w.dep, (size_t)n, w.target),
                            ZCL_FR_WHY_DEPFILE_TARGET));
            w.dep_len = (size_t)n;
            w.receipt.artifacts[1].size = w.dep_len;
            zcl_sha3_256((const uint8_t *)w.dep, w.dep_len,
                         w.receipt.artifacts[1].sha3);
            ASSERT(test_vc_receipt_reencode(&w, &why));
            ASSERT(vc_token(vc_bind(&w, &w.pins, &w.expected, &b),
                            ZCL_FR_WHY_DEPFILE_TARGET));
        }
        /* Control: the exact rule name admits. */
        n = snprintf(w.dep, sizeof(w.dep), "%s: %s\n", w.target,
                     ZCL_FR_SOURCE);
        ASSERT(n > 0 && zcl_fr_depfile_target_check(
                            (const uint8_t *)w.dep, (size_t)n, w.target) == NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 6. signed record v2 admission against the binding ───────────────── */

static struct zcl_verify_attest_trust_root vc_root(bool with_box)
{
    struct zcl_verify_attest_trust_root root;
    uint8_t secret[32];
    memset(&root, 0, sizeof(root));
    root.loaded = true;
    ed25519_keypair(root.verifier_pubkey, secret, k_vc_verifier_seed);
    root.box.known = true;
    root.box.present = with_box;
    if (with_box) ed25519_keypair(root.box.pubkey, secret, k_vc_box_seed);
    return root;
}

static struct zcl_verify_attest_decision vc_admit(
    const struct test_vc_fixture *w, struct zcl_verify_attest_record r,
    const uint8_t seed[32], const struct zcl_verify_attest_binding *bound,
    const struct zcl_verify_attest_trust_root *root)
{
    uint8_t *rec = NULL;
    size_t len = 0;
    const char *why = NULL;
    struct zcl_verify_attest_decision d = {ZCL_VERIFY_ATTEST_REFUSE, "seal"};
    if (!zcl_verify_attest_seal(&r, seed, &rec, &len, &why)) return d;
    const struct zcl_fr_artifact_bytes a = test_vc_artifacts(w);
    d = zcl_verify_attest_admit(rec, len, a.object, a.object_len, a.depfile,
                                a.depfile_len, a.stderr_bytes, a.stderr_len,
                                bound, &w->expected, root);
    free(rec);
    return d;
}

static bool vc_refused(struct zcl_verify_attest_decision d, const char *want)
{
    return d.verdict == ZCL_VERIFY_ATTEST_REFUSE && vc_token(d.reason, want);
}

static int test_vc_record_binding(void)
{
    int failures = 0;
    static struct test_vc_fixture w, other;
    static struct zcl_fr_binding b;
    TEST("verify contract: a record admits only with the bound receipt; "
         "another receipt hash, target, profile, cwd or the box signer "
         "refuses by name") {
        struct zcl_verify_attest_trust_root root = vc_root(true);
        ASSERT(test_vc_fixture_make(&w, 'a'));
        ASSERT(vc_bind(&w, &w.pins, &w.expected, &b) == NULL);
        struct zcl_verify_attest_record r = test_vc_record(&w, 0);
        struct zcl_verify_attest_decision d =
            vc_admit(&w, r, k_vc_verifier_seed, &b.binding, &root);
        ASSERT(d.verdict == ZCL_VERIFY_ATTEST_ADMIT);
        /* Same everything, but sealed over another launch's receipt. */
        ASSERT(test_vc_fixture_make(&other, 'a'));
        other.receipt.mount_namespace_ino ^= 1u;
        ASSERT(test_vc_receipt_reencode(&other, NULL));
        memcpy(r.binding.receipt_sha3, other.binding.receipt_sha3, 32u);
        ASSERT(vc_refused(vc_admit(&w, r, k_vc_verifier_seed, &b.binding,
                                   &root),
                          ZCL_VERIFY_ATTEST_WHY_RECEIPT_MISMATCH));
        r = test_vc_record(&w, 0);
        char b_target[ZCL_FR_TARGET_LEN + 1u];
        test_vc_target(b_target, 'b');
        r.binding.target = (struct zcl_verify_attest_text){
            b_target, ZCL_FR_TARGET_LEN};
        ASSERT(vc_refused(vc_admit(&w, r, k_vc_verifier_seed, &b.binding,
                                   &root),
                          ZCL_VERIFY_ATTEST_WHY_TARGET_MISMATCH));
        r = test_vc_record(&w, 0);
        ASSERT(zcl_hex_decode_lower(ZCL_FR_RETIRED_STRICT_SHA3,
                                    r.binding.profile_sha3, 32u));
        ASSERT(vc_refused(vc_admit(&w, r, k_vc_verifier_seed, &b.binding,
                                   &root),
                          ZCL_VERIFY_ATTEST_WHY_PROFILE_MISMATCH));
        r = test_vc_record(&w, 0);
        ASSERT(zcl_hex_decode_lower(VC_RETIRED_FAST_SHA3,
                                    r.binding.profile_sha3, 32u));
        ASSERT(vc_refused(vc_admit(&w, r, k_vc_verifier_seed, &b.binding,
                                   &root),
                          ZCL_VERIFY_ATTEST_WHY_PROFILE_MISMATCH));
        r = test_vc_record(&w, 0);
        r.recorded_cwd = (struct zcl_verify_attest_text){"/src", 4u};
        ASSERT(vc_refused(vc_admit(&w, r, k_vc_verifier_seed, &b.binding,
                                   &root),
                          ZCL_VERIFY_ATTEST_WHY_CWD_MISMATCH));
        r = test_vc_record(&w, 0);
        ASSERT(vc_refused(vc_admit(&w, r, k_vc_box_seed, &b.binding, &root),
                          ZCL_VERIFY_ATTEST_WHY_SIGNED_BY_BOX));
        ASSERT(vc_refused(vc_admit(&w, r, k_vc_verifier_seed, NULL, &root),
                          ZCL_VERIFY_ATTEST_WHY_BINDING_MISSING));
        PASS();
    } _test_next:;
    return failures;
}

/* ── 7. store custody ────────────────────────────────────────────────── */

#if !defined(_WIN32)
/* A complete, admissible store for the fixture world: the only thing a
 * custody refusal can be reacting to is the uids named for it. */
struct vc_store {
    char root[PATH_MAX], key_dir[PATH_MAX], obs[PATH_MAX], pub[PATH_MAX];
};

static bool vc_path(char out[PATH_MAX], const char *a, const char *b)
{
    int n = snprintf(out, PATH_MAX, "%s/%s", a, b);
    return n > 0 && n < PATH_MAX;
}

static bool vc_file(const char *dir, const char *name, const void *bytes,
                    size_t len)
{
    char path[PATH_MAX];
    if (!vc_path(path, dir, name)) return false;
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (fd < 0) return false;
    size_t at = 0;
    while (at < len) {
        ssize_t n = write(fd, (const uint8_t *)bytes + at, len - at);
        if (n <= 0) break;
        at += (size_t)n;
    }
    bool ok = at == len && fchmod(fd, 0644) == 0;
    return close(fd) == 0 && ok;
}

/* The verifier-key loader refuses group-writable ancestors, which a
 * checkout may have, so the key alone lives in the system temp root. */
static bool vc_store_pubkey(struct vc_store *s)
{
    const char *prior = getenv("TMPDIR");
    char saved[PATH_MAX], made[PATH_MAX], dir[PATH_MAX], hex[66];
    uint8_t pub[32], secret[32];
    if (prior && snprintf(saved, sizeof(saved), "%s", prior) >= PATH_MAX)
        return false;
    if (unsetenv("TMPDIR") != 0) return false;
    bool created = platform_temp_directory_create("z23-verify-contract-",
                                                  made, sizeof(made));
    bool restored = prior ? setenv("TMPDIR", saved, 1) == 0
                          : unsetenv("TMPDIR") == 0;
    if (!created || !restored ||
        !platform_directory_canonical_real(made, dir, sizeof(dir)) ||
        !vc_path(s->pub, dir, "verifier.pub"))
        return false;
    ed25519_keypair(pub, secret, k_vc_verifier_seed);
    zcl_hex_encode(pub, 32, hex);
    hex[64] = '\n'; hex[65] = '\0';
    return vc_file(dir, "verifier.pub", hex, 65) &&
           setenv("ZCL_TEST_VERIFY_ATTEST_PUBKEY", s->pub, 1) == 0;
}

/* <root>/{store/<key>/, locks/fixed_result.lock} */
static bool vc_store_layout(struct vc_store *s, const struct test_vc_fixture *w)
{
    char made[PATH_MAX], store[PATH_MAX], locks[PATH_MAX];
    char key[ZCL_VERIFY_ATTEST_STORE_KEY_HEX];
    if (!test_mkdtemp(made, sizeof(made), "z23-verify-contract-store") ||
        !realpath(made, s->root))
        return false;
    zcl_verify_attest_store_key_hex(&w->expected.toolchain_id,
                                    &w->expected.argv_norm,
                                    &w->expected.recorded_cwd,
                                    w->expected.pp_sha3,
                                    w->expected.closure_sha3, key);
    return vc_path(store, s->root, "store") && mkdir(store, 0755) == 0 &&
           vc_path(locks, s->root, "locks") && mkdir(locks, 0755) == 0 &&
           vc_file(locks, "fixed_result.lock", "", 0) &&
           vc_path(s->key_dir, store, key) && mkdir(s->key_dir, 0755) == 0;
}

static bool vc_store_make(struct vc_store *s, const struct test_vc_fixture *w)
{
    struct zcl_verify_attest_record record = test_vc_record(w, 0);
    uint8_t *bytes = NULL, hash[32];
    size_t len = 0;
    const char *why = NULL;
    char name[65];
    memset(s, 0, sizeof(*s));
    if (!vc_store_layout(s, w) || !vc_store_pubkey(s) ||
        !zcl_verify_attest_seal(&record, k_vc_verifier_seed, &bytes, &len,
                                &why))
        return false;
    zcl_sha3_256(bytes, len, hash);
    zcl_hex_encode(hash, sizeof(hash), name);
    bool ok = vc_path(s->obs, s->key_dir, name) && mkdir(s->obs, 0755) == 0 &&
              vc_file(s->obs, "attest.bin", bytes, len) &&
              vc_file(s->obs, "object.o", TEST_VC_OBJ,
                      sizeof(TEST_VC_OBJ) - 1u) &&
              vc_file(s->obs, "deps.d", w->dep, w->dep_len) &&
              vc_file(s->obs, "stderr.bin", "", 0) &&
              vc_file(s->obs, "launch.bin", w->receipt_bytes, w->receipt_len);
    free(bytes);
    return ok;
}

static bool vc_store_is(const struct vc_store *s, const struct test_vc_fixture *w,
                        unsigned signer, unsigned publisher, bool same_uid,
                        enum zcl_verify_store_verdict verdict, const char *why)
{
    struct zcl_verify_store_result r;
    struct zcl_verify_attest_box_key box = {.known = true};
    zcl_verify_store_lookup_fixture(s->root, signer, publisher, same_uid,
                                    &w->expected, &w->pins, &box, &r);
    bool ok = r.verdict == verdict &&
              (why ? vc_token(r.reason, why)
                   : r.object_len == sizeof(TEST_VC_OBJ) - 1u);
    zcl_verify_store_result_release(&r);
    return ok;
}

static int vc_store_remove(const char *path, const struct stat *st, int type,
                           struct FTW *walk)
{
    (void)st; (void)type; (void)walk;
    return remove(path);
}
#endif

static int test_vc_store_same_uid(void)
{
    int failures = 0;
    TEST("verify contract: a store entry that HITs under the fixture's "
         "same-uid waiver refuses store_owner_same_uid on custody alone, "
         "and other uids pass custody to the ownership walk") {
#if defined(_WIN32)
        PASS();
#else
        static struct test_vc_fixture w;
        static struct vc_store s;
        const unsigned me = (unsigned)geteuid();
        ASSERT(test_vc_fixture_make(&w, 'a'));
        ASSERT(vc_store_make(&s, &w));
        /* Positive path: these exact bytes admit and return the object. */
        ASSERT(vc_store_is(&s, &w, me, me, true, ZCL_VERIFY_STORE_HIT, NULL));
        /* Same bytes, no waiver: the developer uid as signer, publisher or
         * both refuses before any file is read. */
        ASSERT(vc_store_is(&s, &w, me, me, false, ZCL_VERIFY_STORE_COLD,
                           "store_owner_same_uid"));
        ASSERT(vc_store_is(&s, &w, me + 1u, me, false, ZCL_VERIFY_STORE_COLD,
                           "store_owner_same_uid"));
        ASSERT(vc_store_is(&s, &w, me, me + 1u, false, ZCL_VERIFY_STORE_COLD,
                           "store_owner_same_uid"));
        /* Other uids pass custody on the same valid store and stop at the
         * next check, which finds the root not owned by the named signer;
         * with the signer matching, store/ is not the named publisher's.
         * A HIT under two foreign uids needs root to chown the fixture. */
        ASSERT(vc_store_is(&s, &w, me + 1u, me + 2u, false,
                           ZCL_VERIFY_STORE_COLD, "store_path_unsafe"));
        ASSERT(vc_store_is(&s, &w, me, me + 2u, true, ZCL_VERIFY_STORE_COLD,
                           "store_path_unsafe"));
        ASSERT(unsetenv("ZCL_TEST_VERIFY_ATTEST_PUBKEY") == 0);
        ASSERT(nftw(s.root, vc_store_remove, 16, FTW_DEPTH | FTW_PHYS) == 0);
        char *slash = strrchr(s.pub, '/');
        ASSERT(slash && unlink(s.pub) == 0);
        *slash = '\0';
        ASSERT(rmdir(s.pub) == 0);
        PASS();
#endif
    } _test_next:;
    return failures;
}

/* ── 8. key v2 against the checked-in fast profile ───────────────────── */

struct vc_key {
    uint8_t profile[8192];
    size_t profile_len;
    char lines[8192], cwd_arg[512];
    const char *argv[(ZCL_FR_PROFILE_ARGC + 10u)];
    char target_a[ZCL_FR_TARGET_LEN + 1u], target_b[ZCL_FR_TARGET_LEN + 1u];
    struct zcl_fixed_result_v2_roots roots;
    struct zcl_fixed_result_v2_expected a, b;
    uint8_t pp[32];
};

static const char *const k_vc_env[4] = {"LC_ALL=C", "TZ=UTC", "TMPDIR=/tmp",
                                        "PATH=/usr/bin:/bin"};

static bool vc_key_argv(struct vc_key *k)
{
    size_t count = 0;
    char *line = k->lines;
    memcpy(k->lines, k->profile, k->profile_len);
    for (size_t i = 0; i < k->profile_len; i++) {
        if (k->lines[i] != '\n') continue;
        if (count >= ZCL_FR_PROFILE_ARGC) return false;
        k->lines[i] = '\0';
        char *tag = strstr(line, "@CWD@");
        k->argv[count++] = line;
        if (tag) {
            int n = snprintf(k->cwd_arg, sizeof(k->cwd_arg), "%.*s%s%s",
                             (int)(tag - line), line, VC_KEY_CWD, tag + 5);
            if (n <= 0 || (size_t)n >= sizeof(k->cwd_arg)) return false;
            k->argv[count - 1u] = k->cwd_arg;
        }
        line = k->lines + i + 1u;
    }
    static const char *const tail[10] = {
        "-MMD", "-MP", "-MF", "/work/result.ABC123/deps.d", "-MT", NULL,
        "-c", "-o", "/work/result.ABC123/result.o", ZCL_FR_SOURCE};
    for (size_t i = 0; i < 10u; i++) k->argv[ZCL_FR_PROFILE_ARGC + i] = tail[i];
    return count == ZCL_FR_PROFILE_ARGC;
}

static bool vc_key_setup(struct vc_key *k)
{
    FILE *file = fopen("tools/verify/fixed_result_fast.args", "rb");
    if (!file) return false;
    k->profile_len = fread(k->profile, 1, sizeof(k->profile), file);
    if (fclose(file) != 0 || k->profile_len != 5939u) return false;
    uint8_t *fields = (uint8_t *)&k->roots;
    for (size_t i = 0; i < sizeof(k->roots); i++)
        fields[i] = (uint8_t)(1u + i / 32u);
    zcl_sha3_256(k->profile, k->profile_len, k->roots.profile_args);
    zcl_fr_env_fixed_root(k->roots.environment);
    memset(k->pp, 0x5a, sizeof(k->pp));
    test_vc_target(k->target_a, 'a');
    test_vc_target(k->target_b, 'b');
    return vc_key_argv(k);
}

static bool vc_key_make(struct vc_key *k, const char *target,
                        const char *const *envp,
                        struct zcl_fixed_result_v2_expected *out,
                        const char **why)
{
    k->argv[ZCL_FR_PROFILE_ARGC + 5u] = target;
    return zcl_fixed_result_expected_v2(
        &k->roots, k->roots.source_content, k->pp, target, k->profile,
        k->profile_len, VC_KEY_CWD, k->argv, (ZCL_FR_PROFILE_ARGC + 10u), envp, 4u, -1, out, why);
}

static int test_vc_key_v2(void)
{
    int failures = 0;
    static struct vc_key k;
    char hex[65];
    TEST("verify contract: key v2 over the fast profile pins its closure, "
         "is epoch-invariant, and refuses strict, TMPDIR=/work and "
         "test-rel-obj") {
        const char *why = NULL;
        ASSERT(vc_key_setup(&k));
        zcl_hex_encode(k.roots.profile_args, 32u, hex);
        ASSERT_STR_EQ(hex, ZCL_FR_PROFILE_SHA3);
        ASSERT(vc_key_make(&k, k.target_a, k_vc_env, &k.a, &why));
        zcl_hex_encode(k.a.expected.closure_sha3, 32u, hex);
        ASSERT_STR_EQ(hex, VC_KEY_V2_CLOSURE);
        ASSERT(strncmp(k.a.toolchain_id, ZCL_FR_TOOLCHAIN_PREFIX,
                       strlen(ZCL_FR_TOOLCHAIN_PREFIX)) == 0);
        ASSERT(k.a.expected.recorded_cwd.len == strlen(ZCL_FR_CWD));
        ASSERT(vc_key_make(&k, k.target_b, k_vc_env, &k.b, &why));
        ASSERT_STR_EQ(k.a.argv_norm, k.b.argv_norm);
        ASSERT(memcmp(k.a.expected.closure_sha3, k.b.expected.closure_sha3,
                      32u) == 0);
        ASSERT(!vc_key_make(&k, VC_TARGET_REL_OBJ, k_vc_env, &k.b, &why));
        ASSERT(vc_token(why, "fixed_result_v2_arguments_invalid"));
        static const char *const env_work[4] = {
            "LC_ALL=C", "TZ=UTC", "TMPDIR=/work", "PATH=/usr/bin:/bin"};
        ASSERT(!vc_key_make(&k, k.target_a, env_work, &k.b, &why));
        ASSERT(vc_token(why, "fixed_result_v2_arguments_invalid"));
        ASSERT(zcl_hex_decode_lower(ZCL_FR_RETIRED_STRICT_SHA3,
                                    k.roots.profile_args, 32u));
        ASSERT(!vc_key_make(&k, k.target_a, k_vc_env, &k.b, &why));
        ASSERT(vc_token(why, "fixed_result_v2_root_mismatch"));
        PASS();
    } _test_next:;
    return failures;
}

/* The key the receiver builds is the one its receipt binding accepts. */
static int test_vc_key_v2_binds(void)
{
    int failures = 0;
    static struct vc_key k;
    static struct test_vc_fixture w;
    static struct zcl_fr_binding b;
    TEST("verify contract: the key v2 expectation binds a receipt from the "
         "same pins and refuses one naming gcc13") {
        const char *why = NULL;
        ASSERT(vc_key_setup(&k));
        ASSERT(test_vc_fixture_make(&w, 'a'));
        k.roots = w.pins;
        memcpy(k.pp, w.receipt.artifacts[3].sha3, 32u);
        ASSERT(vc_key_make(&k, k.target_a, k_vc_env, &k.a, &why));
        ASSERT(vc_bind(&w, &w.pins, &k.a.expected, &b) == NULL);
        k.a.expected.toolchain_id = (struct zcl_verify_attest_text){
            VC_GCC13_TOOLCHAIN, strlen(VC_GCC13_TOOLCHAIN)};
        ASSERT(vc_token(vc_bind(&w, &w.pins, &k.a.expected, &b),
                        ZCL_FR_WHY_RECEIPT_INPUT));
        PASS();
    } _test_next:;
    return failures;
}

int test_verify_contract(void)
{
    int failures = 0;
    failures += test_vc_pins_roundtrip();
    failures += test_vc_pins_framing();
    failures += test_vc_pins_domains();
    failures += test_vc_pins_values();
    failures += test_vc_request();
    failures += test_vc_packet();
    failures += test_vc_receipt_roundtrip();
    failures += test_vc_receipt_fields();
    failures += test_vc_receipt_framing();
    failures += test_vc_bind();
    failures += test_vc_bind_depfile_target();
    failures += test_vc_record_binding();
    failures += test_vc_store_same_uid();
    failures += test_vc_key_v2();
    failures += test_vc_key_v2_binds();
    return failures;
}
