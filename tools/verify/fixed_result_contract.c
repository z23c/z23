/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: Pure encode, parse and validate for z23verify.fixed_result.v2.
 *          See fixed_result_contract.h and docs/work/verifier-contract-v2.md. */
#include "verify/fixed_result_contract.h"

#include "base/hex.h"
#include "base/serialize_le.h"

#include <stddef.h>
#include <string.h>

#define FR_TARGET_PREFIX "build/test-obj/epochs/"
#define FR_TARGET_SUFFIX "/platform/modules/base/src/result.o"
#define FR_SCRATCH_PREFIX "/work/result."
#define FR_OBJECT_MAX (8u * 1024u * 1024u)
#define FR_OUTPUT_MAX (4u * 1024u * 1024u)

static void fr_why(const char **why, const char *token)
{
    if (why) *why = token;
}

static bool fr_eq(const uint8_t *p, size_t n, const char *s)
{
    return n == strlen(s) && memcmp(p, s, n) == 0;
}

static bool fr_zero(const uint8_t *p, size_t n)
{
    uint8_t v = 0;
    for (size_t i = 0; i < n; i++) v |= p[i];
    return v == 0;
}

static bool fr_graph(const uint8_t *p, size_t n)
{
    if (n == 0) return false;
    for (size_t i = 0; i < n; i++)
        if (p[i] < 0x21u || p[i] > 0x7eu) return false;
    return true;
}

/* `n` lowercase hex digits (n even, at most 64), checked by the one codec. */
static bool fr_lower_hex(const char *s, size_t n)
{
    char text[65];
    uint8_t bytes[32];
    if (n == 0 || n > 64u || n % 2u != 0) return false;
    memcpy(text, s, n);
    text[n] = '\0';
    return zcl_hex_decode_lower(text, bytes, n / 2u);
}

static bool fr_is(const char *why, const char *token)
{
    return why && strcmp(why, token) == 0;
}

/* ── Writer ───────────────────────────────────────────────────────────── */

void zcl_fr_writer_buffer(struct zcl_fr_writer *w, uint8_t *buf, size_t cap)
{
    *w = (struct zcl_fr_writer){buf, buf ? cap : 0u, 0u, NULL, true};
}

void zcl_fr_writer_hash(struct zcl_fr_writer *w, struct sha3_256_ctx *hash)
{
    *w = (struct zcl_fr_writer){NULL, 0u, 0u, hash, hash != NULL};
}

static void fr_raw(struct zcl_fr_writer *w, const void *p, size_t n)
{
    if (!w->ok) return;
    if (w->hash) {
        if (n) sha3_256_write(w->hash, p, n);
        w->len += n;
        return;
    }
    if (n > w->cap - w->len) {
        w->ok = false;
        return;
    }
    if (n) memcpy(w->buf + w->len, p, n);
    w->len += n;
}

void zcl_fr_put(struct zcl_fr_writer *w, const void *bytes, size_t len)
{
    uint8_t prefix[8];
    zcl_write_u64_le(prefix, (uint64_t)len);
    fr_raw(w, prefix, sizeof(prefix));
    fr_raw(w, bytes, len);
}

void zcl_fr_put_text(struct zcl_fr_writer *w, const char *label,
                     const char *text)
{
    zcl_fr_put(w, label, strlen(label));
    zcl_fr_put(w, text, strlen(text));
}

void zcl_fr_put_hash(struct zcl_fr_writer *w, const char *label,
                     const uint8_t hash[32])
{
    zcl_fr_put(w, label, strlen(label));
    zcl_fr_put(w, hash, 32u);
}

void zcl_fr_put_u64(struct zcl_fr_writer *w, const char *label,
                    uint64_t value)
{
    uint8_t bytes[8];
    zcl_write_u64_le(bytes, value);
    zcl_fr_put(w, label, strlen(label));
    zcl_fr_put(w, bytes, sizeof(bytes));
}

/* ── Decoder ──────────────────────────────────────────────────────────── */

struct fr_cursor {
    const uint8_t *p;
    size_t n;
    size_t at;
};

static const char *fr_frame(struct fr_cursor *c, size_t max,
                            const uint8_t **out, size_t *len)
{
    size_t left = c->n - c->at;
    if (left == 0) return ZCL_FR_WHY_FIELD_MISSING;
    if (left < 8u) return ZCL_FR_WHY_TRUNCATED;
    uint64_t n = zcl_read_u64_le(c->p + c->at);
    if (n > max) return ZCL_FR_WHY_OVERSIZE;
    if (n > left - 8u) return ZCL_FR_WHY_TRUNCATED;
    *out = c->p + c->at + 8u;
    *len = (size_t)n;
    c->at += 8u + (size_t)n;
    return NULL;
}

static const char *const k_fr_v1_headers[] = {
    "z23verify.launch.v1\n", "z23verify.fixed_result.pins.v1\n",
    "z23vcc.result.fast.v1\n", "z23.vcc.fixed_result.fast.v1\n",
    "z23verify.fixed_result.env.v1\n",
};

static const char *const k_fr_v2_domains[] = {
    ZCL_FR_DOMAIN_PINS, ZCL_FR_DOMAIN_REQUEST, ZCL_FR_DOMAIN_PACKET,
    ZCL_FR_DOMAIN_RECEIPT, ZCL_FR_DOMAIN_ENV, ZCL_FR_DOMAIN_EXEC_ARGV,
    ZCL_FR_DOMAIN_CLOSURE, ZCL_FR_DOMAIN_FAILURE,
};

static bool fr_v1_header(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < sizeof(k_fr_v1_headers) / sizeof(k_fr_v1_headers[0]);
         i++) {
        size_t h = strlen(k_fr_v1_headers[i]);
        if (n >= h && memcmp(p, k_fr_v1_headers[i], h) == 0) return true;
    }
    return false;
}

/* A domain spelled as raw text (LF- or NUL-terminated) instead of a
 * length-prefixed frame: its first bytes are ASCII, never a small u64. */
static bool fr_text_framed(const uint8_t *p, size_t n)
{
    return n >= 3u && memcmp(p, "z23", 3u) == 0;
}

static const char *fr_domain(struct fr_cursor *c, const char *domain)
{
    const uint8_t *d = NULL;
    size_t n = 0;
    const char *why = fr_frame(c, ZCL_FR_DOMAIN_MAX, &d, &n);
    if (fr_is(why, ZCL_FR_WHY_OVERSIZE) && fr_text_framed(c->p, c->n))
        return ZCL_FR_WHY_DOMAIN_MALFORMED;
    if (why) return fr_is(why, ZCL_FR_WHY_FIELD_MISSING) ? ZCL_FR_WHY_TRUNCATED
                                                    : why;
    if (!fr_graph(d, n)) return ZCL_FR_WHY_DOMAIN_MALFORMED;
    if (fr_eq(d, n, domain)) return NULL;
    for (size_t i = 0; i < sizeof(k_fr_v2_domains) / sizeof(k_fr_v2_domains[0]);
         i++)
        if (fr_eq(d, n, k_fr_v2_domains[i])) return ZCL_FR_WHY_WRONG_ARTIFACT;
    return ZCL_FR_WHY_VERSION_UNKNOWN;
}

static size_t fr_kind_max(const struct zcl_fr_spec *s)
{
    if (s->kind == ZCL_FR_KIND_ROOT) return 32u;
    if (s->kind == ZCL_FR_KIND_U64) return 8u;
    return s->max;
}

static const char *fr_root_check(const uint8_t *p, size_t n)
{
    if (n != 32u) return ZCL_FR_WHY_FIELD_MALFORMED;
    return fr_zero(p, n) ? ZCL_FR_WHY_HASH_ZERO : NULL;
}

static const char *fr_value_check(const struct zcl_fr_spec *s,
                                  const uint8_t *p, size_t n)
{
    if (n > fr_kind_max(s)) return ZCL_FR_WHY_OVERSIZE;
    if (n && !p) return ZCL_FR_WHY_ARGUMENTS;
    bool ok = false;
    switch (s->kind) {
    case ZCL_FR_KIND_TEXT: ok = fr_graph(p, n); break;
    case ZCL_FR_KIND_ROOT: return fr_root_check(p, n);
    case ZCL_FR_KIND_U64: ok = n == 8u; break;
    case ZCL_FR_KIND_BLOB: ok = n == 0 || !memchr(p, 0, n); break;
    case ZCL_FR_KIND_EXACT: ok = n == s->max; break;
    default: return ZCL_FR_WHY_ARGUMENTS;
    }
    return ok ? NULL : ZCL_FR_WHY_FIELD_MALFORMED;
}

static const char *fr_field(struct fr_cursor *c, const struct zcl_fr_spec *s,
                            struct zcl_fr_value *out)
{
    const uint8_t *label = NULL;
    size_t label_len = 0;
    const char *why = fr_frame(c, ZCL_FR_LABEL_MAX, &label, &label_len);
    if (fr_is(why, ZCL_FR_WHY_OVERSIZE)) return ZCL_FR_WHY_FIELD_ORDER;
    if (why) return why;
    if (!fr_eq(label, label_len, s->label)) return ZCL_FR_WHY_FIELD_ORDER;
    why = fr_frame(c, fr_kind_max(s), &out->bytes, &out->len);
    if (why) return fr_is(why, ZCL_FR_WHY_FIELD_MISSING) ? ZCL_FR_WHY_TRUNCATED
                                                    : why;
    why = fr_value_check(s, out->bytes, out->len);
    if (!why && s->kind == ZCL_FR_KIND_U64)
        out->u64 = zcl_read_u64_le(out->bytes);
    return why;
}

const char *zcl_fr_decode_prefix(const uint8_t *bytes, size_t len,
                                 const char *domain,
                                 const struct zcl_fr_spec *spec, size_t count,
                                 struct zcl_fr_value *out, size_t *used)
{
    if ((!bytes && len) || !domain || !spec || !out || !used)
        return ZCL_FR_WHY_ARGUMENTS;
    *used = 0;
    memset(out, 0, count * sizeof(*out));
    if (bytes && fr_v1_header(bytes, len)) return ZCL_FR_WHY_V1_RETIRED;
    struct fr_cursor c = {bytes, len, 0u};
    const char *why = fr_domain(&c, domain);
    if (why) return why;
    size_t fields_used = 0;
    why = zcl_fr_decode_fields(bytes + c.at, len - c.at, spec, count, out,
                               &fields_used);
    if (!why) *used = c.at + fields_used;
    return why;
}

const char *zcl_fr_decode_fields(const uint8_t *bytes, size_t len,
                                 const struct zcl_fr_spec *spec, size_t count,
                                 struct zcl_fr_value *out, size_t *used)
{
    if ((!bytes && len) || !spec || !out || !used)
        return ZCL_FR_WHY_ARGUMENTS;
    *used = 0;
    struct fr_cursor c = {bytes, len, 0u};
    const char *why = NULL;
    for (size_t i = 0; !why && i < count; i++)
        why = fr_field(&c, &spec[i], &out[i]);
    if (why) {
        memset(out, 0, count * sizeof(*out));
        return why;
    }
    *used = c.at;
    return NULL;
}

const char *zcl_fr_decode(const uint8_t *bytes, size_t len,
                          const char *domain,
                          const struct zcl_fr_spec *spec, size_t count,
                          struct zcl_fr_value *out)
{
    size_t used = 0;
    const char *why = zcl_fr_decode_prefix(bytes, len, domain, spec, count,
                                           out, &used);
    if (!why && used != len) {
        memset(out, 0, count * sizeof(*out));
        why = ZCL_FR_WHY_TRAILING;
    }
    return why;
}

const char *zcl_fr_encode(struct zcl_fr_writer *w, const char *domain,
                          const struct zcl_fr_spec *spec, size_t count,
                          const struct zcl_fr_value *values)
{
    if (!w || !domain || !spec || !values) return ZCL_FR_WHY_ARGUMENTS;
    for (size_t i = 0; i < count; i++) {
        if (spec[i].kind == ZCL_FR_KIND_U64) continue;
        const char *why = fr_value_check(&spec[i], values[i].bytes,
                                         values[i].len);
        if (why) return why;
    }
    zcl_fr_put(w, domain, strlen(domain));
    for (size_t i = 0; i < count; i++) {
        if (spec[i].kind == ZCL_FR_KIND_U64) {
            zcl_fr_put_u64(w, spec[i].label, values[i].u64);
            continue;
        }
        zcl_fr_put(w, spec[i].label, strlen(spec[i].label));
        zcl_fr_put(w, values[i].bytes, values[i].len);
    }
    return w->ok ? NULL : ZCL_FR_WHY_BUFFER;
}

/* ── Fixed inputs ─────────────────────────────────────────────────────── */

static const char *const k_fr_env[] = {
    "LC_ALL=C", "TZ=UTC", "TMPDIR=/tmp", "PATH=/usr/bin:/bin"
};
#define FR_ENV_COUNT (sizeof(k_fr_env) / sizeof(k_fr_env[0]))

void zcl_fr_env_root(const char *const *envp, size_t count, uint8_t out[32])
{
    struct sha3_256_ctx h;
    struct zcl_fr_writer w;
    sha3_256_init(&h);
    zcl_fr_writer_hash(&w, &h);
    zcl_fr_put(&w, ZCL_FR_DOMAIN_ENV, strlen(ZCL_FR_DOMAIN_ENV));
    for (size_t i = 0; i < count; i++)
        zcl_fr_put_text(&w, "env", envp[i] ? envp[i] : "");
    sha3_256_finalize(&h, out);
}

void zcl_fr_env_fixed_root(uint8_t out[32])
{
    zcl_fr_env_root(k_fr_env, FR_ENV_COUNT, out);
}

const char *zcl_fr_env_check(const char *const *envp, size_t count)
{
    if (!envp || count != FR_ENV_COUNT) return ZCL_FR_WHY_ENV;
    for (size_t i = 0; i < count; i++)
        if (!envp[i] || strcmp(envp[i], k_fr_env[i]) != 0)
            return ZCL_FR_WHY_ENV;
    return NULL;
}

bool zcl_fr_exec_argv_sha3(const char *const *argv, size_t count,
                           uint8_t out[32])
{
    if (!argv || count == 0 || !out) return false;
    for (size_t i = 0; i < count; i++)
        if (!argv[i]) return false;
    struct sha3_256_ctx h;
    struct zcl_fr_writer w;
    sha3_256_init(&h);
    zcl_fr_writer_hash(&w, &h);
    zcl_fr_put(&w, ZCL_FR_DOMAIN_EXEC_ARGV, strlen(ZCL_FR_DOMAIN_EXEC_ARGV));
    for (size_t i = 0; i < count; i++) zcl_fr_put_text(&w, "arg", argv[i]);
    sha3_256_finalize(&h, out);
    return true;
}

const char *zcl_fr_target_check(const char *target, size_t len)
{
    static const char prefix[] = FR_TARGET_PREFIX;
    static const char suffix[] = FR_TARGET_SUFFIX;
    size_t a = sizeof(prefix) - 1u, b = sizeof(suffix) - 1u;
    if (!target || len != ZCL_FR_TARGET_LEN || memchr(target, 0, len) ||
        memcmp(target, prefix, a) != 0 ||
        memcmp(target + a + 64u, suffix, b) != 0 ||
        !fr_lower_hex(target + a, 64u))
        return ZCL_FR_WHY_TARGET;
    return NULL;
}

const char *zcl_fr_scratch_check(const char *scratch, size_t len)
{
    static const char prefix[] = FR_SCRATCH_PREFIX;
    size_t a = sizeof(prefix) - 1u;
    if (!scratch || len != ZCL_FR_SCRATCH_LEN ||
        memcmp(scratch, prefix, a) != 0)
        return ZCL_FR_WHY_SCRATCH;
    for (size_t i = a; i < len; i++) {
        char ch = scratch[i];
        bool alnum = (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z') ||
                     (ch >= 'a' && ch <= 'z');
        if (!alnum) return ZCL_FR_WHY_SCRATCH;
    }
    return NULL;
}

const char *zcl_fr_depfile_target_check(const uint8_t *dep, size_t dep_len,
                                        const char *target)
{
    size_t n = target ? strlen(target) : 0u;
    if (!dep || n == 0 || dep_len <= n || memcmp(dep, target, n) != 0 ||
        dep[n] != ':')
        return ZCL_FR_WHY_DEPFILE_TARGET;
    return NULL;
}

/* ── Roots and pins ───────────────────────────────────────────────────── */

#define FR_ROOT(label) {label, ZCL_FR_KIND_ROOT, 32u}
#define FR_ROOT_SPECS \
    FR_ROOT("source_content_sha3"), FR_ROOT("profile_args_sha3"), \
    FR_ROOT("source_image_sha3"), FR_ROOT("tool_image_sha3"), \
    FR_ROOT("worker_sha3"), FR_ROOT("launcher_sha3"), \
    FR_ROOT("check_image_sha3"), FR_ROOT("environment_sha3"), \
    FR_ROOT("policy_sha3"), FR_ROOT("seccomp_filter_sha3"), \
    FR_ROOT("bwrap_sha3"), FR_ROOT("tree_checker_sha3")

static const struct zcl_fr_spec k_fr_roots[ZCL_FR_ROOT_COUNT] = {
    FR_ROOT_SPECS
};

#define FR_ROOT_OFFSET(field) offsetof(struct zcl_fixed_result_v2_roots, field)
static const size_t k_fr_root_offset[ZCL_FR_ROOT_COUNT] = {
    FR_ROOT_OFFSET(source_content), FR_ROOT_OFFSET(profile_args),
    FR_ROOT_OFFSET(source_image), FR_ROOT_OFFSET(tool_image),
    FR_ROOT_OFFSET(worker), FR_ROOT_OFFSET(launcher),
    FR_ROOT_OFFSET(check_image), FR_ROOT_OFFSET(environment),
    FR_ROOT_OFFSET(policy), FR_ROOT_OFFSET(seccomp_filter),
    FR_ROOT_OFFSET(bwrap), FR_ROOT_OFFSET(tree_checker),
};

const char *zcl_fr_root_label(size_t index)
{
    return index < ZCL_FR_ROOT_COUNT ? k_fr_roots[index].label : NULL;
}

uint8_t *zcl_fr_root_slot(struct zcl_fixed_result_v2_roots *roots,
                          size_t index)
{
    if (!roots || index >= ZCL_FR_ROOT_COUNT) return NULL;
    return (uint8_t *)roots + k_fr_root_offset[index];
}

const uint8_t *zcl_fr_root_at(const struct zcl_fixed_result_v2_roots *r,
                              size_t index)
{
    if (!r || index >= ZCL_FR_ROOT_COUNT) return NULL;
    return (const uint8_t *)r + k_fr_root_offset[index];
}

static bool fr_hex_eq(const uint8_t hash[32], const char *hex)
{
    char encoded[65];
    zcl_hex_encode(hash, 32u, encoded);
    return strcmp(encoded, hex) == 0;
}

const char *zcl_fr_roots_check(const struct zcl_fixed_result_v2_roots *r)
{
    if (!r) return ZCL_FR_WHY_ARGUMENTS;
    for (size_t i = 0; i < ZCL_FR_ROOT_COUNT; i++)
        if (fr_zero(zcl_fr_root_at(r, i), 32u)) return ZCL_FR_WHY_HASH_ZERO;
    if (!fr_hex_eq(r->profile_args, ZCL_FR_PROFILE_SHA3))
        return ZCL_FR_WHY_PROFILE;
    uint8_t env[32];
    zcl_fr_env_fixed_root(env);
    return memcmp(env, r->environment, 32u) == 0 ? NULL : ZCL_FR_WHY_ENV;
}

static struct zcl_fr_value fr_text_value(const char *s)
{
    return (struct zcl_fr_value){(const uint8_t *)s, s ? strlen(s) : 0u, 0u};
}

static struct zcl_fr_value fr_hash_value(const uint8_t hash[32])
{
    return (struct zcl_fr_value){hash, 32u, 0u};
}

static struct zcl_fr_value fr_u64_value(uint64_t v)
{
    return (struct zcl_fr_value){NULL, 0u, v};
}

static void fr_roots_values(const struct zcl_fixed_result_v2_roots *r,
                            struct zcl_fr_value *out)
{
    for (size_t i = 0; i < ZCL_FR_ROOT_COUNT; i++)
        out[i] = fr_hash_value(zcl_fr_root_at(r, i));
}

static void fr_roots_take(const struct zcl_fr_value *in,
                          struct zcl_fixed_result_v2_roots *r)
{
    for (size_t i = 0; i < ZCL_FR_ROOT_COUNT; i++)
        memcpy(zcl_fr_root_slot(r, i), in[i].bytes, 32u);
}

static const char *fr_profile_check(const struct zcl_fr_value *v)
{
    return fr_eq(v->bytes, v->len, ZCL_FR_PROFILE) ? NULL : ZCL_FR_WHY_PROFILE;
}

static const struct zcl_fr_spec k_fr_pins_spec[] = {
    {"profile", ZCL_FR_KIND_TEXT, ZCL_FR_LABEL_MAX}, FR_ROOT_SPECS
};
#define FR_PINS_FIELDS (sizeof(k_fr_pins_spec) / sizeof(k_fr_pins_spec[0]))

static bool fr_finish(const char *reason, size_t used, size_t *len,
                      const char **why)
{
    fr_why(why, reason);
    if (len) *len = reason ? 0u : used;
    return reason == NULL;
}

bool zcl_fr_pins_encode(const struct zcl_fixed_result_v2_roots *roots,
                        uint8_t *out, size_t cap, size_t *len,
                        const char **why)
{
    if (!len) return fr_finish(ZCL_FR_WHY_ARGUMENTS, 0u, NULL, why);
    const char *reason = zcl_fr_roots_check(roots);
    struct zcl_fr_writer w;
    zcl_fr_writer_buffer(&w, out, cap);
    if (!reason) {
        struct zcl_fr_value v[FR_PINS_FIELDS];
        v[0] = fr_text_value(ZCL_FR_PROFILE);
        fr_roots_values(roots, &v[1]);
        reason = zcl_fr_encode(&w, ZCL_FR_DOMAIN_PINS, k_fr_pins_spec,
                               FR_PINS_FIELDS, v);
    }
    return fr_finish(reason, w.len, len, why);
}

bool zcl_fr_pins_parse(const uint8_t *bytes, size_t len,
                       struct zcl_fixed_result_v2_roots *out,
                       const char **why)
{
    if (!out) return fr_finish(ZCL_FR_WHY_ARGUMENTS, 0u, NULL, why);
    memset(out, 0, sizeof(*out));
    struct zcl_fr_value v[FR_PINS_FIELDS];
    const char *reason = zcl_fr_decode(bytes, len, ZCL_FR_DOMAIN_PINS,
                                       k_fr_pins_spec, FR_PINS_FIELDS, v);
    if (!reason) reason = fr_profile_check(&v[0]);
    if (!reason) {
        fr_roots_take(&v[1], out);
        reason = zcl_fr_roots_check(out);
    }
    if (reason) memset(out, 0, sizeof(*out));
    return fr_finish(reason, 0u, NULL, why);
}

/* ── Launch request ───────────────────────────────────────────────────── */

static const struct zcl_fr_spec k_fr_request_spec[] = {
    {"profile", ZCL_FR_KIND_TEXT, ZCL_FR_LABEL_MAX},
    {"recorded_cwd", ZCL_FR_KIND_TEXT, ZCL_FR_TEXT_MAX},
    {"target", ZCL_FR_KIND_TEXT, ZCL_FR_TEXT_MAX},
};
#define FR_REQUEST_FIELDS \
    (sizeof(k_fr_request_spec) / sizeof(k_fr_request_spec[0]))

static const char *fr_cwd_check(const struct zcl_fr_value *v)
{
    return fr_eq(v->bytes, v->len, ZCL_FR_CWD) ? NULL : ZCL_FR_WHY_CWD;
}

bool zcl_fr_request_encode(const char *target, uint8_t *out, size_t cap,
                           size_t *len, const char **why)
{
    if (!len || !target)
        return fr_finish(ZCL_FR_WHY_ARGUMENTS, 0u, NULL, why);
    const char *reason = zcl_fr_target_check(target, strlen(target));
    struct zcl_fr_writer w;
    zcl_fr_writer_buffer(&w, out, cap);
    if (!reason) {
        const struct zcl_fr_value v[FR_REQUEST_FIELDS] = {
            fr_text_value(ZCL_FR_PROFILE), fr_text_value(ZCL_FR_CWD),
            fr_text_value(target)};
        reason = zcl_fr_encode(&w, ZCL_FR_DOMAIN_REQUEST, k_fr_request_spec,
                               FR_REQUEST_FIELDS, v);
    }
    return fr_finish(reason, w.len, len, why);
}

static void fr_copy_text(char *dst, const struct zcl_fr_value *v)
{
    memcpy(dst, v->bytes, v->len);
    dst[v->len] = '\0';
}

bool zcl_fr_request_parse(const uint8_t *bytes, size_t len,
                          char target[ZCL_FR_TARGET_LEN + 1u],
                          const char **why)
{
    if (!target) return fr_finish(ZCL_FR_WHY_ARGUMENTS, 0u, NULL, why);
    target[0] = '\0';
    struct zcl_fr_value v[FR_REQUEST_FIELDS];
    const char *reason = zcl_fr_decode(bytes, len, ZCL_FR_DOMAIN_REQUEST,
                                       k_fr_request_spec, FR_REQUEST_FIELDS,
                                       v);
    if (!reason) reason = fr_profile_check(&v[0]);
    if (!reason) reason = fr_cwd_check(&v[1]);
    if (!reason)
        reason = zcl_fr_target_check((const char *)v[2].bytes, v[2].len);
    if (!reason) fr_copy_text(target, &v[2]);
    return fr_finish(reason, 0u, NULL, why);
}

/* ── Worker result packet ─────────────────────────────────────────────── */

static const char *const k_fr_artifact_names[ZCL_FR_ARTIFACT_COUNT] = {
    "object.o", "deps.d", "stderr.bin", "preprocessed.i"
};

static bool fr_known_artifact(const char *name)
{
    for (size_t i = 0; i < ZCL_FR_ARTIFACT_COUNT; i++)
        if (strcmp(name, k_fr_artifact_names[i]) == 0) return true;
    return false;
}

static bool fr_duplicate_name(const char *const *names, size_t count)
{
    for (size_t i = 0; i < count; i++)
        for (size_t j = i + 1u; j < count; j++)
            if (strcmp(names[i], names[j]) == 0) return true;
    return false;
}

const char *zcl_fr_artifact_names_check(const char *const *names,
                                        size_t count)
{
    if (!names) return ZCL_FR_WHY_ARGUMENTS;
    for (size_t i = 0; i < count; i++)
        if (!names[i] || !fr_known_artifact(names[i]))
            return ZCL_FR_WHY_ARTIFACT_UNKNOWN;
    if (fr_duplicate_name(names, count)) return ZCL_FR_WHY_ARTIFACT_DUPLICATE;
    if (count != ZCL_FR_ARTIFACT_COUNT) return ZCL_FR_WHY_ARTIFACT_ORDER;
    for (size_t i = 0; i < count; i++)
        if (strcmp(names[i], k_fr_artifact_names[i]) != 0)
            return ZCL_FR_WHY_ARTIFACT_ORDER;
    return NULL;
}

static const struct zcl_fr_spec k_fr_packet_spec[] = {
    {"profile", ZCL_FR_KIND_TEXT, ZCL_FR_LABEL_MAX},
    {"scratch", ZCL_FR_KIND_TEXT, ZCL_FR_TEXT_MAX},
    {"target", ZCL_FR_KIND_TEXT, ZCL_FR_TEXT_MAX},
    FR_ROOT("compile_argv_sha3"), FR_ROOT("preprocess_argv_sha3"),
    FR_ROOT("environment_sha3"),
    {"artifact", ZCL_FR_KIND_TEXT, ZCL_FR_LABEL_MAX},
    {"artifact", ZCL_FR_KIND_TEXT, ZCL_FR_LABEL_MAX},
    {"artifact", ZCL_FR_KIND_TEXT, ZCL_FR_LABEL_MAX},
    {"artifact", ZCL_FR_KIND_TEXT, ZCL_FR_LABEL_MAX},
};
#define FR_PACKET_FIELDS (sizeof(k_fr_packet_spec) / sizeof(k_fr_packet_spec[0]))
#define FR_PACKET_ARTIFACT0 6u

static const char *fr_env_root_check(const uint8_t root[32])
{
    uint8_t env[32];
    zcl_fr_env_fixed_root(env);
    return memcmp(env, root, 32u) == 0 ? NULL : ZCL_FR_WHY_ENV;
}

static const char *fr_packet_check(const struct zcl_fr_packet *p)
{
    const char *why = zcl_fr_scratch_check(p->scratch, strlen(p->scratch));
    if (!why) why = zcl_fr_target_check(p->target, strlen(p->target));
    if (!why) why = fr_env_root_check(p->environment_sha3);
    return why;
}

bool zcl_fr_packet_encode(const struct zcl_fr_packet *packet, uint8_t *out,
                          size_t cap, size_t *len, const char **why)
{
    if (!len || !packet)
        return fr_finish(ZCL_FR_WHY_ARGUMENTS, 0u, NULL, why);
    const char *reason = fr_packet_check(packet);
    struct zcl_fr_writer w;
    zcl_fr_writer_buffer(&w, out, cap);
    if (!reason) {
        struct zcl_fr_value v[FR_PACKET_FIELDS] = {
            fr_text_value(ZCL_FR_PROFILE), fr_text_value(packet->scratch),
            fr_text_value(packet->target),
            fr_hash_value(packet->compile_argv_sha3),
            fr_hash_value(packet->preprocess_argv_sha3),
            fr_hash_value(packet->environment_sha3)};
        for (size_t i = 0; i < ZCL_FR_ARTIFACT_COUNT; i++)
            v[FR_PACKET_ARTIFACT0 + i] = fr_text_value(k_fr_artifact_names[i]);
        reason = zcl_fr_encode(&w, ZCL_FR_DOMAIN_PACKET, k_fr_packet_spec,
                               FR_PACKET_FIELDS, v);
    }
    return fr_finish(reason, w.len, len, why);
}

static const char *fr_packet_names(const struct zcl_fr_value *v)
{
    char names[ZCL_FR_ARTIFACT_COUNT][ZCL_FR_LABEL_MAX + 1u];
    const char *view[ZCL_FR_ARTIFACT_COUNT];
    for (size_t i = 0; i < ZCL_FR_ARTIFACT_COUNT; i++) {
        fr_copy_text(names[i], &v[FR_PACKET_ARTIFACT0 + i]);
        view[i] = names[i];
    }
    return zcl_fr_artifact_names_check(view, ZCL_FR_ARTIFACT_COUNT);
}

static const char *fr_packet_take(const struct zcl_fr_value *v,
                                  struct zcl_fr_packet *out)
{
    const char *why = fr_profile_check(&v[0]);
    if (!why && v[1].len != ZCL_FR_SCRATCH_LEN) why = ZCL_FR_WHY_SCRATCH;
    if (!why && v[2].len != ZCL_FR_TARGET_LEN) why = ZCL_FR_WHY_TARGET;
    if (!why) why = fr_packet_names(v);
    if (why) return why;
    fr_copy_text(out->scratch, &v[1]);
    fr_copy_text(out->target, &v[2]);
    memcpy(out->compile_argv_sha3, v[3].bytes, 32u);
    memcpy(out->preprocess_argv_sha3, v[4].bytes, 32u);
    memcpy(out->environment_sha3, v[5].bytes, 32u);
    return fr_packet_check(out);
}

bool zcl_fr_packet_parse(const uint8_t *bytes, size_t len,
                         struct zcl_fr_packet *out, const char **why)
{
    if (!out) return fr_finish(ZCL_FR_WHY_ARGUMENTS, 0u, NULL, why);
    memset(out, 0, sizeof(*out));
    struct zcl_fr_value v[FR_PACKET_FIELDS];
    const char *reason = zcl_fr_decode(bytes, len, ZCL_FR_DOMAIN_PACKET,
                                       k_fr_packet_spec, FR_PACKET_FIELDS, v);
    if (!reason) reason = fr_packet_take(v, out);
    if (reason) memset(out, 0, sizeof(*out));
    return fr_finish(reason, 0u, NULL, why);
}

/* ── Launch receipt ───────────────────────────────────────────────────── */

struct fr_fixed_u64 {
    const char *label;
    uint64_t value;
};

/* The observed worker identity. Any other value is not a qualified launch;
 * the launcher must refuse rather than write a receipt carrying it. */
static const struct fr_fixed_u64 k_fr_identity[] = {
    {"compiler_ruid", ZCL_FR_COMPILER_UID},
    {"compiler_euid", ZCL_FR_COMPILER_UID},
    {"compiler_suid", ZCL_FR_COMPILER_UID},
    {"compiler_rgid", ZCL_FR_COMPILER_UID},
    {"compiler_egid", ZCL_FR_COMPILER_UID},
    {"compiler_sgid", ZCL_FR_COMPILER_UID},
    {"supplementary_groups", 0u}, {"cap_effective", 0u},
    {"cap_permitted", 0u}, {"cap_inheritable", 0u}, {"cap_ambient", 0u},
    {"no_new_privs", 1u}, {"seccomp_mode", 2u}, {"worker_exit", 0u},
};
#define FR_IDENTITY_COUNT (sizeof(k_fr_identity) / sizeof(k_fr_identity[0]))

#define FR_U64(label) {label, ZCL_FR_KIND_U64, 8u}
#define FR_TEXT(label) {label, ZCL_FR_KIND_TEXT, ZCL_FR_TEXT_MAX}
/* Fields 1-37, shared by the launch receipt and the failure receipt. */
#define FR_LAUNCH_HEAD_SPECS \
    {"profile", ZCL_FR_KIND_TEXT, ZCL_FR_LABEL_MAX}, \
    {"launch_id", ZCL_FR_KIND_TEXT, ZCL_FR_ID_LEN}, \
    {"request_nonce", ZCL_FR_KIND_TEXT, ZCL_FR_ID_LEN}, \
    FR_TEXT("recorded_cwd"), FR_TEXT("source"), FR_TEXT("target"), \
    FR_TEXT("toolchain_id"), \
    FR_ROOT_SPECS, \
    FR_TEXT("scratch"), \
    FR_ROOT("compile_argv_sha3"), FR_ROOT("preprocess_argv_sha3"), \
    FR_U64("mount_namespace_dev"), FR_U64("mount_namespace_ino"), \
    FR_U64("compiler_ruid"), FR_U64("compiler_euid"), \
    FR_U64("compiler_suid"), FR_U64("compiler_rgid"), \
    FR_U64("compiler_egid"), FR_U64("compiler_sgid"), \
    FR_U64("supplementary_groups"), FR_U64("cap_effective"), \
    FR_U64("cap_permitted"), FR_U64("cap_inheritable"), \
    FR_U64("cap_ambient"), FR_U64("no_new_privs"), FR_U64("seccomp_mode")
static const struct zcl_fr_spec k_fr_receipt_spec[] = {
    FR_LAUNCH_HEAD_SPECS,
    FR_U64("worker_exit"),
    FR_U64("object_size"), FR_ROOT("object_sha3"),
    FR_U64("deps_size"), FR_ROOT("deps_sha3"),
    FR_U64("stderr_size"), FR_ROOT("stderr_sha3"),
    FR_U64("preprocessed_size"), FR_ROOT("preprocessed_sha3"),
};
#define FR_RECEIPT_FIELDS \
    (sizeof(k_fr_receipt_spec) / sizeof(k_fr_receipt_spec[0]))

enum {
    FR_R_PROFILE = 0, FR_R_LAUNCH_ID, FR_R_NONCE, FR_R_CWD, FR_R_SOURCE,
    FR_R_TARGET, FR_R_TOOLCHAIN, FR_R_ROOTS,
    FR_R_SCRATCH = FR_R_ROOTS + ZCL_FR_ROOT_COUNT,
    FR_R_COMPILE_ARGV, FR_R_PREPROCESS_ARGV, FR_R_MNT_DEV, FR_R_MNT_INO,
    FR_R_IDENTITY, FR_R_ARTIFACTS = FR_R_IDENTITY + FR_IDENTITY_COUNT,
};

static_assert(FR_R_ARTIFACTS + 2u * ZCL_FR_ARTIFACT_COUNT == FR_RECEIPT_FIELDS,
              "receipt field table and index map disagree");

static void fr_toolchain_expected(const uint8_t tool_image[32],
                                  char out[ZCL_FR_TOOLCHAIN_LEN + 1u])
{
    char hex[65];
    zcl_hex_encode(tool_image, 32u, hex);
    memcpy(out, ZCL_FR_TOOLCHAIN_PREFIX, sizeof(ZCL_FR_TOOLCHAIN_PREFIX) - 1u);
    memcpy(out + sizeof(ZCL_FR_TOOLCHAIN_PREFIX) - 1u, hex, 65u);
}

static const char *fr_receipt_ids(const struct zcl_fr_receipt *r)
{
    if (strlen(r->launch_id) != ZCL_FR_ID_LEN ||
        strlen(r->request_nonce) != ZCL_FR_ID_LEN ||
        !fr_lower_hex(r->launch_id, ZCL_FR_ID_LEN) ||
        !fr_lower_hex(r->request_nonce, ZCL_FR_ID_LEN))
        return ZCL_FR_WHY_FIELD_MALFORMED;
    return NULL;
}

static const char *fr_receipt_sizes(const struct zcl_fr_receipt *r)
{
    const struct zcl_fr_artifact_digest *a = r->artifacts;
    if (a[0].size == 0 || a[0].size > FR_OBJECT_MAX || a[1].size == 0 ||
        a[1].size > FR_OUTPUT_MAX || a[2].size > FR_OUTPUT_MAX ||
        a[3].size == 0 || a[3].size > FR_OUTPUT_MAX)
        return ZCL_FR_WHY_FIELD_MALFORMED;
    return NULL;
}

/* The checks fields 1-37 alone can answer, for either receipt kind. */
static const char *fr_launch_head_check(const struct zcl_fr_receipt *r)
{
    char toolchain[ZCL_FR_TOOLCHAIN_LEN + 1u];
    const char *why = fr_receipt_ids(r);
    if (!why) why = zcl_fr_target_check(r->target, strlen(r->target));
    if (!why) why = zcl_fr_roots_check(&r->pins);
    if (!why) fr_toolchain_expected(r->pins.tool_image, toolchain);
    if (!why && strcmp(r->toolchain_id, toolchain) != 0)
        why = ZCL_FR_WHY_TOOLCHAIN;
    if (!why) why = zcl_fr_scratch_check(r->scratch, strlen(r->scratch));
    if (!why && (fr_zero(r->compile_argv_sha3, 32u) ||
                 fr_zero(r->preprocess_argv_sha3, 32u)))
        why = ZCL_FR_WHY_HASH_ZERO;
    return why;
}

/* Every check the struct alone can answer; shared by encode and parse. */
static const char *fr_receipt_check(const struct zcl_fr_receipt *r)
{
    const char *why = fr_launch_head_check(r);
    if (!why) why = fr_receipt_sizes(r);
    return why;
}

static void fr_receipt_values(const struct zcl_fr_receipt *r,
                              struct zcl_fr_value *v)
{
    v[FR_R_PROFILE] = fr_text_value(ZCL_FR_PROFILE);
    v[FR_R_LAUNCH_ID] = fr_text_value(r->launch_id);
    v[FR_R_NONCE] = fr_text_value(r->request_nonce);
    v[FR_R_CWD] = fr_text_value(ZCL_FR_CWD);
    v[FR_R_SOURCE] = fr_text_value(ZCL_FR_SOURCE);
    v[FR_R_TARGET] = fr_text_value(r->target);
    v[FR_R_TOOLCHAIN] = fr_text_value(r->toolchain_id);
    fr_roots_values(&r->pins, &v[FR_R_ROOTS]);
    v[FR_R_SCRATCH] = fr_text_value(r->scratch);
    v[FR_R_COMPILE_ARGV] = fr_hash_value(r->compile_argv_sha3);
    v[FR_R_PREPROCESS_ARGV] = fr_hash_value(r->preprocess_argv_sha3);
    v[FR_R_MNT_DEV] = fr_u64_value(r->mount_namespace_dev);
    v[FR_R_MNT_INO] = fr_u64_value(r->mount_namespace_ino);
    for (size_t i = 0; i < FR_IDENTITY_COUNT; i++)
        v[FR_R_IDENTITY + i] = fr_u64_value(k_fr_identity[i].value);
    for (size_t i = 0; i < ZCL_FR_ARTIFACT_COUNT; i++) {
        v[FR_R_ARTIFACTS + 2u * i] = fr_u64_value(r->artifacts[i].size);
        v[FR_R_ARTIFACTS + 2u * i + 1u] = fr_hash_value(r->artifacts[i].sha3);
    }
}

bool zcl_fr_receipt_encode(const struct zcl_fr_receipt *receipt,
                           uint8_t *out, size_t cap, size_t *len,
                           const char **why)
{
    if (!len || !receipt)
        return fr_finish(ZCL_FR_WHY_ARGUMENTS, 0u, NULL, why);
    const char *reason = fr_receipt_check(receipt);
    struct zcl_fr_writer w;
    zcl_fr_writer_buffer(&w, out, cap);
    if (!reason) {
        struct zcl_fr_value v[FR_RECEIPT_FIELDS];
        fr_receipt_values(receipt, v);
        reason = zcl_fr_encode(&w, ZCL_FR_DOMAIN_RECEIPT, k_fr_receipt_spec,
                               FR_RECEIPT_FIELDS, v);
    }
    return fr_finish(reason, w.len, len, why);
}

static const char *fr_receipt_fixed(const struct zcl_fr_value *v)
{
    const char *why = fr_profile_check(&v[FR_R_PROFILE]);
    if (!why) why = fr_cwd_check(&v[FR_R_CWD]);
    if (!why && !fr_eq(v[FR_R_SOURCE].bytes, v[FR_R_SOURCE].len,
                       ZCL_FR_SOURCE))
        why = ZCL_FR_WHY_SOURCE;
    for (size_t i = 0; !why && i < FR_IDENTITY_COUNT; i++) {
        if (v[FR_R_IDENTITY + i].u64 == k_fr_identity[i].value) continue;
        why = strcmp(k_fr_identity[i].label, "worker_exit") == 0
                  ? ZCL_FR_WHY_WORKER_EXIT : ZCL_FR_WHY_IDENTITY;
    }
    return why;
}

/* Length gates before copying into fixed buffers: a wrong-length target
 * or toolchain is named by its own token, not a buffer overflow. */
static const char *fr_receipt_lengths(const struct zcl_fr_value *v)
{
    if (v[FR_R_TARGET].len != ZCL_FR_TARGET_LEN) return ZCL_FR_WHY_TARGET;
    if (v[FR_R_TOOLCHAIN].len != ZCL_FR_TOOLCHAIN_LEN)
        return ZCL_FR_WHY_TOOLCHAIN;
    if (v[FR_R_SCRATCH].len != ZCL_FR_SCRATCH_LEN) return ZCL_FR_WHY_SCRATCH;
    if (v[FR_R_LAUNCH_ID].len != ZCL_FR_ID_LEN ||
        v[FR_R_NONCE].len != ZCL_FR_ID_LEN)
        return ZCL_FR_WHY_FIELD_MALFORMED;
    return NULL;
}

static void fr_receipt_take(const struct zcl_fr_value *v,
                            struct zcl_fr_receipt *r)
{
    fr_copy_text(r->launch_id, &v[FR_R_LAUNCH_ID]);
    fr_copy_text(r->request_nonce, &v[FR_R_NONCE]);
    fr_copy_text(r->target, &v[FR_R_TARGET]);
    fr_copy_text(r->toolchain_id, &v[FR_R_TOOLCHAIN]);
    fr_roots_take(&v[FR_R_ROOTS], &r->pins);
    fr_copy_text(r->scratch, &v[FR_R_SCRATCH]);
    memcpy(r->compile_argv_sha3, v[FR_R_COMPILE_ARGV].bytes, 32u);
    memcpy(r->preprocess_argv_sha3, v[FR_R_PREPROCESS_ARGV].bytes, 32u);
    r->mount_namespace_dev = v[FR_R_MNT_DEV].u64;
    r->mount_namespace_ino = v[FR_R_MNT_INO].u64;
    for (size_t i = 0; i < ZCL_FR_ARTIFACT_COUNT; i++) {
        r->artifacts[i].size = v[FR_R_ARTIFACTS + 2u * i].u64;
        memcpy(r->artifacts[i].sha3, v[FR_R_ARTIFACTS + 2u * i + 1u].bytes,
               32u);
    }
}

bool zcl_fr_receipt_parse(const uint8_t *bytes, size_t len,
                          struct zcl_fr_receipt *out, const char **why)
{
    if (!out) return fr_finish(ZCL_FR_WHY_ARGUMENTS, 0u, NULL, why);
    memset(out, 0, sizeof(*out));
    struct zcl_fr_value v[FR_RECEIPT_FIELDS];
    const char *reason = zcl_fr_decode(bytes, len, ZCL_FR_DOMAIN_RECEIPT,
                                       k_fr_receipt_spec, FR_RECEIPT_FIELDS,
                                       v);
    if (!reason) reason = fr_receipt_fixed(v);
    if (!reason) reason = fr_receipt_lengths(v);
    if (!reason) {
        fr_receipt_take(v, out);
        reason = fr_receipt_check(out);
    }
    if (reason) memset(out, 0, sizeof(*out));
    return fr_finish(reason, 0u, NULL, why);
}

/* ── Binding ──────────────────────────────────────────────────────────── */

static const char *fr_bind_pins(const struct zcl_fr_receipt *r,
                                const struct zcl_fixed_result_v2_roots *pins)
{
    for (size_t i = 0; i < ZCL_FR_ROOT_COUNT; i++)
        if (memcmp(zcl_fr_root_at(&r->pins, i), zcl_fr_root_at(pins, i), 32u) != 0)
            return ZCL_FR_WHY_PIN_MISMATCH;
    return NULL;
}

static bool fr_text_is(const struct zcl_verify_attest_text *t, const char *s)
{
    size_t n = strlen(s);
    return t->len == n && (n == 0 || (t->bytes && memcmp(t->bytes, s, n) == 0));
}

static const char *fr_bind_inputs(const struct zcl_fr_receipt *r,
                                  const struct zcl_verify_attest_expected *e)
{
    if (!fr_text_is(&e->toolchain_id, r->toolchain_id) ||
        !fr_text_is(&e->recorded_cwd, ZCL_FR_CWD) ||
        memcmp(e->pp_sha3, r->artifacts[3].sha3, 32u) != 0)
        return ZCL_FR_WHY_RECEIPT_INPUT;
    return NULL;
}

static bool fr_digest_is(const struct zcl_fr_artifact_digest *d,
                         const uint8_t *bytes, size_t len)
{
    uint8_t hash[32];
    if (!bytes && len) return false;
    zcl_sha3_256(bytes ? bytes : (const uint8_t *)"", len, hash);
    return d->size == (uint64_t)len && memcmp(hash, d->sha3, 32u) == 0;
}

static const char *fr_bind_artifacts(const struct zcl_fr_receipt *r,
                                     const struct zcl_fr_artifact_bytes *a)
{
    if (!fr_digest_is(&r->artifacts[0], a->object, a->object_len) ||
        !fr_digest_is(&r->artifacts[1], a->depfile, a->depfile_len) ||
        !fr_digest_is(&r->artifacts[2], a->stderr_bytes, a->stderr_len))
        return ZCL_FR_WHY_RECEIPT_ARTIFACT;
    return zcl_fr_depfile_target_check(a->depfile, a->depfile_len,
                                       r->target);
}

static void fr_binding_fill(const struct zcl_fr_receipt *r,
                            const struct zcl_fixed_result_v2_roots *pins,
                            const uint8_t *receipt, size_t receipt_len,
                            struct zcl_fr_binding *out)
{
    memcpy(out->target, r->target, sizeof(out->target));
    out->binding.contract = (struct zcl_verify_attest_text){
        ZCL_FR_CONTRACT, sizeof(ZCL_FR_CONTRACT) - 1u};
    memcpy(out->binding.profile_sha3, pins->profile_args, 32u);
    out->binding.target = (struct zcl_verify_attest_text){
        out->target, strlen(out->target)};
    zcl_sha3_256(receipt, receipt_len, out->binding.receipt_sha3);
}

bool zcl_fr_receipt_bind(const uint8_t *receipt, size_t receipt_len,
                         const struct zcl_fixed_result_v2_roots *pins,
                         const struct zcl_verify_attest_expected *expected,
                         const struct zcl_fr_artifact_bytes *artifacts,
                         struct zcl_fr_binding *out, const char **why)
{
    if (!out || !receipt || !pins || !expected || !artifacts)
        return fr_finish(ZCL_FR_WHY_ARGUMENTS, 0u, NULL, why);
    memset(out, 0, sizeof(*out));
    struct zcl_fr_receipt r;
    const char *reason = NULL;
    if (!zcl_fr_receipt_parse(receipt, receipt_len, &r, &reason))
        return fr_finish(reason, 0u, NULL, why);
    reason = fr_bind_pins(&r, pins);
    if (!reason) reason = fr_bind_inputs(&r, expected);
    if (!reason) reason = fr_bind_artifacts(&r, artifacts);
    if (!reason) fr_binding_fill(&r, pins, receipt, receipt_len, out);
    return fr_finish(reason, 0u, NULL, why);
}

/* ── Failure receipt ──────────────────────────────────────────────────── */

#define FR_F_EXIT (FR_R_IDENTITY + FR_IDENTITY_COUNT - 1u)
#define FR_F_OUTPUTS (FR_F_EXIT + 1u)
static const struct zcl_fr_spec k_fr_failure_spec[] = {
    FR_LAUNCH_HEAD_SPECS,
    FR_U64("compile_exit"),
    FR_U64("stderr_size"), FR_ROOT("stderr_sha3"),
    FR_U64("preprocessed_size"), FR_ROOT("preprocessed_sha3"),
};
#define FR_FAILURE_FIELDS \
    (sizeof(k_fr_failure_spec) / sizeof(k_fr_failure_spec[0]))
static_assert(FR_F_OUTPUTS + 4u == FR_FAILURE_FIELDS,
              "failure field table and index map disagree");

static const char *fr_failure_check(const struct zcl_fr_failure *f)
{
    const struct zcl_fr_artifact_digest *a = f->launch.artifacts;
    const char *why = fr_launch_head_check(&f->launch);
    if (!why && (a[0].size != 0u || !fr_zero(a[0].sha3, 32u) ||
                 a[1].size != 0u || !fr_zero(a[1].sha3, 32u) ||
                 a[2].size > FR_OUTPUT_MAX || a[3].size == 0u ||
                 a[3].size > FR_OUTPUT_MAX))
        why = ZCL_FR_WHY_FIELD_MALFORMED;
    if (!why && (f->compile_exit == 0u || f->compile_exit > 255u))
        why = ZCL_FR_WHY_FAILURE_EXIT;
    return why;
}

/* A failure's fields laid out as a launch receipt with worker_exit 0 and
 * an empty object and depfile, so the receipt's own checks and copies
 * serve both kinds. */
static void fr_failure_as_receipt(const struct zcl_fr_value *f,
                                  struct zcl_fr_value *r)
{
    static const uint8_t zero[32] = {0};
    for (size_t i = 0; i < FR_F_EXIT; i++) r[i] = f[i];
    r[FR_F_EXIT] = fr_u64_value(0u);
    for (size_t i = 0; i < 2u; i++) {
        r[FR_R_ARTIFACTS + 2u * i] = fr_u64_value(0u);
        r[FR_R_ARTIFACTS + 2u * i + 1u] = fr_hash_value(zero);
    }
    for (size_t i = 0; i < 4u; i++) r[FR_R_ARTIFACTS + 4u + i] = f[FR_F_OUTPUTS + i];
}

bool zcl_fr_failure_encode(const struct zcl_fr_failure *failure,
                           uint8_t *out, size_t cap, size_t *len,
                           const char **why)
{
    if (!len || !failure)
        return fr_finish(ZCL_FR_WHY_ARGUMENTS, 0u, NULL, why);
    const char *reason = fr_failure_check(failure);
    struct zcl_fr_writer w;
    zcl_fr_writer_buffer(&w, out, cap);
    if (!reason) {
        struct zcl_fr_value r[FR_RECEIPT_FIELDS], v[FR_FAILURE_FIELDS];
        fr_receipt_values(&failure->launch, r);
        for (size_t i = 0; i < FR_F_EXIT; i++) v[i] = r[i];
        v[FR_F_EXIT] = fr_u64_value(failure->compile_exit);
        for (size_t i = 0; i < 4u; i++)
            v[FR_F_OUTPUTS + i] = r[FR_R_ARTIFACTS + 4u + i];
        reason = zcl_fr_encode(&w, ZCL_FR_DOMAIN_FAILURE, k_fr_failure_spec,
                               FR_FAILURE_FIELDS, v);
    }
    return fr_finish(reason, w.len, len, why);
}

bool zcl_fr_failure_parse(const uint8_t *bytes, size_t len,
                          struct zcl_fr_failure *out, const char **why)
{
    if (!out) return fr_finish(ZCL_FR_WHY_ARGUMENTS, 0u, NULL, why);
    memset(out, 0, sizeof(*out));
    struct zcl_fr_value v[FR_FAILURE_FIELDS], r[FR_RECEIPT_FIELDS];
    const char *reason = zcl_fr_decode(bytes, len, ZCL_FR_DOMAIN_FAILURE,
                                       k_fr_failure_spec, FR_FAILURE_FIELDS,
                                       v);
    if (!reason) {
        fr_failure_as_receipt(v, r);
        reason = fr_receipt_fixed(r);
    }
    if (!reason) reason = fr_receipt_lengths(r);
    if (!reason) {
        fr_receipt_take(r, &out->launch);
        out->compile_exit = v[FR_F_EXIT].u64;
        reason = fr_failure_check(out);
    }
    if (reason) memset(out, 0, sizeof(*out));
    return fr_finish(reason, 0u, NULL, why);
}
/* ── Source content root v2 ───────────────────────────────────────────── */

/* Relative, non-empty, no trailing slash, no empty, "." or ".." component. */
static bool fr_source_path_ok(const char *p)
{
    size_t n = p ? strlen(p) : 0u;
    if (n == 0u || p[0] == '/' || p[n - 1u] == '/') return false;
    for (const char *s = p; s < p + n; s += strcspn(s, "/") + 1u) {
        size_t c = strcspn(s, "/");
        if (c == 0u || (c <= 2u && strncmp(s, "..", c) == 0)) return false;
    }
    return true;
}

bool zcl_fr_source_content_v2(const char *const *paths,
                              const uint8_t *const *bytes,
                              const size_t *lens, size_t count,
                              uint8_t out[32], const char **why)
{
    static const char domain[] = ZCL_FR_DOMAIN_SOURCE_CONTENT;
    struct sha3_256_ctx h;
    struct zcl_fr_writer w;
    const char *reason = paths && bytes && lens && out && count > 0u
                             ? NULL : ZCL_FR_WHY_ARGUMENTS;
    sha3_256_init(&h);
    zcl_fr_writer_hash(&w, &h);
    zcl_fr_put(&w, domain, sizeof(domain) - 1u);
    for (size_t i = 0; !reason && i < count; i++) {
        if (!fr_source_path_ok(paths[i]) || (!bytes[i] && lens[i] > 0u))
            reason = ZCL_FR_WHY_FIELD_MALFORMED;
        else if (i > 0u && strcmp(paths[i - 1u], paths[i]) >= 0)
            reason = ZCL_FR_WHY_FIELD_ORDER;
        else {
            zcl_fr_put_text(&w, "path", paths[i]);
            zcl_fr_put(&w, "bytes", 5u);
            zcl_fr_put(&w, bytes[i], lens[i]);
        }
    }
    if (!reason) sha3_256_finalize(&h, out);
    fr_why(why, reason);
    return reason == NULL;
}
