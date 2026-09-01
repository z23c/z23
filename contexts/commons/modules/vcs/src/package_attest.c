/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_attest — implementation of the external-verifier attestation
 * codec declared in vcs/package_attest.h. Pure bytes: no filesystem, no
 * compiler, no execution, no keys (verify-only, exactly the
 * package_release.* doctrine). The node NEVER compiles or executes
 * downloaded code; attestations are produced by the separate
 * zclassic23-package-verify program (slice 6). */

#include "vcs/package_attest.h"

#include "crypto/sha3.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include "vcs_priv.h"

#include <secp256k1.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ATTEST_LOG "vcs.attest"

static const uint8_t attest_wire_magic[VCS_PACKAGE_ATTEST_WIRE_MAGIC_BYTES] =
    { 'Z', 'C', 'L', 'A', 'T', 'T', '\r', '\n' };
static const uint8_t attest_id_domain[] = VCS_PACKAGE_ATTEST_ID_DOMAIN;

/* The vendored libsecp256k1 archive does not export the
 * secp256k1_context_static symbol, so this layer keeps its own verify-only
 * context, created once at load time — the package_release.c pattern. */
static secp256k1_context *attest_verify_ctx;

__attribute__((constructor))
static void attest_verify_ctx_init(void)
{
    attest_verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
}

__attribute__((destructor))
static void attest_verify_ctx_destroy(void)
{
    if (attest_verify_ctx)
        secp256k1_context_destroy(attest_verify_ctx);
}

/* secp256k1 group order half, n/2, big-endian: the low-S bound. */
static const uint8_t attest_half_order[32] = {
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
    0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
};

/* ── stable strings ───────────────────────────────────────────────── */

const char *vcs_package_attest_error_string(
    enum vcs_package_attest_error error)
{
    switch (error) {
    case VCS_PACKAGE_ATTEST_OK: return "ok";
    case VCS_PACKAGE_ATTEST_ERR_NULL: return "null-argument";
    case VCS_PACKAGE_ATTEST_ERR_ALLOC: return "allocation-failure";
    case VCS_PACKAGE_ATTEST_ERR_SCHEMA_VERSION: return "schema-version";
    case VCS_PACKAGE_ATTEST_ERR_WIRE_MAGIC: return "wire-magic";
    case VCS_PACKAGE_ATTEST_ERR_WIRE_OVERSIZE: return "wire-oversize";
    case VCS_PACKAGE_ATTEST_ERR_WIRE_TRUNCATED: return "wire-truncated";
    case VCS_PACKAGE_ATTEST_ERR_WIRE_TRAILING: return "wire-trailing";
    case VCS_PACKAGE_ATTEST_ERR_PACKAGE_ROOT: return "package-root-zero";
    case VCS_PACKAGE_ATTEST_ERR_RELEASE_ID: return "release-id-zero";
    case VCS_PACKAGE_ATTEST_ERR_RECIPE_ROOT: return "recipe-root-zero";
    case VCS_PACKAGE_ATTEST_ERR_RESULT_CLASS: return "result-class";
    case VCS_PACKAGE_ATTEST_ERR_DETAIL_CODE: return "detail-code";
    case VCS_PACKAGE_ATTEST_ERR_DETAIL_TEXT: return "detail-text";
    case VCS_PACKAGE_ATTEST_ERR_DETAIL_REQUIRED: return "detail-required";
    case VCS_PACKAGE_ATTEST_ERR_DETAIL_FORBIDDEN: return "detail-forbidden";
    case VCS_PACKAGE_ATTEST_ERR_COMPILER_COUNT: return "compiler-count";
    case VCS_PACKAGE_ATTEST_ERR_COMPILER_ID: return "compiler-id";
    case VCS_PACKAGE_ATTEST_ERR_COMPILER_VERSION: return "compiler-version";
    case VCS_PACKAGE_ATTEST_ERR_COMPILER_OUTCOME: return "compiler-outcome";
    case VCS_PACKAGE_ATTEST_ERR_COMPILER_ORDER: return "compiler-order";
    case VCS_PACKAGE_ATTEST_ERR_SANITIZER_COUNT: return "sanitizer-count";
    case VCS_PACKAGE_ATTEST_ERR_SANITIZER_NAME: return "sanitizer-name";
    case VCS_PACKAGE_ATTEST_ERR_SANITIZER_OUTCOME: return "sanitizer-outcome";
    case VCS_PACKAGE_ATTEST_ERR_SANITIZER_ORDER: return "sanitizer-order";
    case VCS_PACKAGE_ATTEST_ERR_SANITIZER_FINDINGS:
        return "sanitizer-findings-class";
    case VCS_PACKAGE_ATTEST_ERR_TEST_FLAG: return "test-flag";
    case VCS_PACKAGE_ATTEST_ERR_TEST_EXIT: return "test-exit-canonical";
    case VCS_PACKAGE_ATTEST_ERR_TEST_CLASS: return "test-class-mismatch";
    case VCS_PACKAGE_ATTEST_ERR_OUTCOME_CLASS: return "outcome-class-mismatch";
    case VCS_PACKAGE_ATTEST_ERR_ISOLATION: return "isolation-level";
    case VCS_PACKAGE_ATTEST_ERR_PUBKEY: return "verifier-pubkey";
    case VCS_PACKAGE_ATTEST_ERR_SIG_LOW_S: return "signature-low-s";
    case VCS_PACKAGE_ATTEST_ERR_SIG_VERIFY: return "signature-verify";
    }
    return "unknown-error";
}

const char *vcs_package_attest_result_string(uint8_t result_class)
{
    switch (result_class) {
    case VCS_PACKAGE_ATTEST_RESULT_BUILD_PASS: return "build-pass";
    case VCS_PACKAGE_ATTEST_RESULT_BUILD_FAIL: return "build-fail";
    case VCS_PACKAGE_ATTEST_RESULT_TEST_PASS: return "test-pass";
    case VCS_PACKAGE_ATTEST_RESULT_TEST_FAIL: return "test-fail";
    case VCS_PACKAGE_ATTEST_RESULT_SANITIZER_FAIL: return "sanitizer-fail";
    }
    return "unknown";
}

const char *vcs_package_attest_detail_string(uint8_t detail_code)
{
    switch (detail_code) {
    case VCS_PACKAGE_ATTEST_DETAIL_NONE: return "none";
    case VCS_PACKAGE_ATTEST_DETAIL_COMPILE_ERROR: return "compile-error";
    case VCS_PACKAGE_ATTEST_DETAIL_COMPILE_TIMEOUT: return "compile-timeout";
    case VCS_PACKAGE_ATTEST_DETAIL_LINK_ERROR: return "link-error";
    case VCS_PACKAGE_ATTEST_DETAIL_TEST_EXIT_MISMATCH:
        return "test-exit-mismatch";
    case VCS_PACKAGE_ATTEST_DETAIL_TEST_TIMEOUT: return "test-timeout";
    case VCS_PACKAGE_ATTEST_DETAIL_TEST_SIGNAL: return "test-signal";
    case VCS_PACKAGE_ATTEST_DETAIL_ASAN_FINDINGS: return "asan-findings";
    case VCS_PACKAGE_ATTEST_DETAIL_UBSAN_FINDINGS: return "ubsan-findings";
    case VCS_PACKAGE_ATTEST_DETAIL_RESOURCE_LIMIT: return "resource-limit";
    }
    return "unknown";
}

const char *vcs_package_attest_outcome_string(uint8_t outcome)
{
    switch (outcome) {
    case VCS_PACKAGE_ATTEST_OUTCOME_PASS: return "pass";
    case VCS_PACKAGE_ATTEST_OUTCOME_FAIL: return "fail";
    case VCS_PACKAGE_ATTEST_OUTCOME_UNAVAILABLE: return "unavailable";
    }
    return "unknown";
}

const char *vcs_package_attest_sanitizer_outcome_string(uint8_t outcome)
{
    switch (outcome) {
    case VCS_PACKAGE_ATTEST_OUTCOME_PASS: return "clean";
    case VCS_PACKAGE_ATTEST_OUTCOME_FAIL: return "findings";
    case VCS_PACKAGE_ATTEST_OUTCOME_UNAVAILABLE: return "unavailable";
    }
    return "unknown";
}

const char *vcs_package_attest_isolation_string(uint8_t isolation)
{
    switch (isolation) {
    case VCS_PACKAGE_ATTEST_ISOLATION_FULL: return "full";
    case VCS_PACKAGE_ATTEST_ISOLATION_DEGRADED: return "degraded";
    }
    return "unknown";
}

bool vcs_package_attest_result_is_pass(uint8_t result_class)
{
    return result_class == VCS_PACKAGE_ATTEST_RESULT_BUILD_PASS ||
           result_class == VCS_PACKAGE_ATTEST_RESULT_TEST_PASS;
}

/* ── field grammars ───────────────────────────────────────────────── */

static bool attest_root_nonzero(const uint8_t root[32])
{
    uint8_t acc = 0;
    for (size_t i = 0; i < 32; i++)
        acc |= root[i];
    return acc != 0;
}

static bool attest_printable(const char *s)
{
    size_t len = strlen(s);
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c > 0x7e)
            return false;
    }
    return true;
}

static bool attest_token_valid(const char *s, size_t max_len)
{
    size_t len = s ? strlen(s) : 0;
    if (len == 0 || len > max_len)
        return false;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        bool lower = c >= 'a' && c <= 'z';
        bool digit = c >= '0' && c <= '9';
        if (!lower && !digit && c != '.' && c != '+' && c != '-')
            return false;
    }
    return true;
}

static bool attest_compiler_cmp(const struct vcs_package_attest *a,
                                size_t i, size_t j)
{
    /* Strict ascending order by (id bytes, version bytes). */
    int c = strcmp(a->compilers[i].id, a->compilers[j].id);
    if (c != 0)
        return c < 0;
    return strcmp(a->compilers[i].version, a->compilers[j].version) < 0;
}

static bool attest_oncurve(const uint8_t pubkey[33])
{
    secp256k1_pubkey parsed;
    return secp256k1_ec_pubkey_parse(attest_verify_ctx, &parsed, pubkey, 33);
}

/* ── validation ─────────────────────────────────────────────────────── */

enum vcs_package_attest_error vcs_package_attest_validate(
    const struct vcs_package_attest *attest)
{
    if (!attest)
        LOG_RETURN(VCS_PACKAGE_ATTEST_ERR_NULL, ATTEST_LOG, "null attest");
    if (attest->schema_version != VCS_PACKAGE_ATTEST_VERSION)
        return VCS_PACKAGE_ATTEST_ERR_SCHEMA_VERSION;
    if (!attest_root_nonzero(attest->package_root))
        return VCS_PACKAGE_ATTEST_ERR_PACKAGE_ROOT;
    if (!attest_root_nonzero(attest->release_id))
        return VCS_PACKAGE_ATTEST_ERR_RELEASE_ID;
    if (!attest_root_nonzero(attest->recipe_root))
        return VCS_PACKAGE_ATTEST_ERR_RECIPE_ROOT;
    if (attest->result_class < VCS_PACKAGE_ATTEST_RESULT_BUILD_PASS ||
        attest->result_class > VCS_PACKAGE_ATTEST_RESULT_SANITIZER_FAIL)
        return VCS_PACKAGE_ATTEST_ERR_RESULT_CLASS;
    if (attest->detail_code > VCS_PACKAGE_ATTEST_DETAIL_RESOURCE_LIMIT)
        return VCS_PACKAGE_ATTEST_ERR_DETAIL_CODE;
    if (strlen(attest->detail) > VCS_PACKAGE_ATTEST_DETAIL_MAX ||
        !attest_printable(attest->detail))
        return VCS_PACKAGE_ATTEST_ERR_DETAIL_TEXT;
    bool pass = vcs_package_attest_result_is_pass(attest->result_class);
    if (pass && (attest->detail_code != VCS_PACKAGE_ATTEST_DETAIL_NONE ||
                 attest->detail[0] != '\0'))
        return VCS_PACKAGE_ATTEST_ERR_DETAIL_FORBIDDEN;
    if (!pass && attest->detail_code == VCS_PACKAGE_ATTEST_DETAIL_NONE)
        return VCS_PACKAGE_ATTEST_ERR_DETAIL_REQUIRED;

    if (attest->compiler_count == 0 ||
        attest->compiler_count > VCS_PACKAGE_ATTEST_MAX_COMPILERS)
        return VCS_PACKAGE_ATTEST_ERR_COMPILER_COUNT;
    for (size_t i = 0; i < attest->compiler_count; i++) {
        const struct vcs_package_attest_compiler *c = &attest->compilers[i];
        if (!attest_token_valid(c->id, VCS_PACKAGE_ATTEST_COMPILER_ID_MAX))
            return VCS_PACKAGE_ATTEST_ERR_COMPILER_ID;
        size_t vlen = strlen(c->version);
        if (vlen == 0 || vlen > VCS_PACKAGE_ATTEST_COMPILER_VERSION_MAX ||
            !attest_printable(c->version))
            return VCS_PACKAGE_ATTEST_ERR_COMPILER_VERSION;
        if (c->outcome > VCS_PACKAGE_ATTEST_OUTCOME_UNAVAILABLE)
            return VCS_PACKAGE_ATTEST_ERR_COMPILER_OUTCOME;
        if (i > 0 && !attest_compiler_cmp(attest, i - 1, i))
            return VCS_PACKAGE_ATTEST_ERR_COMPILER_ORDER;
        if (pass && c->outcome == VCS_PACKAGE_ATTEST_OUTCOME_FAIL)
            return VCS_PACKAGE_ATTEST_ERR_OUTCOME_CLASS;
    }

    if (attest->sanitizer_count > VCS_PACKAGE_ATTEST_MAX_SANITIZERS)
        return VCS_PACKAGE_ATTEST_ERR_SANITIZER_COUNT;
    bool any_findings = false;
    for (size_t i = 0; i < attest->sanitizer_count; i++) {
        const struct vcs_package_attest_sanitizer *s = &attest->sanitizers[i];
        if (!attest_token_valid(s->name, VCS_PACKAGE_ATTEST_SANITIZER_NAME_MAX))
            return VCS_PACKAGE_ATTEST_ERR_SANITIZER_NAME;
        if (s->outcome > VCS_PACKAGE_ATTEST_OUTCOME_UNAVAILABLE)
            return VCS_PACKAGE_ATTEST_ERR_SANITIZER_OUTCOME;
        if (i > 0 && strcmp(attest->sanitizers[i - 1].name, s->name) >= 0)
            return VCS_PACKAGE_ATTEST_ERR_SANITIZER_ORDER;
        if (s->outcome == VCS_PACKAGE_ATTEST_OUTCOME_FAIL)
            any_findings = true;
    }
    if (attest->result_class == VCS_PACKAGE_ATTEST_RESULT_SANITIZER_FAIL) {
        if (!any_findings)
            return VCS_PACKAGE_ATTEST_ERR_SANITIZER_FINDINGS;
    } else if (any_findings) {
        return VCS_PACKAGE_ATTEST_ERR_SANITIZER_FINDINGS;
    }

    switch (attest->result_class) {
    case VCS_PACKAGE_ATTEST_RESULT_BUILD_PASS:
    case VCS_PACKAGE_ATTEST_RESULT_BUILD_FAIL:
        if (attest->test_ran)
            return VCS_PACKAGE_ATTEST_ERR_TEST_CLASS;
        break;
    default:
        if (!attest->test_ran)
            return VCS_PACKAGE_ATTEST_ERR_TEST_CLASS;
        break;
    }
    if (!attest->test_ran && attest->test_exit_code != 0)
        return VCS_PACKAGE_ATTEST_ERR_TEST_EXIT;

    if (attest->isolation != VCS_PACKAGE_ATTEST_ISOLATION_FULL &&
        attest->isolation != VCS_PACKAGE_ATTEST_ISOLATION_DEGRADED)
        return VCS_PACKAGE_ATTEST_ERR_ISOLATION;
    if (!attest_oncurve(attest->verifier_pubkey))
        return VCS_PACKAGE_ATTEST_ERR_PUBKEY;
    return VCS_PACKAGE_ATTEST_OK;
}

/* ── canonical body encoding ────────────────────────────────────────── */

/* Every field except the signature. Only called on validated attestations,
 * so bounded fields are known to fit. */
static size_t attest_body_encode(const struct vcs_package_attest *attest,
                                 uint8_t *out)
{
    size_t off = 0;
    memcpy(out + off, attest_wire_magic,
           VCS_PACKAGE_ATTEST_WIRE_MAGIC_BYTES);
    off += VCS_PACKAGE_ATTEST_WIRE_MAGIC_BYTES;
    vcs_wr_u16le(out + off, attest->schema_version);
    off += 2;
    memcpy(out + off, attest->package_root, 32);
    off += 32;
    memcpy(out + off, attest->release_id, 32);
    off += 32;
    memcpy(out + off, attest->recipe_root, 32);
    off += 32;
    out[off++] = attest->result_class;
    out[off++] = attest->detail_code;
    size_t detail_len = strlen(attest->detail);
    vcs_wr_u16le(out + off, (uint16_t)detail_len);
    off += 2;
    memcpy(out + off, attest->detail, detail_len);
    off += detail_len;
    out[off++] = (uint8_t)attest->compiler_count;
    for (size_t i = 0; i < attest->compiler_count; i++) {
        const struct vcs_package_attest_compiler *c = &attest->compilers[i];
        size_t id_len = strlen(c->id);
        size_t ver_len = strlen(c->version);
        out[off++] = (uint8_t)id_len;
        memcpy(out + off, c->id, id_len);
        off += id_len;
        out[off++] = (uint8_t)ver_len;
        memcpy(out + off, c->version, ver_len);
        off += ver_len;
        out[off++] = c->outcome;
    }
    out[off++] = (uint8_t)attest->sanitizer_count;
    for (size_t i = 0; i < attest->sanitizer_count; i++) {
        const struct vcs_package_attest_sanitizer *s = &attest->sanitizers[i];
        size_t name_len = strlen(s->name);
        out[off++] = (uint8_t)name_len;
        memcpy(out + off, s->name, name_len);
        off += name_len;
        out[off++] = s->outcome;
    }
    out[off++] = attest->test_ran ? 1u : 0u;
    vcs_wr_u32le(out + off, attest->test_exit_code);
    off += 4;
    out[off++] = attest->isolation;
    memcpy(out + off, attest->verifier_pubkey,
           VCS_PACKAGE_ATTEST_PUBKEY_BYTES);
    off += VCS_PACKAGE_ATTEST_PUBKEY_BYTES;
    return off;
}

enum vcs_package_attest_error vcs_package_attest_id(
    const struct vcs_package_attest *attest,
    uint8_t out[VCS_PACKAGE_ATTEST_ID_BYTES])
{
    if (!out)
        LOG_RETURN(VCS_PACKAGE_ATTEST_ERR_NULL, ATTEST_LOG, "null id out");
    enum vcs_package_attest_error error =
        vcs_package_attest_validate(attest);
    if (error != VCS_PACKAGE_ATTEST_OK)
        return error;

    uint8_t body[VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES];
    size_t body_len = attest_body_encode(attest, body);

    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, attest_id_domain, sizeof(attest_id_domain));
    sha3_256_write(&ctx, body, body_len);
    sha3_256_finalize(&ctx, out);
    return VCS_PACKAGE_ATTEST_OK;
}

enum vcs_package_attest_error vcs_package_attest_serialize(
    const struct vcs_package_attest *attest, uint8_t **out, size_t *out_len)
{
    if (!out || !out_len)
        LOG_RETURN(VCS_PACKAGE_ATTEST_ERR_NULL, ATTEST_LOG,
                   "null serialize out");
    *out = NULL;
    *out_len = 0;
    enum vcs_package_attest_error error =
        vcs_package_attest_validate(attest);
    if (error != VCS_PACKAGE_ATTEST_OK)
        return error;

    uint8_t *wire = zcl_malloc(VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES,
                               "vcs_attest_wire");
    if (!wire)
        LOG_RETURN(VCS_PACKAGE_ATTEST_ERR_ALLOC, ATTEST_LOG,
                   "alloc attest wire");
    size_t written = attest_body_encode(attest, wire);
    memcpy(wire + written, attest->signature,
           VCS_PACKAGE_ATTEST_SIGNATURE_BYTES);
    *out = wire;
    *out_len = written + VCS_PACKAGE_ATTEST_SIGNATURE_BYTES;
    return VCS_PACKAGE_ATTEST_OK;
}

/* ── parsing ──────────────────────────────────────────────────────── */

static bool attest_wire_has(size_t wire_len, size_t off, size_t need)
{
    return off <= wire_len && need <= wire_len - off;
}

static enum vcs_package_attest_error attest_rd_bytes(
    const uint8_t *wire, size_t wire_len, size_t *off, uint8_t *out,
    size_t len)
{
    if (!attest_wire_has(wire_len, *off, len))
        return VCS_PACKAGE_ATTEST_ERR_WIRE_TRUNCATED;
    memcpy(out, wire + *off, len);
    *off += len;
    return VCS_PACKAGE_ATTEST_OK;
}

/* Read one [1 len][bytes] token into a fixed buffer; an embedded NUL is a
 * grammar rejection (it would hide a non-canonical tail from strlen). */
static enum vcs_package_attest_error attest_rd_token(
    const uint8_t *wire, size_t wire_len, size_t *off, size_t max_len,
    char *out, size_t out_capacity, enum vcs_package_attest_error nul_error)
{
    if (!attest_wire_has(wire_len, *off, 1u))
        return VCS_PACKAGE_ATTEST_ERR_WIRE_TRUNCATED;
    uint8_t len = wire[(*off)++];
    if (len > max_len || (size_t)len + 1u > out_capacity ||
        !attest_wire_has(wire_len, *off, len))
        return VCS_PACKAGE_ATTEST_ERR_WIRE_TRUNCATED;
    if (len > 0)
        memcpy(out, wire + *off, len);
    out[len] = '\0';
    if (strnlen(out, len) != len)
        return nul_error;
    *off += len;
    return VCS_PACKAGE_ATTEST_OK;
}

enum vcs_package_attest_error vcs_package_attest_parse(
    const uint8_t *wire, size_t wire_len, struct vcs_package_attest *out)
{
    if (!out)
        LOG_RETURN(VCS_PACKAGE_ATTEST_ERR_NULL, ATTEST_LOG, "null parse out");
    memset(out, 0, sizeof(*out));
    if (!wire)
        LOG_RETURN(VCS_PACKAGE_ATTEST_ERR_NULL, ATTEST_LOG, "null wire");
    if (wire_len > VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES)
        return VCS_PACKAGE_ATTEST_ERR_WIRE_OVERSIZE;

    size_t off = 0;
    uint8_t magic[VCS_PACKAGE_ATTEST_WIRE_MAGIC_BYTES];
    enum vcs_package_attest_error err =
        attest_rd_bytes(wire, wire_len, &off, magic, sizeof(magic));
    if (err != VCS_PACKAGE_ATTEST_OK)
        return err;
    if (memcmp(magic, attest_wire_magic, sizeof(magic)) != 0)
        return VCS_PACKAGE_ATTEST_ERR_WIRE_MAGIC;
    if (!attest_wire_has(wire_len, off, 2u))
        return VCS_PACKAGE_ATTEST_ERR_WIRE_TRUNCATED;
    out->schema_version = vcs_rd_u16le(wire + off);
    off += 2;
    if (out->schema_version != VCS_PACKAGE_ATTEST_VERSION)
        return VCS_PACKAGE_ATTEST_ERR_SCHEMA_VERSION;

    err = attest_rd_bytes(wire, wire_len, &off, out->package_root, 32);
    if (err != VCS_PACKAGE_ATTEST_OK)
        return err;
    err = attest_rd_bytes(wire, wire_len, &off, out->release_id, 32);
    if (err != VCS_PACKAGE_ATTEST_OK)
        return err;
    err = attest_rd_bytes(wire, wire_len, &off, out->recipe_root, 32);
    if (err != VCS_PACKAGE_ATTEST_OK)
        return err;
    if (!attest_wire_has(wire_len, off, 2u))
        return VCS_PACKAGE_ATTEST_ERR_WIRE_TRUNCATED;
    out->result_class = wire[off++];
    out->detail_code = wire[off++];

    /* detail: [2 len][bytes]; embedded NUL is a detail-grammar rejection. */
    if (!attest_wire_has(wire_len, off, 2u))
        return VCS_PACKAGE_ATTEST_ERR_WIRE_TRUNCATED;
    uint16_t detail_len = vcs_rd_u16le(wire + off);
    off += 2;
    if (detail_len > VCS_PACKAGE_ATTEST_DETAIL_MAX ||
        !attest_wire_has(wire_len, off, detail_len))
        return VCS_PACKAGE_ATTEST_ERR_WIRE_TRUNCATED;
    if (detail_len > 0)
        memcpy(out->detail, wire + off, detail_len);
    out->detail[detail_len] = '\0';
    if (strnlen(out->detail, detail_len) != detail_len)
        return VCS_PACKAGE_ATTEST_ERR_DETAIL_TEXT;
    off += detail_len;

    if (!attest_wire_has(wire_len, off, 1u))
        return VCS_PACKAGE_ATTEST_ERR_WIRE_TRUNCATED;
    out->compiler_count = wire[off++];
    if (out->compiler_count > VCS_PACKAGE_ATTEST_MAX_COMPILERS)
        return VCS_PACKAGE_ATTEST_ERR_COMPILER_COUNT;
    for (size_t i = 0; i < out->compiler_count; i++) {
        struct vcs_package_attest_compiler *c = &out->compilers[i];
        err = attest_rd_token(wire, wire_len, &off,
                              VCS_PACKAGE_ATTEST_COMPILER_ID_MAX, c->id,
                              sizeof(c->id), VCS_PACKAGE_ATTEST_ERR_COMPILER_ID);
        if (err != VCS_PACKAGE_ATTEST_OK)
            return err;
        err = attest_rd_token(wire, wire_len, &off,
                              VCS_PACKAGE_ATTEST_COMPILER_VERSION_MAX,
                              c->version, sizeof(c->version),
                              VCS_PACKAGE_ATTEST_ERR_COMPILER_VERSION);
        if (err != VCS_PACKAGE_ATTEST_OK)
            return err;
        if (!attest_wire_has(wire_len, off, 1u))
            return VCS_PACKAGE_ATTEST_ERR_WIRE_TRUNCATED;
        c->outcome = wire[off++];
    }

    if (!attest_wire_has(wire_len, off, 1u))
        return VCS_PACKAGE_ATTEST_ERR_WIRE_TRUNCATED;
    out->sanitizer_count = wire[off++];
    if (out->sanitizer_count > VCS_PACKAGE_ATTEST_MAX_SANITIZERS)
        return VCS_PACKAGE_ATTEST_ERR_SANITIZER_COUNT;
    for (size_t i = 0; i < out->sanitizer_count; i++) {
        struct vcs_package_attest_sanitizer *s = &out->sanitizers[i];
        err = attest_rd_token(wire, wire_len, &off,
                              VCS_PACKAGE_ATTEST_SANITIZER_NAME_MAX, s->name,
                              sizeof(s->name),
                              VCS_PACKAGE_ATTEST_ERR_SANITIZER_NAME);
        if (err != VCS_PACKAGE_ATTEST_OK)
            return err;
        if (!attest_wire_has(wire_len, off, 1u))
            return VCS_PACKAGE_ATTEST_ERR_WIRE_TRUNCATED;
        s->outcome = wire[off++];
    }

    if (!attest_wire_has(wire_len, off, 1u + 4u + 1u))
        return VCS_PACKAGE_ATTEST_ERR_WIRE_TRUNCATED;
    uint8_t test_flag = wire[off++];
    if (test_flag > 1u)
        return VCS_PACKAGE_ATTEST_ERR_TEST_FLAG;
    out->test_ran = test_flag == 1u;
    out->test_exit_code = vcs_rd_u32le(wire + off);
    off += 4;
    out->isolation = wire[off++];

    err = attest_rd_bytes(wire, wire_len, &off, out->verifier_pubkey,
                          VCS_PACKAGE_ATTEST_PUBKEY_BYTES);
    if (err != VCS_PACKAGE_ATTEST_OK)
        return err;
    err = attest_rd_bytes(wire, wire_len, &off, out->signature,
                          VCS_PACKAGE_ATTEST_SIGNATURE_BYTES);
    if (err != VCS_PACKAGE_ATTEST_OK)
        return err;
    if (off != wire_len)
        return VCS_PACKAGE_ATTEST_ERR_WIRE_TRAILING;

    /* Field grammars + consistency (the signature is verify()'s step). */
    return vcs_package_attest_validate(out);
}

/* ── signature ──────────────────────────────────────────────────────── */

static bool attest_signature_low_s(const uint8_t signature[64])
{
    /* Compact r||s: the s half is signature[32..64), big-endian. */
    for (size_t i = 0; i < 32; i++) {
        uint8_t s = signature[32 + i];
        uint8_t h = attest_half_order[i];
        if (s < h)
            return true;
        if (s > h)
            return false;
    }
    return true; /* s == n/2 exactly: <= n/2 passes the low-S bound */
}

enum vcs_package_attest_error vcs_package_attest_verify(
    const struct vcs_package_attest *attest)
{
    if (!attest)
        LOG_RETURN(VCS_PACKAGE_ATTEST_ERR_NULL, ATTEST_LOG, "null verify");
    enum vcs_package_attest_error err = vcs_package_attest_validate(attest);
    if (err != VCS_PACKAGE_ATTEST_OK)
        return err;
    if (!attest_signature_low_s(attest->signature))
        return VCS_PACKAGE_ATTEST_ERR_SIG_LOW_S;

    uint8_t id[VCS_PACKAGE_ATTEST_ID_BYTES];
    err = vcs_package_attest_id(attest, id);
    if (err != VCS_PACKAGE_ATTEST_OK)
        return err;

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(attest_verify_ctx, &pubkey,
                                   attest->verifier_pubkey,
                                   VCS_PACKAGE_ATTEST_PUBKEY_BYTES))
        return VCS_PACKAGE_ATTEST_ERR_PUBKEY;
    secp256k1_ecdsa_signature signature;
    if (!secp256k1_ecdsa_signature_parse_compact(
            attest_verify_ctx, &signature, attest->signature))
        return VCS_PACKAGE_ATTEST_ERR_SIG_VERIFY;
    if (!secp256k1_ecdsa_verify(attest_verify_ctx, &signature, id, &pubkey))
        return VCS_PACKAGE_ATTEST_ERR_SIG_VERIFY;
    return VCS_PACKAGE_ATTEST_OK;
}

bool vcs_package_attest_matches(const struct vcs_package_attest *a,
                                const struct vcs_package_attest *b)
{
    if (!a || !b)
        return false;
    return a->result_class == b->result_class &&
           memcmp(a->package_root, b->package_root, 32) == 0 &&
           memcmp(a->release_id, b->release_id, 32) == 0 &&
           memcmp(a->recipe_root, b->recipe_root, 32) == 0;
}
