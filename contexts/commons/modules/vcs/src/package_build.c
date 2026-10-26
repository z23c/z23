/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_build — implementation of the ZCODE build-receipt codec declared
 * in vcs/package_build.h. Pure bytes: no filesystem, no compiler, no
 * process. The receipt is written by the isolated build worker and
 * INDEPENDENTLY re-checked (every output re-hashed) by the parent before
 * anything is installed. */

#include "vcs/package_build.h"

#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "sha3/sha3.h"
#include "vcs/package_manifest.h"

#include "vcs_priv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUILD_LOG "vcs.build"

static const uint8_t build_wire_magic[VCS_PACKAGE_BUILD_WIRE_MAGIC_BYTES] =
    { 'Z', 'C', 'L', 'B', 'L', 'D', '\r', '\n' };
static const uint8_t build_receipt_domain[] =
    VCS_PACKAGE_BUILD_RECEIPT_DOMAIN;

const char *vcs_package_build_error_string(enum vcs_package_build_error error)
{
    static const char *const names[VCS_PACKAGE_BUILD_ERR_CAPSULE + 1u] = {
        [VCS_PACKAGE_BUILD_OK] = "ok",
        [VCS_PACKAGE_BUILD_ERR_NULL] = "null-argument",
        [VCS_PACKAGE_BUILD_ERR_ALLOC] = "allocation-failure",
        [VCS_PACKAGE_BUILD_ERR_SCHEMA_VERSION] = "schema-version",
        [VCS_PACKAGE_BUILD_ERR_WIRE_MAGIC] = "wire-magic",
        [VCS_PACKAGE_BUILD_ERR_WIRE_OVERSIZE] = "wire-oversize",
        [VCS_PACKAGE_BUILD_ERR_WIRE_TRUNCATED] = "wire-truncated",
        [VCS_PACKAGE_BUILD_ERR_WIRE_TRAILING] = "wire-trailing",
        [VCS_PACKAGE_BUILD_ERR_ROOT] = "all-zero-root",
        [VCS_PACKAGE_BUILD_ERR_DEP_ORDER] = "dep-roots-not-canonical",
        [VCS_PACKAGE_BUILD_ERR_DEP_COUNT] = "dep-count-bound",
        [VCS_PACKAGE_BUILD_ERR_COMPILER] = "compiler-identity",
        [VCS_PACKAGE_BUILD_ERR_FLAGS] = "compiler-flags",
        [VCS_PACKAGE_BUILD_ERR_RESULT] = "result-class",
        [VCS_PACKAGE_BUILD_ERR_ISOLATION] = "isolation-level",
        [VCS_PACKAGE_BUILD_ERR_TEST_STATE] = "test-state-inconsistent",
        [VCS_PACKAGE_BUILD_ERR_OUTPUT_PATH] = "output-path-grammar",
        [VCS_PACKAGE_BUILD_ERR_OUTPUT_ORDER] = "outputs-not-canonical",
        [VCS_PACKAGE_BUILD_ERR_OUTPUT_COUNT] = "output-count-bound",
        [VCS_PACKAGE_BUILD_ERR_OUTPUT_EMPTY] = "passing-build-no-outputs",
        [VCS_PACKAGE_BUILD_ERR_CAPSULE] = "toolchain-capsule",
    };
    const unsigned value = (unsigned)error;
    if (value >= sizeof(names) / sizeof(names[0])) return "unknown-error";
    const char *name = names[value];
    return name ? name : "unknown-error";
}

const char *vcs_package_build_result_string(enum vcs_package_build_result r)
{
    switch (r) {
    case VCS_PACKAGE_BUILD_RESULT_BUILD_FAIL: return "build-fail";
    case VCS_PACKAGE_BUILD_RESULT_TEST_FAIL: return "test-fail";
    case VCS_PACKAGE_BUILD_RESULT_BUILD_PASS: return "build-pass";
    case VCS_PACKAGE_BUILD_RESULT_TEST_PASS: return "test-pass";
    }
    return "unknown-result";
}

const char *vcs_package_build_isolation_string(
    enum vcs_package_build_isolation i)
{
    switch (i) {
    case VCS_PACKAGE_BUILD_ISOLATION_FULL: return "full";
    case VCS_PACKAGE_BUILD_ISOLATION_DEGRADED: return "degraded";
    }
    return "unknown-isolation";
}

void vcs_package_build_receipt_init(struct vcs_package_build_receipt *r)
{
    if (!r)
        return;
    memset(r, 0, sizeof(*r));
    r->schema_version = (uint16_t)VCS_PACKAGE_BUILD_VERSION_MIN;
}

static bool build_root_is_zero(const uint8_t root[32])
{
    uint8_t acc = 0;
    for (size_t i = 0; i < 32; i++)
        acc |= root[i];
    return acc == 0;
}

static bool build_printable(const char *s, size_t max)
{
    size_t n = strlen(s);
    if (n == 0 || n > max)
        return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20u || c > 0x7eu)
            return false;
    }
    return true;
}

enum vcs_package_build_error vcs_package_build_set_toolchain_capsule(
    struct vcs_package_build_receipt *r, const uint8_t capsule_root[32])
{
    if (!r || !capsule_root)
        LOG_RETURN(VCS_PACKAGE_BUILD_ERR_NULL, BUILD_LOG,
                   "null argument binding a toolchain capsule root");
    if (build_root_is_zero(capsule_root))
        return VCS_PACKAGE_BUILD_ERR_CAPSULE;
    memcpy(r->toolchain_capsule_root, capsule_root, 32);
    r->has_toolchain_capsule = true;
    r->schema_version = (uint16_t)VCS_PACKAGE_BUILD_VERSION;
    return VCS_PACKAGE_BUILD_OK;
}

enum vcs_package_build_error vcs_package_build_add_dep(
    struct vcs_package_build_receipt *r, const uint8_t root[32])
{
    if (!r || !root)
        LOG_RETURN(VCS_PACKAGE_BUILD_ERR_NULL, BUILD_LOG,
                   "null argument adding a build-receipt dependency root");
    if (build_root_is_zero(root))
        return VCS_PACKAGE_BUILD_ERR_ROOT;
    if (r->dep_count >= VCS_PACKAGE_BUILD_MAX_DEPS)
        return VCS_PACKAGE_BUILD_ERR_DEP_COUNT;
    size_t pos = 0;
    while (pos < r->dep_count) {
        int cmp = memcmp(root, r->dep_roots[pos], 32);
        if (cmp == 0)
            return VCS_PACKAGE_BUILD_ERR_DEP_ORDER;
        if (cmp < 0)
            break;
        pos++;
    }
    for (size_t i = r->dep_count; i > pos; i--)
        memcpy(r->dep_roots[i], r->dep_roots[i - 1], 32);
    memcpy(r->dep_roots[pos], root, 32);
    r->dep_count++;
    return VCS_PACKAGE_BUILD_OK;
}

enum vcs_package_build_error vcs_package_build_add_output(
    struct vcs_package_build_receipt *r, const char *path,
    const uint8_t sha3[32], uint64_t bytes)
{
    if (!r || !path || !sha3)
        LOG_RETURN(VCS_PACKAGE_BUILD_ERR_NULL, BUILD_LOG,
                   "null argument adding a build-receipt output");
    if (strlen(path) > VCS_PACKAGE_BUILD_PATH_MAX ||
        !vcs_package_path_valid(path))
        return VCS_PACKAGE_BUILD_ERR_OUTPUT_PATH;
    if (r->output_count >= VCS_PACKAGE_BUILD_MAX_OUTPUTS)
        return VCS_PACKAGE_BUILD_ERR_OUTPUT_COUNT;
    size_t pos = 0;
    while (pos < r->output_count) {
        int cmp = strcmp(path, r->outputs[pos].path);
        if (cmp == 0)
            return VCS_PACKAGE_BUILD_ERR_OUTPUT_ORDER;
        if (cmp < 0)
            break;
        pos++;
    }
    for (size_t i = r->output_count; i > pos; i--)
        r->outputs[i] = r->outputs[i - 1];
    memset(&r->outputs[pos], 0, sizeof(r->outputs[pos]));
    (void)snprintf(r->outputs[pos].path, sizeof(r->outputs[pos].path), "%s",
                   path);
    memcpy(r->outputs[pos].sha3, sha3, 32);
    r->outputs[pos].bytes = bytes;
    r->output_count++;
    return VCS_PACKAGE_BUILD_OK;
}

static enum vcs_package_build_error build_validate_version_capsule(
    const struct vcs_package_build_receipt *r)
{
    if (r->schema_version != VCS_PACKAGE_BUILD_VERSION &&
        r->schema_version != VCS_PACKAGE_BUILD_VERSION_MIN)
        return VCS_PACKAGE_BUILD_ERR_SCHEMA_VERSION;
    /* The capsule binding and the schema version move together: a v2 wire
     * carries the 32-byte capsule root, a v1 wire carries none. */
    if (r->has_toolchain_capsule !=
        (r->schema_version == VCS_PACKAGE_BUILD_VERSION))
        return VCS_PACKAGE_BUILD_ERR_CAPSULE;
    if (r->has_toolchain_capsule &&
        build_root_is_zero(r->toolchain_capsule_root))
        return VCS_PACKAGE_BUILD_ERR_CAPSULE;
    return VCS_PACKAGE_BUILD_OK;
}

static enum vcs_package_build_error build_validate_roots(
    const struct vcs_package_build_receipt *r)
{
    if (build_root_is_zero(r->package_root) ||
        build_root_is_zero(r->recipe_root))
        return VCS_PACKAGE_BUILD_ERR_ROOT;
    /* lock_root is never all-zero: a dependency-free package still locks
     * (a one-node lock), so an all-zero lock root means "nobody locked". */
    if (build_root_is_zero(r->lock_root))
        return VCS_PACKAGE_BUILD_ERR_ROOT;
    return VCS_PACKAGE_BUILD_OK;
}

static enum vcs_package_build_error build_validate_deps(
    const struct vcs_package_build_receipt *r)
{
    if (r->dep_count > VCS_PACKAGE_BUILD_MAX_DEPS)
        return VCS_PACKAGE_BUILD_ERR_DEP_COUNT;
    for (size_t i = 0; i < r->dep_count; i++) {
        if (build_root_is_zero(r->dep_roots[i]))
            return VCS_PACKAGE_BUILD_ERR_ROOT;
        if (i > 0 && memcmp(r->dep_roots[i - 1], r->dep_roots[i], 32) >= 0)
            return VCS_PACKAGE_BUILD_ERR_DEP_ORDER;
    }
    return VCS_PACKAGE_BUILD_OK;
}

static enum vcs_package_build_error build_validate_strings(
    const struct vcs_package_build_receipt *r)
{
    if (!build_printable(r->compiler_id, VCS_PACKAGE_BUILD_ID_MAX) ||
        !build_printable(r->compiler_version, VCS_PACKAGE_BUILD_VERSION_MAX))
        return VCS_PACKAGE_BUILD_ERR_COMPILER;
    if (!build_printable(r->flags, VCS_PACKAGE_BUILD_FLAGS_MAX))
        return VCS_PACKAGE_BUILD_ERR_FLAGS;
    return VCS_PACKAGE_BUILD_OK;
}

static enum vcs_package_build_error build_validate_verdict(
    const struct vcs_package_build_receipt *r)
{
    if (r->result_class > (uint8_t)VCS_PACKAGE_BUILD_RESULT_TEST_PASS)
        return VCS_PACKAGE_BUILD_ERR_RESULT;
    if (r->isolation > (uint8_t)VCS_PACKAGE_BUILD_ISOLATION_DEGRADED)
        return VCS_PACKAGE_BUILD_ERR_ISOLATION;
    return VCS_PACKAGE_BUILD_OK;
}

static enum vcs_package_build_error build_validate_test_state(
    const struct vcs_package_build_receipt *r)
{
    /* A test verdict requires a test run, and a run that did not happen
     * carries no exit code. */
    const bool test_verdict =
        r->result_class == (uint8_t)VCS_PACKAGE_BUILD_RESULT_TEST_PASS ||
        r->result_class == (uint8_t)VCS_PACKAGE_BUILD_RESULT_TEST_FAIL;
    if (test_verdict != r->test_ran)
        return VCS_PACKAGE_BUILD_ERR_TEST_STATE;
    if (!r->test_ran && r->test_exit_code != 0)
        return VCS_PACKAGE_BUILD_ERR_TEST_STATE;
    return VCS_PACKAGE_BUILD_OK;
}

static enum vcs_package_build_error build_validate_outputs(
    const struct vcs_package_build_receipt *r)
{
    if (r->output_count > VCS_PACKAGE_BUILD_MAX_OUTPUTS)
        return VCS_PACKAGE_BUILD_ERR_OUTPUT_COUNT;
    for (size_t i = 0; i < r->output_count; i++) {
        if (strlen(r->outputs[i].path) > VCS_PACKAGE_BUILD_PATH_MAX ||
            !vcs_package_path_valid(r->outputs[i].path))
            return VCS_PACKAGE_BUILD_ERR_OUTPUT_PATH;
        if (i > 0 &&
            strcmp(r->outputs[i - 1].path, r->outputs[i].path) >= 0)
            return VCS_PACKAGE_BUILD_ERR_OUTPUT_ORDER;
    }
    return VCS_PACKAGE_BUILD_OK;
}

enum vcs_package_build_error vcs_package_build_validate(
    const struct vcs_package_build_receipt *r)
{
    if (!r)
        LOG_RETURN(VCS_PACKAGE_BUILD_ERR_NULL, BUILD_LOG,
                   "null build receipt to validate");
    enum vcs_package_build_error err = build_validate_version_capsule(r);
    if (err != VCS_PACKAGE_BUILD_OK)
        return err;
    err = build_validate_roots(r);
    if (err != VCS_PACKAGE_BUILD_OK)
        return err;
    err = build_validate_deps(r);
    if (err != VCS_PACKAGE_BUILD_OK)
        return err;
    err = build_validate_strings(r);
    if (err != VCS_PACKAGE_BUILD_OK)
        return err;
    err = build_validate_verdict(r);
    if (err != VCS_PACKAGE_BUILD_OK)
        return err;
    err = build_validate_test_state(r);
    if (err != VCS_PACKAGE_BUILD_OK)
        return err;
    err = build_validate_outputs(r);
    if (err != VCS_PACKAGE_BUILD_OK)
        return err;
    if (vcs_package_build_installable(r) && r->output_count == 0)
        return VCS_PACKAGE_BUILD_ERR_OUTPUT_EMPTY;
    return VCS_PACKAGE_BUILD_OK;
}

bool vcs_package_build_installable(const struct vcs_package_build_receipt *r)
{
    if (!r)
        return false;
    return r->result_class == (uint8_t)VCS_PACKAGE_BUILD_RESULT_TEST_PASS ||
           r->result_class == (uint8_t)VCS_PACKAGE_BUILD_RESULT_BUILD_PASS;
}

static size_t build_wire_size(const struct vcs_package_build_receipt *r)
{
    size_t n = VCS_PACKAGE_BUILD_WIRE_MAGIC_BYTES + 2u + 96u + 2u +
               r->dep_count * 32u + 2u + strlen(r->compiler_id) + 2u +
               strlen(r->compiler_version) + 2u + strlen(r->flags) +
               (r->has_toolchain_capsule ? 32u : 0u) +
               1u + 1u + 1u + 4u + 2u;
    for (size_t i = 0; i < r->output_count; i++)
        n += 2u + strlen(r->outputs[i].path) + 32u + 8u;
    return n;
}

enum vcs_package_build_error vcs_package_build_serialize(
    const struct vcs_package_build_receipt *r, uint8_t **out, size_t *out_len)
{
    if (!r || !out || !out_len)
        LOG_RETURN(VCS_PACKAGE_BUILD_ERR_NULL, BUILD_LOG,
                   "null argument serializing a build receipt");
    *out = NULL;
    *out_len = 0;
    enum vcs_package_build_error verr = vcs_package_build_validate(r);
    if (verr != VCS_PACKAGE_BUILD_OK)
        return verr;
    size_t need = build_wire_size(r);
    if (need > VCS_PACKAGE_BUILD_MAX_WIRE_BYTES)
        return VCS_PACKAGE_BUILD_ERR_WIRE_OVERSIZE;
    uint8_t *buf = zcl_malloc(need, "vcs.build.wire");
    if (!buf)
        return VCS_PACKAGE_BUILD_ERR_ALLOC;
    size_t o = 0;
    memcpy(buf + o, build_wire_magic, sizeof(build_wire_magic));
    o += sizeof(build_wire_magic);
    vcs_wr_u16le(buf + o, r->schema_version);
    o += 2;
    memcpy(buf + o, r->package_root, 32);
    o += 32;
    memcpy(buf + o, r->recipe_root, 32);
    o += 32;
    memcpy(buf + o, r->lock_root, 32);
    o += 32;
    vcs_wr_u16le(buf + o, (uint16_t)r->dep_count);
    o += 2;
    for (size_t i = 0; i < r->dep_count; i++) {
        memcpy(buf + o, r->dep_roots[i], 32);
        o += 32;
    }
    const char *strs[3] = { r->compiler_id, r->compiler_version, r->flags };
    for (size_t i = 0; i < 3; i++) {
        size_t l = strlen(strs[i]);
        vcs_wr_u16le(buf + o, (uint16_t)l);
        o += 2;
        memcpy(buf + o, strs[i], l);
        o += l;
    }
    if (r->has_toolchain_capsule) {
        memcpy(buf + o, r->toolchain_capsule_root, 32);
        o += 32;
    }
    buf[o++] = r->result_class;
    buf[o++] = r->isolation;
    buf[o++] = r->test_ran ? 1u : 0u;
    vcs_wr_u32le(buf + o, r->test_exit_code);
    o += 4;
    vcs_wr_u16le(buf + o, (uint16_t)r->output_count);
    o += 2;
    for (size_t i = 0; i < r->output_count; i++) {
        size_t l = strlen(r->outputs[i].path);
        vcs_wr_u16le(buf + o, (uint16_t)l);
        o += 2;
        memcpy(buf + o, r->outputs[i].path, l);
        o += l;
        memcpy(buf + o, r->outputs[i].sha3, 32);
        o += 32;
        vcs_wr_u64le(buf + o, r->outputs[i].bytes);
        o += 8;
    }
    *out = buf;
    *out_len = o;
    return VCS_PACKAGE_BUILD_OK;
}

/* Read one [2 len][bytes] string; false when it runs past the end or does
 * not fit `cap`. */
static bool build_rd_str(const uint8_t *wire, size_t wire_len, size_t *o,
                         char *dst, size_t cap)
{
    if (wire_len - *o < 2u)
        return false;
    uint16_t l = vcs_rd_u16le(wire + *o);
    *o += 2;
    if (l >= cap || wire_len - *o < (size_t)l)
        return false;
    memcpy(dst, wire + *o, l);
    dst[l] = '\0';
    *o += l;
    return true;
}

static enum vcs_package_build_error build_parse_envelope(const uint8_t *wire,
                                                         size_t wire_len)
{
    if (wire_len > VCS_PACKAGE_BUILD_MAX_WIRE_BYTES)
        return VCS_PACKAGE_BUILD_ERR_WIRE_OVERSIZE;
    if (wire_len < VCS_PACKAGE_BUILD_WIRE_MAGIC_BYTES + 2u + 96u + 2u)
        return VCS_PACKAGE_BUILD_ERR_WIRE_TRUNCATED;
    if (memcmp(wire, build_wire_magic, sizeof(build_wire_magic)) != 0)
        return VCS_PACKAGE_BUILD_ERR_WIRE_MAGIC;
    return VCS_PACKAGE_BUILD_OK;
}

static enum vcs_package_build_error build_parse_schema(
    struct vcs_package_build_receipt *out)
{
    if (out->schema_version != VCS_PACKAGE_BUILD_VERSION &&
        out->schema_version != VCS_PACKAGE_BUILD_VERSION_MIN) {
        vcs_package_build_receipt_init(out);
        return VCS_PACKAGE_BUILD_ERR_SCHEMA_VERSION;
    }
    return VCS_PACKAGE_BUILD_OK;
}

static enum vcs_package_build_error build_parse_roots_deps(
    const uint8_t *wire, size_t wire_len, size_t *o,
    struct vcs_package_build_receipt *out)
{
    memcpy(out->package_root, wire + *o, 32);
    *o += 32;
    memcpy(out->recipe_root, wire + *o, 32);
    *o += 32;
    memcpy(out->lock_root, wire + *o, 32);
    *o += 32;
    uint16_t dep_count = vcs_rd_u16le(wire + *o);
    *o += 2;
    if (dep_count > VCS_PACKAGE_BUILD_MAX_DEPS) {
        vcs_package_build_receipt_init(out);
        return VCS_PACKAGE_BUILD_ERR_DEP_COUNT;
    }
    if (wire_len - *o < (size_t)dep_count * 32u) {
        vcs_package_build_receipt_init(out);
        return VCS_PACKAGE_BUILD_ERR_WIRE_TRUNCATED;
    }
    for (uint16_t i = 0; i < dep_count; i++) {
        memcpy(out->dep_roots[i], wire + *o, 32);
        *o += 32;
    }
    out->dep_count = dep_count;
    return VCS_PACKAGE_BUILD_OK;
}

static enum vcs_package_build_error build_parse_strings(
    const uint8_t *wire, size_t wire_len, size_t *o,
    struct vcs_package_build_receipt *out)
{
    if (!build_rd_str(wire, wire_len, o, out->compiler_id,
                      sizeof(out->compiler_id)) ||
        !build_rd_str(wire, wire_len, o, out->compiler_version,
                      sizeof(out->compiler_version)) ||
        !build_rd_str(wire, wire_len, o, out->flags, sizeof(out->flags))) {
        vcs_package_build_receipt_init(out);
        return VCS_PACKAGE_BUILD_ERR_WIRE_TRUNCATED;
    }
    return VCS_PACKAGE_BUILD_OK;
}

static enum vcs_package_build_error build_parse_capsule(
    const uint8_t *wire, size_t wire_len, size_t *o,
    struct vcs_package_build_receipt *out)
{
    if (out->schema_version == VCS_PACKAGE_BUILD_VERSION) {
        if (wire_len - *o < 32u) {
            vcs_package_build_receipt_init(out);
            return VCS_PACKAGE_BUILD_ERR_WIRE_TRUNCATED;
        }
        memcpy(out->toolchain_capsule_root, wire + *o, 32);
        *o += 32;
        out->has_toolchain_capsule = true;
    }
    return VCS_PACKAGE_BUILD_OK;
}

static enum vcs_package_build_error build_parse_verdict(
    const uint8_t *wire, size_t wire_len, size_t *o,
    struct vcs_package_build_receipt *out)
{
    if (wire_len - *o < 1u + 1u + 1u + 4u + 2u) {
        vcs_package_build_receipt_init(out);
        return VCS_PACKAGE_BUILD_ERR_WIRE_TRUNCATED;
    }
    out->result_class = wire[(*o)++];
    out->isolation = wire[(*o)++];
    uint8_t ran = wire[(*o)++];
    if (ran > 1u) {
        vcs_package_build_receipt_init(out);
        return VCS_PACKAGE_BUILD_ERR_TEST_STATE;
    }
    out->test_ran = ran == 1u;
    out->test_exit_code = vcs_rd_u32le(wire + *o);
    *o += 4;
    return VCS_PACKAGE_BUILD_OK;
}

static enum vcs_package_build_error build_parse_outputs(
    const uint8_t *wire, size_t wire_len, size_t *o,
    struct vcs_package_build_receipt *out)
{
    uint16_t output_count = vcs_rd_u16le(wire + *o);
    *o += 2;
    if (output_count > VCS_PACKAGE_BUILD_MAX_OUTPUTS) {
        vcs_package_build_receipt_init(out);
        return VCS_PACKAGE_BUILD_ERR_OUTPUT_COUNT;
    }
    for (uint16_t i = 0; i < output_count; i++) {
        struct vcs_package_build_output e;
        memset(&e, 0, sizeof(e));
        if (!build_rd_str(wire, wire_len, o, e.path, sizeof(e.path)) ||
            wire_len - *o < 32u + 8u) {
            vcs_package_build_receipt_init(out);
            return VCS_PACKAGE_BUILD_ERR_WIRE_TRUNCATED;
        }
        memcpy(e.sha3, wire + *o, 32);
        *o += 32;
        e.bytes = vcs_rd_u64le(wire + *o);
        *o += 8;
        out->outputs[i] = e;
    }
    out->output_count = output_count;
    return VCS_PACKAGE_BUILD_OK;
}

enum vcs_package_build_error vcs_package_build_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_package_build_receipt *out)
{
    if (!wire || !out)
        LOG_RETURN(VCS_PACKAGE_BUILD_ERR_NULL, BUILD_LOG,
                   "null argument parsing a build receipt");
    vcs_package_build_receipt_init(out);
    enum vcs_package_build_error err = build_parse_envelope(wire, wire_len);
    if (err != VCS_PACKAGE_BUILD_OK)
        return err;
    size_t o = sizeof(build_wire_magic);
    out->schema_version = vcs_rd_u16le(wire + o);
    o += 2;
    err = build_parse_schema(out);
    if (err != VCS_PACKAGE_BUILD_OK)
        return err;
    err = build_parse_roots_deps(wire, wire_len, &o, out);
    if (err != VCS_PACKAGE_BUILD_OK)
        return err;
    err = build_parse_strings(wire, wire_len, &o, out);
    if (err != VCS_PACKAGE_BUILD_OK)
        return err;
    err = build_parse_capsule(wire, wire_len, &o, out);
    if (err != VCS_PACKAGE_BUILD_OK)
        return err;
    err = build_parse_verdict(wire, wire_len, &o, out);
    if (err != VCS_PACKAGE_BUILD_OK)
        return err;
    err = build_parse_outputs(wire, wire_len, &o, out);
    if (err != VCS_PACKAGE_BUILD_OK)
        return err;
    if (o != wire_len) {
        vcs_package_build_receipt_init(out);
        return VCS_PACKAGE_BUILD_ERR_WIRE_TRAILING;
    }
    enum vcs_package_build_error verr = vcs_package_build_validate(out);
    if (verr != VCS_PACKAGE_BUILD_OK) {
        vcs_package_build_receipt_init(out);
        return verr;
    }
    return VCS_PACKAGE_BUILD_OK;
}

enum vcs_package_build_error vcs_package_build_id(
    const struct vcs_package_build_receipt *r, uint8_t out[32])
{
    if (!r || !out)
        LOG_RETURN(VCS_PACKAGE_BUILD_ERR_NULL, BUILD_LOG,
                   "null argument hashing a build receipt");
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    enum vcs_package_build_error err =
        vcs_package_build_serialize(r, &wire, &wire_len);
    if (err != VCS_PACKAGE_BUILD_OK)
        return err;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, build_receipt_domain, sizeof(build_receipt_domain));
    sha3_256_write(&ctx, wire, wire_len);
    sha3_256_finalize(&ctx, out);
    free(wire);
    return VCS_PACKAGE_BUILD_OK;
}
