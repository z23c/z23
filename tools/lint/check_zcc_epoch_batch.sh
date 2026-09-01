#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/zcc-epoch-batch.XXXXXX")
trap 'rm -rf -- "$WORK"' EXIT

read -r -a CC_WORDS <<<"${CC:-cc}"
read -r -a EXTRA_CFLAGS <<<"${CFLAGS:-}"
read -r -a EXTRA_LDFLAGS <<<"${LDFLAGS:-}"
"${CC_WORDS[@]}" -std=c23 -Wall -Wextra -Werror -pedantic \
    "${EXTRA_CFLAGS[@]}" \
    -I"$ROOT/tools" -I"$ROOT/platform/modules/base/include" \
    "$ROOT/tools/zcc_epoch_batch.c" "$ROOT/platform/modules/base/src/safe_alloc.c" \
    -x c - \
    -o "$WORK/check_zcc_epoch_batch" "${EXTRA_LDFLAGS[@]}" <<'EOF_C'
#include "zcc_epoch_batch.h"
#include "base/safe_alloc.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EPOCH_HEX \
    "33333333333333333333333333333333" \
    "33333333333333333333333333333333"
#define EPOCH_DIR "epochs/" EPOCH_HEX "/"

struct buffer {
    uint8_t bytes[4096];
    size_t length;
};

struct fixture {
    struct buffer wire;
    size_t version_offset;
    size_t profile_length_offset;
    size_t source_id_length_offset;
    size_t source_id_data_offset;
    size_t complete_offset;
    size_t session_offset;
    size_t bindings_end_offset;
    size_t common_count_offset;
    size_t common_arg_offset;
    size_t common_arg_end_offset;
    size_t job_count_offset;
    size_t first_mode_offset;
    size_t first_job_header_end_offset;
    size_t first_job_arg_offset;
    size_t first_job_arg_end_offset;
};

static unsigned checks;

static void fail(const char *name, enum zcc_epoch_batch_result got,
                 enum zcc_epoch_batch_result expected)
{
    fprintf(stderr, "%s: got %s, expected %s\n", name,
            zcc_epoch_batch_result_name(got),
            zcc_epoch_batch_result_name(expected));
    exit(1);
}

static void put_u32(struct buffer *buffer, uint32_t value)
{
    if (buffer->length > sizeof(buffer->bytes) - 4u)
        exit(2);
    buffer->bytes[buffer->length++] = (uint8_t)value;
    buffer->bytes[buffer->length++] = (uint8_t)(value >> 8);
    buffer->bytes[buffer->length++] = (uint8_t)(value >> 16);
    buffer->bytes[buffer->length++] = (uint8_t)(value >> 24);
}

static void patch_u32(struct buffer *buffer, size_t offset, uint32_t value)
{
    buffer->bytes[offset] = (uint8_t)value;
    buffer->bytes[offset + 1u] = (uint8_t)(value >> 8);
    buffer->bytes[offset + 2u] = (uint8_t)(value >> 16);
    buffer->bytes[offset + 3u] = (uint8_t)(value >> 24);
}

static void remove_byte(struct buffer *buffer, size_t offset)
{
    if (offset >= buffer->length)
        exit(2);
    memmove(buffer->bytes + offset, buffer->bytes + offset + 1u,
            buffer->length - offset - 1u);
    buffer->length--;
}

static void put_bytes(struct buffer *buffer, const void *bytes, size_t length)
{
    if (length > UINT32_MAX || length > sizeof(buffer->bytes) ||
        buffer->length > sizeof(buffer->bytes) - length)
        exit(2);
    put_u32(buffer, (uint32_t)length);
    memcpy(buffer->bytes + buffer->length, bytes, length);
    buffer->length += length;
}

static void put_text(struct buffer *buffer, const char *text)
{
    put_bytes(buffer, text, strlen(text));
}

static void put_job(struct fixture *fixture, const char *source,
                    const char *output, const char *depfile,
                    enum zcc_epoch_batch_mode mode, bool first)
{
    put_text(&fixture->wire, source);
    put_text(&fixture->wire, output);
    put_text(&fixture->wire, depfile);
    if (first)
        fixture->first_mode_offset = fixture->wire.length;
    put_u32(&fixture->wire, (uint32_t)mode);
    put_u32(&fixture->wire, 2);
    if (first) {
        fixture->first_job_header_end_offset = fixture->wire.length;
        fixture->first_job_arg_offset = fixture->wire.length + 4u;
    }
    put_text(&fixture->wire, "-DUNIT=1");
    if (first)
        fixture->first_job_arg_end_offset = fixture->wire.length;
    put_text(&fixture->wire, "-O2");
}

static struct fixture make_fixture(const char *source,
                                   const char *first_output,
                                   const char *first_depfile,
                                   const char *second_output,
                                   const char *second_depfile)
{
    struct fixture fixture = {0};
    uint8_t root[ZCC_EPOCH_BATCH_ROOT_BYTES];
    memset(root, 0x5a, sizeof(root));
    put_text(&fixture.wire, "zcc.epoch.batch");
    fixture.version_offset = fixture.wire.length;
    put_u32(&fixture.wire, ZCC_EPOCH_BATCH_VERSION);
    fixture.profile_length_offset = fixture.wire.length;
    put_text(&fixture.wire, "build-only");
    memset(root, 0x11, sizeof(root));
    fixture.source_id_length_offset = fixture.wire.length;
    fixture.source_id_data_offset = fixture.wire.length + 4u;
    put_bytes(&fixture.wire, root, sizeof(root));
    fixture.complete_offset = fixture.wire.length;
    put_u32(&fixture.wire, 1);
    memset(root, 0x22, sizeof(root));
    put_bytes(&fixture.wire, root, sizeof(root));
    memset(root, 0x33, sizeof(root));
    put_bytes(&fixture.wire, root, sizeof(root));
    memset(root, 0x44, sizeof(root));
    put_bytes(&fixture.wire, root, sizeof(root));
    memset(root, 0x55, sizeof(root));
    put_bytes(&fixture.wire, root, sizeof(root));
    memset(root, 0x66, sizeof(root));
    put_bytes(&fixture.wire, root, sizeof(root));
    fixture.session_offset = fixture.wire.length + 4u;
    put_text(&fixture.wire, EPOCH_DIR "session-7");
    fixture.bindings_end_offset = fixture.wire.length;
    fixture.common_count_offset = fixture.wire.length;
    put_u32(&fixture.wire, 3);
    put_text(&fixture.wire, "cc");
    put_text(&fixture.wire, "-std=c23");
    fixture.common_arg_offset = fixture.wire.length + 4u;
    put_text(&fixture.wire, "-Wall");
    fixture.common_arg_end_offset = fixture.wire.length;
    fixture.job_count_offset = fixture.wire.length;
    put_u32(&fixture.wire, 2);
    put_job(&fixture, source, first_output, first_depfile,
            ZCC_EPOCH_BATCH_DEP, true);
    put_job(&fixture, "lib/b.c", second_output, second_depfile,
            ZCC_EPOCH_BATCH_COVERAGE, false);
    return fixture;
}

static enum zcc_epoch_batch_result decode(
    const struct buffer *wire, size_t length,
    struct zcc_epoch_batch_error *error)
{
    struct zcc_epoch_batch_manifest manifest = {0};
    enum zcc_epoch_batch_result result = zcc_epoch_batch_manifest_decode(
        wire->bytes, length, &manifest, error);
    zcc_epoch_batch_manifest_free(&manifest);
    return result;
}

static void expect(const char *name, struct fixture fixture,
                   enum zcc_epoch_batch_result expected, size_t offset,
                   uint32_t job_index)
{
    struct zcc_epoch_batch_error error = {0};
    enum zcc_epoch_batch_result got = decode(
        &fixture.wire, fixture.wire.length, &error);
    if (got != expected || error.code != expected ||
        error.offset != offset || error.job_index != job_index)
        fail(name, got, expected);
    checks++;
}

static void expect_allocation_failure(const char *label,
                                      const struct fixture *fixture,
                                      size_t offset, uint32_t job_index)
{
    struct zcc_epoch_batch_manifest manifest = {0};
    struct zcc_epoch_batch_error error = {0};
    zcl_alloc_fault_fail_next(label);
    enum zcc_epoch_batch_result result = zcc_epoch_batch_manifest_decode(
        fixture->wire.bytes, fixture->wire.length, &manifest, &error);
    zcl_alloc_fault_clear();
    if (result != ZCC_EPOCH_BATCH_ALLOCATION ||
        error.code != ZCC_EPOCH_BATCH_ALLOCATION ||
        error.offset != offset || error.job_index != job_index ||
        manifest.common_argv || manifest.jobs || manifest.job_argv ||
        manifest.common_argc != 0 || manifest.job_count != 0 ||
        manifest.job_argc != 0)
        fail(label, result, ZCC_EPOCH_BATCH_ALLOCATION);
    checks++;
}

static bool bytes_equal(const struct zcc_epoch_batch_bytes *left,
                        const struct zcc_epoch_batch_bytes *right)
{
    return left->length == right->length &&
           (left->length == 0 ||
            memcmp(left->data, right->data, left->length) == 0);
}

static bool manifests_equal(const struct zcc_epoch_batch_manifest *left,
                            const struct zcc_epoch_batch_manifest *right)
{
    if (!bytes_equal(&left->profile, &right->profile) ||
        !bytes_equal(&left->source_id, &right->source_id) ||
        left->source_complete != right->source_complete ||
        !bytes_equal(&left->mutation, &right->mutation) ||
        !bytes_equal(&left->epoch, &right->epoch) ||
        !bytes_equal(&left->compiler_id, &right->compiler_id) ||
        !bytes_equal(&left->environment_root, &right->environment_root) ||
        !bytes_equal(&left->build_root, &right->build_root) ||
        !bytes_equal(&left->session, &right->session) ||
        left->common_argc != right->common_argc ||
        left->job_count != right->job_count ||
        left->job_argc != right->job_argc)
        return false;
    for (uint32_t i = 0; i < left->common_argc; ++i)
        if (!bytes_equal(&left->common_argv[i], &right->common_argv[i]))
            return false;
    for (uint32_t i = 0; i < left->job_count; ++i) {
        const struct zcc_epoch_batch_job *a = &left->jobs[i];
        const struct zcc_epoch_batch_job *b = &right->jobs[i];
        if (!bytes_equal(&a->source, &b->source) ||
            !bytes_equal(&a->output, &b->output) ||
            !bytes_equal(&a->depfile, &b->depfile) || a->mode != b->mode ||
            a->argv_offset != b->argv_offset || a->argv_count != b->argv_count)
            return false;
    }
    for (uint32_t i = 0; i < left->job_argc; ++i)
        if (!bytes_equal(&left->job_argv[i], &right->job_argv[i]))
            return false;
    return true;
}

static void expect_encode(const char *name,
                          const struct zcc_epoch_batch_manifest *manifest,
                          enum zcc_epoch_batch_result expected,
                          uint32_t job_index)
{
    struct zcc_epoch_batch_wire wire = {0};
    struct zcc_epoch_batch_error error = {0};
    enum zcc_epoch_batch_result got = zcc_epoch_batch_manifest_encode(
        manifest, &wire, &error);
    if (got != expected || error.code != expected || error.offset != 0 ||
        error.job_index != job_index || wire.data || wire.length != 0)
        fail(name, got, expected);
    checks++;
}

static void expect_encoder_allocation_failure(
    const char *label, const struct zcc_epoch_batch_manifest *manifest)
{
    struct zcc_epoch_batch_wire wire = {0};
    struct zcc_epoch_batch_error error = {0};
    zcl_alloc_fault_fail_next(label);
    enum zcc_epoch_batch_result result = zcc_epoch_batch_manifest_encode(
        manifest, &wire, &error);
    zcl_alloc_fault_clear();
    if (result != ZCC_EPOCH_BATCH_ALLOCATION ||
        error.code != ZCC_EPOCH_BATCH_ALLOCATION || error.offset != 0 ||
        error.job_index != UINT32_MAX || wire.data || wire.length != 0)
        fail(label, result, ZCC_EPOCH_BATCH_ALLOCATION);
    checks++;
}

int main(void)
{
    struct fixture valid = make_fixture(
        "lib/a.c", EPOCH_DIR "obj/a.o", EPOCH_DIR "obj/a.d",
        EPOCH_DIR "obj/b.o", EPOCH_DIR "obj/b.d");
    struct zcc_epoch_batch_manifest manifest = {0};
    struct zcc_epoch_batch_error error = {0};
    enum zcc_epoch_batch_result result = zcc_epoch_batch_manifest_decode(
        valid.wire.bytes, valid.wire.length, &manifest, &error);
    if (result != ZCC_EPOCH_BATCH_OK || manifest.job_count != 2 ||
        error.code != ZCC_EPOCH_BATCH_OK || error.offset != 0 ||
        error.job_index != UINT32_MAX ||
        manifest.common_argc != 3 || manifest.job_argc != 4 ||
        manifest.source_complete != 1 ||
        manifest.source_id.length != ZCC_EPOCH_BATCH_ROOT_BYTES ||
        manifest.epoch.length != ZCC_EPOCH_BATCH_ROOT_BYTES ||
        manifest.jobs[1].argv_offset != 2 ||
        manifest.jobs[1].mode != ZCC_EPOCH_BATCH_COVERAGE)
        fail("valid manifest", result, ZCC_EPOCH_BATCH_OK);

    struct zcc_epoch_batch_wire encoded = {0};
    result = zcc_epoch_batch_manifest_encode(&manifest, &encoded, &error);
    if (result != ZCC_EPOCH_BATCH_OK || error.code != ZCC_EPOCH_BATCH_OK ||
        error.offset != 0 || error.job_index != UINT32_MAX ||
        encoded.length != valid.wire.length ||
        memcmp(encoded.data, valid.wire.bytes, valid.wire.length) != 0)
        fail("canonical decode encode", result, ZCC_EPOCH_BATCH_OK);
    checks++;

    struct zcc_epoch_batch_manifest round_trip = {0};
    result = zcc_epoch_batch_manifest_decode(
        encoded.data, encoded.length, &round_trip, &error);
    if (result != ZCC_EPOCH_BATCH_OK ||
        !manifests_equal(&manifest, &round_trip))
        fail("semantic encode decode", result, ZCC_EPOCH_BATCH_OK);
    zcc_epoch_batch_manifest_free(&round_trip);
    checks++;

    struct zcc_epoch_batch_job no_arg_jobs[2];
    memcpy(no_arg_jobs, manifest.jobs, sizeof(no_arg_jobs));
    no_arg_jobs[0].argv_offset = 0;
    no_arg_jobs[0].argv_count = 0;
    no_arg_jobs[1].argv_offset = 0;
    no_arg_jobs[1].argv_count = 0;
    struct zcc_epoch_batch_manifest no_args = manifest;
    no_args.jobs = no_arg_jobs;
    no_args.job_argv = NULL;
    no_args.job_argc = 0;
    struct zcc_epoch_batch_wire no_arg_wire = {0};
    result = zcc_epoch_batch_manifest_encode(&no_args, &no_arg_wire, &error);
    round_trip = (struct zcc_epoch_batch_manifest){0};
    if (result != ZCC_EPOCH_BATCH_OK ||
        zcc_epoch_batch_manifest_decode(no_arg_wire.data, no_arg_wire.length,
                                        &round_trip, &error) !=
            ZCC_EPOCH_BATCH_OK ||
        !manifests_equal(&no_args, &round_trip))
        fail("zero suffix argument round trip", result,
             ZCC_EPOCH_BATCH_OK);
    zcc_epoch_batch_manifest_free(&round_trip);
    zcc_epoch_batch_wire_free(&no_arg_wire);
    checks++;

    result = zcc_epoch_batch_manifest_encode(&manifest, NULL, &error);
    if (result != ZCC_EPOCH_BATCH_ARGUMENT ||
        error.code != ZCC_EPOCH_BATCH_ARGUMENT || error.offset != 0 ||
        error.job_index != UINT32_MAX)
        fail("null encoder output", result, ZCC_EPOCH_BATCH_ARGUMENT);
    checks++;

    struct zcc_epoch_batch_wire no_error_wire = {0};
    result = zcc_epoch_batch_manifest_encode(
        &manifest, &no_error_wire, NULL);
    if (result != ZCC_EPOCH_BATCH_OK || !no_error_wire.data ||
        no_error_wire.length != valid.wire.length)
        fail("optional encoder error", result, ZCC_EPOCH_BATCH_OK);
    zcc_epoch_batch_wire_free(&no_error_wire);
    zcc_epoch_batch_wire_free(&no_error_wire);
    checks++;

    uint8_t *saved_wire = encoded.data;
    size_t saved_wire_length = encoded.length;
    result = zcc_epoch_batch_manifest_encode(&manifest, &encoded, &error);
    if (result != ZCC_EPOCH_BATCH_ARGUMENT ||
        error.code != ZCC_EPOCH_BATCH_ARGUMENT || error.offset != 0 ||
        error.job_index != UINT32_MAX || encoded.data != saved_wire ||
        encoded.length != saved_wire_length)
        fail("live wire ownership", result, ZCC_EPOCH_BATCH_ARGUMENT);
    zcc_epoch_batch_wire_free(&encoded);
    checks++;

    struct zcc_epoch_batch_manifest malformed = manifest;
    malformed.profile.data = NULL;
    expect_encode("encoder missing profile", &malformed,
                  ZCC_EPOCH_BATCH_AUTHORITY, UINT32_MAX);

    malformed = manifest;
    malformed.common_argv = NULL;
    expect_encode("encoder missing common argv", &malformed,
                  ZCC_EPOCH_BATCH_FORMAT, UINT32_MAX);

    malformed = manifest;
    malformed.common_argc = ZCC_EPOCH_BATCH_MAX_ARGS + 1u;
    expect_encode("encoder common argument limit", &malformed,
                  ZCC_EPOCH_BATCH_LIMIT, UINT32_MAX);

    malformed = manifest;
    malformed.job_argv = NULL;
    expect_encode("encoder missing job argv", &malformed,
                  ZCC_EPOCH_BATCH_ARGUMENT, UINT32_MAX);

    malformed = manifest;
    malformed.job_count = ZCC_EPOCH_BATCH_MAX_JOBS + 1u;
    expect_encode("encoder job count limit", &malformed,
                  ZCC_EPOCH_BATCH_JOB_COUNT, UINT32_MAX);

    malformed = manifest;
    malformed.job_argc = ZCC_EPOCH_BATCH_MAX_ARGS;
    expect_encode("encoder aggregate argument limit", &malformed,
                  ZCC_EPOCH_BATCH_LIMIT, UINT32_MAX);

    struct zcc_epoch_batch_bytes common_args[3];
    memcpy(common_args, manifest.common_argv, sizeof(common_args));
    malformed = manifest;
    malformed.common_argv = common_args;
    malformed.common_argv[2].length = ZCC_EPOCH_BATCH_MAX_FIELD + 1u;
    expect_encode("encoder field limit", &malformed,
                  ZCC_EPOCH_BATCH_LIMIT, UINT32_MAX);

    uint8_t *large_arg = zcl_malloc(
        ZCC_EPOCH_BATCH_MAX_FIELD, "zcc epoch batch wire-limit fixture");
    if (!large_arg)
        exit(2);
    memset(large_arg, 'x', ZCC_EPOCH_BATCH_MAX_FIELD);
    large_arg[0] = '-';
    struct zcc_epoch_batch_bytes large_args[66];
    large_args[0] = manifest.common_argv[0];
    for (size_t i = 1; i < sizeof(large_args) / sizeof(large_args[0]); ++i) {
        large_args[i].data = large_arg;
        large_args[i].length = ZCC_EPOCH_BATCH_MAX_FIELD;
    }
    malformed = manifest;
    malformed.common_argv = large_args;
    malformed.common_argc =
        (uint32_t)(sizeof(large_args) / sizeof(large_args[0]));
    expect_encode("encoder aggregate wire limit", &malformed,
                  ZCC_EPOCH_BATCH_LIMIT, UINT32_MAX);
    free(large_arg);

    struct zcc_epoch_batch_job jobs[2];
    memcpy(jobs, manifest.jobs, sizeof(jobs));
    malformed = manifest;
    malformed.jobs = jobs;
    malformed.jobs[1].argv_offset = 1;
    expect_encode("encoder noncanonical argv offset", &malformed,
                  ZCC_EPOCH_BATCH_ARGUMENT, 1u);

    memcpy(jobs, manifest.jobs, sizeof(jobs));
    malformed = manifest;
    malformed.jobs = jobs;
    malformed.jobs[0].mode = (enum zcc_epoch_batch_mode)99;
    expect_encode("encoder unknown mode", &malformed,
                  ZCC_EPOCH_BATCH_FORMAT, 0u);

    malformed = manifest;
    malformed.job_argc++;
    expect_encode("encoder unused job argument", &malformed,
                  ZCC_EPOCH_BATCH_ARGUMENT, UINT32_MAX);

    memcpy(jobs, manifest.jobs, sizeof(jobs));
    malformed = manifest;
    malformed.jobs = jobs;
    malformed.jobs[1].output = malformed.jobs[0].output;
    malformed.jobs[1].depfile = malformed.jobs[0].depfile;
    expect_encode("encoder destination collision", &malformed,
                  ZCC_EPOCH_BATCH_DESTINATION_COLLISION, UINT32_MAX);

    expect_encoder_allocation_failure(
        "zcc.epoch_batch.destinations", &manifest);
    expect_encoder_allocation_failure("zcc.epoch_batch.wire", &manifest);
    expect_encode("encoder null manifest", NULL,
                  ZCC_EPOCH_BATCH_ARGUMENT, UINT32_MAX);

    struct zcc_epoch_batch_bytes *saved_common = manifest.common_argv;
    struct zcc_epoch_batch_job *saved_jobs = manifest.jobs;
    struct zcc_epoch_batch_bytes *saved_job_argv = manifest.job_argv;
    result = zcc_epoch_batch_manifest_decode(
        valid.wire.bytes, valid.wire.length, &manifest, &error);
    if (result != ZCC_EPOCH_BATCH_ARGUMENT ||
        error.code != ZCC_EPOCH_BATCH_ARGUMENT || error.offset != 0 ||
        error.job_index != UINT32_MAX || manifest.common_argv != saved_common ||
        manifest.jobs != saved_jobs || manifest.job_argv != saved_job_argv)
        fail("live output ownership", result, ZCC_EPOCH_BATCH_ARGUMENT);
    checks++;
    zcc_epoch_batch_manifest_free(&manifest);
    checks++;

    manifest.source_complete = 1;
    result = zcc_epoch_batch_manifest_decode(
        valid.wire.bytes, valid.wire.length, &manifest, &error);
    if (result != ZCC_EPOCH_BATCH_ARGUMENT ||
        error.code != ZCC_EPOCH_BATCH_ARGUMENT || error.offset != 0 ||
        error.job_index != UINT32_MAX || manifest.source_complete != 1)
        fail("nonzero output ownership", result, ZCC_EPOCH_BATCH_ARGUMENT);
    manifest = (struct zcc_epoch_batch_manifest){0};
    checks++;

    result = zcc_epoch_batch_manifest_decode(
        NULL, 0, &manifest, &error);
    if (result != ZCC_EPOCH_BATCH_ARGUMENT ||
        error.code != ZCC_EPOCH_BATCH_ARGUMENT || error.offset != 0 ||
        error.job_index != UINT32_MAX)
        fail("null decoder wire", result, ZCC_EPOCH_BATCH_ARGUMENT);
    result = zcc_epoch_batch_manifest_decode(
        valid.wire.bytes, valid.wire.length, NULL, &error);
    if (result != ZCC_EPOCH_BATCH_ARGUMENT ||
        error.code != ZCC_EPOCH_BATCH_ARGUMENT || error.offset != 0 ||
        error.job_index != UINT32_MAX)
        fail("null decoder output", result, ZCC_EPOCH_BATCH_ARGUMENT);
    checks++;

    result = zcc_epoch_batch_manifest_decode(
        valid.wire.bytes, (size_t)ZCC_EPOCH_BATCH_MAX_WIRE + 1u,
        &manifest, &error);
    if (result != ZCC_EPOCH_BATCH_LIMIT ||
        error.code != ZCC_EPOCH_BATCH_LIMIT || error.offset != 0 ||
        error.job_index != UINT32_MAX)
        fail("wire limit", result, ZCC_EPOCH_BATCH_LIMIT);
    checks++;

    for (size_t length = 0; length < valid.wire.length; ++length) {
        error = (struct zcc_epoch_batch_error){0};
        result = decode(&valid.wire, length, &error);
        if (result != ZCC_EPOCH_BATCH_TRUNCATED ||
            error.code != ZCC_EPOCH_BATCH_TRUNCATED ||
            error.offset > length ||
            (error.job_index != UINT32_MAX && error.job_index >= 2u))
            fail("every truncation", result, ZCC_EPOCH_BATCH_TRUNCATED);
    }
    checks++;

    struct fixture changed = valid;
    changed.wire.bytes[changed.wire.length++] = 0;
    expect("trailing byte", changed, ZCC_EPOCH_BATCH_TRAILING_BYTES,
           valid.wire.length, UINT32_MAX);

    changed = valid;
    patch_u32(&changed.wire, changed.version_offset, 2);
    expect("unknown version", changed, ZCC_EPOCH_BATCH_UNSUPPORTED_VERSION,
           changed.version_offset + 4u, UINT32_MAX);

    changed = valid;
    changed.wire.bytes[4] ^= 1u;
    expect("wrong magic", changed, ZCC_EPOCH_BATCH_FORMAT,
           changed.version_offset + 4u, UINT32_MAX);

    changed = valid;
    patch_u32(&changed.wire, changed.profile_length_offset,
              ZCC_EPOCH_BATCH_MAX_FIELD + 1u);
    expect("field limit", changed, ZCC_EPOCH_BATCH_LIMIT,
           changed.profile_length_offset + 4u, UINT32_MAX);

    changed = valid;
    patch_u32(&changed.wire, changed.source_id_length_offset,
              ZCC_EPOCH_BATCH_ROOT_BYTES - 1u);
    remove_byte(&changed.wire,
                changed.source_id_data_offset +
                ZCC_EPOCH_BATCH_ROOT_BYTES - 1u);
    expect("source root length", changed, ZCC_EPOCH_BATCH_AUTHORITY,
           changed.bindings_end_offset - 1u, UINT32_MAX);

    changed = valid;
    patch_u32(&changed.wire, changed.job_count_offset, 0);
    expect("zero jobs", changed, ZCC_EPOCH_BATCH_JOB_COUNT,
           changed.job_count_offset + 4u, UINT32_MAX);

    changed = valid;
    patch_u32(&changed.wire, changed.complete_offset, 0);
    expect("incomplete source", changed, ZCC_EPOCH_BATCH_AUTHORITY,
           changed.bindings_end_offset, UINT32_MAX);

    changed = valid;
    changed.wire.bytes[changed.session_offset + sizeof("epochs/") - 1u] = '2';
    expect("session outside epoch", changed, ZCC_EPOCH_BATCH_AUTHORITY,
           changed.bindings_end_offset, UINT32_MAX);

    changed = valid;
    patch_u32(&changed.wire, changed.common_count_offset, 0);
    expect("empty compiler argv", changed, ZCC_EPOCH_BATCH_FORMAT,
           changed.common_count_offset + 4u, UINT32_MAX);

    changed = valid;
    patch_u32(&changed.wire, changed.job_count_offset,
              ZCC_EPOCH_BATCH_MAX_JOBS + 1u);
    expect("job limit", changed, ZCC_EPOCH_BATCH_JOB_COUNT,
           changed.job_count_offset + 4u, UINT32_MAX);

    changed = valid;
    patch_u32(&changed.wire, changed.job_count_offset, 3);
    expect("count mismatch", changed, ZCC_EPOCH_BATCH_TRUNCATED,
           changed.wire.length, 2u);

    changed = valid;
    patch_u32(&changed.wire, changed.first_mode_offset + 4u,
              ZCC_EPOCH_BATCH_MAX_ARGS);
    expect("aggregate argument limit", changed, ZCC_EPOCH_BATCH_LIMIT,
           changed.first_job_header_end_offset, 0u);

    changed = make_fixture("lib/a.c", EPOCH_DIR "obj/a.o",
                           EPOCH_DIR "obj/a.d", EPOCH_DIR "obj/a.o",
                           EPOCH_DIR "obj/a.d");
    expect("duplicate output", changed,
           ZCC_EPOCH_BATCH_DESTINATION_COLLISION,
           changed.wire.length, UINT32_MAX);

    changed = make_fixture("lib/a.c", EPOCH_DIR "obj/A.o",
                           EPOCH_DIR "obj/A.d", EPOCH_DIR "obj/a.o",
                           EPOCH_DIR "obj/a.d");
    expect("ascii case destination alias", changed,
           ZCC_EPOCH_BATCH_DESTINATION_COLLISION,
           changed.wire.length, UINT32_MAX);

    changed = make_fixture("lib/a.c", EPOCH_DIR "obj/a",
                           EPOCH_DIR "obj/a.d", EPOCH_DIR "obj/b.o",
                           EPOCH_DIR "obj/b.d");
    expect("non-object output", changed, ZCC_EPOCH_BATCH_PATH,
           changed.first_job_header_end_offset, 0u);

    changed = make_fixture("../lib/a.c", EPOCH_DIR "obj/a.o",
                           EPOCH_DIR "obj/a.d", EPOCH_DIR "obj/b.o",
                           EPOCH_DIR "obj/b.d");
    expect("parent traversal", changed, ZCC_EPOCH_BATCH_PATH,
           changed.first_job_header_end_offset, 0u);

    changed = make_fixture("lib/a.c", "/obj/a.o", EPOCH_DIR "obj/a.d",
                           EPOCH_DIR "obj/b.o", EPOCH_DIR "obj/b.d");
    expect("absolute output", changed, ZCC_EPOCH_BATCH_PATH,
           changed.first_job_header_end_offset, 0u);

    changed = make_fixture("lib/a.c", "epochs/22/obj/a.o",
                           "epochs/22/obj/a.d", EPOCH_DIR "obj/b.o",
                           EPOCH_DIR "obj/b.d");
    expect("output outside epoch", changed, ZCC_EPOCH_BATCH_PATH,
           changed.first_job_header_end_offset, 0u);

    changed = make_fixture("lib/a.c", EPOCH_DIR "obj/a.o",
                           EPOCH_DIR "dep/a.d", EPOCH_DIR "obj/b.o",
                           EPOCH_DIR "obj/b.d");
    expect("depfile does not match output", changed, ZCC_EPOCH_BATCH_PATH,
           changed.first_job_header_end_offset, 0u);

    changed = make_fixture("lib\\..\\a.c", EPOCH_DIR "obj/a.o",
                           EPOCH_DIR "obj/a.d", EPOCH_DIR "obj/b.o",
                           EPOCH_DIR "obj/b.d");
    expect("windows traversal", changed, ZCC_EPOCH_BATCH_PATH,
           changed.first_job_header_end_offset, 0u);

    changed = make_fixture("lib//a.c", EPOCH_DIR "obj/a.o",
                           EPOCH_DIR "obj/a.d", EPOCH_DIR "obj/b.o",
                           EPOCH_DIR "obj/b.d");
    expect("empty path component", changed, ZCC_EPOCH_BATCH_PATH,
           changed.first_job_header_end_offset, 0u);

    changed = valid;
    patch_u32(&changed.wire, changed.first_mode_offset, 99);
    expect("unknown mode", changed, ZCC_EPOCH_BATCH_FORMAT,
           changed.first_job_header_end_offset, 0u);

    changed = valid;
    changed.wire.bytes[changed.common_arg_offset] = 0;
    expect("nul argument", changed, ZCC_EPOCH_BATCH_ARGV,
           changed.common_arg_end_offset, UINT32_MAX);

    changed = valid;
    memcpy(changed.wire.bytes + changed.common_arg_offset, "@Wall", 5u);
    expect("response-file argument", changed, ZCC_EPOCH_BATCH_ARGV,
           changed.common_arg_end_offset, UINT32_MAX);

    changed = valid;
    memcpy(changed.wire.bytes + changed.first_job_arg_offset,
           "-oFILE=x", 8u);
    expect("output override argument", changed, ZCC_EPOCH_BATCH_ARGV,
           changed.first_job_arg_end_offset, 0u);

    changed = valid;
    memcpy(changed.wire.bytes + changed.first_job_arg_offset,
           "-specs=x", 8u);
    expect("specs input argument", changed, ZCC_EPOCH_BATCH_ARGV,
           changed.first_job_arg_end_offset, 0u);

    changed = valid;
    memcpy(changed.wire.bytes + changed.first_job_arg_offset,
           "-fplugin", 8u);
    expect("plugin input argument", changed, ZCC_EPOCH_BATCH_ARGV,
           changed.first_job_arg_end_offset, 0u);

    changed = valid;
    memcpy(changed.wire.bytes + changed.first_job_arg_offset,
           "-MFfilex", 8u);
    expect("depfile override argument", changed, ZCC_EPOCH_BATCH_ARGV,
           changed.first_job_arg_end_offset, 0u);

    changed = valid;
    memcpy(changed.wire.bytes + changed.first_job_arg_offset,
           "source.c", 8u);
    expect("extra source operand", changed, ZCC_EPOCH_BATCH_ARGV,
           changed.first_job_arg_end_offset, 0u);

    expect_allocation_failure(
        "zcc.epoch_batch.common_argv", &valid,
        valid.common_count_offset + 4u, UINT32_MAX);
    expect_allocation_failure(
        "zcc.epoch_batch.jobs", &valid,
        valid.job_count_offset + 4u, UINT32_MAX);
    expect_allocation_failure(
        "zcc.epoch_batch.job_argv", &valid,
        valid.first_job_header_end_offset, 0u);
    expect_allocation_failure(
        "zcc.epoch_batch.destinations", &valid,
        valid.wire.length, UINT32_MAX);

    printf("check_zcc_epoch_batch: OK — %u codec cases, %zu truncations\n",
           checks, valid.wire.length);
    return 0;
}
EOF_C

"$WORK/check_zcc_epoch_batch"
