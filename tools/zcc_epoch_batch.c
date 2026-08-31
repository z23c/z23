/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 *
 * Bounded canonical codec for versioned native epoch-batch manifests. */

#include "zcc_epoch_batch.h"

#include "base/safe_alloc.h"
#include "base/serialize_le.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t batch_magic[] = "zcc.epoch.batch";

struct batch_reader {
    const uint8_t *wire;
    size_t size;
    size_t offset;
    struct zcc_epoch_batch_error *error;
    bool field_limit;
};

struct batch_writer {
    uint8_t *wire;
    size_t size;
    size_t offset;
};

static enum zcc_epoch_batch_result batch_fail(
    struct batch_reader *reader, enum zcc_epoch_batch_result code,
    uint32_t job_index)
{
    if (reader->error) {
        reader->error->code = code;
        reader->error->offset = reader->offset;
        reader->error->job_index = job_index;
    }
    return code;
}

static bool batch_read_u32(struct batch_reader *reader, uint32_t *value)
{
    if (reader->size - reader->offset < 4u)
        return false;
    const uint8_t *p = reader->wire + reader->offset;
    *value = zcl_read_u32_le(p);
    reader->offset += 4u;
    return true;
}

static bool batch_read_field(struct batch_reader *reader,
                             struct zcc_epoch_batch_bytes *field)
{
    uint32_t length = 0;
    if (!batch_read_u32(reader, &length))
        return false;
    if (length > ZCC_EPOCH_BATCH_MAX_FIELD) {
        reader->field_limit = true;
        return false;
    }
    if ((size_t)length > reader->size - reader->offset)
        return false;
    field->data = reader->wire + reader->offset;
    field->length = length;
    reader->offset += length;
    return true;
}

static bool batch_field_equal(const struct zcc_epoch_batch_bytes *left,
                              const struct zcc_epoch_batch_bytes *right)
{
    return left->length == right->length &&
           (left->length == 0 ||
            (left->data && right->data &&
             memcmp(left->data, right->data, left->length) == 0));
}

static enum zcc_epoch_batch_result batch_field_failure(
    struct batch_reader *reader, uint32_t job_index)
{
    return batch_fail(reader, reader->field_limit ? ZCC_EPOCH_BATCH_LIMIT :
                      ZCC_EPOCH_BATCH_TRUNCATED, job_index);
}

static bool batch_field_is_text(const struct zcc_epoch_batch_bytes *field)
{
    return field->data && field->length != 0 &&
           memchr(field->data, '\0', field->length) == NULL;
}

static bool batch_arg_equals(const struct zcc_epoch_batch_bytes *arg,
                             const char *text)
{
    size_t length = strlen(text);
    return arg->length == length && memcmp(arg->data, text, length) == 0;
}

static bool batch_arg_starts(const struct zcc_epoch_batch_bytes *arg,
                             const char *prefix)
{
    size_t length = strlen(prefix);
    return arg->length >= length && memcmp(arg->data, prefix, length) == 0;
}

static bool batch_compiler_arg_safe(const struct zcc_epoch_batch_bytes *arg,
                                    bool command)
{
    if (!batch_field_is_text(arg) || memchr(arg->data, '@', arg->length))
        return false;
    if (command)
        return arg->data[0] != '-';
    if (arg->data[0] != '-')
        return false;
    static const char *const exact[] = {
        "-", "--", "-c", "-E", "-S", "-M", "-MM", "-MD", "-MMD",
        "-MP", "-o", "-MF", "-MT", "-MQ", "-MJ", "-Xclang",
        "-Xassembler", "-load", "-wrapper", "-specs", "--specs",
        "-gsplit-dwarf", "-ftime-trace", "-fstack-usage",
        "-fsyntax-only", "-emit-llvm", "-###", "--help", "--version"
    };
    for (size_t i = 0; i < sizeof(exact) / sizeof(exact[0]); ++i) {
        if (batch_arg_equals(arg, exact[i]))
            return false;
    }
    static const char *const prefixes[] = {
        "-o", "--output=", "-MF", "-MT", "-MQ", "-MJ", "-Wp,",
        "-specs=", "--specs=", "-fplugin", "-fpass-plugin=", "-load=",
        "-wrapper=", "-save-temps", "-dumpbase", "-dumpdir", "-auxbase",
        "-gsplit-dwarf=", "-ftime-trace=", "-fdump-", "-fmodules",
        "-serialize-diagnostics=", "-fdiagnostics-serialization-file=",
        "-fmodules-cache-path=", "-fmodule-output="
    };
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); ++i) {
        if (batch_arg_starts(arg, prefixes[i]))
            return false;
    }
    return true;
}

static bool batch_path_is_relative(const struct zcc_epoch_batch_bytes *path)
{
    if (!batch_field_is_text(path) ||
        path->length > ZCC_EPOCH_BATCH_MAX_PATH || path->data[0] == '/' ||
        path->data[path->length - 1u] == '/')
        return false;
    size_t component = 0;
    for (uint32_t i = 0; i <= path->length; ++i) {
        if (i != path->length &&
            (path->data[i] == '\\' || path->data[i] == ':'))
            return false;
        if (i != path->length && path->data[i] != '/')
            continue;
        size_t length = (size_t)i - component;
        if (length == 0 ||
            (length == 1 && path->data[component] == '.') ||
            (length == 2 && path->data[component] == '.' &&
             path->data[component + 1u] == '.'))
            return false;
        component = (size_t)i + 1u;
    }
    return true;
}

static uint8_t batch_hex_digit(uint8_t value)
{
    static const uint8_t digits[] = "0123456789abcdef";
    return digits[value & 0x0fu];
}

static bool batch_path_is_in_epoch(
    const struct zcc_epoch_batch_bytes *path,
    const struct zcc_epoch_batch_bytes *epoch)
{
    static const uint8_t prefix[] = "epochs/";
    const size_t prefix_length = sizeof(prefix) - 1u;
    const size_t hex_length = ZCC_EPOCH_BATCH_ROOT_BYTES * 2u;
    if (path->length <= prefix_length + hex_length ||
        memcmp(path->data, prefix, prefix_length) != 0 ||
        path->data[prefix_length + hex_length] != '/')
        return false;
    for (size_t i = 0; i < ZCC_EPOCH_BATCH_ROOT_BYTES; ++i) {
        if (path->data[prefix_length + i * 2u] !=
                batch_hex_digit(epoch->data[i] >> 4) ||
            path->data[prefix_length + i * 2u + 1u] !=
                batch_hex_digit(epoch->data[i] & 0x0fu))
            return false;
    }
    return true;
}

static bool batch_depfile_matches_output(
    const struct zcc_epoch_batch_bytes *output,
    const struct zcc_epoch_batch_bytes *depfile)
{
    bool object_suffix = output->length >= 2u &&
                         output->data[output->length - 2u] == '.' &&
                         output->data[output->length - 1u] == 'o';
    return object_suffix && depfile->length == output->length &&
           memcmp(depfile->data, output->data, output->length - 1u) == 0 &&
           depfile->data[depfile->length - 1u] == 'd';
}

static bool batch_args_reserve(struct zcc_epoch_batch_manifest *manifest,
                               uint32_t needed, uint32_t *capacity)
{
    if (needed <= *capacity)
        return true;
    uint32_t next = *capacity ? *capacity : 64u;
    while (next < needed) {
        if (next > ZCC_EPOCH_BATCH_MAX_ARGS / 2u) {
            next = ZCC_EPOCH_BATCH_MAX_ARGS;
            break;
        }
        next *= 2u;
    }
    if (next < needed)
        return false;
    void *memory = zcl_realloc(manifest->job_argv,
                               (size_t)next * sizeof(*manifest->job_argv),
                               "zcc.epoch_batch.job_argv");
    if (!memory)
        return false;
    manifest->job_argv = memory;
    *capacity = next;
    return true;
}

static enum zcc_epoch_batch_result batch_read_bindings(
    struct batch_reader *reader, struct zcc_epoch_batch_manifest *manifest)
{
    struct zcc_epoch_batch_bytes magic = {0};
    uint32_t version = 0;
    if (!batch_read_field(reader, &magic) || !batch_read_u32(reader, &version))
        return batch_field_failure(reader, UINT32_MAX);
    const struct zcc_epoch_batch_bytes expected = {
        .data = batch_magic, .length = (uint32_t)(sizeof(batch_magic) - 1u)};
    if (!batch_field_equal(&magic, &expected))
        return batch_fail(reader, ZCC_EPOCH_BATCH_FORMAT, UINT32_MAX);
    if (version != ZCC_EPOCH_BATCH_VERSION)
        return batch_fail(reader, ZCC_EPOCH_BATCH_UNSUPPORTED_VERSION,
                          UINT32_MAX);
    if (!batch_read_field(reader, &manifest->profile) ||
        !batch_read_field(reader, &manifest->source_id) ||
        !batch_read_u32(reader, &manifest->source_complete) ||
        !batch_read_field(reader, &manifest->mutation) ||
        !batch_read_field(reader, &manifest->epoch) ||
        !batch_read_field(reader, &manifest->compiler_id) ||
        !batch_read_field(reader, &manifest->environment_root) ||
        !batch_read_field(reader, &manifest->build_root) ||
        !batch_read_field(reader, &manifest->session))
        return batch_field_failure(reader, UINT32_MAX);
    if (!batch_field_is_text(&manifest->profile) ||
        manifest->profile.length > ZCC_EPOCH_BATCH_MAX_PROFILE ||
        manifest->source_id.length != ZCC_EPOCH_BATCH_ROOT_BYTES ||
        manifest->source_complete != 1u ||
        manifest->mutation.length != ZCC_EPOCH_BATCH_ROOT_BYTES ||
        manifest->epoch.length != ZCC_EPOCH_BATCH_ROOT_BYTES ||
        manifest->compiler_id.length != ZCC_EPOCH_BATCH_ROOT_BYTES ||
        manifest->environment_root.length != ZCC_EPOCH_BATCH_ROOT_BYTES ||
        manifest->build_root.length != ZCC_EPOCH_BATCH_ROOT_BYTES ||
        !batch_path_is_relative(&manifest->session) ||
        !batch_path_is_in_epoch(&manifest->session, &manifest->epoch))
        return batch_fail(reader, ZCC_EPOCH_BATCH_AUTHORITY, UINT32_MAX);
    return ZCC_EPOCH_BATCH_OK;
}

static enum zcc_epoch_batch_result batch_read_common_args(
    struct batch_reader *reader, struct zcc_epoch_batch_manifest *manifest)
{
    if (!batch_read_u32(reader, &manifest->common_argc))
        return batch_fail(reader, ZCC_EPOCH_BATCH_TRUNCATED, UINT32_MAX);
    if (manifest->common_argc == 0)
        return batch_fail(reader, ZCC_EPOCH_BATCH_FORMAT, UINT32_MAX);
    if (manifest->common_argc > ZCC_EPOCH_BATCH_MAX_ARGS)
        return batch_fail(reader, ZCC_EPOCH_BATCH_LIMIT, UINT32_MAX);
    if (manifest->common_argc != 0) {
        manifest->common_argv = zcl_calloc(
            manifest->common_argc, sizeof(*manifest->common_argv),
            "zcc.epoch_batch.common_argv");
        if (!manifest->common_argv)
            return batch_fail(reader, ZCC_EPOCH_BATCH_ALLOCATION, UINT32_MAX);
    }
    for (uint32_t i = 0; i < manifest->common_argc; ++i) {
        if (!batch_read_field(reader, &manifest->common_argv[i]))
            return batch_field_failure(reader, UINT32_MAX);
        if (!batch_compiler_arg_safe(&manifest->common_argv[i], i == 0))
            return batch_fail(reader, ZCC_EPOCH_BATCH_ARGV, UINT32_MAX);
    }
    return ZCC_EPOCH_BATCH_OK;
}

static enum zcc_epoch_batch_result batch_read_job(
    struct batch_reader *reader, struct zcc_epoch_batch_manifest *manifest,
    uint32_t job_index, uint32_t *argv_capacity)
{
    struct zcc_epoch_batch_job *job = &manifest->jobs[job_index];
    uint32_t mode = 0;
    if (!batch_read_field(reader, &job->source) ||
        !batch_read_field(reader, &job->output) ||
        !batch_read_field(reader, &job->depfile) ||
        !batch_read_u32(reader, &mode) ||
        !batch_read_u32(reader, &job->argv_count))
        return batch_field_failure(reader, job_index);
    if (!batch_path_is_relative(&job->source) ||
        !batch_path_is_relative(&job->output) ||
        !batch_path_is_relative(&job->depfile) ||
        !batch_path_is_in_epoch(&job->output, &manifest->epoch) ||
        !batch_path_is_in_epoch(&job->depfile, &manifest->epoch) ||
        !batch_depfile_matches_output(&job->output, &job->depfile))
        return batch_fail(reader, ZCC_EPOCH_BATCH_PATH, job_index);
    if (mode != ZCC_EPOCH_BATCH_DEP && mode != ZCC_EPOCH_BATCH_COVERAGE)
        return batch_fail(reader, ZCC_EPOCH_BATCH_FORMAT, job_index);
    job->mode = (enum zcc_epoch_batch_mode)mode;
    uint32_t remaining = ZCC_EPOCH_BATCH_MAX_ARGS - manifest->common_argc -
                         manifest->job_argc;
    if (job->argv_count > remaining)
        return batch_fail(reader, ZCC_EPOCH_BATCH_LIMIT, job_index);
    job->argv_offset = manifest->job_argc;
    uint32_t needed = manifest->job_argc + job->argv_count;
    if (!batch_args_reserve(manifest, needed, argv_capacity))
        return batch_fail(reader, ZCC_EPOCH_BATCH_ALLOCATION, job_index);
    for (uint32_t i = 0; i < job->argv_count; ++i) {
        if (!batch_read_field(reader, &manifest->job_argv[manifest->job_argc]))
            return batch_field_failure(reader, job_index);
        if (!batch_compiler_arg_safe(
                &manifest->job_argv[manifest->job_argc], false))
            return batch_fail(reader, ZCC_EPOCH_BATCH_ARGV, job_index);
        manifest->job_argc++;
    }
    return ZCC_EPOCH_BATCH_OK;
}

static int batch_destination_compare(const void *left, const void *right)
{
    const struct zcc_epoch_batch_bytes *const *a = left;
    const struct zcc_epoch_batch_bytes *const *b = right;
    size_t shared = (*a)->length < (*b)->length ? (*a)->length : (*b)->length;
    for (size_t i = 0; i < shared; ++i) {
        uint8_t ac = (*a)->data[i], bc = (*b)->data[i];
        if (ac >= 'A' && ac <= 'Z') ac = (uint8_t)(ac + ('a' - 'A'));
        if (bc >= 'A' && bc <= 'Z') bc = (uint8_t)(bc + ('a' - 'A'));
        if (ac != bc)
            return (ac > bc) - (ac < bc);
    }
    return ((*a)->length > (*b)->length) - ((*a)->length < (*b)->length);
}

static enum zcc_epoch_batch_result batch_destinations_unique(
    struct batch_reader *reader, const struct zcc_epoch_batch_manifest *manifest)
{
    size_t count = (size_t)manifest->job_count * 2u;
    if (count == 0)
        return batch_fail(reader, ZCC_EPOCH_BATCH_JOB_COUNT, UINT32_MAX);
    if (count > SIZE_MAX / sizeof(const struct zcc_epoch_batch_bytes *))
        return batch_fail(reader, ZCC_EPOCH_BATCH_LIMIT, UINT32_MAX);
    const struct zcc_epoch_batch_bytes **paths =
        zcl_calloc(count, sizeof(*paths), "zcc.epoch_batch.destinations");
    if (!paths)
        return batch_fail(reader, ZCC_EPOCH_BATCH_ALLOCATION, UINT32_MAX);
    for (uint32_t i = 0; i < manifest->job_count; ++i) {
        paths[(size_t)i * 2u] = &manifest->jobs[i].output;
        paths[(size_t)i * 2u + 1u] = &manifest->jobs[i].depfile;
    }
    qsort(paths, count, sizeof(*paths), batch_destination_compare);
    bool unique = true;
    for (size_t i = 1; i < count; ++i) {
        if (batch_destination_compare(&paths[i - 1u], &paths[i]) == 0) {
            unique = false;
            break;
        }
    }
    free(paths);
    return unique ? ZCC_EPOCH_BATCH_OK :
        batch_fail(reader, ZCC_EPOCH_BATCH_DESTINATION_COLLISION, UINT32_MAX);
}

static bool batch_manifest_empty(
    const struct zcc_epoch_batch_manifest *manifest)
{
    const struct zcc_epoch_batch_bytes *const fields[] = {
        &manifest->profile, &manifest->source_id, &manifest->mutation,
        &manifest->epoch, &manifest->compiler_id, &manifest->environment_root,
        &manifest->build_root, &manifest->session
    };
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
        if (fields[i]->data || fields[i]->length != 0)
            return false;
    }
    return manifest->source_complete == 0 && !manifest->common_argv &&
           manifest->common_argc == 0 && !manifest->jobs &&
           manifest->job_count == 0 && !manifest->job_argv &&
           manifest->job_argc == 0;
}

static enum zcc_epoch_batch_result batch_manifest_fail(
    struct zcc_epoch_batch_error *error, enum zcc_epoch_batch_result code,
    uint32_t job_index)
{
    if (error) {
        error->code = code;
        error->offset = 0;
        error->job_index = job_index;
    }
    return code;
}

static bool batch_root_valid(const struct zcc_epoch_batch_bytes *root)
{
    return root->data && root->length == ZCC_EPOCH_BATCH_ROOT_BYTES;
}

static enum zcc_epoch_batch_result batch_manifest_validate(
    const struct zcc_epoch_batch_manifest *manifest,
    struct zcc_epoch_batch_error *error)
{
    if (!batch_field_is_text(&manifest->profile) ||
        manifest->profile.length > ZCC_EPOCH_BATCH_MAX_PROFILE ||
        !batch_root_valid(&manifest->source_id) ||
        manifest->source_complete != 1u ||
        !batch_root_valid(&manifest->mutation) ||
        !batch_root_valid(&manifest->epoch) ||
        !batch_root_valid(&manifest->compiler_id) ||
        !batch_root_valid(&manifest->environment_root) ||
        !batch_root_valid(&manifest->build_root) ||
        !batch_path_is_relative(&manifest->session) ||
        !batch_path_is_in_epoch(&manifest->session, &manifest->epoch))
        return batch_manifest_fail(error, ZCC_EPOCH_BATCH_AUTHORITY,
                                   UINT32_MAX);
    if (manifest->common_argc == 0 || !manifest->common_argv)
        return batch_manifest_fail(error, ZCC_EPOCH_BATCH_FORMAT,
                                   UINT32_MAX);
    if (manifest->common_argc > ZCC_EPOCH_BATCH_MAX_ARGS)
        return batch_manifest_fail(error, ZCC_EPOCH_BATCH_LIMIT,
                                   UINT32_MAX);
    for (uint32_t i = 0; i < manifest->common_argc; ++i) {
        if (manifest->common_argv[i].length > ZCC_EPOCH_BATCH_MAX_FIELD)
            return batch_manifest_fail(error, ZCC_EPOCH_BATCH_LIMIT,
                                       UINT32_MAX);
        if (!batch_compiler_arg_safe(&manifest->common_argv[i], i == 0))
            return batch_manifest_fail(error, ZCC_EPOCH_BATCH_ARGV,
                                       UINT32_MAX);
    }
    if (manifest->job_count == 0 ||
        manifest->job_count > ZCC_EPOCH_BATCH_MAX_JOBS || !manifest->jobs)
        return batch_manifest_fail(error, ZCC_EPOCH_BATCH_JOB_COUNT,
                                   UINT32_MAX);
    if (manifest->job_argc > ZCC_EPOCH_BATCH_MAX_ARGS - manifest->common_argc)
        return batch_manifest_fail(error, ZCC_EPOCH_BATCH_LIMIT,
                                   UINT32_MAX);
    if ((manifest->job_argc != 0) != (manifest->job_argv != NULL))
        return batch_manifest_fail(error, ZCC_EPOCH_BATCH_ARGUMENT,
                                   UINT32_MAX);

    uint32_t expected_offset = 0;
    for (uint32_t i = 0; i < manifest->job_count; ++i) {
        const struct zcc_epoch_batch_job *job = &manifest->jobs[i];
        if (!batch_path_is_relative(&job->source) ||
            !batch_path_is_relative(&job->output) ||
            !batch_path_is_relative(&job->depfile) ||
            !batch_path_is_in_epoch(&job->output, &manifest->epoch) ||
            !batch_path_is_in_epoch(&job->depfile, &manifest->epoch) ||
            !batch_depfile_matches_output(&job->output, &job->depfile))
            return batch_manifest_fail(error, ZCC_EPOCH_BATCH_PATH, i);
        if (job->mode != ZCC_EPOCH_BATCH_DEP &&
            job->mode != ZCC_EPOCH_BATCH_COVERAGE)
            return batch_manifest_fail(error, ZCC_EPOCH_BATCH_FORMAT, i);
        if (job->argv_offset != expected_offset ||
            job->argv_count > manifest->job_argc - expected_offset)
            return batch_manifest_fail(error, ZCC_EPOCH_BATCH_ARGUMENT, i);
        for (uint32_t j = 0; j < job->argv_count; ++j) {
            const struct zcc_epoch_batch_bytes *arg =
                &manifest->job_argv[expected_offset + j];
            if (arg->length > ZCC_EPOCH_BATCH_MAX_FIELD)
                return batch_manifest_fail(error, ZCC_EPOCH_BATCH_LIMIT, i);
            if (!batch_compiler_arg_safe(arg, false))
                return batch_manifest_fail(error, ZCC_EPOCH_BATCH_ARGV, i);
        }
        expected_offset += job->argv_count;
    }
    if (expected_offset != manifest->job_argc)
        return batch_manifest_fail(error, ZCC_EPOCH_BATCH_ARGUMENT,
                                   UINT32_MAX);

    struct batch_reader report = {.error = error};
    return batch_destinations_unique(&report, manifest);
}

static bool batch_size_add(size_t *total, size_t amount)
{
    if (amount > (size_t)ZCC_EPOCH_BATCH_MAX_WIRE - *total)
        return false;
    *total += amount;
    return true;
}

static bool batch_size_field(size_t *total,
                             const struct zcc_epoch_batch_bytes *field)
{
    return field->length <= ZCC_EPOCH_BATCH_MAX_FIELD &&
           batch_size_add(total, 4u + (size_t)field->length);
}

static bool batch_manifest_size(
    const struct zcc_epoch_batch_manifest *manifest, size_t *size)
{
    const struct zcc_epoch_batch_bytes magic = {
        .data = batch_magic, .length = (uint32_t)(sizeof(batch_magic) - 1u)};
    size_t total = 0;
    if (!batch_size_field(&total, &magic) || !batch_size_add(&total, 4u) ||
        !batch_size_field(&total, &manifest->profile) ||
        !batch_size_field(&total, &manifest->source_id) ||
        !batch_size_add(&total, 4u) ||
        !batch_size_field(&total, &manifest->mutation) ||
        !batch_size_field(&total, &manifest->epoch) ||
        !batch_size_field(&total, &manifest->compiler_id) ||
        !batch_size_field(&total, &manifest->environment_root) ||
        !batch_size_field(&total, &manifest->build_root) ||
        !batch_size_field(&total, &manifest->session) ||
        !batch_size_add(&total, 4u))
        return false;
    for (uint32_t i = 0; i < manifest->common_argc; ++i)
        if (!batch_size_field(&total, &manifest->common_argv[i]))
            return false;
    if (!batch_size_add(&total, 4u))
        return false;
    for (uint32_t i = 0; i < manifest->job_count; ++i) {
        const struct zcc_epoch_batch_job *job = &manifest->jobs[i];
        if (!batch_size_field(&total, &job->source) ||
            !batch_size_field(&total, &job->output) ||
            !batch_size_field(&total, &job->depfile) ||
            !batch_size_add(&total, 8u))
            return false;
        for (uint32_t j = 0; j < job->argv_count; ++j)
            if (!batch_size_field(
                    &total, &manifest->job_argv[job->argv_offset + j]))
                return false;
    }
    *size = total;
    return true;
}

static bool batch_write_u32(struct batch_writer *writer, uint32_t value)
{
    if (writer->size - writer->offset < 4u)
        return false;
    zcl_write_u32_le(writer->wire + writer->offset, value);
    writer->offset += 4u;
    return true;
}

static bool batch_write_field(struct batch_writer *writer,
                              const struct zcc_epoch_batch_bytes *field)
{
    if (!batch_write_u32(writer, field->length) ||
        (size_t)field->length > writer->size - writer->offset)
        return false;
    memcpy(writer->wire + writer->offset, field->data, field->length);
    writer->offset += field->length;
    return true;
}

enum zcc_epoch_batch_result zcc_epoch_batch_manifest_decode(
    const uint8_t *wire, size_t wire_size,
    struct zcc_epoch_batch_manifest *out,
    struct zcc_epoch_batch_error *error)
{
    if (error)
        *error = (struct zcc_epoch_batch_error){.job_index = UINT32_MAX};
    if (!out) {
        if (error)
            error->code = ZCC_EPOCH_BATCH_ARGUMENT;
        return ZCC_EPOCH_BATCH_ARGUMENT;
    }
    if (!batch_manifest_empty(out)) {
        if (error)
            error->code = ZCC_EPOCH_BATCH_ARGUMENT;
        return ZCC_EPOCH_BATCH_ARGUMENT;
    }
    *out = (struct zcc_epoch_batch_manifest){0};
    if (!wire) {
        if (error)
            error->code = ZCC_EPOCH_BATCH_ARGUMENT;
        return ZCC_EPOCH_BATCH_ARGUMENT;
    }
    if (wire_size > ZCC_EPOCH_BATCH_MAX_WIRE) {
        if (error)
            error->code = ZCC_EPOCH_BATCH_LIMIT;
        return ZCC_EPOCH_BATCH_LIMIT;
    }
    struct batch_reader reader = {
        .wire = wire, .size = wire_size, .error = error};
    enum zcc_epoch_batch_result result = batch_read_bindings(&reader, out);
    if (result == ZCC_EPOCH_BATCH_OK)
        result = batch_read_common_args(&reader, out);
    if (result == ZCC_EPOCH_BATCH_OK && !batch_read_u32(&reader, &out->job_count))
        result = batch_fail(&reader, ZCC_EPOCH_BATCH_TRUNCATED, UINT32_MAX);
    if (result == ZCC_EPOCH_BATCH_OK &&
        (out->job_count == 0 || out->job_count > ZCC_EPOCH_BATCH_MAX_JOBS))
        result = batch_fail(&reader, ZCC_EPOCH_BATCH_JOB_COUNT, UINT32_MAX);
    if (result == ZCC_EPOCH_BATCH_OK) {
        out->jobs = zcl_calloc(out->job_count, sizeof(*out->jobs),
                               "zcc.epoch_batch.jobs");
        if (!out->jobs)
            result = batch_fail(&reader, ZCC_EPOCH_BATCH_ALLOCATION, UINT32_MAX);
    }
    uint32_t argv_capacity = 0;
    for (uint32_t i = 0; result == ZCC_EPOCH_BATCH_OK && i < out->job_count; ++i)
        result = batch_read_job(&reader, out, i, &argv_capacity);
    if (result == ZCC_EPOCH_BATCH_OK && reader.offset != reader.size)
        result = batch_fail(&reader, ZCC_EPOCH_BATCH_TRAILING_BYTES, UINT32_MAX);
    if (result == ZCC_EPOCH_BATCH_OK)
        result = batch_destinations_unique(&reader, out);
    if (result != ZCC_EPOCH_BATCH_OK)
        zcc_epoch_batch_manifest_free(out);
    else if (error)
        error->code = ZCC_EPOCH_BATCH_OK;
    return result;
}

enum zcc_epoch_batch_result zcc_epoch_batch_manifest_encode(
    const struct zcc_epoch_batch_manifest *manifest,
    struct zcc_epoch_batch_wire *out,
    struct zcc_epoch_batch_error *error)
{
    if (error)
        *error = (struct zcc_epoch_batch_error){.job_index = UINT32_MAX};
    if (!manifest || !out || out->data || out->length != 0)
        return batch_manifest_fail(error, ZCC_EPOCH_BATCH_ARGUMENT,
                                   UINT32_MAX);
    enum zcc_epoch_batch_result result =
        batch_manifest_validate(manifest, error);
    if (result != ZCC_EPOCH_BATCH_OK)
        return result;

    size_t size = 0;
    if (!batch_manifest_size(manifest, &size))
        return batch_manifest_fail(error, ZCC_EPOCH_BATCH_LIMIT, UINT32_MAX);
    uint8_t *wire = zcl_malloc(size, "zcc.epoch_batch.wire");
    if (!wire)
        return batch_manifest_fail(error, ZCC_EPOCH_BATCH_ALLOCATION,
                                   UINT32_MAX);
    struct batch_writer writer = {.wire = wire, .size = size};
    const struct zcc_epoch_batch_bytes magic = {
        .data = batch_magic, .length = (uint32_t)(sizeof(batch_magic) - 1u)};
    bool complete = batch_write_field(&writer, &magic) &&
                    batch_write_u32(&writer, ZCC_EPOCH_BATCH_VERSION) &&
                    batch_write_field(&writer, &manifest->profile) &&
                    batch_write_field(&writer, &manifest->source_id) &&
                    batch_write_u32(&writer, manifest->source_complete) &&
                    batch_write_field(&writer, &manifest->mutation) &&
                    batch_write_field(&writer, &manifest->epoch) &&
                    batch_write_field(&writer, &manifest->compiler_id) &&
                    batch_write_field(&writer, &manifest->environment_root) &&
                    batch_write_field(&writer, &manifest->build_root) &&
                    batch_write_field(&writer, &manifest->session) &&
                    batch_write_u32(&writer, manifest->common_argc);
    for (uint32_t i = 0; complete && i < manifest->common_argc; ++i)
        complete = batch_write_field(&writer, &manifest->common_argv[i]);
    complete = complete && batch_write_u32(&writer, manifest->job_count);
    for (uint32_t i = 0; complete && i < manifest->job_count; ++i) {
        const struct zcc_epoch_batch_job *job = &manifest->jobs[i];
        complete = batch_write_field(&writer, &job->source) &&
                   batch_write_field(&writer, &job->output) &&
                   batch_write_field(&writer, &job->depfile) &&
                   batch_write_u32(&writer, (uint32_t)job->mode) &&
                   batch_write_u32(&writer, job->argv_count);
        for (uint32_t j = 0; complete && j < job->argv_count; ++j)
            complete = batch_write_field(
                &writer, &manifest->job_argv[job->argv_offset + j]);
    }
    if (!complete || writer.offset != writer.size) {
        free(wire);
        return batch_manifest_fail(error, ZCC_EPOCH_BATCH_FORMAT,
                                   UINT32_MAX);
    }
    *out = (struct zcc_epoch_batch_wire){.data = wire, .length = size};
    if (error)
        error->code = ZCC_EPOCH_BATCH_OK;
    return ZCC_EPOCH_BATCH_OK;
}

void zcc_epoch_batch_manifest_free(struct zcc_epoch_batch_manifest *manifest)
{
    if (!manifest)
        return;
    free(manifest->common_argv);
    free(manifest->jobs);
    free(manifest->job_argv);
    *manifest = (struct zcc_epoch_batch_manifest){0};
}

void zcc_epoch_batch_wire_free(struct zcc_epoch_batch_wire *wire)
{
    if (!wire)
        return;
    free(wire->data);
    *wire = (struct zcc_epoch_batch_wire){0};
}

const char *zcc_epoch_batch_result_name(enum zcc_epoch_batch_result result)
{
    switch (result) {
    case ZCC_EPOCH_BATCH_OK: return "ok";
    case ZCC_EPOCH_BATCH_ARGUMENT: return "argument";
    case ZCC_EPOCH_BATCH_TRUNCATED: return "truncated";
    case ZCC_EPOCH_BATCH_FORMAT: return "format";
    case ZCC_EPOCH_BATCH_UNSUPPORTED_VERSION: return "version";
    case ZCC_EPOCH_BATCH_LIMIT: return "limit";
    case ZCC_EPOCH_BATCH_ALLOCATION: return "allocation";
    case ZCC_EPOCH_BATCH_JOB_COUNT: return "job_count";
    case ZCC_EPOCH_BATCH_AUTHORITY: return "authority";
    case ZCC_EPOCH_BATCH_ARGV: return "argv";
    case ZCC_EPOCH_BATCH_PATH: return "path";
    case ZCC_EPOCH_BATCH_DESTINATION_COLLISION:
        return "destination_collision";
    case ZCC_EPOCH_BATCH_TRAILING_BYTES: return "trailing_bytes";
    }
    return "unknown";
}
