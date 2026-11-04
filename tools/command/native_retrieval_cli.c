/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Bounded transport for the maintained native retrieval handlers. */
#include "command/native_retrieval_cli.h"
#include "command/native_json_input.h"
#include "kernel/command_registry.h"
#include "json/json.h"
#include "util/safe_alloc.h"
#include "zutf8/zutf8.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void zcl_native_handle_dev_retrieval_benchmark(
    const struct zcl_command_request *, struct zcl_command_reply *);
void zcl_native_handle_dev_retrieval_pair(
    const struct zcl_command_request *, struct zcl_command_reply *);

/* Expand the same declarations as the development catalog. Only these two
 * read-only handlers are linked; no fixture or global catalog fallback. */
#define ZCL_COMMAND_DEV_READ(path_, parent_, aliases_, summary_, semantics_, \
    budget_, tags_, in_, out_, keys_, pos_, example_, scope_, auth_, latency_, \
    cost_, lanes_, caps_, traits_, handler_, reason_, compat_) \
    { .path = path_, .parent = parent_, .aliases = aliases_, \
      .summary = summary_, .semantics = semantics_, .tags = tags_, \
      .input_schema = in_, .output_schema = out_, .input_keys = keys_, \
      .positional_keys = pos_, .example = example_, \
      .availability_reason = "", .compat_target = "", .budget_bytes = budget_, \
      .layer = ZCL_COMMAND_LAYER_DEV, .effect = ZCL_COMMAND_EFFECT_READ, \
      .risk = ZCL_COMMAND_RISK_READ, .scope = scope_, .authority = auth_, \
      .availability = ZCL_COMMAND_READY, .mode = ZCL_COMMAND_MODE_SYNC, \
      .latency = latency_, .cost = cost_, .confirmation = ZCL_COMMAND_CONFIRM_NONE, \
      .allowed_lanes = lanes_, .required_capabilities = caps_, .traits = traits_, \
      .transports = ZCL_COMMAND_TRANSPORT_NATIVE, .handler = handler_ },
#define ZCL_COMMAND_READY_READ(path_, parent_, aliases_, summary_, semantics_, \
    budget_, tags_, in_, out_, keys_, pos_, example_, layer_, scope_, auth_, \
    latency_, cost_, lanes_, caps_, traits_, transports_, handler_) \
    { .path = path_, .parent = parent_, .aliases = aliases_, \
      .summary = summary_, .semantics = semantics_, .tags = tags_, \
      .input_schema = in_, .output_schema = out_, .input_keys = keys_, \
      .positional_keys = pos_, .example = example_, .budget_bytes = budget_, \
      .availability_reason = "discovery is supplied by the full native CLI", \
      .compat_target = "z23 discover describe", .availability = ZCL_COMMAND_COMPAT, \
      .layer = layer_, .effect = ZCL_COMMAND_EFFECT_READ, .risk = ZCL_COMMAND_RISK_READ, \
      .scope = scope_, .authority = auth_, .mode = ZCL_COMMAND_MODE_SYNC, \
      .latency = latency_, .cost = cost_, .confirmation = ZCL_COMMAND_CONFIRM_NONE, \
      .allowed_lanes = lanes_, .required_capabilities = caps_, .traits = traits_, \
      .transports = transports_, .handler = NULL },
static const struct zcl_command_spec retrieval_commands[] = {
#include "../../engine/composition/commands/retrieval_pair.def"
/* Native failures refer to this external discovery contract. Metadata only:
 * it validates next actions without linking the full catalog or its handler. */
#include "../../engine/composition/commands/discover_describe.def"
};
#undef ZCL_COMMAND_DEV_READ
#undef ZCL_COMMAND_READY_READ
static const struct zcl_command_registry retrieval_registry = {
    retrieval_commands, sizeof(retrieval_commands) / sizeof(retrieval_commands[0])
};

static const struct zcl_command_spec *retrieval_leaf(const char *verb)
{
    const char *path = strcmp(verb, "benchmark") == 0 ? "dev.retrieval.benchmark" :
        strcmp(verb, "pair") == 0 ? "dev.retrieval.pair" : NULL;
    return path ? zcl_command_registry_find(&retrieval_registry, path, NULL) : NULL;
}

static bool retrieval_write(const char *out, size_t length)
{
    return length > 0 && fwrite(out, 1, length, stdout) == length &&
        fputc('\n', stdout) != EOF && fflush(stdout) == 0;
}

static int retrieval_error(const char *command, const char *code,
                            const char *message)
{
    char out[ZCL_COMMAND_ERROR_BUDGET + 1u];
    size_t length = zcl_native_error_json(command, code, "normalize", message,
                                         "", "", NULL, out, sizeof(out));
    return retrieval_write(out, length) ? ZCL_COMMAND_EXIT_INVALID : ZCL_COMMAND_EXIT_INTERNAL;
}

static bool retrieval_input(const struct zcl_command_spec *spec,
                            const char *argument, struct json_value *input)
{
    size_t length = 0;
    bool oversize = false;
    size_t budget = zcl_command_registry_input_budget_bytes(spec);
    char *owned = NULL;
    const char *raw = argument;
    if (strcmp(argument, "-") == 0) {
        owned = zcl_native_read_stdin(budget, &oversize, &length);
        raw = owned;
    } else {
        length = strlen(raw);
    }
    bool ok = raw && !oversize && length <= budget &&
        !memchr(raw, 0, length) && zutf8_validate_n(raw, length) &&
        json_read(input, raw, length) && input->type == JSON_OBJ;
    free(owned);
    return ok;
}

int zcl_retrieval_cli_main(int argc, char **argv)
{
    if (argc != 3 || strncmp(argv[2], "--input=", 8) != 0) {
        return retrieval_error("dev.retrieval", "INVALID_ARGUMENTS",
            "usage: rank-pair benchmark|pair --input=<JSON|->");
    }
    const struct zcl_command_spec *spec = retrieval_leaf(argv[1]);
    if (!spec) {
        return retrieval_error("dev.retrieval", "UNKNOWN_COMMAND", "expected benchmark or pair");
    }
    struct json_value input = {0};
    if (!retrieval_input(spec, argv[2] + 8, &input)) {
        json_free(&input);
        return retrieval_error(spec->path, "BAD_INPUT", "expected one bounded UTF-8 JSON object");
    }
    size_t capacity = (size_t)spec->budget_bytes + 1u;
    char *out = zcl_malloc(capacity, "retrieval_cli.response");
    if (!out) {
        json_free(&input);
        fputs("rank-pair: ALLOCATION_FAILED: response allocation failed\n", stderr);
        return ZCL_COMMAND_EXIT_INTERNAL;
    }
    const struct zcl_command_context context = {
        .registry = &retrieval_registry,
        .source_root = getenv("ZCL_DEV_SOURCE_ROOT"),
        .operator_lane = "dev", .authority_ceiling = ZCL_COMMAND_AUTH_OPERATOR,
        .granted_capabilities = ZCL_COMMAND_CAP_CHECKOUT_READ, .dev_build = true,
    };
    enum zcl_command_exit status = ZCL_COMMAND_EXIT_INTERNAL;
    size_t length = zcl_command_registry_execute_json(&retrieval_registry, spec,
        &context, &input, false, spec->path, "", (size_t)spec->budget_bytes,
        0, "", out, capacity, &status);
    json_free(&input);
    bool written = length < capacity && retrieval_write(out, length);
    free(out);
    if (!written) {
        fputs("rank-pair: OUTPUT_FAILED: complete response could not be written\n", stderr);
        return ZCL_COMMAND_EXIT_INTERNAL;
    }
    return (int)status;
}
