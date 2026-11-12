/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Owner-gated, typed plan -> commit adapter for the isolated dev generation
 * activation engine.  The release binary never contains this implementation.
 */

#define _GNU_SOURCE
#include "command/native_command.h"

#ifdef ZCL_DEV_BUILD

#include "base/hex.h"
#include "crypto/sha3.h"
#include "dev_activation.h"
#include "devloop.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "platform/directory_transaction.h"
#include "platform/os_proc.h"
#include "platform/positioned_file.h"
#include "platform/time_compat.h"
#include "util/authority_receipt.h"
#include "util/log_macros.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if !defined(_WIN32)
#include <fcntl.h>
#include <unistd.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define DAC_TAG "native.dev.activation"
#define DAC_SCHEMA "zcl.dev_generation_activate.v1"
#define DAC_AUTHORITY_SCHEMA "zcl.dev_generation_activate.authority.v1"

static void dac_fail(struct zcl_command_reply *reply,
                     enum zcl_command_status status,
                     enum zcl_command_exit exit_code, const char *code,
                     const char *phase, const char *message,
                     const char *evidence)
{
    LOG_ERROR(DAC_TAG, "%s: %s (%s)", code, message,
              evidence && evidence[0] ? evidence : "-");
    zcl_command_reply_fail(reply, status, exit_code, code, phase, false, false,
                           message, evidence ? evidence : "");
}

static bool dac_hex64(const char *s)
{
    return s && strlen(s) == 64 &&
           strspn(s, "0123456789abcdef") == 64;
}

static bool dac_generation(const char *s)
{
    return s && strncmp(s, "gen-", 4) == 0 && dac_hex64(s + 4);
}

static bool dac_key(const char *s)
{
    if (!s || !s[0] || strlen(s) > 64)
        return false;
    return strspn(s,
                  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                  "0123456789._:-") == strlen(s);
}

#if defined(_WIN32)
static bool dac_child_stable(const struct platform_directory_child_info *a,
                             const struct platform_directory_child_info *b)
{
    return a->size == b->size && a->volume == b->volume &&
           a->file_low == b->file_low && a->file_high == b->file_high &&
           a->link_count == b->link_count &&
           a->modified_seconds == b->modified_seconds &&
           a->modified_nanoseconds == b->modified_nanoseconds &&
           a->changed_seconds == b->changed_seconds &&
           a->changed_nanoseconds == b->changed_nanoseconds &&
           a->current_user_only == b->current_user_only;
}
#endif

static bool dac_unhex32(const char hex[65], uint8_t out[32])
{
    return zcl_hex_decode_lower(hex, out, 32);
}

static void dac_hash_parts(const char *domain, const char *const *parts,
                           size_t count, char out[65])
{
    struct sha3_256_ctx sha;
    uint8_t digest[32];
    static const uint8_t zero = 0;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, strlen(domain));
    sha3_256_write(&sha, &zero, 1);
    for (size_t i = 0; i < count; i++) {
        sha3_256_write(&sha, (const uint8_t *)parts[i], strlen(parts[i]));
        sha3_256_write(&sha, &zero, 1);
    }
    sha3_256_finalize(&sha, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
}

static bool dac_authority_fields(const char *candidate,
                                 const char *expected_current,
                                 const char *effect,
                                 uint8_t artifact[32], uint8_t anchor[32],
                                 uint8_t detail[32])
{
    char anchor_hex[65];
    const char *parts[] = { expected_current };
    dac_hash_parts("zcl.dev_generation_activate.resident.v1", parts, 1,
                   anchor_hex);
    return dac_unhex32(candidate, artifact) &&
           dac_unhex32(anchor_hex, anchor) && dac_unhex32(effect, detail);
}

static bool dac_authority_name(const char *intent, char out[96])
{
    if (!dac_hex64(intent))
        return false;
    int n = snprintf(out, 96, "activation-authority-%s.bin", intent);
    return n > 0 && n < 96;
}

#if defined(_WIN32)
static bool dac_read_selection_stable(
    struct platform_directory_child *selection,
    struct platform_directory_child_info *before,
    struct platform_directory_child_info *after, char blob[256],
    size_t blob_capacity)
{
    return platform_directory_child_info(selection, before) &&
           before->current_user_only && before->size > 0 &&
           before->size < blob_capacity &&
           platform_directory_child_read_exact(selection, blob,
                                               (size_t)before->size, 0) &&
           platform_directory_child_info(selection, after) &&
           dac_child_stable(before, after);
}

static bool dac_parse_selection_generation(char out[80], const char *blob,
                                           size_t blob_size)
{
    struct json_value doc;
    json_init(&doc);
    bool ok = json_read(&doc, blob, blob_size) &&
              doc.type == JSON_OBJ;
    const char *schema = ok ? json_get_str(json_get(&doc, "schema")) : NULL;
    const char *selected = ok ? json_get_str(json_get(&doc, "generation")) : NULL;
    ok = schema && selected &&
         strcmp(schema, "zcl.dev_generation_selection.v1") == 0 &&
         dac_generation(selected) &&
         snprintf(out, 80, "%s", selected) > 0;
    json_free(&doc);
    return ok;
}

static bool dac_read_current_win32(const char *gen_root, char out[80])
{
    struct platform_directory_transaction root, generation;
    struct platform_directory_child selection, binary;
    platform_directory_transaction_init(&root);
    platform_directory_transaction_init(&generation);
    platform_directory_child_init(&selection);
    platform_directory_child_init(&binary);
    struct platform_directory_child_info before = {0}, after = {0};
    char blob[256];
    bool ok = platform_directory_transaction_open(&root, gen_root);
    enum platform_directory_result selected = ok
        ? platform_directory_child_open_result(&root, "current", false, true,
                                               &selection, NULL)
        : PLATFORM_DIRECTORY_IO;
    if (selected == PLATFORM_DIRECTORY_MISSING) {
        out[0] = 0;
        platform_directory_transaction_close(&root);
        return true;
    }
    ok = ok && selected == PLATFORM_DIRECTORY_OK &&
         dac_read_selection_stable(&selection, &before, &after, blob,
                                   sizeof(blob));
    if (ok) {
        blob[before.size] = 0;
        ok = dac_parse_selection_generation(out, blob, (size_t)before.size);
    }
    if (ok)
        ok = platform_directory_transaction_open_child(
                 &root, out, false, &generation) == PLATFORM_DIRECTORY_OK &&
             platform_directory_child_open(&generation,
                                           "zclassic23-dev.exe", &binary) &&
             platform_directory_child_info(&binary, &before) &&
             before.current_user_only && before.size > 0;
    platform_directory_child_close(&binary);
    platform_directory_transaction_close(&generation);
    platform_directory_child_close(&selection);
    platform_directory_transaction_close(&root);
    return ok;
}
#endif

static bool dac_read_current(const char *gen_root, char out[80])
{
#if defined(_WIN32)
    return dac_read_current_win32(gen_root, out);
#else
    char link[PATH_MAX];
    int n = snprintf(link, sizeof(link), "%s/current", gen_root);
    if (n <= 0 || (size_t)n >= sizeof(link))
        return false;
    ssize_t got = readlink(link, out, 79);
    if (got < 0) {
        out[0] = 0;
        return true;
    }
    if (got == 0 || got >= 79)
        return false;
    out[got] = 0;
    return dac_generation(out);
#endif
}

/* Read any generation locator symlink (<gen_root>/<name>) into out. An absent
 * link reads as the empty generation with true, mirroring dac_read_current. */
static bool dac_read_generation_link(const char *gen_root, const char *name,
                                     char out[80])
{
#if defined(_WIN32)
    /* The win32 lane stores locators as selection files only for `current`;
     * until that store grows named locators, rollback fails closed rather
     * than guessing a target. */
    (void)gen_root;
    (void)name;
    out[0] = 0;
    return false;
#else
    out[0] = 0;
    char link[PATH_MAX];
    int n = snprintf(link, sizeof(link), "%s/%s", gen_root, name);
    if (n <= 0 || (size_t)n >= sizeof(link))
        return false;
    ssize_t got = readlink(link, out, 79);
    if (got < 0)
        return true;
    if (got == 0 || got >= 79) {
        out[0] = 0;
        return false;
    }
    out[got] = 0;
    if (!dac_generation(out)) {
        out[0] = 0;
        return false;
    }
    return true;
#endif
}

static bool dac_resolve_root(const struct zcl_command_request *request,
                             char out[PATH_MAX])
{
    return platform_directory_canonical_real(zcl_native_source_root(request), out,
                                             PATH_MAX);
}

#if defined(_WIN32)
static bool dac_receipt_header_matches(
    const uint8_t blob[AUTHORITY_RECEIPT_HEADER_BYTES],
    const uint8_t artifact[32], const uint8_t anchor[32],
    const uint8_t detail[32])
{
    struct authority_receipt_header header;
    bool ok = authority_receipt_header_deserialize(blob, &header);
    uint8_t running[32];
    ok = ok && authority_receipt_running_binary_digest(running) &&
         strcmp(header.schema, DAC_AUTHORITY_SCHEMA) == 0 &&
         memcmp(header.verifier_binary_digest, running, 32) == 0 &&
         memcmp(header.artifact_digest, artifact, 32) == 0 &&
         memcmp(header.context_anchor, anchor, 32) == 0 &&
         memcmp(header.detail_digest, detail, 32) == 0;
    return ok;
}
#endif

static bool dac_authority_available(
    const char *datadir, const char *name, const uint8_t artifact[32],
    const uint8_t anchor[32], const uint8_t detail[32])
{
#if defined(_WIN32)
    struct platform_directory_transaction directory;
    struct platform_directory_child receipt;
    struct platform_directory_child_info before = {0}, after = {0};
    platform_directory_transaction_init(&directory);
    platform_directory_child_init(&receipt);
    uint8_t blob[AUTHORITY_RECEIPT_HEADER_BYTES];
    bool ok = platform_directory_transaction_open(&directory, datadir) &&
              platform_directory_child_open(&directory, name, &receipt) &&
              platform_directory_child_info(&receipt, &before) &&
              before.current_user_only &&
              before.size == AUTHORITY_RECEIPT_HEADER_BYTES &&
              platform_directory_child_read_exact(&receipt, blob,
                                                   sizeof(blob), 0) &&
              platform_directory_child_info(&receipt, &after) &&
              dac_child_stable(&before, &after);
    ok = ok && dac_receipt_header_matches(blob, artifact, anchor, detail);
    platform_directory_child_close(&receipt);
    platform_directory_transaction_close(&directory);
    return ok;
#else
    int datadir_fd = open(datadir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    bool ok = datadir_fd >= 0 &&
              authority_receipt_header_authority_available(
                  datadir_fd, name, DAC_AUTHORITY_SCHEMA, artifact, anchor,
                  detail);
    if (datadir_fd >= 0)
        (void)close(datadir_fd);
    return ok;
#endif
}

static bool dac_capture_source(const char *root,
                               struct dev_source_record *record,
                               char why[192])
{
    memset(record, 0, sizeof(*record));
    if (!zcl_dev_source_identity_capture(root, record, why, 192))
        return false;
    return dac_hex64(record->source_id) &&
           dac_hex64(record->mutation_id) && record->cas_present &&
           dac_hex64(record->cas_root_sha3);
}

static void dac_effect(const char *key, const char *candidate,
                       const struct dev_source_record *source,
                       const char *expected_current, int64_t expires,
                       char intent_id[65], char effect_digest[65])
{
    const char *intent_parts[] = { key };
    dac_hash_parts("zcl.dev_generation_activate.intent.v1", intent_parts, 1,
                   intent_id);
    char expires_text[32];
    (void)snprintf(expires_text, sizeof(expires_text), "%lld",
                   (long long)expires);
    const char *effect_parts[] = {
        intent_id, candidate, source->source_id, source->mutation_id,
        source->cas_root_sha3, expected_current, expires_text
    };
    dac_hash_parts("zcl.dev_generation_activate.effect.v1", effect_parts,
                   sizeof(effect_parts) / sizeof(effect_parts[0]),
                   effect_digest);
}

static void dac_result_fields(struct zcl_command_reply *reply,
                              const struct dev_activation_result *result)
{
    (void)json_push_kv_str(&reply->data, "activation_status",
                           result->activation_status);
    (void)json_push_kv_str(&reply->data, "verify_status",
                           result->verify_status);
    (void)json_push_kv_str(&reply->data, "rollback_status",
                           result->rollback_status);
    (void)json_push_kv_str(&reply->data, "candidate_generation",
                           result->candidate_generation);
    (void)json_push_kv_str(&reply->data, "running_generation",
                           result->running_generation);
}

/* True when `path` opens as the staging engine opens artifacts: a regular
 * executable file reachable WITHOUT following a symlink (the O_NOFOLLOW
 * content-path contract). */
static bool dac_artifact_usable(const char *path)
{
    struct platform_positioned_file artifact;
    platform_positioned_file_init(&artifact);
    bool usable = platform_positioned_file_open(&artifact, path) &&
                  platform_positioned_file_is_executable(&artifact);
    platform_positioned_file_close(&artifact);
    return usable;
}

/* dev_activation_request_from_cycle() names the checkout's migration alias
 * build/bin/zclassic23-dev, which the Makefile installs as "ln -sfn z23-dev"
 * -- a SYMLINK. The staging engine opens the artifact with O_NOFOLLOW, so a
 * symlinked artifact is refused with ELOOP before any digest is taken and
 * every plan fails ACTIVATION_PREFLIGHT_FAILED "candidate staging failed".
 * The proven shell transaction stages the hard-linked regular file
 * build/bin/z23-dev for exactly this reason (the Makefile installs it as a
 * regular file "for O_NOFOLLOW proof open"). Prefer that regular file, then
 * the alias's resolved referent, so the engine receives a regular file. */
static void dac_stage_artifact(const char *root,
                               struct dev_activation_cycle_request *cycle)
{
    char regular[PATH_MAX];
    int n = snprintf(regular, sizeof(regular), "%s/build/bin/z23-dev", root);
    if (n > 0 && (size_t)n < sizeof(regular) && dac_artifact_usable(regular)) {
        snprintf(cycle->artifact_path, sizeof(cycle->artifact_path), "%s",
                 regular);
        cycle->req.artifact_path = cycle->artifact_path;
        return;
    }
    /* Only normalize a request whose artifact still points at the cycle's own
     * constructed path; an adapter that bound a different artifact string
     * owns that choice. */
    if (!cycle->req.artifact_path ||
        strcmp(cycle->req.artifact_path, cycle->artifact_path) != 0)
        return;
    char resolved[PATH_MAX];
    if (platform_directory_canonical_real(cycle->artifact_path, resolved,
                                          sizeof(resolved)) &&
        strcmp(resolved, cycle->artifact_path) != 0 &&
        dac_artifact_usable(resolved)) {
        snprintf(cycle->artifact_path, sizeof(cycle->artifact_path), "%s",
                 resolved);
        cycle->req.artifact_path = cycle->artifact_path;
    }
}

static bool dac_request(const char *root, const char *source_id,
                        const char *mutation, const char *expected_current,
                        enum dev_activation_mode mode,
                        struct dev_activation_cycle_request *cycle)
{
    if (!dev_activation_request_from_cycle(root, "", cycle))
        return false;
    cycle->req.source_identity = source_id;
    cycle->req.source_mutation = mutation;
    cycle->req.expected_current_generation = expected_current;
    cycle->req.mode = mode;
    dac_stage_artifact(root, cycle);
    return true;
}

static bool dac_plan_ttl(const struct zcl_command_request *request,
                          struct zcl_command_reply *reply, int64_t *ttl)
{
    *ttl = 900;
    const struct json_value *ttl_value =
        json_get(request->input, "expires_in_seconds");
    if (ttl_value && !json_is_null(ttl_value))
        *ttl = json_get_int(ttl_value);
    if (*ttl < 60 || *ttl > 3600) {
        dac_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "INVALID_EXPIRY", "normalize",
                 "expires_in_seconds must be between 60 and 3600", "");
        return false;
    }

    return true;
}

static void dac_plan(const struct zcl_command_request *request,
                     struct zcl_command_reply *reply, const char *key)
{
    int64_t ttl;
    if (!dac_plan_ttl(request, reply, &ttl))
        return;

    char root[PATH_MAX];
    if (!dac_resolve_root(request, root)) {
        dac_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "ROOT_RESOLVE_FAILED", "normalize",
                 "could not resolve the checkout root", "");
        return;
    }
    struct dev_source_record source;
    char why[192] = {0};
    if (!dac_capture_source(root, &source, why)) {
        dac_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                 "SOURCE_EPOCH_UNKNOWN", "plan",
                 "could not capture a complete source epoch",
                 why[0] ? why : "source_capture_failed");
        return;
    }
    struct dev_activation_cycle_request cycle;
    if (!dac_request(root, source.source_id, source.mutation_id, NULL,
                     DEV_ACTIVATION_MODE_STAGE_ONLY, &cycle)) {
        dac_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "ACTIVATION_REQUEST_FAILED", "plan",
                 "could not construct the confined dev-lane request", "");
        return;
    }
    char current[80];
    if (!dac_read_current(cycle.gen_root, current)) {
        dac_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                 "RESIDENT_EPOCH_UNKNOWN", "plan",
                 "current dev generation is malformed or unreachable", "");
        return;
    }
    cycle.req.expected_current_generation = current;
    struct dev_activation_ops ops;
    dev_activation_default_ops(&cycle.req, &ops);
    struct dev_activation_result result = {0};
    int rc = dev_activation_run(&cycle.req, &ops, &result);
    if (rc != DEV_ACTIVATION_OK) {
        dac_result_fields(reply, &result);
        dac_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                 "ACTIVATION_PREFLIGHT_FAILED", "plan",
                 result.verify_detail,
                 result.failure_capsule);
        return;
    }

    int64_t expires = platform_time_wall_unix() + ttl;
    const char *expected = current[0] ? current : "-";
    char intent_id[65], effect_digest[65];
    dac_effect(key, result.candidate_sha256, &source, expected, expires,
               intent_id, effect_digest);

    struct authority_receipt_header authority = {0};
    (void)snprintf(authority.schema, sizeof(authority.schema), "%s",
                   DAC_AUTHORITY_SCHEMA);
    if (!dac_authority_fields(result.candidate_sha256, expected,
                              effect_digest, authority.artifact_digest,
                              authority.context_anchor,
                              authority.detail_digest)) {
        dac_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "AUTHORITY_FIELDS_INVALID", "authorize",
                 "could not bind the activation authority receipt", "");
        return;
    }
    char authority_name[96];
    if (!dac_authority_name(intent_id, authority_name) ||
        !authority_receipt_header_seal_and_write(
            &authority, cycle.datadir, authority_name, NULL, 0)) {
        dac_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "AUTHORITY_RECEIPT_FAILED", "authorize",
                 "could not persist the activation authority receipt", "");
        return;
    }

    struct json_value commit;
    json_init(&commit);
    json_set_object(&commit);
    (void)json_push_kv_str(&commit, "idempotency_key", key);
    (void)json_push_kv_str(&commit, "intent_id", intent_id);
    (void)json_push_kv_str(&commit, "effect_digest", effect_digest);
    (void)json_push_kv_str(&commit, "candidate_sha256",
                           result.candidate_sha256);
    (void)json_push_kv_str(&commit, "source_id_sha256", source.source_id);
    (void)json_push_kv_str(&commit, "source_mutation_sha256",
                           source.mutation_id);
    (void)json_push_kv_str(&commit, "source_cas_sha3",
                           source.cas_root_sha3);
    (void)json_push_kv_str(&commit, "expected_current_generation", expected);
    (void)json_push_kv_int(&commit, "expires_unix", expires);
    (void)json_push_kv_bool(&commit, "confirm", true);
    char commit_input[1024];
    size_t written = json_write(&commit, commit_input, sizeof(commit_input));
    json_free(&commit);
    if (written == 0 || written >= sizeof(commit_input)) {
        dac_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "COMMIT_INPUT_OVERFLOW", "serialize",
                 "could not serialize the exact activation commit", "");
        return;
    }

    (void)json_push_kv_str(&reply->data, "schema", DAC_SCHEMA);
    (void)json_push_kv_str(&reply->data, "stage", "plan");
    (void)json_push_kv_str(&reply->data, "intent_id", intent_id);
    (void)json_push_kv_str(&reply->data, "effect_digest", effect_digest);
    (void)json_push_kv_int(&reply->data, "expires_unix", expires);
    (void)json_push_kv_str(&reply->data, "source_id_sha256",
                           source.source_id);
    (void)json_push_kv_str(&reply->data, "source_cas_sha3",
                           source.cas_root_sha3);
    dac_result_fields(reply, &result);
    (void)json_push_kv_str(&reply->data, "commit_input", commit_input);
    (void)json_push_kv_str(&reply->data, "confirm_hint",
                           "re-run this command with commit_input to activate");
    reply->error.mutated = true; /* immutable staging + durable deploy state */
}

struct dac_commit_input {
    const char *intent, *effect, *candidate, *source_id, *mutation, *cas, *expected;
    int64_t expires;
};

/* Defined with the generation-history helpers below dac_commit(). */
static void dac_record_accepted(const char *gen_root, const char *generation,
                                const char *sha_hex, const char *result);

static bool dac_commit_input_valid(const struct dac_commit_input *c)
{
    return dac_hex64(c->intent) && dac_hex64(c->effect) &&
           dac_hex64(c->candidate) && dac_hex64(c->source_id) &&
           dac_hex64(c->mutation) && dac_hex64(c->cas) && c->expected &&
           (strcmp(c->expected, "-") == 0 || dac_generation(c->expected)) &&
           c->expires > 0;
}

static bool dac_commit_authorize(const struct zcl_command_request *request,
                                 struct zcl_command_reply *reply,
                                 const char *key,
                                 const struct dac_commit_input *c,
                                 char root[PATH_MAX])
{
    struct dev_source_record planned = {0};
    (void)snprintf(planned.source_id, sizeof(planned.source_id), "%s",
                   c->source_id);
    (void)snprintf(planned.mutation_id, sizeof(planned.mutation_id), "%s",
                   c->mutation);
    (void)snprintf(planned.cas_root_sha3, sizeof(planned.cas_root_sha3), "%s",
                   c->cas);
    planned.cas_present = true;
    char want_intent[65], want_effect[65];
    dac_effect(key, c->candidate, &planned, c->expected, c->expires, want_intent,
               want_effect);
    if (strcmp(c->intent, want_intent) != 0 || strcmp(c->effect, want_effect) != 0) {
        dac_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_DENIED,
                 "EFFECT_DIGEST_MISMATCH", "authorize",
                 "activation plan fields changed after preflight", "");
        return false;
    }
    if (platform_time_wall_unix() > c->expires) {
        dac_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                 "ACTIVATION_PLAN_EXPIRED", "authorize",
                 "activation plan expired; create a fresh plan", "");
        return false;
    }

    if (!dac_resolve_root(request, root)) {
        dac_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "ROOT_RESOLVE_FAILED", "normalize",
                 "could not resolve the checkout root", "");
        return false;
    }
    struct dev_source_record current_source;
    char why[192] = {0};
    if (!dac_capture_source(root, &current_source, why) ||
        strcmp(current_source.source_id, c->source_id) != 0 ||
        strcmp(current_source.mutation_id, c->mutation) != 0 ||
        strcmp(current_source.cas_root_sha3, c->cas) != 0) {
        dac_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                 "SOURCE_EPOCH_SUPERSEDED", "authorize",
                 "source changed after activation planning",
                 why[0] ? why : "source_epoch_mismatch");
        return false;
    }
    return true;
}

static void dac_commit(const struct zcl_command_request *request,
                       struct zcl_command_reply *reply, const char *key)
{
    const char *intent = json_get_str(json_get(request->input, "intent_id"));
    const char *effect =
        json_get_str(json_get(request->input, "effect_digest"));
    const char *candidate =
        json_get_str(json_get(request->input, "candidate_sha256"));
    const char *source_id =
        json_get_str(json_get(request->input, "source_id_sha256"));
    const char *mutation =
        json_get_str(json_get(request->input, "source_mutation_sha256"));
    const char *cas = json_get_str(json_get(request->input, "source_cas_sha3"));
    const char *expected = json_get_str(
        json_get(request->input, "expected_current_generation"));
    const struct json_value *expires_value =
        json_get(request->input, "expires_unix");
    int64_t expires = expires_value ? json_get_int(expires_value) : 0;
    const struct dac_commit_input c = {
        intent, effect, candidate, source_id, mutation, cas, expected, expires
    };
    if (!dac_commit_input_valid(&c)) {
        dac_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "INVALID_COMMIT_INPUT", "normalize",
                 "commit requires the complete unmodified plan input", "");
        return;
    }
    char root[PATH_MAX];
    if (!dac_commit_authorize(request, reply, key, &c, root))
        return;
    struct dev_activation_cycle_request cycle;
    const char *expected_engine = strcmp(expected, "-") == 0 ? "" : expected;
    if (!dac_request(root, source_id, mutation, expected_engine,
                     DEV_ACTIVATION_MODE_ACTIVATE, &cycle)) {
        dac_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "ACTIVATION_REQUEST_FAILED", "commit",
                 "could not construct the confined dev-lane request", "");
        return;
    }
    uint8_t artifact_digest[32], context_anchor[32], detail_digest[32];
    char authority_name[96];
    if (!dac_authority_fields(candidate, expected, effect, artifact_digest,
                              context_anchor, detail_digest) ||
        !dac_authority_name(intent, authority_name) ||
        !dac_authority_available(cycle.datadir, authority_name,
                                 artifact_digest, context_anchor,
                                 detail_digest)) {
        dac_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_DENIED,
                 "AUTHORITY_RECEIPT_UNAVAILABLE", "authorize",
                 "activation requires the exact independently sealed plan receipt",
                 "create a fresh plan with this exact dev binary");
        return;
    }
    char current[80];
    if (!dac_read_current(cycle.gen_root, current)) {
        dac_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                 "RESIDENT_EPOCH_UNKNOWN", "authorize",
                 "current dev generation is malformed or unreachable", "");
        return;
    }
    char candidate_generation[80];
    (void)snprintf(candidate_generation, sizeof(candidate_generation),
                   "gen-%s", candidate);
    bool retry_same_effect = strcmp(current, candidate_generation) == 0;
    if (!retry_same_effect && strcmp(current, expected_engine) != 0) {
        dac_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                 "RESIDENT_EPOCH_SUPERSEDED", "authorize",
                 "resident generation changed after activation planning", "");
        return;
    }
    cycle.req.expected_current_generation =
        retry_same_effect ? candidate_generation : expected_engine;
    uint8_t candidate_bytes[32];
    if (!dac_unhex32(candidate, candidate_bytes)) {
        dac_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "INVALID_CANDIDATE", "normalize",
                 "candidate hash is malformed", "");
        return;
    }
    struct dev_activation_ops ops;
    dev_activation_default_ops(&cycle.req, &ops);
    struct dev_activation_result result = {0};
    int rc = dev_activation_activate_generation(candidate_bytes, &cycle.req,
                                                &ops, &result);
    if (rc != DEV_ACTIVATION_OK) {
        dac_result_fields(reply, &result);
        dac_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                 "ACTIVATION_COMMIT_FAILED", "commit",
                 result.verify_detail,
                 result.failure_capsule);
        /* The engine may have stopped, flipped, restarted, and restored the
         * lane before reporting failure. Never describe that as untouched. */
        reply->error.mutated = true;
        return;
    }
    (void)json_push_kv_str(&reply->data, "schema", DAC_SCHEMA);
    (void)json_push_kv_str(&reply->data, "stage", "committed");
    (void)json_push_kv_str(&reply->data, "intent_id", intent);
    (void)json_push_kv_str(&reply->data, "effect_digest", effect);
    (void)json_push_kv_bool(&reply->data, "idempotent_retry",
                            retry_same_effect);
    dac_result_fields(reply, &result);
    dac_record_accepted(cycle.gen_root, result.candidate_generation,
                        result.candidate_sha256, "activated");
    reply->error.mutated = true;
}

/* ── generation history: accepted markers ────────────────────────────── */

static void dac_iso_utc_now(char out[32])
{
    time_t now = platform_time_wall_time_t();
    struct tm tmv;
    if (gmtime_r(&now, &tmv))
        strftime(out, 32, "%Y-%m-%dT%H:%M:%SZ", &tmv);
    else
        snprintf(out, 32, "1970-01-01T00:00:00Z");
}

/* Read one bounded JSON document through the O_NOFOLLOW content-path open.
 * The dev lane's deploy state and generation manifests are regular files the
 * engine itself wrote; a replaced or oversized path simply reads as absent. */
static bool dac_read_json_bounded(const char *path, char *buf, size_t capacity)
{
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path))
        return false;
    uint64_t size = 0;
    int64_t got = platform_positioned_file_size(&file, &size)
        ? platform_positioned_file_read(&file, buf, capacity - 1, 0)
        : -1;
    platform_positioned_file_close(&file);
    if (got <= 0)
        return false;
    buf[got] = 0;
    return (uint64_t)got == size;
}

/* The generation the last activation replaced (agent-deploy.json's
 * previous_generation), or false when no deploy state records one. */
static bool dac_read_previous_generation(const char *datadir, char out[80])
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/agent-deploy.json", datadir);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return false;
    char blob[4096];
    if (!dac_read_json_bounded(path, blob, sizeof(blob)))
        return false;
    struct json_value doc;
    json_init(&doc);
    bool ok = json_read(&doc, blob, strlen(blob)) && doc.type == JSON_OBJ;
    const char *previous =
        ok ? json_get_str(json_get(&doc, "previous_generation")) : NULL;
    ok = previous && dac_generation(previous);
    if (ok)
        snprintf(out, 80, "%s", previous);
    json_free(&doc);
    return ok;
}

/* The authoritative baked source identity of an immutable generation. */
static bool dac_read_generation_source_id(const char *gen_root,
                                          const char *generation,
                                          char out[65])
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s/manifest.json", gen_root,
                     generation);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return false;
    char blob[4096];
    if (!dac_read_json_bounded(path, blob, sizeof(blob)))
        return false;
    struct json_value doc;
    json_init(&doc);
    bool ok = json_read(&doc, blob, strlen(blob)) && doc.type == JSON_OBJ;
    const char *source_id =
        ok ? json_get_str(json_get(&doc, "source_id_sha256")) : NULL;
    ok = source_id && dac_hex64(source_id);
    if (ok)
        snprintf(out, 65, "%s", source_id);
    json_free(&doc);
    return ok;
}

/* Record a verified activation in the history the `dev generation history`
 * reader scans: accepted/<gen>.json, mirroring the engine's rejected/<gen>.json
 * quarantine markers, so an activate->rollback cycle leaves BOTH generations
 * recorded with their results. */
static void dac_record_accepted(const char *gen_root, const char *generation,
                                const char *sha_hex, const char *result)
{
    char dir[PATH_MAX], path[PATH_MAX], tmp[PATH_MAX], now[32];
    int n1 = snprintf(dir, sizeof(dir), "%s/accepted", gen_root);
    int n2 = snprintf(path, sizeof(path), "%s/%s.json", dir, generation);
    int n3 = snprintf(tmp, sizeof(tmp), "%s/.%s.%lld", dir, generation,
                      (long long)os_proc_current_pid());
    if (n1 <= 0 || (size_t)n1 >= sizeof(dir) || n2 <= 0 ||
        (size_t)n2 >= sizeof(path) || n3 <= 0 || (size_t)n3 >= sizeof(tmp))
        return;
    (void)platform_directory_create(dir, 0755); /* EEXIST is fine */
    dac_iso_utc_now(now);
    FILE *f = fopen(tmp, "w");
    if (!f)
        return;
    fprintf(f, "{\"schema\":\"zcl.dev_accepted_generation.v1\","
               "\"generation\":\"%s\",\"sha256\":\"%s\","
               "\"accepted_at_utc\":\"%s\",\"result\":\"%s\"}\n",
            generation, sha_hex, now, result);
    if (fclose(f) == 0)
        (void)rename(tmp, path);
    else
        (void)remove(tmp);
}

/* ── dev generation rollback: restore the verified last-good generation ── */

/* The undo target: last-good when it differs from the resident generation,
 * else the generation the last activation replaced. After a VERIFIED
 * activation the engine repoints last-good at the new candidate, so the
 * distinct prior generation lives in the deploy state's previous_generation. */
static bool dac_rollback_target(const char *gen_root, const char *datadir,
                                const char *current, char out[80])
{
    char candidate[80];
    if (dac_read_generation_link(gen_root, "last-good", candidate) &&
        candidate[0] && strcmp(candidate, current) != 0) {
        snprintf(out, 80, "%s", candidate);
        return true;
    }
    if (dac_read_previous_generation(datadir, candidate) && candidate[0] &&
        strcmp(candidate, current) != 0) {
        snprintf(out, 80, "%s", candidate);
        return true;
    }
    return false;
}

static void dac_rollback_plan(const struct zcl_command_request *request,
                              struct zcl_command_reply *reply)
{
    char root[PATH_MAX];
    if (!dac_resolve_root(request, root)) {
        dac_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "ROOT_RESOLVE_FAILED", "normalize",
                 "could not resolve the checkout root", "");
        return;
    }
    struct dev_activation_cycle_request cycle;
    if (!dac_request(root, "", NULL, NULL, DEV_ACTIVATION_MODE_ACTIVATE,
                     &cycle)) {
        dac_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "ACTIVATION_REQUEST_FAILED", "plan",
                 "could not construct the confined dev-lane request", "");
        return;
    }
    char current[80];
    if (!dac_read_current(cycle.gen_root, current)) {
        dac_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                 "RESIDENT_EPOCH_UNKNOWN", "plan",
                 "current dev generation is malformed or unreachable", "");
        return;
    }
    char target[80];
    if (!dac_rollback_target(cycle.gen_root, cycle.datadir, current, target)) {
        dac_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                 "ROLLBACK_TARGET_UNAVAILABLE", "plan",
                 "no verified generation differs from the resident one; "
                 "nothing to roll back to",
                 current[0] ? current : "no current generation");
        return;
    }
    char source_id[65];
    if (!dac_read_generation_source_id(cycle.gen_root, target, source_id)) {
        dac_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                 "ROLLBACK_TARGET_INVALID", "plan",
                 "rollback target carries no authoritative manifest source "
                 "identity",
                 target);
        return;
    }
    (void)json_push_kv_str(&reply->data, "schema",
                           "zcl.dev_generation_rollback.v1");
    (void)json_push_kv_str(&reply->data, "stage", "plan");
    (void)json_push_kv_str(&reply->data, "current_generation", current);
    (void)json_push_kv_str(&reply->data, "rollback_generation", target);
    (void)json_push_kv_str(&reply->data, "source_id_sha256", source_id);
    (void)json_push_kv_str(&reply->data, "confirm_hint",
                           "re-run this command with confirm to restore the "
                           "rollback generation");
}

static void dac_rollback_commit(const struct zcl_command_request *request,
                                struct zcl_command_reply *reply)
{
    char root[PATH_MAX];
    if (!dac_resolve_root(request, root)) {
        dac_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "ROOT_RESOLVE_FAILED", "normalize",
                 "could not resolve the checkout root", "");
        return;
    }
    struct dev_activation_cycle_request cycle;
    if (!dac_request(root, NULL, NULL, NULL, DEV_ACTIVATION_MODE_ACTIVATE,
                     &cycle)) {
        dac_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "ACTIVATION_REQUEST_FAILED", "commit",
                 "could not construct the confined dev-lane request", "");
        return;
    }
    char current[80];
    if (!dac_read_current(cycle.gen_root, current)) {
        dac_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                 "RESIDENT_EPOCH_UNKNOWN", "authorize",
                 "current dev generation is malformed or unreachable", "");
        return;
    }
    char target[80];
    if (!dac_rollback_target(cycle.gen_root, cycle.datadir, current, target)) {
        dac_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                 "ROLLBACK_TARGET_UNAVAILABLE", "authorize",
                 "no verified generation differs from the resident one; "
                 "nothing to roll back to",
                 current[0] ? current : "no current generation");
        return;
    }
    char source_id[65];
    if (!dac_read_generation_source_id(cycle.gen_root, target, source_id)) {
        dac_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                 "ROLLBACK_TARGET_INVALID", "authorize",
                 "rollback target carries no authoritative manifest source "
                 "identity",
                 target);
        return;
    }
    char expected[80];
    snprintf(expected, sizeof(expected), "%s", current);
    cycle.req.source_identity = source_id;
    cycle.req.expected_current_generation = expected;
    uint8_t target_bytes[32];
    if (!dac_unhex32(target + 4, target_bytes)) {
        dac_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "ROLLBACK_TARGET_INVALID", "normalize",
                 "rollback target hash is malformed", target);
        return;
    }
    struct dev_activation_ops ops;
    dev_activation_default_ops(&cycle.req, &ops);
    /* Rollback exists to restore a binary from a PRIOR source epoch, so the
     * current-tree source CAS would refuse exactly the restoration being
     * requested. Authority is the target generation's own manifest identity,
     * which candidate preflight still proves the staged binary carries. */
    ops.source_epoch_cas = NULL;
    struct dev_activation_result result = {0};
    int rc = dev_activation_activate_generation(target_bytes, &cycle.req,
                                                &ops, &result);
    if (rc != DEV_ACTIVATION_OK) {
        dac_result_fields(reply, &result);
        dac_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                 "ACTIVATION_ROLLBACK_FAILED", "commit",
                 result.verify_detail, result.failure_capsule);
        /* The engine may have stopped, flipped, restarted, and restored the
         * lane before reporting failure. Never describe that as untouched. */
        reply->error.mutated = true;
        return;
    }
    dac_record_accepted(cycle.gen_root, target, target + 4,
                        "rollback_verified");
    (void)json_push_kv_str(&reply->data, "schema",
                           "zcl.dev_generation_rollback.v1");
    (void)json_push_kv_str(&reply->data, "stage", "committed");
    (void)json_push_kv_str(&reply->data, "restored_generation", target);
    dac_result_fields(reply, &result);
    reply->error.mutated = true;
}

void zcl_native_handle_dev_generation_rollback(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !request->input || !reply) {
        if (reply)
            dac_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                     ZCL_COMMAND_EXIT_INTERNAL, "BAD_REQUEST", "normalize",
                     "missing rollback request input", "");
        return;
    }
    if (json_get_bool(json_get(request->input, "confirm")))
        dac_rollback_commit(request, reply);
    else
        dac_rollback_plan(request, reply);
}

void zcl_native_handle_dev_generation_activate(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !request->input || !reply) {
        if (reply)
            dac_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                     ZCL_COMMAND_EXIT_INTERNAL, "BAD_REQUEST", "normalize",
                     "missing activation request input", "");
        return;
    }
    const char *key =
        json_get_str(json_get(request->input, "idempotency_key"));
    if (!dac_key(key)) {
        dac_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "INVALID_IDEMPOTENCY_KEY", "normalize",
                 "idempotency_key must be 1..64 letters, digits, '.', '_', ':', or '-'",
                 "idempotency_key");
        return;
    }
    if (json_get_bool(json_get(request->input, "confirm")))
        dac_commit(request, reply, key);
    else
        dac_plan(request, reply, key);
}

#endif /* ZCL_DEV_BUILD */
