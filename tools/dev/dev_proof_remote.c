/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: bind native proof receipt admission to a caller's pinned request. */
#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#endif
#include "dev_proof_remote.h"
#include "base/bytes.h"
#include "base/hex.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static bool remote_refuse(char *why, size_t size, const char *reason)
{
    if (why && size) (void)snprintf(why, size, "%s", reason);
    return false;
}

static bool remote_expectation_valid(
    const struct zcl_dev_proof_remote_expectation *expected)
{
    uint8_t oid[ZCL_DEV_PROOF_OID_MAX], length;
    return expected &&
        zcl_dev_proof_oid_decode(expected->local_commit, oid, &length) &&
        zcl_dev_proof_oid_decode(expected->remote_base, oid, &length) &&
        zcl_bytes_any_set(expected->signer_pubkey, 32) &&
        zcl_bytes_any_set(expected->source_root, 32) &&
        zcl_bytes_any_set(expected->source_cas_root, 32) &&
        zcl_bytes_any_set(expected->changed_set_root, 32) &&
        zcl_bytes_any_set(expected->impact_policy_root, 32);
}

static bool remote_bindings_match(
    const struct zcl_dev_acceptance_receipt_v1 *receipt,
    const struct zcl_dev_proof_remote_expectation *expected,
    char *why, size_t size)
{
    const struct { const uint8_t *actual, *pinned; const char *reason; } fields[] = {
        {receipt->signer_pubkey, expected->signer_pubkey, "remote_signer_mismatch"},
        {receipt->source_root, expected->source_root, "remote_source_root_mismatch"},
        {receipt->source_cas_root, expected->source_cas_root, "remote_source_cas_root_mismatch"},
        {receipt->changed_set_root, expected->changed_set_root, "remote_changed_set_root_mismatch"},
        {receipt->impact_policy_root, expected->impact_policy_root, "remote_impact_policy_root_mismatch"},
    };
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++)
        if (memcmp(fields[i].actual, fields[i].pinned, 32) != 0)
            return remote_refuse(why, size, fields[i].reason);
    return true;
}

#if !defined(_WIN32)
#include "command/native_command.h"
#include "command/native_dev_land_remote_shared.h"
#include "platform/positioned_file.h"
#include "platform/temp_directory.h"
#include "util/file_io.h"
#include "util/write_all.h"
#include <fcntl.h>
#include <unistd.h>

extern char **environ;
#define REMOTE_GIT_MS 600000

static bool remote_host_admitted(char *why, size_t size)
{
    const char *admission = getenv("DEVBUILD_ACTIVE");
    return admission && strcmp(admission, "z23") == 0
        ? true : remote_refuse(why, size, "remote_host_admission_required");
}

/* The existing runner uses execvp("git"). Qualify its executable search and
 * refuse Git redirection/config injection rather than changing process-wide
 * environment (which would race other callers). The receiver owns this env. */
static bool remote_git_environment(char *why, size_t size)
{
    const char *path = getenv("PATH");
    if (!path || strcmp(path, "/usr/bin:/bin") != 0)
        return remote_refuse(why, size, "remote_git_path_unqualified");
    for (char **at = environ; at && *at; at++) {
        if (strncmp(*at, "GIT_", 4) == 0 ||
            strncmp(*at, "LD_", 3) == 0 ||
            strncmp(*at, "DYLD_", 5) == 0 ||
            strncmp(*at, "BASH_ENV=", 9) == 0 ||
            strncmp(*at, "ENV=", 4) == 0 ||
            strncmp(*at, "ZCL_SOVEREIGN_SOURCE_ROOT=", 26) == 0 ||
            strncmp(*at, "ZCL_SOURCE_IDENTITY_", 20) == 0)
            return remote_refuse(why, size, "remote_git_environment_redirected");
    }
    return true;
}

/* No shell, external filters, hooks, fsmonitor or recursive submodule work.
 * The underlying native runner has room for exactly 20 argument operands.
 * A full capture is ambiguous (possibly truncated), so refuse it. */
static int remote_git(const char *root, const char *const *args,
                       char *out, size_t size)
{
    const char *argv[21] = {
        "--no-replace-objects", "--no-pager",
        "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
        "-c", "core.autocrlf=false", "-c", "core.attributesFile=/dev/null",
        "-c", "submodule.recurse=false", "-c", "gc.auto=0",
    };
    size_t used = 14;
    if (!out || size < 2u) return -1;
    out[0] = '\0';
    for (size_t i = 0; args[i]; i++) {
        if (used == 20u) return -1;
        argv[used++] = args[i];
    }
    argv[used] = NULL;
    int rc = zcl_native_dev_land_git(root, argv, out, size, REMOTE_GIT_MS);
    if (strlen(out) >= size - 1u) return -1;
    return rc;
}

static bool remote_canonical(const char *input, char out[4096])
{
    return input && input[0] == '/' && zcl_dlr_arg_ok(input, true) &&
        realpath(input, out) && strcmp(input, out) == 0;
}

static bool remote_git_text(const char *root, const char *const *args,
                            char *out, size_t size)
{
    char captured[4098];
    if (size > sizeof(captured) - 2u ||
        remote_git(root, args, captured, size + 2u) != 0) return false;
    size_t len = strlen(captured);
    if (!len || captured[len - 1u] != '\n') return false;
    captured[--len] = '\0';
    if (!len || len >= size || strchr(captured, '\n') || strchr(captured, '\r')) return false;
    memcpy(out, captured, len + 1u);
    return true;
}

static bool remote_hex(const char *value, size_t bytes)
{
    uint8_t decoded[32];
    return value && bytes <= sizeof(decoded) && strlen(value) == bytes * 2u &&
        zcl_hex_decode_lower(value, decoded, bytes);
}

static bool remote_assignment_valid(
    const struct zcl_dev_proof_remote_assignment *a)
{
    uint8_t oid[ZCL_DEV_PROOF_OID_MAX], len;
    return a && remote_expectation_valid(&a->expected) &&
        memchr(a->bundle_sha256, 0, sizeof(a->bundle_sha256)) &&
        memchr(a->source_id, 0, sizeof(a->source_id)) &&
        memchr(a->git_tree, 0, sizeof(a->git_tree)) &&
        remote_hex(a->bundle_sha256, 32) && remote_hex(a->source_id, 32) &&
        zcl_dev_proof_oid_decode(a->git_tree, oid, &len);
}

bool zcl_dev_proof_remote_git_policy_check(const char *root, char *why, size_t size)
{
    if (!remote_git_environment(why, size)) return false;
    char output[16384];
    /* Refuse lazy-fetch configuration before status or any object reads. */
    const char *promisor[] = {"config", "--get-regexp",
        "^(extensions\\.partialclone$|remote\\..*\\.promisor$)", NULL};
    int rc = remote_git(root, promisor, output, sizeof(output));
    if (rc != 1 || output[0])
        return remote_refuse(why, size, "remote_git_lazy_fetch_config");
    const char *config[] = {"config", "--get-regexp",
        "^(filter\\.|core\\.alternateRefsCommand$)", NULL};
    rc = remote_git(root, config, output, sizeof(output));
    if (rc != 1 || output[0])
        return remote_refuse(why, size, "remote_git_external_filter_or_config");
    return true;
}

static bool remote_clean(const char *root, char *why, size_t size)
{
    char output[16384];
    if (!zcl_dev_proof_remote_git_policy_check(root, why, size)) return false;
    const char *status[] = {"status", "--porcelain=v1", "--untracked-files=all", NULL};
    if (remote_git(root, status, output, sizeof(output)) != 0 || output[0])
        return remote_refuse(why, size, "remote_destination_dirty_or_unreadable");
    return true;
}

static bool remote_workspace(const struct zcl_dev_proof_remote_assignment *a,
    zcl_dev_proof_remote_owner_check owner, void *ctx,
    struct zcl_dev_proof_remote_placement *out, char *why, size_t size)
{
    char repository[4096], destination[4096], common[4096], top[4096];
    const char *common_args[] = {"rev-parse", "--path-format=absolute", "--git-common-dir", NULL};
    const char *top_args[] = {"rev-parse", "--show-toplevel", NULL};
    const char *head_args[] = {"rev-parse", "--verify", "HEAD", NULL};
    if (!remote_canonical(a->repository, repository) ||
        !remote_canonical(a->destination, destination) || !owner ||
        !owner(ctx, destination, why, size))
        return remote_refuse(why, size, "remote_destination_not_owned");
    if (!remote_git_text(destination, top_args, top, sizeof(top)) ||
        strcmp(top, destination) != 0 ||
        !remote_git_text(repository, common_args, common, sizeof(common)) ||
        !remote_git_text(destination, common_args, out->common_git_dir,
                          sizeof(out->common_git_dir)) ||
        strcmp(common, out->common_git_dir) != 0)
        return remote_refuse(why, size, "remote_destination_repository_mismatch");
    if (!remote_clean(destination, why, size)) return false;
    if (!remote_git_text(destination, head_args, out->previous_head,
                          sizeof(out->previous_head)))
        return remote_refuse(why, size, "remote_destination_head_unavailable");
    memcpy(out->canonical_root, destination, strlen(destination) + 1u);
    return true;
}

/* Pin transport bytes before any Git import. Stable handle snapshots close
 * pathname replacement/truncation races. Keep the private copies as evidence,
 * including on failure; no recursive cleanup of caller paths is attempted. */
static bool remote_copy_input(const char *input, const char *output, uint64_t limit)
{
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    if (!input || !platform_positioned_file_open(&file, input)) return false;
    bool ok = platform_positioned_file_snapshot(&file, &before) && before.size <= limit;
    int fd = ok ? open(output, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0400) : -1;
    ok = fd >= 0;
    uint64_t offset = 0;
    uint8_t buffer[16384];
    while (ok && offset < before.size) {
        uint64_t left = before.size - offset;
        size_t count = left < sizeof(buffer) ? (size_t)left : sizeof(buffer);
        int64_t n = platform_positioned_file_read(&file, buffer, count, offset);
        ok = n > 0 && (uint64_t)n <= count && zcl_write_all(fd, buffer, (size_t)n);
        if (ok) offset += (uint64_t)n;
    }
    ok = ok && platform_positioned_file_snapshot(&file, &after) &&
        platform_positioned_file_snapshot_equal(&before, &after);
    if (fd >= 0 && close(fd) != 0) ok = false;
    platform_positioned_file_close(&file);
    return ok;
}

static bool remote_offer_pin(const char *path, const char *key, const char *pin)
{
    uint8_t *wire = NULL;
    size_t len = 0, matches = 0;
    struct json_value doc = {0};
    bool ok = zcl_read_whole_file(path, ZCL_DEV_PROOF_REMOTE_OFFER_MAX_BYTES,
        &wire, &len, "remote-proof-offer") &&
        json_read(&doc, (const char *)wire, len) && doc.type == JSON_OBJ;
    for (size_t i = 0; ok && i < json_size(&doc); i++) {
        if (strcmp(doc.keys[i], key) != 0) continue;
        matches++;
        const struct json_value *v = json_at(&doc, i);
        ok = v && v->type == JSON_STR && strcmp(json_get_str(v), pin) == 0;
    }
    free(wire);
    json_free(&doc);
    return ok && matches == 1u;
}

static bool remote_transport_snapshot(const struct zcl_dev_proof_remote_assignment *a,
    struct zcl_dev_proof_remote_placement *out, char bundle[4096], char offer[4096],
    char *why, size_t size)
{
    char sha[65], cache[4096];
    int cn = snprintf(cache, sizeof(cache), "%s/.cache/zcl-dev-proof", out->canonical_root);
    /* The execution guard established this private cache. Keep inputs with
     * the owned checkout: successful devbuild jobs retire their TMPDIR. */
    if (cn < 0 || (size_t)cn >= sizeof(cache) ||
        !platform_temp_directory_create_under(cache, "remote-proof-inputs-",
            out->evidence_dir, sizeof(out->evidence_dir)))
        return remote_refuse(why, size, "remote_transport_snapshot_unavailable");
    int bn = snprintf(bundle, 4096, "%s/source.bundle", out->evidence_dir);
    int on = snprintf(offer, 4096, "%s/source.offer.json", out->evidence_dir);
    if (bn < 0 || bn >= 4096 || on < 0 || on >= 4096 ||
        !remote_copy_input(a->offer, offer, ZCL_DEV_PROOF_REMOTE_OFFER_MAX_BYTES) ||
        !remote_copy_input(a->bundle, bundle, ZCL_DEV_PROOF_REMOTE_BUNDLE_MAX_BYTES) ||
        !zcl_dlr_file_sha256(bundle, sha) || strcmp(sha, a->bundle_sha256) != 0)
        return remote_refuse(why, size, "remote_transport_bytes_mismatch");
    return true;
}

static bool remote_transport(const struct zcl_dev_proof_remote_assignment *a,
    struct zcl_dev_proof_remote_placement *out, char bundle[4096],
    char *why, size_t size)
{
    char offer[4096];
    if (!remote_transport_snapshot(a, out, bundle, offer, why, size)) return false;
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "remote-proof-prepare");
    bool ok = zcl_dlr_check_offer_at(out->canonical_root, bundle, offer,
        "dev.proof.remote.prepare", &reply);
    if (!ok) (void)remote_refuse(why, size, reply.error.code[0]
        ? reply.error.code : "remote_bundle_offer_refused");
    zcl_command_reply_free(&reply);
    if (!ok) return false;
    if (!remote_offer_pin(offer, "commit", a->expected.local_commit) ||
        !remote_offer_pin(offer, "base", a->expected.remote_base) ||
        !remote_offer_pin(offer, "bundle_sha256", a->bundle_sha256))
        return remote_refuse(why, size, "remote_offer_assignment_mismatch");
    return true;
}

static bool remote_pair_tree(const struct zcl_dev_proof_remote_assignment *a,
    const char *root, char tree[65], char *why, size_t size)
{
    char output[128], expression[80];
    const char *base[] = {"cat-file", "-t", a->expected.remote_base, NULL};
    const char *local[] = {"cat-file", "-t", a->expected.local_commit, NULL};
    const char *ancestor[] = {"merge-base", "--is-ancestor",
        a->expected.remote_base, a->expected.local_commit, NULL};
    if (!remote_git_text(root, base, output, sizeof(output)) || strcmp(output, "commit") != 0 ||
        !remote_git_text(root, local, output, sizeof(output)) || strcmp(output, "commit") != 0 ||
        remote_git(root, ancestor, output, sizeof(output)) != 0)
        return remote_refuse(why, size, "remote_pair_objects_or_ancestry_invalid");
    int n = snprintf(expression, sizeof(expression), "%s^{tree}", a->expected.local_commit);
    const char *args[] = {"rev-parse", "--verify", expression, NULL};
    if (n < 0 || (size_t)n >= sizeof(expression) ||
        !remote_git_text(root, args, tree, 65) || strcmp(tree, a->git_tree) != 0)
        return remote_refuse(why, size, "remote_git_tree_mismatch");
    return true;
}

/* Trusted native Merkle capture must bind source bytes BEFORE invoking the
 * placed helper (which may compile its native batch). Capture again afterward;
 * that helper is never the first authority for fetched source. */
static bool remote_native_cas(const struct zcl_dev_proof_remote_assignment *a,
    const char *root, struct dev_source_record *source, char *why, size_t size)
{
    uint8_t cas[32];
    if (!zcl_dev_source_cas_capture(root, source) || !source->cas_present ||
        !zcl_hex_decode_lower(source->cas_root_sha3, cas, 32) ||
        memcmp(cas, a->expected.source_cas_root, 32) != 0)
        return remote_refuse(why, size, "remote_native_source_cas_mismatch");
    return true;
}

static bool remote_source(const struct zcl_dev_proof_remote_assignment *a,
    const char *root, struct dev_source_record *source, char *why, size_t size)
{
    struct dev_source_record native = {0};
    if (!remote_native_cas(a, root, &native, why, size) ||
        !zcl_dev_source_identity_capture(root, source, why, size)) return false;
    memset(&native, 0, sizeof(native));
    if (!remote_native_cas(a, root, &native, why, size)) return false;
    if (!source->cas_present || strcmp(source->source_id, a->source_id) != 0 ||
        strcmp(native.cas_root_sha3, source->cas_root_sha3) != 0)
        return remote_refuse(why, size, "remote_placed_source_identity_mismatch");
    return true;
}

static bool remote_import_checkout(const struct zcl_dev_proof_remote_assignment *a,
    const char *bundle, struct zcl_dev_proof_remote_placement *out,
    char *why, size_t size)
{
    char output[16384];
    const char *import[] = {"bundle", "unbundle", bundle, NULL};
    if (remote_git(out->canonical_root, import, output, sizeof(output)) != 0)
        return remote_refuse(why, size, "remote_bundle_import_failed");
    out->objects_imported = true;
    if (!remote_pair_tree(a, out->canonical_root, out->git_tree, why, size)) return false;
    const char *checkout[] = {"checkout", "--quiet", "--detach",
        "--no-overwrite-ignore", "--no-recurse-submodules", a->expected.local_commit, NULL};
    if (remote_git(out->canonical_root, checkout, output, sizeof(output)) != 0)
        return remote_refuse(why, size, "remote_detached_checkout_failed");
    out->placed = true;
    return true;
}

static bool remote_prepare_finish(const struct zcl_dev_proof_remote_assignment *a,
    const char *bundle, zcl_dev_proof_remote_owner_check owner, void *ctx,
    struct zcl_dev_proof_remote_placement *out, char *why, size_t size)
{
    struct zcl_dev_proof_remote_placement recheck = {0};
    if (!remote_workspace(a, owner, ctx, &recheck, why, size) ||
        strcmp(recheck.previous_head, out->previous_head) != 0 ||
        strcmp(recheck.common_git_dir, out->common_git_dir) != 0)
        return remote_refuse(why, size, "remote_destination_changed_before_import");
    if (!remote_import_checkout(a, bundle, out, why, size) ||
        !remote_clean(out->canonical_root, why, size) ||
        !remote_source(a, out->canonical_root, &out->source, why, size)) return false;
    if (!remote_workspace(a, owner, ctx, &recheck, why, size) ||
        strcmp(recheck.previous_head, a->expected.local_commit) != 0 ||
        strcmp(recheck.common_git_dir, out->common_git_dir) != 0)
        return remote_refuse(why, size, "remote_destination_changed_after_placement");
    memcpy(out->local_commit, a->expected.local_commit, strlen(a->expected.local_commit) + 1u);
    memcpy(out->remote_base, a->expected.remote_base, strlen(a->expected.remote_base) + 1u);
    if (why && size) why[0] = '\0';
    return true;
}
#endif

bool zcl_dev_proof_remote_prepare(
    const struct zcl_dev_proof_remote_assignment *assignment,
    zcl_dev_proof_remote_owner_check owner_check, void *owner_ctx,
    struct zcl_dev_proof_remote_placement *out, char *why, size_t why_len)
{
    if (!out) return remote_refuse(why, why_len, "remote_arguments_invalid");
    memset(out, 0, sizeof(*out));
#if defined(_WIN32)
    (void)assignment; (void)owner_check; (void)owner_ctx;
    return remote_refuse(why, why_len, "remote_placement_platform_unavailable");
#else
    if (!remote_host_admitted(why, why_len)) return false;
    if (!remote_assignment_valid(assignment))
        return remote_refuse(why, why_len, "remote_assignment_invalid");
    if (!remote_git_environment(why, why_len) ||
        !remote_workspace(assignment, owner_check, owner_ctx, out, why, why_len)) return false;
    int guard = -1;
    int acquired = zcl_dev_proof_execution_acquire(out->canonical_root, &guard,
                                                   why, why_len);
    if (acquired != 1) {
        if (acquired == 0) (void)remote_refuse(why, why_len, "remote_execution_busy");
        return false;
    }
    char bundle[4096];
    bool ok = remote_transport(assignment, out, bundle, why, why_len) &&
        remote_prepare_finish(assignment, bundle, owner_check, owner_ctx, out, why, why_len);
    zcl_dev_proof_execution_release(guard);
    return ok;
#endif
}

#if !defined(_WIN32)
static bool remote_execution_recheck(
    const struct zcl_dev_proof_remote_assignment *a,
    const struct zcl_dev_proof_remote_placement *observed,
    struct zcl_dev_proof_remote_placement *current, char *why, size_t size)
{
    if (strcmp(current->canonical_root, observed->canonical_root) != 0 ||
        strcmp(current->common_git_dir, observed->common_git_dir) != 0 ||
        strcmp(current->previous_head, a->expected.local_commit) != 0 ||
        strcmp(observed->local_commit, a->expected.local_commit) != 0 ||
        strcmp(observed->remote_base, a->expected.remote_base) != 0 ||
        strcmp(observed->git_tree, a->git_tree) != 0)
        return remote_refuse(why, size, "remote_placement_assignment_mismatch");
    if (!remote_pair_tree(a, current->canonical_root, current->git_tree, why, size) ||
        !remote_source(a, current->canonical_root, &current->source, why, size)) return false;
    if (strcmp(current->source.mutation_id, observed->source.mutation_id) != 0)
        return remote_refuse(why, size, "remote_local_mutation_changed");
    return true;
}

static int remote_settlement_recheck(
    const struct zcl_dev_proof_remote_assignment *assignment,
    const struct zcl_dev_proof_remote_placement *observed,
    zcl_dev_proof_remote_owner_check owner_check, void *owner_ctx,
    struct zcl_dev_proof_status *out, int result)
{
    if (out->state != ZCL_DEV_PROOF_STATE_PASSED) return result;
    /* The native receipt proves its generation, not the current destination.
     * Preserve that evidence while withholding remote PASS until recaptured. */
    out->state = ZCL_DEV_PROOF_STATE_NO_VERDICT;
    if (result <= 0) return result;
    int guard = -1;
    int acquired = zcl_dev_proof_execution_acquire(observed->canonical_root, &guard,
        out->detail, sizeof(out->detail));
    if (acquired != 1) {
        if (acquired == 0)
            (void)remote_refuse(out->detail, sizeof(out->detail), "remote_settlement_busy");
        return acquired == 0 ? 0 : -1;
    }
    struct zcl_dev_proof_remote_placement current = {0};
    bool checked = remote_git_environment(out->detail, sizeof(out->detail)) &&
        remote_workspace(assignment, owner_check, owner_ctx, &current,
            out->detail, sizeof(out->detail)) &&
        remote_execution_recheck(assignment, observed, &current,
            out->detail, sizeof(out->detail));
    zcl_dev_proof_execution_release(guard);
    if (!checked) return -1;
    out->state = ZCL_DEV_PROOF_STATE_PASSED;
    return result;
}
#endif

int zcl_dev_proof_remote_execute(
    const struct zcl_dev_proof_remote_assignment *assignment,
    const struct zcl_dev_proof_remote_placement *observed,
    zcl_dev_proof_remote_owner_check owner_check, void *owner_ctx,
    struct zcl_dev_proof_status *out)
{
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    out->state = ZCL_DEV_PROOF_STATE_NO_VERDICT;
#if defined(_WIN32)
    (void)assignment; (void)observed; (void)owner_check; (void)owner_ctx;
    (void)remote_refuse(out->detail, sizeof(out->detail), "remote_execution_platform_unavailable");
    return -1;
#else
    if (!remote_host_admitted(out->detail, sizeof(out->detail))) return -1;
    if (!observed || !observed->placed || !remote_assignment_valid(assignment)) {
        (void)remote_refuse(out->detail, sizeof(out->detail), "remote_placement_observation_invalid");
        return -1;
    }
    struct zcl_dev_proof_remote_placement current = {0};
    if (!remote_git_environment(out->detail, sizeof(out->detail)) ||
        !remote_workspace(assignment, owner_check, owner_ctx, &current,
                           out->detail, sizeof(out->detail))) return -1;
    int guard = -1;
    int acquired = zcl_dev_proof_execution_acquire(current.canonical_root, &guard,
        out->detail, sizeof(out->detail));
    if (acquired != 1) {
        if (acquired == 0)
            (void)remote_refuse(out->detail, sizeof(out->detail), "remote_execution_busy");
        return acquired == 0 ? 0 : -1;
    }
    bool checked = remote_workspace(assignment, owner_check, owner_ctx, &current,
        out->detail, sizeof(out->detail)) &&
        remote_execution_recheck(assignment, observed, &current,
                                  out->detail, sizeof(out->detail));
    /* step acquires this same guard and rechecks/seals its exact source.
     * Never nest the guard or treat this observation as future authority. */
    zcl_dev_proof_execution_release(guard);
    if (!checked) return -1;
    int result = zcl_dev_proof_step(current.canonical_root,
        assignment->expected.local_commit, assignment->expected.remote_base, out);
    return remote_settlement_recheck(assignment, observed, owner_check, owner_ctx,
        out, result);
#endif
}

/* Native policy retains its historical local-signer exception. This remote
 * return contract also binds a local return to the CURRENT requested build. */
static bool remote_local_identity(
    const struct zcl_dev_acceptance_receipt_v1 *receipt,
    zcl_dev_proof_host_toolchain_fn capture, void *ctx,
    char *why, size_t size)
{
    if (!zcl_dev_proof_receipt_signer_is_local(receipt)) return true;
    uint8_t roots[4][32];
    char cause[96] = "capture_failed";
    bool captured = capture(ctx, roots, cause, sizeof(cause));
    cause[sizeof(cause) - 1u] = '\0';
    if (!captured) {
        if (why && size) (void)snprintf(why, size,
            "remote_toolchain_unverifiable:%.95s", cause);
        return false;
    }
    const struct { const uint8_t *root; const char *name; } fields[] = {
        {receipt->compiler_root, "compiler_root"},
        {receipt->flags_root, "flags_root"},
        {receipt->environment_root, "environment_root"},
        {receipt->build_graph_root, "build_graph_root"},
    };
    for (size_t i = 0; i < 4u; i++) {
        if (memcmp(fields[i].root, roots[i], 32) == 0) continue;
        if (why && size) (void)snprintf(why, size,
            "remote_toolchain_mismatch:%s", fields[i].name);
        return false;
    }
    return true;
}

bool zcl_dev_proof_remote_verify(
    const uint8_t *wire, size_t wire_len,
    const struct zcl_dev_proof_remote_expectation *expected,
    zcl_dev_proof_host_toolchain_fn capture, void *capture_ctx,
    struct zcl_dev_acceptance_receipt_v1 *out,
    char *why, size_t why_len)
{
    if (!wire || !out || !capture || !remote_expectation_valid(expected))
        return remote_refuse(why, why_len, "remote_arguments_invalid");
    struct zcl_dev_acceptance_receipt_v1 receipt;
    if (!zcl_dev_proof_receipt_parse(wire, wire_len, &receipt))
        return remote_refuse(why, why_len, "remote_receipt_parse_failed");
    if (!zcl_dev_proof_receipt_admit(&receipt, expected->local_commit,
            expected->remote_base, capture, capture_ctx, why, why_len) ||
        !remote_local_identity(&receipt, capture, capture_ctx, why, why_len) ||
        !remote_bindings_match(&receipt, expected, why, why_len))
        return false;
    *out = receipt;
    if (why && why_len) why[0] = '\0';
    return true;
}
