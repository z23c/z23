/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: exercise real owned Git placement without manufacturing proof PASS. */
#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#endif
#include "test/test_core.h"
#include "dev_proof_remote.h"

#if !defined(_WIN32)
#include "base/hex.h"
#include "command/native_dev_land_remote_shared.h"
#include "crypto/sha3.h"
#include "util/file_io.h"
#include "util/compare.h"
#include "util/spawn.h"
#include <errno.h>
#include <sys/wait.h>

extern char **environ;

struct rpp_fixture {
    char root[512], sender[600], receiver[600], bundle[600], offer[600];
    char base[65], tip[65], refs[4096];
    struct zcl_dev_proof_remote_assignment assignment;
};

static bool rpp_path(char *out, size_t cap, const char *root, const char *leaf)
{
    int n = snprintf(out, cap, "%s/%s", root, leaf);
    return n > 0 && (size_t)n < cap;
}

static bool rpp_parents(const char *path)
{
    char parent[4096];
    if (snprintf(parent, sizeof(parent), "%s", path) >= (int)sizeof(parent)) return false;
    for (size_t i = 1; parent[i]; i++) {
        if (parent[i] != '/') continue;
        parent[i] = '\0';
        int rc = mkdir(parent, 0700);
        parent[i] = '/';
        if (rc != 0 && errno != EEXIST) return false;
    }
    return true;
}

static bool rpp_write(const char *root, const char *leaf, const void *body,
                      size_t size, mode_t mode)
{
    char path[4096];
    if (!rpp_path(path, sizeof(path), root, leaf) || !rpp_parents(path)) return false;
    FILE *file = fopen(path, "wb");
    if (!file) return false;
    bool ok = fwrite(body, 1, size, file) == size;
    return fclose(file) == 0 && ok && chmod(path, mode) == 0;
}

static bool rpp_text(const char *root, const char *leaf, const char *text)
{
    return rpp_write(root, leaf, text, strlen(text), 0644);
}

/* Native argv capture, including EOF and observed status; no transport stub. */
static bool rpp_git(const char *root, const char *const *args, char *out, size_t cap)
{
    const char *argv[32] = {"/usr/bin/git", "-C", root,
        "-c", "core.hooksPath=/dev/null", "-c", "user.name=Placement fixture",
        "-c", "user.email=placement@z23.invalid", "-c", "commit.gpgsign=false"};
    size_t used = 11;
    for (size_t i = 0; args[i]; i++) {
        if (used + 1 >= sizeof(argv) / sizeof(argv[0])) return false;
        argv[used++] = args[i];
    }
    argv[used] = NULL;
    char sink[8192];
    if (!out) { out = sink; cap = sizeof(sink); }
    if (!cap) return false;
    struct zcl_spawn_binary_observation observation = {0};
    (void)zcl_spawn_capture_binary(argv, out, cap - 1u, 60000, &observation);
    bool ok = observation.eof && observation.exit_observed &&
        observation.exit_code == 0 && !observation.overflow && !observation.timed_out;
    if (observation.output_len >= cap) return false;
    out[observation.output_len] = '\0';
    size_t n = observation.output_len;
    if (n && out[n - 1] == '\n') out[n - 1] = '\0';
    if (!ok) printf("placement Git %s failed: exit=%d output=%s\n",
        args[0], observation.exit_code, out);
    return ok;
}

#define RPP_GIT(root, out, cap, ...) \
    rpp_git(root, (const char *const[]){__VA_ARGS__, NULL}, out, cap)

static bool rpp_copy_source(const char *source, const char *destination, const char *leaf)
{
    char path[4096];
    uint8_t *bytes = NULL;
    size_t size = 0;
    struct stat st;
    bool ok = rpp_path(path, sizeof(path), source, leaf) && stat(path, &st) == 0 &&
        S_ISREG(st.st_mode) &&
        zcl_read_whole_file(path, 1024 * 1024, &bytes, &size, "placement-fixture-source");
    if (ok) ok = rpp_write(destination, leaf, bytes, size, st.st_mode & 0777);
    free(bytes);
    return ok;
}

/* Copy maintained capture code, never a script returning invented roots.
 * Its optional batch bootstrap may compile, so this entire group is admitted. */
static bool rpp_capture_sources(const char *source, const char *destination)
{
    static const char *const inputs[] = {
        "tools/dev/source-identity.sh", "tools/dev/source-identity-batch-bootstrap.sh",
        "tools/dev/source_identity_batch.c",
        "contexts/commons/packages/zsha256/src/zsha256.c",
        "contexts/commons/packages/zsha256/include/zsha256/zsha256.h",
        "platform/modules/base/src/safe_alloc.c",
        "platform/modules/base/include/base/safe_alloc.h",
        "platform/modules/base/include/base/hex.h",
    };
    for (size_t i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++)
        if (!rpp_copy_source(source, destination, inputs[i])) return false;
    return true;
}

static bool rpp_owner(void *ctx, const char *root, char *why, size_t cap)
{
    bool ok = ctx && strcmp(ctx, root) == 0;
    if (!ok && why && cap) (void)snprintf(why, cap, "fixture_owner_refused");
    return ok;
}

static bool rpp_offer(struct rpp_fixture *f)
{
    char text[1024];
    int n = snprintf(text, sizeof(text),
        "{\"schema\":\"zcl.dev_land_offer.v1\",\"commit\":\"%s\","
        "\"base\":\"%s\",\"bundle_sha256\":\"%s\",\"lane\":\"fixture\"}\n",
        f->tip, f->base, f->assignment.bundle_sha256);
    return n > 0 && (size_t)n < sizeof(text) &&
        rpp_write(f->root, "source.offer.json", text, (size_t)n, 0600);
}

static bool rpp_base(struct rpp_fixture *f, const char *source)
{
    return mkdir(f->sender, 0700) == 0 &&
        RPP_GIT(f->sender, NULL, 0, "init", "--quiet", "-b", "main") &&
        rpp_capture_sources(source, f->sender) &&
        rpp_text(f->sender, ".gitignore", "/build/\n/.cache/\n/.codeindex/\n/ignored.txt\n") &&
        rpp_text(f->sender, "core/placement.c", "int placement(void) { return 1; }\n") &&
        RPP_GIT(f->sender, NULL, 0, "add", ".") &&
        RPP_GIT(f->sender, NULL, 0, "commit", "--quiet", "-m", "base") &&
        RPP_GIT(f->sender, f->base, sizeof(f->base), "rev-parse", "HEAD") &&
        RPP_GIT(f->root, NULL, 0, "clone", "--quiet", "--no-local", f->sender, f->receiver);
}

static bool rpp_candidate(struct rpp_fixture *f)
{
    return rpp_text(f->sender, "core/placement.c", "int placement(void) { return 2; }\n") &&
        rpp_text(f->sender, "collision.txt", "offered collision\n") &&
        rpp_text(f->sender, "ignored.txt", "offered ignored\n") &&
        RPP_GIT(f->sender, NULL, 0, "add", "core/placement.c", "collision.txt") &&
        RPP_GIT(f->sender, NULL, 0, "add", "--force", "ignored.txt") &&
        RPP_GIT(f->sender, NULL, 0, "commit", "--quiet", "-m", "candidate") &&
        RPP_GIT(f->sender, f->tip, sizeof(f->tip), "rev-parse", "HEAD");
}

static void rpp_assignment(struct rpp_fixture *f)
{
    struct zcl_dev_proof_remote_assignment *a = &f->assignment;
    a->repository = f->receiver;
    a->destination = f->receiver;
    a->bundle = f->bundle;
    a->offer = f->offer;
    a->expected.local_commit = f->tip;
    a->expected.remote_base = f->base;
    /* Receipt-only pins are nonzero fixture inputs, not claimed attestations. */
    memset(a->expected.signer_pubkey, 1, 32);
    memset(a->expected.changed_set_root, 2, 32);
    memset(a->expected.impact_policy_root, 3, 32);
    struct sha3_256_ctx hash;
    static const char domain[] = "zcl.dev_proof_git_source.v1";
    sha3_256_init(&hash);
    sha3_256_write(&hash, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&hash, (const uint8_t *)f->tip, strlen(f->tip));
    sha3_256_finalize(&hash, a->expected.source_root);
}

static bool rpp_batch_state(const char *root, bool present)
{
    char path[1024];
    struct stat st;
    if (!rpp_path(path, sizeof(path), root, "build/bin/source-identity-batch")) return false;
    if (lstat(path, &st) != 0) return !present && errno == ENOENT;
    return present && S_ISREG(st.st_mode) && (st.st_mode & 0111) != 0;
}

static bool rpp_transport(struct rpp_fixture *f)
{
    struct zcl_dev_proof_remote_assignment *a = &f->assignment;
    struct dev_source_record captured = {0};
    char why[256] = {0}, range[140], head[65];
    if (!RPP_GIT(f->sender, a->git_tree, sizeof(a->git_tree), "rev-parse", "HEAD^{tree}") ||
        !zcl_dev_source_identity_capture(f->sender, &captured, why, sizeof(why)) ||
        !captured.cas_present ||
        !zcl_hex_decode_lower(captured.cas_root_sha3, a->expected.source_cas_root, 32)) {
        printf("placement source prerequisite failed: %s\n", why);
        return false;
    }
    /* This particular ordering oracle needs the real bootstrap to work. The
     * production fallback remains valid; silently using it here would make
     * the helper-before-CAS mutation indistinguishable from correct ordering. */
    if (!rpp_batch_state(f->sender, true) || !rpp_batch_state(f->receiver, false)) {
        printf("placement ordering prerequisite: maintained C23 batch bootstrap must produce its executable\n");
        return false;
    }
    memcpy(a->source_id, captured.source_id, sizeof(a->source_id));
    /* Bundle needs an advertised ref; a raw-OID endpoint produces no head. */
    int n = snprintf(range, sizeof(range), "%s..HEAD", f->base);
    return n > 0 && (size_t)n < sizeof(range) &&
        RPP_GIT(f->sender, head, sizeof(head), "rev-parse", "HEAD") && strcmp(head, f->tip) == 0 &&
        RPP_GIT(f->sender, NULL, 0, "bundle", "create", f->bundle, range) &&
        zcl_dlr_file_sha256(f->bundle, a->bundle_sha256) && rpp_offer(f) &&
        RPP_GIT(f->receiver, f->refs, sizeof(f->refs), "for-each-ref", "--format=%(refname) %(objectname)");
}

static bool rpp_setup(struct rpp_fixture *f, const char *source)
{
    memset(f, 0, sizeof(*f));
    test_make_tmpdir(f->root, sizeof(f->root), "dev_proof_remote_placement", "real-git");
    if (!rpp_path(f->sender, sizeof(f->sender), f->root, "sender") ||
        !rpp_path(f->receiver, sizeof(f->receiver), f->root, "receiver") ||
        !rpp_path(f->bundle, sizeof(f->bundle), f->root, "source.bundle") ||
        !rpp_path(f->offer, sizeof(f->offer), f->root, "source.offer.json") ||
        !rpp_base(f, source) || !rpp_candidate(f)) return false;
    rpp_assignment(f);
    return rpp_transport(f);
}

static bool rpp_directory_empty(const char *path)
{
    DIR *dir = opendir(path);
    if (!dir) return false;
    bool ok = true;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(dir);
        if (!entry) { if (errno) ok = false; break; }
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) { ok = false; break; }
    }
    return closedir(dir) == 0 && ok;
}

static bool rpp_transport_only(const char *path, const struct stat *st)
{
    if (!S_ISDIR(st->st_mode) || (st->st_mode & 0777) != 0700) return false;
    DIR *dir = opendir(path);
    if (!dir) return false;
    bool ok = true;
    while (ok) {
        errno = 0;
        struct dirent *entry = readdir(dir);
        if (!entry) { if (errno) ok = false; break; }
        const char *name = entry->d_name;
        if (!strcmp(name, ".") || !strcmp(name, "..")) continue;
        char file[1600];
        struct stat child;
        ok = (!strcmp(name, "source.bundle") || !strcmp(name, "source.offer.json")) &&
            rpp_path(file, sizeof(file), path, name) && lstat(file, &child) == 0 &&
            S_ISREG(child.st_mode) && (child.st_mode & 0777) == 0400;
    }
    return closedir(dir) == 0 && ok;
}

/* The native guard may create its lock and empty queue directories. Those
 * operational files are not proof evidence; no attempt/request/receipt is allowed. */
static bool rpp_guard_entry(const char *state, const char *name)
{
    char child[1200];
    struct stat st;
    if (!rpp_path(child, sizeof(child), state, name) || lstat(child, &st) != 0) return false;
    if (!strcmp(name, "execution.lock")) return S_ISREG(st.st_mode);
    if (!strcmp(name, "requests") || !strcmp(name, "attempts"))
        return S_ISDIR(st.st_mode) && rpp_directory_empty(child);
    static const char prefix[] = "remote-proof-inputs-";
    if (!strncmp(name, prefix, sizeof(prefix) - 1u) && name[sizeof(prefix) - 1u])
        return rpp_transport_only(child, &st);
    return false;
}

static bool rpp_no_proof(const struct rpp_fixture *f)
{
    char state[1024];
    struct stat st;
    if (!rpp_path(state, sizeof(state), f->receiver, ".cache/zcl-dev-proof")) return false;
    if (lstat(state, &st) != 0) return errno == ENOENT;
    if (!S_ISDIR(st.st_mode)) return false;
    DIR *dir = opendir(state);
    if (!dir) return false;
    bool ok = true;
    while (ok) {
        errno = 0;
        struct dirent *entry = readdir(dir);
        if (!entry) { if (errno) ok = false; break; }
        const char *name = entry->d_name;
        if (!strcmp(name, ".") || !strcmp(name, "..")) continue;
        ok = rpp_guard_entry(state, name);
    }
    return closedir(dir) == 0 && ok;
}

static bool rpp_refs_unchanged(const struct rpp_fixture *f, const char *head)
{
    char refs[4096], actual[65];
    return RPP_GIT(f->receiver, refs, sizeof(refs), "for-each-ref", "--format=%(refname) %(objectname)") &&
        strcmp(refs, f->refs) == 0 &&
        RPP_GIT(f->receiver, actual, sizeof(actual), "rev-parse", "HEAD") && strcmp(head, actual) == 0 &&
        rpp_no_proof(f);
}

static bool rpp_contents(const struct rpp_fixture *f, const char *leaf, const char *text)
{
    char path[1024];
    uint8_t *bytes = NULL;
    size_t size = 0;
    bool ok = rpp_path(path, sizeof(path), f->receiver, leaf) &&
        zcl_read_whole_file(path, 4096, &bytes, &size, "placement-fixture-check") &&
        size == strlen(text) && memcmp(bytes, text, size) == 0;
    free(bytes);
    return ok;
}

static bool rpp_retire(struct zcl_dev_proof_remote_placement *placed)
{
    return !placed->evidence_dir[0] || test_rm_rf_recursive(placed->evidence_dir) == 0;
}

static bool rpp_guard_available(const struct rpp_fixture *f)
{
    int guard = -1;
    char why[256] = {0};
    int acquired = zcl_dev_proof_execution_acquire(f->receiver, &guard, why, sizeof(why));
    zcl_dev_proof_execution_release(guard);
    if (acquired != 1) printf("placement leaked guard: %s\n", why);
    return acquired == 1 && rpp_no_proof(f);
}

static bool rpp_prepare_refusal(struct rpp_fixture *f,
    const struct zcl_dev_proof_remote_assignment *assignment,
    void *owner, const char *expected_why, bool imported, bool placed)
{
    struct zcl_dev_proof_remote_placement observed = {0};
    char why[256] = {0};
    bool accepted = zcl_dev_proof_remote_prepare(assignment, rpp_owner, owner,
        &observed, why, sizeof(why));
    bool ok = !accepted && strcmp(why, expected_why) == 0 &&
        observed.objects_imported == imported && observed.placed == placed &&
        rpp_refs_unchanged(f, placed ? f->tip : f->base);
    if (!ok) printf("placement refusal: expected=%s actual=%s accepted=%d import=%d placed=%d\n",
        expected_why, why, accepted, observed.objects_imported, observed.placed);
    if (!ok) {
        printf("placement input evidence retained: %s\n", observed.evidence_dir);
        return false;
    }
    bool released = strcmp(expected_why, "remote_execution_busy") == 0 || rpp_guard_available(f);
    return released && rpp_retire(&observed);
}

static bool rpp_prepare_busy(struct rpp_fixture *f)
{
    int guard = -1;
    char why[256] = {0};
    if (zcl_dev_proof_execution_acquire(f->receiver, &guard, why, sizeof(why)) != 1) return false;
    bool ok = rpp_prepare_refusal(f, &f->assignment, f->receiver,
        "remote_execution_busy", false, false) &&
        rpp_contents(f, "core/placement.c", "int placement(void) { return 1; }\n");
    zcl_dev_proof_execution_release(guard);
    return rpp_guard_available(f) && ok;
}

static bool rpp_remove(struct rpp_fixture *f, const char *leaf)
{
    char path[1024];
    return rpp_path(path, sizeof(path), f->receiver, leaf) && unlink(path) == 0;
}

static bool rpp_collision(struct rpp_fixture *f, const char *leaf, bool ignored)
{
    const char *text = "locally owned bytes\n";
    bool ok = rpp_text(f->receiver, leaf, text) &&
        rpp_prepare_refusal(f, &f->assignment, f->receiver,
            ignored ? "remote_detached_checkout_failed" : "remote_destination_dirty_or_unreadable",
            ignored, false) && rpp_contents(f, leaf, text) &&
        rpp_contents(f, "core/placement.c", "int placement(void) { return 1; }\n");
    return rpp_remove(f, leaf) && ok;
}

static bool rpp_dirty(struct rpp_fixture *f)
{
    if (!rpp_text(f->receiver, "core/placement.c", "dirty tracked bytes\n")) return false;
    bool ok = rpp_prepare_refusal(f, &f->assignment, f->receiver,
        "remote_destination_dirty_or_unreadable", false, false) &&
        rpp_contents(f, "core/placement.c", "dirty tracked bytes\n");
    return rpp_text(f->receiver, "core/placement.c", "int placement(void) { return 1; }\n") && ok;
}

static bool rpp_transport_refusals(struct rpp_fixture *f)
{
    char wrong_bundle[1024];
    struct zcl_dev_proof_remote_assignment changed = f->assignment;
    if (!rpp_text(f->root, "wrong.bundle", "not the offered Git bundle\n") ||
        !rpp_path(wrong_bundle, sizeof(wrong_bundle), f->root, "wrong.bundle")) return false;
    changed.bundle = wrong_bundle;
    if (!rpp_prepare_refusal(f, &changed, f->receiver,
        "remote_transport_bytes_mismatch", false, false)) return false;
    changed = f->assignment;
    if (!RPP_GIT(f->receiver, changed.git_tree, sizeof(changed.git_tree), "rev-parse", "HEAD^{tree}") ||
        !rpp_prepare_refusal(f, &changed, f->receiver, "remote_git_tree_mismatch", true, false)) return false;
    return true;
}

static bool rpp_source_refusals(struct rpp_fixture *f)
{
    struct zcl_dev_proof_remote_assignment changed = f->assignment;
    changed.expected.source_cas_root[0] ^= 1;
    if (!rpp_batch_state(f->receiver, false) ||
        !rpp_prepare_refusal(f, &changed, f->receiver, "remote_native_source_cas_mismatch", true, true) ||
        !rpp_batch_state(f->receiver, false) ||
        !RPP_GIT(f->receiver, NULL, 0, "checkout", "--quiet", "--detach", f->base)) return false;
    changed = f->assignment;
    changed.source_id[0] = changed.source_id[0] == '0' ? '1' : '0';
    return rpp_prepare_refusal(f, &changed, f->receiver,
        "remote_placed_source_identity_mismatch", true, true) &&
        RPP_GIT(f->receiver, NULL, 0, "checkout", "--quiet", "--detach", f->base);
}

static bool rpp_lazy_fetch_refused(struct rpp_fixture *f, const char *key, const char *value)
{
    if (!RPP_GIT(f->receiver, NULL, 0, "config", "--local", key, value)) return false;
    struct zcl_dev_proof_remote_placement observed = {0};
    char why[256] = {0};
    bool accepted = zcl_dev_proof_remote_prepare(&f->assignment, rpp_owner, f->receiver,
        &observed, why, sizeof(why));
    bool ok = !accepted && !strcmp(why, "remote_git_lazy_fetch_config") &&
        !observed.evidence_dir[0] && !observed.objects_imported && !observed.placed &&
        rpp_refs_unchanged(f, f->base) && rpp_guard_available(f);
    if (!ok) printf("placement lazy-fetch refusal %s: accepted=%d reason=%s\n", key, accepted, why);
    return RPP_GIT(f->receiver, NULL, 0, "config", "--local", "--unset-all", key) && ok;
}

static bool rpp_negative_prepare(struct rpp_fixture *f)
{
    return rpp_prepare_refusal(f, &f->assignment, NULL, "remote_destination_not_owned", false, false) &&
        rpp_lazy_fetch_refused(f, "extensions.partialClone", "origin") &&
        rpp_lazy_fetch_refused(f, "remote.origin.promisor", "true") &&
        rpp_prepare_busy(f) && rpp_collision(f, "collision.txt", false) && rpp_collision(f, "ignored.txt", true) &&
        rpp_dirty(f) && rpp_transport_refusals(f) && rpp_source_refusals(f);
}

static bool rpp_execute_refused(struct rpp_fixture *f,
    const struct zcl_dev_proof_remote_placement *observed, void *owner, const char *reason)
{
    struct zcl_dev_proof_status status = {0};
    int rc = zcl_dev_proof_remote_execute(&f->assignment, observed, rpp_owner, owner, &status);
    bool ok = rc == -1 && status.state == ZCL_DEV_PROOF_STATE_NO_VERDICT &&
        strcmp(status.detail, reason) == 0 && rpp_refs_unchanged(f, f->tip);
    if (!ok) printf("placement execute refusal: rc=%d detail=%s\n", rc, status.detail);
    return ok && rpp_guard_available(f);
}

static bool rpp_execute_busy(struct rpp_fixture *f,
    const struct zcl_dev_proof_remote_placement *observed)
{
    int guard = -1;
    char why[256] = {0};
    if (zcl_dev_proof_execution_acquire(f->receiver, &guard, why, sizeof(why)) != 1) return false;
    struct zcl_dev_proof_status status = {0};
    int rc = zcl_dev_proof_remote_execute(&f->assignment, observed, rpp_owner, f->receiver, &status);
    bool ok = rc == 0 && status.state == ZCL_DEV_PROOF_STATE_NO_VERDICT &&
        strcmp(status.detail, "remote_execution_busy") == 0 && rpp_refs_unchanged(f, f->tip);
    zcl_dev_proof_execution_release(guard);
    return rpp_guard_available(f) && ok;
}

static bool rpp_placed_identity(const struct rpp_fixture *f,
    const struct zcl_dev_proof_remote_placement *observed)
{
    uint8_t cas[32];
    return observed->objects_imported && observed->placed &&
        strcmp(observed->previous_head, f->base) == 0 &&
        strcmp(observed->local_commit, f->tip) == 0 &&
        strcmp(observed->remote_base, f->base) == 0 &&
        strcmp(observed->git_tree, f->assignment.git_tree) == 0 &&
        observed->source.cas_present &&
        strcmp(observed->source.source_id, f->assignment.source_id) == 0 &&
        zcl_hex_decode_lower(observed->source.cas_root_sha3, cas, 32) &&
        memcmp(cas, f->assignment.expected.source_cas_root, 32) == 0;
}

static bool rpp_placed_bytes(struct rpp_fixture *f)
{
    char branch[256];
    return rpp_refs_unchanged(f, f->tip) &&
        RPP_GIT(f->receiver, branch, sizeof(branch), "rev-parse", "--abbrev-ref", "HEAD") &&
        strcmp(branch, "HEAD") == 0 &&
        rpp_contents(f, "core/placement.c", "int placement(void) { return 2; }\n") &&
        rpp_contents(f, "collision.txt", "offered collision\n") &&
        rpp_contents(f, "ignored.txt", "offered ignored\n");
}

static bool rpp_execute_controls(struct rpp_fixture *f,
    const struct zcl_dev_proof_remote_placement *observed)
{
    if (!rpp_execute_refused(f, observed, NULL, "remote_destination_not_owned")) return false;
    if (!rpp_execute_busy(f, observed)) return false;
    struct zcl_dev_proof_remote_placement altered = *observed;
    altered.placed = false;
    if (!rpp_execute_refused(f, &altered, f->receiver, "remote_placement_observation_invalid")) return false;
    altered = *observed;
    altered.source.mutation_id[0] = altered.source.mutation_id[0] == '0' ? '1' : '0';
    return rpp_execute_refused(f, &altered, f->receiver, "remote_local_mutation_changed");
}

static bool rpp_retained_inputs(const struct rpp_fixture *f,
    const struct zcl_dev_proof_remote_placement *observed)
{
    char prefix[700], bundle[4096], sha[65];
    struct stat st;
    return rpp_path(prefix, sizeof(prefix), f->receiver, ".cache/zcl-dev-proof/remote-proof-inputs-") &&
        strncmp(observed->evidence_dir, prefix, strlen(prefix)) == 0 &&
        lstat(observed->evidence_dir, &st) == 0 && S_ISDIR(st.st_mode) &&
        (st.st_mode & 0777) == 0700 &&
        rpp_path(bundle, sizeof(bundle), observed->evidence_dir, "source.bundle") &&
        zcl_dlr_file_sha256(bundle, sha) && strcmp(sha, f->assignment.bundle_sha256) == 0;
}

static bool rpp_positive(struct rpp_fixture *f)
{
    struct zcl_dev_proof_remote_placement observed = {0};
    char why[256] = {0};
    bool ok = zcl_dev_proof_remote_prepare(&f->assignment, rpp_owner, f->receiver,
        &observed, why, sizeof(why));
    if (!ok) printf("real placement failed: %s\n", why);
    ok = ok && rpp_placed_identity(f, &observed) && rpp_placed_bytes(f) &&
        rpp_retained_inputs(f, &observed) &&
        rpp_execute_controls(f, &observed);
    if (!ok) {
        printf("placement input evidence retained: %s\n", observed.evidence_dir);
        return false;
    }
    return rpp_retire(&observed);
}

struct rpp_lazy_fixture {
    struct rpp_fixture fixture;
    char sentinel[1024], object[128];
    uint8_t *object_bytes;
    size_t object_size;
    mode_t object_mode;
};

/* Compare the entire private receiver, including refs, index, config and
 * objects. Only access/modify timestamps are omitted. Unexpected file kinds,
 * truncation or bounded-inventory overflow refuse the oracle. */
struct rpp_snapshot {
    struct sha3_256_ctx hash;
    size_t entries, bytes;
};

static bool rpp_snapshot_node(const char *path, struct rpp_snapshot *snapshot, unsigned depth);

static bool rpp_snapshot_children(const char *path, struct rpp_snapshot *snapshot, unsigned depth)
{
    char storage[128][256], *names[128];
    size_t count = 0;
    DIR *dir = opendir(path);
    if (!dir) return false;
    bool ok = true;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(dir);
        if (!entry) { if (errno) ok = false; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (count == 128 || strlen(entry->d_name) >= sizeof(storage[0])) { ok = false; break; }
        names[count] = storage[count];
        memcpy(names[count++], entry->d_name, strlen(entry->d_name) + 1u);
    }
    if (closedir(dir) != 0) ok = false;
    qsort(names, count, sizeof(names[0]), zcl_cmp_cstr);
    for (size_t i = 0; ok && i < count; i++) {
        char child[4096];
        ok = rpp_path(child, sizeof(child), path, names[i]) &&
            rpp_snapshot_node(child, snapshot, depth + 1u);
    }
    return ok;
}

static bool rpp_snapshot_node(const char *path, struct rpp_snapshot *snapshot, unsigned depth)
{
    struct stat st;
    char metadata[96];
    if (depth > 24 || ++snapshot->entries > 2048 || lstat(path, &st) != 0) return false;
    if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode)) return false;
    int n = snprintf(metadata, sizeof(metadata), "%o %llu",
        (unsigned)(st.st_mode & 0177777), (unsigned long long)(S_ISREG(st.st_mode) ? st.st_size : 0));
    if (n < 0 || (size_t)n >= sizeof(metadata)) return false;
    sha3_256_write(&snapshot->hash, (const uint8_t *)path, strlen(path) + 1u);
    sha3_256_write(&snapshot->hash, (const uint8_t *)metadata, (size_t)n + 1u);
    if (S_ISDIR(st.st_mode)) return rpp_snapshot_children(path, snapshot, depth);
    uint8_t *bytes = NULL;
    size_t size = 0;
    bool ok = zcl_read_whole_file(path, 1024 * 1024, &bytes, &size, "placement-lazy-snapshot");
    if (ok) {
        snapshot->bytes += size;
        ok = snapshot->bytes <= 16 * 1024 * 1024;
        if (ok) sha3_256_write(&snapshot->hash, bytes, size);
    }
    free(bytes);
    return ok;
}

static bool rpp_snapshot_root(const char *root, uint8_t out[32])
{
    struct rpp_snapshot snapshot = {0};
    sha3_256_init(&snapshot.hash);
    if (!rpp_snapshot_node(root, &snapshot, 0)) return false;
    sha3_256_finalize(&snapshot.hash, out);
    return true;
}

static bool rpp_sentinel(const struct rpp_lazy_fixture *lazy, bool present)
{
    struct stat st;
    if (lstat(lazy->sentinel, &st) != 0) return !present && errno == ENOENT;
    return present && S_ISREG(st.st_mode) && st.st_size == 0;
}

/* git-remote-ext uses percent quoting, not shell quoting. Keep the only
 * transport local: touch creates the sentinel and speaks no Git protocol. */
static bool rpp_sentinel_url(const char *marker, char *out, size_t cap)
{
    const char *prefix = "ext::/usr/bin/touch ";
    size_t used = strlen(prefix);
    if (used >= cap) return false;
    memcpy(out, prefix, used);
    for (size_t i = 0; marker[i]; i++) {
        if (used + 3u >= cap) return false;
        if (marker[i] == '%' || marker[i] == ' ') out[used++] = '%';
        if (marker[i] == '\n' || marker[i] == '\r') return false;
        out[used++] = marker[i];
    }
    out[used] = '\0';
    return true;
}

static bool rpp_lazy_object(struct rpp_lazy_fixture *lazy)
{
    char tree[65], path[1024];
    struct stat st;
    struct rpp_fixture *f = &lazy->fixture;
    if (!RPP_GIT(f->receiver, tree, sizeof(tree), "rev-parse", "HEAD^{tree}") || strlen(tree) != 40)
        return false;
    int n = snprintf(lazy->object, sizeof(lazy->object), ".git/objects/%.2s/%s", tree, tree + 2);
    if (n < 0 || (size_t)n >= sizeof(lazy->object) ||
        !rpp_path(path, sizeof(path), f->receiver, lazy->object) || lstat(path, &st) != 0 ||
        !S_ISREG(st.st_mode) || st.st_nlink != 1) return false;
    lazy->object_mode = st.st_mode & 0777;
    return zcl_read_whole_file(path, 1024 * 1024, &lazy->object_bytes, &lazy->object_size,
        "placement-lazy-loose-tree") &&
        rpp_write(f->root, "lazy-tree.saved", lazy->object_bytes, lazy->object_size, 0600);
}

static bool rpp_lazy_setup(struct rpp_lazy_fixture *lazy, const struct rpp_fixture *original)
{
    lazy->fixture = *original;
    struct rpp_fixture *f = &lazy->fixture;
    char url[2400];
    if (!rpp_path(f->receiver, sizeof(f->receiver), f->root, "lazy-receiver") ||
        !rpp_path(lazy->sentinel, sizeof(lazy->sentinel), f->root, "lazy-fetch-contacted") ||
        !rpp_sentinel_url(lazy->sentinel, url, sizeof(url))) return false;
    f->assignment.repository = f->receiver;
    f->assignment.destination = f->receiver;
    if (!RPP_GIT(f->root, NULL, 0, "clone", "--quiet", "--local", "--no-hardlinks", f->sender, f->receiver) ||
        !RPP_GIT(f->receiver, NULL, 0, "checkout", "--quiet", "--detach", f->base) ||
        !RPP_GIT(f->receiver, f->refs, sizeof(f->refs), "for-each-ref", "--format=%(refname) %(objectname)"))
        return false;
    return RPP_GIT(f->receiver, NULL, 0, "config", "core.repositoryformatversion", "1") &&
        RPP_GIT(f->receiver, NULL, 0, "config", "protocol.ext.allow", "always") &&
        RPP_GIT(f->receiver, NULL, 0, "config", "remote.sentinel.url", url) && rpp_lazy_object(lazy);
}

static bool rpp_lazy_prepare_refused(struct rpp_lazy_fixture *lazy)
{
    struct rpp_fixture *f = &lazy->fixture;
    uint8_t before[32], after[32];
    if (!rpp_sentinel(lazy, false) || !rpp_snapshot_root(f->receiver, before)) return false;
    struct zcl_dev_proof_remote_placement observed = {0};
    char why[256] = {0};
    bool accepted = zcl_dev_proof_remote_prepare(&f->assignment, rpp_owner, f->receiver,
        &observed, why, sizeof(why));
    bool ok = !accepted && !strcmp(why, "remote_git_lazy_fetch_config") &&
        !observed.objects_imported && !observed.placed && !observed.evidence_dir[0];
    ok = ok && rpp_sentinel(lazy, false) && rpp_snapshot_root(f->receiver, after) &&
        memcmp(before, after, sizeof(before)) == 0;
    if (!ok) printf("missing-object prepare: accepted=%d reason=%s\n", accepted, why);
    return ok;
}

static bool rpp_lazy_case(struct rpp_lazy_fixture *lazy, const char *key, const char *value)
{
    struct rpp_fixture *f = &lazy->fixture;
    char config[1024];
    uint8_t *bytes = NULL;
    size_t size = 0;
    struct stat config_stat;
    if (!rpp_path(config, sizeof(config), f->receiver, ".git/config") ||
        lstat(config, &config_stat) != 0 || !S_ISREG(config_stat.st_mode) ||
        !zcl_read_whole_file(config, 16384, &bytes, &size, "placement-lazy-config")) return false;
    bool ok = RPP_GIT(f->receiver, NULL, 0, "config", "--local", key, value) &&
        rpp_sentinel(lazy, false) && rpp_remove(f, lazy->object);
    if (ok) {
        bool status_ok = RPP_GIT(f->receiver, NULL, 0, "status", "--porcelain=v1", "--untracked-files=all");
        ok = !status_ok && rpp_sentinel(lazy, true);
        printf("missing-object status transport control %s: %s\n", key, ok ? "OBSERVED" : "FAIL");
    }
    if (ok) ok = unlink(lazy->sentinel) == 0 && rpp_lazy_prepare_refused(lazy);
    /* Always repair the deliberately removed private object/config, even if
     * an oracle fails. No original sender object is shared or removed. */
    bool object_restored = rpp_write(f->receiver, lazy->object, lazy->object_bytes,
        lazy->object_size, lazy->object_mode);
    bool config_restored = rpp_write(f->receiver, ".git/config", bytes, size, config_stat.st_mode & 0777);
    free(bytes);
    return object_restored && config_restored && ok;
}

static bool rpp_missing_object_controls(struct rpp_fixture *original)
{
    struct rpp_lazy_fixture lazy = {0};
    bool ok = rpp_lazy_setup(&lazy, original);
    if (ok) ok = rpp_lazy_case(&lazy, "extensions.partialClone", "sentinel") &&
        rpp_lazy_case(&lazy, "remote.sentinel.promisor", "true");
    if (ok) ok = RPP_GIT(lazy.fixture.receiver, NULL, 0, "remote", "remove", "sentinel") &&
        RPP_GIT(lazy.fixture.receiver, NULL, 0, "config", "--unset", "protocol.ext.allow") &&
        rpp_sentinel(&lazy, false) && rpp_positive(&lazy.fixture);
    if (!ok) printf("missing-object fixture retained: %s\n", lazy.fixture.receiver);
    free(lazy.object_bytes);
    return ok;
}

/* A fork confines environment qualification to the fixture process. Never set
 * DEVBUILD_ACTIVE: it must be inherited from the admitted registered runner. */
static bool rpp_redirected_environment(const char *entry)
{
    static const char *const prefixes[] = {
        "GIT_", "LD_", "DYLD_", "BASH_ENV=", "ENV=", "ZCL_SOURCE_IDENTITY_",
        "ZCL_SOVEREIGN_SOURCE_ROOT=", "ZCL_BIN_DIR=",
    };
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++)
        if (strncmp(entry, prefixes[i], strlen(prefixes[i])) == 0) return true;
    return false;
}

static bool rpp_environment(const char *root)
{
    for (size_t i = 0; environ[i];) {
        const char *entry = environ[i];
        if (!rpp_redirected_environment(entry)) {
            i++;
            continue;
        }
        char name[256];
        const char *eq = strchr(entry, '=');
        if (!eq || (size_t)(eq - entry) >= sizeof(name)) return false;
        memcpy(name, entry, (size_t)(eq - entry));
        name[eq - entry] = '\0';
        if (unsetenv(name) != 0) return false;
    }
    return setenv("PATH", "/usr/bin:/bin", 1) == 0 &&
        setenv("HOME", root, 1) == 0 && setenv("XDG_CONFIG_HOME", root, 1) == 0 &&
        setenv("XDG_STATE_HOME", root, 1) == 0 && setenv("XDG_CACHE_HOME", root, 1) == 0;
}

static int rpp_child(const char *source)
{
    struct rpp_fixture fixture = {0};
    /* Private environment root is a native harness fixture, not a worktree. */
    char home[512];
    test_make_tmpdir(home, sizeof(home), "dev_proof_remote_placement", "environment");
    /* Only this fork-isolated fixture may execute the real source helper. */
    bool ok = rpp_environment(home) &&
        setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1) == 0 && rpp_setup(&fixture, source);
    if (ok) ok = rpp_missing_object_controls(&fixture) &&
        rpp_negative_prepare(&fixture) && rpp_positive(&fixture);
    if (!ok) printf("real placement fixture retained: %s\n", fixture.root);
    else ok = test_rm_rf_recursive(fixture.root) == 0;
    if (test_rm_rf_recursive(home) != 0) ok = false;
    return ok ? 0 : 1;
}
#endif

int test_dev_proof_remote_placement(void)
{
#if defined(_WIN32)
    printf("dev_proof_remote_placement: unsupported (POSIX owned Git placement)\n");
    return 2;
#else
    const char *admitted = getenv("DEVBUILD_ACTIVE");
    if (!admitted || strcmp(admitted, "z23") != 0) {
        printf("dev_proof_remote_placement: requires admitted registered runner\n");
        return 1;
    }
    char source[4096];
    if (!getcwd(source, sizeof(source))) return 1;
    fflush(NULL);
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        int rc = rpp_child(source);
        fflush(NULL);
        _exit(rc);
    }
    int status = 0;
    pid_t waited;
    do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    bool ok = waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    printf("dev_proof_remote_placement: real bundle/checkout/source controls %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
#endif
}
