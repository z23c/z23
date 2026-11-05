/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Shared isolated Git offer and native source identity fixture. */
#ifndef ZCL_TEST_DEV_PROOF_REMOTE_FIXTURE_H
#define ZCL_TEST_DEV_PROOF_REMOTE_FIXTURE_H
#include "test/test_core.h"
#include "dev_proof_remote.h"
#include "base/hex.h"
#include "command/native_dev_land_remote_shared.h"
#include "crypto/sha3.h"
#include "util/file_io.h"
#include "util/spawn.h"
#include <errno.h>
#include <sys/wait.h>
struct rpp_fixture {
    char root[512], sender[600], receiver[600], bundle[600], offer[600];
    char base[65], tip[65], refs[4096];
    struct zcl_dev_proof_remote_assignment assignment;
};

static inline bool rpp_path(char *out, size_t cap, const char *root, const char *leaf)
{
    int n = snprintf(out, cap, "%s/%s", root, leaf);
    return n > 0 && (size_t)n < cap;
}

static inline bool rpp_parents(const char *path)
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

static inline bool rpp_write(const char *root, const char *leaf, const void *body,
                      size_t size, mode_t mode)
{
    char path[4096];
    if (!rpp_path(path, sizeof(path), root, leaf) || !rpp_parents(path)) return false;
    FILE *file = fopen(path, "wb");
    if (!file) return false;
    bool ok = fwrite(body, 1, size, file) == size;
    return fclose(file) == 0 && ok && chmod(path, mode) == 0;
}

static inline bool rpp_text(const char *root, const char *leaf, const char *text)
{
    return rpp_write(root, leaf, text, strlen(text), 0644);
}

/* Native argv capture, including EOF and observed status; no transport stub. */
static inline bool rpp_git(const char *root, const char *const *args, char *out, size_t cap)
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

static inline bool rpp_copy_source(const char *source, const char *destination, const char *leaf)
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
static inline bool rpp_capture_sources(const char *source, const char *destination)
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

static inline bool rpp_owner(void *ctx, const char *root, char *why, size_t cap)
{
    bool ok = ctx && strcmp(ctx, root) == 0;
    if (!ok && why && cap) (void)snprintf(why, cap, "fixture_owner_refused");
    return ok;
}

static inline bool rpp_offer(struct rpp_fixture *f)
{
    char text[1024];
    int n = snprintf(text, sizeof(text),
        "{\"schema\":\"zcl.dev_land_offer.v1\",\"commit\":\"%s\","
        "\"base\":\"%s\",\"bundle_sha256\":\"%s\",\"lane\":\"fixture\"}\n",
        f->tip, f->base, f->assignment.bundle_sha256);
    return n > 0 && (size_t)n < sizeof(text) &&
        rpp_write(f->root, "source.offer.json", text, (size_t)n, 0600);
}

static inline bool rpp_base(struct rpp_fixture *f, const char *source)
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

static inline bool rpp_candidate(struct rpp_fixture *f)
{
    return rpp_text(f->sender, "core/placement.c", "int placement(void) { return 2; }\n") &&
        rpp_text(f->sender, "collision.txt", "offered collision\n") &&
        rpp_text(f->sender, "ignored.txt", "offered ignored\n") &&
        RPP_GIT(f->sender, NULL, 0, "add", "core/placement.c", "collision.txt") &&
        RPP_GIT(f->sender, NULL, 0, "add", "--force", "ignored.txt") &&
        RPP_GIT(f->sender, NULL, 0, "commit", "--quiet", "-m", "candidate") &&
        RPP_GIT(f->sender, f->tip, sizeof(f->tip), "rev-parse", "HEAD");
}

static inline void rpp_assignment(struct rpp_fixture *f)
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

static inline bool rpp_batch_state(const char *root, bool present)
{
    char path[1024];
    struct stat st;
    if (!rpp_path(path, sizeof(path), root, "build/bin/source-identity-batch")) return false;
    if (lstat(path, &st) != 0) return !present && errno == ENOENT;
    return present && S_ISREG(st.st_mode) && (st.st_mode & 0111) != 0;
}

static inline bool rpp_transport(struct rpp_fixture *f)
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

static inline bool rpp_setup(struct rpp_fixture *f, const char *source)
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

#endif
