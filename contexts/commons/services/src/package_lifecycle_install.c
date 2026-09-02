/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_lifecycle_install — the WRITE adapter of the ZCODE install
 * lifecycle: spawn the confined build worker, re-hash everything it emitted,
 * install atomically, append the generation log, swap the active pointer,
 * and pin.
 *
 * The node NEVER compiles anything and NEVER loads a package's output. The
 * only compilation is inside the fixed package verifier --emit; the
 * only thing that crosses back is bytes on disk, and every one of those bytes
 * is re-hashed here against the worker's own receipt before it is installed.
 * There is no dlopen anywhere in this file by design. */

/* realpath() reaches this TU only through the glibc fortify inline that
 * -D_FORTIFY_SOURCE=2 pulls in at -O1 and above; the build's
 * -D_POSIX_C_SOURCE=200809L declares it nowhere. Without this the file
 * compiles by accident of optimisation and breaks at -O0, under
 * -U_FORTIFY_SOURCE, and on any non-glibc libc. It must precede every
 * include: after them it does nothing. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "package_lifecycle_internal.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/result.h"
#include "base/safe_alloc.h"
#include "crypto/sha3.h"
#include "platform/os_proc.h"
#include "util/spawn.h"
#include "vcs/package_store.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef _WIN32
#include <io.h>
#endif

#define PKGL_DEV_WORKER_NAME "zclassic23-package-verify-dev"
#define PKGL_RELEASE_WORKER_NAME "zclassic23-package-verify"

/* ── worker discovery ───────────────────────────────────────────────── */

/* The worker ships beside whatever binary is running. Resolving it from
 * /proc/self/exe — never from PATH — means a PATH entry can never substitute
 * a different program into the only place that compiles. The one fallback is
 * the build tree's own build/bin, because the fast-test lane runs its binary
 * out of a per-epoch subdirectory; it is still a fixed relative path, not a
 * search. */
struct zcl_result pkgl_worker_path(char *out, size_t cap)
{
    char exe[PKGL_PATH_MAX];
    if (!os_proc_exe_path(exe, sizeof(exe)))
        return ZCL_ERR(-1, "cannot resolve own executable path");
    char *deleted = strstr(exe, " (deleted)");
    if (deleted)
        *deleted = '\0';
    char *slash = strrchr(exe, '/');
    if (!slash)
        return ZCL_ERR(-1, "resolved executable path has no directory component");
    *slash = '\0';
    bool present = false;
    const char *names[] = {
        PKGL_DEV_WORKER_NAME,
        PKGL_RELEASE_WORKER_NAME,
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        int w = snprintf(out, cap, "%s/%s", exe, names[i]);
        if (w <= 0 || (size_t)w >= cap)
            return ZCL_ERR(-1, "worker path too long");
        ZCL_CHECK(pkgl_exists(out, &present));
        if (present)
            return ZCL_OK;
    }
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        int w = snprintf(out, cap, "build/bin/%s", names[i]);
        if (w <= 0 || (size_t)w >= cap)
            return ZCL_ERR(-1, "worker path too long");
        ZCL_CHECK(pkgl_exists(out, &present));
        if (present)
            return ZCL_OK;
    }
    return ZCL_ERR(-1,
                   "the fixed development or release package verifier is "
                   "neither next to this binary nor in build/bin — build "
                   "the development helper (make dev-bin) before "
                   "installing packages");
}

/* ── streaming copy that hashes what it wrote ───────────────────────── */

static struct zcl_result pkgl_copy_hashed(const char *src, const char *dst,
                                          uint8_t out32[32],
                                          uint64_t *bytes_out)
{
    char parent[PKGL_PATH_MAX];
    int n = snprintf(parent, sizeof(parent), "%s", dst);
    if (n <= 0 || (size_t)n >= sizeof(parent))
        return ZCL_ERR(-1, "install path too long");
    char *slash = strrchr(parent, '/');
    if (slash) {
        *slash = '\0';
        ZCL_CHECK(pkgl_mkdir_p(parent));
    }
    FILE *in = fopen(src, "rb");
    if (!in)
        return ZCL_ERR(-1, "fopen %s: %s", src, strerror(errno));
    FILE *outf = fopen(dst, "wb");
    if (!outf) {
        fclose(in);
        return ZCL_ERR(-1, "fopen %s: %s", dst, strerror(errno));
    }
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    uint8_t buf[65536];
    uint64_t total = 0;
    size_t got;
    bool bad = false;
    while ((got = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, got, outf) != got) {
            bad = true;
            break;
        }
        sha3_256_write(&ctx, buf, got);
        total += got;
    }
    if (ferror(in))
        bad = true;
    fclose(in);
    if (fflush(outf) != 0
#ifdef _WIN32
        || _commit(_fileno(outf)) != 0
#else
        || fsync(fileno(outf)) != 0
#endif
    )
        bad = true;
    if (fclose(outf) != 0)
        bad = true;
    if (bad)
        return ZCL_ERR(-1, "copy %s -> %s failed: %s", src, dst,
                       strerror(errno));
    sha3_256_finalize(&ctx, out32);
    *bytes_out = total;
    return ZCL_OK;
}

/* An output whose receipt path is under bin/ is the PROGRAM a person runs,
 * so it is staged — and therefore installed, the stage is renamed into
 * place — with the executable bit set. Everything else (the static archive,
 * the public headers) is data and stays 0644. The mode is deliberately NOT
 * a receipt field: the receipt commits BYTES, and two verifiers under
 * different umasks must still agree on every hash, so the permission is
 * decided here, by the layer that owns the install layout, from the path
 * the receipt already commits. On Windows there is no executable bit — the
 * file extension decides — so there is nothing to set. */
static struct zcl_result pkgl_apply_output_mode(const char *path,
                                                const char *rel)
{
#ifdef _WIN32
    (void)path;
    (void)rel;
#else
    mode_t mode = strncmp(rel, "bin/", 4) == 0 ? (mode_t)0755 : (mode_t)0644;
    if (chmod(path, mode) != 0)
        return ZCL_ERR(-1, "chmod %o %s: %s", (unsigned)mode, path,
                       strerror(errno));
#endif
    return ZCL_OK;
}

/* ── the receipt cross-check ────────────────────────────────────────── */

static struct zcl_result pkgl_receipt_inputs_match(
    const struct vcs_package_build_receipt *receipt,
    const uint8_t root[32], const struct vcs_package_release *release,
    const uint8_t (*dep_roots)[32], size_t dep_count)
{
    if (memcmp(receipt->package_root, root, 32) != 0)
        return ZCL_ERR(-1, "receipt names a different package root");
    if (memcmp(receipt->recipe_root, release->recipe_root, 32) != 0)
        return ZCL_ERR(-1, "receipt names a different recipe root");
    if (receipt->dep_count != dep_count)
        return ZCL_ERR(-1, "receipt lists %zu dependencies, package has %zu",
                       receipt->dep_count, dep_count);
    for (size_t i = 0; i < dep_count; i++) {
        bool found = false;
        for (size_t j = 0; j < receipt->dep_count && !found; j++)
            found = memcmp(receipt->dep_roots[j], dep_roots[i], 32) == 0;
        if (!found)
            return ZCL_ERR(-1, "receipt omits an exact dependency root");
    }
    return ZCL_OK;
}

static struct zcl_result pkgl_receipt_matches(
    const struct vcs_package_build_receipt *receipt,
    const uint8_t root[32], const struct vcs_package_release *release,
    const uint8_t lock_root[32], const uint8_t (*dep_roots)[32],
    size_t dep_count)
{
    ZCL_CHECK(pkgl_receipt_inputs_match(receipt, root, release, dep_roots,
                                        dep_count));
    if (memcmp(receipt->lock_root, lock_root, 32) != 0)
        return ZCL_ERR(-1, "receipt names a different dependency lock");
    return ZCL_OK;
}

static struct zcl_result pkgl_installed_outputs_match(
    const char *installed, const struct vcs_package_build_receipt *receipt)
{
    for (size_t i = 0; i < receipt->output_count; i++) {
        const struct vcs_package_build_output *output = &receipt->outputs[i];
        char path[PKGL_PATH_MAX];
        int n = snprintf(path, sizeof(path), "%s/%s", installed,
                         output->path);
        if (n <= 0 || (size_t)n >= sizeof(path))
            return ZCL_ERR(-1, "installed output path is too long");
        uint8_t digest[32];
        uint64_t bytes = 0;
        ZCL_CHECK(pkgl_sha3_file(path, digest, &bytes));
        if (bytes != output->bytes || memcmp(digest, output->sha3, 32) != 0)
            return ZCL_ERR(-1, "installed output %s does not match receipt",
                           output->path);
    }
    return ZCL_OK;
}

struct zcl_result pkgl_verify_installed_receipt(
    const struct pkgl_ctx *ctx, const uint8_t root[32],
    const struct vcs_package_release *release, const uint8_t lock_root[32],
    const uint8_t (*dep_roots)[32], size_t dep_count,
    struct package_lifecycle_step *step)
{
    if (!ctx || !root || !release || !lock_root || !step)
        return ZCL_ERR(-1, "null argument verifying installed evidence");
    char installed[PKGL_PATH_MAX];
    ZCL_CHECK(pkgl_installed_dir(ctx, root, installed, sizeof(installed)));
    char report[PKGL_PATH_MAX];
    int n = snprintf(report, sizeof(report), "%s/build-report", installed);
    if (n <= 0 || (size_t)n >= sizeof(report))
        return ZCL_ERR(-1, "installed receipt path is too long");
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    ZCL_CHECK(pkgl_read_file(report, VCS_PACKAGE_BUILD_MAX_WIRE_BYTES,
                             &wire, &wire_len));
    struct vcs_package_build_receipt receipt;
    enum vcs_package_build_error parsed =
        vcs_package_build_parse(wire, wire_len, &receipt);
    if (parsed != VCS_PACKAGE_BUILD_OK) {
        free(wire);
        return ZCL_ERR(-1, "installed receipt: %s",
                       vcs_package_build_error_string(parsed));
    }
    struct zcl_result matched = pkgl_receipt_inputs_match(
        &receipt, root, release, dep_roots, dep_count);
    if (!matched.ok || !vcs_package_build_installable(&receipt)) {
        free(wire);
        return matched.ok ? ZCL_ERR(-1, "installed receipt is not installable")
                          : matched;
    }
    uint8_t receipt_id[32];
    if (vcs_package_build_id(&receipt, receipt_id) != VCS_PACKAGE_BUILD_OK) {
        free(wire);
        return ZCL_ERR(-1, "installed receipt id cannot be rederived");
    }
    char id_hex[65], filed[PKGL_PATH_MAX];
    zcl_hex_encode(receipt_id, 32, id_hex);
    char relative[96];
    n = snprintf(relative, sizeof(relative), "receipts/%s", id_hex);
    struct zcl_result joined = n > 0 && (size_t)n < sizeof(relative)
        ? pkgl_join(ctx, relative, filed, sizeof(filed))
        : ZCL_ERR(-1, "filed receipt path is too long");
    uint8_t *filed_wire = NULL;
    size_t filed_len = 0;
    if (joined.ok)
        joined = pkgl_read_file(filed, VCS_PACKAGE_BUILD_MAX_WIRE_BYTES,
                                &filed_wire, &filed_len);
    bool filed_equal = joined.ok && filed_len == wire_len &&
        memcmp(filed_wire, wire, wire_len) == 0;
    free(filed_wire);
    free(wire);
    if (!filed_equal)
        return joined.ok ? ZCL_ERR(-1, "filed receipt bytes do not match install")
                         : joined;
    ZCL_CHECK(pkgl_installed_outputs_match(installed, &receipt));
    step->has_receipt = true;
    step->receipt_reused = memcmp(receipt.lock_root, lock_root, 32) == 0;
    memcpy(step->receipt_id, receipt_id, 32);
    return ZCL_OK;
}

static void pkgl_step_fail(struct package_lifecycle_step *step,
                           const char *rule, const char *detail)
{
    if (!step)
        return;
    (void)snprintf(step->rule, sizeof(step->rule), "%s", rule);
    (void)snprintf(step->detail, sizeof(step->detail), "%.191s", detail);
}

/* ── build + install one root ───────────────────────────────────────── */

struct pkgl_build_paths {
    char worker[PKGL_PATH_MAX];
    char emit[PKGL_PATH_MAX];
    char stage[PKGL_PATH_MAX];
    char final[PKGL_PATH_MAX];
};

static struct zcl_result pkgl_build_paths_init(const struct pkgl_ctx *ctx,
                                               const uint8_t root[32],
                                               struct pkgl_build_paths *p)
{
    char hex[65];
    zcl_hex_encode(root, 32, hex);
    char rel[128];
    ZCL_CHECK(pkgl_worker_path(p->worker, sizeof(p->worker)));
    (void)snprintf(rel, sizeof(rel), "buildwork/%s", hex);
    ZCL_CHECK(pkgl_join(ctx, rel, p->emit, sizeof(p->emit)));
    (void)snprintf(rel, sizeof(rel), "installed/.stage-%s", hex);
    ZCL_CHECK(pkgl_join(ctx, rel, p->stage, sizeof(p->stage)));
    ZCL_CHECK(pkgl_installed_dir(ctx, root, p->final, sizeof(p->final)));
    return ZCL_OK;
}

/* Spawn the worker over one package root. Returns non-ok when the worker
 * could not be run or reported a non-zero verdict. */
static struct zcl_result pkgl_run_worker(const struct pkgl_ctx *ctx,
                                         const struct pkgl_build_paths *p,
                                         const uint8_t root[32],
                                         const uint8_t lock_root[32],
                                         const uint8_t (*dep_roots)[32],
                                         size_t dep_count)
{
    if (dep_count > VCS_PACKAGE_BUILD_MAX_DEPS)
        return ZCL_ERR(-1, "%zu dependencies exceeds the worker bound",
                       dep_count);
    char root_hex[65];
    zcl_hex_encode(root, 32, root_hex);
    char lock_hex[65];
    zcl_hex_encode(lock_root, 32, lock_hex);
    char store_arg[PKGL_PATH_MAX + 16];
    (void)snprintf(store_arg, sizeof(store_arg), "--store=%s", ctx->zcode_dir);
    char emit_arg[PKGL_PATH_MAX + 16];
    (void)snprintf(emit_arg, sizeof(emit_arg), "--emit=%s", p->emit);
    char lock_arg[96];
    (void)snprintf(lock_arg, sizeof(lock_arg), "--lock-root=%s", lock_hex);

    char *dep_args = NULL;
    const size_t dep_stride = PKGL_PATH_MAX + 96u;
    if (dep_count) {
        dep_args = zcl_malloc(dep_stride * dep_count, "pkgl.dep_args");
        if (!dep_args)
            return ZCL_ERR(-1, "cannot allocate the dependency argv");
    }
    const char *argv[8u + VCS_PACKAGE_BUILD_MAX_DEPS];
    size_t argc = 0;
    argv[argc++] = p->worker;
    argv[argc++] = root_hex;
    argv[argc++] = store_arg;
    argv[argc++] = emit_arg;
    argv[argc++] = lock_arg;
    for (size_t i = 0; i < dep_count; i++) {
        char dep_hex[65];
        zcl_hex_encode(dep_roots[i], 32, dep_hex);
        char *slot = dep_args + dep_stride * i;
        char install[PKGL_PATH_MAX];
        struct zcl_result ir =
            pkgl_installed_dir(ctx, dep_roots[i], install, sizeof(install));
        if (!ir.ok) {
            free(dep_args);
            return ir;
        }
        (void)snprintf(slot, dep_stride, "--dep=%s,%s", dep_hex, install);
        argv[argc++] = slot;
    }
    argv[argc] = NULL;

    char out[8192];
    int rc = zcl_spawn_capture(argv, out, sizeof(out), PKGL_BUILD_TIMEOUT_MS);
    free(dep_args);
    if (rc != 0) {
        /* Trim the captured stdout to one line for the operator's detail. */
        char *nl = strchr(out, '\n');
        if (nl)
            *nl = '\0';
        return ZCL_ERR(-1, "build worker exit %d%s%s", rc,
                       out[0] ? ": " : "", out);
    }
    return ZCL_OK;
}

// long-function-ok:one-install-transaction — the emit, the receipt
// cross-check, the per-output re-hash and the atomic rename are ONE
// transaction; a split would create a reachable state where some outputs
// were copied without the receipt having been checked.
struct zcl_result pkgl_build_and_install(
    const struct pkgl_ctx *ctx, const uint8_t root[32],
    const struct vcs_package_release *release, const uint8_t lock_root[32],
    const uint8_t (*dep_roots)[32], size_t dep_count,
    struct package_lifecycle_step *step)
{
    if (!ctx || !root || !release || !lock_root || !step)
        return ZCL_ERR(-1, "null argument installing a package");
#ifdef _WIN32
    /* Package builds execute untrusted recipes and activation publishes their
     * output.  Keep the native boundary closed until the restricted-token /
     * Job Object sandbox and immutable generation transaction are qualified. */
    pkgl_step_fail(step, "windows-package-install-disabled",
                   "native package install awaits sandbox qualification");
    return ZCL_ERR(-1,
                   "native Windows package install is disabled until the "
                   "sandbox and secure immutable generation activation pass "
                   "qualification");
#endif

    struct pkgl_build_paths p;
    struct zcl_result pr = pkgl_build_paths_init(ctx, root, &p);
    if (!pr.ok) {
        pkgl_step_fail(step, "worker-missing", pr.message);
        return pr;
    }
    ZCL_IGNORE_RESULT(pkgl_rm_rf(p.emit), "stale build work is replaced");
    ZCL_IGNORE_RESULT(pkgl_rm_rf(p.stage), "stale staging is replaced");
    ZCL_CHECK(pkgl_mkdir_p(p.emit));

    struct zcl_result wr =
        pkgl_run_worker(ctx, &p, root, lock_root, dep_roots, dep_count);
    if (!wr.ok) {
        pkgl_step_fail(step, "build-failed", wr.message);
        ZCL_IGNORE_RESULT(pkgl_rm_rf(p.emit), "failed build work removed");
        return wr;
    }

    /* The worker's own account of what it produced. */
    char report[PKGL_PATH_MAX];
    int n = snprintf(report, sizeof(report), "%s/build-report", p.emit);
    if (n <= 0 || (size_t)n >= sizeof(report)) {
        pkgl_step_fail(step, "build-report-path", "emit path too long");
        return ZCL_ERR(-1, "emit path too long");
    }
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    struct zcl_result rr = pkgl_read_file(
        report, VCS_PACKAGE_BUILD_MAX_WIRE_BYTES, &wire, &wire_len);
    if (!rr.ok) {
        pkgl_step_fail(step, "build-report-missing", rr.message);
        ZCL_IGNORE_RESULT(pkgl_rm_rf(p.emit), "unusable build work removed");
        return rr;
    }
    struct vcs_package_build_receipt receipt;
    enum vcs_package_build_error berr =
        vcs_package_build_parse(wire, wire_len, &receipt);
    free(wire);
    if (berr != VCS_PACKAGE_BUILD_OK) {
        pkgl_step_fail(step, "build-report-invalid",
                       vcs_package_build_error_string(berr));
        ZCL_IGNORE_RESULT(pkgl_rm_rf(p.emit), "unusable build work removed");
        return ZCL_ERR(-1, "build report: %s",
                       vcs_package_build_error_string(berr));
    }
    struct zcl_result mr = pkgl_receipt_matches(&receipt, root, release,
                                                lock_root, dep_roots,
                                                dep_count);
    if (!mr.ok) {
        pkgl_step_fail(step, "build-report-mismatch", mr.message);
        ZCL_IGNORE_RESULT(pkgl_rm_rf(p.emit), "unusable build work removed");
        return mr;
    }
    step->state = VCS_PACKAGE_LIFECYCLE_BUILT;
    if (!vcs_package_build_installable(&receipt)) {
        char detail[PACKAGE_LIFECYCLE_DETAIL_MAX + 1u];
        (void)snprintf(detail, sizeof(detail), "verdict %s (test exit %u)",
                       vcs_package_build_result_string(
                           (enum vcs_package_build_result)
                               receipt.result_class),
                       receipt.test_exit_code);
        pkgl_step_fail(step, "build-not-installable", detail);
        ZCL_IGNORE_RESULT(pkgl_rm_rf(p.emit), "failed build work removed");
        return ZCL_ERR(-1, "%s", detail);
    }
    step->state = VCS_PACKAGE_LIFECYCLE_TESTED;

    /* Re-hash and install ONLY what the receipt declares. An artifact the
     * worker produced but did not commit to simply never lands. */
    ZCL_CHECK(pkgl_mkdir_p(p.stage));
    char src[PKGL_PATH_MAX];
    char dst[PKGL_PATH_MAX];
    for (size_t i = 0; i < receipt.output_count; i++) {
        const struct vcs_package_build_output *o = &receipt.outputs[i];
        int sn = snprintf(src, sizeof(src), "%s/%s", p.emit, o->path);
        int dn = snprintf(dst, sizeof(dst), "%s/%s", p.stage, o->path);
        if (sn <= 0 || (size_t)sn >= sizeof(src) || dn <= 0 ||
            (size_t)dn >= sizeof(dst)) {
            pkgl_step_fail(step, "output-path-too-long", o->path);
            ZCL_IGNORE_RESULT(pkgl_rm_rf(p.stage), "aborted install removed");
            return ZCL_ERR(-1, "output path too long: %s", o->path);
        }
        uint8_t got[32];
        uint64_t bytes = 0;
        struct zcl_result cr = pkgl_copy_hashed(src, dst, got, &bytes);
        if (!cr.ok) {
            pkgl_step_fail(step, "output-missing", cr.message);
            ZCL_IGNORE_RESULT(pkgl_rm_rf(p.stage), "aborted install removed");
            ZCL_IGNORE_RESULT(pkgl_rm_rf(p.emit), "aborted build removed");
            return cr;
        }
        if (bytes != o->bytes || memcmp(got, o->sha3, 32) != 0) {
            pkgl_step_fail(step, "output-hash-mismatch", o->path);
            ZCL_IGNORE_RESULT(pkgl_rm_rf(p.stage), "aborted install removed");
            ZCL_IGNORE_RESULT(pkgl_rm_rf(p.emit), "aborted build removed");
            return ZCL_ERR(-1,
                           "%s does not match the hash the build receipt "
                           "commits — refusing to install it", o->path);
        }
        struct zcl_result moded = pkgl_apply_output_mode(dst, o->path);
        if (!moded.ok) {
            pkgl_step_fail(step, "output-mode", moded.message);
            ZCL_IGNORE_RESULT(pkgl_rm_rf(p.stage), "aborted install removed");
            ZCL_IGNORE_RESULT(pkgl_rm_rf(p.emit), "aborted build removed");
            return moded;
        }
    }

    /* The receipt travels with the install and is also filed by its id, so
     * "what produced this tree" is answerable from either end. */
    uint8_t *rwire = NULL;
    size_t rwire_len = 0;
    if (vcs_package_build_serialize(&receipt, &rwire, &rwire_len) !=
        VCS_PACKAGE_BUILD_OK) {
        pkgl_step_fail(step, "receipt-serialize", "cannot re-encode receipt");
        ZCL_IGNORE_RESULT(pkgl_rm_rf(p.stage), "aborted install removed");
        return ZCL_ERR(-1, "cannot re-encode the build receipt");
    }
    uint8_t receipt_id[32];
    if (vcs_package_build_id(&receipt, receipt_id) != VCS_PACKAGE_BUILD_OK) {
        free(rwire);
        pkgl_step_fail(step, "receipt-id", "cannot compute receipt id");
        ZCL_IGNORE_RESULT(pkgl_rm_rf(p.stage), "aborted install removed");
        return ZCL_ERR(-1, "cannot compute the build receipt id");
    }
    int dst_len = snprintf(dst, sizeof(dst), "%s/build-report", p.stage);
    if (dst_len <= 0 || (size_t)dst_len >= sizeof(dst)) {
        free(rwire);
        pkgl_step_fail(step, "receipt-store", "build report path is too long");
        ZCL_IGNORE_RESULT(pkgl_rm_rf(p.stage), "aborted install removed");
        return ZCL_ERR(-1, "build report path is too long");
    }
    struct zcl_result sw = pkgl_write_atomic(dst, rwire, rwire_len);
    if (sw.ok) {
        char id_hex[65];
        zcl_hex_encode(receipt_id, 32, id_hex);
        (void)snprintf(src, sizeof(src), "receipts/%s", id_hex);
        struct zcl_result jr = pkgl_join(ctx, src, dst, sizeof(dst));
        if (jr.ok) {
            char *slash = strrchr(dst, '/');
            if (slash) {
                *slash = '\0';
                sw = pkgl_mkdir_p(dst);
                *slash = '/';
            }
            if (sw.ok)
                sw = pkgl_write_atomic(dst, rwire, rwire_len);
        } else {
            sw = jr;
        }
    }
    free(rwire);
    if (!sw.ok) {
        pkgl_step_fail(step, "receipt-write", sw.message);
        ZCL_IGNORE_RESULT(pkgl_rm_rf(p.stage), "aborted install removed");
        return sw;
    }

    /* Atomic activation of THIS root's tree: rename, never in-place edit. */
    bool present = false;
    ZCL_CHECK(pkgl_exists(p.final, &present));
    if (present) {
        /* Same root, same content: the existing tree is already correct. */
        ZCL_IGNORE_RESULT(pkgl_rm_rf(p.stage), "already installed");
    } else if (rename(p.stage, p.final) != 0) {
        pkgl_step_fail(step, "install-rename", strerror(errno));
        struct zcl_result e = ZCL_ERR(-1, "rename %s -> %s: %s", p.stage,
                                      p.final, strerror(errno));
        ZCL_IGNORE_RESULT(pkgl_rm_rf(p.stage), "aborted install removed");
        return e;
    }
    ZCL_IGNORE_RESULT(pkgl_rm_rf(p.emit), "build work is not kept");

    step->state = VCS_PACKAGE_LIFECYCLE_INSTALLED;
    step->has_receipt = true;
    memcpy(step->receipt_id, receipt_id, 32);
    return ZCL_OK;
}

/* ── generations + activation ───────────────────────────────────────── */

static struct zcl_result pkgl_generations_path(const struct pkgl_ctx *ctx,
                                               const char *name, char *out,
                                               size_t cap)
{
    char publisher[VCS_PACKAGE_RELEASE_NAME_MAX + 1u];
    char package[VCS_PACKAGE_RELEASE_NAME_MAX + 1u];
    if (!vcs_package_name_split(name, publisher, package))
        return ZCL_ERR(-1, "'%s' is not a publisher/package name", name);
    char rel[2u * (VCS_PACKAGE_RELEASE_NAME_MAX + 1u) + 32u];
    int n = snprintf(rel, sizeof(rel), "generations/%s/%s", publisher,
                     package);
    if (n <= 0 || (size_t)n >= sizeof(rel))
        return ZCL_ERR(-1, "generation path too long for %s", name);
    return pkgl_join(ctx, rel, out, cap);
}

static struct zcl_result pkgl_active_path(const struct pkgl_ctx *ctx,
                                          const char *name, char *out,
                                          size_t cap)
{
    char publisher[VCS_PACKAGE_RELEASE_NAME_MAX + 1u];
    char package[VCS_PACKAGE_RELEASE_NAME_MAX + 1u];
    if (!vcs_package_name_split(name, publisher, package))
        return ZCL_ERR(-1, "'%s' is not a publisher/package name", name);
    char rel[2u * (VCS_PACKAGE_RELEASE_NAME_MAX + 1u) + 32u];
    int n = snprintf(rel, sizeof(rel), "active/%s/%s", publisher, package);
    if (n <= 0 || (size_t)n >= sizeof(rel))
        return ZCL_ERR(-1, "active path too long for %s", name);
    return pkgl_join(ctx, rel, out, cap);
}

struct zcl_result pkgl_generations_load(const struct pkgl_ctx *ctx,
                                        const char *name,
                                        struct vcs_package_generations *out)
{
    if (!ctx || !name || !out)
        return ZCL_ERR(-1, "null argument loading the generation log");
    vcs_package_generations_init(out);
    char path[PKGL_PATH_MAX];
    ZCL_CHECK(pkgl_generations_path(ctx, name, path, sizeof(path)));
    bool present = false;
    ZCL_CHECK(pkgl_exists(path, &present));
    if (!present)
        return ZCL_OK;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    ZCL_CHECK(pkgl_read_file(path, VCS_PACKAGE_GENERATION_MAX_WIRE_BYTES,
                             &wire, &wire_len));
    enum vcs_package_install_error err =
        vcs_package_generations_parse(wire, wire_len, out);
    free(wire);
    if (err != VCS_PACKAGE_INSTALL_OK)
        return ZCL_ERR(-1, "generation log for %s: %s", name,
                       vcs_package_install_error_string(err));
    return ZCL_OK;
}

/* Point active/<publisher>/<package> at installed/<root>. The swap is a
 * rename over a fresh symlink, so a reader either sees the old generation or
 * the new one — never a missing or half-written pointer. */
static struct zcl_result pkgl_swap_active(const struct pkgl_ctx *ctx,
                                          const char *name,
                                          const uint8_t root[32])
{
    char link[PKGL_PATH_MAX];
    ZCL_CHECK(pkgl_active_path(ctx, name, link, sizeof(link)));
    char parent[PKGL_PATH_MAX];
    (void)snprintf(parent, sizeof(parent), "%s", link);
    char *slash = strrchr(parent, '/');
    if (!slash)
        return ZCL_ERR(-1, "active path has no parent");
    *slash = '\0';
    ZCL_CHECK(pkgl_mkdir_p(parent));

    char target[PKGL_PATH_MAX];
    ZCL_CHECK(pkgl_installed_dir(ctx, root, target, sizeof(target)));
    bool present = false;
    ZCL_CHECK(pkgl_exists(target, &present));
    if (!present)
        return ZCL_ERR(-1, "cannot activate a root that is not installed");

    char tmp[PKGL_PATH_MAX];
    int n = snprintf(tmp, sizeof(tmp), "%s.zplnew.%ld", link, (long)getpid());
    if (n <= 0 || (size_t)n >= sizeof(tmp))
        return ZCL_ERR(-1, "active temp path too long");
    ZCL_IGNORE_RESULT(pkgl_rm_rf(tmp), "stale active temp link");
#ifdef _WIN32
    errno = ENOTSUP;
    return ZCL_ERR(-1, "symlink %s: %s", tmp, strerror(errno));
#else
    if (symlink(target, tmp) != 0)
        return ZCL_ERR(-1, "symlink %s: %s", tmp, strerror(errno));
#endif
    if (rename(tmp, link) != 0) {
        int e = errno;
        ZCL_IGNORE_RESULT(pkgl_rm_rf(tmp), "failed active swap cleaned up");
        return ZCL_ERR(-1, "activate %s: %s", link, strerror(e));
    }
    return ZCL_OK;
}

struct zcl_result pkgl_activate(const struct pkgl_ctx *ctx, const char *name,
                                const uint8_t root[32], int64_t now_unix,
                                uint8_t prev_root_out[32],
                                bool *had_previous_out)
{
    if (!ctx || !name || !root || !prev_root_out || !had_previous_out)
        return ZCL_ERR(-1, "null argument activating a package");
    memset(prev_root_out, 0, 32);
    *had_previous_out = false;
#ifdef _WIN32
    return ZCL_ERR(-1,
                   "native Windows package activation is disabled until the "
                   "sandbox and secure immutable generation activation pass "
                   "qualification");
#endif

    struct vcs_package_generations gens;
    ZCL_CHECK(pkgl_generations_load(ctx, name, &gens));
    bool already_active =
        gens.count > 0 && memcmp(gens.items[gens.count - 1].root, root, 32) == 0;
    if (gens.count > 0 && !already_active) {
        memcpy(prev_root_out, gens.items[gens.count - 1].root, 32);
        *had_previous_out = true;
    } else if (already_active) {
        *had_previous_out =
            vcs_package_generations_previous(&gens, prev_root_out);
    }

    /* The pointer is swapped first: if the log write then fails the operator
     * sees a log that lags reality, which the next activation repairs. The
     * reverse order could leave a log claiming an activation that never
     * happened. */
    ZCL_CHECK(pkgl_swap_active(ctx, name, root));
    if (already_active)
        return ZCL_OK;

    enum vcs_package_install_error err =
        vcs_package_generations_append(&gens, root, now_unix);
    if (err != VCS_PACKAGE_INSTALL_OK)
        return ZCL_ERR(-1, "generation append for %s: %s", name,
                       vcs_package_install_error_string(err));
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    err = vcs_package_generations_serialize(&gens, &wire, &wire_len);
    if (err != VCS_PACKAGE_INSTALL_OK)
        return ZCL_ERR(-1, "generation serialize for %s: %s", name,
                       vcs_package_install_error_string(err));
    char path[PKGL_PATH_MAX];
    struct zcl_result gr = pkgl_generations_path(ctx, name, path,
                                                 sizeof(path));
    if (gr.ok) {
        char parent[PKGL_PATH_MAX];
        (void)snprintf(parent, sizeof(parent), "%s", path);
        char *slash = strrchr(parent, '/');
        if (slash) {
            *slash = '\0';
            gr = pkgl_mkdir_p(parent);
        }
        if (gr.ok)
            gr = pkgl_write_atomic(path, wire, wire_len);
    }
    free(wire);
    return gr;
}

/* ── pinning ────────────────────────────────────────────────────────── */

struct zcl_result pkgl_pin(const struct pkgl_ctx *ctx, const uint8_t root[32])
{
    if (!ctx || !root)
        return ZCL_ERR(-1, "null argument pinning a package");
    struct vcs_package_store *store =
        vcs_package_store_open(ctx->datadir, vcs_package_store_quota_bytes());
    if (!store)
        return ZCL_ERR(-1, "cannot open the package store under %s",
                       ctx->datadir);
    enum vcs_package_store_result r =
        vcs_package_store_pin(store, root, true);
    vcs_package_store_close(store);
    if (r != VCS_PACKAGE_STORE_OK)
        return ZCL_ERR(-1, "pin refused: %s",
                       vcs_package_store_result_string(r));
    return ZCL_OK;
}

/* ── the programs an install hands a person ─────────────────────────── */

struct zcl_result package_lifecycle_installed_programs(
    const char *datadir, const uint8_t root[32],
    struct package_lifecycle_programs *out)
{
    if (!out)
        return ZCL_ERR(-1, "null installed-programs report");
    memset(out, 0, sizeof(*out));
    if (!root)
        return ZCL_ERR(-1, "null package root");
    struct pkgl_ctx ctx;
    ZCL_CHECK(pkgl_ctx_open(&ctx, datadir));
    char installed[PKGL_PATH_MAX];
    struct zcl_result r =
        pkgl_installed_dir(&ctx, root, installed, sizeof(installed));
    bool present = false;
    if (r.ok)
        r = pkgl_exists(installed, &present);
    if (r.ok && !present)
        r = ZCL_ERR(-1, "this package root is not installed under %s",
                    ctx.datadir);
    /* An operator is handed a path to RUN, so report the resolved absolute
     * one: a relative datadir would otherwise produce a command that only
     * works from whichever directory the node happened to be started in. */
    if (r.ok) {
#ifdef _WIN32
        int n = snprintf(out->install_dir, sizeof(out->install_dir), "%s",
                         installed);
        if (n <= 0 || (size_t)n >= sizeof(out->install_dir))
            r = ZCL_ERR(-1, "installed directory path is too long");
#else
        char resolved[PKGL_PATH_MAX];
        if (!realpath(installed, resolved))
            r = ZCL_ERR(-1, "cannot resolve %s: %s", installed,
                        strerror(errno));
        else {
            int n = snprintf(out->install_dir, sizeof(out->install_dir),
                             "%s", resolved);
            if (n <= 0 || (size_t)n >= sizeof(out->install_dir))
                r = ZCL_ERR(-1, "installed directory path is too long");
        }
#endif
    }
    char report[PKGL_PATH_MAX];
    if (r.ok) {
        int n = snprintf(report, sizeof(report), "%s/build-report", installed);
        if (n <= 0 || (size_t)n >= sizeof(report))
            r = ZCL_ERR(-1, "installed receipt path is too long");
    }
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (r.ok)
        r = pkgl_read_file(report, VCS_PACKAGE_BUILD_MAX_WIRE_BYTES, &wire,
                           &wire_len);
    if (!r.ok) {
        pkgl_ctx_close(&ctx);
        return r;
    }
    struct vcs_package_build_receipt receipt;
    enum vcs_package_build_error parsed =
        vcs_package_build_parse(wire, wire_len, &receipt);
    free(wire);
    pkgl_ctx_close(&ctx);
    if (parsed != VCS_PACKAGE_BUILD_OK)
        return ZCL_ERR(-1, "installed receipt: %s",
                       vcs_package_build_error_string(parsed));
    for (size_t i = 0; i < receipt.output_count; i++) {
        const char *path = receipt.outputs[i].path;
        if (strncmp(path, "bin/", 4) != 0)
            continue;
        if (out->count >= PACKAGE_LIFECYCLE_MAX_PROGRAMS)
            return ZCL_ERR(-1, "receipt names more than %u programs",
                           (unsigned)PACKAGE_LIFECYCLE_MAX_PROGRAMS);
        (void)snprintf(out->output[out->count],
                       sizeof(out->output[out->count]), "%s", path);
        out->count++;
    }
    return ZCL_OK;
}
