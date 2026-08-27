/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_lifecycle_reproduce — the SECOND-RECEIPT adapter of the ZCODE
 * install lifecycle. Given one ALREADY-INSTALLED package root it re-runs
 * the fixed verifier worker over the exact committed inputs — the source
 * tree re-materialized from the chunk-verified CAS, the canonical recipe
 * wire, and the install receipt's own lock root and dependency set — under
 * the STANDARD build profile. Only when the rebuild receipt is
 * byte-identical on every committed output (vcs_package_reproduce_compare
 * == MATCH) AND hashes to a DISTINCT receipt id is it filed beside the
 * install receipt under <datadir>/zcode/receipts/<receipt-id-hex>. Two
 * distinct receipt ids with byte-identical output sets is the reproduction
 * fact vcs_package_reproduce_scan reports as reproduced=true.
 *
 * The store/emit worker shape the install build uses has no profile input
 * (it is always the quick profile), so the reproduce run feeds the worker
 * the materialized source and recipe explicitly — the same argv shape
 * build_fabric_package_prepare assembles for a standard-profile candidate
 * build. The reference is the receipt that TRAVELS WITH THE INSTALL
 * (installed/<root>/build-report), which install cross-checked
 * byte-for-byte against the filed copy before activating anything.
 *
 * The same boundaries hold as everywhere in this layer: nothing compiles
 * in this process, no package byte is executed here, there is no dlopen,
 * and every refusal is named in the report's rule/detail. */

#include "package_lifecycle_internal.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/result.h"
#include "base/safe_alloc.h"
#include "util/spawn.h"
#include "vcs/package_reproduce.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The standard-profile rebuild gets the same cpu bound the package factory
 * gives its second-receipt run. */
#define PKGL_REPRODUCE_CPU_SECONDS 120u

struct pkgl_reproduce_paths {
    char worker[PKGL_PATH_MAX];
    char work[PKGL_PATH_MAX];
    char src[PKGL_PATH_MAX];
    char emit[PKGL_PATH_MAX];
    char recipe[PKGL_PATH_MAX];
};

static void pkgl_repro_note(struct package_lifecycle_reproduce_report *out,
                            const char *rule, const char *detail)
{
    if (!out)
        return;
    (void)snprintf(out->rule, sizeof(out->rule), "%s", rule);
    (void)snprintf(out->detail, sizeof(out->detail), "%.191s", detail);
}

/* One named refusal, logged with its context: a reproduce that cannot run
 * or cannot match files NOTHING. */
static struct zcl_result pkgl_reproduce_refused(
    struct package_lifecycle_reproduce_report *out, const char *rule,
    struct zcl_result r)
{
    pkgl_repro_note(out, rule, r.message);
    LOG_ERROR(PKGL_LOG, "reproduce refused (%s): %s", rule, r.message);
    return r;
}

static struct zcl_result pkgl_reproduce_paths_init(
    const struct pkgl_ctx *ctx, const uint8_t root[32],
    const uint8_t recipe_root[32], struct pkgl_reproduce_paths *p)
{
    char hex[65];
    zcl_hex_encode(root, 32, hex);
    char rel[128];
    ZCL_CHECK(pkgl_worker_path(p->worker, sizeof(p->worker)));
    (void)snprintf(rel, sizeof(rel), "buildwork/repro-%s", hex);
    ZCL_CHECK(pkgl_join(ctx, rel, p->work, sizeof(p->work)));
    int n = snprintf(p->src, sizeof(p->src), "%s/src", p->work);
    if (n <= 0 || (size_t)n >= sizeof(p->src))
        return ZCL_ERR(-1, "reproduce source path too long");
    n = snprintf(p->emit, sizeof(p->emit), "%s/emit", p->work);
    if (n <= 0 || (size_t)n >= sizeof(p->emit))
        return ZCL_ERR(-1, "reproduce emit path too long");
    char rhex[65];
    zcl_hex_encode(recipe_root, 32, rhex);
    (void)snprintf(rel, sizeof(rel), "recipes/%s", rhex);
    ZCL_CHECK(pkgl_join(ctx, rel, p->recipe, sizeof(p->recipe)));
    return ZCL_OK;
}

/* A fast_cache that is NULL or only whitespace IS the cold rebuild: the
 * worker argv must stay byte-for-byte today's, so the flag is dropped
 * rather than passed empty (an empty --fast-cache= makes the worker refuse
 * the whole run). */
static bool pkgl_fast_cache_blank(const char *s)
{
    if (!s)
        return true;
    for (; *s; s++)
        if (*s != ' ' && *s != '\t' && *s != '\n' && *s != '\r')
            return false;
    return true;
}

/* The worker ends a cache-fed run with one stats line,
 *   zbuild-package-fast-cache=v1 hits=N misses=N reused_bytes=N
 *   admission=<token>
 * Parse the FIRST such line into the report. A worker that printed none
 * (a refusal, or a run the cache never applied to) leaves the counters at
 * zero — reported as zero, never silently dropped. */
static void pkgl_fast_stats_consume(
    struct package_lifecycle_reproduce_report *out, const char *vout)
{
    const char *line = vout;
    while (line && *line) {
        const char *nl = strchr(line, '\n');
        size_t len = nl ? (size_t)(nl - line) : strlen(line);
        unsigned long long h = 0, m = 0, b = 0;
        char admission[32];
        admission[0] = '\0';
        if (len < 1024 &&
            strncmp(line, "zbuild-package-fast-cache=v1", 28) == 0 &&
            sscanf(line,
                   "zbuild-package-fast-cache=v1 hits=%llu misses=%llu "
                   "reused_bytes=%llu admission=%31s",
                   &h, &m, &b, admission) == 4) {
            out->fast_cache_hits = h;
            out->fast_cache_misses = m;
            out->fast_cache_reused_bytes = b;
            (void)snprintf(out->fast_cache_admission,
                           sizeof(out->fast_cache_admission), "%s",
                           admission);
            return;
        }
        line = nl ? nl + 1 : NULL;
    }
}

/* Rebuild one installed root under the standard profile in candidate mode.
 * The dependency argv comes from the reference (install) receipt's own
 * committed set — never from a re-derived lock — so the rebuild is fed
 * exactly the inputs the install-time validation committed to. When
 * fast_cache names a directory, the confined worker gets it as
 * --fast-cache=<dir> — the same candidate-mode flag the package factory's
 * second-receipt run uses — so a node holding the objects rebuilds with
 * zero compiler spawns. The worker quarantines and re-verifies every cache
 * entry itself; this layer only hands the path over, unchanged. */
static struct zcl_result pkgl_run_reproduce_worker(
    const struct pkgl_ctx *ctx, const struct pkgl_reproduce_paths *p,
    const char *name, const struct vcs_package_build_receipt *reference,
    const char *fast_cache, struct package_lifecycle_reproduce_report *rep)
{
    char root_hex[65];
    zcl_hex_encode(reference->package_root, 32, root_hex);
    char lock_hex[65];
    zcl_hex_encode(reference->lock_root, 32, lock_hex);
    char source_arg[PKGL_PATH_MAX + 32];
    (void)snprintf(source_arg, sizeof(source_arg),
                   "--zbuild-package-source=%s", p->src);
    char recipe_arg[PKGL_PATH_MAX + 32];
    (void)snprintf(recipe_arg, sizeof(recipe_arg),
                   "--zbuild-package-recipe=%s", p->recipe);
    char name_arg[VCS_PACKAGE_RELEASE_NAME_MAX + 32];
    (void)snprintf(name_arg, sizeof(name_arg), "--zbuild-package-name=%s",
                   name);
    char cpu_arg[64];
    (void)snprintf(cpu_arg, sizeof(cpu_arg),
                   "--zbuild-package-max-cpu-seconds=%u",
                   PKGL_REPRODUCE_CPU_SECONDS);
    char emit_arg[PKGL_PATH_MAX + 16];
    (void)snprintf(emit_arg, sizeof(emit_arg), "--emit=%s", p->emit);
    char lock_arg[96];
    (void)snprintf(lock_arg, sizeof(lock_arg), "--lock-root=%s", lock_hex);
    char fast_arg[PKGL_PATH_MAX + 16];
    bool use_fast = !pkgl_fast_cache_blank(fast_cache);
    int fn = 0;
    if (use_fast) {
        fn = snprintf(fast_arg, sizeof(fast_arg), "--fast-cache=%s",
                      fast_cache);
        if (fn <= 0 || (size_t)fn >= sizeof(fast_arg))
            return ZCL_ERR(-1, "fast-cache arg path too long");
    }

    char *dep_args = NULL;
    const size_t dep_stride = PKGL_PATH_MAX + 96u;
    if (reference->dep_count) {
        dep_args = zcl_malloc(dep_stride * reference->dep_count,
                              "pkgl.repro_dep_args");
        if (!dep_args)
            return ZCL_ERR(-1, "cannot allocate the dependency argv");
    }
    const char *argv[13u + VCS_PACKAGE_BUILD_MAX_DEPS];
    size_t argc = 0;
    argv[argc++] = p->worker;
    argv[argc++] = root_hex;
    argv[argc++] = source_arg;
    argv[argc++] = recipe_arg;
    argv[argc++] = name_arg;
    argv[argc++] = "--zbuild-package-profile=standard";
    argv[argc++] = cpu_arg;
    argv[argc++] = emit_arg;
    argv[argc++] = lock_arg;
    for (size_t i = 0; i < reference->dep_count; i++) {
        char dep_hex[65];
        zcl_hex_encode(reference->dep_roots[i], 32, dep_hex);
        char install[PKGL_PATH_MAX];
        struct zcl_result ir = pkgl_installed_dir(
            ctx, reference->dep_roots[i], install, sizeof(install));
        if (!ir.ok) {
            free(dep_args);
            return ir;
        }
        bool present = false;
        struct zcl_result er = pkgl_exists(install, &present);
        if (!er.ok || !present) {
            free(dep_args);
            return er.ok
                ? ZCL_ERR(-1, "locked dependency %s is no longer installed",
                          dep_hex)
                : er;
        }
        char *slot = dep_args + dep_stride * i;
        (void)snprintf(slot, dep_stride, "--dep=%s,%s", dep_hex, install);
        argv[argc++] = slot;
    }
    /* The cache flag sits where the factory's second-receipt run puts it:
     * after the committed dependency set, before the isolation demand. */
    if (use_fast)
        argv[argc++] = fast_arg;
    argv[argc++] = "--require-full-isolation";
    /* Reproduce rebuilds an ALREADY-accepted package to check byte-identity,
     * not to compose admission evidence, so it opts out of the
     * evidence-track refusal of testless standard-profile builds. */
    argv[argc++] = "--allow-testless-standard";
    argv[argc] = NULL;

    char out[8192];
    int rc = zcl_spawn_capture(argv, out, sizeof(out), PKGL_BUILD_TIMEOUT_MS);
    free(dep_args);
    if (use_fast) {
        rep->fast_cache_used = true;
        /* The stats line is printed only by a run that completed, so a
         * refused rebuild honestly reports the all-zero outcome. */
        if (rc == 0)
            pkgl_fast_stats_consume(rep, out);
    }
    if (rc != 0) {
        /* Trim the captured stdout to one line for the operator's detail. */
        char *nl = strchr(out, '\n');
        if (nl)
            *nl = '\0';
        return ZCL_ERR(-1, "rebuild worker exit %d%s%s", rc,
                       out[0] ? ": " : "", out);
    }
    return ZCL_OK;
}

/* Read, parse, and re-hash the receipt that travels with the install. */
static struct zcl_result pkgl_reproduce_reference(
    const char *installed, const uint8_t root[32],
    const struct vcs_package_release *release,
    struct vcs_package_build_receipt *out, uint8_t receipt_id_out[32])
{
    char report_path[PKGL_PATH_MAX];
    int n = snprintf(report_path, sizeof(report_path), "%s/build-report",
                     installed);
    if (n <= 0 || (size_t)n >= sizeof(report_path))
        return ZCL_ERR(-1, "installed receipt path too long");
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    struct zcl_result r =
        pkgl_read_file(report_path, VCS_PACKAGE_BUILD_MAX_WIRE_BYTES, &wire,
                       &wire_len);
    if (!r.ok)
        return r;
    enum vcs_package_build_error berr =
        vcs_package_build_parse(wire, wire_len, out);
    free(wire);
    if (berr != VCS_PACKAGE_BUILD_OK)
        return ZCL_ERR(-1, "installed receipt: %s",
                       vcs_package_build_error_string(berr));
    if (!vcs_package_build_installable(out))
        return ZCL_ERR(-1, "the install receipt is not a passing build");
    if (memcmp(out->package_root, root, 32) != 0 ||
        memcmp(out->recipe_root, release->recipe_root, 32) != 0)
        return ZCL_ERR(-1, "the installed receipt names different package or "
                           "recipe roots than the release envelope");
    if (vcs_package_build_id(out, receipt_id_out) != VCS_PACKAGE_BUILD_OK)
        return ZCL_ERR(-1, "the install receipt id cannot be rederived");
    return ZCL_OK;
}

// long-function-ok:one-reproduce-transaction — the reference load, the
// input re-verification, the confined rebuild, the byte-identity compare,
// and the conditional filing are ONE transaction: a split would create a
// reachable state where a second receipt exists without the MATCH and
// distinct-id gates having been applied to it.
static struct zcl_result pkgl_reproduce_run(
    const struct pkgl_ctx *ctx, const uint8_t root[32],
    const struct vcs_package_release *release, const char *fast_cache,
    struct package_lifecycle_reproduce_report *out)
{
    /* Reproduction is a fact about an install: the reference receipt is the
     * one that travels with the installed tree. */
    char installed[PKGL_PATH_MAX];
    struct zcl_result r = pkgl_installed_dir(ctx, root, installed,
                                             sizeof(installed));
    bool present = false;
    if (r.ok)
        r = pkgl_exists(installed, &present);
    if (!r.ok)
        return pkgl_reproduce_refused(out, "not-installed", r);
    if (!present)
        return pkgl_reproduce_refused(
            out, "not-installed",
            ZCL_ERR(-1, "%s is not installed on this node — install it "
                        "before asking for a reproduction", release->name));

    struct vcs_package_build_receipt reference;
    r = pkgl_reproduce_reference(installed, root, release, &reference,
                                 out->reference_receipt_id);
    if (!r.ok)
        return pkgl_reproduce_refused(out, "installed-receipt-invalid", r);

    /* Every input the rebuild compiles is re-verified against its
     * commitment before it reaches the worker: the release envelope, the
     * manifest root, the recipe root, and every CAS chunk. */
    char rule[64];
    rule[0] = '\0';
    r = pkgl_verify_package(ctx, root, rule, sizeof(rule));
    if (!r.ok)
        return pkgl_reproduce_refused(
            out, rule[0] ? rule : "package-verify-failed", r);

    struct pkgl_reproduce_paths p;
    r = pkgl_reproduce_paths_init(ctx, root, release->recipe_root, &p);
    if (!r.ok)
        return pkgl_reproduce_refused(out, "worker-missing", r);
    ZCL_IGNORE_RESULT(pkgl_rm_rf(p.work), "stale reproduce work is replaced");
    r = pkgl_materialize_package(ctx, root, p.src);
    if (r.ok)
        r = pkgl_run_reproduce_worker(ctx, &p, release->name, &reference,
                                      fast_cache, out);
    if (!r.ok) {
        ZCL_IGNORE_RESULT(pkgl_rm_rf(p.work),
                          "failed reproduce work removed");
        return pkgl_reproduce_refused(out, "build-failed", r);
    }

    /* The rebuild's own account of what it produced. */
    char report_path[PKGL_PATH_MAX];
    int n = snprintf(report_path, sizeof(report_path), "%s/build-report",
                     p.emit);
    if (n <= 0 || (size_t)n >= sizeof(report_path)) {
        ZCL_IGNORE_RESULT(pkgl_rm_rf(p.work), "failed reproduce work removed");
        return pkgl_reproduce_refused(
            out, "build-report-path", ZCL_ERR(-1, "emit path too long"));
    }
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    r = pkgl_read_file(report_path, VCS_PACKAGE_BUILD_MAX_WIRE_BYTES, &wire,
                       &wire_len);
    if (!r.ok) {
        ZCL_IGNORE_RESULT(pkgl_rm_rf(p.work), "failed reproduce work removed");
        return pkgl_reproduce_refused(out, "build-report-missing", r);
    }
    struct vcs_package_build_receipt rebuild;
    enum vcs_package_build_error berr =
        vcs_package_build_parse(wire, wire_len, &rebuild);
    uint8_t rebuild_id[32];
    memset(rebuild_id, 0, sizeof(rebuild_id));
    if (berr == VCS_PACKAGE_BUILD_OK &&
        vcs_package_build_id(&rebuild, rebuild_id) != VCS_PACKAGE_BUILD_OK)
        berr = VCS_PACKAGE_BUILD_ERR_ROOT;
    struct vcs_reproduce_verdict verdict;
    memset(&verdict, 0, sizeof(verdict));
    if (berr == VCS_PACKAGE_BUILD_OK) {
        vcs_package_reproduce_compare(&reference, &rebuild, &verdict);
        out->matched = verdict.reproduced;
        out->compare_rule = verdict.rule;
        (void)snprintf(out->compare_detail, sizeof(out->compare_detail),
                       "%s", verdict.detail);
    }
    if (berr != VCS_PACKAGE_BUILD_OK || !verdict.reproduced ||
        memcmp(rebuild_id, out->reference_receipt_id, 32) == 0) {
        free(wire);
        ZCL_IGNORE_RESULT(pkgl_rm_rf(p.work), "failed reproduce work removed");
        if (berr != VCS_PACKAGE_BUILD_OK)
            return pkgl_reproduce_refused(
                out, "build-report-invalid",
                ZCL_ERR(-1, "rebuild receipt: %s",
                        vcs_package_build_error_string(berr)));
        if (!verdict.reproduced)
            return pkgl_reproduce_refused(
                out, "reproduce-mismatch",
                ZCL_ERR(-1, "the standard-profile rebuild does NOT reproduce "
                            "the install build: %s %s",
                        vcs_reproduce_rule_string(
                            (enum vcs_reproduce_rule)verdict.rule),
                        verdict.detail));
        return pkgl_reproduce_refused(
            out, "receipt-not-distinct",
            ZCL_ERR(-1, "the rebuild produced the install build's own "
                        "receipt id — no second build event exists"));
    }
    memcpy(out->receipt_id, rebuild_id, 32);

    /* File the second receipt by its exact id, with the install path's
     * atomic-write discipline. */
    char id_hex[65];
    zcl_hex_encode(rebuild_id, 32, id_hex);
    char rel[96];
    (void)snprintf(rel, sizeof(rel), "receipts/%s", id_hex);
    char filed[PKGL_PATH_MAX];
    r = pkgl_join(ctx, rel, filed, sizeof(filed));
    if (r.ok) {
        char parent[PKGL_PATH_MAX];
        (void)snprintf(parent, sizeof(parent), "%s", filed);
        char *slash = strrchr(parent, '/');
        if (!slash)
            r = ZCL_ERR(-1, "filed receipt path has no parent");
        else {
            *slash = '\0';
            r = pkgl_mkdir_p(parent);
        }
    }
    if (r.ok)
        r = pkgl_write_atomic(filed, wire, wire_len);
    free(wire);
    ZCL_IGNORE_RESULT(pkgl_rm_rf(p.work), "reproduce work is not kept");
    if (!r.ok)
        return pkgl_reproduce_refused(out, "receipt-write", r);
    out->filed = true;
    return ZCL_OK;
}

struct zcl_result package_lifecycle_reproduce(
    const char *datadir, const char *name_or_root, const char *fast_cache,
    struct package_lifecycle_reproduce_report *out)
{
    if (!out)
        return ZCL_ERR(-1, "null reproduce report");
    memset(out, 0, sizeof(*out));
    struct pkgl_ctx ctx;
    ZCL_CHECK(pkgl_ctx_open(&ctx, datadir));

    uint8_t root[32];
    struct zcl_result r = pkgl_resolve_target(&ctx, name_or_root, root);
    /* resolve_target already required a release envelope for the root; the
     * lookup is identity, never a selection. */
    const struct vcs_package_release *release =
        r.ok ? pkgl_release_for_root(&ctx, root) : NULL;
    if (r.ok && !release)
        r = ZCL_ERR(-1, "no release names the resolved package root");
    if (!r.ok) {
        pkgl_repro_note(out, "target-unresolved", r.message);
        LOG_ERROR(PKGL_LOG, "reproduce refused (target-unresolved): %s",
                  r.message);
        pkgl_ctx_close(&ctx);
        return r;
    }
    (void)snprintf(out->name, sizeof(out->name), "%s", release->name);
    (void)snprintf(out->semver, sizeof(out->semver), "%s", release->semver);
    memcpy(out->root, root, 32);
    r = pkgl_reproduce_run(&ctx, root, release, fast_cache, out);
    pkgl_ctx_close(&ctx);
    return r;
}
