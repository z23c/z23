/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * corpus-census: per-scope measurement (slice 1b). Builds each scope's
 * release wire (release_root), binds its license and build recipe
 * (license_root, recipe_root, dependency_closure_root), computes the
 * global quality_root over tools/lint/, and rederives release roots for
 * the REPRODUCIBLE bit (a temporary detached worktree at HEAD when git
 * supports it, else a weaker in-process re-enumeration). See the EVIDENCE
 * ROOT RECIPES block at the top of tools/corpus_census.c for the wire
 * format each root commits to.
 */

#define _GNU_SOURCE

#include "corpus_census_priv.h"

#include "base/checked.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "sha3/sha3.h"
#include "vcs/package_release.h"
#include "vcs/package_score.h"
#include "vcs/vcs_object.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

void scope_measure_free(struct scope_measure *m)
{
    if (!m) return;
    free(m->license_path);
    free(m->recipe_path);
    if (m->deps) {
        json_free(m->deps);
        free(m->deps);
    }
    memset(m, 0, sizeof(*m));
}

/* ── dependency closure (shared by repo and package recipe binds) ─── */

static bool dep_entry_extract(const struct json_value *dep,
                              const char **dname, const char **droot,
                              const char **dsemver, const char *scope_name,
                              size_t d)
{
    *dname = json_get_str(json_get(dep, "name"));
    *droot = json_get_str(json_get(dep, "root"));
    *dsemver = json_get_str(json_get(dep, "semver"));
    if (!*dname || !*droot || !*dsemver || strlen(*droot) != 64) {
        LOG_ERROR(CENSUS_LOG, "scope %s: malformed dependency %zu",
                  scope_name, d);
        return false;
    }
    return true;
}

static bool dep_entry_append(struct json_value *deps, struct buf *cwire,
                             const char *dname, const char *droot,
                             const char *dsemver)
{
    struct json_value row;
    json_init(&row);
    json_set_object(&row);
    (void)json_push_kv_str(&row, "name", dname);
    (void)json_push_kv_str(&row, "root", droot);
    (void)json_push_kv_str(&row, "semver", dsemver);
    (void)json_push_back(deps, &row);
    json_free(&row);
    return buf_put(cwire, dname, strlen(dname) + 1u) &&
           buf_put(cwire, droot, strlen(droot) + 1u) &&
           buf_put(cwire, dsemver, strlen(dsemver) + 1u);
}

static bool dep_closure_collect(const struct json_value *list,
                                struct json_value *deps, struct buf *cwire,
                                const char *scope_name)
{
    for (size_t d = 0; d < list->num_children; d++) {
        const struct json_value *dep = json_at(list, d);
        const char *dname = NULL, *droot = NULL, *dsemver = NULL;
        if (!dep_entry_extract(dep, &dname, &droot, &dsemver, scope_name, d))
            return false;
        if (!dep_entry_append(deps, cwire, dname, droot, dsemver))
            return false;
    }
    return true;
}

/* Pinned dependencies from a zcode-package.json document -> the dependency
 * closure wire (file order) plus the owned m->deps JSON array for the
 * evidence bundle. Shared by the repo-scope and package-scope binds. */
bool dep_closure_bind(struct scope_measure *m, const uint8_t *bytes,
                      size_t blen, const char *scope_name,
                      const char *meta_path)
{
    struct buf cwire = {0};
    struct json_value doc;
    json_init(&doc);
    if (!m || m->deps)
        LOG_FAIL(CENSUS_LOG, "dependency closure output is invalid");
    struct json_value *deps = zcl_malloc(sizeof(*deps), "corpus.deps");
    if (!deps)
        LOG_FAIL(CENSUS_LOG, "deps json alloc");
    json_init(deps);
    json_set_array(deps);
    bool ok = true;
    if (!json_read(&doc, (const char *)bytes, blen)) {
        LOG_ERROR(CENSUS_LOG, "scope %s: %s is not valid JSON",
                  scope_name, meta_path);
        ok = false;
    }
    const struct json_value *list =
        ok ? json_get(&doc, "dependencies") : NULL;
    if (ok && list && list->type != JSON_ARR) {
        LOG_ERROR(CENSUS_LOG, "scope %s: dependencies not an array",
                  scope_name);
        ok = false;
    }
    if (ok && list)
        ok = dep_closure_collect(list, deps, &cwire, scope_name);
    json_free(&doc);
    if (ok)
        ok = evidence_root(k_domain_dep_closure, cwire.p, cwire.len,
                           m->dep_closure_root);
    buf_free(&cwire);
    if (ok) {
        m->deps = deps;
        deps = NULL;
    }
    if (deps) {
        json_free(deps);
        free(deps);
    }
    return ok;
}

/* ── release wire ─────────────────────────────────────────────────── */

/* physical/production/test LOC tally plus the has_api / has_tests_sem bits
 * for one already-loaded file. */
static bool scope_measure_tally(struct scope_measure *measure,
                                const char *path, const uint8_t *bytes,
                                size_t len, bool via_tests,
                                const char *scope_name)
{
    enum vcs_score_exclude_reason reason = VCS_SCORE_EXCLUDE_NONE;
    enum vcs_score_file_kind kind = vcs_score_classify_path(path, &reason);
    struct vcs_score_line_tally tally;
    memset(&tally, 0, sizeof(tally));
    vcs_score_classify_lines(bytes, len, &tally);
    uint64_t physical = (uint64_t)tally.semantic + tally.blank +
                        tally.comment_only + tally.brace_only;
    if (!zcl_u64_add(measure->physical, physical, &measure->physical))
        LOG_FAIL(CENSUS_LOG, "scope %s: physical overflow", scope_name);
    if (kind != VCS_SCORE_FILE_EXCLUDED) {
        uint64_t *dst =
            kind == VCS_SCORE_FILE_TEST ? &measure->test_loc
                                        : &measure->prod_loc;
        if (!zcl_u64_add(*dst, tally.semantic, dst))
            LOG_FAIL(CENSUS_LOG, "scope %s: loc overflow", scope_name);
    }
    size_t plen = strlen(path);
    if (tally.semantic && plen >= 2 && strcmp(path + plen - 2, ".h") == 0)
        measure->has_api = true;
    if (tally.semantic && via_tests)
        measure->has_tests_sem = true;
    return true;
}

/* COMPLETE_POSSESSION probe for one repo-scope file: store the blob into
 * the repo .zvcs CAS, re-read it (the get re-verifies the content hash),
 * and byte-compare. A CAS put/verify failure is a soft outcome (clears
 * possession_ok and keeps scanning); only a hard allocation failure
 * returns false. */
static bool scope_measure_possession_probe(const char *root, const char *path,
                                           const uint8_t *bytes, size_t len,
                                           struct scope_measure *measure,
                                           struct str_vec *blob_hashes,
                                           const char *scope_name)
{
    uint8_t hash[32];
    if (!vcs_object_put(root, bytes, len, VCS_TAG_BLOB, hash)) {
        LOG_ERROR(CENSUS_LOG, "scope %s: CAS put failed for %s", scope_name,
                  path);
        measure->possession_ok = false;
        return true;
    }
    uint8_t *back = NULL;
    size_t back_len = 0;
    if (vcs_object_get(root, hash, VCS_TAG_BLOB, &back, &back_len) != 0 ||
        back_len != len || (len && memcmp(back, bytes, len) != 0)) {
        LOG_ERROR(CENSUS_LOG, "scope %s: CAS verify failed for %s",
                  scope_name, path);
        measure->possession_ok = false;
        free(back);
        return true;
    }
    char hex[65];
    zcl_hex_encode(hash, 32, hex);
    bool pushed = vec_push(blob_hashes, hex);
    free(back);
    if (!pushed)
        LOG_FAIL(CENSUS_LOG, "blob hash vec push");
    return true;
}

/* Load one scope file's bytes (repo or package CAS), append it to the
 * release wire, and — when `measure` is non-NULL — tally its LOC and probe
 * its possession. */
static bool scope_release_wire_load_and_append(
    const char *root, const struct scope_files *sf, size_t i,
    const struct package_ctx *pkg, struct buf *wire, const char *scope_name,
    struct scope_measure *measure, struct str_vec *blob_hashes)
{
    const char *path = sf->paths[i];
    uint8_t *bytes = NULL;
    size_t len = 0;
    uint64_t declared = 0;
    bool loaded = pkg
        ? package_file_load(pkg, path, &bytes, &len, &declared)
        : file_load(root, path, &bytes, &len, &declared);
    if (!loaded)
        LOG_FAIL(CENSUS_LOG, "scope %s: cannot read %s", scope_name, path);
    uint8_t digest[32];
    sha3_256(bytes, bytes ? len : 0, digest);
    if (!buf_put(wire, path, strlen(path) + 1u) ||
        !buf_put_u64le(wire, declared) ||
        !buf_put(wire, digest, sizeof(digest))) {
        free(bytes);
        LOG_FAIL(CENSUS_LOG, "scope %s: release wire build failed",
                 scope_name);
    }
    if (measure) {
        measure->file_count++;
        if (bytes) {
            if (!scope_measure_tally(measure, path, bytes, len,
                                     sf->via_tests[i], scope_name)) {
                free(bytes);
                return false;
            }
            /* Package scopes skip the CAS probe: the chunk-verified CAS
             * read already proved possession of this file's exact bytes. */
            if (!pkg && !scope_measure_possession_probe(
                            root, path, bytes, len, measure, blob_hashes,
                            scope_name)) {
                free(bytes);
                return false;
            }
        } else {
            /* Oversize/unavailable content can never be possessed. */
            measure->possession_ok = false;
        }
    }
    free(bytes);
    return true;
}

static bool scope_release_possession_root_build(struct str_vec *blob_hashes,
                                                struct scope_measure *measure,
                                                const char *scope_name)
{
    qsort(blob_hashes->v, blob_hashes->n, sizeof(char *), cmp_strp);
    struct buf pwire = {0};
    bool ok = true;
    for (size_t i = 0; ok && i < blob_hashes->n; i++) {
        uint8_t hash[32];
        if (!zcl_hex_decode_lower(blob_hashes->v[i], hash, 32) ||
            !buf_put(&pwire, hash, 32))
            ok = false;
    }
    if (ok)
        ok = evidence_root(k_domain_possession, pwire.p, pwire.len,
                           measure->possession_root);
    buf_free(&pwire);
    if (!ok)
        LOG_FAIL(CENSUS_LOG, "scope %s: possession root failed", scope_name);
    return true;
}

/* The release wire for one scope's claimed files under `root`:
 * concat over sorted paths of path || NUL || u64-LE size || sha3(content).
 * When `measure` is NULL this is the pure rederivation (worktree pass);
 * no CAS writes, no tallies. When `pkg` is non-NULL the paths are
 * package-relative and the bytes come from the package store's CAS
 * (verify-on-read) instead of the repo tree. */
bool scope_release_wire(const char *root, const struct scope_files *sf,
                        struct buf *wire, struct scope_measure *measure,
                        const char *scope_name, const struct package_ctx *pkg)
{
    struct str_vec blob_hashes = {0}; /* hex, for the possession root */
    for (size_t i = 0; i < sf->n; i++) {
        if (!scope_release_wire_load_and_append(root, sf, i, pkg, wire,
                                                scope_name, measure,
                                                &blob_hashes)) {
            vec_free(&blob_hashes);
            return false;
        }
    }
    if (measure && measure->possession_ok && blob_hashes.n &&
        !scope_release_possession_root_build(&blob_hashes, measure,
                                             scope_name)) {
        vec_free(&blob_hashes);
        return false;
    }
    vec_free(&blob_hashes);
    return true;
}

/* ── license bind ──────────────────────────────────────────────────── */

static bool scope_license_bind_package(const struct scope_def *def,
                                       struct scope_measure *m,
                                       const struct package_ctx *pkg)
{
    uint8_t *bytes = NULL;
    size_t len = 0;
    uint64_t declared = 0;
    if (!package_file_load(pkg, "LICENSE", &bytes, &len, &declared) ||
        !bytes) {
        LOG_ERROR(CENSUS_LOG, "package %s: cannot read LICENSE", def->name);
        free(bytes);
        return false;
    }
    struct buf wire = {0};
    uint8_t digest[32];
    sha3_256(bytes, len, digest);
    bool built = buf_put(&wire, "LICENSE", sizeof("LICENSE")) &&
                 buf_put_u64le(&wire, declared) &&
                 buf_put(&wire, digest, sizeof(digest));
    free(bytes);
    if (built)
        built = evidence_root(k_domain_license, wire.p, wire.len,
                              m->license_root);
    buf_free(&wire);
    if (!built)
        LOG_FAIL(CENSUS_LOG, "package %s: license root failed", def->name);
    m->license_path = dup_str("LICENSE", "corpus.lic.bound");
    if (!m->license_path)
        LOG_FAIL(CENSUS_LOG, "license path dup");
    m->license_ok = vcs_package_release_license_allowed(def->spdx);
    if (!m->license_ok)
        LOG_WARN(CENSUS_LOG, "package %s: spdx %s is off the v1 "
                 "allowlist", def->name, def->spdx);
    return true;
}

static bool license_candidates_build(const struct scope_def *def,
                                     struct str_vec *candidates)
{
    for (size_t i = 0; i < def->nsrc; i++) {
        if (!def->src[i].is_dir) continue;
        size_t len = strlen(def->src[i].text) + strlen("LICENSE") + 1u;
        char *rel = zcl_malloc(len, "corpus.lic.path");
        if (!rel)
            LOG_FAIL(CENSUS_LOG, "license path alloc");
        (void)snprintf(rel, len, "%sLICENSE", def->src[i].text);
        if (!vec_push(candidates, rel)) {
            free(rel);
            LOG_FAIL(CENSUS_LOG, "license candidate push");
        }
        free(rel);
    }
    if (!vec_push(candidates, "LICENSE"))
        LOG_FAIL(CENSUS_LOG, "license candidate push");
    return true;
}

/* Try one license candidate path: *bound stays false when the candidate
 * does not exist (keep looking); the bool return is false only for a hard
 * read/root failure once the candidate is known to exist. */
static bool license_try_candidate(const char *root, const char *candidate,
                                  const struct scope_def *def,
                                  struct scope_measure *m, bool *bound)
{
    *bound = false;
    uint8_t *bytes = NULL;
    size_t len = 0;
    uint64_t declared = 0;
    size_t full_len = strlen(root) + strlen(candidate) + 2u;
    char *full = zcl_malloc(full_len, "corpus.lic.full");
    if (!full)
        LOG_FAIL(CENSUS_LOG, "license full path alloc");
    (void)snprintf(full, full_len, "%s/%s", root, candidate);
    bool exists = access(full, R_OK) == 0;
    free(full);
    if (!exists) return true;
    if (!file_load(root, candidate, &bytes, &len, &declared) || !bytes) {
        LOG_ERROR(CENSUS_LOG, "scope %s: cannot read license %s", def->name,
                  candidate);
        return false;
    }
    struct buf wire = {0};
    uint8_t digest[32];
    sha3_256(bytes, len, digest);
    bool built = buf_put(&wire, candidate, strlen(candidate) + 1u) &&
                 buf_put_u64le(&wire, declared) &&
                 buf_put(&wire, digest, sizeof(digest));
    free(bytes);
    if (built)
        built = evidence_root(k_domain_license, wire.p, wire.len,
                              m->license_root);
    buf_free(&wire);
    if (!built) return false;
    m->license_path = dup_str(candidate, "corpus.lic.bound");
    if (!m->license_path) return false;
    m->license_ok = vcs_package_release_license_allowed(def->spdx);
    if (!m->license_ok)
        LOG_WARN(CENSUS_LOG, "scope %s: spdx %s is off the v1 "
                 "allowlist", def->name, def->spdx);
    *bound = true;
    return true;
}

static bool scope_license_bind_repo(const char *root,
                                    const struct scope_def *def,
                                    struct scope_measure *m)
{
    struct str_vec candidates = {0};
    if (!license_candidates_build(def, &candidates)) {
        vec_free(&candidates);
        return false;
    }
    bool ok = false;
    for (size_t i = 0; i < candidates.n; i++) {
        bool bound = false;
        if (!license_try_candidate(root, candidates.v[i], def, m, &bound)) {
            vec_free(&candidates);
            return false;
        }
        if (bound) {
            ok = true;
            break;
        }
    }
    if (!ok)
        LOG_ERROR(CENSUS_LOG, "scope %s: no license file found", def->name);
    vec_free(&candidates);
    return ok;
}

/* Bind the scope's license: the first scope-local LICENSE among its src
 * directory prefixes, else the repo-root LICENSE. A package scope binds
 * its own LICENSE from the store (the fixed package layout requires one);
 * the def spdx was already cross-checked against the release envelope. */
bool scope_license_bind(const char *root, const struct scope_def *def,
                        struct scope_measure *m, const struct package_ctx *pkg)
{
    if (pkg) return scope_license_bind_package(def, m, pkg);
    return scope_license_bind_repo(root, def, m);
}

/* ── recipe bind ───────────────────────────────────────────────────── */

/* Try one src directory's zcode-package.json: *bound stays false when the
 * directory is not a directory prefix or the file does not exist there. */
static bool scope_recipe_try_srcdir(const char *root,
                                    const struct scope_def *def,
                                    const struct prefix *srcdir,
                                    struct scope_measure *m, bool *bound)
{
    *bound = false;
    if (!srcdir->is_dir) return true;
    const char *name = "zcode-package.json";
    size_t len = strlen(srcdir->text) + strlen(name) + 1u;
    char *rel = zcl_malloc(len, "corpus.recipe.path");
    if (!rel)
        LOG_FAIL(CENSUS_LOG, "recipe path alloc");
    (void)snprintf(rel, len, "%s%s", srcdir->text, name);
    size_t full_len = strlen(root) + len + 1u;
    char *full = zcl_malloc(full_len, "corpus.recipe.full");
    if (!full) {
        free(rel);
        LOG_FAIL(CENSUS_LOG, "recipe full path alloc");
    }
    (void)snprintf(full, full_len, "%s/%s", root, rel);
    bool exists = access(full, R_OK) == 0;
    free(full);
    if (!exists) {
        free(rel);
        return true;
    }
    uint8_t *bytes = NULL;
    size_t blen = 0;
    uint64_t declared = 0;
    if (!file_load(root, rel, &bytes, &blen, &declared) || !bytes) {
        LOG_ERROR(CENSUS_LOG, "scope %s: cannot read %s", def->name, rel);
        free(rel);
        return false;
    }
    /* Pinned dependencies -> dependency closure wire (file order). */
    bool ok = dep_closure_bind(m, bytes, blen, def->name, rel);
    if (ok) {
        uint8_t digest[32];
        struct buf rwire = {0};
        sha3_256(bytes, blen, digest);
        ok = buf_put(&rwire, rel, strlen(rel) + 1u) &&
             buf_put_u64le(&rwire, declared) &&
             buf_put(&rwire, digest, sizeof(digest)) &&
             evidence_root(k_domain_recipe, rwire.p, rwire.len,
                           m->recipe_root);
        buf_free(&rwire);
    }
    free(bytes);
    if (!ok) {
        free(rel);
        LOG_FAIL(CENSUS_LOG, "scope %s: recipe bind failed", def->name);
    }
    m->recipe_path = rel;
    m->recipe_is_package = true;
    *bound = true;
    return true;
}

/* Declared core scope fallback: the repo Makefile is the build recipe,
 * with an empty dependency closure root (no declared pinned deps). */
static bool scope_recipe_bind_makefile(const char *root,
                                       const struct scope_def *def,
                                       struct scope_measure *m)
{
    uint8_t *bytes = NULL;
    size_t blen = 0;
    uint64_t declared = 0;
    if (!file_load(root, "Makefile", &bytes, &blen, &declared) || !bytes)
        LOG_FAIL(CENSUS_LOG, "scope %s: cannot read repo Makefile",
                 def->name);
    uint8_t digest[32];
    struct buf rwire = {0};
    sha3_256(bytes, blen, digest);
    free(bytes);
    bool ok = buf_put(&rwire, "Makefile", sizeof("Makefile")) &&
              buf_put_u64le(&rwire, declared) &&
              buf_put(&rwire, digest, sizeof(digest)) &&
              evidence_root(k_domain_recipe, rwire.p, rwire.len,
                            m->recipe_root);
    buf_free(&rwire);
    if (!ok)
        LOG_FAIL(CENSUS_LOG, "scope %s: Makefile recipe root failed",
                 def->name);
    if (!evidence_root(k_domain_dep_closure, NULL, 0, m->dep_closure_root))
        LOG_FAIL(CENSUS_LOG, "scope %s: empty closure root failed",
                 def->name);
    m->recipe_path = dup_str("Makefile", "corpus.recipe.bound");
    if (!m->recipe_path)
        LOG_FAIL(CENSUS_LOG, "recipe path dup");
    m->recipe_is_package = false;
    return true;
}

/* Bind the scope's build recipe: its zcode-package.json when one exists at
 * a src directory prefix (pinned dependencies feed the admission closure
 * root), else the repo Makefile (the declared core-scope build recipe). A
 * package scope binds the release envelope's recipe from the store. */
bool scope_recipe_bind(const char *root, const struct scope_def *def,
                       struct scope_measure *m, const struct package_ctx *pkg)
{
    if (pkg) return package_recipe_bind(def, m, pkg);
    for (size_t i = 0; i < def->nsrc; i++) {
        bool bound = false;
        if (!scope_recipe_try_srcdir(root, def, &def->src[i], m, &bound))
            return false;
        if (bound) return true;
    }
    return scope_recipe_bind_makefile(root, def, m);
}

/* ── reproduction (REPRODUCIBLE bit) ──────────────────────────────── */

/* Re-enumerate every scope under `root` and recompute its release root.
 * Returns false only on hard failure; per-scope mismatch is reported
 * through matched[i]. */
bool rederive_release_roots(const char *root, const struct scope_def *defs,
                            size_t scope_count,
                            const uint8_t (*expected)[32], bool *matched)
{
    struct scope_files *files = NULL;
    if (!claims_resolve(root, defs, scope_count, &files))
        LOG_FAIL(CENSUS_LOG, "re-enumeration under %s failed", root);
    bool ok = true;
    for (size_t s = 0; ok && s < scope_count; s++) {
        /* Package scopes are not in git: their reproduction binding is the
         * receipts scan, preset in matched[s] by the caller. */
        if (defs[s].is_package) continue;
        struct buf wire = {0};
        if (!scope_release_wire(root, &files[s], &wire, NULL,
                                defs[s].name, NULL)) {
            ok = false;
            buf_free(&wire);
            break;
        }
        uint8_t root_out[32];
        if (!evidence_root(k_domain_release, wire.p, wire.len, root_out)) {
            buf_free(&wire);
            ok = false;
            break;
        }
        buf_free(&wire);
        matched[s] = memcmp(root_out, expected[s], 32) == 0;
        if (!matched[s])
            LOG_WARN(CENSUS_LOG,
                     "scope %s: rederived release root differs under %s",
                     defs[s].name, root);
    }
    for (size_t s = 0; s < scope_count; s++) scope_files_free(&files[s]);
    free(files);
    return ok;
}

/* Dual-materialization rederivation: check the repo out at HEAD into a
 * temporary detached worktree, re-enumerate and recompute every scope's
 * release_root there, and require byte-identical roots. A scope whose
 * content is not fully committed at HEAD (e.g. not-yet-committed driver
 * files) honestly mismatches and loses the bit; the report names it. On
 * any worktree machinery failure the caller falls back to an in-process
 * re-enumeration pass (weaker binding, disclosed). */
bool worktree_rederive(const char *repo, const struct scope_def *defs,
                       size_t scope_count, const uint8_t (*expected)[32],
                       bool *matched, bool *worktree_used)
{
    *worktree_used = false;
    char tmp[512];
    const char *tmpdir = getenv("TMPDIR");
    if (!tmpdir || !shell_safe(tmpdir)) tmpdir = "/tmp";
    if (snprintf(tmp, sizeof(tmp), "%s/corpus-census-wt-XXXXXX", tmpdir) >=
        (int)sizeof(tmp))
        LOG_FAIL(CENSUS_LOG, "worktree path template overflow");
    if (!mkdtemp(tmp))
        LOG_FAIL(CENSUS_LOG, "mkdtemp under %s: %s", tmpdir,
                 strerror(errno));
    char cmd[1024];
    if (snprintf(cmd, sizeof(cmd),
                 "git -C '%s' worktree add --detach '%s' HEAD >/dev/null 2>&1",
                 repo, tmp) >= (int)sizeof(cmd)) {
        rmdir(tmp);
        LOG_FAIL(CENSUS_LOG, "worktree command overflow");
    }
    int status = system(cmd); /* shellout-ok: standalone CLI tool */
    if (status == -1 || !WIFEXITED(status) || WEXITSTATUS(status)) {
        LOG_WARN(CENSUS_LOG,
                 "git worktree add failed (status=%d); falling back to "
                 "in-process re-enumeration", status);
        rmdir(tmp);
        return true;
    }
    *worktree_used = true;
    bool ok = rederive_release_roots(tmp, defs, scope_count, expected,
                                     matched);
    if (snprintf(cmd, sizeof(cmd),
                 "git -C '%s' worktree remove --force '%s' >/dev/null 2>&1",
                 repo, tmp) < (int)sizeof(cmd)) {
        status = system(cmd); /* shellout-ok: standalone CLI tool */
        if (status == -1 || !WIFEXITED(status) || WEXITSTATUS(status))
            LOG_WARN(CENSUS_LOG,
                     "git worktree remove failed for %s (status=%d); "
                     "leaving the temp dir for the operator", tmp, status);
    }
    if (!ok)
        LOG_FAIL(CENSUS_LOG, "worktree rederivation failed");
    return true;
}

/* ── quality profile (QUALITY_PROFILE bit) ────────────────────────── */

static bool quality_git_ls_lint_files(const char *root, struct str_vec *paths)
{
    char cmd[CORPUS_CENSUS_CMD_MAX];
    if (snprintf(cmd, sizeof(cmd), "git -C '%s' ls-files -z -- tools/lint",
                 root) >= (int)sizeof(cmd))
        LOG_FAIL(CENSUS_LOG, "quality git command overflow");
    FILE *pipe = popen(cmd, "r"); /* shellout-ok: standalone CLI tool */
    if (!pipe)
        LOG_FAIL(CENSUS_LOG, "popen git ls-files tools/lint");
    struct buf raw = {0};
    uint8_t chunk[65536];
    size_t got;
    bool ok = true;
    while ((got = fread(chunk, 1, sizeof(chunk), pipe)) > 0) {
        if (!buf_put(&raw, chunk, got)) {
            ok = false;
            break;
        }
    }
    int status = pclose(pipe); /* shellout-ok: standalone CLI tool */
    if (!ok || status == -1 || !WIFEXITED(status) || WEXITSTATUS(status)) {
        buf_free(&raw);
        LOG_FAIL(CENSUS_LOG, "git ls-files tools/lint failed");
    }
    size_t off = 0;
    while (off < raw.len) {
        size_t end = off;
        while (end < raw.len && raw.p[end] != 0) end++;
        if (end > off &&
            !vec_push_len(paths, (const char *)raw.p + off, end - off)) {
            buf_free(&raw);
            LOG_FAIL(CENSUS_LOG, "quality path push");
        }
        off = end + 1u;
    }
    buf_free(&raw);
    if (!paths->n)
        LOG_FAIL(CENSUS_LOG, "tools/lint has no tracked files");
    return true;
}

static bool quality_wire_build(const char *root, const struct str_vec *paths,
                               struct buf *wire)
{
    for (size_t i = 0; i < paths->n; i++) {
        uint8_t *bytes = NULL;
        size_t len = 0;
        uint64_t declared = 0;
        if (!file_load(root, paths->v[i], &bytes, &len, &declared) ||
            !bytes)
            return false;
        uint8_t digest[32];
        sha3_256(bytes, len, digest);
        free(bytes);
        if (!buf_put(wire, paths->v[i], strlen(paths->v[i]) + 1u) ||
            !buf_put(wire, digest, sizeof(digest)))
            return false;
    }
    return true;
}

/* quality_root over the sorted (path || NUL || sha3(content)) pairs of
 * every tracked tools/lint/ file. Computed only when the operator passes
 * --quality-attested 1, asserting `make lint` passed at census time. */
bool quality_root_compute(const char *root, uint8_t out[32])
{
    struct str_vec paths = {0};
    if (!quality_git_ls_lint_files(root, &paths)) {
        vec_free(&paths);
        return false;
    }
    qsort(paths.v, paths.n, sizeof(char *), cmp_strp);
    struct buf wire = {0};
    bool ok = quality_wire_build(root, &paths, &wire);
    vec_free(&paths);
    if (ok)
        ok = evidence_root(k_domain_quality, wire.p, wire.len, out);
    buf_free(&wire);
    if (!ok)
        LOG_FAIL(CENSUS_LOG, "quality root computation failed");
    return true;
}
