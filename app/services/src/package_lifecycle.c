/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_lifecycle — THE one ZCODE install lifecycle state machine. See
 * services/package_lifecycle.h for the contract; the adapters it drives are
 * package_lifecycle_store.c (read) and package_lifecycle_install.c (write).
 *
 * This file decides; it does not do. Every filesystem touch, every spawn,
 * every hash is behind a pkgl_* adapter call, and no package byte is ever
 * interpreted as code here. */

#include "package_lifecycle_internal.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/result.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── the DAG loader ─────────────────────────────────────────────────── */

struct pkgl_source {
    const struct pkgl_ctx *ctx;
};

/* Report a root's REAL name/semver (from its release envelope) and its
 * declared direct dependencies. False = unresolvable, which the resolver
 * turns into a named ERR_UNRESOLVED rather than a silent skip. */
static bool pkgl_src_load(void *vctx, const uint8_t root[32],
                          char name_out[VCS_PACKAGE_RELEASE_NAME_MAX + 1u],
                          char semver_out[VCS_PACKAGE_RELEASE_SEMVER_MAX + 1u],
                          struct vcs_package_deps *deps_out)
{
    struct pkgl_source *src = vctx;
    if (!src || !src->ctx)
        LOG_FAIL(PKGL_LOG, "dependency loader has no context");
    const struct vcs_package_release *rel =
        pkgl_release_for_root(src->ctx, root);
    if (!rel)
        return false; /* ERR_UNRESOLVED, named by the resolver */
    (void)snprintf(name_out, VCS_PACKAGE_RELEASE_NAME_MAX + 1u, "%s",
                   rel->name);
    (void)snprintf(semver_out, VCS_PACKAGE_RELEASE_SEMVER_MAX + 1u, "%s",
                   rel->semver);
    struct zcl_result r = pkgl_load_declared_deps(src->ctx, root, deps_out);
    if (!r.ok)
        LOG_FAIL(PKGL_LOG, "%s", r.message);
    return true;
}

/* ── small helpers ──────────────────────────────────────────────────── */

static void pkgl_note(char *rule, size_t rule_cap, char *detail,
                      size_t detail_cap, const char *rule_text,
                      const char *detail_text)
{
    (void)snprintf(rule, rule_cap, "%s", rule_text);
    (void)snprintf(detail, detail_cap, "%s", detail_text);
}

static const struct vcs_package_release *pkgl_release_for_name_semver(
    const struct pkgl_ctx *ctx, const char *name, size_t name_len,
    const char *semver)
{
    if (!ctx || !name || name_len == 0 ||
        name_len > VCS_PACKAGE_RELEASE_NAME_MAX || !semver || !semver[0])
        return NULL;
    const struct vcs_package_release *best = NULL;
    for (size_t i = 0; i < ctx->release_count; i++) {
        const struct vcs_package_release *release = &ctx->releases[i];
        if (strlen(release->name) != name_len ||
            memcmp(release->name, name, name_len) != 0 ||
            strcmp(release->semver, semver) != 0)
            continue;
        if (!best || release->publisher_sequence > best->publisher_sequence)
            best = release;
    }
    return best;
}

/* `name_or_root` is 64 hex (identity), "publisher/package@semver" (an exact
 * version selection), or "publisher/package" (a selection that resolves to
 * the highest published semver). Every later lifecycle step is root-pinned. */
struct zcl_result pkgl_resolve_target(const struct pkgl_ctx *ctx,
                                      const char *name_or_root,
                                      uint8_t out_root[32])
{
    if (!name_or_root || !name_or_root[0])
        return ZCL_ERR(-1, "name_or_root is required");
    if (strlen(name_or_root) == 64u &&
        zcl_hex_decode_lower(name_or_root, out_root, 32)) {
        if (!pkgl_release_for_root(ctx, out_root))
            return ZCL_ERR(-1, "no release names package root %s",
                           name_or_root);
        return ZCL_OK;
    }
    const char *at = strrchr(name_or_root, '@');
    const struct vcs_package_release *rel = at
        ? pkgl_release_for_name_semver(
              ctx, name_or_root, (size_t)(at - name_or_root), at + 1)
        : pkgl_release_for_name(ctx, name_or_root);
    if (!rel)
        return ZCL_ERR(-1, "no package named '%s' is published here",
                       name_or_root);
    memcpy(out_root, rel->package_root, 32);
    return ZCL_OK;
}

static struct zcl_result pkgl_lock_for(const struct pkgl_ctx *ctx,
                                       const uint8_t target_root[32],
                                       struct vcs_package_lock *lock,
                                       uint8_t lock_root[32])
{
    struct pkgl_source src_ctx = { .ctx = ctx };
    struct vcs_package_deps_source src = { .ctx = &src_ctx,
                                           .load = pkgl_src_load };
    char detail[160];
    detail[0] = '\0';
    enum vcs_package_deps_error err = vcs_package_lock_resolve(
        target_root, &src, lock, detail, sizeof(detail));
    if (err != VCS_PACKAGE_DEPS_OK)
        return ZCL_ERR(-1, "%s%s%s", vcs_package_deps_error_string(err),
                       detail[0] ? ": " : "", detail);
    err = vcs_package_lock_root(lock, lock_root);
    if (err != VCS_PACKAGE_DEPS_OK)
        return ZCL_ERR(-1, "cannot hash the dependency lock: %s",
                       vcs_package_deps_error_string(err));
    return ZCL_OK;
}

static struct zcl_result pkgl_plan_path(const struct pkgl_ctx *ctx,
                                        const uint8_t plan_id[32], char *out,
                                        size_t cap)
{
    char hex[65];
    zcl_hex_encode(plan_id, 32, hex);
    char rel[96];
    (void)snprintf(rel, sizeof(rel), "addplans/%s", hex);
    return pkgl_join(ctx, rel, out, cap);
}

struct zcl_result package_lifecycle_receipt_read(
    const char *datadir, const uint8_t receipt_id[32],
    struct vcs_package_build_receipt *out)
{
    if (!receipt_id || !out)
        return ZCL_ERR(-1, "receipt id and output are required");
    memset(out, 0, sizeof(*out));
    struct pkgl_ctx ctx;
    ZCL_CHECK(pkgl_ctx_open(&ctx, datadir));
    char id_hex[65], relative[96], path[PKGL_PATH_MAX];
    zcl_hex_encode(receipt_id, 32, id_hex);
    (void)snprintf(relative, sizeof(relative), "receipts/%s", id_hex);
    struct zcl_result result = pkgl_join(&ctx, relative, path, sizeof(path));
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (result.ok)
        result = pkgl_read_file(path, VCS_PACKAGE_BUILD_MAX_WIRE_BYTES,
                                &wire, &wire_len);
    if (result.ok) {
        enum vcs_package_build_error parsed =
            vcs_package_build_parse(wire, wire_len, out);
        if (parsed != VCS_PACKAGE_BUILD_OK)
            result = ZCL_ERR(-1, "filed receipt: %s",
                             vcs_package_build_error_string(parsed));
    }
    uint8_t rederived[32];
    if (result.ok &&
        (vcs_package_build_id(out, rederived) != VCS_PACKAGE_BUILD_OK ||
         memcmp(rederived, receipt_id, 32) != 0))
        result = ZCL_ERR(-1, "filed receipt does not hash to its exact id");
    free(wire);
    pkgl_ctx_close(&ctx);
    if (!result.ok) memset(out, 0, sizeof(*out));
    return result;
}

/* ── plan ───────────────────────────────────────────────────────────── */

// long-function-ok:one-plan-derivation — resolving the target, locking the
// DAG, surveying every node and stamping the expiry are one derivation; a
// caller must never be able to obtain a plan whose steps were surveyed
// against a different lock than the one it commits to.
struct zcl_result package_lifecycle_plan(
    const char *datadir, const char *name_or_root, int64_t now_unix,
    struct package_lifecycle_plan_report *out)
{
    if (!out)
        return ZCL_ERR(-1, "null plan report");
    memset(out, 0, sizeof(*out));
    vcs_package_plan_init(&out->plan);

    struct pkgl_ctx ctx;
    ZCL_CHECK(pkgl_ctx_open(&ctx, datadir));

    uint8_t target[32];
    struct zcl_result r = pkgl_resolve_target(&ctx, name_or_root, target);
    if (!r.ok) {
        pkgl_note(out->rule, sizeof(out->rule), out->detail,
                  sizeof(out->detail), "target-unresolved", r.message);
        pkgl_ctx_close(&ctx);
        return r;
    }

    struct vcs_package_lock lock;
    uint8_t lock_root[32];
    r = pkgl_lock_for(&ctx, target, &lock, lock_root);
    if (!r.ok) {
        pkgl_note(out->rule, sizeof(out->rule), out->detail,
                  sizeof(out->detail), "dependency-lock", r.message);
        pkgl_ctx_close(&ctx);
        return r;
    }

    memcpy(out->plan.target_root, target, 32);
    memcpy(out->plan.lock_root, lock_root, 32);
    out->plan.created_unix = now_unix;
    out->plan.expires_unix = now_unix + VCS_PACKAGE_PLAN_TTL_SECONDS;
    out->plan.step_count = lock.count;
    out->ready = true;

    for (size_t i = 0; i < lock.count; i++) {
        const struct vcs_package_lock_node *n = &lock.nodes[i];
        struct vcs_package_plan_step *s = &out->plan.steps[i];
        memcpy(s->root, n->root, 32);
        (void)snprintf(s->name, sizeof(s->name), "%s", n->name);
        (void)snprintf(s->semver, sizeof(s->semver), "%s", n->semver);
        s->depth = n->depth;
        const struct vcs_package_release *rel =
            pkgl_release_for_root(&ctx, n->root);
        if (rel)
            (void)snprintf(s->license, sizeof(s->license), "%s", rel->license);

        char installed[PKGL_PATH_MAX];
        r = pkgl_installed_dir(&ctx, n->root, installed, sizeof(installed));
        if (r.ok)
            r = pkgl_exists(installed, &s->installed);
        if (r.ok)
            r = pkgl_survey_package(&ctx, n->root, &s->complete,
                                    &s->total_bytes, &s->total_chunks);
        if (!r.ok) {
            pkgl_note(out->rule, sizeof(out->rule), out->detail,
                      sizeof(out->detail), "survey-failed", r.message);
            pkgl_ctx_close(&ctx);
            return r;
        }

        if (s->installed) {
            s->state = VCS_PACKAGE_LIFECYCLE_INSTALLED;
        } else if (!s->complete) {
            /* Honest phase boundary: this layer does not fetch. */
            s->state = VCS_PACKAGE_LIFECYCLE_FETCHING;
            out->ready = false;
            if (!out->rule[0])
                pkgl_note(out->rule, sizeof(out->rule), out->detail,
                          sizeof(out->detail), "package-incomplete", s->name);
        } else {
            char vrule[PACKAGE_LIFECYCLE_RULE_MAX + 1u];
            struct zcl_result vr = pkgl_verify_package(&ctx, n->root, vrule,
                                                       sizeof(vrule));
            if (vr.ok) {
                s->state = VCS_PACKAGE_LIFECYCLE_VERIFIED;
            } else {
                s->state = VCS_PACKAGE_LIFECYCLE_DISCOVERED;
                out->ready = false;
                if (!out->rule[0])
                    pkgl_note(out->rule, sizeof(out->rule), out->detail,
                              sizeof(out->detail),
                              vrule[0] ? vrule : "verify-failed", vr.message);
            }
        }
    }

    enum vcs_package_install_error perr = vcs_package_plan_validate(&out->plan);
    if (perr == VCS_PACKAGE_INSTALL_OK)
        perr = vcs_package_plan_id(&out->plan, out->plan_id);
    if (perr != VCS_PACKAGE_INSTALL_OK) {
        pkgl_note(out->rule, sizeof(out->rule), out->detail,
                  sizeof(out->detail), "plan-invalid",
                  vcs_package_install_error_string(perr));
        pkgl_ctx_close(&ctx);
        return ZCL_ERR(-1, "plan rejected: %s",
                       vcs_package_install_error_string(perr));
    }

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    perr = vcs_package_plan_serialize(&out->plan, &wire, &wire_len);
    if (perr != VCS_PACKAGE_INSTALL_OK) {
        pkgl_note(out->rule, sizeof(out->rule), out->detail,
                  sizeof(out->detail), "plan-encode",
                  vcs_package_install_error_string(perr));
        pkgl_ctx_close(&ctx);
        return ZCL_ERR(-1, "cannot encode the plan: %s",
                       vcs_package_install_error_string(perr));
    }
    char path[PKGL_PATH_MAX];
    r = pkgl_plan_path(&ctx, out->plan_id, path, sizeof(path));
    if (r.ok) {
        char dir[PKGL_PATH_MAX];
        r = pkgl_join(&ctx, "addplans", dir, sizeof(dir));
        if (r.ok)
            r = pkgl_mkdir_p(dir);
        if (r.ok)
            r = pkgl_write_atomic(path, wire, wire_len);
    }
    free(wire);
    pkgl_ctx_close(&ctx);
    if (!r.ok) {
        pkgl_note(out->rule, sizeof(out->rule), out->detail,
                  sizeof(out->detail), "plan-write", r.message);
        return r;
    }
    return ZCL_OK;
}

/* ── commit ─────────────────────────────────────────────────────────── */

/* Load the plan named by `plan_id`, refusing an edited file (the id is a
 * commitment to every field, so an edit renames it) and an expired one. */
static struct zcl_result pkgl_load_plan(const struct pkgl_ctx *ctx,
                                        const uint8_t plan_id[32],
                                        int64_t now_unix,
                                        struct vcs_package_plan *out,
                                        char *rule, size_t rule_cap)
{
    char path[PKGL_PATH_MAX];
    ZCL_CHECK(pkgl_plan_path(ctx, plan_id, path, sizeof(path)));
    bool present = false;
    ZCL_CHECK(pkgl_exists(path, &present));
    if (!present) {
        (void)snprintf(rule, rule_cap, "plan-unknown");
        return ZCL_ERR(-1, "no such plan — run 'zcode package add plan' "
                           "first, or the plan was already pruned");
    }
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    ZCL_CHECK(pkgl_read_file(path, VCS_PACKAGE_PLAN_MAX_WIRE_BYTES, &wire,
                             &wire_len));
    enum vcs_package_install_error err =
        vcs_package_plan_parse(wire, wire_len, out);
    free(wire);
    if (err != VCS_PACKAGE_INSTALL_OK) {
        (void)snprintf(rule, rule_cap, "plan-invalid");
        return ZCL_ERR(-1, "stored plan: %s",
                       vcs_package_install_error_string(err));
    }
    uint8_t recomputed[32];
    if (vcs_package_plan_id(out, recomputed) != VCS_PACKAGE_INSTALL_OK ||
        memcmp(recomputed, plan_id, 32) != 0) {
        (void)snprintf(rule, rule_cap, "plan-tampered");
        return ZCL_ERR(-1, "the stored plan does not hash to its own id");
    }
    if (vcs_package_plan_expired(out, now_unix)) {
        (void)snprintf(rule, rule_cap, "plan-expired");
        return ZCL_ERR(-1,
                       "this plan expired at %lld (now %lld) — a plan is a "
                       "proposal, not a standing authorization; re-plan",
                       (long long)out->expires_unix, (long long)now_unix);
    }
    return ZCL_OK;
}

/* Collect the direct dependency roots of one node, all of which the commit
 * loop has already installed (build order guarantees it). */
static struct zcl_result pkgl_direct_deps(const struct pkgl_ctx *ctx,
                                          const uint8_t root[32],
                                          uint8_t (*out)[32],
                                          size_t *count_out)
{
    struct vcs_package_deps deps;
    ZCL_CHECK(pkgl_load_declared_deps(ctx, root, &deps));
    if (deps.count > VCS_PACKAGE_BUILD_MAX_DEPS)
        return ZCL_ERR(-1, "%zu direct dependencies exceeds the bound",
                       deps.count);
    for (size_t i = 0; i < deps.count; i++)
        memcpy(out[i], deps.items[i].root, 32);
    *count_out = deps.count;
    return ZCL_OK;
}

struct zcl_result package_lifecycle_installed_inspect(
    const char *datadir, const uint8_t root[32],
    struct package_lifecycle_step *out, bool *installed_out)
{
    if (!datadir || !root || !out || !installed_out)
        return ZCL_ERR(-1, "datadir, root, output and installed flag are required");
    memset(out, 0, sizeof(*out));
    *installed_out = false;
    struct pkgl_ctx ctx;
    ZCL_CHECK(pkgl_ctx_open(&ctx, datadir));
    const struct vcs_package_release *release =
        pkgl_release_for_root(&ctx, root);
    struct zcl_result result = release
        ? ZCL_OK : ZCL_ERR(-1, "no release names the inspected package root");
    char installed[PKGL_PATH_MAX];
    bool present = false;
    if (result.ok)
        result = pkgl_installed_dir(&ctx, root, installed, sizeof(installed));
    if (result.ok)
        result = pkgl_exists(installed, &present);
    if (result.ok && present) {
        struct vcs_package_lock lock;
        uint8_t lock_root[32];
        result = pkgl_lock_for(&ctx, root, &lock, lock_root);
        uint8_t deps[VCS_PACKAGE_BUILD_MAX_DEPS][32];
        size_t dep_count = 0;
        if (result.ok)
            result = pkgl_direct_deps(&ctx, root, deps, &dep_count);
        if (result.ok)
            result = pkgl_verify_installed_receipt(
                &ctx, root, release, lock_root,
                (const uint8_t (*)[32])deps, dep_count, out);
        if (result.ok) {
            memcpy(out->root, root, 32);
            (void)snprintf(out->name, sizeof(out->name), "%s", release->name);
            (void)snprintf(out->semver, sizeof(out->semver), "%s",
                           release->semver);
            out->state = VCS_PACKAGE_LIFECYCLE_INSTALLED;
            out->already_installed = true;
            *installed_out = true;
        }
    }
    pkgl_ctx_close(&ctx);
    return result;
}

/* Advance ONE locked step from wherever it is to PINNED. */
static struct zcl_result pkgl_commit_step(const struct pkgl_ctx *ctx,
                                          const struct vcs_package_plan *plan,
                                          size_t index, int64_t now_unix,
                                          struct package_lifecycle_step *step,
                                          uint8_t prev_root[32],
                                          bool *had_previous)
{
    const struct vcs_package_plan_step *ps = &plan->steps[index];
    memcpy(step->root, ps->root, 32);
    (void)snprintf(step->name, sizeof(step->name), "%s", ps->name);
    (void)snprintf(step->semver, sizeof(step->semver), "%s", ps->semver);
    step->depth = ps->depth;
    step->state = VCS_PACKAGE_LIFECYCLE_DISCOVERED;

    char installed[PKGL_PATH_MAX];
    ZCL_CHECK(pkgl_installed_dir(ctx, ps->root, installed, sizeof(installed)));
    ZCL_CHECK(pkgl_exists(installed, &step->already_installed));

    /* A receipt belongs to this package's own exact transitive closure, not
     * to whichever larger application happened to request it. This keeps a
     * dependency's evidence reusable when an unrelated downstream root
     * changes while still binding every dependency byte. */
    struct vcs_package_lock step_lock;
    uint8_t step_lock_root[32];
    struct zcl_result sl =
        pkgl_lock_for(ctx, ps->root, &step_lock, step_lock_root);
    if (!sl.ok) {
        pkgl_note(step->rule, sizeof(step->rule), step->detail,
                  sizeof(step->detail), "step-lock", sl.message);
        return sl;
    }

    if (!step->already_installed) {
        char vrule[PACKAGE_LIFECYCLE_RULE_MAX + 1u];
        struct zcl_result vr =
            pkgl_verify_package(ctx, ps->root, vrule, sizeof(vrule));
        if (!vr.ok) {
            pkgl_note(step->rule, sizeof(step->rule), step->detail,
                      sizeof(step->detail), vrule[0] ? vrule : "verify-failed",
                      vr.message);
            return vr;
        }
        step->state = VCS_PACKAGE_LIFECYCLE_VERIFIED;

        const struct vcs_package_release *rel =
            pkgl_release_for_root(ctx, ps->root);
        if (!rel) {
            pkgl_note(step->rule, sizeof(step->rule), step->detail,
                      sizeof(step->detail), "release-missing", ps->name);
            return ZCL_ERR(-1, "no release envelope for %s", ps->name);
        }
        uint8_t deps[VCS_PACKAGE_BUILD_MAX_DEPS][32];
        size_t dep_count = 0;
        struct zcl_result dr =
            pkgl_direct_deps(ctx, ps->root, deps, &dep_count);
        if (!dr.ok) {
            pkgl_note(step->rule, sizeof(step->rule), step->detail,
                      sizeof(step->detail), "dependency-read", dr.message);
            return dr;
        }
        ZCL_CHECK(pkgl_build_and_install(ctx, ps->root, rel, step_lock_root,
                                         (const uint8_t (*)[32])deps,
                                         dep_count, step));
    } else {
        const struct vcs_package_release *rel =
            pkgl_release_for_root(ctx, ps->root);
        if (!rel) {
            pkgl_note(step->rule, sizeof(step->rule), step->detail,
                      sizeof(step->detail), "release-missing", ps->name);
            return ZCL_ERR(-1, "no release envelope for %s", ps->name);
        }
        uint8_t deps[VCS_PACKAGE_BUILD_MAX_DEPS][32];
        size_t dep_count = 0;
        struct zcl_result dr =
            pkgl_direct_deps(ctx, ps->root, deps, &dep_count);
        if (!dr.ok) {
            pkgl_note(step->rule, sizeof(step->rule), step->detail,
                      sizeof(step->detail), "dependency-read", dr.message);
            return dr;
        }
        struct zcl_result er = pkgl_verify_installed_receipt(
            ctx, ps->root, rel, step_lock_root,
            (const uint8_t (*)[32])deps, dep_count, step);
        if (!er.ok) {
            pkgl_note(step->rule, sizeof(step->rule), step->detail,
                      sizeof(step->detail), "installed-receipt-invalid",
                      er.message);
            return er;
        }
        step->state = VCS_PACKAGE_LIFECYCLE_INSTALLED;
    }

    struct zcl_result ar = pkgl_activate(ctx, ps->name, ps->root, now_unix,
                                         prev_root, had_previous);
    if (!ar.ok) {
        pkgl_note(step->rule, sizeof(step->rule), step->detail,
                  sizeof(step->detail), "activate-failed", ar.message);
        return ar;
    }

    /* Pinning is what makes the package seedable to other peers. A refusal
     * (a full pins pool, an untracked root) is reported on the step and does
     * not undo a correct install. */
    struct zcl_result pr = pkgl_pin(ctx, ps->root);
    if (!pr.ok)
        pkgl_note(step->rule, sizeof(step->rule), step->detail,
                  sizeof(step->detail), "pin-refused", pr.message);
    else
        step->state = VCS_PACKAGE_LIFECYCLE_PINNED;
    return ZCL_OK;
}

struct zcl_result package_lifecycle_commit(
    const char *datadir, const uint8_t plan_id[32], int64_t now_unix,
    struct package_lifecycle_commit_report *out)
{
    if (!out || !plan_id)
        return ZCL_ERR(-1, "null commit report");
    memset(out, 0, sizeof(*out));
    memcpy(out->plan_id, plan_id, 32);

    struct pkgl_ctx ctx;
    ZCL_CHECK(pkgl_ctx_open(&ctx, datadir));

    struct vcs_package_plan plan;
    struct zcl_result r = pkgl_load_plan(&ctx, plan_id, now_unix, &plan,
                                         out->rule, sizeof(out->rule));
    if (!r.ok) {
        (void)snprintf(out->detail, sizeof(out->detail), "%s", r.message);
        pkgl_ctx_close(&ctx);
        return r;
    }

    /* The plan is a proposal about a store that may have changed under it.
     * Re-derive the lock now and require it to be the same one. */
    struct vcs_package_lock lock;
    uint8_t lock_root[32];
    r = pkgl_lock_for(&ctx, plan.target_root, &lock, lock_root);
    if (!r.ok) {
        pkgl_note(out->rule, sizeof(out->rule), out->detail,
                  sizeof(out->detail), "dependency-lock", r.message);
        pkgl_ctx_close(&ctx);
        return r;
    }
    if (memcmp(lock_root, plan.lock_root, 32) != 0 ||
        lock.count != plan.step_count) {
        pkgl_note(out->rule, sizeof(out->rule), out->detail,
                  sizeof(out->detail), "lock-changed",
                  "the dependency lock changed since this plan was made");
        pkgl_ctx_close(&ctx);
        return ZCL_ERR(-1, "the dependency lock changed since this plan was "
                           "made — re-plan before committing");
    }

    out->step_count = plan.step_count;
    for (size_t i = 0; i < plan.step_count; i++) {
        uint8_t prev[32];
        bool had_prev = false;
        r = pkgl_commit_step(&ctx, &plan, i, now_unix, &out->steps[i], prev,
                             &had_prev);
        if (!r.ok) {
            (void)snprintf(out->rule, sizeof(out->rule), "%s",
                           out->steps[i].rule);
            (void)snprintf(out->detail, sizeof(out->detail), "%s",
                           out->steps[i].detail);
            pkgl_ctx_close(&ctx);
            return r;
        }
        if (i + 1u == plan.step_count) {
            out->installed = true;
            memcpy(out->active_root, plan.steps[i].root, 32);
            out->had_previous = had_prev;
            if (had_prev)
                memcpy(out->previous_root, prev, 32);
        }
    }
    pkgl_ctx_close(&ctx);
    return ZCL_OK;
}

/* ── rollback + read ────────────────────────────────────────────────── */

/* Consider one "<publisher>/<package>" generation log as a candidate for
 * "the package whose active version changed most recently". */
static void pkgl_last_consider(const struct pkgl_ctx *ctx, const char *name,
                               char *best_name, size_t cap,
                               int64_t *best_unix, bool *found)
{
    struct vcs_package_generations gens;
    struct zcl_result r = pkgl_generations_load(ctx, name, &gens);
    if (!r.ok || gens.count == 0)
        return;
    int64_t when = gens.items[gens.count - 1u].activated_unix;
    /* Ties resolve to the lexicographically smaller name so two packages
     * activated in the same second still give one deterministic answer. */
    if (*found && (when < *best_unix ||
                   (when == *best_unix && strcmp(name, best_name) >= 0)))
        return;
    (void)snprintf(best_name, cap, "%s", name);
    *best_unix = when;
    *found = true;
}

/* Name the package whose newest generation was activated last — the "what I
 * just changed" answer that lets a user go back without knowing an
 * identifier. This reads ONLY the local generation logs: no network, no
 * build, no release index, and nothing from the package's own bytes. That
 * is deliberate — it must answer even when the version just activated is
 * broken, because that is precisely when it is asked. */
static struct zcl_result pkgl_last_activated(const struct pkgl_ctx *ctx,
                                             char *name_out, size_t cap,
                                             bool *present_out)
{
    *present_out = false;
    name_out[0] = '\0';
    char root[PKGL_PATH_MAX];
    ZCL_CHECK(pkgl_join(ctx, "generations", root, sizeof(root)));
    DIR *pubs = opendir(root);
    if (!pubs)
        return errno == ENOENT ? ZCL_OK
                               : ZCL_ERR(-1, "opendir %s: %s", root,
                                         strerror(errno));
    int64_t best_unix = 0;
    struct dirent *pub;
    while ((pub = readdir(pubs)) != NULL) {
        /* Only entries that could be a legal publisher half are considered;
         * a directory that cannot be part of a package name is not one. */
        if (pub->d_name[0] == '.' ||
            strlen(pub->d_name) > VCS_PACKAGE_RELEASE_NAME_HALF_MAX)
            continue;
        char pubdir[PKGL_PATH_MAX];
        int n = snprintf(pubdir, sizeof(pubdir), "%s/%s", root, pub->d_name);
        if (n <= 0 || (size_t)n >= sizeof(pubdir))
            continue;
        DIR *pkgs = opendir(pubdir);
        if (!pkgs)
            continue;
        struct dirent *pkg;
        while ((pkg = readdir(pkgs)) != NULL) {
            if (pkg->d_name[0] == '.' ||
                strlen(pkg->d_name) > VCS_PACKAGE_RELEASE_NAME_HALF_MAX)
                continue;
            char name[VCS_PACKAGE_RELEASE_NAME_MAX + 1u];
            n = snprintf(name, sizeof(name), "%s/%s", pub->d_name,
                         pkg->d_name);
            if (n <= 0 || (size_t)n >= sizeof(name))
                continue;
            pkgl_last_consider(ctx, name, name_out, cap, &best_unix,
                               present_out);
        }
        closedir(pkgs);
    }
    closedir(pubs);
    return ZCL_OK;
}

struct zcl_result package_lifecycle_last_activated(
    const char *datadir, char *name_out, size_t name_cap, bool *present_out)
{
    if (!name_out || !name_cap || !present_out)
        return ZCL_ERR(-1, "null argument naming the last activated package");
    struct pkgl_ctx ctx;
    ZCL_CHECK(pkgl_ctx_open(&ctx, datadir));
    struct zcl_result r =
        pkgl_last_activated(&ctx, name_out, name_cap, present_out);
    pkgl_ctx_close(&ctx);
    return r;
}

struct zcl_result package_lifecycle_rollback(
    const char *datadir, const char *name, int64_t now_unix,
    struct package_lifecycle_rollback_report *out)
{
    if (!out)
        return ZCL_ERR(-1, "null rollback report");
    memset(out, 0, sizeof(*out));

    struct pkgl_ctx ctx;
    ZCL_CHECK(pkgl_ctx_open(&ctx, datadir));

    /* No name means "go back one step" — the package whose active version
     * changed most recently. */
    if (!name || !name[0]) {
        bool present = false;
        struct zcl_result lr = pkgl_last_activated(&ctx, out->name,
                                                   sizeof(out->name),
                                                   &present);
        if (!lr.ok) {
            pkgl_note(out->rule, sizeof(out->rule), out->detail,
                      sizeof(out->detail), "generations-unreadable",
                      lr.message);
            pkgl_ctx_close(&ctx);
            return lr;
        }
        if (!present) {
            pkgl_note(out->rule, sizeof(out->rule), out->detail,
                      sizeof(out->detail), "nothing-installed",
                      "no package has ever been activated here");
            pkgl_ctx_close(&ctx);
            return ZCL_ERR(-1, "there is nothing to go back from");
        }
        out->selected_by_default = true;
    } else {
        (void)snprintf(out->name, sizeof(out->name), "%s", name);
    }
    name = out->name;

    struct vcs_package_generations gens;
    struct zcl_result r = pkgl_generations_load(&ctx, name, &gens);
    if (!r.ok) {
        pkgl_note(out->rule, sizeof(out->rule), out->detail,
                  sizeof(out->detail), "generations-unreadable", r.message);
        pkgl_ctx_close(&ctx);
        return r;
    }
    out->generation_count = gens.count;
    if (gens.count == 0) {
        pkgl_note(out->rule, sizeof(out->rule), out->detail,
                  sizeof(out->detail), "never-installed", name);
        pkgl_ctx_close(&ctx);
        return ZCL_ERR(-1, "'%s' was never installed here", name);
    }
    memcpy(out->from_root, gens.items[gens.count - 1].root, 32);
    if (!vcs_package_generations_previous(&gens, out->to_root)) {
        pkgl_note(out->rule, sizeof(out->rule), out->detail,
                  sizeof(out->detail), "no-previous-generation",
                  "only one generation of this package was ever active");
        pkgl_ctx_close(&ctx);
        return ZCL_ERR(-1, "nothing to roll back to for '%s'", name);
    }

    uint8_t prev[32];
    bool had_prev = false;
    r = pkgl_activate(&ctx, name, out->to_root, now_unix, prev, &had_prev);
    if (!r.ok) {
        pkgl_note(out->rule, sizeof(out->rule), out->detail,
                  sizeof(out->detail), "activate-failed", r.message);
        pkgl_ctx_close(&ctx);
        return r;
    }
    out->generation_count = gens.count + 1u;
    pkgl_ctx_close(&ctx);
    return ZCL_OK;
}

struct zcl_result package_lifecycle_active(
    const char *datadir, const char *name, uint8_t out_root[32],
    size_t *generation_count_out, bool *present_out)
{
    if (!name || !out_root || !generation_count_out || !present_out)
        return ZCL_ERR(-1, "null argument reading the active package");
    memset(out_root, 0, 32);
    *generation_count_out = 0;
    *present_out = false;

    struct pkgl_ctx ctx;
    ZCL_CHECK(pkgl_ctx_open(&ctx, datadir));
    struct vcs_package_generations gens;
    struct zcl_result r = pkgl_generations_load(&ctx, name, &gens);
    pkgl_ctx_close(&ctx);
    if (!r.ok)
        return r;
    *generation_count_out = gens.count;
    if (gens.count == 0)
        return ZCL_OK;
    memcpy(out_root, gens.items[gens.count - 1].root, 32);
    *present_out = true;
    return ZCL_OK;
}
