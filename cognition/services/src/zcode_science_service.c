/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: CAS-authoritative ZCODE science plan/commit services. */

#include "services/zcode_science_service.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "crypto/sha3.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_science.h"
#include "vcs/zcode_science_index.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t result_v2_magic[8] = {'Z','C','B','E','N','2','\r','\n'};
static const uint8_t reproduction_magic[8] =
    {'Z','C','R','E','P','R','\r','\n'};

/* ── request/plan identity ─────────────────────────────────────── */

static void science_request_hash(const char *kind, const uint8_t *wire,
                                 size_t wire_len, const uint8_t *aux,
                                 size_t aux_len, uint8_t out[32])
{
    static const char domain[] = "zcl.zcode.science.request.v1";
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)domain, sizeof(domain) - 1);
    sha3_256_write(&ctx, (const unsigned char *)kind, strlen(kind));
    sha3_256_write(&ctx, wire, wire_len);
    if (aux && aux_len)
        sha3_256_write(&ctx, aux, aux_len);
    sha3_256_finalize(&ctx, out);
}

static void science_plan_root(const uint8_t request_hash[32], uint8_t out[32])
{
    static const char domain[] = "zcl.zcode.science.plan.v1";
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)domain, sizeof(domain) - 1);
    sha3_256_write(&ctx, request_hash, 32);
    sha3_256_finalize(&ctx, out);
}

static bool science_hex_decode(const char *hex, uint8_t *out, size_t len)
{
    return hex && strlen(hex) == len * 2u && zcl_hex_decode_lower(hex, out, len);
}

/* ── CAS helpers ───────────────────────────────────────────────── */

static bool science_cas_load(const char *workspace, const uint8_t root[32],
                             uint8_t **wire, size_t *wire_len)
{
    return vcs_object_load_raw(workspace, root, wire, wire_len) == 0;
}

/* Load + parse + rederived-root-check one study wire from CAS. */
static bool science_load_study(const char *workspace,
                               const uint8_t study_root[32],
                               struct vcs_zcode_study_spec_v1 *out)
{
    uint8_t *wire = NULL, checked[32];
    size_t len = 0;
    bool ok = science_cas_load(workspace, study_root, &wire, &len) &&
        vcs_zcode_study_spec_parse(wire, len, out) == VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_study_spec_validate(out) == VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_study_spec_root(out, checked) == VCS_ZCODE_SCIENCE_OK &&
        memcmp(checked, study_root, 32) == 0;
    free(wire);
    return ok;
}

/* Load one benchmark result (v1 or v2 wire) into the shared v1 view; the
 * v2 struct prefix is layout-identical to v1. */
static bool science_load_result_v1(const char *workspace,
                                   const uint8_t result_root[32],
                                   struct vcs_zcode_benchmark_result_v1 *out)
{
    uint8_t *wire = NULL, checked[32];
    size_t len = 0;
    if (!science_cas_load(workspace, result_root, &wire, &len))
        return false; /* raw-return-ok: callers name the missing CAS object
                         in their own ZCL_ERR context */
    bool ok = false;
    if (len == VCS_ZCODE_BENCHMARK_RESULT_V2_WIRE_BYTES) {
        struct vcs_zcode_benchmark_result_v2 v2;
        ok = vcs_zcode_benchmark_result_v2_parse(wire, len, &v2) ==
                VCS_ZCODE_SCIENCE_OK &&
            vcs_zcode_benchmark_result_v2_validate(&v2) ==
                VCS_ZCODE_SCIENCE_OK &&
            vcs_zcode_benchmark_result_v2_root(&v2, checked) ==
                VCS_ZCODE_SCIENCE_OK &&
            memcmp(checked, result_root, 32) == 0;
        if (ok)
            memcpy(out, &v2, sizeof(*out));
    } else {
        ok = vcs_zcode_benchmark_result_parse(wire, len, out) ==
                VCS_ZCODE_SCIENCE_OK &&
            vcs_zcode_benchmark_result_validate(out) ==
                VCS_ZCODE_SCIENCE_OK &&
            vcs_zcode_benchmark_result_root(out, checked) ==
                VCS_ZCODE_SCIENCE_OK &&
            memcmp(checked, result_root, 32) == 0;
    }
    free(wire);
    return ok;
}

/* ── plan plumbing ─────────────────────────────────────────────── */

struct zcl_result science_plan_open(
    struct node_db *ndb, const char *kind, const uint8_t *wire,
    size_t wire_len, const uint8_t *aux, size_t aux_len, int64_t now,
    struct zcode_science_plan_out *out)
{
    if (!ndb || !ndb->open || !kind || !wire || !wire_len || now <= 0 || !out)
        return ZCL_ERR(-1, "science-plan-input-invalid");
    if (wire_len * 2u >= ZCODE_SCIENCE_PLAN_WIRE_HEX_MAX)
        return ZCL_ERR(-1, "science-wire-too-large");
    uint8_t request[32], plan_root[32];
    science_request_hash(kind, wire, wire_len, aux, aux_len, request);
    science_plan_root(request, plan_root);
    memset(out, 0, sizeof(*out));
    zcl_hex_encode(request, 32, out->request_hash);
    zcl_hex_encode(plan_root, 32, out->plan_root);
    struct db_zcode_science_plan existing;
    if (db_zcode_science_plan_find_by_request(ndb, out->request_hash,
                                              &existing)) {
        out->expires_unix = existing.expires_unix;
        out->already_planned = true;
        return ZCL_OK;
    }
    struct db_zcode_science_plan row;
    memset(&row, 0, sizeof(row));
    (void)snprintf(row.plan_root, sizeof(row.plan_root), "%s", out->plan_root);
    (void)snprintf(row.kind, sizeof(row.kind), "%s", kind);
    (void)snprintf(row.request_hash, sizeof(row.request_hash), "%s",
                   out->request_hash);
    zcl_hex_encode(wire, wire_len, row.wire_hex);
    (void)snprintf(row.state, sizeof(row.state), "%s",
                   ZCODE_SCIENCE_PLAN_STATE_PLANNED);
    row.expires_unix = now + ZCODE_SCIENCE_PLAN_TTL_SECONDS;
    row.created_at = now;
    if (!db_zcode_science_plan_save(ndb, &row))
        return ZCL_ERR(-1, "science-plan-save-failed");
    out->expires_unix = row.expires_unix;
    return ZCL_OK;
}

/* Shared commit prelude: confirm gate, plan lookup, expiry, exact-wire
 * agreement, idempotent reattach. On ZCL_OK with *done=true the commit is
 * already satisfied; with *done=false the caller runs evidence validation,
 * CAS storage, and the projection, then science_plan_mark_committed. */
struct zcl_result science_commit_prelude(
    struct node_db *ndb, const char *kind, const uint8_t *wire,
    size_t wire_len, const uint8_t *aux, size_t aux_len, bool confirm,
    int64_t now, struct db_zcode_science_plan *plan, bool *done,
    struct zcode_science_commit_out *out)
{
    if (!confirm)
        return ZCL_ERR(-1, "science-commit-requires-confirm-true");
    uint8_t request[32];
    science_request_hash(kind, wire, wire_len, aux, aux_len, request);
    char request_hex[65];
    zcl_hex_encode(request, 32, request_hex);
    if (!db_zcode_science_plan_find_by_request(ndb, request_hex, plan))
        return ZCL_ERR(-1, "science-plan-not-found");
    if (strcmp(plan->kind, kind) != 0)
        return ZCL_ERR(-1, "science-plan-kind-mismatch");
    if (now >= plan->expires_unix)
        return ZCL_ERR(-1, "science-plan-expired");
    if (strlen(plan->wire_hex) != wire_len * 2u) /* exact plan binding */
        return ZCL_ERR(-1, "science-plan-wire-mismatch");
    uint8_t *planned = zcl_malloc(wire_len, "science_plan_wire");
    if (!planned)
        return ZCL_ERR(-1, "science-plan-wire-alloc");
    bool exact = zcl_hex_decode_lower(plan->wire_hex, planned, wire_len) &&
                 memcmp(planned, wire, wire_len) == 0;
    free(planned);
    if (!exact)
        return ZCL_ERR(-1, "science-plan-wire-mismatch");
    memset(out, 0, sizeof(*out));
    if (strcmp(plan->state, ZCODE_SCIENCE_PLAN_STATE_COMMITTED) == 0) {
        (void)snprintf(out->result_root, sizeof(out->result_root), "%s",
                       plan->result_root);
        out->already_committed = true;
        *done = true;
        return ZCL_OK;
    }
    *done = false;
    return ZCL_OK;
}

struct zcl_result science_plan_mark_committed(
    struct node_db *ndb, struct db_zcode_science_plan *plan,
    const char *result_root_hex)
{
    (void)snprintf(plan->result_root, sizeof(plan->result_root), "%s",
                   result_root_hex);
    (void)snprintf(plan->state, sizeof(plan->state), "%s",
                   ZCODE_SCIENCE_PLAN_STATE_COMMITTED);
    if (!db_zcode_science_plan_save(ndb, plan))
        return ZCL_ERR(-1, "science-plan-commit-save-failed");
    return ZCL_OK;
}

/* ── study ─────────────────────────────────────────────────────── */

struct zcl_result zcode_science_study_plan(
    struct node_db *ndb, const char *workspace,
    const uint8_t *wire, size_t wire_len, int64_t now,
    struct zcode_science_plan_out *out)
{
    (void)workspace;
    struct vcs_zcode_study_spec_v1 study;
    if (!wire || wire_len != VCS_ZCODE_STUDY_SPEC_WIRE_BYTES ||
        vcs_zcode_study_spec_parse(wire, wire_len, &study) !=
            VCS_ZCODE_SCIENCE_OK ||
        vcs_zcode_study_spec_validate(&study) != VCS_ZCODE_SCIENCE_OK)
        return ZCL_ERR(-1, "science-study-wire-invalid");
    if (!vcs_zcode_study_spec_accepts_submission_at(&study, now))
        return ZCL_ERR(-1, "science-study-window-closed");
    return science_plan_open(ndb, "study", wire, wire_len, NULL, 0, now, out);
}

struct zcl_result zcode_science_study_commit(
    struct node_db *ndb, const char *workspace,
    const uint8_t *wire, size_t wire_len, bool confirm, int64_t now,
    struct zcode_science_commit_out *out)
{
    if (!workspace || !wire)
        return ZCL_ERR(-1, "science-commit-input-invalid");
    struct db_zcode_science_plan plan;
    bool done = false;
    ZCL_CHECK(science_commit_prelude(ndb, "study", wire, wire_len, NULL, 0,
                                     confirm, now, &plan, &done, out));
    if (done)
        return ZCL_OK;
    struct vcs_zcode_study_spec_v1 study;
    uint8_t root[32];
    if (vcs_zcode_study_spec_parse(wire, wire_len, &study) !=
            VCS_ZCODE_SCIENCE_OK ||
        vcs_zcode_study_spec_validate(&study) != VCS_ZCODE_SCIENCE_OK ||
        vcs_zcode_study_spec_root(&study, root) != VCS_ZCODE_SCIENCE_OK)
        return ZCL_ERR(-1, "science-study-wire-invalid");
    /* The window gates new submissions at both plan and commit time; it
     * never erases stored evidence. */
    if (!vcs_zcode_study_spec_accepts_submission_at(&study, now))
        return ZCL_ERR(-1, "science-study-window-closed");
    char root_hex[65];
    zcl_hex_encode(root, 32, root_hex);
    if (!vcs_object_put_addressed(workspace, root, wire, wire_len))
        return ZCL_ERR(-1, "science-study-cas-store-failed");
    struct db_zcode_science_entry row;
    memset(&row, 0, sizeof(row));
    (void)snprintf(row.root, sizeof(row.root), "%s", root_hex);
    zcl_hex_encode(study.hypothesis_root, 32, row.link_root);
    zcl_hex_encode(study.null_hypothesis_root, 32, row.aux_root);
    row.code = study.required_reproductions;
    row.flags = study.required_reviews;
    row.sequence = (int64_t)study.sequence;
    row.created_at = study.created_unix;
    row.expires_at = study.expires_unix;
    if (!db_zcode_science_study_save(ndb, &row))
        return ZCL_ERR(-1, "science-study-projection-save-failed");
    ZCL_CHECK(science_plan_mark_committed(ndb, &plan, root_hex));
    (void)snprintf(out->result_root, sizeof(out->result_root), "%s", root_hex);
    return ZCL_OK;
}

struct zcl_result zcode_science_study_show(
    struct node_db *ndb, const char *study_root_hex,
    struct db_zcode_science_entry *out, bool *found)
{
    if (!ndb || !ndb->open || !study_root_hex || !out || !found)
        return ZCL_ERR(-1, "science-show-input-invalid");
    uint8_t root[32];
    if (!science_hex_decode(study_root_hex, root, 32))
        return ZCL_ERR(-1, "science-show-root-invalid");
    *found = db_zcode_science_study_find(ndb, study_root_hex, out);
    return ZCL_OK;
}

struct zcl_result zcode_science_study_list(
    struct node_db *ndb, struct db_zcode_science_entry *out, int max,
    int *count)
{
    if (!ndb || !ndb->open || !out || max <= 0 || !count)
        return ZCL_ERR(-1, "science-list-input-invalid");
    *count = db_zcode_science_study_list(ndb, out, max);
    return ZCL_OK;
}

/* ── work ──────────────────────────────────────────────────────── */

static bool science_wire_is_result_v2(const uint8_t *wire, size_t len)
{
    return wire && len == VCS_ZCODE_BENCHMARK_RESULT_V2_WIRE_BYTES &&
           memcmp(wire, result_v2_magic, sizeof(result_v2_magic)) == 0;
}

static bool science_wire_is_reproduction(const uint8_t *wire, size_t len)
{
    return wire && len == VCS_ZCODE_REPRODUCTION_WIRE_BYTES &&
           memcmp(wire, reproduction_magic, sizeof(reproduction_magic)) == 0;
}

/* Plan-time auxiliary identity: for a v2 result the method and profile
 * canonical roots join the request hash so the plan binds them exactly. */
static struct zcl_result science_work_aux(
    const uint8_t *method_wire, size_t method_len,
    const uint8_t *profile_wire, size_t profile_len, uint8_t aux[64])
{
    if (!method_wire || method_len != VCS_ZCODE_BENCHMARK_METHOD_WIRE_BYTES ||
        !profile_wire || profile_len != VCS_ZCODE_HARDWARE_PROFILE_WIRE_BYTES)
        return ZCL_ERR(-1, "science-work-method-profile-required");
    struct vcs_zcode_benchmark_method_v1 method;
    struct vcs_zcode_hardware_profile_v1 profile;
    if (vcs_zcode_benchmark_method_parse(method_wire, method_len, &method) !=
            VCS_ZCODE_SCIENCE_OK ||
        vcs_zcode_benchmark_method_validate(&method) !=
            VCS_ZCODE_SCIENCE_OK ||
        vcs_zcode_benchmark_method_root(&method, aux) !=
            VCS_ZCODE_SCIENCE_OK)
        return ZCL_ERR(-1, "science-work-method-invalid");
    if (vcs_zcode_hardware_profile_parse(profile_wire, profile_len,
                                         &profile) != VCS_ZCODE_SCIENCE_OK ||
        vcs_zcode_hardware_profile_validate(&profile) !=
            VCS_ZCODE_SCIENCE_OK ||
        vcs_zcode_hardware_profile_root(&profile, aux + 32) !=
            VCS_ZCODE_SCIENCE_OK)
        return ZCL_ERR(-1, "science-work-profile-invalid");
    return ZCL_OK;
}

struct zcl_result zcode_science_work_plan(
    struct node_db *ndb, const char *workspace,
    const uint8_t *wire, size_t wire_len,
    const uint8_t *method_wire, size_t method_len,
    const uint8_t *profile_wire, size_t profile_len,
    const struct vcs_build_action_v1 *action,
    int64_t now, struct zcode_science_plan_out *out)
{
    if (!workspace || !wire)
        return ZCL_ERR(-1, "science-work-input-invalid");
    uint8_t aux[64];
    size_t aux_len = 0;
    if (science_wire_is_result_v2(wire, wire_len)) {
        struct vcs_zcode_benchmark_result_v2 result;
        if (vcs_zcode_benchmark_result_v2_parse(wire, wire_len, &result) !=
                VCS_ZCODE_SCIENCE_OK ||
            vcs_zcode_benchmark_result_v2_validate(&result) !=
                VCS_ZCODE_SCIENCE_OK)
            return ZCL_ERR(-1, "science-work-result-invalid");
        if (!action)
            return ZCL_ERR(-1, "science-work-action-required");
        ZCL_CHECK(science_work_aux(method_wire, method_len, profile_wire,
                                   profile_len, aux));
        aux_len = sizeof(aux);
        /* The method and profile are CAS citizens: store them addressed by
         * their canonical roots so commit can re-load them. */
        if (!vcs_object_put_addressed(workspace, aux, method_wire,
                                      method_len) ||
            !vcs_object_put_addressed(workspace, aux + 32, profile_wire,
                                      profile_len))
            return ZCL_ERR(-1, "science-work-aux-cas-store-failed");
    } else if (science_wire_is_reproduction(wire, wire_len)) {
        struct vcs_zcode_reproduction_v1 reproduction;
        if (vcs_zcode_reproduction_parse(wire, wire_len, &reproduction) !=
                VCS_ZCODE_SCIENCE_OK ||
            vcs_zcode_reproduction_validate(&reproduction) !=
                VCS_ZCODE_SCIENCE_OK)
            return ZCL_ERR(-1, "science-work-reproduction-invalid");
    } else {
        return ZCL_ERR(-1, "science-work-wire-kind-unknown");
    }
    return science_plan_open(ndb, "work", wire, wire_len, aux, aux_len, now,
                             out);
}

static struct zcl_result science_work_commit_result(
    struct node_db *ndb, const char *workspace,
    const struct vcs_zcode_benchmark_result_v2 *result,
    const struct vcs_build_action_v1 *action, int64_t now,
    const uint8_t *wire, size_t wire_len, struct db_zcode_science_plan *plan,
    struct zcode_science_commit_out *out)
{
    if (!action)
        return ZCL_ERR(-1, "science-work-action-required");
    struct vcs_zcode_study_spec_v1 study;
    if (!science_load_study(workspace, result->study_root, &study))
        return ZCL_ERR(-1, "science-work-study-not-in-cas");
    struct vcs_zcode_task_v1 task;
    struct vcs_zcode_candidate_v1 candidate;
    {
        uint8_t *twire = NULL, *cwire = NULL, checked[32];
        size_t tlen = 0, clen = 0;
        bool ok = science_cas_load(workspace, result->task_root, &twire,
                                   &tlen) &&
            vcs_zcode_task_parse(twire, tlen, &task) == VCS_ZCODE_DEV_OK &&
            vcs_zcode_task_root(&task, checked) == VCS_ZCODE_DEV_OK &&
            memcmp(checked, result->task_root, 32) == 0 &&
            science_cas_load(workspace, result->candidate_root, &cwire,
                             &clen) &&
            vcs_zcode_candidate_parse(cwire, clen, &candidate) ==
                VCS_ZCODE_DEV_OK &&
            vcs_zcode_candidate_root(&candidate, checked) ==
                VCS_ZCODE_DEV_OK &&
            memcmp(checked, result->candidate_root, 32) == 0;
        free(twire);
        free(cwire);
        if (!ok)
            return ZCL_ERR(-1, "science-work-task-candidate-not-in-cas");
    }
    struct vcs_zcode_benchmark_method_v1 method;
    struct vcs_zcode_hardware_profile_v1 profile;
    {
        uint8_t *mwire = NULL, *pwire = NULL, checked[32];
        size_t mlen = 0, plen = 0;
        bool ok = science_cas_load(workspace, result->method_root, &mwire,
                                   &mlen) &&
            vcs_zcode_benchmark_method_parse(mwire, mlen, &method) ==
                VCS_ZCODE_SCIENCE_OK &&
            vcs_zcode_benchmark_method_root(&method, checked) ==
                VCS_ZCODE_SCIENCE_OK &&
            memcmp(checked, result->method_root, 32) == 0 &&
            science_cas_load(workspace, result->hardware_profile_root, &pwire,
                             &plen) &&
            vcs_zcode_hardware_profile_parse(pwire, plen, &profile) ==
                VCS_ZCODE_SCIENCE_OK &&
            vcs_zcode_hardware_profile_root(&profile, checked) ==
                VCS_ZCODE_SCIENCE_OK &&
            memcmp(checked, result->hardware_profile_root, 32) == 0;
        free(mwire);
        free(pwire);
        if (!ok)
            return ZCL_ERR(-1, "science-work-method-profile-not-in-cas");
    }
    enum vcs_zcode_science_error verr =
        vcs_zcode_benchmark_result_v2_validate_for_study(
            &study, &task, &candidate, action, &method, &profile, result,
            now);
    if (verr != VCS_ZCODE_SCIENCE_OK)
        return ZCL_ERR(-1, "science-work-cross-validation-failed: %s",
                       vcs_zcode_science_error_string(verr));
    uint8_t root[32];
    if (vcs_zcode_benchmark_result_v2_root(result, root) !=
        VCS_ZCODE_SCIENCE_OK)
        return ZCL_ERR(-1, "science-work-root-failed");
    char root_hex[65];
    zcl_hex_encode(root, 32, root_hex);
    if (!vcs_object_put_addressed(workspace, root, wire, wire_len))
        return ZCL_ERR(-1, "science-work-cas-store-failed");
    struct db_zcode_science_entry row;
    memset(&row, 0, sizeof(row));
    (void)snprintf(row.root, sizeof(row.root), "%s", root_hex);
    zcl_hex_encode(result->study_root, 32, row.study_root);
    zcl_hex_encode(result->task_root, 32, row.link_root);
    zcl_hex_encode(result->candidate_root, 32, row.aux_root);
    row.code = result->status;
    row.sequence = (int64_t)result->sequence;
    row.created_at = result->started_unix;
    row.expires_at = result->finished_unix;
    if (!db_zcode_science_result_save(ndb, &row))
        return ZCL_ERR(-1, "science-work-projection-save-failed");
    ZCL_CHECK(science_plan_mark_committed(ndb, plan, root_hex));
    (void)snprintf(out->result_root, sizeof(out->result_root), "%s", root_hex);
    return ZCL_OK;
}

static struct zcl_result science_work_commit_reproduction(
    struct node_db *ndb, const char *workspace,
    const struct vcs_zcode_reproduction_v1 *reproduction, int64_t now,
    const uint8_t *wire, size_t wire_len, struct db_zcode_science_plan *plan,
    struct zcode_science_commit_out *out)
{
    struct vcs_zcode_study_spec_v1 study;
    struct vcs_zcode_benchmark_result_v1 original, reproduced;
    if (!science_load_study(workspace, reproduction->study_root, &study))
        return ZCL_ERR(-1, "science-work-study-not-in-cas");
    if (!science_load_result_v1(workspace, reproduction->original_result_root,
                                &original) ||
        !science_load_result_v1(workspace,
                                reproduction->reproduced_result_root,
                                &reproduced))
        return ZCL_ERR(-1, "science-work-results-not-in-cas");
    enum vcs_zcode_science_error verr =
        vcs_zcode_reproduction_validate_for_results(
            &study, &original, &reproduced, reproduction, now);
    if (verr != VCS_ZCODE_SCIENCE_OK)
        return ZCL_ERR(-1, "science-work-cross-validation-failed: %s",
                       vcs_zcode_science_error_string(verr));
    uint8_t root[32];
    if (vcs_zcode_reproduction_root(reproduction, root) !=
        VCS_ZCODE_SCIENCE_OK)
        return ZCL_ERR(-1, "science-work-root-failed");
    char root_hex[65];
    zcl_hex_encode(root, 32, root_hex);
    if (!vcs_object_put_addressed(workspace, root, wire, wire_len))
        return ZCL_ERR(-1, "science-work-cas-store-failed");
    struct db_zcode_science_entry row;
    memset(&row, 0, sizeof(row));
    (void)snprintf(row.root, sizeof(row.root), "%s", root_hex);
    zcl_hex_encode(reproduction->study_root, 32, row.study_root);
    zcl_hex_encode(reproduction->original_result_root, 32, row.link_root);
    zcl_hex_encode(reproduction->reproduced_result_root, 32, row.aux_root);
    zcl_hex_encode(reproduction->reproducer_pubkey, 32, row.author);
    row.code = reproduction->verdict;
    row.sequence = (int64_t)reproduction->sequence;
    row.created_at = reproduction->created_unix;
    if (!db_zcode_science_reproduction_save(ndb, &row))
        return ZCL_ERR(-1, "science-work-projection-save-failed");
    ZCL_CHECK(science_plan_mark_committed(ndb, plan, root_hex));
    (void)snprintf(out->result_root, sizeof(out->result_root), "%s", root_hex);
    return ZCL_OK;
}

struct zcl_result zcode_science_work_commit(
    struct node_db *ndb, const char *workspace,
    const uint8_t *wire, size_t wire_len,
    const struct vcs_build_action_v1 *action,
    bool confirm, int64_t now, struct zcode_science_commit_out *out)
{
    if (!workspace || !wire)
        return ZCL_ERR(-1, "science-work-input-invalid");
    uint8_t aux[64];
    size_t aux_len = 0;
    bool is_result = science_wire_is_result_v2(wire, wire_len);
    bool is_reproduction = science_wire_is_reproduction(wire, wire_len);
    if (!is_result && !is_reproduction)
        return ZCL_ERR(-1, "science-work-wire-kind-unknown");
    if (is_result) {
        /* The aux identity is the method/profile roots carried by the
         * result itself — plan hashed the same pair. */
        struct vcs_zcode_benchmark_result_v2 probe;
        if (vcs_zcode_benchmark_result_v2_parse(wire, wire_len, &probe) !=
            VCS_ZCODE_SCIENCE_OK)
            return ZCL_ERR(-1, "science-work-result-invalid");
        memcpy(aux, probe.method_root, 32);
        memcpy(aux + 32, probe.hardware_profile_root, 32);
        aux_len = sizeof(aux);
    }
    struct db_zcode_science_plan plan;
    bool done = false;
    ZCL_CHECK(science_commit_prelude(ndb, "work", wire, wire_len, aux,
                                     aux_len, confirm, now, &plan, &done,
                                     out));
    if (done)
        return ZCL_OK;
    if (is_result) {
        struct vcs_zcode_benchmark_result_v2 result;
        if (vcs_zcode_benchmark_result_v2_parse(wire, wire_len, &result) !=
            VCS_ZCODE_SCIENCE_OK)
            return ZCL_ERR(-1, "science-work-result-invalid");
        return science_work_commit_result(ndb, workspace, &result, action,
                                          now, wire, wire_len, &plan, out);
    }
    struct vcs_zcode_reproduction_v1 reproduction;
    if (vcs_zcode_reproduction_parse(wire, wire_len, &reproduction) !=
        VCS_ZCODE_SCIENCE_OK)
        return ZCL_ERR(-1, "science-work-reproduction-invalid");
    return science_work_commit_reproduction(ndb, workspace, &reproduction,
                                            now, wire, wire_len, &plan, out);
}

struct zcl_result zcode_science_work_status(
    struct node_db *ndb, const char *root_hex,
    struct db_zcode_science_entry *out, const char **kind, bool *found)
{
    if (!ndb || !ndb->open || !root_hex || !out || !kind || !found)
        return ZCL_ERR(-1, "science-status-input-invalid");
    uint8_t root[32];
    if (!science_hex_decode(root_hex, root, 32))
        return ZCL_ERR(-1, "science-status-root-invalid");
    if (db_zcode_science_result_find(ndb, root_hex, out)) {
        *kind = "result";
        *found = true;
    } else if (db_zcode_science_reproduction_find(ndb, root_hex, out)) {
        *kind = "reproduction";
        *found = true;
    } else {
        *found = false;
    }
    return ZCL_OK;
}

struct zcl_result zcode_science_work_receipt(
    struct node_db *ndb, const char *workspace, const char *root_hex,
    struct db_zcode_science_entry *out, const char **kind)
{
    if (!workspace)
        return ZCL_ERR(-1, "science-receipt-input-invalid");
    bool found = false;
    ZCL_CHECK(zcode_science_work_status(ndb, root_hex, out, kind, &found));
    if (!found)
        return ZCL_ERR(-1, "science-receipt-not-found");
    uint8_t root[32];
    (void)science_hex_decode(root_hex, root, 32);
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (!science_cas_load(workspace, root, &wire, &wire_len))
        return ZCL_ERR(-1, "science-receipt-cas-missing");
    /* The receipt re-verifies the canonical wire against its address; the
     * projection row alone is never the proof. */
    bool ok = false;
    if (strcmp(*kind, "result") == 0) {
        struct vcs_zcode_benchmark_result_v2 result;
        uint8_t checked[32];
        ok = vcs_zcode_benchmark_result_v2_parse(wire, wire_len, &result) ==
                VCS_ZCODE_SCIENCE_OK &&
            vcs_zcode_benchmark_result_v2_validate(&result) ==
                VCS_ZCODE_SCIENCE_OK &&
            vcs_zcode_benchmark_result_v2_root(&result, checked) ==
                VCS_ZCODE_SCIENCE_OK &&
            memcmp(checked, root, 32) == 0;
    } else {
        struct vcs_zcode_reproduction_v1 reproduction;
        uint8_t checked[32];
        ok = vcs_zcode_reproduction_parse(wire, wire_len, &reproduction) ==
                VCS_ZCODE_SCIENCE_OK &&
            vcs_zcode_reproduction_validate(&reproduction) ==
                VCS_ZCODE_SCIENCE_OK &&
            vcs_zcode_reproduction_root(&reproduction, checked) ==
                VCS_ZCODE_SCIENCE_OK &&
            memcmp(checked, root, 32) == 0;
    }
    free(wire);
    if (!ok)
        return ZCL_ERR(-1, "science-receipt-cas-invalid");
    return ZCL_OK;
}

/* ── review ────────────────────────────────────────────────────── */

struct zcl_result zcode_science_review_submit(
    struct node_db *ndb, const char *workspace,
    const uint8_t *wire, size_t wire_len, bool confirm, int64_t now,
    struct zcode_science_plan_out *plan_out,
    struct zcode_science_commit_out *commit_out)
{
    if (!workspace || !wire || wire_len != VCS_ZCODE_REVIEW_WIRE_BYTES ||
        !plan_out || !commit_out)
        return ZCL_ERR(-1, "science-review-input-invalid");
    struct vcs_zcode_review_v1 review;
    if (vcs_zcode_review_parse(wire, wire_len, &review) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_review_validate(&review) != VCS_ZCODE_DEV_OK)
        return ZCL_ERR(-1, "science-review-wire-invalid");
    if (!confirm) {
        memset(commit_out, 0, sizeof(*commit_out));
        return science_plan_open(ndb, "review", wire, wire_len, NULL, 0, now,
                                 plan_out);
    }
    struct db_zcode_science_plan plan;
    bool done = false;
    ZCL_CHECK(science_commit_prelude(ndb, "review", wire, wire_len, NULL, 0,
                                     true, now, &plan, &done, commit_out));
    memset(plan_out, 0, sizeof(*plan_out));
    (void)snprintf(plan_out->plan_root, sizeof(plan_out->plan_root), "%s",
                   plan.plan_root);
    (void)snprintf(plan_out->request_hash, sizeof(plan_out->request_hash),
                   "%s", plan.request_hash);
    plan_out->expires_unix = plan.expires_unix;
    if (done)
        return ZCL_OK;
    /* H1: the findings wire must exist in CAS and the review must not
     * predate it. */
    struct vcs_zcode_science_findings_v1 findings;
    {
        uint8_t *fwire = NULL, checked[32];
        size_t flen = 0;
        bool ok = science_cas_load(workspace, review.findings_root, &fwire,
                                   &flen) &&
            vcs_zcode_science_findings_parse(fwire, flen, &findings) ==
                VCS_ZCODE_SCIENCE_OK &&
            vcs_zcode_science_findings_validate(&findings) ==
                VCS_ZCODE_SCIENCE_OK &&
            vcs_zcode_science_findings_root(&findings, checked) ==
                VCS_ZCODE_SCIENCE_OK &&
            memcmp(checked, review.findings_root, 32) == 0;
        free(fwire);
        if (!ok)
            return ZCL_ERR(-1, "science-review-findings-not-in-cas");
    }
    if (review.created_unix < findings.created_unix)
        return ZCL_ERR(-1, "science-review-predates-findings");
    uint8_t root[32];
    if (vcs_zcode_review_root(&review, root) != VCS_ZCODE_DEV_OK)
        return ZCL_ERR(-1, "science-review-root-failed");
    char root_hex[65];
    zcl_hex_encode(root, 32, root_hex);
    if (!vcs_object_put_addressed(workspace, root, wire, wire_len))
        return ZCL_ERR(-1, "science-review-cas-store-failed");
    struct db_zcode_science_entry row;
    memset(&row, 0, sizeof(row));
    (void)snprintf(row.root, sizeof(row.root), "%s", root_hex);
    zcl_hex_encode(findings.study_root, 32, row.study_root);
    zcl_hex_encode(review.findings_root, 32, row.link_root);
    zcl_hex_encode(review.reviewer_pubkey, 32, row.author);
    row.code = review.verdict;
    row.sequence = (int64_t)review.sequence;
    row.created_at = review.created_unix;
    if (!db_zcode_science_review_save(ndb, &row))
        return ZCL_ERR(-1, "science-review-projection-save-failed");
    ZCL_CHECK(science_plan_mark_committed(ndb, &plan, root_hex));
    (void)snprintf(commit_out->result_root, sizeof(commit_out->result_root),
                   "%s", root_hex);
    return ZCL_OK;
}

/* ── vote ──────────────────────────────────────────────────────── */

struct zcl_result zcode_science_vote_submit(
    struct node_db *ndb, const char *workspace,
    const uint8_t *wire, size_t wire_len,
    const uint8_t expected_network_genesis[32],
    const uint8_t expected_voter_zid[32],
    const uint8_t expected_signer[32],
    bool confirm, int64_t now,
    struct zcode_science_plan_out *plan_out,
    struct zcode_science_commit_out *commit_out)
{
    if (!workspace || !wire ||
        wire_len != VCS_ZCODE_CURATION_VOTE_WIRE_BYTES ||
        !expected_network_genesis || !expected_voter_zid ||
        !expected_signer || !plan_out || !commit_out)
        return ZCL_ERR(-1, "science-vote-input-invalid");
    struct vcs_zcode_curation_vote_v1 vote;
    if (vcs_zcode_curation_vote_parse(wire, wire_len, &vote) !=
            VCS_ZCODE_SCIENCE_OK ||
        vcs_zcode_curation_vote_validate(&vote) != VCS_ZCODE_SCIENCE_OK)
        return ZCL_ERR(-1, "science-vote-wire-invalid");
    uint8_t vote_id[32];
    if (vcs_zcode_curation_vote_id(&vote, vote_id) != VCS_ZCODE_SCIENCE_OK)
        return ZCL_ERR(-1, "science-vote-id-failed");
    char vote_id_hex[65];
    zcl_hex_encode(vote_id, 32, vote_id_hex);
    if (!confirm) {
        memset(commit_out, 0, sizeof(*commit_out));
        return science_plan_open(ndb, "vote", wire, wire_len, NULL, 0, now,
                                 plan_out);
    }
    struct db_zcode_science_plan plan;
    bool done = false;
    ZCL_CHECK(science_commit_prelude(ndb, "vote", wire, wire_len, NULL, 0,
                                     true, now, &plan, &done, commit_out));
    memset(plan_out, 0, sizeof(*plan_out));
    (void)snprintf(plan_out->plan_root, sizeof(plan_out->plan_root), "%s",
                   plan.plan_root);
    (void)snprintf(plan_out->request_hash, sizeof(plan_out->request_hash),
                   "%s", plan.request_hash);
    plan_out->expires_unix = plan.expires_unix;
    if (done)
        return ZCL_OK;
    /* Cross-network identity: genesis, voter zid, and signer must all be
     * the expected ones, and the seal must verify. */
    enum vcs_zcode_science_error verr = vcs_zcode_curation_vote_verify(
        &vote, expected_network_genesis, expected_voter_zid, expected_signer,
        now);
    if (verr != VCS_ZCODE_SCIENCE_OK)
        return ZCL_ERR(-1, "science-vote-identity-rejected: %s",
                       vcs_zcode_science_error_string(verr));
    /* Idempotent by vote id: a re-submitted identical vote reattaches. */
    struct db_zcode_science_entry existing;
    if (db_zcode_science_vote_find(ndb, vote_id_hex, &existing)) {
        ZCL_CHECK(science_plan_mark_committed(ndb, &plan, vote_id_hex));
        (void)snprintf(commit_out->result_root,
                       sizeof(commit_out->result_root), "%s", vote_id_hex);
        commit_out->already_committed = true;
        return ZCL_OK;
    }
    /* Replay: a different vote id carrying this voter+sequence is a
     * replayed sequence number and is rejected. */
    char voter_hex[65];
    zcl_hex_encode(vote.voter_zid_root, 32, voter_hex);
    if (db_zcode_science_vote_sequence_seen(ndb, voter_hex,
                                            (int64_t)vote.sequence,
                                            vote_id_hex))
        return ZCL_ERR(-1, "science-vote-replay-rejected");
    if (!vcs_object_put_addressed(workspace, vote_id, wire, wire_len))
        return ZCL_ERR(-1, "science-vote-cas-store-failed");
    struct db_zcode_science_entry row;
    memset(&row, 0, sizeof(row));
    (void)snprintf(row.root, sizeof(row.root), "%s", vote_id_hex);
    zcl_hex_encode(vote.property_root, 32, row.link_root);
    zcl_hex_encode(vote.signer_pubkey, 32, row.aux_root);
    (void)snprintf(row.author, sizeof(row.author), "%s", voter_hex);
    row.code = vote.signal;
    row.sequence = (int64_t)vote.sequence;
    row.expires_at = vote.expires_unix;
    if (!db_zcode_science_vote_save(ndb, &row))
        return ZCL_ERR(-1, "science-vote-projection-save-failed");
    ZCL_CHECK(science_plan_mark_committed(ndb, &plan, vote_id_hex));
    (void)snprintf(commit_out->result_root, sizeof(commit_out->result_root),
                   "%s", vote_id_hex);
    return ZCL_OK;
}

/* ── rebuild ───────────────────────────────────────────────────── */

static void entry_from_study(struct db_zcode_science_entry *row,
                             const struct vcs_zcode_science_index_study_entry *e)
{
    memset(row, 0, sizeof(*row));
    (void)snprintf(row->root, sizeof(row->root), "%s", e->study_root_hex);
    (void)snprintf(row->link_root, sizeof(row->link_root), "%s",
                   e->hypothesis_root_hex);
    (void)snprintf(row->aux_root, sizeof(row->aux_root), "%s",
                   e->null_hypothesis_root_hex);
    row->code = e->required_reproductions;
    row->flags = e->required_reviews | (e->retracted ? 0x10000 : 0);
    row->sequence = (int64_t)e->sequence;
    row->created_at = e->created_unix;
    row->expires_at = e->expires_unix;
}

struct zcl_result zcode_science_rebuild(
    struct node_db *ndb, const char *workspace, int64_t now,
    struct zcode_science_rebuild_out *out)
{
    if (!ndb || !ndb->open || !workspace || !out)
        return ZCL_ERR(-1, "science-rebuild-input-invalid");
    struct vcs_zcode_science_index *index =
        vcs_zcode_science_index_build(workspace, now);
    if (!index)
        return ZCL_ERR(-1, "science-rebuild-index-failed");
    if (!db_zcode_science_projection_clear(ndb)) {
        vcs_zcode_science_index_free(index);
        return ZCL_ERR(-1, "science-rebuild-clear-failed");
    }
    memset(out, 0, sizeof(*out));
    bool ok = true;
    for (size_t i = 0; i < vcs_zcode_science_index_study_count(index); i++) {
        struct db_zcode_science_entry row;
        entry_from_study(&row, vcs_zcode_science_index_study_at(index, i));
        if (!db_zcode_science_study_save(ndb, &row)) ok = false;
        out->studies++;
    }
    for (size_t i = 0; i < vcs_zcode_science_index_result_count(index); i++) {
        const struct vcs_zcode_science_index_result_entry *e =
            vcs_zcode_science_index_result_at(index, i);
        struct db_zcode_science_entry row;
        memset(&row, 0, sizeof(row));
        (void)snprintf(row.root, sizeof(row.root), "%s", e->result_root_hex);
        (void)snprintf(row.study_root, sizeof(row.study_root), "%s",
                       e->study_root_hex);
        (void)snprintf(row.link_root, sizeof(row.link_root), "%s",
                       e->task_root_hex);
        (void)snprintf(row.aux_root, sizeof(row.aux_root), "%s",
                       e->candidate_root_hex);
        row.code = e->status;
        row.flags = e->retracted ? 1 : 0;
        row.sequence = (int64_t)e->sequence;
        row.created_at = e->started_unix;
        row.expires_at = e->finished_unix;
        if (!db_zcode_science_result_save(ndb, &row)) ok = false;
        out->results++;
    }
    for (size_t i = 0; i < vcs_zcode_science_index_reproduction_count(index);
         i++) {
        const struct vcs_zcode_science_index_reproduction_entry *e =
            vcs_zcode_science_index_reproduction_at(index, i);
        struct db_zcode_science_entry row;
        memset(&row, 0, sizeof(row));
        (void)snprintf(row.root, sizeof(row.root), "%s",
                       e->reproduction_root_hex);
        (void)snprintf(row.study_root, sizeof(row.study_root), "%s",
                       e->study_root_hex);
        (void)snprintf(row.link_root, sizeof(row.link_root), "%s",
                       e->original_result_root_hex);
        (void)snprintf(row.aux_root, sizeof(row.aux_root), "%s",
                       e->reproduced_result_root_hex);
        (void)snprintf(row.author, sizeof(row.author), "%s",
                       e->reproducer_pubkey_hex);
        row.code = e->verdict;
        row.sequence = (int64_t)e->sequence;
        row.created_at = e->created_unix;
        if (!db_zcode_science_reproduction_save(ndb, &row)) ok = false;
        out->reproductions++;
    }
    for (size_t i = 0; i < vcs_zcode_science_index_findings_count(index);
         i++) {
        const struct vcs_zcode_science_index_findings_entry *e =
            vcs_zcode_science_index_findings_at(index, i);
        struct db_zcode_science_entry row;
        memset(&row, 0, sizeof(row));
        (void)snprintf(row.root, sizeof(row.root), "%s", e->findings_root_hex);
        (void)snprintf(row.study_root, sizeof(row.study_root), "%s",
                       e->study_root_hex);
        (void)snprintf(row.link_root, sizeof(row.link_root), "%s",
                       e->result_root_hex);
        (void)snprintf(row.aux_root, sizeof(row.aux_root), "%s",
                       e->retraction_target_root_hex);
        row.code = e->severity;
        row.flags = e->flags;
        row.sequence = (int64_t)e->sequence;
        row.created_at = e->created_unix;
        if (!db_zcode_science_findings_save(ndb, &row)) ok = false;
        out->findings++;
    }
    for (size_t i = 0; i < vcs_zcode_science_index_vote_count(index); i++) {
        const struct vcs_zcode_science_index_vote_entry *e =
            vcs_zcode_science_index_vote_at(index, i);
        /* Rebuild keeps the replay discipline: the first (lowest-id) vote
         * for a voter+sequence wins; later ones are replay shapes and are
         * not projected. */
        if (vcs_zcode_science_index_vote_sequence_seen(
                index, e->voter_zid_root_hex, e->sequence, e->vote_id_hex))
            continue;
        struct db_zcode_science_entry row;
        memset(&row, 0, sizeof(row));
        (void)snprintf(row.root, sizeof(row.root), "%s", e->vote_id_hex);
        (void)snprintf(row.link_root, sizeof(row.link_root), "%s",
                       e->property_root_hex);
        (void)snprintf(row.aux_root, sizeof(row.aux_root), "%s",
                       e->signer_pubkey_hex);
        (void)snprintf(row.author, sizeof(row.author), "%s",
                       e->voter_zid_root_hex);
        row.code = e->signal;
        row.sequence = (int64_t)e->sequence;
        row.expires_at = e->expires_unix;
        if (!db_zcode_science_vote_save(ndb, &row)) ok = false;
        out->votes++;
    }
    for (size_t i = 0; i < vcs_zcode_science_index_review_count(index); i++) {
        const struct vcs_zcode_science_index_review_entry *e =
            vcs_zcode_science_index_review_at(index, i);
        struct db_zcode_science_entry row;
        memset(&row, 0, sizeof(row));
        (void)snprintf(row.root, sizeof(row.root), "%s", e->review_root_hex);
        /* study_root is recovered through the findings row when present. */
        const struct vcs_zcode_science_index_findings_entry *fe = NULL;
        for (size_t f = 0; f < vcs_zcode_science_index_findings_count(index);
             f++) {
            const struct vcs_zcode_science_index_findings_entry *cand =
                vcs_zcode_science_index_findings_at(index, f);
            if (strcmp(cand->findings_root_hex, e->findings_root_hex) == 0) {
                fe = cand;
                break;
            }
        }
        if (fe)
            (void)snprintf(row.study_root, sizeof(row.study_root), "%s",
                           fe->study_root_hex);
        (void)snprintf(row.link_root, sizeof(row.link_root), "%s",
                       e->findings_root_hex);
        (void)snprintf(row.author, sizeof(row.author), "%s",
                       e->reviewer_pubkey_hex);
        row.code = e->verdict;
        row.sequence = (int64_t)e->sequence;
        row.created_at = e->created_unix;
        if (!db_zcode_science_review_save(ndb, &row)) ok = false;
        out->reviews++;
    }
    vcs_zcode_science_index_free(index);
    if (!ok)
        return ZCL_ERR(-1, "science-rebuild-projection-save-failed");
    return ZCL_OK;
}
