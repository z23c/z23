/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the reuse projection `zcode work start` shows a human — which
 * already-published packages cover the goal, which are usable now, and what
 * still has to be created — plus the exact zcode.use continuation, split out
 * of native_zcode_work_command.c so each function stays under the
 * cyclomatic-complexity cap; sibling declarations live in
 * native_zcode_work_priv.h. This is a projection: it admits nothing and
 * installs nothing. */

#include "command/native_command.h"
#include "native_zcode_work_priv.h"

#include "json/json.h"
#include "util/safe_alloc.h"
#include "vcs/package_index.h"
#include "vcs/package_prepare.h"
#include "vcs/package_recipe.h"
#include "vcs/package_release.h"
#include "vcs/package_reuse.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Everything the two rendered documents report about the local search. */
struct zwork_reuse_counts {
    size_t indexed;
    size_t skipped;
    size_t matched;
    size_t count;
    size_t invalid_installs;
    size_t superseded_releases;
    size_t composed_packages;
};

/* The three parallel bounded arrays one search needs, allocated together so
 * a partial allocation can never be observed. */
struct zwork_reuse_arena {
    struct zwork_reuse_candidate *candidates;
    struct vcs_package_recipe *recipes;
    struct vcs_package_reuse_input *inputs;
};

const char *zwork_reuse_datadir(
    const struct zcl_command_request *request)
{
    const char *datadir = zwork_str(request->input, "datadir");
    if (datadir && datadir[0]) return datadir;
    datadir = zcl_native_command_datadir();
    return datadir && datadir[0] ? datadir : NULL;
}

bool zwork_use_next_input(
    const struct zcl_command_request *request, const char *package_ref,
    struct json_value *next_input)
{
    const char *datadir = zwork_str(request->input, "datadir");
    json_init(next_input);
    json_set_object(next_input);
    return json_push_kv_str(next_input, "name_or_root", package_ref) &&
        ((!datadir || !datadir[0]) ||
         json_push_kv_str(next_input, "datadir", datadir));
}

static bool zwork_reuse_unavailable_search(struct json_value *plan,
                                           const char *license)
{
    return json_push_kv_str(plan, "stage", "Finding reusable software") &&
        json_push_kv_str(plan, "search_status", "datadir_not_provided") &&
        json_push_kv_str(plan, "network_discovery", "not_requested") &&
        json_push_kv_str(plan, "license_filter", license ? license : "") &&
        json_push_kv_bool(plan, "license_filter_applied", false) &&
        json_push_kv_str(plan, "license_filter_scope", "not_applied") &&
        json_push_kv_bool(plan, "dependency_closure_filtered", false) &&
        json_push_kv_bool(plan, "new_source_license_constrained", false);
}

/* Without a datadir there are no local package facts at all: say so
 * explicitly rather than reporting an empty search as a finished one. */
static bool zwork_reuse_render_unavailable(const char *license,
                                           struct json_value *plan,
                                           struct json_value *expert)
{
    json_init(plan); json_set_object(plan);
    json_init(expert); json_set_object(expert);
    struct json_value selected, pending, roots;
    json_init(&selected); json_set_array(&selected);
    json_init(&pending); json_set_array(&pending);
    json_init(&roots); json_set_array(&roots);
    bool ok = zwork_reuse_unavailable_search(plan, license) &&
        json_push_kv(plan, "reused", &selected) &&
        json_push_kv(plan, "available_after_use", &pending) &&
        json_push_kv_int(plan, "packages_scanned", 0) &&
        json_push_kv_bool(plan, "new_code_required", true) &&
        json_push_kv_str(plan, "missing", "local package facts unavailable") &&
        json_push_kv(expert, "selected_roots", &roots);
    json_free(&roots); json_free(&pending); json_free(&selected); return ok;
}

static struct vcs_package_index *zwork_reuse_open_index(
    const char *datadir, char zcode_dir[ZWORK_PATH_MAX])
{
    int n = snprintf(zcode_dir, ZWORK_PATH_MAX, "%s/zcode", datadir);
    if (n <= 0 || n >= ZWORK_PATH_MAX) return NULL;
    return vcs_package_index_build(zcode_dir);
}

/* An exact license search must fit the bounded result set; a wider match is
 * refused rather than silently truncated. */
static bool zwork_reuse_filter(
    const struct vcs_package_index *index, const char *license,
    const struct vcs_package_index_entry **filtered, size_t indexed,
    size_t *matched_out, bool *truncated_out)
{
    if (!license) { *matched_out = indexed; return true; }
    const struct vcs_package_search search = {.license = license};
    size_t matched = vcs_package_index_search(
        index, &search, filtered, VCS_PACKAGE_REUSE_MAX_INPUTS);
    *matched_out = matched;
    if (matched <= VCS_PACKAGE_REUSE_MAX_INPUTS) return true;
    *truncated_out = true;
    return false;
}

static bool zwork_reuse_arena_alloc(struct zwork_reuse_arena *arena,
                                    size_t count)
{
    size_t slots = count ? count : 1u;
    arena->candidates = zcl_calloc(slots, sizeof(*arena->candidates),
                                   "zcode.work.reuse_candidates");
    arena->recipes = zcl_calloc(slots, sizeof(*arena->recipes),
                                "zcode.work.reuse_recipes");
    arena->inputs = zcl_calloc(slots, sizeof(*arena->inputs),
                               "zcode.work.reuse_inputs");
    return arena->candidates && arena->recipes && arena->inputs;
}

static void zwork_reuse_arena_free(struct zwork_reuse_arena *arena,
                                   size_t count)
{
    for (size_t i = 0; arena->recipes && i < count; i++)
        vcs_package_recipe_free(&arena->recipes[i]);
    free(arena->inputs); free(arena->recipes); free(arena->candidates);
}

/* One candidate per index row the lifecycle would still resolve, carrying
 * the public API text its verified recipe and installed receipt name. */
static void zwork_reuse_collect(
    const char *datadir, const char *zcode_dir,
    const struct vcs_package_index *index, const char *license,
    const struct vcs_package_index_entry **filtered,
    const struct vcs_package_prepared *prepared,
    struct zwork_reuse_arena *arena, struct zwork_reuse_counts *counts)
{
    for (size_t i = 0; i < counts->count; i++) {
        const struct vcs_package_index_entry *entry =
            license ? filtered[i] : vcs_package_index_at(index, i);
        struct zwork_reuse_candidate *candidate = &arena->candidates[i];
        candidate->input.package = entry;
        candidate->input.locked = zwork_lock_has_root(
            &prepared->lock, entry->package_root_hex);
        vcs_package_recipe_init(&arena->recipes[i]);
        bool lifecycle_release = zwork_reuse_is_lifecycle_release(
            index, entry);
        if (!lifecycle_release) counts->superseded_releases++;
        bool recipe_ok = lifecycle_release && zwork_reuse_load_facts(
            zcode_dir, entry, &arena->recipes[i]);
        candidate->input.compatible = recipe_ok;
        if (recipe_ok) {
            for (size_t h = 0; h < arena->recipes[i].public_headers.count &&
                 candidate->input.api_count < VCS_PACKAGE_REUSE_MAX_APIS;
                 h++) {
                const char *header = arena->recipes[i].public_headers.items[h];
                (void)zwork_reuse_api_add(candidate, header, strlen(header));
            }
            zwork_reuse_installed(datadir, zcode_dir, entry, candidate);
        }
        if (candidate->installed_invalid) counts->invalid_installs++;
    }
}

/* "usable now" is the difference between a package the caller can build
 * against immediately and one that still needs an explicit zcode.use. */
static const char *zwork_reuse_composition(
    const struct vcs_package_reuse_input *input,
    const struct vcs_package_reuse_plan *reuse)
{
    return input->locked ? "already_declared" :
        input->installed
            ? reuse->disposition == VCS_PACKAGE_REUSE_PARTIAL
                ? "candidate_only" : "available_now"
            : "explicit_use_required";
}

static bool zwork_reuse_row_json(const struct vcs_package_reuse_input *input,
                                 const struct vcs_package_reuse_plan *reuse,
                                 struct json_value *row)
{
    struct json_value apis;
    json_init(&apis); json_set_array(&apis);
    bool ok = json_push_kv_str(row, "name", input->package->name) &&
        json_push_kv_str(row, "semver", input->package->semver) &&
        json_push_kv_str(row, "license", input->package->license) &&
        json_push_kv_bool(row, "installed", input->installed) &&
        json_push_kv_int(row, "peer_advertisers",
                         (int64_t)input->peer_advertisers) &&
        json_push_kv_str(row, "composition",
                         zwork_reuse_composition(input, reuse));
    for (size_t a = 0; ok && a < input->api_count; a++) {
        struct json_value api; json_init(&api);
        json_set_str(&api, input->apis[a]);
        ok = json_push_back(&apis, &api); json_free(&api);
    }
    ok = ok && json_push_kv(row, "apis", &apis);
    json_free(&apis);
    return ok;
}

static bool zwork_reuse_root_json(const struct vcs_package_reuse_input *input,
                                  int64_t score, struct json_value *root)
{
    return json_push_kv_str(root, "name", input->package->name) &&
        json_push_kv_str(root, "semver", input->package->semver) &&
        json_push_kv_str(root, "package_root",
                         input->package->package_root_hex) &&
        json_push_kv_bool(root, "already_locked", input->locked) &&
        json_push_kv_int(root, "score", score);
}

/* The first package that is not usable yet names the exact zcode.use the
 * human must run before any code is created. */
static bool zwork_reuse_row_track(
    const struct vcs_package_reuse_input *input, bool usable_now,
    size_t *ready_count, char selected_root[65],
    char prepare_ref[VCS_PACKAGE_RELEASE_NAME_MAX +
                     VCS_PACKAGE_RELEASE_SEMVER_MAX + 2u])
{
    const size_t ref_cap = VCS_PACKAGE_RELEASE_NAME_MAX +
        VCS_PACKAGE_RELEASE_SEMVER_MAX + 2u;
    if (usable_now) (*ready_count)++;
    if (selected_root[0] == '\0')
        (void)snprintf(selected_root, 65, "%s",
                       input->package->package_root_hex);
    if (usable_now || prepare_ref[0] != '\0') return true;
    int rn = snprintf(prepare_ref, ref_cap, "%s",
                      input->package->package_root_hex);
    return rn > 0 && rn < (int)ref_cap;
}

static bool zwork_reuse_selected_json(
    const struct vcs_package_reuse_input *inputs,
    const struct vcs_package_reuse_plan *reuse,
    struct json_value *selected, struct json_value *pending,
    struct json_value *roots, size_t *ready_count, char selected_root[65],
    char prepare_ref[VCS_PACKAGE_RELEASE_NAME_MAX +
                     VCS_PACKAGE_RELEASE_SEMVER_MAX + 2u])
{
    bool ok = true;
    for (size_t i = 0; ok && i < reuse->selected_count; i++) {
        const struct vcs_package_reuse_input *input =
            &inputs[reuse->selected[i].input_index];
        bool usable_now = input->locked || input->installed ||
            reuse->disposition == VCS_PACKAGE_REUSE_COMPLETE;
        struct json_value row, root;
        json_init(&row); json_set_object(&row);
        json_init(&root); json_set_object(&root);
        ok = zwork_reuse_row_json(input, reuse, &row) &&
            json_push_back(usable_now ? selected : pending, &row) &&
            zwork_reuse_root_json(input, reuse->selected[i].score, &root) &&
            json_push_back(roots, &root) &&
            zwork_reuse_row_track(input, usable_now, ready_count,
                                  selected_root, prepare_ref);
        json_free(&root); json_free(&row);
    }
    return ok;
}

static bool zwork_reuse_plan_search_json(
    struct json_value *plan, const char *license, size_t skipped,
    const struct zwork_peer_inventory *peer)
{
    return json_push_kv_str(plan, "stage", "Finding reusable software") &&
        json_push_kv_str(
            plan, "search_status",
            skipped ? "bounded_projection_incomplete" : "complete") &&
        json_push_kv_str(
            plan, "network_discovery",
            !peer->live ? "unavailable_no_live_swarm"
            : !peer->pointer_board_available
                ? "signed_pointer_board_unavailable"
                : "signed_pointer_peer_inventory_consulted") &&
        json_push_kv_str(plan, "license_filter", license ? license : "") &&
        json_push_kv_bool(plan, "license_filter_applied", license != NULL) &&
        json_push_kv_str(
            plan, "license_filter_scope",
            license ? "selected_top_level_release_only" : "none") &&
        json_push_kv_bool(plan, "dependency_closure_filtered", false) &&
        json_push_kv_bool(plan, "new_source_license_constrained", false);
}

static bool zwork_reuse_plan_result_json(
    struct json_value *plan, const struct vcs_package_reuse_plan *reuse,
    const char *goal, const char *prepare_ref,
    struct json_value *selected, struct json_value *pending)
{
    return json_push_kv_str(plan, "disposition",
            vcs_package_reuse_disposition_string(reuse->disposition)) &&
        json_push_kv(plan, "reused", selected) &&
        json_push_kv(plan, "available_after_use", pending) &&
        json_push_kv_bool(plan, "new_code_required",
                          reuse->new_code_required) &&
        json_push_kv_str(plan, "missing",
            prepare_ref[0]
                ? "explicitly use the selected package before creating code"
                : reuse->new_code_required ? goal : "none");
}

static bool zwork_reuse_expert_peer_json(
    struct json_value *expert, const char *license,
    const struct zwork_peer_inventory *peer)
{
    return json_push_kv_str(expert, "search_order",
                            "semantic_locality_peer_identity") &&
        json_push_kv_int(expert, "peer_roots_seen",
                         (int64_t)peer->roots_seen) &&
        json_push_kv_int(expert, "peer_roots_matched",
                         (int64_t)peer->roots_matched) &&
        json_push_kv_bool(expert, "peer_inventory_truncated",
                          peer->truncated) &&
        json_push_kv_str(expert, "license_filter", license ? license : "") &&
        json_push_kv_str(expert, "license_filter_basis",
                         "persisted_release_exact_spdx");
}

static bool zwork_reuse_expert_counts_json(
    struct json_value *expert, const struct zwork_reuse_counts *counts,
    const struct vcs_package_reuse_plan *reuse, struct json_value *roots)
{
    return json_push_kv_int(expert, "packages_indexed",
                            (int64_t)counts->indexed) &&
        json_push_kv_int(expert, "package_release_rows_skipped",
                         (int64_t)counts->skipped) &&
        json_push_kv_int(expert, "packages_filter_matched",
                         (int64_t)counts->matched) &&
        json_push_kv_int(expert, "packages_scanned",
                         (int64_t)reuse->packages_scanned) &&
        json_push_kv_bool(expert, "packages_truncated",
                          counts->matched > counts->count) &&
        json_push_kv_int(expert, "compatible_matches",
                         (int64_t)reuse->compatible_matches) &&
        json_push_kv_int(expert, "incompatible_matches",
                         (int64_t)reuse->incompatible_matches) &&
        json_push_kv_int(expert, "invalid_installs",
                         (int64_t)counts->invalid_installs) &&
        json_push_kv_int(expert, "lifecycle_nonselected_release_rows",
                         (int64_t)counts->superseded_releases) &&
        json_push_kv_int(expert, "composed_dependency_roots",
                         (int64_t)counts->composed_packages) &&
        json_push_kv(expert, "selected_roots", roots);
}

/* The human plan and its expert companion are one bounded projection of the
 * same search; a package still to be prepared clears the ready selection. */
static bool zwork_reuse_documents(
    struct json_value *plan_json, struct json_value *expert_json,
    const char *goal, const char *license,
    const struct vcs_package_reuse_plan *reuse,
    const struct zwork_reuse_counts *counts,
    const struct zwork_peer_inventory *peer,
    const struct vcs_package_reuse_input *inputs, char selected_root[65],
    char prepare_ref[VCS_PACKAGE_RELEASE_NAME_MAX +
                     VCS_PACKAGE_RELEASE_SEMVER_MAX + 2u],
    bool ok)
{
    json_init(plan_json); json_set_object(plan_json);
    json_init(expert_json); json_set_object(expert_json);
    struct json_value selected, pending, roots;
    json_init(&selected); json_set_array(&selected);
    json_init(&pending); json_set_array(&pending);
    json_init(&roots); json_set_array(&roots);
    size_t ready_count = 0;
    ok = ok && zwork_reuse_selected_json(inputs, reuse, &selected, &pending,
                                        &roots, &ready_count, selected_root,
                                        prepare_ref);
    if (reuse->disposition != VCS_PACKAGE_REUSE_PARTIAL || ready_count > 0)
        prepare_ref[0] = '\0';
    ok = ok &&
        zwork_reuse_plan_search_json(plan_json, license, counts->skipped,
                                     peer) &&
        zwork_reuse_plan_result_json(plan_json, reuse, goal, prepare_ref,
                                     &selected, &pending) &&
        zwork_reuse_expert_peer_json(expert_json, license, peer) &&
        zwork_reuse_expert_counts_json(expert_json, counts, reuse, &roots);
    if (ok && counts->invalid_installs > 0)
        ok = json_push_kv_str(
            plan_json, "note",
            "One or more installed packages were ignored because their exact receipts or outputs did not verify");
    json_free(&roots); json_free(&pending); json_free(&selected);
    return ok;
}

bool zwork_reuse_render(
    const struct zcl_command_request *request, const char *goal,
    const char *license,
    struct vcs_package_prepared *prepared, struct json_value *plan_json,
    struct json_value *expert_json, bool *complete_out, bool *composed_out,
    bool *filter_truncated_out, bool *filter_incomplete_out,
    size_t *indexed_out, size_t *matched_out, size_t *skipped_out,
    char selected_root[65],
    char prepare_ref[VCS_PACKAGE_RELEASE_NAME_MAX +
                     VCS_PACKAGE_RELEASE_SEMVER_MAX + 2u])
{
    *complete_out = false;
    *composed_out = false;
    *filter_truncated_out = false;
    *filter_incomplete_out = false;
    *indexed_out = 0;
    *matched_out = 0;
    *skipped_out = 0;
    selected_root[0] = '\0';
    prepare_ref[0] = '\0';
    const char *datadir = zwork_reuse_datadir(request);
    if (!datadir)
        return zwork_reuse_render_unavailable(license, plan_json, expert_json);
    char zcode_dir[ZWORK_PATH_MAX];
    struct vcs_package_index *index = zwork_reuse_open_index(datadir,
                                                             zcode_dir);
    if (!index) return false;
    struct zwork_reuse_counts counts = {0};
    counts.indexed = vcs_package_index_count(index);
    counts.skipped = vcs_package_index_skipped_count(index);
    *indexed_out = counts.indexed;
    *skipped_out = counts.skipped;
    const struct vcs_package_index_entry
        *filtered[VCS_PACKAGE_REUSE_MAX_INPUTS];
    if (license && counts.skipped > 0) {
        *filter_incomplete_out = true;
        vcs_package_index_free(index);
        return false;
    }
    if (!zwork_reuse_filter(index, license, filtered, counts.indexed,
                            &counts.matched, filter_truncated_out)) {
        *matched_out = counts.matched;
        vcs_package_index_free(index);
        return false;
    }
    *matched_out = counts.matched;
    counts.count = counts.matched < VCS_PACKAGE_REUSE_MAX_INPUTS
        ? counts.matched : VCS_PACKAGE_REUSE_MAX_INPUTS;
    struct zwork_reuse_arena arena = {0};
    if (!zwork_reuse_arena_alloc(&arena, counts.count)) {
        zwork_reuse_arena_free(&arena, 0);
        vcs_package_index_free(index); return false;
    }
    zwork_reuse_collect(datadir, zcode_dir, index, license, filtered,
                        prepared, &arena, &counts);
    struct zwork_peer_inventory peer_inventory;
    zwork_peer_inventory_apply(arena.candidates, counts.count,
                               &peer_inventory);
    for (size_t i = 0; i < counts.count; i++)
        arena.inputs[i] = arena.candidates[i].input;
    struct vcs_package_reuse_plan reuse;
    bool ok = vcs_package_reuse_plan_build(goal, arena.inputs, counts.count,
                                           &reuse) &&
        zwork_compose_selected_lock(prepared, index, arena.candidates, &reuse,
                                    &counts.composed_packages);
    ok = zwork_reuse_documents(plan_json, expert_json, goal, license,
                               &reuse, &counts, &peer_inventory,
                               arena.inputs, selected_root, prepare_ref, ok);
    *complete_out = ok && reuse.disposition == VCS_PACKAGE_REUSE_COMPLETE;
    *composed_out = ok && counts.composed_packages > 0;
    zwork_reuse_arena_free(&arena, counts.count);
    vcs_package_index_free(index);
    return ok;
}
