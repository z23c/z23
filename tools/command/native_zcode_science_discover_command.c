/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Typed ZCODE science discovery commands over the rebuildable
 *          S5 rank projection. LOCAL and EXPLANATORY only: rank, votes,
 *          and mass never feed proof acceptance, routing, rewards, or
 *          protocol control. */

#include "command/native_command.h"

#include "base/hex.h"
#include "json/json.h"
#include "models/database.h"
#include "models/zcode_science.h"
#include "platform/time_compat.h"
#include "platform/directory_compat.h"
#include "util/safe_alloc.h"
#include "vcs/zcode_discovery_projection.h"
#include "vcs/zcode_discovery_rank.h"
#include "vcs/zcode_science_index.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ZDSC_PATH_MAX 4096
#define ZDSC_STUDY_FILTER_MAX 1024 /* the index study cap */
#define ZDSC_RENDER_DEFAULT 32
#define ZDSC_RENDER_MAX 512
#define ZDSC_SEARCH_MAX 96

static int zdsc_root_cmp(const void *a, const void *b)
{
    return memcmp(a, b, 32);
}

static const char *zdsc_str(const struct json_value *input, const char *key)
{
    const struct json_value *v = input ? json_get(input, key) : NULL;
    return v ? json_get_str(v) : NULL;
}

static int64_t zdsc_int(const struct json_value *input, const char *key,
                        int64_t fallback)
{
    const struct json_value *v = input ? json_get(input, key) : NULL;
    return v ? json_get_int(v) : fallback;
}

static void zdsc_fail(struct zcl_command_reply *reply, const char *code,
                      const char *detail, const char *leaf)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, "validate", false,
                           false, detail, leaf);
}

static void zdsc_fail_run(struct zcl_command_reply *reply, const char *code,
                          const char *detail, const char *leaf)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, code, "rank", false,
                           false, detail, leaf);
}

static const char *zdsc_datadir(const struct json_value *input)
{
    const char *datadir = zdsc_str(input, "datadir");
    if (!datadir || !datadir[0])
        datadir = zcl_native_command_datadir();
    return datadir;
}

/* The workspace CAS root: an explicit workspace must resolve; the default
 * is <datadir>/zcode (an absent one simply yields an empty corpus). */
static const char *zdsc_workspace(const struct json_value *input,
                                  char *resolved, size_t resolved_size)
{
    const char *workspace = zdsc_str(input, "workspace");
    if (workspace && workspace[0]) {
        if (platform_directory_canonical_real(workspace, resolved,
                                               resolved_size))
            return resolved;
        return NULL;
    }
    const char *datadir = zdsc_datadir(input);
    int n = snprintf(resolved, resolved_size, "%s/zcode", datadir);
    return n > 0 && (size_t)n < resolved_size ? resolved : NULL;
}

static int64_t zdsc_now(const struct json_value *input)
{
    return zdsc_int(input, "now_unix",
                    (int64_t)platform_time_wall_unix());
}

static bool zdsc_hex32(const char *hex, uint8_t out[32])
{
    return hex && strlen(hex) == 64 && zcl_hex_decode_lower(hex, out, 32);
}

static void zdsc_hex(const uint8_t root[32], char out[65])
{
    zcl_hex_encode(root, 32, out);
}

/* Escape LIKE wildcards and wrap for a substring match. */
static bool zdsc_search_like(const char *search, char *out, size_t out_size)
{
    if (!search || !search[0])
        return false;
    size_t at = 0;
    out[at++] = '%';
    for (size_t i = 0; search[i] && i < ZDSC_SEARCH_MAX; i++) {
        char c = search[i];
        if (c == '\\' || c == '%' || c == '_')
            out[at++] = '\\';
        out[at++] = c;
        if (at + 3 >= out_size)
            return false;
    }
    out[at++] = '%';
    out[at] = '\0';
    return true;
}

struct zdsc_build {
    struct vcs_zcode_science_index *index;
    struct vcs_zcode_discovery_scan_v1 *scan;
    struct vcs_zcode_discovery_graph_v1 graph;
    uint8_t corpus_root[32];
};

static void zdsc_build_free(struct zdsc_build *build)
{
    if (!build)
        return;
    vcs_zcode_discovery_graph_free(&build->graph);
    vcs_zcode_discovery_scan_free(build->scan);
    vcs_zcode_science_index_free(build->index);
    memset(build, 0, sizeof(*build));
}

/* index -> scan -> assemble. Returns false (with an error body set) on
 * allocation/assembly failure. */
static bool zdsc_projection(struct zdsc_build *build,
                            const char *workspace, int64_t now,
                            const uint8_t (*allowlist)[32],
                            size_t allowlist_count,
                            const uint8_t *genesis,
                            struct zcl_command_reply *reply,
                            const char *leaf)
{
    build->index = vcs_zcode_science_index_build(workspace, now);
    if (!build->index) {
        zdsc_fail_run(reply, "INDEX_BUILD_FAILED",
                      "the science index could not be built from the workspace CAS",
                      leaf);
        return false;
    }
    build->scan = vcs_zcode_discovery_projection_scan(
        workspace, build->index, allowlist, allowlist_count, genesis, now);
    if (!build->scan) {
        zdsc_fail_run(reply, "SCAN_FAILED",
                      "the discovery scan could not be assembled", leaf);
        return false;
    }
    memcpy(build->corpus_root, build->scan->corpus_root, 32);
    enum vcs_zcode_discovery_rank_error error =
        vcs_zcode_discovery_projection_assemble(build->scan, &build->graph);
    if (error != VCS_ZCODE_DISCOVERY_RANK_OK) {
        char detail[128];
        (void)snprintf(detail, sizeof(detail),
                       "graph assembly failed: %s",
                       vcs_zcode_discovery_rank_error_string(error));
        zdsc_fail_run(reply, "ASSEMBLE_FAILED", detail, leaf);
        return false;
    }
    return true;
}

static void zdsc_push_roots(struct json_value *data,
                            const struct zdsc_build *build,
                            const uint8_t graph_root[32],
                            const uint8_t seed_set_root[32])
{
    char hex[65];
    zdsc_hex(build->corpus_root, hex);
    (void)json_push_kv_str(data, "corpus_root", hex);
    zdsc_hex(graph_root, hex);
    (void)json_push_kv_str(data, "graph_root", hex);
    zdsc_hex(seed_set_root, hex);
    (void)json_push_kv_str(data, "seed_set_root", hex);
    (void)json_push_kv_int(data, "node_count",
                           (int64_t)build->graph.node_count);
    (void)json_push_kv_int(data, "edge_count",
                           (int64_t)build->graph.edge_count);
    (void)json_push_kv_int(data, "seed_count",
                           (int64_t)build->graph.seed_count);
    (void)json_push_kv_int(data, "omitted_node_count",
                           build->graph.omitted_node_count);
    (void)json_push_kv_int(data, "omitted_edge_count",
                           build->graph.omitted_edge_count);
    (void)json_push_kv_int(data, "votes_considered",
                           build->scan->votes_considered);
    (void)json_push_kv_int(data, "votes_accepted",
                           build->scan->votes_accepted);
}

void zcl_native_handle_zcode_science_discover(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *leaf = "zcode.science.discover";
    const char *search = zdsc_str(request->input, "search");
    const char *category = zdsc_str(request->input, "category");
    const char *hardware = zdsc_str(request->input, "hardware");
    const char *genesis_hex = zdsc_str(request->input, "network_genesis_root");
    if (search && strlen(search) > ZDSC_SEARCH_MAX) {
        zdsc_fail(reply, "BAD_SEARCH",
                  "search must be at most 96 characters", leaf);
        return;
    }
    if (category && category[0] && strcmp(category, "active") != 0 &&
        strcmp(category, "expired") != 0 &&
        strcmp(category, "retracted") != 0) {
        zdsc_fail(reply, "BAD_CATEGORY",
                  "category must be one of active, expired, retracted", leaf);
        return;
    }
    if (hardware && hardware[0] && strlen(hardware) != 64) {
        zdsc_fail(reply, "BAD_HARDWARE",
                  "hardware must be a 64-hex hardware profile root", leaf);
        return;
    }
    uint8_t genesis[32];
    const uint8_t *genesis_p = NULL;
    if (genesis_hex && genesis_hex[0]) {
        if (!zdsc_hex32(genesis_hex, genesis)) {
            zdsc_fail(reply, "BAD_IDENTITY",
                      "network_genesis_root must be 64 lowercase hex", leaf);
            return;
        }
        genesis_p = genesis;
    }
    int64_t max = zdsc_int(request->input, "max", ZDSC_RENDER_DEFAULT);
    if (max <= 0 || max > ZDSC_RENDER_MAX)
        max = ZDSC_RENDER_MAX;
    int64_t now = zdsc_now(request->input);
    char ws[ZDSC_PATH_MAX];
    const char *workspace = zdsc_workspace(request->input, ws, sizeof(ws));
    if (!workspace) {
        zdsc_fail(reply, "WORKSPACE_NOT_FOUND",
                  "workspace must name an existing directory", leaf);
        return;
    }

    /* Filter FIRST, over the SQL projection: search (root/hypothesis
     * substring) and category (projection state at now). */
    char search_like[ZDSC_SEARCH_MAX * 2 + 4];
    const char *search_like_p =
        zdsc_search_like(search, search_like, sizeof(search_like))
            ? search_like
            : NULL;
    struct node_db ndb = {0};
    struct sqlite3 *db = NULL;
    if (!zcl_native_node_db_require_readonly(
            zdsc_datadir(request->input), reply, "the science projection",
            &db, &ndb))
        return;
    struct db_zcode_science_entry *rows = zcl_malloc(
        sizeof(*rows) * ZDSC_STUDY_FILTER_MAX, "zcode.science.discover.rows");
    int row_count = 0;
    if (rows)
        row_count = db_zcode_science_study_list_filtered(
            &ndb, search_like_p,
            (category && category[0]) ? category : NULL, now, rows,
            ZDSC_STUDY_FILTER_MAX);
    zcl_native_node_db_close_readonly(&db, &ndb);
    if (!rows) {
        zdsc_fail_run(reply, "ALLOCATION",
                      "the study filter could not allocate its row buffer",
                      leaf);
        return;
    }

    /* The allowlist: filtered study roots, ascending. */
    uint8_t(*allowlist)[32] = zcl_malloc(
        sizeof(*allowlist) * (size_t)(row_count > 0 ? row_count : 1),
        "zcode.science.discover.allowlist");
    if (!allowlist) {
        free(rows);
        zdsc_fail_run(reply, "ALLOCATION",
                      "the study allowlist could not be allocated", leaf);
        return;
    }
    size_t allow_count = 0;
    for (int i = 0; i < row_count; i++)
        if (zcl_hex_decode_lower(rows[i].root, allowlist[allow_count], 32))
            allow_count++;
    free(rows);

    struct zdsc_build build = {0};
    build.index = vcs_zcode_science_index_build(workspace, now);
    if (!build.index) {
        free(allowlist);
        zdsc_fail_run(reply, "INDEX_BUILD_FAILED",
                      "the science index could not be built from the workspace CAS",
                      leaf);
        return;
    }
    /* The hardware predicate: keep only studies with at least one projected
     * result carrying the requested hardware profile root. */
    if (hardware && hardware[0]) {
        size_t kept = 0;
        for (size_t i = 0; i < allow_count; i++) {
            char study_hex[65];
            zdsc_hex(allowlist[i], study_hex);
            bool match = false;
            size_t results =
                vcs_zcode_science_index_result_count(build.index);
            for (size_t r = 0; r < results && !match; r++) {
                const struct vcs_zcode_science_index_result_entry *re =
                    vcs_zcode_science_index_result_at(build.index, r);
                if (strcmp(re->study_root_hex, study_hex) == 0 &&
                    strcmp(re->hardware_profile_root_hex, hardware) == 0)
                    match = true;
            }
            if (match)
                memcpy(allowlist[kept++], allowlist[i], 32);
        }
        allow_count = kept;
    }
    if (allow_count > 1)
        qsort(allowlist, allow_count, sizeof(*allowlist), zdsc_root_cmp);
    build.scan = vcs_zcode_discovery_projection_scan(
        workspace, build.index, allowlist, allow_count, genesis_p, now);
    free(allowlist);
    if (!build.scan) {
        vcs_zcode_science_index_free(build.index);
        zdsc_fail_run(reply, "SCAN_FAILED",
                      "the discovery scan could not be assembled", leaf);
        return;
    }
    memcpy(build.corpus_root, build.scan->corpus_root, 32);
    enum vcs_zcode_discovery_rank_error error =
        vcs_zcode_discovery_projection_assemble(build.scan, &build.graph);
    if (error != VCS_ZCODE_DISCOVERY_RANK_OK) {
        char detail[128];
        (void)snprintf(detail, sizeof(detail), "graph assembly failed: %s",
                       vcs_zcode_discovery_rank_error_string(error));
        zdsc_build_free(&build);
        zdsc_fail_run(reply, "ASSEMBLE_FAILED", detail, leaf);
        return;
    }

    uint8_t filter_root[32], zero_root[32] = {0};
    vcs_zcode_discovery_filter_policy_root(
        search, (category && category[0]) ? category : NULL,
        (hardware && hardware[0]) ? hardware : NULL, genesis_p, filter_root);
    if (build.graph.node_count == 0) {
        /* The empty filtered corpus: roots are zero, every count honest. */
        zdsc_push_roots(&reply->data, &build, zero_root, zero_root);
        char filter_hex[65];
        zdsc_hex(filter_root, filter_hex);
        (void)json_push_kv_str(&reply->data, "filter_policy_root", filter_hex);
        (void)json_push_kv_bool(&reply->data, "truncated", false);
        (void)json_push_kv_int(&reply->data, "coverage_mass", 0);
        (void)json_push_kv_int(&reply->data, "convergence_residual", 0);
        struct json_value arr;
        json_init(&arr);
        json_set_array(&arr);
        (void)json_push_kv(&reply->data, "entries", &arr);
        json_free(&arr);
        (void)json_push_kv_int(&reply->data, "count", 0);
        zdsc_build_free(&build);
        return;
    }

    struct vcs_zcode_discovery_rank_entry_v1 *entries = zcl_malloc(
        sizeof(*entries) * build.graph.node_count,
        "zcode.science.discover.entries");
    if (!entries) {
        zdsc_build_free(&build);
        zdsc_fail_run(reply, "ALLOCATION",
                      "the rank entry buffer could not be allocated", leaf);
        return;
    }
    struct vcs_zcode_discovery_rank_result_v1 result;
    uint64_t residual = 0;
    error = vcs_zcode_discovery_projection_compute(
        &build.graph, filter_root, entries, &result, &residual);
    if (error != VCS_ZCODE_DISCOVERY_RANK_OK) {
        char detail[128];
        (void)snprintf(detail, sizeof(detail), "rank compute failed: %s",
                       vcs_zcode_discovery_rank_error_string(error));
        free(entries);
        zdsc_build_free(&build);
        zdsc_fail_run(reply, "RANK_FAILED", detail, leaf);
        return;
    }

    size_t rendered = build.graph.node_count < (size_t)max
                          ? build.graph.node_count
                          : (size_t)max;
    uint64_t coverage = 0;
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < rendered; i++) {
        coverage += entries[i].mass;
        /* The explanation: this node's direct citation count and seed
         * weight, by binary search on the ascending node array. */
        uint32_t direct_citations = 0, seed_weight = 0;
        size_t lo = 0, hi = build.graph.node_count;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            int cmp = memcmp(entries[i].property_root,
                             build.graph.nodes[mid].property_root, 32);
            if (cmp == 0) {
                direct_citations = build.graph.in_degree[mid];
                seed_weight = build.graph.node_seed_weight[mid];
                break;
            }
            if (cmp < 0)
                hi = mid;
            else
                lo = mid + 1;
        }
        struct json_value entry;
        char hex[65];
        json_init(&entry);
        json_set_object(&entry);
        zdsc_hex(entries[i].property_root, hex);
        (void)json_push_kv_str(&entry, "property_root", hex);
        (void)json_push_kv_int(&entry, "mass", (int64_t)entries[i].mass);
        (void)json_push_kv_int(&entry, "mass_share_millionths",
            (int64_t)(entries[i].mass * UINT64_C(1000000) /
                      VCS_ZCODE_DISCOVERY_RANK_MASS));
        (void)json_push_kv_int(&entry, "direct_citations", direct_citations);
        (void)json_push_kv_int(&entry, "seed_weight", seed_weight);
        (void)json_push_back(&arr, &entry);
        json_free(&entry);
    }
    zdsc_push_roots(&reply->data, &build, result.graph_root,
                    result.seed_set_root);
    char filter_hex[65];
    zdsc_hex(filter_root, filter_hex);
    (void)json_push_kv_str(&reply->data, "filter_policy_root", filter_hex);
    (void)json_push_kv_bool(&reply->data, "truncated",
                            rendered < build.graph.node_count);
    (void)json_push_kv_int(&reply->data, "coverage_mass", (int64_t)coverage);
    (void)json_push_kv_int(&reply->data, "convergence_residual",
                           (int64_t)residual);
    (void)json_push_kv(&reply->data, "entries", &arr);
    json_free(&arr);
    (void)json_push_kv_int(&reply->data, "count", (int64_t)rendered);
    free(entries);
    zdsc_build_free(&build);
}

void zcl_native_handle_zcode_science_rank_snapshot(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *leaf = "zcode.science.rank.snapshot";
    const char *workspace_in = zdsc_str(request->input, "workspace");
    const char *genesis_hex = zdsc_str(request->input, "network_genesis_root");
    char ws[ZDSC_PATH_MAX];
    if (!workspace_in || !workspace_in[0] ||
        !platform_directory_canonical_real(workspace_in, ws, sizeof(ws))) {
        zdsc_fail(reply, "WORKSPACE_NOT_FOUND",
                  "workspace must name an existing directory", leaf);
        return;
    }
    uint8_t genesis[32];
    const uint8_t *genesis_p = NULL;
    if (genesis_hex && genesis_hex[0]) {
        if (!zdsc_hex32(genesis_hex, genesis)) {
            zdsc_fail(reply, "BAD_IDENTITY",
                      "network_genesis_root must be 64 lowercase hex", leaf);
            return;
        }
        genesis_p = genesis;
    }
    int64_t now = zdsc_now(request->input);
    struct zdsc_build build = {0};
    if (!zdsc_projection(&build, ws, now, NULL, 0, genesis_p, reply, leaf))
        return;
    uint8_t graph_root[32] = {0}, seed_set_root[32] = {0};
    if (build.graph.node_count > 0) {
        enum vcs_zcode_discovery_rank_error error =
            vcs_zcode_discovery_graph_root(build.graph.nodes,
                                           build.graph.node_count,
                                           build.graph.edges,
                                           build.graph.edge_count, graph_root);
        if (error == VCS_ZCODE_DISCOVERY_RANK_OK)
            error = vcs_zcode_discovery_seed_set_root(
                build.graph.nodes, build.graph.node_count, build.graph.seeds,
                build.graph.seed_count, seed_set_root);
        if (error != VCS_ZCODE_DISCOVERY_RANK_OK) {
            char detail[128];
            (void)snprintf(detail, sizeof(detail), "root compute failed: %s",
                           vcs_zcode_discovery_rank_error_string(error));
            zdsc_build_free(&build);
            zdsc_fail_run(reply, "ROOT_FAILED", detail, leaf);
            return;
        }
    }
    zdsc_push_roots(&reply->data, &build, graph_root, seed_set_root);
    (void)json_push_kv_str(&reply->data, "authority",
                           "REBUILDABLE_PROJECTION_OVER_CAS");
    zdsc_build_free(&build);
}
