/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native handlers for the registry-owned `code` tree — the in-binary,
 * hierarchical, token-bounded source-code navigator. Each leaf opens the
 * cognition/modules/codeindex store (which self-rebuilds on open if the source tree is
 * stale), runs one query, and renders exactly one bounded JSON document within
 * ZCL_COMMAND_RESULT_BUDGET: a structured array plus compact human one-liners.
 *
 * Local, read-only, deterministic. Never bound to RPC or REST (native
 * transport only). The source of truth is IN-TREE SOURCE SCANNING, so these
 * answer "where is X / what calls X / what's in this file" without spending
 * tokens reading whole files.
 */

#define _GNU_SOURCE
#include "command/native_command.h"

#include "kernel/command_registry.h"
#include "json/json.h"
#include "codeindex/codeindex.h"
#include "codeindex/codeindex_build.h"
#include "codeindex/codeindex_context.h"
#include "codeindex/codeindex_merkle.h"
#include "config/command_catalog.h"
#include "config/command_handler_index.h"
#include "controllers/agent_impact_harness.h"
#include "controllers/agent_impact_rules.h"
#include "base/hex.h"
#include "kpi/kpi.h"
#include "platform/file_metadata.h"
#include "platform/time_compat.h"
#include "territory/territory.h"
#include "test_group_catalog.h"
#include "command/native_code_priv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Bounded copy of at most `max` visible chars of `src` into dst[cap]; appends
 * "…"-as-"..." when truncated. Always NUL-terminates. */
void code_trunc(char *dst, size_t cap, const char *src, size_t max)
{
    if (!dst || cap == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    size_t lim = max;
    if (lim > cap - 1) lim = cap - 1;
    size_t i = 0;
    for (; i < lim && src[i]; i++) dst[i] = src[i];
    if (src[i] != '\0' && i + 3 < cap) {
        dst[i++] = '.'; dst[i++] = '.'; dst[i++] = '.';
    }
    dst[i] = '\0';
}

/* The checkout root the index scans: an explicit context source_root wins, then
 * ZCL_DEV_SOURCE_ROOT, else the current directory. */
const char *code_source_root(const struct zcl_command_request *request)
{
    if (request && request->context && request->context->source_root &&
        request->context->source_root[0])
        return request->context->source_root;
    const char *env = getenv("ZCL_DEV_SOURCE_ROOT");
    return env && env[0] ? env : ".";
}

/* Open the index or fail the reply with a bounded internal error. */
struct codeindex *code_open(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply)
{
    struct codeindex *ci = codeindex_open(code_source_root(request));
    if (!ci) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "CODEINDEX_OPEN",
                               "dispatch", true, false,
                               "could not open or rebuild the code index",
                               code_source_root(request));
    }
    return ci;
}

/* code.group and code.map consume only source-derived file/group rows.
 * Compiler depfile epochs affect include edges, not these answers, so do not
 * put their post-build writeback on either command's warm latency path. */
struct codeindex *code_open_source_view(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    struct codeindex *ci =
        codeindex_open_source_view(code_source_root(request));
    if (!ci) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "CODEINDEX_OPEN",
                               "dispatch", true, false,
                               "could not open or rebuild the source index",
                               code_source_root(request));
    }
    return ci;
}

static int64_t code_index_leaf_bytes(const char *root, const char *leaf)
{
    char path[4096];
    int n = snprintf(path, sizeof(path), "%s/.codeindex/%s", root, leaf);
    if (n <= 0 || (size_t)n >= sizeof(path)) return 0;
    struct platform_file_metadata meta;
    if (platform_file_metadata_read(path, &meta) != PLATFORM_FILE_METADATA_OK)
        return 0;
    if (meta.size > (uint64_t)INT64_MAX) return INT64_MAX;
    return (int64_t)meta.size;
}

void zcl_native_handle_code_index_metrics(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const char *root = code_source_root(request);
    struct codeindex *ci = codeindex_open_existing(root);
    if (!ci) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "CODEINDEX_OPEN",
                               "dispatch", true, false,
                               "could not open the existing code index",
                               root);
        return;
    }

    long long cold_ms = 0, cold_files = 0;
    (void)codeindex_build_cold_ms(ci, &cold_ms, &cold_files);

    int64_t files = 0, symbols = 0, refs = 0, groups = 0;
    if (!codeindex_table_counts(ci, &files, &symbols, &refs, &groups)) {
        codeindex_close(ci);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "COUNT_FAILED",
                               "query", false, false,
                               "could not count code-index tables", root);
        return;
    }

    int64_t t0 = platform_time_monotonic_ms();
    bool current = false;
    if (!codeindex_source_view_is_current(ci, &current)) {
        codeindex_close(ci);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "FRESHNESS_CHECK",
                               "measure", false, false,
                               "could not run a source-only freshness check",
                               root);
        return;
    }
    int64_t freshness_ms = platform_time_monotonic_ms() - t0;
    if (freshness_ms < 0) freshness_ms = 0;

    struct ci_group_metric gm[CODE_METRICS_GROUP_CAP];
    int ng = codeindex_group_metrics(ci, gm, CODE_METRICS_GROUP_CAP);
    if (ng < 0) {
        codeindex_close(ci);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "GROUP_METRICS",
                               "query", false, false,
                               "could not read per-group index counts", root);
        return;
    }
    struct json_value per;
    json_init(&per);
    json_set_array(&per);
    for (int i = 0; i < ng; i++) {
        struct json_value o;
        json_init(&o);
        json_set_object(&o);
        (void)json_push_kv_str(&o, "name", gm[i].name);
        (void)json_push_kv_int(&o, "files", gm[i].files);
        (void)json_push_kv_int(&o, "lines", gm[i].lines);
        (void)json_push_back(&per, &o);
        json_free(&o);
    }

    (void)json_push_kv_int(&reply->data, "build_cold_ms", cold_ms);
    (void)json_push_kv_int(&reply->data, "build_cold_files", cold_files);
    (void)json_push_kv_int(&reply->data, "image_bytes",
                           code_index_leaf_bytes(root, "index.kv"));
    (void)json_push_kv_int(&reply->data, "merkle_bytes",
                           code_index_leaf_bytes(root, "source_tree.merkle"));
    (void)json_push_kv_int(
        &reply->data, "territory_bytes",
        code_index_leaf_bytes(root, "territory_reach.v1") +
            code_index_leaf_bytes(root, "territory_rollup.v1"));
    (void)json_push_kv_int(&reply->data, "freshness_check_ms", freshness_ms);
    (void)json_push_kv_bool(&reply->data, "stale", !current);
    (void)json_push_kv_int(&reply->data, "files_indexed", files);
    (void)json_push_kv_int(&reply->data, "symbols", symbols);
    (void)json_push_kv_int(&reply->data, "refs", refs);
    (void)json_push_kv_int(&reply->data, "groups_count", groups);
    (void)json_push_kv(&reply->data, "per_group", &per);
    json_free(&per);
    codeindex_close(ci);
}

/* Positional/typed string input for `key` (NULL when absent/empty). */
const char *code_str(const struct zcl_command_request *request,
                            const char *key)
{
    const char *v = json_get_str(json_get(request->input, key));
    return (v && v[0]) ? v : NULL;
}

/* Push one string onto a JSON array. */
void code_push_line(struct json_value *arr, const char *s)
{
    struct json_value item;
    json_init(&item);
    json_set_str(&item, s);
    (void)json_push_back(arr, &item);
    json_free(&item);
}

/* Push a completed object onto an array (copies, then frees the local). */
void code_push_obj(struct json_value *arr, struct json_value *obj)
{
    (void)json_push_back(arr, obj);
    json_free(obj);
}

/* ── the routing link (code.tests + code.file) ───────────────────────────── */

/* MIRROR of tools/dev/devloop_plan.c's consensus-risk detection: the whole
 * sealed core/ tree (zcl_devloop_path_is_sealed_core) plus the non-core
 * consensus/validation prefixes (path_is_consensus_risk). Kept in lockstep by
 * the route-parity invariant in test_codeindex.c — `code tests <path>`'s route
 * MUST equal `dev test plan`'s proof_group for the same single file, and that
 * test fails the moment this list drifts from devloop's. */
bool code_path_is_consensus_risk(const char *path)
{
    if (!path) return false;
    if (strncmp(path, "core/", 5) == 0) return true;   /* whole sealed core */
    static const char *const prefixes[] = {
        "core/modules/validation/", "core/modules/chain/", "core/modules/primitives/", "core/modules/crypto/",
        "core/modules/sapling/", "engine/jobs/",
    };
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++)
        if (strncmp(path, prefixes[i], strlen(prefixes[i])) == 0) return true;
    return false;
}

const char *zcl_native_code_route_for_path(const char *path,
                                           struct agent_impact_acc *acc,
                                           bool *consensus_risk)
{
    struct agent_impact_acc local = {0};
    struct agent_impact_acc *a = acc ? acc : &local;
    if (acc)
        memset(acc, 0, sizeof(*acc));
    /* Harness-file routing runs FIRST: harness .c files under
     * tests/harness/src/ are leaves nothing #includes, so the shared rule
     * table below (which only
     * fires on a compiled-source edge or a hand-written glob) never reaches
     * them. See agent_impact_harness.h for the two structural conventions
     * this resolves — test_<group>.c naming and the Windows-acceptance
     * sources table — ahead of any shared-rule match. */
    (void)agent_impact_apply_harness_routes(path, a);
    (void)agent_impact_apply_shared_rules(path, a);
    /* Secondary candidates: a harness/lint-gate file that names this path
     * inside a string literal (a binary name, a bare path) with no
     * #include edge. Appended last so it can only ADD to test_groups, never
     * change which group is picked as the route below. */
    (void)agent_impact_apply_name_reference_routes(path, a);
    bool crisk = code_path_is_consensus_risk(path);
    if (consensus_risk) *consensus_risk = crisk;
    /* devloop_plan.c:171-185: a consensus/sealed surface always routes to the
     * heaviest proof; else the first matched shared-rule group; else the
     * lint-gate floor. */
    if (crisk) return "consensus_parity";
    if (a->groups_len > 0) {
        char full[ZCL_TEST_GROUP_FULL_MAX];
        if (zcl_test_group_resolve_exact(a->groups[0], full)) {
            for (size_t i = 0; i < zcl_test_group_catalog_count(); i++) {
                const char *registered = zcl_test_group_catalog_at(i);
                if (!registered || strcmp(registered, full) != 0)
                    continue;
                if (strcmp(a->groups[0], registered) == 0)
                    return registered;
                if ((strncmp(registered, "test_", 5) == 0 ||
                     strncmp(registered, "spec_", 5) == 0) &&
                    strcmp(a->groups[0], registered + 5) == 0)
                    return registered + 5;
                break;
            }
        }
    }
    return "make_lint_gates";
}

/* Emit the routing block for a changed source `path` into reply->data:
 * test_groups[] (the matched shared-rule groups, capped), the routed group,
 * whether it is a consensus surface, and whether any rule matched. Shared by
 * code.tests (top-level) and code.file (appended after the file info). Returns
 * the routed group and, via `consensus_risk`, whether it is a consensus
 * surface — so the caller can render a summary without recomputing. */
const char *code_emit_route(
    struct zcl_command_reply *reply, const char *path, bool *consensus_risk,
    char route_storage[static ZCL_AGENT_IMPACT_GROUP_MAX])
{
    struct agent_impact_acc acc = {0};
    bool crisk = false;
    const char *resolved =
        zcl_native_code_route_for_path(path, &acc, &crisk);
    if (!resolved)
        resolved = "make_lint_gates";
    (void)snprintf(route_storage, ZCL_AGENT_IMPACT_GROUP_MAX, "%s", resolved);
    const char *route = route_storage;
    if (consensus_risk) *consensus_risk = crisk;

    struct json_value arr;
    json_init(&arr); json_set_array(&arr);
    size_t shown = acc.groups_len < (size_t)CODE_TESTS_CAP
                       ? acc.groups_len : (size_t)CODE_TESTS_CAP;
    for (size_t i = 0; i < shown; i++)
        code_push_line(&arr, acc.groups[i]);

    (void)json_push_kv(&reply->data, "test_groups", &arr);
    (void)json_push_kv_str(&reply->data, "route", route);
    (void)json_push_kv_bool(&reply->data, "consensus_risk", crisk);
    (void)json_push_kv_bool(&reply->data, "matched", acc.shared_rule_hits > 0);
    json_free(&arr);
    return route;
}

/* ── the dispatch join (code.room + code.capsule) ─────────────────────────
 *
 * WF4 4C landed a PARALLEL stringizing expansion of the command .def catalogs
 * (config/command_handler_index.h): {path, handler_name} for every leaf that
 * binds a non-NULL native handler. Joined here against the code index's own
 * symbol table for one FILE, this answers "which commands does this file
 * back" without the registry ever exposing a function pointer as data.
 * Deterministic: dispatch-index declaration order (catalog order), first
 * match wins per entry. Returns the count (0 when nothing in `def_path` backs
 * a command — a real answer, not a guess). */
int code_commands_for_file(struct codeindex *ci, const char *def_path,
                                  const char **out, int cap)
{
    if (!ci || !def_path || !def_path[0] || !out || cap <= 0) return 0;
    static struct ci_symbol syms[64];
    int ns = codeindex_symbols_in_file(ci, def_path, syms, 64);
    if (ns < 0) ns = 0;
    const struct zcl_command_handler_index *ix = zcl_command_handler_index();
    int n = 0;
    for (size_t i = 0; ix && i < ix->count && n < cap; i++) {
        const char *hn = ix->entries[i].handler_name;
        if (!hn || !hn[0]) continue;
        for (int j = 0; j < ns; j++) {
            if (strcmp(syms[j].name, hn) == 0) {
                out[n++] = ix->entries[i].path;
                break;
            }
        }
    }
    return n;
}

/* Exact function-pointer/.def join for one handler symbol. Unlike the file
 * join used by code.room, this never attributes sibling handlers in the same
 * translation unit to the requested symbol. */
int code_commands_for_symbol(const char *symbol_name,
                                    const char **out, int cap)
{
    if (!symbol_name || !symbol_name[0] || !out || cap <= 0) return 0;
    const struct zcl_command_handler_index *ix = zcl_command_handler_index();
    int n = 0;
    for (size_t i = 0; ix && i < ix->count && n < cap; i++) {
        const char *handler = ix->entries[i].handler_name;
        if (handler && strcmp(handler, symbol_name) == 0)
            out[n++] = ix->entries[i].path;
    }
    return n;
}

/* ── code.tests ─────────────────────────────────────────────────────────── */
/* The routing link: which focused test group a change to one file routes to.
 * Pure path→route (no index open needed) — mirrors `dev test plan`'s
 * proof_group so an agent can decide what to run before touching the tree. */
void zcl_native_handle_code_tests(const struct zcl_command_request *request,
                                  struct zcl_command_reply *reply)
{
    const char *path = code_str(request, "path");
    if (!path) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_PATH",
                               "normalize", false, false,
                               "code tests requires a repo-relative path", "");
        return;
    }

    (void)json_push_kv_str(&reply->data, "path", path);
    bool crisk = false;
    char route_storage[ZCL_AGENT_IMPACT_GROUP_MAX];
    const char *route = code_emit_route(reply, path, &crisk, route_storage);

    char summary[224];
    (void)snprintf(summary, sizeof(summary), "%s routes to `%s`%s", path, route,
                   crisk ? " (consensus surface — heaviest proof)" : "");
    (void)json_push_kv_str(&reply->data, "summary", summary);
}

