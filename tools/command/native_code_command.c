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
#include "controllers/agent_impact_rules.h"
#include "base/hex.h"
#include "kpi/kpi.h"
#include "territory/territory.h"
#include "test_group_catalog.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Conservative per-list caps. The whole reply envelope must fit in
 * ZCL_COMMAND_RESULT_BUDGET (4096 bytes), so lists stay small and each rendered
 * string is truncated. Overflow beyond a cap is reported, never silently cut. */
enum {
    CODE_SUBGROUP_CAP = 40,
    CODE_FILE_CAP     = 16,
    CODE_SYM_CAP      = 20,
    CODE_INC_CAP      = 16,
    CODE_REFS_DEFAULT = 5,
    CODE_REFS_MAX     = 20,
    CODE_FIND_DEFAULT = 5,
    CODE_FIND_MAX     = 12,
    CODE_OTHER_DEF_CAP = 5,
    CODE_TESTS_CAP     = 12,   /* max test_groups emitted by code.tests/code.file */
    CODE_MAP_ROOT_CAP  = 16,   /* max root groups rendered by code.map */
    CODE_MAP_SHAPE_CAP = 16,   /* max app/ shapes rendered by code.map */
    CODE_COMMAND_CAP    = 12,  /* max command paths per file (code.room/code.capsule) */
    CODE_CAPSULE_CALLER_CAP = 10,
    CODE_CAPSULE_CALLEE_CAP = 10,
    CODE_CAPSULE_INC_CAP    = 10,
    CODE_IMPACT_CAP     = 120, /* max impacted_files rendered by code.impact
                                * (list budget; the engine's own cap+truncated
                                * contract, not a second layer of paging) */
    CODE_IMPACT_INC_CAP = 32,  /* direct_includes fan-out cap */
    /* include_dependents is a DISPLAY cap over a larger true answer, which is
     * the opposite of CODE_IMPACT_CAP above and is why the two are separate
     * constants. The reverse-include query still runs at CODE_IMPACT_CAP, so
     * `include_dependent_count` and `include_dimension` describe the whole
     * answer; only the rendered array is abridged, because a hub header has
     * hundreds of readers and this leaf's declared reply budget is 8 KB. A
     * consumer that needs the full set asks the store, not the summary. */
    CODE_IMPACT_INCDEP_LIST_CAP = 20,
    CODE_IMPACT_SYM_CAP = 64,  /* symbols-in-file cap when summing direct_callers */
    CODE_IMPACT_REF_CAP = 256, /* per-symbol callers cap when summing direct_callers */
    CODE_MERKLE_CHILD_CAP = 40, /* direct subtree roots rendered by code.merkle
                                 * (list budget); `children_total` always
                                 * reports the true count */
};

/* Bounded copy of at most `max` visible chars of `src` into dst[cap]; appends
 * "…"-as-"..." when truncated. Always NUL-terminates. */
static void code_trunc(char *dst, size_t cap, const char *src, size_t max)
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
static const char *code_source_root(const struct zcl_command_request *request)
{
    if (request && request->context && request->context->source_root &&
        request->context->source_root[0])
        return request->context->source_root;
    const char *env = getenv("ZCL_DEV_SOURCE_ROOT");
    return env && env[0] ? env : ".";
}

/* Open the index or fail the reply with a bounded internal error. */
static struct codeindex *code_open(const struct zcl_command_request *request,
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
static struct codeindex *code_open_source_view(
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

/* Positional/typed string input for `key` (NULL when absent/empty). */
static const char *code_str(const struct zcl_command_request *request,
                            const char *key)
{
    const char *v = json_get_str(json_get(request->input, key));
    return (v && v[0]) ? v : NULL;
}

/* Optional bounded "limit" input: clamp to [1, max], default `def`. */
static int code_limit(const struct zcl_command_request *request, int def, int max)
{
    const struct json_value *v = json_get(request->input, "limit");
    if (!v) return def;
    long n = (long)json_get_int(v);
    if (n < 1) n = 1;
    if (n > max) n = max;
    return (int)n;
}

/* Push one string onto a JSON array. */
static void code_push_line(struct json_value *arr, const char *s)
{
    struct json_value item;
    json_init(&item);
    json_set_str(&item, s);
    (void)json_push_back(arr, &item);
    json_free(&item);
}

/* Push a completed object onto an array (copies, then frees the local). */
static void code_push_obj(struct json_value *arr, struct json_value *obj)
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
static bool code_path_is_consensus_risk(const char *path)
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
    (void)agent_impact_apply_shared_rules(path, a);
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
static const char *code_emit_route(
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
static int code_commands_for_file(struct codeindex *ci, const char *def_path,
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
static int code_commands_for_symbol(const char *symbol_name,
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

/* ── code.group ─────────────────────────────────────────────────────────── */
void zcl_native_handle_code_group(const struct zcl_command_request *request,
                                  struct zcl_command_reply *reply)
{
    struct codeindex *ci = code_open_source_view(request, reply);
    if (!ci) return;

    const char *arg = code_str(request, "group");

    static struct ci_group groups[512];
    int ng = codeindex_groups(ci, groups, (int)(sizeof(groups) / sizeof(groups[0])));
    if (ng < 0) ng = 0;

    struct json_value list, lines;
    json_init(&list);  json_set_array(&list);
    json_init(&lines); json_set_array(&lines);

    if (!arg) {
        /* No arg: the top buckets (direct children of "root", plus root). */
        int shown = 0;
        for (int i = 0; i < ng; i++) {
            const char *p = groups[i].parent;
            bool top = (p[0] == '\0') || strcmp(p, "root") == 0;
            if (!top) continue;
            if (shown >= CODE_SUBGROUP_CAP) break;
            char purpose[80];
            code_trunc(purpose, sizeof(purpose), groups[i].purpose, 64);
            int fc = codeindex_count_files_in_group(ci, groups[i].path, true);
            if (fc < 0) fc = 0;
            struct json_value o;
            json_init(&o); json_set_object(&o);
            (void)json_push_kv_str(&o, "path", groups[i].path);
            (void)json_push_kv_str(&o, "kind", groups[i].kind);
            (void)json_push_kv_int(&o, "file_count", fc);
            (void)json_push_kv_str(&o, "purpose", purpose);
            code_push_obj(&list, &o);
            char line[176];
            (void)snprintf(line, sizeof(line), "%s (%d files)%s%s", groups[i].path,
                           fc, purpose[0] ? " — " : "", purpose);
            code_push_line(&lines, line);
            shown++;
        }
        (void)json_push_kv_str(&reply->data, "scope", "top");
        (void)json_push_kv(&reply->data, "groups", &list);
        (void)json_push_kv(&reply->data, "lines", &lines);
        (void)json_push_kv_int(&reply->data, "count", shown);
        char summary[128];
        (void)snprintf(summary, sizeof(summary),
                       "%d top source groups; run `code group <path>` to descend",
                       shown);
        (void)json_push_kv_str(&reply->data, "summary", summary);
        json_free(&list); json_free(&lines);
        codeindex_close(ci);
        return;
    }

    /* Arg given: that group's immediate subgroups, then its files. */
    static struct ci_file files[CODE_FILE_CAP + 1];
    int nf = codeindex_files_in_group(ci, arg, files, CODE_FILE_CAP + 1);
    if (nf < 0) nf = 0;
    bool files_trunc = nf > CODE_FILE_CAP;
    if (files_trunc) nf = CODE_FILE_CAP;

    struct json_value farr;
    json_init(&farr); json_set_array(&farr);

    /* Subgroup purposes mirror the top-bucket branch above, but a LARGE group
     * (lib: 34 modules x ~64-char purposes, emitted twice — JSON field + text
     * line) cannot fit the kernel's 4096-byte ZCL_COMMAND_RESULT_BUDGET.
     * Assemble WITH purposes first, measure, and rebuild without them when the
     * reply would overflow: a purpose-less listing (the pre-purpose output)
     * beats a RESPONSE_BUDGET_EXCEEDED error. */
    int nsub = 0;
    for (bool with_purpose = true;; with_purpose = false) {
        json_free(&list);  json_init(&list);  json_set_array(&list);
        json_free(&lines); json_init(&lines); json_set_array(&lines);
        json_free(&farr);  json_init(&farr);  json_set_array(&farr);
        nsub = 0;
        for (int i = 0; i < ng && nsub < CODE_SUBGROUP_CAP; i++) {
            if (strcmp(groups[i].parent, arg) != 0) continue;
            int fc = codeindex_count_files_in_group(ci, groups[i].path, true);
            if (fc < 0) fc = 0;
            char purpose[80];
            purpose[0] = '\0';
            if (with_purpose)
                code_trunc(purpose, sizeof(purpose), groups[i].purpose, 64);
            struct json_value o;
            json_init(&o); json_set_object(&o);
            (void)json_push_kv_str(&o, "path", groups[i].path);
            (void)json_push_kv_str(&o, "kind", groups[i].kind);
            (void)json_push_kv_int(&o, "file_count", fc);
            if (with_purpose)
                (void)json_push_kv_str(&o, "purpose", purpose);
            code_push_obj(&list, &o);
            char sline[176];
            (void)snprintf(sline, sizeof(sline), "%s (%d files)%s%s",
                           groups[i].path, fc, purpose[0] ? " — " : "",
                           purpose);
            code_push_line(&lines, sline);
            nsub++;
        }
        for (int i = 0; i < nf; i++) {
            char purpose[72];
            code_trunc(purpose, sizeof(purpose), files[i].purpose, 55);
            struct json_value o;
            json_init(&o); json_set_object(&o);
            (void)json_push_kv_str(&o, "path", files[i].path);
            (void)json_push_kv_str(&o, "purpose", purpose);
            code_push_obj(&farr, &o);
            char line[200];
            (void)snprintf(line, sizeof(line), "%s%s%s", files[i].path,
                           purpose[0] ? " — " : "", purpose);
            code_push_line(&lines, line);
        }
        if (!with_purpose) break;
        /* ~900 bytes reserved for the result envelope + the scalar fields
         * pushed below; json_write overflow counts as the full scratch. */
        char scratch[ZCL_COMMAND_RESULT_BUDGET + 1];
        size_t used = 0;
        const struct json_value *parts[] = { &list, &farr, &lines };
        for (size_t p = 0; p < sizeof(parts) / sizeof(parts[0]); p++) {
            size_t n = json_write(parts[p], scratch, sizeof(scratch));
            used += (n == 0 || n >= sizeof(scratch)) ? sizeof(scratch) : n;
        }
        if (used <= ZCL_COMMAND_RESULT_BUDGET - 900)
            break;
    }

    (void)json_push_kv_str(&reply->data, "scope", "group");
    (void)json_push_kv_str(&reply->data, "group", arg);
    (void)json_push_kv(&reply->data, "subgroups", &list);
    (void)json_push_kv(&reply->data, "files", &farr);
    (void)json_push_kv(&reply->data, "lines", &lines);
    (void)json_push_kv_int(&reply->data, "subgroup_count", nsub);
    (void)json_push_kv_int(&reply->data, "file_count", nf);
    (void)json_push_kv_bool(&reply->data, "files_truncated", files_trunc);
    if (nsub == 0 && nf == 0)
        (void)json_push_kv_bool(&reply->data, "found", false);
    char summary[160];
    (void)snprintf(summary, sizeof(summary),
                   "group %s: %d subgroup(s), %d file(s)%s", arg, nsub, nf,
                   files_trunc ? " (more not shown)" : "");
    (void)json_push_kv_str(&reply->data, "summary", summary);

    json_free(&list); json_free(&farr); json_free(&lines);
    codeindex_close(ci);
}

/* ── code.file ──────────────────────────────────────────────────────────── */
void zcl_native_handle_code_file(const struct zcl_command_request *request,
                                 struct zcl_command_reply *reply)
{
    const char *path = code_str(request, "path");
    if (!path) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_PATH",
                               "normalize", false, false,
                               "code file requires a repo-relative path", "");
        return;
    }
    struct codeindex *ci = code_open(request, reply);
    if (!ci) return;

    struct ci_file finfo;
    bool ffound = false;
    (void)codeindex_file(ci, path, &finfo, &ffound);

    static struct ci_symbol syms[CODE_SYM_CAP + 1];
    int ns = codeindex_symbols_in_file(ci, path, syms, CODE_SYM_CAP + 1);
    if (ns < 0) ns = 0;
    bool syms_trunc = ns > CODE_SYM_CAP;
    if (syms_trunc) ns = CODE_SYM_CAP;

    static char incs[CODE_INC_CAP + 1][256];
    int ni = codeindex_includes_of_file(ci, path, incs, CODE_INC_CAP + 1);
    if (ni < 0) ni = 0;
    bool inc_trunc = ni > CODE_INC_CAP;
    if (inc_trunc) ni = CODE_INC_CAP;

    /* D4: `"includes":[]` had exactly one meaning here — "this file includes
     * nothing" — and it was WRONG for every header in the tree. The edges come
     * from compiler depfiles keyed on the translation unit, so a header (or a
     * .def registry) can never appear on the left of one; a file whose entire
     * body is `#include "base/safe_alloc.h"` rendered include_count 0 with
     * includes_truncated false, and any proof graph built on that inherited the
     * lie. There was an honest flag for "the cap fired" and none for "the graph
     * cannot answer" — so add one, and use the SAME word the impact closure and
     * the result cache use for an absent graph. */
    const char *inc_status = "complete";
    if (inc_trunc) {
        inc_status = "closure-truncated";
    } else if (!codeindex_path_is_translation_unit(path)) {
        inc_status = "not-a-translation-unit";
    } else {
        int64_t edges = codeindex_include_edge_count(ci);
        if (edges == 0)
            inc_status = "no-include-graph";
    }

    (void)json_push_kv_str(&reply->data, "path", path);
    (void)json_push_kv_str(&reply->data, "group", ffound ? finfo.group : "");
    if (ffound)
        (void)json_push_kv_str(&reply->data, "purpose", finfo.purpose);
    (void)json_push_kv_bool(&reply->data, "found",
                            ffound || ns > 0 || ni > 0);

    /* code.file emits ONLY the structured `symbols` array (the machine-readable
     * form); the redundant per-symbol human `lines` string is dropped so a large
     * file's reply fits the 4096-byte result budget. `signature` carries the
     * human-readable content; the CLI can render lines from the structured rows. */
    struct json_value sarr, iarr;
    json_init(&sarr);  json_set_array(&sarr);
    json_init(&iarr);  json_set_array(&iarr);

    for (int i = 0; i < ns; i++) {
        char sig[72];
        code_trunc(sig, sizeof(sig), syms[i].signature, 60);
        int line = syms[i].def_path[0] && strcmp(syms[i].def_path, path) == 0
                       ? syms[i].def_line : syms[i].decl_line;
        struct json_value o;
        json_init(&o); json_set_object(&o);
        (void)json_push_kv_str(&o, "name", syms[i].name);
        char kind[2] = { syms[i].kind, '\0' };
        (void)json_push_kv_str(&o, "kind", kind);
        (void)json_push_kv_int(&o, "line", line);
        (void)json_push_kv_str(&o, "signature", sig);
        if (syms[i].partial)
            (void)json_push_kv_bool(&o, "partial", true);
        code_push_obj(&sarr, &o);
    }
    for (int i = 0; i < ni; i++)
        code_push_line(&iarr, incs[i]);

    (void)json_push_kv(&reply->data, "symbols", &sarr);
    (void)json_push_kv(&reply->data, "includes", &iarr);
    (void)json_push_kv_int(&reply->data, "symbol_count", ns);
    (void)json_push_kv_int(&reply->data, "include_count", ni);
    (void)json_push_kv_bool(&reply->data, "symbols_truncated", syms_trunc);
    (void)json_push_kv_bool(&reply->data, "includes_truncated", inc_trunc);
    (void)json_push_kv_str(&reply->data, "includes_status", inc_status);
    bool inc_complete = strcmp(inc_status, "complete") == 0;
    (void)json_push_kv_bool(&reply->data, "includes_complete", inc_complete);
    char summary[176];
    (void)snprintf(summary, sizeof(summary),
                   "%s: %d symbol(s)%s, %d include(s)%s", path, ns,
                   syms_trunc ? "+" : "",
                   ni, inc_complete ? "" : " (INCOMPLETE)");
    (void)json_push_kv_str(&reply->data, "summary", summary);

    /* The routing link: which focused test group a change to THIS file routes
     * to (mirrors `dev test plan` / code.tests). Lets an editor jump from a
     * file to its proof group in one call. */
    char route_storage[ZCL_AGENT_IMPACT_GROUP_MAX];
    (void)code_emit_route(reply, path, NULL, route_storage);

    json_free(&sarr); json_free(&iarr);
    codeindex_close(ci);
}

/* ── code.sym ───────────────────────────────────────────────────────────── */
void zcl_native_handle_code_sym(const struct zcl_command_request *request,
                                struct zcl_command_reply *reply)
{
    const char *name = code_str(request, "name");
    if (!name) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_NAME",
                               "normalize", false, false,
                               "code sym requires a symbol name", "");
        return;
    }
    struct codeindex *ci = code_open(request, reply);
    if (!ci) return;

    struct ci_symbol s;
    bool found = false;
    (void)codeindex_symbol(ci, name, &s, &found);
    if (!found) {
        (void)json_push_kv_str(&reply->data, "name", name);
        (void)json_push_kv_bool(&reply->data, "found", false);
        char summary[160];
        (void)snprintf(summary, sizeof(summary),
                       "no indexed symbol named '%s'; try `code find %s`",
                       name, name);
        (void)json_push_kv_str(&reply->data, "summary", summary);
        codeindex_close(ci);
        return;
    }

    char sig[320], doc[224];
    code_trunc(sig, sizeof(sig), s.signature, 300);
    code_trunc(doc, sizeof(doc), s.doc, 200);
    char kind[2] = { s.kind, '\0' };

    (void)json_push_kv_bool(&reply->data, "found", true);
    (void)json_push_kv_str(&reply->data, "name", s.name);
    (void)json_push_kv_str(&reply->data, "kind", kind);
    (void)json_push_kv_str(&reply->data, "def_path", s.def_path);
    (void)json_push_kv_int(&reply->data, "def_line", s.def_line);
    (void)json_push_kv_str(&reply->data, "decl_path", s.decl_path);
    (void)json_push_kv_int(&reply->data, "decl_line", s.decl_line);
    (void)json_push_kv_str(&reply->data, "signature", sig);
    (void)json_push_kv_str(&reply->data, "doc", doc);
    (void)json_push_kv_str(&reply->data, "guard", s.guard);
    (void)json_push_kv_str(&reply->data, "group", s.group);
    if (s.partial)
        (void)json_push_kv_bool(&reply->data, "partial", true);

    /* The ~150-token rendered card as the human one-liner block. */
    char card[600];
    int cn = codeindex_render_card(ci, name, card, sizeof(card));
    if (cn > 0)
        (void)json_push_kv_str(&reply->data, "card", card);

    /* Other same-named definitions (overloads/statics in multiple files). */
    static struct ci_symbol hits[CODE_OTHER_DEF_CAP + 4];
    int nh = codeindex_find(ci, name, hits, (int)(sizeof(hits) / sizeof(hits[0])));
    if (nh < 0) nh = 0;
    struct json_value others;
    json_init(&others); json_set_array(&others);
    int shown = 0;
    for (int i = 0; i < nh && shown < CODE_OTHER_DEF_CAP; i++) {
        if (strcmp(hits[i].name, name) != 0) continue;              /* exact only */
        if (hits[i].def_path[0] == '\0') continue;                  /* bare decl */
        if (hits[i].def_line == s.def_line &&
            strcmp(hits[i].def_path, s.def_path) == 0) continue;    /* the primary */
        struct json_value o;
        json_init(&o); json_set_object(&o);
        (void)json_push_kv_str(&o, "def_path", hits[i].def_path);
        (void)json_push_kv_int(&o, "def_line", hits[i].def_line);
        code_push_obj(&others, &o);
        shown++;
    }
    if (shown > 0)
        (void)json_push_kv(&reply->data, "other_defs", &others);
    json_free(&others);

    char summary[224];
    (void)snprintf(summary, sizeof(summary), "%s [%s] %s:%d", s.name, kind,
                   s.def_path[0] ? s.def_path : s.decl_path,
                   s.def_path[0] ? s.def_line : s.decl_line);
    (void)json_push_kv_str(&reply->data, "summary", summary);

    codeindex_close(ci);
}

/* ── code.capsule ───────────────────────────────────────────────────────── */
/* WF4 4B: one bounded document composing everything code.sym + code.refs +
 * code.file + code.tests would take four calls to assemble, for ONE symbol:
 * identity (linkage-aware id, kind, def/decl site, signature, group), direct
 * callers/callees (codeindex_callers/callees, each capped), the in-tree
 * includes of its def file, the command paths whose registered handler is
 * defined there (code_commands_for_file), and the test route. Budget-aware
 * self-shrinking: when the droppable sections (includes, callees, callers)
 * would push the reply past ZCL_COMMAND_RESULT_BUDGET, they are dropped ONE
 * AT A TIME in that fixed order — includes first (least load-bearing: an
 * `code file` call away), then callees, then callers — and never
 * identity/def/route/other_defs/commands. `dropped_sections` names what was
 * cut, so a caller knows the capsule is honest, not silently truncated. */
void zcl_native_handle_code_capsule(const struct zcl_command_request *request,
                                    struct zcl_command_reply *reply)
{
    const char *query = code_str(request, "name");
    if (!query) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_NAME",
                               "normalize", false, false,
                               "code capsule requires a symbol name", "");
        return;
    }
    struct codeindex *ci = code_open(request, reply);
    if (!ci) return;

    struct ci_symbol s;
    bool found = false;
    bool by_id = strchr(query, ':') != NULL;
    if (by_id)
        (void)codeindex_symbol_by_id(ci, query, &s, &found);
    else
        (void)codeindex_symbol(ci, query, &s, &found);
    if (!found) {
        (void)json_push_kv_str(&reply->data, "query", query);
        (void)json_push_kv_bool(&reply->data, "found", false);
        char summary[160];
        (void)snprintf(summary, sizeof(summary),
                       "no indexed symbol named '%s'; try `code find %s`",
                       query, query);
        (void)json_push_kv_str(&reply->data, "summary", summary);
        codeindex_close(ci);
        return;
    }

    char id[400];
    id[0] = '\0';
    (void)codeindex_symbol_record_id(&s, id, sizeof(id));

    char sig[320];
    code_trunc(sig, sizeof(sig), s.signature, 300);
    char kind[2] = { s.kind, '\0' };
    const char *def_path = s.def_path[0] ? s.def_path : s.decl_path;

    /* shape: mirrors code.room's derivation (second component of app/<shape>). */
    char shape[64] = "";
    if (strncmp(s.group, "app/", 4) == 0) {
        const char *sp = s.group + 4;
        size_t j = 0;
        for (; sp[j] && sp[j] != '/' && j + 1 < sizeof(shape); j++)
            shape[j] = sp[j];
        shape[j] = '\0';
    }

    /* other_defs: the same mechanism as code.sym (never dropped for budget —
     * capped at CODE_OTHER_DEF_CAP already, small by construction). */
    static struct ci_symbol hits[CODE_OTHER_DEF_CAP + 4];
    int nh = codeindex_find(ci, s.name, hits,
                            (int)(sizeof(hits) / sizeof(hits[0])));
    if (nh < 0) nh = 0;
    struct json_value others;
    json_init(&others); json_set_array(&others);
    int nother = 0;
    for (int i = 0; i < nh && nother < CODE_OTHER_DEF_CAP; i++) {
        if (strcmp(hits[i].name, s.name) != 0) continue;
        if (hits[i].def_path[0] == '\0') continue;
        if (hits[i].def_line == s.def_line &&
            strcmp(hits[i].def_path, s.def_path) == 0) continue;
        struct json_value o;
        json_init(&o); json_set_object(&o);
        char other_id[400];
        other_id[0] = '\0';
        (void)codeindex_symbol_record_id(&hits[i], other_id,
                                         sizeof(other_id));
        (void)json_push_kv_str(&o, "id", other_id);
        (void)json_push_kv_str(&o, "def_path", hits[i].def_path);
        (void)json_push_kv_int(&o, "def_line", hits[i].def_line);
        code_push_obj(&others, &o);
        nother++;
    }

    /* commands[]: exact handler-name join against the .def-derived dispatch
     * index (never dropped; capped and small by construction). */
    const char *cmd_paths[CODE_COMMAND_CAP];
    int ncmd = code_commands_for_symbol(s.name, cmd_paths, CODE_COMMAND_CAP);
    struct json_value cmds;
    json_init(&cmds); json_set_array(&cmds);
    for (int i = 0; i < ncmd; i++) code_push_line(&cmds, cmd_paths[i]);

    /* Self-shrinking assembly: build callers/callees/includes at full cap,
     * measure their serialized size, and — only if the reply would overflow —
     * drop ONE section at a time (includes, then callees, then callers) and
     * rebuild, until it fits or nothing droppable remains. */
    bool want_includes = true, want_callees = true, want_callers = true;
    struct json_value callers_arr, callees_arr, inc_arr;
    int n_callers = 0, n_callees = 0, n_inc = 0;
    bool callers_trunc = false, callees_trunc = false, inc_trunc = false;
    json_init(&callers_arr); json_set_array(&callers_arr);
    json_init(&callees_arr); json_set_array(&callees_arr);
    json_init(&inc_arr);     json_set_array(&inc_arr);

    for (;;) {
        json_free(&callers_arr); json_init(&callers_arr); json_set_array(&callers_arr);
        json_free(&callees_arr); json_init(&callees_arr); json_set_array(&callees_arr);
        json_free(&inc_arr);     json_init(&inc_arr);     json_set_array(&inc_arr);
        n_callers = 0; n_callees = 0; n_inc = 0;
        callers_trunc = callees_trunc = inc_trunc = false;

        if (want_callers) {
            static struct ci_ref crefs[CODE_CAPSULE_CALLER_CAP + 1];
            int want = CODE_CAPSULE_CALLER_CAP + 1;
            int nc = codeindex_callers_for_symbol(ci, &s, crefs, want);
            if (nc < 0) nc = 0;
            callers_trunc = nc > CODE_CAPSULE_CALLER_CAP;
            n_callers = callers_trunc ? CODE_CAPSULE_CALLER_CAP : nc;
            for (int i = 0; i < n_callers; i++) {
                struct json_value o;
                json_init(&o); json_set_object(&o);
                (void)json_push_kv_str(&o, "file", crefs[i].ref_file);
                (void)json_push_kv_int(&o, "line", crefs[i].ref_line);
                (void)json_push_kv_str(&o, "enclosing", crefs[i].enclosing);
                code_push_obj(&callers_arr, &o);
            }
        }
        if (want_callees) {
            static struct ci_ref erefs[CODE_CAPSULE_CALLEE_CAP + 1];
            int want = CODE_CAPSULE_CALLEE_CAP + 1;
            int ne = codeindex_callees_for_symbol(ci, &s, erefs, want);
            if (ne < 0) ne = 0;
            callees_trunc = ne > CODE_CAPSULE_CALLEE_CAP;
            n_callees = callees_trunc ? CODE_CAPSULE_CALLEE_CAP : ne;
            for (int i = 0; i < n_callees; i++) {
                struct json_value o;
                json_init(&o); json_set_object(&o);
                (void)json_push_kv_str(&o, "callee", erefs[i].callee);
                (void)json_push_kv_str(&o, "file", erefs[i].ref_file);
                (void)json_push_kv_int(&o, "line", erefs[i].ref_line);
                code_push_obj(&callees_arr, &o);
            }
        }
        if (want_includes && def_path[0]) {
            static char incs[CODE_CAPSULE_INC_CAP + 1][256];
            int want = CODE_CAPSULE_INC_CAP + 1;
            int ni = codeindex_includes_of_file(ci, def_path, incs, want);
            if (ni < 0) ni = 0;
            inc_trunc = ni > CODE_CAPSULE_INC_CAP;
            n_inc = inc_trunc ? CODE_CAPSULE_INC_CAP : ni;
            for (int i = 0; i < n_inc; i++)
                code_push_line(&inc_arr, incs[i]);
        }

        /* Measure only the droppable sections; the fixed identity/other_defs/
         * commands/route fields are pushed directly below and are small and
         * constant by construction (capped at CODE_OTHER_DEF_CAP /
         * CODE_COMMAND_CAP), so a fixed reserve covers them plus envelope
         * overhead — the same budgeting shape code.group uses. */
        char scratch[ZCL_COMMAND_RESULT_BUDGET + 1];
        size_t used = 0;
        const struct json_value *parts[] = { &callers_arr, &callees_arr, &inc_arr };
        for (size_t p = 0; p < sizeof(parts) / sizeof(parts[0]); p++) {
            size_t n = json_write(parts[p], scratch, sizeof(scratch));
            used += (n == 0 || n >= sizeof(scratch)) ? sizeof(scratch) : n;
        }
        if (used <= ZCL_COMMAND_RESULT_BUDGET - 2600)
            break;
        if (want_includes) { want_includes = false; continue; }
        if (want_callees)  { want_callees = false; continue; }
        if (want_callers)  { want_callers = false; continue; }
        break;   /* nothing left to drop */
    }

    (void)json_push_kv_bool(&reply->data, "found", true);
    (void)json_push_kv_str(&reply->data, "query", query);
    (void)json_push_kv_str(&reply->data, "resolution",
                           by_id ? "exact_stable_id" : "legacy_name_primary");
    (void)json_push_kv_str(&reply->data, "name", s.name);
    (void)json_push_kv_str(&reply->data, "id", id);
    (void)json_push_kv_str(&reply->data, "kind", kind);
    (void)json_push_kv_str(&reply->data, "def_path", s.def_path);
    (void)json_push_kv_int(&reply->data, "def_line", s.def_line);
    (void)json_push_kv_str(&reply->data, "decl_path", s.decl_path);
    (void)json_push_kv_int(&reply->data, "decl_line", s.decl_line);
    (void)json_push_kv_str(&reply->data, "signature", sig);
    (void)json_push_kv_str(&reply->data, "group", s.group);
    (void)json_push_kv_str(&reply->data, "shape", shape);
    if (s.partial)
        (void)json_push_kv_bool(&reply->data, "partial", true);

    (void)json_push_kv(&reply->data, "other_defs", &others);
    (void)json_push_kv_int(&reply->data, "other_defs_count", nother);

    (void)json_push_kv(&reply->data, "commands", &cmds);
    (void)json_push_kv_int(&reply->data, "command_count", ncmd);

    struct json_value evidence, likely, empty, unknowns;
    json_init(&evidence); json_set_object(&evidence);
    (void)json_push_kv_str(&evidence, "identity", "exact_index_row");
    (void)json_push_kv_str(&evidence, "definition", "exact_index_location");
    (void)json_push_kv_str(&evidence, "call_graph",
                           "heuristic_lexical_attribution");
    (void)json_push_kv_str(&evidence, "registry",
                           "exact_def_handler_name");
    (void)json_push_kv_str(&evidence, "includes",
                           "exact_compiler_depfile_edges");
    (void)json_push_kv_str(&evidence, "tests",
                           "exact_shared_rule_path_floor");
    (void)json_push_kv(&reply->data, "evidence", &evidence);

    json_init(&likely); json_set_array(&likely);
    if (def_path[0]) {
        struct json_value item;
        json_init(&item); json_set_object(&item);
        (void)json_push_kv_str(&item, "path", def_path);
        (void)json_push_kv_str(&item, "evidence",
                               "heuristic_primary_edit_site");
        code_push_obj(&likely, &item);
    }
    if (s.decl_path[0] && strcmp(s.decl_path, def_path) != 0) {
        struct json_value item;
        json_init(&item); json_set_object(&item);
        (void)json_push_kv_str(&item, "path", s.decl_path);
        (void)json_push_kv_str(&item, "evidence",
                               "heuristic_if_contract_changes");
        code_push_obj(&likely, &item);
    }
    (void)json_push_kv(&reply->data, "likely_change_files", &likely);

    json_init(&empty); json_set_array(&empty);
    (void)json_push_kv(&reply->data, "struct_fields", &empty);
    (void)json_push_kv(&reply->data, "ownership_locks", &empty);
    (void)json_push_kv(&reply->data, "database_tables", &empty);
    (void)json_push_kv(&reply->data, "events", &empty);
    (void)json_push_kv(&reply->data, "blockers", &empty);
    (void)json_push_kv(&reply->data, "invariants", &empty);
    json_init(&unknowns); json_set_array(&unknowns);
    code_push_line(&unknowns,
                   "semantic field/ownership/lock/db/event/blocker index not built");
    code_push_line(&unknowns,
                   "definition extent and per-symbol compiler AST not indexed");
    (void)json_push_kv(&reply->data, "unknowns", &unknowns);

    (void)json_push_kv(&reply->data, "callers", &callers_arr);
    (void)json_push_kv_int(&reply->data, "caller_count", n_callers);
    (void)json_push_kv_bool(&reply->data, "callers_truncated", callers_trunc);

    (void)json_push_kv(&reply->data, "callees", &callees_arr);
    (void)json_push_kv_int(&reply->data, "callee_count", n_callees);
    (void)json_push_kv_bool(&reply->data, "callees_truncated", callees_trunc);

    (void)json_push_kv(&reply->data, "includes", &inc_arr);
    (void)json_push_kv_int(&reply->data, "include_count", n_inc);
    (void)json_push_kv_bool(&reply->data, "includes_truncated", inc_trunc);

    struct json_value dropped;
    json_init(&dropped); json_set_array(&dropped);
    if (!want_includes) code_push_line(&dropped, "includes");
    if (!want_callees)  code_push_line(&dropped, "callees");
    if (!want_callers)  code_push_line(&dropped, "callers");
    (void)json_push_kv(&reply->data, "dropped_sections", &dropped);
    json_free(&dropped);

    /* test route: the same resolver code.tests/code.room use. */
    bool crisk = false;
    char route_storage[ZCL_AGENT_IMPACT_GROUP_MAX];
    const char *route =
        code_emit_route(reply, def_path, &crisk, route_storage);

    char summary[300];
    (void)snprintf(summary, sizeof(summary),
                   "%s [%s] %s:%d — %d caller(s), %d callee(s), %d command(s), "
                   "tests→`%s`%s", s.name, kind, def_path,
                   s.def_path[0] ? s.def_line : s.decl_line, n_callers,
                   n_callees, ncmd, route,
                   (!want_includes || !want_callees || !want_callers)
                       ? " (shrunk to fit budget)" : "");
    (void)json_push_kv_str(&reply->data, "summary", summary);

    json_free(&others); json_free(&cmds); json_free(&evidence);
    json_free(&likely); json_free(&empty); json_free(&unknowns);
    json_free(&callers_arr); json_free(&callees_arr); json_free(&inc_arr);
    codeindex_close(ci);
}

/* ── code.refs ──────────────────────────────────────────────────────────── */
void zcl_native_handle_code_refs(const struct zcl_command_request *request,
                                 struct zcl_command_reply *reply)
{
    const char *name = code_str(request, "name");
    if (!name) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_NAME",
                               "normalize", false, false,
                               "code refs requires a symbol name", "");
        return;
    }
    int limit = code_limit(request, CODE_REFS_DEFAULT, CODE_REFS_MAX);
    struct codeindex *ci = code_open(request, reply);
    if (!ci) return;

    /* Fetch one extra to detect (and report) overflow past the cap. */
    static struct ci_ref refs[CODE_REFS_MAX + 1];
    int want = limit + 1;
    if (want > CODE_REFS_MAX + 1) want = CODE_REFS_MAX + 1;
    int nr = codeindex_refs(ci, name, refs, want);
    if (nr < 0) nr = 0;
    bool truncated = nr > limit;
    if (truncated) nr = limit;

    struct json_value arr, lines;
    json_init(&arr);   json_set_array(&arr);
    json_init(&lines); json_set_array(&lines);
    for (int i = 0; i < nr; i++) {
        struct json_value o;
        json_init(&o); json_set_object(&o);
        (void)json_push_kv_str(&o, "file", refs[i].ref_file);
        (void)json_push_kv_int(&o, "line", refs[i].ref_line);
        code_push_obj(&arr, &o);
        char l[300];
        (void)snprintf(l, sizeof(l), "%s:%d", refs[i].ref_file, refs[i].ref_line);
        code_push_line(&lines, l);
    }

    (void)json_push_kv_str(&reply->data, "name", name);
    (void)json_push_kv(&reply->data, "refs", &arr);
    (void)json_push_kv(&reply->data, "lines", &lines);
    (void)json_push_kv_int(&reply->data, "count", nr);
    (void)json_push_kv_int(&reply->data, "limit", limit);
    (void)json_push_kv_bool(&reply->data, "truncated", truncated);
    char summary[160];
    (void)snprintf(summary, sizeof(summary), "%d reference(s) to %s%s", nr, name,
                   truncated ? " (more not shown; raise --limit)" : "");
    (void)json_push_kv_str(&reply->data, "summary", summary);

    json_free(&arr); json_free(&lines);
    codeindex_close(ci);
}

/* ── code.find ──────────────────────────────────────────────────────────── */
void zcl_native_handle_code_find(const struct zcl_command_request *request,
                                 struct zcl_command_reply *reply)
{
    const char *text = code_str(request, "text");
    if (!text) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_TEXT",
                               "normalize", false, false,
                               "code find requires search text", "");
        return;
    }
    int limit = code_limit(request, CODE_FIND_DEFAULT, CODE_FIND_MAX);
    struct codeindex *ci = code_open(request, reply);
    if (!ci) return;

    static struct ci_symbol hits[CODE_FIND_MAX + 1];
    int want = limit + 1;
    if (want > CODE_FIND_MAX + 1) want = CODE_FIND_MAX + 1;
    int nh = codeindex_find(ci, text, hits, want);
    if (nh < 0) nh = 0;
    bool truncated = nh > limit;
    if (truncated) nh = limit;

    struct json_value arr, lines;
    json_init(&arr);   json_set_array(&arr);
    json_init(&lines); json_set_array(&lines);
    for (int i = 0; i < nh; i++) {
        char sig[64];
        code_trunc(sig, sizeof(sig), hits[i].signature, 52);
        const char *p = hits[i].def_path[0] ? hits[i].def_path : hits[i].decl_path;
        int line = hits[i].def_path[0] ? hits[i].def_line : hits[i].decl_line;
        char kind[2] = { hits[i].kind, '\0' };
        struct json_value o;
        json_init(&o); json_set_object(&o);
        (void)json_push_kv_str(&o, "name", hits[i].name);
        (void)json_push_kv_str(&o, "kind", kind);
        (void)json_push_kv_str(&o, "def_path", p);
        (void)json_push_kv_int(&o, "def_line", line);
        (void)json_push_kv_str(&o, "signature", sig);
        code_push_obj(&arr, &o);
        char l[200];
        (void)snprintf(l, sizeof(l), "%s  %s:%d", hits[i].name, p, line);
        code_push_line(&lines, l);
    }

    (void)json_push_kv_str(&reply->data, "query", text);
    (void)json_push_kv(&reply->data, "matches", &arr);
    (void)json_push_kv(&reply->data, "lines", &lines);
    (void)json_push_kv_int(&reply->data, "count", nh);
    (void)json_push_kv_int(&reply->data, "limit", limit);
    (void)json_push_kv_bool(&reply->data, "truncated", truncated);
    char summary[160];
    (void)snprintf(summary, sizeof(summary), "%d match(es) for '%s'%s", nh, text,
                   truncated ? " (more not shown; raise --limit)" : "");
    (void)json_push_kv_str(&reply->data, "summary", summary);

    json_free(&arr); json_free(&lines);
    codeindex_close(ci);
}

/* ── code.map ───────────────────────────────────────────────────────────── */
void zcl_native_handle_code_map(const struct zcl_command_request *request,
                                struct zcl_command_reply *reply)
{
    struct codeindex *ci = code_open_source_view(request, reply);
    if (!ci) return;

    static struct ci_group groups[512];
    int ng = codeindex_groups(ci, groups, (int)(sizeof(groups) / sizeof(groups[0])));
    if (ng < 0) ng = 0;

    struct json_value roots, shapes;
    json_init(&roots);  json_set_array(&roots);
    json_init(&shapes); json_set_array(&shapes);

    /* The exact maintained roots, shared with every whole-tree scanner. Each
     * count is aggregate so lib/ and app/ include their child groups. */
    static const char *const source_roots[] = {
#define SOURCE_ROOT(name_) name_,
#include "codeindex/source_roots.def"
#undef SOURCE_ROOT
    };
    int total = 0, nroot = 0;
    for (size_t i = 0;
         i < sizeof(source_roots) / sizeof(source_roots[0]); i++) {
        int fc = codeindex_count_files_in_group(ci, source_roots[i], true);
        if (fc <= 0) continue;
        if (nroot >= CODE_MAP_ROOT_CAP) {
            json_free(&roots); json_free(&shapes);
            codeindex_close(ci);
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INTERNAL,
                                   "ROOT_CAPACITY", "render", false, false,
                                   "code map source roots exceed reply capacity",
                                   "increase CODE_MAP_ROOT_CAP");
            return;
        }
        total += fc;
        const char *group_purpose = "";
        for (int g = 0; g < ng; g++)
            if (strcmp(groups[g].path, source_roots[i]) == 0) {
                group_purpose = groups[g].purpose;
                break;
            }
        char purpose[64];
        code_trunc(purpose, sizeof(purpose), group_purpose, 48);
        struct json_value o;
        json_init(&o); json_set_object(&o);
        (void)json_push_kv_str(&o, "path", source_roots[i]);
        (void)json_push_kv_int(&o, "file_count", fc);
        (void)json_push_kv_str(&o, "purpose", purpose);
        code_push_obj(&roots, &o);
        nroot++;
    }

    /* Product shapes recur inside feature rooms and the engine. Aggregate
     * their direct counts without inventing a second physical `app/` tree. */
    size_t nsh = 0;
    const char *const *sh = ci_app_shapes(&nsh);
    int nshape = 0;
    for (size_t i = 0; i < nsh && nshape < CODE_MAP_SHAPE_CAP; i++) {
        char path[64];
        (void)snprintf(path, sizeof(path), "*/%s", sh[i]);
        int fc = 0;
        const char *purpose = "";
        for (int g = 0; g < ng; g++) {
            size_t path_length = strlen(groups[g].path);
            size_t shape_length = strlen(sh[i]);
            if (path_length <= shape_length ||
                groups[g].path[path_length - shape_length - 1] != '/' ||
                strcmp(groups[g].path + path_length - shape_length,
                       sh[i]) != 0)
                continue;
            int direct = codeindex_count_files_in_group(
                ci, groups[g].path, false);
            if (direct > 0) fc += direct;
            if (!purpose[0]) purpose = groups[g].purpose;
        }
        char ptrunc[64];
        code_trunc(ptrunc, sizeof(ptrunc), purpose, 48);
        struct json_value o;
        json_init(&o); json_set_object(&o);
        (void)json_push_kv_str(&o, "path", path);
        (void)json_push_kv_int(&o, "file_count", fc);
        (void)json_push_kv_str(&o, "purpose", ptrunc);
        code_push_obj(&shapes, &o);
        nshape++;
    }

    struct ci_source_file_counts counts;
    if (!codeindex_source_file_counts(ci, &counts)) {
        json_free(&roots); json_free(&shapes);
        codeindex_close(ci);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "COUNT_FAILED",
                               "query", false, false,
                               "code map could not count source file kinds", "");
        return;
    }
    if (counts.c23_files + counts.registry_nodes != total) {
        json_free(&roots); json_free(&shapes);
        codeindex_close(ci);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL,
                               "COUNT_DISAGREEMENT", "verify", false, false,
                               "code map source-kind totals disagree with roots", "");
        return;
    }

    (void)json_push_kv_str(&reply->data, "scope", "map");
    (void)json_push_kv(&reply->data, "roots", &roots);
    (void)json_push_kv(&reply->data, "shapes", &shapes);
    (void)json_push_kv_int(&reply->data, "total_files", total);
    (void)json_push_kv_int(&reply->data, "c23_files", counts.c23_files);
    (void)json_push_kv_int(&reply->data, "registry_nodes",
                           counts.registry_nodes);
    char summary[176];
    (void)snprintf(summary, sizeof(summary),
                   "%d C23 files + %d registry nodes across %d physical roots "
                   "+ %d product shapes; run `code group <path>` to descend",
                   counts.c23_files, counts.registry_nodes, nroot, nshape);
    (void)json_push_kv_str(&reply->data, "summary", summary);

    json_free(&roots); json_free(&shapes);
    codeindex_close(ci);
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

/* ── code.room ──────────────────────────────────────────────────────────── */
/* The unified single-room view (palace-design.md §2): one bounded document that
 * composes the four legibility namespaces for ONE path, so an LLM learns where a
 * file lives / what it is / what it breaks in one call, no grep, no file read:
 *   shape     — the 8 app/ shapes: the second component of an app/<shape> group
 *   purpose   — self-description: finfo.purpose (populated by the P4.0 lane;
 *               honestly empty in a tree where that lane has not landed)
 *   group +   — directory-groups: codeindex_file() for the group,
 *   neighbors   codeindex_files_in_group() for the siblings
 *   tests +   — the ~580 test groups via the SAME impact resolver code.tests
 *   route       uses (zcl_native_code_route_for_path → code_emit_route)
 *   commands  — command branches whose registered native handler is DEFINED in
 *               this file: the WF4 4C dispatch index (config/
 *               command_handler_index.h, a parallel {path, handler_name}
 *               stringizing expansion of the same .def catalogs) joined
 *               against the code index's symbol table for this file
 *               (code_commands_for_file). Empty when nothing here backs a
 *               command — a real answer, not a guess. */
enum { CODE_ROOM_NEIGHBOR_CAP = 12 };

enum {
    CODE_ROOM_FEATURE_COMMAND_CAP = 24,
    CODE_ROOM_FEATURE_HANDLER_CAP = 24,
    CODE_ROOM_FEATURE_FILE_CAP = 16,
    CODE_ROOM_FEATURE_COUPLED_CAP = 12,
};

static bool code_command_is_in_room(const char *root, const char *path)
{
    if (!root || !path) return false;
    size_t n = strlen(root);
    return strcmp(root, path) == 0 ||
           (strncmp(root, path, n) == 0 && path[n] == '.');
}

static bool code_room_has_file(char files[][256], int count, const char *path)
{
    for (int i = 0; i < count; i++)
        if (strcmp(files[i], path) == 0) return true;
    return false;
}

/* A command branch is already the product's exact public feature boundary.
 * Compose its registered leaves, exact handler definitions, proof routes and
 * mixed-file coupling without introducing a second feature manifest. */
static bool code_emit_feature_room(
    const struct zcl_command_request *request, struct zcl_command_reply *reply,
    struct codeindex *ci, const char *root)
{
    const struct zcl_command_registry *registry =
        request && request->context && request->context->registry
            ? request->context->registry : zcl_command_catalog();
    const struct zcl_command_spec *root_spec =
        zcl_command_registry_find(registry, root, NULL);
    if (!root_spec) return false;

    int command_total = 0;
    struct json_value commands;
    json_init(&commands); json_set_array(&commands);
    for (size_t i = 0; i < registry->count; i++) {
        const char *path = registry->commands[i].path;
        if (!code_command_is_in_room(root, path)) continue;
        command_total++;
        if (command_total <= CODE_ROOM_FEATURE_COMMAND_CAP)
            code_push_line(&commands, path);
    }
    /* A leaf is not a feature room. Preserve the historical file-path result
     * for unknown paths and command leaves alike. */
    if (command_total <= 1) {
        json_free(&commands);
        return false;
    }

    char handler_files[CODE_ROOM_FEATURE_FILE_CAP][256] = {{0}};
    const char *handler_names[CODE_ROOM_FEATURE_HANDLER_CAP] = {0};
    int handler_file_count = 0, handler_count = 0, handler_total = 0;
    int handler_unindexed = 0;
    bool handler_truncated = false;
    bool file_truncated = false;
    const struct zcl_command_handler_index *handlers =
        zcl_command_handler_index();
    for (size_t i = 0; handlers && i < handlers->count; i++) {
        const struct zcl_command_handler_entry *entry = &handlers->entries[i];
        if (!code_command_is_in_room(root, entry->path)) continue;
        handler_total++;
        struct ci_symbol symbol;
        bool found = false;
        if (!codeindex_symbol(ci, entry->handler_name, &symbol, &found) ||
            !found || !symbol.def_path[0]) {
            handler_unindexed++;
            continue;
        }
        bool seen_handler = false;
        for (int j = 0; j < handler_count; j++)
            if (strcmp(handler_names[j], entry->handler_name) == 0)
                seen_handler = true;
        if (!seen_handler) {
            if (handler_count < CODE_ROOM_FEATURE_HANDLER_CAP)
                handler_names[handler_count++] = entry->handler_name;
            else
                handler_truncated = true;
        }
        if (!code_room_has_file(handler_files, handler_file_count,
                                symbol.def_path)) {
            if (handler_file_count < CODE_ROOM_FEATURE_FILE_CAP) {
                (void)snprintf(handler_files[handler_file_count],
                               sizeof(handler_files[handler_file_count]), "%s",
                               symbol.def_path);
                handler_file_count++;
            } else {
                file_truncated = true;
            }
        }
    }

    struct json_value handler_arr, file_arr;
    json_init(&handler_arr); json_set_array(&handler_arr);
    json_init(&file_arr); json_set_array(&file_arr);
    for (int i = 0; i < handler_count; i++)
        code_push_line(&handler_arr, handler_names[i]);
    for (int i = 0; i < handler_file_count; i++)
        code_push_line(&file_arr, handler_files[i]);

    char groups[CODE_ROOM_FEATURE_FILE_CAP][128] = {{0}};
    int group_count = 0;
    for (int i = 0; i < handler_file_count; i++) {
        struct ci_file file;
        bool found = false;
        if (!codeindex_file(ci, handler_files[i], &file, &found) || !found ||
            !file.group[0])
            continue;
        bool seen = false;
        for (int j = 0; j < group_count; j++)
            if (strcmp(groups[j], file.group) == 0) seen = true;
        if (!seen && group_count < CODE_ROOM_FEATURE_FILE_CAP) {
            (void)snprintf(groups[group_count], sizeof(groups[group_count]),
                           "%s", file.group);
            group_count++;
        }
    }
    struct json_value group_arr;
    json_init(&group_arr); json_set_array(&group_arr);
    for (int i = 0; i < group_count; i++)
        code_push_line(&group_arr, groups[i]);

    struct agent_impact_acc proofs = {0};
    bool consensus_risk = false;
    for (int i = 0; i < handler_file_count; i++) {
        (void)agent_impact_apply_shared_rules(handler_files[i], &proofs);
        if (code_path_is_consensus_risk(handler_files[i]))
            consensus_risk = true;
    }
    if (proofs.groups_len == 0)
        agent_impact_add_group(&proofs, "make_lint_gates");
    struct json_value test_arr;
    json_init(&test_arr); json_set_array(&test_arr);
    size_t tests_shown = proofs.groups_len < (size_t)CODE_TESTS_CAP
                             ? proofs.groups_len : (size_t)CODE_TESTS_CAP;
    for (size_t i = 0; i < tests_shown; i++)
        code_push_line(&test_arr, proofs.groups[i]);

    int coupled_total = 0;
    struct json_value coupled;
    json_init(&coupled); json_set_array(&coupled);
    for (size_t i = 0; handlers && i < handlers->count; i++) {
        const struct zcl_command_handler_entry *entry = &handlers->entries[i];
        if (code_command_is_in_room(root, entry->path)) continue;
        struct ci_symbol symbol;
        bool found = false;
        if (!codeindex_symbol(ci, entry->handler_name, &symbol, &found) ||
            !found || !symbol.def_path[0] ||
            !code_room_has_file(handler_files, handler_file_count,
                                symbol.def_path))
            continue;
        coupled_total++;
        if (coupled_total <= CODE_ROOM_FEATURE_COUPLED_CAP)
            code_push_line(&coupled, entry->path);
    }

    (void)json_push_kv_str(&reply->data, "path", root);
    (void)json_push_kv_bool(&reply->data, "found", true);
    (void)json_push_kv_str(&reply->data, "room_kind", "command_feature");
    (void)json_push_kv_str(&reply->data, "purpose",
                           root_spec->summary ? root_spec->summary : "");
    (void)json_push_kv(&reply->data, "commands", &commands);
    (void)json_push_kv_int(&reply->data, "command_count", command_total);
    (void)json_push_kv_bool(&reply->data, "commands_truncated",
                            command_total > CODE_ROOM_FEATURE_COMMAND_CAP);
    (void)json_push_kv(&reply->data, "handler_symbols", &handler_arr);
    (void)json_push_kv_int(&reply->data, "handler_count", handler_count);
    (void)json_push_kv_int(&reply->data, "handler_binding_count",
                           handler_total);
    (void)json_push_kv_int(&reply->data, "handler_unindexed",
                           handler_unindexed);
    (void)json_push_kv_bool(&reply->data, "handler_symbols_truncated",
                            handler_truncated);
    (void)json_push_kv(&reply->data, "implementation_files", &file_arr);
    (void)json_push_kv_int(&reply->data, "implementation_file_count",
                           handler_file_count);
    (void)json_push_kv(&reply->data, "implementation_groups", &group_arr);
    (void)json_push_kv_int(&reply->data, "implementation_group_count",
                           group_count);
    (void)json_push_kv_bool(&reply->data, "implementation_truncated",
                            file_truncated);
    (void)json_push_kv_bool(&reply->data, "implementation_complete",
                            !file_truncated && handler_unindexed == 0);
    (void)json_push_kv(&reply->data, "test_groups", &test_arr);
    (void)json_push_kv_bool(&reply->data, "test_groups_truncated",
                            proofs.groups_len > (size_t)CODE_TESTS_CAP);
    (void)json_push_kv_bool(&reply->data, "consensus_risk", consensus_risk);
    (void)json_push_kv(&reply->data, "shared_handler_file_commands", &coupled);
    (void)json_push_kv_int(&reply->data,
                           "shared_handler_file_command_count",
                           coupled_total);
    (void)json_push_kv_bool(&reply->data,
                            "shared_handler_file_commands_truncated",
                            coupled_total > CODE_ROOM_FEATURE_COUPLED_CAP);
    (void)json_push_kv_bool(&reply->data,
                            "shared_handler_file_command_count_complete",
                            !file_truncated && handler_unindexed == 0);
    (void)json_push_kv_str(
        &reply->data, "implementation_scope",
        "exact registered handler definitions; indirect and unregistered dependencies remain UNKNOWN");

    char summary[256];
    (void)snprintf(summary, sizeof(summary),
                   "%s: %d command row(s), %d handler file(s), %zu proof "
                   "group(s), %d outside command(s) share those handler files",
                   root, command_total, handler_file_count, proofs.groups_len,
                   coupled_total);
    (void)json_push_kv_str(&reply->data, "summary", summary);

    json_free(&commands); json_free(&handler_arr); json_free(&file_arr);
    json_free(&group_arr);
    json_free(&test_arr); json_free(&coupled);
    return true;
}

void zcl_native_handle_code_room(const struct zcl_command_request *request,
                                 struct zcl_command_reply *reply)
{
    const char *path = code_str(request, "path");
    if (!path) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_PATH",
                               "normalize", false, false,
                               "code room requires a repo-relative path", "");
        return;
    }
    struct codeindex *ci = code_open(request, reply);
    if (!ci) return;

    struct ci_file finfo;
    bool ffound = false;
    (void)codeindex_file(ci, path, &finfo, &ffound);
    if (!ffound && code_emit_feature_room(request, reply, ci, path)) {
        codeindex_close(ci);
        return;
    }
    const char *group = ffound ? finfo.group : "";

    struct ci_context_assignment assignment;
    memset(&assignment, 0, sizeof(assignment));
    if (ffound) (void)codeindex_context_classify(path, &assignment);

    (void)json_push_kv_str(&reply->data, "path", path);
    (void)json_push_kv_bool(&reply->data, "found", ffound);
    (void)json_push_kv_str(&reply->data, "context", assignment.context);
    (void)json_push_kv_str(&reply->data, "shape", assignment.shape);
    (void)json_push_kv_str(&reply->data, "context_basis", assignment.basis);
    (void)json_push_kv_bool(&reply->data, "context_orphan",
                            ffound && assignment.orphan);
    (void)json_push_kv_bool(&reply->data, "context_overlap",
                            ffound && assignment.overlap);
    struct json_value context_matches;
    json_init(&context_matches); json_set_array(&context_matches);
    for (size_t i = 0; i < assignment.match_count; i++)
        code_push_line(&context_matches, assignment.matches[i]);
    (void)json_push_kv(&reply->data, "context_matches", &context_matches);
    json_free(&context_matches);
    (void)json_push_kv_str(&reply->data, "purpose", ffound ? finfo.purpose : "");
    (void)json_push_kv_str(&reply->data, "group", group);

    /* neighbors: sibling files stamped with EXACTLY this group, this file
     * excluded, capped. group_file_count is the accurate group size (from the
     * count query), so neighbors_truncated is exact even past the render cap. */
    struct json_value neigh;
    json_init(&neigh); json_set_array(&neigh);
    int gcount = 0, shown = 0;
    if (group[0]) {
        gcount = codeindex_count_files_in_group(ci, group, false);
        if (gcount < 0) gcount = 0;
        static struct ci_file sib[CODE_ROOM_NEIGHBOR_CAP + 8];
        int nf = codeindex_files_in_group(ci, group, sib,
                                          (int)(sizeof(sib) / sizeof(sib[0])));
        if (nf < 0) nf = 0;
        for (int i = 0; i < nf && shown < CODE_ROOM_NEIGHBOR_CAP; i++) {
            if (strcmp(sib[i].path, path) == 0) continue;   /* exclude self */
            code_push_line(&neigh, sib[i].path);
            shown++;
        }
    }
    int siblings = gcount > 0 ? gcount - 1 : 0;   /* group total minus self */
    (void)json_push_kv(&reply->data, "neighbors", &neigh);
    (void)json_push_kv_int(&reply->data, "neighbor_count", shown);
    (void)json_push_kv_int(&reply->data, "group_file_count", gcount);
    (void)json_push_kv_bool(&reply->data, "neighbors_truncated",
                            siblings > shown);
    json_free(&neigh);

    /* tests[] + route + consensus_risk + matched — the same resolver code.tests
     * and `dev test plan` use, so a room view and a test plan never disagree. */
    bool crisk = false;
    char route_storage[ZCL_AGENT_IMPACT_GROUP_MAX];
    const char *route = code_emit_route(reply, path, &crisk, route_storage);

    /* commands[]: WF4 4C dispatch-index join (code_commands_for_file above) —
     * command paths whose registered native handler is DEFINED in this file.
     * Empty is a real answer (no leaf's handler lives here), never a guess. */
    const char *cmd_paths[CODE_COMMAND_CAP];
    int ncmd = code_commands_for_file(ci, path, cmd_paths, CODE_COMMAND_CAP);
    struct json_value cmds;
    json_init(&cmds); json_set_array(&cmds);
    for (int i = 0; i < ncmd; i++) code_push_line(&cmds, cmd_paths[i]);
    (void)json_push_kv(&reply->data, "commands", &cmds);
    (void)json_push_kv_int(&reply->data, "command_count", ncmd);
    json_free(&cmds);

    char summary[256];
    (void)snprintf(summary, sizeof(summary),
                   "%s: context=%s shape=%s group=%s neighbors=%d "
                   "tests→`%s`%s", path,
                   assignment.context[0] ? assignment.context : "-",
                   assignment.shape[0] ? assignment.shape : "-",
                   group[0] ? group : "-", shown, route,
                   crisk ? " (consensus surface)" : "");
    (void)json_push_kv_str(&reply->data, "summary", summary);

    codeindex_close(ci);
}

/* ── code.impact ────────────────────────────────────────────────────────── */
/* The blast-radius leaf: given one changed FILE, the reverse-dependency
 * closure — every file that transitively depends on it, so an agent can SEE
 * "what breaks if I touch this" before editing. Entirely reuses the existing
 * engine: codeindex_impact_closure (cognition/modules/codeindex/src/codeindex_impact.c) for
 * the file->symbol->reverse-caller walk, and the SAME
 * agent_impact_apply_shared_rules() resolver code.tests/devloop_plan.c use
 * (via code_emit_route) for the downstream focused test groups — no graph
 * walk is reimplemented here.
 *
 * `impacted_files`/`count`/`truncated` mirror the engine's own cap+truncated
 * contract directly (CODE_IMPACT_CAP is the query cap, not a second display
 * cap over a larger true answer): a capped, truncated=true result means "at
 * least this many, more exist" — the same fail-safe meaning documented on
 * codeindex_impact_closure itself. `direct_includes` (this file's own
 * in-tree #include fan-out) and `direct_callers` (call sites directly
 * referencing a symbol this file defines, summed over its symbol table) are
 * cheap depth-1 numbers for a quick glance, distinct from the full closure. */
void zcl_native_handle_code_impact(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply)
{
    const char *path = code_str(request, "path");
    if (!path) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_PATH",
                               "normalize", false, false,
                               "code impact requires a repo-relative path", "");
        return;
    }
    struct codeindex *ci = code_open(request, reply);
    if (!ci) return;

    char changed[1][256];
    memset(changed[0], 0, sizeof(changed[0]));
    (void)snprintf(changed[0], sizeof(changed[0]), "%s", path);

    static char impacted[CODE_IMPACT_CAP][256];
    bool truncated = false;
    int n = codeindex_impact_closure(ci, changed, 1, 0, impacted,
                                     CODE_IMPACT_CAP, &truncated);
    if (n < 0) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "CLOSURE_FAILED",
                               "dispatch", true, false,
                               "impact closure traversal failed", path);
        codeindex_close(ci);
        return;
    }

    struct json_value arr;
    json_init(&arr); json_set_array(&arr);
    for (int i = 0; i < n; i++) code_push_line(&arr, impacted[i]);
    (void)json_push_kv_str(&reply->data, "path", path);
    (void)json_push_kv(&reply->data, "impacted_files", &arr);
    (void)json_push_kv_int(&reply->data, "count", n);
    (void)json_push_kv_bool(&reply->data, "truncated", truncated);
    json_free(&arr);

    /* The INCLUDE dimension — the half of the blast radius the walk above
     * structurally cannot see. `impacted_files` is a CALL-graph answer, so a
     * macro-only header, an enum, a typedef, or an X-macro registry comes back
     * with a blast radius of exactly itself even though every translation unit
     * that reads it recompiles. These are the files the compiler proves read
     * `path`, taken from its own depfiles. Reported as a separate array on
     * purpose: unioning them into `impacted_files` would hide which graph
     * answered, and the two have different completeness conditions. */
    static char dependents[CODE_IMPACT_CAP][256];
    enum codeindex_include_dim idim = CODEINDEX_INCLUDE_DIM_UNAVAILABLE;
    int nd = codeindex_reverse_includes(ci, path, dependents, CODE_IMPACT_CAP,
                                        &idim);
    if (nd < 0) nd = 0;
    int nd_listed = nd < CODE_IMPACT_INCDEP_LIST_CAP
                        ? nd : CODE_IMPACT_INCDEP_LIST_CAP;
    struct json_value darr;
    json_init(&darr); json_set_array(&darr);
    for (int i = 0; i < nd_listed; i++) code_push_line(&darr, dependents[i]);
    (void)json_push_kv(&reply->data, "include_dependents", &darr);
    (void)json_push_kv_int(&reply->data, "include_dependents_listed", nd_listed);
    (void)json_push_kv_int(&reply->data, "include_dependent_count", nd);
    (void)json_push_kv_str(&reply->data, "include_dimension",
                           codeindex_include_dim_label(idim));
    json_free(&darr);

    /* direct_includes: this file's own forward in-tree #include fan-out
     * (codeindex_includes_of_file) — a quick depth-1 number, not the closure. */
    static char incs[CODE_IMPACT_INC_CAP][256];
    int ninc = codeindex_includes_of_file(ci, path, incs, CODE_IMPACT_INC_CAP);
    if (ninc < 0) ninc = 0;
    (void)json_push_kv_int(&reply->data, "direct_includes", ninc);

    /* direct_callers: call sites directly referencing a symbol DEFINED in this
     * file, summed over its symbol table (codeindex_symbols_in_file +
     * codeindex_callers per symbol) — the depth-1 fan-out the closure walk
     * would expand from first, reported before that expansion. */
    static struct ci_symbol syms[CODE_IMPACT_SYM_CAP];
    int nsym = codeindex_symbols_in_file(ci, path, syms, CODE_IMPACT_SYM_CAP);
    if (nsym < 0) nsym = 0;
    static struct ci_ref callerbuf[CODE_IMPACT_REF_CAP];
    int direct_callers = 0;
    for (int i = 0; i < nsym; i++) {
        int nc = codeindex_callers(ci, syms[i].name, callerbuf,
                                   CODE_IMPACT_REF_CAP);
        if (nc > 0) direct_callers += nc;
    }
    (void)json_push_kv_int(&reply->data, "direct_callers", direct_callers);

    /* test_groups + route + consensus_risk + matched — the SAME shared-rule
     * resolver code.tests/code.room/devloop_plan.c use, so a blast-radius
     * check and a test plan never disagree on what a change to `path` routes
     * to downstream. */
    bool crisk = false;
    char route_storage[ZCL_AGENT_IMPACT_GROUP_MAX];
    const char *route = code_emit_route(reply, path, &crisk, route_storage);

    char summary[256];
    (void)snprintf(summary, sizeof(summary),
                   "%s: %d impacted file(s)%s via calls, %d via includes (%s%s), "
                   "%d direct include(s), %d direct caller(s), routes to "
                   "`%s`%s",
                   path, n, truncated ? " (capped; more exist)" : "",
                   nd, codeindex_include_dim_label(idim),
                   nd_listed < nd ? "; list abridged" : "", ninc,
                   direct_callers, route,
                   crisk ? " (consensus surface)" : "");
    (void)json_push_kv_str(&reply->data, "summary", summary);

    codeindex_close(ci);
}

/* ── code.merkle ────────────────────────────────────────────────────────── */
/* The identity leaf: one 32-byte SHA3 answer to "what does this checkout
 * contain", and one 32-byte answer per directory to "did anything under here
 * change since I last looked". Backed by cognition/modules/codeindex/src/codeindex_merkle.c,
 * whose snapshot makes a repeat call re-read only the files whose stat cache key
 * moved — so this is cheap enough to call between edits, and the `build` object
 * reports exactly what the call cost (files_read, bytes_read, nodes_hashed).
 *
 * Deliberately does NOT open the symbol index: the Merkle pass is independent of
 * it and must not drag a full index rebuild behind a digest question. */
void zcl_native_handle_code_merkle(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply)
{
    const char *path = code_str(request, "path");
    const char *root = code_source_root(request);

    struct ci_merkle_cost cost;
    memset(&cost, 0, sizeof(cost));
    struct ci_merkle *m = ci_merkle_refresh(root, &cost);
    if (!m) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "MERKLE_BUILD",
                               "dispatch", true, false,
                               "could not build the source-tree Merkle root",
                               root);
        return;
    }

    struct ci_merkle_node tree;
    if (!ci_merkle_root(m, &tree)) {
        ci_merkle_free(m);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "MERKLE_NO_ROOT",
                               "dispatch", true, false,
                               "the source-tree Merkle tree has no root node",
                               root);
        return;
    }

    /* Resolve the request: absent/""/"." = the whole tree, else a directory
     * subtree, else one file's leaf. An unresolvable path reports found=false
     * rather than failing — the same contract code.impact uses for a path
     * outside the indexed set. */
    const char *want = path ? path : "";
    bool is_root = !path || !path[0] || strcmp(path, ".") == 0 ||
                   strcmp(path, "/") == 0;
    struct ci_merkle_node node = tree;
    struct ci_merkle_leaf leaf;
    memset(&leaf, 0, sizeof(leaf));
    const char *kind = "tree";
    bool found = true;
    bool is_file = false;
    if (!is_root) {
        bool dir_found = false, file_found = false;
        (void)ci_merkle_node(m, want, &node, &dir_found);
        if (dir_found) {
            kind = "dir";
        } else if (ci_merkle_leaf(m, want, &leaf, &file_found) && file_found) {
            kind = "file";
            is_file = true;
        } else {
            kind = "absent";
            found = false;
        }
    }

    char hex[65] = "";
    if (found) ci_merkle_hex(is_file ? &leaf.digest : &node.digest, hex);
    char tree_hex[65];
    ci_merkle_hex(&tree.digest, tree_hex);

    (void)json_push_kv_str(&reply->data, "path", is_root ? "" : want);
    (void)json_push_kv_str(&reply->data, "kind", kind);
    (void)json_push_kv_bool(&reply->data, "found", found);
    (void)json_push_kv_str(&reply->data, "digest", hex);
    if (is_file) {
        (void)json_push_kv_int(&reply->data, "size_bytes", (int64_t)leaf.size);
    } else if (found) {
        (void)json_push_kv_int(&reply->data, "file_count",
                               (int64_t)node.file_count);
        (void)json_push_kv_int(&reply->data, "dir_count",
                               (int64_t)node.dir_count);
        (void)json_push_kv_int(&reply->data, "direct_children",
                               (int64_t)node.direct_children);
        (void)json_push_kv_int(&reply->data, "total_bytes",
                               (int64_t)node.total_bytes);
    }

    /* Direct subdirectory subtree roots (16-hex prefixes — enough to compare,
     * cheap enough to list), so an agent descends to the changed subtree in a
     * few steps instead of rescanning the tree. */
    if (found && !is_file) {
        static struct ci_merkle_node kids[CODE_MERKLE_CHILD_CAP];
        int nkids = ci_merkle_child_dirs(m, is_root ? "" : want, kids,
                                        CODE_MERKLE_CHILD_CAP);
        if (nkids < 0) nkids = 0;
        int shown = nkids > CODE_MERKLE_CHILD_CAP ? CODE_MERKLE_CHILD_CAP : nkids;
        struct json_value arr;
        json_init(&arr); json_set_array(&arr);
        for (int i = 0; i < shown; i++) {
            char kh[65];
            ci_merkle_hex(&kids[i].digest, kh);
            kh[16] = '\0';
            struct json_value o;
            json_init(&o); json_set_object(&o);
            (void)json_push_kv_str(&o, "path", kids[i].path);
            (void)json_push_kv_str(&o, "digest", kh);
            (void)json_push_kv_int(&o, "file_count",
                                   (int64_t)kids[i].file_count);
            (void)json_push_kv_int(&o, "total_bytes",
                                   (int64_t)kids[i].total_bytes);
            code_push_obj(&arr, &o);
        }
        (void)json_push_kv(&reply->data, "children", &arr);
        (void)json_push_kv_int(&reply->data, "children_total", nkids);
        (void)json_push_kv_bool(&reply->data, "children_truncated",
                                nkids > shown);
        json_free(&arr);
    }

    /* Every answer carries the whole-tree identity, so a subtree digest is
     * always attributable to one tree state. */
    (void)json_push_kv_str(&reply->data, "tree_root", tree_hex);
    (void)json_push_kv_int(&reply->data, "tree_files",
                           (int64_t)tree.file_count);
    (void)json_push_kv_int(&reply->data, "tree_bytes",
                           (int64_t)tree.total_bytes);

    /* What this call cost — the incrementality report, not a claim about it. */
    struct json_value build;
    json_init(&build); json_set_object(&build);
    (void)json_push_kv_int(&build, "files_total", (int64_t)cost.files_total);
    (void)json_push_kv_int(&build, "files_read", (int64_t)cost.files_read);
    (void)json_push_kv_int(&build, "leaves_reused",
                           (int64_t)cost.leaves_reused);
    (void)json_push_kv_int(&build, "bytes_read", (int64_t)cost.bytes_read);
    (void)json_push_kv_int(&build, "nodes_total", (int64_t)cost.nodes_total);
    (void)json_push_kv_int(&build, "nodes_hashed", (int64_t)cost.nodes_hashed);
    (void)json_push_kv_int(&build, "nodes_reused", (int64_t)cost.nodes_reused);
    (void)json_push_kv_bool(&build, "snapshot_used", cost.snapshot_used);
    (void)json_push_kv_bool(&build, "snapshot_saved", cost.snapshot_saved);
    (void)json_push_kv_bool(&build, "inventory_changed",
                            cost.inventory_changed);
    (void)json_push_kv_bool(&build, "full_rescan", cost.full_rescan);
    (void)json_push_kv(&reply->data, "build", &build);
    json_free(&build);

    char summary[288];
    if (!found) {
        (void)snprintf(summary, sizeof(summary),
                       "'%s' is not an indexed source file or directory; tree "
                       "root %.16s covers %u file(s)",
                       want, tree_hex, (unsigned)tree.file_count);
    } else if (is_file) {
        (void)snprintf(summary, sizeof(summary),
                       "leaf %s = %.16s (%llu bytes); tree root %.16s; re-read "
                       "%u/%u file(s) this call",
                       leaf.path, hex, (unsigned long long)leaf.size, tree_hex,
                       (unsigned)cost.files_read, (unsigned)cost.files_total);
    } else {
        (void)snprintf(summary, sizeof(summary),
                       "%s subtree %.16s over %u file(s)/%llu bytes; tree root "
                       "%.16s; re-read %u/%u file(s), hashed %u/%u node(s)",
                       is_root ? "whole-tree" : want, hex,
                       (unsigned)node.file_count,
                       (unsigned long long)node.total_bytes, tree_hex,
                       (unsigned)cost.files_read, (unsigned)cost.files_total,
                       (unsigned)cost.nodes_hashed, (unsigned)cost.nodes_total);
    }
    (void)json_push_kv_str(&reply->data, "summary", summary);

    ci_merkle_free(m);
}

/* ── code.territory ─────────────────────────────────────────────────────
 *
 * The management view of one module: what it owns, what it is for, what
 * PROVES it, what it depends on, and where it is weak — all generated, none
 * of it remembered. Every list this leaf prints is derived at call time from
 * engine/composition/lib_module_order.def (through the code index's group rows), the tree
 * itself, and the registered test catalog. No table in this repository has to
 * be updated when a file, a symbol, or a test group is added; such a table is
 * exactly the thing that would go stale.
 *
 * ── The two proof numbers ──
 * ROUTED and REACHED are different facts and are never added together:
 *   routed_groups — the shared-rule router `code tests` uses: change this
 *                   file, run that group. A routing answer; it says nothing
 *                   about whether the group executes the file.
 *   reached/…     — a call-graph closure from every registered group entry
 *                   point. A symbol here is actually CALLED by a test.
 * A symbol can be linked into a test binary and never called, which is why a
 * territory can be fully routed and still be almost entirely unreached.
 *
 * ── Three buckets, and the refusal ──
 * reached + unreached + unknown == public_symbols, always. `unknown` is not a
 * rounding bucket: it is the walk declining to answer, either because the
 * closure was bounded or because the symbol's only references sit at file
 * scope (a dispatch-table row, which a source call graph structurally cannot
 * follow). Folding it into either neighbour is how a tool starts lying.
 *
 * The two facts lib/ may not reach up for arrive as ports (territory.h): the
 * registered catalog lives in tools/dev and the router in app/controllers.
 * This handler already owns both, so it supplies them.
 */

enum {
    CODE_TERRITORY_LIST_CAP    = 96, /* territories rendered by the no-arg form */
    CODE_TERRITORY_GROUP_CAP   = 6,
    CODE_TERRITORY_DEP_CAP     = 6,
    CODE_TERRITORY_WEAK_CAP    = 10,
    CODE_TERRITORY_UNKNOWN_CAP = 4,
    CODE_TERRITORY_FILE_CAP    = 4,
};

static const char *code_territory_entry_at(size_t index, void *user)
{
    (void)user;
    return zcl_test_group_catalog_at(index);
}

/* The router port: the SAME shared-rule resolver behind `code tests`. A
 * consensus surface is reported as routed to consensus_parity even when no
 * path rule matched, because that is what the router actually returns; a path
 * that matches no rule at all returns zero, which is the "no test group at
 * all" signal the scorecard's weak section reports. */
static size_t code_territory_route(const char *path,
                                   char (*out)[TERRITORY_GROUP_MAX],
                                   size_t cap, void *user)
{
    (void)user;
    struct agent_impact_acc acc = {0};
    bool crisk = false;
    const char *route = zcl_native_code_route_for_path(path, &acc, &crisk);
    size_t n = 0;
    if (crisk && n < cap)
        (void)snprintf(out[n++], TERRITORY_GROUP_MAX, "%s", route);
    for (size_t i = 0; i < acc.groups_len && n < cap; i++) {
        bool dup = false;
        for (size_t j = 0; j < n; j++)
            if (strcmp(out[j], acc.groups[i]) == 0) { dup = true; break; }
        if (!dup)
            (void)snprintf(out[n++], TERRITORY_GROUP_MAX, "%s", acc.groups[i]);
    }
    return n;
}

/* The no-arg form: every territory the index declares, with its direct file
 * count. Derived from the group rows, which are themselves the X-macro paste
 * of engine/composition/lib_module_order.def plus the app shapes.
 *
 * ONE array, not the usual structured-plus-`lines` pair. There are ~64
 * territories, and rendering each twice puts the menu over the 4096-byte
 * ordinary-result ceiling that the registry latency contract measures every
 * READY code.* leaf against with an empty input. The structured rows carry
 * the same two facts the text lines would, so the duplicate is what gets
 * dropped rather than the leaf's budget being raised around it. */
static void code_territory_render_list(struct codeindex *ci,
                                       struct zcl_command_reply *reply)
{
    static char names[CODE_TERRITORY_LIST_CAP][TERRITORY_NAME_MAX];
    int n = territory_list(ci, names, CODE_TERRITORY_LIST_CAP);
    if (n < 0) n = 0;

    struct json_value arr;
    json_init(&arr); json_set_array(&arr);
    int total = 0;
    for (int i = 0; i < n; i++) {
        int fc = codeindex_count_files_in_group(ci, names[i], false);
        if (fc < 0) fc = 0;
        total += fc;
        struct json_value o;
        json_init(&o); json_set_object(&o);
        (void)json_push_kv_str(&o, "name", names[i]);
        (void)json_push_kv_int(&o, "files", fc);
        code_push_obj(&arr, &o);
    }
    (void)json_push_kv_str(&reply->data, "scope", "list");
    (void)json_push_kv(&reply->data, "territories", &arr);
    (void)json_push_kv_int(&reply->data, "count", n);
    (void)json_push_kv_int(&reply->data, "files", total);
    char summary[160];
    (void)snprintf(summary, sizeof(summary),
                   "%d territories owning %d files; run "
                   "`code territory <name>` for one scorecard", n, total);
    (void)json_push_kv_str(&reply->data, "summary", summary);
    json_free(&arr);
}

void zcl_native_handle_code_territory(const struct zcl_command_request *request,
                                      struct zcl_command_reply *reply)
{
    struct codeindex *ci = code_open(request, reply);
    if (!ci) return;

    const char *name = code_str(request, "name");
    if (!name) {
        code_territory_render_list(ci, reply);
        codeindex_close(ci);
        return;
    }

    const char *root = code_source_root(request);
    struct territory_proof_source src = {
        .at = code_territory_entry_at,
        .count = zcl_test_group_catalog_count(),
        .user = NULL,
    };
    struct territory_reach_stats rstats = {0};
    struct territory_reach_set *rs =
        territory_reach_open(ci, root, &src, &rstats);
    struct territory_router router = { .route = code_territory_route,
                                       .user = NULL };
    struct territory_report *r =
        territory_scorecard(ci, root, name, rs, &router);
    if (!r) {
        territory_reach_free(rs);
        codeindex_close(ci);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "TERRITORY_SCORECARD",
                               "dispatch", true, false,
                               "could not build the territory scorecard", name);
        return;
    }
    r->reach = rstats;

    (void)json_push_kv_str(&reply->data, "scope", "territory");
    (void)json_push_kv_str(&reply->data, "territory", r->name);
    (void)json_push_kv_bool(&reply->data, "found", r->found);
    (void)json_push_kv_str(&reply->data, "kind", r->kind);
    char purpose[136];
    code_trunc(purpose, sizeof(purpose), r->purpose, 128);
    (void)json_push_kv_str(&reply->data, "purpose", purpose);

    /* what it owns */
    struct json_value owns;
    json_init(&owns); json_set_object(&owns);
    (void)json_push_kv_int(&owns, "files", r->file_count);
    (void)json_push_kv_int(&owns, "headers", r->header_count);
    (void)json_push_kv_int(&owns, "sources", r->source_count);
    (void)json_push_kv_int(&owns, "bytes", r->bytes);
    (void)json_push_kv_bool(&owns, "truncated", r->files_truncated);
    (void)json_push_kv(&reply->data, "owns", &owns);
    json_free(&owns);

    /* what proves it — ROUTED */
    struct json_value groups;
    json_init(&groups); json_set_array(&groups);
    for (int i = 0; i < r->group_count && i < CODE_TERRITORY_GROUP_CAP; i++) {
        struct json_value o;
        json_init(&o); json_set_object(&o);
        (void)json_push_kv_str(&o, "group", r->groups[i].name);
        (void)json_push_kv_int(&o, "files", r->groups[i].files);
        code_push_obj(&groups, &o);
    }
    (void)json_push_kv(&reply->data, "routed_groups", &groups);
    json_free(&groups);
    (void)json_push_kv_int(&reply->data, "routed_group_count", r->group_count);
    (void)json_push_kv_int(&reply->data, "files_unrouted", r->files_unrouted);

    /* what proves it — REACHED. The three buckets partition public_symbols. */
    (void)json_push_kv_int(&reply->data, "public_symbols", r->public_symbols);
    (void)json_push_kv_int(&reply->data, "reached", r->reached);
    (void)json_push_kv_int(&reply->data, "unreached", r->unreached);
    (void)json_push_kv_int(&reply->data, "unknown", r->unknown);
    (void)json_push_kv_int(&reply->data, "public_types", r->public_types);
    (void)json_push_kv_int(&reply->data, "public_macros", r->public_macros);
    /* The blind spot in public_symbols, counted rather than hidden: the code
     * index attributes a function declaration only at file scope, so every
     * function inside a header's `extern "C" { … }` block is invisible to it.
     * A low public_symbols next to a high headers_extern_c is a measurement
     * limit, not a small public surface. */
    (void)json_push_kv_int(&reply->data, "headers_without_functions",
                           r->headers_without_functions);
    (void)json_push_kv_int(&reply->data, "headers_extern_c",
                           r->headers_extern_c);
    (void)json_push_kv_bool(&reply->data, "symbols_truncated",
                            r->symbols_truncated);

    /* how the reached set itself was obtained — the honesty counters */
    struct json_value reach;
    json_init(&reach); json_set_object(&reach);
    (void)json_push_kv_str(&reach, "source",
                           rs ? (r->reach.from_cache ? "memo" : "walk")
                              : "unavailable");
    (void)json_push_kv_int(&reach, "entry_points", (int64_t)r->reach.seeds);
    (void)json_push_kv_int(&reach, "closure_symbols", (int64_t)r->reach.symbols);
    (void)json_push_kv_int(&reach, "walk_steps", (int64_t)r->reach.steps);
    (void)json_push_kv_int(&reach, "walk_us", (int64_t)r->reach.build_us);
    (void)json_push_kv_bool(&reach, "truncated", r->reach.truncated);
    (void)json_push_kv(&reply->data, "reach", &reach);
    json_free(&reach);

    /* What this call cost, per phase. Reported, not claimed: a reader who
     * doubts a number can see how much work produced it. */
    struct json_value cost;
    json_init(&cost); json_set_object(&cost);
    (void)json_push_kv_int(&cost, "owns_us", (int64_t)r->owns_us);
    (void)json_push_kv_int(&cost, "routed_us", (int64_t)r->routed_us);
    (void)json_push_kv_int(&cost, "symbols_us", (int64_t)r->symbols_us);
    (void)json_push_kv_int(&cost, "deps_us", (int64_t)r->deps_us);
    (void)json_push_kv_int(&cost, "index_lookups", (int64_t)r->index_lookups);
    (void)json_push_kv(&reply->data, "cost", &cost);
    json_free(&cost);

    /* what it depends on, and what depends on it */
    struct json_value dout, din;
    json_init(&dout); json_set_array(&dout);
    json_init(&din);  json_set_array(&din);
    for (int i = 0; i < r->deps_out_count && i < CODE_TERRITORY_DEP_CAP; i++) {
        struct json_value o;
        json_init(&o); json_set_object(&o);
        (void)json_push_kv_str(&o, "name", r->deps_out[i].name);
        (void)json_push_kv_int(&o, "edges", r->deps_out[i].edges);
        code_push_obj(&dout, &o);
    }
    for (int i = 0; i < r->deps_in_count && i < CODE_TERRITORY_DEP_CAP; i++) {
        struct json_value o;
        json_init(&o); json_set_object(&o);
        (void)json_push_kv_str(&o, "name", r->deps_in[i].name);
        (void)json_push_kv_int(&o, "edges", r->deps_in[i].edges);
        code_push_obj(&din, &o);
    }
    (void)json_push_kv(&reply->data, "depends_on", &dout);
    (void)json_push_kv(&reply->data, "depended_on_by", &din);
    json_free(&dout); json_free(&din);
    (void)json_push_kv_int(&reply->data, "depends_on_count", r->deps_out_count);
    (void)json_push_kv_int(&reply->data, "depended_on_by_count",
                           r->deps_in_count);
    (void)json_push_kv_str(&reply->data, "deps_dimension",
                           !r->deps_available ? "no-include-graph"
                           : r->deps_truncated ? "closure-truncated"
                                               : "complete");

    /* where it is weak */
    struct json_value weak_syms, weak_unknown, weak_files;
    json_init(&weak_syms);    json_set_array(&weak_syms);
    json_init(&weak_unknown); json_set_array(&weak_unknown);
    json_init(&weak_files);   json_set_array(&weak_files);
    int shown_u = 0, shown_k = 0;
    for (int i = 0; i < r->public_symbols; i++) {
        if (r->symbols[i].verdict == TERRITORY_UNREACHED &&
            shown_u < CODE_TERRITORY_WEAK_CAP) {
            code_push_line(&weak_syms, r->symbols[i].name);
            shown_u++;
        } else if (r->symbols[i].verdict == TERRITORY_UNKNOWN &&
                   shown_k < CODE_TERRITORY_UNKNOWN_CAP) {
            char line[192];
            (void)snprintf(line, sizeof(line), "%s (%s)", r->symbols[i].name,
                           territory_reach_reason_label(r->symbols[i].reason));
            code_push_line(&weak_unknown, line);
            shown_k++;
        }
    }
    int shown_f = 0;
    for (int i = 0; i < r->file_count && shown_f < CODE_TERRITORY_FILE_CAP; i++)
        if (!r->files[i].routed) {
            code_push_line(&weak_files, r->files[i].path);
            shown_f++;
        }
    (void)json_push_kv(&reply->data, "unreached_symbols", &weak_syms);
    (void)json_push_kv(&reply->data, "unknown_symbols", &weak_unknown);
    (void)json_push_kv(&reply->data, "unrouted_files", &weak_files);
    json_free(&weak_syms); json_free(&weak_unknown); json_free(&weak_files);

    char summary[544];
    (void)snprintf(summary, sizeof(summary),
                   "%s: %d files (%d headers, %d sources, %lld bytes); routed "
                   "to %d group(s), %d file(s) routed to none; %d public "
                   "functions = %d reached + %d unreached + %d unknown "
                   "(%d header(s) contributed none, %d of those are extern "
                   "\"C\" and invisible to the index); depends on %d "
                   "territor(y/ies), %d depend on it",
                   r->name, r->file_count, r->header_count, r->source_count,
                   (long long)r->bytes, r->group_count, r->files_unrouted,
                   r->public_symbols, r->reached, r->unreached, r->unknown,
                   r->headers_without_functions, r->headers_extern_c,
                   r->deps_out_count, r->deps_in_count);
    (void)json_push_kv_str(&reply->data, "summary", summary);

    territory_report_free(r);
    territory_reach_free(rs);
    codeindex_close(ci);
}

/* ── code.kpi ────────────────────────────────────────────────────────────
 *
 * The build's own numbers, recorded rather than remembered. Every metric here
 * already existed somewhere in the checkout; what did not exist was a record
 * of what it was LAST time, so "did that get better?" was answered from memory
 * or not at all.
 *
 * THE ONLY code.* LEAF THAT WRITES. It appends one canonical frame per run to
 * <root>/.codeindex/kpi.chainlog — the same directory the code index already
 * uses for local derived state, and one git does not track. That write is the
 * point of the command, so the registry row classes it MUTATE rather than
 * dressing a writer as a read.
 *
 * 0 AND "I COULD NOT LOOK" ARE DIFFERENT FACTS. A metric whose artifact is
 * missing or unparsable renders state "unavailable", value null and verdict
 * "unavailable" — never 0. The run still writes its frame, because the
 * unavailability is itself what is being recorded, and the summary names how
 * many were unavailable so a short answer is never read as a clean one.
 *
 * `previous` is the most recent PRIOR frame, read before the append. With no
 * prior frame the verdict is no_baseline, never unchanged: "equal to nothing"
 * is not a measurement.
 *
 * IT GRANTS NOTHING. A frame is a measurement, never an approval, never a
 * gate, never permission to land anything.
 */


void zcl_native_handle_code_kpi(const struct zcl_command_request *request,
                                struct zcl_command_reply *reply)
{
    const char *root = code_source_root(request);
    struct codeindex *ci = code_open(request, reply);
    if (!ci) return;

    struct kpi_frame frame;
    kpi_collect(root, ci, &frame);
    codeindex_close(ci);

    char ledger[1024];
    int wrote_path = snprintf(ledger, sizeof ledger, "%s/.codeindex/kpi.chainlog",
                              root);
    if (wrote_path < 0 || (size_t)wrote_path >= sizeof ledger) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "KPI_LEDGER_PATH",
                               "dispatch", true, false,
                               "the source root is too long to hold a ledger "
                               "path", root);
        return;
    }

    struct kpi_ledger_result led;
    bool appended = kpi_ledger_record(ledger, &frame, &led);
    /* A ledger that refuses is reported as a refusal, by the chainlog's own
     * status name. Rendering the metrics anyway while quietly dropping the
     * frame would leave a reader believing a history exists that does not. */
    if (!appended) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "KPI_LEDGER_APPEND",
                               "dispatch", true, false,
                               zcl_chainlog_status_label(led.status), ledger);
        return;
    }

    size_t ndefs = 0;
    const struct kpi_metric_def *defs = kpi_metric_defs(&ndefs);

    struct json_value arr;
    json_init(&arr); json_set_array(&arr);
    int improved = 0, regressed = 0, unavailable = 0;

    for (size_t i = 0; i < ndefs; i++) {
        const struct kpi_entry *cur = kpi_frame_find(&frame, defs[i].id);
        if (!cur) continue;
        const struct kpi_entry *prev =
            led.have_previous ? kpi_frame_find(&led.previous, defs[i].id)
                              : NULL;
        enum kpi_verdict v = kpi_verdict_of(defs[i].direction, prev, cur);
        if (v == KPI_VERDICT_IMPROVED) improved++;
        else if (v == KPI_VERDICT_REGRESSED) regressed++;
        if (cur->state != KPI_STATE_PRESENT) unavailable++;

        struct json_value o;
        json_init(&o); json_set_object(&o);
        (void)json_push_kv_str(&o, "id", defs[i].id);
        (void)json_push_kv_str(&o, "state", kpi_state_label(cur->state));
        if (cur->state == KPI_STATE_PRESENT)
            (void)json_push_kv_int(&o, "value", (int64_t)cur->value);
        if (prev && prev->state == KPI_STATE_PRESENT) {
            (void)json_push_kv_int(&o, "previous", (int64_t)prev->value);
            if (cur->state == KPI_STATE_PRESENT)
                (void)json_push_kv_int(&o, "delta",
                                       (int64_t)cur->value -
                                           (int64_t)prev->value);
        }
        (void)json_push_kv_str(&o, "direction",
                               kpi_direction_label(defs[i].direction));
        (void)json_push_kv_str(&o, "verdict", kpi_verdict_label(v));
        (void)json_push_kv_str(&o, "drill", defs[i].drill);
        code_push_obj(&arr, &o);
    }

    char root_hex[65];
    zcl_hex_encode(frame.source_root_sha3, 32, root_hex);

    (void)json_push_kv_str(&reply->data, "scope", "kpi");
    (void)json_push_kv(&reply->data, "metrics", &arr);
    (void)json_push_kv_int(&reply->data, "count", (int64_t)ndefs);
    (void)json_push_kv_int(&reply->data, "seq", (int64_t)led.seq);
    (void)json_push_kv_int(&reply->data, "prior_frames",
                           (int64_t)led.prior_records);
    (void)json_push_kv_str(&reply->data, "source_root_sha3", root_hex);
    (void)json_push_kv_str(&reply->data, "ledger", ".codeindex/kpi.chainlog");
    json_free(&arr);

    char summary[320];
    if (!led.have_previous)
        (void)snprintf(summary, sizeof summary,
                       "frame %llu is the first: %d improved, %d regressed, "
                       "%d unavailable, %d with no baseline yet",
                       (unsigned long long)led.seq, improved, regressed,
                       unavailable, (int)ndefs - unavailable);
    else
        (void)snprintf(summary, sizeof summary,
                       "frame %llu vs %llu: %d improved, %d regressed, "
                       "%d unavailable",
                       (unsigned long long)led.seq,
                       (unsigned long long)led.prior_records, improved,
                       regressed, unavailable);
    (void)json_push_kv_str(&reply->data, "summary", summary);
}

/* ── `general` — the dispatch brief, and the roll-up ─────────────────────
 *
 * A GENERAL GRANTS NO AUTHORITY. This leaf reports; it never decides. Z23's
 * standing rule is "no referee, no authority — everyone runs a full node",
 * and a brief that could approve or block work would be a referee with a
 * friendlier name. Nothing here is on any permission path, and
 * metaverse_grant_check() remains the only answer to what anything may do.
 * If someone later adds an "approved" field or a caller that branches on a
 * brief, that is the defect — not a missing feature.
 *
 * What it is for: several agents work this tree at once, and the recurring
 * failure is acting on a REMEMBERED inventory instead of the real one. The
 * worst case so far was two lanes dispatched to import a 12,474-line
 * ActiveRecord library the repo already had in 970 lines. A brief is the
 * scorecard projected into the form whoever is about to work in a territory
 * needs at dispatch time: what is here, how much of it is proven, what binds
 * it, and what the tree cannot tell you.
 *
 * Everything is generated per call. No persona text, no owners table, no
 * per-territory prose — a written brief goes stale exactly the way a
 * MAINTAINERS file does, and staleness is the defect being cured.
 */

enum {
    GENERAL_ROLLUP_ROWS  = 12,  /* the page a person actually reads */
    GENERAL_REFUSAL_ROWS = 12,
    GENERAL_WEAK_ROWS    = 8,
    GENERAL_DEP_ROWS     = 5,
};

/* The determinism ledger port. It is NOT landed: the lane building it has not
 * merged, so every group's answer is UNKNOWN. The field is emitted anyway,
 * with its count and the reason, because a missing field reads as "nothing to
 * worry about" — and an unreproducible test group is precisely the evidence a
 * second person cannot re-check. When the ledger lands, give this struct a
 * `lookup` and the brief starts answering; nothing else moves. */
static const struct territory_trust_ledger g_general_trust = {
    .lookup = NULL,
    .user   = NULL,
    .source = "determinism ledger not landed (concurrent lane)",
};

static void general_render_rollup(struct codeindex *ci, const char *root,
                                  const struct territory_reach_set *rs,
                                  const struct territory_router *router,
                                  struct zcl_command_reply *reply)
{
    struct territory_rollup *u = territory_rollup_build(ci, root, rs, router);
    if (!u) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "TERRITORY_ROLLUP",
                               "dispatch", true, false,
                               "could not score the territories", "");
        return;
    }

    struct json_value arr;
    json_init(&arr); json_set_array(&arr);
    for (int i = 0; i < u->count && i < GENERAL_ROLLUP_ROWS; i++) {
        const struct territory_rank *k = &u->ranks[i];
        struct json_value o;
        json_init(&o); json_set_object(&o);
        (void)json_push_kv_str(&o, "territory", k->name);
        (void)json_push_kv_int(&o, "unproven", k->unproven);
        (void)json_push_kv_int(&o, "unreached", k->unreached);
        (void)json_push_kv_int(&o, "unknown", k->unknown);
        (void)json_push_kv_int(&o, "reached", k->reached);
        (void)json_push_kv_int(&o, "public", k->public_symbols);
        (void)json_push_kv_int(&o, "unrouted_files", k->unrouted_files);
        (void)json_push_kv_int(&o, "files", k->files);
        code_push_obj(&arr, &o);
    }
    (void)json_push_kv_str(&reply->data, "scope", "roll-up");
    (void)json_push_kv(&reply->data, "weakest", &arr);
    json_free(&arr);

    (void)json_push_kv_str(&reply->data, "rank_key",
                           "unproven = unreached + unknown, then "
                           "unrouted_files, then name");
    (void)json_push_kv_int(&reply->data, "territories", u->count);
    (void)json_push_kv_int(&reply->data, "rows_shown",
                           u->count < GENERAL_ROLLUP_ROWS
                               ? u->count : GENERAL_ROLLUP_ROWS);
    (void)json_push_kv_int(&reply->data, "scored", u->scored);
    (void)json_push_kv_int(&reply->data, "failed", u->failed);

    /* The tree-wide totals, each printed beside the parts it is made of so a
     * reader can add them up and check. */
    struct json_value tot;
    json_init(&tot); json_set_object(&tot);
    (void)json_push_kv_int(&tot, "files", u->total_files);
    (void)json_push_kv_int(&tot, "public_functions", u->total_public);
    (void)json_push_kv_int(&tot, "reached", u->total_reached);
    (void)json_push_kv_int(&tot, "unreached", u->total_unreached);
    (void)json_push_kv_int(&tot, "unknown", u->total_unknown);
    (void)json_push_kv_int(&tot, "unrouted_files", u->total_unrouted);
    (void)json_push_kv_int(&tot, "headers_extern_c",
                           u->total_headers_extern_c);
    (void)json_push_kv(&reply->data, "tree", &tot);
    json_free(&tot);

    struct json_value cost;
    json_init(&cost); json_set_object(&cost);
    (void)json_push_kv_str(&cost, "source", u->from_cache ? "memo" : "scored");
    (void)json_push_kv_bool(&cost, "memo_written", u->cache_written);
    (void)json_push_kv_int(&cost, "build_us", (int64_t)u->build_us);
    (void)json_push_kv(&reply->data, "cost", &cost);
    json_free(&cost);

    char summary[512];
    (void)snprintf(summary, sizeof(summary),
                   "%d territories, %lld files: %lld public functions = %lld "
                   "reached + %lld unreached + %lld unknown; %lld file(s) "
                   "route to no registered group; %lld header(s) are extern "
                   "\"C\" and invisible to the index, so the public count is a "
                   "floor. Ranked by unproven public surface — the top row is "
                   "where a reader should look first, not the biggest module.",
                   u->count, (long long)u->total_files,
                   (long long)u->total_public, (long long)u->total_reached,
                   (long long)u->total_unreached, (long long)u->total_unknown,
                   (long long)u->total_unrouted,
                   (long long)u->total_headers_extern_c);
    (void)json_push_kv_str(&reply->data, "summary", summary);
    territory_rollup_free(u);
}

static void general_render_brief(struct codeindex *ci, const char *root,
                                 const char *name,
                                 const struct territory_reach_set *rs,
                                 const struct territory_router *router,
                                 struct zcl_command_reply *reply)
{
    static char names[CODE_TERRITORY_LIST_CAP][TERRITORY_NAME_MAX];
    int nt = territory_list(ci, names, CODE_TERRITORY_LIST_CAP);
    if (nt < 0) nt = 0;
    struct territory_gates *gates = territory_gates_open(root, names, nt);

    struct territory_brief *b = territory_brief_build(ci, root, name, rs,
                                                      router, gates,
                                                      &g_general_trust);
    if (!b) {
        territory_gates_free(gates);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "TERRITORY_BRIEF",
                               "dispatch", true, false,
                               "could not build the territory brief", name);
        return;
    }
    const struct territory_report *r = b->report;

    (void)json_push_kv_str(&reply->data, "scope", "brief");
    (void)json_push_kv_str(&reply->data, "territory", r->name);
    (void)json_push_kv_bool(&reply->data, "found", r->found);
    (void)json_push_kv_str(&reply->data, "authority",
                           "none — this brief reports; it never approves, "
                           "gates, or blocks. metaverse_grant_check() is the "
                           "only answer to what anything may do.");
    char purpose[136];
    code_trunc(purpose, sizeof(purpose), r->purpose, 128);
    (void)json_push_kv_str(&reply->data, "purpose", purpose);

    /* owns */
    struct json_value owns;
    json_init(&owns); json_set_object(&owns);
    (void)json_push_kv_int(&owns, "files", r->file_count);
    (void)json_push_kv_int(&owns, "headers", r->header_count);
    (void)json_push_kv_int(&owns, "sources", r->source_count);
    (void)json_push_kv_int(&owns, "bytes", r->bytes);
    (void)json_push_kv_int(&owns, "public_functions", r->public_symbols);
    (void)json_push_kv_int(&owns, "public_types", r->public_types);
    (void)json_push_kv_int(&owns, "public_macros", r->public_macros);
    (void)json_push_kv(&reply->data, "owns", &owns);
    json_free(&owns);

    /* proves — routed and reached, never summed */
    struct json_value proves;
    json_init(&proves); json_set_object(&proves);
    (void)json_push_kv_int(&proves, "routed_groups", r->group_count);
    (void)json_push_kv_int(&proves, "files_unrouted", r->files_unrouted);
    (void)json_push_kv_int(&proves, "reached", r->reached);
    (void)json_push_kv_int(&proves, "unreached", r->unreached);
    (void)json_push_kv_int(&proves, "unknown", r->unknown);
    (void)json_push_kv_int(&proves, "public_functions", r->public_symbols);
    (void)json_push_kv_str(&proves, "note",
                           "routed answers 'change this file, run that group'. "
                           "reached answers 'a test actually calls this'. They "
                           "are never added together.");
    struct json_value garr;
    json_init(&garr); json_set_array(&garr);
    for (int i = 0; i < r->group_count && i < CODE_TERRITORY_GROUP_CAP; i++) {
        struct json_value o;
        json_init(&o); json_set_object(&o);
        (void)json_push_kv_str(&o, "group", r->groups[i].name);
        (void)json_push_kv_int(&o, "files", r->groups[i].files);
        code_push_obj(&garr, &o);
    }
    (void)json_push_kv(&proves, "groups", &garr);
    json_free(&garr);
    (void)json_push_kv(&reply->data, "proves", &proves);
    json_free(&proves);

    /* trusts — the declared hole, never omitted */
    struct json_value trust;
    json_init(&trust); json_set_object(&trust);
    (void)json_push_kv_int(&trust, "reproducible", b->trust_reproducible);
    (void)json_push_kv_int(&trust, "not_reproducible",
                           b->trust_not_reproducible);
    (void)json_push_kv_int(&trust, "unknown", b->trust_unknown);
    (void)json_push_kv_str(&trust, "source", b->trust_source);
    (void)json_push_kv_str(&trust, "note",
                           "whether a result from these groups can be "
                           "re-checked by someone else is NOT known here. The "
                           "ledger that would answer it has not landed; this "
                           "field is reported empty rather than omitted, "
                           "because an omitted field reads as 'fine'.");
    (void)json_push_kv(&reply->data, "trusts", &trust);
    json_free(&trust);

    /* refuses — three buckets that partition the wired gates */
    struct json_value refuses, rarr;
    json_init(&refuses); json_set_object(&refuses);
    json_init(&rarr); json_set_array(&rarr);
    for (int i = 0; i < b->refusal_count && i < GENERAL_REFUSAL_ROWS; i++) {
        struct json_value o;
        json_init(&o); json_set_object(&o);
        (void)json_push_kv_str(&o, "gate", b->refuses[i].gate);
        (void)json_push_kv_bool(&o, "names_this_territory",
                                b->refuses[i].named_in_gate);
        (void)json_push_kv_int(&o, "baseline_rows",
                               b->refuses[i].baseline_rows);
        code_push_obj(&rarr, &o);
    }
    (void)json_push_kv(&refuses, "gates", &rarr);
    json_free(&rarr);
    (void)json_push_kv_bool(&refuses, "wiring_readable", b->gate_wiring_found);
    (void)json_push_kv_int(&refuses, "wired_gates", b->gates_total);
    (void)json_push_kv_int(&refuses, "binds", b->gates_binding);
    (void)json_push_kv_int(&refuses, "unknown_names_other_territories",
                           b->gates_unknown_named_others);
    (void)json_push_kv_int(&refuses, "unknown_names_no_territory",
                           b->gates_unknown_named_none);
    (void)json_push_kv_int(&refuses, "unknown_total",
                           b->gates_unknown_named_others +
                               b->gates_unknown_named_none);
    (void)json_push_kv_bool(&refuses, "rows_truncated", b->refusals_truncated);
    (void)json_push_kv_str(&refuses, "note",
                           "derived from tools/lint/run_lint.sh's gate table, "
                           "each gate script's own text, and the baseline "
                           "ledgers those scripts name. Only `binds` is a "
                           "claim, and it carries its evidence. Both unknown "
                           "buckets mean 'cannot tell': most gates scan the "
                           "whole tree, so a gate that never names this "
                           "territory may still bind it. Naming other "
                           "territories is NOT reported as 'scoped elsewhere' "
                           "— that would be a guess.");
    (void)json_push_kv(&reply->data, "refuses", &refuses);
    json_free(&refuses);

    /* weak at */
    struct json_value weak, wsym, wunk, wfile;
    json_init(&weak); json_set_object(&weak);
    json_init(&wsym);  json_set_array(&wsym);
    json_init(&wunk);  json_set_array(&wunk);
    json_init(&wfile); json_set_array(&wfile);
    int su = 0, sk = 0;
    for (int i = 0; i < r->public_symbols; i++) {
        if (r->symbols[i].verdict == TERRITORY_UNREACHED &&
            su < GENERAL_WEAK_ROWS) {
            code_push_line(&wsym, r->symbols[i].name);
            su++;
        } else if (r->symbols[i].verdict == TERRITORY_UNKNOWN &&
                   sk < CODE_TERRITORY_UNKNOWN_CAP) {
            char line[192];
            (void)snprintf(line, sizeof(line), "%s (%s)", r->symbols[i].name,
                           territory_reach_reason_label(r->symbols[i].reason));
            code_push_line(&wunk, line);
            sk++;
        }
    }
    int sf = 0;
    for (int i = 0; i < r->file_count && sf < CODE_TERRITORY_FILE_CAP; i++)
        if (!r->files[i].routed) {
            code_push_line(&wfile, r->files[i].path);
            sf++;
        }
    (void)json_push_kv(&weak, "unreached_symbols", &wsym);
    (void)json_push_kv(&weak, "unknown_symbols", &wunk);
    (void)json_push_kv(&weak, "unrouted_files", &wfile);
    json_free(&wsym); json_free(&wunk); json_free(&wfile);
    (void)json_push_kv_int(&weak, "unproven", b->unproven);
    /* The second declared hole, and the one closest to the failure this whole
     * command exists to prevent: near-duplicate code inside a territory is
     * exactly what a lane re-implements when it acts on memory. cognition/modules/fingerprint
     * would answer it and has not landed, so the field says UNKNOWN rather
     * than being left out — an absent duplicate section reads as "no
     * duplicates", which is the belief that cost us the ActiveRecord rebuild. */
    (void)json_push_kv_str(&weak, "duplicate_clusters",
                           "unknown — cognition/modules/fingerprint has not landed; this "
                           "brief makes no claim either way");
    (void)json_push_kv_int(&weak, "headers_extern_c", r->headers_extern_c);
    (void)json_push_kv_int(&weak, "headers_without_functions",
                           r->headers_without_functions);
    (void)json_push_kv(&reply->data, "weak_at", &weak);
    json_free(&weak);

    /* depends */
    struct json_value dout, din;
    json_init(&dout); json_set_array(&dout);
    json_init(&din);  json_set_array(&din);
    for (int i = 0; i < r->deps_out_count && i < GENERAL_DEP_ROWS; i++) {
        struct json_value o;
        json_init(&o); json_set_object(&o);
        (void)json_push_kv_str(&o, "name", r->deps_out[i].name);
        (void)json_push_kv_int(&o, "edges", r->deps_out[i].edges);
        code_push_obj(&dout, &o);
    }
    for (int i = 0; i < r->deps_in_count && i < GENERAL_DEP_ROWS; i++) {
        struct json_value o;
        json_init(&o); json_set_object(&o);
        (void)json_push_kv_str(&o, "name", r->deps_in[i].name);
        (void)json_push_kv_int(&o, "edges", r->deps_in[i].edges);
        code_push_obj(&din, &o);
    }
    (void)json_push_kv(&reply->data, "depends_on", &dout);
    (void)json_push_kv(&reply->data, "depended_on_by", &din);
    json_free(&dout); json_free(&din);

    struct json_value cost;
    json_init(&cost); json_set_object(&cost);
    (void)json_push_kv_str(&cost, "reach_source",
                           rs ? (r->reach.from_cache ? "memo" : "walk")
                              : "unavailable");
    (void)json_push_kv_int(&cost, "gates_us", (int64_t)b->gates_us);
    (void)json_push_kv_int(&cost, "routed_us", (int64_t)r->routed_us);
    (void)json_push_kv_int(&cost, "symbols_us", (int64_t)r->symbols_us);
    (void)json_push_kv_int(&cost, "deps_us", (int64_t)r->deps_us);
    (void)json_push_kv(&reply->data, "cost", &cost);
    json_free(&cost);

    char summary[544];
    (void)snprintf(summary, sizeof(summary),
                   "%s: %d files (%lld bytes), %d public functions = %d "
                   "reached + %d unreached + %d unknown; routed to %d group(s) "
                   "with %d file(s) routed to none; %d of %d wired lint gates "
                   "demonstrably bind here (%d name another territory, %d name "
                   "none — both mean 'cannot tell', not 'no'); "
                   "reproducibility of those groups is UNKNOWN (%s)",
                   r->name, r->file_count, (long long)r->bytes,
                   r->public_symbols, r->reached, r->unreached, r->unknown,
                   r->group_count, r->files_unrouted, b->gates_binding,
                   b->gates_total, b->gates_unknown_named_others,
                   b->gates_unknown_named_none, b->trust_source);
    (void)json_push_kv_str(&reply->data, "summary", summary);

    territory_brief_free(b);
    territory_gates_free(gates);
}

void zcl_native_handle_general(const struct zcl_command_request *request,
                               struct zcl_command_reply *reply)
{
    struct codeindex *ci = code_open(request, reply);
    if (!ci) return;

    const char *root = code_source_root(request);
    struct territory_proof_source src = {
        .at = code_territory_entry_at,
        .count = zcl_test_group_catalog_count(),
        .user = NULL,
    };
    struct territory_reach_stats rstats = {0};
    struct territory_reach_set *rs =
        territory_reach_open(ci, root, &src, &rstats);
    struct territory_router router = { .route = code_territory_route,
                                       .user = NULL };

    const char *name = code_str(request, "name");
    if (!name || !name[0] || strcmp(name, "roll-up") == 0 ||
        strcmp(name, "rollup") == 0)
        general_render_rollup(ci, root, rs, &router, reply);
    else
        general_render_brief(ci, root, name, rs, &router, reply);

    territory_reach_free(rs);
    codeindex_close(ci);
}
