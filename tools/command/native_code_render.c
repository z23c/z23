/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The code.map, code.room and `general` handlers: the `code` command
 * family's whole-tree map, the unified single-room view, and the
 * dispatch-brief/roll-up leaf. Split out of native_code_command.c (the
 * family's shared helpers, routing link, and dispatch join) so each
 * sibling file stays under the single-family line ceiling; see
 * native_code_priv.h for the interface this file shares with its siblings.
 */

#include "command/native_command.h"
#include "command/native_code_priv.h"

#include "codeindex/codeindex.h"
#include "codeindex/codeindex_build.h"
#include "codeindex/codeindex_context.h"
#include "config/command_catalog.h"
#include "config/command_handler_index.h"
#include "controllers/agent_impact_rules.h"
#include "json/json.h"
#include "territory/territory.h"
#include "test_group_catalog.h"

#include <stdio.h>
#include <string.h>

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
    if (counts.governed_c23_files + counts.fixture_c23_files !=
        counts.c23_files) {
        json_free(&roots); json_free(&shapes);
        codeindex_close(ci);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL,
                               "GOVERNED_COUNT_DISAGREEMENT", "verify",
                               false, false,
                               "code map governed and fixture counts disagree",
                               "");
        return;
    }

    (void)json_push_kv_str(&reply->data, "scope", "map");
    (void)json_push_kv(&reply->data, "roots", &roots);
    (void)json_push_kv(&reply->data, "shapes", &shapes);
    (void)json_push_kv_int(&reply->data, "total_files", total);
    (void)json_push_kv_int(&reply->data, "governed_c23_files",
                           counts.governed_c23_files);
    (void)json_push_kv_int(&reply->data, "indexed_fixture_c23_files",
                           counts.fixture_c23_files);
    (void)json_push_kv_int(&reply->data, "indexed_c23_files",
                           counts.c23_files);
    /* Compatibility field for zcl.code_map.v1 consumers. It has always meant
     * every indexed .c/.h file, including tracked fixture proof inputs. */
    (void)json_push_kv_int(&reply->data, "c23_files", counts.c23_files);
    (void)json_push_kv_int(&reply->data, "registry_nodes",
                           counts.registry_nodes);
    char summary[224];
    (void)snprintf(summary, sizeof(summary),
                   "%d governed C23 files + %d indexed fixture C23 files + "
                   "%d registry nodes across %d physical roots + %d product "
                   "shapes; run `code group <path>` to descend",
                   counts.governed_c23_files, counts.fixture_c23_files,
                   counts.registry_nodes, nroot, nshape);
    (void)json_push_kv_str(&reply->data, "summary", summary);

    json_free(&roots); json_free(&shapes);
    codeindex_close(ci);
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
