/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * code.change-plan — a bounded evidence-labelled bridge from one symbol,
 * intent, or unified patch to the files and proof commands an agent needs.
 * It composes existing codeindex and impact-rule facts; it does not invent a
 * semantic result when the index cannot prove one. */

#include "command/native_command.h"

#include "codeindex/codeindex.h"
#include "controllers/agent_impact_rules.h"
#include "json/json.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { PLAN_PATH_CAP = 8, PLAN_TEST_CAP = 12, PLAN_INTENT_HIT_CAP = 4 };

struct plan_paths {
    char path[PLAN_PATH_CAP][256];
    int line[PLAN_PATH_CAP];
    const char *reason[PLAN_PATH_CAP];
    const char *evidence[PLAN_PATH_CAP];
    size_t len;
};

static const char *plan_str(const struct zcl_command_request *request,
                            const char *key)
{
    const char *value = json_get_str(json_get(request->input, key));
    return value && value[0] ? value : NULL;
}

static void plan_push_string(struct json_value *array, const char *value)
{
    struct json_value item;
    json_init(&item);
    json_set_str(&item, value ? value : "");
    (void)json_push_back(array, &item);
    json_free(&item);
}

static void plan_add_path(struct plan_paths *paths, const char *path, int line,
                          const char *reason, const char *evidence)
{
    if (!paths || !path || !path[0]) return;
    for (size_t i = 0; i < paths->len; i++)
        if (strcmp(paths->path[i], path) == 0) return;
    if (paths->len >= PLAN_PATH_CAP) return;
    size_t i = paths->len++;
    (void)snprintf(paths->path[i], sizeof(paths->path[i]), "%s", path);
    paths->line[i] = line;
    paths->reason[i] = reason;
    paths->evidence[i] = evidence;
}

static void plan_emit_paths(struct json_value *out,
                            const struct plan_paths *paths)
{
    json_set_array(out);
    for (size_t i = 0; i < paths->len; i++) {
        struct json_value item;
        json_init(&item); json_set_object(&item);
        (void)json_push_kv_str(&item, "path", paths->path[i]);
        if (paths->line[i] > 0)
            (void)json_push_kv_int(&item, "line", paths->line[i]);
        (void)json_push_kv_str(&item, "reason", paths->reason[i]);
        (void)json_push_kv_str(&item, "evidence", paths->evidence[i]);
        (void)json_push_back(out, &item);
        json_free(&item);
    }
}

static bool plan_has_test(char tests[][64], size_t count, const char *group)
{
    for (size_t i = 0; i < count; i++)
        if (strcmp(tests[i], group) == 0) return true;
    return false;
}

static void plan_add_test(char tests[][64], size_t *count,
                          const char *group)
{
    if (*count >= PLAN_TEST_CAP || plan_has_test(tests, *count, group)) return;
    (void)snprintf(tests[(*count)++], 64, "%s", group);
}

static bool plan_is_package_workspace(const char *root)
{
    char path[4096];
    int n = snprintf(path, sizeof(path), "%s/zcode-package.json", root);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    FILE *file = fopen(path, "rb");
    if (!file) return false;
    return fclose(file) == 0;
}

static bool plan_is_package_source(const char *path)
{
    static const char *const roots[] = {"app/", "include/", "src/", "tests/"};
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (strncmp(path, roots[i], strlen(roots[i])) == 0) return true;
    return false;
}

static void plan_add_tests_for_path(const char *path, char tests[][64],
                                    size_t *count, bool *consensus_risk)
{
    struct agent_impact_acc impact = {0};
    bool risk = false;
    const char *route = zcl_native_code_route_for_path(path, &impact, &risk);
    if (risk && consensus_risk) *consensus_risk = true;
    for (size_t i = 0; i < impact.groups_len && *count < PLAN_TEST_CAP; i++) {
        if (plan_has_test(tests, *count, impact.groups[i])) continue;
        (void)snprintf(tests[(*count)++], 64, "%s", impact.groups[i]);
    }
    if (*count == 0 || !plan_has_test(tests, *count, route)) {
        if (*count < PLAN_TEST_CAP)
            (void)snprintf(tests[(*count)++], 64, "%s", route);
    }
}

static bool plan_resolve_intent(struct codeindex *index, const char *intent,
                                struct ci_symbol *symbol)
{
    char token[128];
    size_t used = 0;
    for (const char *p = intent;; p++) {
        bool ident = *p && (isalnum((unsigned char)*p) || *p == '_');
        if (ident && used + 1 < sizeof(token)) {
            token[used++] = *p;
            continue;
        }
        if (used >= 4) {
            token[used] = '\0';
            struct ci_symbol hits[PLAN_INTENT_HIT_CAP];
            int count = codeindex_find(index, token, hits, PLAN_INTENT_HIT_CAP);
            if (count > 0) {
                *symbol = hits[0];
                return true;
            }
        }
        used = 0;
        if (!*p) break;
    }
    return false;
}

static void plan_paths_from_patch(const char *patch, struct plan_paths *edit)
{
    const char *line = patch;
    while (line && *line && edit->len < PLAN_PATH_CAP) {
        const char *end = strchr(line, '\n');
        size_t len = end ? (size_t)(end - line) : strlen(line);
        if (len > 6 && strncmp(line, "+++ b/", 6) == 0) {
            size_t path_len = len - 6;
            if (path_len < sizeof(edit->path[0])) {
                char path[256];
                memcpy(path, line + 6, path_len);
                path[path_len] = '\0';
                plan_add_path(edit, path, 0, "changed by supplied patch",
                              "exact_patch_header");
            }
        }
        line = end ? end + 1 : NULL;
    }
}

static const char *plan_input_kind(const char *patch, const char *symbol_query)
{
    return patch ? "patch" : symbol_query ? "symbol" : "intent";
}

static bool plan_symbol_query_is_stable_id(const char *symbol_query)
{
    return strncmp(symbol_query, "fn:", 3) == 0 ||
           strncmp(symbol_query, "struct:", 7) == 0 ||
           strncmp(symbol_query, "typedef:", 8) == 0 ||
           strncmp(symbol_query, "enum:", 5) == 0 ||
           strncmp(symbol_query, "macro:", 6) == 0 ||
           strncmp(symbol_query, "data:", 5) == 0;
}

static const char *plan_resolve_symbol_query(struct codeindex *index,
                                             const char *symbol_query,
                                             struct ci_symbol *symbol,
                                             bool *found)
{
    bool stable = plan_symbol_query_is_stable_id(symbol_query);
    if (stable)
        (void)codeindex_symbol_by_id(index, symbol_query, symbol, found);
    else
        (void)codeindex_symbol(index, symbol_query, symbol, found);
    return *found ? (stable ? "exact_stable_id" : "legacy_name_primary")
                  : "unresolved";
}

static void plan_collect_patch_paths(const char *patch,
                                     struct plan_paths *read,
                                     struct plan_paths *edit)
{
    plan_paths_from_patch(patch, edit);
    for (size_t i = 0; i < edit->len; i++)
        plan_add_path(read, edit->path[i], 0, "inspect changed file",
                      "exact_patch_header");
}

static const char *plan_resolve_input(struct codeindex *index,
                                      const char *symbol_query,
                                      const char *intent, const char *patch,
                                      struct ci_symbol *symbol, bool *found,
                                      struct plan_paths *read,
                                      struct plan_paths *edit)
{
    const char *resolution = patch ? "exact_patch_paths" : "unresolved";
    if (patch) {
        plan_collect_patch_paths(patch, read, edit);
    } else if (symbol_query) {
        resolution = plan_resolve_symbol_query(index, symbol_query, symbol,
                                               found);
    } else if (plan_resolve_intent(index, intent, symbol)) {
        *found = true;
        resolution = "heuristic_intent_symbol";
    }
    return resolution;
}

static void plan_add_symbol_paths(struct codeindex *index,
                                  struct ci_symbol *symbol,
                                  struct plan_paths *read,
                                  struct plan_paths *edit)
{
    const char *def = symbol->def_path[0] ? symbol->def_path : symbol->decl_path;
    int line = symbol->def_path[0] ? symbol->def_line : symbol->decl_line;
    plan_add_path(read, def, line, "symbol definition",
                  "exact_index_location");
    plan_add_path(edit, def, line, "likely implementation site",
                  "heuristic_change_site");
    if (symbol->decl_path[0] && strcmp(symbol->decl_path, def) != 0) {
        plan_add_path(read, symbol->decl_path, symbol->decl_line,
                      "public declaration", "exact_index_location");
        plan_add_path(edit, symbol->decl_path, symbol->decl_line,
                      "only if the contract changes",
                      "heuristic_change_site");
    }
    struct ci_ref callers[PLAN_PATH_CAP];
    int count = codeindex_callers_for_symbol(index, symbol, callers,
                                             PLAN_PATH_CAP);
    for (int i = 0; i < count; i++)
        plan_add_path(read, callers[i].ref_file, callers[i].ref_line,
                      "direct caller", "exact_call_site");
}

static void plan_collect_test_groups(const struct zcl_command_request *request,
                                     const struct plan_paths *edit,
                                     char tests[][64], size_t *count,
                                     bool *consensus_risk)
{
    for (size_t i = 0; i < edit->len; i++)
        plan_add_tests_for_path(edit->path[i], tests, count, consensus_risk);
    if (plan_is_package_workspace(zcl_native_source_root(request))) {
        for (size_t i = 0; i < edit->len; i++) {
            if (!plan_is_package_source(edit->path[i])) continue;
            plan_add_test(tests, count, "zcode_package_registry");
            plan_add_test(tests, count, "zcode_package_dev");
            plan_add_test(tests, count, "make_lint_gates");
            break;
        }
    }
}

static void plan_push_unknowns(struct json_value *unknowns, bool found,
                               const char *patch, size_t read_len)
{
    if (!found && !patch)
        plan_push_string(unknowns, "no indexed symbol was resolved; search before editing");
    plan_push_string(unknowns,
                     "field access, ownership, locks, database/events/blockers are not yet indexed");
    if (read_len >= PLAN_PATH_CAP)
        plan_push_string(unknowns, "read file list reached its bounded cap");
}

void zcl_native_handle_code_change_plan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const char *symbol_query = plan_str(request, "symbol");
    if (!symbol_query) symbol_query = plan_str(request, "name");
    const char *intent = plan_str(request, "intent");
    const char *patch = plan_str(request, "patch");
    if (!symbol_query && !intent && !patch) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_CHANGE",
                               "normalize", false, false,
                               "code change-plan requires a symbol, intent, or patch",
                               "");
        return;
    }

    struct codeindex *index = codeindex_open(zcl_native_source_root(request));
    if (!index) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "CODEINDEX_OPEN",
                               "dispatch", true, false,
                               "could not open or rebuild the code index",
                               zcl_native_source_root(request));
        return;
    }

    struct plan_paths read = {0}, edit = {0};
    struct ci_symbol symbol = {0};
    bool found = false;
    const char *input_kind = plan_input_kind(patch, symbol_query);
    const char *resolution = plan_resolve_input(index, symbol_query, intent,
                                                patch, &symbol, &found, &read,
                                                &edit);
    if (found)
        plan_add_symbol_paths(index, &symbol, &read, &edit);

    char tests[PLAN_TEST_CAP][64] = {{0}};
    size_t test_count = 0;
    bool consensus_risk = false;
    plan_collect_test_groups(request, &edit, tests, &test_count,
                             &consensus_risk);

    (void)json_push_kv_str(&reply->data, "input_kind", input_kind);
    (void)json_push_kv_str(&reply->data, "resolution", resolution);
    (void)json_push_kv_bool(&reply->data, "symbol_found", found);
    if (found) {
        char id[400] = {0};
        (void)codeindex_symbol_record_id(&symbol, id, sizeof(id));
        (void)json_push_kv_str(&reply->data, "symbol_id", id);
    }
    struct json_value read_json, edit_json, avoid, compile, test_groups;
    struct json_value test_commands, unknowns;
    json_init(&read_json); plan_emit_paths(&read_json, &read);
    json_init(&edit_json); plan_emit_paths(&edit_json, &edit);
    json_init(&avoid); json_set_array(&avoid);
    json_init(&compile); json_set_array(&compile);
    json_init(&test_groups); json_set_array(&test_groups);
    json_init(&test_commands); json_set_array(&test_commands);
    json_init(&unknowns); json_set_array(&unknowns);
    plan_push_string(&avoid, "consensus and frozen verifier surfaces unless explicitly in scope");
    plan_push_string(&avoid, "protected node datadirs and deployment surfaces");
    plan_push_string(&compile, "make build-only");
    for (size_t i = 0; i < test_count; i++) {
        plan_push_string(&test_groups, tests[i]);
        char command[128];
        (void)snprintf(command, sizeof(command), "make t-fast ONLY=%s", tests[i]);
        plan_push_string(&test_commands, command);
    }
    plan_push_string(&test_commands, "make lint");
    plan_push_unknowns(&unknowns, found, patch, read.len);

    (void)json_push_kv(&reply->data, "read", &read_json);
    (void)json_push_kv(&reply->data, "edit", &edit_json);
    (void)json_push_kv(&reply->data, "avoid", &avoid);
    (void)json_push_kv(&reply->data, "compile", &compile);
    (void)json_push_kv(&reply->data, "test_groups", &test_groups);
    (void)json_push_kv(&reply->data, "test_commands", &test_commands);
    (void)json_push_kv(&reply->data, "unknowns", &unknowns);
    (void)json_push_kv_bool(&reply->data, "consensus_risk", consensus_risk);
    char summary[224];
    (void)snprintf(summary, sizeof(summary),
                   "%s plan: %zu read, %zu likely edit, %zu focused test group(s); resolution=%s",
                   input_kind, read.len, edit.len, test_count, resolution);
    (void)json_push_kv_str(&reply->data, "summary", summary);

    json_free(&read_json); json_free(&edit_json); json_free(&avoid);
    json_free(&compile); json_free(&test_groups); json_free(&test_commands);
    json_free(&unknowns);
    codeindex_close(index);
}
