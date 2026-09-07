/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The code.capsule handler: one bounded document composing everything
 * code.sym + code.refs + code.file + code.tests would take four calls to
 * assemble, for ONE symbol. Split out of native_code_command.c (the `code`
 * command family's shared helpers, routing link, and dispatch join) so each
 * sibling file stays under the single-family line ceiling; see
 * native_code_priv.h for the interface this file shares with its siblings.
 */

#include "command/native_command.h"
#include "command/native_code_priv.h"

#include "codeindex/codeindex.h"
#include "json/json.h"

#include <stdio.h>
#include <string.h>

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

