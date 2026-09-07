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

/* shape: mirrors code.room's derivation (second component of app/<shape>). */
static void code_capsule_derive_shape(const char *group, char shape[64])
{
    shape[0] = '\0';
    if (strncmp(group, "app/", 4) != 0) return;
    const char *sp = group + 4;
    size_t j = 0;
    for (; sp[j] && sp[j] != '/' && j + 1 < 64; j++)
        shape[j] = sp[j];
    shape[j] = '\0';
}

/* other_defs: the same mechanism as code.sym (never dropped for budget —
 * capped at CODE_OTHER_DEF_CAP already, small by construction). Returns the
 * count and fills `others` (already json_init'd/set_array'd by the caller). */
static int code_capsule_other_defs(struct codeindex *ci,
                                   const struct ci_symbol *s,
                                   struct json_value *others)
{
    static struct ci_symbol hits[CODE_OTHER_DEF_CAP + 4];
    int nh = codeindex_find(ci, s->name, hits,
                            (int)(sizeof(hits) / sizeof(hits[0])));
    if (nh < 0) nh = 0;
    int nother = 0;
    for (int i = 0; i < nh && nother < CODE_OTHER_DEF_CAP; i++) {
        if (strcmp(hits[i].name, s->name) != 0) continue;
        if (hits[i].def_path[0] == '\0') continue;
        if (hits[i].def_line == s->def_line &&
            strcmp(hits[i].def_path, s->def_path) == 0) continue;
        struct json_value o;
        json_init(&o); json_set_object(&o);
        char other_id[400];
        other_id[0] = '\0';
        (void)codeindex_symbol_record_id(&hits[i], other_id,
                                         sizeof(other_id));
        (void)json_push_kv_str(&o, "id", other_id);
        (void)json_push_kv_str(&o, "def_path", hits[i].def_path);
        (void)json_push_kv_int(&o, "def_line", hits[i].def_line);
        code_push_obj(others, &o);
        nother++;
    }
    return nother;
}

/* One droppable section of the self-shrinking assembly below: direct callers
 * of `s` (codeindex_callers_for_symbol), capped at CODE_CAPSULE_CALLER_CAP. */
static void code_capsule_fill_callers(struct codeindex *ci,
                                      const struct ci_symbol *s,
                                      struct json_value *arr, int *n,
                                      bool *trunc)
{
    static struct ci_ref crefs[CODE_CAPSULE_CALLER_CAP + 1];
    int want = CODE_CAPSULE_CALLER_CAP + 1;
    int nc = codeindex_callers_for_symbol(ci, s, crefs, want);
    if (nc < 0) nc = 0;
    *trunc = nc > CODE_CAPSULE_CALLER_CAP;
    *n = *trunc ? CODE_CAPSULE_CALLER_CAP : nc;
    for (int i = 0; i < *n; i++) {
        struct json_value o;
        json_init(&o); json_set_object(&o);
        (void)json_push_kv_str(&o, "file", crefs[i].ref_file);
        (void)json_push_kv_int(&o, "line", crefs[i].ref_line);
        (void)json_push_kv_str(&o, "enclosing", crefs[i].enclosing);
        code_push_obj(arr, &o);
    }
}

/* One droppable section: direct callees of `s`
 * (codeindex_callees_for_symbol), capped at CODE_CAPSULE_CALLEE_CAP. */
static void code_capsule_fill_callees(struct codeindex *ci,
                                      const struct ci_symbol *s,
                                      struct json_value *arr, int *n,
                                      bool *trunc)
{
    static struct ci_ref erefs[CODE_CAPSULE_CALLEE_CAP + 1];
    int want = CODE_CAPSULE_CALLEE_CAP + 1;
    int ne = codeindex_callees_for_symbol(ci, s, erefs, want);
    if (ne < 0) ne = 0;
    *trunc = ne > CODE_CAPSULE_CALLEE_CAP;
    *n = *trunc ? CODE_CAPSULE_CALLEE_CAP : ne;
    for (int i = 0; i < *n; i++) {
        struct json_value o;
        json_init(&o); json_set_object(&o);
        (void)json_push_kv_str(&o, "callee", erefs[i].callee);
        (void)json_push_kv_str(&o, "file", erefs[i].ref_file);
        (void)json_push_kv_int(&o, "line", erefs[i].ref_line);
        code_push_obj(arr, &o);
    }
}

/* One droppable section: the in-tree #include fan-out of the symbol's def
 * file (codeindex_includes_of_file), capped at CODE_CAPSULE_INC_CAP. */
static void code_capsule_fill_includes(struct codeindex *ci,
                                       const char *def_path,
                                       struct json_value *arr, int *n,
                                       bool *trunc)
{
    static char incs[CODE_CAPSULE_INC_CAP + 1][256];
    int want = CODE_CAPSULE_INC_CAP + 1;
    int ni = codeindex_includes_of_file(ci, def_path, incs, want);
    if (ni < 0) ni = 0;
    *trunc = ni > CODE_CAPSULE_INC_CAP;
    *n = *trunc ? CODE_CAPSULE_INC_CAP : ni;
    for (int i = 0; i < *n; i++)
        code_push_line(arr, incs[i]);
}

/* Measures only the droppable sections against the fixed reserve the rest of
 * the reply needs (the same budgeting shape code.group uses); true once the
 * three arrays serialize small enough to keep the whole reply under
 * ZCL_COMMAND_RESULT_BUDGET. */
static bool code_capsule_sections_fit(const struct json_value *callers,
                                      const struct json_value *callees,
                                      const struct json_value *inc)
{
    char scratch[ZCL_COMMAND_RESULT_BUDGET + 1];
    size_t used = 0;
    const struct json_value *parts[] = { callers, callees, inc };
    for (size_t p = 0; p < sizeof(parts) / sizeof(parts[0]); p++) {
        size_t n = json_write(parts[p], scratch, sizeof(scratch));
        used += (n == 0 || n >= sizeof(scratch)) ? sizeof(scratch) : n;
    }
    return used <= ZCL_COMMAND_RESULT_BUDGET - 2600;
}

/* The static evidence/unknowns scaffolding: fixed keys this leaf always
 * reports, none of them derived from the requested symbol. */
static void code_capsule_emit_static_fields(struct zcl_command_reply *reply)
{
    struct json_value evidence, empty, unknowns;
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
    json_free(&evidence);

    json_init(&empty); json_set_array(&empty);
    (void)json_push_kv(&reply->data, "struct_fields", &empty);
    (void)json_push_kv(&reply->data, "ownership_locks", &empty);
    (void)json_push_kv(&reply->data, "database_tables", &empty);
    (void)json_push_kv(&reply->data, "events", &empty);
    (void)json_push_kv(&reply->data, "blockers", &empty);
    (void)json_push_kv(&reply->data, "invariants", &empty);
    json_free(&empty);

    json_init(&unknowns); json_set_array(&unknowns);
    code_push_line(&unknowns,
                   "semantic field/ownership/lock/db/event/blocker index not built");
    code_push_line(&unknowns,
                   "definition extent and per-symbol compiler AST not indexed");
    (void)json_push_kv(&reply->data, "unknowns", &unknowns);
    json_free(&unknowns);
}

/* likely_change_files: the def site, plus the decl site when it differs. */
static void code_capsule_emit_likely_change_files(
    struct zcl_command_reply *reply, const char *def_path,
    const char *decl_path)
{
    struct json_value likely;
    json_init(&likely); json_set_array(&likely);
    if (def_path[0]) {
        struct json_value item;
        json_init(&item); json_set_object(&item);
        (void)json_push_kv_str(&item, "path", def_path);
        (void)json_push_kv_str(&item, "evidence",
                               "heuristic_primary_edit_site");
        code_push_obj(&likely, &item);
    }
    if (decl_path[0] && strcmp(decl_path, def_path) != 0) {
        struct json_value item;
        json_init(&item); json_set_object(&item);
        (void)json_push_kv_str(&item, "path", decl_path);
        (void)json_push_kv_str(&item, "evidence",
                               "heuristic_if_contract_changes");
        code_push_obj(&likely, &item);
    }
    (void)json_push_kv(&reply->data, "likely_change_files", &likely);
    json_free(&likely);
}

/* The three droppable sections' arrays, counts, truncation flags, and
 * "still wanted" flags, bundled so the self-shrinking assembly below can
 * pass them around as one unit instead of a dozen separate out-params. */
struct code_capsule_sections {
    struct json_value callers, callees, includes;
    int n_callers, n_callees, n_inc;
    bool callers_trunc, callees_trunc, inc_trunc;
    bool want_includes, want_callees, want_callers;
};

/* Self-shrinking assembly: build callers/callees/includes at full cap,
 * measure their serialized size, and — only if the reply would overflow —
 * drop ONE section at a time (includes, then callees, then callers) and
 * rebuild, until it fits or nothing droppable remains. */
static void code_capsule_assemble_sections(struct codeindex *ci,
                                           const struct ci_symbol *s,
                                           const char *def_path,
                                           struct code_capsule_sections *sec)
{
    sec->want_includes = sec->want_callees = sec->want_callers = true;
    json_init(&sec->callers);  json_set_array(&sec->callers);
    json_init(&sec->callees);  json_set_array(&sec->callees);
    json_init(&sec->includes); json_set_array(&sec->includes);

    for (;;) {
        json_free(&sec->callers);
        json_init(&sec->callers);  json_set_array(&sec->callers);
        json_free(&sec->callees);
        json_init(&sec->callees);  json_set_array(&sec->callees);
        json_free(&sec->includes);
        json_init(&sec->includes); json_set_array(&sec->includes);
        sec->n_callers = sec->n_callees = sec->n_inc = 0;
        sec->callers_trunc = sec->callees_trunc = sec->inc_trunc = false;

        if (sec->want_callers)
            code_capsule_fill_callers(ci, s, &sec->callers, &sec->n_callers,
                                      &sec->callers_trunc);
        if (sec->want_callees)
            code_capsule_fill_callees(ci, s, &sec->callees, &sec->n_callees,
                                      &sec->callees_trunc);
        if (sec->want_includes && def_path[0])
            code_capsule_fill_includes(ci, def_path, &sec->includes,
                                       &sec->n_inc, &sec->inc_trunc);

        if (code_capsule_sections_fit(&sec->callers, &sec->callees,
                                      &sec->includes))
            return;
        if (sec->want_includes) { sec->want_includes = false; continue; }
        if (sec->want_callees)  { sec->want_callees = false; continue; }
        if (sec->want_callers)  { sec->want_callers = false; continue; }
        return;   /* nothing left to drop */
    }
}

/* dropped_sections: names which droppable section(s) the self-shrinking
 * assembly cut to fit the reply budget. */
static void code_capsule_emit_dropped_sections(
    struct zcl_command_reply *reply, bool want_includes, bool want_callees,
    bool want_callers)
{
    struct json_value dropped;
    json_init(&dropped); json_set_array(&dropped);
    if (!want_includes) code_push_line(&dropped, "includes");
    if (!want_callees)  code_push_line(&dropped, "callees");
    if (!want_callers)  code_push_line(&dropped, "callers");
    (void)json_push_kv(&reply->data, "dropped_sections", &dropped);
    json_free(&dropped);
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
/* code.capsule's identity fields: the resolved symbol's name/id/kind/
 * location/signature/group/shape, plus other_defs and commands. */
static void code_capsule_emit_identity(
    struct zcl_command_reply *reply, const char *query, bool by_id,
    const struct ci_symbol *s, const char *id, const char *sig,
    const char *kind, const char *shape, const struct json_value *others,
    int nother, const struct json_value *cmds, int ncmd)
{
    (void)json_push_kv_bool(&reply->data, "found", true);
    (void)json_push_kv_str(&reply->data, "query", query);
    (void)json_push_kv_str(&reply->data, "resolution",
                           by_id ? "exact_stable_id" : "legacy_name_primary");
    (void)json_push_kv_str(&reply->data, "name", s->name);
    (void)json_push_kv_str(&reply->data, "id", id);
    (void)json_push_kv_str(&reply->data, "kind", kind);
    (void)json_push_kv_str(&reply->data, "def_path", s->def_path);
    (void)json_push_kv_int(&reply->data, "def_line", s->def_line);
    (void)json_push_kv_str(&reply->data, "decl_path", s->decl_path);
    (void)json_push_kv_int(&reply->data, "decl_line", s->decl_line);
    (void)json_push_kv_str(&reply->data, "signature", sig);
    (void)json_push_kv_str(&reply->data, "group", s->group);
    (void)json_push_kv_str(&reply->data, "shape", shape);
    if (s->partial)
        (void)json_push_kv_bool(&reply->data, "partial", true);

    (void)json_push_kv(&reply->data, "other_defs", others);
    (void)json_push_kv_int(&reply->data, "other_defs_count", nother);

    (void)json_push_kv(&reply->data, "commands", cmds);
    (void)json_push_kv_int(&reply->data, "command_count", ncmd);
}

/* code.capsule's callers/callees/includes sections, plus the dropped-section
 * flags for whichever of the three were shrunk to fit the reply budget. */
static void code_capsule_emit_call_sections(
    struct zcl_command_reply *reply, const struct code_capsule_sections *sec)
{
    (void)json_push_kv(&reply->data, "callers", &sec->callers);
    (void)json_push_kv_int(&reply->data, "caller_count", sec->n_callers);
    (void)json_push_kv_bool(&reply->data, "callers_truncated",
                            sec->callers_trunc);

    (void)json_push_kv(&reply->data, "callees", &sec->callees);
    (void)json_push_kv_int(&reply->data, "callee_count", sec->n_callees);
    (void)json_push_kv_bool(&reply->data, "callees_truncated",
                            sec->callees_trunc);

    (void)json_push_kv(&reply->data, "includes", &sec->includes);
    (void)json_push_kv_int(&reply->data, "include_count", sec->n_inc);
    (void)json_push_kv_bool(&reply->data, "includes_truncated",
                            sec->inc_trunc);

    code_capsule_emit_dropped_sections(reply, sec->want_includes,
                                       sec->want_callees, sec->want_callers);
}

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

    char shape[64];
    code_capsule_derive_shape(s.group, shape);

    struct json_value others;
    json_init(&others); json_set_array(&others);
    int nother = code_capsule_other_defs(ci, &s, &others);

    /* commands[]: exact handler-name join against the .def-derived dispatch
     * index (never dropped; capped and small by construction). */
    const char *cmd_paths[CODE_COMMAND_CAP];
    int ncmd = code_commands_for_symbol(s.name, cmd_paths, CODE_COMMAND_CAP);
    struct json_value cmds;
    json_init(&cmds); json_set_array(&cmds);
    for (int i = 0; i < ncmd; i++) code_push_line(&cmds, cmd_paths[i]);

    struct code_capsule_sections sec;
    code_capsule_assemble_sections(ci, &s, def_path, &sec);

    code_capsule_emit_identity(reply, query, by_id, &s, id, sig, kind, shape,
                               &others, nother, &cmds, ncmd);

    code_capsule_emit_static_fields(reply);
    code_capsule_emit_likely_change_files(reply, def_path, s.decl_path);

    code_capsule_emit_call_sections(reply, &sec);

    /* test route: the same resolver code.tests/code.room use. */
    bool crisk = false;
    char route_storage[ZCL_AGENT_IMPACT_GROUP_MAX];
    const char *route =
        code_emit_route(reply, def_path, &crisk, route_storage);

    char summary[300];
    (void)snprintf(summary, sizeof(summary),
                   "%s [%s] %s:%d — %d caller(s), %d callee(s), %d command(s), "
                   "tests→`%s`%s", s.name, kind, def_path,
                   s.def_path[0] ? s.def_line : s.decl_line, sec.n_callers,
                   sec.n_callees, ncmd, route,
                   (!sec.want_includes || !sec.want_callees ||
                    !sec.want_callers)
                       ? " (shrunk to fit budget)" : "");
    (void)json_push_kv_str(&reply->data, "summary", summary);

    json_free(&others); json_free(&cmds);
    json_free(&sec.callers); json_free(&sec.callees); json_free(&sec.includes);
    codeindex_close(ci);
}
