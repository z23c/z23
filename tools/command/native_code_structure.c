/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The code.group, code.file, code.sym, code.refs, code.find, code.impact,
 * code.merkle, code.territory and code.kpi handlers: the `code` command
 * family's structural and scorecard leaves. Split out of
 * native_code_command.c (the family's shared helpers, routing link, and
 * dispatch join) so each sibling file stays under the single-family line
 * ceiling; see native_code_priv.h for the interface this file shares with
 * its siblings.
 */

#include "command/native_command.h"
#include "command/native_code_priv.h"

#include "codeindex/codeindex.h"
#include "codeindex/codeindex_merkle.h"
#include "config/command_catalog.h"
#include "config/command_handler_index.h"
#include "controllers/agent_impact_rules.h"
#include "base/hex.h"
#include "json/json.h"
#include "kpi/kpi.h"
#include "territory/territory.h"
#include "test_group_catalog.h"

#include <stdio.h>
#include <string.h>

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

const char *code_territory_entry_at(size_t index, void *user)
{
    (void)user;
    return zcl_test_group_catalog_at(index);
}

/* The router port: the SAME shared-rule resolver behind `code tests`. A
 * consensus surface is reported as routed to consensus_parity even when no
 * path rule matched, because that is what the router actually returns; a path
 * that matches no rule at all returns zero, which is the "no test group at
 * all" signal the scorecard's weak section reports. */
size_t code_territory_route(const char *path,
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

