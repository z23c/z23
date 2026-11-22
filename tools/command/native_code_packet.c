/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The code.packet handler: ONE call that returns the work packet a builder
 * needs, composed from the index-backed code.* readers instead of a scout
 * pass. For each symbol it returns the verbatim definition (head and tail
 * elided past max_lines); for every touched file the covering test groups
 * (the code.tests resolver), the blast radius (the code.impact closure), the
 * module_capabilities and remote-class rows, the exact gate lines, and routed
 * failures from the latest test artifact. That artifact has no commit identity,
 * so its evidence is always labeled revision-unbound. The same packet is
 * rendered as markdown in PACKET_TEMPLATE field order.
 *
 * It opens the index READ-ONLY and refuses a stale or absent one, so it never
 * rebuilds, writes, locks or spawns; both generation roots come from that one
 * open and are printed beside the checkout HEAD. Every input is bounded, every
 * refusal is typed, and a thing the tree cannot show is reported as absent
 * rather than guessed. See native_code_packet_priv.h for the unit layout. */

#include "command/native_code_packet_priv.h"
#include "command/native_command.h"

#include "base/safe_alloc.h"
#include "codeindex/codeindex.h"
#include "codeindex/codeindex_focus.h"
#include "controllers/agent_impact_rules.h"
#include "kernel/command_registry.h"
#include "test_group_catalog.h"
#include "test_group_host_need.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PK_REPLY_BUDGET ((size_t)65536u)
#define PK_LOOKUP_CAP 64
#define PK_DECL_CAP 4

struct pk_declaration {
    char file[256];
    int line;
};

struct pk_choice {
    struct ci_symbol symbol;
    const char *status;
    int body_end;
    struct pk_declaration declarations[PK_DECL_CAP];
    int ndecl;
    const char *declaration_status;
    bool definition_count_known;
    int definition_count, exact_count;
    char definition_at[300];
};

/* One assembly of the packet; rebuilt (cache kept) when the reply must shrink. */
struct pk_run {
    struct pk_ctx ctx;
    struct pk_input in;
    struct pk_facts f;
    char touch[PK_TOUCH_MAX][256];
    bool touch_from_input[PK_TOUCH_MAX];
    int ntouch;
    unsigned traps;
    struct pk_choice choice[PK_SYMBOLS_MAX];
    bool neighborhoods;
    bool declarations;
    bool declaration_output_failed;
    char impact_error_path[256];
    struct agent_impact_acc *route_accs;
    const char *routes[PK_TOUCH_MAX];
    bool route_risks[PK_TOUCH_MAX];
    struct specialist_focus_evidence failure;
    bool failure_unavailable;
    struct json_value excerpts, files, tests, pattern, impact, caps, auth,
        claims;
    struct pk_sb map, exc, pat, keep, authority, notes;
};

static void pk_refuse(struct zcl_command_reply *reply, const char *code,
                      const char *message, const char *evidence)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, "normalize", false,
                           false, message, evidence);
}

/* ── input ──────────────────────────────────────────────────────────────── */

static bool pk_id_char(char c, bool first)
{
    if (c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))
        return true;
    return !first && c >= '0' && c <= '9';
}

static bool pk_ident_ok(const char *s)
{
    size_t n = strlen(s);
    if (n == 0 || n >= 128 || !pk_id_char(s[0], true))
        return false;
    for (size_t i = 1; i < n; i++)
        if (!pk_id_char(s[i], false))
            return false;
    return true;
}

/* One path segment: non-empty and neither "." nor "..". */
static bool pk_segment_ok(const char *start, size_t seg)
{
    if (seg == 0)
        return false;
    if (seg == 1 && start[0] == '.')
        return false;
    return !(seg == 2 && start[0] == '.' && start[1] == '.');
}

/* A repo-relative path that cannot leave the corpus: no leading slash, no
 * backslash, no control byte, and no empty, "." or ".." segment. */
static bool pk_path_ok(const char *s)
{
    size_t n = strlen(s);
    if (n == 0 || n >= 256 || s[0] == '/')
        return false;
    size_t seg = 0;
    for (size_t i = 0; i <= n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '\\' || (c < 0x20 && c != 0))
            return false;
        if (c != '/' && c != 0) {
            seg++;
            continue;
        }
        if (!pk_segment_ok(s + i - seg, seg))
            return false;
        seg = 0;
    }
    return true;
}


/* Parse one string-array key into fixed rows. Duplicates collapse. */
static bool pk_parse_list(const struct zcl_command_request *request,
                          struct zcl_command_reply *reply, const char *key,
                          int max, size_t stride, char *rows, int *count,
                          bool (*valid)(const char *), const char *code_many,
                          const char *code_bad)
{
    const struct json_value *arr = json_get(request->input, key);
    *count = 0;
    if (!arr)
        return true;
    if (arr->type != JSON_ARR || arr->num_children > (size_t)max) {
        pk_refuse(reply, arr->type == JSON_ARR ? code_many : code_bad,
                  "list input exceeds its bound or is not an array of strings",
                  key);
        return false;
    }
    for (size_t i = 0; i < arr->num_children; i++) {
        const char *s = json_get_str(&arr->children[i]);
        if (!s || !valid(s) || strlen(s) >= stride) {
            pk_refuse(reply, code_bad,
                      "entry is not a valid value for this key", key);
            return false;
        }
        {
            bool dup = false;
            for (int k = 0; k < *count && !dup; k++)
                dup = strcmp(rows + (size_t)k * stride, s) == 0;
            if (!dup)
                (void)snprintf(rows + (size_t)(*count)++ * stride, stride,
                               "%s", s);
        }
    }
    return true;
}

static bool pk_parse_bounds(const struct zcl_command_request *request,
                            struct zcl_command_reply *reply,
                            struct pk_input *in)
{
    in->goal = code_str(request, "goal");
    if (!in->goal) {
        pk_refuse(reply, "MISSING_GOAL",
                  "code packet requires a goal (one sentence)", "goal");
        return false;
    }
    if (strlen(in->goal) > PK_GOAL_MAX) {
        pk_refuse(reply, "GOAL_TOO_LONG", "goal is longer than 512 bytes",
                  "goal");
        return false;
    }
    in->change = code_str(request, "change");
    if (in->change && strlen(in->change) > PK_CHANGE_MAX) {
        pk_refuse(reply, "CHANGE_TOO_LONG", "change is longer than 1024 bytes",
                  "change");
        return false;
    }
    in->max_lines = PK_LINES_DEFAULT;
    const struct json_value *ml = json_get(request->input, "max_lines");
    if (ml && (ml->type != JSON_INT || json_get_int(ml) < PK_LINES_MIN ||
               json_get_int(ml) > PK_LINES_MAX)) {
        pk_refuse(reply, "MAX_LINES_RANGE",
                  "max_lines must be an integer from 20 to 120", "max_lines");
        return false;
    }
    if (ml)
        in->max_lines = (int)json_get_int(ml);
    return true;
}

static bool pk_parse_input(const struct zcl_command_request *request,
                           struct zcl_command_reply *reply,
                           struct pk_input *in)
{
    memset(in, 0, sizeof(*in));
    if (!pk_parse_bounds(request, reply, in))
        return false;
    if (!pk_parse_list(request, reply, "symbols", PK_SYMBOLS_MAX,
                       sizeof(in->symbols[0]), &in->symbols[0][0], &in->nsym,
                       pk_ident_ok, "TOO_MANY_SYMBOLS", "BAD_SYMBOL"))
        return false;
    if (!pk_parse_list(request, reply, "files", PK_FILES_MAX,
                       sizeof(in->files[0]), &in->files[0][0], &in->nfile,
                       pk_path_ok, "TOO_MANY_FILES", "BAD_PATH"))
        return false;
    if (in->nsym == 0 && in->nfile == 0) {
        pk_refuse(reply, "EMPTY_PACKET",
                  "give at least one symbol or one file", "symbols,files");
        return false;
    }
    return true;
}

/* ── small JSON helpers ─────────────────────────────────────────────────── */

static void pk_obj(struct json_value *o)
{
    json_init(o);
    json_set_object(o);
}

static void pk_push(struct json_value *arr, struct json_value *o)
{
    code_push_obj(arr, o);
}

static const char *pk_kind_name(char k)
{
    switch (k) {
    case 'T': return "function";
    case 't': return "static function";
    case 'S': return "struct";
    case 'Y': return "typedef";
    case 'E': return "enum";
    case 'M': return "macro";
    case 'D': return "data";
    default: return "symbol";
    }
}

/* Record one checked claim in JSON and as a Packer-notes line. */
static void pk_claim(struct pk_run *run, bool value, const char *at,
                     const char *fmt, ...) __attribute__((format(printf, 4, 5)));
static void pk_claim(struct pk_run *run, bool value, const char *at,
                     const char *fmt, ...)
{
    char text[320];
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(text, sizeof(text), fmt, ap);
    va_end(ap);
    struct json_value o;
    pk_obj(&o);
    (void)json_push_kv_str(&o, "claim", text);
    (void)json_push_kv_bool(&o, "value", value);
    (void)json_push_kv_str(&o, "at", at);
    pk_push(&run->claims, &o);
    pk_sb_add(&run->notes, "  %-5s %s  [%s]\n", value ? "TRUE" : "FALSE", text,
              at);
}

static void pk_touch_add(struct pk_run *run, const char *path, bool from_input)
{
    for (int i = 0; i < run->ntouch; i++) {
        if (strcmp(run->touch[i], path) == 0) {
            run->touch_from_input[i] = run->touch_from_input[i] || from_input;
            return;
        }
    }
    if (run->ntouch >= PK_TOUCH_MAX)
        return;
    (void)snprintf(run->touch[run->ntouch], sizeof(run->touch[0]), "%s", path);
    run->touch_from_input[run->ntouch++] = from_input;
}

/* ── excerpts ───────────────────────────────────────────────────────────── */

static const char *pk_status_note(const char *status)
{
    if (strcmp(status, "declaration_only") == 0)
        return "  (declaration only: no definition indexed)";
    if (strcmp(status, "no_body") == 0)
        return "  (no closing brace found: the index may be stale)";
    if (strcmp(status, "ok") == 0)
        return "";
    return "  (source could not be read)";
}

static void pk_md_excerpt(struct pk_sb *sb, const struct pk_excerpt *ex,
                          const char *label)
{
    const char *fence = ex->text.p && strstr(ex->text.p, "```") ? "~~~~~" : "```";
    pk_sb_add(sb, "### %s:%d-%d  %s%s", ex->file, ex->first, ex->last, label,
              pk_status_note(ex->status));
    if (ex->elide_from > 0)
        pk_sb_add(sb, "  [L%d-L%d elided]", ex->elide_from, ex->elide_to);
    pk_sb_add(sb, "\n%sc\n", fence);
    pk_sb_raw(sb, ex->text.p ? ex->text.p : "", ex->text.len);
    pk_sb_add(sb, "%s\n\n", fence);
}

static bool pk_json_declarations(struct json_value *out, const struct pk_choice *choice,
                                  bool show)
{
    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    const char *status = choice->declaration_status;
    if (!show && choice->ndecl) status = "omitted_reply_budget";
    bool ok = true;
    for (int i = 0; ok && show && i < choice->ndecl; i++) {
        struct json_value row;
        pk_obj(&row);
        ok = json_push_kv_str(&row, "file", choice->declarations[i].file) &&
             json_push_kv_int(&row, "line", choice->declarations[i].line) &&
             json_push_back(&rows, &row);
        json_free(&row);
    }
    ok = ok && json_push_kv_str(out, "declaration_candidates_status", status) &&
         json_push_kv_str(out, "declaration_candidates_basis", "same_name_only; linkage_not_proven") &&
         json_push_kv(out, "declaration_candidates", &rows);
    json_free(&rows);
    return ok;
}

static bool pk_json_excerpt(struct json_value *arr, const struct pk_excerpt *ex,
                            const struct ci_symbol *s, bool neighborhood,
                            const char *shared_with, const struct pk_choice *choice,
                            bool declarations)
{
    struct json_value o;
    pk_obj(&o);
    (void)json_push_kv_str(&o, "symbol", ex->symbol);
    (void)json_push_kv_str(&o, "status", ex->status);
    if (s) {
        char id[400];
        id[0] = '\0';
        (void)codeindex_symbol_record_id(s, id, sizeof(id));
        char sig[260];
        code_trunc(sig, sizeof(sig), s->signature, 240);
        (void)json_push_kv_str(&o, "kind", pk_kind_name(s->kind));
        (void)json_push_kv_str(&o, "id", id);
        (void)json_push_kv_str(&o, "signature", sig);
    }
    if (ex->text.len > 0) {
        (void)json_push_kv_str(&o, "file", ex->file);
        (void)json_push_kv_int(&o, "site_line", ex->site_line);
        (void)json_push_kv_int(&o, "end_line", ex->end_line);
        (void)json_push_kv_int(&o, "first_line", ex->first);
        (void)json_push_kv_int(&o, "last_line", ex->last);
        (void)json_push_kv_int(&o, "shown_lines", ex->shown);
        (void)json_push_kv_int(&o, "elided_from", ex->elide_from);
        (void)json_push_kv_int(&o, "elided_to", ex->elide_to);
    }
    if (neighborhood) (void)json_push_kv_str(&o, "context", "same_file_neighborhood");
    if (shared_with) (void)json_push_kv_str(&o, "shared_with", shared_with);
    if (!pk_json_declarations(&o, choice, declarations)) {
        json_free(&o);
        return false;
    }
    pk_push(arr, &o);
    return true;
}

/* The claim uses the same complete exact enumeration as symbol selection. */
static void pk_claim_defined_once(struct pk_run *run, const char *name,
                                  const struct pk_choice *choice)
{
    if (!choice->definition_count_known) {
        pk_claim(run, false, "exact lookup incomplete; uniqueness unproven",
                 "global definition count for %s is known", name);
        return;
    }
    const char *at = choice->definition_at;
    if (!choice->definition_count && !choice->exact_count)
        at = "not in the code index";
    else if (!choice->definition_count && !at[0])
        at = "declaration only; no indexed definition";
    pk_claim(run, choice->definition_count == 1,
             at, "symbol %s is defined once", name);
}

struct pk_match {
    struct ci_symbol symbol;
    int count;
    bool definition;
};

static void pk_match_add(struct pk_match *match, const struct ci_symbol *symbol)
{
    bool definition = symbol->def_path[0] != '\0';
    if (match->definition && !definition) return;
    if (definition && !match->definition) match->count = 0;
    match->definition = definition;
    if (!match->count) {
        match->symbol = *symbol;
        match->count = 1;
        return;
    }
    const struct ci_symbol *old = &match->symbol;
    if (!strcmp(old->def_path, symbol->def_path) && old->def_line == symbol->def_line &&
        (definition || (!strcmp(old->decl_path, symbol->decl_path) &&
                        old->decl_line == symbol->decl_line))) return;
    match->count++;
}

static const char *pk_scoped_matches(struct pk_run *run, const char *name, struct pk_match *match)
{
    static struct ci_symbol hits[PK_LOOKUP_CAP];
    for (int f = 0; f < run->in.nfile; f++) {
        int n = codeindex_symbols_in_file(run->ctx.ci, run->in.files[f], hits, PK_LOOKUP_CAP);
        if (n < 0) return "lookup_failed";
        if (n == PK_LOOKUP_CAP) return "lookup_capped";
        for (int i = 0; i < n; i++) {
            const struct ci_symbol *s = &hits[i];
            const char *site = s->def_path[0] ? s->def_path : s->decl_path;
            if (!strcmp(s->name, name) && !strcmp(site, run->in.files[f])) pk_match_add(match, s);
        }
    }
    return NULL;
}

static bool pk_file_supplied(const struct pk_run *run, const char *file);

static const char *pk_match_result(const struct pk_match *match, struct ci_symbol *symbol,
                                  const char *empty)
{
    if (!match->count) return empty;
    if (match->count != 1) return "ambiguous";
    *symbol = match->symbol;
    return "ok";
}

/* A complete name result already proves which exact candidates can occur in
 * supplied files. Independent large impact files must not cap this lookup. */
static const char *pk_complete_matches(struct pk_run *run, const char *name,
    const struct ci_symbol *hits, int count, struct ci_symbol *symbol)
{
    struct pk_match global = {0}, scoped = {0};
    for (int i = 0; i < count; i++) {
        const struct ci_symbol *s = &hits[i];
        if (strcmp(s->name, name)) continue;
        pk_match_add(&global, s);
        const char *site = s->def_path[0] ? s->def_path : s->decl_path;
        if (pk_file_supplied(run, site)) pk_match_add(&scoped, s);
    }
    return pk_match_result(scoped.count ? &scoped : &global, symbol, "not_found");
}

/* Keep the first four distinct sites in byte-stable path/line order. These
 * are name matches, never an assertion that C linkage joins the records. */
static void pk_declaration_add(struct pk_choice *choice, const struct ci_symbol *s)
{
    int at = 0;
    while (at < choice->ndecl) {
        const struct pk_declaration *d = &choice->declarations[at];
        int cmp = strcmp(d->file, s->decl_path);
        if (!cmp && d->line == s->decl_line) return;
        if (cmp > 0 || (!cmp && d->line > s->decl_line)) break;
        at++;
    }
    if (choice->ndecl == PK_DECL_CAP) choice->declaration_status = "candidate_cap";
    else choice->ndecl++;
    for (int i = choice->ndecl - 1; i > at; i--)
        choice->declarations[i] = choice->declarations[i - 1];
    if (at < PK_DECL_CAP) {
        struct pk_declaration *d = &choice->declarations[at];
        (void)snprintf(d->file, sizeof(d->file), "%s", s->decl_path);
        d->line = s->decl_line;
    }
}

static void pk_declarations_collect(struct pk_choice *choice, const char *name,
                                     const struct ci_symbol *hits, int count)
{
    choice->declaration_status = "complete";
    if (strcmp(choice->status, "ok")) {
        choice->declaration_status = "unresolved";
        return;
    }
    if (choice->symbol.kind == 't') {
        choice->declaration_status = "not_applicable_static";
        return;
    }
    for (int i = 0; i < count; i++) {
        const struct ci_symbol *s = &hits[i];
        if (!strcmp(s->name, name) && s->kind == choice->symbol.kind &&
            s->decl_path[0] && s->decl_line > 0)
            pk_declaration_add(choice, s);
    }
}

static void pk_definition_evidence(struct pk_choice *choice,
                                   const struct ci_symbol *hits, int count)
{
    choice->definition_count_known = true;
    choice->exact_count = count;
    const struct ci_symbol *first = NULL;
    for (int i = 0; i < count; i++) {
        if (!hits[i].def_path[0]) {
            if (!choice->definition_at[0] && hits[i].decl_path[0])
                (void)snprintf(choice->definition_at, sizeof(choice->definition_at),
                               "declaration only: %s:%d", hits[i].decl_path, hits[i].decl_line);
            continue;
        }
        if (!first) {
            first = &hits[i];
            choice->definition_count = 1;
            (void)snprintf(choice->definition_at, sizeof(choice->definition_at),
                           "%s:%d", hits[i].def_path, hits[i].def_line);
        } else if (first->def_line != hits[i].def_line ||
                   strcmp(first->def_path, hits[i].def_path) != 0) {
            choice->definition_count = 2;
            break;
        }
    }
}

static const char *pk_resolve_symbol(struct pk_run *run, const char *name, struct pk_choice *choice)
{
    static struct ci_symbol hits[PK_LOOKUP_CAP];
    int n = 0;
    enum codeindex_exact_status exact =
        codeindex_find_exact_checked(run->ctx.ci, name, hits, PK_LOOKUP_CAP, &n);
    choice->declaration_status = "lookup_failed";
    if (exact == CODEINDEX_EXACT_ERROR || exact == CODEINDEX_EXACT_CORRUPT)
        return "lookup_failed";
    if (exact == CODEINDEX_EXACT_COMPLETE) {
        pk_definition_evidence(choice, hits, n);
        choice->status = pk_complete_matches(run, name, hits, n, &choice->symbol);
        pk_declarations_collect(choice, name, hits, n);
        return choice->status;
    }
    choice->declaration_status = "lookup_capped";
    struct pk_match match = {0};
    const char *status = pk_scoped_matches(run, name, &match);
    if (status) return status;
    return pk_match_result(&match, &choice->symbol, "lookup_capped");
}

static void pk_prepare_symbols(struct pk_run *run)
{
    for (int i = 0; i < run->in.nsym; i++) {
        struct pk_choice *choice = &run->choice[i];
        memset(choice, 0, sizeof(*choice));
        choice->status = pk_resolve_symbol(run, run->in.symbols[i], choice);
        if (strcmp(choice->status, "ok")) continue;
        struct pk_excerpt ex;
        pk_excerpt_symbol(&run->ctx, &choice->symbol, 0, run->ctx.max_lines, &ex);
        if (ex.text.len) choice->body_end = ex.end_line;
        pk_excerpt_free(&ex);
    }
}

static bool pk_file_supplied(const struct pk_run *run, const char *file)
{
    for (int i = 0; i < run->in.nfile; i++)
        if (!strcmp(run->in.files[i], file)) return true;
    return false;
}

static void pk_file_span(const struct pk_run *run, int index, int *first, int *last, int *shared)
{
    const char *file = run->choice[index].symbol.def_path;
    *first = run->choice[index].symbol.def_line;
    *last = run->choice[index].body_end;
    *shared = -1;
    for (int i = 0; i < run->in.nsym; i++) {
        const struct pk_choice *other = &run->choice[i];
        if (strcmp(other->status, "ok") || strcmp(file, other->symbol.def_path)) continue;
        if (other->symbol.def_line < *first) *first = other->symbol.def_line;
        if (other->body_end > *last) *last = other->body_end;
        if (i < index && *shared < 0) *shared = i;
    }
}

static bool pk_symbol_excerpt(struct pk_run *run, int index, struct pk_excerpt *ex, int *shared)
{
    const struct pk_choice *choice = &run->choice[index];
    const struct ci_symbol *s = &choice->symbol;
    *shared = -1;
    bool supplied = s->def_path[0] && pk_file_supplied(run, s->def_path);
    int first = 0, last = 0;
    if (supplied) pk_file_span(run, index, &first, &last, shared);
    bool neighborhood = run->neighborhoods && supplied && choice->body_end >= s->def_line &&
        last - first + 1 <= run->ctx.max_lines;
    if (neighborhood) pk_excerpt_neighborhood(&run->ctx, s, first, last, run->ctx.max_lines, ex);
    else {
        *shared = -1;
        pk_excerpt_symbol(&run->ctx, s, supplied ? 0 : PK_CONTEXT_LINES, run->ctx.max_lines, ex);
    }
    return neighborhood;
}

static void pk_md_declarations(struct pk_run *run, const char *name,
                                 const struct pk_choice *choice)
{
    if (!run->declarations || !choice->ndecl) return;
    pk_sb_add(&run->exc, "  - %s same-name declaration candidates; linkage not proven (%s):\n",
              name, choice->declaration_status);
    for (int i = 0; i < choice->ndecl; i++)
        pk_sb_add(&run->exc, "    - %s:%d\n", choice->declarations[i].file,
                  choice->declarations[i].line);
}

static void pk_do_symbol(struct pk_run *run, int index)
{
    const char *name = run->in.symbols[index];
    const struct pk_choice *choice = &run->choice[index];
    struct ci_symbol s = choice->symbol;
    bool found = !strcmp(choice->status, "ok");
    struct pk_excerpt ex;
    int shared = -1;
    bool neighborhood = false;
    if (found) {
        neighborhood = pk_symbol_excerpt(run, index, &ex, &shared);
    } else {
        memset(&ex, 0, sizeof(ex));
        (void)snprintf(ex.symbol, sizeof(ex.symbol), "%s", name);
        ex.status = choice->status;
    }
    if (!pk_json_excerpt(&run->excerpts, &ex, found ? &s : NULL, neighborhood,
                    shared >= 0 ? run->in.symbols[shared] : NULL, choice, run->declarations))
        run->declaration_output_failed = true;
    pk_md_declarations(run, name, choice);
    if (found)
        pk_touch_add(run, s.def_path[0] ? s.def_path : s.decl_path, false);
    if (ex.text.len > 0 && shared < 0) {
        char label[200];
        (void)snprintf(label, sizeof(label), "%s (%s)", name,
                       neighborhood ? "same-file context; no binding inferred" : pk_kind_name(ex.kind));
        pk_md_excerpt(&run->exc, &ex, label);
        run->f.excerpt_lines += ex.shown;
        if (ex.text.p && strstr(ex.text.p, "#if"))
            run->traps |= PK_TRAP_ARM;
    } else if (!ex.text.len) {
        pk_sb_add(&run->exc, "### %s  NOT AVAILABLE: %s (try `code find %s`)\n\n",
                  name, ex.status, name);
    }
    pk_claim_defined_once(run, name, choice);
    pk_excerpt_free(&ex);
}

/* ── per-file sections ──────────────────────────────────────────────────── */

static void pk_do_file_map(struct pk_run *run, const char *path, bool from_input)
{
    struct ci_file cf;
    bool found = false;
    (void)codeindex_file(run->ctx.ci, path, &cf, &found);
    struct json_value o;
    pk_obj(&o);
    (void)json_push_kv_str(&o, "path", path);
    (void)json_push_kv_bool(&o, "indexed", found);
    (void)json_push_kv_bool(&o, "given", from_input);
    if (!found) {
        pk_sb_add(&run->map,
                  "FILE %s  NOT INDEXED (a new file, or outside the code "
                  "corpus): no excerpt and no impact\n", path);
        pk_push(&run->files, &o);
        return;
    }
    static struct ci_symbol syms[64];
    int total = -1;
    int ns = codeindex_symbols_in_file_total(run->ctx.ci, path, syms, 64, &total);
    if (ns < 0) ns = 0;
    char purpose[200];
    code_trunc(purpose, sizeof(purpose), cf.purpose, 180);
    (void)json_push_kv_str(&o, "group", cf.group);
    (void)json_push_kv_str(&o, "purpose", purpose);
    if (total >= 0) (void)json_push_kv_int(&o, "symbols_total", total);
    else (void)json_push_kv_str(&o, "symbols_status", "unavailable");
    pk_sb_add(&run->map, "FILE %s  [%s]  %s\n  symbols:", path, cf.group,
              purpose);
    if (total < 0) pk_sb_add(&run->map, " unavailable");
    int shown = 0;
    for (int pass = 0; pass < 2; pass++) {
        for (int i = 0; i < ns && shown < PK_FILE_SYMS; i++) {
            if ((syms[i].kind == 'M') != (pass == 1))
                continue;
            pk_sb_add(&run->map, " %c:%s@%d", syms[i].kind, syms[i].name,
                      syms[i].def_path[0] ? syms[i].def_line
                                          : syms[i].decl_line);
            shown++;
        }
    }
    if (total > shown)
        pk_sb_add(&run->map, " (+%d more)", total - shown);
    pk_sb_add(&run->map, "\n");
    pk_push(&run->files, &o);
}

static void pk_need_text(const char *full, char *out, size_t cap)
{
    struct zcl_test_group_host_need hn;
    if (!zcl_test_group_host_need(full, &hn)) {
        (void)snprintf(out, cap, "unresolved");
        return;
    }
    switch (hn.kind) {
    case ZCL_HOST_NEED_FILE: (void)snprintf(out, cap, "file %s", hn.value); break;
    case ZCL_HOST_NEED_ENV: (void)snprintf(out, cap, "env %s", hn.value); break;
    case ZCL_HOST_NEED_C23_TOOLCHAIN: (void)snprintf(out, cap, "c23 toolchain");
        break;
    case ZCL_HOST_NEED_BUILD:
        (void)snprintf(out, cap, "build %s -> %s", hn.target ? hn.target : "?",
                       hn.value);
        break;
    default: (void)snprintf(out, cap, "none"); break;
    }
}

static void pk_group_add(struct pk_run *run, const char *raw,
                         struct json_value *ids)
{
    char full[ZCL_TEST_GROUP_FULL_MAX];
    if (!zcl_test_group_resolve_exact(raw, full)) {
        pk_claim(run, false, "tools/dev/test_group_catalog.def",
                 "group %s resolves to one registered test group", raw);
        return;
    }
    code_push_line(ids, full);
    for (int i = 0; i < run->f.ngroup; i++)
        if (strcmp(run->f.group[i].id, full) == 0)
            return;
    if (run->f.ngroup >= PK_GROUPS_MAX)
        return;
    struct pk_group_line *g = &run->f.group[run->f.ngroup++];
    (void)snprintf(g->id, sizeof(g->id), "%s", full);
    g->catalog_line = pk_catalog_line(&run->ctx, full);
    pk_need_text(full, g->need, sizeof(g->need));
}

/* tests[]: the same resolver code.tests uses, one entry per touched file. */
static void pk_do_tests(struct pk_run *run, const char *path, int index)
{
    struct agent_impact_acc local;
    struct agent_impact_acc *acc = run->route_accs ? &run->route_accs[index] : &local;
    bool crisk = run->route_accs ? run->route_risks[index] : false;
    const char *route = run->route_accs ? run->routes[index]
        : zcl_native_code_route_at(run->ctx.root, path, acc, &crisk);
    struct json_value o, raw, ids;
    pk_obj(&o);
    json_init(&raw); json_set_array(&raw);
    json_init(&ids); json_set_array(&ids);
    size_t shown = acc->groups_len < (size_t)CODE_TESTS_CAP
                       ? acc->groups_len : (size_t)CODE_TESTS_CAP;
    for (size_t i = 0; i < shown; i++) {
        code_push_line(&raw, acc->groups[i]);
        pk_group_add(run, acc->groups[i], &ids);
    }
    pk_group_add(run, route ? route : "make_lint_gates", &ids);
    (void)json_push_kv_str(&o, "file", path);
    (void)json_push_kv_str(&o, "route", route ? route : "make_lint_gates");
    (void)json_push_kv_bool(&o, "consensus_risk", crisk);
    (void)json_push_kv_bool(&o, "matched", acc->shared_rule_hits > 0);
    (void)json_push_kv_bool(&o, "groups_lost", acc->groups_lost);
    if (acc->referrer_read_failed)
        (void)json_push_kv_bool(&o, "test_evidence_unavailable", true);
    (void)json_push_kv(&o, "test_groups", &raw);
    (void)json_push_kv(&o, "groups", &ids);
    json_free(&raw); json_free(&ids);
    pk_push(&run->tests, &o);
    if (run->f.nroute < PK_TOUCH_MAX) {
        struct pk_route_line *r = &run->f.route[run->f.nroute++];
        (void)snprintf(r->file, sizeof(r->file), "%s", path);
        (void)snprintf(r->route, sizeof(r->route), "%s",
                       route ? route : "make_lint_gates");
        r->consensus_risk = crisk;
    }
}

/* impact[]: depth-1 and full closure from codeindex_impact_closure. */
static int pk_closure(struct codeindex *ci, const char *path, int depth,
                      char (*out)[256], bool *trunc)
{
    char changed[1][256];
    memset(changed[0], 0, sizeof(changed[0]));
    (void)snprintf(changed[0], sizeof(changed[0]), "%s", path);
    return codeindex_impact_closure(ci, changed, 1, depth, out, CODE_IMPACT_CAP,
                                    trunc);
}

static int pk_others(char (*list)[256], int n, const char *self,
                     struct json_value *top)
{
    int others = 0;
    for (int i = 0; i < n; i++) {
        if (strcmp(list[i], self) == 0)
            continue;
        if (others < PK_TOP_NAMES && top)
            code_push_line(top, list[i]);
        others++;
    }
    return others;
}

static bool pk_do_impact(struct pk_run *run, const char *path)
{
    static char direct[CODE_IMPACT_CAP][256];
    static char full[CODE_IMPACT_CAP][256];
    static char incdeps[CODE_IMPACT_CAP][256];
    bool t1 = false, t2 = false;
    int n1 = pk_closure(run->ctx.ci, path, 1, direct, &t1);
    if (n1 < 0) return false;
    int n2 = pk_closure(run->ctx.ci, path, 0, full, &t2);
    if (n2 < 0) return false;
    enum codeindex_include_dim dim = CODEINDEX_INCLUDE_DIM_UNAVAILABLE;
    int ni = codeindex_reverse_includes(run->ctx.ci, path, incdeps,
                                        CODE_IMPACT_CAP, &dim);
    if (ni < 0) return false;
    struct json_value o, top;
    pk_obj(&o);
    json_init(&top); json_set_array(&top);
    int d1 = pk_others(direct, n1, path, NULL);
    int d2 = pk_others(full, n2, path, &top);
    (void)json_push_kv_str(&o, "file", path);
    (void)json_push_kv_int(&o, "direct_dependents", d1);
    (void)json_push_kv_int(&o, "transitive_dependents", d2);
    (void)json_push_kv_bool(&o, "truncated", t2);
    (void)json_push_kv(&o, "top", &top);
    (void)json_push_kv_int(&o, "include_dependents", ni);
    (void)json_push_kv_str(&o, "include_dimension", codeindex_include_dim_label(dim));
    pk_push(&run->impact, &o);
    if (d2 > run->f.max_dependents)
        run->f.max_dependents = d2;
    pk_sb_add(&run->keep, "  - Behaviour seen by dependents of %s: %d direct, "
              "%d transitive file(s)%s", path, d1, d2,
              t2 ? " (at least: the closure was capped)" : "");
    for (size_t i = 0; i < top.num_children; i++)
        pk_sb_add(&run->keep, "%s%s", i ? ", " : "; first: ",
                  json_get_str(&top.children[i]));
    pk_sb_add(&run->keep, "; %d reader(s) by #include (%s)\n", ni,
              codeindex_include_dim_label(dim));
    json_free(&top);
    return true;
}

/* The class a command resolves to. A command with no row in
 * remote_command_classes.def is REMOTE_CLASS_NEVER, and so is a row whose
 * class token is not exactly a permit: absent or unreadable never widens. */
static const char *pk_resolved_remote_class(const struct pk_row *rr)
{
    if (rr->found
        && (strcmp(rr->caps, "REMOTE_CLASS_READ_ONLY") == 0
            || strcmp(rr->caps, "REMOTE_CLASS_OWNER_CAPABILITY") == 0))
        return rr->caps;
    return "REMOTE_CLASS_NEVER";
}

static void pk_authority_commands(struct pk_run *run, const char *path)
{
    const char *cmds[CODE_COMMAND_CAP];
    int nc = code_commands_for_file(run->ctx.ci, path, cmds, CODE_COMMAND_CAP);
    for (int i = 0; i < nc; i++) {
        struct pk_row rr;
        pk_remote_class_row(&run->ctx, cmds[i], &rr);
        struct json_value o;
        pk_obj(&o);
        (void)json_push_kv_str(&o, "command", cmds[i]);
        (void)json_push_kv_str(&o, "file", path);
        (void)json_push_kv_str(&o, "remote_class",
                               pk_resolved_remote_class(&rr));
        (void)json_push_kv_int(&o, "line", rr.line);
        pk_push(&run->auth, &o);
        pk_sb_add(&run->authority, "  command %-22s remote class %s", cmds[i],
                  pk_resolved_remote_class(&rr));
        if (rr.found)
            pk_sb_add(&run->authority, "  (%s:%d)", rr.source, rr.line);
        pk_sb_add(&run->authority, "\n");
    }
}

static void pk_do_capability(struct pk_run *run, const char *path, bool indexed)
{
    struct pk_row row;
    pk_capability_row(&run->ctx, path, &row);
    struct json_value o;
    pk_obj(&o);
    (void)json_push_kv_str(&o, "file", path);
    (void)json_push_kv_bool(&o, "row", row.found);
    pk_sb_add(&run->authority, "%s\n", path);
    if (row.found) {
        (void)json_push_kv_str(&o, "capabilities", row.caps);
        (void)json_push_kv_str(&o, "note", row.note);
        (void)json_push_kv_int(&o, "line", row.line);
        pk_sb_add(&run->authority, "  module_capabilities %s  (%s:%d)%s%s\n",
                  row.caps, row.source, row.line, row.note[0] ? "  " : "",
                  row.note);
    } else {
        const char *why = indexed
            ? "none: no row, so the unit declares no reach; adding filesystem, "
              "clock, process or network reach needs one"
            : "none: a new file needs a row";
        (void)json_push_kv_str(&o, "capabilities", why);
        pk_sb_add(&run->authority, "  module_capabilities %s\n", why);
    }
    pk_push(&run->caps, &o);
    char at[160];
    (void)snprintf(at, sizeof(at), "%s:%d", row.found ? row.source : "no row",
                   row.line);
    pk_claim(run, row.found, row.found ? at : "no row in the capability defs",
             "%s has a module_capabilities row", path);
    pk_authority_commands(run, path);
}

static void pk_do_touched(struct pk_run *run, int i)
{
    const char *path = run->touch[i];
    bool given = run->touch_from_input[i];
    pk_do_file_map(run, path, given);
    struct ci_file cf;
    bool indexed = false;
    (void)codeindex_file(run->ctx.ci, path, &cf, &indexed);
    if (given)
        pk_claim(run, indexed, indexed ? "code index" : "not in the code index",
                 "file %s is in the code index", path);
    pk_do_tests(run, path, i);
    if (indexed && !pk_do_impact(run, path)) {
        (void)snprintf(run->impact_error_path, sizeof(run->impact_error_path), "%s", path);
        return;
    }
    pk_do_capability(run, path, indexed);
    if (strncmp(path, "tests/", 6) == 0) run->traps |= PK_TRAP_TESTS;
    if (strncmp(path, "tools/command/", 14) == 0) run->traps |= PK_TRAP_COMMAND;
    if (strncmp(path, "core/", 5) == 0) run->traps |= PK_TRAP_CORE;
    if (strncmp(path, "docs/", 5) == 0 ||
        (strlen(path) > 3 && strcmp(path + strlen(path) - 3, ".md") == 0))
        run->traps |= PK_TRAP_DOCS;
    if (strlen(path) > 4 && strcmp(path + strlen(path) - 4, ".def") == 0)
        run->traps |= PK_TRAP_DEF;
}

/* ── the nearest existing test case ─────────────────────────────────────── */

static bool pk_in_covering_group(const struct pk_run *run, const char *file)
{
    char want[160];
    for (int i = 0; i < run->f.ngroup; i++) {
        (void)snprintf(want, sizeof(want), "tests/harness/src/%s.c",
                       run->f.group[i].id);
        if (strcmp(want, file) == 0)
            return true;
    }
    return false;
}

static int pk_pick_test_ref(const struct pk_run *run, const struct ci_ref *refs,
                            int nr)
{
    int best = -1;
    for (int i = 0; i < nr; i++) {
        if (strncmp(refs[i].ref_file, "tests/harness/src/", 18) != 0)
            continue;
        if (pk_in_covering_group(run, refs[i].ref_file))
            return i;
        if (best < 0)
            best = i;
    }
    return best;
}

static bool pk_enclosing_symbol(struct pk_run *run, const struct ci_ref *ref,
                                struct ci_symbol *out)
{
    static struct ci_symbol hits[8];
    int nh = codeindex_find(run->ctx.ci, ref->enclosing, hits, 8);
    for (int i = 0; i < nh; i++) {
        if (strcmp(hits[i].name, ref->enclosing) == 0 &&
            strcmp(hits[i].def_path, ref->ref_file) == 0 &&
            hits[i].def_line >= 1 && hits[i].def_line <= ref->ref_line) {
            *out = hits[i];
            return true;
        }
    }
    return false;
}

static void pk_pattern_none(struct pk_run *run, const char *name, int nr)
{
    struct json_value o;
    pk_obj(&o);
    (void)json_push_kv_str(&o, "symbol", name);
    (void)json_push_kv_str(&o, "status", "none_in_index_refs");
    (void)json_push_kv_int(&o, "refs_scanned", nr);
    (void)json_push_kv_bool(&o, "scan_capped", nr >= PK_REFS_SCAN);
    pk_push(&run->pattern, &o);
    pk_sb_add(&run->pat, "PATTERN %s: no test case under tests/harness/src "
              "references it in the %d index reference(s) examined%s\n\n", name,
              nr, nr >= PK_REFS_SCAN ? " (scan capped: not proof of absence)" : "");
}

static void pk_do_pattern(struct pk_run *run, int index)
{
    const char *name = run->in.symbols[index];
    const struct pk_choice *choice = &run->choice[index];
    static struct ci_ref refs[PK_REFS_SCAN];
    int nr = 0;
    if (!strcmp(choice->status, "ok"))
        nr = codeindex_callers_for_symbol(run->ctx.ci, &choice->symbol, refs, PK_REFS_SCAN);
    if (nr < 0) nr = 0;
    int best = pk_pick_test_ref(run, refs, nr);
    if (best < 0) {
        pk_pattern_none(run, name, nr);
        return;
    }
    struct ci_symbol enc;
    struct pk_excerpt ex;
    bool exact = pk_enclosing_symbol(run, &refs[best], &enc);
    if (exact)
        pk_excerpt_symbol(&run->ctx, &enc, 0, run->ctx.max_lines, &ex);
    else
        pk_excerpt_site(&run->ctx, refs[best].ref_file, refs[best].ref_line,
                        PK_CONTEXT_LINES, &ex);
    struct json_value o;
    pk_obj(&o);
    bool covering = pk_in_covering_group(run, refs[best].ref_file);
    (void)json_push_kv_str(&o, "symbol", name);
    (void)json_push_kv_str(&o, "status", exact ? ex.status : "reference_site");
    (void)json_push_kv_str(&o, "file", refs[best].ref_file);
    (void)json_push_kv_int(&o, "ref_line", refs[best].ref_line);
    (void)json_push_kv_str(&o, "enclosing", refs[best].enclosing);
    (void)json_push_kv_int(&o, "first_line", ex.first);
    (void)json_push_kv_int(&o, "last_line", ex.last);
    (void)json_push_kv_bool(&o, "in_covering_group", covering);
    pk_push(&run->pattern, &o);
    if (ex.text.len > 0) {
        char label[360];
        (void)snprintf(label, sizeof(label),
                       "PATTERN for %s: %s%s%s", name, refs[best].enclosing,
                       exact ? "" : " (reference site, enclosing definition "
                                    "not resolved)",
                       covering ? "  [in a covering group]" : "");
        pk_md_excerpt(&run->pat, &ex, label);
        if (strstr(ex.text.p, "#if")) run->traps |= PK_TRAP_ARM;
    }
    pk_excerpt_free(&ex);
}

/* ── previous-run evidence ──────────────────────────────────────────────── */

static bool pk_failed_group(const struct pk_run *run, const char *id)
{
    for (size_t i = 0; i < run->failure.failed_count; i++) {
        char full[ZCL_TEST_GROUP_FULL_MAX];
        if (zcl_test_group_resolve_exact(run->failure.failed[i], full) &&
            strcmp(full, id) == 0)
            return true;
    }
    return false;
}

static const char *pk_failure_status(const struct pk_run *run)
{
    if (run->failure_unavailable) return "unavailable";
    return run->failure.tests_run == SPECIALIST_FOCUS_ARTIFACT_MISSING
        ? "no run recorded" : "recorded";
}

static void pk_failure_note(struct pk_run *run)
{
    const char *status = pk_failure_status(run);
    if (strcmp(status, "recorded") != 0) {
        pk_sb_add(&run->notes, "\nPREVIOUS FAILURE: %s", status);
    } else {
        int shown = 0;
        pk_sb_add(&run->notes, "\nPREVIOUS FAILURE (unbound_last_run):");
        for (int i = 0; i < run->f.ngroup; i++) {
            if (!pk_failed_group(run, run->f.group[i].id)) continue;
            pk_sb_add(&run->notes, "%s%s", shown++ == 0 ? " " : ", ",
                      run->f.group[i].id);
        }
        if (!shown) pk_sb_add(&run->notes, " (none routed)");
    }
    pk_sb_add(&run->notes,
              "\n  Previous run only; the artifact has no commit identity and "
              "is not a verdict on BASE.\n");
}

/* ── assembly ───────────────────────────────────────────────────────────── */

static void pk_run_reset(struct pk_run *run, int max_lines)
{
    struct json_value *arrs[] = { &run->excerpts, &run->files, &run->tests,
                                  &run->pattern, &run->impact, &run->caps,
                                  &run->auth, &run->claims };
    for (size_t i = 0; i < sizeof(arrs) / sizeof(arrs[0]); i++) {
        json_free(arrs[i]);
        json_init(arrs[i]);
        json_set_array(arrs[i]);
    }
    struct pk_sb *sbs[] = { &run->map, &run->exc, &run->pat, &run->keep,
                            &run->authority, &run->notes };
    for (size_t i = 0; i < sizeof(sbs) / sizeof(sbs[0]); i++)
        pk_sb_free(sbs[i]);
    char head[65], src[65], dep[65], name[48];
    (void)snprintf(head, sizeof(head), "%s", run->f.head);
    (void)snprintf(src, sizeof(src), "%s", run->f.source_hex);
    (void)snprintf(dep, sizeof(dep), "%s", run->f.dep_hex);
    (void)snprintf(name, sizeof(name), "%s", run->f.name);
    memset(&run->f, 0, sizeof(run->f));
    (void)snprintf(run->f.head, sizeof(run->f.head), "%s", head);
    (void)snprintf(run->f.source_hex, sizeof(run->f.source_hex), "%s", src);
    (void)snprintf(run->f.dep_hex, sizeof(run->f.dep_hex), "%s", dep);
    (void)snprintf(run->f.name, sizeof(run->f.name), "%s", name);
    run->ntouch = 0;
    run->declaration_output_failed = false;
    run->impact_error_path[0] = 0;
    run->traps = 0;
    run->ctx.max_lines = max_lines;
}

static void pk_keep_signatures(struct pk_run *run)
{
    pk_sb_add(&run->keep, "  - Files and symbols outside this packet; core/ is sealed.\n");
    for (int i = 0; i < run->in.nsym; i++) {
        const struct pk_choice *choice = &run->choice[i];
        if (strcmp(choice->status, "ok")) continue;
        const struct ci_symbol *s = &choice->symbol;
        char sig[260];
        code_trunc(sig, sizeof(sig), s->signature, 240);
        pk_sb_add(&run->keep, "  - Signature of %s unless CHANGE says otherwise: "
                  "%s\n", s->name, sig);
    }
}

static void pk_routes_prepare(struct pk_run *run)
{
    if (run->ntouch < 2) return;
    run->route_accs = zcl_calloc((size_t)run->ntouch, sizeof(*run->route_accs),
                                 "code_packet_routes");
    if (!run->route_accs) return;
    const char *paths[PK_TOUCH_MAX];
    for (int i = 0; i < run->ntouch; i++) paths[i] = run->touch[i];
    if (!zcl_native_code_routes_many_at(run->ctx.root, paths, (size_t)run->ntouch, run->route_accs,
                                     run->routes, run->route_risks)) {
        free(run->route_accs);
        run->route_accs = NULL;
    }
}

static void pk_assemble(struct pk_run *run, int max_lines)
{
    pk_run_reset(run, max_lines);
    pk_claim(run, run->f.head[0] != '\0',
             run->f.head[0] ? ".git" : "no readable .git",
             "HEAD was read from the checkout");
    for (int i = 0; i < run->in.nsym; i++)
        pk_do_symbol(run, i);
    for (int i = 0; i < run->in.nfile; i++)
        pk_touch_add(run, run->in.files[i], true);
    pk_routes_prepare(run);
    for (int i = 0; i < run->ntouch && !run->impact_error_path[0]; i++)
        pk_do_touched(run, i);
    free(run->route_accs);
    run->route_accs = NULL;
    if (run->impact_error_path[0]) return;
    run->f.ntouch = run->ntouch;
    int missing = 0;
    for (int i = 0; i < run->f.ngroup; i++)
        missing += run->f.group[i].catalog_line == 0;
    pk_claim(run, missing == 0, "tools/dev/test_group_catalog.def",
             "all %d covering group(s) are registered in the catalog",
             run->f.ngroup);
    for (int i = 0; i < run->in.nsym; i++)
        pk_do_pattern(run, i);
    pk_keep_signatures(run);
    pk_claim(run, !run->ctx.budget_hit, "4 MiB per request",
             "every governed read stayed within the read budget");
    pk_sb_add(&run->notes,
              "\n  Excerpts are verbatim; the only non-source line is a "
              "`/* ... N lines elided ... */` marker.\n"
              "  BASE names the committed HEAD; uncommitted edits are covered "
              "by source_root_sha3 (the scanned tree).\n"
              "Traps:\n");
    char traps[PK_TRAPS][PK_TRAP_LEN];
    size_t nt = pk_trap_lines(run->traps, traps);
    for (size_t i = 0; i < nt; i++)
        pk_sb_add(&run->notes, "  - %s\n", traps[i]);
    pk_failure_note(run);
}

static bool pk_tail_line(struct json_value *arr, const char *text)
{
    struct json_value value;
    json_init(&value);
    json_set_str(&value, text);
    bool ok = value.type == JSON_STR && json_push_back(arr, &value);
    json_free(&value);
    return ok;
}

static bool pk_json_previous_failure(const struct pk_run *run,
                                     struct json_value *out)
{
    struct json_value obj, groups;
    json_init(&obj);
    json_set_object(&obj);
    json_init(&groups);
    json_set_array(&groups);
    const char *status = pk_failure_status(run);
    bool ok = json_push_kv_str(&obj, "status", status) &&
        json_push_kv_str(&obj, "source", ".cache/test-timing/last-run.json");
    if (ok && strcmp(status, "recorded") == 0)
        ok = json_push_kv_str(&obj, "revision_binding", "unbound_last_run");
    for (int i = 0; ok && !run->failure_unavailable && i < run->f.ngroup; i++)
        if (pk_failed_group(run, run->f.group[i].id))
            ok = pk_tail_line(&groups, run->f.group[i].id);
    if (ok)
        ok = json_push_kv(&obj, "failed_groups", &groups) &&
             json_push_kv(out, "previous_failure", &obj);
    json_free(&groups);
    json_free(&obj);
    return ok;
}

static bool pk_tail_header(const struct pk_run *run, struct json_value *out)
{
    if (!json_push_kv_str(out, "name", run->f.name) ||
        !json_push_kv_str(out, "goal", run->in.goal) ||
        !json_push_kv_str(out, "change", run->in.change ? run->in.change : "") ||
        !json_push_kv_str(out, "head", run->f.head[0] ? run->f.head : "unavailable") ||
        !json_push_kv_str(out, "source_root_sha3", run->f.source_hex) ||
        !json_push_kv_str(out, "dep_root_sha3", run->f.dep_hex) ||
        !json_push_kv_int(out, "max_lines", run->in.max_lines) ||
        !json_push_kv_int(out, "max_lines_effective", run->ctx.max_lines) ||
        !json_push_kv_str(out, "size", pk_size_class(run->f.max_dependents)) ||
        !json_push_kv_int(out, "excerpt_lines", run->f.excerpt_lines) ||
        !json_push_kv_int(out, "bytes_read", (int64_t)run->ctx.bytes_read))
        return false;
    return true;
}

static bool pk_tail_sections(const struct pk_run *run, struct json_value *out)
{
    if (!json_push_kv(out, "excerpts", &run->excerpts) ||
        !json_push_kv(out, "files", &run->files) ||
        !json_push_kv(out, "tests", &run->tests) ||
        !json_push_kv(out, "pattern", &run->pattern) ||
        !json_push_kv(out, "impact", &run->impact) ||
        !json_push_kv(out, "capabilities", &run->caps) ||
        !json_push_kv(out, "authority", &run->auth) ||
        !json_push_kv(out, "claims", &run->claims)) return false;
    return true;
}

static bool pk_json_tail(struct pk_run *run, struct json_value *out,
                         const struct pk_sb *doc)
{
    if (!pk_tail_header(run, out) || !pk_json_previous_failure(run, out) ||
        !pk_tail_sections(run, out)) return false;
    struct json_value gates, traps;
    json_init(&gates); json_set_array(&gates);
    json_init(&traps); json_set_array(&traps);
    char g[PK_GATES][PK_GATE_LEN];
    size_t ng = pk_gate_lines(&run->f, g);
    bool ok = true;
    for (size_t i = 0; i < ng && ok; i++)
        ok = pk_tail_line(&gates, g[i]);
    char t[PK_TRAPS][PK_TRAP_LEN];
    size_t nt = pk_trap_lines(run->traps, t);
    for (size_t i = 0; i < nt && ok; i++)
        ok = pk_tail_line(&traps, t[i]);
    ok = ok && json_push_kv(out, "gates", &gates) &&
         json_push_kv(out, "traps", &traps);
    json_free(&gates); json_free(&traps);
    return ok && json_push_kv_str(out, "markdown", doc->p ? doc->p : "");
}

#if defined(ZCL_TESTING)
bool zcl_packet_test_tail(struct json_value *out)
{
    struct pk_run *run = zcl_calloc(1, sizeof(*run), "packet_tail_test");
    if (!run) return false;
    run->in.goal = "fixture";
    struct pk_sb doc = {0};
    json_init(out);
    json_set_object(out);
    bool ok = pk_json_tail(run, out, &doc);
    free(run);
    return ok;
}
#endif

enum pk_render_result { PK_RENDER_OK, PK_RENDER_FIT, PK_RENDER_ALLOC, PK_RENDER_IMPACT };

static bool pk_render_fits(const struct pk_run *run, const struct pk_sb *files,
                           const struct pk_sb *doc)
{
    return !run->declaration_output_failed && !files->over && !doc->over &&
           !run->map.over && !run->exc.over && !run->pat.over &&
           !run->keep.over && !run->authority.over && !run->notes.over;
}

/* Keep allocation refusal distinct from bounded overflow. */
static enum pk_render_result pk_render(struct pk_run *run, struct json_value *out)
{
    struct pk_sb files = {0}, doc = {0};
    pk_sb_raw(&files, run->map.p ? run->map.p : "", run->map.len);
    pk_sb_add(&files, "\n");
    pk_sb_raw(&files, run->exc.p ? run->exc.p : "", run->exc.len);
    pk_sb_raw(&files, run->pat.p ? run->pat.p : "", run->pat.len);
    pk_md_document(&doc, &run->in, &run->f, &files, &run->keep,
                   &run->authority, &run->notes);
    bool allocation_failed = false;
    bool ok = pk_render_fits(run, &files, &doc);
    if (ok) {
        json_init(out);
        json_set_object(out);
        if (!pk_json_tail(run, out, &doc)) {
            json_free(out);
            json_init(out);
            ok = false;
            allocation_failed = true;
        }
    }
    pk_sb_free(&files);
    pk_sb_free(&doc);
    return allocation_failed ? PK_RENDER_ALLOC : ok ? PK_RENDER_OK : PK_RENDER_FIT;
}

/* The reply cap: this leaf's declared budget (code.def: 65536, the registry
 * maximum), never above a smaller request, less room for the envelope. */
static size_t pk_reply_cap(const struct zcl_command_request *request)
{
    size_t cap = PK_REPLY_BUDGET;
    if (request->spec && request->spec->budget_bytes > 0 &&
        (size_t)request->spec->budget_bytes < cap)
        cap = (size_t)request->spec->budget_bytes;
    if (request->budget_bytes > 0 && request->budget_bytes < cap)
        cap = request->budget_bytes;
    return cap > 4096 ? cap - 2048 : cap / 2;
}

static int pk_next_lines(int lines)
{
    return lines * 2 / 3 < PK_LINES_MIN ? PK_LINES_MIN : lines * 2 / 3;
}

/* Assemble, shrinking max_lines by a third (floor 20) until it fits `cap`. */
static enum pk_render_result pk_fit(struct pk_run *run, size_t cap,
                                    struct json_value *out)
{
    int lines = run->in.max_lines;
    /* One immutable index generation and source cache serve every retry.
     * body_end is the full source extent, independent of excerpt elision. */
    run->ctx.max_lines = lines;
    pk_prepare_symbols(run);
    run->neighborhoods = true;
    run->declarations = true;
    bool reuse_files = false;
    for (;;) {
        if (reuse_files) run->ctx.max_lines = lines;
        else pk_assemble(run, lines);
        if (run->impact_error_path[0]) return PK_RENDER_IMPACT;
        enum pk_render_result result = pk_render(run, out);
        if (result == PK_RENDER_ALLOC) return result;
        bool ok = result == PK_RENDER_OK;
        if (ok && json_write(out, NULL, 0) <= cap)
            return PK_RENDER_OK;
        if (ok)
            json_free(out);
        if (ok && run->in.nsym == 0) {
            if (lines <= PK_LINES_MIN) return PK_RENDER_FIT;
            lines = pk_next_lines(lines);
            reuse_files = true;
            continue;
        }
        reuse_files = false;
        if (run->neighborhoods) {
            run->neighborhoods = false;
            continue;
        }
        if (run->declarations) {
            run->declarations = false;
            continue;
        }
        if (lines <= PK_LINES_MIN)
            return PK_RENDER_FIT;
        lines = pk_next_lines(lines);
    }
}

static bool pk_merge(struct zcl_command_reply *reply, struct json_value *out)
{
    if (reply->data.type == JSON_OBJ && reply->data.num_children == 0) {
        json_free(&reply->data);
        reply->data = *out;
        json_init(out);
        return true;
    }
    struct json_value staged;
    json_init(&staged);
    if (!json_copy_checked(&staged, &reply->data)) return false;
    for (size_t i = 0; i < out->num_children; i++) {
        if (!json_push_kv(&staged, out->keys[i], &out->children[i])) {
            json_free(&staged);
            return false;
        }
    }
    json_free(&reply->data);
    reply->data = staged;
    return true;
}

static bool pk_finish(struct zcl_command_reply *reply, struct json_value *out,
                      const char *summary)
{
    return json_push_kv_str(out, "summary", summary) && pk_merge(reply, out);
}

#if defined(ZCL_TESTING)
bool zcl_packet_test_finish(struct zcl_command_reply *reply,
                            struct json_value *out, const char *summary)
{
    return pk_finish(reply, out, summary);
}

bool zcl_packet_test_merge(struct zcl_command_reply *reply, struct json_value *out)
{
    return pk_merge(reply, out);
}
#endif

/* Open the index read-only and bind the run to its generation. */
static bool pk_open(const struct zcl_command_request *request,
                    struct zcl_command_reply *reply, struct pk_run *run)
{
    bool stale = true;
    run->ctx.root = zcl_native_source_root(request);
    run->ctx.ci = codeindex_open_readonly(run->ctx.root, &stale);
    if (!run->ctx.ci) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "CODEINDEX_ABSENT",
                               "open", false, false,
                               "no readable code index; run code.map, then retry; "
                               "if an index owner is active, wait for its refresh", "");
        (void)zcl_command_reply_add_next(reply, "code.map", "{}",
                                         "prepare the source index, then retry code.packet");
        return false;
    }
    if (stale) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "CODEINDEX_STALE",
                               "open", true, false,
                               "the source index is stale; run code.map, then retry; "
                               "if an index owner is active, wait for its refresh",
                               "source_root_sha3");
        (void)zcl_command_reply_add_next(reply, "code.map", "{}",
                                         "refresh the source index, then retry code.packet");
        return false;
    }
    if (!code_generation_hex(run->ctx.ci, run->f.source_hex, run->f.dep_hex)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "CODEINDEX_GENERATION",
                               "derive", false, false,
                               "code index generation metadata is unavailable",
                               "source_root_sha3,dep_root_sha3");
        return false;
    }
    (void)pk_git_head(&run->ctx, run->f.head, sizeof(run->f.head));
    specialist_focus_evidence_clear(&run->failure);
    run->failure_unavailable =
        !specialist_focus_load_failed_groups(run->ctx.root, &run->failure);
    pk_slug(run->in.goal, run->f.name, sizeof(run->f.name));
    return true;
}

static void pk_run_free(struct pk_run *run)
{
    struct json_value *arrs[] = { &run->excerpts, &run->files, &run->tests,
                                  &run->pattern, &run->impact, &run->caps,
                                  &run->auth, &run->claims };
    for (size_t i = 0; i < sizeof(arrs) / sizeof(arrs[0]); i++)
        json_free(arrs[i]);
    struct pk_sb *sbs[] = { &run->map, &run->exc, &run->pat, &run->keep,
                            &run->authority, &run->notes };
    for (size_t i = 0; i < sizeof(sbs) / sizeof(sbs[0]); i++)
        pk_sb_free(sbs[i]);
    pk_ctx_free(&run->ctx);
    if (run->ctx.ci)
        codeindex_close(run->ctx.ci);
    free(run);
}

void zcl_native_handle_code_packet(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply)
{
    struct pk_run *run = zcl_calloc(1, sizeof(*run), "code_packet_run");
    if (!run) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "OUT_OF_MEMORY",
                               "dispatch", true, false,
                               "could not allocate the packet", "");
        return;
    }
    if (!pk_parse_input(request, reply, &run->in) ||
        !pk_open(request, reply, run)) {
        pk_run_free(run);
        return;
    }
    struct json_value out;
    enum pk_render_result fit = pk_fit(run, pk_reply_cap(request), &out);
    if (fit != PK_RENDER_OK) {
        if (fit == PK_RENDER_IMPACT) {
            json_free(&reply->data);
            json_init(&reply->data);
            json_set_object(&reply->data);
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INTERNAL, "PACKET_IMPACT_UNAVAILABLE",
                                   "assemble", true, false,
                                   "could not determine packet impact", run->impact_error_path);
            pk_run_free(run);
            return;
        }
        if (fit == PK_RENDER_ALLOC) {
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INTERNAL, "OUT_OF_MEMORY",
                                   "assemble", true, false,
                                   "could not construct the packet", "");
            pk_run_free(run);
            return;
        }
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "PACKET_TOO_LARGE",
                               "assemble", false, false,
                               "the packet does not fit the reply budget even "
                               "at max_lines=20; ask for fewer symbols or files",
                               "symbols,files");
        pk_run_free(run);
        return;
    }
    char summary[300];
    (void)snprintf(summary, sizeof(summary),
                   "packet %s: %d excerpt line(s), %d covering group(s), size "
                   "%s", run->f.name, run->f.excerpt_lines, run->f.ngroup,
                   pk_size_class(run->f.max_dependents));
    if (!pk_finish(reply, &out, summary))
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "OUT_OF_MEMORY",
                               "assemble", true, false,
                               "could not transfer the packet to the reply", "");
    json_free(&out);
    pk_run_free(run);
}
