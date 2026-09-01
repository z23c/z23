/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * `code provenance emitter` — hand it something the node SAID; get back the code that
 * said it.
 *
 * ── The gap this closes ──
 * `dumpstate blocker` names a stall with an id, an owner and a reason. Acting
 * on that meant guessing: which file emits this, which registry row owns it,
 * which test covers it. Four registries already know the answer and none of
 * them were joined:
 *
 *   the SOURCE TEXT              which literal formatted the string
 *                                (cognition/modules/codeindex/src/codeindex_emitter.c)
 *   the codeindex symbol table   which function that literal sits in, and who
 *                                calls that function
 *   blocker_remedy_bindings.def  which blocker-id pattern owns the id, and
 *                                whether any auto-remedy exists for it
 *   diagnostics_dumpers.def      which .c owns a subsystem, and the test that
 *                                proves it
 *
 * ── Why this cannot rot ──
 * Every field is DERIVED on the call. The two .def registries are read the
 * only way that cannot disagree with them — the build expands their rows into
 * this translation unit, so a deleted row disappears from the answer and a row
 * naming a nonexistent condition is still their own gate's problem, not a
 * second copy here. The source evidence is re-scanned per query. There is no
 * checked-in id→file table anywhere in this feature, and therefore nothing to
 * keep in sync and no freshness gate to add.
 *
 * ── Honest failure ──
 * A miss reports WHICH join missed and what to run next, because an empty
 * result is what sends an agent back to grep.
 */

#define _GNU_SOURCE
#include "command/native_command.h"

#include "kernel/command_registry.h"
#include "json/json.h"
#include "codeindex/codeindex.h"
#include "codeindex/codeindex_emitter.h"
#include "controllers/diagnostics_internal.h"
#include "base/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── the blocker-remedy registry, expanded in place ──────────────────────
 * engine/conditions/include/conditions/blocker_remedy_bindings.def is the ratchet
 * that requires every blocker id a production call site can build to declare
 * its remedy (condition name, ESCAPE(action), or the honest token OWNER). Its
 * rows are bare tokens, so they stringize; that is the whole projection. */
struct emit_remedy_row {
    const char *pattern;
    const char *remedy;
};

#define ZCL_BLOCKER_REMEDY(id, remedy) { #id, #remedy },
static const struct emit_remedy_row k_remedy_rows[] = {
#include "conditions/blocker_remedy_bindings.def"
};
#undef ZCL_BLOCKER_REMEDY

/* ── the dumper registry's function NAMES ────────────────────────────────
 * struct diagnostics_dump_entry stores a function POINTER, and a pointer
 * cannot be looked up in the code index. config/command_handler_index.h
 * already solved exactly this for the command catalog: re-include the SAME
 * .def through a stringizing macro and get {name, handler_name}. Same trick,
 * same file, same guarantee — the rows come from the one authoritative .def,
 * so a renamed dumper function renames itself here too, and a row that names
 * a function the tree does not define fails the link in diagnostics_registry.c
 * before it can lie here. */
struct emit_dumper_fn_row {
    const char *name;
    const char *fn_name;
};

#define EMIT_STR_(x) #x
#define EMIT_STR(x)  EMIT_STR_(x)   /* two levels: expand fn_ before stringizing */
#define DIAG_ENTRY(name_, fn_, ...)      { (name_), EMIT_STR(fn_) }
#define DIAG_SERVICE(name_, fn_, ...)    { (name_), EMIT_STR(fn_) }
#define DIAG_LOCAL(name_, fn_, ...)      { (name_), EMIT_STR(fn_) }
#define DIAG_CHAIN(name_, fn_, ...)      { (name_), EMIT_STR(fn_) }
#define DIAG_CONDITION(name_, fn_, ...)  { (name_), EMIT_STR(fn_) }
#define DIAG_RUNTIME(name_, fn_, ...)    { (name_), EMIT_STR(fn_) }
#define DIAG_JOB(name_, fn_, ...)        { (name_), EMIT_STR(fn_) }
#define DIAG_STAGE(name_, fn_, ...)      { (name_), EMIT_STR(fn_) }
#define DIAG_PROJECTION(name_, fn_, ...) { (name_), EMIT_STR(fn_) }
static const struct emit_dumper_fn_row k_dumper_fns[] = {
#include "controllers/diagnostics_dumpers.def"
};
#undef DIAG_PROJECTION
#undef DIAG_STAGE
#undef DIAG_JOB
#undef DIAG_RUNTIME
#undef DIAG_CONDITION
#undef DIAG_CHAIN
#undef DIAG_LOCAL
#undef DIAG_SERVICE
#undef DIAG_ENTRY
#undef EMIT_STR
#undef EMIT_STR_

enum {
    EMIT_SITE_CAP     = 12,  /* ranked sites pulled from the scan */
    EMIT_SHOW_ALSO    = 3,   /* extra production sites rendered */
    EMIT_SHOW_TESTS   = 3,   /* test-file sites rendered */
    EMIT_SHOW_CALLERS = 4,
    EMIT_EVIDENCE_SHOW = 150,
};

/* Bounded copy with an ellipsis marker when truncated. */
static void emit_trunc(char *dst, size_t cap, const char *src, size_t max)
{
    if (!dst || cap == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    size_t lim = max < cap - 1 ? max : cap - 1;
    size_t i = 0;
    for (; i < lim && src[i]; i++) dst[i] = (src[i] == '\n') ? ' ' : src[i];
    if (src[i] != '\0' && i + 3 < cap) { dst[i++] = '.'; dst[i++] = '.'; dst[i++] = '.'; }
    dst[i] = '\0';
}

static void emit_push_line(struct json_value *arr, const char *s)
{
    struct json_value item;
    json_init(&item);
    json_set_str(&item, s);
    (void)json_push_back(arr, &item);
    json_free(&item);
}

/* The most specific remedy row owning `id`: exact rows beat globs, and among
 * globs the longest pattern wins (so `catalog.*.lag_exceeded` beats `*`). */
static const struct emit_remedy_row *emit_remedy_for(const char *id)
{
    const struct emit_remedy_row *best = NULL;
    size_t best_score = 0;
    for (size_t i = 0; i < sizeof(k_remedy_rows) / sizeof(k_remedy_rows[0]); i++) {
        const char *pat = k_remedy_rows[i].pattern;
        bool glob = strchr(pat, '*') != NULL;
        if (glob ? !codeindex_emit_glob_match(pat, id) : strcmp(pat, id) != 0)
            continue;
        size_t score = strlen(pat) + (glob ? 0u : 10000u);
        if (best && score <= best_score) continue;
        best = &k_remedy_rows[i];
        best_score = score;
    }
    return best;
}

/* The diagnostics_dumpers.def row whose subsystem name is exactly `name`. */
static const struct diagnostics_dump_entry *emit_dumper_named(const char *name)
{
    for (size_t i = 0; i < diagnostics_dumper_count(); i++) {
        const struct diagnostics_dump_entry *e = diagnostics_dumper_at(i);
        if (e && e->name && strcmp(e->name, name) == 0) return e;
    }
    return NULL;
}

/* The first diagnostics_dumpers.def row that declares `path` as its owner .c —
 * the registry's own answer to "which test proves this file". */
static const struct diagnostics_dump_entry *emit_dumper_owning(const char *path)
{
    for (size_t i = 0; i < diagnostics_dumper_count(); i++) {
        const struct diagnostics_dump_entry *e = diagnostics_dumper_at(i);
        if (e && e->owner_file && e->owner_file[0] &&
            strcmp(e->owner_file, path) == 0)
            return e;
    }
    return NULL;
}

/* The dump function's NAME for subsystem `name`, from the stringized rows. */
static const char *emit_dumper_fn_name(const char *name)
{
    for (size_t i = 0; i < sizeof(k_dumper_fns) / sizeof(k_dumper_fns[0]); i++)
        if (k_dumper_fns[i].name && strcmp(k_dumper_fns[i].name, name) == 0)
            return k_dumper_fns[i].fn_name;
    return NULL;
}

/* Leading dot-component of `text` (blocker ids are "<owner>.<condition>"). */
static void emit_first_component(char *dst, size_t cap, const char *text)
{
    size_t i = 0;
    for (; i + 1 < cap && text[i] && text[i] != '.'; i++) dst[i] = text[i];
    dst[i] = '\0';
}

/* ── code.emitter ───────────────────────────────────────────────────────── */
void zcl_native_handle_code_emitter(const struct zcl_command_request *request,
                                    struct zcl_command_reply *reply)
{
    const char *text = json_get_str(json_get(request->input, "text"));
    if (!text || !text[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_TEXT",
                               "normalize", false, false,
                               "code provenance emitter needs the text the node emitted: "
                               "a blocker id, a dumper subsystem name, or a "
                               "distinctive fragment of a reason or log line",
                               "");
        return;
    }

    const char *root = ".";
    if (request->context && request->context->source_root &&
        request->context->source_root[0])
        root = request->context->source_root;
    else {
        const char *env = getenv("ZCL_DEV_SOURCE_ROOT");
        if (env && env[0]) root = env;
    }

    struct codeindex *ci = codeindex_open(root);
    if (!ci) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "CODEINDEX_OPEN",
                               "dispatch", true, false,
                               "could not open or rebuild the code index", root);
        return;
    }

    /* ── join 1: the diagnostics registry (exact name, then the id's owner
     * component — `address_index.below_snapshot_seed` asks about
     * `address_index`). */
    char owner_component[64];
    emit_first_component(owner_component, sizeof(owner_component), text);
    const struct diagnostics_dump_entry *dumper = emit_dumper_named(text);
    const char *dumper_via = dumper ? "exact_subsystem_name" : NULL;
    if (!dumper && owner_component[0] && strcmp(owner_component, text) != 0) {
        dumper = emit_dumper_named(owner_component);
        if (dumper) dumper_via = "owner_component_of_id";
    }

    /* ── join 2: the blocker-remedy ratchet. */
    const struct emit_remedy_row *remedy = emit_remedy_for(text);

    /* ── join 3: source evidence. */
    struct ci_emit_site *sites = zcl_malloc(EMIT_SITE_CAP * sizeof(*sites),
                                            "code_emitter_sites");
    if (!sites) {
        codeindex_close(ci);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ALLOC",
                               "dispatch", true, false,
                               "could not allocate the site table", "");
        return;
    }
    /* The scan runs AFTER the registry joins so it can be told what they
     * already know: an exact subsystem-name hit names the owning .c, and a site
     * in that file must survive the candidate pool no matter how common the
     * text is elsewhere. */
    const char *prefer_path = NULL;
    if (dumper && dumper_via && strcmp(dumper_via, "exact_subsystem_name") == 0)
        prefer_path = dumper->owner_file;

    struct ci_emit_scan_report scan = {0};
    int n = codeindex_emitter_sites(ci, text, prefer_path, sites,
                                    EMIT_SITE_CAP, &scan);
    if (n < 0) {
        free(sites);
        codeindex_close(ci);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "EMITTER_SCAN",
                               "dispatch", true, false,
                               "the source-evidence scan failed", root);
        return;
    }

    /* First non-test site is the emitter; test sites are reported separately
     * because a test that names the string IS the proof that covers it. */
    int primary = -1, first_test = -1;
    for (int i = 0; i < n; i++) {
        if (!sites[i].is_test && primary < 0) primary = i;
        if (sites[i].is_test && first_test < 0) first_test = i;
    }
    /* A string only a test emits still resolves — to that test. */
    if (primary < 0 && first_test >= 0) primary = first_test;

    /* Registry beats scan on its own ground. A bare subsystem name is a short
     * string occurring in hundreds of literals, so text ranking cannot single
     * out its emitter and should not pretend to. The .def row names the dump
     * FUNCTION, and the code index knows exactly where that function is
     * defined — an exact answer with no text matching in it at all. */
    const char *registry_pin = NULL;
    struct ci_emit_site pinned = {0};
    if (dumper && prefer_path) {
        const char *fn = emit_dumper_fn_name(dumper->name);
        struct ci_symbol sym;
        bool found = false;
        if (fn && codeindex_symbol(ci, fn, &sym, &found) && found &&
            sym.def_path[0] && sym.def_line > 0) {
            snprintf(pinned.path, sizeof(pinned.path), "%s", sym.def_path);
            pinned.line = sym.def_line;
            snprintf(pinned.enclosing, sizeof(pinned.enclosing), "%s", sym.name);
            snprintf(pinned.context, sizeof(pinned.context),
                     "diagnostics_dumpers.def row");
            snprintf(pinned.evidence, sizeof(pinned.evidence),
                     "DIAG row '%s' names %s()", dumper->name, fn);
            pinned.kind = CI_EMIT_REGISTRY_ROW;
            registry_pin = "diagnostics_dumpers_def_fn";
        }
    }

    char query_shown[132];
    emit_trunc(query_shown, sizeof(query_shown), text, 128);
    (void)json_push_kv_str(&reply->data, "query", query_shown);
    (void)json_push_kv_bool(&reply->data, "resolved",
                            registry_pin != NULL || primary >= 0);

    const char *route = NULL;
    if (registry_pin || primary >= 0) {
        const struct ci_emit_site *s = registry_pin ? &pinned : &sites[primary];
        struct json_value em;
        json_init(&em); json_set_object(&em);
        (void)json_push_kv_str(&em, "path", s->path);
        (void)json_push_kv_int(&em, "line", s->line);
        (void)json_push_kv_str(&em, "function",
                               s->enclosing[0] ? s->enclosing : "(file scope)");
        char ev[EMIT_EVIDENCE_SHOW + 8];
        emit_trunc(ev, sizeof(ev), s->evidence, EMIT_EVIDENCE_SHOW);
        (void)json_push_kv_str(&em, "evidence", ev);
        (void)json_push_kv_str(&em, "evidence_kind",
                               codeindex_emit_kind_name(s->kind));
        (void)json_push_kv_int(&em, "literal_chars", s->literal_chars);
        if (s->context[0])
            (void)json_push_kv_str(&em, "call_context", s->context);
        if (registry_pin)
            (void)json_push_kv_str(&em, "selected_by", registry_pin);
        (void)json_push_kv(&reply->data, "emitter", &em);
        json_free(&em);

        /* callers of the emitting function — the next hop out. */
        struct json_value callers;
        json_init(&callers); json_set_array(&callers);
        int ncall = 0;
        if (s->enclosing[0]) {
            struct ci_ref refs[EMIT_SHOW_CALLERS + 1];
            int nr = codeindex_callers(ci, s->enclosing, refs,
                                       EMIT_SHOW_CALLERS + 1);
            if (nr < 0) nr = 0;
            for (int i = 0; i < nr && ncall < EMIT_SHOW_CALLERS; i++, ncall++) {
                char line[200];
                (void)snprintf(line, sizeof(line), "%s @ %s:%d",
                               refs[i].enclosing[0] ? refs[i].enclosing : "?",
                               refs[i].ref_file, refs[i].ref_line);
                emit_push_line(&callers, line);
            }
        }
        (void)json_push_kv(&reply->data, "callers", &callers);
        json_free(&callers);

        bool crisk = false;
        route = zcl_native_code_route_for_path(s->path, NULL, &crisk);
    }

    /* ── the owning proof, from strongest evidence to weakest fallback:
     * a test that names the string, then the dumper row's declared test, then
     * the path-rule route. Each is labelled with how it was obtained. */
    struct json_value proofs;
    json_init(&proofs); json_set_array(&proofs);
    int nproof = 0;
    for (int i = 0; i < n && nproof < EMIT_SHOW_TESTS; i++) {
        if (!sites[i].is_test || (!registry_pin && i == primary)) continue;
        char line[256];
        (void)snprintf(line, sizeof(line), "%s:%d — names the string (%s)",
                       sites[i].path, sites[i].line,
                       codeindex_emit_kind_name(sites[i].kind));
        emit_push_line(&proofs, line);
        nproof++;
    }
    const struct diagnostics_dump_entry *owner_row =
        (!registry_pin && primary >= 0) ? emit_dumper_owning(sites[primary].path)
                                        : NULL;
    if (dumper && dumper->primary_test && dumper->primary_test[0]) {
        char line[256];
        (void)snprintf(line, sizeof(line),
                       "%s — declared by diagnostics_dumpers.def row '%s'",
                       dumper->primary_test, dumper->name);
        emit_push_line(&proofs, line);
        nproof++;
    } else if (owner_row && owner_row->primary_test && owner_row->primary_test[0]) {
        char line[256];
        (void)snprintf(line, sizeof(line),
                       "%s — declared by diagnostics_dumpers.def row '%s'",
                       owner_row->primary_test, owner_row->name);
        emit_push_line(&proofs, line);
        nproof++;
    }
    if (route) {
        char line[160];
        (void)snprintf(line, sizeof(line),
                       "make t-fast ONLY=%s — path route for the emitting file",
                       route);
        emit_push_line(&proofs, line);
        nproof++;
    }
    (void)json_push_kv(&reply->data, "owning_proofs", &proofs);
    json_free(&proofs);

    /* ── registry rows that own this text. */
    struct json_value regs;
    json_init(&regs); json_set_array(&regs);
    if (remedy) {
        char line[224];
        (void)snprintf(line, sizeof(line),
                       "blocker_remedy_bindings.def: %s -> %s%s",
                       remedy->pattern, remedy->remedy,
                       strcmp(remedy->remedy, "OWNER") == 0
                           ? " (no auto-remedy in-tree; operator clears)" : "");
        emit_push_line(&regs, line);
    }
    if (dumper) {
        char line[248];
        (void)snprintf(line, sizeof(line),
                       "diagnostics_dumpers.def: %s owner=%s class=%s cost=%s "
                       "(matched by %s)",
                       dumper->name, dumper->owner_file, dumper->state_class,
                       dumper->cost, dumper_via ? dumper_via : "?");
        emit_push_line(&regs, line);
    }
    (void)json_push_kv(&reply->data, "registry_rows", &regs);
    json_free(&regs);

    /* ── other production sites carrying the same evidence. */
    struct json_value also;
    json_init(&also); json_set_array(&also);
    int nalso = 0;
    for (int i = 0; i < n && nalso < EMIT_SHOW_ALSO; i++) {
        if ((!registry_pin && i == primary) || sites[i].is_test) continue;
        char line[240];
        (void)snprintf(line, sizeof(line), "%s:%d %s in %s() [%s, %d chars]",
                       sites[i].path, sites[i].line,
                       sites[i].context[0] ? sites[i].context : "?",
                       sites[i].enclosing[0] ? sites[i].enclosing : "(file scope)",
                       codeindex_emit_kind_name(sites[i].kind),
                       sites[i].literal_chars);
        emit_push_line(&also, line);
        nalso++;
    }
    (void)json_push_kv(&reply->data, "also_emits", &also);
    (void)json_push_kv_int(&reply->data, "site_count", n);
    json_free(&also);

    /* ── what each join did. A miss here is the answer, not a gap in it. */
    struct json_value joins;
    json_init(&joins); json_set_object(&joins);
    (void)json_push_kv_str(&joins, "source_evidence",
                           primary >= 0
                               ? codeindex_emit_kind_name(sites[primary].kind)
                               : "miss");
    (void)json_push_kv_str(&joins, "emitter_selected_by",
                           registry_pin ? registry_pin : "source_evidence_rank");
    (void)json_push_kv_str(&joins, "diagnostics_dumpers_def",
                           dumper ? (dumper_via ? dumper_via : "hit") : "miss");
    (void)json_push_kv_str(&joins, "blocker_remedy_bindings_def",
                           remedy ? remedy->pattern : "miss");
    (void)json_push_kv_int(&joins, "files_scanned", scan.files_scanned);
    (void)json_push_kv_int(&joins, "literal_runs", scan.literal_runs);
    (void)json_push_kv_int(&joins, "markers_seen", scan.markers_seen);
    (void)json_push_kv_int(&joins, "candidates", scan.candidates);
    if (scan.files_unreadable)
        (void)json_push_kv_int(&joins, "files_unreadable", scan.files_unreadable);
    if (scan.enumeration_incomplete)
        (void)json_push_kv_bool(&joins, "enumeration_incomplete", true);
    (void)json_push_kv(&reply->data, "joins", &joins);
    json_free(&joins);

    /* Say when the text was too common to single out an emitter on its own. A
     * short string in 392 places has no unique source, and reporting the first
     * one as if it did is the failure mode this command exists to end. */
    if (primary >= 0 && !registry_pin && scan.candidates > 20 &&
        sites[primary].kind != CI_EMIT_BLOCKER_MARKER &&
        sites[primary].literal_chars < 40) {
        /* query_shown is intentionally bounded to 128 bytes, but the fixed
         * explanatory suffix is longer than the old 248-byte destination. */
        char caveat[512];
        (void)snprintf(caveat, sizeof(caveat),
                       "'%s' occurs at %d sites and no registry row pins one, so "
                       "the emitter below is first by rank, not unique. Compare "
                       "call_context across also_emits — a raise site reads "
                       "blocker_init, a clear site reads blocker_clear — or "
                       "re-run with the whole reason string.",
                       query_shown, scan.candidates);
        (void)json_push_kv_str(&reply->data, "caveat", caveat);
    }

    char summary[280];
    if (registry_pin || primary >= 0) {
        const struct ci_emit_site *s = registry_pin ? &pinned : &sites[primary];
        (void)snprintf(summary, sizeof(summary), "%s:%d %s — %s evidence%s%s",
                       s->path, s->line,
                       s->enclosing[0] ? s->enclosing : "(file scope)",
                       codeindex_emit_kind_name(s->kind),
                       remedy ? "; remedy " : "",
                       remedy ? remedy->remedy : "");
    } else {
        /* Name the strongest partial evidence and the next concrete move. The
         * scan's SCOPE is part of an honest miss: vendored code is deliberately
         * outside it, so a libsqlite3/OpenSSL/Tor message can never resolve
         * here and an agent should stop looking in-tree. */
        char next[420];
        if (scan.files_scanned == 0) {
            (void)snprintf(next, sizeof(next),
                           "the source scan read 0 files — run this from a "
                           "checkout, or set ZCL_DEV_SOURCE_ROOT (tried '%s')",
                           root);
        } else if (remedy) {
            (void)snprintf(next, sizeof(next),
                           "no literal accounts for this text, but "
                           "blocker_remedy_bindings.def owns it as '%s' — grep "
                           "that pattern's stem; the id is likely built from "
                           "runtime pieces with no marker comment",
                           remedy->pattern);
        } else if (scan.best_rejected_chars > 0) {
            (void)snprintf(next, sizeof(next),
                           "closest format string in %d scanned in-tree files "
                           "accounted for only %d literal chars (floor %d, "
                           "longest-segment floor %d). Either retry with a "
                           "longer verbatim fragment (values included), or this "
                           "text is not ours: the scan covers lib/ app/ core/ "
                           "config/ tools/ domain/ platform/adapters/ src/ tests/harness/include/test/ and "
                           "NOT vendor/, so a libsqlite3, OpenSSL or Tor message "
                           "resolves nowhere in-tree.",
                           scan.files_scanned, scan.best_rejected_chars,
                           CI_EMIT_MIN_FORMAT_CHARS, CI_EMIT_MIN_FORMAT_SEGMENT);
        } else {
            (void)snprintf(next, sizeof(next),
                           "no literal in %d scanned in-tree files shares any "
                           "segment with this text: it is assembled entirely "
                           "from runtime data, it comes from vendored code "
                           "(vendor/ is outside the scan), or the running binary "
                           "is not built from this checkout — compare "
                           "`core status` build id.",
                           scan.files_scanned);
        }
        (void)json_push_kv_str(&reply->data, "next_step", next);
        (void)snprintf(summary, sizeof(summary),
                       "unresolved: source_evidence=miss dumper=%s remedy=%s",
                       dumper ? "hit" : "miss", remedy ? "hit" : "miss");
    }
    (void)json_push_kv_str(&reply->data, "summary", summary);

    free(sites);
    codeindex_close(ci);
}
