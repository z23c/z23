/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate — check-sqlite-cursor-lifetime. A stepped sqlite3_stmt must
 * be released (sqlite3_finalize / sqlite3_reset) before any returning error
 * macro (LOG_FAIL, LOG_ERR, LOG_NULL, LOG_RETURN, GUARD, GUARD_NOT_NULL,
 * GUARD_NOT_NULL_RET_NULL, GUARD_NOT_NULL_ERR) fires in the same function.
 *
 * Origin: the 2026-09-29 node.db write-plane wedge. The LOG_* / GUARD*
 * macros RETURN from the caller (platform/modules/util/include/util/
 * log_macros.h), so a finalize written after them is dead code: the parked
 * SELECT keeps the connection's WAL read snapshot pinned and every later
 * writer on that connection fails with SQLITE_BUSY_SNAPSHOT. Three live
 * instances were fixed on 2026-09-29 (snapshot_shielded collect_nullifiers
 * 278f328c56; stage_repair_rewind delete_from_table ad6920b8d4; fast_sync
 * serve_chunk_db, pending core unseal). The safe idiom is finalize-then-
 * log-and-return; this gate keeps the tree there.
 *
 * Rule, per function, per statement variable V: an sqlite3_step call on V
 * (or the AR_STEP_* wrappers) marks V live; sqlite3_finalize(V) / sqlite3_reset(V) and
 * the AR_FINALIZE* / AR_RESET wrappers clear it; a returning macro while any
 * variable is live is a violation. Variables are learned from a direct
 * sqlite3_prepare* &out argument, or from the stmt (2nd) argument of the
 * activerecord.h preparing macros: AR_PREPARE_RET / AR_PREPARE_BOOL leave the
 * release to the function, while the self-contained query/exec helpers
 * (AR_QUERY_ONE_BOOL, AR_QUERY_LIST, AR_QUERY_EXISTS, AR_QUERY_COUNT_BOUND,
 * AR_QUERY_INT64_BOUND, AR_ADHOC_SAVE, AR_ADHOC_DESTROY, AR_EXEC_BOOL,
 * AR_EXEC_CHANGED_BOOL) step AND finalize inside the expansion — those mark
 * their stmt live at invocation and clear it at the invocation's own closing
 * paren, so a returning macro inside bind_code/row_code (which would skip the
 * expansion's internal AR_FINALIZE) is still caught, and an explicit
 * AR_FINALIZE inside row_code before the return is honored. A step on a name
 * no in-function prepare introduced is a CACHED statement owned elsewhere
 * (reset on next use, released at close) and out of scope. A never-stepped
 * statement (the prepare-failure branch) holds no snapshot and is out of
 * scope. State resets when brace depth returns to 0 (function end). Scanning
 * is comment/string-stripped (cstrip_line), so decoy text in literals never
 * registers.
 *
 * Known blind spots (misses, never false positives): the stmt argument of a
 * preparing macro is learned only when it sits on the invocation's own line;
 * AR_QUERY_COUNT_SQL's internal _s is invisible but leak-free by construction
 * (no bind/row code); AR_FIND_ONE_CACHED and the AR_CACHED_* family operate
 * on cached fields (ndb->stmt_*), not locals.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "lintc.h"

enum { SCL_VARS = 16, SCL_VNAME = 48, SCL_LINE = 8192 };

struct scl_var { char name[SCL_VNAME]; int live; };

struct scl {
    FILE *out;
    const char *path;
    struct cstrip strip;
    struct scl_var vars[SCL_VARS];
    int nvars;
    int depth;
    int pdepth;    /* parens, counted uniformly across all call sites */
    int prep;      /* >0: still hunting the prepare &out parameter */
    int clos_var[SCL_VARS];   /* PREP2C: var index to clear at invocation ')' */
    int clos_depth[SCL_VARS]; /*        entry pdepth; pop when pdepth <= it */
    int nclosers;
    int lineno;
    int hits;
};

struct scl_acc { FILE *out; int hits; int scanned; };

enum { SCL_PREP, SCL_PREP2, SCL_PREP2C, SCL_STEP, SCL_CLEAR, SCL_MACRO };
struct scl_tok { const char *name; int kind; };

/* Exact-call matching requires '(' right after the name and a non-identifier
 * boundary after the spelling, so order is cosmetic; related spellings are
 * grouped longest-first for the reader. */
static const struct scl_tok scl_toks[] = {
    { "sqlite3_prepare_v2", SCL_PREP },
    { "sqlite3_prepare_v3", SCL_PREP },
    { "sqlite3_prepare", SCL_PREP },
    { "AR_PREPARE_RET", SCL_PREP2 },
    { "AR_PREPARE_BOOL", SCL_PREP2 },
    { "AR_QUERY_COUNT_BOUND", SCL_PREP2C },
    { "AR_QUERY_INT64_BOUND", SCL_PREP2C },
    { "AR_QUERY_ONE_BOOL", SCL_PREP2C },
    { "AR_QUERY_EXISTS", SCL_PREP2C },
    { "AR_QUERY_LIST", SCL_PREP2C },
    { "AR_ADHOC_DESTROY", SCL_PREP2C },
    { "AR_ADHOC_SAVE", SCL_PREP2C },
    { "AR_EXEC_CHANGED_BOOL", SCL_PREP2C },
    { "AR_EXEC_BOOL", SCL_PREP2C },
    { "AR_STEP_ROW_READONLY", SCL_STEP },
    { "AR_STEP_WRITE", SCL_STEP },
    { "AR_STEP_ROW", SCL_STEP },
    { "AR_STEP_DONE", SCL_STEP },
    { "sqlite3_step", SCL_STEP },
    { "AR_FINALIZE_STEP_DONE", SCL_CLEAR },
    { "AR_FINALIZE", SCL_CLEAR },
    { "AR_RESET", SCL_CLEAR },
    { "sqlite3_finalize", SCL_CLEAR },
    { "sqlite3_reset", SCL_CLEAR },
    { "GUARD_NOT_NULL_RET_NULL", SCL_MACRO },
    { "GUARD_NOT_NULL_ERR", SCL_MACRO },
    { "GUARD_NOT_NULL", SCL_MACRO },
    { "LOG_RETURN", SCL_MACRO },
    { "LOG_FAIL", SCL_MACRO },
    { "LOG_ERR", SCL_MACRO },
    { "LOG_NULL", SCL_MACRO },
    { "GUARD", SCL_MACRO },
};

/* p sits at an identifier start. Match `name` exactly, then optional blanks
 * and '('. Returns the offset one past '(' on match, else 0. */
static size_t scl_call_at(const char *p, const char *name)
{
    size_t n = strlen(name);
    size_t i = n;
    if (strncmp(p, name, n) != 0 || lintc_ident_char((unsigned char)p[n]))
        return 0;
    while (p[i] == ' ' || p[i] == '\t')
        i++;
    return p[i] == '(' ? i + 1 : 0;
}

/* Skip blanks, then read one identifier into out. Advances *pp past it. */
static int scl_read_ident(const char **pp, char *out, size_t cap)
{
    const char *p = *pp;
    size_t n = 0;
    while (*p == ' ' || *p == '\t')
        p++;
    if (!lintc_ident_char((unsigned char)*p) ||
        (*p >= '0' && *p <= '9'))
        return 0;
    while (lintc_ident_char((unsigned char)*p) && n + 1 < cap)
        out[n++] = *p++;
    out[n] = '\0';
    *pp = p;
    return n > 0;
}

static struct scl_var *scl_var(struct scl *s, const char *name, int create)
{
    int i;
    for (i = 0; i < s->nvars; i++)
        if (strcmp(s->vars[i].name, name) == 0)
            return &s->vars[i];
    if (!create || s->nvars >= SCL_VARS)
        return NULL;
    snprintf(s->vars[s->nvars].name, SCL_VNAME, "%s", name);
    s->vars[s->nvars].live = 0;
    return &s->vars[s->nvars++];
}

/* Capture the prepare statement out-parameter: the first &ident at or after
 * the prepare call's argument list (the call may wrap onto later lines; the
 * caller keeps prep>0 for up to 3 lines). A (re)prepare starts the variable
 * clean. */
static void scl_capture(struct scl *s, const char *p)
{
    char nm[SCL_VNAME];
    struct scl_var *v;
    while (s->prep && *p) {
        if (*p != '&' || !lintc_ident_char((unsigned char)p[1])) {
            p++;
            continue;
        }
        p++;
        if (scl_read_ident(&p, nm, sizeof nm)) {
            v = scl_var(s, nm, 1);
            if (v)
                v->live = 0;
            s->prep = 0;
        }
    }
}

static void scl_mark(struct scl *s, const char *args, int live, int create)
{
    char nm[SCL_VNAME];
    struct scl_var *v;
    if (!scl_read_ident(&args, nm, sizeof nm))
        return;
    v = scl_var(s, nm, create);
    if (v)
        v->live = live;
}

static void scl_macro(struct scl *s, const char *name)
{
    int i;
    for (i = 0; i < s->nvars; i++) {
        if (!s->vars[i].live)
            continue;
        fprintf(s->out,
                "%s:%d: %s returns while sqlite cursor '%s' is live "
                "(stepped, not finalized)\n",
                s->path, s->lineno, name, s->vars[i].name);
        s->hits++;
        return;
    }
}

/* Learn the stmt (2nd) argument of an activerecord.h preparing macro: skip
 * the ndb argument to the first top-level comma on this line, then read one
 * identifier. A multi-line first argument is a documented miss. `live` is 1
 * for the self-contained query/exec helpers (they step internally); `track`
 * pushes a closer so the variable clears at the invocation's own closing
 * paren (they also finalize internally). */
static void scl_learn2(struct scl *s, const char *args, int live, int track)
{
    const char *p = args;
    char nm[SCL_VNAME];
    struct scl_var *v;
    while (*p == ' ' || *p == '\t')
        p++;
    while (*p && *p != ',' && *p != '(')
        p++;
    if (*p != ',')
        return;
    p++;
    if (!scl_read_ident(&p, nm, sizeof nm))
        return;
    v = scl_var(s, nm, 1);
    if (!v)
        return;
    v->live = live;
    if (!track || s->nclosers >= SCL_VARS)
        return;
    s->clos_var[s->nclosers] = (int)(v - s->vars);
    s->clos_depth[s->nclosers] = s->pdepth;
    s->nclosers++;
}

static void scl_tok(struct scl *s, const char **pp)
{
    const char *p = *pp;
    size_t t;
    for (t = 0; t < sizeof scl_toks / sizeof scl_toks[0]; t++) {
        size_t adv = scl_call_at(p, scl_toks[t].name);
        const char *args = p + adv;
        if (!adv)
            continue;
        /* Step marks live only a variable this function's own sqlite3_prepare*
         * or AR preparing macro introduced. A step on an unknown name is a
         * CACHED statement prepared elsewhere (ws->stmt_*,
         * ci_store_insert_prepare, ...) whose owner resets it on next use and
         * releases it at close — out of scope, and flagging it would
         * false-positive the cached-statement idiom. */
        switch (scl_toks[t].kind) {
        case SCL_PREP:   s->prep = 3; scl_capture(s, args); break;
        case SCL_PREP2:  scl_learn2(s, args, 0, 0); break;
        case SCL_PREP2C: scl_learn2(s, args, 1, 1); break;
        case SCL_STEP:   scl_mark(s, args, 1, 0); break;
        case SCL_CLEAR:  scl_mark(s, args, 0, 0); break;
        default:         scl_macro(s, scl_toks[t].name); break;
        }
        /* Land on the call's '(' so the walk counts it; every call site then
         * keeps pdepth balanced, which the PREP2C closers rely on. */
        *pp = args - 1;
        return;
    }
    while (lintc_ident_char((unsigned char)*p))
        p++;
    *pp = p;
}

static void scl_close_brace(struct scl *s)
{
    if (--s->depth > 0)
        return;
    s->depth = 0;
    s->nvars = 0;
    s->prep = 0;
    s->nclosers = 0;
}

static void scl_close_paren(struct scl *s)
{
    s->pdepth--;
    while (s->nclosers > 0 &&
           s->pdepth <= s->clos_depth[s->nclosers - 1]) {
        s->nclosers--;
        s->vars[s->clos_var[s->nclosers]].live = 0;
    }
}

static void scl_walk(struct scl *s, const char *clean)
{
    const char *p = clean;
    while (*p) {
        int c = (unsigned char)*p;
        if (c == '{') {
            s->depth++;
            p++;
        } else if (c == '}') {
            scl_close_brace(s);
            p++;
        } else if (c == '(') {
            s->pdepth++;
            p++;
        } else if (c == ')') {
            scl_close_paren(s);
            p++;
        } else if (s->prep && c == '&' &&
                   lintc_ident_char((unsigned char)p[1])) {
            p++;
            scl_capture(s, p - 1);
        } else if (lintc_ident_char(c) && !(c >= '0' && c <= '9')) {
            scl_tok(s, &p);
        } else {
            p++;
        }
    }
}

static int scl_scan(struct scl *fs, FILE *f)
{
    char line[SCL_LINE];
    char clean[SCL_LINE];
    while (fgets(line, (int)sizeof line, f)) {
        fs->lineno++;
        /* cstrip_line returns 1 on success, 0 on overflow (out untouched).
         * SCL_LINE-sized fgets reads keep n < cap, so 0 is defensive. */
        if (cstrip_line(&fs->strip, line, strlen(line), clean,
                        sizeof clean) == 0)
            return 2;
        scl_walk(fs, clean);
        if (fs->prep > 0)
            fs->prep--;
    }
    return 0;
}

static int scl_file(const char *path, FILE *out, int *hits)
{
    struct scl fs;
    FILE *f;
    int rc;
    memset(&fs, 0, sizeof fs);
    fs.out = out;
    fs.path = path;
    f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "check_sqlite_cursor_lifetime: UNPROVEN — cannot "
                "read %s\n", path);
        return 2;
    }
    rc = scl_scan(&fs, f);
    fclose(f);
    *hits = fs.hits;
    return rc;
}

static int scl_is_c(const char *path)
{
    size_t n = strlen(path);
    if (n < 3 || path[n - 2] != '.')
        return 0;
    return path[n - 1] == 'c' || path[n - 1] == 'h';
}

static int scl_on_idx(const char *path, int stage, void *ctx)
{
    struct scl_acc *a = ctx;
    int hits = 0;
    int rc;
    (void)stage;
    if (!scl_is_c(path) || lint_path_is_excluded(path))
        return 0;
    rc = scl_file(path, a->out, &hits);
    if (rc)
        return rc;
    a->hits += hits;
    a->scanned++;
    return 0;
}

static int scl_on_walk(const char *path, void *ctx)
{
    return scl_on_idx(path, 0, ctx);
}

static int scl_collect(struct scl_acc *a)
{
    static const char *const roots[] = {
        "core", "engine", "contexts", "cognition", "platform", "tools",
        "tests", "apps",
    };
    struct stat st;
    char bad[8] = {0};
    int rc = 0;
    size_t i;
    if (stat(".git", &st) == 0) {
        rc = lint_git_index_foreach(scl_on_idx, a, bad);
        if (rc)
            fprintf(stderr, "check_sqlite_cursor_lifetime: UNPROVEN — git "
                    "index%s%s\n", bad[0] ? " extension " : "", bad);
        return rc;
    }
    for (i = 0; rc == 0 && i < sizeof roots / sizeof roots[0]; i++)
        rc = walk_src(roots[i], 1, scl_on_walk, a);
    return rc;
}

static int scl_run(void)
{
    struct scl_acc a;
    memset(&a, 0, sizeof a);
    a.out = stdout;
    if (scl_collect(&a) != 0)
        return 2;
    if (gate_require_scanned(a.scanned, 1000,
                             "check-sqlite-cursor-lifetime", "C sources") != 0)
        return 2;
    if (!a.hits) {
        printf("check_sqlite_cursor_lifetime: PASS — %d file(s), no stepped "
               "cursor returned past\n", a.scanned);
        return 0;
    }
    printf("\ncheck_sqlite_cursor_lifetime: %d stepped cursor(s) live across "
           "a returning error macro\n\n", a.hits);
    fputs("LOG_FAIL/LOG_ERR/LOG_NULL/LOG_RETURN/GUARD* RETURN from the "
          "caller, so a sqlite3_finalize written after them never runs and "
          "the parked statement pins the connection's WAL read snapshot "
          "(the 2026-09-29 node.db write-plane wedge class). Finalize (or "
          "reset) FIRST, then log-and-return.\n", stdout);
    return 1;
}

/* ── selftest: planted shapes over in-memory streams ─────────────────── */

static int scl_expect(const char *label, const char *src, int want)
{
    struct scl fs;
    FILE *sink = fopen("/dev/null", "w");
    FILE *f = fmemopen((void *)src, strlen(src), "r");
    int rc;
    if (!sink || !f)
        return die("z23-lint: cursor-lifetime selftest stream\n", "");
    memset(&fs, 0, sizeof fs);
    fs.out = sink;
    fs.path = label;
    rc = scl_scan(&fs, f);
    fclose(f);
    fclose(sink);
    if (rc != 0 || fs.hits != want) {
        fprintf(stderr, "check_sqlite_cursor_lifetime selftest: FAIL — %s "
                "hits=%d want=%d rc=%d\n", label, fs.hits, want, rc);
        return 1;
    }
    return 0;
}

static const char scl_src_leak_loop[] =
    "static bool f(sqlite3 *db) {\n"
    "    sqlite3_stmt *s = NULL;\n"
    "    if (sqlite3_prepare_v2(db, \"SELECT x\", -1, &s, NULL) != SQLITE_OK)\n"
    "        LOG_FAIL(\"d\", \"prepare\");\n"
    "    while (sqlite3_step(s) == SQLITE_ROW) {\n"
    "        if (bad())\n"
    "            LOG_FAIL(\"d\", \"bad row\");\n"
    "    }\n"
    "    sqlite3_finalize(s);\n"
    "    return true;\n"
    "}\n";

static const char scl_src_leak_tail[] =
    "static bool f(sqlite3 *db) {\n"
    "    sqlite3_stmt *s = NULL;\n"
    "    if (sqlite3_prepare_v2(db, \"SELECT x\", -1, &s, NULL) != SQLITE_OK)\n"
    "        LOG_FAIL(\"d\", \"prepare\");\n"
    "    int rc = sqlite3_step(s);\n"
    "    if (rc != SQLITE_DONE)\n"
    "        LOG_FAIL(\"d\", \"step\");\n"
    "    sqlite3_finalize(s);\n"
    "    return true;\n"
    "}\n";

static const char scl_src_safe_finalize_first[] =
    "static bool f(sqlite3 *db) {\n"
    "    sqlite3_stmt *s = NULL;\n"
    "    if (sqlite3_prepare_v2(db, \"SELECT x\", -1, &s, NULL) != SQLITE_OK)\n"
    "        LOG_FAIL(\"d\", \"prepare\");\n"
    "    int rc = sqlite3_step(s);\n"
    "    sqlite3_finalize(s);\n"
    "    if (rc != SQLITE_DONE)\n"
    "        LOG_FAIL(\"d\", \"step\");\n"
    "    return true;\n"
    "}\n";

static const char scl_src_safe_prepare_fail[] =
    "static bool f(sqlite3 *db) {\n"
    "    sqlite3_stmt *s = NULL;\n"
    "    if (sqlite3_prepare_v2(db, \"SELECT x\", -1, &s, NULL) != SQLITE_OK) {\n"
    "        GUARD_NOT_NULL(db, \"d\", \"db\");\n"
    "    }\n"
    "    sqlite3_finalize(s);\n"
    "    return true;\n"
    "}\n";

static const char scl_src_leak_second_var[] =
    "static bool f(sqlite3 *db) {\n"
    "    sqlite3_stmt *a = NULL, *b = NULL;\n"
    "    sqlite3_prepare_v2(db, \"A\", -1, &a, NULL);\n"
    "    sqlite3_prepare_v2(db, \"B\", -1, &b, NULL);\n"
    "    sqlite3_step(a);\n"
    "    sqlite3_step(b);\n"
    "    sqlite3_finalize(a);\n"
    "    LOG_ERR(\"d\", \"only a was finalized\");\n"
    "}\n";

static const char scl_src_leak_wrapper[] =
    "static bool f(sqlite3 *db) {\n"
    "    sqlite3_stmt *s = NULL;\n"
    "    sqlite3_prepare_v2(db,\n"
    "        \"SELECT x FROM t\",\n"
    "        -1, &s, NULL);\n"
    "    while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {\n"
    "        GUARD(s != NULL, \"d\", \"live\");\n"
    "    }\n"
    "    sqlite3_finalize(s);\n"
    "    return true;\n"
    "}\n";

static const char scl_src_safe_reset[] =
    "static bool f(sqlite3 *db) {\n"
    "    sqlite3_stmt *s = NULL;\n"
    "    sqlite3_prepare_v2(db, \"SELECT x\", -1, &s, NULL);\n"
    "    sqlite3_step(s);\n"
    "    sqlite3_reset(s);\n"
    "    LOG_RETURN(false, \"d\", \"reset released the cursor\");\n"
    "}\n";

static const char scl_src_safe_decoy[] =
    "static bool f(sqlite3 *db) {\n"
    "    sqlite3_stmt *s = NULL;\n"
    "    sqlite3_prepare_v2(db, \"SELECT x\", -1, &s, NULL);\n"
    "    /* sqlite3_step(s) in a comment does not step */\n"
    "    say(\"sqlite3_step(s) in a string does not step\");\n"
    "    sqlite3_finalize(s);\n"
    "    LOG_FAIL(\"d\", \"no live cursor\");\n"
    "}\n";

static const char scl_src_safe_two_fns[] =
    "static bool g(sqlite3 *db) {\n"
    "    sqlite3_stmt *s = NULL;\n"
    "    sqlite3_prepare_v2(db, \"SELECT x\", -1, &s, NULL);\n"
    "    sqlite3_step(s);\n"
    "    sqlite3_finalize(s);\n"
    "    return true;\n"
    "}\n"
    "static bool h(sqlite3 *db) {\n"
    "    if (!db)\n"
    "        LOG_NULL(\"d\", \"clean function after a clean one\");\n"
    "    return db;\n"
    "}\n";

/* A returning macro inside an AR_QUERY_LIST row_code skips the expansion's
 * internal AR_FINALIZE — the exact wedge class the macro shape hides. */
static const char scl_src_leak_ar_query_list[] =
    "static int f(struct node_db *ndb, struct row *out, size_t max) {\n"
    "    sqlite3_stmt *s = NULL;\n"
    "    AR_QUERY_LIST(ndb, s,\n"
    "        \"SELECT x FROM t LIMIT ?\",\n"
    "        out, max,\n"
    "        AR_BIND_INT(s, 1, (int)max),\n"
    "        if (!row_read(s, &out[count]))\n"
    "            LOG_FAIL(\"d\", \"row read failed\");\n"
    "        );\n"
    "}\n";

/* The established safe idiom inside row_code: AR_FINALIZE before the
 * returning macro (market_seller_key msk_read shape). */
static const char scl_src_safe_ar_finalize_in_row[] =
    "static bool f(struct node_db *ndb, struct row *row) {\n"
    "    sqlite3_stmt *s = NULL;\n"
    "    AR_QUERY_ONE_BOOL(ndb, s,\n"
    "        \"SELECT x,n FROM t WHERE id=1\", ;,\n"
    "        row->x = AR_COL_INT(s, 0);\n"
    "        int n = AR_COL_BYTES(s, 1);\n"
    "        if (n != 32) {\n"
    "            AR_FINALIZE(s);\n"
    "            LOG_FAIL(\"d\", \"bad length\");\n"
    "        }\n"
    "        );\n"
    "    return true;\n"
    "}\n";

/* The self-contained helper finalizes at its own closing paren, so a
 * returning macro AFTER the invocation is fine. */
static const char scl_src_safe_ar_after_close[] =
    "static int f(struct node_db *ndb, struct row *out, size_t max) {\n"
    "    sqlite3_stmt *s = NULL;\n"
    "    AR_QUERY_LIST(ndb, s,\n"
    "        \"SELECT x FROM t LIMIT ?\",\n"
    "        out, max,\n"
    "        AR_BIND_INT(s, 1, (int)max),\n"
    "        row_read(s, &out[count]));\n"
    "    if (max == 0)\n"
    "        LOG_RETURN(0, \"d\", \"nothing asked\");\n"
    "    return 0;\n"
    "}\n";

/* AR_PREPARE_BOOL leaves the release to the function: stepping it and then
 * returning through an error macro without AR_FINALIZE is a leak. */
static const char scl_src_leak_ar_prepare_bool[] =
    "static bool f(struct node_db *ndb) {\n"
    "    sqlite3_stmt *s = NULL;\n"
    "    AR_PREPARE_BOOL(ndb, s, \"DELETE FROM t WHERE id=1\");\n"
    "    bool ok = AR_STEP_DONE(s);\n"
    "    if (!ok)\n"
    "        LOG_RETURN(false, \"d\", \"delete failed\");\n"
    "    AR_FINALIZE(s);\n"
    "    return true;\n"
    "}\n";

static const char scl_src_safe_ar_prepare_bool[] =
    "static bool f(struct node_db *ndb) {\n"
    "    sqlite3_stmt *s = NULL;\n"
    "    AR_PREPARE_BOOL(ndb, s, \"DELETE FROM t WHERE id=1\");\n"
    "    bool ok = AR_STEP_DONE(s);\n"
    "    AR_FINALIZE(s);\n"
    "    if (!ok)\n"
    "        LOG_RETURN(false, \"d\", \"delete failed\");\n"
    "    return true;\n"
    "}\n";

int check_sqlite_cursor_lifetime_selftest(void)
{
    static const struct { const char *label; const char *src; int want; }
        cases[] = {
            { "leak-loop", scl_src_leak_loop, 1 },
            { "leak-tail", scl_src_leak_tail, 1 },
            { "safe-finalize-first", scl_src_safe_finalize_first, 0 },
            { "safe-prepare-fail", scl_src_safe_prepare_fail, 0 },
            { "leak-second-var", scl_src_leak_second_var, 1 },
            { "leak-wrapper-multiline-prepare", scl_src_leak_wrapper, 1 },
            { "safe-reset", scl_src_safe_reset, 0 },
            { "safe-decoy", scl_src_safe_decoy, 0 },
            { "safe-two-fns", scl_src_safe_two_fns, 0 },
            { "leak-ar-query-list-row-code", scl_src_leak_ar_query_list, 1 },
            { "safe-ar-finalize-in-row", scl_src_safe_ar_finalize_in_row, 0 },
            { "safe-ar-after-close", scl_src_safe_ar_after_close, 0 },
            { "leak-ar-prepare-bool", scl_src_leak_ar_prepare_bool, 1 },
            { "safe-ar-prepare-bool", scl_src_safe_ar_prepare_bool, 0 },
        };
    size_t i;
    int bad = 0;
    for (i = 0; i < sizeof cases / sizeof cases[0]; i++)
        bad |= scl_expect(cases[i].label, cases[i].src, cases[i].want);
    if (bad)
        return 1;
    if (scl_run() != 0) {
        fprintf(stderr, "check_sqlite_cursor_lifetime selftest: FAIL — "
                "clean tree reported a violation\n");
        return 1;
    }
    fputs("check_sqlite_cursor_lifetime selftest: PASS — 14 planted shapes, "
          "clean tree green\n", stdout);
    return 0;
}

int check_sqlite_cursor_lifetime_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return scl_run();
}
