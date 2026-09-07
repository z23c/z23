/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate — command-availability truthfulness (HARD). Sibling of
 * check_command_contract.sh, same scan shape, different predicate.
 *
 * The typed command surface is declared in engine/composition/commands (one
 * .def file per area) and expanded by engine/composition/src/command_catalog.c into one
 * immutable g_catalog_commands[]. Every leaf carries an `availability`
 * (READY / COMPAT / PLANNED, see
 * engine/modules/kernel/include/kernel/command_registry.h) that the engine
 * acts on: a READY leaf is dispatched to its handler, a PLANNED leaf is
 * fail-closed with a typed BLOCKED reply that quotes its
 * `availability_reason`.
 *
 * Two ways that declaration can LIE, both compile clean:
 *
 *   1. A READY leaf that binds no handler. `discover help` advertises it as
 *      executable, the operator invokes it, and the engine has nothing to
 *      call. READY with a NULL handler is a promise the binary cannot keep.
 *
 *   2. A PLANNED leaf with an empty availability_reason. The refusal is
 *      honest about REFUSING but says nothing about WHY, so the operator
 *      cannot tell "not built yet" from "your node is misconfigured" and has
 *      no next move.
 *
 * The same rule extends to the two neighbouring shapes: a COMPAT leaf that
 * names no compat_target (and, for COMPAT_COMMAND, no reason) is the same
 * dead end; a DEV leaf is READY in a dev build and COMPAT in a release
 * build, so its handler must be non-NULL and its release reason/target
 * non-empty for the same reasons as (1) and (2).
 *
 * Anti-hollow: the leaf population is parsed with a hand-rolled
 * character-level state machine (no regex — the shell original does not use
 * one here either), not grepped, and the realized per-shape counts are
 * floor-gated. The parser also asserts each macro's ARITY against the
 * grammar in command_catalog.c — if a macro gains or loses an argument,
 * this gate aborts LOUD (exit 2) rather than silently reading the wrong
 * slot and reporting a clean scan.
 *
 * Ported from tools/lint/check_command_availability_truthful.sh, which is
 * now a 3-line exec shim onto this binary.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

enum {
    CAT_MAX_FILES = 4096,
    CAT_PATH = 512,
    CAT_MAX_ARGS = 32,
    CAT_ARG_CAP = 8192,
    CAT_TOK_CAP = 64,
    CAT_VIOL_CAP = 262144,
    CAT_FATAL_CAP = 65536,
};

struct cat_macro_rule {
    const char *name;
    int arity;
    int handler_arg;   /* 1-based; 0 = no handler check */
    int reason_arg1;   /* 1-based; 0 = no first reason check */
    const char *reason1_label;
    int reason_arg2;   /* 1-based; 0 = no second reason check */
    const char *reason2_label;
    int is_ready;       /* counts toward nready (1) or nplanned (0) */
};

static const struct cat_macro_rule k_cat_rules[] = {
    { "ZCL_COMMAND_READY_READ", 22, 22, 0, NULL, 0, NULL, 1 },
    { "ZCL_COMMAND_READY_COMMAND", 25, 25, 0, NULL, 0, NULL, 1 },
    { "ZCL_COMMAND_DEV_READ", 22, 20, 21, "the release-build availability_reason",
      22, "the release-build compat_target", 1 },
    { "ZCL_COMMAND_DEV_COMMAND", 26, 24, 25, "the release-build availability_reason",
      26, "the release-build compat_target", 1 },
    { "ZCL_COMMAND_PLANNED_READ", 20, 0, 20, "availability_reason", 0, NULL, 0 },
    { "ZCL_COMMAND_PLANNED_COMMAND", 25, 0, 25, "availability_reason", 0, NULL, 0 },
    { "ZCL_COMMAND_COMPAT_READ", 21, 0, 21, "compat_target", 0, NULL, 0 },
    { "ZCL_COMMAND_COMPAT_COMMAND", 26, 0, 25, "availability_reason",
      26, "compat_target", 0 },
};
enum { CAT_N_RULES = sizeof k_cat_rules / sizeof k_cat_rules[0] };

struct cat_ctx {
    /* per-file-reset scan state */
    int in_comment, in_str, esc, collecting, depth;
    char tok[CAT_TOK_CAP];
    size_t tok_len;
    char args[CAT_MAX_ARGS][CAT_ARG_CAP];
    int nargs;
    size_t cur_len;
    const struct cat_macro_rule *rule;
    char startfile[CAT_PATH];
    int startline;
    int line;

    /* accumulators across the whole scan */
    int nleaf, nready, nplanned;
    char viol[CAT_VIOL_CAP];
    size_t viol_len;
    int nviol;
    char fatal[CAT_FATAL_CAP];
    size_t fatal_len;
    int nfatal;
};

/* Bounded copy that never triggers -Wformat-truncation the way an snprintf
 * "%s" of a large fixed-size source array can at -O2 (once GCC inlines back
 * to the caller's declared array bound): no printf-family call at all, just
 * an explicit length clamp. */
static void cat_copy_trunc(char *dst, size_t dcap, const char *src)
{
    size_t n = strlen(src);
    if (n + 1 > dcap) n = dcap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static const struct cat_macro_rule *cat_lookup(const char *name)
{
    for (size_t i = 0; i < CAT_N_RULES; i++)
        if (strcmp(k_cat_rules[i].name, name) == 0)
            return &k_cat_rules[i];
    return NULL;
}

static int cat_add_fatal(struct cat_ctx *c, const char *msg)
{
    int k = snprintf(c->fatal + c->fatal_len, sizeof c->fatal - c->fatal_len,
                      "  %s:%d: %s — %s\n", c->startfile, c->startline,
                      c->rule ? c->rule->name : "?", msg);
    if (ovf(k, sizeof c->fatal - c->fatal_len))
        return die("z23-lint: derived buffer overflow\n", "");
    c->fatal_len += (size_t)k;
    c->nfatal++;
    return 0;
}

static void cat_trim(char *s)
{
    size_t n = strlen(s), start = 0;
    while (start < n && isspace((unsigned char)s[start])) start++;
    size_t end = n;
    while (end > start && isspace((unsigned char)s[end - 1])) end--;
    size_t out = 0;
    for (size_t i = start; i < end; i++) s[out++] = s[i];
    s[out] = '\0';
}

/* All '\"' pairs, then any remaining '"', then all whitespace, stripped —
 * matches the shell's literal_body(): non-empty iff the quoted argument
 * says something. */
static void cat_literal_body(const char *in, char *out, size_t cap)
{
    size_t o = 0;
    for (const char *p = in; *p && o + 1 < cap; ) {
        if (p[0] == '\\' && p[1] == '"') { p += 2; continue; }
        if (*p == '"') { p++; continue; }
        if (isspace((unsigned char)*p)) { p++; continue; }
        out[o++] = *p++;
    }
    out[o] = '\0';
}

static void cat_pathof(struct cat_ctx *c, char *out, size_t cap)
{
    char tmp[CAT_ARG_CAP];
    cat_copy_trunc(tmp, sizeof tmp, c->nargs >= 1 ? c->args[0] : "");
    size_t o = 0;
    for (const char *p = tmp; *p && o + 1 < cap; p++)
        if (*p != '"') out[o++] = *p;
    out[o] = '\0';
    cat_trim(out);
}

static int cat_add_violation(struct cat_ctx *c, const char *msg)
{
    char path[CAT_ARG_CAP];
    cat_pathof(c, path, sizeof path);
    int k = snprintf(c->viol + c->viol_len, sizeof c->viol - c->viol_len,
                      "%s:%d: %s leaf %s\n    %s\n", c->startfile, c->startline,
                      c->rule ? c->rule->name : "?", path, msg);
    if (ovf(k, sizeof c->viol - c->viol_len))
        return die("z23-lint: derived buffer overflow\n", "");
    c->viol_len += (size_t)k;
    c->nviol++;
    return 0;
}

static int cat_check_handler(struct cat_ctx *c, int idx)
{
    if (idx < 1 || idx > c->nargs) return 0;
    char h[CAT_ARG_CAP];
    cat_copy_trunc(h, sizeof h, c->args[idx - 1]);
    cat_trim(h);
    if (h[0] == '\0' || strcmp(h, "NULL") == 0 || strcmp(h, "0") == 0) {
        char msg[CAT_ARG_CAP + 256];
        snprintf(msg, sizeof msg,
                 "declares availability READY but binds no handler (handler "
                 "argument is \"%s\"): the catalog advertises an executable "
                 "command the engine cannot dispatch.", h);
        return cat_add_violation(c, msg);
    }
    return 0;
}

static int cat_check_reason(struct cat_ctx *c, int idx, const char *what)
{
    if (idx < 1 || idx > c->nargs) return 0;
    char body[CAT_ARG_CAP];
    cat_literal_body(c->args[idx - 1], body, sizeof body);
    if (body[0] == '\0') {
        char msg[512];
        snprintf(msg, sizeof msg,
                 "refuses without saying why: %s is empty. A typed refusal "
                 "with no stated cause is a silent stall; name the exact "
                 "missing code path.", what);
        return cat_add_violation(c, msg);
    }
    return 0;
}

static int cat_finish_leaf(struct cat_ctx *c)
{
    c->nleaf++;
    const struct cat_macro_rule *r = c->rule;
    if (!r) return 0;
    if (r->is_ready) c->nready++; else c->nplanned++;
    if (c->nargs != r->arity) {
        char msg[256];
        snprintf(msg, sizeof msg,
                 "macro grammar drift: expected %d arguments, parsed %d. "
                 "Re-read the macro definition in "
                 "engine/composition/src/command_catalog.c and fix this "
                 "gate before trusting it.", r->arity, c->nargs);
        return cat_add_fatal(c, msg);
    }
    int rc = 0;
    if (r->handler_arg) rc = rc || cat_check_handler(c, r->handler_arg);
    if (r->reason_arg1) rc = rc || cat_check_reason(c, r->reason_arg1, r->reason1_label);
    if (r->reason_arg2) rc = rc || cat_check_reason(c, r->reason_arg2, r->reason2_label);
    return rc;
}

static int cat_arg_putc(struct cat_ctx *c, char ch)
{
    if (c->nargs >= CAT_MAX_ARGS)
        return die("z23-lint: derived buffer overflow\n", "");
    if (c->cur_len + 1 >= CAT_ARG_CAP)
        return die("z23-lint: derived buffer overflow\n", "");
    c->args[c->nargs][c->cur_len++] = ch;
    c->args[c->nargs][c->cur_len] = '\0';
    return 0;
}

static int cat_arg_close(struct cat_ctx *c)
{
    if (c->nargs >= CAT_MAX_ARGS)
        return die("z23-lint: derived buffer overflow\n", "");
    c->args[c->nargs][c->cur_len] = '\0';
    c->nargs++;
    c->cur_len = 0;
    return 0;
}

static int cat_feed_in_comment(struct cat_ctx *c, char ch, char next)
{
    if (ch == '*' && next == '/') { c->in_comment = 0; return 1; }
    return 0;
}

static int cat_feed_in_str(struct cat_ctx *c, char ch)
{
    if (c->collecting && cat_arg_putc(c, ch)) return -1;
    if (c->esc) c->esc = 0;
    else if (ch == '\\') c->esc = 1;
    else if (ch == '"') c->in_str = 0;
    return 0;
}

static int cat_feed_collecting(struct cat_ctx *c, char ch)
{
    if (ch == '(') {
        c->depth++;
        return cat_arg_putc(c, ch) ? -1 : 0;
    }
    if (ch == ')') {
        c->depth--;
        if (c->depth == 0) {
            if (cat_arg_close(c)) return -1;
            c->collecting = 0;
            return cat_finish_leaf(c) ? -1 : 0;
        }
        return cat_arg_putc(c, ch) ? -1 : 0;
    }
    if (ch == ',' && c->depth == 1)
        return cat_arg_close(c) ? -1 : 0;
    return cat_arg_putc(c, ch) ? -1 : 0;
}

static void cat_tok_push(struct cat_ctx *c, char ch)
{
    if (c->tok_len + 1 < sizeof c->tok) c->tok[c->tok_len++] = ch;
    if (c->tok_len < sizeof c->tok) c->tok[c->tok_len] = '\0';
}

static int cat_maybe_open_macro(struct cat_ctx *c)
{
    c->tok[c->tok_len] = '\0';
    const struct cat_macro_rule *r = cat_lookup(c->tok);
    if (r) {
        c->rule = r;
        c->collecting = 1;
        c->depth = 1;
        c->nargs = 0;
        c->cur_len = 0;
        c->startline = c->line;
    }
    c->tok_len = 0;
    return 0;
}

static int cat_feed_scanning(struct cat_ctx *c, char ch, char next)
{
    if (ch == '/' && next == '*') { c->in_comment = 1; return 1; }
    if (ch == '"') {
        c->in_str = 1; c->esc = 0;
        if (c->collecting && cat_arg_putc(c, ch)) return -1;
        return 0;
    }
    if (c->collecting) return cat_feed_collecting(c, ch);
    if (isalnum((unsigned char)ch) || ch == '_') { cat_tok_push(c, ch); return 0; }
    if (ch == '(') return cat_maybe_open_macro(c);
    c->tok_len = 0;
    return 0;
}

/* One character of the file. Mirrors the shell awk parser's per-character
 * state machine exactly: C block comments and string literals (with
 * backslash escapes) are tracked so a macro name inside prose, or a comma
 * inside a string literal, is never mistaken for argument structure. */
static int cat_feed_char(struct cat_ctx *c, char ch, char next)
{
    if (c->in_comment) return cat_feed_in_comment(c, ch, next);
    if (c->in_str) return cat_feed_in_str(c, ch);
    return cat_feed_scanning(c, ch, next);
}

static int cat_scan_file(struct cat_ctx *c, const char *path, const char *buf, size_t n)
{
    /* File-boundary reset, matching the shell's FNR == 1 handler. */
    c->in_comment = 0; c->in_str = 0; c->esc = 0; c->collecting = 0;
    c->tok_len = 0; c->line = 1;
    cat_copy_trunc(c->startfile, sizeof c->startfile, path);
    for (size_t i = 0; i < n; i++) {
        char ch = buf[i], next = (i + 1 < n) ? buf[i + 1] : '\0';
        int consumed_extra = cat_feed_char(c, ch, next);
        if (consumed_extra < 0) return 2;
        if (consumed_extra == 1) i++;
        if (ch == '\n') c->line++;
    }
    return 0;
}

static int cat_collect_cb(const char *path, void *vctx)
{
    struct { char (*names)[CAT_PATH]; int *n; } *ctx = vctx;
    if (*ctx->n >= CAT_MAX_FILES)
        return die("z23-lint: derived buffer overflow\n", "");
    cat_copy_trunc(ctx->names[*ctx->n], CAT_PATH, path);
    (*ctx->n)++;
    return 0;
}

static int cat_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static int cat_env_int_or(const char *name, int fallback)
{
    const char *e = getenv(name);
    return (e && e[0]) ? atoi(e) : fallback;
}

static int cat_read_file(const char *path, char **out_buf, size_t *out_sz)
{
    FILE *f = fopen(path, "r");
    if (!f) return die("z23-lint: cannot open %s\n", path);
    struct stat st;
    if (fstat(fileno(f), &st) != 0) {
        fclose(f);
        return die("z23-lint: cannot open %s\n", path);
    }
    size_t sz = (size_t)st.st_size;
    char *buf = malloc(sz + 1); // raw-alloc-ok:lint-runtime
    if (!buf) { fclose(f); return die("z23-lint: derived buffer overflow\n", ""); }
    size_t got = fread(buf, 1, sz, f);
    int rf_err = ferror(f);
    fclose(f);
    if (rf_err || got != sz) { free(buf); return die("z23-lint: cannot open %s\n", path); }
    *out_buf = buf;
    *out_sz = sz;
    return 0;
}

static int cat_scan_all(struct cat_ctx *c, char names[][CAT_PATH], int nfiles)
{
    for (int i = 0; i < nfiles; i++) {
        char *buf = NULL;
        size_t sz = 0;
        int rc = cat_read_file(names[i], &buf, &sz);
        if (rc) return rc;
        rc = cat_scan_file(c, names[i], buf, sz);
        free(buf);
        if (rc) return rc;
    }
    return 0;
}

static int cat_report(struct cat_ctx *c, const char *mode, int ready_floor,
                       int planned_floor, FILE *out, FILE *err)
{
    if (c->collecting)
        cat_add_fatal(c, "unterminated macro invocation: the parser reached "
                          "EOF with an open argument list.");
    if (c->nfatal > 0) {
        fputs(c->fatal, err);
        fputs("check_command_availability_truthful: FATAL — macro grammar drift.\n"
              "  This gate reads a fixed argument slot per macro shape. A changed\n"
              "  arity means it would be reading the WRONG slot, so it refuses to\n"
              "  report a verdict at all. Fix the arity table in this script\n"
              "  against engine/composition/src/command_catalog.c.\n", err);
        return 2;
    }
    char h1[128], h2[128];
    snprintf(h1, sizeof h1, "READY/DEV leaf population collapsed under floor (parsed %d)", c->nready);
    int rc = gate_require_scanned(c->nready, ready_floor, "check_command_availability_truthful", h1);
    if (rc) return rc;
    snprintf(h2, sizeof h2, "PLANNED/COMPAT leaf population collapsed under floor (parsed %d)", c->nplanned);
    rc = gate_require_scanned(c->nplanned, planned_floor, "check_command_availability_truthful", h2);
    if (rc) return rc;
    if (c->nviol > 0) {
        fputs(c->viol, out);
        fprintf(out, "[check_command_availability_truthful] %d leaf(s) whose "
                     "declared availability does not match what the catalog "
                     "binds (mode: %s)\n", c->nviol, mode);
        fputs("  A READY leaf must bind a non-NULL handler; a PLANNED/COMPAT leaf\n"
              "  must state a non-empty availability_reason (and a COMPAT leaf its\n"
              "  compat_target). See engine/modules/kernel/include/kernel/command_registry.h\n"
              "  (enum zcl_command_availability) and engine/composition/commands/README.md.\n",
              out);
        if (strcmp(mode, "FAIL") == 0) return 1;
    }
    fprintf(out, "[check_command_availability_truthful] PASS (%d leaves: %d "
                 "executable — all bind a handler; %d refusing — all name a "
                 "cause)\n", c->nleaf, c->nready, c->nplanned);
    return 0;
}

static int cat_run_at(const char *dir, int ready_floor, int planned_floor,
                       const char *mode, FILE *out, FILE *err)
{
    static char names[CAT_MAX_FILES][CAT_PATH];
    int nfiles = 0;
    struct { char (*names)[CAT_PATH]; int *n; } ctx = { names, &nfiles };
    int rc = walk_src(dir, 2 /* *.def */, cat_collect_cb, &ctx);
    if (rc) return rc;
    qsort(names, (size_t)nfiles, CAT_PATH, cat_cmp);

    char hint[512];
    snprintf(hint, sizeof hint, "no *.def under: %s", dir);
    rc = gate_require_scanned(nfiles, 1, "check_command_availability_truthful", hint);
    if (rc) return rc;

    static struct cat_ctx c;
    memset(&c, 0, sizeof c);
    rc = cat_scan_all(&c, names, nfiles);
    if (rc) return rc;
    return cat_report(&c, mode, ready_floor, planned_floor, out, err);
}

int check_command_availability_truthful_run(int argc, char **argv)
{
    (void)argc; (void)argv;
    const char *dir = env_or("ZCL_COMMAND_AVAILABILITY_DIR", "engine/composition/commands");
    int ready_floor = cat_env_int_or("ZCL_COMMAND_AVAILABILITY_READY_FLOOR", 160);
    int planned_floor = cat_env_int_or("ZCL_COMMAND_AVAILABILITY_PLANNED_FLOOR", 18);
    const char *mode = env_or("ZCL_LINT_MODE", "FAIL");
    return cat_run_at(dir, ready_floor, planned_floor, mode, stdout, stderr);
}

/* ── selftest ─────────────────────────────────────────────────────────── */

static int cat_hush(int (*fn)(void))
{
    int n = open("/dev/null", O_WRONLY);
    int o = dup(1), e = dup(2);
    if (n < 0 || o < 0 || e < 0) return die("z23-lint: tmpfile failed\n", "");
    int rc = 2;
    if (dup2(n, 1) >= 0 && dup2(n, 2) >= 0) rc = fn();
    fflush(stdout); fflush(stderr); /* buffered stdout else leaks post-restore */
    (void)dup2(o, 1); (void)dup2(e, 2);
    close(n); close(o); close(e);
    return rc;
}

static const char k_cat_clean[] =
    "ZCL_COMMAND_READY_READ(\n"
    "    \"x.test\", \"t\", \"\", \"d\", \"e\", 0, \"f\", \"g\", \"h\", \"\", \"\",\n"
    "    \"i\", A, B, C, D, E, F, G, H, I, zcl_native_handle_x)\n";

static const char k_cat_bad[] =
    "ZCL_COMMAND_READY_READ(\n"
    "    \"x.test\", \"t\", \"\", \"d\", \"e\", 0, \"f\", \"g\", \"h\", \"\", \"\",\n"
    "    \"i\", A, B, C, D, E, F, G, H, I, NULL)\n";

static char g_cat_st_dir[4096];

static int cat_st_prep(const char *content)
{
    const char *td = env_or("TMPDIR", "/tmp");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-cat.XXXXXX", td), sizeof tmpl))
        return 2;
    char *tmp = mkdtemp(tmpl);
    if (!tmp) return die("z23-lint: mkdir failed: %s\n", td);
    cat_copy_trunc(g_cat_st_dir, sizeof g_cat_st_dir, tmp);
    char fpath[4096];
    if (ovf(snprintf(fpath, sizeof fpath, "%s/fixture.def", tmp), sizeof fpath))
        return 2;
    return csr_write(fpath, content);
}

static int cat_st_run(void)
{
    return cat_run_at(g_cat_st_dir, 0, 0, "FAIL", stdout, stderr);
}

static int cat_st_clean(void)
{
    if (cat_st_prep(k_cat_clean)) return 1;
    int rc = cat_hush(cat_st_run);
    (void)rap_rm_rf(g_cat_st_dir);
    return rc != 0;
}

static int cat_st_bad(void)
{
    if (cat_st_prep(k_cat_bad)) return 1;
    int rc = cat_hush(cat_st_run);
    (void)rap_rm_rf(g_cat_st_dir);
    return rc != 1;
}

int check_command_availability_truthful_selftest(void)
{
    int bad = 0;
    bad |= cat_st_clean();
    bad |= cat_st_bad();
    return st_ok(bad, "check_command_availability_truthful selftest: OK\n");
}
