/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — the flag registry lint gate of the C23 lint
 * runtime (check-flag-registry). One family file, one gate: the closed
 * catalog at engine/composition/flags.def is a data file the OTHER seven
 * families have no reason to touch, and this gate's own logic (an X-macro
 * text parser plus a two-shape read-site scanner) does not fit the git-scan,
 * tree-walk, build-config, doc-index, ratchet-ports or landing-proof shapes
 * those families already carry.
 */

/*
 * Gates: check-flag-registry
 * Default landing spot for a FUTURE gate port: a filesystem-tree-walking
 * gate (walk_src/clock_walk/repo_shape_room_dirs) joins gate_tree_walk.c;
 * a git-tracked-enumeration gate (each_zpath/each_zpath_st) joins whichever
 * of gate_git_scan_a.c/gate_git_scan_b.c is currently smaller by wc -l;
 * a proof/landing/receipt-shaped gate joins gate_landing_proof.c; a
 * build-flag/CI-toggle-shaped gate joins gate_build_config.c; only once
 * EVERY existing family is within ~200 lines of the ~1500 cap does a new
 * gate warrant a new family file — name it for its own subject the same
 * way the eight above are named for theirs.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"

enum {
    FR_MAX = 4096,   /* headroom over the ~1154 rows the first sweep found */
    FR_NAME = 96,
    FR_KIND = 24,
    FR_VAL = 64,
    FR_WHY = 512,
    FR_DEF_BUF = 512 * 1024,
};

struct fr_row {
    char name[FR_NAME];
    char kind[FR_KIND];
    char def[FR_VAL];
    char exp[FR_VAL];
    int used;
};

struct fr_ctx {
    struct fr_row *rows;
    int n;
    int files;
    int reads;
    int unreg;
    FILE *out;
};

static const char k_def_path[] = "engine/composition/flags.def";
static const char k_ls_scan[] = "git ls-files -z -- '*.c' '*.h' '*.sh' Makefile";

/* ── flags.def parsing ───────────────────────────────────────────────── */

static int fr_next_quoted(const char **cur, char *out, size_t cap)
{
    const char *p = *cur;
    while (*p && *p != '"')
        p++;
    if (!*p)
        return 0;
    p++;
    const char *start = p;
    while (*p && *p != '"')
        p++;
    if (!*p)
        return 0;
    size_t n = (size_t)(p - start);
    if (n >= cap)
        n = cap - 1;
    memcpy(out, start, n);
    out[n] = '\0';
    *cur = p + 1;
    return 1;
}

static int fr_skip_close(const char **cur)
{
    const char *p = *cur;
    while (*p && *p != ')')
        p++;
    if (!*p)
        return 0;
    *cur = p + 1;
    return 1;
}

static int fr_parse_one(const char **cur, struct fr_row *row)
{
    char why[FR_WHY];
    memset(row, 0, sizeof *row);
    if (!fr_next_quoted(cur, row->name, sizeof row->name))
        return 0;
    if (!fr_next_quoted(cur, row->kind, sizeof row->kind))
        return 0;
    if (!fr_next_quoted(cur, row->def, sizeof row->def))
        return 0;
    if (!fr_next_quoted(cur, row->exp, sizeof row->exp))
        return 0;
    if (!fr_next_quoted(cur, why, sizeof why))
        return 0;
    (void)why;
    return fr_skip_close(cur);
}

struct fr_strip_state {
    int block;
    int line;
    int str;
};

/* One step inside a block comment: blank the byte (newline stays a
 * newline, so line-based reasoning downstream still works), and recognize
 * the star-slash that closes it — including when the comment closes on the
 * very line it opened. */
static size_t fr_strip_in_block(const char *in, size_t i, char *out, size_t o,
                                struct fr_strip_state *st)
{
    char c = in[i], c2 = in[i + 1];
    if (c == '*' && c2 == '/') {
        out[o] = ' ';
        out[o + 1] = ' ';
        st->block = 0;
        return i + 2;
    }
    out[o] = (c == '\n') ? '\n' : ' ';
    return i + 1;
}

/* One step outside any comment: recognizes a quoted string (tracked so a
 * comment opener inside a why_ sentence is never mistaken for a real one)
 * and the two comment openers; anything else passes through untouched. */
static size_t fr_strip_bare(const char *in, size_t i, char *out, size_t o,
                            struct fr_strip_state *st)
{
    char c = in[i], c2 = in[i + 1];
    if (st->str) {
        out[o] = c;
        if (c == '"')
            st->str = 0;
        return i + 1;
    }
    if (c == '"') {
        st->str = 1;
        out[o] = c;
        return i + 1;
    }
    if (c == '/' && c2 == '*') {
        out[o] = out[o + 1] = ' ';
        st->block = 1;
        return i + 2;
    }
    if (c == '/' && c2 == '/') {
        out[o] = out[o + 1] = ' ';
        st->line = 1;
        return i + 2;
    }
    out[o] = c;
    return i + 1;
}

/* Blanks every line-comment tail (two slashes to end of line) and every
 * block-comment span (slash-star to star-slash, multi-line and its
 * star-continuation lines included) to a same-length run of spaces, leaving
 * newlines and everything outside a comment or a quoted string untouched.
 * The output is exactly as long as the input — one char in, one char (or
 * one blank) out — so callers can reuse the input's own buffer size. */
static void fr_strip_comments(const char *in, char *out)
{
    struct fr_strip_state st = { 0, 0, 0 };
    size_t i = 0;
    while (in[i]) {
        size_t o = i;
        size_t next;
        if (st.block)
            next = fr_strip_in_block(in, i, out, o, &st);
        else if (st.line) {
            out[o] = (in[i] == '\n') ? '\n' : ' ';
            if (in[i] == '\n')
                st.line = 0;
            next = i + 1;
        } else
            next = fr_strip_bare(in, i, out, o, &st);
        i = next;
    }
    out[i] = '\0';
}

/* True only when `at` is the first non-blank byte of its (already
 * comment-stripped) line — the defense the verifier asked for beyond
 * blanking comments: a `Z23_FLAG(` that is not itself a row header (mid-line
 * after other code) is never mistaken for one either. */
static int fr_line_starts_here(const char *buf, const char *at)
{
    const char *ls = at;
    while (ls > buf && ls[-1] != '\n')
        ls--;
    while (*ls == ' ' || *ls == '\t')
        ls++;
    return ls == at;
}

static int fr_parse_def_buf(const char *raw, struct fr_row *rows, int cap, int *n)
{
    static const char k_tag[] = "Z23_FLAG(";
    static char stripped[FR_DEF_BUF];
    fr_strip_comments(raw, stripped);
    const char *p = stripped;
    *n = 0;
    while ((p = strstr(p, k_tag)) != NULL) {
        if (!fr_line_starts_here(stripped, p)) {
            p++;
            continue;
        }
        const char *cur = p + (sizeof k_tag - 1);
        if (*n >= cap)
            return die("z23-lint: flags.def registry overflow\n", "");
        if (!fr_parse_one(&cur, &rows[*n]))
            return die("z23-lint: flags.def: malformed Z23_FLAG row\n", "");
        (*n)++;
        p = cur;
    }
    return 0;
}

static int fr_read_file(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    size_t used = fread(buf, 1, cap - 1, f);
    int err = ferror(f);
    fclose(f);
    if (err)
        return die("z23-lint: read failed: %s\n", path);
    buf[used] = '\0';
    return 0;
}

static int fr_kind_ok(const char *k)
{
    static const char *const kinds[] = {
        "env_runtime", "env_build", "env_test", "make_var"
    };
    for (size_t i = 0; i < sizeof kinds / sizeof kinds[0]; i++)
        if (strcmp(k, kinds[i]) == 0)
            return 1;
    return 0;
}

static int fr_validate_kinds(const struct fr_row *rows, int n)
{
    for (int i = 0; i < n; i++) {
        if (fr_kind_ok(rows[i].kind))
            continue;
        return fprintf(stderr,
                "z23-lint: flags.def: %s has kind '%s' (want env_runtime, "
                "env_build, env_test or make_var)\n", rows[i].name,
                rows[i].kind) < 0
            ? die("z23-lint: write failed\n", "") : 2;
    }
    return 0;
}

static int fr_expired(const char *expires, const char *head_date)
{
    if (!expires || strcmp(expires, "-") == 0)
        return 0;
    if (!head_date || !head_date[0])
        return 0;
    return strcmp(expires, head_date) < 0;
}

static int fr_find(const struct fr_row *rows, int n, const char *name)
{
    for (int i = 0; i < n; i++)
        if (strcmp(rows[i].name, name) == 0)
            return i;
    return -1;
}

/* ── read-site scanning: getenv("ZCL_..."), and the lint runtime's env_or /
 * env_int_or wrappers around it, in C; ${ZCL_...}/$ZCL_... in shell and
 * Makefile text. A wrapper read is a read: scanning only getenv() would call
 * a flag that only the lint gates consume dead and demand its row be deleted.
 * The C regex captures the name in group 2 (group 1 is the reader's name),
 * the shell regex in group 1; an enum/status identifier such as ZCL_OK never
 * follows a '$' or one of those call prefixes, so neither pattern ever
 * mistakes one for a flag. */

static regex_t g_fr_c_re, g_fr_sh_re;
static int g_fr_re_ok;

static int fr_ensure_re(void)
{
    if (g_fr_re_ok)
        return 0;
    int cr = pair_comp(&g_fr_c_re, REG_EXTENDED,
                        "(getenv|env_or|env_int_or)\\(\"(ZCL_[A-Z0-9_]+)\"",
                        "", "", "",
                        &g_fr_sh_re, REG_EXTENDED,
                        "\\$\\{?(ZCL_[A-Z0-9_]+)", "", "", "");
    if (cr)
        return cr;
    g_fr_re_ok = 1;
    return 0;
}

static int fr_is_c_path(const char *path)
{
    size_t n = strlen(path);
    return n >= 2 && path[n - 2] == '.' && (path[n - 1] == 'c' || path[n - 1] == 'h');
}

static int fr_report_unreg(struct fr_ctx *ctx, const char *path, int lineno,
                           const char *name)
{
    ctx->unreg++;
    return fprintf(ctx->out, "FAIL %s:%d: %s is not in engine/composition/flags.def\n",
                   path, lineno, name) < 0
        ? die("z23-lint: write failed\n", "") : 0;
}

/* grp is the capture group holding the flag name: 2 for the C regex (whose
 * first group is the reader — getenv, env_or or env_int_or), 1 for shell. */
static int fr_cap_one(const regex_t *re, const char *cursor, char *name, size_t cap,
                      size_t *adv, int base, int grp)
{
    regmatch_t m[3];
    int eflags = base ? REG_NOTBOL : 0;
    if (regexec(re, cursor, 3, m, eflags) != 0 || m[grp].rm_so < 0)
        return 0;
    size_t ln = (size_t)(m[grp].rm_eo - m[grp].rm_so);
    if (ln >= cap)
        ln = cap - 1;
    memcpy(name, cursor + m[grp].rm_so, ln);
    name[ln] = '\0';
    *adv = (size_t)m[0].rm_eo;
    return 1;
}

static int fr_scan_line(struct fr_ctx *ctx, const regex_t *re, int grp,
                        const char *path, int lineno, const char *line)
{
    const char *cursor = line;
    int base = 0;
    for (;;) {
        char name[FR_NAME];
        size_t adv = 0;
        if (!fr_cap_one(re, cursor, name, sizeof name, &adv, base, grp))
            return 0;
        ctx->reads++;
        int idx = fr_find(ctx->rows, ctx->n, name);
        int rc;
        if (idx < 0)
            rc = fr_report_unreg(ctx, path, lineno, name);
        else {
            ctx->rows[idx].used = 1;
            rc = 0;
        }
        if (rc)
            return rc;
        cursor += adv;
        base = 1;
        if (*cursor == '\0')
            return 0;
    }
}

static int fr_scan_file(const char *path, void *vctx)
{
    struct fr_ctx *ctx = vctx;
    int is_c = fr_is_c_path(path);
    const regex_t *re = is_c ? &g_fr_c_re : &g_fr_sh_re;
    int grp = is_c ? 2 : 1;
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    ctx->files++;
    char *line = NULL;
    size_t cap = 0;
    ssize_t nread;
    int lineno = 0, rc = 0;
    while ((nread = getline(&line, &cap, f)) >= 0) {
        lineno++;
        rc = fr_scan_line(ctx, re, grp, path, lineno, line);
        if (rc)
            break;
    }
    return fin(f, line, path, rc);
}

/* ── post-scan reconciliation ────────────────────────────────────────── */

static int fr_check_stale(const struct fr_row *rows, int n, FILE *out)
{
    int fail = 0;
    for (int i = 0; i < n; i++) {
        if (rows[i].used)
            continue;
        fail = 1;
        if (fprintf(out, "FAIL flags.def: %s is registered but no longer read"
                    " — remove the row\n", rows[i].name) < 0)
            return -1;
    }
    return fail;
}

static int fr_check_expired(const struct fr_row *rows, int n, const char *head_date,
                            FILE *out)
{
    int fail = 0;
    for (int i = 0; i < n; i++) {
        if (!fr_expired(rows[i].exp, head_date))
            continue;
        fail = 1;
        if (fprintf(out, "FAIL flags.def: %s expired on %s\n", rows[i].name,
                    rows[i].exp) < 0)
            return -1;
    }
    return fail;
}

/* ── entry points ────────────────────────────────────────────────────── */

static int fr_run_impl(const char *def_path, const char *ls_cmd,
                       const char *head_date, FILE *out)
{
    static char defbuf[FR_DEF_BUF];
    static struct fr_row rows[FR_MAX];

    if (fr_ensure_re())
        return 2;
    if (fr_read_file(def_path, defbuf, sizeof defbuf))
        return 2;
    int n = 0;
    if (fr_parse_def_buf(defbuf, rows, FR_MAX, &n))
        return 2;
    int vk = fr_validate_kinds(rows, n);
    if (vk)
        return vk;

    struct fr_ctx ctx = { .rows = rows, .n = n, .out = out };
    int rc = each_zpath(ls_cmd, fr_scan_file, &ctx);
    if (rc)
        return rc;
    if (ctx.unreg > 0)
        return 1;
    rc = gate_require_scanned(ctx.files, 1, "check-flag-registry",
            "the tracked-file scan (*.c *.h *.sh Makefile) returned no files"
            " — wrong cwd, or the pathspec no longer matches anything.");
    if (rc)
        return rc;
    rc = gate_require_scanned(ctx.reads, 1, "check-flag-registry",
            "the tracked-file scan found zero ZCL_ reads — the scan is hollow.");
    if (rc)
        return rc;

    int fail = fr_check_stale(rows, n, out);
    if (fail < 0)
        return die("z23-lint: write failed\n", "");
    int fail2 = fr_check_expired(rows, n, head_date, out);
    if (fail2 < 0)
        return die("z23-lint: write failed\n", "");
    if (fail || fail2)
        return 1;

    return fprintf(out, "check_flag_registry: OK — %d flags registered, "
                   "%d read sites, 0 unregistered, 0 expired\n", n, ctx.reads) < 0
        ? die("z23-lint: write failed\n", "") : 0;
}

int check_flag_registry_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    char head[32];
    int code = 0;
    if (capture_cmd("git log -1 --format=%cs", head, sizeof head, &code))
        return 2;
    if (code != 0 || !head[0])
        return die("z23-lint: cannot read HEAD commit date "
                   "(git log -1 --format=%%cs)\n", "");
    return fr_run_impl(k_def_path, k_ls_scan, head, stdout);
}

/* ── selftest ────────────────────────────────────────────────────────── */

static int fr_st_case(const char *def_text, const char *src_name,
                      const char *src_text, const char *head_date,
                      const char *ls_cmd, FILE *out, char *ob, size_t obcap,
                      int *rc_out)
{
    if (csr_write("./f.def", def_text))
        return 1;
    if (src_name && csr_write(src_name, src_text))
        return 1;
    *rc_out = fr_run_impl("./f.def", ls_cmd, head_date, out);
    if (csr_slurp(out, ob, obcap))
        return 1;
    return psp_st_reset(out);
}

int check_flag_registry_selftest(void)
{
    char cwd[4096];
    if (!getcwd(cwd, sizeof cwd))
        return die("z23-lint: getcwd failed\n", "");
    char tmpl[] = "/tmp/z23-lint-flagreg-XXXXXX";
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdir failed: %s\n", "/tmp");
    FILE *out = tmpfile();
    if (!out) {
        rmdir(root);
        return die("z23-lint: tmpfile failed\n", "");
    }
    if (chdir(root) != 0) {
        fclose(out);
        rmdir(root);
        return die("z23-lint: cannot scan %s\n", root);
    }

    char ob[4096];
    int rc = 0, bad = 0;

    bad |= fr_st_case("\n", "./a.c",
            "int f(void){ return getenv(\"ZCL_UNKNOWN_X\") != 0; }\n",
            "2026-01-01", "printf '%s\\0' a.c", out, ob, sizeof ob, &rc);
    bad |= rc != 1
        || strstr(ob, "a.c:1: ZCL_UNKNOWN_X is not in engine/composition/flags.def") == NULL;

    bad |= fr_st_case(
            "Z23_FLAG(\"ZCL_KNOWN_X\", \"env_runtime\", \"-\", \"-\",\n \"why\")\n",
            "./b.c", "int f(void){ return getenv(\"ZCL_KNOWN_X\") != 0; }\n",
            "2026-01-01", "printf '%s\\0' b.c", out, ob, sizeof ob, &rc);
    bad |= rc != 0
        || strstr(ob, "check_flag_registry: OK — 1 flags registered, 1 read "
                      "sites, 0 unregistered, 0 expired") == NULL;

    /* A read through the lint runtime's env_or / env_int_or wrappers is a
     * read. Without this the gate calls a flag only a C gate consumes dead
     * and demands its row be deleted — the shape that first caught it. */
    bad |= fr_st_case(
            "Z23_FLAG(\"ZCL_KNOWN_X\", \"env_runtime\", \"-\", \"-\",\n \"why\")\n"
            "Z23_FLAG(\"ZCL_KNOWN_Y\", \"env_runtime\", \"-\", \"-\",\n \"why\")\n",
            "./w.c",
            "int f(void){ return *env_or(\"ZCL_KNOWN_X\", \"d\")\n"
            "                  + env_int_or(\"ZCL_KNOWN_Y\", 1); }\n",
            "2026-01-01", "printf '%s\\0' w.c", out, ob, sizeof ob, &rc);
    bad |= rc != 0
        || strstr(ob, "check_flag_registry: OK — 2 flags registered, 2 read "
                      "sites, 0 unregistered, 0 expired") == NULL;

    /* ... and an UNregistered name reached through a wrapper still fails. */
    bad |= fr_st_case("\n", "./x.c",
            "int f(void){ return *env_or(\"ZCL_UNKNOWN_W\", \"d\"); }\n",
            "2026-01-01", "printf '%s\\0' x.c", out, ob, sizeof ob, &rc);
    bad |= rc != 1
        || strstr(ob, "x.c:1: ZCL_UNKNOWN_W is not in engine/composition/flags.def") == NULL;

    bad |= fr_st_case(
            "/* example: Z23_FLAG(\"ZCL_NOT_A_FLAG\", \"env_runtime\", \"-\",\n"
            " * \"-\", \"x\") lives only in this comment. */\n"
            "Z23_FLAG(\"ZCL_KNOWN_X\", \"env_runtime\", \"-\", \"-\",\n \"why\")\n",
            "./e.c", "int f(void){ return getenv(\"ZCL_KNOWN_X\") != 0; }\n",
            "2026-01-01", "printf '%s\\0' e.c", out, ob, sizeof ob, &rc);
    bad |= rc != 0
        || strstr(ob, "check_flag_registry: OK — 1 flags registered, 1 read "
                      "sites, 0 unregistered, 0 expired") == NULL;

    bad |= fr_st_case(
            "Z23_FLAG(\"ZCL_KNOWN_X\", \"env_runtime\", \"-\", \"-\",\n \"why\")\n"
            "Z23_FLAG(\"ZCL_STALE_X\", \"env_runtime\", \"-\", \"-\",\n \"why\")\n",
            "./c.c", "int f(void){ return getenv(\"ZCL_KNOWN_X\") != 0; }\n",
            "2026-01-01", "printf '%s\\0' c.c", out, ob, sizeof ob, &rc);
    bad |= rc != 1
        || strstr(ob, "flags.def: ZCL_STALE_X is registered but no longer "
                      "read — remove the row") == NULL;

    bad |= fr_st_case(
            "Z23_FLAG(\"ZCL_EXP_X\", \"env_runtime\", \"-\", \"2020-01-01\",\n"
            " \"why\")\n",
            "./d.c", "int f(void){ return getenv(\"ZCL_EXP_X\") != 0; }\n",
            "2026-01-01", "printf '%s\\0' d.c", out, ob, sizeof ob, &rc);
    bad |= rc != 1 || strstr(ob, "flags.def: ZCL_EXP_X expired on 2020-01-01") == NULL;

    bad |= fr_st_case("\n", NULL, NULL, "2026-01-01", "true", out, ob, sizeof ob, &rc);
    bad |= rc != 2;

    fclose(out);
    unlink("./f.def");
    unlink("./a.c");
    unlink("./b.c");
    unlink("./c.c");
    unlink("./d.c");
    unlink("./e.c");
    if (chdir(cwd) != 0)
        return die("z23-lint: cannot scan %s\n", cwd);
    rmdir(root);
    if (bad)
        fputs("FAIL: check_flag_registry selftest\n", stderr);
    return st_ok(bad, "check_flag_registry selftest: OK\n");
}
