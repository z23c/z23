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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "gate_flag_registry_priv.h"
#include "lintc.h"

enum {
    FR_MAX = 4096,   /* headroom over the ~1154 rows the first sweep found */
    FR_WHY = 2048,   /* a why_ joined from adjacent literals */
    FR_DEF_BUF = 512 * 1024,
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

/* A why_ written as adjacent string literals ("a " "b") is one C string;
 * appends every literal that follows the first (only blanks between) to
 * why, so a "first use" clause in a later literal is parsed and proved —
 * before this, such a pointer was never checked at all. */
static void fr_join_adjacent(const char **cur, char *why, size_t cap)
{
    const char *p = *cur;
    for (;;) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
            p++;
        if (*p != '"')
            return;
        size_t used = strlen(why);
        if (!fr_next_quoted(&p, why + used, cap - used))
            return;
        *cur = p;
    }
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
    fr_join_adjacent(cur, why, sizeof why);
    row->fu_present = fru_parse_pointer(why, row->fu_path, sizeof row->fu_path,
                                        &row->fu_line);
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
 * first group is the reader — getenv, env_or or env_int_or), 1 for shell.
 * *at is where the whole match (the reader token, or the '$') starts. */
static int fr_cap_one(const regex_t *re, const char *cursor, char *name, size_t cap,
                      size_t *adv, size_t *at, int base, int grp)
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
    *at = (size_t)m[0].rm_so;
    return 1;
}

/* A registered read: the row is live, and — when it is a real read in the
 * very file the row's first-use pointer names — that pointer's file is
 * proved to read it (what ":auto" checks and --auto-pointers rebinds to). */
static void fr_note_read(struct fr_row *row, const struct fr_line *ln,
                         size_t off, const char *name)
{
    row->used = 1;
    if (row->fu_present && !row->fu_read_seen
        && strcmp(row->fu_path, ln->path) == 0
        && frl_read_is_real(ln, off, name))
        row->fu_read_seen = 1;
}

static int fr_scan_line(struct fr_ctx *ctx, const regex_t *re, int grp,
                        const struct fr_line *ln)
{
    const char *cursor = ln->text;
    int base = 0;
    for (;;) {
        char name[FR_NAME];
        size_t adv = 0, at = 0;
        if (!fr_cap_one(re, cursor, name, sizeof name, &adv, &at, base, grp))
            return 0;
        ctx->reads++;
        int idx = fr_find(ctx->rows, ctx->n, name);
        if (idx >= 0)
            fr_note_read(&ctx->rows[idx], ln,
                         (size_t)(cursor - ln->text) + at, name);
        else {
            int rc = fr_report_unreg(ctx, ln->path, ln->lineno, name);
            if (rc)
                return rc;
        }
        cursor += adv;
        base = 1;
        if (*cursor == '\0')
            return 0;
    }
}

static int fr_scan_file(const char *path, void *vctx)
{
    struct fr_ctx *ctx = vctx;
    struct fr_line ln = { .path = path, .is_c = fr_is_c_path(path),
                          .c_state = FR_CODE };
    const regex_t *re = ln.is_c ? &g_fr_c_re : &g_fr_sh_re;
    int grp = ln.is_c ? 2 : 1;
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    ctx->files++;
    char *line = NULL;
    size_t cap = 0;
    int rc = 0;
    while (getline(&line, &cap, f) >= 0) {
        ln.lineno++;
        ln.text = line;
        if (ln.is_c && ln.c_state == FR_CODE)
            ln.if0 = frl_c_if0(line, ln.if0);
        rc = fr_scan_line(ctx, re, grp, &ln);
        if (rc)
            break;
        if (ln.is_c)
            ln.c_state = frl_c_state_after(line, ln.c_state);
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

/* Runs the three post-scan reconciliation checks (stale rows, expired
 * rows, and every row's first-use pointer) and either prints the single
 * OK line or leaves the FAIL lines those checks already wrote to out. */
static int fr_reconcile(const struct fr_row *rows, int n, const char *head_date,
                        int reads, FILE *out)
{
    int fail = fr_check_stale(rows, n, out);
    if (fail < 0)
        return die("z23-lint: write failed\n", "");
    int fail2 = fr_check_expired(rows, n, head_date, out);
    if (fail2 < 0)
        return die("z23-lint: write failed\n", "");

    int fu_verified = 0;
    int fail3 = fru_check_rows(rows, n, out, &fu_verified);
    if (fail3 == 2)
        return 2;
    if (fail || fail2 || fail3)
        return 1;

    return fprintf(out, "check_flag_registry: OK — %d flags registered, "
                   "%d read sites, 0 unregistered, 0 expired, %d first-use "
                   "pointers verified\n", n, reads, fu_verified) < 0
        ? die("z23-lint: write failed\n", "") : 0;
}

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

    return fr_reconcile(rows, n, head_date, ctx.reads, out);
}

/* ── --fix-pointers / --auto-pointers ────────────────────────────────── */

/* Finds row name's own "first use <path>:<old_line>" token inside that
 * row's Z23_FLAG(...) text in buf — never another row's, because two flags
 * read on one line cite the same <path>:<line> — and returns where its
 * digits start (*len: how many), or NULL. ":31" never matches the prefix
 * of ":314". */
static char *fr_row_token_digits(char *buf, const char *name, const char *path,
                                 int old_line, size_t *len)
{
    char head[FR_NAME + 16];
    char needle[FR_FU_PATH + 48];
    int hlen = snprintf(head, sizeof head, "Z23_FLAG(\"%s\"", name);
    int nlen = snprintf(needle, sizeof needle, "first use %s:%d", path,
                        old_line);
    int dlen = snprintf(NULL, 0, "%d", old_line);
    if (hlen <= 0 || (size_t)hlen >= sizeof head || nlen <= 0
        || (size_t)nlen >= sizeof needle || dlen <= 0)
        return NULL;
    char *row = strstr(buf, head);
    if (!row)
        return NULL;
    char *next = strstr(row + hlen, "Z23_FLAG(");
    for (char *hit = strstr(row, needle); hit && (!next || hit < next);
         hit = strstr(hit + 1, needle))
        if (hit[nlen] < '0' || hit[nlen] > '9') {
            *len = (size_t)dlen;
            return hit + nlen - dlen;
        }
    return NULL;
}

/* Rewrites the text after the colon of row name's single first-use token
 * ("<old_line>") to repl — a new line number, or "auto" — in place inside
 * buf (capacity bufcap, NUL-terminated). Every other byte, including the
 * path and every other row, is untouched. Returns 0 on success, -1 when
 * the row's own old token can't be found (a parser/state mismatch the
 * caller treats as fatal, never a silent no-op) or the rewrite would not
 * fit in bufcap. */
static int fr_fix_apply(char *buf, size_t bufcap, const char *name,
                        const char *path, int old_line, const char *repl)
{
    size_t old_len = 0;
    char *at = fr_row_token_digits(buf, name, path, old_line, &old_len);
    if (!at)
        return -1;
    size_t rlen = strlen(repl);
    if (strlen(buf) - old_len + rlen + 1 > bufcap)
        return -1;
    memmove(at + rlen, at + old_len, strlen(at + old_len) + 1);
    memcpy(at, repl, rlen);
    return 0;
}

/* Same temp-file-then-rename shape as gate_shell_host_assumptions.c's
 * shl_write_baseline: the catalog is never observed half-written, whether
 * the process dies mid-write or races a concurrent reader. */
static int fr_fix_write_atomic(const char *path, const char *buf)
{
    char tmp[512];
    if (ovf(snprintf(tmp, sizeof tmp, "%s.tmp", path), sizeof tmp))
        return 2;
    FILE *f = fopen(tmp, "w");
    if (!f)
        return die("z23-lint: cannot open %s\n", tmp);
    size_t len = strlen(buf);
    int rc = 0;
    if (fwrite(buf, 1, len, f) != len)
        rc = die("z23-lint: write failed: %s\n", tmp);
    if (fclose(f) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", tmp);
    if (rc == 0 && rename(tmp, path) != 0)
        rc = die("z23-lint: rename failed: %s\n", path);
    return rc;
}

/* One row's repair decision: skipped (not a numeric first-use pointer, or
 * already correct), rewritten in defbuf and reported, or left for a human
 * (with a reason) and reported. Never touches the ":auto" component-file
 * convention — that pointer names no line to move to. */
static int fr_fix_one(struct fr_row *row, char *defbuf, size_t defcap,
                      FILE *out, int *fixed, int *unfixed)
{
    if (!row->fu_present || row->fu_line == -1)
        return 0;
    int near = 0;
    int status = fru_pointer_status(row->fu_path, row->fu_line, row->name,
                                    &near);
    if (status == -1)
        return die("z23-lint: flag_registry: first-use pointer file "
                   "unreadable: %s\n", row->fu_path);
    if (status == 0)
        return 0;
    if (status == 2) {
        (*unfixed)++;
        return fprintf(out, "flag_registry: %s first use %s:%d not fixed —"
                      " %s is no longer read anywhere in that file; a human"
                      " must repoint or remove the row\n", row->name,
                      row->fu_path, row->fu_line, row->name) < 0
            ? die("z23-lint: write failed\n", "") : 0;
    }
    char digits[16];
    snprintf(digits, sizeof digits, "%d", near);
    if (fr_fix_apply(defbuf, defcap, row->name, row->fu_path, row->fu_line,
                     digits))
        return die("z23-lint: flag_registry: --fix-pointers: could not "
                   "locate %s's own first-use token to rewrite\n", row->name);
    (*fixed)++;
    return fprintf(out, "flag_registry: fixed %s first use %s:%d -> :%d\n",
                  row->name, row->fu_path, row->fu_line, near) < 0
        ? die("z23-lint: write failed\n", "") : 0;
}

/* Repairs every drifted numeric first-use pointer in def_path to the
 * nearest current read of the same flag in the same file, rewriting the
 * catalog atomically once (never for zero fixes — an all-clean or
 * all-unfixable run leaves the file byte-identical, which is what makes a
 * second run a no-op). Returns 0 when nothing is left unfixed, 1 when some
 * row still needs a human, 2 on a hard error. */
static int fr_run_fix(const char *def_path, FILE *out)
{
    static char defbuf[FR_DEF_BUF];
    static struct fr_row rows[FR_MAX];

    if (fr_read_file(def_path, defbuf, sizeof defbuf))
        return 2;
    int n = 0;
    if (fr_parse_def_buf(defbuf, rows, FR_MAX, &n))
        return 2;

    int fixed = 0, unfixed = 0;
    for (int i = 0; i < n; i++) {
        int rc = fr_fix_one(&rows[i], defbuf, sizeof defbuf, out, &fixed,
                            &unfixed);
        if (rc)
            return rc;
    }
    if (fixed > 0) {
        int rc = fr_fix_write_atomic(def_path, defbuf);
        if (rc)
            return rc;
    }
    if (fprintf(out, "flag_registry: --fix-pointers: %d rewritten, %d left"
               " for a human\n", fixed, unfixed) < 0)
        return die("z23-lint: write failed\n", "");
    return unfixed > 0 ? 1 : 0;
}

/* One numeric row's --auto-pointers decision: rebound to "<path>:auto"
 * when the scan saw a real read of the flag in that very file (the check
 * the gate will then make), otherwise kept numeric and reported. */
static int fr_auto_one(const struct fr_row *row, char *defbuf, size_t defcap,
                       FILE *out, int *rebound, int *kept)
{
    if (!row->fu_present || row->fu_line == -1)
        return 0;
    if (!row->fu_read_seen) {
        (*kept)++;
        return fprintf(out, "flag_registry: kept %s first use %s:%d — no"
                       " scanner-recognized real read of it in that tracked"
                       " file\n", row->name, row->fu_path, row->fu_line) < 0
            ? die("z23-lint: write failed\n", "") : 0;
    }
    if (fr_fix_apply(defbuf, defcap, row->name, row->fu_path, row->fu_line,
                     "auto"))
        return die("z23-lint: flag_registry: --auto-pointers: could not "
                   "locate %s's own first-use token to rewrite\n", row->name);
    (*rebound)++;
    return 0;
}

/* Rebinds every numeric first-use pointer whose file really reads its
 * flag to "<path>:auto", so inserting or deleting lines in that file never
 * again forces an edit to the shared catalog. Same scan as the gate (so a
 * rebound row is exactly one the gate proves), one atomic rewrite (none
 * for zero rebinds, so a second run is a byte-identical no-op). Rows kept
 * numeric stay under the exact line check. Returns 0, or 2 on a hard
 * error; kept rows are reported, not a failure. */
static int fr_run_auto(const char *def_path, const char *ls_cmd, FILE *out)
{
    static char defbuf[FR_DEF_BUF];
    static struct fr_row rows[FR_MAX];
    int n = 0;
    if (fr_ensure_re() || fr_read_file(def_path, defbuf, sizeof defbuf)
        || fr_parse_def_buf(defbuf, rows, FR_MAX, &n))
        return 2;
    struct fr_ctx ctx = { .rows = rows, .n = n, .out = out };
    int rc = each_zpath(ls_cmd, fr_scan_file, &ctx);
    if (rc)
        return rc;
    rc = gate_require_scanned(ctx.files, 1, "check-flag-registry",
            "--auto-pointers: the tracked-file scan returned no files.");
    if (rc)
        return rc;
    int rebound = 0, kept = 0;
    for (int i = 0; i < n && rc == 0; i++)
        rc = fr_auto_one(&rows[i], defbuf, sizeof defbuf, out, &rebound,
                         &kept);
    if (rc == 0 && rebound > 0)
        rc = fr_fix_write_atomic(def_path, defbuf);
    if (rc)
        return rc;
    return fprintf(out, "flag_registry: --auto-pointers: %d rebound to :auto,"
                   " %d left numeric\n", rebound, kept) < 0
        ? die("z23-lint: write failed\n", "") : 0;
}

/* --key-inputs: the optional action cache must hash every first-use
 * pointer target (":auto" ones included — the gate reads those files too),
 * including a future target outside the tracked scan pathspec. Emits the
 * parser's actual paths, NUL-delimited; failure refuses reuse. */
static int fr_run_key_inputs(void)
{
    static char defbuf[FR_DEF_BUF];
    static struct fr_row rows[FR_MAX];
    int n = 0;
    if (fr_read_file(k_def_path, defbuf, sizeof defbuf) ||
        fr_parse_def_buf(defbuf, rows, FR_MAX, &n))
        return 2;
    for (int i = 0; i < n; i++) {
        if (!rows[i].fu_present)
            continue;
        size_t len = strlen(rows[i].fu_path) + 1;
        if (fwrite(rows[i].fu_path, 1, len, stdout) != len)
            return die("z23-lint: key input write failed\n", "");
    }
    return fflush(stdout) == 0 ? 0 :
        die("z23-lint: key input flush failed\n", "");
}

int check_flag_registry_run(int argc, char **argv)
{
    if (argc == 1 && strcmp(argv[0], "--fix-pointers") == 0)
        return fr_run_fix(k_def_path, stdout);
    if (argc == 1 && strcmp(argv[0], "--auto-pointers") == 0)
        return fr_run_auto(k_def_path, k_ls_scan, stdout);
    if (argc == 1 && strcmp(argv[0], "--key-inputs") == 0)
        return fr_run_key_inputs();
    if (argc != 0)
        return die("z23-lint: check-flag-registry: unknown argument\n", "");
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

/* The eight core parsing/registration/reconciliation cases: unregistered
 * reads (direct and through the env_or/env_int_or wrappers), a clean
 * registration, a comment that must not be mistaken for a live row, a
 * stale row, an expired row, and a hollow scan. None of these rows carry
 * a first-use pointer. */
static int fr_st_core_cases(FILE *out, char *ob, size_t obcap)
{
    int rc = 0, bad = 0;

    bad |= fr_st_case("\n", "./a.c",
            "int f(void){ return getenv(\"ZCL_UNKNOWN_X\") != 0; }\n",
            "2026-01-01", "printf '%s\\0' a.c", out, ob, obcap, &rc);
    bad |= rc != 1
        || strstr(ob, "a.c:1: ZCL_UNKNOWN_X is not in engine/composition/flags.def") == NULL;

    bad |= fr_st_case(
            "Z23_FLAG(\"ZCL_KNOWN_X\", \"env_runtime\", \"-\", \"-\",\n \"why\")\n",
            "./b.c", "int f(void){ return getenv(\"ZCL_KNOWN_X\") != 0; }\n",
            "2026-01-01", "printf '%s\\0' b.c", out, ob, obcap, &rc);
    bad |= rc != 0
        || strstr(ob, "check_flag_registry: OK — 1 flags registered, 1 read "
                      "sites, 0 unregistered, 0 expired, 0 first-use "
                      "pointers verified") == NULL;

    /* A read through the lint runtime's env_or / env_int_or wrappers is a
     * read. Without this the gate calls a flag only a C gate consumes dead
     * and demands its row be deleted — the shape that first caught it. */
    bad |= fr_st_case(
            "Z23_FLAG(\"ZCL_KNOWN_X\", \"env_runtime\", \"-\", \"-\",\n \"why\")\n"
            "Z23_FLAG(\"ZCL_KNOWN_Y\", \"env_runtime\", \"-\", \"-\",\n \"why\")\n",
            "./w.c",
            "int f(void){ return *env_or(\"ZCL_KNOWN_X\", \"d\")\n"
            "                  + env_int_or(\"ZCL_KNOWN_Y\", 1); }\n",
            "2026-01-01", "printf '%s\\0' w.c", out, ob, obcap, &rc);
    bad |= rc != 0
        || strstr(ob, "check_flag_registry: OK — 2 flags registered, 2 read "
                      "sites, 0 unregistered, 0 expired, 0 first-use "
                      "pointers verified") == NULL;

    /* ... and an UNregistered name reached through a wrapper still fails. */
    bad |= fr_st_case("\n", "./x.c",
            "int f(void){ return *env_or(\"ZCL_UNKNOWN_W\", \"d\"); }\n",
            "2026-01-01", "printf '%s\\0' x.c", out, ob, obcap, &rc);
    bad |= rc != 1
        || strstr(ob, "x.c:1: ZCL_UNKNOWN_W is not in engine/composition/flags.def") == NULL;

    bad |= fr_st_case(
            "/* example: Z23_FLAG(\"ZCL_NOT_A_FLAG\", \"env_runtime\", \"-\",\n"
            " * \"-\", \"x\") lives only in this comment. */\n"
            "Z23_FLAG(\"ZCL_KNOWN_X\", \"env_runtime\", \"-\", \"-\",\n \"why\")\n",
            "./e.c", "int f(void){ return getenv(\"ZCL_KNOWN_X\") != 0; }\n",
            "2026-01-01", "printf '%s\\0' e.c", out, ob, obcap, &rc);
    bad |= rc != 0
        || strstr(ob, "check_flag_registry: OK — 1 flags registered, 1 read "
                      "sites, 0 unregistered, 0 expired, 0 first-use "
                      "pointers verified") == NULL;

    bad |= fr_st_case(
            "Z23_FLAG(\"ZCL_KNOWN_X\", \"env_runtime\", \"-\", \"-\",\n \"why\")\n"
            "Z23_FLAG(\"ZCL_STALE_X\", \"env_runtime\", \"-\", \"-\",\n \"why\")\n",
            "./c.c", "int f(void){ return getenv(\"ZCL_KNOWN_X\") != 0; }\n",
            "2026-01-01", "printf '%s\\0' c.c", out, ob, obcap, &rc);
    bad |= rc != 1
        || strstr(ob, "flags.def: ZCL_STALE_X is registered but no longer "
                      "read — remove the row") == NULL;

    bad |= fr_st_case(
            "Z23_FLAG(\"ZCL_EXP_X\", \"env_runtime\", \"-\", \"2020-01-01\",\n"
            " \"why\")\n",
            "./d.c", "int f(void){ return getenv(\"ZCL_EXP_X\") != 0; }\n",
            "2026-01-01", "printf '%s\\0' d.c", out, ob, obcap, &rc);
    bad |= rc != 1 || strstr(ob, "flags.def: ZCL_EXP_X expired on 2020-01-01") == NULL;

    bad |= fr_st_case("\n", NULL, NULL, "2026-01-01", "true", out, ob, obcap, &rc);
    bad |= rc != 2;

    return bad;
}

/* first-use pointer checks: every row below carries a real getenv() so
 * fr_check_stale never fires — the only thing under test is whether the
 * row's own "first use <path>:<line>" clause points where it claims to. */
static int fr_st_first_use_cases(FILE *out, char *ob, size_t obcap)
{
    int rc = 0, bad = 0;

    if (csr_write("./fu_filler.c",
                "int z(void){ return getenv(\"ZCL_FU_FILLER\") != 0; }\n"))
        return 1;

    bad |= fr_st_case(
            "Z23_FLAG(\"ZCL_FU_FILLER\", \"env_runtime\", \"-\", \"-\", \"why\")\n"
            "Z23_FLAG(\"ZCL_FU_OK\", \"env_runtime\", \"-\", \"-\",\n"
            " \"first use ./fu_ok.c:1\")\n",
            "./fu_ok.c", "int f(void){ return getenv(\"ZCL_FU_OK\") != 0; }\n",
            "2026-01-01", "printf '%s\\0' fu_filler.c fu_ok.c", out, ob,
            obcap, &rc);
    bad |= rc != 0
        || strstr(ob, "check_flag_registry: OK — 2 flags registered, 2 read "
                      "sites, 0 unregistered, 0 expired, 1 first-use "
                      "pointers verified") == NULL;

    bad |= fr_st_case(
            "Z23_FLAG(\"ZCL_FU_FILLER\", \"env_runtime\", \"-\", \"-\", \"why\")\n"
            "Z23_FLAG(\"ZCL_FU_BAD_LINE\", \"env_runtime\", \"-\", \"-\",\n"
            " \"first use ./fu_bad.c:2\")\n",
            "./fu_bad.c",
            "int f(void){ return getenv(\"ZCL_FU_BAD_LINE\") != 0; }\n"
            "int g(void){ return 0; }\n",
            "2026-01-01", "printf '%s\\0' fu_filler.c fu_bad.c", out, ob,
            obcap, &rc);
    bad |= rc != 1
        || strstr(ob, "flag_registry: ZCL_FU_BAD_LINE first use "
                      "./fu_bad.c:2 does not read it (name absent; nearest "
                      "read now at ./fu_bad.c:1)") == NULL;

    bad |= fr_st_case(
            "Z23_FLAG(\"ZCL_FU_FILLER\", \"env_runtime\", \"-\", \"-\", \"why\")\n"
            "Z23_FLAG(\"ZCL_FOO\", \"env_runtime\", \"-\", \"-\",\n"
            " \"first use ./fu_bound.c:1\")\n",
            "./fu_bound.c",
            "int x = ZCL_FOO_BAR;\n"
            "int f(void){ return getenv(\"ZCL_FOO\") != 0; }\n",
            "2026-01-01", "printf '%s\\0' fu_filler.c fu_bound.c", out, ob,
            obcap, &rc);
    bad |= rc != 1
        || strstr(ob, "flag_registry: ZCL_FOO first use ./fu_bound.c:1 does"
                      " not read it (name absent; nearest read now at "
                      "./fu_bound.c:2)") == NULL;

    bad |= fr_st_case(
            "Z23_FLAG(\"ZCL_FU_FILLER\", \"env_runtime\", \"-\", \"-\", \"why\")\n"
            "Z23_FLAG(\"ZCL_FU_MISSING\", \"env_runtime\", \"-\", \"-\",\n"
            " \"first use ./fu_missing_nope.c:1\")\n",
            NULL, NULL, "2026-01-01", "printf '%s\\0' fu_filler.c", out, ob,
            obcap, &rc);
    bad |= rc != 1
        || strstr(ob, "flag_registry: ZCL_FU_MISSING first use "
                      "./fu_missing_nope.c:1 does not read it "
                      "(file missing)") == NULL;

    bad |= fr_st_case(
            "Z23_FLAG(\"ZCL_FU_FILLER\", \"env_runtime\", \"-\", \"-\", \"why\")\n"
            "Z23_FLAG(\"ZCL_FU_PAST\", \"env_runtime\", \"-\", \"-\",\n"
            " \"first use ./fu_short.c:5\")\n",
            "./fu_short.c",
            "int f(void){ return getenv(\"ZCL_FU_PAST\") != 0; }\n",
            "2026-01-01", "printf '%s\\0' fu_filler.c fu_short.c", out, ob,
            obcap, &rc);
    bad |= rc != 1
        || strstr(ob, "flag_registry: ZCL_FU_PAST first use ./fu_short.c:5"
                      " does not read it (line past end; nearest read now "
                      "at ./fu_short.c:1)") == NULL;

    bad |= fr_st_case(
            "Z23_FLAG(\"ZCL_FU_ZERO\", \"env_runtime\", \"-\", \"-\",\n"
            " \"first use ./fu_zero.c:0\")\n",
            "./fu_zero.c",
            "int f(void){ return getenv(\"ZCL_FU_ZERO\") != 0; }\n",
            "2026-01-01", "printf '%s\\0' fu_zero.c", out, ob,
            obcap, &rc);
    bad |= rc != 1
        || strstr(ob, "ZCL_FU_ZERO first use ./fu_zero.c:0 does not read it") == NULL;

    /* A why_ split across adjacent literals is one string: its pointer in
     * the second literal is parsed and proved, not skipped. */
    bad |= fr_st_case(
            "Z23_FLAG(\"ZCL_FU_SPLIT\", \"env_runtime\", \"-\", \"-\",\n"
            " \"set by a test; \"\n \"first use ./fu_split.c:9\")\n",
            "./fu_split.c",
            "int f(void){ return getenv(\"ZCL_FU_SPLIT\") != 0; }\n",
            "2026-01-01", "printf '%s\\0' fu_split.c", out, ob,
            obcap, &rc);
    bad |= rc != 1
        || strstr(ob, "ZCL_FU_SPLIT first use ./fu_split.c:9 does not read it"
                      " (line past end; nearest read now at ./fu_split.c:1)")
           == NULL;

    if (csr_write("./fu_secret.c",
                "int f(void){ return getenv(\"ZCL_FU_UNREADABLE\") != 0; }\n"))
        return 1;
    bad |= chmod("./fu_secret.c", 0) != 0;
    /* A privileged reader (root, CAP_DAC_OVERRIDE, a permissive ACL) can
     * still open a mode-0 file, so the gate sees content, not an unreadable
     * file. Probe with a real open — not geteuid — and skip this case when
     * the platform cannot deny the read; the skip names the reason and
     * asserts nothing about the gate's rc. */
    {
        int probe = open("./fu_secret.c", O_RDONLY);
        if (probe >= 0) {
            close(probe);
            printf("  SKIP flag-registry: unreadable-file case: privileged "
                   "reader (chmod 0000 file still readable)\n");
        } else {
            bad |= fr_st_case(
                    "Z23_FLAG(\"ZCL_FU_FILLER\", \"env_runtime\", \"-\", \"-\", \"why\")\n"
                    "Z23_FLAG(\"ZCL_FU_UNREADABLE\", \"env_runtime\", \"-\", \"-\",\n"
                    " \"first use ./fu_secret.c:1\")\n",
                    NULL, NULL, "2026-01-01", "printf '%s\\0' fu_filler.c",
                    out, ob, obcap, &rc);
            bad |= rc != 2;
        }
    }
    chmod("./fu_secret.c", 0644);
    return bad;
}

/* Two component-owned shell files can gain lines independently without
 * editing their shared flag catalog. A comment or a read in the wrong file
 * still cannot satisfy an :auto pointer. */
static int fr_st_auto_component_cases(FILE *out, char *ob, size_t obcap)
{
    static const char def[] =
        "Z23_FLAG(\"ZCL_AUTO_A\", \"env_build\", \"-\", \"-\",\n"
        " \"first use fu_auto_a.sh:auto\")\n"
        "Z23_FLAG(\"ZCL_AUTO_B\", \"env_build\", \"-\", \"-\",\n"
        " \"first use fu_auto_b.sh:auto\")\n";
    static const char ls[] = "printf '%s\\0' fu_auto_a.sh fu_auto_b.sh";
    int bad = csr_write("./f.def", def)
        || csr_write("./fu_auto_a.sh", "a=${ZCL_AUTO_A}\n")
        || csr_write("./fu_auto_b.sh", "b=${ZCL_AUTO_B}\n");
    if (bad) return 1;
    for (int turn = 0; turn < 3; turn++) {
        if (turn == 1)
            bad |= csr_write("./fu_auto_a.sh", "\n\na=${ZCL_AUTO_A}\n");
        if (turn == 2)
            bad |= csr_write("./fu_auto_b.sh", "\n\n\nb=${ZCL_AUTO_B}\n");
        if (bad) return 1;
        int rc = fr_run_impl("./f.def", ls, "2026-01-01", out);
        bad |= csr_slurp(out, ob, obcap);
        bad |= rc != 0 || strstr(ob, "2 first-use pointers verified") == NULL;
        bad |= psp_st_reset(out);
    }
    bad |= csr_write("./fu_auto_a.sh", "# ${ZCL_AUTO_A}\n");
    bad |= csr_write("./fu_auto_b.sh",
                     "a=${ZCL_AUTO_A}\nb=${ZCL_AUTO_B}\n");
    if (bad) return 1;
    int rc = fr_run_impl("./f.def", ls, "2026-01-01", out);
    bad |= csr_slurp(out, ob, obcap);
    bad |= rc != 1
        || strstr(ob, "ZCL_AUTO_A first use fu_auto_a.sh:auto has no ") == NULL;
    bad |= psp_st_reset(out);
    return bad;
}

/* Runs the gate over one fixture and returns 0 when its verdict and output
 * match: want_rc, and want_text somewhere in what it printed. */
static int fr_st_auto_expect(const char *src, const char *text, const char *ls,
                             int want_rc, const char *want_text, FILE *out,
                             char *ob, size_t obcap)
{
    int rc = 0;
    int bad = fr_st_case(
            "Z23_FLAG(\"ZCL_AUTO_C\", \"env_runtime\", \"-\", \"-\",\n"
            " \"first use fu_auto_c.c:auto\")\n",
            src, text, "2026-01-01", ls, out, ob, obcap, &rc);
    return bad || rc != want_rc || strstr(ob, want_text) == NULL;
}

/* C :auto: a real getenv() read binds the row wherever the read moves, but
 * a mention the C scanner's regex would also match inside a comment (line,
 * block, a block spanning lines, a line comment continued by a backslash)
 * or a string literal never does. Those fixtures still mark the row read
 * (a separate question), so the only verdict under test is the :auto
 * pointer's. */
static int fr_st_auto_c_cases(FILE *out, char *ob, size_t obcap)
{
    static const char ls[] = "printf '%s\\0' fu_auto_c.c";
    static const char ok[] = "1 first-use pointers verified";
    static const char no_read[] =
        "ZCL_AUTO_C first use fu_auto_c.c:auto has no scanner-recognized "
        "read in that tracked file";
    static const char *const real[] = {
        "int f(void){ return getenv(\"ZCL_AUTO_C\") != 0; }\n",
        "/* a */\n\n\nint f(void){ return getenv(\"ZCL_AUTO_C\") != 0; }\n",
        "/* \"quoted */ int f(void){ return getenv(\"ZCL_AUTO_C\"); }\n",
        "const char *s = \"//\"; int q = '\\''; int g = getenv(\"ZCL_AUTO_C\");\n",
        "#define R getenv(\"ZCL_AUTO_C\")\n",
        "int x = 1'000; int y = getenv(\"ZCL_AUTO_C\") != 0;\n",
        "#if 0\n#ifdef X\n#endif\n#else\nint g = getenv(\"ZCL_AUTO_C\");\n#endif\n",
    };
    static const char *const fake[] = {
        "// return getenv(\"ZCL_AUTO_C\") != 0;\n",
        "int x; /* getenv(\"ZCL_AUTO_C\") */\n",
        "/* first line\n * getenv(\"ZCL_AUTO_C\")\n */\n",
        "static const char *s = \"x getenv(\"ZCL_AUTO_C\") y\";\n",
        "int q = '\"'; // getenv(\"ZCL_AUTO_C\")\n",
        "// continued \\\n getenv(\"ZCL_AUTO_C\");\n",
        "int x = 1'000; /* opens\n getenv(\"ZCL_AUTO_C\")\n */\n",
        "#if 0\nint g = getenv(\"ZCL_AUTO_C\");\n#endif\n",
    };
    int bad = 0;
    for (size_t i = 0; i < sizeof real / sizeof real[0]; i++)
        bad |= fr_st_auto_expect("./fu_auto_c.c", real[i], ls, 0, ok, out,
                                 ob, obcap);
    for (size_t i = 0; i < sizeof fake / sizeof fake[0]; i++)
        bad |= fr_st_auto_expect("./fu_auto_c.c", fake[i], ls, 1, no_read,
                                 out, ob, obcap);
    /* The cited file is scanned but has no read at all; a real read in a
     * DIFFERENT file keeps the row live but never proves the pointer. */
    bad |= csr_write("./fu_auto_fill.c",
            "int f(void){ return getenv(\"ZCL_AUTO_C\") != 0; }\n");
    bad |= fr_st_auto_expect("./fu_auto_c.c", "int f(void){ return 0; }\n",
                             "printf '%s\\0' fu_auto_c.c fu_auto_fill.c", 1,
                             no_read, out, ob, obcap);
    bad |= strstr(ob, "(file missing)") != NULL;
    /* ... nor at a file that does not exist. */
    unlink("./fu_auto_c.c");
    bad |= fr_st_auto_expect("./fu_auto_fill.c",
            "int f(void){ return getenv(\"ZCL_AUTO_C\") != 0; }\n",
            "printf '%s\\0' fu_auto_fill.c", 1,
            "ZCL_AUTO_C first use fu_auto_c.c:auto has no scanner-recognized"
            " read in that tracked file (file missing)", out, ob, obcap);
    return bad;
}

/* Shell and Makefile :auto: a '#' that cannot open a shell comment
 * (${#arr[@]}, "$#") no longer hides a real read after it; one that can
 * (word start, or right after a quote) still does, and in a Makefile any
 * '#' does. Each fixture holds exactly one mention of the flag. */
static int fr_st_auto_sh_cases(FILE *out, char *ob, size_t obcap)
{
    static const struct { const char *file, *text; int want_rc; } k[] = {
        { "fu_auto_s.sh", "n=${#a[@]} f=${ZCL_AUTO_S:-1}\n", 0 },
        { "fu_auto_s.sh", "[ \"$#\" -eq 0 ] && x=\"${ZCL_AUTO_S}\"\n", 0 },
        { "fu_auto_s.sh", "x=1 # ${ZCL_AUTO_S}\n", 1 },
        { "fu_auto_s.sh", "printf '#  ${ZCL_AUTO_S}'\n", 1 },
        { "Makefile", "X := a#$(Y) ${ZCL_AUTO_S}\n", 1 },
        { "Makefile", "X := ${ZCL_AUTO_S}\n", 0 },
    };
    char def[256], ls[64], src[64];
    int bad = 0;
    for (size_t i = 0; i < sizeof k / sizeof k[0]; i++) {
        int rc = 0;
        snprintf(def, sizeof def,
                 "Z23_FLAG(\"ZCL_AUTO_S\", \"env_build\", \"-\", \"-\",\n"
                 " \"first use %s:auto\")\n", k[i].file);
        snprintf(ls, sizeof ls, "printf '%%s\\0' %s", k[i].file);
        snprintf(src, sizeof src, "./%s", k[i].file);
        bad |= fr_st_case(def, src, k[i].text, "2026-01-01", ls, out, ob,
                          obcap, &rc);
        bad |= rc != k[i].want_rc;
        unlink(src);
    }
    return bad;
}

/* --auto-pointers: a numeric row whose file really reads the flag — even
 * one whose line already drifted — is rebound to :auto; a row whose only
 * mention in its cited file is a comment stays numeric, even though it
 * shares that <path>:<line> with a row that is rebound (the rewrite is
 * anchored to each row's own text); the result passes the gate; and a
 * second run is a byte-identical no-op. */
static int fr_st_auto_rebind_cases(FILE *out, char *ob, size_t obcap)
{
    static char defbuf[FR_DEF_BUF];
    static char before[FR_DEF_BUF];
    static const char ls[] = "printf '%s\\0' ap.c ap_drift.c ap_note.c";
    int bad = csr_write("./ap.c",
            "int f(void){ return getenv(\"ZCL_AP_REAL\") != 0; }"
            " /* getenv(\"ZCL_AP_NOTE\") */\n")
        || csr_write("./ap_note.c",
            "int g(void){ return getenv(\"ZCL_AP_NOTE\") != 0; }\n")
        || csr_write("./ap_drift.c",
            "\n\nint f(void){ return getenv(\"ZCL_AP_DRIFT\") != 0; }\n")
        || csr_write("./f.def",
            "Z23_FLAG(\"ZCL_AP_DRIFT\", \"env_runtime\", \"-\", \"-\",\n"
            " \"first use ap_drift.c:1\")\n"
            "Z23_FLAG(\"ZCL_AP_NOTE\", \"env_runtime\", \"-\", \"-\",\n"
            " \"first use ap.c:1\")\n"
            "Z23_FLAG(\"ZCL_AP_REAL\", \"env_runtime\", \"-\", \"-\",\n"
            " \"first use ap.c:1; kept prose\")\n");
    if (bad)
        return 1;
    int rc = fr_run_auto("./f.def", ls, out);
    bad |= csr_slurp(out, ob, obcap) || psp_st_reset(out);
    bad |= rc != 0
        || strstr(ob, "kept ZCL_AP_NOTE first use ap.c:1 — no") == NULL
        || strstr(ob, "2 rebound to :auto, 1 left numeric") == NULL;
    bad |= fr_read_file("./f.def", defbuf, sizeof defbuf) != 0;
    bad |= strstr(defbuf, "\"first use ap_drift.c:auto\"") == NULL
        || strstr(defbuf, "\"first use ap.c:1\")") == NULL
        || strstr(defbuf, "\"first use ap.c:auto; kept prose\"") == NULL;
    rc = fr_run_impl("./f.def", ls, "2026-01-01", out);
    bad |= csr_slurp(out, ob, obcap) || psp_st_reset(out);
    bad |= rc != 0 || strstr(ob, "3 first-use pointers verified") == NULL;
    memcpy(before, defbuf, sizeof before);
    rc = fr_run_auto("./f.def", ls, out);
    bad |= csr_slurp(out, ob, obcap) || psp_st_reset(out);
    bad |= rc != 0 || strstr(ob, "0 rebound to :auto, 1 left numeric") == NULL;
    bad |= fr_read_file("./f.def", defbuf, sizeof defbuf) != 0
        || strcmp(before, defbuf) != 0;
    return bad;
}

/* --fix-pointers: drifted pointer -> fixed, absent read -> left for a
 * human (never rewritten), and a second run over the already-fixed file
 * is a byte-identical no-op — the three behaviors the landing failure
 * this repair mode targets (ZCL_COMMONS_DEMO_RECORD 3149 -> 3164) needs
 * proved, the same way fr_st_case proves the strict check. */
static int fr_st_fix_cases(FILE *out, char *ob, size_t obcap)
{
    static char defbuf[FR_DEF_BUF];
    int bad = 0;

    bad |= csr_write("./fix_filler.c",
            "int z(void){ return getenv(\"ZCL_FIX_FILLER\") != 0; }\n");
    bad |= csr_write("./fix_ok.c",
            "int a(void){ return 0; }\n"
            "int b(void){ return 0; }\n"
            "int c(void){ return 0; }\n"
            "int d(void){ return 0; }\n"
            "int f(void){ return getenv(\"ZCL_FIX_OK\") != 0; }\n");
    bad |= csr_write("./fix_gone.c", "int a(void){ return 0; }\n");
    bad |= csr_write("./f.def",
            "Z23_FLAG(\"ZCL_FIX_FILLER\", \"env_runtime\", \"-\", \"-\", \"why\")\n"
            "Z23_FLAG(\"ZCL_FIX_OK\", \"env_runtime\", \"-\", \"-\",\n"
            " \"first use ./fix_ok.c:2\")\n"
            "Z23_FLAG(\"ZCL_FIX_GONE\", \"env_runtime\", \"-\", \"-\",\n"
            " \"first use ./fix_gone.c:1\")\n");
    if (bad)
        return 1;

    /* Run 1: one drifted (fixable) row, one absent-read (unfixable) row. */
    int rc = fr_run_fix("./f.def", out);
    bad |= csr_slurp(out, ob, obcap) || psp_st_reset(out);
    bad |= rc != 1
        || strstr(ob, "fixed ZCL_FIX_OK first use ./fix_ok.c:2 -> :5") == NULL
        || strstr(ob, "ZCL_FIX_GONE first use ./fix_gone.c:1 not fixed") == NULL
        || strstr(ob, "1 rewritten, 1 left for a human") == NULL;

    /* The drifted row now reads correctly; the unfixable one is untouched
     * (still fails, still needs a human) — a fully independent re-parse
     * and re-scan proves the file itself, not just the report line. */
    bad |= fr_read_file("./f.def", defbuf, sizeof defbuf) != 0;
    bad |= strstr(defbuf, "first use ./fix_ok.c:5") == NULL;
    bad |= strstr(defbuf, "first use ./fix_gone.c:1") == NULL;
    rc = fr_run_impl("./f.def", "printf '%s\\0' fix_filler.c fix_ok.c fix_gone.c",
                     "2026-01-01", out);
    bad |= csr_slurp(out, ob, obcap) || psp_st_reset(out);
    bad |= rc != 1
        || strstr(ob, "ZCL_FIX_GONE first use ./fix_gone.c:1 does not read it") == NULL;

    /* Run 2, over the just-repaired file: the fixable row is now correct,
     * so nothing moves and the file is byte-identical to run 1's output —
     * a second --fix-pointers is a no-op, never a re-rewrite. */
    static char before[FR_DEF_BUF];
    memcpy(before, defbuf, sizeof before);
    rc = fr_run_fix("./f.def", out);
    bad |= csr_slurp(out, ob, obcap) || psp_st_reset(out);
    bad |= rc != 1 || strstr(ob, "0 rewritten, 1 left for a human") == NULL;
    bad |= fr_read_file("./f.def", defbuf, sizeof defbuf) != 0;
    bad |= strcmp(before, defbuf) != 0;

    return bad;
}

static void fr_st_cleanup(void)
{
    unlink("./f.def");
    unlink("./a.c");
    unlink("./b.c");
    unlink("./c.c");
    unlink("./d.c");
    unlink("./e.c");
    unlink("./fu_filler.c");
    unlink("./fu_ok.c");
    unlink("./fu_bad.c");
    unlink("./fu_bound.c");
    unlink("./fu_short.c");
    unlink("./fu_zero.c");
    unlink("./fu_split.c");
    unlink("./fu_secret.c");
    unlink("./fu_auto_a.sh");
    unlink("./fu_auto_b.sh");
    unlink("./fu_auto_c.c");
    unlink("./fu_auto_fill.c");
    unlink("./ap.c");
    unlink("./ap_note.c");
    unlink("./ap_drift.c");
    unlink("./fix_filler.c");
    unlink("./fix_ok.c");
    unlink("./fix_gone.c");
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
    int bad = fr_st_core_cases(out, ob, sizeof ob);
    bad |= fr_st_first_use_cases(out, ob, sizeof ob);
    bad |= fr_st_auto_component_cases(out, ob, sizeof ob);
    bad |= fr_st_auto_c_cases(out, ob, sizeof ob);
    bad |= fr_st_auto_sh_cases(out, ob, sizeof ob);
    bad |= fr_st_auto_rebind_cases(out, ob, sizeof ob);
    bad |= fr_st_fix_cases(out, ob, sizeof ob);
    fflush(stdout);
    fflush(stderr);

    fclose(out);
    fr_st_cleanup();
    if (chdir(cwd) != 0)
        return die("z23-lint: cannot scan %s\n", cwd);
    rmdir(root);
    if (bad)
        fputs("FAIL: check_flag_registry selftest\n", stderr);
    return st_ok(bad, "check_flag_registry selftest: OK\n");
}
