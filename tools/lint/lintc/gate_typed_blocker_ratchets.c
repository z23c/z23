/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: C23 lint gate — typed blocker_set() adoption ratchet
 * (check-typed-blocker). A raw blocker string site must call the typed
 * primitive, carry a per-file override marker, or appear in the
 * shrink-only baseline.
 *
 * Gates: check-typed-blocker
 * Single-gate family file. Placement ruling (2026-09-06, Linux side): both
 * small-pattern families are claimed by lintc26 (gate_ratchet_ports.c) and
 * lintc28 (gate_pattern_small.c), so new ports land in their own files; the
 * older in-file routing comments that would have folded this gate into an
 * existing family are overridden by that ruling. This gate is a shrink-only
 * ratchet, not a hard structural fence, so it does not share a family with
 * check-projections-pure.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"

/* ── check-typed-blocker (Gate #16) ──────────────────────────────────────
 * Port of tools/scripts/check_typed_blocker.sh. On 2026-05-21 the live
 * node ran 4.3 days with a raw string blocker re-firing ~5/sec because
 * there was no de-duplication at the recorder. blocker_set() is the typed
 * primitive (rate-limiting, escape dispatch, retry budget, class-aware
 * policy); this ratchet forbids NEW raw sites unless they call it, carry
 * // blocker-ok:<tag>, or are listed in typed_blocker_baseline.txt.
 * Baseline load matches THIS script (blank skip; full-line comment is a
 * leading optional space then # on the raw line; no inline-hash strip),
 * not gate_load_list_file. No scan floor — a missing root is skipped.
 * GNU word-boundary tokens on last_blocker_code (trailing) and
 * blocker_set( (leading) become explicit non-identifier-byte checks.
 * A present-but-unreadable scan file is UNPROVEN exit 2, never "no match". */

static const char k_tb_base[] = "tools/scripts/typed_blocker_baseline.txt";
static const char *const k_tb_roots[] = {
    "app/services", "app/controllers", "core/modules/validation",
    "platform/modules/util", "core/modules/net"
};
static const char *const k_tb_skip[] = {
    "platform/modules/util/src/blocker.c",
    "platform/modules/util/include/util/blocker.h"
};
enum { TB_NROOT = (int)(sizeof k_tb_roots / sizeof k_tb_roots[0]),
       TB_NSKIP = (int)(sizeof k_tb_skip / sizeof k_tb_skip[0]),
       TB_MAX = 512, TB_KEY = 512 };

struct tb_set { char n[TB_MAX][TB_KEY]; int count; };

struct tb_acc {
    regex_t *ch;
    regex_t *lms;
    regex_t *last;
    regex_t *set;
    regex_t *ok;
    struct tb_set *base;
    FILE *viol;
    int nnew;
};

static int tb_ident(unsigned char c)
{
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z')
        || (c >= 'a' && c <= 'z') || c == '_';
}

static int tb_bound_ok(const char *line, const regmatch_t *m, int lead,
                       int trail)
{
    if (lead && m->rm_so > 0 && tb_ident((unsigned char)line[m->rm_so - 1]))
        return 0;
    if (trail && line[m->rm_eo] && tb_ident((unsigned char)line[m->rm_eo]))
        return 0;
    return 1;
}

static int tb_search(const regex_t *re, const char *line, int lead, int trail)
{
    size_t off = 0;
    for (;;) {
        regmatch_t m;
        int flags = off ? REG_NOTBOL : 0;
        if (regexec(re, line + off, 1, &m, flags) != 0)
            return 0;
        m.rm_so += (regoff_t)off;
        m.rm_eo += (regoff_t)off;
        if (tb_bound_ok(line, &m, lead, trail))
            return 1;
        size_t nxt = (size_t)m.rm_eo;
        if (nxt <= off)
            nxt = off + 1;
        off = nxt;
        if (line[off] == '\0')
            return 0;
    }
}

static int tb_has(const struct tb_set *s, const char *path)
{
    for (int i = 0; i < s->count; i++) {
        if (strcmp(s->n[i], path) == 0)
            return 1;
    }
    return 0;
}

static int tb_add(struct tb_set *s, const char *path)
{
    size_t n = strlen(path);
    if (s->count >= TB_MAX || n >= TB_KEY)
        return die("z23-lint: derived buffer overflow\n", "");
    memcpy(s->n[s->count++], path, n + 1);
    return 0;
}

static int tb_is_comment(const char *line)
{
    const char *p = line;
    while (*p == ' ' || *p == '\t' || *p == '\f' || *p == '\v')
        p++;
    return *p == '#';
}

static void tb_strip_nl(char *line, ssize_t n)
{
    if (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
        line[n - 1] = '\0';
}

/* Script loop: skip blank; skip raw lines matching ^[[:space:]]*#; else
 * store the untrimmed line. Missing file is an empty set (the shell
 * touched it into existence; the C port only needs zero entries). Any
 * other open failure is UNPROVEN. */
static int tb_load(const char *path, struct tb_set *s)
{
    s->count = 0;
    FILE *f = fopen(path, "r");
    if (!f) {
        if (errno == ENOENT)
            return 0;
        return die("z23-lint: cannot open %s\n", path);
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        tb_strip_nl(line, n);
        if (line[0] == '\0' || tb_is_comment(line))
            continue;
        rc = tb_add(s, line);
    }
    return fin(f, line, path, rc);
}

static int tb_skip_self(const char *path)
{
    for (int i = 0; i < TB_NSKIP; i++) {
        if (strcmp(path, k_tb_skip[i]) == 0)
            return 1;
        size_t n = strlen(path), m = strlen(k_tb_skip[i]);
        if (n > m && path[n - m - 1] == '/'
            && strcmp(path + n - m, k_tb_skip[i]) == 0)
            return 1;
    }
    return 0;
}

static int tb_comp(regex_t *ch, regex_t *lms, regex_t *last, regex_t *set,
                   regex_t *ok)
{
    int rc = pair_comp(ch, REG_EXTENDED, "char[[:space:]]+[a-z_]*_blocker",
                       "(_code)?\\[", "", "",
                       lms, REG_EXTENDED, "lms_set_blocker\\(", "", "", "");
    if (rc)
        return rc;
    rc = compile_pat(last, REG_EXTENDED, "g_[a-z_]*\\.last_blocker_code",
                     "", "", "");
    if (rc) {
        drop2(ch, lms);
        return rc;
    }
    rc = pair_comp(set, REG_EXTENDED, "blocker_set\\(", "", "", "",
                   ok, REG_EXTENDED, "//[[:space:]]*blocker-ok:",
                   "[A-Za-z][A-Za-z0-9_-]*", "", "");
    if (rc) {
        drop3(ch, lms, last);
        return rc;
    }
    return 0;
}

static void tb_drop(regex_t *ch, regex_t *lms, regex_t *last, regex_t *set,
                    regex_t *ok)
{
    drop3(ch, lms, last);
    drop2(set, ok);
}

static int tb_raw_line(const struct tb_acc *a, const char *line)
{
    return tb_search(a->ch, line, 0, 0)
        || tb_search(a->lms, line, 0, 0)
        || tb_search(a->last, line, 0, 1);
}

static int tb_note(struct tb_acc *a, const char *path)
{
    if (fprintf(a->viol, "%s\n", path) < 0)
        return die("z23-lint: write failed\n", "");
    a->nnew++;
    return 0;
}

static int tb_scan_file(const char *path, struct tb_acc *a)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int raw = 0, typed = 0, mark = 0, rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        tb_strip_nl(line, n);
        if (!raw)
            raw = tb_raw_line(a, line);
        if (!typed)
            typed = tb_search(a->set, line, 1, 0);
        if (!mark)
            mark = (regexec(a->ok, line, 0, NULL, 0) == 0);
    }
    rc = fin(f, line, path, 0);
    if (rc)
        return rc;
    if (!raw || typed || mark || tb_has(a->base, path))
        return 0;
    return tb_note(a, path);
}

static int tb_on_file(const char *path, void *ctx)
{
    if (tb_skip_self(path))
        return 0;
    return tb_scan_file(path, ctx);
}

static int tb_copy_viol(FILE *from, FILE *to)
{
    if (fseek(from, 0, SEEK_SET) != 0)
        return die("z23-lint: fseek failed\n", "");
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    while ((n = getline(&line, &cap, from)) >= 0) {
        if (fputs("  ", to) < 0
            || fwrite(line, 1, (size_t)n, to) != (size_t)n) {
            free(line);
            return die("z23-lint: write failed\n", "");
        }
    }
    int err = ferror(from);
    free(line);
    return err ? die("z23-lint: read failed\n", "") : 0;
}

static int tb_report(struct tb_acc *a, int nbase, FILE *out)
{
    if (a->nnew == 0) {
        if (fprintf(out,
                    "check_typed_blocker: clean — %d grandfathered, no new ones\n",
                    nbase) < 0)
            return die("z23-lint: write failed\n", "");
        return 0;
    }
    if (fprintf(out,
                "\ncheck_typed_blocker: %d NEW file(s) with raw blocker "
                "string surface but no typed blocker_set call\n\n",
                a->nnew) < 0)
        return die("z23-lint: write failed\n", "");
    int rc = tb_copy_viol(a->viol, out);
    if (rc)
        return rc;
    if (fputs("\n"
              "Fix options (preferred → fallback):\n"
              "  1. Call blocker_set() to register the blocker through the typed\n"
              "     primitive. See engine/services/src/block_source_policy_runtime.c\n"
              "     classify_mirror_blocker_class() for the classification pattern.\n"
              "  2. Add a per-file marker '// blocker-ok:<tag>' explaining why\n"
              "     this site uses raw strings (typically: scheduled for migration\n"
              "     in Round 7-8 or pre-dates the primitive).\n"
              "  3. Last resort: add the file to ",
              out) < 0
        || fputs(k_tb_base, out) < 0
        || fputs(".\n", out) < 0)
        return die("z23-lint: write failed\n", "");
    return 1;
}

static int tb_eval(const char *const *roots, size_t nroots, const char *base,
                   FILE *out)
{
    struct tb_set set = {0};
    int rc = tb_load(base, &set);
    if (rc)
        return rc;
    regex_t ch, lms, last, typed, ok;
    rc = tb_comp(&ch, &lms, &last, &typed, &ok);
    if (rc)
        return rc;
    FILE *viol = tmpfile();
    if (!viol) {
        tb_drop(&ch, &lms, &last, &typed, &ok);
        return die("z23-lint: tmpfile failed\n", "");
    }
    struct tb_acc a = {
        .ch = &ch, .lms = &lms, .last = &last, .set = &typed, .ok = &ok,
        .base = &set, .viol = viol
    };
    for (size_t i = 0; rc == 0 && i < nroots; i++)
        rc = walk_src(roots[i], 1, tb_on_file, &a);
    if (rc == 0)
        rc = tb_report(&a, set.count, out);
    fclose(viol);
    tb_drop(&ch, &lms, &last, &typed, &ok);
    return rc;
}

int check_typed_blocker_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return tb_eval(k_tb_roots, (size_t)TB_NROOT, k_tb_base, stdout);
}

static int tb_st_run(const char *root, const char *base, int want_rc,
                     const char *need)
{
    FILE *out = tmpfile();
    if (!out)
        return die("z23-lint: tmpfile failed\n", "");
    const char *roots[1] = { root };
    int rc = tb_eval(roots, 1, base, out);
    char buf[4096];
    int sr = csr_slurp(out, buf, sizeof buf);
    fclose(out);
    if (sr)
        return sr;
    if (rc != want_rc)
        return 1;
    return (need && need[0] && strstr(buf, need) == NULL) ? 1 : 0;
}

static int tb_st_clean(const char *root, const char *base)
{
    char path[4096];
    if (ovf(snprintf(path, sizeof path, "%s/clean.c", root), sizeof path))
        return 1;
    return csr_write(path, "int clean(void) { return 0; }\n")
        || tb_st_run(root, base, 0,
                     "check_typed_blocker: clean — 0 grandfathered, no new ones");
}

static int tb_st_raw(const char *root, const char *base)
{
    char path[4096];
    if (ovf(snprintf(path, sizeof path, "%s/raw.c", root), sizeof path))
        return 1;
    if (csr_write(path, "char foo_blocker[32];\n"))
        return 1;
    return tb_st_run(root, base, 1, path);
}

static int tb_st_typed(const char *root, const char *base)
{
    char path[4096];
    if (ovf(snprintf(path, sizeof path, "%s/raw.c", root), sizeof path))
        return 1;
    return csr_write(path, "char foo_blocker[32];\nvoid f(void) { blocker_set(b); }\n")
        || tb_st_run(root, base, 0,
                     "check_typed_blocker: clean — 0 grandfathered, no new ones");
}

static int tb_st_marker(const char *root, const char *base)
{
    char path[4096];
    if (ovf(snprintf(path, sizeof path, "%s/raw.c", root), sizeof path))
        return 1;
    return csr_write(path, "char foo_blocker[32];\n// blocker-ok:legacy\n")
        || tb_st_run(root, base, 0,
                     "check_typed_blocker: clean — 0 grandfathered, no new ones");
}

static int tb_st_base(const char *root, const char *base)
{
    char path[4096];
    if (ovf(snprintf(path, sizeof path, "%s/raw.c", root), sizeof path))
        return 1;
    if (csr_write(path, "char foo_blocker[32];\n"))
        return 1;
    char row[4096];
    if (ovf(snprintf(row, sizeof row, "# comment\n\n%s\n", path), sizeof row))
        return 1;
    if (csr_write(base, row))
        return 1;
    return tb_st_run(root, base, 0,
                     "check_typed_blocker: clean — 1 grandfathered, no new ones");
}

static int tb_st_skip(const char *root, const char *base)
{
    char path[4096];
    if (ovf(snprintf(path, sizeof path,
                     "%s/platform/modules/util/src/blocker.c", root),
            sizeof path))
        return 1;
    (void)unlink(path);
    if (csr_write(path, "char foo_blocker[32];\n"))
        return 1;
    char other[4096];
    if (ovf(snprintf(other, sizeof other, "%s/raw.c", root), sizeof other))
        return 1;
    (void)unlink(other);
    return tb_st_run(root, base, 0,
                     "check_typed_blocker: clean — 0 grandfathered, no new ones");
}

static int tb_st_bounds(void)
{
    regex_t ch, lms, last, set, ok;
    int rc = tb_comp(&ch, &lms, &last, &set, &ok);
    if (rc)
        return 1;
    int bad = 0;
    if (!tb_search(&set, "blocker_set(", 1, 0))
        bad = 1;
    if (tb_search(&set, "my_blocker_set(", 1, 0))
        bad = 1;
    if (!tb_search(&last, "g_foo.last_blocker_code", 0, 1))
        bad = 1;
    if (tb_search(&last, "g_foo.last_blocker_code_x", 0, 1))
        bad = 1;
    if (!tb_search(&ch, "char foo_blocker[32];", 0, 0))
        bad = 1;
    tb_drop(&ch, &lms, &last, &set, &ok);
    return bad;
}

int check_typed_blocker_selftest(void)
{
    const char *td = env_or("TMPDIR", "/tmp");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-tb.XXXXXX", td),
            sizeof tmpl))
        return 2;
    char *tmp = mkdtemp(tmpl);
    if (!tmp)
        return die("z23-lint: mkdir failed: %s\n", td);
    char missing[4096];
    if (ovf(snprintf(missing, sizeof missing, "%s/missing-baseline.txt", tmp),
            sizeof missing)) {
        (void)rap_rm_rf(tmp);
        return 2;
    }
    char seeded[4096];
    if (ovf(snprintf(seeded, sizeof seeded, "%s/seeded-baseline.txt", tmp),
            sizeof seeded)) {
        (void)rap_rm_rf(tmp);
        return 2;
    }
    int bad = tb_st_bounds();
    bad |= tb_st_clean(tmp, missing);
    bad |= tb_st_raw(tmp, missing);
    bad |= tb_st_typed(tmp, missing);
    bad |= tb_st_marker(tmp, missing);
    bad |= tb_st_base(tmp, seeded);
    bad |= tb_st_skip(tmp, missing);
    (void)rap_rm_rf(tmp);
    return st_ok(bad, "check_typed_blocker selftest: OK\n");
}
