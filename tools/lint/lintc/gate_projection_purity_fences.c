/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: C23 lint gate — a storage projection is a pure fold over the
 * event log (check-projections-pure). A *_projection.c file must not
 * include an app-layer services/ or controllers/ header and must not
 * write through the ActiveRecord model save path.
 *
 * Gates: check-projections-pure
 * Single-gate family file. Placement ruling (2026-09-06, Linux side): both
 * small-pattern families are claimed by lintc26 (gate_ratchet_ports.c) and
 * lintc28 (gate_pattern_small.c), so new ports land in their own files; the
 * older in-file routing comments that would have folded this gate into an
 * existing family are overridden by that ruling. This gate is a HARD
 * structural fence, not a ratchet, so it does not share a family with
 * check-typed-blocker.
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

/* ── check-projections-pure (Gate E4) ────────────────────────────────────
 * Port of tools/scripts/check_projections_pure.sh. A projection rebuilds a
 * read-optimized view by folding the event/storage log into its own
 * table(s). It must never invert the storage → services/controllers
 * dependency arrow, and must never write through AR_ADHOC_SAVE /
 * AR_CACHED_SAVE / AR_BEGIN_SAVE (those fire model hooks and create a
 * cross-shape write). HARD: no baseline. Floor-of-1 on the realized
 * *_projection.c set (gate_require_scanned) so a renamed suffix cannot
 * pass hollow. Per-line override: projection-cache-ok:<tag> on the same
 * matched line. Scan is walk_src over one directory (find, not git index).
 * A present-but-unreadable scan file is UNPROVEN exit 2, never "no match". */

static const char k_pp_def[] = "engine/modules/storage/src";
static const char k_pp_suf[] = "_projection.c";
static const char k_pp_clean[] =
    "check_projections_pure: clean — every *_projection.c is a pure fold "
    "(no app includes, no AR model saves)\n";
static const char k_pp_guide[] =
    "A projection is a pure fold over the event/storage log into its own\n"
    "table(s). Fix options:\n"
    "  1. Drop the app-layer include (forward-declare, or move the symbol\n"
    "     down into lib/).\n"
    "  2. Replace the AR model save with raw projection SQL over the\n"
    "     projection's own table (projections do not fire model hooks).\n"
    "  3. For a legitimate cache write, add '// projection-cache-ok:<tag>'\n"
    "     on that line.\n";

struct pp_acc {
    regex_t *inc;
    regex_t *ar;
    regex_t *ov;
    FILE *viol;
    int nscan;
    int nviol;
};

static int pp_is_proj(const char *path)
{
    size_t n = strlen(path), m = strlen(k_pp_suf);
    return n >= m && memcmp(path + n - m, k_pp_suf, m) == 0;
}

static const char *pp_ltrim(const char *s)
{
    while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r'
           || *s == '\f' || *s == '\v')
        s++;
    return s;
}

static void pp_strip_nl(char *line, ssize_t n)
{
    if (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
        line[n - 1] = '\0';
}

static int pp_comp(regex_t *inc, regex_t *ar, regex_t *ov)
{
    int rc = pair_comp(inc, REG_EXTENDED,
                       "^[[:space:]]*#include[[:space:]]+\"",
                       "(services|controllers)/", "", "",
                       ar, REG_EXTENDED,
                       "AR_(ADHOC|CACHED|BEGIN)_SAVE",
                       "[[:space:]]*\\(", "", "");
    if (rc)
        return rc;
    rc = compile_pat(ov, REG_EXTENDED, "//[[:space:]]*projection-cache-ok:",
                     "[A-Za-z][A-Za-z0-9_-]*", "", "");
    if (rc) {
        drop2(inc, ar);
        return rc;
    }
    return 0;
}

static int pp_note(struct pp_acc *a, const char *path, const char *kind,
                   const char *line)
{
    if (fprintf(a->viol, "%s: %s: %s\n", path, kind, pp_ltrim(line)) < 0)
        return die("z23-lint: write failed\n", "");
    a->nviol++;
    return 0;
}

static int pp_scan_file(const char *path, struct pp_acc *a)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        pp_strip_nl(line, n);
        if (regexec(a->ov, line, 0, NULL, 0) == 0)
            continue;
        if (regexec(a->inc, line, 0, NULL, 0) == 0)
            rc = pp_note(a, path,
                         "projection includes an app-layer header "
                         "(services/ or controllers/)",
                         line);
        if (rc == 0 && regexec(a->ar, line, 0, NULL, 0) == 0)
            rc = pp_note(a, path, "projection uses the AR model save path",
                         line);
    }
    return fin(f, line, path, rc);
}

static int pp_on_file(const char *path, void *ctx)
{
    struct pp_acc *a = ctx;
    if (lint_path_is_excluded(path) || !pp_is_proj(path))
        return 0;
    a->nscan++;
    return pp_scan_file(path, a);
}

static int pp_copy_viol(FILE *from, FILE *to)
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

static int pp_report(struct pp_acc *a, FILE *out)
{
    if (a->nviol == 0) {
        if (fputs(k_pp_clean, out) < 0)
            return die("z23-lint: write failed\n", "");
        return 0;
    }
    if (fprintf(out,
                "\ncheck_projections_pure: %d projection-purity violation(s)\n\n",
                a->nviol) < 0)
        return die("z23-lint: write failed\n", "");
    int rc = pp_copy_viol(a->viol, out);
    if (rc)
        return rc;
    if (fputs("\n", out) < 0 || fputs(k_pp_guide, out) < 0)
        return die("z23-lint: write failed\n", "");
    return 1;
}

static int pp_eval(const char *scan_dir, FILE *out)
{
    regex_t inc, ar, ov;
    int rc = pp_comp(&inc, &ar, &ov);
    if (rc)
        return rc;
    FILE *viol = tmpfile();
    if (!viol) {
        drop3(&inc, &ar, &ov);
        return die("z23-lint: tmpfile failed\n", "");
    }
    struct pp_acc a = {
        .inc = &inc, .ar = &ar, .ov = &ov, .viol = viol
    };
    rc = walk_src(scan_dir, 0, pp_on_file, &a);
    if (rc == 0) {
        char hint[4096];
        if (ovf(snprintf(hint, sizeof hint,
                         "no *_projection.c found under '%s' — a "
                         "projection file was renamed/moved?",
                         scan_dir),
                sizeof hint))
            rc = 2;
        else
            rc = gate_require_scanned(a.nscan, 1, "check_projections_pure",
                                      hint);
    }
    if (rc == 0)
        rc = pp_report(&a, out);
    fclose(viol);
    drop3(&inc, &ar, &ov);
    return rc;
}

int check_projections_pure_run(int argc, char **argv)
{
    const char *dir;
    (void)argc;
    (void)argv;
    dir = getenv("ZCL_PROJ_SCAN_DIR");
    return pp_eval((dir && dir[0]) ? dir : k_pp_def, stdout);
}

static int pp_st_run(const char *dir, int want_rc, const char *need)
{
    FILE *out = tmpfile();
    if (!out)
        return die("z23-lint: tmpfile failed\n", "");
    int rc = pp_eval(dir, out);
    char buf[4096];
    int sr = csr_slurp(out, buf, sizeof buf);
    fclose(out);
    if (sr)
        return sr;
    if (rc != want_rc)
        return 1;
    return (need && need[0] && strstr(buf, need) == NULL) ? 1 : 0;
}

static int pp_st_write(const char *dir, const char *body)
{
    char path[4096];
    if (ovf(snprintf(path, sizeof path, "%s/p_projection.c", dir), sizeof path))
        return 1;
    (void)unlink(path);
    return body ? csr_write(path, body) : 0;
}

static int pp_st_empty(const char *dir)
{
    return pp_st_write(dir, NULL) || pp_st_run(dir, 2, NULL);
}

static int pp_st_clean(const char *dir)
{
    return pp_st_write(dir, "int p(void) { return 0; }\n")
        || pp_st_run(dir, 0,
                     "check_projections_pure: clean — every *_projection.c "
                     "is a pure fold (no app includes, no AR model saves)");
}

static int pp_st_inc(const char *dir)
{
    return pp_st_write(dir, "#include \"services/foo.h\"\n")
        || pp_st_run(dir, 1,
                     "projection includes an app-layer header "
                     "(services/ or controllers/): #include \"services/foo.h\"");
}

static int pp_st_ar(const char *dir)
{
    return pp_st_write(dir, "void f(void) { AR_ADHOC_SAVE(m); }\n")
        || pp_st_run(dir, 1,
                     "projection uses the AR model save path: "
                     "void f(void) { AR_ADHOC_SAVE(m); }");
}

static int pp_st_ov(const char *dir)
{
    return pp_st_write(dir,
                       "#include \"services/foo.h\" "
                       "// projection-cache-ok:memo\n"
                       "void f(void) { AR_ADHOC_SAVE(m); } "
                       "// projection-cache-ok:cache\n")
        || pp_st_run(dir, 0,
                     "check_projections_pure: clean — every *_projection.c "
                     "is a pure fold (no app includes, no AR model saves)");
}

static int pp_st_pats(void)
{
    regex_t inc, ar, ov;
    int rc = pp_comp(&inc, &ar, &ov);
    if (rc)
        return 1;
    const char *t = "check_projections_pure";
    int bad = want(t, &inc, "#include \"services/foo.h\"", 1)
            | want(t, &inc, "  #include \"controllers/x.h\"", 1)
            | want(t, &inc, "#include \"storage/x.h\"", 0)
            | want(t, &ar, "AR_ADHOC_SAVE(", 1)
            | want(t, &ar, "AR_CACHED_SAVE (", 1)
            | want(t, &ar, "AR_BEGIN_SAVE(", 1)
            | want(t, &ar, "AR_FOO_SAVE(", 0)
            | want(t, &ov, "// projection-cache-ok:memo", 1)
            | want(t, &ov, "// projection-cache-ok:", 0);
    drop3(&inc, &ar, &ov);
    return bad;
}

int check_projections_pure_selftest(void)
{
    const char *td = env_or("TMPDIR", "/tmp");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-pp.XXXXXX", td),
            sizeof tmpl))
        return 2;
    char *tmp = mkdtemp(tmpl);
    if (!tmp)
        return die("z23-lint: mkdir failed: %s\n", td);
    int bad = pp_st_pats();
    bad |= pp_st_empty(tmp);
    bad |= pp_st_clean(tmp);
    bad |= pp_st_inc(tmp);
    bad |= pp_st_ar(tmp);
    bad |= pp_st_ov(tmp);
    (void)rap_rm_rf(tmp);
    return st_ok(bad, "check_projections_pure selftest: OK\n");
}
