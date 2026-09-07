/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — required-call presence/pairing fences of the C23
 * lint runtime (check-model-validation, check-lag-slo-observable).
 *
 * Single-gate-file placement ruling (2026-09-06, Linux side): both
 * small-pattern families are claimed by lintc26 (gate_ratchet_ports.c) and
 * lintc28 (gate_pattern_small.c), so new ports land in their own files; the
 * older in-file routing comments that would have folded a new port into an
 * existing family are overridden by that ruling. No family header claims
 * this exact subject.
 *
 * check-model-validation: every .c file directly under engine/models/src
 * must call at least one validates_* lifecycle macro or carry an explicit
 * ar-validate-skip:<tag> marker. A model with neither is a silent
 * validation gap.
 *
 * check-lag-slo-observable: legacy_mirror_sync_service.c must emit
 * EV_LAG_SLO_BREACH, and block_source_policy.c must honor
 * mirror_lag_sla_breach_blocks. EV_MIRROR_CONCURRENT_CATCHUP is deliberately
 * not required (post-B8 the mirror is monitor-only).
 *
 * Consumer 1 scan floor: the shell glob is silent on a vanished or empty
 * engine/models/src (nullglob → zero files → clean). This port refuses that
 * hollow scan with gate_require_scanned(count, 1) — zero model sources is a
 * repo-shape regression, not a clean tree. Consumer 2 is a fixed two-file
 * check, so it has no scan floor.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <errno.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

enum { MV_OK = 0, MV_MISSING = 1, MV_UNTAGGED = 2 };
enum { MV_MAX = 512, MV_PATH = 768, MV_LINE = 8192 };

struct mv_list { char v[MV_MAX][MV_PATH]; int n; };

struct mv_re {
    const regex_t *skip;
    const regex_t *val;
    const regex_t *bare;
};

static int mv_is_c(const char *name)
{
    size_t n = strlen(name);
    if (n < 3 || name[0] == '.')
        return 0;
    return name[n - 2] == '.' && name[n - 1] == 'c';
}

static int mv_comp(regex_t *skip, regex_t *val, regex_t *bare)
{
    int rc = compile_pat(skip, REG_EXTENDED,
                         "ar-validate-skip:[A-Za-z][A-Za-z0-9_-]+",
                         "", "", "");
    if (rc)
        return rc;
    rc = compile_pat(val, REG_EXTENDED,
                     "validates_[a-z_]+[[:space:]]*\\(", "", "", "");
    if (rc) {
        regfree(skip);
        return rc;
    }
    rc = compile_pat(bare, REG_EXTENDED,
                     "ar-validate-skip:?[[:space:]]*$", "", "", "");
    if (rc)
        drop2(skip, val);
    return rc;
}

static int mv_kind_of(int has_skip, int has_val, int has_bare)
{
    if (has_skip || has_val)
        return MV_OK;
    if (has_bare)
        return MV_UNTAGGED;
    return MV_MISSING;
}

static void mv_note_line(const char *line, struct mv_re re,
                         int *has_skip, int *has_val, int *has_bare)
{
    if (!*has_skip && regexec(re.skip, line, 0, NULL, 0) == 0)
        *has_skip = 1;
    if (!*has_val && regexec(re.val, line, 0, NULL, 0) == 0)
        *has_val = 1;
    if (!*has_bare && regexec(re.bare, line, 0, NULL, 0) == 0)
        *has_bare = 1;
}

static void mv_strip_nl(char *line, ssize_t *n)
{
    if (*n > 0 && line[*n - 1] == '\n')
        line[--(*n)] = '\0';
    if (*n > 0 && line[*n - 1] == '\r')
        line[--(*n)] = '\0';
}

/* In-memory per-file classifier used by --selftest probes (a)-(d). */
static int mv_classify_text(const char *text, struct mv_re re, int *kind)
{
    int has_skip = 0, has_val = 0, has_bare = 0;
    const char *p = text;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        if (n >= MV_LINE)
            return 2;
        char line[MV_LINE];
        memcpy(line, p, n);
        line[n] = '\0';
        if (n > 0 && line[n - 1] == '\r')
            line[n - 1] = '\0';
        mv_note_line(line, re, &has_skip, &has_val, &has_bare);
        if (has_skip)
            break;
        if (!nl)
            break;
        p = nl + 1;
    }
    *kind = mv_kind_of(has_skip, has_val, has_bare);
    return 0;
}

static int mv_classify_file(const char *path, struct mv_re re, int *kind)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int has_skip = 0, has_val = 0, has_bare = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        mv_strip_nl(line, &n);
        mv_note_line(line, re, &has_skip, &has_val, &has_bare);
        if (has_skip)
            break;
    }
    *kind = mv_kind_of(has_skip, has_val, has_bare);
    return fin(f, line, path, 0);
}

static int mv_push(struct mv_list *l, const char *path)
{
    if (l->n >= MV_MAX)
        return die("z23-lint: too many model-validation hits\n", "");
    if (ovf(snprintf(l->v[l->n], MV_PATH, "%s", path), MV_PATH))
        return 2;
    l->n++;
    return 0;
}

static void mv_free_dir(struct dirent **names, int n)
{
    for (int i = 0; i < n; i++)
        free(names[i]);
    free(names);
}

static int mv_handle_c(const char *dir, const char *name, struct mv_re re,
                       struct mv_list *missing, struct mv_list *untagged,
                       int *scanned)
{
    char path[MV_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/%s", dir, name), sizeof path))
        return 2;
    int kind = 0;
    int rc = mv_classify_file(path, re, &kind);
    if (rc)
        return rc;
    (*scanned)++;
    if (kind == MV_MISSING)
        return mv_push(missing, path);
    if (kind == MV_UNTAGGED)
        return mv_push(untagged, path);
    return 0;
}

static int mv_scan_dir(const char *dir, struct mv_re re,
                       struct mv_list *missing, struct mv_list *untagged,
                       int *scanned)
{
    struct dirent **names = NULL;
    int n = scandir(dir, &names, NULL, alphasort);
    if (n < 0) {
        if (errno == ENOENT) {
            *scanned = 0;
            return 0;
        }
        return die("z23-lint: cannot read directory %s\n", dir);
    }
    int rc = 0;
    for (int i = 0; i < n && rc == 0; i++) {
        const char *name = names[i]->d_name;
        if (mv_is_c(name))
            rc = mv_handle_c(dir, name, re, missing, untagged, scanned);
    }
    mv_free_dir(names, n);
    return rc;
}

static int mv_print_list(FILE *out, const char *hdr, const struct mv_list *l)
{
    if (l->n == 0)
        return 0;
    if (fprintf(out, "%s\n", hdr) < 0)
        return die("z23-lint: write failed\n", "");
    for (int i = 0; i < l->n; i++) {
        if (fprintf(out, "  %s\n", l->v[i]) < 0)
            return die("z23-lint: write failed\n", "");
    }
    return 0;
}

static int mv_eval(const char *dir, FILE *out)
{
    regex_t skip, val, bare;
    int rc = mv_comp(&skip, &val, &bare);
    if (rc)
        return rc;
    struct mv_re re = { .skip = &skip, .val = &val, .bare = &bare };
    struct mv_list missing = {0}, untagged = {0};
    int scanned = 0;
    rc = mv_scan_dir(dir, re, &missing, &untagged, &scanned);
    drop3(&skip, &val, &bare);
    if (rc)
        return rc;
    char hint[MV_PATH];
    if (ovf(snprintf(hint, sizeof hint,
                     "no *.c files under '%s'", dir), sizeof hint))
        return 2;
    rc = gate_require_scanned(scanned, 1, "check_model_validation", hint);
    if (rc)
        return rc;
    rc = mv_print_list(out,
            "FAIL: the following model sources have no validates_* "
            "call and no ar-validate-skip:<tag> marker:", &missing);
    if (rc)
        return rc;
    rc = mv_print_list(out,
            "FAIL: the following files have an ar-validate-skip "
            "marker without a :<tag>:", &untagged);
    if (rc)
        return rc;
    if (missing.n || untagged.n)
        return 1;
    if (fputs("check_model_validation: clean — every model has "
              "validates_* or a tagged skip marker\n", out) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

int check_model_validation_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return mv_eval("engine/models/src", stdout);
}

static int mv_st_text(struct mv_re re, const char *text, int want_kind)
{
    int kind = -1;
    int rc = mv_classify_text(text, re, &kind);
    return rc != 0 || kind != want_kind;
}

static int mv_st_capture(const char *dir, int want_rc,
                         const char *need1, const char *need2)
{
    FILE *out = tmpfile();
    if (!out)
        return die("z23-lint: tmpfile failed\n", "");
    int rc = mv_eval(dir, out);
    char buf[4096];
    int sr = csr_slurp(out, buf, sizeof buf);
    fclose(out);
    if (sr)
        return sr;
    if (rc != want_rc)
        return 1;
    if (need1 && strstr(buf, need1) == NULL)
        return 1;
    if (need2 && strstr(buf, need2) == NULL)
        return 1;
    return 0;
}

static int mv_st_write_c(const char *dir, const char *name, const char *text)
{
    char path[MV_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/%s", dir, name), sizeof path))
        return 2;
    return csr_write(path, text);
}

static int mv_st_kinds(struct mv_re re)
{
    int bad = mv_st_text(re, "ar-validate-skip:infra\n", MV_OK);
    bad |= mv_st_text(re, "void f(void) { validates_presence(m); }\n", MV_OK);
    bad |= mv_st_text(re, "int x;\n", MV_MISSING);
    bad |= mv_st_text(re, "ar-validate-skip:\n", MV_UNTAGGED);
    bad |= mv_st_text(re, "ar-validate-skip\n", MV_UNTAGGED);
    bad |= mv_st_text(re, "ar-validate-skip:   \n", MV_UNTAGGED);
    return bad;
}

static int mv_st_dirs(const char *root)
{
    int bad = mv_st_write_c(root, "skip.c", "ar-validate-skip:infra\n");
    bad |= mv_st_write_c(root, "val.c", "validates_presence(m);\n");
    if (bad)
        return 1;
    bad |= mv_st_capture(root, 0,
            "check_model_validation: clean — every model has "
            "validates_* or a tagged skip marker", NULL);
    bad |= mv_st_write_c(root, "miss.c", "int x;\n");
    bad |= mv_st_write_c(root, "bare.c", "ar-validate-skip:\n");
    if (bad)
        return 1;
    bad |= mv_st_capture(root, 1,
            "FAIL: the following model sources have no validates_* "
            "call and no ar-validate-skip:<tag> marker:",
            "FAIL: the following files have an ar-validate-skip "
            "marker without a :<tag>:");
    return bad;
}

int check_model_validation_selftest(void)
{
    regex_t skip, val, bare;
    int rc = mv_comp(&skip, &val, &bare);
    if (rc)
        return rc;
    struct mv_re re = { .skip = &skip, .val = &val, .bare = &bare };
    const char *t = "check_model_validation";
    int bad = want(t, &skip, "ar-validate-skip:infra", 1)
            | want(t, &skip, "ar-validate-skip:", 0)
            | want(t, &val, "validates_presence(", 1)
            | want(t, &val, "validates_presence (", 1)
            | want(t, &bare, "ar-validate-skip:", 1)
            | want(t, &bare, "ar-validate-skip", 1)
            | want(t, &bare, "ar-validate-skip:infra", 0);
    bad |= mv_st_kinds(re);
    drop3(&skip, &val, &bare);
    const char *td = env_or("TMPDIR", "/tmp");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-mv.XXXXXX", td),
            sizeof tmpl))
        return 2;
    char *tmp = mkdtemp(tmpl);
    if (!tmp)
        return die("z23-lint: mkdir failed: %s\n", td);
    bad |= mv_st_dirs(tmp);
    bad |= mv_st_capture(tmp, 1, NULL, NULL);
    char empty[4096];
    if (ovf(snprintf(empty, sizeof empty, "%s/empty", tmp), sizeof empty)
        || csr_mkdirs(empty))
        bad = 1;
    else
        bad |= mv_st_capture(empty, 2, NULL, NULL);
    (void)rap_rm_rf(tmp);
    return st_ok(bad, "check_model_validation selftest: OK\n");
}

static int lso_is_reg(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static int lso_has(const char *path, const char *needle, int *found)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    *found = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        if (strstr(line, needle) != NULL) {
            *found = 1;
            break;
        }
    }
    return fin(f, line, path, rc);
}

static int lso_fail_lms(FILE *out, const char *path)
{
    if (fprintf(out, "%s: missing EV_LAG_SLO_BREACH emission\n", path) < 0
        || fputs("\n"
                 "FAIL: legacy_mirror_sync_service.c must emit EV_LAG_SLO_BREACH\n"
                 "      so node_health, sd_notify, and Prometheus can react to\n"
                 "      lag SLO breaches. Add a paired emit when crossing the\n"
                 "      breach_blocks / critical_blocks thresholds.\n",
                 out) < 0)
        return die("z23-lint: write failed\n", "");
    return 1;
}

static int lso_fail_policy(FILE *out, const char *path)
{
    if (fprintf(out, "%s: missing mirror_lag_sla_breach_blocks check\n",
                path) < 0
        || fputs("\n"
                 "FAIL: block_source_policy must honor\n"
                 "      in->mirror_lag_sla_breach_blocks in mirror_fallback_allowed().\n"
                 "      Without it, the mirror is gated strictly behind local\n"
                 "      retries — exactly the bug we shipped this gate to prevent.\n",
                 out) < 0)
        return die("z23-lint: write failed\n", "");
    return 1;
}

static int lso_not_found(FILE *out, const char *path)
{
    if (fprintf(out, "FAIL: %s not found\n", path) < 0)
        return die("z23-lint: write failed\n", "");
    return 1;
}

static int lso_eval(const char *lms, const char *policy, FILE *out)
{
    if (!lso_is_reg(lms))
        return lso_not_found(out, lms);
    int found = 0;
    int rc = lso_has(lms, "EV_LAG_SLO_BREACH", &found);
    if (rc)
        return rc;
    if (!found)
        return lso_fail_lms(out, lms);
    if (!lso_is_reg(policy))
        return lso_not_found(out, policy);
    rc = lso_has(policy, "mirror_lag_sla_breach_blocks", &found);
    if (rc)
        return rc;
    if (!found)
        return lso_fail_policy(out, policy);
    if (fputs("  OK: lag SLO emit + concurrent-redundancy override present\n",
              out) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

int check_lag_slo_observable_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return lso_eval("engine/services/src/legacy_mirror_sync_service.c",
                    "engine/services/src/block_source_policy.c", stdout);
}

static int lso_st_paths(const char *root, char *lms, size_t lms_cap,
                        char *pol, size_t pol_cap)
{
    if (ovf(snprintf(lms, lms_cap,
                     "%s/engine/services/src/legacy_mirror_sync_service.c",
                     root), lms_cap))
        return 2;
    if (ovf(snprintf(pol, pol_cap,
                     "%s/engine/services/src/block_source_policy.c",
                     root), pol_cap))
        return 2;
    return 0;
}

static int lso_st_run(const char *lms, const char *pol, int want_rc,
                      const char *need)
{
    FILE *out = tmpfile();
    if (!out)
        return die("z23-lint: tmpfile failed\n", "");
    int rc = lso_eval(lms, pol, out);
    char buf[4096];
    int sr = csr_slurp(out, buf, sizeof buf);
    fclose(out);
    if (sr)
        return sr;
    if (rc != want_rc)
        return 1;
    if (need && strstr(buf, need) == NULL)
        return 1;
    return 0;
}

static int lso_st_clean(const char *lms, const char *pol)
{
    int rc = csr_write(lms, "EV_LAG_SLO_BREACH\n");
    if (rc)
        return 1;
    rc = csr_write(pol, "mirror_lag_sla_breach_blocks\n");
    if (rc)
        return 1;
    return lso_st_run(lms, pol, 0,
            "  OK: lag SLO emit + concurrent-redundancy override present");
}

static int lso_st_no_emit(const char *lms, const char *pol)
{
    int rc = csr_write(lms, "int x;\n");
    if (rc)
        return 1;
    rc = csr_write(pol, "mirror_lag_sla_breach_blocks\n");
    if (rc)
        return 1;
    return lso_st_run(lms, pol, 1, "missing EV_LAG_SLO_BREACH emission");
}

static int lso_st_no_field(const char *lms, const char *pol)
{
    int rc = csr_write(lms, "EV_LAG_SLO_BREACH\n");
    if (rc)
        return 1;
    rc = csr_write(pol, "int y;\n");
    if (rc)
        return 1;
    return lso_st_run(lms, pol, 1, "missing mirror_lag_sla_breach_blocks check");
}

static int lso_st_no_lms(const char *lms, const char *pol)
{
    (void)unlink(lms);
    int rc = csr_write(pol, "mirror_lag_sla_breach_blocks\n");
    if (rc)
        return 1;
    return lso_st_run(lms, pol, 1, " not found");
}

int check_lag_slo_observable_selftest(void)
{
    const char *td = env_or("TMPDIR", "/tmp");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-lso.XXXXXX", td),
            sizeof tmpl))
        return 2;
    char *tmp = mkdtemp(tmpl);
    if (!tmp)
        return die("z23-lint: mkdir failed: %s\n", td);
    char lms[4096], pol[4096];
    int bad = lso_st_paths(tmp, lms, sizeof lms, pol, sizeof pol);
    if (bad == 0)
        bad = lso_st_clean(lms, pol);
    if (bad == 0)
        bad = lso_st_no_emit(lms, pol);
    if (bad == 0)
        bad = lso_st_no_field(lms, pol);
    if (bad == 0)
        bad = lso_st_no_lms(lms, pol);
    (void)rap_rm_rf(tmp);
    return st_ok(bad, "check_lag_slo_observable selftest: OK\n");
}
