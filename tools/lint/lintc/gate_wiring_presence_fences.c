/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — required-wiring presence fences over source text
 * (check-operator-needed-sink, check-shape-includes-header).
 *
 * Gates: check-operator-needed-sink, check-shape-includes-header
 * Two independent required-wiring presence fences: every production
 * EV_OPERATOR_NEEDED emit must be paired with a registered alert-rule
 * subscriber in engine/modules/event/src/alerts.c, and every file under
 * the three shape-owned source directories must #include the header that
 * defines that shape's contract. New family file: the 2026-09-06
 * single-gate-file placement ruling still stands (small-pattern families
 * are claimed; older in-file routing comments are overridden), and no
 * existing family header claims this subject.
 *
 * On 2026-05-25 the live tip could halt while EV_OPERATOR_NEEDED — the
 * loudest "a human must act" signal — reached no consumer. This gate
 * freezes the fix: a production emit must be paired with
 * `.trigger = EV_OPERATOR_NEEDED` and an event_observe call in alerts.c.
 *
 * A file's directory placement under engine/conditions/src/,
 * engine/models/src/, or engine/supervisors/src/ is a path-only claim
 * about its shape. This gate closes the mislabel hole by requiring the
 * matching shape-contract include. engine/jobs/ is deliberately not
 * covered (no job.h shape header exists yet).
 *
 * Scan floors (the shell originals have none): walk_src treats a missing
 * directory as empty (ENOENT -> 0 files). Consumer 1 floors at 1 scanned
 * *.c so a vanished production tree is UNPROVEN (exit 2) rather than
 * "no production emit" (exit 1). Consumer 2 floors at 1 scanned *.c
 * across the three shape roots so a vanished shape tree cannot report
 * clean. Both selftests plant files so the floors do not fire there.
 *
 * Enumeration is walk_src (plain recursive scandir of named roots), not
 * git-index: the shell uses grep -rln / find, not git ls-files.
 * lint_git_index_foreach is not present in lib.c.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

enum { SIH_MAX = 256, SIH_MSG = 512 };

static int wpf_id_end(unsigned char c)
{
    if (c == '\0')
        return 1;
    return !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
             || (c >= '0' && c <= '9') || c == '_');
}

static int wpf_line_bound(const regex_t *re, const char *line)
{
    regmatch_t m;
    if (regexec(re, line, 1, &m, 0) != 0)
        return 0;
    return wpf_id_end((unsigned char)line[m.rm_eo]);
}

static int wpf_file_bound(const char *path, const regex_t *re, int *hit)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    *hit = 0;
    while (getline(&line, &cap, f) >= 0) {
        if (wpf_line_bound(re, line)) {
            *hit = 1;
            break;
        }
    }
    return fin(f, line, path, 0);
}

static int wpf_cap(int rc, FILE *out, int want_rc, const char *needle)
{
    char buf[8192];
    int slurp = csr_slurp(out, buf, sizeof buf);
    fclose(out);
    if (slurp)
        return slurp;
    if (rc != want_rc)
        return 1;
    if (needle && needle[0] && strstr(buf, needle) == NULL)
        return 1;
    return 0;
}

static int wpf_tmp(char *tmpl, size_t cap, char **root)
{
    const char *td = env_or("TMPDIR", "/tmp");
    if (ovf(snprintf(tmpl, cap, "%s/z23-lint-wpf.XXXXXX", td), cap))
        return 2;
    *root = mkdtemp(tmpl);
    if (!*root)
        return die("z23-lint: mkdir failed: %s\n", td);
    return 0;
}

static int wpf_put(char *buf, size_t cap, const char *fmt, const char *root,
                   const char *text)
{
    if (ovf(snprintf(buf, cap, fmt, root), cap))
        return 1;
    return csr_write(buf, text);
}

/* ── check-operator-needed-sink ────────────────────────────────────────── */

struct ons_acc { regex_t *emit; int scanned; int hits; };

static int ons_comp(regex_t *emit, regex_t *trig, regex_t *obs)
{
    int rc = compile_pat(emit, REG_EXTENDED,
                         "event_emitf?[[:space:]]*\\([[:space:]]*",
                         "EV_OPERATOR_NEEDED", "", "");
    if (rc)
        return rc;
    rc = compile_pat(trig, REG_EXTENDED,
                     "\\.trigger[[:space:]]*=[[:space:]]*",
                     "EV_OPERATOR_NEEDED", "", "");
    if (rc) {
        regfree(emit);
        return rc;
    }
    rc = compile_pat(obs, REG_EXTENDED,
                     "event_observe(_async)?[[:space:]]*\\(", "", "", "");
    if (rc)
        drop2(emit, trig);
    return rc;
}

static int ons_on_file(const char *path, void *ctx)
{
    struct ons_acc *a = ctx;
    if (lint_path_is_excluded(path))
        return 0;
    a->scanned++;
    if (a->hits || strstr(path, "/test/") != NULL)
        return 0;
    int hit = 0;
    int rc = wpf_file_bound(path, a->emit, &hit);
    if (rc)
        return rc;
    if (hit)
        a->hits++;
    return 0;
}

static int ons_fail_no_emit(FILE *out)
{
    if (fputs("FAIL: no production emit of EV_OPERATOR_NEEDED found\n"
              "      The condition engine / watchdogs must emit EV_OPERATOR_NEEDED when\n"
              "      auto-healing is exhausted, or operators are never paged.\n",
              out) < 0)
        return die("z23-lint: write failed\n", "");
    return 1;
}

static int ons_fail_missing(const char *path, FILE *out)
{
    if (fprintf(out, "FAIL: %s not found (the EV_OPERATOR_NEEDED sink)\n",
                path) < 0)
        return die("z23-lint: write failed\n", "");
    return 1;
}

static int ons_fail_trig(const char *path, FILE *out)
{
    if (fprintf(out, "%s: missing alert rule with .trigger = EV_OPERATOR_NEEDED\n"
                "\n"
                "FAIL: EV_OPERATOR_NEEDED is emitted but has no registered subscriber.\n"
                "      Add a seed alert rule (.trigger = EV_OPERATOR_NEEDED) in alerts.c so\n"
                "      the signal reaches the health surface / sd_notify / webhook\n"
                "      sinks instead of being silently observed.\n", path) < 0)
        return die("z23-lint: write failed\n", "");
    return 1;
}

static int ons_fail_obs(const char *path, FILE *out)
{
    if (fprintf(out, "%s: alert rule for EV_OPERATOR_NEEDED present but no "
                "event_observe() registration\n"
                "\n"
                "FAIL: the alert rule must be wired to the event bus via\n"
                "      event_observe(rule->trigger, alert_observer, ...). Without it\n"
                "      the rule never fires and EV_OPERATOR_NEEDED reaches no sink.\n",
                path) < 0)
        return die("z23-lint: write failed\n", "");
    return 1;
}

static int ons_alerts(const char *path, const regex_t *trig,
                      const regex_t *obs, FILE *out)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        if (errno != ENOENT)
            return die("z23-lint: cannot stat %s\n", path);
        return ons_fail_missing(path, out);
    }
    if (!S_ISREG(st.st_mode))
        return ons_fail_missing(path, out);
    int th = 0, oh = 0;
    int rc = wpf_file_bound(path, trig, &th);
    if (rc)
        return rc;
    if (!th)
        return ons_fail_trig(path, out);
    rc = scan_re(path, obs, &oh, 0);
    if (rc)
        return rc;
    if (!oh)
        return ons_fail_obs(path, out);
    if (fputs("  OK: EV_OPERATOR_NEEDED emit paired with registered "
              "alerts.c subscriber\n", out) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int ons_eval(const char *const *roots, int nroots,
                    const char *alerts, FILE *out)
{
    regex_t emit, trig, obs;
    int rc = ons_comp(&emit, &trig, &obs);
    if (rc)
        return rc;
    struct ons_acc a = { .emit = &emit };
    for (int i = 0; i < nroots && rc == 0; i++)
        rc = walk_src(roots[i], 0, ons_on_file, &a);
    if (rc == 0)
        rc = gate_require_scanned(a.scanned, 1, "check_operator_needed_sink",
                "no *.c files under core engine contexts cognition platform");
    if (rc == 0 && a.hits == 0)
        rc = ons_fail_no_emit(out);
    if (rc == 0)
        rc = ons_alerts(alerts, &trig, &obs, out);
    drop3(&emit, &trig, &obs);
    return rc;
}

int check_operator_needed_sink_run(int argc, char **argv)
{
    static const char *const roots[] = {
        "core", "engine", "contexts", "cognition", "platform"
    };
    (void)argc;
    (void)argv;
    return ons_eval(roots, 5, "engine/modules/event/src/alerts.c", stdout);
}

static int ons_st_case(const char *root, const char *alerts,
                       int want_rc, const char *needle)
{
    FILE *out = tmpfile();
    if (!out)
        return die("z23-lint: tmpfile failed\n", "");
    const char *roots[] = { root };
    return wpf_cap(ons_eval(roots, 1, alerts, out), out, want_rc, needle);
}

static int ons_st_pat(void)
{
    regex_t emit, trig, obs;
    int rc = ons_comp(&emit, &trig, &obs);
    if (rc)
        return rc;
    int bad = !wpf_line_bound(&emit, "event_emitf(EV_OPERATOR_NEEDED, 0, x);")
            || !wpf_line_bound(&emit, "event_emit( EV_OPERATOR_NEEDED)")
            || wpf_line_bound(&emit, "event_emitf(EV_OPERATOR_NEEDED_X, 0);")
            || !wpf_line_bound(&trig, "        .trigger      = EV_OPERATOR_NEEDED,")
            || wpf_line_bound(&trig, ".trigger = EV_OPERATOR_NEEDED_X,")
            || want("check_operator_needed_sink", &obs,
                    "event_observe(t, alert_observer, NULL);", 1)
            || want("check_operator_needed_sink", &obs,
                    "event_observe_async(t, f, NULL);", 1)
            || want("check_operator_needed_sink", &obs, "event_observer(t);", 0);
    drop3(&emit, &trig, &obs);
    return bad;
}

static const char k_ons_emit[] =
    "event_emitf(EV_OPERATOR_NEEDED, 0, \"x\");\n";
static const char k_ons_ok[] =
    ".trigger = EV_OPERATOR_NEEDED;\nevent_observe(t, alert_observer, NULL);\n";

static int ons_st_clean(const char *root)
{
    char prod[4096], alerts[4096];
    if (wpf_put(prod, sizeof prod, "%s/engine/prod.c", root, k_ons_emit))
        return 1;
    if (wpf_put(alerts, sizeof alerts, "%s/alerts.c", root, k_ons_ok))
        return 1;
    return ons_st_case(root, alerts, 0,
        "  OK: EV_OPERATOR_NEEDED emit paired with registered alerts.c subscriber");
}

static int ons_st_no_emit(const char *root)
{
    char prod[4096], alerts[4096];
    if (wpf_put(prod, sizeof prod, "%s/engine/prod.c", root, "int x;\n"))
        return 1;
    if (wpf_put(alerts, sizeof alerts, "%s/alerts.c", root, k_ons_ok))
        return 1;
    return ons_st_case(root, alerts, 1,
                       "FAIL: no production emit of EV_OPERATOR_NEEDED found");
}

static int ons_st_no_trig(const char *root)
{
    char prod[4096], alerts[4096];
    if (wpf_put(prod, sizeof prod, "%s/engine/prod.c", root, k_ons_emit))
        return 1;
    if (wpf_put(alerts, sizeof alerts, "%s/alerts.c", root,
                "event_observe(t, alert_observer, NULL);\n"))
        return 1;
    return ons_st_case(root, alerts, 1,
                       "missing alert rule with .trigger = EV_OPERATOR_NEEDED");
}

static int ons_st_no_obs(const char *root)
{
    char prod[4096], alerts[4096];
    if (wpf_put(prod, sizeof prod, "%s/engine/prod.c", root, k_ons_emit))
        return 1;
    if (wpf_put(alerts, sizeof alerts, "%s/alerts.c", root,
                ".trigger = EV_OPERATOR_NEEDED;\n"))
        return 1;
    return ons_st_case(root, alerts, 1, "no event_observe() registration");
}

static int ons_st_test_only(const char *root)
{
    char prod[4096], testf[4096], alerts[4096];
    if (wpf_put(prod, sizeof prod, "%s/engine/prod.c", root, "int x;\n"))
        return 1;
    if (wpf_put(testf, sizeof testf, "%s/engine/test/x.c", root, k_ons_emit))
        return 1;
    if (wpf_put(alerts, sizeof alerts, "%s/alerts.c", root, k_ons_ok))
        return 1;
    return ons_st_case(root, alerts, 1,
                       "FAIL: no production emit of EV_OPERATOR_NEEDED found");
}

int check_operator_needed_sink_selftest(void)
{
    char tmpl[4096], *root;
    int rc = wpf_tmp(tmpl, sizeof tmpl, &root);
    if (rc)
        return rc;
    int bad = ons_st_pat();
    bad |= ons_st_clean(root);
    bad |= ons_st_no_emit(root);
    bad |= ons_st_no_trig(root);
    bad |= ons_st_no_obs(root);
    bad |= ons_st_test_only(root);
    (void)rap_rm_rf(root);
    return st_ok(bad, "check_operator_needed_sink selftest: OK\n");
}

/* ── check-shape-includes-header ───────────────────────────────────────── */

struct sih_rule {
    regex_t *ov;
    regex_t *a;
    regex_t *b;
    const char *suffix;
};

struct sih_acc {
    struct sih_rule *rule;
    int n;
    int scanned;
    char msg[SIH_MAX][SIH_MSG];
};

static int sih_inc(regex_t *re, const char *inner)
{
    return compile_pat(re, REG_EXTENDED | REG_NOSUB,
                       "^[[:space:]]*#include[[:space:]]+\"", inner, "\"", "");
}

static int sih_comp(regex_t *ov, regex_t *ch, regex_t *cd, regex_t *mh,
                    regex_t *sd, regex_t *sh)
{
    int rc = compile_pat(ov, REG_EXTENDED | REG_NOSUB,
                         "//[[:space:]]*shape-include-ok:",
                         "[A-Za-z][A-Za-z0-9_-]*", "", "");
    if (rc)
        return rc;
    rc = sih_inc(ch, "framework/condition\\.h");
    if (rc) {
        regfree(ov);
        return rc;
    }
    rc = sih_inc(cd, "conditions/[^\"]+");
    if (rc) {
        drop2(ov, ch);
        return rc;
    }
    rc = sih_inc(mh, "models/[^\"]+");
    if (rc) {
        drop3(ov, ch, cd);
        return rc;
    }
    rc = sih_inc(sd, "supervisors/[^\"]+");
    if (rc) {
        drop3(ov, ch, cd);
        regfree(mh);
        return rc;
    }
    rc = sih_inc(sh, "util/supervisor\\.h");
    if (rc) {
        drop3(ov, ch, cd);
        drop2(mh, sd);
    }
    return rc;
}

static void sih_drop(regex_t *ov, regex_t *ch, regex_t *cd, regex_t *mh,
                     regex_t *sd, regex_t *sh)
{
    drop3(ov, ch, cd);
    drop3(mh, sd, sh);
}

static int sih_cmp(const void *x, const void *y)
{
    return strcmp(x, y);
}

static int sih_ok(struct sih_acc *a, const char *path, int *ok)
{
    int ov = 0, ha = 0, hb = 0;
    int rc = scan_re(path, a->rule->ov, &ov, 0);
    if (rc)
        return rc;
    if (ov) {
        *ok = 1;
        return 0;
    }
    rc = scan_re(path, a->rule->a, &ha, 0);
    if (rc)
        return rc;
    if (a->rule->b) {
        rc = scan_re(path, a->rule->b, &hb, 0);
        if (rc)
            return rc;
    }
    *ok = ha || hb;
    return 0;
}

static int sih_note(struct sih_acc *a, const char *path)
{
    if (a->n >= SIH_MAX)
        return die("z23-lint: derived buffer overflow\n", "");
    return ovf(snprintf(a->msg[a->n++], SIH_MSG, "%s: %s",
                        path, a->rule->suffix), SIH_MSG);
}

static int sih_on_file(const char *path, void *ctx)
{
    struct sih_acc *a = ctx;
    if (lint_path_is_excluded(path))
        return 0;
    a->scanned++;
    int ok = 0;
    int rc = sih_ok(a, path, &ok);
    if (rc || ok)
        return rc;
    return sih_note(a, path);
}

static int sih_scan_dir(const char *dir, struct sih_acc *a)
{
    int before = a->n;
    int rc = walk_src(dir, 0, sih_on_file, a);
    if (rc)
        return rc;
    qsort(a->msg[before], (size_t)(a->n - before), SIH_MSG, sih_cmp);
    return 0;
}

static int sih_report(const struct sih_acc *a, FILE *out)
{
    if (a->n == 0) {
        if (fputs("check_shape_includes_header: clean — every "
                  "condition/model/supervisor file includes its shape header\n",
                  out) < 0)
            return die("z23-lint: write failed\n", "");
        return 0;
    }
    if (fprintf(out, "\ncheck_shape_includes_header: %d shape file(s) "
                "missing their shape header\n\n", a->n) < 0)
        return die("z23-lint: write failed\n", "");
    for (int i = 0; i < a->n; i++) {
        if (fprintf(out, "  %s\n", a->msg[i]) < 0)
            return die("z23-lint: write failed\n", "");
    }
    if (fputs("\n"
              "A shape file must include the header that defines its shape contract.\n"
              "If it does not, it is a mislabeled file (likely a Service in disguise).\n"
              "Fix: add the shape header, move the file to the correct shape folder,\n"
              "or — for a genuine registry/aggregator — add '// shape-include-ok:<tag>'.\n",
              out) < 0)
        return die("z23-lint: write failed\n", "");
    return 1;
}

static int sih_rules(struct sih_acc *a, regex_t *ov, regex_t *ch, regex_t *cd,
                     regex_t *mh, regex_t *sd, regex_t *sh,
                     const char *cond, const char *mod, const char *sup)
{
    struct sih_rule r = { .ov = ov };
    a->rule = &r;
    r.a = ch;
    r.b = cd;
    r.suffix = "condition file includes neither \"framework/condition.h\" "
               "nor a \"conditions/\" header";
    int rc = sih_scan_dir(cond, a);
    if (rc)
        return rc;
    r.a = mh;
    r.b = NULL;
    r.suffix = "model file includes no \"models/\" header (activerecord lifecycle)";
    rc = sih_scan_dir(mod, a);
    if (rc)
        return rc;
    r.a = sd;
    r.b = sh;
    r.suffix = "supervisor file includes neither a \"supervisors/\" header "
               "nor \"util/supervisor.h\"";
    return sih_scan_dir(sup, a);
}

static int sih_eval(const char *cond, const char *mod, const char *sup,
                    FILE *out)
{
    regex_t ov, ch, cd, mh, sd, sh;
    int rc = sih_comp(&ov, &ch, &cd, &mh, &sd, &sh);
    if (rc)
        return rc;
    static struct sih_acc a;
    memset(&a, 0, sizeof a);
    rc = sih_rules(&a, &ov, &ch, &cd, &mh, &sd, &sh, cond, mod, sup);
    if (rc == 0)
        rc = gate_require_scanned(a.scanned, 1, "check_shape_includes_header",
                "no *.c files under the three shape src directories");
    if (rc == 0)
        rc = sih_report(&a, out);
    sih_drop(&ov, &ch, &cd, &mh, &sd, &sh);
    return rc;
}

int check_shape_includes_header_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return sih_eval("engine/conditions/src", "engine/models/src",
                    "engine/supervisors/src", stdout);
}

static int sih_st_case(const char *c, const char *m, const char *s,
                       int want_rc, const char *needle)
{
    FILE *out = tmpfile();
    if (!out)
        return die("z23-lint: tmpfile failed\n", "");
    return wpf_cap(sih_eval(c, m, s, out), out, want_rc, needle);
}

static int sih_st_trio(const char *root, const char *ct, const char *mt,
                       const char *st, int want_rc, const char *needle)
{
    char c[4096], m[4096], s[4096];
    if (wpf_put(c, sizeof c, "%s/conditions/a.c", root, ct))
        return 1;
    if (wpf_put(m, sizeof m, "%s/models/a.c", root, mt))
        return 1;
    if (wpf_put(s, sizeof s, "%s/supervisors/a.c", root, st))
        return 1;
    if (ovf(snprintf(c, sizeof c, "%s/conditions", root), sizeof c))
        return 1;
    if (ovf(snprintf(m, sizeof m, "%s/models", root), sizeof m))
        return 1;
    if (ovf(snprintf(s, sizeof s, "%s/supervisors", root), sizeof s))
        return 1;
    return sih_st_case(c, m, s, want_rc, needle);
}

static const char k_sih_c[] = "#include \"framework/condition.h\"\n";
static const char k_sih_m[] = "#include \"models/foo.h\"\n";
static const char k_sih_s[] = "#include \"util/supervisor.h\"\n";
static const char k_sih_bad[] = "int x;\n";

static int sih_st_clean(const char *root)
{
    return sih_st_trio(root, k_sih_c, k_sih_m, k_sih_s, 0,
        "check_shape_includes_header: clean — every "
        "condition/model/supervisor file includes its shape header");
}

static int sih_st_cond(const char *root)
{
    return sih_st_trio(root, k_sih_bad, k_sih_m, k_sih_s, 1,
        "condition file includes neither \"framework/condition.h\" "
        "nor a \"conditions/\" header");
}

static int sih_st_mod(const char *root)
{
    return sih_st_trio(root, k_sih_c, k_sih_bad, k_sih_s, 1,
        "model file includes no \"models/\" header (activerecord lifecycle)");
}

static int sih_st_sup(const char *root)
{
    return sih_st_trio(root, k_sih_c, k_sih_m, k_sih_bad, 1,
        "supervisor file includes neither a \"supervisors/\" header "
        "nor \"util/supervisor.h\"");
}

static int sih_st_ov(const char *root)
{
    return sih_st_trio(root, "// shape-include-ok:registry\nint x;\n",
                       k_sih_m, k_sih_s, 0,
        "check_shape_includes_header: clean — every "
        "condition/model/supervisor file includes its shape header");
}

static int sih_st_comment(const char *root)
{
    return sih_st_trio(root, k_sih_c, "/* #include \"models/foo.h\" */\n",
                       k_sih_s, 1,
        "model file includes no \"models/\" header (activerecord lifecycle)");
}

int check_shape_includes_header_selftest(void)
{
    char tmpl[4096], *root;
    int rc = wpf_tmp(tmpl, sizeof tmpl, &root);
    if (rc)
        return rc;
    int bad = sih_st_clean(root);
    bad |= sih_st_cond(root);
    bad |= sih_st_mod(root);
    bad |= sih_st_sup(root);
    bad |= sih_st_ov(root);
    bad |= sih_st_comment(root);
    (void)rap_rm_rf(root);
    return st_ok(bad, "check_shape_includes_header selftest: OK\n");
}
