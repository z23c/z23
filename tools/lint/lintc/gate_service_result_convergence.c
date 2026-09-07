/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates: check-service-result-convergence
 * Single-gate family file: a per-file SHRINKING-FLOOR ratchet (sibling to
 * already-ported E2 check_one_result_type), structurally unlike this
 * job's sibling gate_publish_containment.c (a global textual containment
 * tripwire, not a ratchet). Per the standing 2026-09-06 single-gate-file
 * placement ruling already used by gate_framework_shape.c and
 * gate_zclassicd_reach.c (each holds ONE gate, says so in its own
 * header), this port lands in its own file rather than folding in.
 *
 * Byte-parity C23 port of tools/scripts/check_service_result_convergence.sh
 * — Phase 3 of the framework refactor. E2 ratchets at FILE granularity (a
 * file is "clean" once it references struct zcl_result anywhere, even
 * with other bare-bool top-level functions left in it); this gate counts
 * the exported (non-static, top-level) bool-returning function
 * DEFINITIONS in each engine/services/src .c file and ratchets that
 * count down to zero, file by file, via a `<path> <count>` baseline.
 *
 * "Legacy bool export": a definition (not a forward declaration) whose
 * signature starts in column 0 with `bool <name>(`, ported as the small
 * explicit state machine svc_count_legacy() below (no single regexec can
 * express "scan forward across N lines watching for the FIRST of ';' or
 * a trailing '{'"). Baseline: a LOCAL loader (svc_load_baseline), modeled
 * on gate_controller_private_headers.c's cph_load_baseline precedent, not
 * a new shared lib.c helper — this consumer's new/grown/stale semantics
 * match none of lib.c's existing baseline shapes.
 *
 * Seams (already registered in engine/composition/flags.def):
 * ZCL_SERVICE_RESULT_CONVERGENCE_SCAN_DIR (default engine/services/src),
 * ZCL_SERVICE_RESULT_CONVERGENCE_BASELINE (default
 * tools/scripts/service_result_convergence_baseline.txt). Scan order: the
 * shell used `find "$SCAN_DIR" -name '*.c' | sort`; this port collects
 * paths via the runtime's own recursive walk, then byte-sorts (strcmp)
 * before classifying — deterministic BYTE order standing in for the
 * shell's locale-dependent `sort`, the replacement other ported gates
 * already use (e.g. gate_controller_private_headers.c).
 *
 * Baseline-missing: the shell's `[ -f "$BASELINE" ] || touch "$BASELINE"`
 * creates an empty baseline the first time the gate runs against a fresh
 * scan/baseline pair (every --selftest fixture) — ported in
 * svc_load_baseline. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"

static const char k_svc_name[] = "check_service_result_convergence";
static const char k_svc_scan_default[] = "engine/services/src";
static const char k_svc_baseline_default[] =
    "tools/scripts/service_result_convergence_baseline.txt";

enum { SVC_PATH = 512, SVC_MAXBASE = 2048, SVC_MAXFILE = 4096, SVC_MAXF = 1024 };

struct svc_baserow { char path[SVC_PATH]; int count; int seen; };
struct svc_finding { char path[SVC_PATH]; int live, recorded; };

struct svc_result {
    struct svc_finding new_l[SVC_MAXF];   int n_new;
    struct svc_finding grown_l[SVC_MAXF]; int n_grown;
    struct svc_finding clean_l[SVC_MAXF]; int n_clean;
    struct svc_finding marked_l[SVC_MAXF]; int n_marked;
    struct svc_finding shrink_l[SVC_MAXF]; int n_shrink;
    struct svc_finding miss_l[SVC_MAXF];  int n_miss;
};

static regex_t g_svc_dump, g_svc_sig, g_svc_marker;
static int g_svc_re_ok;

static int svc_regex_ensure(void)
{
    if (g_svc_re_ok)
        return 0;
    int cr = reg_fail(&g_svc_dump, regcomp(&g_svc_dump,
        "^bool[ \t]+[A-Za-z_][A-Za-z0-9_]*_dump_state_json\\(",
        REG_EXTENDED));
    if (cr)
        return cr;
    cr = reg_fail(&g_svc_sig, regcomp(&g_svc_sig,
        "^bool[ \t]+[A-Za-z_][A-Za-z0-9_]*\\(", REG_EXTENDED));
    if (cr) {
        regfree(&g_svc_dump);
        return cr;
    }
    cr = reg_fail(&g_svc_marker, regcomp(&g_svc_marker,
        "//[[:space:]]*one-result-type-ok:[A-Za-z][A-Za-z0-9_-]*",
        REG_EXTENDED));
    if (cr) {
        drop2(&g_svc_dump, &g_svc_sig);
        return cr;
    }
    g_svc_re_ok = 1;
    return 0;
}

static void svc_regex_drop(void)
{
    if (!g_svc_re_ok)
        return;
    drop3(&g_svc_dump, &g_svc_sig, &g_svc_marker);
    g_svc_re_ok = 0;
}

/* Port of count_legacy_bool_exports, one line at a time, matching the
 * shell's fallthrough shape: a line that just opened in_sig is re-tested
 * for ';'/trailing '{' on the SAME pass. */
static void svc_rstrip_nl(char *line)
{
    size_t n = strlen(line);
    while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
        line[--n] = '\0';
}

static void svc_trim_ws(const char *in, char *out, size_t cap)
{
    while (*in == ' ' || *in == '\t')
        in++;
    size_t n = strlen(in);
    while (n > 0 && (in[n - 1] == ' ' || in[n - 1] == '\t'))
        n--;
    if (n >= cap)
        n = cap - 1;
    memcpy(out, in, n);
    out[n] = '\0';
}

static int svc_count_legacy(const char *path, int *out)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int in_sig = 0, count = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        svc_rstrip_nl(line);
        if (!in_sig) {
            if (regexec(&g_svc_dump, line, 0, NULL, 0) == 0)
                continue;
            if (regexec(&g_svc_sig, line, 0, NULL, 0) == 0)
                in_sig = 1;
            else
                continue;
        }
        if (strchr(line, ';')) {
            in_sig = 0;
            continue;
        }
        char trimmed[SVC_MAXFILE];
        svc_trim_ws(line, trimmed, sizeof trimmed);
        size_t tl = strlen(trimmed);
        if (tl > 0 && trimmed[tl - 1] == '{') {
            count++;
            in_sig = 0;
        }
    }
    int ferr = ferror(f);
    free(line);
    fclose(f);
    if (ferr)
        return -1;
    *out = count;
    return 0;
}

static int svc_has_marker(const char *path, int *out)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    char *line = NULL;
    size_t cap = 0;
    int found = 0;
    while (!found && getline(&line, &cap, f) >= 0)
        found = regexec(&g_svc_marker, line, 0, NULL, 0) == 0;
    int ferr = ferror(f);
    free(line);
    fclose(f);
    if (ferr)
        return -1;
    *out = found;
    return 0;
}

static struct svc_baserow g_svc_base[SVC_MAXBASE];
static int g_svc_nbase;

/* bash's `${line%% *}` / `${line##* }`: first whitespace-delimited token
 * as the key, LAST as the value, regardless of anything between. */
static void svc_split_kv(const char *line, char *key, size_t kcap,
                         char *val, size_t vcap)
{
    const char *first_sp = NULL, *last_sp = NULL;
    for (const char *p = line; *p; p++)
        if (*p == ' ' || *p == '\t') {
            if (!first_sp)
                first_sp = p;
            last_sp = p;
        }
    size_t klen = first_sp ? (size_t)(first_sp - line) : strlen(line);
    if (klen >= kcap)
        klen = kcap - 1;
    memcpy(key, line, klen);
    key[klen] = '\0';
    const char *vstart = last_sp ? last_sp + 1 : line;
    size_t vlen = strlen(vstart);
    if (vlen >= vcap)
        vlen = vcap - 1;
    memcpy(val, vstart, vlen);
    val[vlen] = '\0';
}

static int svc_base_row(const char *raw)
{
    char line[SVC_MAXFILE];
    if (ovf(snprintf(line, sizeof line, "%s", raw), sizeof line))
        return 2;
    char *hash = strchr(line, '#');
    if (hash)
        *hash = '\0';
    char trimmed[SVC_MAXFILE];
    svc_trim_ws(line, trimmed, sizeof trimmed);
    if (!trimmed[0])
        return 0;
    if (g_svc_nbase >= SVC_MAXBASE)
        return die("z23-lint: baseline overflow\n", "");
    char key[SVC_PATH], val[64];
    svc_split_kv(trimmed, key, sizeof key, val, sizeof val);
    struct svc_baserow *row = &g_svc_base[g_svc_nbase++];
    if (ovf(snprintf(row->path, sizeof row->path, "%s", key),
            sizeof row->path))
        return 2;
    row->count = atoi(val);
    row->seen = 0;
    return 0;
}

/* `[ -f "$BASELINE" ] || touch "$BASELINE"`: an absent baseline is created
 * empty, not treated as an error — every --selftest fixture pair relies
 * on this to start from a clean baseline file. */
static int svc_touch_if_missing(const char *path)
{
    FILE *probe = fopen(path, "r");
    if (probe) {
        fclose(probe);
        return 0;
    }
    FILE *f = fopen(path, "w");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    return fclose(f) != 0 ? die("z23-lint: fclose failed: %s\n", path) : 0;
}

static int svc_load_baseline(const char *path)
{
    g_svc_nbase = 0;
    int rc = svc_touch_if_missing(path);
    if (rc)
        return rc;
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0)
        rc = svc_base_row(line);
    return fin(f, line, path, rc);
}

static int svc_base_find(const char *path)
{
    for (int i = 0; i < g_svc_nbase; i++)
        if (strcmp(g_svc_base[i].path, path) == 0)
            return i;
    return -1;
}

static char g_svc_files[SVC_MAXF][SVC_PATH];
static int g_svc_nfiles;

static int svc_collect_one(const char *path, void *ctx)
{
    (void)ctx;
    if (g_svc_nfiles >= SVC_MAXF)
        return die("z23-lint: scan-set overflow\n", "");
    return ovf(snprintf(g_svc_files[g_svc_nfiles++], SVC_PATH, "%s", path),
               SVC_PATH);
}

static int svc_path_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static int svc_collect_files(const char *scan_dir)
{
    g_svc_nfiles = 0;
    int rc = walk_src_root(k_svc_name, scan_dir, 0, svc_collect_one, NULL);
    if (rc)
        return rc;
    qsort(g_svc_files, (size_t)g_svc_nfiles, SVC_PATH, svc_path_cmp);
    return 0;
}

static int svc_push(struct svc_finding *arr, int *n, const char *path,
                    int live, int recorded)
{
    if (*n >= SVC_MAXF)
        return die("z23-lint: findings overflow\n", "");
    struct svc_finding *e = &arr[(*n)++];
    e->live = live;
    e->recorded = recorded;
    return ovf(snprintf(e->path, sizeof e->path, "%s", path),
               sizeof e->path);
}

static int svc_classify_baselined(struct svc_result *r, const char *f,
                                  int live, int marked, int row_idx)
{
    struct svc_baserow *row = &g_svc_base[row_idx];
    row->seen = 1;
    int recorded = row->count;
    if (marked)
        return svc_push(r->marked_l, &r->n_marked, f, live, recorded);
    if (live > recorded)
        return svc_push(r->grown_l, &r->n_grown, f, live, recorded);
    if (live == 0)
        return svc_push(r->clean_l, &r->n_clean, f, live, recorded);
    if (live < recorded)
        return svc_push(r->shrink_l, &r->n_shrink, f, live, recorded);
    return 0;
}

static int svc_classify_file(struct svc_result *r, const char *f)
{
    int live = 0, marked = 0;
    if (svc_count_legacy(f, &live) != 0)
        return die("z23-lint: cannot open %s\n", f);
    if (svc_has_marker(f, &marked) != 0)
        return die("z23-lint: cannot open %s\n", f);
    int idx = svc_base_find(f);
    if (idx >= 0)
        return svc_classify_baselined(r, f, live, marked, idx);
    if (marked)
        return 0;
    if (live > 0)
        return svc_push(r->new_l, &r->n_new, f, live, 0);
    return 0;
}

static int svc_missing_pass(struct svc_result *r)
{
    for (int i = 0; i < g_svc_nbase; i++)
        if (!g_svc_base[i].seen) {
            int rc = svc_push(r->miss_l, &r->n_miss, g_svc_base[i].path,
                              0, 0);
            if (rc)
                return rc;
        }
    if (r->n_miss > 1)
        qsort(r->miss_l, (size_t)r->n_miss, sizeof r->miss_l[0],
             svc_path_cmp);
    return 0;
}

static int svc_classify_all(struct svc_result *r)
{
    for (int i = 0; i < g_svc_nfiles; i++) {
        int rc = svc_classify_file(r, g_svc_files[i]);
        if (rc)
            return rc;
    }
    return svc_missing_pass(r);
}

static int svc_print_new(FILE *err, const struct svc_result *r)
{
    for (int i = 0; i < r->n_new; i++)
        if (fprintf(err, "  NEW file with legacy bool exports (not in "
                    "baseline): %s has %d legacy bool export(s) (not in "
                    "baseline, no marker)\n", r->new_l[i].path,
                    r->new_l[i].live) < 0)
            return die("z23-lint: write failed\n", "");
    return 0;
}

static int svc_print_grown(FILE *err, const struct svc_result *r)
{
    for (int i = 0; i < r->n_grown; i++)
        if (fprintf(err, "  REGRESSION (legacy exports grew past "
                    "baseline): %s grew to %d legacy bool export(s) "
                    "(baseline %d)\n", r->grown_l[i].path,
                    r->grown_l[i].live, r->grown_l[i].recorded) < 0)
            return die("z23-lint: write failed\n", "");
    return 0;
}

static int svc_print_stale(FILE *err, const struct svc_result *r)
{
    for (int i = 0; i < r->n_clean; i++)
        if (fprintf(err, "  STALE baseline entry (file is clean): %s is "
                    "now fully converted (0 legacy bool exports) — "
                    "delete its baseline line\n", r->clean_l[i].path) < 0)
            return die("z23-lint: write failed\n", "");
    for (int i = 0; i < r->n_marked; i++)
        if (fprintf(err, "  STALE baseline entry (file is now "
                    "marker-exempt): %s now carries a one-result-type-ok "
                    "marker (baseline said %d) — delete its baseline "
                    "line\n", r->marked_l[i].path,
                    r->marked_l[i].recorded) < 0)
            return die("z23-lint: write failed\n", "");
    for (int i = 0; i < r->n_miss; i++)
        if (fprintf(err, "  STALE baseline entry (file no longer "
                    "exists): %s\n", r->miss_l[i].path) < 0)
            return die("z23-lint: write failed\n", "");
    return 0;
}

static const char k_svc_fix_block[] =
    "\nFix options:\n"
    "  1. Migrate the file's legacy bool-returning top-level functions to\n"
    "     struct zcl_result (ZCL_OK / ZCL_ERR).\n"
    "  2. If the file genuinely owns no fallible service surface, add a\n"
    "     top-of-file marker '// one-result-type-ok:<tag>' (same marker\n"
    "     E2 uses) — then remove any stale baseline line for it.\n"
    "  3. A newly-baselined file's count may only be recorded at its\n"
    "     CURRENT count (a reviewable line); raising an existing\n"
    "     baseline entry needs an ADR, not this gate.\n"
    "  4. Remove stale baseline lines for files that are now clean,\n"
    "     marker-exempt, or deleted — %s must only shrink.\n";

static int svc_print_fail(FILE *err, const struct svc_result *r,
                          const char *baseline_path)
{
    if (fputs("\ncheck_service_result_convergence: FAIL — shrinking-floor "
              "violations\n\n", err) < 0)
        return die("z23-lint: write failed\n", "");
    int rc = svc_print_new(err, r);
    if (rc == 0)
        rc = svc_print_grown(err, r);
    if (rc == 0)
        rc = svc_print_stale(err, r);
    if (rc == 0 && fprintf(err, k_svc_fix_block, baseline_path) < 0)
        rc = die("z23-lint: write failed\n", "");
    return rc == 0 ? 1 : rc;
}

static int svc_print_pass(FILE *out, const struct svc_result *r)
{
    if (fprintf(out, "check_service_result_convergence: clean — %d "
                "baselined legacy service file(s), no new/grown/stale "
                "entries\n", g_svc_nbase) < 0)
        return die("z23-lint: write failed\n", "");
    if (r->n_shrink == 0)
        return 0;
    if (fputs("\n  Baseline can tighten (files shrank but still have "
              "legacy exports):\n", out) < 0)
        return die("z23-lint: write failed\n", "");
    for (int i = 0; i < r->n_shrink; i++)
        if (fprintf(out, "    %s is now %d legacy bool export(s) "
                    "(baseline %d) — tighten the baseline entry to %d\n",
                    r->shrink_l[i].path, r->shrink_l[i].live,
                    r->shrink_l[i].recorded, r->shrink_l[i].live) < 0)
            return die("z23-lint: write failed\n", "");
    return 0;
}

static int svc_any_fail(const struct svc_result *r)
{
    return r->n_new || r->n_grown || r->n_clean || r->n_marked || r->n_miss;
}

static int svc_run_body(FILE *out, FILE *err)
{
    const char *scan_dir = env_or("ZCL_SERVICE_RESULT_CONVERGENCE_SCAN_DIR",
                                  k_svc_scan_default);
    const char *baseline = env_or("ZCL_SERVICE_RESULT_CONVERGENCE_BASELINE",
                                  k_svc_baseline_default);
    int rc = svc_load_baseline(baseline);
    if (rc == 0)
        rc = svc_collect_files(scan_dir);
    if (rc == 0)
        rc = gate_require_scanned(g_svc_nfiles, 1, k_svc_name,
                "no *.c under the scan dir — was the services shape dir "
                "renamed/moved?");
    if (rc)
        return rc;
    static struct svc_result r;
    memset(&r, 0, sizeof r);
    rc = svc_classify_all(&r);
    if (rc)
        return rc;
    return svc_any_fail(&r) ? svc_print_fail(err, &r, baseline)
                            : svc_print_pass(out, &r);
}

int check_service_result_convergence_run(int argc, char **argv)
{
    (void)argc; (void)argv;
    char root[4096];
    int rc = cic_repo_root(root, sizeof root);
    if (rc == 0 && chdir(root) != 0)
        rc = 2;
    if (rc == 0)
        rc = svc_regex_ensure();
    if (rc == 0) {
        rc = svc_run_body(stdout, stderr);
        svc_regex_drop();
    }
    return rc;
}

struct svc_env_snap { char val[256]; int set; };

static int svc_snap_save(struct svc_env_snap *sd, struct svc_env_snap *sb)
{
    const char *d = getenv("ZCL_SERVICE_RESULT_CONVERGENCE_SCAN_DIR");
    const char *b = getenv("ZCL_SERVICE_RESULT_CONVERGENCE_BASELINE");
    sd->set = d != NULL;
    sb->set = b != NULL;
    if (d && ovf(snprintf(sd->val, sizeof sd->val, "%s", d), sizeof sd->val))
        return 2;
    if (b && ovf(snprintf(sb->val, sizeof sb->val, "%s", b), sizeof sb->val))
        return 2;
    return 0;
}

static int svc_snap_restore(const struct svc_env_snap *sd,
                            const struct svc_env_snap *sb)
{
    int rc = sd->set ? setenv("ZCL_SERVICE_RESULT_CONVERGENCE_SCAN_DIR",
                              sd->val, 1)
        : unsetenv("ZCL_SERVICE_RESULT_CONVERGENCE_SCAN_DIR");
    if (rc == 0)
        rc = sb->set ? setenv("ZCL_SERVICE_RESULT_CONVERGENCE_BASELINE",
                              sb->val, 1)
            : unsetenv("ZCL_SERVICE_RESULT_CONVERGENCE_BASELINE");
    return rc == 0 ? 0 : die("z23-lint: setenv failed\n", "");
}

/* Runs svc_run_body() with the two seams pointed at a private
 * test-tmp/svc_st_<tag> fixture pair, hands back only exit code + a
 * capture of stdout+stderr for the caller to grep. */
static int svc_run_fixture(const char *tag, char *ob, size_t obcap,
                           int *code)
{
    char scan_dir[256], baseline[256];
    if (ovf(snprintf(scan_dir, sizeof scan_dir, "test-tmp/svc_st_%s/src",
                     tag), sizeof scan_dir)
        || ovf(snprintf(baseline, sizeof baseline,
                        "test-tmp/svc_st_%s/baseline.txt", tag),
               sizeof baseline))
        return 2;
    if (setenv("ZCL_SERVICE_RESULT_CONVERGENCE_SCAN_DIR", scan_dir, 1) != 0
        || setenv("ZCL_SERVICE_RESULT_CONVERGENCE_BASELINE", baseline, 1)
            != 0)
        return die("z23-lint: setenv failed\n", "");
    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err)
        return die("z23-lint: tmpfile failed\n", "");
    *code = svc_run_body(out, err);
    int rc = csr_slurp(out, ob, obcap);
    if (rc == 0) {
        char eb[4096];
        rc = csr_slurp(err, eb, sizeof eb);
        if (rc == 0 && ovf(snprintf(ob + strlen(ob), obcap - strlen(ob),
                                   "%s", eb), obcap - strlen(ob)))
            rc = 2;
    }
    fclose(out);
    fclose(err);
    return rc;
}

static int svc_st_fail(const char *tag, const char *why)
{
    char root[256];
    snprintf(root, sizeof root, "test-tmp/svc_st_%s", tag);
    fprintf(stderr, "%s: SELFTEST FAILED — %s (%s)\n", k_svc_name, why, tag);
    (void)rap_rm_rf(root);
    return 2;
}

/* One row per lettered case (a)-(i) from the job brief: a fixture pair
 * (src/x.c, baseline.txt), the wanted exit code, a substring that must
 * appear, and (cases f/h) a substring that must NOT appear. */
struct svc_case {
    const char *tag, *src, *baseline; int want_code;
    const char *want_needle, *want_forbid, *why;
};

static const struct svc_case k_svc_cases[] = {
    { "a", "bool x_one(void)\n{\n    return 1;\n}\n"
           "bool x_two(void)\n{\n    return 1;\n}\n",
      "test-tmp/svc_st_a/src/x.c 1\n", 1,
      "REGRESSION (legacy exports grew past baseline): "
      "test-tmp/svc_st_a/src/x.c grew to 2 legacy bool export(s) "
      "(baseline 1)", NULL, "regression not reported" },
    { "b", "int noop(void) { return 0; }\n",
      "test-tmp/svc_st_b/src/x.c 2\n", 1,
      "STALE baseline entry (file is clean): test-tmp/svc_st_b/src/x.c "
      "is now fully converted", NULL, "stale-clean not reported" },
    { "c", "// one-result-type-ok:legacy\nbool x(void)\n{\n    return 1;\n}\n",
      "test-tmp/svc_st_c/src/x.c 1\n", 1,
      "STALE baseline entry (file is now marker-exempt): "
      "test-tmp/svc_st_c/src/x.c now carries a one-result-type-ok marker "
      "(baseline said 1)", NULL, "stale-marked not reported" },
    { "d", "bool x(void)\n{\n    return 1;\n}\n",
      "test-tmp/svc_st_d/src/x.c 3\n", 0,
      "tighten the baseline entry to 1", NULL, "shrink advisory wrong" },
    { "e", "bool x(void)\n{\n    return 1;\n}\n", "", 1,
      "NEW file with legacy bool exports (not in baseline): "
      "test-tmp/svc_st_e/src/x.c has 1 legacy bool export(s) (not in "
      "baseline, no marker)", NULL, "new-file violation not reported" },
    { "f", "// one-result-type-ok:legacy\nbool x(void)\n{\n    return 1;\n}\n",
      "", 0, NULL, "x.c", "marked new file was not skipped" },
    { "g", "int noop(void) { return 0; }\n",
      "test-tmp/svc_st_g/src/gone.c 1\n", 1,
      "STALE baseline entry (file no longer exists): "
      "test-tmp/svc_st_g/src/gone.c", NULL, "stale-missing not reported" },
    { "h", "bool x_dump_state_json(struct json_value *v, const char *k)\n"
           "{\n    return 1;\n}\n", "", 0, NULL, "x.c",
      "dump_state_json not exempt" },
    { "i", "bool x_alone(void)\n{\n    return 1;\n}\n"
           "bool x_same(void) {\n    return 1;\n}\n"
           "bool x_decl(void);\n", "", 1, "has 2 legacy bool export(s)",
      NULL, "brace-style counting wrong" },
};

static int svc_case_check(const struct svc_case *c, const char *ob, int code)
{
    if (code != c->want_code)
        return 2;
    if (c->want_needle && !strstr(ob, c->want_needle))
        return 2;
    if (c->want_forbid && strstr(ob, c->want_forbid))
        return 2;
    return 0;
}

static int svc_run_case(const struct svc_case *c)
{
    char path[256];
    int rc = ovf(snprintf(path, sizeof path, "test-tmp/svc_st_%s/src/x.c",
                          c->tag), sizeof path);
    if (rc == 0)
        rc = csr_write(path, c->src);
    if (rc == 0)
        rc = ovf(snprintf(path, sizeof path,
                          "test-tmp/svc_st_%s/baseline.txt", c->tag),
                 sizeof path);
    if (rc == 0)
        rc = csr_write(path, c->baseline);
    char ob[4096];
    int code = 0;
    if (rc == 0)
        rc = svc_run_fixture(c->tag, ob, sizeof ob, &code);
    if (rc == 0)
        rc = svc_case_check(c, ob, code);
    char root[256];
    snprintf(root, sizeof root, "test-tmp/svc_st_%s", c->tag);
    (void)rap_rm_rf(root);
    return rc == 0 ? 0 : svc_st_fail(c->tag, c->why);
}

int check_service_result_convergence_selftest(void)
{
    char root[4096];
    int rc = cic_repo_root(root, sizeof root);
    if (rc == 0 && chdir(root) != 0)
        rc = 2;
    if (rc == 0)
        rc = svc_regex_ensure();
    struct svc_env_snap sd = { .set = 0 }, sb = { .set = 0 };
    if (rc == 0)
        rc = svc_snap_save(&sd, &sb);
    for (size_t i = 0; rc == 0
             && i < sizeof k_svc_cases / sizeof k_svc_cases[0]; i++)
        rc = svc_run_case(&k_svc_cases[i]);
    if (g_svc_re_ok)
        svc_regex_drop();
    int rrc = svc_snap_restore(&sd, &sb);
    if (rc == 0)
        rc = rrc;
    if (rc != 0)
        return rc;
    fputs("check_service_result_convergence: SELFTEST PASS — regression, "
          "stale-clean, stale-marked, shrink-advisory, new-file, "
          "marked-skip, stale-missing, dump_state_json exemption and both "
          "brace styles all behave\n", stdout);
    return 0;
}
