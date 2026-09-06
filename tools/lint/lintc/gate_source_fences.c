/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — source-invariant fence gates of the C23 lint
 * runtime (check-honest-witness, check-mint-skip-crypto-offline-only).
 */

/*
 * Gates: check-honest-witness, check-mint-skip-crypto-offline-only
 * Source-invariant fence gates: a find-driven tree walk over a fixed root
 * set, checking for a forbidden/required code pattern against an explicit
 * allow-list or baseline, failing loud on a hollow scan.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

enum { SF_LINE = 16384, SF_BODY = 131072, SF_HITS = 262144,
       MSC_MAX = 8192, MSC_PATH = 256 };

static int sf_dir(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return 0;
    return S_ISDIR(st.st_mode);
}

/* ── check-honest-witness ─────────────────────────────────────────────── */

static const char k_hw_cond[] = "engine/conditions/src";
static const char k_hw_base[] = "tools/lint/honest_witness_baseline.txt";
static const char k_hw_sig[] = "^static (inline )?bool +witness_[A-Za-z0-9_]+";
static const char k_hw_bare[] = "(^|[^[:alnum:]_])return (true|false);";
static const char k_hw_retw[] = "(^|[^[:alnum:]_])return([^[:alnum:]_]|$)";
static const char k_hw_inv[] =
    "return[[:space:]]+!?[[:space:]]*detect_|[!=]=[[:space:]]*detect_";
static const char k_hw_obs[] =
    "active_chain_height|active_chain_tip|current_tip_height|"
    "reducer_frontier_compute_hstar|reducer_frontier_provable_tip_cached|"
    "block_map_next|block_map_get|pindex_best_header|->nHeight|\\.nHeight|"
    "connman_max_peer_height|connman_outbound_healthy_count|dl_get_stats|"
    "\\.local_height|s\\.local_height|stage_repair_body_fetch_observed|"
    "block_index_have_data_readable|any_utxo_above|target_has_readable_data|"
    "sync_monitor_active_next_child_exists|sqlite3_step|sqlite3_prepare|"
    "[[:space:]]SELECT[[:space:]]|offered_height|offered_utxos|staged_row_count|"
    "received_utxos|(^|[^[:alnum:]_])requested([^[:alnum:]_]|$)";

struct hw_re { regex_t sig, bare, retw, inv, obs; };

static void hw_drop(struct hw_re *r)
{
    regfree(&r->sig); regfree(&r->bare); regfree(&r->retw);
    regfree(&r->inv); regfree(&r->obs);
}

static int hw_init(struct hw_re *r)
{
    int e = reg_fail(&r->sig, regcomp(&r->sig, k_hw_sig, REG_EXTENDED));
    if (e) return e;
    e = reg_fail(&r->bare, regcomp(&r->bare, k_hw_bare, REG_EXTENDED));
    if (e) { regfree(&r->sig); return e; }
    e = reg_fail(&r->retw, regcomp(&r->retw, k_hw_retw, REG_EXTENDED));
    if (e) { drop2(&r->sig, &r->bare); return e; }
    e = reg_fail(&r->inv, regcomp(&r->inv, k_hw_inv, REG_EXTENDED));
    if (e) { drop3(&r->sig, &r->bare, &r->retw); return e; }
    e = reg_fail(&r->obs, regcomp(&r->obs, k_hw_obs, REG_EXTENDED));
    if (e) {
        drop3(&r->sig, &r->bare, &r->retw);
        regfree(&r->inv);
        return e;
    }
    return 0;
}

static int hw_name_from_line(const regex_t *sig, const char *line,
                             char *name, size_t cap)
{
    if (regexec(sig, line, 0, NULL, 0) != 0)
        return 0;
    const char *w = strstr(line, "witness_");
    if (!w) return 0;
    size_t n = 8;
    while (isalnum((unsigned char)w[n]) || w[n] == '_')
        n++;
    if (n >= cap) return 0;
    memcpy(name, w, n);
    name[n] = '\0';
    return 1;
}

static int hw_slice_body(const char *text, const char *name, char *out, size_t cap)
{
    char fn[SR_NAME + 8];
    if (ovf(snprintf(fn, sizeof fn, "bool %s(", name), sizeof fn))
        return 2;
    size_t used = 0;
    out[0] = '\0';
    int flag = 0;
    const char *p = text;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        char line[SF_LINE];
        if (n >= sizeof line)
            return die("z23-lint: derived buffer overflow\n", "");
        memcpy(line, p, n);
        line[n] = '\0';
        if (n && line[n - 1] == '\r')
            line[--n] = '\0';
        if (!flag && strstr(line, fn))
            flag = 1;
        if (flag) {
            if (used + n + 2 > cap)
                return die("z23-lint: derived buffer overflow\n", "");
            memcpy(out + used, line, n);
            used += n;
            out[used++] = '\n';
            out[used] = '\0';
            if (strcmp(line, "}") == 0)
                return 0;
        }
        if (!nl) break;
        p = nl + 1;
    }
    return 0;
}

static int hw_filter_code(const char *body, char *code, size_t cap)
{
    size_t used = 0;
    code[0] = '\0';
    const char *p = body;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        char line[SF_LINE];
        const char *s;
        if (n >= sizeof line)
            return die("z23-lint: derived buffer overflow\n", "");
        memcpy(line, p, n);
        line[n] = '\0';
        s = line;
        while (isspace((unsigned char)*s)) s++;
        if (!(s[0] == '/' && s[1] == '/') && *s != '*'
            && !strstr(line, "(void)target_at_detect")) {
            if (used + n + 2 > cap)
                return die("z23-lint: derived buffer overflow\n", "");
            memcpy(code + used, line, n);
            used += n;
            code[used++] = '\n';
            code[used] = '\0';
        }
        if (!nl) break;
        p = nl + 1;
    }
    return 0;
}

static const char *hw_reason(const char *code, const struct hw_re *re)
{
    int bare = 0, other = 0, inv = 0, obs = 0;
    const char *p = code;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        char line[SF_LINE];
        if (n >= sizeof line)
            return "";
        memcpy(line, p, n);
        line[n] = '\0';
        int is_bare = regexec(&re->bare, line, 0, NULL, 0) == 0;
        if (is_bare) bare++;
        if (regexec(&re->retw, line, 0, NULL, 0) == 0 && !is_bare)
            other++;
        if (regexec(&re->inv, line, 0, NULL, 0) == 0)
            inv = 1;
        if (regexec(&re->obs, line, 0, NULL, 0) == 0)
            obs = 1;
        if (!nl) break;
        p = nl + 1;
    }
    if (bare > 0 && other == 0)
        return "TRIVIAL (constant post-condition observes nothing)";
    if (inv)
        return "PURE-INVERSE (re-runs detect; tautology, not progress)";
    if (!obs)
        return "NO-OBSERVABLE (reads only FSM/poison-absence state)";
    return "";
}

struct hw_acc {
    struct hw_re *re;
    struct sr_set *base;
    const char *mode;
    int scanned, violations, baselined, failed;
};

static int hw_slurp(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot scan %s\n", path);
    size_t n = fread(buf, 1, cap - 1, f);
    buf[n] = '\0';
    int err = ferror(f);
    if (fclose(f) != 0 || err)
        return die("z23-lint: read failed: %s\n", path);
    if (n == cap - 1)
        return die("z23-lint: derived buffer overflow\n", "");
    return 0;
}

static int hw_on_file(const char *path, void *ctx)
{
    struct hw_acc *a = ctx;
    if (lint_path_is_excluded(path))
        return 0;
    static char text[SF_BODY * 2];
    int rc = hw_slurp(path, text, sizeof text);
    if (rc) { a->failed = 1; return rc; }
    const char *p = text;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        char line[SF_LINE], name[SR_NAME];
        if (n >= sizeof line)
            return die("z23-lint: derived buffer overflow\n", "");
        memcpy(line, p, n);
        line[n] = '\0';
        if (n && line[n - 1] == '\r')
            line[n - 1] = '\0';
        if (hw_name_from_line(&a->re->sig, line, name, sizeof name)) {
            a->scanned++;
            static char body[SF_BODY], code[SF_BODY];
            rc = hw_slice_body(text, name, body, sizeof body);
            if (rc) { a->failed = 1; return rc; }
            if (!strstr(body, "// honest-witness-ok:")) {
                rc = hw_filter_code(body, code, sizeof code);
                if (rc) { a->failed = 1; return rc; }
                const char *reason = hw_reason(code, a->re);
                if (reason[0]) {
                    if (strcmp(a->mode, "RATCHET") == 0 && sr_has(a->base, name))
                        a->baselined++;
                    else {
                        a->violations++;
                        if (fprintf(stderr, "%s: %s: %s\n", path, name, reason) < 0)
                            return die("z23-lint: write failed\n", "");
                    }
                }
            }
        }
        if (!nl) break;
        p = nl + 1;
    }
    return 0;
}

static int hw_direct_c(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d) return 0;
    int hit = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        size_t nl = strlen(e->d_name);
        if (nl >= 2 && e->d_name[nl - 2] == '.' && e->d_name[nl - 1] == 'c') {
            hit = 1; break;
        }
    }
    closedir(d);
    return hit;
}

int check_honest_witness_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    const char *mode = env_or("ZCL_LINT_MODE", "WARN");
    char root[4096];
    if (cic_repo_root(root, sizeof root))
        return 2;
    if (chdir(root) != 0)
        return die("z23-lint: cannot scan %s\n", root);
    struct sr_set base = {0};
    int rc = sr_load(&base, k_hw_base);
    if (rc) return rc;
    struct hw_re re;
    rc = hw_init(&re);
    if (rc) return rc;
    struct hw_acc acc = { .re = &re, .base = &base, .mode = mode };
    if (sf_dir(k_hw_cond)) {
        rc = walk_src(k_hw_cond, 0, hw_on_file, &acc);
        if (rc || acc.failed) { hw_drop(&re); return rc ? rc : 2; }
    }
    if (sf_dir(k_hw_cond) && hw_direct_c(k_hw_cond) && acc.scanned == 0) {
        fprintf(stderr,
                "[check_honest_witness] BROKEN — 0 witnesses found in %s despite .c\n"
                "  files present; the producer/anchor is likely stale (witness signature\n"
                "  convention changed?). Refusing to report clean off an empty scan.\n",
                k_hw_cond);
        hw_drop(&re);
        return 2;
    }
    if (printf("[check_honest_witness] scanned %d witness(es) in %s\n",
               acc.scanned, k_hw_cond) < 0
        || printf("[check_honest_witness] %d violation(s) found (mode: %s)\n",
                  acc.violations, mode) < 0) {
        hw_drop(&re);
        return die("z23-lint: write failed\n", "");
    }
    if (acc.baselined > 0
        && printf("[check_honest_witness] %d baselined violation(s) ignored\n",
                  acc.baselined) < 0) {
        hw_drop(&re);
        return die("z23-lint: write failed\n", "");
    }
    if (puts("[check_honest_witness] an honest witness reads OBSERVABLE progress (tip/cursor/H*/block_map/SELECT), never poison-absence or FSM state") == EOF
        || puts("[check_honest_witness] document a reviewed exception with // honest-witness-ok:<reason>; baseline at tools/lint/honest_witness_baseline.txt (ratchet may only shrink)") == EOF) {
        hw_drop(&re);
        return die("z23-lint: write failed\n", "");
    }
    hw_drop(&re);
    if (acc.violations > 0
        && (strcmp(mode, "FAIL") == 0 || strcmp(mode, "RATCHET") == 0))
        return 1;
    return 0;
}

static int hw_case(struct hw_re *re, const char *src, const char *name,
                   const char *want)
{
    static char body[SF_BODY], code[SF_BODY];
    if (hw_slice_body(src, name, body, sizeof body)
        || hw_filter_code(body, code, sizeof code))
        return 1;
    const char *got = hw_reason(code, re);
    return want ? strcmp(got, want) != 0 : got[0] != '\0';
}

int check_honest_witness_selftest(void)
{
    struct hw_re re;
    if (hw_init(&re)) return 2;
    int bad = 0;
    bad |= hw_case(&re, "static bool witness_t(void) {\n    return true;\n}\n",
                   "witness_t", "TRIVIAL (constant post-condition observes nothing)");
    bad |= hw_case(&re,
                   "static bool witness_m(void) {\n"
                   "    if (x) return active_chain_height > 0;\n    return true;\n}\n",
                   "witness_m", NULL);
    bad |= hw_case(&re, "static bool witness_i(void) {\n    return !detect_x();\n}\n",
                   "witness_i", "PURE-INVERSE (re-runs detect; tautology, not progress)");
    bad |= hw_case(&re,
                   "static bool witness_o(void) {\n    return active_chain_height > t;\n}\n",
                   "witness_o", NULL);
    bad |= hw_case(&re,
                   "static bool witness_n(void) {\n    return current_state() == 0;\n}\n",
                   "witness_n", "NO-OBSERVABLE (reads only FSM/poison-absence state)");
    static char body[SF_BODY];
    const char *hatch =
        "static bool witness_h(void) {\n    // honest-witness-ok: reviewed\n"
        "    return true;\n}\n";
    bad |= hw_slice_body(hatch, "witness_h", body, sizeof body);
    bad |= strstr(body, "// honest-witness-ok:") == NULL;
    bad |= hw_reason("int x = requested;\n", &re)[0] != '\0';
    bad |= strcmp(hw_reason("int x = requested_height;\n", &re),
                  "NO-OBSERVABLE (reads only FSM/poison-absence state)") != 0;
    char name[SR_NAME];
    const char *sigs =
        "static bool witness_alpha(void) {\n}\n"
        "static inline bool witness_beta(int y) {\n}\n"
        "static bool\nwitness_multiline(void) { return true; }\n";
    int nnames = 0;
    for (const char *sp = sigs; *sp; ) {
        const char *nl = strchr(sp, '\n');
        size_t n = nl ? (size_t)(nl - sp) : strlen(sp);
        char line[SF_LINE];
        memcpy(line, sp, n); line[n] = '\0';
        if (hw_name_from_line(&re.sig, line, name, sizeof name)) nnames++;
        if (!nl) break;
        sp = nl + 1;
    }
    bad |= nnames != 2;
    const char *stpath = "tools/lint/lintc/_hw_selftest_baseline.txt";
    struct sr_set s = {0};
    bad |= csr_write(stpath, "# comment\n\nwitness_foo\n") != 0;
    bad |= sr_load(&s, stpath) != 0;
    bad |= !sr_has(&s, "witness_foo") || sr_has(&s, "witness_bar") || s.count != 1;
    (void)unlink(stpath);
    hw_drop(&re);
    return st_ok(bad, "check_honest_witness selftest: OK\n");
}

/* ── check-mint-skip-crypto-offline-only ──────────────────────────────── */

static const char k_msc_setter[] = "mint_skip_crypto_set";
static const char k_msc_mod[] = "engine/jobs/src/mint_skip_crypto.c";
static const char k_msc_drv[] = "engine/composition/src/boot_refold_staged.c";
static const char k_msc_call_re[] = "mint_skip_crypto_set[[:space:]]*\\(";
static const char *const k_msc_roots[] = {
    "app", "config", "src", "tools", "domain", "application", "adapters"
};
static const char *const k_msc_allow[] = {
    "engine/composition/src/boot_refold_staged.c",
    "engine/composition/src/boot_mint_anchor.c",
    "engine/jobs/src/mint_skip_crypto.c",
    "tests/harness/src/test_mint_skip_crypto.c"
};

static int msc_allowed(const char *path)
{
    for (size_t i = 0; i < sizeof k_msc_allow / sizeof k_msc_allow[0]; i++)
        if (strcmp(path, k_msc_allow[i]) == 0)
            return 1;
    return 0;
}

static int msc_root_choice(int argv_nonempty, int argv_app, int script_app)
{
    if (argv_nonempty && argv_app) return 0;
    if (script_app) return 1;
    return 2;
}

static int msc_strip_line(const char *in, int *inblk, char *out, size_t cap)
{
    char line[SF_LINE];
    if (ovf(snprintf(line, sizeof line, "%s", in), sizeof line))
        return 2;
    size_t used = 0;
    out[0] = '\0';
    char *cur = line;
    while (*cur) {
        if (*inblk) {
            char *p = strstr(cur, "*/");
            if (!p) break;
            cur = p + 2;
            *inblk = 0;
        } else {
            char *p = strstr(cur, "/*");
            if (!p) {
                size_t n = strlen(cur);
                if (used + n + 1 > cap)
                    return die("z23-lint: derived buffer overflow\n", "");
                memcpy(out + used, cur, n + 1);
                used += n;
                break;
            }
            size_t n = (size_t)(p - cur);
            if (used + n + 1 > cap)
                return die("z23-lint: derived buffer overflow\n", "");
            memcpy(out + used, cur, n);
            used += n;
            out[used] = '\0';
            cur = p + 2;
            *inblk = 1;
        }
    }
    char *sl = strstr(out, "//");
    if (sl) *sl = '\0';
    return 0;
}

static int msc_strip_text(const char *in, char *out, size_t cap)
{
    int inblk = 0;
    size_t used = 0;
    out[0] = '\0';
    const char *p = in;
    if (!*p) return 0;
    for (;;) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        char line[SF_LINE], stripped[SF_LINE];
        if (n >= sizeof line)
            return die("z23-lint: derived buffer overflow\n", "");
        memcpy(line, p, n);
        line[n] = '\0';
        if (msc_strip_line(line, &inblk, stripped, sizeof stripped))
            return 2;
        int k = snprintf(out + used, cap - used, "%s\n", stripped);
        if (ovf(k, cap - used)) return 2;
        used += (size_t)k;
        if (!nl) break;
        p = nl + 1;
        if (!*p) break;
    }
    return 0;
}

static int msc_file_has(const char *path, const char *needle)
{
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char *line = NULL;
    size_t cap = 0;
    int found = 0;
    while (!found && getline(&line, &cap, f) >= 0)
        if (strstr(line, needle)) found = 1;
    free(line);
    return fclose(f) == 0 ? found : 0;
}

static int msc_path_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

struct msc_set { char n[MSC_MAX][MSC_PATH]; int count; };

static int msc_on_file(const char *path, void *ctx)
{
    struct msc_set *s = ctx;
    if (lint_path_is_excluded(path))
        return 0;
    size_t n = strlen(path);
    if (s->count >= MSC_MAX || n >= MSC_PATH)
        return die("z23-lint: derived buffer overflow\n", "");
    memcpy(s->n[s->count++], path, n + 1);
    return 0;
}

static int msc_fmt_hit(char *dst, size_t cap, const char *path, int lineno,
                       const char *line)
{
    return ovf(snprintf(dst, cap, "  %s: %d:%s\n", path, lineno, line), cap);
}

static int msc_scan_file(const char *path, const regex_t *re, char *hits,
                         size_t cap, size_t *used)
{
    if (msc_allowed(path))
        return 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot scan %s\n", path);
    char *line = NULL;
    size_t lcap = 0;
    int inblk = 0, lineno = 0, rc = 0;
    while (rc == 0 && getline(&line, &lcap, f) >= 0) {
        lineno++;
        {
            size_t ln = strlen(line);
            while (ln && (line[ln - 1] == '\n' || line[ln - 1] == '\r'))
                line[--ln] = '\0';
        }
        char stripped[SF_LINE];
        rc = msc_strip_line(line, &inblk, stripped, sizeof stripped);
        if (rc) break;
        if (regexec(re, stripped, 0, NULL, 0) != 0)
            continue;
        if (*used >= cap)
            rc = die("z23-lint: derived buffer overflow\n", "");
        else {
            int k = msc_fmt_hit(hits + *used, cap - *used, path, lineno, stripped);
            if (k) rc = k;
            else *used += strlen(hits + *used);
        }
    }
    return fin(f, line, path, rc);
}

static int msc_resolve_root(int argc, char **argv, char *root, size_t cap)
{
    if (argc >= 1 && argv[0] && argv[0][0]) {
        char app[4096];
        if (ovf(snprintf(app, sizeof app, "%s/app", argv[0]), sizeof app))
            return 2;
        if (sf_dir(app))
            return ovf(snprintf(root, cap, "%s", argv[0]), cap);
    }
    char script_root[4096];
    if (cic_repo_root(script_root, sizeof script_root) == 0) {
        char app[4096];
        if (ovf(snprintf(app, sizeof app, "%s/app", script_root), sizeof app))
            return 2;
        if (sf_dir(app))
            return ovf(snprintf(root, cap, "%s", script_root), cap);
    }
    char gitout[4096];
    int code = 1;
    if (capture_cmd("git rev-parse --show-toplevel 2>/dev/null", gitout,
                    sizeof gitout, &code) == 0 && code == 0 && gitout[0])
        return ovf(snprintf(root, cap, "%s", gitout), cap);
    if (!getcwd(root, cap))
        return die("z23-lint: cannot resolve executable path\n", "");
    return 0;
}

int check_mint_skip_crypto_offline_only_run(int argc, char **argv)
{
    char root[4096];
    int rc = msc_resolve_root(argc, argv, root, sizeof root);
    if (rc) return rc;
    if (chdir(root) != 0) {
        fprintf(stderr, "check_mint_skip_crypto_offline_only: bad root '%s'\n",
                root);
        return 2;
    }
    static struct msc_set scan;
    scan.count = 0;
    for (size_t i = 0; i < sizeof k_msc_roots / sizeof k_msc_roots[0]; i++) {
        if (!sf_dir(k_msc_roots[i]))
            continue;
        rc = walk_src(k_msc_roots[i], 0, msc_on_file, &scan);
        if (rc) return rc;
    }
    if (scan.count == 0) {
        fputs("check_mint_skip_crypto_offline_only: FAIL — empty scan set (no .c found)\n"
              "  This gate must scan a non-empty set; refusing to pass silently.\n",
              stderr);
        return 1;
    }
    qsort(scan.n, (size_t)scan.count, MSC_PATH, msc_path_cmp);
    struct stat st;
    if (stat(k_msc_mod, &st) != 0 || !S_ISREG(st.st_mode)) {
        fprintf(stderr,
                "check_mint_skip_crypto_offline_only: FAIL — module %s missing\n",
                k_msc_mod);
        return 1;
    }
    if (!msc_file_has(k_msc_mod, k_msc_setter)) {
        fprintf(stderr,
                "check_mint_skip_crypto_offline_only: FAIL — %s not defined in the module\n"
                "  The setter was renamed; update this gate deliberately.\n",
                k_msc_setter);
        return 1;
    }
    char call[64];
    if (ovf(snprintf(call, sizeof call, "%s%s", k_msc_setter, "("), sizeof call))
        return 2;
    if (!msc_file_has(k_msc_drv, call)) {
        fprintf(stderr,
                "check_mint_skip_crypto_offline_only: FAIL — the mint driver\n"
                "  %s no longer calls %s(. Either the\n"
                "  wiring regressed or it moved — update this gate deliberately.\n",
                k_msc_drv, k_msc_setter);
        return 1;
    }
    regex_t re;
    rc = reg_fail(&re, regcomp(&re, k_msc_call_re, REG_EXTENDED));
    if (rc) return rc;
    static char hits[SF_HITS];
    hits[0] = '\0';
    size_t used = 0;
    for (int i = 0; i < scan.count; i++) {
        rc = msc_scan_file(scan.n[i], &re, hits, sizeof hits, &used);
        if (rc) { regfree(&re); return rc; }
    }
    regfree(&re);
    if (used == 0) {
        if (printf("check_mint_skip_crypto_offline_only: OK — %s called only from the offline mint driver TUs (scanned %d files)\n",
                   k_msc_setter, scan.count) < 0)
            return die("z23-lint: write failed\n", "");
        return 0;
    }
    if (printf("\ncheck_mint_skip_crypto_offline_only: FAIL — OFFLINE-ONLY FENCE violated\n"
               "\n"
               "%s() was called outside the offline -mint-anchor mint driver. The\n"
               "crypto pass-through is SOUND only for PRODUCING the fingerprint-certified\n"
               "anchor snapshot offline; arming it anywhere a running node can reach it is a\n"
               "signature/proof bypass on the live chain.\n"
               "\n"
               "Offending call site(s):\n", k_msc_setter) < 0
        || fputs(hits, stdout) == EOF
        || printf("\nFIX: only the offline mint driver may call %s. Allowed TUs:\n",
                  k_msc_setter) < 0)
        return die("z23-lint: write failed\n", "");
    for (size_t i = 0; i < sizeof k_msc_allow / sizeof k_msc_allow[0]; i++)
        if (printf("  - %s\n", k_msc_allow[i]) < 0)
            return die("z23-lint: write failed\n", "");
    if (puts("If you genuinely added a new mint-driver TU, add it to ALLOW in this gate") == EOF
        || puts("deliberately AND keep it gated under ctx->mint_anchor — never relax the fence.") == EOF)
        return die("z23-lint: write failed\n", "");
    return 1;
}

int check_mint_skip_crypto_offline_only_selftest(void)
{
    regex_t re;
    int rc = reg_fail(&re, regcomp(&re, k_msc_call_re, REG_EXTENDED));
    if (rc) return rc;
    int bad = 0, inblk = 0;
    char stripped[SF_LINE], text[SF_LINE], hits[512];
    char call[64], blk[160], linecmt[96], ws[64], hitln[80], expect[128];
    if (ovf(snprintf(call, sizeof call, "%s%s", k_msc_setter, "("), sizeof call)
        || ovf(snprintf(blk, sizeof blk, "int x;\n/*\n%s1);\n*/\nint y;\n", call),
               sizeof blk)
        || ovf(snprintf(linecmt, sizeof linecmt, "int a; // %s1);", call),
               sizeof linecmt)
        || ovf(snprintf(ws, sizeof ws, "%s  (1);", k_msc_setter), sizeof ws)
        || ovf(snprintf(hitln, sizeof hitln, "    %s1);", call), sizeof hitln)
        || ovf(snprintf(expect, sizeof expect, "  engine/foo.c: 12:%s\n", hitln),
               sizeof expect)) {
        regfree(&re);
        return 2;
    }
    bad |= msc_strip_text(blk, text, sizeof text) != 0;
    bad |= strstr(text, k_msc_setter) != NULL;
    bad |= msc_strip_line(linecmt, &inblk, stripped, sizeof stripped) != 0;
    bad |= strstr(stripped, k_msc_setter) != NULL;
    inblk = 0;
    bad |= msc_strip_line(ws, &inblk, stripped, sizeof stripped) != 0;
    bad |= regexec(&re, stripped, 0, NULL, 0) != 0;
    bad |= !msc_allowed(k_msc_allow[0]) || msc_allowed("engine/foo.c");
    hits[0] = '\0';
    bad |= msc_fmt_hit(hits, sizeof hits, "engine/foo.c", 12, hitln) != 0;
    bad |= strcmp(hits, expect) != 0;
    bad |= msc_root_choice(1, 1, 0) != 0 || msc_root_choice(1, 0, 1) != 1
        || msc_root_choice(1, 0, 0) != 2 || msc_root_choice(0, 1, 1) != 1
        || msc_root_choice(0, 0, 0) != 2;
    inblk = 0;
    bad |= msc_strip_line("int z;", &inblk, stripped, sizeof stripped) != 0;
    bad |= regexec(&re, stripped, 0, NULL, 0) == 0;
    regfree(&re);
    return st_ok(bad, "check_mint_skip_crypto_offline_only selftest: OK\n");
}
