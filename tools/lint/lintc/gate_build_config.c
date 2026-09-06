/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — build-flag/CI-toggle-shaped lint gates of the C23
 * lint runtime (check-tu-random-seed, check-privileged-transition-receipt,
 * check-asan-adx-exception).
 */

/*
 * Gates: check-tu-random-seed, check-privileged-transition-receipt, check-asan-adx-exception
 * Default landing spot for a FUTURE gate port: a filesystem-tree-walking
 * gate (walk_src/clock_walk/repo_shape_room_dirs) joins gate_tree_walk.c;
 * a git-tracked-enumeration gate (each_zpath/each_zpath_st) joins whichever
 * of gate_git_scan_a.c/gate_git_scan_b.c is currently smaller by wc -l;
 * a proof/landing/receipt-shaped gate joins gate_landing_proof.c; a
 * build-flag/CI-toggle-shaped gate joins gate_build_config.c; only once
 * EVERY existing family is within ~200 lines of the ~1500 cap does a new
 * gate warrant a new family file — name it for its own subject the same
 * way the seven above are named for theirs.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"


static int trs_on_recipe(FILE *out, int cov, int start, const char *argv,
                         int *dep_total, int *dep_seeded, int *cov_total,
                         int *fail)
{
    static const char needle[] = "$(" "ZCL_TU_RANDOM_SEED" ")";
    int has = strstr(argv, needle) != NULL;
    if (!cov) {
        (*dep_total)++;
        if (has) {
            (*dep_seeded)++;
            return 0;
        }
        if (fprintf(out,
                    "FAIL: Makefile:%d — per-TU object recipe does not carry $("
                    "ZCL_TU_RANDOM_SEED)\n", start) < 0)
            return die("z23-lint: write failed\n", "");
        if (fprintf(out, "      %s\n", argv) < 0)
            return die("z23-lint: write failed\n", "");
        *fail = 1;
        return 0;
    }
    (*cov_total)++;
    if (!has)
        return 0;
    if (fprintf(out,
                "FAIL: Makefile:%d — the coverage recipe carries $("
                "ZCL_TU_RANDOM_SEED).\n", start) < 0)
        return die("z23-lint: write failed\n", "");
    if (fputs("      Coverage is the documented exemption (gcno/gcda pairing).\n"
              "      If that changed, update this gate and the reason with it.\n",
              out) < 0)
        return die("z23-lint: write failed\n", "");
    *fail = 1;
    return 0;
}

/* The original gate piped Makefile lines through a bash command
 * substitution ($(awk ...) / $(grep ...)), and bash silently drops any
 * embedded NUL byte from that captured text rather than truncating at it.
 * getline() keeps the NUL as a literal byte, so strstr()/regexec() on the
 * raw buffer would stop early instead — a divergence from the original's
 * behavior. Squeeze NULs out (and drop the trailing newline) so a line
 * with an embedded NUL is judged on the same reassembled text the original
 * bash pipeline saw. */
static ssize_t trs_squeeze_line(char *buf, ssize_t n)
{
    if (n > 0 && buf[n - 1] == '\n')
        n--;
    ssize_t w = 0;
    for (ssize_t r = 0; r < n; r++) {
        if (buf[r] != '\0')
            buf[w++] = buf[r];
    }
    buf[w] = '\0';
    return w;
}

static int trs_check(FILE *out)
{
    regex_t seedre, trig, covre, cont;
    int cr = compile_pat(&seedre, REG_EXTENDED,
                        "^ZCL_TU_" "RANDOM_SEED[[:space:]]*=", "", "", "");
    if (cr)
        return cr;
    cr = compile_pat(&trig, REG_EXTENDED,
                     "BUILD_(EPOCH_OBJECT_TOOL|FAST_EPOCH_OBJECT_COMMAND)\\)"
                     "[[:space:]]+(dep|coverage)[[:space:]]",
                     "", "", "");
    if (cr) {
        regfree(&seedre);
        return cr;
    }
    cr = compile_pat(&covre, REG_EXTENDED, "[[:space:]]coverage[[:space:]]",
                     "", "", "");
    if (cr) {
        drop2(&seedre, &trig);
        return cr;
    }
    cr = compile_pat(&cont, REG_EXTENDED, "\\\\[[:space:]]*$", "", "", "");
    if (cr) {
        drop3(&seedre, &trig, &covre);
        return cr;
    }

    FILE *f = fopen("Makefile", "r");
    char seed_def[4096];
    seed_def[0] = '\0';
    int found_seed = 0;
    if (f) {
        char *line = NULL;
        size_t cap = 0;
        ssize_t n;
        size_t used = 0;
        int rc = 0;
        while ((n = getline(&line, &cap, f)) >= 0) {
            n = trs_squeeze_line(line, n);
            if (regexec(&seedre, line, 0, NULL, 0) != 0)
                continue;
            size_t ln = strlen(line);
            if (found_seed) {
                if (used + 1 >= sizeof seed_def) {
                    rc = die("z23-lint: derived buffer overflow\n", "");
                    break;
                }
                seed_def[used++] = '\n';
                seed_def[used] = '\0';
            }
            if (used + ln >= sizeof seed_def) {
                rc = die("z23-lint: derived buffer overflow\n", "");
                break;
            }
            memcpy(seed_def + used, line, ln + 1);
            used += ln;
            found_seed = 1;
        }
        int fr = fin(f, line, "Makefile", rc);
        if (fr) {
            drop3(&seedre, &trig, &covre);
            regfree(&cont);
            return fr;
        }
    }
    if (!found_seed) {
        drop3(&seedre, &trig, &covre);
        regfree(&cont);
        if (fputs("FAIL: Makefile does not define ZCL_TU_RANDOM_SEED\n", out) < 0)
            return die("z23-lint: write failed\n", "");
        return 1;
    }
    const char *frs = strstr(seed_def, "-" "frandom-seed=");
    if (!frs || !strstr(frs, "$<")) {
        drop3(&seedre, &trig, &covre);
        regfree(&cont);
        if (fputs("FAIL: ZCL_TU_RANDOM_SEED must expand to -frandom-seed=<per-TU value>.\n"
                  "      A seed that is the same for every TU is not a per-TU seed.\n",
                  out) < 0)
            return die("z23-lint: write failed\n", "");
        if (fprintf(out, "      Found: %s\n", seed_def) < 0)
            return die("z23-lint: write failed\n", "");
        return 1;
    }

    f = fopen("Makefile", "r");
    if (!f) {
        drop3(&seedre, &trig, &covre);
        regfree(&cont);
        if (fputs("FAIL: found no compile-epoch-object.sh object recipes in Makefile\n",
                  out) < 0)
            return die("z23-lint: write failed\n", "");
        return 1;
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0, found = 0, fail = 0;
    int dep_total = 0, dep_seeded = 0, cov_total = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        lineno++;
        n = trs_squeeze_line(line, n);
        if (regexec(&trig, line, 0, NULL, 0) != 0)
            continue;
        found = 1;
        int cov = regexec(&covre, line, 0, NULL, 0) == 0;
        int start = lineno;
        while (regexec(&cont, line, 0, NULL, 0) == 0) {
            n = getline(&line, &cap, f);
            if (n < 0)
                break;
            lineno++;
            n = trs_squeeze_line(line, n);
        }
        if (n < 0 && ferror(f)) {
            rc = die("z23-lint: read failed: %s\n", "Makefile");
            break;
        }
        /* bash `IFS=$'\t' read` collapses the delimiter tab with any
         * leading tabs on the argv line, so those tabs never appear. */
        const char *argv = line;
        while (*argv == '\t')
            argv++;
        rc = trs_on_recipe(out, cov, start, argv, &dep_total, &dep_seeded,
                           &cov_total, &fail);
        if (rc)
            break;
    }
    int fr = fin(f, line, "Makefile", rc);
    drop3(&seedre, &trig, &covre);
    regfree(&cont);
    if (fr)
        return fr;
    if (!found) {
        if (fputs("FAIL: found no compile-epoch-object.sh object recipes in Makefile\n",
                  out) < 0)
            return die("z23-lint: write failed\n", "");
        return 1;
    }
    if (cov_total > 1) {
        if (fprintf(out,
                    "FAIL: expected exactly one coverage-mode object recipe, found %d.\n",
                    cov_total) < 0)
            return die("z23-lint: write failed\n", "");
        if (fputs("      The exemption is documented for one recipe; a second one has to\n"
                  "      justify itself rather than inherit the first one's reason.\n",
                  out) < 0)
            return die("z23-lint: write failed\n", "");
        fail = 1;
    }
    if (fail) {
        if (fputs("\n"
                  "Fix: append $(ZCL_TU_RANDOM_SEED) to the compiler argv of the object recipe.\n"
                  "     Proof of the property it buys: make repro-build\n",
                  out) < 0)
            return die("z23-lint: write failed\n", "");
        return 1;
    }
    return fprintf(out,
                   "check-tu-random-seed: PASS — %d/%d per-TU object recipes pin GCC's "
                   "random seed (%d coverage recipe exempt)\n",
                   dep_seeded, dep_total, cov_total) < 0
               ? die("z23-lint: write failed\n", "") : 0;
}

int check_tu_random_seed_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return trs_check(stdout);
}

static const char k_trs_ok[] =
    "ZCL_TU_RANDOM_SEED = -frandom-seed=$<\n"
    "all:\n"
    "\t@$(BUILD_EPOCH_OBJECT_TOOL) dep \"$@\" \"$<\" \\\n"
    "\t  -- \\\n"
    "\t  $(CC) $(CFLAGS) $(ZCL_TU_RANDOM_SEED)\n"
    "\t@$(BUILD_EPOCH_OBJECT_TOOL) coverage \"$@\" \"$<\" \\\n"
    "\t  -- \\\n"
    "\t  $(CC) $(COV)\n";

static const char k_trs_missing[] =
    "all:\n"
    "\t@$(BUILD_EPOCH_OBJECT_TOOL) dep \"$@\" \"$<\" \\\n"
    "\t  -- \\\n"
    "\t  $(CC) $(CFLAGS) $(ZCL_TU_RANDOM_SEED)\n"
    "\t@$(BUILD_EPOCH_OBJECT_TOOL) coverage \"$@\" \"$<\" \\\n"
    "\t  -- \\\n"
    "\t  $(CC) $(COV)\n";

static const char k_trs_unseeded[] =
    "ZCL_TU_RANDOM_SEED = -frandom-seed=$<\n"
    "all:\n"
    "\t@$(BUILD_EPOCH_OBJECT_TOOL) dep \"$@\" \"$<\" \\\n"
    "\t  -- \\\n"
    "\t  $(CC) $(CFLAGS)\n"
    "\t@$(BUILD_EPOCH_OBJECT_TOOL) coverage \"$@\" \"$<\" \\\n"
    "\t  -- \\\n"
    "\t  $(CC) $(COV)\n";

int check_tu_random_seed_selftest(void)
{
    char cwd[4096];
    if (!getcwd(cwd, sizeof cwd))
        return die("z23-lint: getcwd failed\n", "");
    char tmpl[] = "/tmp/z23-lint-trs-XXXXXX";
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdir failed: %s\n", "/tmp");
    FILE *out = tmpfile();
    if (!out) {
        rmdir(root);
        return die("z23-lint: tmpfile failed\n", "");
    }
    char ob[4096];
    int bad = 0, rc = 0;
    if (chdir(root) != 0) {
        fclose(out);
        rmdir(root);
        return die("z23-lint: cannot scan %s\n", root);
    }

    if (csr_write("./Makefile", k_trs_missing))
        bad = 1;
    rc = trs_check(out);
    if (csr_slurp(out, ob, sizeof ob))
        bad = 1;
    bad |= rc != 1
        || strstr(ob, "FAIL: Makefile does not define ZCL_TU_RANDOM_SEED") == NULL;

    rewind(out);
    if (ftruncate(fileno(out), 0) != 0)
        bad = 1;
    if (csr_write("./Makefile", k_trs_ok))
        bad = 1;
    rc = trs_check(out);
    if (csr_slurp(out, ob, sizeof ob))
        bad = 1;
    bad |= rc != 0
        || strstr(ob, "check-tu-random-seed: PASS — 1/1 per-TU object recipes "
                      "pin GCC's random seed (1 coverage recipe exempt)") == NULL;

    rewind(out);
    if (ftruncate(fileno(out), 0) != 0)
        bad = 1;
    if (csr_write("./Makefile", k_trs_unseeded))
        bad = 1;
    rc = trs_check(out);
    if (csr_slurp(out, ob, sizeof ob))
        bad = 1;
    bad |= rc != 1
        || strstr(ob, "FAIL: Makefile:3 — per-TU object recipe does not carry $("
                      "ZCL_TU_RANDOM_SEED)") == NULL;

    fclose(out);
    unlink("./Makefile");
    if (chdir(cwd) != 0)
        return die("z23-lint: cannot scan %s\n", cwd);
    rmdir(root);
    if (bad)
        fputs("FAIL: check_tu_random_seed selftest\n", stderr);
    return st_ok(bad, "check_tu_random_seed selftest: OK\n");
}

enum {
    PTR_LEAF_MAX = 1024,
    PTR_LEAF_LEN = 192,
    PTR_DISP_LEN = 1024,
    PTR_FILE_MAX = 2 * 1024 * 1024
};

static char g_ptr_file[PTR_FILE_MAX];
static char g_ptr_leaf[PTR_LEAF_MAX][PTR_LEAF_LEN];
static char g_ptr_dkey[PTR_LEAF_MAX][PTR_LEAF_LEN];
static char g_ptr_dval[PTR_LEAF_MAX][PTR_DISP_LEN];

static int ptr_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static int ptr_add_leaf(const char *path, int *nleaf)
{
    if (!path[0])
        return 0;
    if (*nleaf >= PTR_LEAF_MAX)
        return die("z23-lint: derived buffer overflow\n", "");
    return ovf(snprintf(g_ptr_leaf[*nleaf], PTR_LEAF_LEN, "%s", path),
               PTR_LEAF_LEN) ? 2 : ((*nleaf)++, 0);
}

static int ptr_tok_at(const char *buf, size_t n, size_t i, size_t *len)
{
    static const char *const toks[] = {
        "ZCL_COMMAND_READY_COMMAND(",
        "ZCL_COMMAND_PLANNED_COMMAND(",
        "ZCL_COMMAND_COMPAT_COMMAND(",
        "ZCL_COMMAND_DEV_COMMAND(",
    };
    for (size_t t = 0; t < sizeof toks / sizeof toks[0]; t++) {
        size_t L = strlen(toks[t]);
        if (i + L <= n && memcmp(buf + i, toks[t], L) == 0) {
            *len = L;
            return 1;
        }
    }
    return 0;
}

static int ptr_parse_buf(char *buf, size_t n, int *nleaf)
{
    size_t i = 0;
    while (i < n) {
        size_t L = 0;
        if (!ptr_tok_at(buf, n, i, &L)) {
            i++;
            continue;
        }
        size_t j = i + L;
        int depth = 1, in_str = 0, esc = 0;
        size_t spec_at = j;
        while (j < n && depth > 0) {
            char c = buf[j];
            if (in_str) {
                if (esc)
                    esc = 0;
                else if (c == '\\')
                    esc = 1;
                else if (c == '"')
                    in_str = 0;
            } else if (c == '"')
                in_str = 1;
            else if (c == '(')
                depth++;
            else if (c == ')')
                depth--;
            j++;
        }
        size_t spec_end = (depth == 0) ? j - 1 : j;
        char save = buf[spec_end];
        buf[spec_end] = '\0';
        const char *spec = buf + spec_at;
        char path[PTR_LEAF_LEN];
        path[0] = '\0';
        const char *q1 = strchr(spec, '"');
        if (q1) {
            const char *q2 = strchr(q1 + 1, '"');
            if (q2) {
                size_t pl = (size_t)(q2 - q1 - 1);
                if (pl >= sizeof path) {
                    buf[spec_end] = save;
                    return die("z23-lint: derived buffer overflow\n", "");
                }
                memcpy(path, q1 + 1, pl);
                path[pl] = '\0';
            }
        }
        int owner = strstr(spec, "ZCL_COMMAND_AUTH_OWNER") != NULL;
        int mutate = strstr(spec, "ZCL_COMMAND_EFFECT_MUTATE") != NULL
                  || strstr(spec, "ZCL_COMMAND_EFFECT_DESTRUCTIVE") != NULL;
        int rcadd = 0;
        if (owner && mutate && path[0])
            rcadd = ptr_add_leaf(path, nleaf);
        buf[spec_end] = save;
        if (rcadd)
            return rcadd;
        i = j;
    }
    return 0;
}

static int ptr_read_file(const char *path, char *buf, size_t cap, size_t *outn)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    size_t n = fread(buf, 1, cap - 1, f);
    if (n == cap - 1) {
        char extra;
        if (fread(&extra, 1, 1, f) == 1) {
            fclose(f);
            return die("z23-lint: derived buffer overflow\n", "");
        }
    }
    int err = ferror(f);
    if (fclose(f) != 0 && !err)
        return die("z23-lint: fclose failed: %s\n", path);
    if (err)
        return die("z23-lint: read failed: %s\n", path);
    buf[n] = '\0';
    *outn = n;
    return 0;
}

static const char *ptr_disp_get(int ndisp, const char *leaf)
{
    for (int i = 0; i < ndisp; i++) {
        if (strcmp(g_ptr_dkey[i], leaf) == 0)
            return g_ptr_dval[i];
    }
    return NULL;
}

static int ptr_disp_set(int *ndisp, const char *leaf, const char *rest)
{
    for (int i = 0; i < *ndisp; i++) {
        if (strcmp(g_ptr_dkey[i], leaf) == 0)
            return ovf(snprintf(g_ptr_dval[i], PTR_DISP_LEN, "%s", rest),
                       PTR_DISP_LEN);
    }
    if (*ndisp >= PTR_LEAF_MAX)
        return die("z23-lint: derived buffer overflow\n", "");
    if (ovf(snprintf(g_ptr_dkey[*ndisp], PTR_LEAF_LEN, "%s", leaf), PTR_LEAF_LEN))
        return 2;
    if (ovf(snprintf(g_ptr_dval[*ndisp], PTR_DISP_LEN, "%s", rest), PTR_DISP_LEN))
        return 2;
    (*ndisp)++;
    return 0;
}

static int ptr_replay_pref(FILE *src, FILE *err)
{
    if (fseek(src, 0, SEEK_SET) != 0)
        return die("z23-lint: fseek failed\n", "");
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while ((n = getline(&line, &cap, src)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        if (fprintf(err, "  %s\n", line) < 0) {
            rc = die("z23-lint: write failed\n", "");
            break;
        }
    }
    free(line);
    return rc;
}

static int ptr_scan(const char *defdir, const char *baseline, const char *workdir,
                    FILE *out, FILE *err)
{
    int def_count = 0, nleaf = 0, ndisp = 0;
    struct stat dst;
    if (stat(defdir, &dst) == 0 && S_ISDIR(dst.st_mode)) {
        DIR *d = opendir(defdir);
        if (!d)
            return die("z23-lint: cannot open %s\n", defdir);
        struct dirent *de;
        int prc = 0;
        while (prc == 0 && (de = readdir(d)) != NULL) {
            const char *nm = de->d_name;
            size_t L = strlen(nm);
            if (L < 5 || nm[0] == '.' || strcmp(nm + L - 4, ".def") != 0)
                continue;
            char full[8192];
            if (ovf(snprintf(full, sizeof full, "%s/%s", defdir, nm), sizeof full)) {
                prc = 2;
                break;
            }
            struct stat st;
            if (stat(full, &st) != 0 || !S_ISREG(st.st_mode))
                continue;
            def_count++;
            size_t got = 0;
            prc = ptr_read_file(full, g_ptr_file, sizeof g_ptr_file, &got);
            if (prc == 0)
                prc = ptr_parse_buf(g_ptr_file, got, &nleaf);
        }
        closedir(d);
        if (prc)
            return prc;
    }

    if (nleaf > 1)
        qsort(g_ptr_leaf, (size_t)nleaf, PTR_LEAF_LEN, ptr_cmp);
    int w = 0;
    for (int i = 0; i < nleaf; i++) {
        if (w && strcmp(g_ptr_leaf[w - 1], g_ptr_leaf[i]) == 0)
            continue;
        if (w != i)
            memcpy(g_ptr_leaf[w], g_ptr_leaf[i], PTR_LEAF_LEN);
        w++;
    }
    nleaf = w;

    if (def_count == 0 || nleaf == 0) {
        if (fprintf(err,
                    "check_privileged_transition_receipt: FATAL — no owner-mutating leaves enumerated from %s/*.def (broken scan; refusing a hollow clean).\n",
                    defdir) < 0)
            return die("z23-lint: write failed\n", "");
        return 2;
    }

    FILE *bf = fopen(baseline, "r");
    if (bf) {
        char *line = NULL;
        size_t cap = 0;
        ssize_t n;
        int brc = 0;
        while (brc == 0 && (n = getline(&line, &cap, bf)) >= 0) {
            if (n > 0 && line[n - 1] == '\n')
                line[n - 1] = '\0';
            char *p = line;
            while (*p && isspace((unsigned char)*p))
                p++;
            if (!*p || *p == '#')
                continue;
            char *leaf = p;
            while (*p && !isspace((unsigned char)*p))
                p++;
            char *rest = p;
            if (*p) {
                *p++ = '\0';
                while (*p && isspace((unsigned char)*p))
                    p++;
                rest = p;
            }
            brc = ptr_disp_set(&ndisp, leaf, rest);
        }
        int fr = fin(bf, line, baseline, brc);
        if (fr)
            return fr;
    }

    regex_t vre;
    int e = regcomp(&vre,
                    "authority_receipt_[a-z_]*_available[(]|"
                    "consensus_state_replay_receipt_authority_available[(]",
                    REG_EXTENDED);
    if (e)
        return reg_fail(&vre, e);

    FILE *violf = tmpfile(), *lostf = tmpfile();
    if (!violf || !lostf) {
        if (violf) fclose(violf);
        if (lostf) fclose(lostf);
        regfree(&vre);
        return die("z23-lint: tmpfile failed\n", "");
    }

    int n_total = 0, n_receipt = 0, n_exempt = 0, nviol = 0, nlost = 0, fail = 0;
    int rc = 0;
    for (int i = 0; i < nleaf && rc == 0; i++) {
        n_total++;
        const char *d = ptr_disp_get(ndisp, g_ptr_leaf[i]);
        if (!d || !d[0]) {
            if (fprintf(violf, "%s\n", g_ptr_leaf[i]) < 0)
                rc = die("z23-lint: write failed\n", "");
            nviol++;
            continue;
        }
        if (strncmp(d, "receipt:", 8) == 0)
            n_receipt++;
        else if (strncmp(d, "exempt:", 7) == 0)
            n_exempt++;
        else if (fprintf(violf,
                         "%s (malformed disposition: '%s' — must start receipt: or exempt:)\n",
                         g_ptr_leaf[i], d) < 0)
            rc = die("z23-lint: write failed\n", "");
        else
            nviol++;
    }

    for (int i = 0; i < ndisp && rc == 0; i++) {
        const char *d = g_ptr_dval[i];
        if (strncmp(d, "receipt:", 8) != 0)
            continue;
        const char *spec = d + 8;
        size_t fl = 0;
        while (spec[fl] && !isspace((unsigned char)spec[fl]))
            fl++;
        if (fl == 0 || fl >= 4096) {
            rc = die("z23-lint: derived buffer overflow\n", "");
            break;
        }
        char file[4096];
        memcpy(file, spec, fl);
        file[fl] = '\0';
        char full[8192];
        const char *openp = file;
        if (file[0] != '/') {
            if (ovf(snprintf(full, sizeof full, "%s/%s", workdir, file),
                    sizeof full)) {
                rc = 2;
                break;
            }
            openp = full;
        }
        struct stat st;
        if (stat(openp, &st) != 0 || !S_ISREG(st.st_mode)) {
            if (fprintf(lostf, "%s -> %s (file not found)\n", g_ptr_dkey[i], file) < 0)
                rc = die("z23-lint: write failed\n", "");
            nlost++;
            continue;
        }
        size_t got = 0;
        rc = ptr_read_file(openp, g_ptr_file, sizeof g_ptr_file, &got);
        if (rc)
            break;
        if (regexec(&vre, g_ptr_file, 0, NULL, 0) != 0) {
            if (fprintf(lostf, "%s -> %s (no authority_receipt verify call)\n",
                        g_ptr_dkey[i], file) < 0)
                rc = die("z23-lint: write failed\n", "");
            nlost++;
        }
    }
    regfree(&vre);
    if (rc) {
        fclose(violf);
        fclose(lostf);
        return rc;
    }

    if (nviol) {
        fail = 1;
        if (fprintf(err,
                    "check_privileged_transition_receipt: owner-mutating leaf/leaves with NO Law-7 disposition in %s:\n",
                    baseline) < 0) {
            fclose(violf);
            fclose(lostf);
            return die("z23-lint: write failed\n", "");
        }
        rc = ptr_replay_pref(violf, err);
        if (rc == 0
            && (fputs("\n", err) < 0
                || fputs("Every ZCL_COMMAND_AUTH_OWNER + EFFECT_MUTATE/DESTRUCTIVE leaf must be dispositioned. Add ONE line:\n",
                         err) < 0
                || fputs("  <leaf.path>  receipt:<relative_handler_file>   # if it installs a privileged artifact — bind authority_receipt_header_* (or the replay-receipt verifier) over {artifact digest, context anchor, running binary}\n",
                         err) < 0
                || fputs("  <leaf.path>  exempt:<one-line reason>          # if it is not an artifact-install transition\n",
                         err) < 0))
            rc = die("z23-lint: write failed\n", "");
    }
    if (rc == 0 && nlost) {
        fail = 1;
        if (fputs("check_privileged_transition_receipt: a receipt: consumer no longer gates on an authority receipt:\n",
                  err) < 0)
            rc = die("z23-lint: write failed\n", "");
        else
            rc = ptr_replay_pref(lostf, err);
        if (rc == 0
            && fputs("  A wired privileged transition must keep calling authority_receipt_*_available( before mutating.\n",
                     err) < 0)
            rc = die("z23-lint: write failed\n", "");
    }
    fclose(violf);
    fclose(lostf);
    if (rc)
        return rc;
    if (fail)
        return 1;
    if (fprintf(out,
                "check_privileged_transition_receipt: clean — %d owner-mutating leaves, all dispositioned (%d receipt, %d exempt)\n",
                n_total, n_receipt, n_exempt) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

int check_privileged_transition_receipt_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    char cwd[4096], basebuf[4096];
    if (!getcwd(cwd, sizeof cwd))
        return die("z23-lint: getcwd failed\n", "");
    const char *envd = getenv("ZCL_PRIV_RECEIPT_DEF_DIR");
    const char *envb = getenv("ZCL_PRIV_RECEIPT_BASELINE");
    const char *defdir = (envd && envd[0]) ? envd : "engine/composition/commands";
    const char *baseline;
    if (envb && envb[0])
        baseline = envb;
    else {
        if (ovf(snprintf(basebuf, sizeof basebuf,
                         "%s/tools/lint/privileged_transition_receipt_baseline.txt",
                         cwd), sizeof basebuf))
            return 2;
        baseline = basebuf;
    }
    return ptr_scan(defdir, baseline, cwd, stdout, stderr);
}

static int ptr_st_env(const char *defdir, const char *baseline)
{
    if (setenv("ZCL_PRIV_RECEIPT_DEF_DIR", defdir, 1) != 0
        || setenv("ZCL_PRIV_RECEIPT_BASELINE", baseline, 1) != 0)
        return 1;
    return 0;
}

static int ptr_st_clear_env(int had_d, const char *oldd, int had_b, const char *oldb)
{
    if (had_d)
        (void)setenv("ZCL_PRIV_RECEIPT_DEF_DIR", oldd, 1);
    else
        (void)unsetenv("ZCL_PRIV_RECEIPT_DEF_DIR");
    if (had_b)
        (void)setenv("ZCL_PRIV_RECEIPT_BASELINE", oldb, 1);
    else
        (void)unsetenv("ZCL_PRIV_RECEIPT_BASELINE");
    return 0;
}

int check_privileged_transition_receipt_selftest(void)
{
    char tmpl[] = "/tmp/z23-lint-ptr-XXXXXX";
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdir failed: %s\n", "/tmp");
    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err) {
        if (out) fclose(out);
        if (err) fclose(err);
        (void)rap_rm_rf(root);
        return die("z23-lint: tmpfile failed\n", "");
    }
    const char *ed = getenv("ZCL_PRIV_RECEIPT_DEF_DIR");
    const char *eb = getenv("ZCL_PRIV_RECEIPT_BASELINE");
    char oldd[4096], oldb[4096];
    int had_d = 0, had_b = 0, bad = 0, rc = 0;
    if (ed) {
        if (ovf(snprintf(oldd, sizeof oldd, "%s", ed), sizeof oldd))
            bad = 1;
        else
            had_d = 1;
    }
    if (eb) {
        if (ovf(snprintf(oldb, sizeof oldb, "%s", eb), sizeof oldb))
            bad = 1;
        else
            had_b = 1;
    }

    char defs[4096], empty[4096], base[4096], handler[4096], defa[4096], ob[8192],
        ebout[8192];
    static const char k_def[] =
        "ZCL_COMMAND_READY_COMMAND(\n"
        "    \"app.test.clean\", \"parent\", \"has (parens) and \\\"quotes\\\" inside\",\n"
        "    ZCL_COMMAND_AUTH_OWNER, ZCL_COMMAND_EFFECT_MUTATE)\n"
        "ZCL_COMMAND_DEV_COMMAND(\n"
        "    \"app.test.dev\", ZCL_COMMAND_AUTH_OWNER, ZCL_COMMAND_EFFECT_DESTRUCTIVE)\n";
    static const char k_pub[] =
        "ZCL_COMMAND_READY_COMMAND(\n"
        "    \"app.test.public\", ZCL_COMMAND_AUTH_PUBLIC, ZCL_COMMAND_EFFECT_MUTATE)\n";
    if (ovf(snprintf(defs, sizeof defs, "%s/defs", root), sizeof defs)
        || ovf(snprintf(empty, sizeof empty, "%s/empty", root), sizeof empty)
        || ovf(snprintf(base, sizeof base, "%s/baseline.txt", root), sizeof base)
        || ovf(snprintf(handler, sizeof handler, "%s/handler.c", root), sizeof handler)
        || ovf(snprintf(defa, sizeof defa, "%s/defs/a.def", root), sizeof defa)
        || csr_mkdirs(defs) || csr_mkdirs(empty) || csr_write(defa, k_def))
        bad = 1;

    if (!bad && ptr_st_env(defs, base))
        bad = 1;

    if (psp_st_reset(out) || psp_st_reset(err))
        bad = 1;
    if (csr_write(base,
                  "app.test.clean  exempt: fixture\n"
                  "app.test.dev    exempt: fixture\n"))
        bad = 1;
    rc = ptr_scan(defs, base, root, out, err);
    if (csr_slurp(out, ob, sizeof ob) || csr_slurp(err, ebout, sizeof ebout))
        bad = 1;
    bad |= rc != 0
        || strstr(ob, "check_privileged_transition_receipt: clean — 2 owner-mutating leaves, all dispositioned (0 receipt, 2 exempt)") == NULL;

    if (psp_st_reset(out) || psp_st_reset(err))
        bad = 1;
    if (csr_write(base, "# none\n"))
        bad = 1;
    rc = ptr_scan(defs, base, root, out, err);
    if (csr_slurp(out, ob, sizeof ob) || csr_slurp(err, ebout, sizeof ebout))
        bad = 1;
    bad |= rc != 1
        || strstr(ebout, "app.test.clean") == NULL
        || strstr(ebout, "app.test.dev") == NULL
        || strstr(ebout, "Every ZCL_COMMAND_AUTH_OWNER + EFFECT_MUTATE/DESTRUCTIVE leaf must be dispositioned.") == NULL;

    if (psp_st_reset(out) || psp_st_reset(err))
        bad = 1;
    if (csr_write(base,
                  "app.test.clean  nope:xyz\n"
                  "app.test.dev    exempt: fixture\n"))
        bad = 1;
    rc = ptr_scan(defs, base, root, out, err);
    if (csr_slurp(out, ob, sizeof ob) || csr_slurp(err, ebout, sizeof ebout))
        bad = 1;
    bad |= rc != 1
        || strstr(ebout, "app.test.clean (malformed disposition: 'nope:xyz' — must start receipt: or exempt:)") == NULL;

    if (psp_st_reset(out) || psp_st_reset(err))
        bad = 1;
    if (csr_write(handler, "int x(void) { authority_receipt_x_available(0); return 0; }\n")
        || csr_write(base,
                     "app.test.clean  receipt:handler.c\n"
                     "app.test.dev    exempt: fixture\n"))
        bad = 1;
    rc = ptr_scan(defs, base, root, out, err);
    if (csr_slurp(out, ob, sizeof ob) || csr_slurp(err, ebout, sizeof ebout))
        bad = 1;
    bad |= rc != 0
        || strstr(ob, "(1 receipt, 1 exempt)") == NULL;

    if (psp_st_reset(out) || psp_st_reset(err))
        bad = 1;
    if (csr_write(handler, "int x(void) { return 0; }\n"))
        bad = 1;
    rc = ptr_scan(defs, base, root, out, err);
    if (csr_slurp(out, ob, sizeof ob) || csr_slurp(err, ebout, sizeof ebout))
        bad = 1;
    bad |= rc != 1
        || strstr(ebout, "app.test.clean -> handler.c (no authority_receipt verify call)") == NULL;

    if (psp_st_reset(out) || psp_st_reset(err))
        bad = 1;
    if (csr_write(base,
                  "app.test.clean  receipt:missing.c\n"
                  "app.test.dev    exempt: fixture\n"))
        bad = 1;
    rc = ptr_scan(defs, base, root, out, err);
    if (csr_slurp(out, ob, sizeof ob) || csr_slurp(err, ebout, sizeof ebout))
        bad = 1;
    bad |= rc != 1
        || strstr(ebout, "app.test.clean -> missing.c (file not found)") == NULL;

    if (psp_st_reset(out) || psp_st_reset(err))
        bad = 1;
    rc = ptr_scan(empty, base, root, out, err);
    if (csr_slurp(out, ob, sizeof ob) || csr_slurp(err, ebout, sizeof ebout))
        bad = 1;
    bad |= rc != 2 || strstr(ebout, "FATAL") == NULL;

    if (psp_st_reset(out) || psp_st_reset(err))
        bad = 1;
    if (csr_write(defa, k_pub))
        bad = 1;
    rc = ptr_scan(defs, base, root, out, err);
    if (csr_slurp(out, ob, sizeof ob) || csr_slurp(err, ebout, sizeof ebout))
        bad = 1;
    bad |= rc != 2 || strstr(ebout, "FATAL") == NULL;

    fclose(out);
    fclose(err);
    ptr_st_clear_env(had_d, oldd, had_b, oldb);
    (void)rap_rm_rf(root);
    if (bad)
        fputs("FAIL: check_privileged_transition_receipt selftest\n", stderr);
    return st_ok(bad, "check_privileged_transition_receipt selftest: OK\n");
}

static int aae_fail(const char *msg)
{
    if (fprintf(stderr, "check_asan_adx_exception: FAIL — %s\n", msg) < 0)
        return die("z23-lint: write failed\n", "");
    return 1;
}

static char *aae_trim(char *s)
{
    while (*s && isspace((unsigned char)*s))
        s++;
    size_t n = strlen(s);
    while (n && isspace((unsigned char)s[n - 1]))
        s[--n] = '\0';
    return s;
}

static int aae_continued(const char *line)
{
    const char *p = line + strlen(line);
    while (p > line && (p[-1] == '\n' || p[-1] == '\r'))
        p--;
    while (p > line && isspace((unsigned char)p[-1]))
        p--;
    return p > line && p[-1] == '\\';
}

static int aae_is_override(const char *line, const char *name, const char **rest)
{
    static const char ov[] = "override";
    const char *p = line;
    size_t nl = strlen(name);
    if (strncmp(p, ov, sizeof ov - 1) != 0)
        return 0;
    p += sizeof ov - 1;
    if (!isspace((unsigned char)*p))
        return 0;
    while (*p && isspace((unsigned char)*p))
        p++;
    if (strncmp(p, name, nl) != 0)
        return 0;
    p += nl;
    while (*p && isspace((unsigned char)*p))
        p++;
    if (p[0] != ':' || p[1] != '=')
        return 0;
    *rest = p + 2;
    return 1;
}

static int aae_append(char *value, size_t cap, const char *tok)
{
    if (!tok[0])
        return 0;
    size_t used = strlen(value), add = strlen(tok);
    if (used) {
        if (used + 1 + add + 1 > cap)
            return die("z23-lint: derived buffer overflow\n", "");
        value[used++] = ' ';
        memcpy(value + used, tok, add + 1);
        return 0;
    }
    if (add + 1 > cap)
        return die("z23-lint: derived buffer overflow\n", "");
    memcpy(value, tok, add + 1);
    return 0;
}

static int aae_read_var(const char *path, const char *name, char *value,
                        size_t cap)
{
    value[0] = '\0';
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char *line = NULL;
    size_t lcap = 0;
    ssize_t n;
    int active = 0, rc = 0;
    while ((n = getline(&line, &lcap, f)) >= 0) {
        const char *body = line;
        if (!active) {
            if (!aae_is_override(line, name, &body))
                continue;
            active = 1;
        }
        int cont = aae_continued(body);
        if (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) {
            line[n - 1] = '\0';
            if (n > 1 && line[n - 2] == '\r')
                line[n - 2] = '\0';
        }
        if (cont) {
            size_t L = strlen((char *)body);
            while (L && isspace((unsigned char)body[L - 1]))
                L--;
            if (L && body[L - 1] == '\\')
                ((char *)body)[L - 1] = '\0';
        }
        char *tok = aae_trim((char *)body);
        if (aae_append(value, cap, tok)) {
            rc = 2;
            break;
        }
        if (!cont)
            break;
    }
    int fr = fin(f, line, path, rc);
    return fr ? fr : rc;
}

static int aae_has_needle(const char *path, const char *needle, int *found)
{
    *found = 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        if (strstr(line, needle) != NULL) {
            *found = 1;
            break;
        }
    }
    return fin(f, line, path, rc);
}

static int aae_count_substr(const char *path, const char *needle, int *count)
{
    *count = 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        if (strstr(line, needle) != NULL)
            (*count)++;
    }
    return fin(f, line, path, rc);
}

static int aae_count_re(const char *path, const regex_t *re, int *count)
{
    *count = 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        if (regexec(re, line, 0, NULL, 0) == 0)
            (*count)++;
    }
    return fin(f, line, path, rc);
}

static int aae_require(const char *path, const char *needle)
{
    int found = 0;
    int rc = aae_has_needle(path, needle, &found);
    if (rc)
        return rc;
    if (found)
        return 0;
    char msg[8192];
    if (ovf(snprintf(msg, sizeof msg, "missing required Makefile wiring: %s",
                     needle), sizeof msg))
        return 2;
    return aae_fail(msg);
}

static int aae_copy(const char *src, const char *dst)
{
    FILE *in = fopen(src, "r");
    if (!in)
        return die("z23-lint: cannot open %s\n", src);
    FILE *out = fopen(dst, "w");
    if (!out) {
        fclose(in);
        return die("z23-lint: cannot open %s\n", dst);
    }
    char buf[8192];
    size_t n;
    int rc = 0;
    while ((n = fread(buf, 1, sizeof buf, in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) {
            rc = die("z23-lint: write failed\n", "");
            break;
        }
    }
    if (rc == 0 && ferror(in))
        rc = die("z23-lint: read failed: %s\n", src);
    if (fclose(out) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", dst);
    if (fclose(in) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", src);
    return rc;
}

static int aae_rewrite_first(const char *src, const char *dst, const char *from,
                             const char *to)
{
    FILE *in = fopen(src, "r");
    if (!in)
        return die("z23-lint: cannot open %s\n", src);
    FILE *out = fopen(dst, "w");
    if (!out) {
        fclose(in);
        return die("z23-lint: cannot open %s\n", dst);
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int done = 0, rc = 0;
    while ((n = getline(&line, &cap, in)) >= 0) {
        char *hit = !done ? strstr(line, from) : NULL;
        if (hit) {
            size_t pre = (size_t)(hit - line);
            size_t fl = strlen(from), tl = strlen(to);
            if (fwrite(line, 1, pre, out) != pre
                || fwrite(to, 1, tl, out) != tl
                || fputs(hit + fl, out) < 0) {
                rc = die("z23-lint: write failed\n", "");
                break;
            }
            done = 1;
        } else if (fwrite(line, 1, (size_t)n, out) != (size_t)n) {
            rc = die("z23-lint: write failed\n", "");
            break;
        }
    }
    free(line);
    if (rc == 0 && ferror(in))
        rc = die("z23-lint: read failed: %s\n", src);
    if (fclose(out) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", dst);
    if (fclose(in) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", src);
    return rc;
}

static const char *aae_makefile(void)
{
    return env_or("ZCL_ASAN_ADX_MAKEFILE", "Makefile");
}

static int aae_check(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        char msg[8192];
        if (ovf(snprintf(msg, sizeof msg, "cannot read %s", path), sizeof msg))
            return 2;
        return aae_fail(msg);
    }
    char sources[8192], flags[4096], common[8192], msg[8192];
    int rc = aae_read_var(path, "ASAN_ADX_FRAME_POINTER_EXCEPTION_SRCS",
                          sources, sizeof sources);
    if (rc)
        return rc;
    rc = aae_read_var(path, "ASAN_ADX_FRAME_POINTER_EXCEPTION_FLAGS",
                      flags, sizeof flags);
    if (rc)
        return rc;
    rc = aae_read_var(path, "ASAN_COMMON_SAN_FLAGS", common, sizeof common);
    if (rc)
        return rc;
    if (strcmp(sources,
               "core/modules/sapling/src/bn254_accel.c "
               "core/modules/sapling/src/fr_avx512.c") != 0) {
        if (ovf(snprintf(msg, sizeof msg,
                         "exception source allowlist changed: '%s'", sources),
                sizeof msg))
            return 2;
        return aae_fail(msg);
    }
    if (strcmp(flags, "-fomit-frame-pointer") != 0) {
        if (ovf(snprintf(msg, sizeof msg, "exception flags changed: '%s'",
                         flags), sizeof msg))
            return 2;
        return aae_fail(msg);
    }
    if (strcmp(common,
               "-fsanitize=address,undefined -fno-omit-frame-pointer "
               "-fno-sanitize=alignment") != 0) {
        if (ovf(snprintf(msg, sizeof msg,
                         "general ASan/UBSan flags changed: '%s'", common),
                sizeof msg))
            return 2;
        return aae_fail(msg);
    }
    static const char *const needles[] = {
        "TEST_ASAN_ADX_FRAME_POINTER_EXCEPTION_OBJS := $(addprefix $(TEST_ASAN_OBJ_DIR)/,$(ASAN_ADX_FRAME_POINTER_EXCEPTION_SRCS:.c=.o))",
        "$(TEST_ASAN_ADX_FRAME_POINTER_EXCEPTION_OBJS): TEST_ASAN_OBJECT_CFLAGS += $(ASAN_ADX_FRAME_POINTER_EXCEPTION_FLAGS)",
        "DEV_ASAN_ADX_FRAME_POINTER_EXCEPTION_OBJS := $(addprefix $(DEV_ASAN_OBJ_DIR)/,$(ASAN_ADX_FRAME_POINTER_EXCEPTION_SRCS:.c=.o))",
        "$(DEV_ASAN_ADX_FRAME_POINTER_EXCEPTION_OBJS): DEV_ASAN_OBJECT_CFLAGS += $(ASAN_ADX_FRAME_POINTER_EXCEPTION_FLAGS)",
    };
    for (size_t i = 0; i < sizeof needles / sizeof needles[0]; i++) {
        rc = aae_require(path, needles[i]);
        if (rc)
            return rc;
    }
    int epoch_count = 0;
    rc = aae_count_substr(path,
                          "adx-exception=$(ASAN_ADX_FRAME_POINTER_EXCEPTION_SRCS):$(ASAN_ADX_FRAME_POINTER_EXCEPTION_FLAGS)",
                          &epoch_count);
    if (rc)
        return rc;
    if (epoch_count != 2) {
        if (ovf(snprintf(msg, sizeof msg,
                         "expected the test and dev ASan compile epochs to bind the exception; found %d binding(s)",
                         epoch_count), sizeof msg))
            return 2;
        return aae_fail(msg);
    }
    regex_t re;
    rc = compile_pat(&re, REG_EXTENDED, "ASAN_COMMON_SAN_FLAGS",
                     "[[:space:]]*=", "", "");
    if (rc)
        return rc;
    int override_count = 0;
    rc = aae_count_re(path, &re, &override_count);
    regfree(&re);
    if (rc)
        return rc;
    if (override_count != 0) {
        if (ovf(snprintf(msg, sizeof msg,
                         "found %d recipe/caller override(s) of ASAN_COMMON_SAN_FLAGS",
                         override_count), sizeof msg))
            return 2;
        return aae_fail(msg);
    }
    rc = aae_require(path,
                     "TEST_ASAN_CFLAGS = $(filter-out -O3 $(ZCL_LTO_FLAG) -Werror,$(CACHED_CFLAGS)) -O1 -g -DZCL_TESTING \\");
    if (rc)
        return rc;
    return aae_require(path,
                       "DEV_ASAN_CFLAGS = $(filter-out -O3 $(ZCL_LTO_FLAG) -Werror,$(CACHED_CFLAGS)) $(ZCL_DEV_OPT) -g3 -DZCL_DEV_BUILD \\");
}

int check_asan_adx_exception_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    char root[4096];
    if (cic_repo_root(root, sizeof root))
        return 2;
    if (chdir(root) != 0)
        return die("z23-lint: cannot scan %s\n", root);
    int rc = aae_check(aae_makefile());
    if (rc)
        return rc;
    if (fputs("check_asan_adx_exception: clean — exactly two ASan ADX TUs omit frame pointers; sanitizer coverage and epoch bindings remain intact\n",
              stdout) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

int check_asan_adx_exception_selftest(void)
{
    char root[4096];
    if (cic_repo_root(root, sizeof root))
        return 2;
    if (chdir(root) != 0)
        return die("z23-lint: cannot scan %s\n", root);
    const char *mk = aae_makefile();
    const char *td = env_or("TMPDIR", "/tmp");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-asan-adx-XXXXXX", td),
            sizeof tmpl))
        return 2;
    char *tmp = mkdtemp(tmpl);
    if (!tmp)
        return die("z23-lint: mkdir failed: %s\n", td);
    char copy[4096], nextp[4096];
    static char logb[256 * 1024];
    int code = 0, rc;
    if (ovf(snprintf(copy, sizeof copy, "%s/Makefile", tmp), sizeof copy)
        || ovf(snprintf(nextp, sizeof nextp, "%s/Makefile.next", tmp),
               sizeof nextp)
        || aae_copy(mk, copy)) {
        (void)rap_rm_rf(tmp);
        return 2;
    }
    if (setenv("ZCL_ASAN_ADX_MAKEFILE", copy, 1) != 0) {
        (void)rap_rm_rf(tmp);
        return die("z23-lint: setenv failed\n", "");
    }
    rc = cic_invoke("check-asan-adx-exception", 0, logb, sizeof logb, &code);
    if (rc) {
        (void)rap_rm_rf(tmp);
        return rc;
    }
    if (code != 0) {
        (void)rap_rm_rf(tmp);
        return code;
    }
    static const char from[] = "core/modules/sapling/src/bn254_accel.c";
    static const char to[] =
        "core/modules/sapling/src/bn254_accel.c core/modules/sapling/src/unaudited_accel.c";
    if (aae_rewrite_first(copy, nextp, from, to) || rename(nextp, copy) != 0) {
        (void)rap_rm_rf(tmp);
        return die("z23-lint: write failed\n", "");
    }
    rc = cic_invoke("check-asan-adx-exception", 1, logb, sizeof logb, &code);
    if (rc) {
        (void)rap_rm_rf(tmp);
        return rc;
    }
    if (code == 0) {
        (void)rap_rm_rf(tmp);
        return aae_fail("selftest expanded the exception allowlist but the gate passed");
    }
    if (strstr(logb, "exception source allowlist changed") == NULL) {
        (void)rap_rm_rf(tmp);
        return aae_fail("selftest failed for the wrong reason");
    }
    (void)rap_rm_rf(tmp);
    if (fputs("check_asan_adx_exception: selftest PASS — an allowlist expansion is rejected\n",
              stdout) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}
