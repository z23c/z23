/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: planted-violation selftest for check-equihash-params, split out
 * of gate_git_scan_a.c to keep that file under the family line-count
 * ceiling. The two files share the gate's regex/scan internals through
 * gate_git_scan_a_priv.h.
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
#include "gate_git_scan_a_priv.h"

/* Original prefilter, retained only as a differential test oracle. */
static int nak_old_possible(const char *s, size_t n)
{
    static const char *const lead[] = {"sk-", "xai-", "gsk_", "ghp_", "glpat-", "AKIA", "Bearer"};
    for (size_t k = 0; k < sizeof lead / sizeof lead[0]; ++k) {
        size_t m = strlen(lead[k]);
        for (size_t i = 0; i + m <= n; ++i)
            if (!memcmp(s + i, lead[k], m)) return 1;
    }
    for (size_t i = 32; i + 16 < n; ++i) {
        if (s[i] != '.') continue;
        size_t j = 0;
        for (; j < 32; ++j) {
            unsigned char c = (unsigned char)s[i - 1 - j];
            if (c < 128 && !isalnum(c)) break;
        }
        if (j != 32) continue;
        for (j = 0; j < 16; ++j) {
            unsigned char c = (unsigned char)s[i + 1 + j];
            if (c < 128 && !isalnum(c)) break;
        }
        if (j == 16) return 1;
    }
    return 0;
}

static int nak_lead_equivalence(void)
{
    static const char *const leads[] = {"s" "k-", "x" "ai-", "g" "sk_", "g" "hp_", "g" "lpat-", "A" "KIA", "B" "earer"};
    char sample[80];
    for (size_t k = 0; k < sizeof leads / sizeof leads[0]; ++k)
        for (size_t offset = 0; offset < 40; ++offset) {
            memset(sample, '!', sizeof sample);
            memcpy(sample + offset, leads[k], strlen(leads[k]));
            for (size_t n = 0; n <= sizeof sample; ++n)
                if (nak_old_possible(sample, n) != nak_regex_possible(sample, n)) return 1;
        }
    return 0;
}

static int nak_bytes_equivalence(void)
{
    unsigned state = 0x537123u; char sample[128];
    for (size_t round = 0; round < 5000; ++round) {
        for (size_t i = 0; i < sizeof sample; ++i) {
            state = state * 1664525u + 1013904223u;
            sample[i] = (char)(state / 16777216u); /* sample the PRNG's high bits */
        }
        size_t n = round % (sizeof sample + 1);
        if (nak_old_possible(sample, n) != nak_regex_possible(sample, n)) return 1;
    }
    memset(sample, 'a', sizeof sample);
    sample[40] = '.';
    for (size_t i = 0; i < sizeof sample; ++i) {
        char saved = sample[i];
        for (unsigned b = 0; b < 256; ++b) {
            sample[i] = (char)b;
            if (nak_old_possible(sample, sizeof sample) != nak_regex_possible(sample, sizeof sample)) return 1;
        }
        sample[i] = saved;
    }
    return 0;
}

int nak_prefilter_equivalence_selftest(void)
{
    int bad = nak_lead_equivalence() | nak_bytes_equivalence();
    if (bad) fprintf(stderr, "check_no_api_keys: prefilter equivalence failed\n");
    return bad;
}

static int eqp_build_paths(char *p_build, size_t bsz, char *p_skill, size_t ssz,
    char *p_disp, size_t dsz)
{
    if (ovf(snprintf(p_build, bsz, "build/x.%s", "md"), bsz)
        || ovf(snprintf(p_skill, ssz, ".claude/skills/w.%s", "md"), ssz)
        || ovf(snprintf(p_disp, dsz, "docs/PLANTED.%s", "md"), dsz))
        return 2;
    return 0;
}

static int eqp_path_filter_bad(const char *p_build, const char *p_skill)
{
    return eqp_keep_path(p_build) | eqp_keep_path("vendor/y.c")
        | eqp_keep_path(".claude/worktrees/z.h")
        | !eqp_keep_path(p_skill)
        | eqp_keep_path("docs/node/EQUIHASH_PARAMS.md")
        | eqp_keep_path("tools/equihash_params_fact.c")
        | eqp_keep_path("foo.py") | !eqp_keep_path("foo.def");
}

static int eqp_case_flat_claim(const char *work, const char *p_disp, regex_t *lit,
    regex_t *claim, regex_t *qual, int *bad)
{
    char planted[4096], line[96];
    if (ovf(snprintf(planted, sizeof planted, "%s/%s", work, p_disp), sizeof planted)
        || snprintf(line, sizeof line, "ZClassic is Equi%s 200,9 and always will be.\n",
                    "hash") >= (int)sizeof line || csr_write(planted, line))
        return 2;
    int nlines = 0, hits = 0;
    int rc = eqp_load(planted, &nlines);
    if (rc == 0) rc = eqp_scan_lines(p_disp, nlines, lit, claim, qual, NULL, &hits);
    if (rc || hits == 0) {
        fputs("check_equihash_params selftest: planted flat claim not detected\n", stderr);
        *bad = 1;
    }
    return 0;
}

static int eqp_case_qualified(const char *work, const char *p_disp, regex_t *lit,
    regex_t *claim, regex_t *qual, int *bad)
{
    char planted[4096];
    if (ovf(snprintf(planted, sizeof planted, "%s/%s", work, p_disp), sizeof planted))
        return 2;
    if (csr_write(planted,
                  "Mainnet is 192,7 from the Bubbles height; 200,9 applies before it.\n"))
        return 2;
    int nlines = 0, hits = 0;
    int rc = eqp_load(planted, &nlines);
    if (rc == 0) rc = eqp_scan_lines(p_disp, nlines, lit, claim, qual, NULL, &hits);
    if (rc || hits != 0) {
        fputs("check_equihash_params selftest: qualified sentence was reported\n", stderr);
        *bad = 1;
    }
    return 0;
}

static int eqp_case_nul(const char *work, const char *p_disp)
{
    char path[4096];
    static const char text[] = "\0ZClassic is Equi" "hash 200,9 and always will be.\n";
    if (ovf(snprintf(path, sizeof path, "%s/%s", work, p_disp), sizeof path))
        return 2;
    FILE *f = fopen(path, "wb");
    if (!f) return 2;
    bool bad = fwrite(text, 1, sizeof text - 1, f) != sizeof text - 1;
    if (fclose(f) != 0) bad = true;
    if (bad) return 2;
    int nlines = 0;
    return eqp_load(path, &nlines) == 2 ? 0 : 1;
}

int check_equihash_params_selftest(void)
{
    regex_t lit, claim, qual;
    int rc = eqp_comp(&lit, &claim, &qual);
    if (rc) return rc;
    char p_build[16], p_skill[32], p_disp[24];
    if (eqp_build_paths(p_build, sizeof p_build, p_skill, sizeof p_skill, p_disp, sizeof p_disp)) {
        drop3(&lit, &claim, &qual);
        return 2;
    }
    int bad = eqp_path_filter_bad(p_build, p_skill);
    if (bad) fputs("check_equihash_params selftest: path filter failed\n", stderr);

    const char *td = env_or("TMPDIR", "/tmp");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-eqparams-st.XXXXXX", td), sizeof tmpl)) {
        drop3(&lit, &claim, &qual);
        return 2;
    }
    char *work = mkdtemp(tmpl);
    if (!work) {
        drop3(&lit, &claim, &qual);
        return die("z23-lint: mkdir failed: %s\n", td);
    }

    int frc = eqp_case_flat_claim(work, p_disp, &lit, &claim, &qual, &bad);
    if (frc == 0)
        frc = eqp_case_qualified(work, p_disp, &lit, &claim, &qual, &bad);
    if (frc == 0) frc = eqp_case_nul(work, p_disp);
    (void)rap_rm_rf(work);
    drop3(&lit, &claim, &qual);
    if (frc)
        return frc;
    return st_ok(bad, "check_equihash_params selftest: OK\n");
}

/* Exercise the real entrypoint in a child: the scan floor must not hide an
 * open failure, and a refusal must never print the clean verdict. */
static int nak_case(const char *exe, const char *path, int want)
{
    char quoted[8192], cmd[16384], output[4096];
    int code = -1;
    if (sh_single_quote(path, quoted, sizeof quoted)
        || ovf(snprintf(cmd, sizeof cmd,
            "ZCL_API_KEY_SCAN_FILES=%s %s check-no-api-keys 2>&1",
            quoted, exe), sizeof cmd)) return 2;
    int rc = capture_cmd(cmd, output, sizeof output, &code);
    if (rc || code != want) return 1;
    bool clean = strstr(output, "0 violation(s)") != NULL;
    if (clean != (want == 0)) return 1;
    if (want == 2 && (!strstr(output, path)
        || !strstr(output, "cannot open API-key input"))) return 1;
    return 0;
}

static int nak_paths(const char *dir, char *path, char *child, char *missing,
                     char *quoted, size_t cap)
{
    char exe[4096];
    return ovf(snprintf(path, 256, "%s/input.c", dir), 256)
        || ovf(snprintf(child, 256, "%s/child.c", path), 256)
        || ovf(snprintf(missing, 256, "%s/missing.c", dir), 256)
        || lint_self_exe(exe, sizeof exe)
        || sh_single_quote(exe, quoted, cap);
}

static int nak_marker_nul(const char *path)
{
    static const char input[] = "api-key-example-ok\0s" "k-" "abcdefghijklmnopqrst\n";
    FILE *f = fopen(path, "wb");
    if (!f) return 1;
    int bad = fwrite(input, 1, sizeof(input) - 1, f) != sizeof(input) - 1;
    return bad | (fclose(f) != 0);
}

static int nak_file_checks(const char *exe, const char *path)
{
    if (csr_write(path, "s" "k-" "abcdefghijklmnopqrst\n")) return 2;
    if (nak_case(exe, path, 1) || nak_marker_nul(path) || nak_case(exe, path, 0)) return 1;
    if (csr_write(path, "ordinary text\n")) return 2;
    return nak_case(exe, path, 0);
}

int nak_filesystem_selftest(void)
{
    char dir[] = "./test-tmp/nak-open.XXXXXX";
    char path[256], child[256], missing[256], quoted[8192];
    if (mkdir("./test-tmp", 0755) != 0 && errno != EEXIST) return 2;
    if (!mkdtemp(dir)) return 2;
    int rc = nak_paths(dir, path, child, missing, quoted, sizeof quoted);
    if (!rc) rc = nak_file_checks(quoted, path);
    if (!rc) rc = nak_case(quoted, missing, 0);
    if (!rc) rc = nak_case(quoted, child, 2);
    if (unlink(path) != 0 && errno != ENOENT && !rc) rc = 2;
    if (rmdir(dir) != 0 && !rc) rc = 2;
    return rc;
}
