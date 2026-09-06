/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — git-tracked-enumeration lint gates of the C23 lint
 * runtime, half A (check-no-stray-root-files, check-simd-os-support,
 * check-c23-only, check-no-api-keys, check-error-doc-refs,
 * check-framework-filename-suffix).
 */

/*
 * Gates: check-no-stray-root-files, check-simd-os-support, check-c23-only, check-no-api-keys, check-error-doc-refs, check-framework-filename-suffix
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

struct sr_acc { struct sr_set allowed; int tracked; };


static void sr_del(struct sr_set *s, const char *name)
{
    for (int i = 0; i < s->count; i++)
        if (!strcmp(s->n[i], name)) {
            if (i + 1 < s->count) memcpy(s->n[i], s->n[s->count - 1], SR_NAME);
            s->count--;
            return;
        }
}

static const char *const k_sr_root_allowed[] = {
    ".git", "build", "vendor", "test-tmp", "compile_commands.json",
    ".cache", ".codeindex", ".zvcs", ".core-unseal-token", ".zcl_test_render",
    "chaos-output", ".antigravitycli", ".gemini", ".aider", ".vscode", ".idea",
    "tags", "TAGS", ".DS_Store",
};

static int sr_seed(struct sr_set *s)
{
    for (size_t i = 0; i < sizeof k_sr_root_allowed / sizeof k_sr_root_allowed[0]; i++)
        if (sr_add(s, k_sr_root_allowed[i])) return 2;
    return 0;
}
static int sr_on_track(const char *path, void *ctx)
{
    struct sr_acc *a = ctx;
    const char *sl = strchr(path, '/');
    size_t n = sl ? (size_t)(sl - path) : strlen(path);
    char seg[SR_NAME];
    a->tracked++;
    if (n >= sizeof seg) return die("z23-lint: stray-root overflow\n", "");
    memcpy(seg, path, n); seg[n] = '\0';
    return sr_add(&a->allowed, seg);
}
static int sr_ok_name(const char *name, const struct sr_set *al)
{
    const char *base = strncmp(name, ".aider", 6) == 0 ? ".aider" : name;
    return sr_has(al, base) || !strncmp(name, "core.", 5) || !strncmp(name, "vgcore.", 7);
}

static int sr_feed(const struct sr_set *al, const char *const *names, int n,
                   char stray[][SR_NAME], int max, int *ns, int *scanned)
{
    *ns = 0;
    *scanned = 0;
    for (int i = 0; i < n; i++) {
        if (!names[i][0] || !strcmp(names[i], ".") || !strcmp(names[i], "..")) continue;
        (*scanned)++;
        if (sr_ok_name(names[i], al)) continue;
        if (*ns >= max || strlen(names[i]) >= SR_NAME)
            return die("z23-lint: stray-root overflow\n", "");
        memcpy(stray[(*ns)++], names[i], strlen(names[i]) + 1);
    }
    return 0;
}

static int sr_report(char stray[][SR_NAME], int n)
{
    if (fprintf(stderr, "FAIL: %d stray entr(y/ies) in the repository root\n", n) < 0
        || fputs("  The root is a curated list: source areas, top-level docs, and a\n"
                 "  short allowlist of generated/local entries. These are neither.\n"
                 "  They are gitignored, so 'git status' stays clean while 'ls' shows\n"
                 "  a junk drawer — that is exactly what this gate exists to stop.\n",
                 stderr) < 0)
        return die("z23-lint: write failed\n", "");
    for (int i = 0; i < n; i++)
        if (fprintf(stderr, "    %s [stray root entry]\n", stray[i]) < 0)
            return die("z23-lint: write failed\n", "");
    if (fputs("  Fix at the WRITER, not here: a test writes its scratch under\n"
              "  ./test-tmp/ (test_make_tmpdir in tests/harness/include/test/test_core.h),\n"
              "  a script writes its log under a state/log dir. 'git add' it if it\n"
              "  is real new content; delete it if it is debris.\n", stderr) < 0)
        return die("z23-lint: write failed\n", "");
    return 1;
}

int check_no_stray_root_files_run(int argc, char **argv)
{
    (void)argc; (void)argv;
    struct sr_acc a = {0};
    int rc = sr_seed(&a.allowed);
    if (rc == 0) rc = each_zpath(k_ls_all, sr_on_track, &a);
    if (rc == 0)
        rc = gate_require_scanned(a.tracked, 100, "check-no-stray-root-files",
                "git ls-files returned almost nothing — not a git checkout, or the wrong cwd.");
    if (rc) return rc;
    const char *extra = getenv("ZCL_ROOT_STRAY_EXTRA_FOR_TEST");
    if (extra && extra[0]) sr_del(&a.allowed, extra);
    struct dirent **names = NULL;
    int nd = scandir(".", &names, NULL, alphasort);
    if (nd < 0) return die("z23-lint: cannot scan %s\n", ".");
    char stray[SR_STRAY][SR_NAME];
    int ns = 0, scanned = 0;
    for (int i = 0; i < nd; i++) {
        const char *name = names[i]->d_name;
        if (rc == 0 && strcmp(name, ".") && strcmp(name, "..")) {
            scanned++;
            if (!sr_ok_name(name, &a.allowed)) {
                if (ns >= SR_STRAY || strlen(name) >= SR_NAME)
                    rc = die("z23-lint: stray-root overflow\n", "");
                else memcpy(stray[ns++], name, strlen(name) + 1);
            }
        }
        free(names[i]);
    }
    free(names);
    if (rc == 0)
        rc = gate_require_scanned(scanned, 20, "check-no-stray-root-files",
                                  "the repo root listed fewer than 20 entries — wrong cwd?");
    if (rc) return rc;
    if (ns) return sr_report(stray, ns);
    return printf("[check_no_stray_root_files] scanned %d root entr(y/ies); 0 strays\n",
                  scanned) < 0 ? die("z23-lint: write failed\n", "") : 0;
}

int check_no_stray_root_files_selftest(void)
{
    struct sr_set al = {0};
    char stray[8][SR_NAME];
    int ns = 0, sc = 0, bad = sr_seed(&al) != 0;
    const char *okn[] = { ".git", "build", "vendor", "test-tmp", ".aider" };
    bad |= sr_feed(&al, okn, 5, stray, 8, &ns, &sc) || ns != 0 || sc != 5;
    const char *badn[] = { ".git", "junk.db" };
    ns = sc = 0;
    bad |= sr_feed(&al, badn, 2, stray, 8, &ns, &sc) || ns != 1
        || strcmp(stray[0], "junk.db") || sr_report(stray, ns) != 1;
    const char *aid[] = { ".aider.tags.cache.v3" };
    ns = sc = 0;
    bad |= sr_feed(&al, aid, 1, stray, 8, &ns, &sc) || ns != 0;
    const char *core[] = { "core.1234", "vgcore.9" };
    ns = sc = 0;
    bad |= sr_feed(&al, core, 2, stray, 8, &ns, &sc) || ns != 0;
    const char *old = getenv("ZCL_ROOT_STRAY_EXTRA_FOR_TEST");
    if (setenv("ZCL_ROOT_STRAY_EXTRA_FOR_TEST", "build", 1) != 0) bad = 1;
    {
        const char *e = getenv("ZCL_ROOT_STRAY_EXTRA_FOR_TEST");
        if (e && e[0]) sr_del(&al, e);
    }
    const char *ex[] = { "build" };
    ns = sc = 0;
    bad |= sr_feed(&al, ex, 1, stray, 8, &ns, &sc) || ns != 1 || strcmp(stray[0], "build");
    if (old) (void)setenv("ZCL_ROOT_STRAY_EXTRA_FOR_TEST", old, 1);
    else (void)unsetenv("ZCL_ROOT_STRAY_EXTRA_FOR_TEST");
    return st_ok(bad, "check_no_stray_root_files selftest: OK\n");
}

static const char *const k_simd_del[] = {
    "keccak_x4_available", "core/modules/crypto/src/keccak_x4.c",
};
static int has_ci(const char *h, const char *n)
{
    size_t nlen = strlen(n);
    for (; *h; h++) {
        size_t i = 0;
        while (i < nlen && h[i]
               && tolower((unsigned char)h[i]) == tolower((unsigned char)n[i])) i++;
        if (i == nlen) return 1;
    }
    return 0;
}
static int mem_local(const char *t)
{
    return strstr(t, "crypto/simd_dispatch.h")
        || (has_ci(t, "xgetbv") && has_ci(t, "osxsave"));
}
static int mem_del(const char *t)
{
    for (size_t i = 0; i + 1 < sizeof k_simd_del / sizeof k_simd_del[0]; i += 2)
        if (strstr(t, k_simd_del[i])) return 1;
    return 0;
}
static int file_has(const char *path, const char *nd, int ci, int *found)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char *line = NULL;
    size_t cap = 0;
    *found = 0;
    while (!*found && getline(&line, &cap, f) >= 0)
        *found = ci ? has_ci(line, nd) : strstr(line, nd) != NULL;
    return fin(f, line, path, 0);
}
static int simd_local_file(const char *path, int *ok)
{
    int a = 0, b = 0, c = 0, rc = file_has(path, "crypto/simd_dispatch.h", 0, &a);
    if (rc) return rc;
    if (a) { *ok = 1; return 0; }
    rc = file_has(path, "xgetbv", 1, &b);
    if (rc) return rc;
    rc = file_has(path, "osxsave", 1, &c);
    if (rc) return rc;
    *ok = b && c;
    return 0;
}
struct simd_acc { char f[64][192]; int n; };
/* git grep -l of tracked *.c (not a filesystem walk): untracked probes do not count. */
static const char k_simd_grep[] =
    "git grep -l -z -E '__attribute__\\(\\(" "target\\(\"avx' -- '*.c'";
static int simd_add_path(const char *path, void *ctx)
{
    struct simd_acc *a = ctx;
    size_t n = strlen(path);
    if (a->n >= 64 || n >= 192) return die("z23-lint: derived buffer overflow\n", "");
    memcpy(a->f[a->n++], path, n + 1);
    return 0;
}
static int simd_pcmp(const void *a, const void *b)
{ return strcmp((const char *)a, (const char *)b); }
static int simd_open(const char *path, int rc)
{ return rc < 0 ? die("z23-lint: cannot open %s\n", path) : rc; }

int check_simd_os_support_run(int argc, char **argv)
{
    (void)argc; (void)argv;
    struct simd_acc a = {0};
    int rc = each_zpath_st(k_simd_grep, 1, simd_add_path, &a), v = 0;
    if (rc == 0 && a.n > 1)
        qsort(a.f, (size_t)a.n, sizeof a.f[0], simd_pcmp);
    if (rc == 0)
        rc = gate_require_scanned(a.n, 1, "check_simd_os_support",
                                  "expected at least core/modules/crypto/src/blake2b_avx2.c "
                                  "to carry target(\"avx...\")");
    for (size_t i = 0; rc == 0 && i + 1 < sizeof k_simd_del / sizeof k_simd_del[0]; i += 2) {
        const char *name = k_simd_del[i], *file = k_simd_del[i + 1];
        struct stat st;
        if (stat(file, &st) != 0 || !S_ISREG(st.st_mode)) {
            if (fprintf(stderr, "%s: delegate '%s' names a file that no longer exists\n",
                        file, name) < 0)
                return die("z23-lint: write failed\n", "");
            v++;
            continue;
        }
        int ok = 0;
        rc = simd_open(file, simd_local_file(file, &ok));
        if (rc) return rc;
        if (!ok) {
            if (fprintf(stderr, "%s: defines delegate '%s' but performs no OS-state check\n",
                        file, name) < 0
                || fputs("    -> every caller that relies on it is now unguarded\n", stderr) < 0)
                return die("z23-lint: write failed\n", "");
            v++;
        }
    }
    for (int i = 0; rc == 0 && i < a.n; i++) {
        int ok = 0, del = 0;
        rc = simd_open(a.f[i], simd_local_file(a.f[i], &ok));
        if (rc) return rc;
        if (ok) continue;
        for (size_t d = 0; d + 1 < sizeof k_simd_del / sizeof k_simd_del[0]; d += 2) {
            int fnd = 0;
            rc = simd_open(a.f[i], file_has(a.f[i], k_simd_del[d], 0, &fnd));
            if (rc) return rc;
            if (fnd) { del = 1; break; }
        }
        if (del) continue;
        if (fprintf(stderr, "%s: dispatches into target(\"avx...\") code with no OS-state check\n",
                    a.f[i]) < 0
            || fputs("    -> #include \"crypto/simd_dispatch.h\" and gate the dispatch on\n",
                     stderr) < 0
            || fputs("       simd_host_has_avx2() / simd_host_has_avx512f()\n", stderr) < 0)
            return die("z23-lint: write failed\n", "");
        v++;
    }
    if (rc) return rc;
    const char *mode = clock_mode();
    if (printf("[check_simd_os_support] scanned %d AVX dispatch file(s), %d violation(s) "
               "(mode: %s)\n", a.n, v, mode) < 0
        || puts("[check_simd_os_support] CPUID says what the CPU decodes; XCR0 says what") < 0
        || puts("[check_simd_os_support] the OS will save. Dispatching on the first alone") < 0
        || puts("[check_simd_os_support] is a SIGILL on a host booted with the state off.") < 0)
        return die("z23-lint: write failed\n", "");
    return clock_grade(v, mode);
}

int check_simd_os_support_selftest(void)
{
    const char *avx = "__attribute__((target(\"" "avx2\"))) void zz(void) {}";
    char a[160], b[200], c[180], d[180], e[200];
    if (ovf(snprintf(a, sizeof a, "%s", avx), sizeof a)
        || ovf(snprintf(b, sizeof b, "#include \"crypto/simd_dispatch.h\"\n%s", avx), sizeof b)
        || ovf(snprintf(c, sizeof c, "XGETBV osxsave\n%s", avx), sizeof c)
        || ovf(snprintf(d, sizeof d, "xgetbv\n%s", avx), sizeof d)
        || ovf(snprintf(e, sizeof e, "keccak_x4_available\n%s", avx), sizeof e))
        return 2;
    int bad = mem_local(a) || !mem_local(b) || !mem_local(c) || mem_local(d)
            || !mem_del(e) || mem_del(a)
            || mem_local(a) || mem_del(a)
            || !(!mem_local(d) && !mem_del(d))
            || !(!mem_local(e) && mem_del(e))
            || mem_local("void keccak_x4_available(void) {}");
    return st_ok(bad, "check_simd_os_support selftest: OK\n");
}

static int slurp_popen_lines(const char *cmd, int allow_exit1, char *out, size_t cap,
                             size_t *used)
{
    FILE *p = popen(cmd, "r");
    if (!p) return die("z23-lint: popen failed (%s)\n", cmd);
    char *line = NULL;
    size_t lcap = 0;
    ssize_t n;
    int rc = 0;
    *used = 0;
    out[0] = '\0';
    while ((n = getline(&line, &lcap, p)) >= 0) {
        if (n > 0 && line[n - 1] == '\n') line[--n] = '\0';
        if (n <= 0) continue;
        int k = snprintf(out + *used, cap - *used, "%s\n", line);
        if (ovf(k, cap - *used)) { rc = 2; break; }
        *used += (size_t)k;
    }
    if (rc == 0 && ferror(p)) rc = die("z23-lint: read failed (%s)\n", cmd);
    free(line);
    int st = pclose(p);
    if (rc) return rc;
    return cmd_done(cmd, st, allow_exit1);
}

static int c23_ends(const char *path, const char *suf)
{
    size_t n = strlen(path), m = strlen(suf);
    return n >= m && memcmp(path + n - m, suf, m) == 0;
}
static int c23_seg_end(const char *path, const char *name)
{
    size_t n = strlen(path), m = strlen(name);
    if (n < m || memcmp(path + n - m, name, m) != 0) return 0;
    return n == m || path[n - m - 1] == '/';
}
static int c23_path_hit(const char *path)
{
    static const char dir[] = { '.', 'c', 'a', 'r', 'g', 'o', '/', '\0' };
    static const char mid[] = { '/', '.', 'c', 'a', 'r', 'g', 'o', '/', '\0' };
    if (c23_seg_end(path, "Cargo.toml") || c23_seg_end(path, "Cargo.lock")
        || c23_seg_end(path, "build.rs") || c23_ends(path, ".rs"))
        return 1;
    return !strncmp(path, dir, 7) || strstr(path, mid) != NULL;
}
static int c23_skip_ref(const char *path)
{
    return !strcmp(path, "contexts/wallet/domain/src/mnemonic.c")
        || !strcmp(path, "core/modules/sapling/src/circuit_gadgets.c");
}
static int c23_fill_pat(char *pat, size_t cap)
{
    return ovf(snprintf(pat, cap, "%s%s%s%s%s",
                       "ZCL_WITH_", "RUST|librust", "zcash\\.a|librust",
                       "zcash_[A-Za-z0-9_]*|-l" "rust[A-Za-z0-9_]*|",
                       "(^|[^A-Za-z0-9_])(car" "go|rust" "c)([^A-Za-z0-9_]|$)"), cap);
}
static int c23_comp(regex_t *re)
{
    char pat[256];
    int rc = c23_fill_pat(pat, sizeof pat);
    return rc ? rc : reg_fail(re, regcomp(re, pat, REG_EXTENDED));
}
static int c23_grep_cmd(char *cmd, size_t cap)
{
    char pat[256];
    int rc = c23_fill_pat(pat, sizeof pat);
    if (rc) return rc;
    return ovf(snprintf(cmd, cap,
        "git grep -n -E '%s' -- Makefile config app core domain "
        "lib ports adapters packages src tools "
        "':!contexts/wallet/domain/src/mnemonic.c' "
        "':!core/modules/sapling/src/circuit_gadgets.c'", pat), cap);
}
struct c23_acc { char *paths; size_t pcap, plen; };
static int c23_on_track(const char *path, void *ctx)
{
    struct c23_acc *a = ctx;
    if (!c23_path_hit(path)) return 0;
    int k = snprintf(a->paths + a->plen, a->pcap - a->plen, "%s\n", path);
    if (ovf(k, a->pcap - a->plen)) return 2;
    a->plen += (size_t)k;
    return 0;
}

int check_c23_only_run(int argc, char **argv)
{
    (void)argc; (void)argv;
    char paths[CLK_MATCH] = {0}, refs[CLK_MATCH] = {0}, cmd[1024];
    struct c23_acc a = { .paths = paths, .pcap = sizeof paths };
    int rc = each_zpath(k_ls_all, c23_on_track, &a);
    if (rc == 0) rc = c23_grep_cmd(cmd, sizeof cmd);
    size_t rlen = 0;
    if (rc == 0) rc = slurp_popen_lines(cmd, 1, refs, sizeof refs, &rlen);
    if (rc) return rc;
    if (a.plen || rlen) {
        if (fputs("check_c23_only: FAIL — Z23 must have no Rust dependency\n", stderr) < 0)
            return die("z23-lint: write failed\n", "");
        if (a.plen && fwrite(paths, 1, a.plen, stderr) != a.plen)
            return die("z23-lint: write failed\n", "");
        if (rlen && fwrite(refs, 1, rlen, stderr) != rlen)
            return die("z23-lint: write failed\n", "");
        return 1;
    }
    return fputs("check_c23_only: clean — no Rust source, manifest, build, link, or FFI path\n",
                 stdout) < 0 ? die("z23-lint: write failed\n", "") : 0;
}

int check_c23_only_selftest(void)
{
    regex_t re;
    int cr = c23_comp(&re);
    if (cr) return cr;
    char cg[24], lr[40], wr[24], pdir[24], pmid[32];
    if (snprintf(cg, sizeof cg, "car%s", "go build") >= (int)sizeof cg
        || snprintf(lr, sizeof lr, "cc main.o -l%s", "rustzcash") >= (int)sizeof lr
        || snprintf(wr, sizeof wr, "ZCL_WITH_%s=1", "RUST") >= (int)sizeof wr
        || snprintf(pdir, sizeof pdir, ".car%s", "go/config") >= (int)sizeof pdir
        || snprintf(pmid, sizeof pmid, "vendor/.car%s", "go/config") >= (int)sizeof pmid) {
        regfree(&re);
        return die("z23-lint: selftest buffer overflow\n", "");
    }
    int bad = want("check_c23_only", &re, "cc -std=c23 main.c", 0)
            | want("check_c23_only", &re, cg, 1)
            | want("check_c23_only", &re, lr, 1)
            | want("check_c23_only", &re, wr, 1)
            | !c23_path_hit("pkg/Cargo.toml")
            | !c23_path_hit("x/Cargo.lock")
            | !c23_path_hit("x/build.rs")
            | !c23_path_hit("tools/zz_probe.rs")
            | !c23_path_hit(pdir)
            | !c23_path_hit(pmid)
            | c23_path_hit("tools/foo.c")
            | c23_path_hit("Cargo.tomlx")
            | !c23_skip_ref("contexts/wallet/domain/src/mnemonic.c")
            | !c23_skip_ref("core/modules/sapling/src/circuit_gadgets.c")
            | c23_skip_ref("tools/foo.c");
    regfree(&re);
    return st_ok(bad, "check_c23_only selftest: OK\n");
}

/* check-no-api-keys: tracked-file credential shapes. Prefixes are split so
 * this translation unit is not itself a hit. */
static int nak_fill_pat(char *pat, size_t cap)
{
    return ovf(snprintf(pat, cap, "%s%s%s%s%s%s%s%s",
        "(^|[^[:alnum:]_])" "s" "k-" "[A-Za-z0-9_-]{20,}|",
        "(^|[^[:alnum:]_])" "x" "ai-" "[A-Za-z0-9_-]{20,}|",
        "(^|[^[:alnum:]_])" "g" "sk_" "[A-Za-z0-9_-]{20,}|",
        "(^|[^[:alnum:]_])" "g" "hp_" "[A-Za-z0-9_-]{20,}|",
        "(^|[^[:alnum:]_])" "g" "lpat-" "[A-Za-z0-9_-]{20,}|",
        "(^|[^[:alnum:]_])" "A" "KIA" "[A-Z0-9]{16}|",
        "Bearer[[:space:]]+[A-Za-z0-9._-]{24,}|",
        "[0-9a-f]{32,}\\.[A-Za-z0-9]{16,}"), cap);
}

static int nak_comp(regex_t *re)
{
    /* POSIX ERE boundaries also work with macOS's default regex mode. */
    char pat[512];
    int rc = nak_fill_pat(pat, sizeof pat);
    return rc ? rc : reg_fail(re, regcomp(re, pat, REG_EXTENDED));
}

static int nak_skip_path(const char *path)
{
    static const char *const ext[] = {
        ".png", ".jpg", ".gz", ".xz", ".zip", ".pdf", ".ico", ".bin", ".dat"
    };
    if (!strcmp(path, "tools/lint/check_no_api_keys.sh")) return 1;
    if (!strncmp(path, "vendor/", 7)) return 1;
    if (!strncmp(path, "tests/harness/fuzz_seeds/", 25)) return 1;
    for (size_t i = 0; i < sizeof ext / sizeof ext[0]; i++)
        if (c23_ends(path, ext[i])) return 1;
    return 0;
}

static int nak_has(const char *s, size_t n, const char *needle)
{
    size_t m = strlen(needle);
    if (m == 0 || m > n) return 0;
    for (size_t i = 0; i + m <= n; i++)
        if (memcmp(s + i, needle, m) == 0) return 1;
    return 0;
}

struct nak_acc { regex_t *re; FILE *hits; int nfiles, nhits; };

static int nak_scan_file(const char *path, struct nak_acc *a)
{
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        lineno++;
        if (n > 0 && line[n - 1] == '\n') line[--n] = '\0';
        if (nak_has(line, (size_t)n, "api-key-example-ok")) continue;
        for (ssize_t i = 0; i < n; i++)
            if (line[i] == '\0') line[i] = ' ';
        if (n <= 0 || regexec(a->re, line, 0, NULL, 0) != 0) continue;
        a->nhits++;
        if (a->nhits > 20) continue;
        if (fprintf(a->hits, "%s:%d:", path, lineno) < 0) {
            rc = die("z23-lint: write failed\n", "");
            break;
        }
        for (ssize_t i = 0; i < n; i++) {
            unsigned char c = (unsigned char)line[i];
            if (c == '\0') continue;
            if (fputc(c, a->hits) == EOF) {
                rc = die("z23-lint: write failed\n", "");
                break;
            }
        }
        if (rc) break;
        if (fputc('\n', a->hits) == EOF) {
            rc = die("z23-lint: write failed\n", "");
            break;
        }
    }
    return fin(f, line, path, rc);
}

static int nak_on_track(const char *path, void *ctx)
{
    struct nak_acc *a = ctx;
    if (nak_skip_path(path)) return 0;
    a->nfiles++;
    return nak_scan_file(path, a);
}

static int nak_scan_env(const char *env, struct nak_acc *a)
{
    const char *p = env;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\n') p++;
        if (!*p) break;
        const char *start = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
        size_t n = (size_t)(p - start);
        char path[4096];
        if (n >= sizeof path)
            return die("z23-lint: path too long: %s\n", "ZCL_API_KEY_SCAN_FILES");
        memcpy(path, start, n);
        path[n] = '\0';
        a->nfiles++;
        int rc = nak_scan_file(path, a);
        if (rc) return rc;
    }
    return 0;
}

static int nak_too_few(int nfiles, int floor)
{
    if (nfiles >= floor) return 0;
    if (fprintf(stderr,
                "check_no_api_keys: FATAL — scanned %d files (floor %d).\n",
                nfiles, floor) < 0
        || fputs("check_no_api_keys: a broken scan is never reported as clean.\n",
                 stderr) < 0)
        return die("z23-lint: write failed\n", "");
    return 2;
}

static int nak_replay20(FILE *hits)
{
    if (fseek(hits, 0, SEEK_SET) != 0) return die("z23-lint: fseek failed\n", "");
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int shown = 0, rc = 0;
    while (shown < 20 && (n = getline(&line, &cap, hits)) >= 0) {
        if (fwrite(line, 1, (size_t)n, stdout) != (size_t)n) {
            rc = die("z23-lint: write failed\n", "");
            break;
        }
        shown++;
    }
    int err = ferror(hits);
    free(line);
    return rc ? rc : (err ? die("z23-lint: read failed\n", "") : 0);
}

static int nak_finish(struct nak_acc *a, int floor)
{
    int rc = nak_too_few(a->nfiles, floor);
    if (rc) return rc;
    if (a->nhits) {
        if (fputs("[check_no_api_keys] a credential-shaped string is in a tracked file:\n",
                  stdout) < 0)
            return die("z23-lint: write failed\n", "");
        rc = nak_replay20(a->hits);
        if (rc) return rc;
        if (fputs("[check_no_api_keys] a key in this tree is SPENT — it is in the history,\n"
                  "[check_no_api_keys] on every clone, and on every mirror. Rotate it, then\n"
                  "[check_no_api_keys] keep the replacement in the environment or in a 0600\n"
                  "[check_no_api_keys] file outside the repository (see engine/engine_secret.h).\n"
                  "[check_no_api_keys] For a documented non-credential, append the marker\n"
                  "[check_no_api_keys] api-key-example-ok to the line.\n", stdout) < 0)
            return die("z23-lint: write failed\n", "");
        return 1;
    }
    return printf("[check_no_api_keys] 0 violation(s) across %d file(s) (mode: FAIL)\n",
                  a->nfiles) < 0 ? die("z23-lint: write failed\n", "") : 0;
}

int check_no_api_keys_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    regex_t re;
    int cr = nak_comp(&re);
    if (cr) return cr;
    FILE *hits = tmpfile();
    if (!hits) {
        regfree(&re);
        return die("z23-lint: tmpfile failed\n", "");
    }
    struct nak_acc a = { .re = &re, .hits = hits };
    const char *env = getenv("ZCL_API_KEY_SCAN_FILES");
    int floor = 1000, rc;
    if (env && env[0]) {
        floor = 1;
        rc = nak_scan_env(env, &a);
    } else {
        rc = each_zpath(k_ls_all, nak_on_track, &a);
    }
    if (rc == 0) rc = nak_finish(&a, floor);
    fclose(hits);
    regfree(&re);
    return rc;
}

static int nak_want(const regex_t *re, const char *s, int w)
{
    int got = (strstr(s, "api-key-example-ok") == NULL)
           && (regexec(re, s, 0, NULL, 0) == 0);
    if (got != w) {
        fprintf(stderr, "check_no_api_keys selftest: want %d: %s\n", w, s);
        return 1;
    }
    return 0;
}

int check_no_api_keys_selftest(void)
{
    regex_t re;
    int cr = nak_comp(&re);
    if (cr) return cr;
    char sk[48], xai[48], gsk[48], ghp[48], glp[56], akia[40];
    char br[64], dig[80], okm[80], sha[48], shortsk[40];
    if (snprintf(sk, sizeof sk, "%s%s", "s" "k-", "abcdefghijklmnopqrst") >= (int)sizeof sk
        || snprintf(xai, sizeof xai, "%s%s", "x" "ai-", "abcdefghijklmnopqrst") >= (int)sizeof xai
        || snprintf(gsk, sizeof gsk, "%s%s", "g" "sk_", "abcdefghijklmnopqrst") >= (int)sizeof gsk
        || snprintf(ghp, sizeof ghp, "%s%s", "g" "hp_", "abcdefghijklmnopqrst") >= (int)sizeof ghp
        || snprintf(glp, sizeof glp, "%s%s", "g" "lpat-", "abcdefghijklmnopqrst") >= (int)sizeof glp
        || snprintf(akia, sizeof akia, "%s%s", "A" "KIA", "ABCDEFGHIJKLMNOP") >= (int)sizeof akia
        || snprintf(br, sizeof br, "Bearer %s", "abcdefghijklmnopqrstuvwx") >= (int)sizeof br
        || snprintf(dig, sizeof dig, "%s.%s", "0123456789abcdef0123456789abcdef",
                    "abcdefghijklmnop") >= (int)sizeof dig
        || snprintf(okm, sizeof okm, "%s api-key-example-ok", sk) >= (int)sizeof okm
        || snprintf(sha, sizeof sha, "%s",
                    "0123456789abcdef0123456789abcdef01234567") >= (int)sizeof sha
        || snprintf(shortsk, sizeof shortsk, "%s%s", "s" "k-",
                    "abcdefghijklmnopqrs") >= (int)sizeof shortsk) {
        regfree(&re);
        return die("z23-lint: selftest buffer overflow\n", "");
    }
    int bad = nak_want(&re, sk, 1) | nak_want(&re, xai, 1) | nak_want(&re, gsk, 1)
            | nak_want(&re, ghp, 1) | nak_want(&re, glp, 1) | nak_want(&re, akia, 1)
            | nak_want(&re, br, 1) | nak_want(&re, dig, 1)
            | nak_want(&re, okm, 0) | nak_want(&re, sha, 0) | nak_want(&re, shortsk, 0)
            | nak_want(&re, "cc -std=c23 main.c", 0)
            | (nak_too_few(0, 1) != 2) | (nak_too_few(1, 1) != 0)
            | (nak_too_few(999, 1000) != 2)
            | !nak_skip_path("vendor/foo.c")
            | !nak_skip_path("tests/harness/fuzz_seeds/x.bin")
            | !nak_skip_path("docs/x.png")
            | nak_skip_path("tools/lint/lintc/main.c")
            | nak_skip_path("tools/lint/lintc/lib.c")
            | nak_skip_path("tools/lint/lintc/gate_ratchet_ports.c");
    const char *const tokens[] = { sk, xai, gsk, ghp, glp, akia };
    static const struct { const char *prefix; int want; } boundaries[] = {
        { "", 1 }, { "\"", 1 }, { " ", 1 }, { "=", 1 },
        { "a", 0 }, { "0", 0 }, { "_", 0 }
    };
    for (size_t i = 0; i < sizeof tokens / sizeof tokens[0]; i++) {
        for (size_t j = 0; j < sizeof boundaries / sizeof boundaries[0]; j++) {
            char sample[80];
            if (ovf(snprintf(sample, sizeof sample, "%s%s",
                             boundaries[j].prefix, tokens[i]), sizeof sample)) {
                regfree(&re);
                return die("z23-lint: selftest boundary buffer overflow\n", "");
            }
            bad |= nak_want(&re, sample, boundaries[j].want);
        }
    }
    regfree(&re);
    return st_ok(bad, "check_no_api_keys selftest: OK\n");
}

static int edr_skip_path(const char *path)
{
    if (!strncmp(path, "tests/harness/", 14)) return 1;
    return !(c23_ends(path, ".c") || c23_ends(path, ".h"));
}

static int edr_word(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
        || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '/' || c == '-';
}

static int edr_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static int edr_resolves(const char *tok)
{
    if (edr_exists(tok)) return 1;
    const char *base = strrchr(tok, '/');
    base = base ? base + 1 : tok;
    char p[4096];
    int n = snprintf(p, sizeof p, "docs/%s", base);
    if (ovf(n, sizeof p)) return 0;
    if (edr_exists(p)) return 1;
    n = snprintf(p, sizeof p, "docs/work/%s", base);
    if (ovf(n, sizeof p)) return 0;
    return edr_exists(p);
}

static int edr_tok_end_md(const char *tok)
{
    size_t n = strlen(tok);
    if (n < 3 || memcmp(tok + n - 3, ".md", 3) != 0) return 0;
    if (n == 3) return 0;
    if (n >= 4 && memcmp(tok + n - 4, "/.md", 4) == 0) return 0;
    return 1;
}

static int edr_lit_skip(const char *s, const char *e)
{
    for (const char *p = s; p < e; p++) {
        if (*p == '*') return 1;
        if (*p == '%' && (p + 1) < e) {
            char n = p[1];
            if (n == 's' || n == 'd' || n == 'l' || n == 'z') return 1;
        }
    }
    return 0;
}

static int edr_line(const char *file, int lineno, char *line, FILE *out, int *violations)
{
    if (!strstr(line, ".md")) return 0;
    if (strstr(line, "// error-doc-ref-ok:")) return 0;
    for (char *p = line; *p; p++) {
        if (*p != '"') continue;
        char *start = p + 1;
        char *end = start;
        while (*end && *end != '"') end++;
        if (!*end) break;
        p = end;
        int has_md = 0;
        for (char *q = start; q < end; q++)
            if (q + 2 < end && q[0] == '.' && q[1] == 'm' && q[2] == 'd') has_md = 1;
        if (!has_md || edr_lit_skip(start, end)) continue;
        char *q = start;
        while (q < end) {
            while (q < end && !edr_word((unsigned char)*q)) q++;
            if (q >= end) break;
            char *tok = q;
            while (q < end && edr_word((unsigned char)*q)) q++;
            char saved = *q;
            *q = '\0';
            if (edr_tok_end_md(tok) && !edr_resolves(tok)) {
                (*violations)++;
                if (out && fprintf(out, "  %s:%d names a document that does not exist: %s\n",
                                   file, lineno, tok) < 0) {
                    *q = saved;
                    return die("z23-lint: write failed\n", "");
                }
            }
            *q = saved;
        }
    }
    return 0;
}

static int edr_scan_file(const char *path, int *violations)
{
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        lineno++;
        if (n > 0 && line[n - 1] == '\n') line[n - 1] = '\0';
        rc = edr_line(path, lineno, line, stdout, violations);
        if (rc) break;
    }
    return fin(f, line, path, rc);
}

static int edr_on_track(const char *path, void *ctx)
{
    int *violations = ctx;
    if (edr_skip_path(path)) return 0;
    return edr_scan_file(path, violations);
}

static int edr_fail(int n)
{
    if (printf("\ncheck_error_doc_refs: FAIL — %d operator-facing reference(s) to a missing document\n"
               "\n"
               "An error message that names a document the reader cannot open is worse\n"
               "than one that names nothing: it spends a round trip and it costs the\n"
               "error surface its credibility. Either write the document, or replace the\n"
               "reference with a command you have actually run.\n"
               "\n"
               "If the path is genuinely produced at runtime, append\n"
               "  // error-doc-ref-ok:<reason>\n"
               "to the line.\n", n) < 0)
        return die("z23-lint: write failed\n", "");
    return 1;
}

int check_error_doc_refs_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    int violations = 0;
    int rc = each_zpath(k_ls_all, edr_on_track, &violations);
    if (rc) return rc;
    if (violations) return edr_fail(violations);
    return fputs("check_error_doc_refs: clean — every document named in a C string literal exists\n",
                 stdout) < 0 ? die("z23-lint: write failed\n", "") : 0;
}

int check_error_doc_refs_selftest(void)
{
    char real[] = "const char *p = \"AGENTS.md\";";
    char miss[] = "const char *p = \"lintc11-no-such.md\";";
    char conv[] = "const char *p = \"lintc11-no-such-%s.md\";";
    char mark[] = "const char *p = \"lintc11-no-such.md\"; // error-doc-ref-ok:runtime";
    char docs[] = "const char *p = \"GETTING_STARTED.md\";";
    int v = 0, bad = 0;
    FILE *out = tmpfile();
    if (!out) return die("z23-lint: tmpfile failed\n", "");
    bad |= edr_line("tools/t.c", 1, real, out, &v) != 0 || v != 0;
    v = 0;
    bad |= edr_line("tools/t.c", 3, miss, out, &v) != 0 || v != 1;
    v = 0;
    bad |= edr_line("tools/t.c", 4, conv, out, &v) != 0 || v != 0;
    v = 0;
    bad |= edr_line("tools/t.c", 5, mark, out, &v) != 0 || v != 0;
    v = 0;
    bad |= edr_line("tools/t.c", 6, docs, out, &v) != 0 || v != 0;
    bad |= !edr_skip_path("tests/harness/foo.c")
        || !edr_skip_path("tests/harness/include/test/x.h")
        || edr_skip_path("tools/t.c")
        || !edr_skip_path("docs/x." "md");
    fclose(out);
    if (bad)
        fputs("FAIL: check_error_doc_refs selftest\n", stderr);
    return st_ok(bad, "check_error_doc_refs selftest: OK\n");
}

enum { FFS_OWN_N = 7, FFS_VMAX = 1024, FFS_VLEN = 384 };
static const struct { const char *folder; const char *suffix; } k_ffs_own[] = {
    { "controllers", "controller" },
    { "services", "service" },
    { "models", "model" },
    { "views", "view" },
    { "jobs", "job" },
    { "supervisors", "supervisor" },
    { "conditions", "condition" },
};
static const char *const k_ffs_all[] = {
    "controller", "service", "model", "view", "job", "supervisor", "condition"
};

static const char *ffs_own_suffix(const char *folder)
{
    for (size_t i = 0; i < sizeof k_ffs_own / sizeof k_ffs_own[0]; i++)
        if (strcmp(k_ffs_own[i].folder, folder) == 0)
            return k_ffs_own[i].suffix;
    return NULL;
}

static int ffs_in_shapes(const char *folder, const char shapes[][RS_NAME], int n)
{
    for (int i = 0; i < n; i++)
        if (strcmp(shapes[i], folder) == 0)
            return 1;
    return 0;
}

static const char *ffs_foreign_shape(const char *b, const char *own)
{
    for (size_t i = 0; i < sizeof k_ffs_all / sizeof k_ffs_all[0]; i++) {
        const char *shape = k_ffs_all[i];
        if (strcmp(shape, own) == 0)
            continue;
        size_t sl = strlen(shape), bl = strlen(b);
        if (bl >= sl + 1 && b[bl - sl - 1] == '_' && strcmp(b + bl - sl, shape) == 0)
            return shape;
    }
    return NULL;
}

static int ffs_marker_comp(regex_t *re)
{
    return compile_pat(re, REG_EXTENDED,
                       "//[[:space:]]*suffix", "-ok:[A-Za-z0-9][A-Za-z0-9_-]*",
                       "", "");
}

static int ffs_buf_has_marker(const char *text, const regex_t *re)
{
    const char *p = text;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        char line[4096];
        if (n < sizeof line) {
            memcpy(line, p, n);
            line[n] = '\0';
            if (regexec(re, line, 0, NULL, 0) == 0)
                return 1;
        }
        if (!nl)
            break;
        p = nl + 1;
    }
    return 0;
}

static int ffs_file_has_marker(const char *path, const regex_t *re, int *hit)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        *hit = 0;
        return 0;
    }
    char *line = NULL;
    size_t cap = 0;
    *hit = 0;
    while (!*hit && getline(&line, &cap, f) >= 0)
        if (regexec(re, line, 0, NULL, 0) == 0)
            *hit = 1;
    return fin(f, line, path, 0);
}

static int ffs_scan_room(const char *d, const char *own, const regex_t *re,
                         char v[][FFS_VLEN], int *nv)
{
    char src[4096];
    if (ovf(snprintf(src, sizeof src, "%s/src", d), sizeof src))
        return 2;
    struct dirent **names = NULL;
    int n = scandir(src, &names, NULL, alphasort);
    if (n < 0)
        return (errno == ENOENT || errno == ENOTDIR) ? 0
            : die("z23-lint: cannot scan %s\n", src);
    int rc = 0;
    for (int i = 0; i < n; i++) {
        const char *name = names[i]->d_name;
        if (rc == 0 && strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
            char path[4096];
            struct stat st;
            size_t nl = strlen(name);
            int k = snprintf(path, sizeof path, "%s/%s", src, name);
            if (k < 0 || (size_t)k >= sizeof path)
                rc = die("z23-lint: path too long: %s\n", src);
            else if (lstat(path, &st) != 0)
                rc = die("z23-lint: cannot stat %s\n", path);
            else if (S_ISREG(st.st_mode) && nl >= 2
                     && name[nl - 2] == '.' && name[nl - 1] == 'c') {
                char b[256];
                if (nl - 2 >= sizeof b)
                    rc = die("z23-lint: derived buffer overflow\n", "");
                else {
                    memcpy(b, name, nl - 2);
                    b[nl - 2] = '\0';
                    int marked = 0;
                    rc = ffs_file_has_marker(path, re, &marked);
                    if (rc == 0 && !marked) {
                        const char *shape = ffs_foreign_shape(b, own);
                        if (shape) {
                            if (*nv >= FFS_VMAX)
                                rc = die("z23-lint: derived buffer overflow\n", "");
                            else if (ovf(snprintf(v[*nv], FFS_VLEN,
                                    "%s ends in foreign-shape suffix _%s "
                                    "(this folder's shape: %s)",
                                    path, shape, own), FFS_VLEN))
                                rc = 2;
                            else
                                (*nv)++;
                        }
                    }
                }
            }
        }
        free(names[i]);
    }
    free(names);
    return rc;
}

int check_framework_filename_suffix_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    int rc = rs_init();
    if (rc)
        return rc;
    for (int i = 0; i < g_n_shapes; i++) {
        if (ffs_own_suffix(g_shapes[i]))
            continue;
        fprintf(stderr, "check_framework_filename_suffix: FATAL — Makefile APP_DIRS has\n");
        fprintf(stderr, "  '%s' but the OWN[] suffix map has no entry for it.\n",
                g_shapes[i]);
        fprintf(stderr, "  Add its singular suffix; leaving it out silently exempts the\n");
        fprintf(stderr, "  whole app/%s/ tree from this gate.\n", g_shapes[i]);
        return 2;
    }
    for (size_t i = 0; i < sizeof k_ffs_own / sizeof k_ffs_own[0]; i++) {
        if (ffs_in_shapes(k_ffs_own[i].folder, g_shapes, g_n_shapes))
            continue;
        fprintf(stderr, "check_framework_filename_suffix: FATAL — OWN[] has '%s'\n",
                k_ffs_own[i].folder);
        fprintf(stderr, "  but the Makefile's APP_DIRS does not declare it.\n");
        return 2;
    }
    regex_t re;
    rc = ffs_marker_comp(&re);
    if (rc)
        return rc;
    static char viol[FFS_VMAX][FFS_VLEN];
    int nv = 0;
    char rooms[RS_MAX][RS_PATH];
    for (size_t i = 0; rc == 0 && i < sizeof k_ffs_own / sizeof k_ffs_own[0]; i++) {
        int nr = 0;
        rc = repo_shape_room_dirs(k_ffs_own[i].folder, rooms, RS_MAX, &nr);
        for (int r = 0; rc == 0 && r < nr; r++)
            rc = ffs_scan_room(rooms[r], k_ffs_own[i].suffix, &re, viol, &nv);
    }
    regfree(&re);
    if (rc)
        return rc;
    if (nv == 0)
        return puts("check_framework_filename_suffix: clean — no shape file carries a "
                    "foreign-shape filename suffix") < 0
                   ? die("z23-lint: write failed\n", "") : 0;
    if (printf("\ncheck_framework_filename_suffix: %d foreign-shape filename suffix "
               "violation(s)\n\n", nv) < 0)
        return die("z23-lint: write failed\n", "");
    for (int i = 0; i < nv; i++)
        if (printf("  %s\n", viol[i]) < 0)
            return die("z23-lint: write failed\n", "");
    if (fputs("\nFix options:\n"
              "  1. Rename the file to its own shape's suffix or a bare entity name.\n"
              "  2. Move it to the folder whose shape its suffix names.\n"
              "  3. If the entity name legitimately ends in that shape word, add a\n"
              "     top-of-file marker '// suffix-ok:<tag>' explaining why.\n",
              stdout) < 0)
        return die("z23-lint: write failed\n", "");
    return 1;
}

int check_framework_filename_suffix_selftest(void)
{
    regex_t re;
    int cr = ffs_marker_comp(&re);
    if (cr)
        return cr;
    int bad = 0;
    const char *shape = ffs_foreign_shape("foo_controller", "service");
    bad |= !(shape && strcmp(shape, "controller") == 0);
    bad |= ffs_foreign_shape("foo_service", "service") != NULL;
    bad |= ffs_foreign_shape("block", "model") != NULL;
    const char *marked = "/* header */\nint x;\n// suffix-ok:file_service\n";
    bad |= !ffs_buf_has_marker(marked, &re);
    bad |= ffs_buf_has_marker("int x;\nvoid f(void) {}\n", &re);
    bad |= !(ffs_buf_has_marker(marked, &re)
             && ffs_foreign_shape("file_service", "model") != NULL);
    char full[FFS_OWN_N][RS_NAME];
    for (int i = 0; i < FFS_OWN_N; i++)
        memcpy(full[i], k_ffs_own[i].folder, strlen(k_ffs_own[i].folder) + 1);
    int cover_own = 1, cover_shapes = 1;
    for (int i = 0; i < FFS_OWN_N; i++)
        if (!ffs_in_shapes(k_ffs_own[i].folder, full, FFS_OWN_N))
            cover_own = 0;
    for (int i = 0; i < FFS_OWN_N; i++)
        if (!ffs_own_suffix(full[i]))
            cover_shapes = 0;
    bad |= !cover_own || !cover_shapes;
    char miss[FFS_OWN_N][RS_NAME];
    for (int i = 0; i < FFS_OWN_N - 1; i++)
        memcpy(miss[i], k_ffs_own[i].folder, strlen(k_ffs_own[i].folder) + 1);
    int miss_cover = 1;
    for (int i = 0; i < FFS_OWN_N; i++)
        if (!ffs_in_shapes(k_ffs_own[i].folder, miss, FFS_OWN_N - 1))
            miss_cover = 0;
    bad |= miss_cover;
    char extra[FFS_OWN_N + 1][RS_NAME];
    for (int i = 0; i < FFS_OWN_N; i++)
        memcpy(extra[i], k_ffs_own[i].folder, strlen(k_ffs_own[i].folder) + 1);
    memcpy(extra[FFS_OWN_N], "widgets", 8);
    int extra_cover = 1;
    for (int i = 0; i < FFS_OWN_N + 1; i++)
        if (!ffs_own_suffix(extra[i]))
            extra_cover = 0;
    bad |= extra_cover;
    regfree(&re);
    return st_ok(bad, "check_framework_filename_suffix selftest: OK\n");
}
