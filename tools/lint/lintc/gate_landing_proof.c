/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — proof/landing/receipt-shaped lint gates of the C23
 * lint runtime (check-core-seal-root-mirror, check-peer-floor-single-source,
 * check-proof-server-pin, check-stopwatch-skip-detector).
 */

/*
 * Gates: check-core-seal-root-mirror, check-peer-floor-single-source, check-proof-server-pin, check-stopwatch-skip-detector
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


static const char k_csr_mirror[] =
    "engine/modules/hotswap/include/hotswap/core_seal_root.h";
static const char k_csr_mod[] =
    "engine/modules/hotswap/include/hotswap/hotswap_module.h";
static const char k_csr_act[] = "engine/modules/hotswap/src/hotswap_activate.c";
static const char k_csr_gen[] = "tools/scripts/gen_core_seal_root.sh";

static int csr_note(FILE *out, const char *msg)
{
    return fprintf(out, "  %s\n", msg) < 0 ? die("z23-lint: write failed\n", "") : 0;
}

static int csr_bad(FILE *err, int *fail, const char *msg)
{
    *fail = 1;
    return fprintf(err, "core_seal_root_mirror: FAIL — %s\n", msg) < 0
               ? die("z23-lint: write failed\n", "") : 0;
}

static int csr_readable(const char *path)
{
    return access(path, R_OK) == 0;
}

static int csr_file_pred(const char *path, int (*pred)(const char *), int *found)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        *found = 0;
        return 0;
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    *found = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        if (pred(line)) {
            *found = 1;
            break;
        }
    }
    return fin(f, line, path, rc);
}

static int csr_has_include(const char *line)
{
    static const char p[] = "#include \"" "hotswap/core_seal_root.h" "\"";
    return strncmp(line, p, sizeof p - 1) == 0;
}

static int csr_has_pin(const char *line)
{
    return strstr(line, "zcl_hotswap_module_core_seal_root" "[] = "
                        "ZCL_CORE_SEAL_ROOT;") != NULL;
}

static int csr_count_sub(const char *path, const char *needle, int *count)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        *count = 0;
        return 0;
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    *count = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[--n] = '\0';
        for (ssize_t i = 0; i < n; i++)
            if (line[i] == '\0')
                line[i] = ' ';
        if (strstr(line, needle))
            (*count)++;
    }
    return fin(f, line, path, rc);
}

static int csr_count_re(const char *path, const regex_t *re, int *count)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        *count = 0;
        return 0;
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    *count = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[--n] = '\0';
        for (ssize_t i = 0; i < n; i++)
            if (line[i] == '\0')
                line[i] = ' ';
        if (regexec(re, line, 0, NULL, 0) == 0)
            (*count)++;
    }
    return fin(f, line, path, rc);
}

static int csr_comp_dlsym(regex_t *re)
{
    return compile_pat(re, REG_EXTENDED,
                       "dl" "sym\\(handle,($|[[:space:]]",
                       "ZCL_HOTSWAP_MODULE_SYMBOL\\))", "", "");
}

static int csr_footer(FILE *err)
{
    if (fputs("core_seal_root_mirror: the hot-swap consensus pin is broken.\n", err) < 0
        || fputs("  A module built against a different sealed consensus core carries its own\n",
                 err) < 0
        || fputs("  stale copy of the inline consensus arithmetic. The pin is what refuses it.\n",
                 err) < 0)
        return die("z23-lint: write failed\n", "");
    return 1;
}

static int csr_check_files(FILE *err, int *fail)
{
    static const char *const files[] = {
        k_csr_mirror, k_csr_mod, k_csr_act, k_csr_gen
    };
    int rc = 0;
    for (size_t i = 0; i < sizeof files / sizeof files[0]; i++) {
        if (csr_readable(files[i]))
            continue;
        char msg[4096];
        if (ovf(snprintf(msg, sizeof msg, "%s is missing or unreadable", files[i]),
                sizeof msg))
            return 2;
        rc = csr_bad(err, fail, msg);
        if (rc) return rc;
    }
    if (*fail)
        return 1;
    return 0;
}

static int csr_check_gen(FILE *out, FILE *err, int *fail)
{
    char cmd[256], genout[8192], note[8192];
    if (ovf(snprintf(cmd, sizeof cmd, "bash %s --check 2>&1", k_csr_gen), sizeof cmd))
        return 2;
    int code = 0;
    int rc = capture_cmd(cmd, genout, sizeof genout, &code);
    if (rc)
        return rc;
    if (code == 0) {
        const char pfx[] = "core_seal_root: ";
        const char *rest = strncmp(genout, pfx, sizeof pfx - 1) == 0
                               ? genout + (sizeof pfx - 1) : genout;
        if (ovf(snprintf(note, sizeof note, "current  : %s", rest), sizeof note))
            return 2;
        rc = csr_note(out, note);
        if (rc) return rc;
    } else {
        if (fprintf(err, "%s\n", genout) < 0)
            return die("z23-lint: write failed\n", "");
        rc = csr_bad(err, fail,
                     "the mirror does not match core/MANIFEST.sha3 (run 'make core-seal')");
        if (rc) return rc;
    }
    return 0;
}

static int csr_check_include(FILE *out, FILE *err, int *fail)
{
    char note[8192], msg[4096];
    int found = 0;
    int rc = csr_file_pred(k_csr_mod, csr_has_include, &found);
    if (rc)
        return rc;
    if (found) {
        if (ovf(snprintf(note, sizeof note, "exported : %s includes the mirror", k_csr_mod),
                sizeof note))
            return 2;
        rc = csr_note(out, note);
        if (rc) return rc;
    } else {
        if (ovf(snprintf(msg, sizeof msg,
                         "%s does not include \"hotswap/core_seal_root.h\" — "
                         "modules would compile without a pin", k_csr_mod),
                sizeof msg))
            return 2;
        rc = csr_bad(err, fail, msg);
        if (rc) return rc;
    }
    return 0;
}

static int csr_check_pin_symbol(FILE *out, FILE *err, int *fail)
{
    char msg[4096];
    int found = 0;
    int rc = csr_file_pred(k_csr_mod, csr_has_pin, &found);
    if (rc)
        return rc;
    if (found) {
        rc = csr_note(out, "exported : the module emitter stamps the pin symbol");
        if (rc) return rc;
    } else {
        if (ovf(snprintf(msg, sizeof msg,
                         "%s's ZCL_HOTSWAP_MODULE_LEAVES does not emit "
                         "zcl_hotswap_module_core_seal_root", k_csr_mod),
                sizeof msg))
            return 2;
        rc = csr_bad(err, fail, msg);
        if (rc) return rc;
    }
    return 0;
}

static int csr_check_enforced(FILE *out, FILE *err, int *fail, int *enforced)
{
    char note[8192], msg[4096];
    int rc = csr_count_sub(k_csr_act, "module_consensus_pin_ok(", enforced);
    if (rc)
        return rc;
    if (*enforced >= 3) {
        if (ovf(snprintf(note, sizeof note,
                         "enforced : %s checks the pin on %d dlsym path(s)",
                         k_csr_act, *enforced - 1),
                sizeof note))
            return 2;
        rc = csr_note(out, note);
        if (rc) return rc;
    } else {
        if (ovf(snprintf(msg, sizeof msg,
                         "%s has %d module_consensus_pin_ok reference(s); "
                         "expected a definition plus a call on BOTH dlsym paths",
                         k_csr_act, *enforced),
                sizeof msg))
            return 2;
        rc = csr_bad(err, fail, msg);
        if (rc) return rc;
    }
    return 0;
}

static int csr_check_dlsym(FILE *err, int *fail, int enforced)
{
    char msg[4096];
    regex_t dlre;
    int rc = csr_comp_dlsym(&dlre);
    if (rc)
        return rc;
    int sites = 0;
    rc = csr_count_re(k_csr_act, &dlre, &sites);
    regfree(&dlre);
    if (rc)
        return rc;
    if (sites != enforced - 1) {
        if (ovf(snprintf(msg, sizeof msg,
                         "%s resolves %d zcl_hotswap_module symbol(s) but pins %d; "
                         "every dlsym path must carry the check",
                         k_csr_act, sites, enforced - 1),
                sizeof msg))
            return 2;
        rc = csr_bad(err, fail, msg);
        if (rc) return rc;
    }
    return 0;
}

static int csr_check(FILE *out, FILE *err)
{
    int fail = 0, rc = 0;
    rc = csr_check_files(err, &fail);
    if (rc) return rc;
    rc = csr_check_gen(out, err, &fail);
    if (rc) return rc;
    rc = csr_check_include(out, err, &fail);
    if (rc) return rc;
    rc = csr_check_pin_symbol(out, err, &fail);
    if (rc) return rc;
    int enforced = 0;
    rc = csr_check_enforced(out, err, &fail, &enforced);
    if (rc) return rc;
    rc = csr_check_dlsym(err, &fail, enforced);
    if (rc) return rc;
    if (fail)
        return csr_footer(err);
    return fputs("core_seal_root_mirror: OK — pin current, exported by the module "
                 "emitter, enforced on every dlsym path\n", out) < 0
               ? die("z23-lint: write failed\n", "") : 0;
}

int check_core_seal_root_mirror_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return csr_check(stdout, stderr);
}

static int csr_plant_act(const char *path)
{
    char body[512];
    int n = snprintf(body, sizeof body,
                     "static bool module_consensus_pin_ok(void *h) { (void)h; return 1; }\n"
                     "void mount(void *handle) {\n"
                     "    (void)dl" "sym(handle, ZCL_HOTSWAP_MODULE_SYMBOL);\n"
                     "    module_consensus_pin_ok(handle);\n"
                     "}\n"
                     "void verify(void *handle) {\n"
                     "    (void)dl" "sym(handle,\n"
                     "    module_consensus_pin_ok(handle);\n"
                     "}\n");
    if (ovf(n, sizeof body))
        return 2;
    return csr_write(path, body);
}

static int csr_plant_mod(const char *path, int with_include)
{
    char body[256];
    int n;
    if (with_include)
        n = snprintf(body, sizeof body,
                     "#include \"" "hotswap/core_seal_root.h" "\"\n"
                     "const char zcl_hotswap_module_core_seal_root" "[] = "
                     "ZCL_CORE_SEAL_ROOT;\n");
    else
        n = snprintf(body, sizeof body,
                     "const char zcl_hotswap_module_core_seal_root" "[] = "
                     "ZCL_CORE_SEAL_ROOT;\n");
    if (ovf(n, sizeof body))
        return 2;
    return csr_write(path, body);
}

static int csr_plant_base(void)
{
    int rc = csr_write(k_csr_mirror, "/* fixture mirror */\n");
    if (rc == 0)
        rc = csr_plant_act(k_csr_act);
    if (rc == 0)
        rc = csr_write(k_csr_gen, "echo \"core_seal_root: OK — fixture\"\nexit 0\n");
    return rc;
}

static int lp_rewind2(FILE *out, FILE *err)
{
    rewind(out); rewind(err);
    return ftruncate(fileno(out), 0) != 0 || ftruncate(fileno(err), 0) != 0;
}

static int lp_slurp2(FILE *out, FILE *err, char *ob, size_t oc, char *eb, size_t ec)
{
    return csr_slurp(out, ob, oc) || csr_slurp(err, eb, ec);
}

/* SCENARIO GROUP: empty tree — every pin file is missing or unreadable. */
static int csr_st_missing(FILE *out, FILE *err, char *ob, size_t oc, char *eb, size_t ec)
{
    int rc = csr_check(out, err);
    int bad = lp_slurp2(out, err, ob, oc, eb, ec);
    bad |= rc != 1
        || strstr(eb, "core_seal_root_mirror: FAIL — ") == NULL
        || strstr(eb, " is missing or unreadable") == NULL;
    return bad;
}

/* SCENARIO GROUP: planted tree without the module include. */
static int csr_st_no_include(FILE *out, FILE *err, char *ob, size_t oc, char *eb, size_t ec)
{
    int bad = lp_rewind2(out, err);
    if (csr_plant_base() || csr_plant_mod(k_csr_mod, 0))
        bad = 1;
    int rc = csr_check(out, err);
    bad |= lp_slurp2(out, err, ob, oc, eb, ec);
    bad |= rc != 1
        || strstr(eb, "does not include \"hotswap/core_seal_root.h\"") == NULL;
    return bad;
}

/* SCENARIO GROUP: planted tree with include — clean pin. */
static int csr_st_clean(FILE *out, FILE *err, char *ob, size_t oc, char *eb, size_t ec)
{
    int bad = lp_rewind2(out, err);
    if (csr_plant_mod(k_csr_mod, 1))
        bad = 1;
    int rc = csr_check(out, err);
    bad |= lp_slurp2(out, err, ob, oc, eb, ec);
    bad |= rc != 0
        || strstr(ob, "core_seal_root_mirror: OK — pin current, exported by the "
                      "module emitter, enforced on every dlsym path") == NULL;
    return bad;
}

int check_core_seal_root_mirror_selftest(void)
{
    char cwd[4096];
    if (!getcwd(cwd, sizeof cwd))
        return die("z23-lint: getcwd failed\n", "");
    char tmpl[] = "/tmp/z23-lint-csr-XXXXXX";
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdir failed: %s\n", "/tmp");
    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err) {
        if (out) fclose(out);
        if (err) fclose(err);
        rmdir(root);
        return die("z23-lint: tmpfile failed\n", "");
    }
    char ob[4096], eb[4096];
    if (chdir(root) != 0) {
        fclose(out); fclose(err); rmdir(root);
        return die("z23-lint: cannot scan %s\n", root);
    }

    int bad = csr_st_missing(out, err, ob, sizeof ob, eb, sizeof eb);
    bad |= csr_st_no_include(out, err, ob, sizeof ob, eb, sizeof eb);
    bad |= csr_st_clean(out, err, ob, sizeof ob, eb, sizeof eb);

    fclose(out);
    fclose(err);
    unlink(k_csr_mirror);
    unlink(k_csr_mod);
    unlink(k_csr_act);
    unlink(k_csr_gen);
    (void)rmdir("engine/modules/hotswap/include/hotswap");
    (void)rmdir("engine/modules/hotswap/include");
    (void)rmdir("engine/modules/hotswap/src");
    (void)rmdir("engine/modules/hotswap");
    (void)rmdir("engine/modules");
    (void)rmdir("engine");
    (void)rmdir("tools/scripts");
    (void)rmdir("tools");
    if (chdir(cwd) != 0)
        return die("z23-lint: cannot scan %s\n", cwd);
    rmdir(root);
    if (bad)
        fputs("FAIL: check_core_seal_root_mirror selftest\n", stderr);
    return st_ok(bad, "check_core_seal_root_mirror selftest: OK\n");
}

static const char k_pf_hdr[] = "core/modules/net/include/net/net.h";
static const char *const k_pf_sites[] = {
    "core/modules/net/src/connman.c",
    "engine/supervisors/src/net_supervisor.c",
    "engine/conditions/src/peer_floor_violated.c",
};
/* Production C roots — "lib app config domain" were dead (renamed away),
 * so this gate's extra-definition scan only ever reached core/ and tools/,
 * missing engine/contexts/cognition/platform where a stray redefinition of
 * ZCL_PEER_FLOOR_HEALTHY would have gone undetected. */
static const char *const k_pf_walk_roots[] = {
    "core", "engine", "contexts", "cognition", "platform", "tools"
};

static int pf_comp_banned(regex_t *re)
{
    char pat[256];
    int n = snprintf(pat, sizeof pat, "%s%s%s%s",
                     "^[[:space:]]*#[[:space:]]*define[[:space:]]+(",
                     "PEER_FLOOR_MIN|PEER_FLOOR_MIN_HEALTHY|",
                     "PEER_FLOOR_TARGET|OUTBOUND_HEALTHY_FLOOR)",
                     "[[:space:]]+[0-9]");
    if (ovf(n, sizeof pat))
        return 2;
    return reg_fail(re, regcomp(re, pat, REG_EXTENDED));
}

static int pf_comp_def(regex_t *re)
{
    char pat[160];
    int n = snprintf(pat, sizeof pat, "%s%s%s",
                     "^[[:space:]]*#[[:space:]]*define[[:space:]]+",
                     "ZCL_" "PEER_FLOOR_HEALTHY",
                     "[[:space:]]+[0-9]");
    if (ovf(n, sizeof pat))
        return 2;
    return reg_fail(re, regcomp(re, pat, REG_EXTENDED));
}

static int pf_comp_ref(regex_t *re)
{
    char pat[160];
    int n = snprintf(pat, sizeof pat, "%s%s%s",
                     "(^|[^[:alnum:]_])",
                     "ZCL_" "PEER_FLOOR_HEALTHY",
                     "([^[:alnum:]_]|$)");
    if (ovf(n, sizeof pat))
        return 2;
    return reg_fail(re, regcomp(re, pat, REG_EXTENDED));
}

static int pf_count_re(const char *path, const regex_t *re, int *count)
{
    return csr_count_re(path, re, count);
}

static int pf_file_has_re(const char *path, const regex_t *re)
{
    int n = 0;
    if (pf_count_re(path, re, &n))
        return 0;
    return n > 0;
}

enum { PF_MAX = 128, PF_NAME = 256 };
struct pf_tree { char p[PF_MAX][PF_NAME]; int n; const regex_t *re; };

static int pf_path_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static int pf_add(struct pf_tree *t, const char *path)
{
    size_t n = strlen(path);
    if (t->n >= PF_MAX || n >= PF_NAME)
        return die("z23-lint: derived buffer overflow\n", "");
    memcpy(t->p[t->n], path, n + 1);
    t->n++;
    return 0;
}

static int pf_walk(const char *dir, struct pf_tree *t)
{
    struct dirent **names = NULL;
    int n = scandir(dir, &names, NULL, alphasort);
    if (n < 0)
        return 0;
    int rc = 0;
    for (int i = 0; i < n; i++) {
        const char *name = names[i]->d_name;
        if (rc == 0 && strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
            char path[4096];
            struct stat st;
            int k = snprintf(path, sizeof path, "%s/%s", dir, name);
            if (k < 0 || (size_t)k >= sizeof path)
                rc = die("z23-lint: path too long: %s\n", dir);
            else if (lstat(path, &st) != 0)
                rc = 0;
            else if (S_ISDIR(st.st_mode))
                rc = pf_walk(path, t);
            else if (S_ISREG(st.st_mode) && pf_file_has_re(path, t->re))
                rc = pf_add(t, path);
        }
        free(names[i]);
    }
    free(names);
    return rc;
}

/* Measured 2026-09-06 under the production roots (.c+.h): 4337 files.
 * Independent of pf_walk's own extra-definition regex, so a root that
 * exists but is scanned near-empty still trips even though
 * require_scan_root() alone would not catch it. */
enum { PF_SCAN_FLOOR = 4000 };

static int pf_scan_floor_check(const char *const *roots, size_t nroots)
{
    int nfiles = 0;
    int rc = walk_count_roots("check-peer-floor-single-source", roots, nroots,
                              1, &nfiles);
    if (rc == 0)
        rc = gate_require_scanned(nfiles, PF_SCAN_FLOOR,
                                  "check-peer-floor-single-source",
                                  "scanned far fewer .c/.h files than expected "
                                  "under the production roots");
    return rc;
}

/* Combines "does every configured root exist" with "did we actually reach
 * the expected file count under them" into one call, kept separate from
 * check_peer_floor_single_source_run so that function's own decision count
 * stays under the complexity gate's cap. */
static int pf_root_floor_check(const char *const *roots, size_t nroots)
{
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < nroots; i++)
        rc = require_scan_root("check-peer-floor-single-source", roots[i]);
    if (rc == 0)
        rc = pf_scan_floor_check(roots, nroots);
    return rc;
}

static int pf_is_reg(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static int pf_selftest_mode(const char *f, FILE *out, FILE *err)
{
    if (!f || !f[0] || !pf_is_reg(f)) {
        if (fprintf(err,
                    "check_peer_floor_single_source: FATAL — selftest file missing: '%s'\n",
                    f ? f : "") < 0)
            return die("z23-lint: write failed\n", "");
        return 2;
    }
    regex_t re;
    int cr = pf_comp_banned(&re);
    if (cr)
        return cr;
    int hit = pf_file_has_re(f, &re);
    regfree(&re);
    if (hit) {
        if (fprintf(out,
                    "check_peer_floor_single_source: selftest TRIP — banned floor literal in %s\n",
                    f) < 0)
            return die("z23-lint: write failed\n", "");
        return 1;
    }
    if (fprintf(out,
                "check_peer_floor_single_source: selftest CLEAN — no banned floor literal in %s\n",
                f) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int pf_scan_banned_lines(const char *path, const regex_t *re, FILE *err)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0, any = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        lineno++;
        if (n > 0 && line[n - 1] == '\n')
            line[--n] = '\0';
        for (ssize_t i = 0; i < n; i++)
            if (line[i] == '\0')
                line[i] = ' ';
        if (regexec(re, line, 0, NULL, 0) != 0)
            continue;
        if (!any) {
            if (fprintf(err,
                        "check_peer_floor_single_source: FAIL — %s reintroduces a "
                        "retired floor literal macro:\n", path) < 0) {
                rc = die("z23-lint: write failed\n", "");
                break;
            }
            any = 1;
        }
        if (fprintf(err, "    %d:%s\n", lineno, line) < 0) {
            rc = die("z23-lint: write failed\n", "");
            break;
        }
    }
    int fr = fin(f, line, path, rc);
    if (fr)
        return fr;
    if (any) {
        if (fprintf(err, "    Use ZCL_" "PEER_FLOOR_HEALTHY from %s instead.\n",
                    k_pf_hdr) < 0)
            return die("z23-lint: write failed\n", "");
        return 1;
    }
    return 0;
}

/* SCAN STAGE: expected header and floor sites exist as regular files. */
static int pf_require_files(void)
{
    if (!pf_is_reg(k_pf_hdr)) {
        fprintf(stderr,
                "check_peer_floor_single_source: FATAL — expected file missing: %s\n",
                k_pf_hdr);
        return 2;
    }
    for (size_t i = 0; i < sizeof k_pf_sites / sizeof k_pf_sites[0]; i++) {
        if (pf_is_reg(k_pf_sites[i]))
            continue;
        fprintf(stderr,
                "check_peer_floor_single_source: FATAL — expected file missing: %s\n",
                k_pf_sites[i]);
        return 2;
    }
    return 0;
}

/* SCAN STAGE: compile the definition, reference, and banned-literal regexes. */
static int pf_compile_all(regex_t *def, regex_t *ref, regex_t *banned)
{
    int cr = pf_comp_def(def);
    if (cr)
        return cr;
    cr = pf_comp_ref(ref);
    if (cr) {
        regfree(def);
        return cr;
    }
    cr = pf_comp_banned(banned);
    if (cr) {
        drop2(def, ref);
        return cr;
    }
    return 0;
}

/* SCAN STAGE: ZCL_PEER_FLOOR_HEALTHY is #define'd exactly once in the header. */
static int pf_check_single_def(const regex_t *def, int *fail)
{
    int def_count = 0;
    int rc = pf_count_re(k_pf_hdr, def, &def_count);
    if (rc)
        return rc;
    if (def_count != 1) {
        if (fprintf(stderr,
                    "check_peer_floor_single_source: FAIL — ZCL_"
                    "PEER_FLOOR_HEALTHY must be #define'd exactly once (as a number) "
                    "in %s (found %d)\n", k_pf_hdr, def_count) < 0)
            return die("z23-lint: write failed\n", "");
        *fail = 1;
    }
    return 0;
}

static void pf_uniq_paths(struct pf_tree *tree)
{
    if (tree->n > 1)
        qsort(tree->p, (size_t)tree->n, sizeof tree->p[0], pf_path_cmp);
    int uniq = 0;
    for (int i = 0; i < tree->n; i++) {
        if (i && strcmp(tree->p[i], tree->p[i - 1]) == 0)
            continue;
        if (uniq != i)
            memcpy(tree->p[uniq], tree->p[i], PF_NAME);
        uniq++;
    }
    tree->n = uniq;
}

static int pf_report_defs(const struct pf_tree *tree, int *fail)
{
    if (tree->n == 1)
        return 0;
    if (fprintf(stderr,
                "check_peer_floor_single_source: FAIL — ZCL_"
                "PEER_FLOOR_HEALTHY defined in %d files (expected 1):\n",
                tree->n) < 0)
        return die("z23-lint: write failed\n", "");
    if (tree->n == 0) {
        if (fputs("    \n", stderr) < 0)
            return die("z23-lint: write failed\n", "");
    } else {
        for (int i = 0; i < tree->n; i++) {
            if (fprintf(stderr, "    %s\n", tree->p[i]) < 0)
                return die("z23-lint: write failed\n", "");
        }
    }
    *fail = 1;
    return 0;
}

/* SCAN STAGE: unique extra-definition walk under the production roots. */
static int pf_scan_extra_defs(const regex_t *def, int *fail)
{
    struct pf_tree tree = { .re = def };
    int rc = pf_root_floor_check(k_pf_walk_roots,
                                 sizeof k_pf_walk_roots / sizeof k_pf_walk_roots[0]);
    for (size_t i = 0; rc == 0 && i < sizeof k_pf_walk_roots / sizeof k_pf_walk_roots[0]; i++)
        rc = pf_walk(k_pf_walk_roots[i], &tree);
    if (rc)
        return rc;
    pf_uniq_paths(&tree);
    return pf_report_defs(&tree, fail);
}

/* SCAN STAGE: each floor site references the symbol and has no banned literal. */
static int pf_scan_sites(const regex_t *ref, const regex_t *banned, int *fail,
                         int *total_refs)
{
    int rc = 0;
    for (size_t i = 0; i < sizeof k_pf_sites / sizeof k_pf_sites[0]; i++) {
        int refs = 0;
        rc = pf_count_re(k_pf_sites[i], ref, &refs);
        if (rc) return rc;
        *total_refs += refs;
        if (refs < 1) {
            if (fprintf(stderr,
                        "check_peer_floor_single_source: FAIL — %s does not reference "
                        "ZCL_" "PEER_FLOOR_HEALTHY (re-hardcoded floor?)\n",
                        k_pf_sites[i]) < 0)
                return die("z23-lint: write failed\n", "");
            *fail = 1;
        }
        int br = pf_scan_banned_lines(k_pf_sites[i], banned, stderr);
        if (br == 2)
            return 2;
        if (br == 1)
            *fail = 1;
    }
    return 0;
}

/* SCAN STAGE: refuse a clean report when wiring drifted. */
static int pf_finish(int fail, int total_refs)
{
    if (total_refs < 1) {
        fputs("check_peer_floor_single_source: FATAL — zero ZCL_"
              "PEER_FLOOR_HEALTHY references across all floor sites; the wiring "
              "drifted (refusing to report clean)\n", stderr);
        return 2;
    }
    if (fail) {
        fputs("check_peer_floor_single_source: the healthy-outbound floor has "
              "drifted from its single source of truth.\n", stderr);
        return 1;
    }
    return printf("[check_peer_floor_single_source] OK — ZCL_"
                  "PEER_FLOOR_HEALTHY defined once in %s and read by all %d floor "
                  "references across %zu sites\n",
                  k_pf_hdr, total_refs,
                  sizeof k_pf_sites / sizeof k_pf_sites[0]) < 0
               ? die("z23-lint: write failed\n", "") : 0;
}

int check_peer_floor_single_source_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    const char *st = getenv("ZCL_PEER_FLOOR_SELFTEST");
    if (st && strcmp(st, "1") == 0)
        return pf_selftest_mode(getenv("ZCL_PEER_FLOOR_SELFTEST_FILE"),
                                stdout, stderr);

    int rc = pf_require_files();
    if (rc) return rc;
    regex_t def, ref, banned;
    rc = pf_compile_all(&def, &ref, &banned);
    if (rc) return rc;
    int fail = 0;
    rc = pf_check_single_def(&def, &fail);
    if (rc) {
        drop3(&def, &ref, &banned);
        return rc;
    }
    rc = pf_scan_extra_defs(&def, &fail);
    if (rc) {
        drop3(&def, &ref, &banned);
        return rc;
    }
    int total_refs = 0;
    rc = pf_scan_sites(&ref, &banned, &fail, &total_refs);
    drop3(&def, &ref, &banned);
    if (rc) return rc;
    return pf_finish(fail, total_refs);
}

/* SCENARIO GROUP: missing selftest file is FATAL. */
static int pf_st_missing(FILE *out, FILE *err, char *ob, size_t oc, char *eb, size_t ec)
{
    char miss[64];
    miss[0] = '\0';
    int rc = pf_selftest_mode(miss, out, err);
    int bad = lp_slurp2(out, err, ob, oc, eb, ec);
    bad |= rc != 2
        || strstr(eb, "check_peer_floor_single_source: FATAL — selftest file missing: ''") == NULL;
    return bad;
}

/* SCENARIO GROUP: banned floor literal trips. */
static int pf_st_trip(FILE *out, FILE *err, const char *trip, char *ob, size_t oc,
                      char *eb, size_t ec)
{
    int bad = lp_rewind2(out, err);
    int rc = pf_selftest_mode(trip, out, err);
    bad |= lp_slurp2(out, err, ob, oc, eb, ec);
    bad |= rc != 1 || strstr(ob, "selftest TRIP — banned floor literal in ") == NULL
        || strstr(ob, trip) == NULL;
    return bad;
}

/* SCENARIO GROUP: healthy-floor reference is clean. */
static int pf_st_clean(FILE *out, FILE *err, const char *clean, char *ob, size_t oc,
                       char *eb, size_t ec)
{
    int bad = lp_rewind2(out, err);
    int rc = pf_selftest_mode(clean, out, err);
    bad |= lp_slurp2(out, err, ob, oc, eb, ec);
    bad |= rc != 0 || strstr(ob, "selftest CLEAN — no banned floor literal in ") == NULL
        || strstr(ob, clean) == NULL;
    return bad;
}

int check_peer_floor_single_source_selftest(void)
{
    char tmpl[] = "/tmp/z23-lint-pf-XXXXXX";
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdir failed: %s\n", "/tmp");
    char trip[256], clean[256], ob[512], eb[512];
    int n = snprintf(trip, sizeof trip, "%s/trip.c", root);
    if (ovf(n, sizeof trip))
        return 2;
    n = snprintf(clean, sizeof clean, "%s/clean.c", root);
    if (ovf(n, sizeof clean))
        return 2;
    FILE *tf = fopen(trip, "w"), *cf = fopen(clean, "w");
    if (!tf || !cf) {
        if (tf) fclose(tf);
        if (cf) fclose(cf);
        rmdir(root);
        return die("z23-lint: cannot open %s\n", root);
    }
    fputs("#define PEER_FLOOR_MIN 3\n", tf);
    fputs("int x = ZCL_" "PEER_FLOOR_HEALTHY;\n", cf);
    fclose(tf);
    fclose(cf);

    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err) {
        if (out) fclose(out);
        if (err) fclose(err);
        unlink(trip); unlink(clean); rmdir(root);
        return die("z23-lint: tmpfile failed\n", "");
    }
    int bad = pf_st_missing(out, err, ob, sizeof ob, eb, sizeof eb);
    bad |= pf_st_trip(out, err, trip, ob, sizeof ob, eb, sizeof eb);
    bad |= pf_st_clean(out, err, clean, ob, sizeof ob, eb, sizeof eb);

    fclose(out);
    fclose(err);
    unlink(trip);
    unlink(clean);
    rmdir(root);
    bad |= require_scan_root("check-peer-floor-single-source", "lib") == 0;
    if (bad)
        fputs("FAIL: check_peer_floor_single_source selftest\n", stderr);
    return st_ok(bad, "check_peer_floor_single_source selftest: OK\n");
}

static const char k_psp_pin[] = "tools/scripts/proof_server_pin.sh";
static const char k_psp_ship[] = "tools/ship.sh";

static int psp_has_pass_line(const char *buf)
{
    static const char want[] = "PROOF SERVER PIN SELF-TEST: PASS";
    size_t w = sizeof want - 1;
    const char *p = buf;
    for (;;) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        if (n == w && memcmp(p, want, w) == 0)
            return 1;
        if (!nl)
            return 0;
        p = nl + 1;
    }
}

static int psp_file_has_record(const char *path, int *has)
{
    regex_t re;
    int cr = compile_pat(&re, REG_EXTENDED,
                        "proof_server_pin" "\\.sh[[:space:]]+",
                        "record", "([^[:alnum:]_]|$)", "");
    if (cr)
        return cr;
    FILE *f = fopen(path, "r");
    if (!f) {
        *has = 0;
        regfree(&re);
        return 0;
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    *has = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        if (regexec(&re, line, 0, NULL, 0) == 0) {
            *has = 1;
            break;
        }
    }
    rc = fin(f, line, path, rc);
    regfree(&re);
    return rc;
}

static int psp_check_pin(FILE *out, int *fail)
{
    if (!csr_readable(k_psp_pin)) {
        if (fprintf(out,
                    "FAIL: %s is missing — the proof-server promotion has no recorder\n",
                    k_psp_pin) < 0)
            return die("z23-lint: write failed\n", "");
        *fail = 1;
        return 0;
    }
    char cmd[256], captured[8192];
    if (ovf(snprintf(cmd, sizeof cmd, "bash %s --self-test 2>&1", k_psp_pin),
            sizeof cmd))
        return 2;
    int code = 0;
    int rc = capture_cmd(cmd, captured, sizeof captured, &code);
    if (rc)
        return rc;
    if (code != 0 || !psp_has_pass_line(captured)) {
        if (fprintf(out,
                    "FAIL: %s --self-test (rc=%d; no 'PROOF SERVER PIN SELF-TEST: PASS' line)\n",
                    k_psp_pin, code) < 0)
            return die("z23-lint: write failed\n", "");
        if (fprintf(out, "%s\n", captured) < 0)
            return die("z23-lint: write failed\n", "");
        *fail = 1;
        return 0;
    }
    if (fprintf(out, "  ok: %s --self-test\n", k_psp_pin) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int psp_check_ship(FILE *out, int *fail)
{
    if (!csr_readable(k_psp_ship)) {
        if (fprintf(out, "FAIL: %s is missing\n", k_psp_ship) < 0)
            return die("z23-lint: write failed\n", "");
        *fail = 1;
        return 0;
    }
    int has = 0;
    int rc = psp_file_has_record(k_psp_ship, &has);
    if (rc)
        return rc;
    if (!has) {
        if (fputs("FAIL: tools/ship.sh no longer calls 'proof_server_pin.sh record' — the\n"
                  "      promotion path would go back to describing a binding it does\n"
                  "      not record. Wire the call back in after the remote health\n"
                  "      check confirms the running daemon reports the candidate's\n"
                  "      source id.\n", out) < 0)
            return die("z23-lint: write failed\n", "");
        *fail = 1;
        return 0;
    }
    if (fprintf(out, "  ok: %s calls 'proof_server_pin.sh record'\n",
               k_psp_ship) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int psp_check(FILE *out)
{
    int fail = 0, rc;
    rc = psp_check_pin(out, &fail);
    if (rc) return rc;
    rc = psp_check_ship(out, &fail);
    if (rc) return rc;
    if (fail)
        return 1;
    return fputs("check_proof_server_pin: clean — recorder self-test passes and "
                 "ship.sh still wires it into the promotion path\n", out) < 0
               ? die("z23-lint: write failed\n", "") : 0;
}

int check_proof_server_pin_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return psp_check(stdout);
}

/* SCENARIO GROUP: empty tree — recorder script is missing. */
static int psp_st_missing(FILE *out, char *ob, size_t oc)
{
    int rc = psp_check(out);
    int bad = 0;
    if (csr_slurp(out, ob, oc))
        bad = 1;
    bad |= rc != 1
        || strstr(ob, "FAIL: tools/scripts/proof_server_pin.sh is missing — "
                      "the proof-server promotion has no recorder") == NULL;
    return bad;
}

/* SCENARIO GROUP: pin self-test passes but ship.sh does not record. */
static int psp_st_no_record(FILE *out, char *ob, size_t oc)
{
    int bad = 0;
    if (psp_st_reset(out))
        bad = 1;
    if (csr_write(k_psp_pin, "echo PROOF SERVER PIN SELF-TEST: PASS\n")
        || csr_write(k_psp_ship,
                     "# mention record elsewhere\n"
                     "tools/scripts/proof_server_pin.sh check\n"))
        bad = 1;
    int rc = psp_check(out);
    if (csr_slurp(out, ob, oc))
        bad = 1;
    bad |= rc != 1
        || strstr(ob, "FAIL: tools/ship.sh no longer calls "
                      "'proof_server_pin.sh record' — the") == NULL;
    return bad;
}

/* SCENARIO GROUP: recorder and ship.sh record call — clean. */
static int psp_st_clean(FILE *out, char *ob, size_t oc)
{
    int bad = 0;
    if (psp_st_reset(out))
        bad = 1;
    if (csr_write(k_psp_ship,
                  "tools/scripts/proof_server_pin.sh record \"$HEAD_SHA\"\n"))
        bad = 1;
    int rc = psp_check(out);
    if (csr_slurp(out, ob, oc))
        bad = 1;
    bad |= rc != 0
        || strstr(ob, "check_proof_server_pin: clean — recorder self-test "
                      "passes and ship.sh still wires it into the promotion "
                      "path") == NULL;
    return bad;
}

int check_proof_server_pin_selftest(void)
{
    char cwd[4096];
    if (!getcwd(cwd, sizeof cwd))
        return die("z23-lint: getcwd failed\n", "");
    char tmpl[] = "/tmp/z23-lint-psp-XXXXXX";
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdir failed: %s\n", "/tmp");
    FILE *out = tmpfile();
    if (!out) {
        rmdir(root);
        return die("z23-lint: tmpfile failed\n", "");
    }
    char ob[4096];
    if (chdir(root) != 0) {
        fclose(out);
        rmdir(root);
        return die("z23-lint: cannot scan %s\n", root);
    }

    int bad = psp_st_missing(out, ob, sizeof ob);
    bad |= psp_st_no_record(out, ob, sizeof ob);
    bad |= psp_st_clean(out, ob, sizeof ob);

    fclose(out);
    unlink(k_psp_pin);
    unlink(k_psp_ship);
    (void)rmdir("tools/scripts");
    (void)rmdir("tools");
    if (chdir(cwd) != 0)
        return die("z23-lint: cannot scan %s\n", cwd);
    rmdir(root);
    if (bad)
        fputs("FAIL: check_proof_server_pin selftest\n", stderr);
    return st_ok(bad, "check_proof_server_pin selftest: OK\n");
}

static const char k_ssd_class[] = "tools/scripts/stopwatch_skip_class.sh";
static const char k_ssd_judge[] = "tools/scripts/stopwatch_evidence_judge.sh";
static const char k_ssd_def[] =
    "engine/services/include/services/stopwatch_skip_classes.def";
static const char k_ssd_table_cmd[] =
    "bash -c '. tools/scripts/stopwatch_skip_class.sh; stopwatch_skip_class_table' | grep -c '|'";

static int ssd_has_pass_line(const char *buf)
{
    static const char want[] = "selftest: PASS";
    size_t w = sizeof want - 1;
    const char *p = buf;
    for (;;) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        if (n == w && memcmp(p, want, w) == 0)
            return 1;
        if (!nl)
            return 0;
        p = nl + 1;
    }
}

static int ssd_run_selftest(FILE *out, const char *script, int *fail)
{
    if (!csr_readable(script)) {
        if (fprintf(out,
                    "FAIL: %s is missing — the skip-streak detector has no shell-side regression guard\n",
                    script) < 0)
            return die("z23-lint: write failed\n", "");
        *fail = 1;
        return 0;
    }
    char cmd[512];
    static char captured[262144];
    if (ovf(snprintf(cmd, sizeof cmd, "bash %s --selftest 2>&1", script),
            sizeof cmd))
        return 2;
    int code = 0;
    int rc = capture_cmd(cmd, captured, sizeof captured, &code);
    if (rc)
        return rc;
    if (code != 0 || !ssd_has_pass_line(captured)) {
        if (fprintf(out, "FAIL: %s --selftest (rc=%d; no 'selftest: PASS' line)\n",
                    script, code) < 0)
            return die("z23-lint: write failed\n", "");
        if (fprintf(out, "%s\n", captured) < 0)
            return die("z23-lint: write failed\n", "");
        *fail = 1;
        return 0;
    }
    if (fprintf(out, "  ok: %s --selftest\n", script) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int ssd_count_def(int *count)
{
    regex_t re;
    int cr = compile_pat(&re, REG_EXTENDED,
                         "^STOPWATCH_SKIP_(CLASS|FALLBACK)\\(", "", "", "");
    if (cr)
        return cr;
    FILE *f = fopen(k_ssd_def, "r");
    if (!f) {
        *count = 0;
        regfree(&re);
        return 0;
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    *count = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        if (regexec(&re, line, 0, NULL, 0) == 0)
            (*count)++;
    }
    rc = fin(f, line, k_ssd_def, rc);
    regfree(&re);
    return rc;
}

static int ssd_check(FILE *out)
{
    (void)setenv("LC_ALL", "C", 1);
    int fail = 0, rc;
    rc = ssd_run_selftest(out, k_ssd_class, &fail);
    if (rc)
        return rc;
    rc = ssd_run_selftest(out, k_ssd_judge, &fail);
    if (rc)
        return rc;

    int rows_in_file = 0;
    rc = ssd_count_def(&rows_in_file);
    if (rc)
        return rc;
    char parsed[64];
    int code = 0;
    rc = capture_cmd(k_ssd_table_cmd, parsed, sizeof parsed, &code);
    if (rc)
        return rc;
    /* The original enables `set -e` inside run_selftest, so a failing
     * table pipeline (missing script, grep -c of zero matches) aborts
     * before the row-count comparison. */
    if (code != 0)
        return 1;
    int rows_parsed = atoi(parsed);
    if (rows_in_file < 5 || rows_in_file != rows_parsed) {
        if (fprintf(out, "FAIL: %s has %d rows but the shell parser sees %d\n",
                    k_ssd_def, rows_in_file, rows_parsed) < 0)
            return die("z23-lint: write failed\n", "");
        if (fputs("      Every row must be ENTIRELY on one line — the parser is line-oriented.\n",
                  out) < 0)
            return die("z23-lint: write failed\n", "");
        fail = 1;
    } else if (fprintf(out,
                       "  ok: %s — %d class rows, parsed identically by the shell side\n",
                       k_ssd_def, rows_in_file) < 0) {
        return die("z23-lint: write failed\n", "");
    }
    if (fail)
        return 1;
    return fputs("check_stopwatch_skip_detector: clean — shell skip-streak detector selftests pass\n",
                 out) < 0
               ? die("z23-lint: write failed\n", "") : 0;
}

int check_stopwatch_skip_detector_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return ssd_check(stdout);
}

static const char k_ssd_class_ok[] =
    "stopwatch_skip_class_table() {\n"
    "echo 'a|'\n"
    "echo 'b|'\n"
    "echo 'c|'\n"
    "echo 'd|'\n"
    "echo 'e|'\n"
    "}\n"
    "if [ \"${1:-}\" = \"--selftest\" ]; then echo \"selftest: PASS\"; exit 0; fi\n";
static const char k_ssd_class_fail[] =
    "stopwatch_skip_class_table() {\n"
    "echo 'a|'\n"
    "}\n"
    "if [ \"${1:-}\" = \"--selftest\" ]; then echo \"selftest: FAIL\"; exit 1; fi\n";
static const char k_ssd_class_four[] =
    "stopwatch_skip_class_table() {\n"
    "echo 'a|'\n"
    "echo 'b|'\n"
    "echo 'c|'\n"
    "echo 'd|'\n"
    "}\n"
    "if [ \"${1:-}\" = \"--selftest\" ]; then echo \"selftest: PASS\"; exit 0; fi\n";
static const char k_ssd_judge_ok[] =
    "if [ \"${1:-}\" = \"--selftest\" ]; then echo \"selftest: PASS\"; exit 0; fi\n";
static const char k_ssd_def_five[] =
    "STOPWATCH_SKIP_CLASS(a, 1)\n"
    "STOPWATCH_SKIP_CLASS(b, 1)\n"
    "STOPWATCH_SKIP_CLASS(c, 1)\n"
    "STOPWATCH_SKIP_CLASS(d, 1)\n"
    "STOPWATCH_SKIP_FALLBACK(\"unclassified\", 2)\n";

/* SCENARIO GROUP: empty tree — skip-class script is missing. */
static int ssd_st_missing(FILE *out, char *ob, size_t oc)
{
    int rc = ssd_check(out);
    int bad = 0;
    if (csr_slurp(out, ob, oc))
        bad = 1;
    bad |= rc != 1
        || strstr(ob, "FAIL: tools/scripts/stopwatch_skip_class.sh is missing — "
                      "the skip-streak detector has no shell-side regression guard") == NULL;
    return bad;
}

/* SCENARIO GROUP: class script --selftest fails. */
static int ssd_st_class_fail(FILE *out, char *ob, size_t oc)
{
    int bad = 0;
    if (psp_st_reset(out))
        bad = 1;
    if (csr_write(k_ssd_class, k_ssd_class_fail)
        || csr_write(k_ssd_judge, k_ssd_judge_ok)
        || csr_write(k_ssd_def, k_ssd_def_five))
        bad = 1;
    int rc = ssd_check(out);
    if (csr_slurp(out, ob, oc))
        bad = 1;
    bad |= rc != 1
        || strstr(ob, "FAIL: tools/scripts/stopwatch_skip_class.sh --selftest (rc=") == NULL
        || strstr(ob, "no 'selftest: PASS' line)") == NULL;
    return bad;
}

/* SCENARIO GROUP: five def rows but the shell parser sees four. */
static int ssd_st_row_mismatch(FILE *out, char *ob, size_t oc)
{
    int bad = 0;
    if (psp_st_reset(out))
        bad = 1;
    if (csr_write(k_ssd_class, k_ssd_class_four))
        bad = 1;
    int rc = ssd_check(out);
    if (csr_slurp(out, ob, oc))
        bad = 1;
    bad |= rc != 1
        || strstr(ob, "FAIL: engine/services/include/services/stopwatch_skip_classes.def has 5 rows but the shell parser sees 4") == NULL;
    return bad;
}

/* SCENARIO GROUP: matching class table and def rows — clean. */
static int ssd_st_clean(FILE *out, char *ob, size_t oc)
{
    int bad = 0;
    if (psp_st_reset(out))
        bad = 1;
    if (csr_write(k_ssd_class, k_ssd_class_ok))
        bad = 1;
    int rc = ssd_check(out);
    if (csr_slurp(out, ob, oc))
        bad = 1;
    bad |= rc != 0
        || strstr(ob, "check_stopwatch_skip_detector: clean — shell skip-streak detector selftests pass") == NULL;
    return bad;
}

int check_stopwatch_skip_detector_selftest(void)
{
    char cwd[4096];
    if (!getcwd(cwd, sizeof cwd))
        return die("z23-lint: getcwd failed\n", "");
    char tmpl[] = "/tmp/z23-lint-ssd-XXXXXX";
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdir failed: %s\n", "/tmp");
    FILE *out = tmpfile();
    if (!out) {
        rmdir(root);
        return die("z23-lint: tmpfile failed\n", "");
    }
    char ob[4096];
    if (chdir(root) != 0) {
        fclose(out);
        rmdir(root);
        return die("z23-lint: cannot scan %s\n", root);
    }

    int bad = ssd_st_missing(out, ob, sizeof ob);
    bad |= ssd_st_class_fail(out, ob, sizeof ob);
    bad |= ssd_st_row_mismatch(out, ob, sizeof ob);
    bad |= ssd_st_clean(out, ob, sizeof ob);

    fclose(out);
    unlink(k_ssd_class);
    unlink(k_ssd_judge);
    unlink(k_ssd_def);
    (void)rmdir("engine/services/include/services");
    (void)rmdir("engine/services/include");
    (void)rmdir("engine/services");
    (void)rmdir("engine");
    (void)rmdir("tools/scripts");
    (void)rmdir("tools");
    if (chdir(cwd) != 0)
        return die("z23-lint: cannot scan %s\n", cwd);
    rmdir(root);
    if (bad)
        fputs("FAIL: check_stopwatch_skip_detector selftest\n", stderr);
    return st_ok(bad, "check_stopwatch_skip_detector selftest: OK\n");
}
