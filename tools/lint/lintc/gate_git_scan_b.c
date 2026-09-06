/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — git-tracked-enumeration lint gates of the C23 lint
 * runtime, half B (check-no-retired-agent-protocol,
 * check-no-warning-suppression, check-mind-owns-rebuild,
 * check-no-stray-untracked-source).
 */

/*
 * Gates: check-no-retired-agent-protocol, check-no-warning-suppression, check-mind-owns-rebuild, check-no-stray-untracked-source
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


static const char *const k_rap_drop[] = {
    "__builtin_memcpy",
    "memcpy_uses_blob_var",
    "memcpys",
    "memcpy",
    "numcpus",
};

static int rap_ci_pref(const char *s, const char *n)
{
    for (; *n; s++, n++) {
        if (!*s)
            return 0;
        if (tolower((unsigned char)*s) != tolower((unsigned char)*n))
            return 0;
    }
    return 1;
}

static void rap_strip_one(char *s, const char *needle)
{
    char *w = s, *r = s;
    size_t nlen = strlen(needle);
    while (*r) {
        if (rap_ci_pref(r, needle))
            r += nlen;
        else
            *w++ = *r++;
    }
    *w = '\0';
}

static int rap_has_tok(const char *s, const char *tok)
{
    size_t n = strlen(tok);
    for (const char *p = s; *p; p++) {
        size_t i = 0;
        for (; i < n && p[i]; i++) {
            if (tolower((unsigned char)p[i]) != tolower((unsigned char)tok[i]))
                break;
        }
        if (i == n)
            return 1;
    }
    return 0;
}

struct rap_acc {
    const char *root;
    const char *tok;
    FILE *out;
    int tracked;
    int regular;
    int path_violation;
};

static int rap_on_track(const char *path, void *ctx)
{
    struct rap_acc *a = ctx;
    a->tracked++;
    char full[8192];
    if (ovf(snprintf(full, sizeof full, "%s/%s", a->root, path), sizeof full))
        return 2;
    struct stat st;
    if (stat(full, &st) != 0 || !S_ISREG(st.st_mode))
        return 0;
    a->regular++;
    if (rap_has_tok(path, a->tok)) {
        if (fprintf(a->out, "FAIL: retired agent protocol in tracked path: %s\n",
                    path) < 0)
            return die("z23-lint: write failed\n", "");
        a->path_violation = 1;
    }
    return 0;
}

static int rap_filter(char *raw, const char *tok, FILE *out, int *hit)
{
    static char work[1024 * 1024];
    char *p = raw;
    while (*p) {
        char *nl = strchr(p, '\n');
        if (nl)
            *nl = '\0';
        if (ovf(snprintf(work, sizeof work, "%s", p), sizeof work))
            return 2;
        for (size_t i = 0; i < sizeof k_rap_drop / sizeof k_rap_drop[0]; i++)
            rap_strip_one(work, k_rap_drop[i]);
        if (rap_has_tok(work, tok)) {
            if (fprintf(out, "%s\n", work) < 0)
                return die("z23-lint: write failed\n", "");
            *hit = 1;
        }
        if (!nl)
            break;
        p = nl + 1;
    }
    return 0;
}

static int rap_git_cmd(const char *root, const char *rest, char *out, size_t cap,
                       int *code)
{
    char cmd[8192];
    if (strchr(root, '\''))
        return die("z23-lint: path too long: %s\n", root);
    if (ovf(snprintf(cmd, sizeof cmd, "git -C '%s' %s", root, rest), sizeof cmd))
        return 2;
    return capture_cmd(cmd, out, cap, code);
}

static int rap_scan(const char *root, FILE *out, FILE *err)
{
    char tok[4] = { 'm', 'c', 'p', 0 };
    char dump[64];
    int code = 0, rc;

    if (strchr(root, '\''))
        return die("z23-lint: path too long: %s\n", root);
    rc = rap_git_cmd(root, "rev-parse --is-inside-work-tree >/dev/null 2>&1",
                     dump, sizeof dump, &code);
    if (rc)
        return rc;
    if (code != 0) {
        if (fprintf(err,
                    "check_no_retired_agent_protocol: FATAL — '%s' is not a git worktree\n",
                    root) < 0)
            return die("z23-lint: write failed\n", "");
        return 2;
    }

    struct rap_acc a = { .root = root, .tok = tok, .out = out };
    char lscmd[8192];
    if (ovf(snprintf(lscmd, sizeof lscmd, "git -C '%s' ls-files -z", root),
            sizeof lscmd))
        return 2;
    rc = each_zpath(lscmd, rap_on_track, &a);
    if (rc)
        return rc;
    if (a.tracked == 0) {
        if (fputs("check_no_retired_agent_protocol: FATAL — tracked-file scan is empty\n",
                  err) < 0)
            return die("z23-lint: write failed\n", "");
        return 2;
    }
    if (a.regular == 0) {
        if (fputs("check_no_retired_agent_protocol: FATAL — no tracked regular files were scanned\n",
                  err) < 0)
            return die("z23-lint: write failed\n", "");
        return 2;
    }

    char greprest[64];
    if (ovf(snprintf(greprest, sizeof greprest, "grep -n -I -i -F '%s' -- .", tok),
            sizeof greprest))
        return 2;
    static char raw[4 * 1024 * 1024];
    rc = rap_git_cmd(root, greprest, raw, sizeof raw, &code);
    if (rc)
        return rc;
    if (code >= 2) {
        if (fprintf(err,
                    "check_no_retired_agent_protocol: FATAL — tracked-content scan failed (exit %d)\n",
                    code) < 0)
            return die("z23-lint: write failed\n", "");
        return 2;
    }
    int content_violation = 0;
    if (code == 0) {
        rc = rap_filter(raw, tok, out, &content_violation);
        if (rc)
            return rc;
    }
    if (a.path_violation || content_violation) {
        if (fputs("FAIL: retired agent protocol remains in tracked files.\n", out) < 0)
            return die("z23-lint: write failed\n", "");
        return 1;
    }
    if (fprintf(out,
                "  OK: %d tracked regular files contain no retired protocol token\n",
                a.regular) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

int check_no_retired_agent_protocol_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    if (fputs("══ LINT: retired agent protocol absent from tracked files ══\n",
              stdout) < 0)
        return die("z23-lint: write failed\n", "");
    char cwd[4096];
    const char *env = getenv("ZCL_RETIRED_PROTOCOL_ROOT");
    const char *root;
    if (env && env[0])
        root = env;
    else {
        if (!getcwd(cwd, sizeof cwd))
            return die("z23-lint: getcwd failed\n", "");
        root = cwd;
    }
    return rap_scan(root, stdout, stderr);
}

int check_no_retired_agent_protocol_selftest(void)
{
    char tok[4] = { 'm', 'c', 'p', 0 };
    char cap[4] = { 'M', 'c', 'p', 0 };
    char tmpl[] = "/tmp/z23-lint-rap-XXXXXX";
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdir failed: %s\n", "/tmp");
    FILE *out = tmpfile();
    if (!out) {
        (void)rap_rm_rf(root);
        return die("z23-lint: tmpfile failed\n", "");
    }
    const char *oldenv = getenv("ZCL_RETIRED_PROTOCOL_ROOT");
    char oldbuf[4096];
    int had_env = 0;
    if (oldenv) {
        if (ovf(snprintf(oldbuf, sizeof oldbuf, "%s", oldenv), sizeof oldbuf)) {
            fclose(out);
            (void)rap_rm_rf(root);
            return 2;
        }
        had_env = 1;
    }
    int bad = 0, rc = 0, code = 0;
    char dump[256], path[8192], body[128], addrest[256], nam[64];
    if (setenv("ZCL_RETIRED_PROTOCOL_ROOT", root, 1) != 0)
        bad = 1;
    rc = rap_git_cmd(root, "init -q", dump, sizeof dump, &code);
    if (rc || code != 0)
        bad = 1;

    if (ovf(snprintf(path, sizeof path, "%s/clean.c", root), sizeof path))
        bad = 1;
    else if (csr_write(path, "memcpy(buffer, source, length);\nnumcpus=4\n"))
        bad = 1;
    rc = rap_git_cmd(root, "add -- clean.c", dump, sizeof dump, &code);
    if (rc || code != 0)
        bad = 1;
    if (psp_st_reset(out))
        bad = 1;
    rc = rap_scan(root, out, stderr);
    if (rc != 0) {
        fputs("selftest: clean embedded substrings were rejected\n", stderr);
        bad = 1;
    }

    if (ovf(snprintf(path, sizeof path, "%s/untracked.txt", root), sizeof path)
        || ovf(snprintf(body, sizeof body, "Open%sClient\n", cap), sizeof body))
        bad = 1;
    else if (csr_write(path, body))
        bad = 1;
    if (psp_st_reset(out))
        bad = 1;
    rc = rap_scan(root, out, stderr);
    if (rc != 0) {
        fputs("selftest: untracked fixture entered the production scan\n", stderr);
        bad = 1;
    }

    rc = rap_git_cmd(root, "add -- untracked.txt", dump, sizeof dump, &code);
    if (rc || code != 0)
        bad = 1;
    if (psp_st_reset(out))
        bad = 1;
    rc = rap_scan(root, out, stderr);
    if (rc == 0) {
        fputs("selftest: tracked content violation was not detected\n", stderr);
        bad = 1;
    }
    rc = rap_git_cmd(root, "rm -q --cached untracked.txt", dump, sizeof dump, &code);
    if (rc || code != 0)
        bad = 1;
    if (ovf(snprintf(path, sizeof path, "%s/untracked.txt", root), sizeof path) == 0)
        unlink(path);

    if (ovf(snprintf(nam, sizeof nam, "old_%s_surface.txt", tok), sizeof nam)
        || ovf(snprintf(path, sizeof path, "%s/%s", root, nam), sizeof path)
        || ovf(snprintf(addrest, sizeof addrest, "add -- %s", nam), sizeof addrest))
        bad = 1;
    else if (csr_write(path, "clean body\n"))
        bad = 1;
    rc = rap_git_cmd(root, addrest, dump, sizeof dump, &code);
    if (rc || code != 0)
        bad = 1;
    if (psp_st_reset(out))
        bad = 1;
    rc = rap_scan(root, out, stderr);
    if (rc == 0) {
        fputs("selftest: tracked path violation was not detected\n", stderr);
        bad = 1;
    }

    fclose(out);
    if (had_env)
        (void)setenv("ZCL_RETIRED_PROTOCOL_ROOT", oldbuf, 1);
    else
        (void)unsetenv("ZCL_RETIRED_PROTOCOL_ROOT");
    (void)rap_rm_rf(root);
    if (bad)
        fputs("FAIL: check_no_retired_agent_protocol selftest\n", stderr);
    return st_ok(bad, "check_no_retired_agent_protocol selftest: OK\n");
}

static const char k_nws_self[] = "tools/lint/check_no_warning_suppression.sh";
static const char k_nws_ls[] =
    "ls-files -z -- Makefile makefile GNUmakefile '*.mk' '*.mak' '*.make' "
    "'*.c' '*.h' '*.sh'";

static int nws_comp(regex_t *flag, regex_t *pragma, regex_t *marker)
{
    char fp[96], pp[160], mp[64];
    if (ovf(snprintf(fp, sizeof fp, "-W" "no-(%s|%s)", "unused-result",
                     "stringop-overflow"), sizeof fp))
        return 2;
    if (ovf(snprintf(pp, sizeof pp,
                     "diagnostic[[:space:]]+ignored[[:space:]]+\"-W(%s|%s)",
                     "unused-result", "stringop-overflow"), sizeof pp))
        return 2;
    if (ovf(snprintf(mp, sizeof mp, "suppression-ok:[[:space:]]*[^[:space:]]"),
            sizeof mp))
        return 2;
    int e = regcomp(flag, fp, REG_EXTENDED);
    if (e)
        return reg_fail(flag, e);
    e = regcomp(pragma, pp, REG_EXTENDED);
    if (e) {
        regfree(flag);
        return reg_fail(pragma, e);
    }
    e = regcomp(marker, mp, REG_EXTENDED);
    if (e) {
        regfree(flag);
        regfree(pragma);
        return reg_fail(marker, e);
    }
    return 0;
}

static void nws_drop(regex_t *flag, regex_t *pragma, regex_t *marker)
{
    regfree(flag);
    regfree(pragma);
    regfree(marker);
}

struct nws_acc {
    const char *root;
    regex_t *flag, *pragma, *marker;
    FILE *hits;
    int scanned, nhits;
};

static int nws_on_track(const char *path, void *ctx)
{
    struct nws_acc *a = ctx;
    if (strncmp(path, "vendor/", 7) == 0 || strcmp(path, k_nws_self) == 0)
        return 0;
    char full[8192];
    if (ovf(snprintf(full, sizeof full, "%s/%s", a->root, path), sizeof full))
        return 2;
    struct stat st;
    if (stat(full, &st) != 0 || !S_ISREG(st.st_mode))
        return 0;
    a->scanned++;
    FILE *f = fopen(full, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", full);
    static char prev[65536];
    prev[0] = '\0';
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        lineno++;
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        if (regexec(a->flag, line, 0, NULL, 0) == 0
            || regexec(a->pragma, line, 0, NULL, 0) == 0) {
            if (regexec(a->marker, line, 0, NULL, 0) != 0
                && regexec(a->marker, prev, 0, NULL, 0) != 0) {
                if (fprintf(a->hits, "%s:%d:%s\n", path, lineno, line) < 0) {
                    rc = die("z23-lint: write failed\n", "");
                    break;
                }
                a->nhits++;
            }
        }
        if (ovf(snprintf(prev, sizeof prev, "%s", line), sizeof prev)) {
            rc = 2;
            break;
        }
    }
    return fin(f, line, full, rc);
}

static int nws_scan(const char *root, FILE *out, FILE *err)
{
    regex_t flag, pragma, marker;
    int cr = nws_comp(&flag, &pragma, &marker);
    if (cr)
        return cr;
    FILE *hits = tmpfile();
    if (!hits) {
        nws_drop(&flag, &pragma, &marker);
        return die("z23-lint: tmpfile failed\n", "");
    }
    if (strchr(root, '\'')) {
        fclose(hits);
        nws_drop(&flag, &pragma, &marker);
        return die("z23-lint: path too long: %s\n", root);
    }
    char cmd[8192];
    if (ovf(snprintf(cmd, sizeof cmd, "git -C '%s' %s", root, k_nws_ls),
            sizeof cmd)) {
        fclose(hits);
        nws_drop(&flag, &pragma, &marker);
        return 2;
    }
    struct nws_acc a = {
        .root = root, .flag = &flag, .pragma = &pragma, .marker = &marker,
        .hits = hits
    };
    int rc = each_zpath(cmd, nws_on_track, &a);
    if (rc) {
        fclose(hits);
        nws_drop(&flag, &pragma, &marker);
        return rc;
    }
    if (a.scanned < 1) {
        fclose(hits);
        nws_drop(&flag, &pragma, &marker);
        if (fputs("check_no_warning_suppression: FATAL — build-surface scan set is empty\n",
                  err) < 0)
            return die("z23-lint: write failed\n", "");
        return 2;
    }
    if (a.nhits) {
        if (fseek(hits, 0, SEEK_SET) != 0) {
            fclose(hits);
            nws_drop(&flag, &pragma, &marker);
            return die("z23-lint: fseek failed\n", "");
        }
        char *line = NULL;
        size_t cap = 0;
        ssize_t n;
        while ((n = getline(&line, &cap, hits)) >= 0) {
            if (n > 0 && line[n - 1] == '\n')
                line[n - 1] = '\0';
            if (fprintf(err, "FAIL: unmarked warning suppression — %s\n", line) < 0) {
                free(line);
                fclose(hits);
                nws_drop(&flag, &pragma, &marker);
                return die("z23-lint: write failed\n", "");
            }
        }
        free(line);
        fclose(hits);
        nws_drop(&flag, &pragma, &marker);
        if (fprintf(err,
                    "check_no_warning_suppression: FAIL — hits=%d scanned=%d\n",
                    a.nhits, a.scanned) < 0)
            return die("z23-lint: write failed\n", "");
        if (fprintf(err,
                    "  -W" "no-%s also disables [[nodiscard]] reporting; -W"
                    "no-%s hides\n",
                    "unused-result", "stringop-overflow") < 0)
            return die("z23-lint: write failed\n", "");
        if (fputs("  a memory-safety diagnostic. Delete the flag, or state the reason on the line above it:\n",
                  err) < 0)
            return die("z23-lint: write failed\n", "");
        if (fputs("      # suppression-ok: <why this build surface genuinely needs it>\n",
                  err) < 0)
            return die("z23-lint: write failed\n", "");
        return 1;
    }
    fclose(hits);
    nws_drop(&flag, &pragma, &marker);
    if (fprintf(out, "check_no_warning_suppression: clean — scanned=%d build surfaces\n",
                a.scanned) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int nws_fx_fail(const char *why)
{
    if (fprintf(stderr,
                "z23-lint: INTERNAL — check_no_warning_suppression fixture: %s\n",
                why) < 0)
        return die("z23-lint: write failed\n", "");
    return 3;
}

static int nws_fx_write(const char *path, const char *kind, const char *extra)
{
    char body[512];
    if (kind) {
        if (ovf(snprintf(body, sizeof body, "CFLAGS += -W" "no-%s%s", kind,
                         extra ? extra : "\n"), sizeof body))
            return 2;
        return csr_write(path, body);
    }
    return csr_write(path, extra);
}

static int nws_fixtures(void)
{
    char tmpl[] = "/tmp/z23-lint-nws-XXXXXX";
    char *tmp = mkdtemp(tmpl);
    if (!tmp)
        return die("z23-lint: mkdir failed: %s\n", "/tmp");
    FILE *cap = tmpfile();
    if (!cap) {
        (void)rap_rm_rf(tmp);
        return die("z23-lint: tmpfile failed\n", "");
    }
    char repo[4096], empty[4096], path[8192], body[512], ob[4096], dump[64];
    int code = 0, rc = 0, scan_rc = 0, bad = 0;
    if (ovf(snprintf(repo, sizeof repo, "%s/repo", tmp), sizeof repo)
        || ovf(snprintf(empty, sizeof empty, "%s/empty", tmp), sizeof empty))
        bad = 1;
    if (!bad
        && (csr_mkdirs(repo) || csr_mkdirs(empty)
            || ovf(snprintf(path, sizeof path, "%s/tools/lint", repo), sizeof path)
            || csr_mkdirs(path)
            || ovf(snprintf(path, sizeof path, "%s/vendor", repo), sizeof path)
            || csr_mkdirs(path)))
        bad = 1;
    if (!bad && (rap_git_cmd(repo, "init -q", dump, sizeof dump, &code) || code))
        bad = 1;
    if (!bad && (rap_git_cmd(empty, "init -q", dump, sizeof dump, &code) || code))
        bad = 1;
    if (!bad) {
        if (ovf(snprintf(path, sizeof path, "%s/Makefile", repo), sizeof path)
            || csr_write(path, "CFLAGS = -std=c23 -Wall -Wextra -Werror\n")
            || ovf(snprintf(path, sizeof path, "%s/a.c", repo), sizeof path)
            || csr_write(path, "int main(void){return 0;}\n")
            || ovf(snprintf(path, sizeof path, "%s/vendor/third_party.mk", repo),
                   sizeof path)
            || nws_fx_write(path, "unused-result", "\n"))
            bad = 1;
    }
    if (!bad
        && (rap_git_cmd(repo, "add Makefile a.c vendor/third_party.mk", dump,
                        sizeof dump, &code)
            || code))
        bad = 1;
    if (bad) {
        fclose(cap);
        (void)rap_rm_rf(tmp);
        return nws_fx_fail("could not plant detector fixture");
    }

    if (psp_st_reset(cap))
        bad = 1;
    scan_rc = nws_scan(repo, cap, cap);
    if (csr_slurp(cap, ob, sizeof ob))
        bad = 1;
    if (bad || scan_rc != 0 || strstr(ob, "check_no_warning_suppression: clean") == NULL) {
        fclose(cap);
        (void)rap_rm_rf(tmp);
        return nws_fx_fail("clean fixture rejected");
    }
    if (strstr(ob, "vendor/third_party.mk") != NULL) {
        fclose(cap);
        (void)rap_rm_rf(tmp);
        return nws_fx_fail("vendor/ must be out of scope");
    }

    if (ovf(snprintf(path, sizeof path, "%s/Makefile", repo), sizeof path)
        || ovf(snprintf(body, sizeof body,
                        "CFLAGS = -std=c23 -Wall -Wextra -Werror\n"
                        "CFLAGS += -W" "no-%s\n",
                        "unused-result"), sizeof body)
        || csr_write(path, body)) {
        fclose(cap);
        (void)rap_rm_rf(tmp);
        return nws_fx_fail("could not plant flag-form fixture");
    }
    if (psp_st_reset(cap))
        bad = 1;
    scan_rc = nws_scan(repo, cap, cap);
    if (csr_slurp(cap, ob, sizeof ob))
        bad = 1;
    if (bad || scan_rc != 1 || strstr(ob, "Makefile:2") == NULL) {
        fclose(cap);
        (void)rap_rm_rf(tmp);
        return nws_fx_fail("flag form did not trip Makefile:2");
    }

    if (ovf(snprintf(body, sizeof body,
                     "# suppression-ok:\nCFLAGS += -W" "no-%s\n",
                     "unused-result"), sizeof body)
        || csr_write(path, body)) {
        fclose(cap);
        (void)rap_rm_rf(tmp);
        return nws_fx_fail("could not plant empty-reason fixture");
    }
    if (psp_st_reset(cap))
        bad = 1;
    scan_rc = nws_scan(repo, cap, cap);
    if (csr_slurp(cap, ob, sizeof ob))
        bad = 1;
    if (bad || scan_rc != 1) {
        fclose(cap);
        (void)rap_rm_rf(tmp);
        return nws_fx_fail("empty-reason marker must not exempt");
    }

    if (ovf(snprintf(body, sizeof body,
                     "# suppression-ok: fixture proves the marker is honoured\n"
                     "CFLAGS += -W" "no-%s\n",
                     "unused-result"), sizeof body)
        || csr_write(path, body)) {
        fclose(cap);
        (void)rap_rm_rf(tmp);
        return nws_fx_fail("could not plant preceding-line fixture");
    }
    if (psp_st_reset(cap))
        bad = 1;
    scan_rc = nws_scan(repo, cap, cap);
    if (csr_slurp(cap, ob, sizeof ob))
        bad = 1;
    if (bad || scan_rc != 0) {
        fclose(cap);
        (void)rap_rm_rf(tmp);
        return nws_fx_fail("preceding-line marker not honoured");
    }

    if (ovf(snprintf(body, sizeof body,
                     "CFLAGS += -W" "no-%s  # suppression-ok: fixture\n",
                     "stringop-overflow"), sizeof body)
        || csr_write(path, body)) {
        fclose(cap);
        (void)rap_rm_rf(tmp);
        return nws_fx_fail("could not plant same-line fixture");
    }
    if (psp_st_reset(cap))
        bad = 1;
    scan_rc = nws_scan(repo, cap, cap);
    if (csr_slurp(cap, ob, sizeof ob))
        bad = 1;
    if (bad || scan_rc != 0) {
        fclose(cap);
        (void)rap_rm_rf(tmp);
        return nws_fx_fail("same-line marker not honoured");
    }

    if (csr_write(path, "CFLAGS = -Wall\n")
        || ovf(snprintf(path, sizeof path, "%s/a.c", repo), sizeof path)
        || ovf(snprintf(body, sizeof body,
                        "#pragma GCC diagnostic ignored \"-W%s\"\n"
                        "int main(void){return 0;}\n",
                        "unused-result"), sizeof body)
        || csr_write(path, body)) {
        fclose(cap);
        (void)rap_rm_rf(tmp);
        return nws_fx_fail("could not plant pragma fixture");
    }
    if (psp_st_reset(cap))
        bad = 1;
    scan_rc = nws_scan(repo, cap, cap);
    if (csr_slurp(cap, ob, sizeof ob))
        bad = 1;
    if (bad || scan_rc != 1 || strstr(ob, "a.c:1") == NULL) {
        fclose(cap);
        (void)rap_rm_rf(tmp);
        return nws_fx_fail("pragma form did not trip a.c:1");
    }

    if (psp_st_reset(cap))
        bad = 1;
    scan_rc = nws_scan(empty, cap, cap);
    if (csr_slurp(cap, ob, sizeof ob))
        bad = 1;
    if (bad || scan_rc != 2 || strstr(ob, "FATAL") == NULL) {
        fclose(cap);
        (void)rap_rm_rf(tmp);
        return nws_fx_fail("empty scan expected FATAL exit 2");
    }

    fclose(cap);
    rc = rap_rm_rf(tmp);
    return rc ? rc : 0;
}

int check_no_warning_suppression_run(int argc, char **argv)
{
    char cwd[4096];
    const char *root;
    if (argc >= 1 && argv[0] && argv[0][0])
        root = argv[0];
    else {
        if (!getcwd(cwd, sizeof cwd))
            return die("z23-lint: getcwd failed\n", "");
        root = cwd;
    }
    struct stat st;
    if (stat(root, &st) != 0 || !S_ISDIR(st.st_mode)) {
        if (fprintf(stderr,
                    "check_no_warning_suppression: FATAL — root is not a directory: %s\n",
                    root) < 0)
            return die("z23-lint: write failed\n", "");
        return 2;
    }
    if (strchr(root, '\''))
        return die("z23-lint: path too long: %s\n", root);
    char dump[64];
    int code = 0;
    int rc = rap_git_cmd(root, "rev-parse --is-inside-work-tree >/dev/null 2>&1",
                         dump, sizeof dump, &code);
    if (rc)
        return rc;
    if (code != 0) {
        if (fprintf(stderr,
                    "check_no_warning_suppression: FATAL — not a Git worktree: %s\n",
                    root) < 0)
            return die("z23-lint: write failed\n", "");
        return 2;
    }
    rc = nws_fixtures();
    if (rc)
        return rc;
    return nws_scan(root, stdout, stderr);
}

int check_no_warning_suppression_selftest(void)
{
    int rc = nws_fixtures();
    if (rc) {
        fputs("FAIL: check_no_warning_suppression selftest\n", stderr);
        return st_ok(1, "check_no_warning_suppression selftest: OK\n");
    }
    return st_ok(0, "check_no_warning_suppression selftest: OK\n");
}

static int mor_comment(const char *line)
{
    while (*line && isspace((unsigned char)*line))
        line++;
    return (line[0] == '/' && line[1] == '*')
        || line[0] == '*'
        || (line[0] == '/' && line[1] == '/');
}

struct mor_acc { regex_t *call; FILE *lines; int scanned; };

static int mor_on_file(const char *path, void *ctx)
{
    struct mor_acc *a = ctx;
    size_t n = strlen(path);
    if (n < 2 || path[n - 2] != '.'
        || (path[n - 1] != 'c' && path[n - 1] != 'h'))
        return 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    int lineno = 0, rc = 0;
    while ((len = getline(&line, &cap, f)) >= 0) {
        lineno++;
        if (regexec(a->call, line, 0, NULL, 0) != 0)
            continue;
        if (len > 0 && line[len - 1] == '\n')
            line[len - 1] = '\0';
        if (mor_comment(line))
            continue;
        a->scanned++;
        if (fprintf(a->lines, "%s:%d:%s\n", path, lineno, line) < 0) {
            rc = die("z23-lint: write failed\n", "");
            break;
        }
    }
    return fin(f, line, path, rc);
}

int check_mind_owns_rebuild_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    regex_t call, allow;
    int cr = compile_pat(&call, REG_EXTENDED, "codeindex",
                         "_rebuild[[:space:]]*\\(", "", "");
    if (cr)
        return cr;
    cr = compile_pat(&allow, REG_EXTENDED,
                     "^(cognition/modules/codeindex/(src|include)/",
                     "|tools/mind/|tests/harness/src/test_codeindex)", "", "");
    if (cr) {
        regfree(&call);
        return cr;
    }
    FILE *hits = tmpfile(), *viol = tmpfile();
    if (!hits || !viol) {
        if (hits) fclose(hits);
        if (viol) fclose(viol);
        drop2(&call, &allow);
        return die("z23-lint: tmpfile failed\n", "");
    }
    struct mor_acc a = { .call = &call, .lines = hits, .scanned = 0 };
    int rc = each_zpath(k_ls_all, mor_on_file, &a);
    if (rc == 0)
        rc = gate_require_scanned(a.scanned, 4, "check-mind-owns-rebuild",
                                  "codeindex_rebuild's own module should always appear; check the pathspec.");
    int nviol = 0;
    if (rc == 0 && fseek(hits, 0, SEEK_SET) != 0)
        rc = die("z23-lint: fseek failed\n", "");
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    while (rc == 0 && (n = getline(&line, &cap, hits)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        if (!line[0])
            continue;
        char *colon = strchr(line, ':');
        char save = 0;
        if (colon) {
            save = *colon;
            *colon = '\0';
        }
        int ok = colon && regexec(&allow, line, 0, NULL, 0) == 0;
        if (colon)
            *colon = save;
        if (ok)
            continue;
        nviol++;
        if (fprintf(viol, "%s\n", line) < 0)
            rc = die("z23-lint: write failed\n", "");
    }
    free(line);
    if (rc == 0 && ferror(hits))
        rc = die("z23-lint: read failed\n", "");
    if (rc == 0 && nviol) {
        if (fputs("check-mind-owns-rebuild: FAIL — codeindex_rebuild called outside the mind and the codeindex module\n",
                  stderr) < 0)
            rc = die("z23-lint: write failed\n", "");
        else if (fseek(viol, 0, SEEK_SET) != 0)
            rc = die("z23-lint: fseek failed\n", "");
        else
            rc = replay(viol);
        if (rc == 0
            && (fputs("  A query that rebuilds is a second writer racing the node resident.\n",
                      stderr) < 0
                || fputs("  Read the published generation with codeindex_open_readonly() and\n",
                         stderr) < 0
                || fputs("  refuse a stale one; the mind rebuilds. See docs/MIND.md.\n",
                         stderr) < 0))
            rc = die("z23-lint: write failed\n", "");
        if (rc == 0)
            rc = 1;
    } else if (rc == 0) {
        if (printf("check-mind-owns-rebuild: PASS — %d call site(s), all inside the codeindex module, tools/mind/, or that module's own tests\n",
                   a.scanned) < 0)
            rc = die("z23-lint: write failed\n", "");
    }
    fclose(hits);
    fclose(viol);
    drop2(&call, &allow);
    return rc;
}

int check_mind_owns_rebuild_selftest(void)
{
    regex_t allow, call;
    int cr = compile_pat(&allow, REG_EXTENDED,
                         "^(cognition/modules/codeindex/(src|include)/",
                         "|tools/mind/|tests/harness/src/test_codeindex)", "", "");
    if (cr)
        return cr;
    cr = compile_pat(&call, REG_EXTENDED, "codeindex",
                     "_rebuild[[:space:]]*\\(", "", "");
    if (cr) {
        regfree(&allow);
        return cr;
    }
    int bad = 0;
    if (regexec(&allow, "cognition/modules/codeindex/src/codeindex_build.c", 0, NULL, 0) != 0
        || regexec(&allow, "tools/mind/mind_resident.c", 0, NULL, 0) != 0
        || regexec(&allow, "tests/harness/src/test_codeindex.c", 0, NULL, 0) != 0
        || regexec(&allow, "tools/command/native_code_command.c", 0, NULL, 0) == 0
        || regexec(&allow, "cognition/services/src/zcode_goal_context_service.c", 0, NULL, 0) == 0)
        bad = 1;
    char s1[80], s2[96];
    if (snprintf(s1, sizeof s1, "    if (!%s%s(ci))", "codeindex", "_rebuild")
            >= (int)sizeof s1
        || snprintf(s2, sizeof s2, " * Explicit %s%s() remains a forced recompute",
                    "codeindex", "_rebuild") >= (int)sizeof s2)
        bad = 1;
    else if (regexec(&call, s1, 0, NULL, 0) != 0
             || regexec(&call, s2, 0, NULL, 0) != 0)
        bad = 1;
    drop2(&allow, &call);
    return st_ok(bad, "check-mind-owns-rebuild selftest: OK\n");
}

enum { SUS_DIRS = 32, SUS_STRAY_N = 256, SUS_STRAY_L = 512, SUS_TRACK = 2 * 1024 * 1024 };
static const char *const k_sus_dirs[] = {
    "core", "engine", "contexts", "cognition", "platform", "core", "adapters", "tools"
};

static int sus_split_ws(const char *s, char out[][RS_PATH], int max, int *n)
{
    *n = 0;
    while (*s) {
        while (*s && isspace((unsigned char)*s))
            s++;
        if (!*s)
            break;
        const char *e = s;
        while (*e && !isspace((unsigned char)*e))
            e++;
        size_t len = (size_t)(e - s);
        if (*n >= max || len >= RS_PATH)
            return die("z23-lint: derived buffer overflow\n", "");
        memcpy(out[*n], s, len);
        out[*n][len] = '\0';
        (*n)++;
        s = e;
    }
    return 0;
}

static int sus_has_seg(const char *path, const char *seg)
{
    /* Reproduce the original's find "-not -path" clause exactly: a literal
     * "/seg/" substring, requiring a slash BEFORE the segment too. A bare
     * top-of-path prefix match (no leading slash) is NOT excluded by the
     * original — that matters concretely for LINT_PLANTED_DIR
     * ("tools/lint/fixtures/planted"), since "tools" is itself one of the
     * scanned top-level dirs: a stray reached as "tools/lint/fixtures/
     * planted/x.c" has no leading slash before "tools" and the original's
     * fnmatch pattern does not match it. A prefix-match branch here would
     * silently NARROW this gate's reporting versus the original. */
    char needle[192];
    int n = snprintf(needle, sizeof needle, "/%s/", seg);
    if (n < 0 || (size_t)n >= sizeof needle)
        return 0;
    return strstr(path, needle) != NULL;
}

static int sus_fix_comp(regex_t *re)
{
    return compile_pat(re, REG_EXTENDED, ".*/_[^/]*fixture[^/]*\\.", "[ch]$", "", "");
}

static int sus_excluded(const char *path, const regex_t *fixre)
{
    if (sus_has_seg(path, k_planted) || sus_has_seg(path, "build")
        || sus_has_seg(path, "vendor") || sus_has_seg(path, "test-tmp"))
        return 1;
    return regexec(fixre, path, 0, NULL, 0) == 0;
}

static int sus_in_set(const char *buf, size_t used, const char *path)
{
    size_t n = strlen(path);
    for (size_t i = 0; i < used; ) {
        size_t m = strlen(buf + i);
        if (m == n && memcmp(buf + i, path, n) == 0)
            return 1;
        i += m + 1;
    }
    return 0;
}

struct sus_track { char *buf; size_t cap, used; };
static int sus_on_track(const char *path, void *ctx)
{
    struct sus_track *t = ctx;
    size_t n = strlen(path) + 1;
    if (t->used + n > t->cap)
        return die("z23-lint: derived buffer overflow\n", "");
    memcpy(t->buf + t->used, path, n);
    t->used += n;
    return 0;
}

struct sus_acc {
    const regex_t *fixre;
    const char *track;
    size_t tused;
    char (*stray)[SUS_STRAY_L];
    int nstray, ncand;
};

static int sus_scan(const char *path, void *ctx)
{
    struct sus_acc *a = ctx;
    if (sus_excluded(path, a->fixre))
        return 0;
    a->ncand++;
    if (sus_in_set(a->track, a->tused, path))
        return 0;
    size_t n = strlen(path);
    if (a->nstray >= SUS_STRAY_N || n >= SUS_STRAY_L)
        return die("z23-lint: derived buffer overflow\n", "");
    memcpy(a->stray[a->nstray], path, n + 1);
    a->nstray++;
    return 0;
}

static int sus_seen(const char seen[][RS_PATH], int n, const char *d)
{
    for (int i = 0; i < n; i++)
        if (strcmp(seen[i], d) == 0)
            return 1;
    return 0;
}

int check_no_stray_untracked_source_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    char scan[SUS_DIRS][RS_PATH];
    int nd = 0, rc = 0;
    const char *env = getenv("ZCL_STRAY_SCAN_DIRS_FOR_TEST");
    if (env && env[0])
        rc = sus_split_ws(env, scan, SUS_DIRS, &nd);
    else {
        for (size_t i = 0; i < sizeof k_sus_dirs / sizeof k_sus_dirs[0]; i++) {
            size_t n = strlen(k_sus_dirs[i]);
            memcpy(scan[nd], k_sus_dirs[i], n + 1);
            nd++;
        }
    }
    if (rc)
        return rc;
    char exist[SUS_DIRS][RS_PATH];
    int ne = 0;
    for (int i = 0; i < nd; i++) {
        struct stat st;
        if (stat(scan[i], &st) == 0 && S_ISDIR(st.st_mode)) {
            size_t n = strlen(scan[i]);
            if (ne >= SUS_DIRS || n >= RS_PATH)
                return die("z23-lint: derived buffer overflow\n", "");
            memcpy(exist[ne], scan[i], n + 1);
            ne++;
        }
    }
    rc = gate_require_scanned(ne, 1, "check-no-stray-untracked-source",
                              "none of the scanned root dirs exist — layout changed?");
    if (rc)
        return rc;
    regex_t fixre;
    rc = sus_fix_comp(&fixre);
    if (rc)
        return rc;
    char lscmd[8192];
    int k = snprintf(lscmd, sizeof lscmd, "git ls-files -z --");
    if (ovf(k, sizeof lscmd)) {
        regfree(&fixre);
        return 2;
    }
    size_t used = (size_t)k;
    for (int i = 0; i < ne; i++) {
        k = snprintf(lscmd + used, sizeof lscmd - used, " %s", exist[i]);
        if (ovf(k, sizeof lscmd - used)) {
            regfree(&fixre);
            return 2;
        }
        used += (size_t)k;
    }
    static char track[SUS_TRACK];
    struct sus_track t = { .buf = track, .cap = sizeof track };
    rc = each_zpath(lscmd, sus_on_track, &t);
    if (rc) {
        regfree(&fixre);
        return rc;
    }
    static char stray[SUS_STRAY_N][SUS_STRAY_L];
    struct sus_acc a = {
        .fixre = &fixre, .track = track, .tused = t.used, .stray = stray
    };
    char walked[SUS_DIRS][RS_PATH];
    int nw = 0;
    for (int i = 0; rc == 0 && i < ne; i++) {
        if (sus_seen(walked, nw, exist[i]))
            continue;
        size_t n = strlen(exist[i]);
        if (nw >= SUS_DIRS || n >= RS_PATH)
            rc = die("z23-lint: derived buffer overflow\n", "");
        else {
            memcpy(walked[nw], exist[i], n + 1);
            nw++;
            rc = walk_src(exist[i], 1, sus_scan, &a);
        }
    }
    regfree(&fixre);
    if (rc)
        return rc;
    if (a.nstray > 0) {
        if (fprintf(stderr, "FAIL: %d untracked stray file(s) under scanned source dirs\n",
                    a.nstray) < 0
            || fputs("  These are NOT code violations — they are files git does not track,\n"
                     "  most often leftovers from a crashed agent or an abandoned worktree\n"
                     "  (files matching the lint-gate selftest fixture naming convention,\n"
                     "  _*fixture*.c, are excluded from this check — see the header comment).\n"
                     "  Delete them (or 'git add' if intentional new source):\n",
                     stderr) < 0)
            return die("z23-lint: write failed\n", "");
        for (int i = 0; i < a.nstray; i++)
            if (fprintf(stderr, "    %s [untracked stray file -- not a code violation]\n",
                        a.stray[i]) < 0)
                return die("z23-lint: write failed\n", "");
        return 1;
    }
    char joined[2048];
    size_t ju = 0;
    joined[0] = '\0';
    for (int i = 0; i < ne; i++) {
        k = snprintf(joined + ju, sizeof joined - ju, "%s%s", i ? " " : "", exist[i]);
        if (ovf(k, sizeof joined - ju))
            return 2;
        ju += (size_t)k;
    }
    return printf("[check_no_stray_untracked_source] scanned %d file(s) under %s; "
                  "0 untracked strays\n", a.ncand, joined) < 0
               ? die("z23-lint: write failed\n", "") : 0;
}

int check_no_stray_untracked_source_selftest(void)
{
    regex_t re;
    int cr = sus_fix_comp(&re);
    if (cr)
        return cr;
    int bad = 0;
    /* A bare top-of-path occurrence (no leading slash before "tools") is
     * NOT excluded, matching the original's find "-not -path" fnmatch
     * semantics for this clause, which requires a slash before the
     * segment too. */
    bad |= sus_excluded("tools/lint/fixtures/planted/foo.c", &re);
    bad |= !sus_excluded("x/tools/lint/fixtures/planted/foo.c", &re);
    bad |= !sus_excluded("core/foo/build/x.c", &re);
    bad |= !sus_excluded("engine/vendor/x.c", &re);
    bad |= !sus_excluded("core/test-tmp/x.c", &re);
    bad |= !sus_excluded("core/src/_abfixture.c", &re);
    bad |= sus_excluded("core/consensus/src/foo.c", &re);
    bad |= sus_excluded("core/.claude/foo.c", &re);
    char set[32];
    memcpy(set, "core/a.c", 9);
    memcpy(set + 9, "core/b.c", 9);
    bad |= !sus_in_set(set, 18, "core/a.c");
    bad |= sus_in_set(set, 18, "core/missing.c");
    regfree(&re);
    return st_ok(bad, "check_no_stray_untracked_source selftest: OK\n");
}
