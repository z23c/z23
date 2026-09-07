/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — checkout-local git hook set
 * (check-git-hooks-installed). A missing .git (lint-gate sandbox) is
 * UNOBSERVED with a distinct message, never a pass. Default source root
 * is getcwd(), matching the shell `cd … && pwd`.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>
#include "lintc.h"

static int gh_fail(const char *detail)
{
    fprintf(stderr, "check_git_hooks_installed: FAIL — %s\n", detail);
    fputs("  Run: make install-hooks\n", stderr);
    return 1;
}

static int gh_unobs(const char *root)
{
    printf("check_git_hooks_installed: UNOBSERVED — no .git at %s; hook "
           "state was not examined\n", root);
    return 0;
}

static int gh_unreadable(const char *path)
{
    fprintf(stderr, "check_git_hooks_installed: UNPROVEN — cannot read %s\n",
            path);
    return 2;
}

static int gh_host(char *out, size_t cap)
{
    const char *e = env_or("ZCL_GIT_HOOK_HOST_FOR_TEST", "");
    struct utsname u;
    if (e[0]) {
        if (ovf(snprintf(out, cap, "%s", e), cap))
            return 2;
        return 0;
    }
    if (uname(&u) != 0)
        return gh_fail("unknown host selection ''");
    if (!strncmp(u.sysname, "MINGW", 5) || !strncmp(u.sysname, "MSYS", 4)
        || !strncmp(u.sysname, "CYGWIN", 6))
        return ovf(snprintf(out, cap, "%s", "windows"), cap) ? 2 : 0;
    return ovf(snprintf(out, cap, "%s", "posix"), cap) ? 2 : 0;
}

static int gh_gitdir(const char *root, char *out, size_t cap)
{
    char p[4096], line[4096];
    struct stat st;
    FILE *f;
    if (ovf(snprintf(p, sizeof p, "%s/.git", root), sizeof p))
        return 2;
    if (stat(p, &st) != 0)
        return 1;
    if (S_ISDIR(st.st_mode))
        return ovf(snprintf(out, cap, "%s", p), cap) ? 2 : 0;
    if (!S_ISREG(st.st_mode))
        return 1;
    f = fopen(p, "r");
    if (!f)
        return gh_unreadable(p);
    if (!fgets(line, (int)sizeof line, f)) {
        fclose(f);
        return 1;
    }
    fclose(f);
    if (strncmp(line, "gitdir:", 7) != 0)
        return 1;
    {
        char *s = line + 7;
        size_t n;
        while (*s == ' ' || *s == '\t')
            s++;
        n = strlen(s);
        while (n && (s[n - 1] == '\n' || s[n - 1] == '\r'))
            n--;
        s[n] = '\0';
        return ovf(snprintf(out, cap, "%s", s), cap) ? 2 : 0;
    }
}

static void gh_skip_ws(char **pp)
{
    char *p = *pp;
    while (*p == ' ' || *p == '\t')
        p++;
    *pp = p;
}

static size_t gh_rtrim(char *p)
{
    size_t n = strlen(p);
    while (n && (p[n - 1] == '\n' || p[n - 1] == '\r' || p[n - 1] == ' '
                 || p[n - 1] == '\t'))
        n--;
    p[n] = '\0';
    return n;
}

static int gh_hooks_eq(char *p, char *out, size_t cap)
{
    size_t n;
    gh_skip_ws(&p);
    if (strncmp(p, "hooksPath", 9) != 0)
        return 0;
    p += 9;
    gh_skip_ws(&p);
    if (*p != '=')
        return 0;
    p++;
    gh_skip_ws(&p);
    n = gh_rtrim(p);
    if (n >= cap)
        return -1;
    memcpy(out, p, n);
    out[n] = '\0';
    return 1;
}

static int gh_cfg_hooks(const char *path, char *out, size_t cap)
{
    FILE *f = fopen(path, "r");
    char line[1024];
    int in_core = 0, hit = 0;
    if (!f)
        return 0;
    while (!hit && fgets(line, (int)sizeof line, f)) {
        int got;
        if (line[0] == '[') {
            in_core = strncmp(line, "[core]", 6) == 0;
            continue;
        }
        if (!in_core)
            continue;
        got = gh_hooks_eq(line, out, cap);
        if (got < 0) {
            fclose(f);
            return 0;
        }
        if (got)
            hit = 1;
    }
    fclose(f);
    return hit;
}

static int gh_hookspath(const char *root, const char *gitdir, char *out,
                        size_t cap)
{
    const char *ov = env_or("ZCL_GIT_HOOKS_PATH_FOR_TEST", "");
    char cfg[4096];
    if (ov[0])
        return ovf(snprintf(out, cap, "%s", ov), cap) ? 2 : 0;
    (void)root;
    if (!ovf(snprintf(cfg, sizeof cfg, "%s/config.worktree", gitdir),
             sizeof cfg)
        && gh_cfg_hooks(cfg, out, cap))
        return 0;
    if (ovf(snprintf(cfg, sizeof cfg, "%s/config", gitdir), sizeof cfg))
        return 2;
    if (gh_cfg_hooks(cfg, out, cap))
        return 0;
    out[0] = '\0';
    return 0;
}

static int gh_cmp(const char *a, const char *b)
{
    FILE *fa = fopen(a, "rb");
    FILE *fb = fopen(b, "rb");
    char ba[4096], bb[4096];
    size_t na, nb;
    int same = 1;
    if (!fa)
        return gh_unreadable(a);
    if (!fb) {
        fclose(fa);
        return gh_unreadable(b);
    }
    while (same) {
        na = fread(ba, 1, sizeof ba, fa);
        nb = fread(bb, 1, sizeof bb, fb);
        if (na != nb || memcmp(ba, bb, na) != 0)
            same = 0;
        if (na < sizeof ba)
            break;
    }
    if (ferror(fa) || ferror(fb))
        same = 0;
    fclose(fa);
    fclose(fb);
    return same ? 0 : 1;
}

static int gh_exe(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return 0;
    return S_ISREG(st.st_mode) && (st.st_mode & 0111) != 0;
}

enum { GH_LINE = 8192 };

static int gh_src_ok(const char *path)
{
    FILE *f = fopen(path, "r");
    char line[GH_LINE];
    int a = 0, b = 0, c = 0, d = 0, e = 0;
    if (!f)
        return gh_unreadable(path);
    while (fgets(line, (int)sizeof line, f)) {
        if (strstr(line, "zcl_dev_proof_receipt_validate"))
            a = 1;
        if (strstr(line, "refs/heads/main"))
            b = 1;
        if (strstr(line, "merge-base"))
            c = 1;
        if (strstr(line, "dev proof wait"))
            d = 1;
        if (strstr(line, "post-commit"))
            e = 1;
    }
    fclose(f);
    return (a && b && c && d && e) ? 0 : 1;
}

static int gh_check_hooks(const char *actual, const char *host,
                          const char *binary)
{
    static const char *const k_hooks[] = {
        "pre-push", "post-commit", "post-merge", "post-checkout"
    };
    int i, win = strcmp(host, "windows") == 0;
    char path[4096];
    for (i = 0; i < 4; i++) {
        if (ovf(snprintf(path, sizeof path, "%s/%s%s", actual, k_hooks[i],
                         win ? ".exe" : ""), sizeof path))
            return 2;
        if (!gh_exe(path) || gh_cmp(binary, path) != 0)
            return gh_fail("is not the installed native hook");
    }
    return 0;
}

static int gh_roots(char *src_buf, size_t src_cap, const char **src_root,
                    const char **root)
{
    const char *src_env = env_or("ZCL_GIT_HOOK_SOURCE_ROOT", "");
    const char *root_env = env_or("ZCL_GIT_HOOK_ROOT", "");
    if (src_env[0]) {
        *src_root = src_env;
    } else if (!getcwd(src_buf, src_cap)) {
        fputs("check_git_hooks_installed: UNPROVEN — cannot read cwd\n",
              stderr);
        return 2;
    } else {
        *src_root = src_buf;
    }
    *root = root_env[0] ? root_env : *src_root;
    return 0;
}

static int gh_fill_expected(const char *root, char *expected, size_t cap)
{
    if (ovf(snprintf(expected, cap, "%s",
                     env_or("ZCL_GIT_HOOK_EXPECTED_DIR_FOR_TEST", "")), cap))
        return 2;
    if (expected[0])
        return 0;
    return ovf(snprintf(expected, cap, "%s/build/githooks", root), cap) ? 2 : 0;
}

static int gh_match_actual(const char *actual, const char *expected, int win)
{
    char msg[512];
    int bad;
    if (win)
        bad = strncmp(actual, expected, strlen(expected)) != 0
            || !strstr(actual, "/native-v2-");
    else
        bad = strcmp(actual, expected) != 0;
    if (!bad)
        return 0;
    if (ovf(snprintf(msg, sizeof msg, "checkout-local core.hooksPath is '%s'",
                     actual[0] ? actual : "<unset>"), sizeof msg))
        return 2;
    return gh_fail(msg);
}

static int gh_check_precommit(const char *src_root, const char *actual)
{
    char pre[4096], tracked[4096];
    if (ovf(snprintf(pre, sizeof pre, "%s",
                     env_or("ZCL_GIT_HOOK_PRECOMMIT_FILE_FOR_TEST", "")),
            sizeof pre))
        return 2;
    if (!pre[0]
        && ovf(snprintf(pre, sizeof pre, "%s/pre-commit", actual), sizeof pre))
        return 2;
    if (ovf(snprintf(tracked, sizeof tracked, "%s/tools/githooks/pre-commit",
                     src_root), sizeof tracked))
        return 2;
    if (!gh_exe(pre) || gh_cmp(tracked, pre) != 0)
        return gh_fail("pre-commit lane guard differs from the tracked hook");
    return 0;
}

static int gh_check_binary(const char *root, int win, char *binary, size_t cap)
{
    if (ovf(snprintf(binary, cap, "%s",
                     env_or("ZCL_GIT_HOOK_NATIVE_BIN_FOR_TEST", "")), cap))
        return 2;
    if (!binary[0]
        && ovf(snprintf(binary, cap, "%s/build/bin/z23-git-hook%s", root,
                        win ? ".exe" : ""), cap))
        return 2;
    if (!gh_exe(binary))
        return gh_fail("native hook binary is missing");
    return 0;
}

static int gh_dev_proof(void)
{
    int nfd, oldo, olde, rc;
    fflush(stdout);
    fflush(stderr);
    nfd = open("/dev/null", O_WRONLY);
    if (nfd < 0)
        return 2;
    oldo = dup(1);
    olde = dup(2);
    dup2(nfd, 1);
    dup2(nfd, 2);
    close(nfd);
    rc = check_dev_proof_native_fast_path_run(0, NULL);
    fflush(stdout);
    fflush(stderr);
    dup2(oldo, 1);
    dup2(olde, 2);
    close(oldo);
    close(olde);
    return rc;
}

static int gh_check_src(const char *src_root)
{
    char src[4096];
    int rc;
    if (ovf(snprintf(src, sizeof src, "%s",
                     env_or("ZCL_GIT_HOOK_FILE_FOR_TEST", "")), sizeof src))
        return 2;
    if (!src[0]
        && ovf(snprintf(src, sizeof src, "%s/tools/dev/z23_git_hook.c",
                        src_root), sizeof src))
        return 2;
    rc = gh_src_ok(src);
    if (rc == 2)
        return 2;
    if (rc)
        return gh_fail("native hook source lacks exact receipt admission");
    return gh_dev_proof();
}

static int gh_run(void)
{
    char src_buf[4096], host[32], gitdir[4096], actual[4096], expected[4096];
    char binary[4096];
    const char *src_root, *root;
    int win, rc, miss;
    rc = gh_roots(src_buf, sizeof src_buf, &src_root, &root);
    if (rc)
        return rc;
    rc = gh_host(host, sizeof host);
    if (rc)
        return rc;
    if (strcmp(host, "posix") != 0 && strcmp(host, "windows") != 0)
        return gh_fail("unknown host selection");
    miss = gh_gitdir(root, gitdir, sizeof gitdir);
    if (miss == 2)
        return 2;
    if (miss == 1)
        return gh_unobs(root);
    win = strcmp(host, "windows") == 0;
    rc = gh_fill_expected(root, expected, sizeof expected);
    if (rc)
        return rc;
    rc = gh_hookspath(root, gitdir, actual, sizeof actual);
    if (rc)
        return rc;
    if (!strcmp(actual, "build/githooks"))
        snprintf(actual, sizeof actual, "%s", expected);
    rc = gh_match_actual(actual, expected, win);
    if (rc)
        return rc;
    rc = gh_check_precommit(src_root, actual);
    if (rc)
        return rc;
    rc = gh_check_binary(root, win, binary, sizeof binary);
    if (rc)
        return rc;
    rc = gh_check_hooks(actual, host, binary);
    if (rc)
        return rc;
    rc = gh_check_src(src_root);
    if (rc)
        return rc;
    printf("check_git_hooks_installed: clean — checkout-local native receipt "
           "hooks armed (%s)\n", host);
    return 0;
}

static int gh_quiet(void)
{
    int nfd, oldo, olde, rc;
    fflush(stdout);
    fflush(stderr);
    nfd = open("/dev/null", O_WRONLY);
    if (nfd < 0)
        return 2;
    oldo = dup(1);
    olde = dup(2);
    dup2(nfd, 1);
    dup2(nfd, 2);
    close(nfd);
    rc = gh_run();
    fflush(stdout);
    fflush(stderr);
    dup2(oldo, 1);
    dup2(olde, 2);
    close(oldo);
    close(olde);
    return rc;
}

int check_git_hooks_installed_selftest(void)
{
    char tmp[] = "/tmp/zcl-gh-XXXXXX";
    char git[4096], cfg[4096];
    int rc, bad = 0;
    if (!mkdtemp(tmp))
        return die("z23-lint: mkdtemp failed\n", "");
    if (setenv("ZCL_GIT_HOOK_ROOT", tmp, 1)
        || setenv("ZCL_GIT_HOOK_SOURCE_ROOT", ".", 1)) {
        rap_rm_rf(tmp);
        return 2;
    }
    rc = gh_quiet();
    if (rc != 0) {
        fprintf(stderr, "check_git_hooks_installed selftest: FAIL — missing "
                        ".git rc=%d want=0 (UNOBSERVED)\n", rc);
        bad = 1;
    }
    if (ovf(snprintf(git, sizeof git, "%s/.git", tmp), sizeof git)
        || csr_mkdirs(git)
        || ovf(snprintf(cfg, sizeof cfg, "%s/config", git), sizeof cfg)
        || csr_write(cfg, "[core]\n\trepositoryformatversion = 0\n")) {
        unsetenv("ZCL_GIT_HOOK_ROOT");
        unsetenv("ZCL_GIT_HOOK_SOURCE_ROOT");
        rap_rm_rf(tmp);
        return 2;
    }
    rc = gh_quiet();
    if (rc != 1) {
        fprintf(stderr, "check_git_hooks_installed selftest: FAIL — empty "
                        "hooksPath rc=%d want=1\n", rc);
        bad = 1;
    }
    unsetenv("ZCL_GIT_HOOK_ROOT");
    unsetenv("ZCL_GIT_HOOK_SOURCE_ROOT");
    rap_rm_rf(tmp);
    if (bad)
        return 1;
    fputs("check_git_hooks_installed: self-test PASS (missing .git is "
          "UNOBSERVED, a .git without hooksPath fails closed)\n", stdout);
    return 0;
}

int check_git_hooks_installed_run(int argc, char **argv)
{
    if (argc >= 1
        && (!strcmp(argv[0], "--selftest") || !strcmp(argv[0], "--self-test")))
        return check_git_hooks_installed_selftest();
    return gh_run();
}
