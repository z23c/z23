/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — compile-fixture lint gates of the C23 lint runtime
 * (check-arena-view-stub). These prove a translation unit still compiles
 * against a hand-maintained header/stub via a real compiler invocation
 * (-fsyntax-only).
 */

/*
 * Gates: check-arena-view-stub
 * Default landing spot for a FUTURE gate port: a filesystem-tree-walking
 * gate (walk_src/clock_walk/repo_shape_room_dirs) joins gate_tree_walk.c;
 * a git-tracked-enumeration gate (each_zpath/each_zpath_st) joins whichever
 * of gate_git_scan_a.c/gate_git_scan_b.c is currently smaller by wc -l;
 * a proof/landing/receipt-shaped gate joins gate_landing_proof.c; a
 * build-flag/CI-toggle-shaped gate joins gate_build_config.c; only once
 * EVERY existing family is within ~200 lines of the ~1500 cap does a new
 * gate warrant a new family file — name it for its own subject the same
 * way the seven above are named for theirs. This family opened anyway
 * because no existing family invokes a real compiler: gate_build_config.c
 * only reads and pattern-matches Makefile text, while compile-fixture
 * gates run cc -fsyntax-only against a translation unit and a stub header.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

static const char k_avs_tu[] = "tools/arena_view.c";
static const char k_avs_stub[] = "tools/arena_view_raylib_stub.h";
static const char k_avs_var[] = "ARENA_VIEW_INCLUDES";
enum { AVS_INC = 8192, AVS_CMD = 16384, AVS_LOG = 256 * 1024 };
static char avs_log[AVS_LOG];

static char *avs_trim(char *s)
{
    while (*s && isspace((unsigned char)*s))
        s++;
    size_t n = strlen(s);
    while (n && isspace((unsigned char)s[n - 1]))
        s[--n] = '\0';
    return s;
}

static int avs_continued(const char *line)
{
    const char *p = line + strlen(line);
    while (p > line && (p[-1] == '\n' || p[-1] == '\r'))
        p--;
    while (p > line && isspace((unsigned char)p[-1]))
        p--;
    return p > line && p[-1] == '\\';
}

static int avs_is_assign(const char *line, const char *name, const char **rest)
{
    size_t nl = strlen(name);
    if (strncmp(line, name, nl) != 0)
        return 0;
    const char *p = line + nl;
    while (*p && isspace((unsigned char)*p))
        p++;
    if (*p != '=')
        return 0;
    *rest = p + 1;
    return 1;
}

static int avs_append(char *value, size_t cap, const char *tok)
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

static void avs_strip_eol(char *line, ssize_t n)
{
    if (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) {
        line[n - 1] = '\0';
        if (n > 1 && line[n - 2] == '\r')
            line[n - 2] = '\0';
    }
}

static void avs_strip_slash(char *body)
{
    size_t L = strlen(body);
    while (L && isspace((unsigned char)body[L - 1]))
        L--;
    if (L && body[L - 1] == '\\')
        body[L - 1] = '\0';
}

static int avs_read_includes(const char *path, char *value, size_t cap)
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
            if (!avs_is_assign(line, k_avs_var, &body))
                continue;
            active = 1;
        }
        int cont = avs_continued(body);
        avs_strip_eol(line, n);
        if (cont)
            avs_strip_slash((char *)body);
        if (avs_append(value, cap, avs_trim((char *)body))) {
            rc = 2;
            break;
        }
        if (!cont)
            break;
    }
    int fr = fin(f, line, path, rc);
    return fr ? fr : rc;
}

static int avs_includes_empty(const char *s)
{
    while (*s && isspace((unsigned char)*s))
        s++;
    return *s == '\0';
}

static int avs_copy(const char *src, const char *dst)
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

static int avs_prefix_log(const char *log)
{
    if (!log[0])
        return 0;
    const char *p = log;
    while (*p) {
        const char *nl = strchr(p, '\n');
        if (fputs("  ", stderr) < 0)
            return die("z23-lint: write failed\n", "");
        if (!nl) {
            if (fputs(p, stderr) < 0 || fputc('\n', stderr) == EOF)
                return die("z23-lint: write failed\n", "");
            break;
        }
        size_t len = (size_t)(nl - p + 1);
        if (fwrite(p, 1, len, stderr) != len)
            return die("z23-lint: write failed\n", "");
        p = nl + 1;
    }
    return 0;
}

static int avs_stub_compile(const char *tu, const char *extra_dir,
                            const char *includes, int *code)
{
    const char *cc = env_or("CC", "cc");
    char qcc[4096], qtu[8192], qextra[8192], extra[8192], cmd[AVS_CMD];
    extra[0] = '\0';
    if (sh_single_quote(cc, qcc, sizeof qcc) || sh_single_quote(tu, qtu, sizeof qtu))
        return 2;
    if (extra_dir && extra_dir[0]) {
        if (sh_single_quote(extra_dir, qextra, sizeof qextra)
            || ovf(snprintf(extra, sizeof extra, "-I%s", qextra), sizeof extra))
            return 2;
    }
    if (ovf(snprintf(cmd, sizeof cmd,
                     "%s -std=c23 -fsyntax-only -Wall -Wextra -Werror -pedantic "
                     "-D_POSIX_C_SOURCE=200809L -DARENA_VIEW_RAYLIB_STUB %s %s %s 2>&1",
                     qcc, extra, includes, qtu), sizeof cmd))
        return 2;
    return capture_cmd(cmd, avs_log, sizeof avs_log, code);
}

static int avs_drop_decl(const char *src, const char *dst, const char *start,
                         const char *stop)
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
    int deleting = 0, rc = 0;
    while ((n = getline(&line, &cap, in)) >= 0) {
        if (!deleting && strstr(line, start))
            deleting = 1;
        if (deleting) {
            int end = strstr(line, stop) != NULL;
            if (end)
                deleting = 0;
            continue;
        }
        if (fwrite(line, 1, (size_t)n, out) != (size_t)n) {
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

static int avs_rewrite_initwindow(const char *src, const char *dst)
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
    int rc = 0;
    static const char k_old[] = "void InitWindow(";
    while ((n = getline(&line, &cap, in)) >= 0) {
        if (strncmp(line, k_old, sizeof k_old - 1) == 0) {
            if (fputs("void InitWindow(void);\n", out) < 0) {
                rc = die("z23-lint: write failed\n", "");
                break;
            }
            continue;
        }
        if (fwrite(line, 1, (size_t)n, out) != (size_t)n) {
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

int check_arena_view_stub_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    char root[4096], includes[AVS_INC];
    if (cic_repo_root(root, sizeof root))
        return 2;
    if (chdir(root) != 0)
        return die("z23-lint: cannot scan %s\n", root);
    int rc = avs_read_includes("Makefile", includes, sizeof includes);
    if (rc)
        return rc;
    if (avs_includes_empty(includes)) {
        fputs("check-arena-view-stub: FAIL — ARENA_VIEW_INCLUDES unreadable "
              "in Makefile.\n", stderr);
        fputs("  The extractor drifted, not the sources; fix the extractor,\n",
              stderr);
        fputs("  never widen or bypass it.\n", stderr);
        return 2;
    }
    struct stat st;
    if (stat(k_avs_tu, &st) != 0 || !S_ISREG(st.st_mode)
        || stat(k_avs_stub, &st) != 0 || !S_ISREG(st.st_mode)) {
        fputs("check-arena-view-stub: FAIL — tools/arena_view.c or "
              "tools/arena_view_raylib_stub.h is missing from the tree.\n",
              stderr);
        return 2;
    }
    int code = 0;
    rc = avs_stub_compile(k_avs_tu, NULL, includes, &code);
    if (rc)
        return rc;
    if (code == 0) {
        if (fputs("check-arena-view-stub: OK — arena_view.c compiles against "
                  "the raylib 6.0 stub\n", stdout) < 0)
            return die("z23-lint: write failed\n", "");
        return 0;
    }
    fputs("check-arena-view-stub: FAIL — arena_view.c no longer compiles "
          "against the raylib\n", stderr);
    fputs("  stub. Every raylib call in the TU needs a declaration in\n", stderr);
    fprintf(stderr, "  %s, with a signature that matches how the TU calls it.\n",
            k_avs_stub);
    fputs("  On raylib hosts the linked build cannot catch this; raylib-less\n",
          stderr);
    fputs("  hosts are where this drift lands. Compiler log:\n", stderr);
    rc = avs_prefix_log(avs_log);
    return rc ? rc : 1;
}

static int avs_selftest_prepare(const char *work, char *tdir, char *tu,
                                char *stub, size_t cap)
{
    char vdir[4096];
    if (ovf(snprintf(tdir, cap, "%s/t", work), cap)
        || ovf(snprintf(vdir, sizeof vdir, "%s/vendor/typography", work),
               sizeof vdir)
        || ovf(snprintf(tu, cap, "%s/t/arena_view.c", work), cap)
        || ovf(snprintf(stub, cap, "%s/t/arena_view_raylib_stub.h", work),
               cap))
        return 2;
    if (csr_mkdirs(tdir) || csr_mkdirs(vdir))
        return 2;
    char mdst[4096], sdst[4096];
    if (ovf(snprintf(mdst, sizeof mdst, "%s/inter_medium_ascii.inc", vdir),
            sizeof mdst)
        || ovf(snprintf(sdst, sizeof sdst, "%s/inter_semibold_ascii.inc", vdir),
               sizeof sdst)
        || avs_copy(k_avs_tu, tu)
        || avs_copy("vendor/typography/inter_medium_ascii.inc", mdst)
        || avs_copy("vendor/typography/inter_semibold_ascii.inc", sdst)
        || avs_copy(k_avs_stub, stub))
        return 2;
    return 0;
}

static int avs_selftest_fixture_copy(const char *tu, const char *tdir,
                                     const char *includes, int *failed)
{
    int rc, code;
    rc = avs_stub_compile(tu, tdir, includes, &code);
    if (rc)
        return rc;
    if (code == 0) {
        if (puts("  selftest ok: fixture copy compiles against the tracked stub")
            < 0)
            return die("z23-lint: write failed\n", "");
    } else {
        fputs("SELFTEST FAIL: fixture copy does not compile — harness bug:\n",
              stderr);
        if (avs_prefix_log(avs_log))
            return 2;
        *failed = 1;
    }
    return 0;
}

static int avs_selftest_dropped_decl(const char *tu, const char *tdir,
                                     const char *stub, const char *includes,
                                     int *failed)
{
    int rc, code;
    if (avs_drop_decl(k_avs_stub, stub, "LoadFontFromMemory", "codepointCount);"))
        return 2;
    rc = avs_stub_compile(tu, tdir, includes, &code);
    if (rc)
        return rc;
    if (code == 0) {
        fputs("SELFTEST FAIL: stub missing LoadFontFromMemory still compiled.\n",
              stderr);
        *failed = 1;
    } else if (strstr(avs_log, "LoadFontFromMemory")) {
        if (puts("  selftest ok: a dropped stub declaration is caught by name") < 0)
            return die("z23-lint: write failed\n", "");
    } else {
        fputs("SELFTEST FAIL: compile failed, but not on LoadFontFromMemory:\n",
              stderr);
        if (avs_prefix_log(avs_log))
            return 2;
        *failed = 1;
    }
    return 0;
}

static int avs_selftest_initwindow(const char *tu, const char *tdir,
                                   const char *stub, const char *includes,
                                   int *failed)
{
    int rc, code;
    if (avs_rewrite_initwindow(k_avs_stub, stub))
        return 2;
    rc = avs_stub_compile(tu, tdir, includes, &code);
    if (rc)
        return rc;
    if (code == 0) {
        fputs("SELFTEST FAIL: stub's InitWindow(void) prototype was accepted.\n",
              stderr);
        *failed = 1;
    } else if (strstr(avs_log, "InitWindow")) {
        if (puts("  selftest ok: stub signature drift is caught by name") < 0)
            return die("z23-lint: write failed\n", "");
    } else {
        fputs("SELFTEST FAIL: compile failed, but not on InitWindow:\n", stderr);
        if (avs_prefix_log(avs_log))
            return 2;
        *failed = 1;
    }
    return 0;
}

static int avs_selftest_verdict(int failed)
{
    if (!failed) {
        if (puts("══ selftest: PASS (3/3) ══") < 0)
            return die("z23-lint: write failed\n", "");
        return 0;
    }
    fputs("══ selftest: FAIL ══\n", stderr);
    return 1;
}

static int avs_selftest_body(const char *work, const char *includes)
{
    char tdir[4096], tu[4096], stub[4096];
    int rc, failed = 0;
    if (avs_selftest_prepare(work, tdir, tu, stub, sizeof tdir))
        return 2;
    rc = avs_selftest_fixture_copy(tu, tdir, includes, &failed);
    if (rc)
        return rc;
    rc = avs_selftest_dropped_decl(tu, tdir, stub, includes, &failed);
    if (rc)
        return rc;
    rc = avs_selftest_initwindow(tu, tdir, stub, includes, &failed);
    if (rc)
        return rc;
    return avs_selftest_verdict(failed);
}

int check_arena_view_stub_selftest(void)
{
    char root[4096], includes[AVS_INC];
    if (cic_repo_root(root, sizeof root))
        return 2;
    if (chdir(root) != 0)
        return die("z23-lint: cannot scan %s\n", root);
    int rc = avs_read_includes("Makefile", includes, sizeof includes);
    if (rc)
        return rc;
    if (avs_includes_empty(includes)) {
        fputs("check-arena-view-stub: FAIL — ARENA_VIEW_INCLUDES unreadable "
              "in Makefile.\n", stderr);
        return 2;
    }
    const char *td = env_or("TMPDIR", "/tmp");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/arena-view-stub-selftest.XXXXXX", td),
            sizeof tmpl))
        return 2;
    char *work = mkdtemp(tmpl);
    if (!work)
        return die("z23-lint: mkdir failed: %s\n", td);
    if (puts("══ check-arena-view-stub selftest ══") < 0) {
        (void)rap_rm_rf(work);
        return die("z23-lint: write failed\n", "");
    }
    rc = avs_selftest_body(work, includes);
    int cl = rap_rm_rf(work);
    return rc ? rc : cl;
}
