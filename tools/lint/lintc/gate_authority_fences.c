/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — exclusive-authority fence gates of the C23 lint
 * runtime (check-vcs-no-git, check-no-authoritative-ram-state).
 */

/*
 * Gates: check-vcs-no-git, check-no-authoritative-ram-state
 *
 * Two independent boundary fences over exclusive authority. check-vcs-no-git
 * is a HARD directory-scoped forbidden-pattern gate: ZVCS
 * (contexts/commons/modules/vcs) is the in-binary content-addressed VCS, so
 * that tree must never name git or a process-spawning primitive — git stays
 * an out-of-band publish bridge under tools/scripts/. check-no-authoritative-
 * ram-state is a shrink-only presence-set RATCHET: consensus authority lives
 * in the log, projections, and durable cursors; new direct active_chain
 * internals or global/static active_chain instances are forbidden outside
 * tools/scripts/no_authoritative_ram_state_baseline.txt.
 *
 * This family exists because gate_ratchet_ports.c is the closest subject
 * match for the RAM-state ratchet (its header invites a shrink-only
 * caller-baseline ratchet) but is already 1169 lines against the 1500 cap
 * (331 lines of headroom — not a comfortable two-gate budget), and consumer 1
 * is not a ratchet. Default landing is this new file.
 *
 * Both shell originals walk the filesystem (grep -rnE / find), not
 * git ls-files, so both ports use walk_src. Consumer 1's live PATTERN is
 * POSIX ERE with boundary classes (^|[^A-Za-z0-9_.]) / ([^A-Za-z0-9_]|$)
 * — the shell header still describes a retired PCRE word-boundary form;
 * this port follows the live PATTERN, not that stale prose.
 *
 * Unreadable mid-scan (directory exists but scandir/fopen fails) uses the
 * runtime die() path (z23-lint: cannot scan / cannot open, exit 2), the
 * analog of the shell's grep rc>=2 FATAL. Missing ZVCS directory is the
 * gate's own FATAL (exit 2) before any walk. The RAM-state shell has no
 * SCAN_FLOOR; this port adds a production-only floor of 200 scanned files
 * so a hollow six-root walk cannot pass clean. Selftests disable it.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

static int af_replay(FILE *from, FILE *to)
{
    if (fseek(from, 0, SEEK_SET) != 0)
        return die("z23-lint: fseek failed\n", "");
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while (rc == 0 && (n = getline(&line, &cap, from)) >= 0) {
        if (fwrite(line, 1, (size_t)n, to) != (size_t)n)
            rc = die("z23-lint: write failed\n", "");
    }
    int err = ferror(from);
    free(line);
    if (rc)
        return rc;
    return err ? die("z23-lint: read failed\n", "") : 0;
}

static int af_is_dir(const char *dir)
{
    struct stat st;
    if (stat(dir, &st) != 0)
        return 0;
    return S_ISDIR(st.st_mode);
}

static void af_strip_nl(char *line, ssize_t n)
{
    if (n > 0 && line[n - 1] == '\n')
        line[n - 1] = '\0';
}

/* ── check-vcs-no-git ─────────────────────────────────────────────────── */

static const char k_vng_dir[] = "contexts/commons/modules/vcs";
static const char k_vng_pat[] =
    "(^|[^A-Za-z0-9_.])(git([^A-Za-z0-9_]|$)|"
    "exec[lv][ep]*[[:space:]]*\\(|execve[[:space:]]*\\(|"
    "system[[:space:]]*\\(|popen[[:space:]]*\\(|fork[[:space:]]*\\()";

struct vng_acc { regex_t *re; FILE *out; int hits; };

static int vng_comp(regex_t *re)
{
    return reg_fail(re, regcomp(re, k_vng_pat, REG_EXTENDED));
}

static int vng_missing(const char *dir)
{
    fprintf(stderr,
            "check_vcs_no_git: FATAL — %s missing; refusing to pass hollow.\n",
            dir);
    return 2;
}

static int vng_fail(FILE *out)
{
    if (fputs("FAIL: contexts/commons/modules/vcs/ must not reference git or spawn processes\n",
              out) < 0)
        return die("z23-lint: write failed\n", "");
    if (fputs("  (no `git`, exec*, system(, popen(, fork()). The ZVCS is sovereign;\n",
              out) < 0)
        return die("z23-lint: write failed\n", "");
    if (fputs("  the git bridge lives only in tools/scripts/, never in contexts/commons/modules/vcs/.\n",
              out) < 0)
        return die("z23-lint: write failed\n", "");
    return 1;
}

static int vng_clean(FILE *out)
{
    if (fputs("check_vcs_no_git: clean — contexts/commons/modules/vcs/ is git-free and spawns no processes\n",
              out) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int vng_note(struct vng_acc *a, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        lineno++;
        if (regexec(a->re, line, 0, NULL, 0) != 0)
            continue;
        af_strip_nl(line, n);
        if (fprintf(a->out, "%s:%d:%s\n", path, lineno, line) < 0) {
            rc = die("z23-lint: write failed\n", "");
            break;
        }
        a->hits++;
    }
    return fin(f, line, path, rc);
}

static int vng_on_file(const char *path, void *ctx)
{
    if (lint_path_is_excluded(path))
        return 0;
    return vng_note(ctx, path);
}

static int vng_eval(const char *dir, FILE *out, int *hits)
{
    if (!af_is_dir(dir))
        return vng_missing(dir);
    regex_t re;
    int rc = vng_comp(&re);
    if (rc)
        return rc;
    struct vng_acc a = { .re = &re, .out = out };
    rc = walk_src(dir, 1, vng_on_file, &a);
    if (hits)
        *hits = a.hits;
    if (rc == 0) {
        if (a.hits)
            rc = vng_fail(out);
        else
            rc = vng_clean(out);
    }
    regfree(&re);
    return rc;
}

int check_vcs_no_git_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return vng_eval(k_vng_dir, stdout, NULL);
}

static int vng_st_write(const char *root, const char *body)
{
    char path[4096];
    if (ovf(snprintf(path, sizeof path, "%s/x.c", root), sizeof path))
        return 1;
    return csr_write(path, body);
}

static int vng_st_case(const char *root, const char *body, int want_rc,
                       int want_hits)
{
    if (vng_st_write(root, body))
        return 1;
    FILE *out = tmpfile();
    if (!out)
        return die("z23-lint: tmpfile failed\n", "");
    int hits = 0;
    int rc = vng_eval(root, out, &hits);
    fclose(out);
    return rc != want_rc || hits != want_hits;
}

static int vng_st_missing(void)
{
    const char *td = env_or("TMPDIR", "/tmp");
    char path[4096];
    if (ovf(snprintf(path, sizeof path, "%s/z23-lint-vng-absent", td),
            sizeof path))
        return 1;
    FILE *out = tmpfile();
    if (!out)
        return die("z23-lint: tmpfile failed\n", "");
    int hits = 0;
    int rc = vng_eval(path, out, &hits);
    fclose(out);
    return rc != 2;
}

int check_vcs_no_git_selftest(void)
{
    const char *td = env_or("TMPDIR", "/tmp");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-vng.XXXXXX", td),
            sizeof tmpl))
        return 2;
    char *tmp = mkdtemp(tmpl);
    if (!tmp)
        return die("z23-lint: mkdir failed: %s\n", td);
    int bad = vng_st_case(tmp, "const char *c = \"git status\";\n", 1, 1);
    bad |= vng_st_case(tmp, "const char *c = \".git\";\n", 0, 0);
    bad |= vng_st_case(tmp, "void f(void) { popen(\"x\", \"r\"); }\n", 1, 1);
    bad |= vng_st_case(tmp, "int x(void) { return 0; }\n", 0, 0);
    bad |= vng_st_missing();
    (void)rap_rm_rf(tmp);
    return st_ok(bad, "check_vcs_no_git selftest: OK\n");
}

/* ── check-no-authoritative-ram-state ─────────────────────────────────── */

static const char k_ram_base[] =
    "tools/scripts/no_authoritative_ram_state_baseline.txt";
static const char *const k_ram_roots[] = {
    "core", "engine", "contexts", "cognition", "platform", "tools"
};
enum { RAM_NROOT = (int)(sizeof k_ram_roots / sizeof k_ram_roots[0]) };
enum { RAM_FLOOR = 200, RAM_KEY = 8192 };

static const char k_ram_pat[] =
    "(\\.|->)chain_active\\.(height|chain|capacity)|"
    "(^|[[:space:]])static[[:space:]]+struct[[:space:]]+active_chain[[:space:]]+[A-Za-z_][A-Za-z0-9_]*|"
    "(^|[[:space:]])struct[[:space:]]+active_chain[[:space:]]+g_[A-Za-z_][A-Za-z0-9_]*";
static const char k_ram_ok[] =
    "//[[:space:]]*ram-state-ok:[A-Za-z][A-Za-z0-9_-]*";

static struct lint_base g_ram_base;

struct ram_acc {
    regex_t *re;
    regex_t *ok;
    struct lint_base *base;
    FILE *hits;
    int floor;
    int nscan;
    int nnew;
};

static int ram_comp(regex_t *re, regex_t *ok)
{
    int e = reg_fail(re, regcomp(re, k_ram_pat, REG_EXTENDED));
    if (e)
        return e;
    e = reg_fail(ok, regcomp(ok, k_ram_ok, REG_EXTENDED));
    if (e)
        regfree(re);
    return e;
}

static int ram_skip(const char *path)
{
    if (lint_path_is_excluded(path))
        return 1;
    if (strstr(path, "/test/") != NULL)
        return 1;
    if (strncmp(path, "tools/scripts/", 14) == 0)
        return 1;
    if (strncmp(path, "tools/lint/", 11) == 0)
        return 1;
    return 0;
}

static int ram_putc(char *out, size_t cap, size_t *n, char c)
{
    if (*n + 1 >= cap)
        return 1;
    out[(*n)++] = c;
    return 0;
}

/* sed -E 's/[[:space:]]+/ /g' on the whole grep -H hit, including a
 * leading or trailing space when the input starts or ends with whitespace. */
static int ram_squash(const char *in, char *out, size_t cap)
{
    size_t n = 0;
    int sp = 0;
    for (const unsigned char *p = (const unsigned char *)in; *p; p++) {
        if (isspace(*p)) {
            sp = 1;
            continue;
        }
        if (sp && ram_putc(out, cap, &n, ' '))
            return 1;
        sp = 0;
        if (ram_putc(out, cap, &n, (char)*p))
            return 1;
    }
    if (sp && ram_putc(out, cap, &n, ' '))
        return 1;
    if (n >= cap)
        return 1;
    out[n] = '\0';
    return 0;
}

static const char *ram_after2(const char *s)
{
    const char *p = strchr(s, ':');
    if (p == NULL)
        return s;
    p = strchr(p + 1, ':');
    if (p == NULL)
        return s;
    return p + 1;
}

static int ram_in_base(struct lint_base *b, const char *key)
{
    if (strlen(key) >= LB_KEY)
        return 0;
    return lint_base_observe(b, key, 1) >= 0;
}

static int ram_emit(struct ram_acc *a, const char *key)
{
    const char *content = ram_after2(key);
    if (regexec(a->ok, content, 0, NULL, 0) == 0)
        return 0;
    if (ram_in_base(a->base, key))
        return 0;
    if (fprintf(a->hits, "  %s\n", key) < 0)
        return die("z23-lint: write failed\n", "");
    a->nnew++;
    return 0;
}

static int ram_hit(struct ram_acc *a, const char *path, int lineno,
                   const char *line)
{
    char raw[RAM_KEY], key[RAM_KEY];
    if (ovf(snprintf(raw, sizeof raw, "%s:%d:%s", path, lineno, line),
            sizeof raw))
        return 2;
    if (ram_squash(raw, key, sizeof key))
        return die("z23-lint: derived buffer overflow\n", "");
    return ram_emit(a, key);
}

static int ram_note(struct ram_acc *a, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0;
    a->nscan++;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        lineno++;
        if (regexec(a->re, line, 0, NULL, 0) != 0)
            continue;
        af_strip_nl(line, n);
        rc = ram_hit(a, path, lineno, line);
    }
    return fin(f, line, path, rc);
}

static int ram_on_file(const char *path, void *ctx)
{
    if (ram_skip(path))
        return 0;
    return ram_note(ctx, path);
}

static int ram_walk(struct ram_acc *a, const char *const *roots, size_t n)
{
    int rc = 0;
    size_t i;
    for (i = 0; rc == 0 && i < n; i++)
        rc = walk_src(roots[i], 1, ram_on_file, a);
    return rc;
}

static int ram_clean_msg(FILE *out, int n)
{
    if (fprintf(out,
                "check_no_authoritative_ram_state: clean — %d grandfathered RAM-authority surface(s), no new ones\n",
                n) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int ram_fail_head(struct ram_acc *a, FILE *out)
{
    if (fputc('\n', out) == EOF)
        return die("z23-lint: write failed\n", "");
    if (fprintf(out,
                "check_no_authoritative_ram_state: %d NEW RAM-authority surface(s)\n",
                a->nnew) < 0)
        return die("z23-lint: write failed\n", "");
    if (fputc('\n', out) == EOF)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int ram_fail_tail(FILE *out)
{
    if (fputc('\n', out) == EOF)
        return die("z23-lint: write failed\n", "");
    if (fputs("Use active_chain accessors for derived reads, and keep authoritative\n",
              out) < 0)
        return die("z23-lint: write failed\n", "");
    if (fputs("consensus state in log/projection/cursor storage. If this is a deliberate\n",
              out) < 0)
        return die("z23-lint: write failed\n", "");
    if (fputs("derived cache, add '// ram-state-ok:<tag>' with the invariant.\n",
              out) < 0)
        return die("z23-lint: write failed\n", "");
    return 1;
}

static int ram_report(struct ram_acc *a, FILE *out)
{
    if (a->floor > 0) {
        int rc = gate_require_scanned(a->nscan, a->floor,
                                      "check_no_authoritative_ram_state",
                                      "expected .c/.h files under core engine contexts cognition platform tools");
        if (rc)
            return rc;
    }
    if (a->nnew == 0)
        return ram_clean_msg(out, a->base->n);
    int rc = ram_fail_head(a, out);
    if (rc)
        return rc;
    rc = af_replay(a->hits, out);
    if (rc)
        return rc;
    return ram_fail_tail(out);
}

static int ram_eval(const char *const *roots, size_t nroots,
                    struct lint_base *base, int floor, FILE *out)
{
    regex_t re, ok;
    int rc = ram_comp(&re, &ok);
    if (rc)
        return rc;
    FILE *hits = tmpfile();
    if (!hits) {
        drop2(&re, &ok);
        return die("z23-lint: tmpfile failed\n", "");
    }
    struct ram_acc a = {
        .re = &re, .ok = &ok, .base = base, .hits = hits, .floor = floor
    };
    rc = ram_walk(&a, roots, nroots);
    if (rc == 0)
        rc = ram_report(&a, out);
    fclose(hits);
    drop2(&re, &ok);
    return rc;
}

int check_no_authoritative_ram_state_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    int rc = lint_base_load_set(&g_ram_base, k_ram_base);
    if (rc)
        return rc;
    return ram_eval(k_ram_roots, (size_t)RAM_NROOT, &g_ram_base, RAM_FLOOR,
                    stdout);
}

static int ram_st_eval(const char *root, const char *base_path, int want_rc)
{
    int rc = lint_base_load_set(&g_ram_base, base_path);
    if (rc)
        return 1;
    FILE *out = tmpfile();
    if (!out)
        return die("z23-lint: tmpfile failed\n", "");
    const char *roots[] = { root };
    rc = ram_eval(roots, 1, &g_ram_base, 0, out);
    fclose(out);
    return rc != want_rc;
}

static int ram_st_case(const char *root, const char *body, int want_rc)
{
    char path[4096], missing[4096];
    if (ovf(snprintf(path, sizeof path, "%s/x.c", root), sizeof path))
        return 1;
    if (ovf(snprintf(missing, sizeof missing, "%s/missing-base", root),
            sizeof missing))
        return 1;
    if (csr_write(path, body))
        return 1;
    int bad = ram_st_eval(root, missing, want_rc);
    (void)unlink(path);
    return bad;
}

static int ram_st_pinned(const char *root)
{
    char src[4096], bpath[4096], key[RAM_KEY];
    if (ovf(snprintf(src, sizeof src, "%s/x.c", root), sizeof src))
        return 1;
    if (ovf(snprintf(bpath, sizeof bpath, "%s/base.txt", root), sizeof bpath))
        return 1;
    if (csr_write(src, "x->chain_active.height;\n"))
        return 1;
    if (ovf(snprintf(key, sizeof key, "%s:1:x->chain_active.height;\n", src),
            sizeof key))
        return 1;
    if (csr_write(bpath, key))
        return 1;
    int bad = ram_st_eval(root, bpath, 0);
    (void)unlink(src);
    (void)unlink(bpath);
    return bad;
}

int check_no_authoritative_ram_state_selftest(void)
{
    const char *td = env_or("TMPDIR", "/tmp");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-ram.XXXXXX", td),
            sizeof tmpl))
        return 2;
    char *tmp = mkdtemp(tmpl);
    if (!tmp)
        return die("z23-lint: mkdir failed: %s\n", td);
    int bad = ram_st_case(tmp, "x->chain_active.height;\n", 1);
    bad |= ram_st_case(tmp,
                       "x->chain_active.height; // ram-state-ok:test-tag\n",
                       0);
    bad |= ram_st_pinned(tmp);
    bad |= ram_st_case(tmp, "static struct active_chain foo;\n", 1);
    bad |= ram_st_case(tmp, "struct active_chain g_bar;\n", 1);
    (void)rap_rm_rf(tmp);
    return st_ok(bad, "check_no_authoritative_ram_state selftest: OK\n");
}
