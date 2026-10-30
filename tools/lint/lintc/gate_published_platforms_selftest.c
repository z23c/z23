/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-published-platforms
 * (gate_published_platforms.c). Copies the three real claim files into a
 * mkdtemp scratch directory under $TMPDIR, then proves each of the seven
 * mutations of the shell original: an unproduced platform claimed by
 * PUBLISHED_PLATFORMS (refusal must name it), a claim with no case arm, a
 * case arm for an unpublished platform, an install.ps1 row with no Windows
 * bootstrap behind it, an FD_PUBLISHED runtime the cutter does not package,
 * a real digest checked in where the sentinel belongs, and the frozen
 * darwin-arm64 fold regression (refusal must name the platform). The cutter
 * stays the real one: it is the authority being measured against, and
 * mutating it would prove nothing. Every case restores all three files first; a baseline and a final restored-tree
 * probe bracket the mutations so each red is the mutation's and not residue
 * of the case before it. Scratch is removed afterwards.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"

#define ST_Z64 "0000000000000000000000000000000000000000000000000000000000000000"

int ppp_check(const char *sh, const char *ps1, const char *fdc,
              const char *cutter, FILE *out, FILE *err);
int ppp_fold_tail_probe(void);

enum { ST_PATH = 1024, ST_BUF = 131072, ST_OUT = 131072, ST_ERR = 8192,
       ST_LINE = 1024 };

static char g_st_in[ST_BUF];
static char g_st_out[ST_OUT];

static const char *const k_st_names[3] = {
    "install.sh", "install.ps1", "front_door_platform.c"
};

struct st_case {
    const char *name;
    int file;              /* 0 install.sh, 1 install.ps1, 2 front_door */
    const char *prefix;    /* match after leading blanks */
    const char *repl;      /* replacement (after=0) or inserted line (1) */
    int after;             /* 1 keeps the matched line and inserts repl */
    int want_fail;         /* 1: the gate must refuse */
    const char *must_err;  /* text the refusal must contain, or NULL */
};

static const struct st_case k_st_cases[] = {
    { "PUBLISHED_PLATFORMS naming an unproduced platform", 0,
      "PUBLISHED_PLATFORMS=",
      "PUBLISHED_PLATFORMS=\" linux-x86_64 darwin-aarch64 \"", 0, 1,
      "publishes darwin-aarch64" },
    { "a published platform with no case arm", 0, "linux-x86_64) WANT=",
      "    never-matches) WANT=\"$BOOT_LINUX_X86_64\" ;;", 0, 1, NULL },
    { "a case arm for an unpublished platform", 0, "linux-x86_64) WANT=",
      "    darwin-aarch64) WANT=\"$BOOT_ZERO\" ;;", 1, 1, NULL },
    { "an install.ps1 row for an unproduced platform", 1,
      "$BootPins = @{",
      "$BootPins = @{\n    'windows-x86_64' = '" ST_Z64 "'\n}", 0, 1, NULL },
    { "FD_PUBLISHED naming an unpackaged runtime", 2, "#define FD_PUBLISHED",
      "#define FD_PUBLISHED \"linux-x86_64 darwin-aarch64\"", 0, 1, NULL },
    { "a non-sentinel digest checked into install.sh", 0,
      "BOOT_LINUX_X86_64=",
      "BOOT_LINUX_X86_64=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
      "deadbeefdeadbeef", 0, 1, NULL },
    { "a cpu fold that makes a produced platform unreachable", 0,
      "case \"$(uname -m)\" in ",
      "case \"$(uname -m)\" in x86_64|amd64) cpu=x86_64 ;; "
      "aarch64|arm64) cpu=aarch64 ;; *) cpu=\"$(uname -m)\" ;; esac",
      0, 1, "darwin-arm64" },
};

struct st_paths {
    char sh[ST_PATH], ps1[ST_PATH], fdc[ST_PATH], cutter[ST_PATH];
    char dsh[ST_PATH], dps1[ST_PATH], dfdc[ST_PATH];
};

/* ── file plumbing ────────────────────────────────────────────────────── */

static int st_read(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return die("z23-lint: cannot read selftest fixture %s\n", path);
    int rc = csr_slurp(f, g_st_in, sizeof g_st_in);
    fclose(f);
    if (rc)
        return die("z23-lint: selftest fixture %s too large or unreadable\n",
                   path);
    return 0;
}

static int st_copy(const char *src, const char *dst)
{
    int rc = st_read(src);
    if (rc)
        return rc;
    return csr_write(dst, g_st_in);
}

static size_t st_append(char *buf, size_t o, const char *s)
{
    size_t l = strlen(s);
    if (o + l + 1 > ST_OUT) {
        fprintf(stderr, "check-published-platforms: fixture text exceeds "
                "%d\n", ST_OUT);
        return (size_t)-1;
    }
    memcpy(buf + o, s, l);
    return o + l;
}

static int st_match(const char *line, const char *prefix)
{
    while (*line == ' ' || *line == '\t')
        line++;
    return strncmp(line, prefix, strlen(prefix)) == 0;
}

/* sed -i equivalent: replace (or insert after) the first-blank-prefixed
 * matching line of the fixture. */
static int st_mutate(const char *path, const char *prefix, const char *repl,
                     int after)
{
    int rc = st_read(path);
    if (rc)
        return rc;
    size_t o = 0;
    char *p = g_st_in;
    while (*p != '\0') {
        char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p + 1) : strlen(p);
        char line[ST_LINE];
        if (n >= sizeof line)
            return die("z23-lint: fixture line too long", "");
        memcpy(line, p, n);
        line[n] = '\0';
        int hit = st_match(line, prefix);
        o = st_append(g_st_out, o, hit && !after ? repl : line);
        if (hit && !after && o != (size_t)-1)
            o = st_append(g_st_out, o, "\n");
        if (hit && after && o != (size_t)-1) {
            o = st_append(g_st_out, o, repl);
            if (o != (size_t)-1)
                o = st_append(g_st_out, o, "\n");
        }
        if (o == (size_t)-1)
            return 2;
        p += n;
    }
    g_st_out[o] = '\0';
    return csr_write(path, g_st_out);
}

/* ── probes and cases ─────────────────────────────────────────────────── */

static int st_probe(const struct st_paths *pp, int want_fail,
                    const char *what, char *errbuf, size_t cap)
{
    FILE *eo = fmemopen(errbuf, cap, "w");
    FILE *oo = tmpfile();
    if (!eo || !oo) {
        if (eo)
            fclose(eo);
        return die("z23-lint: tmpfile or fmemopen failed\n", "");
    }
    int rc = ppp_check(pp->dsh, pp->dps1, pp->dfdc, pp->cutter, oo, eo);
    fclose(oo);
    fclose(eo);
    if (want_fail && rc == 0) {
        fprintf(stderr, "selftest FAIL: %s should have been refused\n", what);
        return 1;
    }
    if (!want_fail && rc != 0) {
        fprintf(stderr, "selftest FAIL: %s should have passed\n", what);
        return 1;
    }
    return 0;
}

static const char *st_src(const struct st_paths *pp, int file)
{
    return file == 0 ? pp->sh : file == 1 ? pp->ps1 : pp->fdc;
}

static const char *st_dst(const struct st_paths *pp, int file)
{
    return file == 0 ? pp->dsh : file == 1 ? pp->dps1 : pp->dfdc;
}

static int st_restore_all(const struct st_paths *pp);

static int st_run_case(const struct st_paths *pp, const struct st_case *c,
                       char *errbuf)
{
    /* every case starts from the pristine tree: no residue from the case before */
    int rc = st_restore_all(pp);
    if (rc)
        return rc;
    rc = st_mutate(st_dst(pp, c->file), c->prefix, c->repl, c->after);
    if (rc)
        return rc;
    memset(errbuf, 0, ST_ERR);
    rc = st_probe(pp, c->want_fail, c->name, errbuf, ST_ERR);
    if (rc)
        return rc;
    if (c->must_err && strstr(errbuf, c->must_err) == NULL) {
        fprintf(stderr, "selftest FAIL: %s: the refusal must name the "
                "platform\n", c->name);
        return 1;
    }
    return 0;
}

static int st_restore_all(const struct st_paths *pp)
{
    for (int i = 0; i < 3; i++) {
        int rc = st_copy(st_src(pp, i), st_dst(pp, i));
        if (rc)
            return rc;
    }
    return 0;
}

static int st_all_cases(const struct st_paths *pp)
{
    char errbuf[ST_ERR];
    memset(errbuf, 0, sizeof errbuf);
    if (ppp_fold_tail_probe() != 0)
        return die("z23-lint: check-published-platforms selftest: a fold "
                   "pattern ending in * read past its terminator%s\n", "");
    int rc = st_probe(pp, 0, "the tree as checked in", errbuf, ST_ERR);
    for (size_t i = 0; rc == 0 && i < sizeof k_st_cases / sizeof
         k_st_cases[0]; i++)
        rc = st_run_case(pp, &k_st_cases[i], errbuf);
    if (rc)
        return rc;
    rc = st_restore_all(pp);
    if (rc)
        return rc;
    memset(errbuf, 0, sizeof errbuf);
    return st_probe(pp, 0, "the restored tree", errbuf, ST_ERR);
}

/* ── setup and entry ──────────────────────────────────────────────────── */

static int st_sources(struct st_paths *pp)
{
    if (ovf(snprintf(pp->sh, ST_PATH, "%s", env_or("ZCL_PP_INSTALL_SH",
             "platform/packaging/install/install.sh")), ST_PATH))
        return 2;
    if (ovf(snprintf(pp->ps1, ST_PATH, "%s", env_or("ZCL_PP_INSTALL_PS1",
             "platform/packaging/install/install.ps1")), ST_PATH))
        return 2;
    if (ovf(snprintf(pp->fdc, ST_PATH, "%s", env_or("ZCL_PP_FRONT_DOOR_C",
             "platform/modules/install/src/front_door_platform.c")),
             ST_PATH))
        return 2;
    return ovf(snprintf(pp->cutter, ST_PATH, "%s", env_or("ZCL_PP_CUTTER",
               "platform/packaging/release/build_release.sh")), ST_PATH)
           ? 2 : 0;
}

static int st_scratch(char *out, size_t cap)
{
    const char *td = env_or("TMPDIR", "test-tmp");
    if (csr_mkdirs(td) != 0)
        return die("z23-lint: cannot create selftest scratch root\n", "");
    if (ovf(snprintf(out, cap, "%s/z23-lint-pubplat.XXXXXX", td), cap))
        return 2;
    if (!mkdtemp(out))
        return die("z23-lint: mkdtemp failed for selftest scratch\n", "");
    return 0;
}

static int st_fixture_paths(struct st_paths *pp, const char *tmpdir)
{
    if (ovf(snprintf(pp->dsh, ST_PATH, "%s/%s", tmpdir, k_st_names[0]),
             ST_PATH))
        return 2;
    if (ovf(snprintf(pp->dps1, ST_PATH, "%s/%s", tmpdir, k_st_names[1]),
             ST_PATH))
        return 2;
    return ovf(snprintf(pp->dfdc, ST_PATH, "%s/%s", tmpdir, k_st_names[2]),
               ST_PATH) ? 2 : 0;
}

int check_published_platforms_selftest(void)
{
    char tmpdir[ST_PATH];
    struct st_paths pp;
    int rc = st_sources(&pp);
    if (rc == 0)
        rc = st_scratch(tmpdir, sizeof tmpdir);
    if (rc == 0)
        rc = st_fixture_paths(&pp, tmpdir);
    if (rc)
        return rc;
    rc = st_restore_all(&pp);
    if (rc == 0)
        rc = st_all_cases(&pp);
    rap_rm_rf(tmpdir);
    if (rc) {
        fputs("FAIL: check-published-platforms selftest\n", stderr);
        return 1;
    }
    printf("check-published-platforms: selftest PASS (7 mutations "
           "refused)\n");
    return 0;
}
