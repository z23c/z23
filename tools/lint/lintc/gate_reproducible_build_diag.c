/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: mismatch diagnosis for check-reproducible-build — the MISMATCH
 * report, the first-divergence offset, the strings-style leakage dumps for both
 * binaries, and the likely-cause HINTS checklist. Ported from the diagnose
 * section of tools/scripts/check_reproducible_build.sh (deleted).
 *
 * The dumps mirror `strings | grep -aE PATTERN | sort -u | head -N`: runs of
 * printable bytes (4 or more) are matched as they stream, and a bounded sorted
 * set keeps the N smallest unique matches, so no run list is ever stored.
 * Runs longer than RP_KLEN-1 bytes are cut to that length before matching.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "lintc.h"
#include "gate_reproducible_build_priv.h"

enum { RP_KLEN = 512, RP_TOPMAX = 20, RP_MINRUN = 4, RP_LINE = 2400 };

struct rpb_top {
    char rows[RP_TOPMAX][RP_KLEN];
    int n;
    int cap;
};

static void rpb_mm(FILE *err, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fputs("\033[31m[repro] MISMATCH:\033[0m ", err);
    vfprintf(err, fmt, ap);
    fputc('\n', err);
    va_end(ap);
}

static void rpb_section(FILE *err, const char *label)
{
    fprintf(err, "\n\033[33m[repro] \342\200\224\342\200\224 %s "
            "\342\200\224\342\200\224\033[0m\n", label);
}

/* grep -E 'GNU[[:space:]].*ld' */
static int rpb_match_gnu_ld(const char *s)
{
    for (const char *g = strstr(s, "GNU"); g; g = strstr(g + 1, "GNU")) {
        if ((g[3] == ' ' || g[3] == '\t') && strstr(g + 4, "ld"))
            return 1;
    }
    return 0;
}

/* grep -E 'build.id': "build", any one byte, "id". */
static int rpb_match_build_dot_id(const char *s)
{
    for (const char *p = strstr(s, "build"); p; p = strstr(p + 1, "build")) {
        if (p[5] && p[6] == 'i' && p[7] == 'd')
            return 1;
    }
    return 0;
}

static int rpb_match_buildid(const char *s)
{
    return strstr(s, "BuildID") != NULL || rpb_match_build_dot_id(s) ||
           rpb_match_gnu_ld(s);
}

/* grep -aE '/tmp/|/var/tmp/|\.XXXXXX|build_[ab]|/__DATE__/|__TIME__' */
static int rpb_match_paths(const char *s)
{
    static const char *const pat[] = { "/tmp/", "/var/tmp/", ".XXXXXX",
        "build_a", "build_b", "/__DATE__/", "__TIME__" };
    for (size_t i = 0; i < sizeof pat / sizeof pat[0]; i++)
        if (strstr(s, pat[i]))
            return 1;
    return 0;
}

/* Insert s into the sorted unique set, keeping at most cap rows. */
static void rpb_top_add(struct rpb_top *t, const char *s)
{
    int at = 0;
    while (at < t->n && strcmp(t->rows[at], s) < 0)
        at++;
    if (at < t->n && strcmp(t->rows[at], s) == 0)
        return;
    if (t->n == t->cap) {
        if (at == t->n)
            return;
        t->n--;
    }
    for (int i = t->n; i > at; i--)
        memcpy(t->rows[i], t->rows[i - 1], RP_KLEN);
    memcpy(t->rows[at], s, strlen(s) + 1);
    t->n++;
}

static void rpb_top_offer(struct rpb_top *t, const char *run,
                          int (*match)(const char *))
{
    if (match(run))
        rpb_top_add(t, run);
}

/* Stream path's printable runs (length >= RP_MINRUN) through match. */
static int rpb_scan(const char *path, int (*match)(const char *),
                     struct rpb_top *t)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return 2;
    char run[RP_KLEN];
    size_t rl = 0;
    unsigned char buf[8192];
    for (;;) {
        size_t nr = fread(buf, 1, sizeof buf, f);
        for (size_t i = 0; i < nr; i++) {
            unsigned c = buf[i];
            if (c >= 0x20 && c <= 0x7e) {
                if (rl + 1 < sizeof run)
                    run[rl++] = (char)c;
                continue;
            }
            if (rl >= RP_MINRUN) {
                run[rl] = '\0';
                rpb_top_offer(t, run, match);
            }
            rl = 0;
        }
        if (nr < sizeof buf)
            break;
    }
    if (rl >= RP_MINRUN) {
        run[rl] = '\0';
        rpb_top_offer(t, run, match);
    }
    int bad = ferror(f);
    fclose(f);
    return bad ? 2 : 0;
}

static void rpb_dump_top(FILE *err, const char *label, const struct rpb_top *t)
{
    rpb_section(err, label);
    for (int i = 0; i < t->n; i++)
        fprintf(err, "%s\n", t->rows[i]);
}

static int rpb_dump_one(FILE *err, const char *path, const char *label,
                        int (*match)(const char *), int head)
{
    struct rpb_top t;
    memset(&t, 0, sizeof t);
    t.cap = head;
    if (rpb_scan(path, match, &t))
        return 2;
    rpb_dump_top(err, label, &t);
    return 0;
}

static int rpb_dump_likely(FILE *err, const char *path, const char *label)
{
    char hdr[RP_KLEN];
    if (ovf(snprintf(hdr, sizeof hdr, "%s: paths / dates / temp-dir leakage",
                     label), sizeof hdr))
        return 2;
    if (rpb_dump_one(err, path, hdr, rpb_match_paths, 20))
        return 2;
    if (ovf(snprintf(hdr, sizeof hdr, "%s: embedded build-id / GNU ld version",
                     label), sizeof hdr))
        return 2;
    return rpb_dump_one(err, path, hdr, rpb_match_buildid, 10);
}

static void rpb_hints(FILE *err, const char *work)
{
    fprintf(err, "\n[repro] Likely-cause checklist (build config, NOT node "
            "code):\n"
            "  1. Embedded absolute build path \342\200\224 a configure/cmake "
            "step baked $PWD or a\n"
            "     temp dir into a vendored .a (OpenSSL OPENSSLDIR, libevent, "
            "leveldb). Fix\n"
            "     in tools/scripts/build_vendor.sh with a neutral --prefix.\n"
            "  2. __DATE__ / __TIME__ macros in source \342\200\224 "
            "non-reproducible by construction;\n"
            "     SOURCE_DATE_EPOCH can't reach them unless the compiler's "
            "-Wdate-time is\n"
            "     honored and the macro replaced.\n"
            "  3. Nondeterministic link order \342\200\224 LTO partitioning "
            "or an unstable glob in the\n"
            "     link line. Sort the source list, or pin ARFLAGS=Dcr "
            "(build_vendor.sh\n"
            "     already does for .a archives).\n"
            "  4. build-id \342\200\224 should already be dropped by "
            "-Wl,--build-id=none in REL_LDFLAGS;\n"
            "     if it appears, the flag did not reach the final link.\n"
            "  5. generated inputs or toolchain drift outside the captured "
            "source inventory.\n"
            "     Git commit ids are intentionally not embedded in the "
            "sovereign binary;\n"
            "     GitHub trace metadata belongs in an external publication "
            "sidecar.\n"
            "\n[repro] KEEP=1 retains the two build dirs under %s for "
            "byte-level forensics.\n", work);
}

/* The divergence line is cmp's own wording, which depends on the locale and
 * the cmp version, so it is taken from cmp: `cmp -n` first, then plain cmp when
 * that prints nothing recognisable, as the shell script did. stdout and stderr
 * are both captured (cmp reports EOF on stderr). */
static int rpb_cmp_line(char *const envp[], const char *a, const char *b,
                        char *out, size_t cap)
{
    char *argv_n[] = { (char *)"cmp", (char *)"-n", (char *)"100000000",
                       (char *)a, (char *)b, NULL };
    char *argv_p[] = { (char *)"cmp", (char *)a, (char *)b, NULL };
    int code = 0;
    if (rpb_spawn(argv_n, envp, RPB_OUT_BOTH, out, cap, &code))
        return 2;
    if (!strstr(out, "differ") && !strstr(out, "byte") &&
        rpb_spawn(argv_p, envp, RPB_OUT_BOTH, out, cap, &code))
        return 2;
    size_t n = strlen(out);
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r'))
        out[--n] = '\0';
    return 0;
}

static int rpb_first_divergence(FILE *err, char *const envp[], const char *bin_a,
                                const char *bin_b)
{
    char line[RP_LINE];
    if (rpb_cmp_line(envp, bin_a, bin_b, line, sizeof line))
        return 2;
    rpb_mm(err, "first divergence: %s", line);
    return 0;
}

static int rpb_mismatch_head(FILE *err, const char *binary, const char *algo,
                             const char *hash_a, const char *hash_b, long sa,
                             long sb)
{
    fputc('\n', err);
    rpb_mm(err, "two builds of '%s' are NOT byte-identical.", binary);
    rpb_mm(err, "  A %s=%s  size=%ld", algo, hash_a, sa);
    rpb_mm(err, "  B %s=%s  size=%ld", algo, hash_b, sb);
    if (sa != sb)
        rpb_mm(err, "sizes differ by %ld bytes \342\200\224 a different amount "
               "of content was embedded.", sb - sa);
    return 0;
}

int rpb_diag(FILE *err, char *const envp[], const char *bin_a, const char *bin_b,
             const char *hash_a, const char *hash_b, const char *algo,
             const char *binary, long sa, long sb, const char *work)
{
    if (rpb_mismatch_head(err, binary, algo, hash_a, hash_b, sa, sb) ||
        rpb_first_divergence(err, envp, bin_a, bin_b) ||
        rpb_dump_likely(err, bin_a, "Build A") ||
        rpb_dump_likely(err, bin_b, "Build B"))
        return 2;
    rpb_hints(err, work ? work : "");
    return 0;
}
