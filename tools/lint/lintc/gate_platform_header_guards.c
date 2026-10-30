// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// purpose: gate check-platform-header-guards — a platform-only system
// header may not be included outside a conditional naming that platform.
// Ported from tools/lint/check_platform_header_guards.sh (deleted); see the
// script's history for the WHY (unguarded <mach-o/fat.h> in 1e1ce62af) and
// the derivation of the table below. Exemptions are parsed from the build
// itself: the Makefile LIB_SRCS per-host branch and the Windows acceptance
// catalog. Selftest: gate_platform_header_guards_selftest.c.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "lintc.h"
#include "gate_platform_header_guards_priv.h"

static const char k_phg_gate[] = "check-platform-header-guards";
static const char k_phg_win_cat[] = "platform/modules/platform/tests/windows_acceptance.mk";
static const char k_phg_win_pfx[] = "platform/modules/platform/tests/";

struct phg_row { const char *pref, *macs, *plat; };
static const struct phg_row k_phg_table[] = {
    { "mach-o/", "__APPLE__ __MACH__", "Apple SDK" },
    { "mach/", "__APPLE__ __MACH__", "Apple SDK" },
    { "CoreFoundation/", "__APPLE__", "Apple SDK" },
    { "CoreGraphics/", "__APPLE__", "Apple SDK" },
    { "CoreVideo/", "__APPLE__", "Apple SDK" },
    { "CoreServices/", "__APPLE__", "Apple SDK" },
    { "Foundation/", "__APPLE__", "Apple SDK" },
    { "Security/", "__APPLE__", "Apple SDK" },
    { "IOKit/", "__APPLE__", "Apple SDK" },
    { "ApplicationServices/", "__APPLE__", "Apple SDK" },
    { "objc/", "__APPLE__", "Apple SDK" },
    { "libproc.h", "__APPLE__", "Apple SDK" },
    { "crt_externs.h", "__APPLE__", "Apple SDK" },
    { "sys/qos.h", "__APPLE__", "Apple SDK" },
    { "sys/event.h", "__APPLE__ __FreeBSD__ __OpenBSD__ __NetBSD__ BSD", "kqueue (Apple/BSD)" },
    { "sys/sysctl.h", "__APPLE__ __FreeBSD__ __OpenBSD__ __NetBSD__ BSD", "sysctl (Apple/BSD)" },
    { "windows.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "winsock2.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "ws2tcpip.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "winternl.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "winuser.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "windowsx.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "winbase.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "winnt.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "wincrypt.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "shellscalingapi.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "shellapi.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "shlobj.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "knownfolders.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "aclapi.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "sddl.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "tlhelp32.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "psapi.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "bcrypt.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "netioapi.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "iphlpapi.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "mswsock.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "dxgi.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "io.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "process.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "direct.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "processthreadsapi.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "synchapi.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "fileapi.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "handleapi.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "memoryapi.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "namedpipeapi.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "errhandlingapi.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "sysinfoapi.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "libloaderapi.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "securitybaseapi.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "versionhelpers.h", "_WIN32 _WIN64 __MINGW32__ __CYGWIN__", "Win32" },
    { "sys/epoll.h", "__linux__ __linux __gnu_linux__", "Linux" },
    { "sys/inotify.h", "__linux__ __linux __gnu_linux__", "Linux" },
    { "sys/prctl.h", "__linux__ __linux __gnu_linux__", "Linux" },
    { "sys/sysinfo.h", "__linux__ __linux __gnu_linux__", "Linux" },
    { "sys/sysmacros.h", "__linux__ __linux __gnu_linux__", "Linux" },
    { "sys/auxv.h", "__linux__ __linux __gnu_linux__ __GLIBC__", "Linux" },
    { "linux/", "__linux__ __linux __gnu_linux__", "Linux" },
    { "liburing.h", "__linux__ __linux __gnu_linux__", "Linux" },
};

enum { PHG_EXN = 2048, PHG_FILES = 8192, PHG_FIND = 256, PHG_FINDROW = 1400,
       PHG_WIN = 512, PHG_MKOUT = 2048, PHG_BR = 16 };

struct phg_ex { char file[PHG_PATH]; char macro[24]; };
static struct phg_ex g_phg_ex[PHG_EXN];
static int g_phg_ex_n;
static char g_phg_files[PHG_FILES][PHG_PATH];
static int g_phg_file_n, g_phg_cand_n;
static char g_phg_find[PHG_FIND][PHG_FINDROW];
static int g_phg_find_n;
static char g_phg_roots[128];

static int phg_ex_add(const char *file, const char *macro)
{
    if (g_phg_ex_n >= PHG_EXN) {
        fprintf(stderr, "%s: exemption entries exceed %d\n", k_phg_gate,
                PHG_EXN);
        return 2;
    }
    if (strlen(file) >= PHG_PATH || strlen(macro) >= 24)
        return 2;
    strcpy(g_phg_ex[g_phg_ex_n].file, file);
    strcpy(g_phg_ex[g_phg_ex_n].macro, macro);
    g_phg_ex_n++;
    return 0;
}

static int phg_floor(int count, int floor, const char *hint, FILE *err)
{
    if (count >= floor)
        return 0;
    fprintf(err,
            "%s: FATAL — scan set is '%d' (< floor %d).\n"
            "  The scan producer (find/glob) returned too little; a\n"
            "  scanned dir/file was likely renamed, moved, or deleted.\n"
            "  Refusing to report 'clean' off a hollow (empty) scan.\n"
            "  %s\n", k_phg_gate, count, floor, hint);
    return 2;
}

// ── Makefile LIB_SRCS per-host branch parse ─────────────────────────────

struct phg_mk {
    int inb, b, nb, branchn;
    char lab[PHG_BR][24];
    int known[PHG_BR];
    char ofile[PHG_MKOUT][PHG_PATH];
    unsigned char ob[PHG_MKOUT];
    int on;
};

static void phg_branch(struct phg_mk *m, int idx, const char *cond)
{
    if (idx >= PHG_BR)
        return;
    if (strstr(cond, "Linux"))
        strcpy(m->lab[idx], "__linux__");
    else if (strstr(cond, "ZCL_HOST_WINDOWS") || strstr(cond, "MINGW"))
        strcpy(m->lab[idx], "_WIN32");
    else
        strcpy(m->lab[idx], "__APPLE__");
    m->known[idx] = 1;
    m->branchn++;
    if (idx + 1 > m->nb)
        m->nb = idx + 1;
}

static int phg_out_add(struct phg_mk *m, int b, const char *f, size_t n)
{
    if (m->on >= PHG_MKOUT) {
        fprintf(stderr, "%s: LIB_SRCS filtered sources exceed %d\n",
                k_phg_gate, PHG_MKOUT);
        return 2;
    }
    if (n >= PHG_PATH)
        return 2;
    memcpy(m->ofile[m->on], f, n);
    m->ofile[m->on][n] = '\0';
    m->ob[m->on] = (unsigned char)b;
    m->on++;
    return 0;
}

// Every (root)/[A-Za-z0-9_/]+\.c occurrence on a LIB_SRCS line.
static int phg_grab_roots(const char *line, int b, struct phg_mk *m)
{
    static const char *rk[] = { "core", "engine", "contexts", "cognition",
                                "platform" };
    size_t i = 0, len = strlen(line);
    while (i < len) {
        int hit = -1;
        for (int r = 0; r < 5; r++)
            if (!strncmp(line + i, rk[r], strlen(rk[r]))) {
                hit = r;
                break;
            }
        if (hit < 0 || line[i + strlen(rk[hit])] != '/') {
            i++;
            continue;
        }
        size_t k = i + strlen(rk[hit]) + 1;
        while (k < len && (isalnum((unsigned char)line[k]) || line[k] == '_' ||
                           line[k] == '/'))
            k++;
        if (k + 1 < len && line[k] == '.' && line[k + 1] == 'c') {
            int rc = phg_out_add(m, b, line + i, k + 2 - i);
            if (rc)
                return rc;
        }
        i = k;
    }
    return 0;
}

static int phg_mk_cb(void *ctx, const char *line, size_t len)
{
    struct phg_mk *m = ctx;
    char buf[PHG_LINE];
    if (len > 0 && line[len - 1] == '\n')
        len--;
    if (len >= sizeof buf)
        return 2;
    memcpy(buf, line, len);
    buf[len] = '\0';
    if (!strcmp(buf, "ifneq ($(filter Linux,$(ZCL_HOST_OS)),)") ||
        !strcmp(buf, "ifeq ($(ZCL_HOST_OS),Linux)")) {
        m->inb = 1;
        m->b = 0;
        phg_branch(m, 0, buf);
        return 0;
    }
    if (!m->inb)
        return 0;
    if (!strcmp(buf, "endif")) {
        m->inb = 0;
        return 0;
    }
    if (!strncmp(buf, "else", 4)) {
        m->b++;
        phg_branch(m, m->b, buf);
        return 0;
    }
    return phg_grab_roots(buf, m->b, m);
}

// Is ofile[i] filtered out of every branch but one (and is that one known)?
static int phg_exclusive_one(const struct phg_mk *m, int i)
{
    int surv = -1, cnt = 0;
    for (int b = 0; b < m->nb; b++) {
        int out = 0;
        for (int j = 0; j < m->on; j++)
            if (m->ob[j] == b && !strcmp(m->ofile[j], m->ofile[i])) {
                out = 1;
                break;
            }
        if (!out) {
            surv = b;
            cnt++;
        }
    }
    if (cnt == 1 && surv >= 0 && surv < PHG_BR && m->known[surv])
        return surv;
    return -1;
}

static int phg_load_libsrcs(const char *root, FILE *err)
{
    char path[PHG_PATH];
    struct stat st;
    if (ovf(snprintf(path, sizeof path, "%s/Makefile", root), sizeof path))
        return 2;
    if (stat(path, &st) != 0) {
        fprintf(err, "%s: FATAL — no Makefile under %s.\n", k_phg_gate, root);
        return 2;
    }
    static struct phg_mk m;
    memset(&m, 0, sizeof m);
    if (lc_each_line(path, phg_mk_cb, &m, 1))
        return 2;
    if (m.branchn < 2) {
        fprintf(err,
                "%s: FATAL — could not read the LIB_SRCS per-host branch out of Makefile.\n"
                "  This gate derives its platform-exclusive file set from that block\n"
                "  (the 'ifneq ($(filter Linux,$(ZCL_HOST_OS)),)' ... else ... endif\n"
                "  around LIB_SRCS := $(filter-out ...)). It found %d branch(es).\n"
                "  Either the block was rewritten into a shape the parser does not know,\n"
                "  or it is gone. Refusing to grade with an exemption set it cannot read:\n"
                "  an empty set turns build-exclusive files into false failures and a\n"
                "  wrong set hides real ones.\n", k_phg_gate, m.branchn);
        return 2;
    }
    for (int i = 0; i < m.on; i++) {
        int sv = phg_exclusive_one(&m, i);
        int dup = 0;
        for (int j = 0; j < i && !dup; j++)
            dup = !strcmp(m.ofile[j], m.ofile[i]);
        if (sv >= 0 && !dup)
            if (phg_ex_add(m.ofile[i], m.lab[sv]))
                return 2;
    }
    return 0;
}

// ── Windows acceptance catalog ──────────────────────────────────────────

static char g_phg_win[PHG_WIN][96];

struct phg_wctx { int n; };

static int phg_win_cb(void *ctx, const char *line, size_t len)
{
    struct phg_wctx *w = ctx;
    char buf[PHG_LINE];
    if (len > 0 && line[len - 1] == '\n')
        len--;
    if (len >= sizeof buf)
        return 2;
    memcpy(buf, line, len);
    buf[len] = '\0';
    const char *p = buf;
    size_t pl = strlen(k_phg_win_pfx);
    while ((p = strstr(p, k_phg_win_pfx)) != NULL) {
        p += pl;
        size_t n = 0;
        while (isalnum((unsigned char)p[n]) || p[n] == '_')
            n++;
        if (n > 0 && p[n] == '.' && p[n + 1] == 'c' && w->n < PHG_WIN)
            snprintf(g_phg_win[w->n++], 96, "%s%.*s.c", k_phg_win_pfx,
                     (int)n, p);
        if (p[n] == '\0')
            break;
        p += n + 1;
    }
    return 0;
}

static int phg_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static int phg_load_wincat(const char *root, int floor, FILE *err)
{
    char path[PHG_PATH];
    struct stat st;
    if (ovf(snprintf(path, sizeof path, "%s/%s", root, k_phg_win_cat),
            sizeof path))
        return 2;
    if (stat(path, &st) != 0) {
        fprintf(err, "%s: FATAL — missing %s under %s.\n"
                "  The Windows-exclusive exemption set is parsed out of that catalog.\n",
                k_phg_gate, k_phg_win_cat, root);
        return 2;
    }
    struct phg_wctx w = { 0 };
    if (lc_each_line(path, phg_win_cb, &w, 1))
        return 2;
    qsort(g_phg_win, (size_t)w.n, 96, phg_cmp);
    int uniq = 0;
    for (int i = 0; i < w.n; i++)
        if (uniq == 0 || strcmp(g_phg_win[uniq - 1], g_phg_win[i]))
            strcpy(g_phg_win[uniq++], g_phg_win[i]);
    if (uniq < floor) {
        fprintf(err,
                "%s: FATAL — %s yielded only %d source(s) (floor %d).\n"
                "  Expected the ZCL_WINDOWS_ACCEPTANCE_*_SOURCES rows. A parse this thin\n"
                "  means the catalog moved or changed shape; refusing to grade the\n"
                "  Windows acceptance programs against an exemption set it cannot read.\n",
                k_phg_gate, k_phg_win_cat, uniq, floor);
        return 2;
    }
    for (int i = 0; i < uniq; i++)
        if (phg_ex_add(g_phg_win[i], "_WIN32"))
            return 2;
    return 0;
}

// ── The file set ────────────────────────────────────────────────────────

static int phg_add_file(const char *rel)
{
    if (g_phg_file_n >= PHG_FILES) {
        fprintf(stderr, "%s: file count exceeds %d\n", k_phg_gate, PHG_FILES);
        return 2;
    }
    if (strlen(rel) >= PHG_PATH)
        return 2;
    strcpy(g_phg_files[g_phg_file_n++], rel);
    return 0;
}

static int phg_walk_dir(const char *root, const char *rel)
{
    char path[PHG_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/%s", root, rel), sizeof path))
        return 2;
    DIR *d = opendir(path);
    if (!d) {
        fprintf(stderr, "%s: cannot read directory %s\n", k_phg_gate, path);
        return 2;
    }
    struct dirent *e;
    int rc = 0;
    while (rc == 0 && (e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.')
            continue;
        char r2[PHG_PATH];
        if (ovf(snprintf(r2, sizeof r2, "%s%s%s", rel, *rel ? "/" : "",
                         e->d_name), sizeof r2)) {
            rc = 2;
            break;
        }
        char full[PHG_PATH];
        struct stat st;
        if (ovf(snprintf(full, sizeof full, "%s/%s", root, r2),
                 sizeof full) ||
            stat(full, &st) != 0) {
            rc = 2;
            break;
        }
        size_t n = strlen(r2);
        if (S_ISDIR(st.st_mode))
            rc = phg_walk_dir(root, r2);
        else if (n > 2 && r2[n - 2] == '.' && (r2[n - 1] == 'c' ||
                   r2[n - 1] == 'h'))
            rc = phg_add_file(r2);
    }
    closedir(d);
    return rc;
}

static int phg_file_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static int phg_collect(const char *root, FILE *err)
{
    static const char *rk[] = { "core", "engine", "contexts", "cognition",
                                "platform" };
    char dir[PHG_PATH];
    struct stat st;
    g_phg_roots[0] = '\0';
    for (size_t i = 0; i < sizeof rk / sizeof rk[0]; i++) {
        if (ovf(snprintf(dir, sizeof dir, "%s/%s", root, rk[i]), sizeof dir))
            return 2;
        if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode))
            continue;
        strcat(g_phg_roots, rk[i]);
        strcat(g_phg_roots, " ");
        int rc = phg_walk_dir(root, rk[i]);
        if (rc)
            return rc;
    }
    if (!g_phg_roots[0]) {
        fprintf(err, "%s: FATAL — none of the scan roots (core engine "
                "contexts cognition platform) exist under %s.\n", k_phg_gate,
                root);
        return 2;
    }
    g_phg_roots[strlen(g_phg_roots) - 1] = '\0';
    qsort(g_phg_files, (size_t)g_phg_file_n, PHG_PATH, phg_file_cmp);
    return 0;
}

// Pre-filter: does the file text mention any table header (plain substring)?
static int phg_is_cand(const char *path)
{
    static char buf[1 << 20];
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    size_t n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    if (n == sizeof buf)
        return 1;
    for (size_t i = 0; i < sizeof k_phg_table / sizeof k_phg_table[0]; i++)
        if (memmem(buf, n, k_phg_table[i].pref,
                   strlen(k_phg_table[i].pref)))
            return 1;
    return 0;
}

// ── Grading ─────────────────────────────────────────────────────────────

struct phg_g { int inc, seen, found; const char *mode; FILE *out; };

static int phg_row_match(const char *hdr)
{
    for (size_t i = 0; i < sizeof k_phg_table / sizeof k_phg_table[0]; i++) {
        const char *p = k_phg_table[i].pref;
        size_t n = strlen(p);
        if (p[n - 1] == '/' ? !strncmp(hdr, p, n) : !strcmp(hdr, p))
            return (int)i;
    }
    return -1;
}

static int phg_is_exempt(const char *file, const char *mac, size_t n)
{
    for (int i = 0; i < g_phg_ex_n; i++)
        if (!strcmp(g_phg_ex[i].file, file) &&
            strlen(g_phg_ex[i].macro) == n &&
            !strncmp(g_phg_ex[i].macro, mac, n))
            return 1;
    return 0;
}

static int phg_ok_why(const struct phg_inc *inc, int r, char *why, size_t cap)
{
    char pat[96], hi[320];
    const char *m = k_phg_table[r].macs;
    while (*m) {
        while (*m == ' ')
            m++;
        size_t n = 0;
        while (m[n] && m[n] != ' ')
            n++;
        if (n && n + 3 < sizeof pat) {
            snprintf(pat, sizeof pat, " %.*s ", (int)n, m);
            if (strstr(inc->act, pat)) {
                snprintf(why, cap, "guard %.*s", (int)n, m);
                return 1;
            }
            if (phg_is_exempt(inc->file, m, n)) {
                snprintf(why, cap, "build-exclusive %.*s", (int)n, m);
                return 1;
            }
        }
        m += n;
    }
    snprintf(hi, sizeof hi, "__has_include(<%s>)", inc->hdr);
    if (strstr(inc->raw, hi)) {
        snprintf(why, cap, "__has_include(<%.100s>)", inc->hdr);
        return 1;
    }
    return 0;
}

static int phg_grade(struct phg_g *g, const struct phg_inc *inc, int r)
{
    char why[160];
    if (phg_ok_why(inc, r, why, sizeof why)) {
        if (!strcmp(g->mode, "list"))
            fprintf(g->out, "ok   %s:%ld <%s> (%s)\n", inc->file, inc->ln,
                    inc->hdr, why);
        return 0;
    }
    g->found++;
    if (!strcmp(g->mode, "list")) {
        fprintf(g->out, "FAIL %s:%ld <%s> needs %s\n", inc->file, inc->ln,
                inc->hdr, k_phg_table[r].macs);
        return 0;
    }
    if (g_phg_find_n >= PHG_FIND) {
        fprintf(stderr, "%s: findings exceed %d\n", k_phg_gate, PHG_FIND);
        return 2;
    }
    if (ovf(snprintf(g_phg_find[g_phg_find_n++], PHG_FINDROW,
                     "    %s:%ld\t<%s>\t%s\trequires one of: %s", inc->file,
                     inc->ln, inc->hdr, k_phg_table[r].plat,
                     k_phg_table[r].macs), PHG_FINDROW))
        return 2;
    return 0;
}

static int phg_classify(const struct phg_inc *inc, void *ctx)
{
    struct phg_g *g = ctx;
    g->inc++;
    int r = phg_row_match(inc->hdr);
    if (r < 0)
        return 0;
    g->seen++;
    return phg_grade(g, inc, r);
}

// Reset state, read the build-derived exemptions, collect the file set.
static int phg_prepare(const char *root, int src_floor, int wincat_floor,
                       FILE *err)
{
    char hint[256];
    g_phg_ex_n = g_phg_file_n = g_phg_find_n = g_phg_cand_n = 0;
    if (phg_load_libsrcs(root, err) || phg_load_wincat(root, wincat_floor, err))
        return 2;
    if (phg_collect(root, err))
        return 2;
    if (ovf(snprintf(hint, sizeof hint, "scanned %s for .c/.h — a directory "
                    "move would empty this", g_phg_roots), sizeof hint))
        return 2;
    return phg_floor(g_phg_file_n, src_floor, hint, err) ? 2 : 0;
}

// Scan every collected file that mentions a table header.
static int phg_scan_loop(const char *root, struct phg_g *g, FILE *err)
{
    char path[PHG_PATH];
    for (int i = 0; i < g_phg_file_n; i++) {
        if (ovf(snprintf(path, sizeof path, "%s/%s", root, g_phg_files[i]),
                 sizeof path))
            return 2;
        int c = phg_is_cand(path);
        if (c < 0) {
            fprintf(err, "%s: FATAL — cannot read %s\n", k_phg_gate, path);
            return 2;
        }
        if (!c)
            continue;
        g_phg_cand_n++;
        int r2 = phg_scan_file(path, g_phg_files[i], phg_classify, g);
        if (r2 == 1)
            fprintf(err, "%s: FATAL — candidate vanished: %s\n", k_phg_gate,
                    g_phg_files[i]);
        if (r2)
            return 2;
    }
    return 0;
}

static void phg_report_found(const struct phg_g *g, FILE *err)
{
    fprintf(err, "  %s: FAIL — %d platform-only header include(s) with no "
            "matching guard:\n", k_phg_gate, g->found);
    for (int i = 0; i < g_phg_find_n; i++)
        fprintf(err, "%s\n", g_phg_find[i]);
    fprintf(err, "\n"
            "  A header that ships only with one platform's SDK must sit inside an\n"
            "  #if/#ifdef whose condition names that platform. Without it the FIRST\n"
            "  build on any other host dies with 'No such file or directory', which\n"
            "  is exactly how main went red on 2026-08-29 with <mach-o/fat.h>.\n"
            "\n"
            "  Fix, in order of preference:\n"
            "    1. Guard the hunk:      #if defined(<MACRO>) ... #endif\n"
            "    2. Guard the whole TU, and give the other platforms one\n"
            "       declaration so the file is not an empty translation unit\n"
            "       (ISO C forbids that under -Wpedantic -Werror). See\n"
            "       engine/modules/hotswap/src/hotswap_macho_probe.c for the shape.\n"
            "    3. If the file is compiled on ONE platform only, say so in the\n"
            "       BUILD (the LIB_SRCS host branch in Makefile, or the Windows\n"
            "       acceptance catalog) — this gate reads both and exempts what\n"
            "       the build itself excludes. Do not add a list to this script.\n");
}

int phg_run_scan(const char *root, int src_floor, int cand_floor,
                 int inc_floor, int seen_floor, int wincat_floor,
                 const char *mode, FILE *out, FILE *err)
{
    if (phg_prepare(root, src_floor, wincat_floor, err))
        return 2;
    struct phg_g g = { 0, 0, 0, mode, out };
    if (phg_scan_loop(root, &g, err))
        return 2;
    if (phg_floor(g_phg_cand_n, cand_floor, "no file in the scan roots even "
                  "mentions a table header — the pre-filter is broken, not "
                  "the tree", err) ||
        phg_floor(g.inc, inc_floor, "the scanner found almost no "
                  "#include <...> lines; it is broken, not the tree", err))
        return 2;
    if (!strcmp(mode, "list")) {
        fprintf(out, "-- %d classified include(s), %d unguarded\n", g.seen,
                g.found);
        return 0;
    }
    if (strcmp(mode, "quiet"))
        fprintf(out, "══ LINT: platform header guards (%d files, %d includes, "
                "%d build-exclusive exemption(s)) ══\n", g_phg_file_n, g.inc,
                g_phg_ex_n);
    fflush(out);
    if (phg_floor(g.seen, seen_floor, "no include matched the header table "
                  "at all — the table or the scanner is broken, not the "
                  "tree", err))
        return 2;
    if (g.found) {
        phg_report_found(&g, err);
        return 1;
    }
    if (strcmp(mode, "quiet"))
        fprintf(out, "  %s: OK — %d platform-only header include(s), every one "
                "guarded or build-exclusive.\n", k_phg_gate, g.seen);
    return 0;
}

int check_platform_header_guards_run(int argc, char **argv)
{
    if (argc == 0)
        return phg_run_scan(".", 2000, 40, 200, 50, 10, "", stdout, stderr);
    if (argc == 1 && !strcmp(argv[0], "--list"))
        return phg_run_scan(".", 2000, 40, 200, 50, 10, "list", stdout,
                            stderr);
    fprintf(stderr, "usage: tools/lint/check_platform_header_guards.sh "
            "[--self-test|--list]\n");
    return 2;
}
