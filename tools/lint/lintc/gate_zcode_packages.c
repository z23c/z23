/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gates over the zcode package registry and package standalone-ness.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <errno.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>
#include "lintc.h"

enum { ZPKG_MAX = 32, ZSRC_MAX = 512, ZMONO_MAX = 2048, ZINC_MAX = 32,
       ZSLURP = 32768, ZCAP = 256 * 1024 };
struct zpkg_row { char name[RS_NAME]; char dir[RS_PATH]; };
struct zpr_acc { char (*v)[RS_PATH]; int n, cap; };

static const char *const k_zpkg_defs[] = {
    "engine/composition/zcode_package_registry.def",
    "engine/composition/zcode_c23_commons_app.def"
};
static const char k_zpkg_defs_join[] =
    "engine/composition/zcode_package_registry.def "
    "engine/composition/zcode_c23_commons_app.def";
static const char k_zpr_checker[] = "build/bin/zcode-package-registry-check";
static const char k_zps_profile[] = "engine/composition/include/config/c23_commons_build_profile.h";
static const char k_zps_toolchain[] = "platform/modules/platform/src/toolchain.c";
static const char *const k_zpr_groups[] = {
    "platform/modules/platform/src/os_sandbox_linux.c "
    "platform/modules/platform/src/os_sandbox_stub.c",
    "contexts/commons/modules/vcs/src/vcs_devloop.c "
    "contexts/commons/modules/vcs/src/vcs_devloop_windows.c"
};
static const char *const k_zpr_optional[] = {
    "platform/modules/platform/src/os_sandbox_package_linux.c",
    "platform/modules/platform/src/os_sandbox_terminal_worker.c"
};
static const char *const k_zpr_codec[] = {
    "contexts/commons/modules/vcs/src/package_release.c",
    "contexts/commons/modules/vcs/src/package_recipe.c",
    "contexts/commons/modules/vcs/src/package_deps.c"
};
static int zpkg_copy(char *dst, size_t cap, const char *s, size_t n)
{ if (n >= cap) return ovf((int)n, cap); memcpy(dst, s, n); dst[n] = '\0'; return 0; }
static int zpkg_slurp_path(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "r");
    if (!f) return die("z23-lint: cannot open %s\n", path);
    int rc = csr_slurp(f, buf, cap);
    if (fclose(f) != 0 && rc == 0) rc = die("z23-lint: fclose failed: %s\n", path);
    return rc;
}
static int zpkg_parse_rows(const char *text, struct zpkg_row *rows, int cap, int *n)
{
    const char *p = text;
    while (*p) {
        const char *eol = strchr(p, '\n');
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        if (len >= 14 && memcmp(p, "ZCODE_PACKAGE(", 14) == 0) {
            const char *lim = p + len;
            const char *q1 = memchr(p, '"', len);
            const char *q1e = q1 ? memchr(q1 + 1, '"', (size_t)(lim - q1 - 1)) : NULL;
            const char *q2 = q1e ? memchr(q1e + 1, '"', (size_t)(lim - q1e - 1)) : NULL;
            const char *q2e = q2 ? memchr(q2 + 1, '"', (size_t)(lim - q2 - 1)) : NULL;
            if (q1e && q2e && q1e > q1 + 1 && q2e > q2 + 1) {
                if (*n >= cap) return ovf(*n + 1, (size_t)cap);
                if (zpkg_copy(rows[*n].name, sizeof rows[*n].name, q1 + 1, (size_t)(q1e - q1 - 1))
                    || zpkg_copy(rows[*n].dir, sizeof rows[*n].dir, q2 + 1, (size_t)(q2e - q2 - 1)))
                    return 2;
                (*n)++;
            }
        }
        p = eol ? eol + 1 : p + len;
    }
    return 0;
}
static int zpkg_load_rows(struct zpkg_row *rows, int cap, int *n)
{
    char buf[ZSLURP]; *n = 0;
    for (int i = 0; i < 2; i++) {
        int rc = zpkg_slurp_path(k_zpkg_defs[i], buf, sizeof buf);
        if (rc || (rc = zpkg_parse_rows(buf, rows, cap, n))) return rc;
    }
    return 0;
}
static const char *zpkg_dir_of(const struct zpkg_row *rows, int n, const char *name)
{
    const char *d = NULL;
    for (int i = 0; i < n; i++) if (strcmp(rows[i].name, name) == 0) d = rows[i].dir;
    return d ? d : "";
}
static int zpr_out(FILE *fp, const char *s)
{ return fprintf(fp, "%s\n", s) < 0 ? die("z23-lint: write failed\n", "") : 0; }
static int zpr_replay(const char *s) { return s[0] ? zpr_out(stdout, s) : 0; }
static int zpr_cmp_path(const void *a, const void *b) { return strcmp(a, b); }
static int zpr_sort_unique(char v[][RS_PATH], int n)
{
    int w = 0;
    if (n > 1) qsort(v, (size_t)n, RS_PATH, zpr_cmp_path);
    for (int i = 0; i < n; i++) {
        if (w && strcmp(v[i], v[w - 1]) == 0) continue;
        if (w != i) memcpy(v[w], v[i], RS_PATH);
        w++;
    }
    return w;
}
static int zpr_on_path(const char *path, void *ctx)
{
    struct zpr_acc *a = ctx;
    if (a->n >= a->cap) return ovf(a->n + 1, (size_t)a->cap);
    if (ovf(snprintf(a->v[a->n], RS_PATH, "%s", path), RS_PATH)) return 2;
    a->n++; return 0;
}
static int zpr_hits(char v[][RS_PATH], int n, const char *src)
{ int c = 0; for (int i = 0; i < n; i++) if (strcmp(v[i], src) == 0) c++; return c; }
static int zpr_in_group(const char *group, const char *src)
{
    for (const char *p = group; *p; ) {
        while (*p == ' ') p++;
        if (!*p) break;
        const char *e = p; while (*e && *e != ' ') e++;
        if ((size_t)(e - p) == strlen(src) && memcmp(p, src, (size_t)(e - p)) == 0) return 1;
        p = e;
    }
    return 0;
}
static int zpr_excluded(const char *src)
{
    for (size_t i = 0; i < sizeof k_zpr_groups / sizeof k_zpr_groups[0]; i++)
        if (zpr_in_group(k_zpr_groups[i], src)) return 1;
    for (size_t i = 0; i < sizeof k_zpr_optional / sizeof k_zpr_optional[0]; i++)
        if (strcmp(k_zpr_optional[i], src) == 0) return 1;
    return 0;
}
static int zpr_host_expected(const char *host)
{ return strncmp(host, "Linux", 5) == 0 ? 1 : 0; }
#define ZPRF "check-zcode-package-registry: FAIL — "
static int zpr_fmt_exact(char *b, size_t cap, const char *src, int count)
{ return ovf(snprintf(b, cap, ZPRF "%s appears %d times in LIB_SRCS", src, count), cap); }
static int zpr_fmt_host(char *b, size_t cap, const char *opt, int count, int expected, const char *host)
{ return ovf(snprintf(b, cap, ZPRF "host-optional %s appears %d times in LIB_SRCS (expected %d on %s)", opt, count, expected, host), cap); }
static int zpr_fmt_host_ok(char *b, size_t cap, const char *opt, int count)
{ return ovf(snprintf(b, cap, "zcode package registry: host-optional source count is exact: %s=%d", opt, count), cap); }
static int zpr_fmt_plat(char *b, size_t cap, int count, const char *group)
{ return ovf(snprintf(b, cap, ZPRF "platform alternative group appears %d times in LIB_SRCS (%s)", count, group), cap); }
static int zpr_fmt_plat_ok(char *b, size_t cap, const char *chosen)
{ return ovf(snprintf(b, cap, "zcode package registry: exactly one host alternative selected: %s", chosen), cap); }
static int zpr_fmt_codec_miss(char *b, size_t cap, const char *src)
{ return ovf(snprintf(b, cap, ZPRF "%s does not use the bounded codec cursor", src), cap); }
static int zpr_fmt_codec_priv(char *b, size_t cap)
{ return ovf(snprintf(b, cap, ZPRF "package release/recipe/lock restored a private codec"), cap); }
static int zpr_group_hits(const char *group, char mono[][RS_PATH], int n,
                         char *chosen, size_t cap)
{
    int pc = 0; chosen[0] = '\0';
    for (const char *p = group; *p; ) {
        while (*p == ' ') p++;
        if (!*p) break;
        const char *e = p; while (*e && *e != ' ') e++;
        char alt[RS_PATH];
        if (zpkg_copy(alt, sizeof alt, p, (size_t)(e - p))) return -1;
        for (int i = 0; i < n; i++)
            if (strcmp(mono[i], alt) == 0) {
                pc++;
                if (ovf(snprintf(chosen, cap, "%s", alt), cap)) return -1;
            }
        p = e;
    }
    return pc;
}
static int zpr_take_match(const char *text, regex_t *re, char v[][RS_PATH], int cap, int *n)
{
    for (const char *p = text; *p; ) {
        const char *eol = strchr(p, '\n');
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        char line[RS_PATH];
        if (zpkg_copy(line, sizeof line, p, len)) return 2;
        if (regexec(re, line, 0, NULL, 0) == 0) {
            if (*n >= cap) return ovf(*n + 1, (size_t)cap);
            memcpy(v[*n], line, strlen(line) + 1); (*n)++;
        }
        p = eol ? eol + 1 : p + len;
    }
    return 0;
}
int check_zcode_package_registry_run(int argc, char **argv)
{
    (void)argc; (void)argv;
    char root[4096];
    if (cic_repo_root(root, sizeof root) || chdir(root) != 0)
        return die("z23-lint: cannot scan %s\n", root);
    static char cap[ZCAP];
    int code = 0;
    if (capture_cmd("tools/scripts/zcode_registry_rederive.sh --selftest", cap, sizeof cap, &code)
        || zpr_replay(cap))
        return 2;
    if (code != 0) return 1;
    char mk[256];
    if (ovf(snprintf(mk, sizeof mk, "make -s --no-print-directory %s >/dev/null 2>&1",
                     k_zpr_checker), sizeof mk)
        || capture_cmd(mk, cap, sizeof cap, &code))
        return 2;
    if (code != 0)
        return fprintf(stderr, ZPRF "could not build %s\n", k_zpr_checker) < 0
                   ? die("z23-lint: write failed\n", "") : 1;
    if (access(k_zpr_checker, X_OK) != 0)
        return fprintf(stderr, ZPRF "missing %s\n", k_zpr_checker) < 0
                   ? die("z23-lint: write failed\n", "") : 1;
    if (capture_cmd("tools/scripts/zcode_registry_rederive.sh --check", cap, sizeof cap, &code)
        || zpr_replay(cap))
        return 2;
    if (code != 0) return 1;
    struct zpkg_row rows[ZPKG_MAX]; int nr = 0;
    if (zpkg_load_rows(rows, ZPKG_MAX, &nr)) return 2;
    char dirs[ZPKG_MAX][RS_PATH];
    int nd = 0;
    for (int i = 0; i < nr; i++) {
        if (nd >= ZPKG_MAX) return ovf(nd + 1, (size_t)ZPKG_MAX);
        memcpy(dirs[nd++], rows[i].dir, RS_PATH);
    }
    nd = zpr_sort_unique(dirs, nd);
    char lscmd[8192], q[RS_PATH + 16], pat[RS_PATH + 16];
    int k = snprintf(lscmd, sizeof lscmd, "git ls-files -z --");
    if (ovf(k, sizeof lscmd)) return 2;
    size_t used = (size_t)k;
    for (int i = 0; i < nd; i++) {
        if (ovf(snprintf(pat, sizeof pat, "%s/src/*.c", dirs[i]), sizeof pat)
            || sh_single_quote(pat, q, sizeof q))
            return 2;
        k = snprintf(lscmd + used, sizeof lscmd - used, " %s", q);
        if (ovf(k, sizeof lscmd - used)) return 2;
        used += (size_t)k;
    }
    static char pkg_src[ZSRC_MAX][RS_PATH], mono[ZMONO_MAX][RS_PATH];
    struct zpr_acc acc = { .v = pkg_src, .cap = ZSRC_MAX };
    if (each_zpath(lscmd, zpr_on_path, &acc)) return 2;
    int ns = zpr_sort_unique(pkg_src, acc.n);
    if (capture_cmd("make -s --no-print-directory print-zcode-monolith-lib-sources", cap, sizeof cap, &code))
        return 2;
    if (code != 0) return 1;
    regex_t re;
    int err = reg_fail(&re, regcomp(&re,
        "^(core|engine|contexts|cognition|platform)/.*/src/.*\\.c$", REG_EXTENDED));
    if (err) return err;
    int nm = 0, rc = zpr_take_match(cap, &re, mono, ZMONO_MAX, &nm);
    regfree(&re); if (rc) return rc;
    if (ns == 0 || nm == 0)
        return fputs(ZPRF "empty package or monolith source projection\n", stderr) < 0
                   ? die("z23-lint: write failed\n", "") : 1;
    char msg[1024];
    for (int i = 0; i < ns; i++) {
        int count = zpr_excluded(pkg_src[i]) ? 1 : zpr_hits(mono, nm, pkg_src[i]);
        if (count != 1)
            return zpr_fmt_exact(msg, sizeof msg, pkg_src[i], count) || zpr_out(stderr, msg) ? 2 : 1;
    }
    char host[64] = "";
    struct utsname u;
    if (uname(&u) == 0 && ovf(snprintf(host, sizeof host, "%s", u.sysname), sizeof host))
        return 2;
    for (size_t i = 0; i < sizeof k_zpr_optional / sizeof k_zpr_optional[0]; i++) {
        int count = zpr_hits(mono, nm, k_zpr_optional[i]), expected = zpr_host_expected(host);
        if (count != expected)
            return zpr_fmt_host(msg, sizeof msg, k_zpr_optional[i], count, expected, host)
                       || zpr_out(stderr, msg) ? 2 : 1;
        if (zpr_fmt_host_ok(msg, sizeof msg, k_zpr_optional[i], count) || zpr_out(stdout, msg))
            return 2;
    }
    for (size_t i = 0; i < sizeof k_zpr_groups / sizeof k_zpr_groups[0]; i++) {
        char chosen[RS_PATH];
        int pc = zpr_group_hits(k_zpr_groups[i], mono, nm, chosen, sizeof chosen);
        if (pc < 0) return 2;
        if (pc != 1)
            return zpr_fmt_plat(msg, sizeof msg, pc, k_zpr_groups[i]) || zpr_out(stderr, msg) ? 2 : 1;
        if (zpr_fmt_plat_ok(msg, sizeof msg, chosen) || zpr_out(stdout, msg)) return 2;
    }
    for (size_t i = 0; i < sizeof k_zpr_codec / sizeof k_zpr_codec[0]; i++) {
        char qs[RS_PATH + 8], cmd[1024];
        if (sh_single_quote(k_zpr_codec[i], qs, sizeof qs)
            || ovf(snprintf(cmd, sizeof cmd, "git grep -q '#include \"codec/cursor.h\"' -- %s", qs),
                   sizeof cmd) || capture_cmd(cmd, cap, 64, &code))
            return 2;
        if (code != 0)
            return zpr_fmt_codec_miss(msg, sizeof msg, k_zpr_codec[i]) || zpr_out(stderr, msg) ? 2 : 1;
    }
    char q0[RS_PATH + 8], q1[RS_PATH + 8], q2[RS_PATH + 8], gcmd[2048];
    if (sh_single_quote(k_zpr_codec[0], q0, sizeof q0)
        || sh_single_quote(k_zpr_codec[1], q1, sizeof q1)
        || sh_single_quote(k_zpr_codec[2], q2, sizeof q2)
        || ovf(snprintf(gcmd, sizeof gcmd,
                        "git grep -n -E 'vcs_(wr|rd)_u(16|32|64)le|#include \"vcs_priv.h\"' -- %s %s %s",
                        q0, q1, q2), sizeof gcmd)
        || capture_cmd(gcmd, cap, sizeof cap, &code))
        return 2;
    if (code == 0)
        return zpr_replay(cap) || zpr_fmt_codec_priv(msg, sizeof msg) || zpr_out(stderr, msg) ? 2 : 1;
    if (printf("zcode package registry: %d authoritative package sources occur exactly once in monolith LIB_SRCS\n", ns) < 0
        || fputs("zcode package registry: exactly one host sandbox implementation is selected\n", stdout) < 0
        || fputs("zcode package registry: release, recipe and lock wires use codec/cursor.h exclusively\n", stdout) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

int check_zcode_package_registry_selftest(void)
{
    char msg[512], ok[512], chosen[RS_PATH], mono[4][RS_PATH];
    int bad = 0;
    bad |= zpr_fmt_exact(msg, sizeof msg, "a.c", 0) || strcmp(msg, ZPRF "a.c appears 0 times in LIB_SRCS");
    bad |= zpr_fmt_exact(msg, sizeof msg, "a.c", 2) || strcmp(msg, ZPRF "a.c appears 2 times in LIB_SRCS");
    if (ovf(snprintf(mono[0], RS_PATH, "%s",
                     "platform/modules/platform/src/os_sandbox_linux.c"), RS_PATH)
        || ovf(snprintf(mono[1], RS_PATH, "%s",
                        "platform/modules/platform/src/os_sandbox_stub.c"), RS_PATH))
        return 2;
    int pc = zpr_group_hits(k_zpr_groups[0], mono, 1, chosen, sizeof chosen);
    bad |= pc != 1 || strcmp(chosen, "platform/modules/platform/src/os_sandbox_linux.c");
    pc = zpr_group_hits(k_zpr_groups[0], mono, 0, chosen, sizeof chosen);
    bad |= pc != 0 || zpr_fmt_plat(msg, sizeof msg, 0, k_zpr_groups[0])
        || !strstr(msg, "appears 0 times in LIB_SRCS");
    pc = zpr_group_hits(k_zpr_groups[0], mono, 2, chosen, sizeof chosen);
    bad |= pc != 2 || zpr_fmt_plat(msg, sizeof msg, 2, k_zpr_groups[0])
        || !strstr(msg, "appears 2 times in LIB_SRCS") || !strstr(msg, k_zpr_groups[0]);
    bad |= zpr_host_expected("Linux") != 1 || zpr_host_expected("Linuxfoo") != 1
        || zpr_host_expected("Darwin") != 0;
    bad |= zpr_fmt_host_ok(ok, sizeof ok, k_zpr_optional[0], 1)
        || strcmp(ok, "zcode package registry: host-optional source count is exact: platform/modules/platform/src/os_sandbox_package_linux.c=1");
    bad |= zpr_fmt_host(msg, sizeof msg, k_zpr_optional[0], 0, 1, "Linux")
        || !strstr(msg, "expected 1 on Linux");
    bad |= zpr_fmt_codec_miss(msg, sizeof msg, k_zpr_codec[0])
        || strcmp(msg, ZPRF "contexts/commons/modules/vcs/src/package_release.c does not use the bounded codec cursor");
    bad |= zpr_fmt_codec_priv(msg, sizeof msg)
        || strcmp(msg, ZPRF "package release/recipe/lock restored a private codec");
    bad |= !zpr_excluded("platform/modules/platform/src/os_sandbox_linux.c")
        || !zpr_excluded(k_zpr_optional[0]) || zpr_excluded("platform/modules/base/src/log_level.c");
    if (ovf(snprintf(mono[0], RS_PATH, "%s", "ok.c"), RS_PATH)) return 2;
    bad |= zpr_hits(mono, 1, "ok.c") != 1;
    return st_ok(bad, "check_zcode_package_registry selftest: OK\n");
}

static int zps_linux_flags(const char *text, char *out, size_t cap)
{
    out[0] = '\0';
    int infn = 0, collecting = 0;
    size_t used = 0;
    for (const char *p = text; *p; ) {
        const char *eol = strchr(p, '\n');
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        char line[4096];
        if (zpkg_copy(line, sizeof line, p, len)) return 2;
        if (!infn)
            infn = strstr(line, "platform_toolchain_commons_flags_quick(void)") != NULL;
        else if (!collecting)
            collecting = strstr(line, "#if defined(__linux__)") != NULL;
        else if (line[0] == '#' && (strncmp(line, "#elif", 5) == 0
                                    || strncmp(line, "#else", 5) == 0
                                    || strncmp(line, "#endif", 6) == 0))
            break;
        else {
            for (char *s = line; (s = strchr(s, '"')) != NULL; ) {
                char *e = strchr(s + 1, '"');
                if (!e) break;
                size_t n = (size_t)(e - s - 1);
                if (used + n >= cap) return ovf((int)(used + n), cap);
                memcpy(out + used, s + 1, n); used += n; out[used] = '\0';
                s = e + 1;
            }
        }
        p = eol ? eol + 1 : p + len;
    }
    return 0;
}
static void zps_strip_sub(char *s, const char *needle)
{ size_t n = strlen(needle); char *p; while ((p = strstr(s, needle))) memmove(p, p + n, strlen(p + n) + 1); }
static int zps_quick_flags(char *out, size_t cap)
{
    struct utsname u;
    if (uname(&u) != 0) { u.sysname[0] = '\0'; u.machine[0] = '\0'; }
    if (strcmp(u.sysname, "Darwin") == 0) {
        const char *f = NULL;
        if (strcmp(u.machine, "arm64") == 0 || strcmp(u.machine, "aarch64") == 0)
            f = "-std=c23 -O1 -march=armv8-a -fno-omit-frame-pointer -D_POSIX_C_SOURCE=200809L -D_DARWIN_C_SOURCE -ffile-prefix-map=SOURCE=. -c";
        else if (strcmp(u.machine, "x86_64") == 0 || strcmp(u.machine, "amd64") == 0)
            f = "-std=c23 -O1 -march=x86-64 -fno-omit-frame-pointer -D_POSIX_C_SOURCE=200809L -D_DARWIN_C_SOURCE -ffile-prefix-map=SOURCE=. -c";
        else
            return fprintf(stderr, "FAIL: unsupported Darwin machine %s\n", u.machine) < 0
                       ? die("z23-lint: write failed\n", "") : 2;
        return ovf(snprintf(out, cap, "%s", f), cap);
    }
    if (strcmp(u.sysname, "Linux") == 0) {
        char text[ZSLURP];
        int rc = zpkg_slurp_path(k_zps_toolchain, text, sizeof text);
        return rc ? rc : zps_linux_flags(text, out, cap);
    }
    return fprintf(stderr, "FAIL: unsupported host %s for standalone package gate\n", u.sysname) < 0
               ? die("z23-lint: write failed\n", "") : 2;
}
static int zps_dep_includes(const char *text, const struct zpkg_row *rows, int nr,
                            char out[][RS_PATH], int cap, int *n)
{
    *n = 0; int in_deps = 0;
    for (const char *p = text; *p; ) {
        const char *eol = strchr(p, '\n');
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        char line[4096];
        if (zpkg_copy(line, sizeof line, p, len)) return 2;
        if (strstr(line, "\"dependencies\"")) in_deps = 1;
        if (in_deps && strchr(line, ']')) in_deps = 0;
        const char *np = strstr(line, "\"name\"");
        if (in_deps && np) {
            const char *c = np + 6;
            while (*c == ' ' || *c == '\t') c++;
            if (*c == ':') {
                const char *z = strstr(line, "\"zclassic23/");
                const char *ze = z ? strchr(z + 1, '"') : NULL;
                if (z && ze) {
                    char dep[RS_NAME];
                    if (zpkg_copy(dep, sizeof dep, z + 1, (size_t)(ze - z - 1))) return 2;
                    const char *dir = zpkg_dir_of(rows, nr, dep);
                    if (*n >= cap) return ovf(*n + 1, (size_t)cap);
                    if (ovf(snprintf(out[*n], RS_PATH, dir[0] ? "-I%s/include" : "MISSINGDEP:%s",
                                     dir[0] ? dir : dep), RS_PATH))
                        return 2;
                    (*n)++;
                }
            }
        }
        p = eol ? eol + 1 : p + len;
    }
    return 0;
}
static int zps_filter_sources(const char *dir, const char *man, const char *const *files,
                              int nf, char out[][RS_PATH], int cap, int *n)
{
    int subset = strstr(man, "\"files\"") != NULL; *n = 0; size_t dl = strlen(dir);
    for (int i = 0; i < nf; i++) {
        const char *f = files[i];
        if (subset) {
            char needle[RS_PATH + 2];
            if (strncmp(f, dir, dl) != 0 || f[dl] != '/') continue;
            if (ovf(snprintf(needle, sizeof needle, "\"%s\"", f + dl + 1), sizeof needle))
                return 2;
            if (!strstr(man, needle)) continue;
        }
        if (*n >= cap) return ovf(*n + 1, (size_t)cap);
        if (ovf(snprintf(out[*n], RS_PATH, "%s", f), RS_PATH)) return 2;
        (*n)++;
    }
    return 0;
}
static int zps_scan_sub(const char *dir, const char *sub, int subset, const char *man,
                        char out[][RS_PATH], int cap, int *n)
{
    char path[4096];
    if (ovf(snprintf(path, sizeof path, "%s/%s", dir, sub), sizeof path)) return 2;
    struct dirent **names = NULL;
    int nd = scandir(path, &names, NULL, alphasort);
    if (nd < 0) return errno == ENOENT ? 0 : die("z23-lint: cannot scan %s\n", path);
    int rc = 0;
    for (int i = 0; i < nd; i++) {
        const char *nm = names[i]->d_name;
        size_t nl = strlen(nm);
        if (rc == 0 && nm[0] != '.' && nl > 2 && nm[nl - 2] == '.' && nm[nl - 1] == 'c') {
            char rel[RS_PATH], full[RS_PATH], needle[RS_PATH + 2];
            if (ovf(snprintf(rel, sizeof rel, "%s/%s", sub, nm), sizeof rel)
                || ovf(snprintf(full, sizeof full, "%s/%s", dir, rel), sizeof full)
                || ovf(snprintf(needle, sizeof needle, "\"%s\"", rel), sizeof needle))
                rc = 2;
            else if (!(subset && !strstr(man, needle))) {
                if (*n >= cap) rc = ovf(*n + 1, (size_t)cap);
                else if (ovf(snprintf(out[*n], RS_PATH, "%s", full), RS_PATH)) rc = 2;
                else (*n)++;
            }
        }
        free(names[i]);
    }
    free(names);
    return rc;
}
static int zps_pkg_sources(const char *dir, const char *man, char out[][RS_PATH], int cap, int *n)
{
    int subset = strstr(man, "\"files\"") != NULL, rc;
    *n = 0; rc = zps_scan_sub(dir, "src", subset, man, out, cap, n);
    return rc ? rc : zps_scan_sub(dir, "tests", subset, man, out, cap, n);
}
static int zps_print_errors(const char *errp)
{
    FILE *f = fopen(errp, "r");
    if (!f) return 0;
    char *line = NULL; size_t cap = 0; ssize_t n; int shown = 0, rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n') line[n - 1] = '\0';
        if (strstr(line, "error:") && printf("      %s\n", line) < 0)
            { rc = die("z23-lint: write failed\n", ""); break; }
        if (strstr(line, "error:") && ++shown >= 3) break;
    }
    return fin(f, line, errp, rc);
}
static int zps_cc(const char *cc, const char *flags, char incs[][RS_PATH], int ni,
                  const char *src, const char *obj, const char *errp, int *code)
{
    char cmd[16384], q[8192];
    if (sh_single_quote(cc, q, sizeof q)) return 2;
    int k = snprintf(cmd, sizeof cmd, "%s %s", q, flags);
    if (ovf(k, sizeof cmd)) return 2;
    size_t used = (size_t)k;
    for (int i = 0; i < ni; i++) {
        char qi[RS_PATH + 8];
        if (sh_single_quote(incs[i], qi, sizeof qi)) return 2;
        k = snprintf(cmd + used, sizeof cmd - used, " %s", qi);
        if (ovf(k, sizeof cmd - used)) return 2;
        used += (size_t)k;
    }
    char qs[4096], qo[4096], qe[4096];
    if (sh_single_quote(src, qs, sizeof qs) || sh_single_quote(obj, qo, sizeof qo)
        || sh_single_quote(errp, qe, sizeof qe)
        || ovf(k = snprintf(cmd + used, sizeof cmd - used, " %s -o %s 2>%s", qs, qo, qe),
               sizeof cmd - used))
        return 2;
    static char dump[256];
    return capture_cmd(cmd, dump, sizeof dump, code);
}
static int zps_compile_package(const char *name, const char *dir, const char *cc,
                               const char *flags, const struct zpkg_row *rows, int nr,
                               const char *work, int *compiled)
{
    char man[RS_PATH];
    if (ovf(snprintf(man, sizeof man, "%s/zcode-package.json", dir), sizeof man)) return 2;
    if (access(man, R_OK) != 0)
        return printf("  %s: no manifest at %s\n", name, man) < 0 ? die("z23-lint: write failed\n", "") : 1;
    char text[ZSLURP], incs[ZINC_MAX][RS_PATH], deps[ZINC_MAX][RS_PATH];
    int rc = zpkg_slurp_path(man, text, sizeof text), ni = 1, nd = 0, missing = 0;
    if (rc || ovf(snprintf(incs[0], RS_PATH, "-I%s/include", dir), RS_PATH)) return rc ? rc : 2;
    rc = zps_dep_includes(text, rows, nr, deps, ZINC_MAX, &nd);
    if (rc) return rc;
    for (int i = 0; i < nd; i++) {
        if (strncmp(deps[i], "MISSINGDEP:", 11) == 0) {
            if (printf("  %s: declares dependency %s, which is not in %s\n",
                       name, deps[i] + 11, k_zpkg_defs_join) < 0)
                return die("z23-lint: write failed\n", "");
            missing = 1; continue;
        }
        if (!deps[i][0]) continue;
        if (ni >= ZINC_MAX) return ovf(ni + 1, (size_t)ZINC_MAX);
        memcpy(incs[ni++], deps[i], RS_PATH);
    }
    if (missing) return 1;
    static char srcs[ZSRC_MAX][RS_PATH];
    int ns = 0, fail = 0;
    char obj[4096], errp[4096];
    if ((rc = zps_pkg_sources(dir, text, srcs, ZSRC_MAX, &ns))
        || ovf(snprintf(obj, sizeof obj, "%s/obj.o", work), sizeof obj)
        || ovf(snprintf(errp, sizeof errp, "%s/err.txt", work), sizeof errp))
        return rc ? rc : 2;
    for (int i = 0; i < ns; i++) {
        int code = 0;
        (*compiled)++;
        rc = zps_cc(cc, flags, incs, ni, srcs[i], obj, errp, &code);
        if (rc) return rc;
        if (code != 0) {
            if (printf("  %s: %s does not compile from its declared dependencies\n", name, srcs[i]) < 0)
                return die("z23-lint: write failed\n", "");
            if ((rc = zps_print_errors(errp))) return rc;
            fail = 1;
        }
    }
    return fail;
}

int check_zcode_package_standalone_run(int argc, char **argv)
{
    (void)argc; (void)argv;
    char root[4096], flags[1024];
    if (cic_repo_root(root, sizeof root) || chdir(root) != 0) {
        fputs("FAIL: cannot reach repo root\n", stderr); return 2;
    }
    int rc = zps_quick_flags(flags, sizeof flags);
    if (rc) return rc;
    if (!flags[0])
        return fprintf(stderr, "FAIL: cannot read ZCL_C23_COMMONS_BUILD_FLAGS_QUICK_V2 from %s\n",
                       k_zps_profile) < 0 ? die("z23-lint: write failed\n", "") : 2;
    zps_strip_sub(flags, "-ffile-prefix-map=SOURCE=.");
    struct zpkg_row rows[ZPKG_MAX];
    int nr = 0;
    if ((rc = zpkg_load_rows(rows, ZPKG_MAX, &nr))) return rc;
    if (nr == 0)
        return fprintf(stderr, "FAIL: no packages parsed from %s — hollow scan\n",
                       k_zpkg_defs_join) < 0 ? die("z23-lint: write failed\n", "") : 2;
    const char *cc = env_or("CC", "cc");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-zps-XXXXXX",
                     env_or("TMPDIR", "/tmp")), sizeof tmpl))
        return 2;
    char *work = mkdtemp(tmpl);
    if (!work) return die("z23-lint: mkdir failed: %s\n", tmpl);
    int compiled = 0, violations = 0;
    for (int i = 0; i < nr; i++) {
        rc = zps_compile_package(rows[i].name, zpkg_dir_of(rows, nr, rows[i].name),
                                 cc, flags, rows, nr, work, &compiled);
        if (rc == 2) { rap_rm_rf(work); return 2; }
        if (rc) violations++;
    }
    if ((rc = rap_rm_rf(work))) return rc;
    if (compiled == 0)
        return fprintf(stderr, "FAIL: parsed %d package(s) but compiled nothing — hollow scan\n",
                       nr) < 0 ? die("z23-lint: write failed\n", "") : 2;
    if (violations > 0) {
        if (printf("[check_zcode_package_standalone] %d package(s) cannot build from their declared dependencies\n", violations) < 0
            || fputs("[check_zcode_package_standalone] a package ships to a node that has only the packages its manifest names; move the shared code down or declare the edge\n", stdout) < 0)
            return die("z23-lint: write failed\n", "");
        return 1;
    }
    return printf("[check_zcode_package_standalone] %d package(s), %d source(s): all build from their declared dependencies\n",
                  nr, compiled) < 0 ? die("z23-lint: write failed\n", "") : 0;
}

static int zps_error_preview(const char *err, char *out, size_t cap)
{
    out[0] = '\0'; size_t used = 0; int shown = 0;
    for (const char *p = err; *p && shown < 3; ) {
        const char *eol = strchr(p, '\n');
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        char line[1024];
        size_t n = len < sizeof line - 1 ? len : sizeof line - 1;
        memcpy(line, p, n); line[n] = '\0';
        if (strstr(line, "error:")) {
            int k = snprintf(out + used, cap - used, "      %s\n", line);
            if (ovf(k, cap - used)) return 2;
            used += (size_t)k; shown++;
        }
        p = eol ? eol + 1 : p + len;
    }
    return 0;
}

int check_zcode_package_standalone_selftest(void)
{
    struct zpkg_row rows[4];
    int nr = 0, bad = 0, n = 0, nd = 0;
    const char *reg =
        "ZCODE_PACKAGE(\"zclassic23/base\", \"platform/modules/base\", 1,\n"
        "skip\n"
        "ZCODE_PACKAGE(\"zclassic23/codec\", \"platform/modules/codec\", 3,\n";
    if (zpkg_parse_rows(reg, rows, 4, &nr)) return 2;
    bad |= nr != 2 || strcmp(rows[0].name, "zclassic23/base")
        || strcmp(rows[0].dir, "platform/modules/base")
        || strcmp(rows[1].name, "zclassic23/codec");
    const char *man_all = "{ \"dependencies\": [] }\n";
    const char *man_sub = "{ \"files\": [ \"src/keep.c\" ],\n  \"dependencies\": [\n"
        "  { \"name\": \"zclassic23/base\" },\n  { \"name\": \"zclassic23/missing\" }\n] }\n";
    const char *files[] = { "pkg/src/keep.c", "pkg/src/drop.c", "pkg/tests/t.c" };
    char out[8][RS_PATH], deps[8][RS_PATH], msg[256];
    if (zps_filter_sources("pkg", man_all, files, 3, out, 8, &n)) return 2;
    bad |= n != 3;
    if (zps_filter_sources("pkg", man_sub, files, 3, out, 8, &n)) return 2;
    bad |= n != 1 || strcmp(out[0], "pkg/src/keep.c");
    if (zps_dep_includes(man_sub, rows, nr, deps, 8, &nd)) return 2;
    bad |= nd != 2 || strcmp(deps[0], "-Iplatform/modules/base/include")
        || strcmp(deps[1], "MISSINGDEP:zclassic23/missing");
    bad |= ovf(snprintf(msg, sizeof msg, "  %s: no manifest at %s", "zclassic23/x",
                        "nowhere/zcode-package.json"), sizeof msg)
        || !strstr(msg, "no manifest at nowhere/zcode-package.json");
    bad |= ovf(snprintf(msg, sizeof msg, "  %s: declares dependency %s, which is not in %s",
                        "zclassic23/codec", "zclassic23/missing", k_zpkg_defs_join), sizeof msg)
        || !strstr(msg, "declares dependency zclassic23/missing, which is not in ");
    const char *cc = env_or("CC", "cc");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-zps-st-XXXXXX",
                     env_or("TMPDIR", "/tmp")), sizeof tmpl))
        return 2;
    char *work = mkdtemp(tmpl);
    if (!work) return die("z23-lint: mkdir failed: %s\n", tmpl);
    char okp[4096], badp[4096], obj[4096], errp[4096], incs[1][RS_PATH];
    incs[0][0] = '\0';
    if (ovf(snprintf(okp, sizeof okp, "%s/ok.c", work), sizeof okp)
        || ovf(snprintf(badp, sizeof badp, "%s/bad.c", work), sizeof badp)
        || ovf(snprintf(obj, sizeof obj, "%s/obj.o", work), sizeof obj)
        || ovf(snprintf(errp, sizeof errp, "%s/err.txt", work), sizeof errp)
        || csr_write(okp, "int z23_lint_zps_ok;\n") || csr_write(badp, "int {\n"))
        { rap_rm_rf(work); return 2; }
    int code = 0;
    if (zps_cc(cc, "-std=c23 -c", incs, 0, okp, obj, errp, &code) || code != 0) bad = 1;
    if (zps_cc(cc, "-std=c23 -c", incs, 0, badp, obj, errp, &code)) bad = 1;
    else {
        char errb[ZSLURP], prev[2048];
        if (zpkg_slurp_path(errp, errb, sizeof errb) || zps_error_preview(errb, prev, sizeof prev))
            bad = 1;
        else if (code == 0 || strncmp(prev, "      ", 6) || !strstr(prev, "error:"))
            bad = 1;
    }
    rap_rm_rf(work);
    return st_ok(bad, "check_zcode_package_standalone selftest: OK\n");
}
