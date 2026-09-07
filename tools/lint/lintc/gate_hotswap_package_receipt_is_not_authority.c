/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: C23 lint gate — check-hotswap-package-receipt-is-not-authority.
 * Port of tools/lint/check_hotswap_package_receipt_is_not_authority.sh: the
 * hot-swap package manifest (a sidecar record beside a built module .so) is
 * a LABEL, never a KEY. This gate proves engine/modules/hotswap/{src,include/hotswap}
 * never opens, stats, or parses a manifest FILE (no ".manifest" string
 * literal, no "zcl.hotswap_package" schema string, no fopen/open/stat/...
 * call whose own line also mentions "manifest") and that the tool which
 * MINTS a package manifest (tools/dev/hotswap-package.sh) stays a dev-only
 * tool with no second copy and no runtime spawn path from node source.
 *
 * Single-gate family file (new port, 2026-09-07).
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
#include "gate_hotswap_package_receipt_is_not_authority_priv.h"

enum { HPR_MAX = 64, HPR_LINE = 8192 };

static const char k_hpr_src_dir[] = "engine/modules/hotswap/src";
static const char k_hpr_inc_dir[] = "engine/modules/hotswap/include/hotswap";
static const char k_hpr_pkg_tool[] = "tools/dev/hotswap-package.sh";
static const char *const k_hpr_stray_roots[] = {
    "core", "engine", "contexts", "cognition", "platform"
};
static const char *const k_hpr_exec_roots[] = { "lib", "app", "core", "src" };

static const char k_hpr_re_suffix[] = "\"[^\"]*\\.manifest[^\"]*\"";
static const char k_hpr_re_schema[] = "\"[^\"]*zcl\\.hotswap_package[^\"]*\"";
static const char k_hpr_re_open[] =
    "(fopen64?|openat?|stat64?|lstat64?|access|opendir|readlink)"
    "[[:space:]]*\\(";

static int hpr_ident(unsigned char c)
{
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z')
        || (c >= 'a' && c <= 'z') || c == '_';
}

/* GNU \b lead-boundary: reject a match whose preceding byte is an // posix-ere-ok: prose describing the technique, not a regex
 * identifier byte (so "xfopen(" does not count as a bare "fopen("). */
static int hpr_lead_ok(const char *line, const regmatch_t *m)
{
    return !(m->rm_so > 0 && hpr_ident((unsigned char)line[m->rm_so - 1]));
}

static int hpr_search_lead(const regex_t *re, const char *line)
{
    size_t off = 0;
    for (;;) {
        regmatch_t m;
        int flags = off ? REG_NOTBOL : 0;
        if (regexec(re, line + off, 1, &m, flags) != 0)
            return 0;
        m.rm_so += (regoff_t)off;
        m.rm_eo += (regoff_t)off;
        if (hpr_lead_ok(line, &m))
            return 1;
        size_t nxt = (size_t)m.rm_eo;
        if (nxt <= off)
            nxt = off + 1;
        off = nxt;
        if (line[off] == '\0')
            return 0;
    }
}

static int hpr_ci_contains(const char *hay, const char *needle)
{
    size_t nl = strlen(needle);
    if (nl == 0)
        return 1;
    for (const char *p = hay; *p; p++) {
        size_t i = 0;
        while (i < nl && p[i]
               && tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i]))
            i++;
        if (i == nl)
            return 1;
    }
    return 0;
}

static void hpr_strip_nl(char *line, ssize_t n)
{
    if (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
        line[n - 1] = '\0';
}

static int hpr_ext_match(const char *nm, const char *const *exts, int nexts)
{
    size_t nl = strlen(nm);
    for (int i = 0; i < nexts; i++) {
        size_t el = strlen(exts[i]);
        if (nl > el + 1 && nm[nl - el - 1] == '.'
            && memcmp(nm + nl - el, exts[i], el) == 0)
            return 1;
    }
    return 0;
}

/* One scandir() entry for hpr_list_dir: skip "."/".."/a name that does not
 * match `exts`, else stat it and, if a regular file, append its full path
 * to `out`. Split out so the caller's loop stays under the complexity cap. */
static int hpr_list_dir_entry(const char *dir, const char *nm,
                              const char *const *exts, int nexts,
                              char out[][RS_PATH], int cap, int *n)
{
    if (strcmp(nm, ".") == 0 || strcmp(nm, "..") == 0)
        return 0;
    if (!hpr_ext_match(nm, exts, nexts))
        return 0;
    char path[4096];
    if (ovf(snprintf(path, sizeof path, "%s/%s", dir, nm), sizeof path))
        return 2;
    struct stat st;
    if (lstat(path, &st) != 0)
        return die("z23-lint: cannot stat %s\n", path);
    if (!S_ISREG(st.st_mode))
        return 0;
    if (*n >= cap)
        return die("z23-lint: hotswap-receipt scan overflow\n", "");
    if (strlen(path) >= RS_PATH)
        return die("z23-lint: path too long: %s\n", path);
    memcpy(out[*n], path, strlen(path) + 1);
    (*n)++;
    return 0;
}

/* List the regular files directly inside `dir` (maxdepth 1) whose name ends
 * in one of `exts` (NUL-separated, e.g. "c\0h\0"); mirrors
 * `find "$dir" -maxdepth 1 -type f \( -name '*.c' -o -name '*.h' \)`. A
 * missing directory yields zero entries (the caller's own "does not exist"
 * check runs first and is fatal before this is called). */
int hpr_list_dir(const char *dir, const char *const *exts, int nexts,
                 char out[][RS_PATH], int cap, int *n)
{
    DIR *d = opendir(dir);
    if (!d)
        return errno == ENOENT ? 0 : die("z23-lint: cannot scan %s\n", dir);
    struct dirent *de;
    int rc = 0;
    while (rc == 0 && (de = readdir(d)) != NULL)
        rc = hpr_list_dir_entry(dir, de->d_name, exts, nexts, out, cap, n);
    closedir(d);
    return rc;
}

/* Scan one flat file list with `re`; a line matching (subject to the
 * fopen()-style lead-boundary rule when `lead` is set, and an additional
 * case-insensitive "manifest" filter when `want_manifest` is set) is
 * printed "path:lineno:content" to `acc`. A present file this process
 * cannot open is UNPROVEN, never a silent skip. */
static int hpr_grep_leg(char paths[][RS_PATH], int npaths, const regex_t *re,
                        int lead, int want_manifest, FILE *acc, int *any)
{
    for (int i = 0; i < npaths; i++) {
        FILE *f = fopen(paths[i], "r");
        if (!f)
            return die("z23-lint: cannot open %s\n", paths[i]);
        char *line = NULL;
        size_t cap = 0;
        ssize_t n;
        int lineno = 0, rc = 0;
        while ((n = getline(&line, &cap, f)) >= 0) {
            lineno++;
            hpr_strip_nl(line, n);
            int hit = lead ? hpr_search_lead(re, line)
                          : regexec(re, line, 0, NULL, 0) == 0;
            if (hit && want_manifest)
                hit = hpr_ci_contains(line, "manifest");
            if (!hit)
                continue;
            *any = 1;
            if (fprintf(acc, "%s:%d:%s\n", paths[i], lineno, line) < 0) {
                rc = die("z23-lint: write failed\n", "");
                break;
            }
        }
        int frc = fin(f, line, paths[i], rc);
        if (frc)
            return frc;
    }
    return 0;
}

static int hpr_scan_three_legs(struct hpr_ctx *c, char src_c[][RS_PATH], int ns,
                               char inc_h[][RS_PATH], int ni,
                               regex_t *re_suffix, regex_t *re_schema,
                               regex_t *re_open, FILE *acc, int *bad,
                               int *any);

static int hpr_copy(FILE *from, FILE *to)
{
    if (fseek(from, 0, SEEK_SET) != 0)
        return die("z23-lint: fseek failed\n", "");
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    while ((n = getline(&line, &cap, from)) >= 0) {
        if (fwrite(line, 1, (size_t)n, to) != (size_t)n) {
            free(line);
            return die("z23-lint: write failed\n", "");
        }
    }
    int err = ferror(from);
    free(line);
    return err ? die("z23-lint: read failed\n", "") : 0;
}

static int hpr_bad(FILE *err, const char *msg, FILE *detail)
{
    if (fprintf(err, "check_hotswap_package_receipt_is_not_authority: FAIL — %s\n",
               msg) < 0)
        return die("z23-lint: write failed\n", "");
    if (detail)
        return hpr_copy(detail, err);
    return 0;
}

static int hpr_dirs_exist(struct hpr_ctx *c)
{
    struct stat st;
    int ok = 1;
    if (stat(c->src_dir, &st) != 0) {
        if (hpr_bad(c->err, "does not exist — cannot scan (a renamed/moved hotswap tree?)",
                    NULL))
            return -1;
        ok = 0;
    }
    if (stat(c->inc_dir, &st) != 0) {
        if (hpr_bad(c->err, "does not exist — cannot scan (a renamed/moved hotswap tree?)",
                    NULL))
            return -1;
        ok = 0;
    }
    return ok;
}

static int hpr_manifest_legs(struct hpr_ctx *c, regex_t *re_suffix,
                             regex_t *re_schema, regex_t *re_open, int *bad)
{
    char src_c[HPR_MAX][RS_PATH], inc_h[HPR_MAX][RS_PATH];
    int ns = 0, ni = 0;
    static const char *const c_and_h[2] = { "c", "h" };
    static const char *const h_only[1] = { "h" };
    int rc = hpr_list_dir(c->src_dir, c_and_h, 2, src_c, HPR_MAX, &ns);
    if (rc == 0)
        rc = hpr_list_dir(c->inc_dir, h_only, 1, inc_h, HPR_MAX, &ni);
    if (rc)
        return rc;
    c->scanned_src = ns;
    c->scanned_inc = ni;
    if (ns == 0 || ni == 0) {
        char msg[256];
        (void)snprintf(msg, sizeof msg,
                       "nothing to scan (src=%d inc=%d under %s, %s) — "
                       "refusing to report a clean tree that contains no sources",
                       ns, ni, c->src_dir, c->inc_dir);
        *bad = 1;
        return hpr_bad(c->err, msg, NULL);
    }
    FILE *acc = tmpfile();
    if (!acc)
        return die("z23-lint: tmpfile failed\n", "");
    int any;
    rc = hpr_scan_three_legs(c, src_c, ns, inc_h, ni, re_suffix, re_schema,
                             re_open, acc, bad, &any);
    fclose(acc);
    if (rc == 0 && !*bad)
        fprintf(c->out,
               "  no-file-read : OK — no \".manifest\" suffix, no "
               "\"zcl.hotswap_package\" schema string, no open/stat/read "
               "call mentions a manifest, under %s or %s\n",
               c->src_dir, c->inc_dir);
    return rc;
}

static int hpr_combine(char src_c[][RS_PATH], int ns, char inc_h[][RS_PATH],
                       int ni, char out[][RS_PATH], int cap)
{
    int n = 0;
    for (int i = 0; i < ns && n < cap; i++)
        memcpy(out[n++], src_c[i], strlen(src_c[i]) + 1);
    for (int i = 0; i < ni && n < cap; i++)
        memcpy(out[n++], inc_h[i], strlen(inc_h[i]) + 1);
    return n;
}

/* One leg: run `re` over `all`/`n`, and if anything matched, print the
 * fixed header line plus the collected "path:lineno:content" hits. */
static int hpr_one_leg(FILE *err, char all[][RS_PATH], int n, const regex_t *re,
                       int lead, int want_manifest, const char *header,
                       int *bad)
{
    FILE *acc = tmpfile();
    if (!acc)
        return die("z23-lint: tmpfile failed\n", "");
    int any = 0;
    int rc = hpr_grep_leg(all, n, re, lead, want_manifest, acc, &any);
    if (rc == 0 && any) {
        *bad = 1;
        rc = hpr_bad(err, header, acc);
    }
    fclose(acc);
    return rc;
}

static int hpr_scan_three_legs(struct hpr_ctx *c, char src_c[][RS_PATH], int ns,
                               char inc_h[][RS_PATH], int ni,
                               regex_t *re_suffix, regex_t *re_schema,
                               regex_t *re_open, FILE *acc, int *bad, int *any)
{
    (void)acc;
    (void)any;
    char all[2 * HPR_MAX][RS_PATH];
    int n = hpr_combine(src_c, ns, inc_h, ni, all, 2 * HPR_MAX);
    int rc = hpr_one_leg(c->err, all, n, re_suffix, 0, 0,
                         "a \".manifest\" path suffix appears in a string literal:",
                         bad);
    if (rc == 0)
        rc = hpr_one_leg(c->err, all, n, re_schema, 0, 0,
                         "the package-manifest schema string \"zcl.hotswap_package\" "
                         "appears in source:",
                         bad);
    if (rc == 0)
        rc = hpr_one_leg(c->err, all, n, re_open, 1, 1,
                         "a filesystem open/stat/read call mentions \"manifest\" on "
                         "its own line (a manifest FILE read):",
                         bad);
    return rc;
}

/* ── leg 3: the packaging tool is a DEV tool, never reachable from the
 * node ────────────────────────────────────────────────────────────────
 * Returns 0 (proven safe), 1 (proven UNSAFE), or 2 (cannot be proven: the
 * packaging tool has not landed — FATAL, not a skip). */
static int hpr_tool_missing_fatal(FILE *err, const char *tool)
{
    fprintf(err,
           "check_hotswap_package_receipt_is_not_authority: FATAL — %s does "
           "not exist yet.\n"
           "  This leg proves the tool that MINTS a package manifest lives "
           "under a\n"
           "  dev-only path and is never reachable from the node's own "
           "runtime load\n"
           "  path. That cannot be proven with the tool itself absent, and "
           "reporting\n"
           "  a pass anyway would go quietly vacuous the instant it lands "
           "somewhere\n"
           "  unsafe. Refusing: FATAL, not a skip, until another lane adds "
           "it here.\n",
           tool);
    return 2;
}

static int hpr_tool_under_dev(const char *tool)
{
    return strncmp(tool, "tools/dev/", 10) == 0;
}

static const char *hpr_basename(const char *path)
{
    const char *s = strrchr(path, '/');
    return s ? s + 1 : path;
}

struct hpr_walk_name {
    const char *base;
    FILE *hits;
    int any;
};

static int hpr_name_walk(const char *dir, struct hpr_walk_name *w);

static int hpr_name_walk_entry(const char *dir, const char *nm,
                               struct hpr_walk_name *w)
{
    if (strcmp(nm, ".") == 0 || strcmp(nm, "..") == 0)
        return 0;
    char path[4096];
    if (ovf(snprintf(path, sizeof path, "%s/%s", dir, nm), sizeof path))
        return 2;
    struct stat st;
    if (lstat(path, &st) != 0)
        return die("z23-lint: cannot stat %s\n", path);
    if (S_ISDIR(st.st_mode))
        return hpr_name_walk(path, w);
    if (S_ISREG(st.st_mode) && strcmp(nm, w->base) == 0) {
        w->any = 1;
        if (fprintf(w->hits, "%s\n", path) < 0)
            return die("z23-lint: write failed\n", "");
    }
    return 0;
}

static int hpr_name_walk(const char *dir, struct hpr_walk_name *w)
{
    DIR *d = opendir(dir);
    if (!d)
        return errno == ENOENT ? 0 : die("z23-lint: cannot scan %s\n", dir);
    struct dirent *de;
    int rc = 0;
    while (rc == 0 && (de = readdir(d)) != NULL)
        rc = hpr_name_walk_entry(dir, de->d_name, w);
    closedir(d);
    return rc;
}

static int hpr_stray_copy(FILE *err, const char *tool, int *bad)
{
    const char *base = hpr_basename(tool);
    FILE *hits = tmpfile();
    if (!hits)
        return die("z23-lint: tmpfile failed\n", "");
    struct hpr_walk_name w = { .base = base, .hits = hits, .any = 0 };
    int rc = 0;
    for (size_t i = 0; rc == 0
         && i < sizeof k_hpr_stray_roots / sizeof k_hpr_stray_roots[0]; i++)
        rc = hpr_name_walk(k_hpr_stray_roots[i], &w);
    if (rc == 0 && w.any) {
        *bad = 1;
        rc = hpr_bad(err,
                     "a second copy of the packaging tool exists outside tools/:",
                     hits);
    }
    fclose(hits);
    return rc;
}

static int hpr_exec_hit_file(const char *path, const char *base,
                             const regex_t *re_exec)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int has_exec = 0, has_base = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        hpr_strip_nl(line, n);
        if (!has_exec)
            has_exec = hpr_search_lead(re_exec, line);
        if (!has_base)
            has_base = strstr(line, base) != NULL;
    }
    int rc = fin(f, line, path, 0);
    if (rc)
        return -rc;
    return has_exec && has_base;
}

struct hpr_exec_ctx {
    const char *base;
    const regex_t *re;
    FILE *hits;
    int any;
    int rc;
};

static int hpr_exec_scan_file(const char *path, void *vctx)
{
    struct hpr_exec_ctx *ctx = vctx;
    if (ctx->rc)
        return 0;
    int hit = hpr_exec_hit_file(path, ctx->base, ctx->re);
    if (hit < 0) {
        ctx->rc = -hit;
        return ctx->rc;
    }
    if (hit) {
        ctx->any = 1;
        if (fprintf(ctx->hits, "%s\n", path) < 0) {
            ctx->rc = die("z23-lint: write failed\n", "");
            return ctx->rc;
        }
    }
    return 0;
}

static int hpr_exec_reach(FILE *err, const char *tool, const regex_t *re_exec,
                          int *bad)
{
    const char *base = hpr_basename(tool);
    FILE *hits = tmpfile();
    if (!hits)
        return die("z23-lint: tmpfile failed\n", "");
    struct hpr_exec_ctx ctx = { .base = base, .re = re_exec, .hits = hits,
                                .any = 0, .rc = 0 };
    int rc = 0;
    for (size_t i = 0; rc == 0
         && i < sizeof k_hpr_exec_roots / sizeof k_hpr_exec_roots[0]; i++) {
        struct stat st;
        if (stat(k_hpr_exec_roots[i], &st) != 0)
            continue;
        rc = walk_src(k_hpr_exec_roots[i], 1, hpr_exec_scan_file, &ctx);
    }
    if (rc == 0)
        rc = ctx.rc;
    if (rc == 0 && ctx.any) {
        *bad = 1;
        rc = hpr_bad(err, "node source spawns the packaging tool at runtime:",
                    hits);
    }
    fclose(hits);
    return rc;
}

static int hpr_package_tool_leg(FILE *out, FILE *err, const char *tool, int *bad)
{
    if (access(tool, F_OK) != 0)
        return hpr_tool_missing_fatal(err, tool);
    if (!hpr_tool_under_dev(tool)) {
        *bad = 1;
        return hpr_bad(err, "packaging tool is not under tools/dev/", NULL);
    }
    fprintf(out, "  tool location  : OK — %s is a dev-only tool\n", tool);
    static const char k_re_exec[] =
        "(popen|system|execl[pe]?|execvp?)[[:space:]]*\\(";
    regex_t re_exec;
    int rc = compile_pat(&re_exec, REG_EXTENDED, k_re_exec, "", "", "");
    if (rc)
        return rc;
    rc = hpr_stray_copy(err, tool, bad);
    if (rc == 0 && !*bad)
        rc = hpr_exec_reach(err, tool, &re_exec, bad);
    regfree(&re_exec);
    if (rc == 0 && !*bad)
        fputs("  tool reach     : OK — no node source (lib/, app/, core/, "
             "src/) execs, popens, or systems the packaging tool\n", out);
    return rc;
}

static int hpr_final(struct hpr_ctx *c, int mbad, int tool_rc, int tool_bad)
{
    if (tool_rc == 2)
        return 2;
    if (tool_rc != 0 || mbad || tool_bad) {
        fputs("check_hotswap_package_receipt_is_not_authority: the package "
             "manifest can still become an authority.\n"
             "  It must stay a record of what was tested, never an input to "
             "the\n"
             "  load decision — that inversion turns forging a label into "
             "mounting\n"
             "  arbitrary code.\n", c->err);
        return 1;
    }
    fprintf(c->out,
           "check_hotswap_package_receipt_is_not_authority: OK — no-file-read "
           "proven over %d file(s) in %s and %d file(s) in %s; packaging tool "
           "confined to tools/dev/ and unreached by node source\n",
           c->scanned_src, c->src_dir, c->scanned_inc, c->inc_dir);
    return 0;
}

static int hpr_manifest_regexes(regex_t *suffix, regex_t *schema, regex_t *open)
{
    int rc = pair_comp(suffix, REG_EXTENDED, k_hpr_re_suffix, "", "", "",
                       schema, REG_EXTENDED, k_hpr_re_schema, "", "", "");
    if (rc)
        return rc;
    rc = compile_pat(open, REG_EXTENDED, k_hpr_re_open, "", "", "");
    if (rc)
        drop2(suffix, schema);
    return rc;
}

int hpr_run_checks(struct hpr_ctx *c)
{
    int exists = hpr_dirs_exist(c);
    if (exists < 0)
        return 2;
    int mbad = 0;
    int rc = 0;
    if (!exists) {
        mbad = 1;
    } else {
        regex_t re_suffix, re_schema, re_open;
        rc = hpr_manifest_regexes(&re_suffix, &re_schema, &re_open);
        if (rc == 0) {
            rc = hpr_manifest_legs(c, &re_suffix, &re_schema, &re_open, &mbad);
            drop2(&re_suffix, &re_schema);
            regfree(&re_open);
        }
    }
    if (rc)
        return rc;

    int tool_bad = 0;
    int tool_rc = hpr_package_tool_leg(c->out, c->err, c->pkg_tool, &tool_bad);
    return hpr_final(c, mbad, tool_rc, tool_bad);
}

int check_hotswap_package_receipt_is_not_authority_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    struct hpr_ctx c = { .src_dir = k_hpr_src_dir, .inc_dir = k_hpr_inc_dir,
                         .pkg_tool = k_hpr_pkg_tool, .out = stdout,
                         .err = stderr, .scanned_src = 0, .scanned_inc = 0 };
    return hpr_run_checks(&c);
}
