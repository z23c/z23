/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * z23-lint — C23 replacements for tools/lint shell gates.
 * Invoke: z23-lint <gate-name> [--selftest] | z23-lint <gate-name> [args...] | --list
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <regex.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lintc.h"

const char k_ls_all[] = "git ls-files -z";
int die(const char *msg, const char *arg)
{
    fprintf(stderr, msg, arg);
    return 2;
}

int fin(FILE *f, char *line, const char *path, int rc)
{
    if (rc == 0 && ferror(f))
        rc = die("z23-lint: read failed: %s\n", path);
    free(line);
    if (fclose(f) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", path);
    return rc;
}

int reg_fail(regex_t *re, int err)
{
    char msg[128];
    if (err == 0)
        return 0;
    (void)regerror(err, re, msg, sizeof msg);
    return die("z23-lint: regcomp failed: %s\n", msg);
}

int cmd_done(const char *cmd, int st, int allow_exit1)
{
    if (st == 0)
        return 0;
    if (allow_exit1 && st != -1 && WIFEXITED(st) && WEXITSTATUS(st) == 1)
        return 0;
    return die("z23-lint: command failed (%s)\n", cmd);
}

int each_zpath_st(const char *cmd, int allow_exit1,
                         int (*fn)(const char *, void *), void *ctx)
{
    FILE *pipe = popen(cmd, "r");
    if (!pipe)
        return die("z23-lint: popen failed (%s)\n", cmd);
    char *buf = NULL;
    size_t cap = 0;
    int rc = 0;
    ssize_t n;
    while ((n = getdelim(&buf, &cap, '\0', pipe)) >= 0) {
        if (n <= 0 || buf[0] == '\0')
            continue;
        rc = fn(buf, ctx);
        if (rc != 0)
            break;
    }
    if (rc == 0 && ferror(pipe))
        rc = die("z23-lint: read failed (%s)\n", cmd);
    free(buf);
    int st = pclose(pipe);
    if (rc != 0)
        return rc;
    return cmd_done(cmd, st, allow_exit1);
}

int each_zpath(const char *cmd, int (*fn)(const char *, void *), void *ctx)
{
    return each_zpath_st(cmd, 0, fn, ctx);
}

/* ── native git index (".git/index", DIRC) enumeration ──────────────────
 * The no-subprocess successor to each_zpath("git ls-files -z ..."). Reads
 * the index file directly and invokes fn(path, stage, ctx) per entry in
 * index order — names byte-sorted, then ascending stage — which is exactly
 * the order `git ls-files` prints in (it walks the same sorted index and
 * only filters). A nonzero fn return stops the walk and propagates.
 *
 * Index path resolution mirrors git's: $GIT_INDEX_FILE, else .git/index,
 * else a ".git" gitfile's "gitdir: <path>/index" (linked worktrees keep
 * their per-worktree index there).
 *
 * Versions 2, 3 (extended flags), and 4 (prefix-compressed names) are
 * supported. Integrity is structural, not cryptographic: magic, version,
 * entry count, name NULs and v2/v3 eight-byte padding, strict
 * (name, stage) ordering, and the trailing hash all must hold; the SHA-1
 * entry layout (62-byte fixed part) is assumed, so anything else desyncs
 * the checks and fails closed. Failures return 2 SILENTLY — the shell
 * gates this replaces sent git's stderr to /dev/null, so the caller's own
 * UNPROVEN/FATAL block is the only diagnostic byte-parity allows. Buffer
 * exhaustion is the exception: die(), as everywhere in this runtime. */

enum { LGI_CAP = 8 << 20, LGI_NAME = 4096 };
static unsigned char g_lgi_buf[LGI_CAP];

static uint32_t lgi_be32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
        | ((uint32_t)p[2] << 8) | p[3];
}

static int lgi_be16(const unsigned char *p)
{
    return (p[0] << 8) | p[1];
}

static int lgi_locate(char *out, size_t cap)
{
    const char *env = getenv("GIT_INDEX_FILE");
    if (env && env[0])
        return ovf(snprintf(out, cap, "%s", env), cap);
    struct stat st;
    if (stat(".git", &st) == 0 && S_ISDIR(st.st_mode))
        return ovf(snprintf(out, cap, ".git/index"), cap);
    FILE *f = fopen(".git", "r");
    if (!f)
        return 2;
    char line[4096];
    char *got = fgets(line, sizeof line, f);
    fclose(f);
    if (!got || strncmp(line, "gitdir: ", 8) != 0)
        return 2;
    char *nl = strchr(line, '\n');
    if (nl)
        *nl = '\0';
    return ovf(snprintf(out, cap, "%s/index", line + 8), cap);
}

static int lgi_load(const char *path, size_t *out_n)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return 2;
    size_t n = fread(g_lgi_buf, 1, sizeof g_lgi_buf, f);
    int bad = ferror(f) || !feof(f);
    fclose(f);
    if (bad)
        return die("z23-lint: git index read failed or oversized\n", "");
    *out_n = n;
    return 0;
}

/* git's varint (MSB continuation, value = ((v + 1) << 7) | next per
 * continuation byte) — v4 name prefix compression. */
static int lgi_varint(const unsigned char **pp, const unsigned char *end,
                      size_t *out)
{
    if (*pp >= end)
        return 2;
    const unsigned char *p = *pp;
    unsigned char c = *p++;
    size_t v = c & 0x7f;
    while (c & 0x80) {
        if (p >= end)
            return 2;
        c = *p++;
        v = ((v + 1) << 7) | (size_t)(c & 0x7f);
    }
    *pp = p;
    *out = v;
    return 0;
}

/* v2/v3 entry: 62-byte fixed part (plus 2 extended-flag bytes in v3), a
 * NUL-terminated name, padded so the whole entry is a multiple of 8. */
static int lgi_name_v23(const unsigned char *ent, const unsigned char *end,
                        int ext, int flags, const char **name, size_t *esz)
{
    size_t nlen = (size_t)(flags & 0xFFF);
    const unsigned char *nm = ent + 62 + ext;
    if (nlen == 0xFFF) {
        const unsigned char *nul = memchr(nm, 0, (size_t)(end - nm));
        if (!nul)
            return 2;
        nlen = (size_t)(nul - nm);
    }
    if ((size_t)(end - nm) < nlen + 1 || nm[nlen] != 0)
        return 2;
    *esz = ((size_t)(62 + ext) + nlen + 8) & ~(size_t)7;
    if ((size_t)(end - ent) < *esz)
        return 2;
    *name = (const char *)nm;
    return 0;
}

/* v4 entry: unpadded fixed part, a strip varint against the previous
 * name, then the NUL-terminated suffix. prev is read-only input; the
 * composed name lands in name. */
static int lgi_name_v4(const unsigned char *ent, const unsigned char *end,
                       int ext, const char *prev, char *name,
                       const unsigned char **next)
{
    const unsigned char *p = ent + 62 + ext;
    size_t strip = 0;
    if (lgi_varint(&p, end, &strip))
        return 2;
    size_t plen = strlen(prev);
    if (strip > plen)
        return 2;
    const unsigned char *nul = memchr(p, 0, (size_t)(end - p));
    if (!nul)
        return 2;
    size_t keep = plen - strip, slen = (size_t)(nul - p);
    if (keep + slen + 1 > LGI_NAME)
        return 2;
    memcpy(name, prev, keep);
    memcpy(name + keep, p, slen + 1);
    *next = nul + 1;
    return 0;
}

/* Index entries sort by (name, stage): a name below the previous, or an
 * equal name without a strictly greater stage, is structural corruption. */
static int lgi_order(char *prev, int *pstage, int *have, const char *nm,
                     int stage)
{
    if (*have) {
        int c = strcmp(nm, prev);
        if (c < 0 || (c == 0 && stage <= *pstage))
            return 2;
    }
    if (ovf(snprintf(prev, LGI_NAME, "%s", nm), LGI_NAME))
        return 2;
    *pstage = stage;
    *have = 1;
    return 0;
}

static int lgi_entries(size_t n, int ver, uint32_t count,
                       int (*fn)(const char *, int, void *), void *ctx)
{
    const unsigned char *p = g_lgi_buf + 12;
    const unsigned char *end = g_lgi_buf + n;
    char prev[LGI_NAME] = "";
    char name[LGI_NAME];
    int pstage = 0, have = 0, rc = 0;
    for (uint32_t i = 0; rc == 0 && i < count; i++) {
        if ((size_t)(end - p) < 62)
            return 2;
        int flags = lgi_be16(p + 60);
        int ext = (ver >= 3 && (flags & 0x4000)) ? 2 : 0;
        int stage = (flags >> 12) & 3;
        const char *nm = NULL;
        const unsigned char *next = NULL;
        if (ver == 4) {
            if (lgi_name_v4(p, end, ext, prev, name, &next))
                return 2;
            nm = name;
        } else {
            size_t esz = 0;
            if (lgi_name_v23(p, end, ext, flags, &nm, &esz))
                return 2;
            next = p + esz;
        }
        if (lgi_order(prev, &pstage, &have, nm, stage))
            return 2;
        p = next;
        rc = fn(nm, stage, ctx);
    }
    if (rc == 0 && (size_t)(end - p) < 20)
        rc = 2;
    return rc;
}

int lint_git_index_foreach(int (*fn)(const char *, int, void *), void *ctx)
{
    char ipath[4608];
    if (lgi_locate(ipath, sizeof ipath))
        return 2;
    size_t n = 0;
    if (lgi_load(ipath, &n))
        return 2;
    if (n < 12 + 20 || memcmp(g_lgi_buf, "DIRC", 4) != 0)
        return 2;
    uint32_t ver = lgi_be32(g_lgi_buf + 4);
    if (ver < 2 || ver > 4)
        return 2;
    return lgi_entries(n, (int)ver, lgi_be32(g_lgi_buf + 8), fn, ctx);
}
int replay(FILE *out)
{
    if (fseek(out, 0, SEEK_SET) != 0)
        return die("z23-lint: fseek failed\n", "");
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    while ((n = getline(&line, &cap, out)) >= 0) {
        if (fwrite(line, 1, (size_t)n, stderr) != (size_t)n) {
            free(line);
            return die("z23-lint: write failed\n", "");
        }
    }
    int err = ferror(out);
    free(line);
    return err ? die("z23-lint: read failed\n", "") : 0;
}

int st_ok(int bad, const char *msg)
{
    if (bad)
        return 1;
    fputs(msg, stdout);
    return 0;
}

int want(const char *tag, const regex_t *re, const char *s, int w)
{
    if ((regexec(re, s, 0, NULL, 0) == 0) != w) {
        fprintf(stderr, "%s selftest: want %d: %s\n", tag, w, s);
        return 1;
    }
    return 0;
}

void drop2(regex_t *a, regex_t *b) { regfree(a); regfree(b); }

int walk_src(const char *dir, int hdrs,
                    int (*scan)(const char *, void *), void *ctx)
{
    struct dirent **names = NULL;
    int n = scandir(dir, &names, NULL, alphasort);
    if (n < 0)
        return errno == ENOENT ? 0 : die("z23-lint: cannot scan %s\n", dir);
    int rc = 0;
    for (int i = 0; i < n; i++) {
        const char *name = names[i]->d_name;
        if (rc == 0 && strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
            char path[4096];
            struct stat st;
            size_t nl = strlen(name);
            int k = snprintf(path, sizeof path, "%s/%s", dir, name);
            if (k < 0 || (size_t)k >= sizeof path)
                rc = die("z23-lint: path too long: %s\n", dir);
            else if (lstat(path, &st) != 0)
                rc = die("z23-lint: cannot stat %s\n", path);
            else if (S_ISDIR(st.st_mode))
                rc = walk_src(path, hdrs, scan, ctx);
            else if (S_ISREG(st.st_mode) && nl >= 2
                     && ((hdrs == 2 && nl >= 4 && memcmp(name + nl - 4, ".def", 4) == 0)
                         || (hdrs != 2 && name[nl - 2] == '.'
                             && (name[nl - 1] == 'c' || (hdrs && name[nl - 1] == 'h')))))
                rc = scan(path, ctx);
        }
        free(names[i]);
    }
    free(names);
    return rc;
}

/* A gate that names its scan roots as a literal C array must not go quiet
 * when the tree is renamed out from under it: walk_src() (below) returns 0
 * on ENOENT so a recursive sub-directory that vanished mid-walk is not an
 * error, but the TOP-level root a gate hard-codes is a different thing — its
 * absence means the gate is scanning nothing and reporting false-clean.
 * require_scan_root() makes that FATAL; walk_src_root() is the checked
 * entry point gates should call instead of walk_src() for such a literal
 * root. Callers that already probe optional/derived paths (stat() the dir
 * themselves before walking, or accept a runtime-supplied path) keep calling
 * walk_src() directly — see each such call site's own comment. */
int require_scan_root(const char *gate, const char *root)
{
    struct stat st;
    if (stat(root, &st) == 0)
        return 0;
    if (errno == ENOENT) {
        fprintf(stderr, "FATAL — scan root '%s' does not exist (gate %s)\n",
                root, gate);
        return 2;
    }
    return die("z23-lint: cannot stat %s\n", root);
}

int walk_src_root(const char *gate, const char *root, int hdrs,
                         int (*scan)(const char *, void *), void *ctx)
{
    int rc = require_scan_root(gate, root);
    return rc ? rc : walk_src(root, hdrs, scan, ctx);
}

int fcount_scan(const char *path, void *ctx)
{
    (void)path;
    (*(int *)ctx)++;
    return 0;
}

/* Count files walk_src_root() would visit across `roots` (matching `hdrs`)
 * without running any pattern match — an independent number a gate can
 * check with gate_require_scanned() so a root that EXISTS but yields far
 * fewer files than expected (an extension-filter bug, not a missing
 * directory — require_scan_root() already FATALs on that) still trips. */
int walk_count_roots(const char *gate, const char *const *roots, size_t nroots,
                     int hdrs, int *out)
{
    *out = 0;
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < nroots; i++)
        rc = walk_src_root(gate, roots[i], hdrs, fcount_scan, out);
    return rc;
}

static size_t cstrip_literal(const char *line, size_t n, char *out, size_t i,
                             char q)
{
    out[i] = line[i];
    i++;
    while (i < n && line[i] != q) {
        if (line[i] == '\\' && i + 1 < n) {
            out[i] = ' ';
            out[i + 1] = ' ';
            i += 2;
            continue;
        }
        out[i] = ' ';
        i++;
    }
    if (i < n) {
        out[i] = line[i];
        i++;
    }
    return i;
}

/* Blank //-line-comments, block comments (state persists across calls via
 * *st, for one that spans lines), and "..."/'...' literal bodies out of
 * `line` (n bytes, no trailing NUL needed in the count) into `out`, so a
 * regex hit-test against `out` skips commented-out code, doc prose, and a
 * pattern that only appears inside a string/char literal. `out` must hold
 * at least `cap` bytes; returns 0 (leaves `out` untouched) if n >= cap, so
 * the caller can fall back to matching the raw line for the rare
 * pathologically long one instead of truncating it silently. Reset *st to
 * {0} at the start of each file — block-comment state does not carry
 * across files. */
/* Advance past one character of an already-open block comment, blanking
 * it, and clear *in_block on its closing "*" "/" pair. Returns the new i. */
static size_t cstrip_in_block(const char *line, size_t n, char *out, size_t i,
                              int *in_block)
{
    if (line[i] == '*' && i + 1 < n && line[i + 1] == '/') {
        out[i] = ' ';
        out[i + 1] = ' ';
        *in_block = 0;
        return i + 2;
    }
    out[i] = ' ';
    return i + 1;
}

int cstrip_line(struct cstrip *st, const char *line, size_t n, char *out,
                size_t cap)
{
    if (n >= cap)
        return 0;
    size_t i = 0;
    while (i < n) {
        if (st->in_block) {
            i = cstrip_in_block(line, n, out, i, &st->in_block);
            continue;
        }
        if (line[i] == '/' && i + 1 < n && line[i + 1] == '/') {
            while (i < n) {
                out[i] = ' ';
                i++;
            }
            break;
        }
        if (line[i] == '/' && i + 1 < n && line[i + 1] == '*') {
            out[i] = ' ';
            out[i + 1] = ' ';
            i += 2;
            st->in_block = 1;
            continue;
        }
        if (line[i] == '"' || line[i] == '\'') {
            i = cstrip_literal(line, n, out, i, line[i]);
            continue;
        }
        out[i] = line[i];
        i++;
    }
    out[n] = '\0';
    return 1;
}

int compile_pat(regex_t *re, int flags, const char *a, const char *b,
                       const char *c, const char *d)
{
    char pat[160];
    int n = snprintf(pat, sizeof pat, "%s%s%s%s", a, b, c, d);
    if (n < 0 || (size_t)n >= sizeof pat)
        return die("z23-lint: pattern buffer overflow\n", "");
    return reg_fail(re, regcomp(re, pat, flags));
}

int pair_comp(regex_t *a, int fa, const char *a0, const char *a1,
                     const char *a2, const char *a3, regex_t *b, int fb,
                     const char *b0, const char *b1, const char *b2, const char *b3)
{
    int cr = compile_pat(a, fa, a0, a1, a2, a3);
    if (cr)
        return cr;
    cr = compile_pat(b, fb, b0, b1, b2, b3);
    if (cr)
        regfree(a);
    return cr;
}

int miss(const char *path, FILE *out, const char *fmt)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        if (errno != ENOENT)
            return die("z23-lint: cannot stat %s\n", path);
    } else if (S_ISREG(st.st_mode))
        return 0;
    fprintf(out, fmt, path);
    return 1;
}

int scan_re(const char *path, const regex_t *re, int *hits, int show)
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
        if (regexec(re, line, 0, NULL, 0) != 0)
            continue;
        (*hits)++;
        if (!show)
            break;
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        if (fprintf(stdout, "%s:%d:%s\n", path, lineno, line) < 0) {
            rc = die("z23-lint: write failed\n", "");
            break;
        }
    }
    return fin(f, line, path, rc);
}

void drop3(regex_t *a, regex_t *b, regex_t *c)
{
    drop2(a, b);
    regfree(c);
}

/* C scan_exclusions/repo_shape/gate_lib bits. Non-parity: no ZCL_GATE_SCAN_LOG. */
const char k_planted[] = "tools/lint/fixtures/planted";
static regex_t g_excl_re;
int g_excl_ok, g_n_ctx, g_n_shapes, g_n_libs, g_n_mods, g_n_auth, g_rs_ready;
char g_ctx[RS_MAX][RS_NAME], g_shapes[RS_SHAPE][RS_NAME];
char g_libs[RS_MAX][RS_NAME], g_mods[RS_MAX][RS_PATH], g_auth[RS_AUTH][RS_PATH];
const char *const k_domain[] = {
    "contexts/wallet/domain", "platform/domain/encoding"
};

int ovf(int n, size_t cap)
{ return (n < 0 || (size_t)n >= cap) ? die("z23-lint: derived buffer overflow\n", "") : 0; }
int rs_ovf(void) { return die("z23-lint: repo-shape overflow\n", ""); }
static const char *rs_root(void)
{ const char *e = getenv("ZCL_REPO_SHAPE_ROOT"); return (e && e[0]) ? e : "."; }
int lint_prod_scan(void)
{ const char *e = getenv("ZCL_LINT_PRODUCTION_SCAN"); return e && strcmp(e, "1") == 0; }

int excl_ensure(void)
{
    if (g_excl_ok) return 0;
    char pat[256];
    int n = snprintf(pat, sizeof pat, "%s|%s%s%s%s%s",
                     "(^|/)_[^/]*fixture[^/]*\\.[ch]$", "(^|/)", k_planted,
                     "/|(^|/)build/|(^|/)vendor/|(^|/)\\.claude/",
                     "|(^|/)test-tmp/", "");
    if (ovf(n, sizeof pat)) return 2;
    int err = reg_fail(&g_excl_re, regcomp(&g_excl_re, pat, REG_EXTENDED));
    return err ? err : (g_excl_ok = 1, 0);
}

int lint_path_is_excluded(const char *path)
{ return lint_prod_scan() && !excl_ensure() && regexec(&g_excl_re, path, 0, NULL, 0) == 0; }

int lint_filter_excluded(const char *in, char *out, size_t cap)
{
    if (!lint_prod_scan())
        return ovf(snprintf(out, cap, "%s", in), cap);
    if (excl_ensure()) return 2;
    size_t used = 0;
    out[0] = '\0';
    for (const char *p = in; *p; ) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        char line[4096];
        if (n >= sizeof line) return die("z23-lint: derived buffer overflow\n", "");
        memcpy(line, p, n);
        line[n] = '\0';
        if (regexec(&g_excl_re, line, 0, NULL, 0) != 0) {
            int k = snprintf(out + used, cap - used, "%s%s", line, nl ? "\n" : "");
            if (ovf(k, cap - used)) return 2;
            used += (size_t)k;
        }
        p = nl ? nl + 1 : p + n;
        if (!nl) break;
    }
    return 0;
}

int lint_annotate_stray(const char *path, FILE *out)
{
    char cmd[4096];
    if (ovf(snprintf(cmd, sizeof cmd, "git ls-files --error-unmatch -- %s", path),
            sizeof cmd))
        return 2;
    FILE *p = popen(cmd, "r");
    if (!p) return die("z23-lint: popen failed (%s)\n", cmd);
    char *buf = NULL;
    size_t cap = 0;
    while (getline(&buf, &cap, p) >= 0) { }
    free(buf);
    int st = pclose(p);
    if (st == 0)
        return fputs(path, out) < 0 ? die("z23-lint: write failed\n", "") : 0;
    return fprintf(out, "%s [untracked stray file -- not a code violation; "
                   "likely left by a crashed agent/worktree, delete it]", path) < 0
               ? die("z23-lint: write failed\n", "") : 0;
}

int gate_require_scanned(int count, int floor, const char *name,
                                const char *hint)
{
    if (count >= floor) return 0;
    fprintf(stderr, "%s: FATAL — scan set is '%d' (< floor %d).\n", name, count, floor);
    fputs("  The scan producer (find/glob/grep) returned too little; a\n"
          "  scanned dir/file was likely renamed, moved, or deleted.\n"
          "  Refusing to report 'clean' off a hollow (empty) scan.\n", stderr);
    if (hint && hint[0]) fprintf(stderr, "  %s\n", hint);
    return 2;
}

int gate_count_and_report(const char *matches, int *out_count)
{
    *out_count = 0;
    if (!matches) return 0;
    int any = 0;
    for (const char *s = matches; *s; s++)
        if (!isspace((unsigned char)*s)) { any = 1; break; }
    if (!any) return 0;
    for (const char *p = matches; *p; ) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        if (n > 0) {
            (*out_count)++;
            if (fwrite(p, 1, n, stderr) != n || fputc('\n', stderr) == EOF)
                return die("z23-lint: write failed\n", "");
        }
        if (!nl) break;
        p = nl + 1;
    }
    return 0;
}

static int rs_continues(const char *s)
{
    size_t n = strlen(s);
    while (n && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' '
                 || s[n - 1] == '\t'))
        n--;
    return n && s[n - 1] == '\\';
}

static int rs_emit(char *line, char dst[][RS_NAME], int max, int *n)
{
    char *hash = strchr(line, '#');
    if (hash) *hash = '\0';
    for (char *q = line; *q; q++) if (*q == '\\') *q = ' ';
    *n = 0;
    for (char *p = line; *p; ) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
        if (!*p) break;
        char *s = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') p++;
        char save = *p;
        *p = '\0';
        if (*n >= max || strlen(s) >= RS_NAME) return rs_ovf();
        memcpy(dst[*n], s, strlen(s) + 1);
        (*n)++;
        *p = save;
        if (save) p++;
    }
    return 0;
}

static int rs_make_list(const char *variable, char dst[][RS_NAME], int max, int *n)
{
    const char *mk = getenv("ZCL_REPO_SHAPE_MAKEFILE");
    char path[4096];
    if (!mk || !mk[0]) {
        if (ovf(snprintf(path, sizeof path, "%s/Makefile", rs_root()), sizeof path))
            return 2;
        mk = path;
    }
    FILE *f = fopen(mk, "r");
    if (!f) return die("z23-lint: cannot open %s\n", mk);
    char *line = NULL, assembled[8192];
    size_t cap = 0, alen = strlen(variable);
    int found = 0, rc = 0;
    assembled[0] = '\0';
    while (getline(&line, &cap, f) >= 0) {
        if (!found) {
            if (strncmp(line, variable, alen) != 0) continue;
            const char *p = line + alen;
            while (*p == ' ' || *p == '\t') p++;
            if (*p != '=') continue;
            found = 1;
            if (ovf(snprintf(assembled, sizeof assembled, "%s", p + 1), sizeof assembled)) {
                rc = 2; break;
            }
            if (!rs_continues(line)) break;
            continue;
        }
        size_t used = strlen(assembled);
        int k = snprintf(assembled + used, sizeof assembled - used, " %s", line);
        if (ovf(k, sizeof assembled - used)) { rc = 2; break; }
        if (!rs_continues(line)) break;
    }
    if (rc == 0) rc = found ? rs_emit(assembled, dst, max, n) : (*n = 0, 0);
    return fin(f, line, mk, rc);
}

static int rs_cmp_name(const void *a, const void *b) { return strcmp(a, b); }

static int rs_uniq(void *arr, int n, size_t stride)
{
    if (n <= 1) return n;
    qsort(arr, (size_t)n, stride, rs_cmp_name);
    int w = 1;
    char *base = arr;
    for (int i = 1; i < n; i++) {
        if (strcmp(base + (size_t)i * stride, base + (size_t)(w - 1) * stride) != 0) {
            if (w != i)
                memcpy(base + (size_t)w * stride, base + (size_t)i * stride, stride);
            w++;
        }
    }
    return w;
}

static const char *rs_env_or(const char *env, char *buf, size_t cap, const char *fmt)
{
    const char *e = getenv(env);
    if (e && e[0]) return e;
    return ovf(snprintf(buf, cap, fmt, rs_root()), cap) ? NULL : buf;
}

static int rs_lib_modules(void)
{
    char path[4096];
    const char *md = rs_env_or("ZCL_REPO_SHAPE_MODULE_DEF", path, sizeof path,
                               "%s/engine/composition/lib_module_order.def");
    if (!md) return 2;
    FILE *f = fopen(md, "r");
    if (!f) return die("z23-lint: cannot open %s\n", md);
    char *line = NULL;
    size_t cap = 0;
    g_n_libs = 0;
    int rc = 0;
    while (getline(&line, &cap, f) >= 0) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (strncmp(p, "LIB_MODULE(\"", 12) != 0) continue;
        p += 12;
        char *e = p;
        while ((*e >= 'A' && *e <= 'Z') || (*e >= 'a' && *e <= 'z')
               || (*e >= '0' && *e <= '9') || *e == '_')
            e++;
        if (*e != '"' || e[1] != ')' ) continue;
        size_t n = (size_t)(e - p);
        if (g_n_libs >= RS_MAX || n >= RS_NAME) { rc = rs_ovf(); break; }
        memcpy(g_libs[g_n_libs], p, n);
        g_libs[g_n_libs][n] = '\0';
        g_n_libs++;
    }
    rc = fin(f, line, md, rc);
    if (rc) return rc;
    g_n_libs = rs_uniq(g_libs, g_n_libs, RS_NAME);
    return 0;
}

static int rs_is_module_dir(const char *rel)
{
    const char *slash = strrchr(rel, '/');
    if (!slash || slash == rel || slash[1] == '\0') return 0;
    if (slash >= rel + 8 && strncmp(slash - 8, "/modules", 8) == 0) return 1;
    return strncmp(rel, "modules/", 8) == 0 && strchr(rel + 8, '/') == NULL;
}

static int rs_mod_walk(const char *dir, int depth)
{
    struct dirent **names = NULL;
    int n = scandir(dir, &names, NULL, alphasort);
    if (n < 0)
        return (errno == ENOENT || errno == EACCES) ? 0
            : die("z23-lint: cannot scan %s\n", dir);
    int rc = 0;
    for (int i = 0; i < n; i++) {
        const char *name = names[i]->d_name;
        if (rc == 0 && strcmp(name, ".") && strcmp(name, "..")) {
            char path[4096];
            struct stat st;
            int k = snprintf(path, sizeof path, "%s/%s", dir, name);
            if (ovf(k, sizeof path)) rc = 2;
            else if (lstat(path, &st) != 0)
                rc = (errno == ENOENT || errno == EACCES) ? 0
                    : die("z23-lint: cannot stat %s\n", path);
            else if (S_ISDIR(st.st_mode)) {
                int nd = depth + 1;
                if (nd >= 2 && nd <= 4) {
                    const char *root = rs_root();
                    size_t rl = strlen(root);
                    const char *rel = (strncmp(path, root, rl) == 0 && path[rl] == '/')
                        ? path + rl + 1 : path;
                    if (rs_is_module_dir(rel)) {
                        if (g_n_mods >= RS_MAX || strlen(rel) >= RS_PATH) rc = rs_ovf();
                        else { memcpy(g_mods[g_n_mods], rel, strlen(rel) + 1); g_n_mods++; }
                    }
                }
                if (rc == 0 && nd < 4) rc = rs_mod_walk(path, nd);
            }
        }
        free(names[i]);
    }
    free(names);
    return rc;
}

static int rs_isdir(const char *rel)
{
    char path[4096];
    struct stat st;
    if (ovf(snprintf(path, sizeof path, "%s/%s", rs_root(), rel), sizeof path))
        return 0;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static int rs_put(char out[][RS_PATH], int max, int *n, const char *base,
                  const char *leaf)
{
    char path[RS_PATH];
    int k = (leaf && leaf[0]) ? snprintf(path, sizeof path, "%s/%s", base, leaf)
                              : snprintf(path, sizeof path, "%s", base);
    if (ovf(k, sizeof path)) return 2;
    if (!rs_isdir(path)) return 0;
    if (*n >= max) return rs_ovf();
    memcpy(out[*n], path, strlen(path) + 1);
    (*n)++;
    return 0;
}

int rs_init(void)
{
    if (g_rs_ready) return 0;
    char mk[4096], md[4096];
    const char *mkp = rs_env_or("ZCL_REPO_SHAPE_MAKEFILE", mk, sizeof mk, "%s/Makefile");
    const char *mdp = rs_env_or("ZCL_REPO_SHAPE_MODULE_DEF", md, sizeof md,
                                "%s/engine/composition/lib_module_order.def");
    if (!mkp || !mdp) return 2;
    FILE *fm = fopen(mkp, "r"), *fd = fopen(mdp, "r");
    if (!fm || !fd) {
        if (fm) fclose(fm);
        if (fd) fclose(fd);
        fputs("repo-shape: FATAL — architecture declarations are unreadable\n", stderr);
        return 2;
    }
    fclose(fm); fclose(fd);
    int rc = rs_make_list("PRODUCT_CONTEXTS", g_ctx, RS_MAX, &g_n_ctx);
    if (rc == 0) rc = rs_make_list("APP_DIRS", g_shapes, RS_SHAPE, &g_n_shapes);
    if (rc == 0) rc = rs_lib_modules();
    if (rc == 0)
        rc = gate_require_scanned(g_n_ctx, 1, "repo-shape",
                                  "PRODUCT_CONTEXTS parse came back empty");
    if (rc == 0)
        rc = gate_require_scanned(g_n_shapes, 1, "repo-shape",
                                  "APP_DIRS parse came back empty");
    if (rc == 0)
        rc = gate_require_scanned(g_n_libs, 1, "repo-shape",
                                  "module declaration parse came back empty");
    g_n_mods = 0;
    static const char *const auth[] = {
        "core", "engine", "cognition", "platform", "contexts"
    };
    for (size_t i = 0; rc == 0 && i < sizeof auth / sizeof auth[0]; i++) {
        char start[4096];
        if (ovf(snprintf(start, sizeof start, "%s/%s", rs_root(), auth[i]), sizeof start))
            return 2;
        rc = rs_mod_walk(start, 0);
    }
    if (rc) return rc;
    g_n_mods = rs_uniq(g_mods, g_n_mods, RS_PATH);
    rc = gate_require_scanned(g_n_mods, g_n_libs, "repo-shape",
                              "physical module directory set is incomplete");
    if (rc) return rc;
    memcpy(g_auth[0], "engine", 7);
    memcpy(g_auth[1], "cognition", 10);
    g_n_auth = 2;
    for (int i = 0; i < g_n_ctx; i++) {
        if (g_n_auth >= RS_AUTH) return rs_ovf();
        if (ovf(snprintf(g_auth[g_n_auth], RS_PATH, "contexts/%s", g_ctx[i]), RS_PATH))
            return 2;
        g_n_auth++;
    }
    g_rs_ready = 1;
    return 0;
}

int repo_shape_dirs(const char *family, const char *leaf,
                           char out[][RS_PATH], int max, int *n)
{
    int rc = rs_init();
    if (rc) return rc;
    *n = 0;
    if (strcmp(family, "app") == 0) {
        for (int a = 0; rc == 0 && a < g_n_auth; a++)
            for (int s = 0; rc == 0 && s < g_n_shapes; s++) {
                char base[RS_PATH];
                if (ovf(snprintf(base, sizeof base, "%s/%s", g_auth[a], g_shapes[s]),
                        sizeof base))
                    return 2;
                rc = rs_put(out, max, n, base, leaf);
            }
        return rc;
    }
    if (strcmp(family, "lib") == 0) {
        for (int i = 0; rc == 0 && i < g_n_mods; i++)
            rc = rs_put(out, max, n, g_mods[i], leaf);
        return rc;
    }
    if (strcmp(family, "domain") == 0) {
        for (size_t i = 0; rc == 0 && i < sizeof k_domain / sizeof k_domain[0]; i++)
            rc = rs_put(out, max, n, k_domain[i], leaf);
        return rc;
    }
    fprintf(stderr, "repo_shape_dirs: FATAL — unknown family '%s'\n", family);
    return 2;
}

int repo_shape_room_dirs(const char *shape, char out[][RS_PATH], int max,
                                int *n)
{
    int rc = rs_init();
    if (rc) return rc;
    *n = 0;
    for (int i = 0; rc == 0 && i < g_n_auth; i++)
        rc = rs_put(out, max, n, g_auth[i], shape);
    if (rc) return rc;
    if (*n == 0) {
        fprintf(stderr, "repo_shape_room_dirs: FATAL — no '%s' room exists\n", shape);
        return 2;
    }
    return 0;
}
const char *clock_mode(void)
{ const char *m = getenv("ZCL_LINT_MODE"); return (m && m[0]) ? m : "FAIL"; }
int clock_grade(int v, const char *mode)
{ return (v > 0 && strcmp(mode, "FAIL") == 0) ? 1 : 0; }
int sr_has(const struct sr_set *s, const char *name)
{ for (int i = 0; i < s->count; i++) if (!strcmp(s->n[i], name)) return 1; return 0; }

int sr_add(struct sr_set *s, const char *name)
{
    size_t n = strlen(name);
    if (sr_has(s, name)) return 0;
    if (s->count >= SR_ALLOW || n >= SR_NAME) return die("z23-lint: stray-root overflow\n", "");
    memcpy(s->n[s->count++], name, n + 1);
    return 0;
}

int sr_load(struct sr_set *s, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char *line = NULL;
    size_t cap = 0;
    int rc = 0;
    while (rc == 0 && getline(&line, &cap, f) >= 0) {
        char *h = strchr(line, '#'), *p = line;
        if (h) *h = '\0';
        while (*p && isspace((unsigned char)*p)) p++;
        size_t n = strlen(p);
        while (n && isspace((unsigned char)p[n - 1])) p[--n] = '\0';
        if (n) rc = sr_add(s, p);
    }
    return fin(f, line, path, rc);
}

int bln_has(const struct bln_set *s, const char *name)
{
    for (int i = 0; i < s->count; i++)
        if (!strcmp(s->n[i], name))
            return 1;
    return 0;
}

int bln_add(struct bln_set *s, const char *name)
{
    size_t n = strlen(name);
    if (bln_has(s, name))
        return 0;
    if (s->count >= BLN_MAX || n >= BLN_ROW)
        return die("z23-lint: baseline-set overflow\n", "");
    memcpy(s->n[s->count++], name, n + 1);
    return 0;
}

int bln_load(struct bln_set *s, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char *line = NULL;
    size_t cap = 0;
    int rc = 0;
    while (rc == 0 && getline(&line, &cap, f) >= 0) {
        char *h = strchr(line, '#'), *p = line;
        if (h) *h = '\0';
        while (*p && isspace((unsigned char)*p)) p++;
        size_t n = strlen(p);
        while (n && isspace((unsigned char)p[n - 1])) p[--n] = '\0';
        if (n) rc = bln_add(s, p);
    }
    return fin(f, line, path, rc);
}

static int bln_diff_into(const struct bln_set *have, const struct bln_set *want,
                         struct bln_set *out)
{
    int rc = 0;
    for (int i = 0; rc == 0 && i < have->count; i++)
        if (!bln_has(want, have->n[i]))
            rc = bln_add(out, have->n[i]);
    return rc;
}

static int bln_print_rows(FILE *out, const struct bln_set *rows, const char *hdr)
{
    if (!rows->count)
        return 0;
    if (fputs(hdr, out) < 0)
        return die("z23-lint: write failed\n", "");
    for (int i = 0; i < rows->count; i++)
        if (fprintf(out, "  %s\n", rows->n[i]) < 0)
            return die("z23-lint: write failed\n", "");
    return 0;
}

int bln_diff_report(FILE *out, const char *gate, const char *baseline_path,
                    const struct bln_set *base, const struct bln_set *found)
{
    struct bln_set newc = {0}, stale = {0};
    int rc = bln_diff_into(found, base, &newc);
    if (rc == 0)
        rc = bln_diff_into(base, found, &stale);
    if (rc)
        return rc;
    if (newc.count == 0 && stale.count == 0)
        return 0;
    char nh[128], sh[192];
    if (ovf(snprintf(nh, sizeof nh, "%s: FATAL — %d NEW site(s) not in %s:\n",
                     gate, newc.count, baseline_path), sizeof nh)
        || ovf(snprintf(sh, sizeof sh,
                        "%s: FATAL — %d STALE baseline row(s) no longer found "
                        "(delete from %s — this baseline is shrink-only):\n",
                        gate, stale.count, baseline_path), sizeof sh))
        return die("z23-lint: message buffer overflow\n", "");
    rc = bln_print_rows(out, &newc, nh);
    if (rc == 0)
        rc = bln_print_rows(out, &stale, sh);
    return rc ? rc : 2;
}

int capture_cmd(const char *cmd, char *out, size_t cap, int *code)
{
    FILE *p = popen(cmd, "r");
    if (!p)
        return die("z23-lint: popen failed (%s)\n", cmd);
    size_t used = 0;
    out[0] = '\0';
    int rc = 0;
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, p)) > 0) {
        if (used + n >= cap) {
            rc = die("z23-lint: derived buffer overflow\n", "");
            break;
        }
        memcpy(out + used, buf, n);
        used += n;
        out[used] = '\0';
    }
    if (rc == 0 && ferror(p))
        rc = die("z23-lint: read failed (%s)\n", cmd);
    int st = pclose(p);
    if (rc)
        return rc;
    while (used && out[used - 1] == '\n')
        out[--used] = '\0';
    if (st == -1)
        *code = 127;
    else if (WIFEXITED(st))
        *code = WEXITSTATUS(st);
    else
        *code = 127;
    return 0;
}

int csr_mkdirs(const char *path)
{
    char buf[4096];
    if (ovf(snprintf(buf, sizeof buf, "%s", path), sizeof buf))
        return 2;
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(buf, 0700) != 0 && errno != EEXIST)
            return die("z23-lint: mkdir failed: %s\n", buf);
        *p = '/';
    }
    if (mkdir(buf, 0700) != 0 && errno != EEXIST)
        return die("z23-lint: mkdir failed: %s\n", buf);
    return 0;
}

int csr_write(const char *path, const char *text)
{
    char dir[4096];
    const char *slash = strrchr(path, '/');
    if (!slash)
        return die("z23-lint: path too long: %s\n", path);
    size_t n = (size_t)(slash - path);
    if (n >= sizeof dir)
        return die("z23-lint: path too long: %s\n", path);
    memcpy(dir, path, n);
    dir[n] = '\0';
    int rc = csr_mkdirs(dir);
    if (rc)
        return rc;
    FILE *f = fopen(path, "w");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    size_t len = strlen(text);
    rc = fwrite(text, 1, len, f) != len;
    if (fclose(f) != 0 && rc == 0)
        return die("z23-lint: fclose failed: %s\n", path);
    return rc ? die("z23-lint: write failed\n", "") : 0;
}

int csr_slurp(FILE *f, char *buf, size_t cap)
{
    rewind(f);
    size_t n = fread(buf, 1, cap - 1, f);
    buf[n] = '\0';
    return ferror(f) ? die("z23-lint: read failed\n", "") : 0;
}

int psp_st_reset(FILE *out)
{
    rewind(out);
    return ftruncate(fileno(out), 0) != 0;
}

int rap_rm_rf(const char *root)
{
    char cmd[8192], dump[64];
    int code = 0;
    if (strchr(root, '\''))
        return die("z23-lint: path too long: %s\n", root);
    if (ovf(snprintf(cmd, sizeof cmd, "rm -rf -- '%s'", root), sizeof cmd))
        return 2;
    return capture_cmd(cmd, dump, sizeof dump, &code);
}

int sh_single_quote(const char *in, char *out, size_t cap)
{
    size_t used = 0;
    if (cap < 3)
        return die("z23-lint: derived buffer overflow\n", "");
    out[used++] = '\'';
    for (const char *p = in; *p; p++) {
        if (*p == '\'') {
            if (used + 4 >= cap)
                return die("z23-lint: derived buffer overflow\n", "");
            out[used++] = '\'';
            out[used++] = '\\';
            out[used++] = '\'';
            out[used++] = '\'';
        } else {
            if (used + 2 > cap)
                return die("z23-lint: derived buffer overflow\n", "");
            out[used++] = *p;
        }
    }
    if (used + 2 > cap)
        return die("z23-lint: derived buffer overflow\n", "");
    out[used++] = '\'';
    out[used] = '\0';
    return 0;
}

/* The program's own absolute path, derived from argv[0] exactly the way the
 * shell gates derive SCRIPT_DIR — `cd "$(dirname "$0")" && pwd` — by entering
 * the directory and reading the working directory back. Every caller reaches
 * this binary through the tools/lint shim, which always passes a path with a
 * directory part; a bare name (found via PATH) is refused. No /proc read. */
const char *g_lint_argv0;

int lint_self_exe(char *buf, size_t cap)
{
    const char *a0 = g_lint_argv0;
    const char *slash = a0 ? strrchr(a0, '/') : NULL;
    char dir[4096], here[4096], there[4096];
    if (!slash || cap == 0)
        return die("z23-lint: cannot resolve executable path\n", "");
    size_t dlen = slash == a0 ? 1 : (size_t)(slash - a0);
    if (dlen >= sizeof dir || !getcwd(here, sizeof here))
        return die("z23-lint: cannot resolve executable path\n", "");
    memcpy(dir, a0, dlen);
    dir[dlen] = '\0';
    int ok = chdir(dir) == 0 && getcwd(there, sizeof there) != NULL;
    if (chdir(here) != 0)
        return die("z23-lint: cannot restore working directory\n", "");
    if (!ok)
        return die("z23-lint: cannot resolve executable path\n", "");
    int n = snprintf(buf, cap, "%s/%s", there, slash + 1);
    if (n < 0 || (size_t)n >= cap)
        return die("z23-lint: cannot resolve executable path\n", "");
    return 0;
}

const char *env_or(const char *name, const char *fallback)
{
    const char *e = getenv(name);
    return (e && e[0]) ? e : fallback;
}

int cic_repo_root(char *buf, size_t cap)
{
    if (lint_self_exe(buf, cap))
        return 2;
    /* $ROOT/build/bin/z23-lint → $ROOT (executable dir, then two parents). */
    for (int i = 0; i < 3; i++) {
        char *slash = strrchr(buf, '/');
        if (!slash || slash == buf)
            return die("z23-lint: cannot resolve executable path\n", "");
        *slash = '\0';
    }
    return 0;
}

int cic_invoke(const char *gate, int merge_err, char *out, size_t cap,
                      int *code)
{
    char exe[4096], quoted[8192], cmd[8192];
    if (lint_self_exe(exe, sizeof exe)
        || sh_single_quote(exe, quoted, sizeof quoted)
        || ovf(snprintf(cmd, sizeof cmd, "%s %s%s", quoted, gate,
                        merge_err ? " 2>&1" : ""), sizeof cmd))
        return 2;
    return capture_cmd(cmd, out, cap, code);
}

/* z23-lint --families: the family-size ledger. Lists every gate_*.c family
 * file under tools/lint/lintc/ (relative to the caller's cwd, like every
 * gate's scan) with its line count and headroom to LINT_FAMILY_CEILING. A
 * file over the ceiling is named on stderr and fails the command, so the
 * ledger doubles as the refusal the wiring gate enforces. Line counts are
 * newline counts, matching wc -l exactly. */

#define FL_MAX 64
#define FL_NAME 256

static int fl_count(const char *path, long *out)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    long n = 0;
    int c;
    while ((c = fgetc(f)) != EOF)
        if (c == '\n')
            n++;
    if (ferror(f)) {
        fclose(f);
        return die("z23-lint: read error on %s\n", path);
    }
    fclose(f);
    *out = n;
    return 0;
}

static int fl_cmp(const void *a, const void *b)
{
    return strcmp(a, b);
}

int lint_families_ledger(void)
{
    static const char k_dir[] = "tools/lint/lintc";
    DIR *d = opendir(k_dir);
    if (!d)
        return die("z23-lint: cannot open %s (run from the repo root)\n",
                   k_dir);
    static char names[FL_MAX][FL_NAME];
    int nf = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        const char *nm = de->d_name;
        size_t nl = strlen(nm);
        if (strncmp(nm, "gate_", 5) != 0 || nl < 7
            || strcmp(nm + nl - 2, ".c") != 0)
            continue;
        if (nf >= FL_MAX || nl >= FL_NAME) {
            closedir(d);
            return die("z23-lint: too many family files under %s\n", k_dir);
        }
        memcpy(names[nf], nm, nl + 1);
        nf++;
    }
    closedir(d);
    if (nf == 0)
        return die("z23-lint: no family files under %s\n", k_dir);
    qsort(names, (size_t)nf, FL_NAME, fl_cmp);
    int breach = 0;
    for (int i = 0; i < nf; i++) {
        char path[FL_NAME + 64];
        if (ovf(snprintf(path, sizeof path, "%s/%s", k_dir, names[i]),
                sizeof path))
            return 2;
        long lines;
        int rc = fl_count(path, &lines);
        if (rc)
            return rc;
        printf("%s: %ld lines, %ld headroom to %d\n", path, lines,
               LINT_FAMILY_CEILING - lines, LINT_FAMILY_CEILING);
        if (lines > LINT_FAMILY_CEILING) {
            fprintf(stderr, "z23-lint: FAMILY CEILING BREACH — %s has %ld "
                    "lines (ceiling %d)\n", path, lines,
                    LINT_FAMILY_CEILING);
            breach = 1;
        }
    }
    return breach;
}

/* ── shared shrink-only ratchet baseline (contract in lintc.h) ────────── */

static int lb_cmp(const void *a, const void *b)
{
    return strcmp(((const struct lb_row *)a)->key,
                  ((const struct lb_row *)b)->key);
}

/* Parse one baseline line into row r. Returns -1 for a comment/blank line,
 * 0 for a parsed row, 2 for a malformed line (named on err). */
static int lb_parse_line(char *line, struct lb_row *r, FILE *err)
{
    char *p = line;
    while (*p == ' ' || *p == '\t')
        p++;
    if (*p == '#' || *p == '\n' || *p == '\0')
        return -1;
    char *nl = strchr(p, '\n');
    if (nl)
        *nl = '\0';
    char *colon = strrchr(p, ':');
    if (!colon || colon == p) {
        fprintf(err, "z23-lint: FATAL — malformed baseline line: %s\n", p);
        return 2;
    }
    *colon = '\0';
    char *end = NULL;
    long v = strtol(colon + 1, &end, 10);
    if (!end || *end != '\0' || v < 1 || v > 100000) {
        fprintf(err, "z23-lint: FATAL — malformed baseline M in line: "
                     "%s:%s\n", p, colon + 1);
        return 2;
    }
    if (strlen(p) >= LB_KEY)
        return die("z23-lint: baseline key too long: %s\n", p);
    memcpy(r->key, p, strlen(p) + 1);
    r->pinned = (int)v;
    r->cur = 0;
    r->seen = 0;
    return 0;
}

int lint_base_load(struct lint_base *b, const char *path, FILE *err)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(err, "z23-lint: FATAL — missing baseline %s (create it, one "
                     "key:M per line, or empty)\n", path);
        return 2;
    }
    char *line = NULL;
    size_t cap = 0;
    int rc = 0;
    b->n = 0;
    while (rc == 0 && getline(&line, &cap, f) >= 0) {
        if (b->n >= LB_MAX) {
            rc = die("z23-lint: baseline overflow: %s\n", path);
            break;
        }
        int pr = lb_parse_line(line, &b->row[b->n], err);
        if (pr < 0)
            continue;
        if (pr) {
            rc = pr;
            break;
        }
        b->n++;
    }
    rc = fin(f, line, path, rc);
    if (rc)
        return rc;
    qsort(b->row, (size_t)b->n, sizeof b->row[0], lb_cmp);
    for (int i = 1; i < b->n; i++) {
        if (strcmp(b->row[i - 1].key, b->row[i].key) == 0) {
            fprintf(err, "z23-lint: FATAL — duplicate baseline entry %s\n",
                    b->row[i].key);
            return 2;
        }
    }
    return 0;
}

/* Presence-set loader: the gate_load_list_file() semantics the shell
 * allowlist gates used, as a lint_base row set. One plain key per line (no
 * :M); `#` starts a comment ANYWHERE on the line; leading/trailing
 * whitespace is trimmed; blank and comment lines are skipped; duplicate
 * keys collapse silently; a missing or non-regular file yields an empty
 * set, not an error. Rows are stored pinned=1 — membership is
 * lint_base_observe(b, key, 1) >= 0. lint_base_finish does NOT apply: an
 * entry no scan observed is unused, never stale. The set is
 * superset-allowed by contract (contract in lintc.h). */
static char *lb_set_key(char *line)
{
    char *h = strchr(line, '#');
    if (h)
        *h = '\0';
    char *p = line;
    while (*p && isspace((unsigned char)*p))
        p++;
    size_t n = strlen(p);
    while (n && isspace((unsigned char)p[n - 1]))
        p[--n] = '\0';
    return n ? p : NULL;
}

static int lb_set_add(struct lint_base *b, const char *key, const char *path)
{
    size_t n = strlen(key);
    if (b->n >= LB_MAX || n >= LB_KEY)
        return die("z23-lint: baseline overflow: %s\n", path);
    struct lb_row *r = &b->row[b->n++];
    memcpy(r->key, key, n + 1);
    r->pinned = 1;
    r->cur = 0;
    r->seen = 0;
    return 0;
}

static void lb_set_dedup(struct lint_base *b)
{
    qsort(b->row, (size_t)b->n, sizeof b->row[0], lb_cmp);
    int w = 0;
    for (int i = 0; i < b->n; i++) {
        if (w > 0 && strcmp(b->row[w - 1].key, b->row[i].key) == 0)
            continue;
        if (w != i)
            memcpy(&b->row[w], &b->row[i], sizeof b->row[0]);
        w++;
    }
    b->n = w;
}

int lint_base_load_set(struct lint_base *b, const char *path)
{
    struct stat st;
    b->n = 0;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
        return 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    int rc = 0;
    while (rc == 0 && getline(&line, &cap, f) >= 0) {
        char *key = lb_set_key(line);
        if (key)
            rc = lb_set_add(b, key, path);
    }
    rc = fin(f, line, path, rc);
    if (rc)
        return rc;
    lb_set_dedup(b);
    return 0;
}

int lint_base_observe(struct lint_base *b, const char *key, int m)
{
    struct lb_row k;
    memset(&k, 0, sizeof k);
    if (strlen(key) >= LB_KEY)
        return -1;
    memcpy(k.key, key, strlen(key) + 1);
    struct lb_row *r = bsearch(&k, b->row, (size_t)b->n, sizeof b->row[0],
                               lb_cmp);
    if (!r)
        return -1;
    r->seen = 1;
    r->cur = m;
    return (int)(r - b->row);
}

int lint_base_finish(const struct lint_base *b, FILE *out)
{
    int viol = 0;
    for (int i = 0; i < b->n; i++) {
        const struct lb_row *r = &b->row[i];
        int bad;
        if (!r->seen)
            bad = fprintf(out, "%s is pinned at M=%d but no longer exists — "
                          "stale baseline, delete the line\n",
                          r->key, r->pinned) < 0;
        else if (r->cur > r->pinned)
            bad = fprintf(out, "%s grew M=%d -> M=%d past its baseline pin\n",
                          r->key, r->pinned, r->cur) < 0;
        else if (r->cur < r->pinned)
            bad = fprintf(out, "%s shrank M=%d -> M=%d — ratchet the "
                          "baseline entry down to %d\n",
                          r->key, r->pinned, r->cur, r->cur) < 0;
        else
            continue;
        if (bad) {
            (void)die("z23-lint: write failed\n", "");
            return -1;
        }
        viol++;
    }
    return viol;
}

int lint_base_pin(struct lint_base *b, const char *key, int m)
{
    if (b->n >= LB_MAX || strlen(key) >= LB_KEY)
        return die("z23-lint: baseline overflow\n", "");
    struct lb_row *r = &b->row[b->n];
    memcpy(r->key, key, strlen(key) + 1);
    r->pinned = m;
    r->cur = 0;
    r->seen = 0;
    b->n++;
    return 0;
}

int lint_base_write(struct lint_base *b, const char *path, const char *hdr)
{
    qsort(b->row, (size_t)b->n, sizeof b->row[0], lb_cmp);
    FILE *f = fopen(path, "w");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    int rc = hdr && fputs(hdr, f) < 0;
    for (int i = 0; !rc && i < b->n; i++)
        rc = fprintf(f, "%s:%d\n", b->row[i].key, b->row[i].pinned) < 0;
    if (fclose(f) != 0 && rc == 0)
        return die("z23-lint: fclose failed: %s\n", path);
    return rc ? die("z23-lint: write failed\n", "") : 0;
}
