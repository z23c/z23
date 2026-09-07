/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — check-tor-full-default, the C23 lint runtime port
 * of tools/lint/check_tor_full_default.sh. Real Tor is the default link
 * and a stub cannot be packaged: (i) a build that links a node establishes
 * the Tor archives first, (ii) the stub is reachable only by naming
 * ZCL_TOR=stub, and (iii) every packaging step refuses a tor=stub binary
 * with the same sentence. This gate reads text only (Makefile, the two
 * refusal-sentence carriers, the two refusal-reaching packaging scripts,
 * and every file under tools/ for a reintroduced forced TOR_FULL=); it
 * spawns no process and runs no build.
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
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

enum {
    TFD_CAP = 2 * 1024 * 1024,
    TFD_LINE = 16384,
    TFD_PATH = 512,
    TFD_MSG = TFD_CAP,
    TFD_MISSING = 1,
};

static const char k_tfd_gate[] = "check-tor-full-default";
static const char k_tfd_refusal[] =
    "refusing to package a tor=stub binary: it cannot reach the onion "
    "network; rebuild with make tor-full";
static const char *const k_tfd_refusal_files[] = {
    "tools/scripts/tor_stamp_lib.sh",
    "tools/scripts/install_z23.sh",
};
static const char *const k_tfd_refusal_users[] = {
    "tools/ship.sh",
    "tools/scripts/build_c23_portable_release.sh",
};
enum { TFD_N_FILES = 2, TFD_N_USERS = 2 };

/* Reused scratch buffers: this gate reads one file at a time. */
static char g_tfd_raw[TFD_CAP];
static char g_tfd_joined[TFD_CAP];

static FILE *tfd_out, *tfd_err;
static const char *tfd_root_ov;

static void tfd_io_prod(void) { tfd_out = stdout; tfd_err = stderr; }
static void tfd_clear_ov(void) { tfd_root_ov = NULL; tfd_io_prod(); }
static const char *tfd_root(void) { return tfd_root_ov ? tfd_root_ov : "."; }

static int tfd_path(char *buf, size_t cap, const char *rel)
{
    return ovf(snprintf(buf, cap, "%s/%s", tfd_root(), rel), cap);
}

static int tfd_cannot_open(const char *path)
{
    fprintf(tfd_err ? tfd_err : stderr, "z23-lint: cannot open %s\n", path);
    return 2;
}

struct tfd_state { int fail; };

static int tfd_note(struct tfd_state *st, const char *msg)
{
    if (fprintf(tfd_err ? tfd_err : stderr, "%s: FAIL \xe2\x80\x94 %s\n",
                k_tfd_gate, msg) < 0)
        return die("z23-lint: write failed\n", "");
    st->fail = 1;
    return 0;
}

static int tfd_note_path(struct tfd_state *st, const char *fmt, const char *p)
{
    char msg[TFD_PATH + 128];
    if (ovf(snprintf(msg, sizeof msg, fmt, p), sizeof msg)) return 2;
    return tfd_note(st, msg);
}

/* Read a whole file into buf. 0 = ok, TFD_MISSING = ENOENT, 2 = fatal
 * (present but unreadable, or the file is larger than the buffer). */
static int tfd_read(const char *path, char *buf, size_t cap, size_t *outn)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return errno == ENOENT ? TFD_MISSING : tfd_cannot_open(path);
    size_t n = fread(buf, 1, cap - 1, f);
    if (n == cap - 1) {
        char extra;
        if (fread(&extra, 1, 1, f) == 1) {
            fclose(f);
            return die("z23-lint: derived buffer overflow\n", "");
        }
    }
    int err = ferror(f);
    if (fclose(f) != 0 && !err) return die("z23-lint: fclose failed: %s\n", path);
    if (err) return die("z23-lint: read failed: %s\n", path);
    buf[n] = '\0';
    *outn = n;
    return 0;
}

/* Collapse every backslash-newline pair, same effect as
 * `sed -e :a -e '/\\$/{N;s/\\\n//;ta}'`: a Makefile assignment split over
 * continuation lines reads as one logical line to the checks that need it. */
static void tfd_join(const char *raw, char *out)
{
    size_t oi = 0;
    for (size_t i = 0; raw[i] != '\0'; i++) {
        if (raw[i] == '\\' && raw[i + 1] == '\n') { i++; continue; }
        out[oi++] = raw[i];
    }
    out[oi] = '\0';
}

static int tfd_mem_has(const char *s, size_t len, const char *needle)
{
    size_t nl = strlen(needle);
    if (nl == 0 || nl > len) return 0;
    for (size_t i = 0; i + nl <= len; i++)
        if (memcmp(s + i, needle, nl) == 0) return 1;
    return 0;
}

static int tfd_line_lit(const char *text, const char *needle)
{
    const char *p = text;
    while (*p != '\0') {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (tfd_mem_has(p, len, needle)) return 1;
        if (!nl) break;
        p = nl + 1;
    }
    return 0;
}

static int tfd_line_re(const char *text, const regex_t *re)
{
    const char *p = text;
    char line[TFD_LINE];
    while (*p != '\0') {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (len >= sizeof line) len = sizeof line - 1;
        memcpy(line, p, len);
        line[len] = '\0';
        if (regexec(re, line, 0, NULL, 0) == 0) return 1;
        if (!nl) break;
        p = nl + 1;
    }
    return 0;
}

/* ── the eight Makefile-shaped checks ──────────────────────────────── */

struct tfd_re {
    regex_t tor_ready, link_req, tor_default, error_clause, tor_full_filter;
};

static int tfd_re_comp(struct tfd_re *r)
{
    int rc = compile_pat(&r->tor_ready, REG_EXTENDED,
        "^\\$\\(TOR_BOOTSTRAP_MK\\):[[:space:]]*tor-ready", "", "", "");
    if (rc) return rc;
    rc = compile_pat(&r->link_req, REG_EXTENDED,
        "ZCL_TOR_LINK_REQUESTED[[:space:]]*:?=.*filter-out[[:space:]]+"
        "\\$\\(ZCL_TOR_SKIP_GOALS\\)", "", "", "");
    if (rc) { regfree(&r->tor_ready); return rc; }
    rc = compile_pat(&r->tor_default, REG_EXTENDED,
        "^ZCL_TOR[[:space:]]*\\?=[[:space:]]*full$", "", "", "");
    if (rc) { regfree(&r->tor_ready); regfree(&r->link_req); return rc; }
    rc = compile_pat(&r->error_clause, REG_EXTENDED,
        "\\$\\(error ZCL_TOR must be", "", "", "");
    if (rc) {
        regfree(&r->tor_ready); regfree(&r->link_req);
        regfree(&r->tor_default);
        return rc;
    }
    rc = compile_pat(&r->tor_full_filter, REG_EXTENDED,
        "^TOR_FULL[[:space:]]*=.*filter[[:space:]]+stub,\\$\\(ZCL_TOR\\)",
        "", "", "");
    if (rc) {
        regfree(&r->tor_ready); regfree(&r->link_req);
        regfree(&r->tor_default); regfree(&r->error_clause);
    }
    return rc;
}

static void tfd_re_drop(struct tfd_re *r)
{
    regfree(&r->tor_ready); regfree(&r->link_req); regfree(&r->tor_default);
    regfree(&r->error_clause); regfree(&r->tor_full_filter);
}

/* One check-and-note site, so the eight Makefile assertions below cost the
 * caller a single branch each instead of an "if (!ok) { note; if (rc) }"
 * triplet apiece (keeps tfd_check_makefile under the complexity cap). */
static int tfd_require(struct tfd_state *st, int ok, const char *msg)
{ return ok ? 0 : tfd_note(st, msg); }

static int tfd_check_makefile(struct tfd_state *st, const struct tfd_re *r)
{
    int rc = tfd_require(st, tfd_line_lit(g_tfd_raw, "-include $(TOR_BOOTSTRAP_MK)"),
        "the Makefile never includes $(TOR_BOOTSTRAP_MK), so a plain "
        "`make` does not establish the Tor archives and links the stub");
    if (rc) return rc;
    rc = tfd_require(st, tfd_line_re(g_tfd_raw, &r->tor_ready),
        "$(TOR_BOOTSTRAP_MK) has no 'tor-ready' prerequisite, so the "
        "include cannot build anything");
    if (rc) return rc;
    rc = tfd_require(st, tfd_line_re(g_tfd_joined, &r->link_req),
        "ZCL_TOR_LINK_REQUESTED is not computed as filter-out of a "
        "skip list; an allow list would let any unlisted goal link "
        "the stub");
    if (rc) return rc;
    rc = tfd_require(st, tfd_line_re(g_tfd_raw, &r->tor_default),
        "ZCL_TOR does not default to 'full'");
    if (rc) return rc;
    rc = tfd_require(st, tfd_line_re(g_tfd_raw, &r->error_clause),
        "an unrecognised ZCL_TOR value is not refused; the Makefile "
        "would guess");
    if (rc) return rc;
    rc = tfd_require(st, tfd_line_re(g_tfd_raw, &r->tor_full_filter),
        "TOR_FULL is not emptied by ZCL_TOR=stub, so the stub is not "
        "selected by the knob");
    if (rc) return rc;
    rc = tfd_require(st,
        tfd_line_lit(g_tfd_raw, "ZCL_TOR=stub - LINKING THE OFFLINE TOR STUB"),
        "selecting the stub prints no loud line");
    if (rc) return rc;
    return tfd_require(st, tfd_line_lit(g_tfd_raw, "zcl_tor_require_full"),
        "the Makefile's install recipe never reads the tor stamp, so "
        "`make install` would place a stub node");
}

static int tfd_check_carriers(struct tfd_state *st)
{
    for (int i = 0; i < TFD_N_FILES; i++) {
        char path[TFD_PATH];
        const char *rel = k_tfd_refusal_files[i];
        if (tfd_path(path, sizeof path, rel)) return 2;
        size_t n = 0;
        int rc = tfd_read(path, g_tfd_raw, sizeof g_tfd_raw, &n);
        if (rc == 2) return rc;
        if (rc == TFD_MISSING) {
            rc = tfd_note_path(st, "%s is missing", rel);
            if (rc) return rc;
            continue;
        }
        if (!tfd_line_lit(g_tfd_raw, k_tfd_refusal)) {
            rc = tfd_note_path(st,
                "%s does not carry the exact tor=stub refusal sentence", rel);
            if (rc) return rc;
        }
    }
    return 0;
}

static int tfd_check_users(struct tfd_state *st)
{
    regex_t re;
    int rc = compile_pat(&re, REG_EXTENDED,
        "ZCL_TOR_STUB_REFUSAL|zcl_tor_require_full", "", "", "");
    if (rc) return rc;
    for (int i = 0; i < TFD_N_USERS; i++) {
        char path[TFD_PATH];
        const char *rel = k_tfd_refusal_users[i];
        if (tfd_path(path, sizeof path, rel)) { regfree(&re); return 2; }
        size_t n = 0;
        rc = tfd_read(path, g_tfd_raw, sizeof g_tfd_raw, &n);
        if (rc == 2) { regfree(&re); return rc; }
        if (rc == TFD_MISSING) {
            rc = tfd_note_path(st, "%s is missing", rel);
            if (rc) { regfree(&re); return rc; }
            continue;
        }
        if (!tfd_line_re(g_tfd_raw, &re)) {
            rc = tfd_note_path(st,
                "%s packages a binary but never reaches the tor=stub refusal",
                rel);
            if (rc) { regfree(&re); return rc; }
        }
    }
    regfree(&re);
    return 0;
}

/* ── forced-TOR_FULL= scan over the whole tools/ tree + the Makefile ──── */

struct tfd_forced {
    regex_t re;
    char *msg;
    size_t used, cap;
    int nmatch;
};

static int tfd_forced_is_self(const char *path)
{
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    /* The shim (kept for parity with the original script) and this C
     * port's own source both discuss/embed the literal "TOR_FULL=" text
     * they hunt for (in comments, and in this file's selftest fixture
     * payload) and must not trip on themselves. */
    return strcmp(base, "check_tor_full_default.sh") == 0
        || strcmp(base, "gate_tor_full_default.c") == 0;
}

static int tfd_forced_append(struct tfd_forced *fo, const char *path,
                             int lineno, const char *line)
{
    char rec[TFD_LINE + TFD_PATH];
    if (ovf(snprintf(rec, sizeof rec, "%s:%d:%s\n", path, lineno, line),
            sizeof rec))
        return 2;
    size_t rl = strlen(rec);
    if (fo->used + rl >= fo->cap)
        return die("z23-lint: derived buffer overflow\n", "");
    memcpy(fo->msg + fo->used, rec, rl + 1);
    fo->used += rl;
    fo->nmatch++;
    return 0;
}

static int tfd_forced_file(const char *path, void *ctx)
{
    struct tfd_forced *fo = ctx;
    if (tfd_forced_is_self(path)) return 0;
    FILE *f = fopen(path, "r");
    if (!f) return errno == ENOENT ? 0 : tfd_cannot_open(path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        lineno++;
        if (n > 0 && line[n - 1] == '\n') line[--n] = '\0';
        if (regexec(&fo->re, line, 0, NULL, 0) != 0) continue;
        const char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#') continue;
        rc = tfd_forced_append(fo, path, lineno, line);
        if (rc) break;
    }
    return fin(f, line, path, rc);
}

static int tfd_walk_all(const char *dir, int (*fn)(const char *, void *),
                        void *ctx)
{
    struct dirent **names = NULL;
    int n = scandir(dir, &names, NULL, alphasort);
    if (n < 0) return errno == ENOENT ? 0 : die("z23-lint: cannot scan %s\n", dir);
    int rc = 0;
    for (int i = 0; i < n; i++) {
        const char *name = names[i]->d_name;
        if (rc == 0 && strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
            char path[TFD_PATH];
            struct stat st;
            int k = snprintf(path, sizeof path, "%s/%s", dir, name);
            if (k < 0 || (size_t)k >= sizeof path)
                rc = die("z23-lint: path too long: %s\n", dir);
            else if (lstat(path, &st) != 0)
                rc = errno == ENOENT ? 0 : die("z23-lint: cannot stat %s\n", path);
            else if (S_ISDIR(st.st_mode))
                rc = tfd_walk_all(path, fn, ctx);
            else if (S_ISREG(st.st_mode))
                rc = fn(path, ctx);
        }
        free(names[i]);
    }
    free(names);
    return rc;
}

static int tfd_check_forced(struct tfd_state *st)
{
    static char msgbuf[TFD_MSG];
    struct tfd_forced fo = { .msg = msgbuf, .cap = sizeof msgbuf };
    int rc = compile_pat(&fo.re, REG_EXTENDED, "TOR_FULL=([[:space:]]|$)",
                         "", "", "");
    if (rc) return rc;
    char toolsdir[TFD_PATH], mkpath[TFD_PATH];
    if (tfd_path(toolsdir, sizeof toolsdir, "tools")
        || tfd_path(mkpath, sizeof mkpath, "Makefile")) {
        regfree(&fo.re);
        return 2;
    }
    rc = tfd_walk_all(toolsdir, tfd_forced_file, &fo);
    if (rc == 0) rc = tfd_forced_file(mkpath, &fo);
    regfree(&fo.re);
    if (rc) return rc;
    if (fo.nmatch == 0) return 0;
    rc = tfd_note(st,
        "something still forces TOR_FULL empty; that is how the portable "
        "release shipped a stub");
    if (rc) return rc;
    if (fputs(fo.msg, tfd_err ? tfd_err : stderr) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int tfd_check_root(struct tfd_state *st)
{
    char mkpath[TFD_PATH];
    if (tfd_path(mkpath, sizeof mkpath, "Makefile")) return 2;
    size_t n = 0;
    int rc = tfd_read(mkpath, g_tfd_raw, sizeof g_tfd_raw, &n);
    if (rc == 2) return rc;
    if (rc == TFD_MISSING)
        return tfd_note_path(st, "no Makefile under %s", tfd_root());
    tfd_join(g_tfd_raw, g_tfd_joined);

    struct tfd_re r;
    rc = tfd_re_comp(&r);
    if (rc) return rc;
    rc = tfd_check_makefile(st, &r);
    tfd_re_drop(&r);
    if (rc) return rc;

    rc = tfd_check_carriers(st);
    if (rc) return rc;
    rc = tfd_check_users(st);
    if (rc) return rc;
    return tfd_check_forced(st);
}

static int tfd_eval(void)
{
    struct tfd_state st = { .fail = 0 };
    int rc = tfd_check_root(&st);
    if (rc) return rc;
    if (st.fail) return 1;
    if (fprintf(tfd_out ? tfd_out : stdout,
                "%s: PASS \xe2\x80\x94 the default build establishes real "
                "Tor, the stub needs ZCL_TOR=stub, and %d packaging "
                "step(s) carry the exact refusal\n",
                k_tfd_gate, TFD_N_FILES + TFD_N_USERS) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

int check_tor_full_default_run(int argc, char **argv)
{
    (void)argv;
    tfd_clear_ov();
    if (argc > 0) {
        fprintf(tfd_err ? tfd_err : stderr,
                "usage: check_tor_full_default.sh [--selftest]\n");
        return 2;
    }
    return tfd_eval();
}

/* ── selftest: plants one defect at a time in a throwaway fixture ─────── */

static char *tfd_mkdtemp(char *tmpl, size_t cap)
{
    const char *td = env_or("TMPDIR", "/tmp");
    if (ovf(snprintf(tmpl, cap, "%s/z23-lint-tfd.XXXXXX", td), cap)) return NULL;
    char *tmp = mkdtemp(tmpl);
    return tmp ? tmp : (die("z23-lint: mkdir failed: %s\n", td), NULL);
}

static int tfd_copy_named(const char *root, const char *rel)
{
    char src[TFD_PATH], dst[TFD_PATH];
    if (ovf(snprintf(src, sizeof src, "%s", rel), sizeof src)) return 1;
    if (ovf(snprintf(dst, sizeof dst, "%s/%s", root, rel), sizeof dst))
        return 1;
    size_t n = 0;
    if (tfd_read(src, g_tfd_raw, sizeof g_tfd_raw, &n) != 0) return 1;
    g_tfd_raw[n] = '\0';
    return csr_write(dst, g_tfd_raw) ? 1 : 0;
}

static int tfd_seed(const char *dir)
{
    if (rap_rm_rf(dir)) return 1;
    if (tfd_copy_named(dir, "Makefile")) return 1;
    if (tfd_copy_named(dir, "tools/ship.sh")) return 1;
    if (tfd_copy_named(dir, "tools/scripts/tor_stamp_lib.sh")) return 1;
    if (tfd_copy_named(dir, "tools/scripts/install_z23.sh")) return 1;
    if (tfd_copy_named(dir, "tools/scripts/build_c23_portable_release.sh"))
        return 1;
    return 0;
}

/* First occurrence of `from` (len flen) within the line [p, p+len). Linear
 * scan, not a library call, so a `from` containing an embedded NUL (never
 * true for this gate's fixtures, but kept honest) still works on the raw
 * bytes rather than stopping at the first NUL the way strstr would. */
static const char *tfd_edit_find(const char *p, size_t len, const char *from,
                                 size_t flen)
{
    if (flen == 0 || flen > len) return NULL;
    for (size_t i = 0; i + flen <= len; i++)
        if (memcmp(p + i, from, flen) == 0) return p + i;
    return NULL;
}

/* Apply one line's substitution (or copy it unchanged) into out/oi,
 * pulled out of tfd_edit's loop to keep that function under the
 * complexity cap. Returns 2 (fatal) on overflow, else 0. */
static int tfd_edit_line(const char *p, size_t len, const char *from,
                         size_t flen, const char *to, size_t tlen, char *out,
                         size_t *oi, size_t outcap, int *any)
{
    const char *hit = tfd_edit_find(p, len, from, flen);
    size_t seg_extra = hit ? (len - flen + tlen) : len;
    if (*oi + seg_extra + 2 >= outcap)
        return die("z23-lint: derived buffer overflow\n", "");
    if (!hit) {
        memcpy(out + *oi, p, len);
        *oi += len;
        return 0;
    }
    *any = 1;
    size_t pre = (size_t)(hit - p);
    memcpy(out + *oi, p, pre); *oi += pre;
    memcpy(out + *oi, to, tlen); *oi += tlen;
    memcpy(out + *oi, hit + flen, len - pre - flen); *oi += len - pre - flen;
    return 0;
}

/* First-occurrence-PER-LINE substring replace, like the original's one-shot
 * `sed -e "s/from/to/"` (no `g`): every line that contains `from` gets one
 * substitution, so a phrase repeated in both a comment and a code line (as
 * ZCL_C23_PORTABLE_RELEASE=1 is) is edited on both. */
static int tfd_edit(const char *root, const char *rel, const char *from,
                    const char *to)
{
    char path[TFD_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/%s", root, rel), sizeof path))
        return 1;
    size_t n = 0;
    if (tfd_read(path, g_tfd_raw, sizeof g_tfd_raw, &n) != 0) return 1;
    static char out[TFD_CAP];
    size_t oi = 0;
    size_t flen = strlen(from), tlen = strlen(to);
    const char *p = g_tfd_raw;
    int any = 0, rc = 0;
    while (*p != '\0') {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        rc = tfd_edit_line(p, len, from, flen, to, tlen, out, &oi, sizeof out, &any);
        if (rc) return rc;
        if (nl) out[oi++] = '\n';
        if (!nl) break;
        p = nl + 1;
    }
    out[oi] = '\0';
    if (!any) return 1;
    return csr_write(path, out) ? 1 : 0;
}

static int tfd_expect(const char *root, int want_accept, int *ok)
{
    struct tfd_state st = { .fail = 0 };
    tfd_root_ov = root;
    int rc = tfd_check_root(&st);
    tfd_clear_ov();
    if (rc == 2) { *ok = 0; return 1; }
    int accepted = st.fail == 0;
    *ok = accepted == (want_accept != 0);
    return 0;
}

static int tfd_st_case(const char *tmp, const char *sub, const char *rel,
                       const char *from, const char *to, int want_accept)
{
    char root[TFD_PATH];
    if (ovf(snprintf(root, sizeof root, "%s/%s", tmp, sub), sizeof root))
        return 1;
    if (tfd_seed(root)) return 1;
    if (rel && tfd_edit(root, rel, from, to)) return 1;
    int ok = 0;
    if (tfd_expect(root, want_accept, &ok)) return 1;
    return ok ? 0 : 1;
}

static int tfd_st_unreadable(const char *tmp)
{
    char root[TFD_PATH], mk[TFD_PATH];
    if (ovf(snprintf(root, sizeof root, "%s/unreadable", tmp), sizeof root))
        return 1;
    if (tfd_seed(root)) return 1;
    if (ovf(snprintf(mk, sizeof mk, "%s/Makefile", root), sizeof mk)) return 1;
    if (chmod(mk, 0) != 0) return 1;
    struct tfd_state st = { .fail = 0 };
    tfd_root_ov = root;
    int rc = tfd_check_root(&st);
    tfd_clear_ov();
    (void)chmod(mk, 0600);
    return rc == 2 ? 0 : 1;
}

int check_tor_full_default_selftest(void)
{
    char tmpl[TFD_PATH];
    char *tmp = tfd_mkdtemp(tmpl, sizeof tmpl);
    if (!tmp) return 2;
    int bad = 0;
    bad |= tfd_st_case(tmp, "good", NULL, NULL, NULL, 1);
    bad |= tfd_st_case(tmp, "sentence", "tools/scripts/install_z23.sh",
        "refusing to package a tor=stub binary",
        "refusing to install a stub binary", 0);
    bad |= tfd_st_case(tmp, "include", "Makefile",
        "-include $(TOR_BOOTSTRAP_MK)", "# removed", 0);
    bad |= tfd_st_case(tmp, "default", "Makefile",
        "ZCL_TOR ?= full", "ZCL_TOR ?= stub", 0);
    bad |= tfd_st_case(tmp, "forced", "tools/scripts/build_c23_portable_release.sh",
        "ZCL_C23_PORTABLE_RELEASE=1 ",
        "ZCL_C23_PORTABLE_RELEASE=1 TOR_FULL= ", 0);
    bad |= tfd_st_case(tmp, "install", "Makefile",
        "zcl_tor_require_full", "some_other_check", 0);
    {
        /* ship.sh loses reach to the refusal: both spellings drop. */
        char root[TFD_PATH];
        int ok = 0;
        bad |= ovf(snprintf(root, sizeof root, "%s/ship", tmp), sizeof root);
        bad |= tfd_seed(root);
        bad |= tfd_edit(root, "tools/ship.sh", "ZCL_TOR_STUB_REFUSAL",
                        "SOME_OTHER_MESSAGE");
        bad |= tfd_edit(root, "tools/ship.sh", "zcl_tor_require_full",
                        "some_other_check");
        bad |= tfd_expect(root, 0, &ok) || !ok;
    }
    bad |= tfd_st_unreadable(tmp);
    tfd_clear_ov();
    (void)rap_rm_rf(tmp);
    return st_ok(bad, "check_tor_full_default selftest: OK\n");
}
