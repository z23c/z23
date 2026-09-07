/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gate: check-hotswap-swappable-shape
 * Port of tools/lint/check_hotswap_swappable_shape.sh (now a shim). THE HARD
 * LINE for the REAL (activatable) Tier-1 hot-swap module ABI:
 * engine/composition/hotswap_swappable.def carries one row per swappable
 * source TU plus the space-separated set of command leaves that TU's module
 * may re-point in a single all-or-nothing batch. This gate enforces both
 * halves of the line: every authority-owning source_tu must be a shape-LEAF
 * translation unit (controller/view/condition, or a stateless island member
 * under the narrower island roots) and never a reducer stage, consensus
 * validation, storage engine, supervisor, or state root; every leaf it
 * claims must be declared ZCL_COMMAND_READY_READ (READY, read-only) in
 * engine/composition/commands (.def) and owned by exactly one file.
 *
 * The three fixed inputs (manifest, command-def directory, island manifest)
 * are scanned with a single shared column-1-anchored, string-literal-aware,
 * paren-depth macro-invocation parser (hsw_scan_macro / hsw_find_close /
 * hsw_extract_args below), reused for all three macro tokens the shell
 * original scanned identically (HOTSWAP_SWAPPABLE, ZCL_COMMAND_READY_READ,
 * HOTSWAP_ISLAND) — a macro invocation is only recognized at column 1, so a
 * .def header comment that spells the macro signature out is never mistaken
 * for a row. Manifest and command-catalog paths are overridable via
 * ZCL_HOTSWAP_SWAPPABLE_MANIFEST / ZCL_HOTSWAP_COMMAND_DEF_DIR /
 * ZCL_HOTSWAP_ISLAND_MANIFEST (three EXISTING registered flags whose
 * first-use pointers already name tools/dev/hotswap-candidates.sh; this
 * gate is not their first consumer and does not move them).
 *
 * Two-phase control flow, ported faithfully: phase 1 (the swappable-row
 * walk) short-circuits everything — any phase-1 violation prints and exits
 * 1 WITHOUT ever parsing the island manifest at all. Phase 2 (island
 * membership) only runs when phase 1 is clean.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <regex.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

enum {
    HSW_PATH = 320,
    HSW_ARG = 2048,
    HSW_LEAF = 160,
    HSW_MAX_ROWS = 2048,
    HSW_MAX_READY = 4096,
    HSW_MAX_KV = 4096,
    HSW_FILE_MAX = 1048576,
    HSW_VIOL_BUF = 32768,
};

struct hsw_row { char a[HSW_PATH]; char b[HSW_ARG]; };
struct hsw_ready { char name[HSW_LEAF]; };
struct hsw_kv { char key[HSW_PATH]; char val[HSW_PATH]; };
struct hsw_kvset { struct hsw_kv e[HSW_MAX_KV]; int n; };
struct hsw_viol { char buf[HSW_VIOL_BUF]; size_t len; int n; };

/* ── whole-file slurp into a caller-owned fixed buffer ─────────────────── */
static int hsw_slurp(const char *path, char *buf, size_t cap, size_t *outlen)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    size_t n = fread(buf, 1, cap - 1, f);
    int err = ferror(f);
    int eof = feof(f);
    if (fclose(f) != 0)
        return die("z23-lint: fclose failed: %s\n", path);
    if (err)
        return die("z23-lint: read failed: %s\n", path);
    if (!eof)
        return die("z23-lint: file too large: %s\n", path);
    buf[n] = '\0';
    *outlen = n;
    return 0;
}

/* ── shared column-1 paren-depth/string-aware macro scanner ────────────── */
static size_t hsw_find_close(const char *buf, size_t n, size_t spec_start,
                             size_t *resume)
{
    size_t j = spec_start;
    int depth = 1, in_str = 0, esc = 0;
    size_t close_idx = n;
    while (j < n && depth > 0) {
        char c = buf[j];
        if (in_str) {
            if (esc)
                esc = 0;
            else if (c == '\\')
                esc = 1;
            else if (c == '"')
                in_str = 0;
        } else if (c == '"') {
            in_str = 1;
        } else if (c == '(') {
            depth++;
        } else if (c == ')') {
            depth--;
            if (depth == 0)
                close_idx = j;
        }
        j++;
    }
    *resume = j;
    return close_idx;
}

/* Extracts the first `argn` (<=2) double-quoted string literals from a raw
 * macro-argument span. NOT backslash-escape-aware (unlike the depth walk
 * above) -- that asymmetry is in the shell original (awk's plain
 * match(rest, /"[^"]*"/)) and is ported verbatim, not "fixed". */
static int hsw_extract_args(const char *spec, size_t speclen, int argn,
                            struct hsw_row *row)
{
    row->a[0] = '\0';
    row->b[0] = '\0';
    char *slot[2] = { row->a, row->b };
    size_t cap[2] = { sizeof row->a, sizeof row->b };
    size_t pos = 0;
    for (int k = 0; k < argn && k < 2; k++) {
        size_t q1 = pos;
        while (q1 < speclen && spec[q1] != '"')
            q1++;
        if (q1 >= speclen)
            continue;
        size_t q2 = q1 + 1;
        while (q2 < speclen && spec[q2] != '"')
            q2++;
        if (q2 >= speclen)
            continue;
        size_t len = q2 - (q1 + 1);
        if (len >= cap[k])
            return die("z23-lint: hotswap-swappable-shape arg too long\n", "");
        memcpy(slot[k], spec + q1 + 1, len);
        slot[k][len] = '\0';
        pos = q2 + 1;
    }
    return 0;
}

static int hsw_scan_macro(const char *buf, size_t n, const char *tok, int argn,
                          struct hsw_row *rows, int max, int *nrows)
{
    size_t toklen = strlen(tok);
    size_t i = 0;
    *nrows = 0;
    while (i < n) {
        int at_col1 = (i == 0 || buf[i - 1] == '\n');
        if (!at_col1 || i + toklen > n || memcmp(buf + i, tok, toklen) != 0) {
            i++;
            continue;
        }
        size_t spec_start = i + toklen;
        size_t resume = 0;
        size_t close_idx = hsw_find_close(buf, n, spec_start, &resume);
        if (*nrows >= max)
            return die("z23-lint: hotswap-swappable-shape row overflow\n", "");
        if (hsw_extract_args(buf + spec_start, close_idx - spec_start, argn,
                             &rows[*nrows]))
            return 2;
        (*nrows)++;
        i = resume;
    }
    return 0;
}

/* ── small string helpers ───────────────────────────────────────────────── */
static int hsw_next_word(const char **p, char *out, size_t cap)
{
    const char *s = *p;
    while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r')
        s++;
    if (!*s) {
        *p = s;
        return 0;
    }
    const char *start = s;
    while (*s && *s != ' ' && *s != '\t' && *s != '\n' && *s != '\r')
        s++;
    size_t len = (size_t)(s - start);
    if (len >= cap)
        len = cap - 1;
    memcpy(out, start, len);
    out[len] = '\0';
    *p = s;
    return 1;
}

static int hsw_is_blank(const char *s)
{
    for (; *s; s++)
        if (!isspace((unsigned char)*s))
            return 0;
    return 1;
}

static int hsw_ends_with(const char *s, const char *suf)
{
    size_t sl = strlen(s), fl = strlen(suf);
    return sl >= fl && strcmp(s + sl - fl, suf) == 0;
}

static int hsw_leaf_name_valid(const char *h)
{
    if (!h[0])
        return 0;
    for (const char *p = h; *p; p++)
        if (!(isalnum((unsigned char)*p) || *p == '_' || *p == '.'))
            return 0;
    return 1;
}

/* ── violation accumulator (used by both phases; each phase gets its own,
 * matching the observable behavior of the shell's shared `violations` var
 * given phase 2 is only ever reached with an EMPTY accumulator, since a
 * non-empty phase 1 always exits before phase 2 runs) ─────────────────── */
static int hsw_note(struct hsw_viol *v, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int k = vsnprintf(v->buf + v->len, sizeof v->buf - v->len, fmt, ap);
    va_end(ap);
    if (ovf(k, sizeof v->buf - v->len))
        return 2;
    v->len += (size_t)k;
    v->n++;
    return 0;
}

/* ── ready (ZCL_COMMAND_READY_READ) set ─────────────────────────────────── */
static int hsw_ready_has(const struct hsw_ready *ready, int n, const char *name)
{
    for (int i = 0; i < n; i++)
        if (strcmp(ready[i].name, name) == 0)
            return 1;
    return 0;
}

static int hsw_ready_add(struct hsw_ready *ready, int *n, const char *name)
{
    if (hsw_ready_has(ready, *n, name))
        return 0;
    if (*n >= HSW_MAX_READY)
        return die("z23-lint: hotswap-swappable-shape ready-set overflow\n", "");
    if (ovf(snprintf(ready[*n].name, sizeof ready[*n].name, "%s", name),
            sizeof ready[*n].name))
        return 2;
    (*n)++;
    return 0;
}

static int hsw_has_suffix(const char *name, const char *suf)
{
    size_t nl = strlen(name), sl = strlen(suf);
    return nl >= sl && strcmp(name + nl - sl, suf) == 0;
}

static int hsw_scan_def_file(const char *path, struct hsw_ready *ready,
                             int *nready, int *def_count, int *ready_count)
{
    (*def_count)++;
    static char buf[HSW_FILE_MAX];
    size_t n = 0;
    int rc = hsw_slurp(path, buf, sizeof buf, &n);
    if (rc)
        return rc;
    static struct hsw_row rows[HSW_MAX_ROWS];
    int nrows = 0;
    rc = hsw_scan_macro(buf, n, "ZCL_COMMAND_READY_READ(", 1, rows, HSW_MAX_ROWS,
                        &nrows);
    if (rc)
        return rc;
    for (int i = 0; i < nrows && rc == 0; i++) {
        (*ready_count)++;
        rc = hsw_ready_add(ready, nready, rows[i].a);
    }
    return rc;
}

static int hsw_load_ready(const char *defdir, struct hsw_ready *ready,
                          int *nready, int *def_count, int *ready_count)
{
    *nready = 0;
    *def_count = 0;
    *ready_count = 0;
    DIR *d = opendir(defdir);
    if (!d)
        return errno == ENOENT ? 0 : die("z23-lint: cannot scan %s\n", defdir);
    struct dirent *de;
    int rc = 0;
    while (rc == 0 && (de = readdir(d)) != NULL) {
        if (!hsw_has_suffix(de->d_name, ".def"))
            continue;
        char path[HSW_PATH];
        if (ovf(snprintf(path, sizeof path, "%s/%s", defdir, de->d_name),
                sizeof path)) {
            rc = 2;
            break;
        }
        rc = hsw_scan_def_file(path, ready, nready, def_count, ready_count);
    }
    closedir(d);
    return rc;
}

static int hsw_ready_floor(int def_count, int ready_count, const char *defdir)
{
    if (def_count != 0 && ready_count != 0)
        return 0;
    fprintf(stderr,
           "check_hotswap_swappable_shape: FATAL — no ZCL_COMMAND_READY_READ "
           "leaves enumerated from %s/*.def.\n", defdir);
    fputs("  The command-catalog scan is hollow; refusing to certify any leaf as\n",
         stderr);
    fputs("  READY read-only off an empty enumeration.\n", stderr);
    return 2;
}

/* ── key/value set (seen_sources / leaf_owner / island_member_owner) ───── */
static const char *hsw_kv_find(const struct hsw_kvset *s, const char *key)
{
    for (int i = 0; i < s->n; i++)
        if (strcmp(s->e[i].key, key) == 0)
            return s->e[i].val;
    return NULL;
}

static int hsw_kv_set(struct hsw_kvset *s, const char *key, const char *val)
{
    for (int i = 0; i < s->n; i++)
        if (strcmp(s->e[i].key, key) == 0)
            return ovf(snprintf(s->e[i].val, sizeof s->e[i].val, "%s", val),
                       sizeof s->e[i].val);
    if (s->n >= HSW_MAX_KV)
        return die("z23-lint: hotswap-swappable-shape kv overflow\n", "");
    if (ovf(snprintf(s->e[s->n].key, sizeof s->e[s->n].key, "%s", key),
            sizeof s->e[s->n].key))
        return 2;
    if (ovf(snprintf(s->e[s->n].val, sizeof s->e[s->n].val, "%s", val),
            sizeof s->e[s->n].val))
        return 2;
    s->n++;
    return 0;
}

/* ── manifest / island loaders (slurp + macro-scan + floor) ────────────── */
static int hsw_load_rows(const char *path, const char *tok, const char *floor_hint,
                         struct hsw_row *rows, int *nrows)
{
    static char buf[HSW_FILE_MAX];
    size_t n = 0;
    int rc = hsw_slurp(path, buf, sizeof buf, &n);
    if (rc)
        return rc;
    rc = hsw_scan_macro(buf, n, tok, 2, rows, HSW_MAX_ROWS, nrows);
    if (rc)
        return rc;
    char hint[512];
    if (ovf(snprintf(hint, sizeof hint, "%s %s", floor_hint, path), sizeof hint))
        return 2;
    return gate_require_scanned(*nrows, 1, "check_hotswap_swappable_shape", hint);
}

static int hsw_leaf_floor(const struct hsw_row *rows, int nrows, const char *manifest,
                          int *leaf_total)
{
    *leaf_total = 0;
    for (int i = 0; i < nrows; i++) {
        const char *p = rows[i].b;
        char w[HSW_LEAF];
        while (hsw_next_word(&p, w, sizeof w))
            (*leaf_total)++;
    }
    char hint[512];
    if (ovf(snprintf(hint, sizeof hint,
                     "no swappable leaves parsed out of %d row(s) in %s", nrows,
                     manifest), sizeof hint))
        return 2;
    return gate_require_scanned(*leaf_total, 1, "check_hotswap_swappable_shape", hint);
}

/* ── phase 1: swappable-row walk ────────────────────────────────────────── */
static int hsw_phase1_leaves(const struct hsw_row *row, const struct hsw_ready *ready,
                             int nready, const char *defdir, struct hsw_kvset *owner,
                             struct hsw_viol *v)
{
    const char *p = row->b;
    char h[HSW_LEAF];
    int rc = 0;
    while (rc == 0 && hsw_next_word(&p, h, sizeof h)) {
        if (!hsw_leaf_name_valid(h)) {
            rc = hsw_note(v, "  %s -> %s (invalid leaf name)\n", row->a, h);
            continue;
        }
        const char *prev = hsw_kv_find(owner, h);
        if (prev) {
            rc = hsw_note(v,
                         "  %s (claimed by both %s and %s; a leaf belongs to "
                         "exactly one file)\n", h, prev, row->a);
            continue;
        }
        rc = hsw_kv_set(owner, h, row->a);
        if (rc)
            break;
        if (!hsw_ready_has(ready, nready, h))
            rc = hsw_note(v,
                         "  %s -> %s (not declared with ZCL_COMMAND_READY_READ "
                         "in %s/*.def — swappable leaves must be READY and "
                         "read-only)\n", row->a, h, defdir);
    }
    return rc;
}

static int hsw_phase1_row(const struct hsw_row *row, const regex_t *forbidden,
                          const regex_t *allowed, const struct hsw_ready *ready,
                          int nready, const char *defdir, struct hsw_kvset *seen,
                          struct hsw_kvset *owner, struct hsw_viol *v)
{
    const char *s = row->a;
    if (s[0] == '\0')
        return hsw_note(v, "  (row with no source_tu string literal)\n");
    int rc = 0;
    if (hsw_kv_find(seen, s))
        rc = hsw_note(v, "  %s (duplicate source row; one row per file)\n", s);
    if (rc == 0)
        rc = hsw_kv_set(seen, s, "1");
    if (rc)
        return rc;
    if (regexec(forbidden, s, 0, NULL, 0) == 0)
        return hsw_note(v, "  %s (under a forbidden consensus/state/supervisor root)\n", s);
    if (regexec(allowed, s, 0, NULL, 0) != 0)
        return hsw_note(v, "  %s (not under a physical controller, view, or condition room)\n", s);
    if (!hsw_ends_with(s, ".c"))
        return hsw_note(v, "  %s (not a .c translation unit)\n", s);
    struct stat st;
    if (stat(s, &st) != 0 || !S_ISREG(st.st_mode))
        return hsw_note(v, "  %s (manifest references a nonexistent file)\n", s);
    if (hsw_is_blank(row->b))
        return hsw_note(v, "  %s (row declares no swappable leaves)\n", s);
    return hsw_phase1_leaves(row, ready, nready, defdir, owner, v);
}

static int hsw_fail1(const char *defdir, const struct hsw_viol *v)
{
    if (fwrite(v->buf, 1, v->len, stdout) != v->len)
        return die("z23-lint: write failed\n", "");
    if (puts("FAIL: the hot-swap swappable allowlist violates the hard line.") < 0
        || puts("  Every source_tu must be a controller/view/condition LEAF, NEVER a") < 0
        || puts("  reducer stage, consensus validation, storage engine, or supervisor.") < 0
        || puts("  Every leaf must be declared ZCL_COMMAND_READY_READ (READY +") < 0
        || printf("  read-only) in %s/*.def and be owned by exactly one file.\n", defdir) < 0
        || puts("  This is what makes activation safe.") < 0)
        return die("z23-lint: write failed\n", "");
    return 1;
}

static int hsw_run_phase1(const struct hsw_row *rows, int nrows, const regex_t *forbidden,
                          const regex_t *allowed, const struct hsw_ready *ready,
                          int nready, const char *defdir, struct hsw_kvset *seen,
                          struct hsw_kvset *owner)
{
    struct hsw_viol v = {0};
    int rc = 0;
    for (int i = 0; i < nrows && rc == 0; i++)
        rc = hsw_phase1_row(&rows[i], forbidden, allowed, ready, nready, defdir,
                            seen, owner, &v);
    if (rc)
        return rc;
    return v.n > 0 ? hsw_fail1(defdir, &v) : 0;
}

/* ── phase 2: island membership walk ────────────────────────────────────── */
static int hsw_phase2_member(const char *owner, const char *member,
                             const regex_t *island_allowed, const regex_t *forbidden,
                             struct hsw_kvset *iowner, struct hsw_viol *v)
{
    int rc;
    struct stat st;
    if (regexec(island_allowed, member, 0, NULL, 0) != 0)
        rc = hsw_note(v, "  %s -> %s (outside stateless island roots)\n", owner, member);
    else if (regexec(forbidden, member, 0, NULL, 0) == 0)
        rc = hsw_note(v, "  %s -> %s (under forbidden state/consensus root)\n", owner, member);
    else if (stat(member, &st) != 0 || !S_ISREG(st.st_mode))
        rc = hsw_note(v, "  %s -> %s (nonexistent island member)\n", owner, member);
    else if (hsw_kv_find(iowner, member))
        rc = hsw_note(v, "  %s (claimed by two island owners)\n", member);
    else
        rc = 0;
    if (rc)
        return rc;
    return hsw_kv_set(iowner, member, owner);
}

static int hsw_phase2_row(const struct hsw_row *irow, const regex_t *island_allowed,
                          const regex_t *forbidden, const struct hsw_kvset *seen,
                          struct hsw_kvset *iowner, struct hsw_viol *v)
{
    const char *owner = irow->a;
    if (!hsw_kv_find(seen, owner))
        return hsw_note(v, "  %s (island owner is not a swappable module owner)\n", owner);
    const char *p = irow->b;
    char member[HSW_PATH];
    int rc = 0;
    while (rc == 0 && hsw_next_word(&p, member, sizeof member))
        rc = hsw_phase2_member(owner, member, island_allowed, forbidden, iowner, v);
    return rc;
}

static int hsw_fail2(const struct hsw_viol *v)
{
    if (fwrite(v->buf, 1, v->len, stdout) != v->len)
        return die("z23-lint: write failed\n", "");
    return puts("FAIL: reloadable-island membership violates the hard line.") < 0
               ? die("z23-lint: write failed\n", "") : 1;
}

static int hsw_run_phase2(const struct hsw_row *irows, int nirows,
                          const regex_t *island_allowed, const regex_t *forbidden,
                          const struct hsw_kvset *seen, struct hsw_kvset *iowner)
{
    struct hsw_viol v = {0};
    int rc = 0;
    for (int i = 0; i < nirows && rc == 0; i++)
        rc = hsw_phase2_row(&irows[i], island_allowed, forbidden, seen, iowner, &v);
    if (rc)
        return rc;
    return v.n > 0 ? hsw_fail2(&v) : 0;
}

/* ── orchestration ───────────────────────────────────────────────────────── */
static int hsw_check_readable(const char *manifest, const char *islands)
{
    if (access(manifest, R_OK) != 0) {
        fprintf(stderr,
               "check_hotswap_swappable_shape: FATAL — manifest '%s' "
               "missing/unreadable.\n", manifest);
        fputs("  Refusing to report 'clean' with no manifest to scan.\n", stderr);
        return 2;
    }
    if (access(islands, R_OK) != 0) {
        fprintf(stderr,
               "check_hotswap_swappable_shape: FATAL — island manifest '%s' "
               "missing/unreadable.\n", islands);
        return 2;
    }
    return 0;
}

static int hsw_compile_regexes(regex_t *forbidden, regex_t *allowed,
                               regex_t *island_allowed)
{
    static const char *const pats[] = {
        "^(engine|cognition|contexts/[^/]+)/(controllers|views|conditions)/",
        "^(engine|cognition|contexts/[^/]+)/(controllers|views|conditions|"
            "services)/.+\\.c$|^contexts/commons/modules/metaverse/src/.+\\.c$|"
            "^platform/modules/encoding/src/.+\\.c$|"
            "^contexts/commons/modules/vcs/src/package_policy\\.c$",
        "^(core/(consensus|modules/(validation|net|coins|chain|mining))|"
            "engine/(reducer|jobs|supervisors|modules/(storage|kernel|"
            "supervisor)))/",
    };
    int err = reg_fail(allowed, regcomp(allowed, pats[0], REG_EXTENDED));
    if (err)
        return err;
    err = reg_fail(island_allowed, regcomp(island_allowed, pats[1], REG_EXTENDED));
    if (err) {
        regfree(allowed);
        return err;
    }
    err = reg_fail(forbidden, regcomp(forbidden, pats[2], REG_EXTENDED));
    if (err) {
        drop2(allowed, island_allowed);
        return err;
    }
    return 0;
}

static int hsw_print_clean(int nrows, int leaf_total, int nmembers, int ready_count,
                           int def_count)
{
    if (printf("  OK: %d swappable file(s), %d READY read-only leaf/leaves, "
              "%d stateless island member(s)\n", nrows, leaf_total, nmembers) < 0)
        return die("z23-lint: write failed\n", "");
    if (printf("      (cross-checked against %d ZCL_COMMAND_READY_READ leaves "
              "in %d catalog file(s))\n", ready_count, def_count) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int hsw_execute(const char *manifest, const char *defdir, const char *islands)
{
    int rc = hsw_check_readable(manifest, islands);
    if (rc)
        return rc;

    static struct hsw_row rows[HSW_MAX_ROWS];
    int nrows = 0;
    rc = hsw_load_rows(manifest, "HOTSWAP_SWAPPABLE(",
                       "no HOTSWAP_SWAPPABLE(\"source\",\"leaves\") rows parsed from",
                       rows, &nrows);
    if (rc)
        return rc;

    static struct hsw_ready ready[HSW_MAX_READY];
    int nready = 0, def_count = 0, ready_count = 0;
    rc = hsw_load_ready(defdir, ready, &nready, &def_count, &ready_count);
    if (rc)
        return rc;
    rc = hsw_ready_floor(def_count, ready_count, defdir);
    if (rc)
        return rc;

    int leaf_total = 0;
    rc = hsw_leaf_floor(rows, nrows, manifest, &leaf_total);
    if (rc)
        return rc;

    regex_t forbidden, allowed, island_allowed;
    rc = hsw_compile_regexes(&forbidden, &allowed, &island_allowed);
    if (rc)
        return rc;

    static struct hsw_kvset seen, owner, iowner;
    memset(&seen, 0, sizeof seen);
    memset(&owner, 0, sizeof owner);
    memset(&iowner, 0, sizeof iowner);

    rc = hsw_run_phase1(rows, nrows, &forbidden, &allowed, ready, nready, defdir,
                        &seen, &owner);
    if (rc) {
        drop3(&forbidden, &allowed, &island_allowed);
        return rc;
    }

    static struct hsw_row irows[HSW_MAX_ROWS];
    int nirows = 0;
    rc = hsw_load_rows(islands, "HOTSWAP_ISLAND(",
                       "no HOTSWAP_ISLAND owner/member rows parsed from",
                       irows, &nirows);
    if (rc) {
        drop3(&forbidden, &allowed, &island_allowed);
        return rc;
    }

    rc = hsw_run_phase2(irows, nirows, &island_allowed, &forbidden, &seen, &iowner);
    drop3(&forbidden, &allowed, &island_allowed);
    if (rc)
        return rc;

    return hsw_print_clean(nrows, leaf_total, iowner.n, ready_count, def_count);
}

int check_hotswap_swappable_shape_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    if (puts("══ LINT: hot-swap swappable allowlist (shape leaf + READY read-only) ══") < 0)
        return die("z23-lint: write failed\n", "");
    const char *manifest = env_or("ZCL_HOTSWAP_SWAPPABLE_MANIFEST",
                                  "engine/composition/hotswap_swappable.def");
    const char *defdir = env_or("ZCL_HOTSWAP_COMMAND_DEF_DIR",
                                "engine/composition/commands");
    const char *islands = env_or("ZCL_HOTSWAP_ISLAND_MANIFEST",
                                 "engine/composition/hotswap_islands.def");
    return hsw_execute(manifest, defdir, islands);
}

/* ── selftest ────────────────────────────────────────────────────────────── */
static int hsw_write_fixture(const char *dir, const char *name, const char *text)
{
    char path[HSW_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/%s", dir, name), sizeof path))
        return 2;
    return csr_write(path, text);
}

static int hsw_st_violating(const char *work)
{
    char manifest[HSW_PATH], defdir[HSW_PATH], islands[HSW_PATH];
    if (ovf(snprintf(manifest, sizeof manifest, "%s/manifest.def", work), sizeof manifest)
        || ovf(snprintf(defdir, sizeof defdir, "%s/commands", work), sizeof defdir)
        || ovf(snprintf(islands, sizeof islands, "%s/islands.def", work), sizeof islands))
        return 2;
    if (csr_mkdirs(defdir))
        return 2;
    int rc = hsw_write_fixture(work, "manifest.def",
        "HOTSWAP_SWAPPABLE(\"core/consensus/bad.c\", \"some_leaf\")\n");
    if (rc == 0)
        rc = hsw_write_fixture(defdir, "a.def", "ZCL_COMMAND_READY_READ(\"some_leaf\")\n");
    if (rc == 0)
        rc = hsw_write_fixture(work, "islands.def", "# empty, unreached\n");
    if (rc)
        return rc;
    int st = hsw_execute(manifest, defdir, islands);
    if (st != 1) {
        fprintf(stderr,
               "check-hotswap-swappable-shape selftest: violating fixture "
               "returned %d, want 1\n", st);
        return 1;
    }
    return 0;
}

/* The "not a manifest-declared-but-missing file" rule is a REAL stat()
 * against the current working tree, so a clean fixture needs a real,
 * already-tracked shape-leaf .c file to name -- this one is an ordinary
 * controller TU, chosen only because it exists; nothing in this selftest
 * creates or touches it. */
static const char k_hsw_real_leaf_tu[] = "engine/controllers/src/identity_controller.c";

static int hsw_st_clean(const char *work)
{
    char manifest[HSW_PATH], defdir[HSW_PATH], islands[HSW_PATH];
    if (ovf(snprintf(manifest, sizeof manifest, "%s/manifest2.def", work), sizeof manifest)
        || ovf(snprintf(defdir, sizeof defdir, "%s/commands2", work), sizeof defdir)
        || ovf(snprintf(islands, sizeof islands, "%s/islands2.def", work), sizeof islands))
        return 2;
    if (csr_mkdirs(defdir))
        return 2;
    char row[HSW_ARG];
    if (ovf(snprintf(row, sizeof row,
                     "HOTSWAP_SWAPPABLE(\"%s\", \"probe_leaf\")\n",
                     k_hsw_real_leaf_tu), sizeof row))
        return 2;
    char irow[HSW_ARG];
    if (ovf(snprintf(irow, sizeof irow, "HOTSWAP_ISLAND(\"%s\", \"\")\n",
                     k_hsw_real_leaf_tu), sizeof irow))
        return 2;
    int rc = hsw_write_fixture(work, "manifest2.def", row);
    if (rc == 0)
        rc = hsw_write_fixture(defdir, "b.def", "ZCL_COMMAND_READY_READ(\"probe_leaf\")\n");
    if (rc == 0)
        rc = hsw_write_fixture(work, "islands2.def", irow);
    if (rc)
        return rc;
    int st = hsw_execute(manifest, defdir, islands);
    if (st != 0) {
        fprintf(stderr,
               "check-hotswap-swappable-shape selftest: clean fixture "
               "returned %d, want 0\n", st);
        return 1;
    }
    return 0;
}

int check_hotswap_swappable_shape_selftest(void)
{
    const char *td = env_or("TMPDIR", "test-tmp");
    (void)csr_mkdirs("test-tmp");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/hotswap-swappable-shape-selftest.XXXXXX",
                     td), sizeof tmpl))
        return 2;
    char *work = mkdtemp(tmpl);
    if (!work)
        return die("z23-lint: mkdir failed: %s\n", td);
    int bad = hsw_st_violating(work) | hsw_st_clean(work);
    int cl = rap_rm_rf(work);
    if (bad)
        return 1;
    if (cl)
        return cl;
    return st_ok(0, "  OK: check-hotswap-swappable-shape self-test (trips on a "
                    "forbidden-root row, silent on a clean manifest/island pair)\n");
}
