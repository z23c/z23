/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: scan half of gate check_identity_parser_single — the recursive
 * *.sh walk under the scan root (with the source_identity_lib.sh /
 * check_identity_parser_single.sh exclusions) and the per-file counter that
 * ports the awk pass of the original shell script: Class A1 (a local
 * json_first_string_field definition), Class A2 (a short function whose
 * body performs a 64-lowercase-hex validity check, name-independent), and
 * Class B (an inline grep/sed extraction of the source_id_sha256 JSON
 * key), each exempted by a zcl-identity-parser-allow marker within the
 * previous 8 lines. See gate_identity_parser_single.c for the ratchet.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "lintc.h"
#include "gate_identity_parser_single_priv.h"

const char k_ips_gate[] = "check_identity_parser_single";

/* Per-file scanner state: the variables the awk pass kept per FILENAME. */
struct ips_fs {
    long count;
    long markers;
    long last_allow;   /* line of the most recent marker, -1000 initially */
    long fn_start;     /* header line of the function being parsed */
    long fn_allow;     /* marker state captured at the header */
    long lineno;
    int infunc, pending_open;
    int brace_depth, body_lines, body_has_sig, too_long;
};

/* ── small predicates ─────────────────────────────────────────────────── */

/* TRUE for the awk has_sig() shape: a negated-hex case-pattern, or a
 * 64-hex regex used in an actual boolean test (=~ or a quiet grep). */
static int ips_grep_quiet(const char *l)
{
    for (const char *p = strstr(l, "grep"); p; p = strstr(p + 1, "grep")) {
        size_t i = 4;
        if (p[i] != ' ' && p[i] != '\t')
            continue;
        while (p[i] == ' ' || p[i] == '\t')
            i++;
        if (p[i] != '-')
            continue;
        i++;
        int q = 0;
        while (isalpha((unsigned char)p[i])) {
            if (p[i] == 'q')
                q = 1;
            i++;
        }
        if (q)
            return 1;
    }
    return 0;
}

static int ips_has_sig(const char *l)
{
    if (strstr(l, "[!0-9a-f]"))
        return 1;
    if (strstr(l, "[0-9a-f]{64}") &&
        (strstr(l, "=~") || ips_grep_quiet(l)))
        return 1;
    return 0;
}

/* Class A1: start-of-line (indent ignored) json_first_string_field(). */
static int ips_a1_def(const char *line)
{
    size_t i = 0;
    while (line[i] == ' ' || line[i] == '\t')
        i++;
    if (strncmp(line + i, "json_first_string_field", 23) != 0)
        return 0;
    i += 23;
    while (line[i] == ' ' || line[i] == '\t')
        i++;
    return line[i] == '(' && line[i + 1] == ')';
}

/* Class B: the literal JSON-key needles (built one piece at a time in the
 * awk original; here as plain C literals) plus a grep/sed invocation. */
static void ips_class_b(struct ips_fs *s, const char *line)
{
    static const char plain[] = "\"source_id_sha256\"[[:space:]]*:";
    static const char esc[] = "\\\"source_id_sha256\\\"[[:space:]]*:";
    if (!strstr(line, plain) && !strstr(line, esc))
        return;
    if (!strstr(line, "grep") && !strstr(line, "sed"))
        return;
    if (s->lineno - s->last_allow > IPS_MARKER_WINDOW)
        s->count++;
}

/* ── function-header / body machinery (Class A2) ──────────────────────── */

static int ips_ident(const char *t, size_t *len)
{
    size_t i = 0;
    if (!(isalpha((unsigned char)t[0]) || t[0] == '_'))
        return 0;
    i = 1;
    while (isalnum((unsigned char)t[i]) || t[i] == '_')
        i++;
    if (!(t[i] == '(' && t[i + 1] == ')'))
        return 0;
    *len = i + 2;
    return 1;
}

/* Length of the leading "name()" plus trailing ws plus '{' of t, or 0. */
static size_t ips_fn_open_len(const char *t)
{
    size_t hl = 0;
    if (!ips_ident(t, &hl))
        return 0;
    while (t[hl] == ' ' || t[hl] == '\t')
        hl++;
    if (t[hl] != '{')
        return 0;
    return hl + 1;
}

/* TRUE when t is exactly "name()" plus trailing whitespace. */
static int ips_fn_pending(const char *t)
{
    size_t hl = 0;
    if (!ips_ident(t, &hl))
        return 0;
    while (t[hl] == ' ' || t[hl] == '\t')
        hl++;
    return t[hl] == '\0';
}

/* Length of a trailing "} ws ;? ws" run, or 0 when absent. */
static size_t ips_tail_brace_len(const char *s)
{
    size_t n = strlen(s), j = n;
    while (j > 0 && (s[j - 1] == ' ' || s[j - 1] == '\t'))
        j--;
    if (j > 0 && s[j - 1] == ';') {
        j--;
        while (j > 0 && (s[j - 1] == ' ' || s[j - 1] == '\t'))
            j--;
    }
    if (j == 0 || s[j - 1] != '}')
        return 0;
    return n - (j - 1);
}

static void ips_open_body(struct ips_fs *s, const char *body)
{
    s->fn_start = s->lineno;
    s->fn_allow = s->last_allow;
    s->infunc = 1;
    s->pending_open = 0;
    s->brace_depth = 1;
    s->body_lines = 0;
    s->body_has_sig = 0;
    s->too_long = 0;
    if (ips_has_sig(body))
        s->body_has_sig = 1;
    if (strspn(body, " \t") < strlen(body))
        s->body_lines++;
}

static void ips_open_line(struct ips_fs *s, const char *body)
{
    s->fn_start = s->lineno;
    s->fn_allow = s->last_allow;
    size_t tail = ips_tail_brace_len(body);
    if (!tail) {
        ips_open_body(s, body);
        return;
    }
    char one[IPS_LINE];
    size_t n = strlen(body) - tail;
    memcpy(one, body, n);
    one[n] = '\0';
    if (ips_has_sig(one) && s->lineno - s->last_allow > IPS_MARKER_WINDOW)
        s->count++;
}

static int ips_count(const char *s, char c)
{
    int n = 0;
    for (; *s; s++)
        n += *s == c;
    return n;
}

static void ips_body_step(struct ips_fs *s, const char *line, const char *t)
{
    int nd = s->brace_depth + ips_count(line, '{') - ips_count(line, '}');
    if (nd <= 0) {
        if (!s->too_long && s->body_lines <= IPS_BODY_LIMIT &&
            s->body_has_sig && s->fn_start - s->fn_allow > IPS_MARKER_WINDOW)
            s->count++;
        s->infunc = 0;
        s->brace_depth = 0;
        return;
    }
    if (strspn(t, " \t") < strlen(t))
        s->body_lines++;
    if (ips_has_sig(line))
        s->body_has_sig = 1;
    if (s->body_lines > IPS_BODY_LIMIT)
        s->too_long = 1;
    s->brace_depth = nd;
}

static void ips_func_machine(struct ips_fs *s, const char *line, const char *t)
{
    if (!s->infunc && !s->pending_open) {
        size_t hl = ips_fn_open_len(t);
        if (hl)
            ips_open_line(s, t + hl);
        else if (ips_fn_pending(t))
            s->pending_open = 1;
    } else if (s->pending_open) {
        if (strcmp(t, "{") == 0)
            ips_open_body(s, "");
        else
            s->pending_open = 0;
    } else if (s->infunc) {
        ips_body_step(s, line, t);
    }
}

static void ips_trim(char *dst, const char *src)
{
    size_t n = strlen(src), a = 0;
    while (a < n && (src[a] == ' ' || src[a] == '\t'))
        a++;
    while (n > a && (src[n - 1] == ' ' || src[n - 1] == '\t'))
        n--;
    memcpy(dst, src + a, n - a);
    dst[n - a] = '\0';
}

static void ips_feed(struct ips_fs *s, char *line)
{
    char t[IPS_LINE];
    s->lineno++;
    if (strstr(line, "zcl-identity-parser-allow")) {
        s->last_allow = s->lineno;
        s->markers++;
    }
    if (ips_a1_def(line))
        s->count++;
    ips_class_b(s, line);
    ips_trim(t, line);
    ips_func_machine(s, line, t);
}

/* ── file scanning and directory walk ─────────────────────────────────── */

static int ips_scan_file(const char *path, long *count, long *markers)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "%s: cannot read %s\n", k_ips_gate, path);
        return 2;
    }
    char line[IPS_LINE];
    struct ips_fs s;
    memset(&s, 0, sizeof s);
    s.last_allow = -1000;
    s.fn_allow = -1000;
    int rc = 0;
    while (fgets(line, sizeof line, f)) {
        size_t n = strlen(line);
        if (n + 1 == sizeof line && line[n - 1] != '\n') {
            fprintf(stderr, "%s: line exceeds %d bytes in %s\n", k_ips_gate,
                    IPS_LINE, path);
            rc = 2;
            break;
        }
        if (n && line[n - 1] == '\n')
            line[n - 1] = '\0';
        ips_feed(&s, line);
    }
    if (!rc && ferror(f)) {
        fprintf(stderr, "%s: read error on %s\n", k_ips_gate, path);
        rc = 2;
    }
    fclose(f);
    *count = s.count;
    *markers = s.markers;
    return rc;
}

static int ips_excluded(const char *base)
{
    return strcmp(base, "source_identity_lib.sh") == 0 ||
           strcmp(base, "check_identity_parser_single.sh") == 0;
}

static int ips_walk_add(struct ips_scanres *r, const char *path)
{
    size_t n = strlen(path);
    if (n < 3 || strcmp(path + n - 3, ".sh") != 0)
        return 0;
    const char *slash = strrchr(path, '/');
    const char *base = slash ? slash + 1 : path;
    if (ips_excluded(base))
        return 0;
    if (r->nfiles >= IPS_MAXFILES) {
        fprintf(stderr, "%s: scan set exceeds %d files\n", k_ips_gate,
                IPS_MAXFILES);
        return 2;
    }
    if (ovf(snprintf(r->files[r->nfiles], IPS_PATH, "%s", path), IPS_PATH))
        return 2;
    r->nfiles++;
    return 0;
}

static int ips_cmp_str(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static int ips_walk(const char *dir, struct ips_scanres *r, int depth)
{
    if (depth > 32) {
        fprintf(stderr, "%s: directory nesting exceeds 32 under %s\n",
                k_ips_gate, dir);
        return 2;
    }
    DIR *d = opendir(dir);
    if (!d) {
        fprintf(stderr, "%s: cannot scan directory %s\n", k_ips_gate, dir);
        return 2;
    }
    struct dirent *de;
    int rc = 0;
    while (rc == 0 && (de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        char sub[IPS_PATH];
        if (ovf(snprintf(sub, sizeof sub, "%s/%s", dir, de->d_name),
                sizeof sub)) {
            rc = 2;
            break;
        }
        struct stat st;
        if (lstat(sub, &st) != 0) {
            fprintf(stderr, "%s: cannot stat %s\n", k_ips_gate, sub);
            rc = 2;
            break;
        }
        if (S_ISDIR(st.st_mode))
            rc = ips_walk(sub, r, depth + 1);
        else if (S_ISREG(st.st_mode))
            rc = ips_walk_add(r, sub);
    }
    closedir(d);
    return rc;
}

static int ips_record(struct ips_scanres *r, const char *path, long debt,
                      long marks)
{
    if (debt > 0) {
        if (r->nrows >= IPS_MAXROWS) {
            fprintf(stderr, "%s: count rows exceed %d\n", k_ips_gate,
                    IPS_MAXROWS);
            return 2;
        }
        if (ovf(snprintf(r->rows[r->nrows].path, IPS_PATH, "%s", path),
                IPS_PATH))
            return 2;
        r->rows[r->nrows].debt = (int)debt;
        r->nrows++;
    }
    if (marks > 0) {
        if (r->nm >= IPS_MAXMFILES) {
            fprintf(stderr, "%s: marker files exceed %d\n", k_ips_gate,
                    IPS_MAXMFILES);
            return 2;
        }
        if (ovf(snprintf(r->mfiles[r->nm], IPS_PATH, "%s", path), IPS_PATH))
            return 2;
        r->mcount[r->nm] = (int)marks;
        r->nm++;
        r->marker_total += (int)marks;
    }
    return 0;
}

int ips_scan_all(const struct ips_cfg *cfg, struct ips_scanres *r)
{
    int rc = ips_walk(cfg->scan_root, r, 0);
    if (rc)
        return rc;
    qsort(r->files, r->nfiles, IPS_PATH, ips_cmp_str);
    for (size_t i = 0; i < r->nfiles && rc == 0; i++) {
        long debt = 0, marks = 0;
        rc = ips_scan_file(r->files[i], &debt, &marks);
        if (rc == 0)
            rc = ips_record(r, r->files[i], debt, marks);
    }
    return rc;
}
