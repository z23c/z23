/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate — the executor rule vocabulary is CLOSED and resolves in
 * both directions (HARD).
 *
 * engine/composition/rule_vocab.def is the only place a rule an executor may
 * be shown is named; everything the harness does with a rule (count trials,
 * score it, retire it) is keyed on that id, so an id naming nothing is a
 * score attached to no rule, and a rule with no id is unmeasured guidance.
 *
 * BOTH DIRECTIONS OR NEITHER. Checking only that rows resolve lets a new
 * persona arrive unscored; checking only that sources are covered lets a
 * row outlive the heading it claims to quote. A hardcoded list checked one
 * way is default-permit, which is the failure this project has already
 * paid for once.
 *
 * Sources: every heading in a .grok/rules markdown file -> "grok:<slug>";
 * every PERSONA row in engine/modules/engine/include/engine/personas.def
 * -> "persona:<territory>". The slug is the heading text lowercased, every
 * run of non-alphanumerics turned into one '-', trimmed at both ends —
 * that transform lives in exactly one C helper here (rv_slug()).
 *
 * Per repo law 10 it FAILS LOUD on an empty scan set: a .def that stopped
 * parsing must never read as "clean". There is no baseline — a row that
 * stopped resolving is not a debt, it is a false statement.
 *
 * Ported from tools/lint/check_rule_vocabulary.sh, now a 3-line exec shim
 * onto this binary. The Makefile recipe still runs this gate twice
 * (`--selftest` then a plain run), matching the shell's own dual-invocation
 * shape; main.c's `--selftest` argv dispatch routes the first half to
 * check_rule_vocabulary_selftest() below.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

enum {
    RV_ID_CAP = 256,
    RV_TEXT_CAP = 4096,
    RV_LINE_CAP = 8192,
    RV_PATH_CAP = 4096,
    RV_MAX_SRC = 4096,
    RV_FAULT_CAP = 262144,
    RV_TEXT_MIN = 30,
    RV_TEXT_MAX = 300,
};

struct rv_str_list { char s[RV_MAX_SRC][RV_ID_CAP]; int n; };

/* Bounded copy that never triggers -Wformat-truncation the way an snprintf
 * "%s" of an over-sized source array would at -O2: no printf-family call at
 * all, just an explicit length clamp. Silent truncation past `dcap` is the
 * same acceptable-degradation the rest of this gate already applies via
 * ovf() elsewhere. */
static void rv_copy_trunc(char *dst, size_t dcap, const char *src)
{
    size_t n = strlen(src);
    if (n + 1 > dcap) n = dcap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

/* "<a><sep><b>" join (sep==0 for the "<prefix><body>" ids grok:/persona:,
 * sep=='/' for a selftest fixture path — `b` is always a short literal
 * there). One shared shape instead of two near-identical helpers. */
static void rv_concat_trunc(char *dst, size_t dcap, const char *a, char sep, const char *b)
{
    size_t an = strlen(a), bn = strlen(b), sn = sep ? 1 : 0;
    if (an + sn + bn + 1 > dcap) an = dcap > bn + sn + 1 ? dcap - bn - sn - 1 : 0;
    memcpy(dst, a, an);
    size_t o = an;
    if (sep) dst[o++] = sep;
    memcpy(dst + o, b, bn);
    dst[o + bn] = '\0';
}

static int rv_list_has(const struct rv_str_list *l, const char *id)
{
    for (int i = 0; i < l->n; i++)
        if (strcmp(l->s[i], id) == 0) return 1;
    return 0;
}

static int rv_list_add_dedup(struct rv_str_list *l, const char *id)
{
    if (rv_list_has(l, id)) return 0;
    if (l->n >= RV_MAX_SRC) return die("z23-lint: derived buffer overflow\n", "");
    rv_copy_trunc(l->s[l->n], RV_ID_CAP, id);
    l->n++;
    return 0;
}

static int rv_list_add_raw(struct rv_str_list *l, const char *id)
{
    if (l->n >= RV_MAX_SRC) return die("z23-lint: derived buffer overflow\n", "");
    rv_copy_trunc(l->s[l->n], RV_ID_CAP, id);
    l->n++;
    return 0;
}

/* ── the one slug transform ─────────────────────────────────────────────
 * lowercase ASCII, every run of non-[a-z0-9] collapsed to one '-', leading
 * and trailing '-' trimmed. Byte-level, no locale. */
static void rv_slug(const char *s, char *out, size_t cap)
{
    size_t o = 0;
    int started = 0, prev_dash = 0;
    for (const char *p = s; *p && o + 1 < cap; p++) {
        unsigned char c = (unsigned char)*p;
        unsigned char lc = (c >= 'A' && c <= 'Z') ? (unsigned char)(c - 'A' + 'a') : c;
        int alnum = (lc >= 'a' && lc <= 'z') || (lc >= '0' && lc <= '9');
        if (alnum) { out[o++] = (char)lc; prev_dash = 0; started = 1; }
        else if (started && !prev_dash) { out[o++] = '-'; prev_dash = 1; }
    }
    while (o > 0 && out[o - 1] == '-') o--;
    out[o] = '\0';
}

static void rv_trim(char *s)
{
    size_t n = strlen(s), start = 0;
    while (start < n && isspace((unsigned char)s[start])) start++;
    size_t end = n;
    while (end > start && isspace((unsigned char)s[end - 1])) end--;
    size_t out = 0;
    for (size_t i = start; i < end; i++) s[out++] = s[i];
    s[out] = '\0';
}

static int rv_path_missing(const char *path, int want_dir)
{
    struct stat st;
    if (stat(path, &st) != 0) return 1;
    return want_dir ? !S_ISDIR(st.st_mode) : !S_ISREG(st.st_mode);
}

/* ── grok headings ───────────────────────────────────────────────────── */
static int rv_grok_heading(const char *line, char *heading, size_t cap)
{
    if (line[0] != '#') return 0;
    size_t h = 0;
    while (line[h] == '#') h++;
    if (line[h] != ' ' && line[h] != '\t') return 0;
    size_t start = h;
    while (line[start] == ' ' || line[start] == '\t') start++;
    size_t end = strlen(line);
    while (end > start && (line[end - 1] == ' ' || line[end - 1] == '\t')) end--;
    if (end <= start) return 0;
    size_t len = end - start;
    if (len >= cap) return die("z23-lint: derived buffer overflow\n", "");
    memcpy(heading, line + start, len);
    heading[len] = '\0';
    return 1;
}

static int rv_scan_md_file(const char *path, struct rv_str_list *raw)
{
    FILE *f = fopen(path, "r");
    if (!f) return die("z23-lint: cannot open %s\n", path);
    char line[RV_LINE_CAP];
    int rc = 0;
    while (rc == 0 && fgets(line, sizeof line, f)) {
        size_t n = strlen(line);
        while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = '\0';
        char heading[RV_LINE_CAP];
        if (!rv_grok_heading(line, heading, sizeof heading)) continue;
        char slug[RV_ID_CAP], id[RV_ID_CAP];
        rv_slug(heading, slug, sizeof slug);
        rv_concat_trunc(id, sizeof id, "grok:", 0, slug);
        rc = rv_list_add_raw(raw, id);
    }
    int rf_err = ferror(f);
    fclose(f);
    return rc ? rc : (rf_err ? die("z23-lint: cannot open %s\n", path) : 0);
}

struct rv_walk_ctx { struct rv_str_list *raw; int rc; };

static int rv_walk_md_dir(const char *dir, struct rv_walk_ctx *ctx)
{
    struct dirent **names = NULL;
    int n = scandir(dir, &names, NULL, alphasort);
    if (n < 0) return errno == ENOENT ? 0 : die("z23-lint: cannot scan %s\n", dir);
    for (int i = 0; i < n && ctx->rc == 0; i++) {
        const char *name = names[i]->d_name;
        if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
            char path[RV_PATH_CAP];
            struct stat st;
            size_t nl = strlen(name);
            int k = snprintf(path, sizeof path, "%s/%s", dir, name);
            if (k < 0 || (size_t)k >= sizeof path) ctx->rc = die("z23-lint: path too long: %s\n", dir);
            else if (lstat(path, &st) != 0) ctx->rc = die("z23-lint: cannot stat %s\n", path);
            else if (S_ISDIR(st.st_mode)) ctx->rc = rv_walk_md_dir(path, ctx);
            else if (S_ISREG(st.st_mode) && nl >= 3
                     && memcmp(name + nl - 3, ".md", 3) == 0)
                ctx->rc = rv_scan_md_file(path, ctx->raw);
        }
        free(names[i]);
    }
    free(names);
    return ctx->rc;
}

static int rv_collect_grok_ids(const char *dir, struct rv_str_list *raw)
{
    struct rv_walk_ctx ctx = { raw, 0 };
    return rv_walk_md_dir(dir, &ctx);
}

/* ── persona ids ─────────────────────────────────────────────────────── */
/* Advances past the next "..." literal at/after `p` into `out` (backslash
 * escapes kept raw, matching the shell's substr-of-match); returns the
 * position past the closing quote, or NULL if malformed. */
static const char *rv_next_literal(const char *p, char *out, size_t cap, int *ok)
{
    const char *q = strchr(p, '"');
    *ok = 0;
    if (!q) return NULL;
    q++;
    size_t o = 0;
    while (*q && *q != '"') {
        if (*q == '\\' && q[1]) {
            if (o + 2 < cap) { out[o++] = *q; out[o++] = q[1]; }
            q += 2;
            continue;
        }
        if (o + 1 < cap) out[o++] = *q;
        q++;
    }
    if (*q != '"') return NULL;
    out[o] = '\0';
    *ok = 1;
    return q + 1;
}

static int rv_collect_persona_ids(const char *path, struct rv_str_list *raw)
{
    FILE *f = fopen(path, "r");
    if (!f) return die("z23-lint: cannot open %s\n", path);
    char line[RV_LINE_CAP];
    int rc = 0;
    while (rc == 0 && fgets(line, sizeof line, f)) {
        size_t n = strlen(line);
        while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = '\0';
        if (strncmp(line, "PERSONA(", 8) != 0) continue;
        char lit[RV_TEXT_CAP], id[RV_ID_CAP];
        int ok = 0;
        rv_next_literal(line, lit, sizeof lit, &ok);
        if (!ok) continue;
        rv_concat_trunc(id, sizeof id, "persona:", 0, lit);
        rc = rv_list_add_raw(raw, id);
    }
    int rf_err = ferror(f);
    fclose(f);
    return rc ? rc : (rf_err ? die("z23-lint: cannot open %s\n", path) : 0);
}

/* ── ZCL_RULE row parsing ────────────────────────────────────────────── */
struct rv_row {
    int malformed;
    char id[RV_ID_CAP], src[64], st[64], fl[32], mt[32];
    char text[RV_TEXT_CAP];
};

static int rv_count_literals(const char *line, char *id, size_t idcap,
                              char *text, size_t textcap, int *total)
{
    int count = 0;
    const char *p = line;
    char buf[RV_TEXT_CAP];
    for (;;) {
        int ok = 0;
        const char *next = rv_next_literal(p, buf, sizeof buf, &ok);
        if (!ok) break;
        count++;
        if (count == 1) rv_copy_trunc(id, idcap, buf);
        else if (count == 2) rv_copy_trunc(text, textcap, buf);
        p = next;
    }
    *total = count;
    return count == 2;
}

static int rv_strip_wrapper(const char *raw, char *body, size_t cap)
{
    static const char prefix[] = "ZCL_RULE(";
    size_t plen = sizeof prefix - 1;
    if (strncmp(raw, prefix, plen) != 0) return 0;
    const char *p = raw + plen;
    size_t len = strlen(p);
    while (len > 0 && isspace((unsigned char)p[len - 1])) len--;
    if (len == 0 || p[len - 1] != ')') return 0;
    len--;
    if (len >= cap) return die("z23-lint: derived buffer overflow\n", "");
    memcpy(body, p, len);
    body[len] = '\0';
    return 1;
}

static int rv_strip_leading_id(const char *body, char *tail, size_t cap)
{
    const char *p = body;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '"') return 0;
    char dummy[RV_TEXT_CAP];
    int ok = 0;
    const char *after = rv_next_literal(p, dummy, sizeof dummy, &ok);
    if (!ok) return 0;
    p = after;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != ',') return 0;
    p++;
    rv_copy_trunc(tail, cap, p);
    return 1;
}

static int rv_split_fields(const char *tail, char *f1, char *f2, char *f3, char *f4)
{
    int commas = 0;
    for (const char *q = tail; *q; q++) if (*q == ',') commas++;
    if (commas < 4) return 0;
    char *outs[4] = { f1, f2, f3, f4 };
    const char *cur = tail;
    for (int i = 0; i < 4; i++) {
        const char *comma = strchr(cur, ',');
        size_t len = (size_t)(comma - cur);
        if (len >= 64) return die("z23-lint: derived buffer overflow\n", "");
        memcpy(outs[i], cur, len);
        outs[i][len] = '\0';
        rv_trim(outs[i]);
        cur = comma + 1;
    }
    return 1;
}

/* Parses one `ZCL_RULE(...)` line; a row not carrying (id, source, state,
 * floor, min_trials, text) sets row->malformed, matching rule_rows(). */
static void rv_parse_row(const char *line, struct rv_row *row)
{
    memset(row, 0, sizeof *row);
    int total = 0;
    char text[RV_TEXT_CAP];
    if (!rv_count_literals(line, row->id, sizeof row->id, text, sizeof text, &total)
        || total != 2) {
        row->malformed = 1;
        return;
    }
    char body[RV_LINE_CAP], tail[RV_LINE_CAP];
    if (!rv_strip_wrapper(line, body, sizeof body)
        || !rv_strip_leading_id(body, tail, sizeof tail)
        || !rv_split_fields(tail, row->src, row->st, row->fl, row->mt)) {
        row->malformed = 1;
        return;
    }
    rv_copy_trunc(row->text, sizeof row->text, text);
}

static int rv_is_uint(const char *s)
{
    if (!*s) return 0;
    for (const char *p = s; *p; p++)
        if (!isdigit((unsigned char)*p)) return 0;
    return 1;
}

static int rv_fault(char *faults, size_t cap, size_t *used, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int k = vsnprintf(faults + *used, cap - *used, fmt, ap);
    va_end(ap);
    if (ovf(k, cap - *used)) return die("z23-lint: derived buffer overflow\n", "");
    *used += (size_t)k;
    return 0;
}

static int rv_check_id_source(struct rv_row *r, char *faults, size_t cap, size_t *used)
{
    if (strncmp(r->id, "grok:", 5) == 0) {
        if (strcmp(r->src, "ZCL_RULE_SRC_GROK") != 0)
            return rv_fault(faults, cap, used, "  %s: a grok: id must declare ZCL_RULE_SRC_GROK, not '%s'\n", r->id, r->src);
        return 0;
    }
    if (strncmp(r->id, "persona:", 8) == 0) {
        if (strcmp(r->src, "ZCL_RULE_SRC_PERSONA") != 0)
            return rv_fault(faults, cap, used, "  %s: a persona: id must declare ZCL_RULE_SRC_PERSONA, not '%s'\n", r->id, r->src);
        return 0;
    }
    return rv_fault(faults, cap, used, "  %s: an id must begin grok: or persona:\n", r->id);
}

static int rv_check_state(struct rv_row *r, char *faults, size_t cap, size_t *used)
{
    if (strcmp(r->st, "ZCL_RULE_SHADOW") == 0 || strcmp(r->st, "ZCL_RULE_OBEYED") == 0
        || strcmp(r->st, "ZCL_RULE_RETIRED") == 0)
        return 0;
    return rv_fault(faults, cap, used, "  %s: state '%s' is not shadow, obeyed or retired\n", r->id, r->st);
}

static int rv_check_floor(struct rv_row *r, char *faults, size_t cap, size_t *used)
{
    if (!rv_is_uint(r->fl))
        return rv_fault(faults, cap, used, "  %s: floor '%s' is not a per-mille integer\n", r->id, r->fl);
    if (atoi(r->fl) > 1000)
        return rv_fault(faults, cap, used, "  %s: floor %s is above 1000 per-mille, which no rule can clear\n", r->id, r->fl);
    return 0;
}

static int rv_check_min_trials(struct rv_row *r, char *faults, size_t cap, size_t *used)
{
    if (!rv_is_uint(r->mt))
        return rv_fault(faults, cap, used, "  %s: min_trials '%s' is not an integer\n", r->id, r->mt);
    if (atoi(r->mt) < 1)
        return rv_fault(faults, cap, used, "  %s: min_trials %s would let a rule be judged on nothing\n", r->id, r->mt);
    return 0;
}

static int rv_check_text(struct rv_row *r, char *faults, size_t cap, size_t *used)
{
    int len = (int)strlen(r->text);
    if (len < RV_TEXT_MIN)
        return rv_fault(faults, cap, used, "  %s: text is %d characters; a rule a reader can act on is longer\n", r->id, len);
    if (len > RV_TEXT_MAX)
        return rv_fault(faults, cap, used, "  %s: text is %d characters; that is a section, not a rule\n", r->id, len);
    return 0;
}

static int rv_check_row(struct rv_row *r, struct rv_str_list *seen, struct rv_str_list *have,
                         const char *gdir, const char *pdef, char *faults, size_t cap, size_t *used)
{
    int rc = 0;
    if (rv_list_has(seen, r->id))
        rc = rc || rv_fault(faults, cap, used, "  %s: a second row for an id that already has one\n", r->id);
    rc = rc || rv_list_add_dedup(seen, r->id);
    rc = rc || rv_check_id_source(r, faults, cap, used);
    if (!rv_list_has(have, r->id))
        rc = rc || rv_fault(faults, cap, used, "  %s: names no heading in %s and no PERSONA row in %s\n", r->id, gdir, pdef);
    rc = rc || rv_check_state(r, faults, cap, used);
    rc = rc || rv_check_floor(r, faults, cap, used);
    rc = rc || rv_check_min_trials(r, faults, cap, used);
    rc = rc || rv_check_text(r, faults, cap, used);
    return rc;
}

static int rv_scan_rows(const char *def, struct rv_str_list *have, const char *gdir,
                         const char *pdef, char *faults, size_t cap, size_t *used, int *rows)
{
    FILE *f = fopen(def, "r");
    if (!f) return die("z23-lint: cannot open %s\n", def);
    struct rv_str_list seen = { .n = 0 };
    char line[RV_LINE_CAP];
    int rc = 0;
    while (rc == 0 && fgets(line, sizeof line, f)) {
        size_t n = strlen(line);
        while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = '\0';
        if (strncmp(line, "ZCL_RULE(", 9) != 0) continue;
        (*rows)++;
        struct rv_row row;
        rv_parse_row(line, &row);
        if (row.malformed) {
            rc = rv_fault(faults, cap, used, "  a ZCL_RULE row does not carry (id, source, state, floor, min_trials, text)\n");
            continue;
        }
        rc = rv_check_row(&row, &seen, have, gdir, pdef, faults, cap, used);
    }
    int rf_err = ferror(f);
    fclose(f);
    if (rc) return rc;
    if (rf_err) return die("z23-lint: cannot open %s\n", def);
    for (int i = 0; i < have->n && rc == 0; i++)
        if (!rv_list_has(&seen, have->s[i]))
            rc = rv_fault(faults, cap, used, "  %s: exists in its source but has no row; it would be shown and never scored\n", have->s[i]);
    return rc;
}

static int rv_require_present(FILE *err, const char *path, int missing)
{
    if (!missing) return 0;
    fprintf(err, "[check_rule_vocabulary] FATAL — %s is missing; refusing to report a clean scan\n", path);
    return 2;
}

static int rv_run_at(const char *def, const char *pdef, const char *gdir, int row_floor,
                      FILE *out, FILE *err)
{
    int rc = rv_require_present(err, def, rv_path_missing(def, 0));
    rc = rc ? rc : rv_require_present(err, pdef, rv_path_missing(pdef, 0));
    rc = rc ? rc : rv_require_present(err, gdir, rv_path_missing(gdir, 1));
    if (rc) return rc;

    static struct rv_str_list raw;
    raw.n = 0;
    rc = rv_collect_grok_ids(gdir, &raw);
    if (rc) return rc;
    rc = rv_collect_persona_ids(pdef, &raw);
    if (rc) return rc;
    int sources = raw.n;

    static struct rv_str_list have;
    have.n = 0;
    for (int i = 0; i < raw.n && rc == 0; i++) rc = rv_list_add_dedup(&have, raw.s[i]);
    if (rc) return rc;

    static char faults[RV_FAULT_CAP];
    size_t used = 0;
    int rows = 0;
    rc = rv_scan_rows(def, &have, gdir, pdef, faults, sizeof faults, &used, &rows);
    if (rc) return rc;
    faults[used] = '\0';

    char hint[256];
    snprintf(hint, sizeof hint, "rule_vocab.def parsed %d row(s); the ZCL_RULE( parser or the file changed shape", rows);
    rc = gate_require_scanned(rows, row_floor, "check_rule_vocabulary", hint);
    if (rc) return rc;

    if (used > 0) {
        fprintf(err, "[check_rule_vocabulary] FAIL — the rule vocabulary is not closed:\n%s\n"
                     "  Every id must resolve to a heading in %s or a PERSONA row in\n"
                     "  %s, and every heading and persona must have a row.\n"
                     "  Add or correct the row in %s.\n", faults, gdir, pdef, def);
        return 1;
    }

    fprintf(out, "[check_rule_vocabulary] PASS — %d rule(s) closed over %d source(s); every "
                 "id resolves and every source has a row\n", rows, sources);
    return 0;
}

int check_rule_vocabulary_run(int argc, char **argv)
{
    (void)argc; (void)argv;
    const char *def = env_or("ZCL_RULE_VOCAB_DEF", "engine/composition/rule_vocab.def");
    const char *pdef = env_or("ZCL_RULE_PERSONA_DEF", "engine/modules/engine/include/engine/personas.def");
    const char *gdir = env_or("ZCL_RULE_GROK_DIR", ".grok/rules");
    const char *rf = getenv("ZCL_RULE_ROW_FLOOR");
    int row_floor = (rf && rf[0]) ? atoi(rf) : 7;
    return rv_run_at(def, pdef, gdir, row_floor, stdout, stderr);
}

/* ── selftest ─────────────────────────────────────────────────────────── */
static int rv_hush(int (*fn)(void))
{
    int n = open("/dev/null", O_WRONLY);
    int o = dup(1), e = dup(2);
    if (n < 0 || o < 0 || e < 0) return die("z23-lint: tmpfile failed\n", "");
    int rc = 2;
    if (dup2(n, 1) >= 0 && dup2(n, 2) >= 0) rc = fn();
    fflush(stdout); fflush(stderr); /* buffered stdout else leaks post-restore */
    (void)dup2(o, 1); (void)dup2(e, 2);
    close(n); close(o); close(e);
    return rc;
}

static const char k_rv_good_grok[] =
    "ZCL_RULE(\"grok:only-rule\", ZCL_RULE_SRC_GROK, ZCL_RULE_OBEYED, 500, 30, "
    "\"New program code is C23 and there is no Python fallback.\")";
static const char k_rv_good_per[] =
    "ZCL_RULE(\"persona:platform/modules/base\", ZCL_RULE_SRC_PERSONA, ZCL_RULE_OBEYED, "
    "500, 30, \"LOG_FAIL and LOG_ERR return; discarding the value changes control flow.\")";

static char g_rv_dir[RV_PATH_CAP];

/* One-shot fixture setup: a temp dir with a grok/r.md heading and a
 * personas.def, both matching the shell selftest's own good_grok/good_per
 * sources so parity is provable. */
static int rv_st_setup(void)
{
    const char *td = env_or("TMPDIR", "/tmp");
    char tmpl[RV_PATH_CAP];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-rv.XXXXXX", td), sizeof tmpl)) return 2;
    char *tmp = mkdtemp(tmpl);
    if (!tmp) return die("z23-lint: mkdir failed: %s\n", td);
    rv_copy_trunc(g_rv_dir, sizeof g_rv_dir, tmp);
    char grok[RV_PATH_CAP], rmd[RV_PATH_CAP], pdef[RV_PATH_CAP];
    rv_concat_trunc(grok, sizeof grok, g_rv_dir, '/', "grok");
    if (csr_mkdirs(grok)) return 1;
    rv_concat_trunc(rmd, sizeof rmd, g_rv_dir, '/', "grok/r.md"); // error-doc-ref-ok: a path this selftest creates in its own temp tree
    rv_concat_trunc(pdef, sizeof pdef, g_rv_dir, '/', "personas.def");
    int rc = csr_write(rmd, "# Only Rule\n");
    rc = rc || csr_write(pdef,
        "PERSONA(\"platform/modules/base\",\n"
        "    \"LOG_FAIL, LOG_ERR and LOG_NULL RETURN; they are not print statements.\",\n"
        "    \"platform/modules/base/include/base/log_macros.h\")\n");
    return rc;
}

static int rv_st_case(const char *def_body, int want_clean)
{
    char defpath[RV_PATH_CAP], grok[RV_PATH_CAP], pdef[RV_PATH_CAP];
    rv_concat_trunc(defpath, sizeof defpath, g_rv_dir, '/', "def");
    rv_concat_trunc(grok, sizeof grok, g_rv_dir, '/', "grok");
    rv_concat_trunc(pdef, sizeof pdef, g_rv_dir, '/', "personas.def");
    if (csr_write(defpath, def_body)) return 1;

    static char faults[RV_FAULT_CAP];
    faults[0] = '\0';
    struct rv_str_list raw = { .n = 0 }, have = { .n = 0 };
    int rc = rv_collect_grok_ids(grok, &raw);
    rc = rc || rv_collect_persona_ids(pdef, &raw);
    for (int i = 0; i < raw.n && rc == 0; i++) rc = rv_list_add_dedup(&have, raw.s[i]);
    if (rc) return 1;
    size_t used = 0;
    int rows = 0;
    if (rv_scan_rows(defpath, &have, grok, pdef, faults, sizeof faults, &used, &rows)) return 1;
    int clean = used == 0;
    return clean != (want_clean != 0);
}

static int rv_st_joined(const char *const *lines, int n, int want_clean)
{
    char body[RV_LINE_CAP];
    size_t o = 0;
    for (int i = 0; i < n; i++) {
        int k = snprintf(body + o, sizeof body - o, "%s\n", lines[i]);
        if (ovf(k, sizeof body - o)) return die("z23-lint: derived buffer overflow\n", "");
        o += (size_t)k;
    }
    return rv_st_case(body, want_clean);
}

/* Each fixture below is the shell selftest's own row text, reproduced
 * verbatim, so parity with tools/lint/check_rule_vocabulary.sh is provable
 * by inspection. */
static int rv_st_scan_cases(void)
{
    static const char no_head[] =
        "ZCL_RULE(\"grok:no-such-heading\", ZCL_RULE_SRC_GROK, ZCL_RULE_OBEYED, 500, 30, "
        "\"A rule quoting a heading that nobody ever wrote down.\")";
    static const char wrong_src[] =
        "ZCL_RULE(\"persona:platform/modules/base\", ZCL_RULE_SRC_GROK, ZCL_RULE_OBEYED, 500, "
        "30, \"LOG_FAIL and LOG_ERR return; discarding the value changes control flow.\")";
    static const char bad_state[] =
        "ZCL_RULE(\"persona:platform/modules/base\", ZCL_RULE_SRC_PERSONA, ZCL_RULE_MAYBE, 500, "
        "30, \"LOG_FAIL and LOG_ERR return; discarding the value changes control flow.\")";
    static const char bad_floor[] =
        "ZCL_RULE(\"persona:platform/modules/base\", ZCL_RULE_SRC_PERSONA, ZCL_RULE_OBEYED, "
        "1400, 30, \"LOG_FAIL and LOG_ERR return; discarding the value changes control flow.\")";
    static const char bad_trials[] =
        "ZCL_RULE(\"persona:platform/modules/base\", ZCL_RULE_SRC_PERSONA, ZCL_RULE_OBEYED, "
        "500, 0, \"LOG_FAIL and LOG_ERR return; discarding the value changes control flow.\")";
    static const char bad_text[] =
        "ZCL_RULE(\"persona:platform/modules/base\", ZCL_RULE_SRC_PERSONA, ZCL_RULE_OBEYED, "
        "500, 30, \"be careful\")";
    int bad = 0;

    { const char *l[] = { k_rv_good_grok, k_rv_good_per }; bad |= rv_st_joined(l, 2, 1); }
    { const char *l[] = { k_rv_good_grok, k_rv_good_per, no_head }; bad |= rv_st_joined(l, 3, 0); }
    { const char *l[] = { no_head, k_rv_good_grok, k_rv_good_per }; bad |= rv_st_joined(l, 3, 0); }
    { const char *l[] = { k_rv_good_grok }; bad |= rv_st_joined(l, 1, 0); }
    { const char *l[] = { k_rv_good_grok, k_rv_good_per, k_rv_good_per }; bad |= rv_st_joined(l, 3, 0); }
    { const char *l[] = { k_rv_good_grok, wrong_src }; bad |= rv_st_joined(l, 2, 0); }
    { const char *l[] = { k_rv_good_grok, bad_state }; bad |= rv_st_joined(l, 2, 0); }
    { const char *l[] = { k_rv_good_grok, bad_floor }; bad |= rv_st_joined(l, 2, 0); }
    { const char *l[] = { k_rv_good_grok, bad_trials }; bad |= rv_st_joined(l, 2, 0); }
    { const char *l[] = { k_rv_good_grok, bad_text }; bad |= rv_st_joined(l, 2, 0); }

    return bad;
}

static int rv_st_run_noargs(void) { return check_rule_vocabulary_run(0, NULL); }

static int rv_st_empty_run(void)
{
    char empty[RV_PATH_CAP];
    rv_concat_trunc(empty, sizeof empty, g_rv_dir, '/', "empty.def");
    if (csr_write(empty, "")) return 1;
    if (setenv("ZCL_RULE_VOCAB_DEF", empty, 1) != 0) return 1;
    int rc = rv_hush(rv_st_run_noargs);
    (void)unsetenv("ZCL_RULE_VOCAB_DEF");
    return rc != 2;
}

int check_rule_vocabulary_selftest(void)
{
    int bad = 0;
    if (rv_st_setup()) return st_ok(1, "check_rule_vocabulary selftest: OK\n");
    bad |= rv_st_scan_cases();
    bad |= rv_st_empty_run();
    (void)rap_rm_rf(g_rv_dir);
    if (bad) return st_ok(1, "check_rule_vocabulary selftest: OK\n");
    if (printf("[check_rule_vocabulary] SELFTEST PASS (unresolvable id at either end of the "
               "file, uncovered source, duplicate id, wrong source tag, bad state, impossible "
               "floor, zero min_trials and unusably short text all fail; a closed vocabulary "
               "passes; an empty .def exits 2)\n") < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}
