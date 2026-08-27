/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * codeindex_emitter — the query-time scan behind codeindex_emitter_sites().
 * Contract, evidence kinds and limits: codeindex/codeindex_emitter.h.
 *
 * Nothing is stored. The scan walks the SAME source enumeration the index
 * rebuild walks (ci_enumerate_sources), extracts each file's string literals
 * with C adjacent-literal concatenation applied, and matches them against the
 * emitted text in both directions. A derived answer computed on demand cannot
 * disagree with the tree, so there is no staleness stamp here and no cache to
 * invalidate.
 */

#include "codeindex_priv.h"
#include "codeindex/codeindex_emitter.h"

#include "base/log_macros.h"
#include "base/safe_alloc.h"

#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum {
    EMIT_MAX_FILE_BYTES = 1u << 21, /* 2 MiB; the largest in-tree .c is ~660 KB */
    EMIT_SEG_MAX        = 512,      /* longest format segment compared at once */
    EMIT_CAND_CAP       = 96,       /* ranked candidate pool before `cap` */
    EMIT_SYMS_CAP       = 512,      /* symbols pulled per file for attribution */
    EMIT_MARKER_PAT_MAX = 96,
    EMIT_LOOKAHEAD_LINES = 15,      /* doc comment -> the function below it */
};

/* The marker convention tools/scripts/check_blocker_remedy.sh already
 * requires at every site that builds a blocker id at runtime. Matching it here
 * reuses that declaration rather than restating the id set. */
static const char k_marker_tag[] = "blocker-id:";

int codeindex_emit_kind_rank(enum ci_emit_kind kind)
{
    switch (kind) {
    case CI_EMIT_REGISTRY_ROW:   return 5;
    case CI_EMIT_LITERAL_EXACT:  return 4;
    case CI_EMIT_BLOCKER_MARKER: return 3;
    case CI_EMIT_LITERAL_SPAN:   return 2;
    case CI_EMIT_FORMAT_MATCH:   return 1;
    case CI_EMIT_NONE:           break;
    }
    return 0;
}

const char *codeindex_emit_kind_name(enum ci_emit_kind kind)
{
    switch (kind) {
    case CI_EMIT_REGISTRY_ROW:   return "registry_row";
    case CI_EMIT_LITERAL_EXACT:  return "literal_exact";
    case CI_EMIT_BLOCKER_MARKER: return "blocker_id_marker";
    case CI_EMIT_LITERAL_SPAN:   return "literal_span";
    case CI_EMIT_FORMAT_MATCH:   return "format_string";
    case CI_EMIT_NONE:           break;
    }
    return "none";
}

bool codeindex_emit_glob_match(const char *pattern, const char *text)
{
    if (!pattern || !text) return false;
    const char *star = NULL, *retry = NULL;
    while (*text) {
        if (*pattern == '*') {
            star = ++pattern;
            retry = text;
        } else if (*pattern == *text) {
            pattern++;
            text++;
        } else if (star) {
            pattern = star;
            text = ++retry;
        } else {
            return false;
        }
    }
    while (*pattern == '*') pattern++;
    return *pattern == '\0';
}

/* ── literal extraction ───────────────────────────────────────────────── */

/* One concatenated literal run: byte offset into the run buffer and the source
 * line its first quote sits on. */
struct emit_run {
    size_t off;      /* offset into emit_buf.lit */
    size_t src_off;  /* offset of the opening quote in the file's bytes */
    int    line;
};

struct emit_buf {
    char            *lit;      /* runs, each NUL-terminated */
    size_t           lit_cap;
    size_t           lit_len;
    struct emit_run *runs;
    size_t           runs_cap;
    size_t           runs_len;
    char            *text;     /* current file's bytes */
    size_t           text_cap;
};

static bool emit_buf_reserve(struct emit_buf *b, size_t file_bytes)
{
    size_t want_text = file_bytes + 1;
    if (want_text > b->text_cap) {
        char *nt = zcl_malloc(want_text, "ci_emit_text");
        if (!nt) LOG_FAIL("codeindex", "emit text buffer alloc %zu", want_text);
        free(b->text);
        b->text = nt;
        b->text_cap = want_text;
    }
    size_t want_lit = file_bytes + 2;
    if (want_lit > b->lit_cap) {
        char *nl = zcl_malloc(want_lit, "ci_emit_literals");
        if (!nl) LOG_FAIL("codeindex", "emit literal buffer alloc %zu", want_lit);
        free(b->lit);
        b->lit = nl;
        b->lit_cap = want_lit;
    }
    size_t want_runs = file_bytes / 8 + 16;
    if (want_runs > b->runs_cap) {
        struct emit_run *nr = zcl_malloc(want_runs * sizeof(*nr), "ci_emit_runs");
        if (!nr) LOG_FAIL("codeindex", "emit run table alloc %zu", want_runs);
        free(b->runs);
        b->runs = nr;
        b->runs_cap = want_runs;
    }
    return true;
}

static void emit_buf_free(struct emit_buf *b)
{
    free(b->lit);
    free(b->runs);
    free(b->text);
    *b = (struct emit_buf){0};
}

/* Escapes decode to their character; numeric and unknown escapes collapse to
 * '?' so a run can never contain an embedded NUL (runs are NUL-separated). */
static char emit_unescape(char e)
{
    switch (e) {
    case 'n':  return '\n';
    case 't':  return '\t';
    case 'r':  return '\r';
    case 'a':  return '\a';
    case 'b':  return '\b';
    case 'f':  return '\f';
    case 'v':  return '\v';
    case '"':  return '"';
    case '\\': return '\\';
    case '\'': return '\'';
    default:   return '?';
    }
}

/* Skip whitespace and comments starting at src[j]; returns the new index and
 * advances *line over any newlines crossed. */
static size_t emit_skip_gap(const char *src, size_t n, size_t j, int *line)
{
    for (;;) {
        if (j < n && (src[j] == ' ' || src[j] == '\t' || src[j] == '\r')) { j++; continue; }
        if (j < n && src[j] == '\n') { (*line)++; j++; continue; }
        if (j + 1 < n && src[j] == '/' && src[j + 1] == '*') {
            j += 2;
            while (j + 1 < n && !(src[j] == '*' && src[j + 1] == '/')) {
                if (src[j] == '\n') (*line)++;
                j++;
            }
            j = (j + 1 < n) ? j + 2 : n;
            continue;
        }
        if (j + 1 < n && src[j] == '/' && src[j + 1] == '/') {
            while (j < n && src[j] != '\n') j++;
            continue;
        }
        return j;
    }
}

/* Fill b->lit / b->runs from one file's bytes. Comments and character literals
 * are skipped; adjacent string literals separated only by whitespace/comments
 * become one run, which is what makes a wrapped format string searchable. */
static void emit_collect_literals(struct emit_buf *b, const char *src, size_t n)
{
    b->lit_len = 0;
    b->runs_len = 0;
    size_t i = 0;
    int line = 1;
    while (i < n) {
        char c = src[i];
        if (c == '\n') { line++; i++; continue; }
        if (c == '/' && i + 1 < n && (src[i + 1] == '*' || src[i + 1] == '/')) {
            i = emit_skip_gap(src, n, i, &line);
            continue;
        }
        if (c == '\'') {
            i++;
            while (i < n && src[i] != '\'') {
                if (src[i] == '\\' && i + 1 < n) i++;
                if (i < n && src[i] == '\n') line++;
                i++;
            }
            if (i < n) i++;
            continue;
        }
        if (c != '"') { i++; continue; }

        int run_line = line;
        size_t start = b->lit_len;
        size_t src_start = i;
        for (;;) {
            i++;                                       /* past the open quote */
            while (i < n && src[i] != '"') {
                if (src[i] == '\\' && i + 1 < n) {
                    if (src[i + 1] == '\n') { line++; i += 2; continue; }
                    if (b->lit_len + 2 < b->lit_cap)
                        b->lit[b->lit_len++] = emit_unescape(src[i + 1]);
                    i += 2;
                    continue;
                }
                if (src[i] == '\n') line++;             /* unterminated: defensive */
                if (b->lit_len + 2 < b->lit_cap)
                    b->lit[b->lit_len++] = src[i];
                i++;
            }
            if (i < n) i++;                            /* past the close quote */
            int peek_line = line;
            size_t j = emit_skip_gap(src, n, i, &peek_line);
            if (j < n && src[j] == '"') { i = j; line = peek_line; continue; }
            break;
        }
        if (b->lit_len + 1 < b->lit_cap && b->runs_len < b->runs_cap) {
            b->lit[b->lit_len++] = '\0';
            b->runs[b->runs_len].off = start;
            b->runs[b->runs_len].src_off = src_start;
            b->runs[b->runs_len].line = run_line;
            b->runs_len++;
        }
    }
}

/* ── format-string matching ───────────────────────────────────────────── */

/* Length of the printf conversion specifier at s[i] (which must be '%'), or 0
 * when it is not one (including "%%", a literal percent). */
static size_t emit_conv_len(const char *s, size_t i)
{
    if (s[i] != '%') return 0;
    size_t j = i + 1;
    if (s[j] == '%' || s[j] == '\0') return 0;
    while (s[j] && strchr("-+ #0'", s[j])) j++;
    while (s[j] && (isdigit((unsigned char)s[j]) || s[j] == '*')) j++;
    if (s[j] == '.') {
        j++;
        while (s[j] && (isdigit((unsigned char)s[j]) || s[j] == '*')) j++;
    }
    while (s[j] && strchr("hlLqjzt", s[j])) j++;
    if (s[j] && strchr("diouxXeEfgGaAcspn", s[j])) return j + 1 - i;
    return 0;
}

/* Walk `run`'s literal segments (the text between conversion specifiers) and
 * require each to occur, in order, inside `query`. Stops at the first segment
 * that does not — which is exactly what a reason truncated at
 * BLOCKER_REASON_MAX looks like. Reports the literal characters accounted for
 * and the longest single segment matched; returns true when EVERY segment
 * matched (a full format match) and false when it stopped early. */
static bool emit_format_walk(const char *run, const char *query,
                             int *chars_out, int *longest_out)
{
    char seg[EMIT_SEG_MAX];
    size_t sl = 0;
    const char *cursor = query;
    int chars = 0, longest = 0;
    bool complete = true;
    size_t i = 0;
    for (;;) {
        char ch = run[i];
        if (ch != '\0' && ch != '%') {
            if (sl + 1 < sizeof(seg)) seg[sl++] = ch;
            i++;
            continue;
        }
        if (ch == '%') {
            size_t conv = emit_conv_len(run, i);
            if (conv == 0) {
                if (sl + 1 < sizeof(seg)) seg[sl++] = '%';
                i += (run[i + 1] == '%') ? 2 : 1;
                continue;
            }
            i += conv;
        }
        if (sl > 0) {
            seg[sl] = '\0';
            const char *p = strstr(cursor, seg);
            if (!p) { complete = false; break; }
            chars += (int)sl;
            if ((int)sl > longest) longest = (int)sl;
            cursor = p + sl;
            sl = 0;
        }
        if (ch == '\0') break;
    }
    *chars_out = chars;
    *longest_out = longest;
    return complete;
}

/* ── candidate pool ───────────────────────────────────────────────────── */

struct emit_scan {
    struct codeindex          *ci;
    const char                *query;
    const char                *prefer_path;
    size_t                     query_len;
    struct ci_emit_site        cand[EMIT_CAND_CAP];
    int                        n_cand;
    struct emit_buf            buf;
    struct ci_emit_scan_report report;
    bool                       failed;
};

static long emit_score(const struct ci_emit_site *s)
{
    return (s->preferred ? 100000000L : 0L) +
           (long)codeindex_emit_kind_rank(s->kind) * 1000000L +
           (long)s->literal_chars * 1000L + (long)s->longest_segment;
}

/* Production before test, then strongest evidence, then path/line. */
static int emit_cmp(const void *a, const void *b)
{
    const struct ci_emit_site *x = a, *y = b;
    if (x->is_test != y->is_test) return x->is_test ? 1 : -1;
    long sx = emit_score(x), sy = emit_score(y);
    if (sx != sy) return sx < sy ? 1 : -1;
    int c = strcmp(x->path, y->path);
    if (c != 0) return c;
    return x->line - y->line;
}

/* The callee whose argument list encloses the literal at src[quote]: walk back
 * to the innermost unclosed '(' and take the identifier before it. Lexical and
 * bounded — a '(' inside an earlier literal or comment can mislead it — but it
 * is the difference between blocker_init() and blocker_clear() at two sites
 * that carry byte-identical evidence, which nothing else here can see. */
static void emit_call_context(const char *src, size_t quote, char *out, size_t cap)
{
    if (cap == 0) return;
    out[0] = '\0';
    size_t floor_off = quote > 480 ? quote - 480 : 0;
    size_t i = quote;
    int depth = 0;
    bool found = false;
    while (i > floor_off) {
        i--;
        if (src[i] == ')') { depth++; continue; }
        if (src[i] != '(') continue;
        if (depth == 0) { found = true; break; }
        depth--;
    }
    if (!found) return;
    size_t end = i;
    while (end > floor_off && (src[end - 1] == ' ' || src[end - 1] == '\t' ||
                               src[end - 1] == '\n'))
        end--;
    size_t start = end;
    while (start > floor_off &&
           (isalnum((unsigned char)src[start - 1]) || src[start - 1] == '_'))
        start--;
    size_t len = end - start;
    if (len == 0 || len >= cap) return;
    memcpy(out, src + start, len);
    out[len] = '\0';
}

static void emit_note(struct emit_scan *sc, const char *path, int line,
                      enum ci_emit_kind kind, const char *evidence,
                      int chars, int longest, const char *context)
{
    /* One site per (path,line): keep the strongest evidence for it. */
    struct ci_emit_site s = {0};
    ci_cpy(s.path, sizeof(s.path), path);
    ci_cpy(s.context, sizeof(s.context), context ? context : "");
    s.line = line;
    ci_cpy(s.evidence, sizeof(s.evidence), evidence ? evidence : "");
    s.kind = kind;
    s.literal_chars = chars;
    s.longest_segment = longest;
    s.is_test = strncmp(path, "lib/test/", 9) == 0;
    s.preferred = sc->prefer_path && strcmp(sc->prefer_path, path) == 0;

    for (int i = 0; i < sc->n_cand; i++) {
        if (sc->cand[i].line != line || strcmp(sc->cand[i].path, path) != 0)
            continue;
        if (emit_score(&s) > emit_score(&sc->cand[i])) sc->cand[i] = s;
        return;
    }
    sc->report.candidates++;
    if (sc->n_cand < EMIT_CAND_CAP) {
        sc->cand[sc->n_cand++] = s;
        return;
    }
    /* Pool full: displace the weakest entry when this one beats it. */
    int weakest = 0;
    for (int i = 1; i < sc->n_cand; i++)
        if (emit_cmp(&sc->cand[i], &sc->cand[weakest]) > 0) weakest = i;
    if (emit_cmp(&s, &sc->cand[weakest]) < 0) sc->cand[weakest] = s;
}

/* `blocker-id: <pattern>` markers in one file's raw text. */
static void emit_scan_markers(struct emit_scan *sc, const char *relpath,
                              const char *src, size_t n)
{
    size_t tag = sizeof(k_marker_tag) - 1;
    int line = 1;
    for (size_t i = 0; i < n; i++) {
        if (src[i] == '\n') { line++; continue; }
        if (src[i] != 'b' || i + tag > n) continue;
        if (memcmp(src + i, k_marker_tag, tag) != 0) continue;
        sc->report.markers_seen++;
        size_t j = i + tag;
        while (j < n && (src[j] == ' ' || src[j] == '\t')) j++;
        char pat[EMIT_MARKER_PAT_MAX];
        size_t k = 0;
        while (j < n && k + 1 < sizeof(pat) &&
               (isalnum((unsigned char)src[j]) || strchr("_.*-", src[j])))
            pat[k++] = src[j++];
        pat[k] = '\0';
        if (k == 0 || strchr(pat, '*') == NULL) continue;
        if (!codeindex_emit_glob_match(pat, sc->query)) continue;
        char ev[CI_EMIT_EVIDENCE_MAX];
        (void)snprintf(ev, sizeof(ev), "blocker-id: %s", pat);
        emit_note(sc, relpath, line, CI_EMIT_BLOCKER_MARKER, ev,
                  (int)strlen(pat), (int)strlen(pat), "declared marker");
    }
}

/* True when src[quote] opens the header path of an `#include "…"` line. Such a
 * literal is never a message an agent saw: it is a build edge, and reporting
 * `foo.h` as the emitter of anything is pure noise. Other directives are NOT
 * skipped — a `#define X_COND_NAME "…"` literal is a real id source. */
static bool emit_is_include_path(const char *src, size_t quote)
{
    size_t i = quote;
    while (i > 0 && src[i - 1] != '\n') i--;          /* start of the line */
    while (src[i] == ' ' || src[i] == '\t') i++;
    if (src[i] != '#') return false;
    i++;
    while (src[i] == ' ' || src[i] == '\t') i++;
    return strncmp(src + i, "include", 7) == 0;
}

static void emit_scan_runs(struct emit_scan *sc, const char *relpath)
{
    const char *src = sc->buf.text;
    for (size_t r = 0; r < sc->buf.runs_len; r++) {
        const char *run = sc->buf.lit + sc->buf.runs[r].off;
        int line = sc->buf.runs[r].line;
        size_t run_len = strlen(run);
        if (run_len == 0) continue;
        if (emit_is_include_path(src, sc->buf.runs[r].src_off)) continue;
        sc->report.literal_runs++;

        /* Direction 1 — the emitted text occurs inside this literal. */
        if (sc->query_len >= CI_EMIT_MIN_LITERAL_QUERY && run_len >= sc->query_len) {
            const char *hit = strstr(run, sc->query);
            if (hit) {
                char ctx[80];
                emit_call_context(src, sc->buf.runs[r].src_off, ctx, sizeof(ctx));
                emit_note(sc, relpath, line,
                          run_len == sc->query_len ? CI_EMIT_LITERAL_EXACT
                                                   : CI_EMIT_LITERAL_SPAN,
                          run, (int)sc->query_len, (int)sc->query_len, ctx);
                continue;
            }
        }
        /* Direction 2 — this literal is a format string whose segments occur,
         * in order, inside the emitted text. */
        int chars = 0, longest = 0;
        bool complete = emit_format_walk(run, sc->query, &chars, &longest);
        if (chars >= CI_EMIT_MIN_FORMAT_CHARS &&
            longest >= CI_EMIT_MIN_FORMAT_SEGMENT) {
            char ev[CI_EMIT_EVIDENCE_MAX];
            (void)snprintf(ev, sizeof(ev), "%s%s", complete ? "" : "[prefix] ", run);
            char ctx[80];
            emit_call_context(src, sc->buf.runs[r].src_off, ctx, sizeof(ctx));
            emit_note(sc, relpath, line, CI_EMIT_FORMAT_MATCH, ev, chars, longest,
                      ctx);
        } else if (chars > sc->report.best_rejected_chars) {
            sc->report.best_rejected_chars = chars;
        }
    }
}

static bool emit_file_cb(const char *relpath, const struct stat *st, void *user)
{
    struct emit_scan *sc = user;
    if (!st || st->st_size <= 0 || (size_t)st->st_size > EMIT_MAX_FILE_BYTES) {
        sc->report.files_unreadable++;
        return true;
    }
    if (!emit_buf_reserve(&sc->buf, (size_t)st->st_size)) {
        sc->failed = true;
        return false;
    }
    char full[CI_PATH_MAX];
    int path_len = snprintf(full, sizeof(full), "%s/%s", sc->ci->root,
                            relpath);
    if (path_len <= 0 || (size_t)path_len >= sizeof(full)) {
        sc->report.files_unreadable++;
        return true;
    }
    int fd = open(full, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        sc->report.files_unreadable++;
        return true;
    }
    size_t got = 0;
    for (;;) {
        ssize_t k = read(fd, sc->buf.text + got, (size_t)st->st_size - got);
        if (k <= 0) break;
        got += (size_t)k;
        if (got >= (size_t)st->st_size) break;
    }
    (void)close(fd);
    if (got == 0) {
        sc->report.files_unreadable++;
        return true;
    }
    sc->buf.text[got] = '\0';
    sc->report.files_scanned++;

    emit_scan_markers(sc, relpath, sc->buf.text, got);
    emit_collect_literals(&sc->buf, sc->buf.text, got);
    emit_scan_runs(sc, relpath);
    return true;
}

/* The enclosing function of `path:line`, using the greatest-def_line rule
 * codeindex documents for ci_ref.enclosing. A `blocker-id:` marker is a DOC
 * comment sitting just above the function it describes, so when nothing is
 * defined above the line, the nearest function defined just below it is the
 * subject — bounded to EMIT_LOOKAHEAD_LINES so a file-header comment does not
 * get attributed to the first function in the file. */
static void emit_attribute(struct codeindex *ci, struct ci_emit_site *s)
{
    struct ci_symbol *syms = zcl_malloc(EMIT_SYMS_CAP * sizeof(*syms),
                                       "ci_emit_syms");
    if (!syms) return;
    int n = codeindex_symbols_in_file(ci, s->path, syms, EMIT_SYMS_CAP);
    int best = -1, after = -1;
    for (int i = 0; i < n; i++) {
        if (syms[i].kind != 'T' && syms[i].kind != 't') continue;
        if (syms[i].def_line <= 0) continue;
        if (strcmp(syms[i].def_path, s->path) != 0) continue;
        if (syms[i].def_line <= s->line) {
            if (best < 0 || syms[i].def_line > syms[best].def_line) best = i;
        } else if (syms[i].def_line - s->line <= EMIT_LOOKAHEAD_LINES) {
            if (after < 0 || syms[i].def_line < syms[after].def_line) after = i;
        }
    }
    if (best >= 0)
        ci_cpy(s->enclosing, sizeof(s->enclosing), syms[best].name);
    else if (after >= 0)
        ci_cpy(s->enclosing, sizeof(s->enclosing), syms[after].name);
    free(syms);
}

int codeindex_emitter_sites(struct codeindex *ci, const char *query,
                            const char *prefer_path,
                            struct ci_emit_site *out, int cap,
                            struct ci_emit_scan_report *report)
{
    if (report) *report = (struct ci_emit_scan_report){0};
    if (!ci || !query || !query[0] || !out || cap <= 0)
        LOG_RETURN(-1, "codeindex", "emitter_sites: bad arguments");

    struct emit_scan *sc = zcl_malloc(sizeof(*sc), "ci_emit_scan");
    if (!sc) LOG_RETURN(-1, "codeindex", "emitter scan alloc");
    memset(sc, 0, sizeof(*sc));
    sc->ci = ci;
    sc->query = query;
    sc->prefer_path = (prefer_path && prefer_path[0]) ? prefer_path : NULL;
    sc->query_len = strlen(query);

    bool walked = ci_enumerate_sources(ci->root, emit_file_cb, sc);
    if (!walked && !sc->failed)
        sc->report.enumeration_incomplete = true;   /* partial enumeration */

    int n = 0;
    if (!sc->failed) {
        qsort(sc->cand, (size_t)sc->n_cand, sizeof(sc->cand[0]), emit_cmp);
        n = sc->n_cand < cap ? sc->n_cand : cap;
        for (int i = 0; i < n; i++) {
            out[i] = sc->cand[i];
            emit_attribute(ci, &out[i]);
        }
    }
    if (report) *report = sc->report;
    emit_buf_free(&sc->buf);
    bool failed = sc->failed;
    free(sc);
    if (failed) LOG_RETURN(-1, "codeindex", "emitter scan buffer allocation");
    return n;
}
