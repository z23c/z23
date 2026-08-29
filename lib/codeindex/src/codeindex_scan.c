/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * codeindex_scan — the in-tree C source scanner (PRIMARY ground truth).
 *
 * The release build ships without `-g`, so nm gives no line info; the only
 * dependable source of def/decl/signature/doc is the source text itself. This
 * scanner tokenizes C robustly enough to place, per top-level symbol:
 *   - kind (func / static func / struct / typedef / enum / macro / data),
 *   - its DEFINITION line (a body `{`) or DECLARATION line (a `;` prototype),
 *   - a cleaned one-line signature,
 *   - the first line of the immediately-preceding doc comment,
 *   - the enclosing `#ifdef` guard (top-of-stack), and
 *   - a bounded set of call-site refs (identifier '(' inside function bodies).
 *
 * ── Confident-parse vs graceful degradation ──
 * When a clean one-line signature can be extracted (single-line prototype or
 * definition, plain `struct/enum/typedef`, `#define`), the symbol is emitted
 * fully. When it CANNOT — a multiline prototype folded onto one logical line,
 * an X-macro-wrapped decl (ZCL_COMMAND_*, AGENT_IMPACT_RULE, …), a
 * function-pointer typedef, an attribute salad — the scanner DEGRADES: it
 * emits the symbol anyway with the raw declaration line as the signature and
 * `partial=true`. It never tries to fully evaluate the preprocessor, and it
 * never silently drops a top-level identifier.
 *
 * This is deliberately heuristic. It is expected to be iterated; correctness
 * lives in test_codeindex against a controlled fixture. */
#include "codeindex_scan_internal.h"

#include "base/text_fit.h"
#include "util/safe_alloc.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>   /* strncasecmp */

#define CI_MAX_SYMS_PER_FILE  20000
#define CI_MAX_REFS_PER_FILE  20000
#define CI_GUARD_STACK_MAX    64

static bool is_ident_start(int c) { return isalpha(c) || c == '_'; }
static bool is_ident_char(int c) { return isalnum(c) || c == '_'; }

/* ── preprocessor / control keywords excluded from refs ─────────────── */
static bool is_keyword(const char *s)
{
    static const char *const kw[] = {
        "if", "for", "while", "switch", "return", "sizeof", "do", "else",
        "case", "default", "goto", "break", "continue", "typeof", "alignof",
        "_Alignof", "static_assert", "_Static_assert", "defined",
        "__attribute__", "asm", "__asm__", "catch", NULL,
    };
    for (size_t i = 0; kw[i]; i++)
        if (strcmp(s, kw[i]) == 0) return true;
    return false;
}

/* A token that is a C keyword / type qualifier is never a real symbol name;
 * when name extraction bottoms out at one of these, the segment carried no
 * declarable identifier and is dropped rather than emitted as noise. */
static bool is_reserved_name(const char *s)
{
    static const char *const rk[] = {
        "extern", "static", "const", "volatile", "register", "inline",
        "void", "char", "short", "int", "long", "float", "double",
        "signed", "unsigned", "struct", "union", "enum", "typedef",
        "return", "goto", "sizeof", "restrict", "_Bool", "bool",
        "_Atomic", "_Noreturn", "_Thread_local", "else", "do", "if",
        "for", "while", "switch", "case", "default", "break", "continue",
        NULL,
    };
    for (size_t i = 0; rk[i]; i++)
        if (strcmp(s, rk[i]) == 0) return true;
    return false;
}

/* ── line index ─────────────────────────────────────────────────────── */

/* `struct scan_ctx` now lives in codeindex_scan_internal.h, shared with the
 * doc-comment layer in codeindex_scan_doc.c. */

/* Record a function definition for later enclosing-attribution. Best-effort:
 * silently drops the record on OOM (the ref simply stays unattributed). */
static void note_func_def(struct scan_ctx *c, const char *name, int def_line)
{
    if (!name || !name[0]) return;
    if (c->nfuncs == c->cap_funcs) {
        size_t ncap = c->cap_funcs ? c->cap_funcs * 2 : 64;
        void *nb = zcl_realloc(c->funcs, ncap * sizeof(*c->funcs), "ci_funcs");
        if (!nb) return;
        c->funcs = nb;
        c->cap_funcs = ncap;
    }
    c->funcs[c->nfuncs].def_line = def_line;
    snprintf(c->funcs[c->nfuncs].name, sizeof(c->funcs[c->nfuncs].name),
             "%s", name);
    c->nfuncs++;
}

/* Enclosing function name for a call site on ref_line: the function definition
 * with the greatest def_line <= ref_line. "" when none precedes it. `c->funcs`
 * is sorted ascending by def_line before this is called. */
static const char *enclosing_for_line(const struct scan_ctx *c, int ref_line)
{
    const char *best = "";
    for (size_t i = 0; i < c->nfuncs; i++) {
        if (c->funcs[i].def_line <= ref_line)
            best = c->funcs[i].name;
        else
            break;  /* sorted ascending: no later entry can qualify */
    }
    return best;
}

static int func_def_cmp(const void *a, const void *b)
{
    int la = ((const int *)a)[0];  /* def_line is the first member */
    int lb = ((const int *)b)[0];
    return (la > lb) - (la < lb);
}

/* 1-based line number containing offset off. */
static int line_of(const struct scan_ctx *c, size_t off)
{
    size_t lo = 0, hi = c->nlines;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (c->line_starts[mid] <= off) lo = mid + 1;
        else hi = mid;
    }
    return (int)lo;  /* lo is count of starts <= off == 1-based line */
}

static const char *guard_of_line(const struct scan_ctx *c, int line1)
{
    if (line1 < 1 || (size_t)line1 > c->nlines) return "";
    return c->line_guard + (size_t)(line1 - 1) * 128;
}

/* ── small string helpers over the clean buffer ─────────────────────── */

/* First non-space offset in [a,b); returns b if none. */
static size_t first_tok(const char *clean, size_t a, size_t b)
{
    while (a < b && isspace((unsigned char)clean[a])) a++;
    return a;
}

/* Extract the identifier at offset o (must be ident start) into buf. */
static void ident_at(const char *clean, size_t o, size_t b, char *buf,
                     size_t cap)
{
    size_t n = 0;
    while (o < b && is_ident_char((unsigned char)clean[o]) && n + 1 < cap)
        buf[n++] = clean[o++];
    buf[n] = '\0';
}

/* Copy the leading token (word) of [a,b) into buf. */
static void leading_word(const char *clean, size_t a, size_t b, char *buf,
                         size_t cap)
{
    a = first_tok(clean, a, b);
    buf[0] = '\0';
    if (a < b && is_ident_start((unsigned char)clean[a]))
        ident_at(clean, a, b, buf, cap);
}

/* Last identifier token in [a,b): fills buf and *off. Returns false if none. */
static bool last_ident(const char *clean, size_t a, size_t b, char *buf,
                       size_t cap, size_t *off)
{
    bool found = false;
    size_t i = a;
    while (i < b) {
        if (is_ident_start((unsigned char)clean[i])) {
            size_t start = i;
            while (i < b && is_ident_char((unsigned char)clean[i])) i++;
            /* skip pure numbers already excluded (ident_start != digit) */
            ident_at(clean, start, b, buf, cap);
            *off = start;
            found = true;
        } else {
            i++;
        }
    }
    return found;
}

/* First '(' in [a,b) at paren-depth 0 (== the first '('); the identifier that
 * immediately precedes it is the callable name. Returns false if the token
 * before '(' is not a plain identifier (fn-pointer / cast / macro salad). */
static bool func_name(const char *clean, size_t a, size_t b, char *buf,
                      size_t cap, size_t *name_off)
{
    size_t lp = b;
    for (size_t i = a; i < b; i++) {
        if (clean[i] == '(') { lp = i; break; }
    }
    if (lp == b || lp == a) return false;
    size_t j = lp;
    while (j > a && isspace((unsigned char)clean[j - 1])) j--;
    if (j == a) return false;
    if (!is_ident_char((unsigned char)clean[j - 1])) return false;  /* '*',')' */
    size_t e = j;
    size_t s = e;
    while (s > a && is_ident_char((unsigned char)clean[s - 1])) s--;
    if (!is_ident_start((unsigned char)clean[s])) return false;
    ident_at(clean, s, e, buf, cap);
    *name_off = s;
    return true;
}

/* Is there a top-level '=' (assignment, not comparison) in [a,b)? */
static bool has_toplevel_eq(const char *clean, size_t a, size_t b)
{
    int depth = 0;
    for (size_t i = a; i < b; i++) {
        char c = clean[i];
        if (c == '(' || c == '[' || c == '{') depth++;
        else if (c == ')' || c == ']' || c == '}') { if (depth > 0) depth--; }
        else if (c == '=' && depth == 0) {
            char prev = i > a ? clean[i - 1] : 0;
            char next = i + 1 < b ? clean[i + 1] : 0;
            if (prev != '=' && prev != '<' && prev != '>' && prev != '!' &&
                next != '=')
                return true;
        }
    }
    return false;
}

/* Build a cleaned one-line signature from the CLEAN range (comments, string
 * literals, and preprocessor-line text already blanked): collapse runs of
 * whitespace to single spaces, trim. Reading `clean` — not `src` — means a
 * leading doc comment or a directive line ahead of the declaration blanks out
 * and trims away, leaving just the declaration itself. */
static void clean_signature(const struct scan_ctx *c, size_t a, size_t b,
                            char *buf, size_t cap)
{
    size_t n = 0;
    bool prev_space = true;  /* trims leading */
    for (size_t i = a; i < b && n + 1 < cap; i++) {
        unsigned char ch = (unsigned char)c->clean[i];
        if (isspace(ch)) {
            if (!prev_space) { buf[n++] = ' '; prev_space = true; }
        } else {
            buf[n++] = (char)ch;
            prev_space = false;
        }
    }
    while (n > 0 && buf[n - 1] == ' ') n--;
    buf[n] = '\0';
}

/* Raw first physical line of the ORIGINAL segment [a,b), trimmed. Used as the
 * partial-fallback signature. */
static void raw_first_line(const struct scan_ctx *c, size_t a, size_t b,
                           char *buf, size_t cap)
{
    a = first_tok(c->src, a, b);  /* skip leading whitespace */
    size_t e = a;
    while (e < b && c->src[e] != '\n') e++;
    while (e > a && isspace((unsigned char)c->src[e - 1])) e--;
    size_t n = e - a;
    if (n > cap - 1) n = cap - 1;
    memcpy(buf, c->src + a, n);
    buf[n] = '\0';
}

/* ── symbol emission ────────────────────────────────────────────────── */

static void emit_sym(struct scan_ctx *c, const char *name, char kind,
                     bool is_def, size_t name_off, size_t seg_a, size_t seg_b,
                     bool partial)
{
    if (!name || !name[0]) return;
    if (is_reserved_name(name)) return;
    if (c->syms_emitted >= CI_MAX_SYMS_PER_FILE) return;
    struct ci_symbol s;
    memset(&s, 0, sizeof(s));
    snprintf(s.name, sizeof(s.name), "%s", name);
    s.kind = kind;
    int line = line_of(c, name_off);
    if (is_def) {
        snprintf(s.def_path, sizeof(s.def_path), "%s", c->relpath);
        s.def_line = line;
    } else {
        snprintf(s.decl_path, sizeof(s.decl_path), "%s", c->relpath);
        s.decl_line = line;
    }
    if (partial)
        raw_first_line(c, seg_a, seg_b, s.signature, sizeof(s.signature));
    else
        clean_signature(c, seg_a, seg_b, s.signature, sizeof(s.signature));
    size_t tok = first_tok(c->clean, seg_a, seg_b);
    snprintf(s.doc, sizeof(s.doc), "%s", doc_for(c, seg_a, tok));
    snprintf(s.guard, sizeof(s.guard), "%s", guard_of_line(c, line));
    snprintf(s.group, sizeof(s.group), "%s", c->group ? c->group : "");
    s.partial = partial;
    /* Track function definitions for call-site enclosing attribution. */
    if (is_def && (kind == 'T' || kind == 't'))
        note_func_def(c, name, line);
    c->on_sym(&s, c->user);
    c->syms_emitted++;
}

/* ── segment classifiers ────────────────────────────────────────────── */

/* A block-opening segment [a,b) (text before its '{'). Sets *pending / *pkind
 * for typedef / anonymous struct-enum whose name follows the block. */
static void classify_block_open(struct scan_ctx *c, size_t a, size_t b,
                                bool *pending, char *pkind)
{
    *pending = false;
    *pkind = 0;
    char first[64];
    leading_word(c->clean, a, b, first, sizeof(first));
    if (first[0] == '\0') return;

    if (strcmp(first, "typedef") == 0) {
        *pending = true; *pkind = 'Y'; return;   /* name follows the block */
    }
    if (strcmp(first, "struct") == 0 || strcmp(first, "union") == 0 ||
        strcmp(first, "enum") == 0) {
        char kind = (first[0] == 'e') ? 'E' : 'S';
        /* named form: "struct NAME {" — start just past the tag WORD, not
         * past seg_start (which may carry leading whitespace). */
        size_t wstart = first_tok(c->clean, a, b);
        size_t after = first_tok(c->clean, wstart + strlen(first), b);
        if (after < b && is_ident_start((unsigned char)c->clean[after])) {
            char nm[128];
            ident_at(c->clean, after, b, nm, sizeof(nm));
            size_t nend = after;
            while (nend < b && is_ident_char((unsigned char)c->clean[nend]))
                nend++;
            size_t rest = first_tok(c->clean, nend, b);
            if (rest >= b) {
                /* "struct NAME {" — a genuine type definition. */
                emit_sym(c, nm, kind, true, after, a, b, false);
                return;
            }
            /* "struct NAME *f(...)" / "struct NAME v = {...}" — a function or
             * data whose RETURN/VAR type is this tag; fall through. */
        } else {
            /* anonymous "struct {" — the (optional) name follows the block. */
            *pending = true; *pkind = kind;
            return;
        }
        /* fall through to function / data detection */
    }
    /* data initializer: "... = { ... }" */
    if (has_toplevel_eq(c->clean, a, b)) {
        char nm[128]; size_t off;
        if (last_ident(c->clean, a, b, nm, sizeof(nm), &off))
            emit_sym(c, nm, 'D', true, off, a, b, false);
        return;
    }
    /* function definition: "<ret> NAME ( args )" */
    char nm[128]; size_t off;
    if (func_name(c->clean, a, b, nm, sizeof(nm), &off)) {
        /* pure macro-call form "NAME( ... )" with no return type → partial */
        if (off == first_tok(c->clean, a, b)) {
            emit_sym(c, nm, 'D', true, off, a, b, true);
            return;
        }
        /* 'static' as a standalone token before the name → internal linkage */
        char sig[512];
        clean_signature(c, a, off, sig, sizeof(sig));
        char kind = (strncmp(sig, "static ", 7) == 0 ||
                     strstr(sig, " static ")) ? 't' : 'T';
        emit_sym(c, nm, kind, true, off, a, b, false);
        return;
    }
    /* unknown block opener → partial best-effort */
    {
        char anm[128]; size_t off2;
        if (last_ident(c->clean, a, b, anm, sizeof(anm), &off2))
            emit_sym(c, anm, 'D', true, off2, a, b, true);
    }
}

/* A ';'-terminated segment [a,b). *pending carries a typedef/anon name to
 * bind from this segment's tail. */
static void classify_semicolon(struct scan_ctx *c, size_t a, size_t b,
                               bool *pending, char *pkind)
{
    /* bind a pending typedef/anonymous name from the tail */
    if (*pending) {
        char nm[128]; size_t off;
        if (last_ident(c->clean, a, b, nm, sizeof(nm), &off))
            emit_sym(c, nm, *pkind, true, off, a, b, false);
        *pending = false; *pkind = 0;
        return;
    }

    size_t s0 = first_tok(c->clean, a, b);
    if (s0 >= b) return;  /* empty */

    char first[64];
    leading_word(c->clean, a, b, first, sizeof(first));

    /* typedef on one line */
    if (strcmp(first, "typedef") == 0) {
        /* function-pointer typedef: "(*NAME)" */
        for (size_t i = a; i + 1 < b; i++) {
            if (c->clean[i] == '(' && c->clean[i + 1] == '*') {
                size_t j = first_tok(c->clean, i + 2, b);
                if (j < b && is_ident_start((unsigned char)c->clean[j])) {
                    char nm[128];
                    ident_at(c->clean, j, b, nm, sizeof(nm));
                    emit_sym(c, nm, 'Y', true, j, a, b, true);
                    return;
                }
            }
        }
        char nm[128]; size_t off;
        if (last_ident(c->clean, a, b, nm, sizeof(nm), &off))
            emit_sym(c, nm, 'Y', true, off, a, b, false);
        return;
    }

    bool tag = (strcmp(first, "struct") == 0 || strcmp(first, "union") == 0 ||
                strcmp(first, "enum") == 0);
    bool has_paren = false;
    for (size_t i = a; i < b; i++) if (c->clean[i] == '(') { has_paren = true; break; }

    if (tag && !has_paren) {
        /* count identifier tokens after the tag word */
        size_t after = first_tok(c->clean, a, b) + strlen(first);
        char nm[128]; size_t off;
        int ntok = 0; size_t last_off = 0; char last_nm[128] = "";
        size_t i = after;
        while (i < b) {
            if (is_ident_start((unsigned char)c->clean[i])) {
                ident_at(c->clean, i, b, nm, sizeof(nm));
                snprintf(last_nm, sizeof(last_nm), "%s", nm);
                last_off = i;
                ntok++;
                while (i < b && is_ident_char((unsigned char)c->clean[i])) i++;
            } else i++;
        }
        (void)off;
        char kind = (first[0] == 'e') ? 'E' : 'S';
        if (ntok == 1) {
            /* "struct foo;" forward declaration */
            emit_sym(c, last_nm, kind, false, last_off, a, b, false);
        } else if (ntok >= 2) {
            /* "struct foo bar;" → data var bar */
            emit_sym(c, last_nm, 'D', false, last_off, a, b, false);
        }
        return;
    }

    if (has_paren) {
        char nm[128]; size_t off;
        if (func_name(c->clean, a, b, nm, sizeof(nm), &off)) {
            /* macro-call form "NAME(...)" with no return type → partial data */
            if (off == s0) {
                emit_sym(c, nm, 'D', false, off, a, b, true);
                return;
            }
            char sig[512];
            clean_signature(c, a, off, sig, sizeof(sig));
            char kind = (strncmp(sig, "static ", 7) == 0 ||
                         strstr(sig, " static ")) ? 't' : 'T';
            /* prototype: DECLARATION (header canonical; also .c forward decl) */
            emit_sym(c, nm, kind, false, off, a, b, false);
            return;
        }
        /* fn-pointer var or messy → partial */
        char anm[128]; size_t aoff;
        if (last_ident(c->clean, a, b, anm, sizeof(anm), &aoff))
            emit_sym(c, anm, 'D', false, aoff, a, b, true);
        return;
    }

    /* plain data declaration: name before first '=' or '[' or last ident */
    {
        size_t stop = b;
        int depth = 0;
        for (size_t i = a; i < b; i++) {
            char ch = c->clean[i];
            if (ch == '(' || ch == '[' || ch == '{') depth++;
            else if (ch == ')' || ch == ']' || ch == '}') { if (depth) depth--; }
            else if (depth == 0 && ch == '=') { stop = i; break; }
        }
        char nm[128]; size_t off;
        if (last_ident(c->clean, a, stop, nm, sizeof(nm), &off))
            emit_sym(c, nm, 'D', false, off, a, b, false);
    }
}

/* ── refs pass (call sites inside function bodies) ──────────────────── */

static void scan_refs(struct scan_ctx *c)
{
    /* Sort function defs ascending by def_line so enclosing_for_line can stop
     * at the first entry past the ref line. */
    if (c->nfuncs > 1)
        qsort(c->funcs, c->nfuncs, sizeof(*c->funcs), func_def_cmp);
    int brace = 0;
    int line = 0;  /* 0-based */
    for (size_t i = 0; i < c->len; i++) {
        if (c->clean[i] == '\n') { line++; continue; }
        if ((size_t)line < c->nlines && c->pp_line[line]) continue;
        char ch = c->clean[i];
        if (ch == '{') { brace++; continue; }
        if (ch == '}') { if (brace > 0) brace--; continue; }
        if (brace <= 0) continue;  /* only body-interior call sites */
        if (is_ident_start((unsigned char)ch)) {
            size_t s = i;
            while (i < c->len && is_ident_char((unsigned char)c->clean[i])) i++;
            size_t e = i;
            /* look ahead past spaces for '(' */
            size_t k = e;
            while (k < c->len && (c->clean[k] == ' ' || c->clean[k] == '\t')) k++;
            if (k < c->len && c->clean[k] == '(') {
                char nm[128];
                size_t n = e - s;
                if (n < sizeof(nm)) {
                    memcpy(nm, c->clean + s, n);
                    nm[n] = '\0';
                    if (!is_keyword(nm) &&
                        c->refs_emitted < CI_MAX_REFS_PER_FILE) {
                        int rl = line_of(c, s);
                        c->on_ref(nm, c->relpath, rl,
                                  enclosing_for_line(c, rl), c->user);
                        c->refs_emitted++;
                    }
                }
            }
            i = e - 1;  /* for-loop will ++ */
        }
    }
}

/* ── the text scanner ───────────────────────────────────────────────── */

void ci_scan_text(const char *src, size_t len, const char *relpath,
                  bool is_header, const char *group,
                  ci_sym_cb on_sym, ci_ref_cb on_ref, void *user,
                  char purpose_out[160])
{
    if (purpose_out) purpose_out[0] = '\0';
    if (!src || len == 0 || !relpath || !on_sym || !on_ref) return;

    char *clean = zcl_malloc(len, "ci_clean");
    if (!clean) return;

    struct scan_ctx c;
    memset(&c, 0, sizeof(c));
    c.src = src; c.clean = clean; c.len = len;
    c.relpath = relpath; c.is_header = is_header; c.group = group;
    c.on_sym = on_sym; c.on_ref = on_ref; c.user = user;

    /* ── pass A: blank comments/strings/chars into clean; capture docs ── */
    {
        enum { NORMAL, STR, CHR, LC, BC } st = NORMAL;
        size_t com_start = 0;
        size_t i = 0;
        while (i < len) {
            char ch = src[i];
            switch (st) {
            case NORMAL:
                if (ch == '/' && i + 1 < len && src[i + 1] == '/') {
                    st = LC; com_start = i; clean[i] = ' ';
                    if (i + 1 < len) clean[i + 1] = ' ';
                    i += 2; break;
                }
                if (ch == '/' && i + 1 < len && src[i + 1] == '*') {
                    st = BC; com_start = i; clean[i] = ' ';
                    if (i + 1 < len) clean[i + 1] = ' ';
                    i += 2; break;
                }
                if (ch == '"') { st = STR; clean[i] = ' '; i++; break; }
                if (ch == '\'') { st = CHR; clean[i] = ' '; i++; break; }
                clean[i] = ch; i++; break;
            case STR:
                if (ch == '\\' && i + 1 < len) {
                    clean[i] = ' ';
                    clean[i + 1] = (src[i + 1] == '\n') ? '\n' : ' ';
                    i += 2; break;
                }
                if (ch == '"') { clean[i] = ' '; st = NORMAL; i++; break; }
                clean[i] = (ch == '\n') ? '\n' : ' '; i++; break;
            case CHR:
                if (ch == '\\' && i + 1 < len) {
                    clean[i] = ' ';
                    clean[i + 1] = (src[i + 1] == '\n') ? '\n' : ' ';
                    i += 2; break;
                }
                if (ch == '\'') { clean[i] = ' '; st = NORMAL; i++; break; }
                clean[i] = (ch == '\n') ? '\n' : ' '; i++; break;
            case LC:
                if (ch == '\n') {
                    capture_doc(&c, com_start + 2, i);
                    clean[i] = '\n'; st = NORMAL; i++; break;
                }
                clean[i] = ' '; i++; break;
            case BC:
                if (ch == '*' && i + 1 < len && src[i + 1] == '/') {
                    clean[i] = ' '; clean[i + 1] = ' ';
                    capture_doc(&c, com_start + 2, i);
                    st = NORMAL; i += 2; break;
                }
                clean[i] = (ch == '\n') ? '\n' : ' '; i++; break;
            }
        }
        if (st == LC) capture_doc(&c, com_start + 2, len);
    }

    /* ── file self-description: derive purpose from the leading comment ── */
    if (purpose_out) ci_file_purpose(&c, purpose_out);

    /* ── line index ── */
    size_t nl = 1;
    for (size_t i = 0; i < len; i++) if (src[i] == '\n') nl++;
    c.nlines = nl;
    c.line_starts = zcl_malloc(nl * sizeof(size_t), "ci_line_starts");
    c.line_guard = zcl_calloc(nl, 128, "ci_line_guard");
    c.pp_line = zcl_calloc(nl, sizeof(bool), "ci_pp_line");
    if (!c.line_starts || !c.line_guard || !c.pp_line) goto done;
    {
        size_t l = 0;
        c.line_starts[l++] = 0;
        for (size_t i = 0; i < len && l < nl; i++)
            if (src[i] == '\n') c.line_starts[l++] = i + 1;
    }

    /* ── pass B: preprocessor guard stack + pp_line marking ── */
    {
        char stack[CI_GUARD_STACK_MAX][128];
        int sp = 0;
        bool prev_pp = false;
        bool prev_cont = false;
        for (size_t l = 0; l < nl; l++) {
            size_t a = c.line_starts[l];
            size_t b = (l + 1 < nl) ? c.line_starts[l + 1] : len;
            size_t t = first_tok(clean, a, b);
            bool is_directive = (t < b && clean[t] == '#');
            bool is_cont = prev_pp && prev_cont;
            c.pp_line[l] = is_directive || is_cont;
            /* guard entering this line = current stack top */
            if (sp > 0)
                snprintf(c.line_guard + l * 128, 128, "%s", stack[sp - 1]);
            else
                c.line_guard[l * 128] = '\0';
            /* apply directive to affect subsequent lines */
            if (is_directive) {
                size_t d = t + 1;
                while (d < b && (clean[d] == ' ' || clean[d] == '\t')) d++;
                char dir[16];
                size_t dn = 0;
                while (d < b && is_ident_char((unsigned char)clean[d]) &&
                       dn + 1 < sizeof(dir))
                    dir[dn++] = clean[d++];
                dir[dn] = '\0';
                if (strcmp(dir, "ifdef") == 0 || strcmp(dir, "ifndef") == 0) {
                    while (d < b && (clean[d] == ' ' || clean[d] == '\t')) d++;
                    char sym[128]; size_t sn = 0;
                    while (d < b && is_ident_char((unsigned char)clean[d]) &&
                           sn + 1 < sizeof(sym))
                        sym[sn++] = clean[d++];
                    sym[sn] = '\0';
                    if (sp < CI_GUARD_STACK_MAX)
                        snprintf(stack[sp++], 128, "%s", sym);
                } else if (strcmp(dir, "if") == 0) {
                    while (d < b && (clean[d] == ' ' || clean[d] == '\t')) d++;
                    char cond[128]; size_t cn = 0;
                    while (d < b && clean[d] != '\n' && cn + 1 < sizeof(cond))
                        cond[cn++] = clean[d++];
                    while (cn > 0 && isspace((unsigned char)cond[cn - 1])) cn--;
                    cond[cn] = '\0';
                    if (sp < CI_GUARD_STACK_MAX)
                        snprintf(stack[sp++], 128, "%s", cond);
                } else if (strcmp(dir, "endif") == 0) {
                    if (sp > 0) sp--;
                }
                /* #define: emit a macro symbol (name only) */
                if (strcmp(dir, "define") == 0) {
                    while (d < b && (clean[d] == ' ' || clean[d] == '\t')) d++;
                    if (d < b && is_ident_start((unsigned char)clean[d])) {
                        char nm[128];
                        ident_at(clean, d, b, nm, sizeof(nm));
                        struct ci_symbol ms;
                        memset(&ms, 0, sizeof(ms));
                        snprintf(ms.name, sizeof(ms.name), "%s", nm);
                        ms.kind = 'M';
                        snprintf(ms.def_path, sizeof(ms.def_path), "%s", relpath);
                        ms.def_line = (int)(l + 1);
                        clean_signature(&c, a, b, ms.signature,
                                        sizeof(ms.signature));
                        snprintf(ms.doc, sizeof(ms.doc), "%s",
                                 doc_for(&c, a, t));
                        if (sp > 0)
                            snprintf(ms.guard, sizeof(ms.guard), "%s",
                                     stack[sp - 1]);
                        snprintf(ms.group, sizeof(ms.group), "%s",
                                 group ? group : "");
                        if (c.syms_emitted < CI_MAX_SYMS_PER_FILE) {
                            on_sym(&ms, user);
                            c.syms_emitted++;
                        }
                    }
                }
            }
            /* track continuation for the next line */
            {
                size_t e = b;
                while (e > a && (src[e - 1] == '\n' || src[e - 1] == '\r')) e--;
                prev_cont = (e > a && src[e - 1] == '\\');
                prev_pp = c.pp_line[l];
            }
        }
    }

    /* Blank preprocessor-line text in the structural buffer: pass B has
     * already consumed guards/#defines, and leaving "#include"/"#define"
     * tokens in `clean` would pollute the top-level segment that follows a
     * directive (its leading token would be '#', not the real return type). */
    for (size_t l = 0; l < nl; l++) {
        if (!c.pp_line[l]) continue;
        size_t a = c.line_starts[l];
        size_t b = (l + 1 < nl) ? c.line_starts[l + 1] : len;
        for (size_t i = a; i < b; i++)
            if (clean[i] != '\n') clean[i] = ' ';
    }

    /* ── pass C: structural scan for definitions/declarations ── */
    {
        size_t seg_start = 0;
        int brace = 0, paren = 0;
        bool pending = false; char pkind = 0;
        size_t line = 0;
        for (size_t i = 0; i < len; i++) {
            char ch = clean[i];
            if (ch == '\n') { line++; continue; }
            if ((size_t)line < nl && c.pp_line[line]) continue;
            if (ch == '(') { paren++; continue; }
            if (ch == ')') { if (paren > 0) paren--; continue; }
            if (brace == 0 && paren == 0) {
                if (ch == '{') {
                    classify_block_open(&c, seg_start, i, &pending, &pkind);
                    brace++;
                    seg_start = i + 1;
                    continue;
                }
                if (ch == '}') { seg_start = i + 1; continue; }
                if (ch == ';') {
                    classify_semicolon(&c, seg_start, i, &pending, &pkind);
                    seg_start = i + 1;
                    continue;
                }
            } else {
                if (ch == '{') { brace++; continue; }
                if (ch == '}') {
                    if (brace > 0) brace--;
                    if (brace == 0) seg_start = i + 1;
                    continue;
                }
            }
        }
    }

    /* ── pass D: refs ── */
    scan_refs(&c);

done:
    free(clean);
    free(c.line_starts);
    free(c.line_guard);
    free(c.pp_line);
    free(c.comments);
    free(c.funcs);
}
