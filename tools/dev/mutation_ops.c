/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The mutation operators: enumerate every place in one C translation unit
 * where a small, realistic defect could be introduced. Pure text in, sites
 * out — no file is opened here and nothing is written anywhere, which is
 * what lets the harness's own test group drive the entire operator space in
 * microseconds.
 *
 * The reasoning for the operator SET is in mutation_harness.h, next to the
 * defect class each one models. What is decided here is the narrower
 * question of where each operator may fire, and that answer is: only in code
 * the compiler actually reads. A mutation inside a string literal, a comment
 * or an #include changes nothing or breaks the build, and either way it
 * teaches nothing about a test.
 */

#include "mutation_harness.h"

#include "base/safe_alloc.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *zcl_mut_class_name(enum zcl_mut_class cls)
{
    switch (cls) {
    case ZCL_MUT_CLASS_RELATIONAL: return "relational";
    case ZCL_MUT_CLASS_LOGICAL:    return "logical";
    case ZCL_MUT_CLASS_BOUNDARY:   return "boundary";
    case ZCL_MUT_CLASS_RETURN:     return "return";
    case ZCL_MUT_CLASS_STATEMENT:  return "statement";
    case ZCL_MUT_CLASS_COUNT:
    default:                       return "unknown";
    }
}

/* ── the code mask ───────────────────────────────────────────────────────
 *
 * One byte per input byte: 1 where the compiler sees code, 0 everywhere
 * else. Unlike a per-line mask this one sees the whole file, so a block
 * comment spanning fifty lines is masked exactly and no line has to be
 * refused for merely LOOKING like prose.
 *
 * #define is deliberately left as code while every other directive is
 * masked out. The bound that made an index hold exactly 32 keys is usually a
 * #define, and mutating it is the highest-signal boundary mutant in the set;
 * mutating `#include <stdio.h>` or `#if defined(__linux__)` is pure noise. */
static bool mask_ident_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
}

/* Is the directive starting at `hash` a #define? Spaces are allowed between
 * the '#' and the keyword, which real code does write. */
static bool mask_is_define(const char *t, size_t len, size_t hash)
{
    size_t i = hash + 1;
    while (i < len && (t[i] == ' ' || t[i] == '\t'))
        i++;
    static const char kw[] = "define";
    size_t n = sizeof(kw) - 1;
    if (i + n > len || memcmp(t + i, kw, n) != 0)
        return false;
    return i + n == len || !mask_ident_char(t[i + n]);
}

static void mut_code_mask(const char *t, size_t len, unsigned char *mask)
{
    enum { NORMAL, LINE_COMMENT, BLOCK_COMMENT, STRING, CHARLIT, DIRECTIVE };
    int state = NORMAL;
    int resume = NORMAL; /* where a block comment returns to */
    bool at_line_start = true;
    for (size_t i = 0; i < len; i++) {
        char c = t[i];
        mask[i] = 0;
        switch (state) {
        case NORMAL:
            if (at_line_start && c == '#') {
                /* #define stays code from the keyword onward; the directive
                 * token itself is masked so `define` is never a site. */
                if (mask_is_define(t, len, i)) {
                    size_t j = i + 1;
                    while (j < len && (t[j] == ' ' || t[j] == '\t'))
                        j++;
                    i = j + 5; /* last byte of "define" */
                    at_line_start = false;
                    continue;
                }
                state = DIRECTIVE;
                continue;
            }
            if (c == '/' && i + 1 < len && t[i + 1] == '/') {
                state = LINE_COMMENT;
                continue;
            }
            if (c == '/' && i + 1 < len && t[i + 1] == '*') {
                resume = NORMAL;
                state = BLOCK_COMMENT;
                i++;
                continue;
            }
            if (c == '"') {
                state = STRING;
                continue;
            }
            if (c == '\'') {
                state = CHARLIT;
                continue;
            }
            if (c == '\n') {
                at_line_start = true;
                continue;
            }
            if (c != ' ' && c != '\t' && c != '\r')
                at_line_start = false;
            mask[i] = 1;
            continue;
        case LINE_COMMENT:
            if (c == '\n') {
                /* A `//` comment continued with a trailing backslash keeps
                 * going; C says so and a mutation past that point would be
                 * inside comment text. */
                if (i == 0 || t[i - 1] != '\\') {
                    state = NORMAL;
                    at_line_start = true;
                }
            }
            continue;
        case BLOCK_COMMENT:
            if (c == '*' && i + 1 < len && t[i + 1] == '/') {
                i++;
                state = resume;
            }
            continue;
        case STRING:
            if (c == '\\' && i + 1 < len)
                i++;
            else if (c == '"')
                state = NORMAL;
            continue;
        case CHARLIT:
            if (c == '\\' && i + 1 < len)
                i++;
            else if (c == '\'')
                state = NORMAL;
            continue;
        case DIRECTIVE:
        default:
            if (c == '/' && i + 1 < len && t[i + 1] == '*') {
                resume = DIRECTIVE;
                state = BLOCK_COMMENT;
                i++;
            } else if (c == '\n' && (i == 0 || t[i - 1] != '\\')) {
                state = NORMAL;
                at_line_start = true;
            }
            continue;
        }
    }
}

/* ── site emission ───────────────────────────────────────────────────── */

struct mut_scan {
    const char *text;
    size_t len;
    const unsigned char *mask;
    struct zcl_mut_site *out;
    size_t cap;
    size_t found;
    size_t line;      /* 1-based line of the cursor */
    size_t line_start;/* offset of the cursor's line */
};

static void mut_copy_text(char *dst, size_t cap, const char *src, size_t n)
{
    if (n + 1 <= cap) {
        memcpy(dst, src, n);
        dst[n] = '\0';
        return;
    }
    /* Elide from the middle-right so both ends of a long `return` stay
     * readable in the survivor list, which is what a human acts on. */
    size_t keep = cap - 4;
    memcpy(dst, src, keep);
    memcpy(dst + keep, "...", 4);
}

static void mut_emit(struct mut_scan *s, size_t offset, size_t span,
                     enum zcl_mut_class cls, const char *rule,
                     const char *after)
{
    if (s->found < s->cap) {
        struct zcl_mut_site *site = &s->out[s->found];
        memset(site, 0, sizeof *site);
        site->offset = offset;
        site->span = span;
        site->line = s->line;
        site->column = offset - s->line_start + 1;
        site->cls = cls;
        (void)snprintf(site->rule, sizeof site->rule, "%s", rule);
        mut_copy_text(site->before, sizeof site->before, s->text + offset, span);
        (void)snprintf(site->after, sizeof site->after, "%s", after);
    }
    s->found++;
}

/* ── operator: relational and logical ───────────────────────────────── */

struct mut_pair {
    const char *from;
    const char *to;
    const char *rule;
    enum zcl_mut_class cls;
};

/* Two-character tokens first: at the '<' of "<=" the one-character rule
 * would otherwise fire and produce "<==". */
static const struct mut_pair g_pairs2[] = {
    { "==", "!=", "eq_to_ne", ZCL_MUT_CLASS_RELATIONAL },
    { "!=", "==", "ne_to_eq", ZCL_MUT_CLASS_RELATIONAL },
    { "<=", "<",  "le_to_lt", ZCL_MUT_CLASS_RELATIONAL },
    { ">=", ">",  "ge_to_gt", ZCL_MUT_CLASS_RELATIONAL },
    { "&&", "||", "and_to_or", ZCL_MUT_CLASS_LOGICAL },
    { "||", "&&", "or_to_and", ZCL_MUT_CLASS_LOGICAL },
};

/* A two-char operator only fires when it is a token on its own. `<<=`,
 * `>>=`, `&&&` and every compound assignment ending in `=` would turn into
 * a syntax error, which reports as "the compiler noticed" and teaches
 * nothing about any test. */
static bool mut_pair2_ok(const char *t, size_t len, size_t i, const char *from)
{
    char prev = i > 0 ? t[i - 1] : '\0';
    char next = i + 2 < len ? t[i + 2] : '\0';
    if (from[0] == '<' && prev == '<')
        return false;
    if (from[0] == '>' && (prev == '>' || prev == '-'))
        return false;
    if (from[0] == '&' && (prev == '&' || next == '&'))
        return false;
    if (from[0] == '|' && (prev == '|' || next == '|'))
        return false;
    if (from[1] == '=' && next == '=')
        return false;
    if (from[0] == '=' && strchr("!<>=+-*/%&|^~", prev) != NULL)
        return false;
    return true;
}

/* `!` is a unary operator only where an expression may start. Anywhere else
 * the character is part of `!=`, which the two-char table already owns. */
static bool mut_not_is_unary(const char *t, size_t len, size_t i)
{
    if (i + 1 < len && t[i + 1] == '=')
        return false;
    size_t j = i;
    while (j > 0) {
        char p = t[j - 1];
        if (p == ' ' || p == '\t' || p == '\n' || p == '\r') {
            j--;
            continue;
        }
        /* After a value, `!` cannot be a prefix — and a value is exactly
         * what these characters end. */
        if (mask_ident_char(p) || p == ')' || p == ']' || p == '.')
            return false;
        return true;
    }
    return true;
}

/* ── operator: integer boundary ─────────────────────────────────────── */

/* Length of a plain decimal integer literal starting at `i`, or 0. Hex,
 * binary, octal and float parts are all rejected: `0xff` is a mask and
 * `0755` is a mode, and bumping either models no defect anyone has. */
static size_t mut_decimal_at(const char *t, size_t len, size_t i)
{
    if (t[i] < '0' || t[i] > '9')
        return 0;
    if (i > 0 && (mask_ident_char(t[i - 1]) || t[i - 1] == '.'))
        return 0;
    size_t n = 0;
    while (i + n < len && t[i + n] >= '0' && t[i + n] <= '9')
        n++;
    if (n > 18)
        return 0; /* would not survive the +1 in unsigned long long */
    if (n > 1 && t[i] == '0')
        return 0; /* octal, or 0x/0b already rejected below */
    size_t j = i + n;
    if (j < len && (t[j] == '.' || t[j] == 'x' || t[j] == 'X' ||
                    t[j] == 'b' || t[j] == 'B' || t[j] == 'e' || t[j] == 'E'))
        return 0;
    /* An integer suffix is fine and is left in place: only the digits are
     * replaced, so `1ull` becomes `2ull` and keeps its type. */
    while (j < len && strchr("uUlL", t[j]) != NULL)
        j++;
    if (j < len && (mask_ident_char(t[j]) || t[j] == '.'))
        return 0;
    return n;
}

/* ── operator: return substitution ──────────────────────────────────── */

/* Offset of the `;` ending the `return` statement at `i`, or SIZE_MAX.
 * Only depth-0 semicolons count, and only code bytes are inspected, so a
 * `;` inside a string literal in the returned expression is not the end. */
static size_t mut_return_end(const char *t, size_t len,
                             const unsigned char *mask, size_t i)
{
    int depth = 0;
    size_t limit = i + 4096 < len ? i + 4096 : len;
    for (size_t j = i + 6; j < limit; j++) {
        if (!mask[j])
            continue;
        char c = t[j];
        if (c == '(' || c == '[')
            depth++;
        else if (c == ')' || c == ']')
            depth--;
        else if (c == '{' || c == '}')
            return SIZE_MAX; /* a compound literal or a brace we do not own */
        else if (c == ';' && depth == 0)
            return j;
        if (depth < 0)
            return SIZE_MAX;
    }
    return SIZE_MAX;
}

/* The returned expression with surrounding blanks removed, for the two
 * "is the mutant already the original?" checks below. */
static void mut_return_expr(const char *t, size_t start, size_t end,
                            char *out, size_t cap)
{
    size_t a = start + 6, b = end;
    while (a < b && isspace((unsigned char)t[a]))
        a++;
    while (b > a && isspace((unsigned char)t[b - 1]))
        b--;
    size_t n = b - a;
    if (n >= cap)
        n = cap - 1;
    memcpy(out, t + a, n);
    out[n] = '\0';
}

/* ── operator: statement deletion ───────────────────────────────────── */

/* Is [start,end] a call statement whose value nobody reads? That is the
 * only statement this deletes: `f(x);`, `(void)g(y);`, `memcpy(a, b, n);`.
 * A declaration, an assignment, a control statement or anything carrying a
 * top-level `=` or `,` is left alone, because deleting those produces an
 * uninitialised read the compiler rejects, and a stillborn mutant costs a
 * build and reports nothing. */
static const char *const g_stmt_keywords[] = {
    "if", "for", "while", "switch", "return", "do", "else", "case",
    "default", "goto", "break", "continue", "typedef", "sizeof",
};

static bool mut_is_call_statement(const char *t, size_t len,
                                  const unsigned char *mask, size_t start,
                                  size_t *end_out)
{
    (void)len;
    if (!(mask_ident_char(t[start]) || t[start] == '('))
        return false;
    size_t w = start;
    while (w < start + 16 && mask_ident_char(t[w]))
        w++;
    size_t wl = w - start;
    for (size_t k = 0; k < sizeof g_stmt_keywords / sizeof g_stmt_keywords[0]; k++) {
        const char *kw = g_stmt_keywords[k];
        if (wl == strlen(kw) && memcmp(t + start, kw, wl) == 0)
            return false;
    }
    /* A DECLARATION also ends in `);` — `bool f(int v);` — and deleting one
     * only ever produces a syntax error, which costs a build and reports
     * nothing. What separates the two is a second identifier before the
     * open paren: a call has one name, a declaration has a type and a name.
     */
    for (size_t j = start; j + 1 < start + 512 && t[j] && t[j] != '('; j++) {
        if ((t[j] == ' ' || t[j] == '\t') && mask_ident_char(t[j + 1]))
            return false;
        if (t[j] == ';' || t[j] == '\n')
            break;
    }

    int depth = 0;
    bool saw_call = false;
    size_t end = SIZE_MAX;
    size_t limit = start + 2048;
    for (size_t j = start; j < limit && t[j] != '\0'; j++) {
        if (!mask[j])
            continue;
        char c = t[j];
        if (c == '(' || c == '[') {
            depth++;
            saw_call = saw_call || c == '(';
        } else if (c == ')' || c == ']') {
            depth--;
            if (depth < 0)
                return false;
        } else if (c == '{' || c == '}') {
            return false;
        } else if (depth == 0 && (c == '=' || c == ',' || c == '?')) {
            return false;
        } else if (depth == 0 && c == ';') {
            end = j;
            break;
        }
    }
    if (end == SIZE_MAX || !saw_call)
        return false;
    /* The statement must END in a call: `)` immediately before the `;`,
     * ignoring blanks. `x++;` and `p->n;` are not writes worth deleting. */
    size_t b = end;
    while (b > start && isspace((unsigned char)t[b - 1]))
        b--;
    if (b == start || t[b - 1] != ')')
        return false;
    *end_out = end;
    return true;
}

/* ── the scan ───────────────────────────────────────────────────────── */

size_t zcl_mut_enumerate(const char *text, size_t len,
                         struct zcl_mut_site *out, size_t cap)
{
    if (!text || len == 0)
        return 0;
    unsigned char *mask = zcl_calloc(len, 1, "mutation.code_mask");
    if (!mask)
        return 0;
    mut_code_mask(text, len, mask);

    struct mut_scan s = { .text = text, .len = len, .mask = mask, .out = out,
                          .cap = out ? cap : 0, .found = 0, .line = 1,
                          .line_start = 0 };
    bool line_has_code = false;

    for (size_t i = 0; i < len; i++) {
        if (text[i] == '\n') {
            s.line++;
            s.line_start = i + 1;
            line_has_code = false;
            continue;
        }
        if (!mask[i])
            continue;
        /* Blanks carry no site, and skipping them here is what makes
         * "the first code byte of this line" mean the first NON-BLANK one,
         * which is where a statement starts. */
        if (text[i] == ' ' || text[i] == '\t' || text[i] == '\r')
            continue;

        /* statement deletion, at the first code byte of a line only */
        if (!line_has_code) {
            size_t end = 0;
            if (mut_is_call_statement(text, len, mask, i, &end))
                mut_emit(&s, i, end - i + 1, ZCL_MUT_CLASS_STATEMENT,
                         "stmt_delete", "(void)0;");
        }
        line_has_code = true;

        /* two-character comparison and connective flips */
        bool matched = false;
        for (size_t p = 0; p < sizeof g_pairs2 / sizeof g_pairs2[0]; p++) {
            const struct mut_pair *r = &g_pairs2[p];
            if (i + 1 >= len || !mask[i + 1])
                break;
            if (text[i] != r->from[0] || text[i + 1] != r->from[1])
                continue;
            if (!mut_pair2_ok(text, len, i, r->from))
                continue;
            mut_emit(&s, i, 2, r->cls, r->rule, r->to);
            matched = true;
            break;
        }
        if (matched)
            continue;

        /* one-character comparison widenings */
        char c = text[i];
        char next = i + 1 < len ? text[i + 1] : '\0';
        char prev = i > 0 ? text[i - 1] : '\0';
        if (c == '<' && next != '<' && next != '=' && prev != '<') {
            mut_emit(&s, i, 1, ZCL_MUT_CLASS_RELATIONAL, "lt_to_le", "<=");
            continue;
        }
        if (c == '>' && next != '>' && next != '=' && prev != '>' &&
            prev != '-') {
            mut_emit(&s, i, 1, ZCL_MUT_CLASS_RELATIONAL, "gt_to_ge", ">=");
            continue;
        }
        if (c == '!' && mut_not_is_unary(text, len, i)) {
            mut_emit(&s, i, 1, ZCL_MUT_CLASS_LOGICAL, "drop_not", "");
            continue;
        }

        /* keywords: return / true / false */
        bool word_start = i == 0 || !mask_ident_char(prev);
        if (word_start) {
            if (i + 4 <= len && memcmp(text + i, "true", 4) == 0 &&
                (i + 4 == len || !mask_ident_char(text[i + 4]))) {
                mut_emit(&s, i, 4, ZCL_MUT_CLASS_LOGICAL, "true_to_false",
                         "false");
                continue;
            }
            if (i + 5 <= len && memcmp(text + i, "false", 5) == 0 &&
                (i + 5 == len || !mask_ident_char(text[i + 5]))) {
                mut_emit(&s, i, 5, ZCL_MUT_CLASS_LOGICAL, "false_to_true",
                         "true");
                continue;
            }
            if (i + 6 <= len && memcmp(text + i, "return", 6) == 0 &&
                (i + 6 == len || !mask_ident_char(text[i + 6]))) {
                size_t end = mut_return_end(text, len, mask, i);
                if (end != SIZE_MAX && end > i + 6) {
                    char expr[64];
                    mut_return_expr(text, i, end, expr, sizeof expr);
                    if (expr[0] != '\0') {
                        if (strcmp(expr, "true") != 0)
                            mut_emit(&s, i, end - i + 1, ZCL_MUT_CLASS_RETURN,
                                     "ret_true", "return true;");
                        if (strcmp(expr, "0") != 0)
                            mut_emit(&s, i, end - i + 1, ZCL_MUT_CLASS_RETURN,
                                     "ret_zero", "return 0;");
                    }
                }
                /* deliberately no `continue`: the returned expression is
                 * still scanned, so `return a > b;` also yields gt_to_ge */
            }
        }

        /* integer boundary, both directions */
        size_t digits = mut_decimal_at(text, len, i);
        if (digits > 0) {
            char buf[32];
            memcpy(buf, text + i, digits);
            buf[digits] = '\0';
            unsigned long long v = strtoull(buf, NULL, 10);
            char after[32];
            (void)snprintf(after, sizeof after, "%llu", v + 1ull);
            mut_emit(&s, i, digits, ZCL_MUT_CLASS_BOUNDARY, "int_inc", after);
            if (v >= 1ull) {
                (void)snprintf(after, sizeof after, "%llu", v - 1ull);
                mut_emit(&s, i, digits, ZCL_MUT_CLASS_BOUNDARY, "int_dec",
                         after);
            }
            i += digits - 1;
            continue;
        }
    }
    free(mask);
    return s.found;
}

bool zcl_mut_apply(const char *text, size_t len, const struct zcl_mut_site *s,
                   char **out, size_t *out_len)
{
    if (!text || !s || !out || !out_len)
        return false;
    *out = NULL;
    *out_len = 0;
    if (s->offset > len || s->span > len - s->offset)
        return false;
    size_t after_len = strlen(s->after);
    size_t total = len - s->span + after_len;
    char *buf = zcl_malloc(total + 1, "mutation.image");
    if (!buf)
        return false;
    memcpy(buf, text, s->offset);
    memcpy(buf + s->offset, s->after, after_len);
    memcpy(buf + s->offset + after_len, text + s->offset + s->span,
           len - s->offset - s->span);
    buf[total] = '\0';
    *out = buf;
    *out_len = total;
    return true;
}
