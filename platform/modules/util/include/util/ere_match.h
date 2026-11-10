/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: bounded POSIX extended-regular-expression matching, in-tree.
 *
 * The node's operator-facing log search promises POSIX-extended regex.
 * Borrowing that from the platform's libc <regex.h> made the promise
 * unkeepable: the header does not exist on Windows, and the project rule is
 * that the node writes its own C rather than depending on what a host
 * happens to ship. This is that implementation.
 *
 * It is a Thompson NFA simulation, not a backtracking matcher: the whole
 * current state set advances one input byte at a time, so matching is
 * O(text * states) with no exponential case. That matters because the
 * pattern arrives over RPC, and the bound here is structural rather than a
 * property of one libc's optimizer. Every dimension is fixed at compile time
 * (states, character classes, nesting depth, repetition counts), and a
 * pattern that would exceed one is REFUSED with a message rather than
 * silently matched or silently truncated.
 *
 * Matching is over bytes, and the character classes are the C locale's, so
 * a log line that is not valid UTF-8 still matches predictably.
 *
 * Supported, matching POSIX ERE (verified against glibc regcomp/regexec in
 * tests/harness/src/test_rpc.c):
 *   literals, '.', '*', '+', '?', '{n}', '{n,}', '{n,m}', concatenation,
 *   '|' alternation, '(...)' grouping, '^' and '$' anchors, bracket
 *   expressions with ranges, negation and [:name:] character classes, and
 *   '\' escaping of a punctuation metacharacter. A search is unanchored.
 *
 * Deliberately refused, each with its own message, so a pattern that used to
 * work cannot silently change meaning:
 *   '\' before a letter or digit (the GNU \w \s \b extensions — POSIX leaves
 *   these undefined and treating them as literals would silently match the
 *   wrong lines), collating symbols '[. .]', and equivalence classes
 *   '[= =]'.
 */

#ifndef ZCL_UTIL_ERE_MATCH_H
#define ZCL_UTIL_ERE_MATCH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum {
    ZCL_ERE_MAX_PATTERN = 1024,
    ZCL_ERE_MAX_STATES = 1024,
    ZCL_ERE_MAX_CLASSES = 64,
    ZCL_ERE_MAX_DEPTH = 64,
    ZCL_ERE_MAX_REPEAT = 64,
    ZCL_ERE_ERROR_SIZE = 96,
};

enum zcl_ere_op {
    ZCL_ERE_OP_CHAR = 0, /* consumes one byte equal to `ch` */
    ZCL_ERE_OP_ANY,      /* consumes any one byte */
    ZCL_ERE_OP_CLASS,    /* consumes one byte in class `cls` */
    ZCL_ERE_OP_SPLIT,    /* epsilon to both `out` and `out1` */
    ZCL_ERE_OP_JUMP,     /* epsilon to `out` */
    ZCL_ERE_OP_BOL,      /* epsilon to `out` only at offset 0 */
    ZCL_ERE_OP_EOL,      /* epsilon to `out` only at end of text */
    ZCL_ERE_OP_MATCH,    /* accept */
};

struct zcl_ere_state {
    uint8_t op;
    uint8_t ch;
    int16_t cls;
    int32_t out;
    int32_t out1;
};

/* One compiled pattern plus its simulation scratch. About 30 KB: allocate it,
 * do not put it on a thread stack. */
struct zcl_ere {
    struct zcl_ere_state states[ZCL_ERE_MAX_STATES];
    uint32_t classes[ZCL_ERE_MAX_CLASSES][8];
    int32_t visit[ZCL_ERE_MAX_STATES];
    int32_t current[ZCL_ERE_MAX_STATES];
    int32_t next[ZCL_ERE_MAX_STATES];
    int32_t work[2 * ZCL_ERE_MAX_STATES + 2];
    int32_t count;
    int32_t class_count;
    int32_t start;
    int32_t generation;
    bool compiled;
    char error[ZCL_ERE_ERROR_SIZE];
};

struct zcl_ere_fragment {
    int32_t entry;
    int32_t exit; /* always a JUMP whose `out` is still unset */
};

struct zcl_ere_parser {
    const char *pattern;
    size_t length;
    size_t pos;
    int depth;
    bool failed;
    struct zcl_ere *re;
};

static inline void zcl_ere_fail(struct zcl_ere_parser *ps, const char *message)
{
    if (!ps->failed) {
        ps->failed = true;
        snprintf(ps->re->error, sizeof(ps->re->error), "%s", message);
    }
}

static inline void zcl_ere_fail_at(struct zcl_ere_parser *ps,
                                   const char *message, char subject)
{
    if (!ps->failed) {
        ps->failed = true;
        snprintf(ps->re->error, sizeof(ps->re->error), "%s '%c'", message,
                 subject >= 0x20 && subject < 0x7f ? subject : '?');
    }
}

static inline int32_t zcl_ere_new_state(struct zcl_ere_parser *ps, uint8_t op)
{
    if (ps->re->count >= ZCL_ERE_MAX_STATES) {
        zcl_ere_fail(ps, "pattern too complex");
        return -1;
    }
    int32_t index = ps->re->count++;
    ps->re->states[index].op = op;
    ps->re->states[index].ch = 0;
    ps->re->states[index].cls = -1;
    ps->re->states[index].out = -1;
    ps->re->states[index].out1 = -1;
    return index;
}

/* An empty fragment: matches the empty string and nothing else. */
static inline struct zcl_ere_fragment zcl_ere_empty(struct zcl_ere_parser *ps)
{
    int32_t jump = zcl_ere_new_state(ps, ZCL_ERE_OP_JUMP);
    struct zcl_ere_fragment fragment = {.entry = jump, .exit = jump};
    return fragment;
}

static inline struct zcl_ere_fragment zcl_ere_consumer(
    struct zcl_ere_parser *ps, uint8_t op, unsigned char ch, int32_t cls)
{
    int32_t state = zcl_ere_new_state(ps, op);
    int32_t jump = zcl_ere_new_state(ps, ZCL_ERE_OP_JUMP);
    if (state >= 0 && jump >= 0) {
        ps->re->states[state].ch = ch;
        ps->re->states[state].cls = (int16_t)cls;
        ps->re->states[state].out = jump;
    }
    struct zcl_ere_fragment fragment = {.entry = state, .exit = jump};
    return fragment;
}

static inline struct zcl_ere_fragment zcl_ere_concat(
    struct zcl_ere_parser *ps, struct zcl_ere_fragment a,
    struct zcl_ere_fragment b)
{
    if (a.exit >= 0)
        ps->re->states[a.exit].out = b.entry;
    struct zcl_ere_fragment fragment = {.entry = a.entry, .exit = b.exit};
    return fragment;
}

static inline struct zcl_ere_fragment zcl_ere_alternate(
    struct zcl_ere_parser *ps, struct zcl_ere_fragment a,
    struct zcl_ere_fragment b)
{
    int32_t split = zcl_ere_new_state(ps, ZCL_ERE_OP_SPLIT);
    int32_t jump = zcl_ere_new_state(ps, ZCL_ERE_OP_JUMP);
    if (split >= 0 && jump >= 0) {
        ps->re->states[split].out = a.entry;
        ps->re->states[split].out1 = b.entry;
        if (a.exit >= 0) ps->re->states[a.exit].out = jump;
        if (b.exit >= 0) ps->re->states[b.exit].out = jump;
    }
    struct zcl_ere_fragment fragment = {.entry = split, .exit = jump};
    return fragment;
}

static inline struct zcl_ere_fragment zcl_ere_star(
    struct zcl_ere_parser *ps, struct zcl_ere_fragment a)
{
    int32_t split = zcl_ere_new_state(ps, ZCL_ERE_OP_SPLIT);
    int32_t jump = zcl_ere_new_state(ps, ZCL_ERE_OP_JUMP);
    if (split >= 0 && jump >= 0) {
        ps->re->states[split].out = a.entry;
        ps->re->states[split].out1 = jump;
        if (a.exit >= 0) ps->re->states[a.exit].out = split;
    }
    struct zcl_ere_fragment fragment = {.entry = split, .exit = jump};
    return fragment;
}

static inline struct zcl_ere_fragment zcl_ere_plus(
    struct zcl_ere_parser *ps, struct zcl_ere_fragment a)
{
    int32_t split = zcl_ere_new_state(ps, ZCL_ERE_OP_SPLIT);
    int32_t jump = zcl_ere_new_state(ps, ZCL_ERE_OP_JUMP);
    if (split >= 0 && jump >= 0) {
        ps->re->states[split].out = a.entry;
        ps->re->states[split].out1 = jump;
        if (a.exit >= 0) ps->re->states[a.exit].out = split;
    }
    struct zcl_ere_fragment fragment = {.entry = a.entry, .exit = jump};
    return fragment;
}

static inline struct zcl_ere_fragment zcl_ere_optional(
    struct zcl_ere_parser *ps, struct zcl_ere_fragment a)
{
    int32_t split = zcl_ere_new_state(ps, ZCL_ERE_OP_SPLIT);
    int32_t jump = zcl_ere_new_state(ps, ZCL_ERE_OP_JUMP);
    if (split >= 0 && jump >= 0) {
        ps->re->states[split].out = a.entry;
        ps->re->states[split].out1 = jump;
        if (a.exit >= 0) ps->re->states[a.exit].out = jump;
    }
    struct zcl_ere_fragment fragment = {.entry = split, .exit = jump};
    return fragment;
}

static inline void zcl_ere_class_set(uint32_t bits[8], unsigned char value)
{
    bits[value >> 5] |= 1u << (value & 31u);
}

enum zcl_ere_class {
    ZCL_ERE_ALPHA, ZCL_ERE_ALNUM, ZCL_ERE_DIGIT, ZCL_ERE_UPPER,
    ZCL_ERE_LOWER, ZCL_ERE_SPACE, ZCL_ERE_BLANK, ZCL_ERE_PRINT,
    ZCL_ERE_GRAPH, ZCL_ERE_PUNCT, ZCL_ERE_CNTRL, ZCL_ERE_XDIGIT,
    ZCL_ERE_UNKNOWN
};

static inline enum zcl_ere_class zcl_ere_class_lookup(const char *name, size_t len)
{
    static const char *const names[] = {
        "alpha", "alnum", "digit", "upper", "lower", "space", "blank",
        "print", "graph", "punct", "cntrl", "xdigit"
    };
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++)
        if (strlen(names[i]) == len && memcmp(name, names[i], len) == 0)
            return (enum zcl_ere_class)i;
    return ZCL_ERE_UNKNOWN;
}

static inline bool zcl_ere_class_letter(enum zcl_ere_class cls, unsigned char c)
{
    bool upper = c >= 'A' && c <= 'Z';
    bool lower = c >= 'a' && c <= 'z';
    bool digit = c >= '0' && c <= '9';
    switch (cls) {
    case ZCL_ERE_ALPHA: return upper || lower;
    case ZCL_ERE_ALNUM: return upper || lower || digit;
    case ZCL_ERE_DIGIT: return digit;
    case ZCL_ERE_UPPER: return upper;
    case ZCL_ERE_LOWER: return lower;
    default: return false;
    }
}

static inline bool zcl_ere_class_xdigit(unsigned char c)
{
    return zcl_ere_class_letter(ZCL_ERE_DIGIT, c) ||
           (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static inline bool zcl_ere_class_other(enum zcl_ere_class cls, unsigned char c)
{
    bool print = c >= 0x20 && c <= 0x7e;
    switch (cls) {
    case ZCL_ERE_SPACE: return c == ' ' || (c >= 0x09 && c <= 0x0d);
    case ZCL_ERE_BLANK: return c == ' ' || c == '\t';
    case ZCL_ERE_PRINT: return print;
    case ZCL_ERE_GRAPH: return print && c != ' ';
    case ZCL_ERE_PUNCT:
        return print && c != ' ' && !zcl_ere_class_letter(ZCL_ERE_ALNUM, c);
    case ZCL_ERE_CNTRL: return c < 0x20 || c == 0x7f;
    default: return false;
    }
}

static inline bool zcl_ere_class_named(uint32_t bits[8], const char *name,
                                       size_t name_len)
{
    enum zcl_ere_class cls = zcl_ere_class_lookup(name, name_len);
    if (cls == ZCL_ERE_UNKNOWN) return false;
    for (int value = 0; value < 256; value++) {
        unsigned char c = (unsigned char)value;
        if (zcl_ere_class_letter(cls, c) || zcl_ere_class_other(cls, c) ||
            (cls == ZCL_ERE_XDIGIT && zcl_ere_class_xdigit(c)))
            zcl_ere_class_set(bits, c);
    }
    return true;
}

static inline bool zcl_ere_bracket_named(struct zcl_ere_parser *ps, uint32_t bits[8])
{
    size_t name_start = ps->pos + 2;
    size_t scan = name_start;
    while (scan + 1 < ps->length &&
           !(ps->pattern[scan] == ':' && ps->pattern[scan + 1] == ']'))
        scan++;
    if (scan + 1 >= ps->length) {
        zcl_ere_fail(ps, "unterminated character class name");
        return false;
    }
    if (!zcl_ere_class_named(bits, ps->pattern + name_start, scan - name_start)) {
        zcl_ere_fail(ps, "unknown character class name");
        return false;
    }
    ps->pos = scan + 2;
    return true;
}

static inline bool zcl_ere_bracket_member(struct zcl_ere_parser *ps,
                                           uint32_t bits[8], unsigned char c)
{
    ps->pos++;
    if (ps->pos + 1 < ps->length && ps->pattern[ps->pos] == '-' &&
        ps->pattern[ps->pos + 1] != ']') {
        ps->pos++;
        unsigned char high = (unsigned char)ps->pattern[ps->pos];
        ps->pos++;
        if (high < c) {
            zcl_ere_fail(ps, "invalid range end in bracket expression");
            return false;
        }
        for (unsigned value = c; value <= high; value++)
            zcl_ere_class_set(bits, (unsigned char)value);
    } else {
        zcl_ere_class_set(bits, c);
    }
    return true;
}

static inline struct zcl_ere_fragment zcl_ere_bracket_finish(
    struct zcl_ere_parser *ps, uint32_t bits[8], bool negate)
{
    if (negate)
        for (int i = 0; i < 8; i++) bits[i] = ~bits[i];
    for (int32_t i = 0; i < ps->re->class_count; i++)
        if (memcmp(ps->re->classes[i], bits, sizeof(ps->re->classes[i])) == 0)
            return zcl_ere_consumer(ps, ZCL_ERE_OP_CLASS, 0, i);
    if (ps->re->class_count >= ZCL_ERE_MAX_CLASSES) {
        zcl_ere_fail(ps, "too many distinct bracket expressions");
        return zcl_ere_empty(ps);
    }
    int32_t cls = ps->re->class_count++;
    memcpy(ps->re->classes[cls], bits, sizeof(ps->re->classes[cls]));
    return zcl_ere_consumer(ps, ZCL_ERE_OP_CLASS, 0, cls);
}

static inline bool zcl_ere_bracket_unsupported(struct zcl_ere_parser *ps,
                                                unsigned char c)
{
    return c == '[' && ps->pos + 1 < ps->length &&
           (ps->pattern[ps->pos + 1] == '.' || ps->pattern[ps->pos + 1] == '=');
}

static inline struct zcl_ere_fragment zcl_ere_parse_bracket(
    struct zcl_ere_parser *ps)
{
    uint32_t bits[8] = {0};
    bool negate = false;
    bool first = true;
    ps->pos++; /* consume '[' */
    if (ps->pos < ps->length && ps->pattern[ps->pos] == '^') {
        negate = true;
        ps->pos++;
    }
    for (;;) {
        if (ps->pos >= ps->length) {
            zcl_ere_fail(ps, "unterminated bracket expression");
            return zcl_ere_empty(ps);
        }
        unsigned char c = (unsigned char)ps->pattern[ps->pos];
        if (c == ']' && !first) {
            ps->pos++;
            break;
        }
        first = false;
        if (zcl_ere_bracket_unsupported(ps, c)) {
            zcl_ere_fail(ps, "collating symbols and equivalence classes are "
                             "not supported");
            return zcl_ere_empty(ps);
        }
        if (c == '[' && ps->pos + 1 < ps->length &&
            ps->pattern[ps->pos + 1] == ':') {
            if (!zcl_ere_bracket_named(ps, bits))
                return zcl_ere_empty(ps);
            continue;
        }
        /* A '-' is a range only between two members; trailing '-' is a
         * literal, matching POSIX and glibc. Backslash is NOT an escape
         * inside a bracket expression: POSIX makes it an ordinary member. */
        if (!zcl_ere_bracket_member(ps, bits, c)) return zcl_ere_empty(ps);
    }
    /* Counted repetition re-parses its unit, so the same bracket expression
     * arrives once per copy. Share one table entry for equal sets. */
    return zcl_ere_bracket_finish(ps, bits, negate);
}

static inline struct zcl_ere_fragment zcl_ere_parse_alternation(
    struct zcl_ere_parser *ps);

static inline struct zcl_ere_fragment zcl_ere_parse_group(struct zcl_ere_parser *ps)
{
    if (ps->depth >= ZCL_ERE_MAX_DEPTH) {
        zcl_ere_fail(ps, "pattern nests too deeply");
        return zcl_ere_empty(ps);
    }
    ps->pos++;
    ps->depth++;
    struct zcl_ere_fragment inner = zcl_ere_parse_alternation(ps);
    ps->depth--;
    if (ps->failed) return inner;
    if (ps->pos >= ps->length || ps->pattern[ps->pos] != ')') {
        zcl_ere_fail(ps, "unmatched '('");
        return inner;
    }
    ps->pos++;
    return inner;
}

static inline struct zcl_ere_fragment zcl_ere_parse_escape(struct zcl_ere_parser *ps)
{
    ps->pos++;
    if (ps->pos >= ps->length) {
        zcl_ere_fail(ps, "trailing backslash");
        return zcl_ere_empty(ps);
    }
    unsigned char escaped = (unsigned char)ps->pattern[ps->pos];
    if ((escaped >= 'a' && escaped <= 'z') ||
        (escaped >= 'A' && escaped <= 'Z') ||
        (escaped >= '0' && escaped <= '9')) {
        zcl_ere_fail_at(ps, "unsupported escape after backslash", (char)escaped);
        return zcl_ere_empty(ps);
    }
    ps->pos++;
    return zcl_ere_consumer(ps, ZCL_ERE_OP_CHAR, escaped, -1);
}

static inline struct zcl_ere_fragment zcl_ere_parse_atom(
    struct zcl_ere_parser *ps)
{
    if (ps->failed || ps->pos >= ps->length)
        return zcl_ere_empty(ps);
    char c = ps->pattern[ps->pos];
    switch (c) {
    case '(': return zcl_ere_parse_group(ps);
    case '[':
        return zcl_ere_parse_bracket(ps);
    case '.':
        ps->pos++;
        return zcl_ere_consumer(ps, ZCL_ERE_OP_ANY, 0, -1);
    case '^':
        ps->pos++;
        return zcl_ere_consumer(ps, ZCL_ERE_OP_BOL, 0, -1);
    case '$':
        ps->pos++;
        return zcl_ere_consumer(ps, ZCL_ERE_OP_EOL, 0, -1);
    case '*':
    case '+':
    case '?':
    case '{':
        zcl_ere_fail_at(ps, "invalid preceding regular expression before", c);
        return zcl_ere_empty(ps);
    case ')':
        zcl_ere_fail(ps, "unmatched ')'");
        return zcl_ere_empty(ps);
    case '\\': return zcl_ere_parse_escape(ps);
    default:
        ps->pos++;
        return zcl_ere_consumer(ps, ZCL_ERE_OP_CHAR, (unsigned char)c, -1);
    }
}

/* An interval is `{n}`, `{n,}`, `{n,m}` or `{,m}` (which is `{0,m}`). Once a
 * '{' follows an expression it always starts an interval: malformed content
 * is an error, not a literal brace, which is what glibc does. A literal brace
 * is written `\{`. */
static inline bool zcl_ere_interval_number(struct zcl_ere_parser *ps,
                                            size_t *scan, int *value, int *digits)
{
    *value = 0;
    *digits = 0;
    while (*scan < ps->length && ps->pattern[*scan] >= '0' &&
           ps->pattern[*scan] <= '9') {
        *value = *value * 10 + (ps->pattern[*scan] - '0');
        if (*value > ZCL_ERE_MAX_REPEAT) {
            zcl_ere_fail(ps, "repetition count above the supported bound");
            return false;
        }
        (*digits)++;
        (*scan)++;
    }
    return true;
}

static inline bool zcl_ere_parse_interval(struct zcl_ere_parser *ps, int *low,
                                          int *high, size_t *after)
{
    size_t scan = ps->pos + 1;
    int lo, digits;
    if (!zcl_ere_interval_number(ps, &scan, &lo, &digits)) return false;
    if (digits == 0 && (scan >= ps->length || ps->pattern[scan] != ',')) {
        zcl_ere_fail(ps, "invalid content of '{}'");
        return false;
    }
    int hi = lo;
    if (scan < ps->length && ps->pattern[scan] == ',') {
        scan++;
        if (scan < ps->length && ps->pattern[scan] == '}') {
            hi = -1;
        } else {
            if (!zcl_ere_interval_number(ps, &scan, &hi, &digits)) return false;
            if (digits == 0) {
                zcl_ere_fail(ps, "missing repetition bound");
                return false;
            }
        }
    }
    if (scan >= ps->length || ps->pattern[scan] != '}') {
        zcl_ere_fail(ps, "unmatched '{'");
        return false;
    }
    if (hi >= 0 && hi < lo) {
        zcl_ere_fail(ps, "repetition bounds are inverted");
        return false;
    }
    *low = lo;
    *high = hi;
    *after = scan + 1;
    return true;
}

static inline struct zcl_ere_fragment zcl_ere_parse_repeat(
    struct zcl_ere_parser *ps);

/* Rebuild one already-parsed repeat unit by parsing its source span again.
 * Counted repetition needs N independent copies of the unit's states, and
 * re-parsing is the copy: it needs no state renumbering, and it handles a
 * unit that is itself quantified (`a{2}{3}`) without a special case. */
static inline struct zcl_ere_fragment zcl_ere_reparse(
    struct zcl_ere_parser *ps, size_t start, size_t end)
{
    struct zcl_ere_parser sub = {
        .pattern = ps->pattern,
        .length = end,
        .pos = start,
        .depth = ps->depth,
        .failed = false,
        .re = ps->re,
    };
    struct zcl_ere_fragment fragment = zcl_ere_parse_repeat(&sub);
    if (sub.failed)
        ps->failed = true;
    return fragment;
}

static inline struct zcl_ere_fragment zcl_ere_build_interval(
    struct zcl_ere_parser *ps, size_t start, size_t end, int low, int high)
{
    struct zcl_ere_fragment result = zcl_ere_empty(ps);
    bool have_result = false;
    for (int i = 0; i < low && !ps->failed; i++) {
        struct zcl_ere_fragment copy = zcl_ere_reparse(ps, start, end);
        result = have_result ? zcl_ere_concat(ps, result, copy) : copy;
        have_result = true;
    }
    if (ps->failed)
        return result;
    if (high < 0) {
        struct zcl_ere_fragment tail =
            zcl_ere_star(ps, zcl_ere_reparse(ps, start, end));
        return have_result ? zcl_ere_concat(ps, result, tail) : tail;
    }
    /* The optional copies nest, so `a{1,3}` is a(a(a)?)? — a flat sequence of
     * independent optionals would also accept a gap in the middle. */
    struct zcl_ere_fragment tail = zcl_ere_empty(ps);
    bool have_tail = false;
    for (int i = 0; i < high - low && !ps->failed; i++) {
        struct zcl_ere_fragment copy = zcl_ere_reparse(ps, start, end);
        tail = zcl_ere_optional(
            ps, have_tail ? zcl_ere_concat(ps, copy, tail) : copy);
        have_tail = true;
    }
    if (!have_tail)
        return have_result ? result : tail;
    return have_result ? zcl_ere_concat(ps, result, tail) : tail;
}

static inline bool zcl_ere_repeat_anchor(struct zcl_ere_parser *ps,
                                         struct zcl_ere_fragment fragment)
{
    return !ps->failed && fragment.entry >= 0 &&
           (ps->re->states[fragment.entry].op == ZCL_ERE_OP_BOL ||
            ps->re->states[fragment.entry].op == ZCL_ERE_OP_EOL);
}

static inline struct zcl_ere_fragment zcl_ere_parse_repeat(
    struct zcl_ere_parser *ps)
{
    size_t unit_start = ps->pos;
    int32_t state_mark = ps->re->count;
    int32_t class_mark = ps->re->class_count;
    struct zcl_ere_fragment fragment = zcl_ere_parse_atom(ps);
    /* An anchor is not a repeatable expression; glibc refuses `^*` and `$?`
     * and so does this, rather than inventing a meaning for them. */
    bool anchor = zcl_ere_repeat_anchor(ps, fragment);
    while (!ps->failed && ps->pos < ps->length) {
        char c = ps->pattern[ps->pos];
        if (anchor && (c == '*' || c == '+' || c == '?' || c == '{')) {
            zcl_ere_fail_at(ps, "invalid preceding regular expression before",
                            c);
            break;
        }
        if (c == '*') {
            ps->pos++;
            fragment = zcl_ere_star(ps, fragment);
        } else if (c == '+') {
            ps->pos++;
            fragment = zcl_ere_plus(ps, fragment);
        } else if (c == '?') {
            ps->pos++;
            fragment = zcl_ere_optional(ps, fragment);
        } else if (c == '{') {
            int low = 0, high = 0;
            size_t after = 0;
            if (!zcl_ere_parse_interval(ps, &low, &high, &after))
                break;
            size_t unit_end = ps->pos;
            ps->re->count = state_mark;
            ps->re->class_count = class_mark;
            fragment = zcl_ere_build_interval(ps, unit_start, unit_end, low,
                                              high);
            ps->pos = after;
        } else {
            break;
        }
    }
    return fragment;
}

static inline struct zcl_ere_fragment zcl_ere_parse_concat(
    struct zcl_ere_parser *ps)
{
    struct zcl_ere_fragment result = zcl_ere_empty(ps);
    bool have_result = false;
    while (!ps->failed && ps->pos < ps->length && ps->pattern[ps->pos] != '|' &&
           ps->pattern[ps->pos] != ')') {
        struct zcl_ere_fragment piece = zcl_ere_parse_repeat(ps);
        result = have_result ? zcl_ere_concat(ps, result, piece) : piece;
        have_result = true;
    }
    return result;
}

static inline struct zcl_ere_fragment zcl_ere_parse_alternation(
    struct zcl_ere_parser *ps)
{
    struct zcl_ere_fragment result = zcl_ere_parse_concat(ps);
    while (!ps->failed && ps->pos < ps->length && ps->pattern[ps->pos] == '|') {
        ps->pos++;
        struct zcl_ere_fragment other = zcl_ere_parse_concat(ps);
        result = zcl_ere_alternate(ps, result, other);
    }
    return result;
}

/* Compile `pattern`. On false, zcl_ere_error() names the reason. */
static inline bool zcl_ere_compile(struct zcl_ere *re, const char *pattern)
{
    if (!re)
        return false;
    re->count = 0;
    re->class_count = 0;
    re->start = -1;
    re->generation = 0;
    re->compiled = false;
    re->error[0] = '\0';
    memset(re->visit, 0, sizeof(re->visit));
    if (!pattern) {
        snprintf(re->error, sizeof(re->error), "missing pattern");
        return false;
    }
    size_t length = strnlen(pattern, ZCL_ERE_MAX_PATTERN + 1u);
    if (length > ZCL_ERE_MAX_PATTERN) {
        snprintf(re->error, sizeof(re->error), "pattern too long");
        return false;
    }
    struct zcl_ere_parser ps = {
        .pattern = pattern,
        .length = length,
        .pos = 0,
        .depth = 0,
        .failed = false,
        .re = re,
    };
    struct zcl_ere_fragment fragment = zcl_ere_parse_alternation(&ps);
    if (!ps.failed && ps.pos != length)
        zcl_ere_fail_at(&ps, "unexpected", pattern[ps.pos]);
    int32_t accept = zcl_ere_new_state(&ps, ZCL_ERE_OP_MATCH);
    if (ps.failed || accept < 0 || fragment.entry < 0 || fragment.exit < 0) {
        if (re->error[0] == '\0')
            snprintf(re->error, sizeof(re->error), "pattern too complex");
        return false;
    }
    re->states[fragment.exit].out = accept;
    re->start = fragment.entry;
    re->compiled = true;
    return true;
}

static inline const char *zcl_ere_error(const struct zcl_ere *re)
{
    if (!re || re->error[0] == '\0')
        return "ok";
    return re->error;
}

/* Add `state` and its epsilon closure to `list`, evaluating the '^' and '$'
 * assertions at `pos`. Sets `matched` if the closure reaches accept. */
static inline void zcl_ere_add_split(struct zcl_ere *re, int32_t *top,
                                      int32_t capacity, const struct zcl_ere_state *s)
{
    if (*top + 2 <= capacity) {
        re->work[(*top)++] = s->out1;
        re->work[(*top)++] = s->out;
    }
}

static inline void zcl_ere_add(struct zcl_ere *re, int32_t *list, int32_t *n,
                               int32_t state, size_t pos, size_t length,
                               bool *matched)
{
    int32_t top = 0;
    int32_t capacity = (int32_t)(sizeof(re->work) / sizeof(re->work[0]));
    re->work[top++] = state;
    while (top > 0) {
        int32_t index = re->work[--top];
        if (index < 0 || index >= re->count || re->visit[index] == re->generation)
            continue;
        re->visit[index] = re->generation;
        const struct zcl_ere_state *s = &re->states[index];
        switch (s->op) {
        case ZCL_ERE_OP_SPLIT:
            zcl_ere_add_split(re, &top, capacity, s);
            break;
        case ZCL_ERE_OP_JUMP:
            if (top < capacity) re->work[top++] = s->out;
            break;
        case ZCL_ERE_OP_BOL:
            if (pos == 0 && top < capacity) re->work[top++] = s->out;
            break;
        case ZCL_ERE_OP_EOL:
            if (pos == length && top < capacity) re->work[top++] = s->out;
            break;
        case ZCL_ERE_OP_MATCH:
            *matched = true;
            break;
        default:
            list[(*n)++] = index;
            break;
        }
    }
}

static inline bool zcl_ere_consumes(const struct zcl_ere *re,
                                    const struct zcl_ere_state *s,
                                    unsigned char c)
{
    switch (s->op) {
    case ZCL_ERE_OP_CHAR:
        return s->ch == c;
    case ZCL_ERE_OP_ANY:
        return true;
    case ZCL_ERE_OP_CLASS:
        return s->cls >= 0 && s->cls < re->class_count &&
               (re->classes[s->cls][c >> 5] & (1u << (c & 31u))) != 0;
    default:
        return false;
    }
}

/* Unanchored search, the same question regexec(..., 0, NULL, 0) answers:
 * does the pattern match anywhere in the first `length` bytes? */
static inline bool zcl_ere_search(struct zcl_ere *re, const char *text,
                                  size_t length)
{
    if (!re || !re->compiled || !text)
        return false;
    int32_t *current = re->current;
    int32_t *next = re->next;
    int32_t current_count = 0;
    bool matched = false;
    re->generation++;
    zcl_ere_add(re, current, &current_count, re->start, 0, length, &matched);
    for (size_t pos = 0; pos < length && !matched; pos++) {
        unsigned char c = (unsigned char)text[pos];
        int32_t next_count = 0;
        re->generation++;
        for (int32_t i = 0; i < current_count; i++) {
            const struct zcl_ere_state *s = &re->states[current[i]];
            if (zcl_ere_consumes(re, s, c))
                zcl_ere_add(re, next, &next_count, s->out, pos + 1, length,
                            &matched);
        }
        /* Seed a fresh start at every offset: the search is unanchored. */
        zcl_ere_add(re, next, &next_count, re->start, pos + 1, length,
                    &matched);
        int32_t *swap = current;
        current = next;
        next = swap;
        current_count = next_count;
    }
    return matched;
}

#endif /* ZCL_UTIL_ERE_MATCH_H */
