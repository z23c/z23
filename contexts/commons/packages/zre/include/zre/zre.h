/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: regular expressions for C23 with GUARANTEED linear-time matching.
 *          Patterns compile to a Thompson NFA and run on a pike VM (parallel
 *          lockstep simulation); there is no backtracking anywhere, so no
 *          pattern/input pair can cause catastrophic blowup. Runtime is
 *          O(program size x text length) with memory fixed at compile time.
 *
 * Pattern syntax (the whole language — anything else fails to compile):
 *  - literals: any byte except the metacharacters below matches itself
 *  - '.'        any byte except '\n' (byte-oriented: a UTF-8 code point is
 *               2-4 separate bytes and matches '.' once per byte)
 *  - '*' '+' '?' greedy postfix repeats (zero-or-more, one-or-more,
 *               zero-or-one); lazy forms like '*?' do not exist — a postfix
 *               on a postfix is a ZRE_ERR_REPEAT compile error
 *  - '{m}' '{m,}' '{m,n}' counted repeat, 0 <= m <= n <= 255; '{' not
 *    followed by a digit is a literal brace
 *  - '[...]'    byte class with ranges ('a-z'), negation ('^' first),
 *               escapes and shorthand classes inside; ']' first is a
 *               literal, '-' last is a literal
 *  - escapes: '\d' '\D' '\w' '\W' '\s' '\S' (ASCII shorthands), '\n' '\t'
 *    '\r' '\f' '\v', '\xNN' (exactly two hex digits), and '\' before any
 *    ASCII punctuation for a literal; '\1'-style backreferences and other
 *    unknown alphanumeric escapes are compile errors
 *  - '^' '$'    absolute anchors: start/end of the whole text (no multiline)
 *  - '(...)'    capturing group (at most ZRE_MAX_GROUPS, numbered from 1 in
 *               order of '('); '(?:...)' non-capturing group; any other '(?'
 *               form (lookahead etc.) is ZRE_ERR_UNSUPPORTED
 *  - '|'        alternation, lowest precedence: "ab|cd" is "(ab)|(cd)";
 *               empty alternatives are allowed ("a|" matches "a" or empty)
 *
 * Match semantics: leftmost-first (Perl-like). The match starts at the
 * lowest text offset that admits one; among paths from that offset the pike
 * VM's thread priority makes quantifiers greedy and prefers the left
 * alternative. zre_match() searches unanchored (grep-style): wrap the
 * pattern in '^'/'$' to pin it.
 *
 * Captures: caps[0] is the whole match, caps[i] is group i. A group that
 * did not participate reports {ZRE_NOMATCH, ZRE_NOMATCH}.
 *
 * Bounds (fail-closed compile errors, never silent truncation):
 *  ZRE_MAX_PATTERN  pattern bytes      ZRE_MAX_PROG    compiled instructions
 *  ZRE_MAX_GROUPS   capture groups     ZRE_MAX_NEST    group nesting depth
 *  ZRE_MAX_REPEAT   counted-repeat bound
 */
#ifndef ZRE_H
#define ZRE_H

#include <stdbool.h>
#include <stddef.h>

#define ZRE_MAX_PATTERN 4096u
#define ZRE_MAX_PROG 1024u
#define ZRE_MAX_GROUPS 8u
#define ZRE_MAX_NEST 32u
#define ZRE_MAX_REPEAT 255u
#define ZRE_MAX_CAPS (ZRE_MAX_GROUPS + 1u)

/* Span sentinel for a capture group that did not participate. */
#define ZRE_NOMATCH ((size_t)-1)

typedef enum {
  ZRE_OK = 0,
  ZRE_ERR_ARG,         /* NULL pattern/out, or other bad argument */
  ZRE_ERR_TOO_LONG,    /* pattern over ZRE_MAX_PATTERN bytes */
  ZRE_ERR_UNBALANCED,  /* '(' without ')' or ')' without '(' */
  ZRE_ERR_CLASS,       /* unterminated class or inverted range */
  ZRE_ERR_ESCAPE,      /* trailing '\' or unknown escape */
  ZRE_ERR_REPEAT,      /* repeat with no atom, stacked postfix, bad {m,n} */
  ZRE_ERR_UNSUPPORTED, /* known-but-unsupported construct (lookahead,
                          backreference, ...) */
  ZRE_ERR_NEST,        /* groups nested over ZRE_MAX_NEST */
  ZRE_ERR_GROUPS,      /* over ZRE_MAX_GROUPS capture groups */
  ZRE_ERR_PROGRAM,     /* compiled program over ZRE_MAX_PROG instructions */
  ZRE_ERR_MEMORY       /* allocation failed */
} zre_status;

/* Half-open byte span [start, end) into the matched text. */
typedef struct {
  size_t start, end;
} zre_span;

typedef struct zre_prog zre_prog;

/* Compile pattern[0..len) into a program. On success returns ZRE_OK and
 * *prog_out receives a heap program to release with zre_free(). On failure
 * *prog_out is NULL and errbuf (when non-NULL with errbuf_cap > 0) receives
 * a NUL-terminated explanation naming the failing offset. */
zre_status zre_compile(const char *pattern, size_t len, zre_prog **prog_out,
                       char *errbuf, size_t errbuf_cap);

/* Search text[0..len) for a match. Returns true on a match and fills
 * caps[0..min(max_caps, zre_groups(prog)+1)) with spans; further entries up
 * to max_caps are set to {ZRE_NOMATCH, ZRE_NOMATCH}. caps may be NULL with
 * max_caps 0 to only test. Returns false on no match and on any argument or
 * allocation failure (fail-closed). */
bool zre_match(const zre_prog *prog, const char *text, size_t len,
               zre_span caps[], size_t max_caps);

/* Number of capture groups in the program (0..ZRE_MAX_GROUPS). */
size_t zre_groups(const zre_prog *prog);

void zre_free(zre_prog *prog);

const char *zre_strerror(zre_status st);

#endif /* ZRE_H */
