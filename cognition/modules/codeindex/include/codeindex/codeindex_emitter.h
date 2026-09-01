/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * codeindex_emitter — resolve a string the RUNNING node emitted back to the
 * source site that formatted it.
 *
 * ── Why this exists ──
 * The node names every stall as a typed blocker with an `id` and a `reason`
 * (platform/modules/util/blocker.h), and it logs. An agent holding one of those strings has
 * to find the code that produced it, and today that means guessing a grep
 * fragment: the emitted text is the format string AFTER substitution and AFTER
 * truncation at BLOCKER_REASON_MAX, so it never appears verbatim in the tree.
 *
 * ── What it derives, and from what ──
 * Nothing here is authored. The one source of truth is the SOURCE TEXT: a
 * string the binary printed was printed by a string literal in a .c file, so
 * the literal IS the authority on which code said it. This scans for that
 * evidence at QUERY TIME over the file list the codeindex store already owns,
 * and attributes each hit to its enclosing function using the store's symbol
 * table. There is no table of ids, no cached mapping, and therefore no
 * freshness gate: re-running the query re-reads the tree.
 *
 * Three independent kinds of source evidence, strongest first:
 *
 *   CI_EMIT_LITERAL_EXACT / _SPAN  the query occurs verbatim inside one
 *       literal (after C adjacent-literal concatenation). This is what a
 *       blocker id built from a literal looks like.
 *
 *   CI_EMIT_BLOCKER_MARKER  a `blocker-id: <pattern>` marker comment whose
 *       glob matches the query. That marker convention is not invented here —
 *       tools/scripts/check_blocker_remedy.sh already requires one at every
 *       site that builds a blocker id dynamically, which is exactly the set of
 *       ids no literal search can find.
 *
 *   CI_EMIT_FORMAT_MATCH  the literal SEGMENTS of a format string (the text
 *       between its conversion specifiers) occur, in order, inside the query.
 *       This is the case that matters most: it recovers the emitter of a
 *       substituted, mid-word-truncated reason, and it DISCRIMINATES between
 *       near-identical format strings, because a one-character difference in a
 *       segment ("...rebuild: fail-closed" vs "...rebuild fail-closed") makes
 *       the segment walk fail on the first segment.
 *
 * Both directions are tried: the query may be a fragment of a long literal
 * (query inside literal) or a substituted whole reason (literal segments
 * inside query). Ranking is deterministic — evidence kind, then literal
 * characters accounted for, then longest single segment, then path/line.
 *
 * ── Known limits, stated rather than papered over ──
 *  - Attribution to the enclosing function follows the same greatest-def_line
 *    rule codeindex documents for `ci_ref.enclosing`: best-effort, not a parse.
 *  - A message assembled from several snprintf calls resolves to whichever
 *    fragment carries the most literal characters, not to all of them.
 *  - A message built entirely from runtime data (no literal at all) is
 *    UNRESOLVABLE by construction, and the report says so.
 *  - The scan reads the CHECKOUT. If the running node was built from a
 *    different revision, this answers for the checkout, not for that binary.
 */

#ifndef ZCL_CODEINDEX_EMITTER_H
#define ZCL_CODEINDEX_EMITTER_H

#include <stdbool.h>
#include <stddef.h>

struct codeindex;

/* Kind of source evidence that tied the query to a site. Ordered weakest to
 * strongest for readability only — ranking uses codeindex_emit_kind_rank(). */
enum ci_emit_kind {
    CI_EMIT_NONE = 0,
    CI_EMIT_FORMAT_MATCH,   /* format-string segments occur in order in query */
    CI_EMIT_LITERAL_SPAN,   /* query occurs inside a longer literal */
    CI_EMIT_BLOCKER_MARKER, /* `blocker-id: <glob>` marker matches the query */
    CI_EMIT_LITERAL_EXACT,  /* a literal equal to the whole query */
    CI_EMIT_REGISTRY_ROW,   /* a .def row names the function itself — the only
                             * kind that owes nothing to text matching, and the
                             * only one that is exact by construction */
};

/* Acceptance floors for CI_EMIT_FORMAT_MATCH. A format string must account for
 * this many literal characters of the query, with at least one unbroken
 * segment this long, before it counts as evidence — otherwise punctuation-only
 * formats ("%s: %d") would match everything. */
enum {
    CI_EMIT_MIN_FORMAT_CHARS   = 20,
    CI_EMIT_MIN_FORMAT_SEGMENT = 12,
    CI_EMIT_MIN_LITERAL_QUERY  = 8,  /* shortest query worth a literal search */
    CI_EMIT_EVIDENCE_MAX       = 192,
};

/* One site that carries evidence for the query. */
struct ci_emit_site {
    char path[256];
    int  line;                               /* 1-based, start of the literal */
    char enclosing[128];                     /* "" when unattributed */
    char context[80];                        /* callee at the literal's call
                                              * site — "blocker_init" vs
                                              * "blocker_clear" is the whole
                                              * difference between a raise and a
                                              * clear, and the ONLY thing that
                                              * tells them apart. Lexical
                                              * backward scan to the innermost
                                              * unclosed '(': best-effort. */
    char evidence[CI_EMIT_EVIDENCE_MAX];     /* the matched literal / marker */
    enum ci_emit_kind kind;
    int  literal_chars;                      /* literal chars accounted for */
    int  longest_segment;                    /* longest unbroken segment */
    bool is_test;                            /* under tests/harness/include/test/ */
    bool preferred;                          /* matched the caller's prefer_path */
};

/* What the scan actually looked at. Reported verbatim so a caller can tell an
 * "unresolvable" answer apart from a scan that never ran. */
struct ci_emit_scan_report {
    int  files_scanned;
    int  files_unreadable;
    int  literal_runs;
    int  markers_seen;
    int  candidates;          /* sites over the floor, before `cap` */
    int  best_rejected_chars; /* strongest sub-floor evidence seen */
    bool enumeration_incomplete; /* the source walk aborted early */
};

/* Rank weight of an evidence kind (higher wins). */
int codeindex_emit_kind_rank(enum ci_emit_kind kind);

/* Stable lowercase name of an evidence kind, for JSON. Never NULL. */
const char *codeindex_emit_kind_name(enum ci_emit_kind kind);

/* Scan `ci`'s own source roots for evidence of `query`, attributing each hit to
 * its enclosing function through `ci`'s symbol table. The checkout scanned is
 * the one the handle was opened on — there is no second root argument, because
 * a second root is a second answer to "which tree is this". Fills up to `cap`
 * ranked sites (production sites before tests/harness/include/test/ sites, strongest first) and
 * always fills *report when non-NULL. Returns the number of sites written
 * (>= 0), or -1 on a hard error (bad arguments, allocation failure). Zero is a
 * real answer: no literal in the tree accounts for that text.
 *
 * `prefer_path` (may be NULL) is a repo-relative file a CALLER'S OWN REGISTRY
 * already names as the owner of this text — e.g. a diagnostics_dumpers.def
 * row's owner_file. Sites in it outrank every text signal and are flagged
 * `preferred`. Without it, a short common string (a bare subsystem name occurs
 * in hundreds of literals) would push the one file that actually owns it out of
 * the candidate pool entirely, and the caller could not pin what it never
 * received. This is the hook that lets a registry decide and the text supply
 * only the line. */
int codeindex_emitter_sites(struct codeindex *ci, const char *query,
                            const char *prefer_path,
                            struct ci_emit_site *out, int cap,
                            struct ci_emit_scan_report *report);

/* Glob match with '*' meaning "any run of characters", used for the
 * `blocker-id:` marker patterns. Exposed because the same rule decides whether
 * a blocker-remedy registry row owns an id, and one implementation of the rule
 * is better than two. */
bool codeindex_emit_glob_match(const char *pattern, const char *text);

#endif /* ZCL_CODEINDEX_EMITTER_H */
