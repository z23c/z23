/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_score — the bounded DETERMINISTIC ZCODE contribution score
 * (slice 7). One release maps to one score, computed purely from the
 * release's own content and its lineage's content: no wall-clock, no
 * randomness, no network, no node state — same inputs, same score. The
 * period caps take the contributor's reward history as an explicit input,
 * so even they are a pure function. Settlement (queue/plan/commit) is a
 * later slice; this layer only computes and names.
 *
 * Scoring model (v1, frozen):
 *   - SEMANTIC LINES. Every scorable file (.c/.h/.def, not vendored, not
 *     generated, within the per-file byte cap) is classified line by line:
 *     semantic, blank, comment-only, or brace-only. Only semantic lines
 *     carry content.
 *   - SEMANTIC UNITS. The semantic content of one file is normalized into
 *     units: all whitespace removed, braces treated as zero-content
 *     structural terminators, ';' at paren depth 0 a terminator,
 *     preprocessor lines self-contained. A unit is therefore a logical
 *     statement, NOT a physical line — splitting one statement across
 *     lines, joining two onto one line, or re-styling braces reproduces
 *     the byte-identical unit and scores NOTHING new.
 *   - LINEAGE DIFF. A unit earns only when it is genuinely new: absent
 *     from the unit set of the whole ancestor chain (parent, grandparent,
 *     ... — content hashing, never filenames) and seen only once within
 *     the release itself. Moved, renamed, re-added, or copy-pasted code
 *     matches an existing unit and scores zero.
 *   - POINTS. A new unit from a source file earns
 *     VCS_SCORE_SOURCE_LINE_POINTS (1); a new unit from a test file earns
 *     VCS_SCORE_TEST_LINE_POINTS (2) — tests out-credit source. The
 *     line-point component is capped at
 *     VCS_SCORE_MAX_LINE_POINTS_PER_RELEASE (500) per release.
 *   - CATEGORY. Auto-derived v1 categories: new-package (a root release,
 *     base 500), package-update (new source units, base 100),
 *     test-contribution (only new test units, base 100), none (nothing
 *     new, base 0). The remaining owner-directive categories (bug fix
 *     with regression test, security fix, 90-day maintenance, independent
 *     review, independent build reproduction) are published as named
 *     constants in the scoring table but are NOT auto-claimed in v1 —
 *     they are claimed through the reviewed settlement flow (slice 8+).
 *   - TOTAL. total = min(category_base + line_points,
 *     VCS_SCORE_MAX_TOTAL_PER_RELEASE).
 *   - PERIOD CAPS. vcs_score_apply_period_caps() enforces
 *     VCS_SCORE_MAX_PER_CONTRIBUTOR_WEEK over a trailing 7-day window and
 *     VCS_SCORE_MAX_RELEASES_PER_DAY rewarded releases per day, given the
 *     contributor's history as explicit entries.
 *
 * This layer parses bytes and computes; it has no filesystem, network,
 * wallet, build, execution, signature, or node-state authority. Callers
 * own all I/O (reading manifests/chunks from the CAS) and every trust
 * decision (the eligibility gates live in vcs/package_eligible.h). */

#ifndef ZCL_VCS_PACKAGE_SCORE_H
#define ZCL_VCS_PACKAGE_SCORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── scoring constants (owner directive, 2026-07-27; named, frozen) ─── */

#define VCS_SCORE_CATEGORY_NEW_PACKAGE_POINTS 500u
#define VCS_SCORE_CATEGORY_PACKAGE_UPDATE_MIN 100u
#define VCS_SCORE_CATEGORY_PACKAGE_UPDATE_MAX 500u
#define VCS_SCORE_CATEGORY_BUG_FIX_REGRESSION_POINTS 250u
#define VCS_SCORE_CATEGORY_TEST_CONTRIBUTION_MIN 100u
#define VCS_SCORE_CATEGORY_TEST_CONTRIBUTION_MAX 500u
#define VCS_SCORE_CATEGORY_BUILD_REPRODUCTION_POINTS 100u
#define VCS_SCORE_CATEGORY_SECURITY_FIX_MIN 500u
#define VCS_SCORE_CATEGORY_SECURITY_FIX_MAX 5000u
#define VCS_SCORE_CATEGORY_MAINTENANCE_90_DAY_POINTS 100u
#define VCS_SCORE_CATEGORY_REVIEW_MIN 50u
#define VCS_SCORE_CATEGORY_REVIEW_MAX 500u

#define VCS_SCORE_SOURCE_LINE_POINTS 1u
#define VCS_SCORE_TEST_LINE_POINTS 2u
#define VCS_SCORE_MAX_LINE_POINTS_PER_RELEASE 500u
#define VCS_SCORE_MAX_TOTAL_PER_RELEASE 5000u
#define VCS_SCORE_MAX_PER_CONTRIBUTOR_WEEK 10000u
#define VCS_SCORE_MAX_RELEASES_PER_DAY 10u

/* Bounds. A file over the byte cap is excluded with the oversize reason
 * (under-crediting is the safe direction); the lineage walk and the
 * per-release report are bounded so one release cannot exhaust memory. */
#define VCS_SCORE_MAX_FILE_BYTES (1024u * 1024u)
#define VCS_SCORE_MAX_LINEAGE_DEPTH 64u
#define VCS_SCORE_MAX_FILE_REPORTS 64u
#define VCS_SCORE_GENERATED_MARKER_LINES 5u
#define VCS_SCORE_MAX_UNIT_BYTES (64u * 1024u)

/* ── per-line classification ────────────────────────────────────────── */

/* The enum order is frozen: it appears in typed JSON. */
enum vcs_score_line_class {
    VCS_SCORE_LINE_SEMANTIC = 0, /* meaningful code */
    VCS_SCORE_LINE_BLANK,        /* whitespace-only */
    VCS_SCORE_LINE_COMMENT_ONLY, /* only comment text (incl. block interior) */
    VCS_SCORE_LINE_BRACE_ONLY,   /* only { } and whitespace */
};

const char *vcs_score_line_class_string(enum vcs_score_line_class cls);

struct vcs_score_line_tally {
    uint32_t semantic;
    uint32_t blank;
    uint32_t comment_only;
    uint32_t brace_only;
};

/* Classify every physical line of one file (block comments carry across
 * lines; string/char literals with escapes are honoured so a comment
 * opener inside a literal never starts a comment). Pure. */
void vcs_score_classify_lines(const uint8_t *bytes, size_t len,
                              struct vcs_score_line_tally *out);

/* ── file classification ────────────────────────────────────────────── */

/* The enum order is frozen: it appears in typed JSON. */
enum vcs_score_file_kind {
    VCS_SCORE_FILE_SOURCE = 0, /* scorable .c/.h/.def, source weight */
    VCS_SCORE_FILE_TEST,       /* scorable test path, test weight */
    VCS_SCORE_FILE_EXCLUDED,   /* excluded; reason names the rule */
};

enum vcs_score_exclude_reason {
    VCS_SCORE_EXCLUDE_NONE = 0,
    VCS_SCORE_EXCLUDE_EXTENSION,        /* not .c/.h/.def */
    VCS_SCORE_EXCLUDE_VENDORED,         /* vendor/third-party path segment */
    VCS_SCORE_EXCLUDE_GENERATED_PATH,   /* a "generated" path segment */
    VCS_SCORE_EXCLUDE_GENERATED_MARKER, /* generation marker in head lines */
    VCS_SCORE_EXCLUDE_OVERSIZE,         /* over VCS_SCORE_MAX_FILE_BYTES */
};

const char *vcs_score_file_kind_string(enum vcs_score_file_kind kind);
const char *vcs_score_exclude_reason_string(
    enum vcs_score_exclude_reason reason);

/* Classify a path alone: extension, vendored/generated segments, and the
 * test-path rule (a "test"/"tests" segment, a "test_" basename prefix, or
 * a "_test" basename suffix). Exclusions outrank test detection. Content
 * rules (generated marker, oversize) are applied by vcs_score_scan_file. */
enum vcs_score_file_kind vcs_score_classify_path(
    const char *path, enum vcs_score_exclude_reason *reason_out);

/* ── unit sets ──────────────────────────────────────────────────────── */

/* A growable string set of normalized semantic units. add() appends
 * (duplicates allowed); finalize() sorts and dedups; contains() is a
 * binary search valid only after finalize(). */
struct vcs_score_set {
    char **items;
    size_t count;
    size_t cap;
    bool finalized;
};

void vcs_score_set_init(struct vcs_score_set *set);
void vcs_score_set_free(struct vcs_score_set *set);

/* Copy one unit into the set. False on allocation failure (logged) or a
 * unit over VCS_SCORE_MAX_UNIT_BYTES (logged; the unit is dropped, never
 * truncated). An empty unit is a no-op true. */
bool vcs_score_set_add(struct vcs_score_set *set, const char *unit,
                       size_t len);

/* Sort ascending and drop duplicates. Idempotent. */
void vcs_score_set_finalize(struct vcs_score_set *set);

/* Membership; valid only after finalize(). */
bool vcs_score_set_contains(const struct vcs_score_set *set,
                            const char *unit, size_t len);

/* ── file scan (classify + unitize) ─────────────────────────────────── */

struct vcs_score_file_scan {
    enum vcs_score_file_kind kind;
    enum vcs_score_exclude_reason reason; /* NONE unless EXCLUDED */
    struct vcs_score_line_tally lines;    /* zeroed when EXCLUDED */
    struct vcs_score_set units;           /* unfinalized, file order */
};

/* Classify and unitize one file. EXCLUDED files carry the named reason,
 * zero tallies, and no units. False on allocation failure (logged). */
bool vcs_score_scan_file(const char *path, const uint8_t *bytes,
                         size_t len, struct vcs_score_file_scan *out);
void vcs_score_file_scan_free(struct vcs_score_file_scan *scan);

/* Absorb every unit of one scorable file into a set (the lineage builder:
 * excluded files contribute nothing). False on allocation failure. */
bool vcs_score_set_absorb_file(struct vcs_score_set *set, const char *path,
                               const uint8_t *bytes, size_t len);

/* ── release scoring ────────────────────────────────────────────────── */

/* The auto-derived v1 categories. The enum order is frozen. */
enum vcs_score_category {
    VCS_SCORE_CATEGORY_NONE = 0, /* nothing genuinely new */
    VCS_SCORE_CATEGORY_NEW_PACKAGE,
    VCS_SCORE_CATEGORY_PACKAGE_UPDATE,
    VCS_SCORE_CATEGORY_TEST_CONTRIBUTION,
};

const char *vcs_score_category_string(enum vcs_score_category category);

/* The owner-directive scoring table: every category with its point value
 * or range and whether v1 derives it automatically from release content
 * (false = claimed only through the reviewed settlement flow). */
struct vcs_score_category_constant {
    const char *name;
    uint32_t min_points;
    uint32_t max_points;
    bool automatic;
};

const struct vcs_score_category_constant *vcs_score_category_table(
    size_t *count_out);

struct vcs_score_input_file {
    const char *path;           /* canonical package-relative path */
    const uint8_t *bytes;       /* exact file content (may be NULL when
                                   declared_size exceeds the file cap) */
    size_t len;                 /* exact content length */
    uint64_t declared_size;     /* manifest size (the oversize authority) */
};

struct vcs_score_file_report {
    const char *path;                  /* borrowed from the input */
    enum vcs_score_file_kind kind;
    enum vcs_score_exclude_reason reason;
    struct vcs_score_line_tally lines; /* zeroed when EXCLUDED */
    uint32_t new_units;                /* genuinely new units from this file */
    uint32_t points;                   /* weighted points earned */
};

struct vcs_score_release {
    enum vcs_score_category category;
    uint32_t category_base;
    /* Line tallies over the SCORED files only. */
    uint32_t semantic_lines;
    uint32_t blank_lines;
    uint32_t comment_lines;
    uint32_t brace_lines;
    uint32_t files_scored;
    uint32_t files_excluded;
    /* Unit accounting. */
    uint32_t units_total;        /* distinct units in the release */
    uint32_t units_duplicate;    /* repeat units dropped within the release */
    uint32_t units_already_rewarded; /* matched the lineage set */
    uint32_t new_source_units;
    uint32_t new_test_units;
    /* Points. */
    uint32_t raw_line_points;    /* before the per-release line cap */
    uint32_t line_points;        /* after VCS_SCORE_MAX_LINE_POINTS_PER_RELEASE */
    bool line_cap_applied;
    uint32_t raw_total;          /* category_base + line_points */
    uint32_t total;              /* after VCS_SCORE_MAX_TOTAL_PER_RELEASE */
    bool release_cap_applied;
    /* Bounded per-file breakdown (input order). */
    struct vcs_score_file_report files[VCS_SCORE_MAX_FILE_REPORTS];
    size_t file_report_count;
    bool file_reports_truncated;
};

/* Compute the deterministic score for one release. `lineage` is the
 * finalized unit set of every scorable file of every ancestor release
 * (an empty set for a root release); `has_parent` is the envelope's
 * lineage flag (it decides the category, not the diff). Files are
 * processed in the given order — callers pass manifest (canonical path)
 * order so duplicate-claim attribution is deterministic. False on
 * allocation failure (logged); every content problem is an exclusion
 * named in the report, never a hard error. */
bool vcs_score_release_compute(const struct vcs_score_input_file *files,
                               size_t file_count,
                               const struct vcs_score_set *lineage,
                               bool has_parent,
                               struct vcs_score_release *out);

/* ── period caps (deterministic; history is an explicit input) ──────── */

/* One already-rewarded release: `day` is a civil day number (e.g. unix
 * time / 86400) and `score` its settled total. The caller defines the
 * epoch; only day arithmetic is used. */
struct vcs_score_period_entry {
    int64_t day;
    uint32_t score;
};

struct vcs_score_period_caps {
    uint32_t candidate_score;    /* input, echoed */
    uint32_t allowed_score;      /* after both caps */
    uint32_t releases_today;     /* history entries on candidate_day */
    bool daily_release_cap_hit;  /* releases_today >= MAX_RELEASES_PER_DAY */
    uint32_t week_spent;         /* sum over the trailing 7-day window */
    uint32_t week_remaining;     /* before the candidate */
    bool weekly_cap_hit;         /* weekly cap reduced the candidate */
};

/* Enforce the weekly contributor cap (trailing 7 days INCLUDING
 * candidate_day) and the daily rewarded-release cap. The daily cap
 * zeroes the candidate outright (the release is simply not rewarded this
 * day); the weekly cap clamps the score to the remaining budget. */
void vcs_score_apply_period_caps(const struct vcs_score_period_entry *history,
                                 size_t history_count,
                                 int64_t candidate_day,
                                 uint32_t candidate_score,
                                 struct vcs_score_period_caps *out);

#endif /* ZCL_VCS_PACKAGE_SCORE_H */
