/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_score — implementation of the deterministic ZCODE contribution
 * score declared in vcs/package_score.h. Pure computation over caller-
 * supplied bytes: the only impurity is allocation (checked via
 * zcl_malloc/zcl_realloc, failures logged). */

#include "vcs/package_score.h"

#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdlib.h>
#include <string.h>

#define SCORE_LOG "vcs.score"

/* ── strings ────────────────────────────────────────────────────────── */

const char *vcs_score_file_kind_string(enum vcs_score_file_kind kind)
{
    switch (kind) {
    case VCS_SCORE_FILE_SOURCE: return "source";
    case VCS_SCORE_FILE_TEST: return "test";
    case VCS_SCORE_FILE_EXCLUDED: return "excluded";
    }
    return "unknown";
}

const char *vcs_score_exclude_reason_string(
    enum vcs_score_exclude_reason reason)
{
    switch (reason) {
    case VCS_SCORE_EXCLUDE_NONE: return "none";
    case VCS_SCORE_EXCLUDE_EXTENSION: return "not-c-source";
    case VCS_SCORE_EXCLUDE_VENDORED: return "vendored-path";
    case VCS_SCORE_EXCLUDE_GENERATED_PATH: return "generated-path";
    case VCS_SCORE_EXCLUDE_GENERATED_MARKER: return "generated-marker";
    case VCS_SCORE_EXCLUDE_OVERSIZE: return "file-oversize";
    }
    return "unknown";
}

const char *vcs_score_category_string(enum vcs_score_category category)
{
    switch (category) {
    case VCS_SCORE_CATEGORY_NONE: return "none";
    case VCS_SCORE_CATEGORY_NEW_PACKAGE: return "new-package";
    case VCS_SCORE_CATEGORY_PACKAGE_UPDATE: return "package-update";
    case VCS_SCORE_CATEGORY_TEST_CONTRIBUTION: return "test-contribution";
    }
    return "unknown";
}

const struct vcs_score_category_constant *vcs_score_category_table(
    size_t *count_out)
{
    static const struct vcs_score_category_constant k_table[] = {
        { "new-package", VCS_SCORE_CATEGORY_NEW_PACKAGE_POINTS,
          VCS_SCORE_CATEGORY_NEW_PACKAGE_POINTS, true },
        { "package-update", VCS_SCORE_CATEGORY_PACKAGE_UPDATE_MIN,
          VCS_SCORE_CATEGORY_PACKAGE_UPDATE_MAX, true },
        { "bug-fix-with-regression-test",
          VCS_SCORE_CATEGORY_BUG_FIX_REGRESSION_POINTS,
          VCS_SCORE_CATEGORY_BUG_FIX_REGRESSION_POINTS, false },
        { "test-contribution", VCS_SCORE_CATEGORY_TEST_CONTRIBUTION_MIN,
          VCS_SCORE_CATEGORY_TEST_CONTRIBUTION_MAX, true },
        { "independent-build-reproduction",
          VCS_SCORE_CATEGORY_BUILD_REPRODUCTION_POINTS,
          VCS_SCORE_CATEGORY_BUILD_REPRODUCTION_POINTS, false },
        { "security-fix", VCS_SCORE_CATEGORY_SECURITY_FIX_MIN,
          VCS_SCORE_CATEGORY_SECURITY_FIX_MAX, false },
        { "maintenance-90-day",
          VCS_SCORE_CATEGORY_MAINTENANCE_90_DAY_POINTS,
          VCS_SCORE_CATEGORY_MAINTENANCE_90_DAY_POINTS, false },
        { "independent-review", VCS_SCORE_CATEGORY_REVIEW_MIN,
          VCS_SCORE_CATEGORY_REVIEW_MAX, false },
    };
    if (count_out)
        *count_out = sizeof(k_table) / sizeof(k_table[0]);
    return k_table;
}

/* ── per-line classification ────────────────────────────────────────── */

static bool score_is_ws(uint8_t c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v';
}

/* One step through a block comment: consumes a byte, or the closing
 * marker and clears *in_block. Returns the next index. */
static size_t score_block_step(const uint8_t *line, size_t len, size_t i,
                               bool *in_block)
{
    if (line[i] == '*' && i + 1 < len && line[i + 1] == '/') {
        *in_block = false;
        return i + 2;
    }
    return i + 1;
}

/* Copies a string or character literal verbatim, starting at its opening
 * quote line[*i_io]. Leaves *i_io past the closing quote (or at the line
 * end) and returns the new cleaned length. */
static size_t score_copy_literal(const uint8_t *line, size_t len, size_t *i_io,
                                 uint8_t *cleaned_out, size_t cleaned)
{
    size_t i = *i_io;
    uint8_t quote = line[i];
    cleaned_out[cleaned++] = quote;
    i++;
    while (i < len) {
        uint8_t d = line[i];
        cleaned_out[cleaned++] = d;
        i++;
        if (d == '\\' && i < len) {
            cleaned_out[cleaned++] = line[i];
            i++;
            continue;
        }
        if (d == quote)
            break;
    }
    *i_io = i;
    return cleaned;
}

static enum vcs_score_line_class score_line_class(bool saw_code,
                                                  bool saw_comment,
                                                  bool saw_nonbrace)
{
    if (!saw_code && !saw_comment)
        return VCS_SCORE_LINE_BLANK;
    if (!saw_code)
        return VCS_SCORE_LINE_COMMENT_ONLY;
    if (!saw_nonbrace)
        return VCS_SCORE_LINE_BRACE_ONLY;
    return VCS_SCORE_LINE_SEMANTIC;
}

/* Scan one physical line (no trailing '\n'; a trailing '\r' is handled
 * as whitespace). Carries the block-comment state. Reports the line
 * class; when the line is SEMANTIC or BRACE_ONLY its cleaned content
 * (comments and non-literal whitespace stripped, literals verbatim) is
 * appended to cleaned_out (bounded at the line length). */
struct score_line_scan {
    enum vcs_score_line_class cls;
    size_t cleaned_len; /* valid for SEMANTIC and BRACE_ONLY */
};

static void score_scan_line(const uint8_t *line, size_t len, bool *in_block,
                            struct score_line_scan *out,
                            uint8_t *cleaned_out)
{
    bool saw_code = false;
    bool saw_comment = *in_block; /* an interior block line is comment */
    bool saw_nonbrace = false;
    size_t cleaned = 0;
    size_t i = 0;
    while (i < len) {
        uint8_t c = line[i];
        if (*in_block) {
            i = score_block_step(line, len, i, in_block);
            continue;
        }
        if (score_is_ws(c)) {
            i++;
            continue;
        }
        if (c == '/' && i + 1 < len && line[i + 1] == '/') {
            saw_comment = true;
            break; /* rest of the line is comment */
        }
        if (c == '/' && i + 1 < len && line[i + 1] == '*') {
            saw_comment = true;
            *in_block = true;
            i += 2;
            continue;
        }
        if (c == '"' || c == '\'') {
            saw_code = true;
            saw_nonbrace = true;
            cleaned = score_copy_literal(line, len, &i, cleaned_out, cleaned);
            continue;
        }
        saw_code = true;
        if (c != '{' && c != '}')
            saw_nonbrace = true;
        cleaned_out[cleaned++] = c;
        i++;
    }
    out->cls = score_line_class(saw_code, saw_comment, saw_nonbrace);
    out->cleaned_len = cleaned;
}

void vcs_score_classify_lines(const uint8_t *bytes, size_t len,
                              struct vcs_score_line_tally *out)
{
    memset(out, 0, sizeof(*out));
    if (!bytes && len > 0)
        return;
    uint8_t *cleaned = zcl_malloc(len + 1u, "score_classify_cleaned");
    if (!cleaned) {
        LOG_ERROR(SCORE_LOG, "alloc %zu classify scratch", len + 1u);
        return;
    }
    bool in_block = false;
    size_t pos = 0;
    while (pos <= len) {
        size_t start = pos;
        while (pos < len && bytes[pos] != '\n')
            pos++;
        size_t line_len = pos - start;
        bool last = pos >= len;
        if (line_len == 0 && last && start == len)
            break; /* no trailing empty line after a final newline */
        struct score_line_scan scan;
        score_scan_line(bytes + start, line_len, &in_block, &scan, cleaned);
        switch (scan.cls) {
        case VCS_SCORE_LINE_SEMANTIC: out->semantic++; break;
        case VCS_SCORE_LINE_BLANK: out->blank++; break;
        case VCS_SCORE_LINE_COMMENT_ONLY: out->comment_only++; break;
        case VCS_SCORE_LINE_BRACE_ONLY: out->brace_only++; break;
        }
        if (last)
            break;
        pos++; /* consume the newline */
    }
    free(cleaned);
}

/* ── path classification ────────────────────────────────────────────── */

static bool score_segment_is(const char *seg, size_t len, const char *want)
{
    return strlen(want) == len && memcmp(seg, want, len) == 0;
}

static bool score_has_ext(const char *base, const char *ext)
{
    size_t blen = strlen(base);
    size_t elen = strlen(ext);
    return blen > elen && memcmp(base + blen - elen, ext, elen) == 0;
}

/* Walks the path segments: a vendored or generated directory excludes the
 * file, and a test segment marks it as a test. */
static enum vcs_score_exclude_reason score_path_segments(const char *path,
                                                         bool *is_test)
{
    const char *seg = path;
    while (*seg) {
        const char *slash = strchr(seg, '/');
        size_t slen = slash ? (size_t)(slash - seg) : strlen(seg);
        if (score_segment_is(seg, slen, "vendor") ||
            score_segment_is(seg, slen, "vendored") ||
            score_segment_is(seg, slen, "third_party") ||
            score_segment_is(seg, slen, "third-party"))
            return VCS_SCORE_EXCLUDE_VENDORED;
        if (score_segment_is(seg, slen, "generated"))
            return VCS_SCORE_EXCLUDE_GENERATED_PATH;
        if (score_segment_is(seg, slen, "test") ||
            score_segment_is(seg, slen, "tests"))
            *is_test = true;
        if (!slash)
            break;
        seg = slash + 1;
    }
    return VCS_SCORE_EXCLUDE_NONE;
}

enum vcs_score_file_kind vcs_score_classify_path(
    const char *path, enum vcs_score_exclude_reason *reason_out)
{
    enum vcs_score_exclude_reason local = VCS_SCORE_EXCLUDE_NONE;
    if (!reason_out)
        reason_out = &local;
    *reason_out = VCS_SCORE_EXCLUDE_NONE;
    if (!path || !path[0]) {
        *reason_out = VCS_SCORE_EXCLUDE_EXTENSION;
        return VCS_SCORE_FILE_EXCLUDED;
    }

    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    if (!score_has_ext(base, ".c") && !score_has_ext(base, ".h") &&
        !score_has_ext(base, ".def")) {
        *reason_out = VCS_SCORE_EXCLUDE_EXTENSION;
        return VCS_SCORE_FILE_EXCLUDED;
    }

    bool is_test = false;
    enum vcs_score_exclude_reason seg_reason =
        score_path_segments(path, &is_test);
    if (seg_reason != VCS_SCORE_EXCLUDE_NONE) {
        *reason_out = seg_reason;
        return VCS_SCORE_FILE_EXCLUDED;
    }
    if (strncmp(base, "test_", 5) == 0)
        is_test = true;
    /* "_test" directly before the extension. */
    {
        const char *dot = strrchr(base, '.');
        if (dot && dot - base >= 5 && memcmp(dot - 5, "_test", 5) == 0)
            is_test = true;
    }
    return is_test ? VCS_SCORE_FILE_TEST : VCS_SCORE_FILE_SOURCE;
}

/* Case-insensitive substring over ASCII (bounded haystack). */
static bool score_contains_ci(const uint8_t *hay, size_t hay_len,
                              const char *needle)
{
    size_t nlen = strlen(needle);
    if (nlen == 0 || hay_len < nlen)
        return false;
    for (size_t i = 0; i + nlen <= hay_len; i++) {
        size_t j = 0;
        for (; j < nlen; j++) {
            uint8_t a = hay[i + j];
            uint8_t b = (uint8_t)needle[j];
            if (a >= 'A' && a <= 'Z')
                a = (uint8_t)(a + ('a' - 'A'));
            if (b >= 'A' && b <= 'Z')
                b = (uint8_t)(b + ('a' - 'A'));
            if (a != b)
                break;
        }
        if (j == nlen)
            return true;
    }
    return false;
}

/* A generation marker ("generated" / "do not edit", case-insensitive)
 * inside the first VCS_SCORE_GENERATED_MARKER_LINES physical lines. */
static bool score_has_generated_marker(const uint8_t *bytes, size_t len)
{
    size_t pos = 0;
    for (uint32_t line_no = 0;
         line_no < VCS_SCORE_GENERATED_MARKER_LINES && pos < len;
         line_no++) {
        size_t start = pos;
        while (pos < len && bytes[pos] != '\n')
            pos++;
        size_t line_len = pos - start;
        if (line_len > 512u)
            line_len = 512u;
        if (score_contains_ci(bytes + start, line_len, "generated") ||
            score_contains_ci(bytes + start, line_len, "do not edit"))
            return true;
        if (pos < len)
            pos++;
    }
    return false;
}

/* ── unit sets ──────────────────────────────────────────────────────── */

void vcs_score_set_init(struct vcs_score_set *set)
{
    memset(set, 0, sizeof(*set));
}

void vcs_score_set_free(struct vcs_score_set *set)
{
    if (!set)
        return;
    for (size_t i = 0; i < set->count; i++)
        free(set->items[i]);
    free(set->items);
    memset(set, 0, sizeof(*set));
}

bool vcs_score_set_add(struct vcs_score_set *set, const char *unit,
                       size_t len)
{
    if (!set || (!unit && len > 0)) {
        LOG_FAIL(SCORE_LOG, "null set/unit in set_add");
        return false;
    }
    if (len == 0)
        return true;
    if (len > VCS_SCORE_MAX_UNIT_BYTES) {
        LOG_FAIL(SCORE_LOG, "unit over %u bytes dropped",
                 VCS_SCORE_MAX_UNIT_BYTES);
        return false;
    }
    set->finalized = false;
    if (set->count == set->cap) {
        size_t ncap = set->cap ? set->cap * 2u : 16u;
        char **nitems = zcl_realloc(set->items, ncap * sizeof(*nitems),
                                    "score_set_items");
        if (!nitems) {
            LOG_FAIL(SCORE_LOG, "grow unit set to %zu", ncap);
            return false;
        }
        set->items = nitems;
        set->cap = ncap;
    }
    char *copy = zcl_malloc(len + 1u, "score_unit");
    if (!copy) {
        LOG_FAIL(SCORE_LOG, "copy %zu-byte unit", len);
        return false;
    }
    memcpy(copy, unit, len);
    copy[len] = '\0';
    set->items[set->count++] = copy;
    return true;
}

static int score_str_cmp(const void *a, const void *b)
{
    const char *const *sa = a;
    const char *const *sb = b;
    return strcmp(*sa, *sb);
}

void vcs_score_set_finalize(struct vcs_score_set *set)
{
    if (!set || set->finalized)
        return;
    if (set->count > 1)
        qsort(set->items, set->count, sizeof(*set->items), score_str_cmp);
    size_t out = 0;
    for (size_t i = 0; i < set->count; i++) {
        if (out > 0 && strcmp(set->items[out - 1], set->items[i]) == 0) {
            free(set->items[i]);
            continue;
        }
        set->items[out++] = set->items[i];
    }
    set->count = out;
    set->finalized = true;
}

bool vcs_score_set_contains(const struct vcs_score_set *set,
                            const char *unit, size_t len)
{
    if (!set || !set->finalized || !unit)
        return false;
    size_t lo = 0, hi = set->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2u;
        const char *item = set->items[mid];
        size_t ilen = strlen(item);
        size_t n = ilen < len ? ilen : len;
        int r = memcmp(item, unit, n);
        if (r == 0) {
            if (ilen == len)
                return true;
            r = ilen < len ? -1 : 1;
        }
        if (r < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return false;
}

/* ── file scan ──────────────────────────────────────────────────────── */

void vcs_score_file_scan_free(struct vcs_score_file_scan *scan)
{
    if (!scan)
        return;
    vcs_score_set_free(&scan->units);
    memset(scan, 0, sizeof(*scan));
}

/* The unitizer: fed the cleaned content of semantic/brace-only lines,
 * emits logical-statement units. ';' at paren depth 0 and every brace
 * are zero-content terminators; preprocessor lines are self-contained. */
struct score_unitizer {
    uint8_t *acc;
    size_t acc_len;
    size_t acc_cap;
    int paren_depth;
    bool oom;
};

static bool score_unitizer_emit(struct score_unitizer *u,
                                struct vcs_score_set *units)
{
    if (u->acc_len == 0)
        return true;
    if (!vcs_score_set_add(units, (const char *)u->acc, u->acc_len)) {
        u->oom = true;
        return false;
    }
    u->acc_len = 0;
    return true;
}

static bool score_unitizer_push(struct score_unitizer *u, uint8_t c)
{
    if (u->acc_len == u->acc_cap) {
        size_t ncap = u->acc_cap ? u->acc_cap * 2u : 256u;
        uint8_t *nacc = zcl_realloc(u->acc, ncap, "score_unit_acc");
        if (!nacc) {
            LOG_FAIL(SCORE_LOG, "grow unit accumulator to %zu", ncap);
            u->oom = true;
            return false;
        }
        u->acc = nacc;
        u->acc_cap = ncap;
    }
    u->acc[u->acc_len++] = c;
    return true;
}

/* Preprocessor line: flush any pending statement, then the whole
 * line is one self-contained unit. */
static bool score_unitizer_feed_pp(struct score_unitizer *u,
                                   struct vcs_score_set *units,
                                   const uint8_t *cleaned, size_t len)
{
    if (!score_unitizer_emit(u, units))
        return false;
    for (size_t i = 0; i < len; i++) {
        if (!score_unitizer_push(u, cleaned[i]))
            return false;
    }
    return score_unitizer_emit(u, units);
}

static void score_unitizer_track_paren(struct score_unitizer *u, uint8_t c)
{
    if (c == '(')
        u->paren_depth++;
    else if (c == ')' && u->paren_depth > 0)
        u->paren_depth--;
}

static bool score_unitizer_feed(struct score_unitizer *u,
                                struct vcs_score_set *units,
                                const uint8_t *cleaned, size_t len,
                                bool semantic)
{
    if (semantic && len > 0 && cleaned[0] == '#')
        return score_unitizer_feed_pp(u, units, cleaned, len);
    for (size_t i = 0; i < len; i++) {
        uint8_t c = cleaned[i];
        if (c == '{' || c == '}') {
            if (!score_unitizer_emit(u, units))
                return false;
            continue;
        }
        if (c == ';' && u->paren_depth == 0) {
            if (!score_unitizer_emit(u, units))
                return false;
            continue;
        }
        score_unitizer_track_paren(u, c);
        if (!score_unitizer_push(u, c))
            return false;
    }
    return true;
}

/* Walks the physical lines of one file: tallies each line class into
 * out->lines and feeds the cleaned text of code lines to the unitizer. */
static bool score_scan_lines(const uint8_t *bytes, size_t len,
                             uint8_t *cleaned, struct score_unitizer *u,
                             struct vcs_score_file_scan *out)
{
    bool in_block = false;
    size_t pos = 0;
    bool ok = true;
    while (ok && pos <= len) {
        size_t start = pos;
        while (pos < len && bytes[pos] != '\n')
            pos++;
        size_t line_len = pos - start;
        bool last = pos >= len;
        if (line_len == 0 && last && start == len)
            break;
        struct score_line_scan scan;
        score_scan_line(bytes + start, line_len, &in_block, &scan, cleaned);
        switch (scan.cls) {
        case VCS_SCORE_LINE_SEMANTIC:
            out->lines.semantic++;
            ok = score_unitizer_feed(u, &out->units, cleaned,
                                     scan.cleaned_len, true);
            break;
        case VCS_SCORE_LINE_BRACE_ONLY:
            out->lines.brace_only++;
            ok = score_unitizer_feed(u, &out->units, cleaned,
                                     scan.cleaned_len, false);
            break;
        case VCS_SCORE_LINE_BLANK: out->lines.blank++; break;
        case VCS_SCORE_LINE_COMMENT_ONLY: out->lines.comment_only++; break;
        }
        if (last)
            break;
        pos++;
    }
    return ok;
}

bool vcs_score_scan_file(const char *path, const uint8_t *bytes,
                         size_t len, struct vcs_score_file_scan *out)
{
    memset(out, 0, sizeof(*out));
    vcs_score_set_init(&out->units);
    if (!bytes)
        len = 0;
    enum vcs_score_exclude_reason reason = VCS_SCORE_EXCLUDE_NONE;
    out->kind = vcs_score_classify_path(path, &reason);
    out->reason = reason;
    if (out->kind == VCS_SCORE_FILE_EXCLUDED)
        return true;
    if (len > VCS_SCORE_MAX_FILE_BYTES) {
        out->kind = VCS_SCORE_FILE_EXCLUDED;
        out->reason = VCS_SCORE_EXCLUDE_OVERSIZE;
        return true;
    }
    if (len > 0 && score_has_generated_marker(bytes, len)) {
        out->kind = VCS_SCORE_FILE_EXCLUDED;
        out->reason = VCS_SCORE_EXCLUDE_GENERATED_MARKER;
        return true;
    }

    uint8_t *cleaned = zcl_malloc(len + 1u, "score_scan_cleaned");
    if (!cleaned) {
        LOG_FAIL(SCORE_LOG, "alloc %zu scan scratch for %s", len + 1u,
                 path ? path : "?");
        return false;
    }
    struct score_unitizer u;
    memset(&u, 0, sizeof(u));
    bool ok = score_scan_lines(bytes, len, cleaned, &u, out);
    /* A trailing unterminated statement still forms its unit. */
    if (ok)
        ok = score_unitizer_emit(&u, &out->units);
    free(u.acc);
    free(cleaned);
    if (!ok) {
        LOG_FAIL(SCORE_LOG, "unitizing %s", path ? path : "?");
        vcs_score_file_scan_free(out);
        return false;
    }
    return true;
}

bool vcs_score_set_absorb_file(struct vcs_score_set *set, const char *path,
                               const uint8_t *bytes, size_t len)
{
    struct vcs_score_file_scan scan;
    if (!vcs_score_scan_file(path, bytes, len, &scan)) {
        LOG_FAIL(SCORE_LOG, "scan %s for lineage", path ? path : "?");
        return false;
    }
    bool ok = true;
    for (size_t i = 0; i < scan.units.count && ok; i++)
        ok = vcs_score_set_add(set, scan.units.items[i],
                               strlen(scan.units.items[i]));
    vcs_score_file_scan_free(&scan);
    if (!ok)
        LOG_FAIL(SCORE_LOG, "absorb %s into lineage", path ? path : "?");
    return ok;
}

/* ── release scoring ────────────────────────────────────────────────── */

struct score_unit_ref {
    const char *unit;  /* borrowed from a file scan (NUL-terminated) */
    uint32_t file_index;
    bool is_test;
};

static int score_unit_ref_cmp(const void *a, const void *b)
{
    const struct score_unit_ref *ra = a;
    const struct score_unit_ref *rb = b;
    int r = strcmp(ra->unit, rb->unit);
    if (r != 0)
        return r;
    if (ra->file_index < rb->file_index)
        return -1;
    if (ra->file_index > rb->file_index)
        return 1;
    /* A test-weighted duplicate sorts before a source-weighted one so the
     * representative occurrence earns the higher weight. */
    return (int)rb->is_test - (int)ra->is_test;
}

/* Capacity for the unit-reference array: doubles, starting at 64. */
static size_t score_refs_next_cap(size_t ref_cap)
{
    return ref_cap ? ref_cap * 2u : 64u;
}

/* Appends the units of one scanned file as references. False when the
 * array cannot grow; the caller logs the attempted capacity. */
static bool score_refs_add_file(struct score_unit_ref **refs,
                                size_t *ref_count, size_t *ref_cap,
                                const struct vcs_score_file_scan *scan,
                                uint32_t file_index)
{
    bool is_test = scan->kind == VCS_SCORE_FILE_TEST;
    for (size_t j = 0; j < scan->units.count; j++) {
        if (*ref_count == *ref_cap) {
            size_t ncap = score_refs_next_cap(*ref_cap);
            struct score_unit_ref *nrefs =
                zcl_realloc(*refs, ncap * sizeof(*nrefs),
                            "score_unit_refs");
            if (!nrefs)
                return false;
            *refs = nrefs;
            *ref_cap = ncap;
        }
        (*refs)[*ref_count].unit = scan->units.items[j];
        (*refs)[*ref_count].file_index = file_index;
        (*refs)[*ref_count].is_test = is_test;
        (*ref_count)++;
    }
    return true;
}

static void score_release_tally_units(struct score_unit_ref *refs,
                                      size_t ref_count,
                                      const struct vcs_score_set *lineage,
                                      struct vcs_score_release *out)
{
    if (ref_count > 1)
        qsort(refs, ref_count, sizeof(*refs), score_unit_ref_cmp);
    for (size_t i = 0; i < ref_count;) {
        size_t j = i + 1;
        while (j < ref_count && strcmp(refs[j].unit, refs[i].unit) == 0)
            j++;
        /* refs[i] is the representative: earliest file, test weight
         * first. refs[i+1..j) are within-release duplicates. */
        out->units_total++;
        out->units_duplicate += (uint32_t)(j - i - 1u);
        bool rewarded = lineage &&
            vcs_score_set_contains(lineage, refs[i].unit,
                                   strlen(refs[i].unit));
        if (rewarded) {
            out->units_already_rewarded++;
        } else {
            uint32_t points = refs[i].is_test
                ? VCS_SCORE_TEST_LINE_POINTS
                : VCS_SCORE_SOURCE_LINE_POINTS;
            if (refs[i].is_test)
                out->new_test_units++;
            else
                out->new_source_units++;
            if (refs[i].file_index < out->file_report_count) {
                struct vcs_score_file_report *rep =
                    &out->files[refs[i].file_index];
                rep->new_units++;
                rep->points += points;
            }
        }
        i = j;
    }
}

static bool score_release_files_invalid(
    const struct vcs_score_input_file *files, size_t file_count)
{
    return !files && file_count > 0;
}

static bool score_lineage_unready(const struct vcs_score_set *lineage)
{
    return lineage && !lineage->finalized;
}

/* The report row for one input file, or NULL once the rows are full. */
static struct vcs_score_file_report *score_release_report_slot(
    struct vcs_score_release *out, const struct vcs_score_input_file *f)
{
    struct vcs_score_file_report *rep = NULL;
    if (out->file_report_count < VCS_SCORE_MAX_FILE_REPORTS) {
        rep = &out->files[out->file_report_count++];
        rep->path = f->path;
    } else {
        out->file_reports_truncated = true;
    }
    return rep;
}

static void score_release_skip_oversize(struct vcs_score_release *out,
                                        struct vcs_score_file_report *rep)
{
    if (rep) {
        rep->kind = VCS_SCORE_FILE_EXCLUDED;
        rep->reason = VCS_SCORE_EXCLUDE_OVERSIZE;
    }
    out->files_excluded++;
}

static void score_release_report_scan(struct vcs_score_file_report *rep,
                                      const struct vcs_score_file_scan *scan)
{
    if (rep) {
        rep->kind = scan->kind;
        rep->reason = scan->reason;
        rep->lines = scan->lines;
    }
}

static void score_release_tally_scan(struct vcs_score_release *out,
                                     const struct vcs_score_file_scan *scan)
{
    out->files_scored++;
    out->semantic_lines += scan->lines.semantic;
    out->blank_lines += scan->lines.blank;
    out->comment_lines += scan->lines.comment_only;
    out->brace_lines += scan->lines.brace_only;
}

static void score_release_free_work(struct vcs_score_file_scan *scans,
                                    size_t file_count,
                                    struct score_unit_ref *refs)
{
    for (size_t i = 0; i < file_count; i++)
        vcs_score_file_scan_free(&scans[i]);
    free(scans);
    free(refs);
}

static void score_release_finish(struct vcs_score_release *out,
                                 bool has_parent)
{
    out->raw_line_points =
        out->new_source_units * VCS_SCORE_SOURCE_LINE_POINTS +
        out->new_test_units * VCS_SCORE_TEST_LINE_POINTS;
    out->line_points = out->raw_line_points;
    if (out->line_points > VCS_SCORE_MAX_LINE_POINTS_PER_RELEASE) {
        out->line_points = VCS_SCORE_MAX_LINE_POINTS_PER_RELEASE;
        out->line_cap_applied = true;
    }

    if (!has_parent) {
        out->category = VCS_SCORE_CATEGORY_NEW_PACKAGE;
        out->category_base = VCS_SCORE_CATEGORY_NEW_PACKAGE_POINTS;
    } else if (out->new_source_units == 0 && out->new_test_units == 0) {
        out->category = VCS_SCORE_CATEGORY_NONE;
        out->category_base = 0;
    } else if (out->new_source_units > 0) {
        out->category = VCS_SCORE_CATEGORY_PACKAGE_UPDATE;
        out->category_base = VCS_SCORE_CATEGORY_PACKAGE_UPDATE_MIN;
    } else {
        out->category = VCS_SCORE_CATEGORY_TEST_CONTRIBUTION;
        out->category_base = VCS_SCORE_CATEGORY_TEST_CONTRIBUTION_MIN;
    }

    out->raw_total = out->category_base + out->line_points;
    out->total = out->raw_total;
    if (out->total > VCS_SCORE_MAX_TOTAL_PER_RELEASE) {
        out->total = VCS_SCORE_MAX_TOTAL_PER_RELEASE;
        out->release_cap_applied = true;
    }
}

bool vcs_score_release_compute(const struct vcs_score_input_file *files,
                               size_t file_count,
                               const struct vcs_score_set *lineage,
                               bool has_parent,
                               struct vcs_score_release *out)
{
    memset(out, 0, sizeof(*out));
    if (score_release_files_invalid(files, file_count)) {
        LOG_FAIL(SCORE_LOG, "null files with count %zu", file_count);
        return false;
    }
    if (score_lineage_unready(lineage)) {
        LOG_FAIL(SCORE_LOG, "lineage set not finalized");
        return false;
    }

    struct vcs_score_file_scan *scans = NULL;
    struct score_unit_ref *refs = NULL;
    size_t ref_count = 0;
    if (file_count > 0) {
        scans = zcl_calloc(file_count, sizeof(*scans), "score_scans");
        if (!scans) {
            LOG_FAIL(SCORE_LOG, "alloc %zu file scans", file_count);
            return false;
        }
    }

    size_t ref_cap = 0;
    bool scanned_ok = true;
    for (size_t i = 0; i < file_count && scanned_ok; i++) {
        const struct vcs_score_input_file *f = &files[i];
        struct vcs_score_file_report *rep =
            score_release_report_slot(out, f);
        if (f->declared_size > VCS_SCORE_MAX_FILE_BYTES) {
            /* Never read: excluded by the manifest-declared size. */
            score_release_skip_oversize(out, rep);
            continue;
        }
        size_t len = f->bytes ? f->len : 0;
        if (!vcs_score_scan_file(f->path, f->bytes, len, &scans[i])) {
            LOG_FAIL(SCORE_LOG, "scan file %zu", i);
            scanned_ok = false;
            break;
        }
        const struct vcs_score_file_scan *scan = &scans[i];
        score_release_report_scan(rep, scan);
        if (scan->kind == VCS_SCORE_FILE_EXCLUDED) {
            out->files_excluded++;
            continue;
        }
        score_release_tally_scan(out, scan);
        if (!score_refs_add_file(&refs, &ref_count, &ref_cap, scan,
                                 (uint32_t)i)) {
            size_t ncap = score_refs_next_cap(ref_cap);
            LOG_FAIL(SCORE_LOG, "grow unit refs to %zu", ncap);
            scanned_ok = false;
            break;
        }
    }

    if (scanned_ok)
        score_release_tally_units(refs, ref_count, lineage, out);
    score_release_free_work(scans, file_count, refs);
    if (!scanned_ok)
        return false;
    score_release_finish(out, has_parent);
    return true;
}

/* ── period caps ────────────────────────────────────────────────────── */

void vcs_score_apply_period_caps(const struct vcs_score_period_entry *history,
                                 size_t history_count,
                                 int64_t candidate_day,
                                 uint32_t candidate_score,
                                 struct vcs_score_period_caps *out)
{
    memset(out, 0, sizeof(*out));
    out->candidate_score = candidate_score;
    uint64_t week = 0;
    for (size_t i = 0; i < history_count; i++) {
        int64_t day = history[i].day;
        if (day == candidate_day)
            out->releases_today++;
        if (day <= candidate_day && day >= candidate_day - 6)
            week += history[i].score;
    }
    if (week > UINT32_MAX)
        week = UINT32_MAX;
    out->week_spent = (uint32_t)week;
    out->week_remaining = out->week_spent >= VCS_SCORE_MAX_PER_CONTRIBUTOR_WEEK
        ? 0
        : VCS_SCORE_MAX_PER_CONTRIBUTOR_WEEK - out->week_spent;

    uint32_t allowed = candidate_score < out->week_remaining
        ? candidate_score : out->week_remaining;
    out->weekly_cap_hit = allowed < candidate_score;
    if (out->releases_today >= VCS_SCORE_MAX_RELEASES_PER_DAY) {
        out->daily_release_cap_hit = true;
        allowed = 0;
    }
    out->allowed_score = allowed;
}
