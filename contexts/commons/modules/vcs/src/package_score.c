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

const char *vcs_score_line_class_string(enum vcs_score_line_class cls)
{
    switch (cls) {
    case VCS_SCORE_LINE_SEMANTIC: return "semantic";
    case VCS_SCORE_LINE_BLANK: return "blank";
    case VCS_SCORE_LINE_COMMENT_ONLY: return "comment-only";
    case VCS_SCORE_LINE_BRACE_ONLY: return "brace-only";
    }
    return "unknown";
}

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
            if (c == '*' && i + 1 < len && line[i + 1] == '/') {
                *in_block = false;
                i += 2;
            } else {
                i++;
            }
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
            uint8_t quote = c;
            saw_code = true;
            saw_nonbrace = true;
            cleaned_out[cleaned++] = c;
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
            continue;
        }
        saw_code = true;
        if (c != '{' && c != '}')
            saw_nonbrace = true;
        cleaned_out[cleaned++] = c;
        i++;
    }
    if (!saw_code && !saw_comment)
        out->cls = VCS_SCORE_LINE_BLANK;
    else if (!saw_code)
        out->cls = VCS_SCORE_LINE_COMMENT_ONLY;
    else if (!saw_nonbrace)
        out->cls = VCS_SCORE_LINE_BRACE_ONLY;
    else
        out->cls = VCS_SCORE_LINE_SEMANTIC;
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
    const char *seg = path;
    while (*seg) {
        const char *slash = strchr(seg, '/');
        size_t slen = slash ? (size_t)(slash - seg) : strlen(seg);
        if (score_segment_is(seg, slen, "vendor") ||
            score_segment_is(seg, slen, "vendored") ||
            score_segment_is(seg, slen, "third_party") ||
            score_segment_is(seg, slen, "third-party")) {
            *reason_out = VCS_SCORE_EXCLUDE_VENDORED;
            return VCS_SCORE_FILE_EXCLUDED;
        }
        if (score_segment_is(seg, slen, "generated")) {
            *reason_out = VCS_SCORE_EXCLUDE_GENERATED_PATH;
            return VCS_SCORE_FILE_EXCLUDED;
        }
        if (score_segment_is(seg, slen, "test") ||
            score_segment_is(seg, slen, "tests"))
            is_test = true;
        if (!slash)
            break;
        seg = slash + 1;
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

static bool score_unitizer_feed(struct score_unitizer *u,
                                struct vcs_score_set *units,
                                const uint8_t *cleaned, size_t len,
                                bool semantic)
{
    if (semantic && len > 0 && cleaned[0] == '#') {
        /* Preprocessor line: flush any pending statement, then the whole
         * line is one self-contained unit. */
        if (!score_unitizer_emit(u, units))
            return false;
        for (size_t i = 0; i < len; i++) {
            if (!score_unitizer_push(u, cleaned[i]))
                return false;
        }
        return score_unitizer_emit(u, units);
    }
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
        if (c == '(')
            u->paren_depth++;
        else if (c == ')' && u->paren_depth > 0)
            u->paren_depth--;
        if (!score_unitizer_push(u, c))
            return false;
    }
    return true;
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
            ok = score_unitizer_feed(&u, &out->units, cleaned,
                                     scan.cleaned_len, true);
            break;
        case VCS_SCORE_LINE_BRACE_ONLY:
            out->lines.brace_only++;
            ok = score_unitizer_feed(&u, &out->units, cleaned,
                                     scan.cleaned_len, false);
            break;
        case VCS_SCORE_LINE_BLANK: out->lines.blank++; break;
        case VCS_SCORE_LINE_COMMENT_ONLY: out->lines.comment_only++; break;
        }
        if (last)
            break;
        pos++;
    }
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

bool vcs_score_release_compute(const struct vcs_score_input_file *files,
                               size_t file_count,
                               const struct vcs_score_set *lineage,
                               bool has_parent,
                               struct vcs_score_release *out)
{
    memset(out, 0, sizeof(*out));
    if (!files && file_count > 0) {
        LOG_FAIL(SCORE_LOG, "null files with count %zu", file_count);
        return false;
    }
    if (lineage && !lineage->finalized) {
        LOG_FAIL(SCORE_LOG, "lineage set not finalized");
        return false;
    }

    struct vcs_score_file_scan *scans = NULL;
    struct score_unit_ref *refs = NULL;
    size_t ref_count = 0;
    bool ok = false;
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
        struct vcs_score_file_report *rep = NULL;
        if (out->file_report_count < VCS_SCORE_MAX_FILE_REPORTS) {
            rep = &out->files[out->file_report_count++];
            rep->path = f->path;
        } else {
            out->file_reports_truncated = true;
        }

        if (f->declared_size > VCS_SCORE_MAX_FILE_BYTES) {
            /* Never read: excluded by the manifest-declared size. */
            if (rep) {
                rep->kind = VCS_SCORE_FILE_EXCLUDED;
                rep->reason = VCS_SCORE_EXCLUDE_OVERSIZE;
            }
            out->files_excluded++;
            continue;
        }
        size_t len = f->bytes ? f->len : 0;
        if (!vcs_score_scan_file(f->path, f->bytes, len, &scans[i])) {
            LOG_FAIL(SCORE_LOG, "scan file %zu", i);
            scanned_ok = false;
            break;
        }
        const struct vcs_score_file_scan *scan = &scans[i];
        if (rep) {
            rep->kind = scan->kind;
            rep->reason = scan->reason;
            rep->lines = scan->lines;
        }
        if (scan->kind == VCS_SCORE_FILE_EXCLUDED) {
            out->files_excluded++;
            continue;
        }
        out->files_scored++;
        out->semantic_lines += scan->lines.semantic;
        out->blank_lines += scan->lines.blank;
        out->comment_lines += scan->lines.comment_only;
        out->brace_lines += scan->lines.brace_only;
        bool is_test = scan->kind == VCS_SCORE_FILE_TEST;
        for (size_t j = 0; j < scan->units.count; j++) {
            if (ref_count == ref_cap) {
                size_t ncap = ref_cap ? ref_cap * 2u : 64u;
                struct score_unit_ref *nrefs =
                    zcl_realloc(refs, ncap * sizeof(*nrefs),
                                "score_unit_refs");
                if (!nrefs) {
                    LOG_FAIL(SCORE_LOG, "grow unit refs to %zu", ncap);
                    scanned_ok = false;
                    break;
                }
                refs = nrefs;
                ref_cap = ncap;
            }
            refs[ref_count].unit = scan->units.items[j];
            refs[ref_count].file_index = (uint32_t)i;
            refs[ref_count].is_test = is_test;
            ref_count++;
        }
    }

    if (scanned_ok) {
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
        ok = true;
    }

    for (size_t i = 0; i < file_count; i++)
        vcs_score_file_scan_free(&scans[i]);
    free(scans);
    free(refs);
    if (!ok)
        return false;

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
