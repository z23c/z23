/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * kpi_metrics — the metric table and the parsers behind it.
 *
 * Every parser here answers a THREE-valued question, not a two-valued one:
 * "the artifact says N", "the artifact says nothing and that is a real N=0",
 * or "I could not read the artifact". Only the first two produce a value. The
 * third returns false and the caller records UNAVAILABLE, because a ledger
 * that writes 0 for "I could not look" makes every later delta a fiction.
 *
 * None of these parsers is a JSON or Makefile parser and none pretends to be.
 * Each recognises exactly one shape in one artifact, refuses when it does not
 * find that shape, and says in kpi.h where the line between an honest 0 and an
 * unreadable artifact is drawn for that source.
 */

#include "kpi/kpi.h"

#include <stdio.h>
#include <string.h>

/* ── labels ──────────────────────────────────────────────────────────── */

const char *kpi_direction_label(enum kpi_direction d)
{
    switch (d) {
    case KPI_DIRECTION_NEUTRAL:          return "NEUTRAL";
    case KPI_DIRECTION_LOWER_IS_BETTER:  return "LOWER_IS_BETTER";
    case KPI_DIRECTION_HIGHER_IS_BETTER: return "HIGHER_IS_BETTER";
    }
    return "UNKNOWN_DIRECTION";
}

const char *kpi_state_label(enum kpi_state s)
{
    switch (s) {
    case KPI_STATE_PRESENT:     return "present";
    case KPI_STATE_UNAVAILABLE: return "unavailable";
    }
    return "unknown_state";
}

const char *kpi_verdict_label(enum kpi_verdict v)
{
    switch (v) {
    case KPI_VERDICT_UNAVAILABLE: return "unavailable";
    case KPI_VERDICT_NO_BASELINE: return "no_baseline";
    case KPI_VERDICT_UNCHANGED:   return "unchanged";
    case KPI_VERDICT_IMPROVED:    return "improved";
    case KPI_VERDICT_REGRESSED:   return "regressed";
    }
    return "unknown_verdict";
}

/* ── the metric table ────────────────────────────────────────────────────
 *
 * SORTED BY ID, and that order is the payload's field order. It is asserted
 * by test_kpi rather than left to whoever adds the next row, because a table
 * that silently stopped being sorted would change the canonical bytes for
 * unchanged values and break every comparison against an older frame.
 *
 * `drill` is the exact command a reader runs to see the rows behind the
 * number. It is data, not prose, so it cannot rot separately from the metric.
 */
static const struct kpi_metric_def k_metrics[] = {
    { "capabilities", KPI_DIRECTION_NEUTRAL,
      "docs/CAPABILITY_INVENTORY.jsonl", "z23 code have <name>" },
    { "cmd.help_pct", KPI_DIRECTION_HIGHER_IS_BETTER,
      "engine/composition/commands/catalog.def", "z23 discover describe <path>" },
    { "cmd.leaves", KPI_DIRECTION_NEUTRAL,
      "engine/composition/commands/catalog.def", "z23 discover describe <path>" },
    { "cmd.ready_pct", KPI_DIRECTION_HIGHER_IS_BETTER,
      "engine/composition/commands/catalog.def", "z23 discover describe <path>" },
    { "cmd.tested", KPI_DIRECTION_HIGHER_IS_BETTER,
      "engine/composition/commands/catalog.def", "z23 code tests <path>" },
    { "code.shell_scripts", KPI_DIRECTION_LOWER_IS_BETTER,
      "tools/lint/bash_allowlist.txt", "cat tools/lint/bash_allowlist.txt" },
    { "code.size_debt", KPI_DIRECTION_LOWER_IS_BETTER,
      "tools/lint/file_size_policy_baseline.txt",
      "cat tools/lint/file_size_policy_baseline.txt" },
    { "determinism_debt", KPI_DIRECTION_LOWER_IS_BETTER,
      "tools/lint/determinism_baseline.txt",
      "make check-determinism-ratchet" },
    { "docs.orphans", KPI_DIRECTION_LOWER_IS_BETTER,
      "tools/lint/orphan_placement_baseline.txt",
      "cat tools/lint/orphan_placement_baseline.txt" },
    { "duplicate_candidates", KPI_DIRECTION_LOWER_IS_BETTER,
      "docs/CAPABILITY_INVENTORY.jsonl", "z23 code have <name>" },
    { "files_owned", KPI_DIRECTION_NEUTRAL, "", "z23 code territory" },
    { "lint_gates", KPI_DIRECTION_NEUTRAL, "Makefile", "make lint" },
    { "territories", KPI_DIRECTION_NEUTRAL, "", "z23 code territory" },
    { "test_groups", KPI_DIRECTION_NEUTRAL,
      "tools/dev/test_group_catalog.def", "build/bin/test_parallel --list" },
    { "untested_invariants", KPI_DIRECTION_LOWER_IS_BETTER,
      "docs/CAPABILITY_INVENTORY.jsonl", "z23 code general" },
};

const struct kpi_metric_def *kpi_metric_defs(size_t *count)
{
    if (count)
        *count = sizeof k_metrics / sizeof k_metrics[0];
    return k_metrics;
}

const struct kpi_metric_def *kpi_metric_def_by_id(const char *id)
{
    if (!id)
        return NULL;
    for (size_t i = 0; i < sizeof k_metrics / sizeof k_metrics[0]; i++)
        if (strcmp(k_metrics[i].id, id) == 0)
            return &k_metrics[i];
    return NULL;
}

/* ── file scanning ───────────────────────────────────────────────────── */

enum {
    KPI_SCAN_CHUNK    = 16384,
    KPI_SCAN_CARRY    = 128,
    KPI_SCAN_PATS_MAX = 2,
    KPI_LINE_MAX      = 4096
};

/* Count occurrences of each pattern in one streaming pass. The trailing
 * (maxlen - 1) bytes of every chunk are carried into the next read, so a
 * pattern straddling a chunk boundary is found exactly once — never missed and
 * never double counted. Returns false on a missing file or a read error;
 * a zero count is a legitimate result and is NOT an error here. Whether zero
 * means "honest 0" or "unreadable shape" is the caller's judgement, and each
 * caller states its rule. */
static bool kpi_scan_counts(const char *path, const char *const *pats,
                            size_t npats, uint64_t *counts)
{
    if (!path || !pats || !counts || npats == 0 || npats > KPI_SCAN_PATS_MAX)
        return false;

    size_t plen[KPI_SCAN_PATS_MAX];
    size_t maxlen = 0;
    for (size_t i = 0; i < npats; i++) {
        if (!pats[i])
            return false;
        plen[i] = strlen(pats[i]);
        if (plen[i] == 0 || plen[i] > KPI_SCAN_CARRY)
            return false;
        if (plen[i] > maxlen)
            maxlen = plen[i];
        counts[i] = 0;
    }

    FILE *f = fopen(path, "rb");
    if (!f)
        return false;

    unsigned char buf[KPI_SCAN_CHUNK + KPI_SCAN_CARRY];
    size_t carry = 0;
    bool more = true;
    while (more) {
        size_t got = fread(buf + carry, 1, KPI_SCAN_CHUNK, f);
        if (got < (size_t)KPI_SCAN_CHUNK) {
            if (ferror(f)) {
                fclose(f);
                return false;
            }
            more = false;
        }
        size_t have = carry + got;
        size_t tail = more ? maxlen - 1 : 0;
        if (tail > have)
            tail = have;
        size_t stop = have - tail;
        for (size_t p = 0; p < stop; p++) {
            unsigned char c = buf[p];
            for (size_t i = 0; i < npats; i++) {
                if (c != (unsigned char)pats[i][0] || plen[i] > have - p)
                    continue;
                if (memcmp(buf + p, pats[i], plen[i]) == 0)
                    counts[i]++;
            }
        }
        if (tail > 0)
            memmove(buf, buf + have - tail, tail);
        carry = tail;
    }
    fclose(f);
    return true;
}

/* One logical line, newline stripped. A line longer than `cap` is truncated
 * and its remainder consumed, so the next call still starts on a real line
 * boundary; `*overlong` reports that it happened rather than hiding it.
 * Returns false at end of file. */
static bool kpi_read_line(FILE *f, char *buf, size_t cap, bool *overlong)
{
    if (overlong)
        *overlong = false;
    if (!f || !buf || cap < 2)
        return false;
    size_t n = 0;
    int c = fgetc(f);
    if (c == EOF)
        return false;
    while (c != EOF && c != '\n') {
        if (n + 1 < cap) {
            buf[n++] = (char)c;
        } else if (overlong) {
            *overlong = true;
        }
        c = fgetc(f);
    }
    buf[n] = '\0';
    return true;
}

static const char *kpi_skip_blanks(const char *s)
{
    while (*s == ' ' || *s == '\t')
        s++;
    return s;
}

/* ── the parsers ─────────────────────────────────────────────────────── */

bool kpi_count_jsonl_records(const char *path, const char *record,
                             uint64_t *out, uint64_t *out_total)
{
    if (!path || !record || !out)
        return false;

    char want[128];
    int wrote = snprintf(want, sizeof want, "\"record\":\"%s\"", record);
    if (wrote < 0 || (size_t)wrote >= sizeof want)
        return false;

    const char *pats[2] = { want, "\"record\":\"" };
    uint64_t counts[2] = { 0, 0 };
    if (!kpi_scan_counts(path, pats, 2, counts))
        return false;
    /* No `"record":"` field of ANY kind means this is not the artifact we
     * think it is — a shape we did not recognise, not a tree with nothing in
     * it. Refuse rather than report 0. */
    if (counts[1] == 0)
        return false;
    if (out_total)
        *out_total = counts[1];
    *out = counts[0];
    return true;
}

bool kpi_count_test_groups(const char *path, uint64_t *out)
{
    if (!path || !out)
        return false;
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;

    char line[KPI_LINE_MAX];
    uint64_t n = 0;
    /* Only a row that BEGINS with one of the macros counts. The catalog's own
     * header comment names both in prose, and a parser that matched anywhere
     * in a line would silently count the documentation.
     *
     * BOTH registry macros count, because the drill-down command counts both:
     * `test_parallel --list` prints one line per ZCL_TEST_GROUP row and one per
     * ZCL_SPEC_GROUP row. A metric whose drill-down disagrees with it is a
     * metric nobody can check, so the number is defined to be what the command
     * beside it prints. */
    static const char k_test[] = "ZCL_TEST_GROUP(";
    static const char k_spec[] = "ZCL_SPEC_GROUP(";
    while (kpi_read_line(f, line, sizeof line, NULL)) {
        const char *s = kpi_skip_blanks(line);
        if (strncmp(s, k_test, sizeof k_test - 1) == 0 ||
            strncmp(s, k_spec, sizeof k_spec - 1) == 0)
            n++;
    }
    bool bad = ferror(f) != 0;
    fclose(f);
    /* A catalog with no registered group is not a state this tree can reach;
     * it means the row shape moved. Refuse rather than report 0. */
    if (bad || n == 0)
        return false;
    *out = n;
    return true;
}

bool kpi_count_lint_gates(const char *makefile_path, uint64_t *out)
{
    if (!makefile_path || !out)
        return false;
    FILE *f = fopen(makefile_path, "rb");
    if (!f)
        return false;

    char line[KPI_LINE_MAX];
    uint64_t n = 0;
    bool found = false;
    bool bad = false;
    static const char k_var[] = "LINT_GATES";

    while (!found && kpi_read_line(f, line, sizeof line, NULL)) {
        /* Column zero only: a `LINT_GATES` mentioned inside a comment or a
         * recipe is prose about the list, not the list. */
        if (strncmp(line, k_var, sizeof k_var - 1) != 0)
            continue;
        const char *s = kpi_skip_blanks(line + sizeof k_var - 1);
        if (*s == ':' || *s == '+')
            s++;
        if (*s != '=')
            continue;
        found = true;
        s++;

        /* Walk the backslash-continued list, counting whitespace-separated
         * tokens. A `#` starts a make comment and ends the line's tokens. */
        bool more = true;
        while (more) {
            more = false;
            for (;;) {
                s = kpi_skip_blanks(s);
                if (*s == '\0')
                    break;
                if (*s == '#') {
                    while (*s != '\0')
                        s++;
                    break;
                }
                if (*s == '\\' && s[1] == '\0') {
                    more = true;
                    break;
                }
                n++;
                while (*s != '\0' && *s != ' ' && *s != '\t')
                    s++;
            }
            if (more) {
                if (!kpi_read_line(f, line, sizeof line, NULL)) {
                    more = false;
                    break;
                }
                s = line;
            }
        }
    }
    bad = ferror(f) != 0;
    fclose(f);
    /* Either the assignment moved or the list is empty; both mean we did not
     * read a gate list, and neither is honestly reported as 0 gates. */
    if (bad || !found || n == 0)
        return false;
    *out = n;
    return true;
}

bool kpi_count_baseline_rows(const char *path, uint64_t *out)
{
    if (!path || !out)
        return false;
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;

    char line[KPI_LINE_MAX];
    uint64_t n = 0;
    while (kpi_read_line(f, line, sizeof line, NULL)) {
        const char *s = kpi_skip_blanks(line);
        if (*s == '\0' || *s == '#' || *s == '\r')
            continue;
        n++;
    }
    bool bad = ferror(f) != 0;
    fclose(f);
    if (bad)
        return false;
    /* Zero is the GOAL STATE here, not a parse failure: an empty ratchet means
     * the tree owes no determinism debt. This is the one source where 0 is a
     * real answer, and reporting it UNAVAILABLE would hide a win. */
    *out = n;
    return true;
}


uint64_t kpi_pct_hundredths(uint64_t num, uint64_t den)
{
    return den == 0 ? 0 : (num * 10000u) / den;
}

/* ── groups ──────────────────────────────────────────────────────────── */

uint32_t kpi_metric_group(const char *id)
{
    if (!id)
        return KPI_GROUP_CODE;
    if (strncmp(id, "cmd.", 4) == 0)
        return KPI_GROUP_CMD;
    if (strncmp(id, "docs.", 5) == 0)
        return KPI_GROUP_DOCS;
    return KPI_GROUP_CODE;
}

bool kpi_group_parse(const char *name, uint32_t *mask)
{
    if (!mask)
        return false;
    if (!name || !name[0] || strcmp(name, "all") == 0)
        *mask = KPI_GROUP_ALL;
    else if (strcmp(name, "cmd") == 0)
        *mask = KPI_GROUP_CMD;
    else if (strcmp(name, "code") == 0)
        *mask = KPI_GROUP_CODE;
    else if (strcmp(name, "docs") == 0)
        *mask = KPI_GROUP_DOCS;
    else
        return false;
    return true;
}

/* ── collection ──────────────────────────────────────────────────────── */

/* What one measurement needs: the artifact path for the metric, and the
 * command catalog scan shared by the four cmd.* metrics (taken once). */
struct kpi_ctx {
    struct kpi_cmd_stats cmd;
    bool                 have_cmd;
};

typedef bool (*kpi_measure_fn)(const struct kpi_ctx *c, const char *path,
                               uint64_t *v);

static bool kpi_m_capabilities(const struct kpi_ctx *c, const char *path,
                               uint64_t *v)
{
    (void)c;
    return kpi_count_jsonl_records(path, "capability", v, NULL);
}

static bool kpi_m_duplicates(const struct kpi_ctx *c, const char *path,
                             uint64_t *v)
{
    (void)c;
    return kpi_count_jsonl_records(path, "duplicate", v, NULL);
}

static bool kpi_m_untested(const struct kpi_ctx *c, const char *path,
                           uint64_t *v)
{
    (void)c;
    return kpi_count_jsonl_records(path, "untested_invariant", v, NULL);
}

static bool kpi_m_groups(const struct kpi_ctx *c, const char *path,
                         uint64_t *v)
{
    (void)c;
    return kpi_count_test_groups(path, v);
}

static bool kpi_m_gates(const struct kpi_ctx *c, const char *path,
                        uint64_t *v)
{
    (void)c;
    return kpi_count_lint_gates(path, v);
}

static bool kpi_m_rows(const struct kpi_ctx *c, const char *path, uint64_t *v)
{
    (void)c;
    return kpi_count_baseline_rows(path, v);
}

static bool kpi_m_cmd_leaves(const struct kpi_ctx *c, const char *path,
                             uint64_t *v)
{
    (void)path;
    *v = c->cmd.leaves;
    return c->have_cmd;
}

static bool kpi_m_cmd_ready(const struct kpi_ctx *c, const char *path,
                            uint64_t *v)
{
    (void)path;
    *v = kpi_pct_hundredths(c->cmd.ready, c->cmd.leaves);
    return c->have_cmd;
}

static bool kpi_m_cmd_help(const struct kpi_ctx *c, const char *path,
                           uint64_t *v)
{
    (void)path;
    *v = kpi_pct_hundredths(c->cmd.help, c->cmd.leaves);
    return c->have_cmd;
}

static bool kpi_m_cmd_tested(const struct kpi_ctx *c, const char *path,
                             uint64_t *v)
{
    (void)path;
    *v = c->cmd.tested;
    return c->have_cmd && c->cmd.have_tested;
}

/* One entry per k_metrics row, same order. NULL means the metric comes from
 * the code index, which this file-only collection does not have. */
static const kpi_measure_fn k_measure[] = {
    kpi_m_capabilities, kpi_m_cmd_help,  kpi_m_cmd_leaves, kpi_m_cmd_ready,
    kpi_m_cmd_tested,   kpi_m_rows,      kpi_m_rows,       kpi_m_rows,
    kpi_m_rows,         kpi_m_duplicates, NULL,            kpi_m_gates,
    NULL,               kpi_m_groups,    kpi_m_untested,
};

_Static_assert(sizeof k_measure / sizeof k_measure[0] ==
                   sizeof k_metrics / sizeof k_metrics[0],
               "every metric row needs a measure entry");

static void kpi_join(char *buf, size_t cap, const char *root, const char *rel)
{
    if (!root || !root[0])
        root = ".";
    int wrote = snprintf(buf, cap, "%s/%s", root, rel);
    if (wrote < 0 || (size_t)wrote >= cap)
        buf[0] = '\0'; /* an unbuildable path opens nothing -> UNAVAILABLE */
}

static void kpi_set(struct kpi_frame *f, size_t slot, const char *id, bool ok,
                    uint64_t value)
{
    (void)snprintf(f->metric[slot].id, sizeof f->metric[slot].id, "%s", id);
    f->metric[slot].state = ok ? KPI_STATE_PRESENT : KPI_STATE_UNAVAILABLE;
    f->metric[slot].value = ok ? value : 0;
}

void kpi_collect_files(const char *root, uint32_t mask, struct kpi_frame *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof *out);

    size_t ndefs = 0;
    const struct kpi_metric_def *defs = kpi_metric_defs(&ndefs);
    if (ndefs > KPI_METRIC_MAX)
        ndefs = KPI_METRIC_MAX;
    out->count = (uint32_t)ndefs;

    struct kpi_ctx ctx;
    memset(&ctx, 0, sizeof ctx);
    if (mask & KPI_GROUP_CMD)
        ctx.have_cmd = kpi_cmd_scan(root, &ctx.cmd);

    char path[1024];
    for (size_t i = 0; i < ndefs; i++) {
        uint64_t v = 0;
        bool ok = false;
        kpi_join(path, sizeof path, root, defs[i].source);
        if ((kpi_metric_group(defs[i].id) & mask) && k_measure[i] &&
            path[0] != '\0')
            ok = k_measure[i](&ctx, path, &v);
        kpi_set(out, i, defs[i].id, ok, v);
    }
}

const struct kpi_entry *kpi_frame_find(const struct kpi_frame *f,
                                       const char *id)
{
    if (!f || !id)
        return NULL;
    for (uint32_t i = 0; i < f->count && i < KPI_METRIC_MAX; i++)
        if (strcmp(f->metric[i].id, id) == 0)
            return &f->metric[i];
    return NULL;
}
