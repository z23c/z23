/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The corpus measurement. Reasoning is in science/science_corpus.h.
 *
 * Two independent readings, never blended:
 *   walk_tree()      counts files, lines and bytes in the checkout NOW
 *   read_inventory() counts proof and duplication from the generated artifact
 * and scope_agrees says whether they were looking at the same tree.
 *
 * The walk goes through platform/modules/platform's directory seam rather than dirent so
 * this file carries no platform conditional at all.
 */

#include "science/science_corpus.h"

#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/directory_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { SCIENCE_CORPUS_PATH_MAX = 4096 };

/* Shared with the capability inventory and code navigator. */
static const char *const k_roots[] = {
#define SOURCE_ROOT(name_) name_,
#include "../../../../engine/composition/source_roots.def"
#undef SOURCE_ROOT
};

/* Also mirrored from the inventory scan. Build output, vendored third-party
 * code and scratch trees are not this project's corpus, and counting them
 * would inflate the line total with lines nobody here has to prove. */
static bool prune_dir(const char *name)
{
#define SOURCE_PRUNE_DIR(name_) if (strcmp(name, name_) == 0) return true;
#include "../../../../engine/composition/source_prune_dirs.def"
#undef SOURCE_PRUNE_DIR
    return strncmp(name, "test-tmp", 8) == 0;
}

static bool is_c23_source(const char *name)
{
    const size_t n = strlen(name);
    return n >= 3 && name[n - 2] == '.' &&
           (name[n - 1] == 'c' || name[n - 1] == 'h');
}

/* Count newlines and bytes. A final line with no terminating newline still
 * counts as a line: it is a line of code either way. */
static bool count_file(const char *path, uint64_t *lines, uint64_t *bytes)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    char buf[65536];
    size_t got;
    uint64_t nl = 0, total = 0;
    int last = '\n';
    while ((got = fread(buf, 1, sizeof buf, f)) > 0) {
        total += got;
        for (size_t i = 0; i < got; i++)
            if (buf[i] == '\n')
                nl++;
        last = (unsigned char)buf[got - 1];
    }
    const bool ok = ferror(f) == 0;
    fclose(f);
    if (!ok)
        return false;
    if (total > 0 && last != '\n')
        nl++;
    *lines += nl;
    *bytes += total;
    return true;
}

static bool walk_dir(const char *root, const char *rel,
                     struct science_corpus_report *out)
{
    char full[SCIENCE_CORPUS_PATH_MAX];
    int n = snprintf(full, sizeof full, "%s/%s", root, rel);
    if (n <= 0 || (size_t)n >= sizeof full)
        return false;

    struct platform_directory_list files = { 0 };
    if (platform_directory_list_regular_sorted(full, &files)) {
        for (size_t i = 0; i < files.count; i++) {
            const char *name = files.entries[i].name;
            if (!name || !is_c23_source(name))
                continue;
            char path[SCIENCE_CORPUS_PATH_MAX];
            int m = snprintf(path, sizeof path, "%s/%s", full, name);
            if (m <= 0 || (size_t)m >= sizeof path) {
                platform_directory_list_free(&files);
                LOG_FAIL("science.corpus", "path too long under %s", full);
            }
            if (!count_file(path, &out->lines, &out->bytes)) {
                platform_directory_list_free(&files);
                LOG_FAIL("science.corpus", "could not read %s", path);
            }
            out->files_walked++;
        }
    }
    platform_directory_list_free(&files);

    struct platform_directory_list dirs = { 0 };
    if (!platform_directory_list_real_sorted(full, &dirs))
        return true; /* not a directory, or unreadable: nothing to add */
    bool ok = true;
    for (size_t i = 0; ok && i < dirs.count; i++) {
        const char *name = dirs.entries[i].name;
        if (!name || prune_dir(name))
            continue;
        char child[SCIENCE_CORPUS_PATH_MAX];
        int m = snprintf(child, sizeof child, "%s/%s", rel, name);
        ok = m > 0 && (size_t)m < sizeof child && walk_dir(root, child, out);
    }
    platform_directory_list_free(&dirs);
    return ok;
}

/* ── the generated inventory artifact ────────────────────────────────── */

/* One line of the JSONL, however long. Returns false at EOF or on error;
 * *len is the line without its newline. The caller owns *buf across calls
 * and frees it once. */
static bool read_line(FILE *f, char **buf, size_t *cap, size_t *len)
{
    size_t used = 0;
    for (;;) {
        if (used + 1 >= *cap) {
            const size_t want = *cap ? *cap * 2 : 8192;
            char *grown = zcl_realloc(*buf, want, "science_corpus_line");
            if (!grown)
                return false;
            *buf = grown;
            *cap = want;
        }
        const int c = fgetc(f);
        if (c == EOF)
            break;
        if (c == '\n') {
            (*buf)[used] = '\0';
            *len = used;
            return true;
        }
        (*buf)[used++] = (char)c;
    }
    if (used == 0)
        return false;
    (*buf)[used] = '\0';
    *len = used;
    return true;
}

static bool line_is_record(const char *line, const char *kind)
{
    char want[64];
    const int n = snprintf(want, sizeof want, "{\"record\":\"%s\"", kind);
    return n > 0 && (size_t)n < sizeof want &&
           strncmp(line, want, (size_t)n) == 0;
}

static uint64_t count_token(const char *line, const char *token)
{
    uint64_t n = 0;
    const size_t tlen = strlen(token);
    for (const char *p = strstr(line, token); p; p = strstr(p + tlen, token))
        n++;
    return n;
}

/* Every number here is derived from the RECORDS, not from the artifact's own
 * summary line. A summary that disagreed with its own records would then show
 * up as a disagreement rather than being quoted as fact — except
 * files_scanned, which has no per-record form and is read from the summary
 * precisely so scope_agrees has something to compare against. */
static void read_inventory(const char *path, struct science_corpus_report *out)
{
    if (!path || !path[0])
        return;
    FILE *f = fopen(path, "rb");
    if (!f)
        return; /* absent is not zero: inventory_present stays false */

    char *line = NULL;
    size_t cap = 0, len = 0;
    bool saw_summary = false;
    while (read_line(f, &line, &cap, &len)) {
        if (line_is_record(line, "inventory")) {
            struct json_value root;
            if (json_read(&root, line, len)) {
                out->inventory_files_scanned =
                    (uint64_t)json_get_int(json_get(&root, "files_scanned"));
                out->inventory_production_files =
                    (uint64_t)json_get_int(json_get(&root, "production_files"));
                out->inventory_test_files =
                    (uint64_t)json_get_int(json_get(&root, "test_files"));
                json_free(&root);
                saw_summary = true;
            }
        } else if (line_is_record(line, "capability")) {
            out->capabilities++;
            out->symbols_test_reached += count_token(
                line, "\"test_evidence\":\"registered_test_reachable\"");
            out->symbols_test_source_only += count_token(
                line,
                "\"test_evidence\":\"test_source_reference_only_UNPROVEN\"");
            out->symbols_no_test +=
                count_token(line, "\"test_evidence\":\"none_UNPROVEN\"");
        } else if (line_is_record(line, "duplicate")) {
            out->duplicates++;
        } else if (line_is_record(line, "untested_invariant")) {
            out->untested_invariants++;
        }
    }
    free(line);
    fclose(f);

    out->symbols_exposed = out->symbols_test_reached +
                           out->symbols_test_source_only +
                           out->symbols_no_test;
    /* A file with no summary record is not an inventory we can scope-check,
     * so it does not count as present. */
    out->inventory_present = saw_summary;
}

/* ── public ──────────────────────────────────────────────────────────── */

bool science_corpus_measure(const char *root, const char *inventory_path,
                            struct science_corpus_report *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof *out);
    if (!root || !root[0])
        LOG_FAIL("science.corpus", "measure needs a source root");

    for (size_t i = 0; i < sizeof(k_roots) / sizeof(k_roots[0]); i++)
        if (!walk_dir(root, k_roots[i], out))
            LOG_FAIL("science.corpus", "walk of %s/%s failed", root,
                     k_roots[i]);

    read_inventory(inventory_path, out);
    out->scope_agrees = out->inventory_present &&
                        out->inventory_files_scanned == out->files_walked;
    return true;
}

int64_t science_corpus_proven_symbols_milli(
    const struct science_corpus_report *report)
{
    /* -1, never 0. "Nothing is proven" and "nobody measured" are different
     * facts and only one of them is an achievement to report. */
    if (!report || !report->inventory_present || report->symbols_exposed == 0)
        return -1;
    return (int64_t)(report->symbols_test_reached * 1000ull /
                     report->symbols_exposed);
}

int64_t science_corpus_goal_milli(const struct science_corpus_report *report)
{
    if (!report)
        return -1;
    if (report->lines >= SCIENCE_CORPUS_GOAL_LINES)
        return 1000;
    return (int64_t)(report->lines * 1000ull / SCIENCE_CORPUS_GOAL_LINES);
}

size_t science_corpus_headline(const struct science_corpus_report *report,
                               char *out, size_t cap)
{
    if (!report || !out || cap == 0)
        return 0;
    char buf[1024];
    int n;
    if (!report->inventory_present) {
        n = snprintf(buf, sizeof buf,
                     "%llu lines of C23 in %llu files. PROOF NOT MEASURED: "
                     "the capability inventory is absent, so the proven "
                     "fraction, the duplicate count and the untested-invariant "
                     "count are all unknown — not zero. Run "
                     "`make docs-capability-inventory`.",
                     (unsigned long long)report->lines,
                     (unsigned long long)report->files_walked);
    } else {
        const int64_t proven = science_corpus_proven_symbols_milli(report);
        const unsigned long long unproven =
            (unsigned long long)(report->symbols_exposed -
                                 report->symbols_test_reached);
        n = snprintf(
            buf, sizeof buf,
            "%llu of %llu public symbols (%lld.%01lld%%) are NOT reached by "
            "any registered test; %llu (%lld.%01lld%%) are. %llu lines of C23 "
            "in %llu files, %lld.%01lld%% of the %llu-line goal — a line count, "
            "not a proof count. %llu duplicate-body candidates and %llu "
            "declared invariants nothing asserts are corpus that counts "
            "AGAINST the goal.%s",
            unproven, (unsigned long long)report->symbols_exposed,
            (long long)((1000 - proven) / 10), (long long)((1000 - proven) % 10),
            (unsigned long long)report->symbols_test_reached,
            (long long)(proven / 10), (long long)(proven % 10),
            (unsigned long long)report->lines,
            (unsigned long long)report->files_walked,
            (long long)(science_corpus_goal_milli(report) / 10),
            (long long)(science_corpus_goal_milli(report) % 10),
            (unsigned long long)SCIENCE_CORPUS_GOAL_LINES,
            (unsigned long long)report->duplicates,
            (unsigned long long)report->untested_invariants,
            report->scope_agrees
                ? ""
                : " THE INVENTORY IS STALE: it counted a different number of "
                  "files than this walk found, so the proof figures describe "
                  "another tree. Run `make docs-capability-inventory`.");
    }
    if (n < 0 || (size_t)n >= sizeof buf || (size_t)n >= cap)
        return 0;
    memcpy(out, buf, (size_t)n + 1u);
    return (size_t)n;
}
