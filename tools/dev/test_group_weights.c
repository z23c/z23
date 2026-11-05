/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Read, order by, and regenerate the expected per-group wall
 *          seconds that make the parallel runner dispatch longest-first. */

#include "test_group_weights.h"
#include "test_group_catalog.h"
#include "base/safe_alloc.h"
#include "json/json.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Catalog row of an exact full id, or SIZE_MAX. Linear: the weights file
 * holds tens of rows and the catalog about a thousand. */
static size_t weights_catalog_index(const char *full_id)
{
    size_t n = zcl_test_group_catalog_count();
    for (size_t i = 0; i < n; i++)
        if (strcmp(zcl_test_group_catalog_at(i), full_id) == 0)
            return i;
    return SIZE_MAX;
}

/* One "full_id<TAB>seconds" row. Comments, blank lines and anything else
 * are not rows. */
static bool weights_parse_line(char *line, const char **id, unsigned *seconds)
{
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\r')
        line[len - 1] = '\0';
    char *tab = strchr(line, '\t');
    if (line[0] == '#' || !tab || tab == line)
        return false;
    *tab = '\0';
    const char *num = tab + 1;
    if (num[0] < '0' || num[0] > '9')
        return false;
    char *end = NULL;
    errno = 0;
    unsigned long v = strtoul(num, &end, 10);
    if (errno != 0 || !end || *end != '\0' ||
        v > ZCL_TEST_GROUP_WEIGHT_MAX_SECONDS)
        return false;
    *id = line;
    *seconds = (unsigned)v;
    return true;
}

/* Read one line into buf. A line longer than the buffer is consumed whole
 * and reported as not a row, so its tail can never parse as a row. */
static bool weights_next_line(FILE *fp, char *buf, size_t cap, bool *fits)
{
    *fits = false;
    size_t used = 0;
    bool valid = true;
    int c;
    while ((c = fgetc(fp)) != EOF && c != '\n') {
        if (c == 0)
            valid = false;
        if (used < cap - 1)
            buf[used++] = (char)c;
        else
            valid = false;
    }
    buf[used] = '\0';
    *fits = valid && !ferror(fp);
    return c != EOF || used != 0;
}

size_t zcl_test_group_weights_read(const char *path, unsigned *out, size_t n)
{
    if (!out)
        return 0;
    memset(out, 0, n * sizeof(*out));
    if (!path || n != zcl_test_group_catalog_count())
        return 0;
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return 0;
    size_t applied = 0;
    char line[256];
    bool fits = false;
    while (weights_next_line(fp, line, sizeof(line), &fits)) {
        const char *id = NULL;
        unsigned seconds = 0;
        if (!fits || !weights_parse_line(line, &id, &seconds))
            continue;
        size_t idx = weights_catalog_index(id);
        if (idx == SIZE_MAX)
            continue;
        out[idx] = seconds;
        applied++;
    }
    (void)fclose(fp);
    return applied;
}

void zcl_test_group_order_longest_first(const unsigned *weights, size_t n,
                                        size_t *order)
{
    if (!order)
        return;
    for (size_t i = 0; i < n; i++)
        order[i] = i;
    if (!weights)
        return;
    /* Insertion sort, moving only past a STRICTLY lighter row: equal
     * weights never cross, so ties keep catalog order. */
    for (size_t a = 1; a < n; a++) {
        size_t key = order[a];
        size_t b = a;
        while (b > 0 && weights[order[b - 1]] < weights[key]) {
            order[b] = order[b - 1];
            b--;
        }
        order[b] = key;
    }
}

void zcl_test_group_order_failure_first(const unsigned *weights,
                                        const bool *priority, size_t n,
                                        size_t *order)
{
    zcl_test_group_order_longest_first(weights, n, order);
    if (!priority || !order) return;
    /* Stable partition retains the old weight/catalog order in both tiers. */
    for (size_t i = 1; i < n; i++) {
        size_t key = order[i], j = i;
        if (!priority[key]) continue;
        while (j && !priority[order[j - 1]]) {
            order[j] = order[j - 1];
            j--;
        }
        order[j] = key;
    }
}

/* ── Regeneration from a timing artifact ───────────────────────────────── */

enum { WEIGHTS_TIMING_MAX_BYTES = 16 * 1024 * 1024 };

static void weights_why(char *why, size_t why_len, const char *text)
{
    if (why && why_len > 0)
        snprintf(why, why_len, "%s", text);
}

static bool weights_load_timing(const char *path, struct json_value *doc,
                                char *why, size_t why_len)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        weights_why(why, why_len, "timing artifact cannot be opened");
        return false;
    }
    char *bytes = zcl_malloc(WEIGHTS_TIMING_MAX_BYTES,
                             "test_group_weights.timing");
    if (!bytes) {
        (void)fclose(fp);
        weights_why(why, why_len, "timing buffer allocation failed");
        return false;
    }
    size_t len = fread(bytes, 1, WEIGHTS_TIMING_MAX_BYTES, fp);
    bool complete = !ferror(fp) && feof(fp) && len < WEIGHTS_TIMING_MAX_BYTES;
    (void)fclose(fp);
    bool ok = complete && json_read(doc, bytes, len) &&
              doc->type == JSON_OBJ;
    free(bytes);
    if (!ok)
        weights_why(why, why_len, "timing artifact is incomplete or not JSON");
    return ok;
}

static bool weights_row_flag(const struct json_value *row, const char *key)
{
    const struct json_value *v = json_get(row, key);
    return v && v->type == JSON_BOOL && json_get_bool(v);
}

/* Measured seconds of one uncached, passing, registered row, else 0. */
static unsigned weights_row_seconds(const struct json_value *row, size_t *idx)
{
    const struct json_value *name = json_get(row, "name");
    const struct json_value *ms = json_get(row, "ms");
    const struct json_value *rc = json_get(row, "rc");
    if (!name || name->type != JSON_STR || !ms || ms->type != JSON_INT ||
        !rc || rc->type != JSON_INT || json_get_int(rc) != 0 ||
        !weights_row_flag(row, "measured") || weights_row_flag(row, "cached"))
        return 0;
    *idx = weights_catalog_index(json_get_str(name));
    int64_t v = json_get_int(ms);
    if (*idx == SIZE_MAX || v < 0 ||
        v > (int64_t)ZCL_TEST_GROUP_WEIGHT_MAX_SECONDS * 1000)
        return 0;
    return (unsigned)((v + 500) / 1000);
}

/* A cold run over at least half the catalog, or a refusal. */
static bool weights_timing_is_full(const struct json_value *doc,
                                   const struct json_value **rows,
                                   char *why, size_t why_len)
{
    const struct json_value *schema = json_get(doc, "schema");
    const struct json_value *cached = json_get(doc, "groups_cached");
    *rows = json_get(doc, "groups");
    if (!schema || schema->type != JSON_STR ||
        strcmp(json_get_str(schema), "zcl.test_timing.v1") != 0 ||
        !*rows || (*rows)->type != JSON_ARR) {
        weights_why(why, why_len, "not a zcl.test_timing.v1 artifact");
        return false;
    }
    if (!cached || cached->type != JSON_INT || json_get_int(cached) != 0) {
        weights_why(why, why_len, "run reused cached verdicts; need a cold run");
        return false;
    }
    if (json_size(*rows) * 2 < zcl_test_group_catalog_count()) {
        weights_why(why, why_len,
                    "run measured under half the catalog; need a full run");
        return false;
    }
    return true;
}

static size_t weights_collect(const struct json_value *rows, unsigned *w)
{
    size_t kept = 0;
    for (size_t i = 0; i < json_size(rows); i++) {
        size_t idx = SIZE_MAX;
        unsigned s = weights_row_seconds(json_at(rows, i), &idx);
        if (s < ZCL_TEST_GROUP_WEIGHT_MIN_SECONDS || w[idx] != 0)
            continue;
        w[idx] = s;
        kept++;
    }
    return kept;
}

/* The source run's timestamp, only when it is a plain UTC stamp: it lands in
 * a comment line and must never be able to end it. */
static const char *weights_source_label(const char *utc)
{
    size_t len = utc ? strlen(utc) : 0;
    if (len == 0 || len > 32 || strspn(utc, "0123456789-:TZ") != len)
        return "unknown";
    return utc;
}

static bool weights_write_rows(FILE *fp, const unsigned *w, size_t n,
                               const char *source_utc)
{
    fprintf(fp,
            "# Copyright 2026 Rhett Creighton - Apache License 2.0\n"
            "# GENERATED by `make test-group-weights-regen` from the\n"
            "# .cache/test-timing/last-run.json of a full cold run. Do not\n"
            "# hand-edit. Source run: %s.\n"
            "#\n"
            "# Expected wall seconds per test group, >= %u s only; every other\n"
            "# group weighs 0. build/bin/test_parallel dispatches its parallel\n"
            "# phases longest-expected-first (ties keep catalog order). This\n"
            "# orders dispatch only: it never selects, skips, isolates or\n"
            "# retimes a group. A missing, malformed or unknown row weighs 0.\n",
            source_utc, ZCL_TEST_GROUP_WEIGHT_MIN_SECONDS);
    for (size_t i = 0; i < n; i++)
        if (w[i] != 0)
            fprintf(fp, "%s\t%u\n", zcl_test_group_catalog_at(i), w[i]);
    return ferror(fp) == 0;
}

static bool weights_publish(const char *out_path, const unsigned *w, size_t n,
                            const char *source_utc, char *why, size_t why_len)
{
    char tmp[4096];
    int len = snprintf(tmp, sizeof(tmp), "%s.tmp", out_path);
    FILE *fp = (len > 0 && (size_t)len < sizeof(tmp)) ? fopen(tmp, "wb") : NULL;
    if (!fp) {
        weights_why(why, why_len, "weights output cannot be created");
        return false;
    }
    bool ok = weights_write_rows(fp, w, n, source_utc);
    if (fclose(fp) != 0)
        ok = false;
#if defined(_WIN32)
    if (ok)
        (void)remove(out_path);
#endif
    if (!ok || rename(tmp, out_path) != 0) {
        (void)remove(tmp);
        weights_why(why, why_len, "weights output write failed");
        return false;
    }
    return true;
}

bool zcl_test_group_weights_render(const char *timing_path,
                                   const char *out_path, size_t *rows_out,
                                   char *why, size_t why_len)
{
    if (rows_out)
        *rows_out = 0;
    if (!timing_path || !out_path) {
        weights_why(why, why_len, "timing and output paths are required");
        return false;
    }
    struct json_value doc;
    json_init(&doc);
    const struct json_value *rows = NULL;
    size_t n = zcl_test_group_catalog_count();
    unsigned *w = zcl_calloc(n ? n : 1, sizeof(*w),
                             "test_group_weights.table");
    bool ok = w && weights_load_timing(timing_path, &doc, why, why_len) &&
              weights_timing_is_full(&doc, &rows, why, why_len);
    if (!w)
        weights_why(why, why_len, "weights table allocation failed");
    if (ok) {
        const char *utc = json_get_str(json_get(&doc, "generated_at_utc"));
        size_t kept = weights_collect(rows, w);
        ok = weights_publish(out_path, w, n, weights_source_label(utc),
                             why, why_len);
        if (ok && rows_out)
            *rows_out = kept;
    }
    free(w);
    json_free(&doc);
    return ok;
}
