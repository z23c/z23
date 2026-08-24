/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native SLO evidence fold.  Peak input is a fixed tail and a checked sample
 * arena; sorting is O(n log n).  Incomplete EOF rows never reach the folder,
 * malformed primitives never become samples, and a partial observation
 * window can never report OK. */

// one-result-type-ok:bounded-reporter-json-bool — this file has no mutating
// or authority-bearing service result. Its bool exports are the diagnostics
// JSON-dumper convention: every internal failure is logged and callers carry
// either the rendered reporter snapshot or a named transport failure.

#include "services/slo_ledger_summary.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "services/evidence_ledger_row.h"
#include "util/log_macros.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

struct slo_sample {
    char instance[SLO_SUMMARY_INSTANCE_MAX + 1];
    int64_t ts;
    int64_t gap;
    uint32_t sequence;
    bool reachable;
    bool gap_known;
};

struct slo_scan {
    struct slo_sample *samples;
    size_t sample_count;
    uint64_t valid_rows;
    uint64_t ignored_rows;
    uint64_t malformed_rows;
    bool sample_overflow;
    bool instance_overflow;
    char instances[SLO_SUMMARY_INSTANCE_CAP][SLO_SUMMARY_INSTANCE_MAX + 1];
    size_t instance_count;
    const char *filter;
};

bool slo_ledger_instance_valid(const char *s)
{
    if (!s || !s[0])
        return false;
    size_t n = strlen(s);
    if (n > SLO_SUMMARY_INSTANCE_MAX)
        return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!isalnum(c) && c != '_' && c != '-' && c != '.')
            return false; // raw-return-ok:pure-instance-name-predicate
    }
    return true;
}

static bool add_instance(struct slo_scan *scan, const char *name)
{
    for (size_t i = 0; i < scan->instance_count; i++) {
        if (strcmp(scan->instances[i], name) == 0)
            return true;
    }
    if (scan->instance_count >= SLO_SUMMARY_INSTANCE_CAP) {
        scan->instance_overflow = true;
        return false;
    }
    evidence_copy_bounded(scan->instances[scan->instance_count],
                          sizeof(scan->instances[0]), name, strlen(name));
    scan->instance_count++;
    return true;
}

static void fold_row(const char *row, size_t len, void *opaque)
{
    struct slo_scan *scan = opaque;
    char instance[SLO_SUMMARY_INSTANCE_MAX + 2];
    int64_t ts = 0;
    bool reachable = false;

    int64_t gap = 0;
    bool gap_known = false;
    if (!evidence_row_flat_object_valid(row, len) ||
        !evidence_row_str(row, len, "instance", instance,
                          sizeof(instance)) ||
        !slo_ledger_instance_valid(instance) ||
        !evidence_row_int(row, len, "ts", &ts) || ts <= 0 ||
        !evidence_row_bool(row, len, "reachable", &reachable) ||
        (!(gap_known = evidence_row_int(row, len, "gap_vs_oracle", &gap)) &&
         !evidence_row_is_null(row, len, "gap_vs_oracle"))) {
        scan->malformed_rows++;
        return;
    }
    scan->valid_rows++;
    if (scan->filter && strcmp(scan->filter, instance) != 0) {
        scan->ignored_rows++;
        return;
    }
    if (!add_instance(scan, instance)) {
        scan->ignored_rows++;
        return;
    }
    if (scan->sample_count >= SLO_SUMMARY_SAMPLE_CAP) {
        scan->sample_overflow = true;
        return;
    }

    struct slo_sample *sample = &scan->samples[scan->sample_count];
    evidence_copy_bounded(sample->instance, sizeof(sample->instance),
                          instance, strlen(instance));
    sample->ts = ts;
    sample->reachable = reachable;
    sample->sequence = (uint32_t)scan->sample_count;
    sample->gap_known = gap_known;
    sample->gap = gap;
    scan->sample_count++;
}

static int compare_samples(const void *av, const void *bv)
{
    const struct slo_sample *a = av;
    const struct slo_sample *b = bv;
    int by_name = strcmp(a->instance, b->instance);
    if (by_name != 0)
        return by_name;
    if (a->ts < b->ts)
        return -1; // raw-return-ok:qsort-comparator
    if (a->ts > b->ts)
        return 1;
    if (a->sequence < b->sequence)
        return -1; // raw-return-ok:qsort-comparator
    return a->sequence > b->sequence ? 1 : 0;
}

static bool push_null(struct json_value *obj, const char *key)
{
    struct json_value value;
    json_init(&value);
    json_set_null(&value);
    bool ok = json_push_kv(obj, key, &value);
    json_free(&value);
    return ok;
}

static int verdict_rank(const char *verdict)
{
    if (strcmp(verdict, "OK") == 0) return 0;
    if (strcmp(verdict, "DEGRADED") == 0) return 1;
    if (strcmp(verdict, "INCOMPLETE_WINDOW") == 0) return 2;
    if (strcmp(verdict, "NO_DATA") == 0) return 3;
    if (strcmp(verdict, "STALE") == 0) return 4;
    if (strcmp(verdict, "CLOCK_SKEW") == 0) return 5;
    return 6; /* INVALID_EVIDENCE */
}

static bool push_summary(struct slo_scan *scan, const char *instance,
                         unsigned hours, int64_t now, bool global_invalid,
                         struct json_value *summaries,
                         const char **out_verdict, const char **out_reason)
{
    size_t begin = 0;
    while (begin < scan->sample_count &&
           strcmp(scan->samples[begin].instance, instance) < 0)
        begin++;
    size_t end = begin;
    while (end < scan->sample_count &&
           strcmp(scan->samples[end].instance, instance) == 0)
        end++;

    const char *verdict = "NO_DATA";
    const char *reason = "no_complete_samples_for_instance";
    int64_t latest = -1;
    int64_t age = -1;
    int64_t cutoff = -1;
    size_t first = end;
    size_t count = 0;
    size_t reachable_count = 0;
    bool gap_known = false;
    int64_t max_gap = 0;
    size_t best_run = 0;
    int64_t best_run_sec = 0;
    bool window_complete = false;

    if (begin < end) {
        latest = scan->samples[end - 1].ts;
        cutoff = latest - (int64_t)hours * 3600;
        first = begin;
        while (first < end && scan->samples[first].ts < cutoff)
            first++;
        count = end - first;
        age = now - latest;
        window_complete = scan->samples[begin].ts <= cutoff;

        size_t run = 0;
        int64_t run_start = 0;
        for (size_t i = first; i < end; i++) {
            const struct slo_sample *sample = &scan->samples[i];
            if (sample->reachable) {
                reachable_count++;
                if (sample->gap_known &&
                    (!gap_known || sample->gap > max_gap)) {
                    gap_known = true;
                    max_gap = sample->gap;
                }
                if (run > 0) {
                    int64_t seconds = scan->samples[i - 1].ts - run_start;
                    if (run > best_run ||
                        (run == best_run && seconds > best_run_sec)) {
                        best_run = run;
                        best_run_sec = seconds;
                    }
                }
                run = 0;
            } else {
                if (run == 0)
                    run_start = sample->ts;
                run++;
            }
        }
        if (run > 0) {
            int64_t seconds = scan->samples[end - 1].ts - run_start;
            if (run > best_run ||
                (run == best_run && seconds > best_run_sec)) {
                best_run = run;
                best_run_sec = seconds;
            }
        }

        double pct = count ? 100.0 * (double)reachable_count /
                                     (double)count : 0.0;
        if (global_invalid) {
            verdict = "INVALID_EVIDENCE";
            reason = "malformed_or_capacity_exceeded";
        } else if (age < 0) {
            verdict = "CLOCK_SKEW";
            reason = "latest_sample_is_in_the_future";
        } else if (age > SLO_SUMMARY_STALE_SECONDS) {
            verdict = "STALE";
            reason = "latest_complete_sample_is_stale";
        } else if (!window_complete) {
            verdict = "INCOMPLETE_WINDOW";
            reason = "requested_window_not_covered";
        } else if (pct < 99.0) {
            verdict = "DEGRADED";
            reason = "reachable_pct_below_99";
        } else {
            verdict = "OK";
            reason = "nominal";
        }
    } else if (global_invalid) {
        verdict = "INVALID_EVIDENCE";
        reason = "malformed_or_capacity_exceeded";
    }

    struct json_value one;
    json_init(&one);
    json_set_object(&one);
    bool ok = json_push_kv_str(&one, "instance", instance) &&
              json_push_kv_int(&one, "window_hours", hours) &&
              json_push_kv_bool(&one, "window_complete", window_complete) &&
              json_push_kv_int(&one, "probe_count", (int64_t)count) &&
              json_push_kv_int(&one, "reachable_count",
                               (int64_t)reachable_count) &&
              json_push_kv_real(&one, "reachable_pct",
                                count ? 100.0 * (double)reachable_count /
                                        (double)count : 0.0) &&
              (gap_known ? json_push_kv_int(&one, "max_gap_vs_oracle",
                                            max_gap)
                         : push_null(&one, "max_gap_vs_oracle")) &&
              json_push_kv_int(&one, "longest_unreachable_run_probes",
                               (int64_t)best_run) &&
              json_push_kv_int(&one, "longest_unreachable_run_sec",
                               best_run_sec) &&
              json_push_kv_int(&one, "last_sample_ts", latest) &&
              json_push_kv_int(&one, "last_sample_age_sec", age) &&
              json_push_kv_str(&one, "verdict", verdict) &&
              json_push_kv_str(&one, "reason", reason) &&
              json_push_back(summaries, &one);
    json_free(&one);
    if (!ok)
        LOG_FAIL("slo_evidence", "could not allocate instance summary JSON");
    *out_verdict = verdict;
    *out_reason = reason;
    return true;
}

bool slo_ledger_summary_render_path(const char *path, const char *instance,
                                    unsigned window_hours, int64_t now_unix,
                                    struct json_value *out)
{
    if (!path || !path[0])
        LOG_FAIL("slo_evidence", "ledger path is NULL/empty");
    if (!out)
        LOG_FAIL("slo_evidence", "JSON output is NULL");
    if (window_hours == 0 || window_hours > SLO_SUMMARY_MAX_HOURS)
        LOG_FAIL("slo_evidence", "window_hours=%u outside 1..%u",
                 window_hours, SLO_SUMMARY_MAX_HOURS);
    if (instance && instance[0] && !slo_ledger_instance_valid(instance))
        LOG_FAIL("slo_evidence", "invalid instance name '%s'", instance);

    struct slo_scan scan = {0};
    scan.filter = instance && instance[0] ? instance : NULL;
    scan.samples = zcl_calloc(SLO_SUMMARY_SAMPLE_CAP,
                              sizeof(*scan.samples), "slo evidence samples");
    if (!scan.samples)
        LOG_FAIL("slo_evidence", "could not allocate bounded sample arena");

    if (scan.filter) {
        (void)add_instance(&scan, scan.filter);
    } else {
        /* Required public-node lanes remain visible when their recorder is
         * silent; observed retired/custom lanes are appended below. */
        (void)add_instance(&scan, "canonical");
        (void)add_instance(&scan, "dev");
    }

    unsigned overlong = 0;
    unsigned incomplete = 0;
    bool scanned = evidence_ledger_scan_tail(
        path, SLO_LEDGER_TAIL_BYTES, fold_row, &scan,
        &overlong, &incomplete);
    if (!scanned) {
        free(scan.samples);
        LOG_FAIL("slo_evidence", "bounded ledger scan rejected '%s'", path);
    }
    scan.malformed_rows += overlong;
    qsort(scan.samples, scan.sample_count, sizeof(*scan.samples),
          compare_samples);

    bool tail_truncated = false;
    struct stat st;
    if (stat(path, &st) == 0 && st.st_size > (off_t)SLO_LEDGER_TAIL_BYTES)
        tail_truncated = true;
    bool invalid = scan.malformed_rows > 0 || scan.sample_overflow ||
                   scan.instance_overflow;

    json_set_object(out);
    struct json_value summaries;
    json_init(&summaries);
    json_set_array(&summaries);
    const char *overall = "OK";
    const char *overall_reason = "nominal";
    int overall_rank = 0;
    for (size_t i = 0; i < scan.instance_count; i++) {
        const char *verdict = NULL;
        const char *reason = NULL;
        if (!push_summary(&scan, scan.instances[i], window_hours, now_unix,
                          invalid, &summaries, &verdict, &reason)) {
            json_free(&summaries);
            free(scan.samples);
            return false;
        }
        int rank = verdict_rank(verdict);
        if (rank > overall_rank) {
            overall_rank = rank;
            overall = verdict;
            overall_reason = reason;
        }
    }

    bool ok = json_push_kv_str(out, "schema", "zcl.slo_evidence.v1") &&
              json_push_kv_bool(out, "reporter_only", true) &&
              json_push_kv_bool(out, "node_free", true) &&
              json_push_kv_str(out, "ledger_path", path) &&
              json_push_kv_int(out, "tail_byte_budget",
                               SLO_LEDGER_TAIL_BYTES) &&
              json_push_kv_int(out, "sample_capacity",
                               SLO_SUMMARY_SAMPLE_CAP) &&
              json_push_kv_int(out, "rows_scanned",
                               (int64_t)scan.valid_rows) &&
              json_push_kv_int(out, "ignored_rows",
                               (int64_t)scan.ignored_rows) &&
              json_push_kv_int(out, "malformed_rows",
                               (int64_t)scan.malformed_rows) &&
              json_push_kv_int(out, "incomplete_rows", incomplete) &&
              json_push_kv_bool(out, "tail_truncated", tail_truncated) &&
              json_push_kv_bool(out, "sample_overflow",
                                scan.sample_overflow) &&
              json_push_kv_bool(out, "instance_overflow",
                                scan.instance_overflow) &&
              json_push_kv_int(out, "captured_at", now_unix) &&
              json_push_kv_str(out, "verdict", overall) &&
              json_push_kv_str(out, "reason", overall_reason) &&
              json_push_kv(out, "summaries", &summaries);
    if (ok)
        diag_push_health(out, strcmp(overall, "OK") == 0, overall_reason);
    json_free(&summaries);
    free(scan.samples);
    if (!ok)
        LOG_FAIL("slo_evidence", "could not allocate summary JSON");
    return true;
}

bool slo_ledger_summary_render(const char *instance, unsigned window_hours,
                               int64_t now_unix, struct json_value *out)
{
    char path[1024];
    if (!evidence_ledger_resolve_path("ZCL_SLO_LEDGER_DIR",
                                      ".local/state/zclassic23-slo",
                                      "uptime-ledger.jsonl", path,
                                      sizeof(path)))
        LOG_FAIL("slo_evidence", "could not resolve uptime ledger path");
    return slo_ledger_summary_render_path(path, instance, window_hours,
                                          now_unix, out);
}

bool slo_evidence_dump_state_json(struct json_value *out, const char *key)
{
    return slo_ledger_summary_render(
        key, SLO_SUMMARY_DEFAULT_HOURS,
        (int64_t)platform_time_wall_time_t(), out);
}
