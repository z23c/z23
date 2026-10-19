/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Interface of the refold H* rate classifier and JSONL sample reader. */

#ifndef ZCL_TOOLS_REFOLD_RATE_VERDICT_H
#define ZCL_TOOLS_REFOLD_RATE_VERDICT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_REFOLD_RATE_MAX_SAMPLES 4096U
#define ZCL_REFOLD_RATE_MAX_LINES 8192U
#define ZCL_REFOLD_RATE_MAX_LINE_BYTES 511U
#define ZCL_REFOLD_RATE_MIN_BLOCKS_PER_SECOND 100
#define ZCL_REFOLD_RATE_RATIO_FLOOR_PER_MILLE 600

struct zcl_refold_rate_sample {
    int64_t monotonic_ns;
    int64_t hstar;
    int64_t wall_epoch_s; /* display metadata only; never used for rates */
};

enum zcl_refold_rate_verdict {
    ZCL_REFOLD_RATE_FLAT,
    ZCL_REFOLD_RATE_DECAYING,
    ZCL_REFOLD_RATE_NO_CLIMB,
    ZCL_REFOLD_RATE_INVALID_INPUT
};

struct zcl_refold_rate_result {
    enum zcl_refold_rate_verdict verdict;
    size_t samples;
    size_t intervals;
    size_t min_at; /* one-based, matching the historical proof output */
    int64_t climb;
    double overall_rate;
    double first_third_rate;
    double last_third_rate;
};

/* Pure classifier shared by the native `z23 ops debug refold verdict`
 * leaf and its registered test group. Every supplied monotonic timestamp
 * must be nonnegative and strictly greater than its predecessor. Nonpositive
 * intervals are invalid input; callers must never clamp them. */
enum zcl_refold_rate_verdict zcl_refold_rate_classify(
    const struct zcl_refold_rate_sample *samples, size_t count,
    struct zcl_refold_rate_result *result);

const char *zcl_refold_rate_verdict_name(enum zcl_refold_rate_verdict verdict);

/* Reads a JSONL sample file. Each record is at most
 * ZCL_REFOLD_RATE_MAX_LINE_BYTES bytes before its newline (or end of file),
 * contains no NUL byte, and carries integer `mono_ns` and `hstar` with an
 * optional integer `ts`. Blank lines and lines starting with # are skipped.
 * Returns false on any unreadable, malformed or over-bound input; `*count`
 * is then unspecified and no verdict may be derived. `samples` must hold
 * ZCL_REFOLD_RATE_MAX_SAMPLES entries. */
bool zcl_refold_rate_read_jsonl(const char *path,
                                struct zcl_refold_rate_sample *samples,
                                size_t *count);

#endif /* ZCL_TOOLS_REFOLD_RATE_VERDICT_H */
