/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the verdict vector — the ordered (check name, outcome) sequence a
 * registered test group asserts — and its stable digest.
 *
 * WHY NOT HASH THE TRANSCRIPT. A group's captured output carries wall-clock
 * durations, temp-directory paths, process ids and pointer values printed by
 * ASSERT_EQ's %p fallback. Hashing those bytes measures the clock and the
 * address-space layout, not the test. Every run would differ and the measure
 * would be worthless.
 *
 * WHAT IS HASHED INSTEAD. The harness in lib/test/include/test/test_core.h
 * already emits the vector: TEST_CASE/TEST print "<name>... " and then exactly
 * one outcome word — OK, "FAIL at <file>:<line> ...", "SKIP (...)" or
 * "UNOBSERVED (...)". That ordered pair sequence IS what the group asserts, so
 * it is derived from output the tree already produces rather than requiring
 * ~1000 groups to be rewritten. It is stable by construction if and only if
 * the group is deterministic, and it detects the three failures that matter:
 *
 *   - a different answer          (an outcome flipped)
 *   - a different set of checks   (something ran only sometimes)
 *   - a different order           (an order dependence between checks)
 *
 * DELIBERATELY EXCLUDED FROM THE DIGEST. The values a failing ASSERT_EQ
 * prints, and the parenthesised reason on SKIP/UNOBSERVED. Both can contain a
 * pointer, a temp path or a pid. Including them would manufacture
 * non-determinism that is not the test's, and a determinism checker with false
 * positives is switched off within a week. A failure keeps only its
 * "<file>:<line>" locator, which names WHICH assertion failed without carrying
 * a runtime value.
 *
 * LOWER BOUND, STATED PLAINLY. A group that is wrong the same way every time
 * has a perfectly stable vector. This measures reproducibility, never
 * correctness. */
#ifndef ZCL_DETERMINISM_VERDICT_H
#define ZCL_DETERMINISM_VERDICT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "sha3/sha3.h"

#define ZCL_DET_NAME_MAX    256   /* check name, NUL-terminated */
#define ZCL_DET_LOCATOR_MAX 128   /* "<file>:<line>" of a failing assertion */
#define ZCL_DET_GROUP_MAX   96    /* longest registered full id is 55 today */
#define ZCL_DET_DIGEST_LEN  SHA3_256_OUTPUT_SIZE

enum zcl_det_outcome {
    ZCL_DET_OUTCOME_NONE = 0,
    ZCL_DET_OUTCOME_PASS = 1,
    ZCL_DET_OUTCOME_FAIL = 2,
    ZCL_DET_OUTCOME_SKIP = 3,
    ZCL_DET_OUTCOME_UNOBSERVED = 4,
};

/* One element of the vector. `name_len` is the ORIGINAL length before any
 * truncation into `name`, and is folded into the digest, so two distinct
 * over-long names sharing a 255-byte prefix still hash apart. */
struct zcl_det_check {
    char name[ZCL_DET_NAME_MAX];
    size_t name_len;
    enum zcl_det_outcome outcome;
    char locator[ZCL_DET_LOCATOR_MAX];
};

/* Streaming digest over the vector. Bounded memory: a group with 28,000
 * checks costs one sha3 context, never an array. */
struct zcl_det_vector {
    struct sha3_256_ctx ctx;
    uint32_t count;
    bool started;
};

const char *zcl_det_outcome_name(enum zcl_det_outcome outcome);

void zcl_det_vector_begin(struct zcl_det_vector *v);
bool zcl_det_vector_add(struct zcl_det_vector *v,
                        const struct zcl_det_check *check);
bool zcl_det_vector_finish(struct zcl_det_vector *v,
                           uint8_t out[ZCL_DET_DIGEST_LEN],
                           uint32_t *out_count);

/* Parse ONE transcript line into a COMPLETE check — name and outcome on the
 * same line. Returns false for every line that is not one, including a line
 * that only OPENS a check (see the stream machine below); ordinary test
 * chatter is ignored rather than guessed at. Leading whitespace is stripped;
 * a trailing CR is ignored. */
bool zcl_det_parse_check_line(const char *line, struct zcl_det_check *out);

/* ── the stream machine ───────────────────────────────────────────────────
 * TEST_CASE prints "<name>... " with NO newline and the outcome word only
 * when the case ends, so anything the test prints in between lands between
 * them. A line-at-a-time reader that only accepts "<name>... OK" therefore
 * sees NOTHING for every group that logs while a case is running — measured
 * on this tree, 91 of 1013 dispatched groups, which would have been reported
 * as "asserts nothing" when they assert plenty.
 *
 * So a check is OPENED by the line carrying its name and CLOSED by the next
 * line that is nothing but an outcome word. Two deliberate restrictions keep
 * that from turning into guesswork:
 *
 *   - a line may open a check only when none is open, so chatter cannot
 *     re-open one mid-case and steal its outcome;
 *   - a closing line must be ONLY the outcome ("OK" alone, or a line starting
 *     "FAIL"/"SKIP ("/"UNOBSERVED ("), never an outcome word embedded in
 *     prose.
 *
 * A check that is opened and never closed is DANGLING: it contributes nothing
 * to the digest and is counted separately, because a silently dropped check
 * would be a hole in the vector that nothing reported. */
struct zcl_det_stream {
    struct zcl_det_vector vec;
    char pending[ZCL_DET_NAME_MAX];
    size_t pending_len;
    bool has_pending;
    uint64_t dangling;
};

void zcl_det_stream_begin(struct zcl_det_stream *s);
bool zcl_det_stream_line(struct zcl_det_stream *s, const char *line);
bool zcl_det_stream_finish(struct zcl_det_stream *s,
                           uint8_t out[ZCL_DET_DIGEST_LEN],
                           uint32_t *out_count, uint64_t *out_dangling);

/* ── transcript scan ───────────────────────────────────────────────────────
 * `build/bin/test_parallel --verbose --no-cache` replays every dispatched
 * group's captured output in registry order behind a header line
 *   ==================== <group> (<status>, <n>s) ====================
 * so ONE suite run yields every group's vector. A group the runner never
 * dispatched simply has no header, which is the honest UNKNOWN signal — never
 * a silent skip. */

enum zcl_det_group_status {
    ZCL_DET_GROUP_UNKNOWN = 0,
    ZCL_DET_GROUP_PASS = 1,
    ZCL_DET_GROUP_FAIL = 2,
    ZCL_DET_GROUP_SIGNALED = 3,
    ZCL_DET_GROUP_WEDGED = 4,
};

struct zcl_det_group_digest {
    char group[ZCL_DET_GROUP_MAX];
    uint8_t digest[ZCL_DET_DIGEST_LEN];
    uint32_t check_count;
    enum zcl_det_group_status status;
};

/* Return false to abort the scan. */
typedef bool (*zcl_det_group_sink)(void *ctx,
                                   const struct zcl_det_group_digest *g);

struct zcl_det_scan_stats {
    uint64_t lines;
    uint64_t groups;
    uint64_t checks;
    uint64_t groups_without_vector;
    uint64_t dangling;   /* checks opened whose outcome never arrived */
};

bool zcl_det_transcript_scan(FILE *in, zcl_det_group_sink sink, void *ctx,
                             struct zcl_det_scan_stats *stats);

/* "<group>" and its status out of a replay header, or false if not a header. */
bool zcl_det_parse_group_header(const char *line, char *out_group,
                                size_t out_cap,
                                enum zcl_det_group_status *out_status);

void zcl_det_hex(const uint8_t *bytes, size_t len, char *out, size_t out_cap);
bool zcl_det_unhex(const char *hex, uint8_t *out, size_t out_len);

#endif /* ZCL_DETERMINISM_VERDICT_H */
