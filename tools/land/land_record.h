/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * land_record — the canonical bytes of a landing queue.
 *
 * WHY A CANONICAL ENCODING AND NOT A LINE OF TEXT
 * -----------------------------------------------
 * Every fact this queue records is evidence a person will later quote back:
 * "you said my branch landed", "you said it was refused, and why". The
 * receipts live in a chainlog (lib/chainlog), whose whole claim is that
 * nothing in the history can be edited without the edit showing. That claim
 * is only worth as much as the bytes it hashes. If the same submission could
 * be encoded two ways, two honest recorders would produce two different
 * chains for the same history, and the chain would prove nothing about
 * content — only about one recorder's formatting habits.
 *
 * So the encoding here is fixed: big-endian integers, explicit lengths, no
 * padding a caller may leave uninitialised, no locale, no float.
 *
 * WHAT IS DELIBERATELY ABSENT
 * ---------------------------
 * No timestamp and no filesystem path appears in any payload.
 *
 *   * ORDER comes from the chainlog's own dense `seq`. A timestamp in the
 *     payload would be a second, disagreeing answer to the same question:
 *     two boxes with skewed clocks would order the same history differently
 *     while both chains verified.
 *   * A PATH is a property of the machine that happened to run the lander,
 *     not of the submission. Recording one would mean the same submission
 *     encodes differently in a developer's worktree and on a fleet box,
 *     which breaks the "identical content, identical bytes" property the
 *     test group holds this file to.
 *
 * Wall-clock timing is still measured — the lander writes it to a plain
 * metrics journal beside the log. That journal is telemetry. It is not
 * evidence, it is not chained, and nothing reads a verdict out of it.
 *
 * WHAT EACH KIND MEANS
 * --------------------
 *   SUBMIT   an agent asked for a branch to be landed. Costs nothing and
 *            waits for nothing; this frame IS the queue entry.
 *   GATE_RUN one execution of the push gate over an integration branch, and
 *            the exact set of submissions that were merged into it. This is
 *            the frame that makes batching auditable: N submissions naming
 *            one GATE_RUN seq is the whole economy of the design.
 *   VERDICT  the lander's answer for one submission.
 *
 * THE FAIL-CLOSED RULE IS STRUCTURAL, NOT A COMMENT
 * -------------------------------------------------
 * A LANDED verdict names the GATE_RUN seq that justifies it, and
 * land_queue_check_landable() (land_queue.h) refuses to record one unless
 * that gate run exists, was GREEN, ran with the stress groups enabled, and
 * actually contained this submission. "The gate did not run" and "the gate
 * passed" are different facts, and there is no code path that turns the
 * first into the second.
 */

#ifndef ZCL_LAND_RECORD_H
#define ZCL_LAND_RECORD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Chainlog frame kinds. Never renumbered: a kind is on disk forever. */
#define LAND_KIND_SUBMIT   1u
#define LAND_KIND_GATE_RUN 2u
#define LAND_KIND_VERDICT  3u

#define LAND_RECORD_VERSION 1u

/* Bounds. Chosen so the largest frame is far below
 * ZCL_CHAINLOG_PAYLOAD_MAX and so every buffer here is a fixed array. */
#define LAND_BRANCH_MAX    128
#define LAND_SUBMITTER_MAX 64
#define LAND_NOTE_MAX      256
#define LAND_REASON_MAX    512
#define LAND_SHA_BYTES     20
#define LAND_SHA_HEX       40
#define LAND_MEMBERS_MAX   256

/* Where a submission is. QUEUED and GATING are live; the rest are final. */
enum land_state {
    LAND_STATE_QUEUED = 0,
    LAND_STATE_GATING = 1,
    LAND_STATE_LANDED = 2,
    LAND_STATE_REFUSED = 3,
    LAND_STATE_TIMEOUT = 4
};

enum land_gate_outcome {
    LAND_GATE_GREEN = 1,
    LAND_GATE_RED = 2,
    LAND_GATE_TIMEOUT = 3
};

const char *land_state_label(enum land_state s);
bool land_state_parse(const char *text, enum land_state *out);
const char *land_gate_outcome_label(enum land_gate_outcome o);
bool land_gate_outcome_parse(const char *text, enum land_gate_outcome *out);

struct land_submit {
    char branch[LAND_BRANCH_MAX + 1];
    char submitter[LAND_SUBMITTER_MAX + 1];
    char note[LAND_NOTE_MAX + 1];
    uint8_t head[LAND_SHA_BYTES];
};

struct land_gate_run {
    enum land_gate_outcome outcome;
    /* True only when the run had ZCL_STRESS_TESTS=1 in its environment. A
     * run without it skips whole groups, and `make pre-push-ci` itself
     * refuses such a receipt with reason=self_skips. A false here can never
     * justify a landing. */
    bool stress;
    uint8_t integration[LAND_SHA_BYTES];
    uint32_t member_count;
    uint64_t member_seq[LAND_MEMBERS_MAX];
};

struct land_verdict {
    enum land_state state;
    uint64_t submit_seq;
    uint64_t gate_run_seq; /* 0 when no gate run backs this verdict */
    char branch[LAND_BRANCH_MAX + 1];
    char reason[LAND_REASON_MAX + 1];
    uint8_t head[LAND_SHA_BYTES];
    uint8_t integration[LAND_SHA_BYTES]; /* all zero unless LANDED */
};

/* Encode into `buf`, returning the byte count, or 0 when the record does not
 * fit or holds a field over its bound. A 0 is never "empty record": there is
 * no valid encoding of length 0, so a caller cannot mistake one for the
 * other. */
size_t land_submit_encode(const struct land_submit *in, uint8_t *buf,
                          size_t cap);
size_t land_gate_run_encode(const struct land_gate_run *in, uint8_t *buf,
                            size_t cap);
size_t land_verdict_encode(const struct land_verdict *in, uint8_t *buf,
                           size_t cap);

/* Decode. False on any malformed input: a wrong version, a length that
 * overruns the frame, a trailing byte nobody claimed, a reserved field that
 * is not zero, or an enum outside its range. Trailing bytes are refused
 * rather than ignored so the encoding cannot grow a silent side channel. */
bool land_submit_decode(const uint8_t *buf, size_t len,
                        struct land_submit *out);
bool land_gate_run_decode(const uint8_t *buf, size_t len,
                          struct land_gate_run *out);
bool land_verdict_decode(const uint8_t *buf, size_t len,
                         struct land_verdict *out);

/* Lowercase hex <-> 20 raw bytes. Refuses anything that is not exactly 40
 * lowercase hex digits, so a short or uppercase sha is a refusal and never a
 * silently-different commit. */
bool land_sha_parse(const char *hex, uint8_t out[LAND_SHA_BYTES]);
void land_sha_format(const uint8_t in[LAND_SHA_BYTES],
                     char out[LAND_SHA_HEX + 1]);

/* The 32-byte chainlog stream id for a landing queue. Binds a queue log to
 * this purpose: opening it as any other stream is a STREAM_MISMATCH. */
void land_stream_id(uint8_t out[32]);

#endif /* ZCL_LAND_RECORD_H */
