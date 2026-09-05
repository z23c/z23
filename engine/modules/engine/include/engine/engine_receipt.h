/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * engine_receipt — the hash-chained record of what one dispatched unit cost
 * and what the gate then said about it.
 *
 * ── WHY A SECOND RECEIPT EXISTS ──────────────────────────────────────────
 * tools/engine_unit.c already writes <state-dir>/receipt.json: one object,
 * overwritten by the next run. It answers "how did THIS run go". It cannot
 * answer "is the fix-gate template better than the add-test template", "does
 * this model cost four times as much for the same green", or "did anything
 * change after we edited the rules", because every one of those is a
 * question about a SEQUENCE and the file holds one element.
 *
 * This is the sequence. One JSON object per line, appended, never rewritten.
 *
 * ── WHAT IT IS NOT ───────────────────────────────────────────────────────
 * It is SIGNAL, not judgement. Nothing here scores a template, retires a
 * rule, or picks an engine; a separate owner reads this file and decides.
 * A record grants nothing and permits nothing. It is a measurement of a run
 * that already happened, and the run's verdict was decided by the gate
 * before any of this was written.
 *
 * ── THE RECORD SHAPE ─────────────────────────────────────────────────────
 * schema `zcl.engine_unit_receipt.v1`. One line, one object, keys in this
 * order, integers as JSON integers and never as floats:
 *
 *   schema             "zcl.engine_unit_receipt.v1"
 *   prev_sha3          64 lowercase hex: SHA3-256 of the PREVIOUS line's
 *                      bytes, EXCLUDING its terminating newline. The first
 *                      record in a file carries 64 zeros.
 *   unit_id            64 hex: SHA3-256("zcl.engine_unit.id.v1\0" ||
 *                      task_sha3 || "\0" || engine || "\0" || decimal ts).
 *                      Two runs of the same task on the same engine in the
 *                      same second collide, deliberately: at that resolution
 *                      they are the same dispatch to anyone reading later.
 *   ts                 unix seconds, integer
 *   engine             registry id ("glm", "grok-cli", "fixture")
 *   model              requested_model compatibility key for v1 readers
 *   requested_model    model sent: caller override or registry default
 *   resolved_model     provider-reported model, null when unreported
 *   reasoning_effort   requested low/medium/high/xhigh, or provider_default
 *   kind               the prompt template kind ("fix-gate", …), "" if none
 *   template_sha3      64 hex over the template's bodies, "" if none
 *   rules_shown        array of rule id strings that were IN the prompt
 *   task_sha3          64 hex over the task file's exact bytes
 *   group              the test group the unit was judged on, "" if none
 *   prompt_tokens      terminal-dispatch compatibility counters; integer,
 *                      -1 when the vendor did not report
 *   completion_tokens  integer, -1 when the vendor did not report
 *   cache_read_input_tokens/cache_creation_input_tokens/reasoning_tokens/
 *                      total_tokens/turns: integer, -1 when unreported
 *   invocations        every provider dispatch in ordinal order, including
 *                      repair turns, compactions, and failed retry attempts.
 *                      Each entry carries phase, result, elapsed_ms,
 *                      http_status, and the six raw provider counters.
 *   total_*_tokens     a checked sum of the corresponding raw counter only
 *                      when every invocation reported it; otherwise -1
 *   accounting_scope   "terminal_dispatch": labels the compatibility timing
 *                      and token fields above, which describe the last turn
 *   total_invocation_elapsed_ms: checked sum of raw request durations only;
 *                      excludes retry backoff, proof, and operator delay
 *   cumulative_proof_ms: all gate time across repair turns
 *   unit_elapsed_ms    monotonic elapsed time across the whole repair loop
 *   dispatch_ms/proof_ms/wall_ms: terminal-turn compatibility timings
 *   http_status        integer, 0 for a CLI or fixture engine
 *   outcome            object:
 *                        applied        bool  work reached the worktree
 *                        groups_ran     int
 *                        groups_failed  int
 *                        gate_pass      bool
 *                        retries        int   dispatch attempts beyond one
 *                        lines_changed  int   changed paths in the worktree
 *                        lint_rc        int   -1 when no lint was run
 *   worktree_head      40 hex commit the unit started from, "" if unknown
 *
 * -1 rather than 0 for an unreported token count is the same rule the KPI
 * ledger keeps: 0 and "I could not look" are different facts, and a mean
 * computed over silent zeros is a lie about cost.
 *
 * ── WHY A CHAIN AND NOT A PLAIN LOG ──────────────────────────────────────
 * The point of this file is to be quoted later — "template X went green 9
 * times out of 10" — and a plain log cannot tell an edit from an append. A
 * chain can: change any earlier line and every prev_sha3 after it stops
 * matching, and engine_receipt_verify_chain() names the first line that
 * does. A rewrite of the LAST line would still carry a valid prev_sha3, so
 * each append also writes `path` plus ENGINE_RECEIPT_HEAD_SUFFIX holding
 * that line's SHA3; verify refuses a tail that does not hash to the pin.
 * It does not SIGN, so it says nothing about who wrote a record; it says
 * only that nothing was altered after the fact.
 *
 * It is deliberately NOT engine/modules/chainlog. That module is a binary
 * frame format with two fsyncs per append, and it is the right thing for
 * evidence a node quotes to another node. This is a development artifact a
 * person greps, a sibling lane reads line by line, and a shell pipeline
 * counts; JSON lines are what those readers already speak, and the cost of
 * a wrong choice here is a text file nobody can read with the tools at hand.
 */

#ifndef ZCL_ENGINE_RECEIPT_H
#define ZCL_ENGINE_RECEIPT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The file name this module appends to, under a caller's state directory.
 * The head pin is that path with ENGINE_RECEIPT_HEAD_SUFFIX appended. */
#define ENGINE_RECEIPT_FILENAME     "engine_receipts.chainlog"
#define ENGINE_RECEIPT_HEAD_SUFFIX  ".head"
#define ENGINE_RECEIPT_SCHEMA       "zcl.engine_unit_receipt.v1"

/* Longest line this writer will produce. A record over it is REFUSED rather
 * than truncated: half a JSON object appended to a chain would break every
 * link after it and look like tampering. */
#define ENGINE_RECEIPT_LINE_MAX  16384u

/* How many rule ids one record may carry. */
#define ENGINE_RECEIPT_RULES_MAX 32u

/* A provider call may not start unless one slot remains. The standalone
 * dispatcher also proves its complete configured turn/retry plan fits this
 * bound before its first call, so reaching the bound cannot strand an
 * already-paid-for observation outside the receipt. */
#define ENGINE_RECEIPT_INVOCATIONS_MAX 24u

/* Told to a token field the vendor did not report. */
#define ENGINE_RECEIPT_UNREPORTED (-1)

struct engine_receipt_outcome {
    bool    applied;
    int64_t groups_ran;
    int64_t groups_failed;
    bool    gate_pass;
    int64_t retries;
    int64_t lines_changed;
    int64_t lint_rc;        /* ENGINE_RECEIPT_UNREPORTED when none was run */
};

struct engine_receipt_invocation {
    int64_t     ordinal;       /* one-based dispatch order */
    const char *phase;         /* "turn" or "compaction" */
    const char *result;        /* "ok" or engine error label */
    int64_t     elapsed_ms;
    int64_t     http_status;   /* 0 for CLI/fixture/no HTTP response */
    const char *resolved_model; /* NULL means this call did not report one */
    int64_t     prompt_tokens;
    int64_t     completion_tokens;
    int64_t     cache_read_input_tokens;
    int64_t     cache_creation_input_tokens;
    int64_t     reasoning_tokens;
    int64_t     total_tokens;  /* provider's field; never synthesized */
};

/* Everything one record says. Every pointer borrows from the caller and is
 * read only during the call. A NULL string field is written as "". */
struct engine_receipt {
    int64_t     ts;                 /* unix seconds */
    const char *engine;             /* required */
    const char *requested_model;
    const char *resolved_model;     /* NULL means provider did not report */
    const char *reasoning_effort;
    const char *kind;
    const char *template_sha3;      /* 64 hex or NULL */
    const char *const *rules_shown; /* may be NULL when rules_count is 0 */
    size_t      rules_count;
    const char *task_sha3;          /* 64 hex or NULL */
    const char *group;
    int64_t     prompt_tokens;
    int64_t     completion_tokens;
    int64_t     cache_read_input_tokens;
    int64_t     cache_creation_input_tokens;
    int64_t     reasoning_tokens;
    int64_t     total_tokens;
    int64_t     turns;
    const struct engine_receipt_invocation *invocations;
    size_t      invocations_count;
    /* A resumed provider session may report counters cumulatively. Its raw
     * invocations remain evidence, but summing them would double count. */
    bool        invocation_totals_ambiguous;
    int64_t     cumulative_proof_ms;
    int64_t     unit_elapsed_ms;
    int64_t     dispatch_ms;
    int64_t     proof_ms;
    int64_t     wall_ms;
    int64_t     http_status;
    const char *worktree_head;      /* 40 hex or NULL */
    struct engine_receipt_outcome outcome;
};

/* Append one record to `path`, creating the file when absent.
 *
 * One fd is opened O_RDWR|O_CREAT|O_APPEND|O_CLOEXEC. An OS whole-file
 * exclusive lock (fcntl on POSIX, LockFileEx on Windows) then covers the
 * tail-read and a single write of the whole record (JSON + '\n'), so two
 * processes cannot both hash the same last line and a record cannot tear into
 * two writes that another unit interleaves.
 * The SHA3 of the line just written is stored in `path` plus
 * ENGINE_RECEIPT_HEAD_SUFFIX. Returns false on any refusal — an unreadable
 * path (anything but a missing or empty file), a torn tail, a record that
 * would exceed ENGINE_RECEIPT_LINE_MAX, too many rule ids, a missing
 * engine id.
 *
 * `out_line_sha3`, when non-NULL, receives the 64-hex SHA3-256 of the line
 * just written (the value the NEXT record will carry as prev_sha3) and must
 * have room for 65 bytes. */
bool engine_receipt_append(const char *path, const struct engine_receipt *r,
                           char *out_line_sha3);

/* Pure preflight for the exact bounded JSON record. Callers that will spend
 * provider quota use this before their first dispatch, with worst-case
 * counters and every possible invocation slot populated. */
bool engine_receipt_fits(const struct engine_receipt *r);

struct engine_receipt_chain_report {
    uint64_t records;         /* lines accepted before the outcome below */
    uint64_t first_bad_line;  /* 1-based; 0 when the whole file verifies */
    char     head_sha3[65];   /* hash of the last accepted line */
    char     why[160];        /* what was wrong with first_bad_line */
};

/* Walk `path` without writing to it and check every link. Returns true when
 * the file verifies end to end — including when it does not exist, which is
 * an empty chain and not a broken one. Any open failure other than ENOENT
 * is a refusal, not an empty chain. A last line that does not hash to the
 * head pin is a refusal, as is a trailing line with no newline. `report`
 * is filled either way and is required: "it refused" without naming the
 * line is not a diagnosis. */
bool engine_receipt_verify_chain(const char *path,
                                 struct engine_receipt_chain_report *report);

#endif /* ZCL_ENGINE_RECEIPT_H */
