/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * engine_verdict — the only place a unit is judged.
 *
 * ── THE LAW, ENFORCED BY A FUNCTION SIGNATURE ────────────────────────────
 *
 *   THE MODEL PROPOSES. THE GATE DECIDES.
 *
 * Look at engine_verdict_of(). It takes a reading of the gate's own output,
 * a count of files that actually changed in the worktree, and whether the
 * clock ran out. It does NOT take an exit code. It does NOT take the engine's
 * report, its finish reason, its token count, or anything else the model said
 * about itself. There is no parameter through which a claim could become a
 * verdict, so the wrong thing cannot be written here without first changing
 * this signature — which is a change a reviewer will see.
 *
 * ── THE FOUR WAYS A UNIT LOOKS GREEN AND IS NOT ──────────────────────────
 *
 * 1. groups_ran = 0. A selector that matches nothing prints zero and EXITS 0.
 *    This is the hollow green: a test group registered with nothing in it, or
 *    a group name that does not exist. -> ENGINE_VERDICT_HOLLOW.
 *
 * 2. Every group served from cache. `ALL TESTS PASSED (CACHED)` still
 *    contains the substring `ALL TESTS PASSED`, so a token grep matches it.
 *    A cached run did not execute the new code and is not evidence about it.
 *    -> ENGINE_VERDICT_HOLLOW.
 *
 * 3. Nothing changed. The engine reported success, exited 0, and left an
 *    empty diff — the three measured failures in engine/engine.h all land
 *    here. The gate then passes, because it was passing before the unit ran.
 *    A harness that reads only the gate calls this a PASS and is wrong, which
 *    is why files_changed is a parameter. -> ENGINE_VERDICT_NO_CHANGE, and
 *    that is a FAILURE.
 *
 * 4. The clock ran out. A unit killed mid-thought leaves a partial file set
 *    and a transcript that ends on a planning sentence. It is neither a pass
 *    nor an honest fail; calling it either loses the distinction that tells an
 *    operator to raise the timeout. -> ENGINE_VERDICT_TIMEOUT.
 *
 * Anything unreadable is a refusal, never a pass. A gate run that produced no
 * verdict line at all is ENGINE_VERDICT_REFUSED: we do not know what happened,
 * and "we do not know" is not "it worked".
 */

#ifndef ZCL_ENGINE_VERDICT_H
#define ZCL_ENGINE_VERDICT_H

#include <stdbool.h>
#include <stddef.h>

enum engine_verdict {
    ENGINE_VERDICT_PASS = 0,   /* the ONLY good outcome */
    ENGINE_VERDICT_FAIL,       /* the group ran and did not pass */
    ENGINE_VERDICT_HOLLOW,     /* the group ran nothing, or ran only cache */
    ENGINE_VERDICT_NO_CHANGE,  /* the engine changed nothing */
    ENGINE_VERDICT_TIMEOUT,    /* the wall clock ended the unit */
    ENGINE_VERDICT_REFUSED,    /* the gate produced no readable verdict */
    ENGINE_VERDICT_UNVERIFIED  /* dispatched with no group; nothing was proved */
};

const char *engine_verdict_name(enum engine_verdict v);

/* Exactly one verdict is a pass. Callers map their exit status through this
 * rather than testing the enum, so a verdict added later cannot accidentally
 * become passing at a call site nobody revisited. */
bool engine_verdict_is_pass(enum engine_verdict v);

/* What the runner said about itself, read from its machine-greppable line.
 * lib/test/src/test_parallel.c emits:
 *
 *   SUITE VERDICT mode=cold groups_total=N groups_ran=N groups_cached=N \
 *       groups_gated=N groups_failed=N self_skips=N env_unobserved=N toolkey=..
 *
 * That line exists precisely because the older headline reported GATE OK for
 * a run that executed nothing. Read the line, never the headline. */
struct engine_gate_reading {
    bool   saw_verdict_line;
    bool   cached_mode;
    long   groups_total;
    long   groups_ran;
    long   groups_cached;
    long   groups_failed;
    long   self_skips;
    long   env_unobserved;
    bool   saw_pass_token;      /* the bare token, NOT the (CACHED) form */
    bool   saw_fail_token;
};

/* Parse a captured gate log. Returns false only when the log is unreadable as
 * bytes; a log with no verdict line parses fine and reports
 * saw_verdict_line = false, which the verdict then refuses on. */
bool engine_gate_read(const char *log, size_t len,
                      struct engine_gate_reading *out);

/* THE JUDGEMENT. No exit code, no model claim — see the header comment. */
enum engine_verdict engine_verdict_of(const struct engine_gate_reading *gate,
                                      size_t files_changed,
                                      bool timed_out,
                                      bool have_group);

#endif /* ZCL_ENGINE_VERDICT_H */
