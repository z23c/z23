/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * stopwatch_skip_watch — the in-node READER of the wall-clock stopwatch
 * evidence ledgers written by tools/scripts/c3_stopwatch_run_and_record.sh
 * and tools/scripts/netdisrupt_stopwatch_run_and_record.sh, so a run of
 * skipped proofs is visible from the typed interface
 * (`z23 ops state --subsystem=stopwatch_evidence`) instead of only
 * existing as an absence nobody looked at.
 *
 * WHAT THIS IS FOR. A stopwatch harness exits 2 (SKIP) when it could not run
 * the proof. The judge already grades a skip as FAIL, but nothing ran the
 * judge, and the architecture scorer reads `tail -n 5` of the ledger — so a
 * single old pass kept a dead gate reading green for four consecutive skips
 * (~30h at the 6h timer cadence) with no operator-visible signal at all. This
 * module names that condition: how many consecutive skips, of what CLASS, for
 * how long, and whether that crosses the class's alarm threshold.
 *
 * AND THE SECOND RUNG. That first alarm only ever asked "could the proof
 * run". Measured 2026-08-29: the C3 gate ran 34 consecutive scheduled times,
 * skipped none of them, and PASSED none of them (the last 17 recorded
 * `stalled-named` with the node under test at zero blocks synced) — and this
 * module's own report line for that state began with the word "quiet",
 * printing no_pass_streak=34 inside it. `no_pass_streak` was computed,
 * stored, serialised and asserted in tests, and gated nothing. So the watch
 * was loud about the LESS damning failure and silent about the worse one.
 * There is now a second, independent alarm on the no-pass streak, with its
 * threshold in the same table as the class thresholds.
 *
 * ══ REPORTER ONLY — the load-bearing contract ══
 * This module NEVER grades. It cannot make a run pass, cannot clear a FAIL,
 * cannot extend an evidence window, and is not wired into the architecture
 * score, the MVP scoreboard, the health rollup, or any Condition/blocker. It
 * only ADDS a description of evidence that already exists on disk. Deliberate,
 * for two reasons:
 *   1. Standing. This ledger is about a WIPED FRESH node dialing a fixture
 *      peer; it says nothing about the binary that is running right now. Its
 *      node_bin field is a path, not a source identity — it cannot satisfy the
 *      source-binding and pre-start-staleness rules that
 *      services/canary_sentinel_watch.h enforces before external evidence is
 *      allowed to page this process. A blocker minted from it would be the
 *      node paging about a claim it has no standing to make.
 *   2. Cloning. The ledger file is the one authority. Latching a copy of its
 *      state into node memory would make a second ledger that can drift — the
 *      recurring defect the architecture north star names, whose fix is always
 *      deleting a copy, never adding a reconciler. So every call re-reads the
 *      file; nothing is cached, nothing is latched.
 *
 * NO supervised child is armed. The cadence belongs to the systemd timer that
 * writes the ledger; there is no in-process work to tick, so there is no
 * liveness contract to declare a progress policy for.
 *
 * Ledger contract (see the collector script headers for the full field list):
 *   one flock-appended JSON object per line, fields read here are
 *   `ts` (epoch seconds), `verdict` (pass|fail|skip|seam|stalled-named|
 *   frontier-busy-timeout|readback-failed|error), `skip_reason`,
 *   `artifact_dir`. Rows written before skip_reason existed are handled: an
 *   ABSENT skip_reason field classifies as `unclassified`, never as benign.
 *
 * Absence is data, never an error. A missing ledger file means the gate was
 * never installed on this host; the report says present=false and raises
 * nothing. "The collector stopped running entirely" is a different rung and
 * belongs to the judge's STALE verdict, not here.
 *
 * Env (same variables the scripts themselves read, so tests stay hermetic and
 * never touch the operator's real ledgers):
 *   ZCL_C3_STOPWATCH_HISTORY / ZCL_C3_HISTORY_DIR
 *   ZCL_NETDISRUPT_STOPWATCH_HISTORY / ZCL_ND_HISTORY_DIR
 *
 * Pure file-scan observer: no DB, no threads, no chain locks, no allocation. */

#ifndef ZCL_SERVICES_STOPWATCH_SKIP_WATCH_H
#define ZCL_SERVICES_STOPWATCH_SKIP_WATCH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define STOPWATCH_SKIP_REASON_MAX   192
#define STOPWATCH_SKIP_CLASS_MAX     32
#define STOPWATCH_SKIP_VERDICT_MAX   32
#define STOPWATCH_SKIP_ALARM_MAX    640

/* Bounded tail read: the detector only ever needs the trailing streak, and a
 * ledger is one short line per 6h run, so 256 KiB is thousands of rows. */
#define STOPWATCH_SKIP_TAIL_BYTES  (256u * 1024u)

struct stopwatch_skip_report {
    bool     present;        /* ledger file existed and carried >=1 usable row */
    unsigned rows_scanned;   /* usable rows in the scanned tail */
    unsigned malformed_rows; /* rows with no verdict field (foreign), plus rows
                              * too long to be an evidence row */
    unsigned incomplete_rows;/* lines that ended with no newline: an append
                              * caught mid-write. Dropped, never scanned, so
                              * half a row cannot set the streaks below. Only
                              * the tail read can see these. */

    /* Trailing streaks, recomputed from the `verdict` values every call. The
     * collector also RECORDS these on the ledger line, but a recorded number
     * is never trusted here — a forged field must not be able to silence the
     * detector, and pre-existing rows do not carry one. */
    unsigned skip_streak;    /* consecutive trailing verdict=="skip" */
    unsigned no_pass_streak; /* consecutive trailing verdict!="pass" */

    int64_t  last_ts;        /* -1 when unknown */
    int64_t  last_pass_ts;   /* -1 when no pass in the scanned tail */
    char     last_verdict[STOPWATCH_SKIP_VERDICT_MAX];

    /* Meaning of the trailing skip run (empty when the last row is not a
     * skip). Sourced from engine/services/include/services/stopwatch_skip_classes.def. */
    char     skip_class[STOPWATCH_SKIP_CLASS_MAX];
    char     skip_reason[STOPWATCH_SKIP_REASON_MAX];
    unsigned threshold;      /* 0 = this class never alarms */
    bool     alarm;          /* skip_streak >= threshold, threshold > 0 */

    /* ── the SECOND rung: the proof RAN and never passed ─────────────
     * `no_pass_streak` above was computed, stored and serialised from the
     * day this module landed, and gated NOTHING: the only alarm path
     * required skip_streak > 0, so "the proof could not run" was loud and
     * "the proof ran 34 times and never once succeeded" was labelled
     * quiet. These three fields close that. */
    unsigned no_pass_threshold; /* consecutive non-passes before the no-pass
                                 * alarm. From STOPWATCH_NO_PASS_THRESHOLD in
                                 * stopwatch_skip_classes.def; always >= 1 —
                                 * 0 is refused at BUILD time, because a 0
                                 * here would mean "mute", not "benign". */
    bool     no_pass_all_benign;/* the ENTIRE trailing no-pass streak is skips
                                 * whose class threshold is 0, i.e. every one
                                 * of those runs genuinely had nothing to
                                 * prove. The only carve-out on the alarm
                                 * below, and it ends the moment a single
                                 * fail/seam/stalled-named/unclassified row
                                 * joins the streak. False when the streak is
                                 * empty. */
    bool     no_pass_alarm;     /* no_pass_streak >= no_pass_threshold and
                                 * !no_pass_all_benign. INDEPENDENT of
                                 * `alarm`: either can fire without the
                                 * other, and the two describe different
                                 * faults — see stopwatch_skip_alarm_text. */
};

/* Classify one recorded skip. `reason` is the ledger row's skip_reason
 * (may be NULL/empty); `reason_field_present` distinguishes "the collector
 * wrote an empty reason" from "this row predates the field"; `has_artifact`
 * is whether artifact_dir was non-empty (a skip with no artifact never
 * reached skip(), so the harness died in argv parsing). Writes the class name
 * into cls/cls_cap and the threshold into *threshold. */
bool stopwatch_skip_classify(const char *reason, bool reason_field_present,
                             bool has_artifact, char *cls, size_t cls_cap,
                             unsigned *threshold);

/* Scan an in-memory ledger tail (newline-separated JSON rows). Pure: no IO,
 * no clock. Returns false only on bad arguments. */
bool stopwatch_skip_scan(const char *text, size_t len,
                         struct stopwatch_skip_report *out);

/* Read the trailing STOPWATCH_SKIP_TAIL_BYTES of `path` and scan it. A
 * missing/empty/unreadable file is NOT a failure: out->present is false and
 * the call still returns true. Returns false only on bad arguments. */
bool stopwatch_skip_read_ledger(const char *path,
                                struct stopwatch_skip_report *out);

/* Resolve a ledger path. `which` is "c3" or "netdisrupt". Returns false when
 * no path can be resolved (no env override and no HOME). */
bool stopwatch_skip_resolve_ledger(const char *which, char *out, size_t cap);

/* One operator-readable line describing the report. TWO alarms live here and
 * they are deliberately distinguishable in the TEXT, because they call for
 * different work:
 *   "ALARM class=fixture_absent skip_streak=4 threshold=2 ...
 *      — this proof has not run for that many consecutive scheduled attempts"
 *          the proof COULD NOT RUN. Go fix the named fixture/config.
 *   "ALARM no_pass_streak=34 no_pass_threshold=4 last_verdict=stalled-named ...
 *      — this proof RAN on every one of those scheduled attempts and never
 *        once passed"
 *          the proof RAN and the CLAIM IS FALSE. Go fix the product.
 * Quiet forms keep the same shape with a leading "quiet". Always
 * NUL-terminates; returns buf. */
const char *stopwatch_skip_alarm_text(const struct stopwatch_skip_report *r,
                                      char *buf, size_t cap);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe.
 * key: NULL/"" = every known ledger, or "c3" / "netdisrupt" for one. */
struct json_value;
bool stopwatch_evidence_dump_state_json(struct json_value *out,
                                        const char *key);

#endif /* ZCL_SERVICES_STOPWATCH_SKIP_WATCH_H */
