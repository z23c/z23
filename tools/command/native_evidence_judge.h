/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The verdict logic of the two evidence-ledger judges, in process:
 *          the 168 h soak window judge (MVP C6) and the last-line stopwatch
 *          judge (MVP C3). Each returns the same report lines, verdict token
 *          and exit code the retired judge scripts printed. */

#ifndef ZCL_NATIVE_EVIDENCE_JUDGE_H
#define ZCL_NATIVE_EVIDENCE_JUDGE_H

#include "command/native_command.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_JUDGE_TEXT_MAX 4096u
#define ZCL_JUDGE_ALARM_MAX 1024u
#define ZCL_JUDGE_REASON_MAX 256u

#define ZCL_SOAK_JUDGE_SCHEMA "zcl.soak_judge.v1"
#define ZCL_STOPWATCH_JUDGE_SCHEMA "zcl.stopwatch_judge.v1"

#define ZCL_SOAK_WINDOW_HOURS 168
#define ZCL_SOAK_WINDOW_HOURS_MAX (INT64_MAX / 3600)
#define ZCL_SOAK_HOLE_THRESHOLD_SEC 8100
#define ZCL_SOAK_WINDOW_SLACK_SEC 900
#define ZCL_SOAK_GAP0_MIN_PCT 99

#define ZCL_STOPWATCH_LEDGER_PATH_CAP 4096u
#define ZCL_STOPWATCH_MAX_AGE_SECS 86400
#define ZCL_STOPWATCH_CHECKPOINT_HEIGHT 3056758
#define ZCL_STOPWATCH_ORACLE_LAG_BUDGET 2000
#define ZCL_STOPWATCH_ORACLE_MAX_AGE_SECS 3600

/* One judge run. `text` holds the report lines a judge prints on stdout, one
 * of them the VERDICT line; `alarm` holds the stderr line, if any. `exit_code`
 * is 0 for a pass, 1 for a refusal and 2 for stale or insufficient evidence. */
struct zcl_judge_result {
    char text[ZCL_JUDGE_TEXT_MAX];
    char alarm[ZCL_JUDGE_ALARM_MAX];
    char verdict[32];
    char reason[ZCL_JUDGE_REASON_MAX];
    char artifact[256];    /* stopwatch: the run artifact the row names */
    char result_class[64]; /* stopwatch: the row's result_class on a FAIL */
    double covered_hours;  /* soak: hours the judged window covers */
    int64_t newest_age_sec; /* soak: age of the last sample */
    int exit_code;
};

struct zcl_soak_judge_opts {
    const char *file;     /* evidence.jsonl */
    int64_t window_hours; /* ZCL_SOAK_WINDOW_HOURS */
    bool allow_stale;     /* judge a historical window */
    int64_t now_unix;     /* 0 = wall clock */
    bool now_supplied;    /* C6: true makes an explicit epoch 0 literal */
};

struct zcl_stopwatch_judge_opts {
    const char *history;         /* history.jsonl */
    int64_t max_age_secs;        /* ZCL_STOPWATCH_MAX_AGE_SECS */
    const char *expect_sha256;   /* NULL or "" = unbound; else 64 hex digits */
    const char *slo_ledger;      /* oracle sample ledger; NULL = none */
    int64_t checkpoint_height;   /* ZCL_STOPWATCH_CHECKPOINT_HEIGHT */
    int64_t oracle_lag_budget;   /* ZCL_STOPWATCH_ORACLE_LAG_BUDGET */
    int64_t oracle_max_age_secs; /* ZCL_STOPWATCH_ORACLE_MAX_AGE_SECS */
    int64_t now_unix;            /* 0 = wall clock */
};

/* The windowed tip-hash agreement judge over the off-host agreement ledger
 * (tools/scripts/tip_agreement_probe.sh). Every knob below may only move in
 * the direction that makes a PASS harder to earn: zcl_tip_judge_check
 * refuses a looser value. Verdicts: PASS 0; DISAGREE, NO_EVIDENCE,
 * THIN_EVIDENCE and MALFORMED 1; STALE 2. */
#define ZCL_TIP_AGREEMENT_JUDGE_SCHEMA "zcl.tip_agreement_judge.v1"
#define ZCL_TIP_DEF_WINDOW_HOURS 24
#define ZCL_TIP_DEF_MAX_AGE_SECS 1800
#define ZCL_TIP_DEF_MIN_AGREE 6
#define ZCL_TIP_DEF_MAX_DISAGREE 0
#define ZCL_TIP_DEF_MIN_SPAN_SECS 2700

struct zcl_tip_judge_opts {
    const char *file;         /* agreement-ledger.jsonl */
    int64_t window_hours;     /* graded window [now - hours*3600, now] */
    int64_t max_age_secs;     /* newest sample older than this is STALE */
    int64_t min_agree;        /* clean agreeing samples required */
    int64_t min_distinct_peers; /* control: distinct remote witnesses */
    int64_t max_disagree;     /* disagreeing or contested samples tolerated */
    int64_t min_span_secs;    /* wall-clock span the clean samples must cover */
    int64_t now_unix;         /* meaningful only when now_set */
    bool now_set;             /* false = wall clock */
};

/* The shipped contract, with ZCL_PARITY_JUDGE_NOW honoured as the clock. On
 * a malformed variable, false with the reason in `err`. */
bool zcl_tip_judge_defaults(struct zcl_tip_judge_opts *opts, char *err,
                            size_t err_cap);
/* False with the reason in `err` when any knob is negative, loosens the
 * shipped contract or lowers the distinct-peer control. */
bool zcl_tip_judge_check(const struct zcl_tip_judge_opts *opts, char *err,
                         size_t err_cap);
/* False only for a missing argument; every shortfall is a verdict. */
bool zcl_tip_agreement_judge(const struct zcl_tip_judge_opts *opts,
                             struct zcl_judge_result *out);

/* False for invalid soak options or when the ledger cannot be held in memory; every evidence
 * shortfall is a verdict, never a failure. */
bool zcl_soak_judge(const struct zcl_soak_judge_opts *opts,
                    struct zcl_judge_result *out);
/* The C8 parity window judge over parity.jsonl: same verdict tokens, same
 * C6 hole and slack constants; a match:false is NOT_MET. */
bool zcl_parity_judge(const struct zcl_soak_judge_opts *opts,
                      struct zcl_judge_result *out);
bool zcl_stopwatch_judge(const struct zcl_stopwatch_judge_opts *opts,
                         struct zcl_judge_result *out);

/* Fills `opts` with the defaults the judges used: the documented constants,
 * overridden by the ZCL_STOPWATCH_* and ZCL_SOAK_NOW environment variables.
 * `path` receives the default ledger path and must hold `cap` bytes. On a
 * malformed variable, false with the reason in `err`. */
bool zcl_soak_judge_defaults(struct zcl_soak_judge_opts *opts, char *path,
                             size_t cap, char *err, size_t err_cap);
bool zcl_stopwatch_judge_defaults(struct zcl_stopwatch_judge_opts *opts,
                                  const char *ledger,
                                  char *slo_path, size_t cap, char *err,
                                  size_t err_cap);

/* The bound leaves: ops.host.slo.soak and ops.host.slo.stopwatch. */
void zcl_native_handle_ops_soak_judge(const struct zcl_command_request *request,
                                      struct zcl_command_reply *reply);
void zcl_native_handle_ops_stopwatch_judge(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);
void zcl_native_handle_ops_tip_agreement_judge(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);

#endif /* ZCL_NATIVE_EVIDENCE_JUDGE_H */
