/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * stopwatch_skip_watch — see services/stopwatch_skip_watch.h for the full
 * contract (what a skip class means, why this is reporter-only, and why it
 * arms no supervised child). This file is a pure file-scan observer: no DB
 * writes, no threads, no chain locks, no allocation, nothing latched. */

// one-result-type-ok:stopwatch-skip-reporter-no-fallible-surface
//
// A read-only evidence reader, not a fallible service executor. Its surfaces
// are bool probes (classify, scan, read, resolve), a formatter, and the
// project-wide bool dump_state_json convention. Every "false" here means the
// CALLER passed bad arguments; a missing or unreadable ledger is data
// (present=false), never an error a caller branches on, because absence of a
// stopwatch ledger is exactly what a host that never installed the gate looks
// like.

#include "services/stopwatch_skip_watch.h"

#include "services/evidence_ledger_row.h"

#include "json/json.h"
#include "util/log_macros.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* One row of the shared class table. match == NULL marks a structural
 * fallback row (see the .def header). */
struct stopwatch_skip_class_row {
    const char *name;
    unsigned    threshold;
    const char *match;
};

static const struct stopwatch_skip_class_row g_class_rows[] = {
#define STOPWATCH_SKIP_CLASS(name_, thr_, match_) { (name_), (thr_), (match_) },
#define STOPWATCH_SKIP_FALLBACK(name_, thr_)      { (name_), (thr_), NULL },
#define STOPWATCH_NO_PASS_THRESHOLD(n_)
#include "services/stopwatch_skip_classes.def"
#undef STOPWATCH_NO_PASS_THRESHOLD
#undef STOPWATCH_SKIP_FALLBACK
#undef STOPWATCH_SKIP_CLASS
};

/* Second pass over the SAME table for its one non-class row. An enum, not a
 * #define, on purpose: a table carrying two STOPWATCH_NO_PASS_THRESHOLD rows
 * is a duplicate enumerator (build error) and a table carrying none leaves
 * the name undeclared (build error). Exactly one row is the only thing that
 * compiles, so the shell parser's `head -n1` can never disagree with the C. */
enum {
#define STOPWATCH_SKIP_CLASS(name_, thr_, match_)
#define STOPWATCH_SKIP_FALLBACK(name_, thr_)
#define STOPWATCH_NO_PASS_THRESHOLD(n_) STOPWATCH_NO_PASS_THRESHOLD_VALUE = (n_)
#include "services/stopwatch_skip_classes.def"
#undef STOPWATCH_NO_PASS_THRESHOLD
#undef STOPWATCH_SKIP_FALLBACK
#undef STOPWATCH_SKIP_CLASS
};

/* A 0 here would not mean "benign", it would mean "mute the no-pass alarm" —
 * the exact defect this rung exists to end. Refuse it at BUILD time rather
 * than discovering the silence in production. */
static_assert(STOPWATCH_NO_PASS_THRESHOLD_VALUE >= 1,
              "STOPWATCH_NO_PASS_THRESHOLD must be >= 1: 0 would silence the "
              "no-pass alarm, and a non-pass is never benign: the harness "
              "had something to prove and did not prove it");

#define STOPWATCH_CLASS_ROW_COUNT \
    (sizeof(g_class_rows) / sizeof(g_class_rows[0]))

#define STOPWATCH_CLASS_HARNESS_MISUSE "harness_misuse"
#define STOPWATCH_CLASS_UNCLASSIFIED   "unclassified"

/* Row parsing and the bounded tail read live in ONE place —
 * services/evidence_ledger_row.h — because the subtle parts (drop the
 * post-seek fragment, consume an overlong row instead of folding its tail as
 * a second sample, treat an absent ledger as data) fabricate evidence when
 * they are copied and one copy drifts. This file used to carry its own copy of
 * all four helpers; it now calls the shared ones.
 *
 * ── classification ─────────────────────────────────────────────────── */

static const struct stopwatch_skip_class_row *class_by_name(const char *name)
{
    for (size_t i = 0; i < STOPWATCH_CLASS_ROW_COUNT; i++) {
        if (strcmp(g_class_rows[i].name, name) == 0)
            return &g_class_rows[i];
    }
    return NULL;
}

bool stopwatch_skip_classify(const char *reason, bool reason_field_present,
                             bool has_artifact, char *cls, size_t cls_cap,
                             unsigned *threshold)
{
    if (!cls || cls_cap == 0)
        LOG_FAIL("stopwatch", "class output buffer is NULL/empty");
    if (!threshold)
        LOG_FAIL("stopwatch", "threshold output is NULL");

    if (reason && reason[0]) {
        size_t rlen = strlen(reason);
        for (size_t i = 0; i < STOPWATCH_CLASS_ROW_COUNT; i++) {
            const struct stopwatch_skip_class_row *r = &g_class_rows[i];
            if (!r->match)
                continue;
            if (evidence_find_sub(reason, rlen, r->match)) {
                evidence_copy_bounded(cls, cls_cap, r->name, strlen(r->name));
                *threshold = r->threshold;
                return true;
            }
        }
    }

    /* No substring matched. Two structural outcomes, and the difference
     * matters: a skip that wrote NO artifact never reached the harness's
     * skip() at all, so it died in argv parsing (harness_misuse, threshold
     * 1). Anything else — including every ledger row written before
     * skip_reason existed — is honestly unknown, not benign. */
    const char *pick = STOPWATCH_CLASS_UNCLASSIFIED;
    if (reason_field_present && (!reason || !reason[0]) && !has_artifact)
        pick = STOPWATCH_CLASS_HARNESS_MISUSE;

    const struct stopwatch_skip_class_row *row = class_by_name(pick);
    if (!row)
        LOG_FAIL("stopwatch", "fallback class '%s' missing from the table",
                 pick);
    evidence_copy_bounded(cls, cls_cap, row->name, strlen(row->name));
    *threshold = row->threshold;
    return true;
}

/* ── scan ───────────────────────────────────────────────────────────── */

/* Running state the per-row folder needs beyond the report itself: whether
 * the MOST RECENT skip row carried a skip_reason field at all, whether it
 * named an artifact dir, and whether every row of the CURRENT no-pass streak
 * has been a benign skip. The first two feed classification once the fold
 * ends; the third is the one carve-out on the no-pass alarm and has to be
 * accumulated per row, because only the trailing SKIP is classified at the
 * end and a streak of 34 stalled runs contains no skip at all. */
struct scan_state {
    bool last_reason_present;
    bool last_has_artifact;
    bool no_pass_all_benign;
};

static void scan_init(struct stopwatch_skip_report *out,
                      struct scan_state *st)
{
    memset(out, 0, sizeof(*out));
    out->last_ts = -1;
    out->last_pass_ts = -1;
    memset(st, 0, sizeof(*st));
    /* Vacuously true over an empty streak; scan_finish refuses to report it
     * as benign unless the streak is non-empty. */
    st->no_pass_all_benign = true;
}

static void scan_row(const char *row, size_t rlen,
                     struct stopwatch_skip_report *out, struct scan_state *st)
{
    if (rlen == 0)
        return;

    char verdict[STOPWATCH_SKIP_VERDICT_MAX];
    if (!evidence_row_str(row, rlen, "verdict", verdict, sizeof(verdict)) ||
        verdict[0] == '\0') {
        out->malformed_rows++;
        return;
    }
    out->rows_scanned++;
    out->present = true;

    int64_t ts = -1;
    if (!evidence_row_int(row, rlen, "ts", &ts))
        ts = -1;
    out->last_ts = ts;
    evidence_copy_bounded(out->last_verdict, sizeof(out->last_verdict), verdict,
                 strlen(verdict));

    if (strcmp(verdict, "pass") == 0) {
        out->skip_streak = 0;
        out->no_pass_streak = 0;
        out->last_pass_ts = ts;
        st->no_pass_all_benign = true;   /* the streak restarts empty */
        return;
    }

    out->no_pass_streak++;
    if (strcmp(verdict, "skip") != 0) {
        out->skip_streak = 0;
        /* fail / seam / stalled-named / error: the harness RAN. It had
         * something to prove and did not prove it, so nothing about this row
         * is benign and the carve-out below is over for this streak. */
        st->no_pass_all_benign = false;
        return;
    }

    out->skip_streak++;
    char reason[STOPWATCH_SKIP_REASON_MAX];
    char artifact[512];
    st->last_reason_present =
        evidence_row_str(row, rlen, "skip_reason", reason, sizeof(reason));
    st->last_has_artifact =
        evidence_row_str(row, rlen, "artifact_dir", artifact, sizeof(artifact)) &&
        artifact[0] != '\0';
    evidence_copy_bounded(out->skip_reason, sizeof(out->skip_reason),
                 st->last_reason_present ? reason : "",
                 st->last_reason_present ? strlen(reason) : 0);

    /* Is THIS skip one the class table calls benign (threshold 0 — "nothing
     * was configured, so there was nothing to prove")? Asked per row, off the
     * fields just parsed, because a streak mixes kinds and only the LAST skip
     * is classified at the end. An unclassifiable row is never benign. */
    char cls[STOPWATCH_SKIP_CLASS_MAX];
    unsigned thr = 0;
    if (!stopwatch_skip_classify(st->last_reason_present ? reason : "",
                                 st->last_reason_present, st->last_has_artifact,
                                 cls, sizeof(cls), &thr) ||
        thr != 0)
        st->no_pass_all_benign = false;
}

static bool scan_finish(struct stopwatch_skip_report *out,
                        const struct scan_state *st)
{
    /* The no-pass rung is computed FIRST and unconditionally, because the
     * whole defect being fixed here is that it used to live behind
     * `skip_streak > 0` and a 34-deep streak of stalled runs has
     * skip_streak == 0. */
    out->no_pass_threshold = (unsigned)STOPWATCH_NO_PASS_THRESHOLD_VALUE;
    out->no_pass_all_benign = out->no_pass_streak > 0 && st->no_pass_all_benign;
    out->no_pass_alarm = out->no_pass_streak >= out->no_pass_threshold &&
                         !out->no_pass_all_benign;

    if (out->skip_streak == 0)
        return true;
    if (!stopwatch_skip_classify(out->skip_reason, st->last_reason_present,
                                 st->last_has_artifact, out->skip_class,
                                 sizeof(out->skip_class), &out->threshold))
        return false;
    out->alarm = out->threshold > 0 && out->skip_streak >= out->threshold;
    return true;
}

/* Adapter onto the shared row walker: the fold needs the report AND the
 * per-row scan_state, so both travel in one ctx. */
struct sw_scan_ctx {
    struct stopwatch_skip_report *out;
    struct scan_state st;
};

static void sw_row_cb(const char *row, size_t rlen, void *ctx)
{
    struct sw_scan_ctx *c = ctx;
    scan_row(row, rlen, c->out, &c->st);
}

bool stopwatch_skip_scan(const char *text, size_t len,
                         struct stopwatch_skip_report *out)
{
    if (!out)
        LOG_FAIL("stopwatch", "report output is NULL");
    struct sw_scan_ctx c = { .out = out };
    scan_init(out, &c.st);
    if (!evidence_ledger_scan_text(text, len, sw_row_cb, &c))
        LOG_FAIL("stopwatch", "ledger text scan rejected len=%zu", len);
    return scan_finish(out, &c.st);
}

/* ── ledger IO ──────────────────────────────────────────────────────── */

bool stopwatch_skip_read_ledger(const char *path,
                                struct stopwatch_skip_report *out)
{
    if (!out)
        LOG_FAIL("stopwatch", "report output is NULL");
    struct sw_scan_ctx c = { .out = out };
    scan_init(out, &c.st);
    if (!path || !path[0])
        LOG_FAIL("stopwatch", "ledger path is NULL/empty");

    /* Bounded tail read, fragment/overlong handling and "absent ledger is
     * data" all live in evidence_ledger_scan_tail(). An overlong row counts
     * as malformed here, exactly as it did when this loop was local. A line
     * with no newline at EOF is counted separately and never scanned: the
     * collector appends under flock, so a torn tail means a run caught
     * mid-write, and folding it in would let half a row set the trailing
     * streaks this report exists to publish. */
    if (!evidence_ledger_scan_tail(path, STOPWATCH_SKIP_TAIL_BYTES, sw_row_cb,
                                   &c, &out->malformed_rows,
                                   &out->incomplete_rows))
        LOG_FAIL("stopwatch", "ledger tail read rejected path '%s'", path);
    return scan_finish(out, &c.st);
}

bool stopwatch_skip_resolve_ledger(const char *which, char *out, size_t cap)
{
    if (!out || cap == 0)
        LOG_FAIL("stopwatch", "path output buffer is NULL/empty");
    out[0] = '\0';
    if (!which || !which[0])
        LOG_FAIL("stopwatch", "ledger selector is NULL/empty");

    const char *file_env = NULL;
    const char *dir_env = NULL;
    const char *dir_default = NULL;
    if (strcmp(which, "c3") == 0) {
        file_env = "ZCL_C3_STOPWATCH_HISTORY";
        dir_env = "ZCL_C3_HISTORY_DIR";
        dir_default = ".local/state/zclassic23-c3-stopwatch";
    } else if (strcmp(which, "netdisrupt") == 0) {
        file_env = "ZCL_NETDISRUPT_STOPWATCH_HISTORY";
        dir_env = "ZCL_ND_HISTORY_DIR";
        dir_default = ".local/state/zclassic23-netdisrupt-stopwatch";
    } else {
        LOG_FAIL("stopwatch", "unknown ledger selector '%s'", which);
    }

    const char *v = getenv(file_env);
    if (v && v[0]) {
        evidence_copy_bounded(out, cap, v, strlen(v));
        return true;
    }
    v = getenv(dir_env);
    if (v && v[0]) {
        if (snprintf(out, cap, "%s/history.jsonl", v) >= (int)cap)
            LOG_FAIL("stopwatch", "%s path too long for buffer", dir_env);
        return true;
    }
    const char *home = getenv("HOME");
    if (!home || !home[0]) {
        out[0] = '\0';
        LOG_FAIL("stopwatch", "no %s, no %s and no HOME to resolve the %s "
                 "ledger path from", file_env, dir_env, which);
    }
    if (snprintf(out, cap, "%s/%s/history.jsonl", home, dir_default) >=
        (int)cap)
        LOG_FAIL("stopwatch", "default %s ledger path too long", which);
    return true;
}

/* How old the last pass is, expressed against the NEWEST ledger row rather
 * than against wall-clock now: this module has no clock (see the header's
 * "Pure file-scan observer"), and inventing one here would make the same
 * report line answer differently on two readers of the same file. The label
 * spells that out so nobody reads it as "seconds ago". */
static void last_pass_age_text(const struct stopwatch_skip_report *r,
                               char *buf, size_t cap)
{
    if (r->last_pass_ts < 0 || r->last_ts < 0 || r->last_ts < r->last_pass_ts) {
        snprintf(buf, cap, "last_pass=never_in_ledger_tail");
        return;
    }
    snprintf(buf, cap, "last_pass_age=%llds-before-newest-row",
             (long long)(r->last_ts - r->last_pass_ts));
}

const char *stopwatch_skip_alarm_text(const struct stopwatch_skip_report *r,
                                      char *buf, size_t cap)
{
    if (!buf || cap == 0)
        return "";
    if (!r) {
        evidence_copy_bounded(buf, cap, "no report", strlen("no report"));
        return buf;
    }
    if (!r->present) {
        snprintf(buf, cap, "quiet no_ledger — the stopwatch gate has never "
                 "written a row on this host");
        return buf;
    }

    char age[64];
    last_pass_age_text(r, age, sizeof(age));

    if (r->skip_streak == 0) {
        /* No skips at all in the trailing run. Either nothing is wrong, or
         * the proof RAN every scheduled time and never passed — which is the
         * more damning of the two conditions this module reports, and is the
         * one that used to print the word "quiet" with no_pass_streak=34
         * sitting inside the line. */
        if (r->no_pass_alarm) {
            snprintf(buf, cap,
                     "ALARM no_pass_streak=%u no_pass_threshold=%u "
                     "last_verdict=%s %s — this proof RAN on every one of "
                     "those consecutive scheduled attempts and never once "
                     "passed, so the claim it exists to prove is unproven; "
                     "fix the failing verdict, do not wait for the score to "
                     "move",
                     r->no_pass_streak, r->no_pass_threshold,
                     r->last_verdict[0] ? r->last_verdict : "-", age);
            return buf;
        }
        snprintf(buf, cap,
                 "quiet last_verdict=%s skip_streak=0 no_pass_streak=%u "
                 "no_pass_threshold=%u %s",
                 r->last_verdict[0] ? r->last_verdict : "-",
                 r->no_pass_streak, r->no_pass_threshold, age);
        return buf;
    }

    /* A trailing SKIP run. The class alarm below is unchanged. The no-pass
     * alarm can still be the reason this line is loud — a streak of fails
     * capped by one benign skip must not read as quiet — so it is checked
     * after the class alarm and before the benign note. */
    const char *tail;
    if (r->alarm)
        tail = " — this proof has not run for that many consecutive "
               "scheduled attempts";
    else if (r->no_pass_alarm)
        tail = " — the trailing SKIP run does not itself cross its class "
               "threshold, but this proof RAN and never once passed across "
               "the whole no_pass_streak above; the claim is unproven";
    else if (r->threshold == 0)
        tail = " — benign: nothing was configured, so there was nothing "
               "to prove";
    else
        tail = "";

    snprintf(buf, cap,
             "%s class=%s skip_streak=%u threshold=%u no_pass_streak=%u "
             "no_pass_threshold=%u reason=\"%s\"%s",
             (r->alarm || r->no_pass_alarm) ? "ALARM" : "quiet",
             r->skip_class[0] ? r->skip_class : "-", r->skip_streak,
             r->threshold, r->no_pass_streak, r->no_pass_threshold,
             r->skip_reason[0] ? r->skip_reason : "-", tail);
    return buf;
}

/* ── typed surface: dumpstate stopwatch_evidence ────────────────────── */

static void push_ledger_json(struct json_value *parent, const char *which)
{
    struct json_value obj;
    json_init(&obj);
    json_set_object(&obj);

    char path[PATH_MAX];
    bool resolved = stopwatch_skip_resolve_ledger(which, path, sizeof(path));
    json_push_kv_str(&obj, "ledger", which);
    json_push_kv_str(&obj, "path", resolved ? path : "unresolved");

    struct stopwatch_skip_report rep;
    bool read_ok = resolved && stopwatch_skip_read_ledger(path, &rep);
    if (!read_ok) {
        memset(&rep, 0, sizeof(rep));
        rep.last_ts = -1;
        rep.last_pass_ts = -1;
    }
    json_push_kv_bool(&obj, "present", rep.present);
    json_push_kv_int(&obj, "rows_scanned", rep.rows_scanned);
    json_push_kv_int(&obj, "malformed_rows", rep.malformed_rows);
    json_push_kv_int(&obj, "incomplete_rows", rep.incomplete_rows);
    json_push_kv_str(&obj, "last_verdict",
                     rep.last_verdict[0] ? rep.last_verdict : "-");
    json_push_kv_int(&obj, "last_ts", rep.last_ts);
    json_push_kv_int(&obj, "last_pass_ts", rep.last_pass_ts);
    json_push_kv_int(&obj, "skip_streak", rep.skip_streak);
    json_push_kv_int(&obj, "no_pass_streak", rep.no_pass_streak);
    json_push_kv_str(&obj, "skip_class",
                     rep.skip_class[0] ? rep.skip_class : "-");
    json_push_kv_str(&obj, "skip_reason",
                     rep.skip_reason[0] ? rep.skip_reason : "-");
    json_push_kv_int(&obj, "alarm_threshold", rep.threshold);
    json_push_kv_bool(&obj, "alarm", rep.alarm);
    json_push_kv_int(&obj, "no_pass_threshold", rep.no_pass_threshold);
    json_push_kv_bool(&obj, "no_pass_all_benign", rep.no_pass_all_benign);
    json_push_kv_bool(&obj, "no_pass_alarm", rep.no_pass_alarm);

    char text[STOPWATCH_SKIP_ALARM_MAX];
    json_push_kv_str(&obj, "summary",
                     stopwatch_skip_alarm_text(&rep, text, sizeof(text)));
    json_push_back(parent, &obj);
    json_free(&obj);
}

bool stopwatch_evidence_dump_state_json(struct json_value *out,
                                        const char *key)
{
    if (!out)
        LOG_FAIL("stopwatch", "dump output is NULL");
    json_set_object(out);
    json_push_kv_str(out, "role",
                     "REPORTER ONLY — describes the stopwatch evidence "
                     "ledgers on disk; never grades a run, never clears a "
                     "verdict, never feeds the architecture score");

    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    if (key && key[0]) {
        if (strcmp(key, "c3") != 0 && strcmp(key, "netdisrupt") != 0) {
            json_free(&arr);
            json_push_kv_str(out, "error",
                             "unknown key: use c3, netdisrupt, or no key");
            return true;
        }
        push_ledger_json(&arr, key);
    } else {
        push_ledger_json(&arr, "c3");
        push_ledger_json(&arr, "netdisrupt");
    }
    json_push_kv(out, "ledgers", &arr);
    json_free(&arr);

    const struct json_value *ledgers = json_get(out, "ledgers");
    int alarms = 0;
    size_t n = ledgers ? json_size(ledgers) : 0;
    for (size_t i = 0; i < n; i++) {
        /* EITHER rung counts. Rolling up only "alarm" would put the
         * no-pass rung on the typed surface and still leave the top-level
         * answer green, which is the same silence one level up. */
        const struct json_value *led = json_at(ledgers, i);
        if (json_get_bool(json_get(led, "alarm")) ||
            json_get_bool(json_get(led, "no_pass_alarm")))
            alarms++;
    }
    json_push_kv_int(out, "alarm_count", alarms);
    json_push_kv_bool(out, "alarm", alarms > 0);
    return true;
}
