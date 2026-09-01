/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * tip_agreement_watch — see services/tip_agreement_watch.h for the full
 * contract: what the three outcomes mean, why this is reporter-only, why it
 * arms no supervised child, and the ORDER in which a sample is graded
 * (independence first, hash bytes second, recorded outcome last).
 *
 * Pure file-scan observer: no DB writes, no threads, no chain locks, no
 * allocation, nothing latched. Row parsing and the bounded tail read come
 * from services/evidence_ledger_row.h — one reader, not a second copy. */

// one-result-type-ok:tip-agreement-reporter-no-fallible-surface
//
// A read-only evidence reader, not a fallible service executor. Its surfaces
// are bool probes (scan, read, resolve), pure classifiers, a formatter, and
// the project-wide bool dump_state_json convention. Every "false" here means
// the CALLER passed bad arguments; a missing or unreadable ledger is data
// (present=false), never an error a caller branches on, because absence of an
// agreement ledger is exactly what a host that never installed the recorder
// looks like.

#include "services/tip_agreement_watch.h"

#include "services/evidence_ledger_row.h"

#include "json/json.h"
#include "util/log_macros.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

#define TIP_AGREEMENT_LEDGER_DIR_ENV "ZCL_PARITY_LEDGER_DIR"
#define TIP_AGREEMENT_LEDGER_HOME_REL ".local/state/zclassic23-parity"
#define TIP_AGREEMENT_LEDGER_FILE "agreement-ledger.jsonl"

/* The recorded `outcome` vocabulary, in one table so the enum, the names and
 * the parser cannot drift apart. */
struct outcome_row {
    const char *text;
    enum tip_agreement_outcome value;
};

static const struct outcome_row g_outcomes[] = {
    { "agrees",        TIP_AGREEMENT_OUTCOME_AGREES },
    { "disagrees",     TIP_AGREEMENT_OUTCOME_DISAGREES },
    { "could-not-ask", TIP_AGREEMENT_OUTCOME_COULD_NOT_ASK },
};

#define OUTCOME_ROW_COUNT (sizeof(g_outcomes) / sizeof(g_outcomes[0]))

const char *tip_agreement_outcome_name(enum tip_agreement_outcome o)
{
    for (size_t i = 0; i < OUTCOME_ROW_COUNT; i++) {
        if (g_outcomes[i].value == o)
            return g_outcomes[i].text;
    }
    return "unknown";
}

const char *tip_agreement_independence_name(enum tip_agreement_independence i)
{
    switch (i) {
    case TIP_AGREEMENT_INDEPENDENCE_SUFFICIENT:   return "sufficient";
    case TIP_AGREEMENT_INDEPENDENCE_INSUFFICIENT: return "insufficient";
    case TIP_AGREEMENT_INDEPENDENCE_UNKNOWN:      break;
    }
    return "unknown";
}

/* ── the derived contract ────────────────────────────────────────────── */

int64_t tip_agreement_required_distinct_peers(int64_t min_distinct_peers)
{
    /* A control we cannot read is not a control. This is deliberately NOT
     * defaulted to the shipped floor: a row that never recorded which floor
     * was in force cannot testify that any floor was. */
    if (min_distinct_peers < 1)
        return -1; // raw-return-ok:unreadable-control-sentinel-not-an-error
    /* THE FLOOR. `min_distinct_peers` is a field of the row being graded, so
     * grading against it alone lets the row set its own bar: a ledger written
     * with ZCL_PARITY_MIN_DISTINCT_PEERS=1 (or copied in, or crafted) would
     * report control=1, be backed by its single peer, and grade SUFFICIENT —
     * one host manufacturing agreement, the precise failure this module
     * exists to prevent. So the row may only ever RAISE the bar. */
    if (min_distinct_peers < TIP_AGREEMENT_MIN_DISTINCT_PEERS)
        return TIP_AGREEMENT_MIN_DISTINCT_PEERS;
    return min_distinct_peers;
}

enum tip_agreement_independence
tip_agreement_classify_independence(int64_t modal_remote_peers,
                                    int64_t min_distinct_peers)
{
    int64_t required =
        tip_agreement_required_distinct_peers(min_distinct_peers);
    if (required < 1)
        return TIP_AGREEMENT_INDEPENDENCE_UNKNOWN;
    /* -1 is "the recorder did not count". Nobody counted is not enough. */
    if (modal_remote_peers < required)
        return TIP_AGREEMENT_INDEPENDENCE_INSUFFICIENT;
    return TIP_AGREEMENT_INDEPENDENCE_SUFFICIENT;
}

/* Case-insensitive hex compare. Our own hash has come back from the RPC in
 * capital letters before, and a case difference must not read as a fork. */
static bool hash_bytes_equal(const char *a, const char *b)
{
    if (!a || !b || !a[0] || !b[0])
        return false;
    size_t i = 0;
    for (; a[i] && b[i]; i++) {
        char ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'Z')
            ca = (char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z')
            cb = (char)(cb - 'A' + 'a');
        if (ca != cb)
            return false;
    }
    return a[i] == '\0' && b[i] == '\0';
}

bool tip_agreement_reports_agreement(const struct tip_agreement_report *r)
{
    if (!r || !r->present)
        return false;
    /* 1. independence first — one peer is an anecdote. */
    if (r->independence != TIP_AGREEMENT_INDEPENDENCE_SUFFICIENT)
        return false;
    /* 2. the recorded BYTES, not the recorded verdict. */
    if (!r->hashes_match)
        return false;
    /* 3. and only then the outcome the recorder wrote down. */
    return r->outcome == TIP_AGREEMENT_OUTCOME_AGREES;
}

/* Short form of a hash for a one-line summary; empty reads as "-". */
static const char *hash_brief(const char *hex, char *buf, size_t cap)
{
    if (!hex || !hex[0]) {
        evidence_copy_bounded(buf, cap, "-", 1);
        return buf;
    }
    snprintf(buf, cap, "%.16s", hex);
    return buf;
}

const char *tip_agreement_summary_text(const struct tip_agreement_report *r,
                                       char *buf, size_t cap)
{
    if (!buf || cap == 0)
        return "";
    buf[0] = '\0';
    if (!r) {
        evidence_copy_bounded(buf, cap, "no report", strlen("no report"));
        return buf;
    }
    if (!r->present) {
        snprintf(buf, cap,
                 "no_ledger — the off-host tip-hash agreement recorder has "
                 "never written a row on this host (make install-tip-agreement)");
        return buf;
    }

    char ours[24], theirs[24];
    hash_brief(r->our_tip_hash, ours, sizeof(ours));
    hash_brief(r->modal_remote_hash, theirs, sizeof(theirs));

    /* ORDER IS THE CONTRACT — see the header. Independence is answered before
     * anything that could read as a verdict, so a sample backed by one
     * non-independent peer can never print "agrees". */
    if (r->independence != TIP_AGREEMENT_INDEPENDENCE_SUFFICIENT) {
        /* `required` is the bar that was actually applied — the row's recorded
         * control raised to TIP_AGREEMENT_MIN_DISTINCT_PEERS — not the number
         * the row asked to be judged by. Printing the row's own number here
         * would tell an operator a weakened control had been honoured. */
        snprintf(buf, cap,
                 "%s independence=%s backed_by=%lld required=%lld "
                 "control_recorded=%lld peers_usable=%lld height=%lld "
                 "recorded_outcome=%s — no agreement verdict from this sample",
                 TIP_AGREEMENT_INSUFFICIENT_TOKEN,
                 tip_agreement_independence_name(r->independence),
                 (long long)r->modal_remote_peers,
                 (long long)tip_agreement_required_distinct_peers(
                     r->min_distinct_peers),
                 (long long)r->min_distinct_peers,
                 (long long)r->peers_usable, (long long)r->height,
                 tip_agreement_outcome_name(r->outcome));
        return buf;
    }

    /* A row whose recorded outcome claims agreement while its own recorded
     * hashes differ is a contradiction in the ledger, not agreement. */
    if (r->outcome == TIP_AGREEMENT_OUTCOME_AGREES && !r->hashes_match) {
        snprintf(buf, cap,
                 "%s height=%lld ours=%s modal_remote=%s backed_by=%lld "
                 "— the row says agrees while its own hashes differ; "
                 "not agreement",
                 TIP_AGREEMENT_CONTRADICTION_TOKEN, (long long)r->height,
                 ours, theirs, (long long)r->modal_remote_peers);
        return buf;
    }

    if (r->outcome == TIP_AGREEMENT_OUTCOME_DISAGREES) {
        snprintf(buf, cap,
                 "disagrees height=%lld ours=%s modal_remote=%s backed_by=%lld "
                 "disagreeing_peers=%lld contested_peers=%lld",
                 (long long)r->height, ours, theirs,
                 (long long)r->modal_remote_peers,
                 (long long)r->disagreeing_peers,
                 (long long)r->contested_peers);
        return buf;
    }

    if (tip_agreement_reports_agreement(r)) {
        snprintf(buf, cap,
                 "agrees height=%lld hash=%s backed_by=%lld distinct remote "
                 "hosts (required %lld, control_recorded %lld) groups=%lld "
                 "contested_peers=%lld",
                 (long long)r->height, theirs,
                 (long long)r->modal_remote_peers,
                 (long long)tip_agreement_required_distinct_peers(
                     r->min_distinct_peers),
                 (long long)r->min_distinct_peers,
                 (long long)r->modal_remote_groups,
                 (long long)r->contested_peers);
        return buf;
    }

    snprintf(buf, cap,
             "%s height=%lld reason=\"%s\" peers_usable=%lld — nothing "
             "comparable; not agreement",
             tip_agreement_outcome_name(r->outcome), (long long)r->height,
             r->reason[0] ? r->reason : "-", (long long)r->peers_usable);
    return buf;
}

/* ── scan ───────────────────────────────────────────────────────────── */

static void scan_init(struct tip_agreement_report *out)
{
    memset(out, 0, sizeof(*out));
    out->last_agree_ts = -1;
    out->last_disagree_ts = -1;
    out->last_ts = -1;
    out->our_height = -1;
    out->height = -1;
    out->modal_remote_peers = -1;
    out->modal_remote_groups = -1;
    out->disagreeing_peers = -1;
    out->contested_peers = -1;
    out->peers_usable = -1;
    out->min_distinct_peers = -1;
    out->excluded_hosts = -1;
    out->outcome = TIP_AGREEMENT_OUTCOME_UNKNOWN;
    out->independence = TIP_AGREEMENT_INDEPENDENCE_UNKNOWN;
}

/* Read one int field, or -1 when the field is absent or JSON null. The -1 is
 * the report's documented UNKNOWN sentinel, not an error code: "the recorder
 * did not measure this" has to stay distinguishable from a measured 0, because
 * a null read as 0 is how "nobody counted the disagreeing peers" becomes "zero
 * peers disagreed". Nothing here can fail, so there is nothing to log. */
static int64_t row_int_or_unknown(const char *row, size_t len, const char *key)
{
    int64_t v = -1;
    if (!evidence_row_int(row, len, key, &v))
        return -1; // raw-return-ok:unknown-sentinel-not-an-error
    return v;
}

static void scan_row(const char *row, size_t rlen, void *ctx)
{
    struct tip_agreement_report *out = ctx;
    if (rlen == 0)
        return;

    char outcome_text[32];
    if (!evidence_row_str(row, rlen, "outcome", outcome_text,
                          sizeof(outcome_text)) || outcome_text[0] == '\0') {
        out->malformed_rows++;
        return;
    }

    enum tip_agreement_outcome outcome = TIP_AGREEMENT_OUTCOME_UNKNOWN;
    for (size_t i = 0; i < OUTCOME_ROW_COUNT; i++) {
        if (strcmp(g_outcomes[i].text, outcome_text) == 0) {
            outcome = g_outcomes[i].value;
            break;
        }
    }

    out->rows_scanned++;
    out->present = true;

    int64_t ts = row_int_or_unknown(row, rlen, "ts");
    switch (outcome) {
    case TIP_AGREEMENT_OUTCOME_AGREES:
        out->agrees++;
        out->last_agree_ts = ts;
        break;
    case TIP_AGREEMENT_OUTCOME_DISAGREES:
        out->disagrees++;
        out->last_disagree_ts = ts;
        break;
    case TIP_AGREEMENT_OUTCOME_COULD_NOT_ASK:
        out->could_not_ask++;
        break;
    case TIP_AGREEMENT_OUTCOME_UNKNOWN:
        /* Counted, never folded into could-not-ask: an unrecognised state
         * that silently reads as "nothing to see" is how a recorder bug
         * becomes invisible. */
        out->unknown_outcome_rows++;
        break;
    }

    /* The last usable row wins every per-sample field. */
    out->outcome = outcome;
    out->last_ts = ts;
    out->our_height = row_int_or_unknown(row, rlen, "our_height");
    out->height = row_int_or_unknown(row, rlen, "height");
    out->modal_remote_peers = row_int_or_unknown(row, rlen,
                                                 "modal_remote_peers");
    out->modal_remote_groups = row_int_or_unknown(row, rlen,
                                                  "modal_remote_groups");
    out->disagreeing_peers = row_int_or_unknown(row, rlen, "disagreeing_peers");
    out->contested_peers = row_int_or_unknown(row, rlen, "contested_peers");
    out->peers_usable = row_int_or_unknown(row, rlen, "peers_usable");
    out->min_distinct_peers = row_int_or_unknown(row, rlen,
                                                 "min_distinct_peers");
    out->excluded_hosts = row_int_or_unknown(row, rlen, "excluded_hosts");
    (void)evidence_row_str(row, rlen, "our_tip_hash", out->our_tip_hash,
                           sizeof(out->our_tip_hash));
    (void)evidence_row_str(row, rlen, "modal_remote_hash",
                           out->modal_remote_hash,
                           sizeof(out->modal_remote_hash));
    (void)evidence_row_str(row, rlen, "reason", out->reason,
                           sizeof(out->reason));
}

static void scan_finish(struct tip_agreement_report *out)
{
    out->independence =
        tip_agreement_classify_independence(out->modal_remote_peers,
                                            out->min_distinct_peers);
    out->hashes_match = hash_bytes_equal(out->our_tip_hash,
                                         out->modal_remote_hash);
}

bool tip_agreement_scan(const char *text, size_t len,
                        struct tip_agreement_report *out)
{
    if (!out)
        LOG_FAIL("tip_agreement", "report output is NULL");
    scan_init(out);
    if (!evidence_ledger_scan_text(text, len, scan_row, out))
        LOG_FAIL("tip_agreement", "ledger text scan rejected len=%zu", len);
    scan_finish(out);
    return true;
}

bool tip_agreement_read_ledger(const char *path,
                               struct tip_agreement_report *out)
{
    if (!out)
        LOG_FAIL("tip_agreement", "report output is NULL");
    scan_init(out);
    if (!path || !path[0])
        LOG_FAIL("tip_agreement", "ledger path is NULL/empty");
    /* Overlong rows count as malformed; a line with no newline at EOF is
     * counted SEPARATELY and never handed over as a sample — a torn append
     * must not be able to become the last row scanned, which is the row every
     * per-sample field comes from. */
    if (!evidence_ledger_scan_tail(path, TIP_AGREEMENT_TAIL_BYTES, scan_row,
                                   out, &out->malformed_rows,
                                   &out->incomplete_rows))
        LOG_FAIL("tip_agreement", "ledger tail read rejected path '%s'", path);
    scan_finish(out);
    return true;
}

bool tip_agreement_resolve_ledger(char *out, size_t cap)
{
    if (!out || cap == 0)
        LOG_FAIL("tip_agreement", "path output buffer is NULL/empty");
    if (!evidence_ledger_resolve_path(TIP_AGREEMENT_LEDGER_DIR_ENV,
                                      TIP_AGREEMENT_LEDGER_HOME_REL,
                                      TIP_AGREEMENT_LEDGER_FILE, out, cap))
        LOG_FAIL("tip_agreement", "could not resolve the agreement ledger path");
    return true;
}

/* ── typed surface: dumpstate tip_agreement ──────────────────────────── */

static void push_last_sample(struct json_value *parent,
                             const struct tip_agreement_report *r)
{
    struct json_value obj;
    json_init(&obj);
    json_set_object(&obj);
    json_push_kv_int(&obj, "ts", r->last_ts);
    json_push_kv_int(&obj, "our_height", r->our_height);
    json_push_kv_int(&obj, "height", r->height);
    json_push_kv_str(&obj, "our_tip_hash",
                     r->our_tip_hash[0] ? r->our_tip_hash : "");
    json_push_kv_str(&obj, "modal_remote_hash",
                     r->modal_remote_hash[0] ? r->modal_remote_hash : "");
    json_push_kv_bool(&obj, "hashes_match", r->hashes_match);
    json_push_kv_int(&obj, "independent_peers_backing_mode",
                     r->modal_remote_peers);
    json_push_kv_int(&obj, "independent_groups_backing_mode",
                     r->modal_remote_groups);
    json_push_kv_int(&obj, "disagreeing_peers", r->disagreeing_peers);
    json_push_kv_int(&obj, "contested_peers", r->contested_peers);
    json_push_kv_int(&obj, "peers_usable", r->peers_usable);
    json_push_kv_int(&obj, "min_distinct_peers_control", r->min_distinct_peers);
    /* The bar actually applied: the recorded control raised to
     * TIP_AGREEMENT_MIN_DISTINCT_PEERS. Published next to the recorded value so
     * a weakened control is visible as weakened rather than as honoured. */
    json_push_kv_int(&obj, "min_distinct_peers_required",
                     tip_agreement_required_distinct_peers(
                         r->min_distinct_peers));
    json_push_kv_int(&obj, "excluded_hosts", r->excluded_hosts);
    json_push_kv_str(&obj, "recorded_outcome",
                     tip_agreement_outcome_name(r->outcome));
    json_push_kv_str(&obj, "reason", r->reason[0] ? r->reason : "");
    json_push_kv_str(&obj, "independence",
                     tip_agreement_independence_name(r->independence));
    (void)json_push_kv(parent, "last_sample", &obj);
    json_free(&obj);
}

static void push_rollup(struct json_value *parent,
                        const struct tip_agreement_report *r)
{
    struct json_value obj;
    json_init(&obj);
    json_set_object(&obj);
    json_push_kv_int(&obj, "rows_scanned", r->rows_scanned);
    json_push_kv_int(&obj, "malformed_rows", r->malformed_rows);
    json_push_kv_int(&obj, "incomplete_rows", r->incomplete_rows);
    json_push_kv_int(&obj, "unknown_outcome_rows", r->unknown_outcome_rows);
    json_push_kv_int(&obj, "agrees", r->agrees);
    json_push_kv_int(&obj, "disagrees", r->disagrees);
    json_push_kv_int(&obj, "could_not_ask", r->could_not_ask);
    json_push_kv_int(&obj, "last_agree_ts", r->last_agree_ts);
    json_push_kv_int(&obj, "last_disagree_ts", r->last_disagree_ts);
    (void)json_push_kv(parent, "tail_rollup", &obj);
    json_free(&obj);
}

bool tip_agreement_dump_state_json(struct json_value *out, const char *key)
{
    if (!out)
        LOG_FAIL("tip_agreement", "dump output is NULL");
    json_set_object(out);

    bool last_only = false;
    if (key && key[0]) {
        if (strcmp(key, "last") != 0) {
            json_push_kv_str(out, "error",
                             "unknown key: use 'last', or no key for the "
                             "whole report");
            return true;
        }
        last_only = true;
    }

    json_push_kv_str(out, "role",
                     "REPORTER ONLY — describes the off-host tip-hash "
                     "agreement ledger on disk; never grades a sample, never "
                     "mints or clears an agreement claim, feeds no score. "
                     "tools/scripts/tip_agreement_judge.sh is the judge");

    char path[PATH_MAX];
    bool resolved = tip_agreement_resolve_ledger(path, sizeof(path));
    json_push_kv_str(out, "ledger_path", resolved ? path : "unresolved");

    struct tip_agreement_report rep;
    if (!resolved || !tip_agreement_read_ledger(path, &rep))
        scan_init(&rep);

    json_push_kv_bool(out, "present", rep.present);
    push_last_sample(out, &rep);
    if (!last_only)
        push_rollup(out, &rep);

    /* The one claim, from the one predicate. */
    json_push_kv_bool(out, "agreement_reported",
                      tip_agreement_reports_agreement(&rep));
    json_push_kv_bool(out, "insufficient_independent_peers",
                      rep.present &&
                      rep.independence !=
                          TIP_AGREEMENT_INDEPENDENCE_SUFFICIENT);

    char text[TIP_AGREEMENT_SUMMARY_MAX];
    json_push_kv_str(out, "summary",
                     tip_agreement_summary_text(&rep, text, sizeof(text)));
    return true;
}
