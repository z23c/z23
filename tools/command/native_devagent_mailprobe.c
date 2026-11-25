/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.agent.mail.probe: measure end-to-end agent-mail latency between two
 * boxes as a number, so "under one second across real hosts" is a
 * measurement and not a belief.
 *
 * ── CONTRACT ───────────────────────────────────────────────────────────────
 *
 * WHAT IS MEASURED. A probe row is posted on host A (dev.agent.mail post, in
 * process) and an echo row is posted by host B when the probe row is first
 * readable in B's maildir. A learns of the echo when the echo row is first
 * readable in A's maildir. Four unix-millisecond timestamps, each taken at the
 * point named and nowhere else:
 *   t1  A, immediately before the probe post;
 *   t2  B, right after the call that first returned the probe row;
 *   t3  B, immediately before the echo post;
 *   t4  A, right after the call that first returned the echo row.
 * Clock offset between the hosts cancels in the standard four-timestamp
 * method: network = (t4 - t1) - (t3 - t2), one_way = network / 2. That
 * assumes a symmetric path and clocks that tick at the same rate; a sample
 * whose arithmetic contradicts either (t3 < t2, t4 < t1, a negative network
 * time) is reported INVALID with its reason, never silently clamped.
 * "First readable" is the granularity of one directory-watcher wake plus one
 * mail pull, because both sides read through dev.agent.mail.wait; that is the
 * same path a real reader uses, so it is the honest bound.
 *
 * ROLES (action). send: post `probes` notes (default 20, 1..64) to the peer
 * BOX `to`, then collect the echoes. echo: a bounded one-shot run on the peer
 * that answers every unanswered probe row addressed to `from` (this box),
 * waiting up to timeout_ms for more, at most `probes` echoes. Start the echo
 * run BEFORE the send run: a probe row that was already in the maildir when
 * the echo run started has no honest t2, so its echo carries basis=scan and
 * the sender reports that sample INVALID (t2_unmeasured_scan). `since` (a
 * next_since token an earlier echo run returned) declares that rows after it
 * are new, and those rows are basis=watch.
 *
 * HARMLESS BY CONSTRUCTION. The kind is the literal note: kind, body and ref
 * are not inputs and are refused by name (PROBE_FIELD_FIXED). The body begins
 * with the fixed prefix "z23-probe v1 " (echo: "z23-probe-echo v1 ") and is
 * at most 96 bytes; the ref is probe.<12 hex nonce>.<index>. A directive is
 * never produced, and the echo role ignores any row whose kind is not note,
 * whose body lacks the prefix or exceeds the cap, and rows whose ts is older
 * than an hour. `to` must be one well-formed name that is neither "*" nor
 * this run's `from`. That is all that is checked: neither name is compared
 * with the roster (no read-only roster source is used), so an alias or an
 * unknown name passes and the run simply reports missing echoes. A probe
 * never fans out to "*".
 * The signed fleet board admits 60 posts per 10 minutes per key, and that
 * quota is per host key: it is shared with every other mail the host posts
 * (other names on the host, a concurrent send and echo, the receiver's own
 * exports). This leaf refuses to spend more than 40 of them:
 * PROBE_RATE_OVER_BUDGET when the count and interval would put more than 40
 * posts in any 10-minute window, PROBE_QUOTA_RECENT when this name already
 * posted probe or echo rows in the last 10 minutes that, with this run, pass
 * 40. The budget does NOT account for the quota other mail spends, so a
 * probe run can still push real mail over the board quota (delayed, not
 * lost).
 *
 * WHICH STREAM A ROW CAME FROM. Every pull row names its `stream`:
 * outbox.jsonl (this box's own posts) or inbox.<box>.jsonl (mail that
 * arrived from outside). Delivery means arrival in an inbox, so: the echo
 * role answers a probe row only when it was read from an inbox stream
 * (counted as skipped_not_inbox otherwise), and the send role counts an echo
 * only when it was read from inbox.<to>.jsonl, the stream of the addressed
 * peer, and its `from` is that peer. Any other echo is an INVALID sample
 * (echo_not_from_peer_inbox, echo_from_not_peer), excluded from percentiles
 * and counted (echo_wrong_stream, echo_from_not_peer); a later echo from the
 * right source replaces it. Running both roles on one box therefore yields
 * no valid sample.
 *
 * REPORT. Every sample (ref, t1..t4, state, reason, legs), counts sent,
 * echoed, valid, missing, invalid, and p50, p90, p99 and max of one_way_ms.
 * The percentile rule is nearest-rank over the SENT population with missing
 * and invalid samples sorted last: a percentile whose rank falls past the
 * valid samples is the string "missing", never dropped from the population
 * (p99 is "missing" once more than 1% of the sent probes have no valid echo;
 * max is "missing" if any sample has none). Fewer than 10 sent probes, or
 * fewer than 10 valid samples, refuse every percentile by name
 * (status "refused") and still list the samples. `transport` is taken from
 * the rows' own evidence, per leg of each VALID sample. A leg is "board"
 * only when its row came from an inbox stream and carries a 64-lowercase-hex
 * board_post AND board_signer; "other" when it came from an inbox stream
 * with no board fields; "unattributed" for anything else (a partial or
 * malformed board field, or a non-inbox stream). The result is the one label
 * every leg shares, "mixed" when legs differ or the same echo arrived by two
 * carriers (that sample's echo_leg is "mixed"), "none" with no valid sample.
 * "board" means "carries well-formed board fields on an inbox stream"; it is
 * NOT verified against the node, because no existing read-only call confirms
 * a post without touching the held mail files. The route the first probe post
 * reported (export_eligible or local) is recorded as first_post_delivery but
 * is not delivery evidence or a gate: the mail_carry baseline is measurable
 * with the same leaf.
 *
 * PROCESS RULE. No spawn, no network, no direct file access: mail is read and
 * written only through dev.agent.mail and dev.agent.mail.wait, in process. */

#include "command/native_command.h"
#include "command/native_devagent_mailprobe.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/rng.h"
#include "platform/time_compat.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PM_SCHEMA "zcl.agent_mail_probe.v1"
#define PM_KIND "note"
#define PM_PROBE_PREFIX "z23-probe v1 "
#define PM_ECHO_PREFIX "z23-probe-echo v1 "
#define PM_REF_PREFIX "probe."
#define PM_BODY_MAX 96u
#define PM_ECHO_BODY_MAX 160u
#define PM_REF_MAX 40u
#define PM_NAME_MAX 129u
#define PM_COUNT_MAX 64
#define PM_COUNT_DEFAULT 20
#define PM_MIN_SAMPLES 10u
#define PM_NONCE_HEX 12u
#define PM_QUOTA_BUDGET 40u
#define PM_QUOTA_WINDOW_S 600
#define PM_STALE_S 3600
#define PM_INTERVAL_MAX_MS 600000
#define PM_RUN_MAX_MS 3600000
#define PM_TIMEOUT_DEFAULT_MS 30000
#define PM_TIMEOUT_MAX_MS 300000
#define PM_TOKEN_CAP 4096u
#define PM_PAGES_MAX 512u
#define PM_PENDING_MAX 256u
#define PM_LEG_MAX 16u
#define PM_HEX_LEN 64u

/* The mail leaves, held as pointers: this leaf builds every request itself
 * and forwards no caller key. */
static const zcl_command_handler_fn pm_mail = zcl_native_handle_dev_agent_mail;
static const zcl_command_handler_fn pm_wait =
    zcl_native_handle_dev_agent_mail_wait;

/* ── clock ─────────────────────────────────────────────────────────────── */

typedef int64_t (*pm_clock_fn)(void *ctx);
typedef void (*pm_pump_fn)(void *ctx);

static pm_clock_fn g_pm_clock;
static void *g_pm_clock_ctx;
static pm_pump_fn g_pm_pump;
static void *g_pm_pump_ctx;

#ifdef ZCL_TESTING
void zcl_devagent_mailprobe_test_set_clock(zcl_devagent_mailprobe_clock_fn fn,
                                           void *ctx)
{
    g_pm_clock = fn;
    g_pm_clock_ctx = ctx;
}

void zcl_devagent_mailprobe_test_set_pump(zcl_devagent_mailprobe_pump_fn fn,
                                          void *ctx)
{
    g_pm_pump = fn;
    g_pm_pump_ctx = ctx;
}
#endif

/* Unix milliseconds: the one source of t1..t4. */
static int64_t pm_wall_ms(void)
{
    if (g_pm_clock)
        return g_pm_clock(g_pm_clock_ctx);
    return platform_time_realtime_us() / 1000;
}

/* ── refusals ──────────────────────────────────────────────────────────── */

static void pm_refuse(struct zcl_command_reply *reply, const char *code,
                      const char *msg, const char *evidence)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, "probe-input", false,
                           false, msg, evidence);
}

/* A run that started and then failed: rows may already be posted. */
static void pm_abort(struct zcl_command_reply *reply, const char *code,
                     const char *msg, const char *evidence, bool mutated)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, code, "probe", false,
                           mutated, msg, evidence);
}

/* ── small parsers ─────────────────────────────────────────────────────── */

static bool pm_starts(const char *s, const char *prefix)
{
    return s && strncmp(s, prefix, strlen(prefix)) == 0;
}

static const char *pm_str(const struct json_value *row, const char *key)
{
    const struct json_value *field = json_get(row, key);
    if (!field || field->type != JSON_STR)
        return "";
    return json_get_str(field) ? json_get_str(field) : "";
}

/* 64 lowercase hex characters: the shape the board carry writes. */
static bool pm_hex64(const char *s)
{
    size_t n = 0;
    for (; s[n]; n++)
        if (!((s[n] >= '0' && s[n] <= '9') || (s[n] >= 'a' && s[n] <= 'f')))
            return false;
    return n == PM_HEX_LEN;
}

/* Mail that arrived from outside: a row read from inbox.<box>.jsonl. This
 * box's own outbox.jsonl is never delivery. */
static bool pm_stream_inbox(const struct json_value *row)
{
    const char *s = pm_str(row, "stream");
    size_t n = strlen(s);
    return pm_starts(s, "inbox.") && n > 12 &&
           strcmp(s + n - 6, ".jsonl") == 0 && !strchr(s, '/');
}

/* The inbox stream of one named peer box. */
static bool pm_stream_of(const struct json_value *row, const char *peer)
{
    char want[PM_NAME_MAX + 16];
    int w = snprintf(want, sizeof(want), "inbox.%s.jsonl", peer);
    return w > 0 && (size_t)w < sizeof(want) &&
           strcmp(pm_str(row, "stream"), want) == 0;
}

/* What a row's own evidence supports about its carrier. */
static const char *pm_leg_label(const struct json_value *row)
{
    const char *post = pm_str(row, "board_post");
    const char *signer = pm_str(row, "board_signer");
    if (!pm_stream_inbox(row))
        return "unattributed";
    if (!post[0] && !signer[0])
        return "other";
    return pm_hex64(post) && pm_hex64(signer) ? "board" : "unattributed";
}

static bool pm_leg_known(const char *leg)
{
    return strcmp(leg, "board") == 0 || strcmp(leg, "other") == 0;
}

/* The name charset dev.agent.mail accepts for a sender or recipient. */
static bool pm_name_ok(const char *s)
{
    if (!s || !s[0] || strlen(s) >= PM_NAME_MAX)
        return false;
    for (const char *p = s; *p; p++)
        if (!isalnum((unsigned char)*p) && *p != '.' && *p != '_' &&
            *p != '-' && *p != '@')
            return false;
    return true;
}

static bool pm_ref_ok(const char *s)
{
    if (!pm_starts(s, PM_REF_PREFIX) || strlen(s) >= PM_REF_MAX)
        return false;
    for (const char *p = s; *p; p++)
        if (!isalnum((unsigned char)*p) && *p != '.' && *p != '_' &&
            *p != '-')
            return false;
    return true;
}

/* " key=<integer>" inside a body; the key carries its own '='. */
static bool pm_field_ll(const char *body, const char *key, long long *out)
{
    char tag[16];
    const char *at;
    char *end;
    int n = snprintf(tag, sizeof(tag), " %s", key);
    if (n <= 0 || (size_t)n >= sizeof(tag))
        return false;
    at = strstr(body, tag);
    if (!at)
        return false;
    *out = strtoll(at + n, &end, 10);
    return end != at + n;
}

/* " key=<word>" inside a body, copied up to the next space. */
static bool pm_field_word(const char *body, const char *key, char *out,
                          size_t cap)
{
    char tag[16];
    const char *at;
    size_t n = 0;
    int t = snprintf(tag, sizeof(tag), " %s", key);
    if (t <= 0 || (size_t)t >= sizeof(tag))
        return false;
    at = strstr(body, tag);
    if (!at)
        return false;
    at += t;
    while (at[n] && at[n] != ' ' && n + 1 < cap) {
        out[n] = at[n];
        n++;
    }
    out[n] = '\0';
    return n > 0;
}

/* "YYYY-MM-DDTHH:MM:SSZ" (the mail row ts) to unix seconds. */
static bool pm_ts_epoch(const char *ts, int64_t *out)
{
    int y, mo, d, h, mi, s;
    char z = 0;
    int64_t yy, era, yoe, doy, doe;
    if (!ts || sscanf(ts, "%4d-%2d-%2dT%2d:%2d:%2d%c", &y, &mo, &d, &h, &mi,
                      &s, &z) != 7 || z != 'Z' || mo < 1 || mo > 12 ||
        d < 1 || d > 31 || h > 23 || mi > 59 || s > 60)
        return false;
    yy = mo <= 2 ? y - 1 : y;
    era = (yy >= 0 ? yy : yy - 399) / 400;
    yoe = yy - era * 400;
    doy = (153 * (mo + (mo > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    *out = (era * 146097 + doe - 719468) * 86400 + h * 3600 + mi * 60 + s;
    return true;
}

/* True when the row ts is within `window_s` of now (real wall clock). */
static bool pm_ts_within(const char *ts, int64_t window_s)
{
    int64_t at, now = platform_time_wall_unix();
    return pm_ts_epoch(ts, &at) && at >= now - window_s;
}

/* ── in-process mail calls ─────────────────────────────────────────────── */

static bool pm_set_since(struct json_value *in, const char *token)
{
    if (!token || !token[0] || strcmp(token, "0") == 0)
        return json_push_kv_int(in, "since", 0);
    return json_push_kv_str(in, "since", token);
}

/* Run `handler` on a request built from `in`; `out` is always initialised. */
static bool pm_call(zcl_command_handler_fn handler,
                    const struct zcl_command_request *request,
                    struct json_value *in, struct zcl_command_reply *out)
{
    struct zcl_command_request sub = *request;
    sub.input = in;
    zcl_command_reply_init(out, "zcl.agent_mail.v1");
    handler(&sub, out);
    return out->status == ZCL_COMMAND_STATUS_PASSED;
}

/* Post one note. Kind is the literal PM_KIND: no caller value reaches it. */
static bool pm_post(const struct zcl_command_request *request,
                    const char *from, const char *to, const char *ref,
                    const char *body, struct zcl_command_reply *out)
{
    struct json_value in;
    bool ok, passed = false;
    json_init(&in);
    json_set_object(&in);
    ok = json_push_kv_str(&in, "action", "post") &&
         json_push_kv_str(&in, "from", from) &&
         json_push_kv_str(&in, "to", to) &&
         json_push_kv_str(&in, "kind", PM_KIND) &&
         json_push_kv_str(&in, "ref", ref) &&
         json_push_kv_str(&in, "body", body);
    zcl_command_reply_init(out, "zcl.agent_mail.v1");
    if (ok)
        passed = pm_call(pm_mail, request, &in, out);
    json_free(&in);
    return passed;
}

/* One non-blocking pull page of PM_KIND rows, optionally filtered. */
static bool pm_pull(const struct zcl_command_request *request,
                    const char *since, const char *to, const char *from,
                    struct zcl_command_reply *out)
{
    struct json_value in;
    bool ok, passed = false;
    json_init(&in);
    json_set_object(&in);
    ok = json_push_kv_str(&in, "action", "pull") && pm_set_since(&in, since) &&
         json_push_kv_str(&in, "kind", PM_KIND) &&
         (!to || json_push_kv_str(&in, "to", to)) &&
         (!from || json_push_kv_str(&in, "from", from));
    zcl_command_reply_init(out, "zcl.agent_mail.v1");
    if (ok)
        passed = pm_call(pm_mail, request, &in, out);
    json_free(&in);
    return passed;
}

/* One blocking wait for a PM_KIND row to `to` after `since`. */
static bool pm_wait_rows(const struct zcl_command_request *request,
                         const char *since, const char *to, int64_t timeout_ms,
                         struct zcl_command_reply *out)
{
    struct json_value in;
    bool ok, passed = false;
    json_init(&in);
    json_set_object(&in);
    ok = pm_set_since(&in, since) && json_push_kv_str(&in, "kind", PM_KIND) &&
         json_push_kv_str(&in, "to", to) &&
         json_push_kv_int(&in, "timeout_ms", timeout_ms);
    zcl_command_reply_init(out, "zcl.agent_mail.v1");
    if (ok)
        passed = pm_call(pm_wait, request, &in, out);
    json_free(&in);
    return passed;
}

/* Copy a reply's next_since token; false when absent or too long. */
static bool pm_next_token(const struct zcl_command_reply *r, char *out,
                          size_t cap)
{
    const struct json_value *v = json_get(&r->data, "next_since");
    const char *s = v && v->type == JSON_STR ? json_get_str(v) : NULL;
    if (!s || strlen(s) >= cap)
        return false;
    (void)snprintf(out, cap, "%s", s);
    return true;
}

typedef bool (*pm_row_fn)(const struct json_value *row, int64_t t_page,
                          void *ctx);

/* Visit every row of a reply's page. */
static void pm_each_row(const struct zcl_command_reply *r, int64_t t_page,
                        pm_row_fn fn, void *ctx)
{
    const struct json_value *rows = json_get(&r->data, "rows");
    for (size_t i = 0; rows && rows->type == JSON_ARR && i < json_size(rows);
         i++)
        (void)fn(json_at(rows, i), t_page, ctx);
}

/* Walk every page from `since` to the end of the maildir, calling fn per row
 * with the clock read right after the page returned. Returns NULL on
 * success, else a PROBE_* code; `next` receives the final cursor. */
static const char *pm_walk(const struct zcl_command_request *request,
                           const char *since, const char *to,
                           const char *from, pm_row_fn fn, void *ctx,
                           char *next, size_t cap, char inner[64])
{
    char token[PM_TOKEN_CAP];
    const char *cur = since;
    for (unsigned page = 0; page < PM_PAGES_MAX; page++) {
        struct zcl_command_reply r;
        const struct json_value *trunc;
        bool more;
        if (!pm_pull(request, cur, to, from, &r)) {
            (void)snprintf(inner, 64, "%s", r.error.code);
            zcl_command_reply_free(&r);
            return "PROBE_READ_FAILED";
        }
        pm_each_row(&r, pm_wall_ms(), fn, ctx);
        trunc = json_get(&r.data, "truncated");
        more = trunc && trunc->type == JSON_BOOL && json_get_bool(trunc);
        if (!pm_next_token(&r, token, sizeof(token))) {
            zcl_command_reply_free(&r);
            return "PROBE_READ_FAILED";
        }
        zcl_command_reply_free(&r);
        if (!more) {
            if (strlen(token) >= cap)
                return "PROBE_READ_FAILED";
            (void)snprintf(next, cap, "%s", token);
            return NULL;
        }
        cur = token;
    }
    return "PROBE_HISTORY_TOO_LONG";
}

/* ── input ─────────────────────────────────────────────────────────────── */

struct pm_input {
    bool send;
    char from[PM_NAME_MAX];
    char to[PM_NAME_MAX];
    char since[PM_TOKEN_CAP];
    int64_t probes, interval_ms, timeout_ms;
};

static const char *const pm_forbidden[] = {"kind", "body", "ref", "cwd",
                                           "sender_binding"};

static bool pm_forbidden_key(const struct json_value *input,
                             struct zcl_command_reply *reply)
{
    for (size_t i = 0; i < sizeof(pm_forbidden) / sizeof(pm_forbidden[0]);
         i++) {
        const struct json_value *v = json_get(input, pm_forbidden[i]);
        if (v && v->type != JSON_NULL) {
            pm_refuse(reply, "PROBE_FIELD_FIXED",
                      "probe kind, body and ref are fixed by the leaf: the "
                      "probe is a note with a fixed body prefix",
                      pm_forbidden[i]);
            return true;
        }
    }
    return false;
}

/* The sending name: input `from`, else $BOARD_AGENT, else $USER, else local
 * (the order dev.agent.mail post uses, so a probe row and a plain post agree). */
static bool pm_identity(const struct json_value *input, char *out)
{
    const struct json_value *v = json_get(input, "from");
    const char *name = v && v->type == JSON_STR ? json_get_str(v) : NULL;
    if (!name || !name[0])
        name = getenv("BOARD_AGENT");
    if (!name || !name[0])
        name = getenv("USER");
    if (!name || !name[0])
        name = "local";
    if (!pm_name_ok(name))
        return false;
    (void)snprintf(out, PM_NAME_MAX, "%s", name);
    return true;
}

/* Optional integer key; absent -> dflt. False writes the refusal. */
static bool pm_int(const struct json_value *input, const char *key,
                   int64_t dflt, int64_t *out, struct zcl_command_reply *reply)
{
    const struct json_value *v = json_get(input, key);
    *out = dflt;
    if (!v || v->type == JSON_NULL)
        return true;
    if (v->type == JSON_INT) {
        *out = json_get_int(v);
        return true;
    }
    pm_refuse(reply, "BAD_INPUT", "integer key expected", key);
    return false;
}

static bool pm_parse_names(const struct json_value *input, struct pm_input *in,
                           struct zcl_command_reply *reply)
{
    const struct json_value *to = json_get(input, "to");
    const struct json_value *since = json_get(input, "since");
    if (!pm_identity(input, in->from)) {
        pm_refuse(reply, "BAD_INPUT", "from names this box", "input.from");
        return false;
    }
    if (since && since->type == JSON_STR) {
        const char *s = json_get_str(since);
        if (!s || strlen(s) >= sizeof(in->since)) {
            pm_refuse(reply, "BAD_INPUT", "since is a next_since token",
                      "input.since");
            return false;
        }
        (void)snprintf(in->since, sizeof(in->since), "%s", s);
    }
    if (!in->send)
        return true;
    if (!to || to->type != JSON_STR || !pm_name_ok(json_get_str(to)) ||
        strcmp(json_get_str(to), "*") == 0) {
        pm_refuse(reply, "PROBE_TO_NOT_A_BOX",
                  "to is one well-formed peer name and never *; only its "
                  "spelling is checked, not the roster",
                  "input.to");
        return false;
    }
    (void)snprintf(in->to, sizeof(in->to), "%s", json_get_str(to));
    if (strcmp(in->to, in->from) == 0) {
        pm_refuse(reply, "PROBE_TO_IS_SELF",
                  "a probe to this box measures nothing", "input.to");
        return false;
    }
    return true;
}

static bool pm_parse_numbers(const struct json_value *input, struct pm_input *in,
                             struct zcl_command_reply *reply)
{
    if (!pm_int(input, "probes", PM_COUNT_DEFAULT, &in->probes, reply) ||
        !pm_int(input, "interval_ms", 0, &in->interval_ms, reply) ||
        !pm_int(input, "timeout_ms", PM_TIMEOUT_DEFAULT_MS, &in->timeout_ms,
                reply))
        return false;
    if (in->probes < 1 || in->probes > PM_COUNT_MAX) {
        pm_refuse(reply, "PROBE_COUNT_OUT_OF_RANGE",
                  "probes is 1..64: more cannot fit the board's per-key post "
                  "quota", "input.probes");
        return false;
    }
    if (in->interval_ms < 0 || in->interval_ms > PM_INTERVAL_MAX_MS) {
        pm_refuse(reply, "PROBE_INTERVAL_OUT_OF_RANGE",
                  "interval_ms is 0..600000", "input.interval_ms");
        return false;
    }
    if (in->timeout_ms < 1 || in->timeout_ms > PM_TIMEOUT_MAX_MS ||
        (in->probes - 1) * in->interval_ms + in->timeout_ms > PM_RUN_MAX_MS) {
        pm_refuse(reply, "PROBE_RUN_TOO_LONG",
                  "timeout_ms is 1..300000 and the whole run at most one "
                  "hour", "input.timeout_ms");
        return false;
    }
    return true;
}

static bool pm_parse(const struct zcl_command_request *request,
                     struct pm_input *in, struct zcl_command_reply *reply)
{
    const struct json_value *input = request->input;
    const struct json_value *action = json_get(input, "action");
    const char *name = action && action->type == JSON_STR
                           ? json_get_str(action) : "";
    memset(in, 0, sizeof(*in));
    if (pm_forbidden_key(input, reply))
        return false;
    if (strcmp(name, "send") != 0 && strcmp(name, "echo") != 0) {
        pm_refuse(reply, "PROBE_ACTION_UNKNOWN", "action is send or echo",
                  "input.action");
        return false;
    }
    in->send = strcmp(name, "send") == 0;
    return pm_parse_names(input, in, reply) &&
           pm_parse_numbers(input, in, reply);
}

/* ── the 10-minute post budget ─────────────────────────────────────────── */

struct pm_pending {
    char ref[PM_REF_MAX];
    char from[PM_NAME_MAX];
    char leg[PM_LEG_MAX];
    int64_t t1, t2;
    bool watch, answered;
};

struct pm_own {
    const char *self;
    struct pm_pending *pend;
    size_t npend;
    unsigned recent;
};

/* One of this box's own notes: count probe and echo rows posted inside the
 * quota window, and mark a pending probe answered by an echo row. */
static bool pm_own_row(const struct json_value *row, int64_t t_page, void *ctx)
{
    struct pm_own *own = ctx;
    const char *body = pm_str(row, "body");
    (void)t_page;
    if (strcmp(pm_str(row, "from"), own->self) != 0)
        return false;
    if (pm_starts(body, PM_ECHO_PREFIX)) {
        const char *ref = pm_str(row, "ref");
        for (size_t i = 0; i < own->npend; i++)
            if (strcmp(own->pend[i].ref, ref) == 0)
                own->pend[i].answered = true;
    } else if (!pm_starts(body, PM_PROBE_PREFIX)) {
        return false;
    }
    if (pm_ts_within(pm_str(row, "ts"), PM_QUOTA_WINDOW_S))
        own->recent++;
    return true;
}

/* Posts one run puts inside any 10-minute window. */
static unsigned pm_window_posts(int64_t count, int64_t interval_ms)
{
    int64_t burst;
    if (interval_ms <= 0)
        return (unsigned)count;
    burst = (int64_t)PM_QUOTA_WINDOW_S * 1000 / interval_ms + 1;
    return (unsigned)(burst < count ? burst : count);
}

/* Refuse a run that would spend more than the probe budget of the board's
 * 60-posts-per-10-minutes key quota. `own` has been filled by a walk. */
static bool pm_quota_ok(const struct pm_input *in, const struct pm_own *own,
                        struct zcl_command_reply *reply)
{
    unsigned planned = in->send ? pm_window_posts(in->probes, in->interval_ms)
                                : (unsigned)in->probes;
    char evidence[96];
    if (planned > PM_QUOTA_BUDGET) {
        (void)snprintf(evidence, sizeof(evidence),
                       "planned=%u budget=%u window_s=%d", planned,
                       PM_QUOTA_BUDGET, PM_QUOTA_WINDOW_S);
        pm_refuse(reply, "PROBE_RATE_OVER_BUDGET",
                  "this count and interval would put more than 40 posts in a "
                  "10-minute window; the board admits 60 per key", evidence);
        return false;
    }
    if (own->recent + planned > PM_QUOTA_BUDGET) {
        (void)snprintf(evidence, sizeof(evidence),
                       "recent=%u planned=%u budget=%u", own->recent, planned,
                       PM_QUOTA_BUDGET);
        pm_refuse(reply, "PROBE_QUOTA_RECENT",
                  "probe and echo rows already posted in the last 10 minutes "
                  "plus this run pass the 40-post probe budget", evidence);
        return false;
    }
    return true;
}

/* ── send role ─────────────────────────────────────────────────────────── */

enum pm_state { PM_MISSING = 0, PM_VALID, PM_INVALID };

struct pm_sample {
    char ref[PM_REF_MAX];
    char echo_from[PM_NAME_MAX];
    char probe_leg[PM_LEG_MAX], echo_leg[PM_LEG_MAX], basis[8];
    int64_t t1, t2, t3, t4, network_ms;
    const char *reason;
    int state;
    bool seen;
    bool bad_source, wrong_stream, wrong_from;
};

struct pm_send {
    const struct zcl_command_request *request;
    struct pm_input in;
    char nonce[PM_NONCE_HEX + 1];
    char cursor[PM_TOKEN_CAP];
    char inner[64];
    unsigned posted, seen, settled, duplicates, name_mismatch, wrong_stream;
    char delivery[24];
    struct pm_sample s[PM_COUNT_MAX];
};

/* Index of the sample an echo ref names, or -1. */
static int pm_ref_index(const struct pm_send *st, const char *ref)
{
    char head[PM_REF_MAX];
    size_t n;
    char *end;
    long idx;
    int w = snprintf(head, sizeof(head), PM_REF_PREFIX "%s.", st->nonce);
    if (w <= 0 || strncmp(ref, head, (size_t)w) != 0)
        return -1;
    n = (size_t)w;
    idx = strtol(ref + n, &end, 10);
    if (end == ref + n || *end || idx < 0 || (unsigned)idx >= st->posted)
        return -1;
    return (int)idx;
}

/* Fill a sample from one echo row. Arithmetic problems are decided later. */
static void pm_take_echo(struct pm_sample *s, const struct json_value *row,
                         int64_t t4, const char *to, struct pm_send *st)
{
    const char *body = pm_str(row, "body");
    long long t1 = 0, t2 = 0, t3 = 0;
    s->seen = true;
    st->seen++;
    s->t4 = t4;
    (void)snprintf(s->echo_from, sizeof(s->echo_from), "%s",
                   pm_str(row, "from"));
    (void)snprintf(s->echo_leg, sizeof(s->echo_leg), "%s", pm_leg_label(row));
    if (!pm_stream_of(row, to)) {
        s->bad_source = s->wrong_stream = true;
        s->state = PM_INVALID;
        s->reason = "echo_not_from_peer_inbox";
        return;
    }
    if (strcmp(s->echo_from, to) != 0) {
        s->bad_source = s->wrong_from = true;
        s->state = PM_INVALID;
        s->reason = "echo_from_not_peer";
        return;
    }
    st->settled++;
    if (strlen(body) > PM_ECHO_BODY_MAX ||
        !pm_field_ll(body, "t1=", &t1) || !pm_field_ll(body, "t2=", &t2) ||
        !pm_field_ll(body, "t3=", &t3) ||
        !pm_field_word(body, "pleg=", s->probe_leg, sizeof(s->probe_leg)) ||
        !pm_field_word(body, "basis=", s->basis, sizeof(s->basis))) {
        s->state = PM_INVALID;
        s->reason = "echo_body_malformed";
        return;
    }
    if (!pm_leg_known(s->probe_leg))
        (void)snprintf(s->probe_leg, sizeof(s->probe_leg), "unattributed");
    s->t2 = t2;
    s->t3 = t3;
    if (t1 != s->t1) {
        s->state = PM_INVALID;
        s->reason = "t1_mismatch";
    }
}

/* Is this row from the addressed peer's own inbox stream? */
static bool pm_echo_source_ok(const struct pm_send *st,
                              const struct json_value *row)
{
    return pm_stream_of(row, st->in.to) &&
           strcmp(pm_str(row, "from"), st->in.to) == 0;
}

/* A second row for an echo already taken. If it is from the right source
 * and a different carrier than the first, the sample's carrier is "mixed". */
static void pm_echo_again(struct pm_send *st, struct pm_sample *s,
                          const struct json_value *row)
{
    st->duplicates++;
    if (pm_echo_source_ok(st, row) &&
        strcmp(pm_leg_label(row), s->echo_leg) != 0)
        (void)snprintf(s->echo_leg, sizeof(s->echo_leg), "mixed");
}

/* One row from the wait page: an echo of one of this run's probes? */
static bool pm_send_row(const struct json_value *row, int64_t t4, void *ctx)
{
    struct pm_send *st = ctx;
    const char *ref = pm_str(row, "ref");
    struct pm_sample *s;
    int idx;
    if (strcmp(pm_str(row, "kind"), PM_KIND) != 0 ||
        !pm_starts(pm_str(row, "body"), PM_ECHO_PREFIX))
        return false;
    idx = pm_ref_index(st, ref);
    if (idx < 0)
        return false;
    s = &st->s[idx];
    if (s->seen && (!s->bad_source || !pm_echo_source_ok(st, row))) {
        pm_echo_again(st, s, row);
        return false;
    }
    if (s->seen) {
        /* An echo from the wrong source gives way to one from the right. */
        struct pm_sample fresh = {.t1 = s->t1};
        (void)snprintf(fresh.ref, sizeof(fresh.ref), "%s", s->ref);
        *s = fresh;
        st->seen--;
    }
    pm_take_echo(s, row, t4, st->in.to, st);
    return true;
}

/* Wait on the maildir until `until_ms` (monotonic), reading echoes as they
 * become readable. `stop_when_seen` ends the wait once every posted probe has
 * an echo row; paced waits between posts keep waiting so pacing is honoured
 * without a sleep. NULL on success, else a PROBE_* code. */
static const char *pm_collect(struct pm_send *st, int64_t until_ms,
                              bool stop_when_seen)
{
    bool first = true;
    for (;;) {
        struct zcl_command_reply r;
        int64_t left = until_ms - platform_time_monotonic_ms();
        bool ok;
        if (stop_when_seen && st->settled >= st->posted)
            return NULL;
        /* One wait always runs, so a row already readable is read now even
         * when the deadline has just passed. */
        if (left <= 0 && !first)
            return NULL;
        first = false;
        if (left < 1)
            left = 1;
        ok = pm_wait_rows(st->request, st->cursor, st->in.from,
                          left < PM_TIMEOUT_MAX_MS ? left : PM_TIMEOUT_MAX_MS,
                          &r);
        if (ok) {
            pm_each_row(&r, pm_wall_ms(), pm_send_row, st);
            if (!pm_next_token(&r, st->cursor, sizeof(st->cursor))) {
                zcl_command_reply_free(&r);
                return "PROBE_WAIT_FAILED";
            }
        } else if (strcmp(r.error.code, "WAIT_TIMEOUT") != 0) {
            (void)snprintf(st->inner, sizeof(st->inner), "%s", r.error.code);
            zcl_command_reply_free(&r);
            return "PROBE_WAIT_FAILED";
        }
        zcl_command_reply_free(&r);
    }
}

/* The first post names export eligibility and the cursor every later wait
 * starts from (parked past every stream, so an echo cannot predate it).
 * Eligibility is not delivery evidence or a gate: another carrier (the
 * mail_carry baseline) is measurable too, and the report names which one the
 * rows actually used. */
static bool pm_first_post_note(struct pm_send *st,
                               const struct zcl_command_reply *post)
{
    const struct json_value *d = json_get(&post->data, "delivery");
    const char *label = d && d->type == JSON_STR ? json_get_str(d) : "";
    (void)snprintf(st->delivery, sizeof(st->delivery), "%s", label);
    return pm_next_token(post, st->cursor, sizeof(st->cursor));
}

/* Post probe i: t1 is read immediately before the post. */
static const char *pm_post_probe(struct pm_send *st, unsigned i)
{
    struct pm_sample *s = &st->s[i];
    struct zcl_command_reply r;
    char body[PM_BODY_MAX + 1];
    int w;
    (void)snprintf(s->ref, sizeof(s->ref), PM_REF_PREFIX "%s.%u", st->nonce, i);
    s->t1 = pm_wall_ms();
    w = snprintf(body, sizeof(body), PM_PROBE_PREFIX "t1=%lld i=%u",
                 (long long)s->t1, i);
    if (w <= 0 || (size_t)w > PM_BODY_MAX) {
        return "PROBE_BODY_TOO_LARGE";
    }
    if (!pm_post(st->request, st->in.from, st->in.to, s->ref, body, &r)) {
        (void)snprintf(st->inner, sizeof(st->inner), "%s", r.error.code);
        zcl_command_reply_free(&r);
        return "PROBE_POST_FAILED";
    }
    st->posted++;
    if (i == 0 && !pm_first_post_note(st, &r)) {
        zcl_command_reply_free(&r);
        return "PROBE_POST_FAILED";
    }
    zcl_command_reply_free(&r);
    return NULL;
}

/* Post the probes on the pacing schedule, collecting echoes in between. */
static const char *pm_send_run(struct pm_send *st)
{
    int64_t start = platform_time_monotonic_ms();
    for (unsigned i = 0; i < (unsigned)st->in.probes; i++) {
        const char *err = pm_post_probe(st, i);
        if (err)
            return err;
        if (g_pm_pump)
            g_pm_pump(g_pm_pump_ctx);
        if (i + 1 < (unsigned)st->in.probes) {
            /* Read echoes as they become readable, so t4 is not delayed to
             * the end of the posting phase: until the next scheduled post,
             * or one wait tick when the probes are not paced. */
            int64_t pace = start + (int64_t)(i + 1) * st->in.interval_ms;
            int64_t tick = platform_time_monotonic_ms() + 1;
            err = pm_collect(st, pace > tick ? pace : tick, false);
            if (err)
                return err;
        }
    }
    return pm_collect(st, platform_time_monotonic_ms() + st->in.timeout_ms,
                      true);
}

/* Decide one sample's state from its timestamps. */
static void pm_judge(struct pm_sample *s)
{
    if (!s->seen) {
        s->state = PM_MISSING;
        return;
    }
    if (s->state == PM_INVALID)
        return;
    s->state = PM_INVALID;
    if (strcmp(s->basis, "watch") != 0)
        s->reason = "t2_unmeasured_scan";
    else if (s->t3 < s->t2)
        s->reason = "echo_clock_step";
    else if (s->t4 < s->t1)
        s->reason = "sender_clock_step";
    else if ((s->t4 - s->t1) - (s->t3 - s->t2) < 0)
        s->reason = "negative_network_time";
    else {
        s->state = PM_VALID;
        s->reason = NULL;
        s->network_ms = (s->t4 - s->t1) - (s->t3 - s->t2);
    }
}

static int pm_cmp_ll(const void *a, const void *b)
{
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
    return x < y ? -1 : x > y;
}

/* ── report ────────────────────────────────────────────────────────────── */

/* The fields only an echoed sample has. */
static bool pm_sample_echo_json(const struct pm_sample *s, struct json_value *o)
{
    static const char *const stamp_keys[] = {"t2", "t3", "t4"};
    static const char *const word_keys[] = {"echo_from", "probe_leg",
                                            "echo_leg", "basis"};
    const int64_t stamps[] = {s->t2, s->t3, s->t4};
    const char *const words[] = {s->echo_from, s->probe_leg, s->echo_leg,
                                 s->basis};
    for (size_t i = 0; i < sizeof(stamps) / sizeof(stamps[0]); i++)
        if (!json_push_kv_int(o, stamp_keys[i], stamps[i]))
            return false;
    for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++)
        if (!json_push_kv_str(o, word_keys[i], words[i]))
            return false;
    return true;
}

/* The derived numbers only a valid sample has. */
static bool pm_sample_valid_json(const struct pm_sample *s,
                                 struct json_value *o)
{
    return json_push_kv_int(o, "round_trip_ms", s->t4 - s->t1) &&
           json_push_kv_int(o, "network_ms", s->network_ms) &&
           json_push_kv_real(o, "one_way_ms", (double)s->network_ms / 2.0);
}

static bool pm_sample_json(const struct pm_sample *s, unsigned i,
                           struct json_value *arr)
{
    struct json_value o;
    static const char *const names[] = {"missing", "valid", "invalid"};
    bool ok;
    json_init(&o);
    json_set_object(&o);
    ok = json_push_kv_int(&o, "i", i) && json_push_kv_str(&o, "ref", s->ref) &&
         json_push_kv_str(&o, "state", names[s->state]) &&
         json_push_kv_int(&o, "t1", s->t1) &&
         (!s->seen || pm_sample_echo_json(s, &o)) &&
         (s->state != PM_VALID || pm_sample_valid_json(s, &o)) &&
         (!s->reason || json_push_kv_str(&o, "reason", s->reason));
    ok = ok && json_push_back(arr, &o);
    json_free(&o);
    return ok;
}

/* One nearest-rank percentile over the sent population. */
static bool pm_percentile_json(struct json_value *obj, const char *name,
                               unsigned pct, const int64_t *sorted,
                               unsigned nvalid, unsigned sent)
{
    struct json_value o;
    unsigned rank = (pct * sent + 99u) / 100u;
    bool ok;
    json_init(&o);
    json_set_object(&o);
    if (rank < 1u)
        rank = 1u;
    if (rank > nvalid) {
        ok = json_push_kv_str(&o, "status", "missing");
    } else {
        ok = json_push_kv_str(&o, "status", "ok") &&
             json_push_kv_real(&o, "one_way_ms", (double)sorted[rank - 1] / 2.0) &&
             json_push_kv_int(&o, "network_ms", sorted[rank - 1]);
    }
    ok = ok && json_push_kv(obj, name, &o);
    json_free(&o);
    return ok;
}

static bool pm_percentiles_json(struct json_value *data, const int64_t *sorted,
                                unsigned nvalid, unsigned sent)
{
    struct json_value p;
    bool ok;
    json_init(&p);
    json_set_object(&p);
    if (sent < PM_MIN_SAMPLES || nvalid < PM_MIN_SAMPLES) {
        ok = json_push_kv_str(&p, "status", "refused") &&
             json_push_kv_str(&p, "reason",
                              sent < PM_MIN_SAMPLES
                                  ? "fewer than 10 probes were sent"
                                  : "fewer than 10 samples are valid");
    } else {
        ok = json_push_kv_str(&p, "status", "ok") &&
             pm_percentile_json(&p, "p50", 50, sorted, nvalid, sent) &&
             pm_percentile_json(&p, "p90", 90, sorted, nvalid, sent) &&
             pm_percentile_json(&p, "p99", 99, sorted, nvalid, sent) &&
             pm_percentile_json(&p, "max", 100, sorted, nvalid, sent);
    }
    ok = ok && json_push_kv(data, "percentiles", &p);
    json_free(&p);
    return ok;
}

/* The one label every leg of every valid sample shares, else "mixed";
 * "none" with no valid sample. "board" is well-formed fields on an inbox
 * stream, not a check against the node. */
static const char *pm_transport(const struct pm_send *st)
{
    static const char *const labels[] = {"board", "other", "unattributed"};
    unsigned count[3] = {0, 0, 0}, legs = 0;
    for (unsigned i = 0; i < st->posted; i++) {
        const struct pm_sample *s = &st->s[i];
        const char *const leg[2] = {s->echo_leg, s->probe_leg};
        if (s->state != PM_VALID)
            continue;
        legs += 2;
        for (size_t l = 0; l < 2; l++)
            for (size_t k = 0; k < 3; k++)
                count[k] += strcmp(leg[l], labels[k]) == 0;
    }
    if (legs == 0)
        return "none";
    for (size_t k = 0; k < 3; k++)
        if (count[k] == legs)
            return labels[k];
    return "mixed";
}

static bool pm_counts_json(struct json_value *data, const struct pm_send *st,
                           unsigned nvalid, unsigned over_1s)
{
    unsigned invalid = st->seen - nvalid;
    return json_push_kv_int(data, "sent", st->posted) &&
           json_push_kv_int(data, "echoed", st->seen) &&
           json_push_kv_int(data, "valid", nvalid) &&
           json_push_kv_int(data, "invalid", invalid) &&
           json_push_kv_int(data, "missing", st->posted - st->seen) &&
           json_push_kv_int(data, "duplicate_echoes", st->duplicates) &&
           json_push_kv_int(data, "echo_from_not_peer", st->name_mismatch) &&
           json_push_kv_int(data, "echo_wrong_stream", st->wrong_stream) &&
           json_push_kv_int(data, "one_way_over_1000ms", over_1s) &&
           json_push_kv_int(data, "min_samples", PM_MIN_SAMPLES);
}

/* The fixed explanatory strings of the report. */
static bool pm_report_notes(struct json_value *data)
{
    return json_push_kv_str(data, "method",
                            "one_way = ((t4 - t1) - (t3 - t2)) / 2; t1 and t4 "
                            "on the sender clock, t2 and t3 on the peer "
                            "clock") &&
           json_push_kv_str(data, "percentile_rule",
                            "nearest-rank over the sent probes; missing and "
                            "invalid sort last; a rank past the valid "
                            "samples is missing; refused below the minimum") &&
           json_push_kv_str(data, "transport_note",
                            "board means an inbox-stream row carrying a "
                            "64-hex board_post and board_signer; it is not "
                            "verified against the node. other is an inbox "
                            "row with no board fields; unattributed is "
                            "anything else; mixed is differing legs or one "
                            "echo by two carriers");
}

/* Judge every sample; the valid network times, sorted, and the counts. */
static unsigned pm_judge_all(struct pm_send *st, int64_t *sorted,
                             unsigned *over_1s)
{
    unsigned nvalid = 0;
    st->wrong_stream = st->name_mismatch = 0;
    for (unsigned i = 0; i < st->posted; i++) {
        const struct pm_sample *s = &st->s[i];
        pm_judge(&st->s[i]);
        st->wrong_stream += s->wrong_stream;
        st->name_mismatch += s->wrong_from;
        if (s->state == PM_VALID) {
            sorted[nvalid++] = s->network_ms;
            *over_1s += s->network_ms > 2000;
        }
    }
    qsort(sorted, nvalid, sizeof(sorted[0]), pm_cmp_ll);
    return nvalid;
}

static bool pm_send_report(struct pm_send *st, struct zcl_command_reply *reply)
{
    struct json_value arr;
    int64_t sorted[PM_COUNT_MAX];
    unsigned nvalid, over_1s = 0;
    bool ok, samples_ok = true;
    json_init(&arr);
    json_set_array(&arr);
    nvalid = pm_judge_all(st, sorted, &over_1s);
    /* A sample that cannot be encoded fails the report; it is never left
     * out while the counts still include it. */
    for (unsigned i = 0; i < st->posted; i++)
        samples_ok = pm_sample_json(&st->s[i], i, &arr) && samples_ok;
    ok = samples_ok && json_push_kv_str(&reply->data, "leaf", "dev.agent.mail.probe") &&
         json_push_kv_str(&reply->data, "role", "send") &&
         json_push_kv_str(&reply->data, "from", st->in.from) &&
         json_push_kv_str(&reply->data, "peer", st->in.to) &&
         json_push_kv_str(&reply->data, "nonce", st->nonce) &&
         json_push_kv_str(&reply->data, "transport", pm_transport(st)) &&
         json_push_kv_str(&reply->data, "first_post_delivery", st->delivery) &&
         pm_report_notes(&reply->data) &&
         pm_counts_json(&reply->data, st, nvalid, over_1s) &&
         pm_percentiles_json(&reply->data, sorted, nvalid, st->posted) &&
         json_push_kv(&reply->data, "samples", &arr);
    json_free(&arr);
    return ok;
}

static bool pm_nonce(char *out)
{
    uint8_t raw[PM_NONCE_HEX / 2];
    if (!rng_fill(raw, sizeof(raw)))
        return false;
    for (size_t i = 0; i < sizeof(raw); i++)
        (void)snprintf(out + 2 * i, 3, "%02x", raw[i]);
    return true;
}

static void pm_send_fail(struct pm_send *st, struct zcl_command_reply *reply,
                         const char *code)
{
    char evidence[160];
    (void)snprintf(evidence, sizeof(evidence), "posted=%u inner=%s delivery=%s",
                   st->posted, st->inner, st->delivery);
    pm_abort(reply, code,
             "the probe run stopped; rows already posted are ordinary notes",
             evidence, st->posted > 0);
}

static void pm_send(const struct zcl_command_request *request,
                    const struct pm_input *in, struct zcl_command_reply *reply)
{
    struct pm_send *st = zcl_calloc(1, sizeof(*st), "mailprobe.send");
    struct pm_own own = {.self = in->from};
    const char *err;
    char token[PM_TOKEN_CAP];
    if (!st) {
        pm_abort(reply, "PROBE_NO_MEMORY", "probe state allocation failed",
                 "calloc", false);
        return;
    }
    st->request = request;
    st->in = *in;
    err = pm_walk(request, NULL, NULL, in->from, pm_own_row, &own, token,
                  sizeof(token), st->inner);
    if (err) {
        pm_abort(reply, err, "own mail could not be read for the post budget",
                 st->inner, false);
    } else if (pm_quota_ok(in, &own, reply)) {
        if (!pm_nonce(st->nonce)) {
            pm_abort(reply, "PROBE_NO_ENTROPY", "no nonce could be drawn",
                     "rng_fill", false);
        } else if ((err = pm_send_run(st)) != NULL) {
            pm_send_fail(st, reply, err);
        } else if (!pm_send_report(st, reply)) {
            pm_abort(reply, "PROBE_REPORT_FAILED",
                     "the report could not be encoded", "json", true);
        } else {
            reply->status = ZCL_COMMAND_STATUS_PASSED;
            reply->exit_code = ZCL_COMMAND_EXIT_OK;
        }
    }
    free(st);
}

/* ── echo role ─────────────────────────────────────────────────────────── */

struct pm_echo {
    const struct zcl_command_request *request;
    struct pm_input in;
    struct pm_pending pend[PM_PENDING_MAX];
    size_t npend;
    bool basis_watch;
    unsigned skipped_oversize, skipped_stale, skipped_other;
    unsigned skipped_not_inbox, table_full;
    unsigned posted;
    char cursor[PM_TOKEN_CAP];
    char inner[64];
    struct json_value out;
};

static struct pm_pending *pm_pending_find(struct pm_echo *e, const char *ref)
{
    for (size_t i = 0; i < e->npend; i++)
        if (strcmp(e->pend[i].ref, ref) == 0)
            return &e->pend[i];
    return NULL;
}

/* Is this row an acceptable probe to answer? Counts what it refuses. */
static bool pm_probe_row_ok(struct pm_echo *e, const struct json_value *row)
{
    const char *body = pm_str(row, "body");
    const char *from = pm_str(row, "from");
    if (!pm_stream_inbox(row)) {
        e->skipped_not_inbox++;
        return false;
    }
    if (strcmp(pm_str(row, "kind"), PM_KIND) != 0 ||
        strcmp(pm_str(row, "to"), e->in.from) != 0 ||
        !pm_starts(body, PM_PROBE_PREFIX) || !pm_ref_ok(pm_str(row, "ref")) ||
        !pm_name_ok(from) || strcmp(from, "*") == 0 ||
        strcmp(from, e->in.from) == 0) {
        e->skipped_other++;
        return false;
    }
    if (strlen(body) > PM_BODY_MAX) {
        e->skipped_oversize++;
        return false;
    }
    if (!pm_ts_within(pm_str(row, "ts"), PM_STALE_S)) {
        e->skipped_stale++;
        return false;
    }
    return true;
}

/* A probe row first readable now: queue it with t2 = the page's clock read. */
static bool pm_echo_row(const struct json_value *row, int64_t t2, void *ctx)
{
    struct pm_echo *e = ctx;
    struct pm_pending *p;
    long long t1 = 0;
    if (!pm_probe_row_ok(e, row) || pm_pending_find(e, pm_str(row, "ref")))
        return false;
    if (e->npend >= PM_PENDING_MAX) {
        e->table_full++;
        return false;
    }
    if (!pm_field_ll(pm_str(row, "body"), "t1=", &t1)) {
        e->skipped_other++;
        return false;
    }
    p = &e->pend[e->npend++];
    memset(p, 0, sizeof(*p));
    (void)snprintf(p->ref, sizeof(p->ref), "%s", pm_str(row, "ref"));
    (void)snprintf(p->from, sizeof(p->from), "%s", pm_str(row, "from"));
    (void)snprintf(p->leg, sizeof(p->leg), "%s",
                   pm_leg_label(row));
    p->t1 = t1;
    p->t2 = t2;
    p->watch = e->basis_watch;
    return true;
}

/* Post the echo for one pending probe: t3 is read immediately before it. */
static const char *pm_post_echo(struct pm_echo *e, struct pm_pending *p)
{
    struct zcl_command_reply r;
    struct json_value item;
    char body[PM_ECHO_BODY_MAX + 1];
    int64_t t3 = pm_wall_ms();
    int w = snprintf(body, sizeof(body),
                     PM_ECHO_PREFIX "t1=%lld t2=%lld t3=%lld pleg=%s basis=%s",
                     (long long)p->t1, (long long)p->t2, (long long)t3, p->leg,
                     p->watch ? "watch" : "scan");
    bool ok;
    if (w <= 0 || (size_t)w > PM_ECHO_BODY_MAX)
        return "PROBE_BODY_TOO_LARGE";
    if (!pm_post(e->request, e->in.from, p->from, p->ref, body, &r)) {
        (void)snprintf(e->inner, sizeof(e->inner), "%s", r.error.code);
        zcl_command_reply_free(&r);
        return "PROBE_POST_FAILED";
    }
    zcl_command_reply_free(&r);
    p->answered = true;
    e->posted++;
    json_init(&item);
    json_set_object(&item);
    ok = json_push_kv_str(&item, "ref", p->ref) &&
         json_push_kv_str(&item, "to", p->from) &&
         json_push_kv_int(&item, "t1", p->t1) &&
         json_push_kv_int(&item, "t2", p->t2) &&
         json_push_kv_int(&item, "t3", t3) &&
         json_push_kv_str(&item, "probe_leg", p->leg) &&
         json_push_kv_str(&item, "basis", p->watch ? "watch" : "scan") &&
         json_push_back(&e->out, &item);
    json_free(&item);
    return ok ? NULL : "PROBE_REPORT_FAILED";
}

/* Answer every unanswered pending probe, up to the echo budget. */
static const char *pm_answer_pending(struct pm_echo *e)
{
    for (size_t i = 0; i < e->npend && e->posted < (unsigned)e->in.probes;
         i++) {
        const char *err;
        if (e->pend[i].answered)
            continue;
        err = pm_post_echo(e, &e->pend[i]);
        if (err)
            return err;
    }
    return NULL;
}

/* Answer, then wait for more probe rows until the budget or deadline. */
static const char *pm_echo_loop(struct pm_echo *e)
{
    int64_t deadline = platform_time_monotonic_ms() + e->in.timeout_ms;
    for (;;) {
        struct zcl_command_reply r;
        int64_t left;
        bool ok;
        const char *err = pm_answer_pending(e);
        if (err)
            return err;
        left = deadline - platform_time_monotonic_ms();
        if (e->posted >= (unsigned)e->in.probes || left <= 0)
            return NULL;
        e->basis_watch = true;
        ok = pm_wait_rows(e->request, e->cursor, e->in.from,
                          left < PM_TIMEOUT_MAX_MS ? left : PM_TIMEOUT_MAX_MS,
                          &r);
        if (ok) {
            pm_each_row(&r, pm_wall_ms(), pm_echo_row, e);
            if (!pm_next_token(&r, e->cursor, sizeof(e->cursor))) {
                zcl_command_reply_free(&r);
                return "PROBE_WAIT_FAILED";
            }
        } else if (strcmp(r.error.code, "WAIT_TIMEOUT") != 0) {
            (void)snprintf(e->inner, sizeof(e->inner), "%s", r.error.code);
            zcl_command_reply_free(&r);
            return "PROBE_WAIT_FAILED";
        }
        zcl_command_reply_free(&r);
    }
}

static bool pm_echo_report(struct pm_echo *e, struct zcl_command_reply *reply)
{
    bool ok = json_push_kv_str(&reply->data, "leaf", "dev.agent.mail.probe") &&
              json_push_kv_str(&reply->data, "role", "echo") &&
              json_push_kv_str(&reply->data, "from", e->in.from) &&
              json_push_kv_int(&reply->data, "answered", e->posted) &&
              json_push_kv_int(&reply->data, "skipped_oversize",
                               e->skipped_oversize) &&
              json_push_kv_int(&reply->data, "skipped_stale",
                               e->skipped_stale) &&
              json_push_kv_int(&reply->data, "skipped_other",
                               e->skipped_other) &&
              json_push_kv_int(&reply->data, "skipped_not_inbox",
                               e->skipped_not_inbox) &&
              json_push_kv_int(&reply->data, "table_full", e->table_full) &&
              json_push_kv_str(&reply->data, "next_since", e->cursor) &&
              json_push_kv(&reply->data, "echoes", &e->out);
    return ok;
}

/* Collect probe rows already readable, mark the ones this box answered, and
 * check the post budget. NULL, else a PROBE_* code (reply already written
 * for a budget refusal, signalled by `refused`). */
static const char *pm_echo_prepare(struct pm_echo *e, bool *refused,
                                   struct zcl_command_reply *reply)
{
    struct pm_own own = {.self = e->in.from, .pend = e->pend};
    char token[PM_TOKEN_CAP];
    const char *err;
    e->basis_watch = e->in.since[0] && strcmp(e->in.since, "0") != 0;
    err = pm_walk(e->request, e->in.since, e->in.from, NULL, pm_echo_row, e,
                  e->cursor, sizeof(e->cursor), e->inner);
    if (err)
        return err;
    own.npend = e->npend;
    err = pm_walk(e->request, NULL, NULL, e->in.from, pm_own_row, &own, token,
                  sizeof(token), e->inner);
    if (err)
        return err;
    *refused = !pm_quota_ok(&e->in, &own, reply);
    return NULL;
}

static void pm_echo_run(const struct zcl_command_request *request,
                        const struct pm_input *in,
                        struct zcl_command_reply *reply)
{
    struct pm_echo *e = zcl_calloc(1, sizeof(*e), "mailprobe.echo");
    bool refused = false;
    const char *err;
    char evidence[160];
    if (!e) {
        pm_abort(reply, "PROBE_NO_MEMORY", "probe state allocation failed",
                 "calloc", false);
        return;
    }
    e->request = request;
    e->in = *in;
    json_init(&e->out);
    json_set_array(&e->out);
    err = pm_echo_prepare(e, &refused, reply);
    if (!err && !refused)
        err = pm_echo_loop(e);
    if (err) {
        (void)snprintf(evidence, sizeof(evidence), "answered=%u inner=%s",
                       e->posted, e->inner);
        pm_abort(reply, err, "the echo run stopped; rows already posted are "
                 "ordinary notes", evidence, e->posted > 0);
    } else if (!refused) {
        if (pm_echo_report(e, reply)) {
            reply->status = ZCL_COMMAND_STATUS_PASSED;
            reply->exit_code = ZCL_COMMAND_EXIT_OK;
        } else {
            pm_abort(reply, "PROBE_REPORT_FAILED",
                     "the report could not be encoded", "json", true);
        }
    }
    json_free(&e->out);
    free(e);
}

/* ── entry ─────────────────────────────────────────────────────────────── */

void zcl_native_handle_dev_agent_mail_probe(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    struct pm_input in;
    if (!reply)
        return;
    if (!request || !request->input) {
        pm_refuse(reply, "BAD_INPUT", "probe needs an action", "request.input");
        return;
    }
    if (!pm_parse(request, &in, reply))
        return;
    if (in.send)
        pm_send(request, &in, reply);
    else
        pm_echo_run(request, &in, reply);
}
