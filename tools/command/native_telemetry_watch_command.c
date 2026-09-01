/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native handler for `ops.telemetry.watch` — the resumable telemetry change
 * feed. Declared in engine/composition/commands/telemetry/watch.def; the ring and its
 * invariants are util/telemetry_watch.h; the sampler is
 * services/telemetry_watch_service.h.
 *
 * IT IS A CURSOR POLL, NOT A STREAM. One call returns the bounded batch of
 * changes recorded after `since` and EXITS; the agent re-invokes with the last
 * sequence it saw. The leaf is declared ZCL_COMMAND_MODE_STREAM because that
 * is what it IS, but the kernel has no long-lived dispatch path and this file
 * does not add one — a persistent connection would mean surgery on the shared
 * command_registry.c dispatch loop, and a poll needs none of it.
 *
 * THIS FILE NAMES NO TELEMETRY FIELD. Every field name it emits arrived inside
 * a `struct telemetry_watch_record`, put there by telemetry_watch_diff() from
 * the domain's own descriptor table. The hand-written keys here are envelope
 * structure — "records", "gap", "coverage" — which are not fields of any
 * telemetry domain and carry no ontology row. It decides no health either: a
 * record's verdict came from telemetry_evaluate() when the sample was taken.
 *
 * THE BATCH IS BOUNDED BEFORE IT IS BUILT. An over-budget reply is written by
 * the kernel as an EMPTY document, not a truncated one (write_bounded_json,
 * engine/modules/kernel/src/command_registry.c), so "emit and see" costs the caller the
 * whole answer and tells them nothing. The record count is therefore computed
 * from a STATIC worst-case record size before anything is encoded, and the
 * built document is then MEASURED and shrunk if the estimate was ever wrong.
 * Both facts travel in the reply.
 *
 * THE RESUME LINK IS DATA, NOT next[]. push_next_array() refuses any next[]
 * entry whose command equals the command being served, and a refusal there
 * aborts the whole serialization — the caller receives an empty reply reported
 * as RESPONSE_BUDGET_EXCEEDED. `watch` resuming into `watch` is exactly that
 * self-reference, so the ready-to-run resume sits in the data plane as
 * `resume_invocation`. (Measured by the sync lane, not reasoned: every rung
 * but the first returned 296 bytes of overflow envelope until its
 * stage-to-stage link moved out of next[].)
 *
 * Layering: a transport adapter over the watch ring. Opens no database,
 * contacts no node, takes no lock but the ring's own bounded one.
 */

#include "command/native_command.h"

#include "chain/chainparams.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "services/telemetry_watch_service.h"
#include "util/telemetry_render.h"
#include "util/telemetry_watch.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Bytes of the LIST budget the ENVELOPE may take: status, exit code, schema
 * id and the next[] array. Two next[] entries at their declared widths
 * (128 + 512 + 160) plus the ~450-byte common envelope fit twice over. */
#define TWC_ENVELOPE_RESERVE ((size_t)1536)

/* Bytes reserved for everything in `data` that is NOT a record: the cursor
 * block, the sampler block, the coverage block and the resume invocation. */
#define TWC_HEADER_RESERVE ((size_t)1600)

/* Longest `ops telemetry watch --since=N --since_epoch=N` this can produce. */
#define TWC_INVOCATION_MAX 128

/* How many records fit, decided before a single byte is encoded. */
static size_t twc_static_record_cap(void)
{
    size_t frame = (size_t)ZCL_COMMAND_LIST_BUDGET;
    size_t overhead = TWC_ENVELOPE_RESERVE + TWC_HEADER_RESERVE;
    if (frame <= overhead)
        return 1; /* never zero: a gapped batch must not come back empty */
    size_t cap = (frame - overhead) / TELEMETRY_WATCH_RECORD_MAX_JSON;
    if (cap < 1)
        cap = 1;
    if (cap > TELEMETRY_WATCH_BATCH_MAX)
        cap = TELEMETRY_WATCH_BATCH_MAX;
    return cap;
}

/* ── one record ──────────────────────────────────────────────────────── */

static bool twc_push_record(struct json_value *arr,
                            const struct telemetry_watch_record *r)
{
    struct json_value row;
    json_init(&row);
    json_set_object(&row);
    bool ok = true;
    ok &= json_push_kv_int(&row, "sequence", (int64_t)r->sequence);
    ok &= json_push_kv_int(&row, "captured_at", r->captured_at);
    ok &= json_push_kv_str(&row, "canonical_path", r->canonical_path);

    struct json_value fields;
    json_init(&fields);
    json_set_array(&fields);
    for (uint32_t i = 0; i < r->changed_count; i++) {
        struct json_value name;
        json_init(&name);
        json_set_str(&name, r->changed_fields[i]);
        ok &= json_push_back(&fields, &name);
        json_free(&name);
    }
    ok &= json_push_kv(&row, "changed_fields", &fields);
    json_free(&fields);

    /* The count is the number the diff FOUND, not the number carried: a wide
     * change cut to the per-record cap must not read as a narrow one. */
    ok &= json_push_kv_int(&row, "changed_field_count",
                           (int64_t)r->changed_total);
    ok &= json_push_kv_bool(&row, "changed_fields_truncated",
                            r->changed_truncated);
    ok &= json_push_kv_str(&row, "health", telemetry_health_name(r->health));
    /* Non-zero on the FIRST record of a gapped batch: an agent consuming these
     * one at a time must see the loss without parsing the envelope. */
    ok &= json_push_kv_int(&row, "dropped_count", (int64_t)r->dropped_count);

    ok &= json_push_back(arr, &row);
    json_free(&row);
    return ok;
}

/* ── the blocks around the records ───────────────────────────────────── */

/* Where the cursor stands, and — the whole point of the leaf — WHY the batch
 * looks the way it does. A quiet period, a missed window and a restarted feed
 * are three different shapes here, never one ambiguous "empty". */
static bool twc_push_cursor(struct json_value *out,
                            const struct telemetry_watch_batch *b,
                            bool epoch_checked)
{
    bool ok = true;
    ok &= json_push_kv_int(out, "epoch", (int64_t)b->epoch);
    ok &= json_push_kv_bool(out, "epoch_changed", b->epoch_changed);
    /* Stated rather than assumed: a caller that sent no epoch cannot be told
     * whether the feed restarted, and must know that about its own reply. */
    ok &= json_push_kv_bool(out, "epoch_checked", epoch_checked);
    ok &= json_push_kv_int(out, "since", (int64_t)b->since);
    ok &= json_push_kv_int(out, "next_since", (int64_t)b->next_since);
    ok &= json_push_kv_int(out, "last_sequence", (int64_t)b->last_sequence);
    ok &= json_push_kv_int(out, "oldest_sequence", (int64_t)b->oldest_sequence);
    ok &= json_push_kv_int(out, "published_total", (int64_t)b->published_total);
    ok &= json_push_kv_bool(out, "gap", b->gap);
    ok &= json_push_kv_int(out, "dropped_count", (int64_t)b->dropped_count);
    ok &= json_push_kv_bool(out, "since_ahead", b->since_ahead);
    ok &= json_push_kv_bool(out, "more", b->more);
    ok &= json_push_kv_str(out, "reason", b->reason ? b->reason : "");
    return ok;
}

static bool twc_push_sampler(struct json_value *out, bool supervised,
                             bool sampled_on_poll)
{
    struct json_value o;
    json_init(&o);
    json_set_object(&o);
    bool ok = true;
    ok &= json_push_kv_bool(&o, "supervised", supervised);
    ok &= json_push_kv_bool(&o, "sampled_on_poll", sampled_on_poll);
    ok &= json_push_kv_int(&o, "records_published",
                           (int64_t)telemetry_watch_service_records_published());
    /* Honesty about scope, and it matters: a native CLI runs in its own
     * short-lived process that never booted the node, so the feed it reads is
     * that process's own, minted this call. Inside the node the supervised
     * child owns the ring and a poll only reads it. */
    ok &= json_push_kv_str(&o, "scope",
                           supervised ? "the supervised sampler in this node "
                                        "process owns this feed"
                                      : "no supervised sampler in this "
                                        "process: this poll sampled once and "
                                        "the feed is process-local");
    ok &= json_push_kv(out, "sampler", &o);
    json_free(&o);
    return ok;
}

/* What the feed does and does not cover. A reply that listed only the sampled
 * domain would let a reader assume the rest are quiet rather than unwatched. */
static bool twc_push_coverage(struct json_value *out)
{
    struct json_value cov, sampled, unsampled;
    json_init(&cov);
    json_init(&sampled);
    json_init(&unsampled);
    json_set_object(&cov);
    json_set_array(&sampled);
    json_set_object(&unsampled);
    bool ok = true;
    size_t n = telemetry_watch_service_source_count();
    for (size_t i = 0; i < n; i++) {
        const char *domain = NULL, *path = NULL, *why = NULL;
        if (!telemetry_watch_service_source_at(i, &domain, &path, &why))
            continue;
        if (!why) {
            struct json_value name;
            json_init(&name);
            json_set_str(&name, domain);
            ok &= json_push_back(&sampled, &name);
            json_free(&name);
        } else {
            ok &= json_push_kv_str(&unsampled, domain, why);
        }
    }
    ok &= json_push_kv(&cov, "sampled", &sampled);
    ok &= json_push_kv(&cov, "unsampled", &unsampled);
    json_free(&sampled);
    json_free(&unsampled);
    ok &= json_push_kv(out, "coverage", &cov);
    json_free(&cov);
    return ok;
}

/* ── the document ────────────────────────────────────────────────────── */

struct twc_frame {
    const struct telemetry_watch_batch *batch;
    size_t records; /* how many of batch->records to encode */
    size_t static_cap;
    size_t limit;   /* the caller's own cap, 0 when unset */
    bool epoch_checked;
    bool supervised;
    bool sampled_on_poll;
    bool shrunk;
};

/* Build the whole reply document from scratch. Rebuildable so the measured
 * shrink below can simply try again with one fewer record. */
static bool twc_build(struct json_value *data, const struct twc_frame *f)
{
    const struct telemetry_watch_batch *b = f->batch;
    json_set_object(data); /* frees whatever a previous attempt left behind */

    bool ok = twc_push_cursor(data, b, f->epoch_checked);
    ok &= json_push_kv_int(data, "record_count", (int64_t)f->records);
    /* The batch was capped: say by WHAT, so a caller that asked for more knows
     * whether to raise its limit or just poll again. */
    ok &= json_push_kv_int(data, "batch_max_records", (int64_t)f->static_cap);
    ok &= json_push_kv_bool(data, "batch_shrunk_to_fit", f->shrunk);
    if (f->limit > 0)
        ok &= json_push_kv_int(data, "limit", (int64_t)f->limit);

    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < f->records; i++)
        ok &= twc_push_record(&arr, &b->records[i]);
    ok &= json_push_kv(data, "records", &arr);
    json_free(&arr);

    /* The resume is DATA, not next[] — see the file header. Ready to paste. */
    char invocation[TWC_INVOCATION_MAX];
    int n = snprintf(invocation, sizeof invocation,
                     "ops telemetry watch --since=%llu --since_epoch=%llu",
                     (unsigned long long)b->next_since,
                     (unsigned long long)b->epoch);
    ok &= n > 0 && (size_t)n < sizeof invocation &&
          json_push_kv_str(data, "resume_invocation", invocation);

    ok &= twc_push_sampler(data, f->supervised, f->sampled_on_poll);
    ok &= twc_push_coverage(data);
    /* The one leaf class the diff deliberately ignores, published so nobody
     * has to discover it by wondering why the clock never shows up. */
    ok &= json_push_kv_str(data, "ignored_group", TELEMETRY_WATCH_SELF_GROUP);
    return ok;
}

/* ── the handler ─────────────────────────────────────────────────────── */

static int64_t twc_input_int(const struct zcl_command_request *request,
                             const char *key, int64_t fallback)
{
    const struct json_value *v = json_get(request->input, key);
    if (!v)
        return fallback;
    int64_t got = json_get_int(v);
    return got >= 0 ? got : fallback;
}

void zcl_native_handle_telemetry_watch(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;

    uint64_t since = (uint64_t)twc_input_int(request, "since", 0);
    const struct json_value *epoch_in = json_get(request->input, "since_epoch");
    bool epoch_checked = epoch_in != NULL;
    uint64_t since_epoch = (uint64_t)twc_input_int(request, "since_epoch", 0);
    if (since_epoch == 0)
        epoch_checked = false; /* 0 IS the "I did not record one" value */
    size_t limit = (size_t)twc_input_int(request, "limit", 0);

    /* A one-shot native CLI process never ran app_init(), so the sync
     * provider's finality-floor read reaches chain_params_get(), which ASSERTS
     * pCurrentParams and aborts the process without this. Verified by the sync
     * lane, not assumed; the same one-liner with the same reason is carried by
     * native_offline_query.c and native_telemetry_sync_command.c. Idempotent,
     * mainnet-only, matching the bridge's own choice. */
    chain_params_select(CHAIN_MAIN);

    /* In the node the supervised child owns sampling and a poll must not race
     * it. In a CLI process nothing is sampling, so the poll is the sampler —
     * otherwise the feed would answer every call with an empty batch forever
     * and the leaf would be decorative. Which of the two happened is reported.
     */
    bool supervised = telemetry_watch_service_is_armed();
    bool sampled_on_poll = false;
    if (!supervised) {
        (void)telemetry_watch_service_sample_once();
        sampled_on_poll = true;
    }
    telemetry_watch_init();

    size_t static_cap = twc_static_record_cap();
    size_t want = static_cap;
    if (limit > 0 && limit < want)
        want = limit;

    struct telemetry_watch_batch batch;
    if (!telemetry_watch_read(since, since_epoch, want, &batch)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "FEED_READ_FAILED",
                               "execute", false, false,
                               "the telemetry change feed did not answer a "
                               "read", "platform/modules/util/src/telemetry_watch.c");
        return;
    }

    /* Measured, not trusted. The static cap above is a worst-case estimate; if
     * it was ever optimistic the document simply does not fit and the kernel
     * would answer EMPTY. Shrink until it fits — never below one record, so a
     * flagged gap can never arrive as an empty batch. */
    struct twc_frame frame = {
        .batch = &batch,
        .records = batch.count,
        .static_cap = static_cap,
        .limit = limit,
        .epoch_checked = epoch_checked,
        .supervised = supervised,
        .sampled_on_poll = sampled_on_poll,
        .shrunk = false,
    };
    size_t fits = (size_t)ZCL_COMMAND_LIST_BUDGET - TWC_ENVELOPE_RESERVE;
    bool built = false;
    for (;;) {
        built = twc_build(&reply->data, &frame);
        if (!built)
            break;
        if (json_write(&reply->data, NULL, 0) <= fits || frame.records <= 1)
            break;
        frame.records--;
        frame.shrunk = true;
    }
    if (!built) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "REPLY_BUILD_FAILED",
                               "execute", false, false,
                               "ran out of memory building the change-feed "
                               "reply", "ops.telemetry.watch");
        return;
    }

    /* next[] never points at `watch` itself — the kernel refuses a
     * self-referential entry and a refusal there loses the WHOLE reply, so the
     * resume lives in `resume_invocation` instead. These two are literal
     * constants for the same reason in reverse: a next[] entry whose command
     * does not resolve, or whose input the leaf would refuse, is also fatal to
     * the reply, and a record's canonical_path is data from the source table
     * rather than something this file can prove is a callable empty-input
     * leaf. The per-record canonical_path is in the data plane, where a bad
     * value costs a link and not the answer. */
    (void)zcl_command_reply_add_next(
        reply, "ops.telemetry.sync.summary", "{}",
        batch.gap ? "changes were lost — read the current posture instead of "
                    "replaying"
                  : "the current posture of the domain this feed samples");
    (void)zcl_command_reply_add_next(
        reply, "ops.telemetry.sync.stages", "{}",
        "the reducer ladder this feed samples, rung by rung");
}
