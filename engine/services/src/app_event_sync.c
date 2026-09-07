/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: serve, verify and store one App topic's signed events pulled
 * from another node — the two ends of appsync/app_event_sync.h that touch
 * this node's own app_events table.
 */

// one-result-type-ok:closed-wire-refusal-vocabulary — every fallible call
// here returns `enum zcl_app_sync_status`, which is the WIRE's own closed
// refusal set (appsync/app_event_sync.h) and is shared with the peer that
// sent the bytes. Wrapping it in a struct zcl_result at this boundary would
// give every refusal a second name — a token on the wire and a sentence
// here — and the two would drift. The one bool left, the frontier read,
// answers a question with no failure mode worth a sentence: the topic is
// held or it is not.

#include "services/app_event_sync_service.h"

#include "base/bytes.h"
#include "base/safe_alloc.h"
#include "models/app_event.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>

#define APP_SYNC_TAG "app.sync"

/* One page of the serving walk. The wire's own batch bound is the ceiling
 * on how many rows an answer may carry, so reading more per page than that
 * could only ever be work thrown away. */
#define APP_SYNC_PAGE_MAX ZCL_APP_SYNC_BATCH_MAX

/* ── the frontier ────────────────────────────────────────────────────── */

bool zcl_app_event_sync_frontier(struct node_db *ndb, const char *app_id,
                                 const char *topic,
                                 struct zcl_app_sync_frontier *out)
{
    if (!ndb || !app_id || !topic || !out)
        return false; // raw-return-ok:argument-shape-checked-by-caller
    memset(out, 0, sizeof(*out));
    out->rows = db_app_event_count(ndb, app_id, topic);
    out->have = db_app_event_topic_frontier(ndb, app_id, topic, &out->cursor,
                                            out->event_id);
    if (!out->have) {
        out->cursor = 0;
        memset(out->event_id, 0, sizeof(out->event_id));
    }
    return true;
}

/* ── serving ─────────────────────────────────────────────────────────── */

/* Read one stored row back and put it on the wire. The read verifies the
 * stored bytes against the host scope (db_app_event_find refuses a row that
 * will not verify), so a serving node hands over only what it can stand
 * behind. */
static enum zcl_app_sync_status app_sync_serve_one(
    struct node_db *ndb, const struct zcl_app_event_scope_v1 *scope,
    const uint8_t event_id[32], struct zcl_app_sync_writer *writer,
    struct db_app_event *record, uint8_t *payload)
{
    if (!db_app_event_find(ndb, event_id, scope, record, payload,
                           ZCL_APP_EVENT_PAYLOAD_MAX)) {
        LOG_WARN(APP_SYNC_TAG,
                 "serving stopped: a stored row would not read back or "
                 "would not verify under this topic's scope");
        return ZCL_APP_SYNC_SIG_INVALID;
    }
    return zcl_app_sync_writer_append(writer, &record->event);
}

enum zcl_app_sync_status zcl_app_event_sync_serve(
    struct node_db *ndb, const struct zcl_app_event_scope_v1 *scope,
    const struct zcl_app_sync_pull *pull, uint8_t *out, size_t cap,
    size_t *len, size_t *rows)
{
    if (!ndb || !scope || !pull || !out || !len || !rows)
        return ZCL_APP_SYNC_ARGUMENT;
    *len = 0;
    *rows = 0;
    /* Resolve the asker's frontier EVENT into this node's own arrival
     * order. A frontier this node does not hold answers from the start of
     * the topic: every save is idempotent by event id, so re-offering rows
     * the asker already holds costs bandwidth and stores nothing, while
     * guessing a cursor would skip rows silently. */
    int64_t after_cursor = 0;
    if (zcl_bytes_any_set(pull->since_event_id, 32) &&
        !db_app_event_topic_cursor_of(ndb, pull->app_id, pull->topic,
                                      pull->since_event_id, &after_cursor))
        after_cursor = 0;

    struct db_app_event_ref *refs =
        zcl_calloc(APP_SYNC_PAGE_MAX, sizeof(*refs), "app_sync_serve_refs");
    struct db_app_event *record =
        zcl_calloc(1, sizeof(*record), "app_sync_serve_record");
    uint8_t *payload =
        zcl_calloc(1, ZCL_APP_EVENT_PAYLOAD_MAX, "app_sync_serve_payload");
    if (!refs || !record || !payload) {
        free(refs);
        free(record);
        free(payload);
        LOG_WARN(APP_SYNC_TAG, "serving stopped: no memory for one page");
        return ZCL_APP_SYNC_ARGUMENT;
    }

    struct zcl_app_sync_writer writer;
    zcl_app_sync_writer_init(&writer, out, cap);
    enum zcl_app_sync_status status = ZCL_APP_SYNC_OK;
    int found = db_app_event_topic_after(ndb, pull->app_id, pull->topic,
                                         after_cursor, refs,
                                         APP_SYNC_PAGE_MAX);
    for (int i = 0; i < found && status == ZCL_APP_SYNC_OK; i++)
        status = app_sync_serve_one(ndb, scope, refs[i].event_id, &writer,
                                    record, payload);
    /* A full batch is the bound doing its job, not a failure: the puller
     * asks again from the frontier this answer moves it to. */
    if (status == ZCL_APP_SYNC_BATCH_FULL)
        status = ZCL_APP_SYNC_OK;
    *len = writer.len;
    *rows = writer.rows;
    free(refs);
    free(record);
    free(payload);
    return status;
}

/* ── applying ────────────────────────────────────────────────────────── */

/* Persist one verified event. The model's save is idempotent by event id
 * and fails closed when that id is already bound to different bytes, so a
 * second pull of the same range writes nothing and a forged reuse of an id
 * is refused here rather than overwriting what this node already holds. */
static bool app_sync_store_one(struct node_db *ndb,
                               const struct zcl_app_event_scope_v1 *scope,
                               const struct zcl_app_signed_event_v1 *event,
                               int64_t received_at)
{
    struct db_app_event record;
    memset(&record, 0, sizeof(record));
    record.event = *event;
    record.receive_cursor = 0; /* the table assigns local arrival order */
    record.received_at = received_at;
    if (!db_app_event_save(ndb, &record, scope))
        return false; // raw-return-ok:model-save-already-logged-the-refusal
    return true;
}

/* One row: decode, verify, store. Returns the refusal that stopped it. */
static enum zcl_app_sync_status app_sync_apply_one(
    struct node_db *ndb, const struct zcl_app_event_scope_v1 *scope,
    struct zcl_app_sync_reader *reader, int64_t received_at,
    struct zcl_app_signed_event_v1 *event, uint8_t *payload,
    struct zcl_app_sync_report *report)
{
    enum zcl_app_sync_status st = zcl_app_sync_reader_next(
        reader, scope, event, payload, ZCL_APP_EVENT_PAYLOAD_MAX);
    if (st != ZCL_APP_SYNC_OK)
        return st;
    report->verified++;
    if (!app_sync_store_one(ndb, scope, event, received_at))
        return ZCL_APP_SYNC_STORE;
    return ZCL_APP_SYNC_OK;
}

/* Say out loud which row stopped the walk and under which rule. The peer is
 * named because an operator has to know which machine to stop asking; the
 * row is named by index and by nothing else, because its bytes are the
 * App's and a log is not the App's audience. */
static void app_sync_report_refusal(struct zcl_app_sync_report *report)
{
    LOG_WARN(APP_SYNC_TAG,
             "pull from %s refused at row %zu: %s (%zu verified, %zu stored "
             "before it)",
             report->peer[0] ? report->peer : "an unnamed peer",
             report->bad_row, zcl_app_sync_status_label(report->status),
             report->verified, report->stored);
}

enum zcl_app_sync_status zcl_app_event_sync_apply(
    struct node_db *ndb, const struct zcl_app_event_scope_v1 *scope,
    const uint8_t *rows, size_t len, int64_t received_at,
    struct zcl_app_sync_report *report)
{
    if (!ndb || !scope || !report || (!rows && len > 0) || received_at <= 0)
        return ZCL_APP_SYNC_ARGUMENT;
    /* The counters are this call's own; the peer name and the frontier
     * belong to whoever set them up, and are left alone. */
    report->status = ZCL_APP_SYNC_OK;
    report->pulled = 0;
    report->verified = 0;
    report->stored = 0;
    report->refused = 0;
    report->bad_row = 0;
    struct zcl_app_signed_event_v1 *event =
        zcl_calloc(1, sizeof(*event), "app_sync_apply_event");
    uint8_t *payload =
        zcl_calloc(1, ZCL_APP_EVENT_PAYLOAD_MAX, "app_sync_apply_payload");
    if (!event || !payload) {
        free(event);
        free(payload);
        LOG_WARN(APP_SYNC_TAG, "pull stopped: no memory for one row");
        return ZCL_APP_SYNC_ARGUMENT;
    }

    int before = db_app_event_count(ndb, scope->app_id, scope->topic);
    struct zcl_app_sync_reader reader;
    zcl_app_sync_reader_init(&reader, rows, len);
    enum zcl_app_sync_status status = ZCL_APP_SYNC_OK;
    while (status == ZCL_APP_SYNC_OK && zcl_app_sync_reader_more(&reader)) {
        status = app_sync_apply_one(ndb, scope, &reader, received_at, event,
                                    payload, report);
        if (status == ZCL_APP_SYNC_OK)
            report->pulled++;
    }
    int after = db_app_event_count(ndb, scope->app_id, scope->topic);
    report->stored = after > before ? (size_t)(after - before) : 0;
    report->status = status;
    if (status != ZCL_APP_SYNC_OK) {
        report->refused = 1;
        report->bad_row = report->pulled; /* the row after the last good one */
        app_sync_report_refusal(report);
    }
    free(event);
    free(payload);
    return status;
}

/* ── one whole pull ──────────────────────────────────────────────────── */

static void app_sync_name_peer(struct zcl_app_sync_report *report,
                               const struct zcl_app_sync_peer *peer)
{
    if (peer && peer->name && peer->name[0])
        (void)snprintf(report->peer, sizeof(report->peer), "%s", peer->name);
}

enum zcl_app_sync_status zcl_app_event_replicate(
    struct node_db *ndb, const struct zcl_app_event_scope_v1 *scope,
    const struct zcl_app_sync_peer *peer, int64_t received_at,
    struct zcl_app_sync_report *report)
{
    if (!ndb || !scope || !report || received_at <= 0)
        return ZCL_APP_SYNC_ARGUMENT;
    memset(report, 0, sizeof(*report));
    app_sync_name_peer(report, peer);
    if (!peer || !peer->ask) {
        report->status = ZCL_APP_SYNC_NO_PEER;
        LOG_WARN(APP_SYNC_TAG,
                 "no session to pull over; nothing was asked and nothing "
                 "was stored");
        return ZCL_APP_SYNC_NO_PEER;
    }
    if (!zcl_app_event_sync_frontier(ndb, scope->app_id, scope->topic,
                                     &report->frontier)) {
        report->status = ZCL_APP_SYNC_ARGUMENT;
        LOG_WARN(APP_SYNC_TAG, "local frontier unreadable; no peer asked");
        return ZCL_APP_SYNC_ARGUMENT;
    }

    struct zcl_app_sync_pull pull;
    memset(&pull, 0, sizeof(pull));
    if (report->frontier.have)
        memcpy(pull.since_event_id, report->frontier.event_id, 32);
    (void)snprintf(pull.app_id, sizeof(pull.app_id), "%s", scope->app_id);
    (void)snprintf(pull.topic, sizeof(pull.topic), "%s", scope->topic);

    uint8_t request[ZCL_APP_SYNC_PULL_MAX_BYTES];
    size_t request_len = 0;
    enum zcl_app_sync_status status =
        zcl_app_sync_pull_encode(&pull, request, sizeof(request),
                                 &request_len);
    if (status != ZCL_APP_SYNC_OK) {
        report->status = status;
        LOG_WARN(APP_SYNC_TAG, "pull request not composed: %s",
                 zcl_app_sync_status_label(status));
        return status;
    }

    uint8_t *answer = zcl_calloc(1, ZCL_APP_SYNC_ANSWER_MAX,
                                 "app_sync_pull_answer");
    if (!answer) {
        report->status = ZCL_APP_SYNC_ARGUMENT;
        LOG_WARN(APP_SYNC_TAG, "pull stopped: no memory for one answer");
        return ZCL_APP_SYNC_ARGUMENT;
    }
    size_t answer_len = 0;
    if (!peer->ask(peer->ctx, request, request_len, answer,
                   ZCL_APP_SYNC_ANSWER_MAX, &answer_len) ||
        answer_len > ZCL_APP_SYNC_ANSWER_MAX) {
        free(answer);
        report->status = ZCL_APP_SYNC_NO_PEER;
        LOG_WARN(APP_SYNC_TAG, "%s did not answer the pull",
                 report->peer[0] ? report->peer : "the peer");
        return ZCL_APP_SYNC_NO_PEER;
    }

    status = zcl_app_event_sync_apply(ndb, scope, answer, answer_len,
                                      received_at, report);
    free(answer);
    report->status = status;
    (void)zcl_app_event_sync_frontier(ndb, scope->app_id, scope->topic,
                                      &report->frontier);
    return status;
}
