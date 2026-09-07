/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * appsync — the bounded, signed wire one z23 node uses to PULL another
 * node's signed App events for one (app_id, topic).
 *
 * WHY THIS EXISTS
 * ---------------
 * A dapp's `AppEvent` rows are already immutable, chained and
 * signature-verified where they are STORED (engine/models/src/app_event.c),
 * and the App platform already says exactly what a signed event is on the
 * wire (framework/app_platform.h). What did not exist was a way for one
 * node to obtain another node's rows: every event a box held had been
 * written by that box. A SaaS that only ever serves what one machine wrote
 * is not replicated, it is single-homed with extra steps.
 *
 * THE SHAPE IS THE FLEET LEDGER'S, DELIBERATELY
 * ---------------------------------------------
 * engine/modules/fleetledger is the one node-to-node replication in this
 * tree that is already proven: PULL only, one bounded answer, every row
 * verified under its own signature before anything is stored, and a refusal
 * that names WHICH rule stopped WHICH row. This module reuses that
 * discipline rather than inventing a second one:
 *
 *   PULL ONLY      Nothing is pushed and nothing is volunteered. A node
 *                  that never asks never learns, so serving is never a way
 *                  to reach a box that did not want to be reached.
 *   BOUNDED        One answer carries at most ZCL_APP_SYNC_BATCH_MAX rows
 *                  and at most ZCL_APP_SYNC_ANSWER_MAX bytes. A peer with
 *                  more to say is asked again from the new frontier.
 *   VERIFY FIRST   Every row is decoded and then checked with the App
 *                  platform's own zcl_app_signed_event_v1_verify() under
 *                  the HOST's scope. This module has no second opinion
 *                  about what a valid event is.
 *   STOP ON BAD    The first row that does not verify ends the walk and is
 *                  named by index. Rows after it are not looked at, because
 *                  a peer that sent one bad row has stopped being a source.
 *   NEVER MERGE    Nothing here reconciles two versions of anything. An
 *                  event is stored or it is refused; forks are retained by
 *                  the model, which is where fork policy already lives.
 *
 * WHAT IT IS NOT
 * --------------
 * It is not a second event format. The row on this wire IS the App
 * platform's canonical signed frame — canonical unsigned bytes, then a
 * little-endian u16 signature length, then the strict-DER low-S signature —
 * so a row that crossed this wire is byte-identical to the one the author
 * signed, and this module could not invent an encoding that verifies.
 *
 * It is not storage. Nothing here opens a database, and no function here
 * decides that an event may be kept: it hands a decoded, verified event
 * back and the caller persists it through the model's own idempotent save.
 *
 * It is not policy. `struct zcl_app_event_scope_v1` is host-owned, comes in
 * from the caller, and is never derived from a row. An event cannot widen
 * the app, topic, chain or byte budget it is allowed to be in by saying so.
 *
 * It is not the transport. This module never opens a socket, never names a
 * peer and never reads a clock; it turns bytes into refusals or events. The
 * paired-session lane that carries those bytes is the caller's.
 *
 * ON THE WIRE (big-endian lengths, no padding, no locale, no float)
 * ----------------------------------------------------------------
 * A PULL request — what a puller sends:
 *
 *     0  msg        u8  = ZCL_APP_SYNC_MSG_PULL
 *     1  version    u8  = ZCL_APP_SYNC_WIRE_VERSION
 *     2  since      u64 the puller's local frontier cursor; 0 = from the
 *                       start. It is the ASKER's own cursor and orders
 *                       nothing on the answering side.
 *    10  app_len    u8  1..ZCL_APP_ID_MAX
 *    11  topic_len  u8  1..ZCL_APP_TOPIC_MAX
 *    12  app_id     app_len bytes, no NUL
 *   ...  topic      topic_len bytes, no NUL
 *
 * A PULL answer — a run of rows, each:
 *
 *     0  row_len    u32 1..ZCL_APP_SYNC_ROW_MAX_BYTES
 *     4  frame      row_len bytes: the canonical signed event frame
 *
 * There is no answer header and no row count: the answer ends when the
 * bytes do, and every bound is checked per row. A truncated answer is a
 * refusal (ZCL_APP_SYNC_MALFORMED), never a short read treated as the end.
 */

#ifndef ZCL_APPSYNC_APP_EVENT_SYNC_H
#define ZCL_APPSYNC_APP_EVENT_SYNC_H

#include "framework/app_platform.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_APP_SYNC_WIRE_VERSION 1u
#define ZCL_APP_SYNC_MSG_PULL 1u

/* The fixed head of a PULL request, and the largest one. */
#define ZCL_APP_SYNC_PULL_HEAD_BYTES 12u
#define ZCL_APP_SYNC_PULL_MAX_BYTES \
    (ZCL_APP_SYNC_PULL_HEAD_BYTES + ZCL_APP_ID_MAX + ZCL_APP_TOPIC_MAX)

/* The per-row length prefix, and the largest row this wire carries. The row
 * bound is the App platform's own maximum event: an event a topic declares
 * as legal must be able to cross, or the sync would silently stop at the
 * first big post rather than refusing by name. */
#define ZCL_APP_SYNC_ROW_HEAD_BYTES 4u
#define ZCL_APP_SYNC_EVENT_MAX_BYTES                                          \
    (4u + ZCL_APP_EVENT_CHAIN_ID_SIZE + 2u + ZCL_APP_ID_MAX + 2u +            \
     ZCL_APP_TOPIC_MAX + 4u + ZCL_APP_EVENT_KEY_ID_SIZE +                     \
     ZCL_APP_EVENT_PUBKEY_SIZE + 8u + 8u + 32u + 4u +                         \
     ZCL_APP_EVENT_PAYLOAD_MAX + 2u + ZCL_APP_EVENT_SIGNATURE_MAX)
#define ZCL_APP_SYNC_ROW_MAX_BYTES \
    (ZCL_APP_SYNC_ROW_HEAD_BYTES + ZCL_APP_SYNC_EVENT_MAX_BYTES)

/* Rows one answer may carry, and the bytes it may carry. Both are refusal
 * points, not hopes: a peer with more to say is asked again from the new
 * frontier rather than allowed to hand this box an unbounded run. */
#define ZCL_APP_SYNC_BATCH_MAX 16u
#define ZCL_APP_SYNC_ANSWER_MAX (size_t)(256u * 1024u)

/* Every way this refuses. There is no generic failure: whoever asks why a
 * row did not cross can always be told which rule stopped it. The label
 * strings are the stable tokens the operator surfaces print. */
enum zcl_app_sync_status {
    ZCL_APP_SYNC_OK = 0,
    ZCL_APP_SYNC_ARGUMENT,     /* a NULL, or a field over its bound */
    ZCL_APP_SYNC_MALFORMED,    /* the bytes are not a frame of this version */
    ZCL_APP_SYNC_VERSION,      /* a wire version this build does not speak */
    ZCL_APP_SYNC_ROW_TOO_LARGE,/* one row is over ZCL_APP_SYNC_ROW_MAX_BYTES */
    ZCL_APP_SYNC_BATCH_FULL,   /* the answer is at its row or byte bound */
    ZCL_APP_SYNC_SCOPE,        /* the row is not in the asked-for app/topic */
    ZCL_APP_SYNC_SIG_INVALID,  /* the App platform refused the signature */
    /* No peer was named, or the named peer has no session to ask over.
     * Distinct from a peer that answered badly: the answer is a pairing or
     * a connection, never a reason to accept anything. */
    ZCL_APP_SYNC_NO_PEER,
    /* The local table refused a row that HAD verified — the event id is
     * already bound to different bytes, or the database said no. Kept
     * apart from a signature failure because one accuses the peer and the
     * other accuses this box's own store. */
    ZCL_APP_SYNC_STORE
};

/* "ok", "appsync_malformed", "appsync_sig_invalid", ... — one stable token
 * per value, and never a sentence. */
const char *zcl_app_sync_status_label(enum zcl_app_sync_status s);

/* ── the PULL request ────────────────────────────────────────────────── */

struct zcl_app_sync_pull {
    uint64_t since_cursor;
    char app_id[ZCL_APP_ID_MAX + 1];
    char topic[ZCL_APP_TOPIC_MAX + 1];
};

/* Encode one request. `*len` receives what was written. Refuses rather than
 * truncating: an app id or topic that does not fit is a refusal, because a
 * shortened topic names a DIFFERENT topic. */
enum zcl_app_sync_status zcl_app_sync_pull_encode(
    const struct zcl_app_sync_pull *pull, uint8_t *out, size_t cap,
    size_t *len);

/* Decode one request. Validates the message byte, the wire version and both
 * token lengths; the tokens themselves are checked against the host's own
 * catalog by the caller, which is where an app id means something. */
enum zcl_app_sync_status zcl_app_sync_pull_decode(
    const uint8_t *in, size_t len, struct zcl_app_sync_pull *out);

/* ── the PULL answer ─────────────────────────────────────────────────── */

/* An answer under construction. `rows` counts what has been appended and
 * `len` how many bytes; both are the caller's evidence that the bound was
 * the reason a walk stopped. */
struct zcl_app_sync_writer {
    uint8_t *out;
    size_t cap;
    size_t len;
    size_t rows;
};

void zcl_app_sync_writer_init(struct zcl_app_sync_writer *w, uint8_t *out,
                              size_t cap);

/* Append one signed event to the answer. Returns ZCL_APP_SYNC_BATCH_FULL —
 * and leaves the answer exactly as it was — when this row would pass either
 * bound, which is the serving side's cue to stop and let the puller ask
 * again from the new frontier. The event is encoded from its own fields, so
 * an answer can only ever carry rows this build can also decode. */
enum zcl_app_sync_status zcl_app_sync_writer_append(
    struct zcl_app_sync_writer *w,
    const struct zcl_app_signed_event_v1 *event);

/* ── reading an answer ───────────────────────────────────────────────── */

/* A walk over an answer's rows. `offset` is how far the walk got, so a
 * refusal names the byte the walk stopped at as well as the row index. */
struct zcl_app_sync_reader {
    const uint8_t *in;
    size_t len;
    size_t offset;
    size_t rows;
};

void zcl_app_sync_reader_init(struct zcl_app_sync_reader *r,
                              const uint8_t *in, size_t len);

/* True when there is another row to read. False at exactly the end; a
 * partial row left over is reported by the next _next() call as
 * ZCL_APP_SYNC_MALFORMED rather than being mistaken for the end. */
bool zcl_app_sync_reader_more(const struct zcl_app_sync_reader *r);

/* Decode and VERIFY the next row.
 *
 * `payload` is caller-owned and must stay alive for as long as `out` is
 * used: the decoded event borrows it, exactly as the model's read path
 * does, so walking an answer never allocates per row.
 *
 * `scope` is host-owned policy and is never derived from the row. The row
 * is checked against it twice over: this function refuses a row whose app
 * id or topic is not the scope's before any crypto runs (so a peer cannot
 * spend this box's verification budget on rows it never asked for), and
 * zcl_app_signed_event_v1_verify() then checks the identity, the event id,
 * the byte budget and the signature.
 *
 * A refusal leaves `*out` zeroed. The caller stops on it and stores
 * nothing further: rows after a bad row are not evidence of anything. */
enum zcl_app_sync_status zcl_app_sync_reader_next(
    struct zcl_app_sync_reader *r,
    const struct zcl_app_event_scope_v1 *scope,
    struct zcl_app_signed_event_v1 *out, uint8_t *payload,
    size_t payload_capacity);

#endif /* ZCL_APPSYNC_APP_EVENT_SYNC_H */
