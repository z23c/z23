/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * app_event_sync_service — one node's half of a bounded, signed pull of
 * another node's App events for one (app_id, topic).
 *
 * appsync/app_event_sync.h owns the WIRE: what a request is, what a row is,
 * and which rule refused which row. This service owns the two ends that
 * touch the local table:
 *
 *   SERVE   answer a peer's PULL out of this node's own app_events rows,
 *           within the wire's row and byte bounds, in receive-cursor order.
 *   APPLY   verify an answer row by row and persist what verified, through
 *           the model's own idempotent save. It stops at the first row that
 *           refuses and stores nothing after it.
 *
 * `zcl_app_event_replicate()` is those two with a peer in between, and it
 * is the whole protocol: read the local frontier, ask the peer for what is
 * newer, verify and store the answer, read the frontier again.
 *
 * THE TRANSPORT IS NOT HERE, AND THAT IS THE POINT
 * ------------------------------------------------
 * Nothing in this file opens a socket, resolves a peer or reads a clock. A
 * peer is a `zcl_app_sync_peer`: a name, and one function that turns a
 * request into a bounded answer. A paired mesh session supplies that; so
 * does a loopback that hands the request straight to another node's SERVE,
 * which is how the two-node test drives the exact bytes production would.
 * A peer with no `ask` is refused as `appsync_no_peer` — a missing session
 * is never a reason to accept anything.
 *
 * `received_at` is the caller's clock. This service reads none, so a test
 * can pin arrival time and two boxes cannot disagree about whose clock
 * ordered what — arrival order is local evidence and orders nothing.
 *
 * SCOPE IS HOST POLICY AND ARRIVES FROM ABOVE
 * -------------------------------------------
 * `struct zcl_app_event_scope_v1` — the app id, the topic, the chain and
 * the topic's byte budget — is compiled from the App catalog by the caller
 * and is never derived from a row. An event cannot widen the app, topic,
 * chain or size it is allowed to be by claiming one.
 *
 * FORKS ARE RETAINED; NOTHING IS MERGED
 * -------------------------------------
 * A pulled event is stored exactly as it was signed. Two events that claim
 * the same predecessor are two rows, both kept, and the model resolves them
 * deterministically at read time. There is no last-writer-wins here and no
 * reconciliation: this service can add rows to a table and can do nothing
 * else to it.
 */

#ifndef ZCL_SERVICES_APP_EVENT_SYNC_SERVICE_H
#define ZCL_SERVICES_APP_EVENT_SYNC_SERVICE_H

#include "appsync/app_event_sync.h"
#include "models/database.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* How much of a peer name a refusal line may carry. A name is for the
 * operator; it is never an identity and grants nothing. */
#define ZCL_APP_SYNC_PEER_NAME_MAX 63u

/* What this node holds for one (app_id, topic). The cursor is this node's
 * OWN arrival order and means nothing on any other box — it is what a PULL
 * asks with, and never what orders an App's projection. */
struct zcl_app_sync_frontier {
    bool have;              /* false when this node holds no such row yet */
    int64_t cursor;         /* the highest local receive cursor held */
    uint8_t event_id[32];   /* the event at that cursor */
    int rows;               /* rows held for this (app_id, topic) */
};

/* Turn one request into one bounded answer. Returns false to refuse; a
 * refusal is a refusal to answer, never a short answer. */
typedef bool (*zcl_app_sync_ask_fn)(void *ctx, const uint8_t *request,
                                    size_t request_len, uint8_t *answer,
                                    size_t answer_cap, size_t *answer_len);

struct zcl_app_sync_peer {
    const char *name;        /* for the operator's line; never an identity */
    zcl_app_sync_ask_fn ask; /* NULL means there is no session to ask over */
    void *ctx;
};

/* Everything one pull did, filled on success AND on refusal — "it refused"
 * without saying which row is not a diagnosis. */
struct zcl_app_sync_report {
    enum zcl_app_sync_status status;
    size_t pulled;    /* rows the peer's answer carried */
    size_t verified;  /* rows that passed the App platform's verifier */
    size_t stored;    /* rows this call newly wrote here */
    size_t refused;   /* 0, or 1 — the walk stops at the first bad row */
    size_t bad_row;   /* which row refused, 0-based; meaningless when 0 */
    char peer[ZCL_APP_SYNC_PEER_NAME_MAX + 1];
    struct zcl_app_sync_frontier frontier; /* as it stands AFTER the pull */
};

/* This node's frontier for one (app_id, topic). One indexed read; no peer
 * is asked and no clock is read. */
bool zcl_app_event_sync_frontier(struct node_db *ndb, const char *app_id,
                                 const char *topic,
                                 struct zcl_app_sync_frontier *out);

/* Answer one decoded PULL from the local table. `*len` receives the answer
 * bytes and `*rows` how many rows they carry; both are zero for a peer that
 * is already current, which is what makes a second pull free.
 *
 * A stored row that will not read back or will not verify stops the answer
 * rather than being skipped: a serving node hands over what it can stand
 * behind, and silence about a corrupt row would make this box the source of
 * a gap nobody could see. */
enum zcl_app_sync_status zcl_app_event_sync_serve(
    struct node_db *ndb, const struct zcl_app_event_scope_v1 *scope,
    const struct zcl_app_sync_pull *pull, uint8_t *out, size_t cap,
    size_t *len, size_t *rows);

/* Verify an answer and persist what verified. Stops at the first row that
 * refuses; rows before it are already stored (each save is its own
 * idempotent write, and a row that verified is true whatever follows it),
 * rows after it are never looked at. `report` is filled either way. */
enum zcl_app_sync_status zcl_app_event_sync_apply(
    struct node_db *ndb, const struct zcl_app_event_scope_v1 *scope,
    const uint8_t *rows, size_t len, int64_t received_at,
    struct zcl_app_sync_report *report);

/* One bounded pull from one peer for the scope's (app_id, topic): frontier,
 * request, answer, verify, store, frontier. Refuses as `appsync_no_peer`
 * when no peer was named or the named peer has no session to ask over. */
enum zcl_app_sync_status zcl_app_event_replicate(
    struct node_db *ndb, const struct zcl_app_event_scope_v1 *scope,
    const struct zcl_app_sync_peer *peer, int64_t received_at,
    struct zcl_app_sync_report *report);

#endif /* ZCL_SERVICES_APP_EVENT_SYNC_SERVICE_H */
