/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_RPC_HTTPSERVER_H
#define ZCL_RPC_HTTPSERVER_H

#include "rpc/server.h"
#include "json/json.h"
#include <stdbool.h>
#include <stdint.h>

bool rpc_http_start(const struct rpc_table *table, uint16_t port,
                     const char *rpc_user, const char *rpc_password,
                     const char *datadir);
void rpc_http_stop(void);
bool rpc_http_is_running(void);

bool rpc_http_tls_active(void);

/* Cookie rotation — call manually for testing; background thread calls
 * automatically every ZCL_RPC_COOKIE_ROTATE_SEC seconds (default 24h). */
void rpc_http_cookie_rotate(void);
int  rpc_http_cookie_rotate_sec(void);

/* test surface: builds the standard JSON-RPC response envelope
 * used by the HTTP server. Safe to call on stack-dirtied / previously
 * uninitialized `response` storage. Production code also routes through
 * this helper to avoid reintroducing stack-init regressions in the HTTP
 * response path. */
bool rpc_http_test_build_response_envelope(bool rpc_ok,
                                           const char *method,
                                           struct json_value *rpc_result,
                                           const struct json_value *id,
                                           struct json_value *response);

/* test surface: two-pass serialization of an RPC response. Sizes the
 * body with a zero-length json_write probe, rejects anything past the
 * internal cap, then allocates exactly len+1 and writes the body — so
 * the length sent to write() can never exceed the allocation (the heap
 * OOB-read fix). Production code routes through this same helper.
 *
 * On true: *out_buf owns a heap buffer the caller must free() and
 * *out_len is the exact body length. On false (OOM / over cap):
 * *out_buf == NULL and *out_len == 0. */
bool rpc_http_test_serialize_response(const struct json_value *response,
                                      char **out_buf, size_t *out_len);

/* Accept-queue admission accounting. The HTTP front door refuses new
 * clients when the admission queue is full, so these are the numbers
 * that say WHY a node is answering "RPC server busy" — how deep the
 * queue got, how many entries the queue had to surrender because their
 * peer hung up or because they waited past the residency deadline, and
 * how many clients were refused while every slot held a live, in-budget
 * request. */
struct rpc_http_queue_stats {
    size_t   capacity;
    size_t   depth;
    size_t   peak_depth;
    uint64_t admitted;
    uint64_t reclaimed_hangup;
    uint64_t reclaimed_stale;
    uint64_t rejected_busy;
};

/* test surface: drive the real admission path — enqueue_client() and
 * the queue's reclaim rule — on plain fds, so the single-owner
 * invariant is proved against production code rather than a copy.
 *
 * rpc_http_test_queue_admit()  — admit fd; false means genuinely full.
 * rpc_http_test_queue_take()   — pop the head, or -1 when empty. Never
 *                                blocks (dequeue_client() would wait).
 * rpc_http_test_queue_reset()  — close every queued fd, zero the
 *                                counters, and set the residency
 *                                deadline (ms; <0 restores the default,
 *                                0 disables age-based reclaim).
 * Not for production use — the server owns this queue while running. */
bool rpc_http_test_queue_admit(int fd);
int  rpc_http_test_queue_take(void);
void rpc_http_test_queue_reset(int wait_ms);
void rpc_http_test_queue_stats(struct rpc_http_queue_stats *out);

#endif
