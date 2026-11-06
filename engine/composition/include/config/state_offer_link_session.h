/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Client session for bounded state object requests and peer responses. */
#ifndef Z23_STATE_OFFER_LINK_SESSION_H
#define Z23_STATE_OFFER_LINK_SESSION_H
#include "config/state_offer_link.h"
#include "config/state_offer_link_receive.h"

bool sol_client_start(uint64_t peer, void (*wake)(void *), void *wake_ctx);
void sol_client_shutdown(void);
void sol_client_drop(uint64_t peer);
enum sol_read_result sol_client_read(void *peer_id, enum sol_object_kind kind,
    const uint8_t root[32], uint32_t index, uint8_t *buf, uint32_t cap, uint32_t *len);
bool sol_client_poll(uint64_t peer, struct state_offer_link_frame *out);
bool sol_client_consume(uint64_t peer, const struct state_offer_link_frame *frame);
/* Monotonic ms when the last part was received this run (opening a session is
 * not progress). INT64_MIN before the first or after shutdown. Lock-free. */
int64_t sol_client_last_progress_ms(void);
#ifdef ZCL_TESTING
/* Stamp progress now, as if a part had just arrived. */
void sol_client_test_note_part(void);
/* Move the last progress back by ms (|ms| < 1e9), as if no part had arrived
 * since; a negative ms moves it forward again. */
void sol_client_test_age_progress(int64_t ms);
#endif
#endif
