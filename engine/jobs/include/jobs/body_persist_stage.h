/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * body_persist_stage — reducer Job stage.
 *
 * Consumes `body_fetch_log`; for each height where the body is on disk,
 * reads the body, verifies header+merkle consistency, and logs the result.
 * READ-class failures (unreadable/wrong/corrupt stored body) are requeued
 * for re-fetch by clearing BLOCK_HAVE_DATA — never persisted as permanent
 * ok=0 rows. */

#ifndef ZCL_SERVICES_BODY_PERSIST_STAGE_H
#define ZCL_SERVICES_BODY_PERSIST_STAGE_H

#include "jobs/stage_helpers.h"
#include "util/stage.h"

#include <stdbool.h>
#include <stdint.h>

struct block;
struct block_index;
struct json_value;
struct main_state;

#define BODY_PERSIST_BATCH_PER_TICK 500

/* Alias onto the shared stage reader type (jobs/stage_helpers.h); the public
 * setter name body_persist_stage_set_reader is unchanged. */
typedef stage_block_reader_fn body_persist_reader_fn;

bool body_persist_stage_init(struct main_state *ms);
void body_persist_stage_shutdown(void);

job_result_t body_persist_stage_step_once(void);
int body_persist_stage_drain(int max_steps);

uint64_t body_persist_stage_cursor(void);
/* Step-timing EWMA (us); see util/stage.h. 0 if never stepped. */
int64_t  body_persist_stage_step_us_ewma(void);
uint64_t body_persist_stage_verified_total(void);
uint64_t body_persist_stage_upstream_failed_total(void);
/* The three READ-class counters count re-fetch requeues (one per cleared
 * HAVE_DATA episode), not permanent verdicts. */
uint64_t body_persist_stage_read_failed_total(void);
uint64_t body_persist_stage_header_mismatch_total(void);
uint64_t body_persist_stage_merkle_mismatch_total(void);

/* Test seam. Passing NULL restores the production disk reader. */
void body_persist_stage_set_reader(body_persist_reader_fn fn, void *user);

#ifdef ZCL_TESTING
/* How long the stage holds on a requeued-but-never-refetched height before it
 * NAMES the hold (blocker body_persist.body_unfetchable). Production value is
 * 60 s; a test drives it to 0 to assert the naming without sleeping. */
void body_persist_stage_set_unfetchable_hold_secs_for_testing(int secs);
#endif

bool body_persist_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_SERVICES_BODY_PERSIST_STAGE_H */
