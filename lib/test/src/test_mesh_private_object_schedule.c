/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Pipelining, retry, resume, and cancellation scheduling proofs. */

#include "test/test_core.h"

#include "session/mesh_private_object_schedule.h"

static int schedule_window(void)
{
    int failures = 0;
    TEST_CASE("private object scheduler fills and advances an eight-chunk window") {
        struct mesh_private_object_schedule_v1 schedule;
        struct mesh_private_object_scheduled_request request;
        ASSERT(mesh_private_object_schedule_v1_init(&schedule, 10, 100));
        for (uint32_t i = 0; i < MESH_PRIVATE_OBJECT_REQUEST_WINDOW; i++) {
            ASSERT_EQ(mesh_private_object_schedule_v1_next(
                          &schedule, 1000, &request),
                      MESH_PRIVATE_OBJECT_SCHEDULE_REQUEST);
            ASSERT_EQ(request.chunk_index, i);
            ASSERT_EQ(request.request_id, 100 + i);
            ASSERT_EQ(request.attempt, 1);
            ASSERT_EQ(request.deadline_ms, 6000);
        }
        ASSERT_EQ(mesh_private_object_schedule_v1_next(
                      &schedule, 1000, &request),
                  MESH_PRIVATE_OBJECT_SCHEDULE_WAIT);
        ASSERT(mesh_private_object_schedule_v1_complete_chunk(&schedule, 3));
        ASSERT_EQ(mesh_private_object_schedule_v1_next(
                      &schedule, 1001, &request),
                  MESH_PRIVATE_OBJECT_SCHEDULE_REQUEST);
        ASSERT_EQ(request.chunk_index, 8);
        ASSERT(mesh_private_object_schedule_v1_complete_chunk(&schedule, 8));
        ASSERT_EQ(mesh_private_object_schedule_v1_next(
                      &schedule, 1002, &request),
                  MESH_PRIVATE_OBJECT_SCHEDULE_REQUEST);
        ASSERT_EQ(request.chunk_index, 9);
    } TEST_END
    return failures;
}

static int schedule_resume_and_correlation(void)
{
    int failures = 0;
    TEST_CASE("private object scheduler resumes with exact response correlation") {
        struct mesh_private_object_schedule_v1 schedule;
        struct mesh_private_object_scheduled_request first, retry, ignored;
        ASSERT(mesh_private_object_schedule_v1_init(&schedule, 2, 9));
        ASSERT(mesh_private_object_schedule_v1_complete_chunk(&schedule, 1));
        ASSERT_EQ(mesh_private_object_schedule_v1_next(
                      &schedule, 10, &first),
                  MESH_PRIVATE_OBJECT_SCHEDULE_REQUEST);
        ASSERT_EQ(first.chunk_index, 0);
        ASSERT_EQ(mesh_private_object_schedule_v1_next(
                      &schedule, first.deadline_ms, &retry),
                  MESH_PRIVATE_OBJECT_SCHEDULE_REQUEST);
        ASSERT_EQ(retry.chunk_index, 0);
        ASSERT(retry.request_id != first.request_id);
        ASSERT_EQ(retry.attempt, 2);
        ASSERT(!mesh_private_object_schedule_v1_accepts_response(
            &schedule, 0, first.request_id));
        ASSERT(mesh_private_object_schedule_v1_accepts_response(
            &schedule, 0, retry.request_id));
        ASSERT(mesh_private_object_schedule_v1_complete_chunk(&schedule, 0));
        ASSERT_EQ(mesh_private_object_schedule_v1_next(
                      &schedule, retry.deadline_ms - 1, &ignored),
                  MESH_PRIVATE_OBJECT_SCHEDULE_COMPLETE);
        ASSERT(mesh_private_object_schedule_v1_complete_chunk(&schedule, 0));
    } TEST_END
    return failures;
}

static int schedule_unissued_request(void)
{
    int failures = 0;
    TEST_CASE("private object scheduler does not charge unsent requests") {
        struct mesh_private_object_schedule_v1 schedule;
        struct mesh_private_object_scheduled_request first, second;
        ASSERT(mesh_private_object_schedule_v1_init(&schedule, 1, 20));
        ASSERT_EQ(mesh_private_object_schedule_v1_next(&schedule, 10, &first),
                  MESH_PRIVATE_OBJECT_SCHEDULE_REQUEST);
        ASSERT(mesh_private_object_schedule_v1_unissue(
            &schedule, first.request_id));
        ASSERT(!mesh_private_object_schedule_v1_accepts_response(
            &schedule, 0, first.request_id));
        ASSERT_EQ(mesh_private_object_schedule_v1_next(&schedule, 11, &second),
                  MESH_PRIVATE_OBJECT_SCHEDULE_REQUEST);
        ASSERT_EQ(second.attempt, 1);
        ASSERT(second.request_id != first.request_id);
    } TEST_END
    return failures;
}

static int schedule_retry_and_cancel(void)
{
    int failures = 0;
    TEST_CASE("private object scheduler bounds retries and cancellation") {
        struct mesh_private_object_schedule_v1 schedule;
        struct mesh_private_object_scheduled_request request;
        ASSERT(mesh_private_object_schedule_v1_init(&schedule, 1, UINT64_MAX));
        uint64_t now = 1;
        for (uint8_t attempt = 1;
             attempt <= MESH_PRIVATE_OBJECT_REQUEST_MAX_ATTEMPTS; attempt++) {
            ASSERT_EQ(mesh_private_object_schedule_v1_next(
                          &schedule, now, &request),
                      MESH_PRIVATE_OBJECT_SCHEDULE_REQUEST);
            ASSERT_EQ(request.attempt, attempt);
            ASSERT(request.request_id != 0);
            now = request.deadline_ms;
        }
        ASSERT_EQ(mesh_private_object_schedule_v1_next(
                      &schedule, now, &request),
                  MESH_PRIVATE_OBJECT_SCHEDULE_EXHAUSTED);
        mesh_private_object_schedule_v1_cancel(&schedule);
        ASSERT_EQ(mesh_private_object_schedule_v1_next(
                      &schedule, now, &request),
                  MESH_PRIVATE_OBJECT_SCHEDULE_CANCELLED);
        ASSERT(!mesh_private_object_schedule_v1_complete_chunk(&schedule, 0));
    } TEST_END
    return failures;
}

static int schedule_invalid(void)
{
    int failures = 0;
    TEST_CASE("private object scheduler rejects impossible bounds") {
        struct mesh_private_object_schedule_v1 schedule;
        struct mesh_private_object_scheduled_request request;
        ASSERT(!mesh_private_object_schedule_v1_init(&schedule, 0, 1));
        ASSERT(!mesh_private_object_schedule_v1_init(
            &schedule, (uint32_t)MESH_PRIVATE_OBJECT_MAX_CHUNKS + 1u, 1));
        ASSERT(!mesh_private_object_schedule_v1_init(&schedule, 1, 0));
        ASSERT(mesh_private_object_schedule_v1_init(&schedule, 1, 1));
        ASSERT_EQ(mesh_private_object_schedule_v1_next(
                      &schedule, 0, &request),
                  MESH_PRIVATE_OBJECT_SCHEDULE_INVALID);
        ASSERT_EQ(mesh_private_object_schedule_v1_next(
                      &schedule,
                      UINT64_MAX - MESH_PRIVATE_OBJECT_REQUEST_TIMEOUT_MS + 1u,
                      &request), MESH_PRIVATE_OBJECT_SCHEDULE_INVALID);
        ASSERT(!mesh_private_object_schedule_v1_complete_chunk(&schedule, 1));
    } TEST_END
    return failures;
}

int test_mesh_private_object_schedule(void)
{
    return schedule_window() + schedule_resume_and_correlation() +
        schedule_unissued_request() + schedule_retry_and_cancel() +
        schedule_invalid();
}
