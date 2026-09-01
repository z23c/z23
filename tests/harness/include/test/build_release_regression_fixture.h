/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Shared exact regression-action fixture for release fabric tests. */

#ifndef ZCL_TEST_BUILD_RELEASE_REGRESSION_FIXTURE_H
#define ZCL_TEST_BUILD_RELEASE_REGRESSION_FIXTURE_H

#include "models/build_fabric.h"
#include "models/database.h"

#include <stdbool.h>
#include <stdint.h>

bool test_build_release_regression_fixture(
    struct node_db *ndb, const char *dir,
    const struct db_build_job *candidate_job,
    const uint8_t test_input_root[32], int64_t now,
    uint8_t action_root_out[32], uint8_t proof_root_out[32],
    char receipt_id_out[65]);

#endif /* ZCL_TEST_BUILD_RELEASE_REGRESSION_FIXTURE_H */
