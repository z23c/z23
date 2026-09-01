/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Shared closed accepted-work fixture for integration gates. */

#ifndef ZCL_TEST_ACCEPTED_WORK_FIXTURE_H
#define ZCL_TEST_ACCEPTED_WORK_FIXTURE_H

#include "vcs/zcode_accepted_work.h"

#include <stdbool.h>
#include <stdint.h>

struct test_accepted_work_fixture {
    struct vcs_zcode_accepted_work_v1 accepted;
    uint8_t signer_secret[32];
    uint8_t signer_pubkey[32];
};

/* Stores a complete, internally consistent task/candidate/policy/proof-set
 * plus FRONTIER->CANDIDATE->PROVEN chain in dir's existing ZVCS CAS. */
bool test_accepted_work_fixture_create(
    const char *dir, const uint8_t source_root[32], int64_t now,
    uint8_t signer_seed, struct test_accepted_work_fixture *fixture);

#endif /* ZCL_TEST_ACCEPTED_WORK_FIXTURE_H */
