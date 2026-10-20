/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_TEST_SNAPSHOT_BOOT_FIXTURE_H
#define ZCL_TEST_SNAPSHOT_BOOT_FIXTURE_H

#include <stdbool.h>
#include <stdint.h>

/* Real 1,200-coin public snapshot at height 1,000,000, with integrity-valid
 * padding above the production import size floor. The caller owns its path. */
bool test_snapshot_boot_fixture_build(const char *path, const uint8_t tip_hash[32]);

#endif
