/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_TEST_ROM_CHECKPOINT_RESUME_H
#define ZCL_TEST_ROM_CHECKPOINT_RESUME_H

#include <stdbool.h>
#include <stddef.h>

/* Retain the verified resumed file in the caller-owned fixture directory.
 * The caller authenticates source and result against checkpoint authority. */
bool rom_checkpoint_resume_fixture(const char *source, const char *client_dir,
                                   char *output, size_t output_cap);
#endif
