/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Accept one research-network frame and refuse a foreign network. */

#ifndef ZCL_RESEARCH_FRAME_H
#define ZCL_RESEARCH_FRAME_H

#include "base/result.h"

#include <stddef.h>
#include <stdint.h>

/* command_len must hold a 12-byte command plus a NUL. On failure the
 * command buffer is left untouched. This does not open a socket or a store. */
struct zcl_result research_frame_accept(const uint8_t *frame, size_t frame_len,
                                        const uint8_t message_start[4],
                                        char *command, size_t command_len);

#endif
