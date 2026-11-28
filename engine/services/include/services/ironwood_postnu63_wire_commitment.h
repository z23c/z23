/* purpose: Derive a PostNu6_3 opening commitment from public wire inputs. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_IRONWOOD_POSTNU63_WIRE_COMMITMENT_H
#define ZCL_IRONWOOD_POSTNU63_WIRE_COMMITMENT_H
#include "base/result.h"
#include <stdint.h>
struct v6_wire_view;
/* Reconstructs the ordered opening commitment using the pinned query map and
 * parameters. This does not check constraints or verify the opening proof.
 * The public view and backing bytes must not overlap out; errors preserve out. */
struct zcl_result ironwood_postnu63_wire_commitment(const struct v6_wire_view *view, uint8_t out[32]);
#endif
