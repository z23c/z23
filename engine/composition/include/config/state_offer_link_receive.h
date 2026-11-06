/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Define bounded state-offer receipt and transport callbacks. */
#ifndef Z23_STATE_OFFER_LINK_RECEIVE_H
#define Z23_STATE_OFFER_LINK_RECEIVE_H
#include "net/rom_fetch.h"
#include <stdint.h>
#include <stddef.h>

enum sol_read_result { SOL_READ_OK, SOL_READ_UNAVAILABLE, SOL_READ_BAD_DATA, SOL_READ_CANCELLED };
enum sol_object_kind { SOL_OBJECT_MANIFEST, SOL_OBJECT_CHUNK };
typedef enum sol_read_result (*sol_object_reader)(void *ctx, enum sol_object_kind kind,
    const uint8_t root[32], uint32_t index, uint8_t *buf, uint32_t cap, uint32_t *len);
enum sol_receive_result { SOL_RECEIVE_OK, SOL_RECEIVE_UNAVAILABLE, SOL_RECEIVE_BAD_DATA,
    SOL_RECEIVE_CANCELLED, SOL_RECEIVE_LOCAL_IO };
/* Worker thread only. The manifest comes from a verified offer. The reader fills
 * the supplied buffer synchronously. landed is set only after durable publish. */
enum sol_receive_result state_offer_link_receive(const struct rom_fetch_manifest *m,
    const char *out_dir, sol_object_reader reader, void *reader_ctx,
    rom_fetch_progress_cb progress, void *progress_ctx, char *landed, size_t landed_cap);
#endif
