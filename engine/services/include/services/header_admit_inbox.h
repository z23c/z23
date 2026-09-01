/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Mailbox inbox for header_admit_stage. Header-probing callers push
 * one of these per discovered header; header_admit_stage drains them
 * on each tick. */

#ifndef ZCL_SERVICES_HEADER_ADMIT_INBOX_H
#define ZCL_SERVICES_HEADER_ADMIT_INBOX_H

#include "core/uint256.h"
#include "primitives/block.h"
#include "util/mailbox.h"

#include <stdbool.h>
#include <stdint.h>

#define HEADER_ADMIT_INBOX_CAPACITY 1024

struct header_admit_msg {
    int64_t height;           /* hint; admit verifies against active chain */
    struct uint256 hash;
    uint32_t peer_id;         /* zero when source is local legacy RPC */
    int64_t observed_unix;
    /* Reducer producer path: when `has_header` is set, `header` carries the
     * raw header bytes so header_admit can CREATE the block_index entry via
     * add_to_block_index without the legacy accept_block_header.
     * Hash-hint-only pushers leave this false. */
    bool has_header;
    struct block_header header;
};

MAILBOX_DECLARE(header_admit, struct header_admit_msg);

#endif /* ZCL_SERVICES_HEADER_ADMIT_INBOX_H */
