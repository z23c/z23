/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Validate and submit verified block-piece payloads to the reducer. */

#include "msgprocessor_internal.h"
#include "msgprocessor_snapshot_internal.h"
#include "net/download.h"
#include "platform/time_compat.h"
#include "validation/main_state.h"
#include "consensus/validation.h"
#include "core/uint256.h"
#include "util/log_macros.h"
#include <stdio.h>
#include <string.h>

#define BLOCK_PAYLOAD_SUBMIT_RETRIES 3

static int block_payload_drain_catchup(struct msg_processor *mp)
{
    if (!mp || !mp->catchup_drain)
        return 0;
    return mp->catchup_drain(mp->catchup_drain_ctx);
}

static bool block_payload_retry_after_drain(const char *reason)
{
    return reason &&
        (strcmp(reason, "header-admit-inbox-full") == 0 ||
         strcmp(reason, "p2p-block-header-missing") == 0 ||
         strcmp(reason, "p2p-block-intake-full") == 0);
}

static bool block_payload_submit_accepted(
        const struct validation_state *state)
{
    if (!state)
        return false;
    if (validation_state_is_valid(state))
        return true;
    return strcmp(state->reject_reason, "p2p-block-queued-for-reducer") == 0 ||
           strcmp(state->reject_reason, "p2p-block-staged-for-reducer") == 0;
}

bool mp_block_payload_submit_all(
        struct msg_processor *mp, struct p2p_node *node,
        const struct block_piece_payload_ref *refs, uint32_t count)
{
    if (!refs)
        return true;
    if (!mp || !node)
        return false;

    /* One piece shares the same bounded durability scope as async intake. */
    bool batch_scope_open = mp->catchup_batch_begin && mp->catchup_batch_end;
    if (batch_scope_open)
        mp->catchup_batch_begin(mp->catchup_batch_scope_ctx);

    for (uint32_t i = 0; i < count; i++) {
        struct byte_stream block_stream;
        stream_init_from_data(&block_stream, refs[i].data, refs[i].len);

        struct block blk;
        block_init(&blk);
        if (!block_deserialize(&blk, &block_stream)) {
            block_free(&blk);
            stream_free(&block_stream);
            LOG_WARN("net", "zblkdata payload deserialize failed index=%u", i);
            if (batch_scope_open)
                mp->catchup_batch_end(mp->catchup_batch_scope_ctx);
            return false;
        }

        struct uint256 hash;
        block_get_hash(&blk, &hash);
        dl_mark_received(get_download_mgr(), &hash);
        dl_add_bytes_received(get_download_mgr(), refs[i].len);

        /* Persisting is idempotent; only BLOCK_HAVE_DATA authorizes a skip. */
        struct block_index *have_bi = mp->main_state
            ? block_map_find(&mp->main_state->map_block_index, &hash) : NULL;
        if (!msg_processor_snapshot_active(mp) &&
            !(have_bi && (have_bi->nStatus & BLOCK_HAVE_DATA))) {
            bool accepted = false;
            char last_reason[MAX_REJECT_REASON] = {0};
            if (!mp->block_submit) {
                snprintf(last_reason, sizeof(last_reason), "not-enqueued");
            } else {
                for (int attempt = 0;
                     attempt < BLOCK_PAYLOAD_SUBMIT_RETRIES && !accepted;
                     attempt++) {
                    struct validation_state state;
                    validation_state_init(&state);
                    bool ok = mp->block_submit(
                        &blk, &state, mp->block_submit_ctx);
                    accepted = ok || block_payload_submit_accepted(&state);
                    if (accepted)
                        break;
                    snprintf(last_reason, sizeof(last_reason), "%s",
                             state.reject_reason[0]
                                 ? state.reject_reason : "not-enqueued");
                    if (!block_payload_retry_after_drain(last_reason) ||
                        block_payload_drain_catchup(mp) <= 0)
                        break;
                }
            }

            if (!accepted) {
                LOG_INFO("net", "zblkdata payload deferred by reducer submit "
                         "(index=%u reason=%s)", i,
                         last_reason[0] ? last_reason : "not-enqueued");
                block_free(&blk);
                stream_free(&block_stream);
                if (batch_scope_open)
                    mp->catchup_batch_end(mp->catchup_batch_scope_ctx);
                return false;
            }
        }

        block_free(&blk);
        stream_free(&block_stream);
    }

    if (batch_scope_open)
        mp->catchup_batch_end(mp->catchup_batch_scope_ctx);
    /* Yield the activation mutex to the waiting reducer between pieces. */
    platform_sleep_ms(1);
    return true;
}
