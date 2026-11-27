/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/miner_signal_round.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include <stdint.h>
#include <string.h>

bool miner_signal_schedule_valid(const struct miner_signal_schedule *s)
{
    /* The window ends at start + window - 1. Leave at least one complete
     * old-rule block between its end and activation. */
    return s && s->start >= 1 && s->window >= 1 &&
           s->activation > (int64_t)s->start + s->window &&
           s->slots >= 1 && s->slots <= 256 && s->slot < s->slots;
}

bool miner_signal_begin(const struct miner_signal_schedule *s, int32_t height,
                        const struct uint256 *hash, struct miner_signal_tally *out)
{
    if (!miner_signal_schedule_valid(s) || !hash || !out || height != s->start - 1)
        return false;
    *out = (struct miner_signal_tally){ .schedule = *s, .parent_height = height,
                                        .parent_hash = *hash };
    return true;
}

static bool signals_slot(const struct miner_signal_schedule *s, const struct transaction *cb)
{
    const struct tx_out *last = &cb->vout[cb->num_vout - 1];
    const struct script *script = &last->script_pub_key;
    static const unsigned char prefix[] = { OP_RETURN, 69, 'Z', '2', '3', 'V', 1 };
    if (last->value != 0 || script->size != 71 ||
        memcmp(script->data, prefix, sizeof(prefix)) ||
        memcmp(script->data + sizeof(prefix), s->catalog, sizeof(s->catalog)))
        return false;
    const uint8_t *bits = script->data + sizeof(prefix) + sizeof(s->catalog);
    /* Any bit outside the agreed catalog invalidates this entire ballot. */
    unsigned used = (s->slots + 7u) / 8u;
    if (s->slots % 8u && (bits[used - 1] >> (s->slots % 8u))) return false;
    for (unsigned i = used; i < 32; ++i)
        if (bits[i]) return false;
    return (bits[s->slot / 8] & (1u << (s->slot % 8))) != 0;
}

bool miner_signal_connect(const struct miner_signal_tally *parent, int32_t height,
                          const struct uint256 *prev_hash, const struct uint256 *hash,
                          const struct transaction *cb, struct miner_signal_tally *out)
{
    if (!parent || !prev_hash || !hash || !out ||
        (int64_t)height != (int64_t)parent->parent_height + 1 ||
        !uint256_eq(prev_hash, &parent->parent_hash)) return false;
    bool vote = false;
    if ((int64_t)height < (int64_t)parent->schedule.start + parent->schedule.window) {
        if (!cb || !cb->vin || !transaction_is_coinbase(cb) || !cb->num_vout || !cb->vout) return false;
        vote = signals_slot(&parent->schedule, cb);
    }
    int32_t votes = parent->votes + (vote ? 1 : 0);
    *out = *parent;
    out->votes = votes;
    out->parent_height = height;
    out->parent_hash = *hash;
    return true;
}

static enum miner_signal_phase phase(const struct miner_signal_tally *t, int64_t next)
{
    if (next < (int64_t)t->schedule.start + t->schedule.window) return MINER_SIGNAL_VOTING;
    if ((int64_t)t->votes * 100 < (int64_t)t->schedule.window * 95) return MINER_SIGNAL_EXPIRED;
    return next < t->schedule.activation ? MINER_SIGNAL_LOCKED_IN : MINER_SIGNAL_ACTIVE;
}

enum miner_signal_phase miner_signal_next_phase(const struct miner_signal_tally *t)
{
    return phase(t, (int64_t)t->parent_height + 1);
}

bool miner_signal_phase_at(const struct miner_signal_tally *t, int32_t height,
                           enum miner_signal_phase *out)
{
    if (!t || !out) return false;
    int64_t next = (int64_t)t->parent_height + 1;
    int64_t end = (int64_t)t->schedule.start + t->schedule.window;
    if (height < next || (height > next && next < end)) return false;
    *out = phase(t, height);
    return true;
}
