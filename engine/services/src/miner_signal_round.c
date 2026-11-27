/* purpose: Evaluate one miner-signalled migration on a selected chain branch. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/miner_signal_round.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include <stdint.h>
#include <string.h>

struct zcl_result miner_signal_schedule_valid(const struct miner_signal_schedule *s)
{
    /* The window ends at start + window - 1. Leave at least one complete
     * old-rule block between its end and activation. */
    if (!s || s->start < 1 || s->window < 1 ||
        s->activation <= (int64_t)s->start + s->window ||
        s->slots < 1 || s->slots > 256 || s->slot >= s->slots)
        return ZCL_ERR(-1, "Invalid window, activation height or catalog slot");
    return ZCL_OK;
}

struct zcl_result miner_signal_begin(const struct miner_signal_schedule *s, int32_t height,
                        const struct uint256 *hash, struct miner_signal_tally *out)
{
    struct zcl_result valid = miner_signal_schedule_valid(s);
    if (!valid.ok) return valid;
    if (!hash || !out || height != s->start - 1)
        return ZCL_ERR(-2, "Missing window parent or wrong initial height");
    *out = (struct miner_signal_tally){ .schedule = *s, .parent_height = height,
                                        .parent_hash = *hash };
    return ZCL_OK;
}

static const uint8_t ballot_prefix[] = { OP_RETURN, 69, 'Z', '2', '3', 'V', 1 };
static_assert(sizeof(ballot_prefix) + 32 + 32 == MINER_SIGNAL_SCRIPT_BYTES);

void miner_signal_ballot_script(const uint8_t catalog[static 32],
                               const uint8_t bitmap[static 32],
                               uint8_t script[static MINER_SIGNAL_SCRIPT_BYTES])
{
    memcpy(script, ballot_prefix, sizeof(ballot_prefix));
    memcpy(script + sizeof(ballot_prefix), catalog, 32);
    memcpy(script + sizeof(ballot_prefix) + 32, bitmap, 32);
}

static bool signals_slot(const struct miner_signal_schedule *s, const struct transaction *cb)
{
    const struct tx_out *last = &cb->vout[cb->num_vout - 1];
    const struct script *script = &last->script_pub_key;
    if (last->value != 0 || script->size != MINER_SIGNAL_SCRIPT_BYTES ||
        memcmp(script->data, ballot_prefix, sizeof(ballot_prefix)) ||
        memcmp(script->data + sizeof(ballot_prefix), s->catalog, sizeof(s->catalog)))
        return false;
    const uint8_t *bits = script->data + sizeof(ballot_prefix) + sizeof(s->catalog);
    /* Any bit outside the agreed catalog invalidates this entire ballot. */
    unsigned used = (s->slots + 7u) / 8u;
    if (s->slots % 8u && (bits[used - 1] >> (s->slots % 8u))) return false;
    for (unsigned i = used; i < 32; ++i)
        if (bits[i]) return false;
    return (bits[s->slot / 8] & (1u << (s->slot % 8))) != 0;
}

struct zcl_result miner_signal_connect(const struct miner_signal_tally *parent, int32_t height,
                          const struct uint256 *prev_hash, const struct uint256 *hash,
                          const struct transaction *cb, struct miner_signal_tally *out)
{
    if (!parent || !prev_hash || !hash || !out ||
        (int64_t)height != (int64_t)parent->parent_height + 1 ||
        !uint256_eq(prev_hash, &parent->parent_hash))
        return ZCL_ERR(-3, "Block does not extend the supplied tally");
    bool vote = false;
    if ((int64_t)height < (int64_t)parent->schedule.start + parent->schedule.window) {
        if (!cb || !cb->vin || !transaction_is_coinbase(cb) || !cb->num_vout || !cb->vout)
            return ZCL_ERR(-4, "Missing validated coinbase in signaling window");
        vote = signals_slot(&parent->schedule, cb);
    }
    int32_t votes = parent->votes + (vote ? 1 : 0);
    *out = *parent;
    out->votes = votes;
    out->parent_height = height;
    out->parent_hash = *hash;
    return ZCL_OK;
}

int32_t miner_signal_required_votes(int32_t window)
{
    return (int32_t)(((int64_t)window * 95 + 99) / 100);
}

static enum miner_signal_phase phase(const struct miner_signal_tally *t, int64_t next)
{
    if (next < (int64_t)t->schedule.start + t->schedule.window) return MINER_SIGNAL_VOTING;
    if (t->votes < miner_signal_required_votes(t->schedule.window)) return MINER_SIGNAL_EXPIRED;
    return next < t->schedule.activation ? MINER_SIGNAL_LOCKED_IN : MINER_SIGNAL_ACTIVE;
}

enum miner_signal_phase miner_signal_next_phase(const struct miner_signal_tally *t)
{
    return phase(t, (int64_t)t->parent_height + 1);
}

struct zcl_result miner_signal_phase_at(const struct miner_signal_tally *t, int32_t height,
                           enum miner_signal_phase *out)
{
    if (!t || !out) return ZCL_ERR(-5, "Missing tally or phase output");
    int64_t next = (int64_t)t->parent_height + 1;
    int64_t end = (int64_t)t->schedule.start + t->schedule.window;
    if (height < next || (height > next && next < end))
        return ZCL_ERR(-6, "Tally does not establish phase at requested height");
    *out = phase(t, height);
    return ZCL_OK;
}
