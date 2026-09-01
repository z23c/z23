/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "coins/coins.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "domain/consensus/coins_math.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

/* Pure coins arithmetic (is_pruned, is_available, spend, cleanup) lives
 * in domain/consensus/coins_math.{c,h}. This file is the lib/ adapter:
 * it owns the construct/copy/free lifecycle (which allocates via the
 * label-tagged safe_alloc allocator) and forwards the pure helpers. */

void coins_init(struct coins *c)
{
    c->is_coinbase = false;
    c->vout = NULL;
    c->num_vout = 0;
    c->height = 0;
    c->version = 0;
}

void coins_free(struct coins *c)
{
    free(c->vout);
    c->vout = NULL;
    c->num_vout = 0;
}

bool coins_alloc(struct coins *c, size_t num_outputs)
{
    /* Not zero-filled: the tx_out_set_null loop below defines every field of
     * every element, and the script tail past `.size` is never read. See
     * primitives/transaction.h and the test_script_tail_poison group. This is
     * the UTXO read path, so it runs once per coin lookup at 10016 bytes per
     * output. */
    c->vout = tx_out_array_alloc(num_outputs, "coins_vout");
    if (num_outputs && !c->vout) {
        /* OOM: leave an empty (num_vout=0, vout=NULL) record and return
         * false BEFORE the null-init loop so we never deref the NULL
         * vout.  Callers distinguish OOM from a fully-pruned record by
         * the return value (false == failure, not "pruned").  Set
         * num_vout=0 before LOG_FAIL, which itself returns false. */
        c->num_vout = 0;
        LOG_FAIL("coins", "tx_out_array_alloc failed for num_outputs=%zu",
                 num_outputs);
    }
    c->num_vout = num_outputs;
    for (size_t i = 0; i < num_outputs; i++)
        tx_out_set_null(&c->vout[i]);
    return true;
}

bool coins_from_transaction(struct coins *c, const struct transaction *tx, int height)
{
    c->is_coinbase = transaction_is_coinbase(tx);
    c->height = height;
    c->version = tx->version;

    coins_free(c);
    /* Validate output count before allocating. MAX_TX_OUTPUTS (65536)
     * is already enforced at deserialization, but defense-in-depth. */
    if (tx->num_vout > 65536) {
        fprintf(stderr, "coins_from_transaction: num_vout=%zu exceeds max "  // obs-ok:over-cap-terminal-return
                "at h=%d\n", tx->num_vout, height);
        return false;
    }
    if (!coins_alloc(c, tx->num_vout)) {
        /* coins_alloc already logged the OOM.  The caller now sees
         * num_vout == 0 which used to be interpreted as "all outputs
         * pruned" — an IBD dead-end we can't quietly accept.  The
         * extra line here names the construction site so an operator
         * staring at the log can correlate the allocation failure
         * with a specific tx height. */
        fprintf(stderr, "[coins] %s:%d %s(): coins_from_transaction "  // obs-ok:oom-terminal-return
                "dropped tx with num_vout=%zu at height=%d due to OOM\n",
                __FILE__, __LINE__, __func__, tx->num_vout, height);
        return false;
    }

    for (size_t i = 0; i < tx->num_vout; i++) {
        /* Skip provably unspendable outputs (OP_RETURN).
         * Bitcoin Core's AddCoin() checks IsUnspendable() and skips them.
         * They never enter the UTXO set in zclassicd. */
        if (script_is_unspendable(&tx->vout[i].script_pub_key))
            tx_out_set_null(&c->vout[i]);
        else
            c->vout[i] = tx->vout[i];
    }

    coins_cleanup(c);
    return true;
}

bool coins_spend(struct coins *c, uint32_t pos)
{
    /* Thin forwarder to the pure domain mutator. The "do NOT cleanup
     * after spend" invariant is documented and enforced inside
     * coins_math_spend(); see domain/consensus/coins_math.h. */
    return coins_math_spend(c, pos);
}

bool coins_is_available(const struct coins *c, unsigned int pos)
{
    return coins_math_is_available(c, pos);
}

bool coins_is_pruned(const struct coins *c)
{
    return coins_math_is_pruned(c);
}

void coins_copy(struct coins *dst, const struct coins *src)
{
    dst->is_coinbase = src->is_coinbase;
    dst->height = src->height;
    dst->version = src->version;
    dst->num_vout = src->num_vout;
    if (src->num_vout > 0 && src->vout) {
        dst->vout = zcl_malloc(src->num_vout * sizeof(struct tx_out), "coins_vout_copy");
        if (dst->vout) {
            memcpy(dst->vout, src->vout, src->num_vout * sizeof(struct tx_out));
        } else {
            /* OOM: dst becomes an empty-coins sentinel.  The failure
             * was silent in the old code — a caller that trusted
             * dst->num_vout would act on zero outputs and treat the
             * record as fully spent.  Log so operators can correlate
             * a cache miss with an allocation failure. */
            fprintf(stderr,  // obs-ok:coins-copy-oom-sentinel
                    "[coins] %s:%d %s(): zcl_malloc failed for "
                    "%zu-vout copy; dst reset to empty\n",
                    __FILE__, __LINE__, __func__, src->num_vout);
            dst->num_vout = 0;
        }
    } else {
        dst->vout = NULL;
        dst->num_vout = 0;
    }
}

void coins_cleanup(struct coins *c)
{
    coins_math_cleanup(c);
}

void coins_stats_init(struct coins_stats *s)
{
    s->height = 0;
    uint256_set_null(&s->hash_block);
    s->num_transactions = 0;
    s->num_tx_outputs = 0;
    s->serialized_size = 0;
    uint256_set_null(&s->hash_serialized);
    s->total_amount = 0;
}
