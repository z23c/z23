/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/miner_signal_round.h"
#include "primitives/transaction.h"
#include <stdio.h>
#include <string.h>

#define ROUND_CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "miner signal round line %d: %s\n", __LINE__, #expr); return 1; \
} } while (0)

static int uneven_window(void)
{
    struct miner_signal_schedule s = { .start = 1, .window = 21, .activation = 23,
                                       .slots = 256, .slot = 255 };
    struct miner_signal_tally tally;
    struct uint256 hash = {{0}};
    struct tx_in in = {0};
    outpoint_set_null(&in.prevout);
    struct tx_out out = {0};
    struct transaction cb = { .vin = &in, .num_vin = 1, .vout = &out, .num_vout = 1 };
    const uint8_t prefix[] = {0x6a, 69, 'Z', '2', '3', 'V', 1};
    memcpy(out.script_pub_key.data, prefix, sizeof(prefix));
    out.script_pub_key.size = 71;
    for (int signals = 19; signals <= 21; ++signals) {
        ROUND_CHECK(miner_signal_begin(&s, 0, &hash, &tally).ok);
        for (int h = 1; h <= 21; ++h) {
            out.script_pub_key.data[70] = h <= signals ? 0x80 : 0;
            struct uint256 child = {{(uint8_t)h}};
            ROUND_CHECK(miner_signal_connect(&tally, h, &tally.parent_hash, &child, &cb, &tally).ok);
        }
        ROUND_CHECK(tally.votes == signals);
        ROUND_CHECK(miner_signal_next_phase(&tally) ==
                    (signals >= 20 ? MINER_SIGNAL_LOCKED_IN : MINER_SIGNAL_EXPIRED));
    }
    s.activation = 22;
    ROUND_CHECK(!miner_signal_begin(&s, 0, &hash, &tally).ok);
    return 0;
}

int test_miner_signal_round(void)
{
    ROUND_CHECK(uneven_window() == 0);
    struct tx_in input = {0};
    outpoint_set_null(&input.prevout);
    struct tx_out outputs[2] = {0};
    struct transaction cb = {.vin=&input, .num_vin=1, .vout=outputs, .num_vout=2};
    struct miner_signal_schedule schedule = { .start=10, .window=20, .activation=32,
                                             .slot=8, .slots=9, .catalog={42} };
    struct miner_signal_tally tally, incompatible, short_branch;
    struct uint256 prev = {{0}}, hash = {{0}}, wrong = {{0}};
    wrong.data[5] = 1;
    struct script *ballot = &outputs[1].script_pub_key;
    const uint8_t prefix[] = {0x6a,69,'Z','2','3','V',1};
    memcpy(ballot->data, prefix, sizeof(prefix));
    memcpy(ballot->data+7, schedule.catalog, 32);
    ballot->size = 71;
    ballot->data[40] = 1;  /* slot 8 */
    ROUND_CHECK(miner_signal_begin(&schedule, 9, &prev, &tally).ok);
    enum miner_signal_phase observed;
    ROUND_CHECK(!miner_signal_phase_at(&tally, 32, &observed).ok);
    ROUND_CHECK(!miner_signal_begin(&schedule, 10, &prev, &incompatible).ok);
    ROUND_CHECK(!miner_signal_connect(&tally, 10, &wrong, &hash, &cb, &incompatible).ok);
    ROUND_CHECK(!miner_signal_connect(&tally, 11, &prev, &hash, &cb, &incompatible).ok);
    ROUND_CHECK(!miner_signal_connect(&tally, 10, &prev, &hash, NULL, &incompatible).ok);

    /* A stale catalog, an unused high bit, and a non-final ballot are abstentions. */
    ballot->data[7] ^= 1;
    ROUND_CHECK(miner_signal_connect(&tally, 10, &prev,&hash,&cb,&incompatible).ok && !incompatible.votes);
    ballot->data[7] ^= 1;
    ballot->data[40] |= 2;
    ROUND_CHECK(miner_signal_connect(&tally, 10, &prev,&hash,&cb,&incompatible).ok && !incompatible.votes);
    ballot->data[40] = 1;
    outputs[0] = outputs[1];
    outputs[1].value = 1;
    ROUND_CHECK(miner_signal_connect(&tally, 10, &prev,&hash,&cb,&incompatible).ok && !incompatible.votes);
    outputs[1].value = 0;

    for (int height = 10; height < 29; ++height) {
        hash.data[0] = (uint8_t)height;
        ballot->data[40] = height != 10;
        ROUND_CHECK(miner_signal_connect(&tally, height, &prev,&hash,&cb,&tally).ok);
        ROUND_CHECK(miner_signal_next_phase(&tally) == MINER_SIGNAL_VOTING);
        prev = hash;
    }
    /* Branches share the first 19 blocks and diverge on the final ballot. */
    hash.data[0] = 29;
    ballot->data[40] = 0;
    ROUND_CHECK(miner_signal_connect(&tally,29,&prev,&hash,&cb,&short_branch).ok);
    ROUND_CHECK(short_branch.votes == 18 && miner_signal_next_phase(&short_branch) == MINER_SIGNAL_EXPIRED);
    ROUND_CHECK(miner_signal_phase_at(&short_branch, INT32_MAX, &observed).ok && observed == MINER_SIGNAL_EXPIRED);
    hash.data[1] = 1;
    ballot->data[40] = 1;
    ROUND_CHECK(miner_signal_connect(&tally,29,&prev,&hash,&cb,&tally).ok);
    ROUND_CHECK(tally.votes == 19 && miner_signal_next_phase(&tally) == MINER_SIGNAL_LOCKED_IN);
    ROUND_CHECK(miner_signal_phase_at(&tally, 32, &observed).ok && observed == MINER_SIGNAL_ACTIVE);
    prev = hash;
    hash.data[0] = 30;
    ROUND_CHECK(miner_signal_connect(&tally,30,&prev,&hash,NULL,&tally).ok);
    ROUND_CHECK(miner_signal_next_phase(&tally) == MINER_SIGNAL_LOCKED_IN);
    prev = hash;
    hash.data[0] = 31;
    ROUND_CHECK(miner_signal_connect(&tally,31,&prev,&hash,NULL,&tally).ok);
    ROUND_CHECK(tally.votes == 19 && miner_signal_next_phase(&tally) == MINER_SIGNAL_ACTIVE);
    return 0;
}
