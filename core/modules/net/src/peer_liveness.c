/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Decide peer keepalive actions from monotonic activity samples. */

#include "net/peer_liveness.h"

#include <stdbool.h>
#include <stddef.h>

static int64_t elapsed_nonnegative(int64_t now_us, int64_t then_us)
{
    if (then_us <= 0 || now_us <= then_us)
        return 0;
    return now_us - then_us;
}

enum peer_liveness_action peer_liveness_decide(
    const struct peer_liveness_sample *sample, int64_t now_us)
{
    if (!sample || now_us <= 0)
        return PEER_LIVENESS_NONE;

    int64_t activity_us = sample->last_activity_us > 0
        ? sample->last_activity_us : sample->connected_us;
    if (activity_us <= 0)
        return PEER_LIVENESS_NONE;

    int64_t silent_us = elapsed_nonnegative(now_us, activity_us);
    bool ping_pending = sample->ping_sent_us > 0 &&
                        sample->ping_sent_us >= activity_us;

    if (ping_pending &&
        elapsed_nonnegative(now_us, sample->ping_sent_us) >=
            PEER_LIVENESS_PONG_DEADLINE_US)
        return PEER_LIVENESS_DISCONNECT_PONG_TIMEOUT;

    /* This is the independent backstop when the message sender is stalled and
     * never manages to queue a ping.  Ordinarily the shorter pong deadline
     * wins first. */
    if (silent_us >= PEER_LIVENESS_HARD_SILENCE_US)
        return PEER_LIVENESS_DISCONNECT_HARD_SILENCE;

    if (!ping_pending && silent_us >= PEER_LIVENESS_PING_IDLE_US)
        return PEER_LIVENESS_SEND_PING;

    return PEER_LIVENESS_NONE;
}
