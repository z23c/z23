/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Define the monotonic peer keepalive decision contract. */

#ifndef ZCL_NET_PEER_LIVENESS_H
#define ZCL_NET_PEER_LIVENESS_H

#include <stdint.h>

/* Peer liveness is driven exclusively by monotonic time.  Wall-clock changes
 * must never make a healthy connection time out or postpone a dead-peer
 * decision. */
#define PEER_LIVENESS_PING_IDLE_US       (60LL * 1000000LL)
#define PEER_LIVENESS_PONG_DEADLINE_US  (180LL * 1000000LL)
#define PEER_LIVENESS_HARD_SILENCE_US  (1200LL * 1000000LL)

enum peer_liveness_action {
    PEER_LIVENESS_NONE = 0,
    PEER_LIVENESS_SEND_PING,
    PEER_LIVENESS_DISCONNECT_PONG_TIMEOUT,
    PEER_LIVENESS_DISCONNECT_HARD_SILENCE,
};

struct peer_liveness_sample {
    int64_t connected_us;
    int64_t last_activity_us;
    int64_t ping_sent_us;
};

/* Pure decision seam used by the real socket/message loops and fake-clock
 * tests.  Any received traffic after a ping proves transport liveness and
 * supersedes that ping generation; a fresh ping becomes eligible after the
 * next idle interval. */
enum peer_liveness_action peer_liveness_decide(
    const struct peer_liveness_sample *sample, int64_t now_us);

#endif /* ZCL_NET_PEER_LIVENESS_H */
