/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_NODE_RESTART_H
#define ZAPP_NODE_RESTART_H
#include <stdbool.h>
#include <stdint.h>

/* A node that exits while the app is open is restarted after 30 s, then after 60 s, then after 120 s. A run that
 * lasts ZAPP_RESTART_HEALTHY_SECS restores the three tries. */
#define ZAPP_RESTART_TRIES 3
#define ZAPP_RESTART_HEALTHY_SECS 600

enum zapp_restart_phase {
    ZAPP_RESTART_BOOT,   /* Set when the app opens: a node already running for the owner is taken over. */
    ZAPP_RESTART_IDLE,   /* The owner or wallet setup stopped the node, or the owner does not want it. */
    ZAPP_RESTART_UP,     /* The node is expected to run. */
    ZAPP_RESTART_WAIT,   /* It exited on its own; the next restart is due at due. */
    ZAPP_RESTART_GAVE_UP /* It exited after the last try. */
};

struct zapp_restart {
    enum zapp_restart_phase phase;
    unsigned tries;   /* Restarts scheduled since the last healthy run. */
    int64_t due;      /* Monotonic seconds at which the pending restart may run; 0 when none. */
    int64_t up_since; /* Monotonic seconds the node was first seen running in this run; 0 when not running. */
};

/* One observation of the node and of the app. */
struct zapp_restart_seen {
    bool running;  /* The node process runs now. */
    bool wanted;   /* The owner's choice is Start node. */
    bool stopping; /* A stop was sent and the node has not exited. */
    bool held;     /* The device is too hot for the node (the pace is pause). */
    bool ready;    /* The app is shown and no action is queued or running. */
    int64_t now;   /* Monotonic seconds. */
};

enum zapp_restart_action { ZAPP_RESTART_NONE, ZAPP_RESTART_RUN /* Queue a node start now. */ };

/* The owner asked the node to start, or wallet setup did: it is expected to run. */
void zapp_restart_started(struct zapp_restart *r);
/* The owner or wallet setup asked the node to stop: nothing is restarted until it is started again. */
void zapp_restart_stopped(struct zapp_restart *r);
/* Records one observation and returns RUN when a scheduled restart is due and may be started now. */
enum zapp_restart_action zapp_restart_observe(struct zapp_restart *r, const struct zapp_restart_seen *s);
/* The plain sentence to show while a restart is pending or after the last try, else NULL. */
const char *zapp_restart_notice(const struct zapp_restart *r);
/* The notice for a node stop while a payment is being sent, or NULL when the stop may proceed. */
const char *zapp_node_stop_refusal(bool send_busy);
#endif
