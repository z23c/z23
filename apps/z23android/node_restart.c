/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "node_restart.h"
#include <stddef.h>

static const int64_t delays[ZAPP_RESTART_TRIES] = {30, 60, 120};

void zapp_restart_started(struct zapp_restart *r)
{
    r->phase = ZAPP_RESTART_UP;
    r->due = 0;
    r->up_since = 0;
}

void zapp_restart_stopped(struct zapp_restart *r)
{
    r->phase = ZAPP_RESTART_IDLE;
    r->due = 0;
    r->up_since = 0;
}

/* A run that is seen first while the app opens, for the owner's node, is taken over: it is expected to run. A run
 * that has lasted ZAPP_RESTART_HEALTHY_SECS restores the tries. */
static enum zapp_restart_action running_seen(struct zapp_restart *r, const struct zapp_restart_seen *s)
{
    if (!r->up_since) r->up_since = s->now;
    if (s->now - r->up_since >= ZAPP_RESTART_HEALTHY_SECS) r->tries = 0;
    if (r->phase == ZAPP_RESTART_BOOT && s->wanted && !s->stopping) {
        r->phase = ZAPP_RESTART_UP;
        r->due = 0;
    }
    return ZAPP_RESTART_NONE;
}

/* A restart is pending: it runs once its time has come, while the app is shown, and never for a node the owner no
 * longer wants or while the device is too hot. */
static enum zapp_restart_action wait_step(struct zapp_restart *r, const struct zapp_restart_seen *s)
{
    if (!s->wanted) {
        r->phase = ZAPP_RESTART_IDLE;
        r->due = 0;
        return ZAPP_RESTART_NONE;
    }
    if (s->held || !s->ready || s->now < r->due) return ZAPP_RESTART_NONE;
    r->phase = ZAPP_RESTART_UP;
    r->due = 0;
    return ZAPP_RESTART_RUN;
}

/* The node is gone. One that was expected to run exited on its own: it is restarted when the owner still wants it,
 * and not after the last try. A heat pause does not cancel the restart: wait_step holds it until the pause ends. */
static enum zapp_restart_action gone_seen(struct zapp_restart *r, const struct zapp_restart_seen *s)
{
    r->up_since = 0;
    if (r->phase == ZAPP_RESTART_WAIT) return wait_step(r, s);
    if (r->phase != ZAPP_RESTART_UP) return ZAPP_RESTART_NONE;
    if (!s->wanted) {
        r->phase = ZAPP_RESTART_IDLE;
        return ZAPP_RESTART_NONE;
    }
    if (r->tries >= ZAPP_RESTART_TRIES) {
        r->phase = ZAPP_RESTART_GAVE_UP;
        return ZAPP_RESTART_NONE;
    }
    r->due = s->now + delays[r->tries++];
    r->phase = ZAPP_RESTART_WAIT;
    return ZAPP_RESTART_NONE;
}

enum zapp_restart_action zapp_restart_observe(struct zapp_restart *r, const struct zapp_restart_seen *s)
{
    return s->running ? running_seen(r, s) : gone_seen(r, s);
}

const char *zapp_restart_notice(const struct zapp_restart *r)
{
    if (r->phase == ZAPP_RESTART_WAIT) return "The node stopped unexpectedly. Restarting it.";
    if (r->phase == ZAPP_RESTART_GAVE_UP) return "The node stopped. Tap Start to try again.";
    return NULL;
}

const char *zapp_node_stop_refusal(bool send_busy)
{
    return send_busy ? "Your payment is still being sent. Stop the node after it finishes." : NULL;
}
