/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "node_restart.h"
#include <assert.h>
#include <string.h>

static struct zapp_restart_seen see(bool running, bool wanted, bool held, bool ready, int64_t now)
{
    struct zapp_restart_seen s = {.running = running, .wanted = wanted, .held = held, .ready = ready, .now = now};
    return s;
}

/* A node the owner wants, with the app shown and the pace normal: running, or gone at now. */
static struct zapp_restart_seen up(int64_t now) { return see(true, true, false, true, now); }
static struct zapp_restart_seen down(int64_t now) { return see(false, true, false, true, now); }

static enum zapp_restart_action obs(struct zapp_restart *r, struct zapp_restart_seen s)
{
    return zapp_restart_observe(r, &s);
}

/* A node that exits on its own is restarted after 30 s, and the notice says so until the restart runs. */
static void first_exit_restarts_after_thirty_seconds(void)
{
    struct zapp_restart r = {0};
    zapp_restart_started(&r);
    assert(obs(&r, up(100)) == ZAPP_RESTART_NONE);
    assert(obs(&r, down(105)) == ZAPP_RESTART_NONE);
    assert(!strcmp(zapp_restart_notice(&r), "The node stopped unexpectedly. Restarting it."));
    assert(obs(&r, down(134)) == ZAPP_RESTART_NONE);
    assert(obs(&r, down(135)) == ZAPP_RESTART_RUN);
    assert(zapp_restart_notice(&r) == NULL);
}

/* Restarts follow 30 s, 60 s and 120 s; the fourth exit gives up and asks for Start. */
static void three_tries_then_the_start_button(void)
{
    struct zapp_restart r = {0};
    zapp_restart_started(&r);
    assert(obs(&r, up(100)) == ZAPP_RESTART_NONE);
    assert(obs(&r, down(110)) == ZAPP_RESTART_NONE);
    assert(obs(&r, down(139)) == ZAPP_RESTART_NONE);
    assert(obs(&r, down(140)) == ZAPP_RESTART_RUN);
    assert(obs(&r, down(141)) == ZAPP_RESTART_NONE);
    assert(obs(&r, down(200)) == ZAPP_RESTART_NONE);
    assert(obs(&r, down(201)) == ZAPP_RESTART_RUN);
    assert(obs(&r, down(202)) == ZAPP_RESTART_NONE);
    assert(obs(&r, down(321)) == ZAPP_RESTART_NONE);
    assert(obs(&r, down(322)) == ZAPP_RESTART_RUN);
    assert(obs(&r, down(323)) == ZAPP_RESTART_NONE);
    assert(r.phase == ZAPP_RESTART_GAVE_UP && r.tries == ZAPP_RESTART_TRIES);
    assert(!strcmp(zapp_restart_notice(&r), "The node stopped. Tap Start to try again."));
    assert(obs(&r, down(5000)) == ZAPP_RESTART_NONE);
    assert(r.phase == ZAPP_RESTART_GAVE_UP);
    zapp_restart_started(&r);
    assert(r.phase == ZAPP_RESTART_UP && zapp_restart_notice(&r) == NULL);
}

/* A run that is ten minutes long restores the tries; one that is shorter does not. */
static void a_healthy_run_restores_the_tries(void)
{
    struct zapp_restart r = {0};
    zapp_restart_started(&r);
    assert(obs(&r, up(100)) == ZAPP_RESTART_NONE);
    assert(obs(&r, down(110)) == ZAPP_RESTART_NONE);
    assert(obs(&r, down(140)) == ZAPP_RESTART_RUN);
    assert(obs(&r, up(141)) == ZAPP_RESTART_NONE);
    assert(obs(&r, up(740)) == ZAPP_RESTART_NONE);
    assert(r.tries == 1);
    assert(obs(&r, down(745)) == ZAPP_RESTART_NONE);
    assert(obs(&r, down(804)) == ZAPP_RESTART_NONE);
    assert(obs(&r, down(805)) == ZAPP_RESTART_RUN);
    assert(obs(&r, up(806)) == ZAPP_RESTART_NONE);
    assert(obs(&r, up(1406)) == ZAPP_RESTART_NONE);
    assert(r.tries == 0);
    assert(obs(&r, down(1410)) == ZAPP_RESTART_NONE);
    assert(obs(&r, down(1439)) == ZAPP_RESTART_NONE);
    assert(obs(&r, down(1440)) == ZAPP_RESTART_RUN);
}

/* A restart that dies before it is seen running counts as a failed try, and the next wait is 60 s. */
static void a_restart_that_dies_at_once_uses_the_next_delay(void)
{
    struct zapp_restart r = {0};
    zapp_restart_started(&r);
    assert(obs(&r, down(100)) == ZAPP_RESTART_NONE);
    assert(obs(&r, down(129)) == ZAPP_RESTART_NONE);
    assert(obs(&r, down(130)) == ZAPP_RESTART_RUN);
    assert(obs(&r, down(131)) == ZAPP_RESTART_NONE);
    assert(obs(&r, down(190)) == ZAPP_RESTART_NONE);
    assert(obs(&r, down(191)) == ZAPP_RESTART_RUN);
}

/* The owner's Stop, or wallet setup, cancels a pending restart; nothing restarts until Start. */
static void a_stop_cancels_the_restart(void)
{
    struct zapp_restart r = {0};
    zapp_restart_started(&r);
    assert(obs(&r, up(100)) == ZAPP_RESTART_NONE);
    assert(obs(&r, down(110)) == ZAPP_RESTART_NONE);
    zapp_restart_stopped(&r);
    assert(zapp_restart_notice(&r) == NULL);
    assert(obs(&r, down(140)) == ZAPP_RESTART_NONE);
    assert(obs(&r, up(141)) == ZAPP_RESTART_NONE);
    assert(obs(&r, down(1000)) == ZAPP_RESTART_NONE);
    assert(r.phase == ZAPP_RESTART_IDLE);
}

/* A node the owner no longer wants is not restarted. */
static void a_node_the_owner_no_longer_wants_is_not_restarted(void)
{
    struct zapp_restart r = {0};
    zapp_restart_started(&r);
    assert(obs(&r, up(100)) == ZAPP_RESTART_NONE);
    assert(obs(&r, see(false, false, false, true, 110)) == ZAPP_RESTART_NONE);
    assert(obs(&r, down(140)) == ZAPP_RESTART_NONE);
    assert(obs(&r, down(500)) == ZAPP_RESTART_NONE);
    assert(zapp_restart_notice(&r) == NULL);
}

/* The heat pause never restarts the node: an exit while paused leaves it stopped, and a restart that is due waits. */
static void the_heat_pause_holds_every_restart(void)
{
    struct zapp_restart r = {0};
    zapp_restart_started(&r);
    assert(obs(&r, up(100)) == ZAPP_RESTART_NONE);
    assert(obs(&r, see(false, true, true, true, 110)) == ZAPP_RESTART_NONE);
    assert(r.phase == ZAPP_RESTART_IDLE);
    assert(obs(&r, down(500)) == ZAPP_RESTART_NONE);
    zapp_restart_started(&r);
    assert(obs(&r, up(600)) == ZAPP_RESTART_NONE);
    assert(obs(&r, down(610)) == ZAPP_RESTART_NONE);
    assert(obs(&r, see(false, true, true, true, 640)) == ZAPP_RESTART_NONE);
    assert(obs(&r, see(false, true, false, true, 650)) == ZAPP_RESTART_RUN);
}

/* A restart waits while the app is hidden and runs once it is shown. */
static void a_hidden_app_waits_for_the_restart(void)
{
    struct zapp_restart r = {0};
    zapp_restart_started(&r);
    assert(obs(&r, up(100)) == ZAPP_RESTART_NONE);
    assert(obs(&r, down(110)) == ZAPP_RESTART_NONE);
    assert(obs(&r, see(false, true, false, false, 150)) == ZAPP_RESTART_NONE);
    assert(obs(&r, see(false, true, false, true, 151)) == ZAPP_RESTART_RUN);
}

/* A node already running when the app opens, for an owner who wants it, is restarted if it exits later. A node
 * still shutting down, or one the owner does not want, is not. */
static void a_node_already_running_is_taken_over(void)
{
    struct zapp_restart r = {0};
    assert(obs(&r, up(100)) == ZAPP_RESTART_NONE);
    assert(r.phase == ZAPP_RESTART_UP);
    assert(obs(&r, down(110)) == ZAPP_RESTART_NONE);
    assert(obs(&r, down(140)) == ZAPP_RESTART_RUN);

    struct zapp_restart shutting = {0};
    struct zapp_restart_seen stopping = up(100);
    stopping.stopping = true;
    assert(obs(&shutting, stopping) == ZAPP_RESTART_NONE);
    assert(shutting.phase == ZAPP_RESTART_BOOT);
    assert(obs(&shutting, down(110)) == ZAPP_RESTART_NONE);
    assert(obs(&shutting, down(500)) == ZAPP_RESTART_NONE);

    struct zapp_restart unwanted = {0};
    assert(obs(&unwanted, see(true, false, false, true, 100)) == ZAPP_RESTART_NONE);
    assert(obs(&unwanted, down(110)) == ZAPP_RESTART_NONE);
    assert(obs(&unwanted, down(500)) == ZAPP_RESTART_NONE);
}

static void a_node_stop_is_refused_while_a_payment_is_sent(void)
{
    assert(zapp_node_stop_refusal(false) == NULL);
    assert(!strcmp(zapp_node_stop_refusal(true), "Your payment is still being sent. Stop the node after it finishes."));
}

int main(void)
{
    first_exit_restarts_after_thirty_seconds();
    three_tries_then_the_start_button();
    a_healthy_run_restores_the_tries();
    a_restart_that_dies_at_once_uses_the_next_delay();
    a_stop_cancels_the_restart();
    a_node_the_owner_no_longer_wants_is_not_restarted();
    the_heat_pause_holds_every_restart();
    a_hidden_app_waits_for_the_restart();
    a_node_already_running_is_taken_over();
    a_node_stop_is_refused_while_a_payment_is_sent();
    return 0;
}
