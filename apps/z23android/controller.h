/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_CONTROLLER_H
#define ZAPP_CONTROLLER_H
#include "app.h"
/* notify may finish concurrently with detach; it must guard its own UI handle. */
bool zapp_controller_start(const char *files, const char *libs, bool preview, void (*notify)(void));
void zapp_controller_snapshot(struct zapp_view *view);
bool zapp_controller_action(const char *action, const char *argument, const char *model);
void zapp_controller_detach(void);
/* Hidden, the app cancels voice and stops observing the node and fleet, which keep running on
 * their own; shown again, it observes at once. */
void zapp_controller_visible(bool visible);
/* True while the node process runs; safe from any thread, with or without an activity. */
bool zapp_controller_node_running(void);
/* Runs one wallet command on the calling thread (see zapp_wallet_run); the controller worker stays free,
 * so a slow wallet command never delays the node status. Safe from any thread. */
bool zapp_controller_wallet_run(const char *op, const char *arg, char *out, size_t cap);
/* Runs one step of a send on the calling thread (see zapp_wallet_send_run), never on the controller worker. Safe from any
 * thread. */
bool zapp_controller_send_run(const char *op, const char *input, unsigned timeout_ms, char *out, size_t cap);
/* Runs one step of wallet setup on the calling thread (see zapp_wallet_setup_run), never on the controller worker. Safe from
 * any thread. */
bool zapp_controller_setup_run(const char *op, const char *input, unsigned timeout_ms, char *out, size_t cap);
/* Starts or stops the node now, on the calling thread: wallet setup needs the node stopped while it writes the wallet,
 * and started again when it is done. A stop only asks the node to exit; poll zapp_controller_node_running. */
bool zapp_controller_node_control(bool start);
/* Setup's stop: as node_control(false) but the owner's on or off choice is kept. */
bool zapp_controller_node_pause_for_setup(void);
/* The node's boot stage as a short plain phrase, copied into out. */
void zapp_controller_node_stage(char *out, size_t cap);
/* Whether a shielded send may be built now (see zapp_send_prover_ready): the proving parameters are
 * installed and the running node reports it can prove. False, with a plain reason in why, when not. Asks
 * the node, so call it on the thread that is about to build the payment, not the controller worker. */
bool zapp_controller_prover_ready(char *why, size_t cap);
/* True while the phone's thermal state has paused the node. */
bool zapp_controller_node_paused(void);
#endif
