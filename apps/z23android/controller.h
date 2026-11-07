/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_CONTROLLER_H
#define ZAPP_CONTROLLER_H
#include "app.h"
/* notify may finish concurrently with detach; it must guard its own UI handle. */
bool zapp_controller_start(const char *files, const char *libs, bool preview, void (*notify)(void));
void zapp_controller_snapshot(struct zapp_view *view);
/* Takes an owner request: a control runs at once and an action is queued, its view saying at once what it does. False when
 * the request is refused, with the plain reason in why (which may be NULL). */
bool zapp_controller_action(const char *action, const char *argument, char *why, size_t cap);
void zapp_controller_detach(void);
/* The owner left the outcome line beside the controls under More (a scan, an invitation, a host control): it is cleared, so an
 * old failure is never shown as current. While an action runs the line is that action's own and stays. */
void zapp_controller_clear_result(void);
void zapp_controller_cancel_scan(void);
/* Hidden, the app cancels voice and stops observing the node and fleet, which keep running on
 * their own; shown again, it observes at once. */
void zapp_controller_visible(bool visible);
/* True while the node process runs; safe from any thread, with or without an activity. */
bool zapp_controller_node_running(void);
bool zapp_controller_setup_node_active(void);
/* Runs one wallet command on the calling thread (see zapp_wallet_run); the controller worker stays free,
 * so a slow wallet command never delays the node status. Safe from any thread. */
bool zapp_controller_wallet_run(const char *op, const char *arg, char *out, size_t cap);
/* Read a validated process-local preload; ready is only a hint. */
bool zapp_controller_preload_ready(void);
bool zapp_controller_preload_get(char *out, size_t cap, char identity[65], uint64_t *epoch, bool *command_ok);
/* Runs one step of a send on the calling thread (see zapp_wallet_send_run), never on the controller worker. Safe from any
 * thread. */
bool zapp_controller_send_run(const char *op, const char *input, unsigned timeout_ms, char *out, size_t cap);
/* Runs one step of wallet setup on the calling thread (see zapp_wallet_setup_run), never on the controller worker. Safe from
 * any thread. */
bool zapp_controller_setup_run(const char *op, const char *input, unsigned timeout_ms, char *out, size_t cap);
/* Starts or stops the node now, on the calling thread: wallet setup needs the node stopped while it writes the wallet,
 * and started again when it is done. A stop only asks the node to exit; poll zapp_controller_node_running. */
bool zapp_controller_node_control(bool start);
bool zapp_controller_node_resume_if_wanted(void);
/* Setup's stop: as node_control(false) but the owner's on or off choice is kept. */
bool zapp_controller_node_pause_for_setup(void);
/* Whether a shielded send may be built now (see zapp_send_prover_ready): the proving parameters are
 * installed and the running node reports it can prove. False, with a plain reason in why, when not. Asks
 * the node, so call it on the thread that is about to build the payment, not the controller worker. */
bool zapp_controller_prover_ready(char *why, size_t cap);
/* True while the phone's thermal state has paused the node. */
bool zapp_controller_node_paused(void);
#endif
