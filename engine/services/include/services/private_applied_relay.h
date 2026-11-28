/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Relay private blocks only after their selected applied witness. */
#ifndef ZCL_PRIVATE_APPLIED_RELAY_H
#define ZCL_PRIVATE_APPLIED_RELAY_H
#include <stdbool.h>

struct chain_activation_controller;
struct connman;
struct uint256;

#ifdef ZCL_TESTING
/* Exercise peer queue behavior independently of chain setup. */
bool private_applied_relay_now(struct connman *cm, const struct uint256 *hash);
void private_applied_relay_test_before_recheck(void (*hook)(void *), void *ctx);
void private_applied_relay_test_evidence(bool allow);
#endif

/* False requests a later retry; no networking occurs under chain/store locks. */
bool private_applied_relay_check(struct chain_activation_controller *ctl,
                                 struct connman *cm);
void private_applied_relay_reset(void);
#endif
