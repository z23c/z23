/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * checkpoint_bundle_install_ready — the mid-session RETRY that finishes the
 * fresh-boot instant-on install. On a genuinely fresh node the staged
 * compiled-checkpoint bundle cannot install at app_init: the validated header
 * chain has not yet reached the checkpoint height, so the boot-time autodetect
 * DEFERS (fail-open, never .failed — see config/consensus_state_install_runtime.h
 * retriable_headers_not_ready). This condition watches the header chain climb;
 * the moment it genuinely OWNS the compiled checkpoint block
 * (consensus_state_checkpoint_header_ready) AND a bundle is still staged AND the
 * node has not already folded past the checkpoint, it ARMS the durable
 * install-on-next-boot request (the bounded 1c budget) and requests a supervised
 * respawn — reusing the SAME concurrency-safe pattern as the shielded ladder's
 * Rung B, so the atomic installer runs at the next single-threaded boot rather
 * than racing the live reducer. Bounded end-to-end: the 1c budget caps respawns,
 * and a TERMINAL budget stops the remedy (operator paged). */

#ifndef ZCL_CONDITIONS_CHECKPOINT_BUNDLE_INSTALL_READY_H
#define ZCL_CONDITIONS_CHECKPOINT_BUNDLE_INSTALL_READY_H

void register_checkpoint_bundle_install_ready(void);

#ifdef ZCL_TESTING
#include <stdbool.h>
struct main_state;
/* Reset all module-static state + the condition's engine state between tests. */
void checkpoint_bundle_install_ready_test_reset(void);
/* Override the runtime main_state / datadir the detect+remedy read (NULL/"" =
 * fall back to the live runtime accessors). */
void checkpoint_bundle_install_ready_test_set_main_state(struct main_state *ms);
void checkpoint_bundle_install_ready_test_set_datadir(const char *datadir);
/* Suppress the real respawn/shutdown so a test can exercise arm + budget
 * bounding without tearing the process down. */
void checkpoint_bundle_install_ready_test_suppress_restart(bool suppress);
/* How many times the remedy has run since the last reset. */
int checkpoint_bundle_install_ready_test_remedy_calls(void);
/* Directly drive detect()/remedy() for the focused test. */
bool checkpoint_bundle_install_ready_test_detect(void);
int checkpoint_bundle_install_ready_test_remedy(void);
#endif

#endif /* ZCL_CONDITIONS_CHECKPOINT_BUNDLE_INSTALL_READY_H */
