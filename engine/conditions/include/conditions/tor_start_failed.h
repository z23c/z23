/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * tor_start_failed condition.
 *
 * DETECT: the embedded Tor thread is not running while this boot asked for
 * an onion — tor_integration_is_requested() && !tor_integration_is_enabled(),
 * observed through the armed boot_tor_watch (config/boot_tor_watch.h).
 * That is an OBSERVATION of core's own predicates, so it is true whether Tor
 * died at second 1 or at hour 6.
 *
 * REMEDY: names the failure with a typed BLOCKER_DEPENDENCY
 * ("tor.start_failed") carrying the classified reason plus the quoted,
 * onion-redacted Tor warning, and retries the start through the engine-side
 * wrapper on an exponential schedule (5s, 15s, 45s, 135s, then a 300s cap)
 * that never gives up while the node runs.
 *
 * WITNESS: the Tor thread is running again. Not the inverse of detect: the
 * remedy only ASKS for a start, and tor_integration_is_enabled() flips only
 * once tor_run_main has actually accepted the configuration and entered its
 * loop — the exact fact that was false in the 2026-09-08 incident while the
 * start call kept returning true.
 *
 * Why this exists: on 2026-09-08 the SOCKS bootstrap port was still held by
 * the outgoing process, Tor's config parse failed, the thread exited -1, and
 * nothing in the tree retried or said so. */

#ifndef ZCL_CONDITIONS_TOR_START_FAILED_H
#define ZCL_CONDITIONS_TOR_START_FAILED_H

void register_tor_start_failed(void);

#ifdef ZCL_TESTING
void tor_start_failed_test_reset(void);
int  tor_start_failed_test_remedy_calls(void);
#endif

#endif /* ZCL_CONDITIONS_TOR_START_FAILED_H */
