/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Prove reproduction entry points force offline, cache-free builds. */

#ifndef ZCL_REPRO_NETWORK_POLICY_H
#define ZCL_REPRO_NETWORK_POLICY_H

/* repo is the checkout whose Makefile and tools/scripts/repro-verify.sh
 * are exercised. Returns 0 after the PASS line. */
int zcl_repro_network_policy(const char *repo);

#endif
