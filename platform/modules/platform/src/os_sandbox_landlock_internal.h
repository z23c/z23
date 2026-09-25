/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Linux-only seam between the Landlock ruleset builder
 * (os_sandbox_landlock_linux.c) and the enforcement/witness state that
 * lives in os_sandbox_linux.c. The builder turns a policy into a ruleset fd;
 * this call makes the calling thread enter it, retains the fd for retrofit
 * joins, and publishes the confinement witness. Declares nothing elsewhere. */
#ifndef ZCL_PLATFORM_OS_SANDBOX_LANDLOCK_INTERNAL_H
#define ZCL_PLATFORM_OS_SANDBOX_LANDLOCK_INTERNAL_H

#if defined(__linux__)
#include "platform/os_sandbox.h"

/* Stage the witness grants for `rules`, landlock_restrict_self(ruleset_fd),
 * retain the fd and publish the witness. Takes ownership of ruleset_fd: it
 * is closed on failure and retained on success. `abi` is the probed ABI the
 * ruleset was built for. */
struct zcl_result os_sandbox_landlock_enforce_ruleset(
    int ruleset_fd, int abi, const struct os_sandbox_path_rule *rules,
    size_t n_rules);
#endif

#endif
