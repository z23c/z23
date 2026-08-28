/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * One-shot authenticated watcher launch and graceful-stop capability. */
#ifndef ZCL_PLATFORM_WATCHER_LEASE_H
#define ZCL_PLATFORM_WATCHER_LEASE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PLATFORM_WATCHER_NONCE_HEX 64u
#define PLATFORM_WATCHER_HASH_HEX 64u

struct platform_watcher_launch {
    uintptr_t inherited_read;
    uintptr_t private_write;
    uintptr_t stop_native;
    uintptr_t record_native;
    char nonce[PLATFORM_WATCHER_NONCE_HEX + 1u];
    char stop_locator[320];
};

struct platform_watcher_lease {
    uintptr_t stop_native;
    char nonce[PLATFORM_WATCHER_NONCE_HEX + 1u];
    char stop_locator[320];
};

void platform_watcher_launch_init(struct platform_watcher_launch *launch);
bool platform_watcher_launch_prepare(struct platform_watcher_launch *launch,
                                     const char *canonical_root,
                                     const char *canonical_image,
                                     const char image_sha256[65]);
/* The sole native handle/fd the process launcher must inherit. */
uintptr_t platform_watcher_launch_inherited(
    const struct platform_watcher_launch *launch);
/* Write the fixed record and close the producer end. Call before/after spawn. */
bool platform_watcher_launch_publish(struct platform_watcher_launch *launch);
void platform_watcher_launch_close(struct platform_watcher_launch *launch);

void platform_watcher_lease_init(struct platform_watcher_lease *lease);
/* Consumes and closes inherited_read on every outcome. */
bool platform_watcher_lease_accept(struct platform_watcher_lease *lease,
                                   uintptr_t inherited_read,
                                   const char *claimed_root,
                                   const char *claimed_image,
                                   const char claimed_sha256[65]);
bool platform_watcher_lease_signal_stop(const char nonce[65]);
/* true means stopped; false means timeout/error. */
bool platform_watcher_lease_wait_stop(struct platform_watcher_lease *lease,
                                     uint32_t timeout_ms);
void platform_watcher_lease_close(struct platform_watcher_lease *lease);

#endif
