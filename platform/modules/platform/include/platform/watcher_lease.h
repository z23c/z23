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
    struct platform_watcher_accepted_binding *accepted;
};

struct platform_watcher_accepted_binding {
    char nonce[65];
    uint64_t creator_pid, creator_start_token;
    char canonical_root[4096];
    uint64_t root_volume, root_low, root_high;
    char canonical_image[4096];
    uint64_t image_volume, image_low, image_high, image_size;
    char image_sha256[65];
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
/* Immutable copy of the identities authenticated during accept. */
bool platform_watcher_lease_binding(
    const struct platform_watcher_lease *lease,
    struct platform_watcher_accepted_binding *out);
bool platform_watcher_lease_signal_stop(const char nonce[65]);
/* true means stopped; false means timeout/error. */
bool platform_watcher_lease_wait_stop(struct platform_watcher_lease *lease,
                                     uint32_t timeout_ms);
void platform_watcher_lease_close(struct platform_watcher_lease *lease);

#endif
