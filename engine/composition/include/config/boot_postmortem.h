/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONFIG_BOOT_POSTMORTEM_H
#define ZCL_CONFIG_BOOT_POSTMORTEM_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Boot-owned postmortem lifecycle.
 *
 * The lower-level sim/postmortem module knows how to write and replay crash
 * capsules. This wrapper owns the node boot policy: capsule directory choice,
 * seed-tape boot event, restart-time compression, and retention pruning. */
bool boot_postmortem_start(const char *datadir);
void boot_postmortem_stop(void);

#ifdef ZCL_TESTING
bool boot_postmortem_init_for_testing(const char *datadir);
void boot_postmortem_shutdown_for_testing(void);
const char *boot_postmortem_dir_for_testing(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* ZCL_CONFIG_BOOT_POSTMORTEM_H */
