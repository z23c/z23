/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Launch the seven-daemon DHT acceptance with one after-sparse
 *          hook. Shared by the acceptance wrappers that only select a hook. */

#ifndef ZCL_DHT_ACCEPTANCE_LAUNCH_H
#define ZCL_DHT_ACCEPTANCE_LAUNCH_H

/* Does not return on success. 2 when script_dir or hook_file is missing.
 * 127 when bash cannot be exec'd. hook_file is a file name inside script_dir. */
int zcl_dht_acceptance_launch(const char *script_dir, const char *hook_file);

#endif
