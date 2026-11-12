/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Launch the sovereign-source network acceptance. Sets the package
 *          host and the source-publication hook, then execs the existing
 *          DHT acceptance script in script_dir. */

#ifndef ZCL_SOVEREIGN_SOURCE_NETWORK_H
#define ZCL_SOVEREIGN_SOURCE_NETWORK_H

/* Does not return on success. 2 when script_dir is missing. 127 when bash
 * cannot be exec'd. */
int zcl_sovereign_source_network_launch(const char *script_dir);

#endif
