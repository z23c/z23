/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Launch the attestation-flight acceptance. Selects the flight
 *          hook, then execs the existing DHT acceptance script in script_dir. */

#ifndef ZCL_ATTESTATION_FLIGHT_H
#define ZCL_ATTESTATION_FLIGHT_H

/* Does not return on success. 2 when script_dir is missing. 127 when bash
 * cannot be exec'd. */
int zcl_attestation_flight_launch(const char *script_dir);

#endif
