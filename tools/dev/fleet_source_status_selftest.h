/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Prove the fleet source classifier against a private git fixture. */

#ifndef ZCL_FLEET_SOURCE_STATUS_SELFTEST_H
#define ZCL_FLEET_SOURCE_STATUS_SELFTEST_H

/* library_path is tools/scripts/fleet_source_status.sh. The classifier
 * stays in that shell; this driver builds the fixture and checks it.
 * 0 when every case matches and the PASS line was printed. */
int zcl_fleet_source_status_selftest(const char *library_path);

#endif
