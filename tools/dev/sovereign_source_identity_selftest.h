/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Sandbox proof of the Git-free ZVCS Make identity adapter. */

#ifndef ZCL_SOVEREIGN_SOURCE_IDENTITY_SELFTEST_H
#define ZCL_SOVEREIGN_SOURCE_IDENTITY_SELFTEST_H

/* Runs tools/dev/source-identity.sh in a private tree. 0 on the PASS line.
 * 1 when a check fails. script_path is the source-identity.sh to drive. */
int zcl_sovereign_source_identity_selftest(const char *script_path);

#endif
