/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Refuse stable release publication and verify one existing archive. */

#ifndef ZCL_RELEASE_CONTAINMENT_H
#define ZCL_RELEASE_CONTAINMENT_H

/* 0 when --verify accepts one archive. 1 on a verification error.
 * 2 when the invocation is not read-only verification. */
int zcl_release_invoke(int argc, char **argv);

#endif
