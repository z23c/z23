/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Read a node's tor: stamp and refuse a stub before packaging. */

#ifndef ZCL_TOR_STAMP_H
#define ZCL_TOR_STAMP_H

#include <stddef.h>

/* Writes "full" or "stub" into out. 0 on a stamp, -1 when the binary
 * is not executable or prints neither line. */
int zcl_tor_stamp(const char *node, char *out, size_t cap);

/* 0 when the node prints tor: full. 1 and the shared refusal sentence
 * on stderr for a stub or a missing stamp. context NULL uses node. */
int zcl_tor_require_full(const char *node, const char *context);

/* Writes <node>.tor-stamp with the stamp line and the binary's SHA-256.
 * 0 on success, -1 when the stamp or the digest is unavailable. */
int zcl_tor_write_stamp_sidecar(const char *node);

#endif
