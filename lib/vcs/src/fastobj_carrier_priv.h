/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * fastobj_carrier_priv — small helpers shared between fastobj_carrier.c
 * (export, verify, admit — every leg that touches a local fastobj cache
 * directory) and fastobj_carrier_fetch.c (the offline wire leg, which
 * moves an already-built carrier package store-to-store with no cache
 * directory involved at all). NOT a public header: nothing outside
 * lib/vcs/src/ includes this. Native-Windows builds compile neither
 * definition (the carrier is disabled there — see the _WIN32 stubs in
 * fastobj_carrier.c), so this header is only pulled in on the non-Windows
 * side. */

#ifndef ZCL_VCS_FASTOBJ_CARRIER_PRIV_H
#define ZCL_VCS_FASTOBJ_CARRIER_PRIV_H

#include "vcs/fastobj_carrier.h"
#include "vcs/package_manifest.h"
#include "vcs/package_store.h"

/* vcs_package_store_result_string(), named for this module's own error
 * prefix convention. */
const char *fc_store_err(enum vcs_package_store_result r);

/* Fill the caller-facing stats struct from a landed manifest plus the
 * counts each leg already tracked while it walked entries. */
void fc_fill_stats(const struct vcs_package_manifest *manifest,
                   uint32_t entries, uint64_t object_bytes,
                   struct vcs_fastobj_carrier_stats *stats);

#endif /* ZCL_VCS_FASTOBJ_CARRIER_PRIV_H */
