/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Private declaration shared between package_prepare.c,
 * package_prepare_schema.c and package_verify_capabilities.c. NOT a public
 * header: only these three translation units include it. The third is the
 * receiver-side capability check, which grades a stranger's manifest and so
 * must apply the SAME closed-shape rule the publisher side applies — a
 * second copy of that rule would be a second answer to what a valid manifest
 * is, and the two would drift. */
#ifndef ZCL_VCS_PACKAGE_PREPARE_INTERNAL_H
#define ZCL_VCS_PACKAGE_PREPARE_INTERNAL_H

#include "json/json.h"

#include <stddef.h>

/* Defined in package_prepare_schema.c. True iff meta's own keys and every
 * dependency object's keys are drawn from the closed C23 v1 package-metadata
 * shape, and `files` (if present) is an array of strings. On a false return,
 * writes a human-readable reason to detail/detail_cap (may be NULL/0). */
bool prepare_meta_closed(const struct json_value *meta,
                         char *detail, size_t detail_cap);

#endif /* ZCL_VCS_PACKAGE_PREPARE_INTERNAL_H */
