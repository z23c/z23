/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Private declarations shared between hotswap_loader.c and
 * hotswap_manifest_validate.c. Neither symbol here is part of the public
 * hotswap API in include/hotswap/; both files are the only translation
 * units that may include this header. */
#ifndef ZCL_HOTSWAP_LOADER_INTERNAL_H
#define ZCL_HOTSWAP_LOADER_INTERNAL_H

#include <stdbool.h>

/* Defined in hotswap_manifest_validate.c. True when `value` is a non-NULL,
 * non-empty, NUL-terminated string shorter than 4096 bytes. Used both by
 * hotswap_manifest_v2_validate() to require manifest text fields and by
 * hotswap_loader.c's manifest_copy() to decide which fields are safe to
 * snapshot into a generation slot / load report. */
bool manifest_text_present(const char *value);

#endif /* ZCL_HOTSWAP_LOADER_INTERNAL_H */
