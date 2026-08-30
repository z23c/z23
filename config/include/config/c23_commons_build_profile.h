/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Closed, receipt-bound compiler profile for portable Commons code.
 *
 * The concrete flags are platform-specific and are supplied by
 * lib/platform/toolchain.h.  These macros remain the stable names so callers
 * do not need platform branches; on Linux they expand to the historical V2
 * string byte-for-byte. */

#ifndef ZCL_CONFIG_C23_COMMONS_BUILD_PROFILE_H
#define ZCL_CONFIG_C23_COMMONS_BUILD_PROFILE_H

#include "platform/toolchain.h"

#define ZCL_C23_COMMONS_BUILD_TARGET_V2 (platform_toolchain_canonical_target_string())
#define ZCL_C23_COMMONS_BUILD_FLAGS_QUICK_V2 \
    (platform_toolchain_commons_flags_quick())
/* The standard profile splits at the sanitizer segment: the BASE is the
 * compile contract; the segment after it is an OBSERVED outcome. The
 * verifier's emit path composes BASE + the outcome it actually observed
 * ("clean" only when both ASan and UBSan ran clean; "not-run" for a
 * testless recipe; "unavailable" when the diagnostic could not run;
 * "findings" for a real report) + the pie/aslr tail. The full-STANDARD_V2
 * constant keeps the evidence-track value byte-identical: that track
 * refuses unless both outcomes are PASS, so "clean" is always verified
 * there. */
#define ZCL_C23_COMMONS_BUILD_FLAGS_STANDARD_BASE_V2 \
    (platform_toolchain_commons_flags_standard_base())
#define ZCL_C23_COMMONS_BUILD_FLAGS_STANDARD_V2 \
    (platform_toolchain_commons_flags_standard())

#endif /* ZCL_CONFIG_C23_COMMONS_BUILD_PROFILE_H */
