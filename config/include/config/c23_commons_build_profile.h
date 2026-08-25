/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Closed, receipt-bound compiler profile for portable Commons code. */

#ifndef ZCL_CONFIG_C23_COMMONS_BUILD_PROFILE_H
#define ZCL_CONFIG_C23_COMMONS_BUILD_PROFILE_H

/* V2 makes the original AMD64/SSE2 floor explicit. V1 receipts remain
 * distinguishable by their older flags string; no historical evidence is
 * relabeled. */
#define ZCL_C23_COMMONS_BUILD_TARGET_V2 "linux-x86_64"
#define ZCL_C23_COMMONS_BUILD_FLAGS_QUICK_V2 \
    "-std=c23 -O1 -march=x86-64 -mtune=generic -fno-omit-frame-pointer " \
    "-D_POSIX_C_SOURCE=200809L -ffile-prefix-map=SOURCE=. -c"
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
    "-std=c23 -O1 -march=x86-64 -mtune=generic -fno-omit-frame-pointer " \
    "-D_POSIX_C_SOURCE=200809L -ffile-prefix-map=SOURCE=. " \
    "-Wall -Wextra -Werror"
#define ZCL_C23_COMMONS_BUILD_FLAGS_STANDARD_V2 \
    ZCL_C23_COMMONS_BUILD_FLAGS_STANDARD_BASE_V2 \
    ";asan,ubsan=clean;sanitizer_pie=off;sanitizer_aslr=off"

#endif /* ZCL_CONFIG_C23_COMMONS_BUILD_PROFILE_H */
