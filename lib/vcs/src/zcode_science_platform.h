/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Internal platform facts used by canonical science profiles. */

#ifndef Z23_VCS_ZCODE_SCIENCE_PLATFORM_H
#define Z23_VCS_ZCODE_SCIENCE_PLATFORM_H

#include "vcs/zcode_science.h"

int zcode_science_platform_logical_cores(void);
void zcode_science_platform_capture(
    struct vcs_zcode_hardware_profile_v1 *out);

#endif
