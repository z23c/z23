/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * A walkable building part is 48 host-endian bytes. Admission reports
 * bounds only when the record meets the existing interior, floor, and
 * collision limits. A refusal leaves the caller's bounds unchanged. */
#ifndef SKY_COMBAT_BUILDING_PART_H
#define SKY_COMBAT_BUILDING_PART_H

#include <stddef.h>
#include <stdint.h>

#define SKY_BUILDING_PART_BYTES 48u
#define SKY_BUILDING_PART_MAGIC 0x31443342u

#define SKY_BUILDING_OFF_MAGIC 0u
#define SKY_BUILDING_OFF_WIDTH 4u
#define SKY_BUILDING_OFF_DEPTH 8u
#define SKY_BUILDING_OFF_HEIGHT 12u
#define SKY_BUILDING_OFF_FLOORS 16u
#define SKY_BUILDING_OFF_INTERIOR 20u
#define SKY_BUILDING_OFF_MIN_X 24u
#define SKY_BUILDING_OFF_MIN_Y 28u
#define SKY_BUILDING_OFF_MIN_Z 32u
#define SKY_BUILDING_OFF_MAX_X 36u
#define SKY_BUILDING_OFF_MAX_Y 40u
#define SKY_BUILDING_OFF_MAX_Z 44u

enum {
    SKY_BUILDING_PART_OK = 0,
    SKY_BUILDING_PART_FORMAT = 1,
    SKY_BUILDING_PART_INTERIOR = 2,
    SKY_BUILDING_PART_FLOOR = 3,
    SKY_BUILDING_PART_COLLISION = 4
};

struct sky_building_bounds {
    float width;
    float depth;
    float height;
    uint32_t floors;
    float min_x;
    float min_y;
    float min_z;
    float max_x;
    float max_y;
    float max_z;
};

int sky_building_part_admit(const unsigned char *bytes, size_t length,
                            struct sky_building_bounds *bounds);
const char *sky_building_part_reason(int status);
int sky_building_part_report_file(const char *path);

#endif
