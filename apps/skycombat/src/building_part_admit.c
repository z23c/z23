/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Bytes in, one stable reason out. Bounds are written only for an
 * admitted part. No script and no second part authority. */
#include "../include/sky_combat/building_part.h"
#include "../specifications/3d_building_specs.h"

#include <stdio.h>
#include <string.h>

struct sky_building_fields {
    float width;
    float depth;
    float height;
    uint32_t floors;
    uint32_t interior;
    float min_x;
    float min_y;
    float min_z;
    float max_x;
    float max_y;
    float max_z;
};

static uint32_t part_u32(const unsigned char *bytes)
{
    uint32_t value;
    memcpy(&value, bytes, sizeof value);
    return value;
}

static float part_f32(const unsigned char *bytes)
{
    float value;
    memcpy(&value, bytes, sizeof value);
    return value;
}

static int part_format(const unsigned char *bytes, size_t length,
                       struct sky_building_fields *part)
{
    if (bytes == NULL || part == NULL || length != SKY_BUILDING_PART_BYTES)
        return SKY_BUILDING_PART_FORMAT;
    if (part_u32(bytes + SKY_BUILDING_OFF_MAGIC) != SKY_BUILDING_PART_MAGIC)
        return SKY_BUILDING_PART_FORMAT;
    part->width = part_f32(bytes + SKY_BUILDING_OFF_WIDTH);
    part->depth = part_f32(bytes + SKY_BUILDING_OFF_DEPTH);
    part->height = part_f32(bytes + SKY_BUILDING_OFF_HEIGHT);
    part->floors = part_u32(bytes + SKY_BUILDING_OFF_FLOORS);
    part->interior = part_u32(bytes + SKY_BUILDING_OFF_INTERIOR);
    part->min_x = part_f32(bytes + SKY_BUILDING_OFF_MIN_X);
    part->min_y = part_f32(bytes + SKY_BUILDING_OFF_MIN_Y);
    part->min_z = part_f32(bytes + SKY_BUILDING_OFF_MIN_Z);
    part->max_x = part_f32(bytes + SKY_BUILDING_OFF_MAX_X);
    part->max_y = part_f32(bytes + SKY_BUILDING_OFF_MAX_Y);
    part->max_z = part_f32(bytes + SKY_BUILDING_OFF_MAX_Z);
    return SKY_BUILDING_PART_OK;
}

static int part_floor(const struct sky_building_fields *part)
{
    float interior_height;
    if (part->floors < BUILDING_MIN_FLOORS || part->floors > BUILDING_MAX_FLOORS)
        return SKY_BUILDING_PART_FLOOR;
    interior_height = part->height - FLOOR_THICKNESS * (float)part->floors;
    if (!(interior_height >= PLAYER_HEIGHT + 0.5f))
        return SKY_BUILDING_PART_FLOOR;
    return SKY_BUILDING_PART_OK;
}

static int part_interior(const struct sky_building_fields *part)
{
    float floor_area;
    float interior_height;
    float volume;
    if (part->interior == 0)
        return SKY_BUILDING_PART_INTERIOR;
    if (!(part->width >= 10.0f) || !(part->depth >= 10.0f))
        return SKY_BUILDING_PART_INTERIOR;
    if (!(part->height >= BUILDING_MIN_CEILING_HEIGHT))
        return SKY_BUILDING_PART_INTERIOR;
    floor_area = part->width * part->depth;
    if (!(floor_area >= BUILDING_MIN_FLOOR_AREA))
        return SKY_BUILDING_PART_INTERIOR;
    interior_height = part->height - FLOOR_THICKNESS * (float)part->floors;
    volume = part->width * part->depth * interior_height;
    if (!(volume >= BUILDING_MIN_INTERIOR_VOLUME))
        return SKY_BUILDING_PART_INTERIOR;
    return SKY_BUILDING_PART_OK;
}

static int part_collision(const struct sky_building_fields *part)
{
    float span_x = part->max_x - part->min_x;
    float span_y = part->max_y - part->min_y;
    float span_z = part->max_z - part->min_z;
    if (!(span_x >= part->width && span_y >= part->height && span_z >= part->depth))
        return SKY_BUILDING_PART_COLLISION;
    return SKY_BUILDING_PART_OK;
}

static void part_store(const struct sky_building_fields *part,
                       struct sky_building_bounds *bounds)
{
    bounds->width = part->width;
    bounds->depth = part->depth;
    bounds->height = part->height;
    bounds->floors = part->floors;
    bounds->min_x = part->min_x;
    bounds->min_y = part->min_y;
    bounds->min_z = part->min_z;
    bounds->max_x = part->max_x;
    bounds->max_y = part->max_y;
    bounds->max_z = part->max_z;
}

int sky_building_part_admit(const unsigned char *bytes, size_t length,
                            struct sky_building_bounds *bounds)
{
    struct sky_building_fields part;
    int status;
    if (bounds == NULL)
        return SKY_BUILDING_PART_FORMAT;
    status = part_format(bytes, length, &part);
    if (status != SKY_BUILDING_PART_OK)
        return status;
    status = part_floor(&part);
    if (status != SKY_BUILDING_PART_OK)
        return status;
    status = part_interior(&part);
    if (status != SKY_BUILDING_PART_OK)
        return status;
    status = part_collision(&part);
    if (status != SKY_BUILDING_PART_OK)
        return status;
    part_store(&part, bounds);
    return SKY_BUILDING_PART_OK;
}

const char *sky_building_part_reason(int status)
{
    switch (status) {
    case SKY_BUILDING_PART_OK:
        return "ok";
    case SKY_BUILDING_PART_FORMAT:
        return "format";
    case SKY_BUILDING_PART_INTERIOR:
        return "interior";
    case SKY_BUILDING_PART_FLOOR:
        return "floor";
    case SKY_BUILDING_PART_COLLISION:
        return "collision";
    default:
        return "format";
    }
}

int sky_building_part_report_file(const char *path)
{
    unsigned char bytes[SKY_BUILDING_PART_BYTES];
    struct sky_building_bounds bounds;
    FILE *file;
    size_t count;
    int status;
    if (path == NULL || path[0] == '\0')
        return -1;
    file = fopen(path, "rb");
    if (file == NULL)
        return -1;
    count = fread(bytes, 1, sizeof bytes, file);
    if (fclose(file) != 0)
        return -1;
    if (count != sizeof bytes)
        status = SKY_BUILDING_PART_FORMAT;
    else
        status = sky_building_part_admit(bytes, count, &bounds);
    if (status == SKY_BUILDING_PART_OK) {
        printf("QA_BUILDING admit=1 width=%.1f depth=%.1f height=%.1f floors=%u "
               "min=%.1f,%.1f,%.1f max=%.1f,%.1f,%.1f\n",
               (double)bounds.width, (double)bounds.depth, (double)bounds.height,
               (unsigned)bounds.floors,
               (double)bounds.min_x, (double)bounds.min_y, (double)bounds.min_z,
               (double)bounds.max_x, (double)bounds.max_y, (double)bounds.max_z);
    } else {
        printf("QA_BUILDING admit=0 reason=%s\n", sky_building_part_reason(status));
    }
    return 0;
}
