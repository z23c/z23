/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * storage_probe — implementation. See platform/storage_probe.h.
 *
 * The whole probe is written against sibling platform seams (directory
 * listing, positioned reads, the monotonic clock, the RNG) rather than raw
 * POSIX, so the same source classifies storage on Linux, macOS and Windows
 * and the posix-only lint gate has nothing to object to.
 *
 * WHY A TIMED PROBE AT ALL. Linux publishes queue/rotational in sysfs and
 * hw_profile already reads it. That flag is absent on macOS and Windows, and
 * on Linux it is absent or wrong for exactly the cases that matter most:
 * a datadir on an overlay, a bind mount, a device-mapper stack, or a USB
 * enclosure whose bridge reports 0 for a spinning disk inside. A node that
 * only trusts sysfs therefore silently applies solid-state pacing to the
 * boxes that most need the spinning-disk pacing. Measuring costs a megabyte
 * of IO once per boot and cannot be lied to by a driver.
 */

#include "platform/storage_probe.h"

#include "platform/clock.h"
#include "platform/directory_compat.h"
#include "platform/positioned_file.h"
#include "platform/rng.h"

#include "base/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Hard caps so a caller-supplied sample count can never turn a boot-time
 * classification into an unbounded IO storm. */
#define PROBE_SAMPLES_MAX 4096
#define PROBE_BLOCK_MAX   (1024u * 1024u)

static int cmp_i64(const void *a, const void *b)
{
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
    return (x > y) - (x < y);
}

/* Pick the LARGEST regular file directly in `dir` that clears the floor. A
 * big file is what makes the samples land far apart, which is what defeats
 * both the page cache and the drive's own readahead. */
static bool probe_pick_file(const char *dir, int64_t min_bytes, char *out,
                            size_t out_size, uint64_t *out_size_bytes)
{
    struct platform_directory_list files;
    memset(&files, 0, sizeof(files));
    if (!platform_directory_list_regular_sorted(dir, &files))
        return false;

    bool found = false;
    uint64_t best = 0;
    for (size_t i = 0; i < files.count; i++) {
        const struct platform_directory_entry *e = &files.entries[i];
        if (!e->snapshot_valid || !e->name)
            continue;
        if (e->size < (uint64_t)min_bytes || e->size <= best)
            continue;
        int n = snprintf(out, out_size, "%s/%s", dir, e->name);
        if (n <= 0 || (size_t)n >= out_size)
            continue;
        best = e->size;
        found = true;
    }
    platform_directory_list_free(&files);
    if (found && out_size_bytes)
        *out_size_bytes = best;
    return found;
}

bool platform_storage_random_read_median_us(const char *dir, int samples,
                                            size_t block,
                                            int64_t min_file_bytes,
                                            int64_t *out_median_us)
{
    if (!dir || !dir[0] || !out_median_us)
        return false;
    if (samples <= 0)
        samples = PLATFORM_STORAGE_PROBE_SAMPLES;
    if (samples > PROBE_SAMPLES_MAX)
        samples = PROBE_SAMPLES_MAX;
    if (block == 0)
        block = PLATFORM_STORAGE_PROBE_BLOCK_BYTES;
    if (block > PROBE_BLOCK_MAX)
        block = PROBE_BLOCK_MAX;
    if (min_file_bytes <= 0)
        min_file_bytes = PLATFORM_STORAGE_PROBE_MIN_FILE_BYTES;
    if (min_file_bytes < (int64_t)block * 16)
        min_file_bytes = (int64_t)block * 16;

    char path[1024];
    uint64_t file_bytes = 0;
    if (!probe_pick_file(dir, min_file_bytes, path, sizeof(path), &file_bytes))
        return false;

    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path))
        return false;

    uint8_t *buf = zcl_malloc(block, "storage_probe_buf");
    int64_t *lat = zcl_malloc((size_t)samples * sizeof(*lat), "storage_probe_lat");
    if (!buf || !lat) {
        free(buf);
        free(lat);
        platform_positioned_file_close(&file);
        return false;
    }

    /* One RNG draw seeds a local xorshift: the probe must not consume the
     * process RNG once per sample, and the offsets only need to be spread,
     * not unpredictable. */
    uint64_t state = rng_u64() | 1u;
    uint64_t span = file_bytes > block ? file_bytes - block : 1;

    int taken = 0;
    for (int i = 0; i < samples; i++) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        uint64_t offset = state % span;
        offset -= offset % block; /* block-aligned: one device read, not two */

        int64_t t0 = clock_now_monotonic_ns();
        int64_t nr = platform_positioned_file_read(&file, buf, block, offset);
        int64_t t1 = clock_now_monotonic_ns();
        if (nr <= 0)
            continue;
        int64_t us = (t1 - t0) / 1000;
        lat[taken++] = us < 0 ? 0 : us;
    }

    platform_positioned_file_close(&file);
    free(buf);

    if (taken == 0) {
        free(lat);
        return false;
    }
    qsort(lat, (size_t)taken, sizeof(*lat), cmp_i64);
    /* Median, not mean: one 300 ms outlier from an unrelated writer must not
     * relabel an SSD as a spinning disk. */
    *out_median_us = lat[taken / 2];
    free(lat);
    return true;
}

enum platform_storage_class
platform_storage_class_from_median_us(int64_t median_us)
{
    if (median_us < 0)
        return PLATFORM_STORAGE_CLASS_UNKNOWN;
    return median_us >= PLATFORM_STORAGE_ROTATIONAL_MEDIAN_US
               ? PLATFORM_STORAGE_CLASS_ROTATIONAL
               : PLATFORM_STORAGE_CLASS_SOLID;
}

const char *platform_storage_class_name(enum platform_storage_class klass)
{
    switch (klass) {
    case PLATFORM_STORAGE_CLASS_SOLID:
        return "solid";
    case PLATFORM_STORAGE_CLASS_ROTATIONAL:
        return "rotational";
    case PLATFORM_STORAGE_CLASS_UNKNOWN:
    default:
        return "unknown";
    }
}

enum platform_storage_class platform_storage_class_parse(const char *name)
{
    if (!name || !name[0])
        return PLATFORM_STORAGE_CLASS_UNKNOWN;
    if (strcmp(name, "rotational") == 0 || strcmp(name, "hdd") == 0 ||
        strcmp(name, "spinning") == 0)
        return PLATFORM_STORAGE_CLASS_ROTATIONAL;
    if (strcmp(name, "solid") == 0 || strcmp(name, "ssd") == 0 ||
        strcmp(name, "nvme") == 0 || strcmp(name, "flash") == 0)
        return PLATFORM_STORAGE_CLASS_SOLID;
    return PLATFORM_STORAGE_CLASS_UNKNOWN;
}
