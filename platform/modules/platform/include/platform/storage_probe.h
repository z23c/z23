/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: measure whether the storage under a directory behaves like a
 * spinning disk, on every host — including the ones where sysfs's
 * queue/rotational flag does not exist (macOS, Windows, containers, tmpfs
 * overlays). The measurement is a median random-read latency over a file the
 * caller already owns, so it needs no privileges and no device names. */

#ifndef ZCL_PLATFORM_STORAGE_PROBE_H
#define ZCL_PLATFORM_STORAGE_PROBE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* What the storage under a directory is, as far as this node can prove it.
 * UNKNOWN is a real answer and is never silently promoted to SOLID: a caller
 * that needs a decision picks its own default and says so. */
enum platform_storage_class {
    PLATFORM_STORAGE_CLASS_UNKNOWN = 0,
    PLATFORM_STORAGE_CLASS_SOLID,
    PLATFORM_STORAGE_CLASS_ROTATIONAL,
};

/* A seek-bound device answers a random read in milliseconds because it has to
 * move a head; anything solid-state answers in tens of microseconds. 2 ms is
 * the middle of that gap by two orders of magnitude on either side, so the
 * classification does not depend on picking the number precisely. */
#define PLATFORM_STORAGE_ROTATIONAL_MEDIAN_US 2000

/* Defaults for the probe below. 256 reads of 4 KiB is 1 MiB of IO — under a
 * second even on a 7200 rpm disk — and 64 MiB of file is enough spread that
 * the page cache cannot answer most of the samples. */
#define PLATFORM_STORAGE_PROBE_SAMPLES        256
#define PLATFORM_STORAGE_PROBE_BLOCK_BYTES    4096
#define PLATFORM_STORAGE_PROBE_MIN_FILE_BYTES (64LL * 1024 * 1024)

/* Median latency, in microseconds, of `samples` random `block`-byte reads
 * spread over the largest regular file directly in `dir` that is at least
 * `min_file_bytes` long.
 *
 * Returns false — and writes nothing — when there is no such file, when the
 * file cannot be opened, or when no read completes. That is the honest
 * "nothing was measured" answer; it is NOT a classification. */
bool platform_storage_random_read_median_us(const char *dir, int samples,
                                            size_t block,
                                            int64_t min_file_bytes,
                                            int64_t *out_median_us);

/* Classify a measured median. Pure — this is the whole decision rule, so a
 * test can pin it without touching a disk. */
enum platform_storage_class
platform_storage_class_from_median_us(int64_t median_us);

/* Stable lowercase name for status output and logs. Never NULL. */
const char *platform_storage_class_name(enum platform_storage_class klass);

/* Parse a name back. Anything unrecognised (including NULL and "auto") is
 * UNKNOWN, which every caller reads as "no override, decide for yourself". */
enum platform_storage_class platform_storage_class_parse(const char *name);

#endif
