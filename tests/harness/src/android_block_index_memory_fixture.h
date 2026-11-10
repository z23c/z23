/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Isolated Android flat-index memory experiment; no chain authority. */
#ifndef Z23_ANDROID_BLOCK_INDEX_MEMORY_FIXTURE_H
#define Z23_ANDROID_BLOCK_INDEX_MEMORY_FIXTURE_H

#if defined(__linux__) && !defined(_WIN32)
#include "services/block_index_loader.h"
#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "core/uint256.h"
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static bool bil_am_decimal(const char *s, uint64_t max, uint64_t *out)
{
    if (!s || !*s) return false;
    uint64_t n = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9' || n > (max - (unsigned)(*s - '0')) / 10) return false;
        n = n * 10 + (unsigned)(*s - '0');
    }
    *out = n;
    return true;
}
static bool bil_am_hex64(const char *s)
{
    if (!s || strlen(s) != 64) return false;
    for (size_t i = 0; i < 64; i++) if (!isxdigit((unsigned char)s[i])) return false;
    return true;
}
static long bil_am_rss_kib(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[256]; long value = -1;
    while (fgets(line, sizeof(line), f)) if (sscanf(line, "VmRSS: %ld kB", &value) == 1) break;
    bool failed = ferror(f);
    if (fclose(f) != 0) failed = true;
    if (failed) return -1;
    return value;
}
static bool bil_am_owned_input(const char *dir, uint64_t bytes)
{
    static const char prefix[] = "/data/local/tmp/z23-index-memory.";
    if (strncmp(dir, prefix, sizeof(prefix) - 1) || !dir[sizeof(prefix) - 1] || strchr(dir + sizeof(prefix) - 1, '/')) return false;
    char path[1024]; struct stat st;
    int n = snprintf(path, sizeof(path), "%s/block_index.bin", dir);
    return n > 0 && (size_t)n < sizeof(path) && lstat(dir, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == geteuid() && (st.st_mode & 07777) == 0700 &&
        lstat(path, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == geteuid() && (st.st_mode & 07777) == 0600 && st.st_size >= 0 && (uint64_t)st.st_size == bytes;
}
static bool bil_am_contiguous(struct block_index *tip, int height)
{
    for (int h = height; h >= 0; h--) {
        if (!tip || !tip->phashBlock || tip->nHeight != h) return false;
        tip = tip->pprev;
    }
    return tip == NULL;
}
static bool bil_am_input_valid(const char *dir, const char *row_arg, const char *height_arg,
    const char *hash_arg, const char *bytes_arg, uint64_t *rows, uint64_t *height, uint64_t *bytes)
{
    return bil_am_decimal(row_arg, 3500000, rows) && *rows &&
        bil_am_decimal(height_arg, 3499999, height) && *height + 1 <= *rows &&
        bil_am_hex64(hash_arg) && bil_am_decimal(bytes_arg, UINT64_C(2000000000), bytes) &&
        bil_am_owned_input(dir, *bytes);
}
static int bil_am_android_memory_fixture(void)
{
    const char *dir = getenv("ZCL_BLOCK_INDEX_MEMORY_DIR");
    const char *row_arg = getenv("ZCL_BLOCK_INDEX_MEMORY_ROWS");
    const char *height_arg = getenv("ZCL_BLOCK_INDEX_MEMORY_HEIGHT");
    const char *hash_arg = getenv("ZCL_BLOCK_INDEX_MEMORY_HASH");
    const char *bytes_arg = getenv("ZCL_BLOCK_INDEX_MEMORY_BYTES");
    uint64_t rows, height, bytes;
    if (!bil_am_input_valid(dir, row_arg, height_arg, hash_arg, bytes_arg, &rows, &height, &bytes)) {
        fputs("set ZCL_BLOCK_INDEX_MEMORY_DIR, ZCL_BLOCK_INDEX_MEMORY_ROWS, ZCL_BLOCK_INDEX_MEMORY_HEIGHT, ZCL_BLOCK_INDEX_MEMORY_HASH and ZCL_BLOCK_INDEX_MEMORY_BYTES\n", stderr);
        return 2;
    }
    long before = bil_am_rss_kib();
    if (before < 0) return 1;
    struct timespec a, b; struct rusage usage;
    if (clock_gettime(CLOCK_MONOTONIC, &a) != 0) return 1;
    struct main_state ms; main_state_init(&ms);
    struct zcl_result loaded = load_block_index_flat(dir, &ms);
    struct uint256 hash; uint256_set_hex(&hash, hash_arg);
    struct block_index *tip = loaded.ok ? block_map_find(&ms.map_block_index, &hash) : NULL;
    bool ok = loaded.ok && ms.map_block_index.size == rows && bil_am_contiguous(tip, (int)height) &&
        active_chain_move_window_tip(&ms.chain_active, tip);
    if (!ok || clock_gettime(CLOCK_MONOTONIC, &b) != 0 || getrusage(RUSAGE_SELF, &usage) != 0) {
        fputs("index load or structural checks failed\n", stderr); main_state_free(&ms); return 1;
    }
    long rss = bil_am_rss_kib();
    if (rss < 0) { main_state_free(&ms); return 1; }
    int64_t ms_elapsed = (int64_t)(b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1000000;
    main_state_free(&ms);
    long after = bil_am_rss_kib();
    if (after < 0) return 1;
    printf("{\"source\":\"supplied_flat_index\",\"rows\":%" PRIu64 ",\"height\":%" PRIu64
           ",\"elapsed_ms\":%" PRId64 ",\"before_rss_kib\":%ld,\"rss_kib\":%ld,\"peak_rss_kib\":%ld,\"after_cleanup_rss_kib\":%ld}\n",
           rows, height, ms_elapsed, before, rss, usage.ru_maxrss, after);
    return 0;
}

/* A child has an independent peak counter; its initial RSS is inherited. */
static int bil_am_android_memory_case(void)
{
    fflush(NULL);
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        int rc = bil_am_android_memory_fixture();
        if (fflush(stdout) != 0) rc = 1;
        _exit(rc);
    }
    int status;
    pid_t got;
    do { got = waitpid(child, &status, 0); } while (got < 0 && errno == EINTR);
    return got == child && WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 1;
}

#else
static int bil_am_android_memory_case(void)
{
    fputs("Android block-index memory experiment unavailable on this platform\n", stderr);
    return 1;
}
#endif
#endif
