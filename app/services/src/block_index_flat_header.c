/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: read one integrity-bound header from the flat block index. */

#include "block_index_flat_internal.h"
#include "platform/read_mapping.h"
#include "services/block_index_integrity.h"
#include "services/block_index_loader.h"
#include "storage/sha3_sidecar_io.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#if defined(_WIN32)
#include <io.h>
#define flat_close _close
#else
#include <unistd.h>
#define flat_close close
#endif

static void flat_header_mapping_close(struct platform_read_mapping *mapping,
                                      int fd)
{
    platform_read_mapping_close(mapping);
    if (fd >= 0) (void)flat_close(fd);
}

struct zcl_result block_index_flat_header_at(const char *datadir,
                                             int32_t height,
                                             uint8_t out_hash[32],
                                             uint8_t out_root[32])
{
    if (!datadir || height < 0 || !out_hash || !out_root)
        return ZCL_ERR(-100, "block_index_flat_header_at: bad args");
    char path[1024];
    snprintf(path, sizeof(path), "%s/block_index.bin", datadir);
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return ZCL_ERR(-101, "block_index_flat_header_at: cannot open "
                       "%s: %s", path, strerror(errno));
    struct stat st;
    if (fstat(fd, &st) != 0) {
        int saved_errno = errno;
        (void)flat_close(fd);
        return ZCL_ERR(-102, "block_index_flat_header_at: fstat: %s",
                       strerror(saved_errno));
    }
    size_t file_size = (size_t)st.st_size;
    if (file_size < 8) {
        (void)flat_close(fd);
        return ZCL_ERR(-103, "block_index_flat_header_at: file too "
                       "small (%zu bytes)", file_size);
    }
    struct platform_read_mapping mapping;
    platform_read_mapping_init(&mapping);
    if (!platform_read_mapping_open(&mapping, fd, file_size)) {
        (void)flat_close(fd);
        return ZCL_ERR(-104, "block_index_flat_header_at: mapping "
                       "failed (%zu bytes)", file_size);
    }
    platform_read_mapping_advise_sequential(&mapping);
    const uint8_t *data = mapping.data;
    uint64_t payload_off = 0;
    uint32_t lead, embedded_magic;
    memcpy(&lead, data, 4);
    memcpy(&embedded_magic, BII_EMBEDDED_MAGIC, 4);
    if (lead != embedded_magic) {
        flat_header_mapping_close(&mapping, fd);
        return ZCL_ERR(-105, "block_index_flat_header_at: no embedded "
                       "integrity header; refusing unverified legacy bytes");
    }
    struct ssio_sidecar_header header;
    int verdict = bii_verify_embedded(datadir, &header, &payload_off);
    if (verdict != 0) {
        flat_header_mapping_close(&mapping, fd);
        return ZCL_ERR(-106, "block_index_flat_header_at: embedded integrity "
                       "check failed (verdict=%d)", verdict);
    }
    uint32_t magic, count;
    if (payload_off > file_size - 8) {
        flat_header_mapping_close(&mapping, fd);
        return ZCL_ERR(-107, "block_index_flat_header_at: payload offset "
                       "%llu exceeds mapped file (%zu bytes)",
                       (unsigned long long)payload_off, file_size);
    }
    memcpy(&magic, data + payload_off, 4);
    memcpy(&count, data + payload_off + 4, 4);
    if (magic != 0x5A434C49 || count == 0 || count > 10000000) {
        flat_header_mapping_close(&mapping, fd);
        return ZCL_ERR(-108, "block_index_flat_header_at: invalid magic/count "
                       "(magic=0x%08x count=%u)", magic, count);
    }
    size_t expected = payload_off + 8 +
                      (size_t)count * sizeof(struct block_index_flat);
    if (file_size < expected) {
        flat_header_mapping_close(&mapping, fd);
        return ZCL_ERR(-109, "block_index_flat_header_at: truncated "
                       "(%zu < %zu bytes for %u entries)",
                       file_size, expected, count);
    }
    const struct block_index_flat *entries =
        (const struct block_index_flat *)(data + payload_off + 8);
    uint32_t lo = 0, hi = count;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (entries[mid].height < height) lo = mid + 1;
        else hi = mid;
    }
    if (lo >= count || entries[lo].height != height) {
        int32_t max_height = entries[count - 1].height;
        flat_header_mapping_close(&mapping, fd);
        return ZCL_ERR(-110, "block_index_flat_header_at: no row at height "
                       "%d (flat tip %d)", height, max_height);
    }
    memcpy(out_hash, entries[lo].hash, 32);
    memcpy(out_root, entries[lo].sapling_root, 32);
    flat_header_mapping_close(&mapping, fd);
    return ZCL_OK;
}
