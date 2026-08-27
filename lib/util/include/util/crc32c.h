/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * crc32c — Castagnoli CRC-32C (polynomial 0x1EDC6F41), reflected form,
 * init 0xFFFFFFFF, final xor 0xFFFFFFFF.
 *
 * One implementation for the whole tree. The software table is the
 * reference; hosts with a hardware Castagnoli instruction (SSE4.2 on x86,
 * FEAT_CRC32 on arm64, each runtime-probed through the OS feature report)
 * use it after a startup self-check proves it reproduces reference output
 * byte for byte. A failed self-check falls back to the table and says so on
 * stderr.
 *
 * Two on-disk formats depend on these exact bytes: the append-only event
 * log (storage/event_log.h) and LevelDB's block/record trailers
 * (storage/ldb_reader.h). Neither may ever see a second spelling of this
 * checksum, which is why it lives here instead of inside either reader.
 */
#ifndef ZCL_UTIL_CRC32C_H
#define ZCL_UTIL_CRC32C_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Active implementation (hardware when available and self-checked). */
uint32_t zcl_crc32c(const void *data, size_t len);

/* Reference software table implementation — always available, used by
 * the startup self-check and by tests that must pin the reference. */
uint32_t zcl_crc32c_sw(const void *data, size_t len);

/* True when a hardware Castagnoli tier was selected (i.e. present AND
 * self-checked): the SSE4.2 path on x86, the FEAT_CRC32 path on arm64. */
bool zcl_crc32c_hw_available(void);

/* "hardware-sse4.2" or "hardware-armv8-crc32" when the corresponding
 * self-checked hardware tier is active; else "software-table". */
const char *zcl_crc32c_impl_name(void);

#endif /* ZCL_UTIL_CRC32C_H */
