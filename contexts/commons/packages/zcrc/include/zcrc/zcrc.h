/*
 * zcrc — CRC-32 (ISO-HDLC, reflected, poly 0xEDB88320) and CRC-32C
 * (Castagnoli, reflected, poly 0x82F63B78), table-driven, in
 * freestanding C23.
 *
 * Both use the standard init 0xFFFFFFFF / final xor 0xFFFFFFFF.
 * Well-known check values for the ASCII string "123456789":
 *   CRC-32  = 0xCBF43926
 *   CRC-32C = 0xE3069283
 *
 * Usage is streaming: seed with zcrc32_init(), fold any number of
 * byte spans with update(), read with final().  Or use the one-shot
 * zcrc32(data, len) / zcrc32c(data, len).
 *
 * The 256-entry tables are generated once, lazily, guarded by C23
 * atomics, so the library is thread-safe without constructors and
 * carries no generated table data in source.
 */
#ifndef ZCRC_H
#define ZCRC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t zcrc32_init(void);
uint32_t zcrc32c_init(void);

/* Fold len bytes into a running crc state.  NULL data with len > 0
 * leaves the state unchanged (returns it). */
uint32_t zcrc32_update(uint32_t state, const void *data, size_t len);
uint32_t zcrc32c_update(uint32_t state, const void *data, size_t len);

uint32_t zcrc32_final(uint32_t state);
uint32_t zcrc32c_final(uint32_t state);

/* One-shot helpers (NULL data with len > 0 returns the empty crc). */
uint32_t zcrc32(const void *data, size_t len);
uint32_t zcrc32c(const void *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* ZCRC_H */
