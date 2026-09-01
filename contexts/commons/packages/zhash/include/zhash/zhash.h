/* zhash — classic non-cryptographic hashes, exact and bounded
 *
 * Apache-2.0 licensed. C23, freestanding-friendly, no allocation.
 *
 * Implementations with fixed, published known-answer values:
 *   - FNV-1a 32/64 (Fowler-Noll-Vo)
 *   - CRC32 (IEEE 802.3, polynomial 0xEDB88320, reflected)
 *   - DJB2 and SDBM string hashes
 *   - splitmix64 finalizer for mixing/sequencing
 *
 * These are NOT cryptographic. Do not use them for integrity against
 * adversaries, signatures, or key derivation.
 */
#ifndef ZHASH_H
#define ZHASH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* FNV-1a. NULL data with n == 0 hashes as empty; NULL with n > 0
 * returns the offset basis unchanged (no deref). */
uint32_t zhash_fnv1a32(const void *data, size_t n);
uint64_t zhash_fnv1a64(const void *data, size_t n);

/* Streaming FNV-1a: pass the previous return as h. */
uint32_t zhash_fnv1a32_update(uint32_t h, const void *data, size_t n);
uint64_t zhash_fnv1a64_update(uint64_t h, const void *data, size_t n);

/* CRC32 (IEEE). One-shot, or stream by passing the previous return
 * as crc. Initial call uses crc = 0. */
uint32_t zhash_crc32(const void *data, size_t n);
uint32_t zhash_crc32_update(uint32_t crc, const void *data, size_t n);

/* String hashes over n bytes (embedded NULs are data, not terminators). */
uint32_t zhash_djb2(const void *data, size_t n);
uint32_t zhash_sdbm(const void *data, size_t n);

/* splitmix64 finalizer: bijective 64->64 bit mixer. */
uint64_t zhash_splitmix64(uint64_t x);

/* Combine two hash values (order-sensitive). */
uint64_t zhash_combine64(uint64_t a, uint64_t b);

#ifdef __cplusplus
}
#endif

#endif /* ZHASH_H */
