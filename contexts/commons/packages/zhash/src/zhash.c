/* zhash — classic non-cryptographic hashes. See include/zhash/zhash.h. */
#include "zhash/zhash.h"

uint32_t zhash_fnv1a32_update(uint32_t h, const void *data, size_t n) {
  const unsigned char *p = data;
  size_t i;
  if (p == NULL) return h;
  for (i = 0; i < n; i++) {
    h ^= p[i];
    h *= UINT32_C(16777619);
  }
  return h;
}

uint64_t zhash_fnv1a64_update(uint64_t h, const void *data, size_t n) {
  const unsigned char *p = data;
  size_t i;
  if (p == NULL) return h;
  for (i = 0; i < n; i++) {
    h ^= p[i];
    h *= UINT64_C(1099511628211);
  }
  return h;
}

uint32_t zhash_fnv1a32(const void *data, size_t n) {
  return zhash_fnv1a32_update(UINT32_C(2166136261), data, n);
}

uint64_t zhash_fnv1a64(const void *data, size_t n) {
  return zhash_fnv1a64_update(UINT64_C(14695981039346656037), data, n);
}

/* Bitwise reflected CRC32, polynomial 0xEDB88320. Eight iterations per
 * byte; simple and table-free. */
uint32_t zhash_crc32_update(uint32_t crc, const void *data, size_t n) {
  const unsigned char *p = data;
  size_t i;
  crc = ~crc;
  if (p != NULL)
    for (i = 0; i < n; i++) {
      int bit;
      crc ^= p[i];
      for (bit = 0; bit < 8; bit++)
        crc = (crc >> 1) ^ (UINT32_C(0xEDB88320) & (UINT32_C(0) - (crc & 1)));
    }
  return ~crc;
}

uint32_t zhash_crc32(const void *data, size_t n) {
  return zhash_crc32_update(0, data, n);
}

uint32_t zhash_djb2(const void *data, size_t n) {
  const unsigned char *p = data;
  uint32_t h = UINT32_C(5381);
  size_t i;
  if (p == NULL) return h;
  for (i = 0; i < n; i++) h = h * 33u + p[i];
  return h;
}

uint32_t zhash_sdbm(const void *data, size_t n) {
  const unsigned char *p = data;
  uint32_t h = 0;
  size_t i;
  if (p == NULL) return h;
  for (i = 0; i < n; i++) h = p[i] + (h << 6) + (h << 16) - h;
  return h;
}

uint64_t zhash_splitmix64(uint64_t x) {
  x += UINT64_C(0x9E3779B97F4A7C15);
  x = (x ^ (x >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
  x = (x ^ (x >> 27)) * UINT64_C(0x94D049BB133111EB);
  return x ^ (x >> 31);
}

uint64_t zhash_combine64(uint64_t a, uint64_t b) {
  /* boost-style combine, then a finalizer for avalanche. */
  a ^= b + UINT64_C(0x9E3779B97F4A7C15) + (a << 6) + (a >> 2);
  return zhash_splitmix64(a);
}
