/* zcrc — CRC-32 and CRC-32C.  See zcrc.h. */

#include "zcrc/zcrc.h"

#include <stdatomic.h>

static uint32_t table32[256];
static uint32_t table32c[256];
static atomic_flag lock32 = ATOMIC_FLAG_INIT;
static atomic_flag lock32c = ATOMIC_FLAG_INIT;
static _Atomic int ready32;
static _Atomic int ready32c;

static void build_table(uint32_t *tab, uint32_t poly) {
  unsigned i, k;
  for (i = 0; i < 256; i++) {
    uint32_t c = i;
    for (k = 0; k < 8; k++) c = (c & 1) ? (c >> 1) ^ poly : (c >> 1);
    tab[i] = c;
  }
}

static void ensure(uint32_t *tab, uint32_t poly, atomic_flag *lock,
                   _Atomic int *ready) {
  if (atomic_load_explicit(ready, memory_order_acquire)) return;
  while (atomic_flag_test_and_set_explicit(lock, memory_order_acquire)) {
    /* spin: table build is 2048 arithmetic steps */
  }
  if (!atomic_load_explicit(ready, memory_order_relaxed)) {
    build_table(tab, poly);
    atomic_store_explicit(ready, 1, memory_order_release);
  }
  atomic_flag_clear_explicit(lock, memory_order_release);
}

uint32_t zcrc32_init(void) {
  ensure(table32, 0xEDB88320u, &lock32, &ready32);
  return 0xFFFFFFFFu;
}

uint32_t zcrc32c_init(void) {
  ensure(table32c, 0x82F63B78u, &lock32c, &ready32c);
  return 0xFFFFFFFFu;
}

static uint32_t update_impl(uint32_t state, const void *data, size_t len,
                            const uint32_t *tab) {
  const unsigned char *p = data;
  size_t i;
  if (!p && len > 0) return state;
  for (i = 0; i < len; i++)
    state = (state >> 8) ^ tab[(state ^ p[i]) & 0xFF];
  return state;
}

uint32_t zcrc32_update(uint32_t state, const void *data, size_t len) {
  ensure(table32, 0xEDB88320u, &lock32, &ready32);
  return update_impl(state, data, len, table32);
}

uint32_t zcrc32c_update(uint32_t state, const void *data, size_t len) {
  ensure(table32c, 0x82F63B78u, &lock32c, &ready32c);
  return update_impl(state, data, len, table32c);
}

uint32_t zcrc32_final(uint32_t state) { return state ^ 0xFFFFFFFFu; }
uint32_t zcrc32c_final(uint32_t state) { return state ^ 0xFFFFFFFFu; }

uint32_t zcrc32(const void *data, size_t len) {
  return zcrc32_final(zcrc32_update(zcrc32_init(), data, len));
}

uint32_t zcrc32c(const void *data, size_t len) {
  return zcrc32c_final(zcrc32c_update(zcrc32c_init(), data, len));
}
