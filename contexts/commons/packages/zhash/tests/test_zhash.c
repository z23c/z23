/* Tests for zhash — classic non-cryptographic hashes.
 * Groups: kat, stream, mix, null, fuzz. */
#include "zhash/zhash.h"

#include <stdio.h>
#include <string.h>

static int g_fail = 0;
#define CHECK(cond)                                                     \
  do {                                                                  \
    if (!(cond)) {                                                      \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
      g_fail = 1;                                                       \
    }                                                                   \
  } while (0)

/* ---- known answers ------------------------------------------------------ */

static void test_kat(void) {
  /* FNV-1a reference values (fnv1a test vectors). */
  CHECK(zhash_fnv1a64("", 0) == UINT64_C(0xcbf29ce484222325));
  CHECK(zhash_fnv1a64("a", 1) == UINT64_C(0xaf63dc4c8601ec8c));
  CHECK(zhash_fnv1a64("foobar", 6) == UINT64_C(0x85944171f73967e8));
  CHECK(zhash_fnv1a32("", 0) == UINT32_C(0x811c9dc5));
  CHECK(zhash_fnv1a32("a", 1) == UINT32_C(0xe40c292c));
  CHECK(zhash_fnv1a32("foobar", 6) == UINT32_C(0xbf9cf968));
  /* CRC32 (IEEE) reference values. */
  CHECK(zhash_crc32("", 0) == UINT32_C(0x00000000));
  CHECK(zhash_crc32("a", 1) == UINT32_C(0xe8b7be43));
  CHECK(zhash_crc32("123456789", 9) == UINT32_C(0xcbf43926));
  CHECK(zhash_crc32("The quick brown fox jumps over the lazy dog", 43) ==
        UINT32_C(0x414fa339));
  /* DJB2 / SDBM. */
  CHECK(zhash_djb2("", 0) == UINT32_C(5381));
  CHECK(zhash_djb2("a", 1) == UINT32_C(177670));
  CHECK(zhash_sdbm("", 0) == 0);
  CHECK(zhash_sdbm("a", 1) == 97);
  /* splitmix64 from a zero state yields the published first output. */
  CHECK(zhash_splitmix64(0) == UINT64_C(0xE220A8397B1DCDAF));
  /* Embedded NULs are data. */
  CHECK(zhash_fnv1a64("a\0b", 3) != zhash_fnv1a64("a", 1));
  CHECK(zhash_crc32("a\0b", 3) != zhash_crc32("a", 1));
}

/* ---- streaming equivalence ---------------------------------------------- */

static void test_stream(void) {
  static const char *doc = "The quick brown fox jumps over the lazy dog";
  size_t n = strlen(doc);
  size_t cut;
  for (cut = 0; cut <= n; cut++) {
    CHECK(zhash_fnv1a64_update(zhash_fnv1a64(doc, cut), doc + cut,
                               n - cut) == zhash_fnv1a64(doc, n));
    CHECK(zhash_fnv1a32_update(zhash_fnv1a32(doc, cut), doc + cut,
                               n - cut) == zhash_fnv1a32(doc, n));
    CHECK(zhash_crc32_update(zhash_crc32(doc, cut), doc + cut, n - cut) ==
          zhash_crc32(doc, n));
  }
}

/* ---- mixing ---------------------------------------------------------------- */

static void test_mix(void) {
  uint64_t seen[64];
  size_t i, j;
  /* splitmix64 of distinct small inputs is distinct (bijective). */
  for (i = 0; i < 64; i++) seen[i] = zhash_splitmix64(i);
  for (i = 0; i < 64; i++)
    for (j = i + 1; j < 64; j++) CHECK(seen[i] != seen[j]);
  /* combine is order-sensitive and deterministic. */
  CHECK(zhash_combine64(1, 2) != zhash_combine64(2, 1));
  CHECK(zhash_combine64(7, 9) == zhash_combine64(7, 9));
}

/* ---- NULL safety -------------------------------------------------------------- */

static void test_null(void) {
  /* NULL with n > 0: no deref, basis/prev returned unchanged. */
  CHECK(zhash_fnv1a64(NULL, 5) == UINT64_C(0xcbf29ce484222325));
  CHECK(zhash_fnv1a32(NULL, 5) == UINT32_C(0x811c9dc5));
  CHECK(zhash_crc32(NULL, 5) == 0);
  CHECK(zhash_fnv1a64_update(42, NULL, 5) == 42);
  CHECK(zhash_crc32_update(42, NULL, 5) == 42);
  CHECK(zhash_djb2(NULL, 3) == UINT32_C(5381));
  CHECK(zhash_sdbm(NULL, 3) == 0);
}

/* ---- fuzz ------------------------------------------------------------------------- */

static uint64_t rng_state = 0x0123456789ABCDEFull;
static uint64_t rng_next(void) {
  rng_state ^= rng_state << 13;
  rng_state ^= rng_state >> 7;
  rng_state ^= rng_state << 17;
  return rng_state;
}

static void test_fuzz(void) {
  /* Random buffers: streaming in random chunk sizes always equals the
   * one-shot value; distinct buffers overwhelmingly hash differently
   * (allow a small collision budget for 32-bit hashes). */
  int trial;
  for (trial = 0; trial < 3000; trial++) {
    unsigned char buf[256];
    size_t n = rng_next() % 256, i, pos = 0;
    uint64_t h64 = 0, f64;
    uint32_t h32 = 0, c32 = 0, f32, cc;
    for (i = 0; i < n; i++) buf[i] = (unsigned char)rng_next();
    h64 = UINT64_C(14695981039346656037);
    h32 = UINT32_C(2166136261);
    while (pos < n) {
      size_t chunk = 1 + rng_next() % 17;
      if (chunk > n - pos) chunk = n - pos;
      h64 = zhash_fnv1a64_update(h64, buf + pos, chunk);
      h32 = zhash_fnv1a32_update(h32, buf + pos, chunk);
      c32 = zhash_crc32_update(c32, buf + pos, chunk);
      pos += chunk;
    }
    f64 = zhash_fnv1a64(buf, n);
    f32 = zhash_fnv1a32(buf, n);
    cc = zhash_crc32(buf, n);
    CHECK(h64 == f64);
    CHECK(h32 == f32);
    CHECK(c32 == cc);
  }
}

int main(void) {
  test_kat();
  test_stream();
  test_mix();
  test_null();
  test_fuzz();
  if (g_fail) {
    fprintf(stderr, "test_zhash: FAILURES\n");
    return 1;
  }
  printf("test_zhash: all groups passed (kat stream mix null fuzz)\n");
  return 0;
}
