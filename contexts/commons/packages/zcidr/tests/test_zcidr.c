/* zcidr tests: parse KATs, rejection table, format round-trips,
 * containment tables, and a randomised masked-compare oracle.
 * Built with -std=c23 -Wall -Wextra -Werror -pedantic, ASan/UBSan. */

#include "zcidr/zcidr.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond)                                                     \
  do {                                                                  \
    if (!(cond)) {                                                      \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
      failures++;                                                       \
    }                                                                   \
  } while (0)

static void expect_v4(const char *s, unsigned a, unsigned b, unsigned c,
                      unsigned d) {
  zcidr_v4 v;
  CHECK(zcidr_parse_v4(s, strlen(s), &v));
  CHECK(v.b[0] == a && v.b[1] == b && v.b[2] == c && v.b[3] == d);
}

static void expect_parse_bad(const char *s) {
  zcidr c;
  CHECK(!zcidr_parse(s, strlen(s), &c));
  if (zcidr_parse(s, strlen(s), &c))
    fprintf(stderr, "  unexpectedly parsed: %s\n", s);
}

/* parse, reformat, compare to canonical spelling */
static void expect_format(const char *in, const char *want) {
  zcidr c;
  char buf[64];
  CHECK(zcidr_parse(in, strlen(in), &c));
  zcidr_format(&c, buf, sizeof buf);
  CHECK(strcmp(buf, want) == 0);
  if (strcmp(buf, want) != 0)
    fprintf(stderr, "  in=%s want=%s got=%s\n", in, want, buf);
}

static void expect_contains(const char *net, const char *addr, int want) {
  zcidr n, a;
  CHECK(zcidr_parse(net, strlen(net), &n));
  CHECK(zcidr_parse(addr, strlen(addr), &a));
  CHECK(zcidr_contains(&n, &a) == want);
  if (zcidr_contains(&n, &a) != want)
    fprintf(stderr, "  net=%s addr=%s want=%d\n", net, addr, want);
}

static void test_v4_kats(void) {
  expect_v4("0.0.0.0", 0, 0, 0, 0);
  expect_v4("255.255.255.255", 255, 255, 255, 255);
  expect_v4("127.0.0.1", 127, 0, 0, 1);
  expect_v4("192.168.1.77", 192, 168, 1, 77);
  expect_v4("8.8.8.8", 8, 8, 8, 8);
}

static void test_v4_bad(void) {
  expect_parse_bad("1.2.3");
  expect_parse_bad("1.2.3.4.5");
  expect_parse_bad("256.0.0.1");
  expect_parse_bad("01.2.3.4"); /* leading zero */
  expect_parse_bad("1.2.3.04");
  expect_parse_bad("1.2.3.");
  expect_parse_bad(".1.2.3");
  expect_parse_bad("1..2.3");
  expect_parse_bad("1.2.3.a");
  expect_parse_bad("0x7f.0.0.1");
  expect_parse_bad("1.2.3.4 ");
  expect_parse_bad(" 1.2.3.4");
  expect_parse_bad("1.2.3.4/");
  expect_parse_bad("1.2.3.4/33");
  expect_parse_bad("1.2.3.4/-1");
  expect_parse_bad("1.2.3.4/032");
  expect_parse_bad("1.2.3.4/1x");
  expect_parse_bad("1.2.3.4/1/2");
  expect_parse_bad("");
}

static void test_v6_kats(void) {
  expect_format("::1", "::1");
  expect_format("::", "::");
  expect_format("1::", "1::");
  expect_format("1::2", "1::2");
  expect_format("2001:0db8:0000:0000:0000:ff00:0042:8329",
                "2001:db8::ff00:42:8329");
  expect_format("2001:DB8::FF00:42:8329", "2001:db8::ff00:42:8329");
  expect_format("fe80:0:0:0:0:0:0:1", "fe80::1");
  /* left-most longest zero run wins */
  expect_format("0:0:1:0:0:0:2:3", "0:0:1::2:3");
  /* a lone zero group is not compressed */
  expect_format("1:0:2:3:4:5:6:7", "1:0:2:3:4:5:6:7");
  /* IPv4 tail */
  expect_format("::ffff:1.2.3.4", "::ffff:102:304");
  expect_format("::ffff:192.168.0.1/96", "::ffff:c0a8:1/96");
  expect_format("2001:db8::/32", "2001:db8::/32");
  expect_format("10.0.0.0/8", "10.0.0.0/8");
  expect_format("192.168.1.77/24", "192.168.1.77/24");
}

static void test_v6_bad(void) {
  expect_parse_bad("1:2:3:4:5:6:7");   /* too few groups */
  expect_parse_bad("1:2:3:4:5:6:7:8:9");
  expect_parse_bad("1::2::3");         /* two compressions */
  expect_parse_bad("::gg");
  expect_parse_bad("12345::");         /* group too wide */
  expect_parse_bad("1:2:3:4:5:6:7:8:");/* trailing colon */
  expect_parse_bad(":1:2:3:4:5:6:7");  /* leading single colon */
  expect_parse_bad("fe80::1%eth0");    /* zone ids rejected */
  expect_parse_bad("::ffff:1.2.3");    /* truncated v4 tail */
  expect_parse_bad("::ffff:1.2.3.256");
  expect_parse_bad("::1/129");
  expect_parse_bad("::1/-1");
  expect_parse_bad("/64");
  expect_parse_bad("::1//64");
}

static void test_contains(void) {
  expect_contains("10.0.0.0/8", "10.255.255.255", 1);
  expect_contains("10.0.0.0/8", "11.0.0.0", 0);
  expect_contains("192.168.1.77/24", "192.168.1.0", 1);
  expect_contains("192.168.1.77/24", "192.168.2.1", 0);
  expect_contains("0.0.0.0/0", "255.255.255.255", 1);
  expect_contains("1.2.3.4/32", "1.2.3.4", 1);
  expect_contains("1.2.3.4/32", "1.2.3.5", 0);
  expect_contains("192.168.0.0/17", "192.168.127.255", 1);
  expect_contains("192.168.0.0/17", "192.168.128.0", 0);
  /* v6 */
  expect_contains("2001:db8::/32", "2001:db8:ffff::1", 1);
  expect_contains("2001:db8::/32", "2001:db9::1", 0);
  expect_contains("::1/128", "::1", 1);
  expect_contains("::1/128", "::2", 0);
  expect_contains("::/0", "ffff::1", 1);
  /* odd prefix lengths */
  expect_contains("10.0.0.0/9", "10.127.255.255", 1);
  expect_contains("10.0.0.0/9", "10.128.0.0", 0);
  /* family mismatch */
  expect_contains("10.0.0.0/8", "::ffff:10.1.2.3", 0);
  expect_contains("::/0", "10.0.0.1", 0);
  /* bare address contains only itself */
  expect_contains("1.2.3.4", "1.2.3.4", 1);
  expect_contains("1.2.3.4", "1.2.3.5", 0);
}

static void test_cmp_and_network(void) {
  zcidr a, b;
  CHECK(zcidr_parse("10.0.0.1", 8, &a));
  CHECK(zcidr_parse("10.0.0.2", 8, &b));
  CHECK(zcidr_cmp(&a, &b) < 0);
  CHECK(zcidr_cmp(&b, &a) > 0);
  CHECK(zcidr_cmp(&a, &a) == 0);
  CHECK(zcidr_parse("255.255.255.255", 15, &b));
  CHECK(zcidr_parse("::", 2, &a));
  CHECK(zcidr_cmp(&b, &a) < 0); /* all v4 before all v6 */
  /* network masking */
  CHECK(zcidr_parse("192.168.1.77/24", 15, &a));
  zcidr_network(&a);
  {
    char buf[64];
    zcidr_format(&a, buf, sizeof buf);
    CHECK(strcmp(buf, "192.168.1.0/24") == 0);
  }
  {
    const char *s = "2001:db8:abcd:1234::1/33";
    CHECK(zcidr_parse(s, strlen(s), &a));
  }
  zcidr_network(&a);
  {
    char buf[64];
    zcidr_format(&a, buf, sizeof buf);
    CHECK(strcmp(buf, "2001:db8:8000::/33") == 0);
  }
}

/* randomised masked-compare oracle: containment must agree with a
 * bit-by-bit reference implementation */
static void test_fuzz_contains(void) {
  unsigned long long rng = 0xDEADBEEFCAFEBABEull;
  int t;
  for (t = 0; t < 20000; t++) {
    uint8_t net[4], addr[4];
    unsigned prefix;
    int i;
    int want = 1;
    zcidr n, a;
    rng = rng * 6364136223846793005ull + 1442695040888963407ull;
    for (i = 0; i < 4; i++) net[i] = (uint8_t)(rng >> (i * 8));
    rng = rng * 6364136223846793005ull + 1442695040888963407ull;
    for (i = 0; i < 4; i++) addr[i] = (uint8_t)(rng >> (i * 8));
    rng = rng * 6364136223846793005ull + 1442695040888963407ull;
    prefix = (unsigned)((rng >> 16) % 33);
    /* half the time share the prefix bits so hits are common */
    if (t & 1) {
      for (i = 0; i < 4; i++) addr[i] = net[i];
      if (prefix < 32) {
        unsigned byte = prefix / 8;
        unsigned bit = 7 - (prefix % 8);
        addr[byte] ^= (uint8_t)(1u << bit);
      }
    }
    memset(&n, 0, sizeof n);
    memset(&a, 0, sizeof a);
    memcpy(n.v4.b, net, 4);
    memcpy(a.v4.b, addr, 4);
    n.has_prefix = 1;
    n.prefix = prefix;
    /* reference */
    for (i = 0; i < (int)prefix; i++) {
      unsigned byte = (unsigned)i / 8;
      unsigned bit = 7 - ((unsigned)i % 8);
      if (((net[byte] >> bit) & 1) != ((addr[byte] >> bit) & 1)) {
        want = 0;
        break;
      }
    }
    CHECK(zcidr_contains(&n, &a) == want);
  }
}

/* randomised v6 format/parse round trip */
static void test_fuzz_v6_roundtrip(void) {
  unsigned long long rng = 0x123456789ABCDEFull;
  int t;
  for (t = 0; t < 20000; t++) {
    zcidr_v6 v6, back;
    char buf[64];
    int i;
    for (i = 0; i < 16; i++) {
      rng = rng * 6364136223846793005ull + 1442695040888963407ull;
      /* bias toward zeros so compression paths fire */
      v6.b[i] = (rng % 3 == 0) ? 0 : (uint8_t)(rng >> 16);
    }
    zcidr_format_v6(&v6, buf, sizeof buf);
    CHECK(zcidr_parse_v6(buf, strlen(buf), &back));
    CHECK(memcmp(v6.b, back.b, 16) == 0);
    /* formatting is a fixed point */
    {
      char buf2[64];
      zcidr_format_v6(&back, buf2, sizeof buf2);
      CHECK(strcmp(buf, buf2) == 0);
    }
  }
}

static void test_null_args(void) {
  zcidr c;
  zcidr_v4 v4;
  char buf[64];
  CHECK(!zcidr_parse(NULL, 5, &c));
  CHECK(!zcidr_parse("1.2.3.4", 7, NULL));
  CHECK(!zcidr_parse_v4(NULL, 1, &v4));
  CHECK(!zcidr_parse_v6("::1", 3, NULL));
  CHECK(!zcidr_contains(NULL, &c));
  CHECK(zcidr_format(NULL, buf, sizeof buf) == 0);
  CHECK(buf[0] == '\0');
  CHECK(zcidr_format_v6(NULL, buf, sizeof buf) == 0);
  /* zero capacity is legal for measurement */
  CHECK(zcidr_parse("192.168.1.77/24", 15, &c));
  CHECK(zcidr_format(&c, NULL, 0) == strlen("192.168.1.77/24"));
}

int main(void) {
  test_v4_kats();
  test_v4_bad();
  test_v6_kats();
  test_v6_bad();
  test_contains();
  test_cmp_and_network();
  test_fuzz_contains();
  test_fuzz_v6_roundtrip();
  test_null_args();
  if (failures) {
    fprintf(stderr, "%d failure(s)\n", failures);
    return 1;
  }
  puts("zcidr: all tests passed");
  return 0;
}
