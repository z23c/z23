/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest of check-ci-symbol-floor. Builds in-memory ELF64
 * little-endian images whose one verneed table requires a chosen set of
 * version names, then proves the parser classifies them: a floor-level
 * GLIBC passes, one above the floor is seen as above it, a C++ ABI family is
 * seen, GLIBC_PRIVATE names no version, and garbage or a truncated table is
 * refused. The dotted compare is checked on the cases sort -V gets right.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdint.h>
#include <string.h>
#include "base/serialize_le.h"
#include "lintc.h"
#include "gate_ci_symbol_floor_priv.h"

enum { CST_IMG = 1024, CST_MAXN = 8, CST_VN = 512, CST_DS = 256 };

/* Store an n-byte little-endian field (n = 2, 4 or 8) at off. */
static void cst_put(unsigned char *b, size_t off, uint64_t v, unsigned n)
{
    if (n == 2)
        zcl_write_u16_le(b + off, (uint16_t)v);
    else if (n == 4)
        zcl_write_u32_le(b + off, (uint32_t)v);
    else
        zcl_write_u64_le(b + off, v);
}

/* Lay out: ELF header, three section headers (null, verneed, dynstr), the
 * dynstr at CST_DS, and one verneed entry with nn auxiliary names at CST_VN.
 * Returns the image size. */
static size_t cst_image(unsigned char *b, const char *const *names, int nn)
{
    size_t offs[CST_MAXN], dl = 1;
    memset(b, 0, CST_IMG);
    b[0] = 0x7f;
    b[1] = 'E';
    b[2] = 'L';
    b[3] = 'F';
    b[4] = 2;
    b[5] = 1;
    b[6] = 1;
    cst_put(b, 0x28, 64, 8);
    cst_put(b, 0x3A, 64, 2);
    cst_put(b, 0x3C, 3, 2);
    for (int i = 0; i < nn; i++) {
        size_t l = strlen(names[i]);
        memcpy(b + CST_DS + dl, names[i], l + 1);
        offs[i] = dl;
        dl += l + 1;
    }
    size_t vl = 16 + 16 * (size_t)nn;
    cst_put(b, CST_VN + 2, (uint64_t)nn, 2);
    cst_put(b, CST_VN + 8, 16, 4);
    for (int i = 0; i < nn; i++) {
        size_t a = CST_VN + 16 + 16 * (size_t)i;
        cst_put(b, a + 8, offs[i], 4);
        cst_put(b, a + 12, i + 1 < nn ? 16 : 0, 4);
    }
    cst_put(b, 64 + 64 + 4, 0x6ffffffe, 4);
    cst_put(b, 64 + 64 + 24, CST_VN, 8);
    cst_put(b, 64 + 64 + 32, vl, 8);
    cst_put(b, 64 + 64 + 40, 2, 4);
    cst_put(b, 64 + 128 + 4, 3, 4);
    cst_put(b, 64 + 128 + 24, CST_DS, 8);
    cst_put(b, 64 + 128 + 32, dl, 8);
    return CST_VN + vl;
}

/* Parse an image of the given size. Returns the scan verdict (0 ok). */
static int cst_scan(const unsigned char *b, size_t n, struct csf_floor *fl)
{
    struct csf_src s;
    s.f = NULL;
    s.mem = b;
    s.size = (uint64_t)n;
    return csf_scan(&s, fl);
}

/* Build an image requiring names[] and scan it. */
static int cst_names(const char *const *names, int nn, struct csf_floor *fl)
{
    static unsigned char img[CST_IMG];
    size_t n = cst_image(img, names, nn);
    return cst_scan(img, n, fl);
}

static int cst_floor_selftest(void)
{
    struct csf_floor fl;
    const char *const at_floor[] = { "GLIBC_2.2.5", "GLIBC_2.38" };
    const char *const over[] = { "GLIBC_2.38", "GLIBC_2.39" };
    const char *const cxx[] = { "GLIBC_2.38", "GLIBCXX_3.4.30" };
    const char *const abi[] = { "GLIBC_2.38", "CXXABI_1.3" };
    const char *const priv[] = { "GLIBC_PRIVATE" };
    int bad = 0;
    bad |= cst_names(at_floor, 2, &fl) != 0 || !fl.glibc.present
        || strcmp(fl.glibc.max, "2.38") != 0 || fl.glibcxx.present || fl.cxxabi.present;
    bad |= cst_names(over, 2, &fl) != 0 || strcmp(fl.glibc.max, "2.39") != 0;
    bad |= cst_names(cxx, 2, &fl) != 0 || !fl.glibcxx.present
        || strcmp(fl.glibcxx.max, "3.4.30") != 0;
    bad |= cst_names(abi, 2, &fl) != 0 || !fl.cxxabi.present;
    bad |= cst_names(priv, 1, &fl) != 0 || fl.glibc.present;
    return bad;
}

static int cst_vcmp_selftest(void)
{
    int bad = 0;
    bad |= csf_vcmp("2.4", "2.38") >= 0;
    bad |= csf_vcmp("2.2", "2.2.5") >= 0;
    bad |= csf_vcmp("2.38", "2.38") != 0;
    bad |= csf_vcmp("2.38.0", "2.38") != 0;
    bad |= csf_vcmp("2.39", "2.38") <= 0;
    return bad;
}

static int cst_refuse_selftest(void)
{
    static const unsigned char junk[] = "not an elf image at all";
    struct csf_floor fl;
    static unsigned char img[CST_IMG];
    const char *const one[] = { "GLIBC_2.38" };
    size_t n = cst_image(img, one, 1);
    int bad = 0;
    bad |= cst_scan(junk, sizeof junk - 1, &fl) == 0;
    bad |= n <= 200 || cst_scan(img, 200, &fl) == 0;
    return bad;
}

int check_ci_symbol_floor_selftest(void)
{
    int bad = cst_floor_selftest() | cst_vcmp_selftest() | cst_refuse_selftest();
    return st_ok(bad, "check_ci_symbol_floor selftest: OK\n");
}
