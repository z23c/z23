/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: planted-violation and coverage selftest for the
 * gate_byte_order_codec_single.c / gate_byte_order_codec_single_report.c
 * family (check-byte-order-codec-single). Split into its own file so the
 * gate bodies stay under the family line-count ceiling; the three files
 * share their internals through gate_byte_order_codec_single_priv.h.
 *
 * Two kinds of case, exactly mirroring the shell original's --selftest:
 *
 *  - shape cases: plant one fresh helper of each detected shape (shift
 *    loop store/load, reversed-operand loop, unrolled store/load,
 *    hand-rolled bswap) in a scratch sandbox and require FAIL; plant
 *    three innocent shapes (bare top-byte shift, a plain indexed loop, a
 *    canonical-codec caller) and require PASS. Only the exit code is
 *    checked (the shell original discards all --selftest sub-run output
 *    too — see run_sandbox()'s ">/dev/null 2>&1").
 *  - coverage cases: re-evaluate the REAL tree with three different
 *    coverage inputs and require the three different verdicts the
 *    coverage check must produce: a complete scan clears (0), a scan
 *    missing a whole declared root is UNPROVEN (2), and a stale
 *    allowance above the true shortfall is a VIOLATION (1).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_byte_order_codec_single_priv.h"

/* Every fixture below is a byte-for-byte copy of the shell original's
 * planted violation shapes. Each one is split mid-token across an
 * adjacent string-literal LINE break (the compiler concatenates the
 * pieces back to the exact original text, so the fixture this gate
 * writes into its sandbox is unchanged) so this selftest's own source
 * text never carries a complete match for the very shapes it plants —
 * otherwise a real `make lint` scan of tools/ would flag this file. */
static const char k_bo_st_shift_store[] =
    "static void my_put_le64(uint8_t *p, uint64_t v)\n"
    "{\n"
    "    for (int i = 0; i < 8; i++)\n"
    "        p[i] = (uint8_t)(v >> (8"
    " * i));\n"
    "}\n";
static const char k_bo_st_shift_load[] =
    "static uint64_t my_get_le64(const uint8_t *p)\n"
    "{\n"
    "    uint64_t v = 0;\n"
    "    for (size_t i = 0; i < 8; i++)\n"
    "        v |= (uint64_t)p[i] << (8u"
    " * i);\n"
    "    return v;\n"
    "}\n";
static const char k_bo_st_reversed[] =
    "static void my_put(uint8_t *p, uint32_t v)\n"
    "{\n"
    "    for (int i = 0; i < 4; i++)\n"
    "        p[i] = (uint8_t)(v >> (i"
    " * 8));\n"
    "}\n";
static const char k_bo_st_unrolled_store[] =
    "static void my_put_le32(uint8_t *p, uint32_t v)\n"
    "{\n"
    "    p[0] = (uint8_t)v;\n"
    "    p[1] = (uint8_t)(v >> 8);\n"
    "    p[2] = (uint8_t)(v >> 16);\n"
    "    p[3"
    "] = (uint8_t)(v >> 24);\n"
    "}\n";
static const char k_bo_st_unrolled_load[] =
    "static uint32_t my_get_le32(const uint8_t *p)\n"
    "{\n"
    "    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |\n"
    "           ((uint32_t)p[2] << 16) | ((uint32_t)p[3"
    "] << 24);\n"
    "}\n";
static const char k_bo_st_bswap[] =
    "static uint32_t my_bswap32(uint32_t x)\n"
    "{\n"
    "    return ((x >> 24) & 0xFFu) | ((x >> 8) & 0x0000FF00u) |\n"
    "           ((x << 8) & 0x00FF00"
    "FF) | ((x << 24) & 0xFF000000u);\n"
    "}\n";
static const char k_bo_st_bare_shift[] =
    "static uint32_t high_octet(uint32_t v)\n"
    "{\n"
    "    return (v >> 24) & 0xFFu;\n"
    "}\n";
static const char k_bo_st_plain_loop[] =
    "static uint32_t checksum(const uint8_t *p, size_t n)\n"
    "{\n"
    "    uint32_t acc = 0;\n"
    "    for (size_t i = 0; i < n; i++)\n"
    "        acc += p[i];\n"
    "    return acc;\n"
    "}\n";
static const char k_bo_st_canonical[] =
    "#include \"base/serialize_le.h\"\n"
    "static void emit(uint8_t *p, uint64_t height)\n"
    "{\n"
    "    zcl_write_u64_le(p, height);\n"
    "}\n";

static int bo_st_run(const char *root, const char *baseline, int floor,
                     int *rc_out)
{
    struct bo_eval_opts opts = {0};
    if (ovf(snprintf(opts.roots[0], RS_PATH, "%s", root), RS_PATH))
        return 2;
    opts.nroots = 1;
    opts.baseline = baseline;
    opts.mode = "FAIL";
    opts.floor = floor;
    opts.coverage = 0;
    opts.coverage_allowance = 0;
    FILE *out = tmpfile();
    if (!out)
        return die("z23-lint: tmpfile failed\n", "");
    *rc_out = bo_eval(&opts, out, out);
    fclose(out);
    return 0;
}

static int bo_st_expect(const char *engine_root, const char *baseline,
                        int want_fail, const char *body)
{
    char fixture[4096];
    if (ovf(snprintf(fixture, sizeof fixture,
                     "%s/services/src/selftest_le.c", engine_root),
            sizeof fixture))
        return 1;
    if (csr_write(fixture, body))
        return 1;
    int rc = 0;
    if (bo_st_run(engine_root, baseline, 1, &rc))
        return 1;
    int got_fail = rc != 0;
    return (got_fail != want_fail) ? 1 : 0;
}

static int bo_st_shapes(const char *tmp)
{
    char engine_root[4096], baseline[4096];
    if (ovf(snprintf(engine_root, sizeof engine_root, "%s/engine", tmp),
            sizeof engine_root)
        || ovf(snprintf(baseline, sizeof baseline, "%s/empty_baseline.txt",
                        tmp),
               sizeof baseline))
        return 1;
    if (csr_write(baseline, ""))
        return 1;
    int bad = 0;
    bad |= bo_st_expect(engine_root, baseline, 1, k_bo_st_shift_store);
    bad |= bo_st_expect(engine_root, baseline, 1, k_bo_st_shift_load);
    bad |= bo_st_expect(engine_root, baseline, 1, k_bo_st_reversed);
    bad |= bo_st_expect(engine_root, baseline, 1, k_bo_st_unrolled_store);
    bad |= bo_st_expect(engine_root, baseline, 1, k_bo_st_unrolled_load);
    bad |= bo_st_expect(engine_root, baseline, 1, k_bo_st_bswap);
    bad |= bo_st_expect(engine_root, baseline, 0, k_bo_st_bare_shift);
    bad |= bo_st_expect(engine_root, baseline, 0, k_bo_st_plain_loop);
    bad |= bo_st_expect(engine_root, baseline, 0, k_bo_st_canonical);
    return bad;
}

/* Coverage cases run against the REAL tree (no fixture): (a) the complete
 * default scan clears its own expectation; (b) a scan missing a whole
 * declared root (drop the trailing "tools" root bo_default_roots always
 * appends last) is UNPROVEN, never a pass or a violation; (c) an
 * allowance held above the true (zero) shortfall is a stale-ratchet
 * VIOLATION. */
static int bo_st_cov_case(int want_rc, char roots[][RS_PATH], int nroots,
                          int allowance, int floor)
{
    struct bo_eval_opts opts = {0};
    memcpy(opts.roots, roots, (size_t)nroots * RS_PATH);
    opts.nroots = nroots;
    opts.baseline = "tools/lint/byte_order_codec_baseline.txt";
    opts.mode = "FAIL";
    opts.floor = floor;
    opts.coverage = 1;
    opts.coverage_allowance = allowance;
    FILE *out = tmpfile();
    if (!out)
        return die("z23-lint: tmpfile failed\n", "");
    int rc = bo_eval(&opts, out, out);
    fclose(out);
    return rc != want_rc;
}

static int bo_st_coverage(void)
{
    static char roots[256][RS_PATH];
    int nroots = 0;
    if (bo_default_roots(roots, 256, &nroots))
        return 1;
    int bad = bo_st_cov_case(0, roots, nroots, 0, 800);
    if (nroots > 0)
        bad |= bo_st_cov_case(2, roots, nroots - 1, 0, 1);
    bad |= bo_st_cov_case(1, roots, nroots, 1, 800);
    return bad;
}

/* Scratch base: TMPDIR if the environment sets one (the runtime's
 * existing seam), else a scratch dir under HOME — never /tmp by default. */
static int bo_st_scratch_base(char *buf, size_t cap)
{
    const char *home = getenv("HOME");
    if (!home || !home[0])
        home = ".";
    char def[4096];
    if (ovf(snprintf(def, sizeof def, "%s/.local/state/zclassic23/scratch",
                     home),
            sizeof def))
        return 2;
    return ovf(snprintf(buf, cap, "%s", env_or("TMPDIR", def)), cap);
}

int check_byte_order_codec_single_selftest(void)
{
    char td[4096];
    if (bo_st_scratch_base(td, sizeof td))
        return 2;
    if (csr_mkdirs(td))
        return 2;
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-bo.XXXXXX", td),
            sizeof tmpl))
        return 2;
    char *tmp = mkdtemp(tmpl);
    if (!tmp)
        return die("z23-lint: mkdir failed: %s\n", td);
    int bad = bo_st_shapes(tmp);
    (void)rap_rm_rf(tmp);
    bad |= bo_st_coverage();
    return st_ok(bad, "check_byte_order_codec_single selftest: OK\n");
}
