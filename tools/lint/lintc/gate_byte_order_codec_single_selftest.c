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
                     const struct lint_changed *changed, int *rc_out)
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
    opts.changed = changed;
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
    if (bo_st_run(engine_root, baseline, 1, NULL, &rc))
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
    if (rc != want_rc) {
        fprintf(stderr, "byte-order coverage selftest: expected %d, got %d\n",
                want_rc, rc);
        if (fseek(out, 0, SEEK_SET) == 0) {
            char line[1024];
            while (fgets(line, sizeof line, out))
                fputs(line, stderr);
        }
    }
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

static int bo_st_verdict(const char *root, const char *baseline,
                         const struct lint_changed *ch, int want,
                         const char *label)
{
    int rc = 0;
    if (bo_st_run(root, baseline, 1, ch, &rc) || rc != want) {
        fprintf(stderr, "byte-order %s failed rc=%d want=%d\n", label, rc, want);
        return 1;
    }
    return 0;
}

static int bo_st_baseline_paths(const char *repo)
{
    char *dot_path[] = { "./tools/lint/byte_order_codec_baseline.txt" };
    struct lint_changed dot = { dot_path, 1, 1 };
    if (bo_narrow_ok(&dot, dot_path[0]))
        return 1;
    char absolute[4096];
    if (ovf(snprintf(absolute, sizeof absolute, "%s/tools/lint/byte_order_codec_baseline.txt", repo),
              sizeof absolute))
        return 1;
    char *relative_path[] = { "tools/lint/byte_order_codec_baseline.txt" };
    struct lint_changed relative = { relative_path, 1, 1 };
    return bo_narrow_ok(&relative, absolute);
}

static int bo_st_root_paths(const char *repo)
{
    char *trailing_path[] = { "./engine/entry/main.c" };
    struct lint_changed trailing = { trailing_path, 1, 1 };
    char roots[1][RS_PATH] = { "engine/" };
    struct bo_pathset selected;
    if (bo_collect_changed(roots, 1, &trailing, &selected) != 0 || selected.n != 1)
        return 1;
    char absolute_source[4096], absolute_root[1][RS_PATH];
    if (ovf(snprintf(absolute_source, sizeof absolute_source, "%s/engine/entry/main.c", repo),
              sizeof absolute_source) ||
        ovf(snprintf(absolute_root[0], RS_PATH, "%s/engine", repo), RS_PATH))
        return 1;
    char *absolute_paths[] = { absolute_source };
    struct lint_changed absolute_change = { absolute_paths, 1, 1 };
    if (bo_collect_changed(absolute_root, 1, &absolute_change, &selected) != 0 ||
        selected.n != 1)
        return 1;
    char slash_root[1][RS_PATH] = { "/" };
    if (bo_collect_changed(slash_root, 1, &trailing, &selected) != 0 || selected.n != 1)
        return 1;
    char dot_root[1][RS_PATH] = { "." };
    if (bo_collect_changed(dot_root, 1, &trailing, &selected) != 0 || selected.n != 1)
        return 1;
    char dot_slash_root[1][RS_PATH] = { "./" };
    if (bo_collect_changed(dot_slash_root, 1, &trailing, &selected) != 0 || selected.n != 1)
        return 1;
    char repo_root[1][RS_PATH];
    if (ovf(snprintf(repo_root[0], RS_PATH, "%s", repo), RS_PATH))
        return 1;
    return bo_collect_changed(repo_root, 1, &trailing, &selected) != 0 || selected.n != 1;
}

static int bo_st_outside_path(void)
{
    char *outside_path[] = { "/usr/include/stdio.h" };
    struct lint_changed outside = { outside_path, 1, 1 };
    char dot_root[1][RS_PATH] = { "." };
    struct bo_pathset selected;
    return bo_collect_changed(dot_root, 1, &outside, &selected) != 0 ||
           selected.n != 0;
}

static int bo_st_path_guards(void)
{
    char repo[4096];
    if (cic_repo_root(repo, sizeof repo) != 0)
        return 1;
    return bo_st_baseline_paths(repo) || bo_st_root_paths(repo) ||
           bo_st_outside_path();
}

static int bo_st_selected(const char *root, const char *baseline,
                          const struct lint_changed *one)
{
    if (csr_write(one->path[0], k_bo_st_shift_store) ||
        bo_st_verdict(root, baseline, one, 1, "selected violation") != 0)
        return 1;
    char row[4096];
    if (ovf(snprintf(row, sizeof row, "%s\n", one->path[0]), sizeof row) ||
        csr_write(baseline, row) ||
        bo_st_verdict(root, baseline, one, 0, "selected baseline") != 0)
        return 1;
    return csr_write(one->path[0], k_bo_st_canonical) == 0 &&
           bo_st_verdict(root, baseline, one, 1, "selected stale baseline") == 0 ? 0 : 1;
}

static int bo_st_narrowed(const char *tmp)
{
    char root[4096], baseline[4096], fixture[4096];
    if (ovf(snprintf(root, sizeof root, "%s/engine", tmp), sizeof root) ||
        ovf(snprintf(baseline, sizeof baseline, "%s/narrow-baseline.txt", tmp),
              sizeof baseline) ||
        ovf(snprintf(fixture, sizeof fixture, "%s/services/src/selftest_le.c", root),
              sizeof fixture))
        return 1;
    if (csr_mkdirs(root) || csr_write(baseline, "services/src/other.c\n") ||
        csr_write(fixture, k_bo_st_canonical))
        return 1;
    char *one_path[] = { fixture };
    struct lint_changed one = { one_path, 1, 1 };
    char roots[1][RS_PATH];
    struct bo_pathset selected;
    if (ovf(snprintf(roots[0], RS_PATH, "%s", root), RS_PATH) ||
        bo_collect_changed(roots, 1, &one, &selected) != 0 || selected.n != 1) {
        fputs("byte-order narrowed collector did not select one file\n", stderr);
        return 1;
    }
    if (bo_st_verdict(root, baseline, &one, 0, "narrowed clean case") != 0)
        return 1;
    char *doc_path[] = { "docs/README.md" };
    struct lint_changed docs = { doc_path, 1, 1 };
    if (bo_st_verdict(root, baseline, &docs, 0, "unrelated case") != 0 ||
        bo_st_selected(root, baseline, &one) != 0)
        return 1;
    char *baseline_path[] = { baseline };
    struct lint_changed edit = { baseline_path, 1, 1 };
    struct lint_changed empty = { NULL, 0, 1 };
    if (bo_narrow_ok(&edit, baseline) || !bo_narrow_ok(&empty, baseline))
        return 1;
    return bo_st_path_guards();
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
    bad |= bo_st_narrowed(tmp);
    (void)rap_rm_rf(tmp);
    bad |= bo_st_coverage();
    return st_ok(bad, "check_byte_order_codec_single selftest: OK\n");
}
