/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: planted-violation selftest for
 * gate_hotswap_package_receipt_is_not_authority.c (check-hotswap-package-
 * receipt-is-not-authority). Split into its own file so the gate body
 * stays comfortably under the family line-count ceiling; the two files
 * share the gate's internals through
 * gate_hotswap_package_receipt_is_not_authority_priv.h.
 *
 * The selftest cannot plant its violating TU in the live
 * engine/modules/hotswap/src/ tree — a concurrent `make lint` globs that
 * directory from other gates and a concurrent build globs it for real
 * compilation, so a fixture that exists for the length of one scan is a
 * race. It mirrors the two scanned directories (native file copy, no
 * subprocess) into a scratch sandbox instead, plants the fixture there,
 * and re-runs hpr_run_checks() pointed at the mirror — the packaging-tool
 * leg still checks the REAL tools/dev/hotswap-package.sh, exactly as the
 * shell original's SANDBOX MODE did.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_hotswap_package_receipt_is_not_authority_priv.h"

static const char k_hprst_fixture[] =
    "/* Planted ONLY by check-hotswap-package-receipt-is-not-authority's\n"
    " * --selftest, into a scratch MIRROR of engine/modules/hotswap — never\n"
    " * into the repo. It exercises the manifest-file-read prohibition on\n"
    " * purpose and is deleted before this selftest returns. */\n"
    "#include <stdio.h>\n"
    "\n"
    "static FILE *__selftest_open_package_manifest(const char *so_path) {\n"
    "    (void)so_path;\n"
    "    return fopen(\"build/hotswap/example.manifest\", \"r\");\n"
    "}\n";

/* Scratch base: TMPDIR if the environment sets one (the runtime's existing
 * seam), else a scratch dir under HOME — never /tmp by default. */
static int hprst_scratch_base(char *buf, size_t cap)
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

static int hprst_copy_file(const char *src, const char *dst)
{
    FILE *in = fopen(src, "rb");
    if (!in)
        return die("z23-lint: cannot open %s\n", src);
    FILE *out = fopen(dst, "wb");
    if (!out) {
        fclose(in);
        return die("z23-lint: cannot open %s\n", dst);
    }
    char buf[65536];
    size_t n;
    int rc = 0;
    while ((n = fread(buf, 1, sizeof buf, in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) {
            rc = die("z23-lint: write failed\n", "");
            break;
        }
    }
    if (rc == 0 && ferror(in))
        rc = die("z23-lint: read failed: %s\n", src);
    fclose(in);
    if (fclose(out) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", dst);
    return rc;
}

static int hprst_mirror_one(const char *from, char basefile[][RS_PATH], int n,
                            const char *todir)
{
    for (int i = 0; i < n; i++) {
        const char *slash = strrchr(basefile[i], '/');
        const char *base = slash ? slash + 1 : basefile[i];
        char dst[4096];
        if (ovf(snprintf(dst, sizeof dst, "%s/%s", todir, base), sizeof dst))
            return 2;
        int rc = hprst_copy_file(basefile[i], dst);
        if (rc)
            return rc;
    }
    (void)from;
    return 0;
}

/* Mirror SRC_DIR (*.c, *.h) and INC_DIR (*.h) into sandbox/src and
 * sandbox/include/hotswap. Returns the copied counts so the caller can
 * refuse to prove anything against an empty mirror. */
static int hprst_mirror(const char *sandbox, int *copied_src, int *copied_inc)
{
    char srcdst[4096], incdst[4096];
    if (ovf(snprintf(srcdst, sizeof srcdst, "%s/src", sandbox), sizeof srcdst)
        || ovf(snprintf(incdst, sizeof incdst, "%s/include/hotswap", sandbox),
               sizeof incdst))
        return 2;
    int rc = csr_mkdirs(srcdst);
    if (rc == 0)
        rc = csr_mkdirs(incdst);
    if (rc)
        return rc;
    static char src_c[64][RS_PATH], inc_h[64][RS_PATH];
    int ns = 0, ni = 0;
    static const char *const c_and_h[2] = { "c", "h" };
    static const char *const h_only[1] = { "h" };
    rc = hpr_list_dir("engine/modules/hotswap/src", c_and_h, 2, src_c, 64, &ns);
    if (rc == 0)
        rc = hpr_list_dir("engine/modules/hotswap/include/hotswap", h_only, 1,
                          inc_h, 64, &ni);
    if (rc)
        return rc;
    rc = hprst_mirror_one("src", src_c, ns, srcdst);
    if (rc == 0)
        rc = hprst_mirror_one("inc", inc_h, ni, incdst);
    *copied_src = ns;
    *copied_inc = ni;
    return rc;
}

static int hprst_run(struct hpr_ctx *ctx, FILE *out, int *rc_out)
{
    if (psp_st_reset(out))
        return die("z23-lint: reset failed\n", "");
    ctx->out = out;
    ctx->err = out;
    *rc_out = hpr_run_checks(ctx);
    return 0;
}

static int hprst_contains(FILE *out, const char *needle)
{
    char buf[16384];
    if (csr_slurp(out, buf, sizeof buf))
        return -1;
    return strstr(buf, needle) != NULL;
}

struct hprst_state {
    char sandbox[4096];
    char src_dir[4096];
    char inc_dir[4096];
    char fixture[4096];
};

static int hprst_setup(struct hprst_state *s)
{
    char base[4096];
    if (hprst_scratch_base(base, sizeof base))
        return 2;
    if (csr_mkdirs(base))
        return 2;
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-hpr.XXXXXX", base),
            sizeof tmpl))
        return 2;
    char *sandbox = mkdtemp(tmpl);
    if (!sandbox)
        return die("z23-lint: mkdir failed: %s\n", base);
    if (ovf(snprintf(s->sandbox, sizeof s->sandbox, "%s", sandbox),
            sizeof s->sandbox))
        return 2;
    if (ovf(snprintf(s->src_dir, sizeof s->src_dir, "%s/src", s->sandbox),
            sizeof s->src_dir)
        || ovf(snprintf(s->inc_dir, sizeof s->inc_dir, "%s/include/hotswap",
                        s->sandbox),
               sizeof s->inc_dir)
        || ovf(snprintf(s->fixture, sizeof s->fixture,
                        "%s/__selftest_manifest_receipt_violation.c",
                        s->src_dir),
               sizeof s->fixture))
        return 2;
    return 0;
}

/* Plant the fixture, re-run, and require: non-zero exit AND the fixture's
 * own path named in the (combined stdout+stderr) output. */
static int hprst_trip(struct hprst_state *s, struct hpr_ctx *ctx, FILE *out,
                      int *bad)
{
    int rc = csr_write(s->fixture, k_hprst_fixture);
    if (rc)
        return rc;
    int tripped_rc = 0;
    rc = hprst_run(ctx, out, &tripped_rc);
    if (rc)
        return rc;
    int names_fixture = hprst_contains(out, s->fixture);
    if (names_fixture < 0)
        return 2;
    if (tripped_rc == 0 || !names_fixture)
        *bad = 1;
    if (unlink(s->fixture) != 0)
        *bad = 1;
    return 0;
}

/* Re-run after the fixture is removed and require the verdict and output
 * both return to the pre-plant baseline. */
static int hprst_recover(struct hprst_state *s, struct hpr_ctx *ctx, FILE *out,
                         int baseline_rc, int *bad)
{
    int recovered_rc = 0;
    int rc = hprst_run(ctx, out, &recovered_rc);
    if (rc)
        return rc;
    int still_names = hprst_contains(out, s->fixture);
    if (still_names < 0)
        return 2;
    if (still_names || recovered_rc != baseline_rc)
        *bad = 1;
    return 0;
}

static int hprst_body(struct hprst_state *s, FILE *out, int *bad)
{
    int copied_src = 0, copied_inc = 0;
    int rc = hprst_mirror(s->sandbox, &copied_src, &copied_inc);
    if (rc)
        return rc;
    if (copied_src == 0 || copied_inc == 0) {
        fputs("check_hotswap_package_receipt_is_not_authority: selftest "
             "FATAL — mirror is empty; refusing to prove anything against "
             "an empty tree\n", stderr);
        return 2;
    }
    struct hpr_ctx ctx = { .src_dir = s->src_dir, .inc_dir = s->inc_dir,
                           .pkg_tool = "tools/dev/hotswap-package.sh",
                           .out = out, .err = out,
                           .scanned_src = 0, .scanned_inc = 0 };
    int baseline_rc = 0;
    rc = hprst_run(&ctx, out, &baseline_rc);
    if (rc)
        return rc;
    if (baseline_rc != 0) {
        *bad = 1;
        return 0;
    }
    rc = hprst_trip(s, &ctx, out, bad);
    if (rc)
        return rc;
    return hprst_recover(s, &ctx, out, baseline_rc, bad);
}

int check_hotswap_package_receipt_is_not_authority_selftest(void)
{
    struct hprst_state s = {0};
    int rc = hprst_setup(&s);
    if (rc)
        return rc;
    FILE *out = tmpfile();
    if (!out) {
        (void)rap_rm_rf(s.sandbox);
        return die("z23-lint: tmpfile failed\n", "");
    }
    int bad = 0;
    rc = hprst_body(&s, out, &bad);
    fclose(out);
    (void)rap_rm_rf(s.sandbox);
    if (rc)
        return rc;
    return st_ok(bad,
                "check_hotswap_package_receipt_is_not_authority selftest: "
                "OK\n");
}
