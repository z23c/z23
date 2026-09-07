/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gate: check-hex-codec-single
 * Second file of the check-hex-codec-single family (the 700-line family
 * ceiling split): the gate's --selftest probes, byte-parity with the
 * original script's --selftest block. The scan roots, the filesystem
 * walk, the in-memory git-oracle coverage check, the two shape detectors
 * and the gate entry live in gate_hex_codec_single.c.
 *
 * Each fixture case plants one file under a private sandbox root (never
 * the real tree) and re-invokes the built gate binary for real via
 * cic_invoke (self-exec through popen, the same seam every other
 * coverage-style gate's selftest uses) so the inner run exercises the
 * genuine scan/detect/report path; only its exit code is graded. The
 * three cov_case probes run the gate against the TRUE tree instead (no
 * scan-root override for case 1) to prove the coverage self-check's
 * three-way verdict: a complete scan clears its own expectation, a scan
 * reduced to a single declared root is UNPROVEN (never 0, never 1), and a
 * recorded allowance above the true shortfall is a stale ratchet.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"

static const char k_hcs_gate[] = "check_hex_codec_single";
/* The CLI-registered gate name (hyphenated, main.c's k_gates table and the
 * Makefile target) — distinct from k_hcs_gate above, which is the
 * underscore-spelled label the original script's own diagnostics used and
 * that this port's messages still use. */
static const char k_hcs_cli[] = "check-hex-codec-single";

static int hcs_st_run_sandbox(const char *root)
{
    char roots_env[4096];
    static char sink[262144];
    int code = 0, rc;
    if (ovf(snprintf(roots_env, sizeof roots_env, "%s/engine", root),
            sizeof roots_env))
        return 2;
    if (setenv("ZCL_HEX_CODEC_SCAN_ROOTS", roots_env, 1) != 0
        || setenv("ZCL_HEX_CODEC_COVERAGE", "0", 1) != 0
        || setenv("ZCL_HEX_CODEC_FILE_FLOOR", "1", 1) != 0
        || setenv("ZCL_LINT_MODE", "FAIL", 1) != 0)
        return die("z23-lint: setenv failed\n", "");
    char base_env[4096];
    if (ovf(snprintf(base_env, sizeof base_env, "%s/empty_baseline.txt", root),
            sizeof base_env))
        return 2;
    rc = csr_write(base_env, "");
    if (rc)
        return rc;
    if (setenv("ZCL_HEX_CODEC_BASELINE", base_env, 1) != 0)
        return die("z23-lint: setenv failed\n", "");
    return cic_invoke(k_hcs_cli, 1, sink, sizeof sink, &code) ? 2 : code;
}

static int hcs_st_expect(const char *root, int want, const char *msg,
                         const char *body)
{
    char path[4096];
    int rc, code;
    if (ovf(snprintf(path, sizeof path, "%s/engine/services/src/selftest_hex.c",
                     root), sizeof path))
        return 2;
    rc = csr_write(path, body);
    if (rc)
        return rc;
    code = hcs_st_run_sandbox(root);
    if ((want == 0 && code != 0) || (want != 0 && code == 0)) {
        fprintf(stderr, "%s: SELFTEST FAILED — %s (rc=%d)\n", k_hcs_gate, msg, code);
        return 2;
    }
    return 0;
}

/* Re-invoke the gate FOR REAL against the true tree (no override baseline,
 * real coverage on): the three-way coverage verdict. */
static int hcs_cov_case(int want, const char *msg, const char *const *assigns)
{
    static char sink[262144];
    int code = 0, rc;
    unsetenv("ZCL_HEX_CODEC_SCAN_ROOTS");
    unsetenv("ZCL_HEX_CODEC_COVERAGE_ALLOWANCE");
    if (setenv("ZCL_HEX_CODEC_COVERAGE", "1", 1) != 0
        || setenv("ZCL_HEX_CODEC_FILE_FLOOR", "800", 1) != 0
        || setenv("ZCL_LINT_MODE", "FAIL", 1) != 0
        || unsetenv("ZCL_HEX_CODEC_BASELINE") != 0)
        return die("z23-lint: setenv failed\n", "");
    for (; *assigns; assigns++) {
        char buf[4096];
        if (ovf(snprintf(buf, sizeof buf, "%s", *assigns), sizeof buf))
            return 2;
        char *eq = strchr(buf, '=');
        if (!eq)
            return die("z23-lint: setenv failed\n", "");
        *eq = '\0';
        if (setenv(buf, eq + 1, 1) != 0)
            return die("z23-lint: setenv failed\n", "");
    }
    rc = cic_invoke(k_hcs_cli, 1, sink, sizeof sink, &code);
    if (rc)
        return rc;
    if (code != want) {
        fprintf(stderr, "%s: SELFTEST FAILED — %s (wanted exit %d, got %d)\n",
                k_hcs_gate, msg, want, code);
        return 2;
    }
    return 0;
}

int check_hex_codec_single_selftest(void)
{
    const char *td = env_or("TMPDIR", "/tmp");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-hcs-XXXXXX", td), sizeof tmpl))
        return 2;
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdtemp failed: %s\n", tmpl);
    int rc = 0;

    rc = hcs_st_expect(root, 1,
        "a fresh private hex ENCODER did not fail the gate",
        "static void my_hex(const unsigned char *in, size_t n, char *out)\n"
        "{\n    static const char hexd[] = \"0123456789" "abcdef\";\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        out[2 * i]     = hexd[(in[i] >>" " 4) & 0xf];\n"
        "        out[2 * i + 1] = hexd[in[i] & 0xf];\n    }\n"
        "    out[2 * n] = 0;\n}\n");

    if (rc == 0)
        rc = hcs_st_expect(root, 1,
            "a fresh private hex DECODER (nibble ladder) did not fail the gate",
            "static int my_nibble(char c)\n{\n"
            "    if (c >= '0' && c <= '9') return c - '0';\n"
            "    if (c >= 'a' && c <= 'f') return c -" " 'a' + 10;\n"
            "    return -1;\n}\n");

    if (rc == 0)
        rc = hcs_st_expect(root, 1,
            "a fresh private hex DECODER (sscanf %2x) did not fail the gate",
            "static int my_decode(const char *hex, unsigned char *out, int n)\n"
            "{\n    for (int i = 0; i < n; i++) {\n        unsigned v;\n"
            "        if (sscanf(hex + 2 * i, \"%2" "x\", &v) != 1) return 0;\n"
            "        out[i] = (unsigned char)v;\n    }\n    return 1;\n}\n");

    if (rc == 0)
        rc = hcs_st_expect(root, 0,
            "a bare hex-digit alphabet with no nibble work was flagged",
            "static int is_hexish(char c)\n{\n"
            "    static const char alphabet[] = \"0123456789" "abcdef\";\n"
            "    return strchr(alphabet, c) != NULL;\n}\n");

    if (rc == 0)
        rc = hcs_st_expect(root, 0,
            "a file calling the canonical codec was flagged",
            "#include \"base/hex.h\"\n"
            "static void emit(const unsigned char id[32], char out[65])\n"
            "{\n    zcl_hex_encode(id, 32, out);\n}\n");

    if (rc == 0) {
        static const char *const c1[] = { NULL };
        rc = hcs_cov_case(0, "the complete scan did not pass its coverage "
                          "expectation", c1);
    }
    if (rc == 0) {
        static const char *const c2[] = {
            "ZCL_HEX_CODEC_SCAN_ROOTS=engine/composition", "ZCL_HEX_CODEC_FILE_FLOOR=1",
            NULL
        };
        rc = hcs_cov_case(2, "a scan missing a whole declared root was not "
                          "UNPROVEN", c2);
    }
    if (rc == 0) {
        static const char *const c3[] = {
            "ZCL_HEX_CODEC_COVERAGE_ALLOWANCE=1", NULL
        };
        rc = hcs_cov_case(1, "an allowance above the true shortfall was "
                          "silently tolerated", c3);
    }

    unsetenv("ZCL_HEX_CODEC_SCAN_ROOTS");
    unsetenv("ZCL_HEX_CODEC_COVERAGE");
    unsetenv("ZCL_HEX_CODEC_FILE_FLOOR");
    unsetenv("ZCL_HEX_CODEC_BASELINE");
    unsetenv("ZCL_HEX_CODEC_COVERAGE_ALLOWANCE");
    unsetenv("ZCL_LINT_MODE");
    if (rc == 0)
        rc = rap_rm_rf(root);
    if (rc)
        return rc;
    printf("[%s] SELFTEST PASS (private encoder, nibble ladder and %%2x "
           "decode all fail; bare alphabet and canonical caller pass; a "
           "full scan clears coverage, a scan short one declared root is "
           "UNPROVEN exit 2, a stale allowance is exit 1)\n", k_hcs_gate);
    return 0;
}
