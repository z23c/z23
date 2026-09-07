/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * check-macos-acceptance family — --selftest. Port of the 20-case
 * --selftest of tools/lint/check_macos_acceptance.sh (which itself drives
 * tools/scripts/macos_acceptance.sh --check against 16 planted fixtures
 * plus 4 reachability-rail fixtures). Every fixture is a mutation of the
 * REAL matrix/Makefile/ACCEPT-script text (never a rewritten mock), planted
 * under a private sandbox — getenv("TMPDIR") or "test-tmp", never /tmp —
 * removed on the way out.
 *
 * No heap: every text transform below writes into a caller-owned static
 * fixed buffer instead of malloc/strdup, matching the fixed-buffer
 * convention used throughout tools/lint/lintc/.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lintc.h"
#include "gate_macos_acceptance_priv.h"

static const char k_gate[] = "check-macos-acceptance";
static const char k_matrix[] = "engine/composition/platform/macos_capabilities.def";
static const char k_catalog[] = "tools/dev/test_group_catalog.def";
static const char k_accept[] = "tools/scripts/macos_acceptance.sh";

enum { SEL_BUF = 1 << 20 };

static int mac_read_all_buf(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 1;
    size_t n = fread(buf, 1, cap - 1, f);
    int err = ferror(f);
    buf[n] = '\0';
    fclose(f);
    return err ? 1 : 0;
}

/* First-occurrence textual substitution — every fixture pattern below
 * occurs exactly once in the real input, so this reproduces sed's
 * per-line-first-match semantics without a subprocess. */
static int mac_replace1_buf(const char *text, const char *find,
                            const char *repl, char *out, size_t cap)
{
    const char *hit = strstr(text, find);
    if (!hit) {
        int k = snprintf(out, cap, "%s", text);
        return k < 0 || (size_t)k >= cap;
    }
    size_t pre = (size_t)(hit - text);
    size_t flen = strlen(find), rlen = strlen(repl), tlen = strlen(text);
    size_t outlen = tlen - flen + rlen;
    if (outlen + 1 > cap)
        return 1;
    memcpy(out, text, pre);
    memcpy(out + pre, repl, rlen);
    memcpy(out + pre + rlen, hit + flen, tlen - pre - flen + 1);
    return 0;
}

/* Delete every line containing `needle` (grep -Fv needle). */
static int mac_drop_lines_containing_buf(const char *text, const char *needle,
                                         char *out, size_t cap)
{
    size_t used = 0;
    const char *p = text;
    while (*p) {
        const char *eol = strchr(p, '\n');
        size_t n = eol ? (size_t)(eol - p + 1) : strlen(p);
        char line[8192];
        size_t cl = n; if (cl >= sizeof line) cl = sizeof line - 1;
        memcpy(line, p, cl);
        line[cl] = '\0';
        if (!strstr(line, needle)) {
            if (used + n + 1 > cap)
                return 1;
            memcpy(out + used, p, n);
            used += n;
        }
        p += n;
    }
    out[used] = '\0';
    return 0;
}

/* Delete every line exactly matching (after full match) a fixed regex-free
 * needle used as a whole-line predicate (O's tabbed recipe line). */
static int mac_drop_lines_prefixed_buf(const char *text, const char *prefix,
                                       const char *suffix, char *out,
                                       size_t cap)
{
    size_t used = 0;
    const char *p = text;
    while (*p) {
        const char *eol = strchr(p, '\n');
        size_t n = eol ? (size_t)(eol - p + 1) : strlen(p);
        char line[8192];
        size_t cl = n; if (cl >= sizeof line) cl = sizeof line - 1;
        memcpy(line, p, cl);
        line[cl] = '\0';
        size_t ll = strlen(line);
        while (ll && (line[ll - 1] == '\n')) line[--ll] = '\0';
        int match = strncmp(line, prefix, strlen(prefix)) == 0
            && ll >= strlen(suffix)
            && strcmp(line + ll - strlen(suffix), suffix) == 0;
        if (!match) {
            if (used + n + 1 > cap)
                return 1;
            memcpy(out + used, p, n);
            used += n;
        }
        p += n;
    }
    out[used] = '\0';
    return 0;
}

static void mac_expect_reject(int *rc, const char *label, const char *needle,
                              const char *fixture_path)
{
    struct mac_result r;
    mac_validate_pub(fixture_path, k_catalog, &r);
    if (r.rc == 0) {
        fprintf(stderr, "SELFTEST FAIL: %s — expected rejection, got a PASS.\n",
               label);
        *rc = 1;
        return;
    }
    if (!strstr(r.out, needle)) {
        fprintf(stderr,
               "SELFTEST FAIL: %s — rejected, but never named '%s'.\n"
               "    %s\n", label, needle, r.out);
        *rc = 1;
        return;
    }
    printf("  selftest ok: %s\n", label);
}

static void mac_expect_accept(int *rc, const char *label,
                              const char *fixture_path)
{
    struct mac_result r;
    mac_validate_pub(fixture_path, k_catalog, &r);
    if (r.rc != 0) {
        fprintf(stderr,
               "SELFTEST FAIL: %s — expected a PASS, got rejection.\n"
               "    %s\n", label, r.out);
        *rc = 1;
        return;
    }
    printf("  selftest ok: %s\n", label);
}

static void mac_expect_make_reject(int *rc, const char *label,
                                   const char *fixture_path)
{
    if (mac_make_target_reachable_pub(fixture_path)) {
        fprintf(stderr,
               "SELFTEST FAIL: %s — malformed Make target was accepted.\n",
               label);
        *rc = 1;
        return;
    }
    printf("  selftest ok: %s\n", label);
}

static void mac_expect_package_reject(int *rc, const char *label,
                                      const char *fixture_text)
{
    if (mac_runtime_package_reachable_text_pub(fixture_text)) {
        fprintf(stderr,
               "SELFTEST FAIL: %s — incomplete package acceptance was "
               "accepted.\n", label);
        *rc = 1;
        return;
    }
    printf("  selftest ok: %s\n", label);
}

static int mac_plant(const char *sandbox, const char *name, const char *text)
{
    char path[512];
    snprintf(path, sizeof path, "%s/%s", sandbox, name);
    return csr_write(path, text);
}

/* Cases 0, A-D: the positive control and the five capability-row
 * mutations that share the "clean matrix + one substitution" shape. */
static int mac_st_group_state(int *rc, const char *sandbox,
                              const char *matrix)
{
    char p[6][512];
    int np = 0;
#define PLANT(name, content) \
    (snprintf(p[np], sizeof p[np], "%s/%s", sandbox, name), \
     mac_plant(sandbox, name, content), np++)

    PLANT("clean.def", matrix);
    mac_expect_accept(rc,
                      "0: a copy of the real matrix passes (positive control)",
                      p[0]);

    static char t[SEL_BUF];
    if (mac_replace1_buf(matrix, "ZCL_MACOS_CAPABILITY(tor, available,",
                         "ZCL_MACOS_CAPABILITY(tor, probably,", t, sizeof t))
        return die("z23-lint: derived buffer overflow\n", "");
    PLANT("state.def", t);
    mac_expect_reject(rc, "A: an illegal capability state is caught",
                      "invalid state", p[1]);

    if (mac_replace1_buf(matrix, "test_tor)",
                         "test_tor_group_that_does_not_exist)", t, sizeof t))
        return die("z23-lint: derived buffer overflow\n", "");
    PLANT("group.def", t);
    mac_expect_reject(rc,
                      "B: a capability naming an unregistered test group is caught",
                      "unregistered group", p[2]);

    if (mac_replace1_buf(matrix, "test_noise_nk_handshake,",
                         "test_noise_group_that_does_not_exist,", t,
                         sizeof t))
        return die("z23-lint: derived buffer overflow\n", "");
    PLANT("group_first.def", t);
    mac_expect_reject(rc,
                      "B2: an unregistered group in a non-last position is caught",
                      "unregistered group", p[3]);

    if (mac_replace1_buf(matrix,
        "ZCL_MACOS_CAPABILITY(tor, available, embedded_full_tor_when_archive_present,",
        "ZCL_MACOS_CAPABILITY(tor, available, ,", t, sizeof t))
        return die("z23-lint: derived buffer overflow\n", "");
    PLANT("reason.def", t);
    mac_expect_reject(rc, "C: a capability with no typed reason is caught",
                      "no typed reason", p[4]);

    if (mac_replace1_buf(matrix, "ZCL_MACOS_CAPABILITY(tor,",
                         "ZCL_MACOS_CAPABILITY(onion,", t, sizeof t))
        return die("z23-lint: derived buffer overflow\n", "");
    PLANT("drift.def", t);
    mac_expect_reject(rc, "D: drift in the closed capability set is caught",
                      "capability set drift", p[5]);
#undef PLANT
    return 0;
}

/* Cases E-F: the two "matrix itself is unusable" rails. */
static void mac_st_group_missing(int *rc, const char *sandbox)
{
    char p[512];
    snprintf(p, sizeof p, "%s/empty.def", sandbox);
    mac_plant(sandbox, "empty.def", "/* no rows */\n");
    mac_expect_reject(rc, "E: an empty capability matrix fails closed",
                      "no rows", p);

    snprintf(p, sizeof p, "%s/not_here.def", sandbox);
    mac_expect_reject(rc, "F: a missing capability matrix fails closed",
                      "missing capability matrix", p);
}

/* Cases G-J: required-baseline and exact-set drift. */
static int mac_st_group_required(int *rc, const char *sandbox,
                                 const char *matrix)
{
    char p[4][512];
    int np = 0;
#define PLANT(name, content) \
    (snprintf(p[np], sizeof p[np], "%s/%s", sandbox, name), \
     mac_plant(sandbox, name, content), np++)

    static char t[SEL_BUF];
    if (mac_drop_lines_prefixed_buf(matrix,
        "ZCL_MACOS_REQUIRED_TEST(test_crypto)", "", t, sizeof t))
        return die("z23-lint: derived buffer overflow\n", "");
    PLANT("required_deleted.def", t);
    mac_expect_reject(rc, "G: deletion from the required baseline is caught",
                      "required test set drift", p[0]);

    if (mac_replace1_buf(matrix, "ZCL_MACOS_REQUIRED_TEST(test_crypto)",
        "ZCL_MACOS_REQUIRED_TEST(test_macos_group_that_does_not_exist)", t,
        sizeof t))
        return die("z23-lint: derived buffer overflow\n", "");
    PLANT("required_unknown.def", t);
    mac_expect_reject(rc, "H: an unknown required group is caught",
                      "unregistered group", p[1]);

    if (mac_replace1_buf(matrix, "ZCL_MACOS_REQUIRED_TEST(test_crypto)",
                         "ZCL_MACOS_REQUIRED_TEST(test_json)", t, sizeof t))
        return die("z23-lint: derived buffer overflow\n", "");
    PLANT("required_exact_set.def", t);
    mac_expect_reject(rc,
                      "I: a same-size registered mutation violates the exact set",
                      "required test set drift", p[2]);

    if (mac_replace1_buf(matrix, "test_tor)", "test_json)", t, sizeof t))
        return die("z23-lint: derived buffer overflow\n", "");
    PLANT("capability_exact_set.def", t);
    mac_expect_reject(rc,
                      "J: same-size registered capability evidence drift is caught",
                      "exact evidence set drift", p[3]);
#undef PLANT
    return 0;
}

/* Cases K-N: the two hand-pinned capability contracts (package_execution,
 * resident_confinement), each with a state mutation and an evidence
 * reassignment (which needs two chained substitutions). */
static int mac_st_group_contracts(int *rc, const char *sandbox,
                                  const char *matrix)
{
    char p[4][512];
    int np = 0;
#define PLANT(name, content) \
    (snprintf(p[np], sizeof p[np], "%s/%s", sandbox, name), \
     mac_plant(sandbox, name, content), np++)

    static char t[SEL_BUF], t2[SEL_BUF];
    if (mac_replace1_buf(matrix,
        "ZCL_MACOS_CAPABILITY(package_execution, available,",
        "ZCL_MACOS_CAPABILITY(package_execution, degraded,", t, sizeof t))
        return die("z23-lint: derived buffer overflow\n", "");
    PLANT("package_state.def", t);
    mac_expect_reject(rc, "K: a legal Seatbelt package downgrade is caught",
                      "package_execution contract drift", p[0]);

    if (mac_replace1_buf(matrix,
        "ZCL_MACOS_CAPABILITY(resident_confinement, unavailable,",
        "ZCL_MACOS_CAPABILITY(resident_confinement, available,", t,
        sizeof t))
        return die("z23-lint: derived buffer overflow\n", "");
    PLANT("resident_state.def", t);
    mac_expect_reject(rc, "L: Seatbelt cannot promote resident confinement",
                      "resident_confinement contract drift", p[1]);

    if (mac_replace1_buf(matrix,
        "test_boot_shutdown_marker_persistence,test_net,test_rpc",
        "test_boot_shutdown_marker_persistence,test_platform_toolchain,test_rpc",
        t, sizeof t))
        return die("z23-lint: derived buffer overflow\n", "");
    if (mac_replace1_buf(t,
        "test_os_sandbox,test_platform_toolchain,test_sandbox_process_budget,test_zcode_verify",
        "test_os_sandbox,test_net,test_sandbox_process_budget,test_zcode_verify",
        t2, sizeof t2))
        return die("z23-lint: derived buffer overflow\n", "");
    PLANT("package_groups.def", t2);
    mac_expect_reject(rc, "M: package evidence reassignment is caught",
                      "package_execution contract drift", p[2]);

    if (mac_replace1_buf(matrix,
        "test_boot_shutdown_marker_persistence,test_net,test_rpc",
        "test_boot_shutdown_marker_persistence,test_net,test_confine", t,
        sizeof t))
        return die("z23-lint: derived buffer overflow\n", "");
    if (mac_replace1_buf(t, "test_os_sandbox,test_confine)",
                         "test_os_sandbox,test_rpc)", t2, sizeof t2))
        return die("z23-lint: derived buffer overflow\n", "");
    PLANT("resident_groups.def", t2);
    mac_expect_reject(rc, "N: resident evidence reassignment is caught",
                      "resident_confinement contract drift", p[3]);
#undef PLANT
    return 0;
}

/* Cases O-R: the four wiring/reachability rails over the Makefile and the
 * ACCEPT script rather than the capability matrix. */
static int mac_st_group_wiring(int *rc, const char *sandbox,
                               const char *makefile, const char *accept)
{
    static char t[SEL_BUF];

    char no_recipe_path[512];
    snprintf(no_recipe_path, sizeof no_recipe_path, "%s/make_no_recipe",
            sandbox);
    if (mac_drop_lines_containing_buf(makefile,
        "@./tools/scripts/macos_acceptance.sh --run", t, sizeof t))
        return die("z23-lint: derived buffer overflow\n", "");
    (void)csr_write(no_recipe_path, t);
    mac_expect_make_reject(rc, "O: deleting the native recipe is caught",
                          no_recipe_path);

    char no_z23_path[512];
    snprintf(no_z23_path, sizeof no_z23_path, "%s/make_no_z23", sandbox);
    if (mac_replace1_buf(makefile,
        "macos-acceptance: z23 zclassic23-package-verify zclassic23-acme",
        "macos-acceptance: z23", t, sizeof t))
        return die("z23-lint: derived buffer overflow\n", "");
    (void)csr_write(no_z23_path, t);
    mac_expect_make_reject(rc,
                          "P: deleting release-member prerequisites is caught",
                          no_z23_path);

    if (mac_drop_lines_containing_buf(accept, "build_release.sh\" --bin", t,
                                      sizeof t))
        return die("z23-lint: derived buffer overflow\n", "");
    mac_expect_package_reject(rc,
                              "Q: deleting the canonical runtime cut is caught",
                              t);

    if (mac_drop_lines_containing_buf(accept, "runtime/z23\" code guide", t,
                                      sizeof t))
        return die("z23-lint: derived buffer overflow\n", "");
    mac_expect_package_reject(rc,
                              "R: deleting packaged-node execution is caught",
                              t);
    return 0;
}

int check_macos_acceptance_selftest(void)
{
    const char *base = getenv("TMPDIR");
    if (!base || !base[0])
        base = "test-tmp";
    if (csr_mkdirs(base))
        return 2;
    char tmpl[512];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/mac_st.XXXXXX", base), sizeof tmpl))
        return 2;
    char *sandbox = mkdtemp(tmpl);
    if (!sandbox)
        return die("z23-lint: mkdir failed: %s\n", base);

    printf("══ %s selftest ══\n", k_gate);
    int st_rc = 0;

    static char matrix[SEL_BUF], makefile[SEL_BUF], accept[SEL_BUF];
    if (mac_read_all_buf(k_matrix, matrix, sizeof matrix)
        || mac_read_all_buf("Makefile", makefile, sizeof makefile)
        || mac_read_all_buf(k_accept, accept, sizeof accept)) {
        (void)rap_rm_rf(sandbox);
        return die("z23-lint: cannot read a real input file\n", "");
    }

    int rc = mac_st_group_state(&st_rc, sandbox, matrix);
    if (rc == 0) {
        mac_st_group_missing(&st_rc, sandbox);
        rc = mac_st_group_required(&st_rc, sandbox, matrix);
    }
    if (rc == 0)
        rc = mac_st_group_contracts(&st_rc, sandbox, matrix);
    if (rc == 0)
        rc = mac_st_group_wiring(&st_rc, sandbox, makefile, accept);
    if (rc) {
        (void)rap_rm_rf(sandbox);
        return rc;
    }

    (void)rap_rm_rf(sandbox);

    if (st_rc == 0)
        printf("══ selftest: PASS (20/20) ══\n");
    else
        printf("══ selftest: FAIL ══\n");
    return st_rc;
}
