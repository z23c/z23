/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-package-capabilities (gate_package_capabilities.c).
 * Every case is a from-scratch fixture tree with its own
 * engine/composition/{capability_classes,module_capabilities,
 * zcode_package_registry}.def and package manifest, graded by the same
 * pc_check_root() the gate runs — nothing about the real tree can make a
 * case pass or fail by accident. Sandbox lives under getenv("TMPDIR") else
 * "test-tmp", never /tmp.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "gate_package_capabilities_priv.h"

enum { PCS_BUF = 1 << 16 };

static int pcs_fixture_base(const char *d)
{
    char p[4096];
    if (ovf(snprintf(p, sizeof p, "%s/engine/composition/capability_classes.def", d),
            sizeof p))
        return 2;
    if (csr_write(p,
                  "ZCL_CAPABILITY_CLASS(NETWORK, \"\", \"\")\n"
                  "ZCL_CAPABILITY_CLASS(FS_READ, \"\", \"\")\n"
                  "ZCL_CAPABILITY_CLASS(FS_WRITE, \"\", \"\")\n"))
        return 2;
    if (ovf(snprintf(p, sizeof p, "%s/engine/composition/module_capabilities.def", d),
            sizeof p))
        return 2;
    return csr_write(p, "");
}

/* rows: NULL-terminated array of "path CAP_A|CAP_B" strings. */
static int pcs_fixture_rows(const char *d, const char *const *rows)
{
    char body[PCS_BUF];
    size_t used = 0;
    body[0] = '\0';
    for (int i = 0; rows[i]; i++) {
        const char *sp = strchr(rows[i], ' ');
        char path[256], cls[64];
        if (!sp || ovf((int)(sp - rows[i]), sizeof path))
            return 2;
        memcpy(path, rows[i], (size_t)(sp - rows[i]));
        path[sp - rows[i]] = '\0';
        if (ovf(snprintf(cls, sizeof cls, "%s", sp + 1), sizeof cls))
            return 2;
        if (pc_append(body, sizeof body, &used,
                     "ZCL_MODULE_CAPABILITY(\"%s\", %s, \"\")\n", path, cls))
            return 2;
    }
    char p[4096];
    if (ovf(snprintf(p, sizeof p, "%s/engine/composition/module_capabilities.def", d),
            sizeof p))
        return 2;
    return csr_write(p, body);
}

static int pcs_fixture_windows_rows(const char *d, const char *const *rows)
{
    char body[PCS_BUF];
    size_t used = 0;
    body[0] = '\0';
    for (int i = 0; rows[i]; i++) {
        const char *sp = strchr(rows[i], ' ');
        char path[256], cls[64];
        if (!sp || ovf((int)(sp - rows[i]), sizeof path))
            return 2;
        memcpy(path, rows[i], (size_t)(sp - rows[i]));
        path[sp - rows[i]] = '\0';
        if (ovf(snprintf(cls, sizeof cls, "%s", sp + 1), sizeof cls))
            return 2;
        if (pc_append(body, sizeof body, &used,
                     "ZCL_MODULE_CAPABILITY(\"%s\", %s, \"Windows exact arm\")\n", path,
                     cls))
            return 2;
    }
    char p[4096];
    if (ovf(snprintf(p, sizeof p, "%s/engine/composition/module_capabilities_windows.def",
                     d), sizeof p))
        return 2;
    return csr_write(p, body);
}

/* srcs: NULL-terminated array of pkgdir-relative paths. caps_json: the
 * literal inner text of the capabilities array, or NULL to omit the key. */
static int pcs_fixture_pkg(const char *d, const char *name, const char *pkgdir,
                           const char *caps_json, const char *const *srcs)
{
    char p[4096];
    if (ovf(snprintf(p, sizeof p, "%s/engine/composition/zcode_package_registry.def", d),
            sizeof p))
        return 2;
    char row[512];
    if (ovf(snprintf(row, sizeof row, "ZCODE_PACKAGE(\"%s\", \"%s\", 1,\n    \"aa\")\n",
                     name, pkgdir), sizeof row))
        return 2;
    if (csr_write(p, row))
        return 2;

    char body[PCS_BUF];
    size_t used = 0;
    body[0] = '\0';
    if (pc_append(body, sizeof body, &used, "{\n  \"schema\": 1,\n  \"name\": \"%s\",\n"
                 "  \"dependencies\": [],\n", name))
        return 2;
    if (caps_json && pc_append(body, sizeof body, &used, "  \"capabilities\": [%s],\n",
                               caps_json))
        return 2;
    if (pc_append(body, sizeof body, &used, "  \"files\": [\n"))
        return 2;
    for (int i = 0; srcs[i]; i++) {
        if (pc_append(body, sizeof body, &used, "%s    \"%s\"", i ? ",\n" : "", srcs[i]))
            return 2;
        char fpath[4096];
        if (ovf(snprintf(fpath, sizeof fpath, "%s/%s/%s", d, pkgdir, srcs[i]),
                sizeof fpath))
            return 2;
        if (csr_write(fpath, ""))
            return 2;
    }
    if (pc_append(body, sizeof body, &used, "\n  ]\n}\n"))
        return 2;
    if (ovf(snprintf(p, sizeof p, "%s/%s/zcode-package.json", d, pkgdir), sizeof p))
        return 2;
    return csr_write(p, body);
}

static int pcs_expect_rc(const char *label, int want, const char *needle, const char *d,
                         int *fails)
{
    char path[4096];
    if (ovf(snprintf(path, sizeof path, "%s/.out", d), sizeof path))
        return 2;
    FILE *o = fopen(path, "w+");
    if (!o)
        return die("z23-lint: cannot open %s\n", path);
    int rc = pc_check_root(d, o);
    static char captured[1 << 20];
    if (csr_slurp(o, captured, sizeof captured)) { fclose(o); return 2; }
    fclose(o);
    if (rc != want) {
        fprintf(stderr, "SELFTEST FAIL: %s — expected exit %d, got %d.\n%s\n", label,
               want, rc, captured);
        (*fails)++;
        return 0;
    }
    if (needle && !strstr(captured, needle)) {
        fprintf(stderr,
               "SELFTEST FAIL: %s — exit %d was right, but the report never said\n"
               "  '%s'.\n%s\n", label, rc, needle, captured);
        (*fails)++;
        return 0;
    }
    printf("  selftest ok: %s (rc=%d)\n", label, rc);
    return 0;
}

static int pcs_case_a(const char *base, int *fails)
{
    char d[4096];
    if (ovf(snprintf(d, sizeof d, "%s/a", base), sizeof d) || csr_mkdirs(d))
        return 2;
    if (pcs_fixture_base(d))
        return 2;
    const char *srcs[] = { "src/dialer.c", NULL };
    if (pcs_fixture_pkg(d, "fx/dialer", "lib/dialer", "", srcs))
        return 2;
    const char *rows[] = { "lib/dialer/src/dialer.c CAP_NETWORK", NULL };
    if (pcs_fixture_rows(d, rows))
        return 2;
    return pcs_expect_rc("A: shipped file uses NETWORK, manifest omits it (understates)",
                        1, "UNDERSTATES", d, fails);
}
static int pcs_case_b(const char *base, int *fails)
{
    char d[4096];
    if (ovf(snprintf(d, sizeof d, "%s/b", base), sizeof d) || csr_mkdirs(d))
        return 2;
    if (pcs_fixture_base(d))
        return 2;
    const char *srcs[] = { "src/quiet.c", NULL };
    if (pcs_fixture_pkg(d, "fx/quiet", "lib/quiet", "\"CAP_NETWORK\"", srcs))
        return 2;
    const char *rows[] = { "lib/other/src/other.c CAP_FS_READ", NULL };
    if (pcs_fixture_rows(d, rows))
        return 2;
    return pcs_expect_rc("B: manifest declares a class no shipped file uses (overstates)",
                        1, "OVERSTATES", d, fails);
}
static int pcs_case_c(const char *base, int *fails)
{
    char d[4096];
    if (ovf(snprintf(d, sizeof d, "%s/c", base), sizeof d) || csr_mkdirs(d))
        return 2;
    if (pcs_fixture_base(d))
        return 2;
    const char *srcs[] = { "src/inert.c", NULL };
    if (pcs_fixture_pkg(d, "fx/inert", "lib/inert", "", srcs))
        return 2;
    const char *rows[] = { "lib/elsewhere/src/elsewhere.c CAP_NETWORK", NULL };
    if (pcs_fixture_rows(d, rows))
        return 2;
    return pcs_expect_rc("C: a genuinely inert package with [] passes (positive control)",
                        0, "OK — every manifest", d, fails);
}
static int pcs_case_c2(const char *base, int *fails)
{
    char d[4096];
    if (ovf(snprintf(d, sizeof d, "%s/c2", base), sizeof d) || csr_mkdirs(d))
        return 2;
    if (pcs_fixture_base(d))
        return 2;
    const char *srcs[] = { "src/a.c", "src/b.c", NULL };
    if (pcs_fixture_pkg(d, "fx/busy", "lib/busy",
                       "\"CAP_FS_READ\", \"CAP_FS_WRITE\", \"CAP_NETWORK\"", srcs))
        return 2;
    const char *rows[] = { "lib/busy/src/a.c CAP_FS_READ|CAP_NETWORK",
                           "lib/busy/src/b.c CAP_FS_WRITE", NULL };
    if (pcs_fixture_rows(d, rows))
        return 2;
    return pcs_expect_rc("C2: a correct three-class declaration passes (positive control)",
                        0, "OK — every manifest", d, fails);
}
static int pcs_case_c3(const char *base, int *fails)
{
    char d[4096];
    if (ovf(snprintf(d, sizeof d, "%s/c3", base), sizeof d) || csr_mkdirs(d))
        return 2;
    if (pcs_fixture_base(d))
        return 2;
    const char *srcs[] = { "src/portable.c", NULL };
    if (pcs_fixture_pkg(d, "fx/cross-target", "lib/cross-target",
                       "\"CAP_FS_READ\", \"CAP_NETWORK\"", srcs))
        return 2;
    const char *rows[] = { "lib/cross-target/src/portable.c CAP_FS_READ", NULL };
    if (pcs_fixture_rows(d, rows))
        return 2;
    const char *wrows[] = { "lib/cross-target/src/portable.c CAP_NETWORK", NULL };
    if (pcs_fixture_windows_rows(d, wrows))
        return 2;
    return pcs_expect_rc("C3: package claims union of portable and Windows exact reach",
                        0, "OK — every manifest", d, fails);
}
static int pcs_case_d(const char *base, int *fails)
{
    char d[4096];
    if (ovf(snprintf(d, sizeof d, "%s/d", base), sizeof d) || csr_mkdirs(d))
        return 2;
    if (pcs_fixture_base(d))
        return 2;
    const char *srcs[] = { "src/silent.c", NULL };
    if (pcs_fixture_pkg(d, "fx/silent", "lib/silent", NULL, srcs))
        return 2;
    const char *rows[] = { "lib/other/src/other.c CAP_FS_READ", NULL };
    if (pcs_fixture_rows(d, rows))
        return 2;
    return pcs_expect_rc("D: a manifest with no capabilities field fails, never 'assume "
                        "empty'", 1, "Absent is not empty", d, fails);
}
static int pcs_case_e(const char *base, int *fails)
{
    char d[4096];
    if (ovf(snprintf(d, sizeof d, "%s/e", base), sizeof d) || csr_mkdirs(d))
        return 2;
    if (pcs_fixture_base(d))
        return 2;
    const char *rows[] = { "lib/x/src/x.c CAP_NETWORK", NULL };
    if (pcs_fixture_rows(d, rows))
        return 2;
    char p[4096];
    if (ovf(snprintf(p, sizeof p, "%s/engine/composition/zcode_package_registry.def", d),
            sizeof p))
        return 2;
    if (csr_write(p, ""))
        return 2;
    return pcs_expect_rc("E: zero packages parsed is UNPROVEN (exit 2), never a clean "
                        "tree", 2, "UNPROVEN", d, fails);
}
static int pcs_case_e2(const char *base, int *fails)
{
    char d[4096];
    if (ovf(snprintf(d, sizeof d, "%s/e2", base), sizeof d) || csr_mkdirs(d))
        return 2;
    if (pcs_fixture_base(d))
        return 2;
    const char *srcs[] = { "README.md", NULL };
    if (pcs_fixture_pkg(d, "fx/empty", "lib/empty", "", srcs))
        return 2;
    const char *rows[] = { "lib/x/src/x.c CAP_NETWORK", NULL };
    if (pcs_fixture_rows(d, rows))
        return 2;
    return pcs_expect_rc("E2: a package shipping zero C sources is UNPROVEN (exit 2)", 2,
                        "ships zero C", d, fails);
}
static int pcs_case_e3(const char *base, int *fails)
{
    char d[4096];
    if (ovf(snprintf(d, sizeof d, "%s/e3", base), sizeof d) || csr_mkdirs(d))
        return 2;
    if (pcs_fixture_base(d))
        return 2;
    const char *srcs[] = { "src/inert.c", NULL };
    if (pcs_fixture_pkg(d, "fx/inert", "lib/inert", "", srcs))
        return 2;
    char p[4096];
    if (ovf(snprintf(p, sizeof p, "%s/engine/composition/module_capabilities.def", d),
            sizeof p))
        return 2;
    if (csr_write(p, ""))
        return 2;
    return pcs_expect_rc("E3: zero module rows is UNPROVEN (exit 2), not a tree of inert "
                        "packages", 2, "parsed 0 rows", d, fails);
}
static int pcs_case_f1(const char *base, int *fails)
{
    char d[4096];
    if (ovf(snprintf(d, sizeof d, "%s/f1", base), sizeof d) || csr_mkdirs(d))
        return 2;
    if (pcs_fixture_base(d))
        return 2;
    const char *srcs[] = { "src/tail.c", NULL };
    if (pcs_fixture_pkg(d, "fx/tail", "lib/tail", "\"CAP_FS_READ\", \"CAP_NETWORK\"",
                       srcs))
        return 2;
    const char *rows[] = { "lib/tail/src/tail.c CAP_FS_READ", NULL };
    if (pcs_fixture_rows(d, rows))
        return 2;
    return pcs_expect_rc("F1: a bogus class in the LAST array position is seen", 1,
                        "CAP_NETWORK", d, fails);
}
static int pcs_case_f2(const char *base, int *fails)
{
    char d[4096];
    if (ovf(snprintf(d, sizeof d, "%s/f2", base), sizeof d) || csr_mkdirs(d))
        return 2;
    if (pcs_fixture_base(d))
        return 2;
    const char *srcs[] = { "src/head.c", NULL };
    if (pcs_fixture_pkg(d, "fx/head", "lib/head", "\"CAP_FS_READ\", \"CAP_NETWORK\"",
                       srcs))
        return 2;
    const char *rows[] = { "lib/head/src/head.c CAP_NETWORK", NULL };
    if (pcs_fixture_rows(d, rows))
        return 2;
    return pcs_expect_rc("F2: the same defect in a NON-LAST array position is seen", 1,
                        "CAP_FS_READ", d, fails);
}
static int pcs_case_g1(const char *base, int *fails)
{
    char d[4096];
    if (ovf(snprintf(d, sizeof d, "%s/g1", base), sizeof d) || csr_mkdirs(d))
        return 2;
    if (pcs_fixture_base(d))
        return 2;
    const char *srcs[] = { "src/one.c", "src/two.c", "src/three.c", NULL };
    if (pcs_fixture_pkg(d, "fx/lastfile", "lib/lastfile", "", srcs))
        return 2;
    const char *rows[] = { "lib/lastfile/src/three.c CAP_NETWORK", NULL };
    if (pcs_fixture_rows(d, rows))
        return 2;
    return pcs_expect_rc("G1: reach from the LAST shipped source is seen", 1,
                        "src/three.c", d, fails);
}
static int pcs_case_g2(const char *base, int *fails)
{
    char d[4096];
    if (ovf(snprintf(d, sizeof d, "%s/g2", base), sizeof d) || csr_mkdirs(d))
        return 2;
    if (pcs_fixture_base(d))
        return 2;
    const char *srcs[] = { "src/one.c", "src/two.c", "src/three.c", NULL };
    if (pcs_fixture_pkg(d, "fx/firstfile", "lib/firstfile", "", srcs))
        return 2;
    const char *rows[] = { "lib/firstfile/src/one.c CAP_NETWORK", NULL };
    if (pcs_fixture_rows(d, rows))
        return 2;
    return pcs_expect_rc("G2: reach from a NON-LAST shipped source is seen", 1,
                        "src/one.c", d, fails);
}
static int pcs_case_h(const char *base, int *fails)
{
    char d[4096];
    if (ovf(snprintf(d, sizeof d, "%s/h", base), sizeof d) || csr_mkdirs(d))
        return 2;
    if (pcs_fixture_base(d))
        return 2;
    const char *srcs[] = { "src/bogus.c", NULL };
    if (pcs_fixture_pkg(d, "fx/bogus", "lib/bogus", "\"CAP_TELEPATHY\"", srcs))
        return 2;
    const char *rows[] = { "lib/bogus/src/bogus.c CAP_NETWORK", NULL };
    if (pcs_fixture_rows(d, rows))
        return 2;
    return pcs_expect_rc("H: a class name absent from capability_classes.def fails", 1,
                        "not a class in", d, fails);
}
static int pcs_case_i(const char *base, int *fails)
{
    char d[4096];
    if (ovf(snprintf(d, sizeof d, "%s/i", base), sizeof d) || csr_mkdirs(d))
        return 2;
    if (pcs_fixture_base(d))
        return 2;
    const char *srcs[] = { "src/u.c", NULL };
    if (pcs_fixture_pkg(d, "fx/unsorted", "lib/unsorted",
                       "\"CAP_NETWORK\", \"CAP_FS_READ\"", srcs))
        return 2;
    const char *rows[] = { "lib/unsorted/src/u.c CAP_FS_READ|CAP_NETWORK", NULL };
    if (pcs_fixture_rows(d, rows))
        return 2;
    return pcs_expect_rc("I: an out-of-order capabilities array fails", 1,
                        "strictly ascending", d, fails);
}
static int pcs_case_j(const char *base, int *fails)
{
    char d[4096];
    if (ovf(snprintf(d, sizeof d, "%s/j", base), sizeof d) || csr_mkdirs(d))
        return 2;
    if (pcs_fixture_base(d))
        return 2;
    const char *srcs[] = { "src/shipped.c", NULL };
    if (pcs_fixture_pkg(d, "fx/narrow", "lib/narrow", "", srcs))
        return 2;
    char p[4096];
    if (ovf(snprintf(p, sizeof p, "%s/lib/narrow/src/unshipped.c", d), sizeof p))
        return 2;
    if (csr_write(p, ""))
        return 2;
    const char *rows[] = { "lib/narrow/src/unshipped.c CAP_NETWORK", NULL };
    if (pcs_fixture_rows(d, rows))
        return 2;
    return pcs_expect_rc("J: a file in the directory but not in files[] contributes "
                        "nothing", 0, "OK — every manifest", d, fails);
}

int check_package_capabilities_selftest(void)
{
    char base[4096];
    if (csr_mkdirs(env_or("TMPDIR", "test-tmp")))
        return 2;
    if (ovf(snprintf(base, sizeof base, "%s/z23-lint-pkgcap-selftest.XXXXXX",
                     env_or("TMPDIR", "test-tmp")), sizeof base))
        return 2;
    char *d0 = mkdtemp(base);
    if (!d0)
        return die("z23-lint: mkdtemp failed: %s\n", base);
    printf("== check_package_capabilities selftest ==\n");
    int fails = 0, rc = 0;
    if (rc == 0) rc = pcs_case_a(d0, &fails);
    if (rc == 0) rc = pcs_case_b(d0, &fails);
    if (rc == 0) rc = pcs_case_c(d0, &fails);
    if (rc == 0) rc = pcs_case_c2(d0, &fails);
    if (rc == 0) rc = pcs_case_c3(d0, &fails);
    if (rc == 0) rc = pcs_case_d(d0, &fails);
    if (rc == 0) rc = pcs_case_e(d0, &fails);
    if (rc == 0) rc = pcs_case_e2(d0, &fails);
    if (rc == 0) rc = pcs_case_e3(d0, &fails);
    if (rc == 0) rc = pcs_case_f1(d0, &fails);
    if (rc == 0) rc = pcs_case_f2(d0, &fails);
    if (rc == 0) rc = pcs_case_g1(d0, &fails);
    if (rc == 0) rc = pcs_case_g2(d0, &fails);
    if (rc == 0) rc = pcs_case_h(d0, &fails);
    if (rc == 0) rc = pcs_case_i(d0, &fails);
    if (rc == 0) rc = pcs_case_j(d0, &fails);
    rap_rm_rf(d0);
    if (rc)
        return rc;
    if (fails) {
        printf("== selftest: FAIL ==\n");
        return 1;
    }
    printf("== selftest: PASS (16/16) ==\n");
    return 0;
}
