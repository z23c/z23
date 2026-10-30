/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: step 1 of the check-windows-acceptance gate — RECONCILE the
 * acceptance catalog against the tree. Ported from the reconcile_root
 * function of tools/lint/check_windows_acceptance.sh (deleted). Fails
 * closed everywhere: an undeclared program, an unparseable catalog, an
 * empty scan set, directory set, group registry or ID list are all hard
 * failures, never a clean pass, because a broken glob that reads as
 * "nothing to check" is exactly how two dead acceptance programs survived
 * under a green gate.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "lintc.h"
#include "gate_windows_acceptance_priv.h"

struct wa_lists {
    struct wa_ids tests, tests_sorted, source_ids;
    struct wa_names declared, dirs, groups, exempt, scanned;
};

static struct wa_lists g_wa;

/* The EXEMPT table: one row per file, path plus a written reason. A row
 * without a reason is refused by wa_exempt_reasonless. Keep this table
 * SHORT: an entry is a standing admission that the file is not covered by
 * this gate, so each reason says who does cover it. */
struct wa_exempt_row { const char *path; const char *reason; };
static const struct wa_exempt_row k_wa_exempt[] = {
    { "platform/modules/platform/tests/test_platform.c",
      "Not an acceptance program: it is the zclassic23/platform zcode package's own standalone test, shipped in the files list of platform/modules/platform/zcode-package.json. It carries its own AGENT_IMPACT_RULE in cognition/controllers/include/controllers/agent_impact_rules.def, which names the dev_platform and os_proc groups. Cross-linking it for Windows would say nothing the package pipeline does not already own." },
    { "platform/modules/base/tests/test_base.c",
      "Not an acceptance program: it is the zclassic23/base zcode package's own test binary. The Makefile builds and runs it as $(ZCODE_PACKAGE_BASE_TEST_BIN) and again under ASan as $(ZCODE_PACKAGE_BASE_ASAN_BIN), so it is executed natively on every run of those targets -- stronger evidence than a cross-link." },
    { "platform/modules/base/tests/cleanse_probe.c",
      "Not a program at all: it defines package_base_cleanse_probe() and no main(). It exists as a separate translation unit so memory_cleanse() cannot be optimised away, and it is compiled into both zcode base test binaries above." },
    { "platform/modules/platform/tests/cpu_affinity_android_acceptance.c",
      "Android Bionic-only affinity acceptance program: make ZCL_TARGET=android-arm64 android-acceptance cross-links it; android-acceptance-device executes it on the connected Android device. Its Bionic pthread API cannot be graded by a Windows cross-link." },
    { "platform/modules/platform/tests/thread_join_android_acceptance.c",
      "Android Bionic-only thread-join acceptance program: make ZCL_TARGET=android-arm64 android-acceptance cross-links it; android-acceptance-device executes it on the connected Android device. Its Bionic pthread API cannot be graded by a Windows cross-link." },
};

int wa_exempt_paths(struct wa_names *out)
{
    for (size_t i = 0; i < sizeof k_wa_exempt / sizeof k_wa_exempt[0]; i++) {
        if (out->n >= WA_NAMES) {
            fprintf(stderr, "check-windows-acceptance: exempt table exceeds %d\n",
                    WA_NAMES);
            return 2;
        }
        strcpy(out->v[out->n++], k_wa_exempt[i].path);
    }
    return 0;
}

int wa_exempt_reasonless(FILE *out)
{
    for (size_t i = 0; i < sizeof k_wa_exempt / sizeof k_wa_exempt[0]; i++) {
        const char *r = k_wa_exempt[i].reason;
        int blank = 1;
        for (; *r; r++)
            if (*r != ' ' && *r != '\t') {
                blank = 0;
                break;
            }
        if (blank) {
            fprintf(out,
                    "FAIL: EXEMPT row for '%s' carries no reason.\n"
                    "      An exemption without a written reason is just a hole.\n",
                    k_wa_exempt[i].path);
            return 1;
        }
    }
    return 0;
}

static int rc_exists(const char *root, const char *rel, FILE *out,
                     const char *what)
{
    char p[WA_PATH];
    struct stat st;
    if (ovf(snprintf(p, sizeof p, "%s/%s", root, rel), sizeof p))
        return 2;
    if (stat(p, &st) == 0 && S_ISREG(st.st_mode))
        return 0;
    fprintf(out, "FAIL: no %s at %s\n", what, p);
    return 1;
}

static int rc_load(const char *root, FILE *out)
{
    int rc = rc_exists(root, WA_CATALOG_REL, out, "acceptance catalog");
    if (rc)
        return rc;
    rc = rc_exists(root, WA_REGISTRY_REL, out, "test group registry");
    if (rc)
        return rc;
    if (wa_catalog_tests(root, &g_wa.tests))
        return 2;
    if (wa_catalog_source_ids(root, &g_wa.source_ids))
        return 2;
    if (wa_catalog_sources(root, &g_wa.declared))
        return 2;
    if (wa_catalog_program_dirs(root, &g_wa.dirs))
        return 2;
    if (wa_registry_groups(root, &g_wa.groups))
        return 2;
    if (wa_exempt_paths(&g_wa.exempt))
        return 2;
    return 0;
}

static void rc_print_iddiff(FILE *out, const struct wa_ids *a,
                            const struct wa_ids *b)
{
    fprintf(out, "--- active acceptance IDs\n+++ _SOURCES IDs\n");
    int i = 0, j = 0;
    while (i < a->n || j < b->n) {
        if (i >= a->n) {
            fprintf(out, "+%s\n", b->v[j++]);
        } else if (j >= b->n) {
            fprintf(out, "-%s\n", a->v[i++]);
        } else if (strcmp(a->v[i], b->v[j]) < 0) {
            fprintf(out, "-%s\n", a->v[i++]);
        } else if (strcmp(a->v[i], b->v[j]) > 0) {
            fprintf(out, "+%s\n", b->v[j++]);
        } else {
            i++;
            j++;
        }
    }
}

static int rc_ids_valid(FILE *out)
{
    if (g_wa.tests.n == 0) {
        fprintf(out, "FAIL: %s yielded no active acceptance IDs.\n",
                WA_CATALOG_REL);
        return 1;
    }
    g_wa.tests_sorted = g_wa.tests;
    wa_ids_sort(&g_wa.tests_sorted);
    if (wa_ids_dup(&g_wa.tests_sorted)) {
        fprintf(out, "FAIL: %s carries duplicate active acceptance IDs.\n",
                WA_CATALOG_REL);
        return 1;
    }
    if (!wa_ids_equal(&g_wa.tests_sorted, &g_wa.source_ids)) {
        fprintf(out,
                "FAIL: active acceptance IDs and _SOURCES IDs differ.\n"
                "      Every active ID must define one source row, and every source\n"
                "      row must be active so Make actually links its program.\n");
        rc_print_iddiff(out, &g_wa.tests_sorted, &g_wa.source_ids);
        return 1;
    }
    if (g_wa.source_ids.n < 1) {
        fprintf(out, "FAIL: %s yielded zero active source definitions.\n",
                WA_CATALOG_REL);
        return 1;
    }
    return 0;
}

static int rc_lists_valid(FILE *out)
{
    if (g_wa.declared.n == 0) {
        fprintf(out,
                "FAIL: %s named no .c sources at all.\n"
                "      A catalog this gate cannot read is worse than a missing row:\n"
                "      every program on disk would silently read as 'not required'.\n",
                WA_CATALOG_REL);
        return 1;
    }
    if (g_wa.dirs.n == 0) {
        fprintf(out,
                "FAIL: could not derive a single acceptance-program directory from\n"
                "      %s. The scan set comes from the first source of each\n"
                "      ZCL_WINDOWS_ACCEPTANCE_*_SOURCES row; if that row shape changed,\n"
                "      this gate is scanning nothing and must say so, not pass.\n",
                WA_CATALOG_REL);
        return 1;
    }
    if (g_wa.groups.n == 0) {
        fprintf(out,
                "FAIL: %s yielded no ZCL_TEST_GROUP rows.\n"
                "      The 'it is a registered suite group' escape hatch would then\n"
                "      accept nothing, turning real coverage into a false violation.\n",
                WA_REGISTRY_REL);
        return 1;
    }
    return wa_exempt_reasonless(out);
}

static int rc_scan(const char *root, FILE *out)
{
    char p[WA_PATH];
    struct stat st;
    for (int i = 0; i < g_wa.dirs.n; i++) {
        const char *d = g_wa.dirs.v[i];
        if (!d[0])
            continue;
        if (ovf(snprintf(p, sizeof p, "%s/%s", root, d), sizeof p))
            return 2;
        if (stat(p, &st) != 0 || !S_ISDIR(st.st_mode))
            continue;
        if (wa_scan_dir(root, d, &g_wa.scanned))
            return 2;
    }
    wa_names_sort_unique(&g_wa.scanned);
    if (g_wa.scanned.n != 0)
        return 0;
    fprintf(out,
            "FAIL: the acceptance-program scan set came back EMPTY.\n"
            "      Directories derived from the catalog:\n");
    for (int i = 0; i < g_wa.dirs.n; i++)
        fprintf(out, "          %s\n", g_wa.dirs.v[i]);
    fprintf(out,
            "      A broken glob must not read as clean. If those directories are\n"
            "      genuinely empty the catalog rows pointing into them are stale.\n");
    return 1;
}

static void rc_report_viol(FILE *out, const struct wa_names *viol)
{
    fprintf(out,
            "FAIL: acceptance program(s) on disk that NOTHING accounts for:\n");
    for (int i = 0; i < viol->n; i++)
        fprintf(out, "    %s\n", viol->v[i]);
    fprintf(out,
            "\n"
            "  Each file above is in a directory the acceptance catalog owns, and it\n"
            "  is none of: a source in a ZCL_WINDOWS_ACCEPTANCE_*_SOURCES row in\n"
            "  %s; the int test_<name>(void) entry of a group registered\n"
            "  in %s; an EXEMPT row with a written reason in this script.\n"
            "\n"
            "  A test file existing proves nothing runs it. Pick one:\n"
            "    - add a catalog row so mingw cross-links it, or\n"
            "    - rehome it into tests/harness/src as a registered group so the suite\n"
            "      EXECUTES it (strictly better, when the program has a POSIX arm), or\n"
            "    - exempt it here and say why.\n",
            WA_CATALOG_REL, WA_REGISTRY_REL);
}

static int rc_classify(const char *root, FILE *out)
{
    static struct wa_names viol;
    viol.n = 0;
    int nd = 0, ng = 0, ne = 0;
    char p[WA_PATH * 2];
    for (int i = 0; i < g_wa.scanned.n; i++) {
        const char *rel = g_wa.scanned.v[i];
        if (wa_has(&g_wa.declared, rel)) {
            nd++;
            continue;
        }
        if (ovf(snprintf(p, sizeof p, "%s/%s", root, rel), sizeof p))
            return 2;
        if (wa_file_group(p, &g_wa.groups)) {
            ng++;
            continue;
        }
        if (wa_has(&g_wa.exempt, rel)) {
            ne++;
            continue;
        }
        if (viol.n >= WA_NAMES) {
            fprintf(stderr, "check-windows-acceptance: violations exceed %d\n",
                    WA_NAMES);
            return 2;
        }
        strcpy(viol.v[viol.n++], rel);
    }
    if (viol.n) {
        rc_report_viol(out, &viol);
        return 1;
    }
    fprintf(out,
            "check-windows-acceptance: reconcile PASS — %d program(s) scanned in %d dir(s): %d catalog-declared, %d registered suite group(s), %d exempt.\n",
            g_wa.scanned.n, g_wa.dirs.n, nd, ng, ne);
    return 0;
}

int wa_reconcile_root(const char *root, FILE *out)
{
    memset(&g_wa, 0, sizeof g_wa);
    int rc = rc_load(root, out);
    if (rc)
        return rc;
    rc = rc_ids_valid(out);
    if (rc)
        return rc;
    rc = rc_lists_valid(out);
    if (rc)
        return rc;
    rc = rc_scan(root, out);
    if (rc)
        return rc;
    return rc_classify(root, out);
}
