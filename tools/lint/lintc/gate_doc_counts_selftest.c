/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the self-check and selftest of check-doc-counts. The self-check
 * runs before every tree scan: the prose matchers scan a hermetic fixture of
 * known-good and known-bad prose and the gate aborts unless exactly the
 * expected eight violations appear, all in the bad file. A gate that reports
 * clean because it can no longer fail is the failure mode it exists to
 * prevent. The selftest adds the claim-number parse and the --fix rewrite.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <string.h>
#include "lintc.h"
#include "gate_doc_counts_priv.h"

static struct dcn_viol g_dcn_st_viol;
static char g_dcn_st_files[3][DCN_PATH];

static int dcn_st_write(const char *dir, const char *name, int idx,
                        const char *text)
{
    if (ovf(snprintf(g_dcn_st_files[idx], DCN_PATH, "%s/%s", dir, name),
            DCN_PATH))
        return 2;
    return csr_write(g_dcn_st_files[idx], text);
}

static int dcn_st_fixture(const char *dir, const struct dcn_counts *c)
{
    char good[1024], bad[1024], sup[512];
    long atl = c->groups > 1 ? c->groups - 1 : 1;
    if (ovf(snprintf(good, sizeof good,
        "The suite has %ld parallel groups.\n"
        "There are %ld port interfaces and %ld persistence adapters.\n"
        "More than %ld+ parallel groups run per CI pass.\n"
        "Unrelated prose: 8 groups of peers, 3 ports, 12 conditions were "
        "met.\n"
        "The catalog is %ld command bundles under %ld command roots.\n"
        "It exposes %ld dumpstate subsystems across %ld shape folders.\n"
        "Unrelated prose: 4 bundles arrived, 3 roots were pruned, 9 "
        "subsystems rebooted.\n", c->groups, c->ports, c->adapters, atl,
        c->bundles, c->roots, c->dumpstate, c->shapes), sizeof good) ||
        ovf(snprintf(bad, sizeof bad,
        "%ld parallel groups\n%ld port interfaces\n"
        "%ld+ registered test groups\n1500+ tests\n%ld command bundles\n"
        "%ld command roots\n%ld dumpstate subsystems\n%ld shape folders\n",
        c->groups + 1, c->ports + 1, c->groups + 5, c->bundles + 1,
        c->roots - 1, c->dumpstate - 5, c->shapes + 1), sizeof bad) ||
        ovf(snprintf(sup, sizeof sup,
        "%ld parallel groups <!-- doc-count-ok: fixture -->\n"
        "1500+ tests <!-- doc-count-ok: fixture -->\n", c->groups + 1),
            sizeof sup))
        return 2;
    int rc = dcn_st_write(dir, "good.md", 0, good); // error-doc-ref-ok: selftest fixture name
    rc = rc ? rc : dcn_st_write(dir, "bad.md", 1, bad); // error-doc-ref-ok: selftest fixture name
    return rc ? rc : dcn_st_write(dir, "suppressed.md", 2, sup); // error-doc-ref-ok: selftest fixture name
}

static int dcn_st_judge(void)
{
    int total = g_dcn_st_viol.n, in_bad = 0;
    for (int i = 0; i < total; i++)
        if (strstr(g_dcn_st_viol.t[i], "bad.md")) // error-doc-ref-ok: selftest fixture name
            in_bad++;
    if (total == 8 && in_bad == 8)
        return 0;
    fputs("FAIL: check_doc_counts self-check broken — the prose matcher no "
          "longer\n      behaves as specified, so a clean tree scan would "
          "prove nothing.\n      expected 8 violations (one per derived "
          "rule, plus the denylist\n      phrase), all in bad.md; got ", // error-doc-ref-ok: selftest fixture name
          stderr);
    fprintf(stderr, "%d total,\n      %d in bad.md:\n        ", total, in_bad); // error-doc-ref-ok: selftest fixture name
    for (int i = 0; i < total; i++)
        fprintf(stderr, "%s%s", i ? "\n" : "", g_dcn_st_viol.t[i]);
    fputc('\n', stderr);
    return 1;
}

int dcn_selfcheck(const struct dcn_counts *c)
{
    char dir[DCN_PATH];
    int rc = lint_mkdtemp(dir, sizeof dir, "doc-counts");
    if (rc)
        return rc;
    g_dcn_st_viol.n = 0;
    rc = dcn_st_fixture(dir, c);
    rc = rc ? rc : dcn_scan(c, g_dcn_st_files, 3, &g_dcn_st_viol);
    rap_rm_rf(dir);
    return rc ? 2 : dcn_st_judge();
}

static int dcn_st_numbers(void)
{
    int plus = 0;
    int bad = dcn_claim_number("1,500+ tests", &plus) != 1500 || !plus;
    bad |= dcn_claim_number("007 ports", &plus) != 7 || plus;
    bad |= dcn_claim_number("12,3 x", &plus) != 123 || plus;
    return bad;
}

static int dcn_st_rewrite(void)
{
    static const struct dcn_counts c = { 1, 5, 6, 7, 8, 9, 10, 11 };
    char dir[DCN_PATH], path[DCN_PATH + 16], got[256] = "";
    if (lint_mkdtemp(dir, sizeof dir, "doc-counts-fix") ||
        ovf(snprintf(path, sizeof path, "%s/map.md", dir), sizeof path))
        return 1;
    int bad = csr_write(path, "# t\nport_interfaces : 1\n  command_roots: 2\n"
                              "command_roots :3");
    bad |= dcn_rewrite_file(path, &c) != 0;
    FILE *f = bad ? NULL : fopen(path, "r");
    if (f) {
        bad |= csr_slurp(f, got, sizeof got) != 0;
        fclose(f);
    }
    rap_rm_rf(dir);
    return bad || strcmp(got, "# t\nport_interfaces : 5\n  command_roots: 2\n"
                              "command_roots : 9") != 0;
}

int check_doc_counts_selftest(void)
{
    static const struct dcn_counts c = { 100, 13, 14, 56, 36, 16, 167, 7 };
    int bad = dcn_st_numbers();
    bad |= dcn_st_rewrite();
    bad |= dcn_selfcheck(&c) != 0;
    return st_ok(bad, "check_doc_counts selftest: OK\n");
}
