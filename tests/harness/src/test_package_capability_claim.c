/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_package_capability_claim — the receiver-side capability re-derivation
 * (contexts/commons/modules/vcs/src/package_verify_capabilities.c).
 *
 * WHAT THIS GROUP IS FOR. Every zcode-package.json carries a "capabilities"
 * array, and tools/lint/check_package_capabilities.sh keeps it exactly equal
 * to what the shipped sources reach — in THIS tree, against THIS tree's
 * config/module_capabilities.def. A package that travels to a stranger
 * carries the array and none of the derivation. The unit under test is what
 * lets the stranger derive it again from the package bytes plus a table the
 * stranger holds, and the cases below are the four the design lives or dies
 * on:
 *
 *   REFUSED   — sources call connect() while the manifest claims [].
 *   VERIFIED  — an inert package with [] is cleared, so the suite cannot be
 *               satisfied by an implementation that simply always refuses.
 *   UNPROVEN  — no table is not "reaches nothing". Never VERIFIED.
 *   SUBSTITUTED TABLE — detected two independent ways: an out-of-band digest
 *               pin, and the anchor floor compiled into the receiver.
 *
 * Both ENDS of every list are pinned. A validator that cannot see the last
 * element of a list fails open for its entire life, and this repository has
 * already been bitten by exactly that (`printf | while read` dropping the
 * final field, same day). So a reach in the LAST shipped file and a reach in
 * a NON-LAST one are separate cases, as are a claim entry in the last and a
 * non-last array position. */

#include "test/test_core.h"

#include "vcs/package_verify_capabilities.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define PCC_CHECK(name, expr)                                    \
    do {                                                         \
        if (expr) {                                              \
            printf("  package_capability_claim: %s... OK\n", (name)); \
        } else {                                                 \
            printf("  package_capability_claim: %s... FAIL\n", (name)); \
            failures++;                                          \
        }                                                        \
    } while (0)

/* The real table this tree ships. The unit reads it as data, so the test
 * reads it as data too — a change to the row shape that this reader can no
 * longer parse must turn this group red rather than quietly halve the
 * vocabulary every package is graded against. */
#define PCC_REAL_TABLE "engine/composition/capability_symbols.def"

/* ── fixture plumbing ────────────────────────────────────────────── */

static bool pcc_mkdir_p(const char *path)
{
    char buf[1024];
    int w = snprintf(buf, sizeof(buf), "%s", path);
    if (w < 0 || (size_t)w >= sizeof(buf)) return false;
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        (void)mkdir(buf, 0755);
        *p = '/';
    }
    (void)mkdir(buf, 0755);
    struct stat st;
    return stat(buf, &st) == 0;
}

static bool pcc_write(const char *dir, const char *rel, const char *body)
{
    char path[1024];
    int w = snprintf(path, sizeof(path), "%s/%s", dir, rel);
    if (w < 0 || (size_t)w >= sizeof(path)) return false;
    char parent[1024];
    (void)snprintf(parent, sizeof(parent), "%s", path);
    char *slash = strrchr(parent, '/');
    if (slash) {
        *slash = '\0';
        if (!pcc_mkdir_p(parent)) return false;
    }
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    size_t n = strlen(body);
    bool ok = n == 0 || fwrite(body, 1, n, f) == n;
    return fclose(f) == 0 && ok;
}

/* A sound minimal table: every anchor the receiver floors on, a handful of
 * other classified rows, and enough CAP_HARMLESS filler to clear the
 * hollowness floor. Written by the test rather than copied from the tree so
 * that the substitution cases can perturb exactly one row. */
static bool pcc_write_table(const char *path, const char *connect_class,
                            const char *extra_rows)
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    fprintf(f, "/* fixture capability table */\n");
    fprintf(f, "ZCL_CAPABILITY_SYMBOL(\"connect\", %s, \"\")\n",
            connect_class);
    static const char *const net[] = { "socket", "bind", "listen", "send",
                                       "recv",   "accept" };
    for (size_t i = 0; i < sizeof(net) / sizeof(net[0]); i++)
        fprintf(f, "ZCL_CAPABILITY_SYMBOL(\"%s\", CAP_NETWORK, \"\")\n",
                net[i]);
    fprintf(f, "ZCL_CAPABILITY_SYMBOL(\"execve\", CAP_PROCESS, \"\")\n");
    fprintf(f, "ZCL_CAPABILITY_SYMBOL(\"fork\", CAP_PROCESS, \"\")\n");
    fprintf(f, "ZCL_CAPABILITY_SYMBOL(\"dlopen\", CAP_DYNLOAD, \"\")\n");
    fprintf(f, "ZCL_CAPABILITY_SYMBOL(\"setuid\", CAP_PRIVILEGE, \"\")\n");
    fprintf(f, "ZCL_CAPABILITY_SYMBOL(\"fopen\", CAP_FS_READ, \"\")\n");
    fprintf(f, "ZCL_CAPABILITY_SYMBOL(\"fwrite\", CAP_FS_WRITE, \"\")\n");
    /* A row whose class sits on the NEXT line, because seven rows in the
     * real table do exactly that and a reader that skipped only spaces and
     * tabs dropped all seven silently. */
    fprintf(f, "ZCL_CAPABILITY_SYMBOL(\"a_very_long_wrapped_symbol_name\",\n"
               "    CAP_FS_READ, \"\")\n");
    for (int i = 0; i < 80; i++)
        fprintf(f, "ZCL_CAPABILITY_SYMBOL(\"pcc_filler_%d\", CAP_HARMLESS,"
                   " \"\")\n",
                i);
    if (extra_rows) fputs(extra_rows, f);
    return fclose(f) == 0;
}

/* A manifest in the closed C23 v1 shape. caps is the literal array body, or
 * NULL for a manifest with no "capabilities" key at all. files is the
 * literal array body, or NULL to omit the key. */
static bool pcc_write_manifest(const char *dir, const char *caps,
                               const char *files)
{
    char body[4096];
    int w = snprintf(body, sizeof(body),
                     "{\n"
                     "  \"schema\": 1,\n"
                     "  \"name\": \"fx/case\",\n"
                     "  \"dependencies\": []%s%s%s%s%s%s\n"
                     "}\n",
                     caps ? ",\n  \"capabilities\": [" : "", caps ? caps : "",
                     caps ? "]" : "", files ? ",\n  \"files\": [" : "",
                     files ? files : "", files ? "]" : "");
    if (w < 0 || (size_t)w >= sizeof(body)) return false;
    return pcc_write(dir, "zcode-package.json", body);
}

struct pcc_case {
    char dir[512];
    char table[640];
};

static bool pcc_case_open(struct pcc_case *c, const char *tag)
{
    test_make_tmpdir(c->dir, sizeof(c->dir), "pkgcap", tag);
    int w = snprintf(c->table, sizeof(c->table), "%s/table.def", c->dir);
    return w > 0 && (size_t)w < sizeof(c->table);
}

static void pcc_case_close(struct pcc_case *c)
{
    test_rm_rf_recursive(c->dir);
}

static void pcc_run(const struct pcc_case *c, const char *table_path,
                    const uint8_t *pin, struct vcs_pkgcap_report *out)
{
    struct vcs_pkgcap_options options = {
        .package_dir = c->dir,
        .table_path = table_path,
        .expected_table_digest = pin,
    };
    (void)vcs_package_verify_capabilities(&options, out);
}

static bool pcc_derived_has(const struct vcs_pkgcap_report *r,
                            const char *name)
{
    for (uint32_t i = 0; i < r->derived.count; i++)
        if (strcmp(r->derived.names[i], name) == 0) return true;
    return false;
}

static bool pcc_finding_names(const struct vcs_pkgcap_report *r,
                              const char *class_name, const char *file)
{
    for (uint32_t i = 0; i < r->finding_count; i++)
        if (strcmp(r->findings[i].class_name, class_name) == 0 &&
            strcmp(r->findings[i].file, file) == 0)
            return true;
    return false;
}

/* ── A. the attack: reach exceeds the claim ──────────────────────── */

static int t_refused_undeclared_network(void)
{
    int failures = 0;
    struct pcc_case c;
    if (!pcc_case_open(&c, "refused")) return 1;

    bool built =
        pcc_write_table(c.table, "CAP_NETWORK", NULL) &&
        pcc_write(c.dir, "src/dialer.c",
                  "#include <sys/socket.h>\n"
                  "int dial(int fd, const struct sockaddr *a, unsigned n)\n"
                  "{\n"
                  "    return connect(fd, a, n);\n"
                  "}\n") &&
        pcc_write_manifest(c.dir, "", "\"src/dialer.c\"");
    PCC_CHECK("A: fixture built", built);

    struct vcs_pkgcap_report r;
    pcc_run(&c, c.table, NULL, &r);
    PCC_CHECK("A: a package calling connect() while claiming [] is REFUSED",
              r.verdict == VCS_PKGCAP_REFUSED);
    PCC_CHECK("A: the rule names the reach, not a generic failure",
              r.rule == VCS_PKGCAP_RULE_REACH_EXCEEDS_CLAIM);
    PCC_CHECK("A: CAP_NETWORK is in the derived set",
              pcc_derived_has(&r, "CAP_NETWORK"));
    PCC_CHECK("A: the finding names the class and the file",
              pcc_finding_names(&r, "CAP_NETWORK", "src/dialer.c"));
    PCC_CHECK("A: the finding is marked outside the claim",
              r.finding_count > 0 && r.findings[0].outside_claim);
    PCC_CHECK("A: the detail says connect", strstr(r.detail, "connect") != NULL);
    PCC_CHECK("A: no_excess_reach is false when reach exceeds the claim",
              !r.no_excess_reach);
    PCC_CHECK("A: a REFUSED verdict is not a VERIFIED one",
              r.verdict != VCS_PKGCAP_VERIFIED);

    pcc_case_close(&c);
    return failures;
}

/* ── B. the positive control ─────────────────────────────────────── */

static int t_verified_inert(void)
{
    int failures = 0;
    struct pcc_case c;
    if (!pcc_case_open(&c, "inert")) return 1;

    bool built = pcc_write_table(c.table, "CAP_NETWORK", NULL) &&
                 pcc_write(c.dir, "src/inert.c",
                           "int add(int a, int b) { return a + b; }\n") &&
                 pcc_write_manifest(c.dir, "", "\"src/inert.c\"");
    PCC_CHECK("B: fixture built", built);

    struct vcs_pkgcap_report r;
    pcc_run(&c, c.table, NULL, &r);
    PCC_CHECK("B: a genuinely inert package with [] is VERIFIED",
              r.verdict == VCS_PKGCAP_VERIFIED);
    PCC_CHECK("B: the rule is match", r.rule == VCS_PKGCAP_RULE_MATCH);
    PCC_CHECK("B: nothing was derived", r.derived.count == 0);
    PCC_CHECK("B: confinement is reported", r.no_excess_reach);
    PCC_CHECK("B: every listed source was scanned",
              r.sources_listed == 1 && r.sources_scanned == 1);

    pcc_case_close(&c);
    return failures;
}

/* A correct NON-EMPTY claim must also pass, so "always refuse unless the set
 * is empty" cannot satisfy this suite either. */
static int t_verified_declared(void)
{
    int failures = 0;
    struct pcc_case c;
    if (!pcc_case_open(&c, "declared")) return 1;

    bool built =
        pcc_write_table(c.table, "CAP_NETWORK", NULL) &&
        pcc_write(c.dir, "src/one.c",
                  "void go(void) { (void)socket(1, 2, 3); }\n") &&
        pcc_write(c.dir, "src/two.c",
                  "void put(void *p) { (void)fwrite(p, 1, 1, 0); }\n") &&
        pcc_write_manifest(c.dir, "\"CAP_FS_WRITE\", \"CAP_NETWORK\"",
                           "\"src/one.c\", \"src/two.c\"");
    PCC_CHECK("B2: fixture built", built);

    struct vcs_pkgcap_report r;
    pcc_run(&c, c.table, NULL, &r);
    PCC_CHECK("B2: a correct two-class declaration is VERIFIED",
              r.verdict == VCS_PKGCAP_VERIFIED);
    PCC_CHECK("B2: both classes were derived",
              pcc_derived_has(&r, "CAP_NETWORK") &&
                  pcc_derived_has(&r, "CAP_FS_WRITE"));

    pcc_case_close(&c);
    return failures;
}

/* ── C. UNPROVEN is never VERIFIED ───────────────────────────────── */

static int t_unproven_no_table(void)
{
    int failures = 0;
    struct pcc_case c;
    if (!pcc_case_open(&c, "notable")) return 1;

    bool built = pcc_write(c.dir, "src/inert.c",
                           "int add(int a, int b) { return a + b; }\n") &&
                 pcc_write_manifest(c.dir, "", "\"src/inert.c\"");
    PCC_CHECK("C: fixture built", built);

    char missing[768];
    (void)snprintf(missing, sizeof(missing), "%s/no-such-table.def", c.dir);

    struct vcs_pkgcap_report r;
    pcc_run(&c, missing, NULL, &r);
    PCC_CHECK("C: an absent table is UNPROVEN",
              r.verdict == VCS_PKGCAP_UNPROVEN);
    PCC_CHECK("C: the rule names the missing table",
              r.rule == VCS_PKGCAP_RULE_NO_TABLE);
    PCC_CHECK("C: an absent table is NOT a clearance",
              r.verdict != VCS_PKGCAP_VERIFIED);
    PCC_CHECK("C: no table digest is claimed when no table was read",
              !r.has_table_digest);

    /* The same package, this time with no table path supplied at all. */
    pcc_run(&c, NULL, NULL, &r);
    PCC_CHECK("C: a NULL table path is UNPROVEN, not an empty vocabulary",
              r.verdict == VCS_PKGCAP_UNPROVEN &&
                  r.rule == VCS_PKGCAP_RULE_NO_TABLE);

    /* A table that parses to nothing would derive [] for every package and
     * "clear" every empty claim off a scan that saw nothing. */
    if (!pcc_write(c.dir, "hollow.def", "/* no rows here */\n")) failures++;
    char hollow[768];
    (void)snprintf(hollow, sizeof(hollow), "%s/hollow.def", c.dir);
    pcc_run(&c, hollow, NULL, &r);
    PCC_CHECK("C: a table that parses to zero rows is UNPROVEN",
              r.verdict == VCS_PKGCAP_UNPROVEN &&
                  r.rule == VCS_PKGCAP_RULE_TABLE_HOLLOW);

    pcc_case_close(&c);
    return failures;
}

static int t_unproven_absent_claim(void)
{
    int failures = 0;
    struct pcc_case c;
    if (!pcc_case_open(&c, "absentclaim")) return 1;

    bool built = pcc_write_table(c.table, "CAP_NETWORK", NULL) &&
                 pcc_write(c.dir, "src/inert.c",
                           "int add(int a, int b) { return a + b; }\n") &&
                 pcc_write_manifest(c.dir, NULL, "\"src/inert.c\"");
    PCC_CHECK("C2: fixture built", built);

    struct vcs_pkgcap_report r;
    pcc_run(&c, c.table, NULL, &r);
    PCC_CHECK("C2: a manifest with no capabilities key is UNPROVEN",
              r.verdict == VCS_PKGCAP_UNPROVEN &&
                  r.rule == VCS_PKGCAP_RULE_CLAIM_ABSENT);
    PCC_CHECK("C2: absent is never read as the empty set",
              r.verdict != VCS_PKGCAP_VERIFIED);

    pcc_case_close(&c);
    return failures;
}

/* A claim WIDER than the derived reach is not a clearance either: the scan
 * under-approximates, so it cannot tell over-declaration from its own blind
 * spot. The confinement fact is still reported. */
static int t_unproven_claim_not_reached(void)
{
    int failures = 0;
    struct pcc_case c;
    if (!pcc_case_open(&c, "wideclaim")) return 1;

    bool built = pcc_write_table(c.table, "CAP_NETWORK", NULL) &&
                 pcc_write(c.dir, "src/inert.c",
                           "int add(int a, int b) { return a + b; }\n") &&
                 pcc_write_manifest(c.dir, "\"CAP_NETWORK\"",
                                    "\"src/inert.c\"");
    PCC_CHECK("C3: fixture built", built);

    struct vcs_pkgcap_report r;
    pcc_run(&c, c.table, NULL, &r);
    PCC_CHECK("C3: a claim wider than the derived reach is UNPROVEN",
              r.verdict == VCS_PKGCAP_UNPROVEN &&
                  r.rule == VCS_PKGCAP_RULE_CLAIM_NOT_REACHED);
    PCC_CHECK("C3: it is not VERIFIED",
              r.verdict != VCS_PKGCAP_VERIFIED);
    PCC_CHECK("C3: confinement is still reported separately",
              r.no_excess_reach);

    pcc_case_close(&c);
    return failures;
}

static int t_unproven_unreadable_source(void)
{
    int failures = 0;
    struct pcc_case c;
    if (!pcc_case_open(&c, "unreadable")) return 1;

    /* The manifest names a file the package does not carry. Skipping it
     * would make a manifest that names a file it does not ship look like a
     * smaller, cleaner package. */
    bool built = pcc_write_table(c.table, "CAP_NETWORK", NULL) &&
                 pcc_write(c.dir, "src/present.c", "int a(void){return 0;}\n") &&
                 pcc_write_manifest(c.dir, "",
                                    "\"src/present.c\", \"src/absent.c\"");
    PCC_CHECK("C4: fixture built", built);

    struct vcs_pkgcap_report r;
    pcc_run(&c, c.table, NULL, &r);
    PCC_CHECK("C4: a listed source that cannot be read is UNPROVEN",
              r.verdict == VCS_PKGCAP_UNPROVEN &&
                  r.rule == VCS_PKGCAP_RULE_SOURCE_UNREADABLE);
    PCC_CHECK("C4: an unread file is not a clean file", !r.no_excess_reach);

    pcc_case_close(&c);
    return failures;
}

/* ── D. a substituted table is detected ──────────────────────────── */

static int t_substituted_table(void)
{
    int failures = 0;
    struct pcc_case c;
    if (!pcc_case_open(&c, "substituted")) return 1;

    char honest[768];
    char swapped[768];
    (void)snprintf(honest, sizeof(honest), "%s/honest.def", c.dir);
    (void)snprintf(swapped, sizeof(swapped), "%s/swapped.def", c.dir);

    bool built =
        pcc_write_table(honest, "CAP_NETWORK", NULL) &&
        /* the substitution: connect declassified to harmless, everything
         * else identical */
        pcc_write_table(swapped, "CAP_HARMLESS", NULL) &&
        pcc_write(c.dir, "src/dialer.c",
                  "int dial(int fd) { return connect(fd, 0, 0); }\n") &&
        pcc_write_manifest(c.dir, "", "\"src/dialer.c\"");
    PCC_CHECK("D: fixture built", built);

    /* 1. The honest table refuses the package, which is the control: the
     *    substitution below has something to hide. */
    struct vcs_pkgcap_report honest_report;
    pcc_run(&c, honest, NULL, &honest_report);
    PCC_CHECK("D: control — the honest table REFUSES the dialer",
              honest_report.verdict == VCS_PKGCAP_REFUSED);
    PCC_CHECK("D: the honest table was digested",
              honest_report.has_table_digest);

    /* 2. THE ANCHOR FLOOR, with nothing pinned. A table that declassifies
     *    connect is refused before it grades anything. Without this, the
     *    swapped table would have cleared the dialer. */
    struct vcs_pkgcap_report swapped_report;
    pcc_run(&c, swapped, NULL, &swapped_report);
    PCC_CHECK("D: a table that declassifies connect is UNPROVEN, unpinned",
              swapped_report.verdict == VCS_PKGCAP_UNPROVEN &&
                  swapped_report.rule == VCS_PKGCAP_RULE_TABLE_UNSOUND);
    PCC_CHECK("D: the substituted table never yields VERIFIED",
              swapped_report.verdict != VCS_PKGCAP_VERIFIED);
    PCC_CHECK("D: the detail names the anchor",
              strstr(swapped_report.detail, "connect") != NULL);

    /* 3. THE DIGEST PIN. A table that keeps every anchor honest but is not
     *    the pinned one is still refused — this is the detector that covers
     *    the rarer symbol the anchor floor does not reach. */
    char benign[768];
    (void)snprintf(benign, sizeof(benign), "%s/benign.def", c.dir);
    if (!pcc_write_table(benign, "CAP_NETWORK",
                         "ZCL_CAPABILITY_SYMBOL(\"fwrite\", CAP_HARMLESS,"
                         " \"\")\n"))
        failures++;
    struct vcs_pkgcap_report pinned;
    pcc_run(&c, benign, honest_report.table_digest, &pinned);
    PCC_CHECK("D: a table that is not the pinned one is UNPROVEN",
              pinned.verdict == VCS_PKGCAP_UNPROVEN &&
                  pinned.rule == VCS_PKGCAP_RULE_TABLE_DIGEST_MISMATCH);
    PCC_CHECK("D: the pinned digest is reported even on mismatch",
              pinned.has_table_digest);

    /* 4. The pin accepts the table it names — otherwise case 3 would pass
     *    for a pin that rejects everything. */
    struct vcs_pkgcap_report matched;
    pcc_run(&c, honest, honest_report.table_digest, &matched);
    PCC_CHECK("D: the pin accepts the table it names (positive control)",
              matched.rule != VCS_PKGCAP_RULE_TABLE_DIGEST_MISMATCH &&
                  matched.verdict == VCS_PKGCAP_REFUSED);
    PCC_CHECK("D: the same table yields the same digest",
              memcmp(matched.table_digest, honest_report.table_digest, 32) ==
                  0);

    /* 5. A row this reader cannot finish is a symbol that silently became
     *    unclassified — indistinguishable from a table that deleted it. */
    char torn[768];
    (void)snprintf(torn, sizeof(torn), "%s/torn.def", c.dir);
    if (!pcc_write_table(torn, "CAP_NETWORK",
                         "ZCL_CAPABILITY_SYMBOL(\"mystery\", NOT_A_CLASS,"
                         " \"\")\n"))
        failures++;
    struct vcs_pkgcap_report torn_report;
    pcc_run(&c, torn, NULL, &torn_report);
    PCC_CHECK("D: a row this reader cannot parse makes the table UNSOUND",
              torn_report.verdict == VCS_PKGCAP_UNPROVEN &&
                  torn_report.rule == VCS_PKGCAP_RULE_TABLE_UNSOUND);

    pcc_case_close(&c);
    return failures;
}

/* ── E. both ends of both lists ──────────────────────────────────── */

static int t_list_ends(void)
{
    int failures = 0;
    struct vcs_pkgcap_report r;

    /* E1: the reach is in the LAST shipped file. */
    struct pcc_case last;
    if (!pcc_case_open(&last, "lastfile")) return 1;
    bool built =
        pcc_write_table(last.table, "CAP_NETWORK", NULL) &&
        pcc_write(last.dir, "src/one.c", "int a(void){return 0;}\n") &&
        pcc_write(last.dir, "src/two.c", "int b(void){return 0;}\n") &&
        pcc_write(last.dir, "src/three.c",
                  "int c(int fd){return connect(fd,0,0);}\n") &&
        pcc_write_manifest(last.dir, "",
                           "\"src/one.c\", \"src/two.c\", \"src/three.c\"");
    PCC_CHECK("E1: fixture built", built);
    pcc_run(&last, last.table, NULL, &r);
    PCC_CHECK("E1: reach in the LAST shipped source is seen",
              r.verdict == VCS_PKGCAP_REFUSED &&
                  pcc_finding_names(&r, "CAP_NETWORK", "src/three.c"));
    PCC_CHECK("E1: all three sources were scanned",
              r.sources_listed == 3 && r.sources_scanned == 3);
    pcc_case_close(&last);

    /* E2: the same defect in the FIRST shipped file. */
    struct pcc_case first;
    if (!pcc_case_open(&first, "firstfile")) return 1;
    built = pcc_write_table(first.table, "CAP_NETWORK", NULL) &&
            pcc_write(first.dir, "src/one.c",
                      "int a(int fd){return connect(fd,0,0);}\n") &&
            pcc_write(first.dir, "src/two.c", "int b(void){return 0;}\n") &&
            pcc_write(first.dir, "src/three.c", "int c(void){return 0;}\n") &&
            pcc_write_manifest(first.dir, "",
                               "\"src/one.c\", \"src/two.c\", "
                               "\"src/three.c\"");
    PCC_CHECK("E2: fixture built", built);
    pcc_run(&first, first.table, NULL, &r);
    PCC_CHECK("E2: reach in a NON-LAST shipped source is seen",
              r.verdict == VCS_PKGCAP_REFUSED &&
                  pcc_finding_names(&r, "CAP_NETWORK", "src/one.c"));
    pcc_case_close(&first);

    /* E3: the unreached class is the LAST entry of the claim array. */
    struct pcc_case tail;
    if (!pcc_case_open(&tail, "claimtail")) return 1;
    built = pcc_write_table(tail.table, "CAP_NETWORK", NULL) &&
            pcc_write(tail.dir, "src/w.c",
                      "void w(void *p){(void)fwrite(p,1,1,0);}\n") &&
            pcc_write_manifest(tail.dir,
                               "\"CAP_FS_WRITE\", \"CAP_NETWORK\"",
                               "\"src/w.c\"");
    PCC_CHECK("E3: fixture built", built);
    pcc_run(&tail, tail.table, NULL, &r);
    PCC_CHECK("E3: a claim entry in the LAST array position is graded",
              r.verdict == VCS_PKGCAP_UNPROVEN &&
                  r.rule == VCS_PKGCAP_RULE_CLAIM_NOT_REACHED &&
                  strstr(r.detail, "CAP_NETWORK") != NULL);
    PCC_CHECK("E3: the claim array kept both entries", r.claimed.count == 2);
    pcc_case_close(&tail);

    /* E4: the same defect in the FIRST claim position. */
    struct pcc_case head;
    if (!pcc_case_open(&head, "claimhead")) return 1;
    built = pcc_write_table(head.table, "CAP_NETWORK", NULL) &&
            pcc_write(head.dir, "src/n.c",
                      "int n(int fd){return connect(fd,0,0);}\n") &&
            pcc_write_manifest(head.dir, "\"CAP_FS_WRITE\", \"CAP_NETWORK\"",
                               "\"src/n.c\"");
    PCC_CHECK("E4: fixture built", built);
    pcc_run(&head, head.table, NULL, &r);
    PCC_CHECK("E4: a claim entry in a NON-LAST array position is graded",
              r.verdict == VCS_PKGCAP_UNPROVEN &&
                  r.rule == VCS_PKGCAP_RULE_CLAIM_NOT_REACHED &&
                  strstr(r.detail, "CAP_FS_WRITE") != NULL);
    pcc_case_close(&head);

    return failures;
}

/* ── F. what must NOT count as reach ─────────────────────────────── */

static int t_scanner_exclusions(void)
{
    int failures = 0;
    struct pcc_case c;
    if (!pcc_case_open(&c, "exclusions")) return 1;

    /* The fixture is scanned as TEXT and never compiled, which is what lets
     * `struct t` stay undefined here: the point is the token stream the
     * receiver walks, not a translation unit. Defining the struct would add
     * a member DECLARATION named connect, and a declaration is NOT excluded
     * — the same deliberate over-approximation as a local variable named
     * socket. This case pins what IS excluded, and nothing more. */
    bool built =
        pcc_write_table(c.table, "CAP_NETWORK", NULL) &&
        pcc_write(c.dir, "src/quiet.c",
                  "#include <sys/socket.h>\n"
                  "/* this comment mentions connect and socket */\n"
                  "// so does this one: connect\n"
                  "static const char *k = \"connect socket bind\";\n"
                  "int q(struct t *p)\n"
                  "{\n"
                  "    (void)k;\n"
                  "    return p->connect + (*p).connect;\n"
                  "}\n") &&
        pcc_write_manifest(c.dir, "", "\"src/quiet.c\"");
    PCC_CHECK("F: fixture built", built);

    struct vcs_pkgcap_report r;
    pcc_run(&c, c.table, NULL, &r);
    PCC_CHECK("F: comments, string literals, member access and an include "
              "line are not reach",
              r.verdict == VCS_PKGCAP_VERIFIED && r.derived.count == 0);

    /* The positive half of the same case: the exclusions must not be so
     * broad that a real call in the same file stops counting. */
    struct pcc_case live;
    if (!pcc_case_open(&live, "exclusions-live")) return 1;
    built = pcc_write_table(live.table, "CAP_NETWORK", NULL) &&
            pcc_write(live.dir, "src/loud.c",
                      "#include <sys/socket.h>\n"
                      "/* mentions connect in prose */\n"
                      "int q(int fd){ return connect(fd, 0, 0); }\n") &&
            pcc_write_manifest(live.dir, "", "\"src/loud.c\"");
    PCC_CHECK("F2: fixture built", built);
    pcc_run(&live, live.table, NULL, &r);
    PCC_CHECK("F2: a real call in a file full of prose still counts",
              r.verdict == VCS_PKGCAP_REFUSED &&
                  pcc_derived_has(&r, "CAP_NETWORK"));
    PCC_CHECK("F2: the finding is call-shaped and on the right line",
              r.finding_count > 0 && r.findings[0].call_shaped &&
                  r.findings[0].line == 3);
    pcc_case_close(&live);

    pcc_case_close(&c);
    return failures;
}

/* A shipped HEADER carries reach too. The nm-based gate never sees a header
 * as a translation unit; the receiver does, because the header is in the
 * bytes it was handed. */
static int t_shipped_header_counts(void)
{
    int failures = 0;
    struct pcc_case c;
    if (!pcc_case_open(&c, "header")) return 1;

    bool built = pcc_write_table(c.table, "CAP_NETWORK", NULL) &&
                 pcc_write(c.dir, "include/fx/dial.h",
                           "static inline int dial(int fd)\n"
                           "{ return connect(fd, 0, 0); }\n") &&
                 pcc_write(c.dir, "src/use.c", "int a(void){return 0;}\n") &&
                 pcc_write_manifest(c.dir, "",
                                    "\"include/fx/dial.h\", \"src/use.c\"");
    PCC_CHECK("G: fixture built", built);

    struct vcs_pkgcap_report r;
    pcc_run(&c, c.table, NULL, &r);
    PCC_CHECK("G: reach inside a shipped header is REFUSED",
              r.verdict == VCS_PKGCAP_REFUSED &&
                  pcc_finding_names(&r, "CAP_NETWORK", "include/fx/dial.h"));

    pcc_case_close(&c);
    return failures;
}

/* ── H. the real table this tree ships ───────────────────────────── */

static int t_real_table(void)
{
    int failures = 0;
    struct pcc_case c;
    if (!pcc_case_open(&c, "realtable")) return 1;

    bool built = pcc_write(c.dir, "src/dialer.c",
                           "int dial(int fd){return connect(fd,0,0);}\n") &&
                 pcc_write_manifest(c.dir, "", "\"src/dialer.c\"");
    PCC_CHECK("H: fixture built", built);

    struct vcs_pkgcap_report r;
    pcc_run(&c, PCC_REAL_TABLE, NULL, &r);

    /* The unit must be able to read the tree's own table. A red here means
     * the row shape moved and every package would be graded against a
     * vocabulary this reader only half understood — which is why the unit
     * refuses rather than grades when a row does not parse. */
    PCC_CHECK("H: the real capability table is readable and sound",
              r.rule != VCS_PKGCAP_RULE_NO_TABLE &&
                  r.rule != VCS_PKGCAP_RULE_TABLE_HOLLOW &&
                  r.rule != VCS_PKGCAP_RULE_TABLE_UNSOUND);
    PCC_CHECK("H: every row in the real table parsed",
              r.table_rows >= 400 && r.table_rows_classified >= 100);
    PCC_CHECK("H: a connect() call is REFUSED against the real table",
              r.verdict == VCS_PKGCAP_REFUSED &&
                  pcc_derived_has(&r, "CAP_NETWORK"));

    pcc_case_close(&c);
    return failures;
}

int test_package_capability_claim(void)
{
    printf("\n=== package_capability_claim: receiver-side capability "
           "re-derivation ===\n");
    int failures = 0;

    failures += t_refused_undeclared_network();
    failures += t_verified_inert();
    failures += t_verified_declared();
    failures += t_unproven_no_table();
    failures += t_unproven_absent_claim();
    failures += t_unproven_claim_not_reached();
    failures += t_unproven_unreadable_source();
    failures += t_substituted_table();
    failures += t_list_ends();
    failures += t_scanner_exclusions();
    failures += t_shipped_header_counts();
    failures += t_real_table();

    printf("package_capability_claim: %d failure(s)\n", failures);
    return failures;
}
