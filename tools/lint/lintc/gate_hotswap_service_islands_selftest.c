/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-hotswap-service-islands
 * (gate_hotswap_service_islands.c). The shell original carried no selftest,
 * so this provides one passing and one failing case. It builds a fixture
 * tree under build/ in the working tree (never a shared temp
 * directory): a multi-line HOTSWAP_SERVICE manifest row with a frozen
 * contract header, a probe-case file with exactly one resident case, and a
 * HOTSHADOW_OWNER row whose static shell routes to the fixture service. The
 * clean tree must pass (exit 0); adding a forbidden sqlite3_ call to the
 * island source must fail (exit 1). Removed afterwards.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"

int hsi_check(const char *manifest, const char *probes, const char *shadow,
              int fixture_mode, FILE *out);

enum { HS_PATH = 1024, HS_TEXT = 4096 };

static const char k_hs_src_rel[] = "engine/services/src/fixture_svc.c";
static const char k_hs_hdr_rel[] = "engine/services/src/fixture_svc.h";
static const char k_hs_shell_rel[] = "engine/services/src/fixture_shell.c";

static int hs_put(const char *root, const char *rel, const char *text)
{
    char path[HS_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/%s", root, rel), sizeof path))
        return 2;
    return csr_write(path, text);
}

static int hs_write_common(const char *root)
{
    char d[HS_PATH];
    if (ovf(snprintf(d, sizeof d, "%s/engine/services/src", root), sizeof d))
        return 2;
    int rc = csr_mkdirs(d);
    if (rc)
        return rc;
    rc = hs_put(root, "manifest.def",
                "HOTSWAP_SERVICE(\n"
                "  \"svc_fixture\",\n"
                "  \"engine/services/src/fixture_svc.c\",\n"
                "  \"-\",\n"
                "  \"engine/services/src/fixture_svc.h\",\n"
                "  \"zcl_host_open zcl_host_read\",\n"
                "  \"abi111\", \"sch111\", \"wir111\", \"kat111\",\n"
                "  \"probe_leaf\")\n");
    if (rc)
        return rc;
    rc = hs_put(root, "probe_cases.def",
                "/* fixture probe cases */\n"
                "\"probe_leaf\",\n");
    if (rc)
        return rc;
    rc = hs_put(root, "shadow_owners.def",
                "HOTSHADOW_OWNER(\"engine/services/src/fixture_shell.c\",\n"
                "  \"engine/services/src/fixture_svc.c\")\n");
    if (rc)
        return rc;
    rc = hs_put(root, k_hs_hdr_rel,
                "/* fixture contract: frozen fingerprints */\n"
                "static const char *k_abi = \"abi111\";\n"
                "static const char *k_schema = \"sch111\";\n"
                "static const char *k_wire = \"wir111\";\n"
                "static const char *k_kat = \"kat111\";\n");
    if (rc)
        return rc;
    return hs_put(root, k_hs_shell_rel,
                  "/* fixture static authority shell (not scanned) */\n"
                  "int fixture_shell_main(void) { return 0; }\n");
}

#define HS_SRC_HEAD \
    "#include \"fixture_svc.h\"\n" \
    "static const char *k_note = \"pure island\";\n" \
    "int svc_fixture_entry(int x)\n" \
    "{\n" \
    "    return zcl_host_open(x) + zcl_host_read(x);\n" \
    "}\n" \
    "int svc_dirty(void)\n" \
    "{\n"

static int hs_write_source(const char *root, int dirty)
{
    return hs_put(root, k_hs_src_rel,
                  dirty ? HS_SRC_HEAD "    return (int)sqlite3_open(0);\n}\n"
                        : HS_SRC_HEAD "    return 0;\n}\n");
}

static int hs_fixture_root(char *out, size_t cap)
{
    char cwd[HS_PATH];
    if (!getcwd(cwd, sizeof cwd))
        return die("z23-lint: getcwd failed for selftest scratch\n", "");
    if (ovf(snprintf(out, cap, "%s/build/z23-lint-hotswap-islands.XXXXXX",
                     cwd), cap))
        return 2;
    if (!mkdtemp(out))
        return die("z23-lint: mkdtemp failed for selftest scratch\n", "");
    return 0;
}

/* Runs one case; returns 0 when the gate answered the way the case expects. */
static int hs_run_case(const char *root, int dirty, int want)
{
    int rc = hs_write_common(root);
    if (rc)
        return rc;
    rc = hs_write_source(root, dirty);
    if (rc)
        return rc;
    char man[HS_PATH], probes[HS_PATH], shadow[HS_PATH];
    if (ovf(snprintf(man, sizeof man, "%s/manifest.def", root), sizeof man) ||
        ovf(snprintf(probes, sizeof probes, "%s/probe_cases.def", root),
            sizeof probes) ||
        ovf(snprintf(shadow, sizeof shadow, "%s/shadow_owners.def", root),
            sizeof shadow))
        return 2;
    FILE *sink = tmpfile();
    if (!sink)
        return die("z23-lint: tmpfile failed\n", "");
    char cwd[HS_PATH];
    if (!getcwd(cwd, sizeof cwd) || chdir(root))
        return die("z23-lint: chdir to selftest scratch failed\n", "");
    int got = hsi_check(man, probes, shadow, 0, sink);
    if (chdir(cwd))
        return die("z23-lint: chdir back failed\n", "");
    if (got != want) {
        char sb[2048];
        rewind(sink);
        size_t k = fread(sb, 1, sizeof sb - 1, sink);
        sb[k] = 0;
        fputs(sb, stderr);
    }
    fclose(sink);
    const char *name = dirty ? "sqlite3_ call in the island fails"
                             : "clean fixture passes";
    if (got != want) {
        fprintf(stderr,
                "check_hotswap_service_islands selftest: %s: want rc=%d "
                "got rc=%d\n", name, want, got);
        return 1;
    }
    printf("  selftest ok: %s (rc=%d)\n", name, got);
    return 0;
}

int check_hotswap_service_islands_selftest(void)
{
    char root[HS_PATH];
    int rc = hs_fixture_root(root, sizeof root);
    if (rc)
        return rc;
    int bad = hs_run_case(root, 0, 0) != 0;
    bad |= hs_run_case(root, 1, 1) != 0;
    rap_rm_rf(root);
    if (bad)
        fputs("FAIL: check_hotswap_service_islands selftest\n", stderr);
    return st_ok(bad, "check_hotswap_service_islands selftest: OK\n");
}
