/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-telemetry-ontology
 * (gate_telemetry_ontology.c). Runs the whole 13-case trip/recover matrix
 * from the shell original: the real tree passes, the checked-in known-bad
 * fixture trips, a hollow manifest is fatal, and one case per way a TABLE
 * row can be violated (unresolved leaf, wrong domain, floor breach,
 * hand-written JSON in a fill provider, empty means, mis-paired TL_SUB,
 * half-registered domain, fill-provider count drift both directions).
 * Every bad input is built in a throwaway directory; the pinned ends never
 * depend on the state of the real tree.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_telemetry_ontology_priv.h"

enum { TOS_PATH = 768, TOS_TEXT = 1024, TOS_CAP = 262144 };

static const char *k_tos_env[] = {
    "ZCL_TELEMETRY_SCAN_MANIFEST", "ZCL_TELEMETRY_SCAN_EXTRA_MANIFEST",
    "ZCL_TELEMETRY_ONTOLOGY_DEF", "ZCL_TELEMETRY_DOMAINS_DEF",
    "ZCL_TELEMETRY_FIELDS_DIR", "ZCL_TELEMETRY_ONTOLOGY_TU",
    "ZCL_TELEMETRY_FILL_SCAN_ROOTS", "ZCL_TELEMETRY_FILL_PROVIDER_COUNT",
    NULL
};

static char g_tos_cap[TOS_CAP];

static void tos_dump(void)
{
    const char *p = g_tos_cap;
    while (p && *p) {
        const char *nl = strchr(p, '\n');
        int n = nl ? (int)(nl - p) : (int)strlen(p);
        fprintf(stderr, "    | %.*s\n", n, p);
        if (!nl)
            break;
        p = nl + 1;
    }
}

/* Runs the gate in-process with NAME=VALUE overrides (NULL = none), merged
 * streams, and checks rc plus an output substring. */
static int tos_run(const char *label, int want, const char *sub,
                   const char *e1, const char *e2)
{
    for (int i = 0; k_tos_env[i]; i++)
        unsetenv(k_tos_env[i]);
    const char *es[2] = { e1, e2 };
    for (int i = 0; i < 2; i++) {
        if (!es[i])
            continue;
        char name[TOS_PATH];
        const char *eq = strchr(es[i], '=');
        if (!eq)
            return die("z23-lint: bad selftest env pair %s\n", es[i]);
        size_t n = (size_t)(eq - es[i]);
        if (n >= sizeof name)
            return die("z23-lint: bad selftest env pair %s\n", es[i]);
        memcpy(name, es[i], n);
        name[n] = '\0';
        setenv(name, eq + 1, 1);
    }
    FILE *f = tmpfile();
    if (!f)
        return die("z23-lint: tmpfile failed\n", "");
    int got = to_check(f, f);
    rewind(f);
    size_t n = fread(g_tos_cap, 1, sizeof g_tos_cap - 1, f);
    g_tos_cap[n] = '\0';
    fclose(f);
    if (got != want) {
        fprintf(stderr,
                "check_telemetry_ontology --selftest: FAIL — %s: rc=%d want=%d\n",
                label, got, want);
        tos_dump();
        return 1;
    }
    if (sub && !strstr(g_tos_cap, sub)) {
        fprintf(stderr,
                "check_telemetry_ontology --selftest: FAIL — %s: output lacks '%s'\n",
                label, sub);
        tos_dump();
        return 1;
    }
    printf("  ok  %s (rc=%d)\n", label, got);
    return 0;
}

static int tos_write(const char *path, const char *text)
{
    return csr_write(path, text) ? 2 : 0;
}

static int tos_table(const char *path, const char *dom, const char *grp,
                     const char *mem, const char *means)
{
    char text[TOS_TEXT];
    if (ovf(snprintf(text, sizeof text,
                     "TL_DOMAIN_META(%s, \"zcl.telemetry.%s.selftest\", \"selftest table\")\n"
                     "TL_GROUP(%s, \"selftest group\")\n"
                     "TL_LEAF(%s, %s, TLC_I64, TFU_UNIX_TIME, TLV_NORMAL,\n"
                     "    TFR_INFO, TL_NONE, 0, TFS_INFO,\n"
                     "    \"%s\",\n"
                     "    \"\", \"\")\n"
                     "TL_GROUP_END(%s)\n",
                     dom, dom, grp, grp, mem, means, grp), sizeof text))
        return 2;
    return tos_write(path, text);
}

static int tos_extra(const char *path, const char *def, int minrows)
{
    char text[TOS_PATH];
    if (ovf(snprintf(text, sizeof text, "TABLE runtime %s %d\n", def, minrows),
             sizeof text))
        return 2;
    return tos_write(path, text);
}

static int tos_make_fill(const char *dir, const char *dom)
{
    if (csr_mkdirs(dir))
        return 2;
    char path[TOS_PATH], text[512];
    if (ovf(snprintf(path, sizeof path, "%s/%s_telemetry_fill.c", dir, dom),
             sizeof path))
        return 2;
    if (ovf(snprintf(text, sizeof text,
                     "bool %s_dump_state_fill(struct %s_snapshot *snap)\n"
                     "{\n"
                     "    TELEMETRY_SET_I64(snap, collected_unix, telemetry_now_unix(),\n"
                     "                      TELEMETRY_SRC_IN_PROCESS);\n"
                     "    return true;\n"
                     "}\n",
                     dom, dom), sizeof text))
        return 2;
    return tos_write(path, text);
}

struct tos_copy_ctx {
    FILE *f;
    int mode; /* 0: re-pair TL_SUB agents to wallet; 1: drop metaverse */
};

static int tos_copy_line(void *v, const char *line, size_t len)
{
    (void)len;
    struct tos_copy_ctx *c = v;
    if (c->mode == 1 && strstr(line, "telemetry/metaverse_fields.def"))
        return 0;
    if (c->mode == 0 && strstr(line, "#define TL_SUB \"agents\"")) {
        fputs("#define TL_SUB \"wallet\"\n", c->f);
        return 0;
    }
    fputs(line, c->f);
    fputc('\n', c->f);
    return 0;
}

static int tos_copy_tu(const char *dst, int mode)
{
    FILE *out = fopen(dst, "w");
    if (!out)
        return die("z23-lint: cannot write selftest fixture %s\n", dst);
    struct tos_copy_ctx c = { out, mode };
    int rc = to_each_line(
        "platform/modules/util/src/telemetry_ontology.c", NULL,
        tos_copy_line, &c);
    fclose(out);
    return rc ? 2 : 0;
}

#define TOS_MEANS "a leaf that exists only for the gate self-test"

/* Builds <td>/<name>.def (a one-leaf table) and <td>/<name>.txt (a TABLE row
 * with floor), then runs the gate with the .txt as the extra manifest. */
static int tos_case_table(const char *td, const char *name, const char *label,
                          const char *dom, const char *mem, const char *means,
                          int floor, int want, const char *sub)
{
    char def[TOS_PATH], txt[TOS_PATH], env[TOS_PATH + 64];
    if (ovf(snprintf(def, sizeof def, "%s/%s.def", td, name), sizeof def) ||
        ovf(snprintf(txt, sizeof txt, "%s/%s.txt", td, name), sizeof txt) ||
        ovf(snprintf(env, sizeof env,
                     "ZCL_TELEMETRY_SCAN_EXTRA_MANIFEST=%s", txt), sizeof env))
        return 2;
    if (tos_table(def, dom, "meta", mem, means) || tos_extra(txt, def, floor))
        return 2;
    return tos_run(label, want, sub, env, NULL);
}

/* 7: a fill provider hand-writing JSON instead of filling the struct. */
static int tos_case_json(const char *td)
{
    char dir[TOS_PATH], path[TOS_PATH], env[TOS_PATH + 64];
    if (ovf(snprintf(dir, sizeof dir, "%s/fillroot", td), sizeof dir) ||
        ovf(snprintf(path, sizeof path, "%s/runtime_telemetry_fill.c", dir),
            sizeof path) ||
        ovf(snprintf(env, sizeof env, "ZCL_TELEMETRY_FILL_SCAN_ROOTS=%s", dir),
            sizeof env))
        return 2;
    if (csr_mkdirs(dir) ||
        tos_write(path,
                  "bool runtime_dump_state_fill(struct runtime_snapshot *snap)\n"
                  "{\n"
                  "    json_push_kv_int(out, \"smuggled_field\", 1);\n"
                  "    return true;\n"
                  "}\n"))
        return 2;
    return tos_run("7 fill provider hand-writes JSON", 1,
                   "PROVIDER HAND-WRITES JSON", env, NULL);
}

/* 9/10: a copy of the paste-site TU, re-paired (mode 0) or with one domain
 * dropped (mode 1). */
static int tos_case_tu(const char *td, int mode, const char *label,
                       const char *sub)
{
    char tu[TOS_PATH], env[TOS_PATH + 64];
    if (ovf(snprintf(tu, sizeof tu, "%s/tu%d.c", td, mode), sizeof tu) ||
        ovf(snprintf(env, sizeof env, "ZCL_TELEMETRY_ONTOLOGY_TU=%s", tu),
            sizeof env))
        return 2;
    if (tos_copy_tu(tu, mode))
        return 2;
    return tos_run(label, 1, sub, env, NULL);
}

/* 11/12/12b: both ends of the fill-provider count are pinned per case. */
static int tos_case_count(const char *td, const char *dir, int providers,
                          int recorded, const char *label, int want,
                          const char *sub)
{
    char root[TOS_PATH], cnt[TOS_PATH], e1[TOS_PATH + 64], e2[TOS_PATH + 64];
    char text[16];
    if (ovf(snprintf(root, sizeof root, "%s/%s", td, dir), sizeof root) ||
        ovf(snprintf(cnt, sizeof cnt, "%s/%s_count.txt", td, dir), sizeof cnt) ||
        ovf(snprintf(text, sizeof text, "%d\n", recorded), sizeof text) ||
        ovf(snprintf(e1, sizeof e1, "ZCL_TELEMETRY_FILL_SCAN_ROOTS=%s", root),
            sizeof e1) ||
        ovf(snprintf(e2, sizeof e2, "ZCL_TELEMETRY_FILL_PROVIDER_COUNT=%s", cnt),
            sizeof e2))
        return 2;
    if (tos_make_fill(root, "runtime") ||
        (providers > 1 && tos_make_fill(root, "network")) ||
        tos_write(cnt, text))
        return 2;
    return tos_run(label, want, sub, e1, e2);
}

static int tos_matrix_a(const char *td)
{
    int bad = 0;
    bad |= tos_run("1 real tree", 0, "PASS", NULL, NULL);
    bad |= tos_run("2 checked-in known-bad FUNC+TABLE fixtures", 1,
                   "runtime|values.fixture_group.leaf_that_ships_with_no_meaning",
                   "ZCL_TELEMETRY_SCAN_EXTRA_MANIFEST=tools/lint/fixtures/telemetry_scan_extra.txt",
                   NULL);
    bad |= tos_run("3 hollow scan manifest", 2, "FATAL",
                   "ZCL_TELEMETRY_SCAN_MANIFEST=", NULL);
    bad |= tos_case_table(td, "bogus_leaf", "4 TL_LEAF with no ontology row",
                          "runtime", "not_a_registered_leaf", TOS_MEANS, 1, 1,
                          "runtime|values.meta.not_a_registered_leaf");
    bad |= tos_case_table(td, "wrong_domain",
                          "5 table declares a different domain", "wallet",
                          "collected_unix", TOS_MEANS, 1, 1, "TABLE MISMATCH");
    bad |= tos_case_table(td, "one_leaf",
                          "6 leaf count below the shrink-only floor", "runtime",
                          "collected_unix", TOS_MEANS, 2, 1,
                          "TABLE FLOOR BREACHED");
    bad |= tos_case_json(td);
    bad |= tos_case_table(td, "empty_means", "8 TL_LEAF with an empty means",
                          "runtime", "collected_unix", "", 1, 1, "empty means");
    return bad;
}

static int tos_matrix_b(const char *td)
{
    int bad = 0;
    bad |= tos_case_tu(td, 0, "9 mis-paired TL_SUB over a field table",
                       "MIS-PAIRED PASTE");
    bad |= tos_case_tu(td, 1, "10 registered domain never pasted",
                       "HALF-REGISTERED DOMAIN");
    bad |= tos_case_count(td, "twofill", 2, 1,
                          "11 a new fill provider must be recorded", 1,
                          "FILL PROVIDER COUNT GREW");
    bad |= tos_case_count(td, "onefill", 1, 2,
                          "12 a vanished fill provider is not silently unscanned",
                          1, "FILL PROVIDER COUNT DROPPED");
    bad |= tos_case_count(td, "pinfill", 1, 1,
                          "12b a matching pinned pair passes", 0, "PASS");
    bad |= tos_run("13 real tree recovers", 0, "PASS", NULL, NULL);
    return bad;
}

int check_telemetry_ontology_selftest(void)
{
    const char *base = env_or("TMPDIR", "test-tmp");
    char td[TOS_PATH];
    if (csr_mkdirs(base) != 0
        || ovf(snprintf(td, sizeof td, "%s/z23-lint-tele-onto.XXXXXX", base),
            sizeof td))
        return 2;
    if (!mkdtemp(td))
        return die("z23-lint: mkdtemp failed for selftest scratch\n", "");
    int bad = tos_matrix_a(td);
    bad |= tos_matrix_b(td);
    rap_rm_rf(td);
    if (bad) {
        fputs("check_telemetry_ontology: --selftest FAILED\n", stderr);
        return 1;
    }
    printf("check_telemetry_ontology: --selftest passed (13 cases)\n");
    return 0;
}
