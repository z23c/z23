/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: isolated production-entrypoint fixtures for live-datadir lint. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "gate_live_datadir_isolation_priv.h"

static const char k_def[] =
    "ZCL_COMMAND_READY_READ(\n"
    " \"sand.thing.peek\", \"sand.thing\", \"\", \"Peek\",\n"
    " \"Semantics, with comma and \\\"quote\\\".\", nested(1, 2),\n"
    " \"tag\", \"zcl.in.v1\", \"zcl.out.v1\", \"datadir\", \"\",\n"
    " \"example\", h_peek)\n"
    "ZCL_COMMAND_READY_READ(\"sand.other.poke\",\"\",\"\",\"\",\"\",0,\"\",\"\",\"\",\"service\",h)\n";
static const char k_clean[] =
    "snprintf(p, n, \"%s/.zclassic-c23-dev\", home);\n"
    "SetDataDir(p); GetDataDir(true, p, n);\n";
static const char k_doc[] = "z23 sand thing peek --datadir=/tmp/fixture\nz23 sand other poke\n";

struct ldi_case {
    const char *name, *test, *doc, *a, *c, *extra, *needle;
    int want;
};

static const struct ldi_case k_cases[] = {
    { "clean", k_clean, k_doc, "", "", "", "PASS", 0 },
    { "A", "\"%s/.zclassic-c23\"\n", k_doc, "", "", "", "PRONG A", 1 },
    { "A HOME", "\"$HOME/.zclassic\"\n", k_doc, "", "", "", "PRONG A", 1 },
    { "A tilde", "\"~/.zclassic-c23\"\n", k_doc, "", "", "", "PRONG A", 1 },
    { "constant root", "\"/fixture/home/.zclassic\"\n", k_doc, "", "", "", "PASS", 0 },
    { "A single-file real-path baseline", "\"%s/.zclassic\" \"~/.zclassic\"\n", k_doc, "@TEST@ 1 # hand analysis\n", "", "ZCL_LDI_CEILING_A=1", "prong A 1 site", 0 },
    { "A grew", "\"%s/.zclassic\"\n\"%s/.zclassic\"\n", k_doc, "@TEST@ 1\n", "", "ZCL_LDI_CEILING_A=1", "baseline allows 1", 1 },
    { "A stale", k_clean, k_doc, "@TEST@ 1\n", "", "ZCL_LDI_CEILING_A=1", "stale", 1 },
    { "zero stale row", k_clean, k_doc, "@TEST@ 0\n", "", "", "stale", 1 },
    { "A ceiling", "\"%s/.zclassic\"\n", k_doc, "@TEST@ 1\n", "", "", "exceeds ceiling", 1 },
    { "B", "GetDataDir(true,p,n);\n", k_doc, "", "", "", "PRONG B", 1 },
    { "B default", "GetDefaultDataDir(p,n);\n", k_doc, "", "", "", "PRONG B", 1 },
    { "B word boundary", "NotGetDataDir(p,n);\n", k_doc, "", "", "", "PASS", 0 },
    { "C", k_clean, "z23 sand thing peek\n", "", "", "", "PRONG C", 1 },
    { "C dev", k_clean, "z23-dev sand thing peek\n", "", "", "", "PRONG C", 1 },
    { "C migration", k_clean, "zclassic23 sand thing peek\n", "", "", "", "PRONG C", 1 },
    { "C substring exception", k_clean, "z23 sand thing peek # datadir documented\n", "", "", "", "PASS", 0 },
    { "C repetition per line", k_clean, "z23 sand thing peek ; z23 sand thing peek\n", "", "@DOC@ 1 # keep this\n", "ZCL_LDI_CEILING_C=1", "prong C 1 site", 0 },
    { "C stale", k_clean, k_doc, "", "@DOC@ 1\n", "ZCL_LDI_CEILING_C=1", "stale", 1 },
    { "WARN", "GetDataDir(p,n);\n", "z23 sand thing peek\n", "", "", "ZCL_LINT_MODE=WARN", "PRONG B", 0 },
    { "UPDATE", "\"%s/.zclassic\"\n", "z23 sand thing peek\n", "@TEST@ 1 # retain analysis\n", "@DOC@ 1 # retain doc analysis\n", "ZCL_LINT_MODE=UPDATE", "UPDATED", 0 },
    { "test floor", k_clean, k_doc, "", "", "ZCL_LDI_TEST_FLOOR=2", "FATAL", 2 },
    { "doc floor", k_clean, k_doc, "", "", "ZCL_LDI_DOC_FLOOR=2", "FATAL", 2 },
    { "leaf floor", k_clean, k_doc, "", "", "ZCL_LDI_LEAF_FLOOR=2", "FATAL", 2 },
    { "invalid baseline", k_clean, k_doc, "@TEST@ invalid\n", "", "", "non-numeric", 2 },
    { "invalid override", k_clean, k_doc, "", "", "ZCL_LDI_CEILING_A=invalid", "invalid", 2 },
};

static int ldi_fixture_base(const char *path, const char *text, const char *test, const char *doc)
{
    FILE *f = fopen(path, "w");
    if (!f) return die("z23-lint: cannot write %s\n", path);
    for (const char *p = text; *p; ) {
        if (!strncmp(p, "@TEST@", 6)) { fputs(test, f); p += 6; }
        else if (!strncmp(p, "@DOC@", 5)) { fputs(doc, f); p += 5; }
        else fputc(*p++, f);
    }
    int rc = ferror(f) ? die("z23-lint: write failed: %s\n", path) : 0;
    if (fclose(f) && !rc) rc = die("z23-lint: fclose failed: %s\n", path);
    return rc;
}

static int ldi_check_update(const char *path)
{
    char out[32768];
    FILE *f = fopen(path, "r");
    if (!f) return die("z23-lint: cannot open %s\n", path);
    int rc = csr_slurp(f, out, sizeof out);
    if (fclose(f) && !rc) rc = die("z23-lint: fclose failed: %s\n", path);
    if (rc || !strstr(out, "# retain analysis")) return die("z23-lint: UPDATE lost analysis comments\n", "");
    return 0;
}
static int ldi_case_run(const char *dir, const char *exe, const struct ldi_case *c)
{
    char t[2048], d[2048], a[2048], b[2048], cmd[16384], out[32768];
    if (ovf(snprintf(t, sizeof t, "%s/test.c", dir), sizeof t)
        || ovf(snprintf(d, sizeof d, "%s/doc.md", dir), sizeof d)
        || ovf(snprintf(a, sizeof a, "%s/a.txt", dir), sizeof a)
        || ovf(snprintf(b, sizeof b, "%s/c.txt", dir), sizeof b)) return 2;
    if (csr_write(t, c->test) || csr_write(d, c->doc)
        || ldi_fixture_base(a, c->a, t, d) || ldi_fixture_base(b, c->c, t, d)) return 2;
    int n = snprintf(cmd, sizeof cmd,
        "ZCL_LDI_TEST_GLOBS='%s' ZCL_LDI_DOC_GLOBS='%s' ZCL_LDI_DEF_DIR='%s/defs' "
        "ZCL_LDI_BASELINE_A='%s' ZCL_LDI_BASELINE_C='%s' ZCL_LDI_CEILING_A=0 ZCL_LDI_CEILING_C=0 "
        "ZCL_LDI_TEST_FLOOR=1 ZCL_LDI_DOC_FLOOR=1 ZCL_LDI_LEAF_FLOOR=1 ZCL_LINT_MODE=FAIL "
        "%s %s check-live-datadir-isolation 2>&1", t, d, dir, a, b, c->extra, exe);
    int code = 0;
    if (ovf(n, sizeof cmd) || capture_cmd(cmd, out, sizeof out, &code)) return 2;
    if (code != c->want || !strstr(out, c->needle)) {
        fprintf(stderr, "check_live_datadir_isolation: SELFTEST FAILED — %s (rc=%d, expected %d): %s\n", c->name, code, c->want, out);
        return 2;
    }
    if (!strcmp(c->name, "UPDATE")) return ldi_check_update(a);
    return 0;
}

static int ldi_port_adapter(void)
{
    char out[8192];
    for (int verdict = 0; verdict < 3; verdict++) {
        char cmd[2048];
        int n = snprintf(cmd, sizeof cmd,
            "bash -c '. tools/scripts/isolated_node_env.sh; z23_tcp_port_listening() { return %d; }; iso_assert_port_free 39070' 2>&1", verdict);
        int code = 0;
        if (ovf(n, sizeof cmd) || capture_cmd(cmd, out, sizeof out, &code)) return 2;
        if ((verdict == 1 && code) || (verdict != 1 && (!code || !strstr(out, verdict == 0 ? "LISTENING" : "UNOBSERVED"))))
            return die("check_live_datadir_isolation: SELFTEST FAILED — isolation adapter verdict\n", "");
    }
    return 0;
}

static int ldi_scratch_dir(char *dir, size_t cap)
{
    const char *tmp = getenv("TMPDIR");
    if (!tmp || !tmp[0]) {
        if (mkdir("./test-tmp", 0755) && errno != EEXIST)
            return die("z23-lint: cannot create ./test-tmp\n", "");
        tmp = "./test-tmp";
    }
    if (ovf(snprintf(dir, cap, "%s/z23-ldi-selftest.XXXXXX", tmp), cap)) return 2;
    if (!mkdtemp(dir)) return die("z23-lint: mkdtemp failed\n", "");
    return 0;
}

int check_live_datadir_isolation_selftest(void)
{
    char dir[4096], path[2048], exe[4096], quoted[16384];
    if (ldi_scratch_dir(dir, sizeof dir)) return 2;
    int rc = ovf(snprintf(path, sizeof path, "%s/defs/sand.def", dir), sizeof path);
    if (!rc) rc = csr_write(path, k_def);
    if (!rc) rc = lint_self_exe(exe, sizeof exe) || sh_single_quote(exe, quoted, sizeof quoted);
    if (!rc) rc = ldi_port_adapter();
    for (size_t i = 0; !rc && i < sizeof k_cases / sizeof k_cases[0]; i++) rc = ldi_case_run(dir, quoted, &k_cases[i]);
    if (rap_rm_rf(dir) && !rc) rc = die("z23-lint: fixture cleanup failed\n", "");
    if (!rc) puts("[check_live_datadir_isolation] SELFTEST PASS (prongs A/B/C, aliases, exact paths, baselines, comments, modes, scan floors and isolation port observations)");
    return rc ? 2 : 0;
}
