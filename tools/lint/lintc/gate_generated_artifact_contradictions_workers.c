/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates: check-generated-artifact-contradictions
 * Fourth file of the check-generated-artifact-contradictions family (the
 * 700-line family ceiling split): the gate's --selftest probes. The gate
 * body (discovery, the verdict chain, the entry) and the family's parity
 * notes live in gate_generated_artifact_contradictions.c; the native
 * scanners live in gate_generated_artifact_contradictions_scan.c.
 */

/* ── --selftest ────────────────────────────────────────────────────────────
 * Byte-parity port of the original script's --selftest block: a mktemp
 * fixture tree with a compatible arm/capability pair, proving the
 * compatible pair passes (exit 0), that an absent arm artifact is named
 * UNPROVEN and exits 2 (the unproven-scan convention), and that an
 * aggregate-constant conflict is named CONTRADICTION and exits 1 (red).
 *
 * Semantic mapping:
 * - mktemp -d "${TMPDIR:-/tmp}/zcl-artifact-contradiction.XXXXXX" is
 *   gacw_setup's mkdtemp (env_or's unset-or-empty fallback matches
 *   ${TMPDIR:-/tmp}); the trap's rm -rf is rap_rm_rf on every exit path.
 * - Fixture directories and files are csr_mkdirs / csr_write (checked,
 *   parent-creating); the two mv renames are rename(2); the conflict
 *   fixture is the shell's per-line first-occurrence substitution (the
 *   BRE's dots can only match the literal bytes in this fixed fixture,
 *   so a fixed-string replacement is the same edit).
 * - Each inner `"$0"` run is setenv of all three ZCL_ARTIFACT_* variables
 *   plus the gate FOR REAL through the runtime's self-exec helper with
 *   merged streams — the call sites' `>log 2>&1`. The pass case replays
 *   at most the first 100 captured lines before its SELFTEST FAIL (sed
 *   -n '1,100p'); the absent and conflict cases grep the capture for
 *   their verdict word (strstr). Selftest failures are exit 1, as the
 *   script's; mktemp/rename failures are die() exit 2 (environment
 *   class, the describe-budget precedent).
 * - The setenv assignments persist in-process where the shell's were
 *   per-command; every inner run sets all three variables and the
 *   process exits when the selftest ends, so no snapshot/restore is
 *   needed (the controller-private-headers precedent).
 * - The merged capture is bounded (64 KiB); the shell's log file was
 *   not. Overflow die()s, fail-closed.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"

static const char k_gacw_gate[] = "check-generated-artifact-contradictions";
static char g_gacw_tmp[4096];
enum { GACW_SINK = 65536 };
static char g_gacw_sink[GACW_SINK];

static int gacw_path(char *buf, size_t cap, const char *rel)
{
    return ovf(snprintf(buf, cap, "%s/%s", g_gacw_tmp, rel), cap);
}

/* Every inner run carries the two ZCL_ARTIFACT_* assignments this gate
 * still reads, then the gate for real with merged output — the call
 * sites' `>log 2>&1`. The shell's third assignment,
 * ZCL_ARTIFACT_SKIP_FRESHNESS, went with the freshness delegation the
 * port no longer performs (see the header of
 * gate_generated_artifact_contradictions.c), so setting it here would
 * name a flag nothing reads. */
static int gacw_run(const char *arm, const char *cap, int *code)
{
    if (setenv("ZCL_ARTIFACT_ARM_BASELINE", arm, 1) != 0
        || setenv("ZCL_ARTIFACT_CAPABILITY_INVENTORY", cap, 1) != 0)
        return die("z23-lint: setenv failed\n", "");
    return cic_invoke(k_gacw_gate, 1, g_gacw_sink, sizeof g_gacw_sink, code);
}

static int gacw_write(const char *rel, const char *text)
{
    char p[4096];
    int rc = gacw_path(p, sizeof p, rel);
    if (rc == 0)
        rc = csr_write(p, text);
    return rc;
}

/* sed -n '1,100p' of the captured log: at most the first hundred lines,
 * newline-terminated as sed printed them. */
static int gacw_replay(const char *log)
{
    int n = 0;
    for (const char *p = log; *p && n < 100; n++) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (fwrite(p, 1, len, stderr) != len || fputc('\n', stderr) == EOF)
            return die("z23-lint: write failed\n", "");
        if (!nl)
            break;
        p = nl + 1;
    }
    return 0;
}

static int gacw_setup(void)
{
    const char *td = env_or("TMPDIR", "/tmp");
    if (ovf(snprintf(g_gacw_tmp, sizeof g_gacw_tmp,
                     "%s/zcl-artifact-contradiction.XXXXXX", td),
            sizeof g_gacw_tmp))
        return 2;
    if (!mkdtemp(g_gacw_tmp))
        return die("z23-lint: mktemp failed: %s\n", g_gacw_tmp);
    char p[4096];
    int rc = gacw_path(p, sizeof p, "self");
    if (rc == 0)
        rc = csr_mkdirs(p);
    if (rc == 0)
        rc = gacw_write("self/arm.txt",
            "# z23-generated-artifact: zcl.generated_artifact.v1\n"
            "# artifact-id: zcl.arm_symbol_single_baseline.v1\n"
            "# asserts: multi_arm_definition(path,symbol)\n"
            "# generated-by: tools/lint/check_arm_symbol_single.sh\n"
            "# regenerate: ZCL_LINT_MODE=UPDATE "
            "tools/lint/check_arm_symbol_single.sh\n"
            "a.c\tf\n");
    if (rc == 0)
        rc = gacw_write("self/cap.jsonl",
            "{\"record\":\"inventory\",\"generated_artifact_schema\":"
            "\"zcl.generated_artifact.v1\",\"artifact_id\":"
            "\"zcl.code_capability_inventory.v1\",\"generated_by\":"
            "\"tools/gen_capability_inventory.c\",\"regenerate\":"
            "\"make docs-capability-inventory\",\"consumes\":[{"
            "\"path\":\"tools/lint/arm_symbol_single_baseline.txt\","
            "\"artifact_id\":\"zcl.arm_symbol_single_baseline.v1\","
            "\"asserts\":\"multi_arm_definition(path,symbol)\"}]}\n"
            "{\"record\":\"multi_arm_symbol\",\"header\":\"a.h\","
            "\"symbol\":\"f\",\"source_path\":\"a.c\","
            "\"definition_arm_count\":2,\"aggregate_definition\":"
            "\"UNPROVEN\",\"aggregate_constant_return\":\"UNPROVEN\","
            "\"verdict\":\"UNPROVEN\"}\n"
            "{\"record\":\"definition_arm\",\"header\":\"a.h\","
            "\"symbol\":\"f\",\"definition\":{\"path\":\"a.c\","
            "\"line\":1},\"constant_return_evidence\":"
            "\"parsed_definition_body\",\"constant_return_body\":true,"
            "\"constant_return_value\":\"false\",\"definition_scope\":"
            "\"preprocessor_arm_UNPROVEN\",\"verdict\":\"UNPROVEN\"}\n"
            "{\"record\":\"definition_arm\",\"header\":\"a.h\","
            "\"symbol\":\"f\",\"definition\":{\"path\":\"a.c\","
            "\"line\":9},\"constant_return_evidence\":"
            "\"parsed_definition_body\",\"constant_return_body\":false,"
            "\"constant_return_value\":null,\"definition_scope\":"
            "\"preprocessor_arm_UNPROVEN\",\"verdict\":\"UNPROVEN\"}\n"
            "{\"record\":\"untested_invariant\",\"symbol\":\"f\","
            "\"definition\":{\"path\":\"a.c\",\"line\":1},"
            "\"multi_arm_definition\":true,\"definition_scope\":"
            "\"preprocessor_arm_UNPROVEN\",\"constant_return_body\":true,"
            "\"verdict\":\"UNPROVEN\"}\n");
    return rc;
}

/* The compatible fixture pair passes. */
static int gacw_pass(void)
{
    char arm[4096], cap[4096];
    int rc = gacw_path(arm, sizeof arm, "self/arm.txt");
    if (rc == 0)
        rc = gacw_path(cap, sizeof cap, "self/cap.jsonl");
    int code = 0;
    if (rc == 0)
        rc = gacw_run(arm, cap, &code);
    if (rc == 0 && code != 0) {
        rc = gacw_replay(g_gacw_sink);
        fputs("[check-generated-artifact-contradictions] SELFTEST FAIL — "
              "compatible artifacts did not pass\n", stderr);
        if (rc == 0)
            rc = 1;
    }
    return rc;
}

/* With the arm baseline renamed away, the gate names it UNPROVEN and
 * exits 2 — the unproven-scan convention. */
static int gacw_absent(void)
{
    char arm[4096], aside[4096], cap[4096];
    int rc = gacw_path(arm, sizeof arm, "self/arm.txt");
    if (rc == 0)
        rc = gacw_path(aside, sizeof aside, "self/arm.absent");
    if (rc == 0)
        rc = gacw_path(cap, sizeof cap, "self/cap.jsonl");
    if (rc == 0 && rename(arm, aside) != 0)
        rc = die("z23-lint: rename failed: %s\n", arm);
    int code = 0;
    if (rc == 0)
        rc = gacw_run(arm, cap, &code);
    if (rc == 0 && code != 2) {
        fputs("[check-generated-artifact-contradictions] SELFTEST FAIL — "
              "absent artifact did not exit 2\n", stderr);
        rc = 1;
    }
    if (rc == 0 && !strstr(g_gacw_sink, "UNPROVEN")) {
        fputs("[check-generated-artifact-contradictions] SELFTEST FAIL — "
              "absence was not named UNPROVEN\n", stderr);
        rc = 1;
    }
    if (rename(aside, arm) != 0 && rc == 0)
        rc = die("z23-lint: rename failed: %s\n", aside);
    return rc;
}

/* The conflict fixture: cap.jsonl with the aggregate constant claim
 * rewritten per line, first occurrence — sed 's/.../.../' on content
 * where the pattern's dots can only match the literal bytes. */
static int gacw_emit_line(FILE *out, const char *line, size_t n)
{
    static const char from[] =
        "\"aggregate_constant_return\":\"UNPROVEN\"";
    static const char to[] =
        "\"aggregate_constant_return\":\"constant_false\"";
    const char *hit = strstr(line, from);
    if (!hit)
        return fwrite(line, 1, n, out) != n
            ? die("z23-lint: write failed\n", "") : 0;
    if (fwrite(line, 1, (size_t)(hit - line), out) != (size_t)(hit - line)
        || fputs(to, out) < 0
        || fputs(hit + sizeof from - 1, out) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int gacw_conflict_write(const char *src, const char *dst)
{
    FILE *in = fopen(src, "r");
    if (!in)
        return die("z23-lint: cannot open %s\n", src);
    FILE *out = fopen(dst, "w");
    if (!out) {
        fclose(in);
        return die("z23-lint: cannot open %s\n", dst);
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while (rc == 0 && (n = getline(&line, &cap, in)) >= 0)
        rc = gacw_emit_line(out, line, (size_t)n);
    free(line);
    if (ferror(in) && rc == 0)
        rc = die("z23-lint: read failed: %s\n", src);
    if (fclose(in) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", src);
    if (fclose(out) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", dst);
    return rc;
}

/* The conflicted inventory names it CONTRADICTION and exits 1 (red). */
static int gacw_conflict(void)
{
    char arm[4096], cap[4096], conflict[4096];
    int rc = gacw_path(arm, sizeof arm, "self/arm.txt");
    if (rc == 0)
        rc = gacw_path(cap, sizeof cap, "self/cap.jsonl");
    if (rc == 0)
        rc = gacw_path(conflict, sizeof conflict, "self/conflict.jsonl");
    if (rc == 0)
        rc = gacw_conflict_write(cap, conflict);
    int code = 0;
    if (rc == 0)
        rc = gacw_run(arm, conflict, &code);
    if (rc == 0 && code != 1) {
        fputs("[check-generated-artifact-contradictions] SELFTEST FAIL — "
              "contradiction did not exit 1\n", stderr);
        rc = 1;
    }
    if (rc == 0 && !strstr(g_gacw_sink, "CONTRADICTION")) {
        fputs("[check-generated-artifact-contradictions] SELFTEST FAIL — "
              "conflict was not named CONTRADICTION\n", stderr);
        rc = 1;
    }
    return rc;
}

int check_generated_artifact_contradictions_selftest(void)
{
    char root[4096];
    int rc = cic_repo_root(root, sizeof root);
    if (rc == 0 && chdir(root) != 0)
        rc = 2;
    if (rc == 0)
        rc = gacw_setup();
    if (rc == 0)
        rc = gacw_pass();
    if (rc == 0)
        rc = gacw_absent();
    if (rc == 0)
        rc = gacw_conflict();
    if (g_gacw_tmp[0])
        (void)rap_rm_rf(g_gacw_tmp);
    if (rc == 0)
        fputs("[check-generated-artifact-contradictions] SELFTEST PASS "
              "(compatible passes; absent is UNPROVEN; conflict is red)\n",
              stdout);
    return rc;
}
