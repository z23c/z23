/* Copyright 2026 Rhett Creiton - Apache License 2.0
 *
 * purpose: the pre-scan self-check for check-doc-claims, ported from the
 * selfcheck() function of tools/lint/check_doc_claims.sh. Proves with
 * known-good and known-bad fixtures that the claim evaluator still fires
 * in every direction (file/symbol/gate predicates, fenced examples
 * skipped, malformed annotations reported, positive-reliance phrases
 * rejected without banning precise terms), and that oracle-gate verdict
 * resolution reuses recorded driver verdicts, falls back fail-closed,
 * never honors unlisted names, runs once per gate, and that the
 * --global/--doc split is disjoint and complete. Runs BEFORE any tree
 * scan; a broken evaluator aborts the gate (exit 2).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include "platform/clock.h"
#include "lintc.h"
#include "gate_doc_claims_priv.h"

enum { ST_PATH = DC_PATH, ST_TEXT = 8192 };

static char g_st_old_vdir[ST_PATH];
static int g_st_had_vdir = 0;

static int dc_st_tmpdir(char *out, size_t cap)
{
    if (ovf(snprintf(out, cap, "%s/z23-lint-doc-claims.XXXXXX",
                     env_or("TMPDIR", "/tmp")), cap))
        return 2;
    if (!mkdtemp(out)) {
        fprintf(stderr, "FAIL: mktemp failed\n");
        return 2;
    }
    return 0;
}

static void dc_st_print_viol(void)
{
    for (int i = 0; i < dc_viol_n; i++)
        fprintf(stderr, "        %s\n", dc_viol[i]);
}

/* ── part 1: the claim evaluator fixtures ──────────────────────────── */

static int dc_st_write_claim_files(const char *tmp, const char *gg,
                                   const char *bg)
{
    char p[ST_PATH], t[ST_TEXT];
    if (ovf(snprintf(p, sizeof p, "%s/good.md", tmp), sizeof p))
        return 2;
    if (ovf(snprintf(t, sizeof t,
            "The Makefile is still the build entry point.\n"
            "<!-- claim: file-present Makefile -->\n"
            "The event-log-fed UTXO projection was deleted by Program H1.\n"
            "<!-- claim: file-absent engine/modules/storage/src/"
            "utxo_projection.c # 9b5add018 -->\n"
            "The package swarm is wired to a real P2P socket at boot.\n"
            "<!-- claim: symbol-present p2p_node_begin_message "
            "engine/composition/src/boot_zcode_swarm_membership.c -->\n"
            "No placeholder symbol survives there.\n"
            "<!-- claim: symbol-absent zzz_doc_claims_selftest_absent_zzz "
            "engine/composition/src/boot_zcode_swarm_membership.c -->\n"
            "The projection copy stays dead.\n"
            "<!-- claim: %s check-no-utxo-projection -->\n", gg), sizeof t))
        return 2;
    if (csr_write(p, t))
        return 2;
    if (ovf(snprintf(p, sizeof p, "%s/bad.md", tmp), sizeof p))
        return 2;
    if (ovf(snprintf(t, sizeof t,
            "Stale: says the Makefile is gone.\n"
            "<!-- claim: file-absent Makefile -->\n"
            "Stale: says the deleted projection is still here.\n"
            "<!-- claim: file-present engine/modules/storage/src/"
            "utxo_projection.c -->\n"
            "Stale: says a live symbol is gone.\n"
            "<!-- claim: symbol-absent p2p_node_begin_message "
            "engine/composition/src/boot_zcode_swarm_membership.c -->\n"
            "Stale: says an absent symbol is present.\n"
            "<!-- claim: symbol-present zzz_doc_claims_selftest_absent_zzz "
            "engine/composition/src/boot_zcode_swarm_membership.c -->\n"
            "Stale: oracle now reports the opposite.\n"
            "<!-- claim: %s check-no-utxo-projection -->\n", bg), sizeof t))
        return 2;
    if (csr_write(p, t))
        return 2;
    if (ovf(snprintf(p, sizeof p, "%s/fenced.md", tmp), sizeof p))
        return 2;
    if (csr_write(p,
            "Syntax documentation, not a live claim:\n"
            "```\n"
            "<!-- claim: file-present engine/modules/storage/src/"
            "utxo_projection.c -->\n"
            "<!-- claim: gate-fails check-no-utxo-projection -->\n"
            "```\n"))
        return 2;
    if (ovf(snprintf(p, sizeof p, "%s/malformed.md", tmp), sizeof p))
        return 2;
    return csr_write(p,
            "Bad predicate name.\n"
            "<!-- claim: teleport-check Makefile -->\n"
            "Missing argument.\n"
            "<!-- claim: file-present -->\n"
            "Unknown oracle gate.\n"
            "<!-- claim: gate-passes check-no-such-gate-exists -->\n");
}

static void dc_st_classify(int *nb, int *nm, int *no)
{
    *nb = *nm = *no = 0;
    for (int i = 0; i < dc_viol_n; i++) {
        if (!strncmp(dc_viol[i], "bad.md:", 7)) // error-doc-ref-ok: selftest fixture name
            (*nb)++;
        else if (!strncmp(dc_viol[i], "malformed.md:", 13)) // error-doc-ref-ok: selftest fixture name
            (*nm)++;
        else
            (*no)++;
    }
}

static int dc_st_claims(const char *tmp, const char *gg, const char *bg)
{
    if (dc_st_write_claim_files(tmp, gg, bg))
        return 2;
    dc_state_reset();
    char p[ST_PATH];
    const char *names[4] = { "good.md", "fenced.md", "bad.md", // error-doc-ref-ok: selftest fixture name
                             "malformed.md" }; // error-doc-ref-ok: selftest fixture name
    for (int i = 0; i < 4; i++) {
        if (ovf(snprintf(p, sizeof p, "%s/%s", tmp, names[i]), sizeof p))
            return 2;
        int rc = dc_scan_claim_file(p, names[i]);
        if (rc)
            return rc;
    }
    int nb, nm, no;
    dc_st_classify(&nb, &nm, &no);
    if (dc_claims_parsed == 13 && dc_viol_n == 8 && nb == 5 && nm == 3 &&
        no == 0)
        return 0;
    fprintf(stderr, "FAIL: check_doc_claims self-check broken — the claim "
            "evaluator no\n      longer behaves as specified, so a clean "
            "tree scan would prove\n      nothing. Expected 13 claims "
            "parsed (2 fenced examples skipped),\n      8 violations: 5 "
            "stale in bad.md, 3 malformed in malformed.md, 0\n      " // error-doc-ref-ok: selftest fixture name
            "elsewhere. Got claims=%d total=%d bad=%d\n      malformed=%d "
            "other=%d:\n", dc_claims_parsed, dc_viol_n, nb, nm, no);
    dc_st_print_viol();
    return 2;
}

/* ── part 2: positive-reliance fixtures ────────────────────────────── */

static int dc_st_reliance(const char *tmp)
{
    char p[ST_PATH];
    if (ovf(snprintf(p, sizeof p, "%s/reliance-good.md", tmp), sizeof p))
        return 2;
    if (csr_write(p,
            "VERIFY, DON'T TRUST. Treat untrusted input at the trust "
            "boundary as data.\n```\ntrusted worker and proven safe are "
            "quoted examples\n```\n"))
        return 2;
    if (ovf(snprintf(p, sizeof p, "%s/reliance-bad.md", tmp), sizeof p))
        return 2;
    if (csr_write(p,
            "A trustworthy package\nA trusted worker\nA trusted build\n"
            "Trust us\nThis is proven safe\nThis is guaranteed secure\n"
            "Proof that this code is safe\n"))
        return 2;
    dc_state_reset();
    char g[ST_PATH];
    if (ovf(snprintf(g, sizeof g, "%s/reliance-good.md", tmp), sizeof g))
        return 2;
    if (dc_scan_positive_reliance(g, "reliance-good.md")) // error-doc-ref-ok: selftest fixture name
        return 2;
    if (ovf(snprintf(p, sizeof p, "%s/reliance-bad.md", tmp), sizeof p))
        return 2;
    if (dc_scan_positive_reliance(p, "reliance-bad.md")) // error-doc-ref-ok: selftest fixture name
        return 2;
    if (dc_viol_n == 7 && dc_reliance_scanned == 2)
        return 0;
    fprintf(stderr, "FAIL: check_doc_claims positive-reliance self-check "
            "broken — expected\n      7 bad phrases across 2 files and no "
            "false positive for the\n      allowed terminology; got "
            "violations=%d files=%d\n", dc_viol_n, dc_reliance_scanned);
    dc_st_print_viol();
    return 2;
}

/* ── part 3: verdict reuse ─────────────────────────────────────────── */

static int dc_st_table_write(const char *vr, const char *gate,
                             const char *cmd)
{
    char p[ST_PATH], t[512];
    if (ovf(snprintf(p, sizeof p, "%s/fake_run_lint.sh", vr), sizeof p))
        return 2;
    if (ovf(snprintf(t, sizeof t, "        %s) echo '%s' ;;\n", gate, cmd),
            sizeof t))
        return 2;
    return csr_write(p, t);
}

static int dc_st_rc_write(const char *vr, const char *gate, const char *val)
{
    char p[ST_PATH];
    if (ovf(snprintf(p, sizeof p, "%s/%s.rc", vr, gate), sizeof p))
        return 2;
    return csr_write(p, val);
}

static void dc_st_arm(const char *vr)
{
    dc_table_override = 1;
    if (ovf(snprintf(dc_table_path, sizeof dc_table_path, "%s/"
                     "fake_run_lint.sh", vr), sizeof dc_table_path))
        dc_table_path[0] = '\0';
    setenv("ZCL_LINT_GATES_DIR_X", vr, 1);
}

static int dc_st_case_reuse(const char *vr, int *fail)
{
    int got;
    if (dc_st_table_write(vr, "zzz_verdict_reuse_gate", "exit 99"))
        return 2;
    if (dc_st_rc_write(vr, "zzz_verdict_reuse_gate", "7\n"))
        return 2;
    dc_st_arm(vr);
    dc_memo_forget("zzz_verdict_reuse_gate");
    got = dc_gate_rc("zzz_verdict_reuse_gate");
    if (got == 7)
        return 0;
    fprintf(stderr, "FAIL: check_doc_claims verdict-reuse self-check broken"
            " — a\n      recorded driver verdict (7) was not reused; "
            "gate_rc\n      returned '%d' instead (99 would mean it re-ran "
            "the gate\n      command itself, recreating the exact race this "
            "fixes).\n", got);
    *fail = 2;
    return 0;
}

static int dc_st_case_fallback(const char *vr, int *fail)
{
    int got, old_t = dc_gate_timeout;
    char p[ST_PATH];
    if (dc_st_table_write(vr, "zzz_verdict_fallback_gate", "exit 42"))
        return 2;
    if (ovf(snprintf(p, sizeof p, "%s/zzz_verdict_fallback_gate.rc", vr),
            sizeof p))
        return 2;
    unlink(p);
    dc_memo_forget("zzz_verdict_fallback_gate");
    dc_gate_timeout = 1;
    got = dc_gate_rc("zzz_verdict_fallback_gate");
    dc_gate_timeout = old_t;
    if (got == 42)
        return 0;
    fprintf(stderr, "FAIL: check_doc_claims verdict-reuse self-check broken"
            " — with no\n      recorded verdict, gate_rc must still run the "
            "gate itself\n      (fail-closed); got '%d', wanted 42.\n", got);
    *fail = 2;
    return 0;
}

static int dc_st_case_unlisted(const char *vr, int *fail)
{
    int got;
    if (dc_st_rc_write(vr, "check-zzz-doc-claims-unlisted", "0\n"))
        return 2;
    dc_memo_forget("check-zzz-doc-claims-unlisted");
    got = dc_gate_rc("check-zzz-doc-claims-unlisted");
    if (got == -1)
        return 0;
    fprintf(stderr, "FAIL: check_doc_claims verdict-reuse self-check broken"
            " — a\n      verdict file for a gate with no table entry was "
            "honored\n      (got '%d', wanted X).\n", got);
    *fail = 2;
    return 0;
}

static int dc_st_case_absent(const char *vr, int *fail)
{
    int got, old_t = dc_gate_timeout;
    char p[ST_PATH];
    if (ovf(snprintf(p, sizeof p, "%s/requested.list", vr), sizeof p))
        return 2;
    if (csr_write(p, "zzz_verdict_other_gate\n"))
        return 2;
    if (dc_st_table_write(vr, "zzz_verdict_absent_gate", "exit 43"))
        return 2;
    dc_memo_forget("zzz_verdict_absent_gate");
    dc_gate_timeout = 30;
    int64_t t0 = clock_now_monotonic_ns();
    got = dc_gate_rc("zzz_verdict_absent_gate");
    long el = (long)((clock_now_monotonic_ns() - t0) / 1000000000LL);
    dc_gate_timeout = old_t;
    if (got == 43 && el <= 5)
        return 0;
    fprintf(stderr, "FAIL: check_doc_claims verdict-reuse self-check broken"
            " — a gate\n      absent from the driver's requested.list must "
            "run at once;\n      got '%d' after %ld s, wanted 43 without "
            "waiting.\n", got, el);
    *fail = 2;
    return 0;
}

static int dc_st_case_listed(const char *vr, int *fail)
{
    int got;
    if (dc_st_table_write(vr, "zzz_verdict_other_gate", "exit 99"))
        return 2;
    if (dc_st_rc_write(vr, "zzz_verdict_other_gate", "7\n"))
        return 2;
    dc_memo_forget("zzz_verdict_other_gate");
    got = dc_gate_rc("zzz_verdict_other_gate");
    char p[ST_PATH];
    if (ovf(snprintf(p, sizeof p, "%s/requested.list", vr), sizeof p))
        return 2;
    unlink(p);
    if (got == 7)
        return 0;
    fprintf(stderr, "FAIL: check_doc_claims verdict-reuse self-check broken"
            " — a gate\n      named in requested.list did not reuse its "
            "verdict (got '%d').\n", got);
    *fail = 2;
    return 0;
}

static int dc_st_count_lines(const char *path, int *n)
{
    *n = 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char b[256];
    while (fgets(b, sizeof b, f)) {
        size_t l = strlen(b);
        if (l && b[l - 1] != '\n') {
            (*n)++;
            break;
        }
        (*n)++;
    }
    fclose(f);
    return 0;
}

static int dc_st_case_memo(const char *vr, int *fail)
{
    char p[ST_PATH], cmd[512], md[ST_TEXT];
    if (ovf(snprintf(cmd, sizeof cmd, "echo run >> %s/memo.count", vr),
            sizeof cmd))
        return 2;
    if (dc_st_table_write(vr, "check-zzz-doc-claims-memo", cmd))
        return 2;
    if (ovf(snprintf(md, sizeof md, "First reliance.\n<!-- claim: "
            "gate-passes check-zzz-doc-claims-memo -->\nSecond reliance.\n"
            "<!-- claim: gate-passes check-zzz-doc-claims-memo -->\n"),
            sizeof md))
        return 2;
    if (ovf(snprintf(p, sizeof p, "%s/memo.md", vr), sizeof p))
        return 2;
    if (csr_write(p, md))
        return 2;
    unsetenv("ZCL_LINT_GATES_DIR_X");
    dc_memo_forget("check-zzz-doc-claims-memo");
    dc_state_reset();
    int rc = dc_scan_claim_file(p, "memo.md"); // error-doc-ref-ok: selftest fixture name
    if (rc)
        return rc;
    int runs;
    if (ovf(snprintf(p, sizeof p, "%s/memo.count", vr), sizeof p))
        return 2;
    dc_st_count_lines(p, &runs);
    if (runs == 1 && dc_viol_n == 0 && dc_claims_parsed == 2)
        return 0;
    fprintf(stderr, "FAIL: check_doc_claims memo self-check broken — two "
            "claims on one\n      oracle gate must run it exactly once and "
            "both hold; got\n      runs=%d violations=%d claims=%d\n", runs,
            dc_viol_n, dc_claims_parsed);
    *fail = 2;
    return 0;
}

static int dc_viol_has(const char *needle)
{
    for (int i = 0; i < dc_viol_n; i++)
        if (strstr(dc_viol[i], needle))
            return 1;
    return 0;
}

static int dc_st_split_one(const char *md, const char *name, int part,
                           char *got, size_t cap)
{
    dc_claim_part = part;
    dc_state_reset();
    int rc = dc_scan_claim_file(md, "split.md"); // error-doc-ref-ok: selftest fixture name
    if (rc)
        return rc;
    int n = snprintf(got + strlen(got), cap - strlen(got), " %s:%d/%d/%d",
                     name, dc_viol_n, dc_claims_parsed, dc_claims_left);
    if (ovf(n, cap - strlen(got)))
        return 2;
    if (part == DC_PART_DOC) {
        if (dc_viol_has("gate-passes"))
            strcat(got, "(wrong-claim)");
        if (access("split.count.proxy", F_OK) == 0)
            strcat(got, "(oracle-ran)");
    }
    if (part == DC_PART_GATE && dc_viol_has("file-absent"))
        strcat(got, "(wrong-claim)");
    return 0;
}

static int dc_st_case_split(const char *vr, int *fail)
{
    char p[ST_PATH], cmd[512], md[ST_TEXT], got[192];
    if (ovf(snprintf(cmd, sizeof cmd, "echo run >> %s/split.count; exit 3",
                     vr), sizeof cmd))
        return 2;
    if (dc_st_table_write(vr, "check-zzz-doc-claims-split", cmd))
        return 2;
    if (ovf(snprintf(md, sizeof md, "Holds.\n<!-- claim: file-present "
            "Makefile -->\nStale file claim.\n<!-- claim: file-absent "
            "Makefile -->\nStale oracle claim.\n<!-- claim: gate-passes "
            "check-zzz-doc-claims-split -->\n"), sizeof md))
        return 2;
    if (ovf(snprintf(p, sizeof p, "%s/split.md", vr), sizeof p))
        return 2;
    if (csr_write(p, md))
        return 2;
    dc_memo_forget("check-zzz-doc-claims-split");
    if (ovf(snprintf(p, sizeof p, "%s/split.count", vr), sizeof p))
        return 2;
    unlink(p);
    char mdpath[ST_PATH];
    if (ovf(snprintf(mdpath, sizeof mdpath, "%s/split.md", vr), sizeof mdpath))
        return 2;
    got[0] = '\0';
    int rc = dc_st_split_one(mdpath, "doc", DC_PART_DOC, got, sizeof got);
    if (!rc && access(p, F_OK) == 0)
        strcat(got, "(oracle-ran)");
    if (!rc)
        rc = dc_st_split_one(mdpath, "gate", DC_PART_GATE, got, sizeof got);
    if (!rc)
        rc = dc_st_split_one(mdpath, "all", DC_PART_ALL, got, sizeof got);
    dc_claim_part = DC_PART_ALL;
    if (rc)
        return rc;
    if (!strcmp(got, " doc:1/3/1 gate:1/3/2 all:2/3/0"))
        return 0;
    fprintf(stderr, "FAIL: check_doc_claims split self-check broken — the "
            "doc part must\n      report only the stale file claim without "
            "running the oracle,\n      the gate part only the stale oracle "
            "claim, the plain run both.\n      Want ' doc:1/3/1 gate:1/3/2 "
            "all:2/3/0', got '%s'.\n", got);
    *fail = 2;
    return 0;
}

static int dc_st_verdict(const char *vr, int *fail)
{
    int rc;
    rc = dc_st_case_reuse(vr, fail);
    if (!rc)
        rc = dc_st_case_fallback(vr, fail);
    if (!rc)
        rc = dc_st_case_unlisted(vr, fail);
    if (!rc)
        rc = dc_st_case_absent(vr, fail);
    if (!rc)
        rc = dc_st_case_listed(vr, fail);
    if (!rc)
        rc = dc_st_case_memo(vr, fail);
    if (!rc)
        rc = dc_st_case_split(vr, fail);
    return rc;
}

/* ── driver ────────────────────────────────────────────────────────── */

int dc_selfcheck(void)
{
    const char *ov = getenv("ZCL_LINT_GATES_DIR_X");
    g_st_had_vdir = ov && *ov;
    if (g_st_had_vdir && strlen(ov) >= sizeof g_st_old_vdir)
        g_st_had_vdir = 0;
    if (g_st_had_vdir)
        strcpy(g_st_old_vdir, ov);
    char tmp[ST_PATH], vr[ST_PATH];
    if (dc_st_tmpdir(tmp, sizeof tmp))
        return 2;
    int st_fail = 0;
    int orc = dc_gate_rc("check-no-utxo-projection");
    if (orc < 0) {
        fprintf(stderr, "FAIL: self-check could not resolve the oracle gate "
                "check-no-utxo-projection\n");
        rap_rm_rf(tmp);
        return 2;
    }
    const char *gg = orc == 0 ? "gate-passes" : "gate-fails";
    const char *bg = orc == 0 ? "gate-fails" : "gate-passes";
    int rc = dc_st_claims(tmp, gg, bg);
    if (rc)
        return rc;
    if (dc_st_reliance(tmp))
        st_fail = 2;
    dc_state_reset();
    if (dc_st_tmpdir(vr, sizeof vr))
        return 2;
    rc = dc_st_verdict(vr, &st_fail);
    if (rc)
        return rc;
    dc_memo_forget("check-zzz-doc-claims-unlisted");
    dc_memo_forget("check-zzz-doc-claims-memo");
    dc_memo_forget("check-zzz-doc-claims-split");
    dc_memo_forget("zzz_verdict_reuse_gate");
    dc_memo_forget("zzz_verdict_fallback_gate");
    dc_memo_forget("zzz_verdict_absent_gate");
    dc_memo_forget("zzz_verdict_other_gate");
    dc_table_override = 0;
    if (g_st_had_vdir)
        setenv("ZCL_LINT_GATES_DIR_X", g_st_old_vdir, 1);
    else
        unsetenv("ZCL_LINT_GATES_DIR_X");
    rap_rm_rf(vr);
    rap_rm_rf(tmp);
    dc_state_reset();
    dc_claim_part = DC_PART_ALL;
    return st_fail;
}
