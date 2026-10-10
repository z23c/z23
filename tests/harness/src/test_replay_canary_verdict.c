/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_replay_canary_verdict — the hermetic, in-CI half of the standing
 * replay canary.
 *
 * It spawns no mainnet node. It drives the harness's verdict logic through
 * `replay_canary.sh --self-test=<mode>`, which injects synthetic RPC outputs
 * from a fixture dir, and asserts two contracts:
 *
 *   1. Gate fires on known-bad: each seeded-bad fixture produces a FAIL
 *      sentinel with the correct `reason` and a non-zero exit. The two named
 *      cases are fail-rejects (a seeded consensus reject) and fail-sha3 (a
 *      commitment != the compiled checkpoint).
 *
 *   2. Never exit 0 as proof: a SIGKILL of the harness mid-run leaves no
 *      fresh PASS sentinel. Proof requires a positive fresh PASS record.
 *
 * Every run uses a private fixture dir and verdict dir under /tmp, so the
 * live node, datadir and real verdict dir are never touched. */

#include "test/test_core.h"
#include "crypto/sha256.h"
#include "platform/os_proc.h"
#include "platform/time_compat.h"
#include "util/spawn.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#endif
#if defined(__linux__)
#include <sys/prctl.h>
#endif
#include <time.h>
#include <unistd.h>
#if !defined(_WIN32)

/* ── repo_root: walk UP from the test binary to the tree that holds the
 * Makefile AND the canary harness, so the shell-out hits the right file
 * regardless of the cwd the suite runs in. Bounded walk. ─────────── */
#define CANARY_REL "tools/scripts/replay_canary.sh"
#define CANARY_SOURCE_A \
    "aaaaaaaaaaaaaaaa" "aaaaaaaaaaaaaaaa" \
    "aaaaaaaaaaaaaaaa" "aaaaaaaaaaaaaaaa"
#define CANARY_SOURCE_B \
    "bbbbbbbbbbbbbbbb" "bbbbbbbbbbbbbbbb" \
    "bbbbbbbbbbbbbbbb" "bbbbbbbbbbbbbbbb"

static const char *repo_root(void)
{
    static char root[PATH_MAX];
    static int cached = 0;
    if (cached) return root[0] ? root : NULL;

    char exe[PATH_MAX];
    if (!os_proc_exe_path(exe, sizeof(exe))) {
        cached = 1; root[0] = '\0'; return NULL;
    }

    for (int depth = 0; depth < 8; depth++) {
        char *slash = strrchr(exe, '/');
        if (!slash || slash == exe) break;
        *slash = '\0';

        char probe[PATH_MAX];
        struct stat st;
        if (snprintf(probe, sizeof(probe), "%s/Makefile", exe) >= (int)sizeof(probe))
            break;
        if (stat(probe, &st) != 0) continue;
        if (snprintf(probe, sizeof(probe), "%s/%s", exe, CANARY_REL) >= (int)sizeof(probe))
            break;
        if (stat(probe, &st) != 0) continue;

        if (snprintf(root, sizeof(root), "%s", exe) >= (int)sizeof(root)) break;
        cached = 1;
        return root;
    }
    cached = 1; root[0] = '\0';
    return NULL;
}

/* ── tiny fs helpers ────────────────────────────────────────────── */

static void write_file(const char *dir, const char *name, const char *content)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "w");
    if (f) { fputs(content, f); fclose(f); }
}

static bool read_file(const char *path, char *buf, size_t bufsz)
{
    FILE *f = fopen(path, "r");
    if (!f) return false;
    size_t r = fread(buf, 1, bufsz - 1, f);
    fclose(f);
    buf[r] = '\0';
    return r > 0;
}

static bool sha256_file_hex(const char *path, char out[65])
{
    FILE *f = fopen(path, "rb");
    if (!f) return false;

    struct sha256_ctx ctx;
    sha256_init(&ctx);
    unsigned char buf[4096];
    size_t n = 0;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        sha256_write(&ctx, buf, n);
    bool ok = !ferror(f) && fclose(f) == 0;
    if (!ok) return false;

    unsigned char digest[SHA256_OUTPUT_SIZE];
    static const char hex[] = "0123456789abcdef";
    sha256_finalize(&ctx, digest);
    for (size_t i = 0; i < sizeof(digest); i++) {
        out[i * 2] = hex[digest[i] >> 4];
        out[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    out[64] = '\0';
    return true;
}

static bool write_identity_fixture_binary(const char *dir, char *out,
                                          size_t outsz)
{
    if (snprintf(out, outsz, "%s/identity-fixture", dir) >= (int)outsz)
        return false;
    char script[512];
    snprintf(script, sizeof(script),
             "#!/usr/bin/env bash\n"
             "if [ \"${1:-}\" = agentbuild ]; then\n"
             "  printf '%%s\\n' '{\"source_id_sha256\":\"%s\","
             "\"build_commit\":\"fixture-trace\"}'\n"
             "  exit 0\n"
             "fi\n"
             "exit 2\n", CANARY_SOURCE_A);
    write_file(dir, "identity-fixture", script);
    return chmod(out, 0700) == 0;
}

/* Write the five baseline PASS fixtures into a fresh fixture dir, then
 * apply a per-mode mutation that flips exactly one assertion. */
static void seed_fixtures(const char *fx, const char *mode)
{
    /* bg_validation reaches COMPLETE, full coverage. */
    write_file(fx, "getsyncdetail.json",
        "{\"bg_validation\":{\"state\":\"complete\","
        "\"verified_height\":3145329,\"chain_height\":3145329,"
        "\"script_verif_skipped_no_undo\":0,\"verification_incomplete\":false}}\n");
    /* zero header rejects. */
    write_file(fx, "getsyncdiag.json",
        "{\"headers\":{\"total_accepted\":3145329,\"total_rejected\":0}}\n");
    /* a real 64-hex commitment, taken at the tip (not the anchor). */
    write_file(fx, "getutxocommitment.json",
        "{\"sha3_hash\":\"deadbeef00000000000000000000000000000000"
        "00000000000000000000beef\",\"height\":3145329,"
        "\"utxo_count\":1354769}\n");
    /* node coarse stats. */
    write_file(fx, "gettxoutsetinfo.json",
        "{\"height\":3145329,\"bestblock\":\"abc123\","
        "\"transactions\":100,\"txouts\":1354769,"
        "\"total_amount\":\"10364137.94674881\"}\n");
    /* zclassicd coarse stats: same values, but total_amount is an unquoted
     * JSON number (zclassicd's real format), exercising the harness's
     * json_amount tolerance. */
    write_file(fx, "zd_gettxoutsetinfo.json",
        "{\"height\":3145329,\"bestblock\":\"abc123\","
        "\"transactions\":100,\"txouts\":1354769,"
        "\"total_amount\":10364137.94674881}\n");
    /* byte-exact tier: the legacy chainstate SHA3 equals the node's served
     * commitment at the SAME tip hash => exact tier MATCH. */
    write_file(fx, "legacy_utxo_commitment.json",
        "{\"legacy_utxo_sha3\":\"deadbeef00000000000000000000000000000000"
        "00000000000000000000beef\",\"records\":100,\"vouts\":1354769,"
        "\"best_block\":\"abc123\"}\n");

    if (strcmp(mode, "fail-rejects") == 0) {
        /* a single header-admit reject => "consensus_rejects". */
        write_file(fx, "getsyncdiag.json",
            "{\"headers\":{\"total_accepted\":3145329,"
            "\"total_rejected\":1}}\n");
    } else if (strcmp(mode, "fail-sha3") == 0) {
        /* commitment AT the anchor height that does NOT equal the
         * compiled checkpoint => "sha3_mismatch". */
        write_file(fx, "getutxocommitment.json",
            "{\"sha3_hash\":\"00000000000000000000000000000000"
            "00000000000000000000000000000bad\","
            "\"height\":3056758,\"utxo_count\":1354769}\n");
    } else if (strcmp(mode, "fail-sha3-missing") == 0) {
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/getutxocommitment.json", fx);
        unlink(path);
    } else if (strcmp(mode, "fail-sha3-malformed") == 0) {
        write_file(fx, "getutxocommitment.json",
            "{\"sha3_hash\":\"azzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\",\"height\":3145329}\n");
    } else if (strcmp(mode, "fail-crossnode") == 0) {
        /* zclassicd txouts disagree with the node => "crossnode_txouts". */
        write_file(fx, "zd_gettxoutsetinfo.json",
            "{\"height\":3145329,\"bestblock\":\"abc123\","
            "\"transactions\":100,\"txouts\":999999,"
            "\"total_amount\":\"10364137.94674881\"}\n");
    } else if (strcmp(mode, "fail-timeout") == 0) {
        /* the live harness writes state=timeout on a budget overrun;
         * the fixture mirrors that terminal state => "budget_exceeded". */
        write_file(fx, "getsyncdetail.json",
            "{\"bg_validation\":{\"state\":\"timeout\","
            "\"verified_height\":100,\"chain_height\":3145329,"
            "\"script_verif_skipped_no_undo\":0}}\n");
    } else if (strcmp(mode, "fail-verified-below-tip") == 0) {
        /* COMPLETE at boot over a stub extent: verified 100 << tip. */
        write_file(fx, "getsyncdetail.json",
            "{\"bg_validation\":{\"state\":\"complete\","
            "\"verified_height\":100,\"chain_height\":3145329,"
            "\"script_verif_skipped_no_undo\":0,"
            "\"verification_incomplete\":false}}\n");
    } else if (strcmp(mode, "fail-incomplete-flag") == 0) {
        write_file(fx, "getsyncdetail.json",
            "{\"bg_validation\":{\"state\":\"complete\","
            "\"verified_height\":3145329,\"chain_height\":3145329,"
            "\"script_verif_skipped_no_undo\":0,"
            "\"verification_incomplete\":true}}\n");
    } else if (strcmp(mode, "timeout-last-observed") == 0) {
        /* last real getsyncdetail before the budget blew. */
        write_file(fx, "getsyncdetail.json",
            "{\"bg_validation\":{\"state\":\"running\","
            "\"verified_height\":3000000,\"chain_height\":3145329,"
            "\"script_verif_skipped_no_undo\":0,"
            "\"verification_incomplete\":true}}\n");
    } else if (strcmp(mode, "fail-elapsed-fast") == 0) {
        /* a COMPLETE that arrives implausibly fast — the from-anchor seed
         * never applied, so the node "completed" a stub. Drive the elapsed
         * band BELOW the anchor floor (300 s) => "elapsed_too_fast". The
         * harness reads elapsed.json (a bare integer) only in self-test. */
        write_file(fx, "elapsed.json", "5\n");
    } else if (strcmp(mode, "fail-elapsed-slow") == 0) {
        /* a from-anchor COMPLETE that silently degraded to a genesis-scale
         * replay — the NAMED I5 defect. Drive the elapsed band ABOVE the
         * anchor ceiling (5400 s) => "elapsed_too_slow". */
        write_file(fx, "elapsed.json", "99999\n");
    } else if (strcmp(mode, "fail-exact-sha3") == 0) {
        /* the legacy chainstate hashes DIFFERENTLY at the same tip hash =>
         * "crossnode_utxo_sha3" — the byte-exact drift alarm (coarse stats
         * all agree, the SET does not). */
        write_file(fx, "legacy_utxo_commitment.json",
            "{\"legacy_utxo_sha3\":\"cafe00000000000000000000000000000000"
            "00000000000000000000000000000bad\",\"best_block\":\"abc123\"}\n");
    } else if (strcmp(mode, "pass-exact-skew") == 0) {
        /* the oracle advanced mid-run: a different best_block means the
         * exact tier SKIPS (never proof, never drift) and the otherwise
         * clean run still PASSes with exact_tier=skew. */
        write_file(fx, "legacy_utxo_commitment.json",
            "{\"legacy_utxo_sha3\":\"deadbeef00000000000000000000000000000000"
            "00000000000000000000beef\",\"best_block\":\"def456\"}\n");
    } else if (strcmp(mode, "fail-exact-unreadable") == 0) {
        /* blob present but no sha3 field => "exact_reference_unreadable". */
        write_file(fx, "legacy_utxo_commitment.json",
            "{\"best_block\":\"abc123\"}\n");
    }
    /* mode == "pass": no mutation. */
}

/* Run the harness in self-test mode against fixtures `mode`. Returns the
 * process exit code via *exit_code, and the sentinel verdict + reason via
 * out_verdict / out_reason (each may be empty if no sentinel was written).
 * `from` selects anchor|genesis (sentinel name differs). */
static char g_last_sentinel[2048];
static int run_canary_selftest(const char *mode, const char *from,
                               char *out_verdict, size_t vsz,
                               char *out_reason, size_t rsz)
{
    const char *root = repo_root();
    if (!root) return -999;

    char fx[PATH_MAX], vd[PATH_MAX], identity_bin[PATH_MAX];
    snprintf(fx, sizeof(fx), "/tmp/test_canary_fx_%d_%s", (int)getpid(), mode);
    snprintf(vd, sizeof(vd), "/tmp/test_canary_vd_%d_%s", (int)getpid(), mode);
    mkdir(fx, 0755);
    mkdir(vd, 0755);
    seed_fixtures(fx, mode);
    if (!write_identity_fixture_binary(fx, identity_bin,
                                       sizeof(identity_bin))) {
        char rm_failed[PATH_MAX * 2 + 32];
        snprintf(rm_failed, sizeof(rm_failed),
                 "rm -rf '%s' '%s'", fx, vd);
        if (system(rm_failed) != 0) { /* best-effort */ }
        return -998;
    }

    char cmd[PATH_MAX * 4];
    snprintf(cmd, sizeof(cmd),
        "ZCL_CANARY_SELFTEST_DIR='%s' ZCL_CANARY_VERDICT_DIR='%s' "
        "ZCL_CANARY_SELFTEST_NODE_BIN='%s' "
        "bash '%s/%s' --from=%s --self-test=%s >/dev/null 2>&1",
        fx, vd, identity_bin, root, CANARY_REL, from, mode);

    int rc = system(cmd);
    int exit_code = (rc == -1) ? -1 : WEXITSTATUS(rc);

    char sentinel[PATH_MAX];
    snprintf(sentinel, sizeof(sentinel), "%s/replay_canary_%s.json", vd, from);
    char buf[2048] = {0};
    g_last_sentinel[0] = '\0';
    out_verdict[0] = '\0';
    out_reason[0] = '\0';
    if (read_file(sentinel, buf, sizeof(buf))) {
        const char *v = strstr(buf, "\"verdict\":\"");
        if (v) { v += strlen("\"verdict\":\""); size_t i = 0;
                 while (v[i] && v[i] != '"' && i < vsz - 1) { out_verdict[i] = v[i]; i++; }
                 out_verdict[i] = '\0'; }
        const char *r = strstr(buf, "\"reason\":\"");
        if (r) { r += strlen("\"reason\":\""); size_t i = 0;
                 while (r[i] && r[i] != '"' && i < rsz - 1) { out_reason[i] = r[i]; i++; }
                 out_reason[i] = '\0'; }
    }

    snprintf(g_last_sentinel, sizeof(g_last_sentinel), "%s", buf);
    /* clean up fixture + verdict dirs */
    char rm[PATH_MAX + 32];
    snprintf(rm, sizeof(rm), "rm -rf '%s' '%s'", fx, vd);
    if (system(rm) != 0) { /* best-effort cleanup */ }

    return exit_code;
}

/* ── Tests ──────────────────────────────────────────────────────── */

static int test_pass_writes_pass_sentinel(void)
{
    int failures = 0;
    TEST("replay-canary: --self-test=pass writes a PASS sentinel, exit 0") {
        char verdict[16], reason[64];
        int ec = run_canary_selftest("pass", "anchor",
                                     verdict, sizeof(verdict),
                                     reason, sizeof(reason));
        if (ec == -999) { printf("SKIP (repo root not found)\n"); break; }
        ASSERT_EQ(ec, 0);
        ASSERT_STR_EQ(verdict, "PASS");
        ASSERT_STR_EQ(reason, "");
        PASS();
    } _test_next:;
    return failures;
}

static int test_fail_rejects_fires(void)
{
    int failures = 0;
    TEST("replay-canary: seeded consensus reject => FAIL reason=consensus_rejects") {
        char verdict[16], reason[64];
        int ec = run_canary_selftest("fail-rejects", "anchor",
                                     verdict, sizeof(verdict),
                                     reason, sizeof(reason));
        if (ec == -999) { printf("SKIP (repo root not found)\n"); break; }
        ASSERT(ec != 0);
        ASSERT_STR_EQ(verdict, "FAIL");
        ASSERT_STR_EQ(reason, "consensus_rejects");
        PASS();
    } _test_next:;
    return failures;
}

static int test_fail_sha3_fires(void)
{
    int failures = 0;
    TEST("replay-canary: seeded bad commitment => FAIL reason=sha3_mismatch") {
        char verdict[16], reason[64];
        int ec = run_canary_selftest("fail-sha3", "anchor",
                                     verdict, sizeof(verdict),
                                     reason, sizeof(reason));
        if (ec == -999) { printf("SKIP (repo root not found)\n"); break; }
        ASSERT(ec != 0);
        ASSERT_STR_EQ(verdict, "FAIL");
        ASSERT_STR_EQ(reason, "sha3_mismatch");
        PASS();
    } _test_next:;
    return failures;
}

static int test_missing_sha3_fires(void)
{
    int failures = 0;
    TEST("replay-canary: missing commitment RPC => FAIL") {
        char verdict[16], reason[64];
        int ec = run_canary_selftest("fail-sha3-missing", "anchor",
                                     verdict, sizeof(verdict),
                                     reason, sizeof(reason));
        ASSERT(ec != 0);
        ASSERT_STR_EQ(verdict, "FAIL");
        ASSERT_STR_EQ(reason, "rpc_unreachable_getutxocommitment");
        PASS();
    } _test_next:;
    return failures;
}

static int test_malformed_sha3_fires(void)
{
    int failures = 0;
    TEST("replay-canary: 64-byte nonhex commitment => FAIL") {
        char verdict[16], reason[64];
        int ec = run_canary_selftest("fail-sha3-malformed", "anchor",
                                     verdict, sizeof(verdict),
                                     reason, sizeof(reason));
        ASSERT(ec != 0);
        ASSERT_STR_EQ(verdict, "FAIL");
        ASSERT_STR_EQ(reason, "sha3_malformed");
        PASS();
    } _test_next:;
    return failures;
}

static int test_fail_exact_sha3_fires(void)
{
    int failures = 0;
    TEST("replay-canary: legacy chainstate SHA3 differs at same tip => FAIL reason=crossnode_utxo_sha3") {
        char verdict[16], reason[64];
        int ec = run_canary_selftest("fail-exact-sha3", "anchor",
                                     verdict, sizeof(verdict),
                                     reason, sizeof(reason));
        if (ec == -999) { printf("SKIP (repo root not found)\n"); break; }
        ASSERT(ec != 0);
        ASSERT_STR_EQ(verdict, "FAIL");
        ASSERT_STR_EQ(reason, "crossnode_utxo_sha3");
        PASS();
    } _test_next:;
    return failures;
}

static int test_pass_exact_skew_skips_tier(void)
{
    int failures = 0;
    TEST("replay-canary: oracle advanced mid-run => exact tier SKIPS, run still PASSes") {
        char verdict[16], reason[64];
        int ec = run_canary_selftest("pass-exact-skew", "anchor",
                                     verdict, sizeof(verdict),
                                     reason, sizeof(reason));
        if (ec == -999) { printf("SKIP (repo root not found)\n"); break; }
        ASSERT_EQ(ec, 0);
        ASSERT_STR_EQ(verdict, "PASS");
        ASSERT_STR_EQ(reason, "");
        PASS();
    } _test_next:;
    return failures;
}

static int test_fail_exact_unreadable_fires(void)
{
    int failures = 0;
    TEST("replay-canary: legacy blob without sha3 => FAIL reason=exact_reference_unreadable") {
        char verdict[16], reason[64];
        int ec = run_canary_selftest("fail-exact-unreadable", "anchor",
                                     verdict, sizeof(verdict),
                                     reason, sizeof(reason));
        if (ec == -999) { printf("SKIP (repo root not found)\n"); break; }
        ASSERT(ec != 0);
        ASSERT_STR_EQ(verdict, "FAIL");
        ASSERT_STR_EQ(reason, "exact_reference_unreadable");
        PASS();
    } _test_next:;
    return failures;
}

static int test_fail_crossnode_fires(void)
{
    int failures = 0;
    TEST("replay-canary: txouts disagree with zclassicd => FAIL reason=crossnode_txouts") {
        char verdict[16], reason[64];
        int ec = run_canary_selftest("fail-crossnode", "anchor",
                                     verdict, sizeof(verdict),
                                     reason, sizeof(reason));
        if (ec == -999) { printf("SKIP (repo root not found)\n"); break; }
        ASSERT(ec != 0);
        ASSERT_STR_EQ(verdict, "FAIL");
        ASSERT_STR_EQ(reason, "crossnode_txouts");
        PASS();
    } _test_next:;
    return failures;
}

/* A budget overrun is not a divergence. bg_validation never reached
 * COMPLETE, so no sha3, cross-node equality or reject count was compared and
 * there is no parity evidence either way. It is BLOCKED (exit 2), inert to
 * the pager, so the run is re-attempted with a bigger budget or faster
 * hardware instead of being treated as a consensus finding.
 *
 * bg_validation FAILED still FAILs (a reject surfaces there and is
 * consensus-grade); only "did not finish" is demoted. See
 * test_fail_bg_validation_failed. */
static int test_timeout_blocks_rather_than_fails(void)
{
    int failures = 0;
    TEST("replay-canary: bg stuck past budget => BLOCKED (not FAIL), exit 2") {
        char verdict[16], reason[64];
        int ec = run_canary_selftest("fail-timeout", "anchor",
                                     verdict, sizeof(verdict),
                                     reason, sizeof(reason));
        if (ec == -999) { printf("SKIP (repo root not found)\n"); break; }
        ASSERT_EQ(ec, 2);
        ASSERT_STR_EQ(verdict, "BLOCKED");
        ASSERT_STR_EQ(reason, "budget_exceeded_incomplete_no_parity_evidence");
        PASS();
    } _test_next:;
    return failures;
}

/* COMPLETE is not proof: the verdict also needs verified_height at the tip
 * and no verification_incomplete flag. Unproven is BLOCKED, never PASS. */
static int test_verified_at_tip_passes(void)
{
    int failures = 0;
    TEST("replay-canary: verified_height == tip, not incomplete => PASS") {
        char verdict[16], reason[64];
        int ec = run_canary_selftest("pass", "anchor", verdict,
                                     sizeof(verdict), reason, sizeof(reason));
        if (ec == -999) { printf("SKIP (repo root not found)\n"); break; }
        ASSERT_EQ(ec, 0);
        ASSERT_STR_EQ(verdict, "PASS");
        ASSERT(strstr(g_last_sentinel, "\"verified_height\":3145329"));
        PASS();
    } _test_next:;
    return failures;
}

static int test_complete_below_tip_is_not_pass(void)
{
    int failures = 0;
    TEST("replay-canary: state COMPLETE but verified_height < tip => BLOCKED") {
        char verdict[16], reason[64];
        int ec = run_canary_selftest("fail-verified-below-tip", "anchor",
                                     verdict, sizeof(verdict),
                                     reason, sizeof(reason));
        if (ec == -999) { printf("SKIP (repo root not found)\n"); break; }
        ASSERT_EQ(ec, 2);
        ASSERT_STR_EQ(verdict, "BLOCKED");
        ASSERT_STR_EQ(reason, "verified_height_below_tip_no_parity_evidence");
        PASS();
    } _test_next:;
    return failures;
}

static int test_incomplete_flag_is_not_pass(void)
{
    int failures = 0;
    TEST("replay-canary: verification_incomplete=true at tip => BLOCKED") {
        char verdict[16], reason[64];
        int ec = run_canary_selftest("fail-incomplete-flag", "genesis",
                                     verdict, sizeof(verdict),
                                     reason, sizeof(reason));
        if (ec == -999) { printf("SKIP (repo root not found)\n"); break; }
        ASSERT_EQ(ec, 2);
        ASSERT_STR_EQ(verdict, "BLOCKED");
        ASSERT_STR_EQ(reason, "verification_incomplete_no_parity_evidence");
        PASS();
    } _test_next:;
    return failures;
}

static int test_timeout_keeps_last_observed_values(void)
{
    int failures = 0;
    TEST("replay-canary: timeout evidence keeps last real verified/tip") {
        char verdict[16], reason[64];
        int ec = run_canary_selftest("timeout-last-observed", "anchor",
                                     verdict, sizeof(verdict),
                                     reason, sizeof(reason));
        if (ec == -999) { printf("SKIP (repo root not found)\n"); break; }
        ASSERT_EQ(ec, 2);
        ASSERT_STR_EQ(verdict, "BLOCKED");
        ASSERT_STR_EQ(reason, "budget_exceeded_incomplete_no_parity_evidence");
        ASSERT(strstr(g_last_sentinel, "\"bg_state\":\"timeout\""));
        ASSERT(strstr(g_last_sentinel, "\"last_state\":\"running\""));
        ASSERT(strstr(g_last_sentinel, "\"verified_height\":3000000"));
        ASSERT(strstr(g_last_sentinel, "\"tip\":3145329"));
        PASS();
    } _test_next:;
    return failures;
}

/* The elapsed-time band: a from-anchor COMPLETE that arrives implausibly
 * fast (seed never applied) blows the floor; one that degrades to a
 * genesis-scale replay blows the ceiling. Both FAIL with a typed reason
 * before cross-node equality can mask a degraded-but-matching tip. */
static int test_fail_elapsed_too_fast_fires(void)
{
    int failures = 0;
    TEST("replay-canary: COMPLETE too fast => FAIL reason=elapsed_too_fast") {
        char verdict[16], reason[64];
        int ec = run_canary_selftest("fail-elapsed-fast", "anchor",
                                     verdict, sizeof(verdict),
                                     reason, sizeof(reason));
        if (ec == -999) { printf("SKIP (repo root not found)\n"); break; }
        ASSERT(ec != 0);
        ASSERT_STR_EQ(verdict, "FAIL");
        ASSERT_STR_EQ(reason, "elapsed_too_fast");
        PASS();
    } _test_next:;
    return failures;
}

static int test_fail_elapsed_too_slow_fires(void)
{
    int failures = 0;
    TEST("replay-canary: anchor degraded to genesis-scale => FAIL reason=elapsed_too_slow") {
        char verdict[16], reason[64];
        int ec = run_canary_selftest("fail-elapsed-slow", "anchor",
                                     verdict, sizeof(verdict),
                                     reason, sizeof(reason));
        if (ec == -999) { printf("SKIP (repo root not found)\n"); break; }
        ASSERT(ec != 0);
        ASSERT_STR_EQ(verdict, "FAIL");
        ASSERT_STR_EQ(reason, "elapsed_too_slow");
        PASS();
    } _test_next:;
    return failures;
}

/* Seed a STALE PASS sentinel (a previous successful run's leftover) into a
 * verdict dir, back-dated so it cannot be mistaken for fresh. Returns the
 * stale ts written (0 on failure). */
static long seed_stale_pass(const char *vd, const char *from)
{
    char sentinel[PATH_MAX];
    snprintf(sentinel, sizeof(sentinel), "%s/replay_canary_%s.json", vd, from);
    long stale_ts = 1000000000L;  /* a 2001 timestamp — unambiguously old */
    FILE *f = fopen(sentinel, "w");
    if (!f) return 0;
    fprintf(f,
        "{\"verdict\":\"PASS\",\"from\":\"%s\",\"ts\":%ld,\"started_ts\":%ld,"
        "\"build_commit\":\"stale\",\"tip\":3145329,\"verified_height\":3145329,"
        "\"bg_state\":\"complete\",\"consensus_rejects\":0,"
        "\"local_sha3\":\"deadbeef\",\"expected_sha3\":\"\",\"txouts\":1,"
        "\"zd_txouts\":1,\"supply\":\"0\",\"zd_supply\":\"0\","
        "\"reason\":\"\",\"elapsed_sec\":2700}\n",
        from, stale_ts, stale_ts);
    fclose(f);
    /* Back-date the file mtime so a freshness/mtime reader also sees it old. */
    struct timespec times[2] = {
        { .tv_sec = stale_ts, .tv_nsec = 0 },
        { .tv_sec = stale_ts, .tv_nsec = 0 },
    };
    if (utimensat(AT_FDCWD, sentinel, times, 0) != 0) { /* best-effort */ }
    return stale_ts;
}

/* Polls for `stamp` until it exists or worker `pid` has exited (reaped
 * here; *gone reports it). No poll count bounds the wait: the worker's own
 * alarm() bounds its life, so a loaded box only slows the answer down. */
static bool canary_wait_stamp(const char *stamp, pid_t pid, bool *gone)
{
    struct stat st;
    int status = 0;
    struct timespec poll = { .tv_sec = 0, .tv_nsec = 10 * 1000 * 1000 };
    *gone = false;
    for (;;) {
        if (stat(stamp, &st) == 0)
            return true;
        if (waitpid(pid, &status, WNOHANG) == pid) {
            *gone = true;
            return false;
        }
        nanosleep(&poll, NULL);
    }
}

/* Never exit 0 as proof:
 *
 *   1. A stale PASS from a previous run is pre-seeded in the verdict dir;
 *      the harness must remove it at run start (reset_verdict).
 *   2. The harness is killed after reset_verdict but before it writes a
 *      fresh sentinel (its self-test blocks on a never-fed FIFO via
 *      ZCL_CANARY_SELFTEST_BLOCK_FIFO). The post-kill read must find no
 *      sentinel, so absence of a fresh PASS resolves FAIL.
 *
 * This proves a kill inside an actual run leaves no fresh PASS. */
static int test_sigkill_midrun_clears_stale_no_fresh_pass(void)
{
    int failures = 0;
    TEST("replay-canary: SIGKILL mid-run clears stale PASS, leaves NO fresh PASS") {
        const char *root = repo_root();
        if (!root) { printf("SKIP (repo root not found)\n"); break; }

        char fx[PATH_MAX], vd[PATH_MAX], fifo[PATH_MAX];
        char identity_bin[PATH_MAX];
        snprintf(fx, sizeof(fx), "/tmp/test_canary_kill_fx_%d", (int)getpid());
        snprintf(vd, sizeof(vd), "/tmp/test_canary_kill_vd_%d", (int)getpid());
        snprintf(fifo, sizeof(fifo), "/tmp/test_canary_kill_fifo_%d", (int)getpid());
        mkdir(fx, 0755);
        mkdir(vd, 0755);
        /* Valid fixtures: an UNINTERRUPTED run would write a fresh PASS. */
        seed_fixtures(fx, "pass");
        if (!write_identity_fixture_binary(fx, identity_bin,
                                           sizeof(identity_bin))) {
            printf("FAIL (could not create identity fixture)\n");
            failures++; goto _kill_cleanup;
        }
        /* A stale PASS leftover from a previous successful run. */
        long stale_ts = seed_stale_pass(vd, "anchor");
        if (stale_ts == 0) {
            printf("FAIL (could not seed stale sentinel)\n");
            failures++; goto _kill_cleanup;
        }

        unlink(fifo);
        if (mkfifo(fifo, 0644) != 0) {
            printf("FAIL (mkfifo: %s)\n", strerror(errno));
            failures++; goto _kill_cleanup;
        }

        char sentinel[PATH_MAX];
        snprintf(sentinel, sizeof(sentinel), "%s/replay_canary_anchor.json", vd);
        char stamp[PATH_MAX];
        snprintf(stamp, sizeof(stamp), "%s/.run_started_anchor", vd);
        unlink(stamp);

#if defined(__linux__)
        pid_t parent_pid = getpid();
#endif
        pid_t pid = fork();
        if (pid == 0) {
            /* Child in its own group: the real harness clears the stale
             * sentinel before its self-test can block on the FIFO. */
#if defined(__linux__)
            /* A cancelled proof can kill the test worker before its explicit
             * kill below. Do not leave the blocked harness orphaned with the
             * inherited checkout lock indefinitely. */
            if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 ||
                getppid() != parent_pid)
                _exit(126);
#endif
            /* Portable bound if the worker disappears on a platform without
             * a parent-death signal. Normal self-test kills within seconds. */
            alarm(15);
            setsid();
            /* Exercise the run-start handshake under delayed scheduling. */
            struct timespec delayed_start = { .tv_sec = 0,
                .tv_nsec = 750 * 1000 * 1000 };
            nanosleep(&delayed_start, NULL);
            char cmd[PATH_MAX * 5];
            snprintf(cmd, sizeof(cmd),
                "ZCL_CANARY_SELFTEST_DIR='%s' ZCL_CANARY_VERDICT_DIR='%s' "
                "ZCL_CANARY_SELFTEST_BLOCK_FIFO='%s' "
                "ZCL_CANARY_SELFTEST_NODE_BIN='%s' "
                "exec bash '%s/%s' --from=anchor --self-test=pass",
                fx, vd, fifo, identity_bin, root, CANARY_REL);
            execlp("sh", "sh", "-c", cmd, (char *)NULL);
            _exit(127);
        }

        /* Wait for reset_verdict's stamp or for the worker to end, never
         * for a poll count: a loaded box only slows the stamp down. The
         * worker's own alarm() bounds how long it can live, so a missing
         * stamp still fails once the worker is gone. */
        bool worker_gone = false;
        bool stamp_present = canary_wait_stamp(stamp, pid, &worker_gone);
        struct stat st_mid;
        bool exists_mid = (stat(sentinel, &st_mid) == 0);

        kill(-pid, SIGKILL);
        kill(pid, SIGKILL);
        int wstatus = 0;
        if (!worker_gone)
            waitpid(pid, &wstatus, 0);

        struct stat st_after;
        bool exists_after = (stat(sentinel, &st_after) == 0);

        if (!stamp_present) {
            printf("FAIL: run-start stamp %s absent — harness never reached "
                   "reset_verdict, the kill proves nothing\n", stamp);
            failures++; goto _kill_cleanup;
        }
        if (exists_mid) {
            printf("FAIL: stale sentinel %s survived reset_verdict mid-run "
                   "— staleness contract is vaporware\n", sentinel);
            failures++; goto _kill_cleanup;
        }
        if (exists_after) {
            printf("FAIL: sentinel %s exists after SIGKILL — exit-0/stale-file "
                   "-as-proof leak\n", sentinel);
            failures++; goto _kill_cleanup;
        }
        PASS();

    _kill_cleanup:;
        unlink(fifo);
        char rm[PATH_MAX + 32];
        snprintf(rm, sizeof(rm), "rm -rf '%s' '%s'", fx, vd);
        if (system(rm) != 0) { /* best-effort */ }
    }
    return failures;
}

/* A completing run must replace a stale PASS with a fresh one: started_ts
 * reflects this run, so a freshness reader (Makefile guard, live Condition)
 * never sees the previous run's verdict. */
static int test_pass_replaces_stale_sentinel(void)
{
    int failures = 0;
    TEST("replay-canary: a fresh PASS overwrites a stale PASS sentinel") {
        const char *root = repo_root();
        if (!root) { printf("SKIP (repo root not found)\n"); break; }

        char fx[PATH_MAX], vd[PATH_MAX], identity_bin[PATH_MAX];
        snprintf(fx, sizeof(fx), "/tmp/test_canary_stale_fx_%d", (int)getpid());
        snprintf(vd, sizeof(vd), "/tmp/test_canary_stale_vd_%d", (int)getpid());
        mkdir(fx, 0755);
        mkdir(vd, 0755);
        seed_fixtures(fx, "pass");
        ASSERT(write_identity_fixture_binary(fx, identity_bin,
                                              sizeof(identity_bin)));
        long stale_ts = seed_stale_pass(vd, "anchor");
        ASSERT(stale_ts != 0);

        char cmd[PATH_MAX * 4];
        snprintf(cmd, sizeof(cmd),
            "ZCL_CANARY_SELFTEST_DIR='%s' ZCL_CANARY_VERDICT_DIR='%s' "
            "ZCL_CANARY_SELFTEST_NODE_BIN='%s' "
            "bash '%s/%s' --from=anchor --self-test=pass >/dev/null 2>&1",
            fx, vd, identity_bin, root, CANARY_REL);
        int rc = system(cmd);
        ASSERT_EQ((rc == -1) ? -1 : WEXITSTATUS(rc), 0);

        char sentinel[PATH_MAX];
        snprintf(sentinel, sizeof(sentinel), "%s/replay_canary_anchor.json", vd);
        char buf[2048] = {0};
        ASSERT(read_file(sentinel, buf, sizeof(buf)));
        /* Verdict still PASS, but started_ts is the CURRENT run, not stale. */
        ASSERT(strstr(buf, "\"verdict\":\"PASS\"") != NULL);
        ASSERT(strstr(buf, "\"source_id_sha256\":") != NULL);
        ASSERT(strstr(buf, "\"artifact_sha256\":") != NULL);
        const char *s = strstr(buf, "\"started_ts\":");
        ASSERT(s != NULL);
        long got = atol(s + strlen("\"started_ts\":"));
        if (got <= stale_ts) {
            printf("FAIL: started_ts %ld is not newer than stale %ld — "
                   "the stale sentinel was not refreshed\n", got, stale_ts);
            failures++;
        } else {
            PASS();
        }

        char rm[PATH_MAX + 32];
        snprintf(rm, sizeof(rm), "rm -rf '%s' '%s'", fx, vd);
        if (system(rm) != 0) { /* best-effort */ }
    } _test_next:;
    return failures;
}

/* Open the FIFO's write end once the child reads it. Retries while the
 * child lives (cap near 180 s, 10 ms per tick; a loaded proof host can
 * delay the forked bash script well past 30 s); a child that exits early
 * is reaped here and its status kept, so a healthy child costs no wait. */
#define CANARY_FIFO_WAIT_TICKS 18000
static int canary_open_fifo_writer(pid_t pid, const char *fifo,
                                   int *wstatus, bool *reaped)
{
    for (int i = 0; i < CANARY_FIFO_WAIT_TICKS; i++) {
        int writer = open(fifo, O_WRONLY | O_NONBLOCK);
        if (writer >= 0) return writer;
        if (errno != ENXIO && errno != ENOENT) return -1;
        if (waitpid(pid, wstatus, WNOHANG) == pid) { *reaped = true; return -1; }
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 10 * 1000 * 1000 };
        nanosleep(&ts, NULL); /* real-clock: pre-existing bounded poll loop, seeded when check_no_real_clock_test_deadline.sh was introduced */
    }
    return -1;
}

/* A replay can run for hours while build/bin is replaced. The harness must
 * bind its verdict to identity captured before the run, not re-query a
 * mutable executable path when it writes PASS. This fixture swaps the fake
 * executable from source A to source B after capture, then completes. */
static int test_identity_is_captured_once_before_replay(void)
{
    int failures = 0;
    TEST("replay-canary: verdict identity survives executable-path replacement") {
        const char *root = repo_root();
        if (!root) { printf("SKIP (repo root not found)\n"); break; }

        char fx[PATH_MAX], vd[PATH_MAX], fifo[PATH_MAX], fake[PATH_MAX];
        snprintf(fx, sizeof(fx), "/tmp/test_canary_id_fx_%d", (int)getpid());
        snprintf(vd, sizeof(vd), "/tmp/test_canary_id_vd_%d", (int)getpid());
        snprintf(fifo, sizeof(fifo), "/tmp/test_canary_id_fifo_%d", (int)getpid());
        snprintf(fake, sizeof(fake), "/tmp/test_canary_id_bin_%d", (int)getpid());
        mkdir(fx, 0755);
        mkdir(vd, 0755);
        seed_fixtures(fx, "pass");

        char script_a[512];
        snprintf(script_a, sizeof(script_a),
                 "#!/usr/bin/env bash\n"
                 "if [ \"${1:-}\" = agentbuild ]; then\n"
                 "  printf '%%s\\n' '{\"source_id_sha256\":\"%s\","
                 "\"build_commit\":\"trace-a\"}'\n"
                 "  exit 0\n"
                 "fi\n"
                 "exit 2\n", CANARY_SOURCE_A);
        write_file("/tmp", strrchr(fake, '/') + 1, script_a);
        bool fake_ready = chmod(fake, 0700) == 0;
        char expected_artifact[65] = {0};
        fake_ready = fake_ready && sha256_file_hex(fake, expected_artifact);

        unlink(fifo);
        bool fifo_ready = mkfifo(fifo, 0600) == 0;
        pid_t pid = -1;
        if (fake_ready && fifo_ready) pid = fork();
        if (pid == 0) {
            setsid();
            char cmd[PATH_MAX * 5];
            snprintf(cmd, sizeof(cmd),
                     "ZCL_CANARY_SELFTEST_DIR='%s' "
                     "ZCL_CANARY_VERDICT_DIR='%s' "
                     "ZCL_CANARY_SELFTEST_BLOCK_FIFO='%s' "
                     "ZCL_CANARY_SELFTEST_NODE_BIN='%s' "
                     "exec bash '%s/%s' --from=anchor --self-test=pass",
                     fx, vd, fifo, fake, root, CANARY_REL);
            execlp("sh", "sh", "-c", cmd, (char *)NULL);
            _exit(127);
        }

        bool reaped = false;
        int wstatus = 0;
        int writer = (pid > 0) ? canary_open_fifo_writer(pid, fifo, &wstatus, &reaped) : -1;

        bool swapped = false;
        if (writer >= 0) {
            char script_b[512];
            snprintf(script_b, sizeof(script_b),
                     "#!/usr/bin/env bash\n"
                     "if [ \"${1:-}\" = agentbuild ]; then\n"
                     "  printf '%%s\\n' '{\"source_id_sha256\":\"%s\","
                     "\"build_commit\":\"trace-b\"}'\n"
                     "  exit 0\n"
                     "fi\n"
                     "exit 2\n", CANARY_SOURCE_B);
            write_file("/tmp", strrchr(fake, '/') + 1, script_b);
            swapped = chmod(fake, 0700) == 0;
            if (write(writer, "continue\n", 9) != 9) swapped = false;
            close(writer);
        }

        if (pid > 0 && !reaped) {
            if (writer < 0) {
                kill(-pid, SIGKILL);
                kill(pid, SIGKILL);
            }
            waitpid(pid, &wstatus, 0);
        }

        char sentinel[PATH_MAX], body[4096] = {0};
        snprintf(sentinel, sizeof(sentinel),
                 "%s/replay_canary_anchor.json", vd);
        bool sentinel_ok = read_file(sentinel, body, sizeof(body));
        char expected_source[128], rejected_source[128], expected_binary[128];
        snprintf(expected_source, sizeof(expected_source),
                 "\"source_id_sha256\":\"%s\"", CANARY_SOURCE_A);
        snprintf(rejected_source, sizeof(rejected_source),
                 "\"source_id_sha256\":\"%s\"", CANARY_SOURCE_B);
        snprintf(expected_binary, sizeof(expected_binary),
                 "\"artifact_sha256\":\"%s\"", expected_artifact);
        bool child_ok = pid > 0 && WIFEXITED(wstatus) &&
                        WEXITSTATUS(wstatus) == 0;
        bool source_ok = sentinel_ok && strstr(body, expected_source) != NULL &&
                         strstr(body, rejected_source) == NULL;
        bool artifact_ok = sentinel_ok &&
                           strstr(body, expected_binary) != NULL;

        unlink(fifo);
        unlink(fake);
        char rm[PATH_MAX * 2 + 32];
        snprintf(rm, sizeof(rm), "rm -rf '%s' '%s'", fx, vd);
        if (system(rm) != 0) { /* best-effort */ }

        ASSERT(fake_ready);
        ASSERT(fifo_ready);
        ASSERT(writer >= 0);
        ASSERT(swapped);
        ASSERT(child_ok);
        ASSERT(source_ok);
        ASSERT(artifact_ok);
        PASS();
    } _test_next:;
    return failures;
}

/* The verdict is per-`--from`: a genesis fixture writes a genesis-named
 * sentinel, an anchor fixture an anchor-named one. Confirms the sentinel
 * naming the systemd units + staleness check rely on. */
static int test_from_genesis_sentinel_name(void)
{
    int failures = 0;
    TEST("replay-canary: --from=genesis writes the genesis-named sentinel") {
        char verdict[16], reason[64];
        int ec = run_canary_selftest("pass", "genesis",
                                     verdict, sizeof(verdict),
                                     reason, sizeof(reason));
        if (ec == -999) { printf("SKIP (repo root not found)\n"); break; }
        ASSERT_EQ(ec, 0);
        ASSERT_STR_EQ(verdict, "PASS");
        PASS();
    } _test_next:;
    return failures;
}

/* A self-test whose binary-identity capture fails (nonexistent or
 * non-executable ZCL_CANARY_SELFTEST_NODE_BIN) could not attempt a replay:
 * it must write a BLOCKED sentinel (exit 2), never a FAIL (exit 1), so a
 * reader can tell an unmet prerequisite from a consensus-grade anomaly.
 * Only verdict=="FAIL" pages (canary_sentinel_watch.h); BLOCKED is inert. */
static int test_blocked_on_identity_capture_failure(void)
{
    int failures = 0;
    TEST("replay-canary: unusable node binary => BLOCKED (not FAIL), exit 2") {
        const char *root = repo_root();
        if (!root) { printf("SKIP (repo root not found)\n"); break; }

        char fx[PATH_MAX], vd[PATH_MAX];
        snprintf(fx, sizeof(fx), "/tmp/test_canary_blocked_fx_%d", (int)getpid());
        snprintf(vd, sizeof(vd), "/tmp/test_canary_blocked_vd_%d", (int)getpid());
        mkdir(fx, 0755);
        mkdir(vd, 0755);
        seed_fixtures(fx, "pass");

        /* A path that cannot exist: capture_binary_identity's `[ -x "$binary" ]`
         * guard must reject it, driving run_self_test's identity-capture
         * failure branch. */
        char bogus_bin[PATH_MAX];
        snprintf(bogus_bin, sizeof(bogus_bin),
                 "/tmp/test_canary_blocked_no_such_binary_%d", (int)getpid());

        char cmd[PATH_MAX * 4];
        snprintf(cmd, sizeof(cmd),
            "ZCL_CANARY_SELFTEST_DIR='%s' ZCL_CANARY_VERDICT_DIR='%s' "
            "ZCL_CANARY_SELFTEST_NODE_BIN='%s' "
            "bash '%s/%s' --from=anchor --self-test=pass >/dev/null 2>&1",
            fx, vd, bogus_bin, root, CANARY_REL);
        int rc = system(cmd);
        int exit_code = (rc == -1) ? -1 : WEXITSTATUS(rc);

        char sentinel[PATH_MAX];
        snprintf(sentinel, sizeof(sentinel), "%s/replay_canary_anchor.json", vd);
        char buf[2048] = {0};
        bool have_sentinel = read_file(sentinel, buf, sizeof(buf));

        char rm[PATH_MAX + 32];
        snprintf(rm, sizeof(rm), "rm -rf '%s' '%s'", fx, vd);
        if (system(rm) != 0) { /* best-effort cleanup */ }

        ASSERT_EQ(exit_code, 2);
        ASSERT(have_sentinel);
        ASSERT(strstr(buf, "\"verdict\":\"BLOCKED\"") != NULL);
        ASSERT(strstr(buf, "\"reason\":\"source_identity_capture_failed\"") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* A missing co-located zclassicd is an unmet prerequisite, not a consensus
 * finding. The live-mode preflight, given an invalid RPC port, must fail
 * fast, leave a durable BLOCKED sentinel, and never spawn the mainnet
 * candidate or wait out the replay budget. */
static int test_blocked_on_oracle_rpc_unreachable(void)
{
    int failures = 0;
    TEST("replay-canary: absent zclassicd RPC => fast BLOCKED, not replay FAIL") {
        const char *root = repo_root();
        if (!root) { printf("SKIP (repo root not found)\n"); break; }

        char vd[PATH_MAX];
        snprintf(vd, sizeof(vd), "/tmp/test_canary_oracle_vd_%d", (int)getpid());
        mkdir(vd, 0755);

        char cmd[PATH_MAX * 3];
        snprintf(cmd, sizeof(cmd),
            "ZCL_CANARY_VERDICT_DIR='%s' "
            "bash '%s/%s' --from=genesis --zclassicd-rpc=1 "
            "--zclassicd-p2p=1 >/dev/null 2>&1",
            vd, root, CANARY_REL);
        int64_t started_ms = platform_time_monotonic_ms();
        int rc = system(cmd);
        int64_t elapsed_ms = platform_time_monotonic_ms() - started_ms;
        int exit_code = (rc == -1) ? -1 : WEXITSTATUS(rc);

        char sentinel[PATH_MAX];
        snprintf(sentinel, sizeof(sentinel), "%s/replay_canary_genesis.json", vd);
        char buf[2048] = {0};
        bool have_sentinel = read_file(sentinel, buf, sizeof(buf));

        char rm[PATH_MAX + 32];
        snprintf(rm, sizeof(rm), "rm -rf '%s'", vd);
        if (system(rm) != 0) { /* best-effort cleanup */ }

        ASSERT_EQ(exit_code, 2);
        ASSERT(elapsed_ms < 30000);
        ASSERT(have_sentinel);
        ASSERT(strstr(buf, "\"verdict\":\"BLOCKED\"") != NULL);
        ASSERT(strstr(buf, "\"reason\":\"oracle_rpc_unreachable\"") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Static source guards ──────────────────────────────────────────
 *
 * These checks pin shell-level invariants the fixture harness cannot reach
 * without a real mainnet node:
 *
 *   1. Every blob variable is always bound (script-wide default
 *      SD=""; DIAG=""; UC=""; TX=""; ZD="" plus an explicit UC= in the
 *      timeout branch), so evaluate_verdict never dies on an unbound
 *      reference under `set -u` before fail() writes a sentinel.
 *   2. "Cannot attempt a replay" conditions (missing binary, no disk, bad
 *      source datadir, failed header import) route through blocked(), not a
 *      bare `exit`, leaving a typed sentinel distinct from a MISMATCH.
 *   3. The genesis track's only real peer is dialed via -connect= (which
 *      disables DNS-seed/addrman discovery), never -addnode=, so a run
 *      cannot reach public IPs outside the isolated fixture network.
 *   4. isolated_mainnet_env.sh's iso_die still routes a fatal isolation
 *      setup problem through blocked() when the sourcing script defines it.
 */

static bool read_script_source(const char *root, const char *rel,
                               char *buf, size_t bufsz)
{
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/%s", root, rel) >= (int)sizeof(path))
        return false;
    return read_file(path, buf, bufsz);
}

static int test_source_guard_no_unbound_result_vars(void)
{
    int failures = 0;
    TEST("replay-canary: SD/DIAG/UC/TX/ZD always defaulted + timeout branch sets UC") {
        const char *root = repo_root();
        if (!root) { printf("SKIP (repo root not found)\n"); break; }

        static char body[65536];
        ASSERT(read_script_source(root, CANARY_REL, body, sizeof(body)));

        /* (1a) the script-wide default that makes every blob variable
         * always-bound regardless of which run mode/branch populates it. */
        ASSERT(strstr(body, "SD=\"\"; DIAG=\"\"; UC=\"\"; TX=\"\"; ZD=\"\"") != NULL);

        /* (1b) the timeout branch (identified by its synthetic bg_state
         * marker) must assign UC before evaluate_verdict runs. Bounded
         * window so this cannot false-pass on a UC= assignment written
         * somewhere unrelated in the file. */
        const char *marker = strstr(body, "R_BGSTATE=\"timeout\"");
        ASSERT(marker != NULL);
        const char *eval_call = strstr(marker, "evaluate_verdict");
        ASSERT(eval_call != NULL);
        const char *uc_assign = strstr(marker, "UC=\"$(iso_rpc getutxocommitment)\"");
        ASSERT(uc_assign != NULL && uc_assign < eval_call);
        PASS();
    } _test_next:;
    return failures;
}

static int test_source_guard_missing_prereqs_route_through_blocked(void)
{
    int failures = 0;
    TEST("replay-canary: cannot-run prerequisites route through blocked(), not a bare exit") {
        const char *root = repo_root();
        if (!root) { printf("SKIP (repo root not found)\n"); break; }

        static char body[65536];
        ASSERT(read_script_source(root, CANARY_REL, body, sizeof(body)));

        static const char *want[] = {
            "blocked \"binary_missing_zclassic23\"",
            "blocked \"binary_missing_zcl_rpc\"",
            "blocked \"source_identity_capture_failed\"",
            "blocked \"insufficient_disk\"",
            "blocked \"src_datadir_missing\"",
            "blocked \"blockindex_import_failed\"",
            "blocked \"oracle_rpc_unreachable\"",
            "blocked \"oracle_p2p_unreachable\"",
        };
        for (size_t i = 0; i < sizeof(want) / sizeof(want[0]); i++) {
            if (!strstr(body, want[i])) {
                printf("FAIL: missing '%s' — a cannot-run prerequisite check "
                       "regressed to a bare exit instead of blocked()\n",
                       want[i]);
                failures++;
                goto _test_next;
            }
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_source_guard_genesis_uses_connect_not_addnode(void)
{
    int failures = 0;
    TEST("replay-canary: genesis dials zclassicd via -connect= (g_connect_only), never -addnode=") {
        const char *root = repo_root();
        if (!root) { printf("SKIP (repo root not found)\n"); break; }

        static char body[65536];
        ASSERT(read_script_source(root, CANARY_REL, body, sizeof(body)));

        /* The live invocation must use -connect=. (Checks the call site, not
         * prose that quotes the old flag.) */
        ASSERT(strstr(body, "iso_spawn_mainnet_node \"-nolegacyimport -connect=127.0.0.1:$ZD_P2P\"") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_source_guard_iso_die_routes_through_blocked(void)
{
    int failures = 0;
    TEST("replay-canary: isolated_mainnet_env.sh's iso_die routes through blocked() when defined") {
        const char *root = repo_root();
        if (!root) { printf("SKIP (repo root not found)\n"); break; }

        static char body[65536];
        ASSERT(read_script_source(root,
            "tools/scripts/isolated_mainnet_env.sh", body, sizeof(body)));

        const char *fn = strstr(body, "iso_die() {");
        ASSERT(fn != NULL);
        const char *close = strstr(fn, "\n}\n");
        ASSERT(close != NULL);
        const char *check = strstr(fn, "command -v blocked");
        ASSERT(check != NULL && check < close);
        const char *call = strstr(fn, "blocked \"isolation_setup_failed\"");
        ASSERT(call != NULL && call < close);
        PASS();
    } _test_next:;
    return failures;
}

static int test_source_guard_iso_scratch_root_stays_isolated(void)
{
    int failures = 0;
    TEST("replay-canary: scratch root is ZCL_ISO_SCRATCH_ROOT, cleanup still refuses live datadirs") {
        const char *root = repo_root();
        if (!root) { printf("SKIP (repo root not found)\n"); break; }

        static char env_body[65536];
        static char canary_body[65536];
        ASSERT(read_script_source(root,
            "tools/scripts/isolated_mainnet_env.sh", env_body,
            sizeof(env_body)));
        ASSERT(read_script_source(root, CANARY_REL, canary_body,
                                  sizeof(canary_body)));
        ASSERT(strstr(env_body,
                      "ISO_SCRATCH_ROOT=\"${ZCL_ISO_SCRATCH_ROOT:-/tmp}\"")
               != NULL);
        ASSERT(strstr(env_body, "iso_assert_scratch_root") != NULL);
        ASSERT(strstr(env_body,
                      "\"$HOME\"/.zclassic*") != NULL);
        ASSERT(strstr(env_body,
                      "\"${ISO_SCRATCH_ROOT}\"/zcl23-*") != NULL);
        ASSERT(strstr(canary_body,
                      "scratch=\"${ZCL_ISO_SCRATCH_ROOT:-/tmp}\"") != NULL);
        ASSERT(strstr(canary_body, "df -Pk \"$scratch\"") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_source_guard_replay_uses_empty_paramsdir(void)
{
    int failures = 0;
    TEST("replay-canary: child uses and rechecks an explicit empty paramsdir") {
        const char *root = repo_root();
        if (!root) { printf("SKIP (repo root not found)\n"); break; }

        static char env_body[65536];
        static char canary_body[65536];
        ASSERT(read_script_source(root,
            "tools/scripts/isolated_mainnet_env.sh", env_body,
            sizeof(env_body)));
        ASSERT(read_script_source(root, CANARY_REL, canary_body,
                                  sizeof(canary_body)));
        ASSERT(strstr(env_body,
                      "ISO_PARAMS_DIR=\"$ISO_DD/empty-params\"") != NULL);
        ASSERT(strstr(env_body,
                      "-paramsdir=\"$ISO_PARAMS_DIR\"") != NULL);
        ASSERT(strstr(canary_body,
                      "fail \"isolated_paramsdir_not_empty\"") != NULL);
        ASSERT(strstr(canary_body, "\"params_dir_empty\":%s") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_source_guard_mvp_binds_canary_to_running_binary(void)
{
    int failures = 0;
    TEST("mvp gate: C8 PASS requires replay identity to match running bytes") {
        const char *root = repo_root();
        if (!root) { printf("SKIP (repo root not found)\n"); break; }

        static char body[65536];
        ASSERT(read_script_source(root, "tools/mvp_gate.sh", body,
                                  sizeof(body)));
        ASSERT(strstr(body, "exe=\"/proc/$pid/exe\"") != NULL);
        ASSERT(strstr(body, "zcl_binary_source_id \"$exe\"") != NULL);
        ASSERT(strstr(body, "C_ARTIFACT=\"$(canary_field \"$document\" artifact_sha256 string)\"") != NULL);
        ASSERT(strstr(body, "\"$G_ARTIFACT\" == \"$LIVE_ARTIFACT\"") != NULL);
        ASSERT(strstr(body,
                      "PASS belongs to different or unreadable bytes") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_source_guard_mvp_binds_c3_stopwatch_to_running_binary(void)
{
    int failures = 0;
    TEST("mvp gate: C3 PASS requires a stopwatch receipt bound to running bytes") {
        const char *root = repo_root();
        if (!root) { printf("SKIP (repo root not found)\n"); break; }

        static char body[65536];
        ASSERT(read_script_source(root, "tools/mvp_gate.sh", body,
                                  sizeof(body)));
        ASSERT(strstr(body,
                      "--expect-artifact-sha256=\"$LIVE_ARTIFACT\"") != NULL);
        ASSERT(strstr(body, "set_v 3 \"PASS\"") != NULL);
        ASSERT(strstr(body, "node at-tip status is not this claim") != NULL);
        /* A live at-tip reading must never stand in for the stopwatch claim. */
        ASSERT(strstr(body, "elif [[ \"$AT_TIP\" == 1 ]]; then\n    set_v 3")
               == NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Registration ───────────────────────────────────────────────── */

static bool copy_gate_function(FILE *out, const char *source, const char *name)
{
    const char *start = strstr(source, name);
    if (!start) return false;
    const char *end = strstr(start, "\n}\n");
    if (!end) return false;
    size_t len = (size_t)(end + 3 - start);
    return fwrite(start, 1, len, out) == len;
}

static bool write_freshness_probe(const char *path, const char *source)
{
    FILE *out = fopen(path, "w");
    if (!out) return false;
    bool ok = copy_gate_function(out, source, "canary_decimal() {");
    ok = copy_gate_function(out, source, "canary_field() {") && ok;
    ok = copy_gate_function(out, source, "canary_read() {") && ok;
    const char *probe =
        "CANARY_DIR=$1; NOW_TS=$3; CANARY_MAX_AGE_S=$4; ZCL_JSONQ=$5\n"
        "f=$1/replay_canary_genesis.json\n"
        "case $2 in\n"
        "  @nul) printf '{\"verdict\":\"PASS\",\"ts\":1000000}\\0' > \"$f\";;\n"
        "  @oversize) dd if=/dev/zero of=\"$f\" bs=1048576 count=17 2>/dev/null;;\n"
        "  '{'*|'['*) printf '%s' \"$2\" > \"$f\";;\n"
        "  *) printf '{\"verdict\":\"PASS\",\"ts\":%s}' \"$2\" > \"$f\";;\n"
        "esac || exit 1\n"
        "canary_read genesis\n"
        "if [[ ${6:-} == identity ]]; then\n"
        "  printf '%s|%s|%s\\n' \"$C_SRC\" \"$C_ARTIFACT\" \"$C_VERDICT\"\n"
        "else printf '%s %s\\n' \"$C_FRESH\" \"$C_AGE\"; fi\n";
    ok = fputs(probe, out) >= 0 && ok;
    return fclose(out) == 0 && ok;
}

static bool run_freshness_probes(const char *script, const char *dir, const char *parser)
{
    static const struct { const char *ts, *now, *max, *expected; } cases[] = {
        {"1000000", "1000000", "604800", "1 0\n"},
        {"395200", "1000000", "604800", "1 604800\n"},
        {"395199", "1000000", "604800", "0 604801\n"},
        {"1000001", "1000000", "604800", "0 -1\n"},
        {"0", "1000000", "604800", "0 -1\n"},
        {"08", "1000000", "604800", "0 -1\n"},
        {"123oops", "1000000", "604800", "0 -1\n"},
        {"1e6", "1000000", "604800", "0 -1\n"},
        {"\"1000000\"", "1000000", "604800", "0 -1\n"},
        {"-1", "1000000", "604800", "0 -1\n"},
        {"9223372036854775808", "1000000", "604800", "0 -1\n"},
        {"999999999999999999999999999999", "1000000", "604800", "0 -1\n"},
        {"9223372036854775807", "9223372036854775807", "0", "1 0\n"},
        {"8", "10", "2", "1 2\n"},
        {"7", "10", "2", "0 3\n"},
        {"8", "010", "2", "0 -1\n"},
        {"8", "10", "9223372036854775808", "0 -1\n"},
        {"{\"note\":\"\\\"ts\\\":1000000,\",\"verdict\":\"PASS\"}", "1000000", "604800", "0 -1\n"},
        {"{\"nested\":{\"ts\":1000000},\"verdict\":\"PASS\"}", "1000000", "604800", "0 -1\n"},
        {"{\"ts\":1000000,\"ts\":1000000}", "1000000", "604800", "0 -1\n"},
        {"[1000000]", "1000000", "604800", "0 -1\n"},
        {"{\"ts\":1000000", "1000000", "604800", "0 -1\n"},
        {"@nul", "1000000", "604800", "0 -1\n"},
        {"@oversize", "1000000", "604800", "0 -1\n"}
    };
    bool ok = true;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        const char *argv[] = {"bash", script, dir, cases[i].ts,
                              cases[i].now, cases[i].max, parser, NULL};
        char output[128];
        int rc = zcl_spawn_capture(argv, output, sizeof(output), 5000);
        if (rc != 0 || strcmp(output, cases[i].expected) != 0) {
            fprintf(stderr, "canary freshness case %zu: rc=%d output=%s\n", i, rc, output);
            ok = false;
        }
    }
    return ok;
}

#define MVP_SOURCE_HALF "11111111111111111111111111111111"
#define MVP_SOURCE_HASH MVP_SOURCE_HALF MVP_SOURCE_HALF
#define MVP_ARTIFACT_HASH "2222222222222222222222222222222222222222222222222222222222222222"

static bool run_canary_identity_probes(const char *script, const char *dir, const char *parser)
{
    static const struct { const char *json, *expected; } cases[] = {
        {"{\"ts\":1000000,\"verdict\":\"PASS\",\"source_id_sha256\":\"" MVP_SOURCE_HASH "\",\"artifact_sha256\":\"" MVP_ARTIFACT_HASH "\"}", MVP_SOURCE_HASH "|" MVP_ARTIFACT_HASH "|PASS\n"},
        {"{\"ts\":1000000,\"verdict\":\"PASS\",\"note\":\"\\\"source_id_sha256\\\":\\\"" MVP_SOURCE_HASH "\\\",\\\"artifact_sha256\\\":\\\"" MVP_ARTIFACT_HASH "\\\"\"}", "||PASS\n"},
        {"{\"ts\":1000000,\"verdict\":\"FAIL\",\"source_id_sha256\":\"" MVP_SOURCE_HASH "\",\"artifact_sha256\":\"" MVP_ARTIFACT_HASH "\"}", MVP_SOURCE_HASH "|" MVP_ARTIFACT_HASH "|FAIL\n"},
        {"{\"ts\":1000000,\"verdict\":\"PASS\",\"source_id_sha256\":\"" MVP_SOURCE_HASH "\",\"source_id_sha256\":\"" MVP_ARTIFACT_HASH "\",\"artifact_sha256\":\"" MVP_SOURCE_HASH "\",\"artifact_sha256\":\"" MVP_ARTIFACT_HASH "\"}", "||PASS\n"},
        {"{\"ts\":1000000,\"verdict\":\"FAIL\",\"verdict\":\"PASS\"}", "||unreadable\n"},
        {"{\"ts\":1000000,\"verdict\":\"PASS\",\"source_id_sha256\":\"" MVP_SOURCE_HASH "\\u0000\",\"artifact_sha256\":\"" MVP_ARTIFACT_HASH "\\u0000\"}", "||PASS\n"},
        {"{\"ts\":1000000,\"verdict\":\"PASS\",\"source_id_sha256\":\"" MVP_SOURCE_HALF "\\u0000" MVP_SOURCE_HALF "\",\"artifact_sha256\":\"" MVP_ARTIFACT_HASH "\"}", "|" MVP_ARTIFACT_HASH "|PASS\n"},
        {"{\"ts\":1000000,\"verdict\":\"PASS\",\"source_id_sha256\":\"" MVP_SOURCE_HASH "\\n\",\"artifact_sha256\":\"" MVP_ARTIFACT_HASH "\\n\"}", "||PASS\n"},
        {"{\"ts\":1000000,\"verdict\":\"PASS\\u0000\",\"source_id_sha256\":\"" MVP_SOURCE_HASH "\",\"artifact_sha256\":\"" MVP_ARTIFACT_HASH "\"}", MVP_SOURCE_HASH "|" MVP_ARTIFACT_HASH "|unreadable\n"}
    };
    bool ok = true;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        const char *argv[] = {"bash", script, dir, cases[i].json, "1000000", "604800", parser, "identity", NULL};
        char output[256];
        int rc = zcl_spawn_capture(argv, output, sizeof(output), 5000);
        if (rc != 0 || strcmp(output, cases[i].expected) != 0) {
            fprintf(stderr, "canary identity case %zu: rc=%d output=%s\n", i, rc, output);
            ok = false;
        }
    }
    const char *missing[] = {"bash", script, dir, cases[0].json, "1000000",
                             "604800", "/nonexistent/z23-jsonq", "identity", NULL};
    char output[128];
    int rc = zcl_spawn_capture(missing, output, sizeof(output), 5000);
    return rc == 0 && strcmp(output, "||unavailable\n") == 0 && ok;
}

static int test_mvp_canary_freshness(void)
{
    int failures = 0;
    char dir[PATH_MAX] = "", script[PATH_MAX] = "", verdict[PATH_MAX] = "";
    TEST("MVP canary: production freshness refuses future and invalid decimals") {
        const char *root = repo_root();
        ASSERT(root != NULL);
        static char source[65536];
        ASSERT(read_script_source(root, "tools/mvp_gate.sh", source, sizeof(source)));
        ASSERT(test_mkdtemp(dir, sizeof(dir), "mvp-canary-freshness") != NULL);
        ASSERT(snprintf(script, sizeof(script), "%s/probe.sh", dir) < (int)sizeof(script));
        ASSERT(snprintf(verdict, sizeof(verdict), "%s/replay_canary_genesis.json", dir) < (int)sizeof(verdict));
        ASSERT(write_freshness_probe(script, source));
        char parser[PATH_MAX];
        ASSERT(snprintf(parser, sizeof(parser), "%s/build/bin/jsonq", root) < (int)sizeof(parser));
        ASSERT(access(parser, X_OK) == 0);
        ASSERT(run_freshness_probes(script, dir, parser));
        ASSERT(run_canary_identity_probes(script, dir, parser));
    } _test_next:;
    if (script[0]) unlink(script);
    if (verdict[0]) unlink(verdict);
    if (dir[0]) rmdir(dir);
    return failures;
}

static int test_replay_canary_verdict_platform_arm(void)
{
    int failures = 0;
    failures += test_pass_writes_pass_sentinel();
    failures += test_mvp_canary_freshness();
    failures += test_source_guard_mvp_binds_c3_stopwatch_to_running_binary();
    failures += test_fail_rejects_fires();
    failures += test_fail_sha3_fires();
    failures += test_missing_sha3_fires();
    failures += test_malformed_sha3_fires();
    failures += test_fail_crossnode_fires();
    failures += test_fail_exact_sha3_fires();
    failures += test_pass_exact_skew_skips_tier();
    failures += test_fail_exact_unreadable_fires();
    failures += test_timeout_blocks_rather_than_fails();
    failures += test_verified_at_tip_passes();
    failures += test_complete_below_tip_is_not_pass();
    failures += test_incomplete_flag_is_not_pass();
    failures += test_timeout_keeps_last_observed_values();
    failures += test_fail_elapsed_too_fast_fires();
    failures += test_fail_elapsed_too_slow_fires();
    failures += test_sigkill_midrun_clears_stale_no_fresh_pass();
    failures += test_pass_replaces_stale_sentinel();
    failures += test_identity_is_captured_once_before_replay();
    failures += test_from_genesis_sentinel_name();
    failures += test_blocked_on_identity_capture_failure();
    failures += test_blocked_on_oracle_rpc_unreachable();
    failures += test_source_guard_no_unbound_result_vars();
    failures += test_source_guard_missing_prereqs_route_through_blocked();
    failures += test_source_guard_genesis_uses_connect_not_addnode();
    failures += test_source_guard_iso_die_routes_through_blocked();
    failures += test_source_guard_iso_scratch_root_stays_isolated();
    failures += test_source_guard_replay_uses_empty_paramsdir();
    failures += test_source_guard_mvp_binds_canary_to_running_binary();
    return failures;
}
#else  /* _WIN32 */
/* Windows has no fork()/waitpid process model; this group's fork/exec verdict-child lane
 * cannot run here. Skipped loudly rather than faked. */
static int test_replay_canary_verdict_platform_arm(void)
{
    printf("replay_canary_verdict: SKIP (Windows): fork/exec verdict-child lane\n");
    return 0;
}
#endif

int test_replay_canary_verdict(void)
{
    return test_replay_canary_verdict_platform_arm();
}
