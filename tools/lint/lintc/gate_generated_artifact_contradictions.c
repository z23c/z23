/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 *
 * Gates: check-generated-artifact-contradictions
 * Single-gate family, four files under the 700-line family ceiling:
 * gate_generated_artifact_contradictions.c (this file) holds the gate
 * body — the capability-artifact discovery, the consumed-arm derivation,
 * the header/claim chain, the verdict loops, and the gate entry;
 * gate_generated_artifact_contradictions_scan.c holds the native scanners
 * (the git grep -l file test, the sed line-1 reads and BRE extractions,
 * the baseline row set, the inventory parse);
 * gate_generated_artifact_contradictions_workers.c holds the --selftest
 * probes; gate_generated_artifact_contradictions.h holds the shared
 * structs and prototypes. Placement ruling (2026-09-06, Linux side): the
 * small-pattern, ratchet, tree-walk, and git-scan families are claimed or
 * full, so new ports land in their own files; the older in-file routing
 * comments that would have folded this gate into an existing family are
 * overridden by that ruling.
 */

/* ── check-generated-artifact-contradictions ─────────────────────────────
 * Byte-parity C23 port of
 * tools/lint/check_generated_artifact_contradictions.sh (fail closed when
 * the generated evidence artifacts disagree: the capability inventory
 * declares its consumed arm baseline in its own first record, and every
 * multi-arm claim must survive both directions of the cross-check).
 * No subprocess runs anywhere in this gate family (the standing lint-gate
 * ruling); the scan file carries the per-construct mapping notes.
 *
 * Semantic mapping (this file):
 * - Env: ZCL_ARTIFACT_CAPABILITY_INVENTORY and ZCL_ARTIFACT_ARM_BASELINE
 *   use ${VAR:-} semantics — unset OR empty reads as absent, so getenv
 *   plus an empty-string test, not env_or.
 * - Discovery: the git grep -l candidate list runs natively over
 *   lint_git_index_foreach (index order = git grep's tracked-file
 *   order). The shell ignored git's exit status (mapfile over a process
 *   substitution), so the reader's silent rc=2 failure mode is ignored
 *   here too; a partial enumeration degrades to the candidate-count
 *   UNPROVEN exactly as a partial git grep listing did. Only the count
 *   and (when exactly 1) the single path are ever used.
 * - The arm path derivation `sed -n '1s/.*"consumes":\[{"path":"...' runs
 *   only when ARM is absent AND [ -f "$CAP" ] (stat, S_ISREG, following
 *   symlinks, exactly the test builtin). An absent CAP or an unmatched
 *   first line leaves ARM empty, hitting the
 *   "declares no consumable arm artifact path" UNPROVEN.
 * - The verdict chain preserves the shell's order byte-for-byte: arm
 *   absent, capability absent, the five self-describing header lines
 *   (grep -Fqx full-line membership), the seven declared-edge claims on
 *   line 1 (grep -Fq, first absent claim in declaration order), the
 *   baseline row set ([ -s ] = "asserts no rows"), then per multi-arm
 *   row: empty path/symbol, baseline membership, the inventory arm count
 *   (>= 2), claimed == emitted, the aggregate-collapse refusal, and the
 *   per-arm UNPROVEN ceiling; then the reverse direction (every arm
 *   triple needs its multi-arm aggregate row, strcmp byte order standing
 *   in for LC_ALL=C sort -u); then the untested-invariant constant-stub
 *   checks in file order. Every verdict is the shell's exact text on
 *   stderr; CONTRADICTION exits 1 and UNPROVEN exits 2 (see below).
 * - The PASS line's count is the extracted multi_arm_symbol row count
 *   (the shell's wc -l over the sed output — one line per row).
 *
 * Exit codes: PASS is exit 0 and CONTRADICTION (a real disagreement) is
 * exit 1, exactly as the original script. Every UNPROVEN verdict is exit
 * 2 — a verifier-directed divergence (2026-09-07, Linux side) from the
 * original, whose unproven() exits 1 just like its contradictions. The
 * fleet convention the sibling ports (controller-private-headers,
 * supervisor-domain) already follow is that a red gate is 1 and an
 * unproven scan is 2, and the driver treats them differently. die()
 * exit 2 remains the environment-failure class, matching the model
 * ports.
 *
 * THE FRESHNESS DELEGATION — the one structural divergence. When
 * ZCL_ARTIFACT_SKIP_FRESHNESS is not 1, the original spawned two sibling
 * shell gates (check_arm_symbol_single.sh, and
 * check_capability_inventory_generated.sh — which compiles a C generator
 * with $CC and runs it) and replayed up to 80 lines of their captured
 * logs before its UNPROVEN on failure. The no-subprocess ruling forbids
 * reimplementing that delegation by spawning, and a native re-derivation
 * is out of reach (one delegate's freshness proof IS a compiler run; both
 * delegates remain unported shell gates with their own pipeline entries).
 * The port therefore performs the content checks only, and the delegation
 * stays discharged by the two delegates' own LINT_GATES entries, which
 * run immediately ahead of this gate in the full pipeline. Parity is
 * exact whenever the delegates would PASS: their output is discarded on
 * success on both sides, so the port is byte-identical on every fresh
 * tree. On a stale tree the divergence is that the shell fails with the
 * delegate's replayed log (which embeds a random mktemp path and is not
 * byte-stable even between two shell runs) where the port proceeds to the
 * content checks. Flagged, not hidden.
 *
 * Preserved latent defects / parity notes:
 * - `IFS=$'\t' read -r` treats tab as IFS whitespace: an EMPTY extracted
 *   field (e.g. "source_path":"") vanishes and the remaining fields shift
 *   left, so the shell's "without an exact path/symbol" UNPROVEN is not
 *   what an empty source_path produces — the shifted row fails baseline
 *   membership as CONTRADICTION "says f:2 is multi-arm ..." instead.
 *   gac_read_split reproduces the shift byte-exactly (A/B case
 *   fixture-multi-empty-path). The shifted claimed field can also read as
 *   ""/overflowing, where bash's `[ -eq ]` adds an "integer expression
 *   expected" diagnostic before the CONTRADICTION branch; the port takes
 *   the same branch (strtol end/ERANGE reads as unequal) without bash's
 *   diagnostic line. Both triggers need crafted artifact rows.
 * - An unreadable-but-present artifact (chmod 000): the shell's awk/sed
 *   fails with its own "cannot open" text and set -e/pipefail exit 2;
 *   the port die()s exit 2 with the runtime's text. Environment failure,
 *   not a gate verdict.
 * - mktemp failure: shell exit 1 with mktemp's text; port die() exit 2
 *   (the describe-budget precedent). The port's run path needs no scratch
 *   directory at all; only --selftest builds one.
 * - The tab-in-a-value and NUL-in-a-header-line latent edges live in
 *   gate_generated_artifact_contradictions_scan.c's header.
 * - The shell was unbounded; the port's fixed pools fail closed with
 *   die().
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_generated_artifact_contradictions.h"

static const char k_gac_gate[] = "check-generated-artifact-contradictions";
static char g_gac_cap[4096];
static char g_gac_arm[4096];

/* ── discovery ─────────────────────────────────────────────────────────── */

static int gac_disc_cb(const char *path, int stage, void *ctx)
{
    (void)stage;
    int *count = ctx;
    if (!gacs_discover_ok(path))
        return 0;
    if (*count == 0
        && ovf(snprintf(g_gac_cap, sizeof g_gac_cap, "%s", path),
               sizeof g_gac_cap))
        return 2;
    (*count)++;
    return 0;
}

/* git grep -l ... | first-line filter, counted: exactly one candidate or
 * the discovery UNPROVEN. The reader's rc is ignored, as the shell
 * ignored git's. */
static int gac_discover(void)
{
    int count = 0;
    (void)lint_git_index_foreach(gac_disc_cb, &count, NULL);
    if (count == 1)
        return 0;
    fprintf(stderr, "[%s] UNPROVEN — capability artifact discovery found "
            "%d candidates\n", k_gac_gate, count);
    return 2;
}

/* ── resolution (CAP and ARM) ──────────────────────────────────────────── */

static int gac_is_file(const char *p)
{
    struct stat st;
    return stat(p, &st) == 0 && S_ISREG(st.st_mode);
}

static int gac_resolve(void)
{
    const char *cap = getenv("ZCL_ARTIFACT_CAPABILITY_INVENTORY");
    if (cap && *cap) {
        if (ovf(snprintf(g_gac_cap, sizeof g_gac_cap, "%s", cap),
                sizeof g_gac_cap))
            return 2;
    } else {
        int rc = gac_discover();
        if (rc)
            return rc;
    }
    const char *arm = getenv("ZCL_ARTIFACT_ARM_BASELINE");
    if (arm && *arm) {
        if (ovf(snprintf(g_gac_arm, sizeof g_gac_arm, "%s", arm),
                sizeof g_gac_arm))
            return 2;
    } else if (gac_is_file(g_gac_cap)) {
        int rc = gacs_consumes_path(g_gac_cap, g_gac_arm, sizeof g_gac_arm);
        if (rc)
            return rc;
    }
    if (!g_gac_arm[0]) {
        fprintf(stderr, "[%s] UNPROVEN — %s declares no consumable arm "
                "artifact path\n", k_gac_gate, g_gac_cap);
        return 2;
    }
    return 0;
}

/* ── the header and claim chain ────────────────────────────────────────── */

/* require_exact_line: [ -f ] then grep -Fqx. */
static int gac_require_line(const char *file, const char *line)
{
    if (!gac_is_file(file)) {
        fprintf(stderr, "[%s] UNPROVEN — generated artifact absent: %s\n",
                k_gac_gate, file);
        return 2;
    }
    int found = 0;
    int rc = gacs_file_has_line(file, line, &found);
    if (rc)
        return rc;
    if (!found) {
        fprintf(stderr, "[%s] UNPROVEN — %s lacks self-describing header: "
                "%s\n", k_gac_gate, file, line);
        return 2;
    }
    return 0;
}

static int gac_headers(const char *arm)
{
    static const char *const hdrs[] = {
        "# z23-generated-artifact: zcl.generated_artifact.v1",
        "# artifact-id: zcl.arm_symbol_single_baseline.v1",
        "# asserts: multi_arm_definition(path,symbol)",
        "# generated-by: tools/lint/check_arm_symbol_single.sh",
        ("# regenerate: ZCL_LINT_MODE=UPDATE "
         "tools/lint/check_arm_symbol_single.sh"),
    };
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < sizeof hdrs / sizeof hdrs[0]; i++)
        rc = gac_require_line(arm, hdrs[i]);
    return rc;
}

static int gac_claims(const char *cap)
{
    static const char *const claims[] = {
        "\"generated_artifact_schema\":\"zcl.generated_artifact.v1\"",
        "\"artifact_id\":\"zcl.code_capability_inventory.v1\"",
        "\"generated_by\":\"tools/gen_capability_inventory.c\"",
        "\"regenerate\":\"make docs-capability-inventory\"",
        "\"path\":\"tools/lint/arm_symbol_single_baseline.txt\"",
        "\"artifact_id\":\"zcl.arm_symbol_single_baseline.v1\"",
        "\"asserts\":\"multi_arm_definition(path,symbol)\"",
    };
    const char *miss = NULL;
    int rc = gacs_meta_check(cap, claims,
                             (int)(sizeof claims / sizeof claims[0]), &miss);
    if (rc == 0 && miss) {
        fprintf(stderr, "[%s] UNPROVEN — %s lacks declared "
                "generated-artifact edge: %s\n", k_gac_gate, cap, miss);
        rc = 2;
    }
    return rc;
}

/* ── the verdict loops ─────────────────────────────────────────────────── */

/* bash `IFS=$'\t' read -r a b ...` field assignment over one TSV row: tab
 * is IFS whitespace, so a leading run is skipped, interior runs collapse
 * to ONE delimiter (an empty extracted field disappears and the remaining
 * fields SHIFT left — a preserved latent defect of the original, proven
 * by the A/B fixture-multi-empty-path case), the last variable keeps the
 * remainder with inner tabs verbatim and the trailing run stripped, and
 * missing words leave the tail variables empty. buf is destroyed. */
static void gac_read_split(char *buf, char **f, int n)
{
    char *p = buf;
    int i = 0;
    p += strspn(p, "\t");
    for (; i < n - 1; i++) {
        if (!*p) {
            f[i] = p;
            continue;
        }
        char *tab = strchr(p, '\t');
        if (!tab) {
            f[i] = p;
            p += strlen(p);
            continue;
        }
        *tab = '\0';
        f[i] = p;
        p = tab + 1 + strspn(tab + 1, "\t");
    }
    f[i] = p;
    size_t len = strlen(p);
    while (len && p[len - 1] == '\t')
        p[--len] = '\0';
}

static int gac_multi_row(const char *cap, const char *arm,
                         const struct gac_multi *r)
{
    char row[32768];
    int k = snprintf(row, sizeof row, "%s\t%s\t%s\t%s\t%s\t%s", r->h, r->p,
                     r->s, r->claimed, r->agdef, r->agcon);
    if (ovf(k, sizeof row))
        return 2;
    char *f[6];
    gac_read_split(row, f, 6);
    if (!f[1][0] || !f[2][0]) {
        fprintf(stderr, "[%s] UNPROVEN — %s emitted a multi-arm claim "
                "without an exact path/symbol\n", k_gac_gate, cap);
        return 2;
    }
    char key[8192];
    if (ovf(snprintf(key, sizeof key, "%s\t%s", f[1], f[2]), sizeof key))
        return 2;
    if (!gacs_baseline_has(key)) {
        fprintf(stderr, "[%s] CONTRADICTION — %s says %s:%s is multi-arm "
                "but %s does not\n", k_gac_gate, cap, f[1], f[2], arm);
        return 1;
    }
    int actual = gacs_arm_count(f[0], f[1], f[2]);
    if (actual < 2) {
        fprintf(stderr, "[%s] UNPROVEN — %s:%s has %d inventory arm(s), "
                "but the consumed artifact asserts multiple definitions\n",
                k_gac_gate, f[1], f[2], actual);
        return 2;
    }
    char *end = NULL;
    errno = 0;
    long cv = strtol(f[3], &end, 10);
    if (errno == ERANGE || !end || *end != '\0' || cv != actual) {
        fprintf(stderr, "[%s] CONTRADICTION — %s:%s claims %s arms but "
                "emits %d\n", k_gac_gate, f[1], f[2], f[3], actual);
        return 1;
    }
    if (strcmp(f[4], "UNPROVEN") != 0 || strcmp(f[5], "UNPROVEN") != 0) {
        fprintf(stderr, "[%s] CONTRADICTION — %s:%s collapses a multi-arm "
                "definition into an aggregate claim\n", k_gac_gate, f[1],
                f[2]);
        return 1;
    }
    if (gacs_arm_clean(f[0], f[1], f[2]) < 2) {
        fprintf(stderr, "[%s] CONTRADICTION — %s:%s has an arm lacking an "
                "explicit UNPROVEN scope/evidence ceiling\n", k_gac_gate,
                f[1], f[2]);
        return 1;
    }
    return 0;
}

static int gac_multi_loop(const char *cap, const char *arm)
{
    int rc = 0;
    for (int i = 0; rc == 0 && i < gacs_multi_n(); i++)
        rc = gac_multi_row(cap, arm, gacs_multi_at(i));
    return rc;
}

static int gac_triple_loop(const char *cap)
{
    int rc = 0;
    for (int i = 0; rc == 0 && i < gacs_ntriples(); i++) {
        char key[12288];
        if (ovf(snprintf(key, sizeof key, "%s", gacs_triple_key(i)),
                sizeof key))
            return 2;
        char *f[3];
        gac_read_split(key, f, 3);
        if (gacs_multi_has(f[0], f[1], f[2]))
            continue;
        fprintf(stderr, "[%s] CONTRADICTION — %s emits definition arms "
                "for %s:%s without a multi-arm aggregate row\n", k_gac_gate,
                cap, f[1], f[2]);
        rc = 1;
    }
    return rc;
}

static int gac_untested_row(const struct gac_untested *u)
{
    char key[8192];
    if (ovf(snprintf(key, sizeof key, "%s\t%s", u->p, u->s), sizeof key))
        return 2;
    if (!gacs_baseline_has(key))
        return 0;
    if (!u->scope_ok) {
        fprintf(stderr, "[%s] CONTRADICTION — %s:%s is reported as a "
                "constant stub without per-arm scope\n", k_gac_gate, u->p,
                u->s);
        return 1;
    }
    if (!u->verdict_ok) {
        fprintf(stderr, "[%s] CONTRADICTION — %s:%s constant arm lacks an "
                "UNPROVEN verdict\n", k_gac_gate, u->p, u->s);
        return 1;
    }
    return 0;
}

static int gac_untested_loop(void)
{
    int rc = 0;
    for (int i = 0; rc == 0 && i < gacs_untested_n(); i++)
        rc = gac_untested_row(gacs_untested_at(i));
    return rc;
}

/* ── the gate ──────────────────────────────────────────────────────────── */

static int gac_check(const char *cap, const char *arm)
{
    if (!gac_is_file(arm)) {
        fprintf(stderr, "[%s] UNPROVEN — generated arm artifact absent: "
                "%s\n", k_gac_gate, arm);
        return 2;
    }
    if (!gac_is_file(cap)) {
        fprintf(stderr, "[%s] UNPROVEN — generated capability artifact "
                "absent: %s\n", k_gac_gate, cap);
        return 2;
    }
    int rc = gac_headers(arm);
    if (rc == 0)
        rc = gac_claims(cap);
    if (rc == 0)
        rc = gacs_load_baseline(arm);
    if (rc == 0 && gacs_baseline_n() == 0) {
        fprintf(stderr, "[%s] UNPROVEN — %s asserts no rows; absence is "
                "not agreement\n", k_gac_gate, arm);
        rc = 2;
    }
    if (rc == 0)
        rc = gacs_parse_cap(cap);
    if (rc == 0)
        rc = gacs_build_triples();
    if (rc == 0)
        rc = gac_multi_loop(cap, arm);
    if (rc == 0)
        rc = gac_triple_loop(cap);
    if (rc == 0)
        rc = gac_untested_loop();
    if (rc == 0)
        printf("[%s] PASS (%d exposed multi-arm symbols; artifacts fresh "
               "and compatible)\n", k_gac_gate, gacs_multi_n());
    return rc;
}

int check_generated_artifact_contradictions_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    char root[4096];
    int rc = cic_repo_root(root, sizeof root);
    if (rc == 0 && chdir(root) != 0)
        rc = 2;
    if (rc == 0)
        rc = gacs_comp();
    if (rc == 0) {
        rc = gac_resolve();
        if (rc == 0)
            rc = gac_check(g_gac_cap, g_gac_arm);
        gacs_drop();
    }
    return rc;
}
