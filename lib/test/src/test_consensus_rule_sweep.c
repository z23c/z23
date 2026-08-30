/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_consensus_rule_sweep — teeth for the FORWARD-facing consensus check
 * (tools/consensus_rule_sweep.{h,c}).
 *
 * THE HOLE THIS GATE FILLS. Every past-facing check the project owns —
 * deterministic rebuild, full-chain replay to tip, historical UTXO-root
 * agreement, the E13 consensus-parity lint — is satisfiable BY CONSTRUCTION by
 * a malicious build carrying a rule change gated on a height we have not
 * reached. All five mainnet activation heights are <= 707,000, ~2.5M blocks
 * behind the tip, so such a build reproduces every historical byte and still
 * contains `if (n_height >= 3400000) halvings--`. The sweep digest is the
 * check that sees that; this group is the check that the sweep digest works.
 *
 * A digest gate is worthless unless it can FAIL. So this group proves the
 * fail arms as hard as the pass arms: a planted future-height bomb, a
 * one-satoshi perturbation at a single swept height, and a per-slot mutation
 * of every network-upgrade row must each move the digest — and a bomb gated
 * ABOVE the swept range must NOT move it (the negative control that keeps a
 * "digest changed" verdict from being noise).
 *
 * Everything here is pure: the mutated schedules are driven through the real
 * pure consensus functions with a MUTATED COPY of chain_params. No consensus
 * source is edited to make a test fail, and no datadir, disk, clock, network
 * or node process is touched.
 */

#include "test/test_core.h"

#include "consensus_rule_sweep.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#endif
#include <unistd.h>
#if !defined(_WIN32)

#define CRS_CHECK(name, expr) do {                  \
    printf("  consensus_rule_sweep: %s... ", (name)); \
    if ((expr)) printf("OK\n");                     \
    else { printf("FAIL\n"); failures++; }          \
} while (0)

/* The test drives the canonical vector (~38k heights), so a 262,144-entry
 * buffer is ample. It is deliberately SMALLER than the tool's CRS_MAX_HEIGHTS:
 * one arm below proves the engine fails closed with CRS_ERR_CAPACITY rather
 * than silently truncating a vector that does not fit. */
#define CRS_TEST_HEIGHTS 262144

static int32_t g_heights[CRS_TEST_HEIGHTS];
static struct chain_params g_mutant;
static struct checkpoint_entry g_ckpt_copy[256];

/* ── row sink: per-slot activation observations ───────────────────────────*/

struct slot_stats {
    size_t rows;
    size_t active[MAX_NETWORK_UPGRADES];    /* rows where the mask bit was 1 */
    size_t inactive[MAX_NETWORK_UPGRADES];  /* rows where the mask bit was 0 */
    size_t st_disabled[MAX_NETWORK_UPGRADES];
    size_t st_pending[MAX_NETWORK_UPGRADES];
    size_t st_active[MAX_NETWORK_UPGRADES];
};

static void slot_sink(const struct crs_row *row, void *vctx)
{
    struct slot_stats *s = (struct slot_stats *)vctx;
    s->rows++;
    for (int i = 0; i < MAX_NETWORK_UPGRADES; i++) {
        if (row->upgrade_active_mask & ((uint64_t)1 << i))
            s->active[i]++;
        else
            s->inactive[i]++;
        unsigned st = (unsigned)((row->upgrade_state_packed >> (2 * i)) & 0x3u);
        if (st == UPGRADE_DISABLED)      s->st_disabled[i]++;
        else if (st == UPGRADE_PENDING)  s->st_pending[i]++;
        else                             s->st_active[i]++;
    }
}

/* ── fail-arm hooks ───────────────────────────────────────────────────────*/

/* The exact shape the brief names: a rule that only bites at heights we have
 * not reached. Applied to a SCRATCH copy of the evaluation, never to source. */
struct bomb_ctx {
    int32_t gate;
    size_t fired;
};

static void bomb_hook(struct crs_row *row, void *vctx)
{
    struct bomb_ctx *c = (struct bomb_ctx *)vctx;
    if (row->height >= c->gate) {
        row->subsidy /= 2;
        c->fired++;
    }
}

/* One satoshi, one height — the strictest sensitivity claim the fold can make. */
struct pinprick_ctx {
    int32_t height;
    size_t fired;
};

static void pinprick_hook(struct crs_row *row, void *vctx)
{
    struct pinprick_ctx *c = (struct pinprick_ctx *)vctx;
    if (row->height == c->height) {
        row->subsidy += 1;
        c->fired++;
    }
}

/* ── helpers ──────────────────────────────────────────────────────────────*/

static bool digest_eq(const uint8_t a[32], const uint8_t b[32])
{
    return memcmp(a, b, 32) == 0;
}

static bool vector_contains(const int32_t *v, size_t n, int32_t h)
{
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (v[mid] == h) return true;
        if (v[mid] < h) lo = mid + 1;
        else hi = mid;
    }
    return false;
}

/* Run the engine over the canonical buffer. Returns CRS_OK on success. */
static enum crs_status sweep(const struct crs_config *cfg,
                             const struct chain_params *cp,
                             crs_row_hook hook, void *hook_ctx,
                             crs_row_sink sink, void *sink_ctx,
                             uint8_t out[32], size_t *rows)
{
    return crs_run(cfg, cp, g_heights, CRS_TEST_HEIGHTS, hook, hook_ctx,
                   sink, sink_ctx, out, rows);
}

/* Compute the digest inside a FORKED CHILD and hand the 32 bytes back over a
 * pipe. The child re-selects the chain params and rebuilds the whole vector in
 * its own address space, so a digest that depended on accumulated in-process
 * state would diverge here. */
static bool child_digest(const struct crs_config *cfg, uint8_t out[32])
{
    int fds[2];
    if (pipe(fds) != 0)
        return false;

    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return false;
    }
    if (pid == 0) {
        close(fds[0]);
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *cp = chain_params_get();
        uint8_t d[32];
        size_t rows = 0;
        enum crs_status st = crs_run(cfg, cp, g_heights, CRS_TEST_HEIGHTS,
                                     NULL, NULL, NULL, NULL, d, &rows);
        if (st != CRS_OK)
            _exit(2);
        ssize_t w = write(fds[1], d, sizeof(d));
        close(fds[1]);
        _exit(w == (ssize_t)sizeof(d) ? 0 : 3);
    }

    close(fds[1]);
    size_t got = 0;
    while (got < 32) {
        ssize_t r = read(fds[0], out + got, 32 - got);
        if (r > 0) { got += (size_t)r; continue; }
        if (r < 0 && errno == EINTR) continue;
        break;
    }
    close(fds[0]);

    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) { /* retry */ }
    return got == 32 && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/* Exec the standalone tool and parse the digest off its single output line.
 * Returns false (with *present=false) when the binary has not been built —
 * that arm is then reported NOT RUN rather than silently passing. */
static bool tool_digest(uint8_t out[32], bool *present)
{
    *present = false;
    const char *bin = getenv("ZCL_CONSENSUS_RULE_SWEEP_BIN");
    if (!bin || !*bin)
        bin = "build/bin/consensus_rule_sweep";
    if (access(bin, X_OK) != 0)
        return false;
    *present = true;

    int fds[2];
    if (pipe(fds) != 0)
        return false;

    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return false;
    }
    if (pid == 0) {
        close(fds[0]);
        if (dup2(fds[1], STDOUT_FILENO) < 0)
            _exit(127);
        close(fds[1]);
        execl(bin, bin, (char *)NULL);
        _exit(127);
    }

    close(fds[1]);
    char buf[512];
    size_t got = 0;
    while (got < sizeof(buf) - 1) {
        ssize_t r = read(fds[0], buf + got, sizeof(buf) - 1 - got);
        if (r > 0) { got += (size_t)r; continue; }
        if (r < 0 && errno == EINTR) continue;
        break;
    }
    buf[got] = '\0';
    close(fds[0]);

    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) { /* retry */ }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0 || got < 64)
        return false;

    /* The digest is the first field of the single output line. Decode it with
     * the tree's one hex codec, in canonical-lowercase mode: the tool must
     * emit exactly what zcl_hex_encode produced, not a case variant. */
    char hex[65];
    memcpy(hex, buf, 64);
    hex[64] = '\0';
    return zcl_hex_decode_lower(hex, out, 32);
}

/* ── the group ────────────────────────────────────────────────────────────*/

static int test_consensus_rule_sweep_platform_arm(void)
{
    int failures = 0;
    printf("consensus_rule_sweep (forward-facing consensus schedule digest)\n");

    chain_params_select(CHAIN_MAIN);
    const struct chain_params *cp = chain_params_get();
    const struct consensus_params *p = &cp->consensus;
    const struct crs_config cfg = crs_default_config();

    /* ── 1. the canonical run ─────────────────────────────────────────── */
    uint8_t base[32];
    size_t rows = 0;
    enum crs_status st = sweep(&cfg, cp, NULL, NULL, NULL, NULL, base, &rows);
    CRS_CHECK("canonical sweep succeeds", st == CRS_OK);
    CRS_CHECK("canonical sweep is non-trivial (>= 30000 rows)", rows >= 30000);
    if (st != CRS_OK) {
        printf("  consensus_rule_sweep: ABORTING — engine failed: %s\n",
               crs_status_str(st));
        return failures + 1;
    }
    {
        char hex[65];
        crs_hex32(base, hex);
        printf("  consensus_rule_sweep: digest=%s rows=%zu\n", hex, rows);
    }

    /* ── 2. byte stability, same process ──────────────────────────────── */
    {
        uint8_t again[32];
        size_t rows2 = 0;
        enum crs_status s2 = sweep(&cfg, cp, NULL, NULL, NULL, NULL,
                                   again, &rows2);
        CRS_CHECK("digest is byte-stable across two runs in one process",
                  s2 == CRS_OK && rows2 == rows && digest_eq(base, again));
    }

    /* ── 3. byte stability, separate processes ────────────────────────── */
    {
        uint8_t c1[32], c2[32];
        bool ok1 = child_digest(&cfg, c1);
        bool ok2 = child_digest(&cfg, c2);
        CRS_CHECK("digest is byte-stable across two forked child processes",
                  ok1 && ok2 && digest_eq(base, c1) && digest_eq(base, c2));
    }
    {
        uint8_t t[32];
        bool present = false;
        bool ok = tool_digest(t, &present);
        if (present) {
            CRS_CHECK("digest matches a separate exec of the standalone tool",
                      ok && digest_eq(base, t));
        } else {
            printf("  consensus_rule_sweep: exec-the-tool arm NOT RUN — "
                   "build/bin/consensus_rule_sweep absent "
                   "(make tools/consensus_rule_sweep); the two forked-process "
                   "arms above still ran\n");
        }
    }

    /* ── 4. the sweep vector itself ───────────────────────────────────── */
    {
        size_t n = 0;
        enum crs_status vs = crs_build_vector(&cfg, cp, g_heights,
                                              CRS_TEST_HEIGHTS, &n);
        bool ascending = (vs == CRS_OK) && n == rows && n > 0 &&
                         g_heights[0] >= 0;
        for (size_t i = 1; ascending && i < n; i++)
            ascending = g_heights[i] > g_heights[i - 1];
        CRS_CHECK("vector is strictly ascending, deduplicated, non-negative",
                  ascending);

        /* The four declared families are all present. */
        bool low = true;
        for (int32_t h = 0; h <= CRS_LOW_DENSE_MAX && low; h++)
            low = vector_contains(g_heights, n, h);
        CRS_CHECK("family 1: every height in [0, 2000] is swept", low);

        bool upg = true;
        for (int i = 0; i < MAX_NETWORK_UPGRADES; i++) {
            int32_t a = p->vUpgrades[i].nActivationHeight;
            if (a == NETWORK_UPGRADE_NO_ACTIVATION)
                continue;
            upg = upg && vector_contains(g_heights, n, a) &&
                  (a == 0 || vector_contains(g_heights, n, a - 1)) &&
                  vector_contains(g_heights, n, a + 1);
        }
        CRS_CHECK("family 3: every activation height and +/-1 is swept", upg);

        bool fwd = vector_contains(g_heights, n, cfg.tip) &&
                   vector_contains(g_heights, n, cfg.tip + cfg.horizon) &&
                   vector_contains(g_heights, n,
                                   cfg.tip + cfg.stride * 1234);
        CRS_CHECK("family 4: the forward band reaches tip+horizon", fwd);

        /* Family 2 proven exhaustively: scan EVERY height in range and assert
         * the sweep contains each height where consensus_halving() actually
         * changes value, plus the block before it. This is what makes "every
         * halving boundary" a fact rather than an assertion about arithmetic
         * this file did itself. */
        const int32_t max_h = cfg.tip + cfg.horizon + cfg.band;
        int prev = consensus_halving(p, 0);
        size_t boundaries = 0, missed = 0;
        int32_t first_missed = -1;
        for (int32_t h = 1; h <= max_h; h++) {
            int cur = consensus_halving(p, h);
            if (cur != prev) {
                boundaries++;
                if (!vector_contains(g_heights, n, h) ||
                    !vector_contains(g_heights, n, h - 1)) {
                    if (!missed) first_missed = h;
                    missed++;
                }
            }
            prev = cur;
        }
        CRS_CHECK("family 2: every real halving boundary (and -1) is swept",
                  boundaries > 0 && missed == 0);
        printf("  consensus_rule_sweep: %zu halving boundaries in [1, %"
               PRId32 "], %zu missed%s\n", boundaries, max_h, missed,
               missed ? " (first: see below)" : "");
        if (missed)
            printf("  consensus_rule_sweep: first missed boundary h=%" PRId32
                   "\n", first_missed);
    }

    /* ── 5. fail closed, never truncate ───────────────────────────────── */
    {
        size_t n = 999;
        enum crs_status cs = crs_build_vector(&cfg, cp, g_heights, 10, &n);
        CRS_CHECK("a too-small buffer returns CRS_ERR_CAPACITY, not a short "
                  "vector", cs == CRS_ERR_CAPACITY && n == 0);
    }
    {
        struct crs_config bad = cfg;
        bad.stride = 0;
        enum crs_status b1 = crs_validate_config(&bad);
        bad = cfg;
        bad.tip = -1;
        enum crs_status b2 = crs_validate_config(&bad);
        bad = cfg;
        bad.horizon = CRS_MAX_HORIZON + 1;
        enum crs_status b3 = crs_validate_config(&bad);
        CRS_CHECK("out-of-range sweep parameters are rejected",
                  b1 == CRS_ERR_BAD_CONFIG && b2 == CRS_ERR_BAD_CONFIG &&
                  b3 == CRS_ERR_BAD_CONFIG);
    }

    /* ── 6. the sweep vector is BOUND to the digest ───────────────────── */
    {
        struct crs_config other = cfg;
        other.tip = cfg.tip + 1;
        uint8_t d[32];
        size_t r2 = 0;
        enum crs_status s2 = sweep(&other, cp, NULL, NULL, NULL, NULL, d, &r2);
        CRS_CHECK("a different --tip yields a different digest",
                  s2 == CRS_OK && !digest_eq(base, d));
    }

    /* ── 7. FAIL ARM — the planted future-height bomb ─────────────────── */
    {
        struct bomb_ctx bc = { .gate = 3400000, .fired = 0 };
        uint8_t d[32];
        size_t r2 = 0;
        enum crs_status s2 = sweep(&cfg, cp, bomb_hook, &bc, NULL, NULL,
                                   d, &r2);
        CRS_CHECK("fail arm: `if (h >= 3400000) subsidy /= 2` is DETECTED",
                  s2 == CRS_OK && bc.fired > 0 && !digest_eq(base, d));
        printf("  consensus_rule_sweep: bomb gate h>=3400000 perturbed %zu of "
               "%zu swept rows\n", bc.fired, rows);
    }
    {
        /* Negative control. A bomb gated ABOVE everything the sweep looks at
         * must leave the digest alone — otherwise "the digest changed" above
         * would prove nothing about the bomb. This is also the honest
         * statement of the tool's blind spot. */
        struct bomb_ctx bc = { .gate = cfg.tip + cfg.horizon + cfg.band + 1,
                               .fired = 0 };
        uint8_t d[32];
        size_t r2 = 0;
        enum crs_status s2 = sweep(&cfg, cp, bomb_hook, &bc, NULL, NULL,
                                   d, &r2);
        CRS_CHECK("negative control: a bomb above the swept range does NOT "
                  "move the digest",
                  s2 == CRS_OK && bc.fired == 0 && digest_eq(base, d));
    }

    /* ── 8. one satoshi at one height moves the digest ────────────────── */
    {
        struct pinprick_ctx pc = { .height = cfg.tip + cfg.stride * 300,
                                   .fired = 0 };
        uint8_t d[32];
        size_t r2 = 0;
        enum crs_status s2 = sweep(&cfg, cp, pinprick_hook, &pc, NULL, NULL,
                                   d, &r2);
        CRS_CHECK("+1 zatoshi at ONE swept height changes the digest",
                  s2 == CRS_OK && pc.fired == 1 && !digest_eq(base, d));
    }

    /* ── 9. a mutated params COPY drives the real pure functions ──────── */
    {
        g_mutant = *cp;
        g_mutant.consensus.vUpgrades[UPGRADE_BUTTERCUP].nActivationHeight += 1;
        uint8_t d[32];
        size_t r2 = 0;
        enum crs_status s2 = sweep(&cfg, &g_mutant, NULL, NULL, NULL, NULL,
                                   d, &r2);

        /* Count how many swept heights the mutation actually moved, so the
         * digest change is attributable rather than assumed. */
        size_t moved = 0;
        size_t n = 0;
        enum crs_status vs = crs_build_vector(&cfg, cp, g_heights,
                                              CRS_TEST_HEIGHTS, &n);
        if (vs == CRS_OK) {
            for (size_t i = 0; i < n; i++) {
                int64_t a = 0, b = 0;
                struct zcl_result ra =
                    domain_consensus_block_subsidy(g_heights[i],
                                                   &cp->consensus, &a);
                struct zcl_result rb =
                    domain_consensus_block_subsidy(g_heights[i],
                                                   &g_mutant.consensus, &b);
                if (ra.ok != rb.ok || a != b)
                    moved++;
            }
        }
        CRS_CHECK("a mutated params copy (Buttercup +1) changes the digest",
                  s2 == CRS_OK && moved > 0 && !digest_eq(base, d));
        printf("  consensus_rule_sweep: Buttercup+1 moved the subsidy at %zu "
               "swept heights\n", moved);
    }

    /* ── 10. EVERY upgrade slot is covered, disabled ones included ────── */
    {
        static struct slot_stats stats;
        memset(&stats, 0, sizeof(stats));
        uint8_t d[32];
        size_t r2 = 0;
        enum crs_status s2 = sweep(&cfg, cp, NULL, NULL, slot_sink, &stats,
                                   d, &r2);
        CRS_CHECK("slot-observation run reproduces the canonical digest",
                  s2 == CRS_OK && digest_eq(base, d) && stats.rows == rows);

        bool always_seen = false, disabled_seen = false, gated_ok = true;
        int gated = 0;
        for (int i = 0; i < MAX_NETWORK_UPGRADES; i++) {
            int32_t a = p->vUpgrades[i].nActivationHeight;
            if (a == NETWORK_UPGRADE_ALWAYS_ACTIVE) {
                /* Active at every swept height, and never anything else. */
                bool ok = stats.active[i] == stats.rows &&
                          stats.inactive[i] == 0 &&
                          stats.st_active[i] == stats.rows;
                always_seen = always_seen || ok;
                gated_ok = gated_ok && ok;
            } else if (a == NETWORK_UPGRADE_NO_ACTIVATION) {
                /* The slot the naive implementation SKIPS. It must be present
                 * in the mask and observed inactive/DISABLED everywhere. */
                bool ok = stats.inactive[i] == stats.rows &&
                          stats.active[i] == 0 &&
                          stats.st_disabled[i] == stats.rows;
                disabled_seen = disabled_seen || ok;
                gated_ok = gated_ok && ok;
            } else {
                /* A real height: the sweep must straddle it. */
                bool ok = stats.active[i] > 0 && stats.inactive[i] > 0 &&
                          stats.st_pending[i] > 0 && stats.st_active[i] > 0 &&
                          stats.st_disabled[i] == 0;
                gated_ok = gated_ok && ok;
                gated++;
            }
        }
        CRS_CHECK("every UPGRADE_* slot is observed with the right shape",
                  gated_ok);
        CRS_CHECK("an ALWAYS_ACTIVE slot is observed active at every height",
                  always_seen);
        CRS_CHECK("a NETWORK_UPGRADE_NO_ACTIVATION slot IS covered (observed "
                  "disabled at every height, not skipped)", disabled_seen);
        CRS_CHECK("every height-gated slot is straddled by the sweep",
                  gated >= 4);

        /* Coverage by observation is not enough. `inactive[i] == rows` for the
         * disabled slot looks identical whether the per-height loop queried
         * that slot and got false, or never queried it at all — an
         * implementation bounded by "slots that have a height" would produce
         * the same counts. So mutate exactly ONE slot at a time and require
         * the observed PER-ROW mask to move, not just the digest. That
         * distinguishes a covered slot from a skipped one, disabled included. */
        static struct slot_stats mut_stats;
        bool each_slot_binds = true;
        for (int i = 0; i < MAX_NETWORK_UPGRADES; i++) {
            g_mutant = *cp;
            int32_t a = p->vUpgrades[i].nActivationHeight;
            /* Every case moves the slot to a height the sweep straddles, so a
             * genuinely queried slot MUST report a different active count. */
            g_mutant.consensus.vUpgrades[i].nActivationHeight =
                (a == cfg.tip + 1000) ? (cfg.tip + 2000) : (cfg.tip + 1000);
            memset(&mut_stats, 0, sizeof(mut_stats));
            uint8_t md[32];
            size_t mr = 0;
            enum crs_status ms = sweep(&cfg, &g_mutant, NULL, NULL, slot_sink,
                                       &mut_stats, md, &mr);
            /* Counts, not equality of row totals: moving an activation height
             * also moves family 3 of the sweep vector, so the two runs differ
             * by a handful of rows. A SKIPPED slot would report active[i] == 0 in
             * both runs; a queried one cannot, because the height moved. */
            bool row_moved = (ms == CRS_OK) &&
                             mut_stats.active[i] != stats.active[i];
            bool digest_moved = (ms == CRS_OK) && !digest_eq(base, md);
            if (!row_moved || !digest_moved) {
                each_slot_binds = false;
                printf("  consensus_rule_sweep: slot %d NOT covered "
                       "(row_moved=%d digest_moved=%d base_active=%zu/%zu "
                       "mut_active=%zu/%zu)\n", i, (int)row_moved,
                       (int)digest_moved, stats.active[i], stats.rows,
                       mut_stats.active[i], mut_stats.rows);
            }
        }
        CRS_CHECK("moving any ONE upgrade slot moves that slot's per-row mask "
                  "AND the digest", each_slot_binds);
    }

    /* ── 11. the compiled checkpoint table ────────────────────────────── */
    {
        /* Pins the correction to the stale claim in
         * tools/gen_utxo_root_ladder.c that this table carries only `{{0}}`
         * placeholders: the static initializer does, but init_main_params()
         * overwrites all 63 with real hashes before any caller sees them. */
        const struct checkpoint_data *d = &cp->checkpointData;
        int nonzero = 0;
        for (int i = 0; i < d->nEntries; i++)
            if (!uint256_is_null(&d->entries[i].hash))
                nonzero++;
        CRS_CHECK("mainnet checkpoint table is POPULATED at runtime "
                  "(63 entries, none zero)",
                  d->nEntries == 63 && nonzero == 63);
        CRS_CHECK("checkpoint table spans genesis..3,100,000",
                  d->nEntries == 63 && d->entries[0].height == 0 &&
                  d->entries[62].height == 3100000);

        /* And the table is bound to the digest: flip one byte of a copy. */
        int n = d->nEntries;
        if (n > (int)(sizeof(g_ckpt_copy) / sizeof(g_ckpt_copy[0])))
            n = (int)(sizeof(g_ckpt_copy) / sizeof(g_ckpt_copy[0]));
        memcpy(g_ckpt_copy, d->entries, (size_t)n * sizeof(g_ckpt_copy[0]));
        g_ckpt_copy[n / 2].hash.data[0] ^= 0x01;
        g_mutant = *cp;
        g_mutant.checkpointData.entries = g_ckpt_copy;
        uint8_t md[32];
        size_t mr = 0;
        enum crs_status ms = sweep(&cfg, &g_mutant, NULL, NULL, NULL, NULL,
                                   md, &mr);
        CRS_CHECK("flipping one checkpoint-hash bit changes the digest",
                  ms == CRS_OK && !digest_eq(base, md));
    }

    /* ── 12. the pinned schedule values the digest is folding ─────────── */
    {
        /* If these drift the digest changes, but a bare digest change tells
         * you nothing about WHAT moved. Pin the headline values so the
         * transcript names the schedule this digest describes. */
        int64_t s0 = -1, s707k = -1, s2387001 = -1;
        struct zcl_result r0 = domain_consensus_block_subsidy(0, p, &s0);
        struct zcl_result r1 = domain_consensus_block_subsidy(707000, p, &s707k);
        struct zcl_result r2 = domain_consensus_block_subsidy(2387001, p,
                                                              &s2387001);
        CRS_CHECK("subsidy(0)=0, subsidy(707000)=78125000, "
                  "subsidy(2387001)=39062500",
                  r0.ok && r1.ok && r2.ok && s0 == 0 && s707k == 78125000 &&
                  s2387001 == 39062500);
        CRS_CHECK("spacing 150 before Buttercup, 75 at and after",
                  consensus_pow_target_spacing(p, 706999) == 150 &&
                  consensus_pow_target_spacing(p, 707000) == 75);
        CRS_CHECK("Equihash (200,9) at genesis, (192,7) from Bubbles",
                  chain_params_equihash_n(cp, 0) == 200 &&
                  chain_params_equihash_k(cp, 0) == 9 &&
                  chain_params_equihash_n(cp, 585318) == 192 &&
                  chain_params_equihash_k(cp, 585318) == 7);
    }

    printf("consensus_rule_sweep: %d failure(s)\n", failures);
    return failures;
}
#else  /* _WIN32 */
/* Windows has no fork()/waitpid process model; this group's fork/exec rule-sweep child lane
 * cannot run here. Skipped loudly rather than faked. */
static int test_consensus_rule_sweep_platform_arm(void)
{
    printf("consensus_rule_sweep: SKIP (Windows): fork/exec rule-sweep child lane\n");
    return 0;
}
#endif

int test_consensus_rule_sweep(void)
{
    return test_consensus_rule_sweep_platform_arm();
}
