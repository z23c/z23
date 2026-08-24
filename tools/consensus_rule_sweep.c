/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * consensus_rule_sweep — CLI over the forward-facing consensus schedule check.
 *
 * The engine, the sweep vector and the digest preimage are documented in
 * tools/consensus_rule_sweep.h; this file is argument parsing and printing
 * only, so the test group drives the identical evaluation code the tool ships.
 *
 * WHAT IT ANSWERS. "Do two builds agree about the consensus rules at heights
 * we have not reached yet?" Every past-facing check we own — deterministic
 * rebuild, replay to tip, historical UTXO-root agreement, the E13 parity lint
 * — is satisfiable by a binary that reproduces all of history and still
 * carries `if (n_height >= 3400000) halvings--`. This one is not.
 *
 * NO INPUTS OF ANY KIND. No daemon, no datadir, no disk reads, no network, no
 * clock, no RNG, no heap. Everything comes from the compiled parameter tables,
 * so this is safe to run next to a live node and cheap on the weakest box.
 *
 *   consensus_rule_sweep [--tip=N] [--horizon=N] [--stride=N] [--band=N]
 *                        [--verbose] [--help]
 *
 * Output is ONE line on stdout, sha256sum-shaped so it composes with cut/diff:
 *
 *   <64-hex sha3-256>  consensus_rule_sweep/v1 network=main tip=... rows=...
 *
 * COMPARING TWO BOXES. Each runs the tool with the SAME arguments and the
 * lines are compared byte for byte (`diff <(a) <(b)`, or `cut -d' ' -f1`).
 * Equal digest = the two builds agree on the entire swept forward schedule.
 * The sweep parameters are folded into the digest preimage, so a run with a
 * different --tip cannot accidentally read as agreement; it just differs.
 *
 * --verbose additionally prints one `row ...` line per swept height, in
 * ascending height order, BEFORE the digest line — the digest line is always
 * last, so `tail -n1` works in both modes. That is the audit trail: when two
 * digests differ, diff the two verbose outputs and the first differing row
 * names the height where the two builds part company.
 *
 * Exit status: 0 on success, 1 on a usage or configuration error.
 */

#include "consensus_rule_sweep.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Caller-owned scratch for the height vector; the engine never allocates. */
static int32_t g_heights[CRS_MAX_HEIGHTS];

static void print_usage(FILE *out)
{
    fprintf(out,
        "usage: consensus_rule_sweep [--tip=N] [--horizon=N] [--stride=N]\n"
        "                            [--band=N] [--verbose] [--help]\n"
        "\n"
        "Folds the pure consensus schedule over a deterministic height sweep\n"
        "into one SHA3-256 digest. Reads no datadir, no disk, no network.\n"
        "\n"
        "  --tip=N      sweep origin for the forward band (default %d — a\n"
        "               PINNED constant, not the live chain tip, so two boxes\n"
        "               must agree on the vector deliberately)\n"
        "  --horizon=N  how far past the tip to reach (default %d)\n"
        "  --stride=N   spacing of the forward samples (default %d)\n"
        "  --band=N     dense band radius around each sample (default %d)\n"
        "  --verbose    also print one row per swept height, ascending\n"
        "\n"
        "Every parameter above is folded into the digest preimage, so digests\n"
        "from different sweep vectors differ rather than falsely agreeing.\n",
        CRS_DEFAULT_TIP, CRS_DEFAULT_HORIZON, CRS_DEFAULT_STRIDE,
        CRS_DEFAULT_BAND);
}

/* Strict decimal parse: the whole suffix must be digits and fit int32_t.
 * A silently truncated "--tip=99999999999" would produce a digest for a sweep
 * nobody asked for, which is the one failure mode this tool cannot have. */
static bool parse_i32(const char *s, int32_t *out)
{
    if (!s || !*s)
        return false;
    for (const char *c = s; *c; c++) {
        if (*c < '0' || *c > '9')
            return false;
    }
    char *end = NULL;
    long long v = strtoll(s, &end, 10);
    if (!end || *end != '\0')
        return false;
    if (v < 0 || v > INT32_MAX)
        return false;
    *out = (int32_t)v;
    return true;
}

static void print_row(const struct crs_row *row, void *ctx)
{
    (void)ctx;
    char pow_hex[65];
    char ckpt_hex[65];
    crs_hex32(row->pow_limit, pow_hex);
    crs_hex32(row->checkpoint_digest, ckpt_hex);
    printf("row h=%" PRId32 " subsidy=%" PRId64 " ok=%u code=%" PRId32
           " halvings=%" PRId32 " upg=%016" PRIx64 " state=%016" PRIx64
           " epoch=%" PRId32 " branch=%08" PRIx32 " eh=%u,%u"
           " spacing=%" PRId64 " awt=%" PRId64 " mints=%" PRId64
           " maxts=%" PRId64 " maxblk=%" PRIu64 " maxtx=%" PRIu64
           " pow=%s ckpt=%s\n",
           row->height, row->subsidy, (unsigned)row->subsidy_ok,
           row->subsidy_code, row->halvings, row->upgrade_active_mask,
           row->upgrade_state_packed, row->epoch, row->branch_id,
           row->equihash_n, row->equihash_k, row->target_spacing,
           row->averaging_window_timespan, row->min_actual_timespan,
           row->max_actual_timespan, row->max_block_size,
           row->max_tx_size_after_sapling, pow_hex, ckpt_hex);
}

int main(int argc, char **argv)
{
    struct crs_config cfg = crs_default_config();
    bool verbose = false;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) {
            print_usage(stdout);
            return 0;
        } else if (strcmp(a, "--verbose") == 0) {
            verbose = true;
        } else if (strncmp(a, "--tip=", 6) == 0) {
            if (!parse_i32(a + 6, &cfg.tip)) goto bad_arg;
        } else if (strncmp(a, "--horizon=", 10) == 0) {
            if (!parse_i32(a + 10, &cfg.horizon)) goto bad_arg;
        } else if (strncmp(a, "--stride=", 9) == 0) {
            if (!parse_i32(a + 9, &cfg.stride)) goto bad_arg;
        } else if (strncmp(a, "--band=", 7) == 0) {
            if (!parse_i32(a + 7, &cfg.band)) goto bad_arg;
        } else {
            fprintf(stderr, "consensus_rule_sweep: unknown argument '%s'\n", a);
            print_usage(stderr);
            return 1;
        }
        continue;
    bad_arg:
        fprintf(stderr,
                "consensus_rule_sweep: '%s' is not a non-negative int32\n", a);
        return 1;
    }

    enum crs_status st = crs_validate_config(&cfg);
    if (st != CRS_OK) {
        fprintf(stderr, "consensus_rule_sweep: %s (tip=%" PRId32
                " horizon=%" PRId32 " stride=%" PRId32 " band=%" PRId32 ")\n",
                crs_status_str(st), cfg.tip, cfg.horizon, cfg.stride, cfg.band);
        return 1;
    }

    chain_params_select(CHAIN_MAIN);
    const struct chain_params *cp = chain_params_get();

    uint8_t digest[32];
    size_t rows = 0;
    st = crs_run(&cfg, cp, g_heights, CRS_MAX_HEIGHTS, NULL, NULL,
                 verbose ? print_row : NULL, NULL, digest, &rows);
    if (st != CRS_OK) {
        fprintf(stderr, "consensus_rule_sweep: %s\n", crs_status_str(st));
        return 1;
    }

    char hex[65];
    crs_hex32(digest, hex);
    printf("%s  %s network=%s tip=%" PRId32 " horizon=%" PRId32
           " stride=%" PRId32 " band=%" PRId32 " slots=%d rows=%zu\n",
           hex, CRS_VERSION_TAG, cp->strNetworkID, cfg.tip, cfg.horizon,
           cfg.stride, cfg.band, (int)MAX_NETWORK_UPGRADES, rows);
    return 0;
}
