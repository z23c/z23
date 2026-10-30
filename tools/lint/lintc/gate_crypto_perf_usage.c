/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the -h text of check-crypto-perf, byte for byte what the shell script
 * printed (its header comment lines, `grep ^#` then the `# ` prefix stripped).
 * Split from gate_crypto_perf.c to keep that file small.
 */
#include <stdio.h>
#include "gate_crypto_perf_priv.h"

void ccp_usage(FILE *out)
{
    static const char *const u[] = {
        "!/usr/bin/env bash",
        "check_crypto_perf.sh — the STANDING crypto-vs-Rust performance gate.",
        "",
        "Measures every C crypto primitive on the consensus path live (median ns/op,",
        "via build/bin/zclassic23 -bench-crypto-vs-rust) and enforces two invariants",
        "against the pinned baseline (tools/crypto_perf_baseline.csv):",
        "",
        "  RATCHET (always, hard):  measured_c_ns <= c_ns_baseline * (1 + margin).",
        "          The baseline is a CEILING that may only shrink — a self-regression",
        "          beyond the flake margin FAILS. This is the core protection: our C",
        "          crypto can only get faster.",
        "",
        "  RATIO vs Rust:",
        "    gate_mode=beat   -> hard-FAIL if measured_c_ns >= rust_ns_baseline. We",
        "                        beat Rust here and must stay ahead. Flake-proof by",
        "                        construction: a `beat` row is only valid when",
        "                        rust_ns_baseline >= c_ns_baseline*(1+margin), so any",
        "                        run that passes the ratchet is necessarily < rust.",
        "    gate_mode=behind -> NO hard fail (would red main today); prints a loud",
        "                        \"BEHIND RUST — optimize\" line and leans on the ratchet",
        "                        for monotonic improvement toward parity.",
        "",
        "This gate is a DELIBERATE target, NOT part of the default `make lint` aggregate",
        "(microbench timing flakes under CI load). Run it in a quiet context:",
        "    make check-crypto-perf                # measure + gate + append history",
        "    tools/scripts/check_crypto_perf.sh --selftest   # logic self-test, no build",
        "",
        "Rules honoured: no Rust is linked into the shipped binary (comparison is",
        "against pinned/cited numbers only); monotonic clock inside the bench; timing",
        "uses median-of-N for flake resistance.",
        "",
        "Exit: 0 = all invariants hold (behind rows are allowed), non-zero = a ratchet",
        "regression or a lost lead against Rust.",
        "float_le A B  -> exit 0 if A <= B",
        "eval_row KEY MEAS C_BASE RUST MODE MARGIN",
        "Echoes: \"<verdict> <ratio>\" where verdict in",
        "  OK_BEAT | OK_BEHIND | FAIL_RATCHET | FAIL_BEAT | FAIL_CONFIG",
        "Returns 0 for OK_*, 1 for FAIL_*. Pure arithmetic — shared by gate + selftest.",
        "── selftest: exercise the evaluator against synthetic rows ─────────────",
        "── live gate ───────────────────────────────────────────────────────────",
        "key -> measured c_ns",
        NULL,
    };
    for (size_t i = 0; u[i]; i++)
        fprintf(out, "%s\n", u[i]);
}
