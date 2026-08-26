/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The zk-parameter boot gate. See config/src/boot_params_gate.c for why a
 * node with no ~/.zcash-params still syncs, validates and serves.
 */

#ifndef ZCL_CONFIG_BOOT_PARAMS_GATE_H
#define ZCL_CONFIG_BOOT_PARAMS_GATE_H

#include <stdbool.h>

struct app_context;
struct chain_params;

enum boot_params_gate_result {
    /* The parameter files are there (or this network/mode does not need
     * them). The caller starts the background loader as before. */
    BOOT_PARAMS_GATE_PRESENT = 0,
    /* Files absent; the compiled-in verifying keys are installed. Shielded
     * proof VALIDATION is armed, shielded spend CREATION is not, and a
     * shielded_spend_unavailable blocker names that. The caller must NOT
     * start the loader — there is nothing for it to load. */
    BOOT_PARAMS_GATE_EMBEDDED,
    /* The compiled-in keys failed their integrity check: this binary cannot
     * verify shielded proofs. The caller must park alive-degraded without
     * advancing CRYPTO_READY. */
    BOOT_PARAMS_GATE_PARK,
};

/* Evaluate the gate and emit its blocker/telemetry. params_dir is the
 * resolved parameter directory buffer the caller will hand the loader. */
enum boot_params_gate_result
boot_params_gate_evaluate(const struct app_context *ctx,
                          const struct chain_params *params,
                          const char *params_dir);

/* The other half of the same question: the files WERE there, so the loader
 * ran, and it refused them (pinned SHA-512 mismatch or parse failure). Absent
 * and refused cost the same one capability, so they are decided in the same
 * place. Installs the compiled-in verifying keys, emits the blocker and log
 * lines, and returns true when shielded proof VALIDATION is armed — the caller
 * publishes its own params-loaded flag on true. Returns false only when the
 * compiled-in keys ALSO failed their integrity check, which is the one case
 * where validation really cannot proceed. */
bool boot_params_gate_on_load_refused(const char *params_dir);

#endif /* ZCL_CONFIG_BOOT_PARAMS_GATE_H */
