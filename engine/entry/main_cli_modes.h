/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Entry points for the CLI client + offline run-and-exit modes implemented
 * in src/main_cli_modes.c. main() (engine/entry/main.c) dispatches to these; each runs
 * one command and returns a process exit code — none boot the resident node.
 */
#ifndef ZCLASSIC23_SRC_MAIN_CLI_MODES_H
#define ZCLASSIC23_SRC_MAIN_CLI_MODES_H

#include <stdbool.h>

/* -bench* crypto/regress benchmarks. */
int bench_mode_main(int argc, char **argv);

/* Native-command + RPC client / status client. is_cli_mode() decides whether
 * argv should be routed here rather than to a node boot. */
int cli_main(int argc, char **argv);
bool is_cli_mode(int argc, char **argv);

/* --gen-utxo-snapshot: build a UTXO sidecar from a legacy chainstate. */
int gen_utxo_snapshot_mode(int argc, char **argv);
/* --legacy-utxo-commitment: hash-only — print the canonical SHA3-256 over
 * the legacy chainstate UTXO set as one JSON line (byte-exact C8 parity
 * reference; no sidecar, no checkpoint assert). */
int legacy_utxo_commitment_mode(int argc, char **argv);

/* -import-complete-shielded=<zclassicd-datadir>: owner-gated shielded-state
 * import into a target-copy datadir. */
int import_complete_shielded_mode(int argc, char **argv);

/* --importblockindex <legacy-datadir|node.db>: header/block-index import.
 * ibi_idx is the argv index of the --importblockindex token. */
int importblockindex_cli_mode(int argc, char **argv, int ibi_idx);

/* Former inline main() sub-modes (unchanged behavior). */
int wallet_backup_decrypt_mode(int argc, char **argv);
int repair_utxos_mode(int argc, char **argv);
int importchainstate_mode(int argc, char **argv);
int mintutxocommitment_mode(int argc, char **argv);

#endif /* ZCLASSIC23_SRC_MAIN_CLI_MODES_H */
