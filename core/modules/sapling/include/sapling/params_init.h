/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Load Zcash zkSNARK verification keys from params files. */

#ifndef ZCL_SAPLING_PARAMS_INIT_H
#define ZCL_SAPLING_PARAMS_INIT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Load a full parameter directory: the Sapling and Sprout Groth16 verifying
 * keys, and the proving keys that make shielded SENDING possible. Every file
 * is checked against its compiled-in SHA-512 before a byte of it is used, and
 * a directory that fails any of those pins is refused whole.
 *
 * CALL IT WHENEVER THE PARAMETERS ARRIVE — including on a running node.
 *
 * A node that booted with no parameter directory installed the compiled-in
 * verifying keys (sapling_install_embedded_vks) and has been validating and
 * serving ever since; the one thing it cannot do is create a shielded
 * transaction. When the proving parameters land — a fetch that completed
 * (net/params_service.h), an operator copying files in — this is the call that
 * turns that capability on, with no restart:
 *
 *     if (sapling_init_params(params_dir) &&
 *         zclassic_sapling_prover_is_ready()) { ... shielded send is armed ... }
 *
 * Both halves matter. The first says the pinned parameter set loaded; the
 * second says the prover proved a real Spend + Output + binding bundle that
 * this node's own consensus verifier accepted. Only the second one gates
 * sending.
 *
 * Thread rules. Safe to call from any thread and safe to call concurrently:
 * the loaders are serialised internally, and a late load only ADDS the proving
 * keys — it never re-parses, replaces or frees a verifying key that consensus
 * threads are reading. But it reads ~777 MB and runs a Groth16 self-test, so
 * call it from a BACKGROUND thread. Never from a P2P message handler, and
 * never while holding a lock a message handler takes.
 *
 * Returns false if the directory is unusable; the keys already published stay
 * published and the node keeps validating. */
bool sapling_init_params(const char *params_dir);

/* True once the VERIFYING keys are published and shielded proof VALIDATION is
 * armed — by a parameter directory or by the compiled-in fallback. It says
 * nothing about proving: use zclassic_sapling_prover_is_ready() for that.
 * Safe to read from reducer/validation threads while the boot loader thread is
 * still parsing the large params files. */
bool sapling_params_loaded(void);

/* Get raw proving key data for Sapling output/spend proofs.
 * Returns pointer to mmap'd file data. NULL if not loaded. */
const uint8_t *sapling_get_output_pk(size_t *len);
const uint8_t *sapling_get_spend_pk(size_t *len);

/* Free all loaded verification keys. */
void sapling_free_params(void);

#endif
