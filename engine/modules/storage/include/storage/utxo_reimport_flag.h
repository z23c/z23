/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_reimport_flag — durable "needs reimport" sentinel.
 *
 * Background
 * ----------
 * When `process_block.c` self-heal sees N consecutive UTXO validation
 * failures (currently N=3), it writes a single-byte '1' marker to
 * `<datadir>/needs_reimport`. On the next boot, the recovery path
 * checks for this marker; if present, it triggers a forced UTXO
 * re-import from the LevelDB chainstate.
 *
 * Keeping this flag in its own storage primitive (rather than inline in
 * utxo_recovery_service.c / process_block_self_heal.c) does three things:
 *
 *   - Puts a storage concern in the storage layer (engine/modules/storage/) rather
 *     than scattering `fopen`/`fread`/`remove` across services.
 *   - Lets the boot path and the validation path share a single
 *     authoritative implementation of the on-disk format.
 *   - Renames the read-side helper from `check_reimport_flag` to
 *     `check_and_clear` — the old name hid the destructive clear that
 *     happens unconditionally.
 *
 * On-disk format (unchanged)
 * ---------------------------
 *   path:    <datadir>/needs_reimport
 *   content: single byte '1' (0x31). Absent file or any other content
 *            means "not set".
 *
 * Concurrency
 * -----------
 * Production has one writer (process_block self-heal, single-threaded
 * inside the chain-advance hot loop) and one reader (boot path, before
 * any chain mutators are spun up). There are no locks; the contract is
 * "set once, clear once at boot".
 */

#ifndef ZCL_STORAGE_UTXO_REIMPORT_FLAG_H
#define ZCL_STORAGE_UTXO_REIMPORT_FLAG_H

#include <stdbool.h>

/* Read the flag and remove the file as an atomic side effect.
 *
 * Returns true iff the file existed AND its first byte was '1'. In
 * every case where the file existed (regardless of content), the file
 * is removed before this function returns — the clear is unconditional
 * by design, so a malformed marker cannot loop forever. */
bool utxo_reimport_flag_check_and_clear(const char *datadir);

/* Write the flag. Called by validation self-heal when consecutive
 * UTXO failures cross the threshold. Returns true on success. */
bool utxo_reimport_flag_set(const char *datadir);

#endif /* ZCL_STORAGE_UTXO_REIMPORT_FLAG_H */
