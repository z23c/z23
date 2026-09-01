/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Durable consensus-bundle-installed marker: written atomically on
 * successful -install-consensus-bundle activation; its presence makes boot
 * refuse borrowed starter-pack seed auto-loads over sovereign state. */
#ifndef ZCL_BOOT_CONSENSUS_BUNDLE_MARKER_H
#define ZCL_BOOT_CONSENSUS_BUNDLE_MARKER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Durable datadir marker written by a successful -install-consensus-bundle
 * activation. Its presence is the "this datadir now holds sovereign, installed
 * consensus state" flag that boot_snapshot_failure_memory consults: once a
 * bundle has been installed here, a leftover starter-pack 'utxo-seed-*.snapshot'
 * must NEVER be auto-loaded back over the installed state — a stale borrowed
 * seed can otherwise flip coins-best off the installed anchor.
 *
 * The marker records the installed height, the bundle artifact digest, and the
 * install time so an operator (and diagnostics) can see exactly which bundle is
 * resident. It is a plain text file written atomically (temp + rename). */

#define BOOT_CONSENSUS_BUNDLE_MARKER_NAME "consensus-bundle-installed.marker"

/* Write (or overwrite) the marker in `datadir`. `artifact_digest` is the 32-byte
 * bundle manifest artifact digest. Returns false (and logs) on any I/O error. */
bool boot_consensus_bundle_marker_write(const char *datadir, int32_t height,
                                        const uint8_t artifact_digest[32]);

/* True iff the marker file exists in `datadir`. Cheap access() probe; never
 * parses contents (a present-but-unreadable marker still counts as installed). */
bool boot_consensus_bundle_marker_exists(const char *datadir);

#endif /* ZCL_BOOT_CONSENSUS_BUNDLE_MARKER_H */
