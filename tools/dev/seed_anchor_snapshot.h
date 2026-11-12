/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Stage one anchor UTXO snapshot into a datadir. */

#ifndef ZCL_SEED_ANCHOR_SNAPSHOT_H
#define ZCL_SEED_ANCHOR_SNAPSHOT_H

/* Reads ZCL_DATADIR (else $HOME/.zclassic-c23) and ZCL_ANCHOR_SNAPSHOT_SRC
 * (else /tmp/anchor-ram.snapshot). An empty value is unset. Stages
 * <datadir>/utxo-anchor.snapshot.
 * Returns 0 when the snapshot is staged or the skip is non-fatal,
 * including a temp path that does not fit.
 * Returns 1 when neither ZCL_DATADIR nor HOME can name a datadir, or the
 * datadir, source, or destination path does not fit. */
int zcl_seed_anchor_snapshot(void);

#endif
