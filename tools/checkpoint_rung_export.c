/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * checkpoint_rung_export — the ladder RUNG generator entry point.
 *
 * Reads a `zcl.consensus_state_bundle.v1` bundle (the exporter's output),
 * derives the complete-state rung at that bundle's height (transparent utxo
 * root, sprout/sapling frontier roots, nullifier digest, rom_state_root, block
 * hash), folds in the operator-supplied cumulative chainwork, and emits BOTH:
 *   - a binary artifact  <out_dir>/rung-<height>.rung  (CHECKPOINT_RUNG_WIRE_SIZE
 *     bytes; parseable by the node's checkpoint_ladder verifier), and
 *   - a C designated-initializer fragment <out_dir>/rung-<height>.c (also on
 *     stdout) — ready to paste into the SEALED core/chainparams/src/checkpoints.c
 *     table during the owner two-builder unseal ritual.
 *
 * HONESTY: a rung emitted here is candidate_unbaked self-attestation — a node
 * asserting its own state. It becomes a trust root ONLY when the owner
 * re-derives it under the two-builder gate and bakes it into sealed core. This
 * tool does not (and cannot) elevate it.
 *
 * The rung fold/serialize/self-digest all come from the CANONICAL node module
 * lib/storage/src/checkpoint_rung.c (linked here), so a tool artifact and a
 * node-produced artifact are byte-identical by construction. Standalone build:
 * vendored sqlite + lib/crypto sha3 + the pure rung TU + log_level. Opens the
 * bundle read-only; writes only into out_dir.
 *
 * Usage: checkpoint_rung_export BUNDLE.sqlite OUT_DIR [--chainwork=<64hex-BE>]
 * Exit:  0 = rung written; 1 = derive/IO error; 2 = usage error.
 */

#include "storage/checkpoint_rung.h"

#include "base/hex.h"

#include <sqlite3.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    const char *bundle_path = NULL;
    const char *out_dir = NULL;
    uint8_t chainwork[32] = {0};
    bool have_chainwork = false;

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--chainwork=", 12) == 0) {
            if (!zcl_hex_decode(argv[i] + 12, chainwork, 32)) {
                fprintf(stderr, "checkpoint_rung_export: --chainwork must be "
                                "64 hex chars (32-byte big-endian)\n");
                return 2;
            }
            have_chainwork = true;
        } else if (!bundle_path) {
            bundle_path = argv[i];
        } else if (!out_dir) {
            out_dir = argv[i];
        } else {
            fprintf(stderr, "checkpoint_rung_export: unexpected arg '%s'\n",
                    argv[i]);
            return 2;
        }
    }
    if (!bundle_path || !out_dir) {
        fprintf(stderr,
                "usage: %s BUNDLE.sqlite OUT_DIR [--chainwork=<64hex-BE>]\n"
                "  0 = rung written; 1 = derive/IO error; 2 = usage error\n",
                argv[0]);
        return 2;
    }

    char uri[4096];
    snprintf(uri, sizeof(uri), "file:%s?mode=ro", bundle_path);
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(uri, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI,
                        NULL) != SQLITE_OK) {
        fprintf(stderr, "checkpoint_rung_export: open %s: %s\n", bundle_path,
                db ? sqlite3_errmsg(db) : "unknown");
        if (db)
            sqlite3_close(db);
        return 1;
    }

    struct checkpoint_rung rung;
    bool ok = checkpoint_rung_derive_from_bundle(
        db, have_chainwork ? chainwork : NULL, &rung);
    sqlite3_close(db);
    if (!ok) {
        fprintf(stderr, "checkpoint_rung_export: derive failed (see log)\n");
        return 1;
    }

    /* Binary artifact. */
    uint8_t wire[CHECKPOINT_RUNG_WIRE_SIZE];
    if (!checkpoint_rung_serialize(&rung, wire)) {
        fprintf(stderr, "checkpoint_rung_export: serialize failed\n");
        return 1;
    }
    char bin_path[4200];
    snprintf(bin_path, sizeof(bin_path), "%s/rung-%d.rung", out_dir,
             rung.height);
    FILE *bf = fopen(bin_path, "wb");
    if (!bf || fwrite(wire, 1, sizeof(wire), bf) != sizeof(wire)) {
        fprintf(stderr, "checkpoint_rung_export: write %s failed\n", bin_path);
        if (bf)
            fclose(bf);
        return 1;
    }
    fclose(bf);

    /* C fragment. */
    char frag[8192];
    int fn = checkpoint_rung_emit_c_fragment(&rung, frag, sizeof(frag));
    if (fn < 0 || (size_t)fn >= sizeof(frag)) {
        fprintf(stderr, "checkpoint_rung_export: fragment emit failed/truncated"
                        " (%d bytes)\n", fn);
        return 1;
    }
    char c_path[4200];
    snprintf(c_path, sizeof(c_path), "%s/rung-%d.c", out_dir, rung.height);
    FILE *cf = fopen(c_path, "w");
    if (!cf || fwrite(frag, 1, (size_t)fn, cf) != (size_t)fn) {
        fprintf(stderr, "checkpoint_rung_export: write %s failed\n", c_path);
        if (cf)
            fclose(cf);
        return 1;
    }
    fclose(cf);

    fputs(frag, stdout);
    fprintf(stderr,
            "checkpoint_rung_export: wrote rung at height %d\n"
            "  binary:   %s (%u bytes)\n"
            "  fragment: %s\n"
            "  candidate_unbaked — bake only under the two-builder unseal "
            "ritual.\n",
            rung.height, bin_path, CHECKPOINT_RUNG_WIRE_SIZE, c_path);
    return 0;
}
