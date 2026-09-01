/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: pick the consensus-state bundle and header-chain seed manifests
 * out of a peer's /directory.json body.
 *
 * Split out of engine/composition/src/boot_bundle_fetch.c (THE WELD) when that file
 * passed its shape ceiling. This half is the pure SELECTION policy — it
 * parses a directory body, applies the kind-aware newest-then-largest rule,
 * and assigns the canonical filename the installer's classify step needs.
 * It performs no I/O and touches no datadir. The gate, the verified
 * download, and the peer-discovery entry point stay in boot_bundle_fetch.c.
 * Both entry points are declared in config/boot_bundle_fetch.h, so this is
 * a pure move with no linkage change.
 */

#include "config/boot_bundle_fetch.h"

#include "chain/checkpoints.h"                 /* get_sha3_utxo_checkpoint */
#include "net/rom_fetch.h"

#include <stdio.h>
#include <string.h>

/* ── Manifest pick from a /directory.json body ──────────────────────────── */

bool boot_bundle_pick_manifest(const char *directory_json,
                               struct rom_fetch_manifest *out)
{
    if (!directory_json || !out)
        return false;

    struct rom_fetch_manifest arts[ROM_FETCH_MAX_ARTIFACTS];
    memset(arts, 0, sizeof(arts));
    int n = rom_fetch_parse_directory(directory_json, arts,
                                      ROM_FETCH_MAX_ARTIFACTS);
    if (n <= 0)
        return false;

    /* Kind-aware, NEWEST-by-height bundle selection. Pass 1: among explicitly
     * consensus-bundle-kinded artifacts pick the HIGHEST advertised height, with
     * size as the tie-break (and, since a legacy no-height entry parses to
     * height 0, this reduces to "largest wins" when every candidate is a legacy
     * 0). Pass 2 (legacy back-compat): a directory that carries no "kind" field
     * parses every entry to ROM_ARTIFACT_UNKNOWN, so fall back to the same
     * newest-then-largest rule over non-header-seed artifacts — never
     * mis-picking the header-chain seed as a .sqlite bundle. Newest-by-height
     * (not size) is what lets a fresh consumer pick the freshest bundle across a
     * mixed-height seed set; height is untrusted (trust binds at install). */
    int best = -1;
    for (int i = 0; i < n; i++) {
        if (!arts[i].used || arts[i].kind != ROM_ARTIFACT_CONSENSUS_BUNDLE)
            continue;
        if (best < 0 || arts[i].height > arts[best].height ||
            (arts[i].height == arts[best].height &&
             arts[i].size_bytes > arts[best].size_bytes))
            best = i;
    }
    if (best < 0) {
        for (int i = 0; i < n; i++) {
            if (!arts[i].used || arts[i].kind == ROM_ARTIFACT_HEADER_SEED)
                continue;
            if (best < 0 || arts[i].height > arts[best].height ||
                (arts[i].height == arts[best].height &&
                 arts[i].size_bytes > arts[best].size_bytes))
                best = i;
        }
    }
    if (best < 0)
        return false;

    *out = arts[best];

    /* directory.json entries carry digests + layout but NO filename. Assign a
     * canonical, classifiable name so both boot_autodetect_consensus_bundle
     * (requires *.sqlite) and the installer's classify step (requires the
     * consensus-state-bundle- prefix) accept the downloaded file. Name it by the
     * ADVERTISED height when present so the staged file (and the
     * lexicographic-then-numeric autodetect in boot_auto_install_bundle.c) knows
     * WHICH generation it is; only when the advertisement carried no height
     * (legacy 0) fall back to the compiled checkpoint height. The height is
     * cosmetic to the classifier; the CHECKPOINT_ROM authority is what actually
     * binds the installed state. */
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    long h = out->height > 0 ? (long)out->height : (cp ? (long)cp->height : 0);
    snprintf(out->filename, sizeof(out->filename),
             "consensus-state-bundle-%ld.sqlite", h);
    out->used = true;

    /* Re-check with the assigned filename (rom_fetch_manifest_sane also enforces
     * the filename is a bare basename — it is). */
    if (!rom_fetch_manifest_sane(out))
        return false;
    return true;
}

bool boot_bundle_pick_header_seed_manifest(const char *directory_json,
                                           struct rom_fetch_manifest *out)
{
    if (!directory_json || !out)
        return false;

    struct rom_fetch_manifest arts[ROM_FETCH_MAX_ARTIFACTS];
    memset(arts, 0, sizeof(arts));
    int n = rom_fetch_parse_directory(directory_json, arts,
                                      ROM_FETCH_MAX_ARTIFACTS);
    if (n <= 0)
        return false;

    /* The header-chain seed is the ROM_ARTIFACT_HEADER_SEED-kinded entry. It is
     * selected by kind ONLY (never by size) — a legacy directory that emits no
     * kind cannot advertise a header seed, and must not have some other artifact
     * mistaken for one. */
    int best = -1;
    for (int i = 0; i < n; i++) {
        if (!arts[i].used || arts[i].kind != ROM_ARTIFACT_HEADER_SEED)
            continue;
        if (best < 0 || arts[i].size_bytes > arts[best].size_bytes)
            best = i;
    }
    if (best < 0)
        return false;

    *out = arts[best];

    /* directory.json entries carry no filename; assign the canonical
     * block_index.bin so rom_seed_classify (serve + re-seed) and the flat loader
     * (boot_header_seed_import) accept the downloaded file. */
    snprintf(out->filename, sizeof(out->filename), "block_index.bin");
    out->used = true;

    if (!rom_fetch_manifest_sane(out))
        return false;
    return true;
}
