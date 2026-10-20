/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_checkpoint_rom_authority — focused unit test for the CHECKPOINT_ROM
 * ACTIVATE authority (engine/composition/src/consensus_state_snapshot_install_checkpoint_
 * authority.c).
 *
 * CHECKPOINT_ROM lifts ACTIVATE containment SOVEREIGNLY when an install
 * candidate's manifest reproduces EVERY component of the compiled shielded ROM
 * state checkpoint (g_rom_state_checkpoint) byte-for-byte, header-independent
 * and fail-closed. It binds the historical Sprout anchors and the full
 * nullifier set that the header-dependent CHECKPOINT_CONTENT authority
 * (transparent coins + Sapling tip frontier root) leaves unbound.
 *
 * Pure synthetic fixture: it drives the content-authority resolver
 * (consensus_state_activate_resolve_content_authority_name_for_test — the
 * CHECKPOINT_ROM -> CHECKPOINT_CONTENT half of the resolver, bypassing the
 * evidence/receipt gate) with a hand-built manifest against a
 * checkpoints_set_rom_state_override_for_test() keystone. No bundle file,
 * datadir, replay receipt, or 3M-block boot. Asserts:
 *   (a) full component match at the override height   -> "checkpoint_rom"
 *   (b) any single flipped component                  -> not activate ("none")
 *   (c) height mismatch                               -> falls through to the
 *       CHECKPOINT_CONTENT path UNCHANGED (no SHA3 match -> "none"; a matching
 *       SHA3 checkpoint + validated-header Sapling root -> "checkpoint_content")
 *   (d) unbaked (placeholder) keystone                -> not activate ("none")
 */

#include "test/test_core.h"

#include "chain/checkpoints.h"
#include "config/consensus_state_snapshot_install.h"
#include "storage/consensus_state_bundle_codec.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CROM_H 4242 /* synthetic ROM checkpoint height (never the real 3056758) */

/* A fully-baked synthetic keystone: every component nonzero so it is not a
 * placeholder. Values mirror the real keystone's magnitudes for readability
 * (they are not asserted against production — this is a self-contained fixture). */
static void synth_rom(struct rom_state_checkpoint *rom, int32_t height)
{
    memset(rom, 0, sizeof(*rom));
    rom->height = height;
    memset(rom->block_hash, 0xb1, 32);
    memset(rom->utxo_root, 0x11, 32);
    rom->utxo_count = 1354769;
    rom->total_supply = 1036413794674881LL;
    memset(rom->anchor_digest, 0x22, 32);
    rom->anchor_count = 631645;
    memset(rom->sprout_frontier_root, 0x33, 32);
    rom->sprout_frontier_height = 2124937;
    memset(rom->sapling_frontier_root, 0x44, 32);
    rom->sapling_frontier_height = height - 16;
    memset(rom->nullifier_digest, 0x55, 32);
    rom->nullifier_count = 1495126;
    memset(rom->rom_state_root, 0x66, 32); /* nonzero -> not a placeholder */
}

/* A manifest whose every ROM-bound component equals the keystone. */
static void manifest_from_rom(struct consensus_state_bundle_manifest *m,
                              const struct rom_state_checkpoint *rom)
{
    memset(m, 0, sizeof(*m));
    m->height = rom->height;
    memcpy(m->block_hash, rom->block_hash, 32);
    m->history_complete = true;
    memcpy(m->utxo_root, rom->utxo_root, 32);
    m->utxo_count = rom->utxo_count;
    m->total_supply = rom->total_supply;
    memcpy(m->anchor_digest, rom->anchor_digest, 32);
    m->anchor_count = rom->anchor_count;
    memcpy(m->sprout_frontier_root, rom->sprout_frontier_root, 32);
    m->sprout_frontier_height = rom->sprout_frontier_height;
    memcpy(m->sapling_frontier_root, rom->sapling_frontier_root, 32);
    m->sapling_frontier_height = rom->sapling_frontier_height;
    memcpy(m->nullifier_digest, rom->nullifier_digest, 32);
    m->nullifier_count = rom->nullifier_count;
}

/* Baked ladder rung activation. A bundle at a baked rung height (above the
 * keystone) activates via CHECKPOINT_ROM only when EVERY field of THAT rung is
 * reproduced; the keystone height keeps resolving (non-regression) with the rung
 * table installed; an UNBAKED height, a rung with an unbaked placeholder, and a
 * rung-height bundle carrying the keystone's content all stay "none". */
static int rung_activation_tests(const struct rom_state_checkpoint *keystone,
                                 const struct consensus_state_activate_request *req)
{
    int failures = 0;
#define RCHECK(desc, cond)                                                   \
    do {                                                                     \
        printf("checkpoint_rom_authority: rung: %s... ", (desc));            \
        if (cond) printf("OK\n");                                            \
        else { printf("FAIL\n"); failures++; }                              \
    } while (0)
#define RNAME(m)                                                             \
    consensus_state_activate_resolve_content_authority_name_for_test(        \
        (m), req)

    struct rom_state_rung rung;
    memset(&rung, 0, sizeof(rung));
    synth_rom(&rung.cp, CROM_H + 500);
    /* Distinct content from the keystone so cross-binding is observable. */
    memset(rung.cp.block_hash, 0xc3, 32);
    memset(rung.cp.utxo_root, 0x12, 32);
    memset(rung.cp.anchor_digest, 0x23, 32);
    memset(rung.cp.sprout_frontier_root, 0x34, 32);
    memset(rung.cp.sapling_frontier_root, 0x45, 32);
    memset(rung.cp.nullifier_digest, 0x56, 32);
    rung.cp.utxo_count += 99;
    rung.cp.anchor_count += 99;
    rung.cp.nullifier_count += 99;
    rung.chainwork[31] = 9;

    checkpoints_set_rom_state_override_for_test(keystone);
    checkpoints_set_rom_state_rungs_override_for_test(&rung, 1);

    /* (a) full match at the rung height activates via CHECKPOINT_ROM, no header. */
    {
        struct consensus_state_bundle_manifest m;
        manifest_from_rom(&m, &rung.cp);
        const char *nm = RNAME(&m);
        RCHECK("full rung match -> checkpoint_rom",
               nm && strcmp(nm, "checkpoint_rom") == 0);
    }

    /* (b) every single tampered field refuses (none). */
#define RFLIP(desc, mutate)                                                  \
    do {                                                                     \
        struct consensus_state_bundle_manifest m;                            \
        manifest_from_rom(&m, &rung.cp);                                     \
        mutate;                                                              \
        const char *nm = RNAME(&m);                                          \
        RCHECK("tampered " desc " -> none", nm && strcmp(nm, "none") == 0);  \
    } while (0)
    RFLIP("block_hash", m.block_hash[0] ^= 0xff);
    RFLIP("utxo_root", m.utxo_root[0] ^= 0xff);
    RFLIP("utxo_count", m.utxo_count += 1);
    RFLIP("total_supply", m.total_supply += 1);
    RFLIP("anchor_digest", m.anchor_digest[0] ^= 0xff);
    RFLIP("anchor_count", m.anchor_count += 1);
    RFLIP("sprout_frontier_root", m.sprout_frontier_root[0] ^= 0xff);
    RFLIP("sprout_frontier_height", m.sprout_frontier_height += 1);
    RFLIP("sapling_frontier_root", m.sapling_frontier_root[0] ^= 0xff);
    RFLIP("sapling_frontier_height", m.sapling_frontier_height += 1);
    RFLIP("nullifier_digest", m.nullifier_digest[0] ^= 0xff);
    RFLIP("nullifier_count", m.nullifier_count += 1);
#undef RFLIP

    /* (c) the keystone height still activates with the rung table installed. */
    {
        struct consensus_state_bundle_manifest m;
        manifest_from_rom(&m, keystone);
        const char *nm = RNAME(&m);
        RCHECK("keystone-height bundle still -> checkpoint_rom",
               nm && strcmp(nm, "checkpoint_rom") == 0);
    }

    /* (d) UNBAKED height: rung content at a height no commitment is baked for. */
    {
        struct consensus_state_bundle_manifest m;
        manifest_from_rom(&m, &rung.cp);
        m.height = CROM_H + 700;
        const char *nm = RNAME(&m);
        RCHECK("unbaked height -> none", nm && strcmp(nm, "none") == 0);
    }
    /* Rung-height bundle carrying the KEYSTONE's content is not the rung. */
    {
        struct consensus_state_bundle_manifest m;
        manifest_from_rom(&m, keystone);
        m.height = rung.cp.height;
        const char *nm = RNAME(&m);
        RCHECK("rung height with keystone content -> none",
               nm && strcmp(nm, "none") == 0);
    }
    /* Rung whose shielded fold is unbaked (placeholder): never a trust root. */
    {
        struct rom_state_rung ph = rung;
        memset(ph.cp.nullifier_digest, 0, 32);
        checkpoints_set_rom_state_rungs_override_for_test(&ph, 1);
        struct consensus_state_bundle_manifest m;
        manifest_from_rom(&m, &ph.cp);
        const char *nm = RNAME(&m);
        RCHECK("placeholder rung -> none", nm && strcmp(nm, "none") == 0);
    }
    /* Rung withdrawn: the same exact bundle is no longer activatable. */
    {
        checkpoints_reset_rom_state_rungs_override_for_test();
        struct consensus_state_bundle_manifest m;
        manifest_from_rom(&m, &rung.cp);
        const char *nm = RNAME(&m);
        RCHECK("no baked rung -> none", nm && strcmp(nm, "none") == 0);
    }
    checkpoints_reset_rom_state_rungs_override_for_test();
#undef RNAME
#undef RCHECK
    return failures;
}

int test_checkpoint_rom_authority(void)
{
    printf("\n=== checkpoint_rom_authority ===\n");
    int failures = 0;

#define CHECK(desc, cond)                                                    \
    do {                                                                     \
        printf("checkpoint_rom_authority: %s... ", (desc));                  \
        if (cond) printf("OK\n");                                            \
        else { printf("FAIL\n"); failures++; }                              \
    } while (0)

    /* Hermetic: clear any override a sibling group may have left installed. */
    checkpoints_reset_rom_state_override_for_test();
    checkpoints_reset_sha3_override_for_test();

    struct rom_state_checkpoint rom;
    synth_rom(&rom, CROM_H);

    /* Zeroed request: no validated-header Sapling root. CHECKPOINT_ROM must not
     * need one; CHECKPOINT_CONTENT (the fallback) would CONTAIN without it. */
    struct consensus_state_activate_request req;
    memset(&req, 0, sizeof(req));

    /* (a) POSITIVE — full component match at the override height activates via
     *     CHECKPOINT_ROM with NO validated header in the request. */
    checkpoints_set_rom_state_override_for_test(&rom);
    {
        struct consensus_state_bundle_manifest m;
        manifest_from_rom(&m, &rom);
        const char *name =
            consensus_state_activate_resolve_content_authority_name_for_test(
                &m, &req);
        CHECK("full component match -> checkpoint_rom (no header needed)",
              name && strcmp(name, "checkpoint_rom") == 0);
    }

    /* (b) NEGATIVE — every single flipped component drops the ROM authority
     *     (fail-closed). With no SHA3 checkpoint at this synthetic height the
     *     content fallback also declines, so the verdict is "none". */
#define FLIP_CHECK(desc, mutate)                                              \
    do {                                                                      \
        struct consensus_state_bundle_manifest m;                             \
        manifest_from_rom(&m, &rom);                                          \
        mutate;                                                               \
        const char *nm =                                                     \
            consensus_state_activate_resolve_content_authority_name_for_test( \
                &m, &req);                                                    \
        CHECK("flipped " desc " -> not activate (none)",                      \
              nm && strcmp(nm, "none") == 0);                                 \
    } while (0)

    FLIP_CHECK("utxo_root", m.utxo_root[0] ^= 0xff);
    FLIP_CHECK("utxo_count", m.utxo_count += 1);
    FLIP_CHECK("total_supply", m.total_supply += 1);
    FLIP_CHECK("anchor_digest", m.anchor_digest[0] ^= 0xff);
    FLIP_CHECK("anchor_count", m.anchor_count += 1);
    FLIP_CHECK("sprout_frontier_root", m.sprout_frontier_root[0] ^= 0xff);
    FLIP_CHECK("sprout_frontier_height", m.sprout_frontier_height += 1);
    FLIP_CHECK("sapling_frontier_root", m.sapling_frontier_root[0] ^= 0xff);
    FLIP_CHECK("sapling_frontier_height", m.sapling_frontier_height += 1);
    FLIP_CHECK("nullifier_digest", m.nullifier_digest[0] ^= 0xff);
    FLIP_CHECK("nullifier_count", m.nullifier_count += 1);

#undef FLIP_CHECK

    /* (c1) HEIGHT MISMATCH — the ROM binding is inert off the checkpoint
     *      height, and with no SHA3 checkpoint here the content fallback
     *      declines too: "none". Proves CHECKPOINT_ROM never false-fires. */
    {
        struct consensus_state_bundle_manifest m;
        manifest_from_rom(&m, &rom);
        m.height = CROM_H + 1000; /* off the ROM checkpoint height */
        const char *nm =
            consensus_state_activate_resolve_content_authority_name_for_test(
                &m, &req);
        CHECK("height mismatch -> ROM inert, falls through to content (none)",
              nm && strcmp(nm, "none") == 0);
    }

    /* (c2) HEIGHT MISMATCH + a matching SHA3 checkpoint + a validated-header
     *      Sapling root -> the CHECKPOINT_CONTENT fallback still activates,
     *      UNCHANGED by the new ROM authority (which is inert off its height). */
    {
        struct consensus_state_bundle_manifest m;
        manifest_from_rom(&m, &rom);
        int32_t cc_h = CROM_H + 1000;
        m.height = cc_h;

        struct sha3_utxo_checkpoint sha3;
        memset(&sha3, 0, sizeof(sha3));
        sha3.height = cc_h;
        memcpy(sha3.block_hash, m.block_hash, 32);
        sha3.utxo_count = m.utxo_count;
        sha3.total_supply = m.total_supply;
        memcpy(sha3.sha3_hash, m.utxo_root, 32);
        checkpoints_set_sha3_override_for_test(&sha3);

        struct consensus_state_activate_request creq = req;
        creq.checkpoint_sapling_root_from_validated_header = true;
        memcpy(creq.checkpoint_sapling_root, m.sapling_frontier_root, 32);

        const char *nm =
            consensus_state_activate_resolve_content_authority_name_for_test(
                &m, &creq);
        CHECK("height mismatch + SHA3 match + header root -> checkpoint_content "
              "(fallback intact)",
              nm && strcmp(nm, "checkpoint_content") == 0);
        checkpoints_reset_sha3_override_for_test();
    }

    /* (d) FAIL-CLOSED — an UNBAKED (placeholder) keystone at the checkpoint
     *     height, matched exactly by the manifest, must NOT activate: an
     *     all-zero shielded fold is not a trust root. Falls through to
     *     content -> "none". */
    {
        struct rom_state_checkpoint ph = rom;
        memset(ph.nullifier_digest, 0, 32); /* unbaked shielded fold */
        checkpoints_set_rom_state_override_for_test(&ph);
        struct consensus_state_bundle_manifest m;
        manifest_from_rom(&m, &ph); /* manifest matches the placeholder exactly */
        const char *nm =
            consensus_state_activate_resolve_content_authority_name_for_test(
                &m, &req);
        CHECK("placeholder (unbaked) keystone -> not activate (none)",
              nm && strcmp(nm, "none") == 0);
    }

    /* (e) ASSISTED above-checkpoint tier. A FRESHEST bundle strictly ABOVE the
     *     compiled checkpoint, admitted by the chain-binding assisted relaxation
     *     (request->assisted_tier), activates via the ASSISTED authority ONLY
     *     when its shielded TIP frontier root is bound to a validated-header
     *     hashFinalSaplingRoot the runtime read at the BUNDLE height. It never
     *     binds the CONTENT below the seam — the tier withholds sovereignty. */
    checkpoints_reset_rom_state_override_for_test();
    {
        int32_t cp_h = CROM_H;
        int32_t bundle_h = cp_h + 500; /* strictly above the checkpoint */
        struct sha3_utxo_checkpoint sha3;
        memset(&sha3, 0, sizeof(sha3));
        sha3.height = cp_h;
        memset(sha3.block_hash, 0xc1, 32);
        sha3.utxo_count = 100;
        memset(sha3.sha3_hash, 0xc2, 32);
        checkpoints_set_sha3_override_for_test(&sha3);

        /* A borrowed above-checkpoint manifest: its coins do NOT reproduce the
         * checkpoint (that is the whole point — it is fresher, unbound content). */
        struct consensus_state_bundle_manifest m;
        memset(&m, 0, sizeof(m));
        m.height = bundle_h;
        m.history_complete = true;
        memset(m.block_hash, 0xab, 32);
        memset(m.utxo_root, 0x99, 32);
        m.utxo_count = 4242;
        memset(m.sapling_frontier_root, 0x77, 32);
        m.sapling_frontier_height = bundle_h - 20;

        struct consensus_state_activate_request areq;
        memset(&areq, 0, sizeof(areq));
        areq.assisted_tier = true;
        areq.assisted_sapling_root_from_validated_header = true;
        memcpy(areq.assisted_sapling_root, m.sapling_frontier_root, 32);
        CHECK("above-checkpoint + assisted_tier + header sapling root -> assisted",
              strcmp(
                  consensus_state_activate_resolve_content_authority_name_for_test(
                      &m, &areq), "assisted") == 0);

        /* assisted_tier off -> the runtime never opted in -> contained. */
        struct consensus_state_activate_request off = areq;
        off.assisted_tier = false;
        CHECK("assisted_tier off -> none",
              strcmp(
                  consensus_state_activate_resolve_content_authority_name_for_test(
                      &m, &off), "none") == 0);

        /* Shielded tip not bound to a validated header -> contained. */
        struct consensus_state_activate_request noheader = areq;
        noheader.assisted_sapling_root_from_validated_header = false;
        CHECK("no validated-header sapling root -> none",
              strcmp(
                  consensus_state_activate_resolve_content_authority_name_for_test(
                      &m, &noheader), "none") == 0);

        /* Header sapling root disagrees with the manifest frontier -> contained. */
        struct consensus_state_activate_request badroot = areq;
        badroot.assisted_sapling_root[0] ^= 0xff;
        CHECK("sapling root mismatch -> none",
              strcmp(
                  consensus_state_activate_resolve_content_authority_name_for_test(
                      &m, &badroot), "none") == 0);

        /* A bundle AT (not above) the checkpoint height is never assisted. */
        struct consensus_state_bundle_manifest at_cp = m;
        at_cp.height = cp_h;
        CHECK("at checkpoint height -> none (assisted is strictly above)",
              strcmp(
                  consensus_state_activate_resolve_content_authority_name_for_test(
                      &at_cp, &areq), "none") == 0);

        /* No compiled checkpoint at all -> no promotion anchor -> contained. */
        checkpoints_reset_sha3_override_for_test();
        CHECK("no compiled checkpoint -> none (assisted needs a promotion anchor)",
              strcmp(
                  consensus_state_activate_resolve_content_authority_name_for_test(
                      &m, &areq), "none") == 0);
    }


    /* (f) baked ladder rungs: activation at a rung height (see above). */
    checkpoints_reset_sha3_override_for_test();
    failures += rung_activation_tests(&rom, &req);
    checkpoints_reset_rom_state_override_for_test();
    checkpoints_reset_sha3_override_for_test();

#undef CHECK

    printf("=== checkpoint_rom_authority: %d failure(s) ===\n", failures);
    return failures;
}
