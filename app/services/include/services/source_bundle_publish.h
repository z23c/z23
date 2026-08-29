/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Make one local C23 workspace FETCHABLE BY ITS CONTENT ROOT — the serve-side
 * half of app/services/src/source_bundle_fetch.c.
 *
 * The gap this closes. `zcode.workspace.source.bundle.create` writes a .zvsb
 * to a scratch path the operator names, and nothing further happens: the file
 * is not where the node seeds artifacts from, the running node's artifact
 * registry has never heard of it, and no directory listing advertises its tree
 * root. So the loop the whole v1 set exists for — edit on machine B, pull on
 * machine A — could not be closed with the commands that existed. `create`
 * produces transport; this produces an OFFER.
 *
 * ── What "published" is allowed to mean ───────────────────────────────
 *
 * Exactly one thing: a peer that asks this node for its artifact directory is
 * told a bundle carrying this tree root exists here, and a chunk request for
 * that artifact is answered. That is a FIND key, not an authority — identical
 * to the rule stated in net/rom_seed.h. Publishing mints no trust and asks for
 * none: no signer, no author key, no acceptance chain, no operator identity
 * and no hardcoded host takes part, and a fetcher still accepts the delivered
 * bytes only because they rederive the root it asked for
 * (vcs_source_bundle_verify against its own 32 bytes).
 *
 * ── Why it never rides the directory sweep ────────────────────────────
 *
 * rom_seed_scan_datadir() walks at most ROM_SEED_SCAN_ENTRY_CAP entries per
 * directory. A busy datadir has more, readdir order is arbitrary, and the walk
 * that stops early cannot know which artifacts it did not reach — so a bundle
 * published through a sweep can sit past the cap and never be offered, with
 * the publisher told nothing. This service therefore registers the artifact BY
 * ITS EXACT NAME (rom_seed_register), which is a stat+open of one known path
 * and cannot be affected by how many other entries share the directory, and
 * then re-reads the registry BY ROOT to prove the offer exists before it
 * reports success. The sweep is never consulted.
 *
 * The residual the sweep still owns is the NEXT BOOT, which re-registers from
 * a walk this service does not control. `rescan_guaranteed` in the report
 * below states that honestly per call rather than leaving the operator to
 * assume durability; it is a fact about the future, never a claim about now.
 *
 * ── Fail-closed ──────────────────────────────────────────────────────
 *
 * Every way this call can end with the bundle NOT being offered is a distinct
 * refusal code, never a success with a caveat: seeding switched off, no file
 * service to dial, a full registry, a registration the registry then does not
 * confirm. SOURCE_BUNDLE_PUBLISH_OK means a chunk request would be answered
 * at the moment of the call, and nothing weaker. */

#ifndef ZCL_SERVICES_SOURCE_BUNDLE_PUBLISH_H
#define ZCL_SERVICES_SOURCE_BUNDLE_PUBLISH_H

#include "net/rom_seed.h"
#include "vcs/source_bundle.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Longest absolute path this service will build or report. */
#define SOURCE_BUNDLE_PUBLISH_PATH_MAX 4400u

enum source_bundle_publish_result {
    SOURCE_BUNDLE_PUBLISH_OK = 0,
    SOURCE_BUNDLE_PUBLISH_ERR_ARGS,        /* null/empty/over-long arguments  */
    SOURCE_BUNDLE_PUBLISH_ERR_WORKSPACE,   /* ZVCS capture refused the tree   */
    SOURCE_BUNDLE_PUBLISH_ERR_ROOT_PIN,    /* captured root != pinned root    */
    SOURCE_BUNDLE_PUBLISH_ERR_BUNDLE,      /* bundle build refused            */
    SOURCE_BUNDLE_PUBLISH_ERR_STORE,       /* could not land it under datadir */
    SOURCE_BUNDLE_PUBLISH_ERR_SEEDING_OFF, /* artifact seeding is disabled    */
    SOURCE_BUNDLE_PUBLISH_ERR_NO_SERVICE,  /* no file service is listening    */
    SOURCE_BUNDLE_PUBLISH_ERR_REGISTRY_FULL,
    SOURCE_BUNDLE_PUBLISH_ERR_REGISTER,    /* registration refused the bytes  */
    SOURCE_BUNDLE_PUBLISH_ERR_NOT_OFFERED, /* registered, registry disagrees  */
};

struct source_bundle_publish_report {
    uint8_t  source_root[32];   /* ZVCS tree root — what the other machine asks for */
    uint8_t  artifact_root[32]; /* rom chunk_root — what a chunk request carries    */
    /* "bundles/<64hex>.zvsb": the datadir-relative name the artifact is
     * registered under, and the exact name rom_seed_read_chunk re-opens. */
    char     filename[ROM_SEED_NAME_MAX];
    char     path[SOURCE_BUNDLE_PUBLISH_PATH_MAX]; /* absolute file on disk   */
    uint64_t wire_bytes;
    uint32_t num_chunks;
    uint16_t file_service_port; /* the port a peer dials to fetch this        */
    /* The identical bundle was already on disk under the same content-derived
     * name, so this call re-offered it rather than writing it. Publishing the
     * same tree twice is a no-op, not an error. */
    bool     republished;
    /* Entries counted in the seeded bundles/ directory, stopping at
     * ROM_SEED_SCAN_ENTRY_CAP + 1 (the walk is bounded like the seeder's). */
    unsigned seed_directory_entries;
    /* False when a future boot-time sweep could stop before reaching this
     * bundle — see the header comment. The sweep is bounded TWICE and the
     * registry is the tighter bound: it walks at most ROM_SEED_SCAN_ENTRY_CAP
     * entries per directory AND stops the moment it holds
     * ROM_SEED_MAX_ARTIFACTS artifacts, filling those slots in arbitrary
     * readdir order across the datadir root and bundles/. So this is true only
     * when every classifying entry in BOTH locations fits the registry, not
     * merely when the walk is short enough. Never affects whether this call is
     * serving the bundle NOW. */
    bool     rescan_guaranteed;
    struct vcs_source_bundle_metrics bundle;
};

/* Capture `workspace` into its own ZVCS CAS, build the compressed bundle for
 * the captured tree root, land it under `<datadir>/bundles/<root>.zvsb`, and
 * register + announce it so this node answers for it immediately — no restart,
 * no directory sweep.
 *
 * `pinned_root`, when non-NULL, is the caller's commitment to WHICH tree it
 * believes it is publishing: the captured root must equal it or the call is
 * refused before a byte is written. Pass NULL to publish whatever the
 * workspace currently is.
 *
 * `report` is zeroed on entry and is only meaningful on
 * SOURCE_BUNDLE_PUBLISH_OK, which is returned if and only if the registry
 * confirms, by root, that the artifact is offered. */
enum source_bundle_publish_result source_bundle_publish(
    const char *workspace, const char *datadir, const uint8_t *pinned_root,
    struct source_bundle_publish_report *report);

/* Stable human label for a result code. Never NULL. */
const char *source_bundle_publish_result_string(
    enum source_bundle_publish_result result);

#endif /* ZCL_SERVICES_SOURCE_BUNDLE_PUBLISH_H */
