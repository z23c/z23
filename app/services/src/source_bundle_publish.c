/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: make one local C23 workspace fetchable by its content root, with no
 * signer, no author key and no hardcoded host. */

// one-result-type-ok:typed-refusal-enum-carries-more-than-a-message — the one
// fallible entry point returns enum source_bundle_publish_result rather than
// struct zcl_result, mirroring its serve-side twin source_bundle_fetch(). The
// gate exists so a failure reason cannot be lost; here every value is closed,
// has a stable string (source_bundle_publish_result_string) and a LOG line,
// and the values that matter are pinned by name in
// lib/test/src/test_source_bundle_publish.c — so a regression that turned "the
// registry never confirmed the offer" into "the bundle could not be written"
// fails the suite instead of reading plausibly in a log.

/* The serve-side half of identity-free source transport — see
 * services/source_bundle_publish.h for the contract, the trust rule and the
 * reason this never rides the bounded directory sweep.
 *
 * WHAT IS REUSED, and it is everything that matters. The tree is captured by
 * the ordinary ZVCS capture (vcs_tree_capture_path), the transport is the
 * ordinary bundle (vcs_source_bundle_create), the file lands in the ONE
 * datadir subdirectory the seeder already reaches into
 * (ROM_SEED_BUNDLES_SUBDIR), and it is offered through the ordinary free-tier
 * artifact registry (rom_seed_register) and the ordinary price-0 market offer.
 * No new wire message, no new listening port, no new file format and no second
 * catalog exist because of this file.
 *
 * WHAT IS NEW is one ordering decision and one proof:
 *
 *   ORDERING — the artifact is registered BY NAME, never found by a walk. A
 *   directory sweep is bounded (ROM_SEED_SCAN_ENTRY_CAP) and its order is
 *   arbitrary, so "it is in the seeded directory" and "it is being offered"
 *   are different claims. Only the second one is worth reporting, and only a
 *   by-name registration can make it true independently of the neighbours.
 *
 *   PROOF — after registering, the registry is re-read BY ROOT
 *   (rom_seed_find_by_root) and the artifact it hands back must carry the
 *   source root this call captured. Success is that read, not the return value
 *   of the write that preceded it. A publisher is never told "published" on
 *   the strength of its own optimism.
 *
 * The bundle bytes are content-addressed by the tree root they commit to, so
 * publishing the same tree twice is a no-op that re-offers the existing file
 * rather than an error or a second copy. A DIFFERENT byte sequence under that
 * name is impossible unless the file was tampered with, and is refused. */

#include "services/source_bundle_publish.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "net/file_market.h"
#include "net/file_service.h"
#include "net/rom_seed.h"
#include "platform/directory_compat.h"
#include "platform/positioned_file.h"
#include "platform/private_file.h"
#include "util/safe_alloc.h"
#include "vcs/vcs.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SBP_SUBSYS "source_bundle_publish"

/* "<64hex>.zvsb" plus the staging suffix must both fit ROM_SEED_NAME_MAX with
 * the "bundles/" prefix, or the artifact could be written under a name the
 * seeder cannot register. Assert it here rather than discover it at runtime:
 * 8 ("bundles/") + 64 + 5 (".zvsb") + 5 (".part") = 82. */
#define SBP_LEAF_MAX 96u
_Static_assert(sizeof(ROM_SEED_BUNDLES_SUBDIR) - 1u + SBP_LEAF_MAX <
                   ROM_SEED_NAME_MAX,
               "a published bundle's registered name must fit the registry");

const char *source_bundle_publish_result_string(
    enum source_bundle_publish_result result)
{
    switch (result) {
    case SOURCE_BUNDLE_PUBLISH_OK:            return "ok";
    case SOURCE_BUNDLE_PUBLISH_ERR_ARGS:      return "arguments";
    case SOURCE_BUNDLE_PUBLISH_ERR_WORKSPACE: return "workspace-capture";
    case SOURCE_BUNDLE_PUBLISH_ERR_ROOT_PIN:  return "source-root-pin";
    case SOURCE_BUNDLE_PUBLISH_ERR_BUNDLE:    return "bundle-create";
    case SOURCE_BUNDLE_PUBLISH_ERR_STORE:     return "seed-directory-write";
    case SOURCE_BUNDLE_PUBLISH_ERR_SEEDING_OFF: return "seeding-disabled";
    case SOURCE_BUNDLE_PUBLISH_ERR_NO_SERVICE:  return "no-file-service";
    case SOURCE_BUNDLE_PUBLISH_ERR_REGISTRY_FULL: return "registry-full";
    case SOURCE_BUNDLE_PUBLISH_ERR_REGISTER:    return "registration-refused";
    case SOURCE_BUNDLE_PUBLISH_ERR_NOT_OFFERED: return "not-offered";
    }
    return "unknown";
}

/* ── Landing the bundle in the seeded directory ──────────────────────── */

/* Read `path` whole, bounded by the transport's own wire ceiling. Returns NULL
 * (and *len_out = 0) for an absent, unreadable, empty or over-large file —
 * every one of which means "there is no identical bundle already here". */
enum sbp_read_result { SBP_READ_ABSENT, SBP_READ_OK, SBP_READ_ERROR };

static enum sbp_read_result sbp_read_whole(const char *path,
                                            uint8_t **bytes_out,
                                            size_t *len_out)
{
    *bytes_out = NULL;
    *len_out = 0;
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path))
        return SBP_READ_ABSENT;
    if (!platform_positioned_file_snapshot(&file, &before) ||
        before.size == 0 || before.size > VCS_SOURCE_BUNDLE_MAX_WIRE_BYTES) {
        platform_positioned_file_close(&file);
        return SBP_READ_ERROR;
    }
    size_t len = (size_t)before.size;
    uint8_t *bytes = zcl_malloc(len, "source_bundle_publish.readback");
    if (!bytes) {
        platform_positioned_file_close(&file);
        return SBP_READ_ERROR;
    }
    size_t off = 0;
    while (off < len) {
        int64_t got = platform_positioned_file_read(&file, bytes + off,
                                                    len - off, off);
        if (got <= 0) break;
        off += (size_t)got;
    }
    bool ok = off == len && platform_positioned_file_snapshot(&file, &after) &&
        platform_positioned_file_snapshot_equal(&before, &after);
    platform_positioned_file_close(&file);
    if (!ok) {
        free(bytes);
        return SBP_READ_ERROR;
    }
    *bytes_out = bytes;
    *len_out = len;
    return SBP_READ_OK;
}

/* Stage the wire beside its destination and replace it in one step, so the
 * seeded directory never holds a partially written file under the name the
 * registry will open. The staging leaf is derived from the same content root,
 * and is opened with a WAITING exclusive lock: two processes publishing the
 * identical tree at once serialize instead of one of them failing. */
static bool sbp_write_atomic(const char *staging, const char *final_path,
                             const uint8_t *wire, size_t wire_len)
{
    struct platform_private_file staged;
    platform_private_file_init(&staged);
    if (!platform_private_file_open_locked_create_wait(staging, &staged))
        LOG_FAIL(SBP_SUBSYS, "could not stage '%s'", staging);
    bool ok = platform_private_file_truncate(&staged, 0) &&
        platform_private_file_write_at(&staged, wire, wire_len, 0) &&
        platform_private_file_flush(&staged) &&
        platform_private_file_replace(&staged, staging, final_path);
    if (!ok)
        (void)platform_private_file_retire(&staged, staging);
    platform_private_file_close(&staged);
    if (!ok)
        LOG_FAIL(SBP_SUBSYS, "could not publish '%s'", final_path);
    return ok;
}

/* Count entries in one directory the same bounded way rom_seed's own sweep
 * does, stopping one past the cap, and separately count the entries that
 * CLASSIFY as an artifact — the ones that will contend for a registry slot.
 * The answers are only used to tell the operator whether a FUTURE boot-time
 * sweep is guaranteed to reach this bundle; they never decide whether this
 * call serves it. An unopenable directory reports 0 of each, which is the
 * honest "nothing here is crowding it". */
static unsigned sbp_seed_dir_entries(const char *dirpath,
                                     unsigned *artifacts_out)
{
    if (artifacts_out)
        *artifacts_out = 0;
    DIR *d = opendir(dirpath);
    if (!d)
        return 0;
    unsigned seen = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        seen++;
        if (seen > ROM_SEED_SCAN_ENTRY_CAP)
            break;
        if (artifacts_out &&
            rom_seed_classify(e->d_name) != ROM_ARTIFACT_UNKNOWN)
            (*artifacts_out)++;
    }
    closedir(d);
    return seen;
}

/* ── The one entry point ─────────────────────────────────────────────── */

enum source_bundle_publish_result source_bundle_publish(
    const char *workspace, const char *datadir, const uint8_t *pinned_root,
    struct source_bundle_publish_report *report)
{
    if (!report)
        return SOURCE_BUNDLE_PUBLISH_ERR_ARGS;
    memset(report, 0, sizeof(*report));
    if (!workspace || !workspace[0] || !datadir || !datadir[0])
        return SOURCE_BUNDLE_PUBLISH_ERR_ARGS;

    /* Refuse before doing any work when the result could not be served
     * anyway. Both of these are node posture, not caller error, and both are
     * their own code so the operator is told which switch to reach for. */
    if (!rom_seed_enabled()) {
        LOG_WARN(SBP_SUBSYS, "publish refused: artifact seeding is disabled");
        return SOURCE_BUNDLE_PUBLISH_ERR_SEEDING_OFF;
    }
    if (!fs_server_is_running()) {
        LOG_WARN(SBP_SUBSYS,
                 "publish refused: no file service is listening, so no peer "
                 "could fetch what this would register");
        return SOURCE_BUNDLE_PUBLISH_ERR_NO_SERVICE;
    }

    /* The workspace's own ZVCS capture is the sole source of the root. A
     * caller-supplied root is a PIN on that answer, never a substitute for
     * it. */
    uint8_t root[32];
    if (vcs_tree_capture_path(workspace, root) != VCS_OK) {
        LOG_WARN(SBP_SUBSYS, "publish refused: ZVCS capture refused '%s'",
                 workspace);
        return SOURCE_BUNDLE_PUBLISH_ERR_WORKSPACE;
    }
    if (pinned_root && memcmp(pinned_root, root, 32) != 0) {
        LOG_WARN(SBP_SUBSYS,
                 "publish refused: the captured tree is not the pinned root");
        return SOURCE_BUNDLE_PUBLISH_ERR_ROOT_PIN;
    }

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    struct vcs_source_bundle_metrics metrics;
    enum vcs_source_bundle_result made =
        vcs_source_bundle_create(workspace, root, &wire, &wire_len, &metrics);
    if (made != VCS_SOURCE_BUNDLE_OK) {
        free(wire);
        LOG_WARN(SBP_SUBSYS, "publish refused: bundle create said '%s'",
                 vcs_source_bundle_result_string(made));
        return SOURCE_BUNDLE_PUBLISH_ERR_BUNDLE;
    }

    char root_hex[65];
    zcl_hex_encode(root, 32, root_hex);

    char seed_dir[SOURCE_BUNDLE_PUBLISH_PATH_MAX];
    char final_path[SOURCE_BUNDLE_PUBLISH_PATH_MAX];
    char staging[SOURCE_BUNDLE_PUBLISH_PATH_MAX];
    char relname[ROM_SEED_NAME_MAX];
    int dn = snprintf(seed_dir, sizeof(seed_dir), "%s/%s", datadir,
                      ROM_SEED_BUNDLES_SUBDIR);
    int fn = snprintf(final_path, sizeof(final_path), "%s/%s%s", seed_dir,
                      root_hex, ROM_SEED_SOURCE_BUNDLE_SUFFIX);
    int sn = snprintf(staging, sizeof(staging), "%s/%s%s.part", seed_dir,
                      root_hex, ROM_SEED_SOURCE_BUNDLE_SUFFIX);
    int rn = snprintf(relname, sizeof(relname), "%s/%s%s",
                      ROM_SEED_BUNDLES_SUBDIR, root_hex,
                      ROM_SEED_SOURCE_BUNDLE_SUFFIX);
    if (dn <= 0 || (size_t)dn >= sizeof(seed_dir) ||
        fn <= 0 || (size_t)fn >= sizeof(final_path) ||
        sn <= 0 || (size_t)sn >= sizeof(staging) ||
        rn <= 0 || (size_t)rn >= sizeof(relname) ||
        !platform_directory_ensure(seed_dir, 0700)) {
        free(wire);
        LOG_WARN(SBP_SUBSYS, "publish refused: seeded directory '%s' unusable",
                 seed_dir);
        return SOURCE_BUNDLE_PUBLISH_ERR_STORE;
    }

    /* Content-addressed name: an existing file under it is either this exact
     * bundle (a republish, which is a no-op) or something that must not be
     * silently overwritten. */
    size_t present_len = 0;
    uint8_t *present = NULL;
    enum sbp_read_result read_result =
        sbp_read_whole(final_path, &present, &present_len);
    if (read_result == SBP_READ_ERROR) {
        free(wire);
        LOG_WARN(SBP_SUBSYS, "publish refused: existing '%s' could not be "
                 "verified and was not overwritten", final_path);
        return SOURCE_BUNDLE_PUBLISH_ERR_STORE;
    }
    bool republished = present && present_len == wire_len &&
        memcmp(present, wire, wire_len) == 0;
    bool foreign = present && !republished;
    free(present);
    if (foreign) {
        free(wire);
        LOG_WARN(SBP_SUBSYS,
                 "publish refused: '%s' already holds different bytes under "
                 "this content root and was not overwritten", final_path);
        return SOURCE_BUNDLE_PUBLISH_ERR_STORE;
    }
    if (!republished && !sbp_write_atomic(staging, final_path, wire, wire_len)) {
        free(wire);
        return SOURCE_BUNDLE_PUBLISH_ERR_STORE;
    }
    free(wire);

    /* BY NAME, never by a walk — the whole point of this module. Registration
     * re-derives every digest from the bytes now on disk, so what gets offered
     * is what a peer will actually receive. */
    struct rom_artifact art;
    enum rom_register_result rr =
        rom_seed_register(datadir, relname, NULL, &art);
    if (rr != ROM_REG_OK) {
        LOG_WARN(SBP_SUBSYS,
                 "publish refused: registering '%s' returned %d", relname,
                 (int)rr);
        return rr == ROM_REG_ERR_FULL
            ? SOURCE_BUNDLE_PUBLISH_ERR_REGISTRY_FULL
            : SOURCE_BUNDLE_PUBLISH_ERR_REGISTER;
    }

    /* Announce the price-0 offer with the port a peer would actually dial. The
     * ROM directory listing is what the fetcher reads, so this is redundancy
     * for the gossip/market view rather than the discovery path itself — but
     * an offer carrying port 0 would be an advertisement nobody can act on. */
    uint16_t fs_port = fs_server_get_port();
    struct file_offer offer;
    uint8_t self_ip[16] = {0};
    if (rom_seed_build_offer(&art, self_ip, fs_port, &offer))
        (void)file_market_add_offer(&offer);

    /* THE proof. Ask the registry, by the root a peer would ask for, whether
     * this artifact is offered — and require the answer to carry the source
     * root this call captured. Anything else is reported as a failure to
     * publish, never as a success with a note. */
    struct rom_artifact offered;
    if (!rom_seed_find_by_root(art.chunk_root, &offered) ||
        !offered.has_source_root ||
        memcmp(offered.source_root, root, 32) != 0 ||
        offered.kind != ROM_ARTIFACT_SOURCE_BUNDLE) {
        LOG_WARN(SBP_SUBSYS,
                 "publish refused: the registry did not confirm '%s' as an "
                 "offered source bundle after registering it", relname);
        return SOURCE_BUNDLE_PUBLISH_ERR_NOT_OFFERED;
    }

    memcpy(report->source_root, root, 32);
    memcpy(report->artifact_root, offered.chunk_root, 32);
    snprintf(report->filename, sizeof(report->filename), "%s", relname);
    snprintf(report->path, sizeof(report->path), "%s", final_path);
    report->wire_bytes = offered.size_bytes;
    report->num_chunks = offered.num_chunks;
    report->file_service_port = fs_port;
    report->republished = republished;
    /* A boot sweep is bounded TWICE, and the tighter bound is the registry,
     * not the walk: rom_seed_scan_datadir() stops after
     * ROM_SEED_SCAN_ENTRY_CAP entries per directory, but it also `break`s the
     * moment the registry holds ROM_SEED_MAX_ARTIFACTS — three orders of
     * magnitude sooner — and it fills those slots in arbitrary readdir order
     * across the datadir root AND bundles/. So promising the sweep on entry
     * count alone is a promise a synced node with a header seed and a full
     * shelf of bundles cannot keep. Both directories are counted, and every
     * classifying entry in either of them is a slot contender. */
    unsigned seed_artifacts = 0, root_artifacts = 0;
    report->seed_directory_entries =
        sbp_seed_dir_entries(seed_dir, &seed_artifacts);
    unsigned root_entries = sbp_seed_dir_entries(datadir, &root_artifacts);
    report->rescan_guaranteed =
        report->seed_directory_entries <= ROM_SEED_SCAN_ENTRY_CAP &&
        root_entries <= ROM_SEED_SCAN_ENTRY_CAP &&
        (uint64_t)root_artifacts + (uint64_t)seed_artifacts <=
            (uint64_t)ROM_SEED_MAX_ARTIFACTS;
    report->bundle = metrics;
    if (!report->rescan_guaranteed)
        LOG_WARN(SBP_SUBSYS,
                 "'%s' is being offered now, but a boot-time sweep of '%s' is "
                 "not guaranteed to reach it (%u entries / %u artifacts here, "
                 "%u entries / %u artifacts in the datadir root; the sweep "
                 "walks at most %u entries per directory and registers at most "
                 "%u artifacts in all) — re-run publish after a restart",
                 relname, seed_dir, report->seed_directory_entries,
                 seed_artifacts, root_entries, root_artifacts,
                 (unsigned)ROM_SEED_SCAN_ENTRY_CAP,
                 (unsigned)ROM_SEED_MAX_ARTIFACTS);
    LOG_INFO(SBP_SUBSYS, "offering source root %s as '%s' on port %u",
             root_hex, relname, (unsigned)fs_port);
    return SOURCE_BUNDLE_PUBLISH_OK;
}
