/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: pull a ZVCS source bundle from peers by its content root, with no
 * signer, no acceptance chain and no hardcoded host. */

// one-result-type-ok:typed-refusal-enum-carries-more-than-a-message — the one
// fallible entry point returns enum source_bundle_fetch_result rather than
// struct zcl_result, and for this surface that is the stronger shape. The gate
// exists so a failure reason cannot be lost; here it is carried THREE ways: a
// closed enum whose every value has a stable string
// (source_bundle_fetch_result_string), a LOG line on every failing path, and
// struct source_bundle_fetch_metrics.last_refusal, which reports the CONTENT
// check's own verdict so "tree-root-mismatch" (a substitution) never collapses
// into "bundle-limit" (a truncation) or "compression-codec" (garbage). A
// free-form message cannot be asserted on; lib/test/src/
// test_source_bundle_fetch.c pins exact enum values, so a regression that
// turned a substitution refusal into a transport failure fails the suite
// instead of reading plausibly in a log.

/* Identity-free P2P retrieval of a ZVCS source bundle by its content root —
 * see services/source_bundle_fetch.h for the contract, the trust model and the
 * time bound. This file is the search + download + prove loop.
 *
 * WHAT IS REUSED, and it is nearly everything. The bytes ride the existing ROM
 * artifact transport unchanged: rom_fetch_get_directory (discovery),
 * rom_fetch_get_manifest (per-chunk digests, folded against the artifact's own
 * chunk_root before they are trusted as a download plan),
 * rom_fetch_download_verified_parallel (per-chunk content check before a
 * journal bit is set, round-robin failover across peers, durable resume,
 * atomic install) and rom_peer_note_bad_chunk — which RECORDS the offence and
 * logs it, but see sbf_note_substitution: nothing in production reads that
 * list back, so it does not change who is asked next.
 * The serve side is the ordinary free-tier ROM path with its per-peer
 * concurrency and byte-rate caps. Nothing new was invented on the wire, and no
 * new listening port exists.
 *
 * WHAT IS DELIBERATELY NOT REUSED: the package/carrier route
 * (lib/vcs/src/package_swarm*.c, source_package_checkout.c). It solves a
 * different problem well — a signed, accepted, authority-resolved release —
 * and every one of those properties is an identity requirement. Reaching for
 * it here would have made "any machine with a 64-hex root" false again. So its
 * acceptance layer is not imported, not linked, and not consulted: no
 * accepted_work_root, no signer derivation, no PROVEN re-resolution, no
 * package store. This module's ONLY acceptance predicate is
 * vcs_source_bundle_verify() against the caller's own root.
 *
 * WHY THE OUTPUT PATH IS ABSENT FROM THIS FILE. The verified wire is returned
 * in memory and the caller commits it. That is not a style choice: it makes
 * "never partially materialize" structural rather than a cleanup obligation.
 * There is no code path here — success, refusal, transport failure, budget
 * exhaustion or crash — that can create the caller's output file, because this
 * file has never been told its name. */

#include "services/source_bundle_fetch.h"

#include "base/log_macros.h"
#include "encoding/utilstrencodings.h"
#include "net/rom_peer_scoring.h"
#include "net/rom_seed.h"
#include "platform/positioned_file.h"
#include "platform/time_compat.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SBF_SUBSYS "source_bundle_fetch"

/* Room for "<staging_dir>/<name>" plus the ".part.journal" the download layer
 * appends; the download layer's own path buffers are 1200/1264, so a staging
 * directory that fits here fits there. */
#define SBF_PATH_MAX 1024

/* Directory-listing reply buffer. The serve side bounds its own body at
 * FS_ROM_LIST_ARTS_MAX + 64 (lib/net/src/file_service.c); this is comfortably
 * over that, and rom_fetch_get_directory refuses anything at or over the cap
 * rather than truncating. */
#define SBF_DIRECTORY_MAX 8192

/* One artifact several peers may all be offering. Peers are grouped by
 * chunk_root so that honest replicas of the same bundle become FAILOVER for a
 * single download, while a genuinely different byte sequence claiming the same
 * source root becomes a separate candidate that must be refused on its own. */
struct sbf_candidate {
    struct rom_fetch_manifest manifest;
    struct rom_fetch_peer peers[SOURCE_BUNDLE_FETCH_MAX_PEERS];
    size_t npeers;
};

const char *source_bundle_fetch_result_string(
    enum source_bundle_fetch_result result)
{
    switch (result) {
    case SOURCE_BUNDLE_FETCH_OK:            return "ok";
    case SOURCE_BUNDLE_FETCH_ERR_ARGS:      return "bad-arguments";
    case SOURCE_BUNDLE_FETCH_ERR_NO_PEER:   return "no-peer-offers-this-root";
    case SOURCE_BUNDLE_FETCH_ERR_TRANSPORT: return "no-candidate-delivered";
    case SOURCE_BUNDLE_FETCH_ERR_ROOT:      return "tree-root-mismatch";
    case SOURCE_BUNDLE_FETCH_ERR_STAGING:   return "staging-unreadable";
    case SOURCE_BUNDLE_FETCH_ERR_ALLOC:     return "allocation";
    case SOURCE_BUNDLE_FETCH_ERR_BUDGET:    return "time-budget-spent";
    }
    return "unknown";
}

/* True while the whole-call budget still has room. Consulted only BETWEEN
 * network operations — see the bound in the header. */
static bool sbf_budget_left(int64_t start_us)
{
    int64_t spent = platform_time_monotonic_us() - start_us;
    return spent >= 0 &&
           spent < (int64_t)SOURCE_BUNDLE_FETCH_BUDGET_MS * INT64_C(1000);
}

/* Remove every file the download layer may have left under `staging_dir` for
 * `name`: the staged-complete file, its .part and the .part.journal. Called on
 * EVERY path out of a candidate attempt, so a refused candidate leaves the
 * staging directory exactly as it found it and cannot seed a later resume. */
static void sbf_staging_clear(const char *staging_dir, const char *name)
{
    char path[SBF_PATH_MAX + 64];
    if (snprintf(path, sizeof(path), "%s/%s", staging_dir, name) > 0)
        (void)remove(path);
    if (snprintf(path, sizeof(path), "%s/%s%s", staging_dir, name,
                 ROM_FETCH_PART_SUFFIX) > 0)
        (void)remove(path);
    if (snprintf(path, sizeof(path), "%s/%s%s.journal", staging_dir, name,
                 ROM_FETCH_PART_SUFFIX) > 0)
        (void)remove(path);
}

/* Read the staged bundle back into memory, refusing anything whose size does
 * not match what the download layer just installed. The size is re-read from
 * the file itself and re-checked after the read, so a concurrent writer cannot
 * hand back a torn buffer. */
static uint8_t *sbf_read_staged(const char *path, uint64_t expect_bytes,
                                size_t *len_out)
{
    *len_out = 0;
    if (expect_bytes == 0 || expect_bytes > VCS_SOURCE_BUNDLE_MAX_WIRE_BYTES ||
        expect_bytes > SIZE_MAX)
        return NULL;
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path) ||
        !platform_positioned_file_snapshot(&file, &before) ||
        before.size != expect_bytes) {
        platform_positioned_file_close(&file);
        return NULL;
    }
    size_t len = (size_t)expect_bytes;
    uint8_t *bytes = zcl_malloc(len, "services.source_bundle_fetch.wire");
    if (!bytes) {
        platform_positioned_file_close(&file);
        return NULL;
    }
    size_t off = 0;
    while (off < len) {
        int64_t got = platform_positioned_file_read(&file, bytes + off,
                                                    len - off, off);
        if (got <= 0)
            break;
        off += (size_t)got;
    }
    bool ok = off == len &&
              platform_positioned_file_snapshot(&file, &after) &&
              platform_positioned_file_snapshot_equal(&before, &after);
    platform_positioned_file_close(&file);
    if (!ok) {
        free(bytes);
        return NULL;
    }
    *len_out = len;
    return bytes;
}

/* Fold one advertised artifact into the candidate set: append the peer to an
 * existing candidate with the same chunk_root, else open a new one. Returns
 * false only when both bounds are already full — a full set is not an error,
 * it is the cap doing its job. */
static bool sbf_candidate_add(struct sbf_candidate *cands, size_t *ncands,
                              const struct rom_fetch_manifest *m,
                              const struct rom_fetch_peer *peer)
{
    for (size_t i = 0; i < *ncands; i++) {
        if (memcmp(cands[i].manifest.chunk_root, m->chunk_root, 32) != 0)
            continue;
        if (cands[i].npeers >= SOURCE_BUNDLE_FETCH_MAX_PEERS)
            return false;
        /* Same peer twice (a seeder listing one artifact under two names) is
         * harmless but wastes a failover slot. */
        for (size_t p = 0; p < cands[i].npeers; p++)
            if (cands[i].peers[p].port == peer->port &&
                strcmp(cands[i].peers[p].addr, peer->addr) == 0)
                return true;
        cands[i].peers[cands[i].npeers++] = *peer;
        return true;
    }
    if (*ncands >= SOURCE_BUNDLE_FETCH_MAX_CANDIDATES)
        return false;
    struct sbf_candidate *c = &cands[(*ncands)++];
    memset(c, 0, sizeof(*c));
    c->manifest = *m;
    c->peers[0] = *peer;
    c->npeers = 1;
    return true;
}

/* Ask one peer what it seeds and record every artifact advertising
 * `source_root`. Returns true if this peer offered at least one. Everything
 * read here is an untrusted claim used only to choose what to download. */
static bool sbf_discover_peer(const struct rom_fetch_peer *peer,
                              const uint8_t source_root[32],
                              struct sbf_candidate *cands, size_t *ncands)
{
    char body[SBF_DIRECTORY_MAX];
    if (!rom_fetch_get_directory(peer->addr, peer->port, body, sizeof(body)))
        return false; // raw-return-ok:rom_fetch_get_directory already logged the
                      // named per-peer reason (connect/handshake/MAC/size-cap);
                      // an unreachable or silent seeder is the ORDINARY case
                      // here and a second line per peer would bury the real one

    struct rom_fetch_manifest arts[ROM_FETCH_MAX_ARTIFACTS];
    memset(arts, 0, sizeof(arts));
    int n = rom_fetch_parse_directory(body, arts, ROM_FETCH_MAX_ARTIFACTS);
    bool offered = false;
    for (int i = 0; i < n; i++) {
        if (arts[i].kind != ROM_ARTIFACT_SOURCE_BUNDLE ||
            !arts[i].has_source_root ||
            memcmp(arts[i].source_root, source_root, 32) != 0)
            continue;
        /* Refuse an offer this build could not accept anyway, BEFORE spending
         * a connection on it: a bundle over the wire cap can never pass
         * vcs_source_bundle_verify, and its chunk count bounds the fixed
         * digest table below. */
        if (arts[i].size_bytes > VCS_SOURCE_BUNDLE_MAX_WIRE_BYTES ||
            arts[i].num_chunks > SOURCE_BUNDLE_FETCH_MAX_CHUNKS)
            continue;
        offered = true;
        (void)sbf_candidate_add(cands, ncands, &arts[i], peer);
    }
    return offered;
}

/* Download one candidate and hand back its bytes UNVERIFIED-BY-ROOT. Every
 * transport-level check has passed at this point (per-chunk digests folded to
 * the artifact's chunk_root, whole-file digest, atomic install); the root check
 * is the caller's next step and the only one that decides acceptance. */
static uint8_t *sbf_download_candidate(const struct sbf_candidate *c,
                                       const char *staging_dir,
                                       size_t *len_out)
{
    *len_out = 0;

    /* WE name the staging file, never the peer. rom_fetch_download_verified*
     * would otherwise synthesize a name from the peer-supplied chunk_root and
     * write it into a directory the caller owns. Deriving it from chunk_root
     * ourselves keeps concurrent candidates from colliding while keeping the
     * whole path caller-controlled; the ".stage" suffix keeps a scratch
     * directory from ever classifying as a seedable ".zvsb". */
    char stem[17];
    HexStr(c->manifest.chunk_root, 8, false, stem, sizeof(stem));
    char name[ROM_FETCH_NAME_MAX];
    if (snprintf(name, sizeof(name), "zvsb-stage-%s.stage", stem) <= 0)
        return NULL;

    struct rom_fetch_manifest m = c->manifest;
    snprintf(m.filename, sizeof(m.filename), "%s", name);

    sbf_staging_clear(staging_dir, name);

    uint8_t chunk_sha3[SOURCE_BUNDLE_FETCH_MAX_CHUNKS][32];
    uint32_t num_chunks = 0;
    bool have_plan = false;
    for (size_t p = 0; p < c->npeers && !have_plan; p++) {
        have_plan = rom_fetch_get_manifest(
            c->peers[p].addr, c->peers[p].port, m.chunk_root, chunk_sha3,
            SOURCE_BUNDLE_FETCH_MAX_CHUNKS, &num_chunks);
        /* rom_fetch_parse_manifest_blob already required these digests to fold
         * to chunk_root, so a peer cannot hand out a plan for other bytes. A
         * plan whose length disagrees with the advertised layout is that same
         * peer contradicting itself — try the next one. */
        if (have_plan && num_chunks != m.num_chunks)
            have_plan = false;
    }
    if (!have_plan) {
        LOG_INFO(SBF_SUBSYS, "no peer served a per-chunk plan for candidate "
                 "%s — abandoning it", stem);
        return NULL;
    }

    if (!rom_fetch_download_verified_parallel(c->peers, c->npeers, &m,
                                              chunk_sha3, num_chunks,
                                              staging_dir, NULL, NULL)) {
        sbf_staging_clear(staging_dir, name);
        return NULL;
    }

    char staged[SBF_PATH_MAX + 64];
    uint8_t *wire = NULL;
    if (snprintf(staged, sizeof(staged), "%s/%s", staging_dir, name) > 0)
        wire = sbf_read_staged(staged, m.size_bytes, len_out);
    sbf_staging_clear(staging_dir, name);
    return wire;
}

/* Score every peer that stood behind a candidate the root check refused. They
 * all advertised these exact bytes under a root the bytes do not carry, so the
 * offence is theirs jointly; the deprioritize list is bounded and expires.
 *
 * WHAT THIS DOES NOT DO, stated so nobody reads more into it. The list this
 * writes (lib/net/src/rom_peer_scoring.c) is WRITE-ONLY in production:
 * rom_peer_is_deprioritized() — whose own header calls it "query helper for
 * the fetch scheduler" — is called by no production translation unit, only by
 * the chaos harness and tests. So this records and logs the offence; it does
 * NOT stop the same peer being asked first again on the very next call, and
 * the per-chunk `poisoned` mask in rf_ver_acquire_chunk is scoped to one chunk
 * of one download. Treat this as evidence, not as scheduling pressure. */
static void sbf_note_substitution(const struct sbf_candidate *c)
{
    for (size_t p = 0; p < c->npeers; p++)
        (void)rom_peer_note_bad_chunk(c->peers[p].addr, c->peers[p].port, 0,
                                      "source-root-mismatch");
}

enum source_bundle_fetch_result source_bundle_fetch(
    const struct rom_fetch_peer *peers, size_t npeers,
    const uint8_t source_root[32], const char *staging_dir,
    uint8_t **wire_out, size_t *wire_len_out,
    struct source_bundle_fetch_metrics *metrics)
{
    if (wire_out) *wire_out = NULL;
    if (wire_len_out) *wire_len_out = 0;
    if (metrics) memset(metrics, 0, sizeof(*metrics));

    if (!peers || npeers == 0 || npeers > SOURCE_BUNDLE_FETCH_MAX_PEERS ||
        !source_root || !staging_dir || !staging_dir[0] || !wire_out ||
        !wire_len_out || strlen(staging_dir) >= SBF_PATH_MAX)
        LOG_RETURN(SOURCE_BUNDLE_FETCH_ERR_ARGS, SBF_SUBSYS,
                   "bad arguments (peers=%zu staging_dir=%s)", npeers,
                   staging_dir ? staging_dir : "(null)");

    int64_t start_us = platform_time_monotonic_us();
    struct sbf_candidate cands[SOURCE_BUNDLE_FETCH_MAX_CANDIDATES];
    size_t ncands = 0;
    uint32_t asked = 0, offering = 0;

    for (size_t i = 0; i < npeers; i++) {
        if (!peers[i].addr[0] || peers[i].port == 0)
            continue;
        if (!sbf_budget_left(start_us))
            break;
        asked++;
        if (sbf_discover_peer(&peers[i], source_root, cands, &ncands))
            offering++;
    }
    if (metrics) {
        metrics->peers_asked = asked;
        metrics->peers_offering = offering;
    }

    if (ncands == 0) {
        /* A NAMED refusal, never a hang: nobody advertised this root. The
         * caller learns "not found here", which is a different fact from
         * "found and refused" and must stay distinguishable. */
        LOG_INFO(SBF_SUBSYS, "no peer of %u asked advertises the requested "
                 "source root", asked);
        return sbf_budget_left(start_us) ? SOURCE_BUNDLE_FETCH_ERR_NO_PEER
                                         : SOURCE_BUNDLE_FETCH_ERR_BUDGET;
    }

    /* Offers exist, so from here a failure is TRANSPORT (nothing arrived) or
     * ROOT (bytes arrived and were refused). ROOT outranks TRANSPORT: once a
     * candidate has been proven wrong, that is the more precise answer. */
    enum source_bundle_fetch_result result = SOURCE_BUNDLE_FETCH_ERR_TRANSPORT;
    uint32_t tried = 0, refused = 0;
    enum vcs_source_bundle_result last_refusal = VCS_SOURCE_BUNDLE_OK;

    for (size_t c = 0; c < ncands; c++) {
        if (!sbf_budget_left(start_us)) {
            if (result == SOURCE_BUNDLE_FETCH_ERR_TRANSPORT)
                result = SOURCE_BUNDLE_FETCH_ERR_BUDGET;
            break;
        }
        size_t wire_len = 0;
        uint8_t *wire = sbf_download_candidate(&cands[c], staging_dir,
                                               &wire_len);
        if (!wire)
            continue;
        tried++;

        struct vcs_source_bundle_metrics bm;
        enum vcs_source_bundle_result vr =
            vcs_source_bundle_verify(wire, wire_len, source_root, &bm);
        if (vr != VCS_SOURCE_BUNDLE_OK) {
            /* THE substitution refusal. These bytes may be a perfectly
             * well-formed bundle that verifies under its OWN root; they are
             * not the tree the caller asked for, so they are discarded here
             * and never reach any caller-visible path. */
            free(wire);
            refused++;
            last_refusal = vr;
            result = SOURCE_BUNDLE_FETCH_ERR_ROOT;
            sbf_note_substitution(&cands[c]);
            LOG_WARN(SBF_SUBSYS, "candidate %zu of %zu delivered bytes that do "
                     "not rederive to the requested source root (%s) — "
                     "discarded, offence recorded against its peer(s), "
                     "continuing",
                     c + 1u, ncands, vcs_source_bundle_result_string(vr));
            continue;
        }

        *wire_out = wire;
        *wire_len_out = wire_len;
        if (metrics) {
            metrics->candidates_tried = tried;
            metrics->candidates_refused = refused;
            metrics->last_refusal = last_refusal;
            metrics->wire_bytes = (uint64_t)wire_len;
            metrics->bundle = bm;
        }
        LOG_INFO(SBF_SUBSYS, "accepted a %zu-byte source bundle after %u "
                 "candidate(s), %u refused", wire_len, tried, refused);
        return SOURCE_BUNDLE_FETCH_OK;
    }

    if (metrics) {
        metrics->candidates_tried = tried;
        metrics->candidates_refused = refused;
        metrics->last_refusal = last_refusal;
    }
    LOG_WARN(SBF_SUBSYS, "no candidate satisfied the requested source root "
             "(%u peer(s) offered, %u downloaded, %u refused by the root): %s",
             offering, tried, refused,
             source_bundle_fetch_result_string(result));
    return result;
}
