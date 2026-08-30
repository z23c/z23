/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_bundle_fetch.c — THE WELD. See config/boot_bundle_fetch.h for the
 * contract. Downloads (never installs) a content-verified consensus-state
 * checkpoint bundle into <datadir>/bundles/ so the already-wired autodetect
 * installs it under the compiled CHECKPOINT_ROM authority. Fail-closed on the
 * bytes (per-chunk / whole-file SHA3), fail-open on the wiring (any miss leaves
 * boot on its unchanged path). Consumes net/rom_fetch.h; edits none of it. */
#include "config/boot_bundle_fetch.h"
#include "boot_bundle_fetch_seeds_internal.h"    /* bbf_assemble_seeds/_add_peer */
#include "boot_bundle_fetch_probe_internal.h"
#include "config/boot.h"                       /* struct app_context */
#include "config/boot_consensus_bundle_marker.h"
#include "config/consensus_state_install_runtime.h" /* boot_autodetect_consensus_bundle */
#include "chain/checkpoints.h"                 /* get_sha3_utxo_checkpoint */
#include "net/rom_fetch.h"
#include "net/rom_seed.h"                       /* ROM_SEED_* bounds */
#include "net/file_service.h"                   /* FS_PORT default */
#include "encoding/utilstrencodings.h"          /* HexStr */
#include "platform/file_metadata.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "platform/safe_root_read.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"                    /* zcl_malloc */
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define BBF_SUBSYS "boot_bundle_fetch"
/* The manifest commitment (a /directory.json body) is small + auditable; cap
 * the read well above a realistic ROM directory (a few artifacts). */
#define BBF_DIRECTORY_JSON_MAX (64u * 1024u)
/* ── Gate ───────────────────────────────────────────────────────────────── */
/* MAINNET-ONLY. The artifact this weld downloads is bound at install to the
 * compiled CHECKPOINT_ROM, and that checkpoint is a MAINNET one (see
 * boot_bundle_pick_manifest's fallback to get_sha3_utxo_checkpoint()->height).
 * A regtest or testnet node therefore has nothing to gain from the fetch and
 * everything to leak by attempting it: on 2026-07-28 a `-regtest` fixture that
 * named a deliberately dead `-connect` sink still ran this weld, reached the
 * operator's LIVE node on its file-service port, and pulled ~1 GB of real
 * mainnet chain state into what was supposed to be an empty regtest datadir.
 * The gate is "is mainnet", not "is not regtest": a testnet node must not pull
 * a mainnet bundle either.
 *
 * ctx is THE authority, deliberately, and chain_params_get() is not consulted:
 * boot_step_select_chain_and_datadir (config/src/boot.c) derives the selected
 * chain from exactly these two ctx fields, so ctx is the same answer one step
 * earlier — and chain_params_get() asserts when no chain has been selected yet,
 * which a unit-test caller has every right not to have done. A NULL ctx means
 * "no argv context", which is mainnet, matching every other gate in this
 * function. */
static bool bbf_network_is_mainnet(const struct app_context *ctx)
{
    return !(ctx && (ctx->regtest || ctx->testnet));
}
/* Name the skip once per process. Never silent: a fetch that does not happen
 * has to say so, or the next fixture leak reads as "the gate worked". */
static void bbf_log_network_skip(const char *what,
                                 const struct app_context *ctx)
{
    static bool logged = false;
    if (logged)
        return;
    logged = true;
    LOG_INFO(BBF_SUBSYS,
             "%s SKIPPED: network=%s is not mainnet, and the checkpoint bundle "
             "(plus the CHECKPOINT_ROM authority that installs it) is "
             "mainnet-only. No file-service peer was contacted.",
             what, (ctx && ctx->regtest) ? "regtest" : "testnet");
}
bool boot_bundle_fetch_should_run(const char *datadir,
                                  const struct app_context *ctx)
{
    if (!datadir || !datadir[0])
        return false;
    /* Network first: a non-mainnet node must not reach out at all. */
    if (!bbf_network_is_mainnet(ctx)) {
        bbf_log_network_skip("instant-on checkpoint-bundle acquisition", ctx);
        return false;
    }
    /* -nofilesync already means "do not reach out to file-service downloads". */
    if (ctx && ctx->no_file_sync)
        return false;
    if (getenv("ZCL_NO_BUNDLE_FETCH"))
        return false;
    /* Never re-fetch over already-sovereign state. */
    if (boot_consensus_bundle_marker_exists(datadir))
        return false;
    /* A bundle already staged under <datadir>/bundles/ → the autodetect installs
     * it; no download needed. (Autodetect returns NULL when the marker is set or
     * every candidate is <name>.failed; the marker case is already handled.) */
    char *staged = boot_autodetect_consensus_bundle(datadir);
    if (staged) {
        free(staged);
        return false;
    }
    return true;
}
/* Manifest pick from a /directory.json body (boot_bundle_pick_manifest,
 * boot_bundle_pick_header_seed_manifest) lives in
 * config/src/boot_bundle_manifest_pick.c. */
/* ── Verified download into <datadir>/bundles/ ──────────────────────────── */
bool boot_bundle_fetch_download(const char *datadir,
                                const struct rom_fetch_peer *peers,
                                size_t npeers,
                                const struct rom_fetch_manifest *m)
{
    if (!datadir || !datadir[0] || !peers || npeers == 0 || !m)
        return false;
    if (!m->filename[0] || !rom_fetch_manifest_sane(m))
        LOG_FAIL(BBF_SUBSYS,
                 "refusing bundle fetch: committed manifest not sane / no name");
    char bundles[PATH_MAX];
    int bn = snprintf(bundles, sizeof(bundles), "%s/bundles", datadir);
    if (bn < 0 || (size_t)bn >= sizeof(bundles))
        LOG_FAIL(BBF_SUBSYS, "bundles path too long under %s", datadir);
    if (!platform_private_directory_ensure(bundles))
        LOG_FAIL(BBF_SUBSYS, "private bundles directory %s refused: %s",
                 bundles, strerror(errno));
    /* Prefer the per-chunk-verified swarm path (rom_fetch_download_verified_
     * parallel): probe reachable seeders for the artifact's "RMF" manifest and,
     * on the first that serves one matching the committed num_chunks, run the
     * content-verify-and-failover download. Only if NO reachable peer serves a
     * manifest (an all-legacy seeder set) do we take the whole-file-only
     * multi-seeder scheduler. Both verify the bytes against `m` before the
     * atomic rename — a byte-mismatch never lands a *.sqlite. */
    uint8_t (*chunk_sha3)[32] =
        zcl_malloc((size_t)ROM_SEED_MAX_CHUNKS * 32, "bbf_chunk_sha3");
    if (!chunk_sha3)
        LOG_FAIL(BBF_SUBSYS, "OOM allocating chunk-manifest buffer");
    /* The pre-flight runs against EVERY seed at once rather than walking them.
     * A seed that accepts the connection and then goes silent costs the whole
     * connect budget plus the whole probe budget, and walking multiplied that
     * by the seed count before boot could move on — the very stall the RLS
     * discovery sweep is already fanned out to avoid, and worse on a Tor
     * circuit where both budgets are legitimately 4x larger. Same seed wins
     * (lowest index with a matching chunk count), same verification, same
     * budgets; only the waiting overlaps. */
    uint32_t manifest_chunks = 0;
    bool have_manifest = bbf_probe_manifest(peers, npeers, m->chunk_root,
                                            m->num_chunks, chunk_sha3,
                                            ROM_SEED_MAX_CHUNKS,
                                            &manifest_chunks,
                                            rom_fetch_get_manifest);
    uint32_t workers = (uint32_t)(2 * npeers);
    if (workers > ROM_FETCH_MAX_WORKERS)
        workers = ROM_FETCH_MAX_WORKERS;
    bool ok;
    if (have_manifest)
        ok = rom_fetch_download_verified_parallel(peers, npeers, m, chunk_sha3,
                                                  manifest_chunks, bundles,
                                                  NULL, NULL);
    else
        ok = rom_fetch_download_parallel(peers, npeers, m, bundles, workers,
                                         NULL, NULL);
    free(chunk_sha3);
    if (!ok) {
        LOG_WARN(BBF_SUBSYS,
                 "instant-on bundle fetch did not complete for %s "
                 "(content-verify/transport failure — left partial for resume, "
                 "boot falls back to P2P / operator bundle)", m->filename);
        return false;
    }
    LOG_INFO(BBF_SUBSYS,
             "instant-on bundle fetch landed %s/%s (%u chunks, content-verified) "
             "— the autodetect installs it under the CHECKPOINT_ROM authority",
             bundles, m->filename, m->num_chunks);
    /* Reseed the swarm: register the just-landed, content-verified bundle
     * with rom_seed IMMEDIATELY so this node starts serving it to other
     * downloaders within the same boot, with no restart needed — BitTorrent-
     * style swarm widening with zero operator input.
     *
     * rom_seed_register is pure registry state (a mutex + static tables); it
     * has no dependency on the file-service thread, rom_seed_start_scan, or
     * any other boot stage having run yet, so it is always safe to call here
     * — even though, in production, this function runs from
     * boot_select_state_source, which fires BEFORE boot_rom_seed_start /
     * fs_server_start (config/src/boot_auto_install_bundle.c). That ordering
     * is exactly why this call cannot simply gate on "is the file service
     * running": at this point in a fresh boot it never is yet. A failure
     * here (registry full, path overflow) is logged and non-fatal — it never
     * blocks or fails boot — because rom_seed_scan_datadir now recurses into
     * <datadir>/bundles/ (net/rom_seed.c) and will register the same file
     * the next time it runs: this same boot's own rom_seed_start_scan (which
     * starts moments later, once the frontend services init), or a later
     * boot if seeding was disabled this run. */
    char reseed_name[ROM_SEED_NAME_MAX];
    int rnn = snprintf(reseed_name, sizeof(reseed_name), "%s/%s",
                       ROM_SEED_BUNDLES_SUBDIR, m->filename);
    if (rnn > 0 && (size_t)rnn < sizeof(reseed_name)) {
        enum rom_register_result rrc =
            rom_seed_register(datadir, reseed_name, m->whole_sha3, NULL);
        if (rrc == ROM_REG_OK)
            LOG_INFO(BBF_SUBSYS,
                     "reseed: registered fetched bundle '%s' with rom_seed — "
                     "this node now serves it to the swarm", reseed_name);
        else
            LOG_WARN(BBF_SUBSYS,
                     "reseed: could not register fetched bundle '%s' (rc=%d) "
                     "— the next rom_seed scan will pick it up", reseed_name,
                     (int)rrc);
    } else {
        LOG_WARN(BBF_SUBSYS,
                 "reseed: bundle relative name overflow — the next rom_seed "
                 "scan will pick it up");
    }
    return true;
}
/* ── Production entry: assemble seeds, read the manifest hint, download ──── */
/* Read up to `cap` bytes of a text file into a NUL-terminated malloc'd buffer.
 * Returns NULL when absent/empty/too-large (all non-fatal). */
static char *bbf_read_text_file(const char *root, const char *relative,
                                size_t cap)
{
    uint8_t *bytes = NULL;
    size_t size = 0;
    if (platform_safe_root_read(root, relative, cap, &bytes, &size) !=
            PLATFORM_SAFE_ROOT_READ_OK || size == 0) {
        free(bytes);
        return NULL;
    }
    char *buf = zcl_malloc(size + 1, "bbf_directory_json");
    if (!buf) {
        free(bytes);
        return NULL;
    }
    memcpy(buf, bytes, size);
    buf[size] = '\0';
    free(bytes);
    return buf;
}
/* Baked-facts cross-check for a picked manifest — the chunking + size invariants
 * the compiled seeder always honours. rom_fetch_manifest_sane (called inside
 * boot_bundle_pick_manifest) already enforces these; this is the belt-and-
 * suspenders guard the discovery path asserts before it trusts a peer-advertised
 * triple. Pure predicate — a false return is "not the compiled artifact shape",
 * not an error site. */
static bool bbf_manifest_facts_ok(const struct rom_fetch_manifest *m)
{
    if (!m)
        return false;
    if (m->chunk_size != ROM_SEED_CHUNK_SIZE)
        return false;
    if (m->size_bytes < ROM_SEED_MIN_ARTIFACT_BYTES ||
        m->size_bytes > ROM_SEED_MAX_ARTIFACT_BYTES)
        return false;
    uint32_t expect =
        (uint32_t)((m->size_bytes + m->chunk_size - 1) / m->chunk_size);
    return m->num_chunks > 0 && m->num_chunks <= ROM_SEED_MAX_CHUNKS &&
           m->num_chunks == expect;
}
/* Emit one {"kind":..,"digest":..,"whole_sha3":..,"size":..,"chunk_size":..,
 * "chunks":..} object into `dst` (capacity `cap`). `kind` is the wire token
 * rom_seed_kind_from_name round-trips ("consensus_bundle" / "header_seed").
 * Returns the byte count, or 0 on overflow. */
static int bbf_emit_artifact_obj(char *dst, size_t cap, const char *kind,
                                 const struct rom_fetch_manifest *m)
{
    char digest_hex[65], whole_hex[65];
    HexStr(m->chunk_root, 32, false, digest_hex, sizeof(digest_hex));
    HexStr(m->whole_sha3, 32, false, whole_hex, sizeof(whole_hex));
    int wn = snprintf(dst, cap,
        "{\"kind\":\"%s\",\"digest\":\"%s\",\"whole_sha3\":\"%s\","
        "\"size\":%llu,\"chunk_size\":%u,\"chunks\":%u,\"height\":%lld}",
        kind, digest_hex, whole_hex, (unsigned long long)m->size_bytes,
        m->chunk_size, m->num_chunks, (long long)m->height);
    if (wn <= 0 || (size_t)wn >= cap)
        return 0;
    return wn;
}
/* Persist the discovered manifest(s) as the canonical
 * <datadir>/bundles/directory.json hint so a resume/reseed reads them locally
 * without re-querying peers. Emits the {"artifacts":[...]} object
 * rom_fetch_parse_directory / pick consume — the consensus bundle plus, when
 * `hs` is non-NULL, the header-chain seed. Writes via a .tmp + rename so a
 * crash never leaves a truncated hint. */
static bool bbf_write_directory_hint(const char *datadir,
                                     const struct rom_fetch_manifest *m,
                                     const struct rom_fetch_manifest *hs)
{
    if (!datadir || !datadir[0] || !m)
        LOG_FAIL(BBF_SUBSYS, "write hint: null arg");
    char bundles[PATH_MAX];
    int bn = snprintf(bundles, sizeof(bundles), "%s/bundles", datadir);
    if (bn < 0 || (size_t)bn >= sizeof(bundles))
        LOG_FAIL(BBF_SUBSYS, "write hint: bundles path too long under %s",
                 datadir);
    if (!platform_private_directory_ensure(bundles))
        LOG_FAIL(BBF_SUBSYS, "write hint: private directory %s refused: %s",
                 bundles, strerror(errno));
    char body[2048];
    int off = snprintf(body, sizeof(body), "{\"artifacts\":[");
    if (off <= 0 || (size_t)off >= sizeof(body))
        LOG_FAIL(BBF_SUBSYS, "write hint: directory.json body overflow");
    int en = bbf_emit_artifact_obj(body + off, sizeof(body) - (size_t)off,
                                   "consensus_bundle", m);
    if (en == 0)
        LOG_FAIL(BBF_SUBSYS, "write hint: bundle artifact object overflow");
    off += en;
    if (hs) {
        int cn = snprintf(body + off, sizeof(body) - (size_t)off, ",");
        if (cn <= 0 || (size_t)(off + cn) >= sizeof(body))
            LOG_FAIL(BBF_SUBSYS, "write hint: directory.json separator overflow");
        off += cn;
        en = bbf_emit_artifact_obj(body + off, sizeof(body) - (size_t)off,
                                   "header_seed", hs);
        if (en == 0)
            LOG_FAIL(BBF_SUBSYS, "write hint: header-seed artifact object overflow");
        off += en;
    }
    int cn = snprintf(body + off, sizeof(body) - (size_t)off, "]}");
    if (cn <= 0 || (size_t)(off + cn) >= sizeof(body))
        LOG_FAIL(BBF_SUBSYS, "write hint: directory.json close overflow");
    int wn = off + cn;
    if (wn <= 0 || (size_t)wn >= sizeof(body))
        LOG_FAIL(BBF_SUBSYS, "write hint: directory.json body overflow");
    char path[PATH_MAX];
    int pn = snprintf(path, sizeof(path), "%s/bundles/directory.json", datadir);
    if (pn < 0 || (size_t)pn >= sizeof(path))
        LOG_FAIL(BBF_SUBSYS, "write hint: path too long under %s", datadir);
    char tmp[PATH_MAX];
    int tn = snprintf(tmp, sizeof(tmp), "%s/bundles/directory.json.tmp", datadir);
    if (tn < 0 || (size_t)tn >= sizeof(tmp))
        LOG_FAIL(BBF_SUBSYS, "write hint: tmp path too long under %s", datadir);
    (void)platform_private_file_unlink_missing_ok(tmp);
    struct platform_private_file staging;
    platform_private_file_init(&staging);
    if (!platform_private_file_create(tmp, &staging) ||
        !platform_private_file_write_at(&staging, body, (size_t)wn, 0) ||
        !platform_private_file_flush(&staging) ||
        !platform_private_file_replace(&staging, tmp, path) ||
        !platform_private_parent_flush(bundles)) {
        (void)platform_private_file_retire(&staging, tmp);
        platform_private_file_close(&staging);
        LOG_FAIL(BBF_SUBSYS, "write hint: durable private replace failed: %s",
                 strerror(errno));
    }
    return true;
}
/* One discovered-manifest candidate and how many independent seeds served it.
 * The advertised height is carried on `m.height` (rom_fetch_manifest.height) and
 * drives newest-first ranking (bbf_quorum_pick / bbf_quorum_rank). */
struct bbf_disc_cand {
    struct rom_fetch_manifest m;
    int  count;
    bool has_explicit;   /* an explicit -fileservice seed served this triple */
};
/* Pure candidate ranking over the tallied candidates. Returns the index of the
 * candidate to attempt FIRST, or -1 only when ncand == 0.
 *
 * STEP 0 verdict — the export is NOT byte-deterministic across independent
 * nodes, so a per-height triple quorum almost never forms across a mixed fleet.
 * A consensus-state bundle is a SQLite file, and its `source_receipt` table
 * binds the PRODUCER's running-binary digest (SHA3 of /proc/self/exe — see
 * config/src/consensus_state_producer_receipt.c) plus toolchain/build-input
 * digests; two honest at-tip nodes at the same height whose binaries are not
 * proven byte-identical (they are not — no two-builder gate exists yet) write
 * different bundle bytes, so their (chunk_root, whole_sha3, size) triples
 * differ. SQLite page/freelist/writer-version layout is a further nondeterminism
 * source over the whole-file digest. A triple therefore agrees across seeds
 * essentially ONLY when the SAME physical artifact re-propagated (a re-seeded
 * copy), never as an independent second attestation.
 *
 * Consequences for the rule (this is why the old ">=2 agree or refuse" gate is
 * gone — it silently fell OPEN to a from-genesis IBD whenever a mixed-height
 * fleet served distinct triples, even with a perfectly valid newest bundle on
 * offer):
 *   - Prefer the HIGHEST advertised height (the freshest bundle).
 *   - Within the same height, a >=2-seed triple still beats a lone one, then an
 *     explicit -fileservice seed beats a non-explicit one.
 *   - A lone non-explicit highest-height candidate is STILL returned: quorum is
 *     only a bandwidth-DoS guard here, NOT a trust source. Trust binds solely at
 *     install under the CHECKPOINT_ROM authority (boot_bundle_fetch.c's install
 *     path / config/src/boot_install_consensus_bundle.c), so a lying seed at
 *     worst wastes ONE bounded, content-verified fetch that fails to install;
 *     the caller then falls back to the next-highest candidate (bbf_quorum_rank)
 *     before it ever falls open to IBD.
 * `heights`/`counts`/`has_explicit` are parallel arrays of length `ncand`. No IO. */
static int bbf_quorum_pick(const int64_t *heights, const int *counts,
                           const bool *has_explicit, size_t ncand)
{
    int best = -1;
    for (size_t c = 0; c < ncand; c++) {
        if (best < 0) {
            best = (int)c;
            continue;
        }
        if (heights[c] > heights[(size_t)best]) {
            best = (int)c;
            continue;
        }
        if (heights[c] < heights[(size_t)best])
            continue;
        /* Same height: higher count wins; a tie prefers an explicit-seed
         * candidate so a lone operator-named seed is not shadowed by an
         * equal-count non-explicit. */
        if (counts[c] > counts[best] ||
            (counts[c] == counts[best] && has_explicit[c] && !has_explicit[best]))
            best = (int)c;
    }
    return best;
}
/* Tally one picked manifest into a candidate list, merging on a byte-identical
 * (chunk_root, whole_sha3, size) triple. Bounded by `ccap`. */
static void bbf_tally_cand(struct bbf_disc_cand *cands, size_t *ncand,
                           size_t ccap, const struct rom_fetch_manifest *m,
                           bool is_explicit)
{
    for (size_t c = 0; c < *ncand; c++) {
        if (cands[c].m.size_bytes == m->size_bytes &&
            memcmp(cands[c].m.chunk_root, m->chunk_root, 32) == 0 &&
            memcmp(cands[c].m.whole_sha3, m->whole_sha3, 32) == 0) {
            cands[c].count++;
            cands[c].has_explicit = cands[c].has_explicit || is_explicit;
            return;
        }
    }
    if (*ncand < ccap) {
        cands[*ncand].m = *m;
        cands[*ncand].count = 1;
        cands[*ncand].has_explicit = is_explicit;
        (*ncand)++;
    }
}
/* Apply the ranking to a tallied candidate list. Returns true (and fills *out)
 * with the top candidate; false only when ncand == 0. */
static bool bbf_quorum_winner(const struct bbf_disc_cand *cands, size_t ncand,
                              struct rom_fetch_manifest *out)
{
    int64_t heights[ROM_FETCH_MAX_WORKERS];
    int counts[ROM_FETCH_MAX_WORKERS];
    bool flags[ROM_FETCH_MAX_WORKERS];
    if (ncand > ROM_FETCH_MAX_WORKERS)
        ncand = ROM_FETCH_MAX_WORKERS;
    for (size_t c = 0; c < ncand; c++) {
        heights[c] = cands[c].m.height;
        counts[c] = cands[c].count;
        flags[c] = cands[c].has_explicit;
    }
    int best = bbf_quorum_pick(heights, counts, flags, ncand);
    if (best < 0)
        return false;
    *out = cands[best].m;
    return true;
}
/* Rank a tallied candidate list into `out[]` (capacity `out_cap`), best first,
 * by repeatedly selecting the current bbf_quorum_pick winner among the not-yet-
 * emitted candidates. This is the bounded fallback list: the caller downloads
 * the newest, and on a fetch/verify miss tries the next-highest before ever
 * falling open to IBD (see bbf_quorum_pick's STEP 0 rationale). Returns the
 * number written. O(n^2) over a list bounded by ROM_FETCH_MAX_WORKERS. */
static size_t bbf_quorum_rank(const struct bbf_disc_cand *cands, size_t ncand,
                              struct rom_fetch_manifest *out, size_t out_cap)
{
    if (ncand > ROM_FETCH_MAX_WORKERS)
        ncand = ROM_FETCH_MAX_WORKERS;
    bool taken[ROM_FETCH_MAX_WORKERS] = { false };
    size_t nout = 0;
    for (size_t rank = 0; rank < ncand && nout < out_cap; rank++) {
        int64_t heights[ROM_FETCH_MAX_WORKERS];
        int counts[ROM_FETCH_MAX_WORKERS];
        bool flags[ROM_FETCH_MAX_WORKERS];
        int map[ROM_FETCH_MAX_WORKERS];
        size_t k = 0;
        for (size_t c = 0; c < ncand; c++) {
            if (taken[c])
                continue;
            heights[k] = cands[c].m.height;
            counts[k] = cands[c].count;
            flags[k] = cands[c].has_explicit;
            map[k] = (int)c;
            k++;
        }
        if (k == 0)
            break;
        int pick = bbf_quorum_pick(heights, counts, flags, k);
        if (pick < 0)
            break;
        int src = map[pick];
        out[nout++] = cands[src].m;
        taken[src] = true;
    }
    return nout;
}
/* One discovered directory: the required consensus bundle(s) plus the optional
 * header-chain seed. `bundles` is ranked newest-first (bbf_quorum_rank); the
 * download tries them in order (bounded fallback to the next-highest on a
 * fetch/verify miss). n_bundles == 0 means no usable bundle was advertised. */
struct bbf_discovery {
    struct rom_fetch_manifest bundles[ROM_FETCH_MAX_WORKERS];
    size_t n_bundles;
    struct rom_fetch_manifest header_seed;
    bool have_header_seed;
    /* A responder is eligible only for the exact artifact it advertised.
     * Merely answering RLS is insufficient: a fast `{}` reply must never buy
     * entry into the 120-second per-chunk rotation. Local hints have no live
     * discovery evidence and therefore retain the operator's full seed set. */
    struct rom_fetch_peer
        bundle_peers[ROM_FETCH_MAX_WORKERS][ROM_FETCH_MAX_WORKERS];
    size_t bundle_peer_count[ROM_FETCH_MAX_WORKERS];
    struct rom_fetch_peer header_peers[ROM_FETCH_MAX_WORKERS];
    size_t header_peer_count;
};

static bool bbf_manifest_same_artifact(const struct rom_fetch_manifest *a,
                                       const struct rom_fetch_manifest *b)
{
    return a && b && a->size_bytes == b->size_bytes &&
           a->num_chunks == b->num_chunks &&
           memcmp(a->chunk_root, b->chunk_root, 32) == 0 &&
           memcmp(a->whole_sha3, b->whole_sha3, 32) == 0;
}
/* Query each seed for its directory listing over the FS "RLS" wire, pick both
 * the consensus-bundle and header-seed manifests each advertises, and require
 * >=2 independent seeds returning a byte-identical (chunk_root, whole_sha3,
 * size) triple before trusting EACH manifest — a bandwidth-DoS / lone-liar
 * guard: trust binds at install, not here. quorum=1 is accepted ONLY when the
 * lone seed is the operator's explicit -fileservice peer. The bundle is
 * REQUIRED (no bundle quorum → fail-open to IBD); the header seed is OPTIONAL
 * (its absence just means the header chain still arrives via P2P). On success
 * *out holds the winning manifest(s) and the winning directory.json (both
 * artifacts) is persisted for resume. Returns false when no bundle quorum
 * forms. */
/* Persists the last discovery quorum outcome to progress.kv for the
 * "bbf_discovery" diagnostics dumper — see
 * config/src/boot_bundle_fetch_discovery_outcome.c (split out to keep this
 * file under the E1 800-line ceiling) for the full rationale and contract. */
void bbf_record_discovery_outcome(const char *outcome_name,
                                  size_t seed_count, size_t responded_count);
static bool bbf_discover_from_peers(const char *datadir,
                                    const struct rom_fetch_peer *peers,
                                    size_t np, bool explicit_first,
                                    struct bbf_discovery *out)
{
    memset(out, 0, sizeof(*out));
    const size_t stride = BBF_DIRECTORY_JSON_MAX + 1;
    char *bodies = zcl_calloc(np, stride, "bbf_disc_bodies");
    bool responded_flags[ROM_FETCH_MAX_WORKERS] = { false };
    if (!bodies)
        LOG_FAIL(BBF_SUBSYS, "discovery: OOM allocating listing buffers");
    struct bbf_disc_cand bundle_cands[ROM_FETCH_MAX_WORKERS];
    struct bbf_disc_cand hs_cands[ROM_FETCH_MAX_WORKERS];
    memset(bundle_cands, 0, sizeof(bundle_cands));
    memset(hs_cands, 0, sizeof(hs_cands));
    size_t nbundle = 0, nhs = 0;
    size_t responded = bbf_probe_directories(
        peers, np, bodies, stride, responded_flags, rom_fetch_get_directory);
    const size_t ccap = sizeof(bundle_cands) / sizeof(bundle_cands[0]);
    for (size_t i = 0; i < np; i++) {
        if (!responded_flags[i]) {
            /* Bounded, once, then dropped — see struct bbf_discovery.live.
             * A seed that did not answer discovery is not carried into the
             * download: there it would sit on the 120s per-chunk IO timeout
             * and be retried every round, which is the stall this avoids. */
            LOG_INFO(BBF_SUBSYS,
                     "discovery: seed %s:%u did not serve a directory listing "
                     "— dropping it from this boot's download seed set",
                     peers[i].addr, (unsigned)peers[i].port);
            continue;
        }
        const char *body = bodies + i * stride;
        bool is_explicit = explicit_first && i == 0;
        struct rom_fetch_manifest m;
        memset(&m, 0, sizeof(m));
        if (boot_bundle_pick_manifest(body, &m)) {
            if (bbf_manifest_facts_ok(&m))
                bbf_tally_cand(bundle_cands, &nbundle, ccap, &m, is_explicit);
            else
                LOG_WARN(BBF_SUBSYS, "discovery: seed %s:%u advertised a bundle "
                         "manifest that fails the baked-facts cross-check — "
                         "ignoring", peers[i].addr, (unsigned)peers[i].port);
        }
        struct rom_fetch_manifest hm;
        memset(&hm, 0, sizeof(hm));
        if (boot_bundle_pick_header_seed_manifest(body, &hm)) {
            if (bbf_manifest_facts_ok(&hm))
                bbf_tally_cand(hs_cands, &nhs, ccap, &hm, is_explicit);
            else
                LOG_WARN(BBF_SUBSYS, "discovery: seed %s:%u advertised a header-"
                         "seed manifest that fails the baked-facts cross-check "
                         "— ignoring", peers[i].addr, (unsigned)peers[i].port);
        }
    }
    out->n_bundles = bbf_quorum_rank(bundle_cands, nbundle, out->bundles,
                                     ROM_FETCH_MAX_WORKERS);
    if (out->n_bundles == 0) {
        free(bodies);
        LOG_INFO(BBF_SUBSYS, "discovery: no reachable seed served a usable "
                 "bundle manifest — skipping instant-on fetch");
        bbf_record_discovery_outcome("no_quorum_fell_open_to_ibd", np,
                                     responded);
        return false;
    }
    out->have_header_seed = bbf_quorum_winner(hs_cands, nhs, &out->header_seed);
    /* Bind each download rotation to the responders that advertised that
     * exact committed artifact. This is a liveness boundary, not trust: byte
     * and checkpoint verification remain unchanged downstream. */
    for (size_t i = 0; i < np; i++) {
        if (!responded_flags[i])
            continue;
        const char *body = bodies + i * stride;
        struct rom_fetch_manifest advertised;
        memset(&advertised, 0, sizeof(advertised));
        if (boot_bundle_pick_manifest(body, &advertised) &&
            bbf_manifest_facts_ok(&advertised)) {
            for (size_t b = 0; b < out->n_bundles; b++) {
                if (bbf_manifest_same_artifact(&advertised,
                                               &out->bundles[b])) {
                    size_t n = out->bundle_peer_count[b];
                    if (n < ROM_FETCH_MAX_WORKERS) {
                        out->bundle_peers[b][n] = peers[i];
                        out->bundle_peer_count[b] = n + 1;
                    }
                }
            }
        }
        memset(&advertised, 0, sizeof(advertised));
        if (out->have_header_seed &&
            boot_bundle_pick_header_seed_manifest(body, &advertised) &&
            bbf_manifest_facts_ok(&advertised) &&
            bbf_manifest_same_artifact(&advertised, &out->header_seed)) {
            size_t n = out->header_peer_count;
            if (n < ROM_FETCH_MAX_WORKERS) {
                out->header_peers[n] = peers[i];
                out->header_peer_count = n + 1;
            }
        }
    }
    free(bodies);
    LOG_INFO(BBF_SUBSYS, "discovery: %zu bundle candidate(s) ranked "
             "(newest height=%lld, size=%llu); header-seed manifest %s — "
             "proceeding", out->n_bundles, (long long)out->bundles[0].height,
             (unsigned long long)out->bundles[0].size_bytes,
             out->have_header_seed ? "also advertised (headers arrive as an "
             "artifact)" : "not advertised (header chain via P2P)");
    /* Outcome category under ranked discovery: proceeding on a >=2-seed
     * byte-identical winner is "reached"; proceeding on a lone-seed winner is
     * "degraded_single_seed" (no longer a refusal — trust binds at install,
     * not at discovery; see bbf_quorum_pick's STEP 0 comment). */
    {
        int win_count = 0;
        for (size_t c = 0; c < nbundle; c++) {
            if (memcmp(bundle_cands[c].m.whole_sha3, out->bundles[0].whole_sha3,
                       sizeof(out->bundles[0].whole_sha3)) == 0) {
                win_count = bundle_cands[c].count;
                break;
            }
        }
        bbf_record_discovery_outcome(win_count >= 2 ? "reached"
                                                    : "degraded_single_seed",
                                     np, responded);
    }
    /* Persist the winning (newest) bundle + header seed as the local hint for a
     * resume; a fetch/verify miss on it re-discovers the full ranked set. */
    if (!bbf_write_directory_hint(datadir, &out->bundles[0],
                                  out->have_header_seed ? &out->header_seed
                                                        : NULL))
        LOG_WARN(BBF_SUBSYS, "discovery: could not persist the discovered "
                 "directory.json hint — resume will re-discover");
    return true;
}
/* Is the header-chain seed artifact still WANTED on this datadir? True on a
 * fresh, non-sovereign node that has neither imported it (<datadir>/
 * block_index.bin at the root) nor already downloaded it (<datadir>/bundles/
 * block_index.bin). Independent of the bundle gate: a datadir with a staged
 * bundle but no header chain STILL needs the seed so the install can bind. */
static bool bbf_header_seed_needed(const char *datadir,
                                   const struct app_context *ctx)
{
    if (!datadir || !datadir[0])
        return false;
    /* Same mainnet-only rule as the bundle gate: the header-chain seed is the
     * mainnet header chain, and fetching it is the same outbound dial. */
    if (!bbf_network_is_mainnet(ctx)) {
        bbf_log_network_skip("header-chain seed acquisition", ctx);
        return false;
    }
    if (ctx && ctx->no_file_sync)
        return false;
    if (getenv("ZCL_NO_BUNDLE_FETCH"))
        return false;
    if (boot_consensus_bundle_marker_exists(datadir))
        return false;
    char path[PATH_MAX];
    struct platform_file_metadata metadata;
    int pn = snprintf(path, sizeof(path), "%s/block_index.bin", datadir);
    if (pn > 0 && (size_t)pn < sizeof(path) &&
        platform_file_metadata_read(path, &metadata) ==
            PLATFORM_FILE_METADATA_OK)
        return false; /* already imported (or a legacy flat cache present) */
    pn = snprintf(path, sizeof(path), "%s/bundles/block_index.bin", datadir);
    if (pn > 0 && (size_t)pn < sizeof(path) &&
        platform_file_metadata_read(path, &metadata) ==
            PLATFORM_FILE_METADATA_OK)
        return false; /* already downloaded — import consumes it, no re-fetch */
    return true;
}
bool boot_bundle_fetch_maybe(const char *datadir, const struct app_context *ctx)
{
    bool bundle_needed = boot_bundle_fetch_should_run(datadir, ctx);
    bool header_needed = bbf_header_seed_needed(datadir, ctx);
    if (!bundle_needed && !header_needed)
        return false;
    /* Assemble the file-service seed set once — both discovery and the download
     * ride it (see bbf_assemble_seeds for the trust rationale). */
    struct rom_fetch_peer peers[ROM_FETCH_MAX_WORKERS];
    memset(peers, 0, sizeof(peers));
    bool explicit_first = false;
    size_t np = bbf_assemble_seeds(ctx, peers, sizeof(peers) / sizeof(peers[0]),
                                   &explicit_first);
    if (np == 0) {
        LOG_WARN(BBF_SUBSYS,
                 "file-service seed set is EMPTY — the instant-on fetch was "
                 "never attempted (connect-only with neither a -fileservice "
                 "peer nor a usable -connect host). This is a wiring miss, not "
                 "a discovery miss: see blocker bootstrap.no_state_source "
                 "fetch=seeds_empty");
        return false;
    }
    /* Manifest commitment. Prefer a LOCAL <datadir>/bundles/directory.json (an
     * operator hint, or one a prior discovery/resume persisted). On a truly fresh
     * node it is absent — discover it from the seed set over the file-service RLS
     * wire, requiring a >=2-seed quorum before trusting it. Either way the multi-
     * GB bytes are swarmed + content-verified against the committed manifest and
     * the install gate binds the result to the compiled checkpoint. */
    char hint_path[PATH_MAX];
    int hn = snprintf(hint_path, sizeof(hint_path),
                      "%s/bundles/directory.json", datadir);
    if (hn < 0 || (size_t)hn >= sizeof(hint_path))
        return false;
    struct bbf_discovery disc;
    memset(&disc, 0, sizeof(disc));
    char bundles_root[PATH_MAX];
    int brn = snprintf(bundles_root, sizeof(bundles_root), "%s/bundles",
                       datadir);
    if (brn < 0 || (size_t)brn >= sizeof(bundles_root)) return false;
    char *body = bbf_read_text_file(bundles_root, "directory.json",
                                    BBF_DIRECTORY_JSON_MAX);
    bool discovered_live = false;
    if (body) {
        if (boot_bundle_pick_manifest(body, &disc.bundles[0]))
            disc.n_bundles = 1;
        disc.have_header_seed =
            boot_bundle_pick_header_seed_manifest(body, &disc.header_seed);
        free(body);
        if (disc.n_bundles == 0 && !disc.have_header_seed) {
            LOG_WARN(BBF_SUBSYS,
                     "manifest hint present at %s but no usable artifact "
                     "— skipping", hint_path);
            return false;
        }
    } else {
        LOG_INFO(BBF_SUBSYS,
                 "no local bundle manifest at %s — attempting peer directory "
                 "discovery over the file-service RLS wire", hint_path);
        if (!bbf_discover_from_peers(datadir, peers, np, explicit_first, &disc))
            return false; /* fail-open: normal P2P IBD is the path */
        discovered_live = true;
    }
    /* Headers FIRST: the bundle install DEFERS on the header chain reaching the
     * checkpoint (checkpoint_bundle_install_ready), so the header seed is on the
     * critical path — download it before the (larger) bundle so the in-process
     * import that follows can climb pindex_best_header this boot. Both rides the
     * same content-verified swarm path; a header-seed miss is non-fatal (the
     * chain still arrives via P2P, just slower). */
    bool any = false;
    if (header_needed && disc.have_header_seed) {
        const struct rom_fetch_peer *header_peers = peers;
        size_t header_np = np;
        if (discovered_live) {
            header_peers = disc.header_peers;
            header_np = disc.header_peer_count;
        }
        if (boot_bundle_fetch_download(datadir, header_peers, header_np,
                                       &disc.header_seed)) {
            any = true;
            LOG_INFO(BBF_SUBSYS, "instant-on: header-chain seed landed — the "
                     "in-process import climbs the header frontier (no serial "
                     "P2P header crawl before install)");
        } else {
            LOG_WARN(BBF_SUBSYS, "instant-on: header-chain seed fetch did not "
                     "complete — header chain falls back to P2P sync");
        }
    }
    /* Bounded fallback: try the ranked bundle candidates newest-first, stopping
     * at the first that lands (content-verified). A miss on the newest is not
     * fatal — the next-highest is tried before boot falls open to IBD (STEP 0:
     * the export is not cross-node deterministic, so a lone newest candidate is
     * legitimate and must not be refused, but it also cannot be blindly trusted;
     * a bad one just wastes one bounded fetch, and the install gate is the trust
     * boundary either way). */
    if (bundle_needed) {
        for (size_t bi = 0; bi < disc.n_bundles; bi++) {
            const struct rom_fetch_peer *bundle_peers = peers;
            size_t bundle_np = np;
            if (discovered_live) {
                bundle_peers = disc.bundle_peers[bi];
                bundle_np = disc.bundle_peer_count[bi];
            }
            if (boot_bundle_fetch_download(datadir, bundle_peers, bundle_np,
                                           &disc.bundles[bi])) {
                any = true;
                break;
            }
            if (bi + 1 < disc.n_bundles)
                LOG_WARN(BBF_SUBSYS,
                         "instant-on: bundle candidate height=%lld did not land "
                         "— trying the next-highest of %zu candidate(s)",
                         (long long)disc.bundles[bi].height, disc.n_bundles);
        }
    }
    return any;
}
#ifdef ZCL_TESTING
/* Test surface: the pure baked-facts cross-check and quorum decision (see
 * config/boot_bundle_fetch.h). Kept out of the production ABI. */
bool boot_bundle_manifest_facts_ok_for_test(const struct rom_fetch_manifest *m)
{
    return bbf_manifest_facts_ok(m);
}
int boot_bundle_quorum_pick_for_test(const int64_t *heights, const int *counts,
                                     const bool *has_explicit, size_t ncand)
{
    return bbf_quorum_pick(heights, counts, has_explicit, ncand);
}
#endif
