/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_boot_bundle_fetch — THE WELD (config/src/boot_bundle_fetch.c).
 *
 * Proves the instant-on download-before-autodetect weld end to end against the
 * REAL file-service serve path on a loopback seeder:
 *
 *   (a) the gate (boot_bundle_fetch_should_run): fresh datadir → run; opted out
 *       (-nofilesync / ZCL_NO_BUNDLE_FETCH) → skip; sovereign marker present →
 *       skip; a *.sqlite already staged → skip.
 *   (b) manifest pick (boot_bundle_pick_manifest): a /directory.json body parses
 *       to the largest sane artifact and is assigned a classifiable
 *       consensus-state-bundle-*.sqlite name; empty/garbage → refused.
 *   (c) E2E: fresh datadir + no bundle + a reachable seeder ⇒ the content-
 *       verified bundle lands under <datadir>/bundles/, the autodetect then
 *       FINDS it (install fires), and the install of this synthetic (non-
 *       checkpoint) bundle FAILS CLOSED with NO sovereign marker written —
 *       sovereignty preserved. A byte-mismatched committed digest ⇒ the fetch
 *       is REFUSED, nothing lands, and the autodetect finds nothing (no install).
 *   (d) the production entry (boot_bundle_fetch_maybe): a directory.json hint +
 *       an -fileservice peer drives the same land-in-bundles/ result.
 *
 * Fixtures live under mkdtemp() dirs in /tmp — never a real datadir. The
 * synthetic bundle is a valid SQLite-magic blob that the serve path streams and
 * the fetch content-verifies, but it is NOT a real consensus-state bundle, so
 * the install path fail-closes at admission (exactly the sovereignty guard). */

#include "test/test_core.h"

#include "config/boot.h"                       /* struct app_context */
#include "config/boot_bundle_fetch.h"
#include "config/boot_consensus_bundle_marker.h"
#include "config/consensus_state_install_runtime.h"
#include "chain/checkpoints.h"
#include "net/rom_fetch.h"
#include "net/rom_seed.h"
#include "net/file_service.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "storage/progress_store.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* SQLite-magic-prefixed deterministic content the serve path accepts + the
 * fetch content-verifies (mirrors test_rom_fetch). */
static void bbf_gen_content(uint8_t *buf, size_t size)
{
    static const uint8_t magic[16] = "SQLite format 3";
    for (size_t i = 0; i < size; i++)
        buf[i] = (uint8_t)((i * 131u + 7u) & 0xffu);
    if (size >= 16)
        memcpy(buf, magic, 16);
}

static bool bbf_write_file(const char *dir, const char *name,
                           const uint8_t *buf, size_t size)
{
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return false;
    bool ok = (write(fd, buf, size) == (ssize_t)size);
    close(fd);
    return ok;
}

/* Wrap the serve-side artifacts array (rom_seed_directory_json) into the full
 * /directory.json object shape the parser expects ({"artifacts":[...]}). */
static void bbf_directory_json(char *out, size_t cap)
{
    char arts[2560];
    size_t an = rom_seed_directory_json(arts, sizeof(arts));
    const char *body = (an > 0) ? arts : "[]";
    snprintf(out, cap, "{\"count\":0,\"artifacts\":%s}", body);
}

/* ── (a) Gate ───────────────────────────────────────────────────────────── */

static int case_gate(void)
{
    int failures = 0;
    TEST("boot_bundle_fetch: gate runs on a fresh datadir, skips otherwise") {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "bbf_gate", "ok");

        /* Fresh, marker-less, no bundle → run. */
        ASSERT(boot_bundle_fetch_should_run(dir, NULL));

        /* Opt-out via env. */
        setenv("ZCL_NO_BUNDLE_FETCH", "1", 1);
        ASSERT(!boot_bundle_fetch_should_run(dir, NULL));
        unsetenv("ZCL_NO_BUNDLE_FETCH");
        ASSERT(boot_bundle_fetch_should_run(dir, NULL));

        /* Opt-out via -nofilesync (ctx->no_file_sync). */
        struct app_context ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.no_file_sync = true;
        ASSERT(!boot_bundle_fetch_should_run(dir, &ctx));
        ctx.no_file_sync = false;
        ASSERT(boot_bundle_fetch_should_run(dir, &ctx));

        /* Empty datadir → never runs. */
        ASSERT(!boot_bundle_fetch_should_run("", NULL));

        /* Sovereign marker present → never re-fetch. */
        uint8_t digest[32];
        memset(digest, 0xab, sizeof(digest));
        ASSERT(boot_consensus_bundle_marker_write(dir, 3056758, digest));
        ASSERT(!boot_bundle_fetch_should_run(dir, NULL));

        test_rm_rf_recursive(dir);

        /* A *.sqlite already staged under bundles/ → autodetect installs it, so
         * the weld skips the download. */
        char dir2[256];
        test_make_tmpdir(dir2, sizeof(dir2), "bbf_gate_staged", "ok");
        char bundles[320];
        snprintf(bundles, sizeof(bundles), "%s/bundles", dir2);
        ASSERT(mkdir(bundles, 0700) == 0);
        char staged[400];
        snprintf(staged, sizeof(staged), "%s/consensus-state-bundle-1.sqlite",
                 bundles);
        FILE *sf = fopen(staged, "w");
        ASSERT(sf != NULL);
        fclose(sf);
        ASSERT(!boot_bundle_fetch_should_run(dir2, NULL));
        test_rm_rf_recursive(dir2);
    } _test_next:;
    return failures;
}

/* A REGTEST (or testnet) node must never attempt to acquire mainnet bundle
 * state. The gate did not exist until 2026-07-29: `-regtest` isolated the P2P
 * wire and nothing else, so a sealed fixture ran the instant-on weld, reached
 * the operator's LIVE node on its file-service port and pulled ~1 GB of real
 * mainnet chain into an empty regtest datadir — twice. The artifact is bound at
 * install to the compiled CHECKPOINT_ROM, which is a MAINNET checkpoint, so a
 * non-mainnet node has nothing to gain from the fetch and a live node to leak
 * into by attempting it. */
static int case_network_gate(void)
{
    int failures = 0;
    TEST("boot_bundle_fetch: non-mainnet never attempts bundle acquisition") {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "bbf_netgate", "ok");

        struct app_context ctx;

        /* Baseline: a fresh mainnet datadir IS eligible, so the assertions
         * below are proving the network gate and not an unrelated skip. */
        memset(&ctx, 0, sizeof(ctx));
        ASSERT(boot_bundle_fetch_should_run(dir, &ctx));

        /* -regtest → never. */
        ctx.regtest = true;
        ASSERT(!boot_bundle_fetch_should_run(dir, &ctx));

        /* -testnet → never either. The gate is "is mainnet", not
         * "is not regtest": a testnet node must not pull a mainnet bundle. */
        memset(&ctx, 0, sizeof(ctx));
        ctx.testnet = true;
        ASSERT(!boot_bundle_fetch_should_run(dir, &ctx));

        /* Both flags together (nonsense argv) still refuses. */
        ctx.regtest = true;
        ASSERT(!boot_bundle_fetch_should_run(dir, &ctx));

        /* Back to mainnet → eligible again, so the gate is the only thing that
         * changed hands here. */
        memset(&ctx, 0, sizeof(ctx));
        ASSERT(boot_bundle_fetch_should_run(dir, &ctx));

        /* End to end: the whole weld is a no-op on regtest even when a
         * -connect peer is present. The peer names a port, so fix (b) already
         * assembles ZERO seeds — a regression in EITHER gate alone still
         * cannot produce an outbound dial from this assertion. */
        memset(&ctx, 0, sizeof(ctx));
        ctx.regtest = true;
        ctx.connect_only = true;
        ctx.connect_peers[0] = "127.0.0.1:39099";
        ctx.n_connect_peers = 1;
        ASSERT(boot_bundle_fetch_seed_count(&ctx) == 0);
        ASSERT(!boot_bundle_fetch_maybe(dir, &ctx));

        test_rm_rf_recursive(dir);
    } _test_next:;
    return failures;
}

/* ── (b) Manifest pick from a /directory.json body ──────────────────────── */

static int case_pick(void)
{
    int failures = 0;
    TEST("boot_bundle_fetch: pick_manifest chooses + names the bundle artifact") {
        /* A single sane artifact: 2 chunks (one full + a 4 KB tail). */
        uint64_t size = (uint64_t)ROM_SEED_CHUNK_SIZE + 4096;
        char body[512];
        snprintf(body, sizeof(body),
                 "{\"artifacts\":[{\"kind\":\"consensus_state_bundle\","
                 "\"digest\":\"%064d\",\"whole_sha3\":\"%064d\","
                 "\"size\":%llu,\"chunk_size\":%u,\"chunks\":2}]}",
                 1, 2, (unsigned long long)size, (unsigned)ROM_SEED_CHUNK_SIZE);

        struct rom_fetch_manifest m;
        memset(&m, 0, sizeof(m));
        ASSERT(boot_bundle_pick_manifest(body, &m));
        ASSERT(m.size_bytes == size);
        ASSERT(m.num_chunks == 2);
        ASSERT(m.chunk_size == ROM_SEED_CHUNK_SIZE);
        /* Assigned a classifiable *.sqlite name (directory.json carries none). */
        ASSERT(strncmp(m.filename, "consensus-state-bundle-", 23) == 0);
        size_t fl = strlen(m.filename);
        ASSERT(fl > 7 && strcmp(m.filename + fl - 7, ".sqlite") == 0);
        ASSERT(rom_fetch_manifest_sane(&m));

        /* Negative: no artifacts, garbage, NULL → refused. */
        struct rom_fetch_manifest z;
        ASSERT(!boot_bundle_pick_manifest("{\"artifacts\":[]}", &z));
        ASSERT(!boot_bundle_pick_manifest("{not json", &z));
        ASSERT(!boot_bundle_pick_manifest(NULL, &z));
    } _test_next:;
    return failures;
}

/* ── (b2) Kind-aware selection: bundle vs header seed ───────────────────── */

static int case_pick_kinds(void)
{
    int failures = 0;
    TEST("boot_bundle_fetch: kind-aware pick separates bundle from header seed") {
        uint64_t bundle_size = (uint64_t)ROM_SEED_CHUNK_SIZE + 4096; /* 2 chunks */
        uint64_t hs_size = 3ull * (uint64_t)ROM_SEED_CHUNK_SIZE;     /* 3 chunks, LARGER */

        /* A directory advertising BOTH artifacts, header seed LARGER than the
         * bundle — proves selection is by KIND, not size. */
        char body[1024];
        snprintf(body, sizeof(body),
                 "{\"artifacts\":["
                 "{\"kind\":\"consensus_bundle\",\"digest\":\"%064d\","
                 "\"whole_sha3\":\"%064d\",\"size\":%llu,\"chunk_size\":%u,"
                 "\"chunks\":2},"
                 "{\"kind\":\"header_seed\",\"digest\":\"%064d\","
                 "\"whole_sha3\":\"%064d\",\"size\":%llu,\"chunk_size\":%u,"
                 "\"chunks\":3}]}",
                 1, 2, (unsigned long long)bundle_size,
                 (unsigned)ROM_SEED_CHUNK_SIZE,
                 3, 4, (unsigned long long)hs_size,
                 (unsigned)ROM_SEED_CHUNK_SIZE);

        /* Bundle pick returns the consensus bundle (the SMALLER artifact) and a
         * classifiable *.sqlite name — never the larger header seed. */
        struct rom_fetch_manifest bm;
        memset(&bm, 0, sizeof(bm));
        ASSERT(boot_bundle_pick_manifest(body, &bm));
        ASSERT(bm.size_bytes == bundle_size);
        ASSERT(bm.kind == ROM_ARTIFACT_CONSENSUS_BUNDLE);
        ASSERT(strncmp(bm.filename, "consensus-state-bundle-", 23) == 0);

        /* Header-seed pick returns the header seed with the block_index.bin name. */
        struct rom_fetch_manifest hm;
        memset(&hm, 0, sizeof(hm));
        ASSERT(boot_bundle_pick_header_seed_manifest(body, &hm));
        ASSERT(hm.size_bytes == hs_size);
        ASSERT(hm.kind == ROM_ARTIFACT_HEADER_SEED);
        ASSERT(strcmp(hm.filename, "block_index.bin") == 0);
        ASSERT(rom_fetch_manifest_sane(&hm));

        /* Legacy back-compat: a directory with NO kind field → bundle pick
         * still returns the (largest) artifact; header-seed pick returns false
         * (a header seed cannot be advertised without the kind token). */
        char legacy[512];
        snprintf(legacy, sizeof(legacy),
                 "{\"artifacts\":[{\"digest\":\"%064d\",\"whole_sha3\":\"%064d\","
                 "\"size\":%llu,\"chunk_size\":%u,\"chunks\":2}]}",
                 5, 6, (unsigned long long)bundle_size,
                 (unsigned)ROM_SEED_CHUNK_SIZE);
        struct rom_fetch_manifest lm;
        memset(&lm, 0, sizeof(lm));
        ASSERT(boot_bundle_pick_manifest(legacy, &lm));
        ASSERT(lm.size_bytes == bundle_size);
        struct rom_fetch_manifest lh;
        memset(&lh, 0, sizeof(lh));
        ASSERT(!boot_bundle_pick_header_seed_manifest(legacy, &lh));

        /* A bundle-only directory → header-seed pick returns false. */
        struct rom_fetch_manifest none;
        memset(&none, 0, sizeof(none));
        ASSERT(!boot_bundle_pick_header_seed_manifest(
                   "{\"artifacts\":[{\"kind\":\"consensus_bundle\","
                   "\"digest\":\"" "0000000000000000000000000000000000000000000000000000000000000001"
                   "\",\"whole_sha3\":\"" "0000000000000000000000000000000000000000000000000000000000000002"
                   "\",\"size\":8192,\"chunk_size\":4194304,\"chunks\":1}]}",
                   &none));
    } _test_next:;
    return failures;
}

/* ── (c)+(d) E2E against the real serve path ────────────────────────────── */

static int case_e2e(void)
{
    int failures = 0;
    TEST("boot_bundle_fetch: E2E download lands + install fires + guards hold") {
        rom_seed_reset();
        /* Move ~3x the artifact inside one wall-second — raise the byte caps so
         * the outcome is not wall-clock dependent (reset restores defaults). */
        rom_seed_set_peer_bps_cap(1ull << 30);
        rom_seed_set_global_bps_cap(1ull << 30);

        char sroot[] = "/tmp/zcl_bbf_srv_XXXXXX";
        char *sdir = mkdtemp(sroot);
        ASSERT(sdir != NULL);

        /* 2 chunks: one full 4 MB chunk + a short 4 KB tail. */
        size_t size = (size_t)ROM_SEED_CHUNK_SIZE + 4096;
        uint8_t *content = malloc(size);
        ASSERT(content != NULL);
        bbf_gen_content(content, size);
        ASSERT(bbf_write_file(sdir, "consensus-state-bundle-3056758.sqlite",
                              content, size));

        struct rom_artifact art;
        ASSERT(rom_seed_register(sdir, "consensus-state-bundle-3056758.sqlite",
                                 NULL, &art) == ROM_REG_OK);

                uint16_t port = 0;
        fs_server_start(sdir, 0); /* OS-assigned: no cross-checkout port collisions */
        for (int w = 0; w < 40 && !fs_server_is_running(); w++)
            platform_sleep_ms(50);
        if (fs_server_is_running())
            port = fs_server_get_port();
        ASSERT(port != 0);

        /* pick_manifest consumes the seeder's REAL directory.json. */
        char dirjson[3072];
        bbf_directory_json(dirjson, sizeof(dirjson));
        struct rom_fetch_manifest m;
        memset(&m, 0, sizeof(m));
        ASSERT(boot_bundle_pick_manifest(dirjson, &m));
        ASSERT(memcmp(m.chunk_root, art.chunk_root, 32) == 0);
        ASSERT(m.size_bytes == art.size_bytes);
        ASSERT(m.num_chunks == art.num_chunks);

        /* (c) Download core lands the content-verified bundle in bundles/. */
        char croot[] = "/tmp/zcl_bbf_cli_XXXXXX";
        char *cdir = mkdtemp(croot);
        ASSERT(cdir != NULL);
        struct rom_fetch_peer peers[1];
        memset(peers, 0, sizeof(peers));
        snprintf(peers[0].addr, sizeof(peers[0].addr), "%s", "127.0.0.1");
        peers[0].port = port;

        ASSERT(boot_bundle_fetch_download(cdir, peers, 1, &m));
        char landed[1200];
        snprintf(landed, sizeof(landed), "%s/bundles/%s", cdir, m.filename);
        ASSERT(rom_fetch_verify_file(landed, &m));

        /* Reseed (Lane A2): the just-landed bundle is registered with rom_seed
         * IMMEDIATELY on download success — no restart, no scan needed — so
         * this node is already a swarm source for it. Assert via the rom_seed
         * catalog API (rom_seed_list) that a "bundles/<filename>" entry exists
         * with the SAME chunk_root the source artifact carries. */
        {
            char want[ROM_SEED_NAME_MAX];
            snprintf(want, sizeof(want), "%s/%s", ROM_SEED_BUNDLES_SUBDIR,
                     m.filename);
            struct rom_artifact cat[ROM_SEED_MAX_ARTIFACTS];
            int cn = rom_seed_list(cat, ROM_SEED_MAX_ARTIFACTS);
            bool reseed_found = false;
            for (int i = 0; i < cn; i++) {
                if (strcmp(cat[i].filename, want) != 0)
                    continue;
                reseed_found = true;
                ASSERT(memcmp(cat[i].chunk_root, art.chunk_root, 32) == 0);
                ASSERT(cat[i].size_bytes == m.size_bytes);
                ASSERT(cat[i].num_chunks == m.num_chunks);
                break;
            }
            ASSERT(reseed_found);
        }

        /* Install FIRES: the autodetect now finds the downloaded bundle. */
        char *auto_path = boot_autodetect_consensus_bundle(cdir);
        ASSERT(auto_path != NULL);
        ASSERT(strcmp(auto_path, landed) == 0);

        /* Sovereignty: this synthetic (non-checkpoint) bundle is REFUSED at
         * install — fail-closed at admission, no state, NO marker. */
        struct consensus_state_install_runtime_result rr;
        struct zcl_result r =
            consensus_state_install_from_bundle(NULL, NULL, auto_path, cdir, &rr);
        ASSERT(!r.ok);
        ASSERT(!rr.state_installed);
        ASSERT(!rr.marker_written);
        ASSERT(!boot_consensus_bundle_marker_exists(cdir));
        free(auto_path);

        /* Byte-mismatch: a wrong committed whole-digest downloads every chunk,
         * fails the whole-file content proof, and lands NOTHING → no install. */
        char croot2[] = "/tmp/zcl_bbf_bad_XXXXXX";
        char *cdir2 = mkdtemp(croot2);
        ASSERT(cdir2 != NULL);
        struct rom_fetch_manifest bad = m;
        bad.whole_sha3[0] ^= 0x01;
        ASSERT(!boot_bundle_fetch_download(cdir2, peers, 1, &bad));
        char *bad_auto = boot_autodetect_consensus_bundle(cdir2);
        ASSERT(bad_auto == NULL); /* nothing installable landed */
        free(bad_auto);
        /* Nothing landed on disk for cdir2 at all, so there is nothing rom_seed
         * could have (re-)registered for it either — the reseed call only runs
         * on the success path, guarded by boot_bundle_fetch_download's own
         * `if (!ok) return false;` above the reseed block. */

        /* (d) Production entry: a directory.json hint + -fileservice peer drives
         * the whole gate → pick → seed-assembly → download → land path. */
        char croot3[] = "/tmp/zcl_bbf_maybe_XXXXXX";
        char *cdir3 = mkdtemp(croot3);
        ASSERT(cdir3 != NULL);
        char b3[400];
        snprintf(b3, sizeof(b3), "%s/bundles", cdir3);
        ASSERT(mkdir(b3, 0700) == 0);
        ASSERT(bbf_write_file(b3, "directory.json",
                              (const uint8_t *)dirjson, strlen(dirjson)));

        struct app_context ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.datadir = cdir3;
        /* host:port so the weld's peer parse targets the loopback seeder; and
         * connect_only so the hardcoded (unreachable-in-test) clearnet seeds are
         * skipped — deterministic + fast. */
        char peer_hp[64];
        snprintf(peer_hp, sizeof(peer_hp), "127.0.0.1:%u", (unsigned)port);
        ctx.file_service_peer = peer_hp;
        ctx.connect_only = true;

        ASSERT(boot_bundle_fetch_maybe(cdir3, &ctx));
        char *auto3 = boot_autodetect_consensus_bundle(cdir3);
        ASSERT(auto3 != NULL);
        free(auto3);
        /* The production entry point reseeds too (it drives the same
         * boot_bundle_fetch_download core). */
        {
            char want3[ROM_SEED_NAME_MAX];
            snprintf(want3, sizeof(want3), "%s/%s", ROM_SEED_BUNDLES_SUBDIR,
                     m.filename);
            struct rom_artifact cat3[ROM_SEED_MAX_ARTIFACTS];
            int cn3 = rom_seed_list(cat3, ROM_SEED_MAX_ARTIFACTS);
            bool reseed_found3 = false;
            for (int i = 0; i < cn3; i++) {
                if (strcmp(cat3[i].filename, want3) == 0) {
                    reseed_found3 = true;
                    break;
                }
            }
            ASSERT(reseed_found3);
        }

        fs_server_stop();
        free(content);
        test_rm_rf_recursive(cdir);
        test_rm_rf_recursive(cdir2);
        test_rm_rf_recursive(cdir3);
        rmdir(sdir);
        rom_seed_reset();
    } _test_next:;
    return failures;
}

/* ── (e) Baked-facts cross-check + quorum decision (pure) ────────────────── */

static int case_baked_facts(void)
{
    int failures = 0;
    TEST("boot_bundle_fetch: baked-facts cross-check rejects off-shape manifests") {
        struct rom_fetch_manifest m;
        memset(&m, 0, sizeof(m));
        m.chunk_size = ROM_SEED_CHUNK_SIZE;
        m.size_bytes = (uint64_t)ROM_SEED_CHUNK_SIZE + 4096;
        m.num_chunks = 2; /* ceil((CHUNK+4096)/CHUNK) */
        ASSERT(boot_bundle_manifest_facts_ok_for_test(&m));

        /* num_chunks != ceil(size/chunk). */
        struct rom_fetch_manifest bad = m;
        bad.num_chunks = 3;
        ASSERT(!boot_bundle_manifest_facts_ok_for_test(&bad));

        /* chunk_size != ROM_SEED_CHUNK_SIZE. */
        bad = m;
        bad.chunk_size = 1234;
        ASSERT(!boot_bundle_manifest_facts_ok_for_test(&bad));

        /* size below ROM_SEED_MIN_ARTIFACT_BYTES (num_chunks consistent). */
        bad = m;
        bad.size_bytes = 100;
        bad.num_chunks = 1;
        ASSERT(!boot_bundle_manifest_facts_ok_for_test(&bad));

        ASSERT(!boot_bundle_manifest_facts_ok_for_test(NULL));
    } _test_next:;
    return failures;
}

static int case_quorum(void)
{
    int failures = 0;
    /* STEP 0: the export is NOT byte-deterministic across independent nodes, so
     * a per-height triple quorum almost never forms across a mixed fleet. The
     * pick therefore ranks NEWEST-height-first (bandwidth-DoS guard, not a trust
     * source — trust binds at install), and a lone non-explicit newest candidate
     * is ACCEPTED (no longer refused). heights is the new first argument. */
    TEST("boot_bundle_fetch: quorum ranks newest-height-first, never refuses a "
         "valid newest candidate") {
        /* No candidates → still -1. */
        ASSERT(boot_bundle_quorum_pick_for_test(NULL, NULL, NULL, 0) == -1);

        /* REGRESSION (the bug this fixes): a lone non-explicit seed used to be
         * REFUSED (→ silent fall-open to from-genesis IBD). Now it is ACCEPTED —
         * a fresh consumer must be able to use the one bundle on offer. */
        int64_t h1[] = { 3056758 };
        int c1[] = { 1 };
        bool f_false[] = { false };
        ASSERT(boot_bundle_quorum_pick_for_test(h1, c1, f_false, 1) == 0);

        /* Lone explicit -fileservice seed → also accepted. */
        bool f_true[] = { true };
        ASSERT(boot_bundle_quorum_pick_for_test(h1, c1, f_true, 1) == 0);

        /* Highest height wins regardless of count/explicit: a lower-height
         * 2-seed / explicit candidate does NOT shadow a higher-height lone one. */
        int64_t hh[] = { 3000000, 3056758 };
        int lowmore[] = { 2, 1 };
        bool lowexpl[] = { true, false };
        ASSERT(boot_bundle_quorum_pick_for_test(hh, lowmore, lowexpl, 2) == 1);

        /* THE mixed-height regression case: two distinct single-seed triples at
         * two heights (exports are not cross-node deterministic, so no two seeds
         * share a triple). Must pick the NEWEST (index 1), never -1 / fall open
         * to IBD. */
        int64_t mixed_h[] = { 3000000, 3056758 };
        int mixed_c[] = { 1, 1 };
        bool mixed_f[] = { false, false };
        ASSERT(boot_bundle_quorum_pick_for_test(mixed_h, mixed_c, mixed_f, 2)
               == 1);

        /* Same height: higher count wins (a >=2-seed triple beats a lone one). */
        int64_t same_h[] = { 3056758, 3056758 };
        int same_c[] = { 1, 2 };
        bool same_f[] = { false, false };
        ASSERT(boot_bundle_quorum_pick_for_test(same_h, same_c, same_f, 2) == 1);

        /* Same height, tie count → prefer the explicit-seed candidate. */
        int64_t tie_h[] = { 3056758, 3056758 };
        int tie_c[] = { 1, 1 };
        bool tie_f[] = { false, true };
        ASSERT(boot_bundle_quorum_pick_for_test(tie_h, tie_c, tie_f, 2) == 1);
    } _test_next:;
    return failures;
}

/* ── (e2) Newest-by-height pick + legacy size fallback (GAP-4) ──────────── */

static int case_pick_newest(void)
{
    int failures = 0;
    TEST("boot_bundle_fetch: pick_manifest chooses the NEWEST height + names it") {
        uint64_t size = (uint64_t)ROM_SEED_CHUNK_SIZE + 4096;
        /* Two consensus_bundle-kinded artifacts at different heights; the newer
         * (3056758) must win even though it is listed first and same-sized. */
        char body[1024];
        snprintf(body, sizeof(body),
                 "{\"artifacts\":["
                 "{\"kind\":\"consensus_bundle\",\"digest\":\"%064d\","
                 "\"whole_sha3\":\"%064d\",\"size\":%llu,\"chunk_size\":%u,"
                 "\"chunks\":2,\"height\":3056758},"
                 "{\"kind\":\"consensus_bundle\",\"digest\":\"%064d\","
                 "\"whole_sha3\":\"%064d\",\"size\":%llu,\"chunk_size\":%u,"
                 "\"chunks\":2,\"height\":3000000}]}",
                 1, 2, (unsigned long long)size, (unsigned)ROM_SEED_CHUNK_SIZE,
                 3, 4, (unsigned long long)size, (unsigned)ROM_SEED_CHUNK_SIZE);

        struct rom_fetch_manifest m;
        memset(&m, 0, sizeof(m));
        ASSERT(boot_bundle_pick_manifest(body, &m));
        ASSERT(m.height == 3056758);
        /* Named by the ADVERTISED height (not the compiled checkpoint). */
        ASSERT(strcmp(m.filename, "consensus-state-bundle-3056758.sqlite") == 0);
        ASSERT(rom_fetch_manifest_sane(&m));

        /* LEGACY fallback: no kind (→ UNKNOWN) and no height (→ 0) on either
         * entry → the picker falls back to LARGEST size, and names the file from
         * the compiled checkpoint height (height 0 → not advertised). */
        uint64_t small = (uint64_t)ROM_SEED_CHUNK_SIZE + 4096; /* 2 chunks */
        uint64_t big = (uint64_t)ROM_SEED_CHUNK_SIZE * 2 + 4096; /* 3 chunks */
        char legacy[1024];
        snprintf(legacy, sizeof(legacy),
                 "{\"artifacts\":["
                 "{\"digest\":\"%064d\",\"whole_sha3\":\"%064d\",\"size\":%llu,"
                 "\"chunk_size\":%u,\"chunks\":2},"
                 "{\"digest\":\"%064d\",\"whole_sha3\":\"%064d\",\"size\":%llu,"
                 "\"chunk_size\":%u,\"chunks\":3}]}",
                 5, 6, (unsigned long long)small, (unsigned)ROM_SEED_CHUNK_SIZE,
                 7, 8, (unsigned long long)big, (unsigned)ROM_SEED_CHUNK_SIZE);
        struct rom_fetch_manifest lm;
        memset(&lm, 0, sizeof(lm));
        ASSERT(boot_bundle_pick_manifest(legacy, &lm));
        ASSERT(lm.height == 0);         /* legacy: no height advertised */
        ASSERT(lm.size_bytes == big);   /* largest wins in the legacy path */
        ASSERT(strncmp(lm.filename, "consensus-state-bundle-", 23) == 0);
        size_t fl = strlen(lm.filename);
        ASSERT(fl > 7 && strcmp(lm.filename + fl - 7, ".sqlite") == 0);
    } _test_next:;
    return failures;
}

/* ── (f) Absent-local-manifest → RLS discovery drives the whole path ─────── */

static int case_discovery(void)
{
    int failures = 0;
    TEST("boot_bundle_fetch: no local hint → RLS discovery lands + persists it") {
        rom_seed_reset();
        rom_seed_set_peer_bps_cap(1ull << 30);
        rom_seed_set_global_bps_cap(1ull << 30);

        char sroot[] = "/tmp/zcl_bbf_disc_srv_XXXXXX";
        char *sdir = mkdtemp(sroot);
        ASSERT(sdir != NULL);

        size_t size = (size_t)ROM_SEED_CHUNK_SIZE + 4096;
        uint8_t *content = malloc(size);
        ASSERT(content != NULL);
        bbf_gen_content(content, size);
        ASSERT(bbf_write_file(sdir, "consensus-state-bundle-3056758.sqlite",
                              content, size));
        struct rom_artifact art;
        ASSERT(rom_seed_register(sdir, "consensus-state-bundle-3056758.sqlite",
                                 NULL, &art) == ROM_REG_OK);

                uint16_t port = 0;
        fs_server_start(sdir, 0); /* OS-assigned: no cross-checkout port collisions */
        for (int w = 0; w < 40 && !fs_server_is_running(); w++)
            platform_sleep_ms(50);
        if (fs_server_is_running())
            port = fs_server_get_port();
        ASSERT(port != 0);

        /* Fresh client datadir with NO bundles/directory.json hint. The explicit
         * -fileservice peer + connect_only (no clearnet seeds) makes the lone
         * reachable seed the operator-named one → quorum=1 accepted. */
        char croot[] = "/tmp/zcl_bbf_disc_cli_XXXXXX";
        char *cdir = mkdtemp(croot);
        ASSERT(cdir != NULL);

        struct app_context ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.datadir = cdir;
        char peer_hp[64];
        snprintf(peer_hp, sizeof(peer_hp), "127.0.0.1:%u", (unsigned)port);
        ctx.file_service_peer = peer_hp;
        ctx.connect_only = true;

        /* No local hint exists yet. */
        char hint[512];
        snprintf(hint, sizeof(hint), "%s/bundles/directory.json", cdir);
        ASSERT(access(hint, F_OK) != 0);

        ASSERT(boot_bundle_fetch_maybe(cdir, &ctx));

        /* Discovery persisted the winning directory.json for resume/reseed. */
        ASSERT(access(hint, F_OK) == 0);
        /* And the content-verified bundle landed → autodetect installs it. */
        char *auto_p = boot_autodetect_consensus_bundle(cdir);
        ASSERT(auto_p != NULL);
        free(auto_p);

        fs_server_stop();
        free(content);
        test_rm_rf_recursive(cdir);
        char p[1024];
        snprintf(p, sizeof(p), "%s/consensus-state-bundle-3056758.sqlite", sdir);
        unlink(p);
        rmdir(sdir);
        rom_seed_reset();
    } _test_next:;
    return failures;
}

/* ── Discovery-outcome observability (bbf_record_discovery_outcome /
 * boot_bundle_fetch_discovery_dump_state_json, config/src/boot_bundle_
 * fetch.c) ──────────────────────────────────────────────────────────────
 *
 * Proves bbf_discover_from_peers() persists a labeled outcome + seed/
 * response counts that the diagnostics dumper reads back correctly, for
 * both the lone-explicit-seed "degraded_single_seed" case (the exact case_discovery scenario above) and
 * the "no_quorum_fell_open_to_ibd" case (a reachable seed that serves an
 * empty directory — responds, but advertises no usable bundle manifest). */
static int case_discovery_outcome_persists(void)
{
    int failures = 0;
    TEST("boot_bundle_fetch: discovery outcome persists + the diagnostics "
         "dumper reads it back labeled") {
        char proot[] = "/tmp/zcl_bbf_disc_outcome_prog_XXXXXX";
        char *pdir = mkdtemp(proot);
        ASSERT(pdir != NULL);
        progress_store_close();
        ASSERT(progress_store_open(pdir));

        /* ── (1) degraded_single_seed: same shape as case_discovery — a lone
         * EXPLICIT seed serving a real registered artifact proceeds under
         * ranked discovery, but with fetch redundancy 1 the recorded outcome
         * is "degraded_single_seed" ("reached" is reserved for a >=2-seed
         * byte-identical winner; explicitness does not add redundancy). ── */
        rom_seed_reset();
        rom_seed_set_peer_bps_cap(1ull << 30);
        rom_seed_set_global_bps_cap(1ull << 30);

        char sroot[] = "/tmp/zcl_bbf_disc_outcome_srv_XXXXXX";
        char *sdir = mkdtemp(sroot);
        ASSERT(sdir != NULL);

        size_t size = (size_t)ROM_SEED_CHUNK_SIZE + 4096;
        uint8_t *content = malloc(size);
        ASSERT(content != NULL);
        bbf_gen_content(content, size);
        ASSERT(bbf_write_file(sdir, "consensus-state-bundle-3056758.sqlite",
                              content, size));
        struct rom_artifact art;
        ASSERT(rom_seed_register(sdir, "consensus-state-bundle-3056758.sqlite",
                                 NULL, &art) == ROM_REG_OK);

                uint16_t port = 0;
        fs_server_start(sdir, 0); /* OS-assigned: no cross-checkout port collisions */
        for (int w = 0; w < 40 && !fs_server_is_running(); w++)
            platform_sleep_ms(50);
        if (fs_server_is_running())
            port = fs_server_get_port();
        ASSERT(port != 0);

        char croot[] = "/tmp/zcl_bbf_disc_outcome_cli_XXXXXX";
        char *cdir = mkdtemp(croot);
        ASSERT(cdir != NULL);

        struct app_context ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.datadir = cdir;
        char peer_hp[64];
        snprintf(peer_hp, sizeof(peer_hp), "127.0.0.1:%u", (unsigned)port);
        ctx.file_service_peer = peer_hp;
        ctx.connect_only = true;

        ASSERT(boot_bundle_fetch_maybe(cdir, &ctx));

        struct json_value out;
        json_init(&out);
        ASSERT(boot_bundle_fetch_discovery_dump_state_json(&out, NULL));
        ASSERT(json_get_bool(json_get(&out, "progress_store_open")));
        ASSERT(json_get_bool(json_get(&out, "outcome_recorded")));
        ASSERT_STR_EQ(json_get_str(json_get(&out, "outcome")),
                      "degraded_single_seed");
        ASSERT(json_get_int(json_get(&out, "seed_count")) >= 1);
        ASSERT(json_get_int(json_get(&out, "responded_count")) >= 1);
        json_free(&out);

        fs_server_stop();
        free(content);
        test_rm_rf_recursive(cdir);
        char p[1024];
        snprintf(p, sizeof(p), "%s/consensus-state-bundle-3056758.sqlite", sdir);
        unlink(p);
        rmdir(sdir);
        rom_seed_reset();

        /* ── (2) no_quorum_fell_open_to_ibd: a fresh explicit seed that
         * answers /directory.json but has registered NO artifact — the
         * peer responds (responded_count>=1) yet advertises nothing usable,
         * so this MUST overwrite the prior recorded outcome with the new
         * label rather than leaving the stale one. ── */
        char sroot2[] = "/tmp/zcl_bbf_disc_outcome_empty_srv_XXXXXX";
        char *sdir2 = mkdtemp(sroot2);
        ASSERT(sdir2 != NULL);

        uint16_t port2 = 0;
        fs_server_start(sdir2, 0); /* OS-assigned: no cross-checkout port collisions */
        for (int w = 0; w < 40 && !fs_server_is_running(); w++)
            platform_sleep_ms(50);
        if (fs_server_is_running())
            port2 = fs_server_get_port();
        ASSERT(port2 != 0);

        char croot2[] = "/tmp/zcl_bbf_disc_outcome_empty_cli_XXXXXX";
        char *cdir2 = mkdtemp(croot2);
        ASSERT(cdir2 != NULL);

        struct app_context ctx2;
        memset(&ctx2, 0, sizeof(ctx2));
        ctx2.datadir = cdir2;
        char peer_hp2[64];
        snprintf(peer_hp2, sizeof(peer_hp2), "127.0.0.1:%u", (unsigned)port2);
        ctx2.file_service_peer = peer_hp2;
        ctx2.connect_only = true;

        /* An empty seed cannot land a bundle — boot_bundle_fetch_maybe
         * returns false, but the discovery attempt still ran and its
         * outcome is still persisted (observability is independent of the
         * overall boot decision). */
        ASSERT(!boot_bundle_fetch_maybe(cdir2, &ctx2));

        json_init(&out);
        ASSERT(boot_bundle_fetch_discovery_dump_state_json(&out, NULL));
        ASSERT(json_get_bool(json_get(&out, "outcome_recorded")));
        ASSERT_STR_EQ(json_get_str(json_get(&out, "outcome")),
                      "no_quorum_fell_open_to_ibd");
        ASSERT(json_get_int(json_get(&out, "responded_count")) >= 1);
        json_free(&out);

        fs_server_stop();
        test_rm_rf_recursive(cdir2);
        rmdir(sdir2);
        rom_seed_reset();

        progress_store_close();
        test_rm_rf_recursive(pdir);
    } _test_next:;
    return failures;
}

/* The seed set the weld is PERMITTED to contact (config/src/
 * boot_bundle_fetch_seeds.c). The connect-only branch is the one that
 * structurally disabled the whole weld on the 2026-07-27 bare cold start: with
 * `-connect=` and no `-fileservice=` the set assembled to ZERO peers, nothing
 * was ever contacted, and the miss was then reported as `fetch=no_seed` — the
 * same token a genuine discovery miss produces. */
static int case_seed_set(void)
{
    int failures = 0;
    TEST("boot_bundle_fetch: seed set — connect-only uses the -connect hosts, "
         "never an empty set") {
        struct app_context ctx;

        /* (1) No flags at all: the compiled clearnet seeds (the operator's
         * own file-service seeds are runtime -fileservice=/-connect= values,
         * never compiled in — see config/bundle_fetch_seeds.h). */
        memset(&ctx, 0, sizeof(ctx));
        size_t open_seeds = boot_bundle_fetch_seed_count(&ctx);
        ASSERT(open_seeds >= 1);

        /* (2) connect-only with a -connect host that NAMES A PORT and no
         * -fileservice: REFUSED, zero seeds. This used to strip the port and
         * refill it with FS_PORT, which is how `-connect=127.0.0.1:39099` (a
         * deliberately dead sink that seals a fixture) became a dial to
         * 127.0.0.1:18034 — the operator's LIVE node — and pulled ~1 GB of
         * mainnet chain state into a regtest datadir. -connect means the
         * address it names; a port is never substituted. */
        memset(&ctx, 0, sizeof(ctx));
        ctx.connect_only = true;
        ctx.connect_peers[0] = "203.0.113.7:8033";
        ctx.n_connect_peers = 1;
        ASSERT(boot_bundle_fetch_seed_count(&ctx) == 0);

        /* The dead-sink shape every isolated fixture on this box uses. */
        ctx.connect_peers[0] = "127.0.0.1:39099";
        ASSERT(boot_bundle_fetch_seed_count(&ctx) == 0);

        /* More port-naming hosts are still zero — refusal is per value. */
        ctx.connect_peers[1] = "203.0.113.8:8033";
        ctx.n_connect_peers = 2;
        ASSERT(boot_bundle_fetch_seed_count(&ctx) == 0);

        /* (2b) A -connect value that names NO port is unchanged: the operator
         * named a host, so nothing is being overridden, and it seeds the file
         * service at FS_PORT. This is the case the seam was built for. */
        memset(&ctx, 0, sizeof(ctx));
        ctx.connect_only = true;
        ctx.connect_peers[0] = "203.0.113.7";
        ctx.n_connect_peers = 1;
        ASSERT(boot_bundle_fetch_seed_count(&ctx) == 1);

        /* Two distinct bare hosts → two seeds; the same host twice de-dups. */
        ctx.connect_peers[1] = "203.0.113.8";
        ctx.n_connect_peers = 2;
        ASSERT(boot_bundle_fetch_seed_count(&ctx) == 2);
        ctx.connect_peers[1] = "203.0.113.7";
        ASSERT(boot_bundle_fetch_seed_count(&ctx) == 1);

        /* (3) connect-only with NO usable host: still zero — the honest
         * "nothing was ever contacted" case nss_classify reports as
         * seeds_empty, NOT as no_seed. */
        memset(&ctx, 0, sizeof(ctx));
        ctx.connect_only = true;
        ASSERT(boot_bundle_fetch_seed_count(&ctx) == 0);

        /* (4) An explicit -fileservice peer is honoured VERBATIM, port and all,
         * and is additive to any usable -connect host. It takes slot 0. This is
         * the supported way to name a file-service seed on a specific port. */
        memset(&ctx, 0, sizeof(ctx));
        ctx.connect_only = true;
        ctx.file_service_peer = "198.51.100.9:19034";
        ctx.connect_peers[0] = "203.0.113.7";
        ctx.n_connect_peers = 1;
        ASSERT(boot_bundle_fetch_seed_count(&ctx) == 2);

        /* ...and a port-naming -connect alongside it adds nothing. */
        ctx.connect_peers[0] = "203.0.113.7:8033";
        ASSERT(boot_bundle_fetch_seed_count(&ctx) == 1);

        /* (5) NULL ctx must not crash and must not silently disable the weld. */
        ASSERT(boot_bundle_fetch_seed_count(NULL) == open_seeds);
    } _test_next:;
    return failures;
}

int test_boot_bundle_fetch(void)
{
    printf("\n=== boot_bundle_fetch ===\n");
    int failures = 0;
    failures += case_seed_set();
    failures += case_gate();
    failures += case_network_gate();
    failures += case_pick();
    failures += case_pick_kinds();
    failures += case_e2e();
    failures += case_baked_facts();
    failures += case_pick_newest();
    failures += case_quorum();
    failures += case_discovery();
    failures += case_discovery_outcome_persists();
    printf("=== boot_bundle_fetch: %d failure(s) ===\n", failures);
    return failures;
}
