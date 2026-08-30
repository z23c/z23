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
#include "config/bundle_fetch_seeds.h"          /* ZCL_BUNDLE_FETCH_CLEARNET_SEEDS */
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
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
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

static _Atomic int probe_active, probe_peak;
static bool delayed_directory_fetch(const char *addr, uint16_t port,
                                    char *buf, size_t cap)
{
    (void)addr;
    (void)port;
    int active = atomic_fetch_add(&probe_active, 1) + 1;
    int peak = atomic_load(&probe_peak);
    while (peak < active && !atomic_compare_exchange_weak(&probe_peak, &peak,
                                                           active)) {}
    platform_sleep_ms(50);
    atomic_fetch_sub(&probe_active, 1);
    return snprintf(buf, cap, "{}") == 2;
}
static int case_parallel_probe(void)
{
    int failures = 0;
    TEST("boot_bundle_fetch: seed directory probes overlap") {
        struct rom_fetch_peer peers[4] = {0};
        char bodies[4][8] = {{0}};
        bool responded[4] = {false};
        for (size_t i = 0; i < 4; i++) {
            snprintf(peers[i].addr, sizeof(peers[i].addr), "seed%zu", i);
            peers[i].port = (uint16_t)(18034 + i);
        }
        atomic_store(&probe_active, 0); atomic_store(&probe_peak, 0);
        ASSERT(boot_bundle_probe_directories_for_test(
                   peers, 4, &bodies[0][0], sizeof(bodies[0]), responded,
                   delayed_directory_fetch) == 4);
        ASSERT(atomic_load(&probe_peak) >= 2);
        ASSERT(responded[0] && responded[1] && responded[2] && responded[3]);
        PASS();
    } _test_next:;
    return failures;
}
/* ── (e1b) The per-chunk manifest pre-flight is a SWEEP, not a walk ──────
 *
 * A seed that accepts and then goes silent costs the connect budget plus the
 * probe budget. Walking the seed set multiplied that by the seed count before
 * boot could give up; sweeping it makes the worst case one seed's budget.
 * The two properties that must hold together: the probes OVERLAP, and the
 * winner is still the lowest-indexed seed with a matching chunk count, so
 * seed ordering remains policy and concurrency is only about the clock. */

static _Atomic int rmf_active, rmf_peak;
/* Seed 0 answers with the WRONG chunk count, seed 1 and seed 2 with the right
 * one but different digests — so "lowest matching index wins" is observable. */
static bool delayed_manifest_fetch(const char *addr, uint16_t port,
                                   const uint8_t chunk_root[32],
                                   uint8_t (*out)[32], uint32_t cap,
                                   uint32_t *out_n)
{
    (void)chunk_root;
    (void)port;
    int active = atomic_fetch_add(&rmf_active, 1) + 1;
    int peak = atomic_load(&rmf_peak);
    while (peak < active && !atomic_compare_exchange_weak(&rmf_peak, &peak,
                                                          active)) {}
    platform_sleep_ms(50);
    atomic_fetch_sub(&rmf_active, 1);
    if (cap < 4)
        return false;
    unsigned which = (unsigned)(addr[strlen(addr) - 1] - '0');
    /* Seed 0 is the "answers, but not about this artifact" case. */
    *out_n = which == 0 ? 3u : 4u;
    for (uint32_t k = 0; k < *out_n; k++)
        memset(out[k], (int)(0x10u * (which + 1u) + k), 32);
    return true;
}

static int case_parallel_manifest_probe(void)
{
    int failures = 0;
    TEST("boot_bundle_fetch: the per-chunk manifest pre-flight sweeps every "
         "seed at once and still settles on the lowest-indexed match") {
        struct rom_fetch_peer peers[4] = {0};
        for (size_t i = 0; i < 4; i++) {
            snprintf(peers[i].addr, sizeof(peers[i].addr), "seed%zu", i);
            peers[i].port = (uint16_t)(18034 + i);
        }
        uint8_t root[32];
        memset(root, 0x77, sizeof(root));
        uint8_t digests[8][32];
        memset(digests, 0, sizeof(digests));
        uint32_t n = 0;

        atomic_store(&rmf_active, 0);
        atomic_store(&rmf_peak, 0);
        int64_t t0 = platform_time_monotonic_ms();
        ASSERT(boot_bundle_probe_manifest_for_test(peers, 4, root, 4, digests,
                                                   8, &n,
                                                   delayed_manifest_fetch));
        int64_t elapsed = platform_time_monotonic_ms() - t0;

        /* OVERLAP: at least two seeds were in flight together, and four 50 ms
         * probes did not cost four 50 ms waits. */
        ASSERT(atomic_load(&rmf_peak) >= 2);
        ASSERT(elapsed < 4 * 50);

        /* ORDERING: seed 0 answered first but about a 3-chunk artifact, so it
         * is not a match; seed 1 is the lowest-indexed seed that IS. */
        ASSERT(n == 4);
        uint8_t expect[32];
        memset(expect, 0x20, sizeof(expect)); /* 0x10 * (1 + 1) + 0 */
        ASSERT(memcmp(digests[0], expect, 32) == 0);
        memset(expect, 0x23, sizeof(expect)); /* 0x10 * (1 + 1) + 3 */
        ASSERT(memcmp(digests[3], expect, 32) == 0);

        /* A sweep that matches nothing must report that, not a partial fill. */
        uint32_t none = 0;
        ASSERT(!boot_bundle_probe_manifest_for_test(peers, 4, root, 9, digests,
                                                    8, &none,
                                                    delayed_manifest_fetch));
        ASSERT(none == 0);
        PASS();
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

        /* (1) No flags at all: exactly the compiled clearnet seed set, whose
         * length this reads rather than assuming. The set is EMPTY by policy —
         * this project's own file-service endpoints are runtime
         * -fileservice=/-connect= values and are never compiled in (see
         * config/bundle_fetch_seeds.h), and no third-party seed is vouched for
         * in-tree. Asserting equality instead of ">= 1" keeps this case honest
         * whichever way that list later moves. */
        memset(&ctx, 0, sizeof(ctx));
        size_t compiled_seeds = 0;
        while (ZCL_BUNDLE_FETCH_CLEARNET_SEEDS[compiled_seeds])
            compiled_seeds++;
        size_t open_seeds = boot_bundle_fetch_seed_count(&ctx);
        ASSERT(open_seeds == compiled_seeds);

        /* (2) connect-only with `-connect=host:8033` (the published mainnet
         * P2P port) and no `-fileservice`: seeds file-service at host:FS_PORT.
         * That is the new-node command. A NON-default port stays refused, which
         * is how `-connect=127.0.0.1:39099` (a deliberately dead fixture sink)
         * must not become a dial to 127.0.0.1:18034. */
        memset(&ctx, 0, sizeof(ctx));
        ctx.connect_only = true;
        ctx.connect_peers[0] = "203.0.113.7:8033";
        ctx.n_connect_peers = 1;
        ASSERT(boot_bundle_fetch_seed_count(&ctx) == 1);

        /* The dead-sink shape every isolated fixture on this box uses. */
        ctx.connect_peers[0] = "127.0.0.1:39099";
        ASSERT(boot_bundle_fetch_seed_count(&ctx) == 0);

        /* Two default-P2P-port hosts → two seeds. */
        ctx.connect_peers[0] = "203.0.113.7:8033";
        ctx.connect_peers[1] = "203.0.113.8:8033";
        ctx.n_connect_peers = 2;
        ASSERT(boot_bundle_fetch_seed_count(&ctx) == 2);

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

        /* ...and a default-P2P-port -connect alongside it adds the host at
         * FS_PORT (de-duped if it matches the explicit fileservice). */
        ctx.connect_peers[0] = "203.0.113.7:8033";
        ASSERT(boot_bundle_fetch_seed_count(&ctx) == 2);
        ctx.connect_peers[0] = "203.0.113.7:39099";
        ASSERT(boot_bundle_fetch_seed_count(&ctx) == 1);

        /* (5) -addnode preserves normal discovery while contributing the
         * operator-named host. The same port-safety and de-duplication rules
         * as -connect apply. */
        memset(&ctx, 0, sizeof(ctx));
        ctx.addnode_peers[0] = "203.0.113.7:8033";
        ctx.n_addnode_peers = 1;
        ASSERT(boot_bundle_fetch_seed_count(&ctx) == open_seeds + 1);
        ctx.addnode_peers[1] = "203.0.113.7";
        ctx.n_addnode_peers = 2;
        ASSERT(boot_bundle_fetch_seed_count(&ctx) == open_seeds + 1);
        ctx.addnode_peers[1] = "203.0.113.8:39099";
        ASSERT(boot_bundle_fetch_seed_count(&ctx) == open_seeds + 1);

        /* (6) NULL ctx must not crash and must not silently disable the weld. */
        ASSERT(boot_bundle_fetch_seed_count(NULL) == open_seeds);
    } _test_next:;
    return failures;
}

/* ── Peer-DISCOVERED seeds ───────────────────────────────────────────────
 *
 * The gap these close: peers ALREADY advertise their file-service port over
 * the zfileaddr P2P message and this node ALREADY caches it (handle_zfileaddr
 * -> boot_save_file_service -> db_file_service_save). Nothing ever read that
 * cache back, so a node run with NO operator flags assembled ZERO file-service
 * seeds — the compiled clearnet list is deliberately empty — the instant-on
 * fetch was never attempted, and the node fell back to a from-genesis IBD. The
 * missing piece was the CONSUMER (config/src/boot_bundle_fetch_peer_seeds.c).
 *
 * What must stay true, and is asserted below: making a seed easier to FIND
 * must not make its bytes easier to ACCEPT. A peer-discovered seed is an
 * ADDRESS; it travels the identical verification path an operator-named seed
 * travels, and a peer-discovered seed serving bytes that do not match the
 * committed digest is refused exactly as a flag-supplied one is.
 *
 * No wall-clock duration is asserted anywhere here — only relationships and
 * outcomes, because this fleet deliberately includes slow 7200rpm boxes. */

/* (1) PURE: does a cached peer endpoint become a seed? Only if that peer
 * actually advertised a file-service port. */
static int case_peer_seed_offer_filter(void)
{
    int failures = 0;
    TEST("boot_bundle_fetch: a peer becomes an instant-on seed IFF it "
         "advertised a file-service port, dialed at THAT port") {
        struct app_context ctx;
        boot_bundle_fetch_disarm_peer_seeds();

        /* Baseline: no flags, no peers → the pre-existing empty set. This is
         * the stranger's `seeds_empty` boot. */
        memset(&ctx, 0, sizeof(ctx));
        size_t compiled_seeds = 0;
        while (ZCL_BUNDLE_FETCH_CLEARNET_SEEDS[compiled_seeds])
            compiled_seeds++;
        ASSERT(boot_bundle_fetch_seed_count(&ctx) == compiled_seeds);
        ASSERT(boot_bundle_fetch_armed_peer_seed_count() == 0);

        /* A cached peer row that names NO file-service port (the peer never
         * sent zfileaddr) is NOT offered — the count is unchanged from the
         * baseline even though the row is armed and visible to the assembler.
         * This is the "did not advertise ⇒ not a seed" half. */
        boot_bundle_fetch_arm_peer_seed_for_test("203.0.113.20", 0);
        ASSERT(boot_bundle_fetch_armed_peer_seed_count() == 1);
        ASSERT(boot_bundle_fetch_seed_count(&ctx) == compiled_seeds);

        /* The same peer, having advertised a port, IS offered. */
        boot_bundle_fetch_disarm_peer_seeds();
        boot_bundle_fetch_arm_peer_seed_for_test("203.0.113.20", 18034);
        ASSERT(boot_bundle_fetch_seed_count(&ctx) == compiled_seeds + 1);

        /* Mixed set: only the advertisers count. */
        boot_bundle_fetch_arm_peer_seed_for_test("203.0.113.21", 0);
        boot_bundle_fetch_arm_peer_seed_for_test("203.0.113.22", 18035);
        ASSERT(boot_bundle_fetch_armed_peer_seed_count() == 3);
        ASSERT(boot_bundle_fetch_seed_count(&ctx) == compiled_seeds + 2);

        /* THE PEER'S OWN PORT IS USED, NOT FS_PORT — proven WITHOUT a socket,
         * by de-duplication. A live node's peer set really does mix 18034 and
         * 18035, so substituting the default would silently dial the wrong
         * service. An explicit -fileservice naming the SAME host at the SAME
         * port the peer advertised collapses onto the peer-discovered entry;
         * the same host at any other port does not. */
        boot_bundle_fetch_disarm_peer_seeds();
        boot_bundle_fetch_arm_peer_seed_for_test("203.0.113.20", 18035);
        memset(&ctx, 0, sizeof(ctx));
        ctx.connect_only = true;   /* keep the compiled list out of the count */
        ctx.file_service_peer = "203.0.113.20:18035";
        ASSERT(boot_bundle_fetch_seed_count(&ctx) == 1);
        /* FS_PORT is NOT what this peer advertised, so it must not collapse. */
        char fs_default[64];
        snprintf(fs_default, sizeof(fs_default), "203.0.113.20:%u",
                 (unsigned)FS_PORT);
        ctx.file_service_peer = fs_default;
        ASSERT(boot_bundle_fetch_seed_count(&ctx) == 2);

        /* PRECEDENCE + ADDITIVITY: every operator-named source keeps its slot
         * and the peer-discovered seed is added after them, never instead of
         * them. */
        memset(&ctx, 0, sizeof(ctx));
        ctx.connect_only = true;
        ctx.file_service_peer = "198.51.100.9:19034";
        ctx.connect_peers[0] = "203.0.113.7:8033";
        ctx.n_connect_peers = 1;
        boot_bundle_fetch_disarm_peer_seeds();
        ASSERT(boot_bundle_fetch_seed_count(&ctx) == 2); /* pre-existing pair */
        boot_bundle_fetch_arm_peer_seed_for_test("203.0.113.21", 18034);
        ASSERT(boot_bundle_fetch_seed_count(&ctx) == 3);

        /* Bounded: the assembler never overruns its seed array however many
         * peers are armed. */
        boot_bundle_fetch_disarm_peer_seeds();
        for (int i = 0; i < 32; i++) {
            char h[64];
            snprintf(h, sizeof(h), "203.0.113.%d", 100 + i);
            boot_bundle_fetch_arm_peer_seed_for_test(h, 18034);
        }
        memset(&ctx, 0, sizeof(ctx));
        ctx.connect_only = true;
        ASSERT(boot_bundle_fetch_seed_count(&ctx) <= ROM_FETCH_MAX_WORKERS);

        /* Disarming restores the exact pre-existing behaviour. */
        boot_bundle_fetch_disarm_peer_seeds();
        memset(&ctx, 0, sizeof(ctx));
        ASSERT(boot_bundle_fetch_seed_count(&ctx) == compiled_seeds);
        ASSERT(boot_bundle_fetch_armed_peer_seed_count() == 0);
    } _test_next:;
    boot_bundle_fetch_disarm_peer_seeds();
    return failures;
}

/* A loopback ROM seeder for the two network cases below. Registers one
 * synthetic artifact and starts the REAL file-service serve path on an
 * OS-assigned port (never a fixed port: this host runs a live node). */
struct bbf_seeder {
    char     dir[256];
    uint8_t *content;
    size_t   size;
    struct rom_artifact art;
    uint16_t port;
};

static bool bbf_seeder_start(struct bbf_seeder *s)
{
    memset(s, 0, sizeof(*s));
    rom_seed_reset();
    rom_seed_set_peer_bps_cap(1ull << 30);
    rom_seed_set_global_bps_cap(1ull << 30);
    test_make_tmpdir(s->dir, sizeof(s->dir), "bbf_peerseed_srv", "ok");
    s->size = (size_t)ROM_SEED_CHUNK_SIZE + 4096;
    s->content = malloc(s->size);
    if (!s->content)
        return false;
    bbf_gen_content(s->content, s->size);
    if (!bbf_write_file(s->dir, "consensus-state-bundle-3056758.sqlite",
                        s->content, s->size))
        return false;
    if (rom_seed_register(s->dir, "consensus-state-bundle-3056758.sqlite",
                          NULL, &s->art) != ROM_REG_OK)
        return false;
    fs_server_start(s->dir, 0);
    for (int w = 0; w < 40 && !fs_server_is_running(); w++)
        platform_sleep_ms(50);
    if (!fs_server_is_running())
        return false;
    s->port = fs_server_get_port();
    return s->port != 0;
}

static void bbf_seeder_stop(struct bbf_seeder *s)
{
    fs_server_stop();
    free(s->content);
    s->content = NULL;
    char p[1024];
    snprintf(p, sizeof(p), "%s/consensus-state-bundle-3056758.sqlite", s->dir);
    unlink(p);
    test_rm_rf_recursive(s->dir);
    rom_seed_reset();
}

/* Write a <datadir>/bundles/directory.json hint for the seeder's artifact.
 * `corrupt_whole` flips one bit of the committed whole-file digest — the
 * bytes on the wire are then perfectly good but do not match what the client
 * committed to, which is precisely what the content proof must catch. */
static bool bbf_write_hint(const char *datadir, const struct rom_artifact *a,
                           bool corrupt_whole)
{
    char b[512];
    snprintf(b, sizeof(b), "%s/bundles", datadir);
    if (mkdir(b, 0700) != 0)
        return false;
    uint8_t whole[32];
    memcpy(whole, a->whole_sha3, 32);
    if (corrupt_whole)
        whole[0] ^= 0x01;
    char digest_hex[65], whole_hex[65];
    HexStr(a->chunk_root, 32, false, digest_hex, sizeof(digest_hex));
    HexStr(whole, 32, false, whole_hex, sizeof(whole_hex));
    char json[1024];
    int n = snprintf(json, sizeof(json),
                     "{\"count\":1,\"artifacts\":[{\"kind\":\"consensus_bundle\","
                     "\"digest\":\"%s\",\"whole_sha3\":\"%s\",\"size\":%llu,"
                     "\"chunk_size\":%u,\"chunks\":%u,\"height\":3056758}]}",
                     digest_hex, whole_hex,
                     (unsigned long long)a->size_bytes, a->chunk_size,
                     a->num_chunks);
    if (n <= 0 || (size_t)n >= sizeof(json))
        return false;
    return bbf_write_file(b, "directory.json", (const uint8_t *)json,
                          strlen(json));
}

/* (2) END TO END: a peer-discovered seed reaches the fetch path with NO
 * operator flag, and its bytes are accepted or refused on EXACTLY the same
 * terms as a flag-supplied seed's. */
static int case_peer_seed_e2e_and_verification(void)
{
    int failures = 0;
    TEST("boot_bundle_fetch: a peer-discovered seed lands a bundle with no "
         "operator flag, and corrupt bytes from it are refused exactly as "
         "corrupt bytes from a flag-supplied seed are") {
        struct bbf_seeder srv;
        boot_bundle_fetch_disarm_peer_seeds();
        ASSERT(bbf_seeder_start(&srv));

        /* (a) NO operator flags at all — no -fileservice, no -connect, no
         * -addnode — and the compiled clearnet list is empty. The ONLY seed is
         * the peer that advertised its file-service port over zfileaddr and
         * whose endpoint this node cached. Before this consumer existed that
         * boot assembled zero seeds and never attempted the fetch. */
        char cdir[256];
        test_make_tmpdir(cdir, sizeof(cdir), "bbf_peerseed_ok", "ok");
        struct app_context ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.datadir = cdir;
        ASSERT(boot_bundle_fetch_seed_count(&ctx) == 0); /* the stranger today */
        boot_bundle_fetch_arm_peer_seed_for_test("127.0.0.1", srv.port);
        ASSERT(boot_bundle_fetch_seed_count(&ctx) == 1);
        ASSERT(bbf_write_hint(cdir, &srv.art, false));
        ASSERT(boot_bundle_fetch_maybe(cdir, &ctx));
        char *landed = boot_autodetect_consensus_bundle(cdir);
        ASSERT(landed != NULL);
        free(landed);

        /* (b) The SAME peer-discovered seed, same wire bytes, but the client
         * committed to a digest those bytes do not match: REFUSED, nothing
         * lands, no sovereign marker. Discovery made the seed findable; it did
         * not make its bytes acceptable. */
        char bdir[256];
        test_make_tmpdir(bdir, sizeof(bdir), "bbf_peerseed_bad", "ok");
        struct app_context bctx;
        memset(&bctx, 0, sizeof(bctx));
        bctx.datadir = bdir;
        ASSERT(bbf_write_hint(bdir, &srv.art, true));
        ASSERT(!boot_bundle_fetch_maybe(bdir, &bctx));
        char *bad_auto = boot_autodetect_consensus_bundle(bdir);
        ASSERT(bad_auto == NULL);
        free(bad_auto);
        ASSERT(!boot_consensus_bundle_marker_exists(bdir));

        /* (c) The SAME corrupt commitment against a FLAG-supplied seed (same
         * seeder, named with -fileservice, peer source disarmed) fails in
         * exactly the same way. Same outcome, same absence of a marker — the
         * two seed provenances are indistinguishable to the verifier, which is
         * the whole claim. */
        boot_bundle_fetch_disarm_peer_seeds();
        char fdir[256];
        test_make_tmpdir(fdir, sizeof(fdir), "bbf_flagseed_bad", "ok");
        struct app_context fctx;
        memset(&fctx, 0, sizeof(fctx));
        fctx.datadir = fdir;
        char peer_hp[64];
        snprintf(peer_hp, sizeof(peer_hp), "127.0.0.1:%u", (unsigned)srv.port);
        fctx.file_service_peer = peer_hp;
        fctx.connect_only = true;
        ASSERT(boot_bundle_fetch_seed_count(&fctx) == 1);
        ASSERT(bbf_write_hint(fdir, &srv.art, true));
        ASSERT(!boot_bundle_fetch_maybe(fdir, &fctx));
        char *flag_auto = boot_autodetect_consensus_bundle(fdir);
        ASSERT(flag_auto == NULL);
        free(flag_auto);
        ASSERT(!boot_consensus_bundle_marker_exists(fdir));

        /* And the GOOD commitment through the flag-supplied seed still lands —
         * so (b) and (c) are refusals of the DIGEST, not of the provenance. */
        char gdir[256];
        test_make_tmpdir(gdir, sizeof(gdir), "bbf_flagseed_ok", "ok");
        struct app_context gctx;
        memset(&gctx, 0, sizeof(gctx));
        gctx.datadir = gdir;
        gctx.file_service_peer = peer_hp;
        gctx.connect_only = true;
        ASSERT(bbf_write_hint(gdir, &srv.art, false));
        ASSERT(boot_bundle_fetch_maybe(gdir, &gctx));
        char *good_auto = boot_autodetect_consensus_bundle(gdir);
        ASSERT(good_auto != NULL);
        free(good_auto);

        test_rm_rf_recursive(cdir);
        test_rm_rf_recursive(bdir);
        test_rm_rf_recursive(fdir);
        test_rm_rf_recursive(gdir);
        bbf_seeder_stop(&srv);
    } _test_next:;
    boot_bundle_fetch_disarm_peer_seeds();
    return failures;
}

/* (3) A peer that ADVERTISES the file service but does not serve costs a
 * BOUNDED amount of time and is then dropped — the remaining seeds are still
 * tried and the bundle still lands.
 *
 * The bound is structural, not timed here: rom_fetch_get_directory gives up
 * after RF_CONNECT_TIMEOUT_MS + its recv window, discovery `continue`s to the
 * next seed, and the non-answering seed is left OUT of the download peer set
 * (struct bbf_discovery.live) so it can never re-enter the per-chunk rotation.
 * The recv window is shortened for this case so the machine is not made to sit
 * out the production wait; the test asserts the DEFAULT is unchanged rather
 * than asserting any elapsed duration. */
static int case_peer_seed_stall_is_bounded(void)
{
    int failures = 0;
    TEST("boot_bundle_fetch: a seed that advertises but stalls is abandoned "
         "and dropped; the remaining seeds still land the bundle") {
        struct bbf_seeder srv;
        boot_bundle_fetch_disarm_peer_seeds();

        /* The production default must be the real one; the override is a
         * WAIT, not a check. */
        ASSERT(rom_fetch_directory_io_timeout_ms_for_test() ==
               rom_fetch_directory_io_timeout_default_ms_for_test());
        ASSERT(rom_fetch_directory_io_timeout_default_ms_for_test() > 0);

        /* A listener that completes the TCP handshake and then never speaks —
         * the expensive shape a bounded wait exists for. Never accept(): the
         * kernel backlog completes the connect, so the client gets a live
         * socket and no reply. */
        int stall_fd = socket(AF_INET, SOCK_STREAM, 0);
        ASSERT(stall_fd >= 0);
        int one = 1;
        (void)setsockopt(stall_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sa.sin_port = 0; /* OS-assigned */
        ASSERT(bind(stall_fd, (struct sockaddr *)&sa, sizeof(sa)) == 0);
        ASSERT(listen(stall_fd, 8) == 0);
        socklen_t slen = sizeof(sa);
        ASSERT(getsockname(stall_fd, (struct sockaddr *)&sa, &slen) == 0);
        uint16_t stall_port = ntohs(sa.sin_port);
        ASSERT(stall_port != 0);

        ASSERT(bbf_seeder_start(&srv));
        rom_fetch_set_directory_io_timeout_ms_for_test(400);
        ASSERT(rom_fetch_directory_io_timeout_ms_for_test() == 400);

        /* Two peer-discovered seeds, the stalling one FIRST so it cannot be
         * skipped by luck of ordering. No operator flags at all. */
        char cdir[256];
        test_make_tmpdir(cdir, sizeof(cdir), "bbf_peerseed_stall", "ok");
        boot_bundle_fetch_arm_peer_seed_for_test("127.0.0.1", stall_port);
        boot_bundle_fetch_arm_peer_seed_for_test("127.0.0.1", srv.port);
        struct app_context ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.datadir = cdir;
        /* Both are offered: the stall is discovered by CONTACTING the peer,
         * not by pre-judging it. */
        ASSERT(boot_bundle_fetch_seed_count(&ctx) == 2);

        /* No local hint: discovery runs, the stalling seed is abandoned and
         * dropped, and the surviving seed carries the download. */
        ASSERT(boot_bundle_fetch_maybe(cdir, &ctx));
        char *landed = boot_autodetect_consensus_bundle(cdir);
        ASSERT(landed != NULL);
        free(landed);

        /* Restore the production bound for every later case. */
        rom_fetch_set_directory_io_timeout_ms_for_test(0);
        ASSERT(rom_fetch_directory_io_timeout_ms_for_test() ==
               rom_fetch_directory_io_timeout_default_ms_for_test());

        close(stall_fd);
        test_rm_rf_recursive(cdir);
        bbf_seeder_stop(&srv);
    } _test_next:;
    rom_fetch_set_directory_io_timeout_ms_for_test(0);
    boot_bundle_fetch_disarm_peer_seeds();
    return failures;
}

int test_boot_bundle_fetch(void)
{
    printf("\n=== boot_bundle_fetch ===\n");
    int failures = 0;
    failures += case_seed_set();
    failures += case_peer_seed_offer_filter();
    failures += case_peer_seed_e2e_and_verification();
    failures += case_peer_seed_stall_is_bounded();
    failures += case_gate();
    failures += case_network_gate();
    failures += case_pick();
    failures += case_pick_kinds();
    failures += case_e2e();
    failures += case_baked_facts();
    failures += case_pick_newest();
    failures += case_quorum();
    failures += case_parallel_probe();
    failures += case_parallel_manifest_probe();
    failures += case_discovery();
    failures += case_discovery_outcome_persists();
    printf("=== boot_bundle_fetch: %d failure(s) ===\n", failures);
    return failures;
}
