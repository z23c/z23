/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_boot_bundle_fetch — THE WELD (engine/composition/src/boot_bundle_fetch.c).
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
 * Fixtures live under mkdtemp() dirs, never a real datadir. The synthetic bundle
 * is SQLite-magic content, not a real consensus-state bundle, so install fails closed. */

#include "test/test_core.h"
#include "base/log_macros.h"

#include "config/boot.h"                       /* struct app_context */
#include "config/boot_bundle_fetch.h"
#include "config/boot_first_run_banner.h"
#include "config/bundle_fetch_seeds.h"          /* ZCL_BUNDLE_FETCH_CLEARNET_SEEDS */
#include "config/boot_consensus_bundle_marker.h"
#include "config/consensus_state_install_runtime.h"
#include "chain/chainparams.h"
#include "chain/checkpoints.h"
#include "net/rom_fetch.h"
#include "net/rom_seed.h"
#include "util/thread_registry.h"
#include "net/file_service.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "platform/socket_compat.h"
#include "platform/time_compat.h"
#include "storage/progress_store.h"
#include "util/safe_alloc.h"
#include "validation/chainstate.h"              /* block_map, active_chain */
#include "validation/main_state.h"              /* struct main_state */
#include "chain/chain.h"                        /* block_index status bits */

#include <dirent.h>
#include <fcntl.h>
#include <stdatomic.h>
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

/* ── First-run banner text (pure builder) ───────────────────────────────── */

static int case_first_run_banner(void)
{
    int failures = 0;
    TEST("boot_first_run_banner: tty text on a first and a later run, empty off a tty") {
        char b[1024];
        size_t n = boot_first_run_banner_text(b, sizeof(b), "/d", true, true);
        ASSERT(n == strlen(b));
        ASSERT_STR_EQ(b,
            "Z23 node starting (data in /d).\n"
            "First run: the first sync takes a while; z23 status shows how "
            "far it is.\n"
            "Leave this running; in another terminal run: z23 status\n"
            "Stop with Ctrl-C. Guide: https://z23.sh/start\n");
        n = boot_first_run_banner_text(b, sizeof(b), "/d", false, true);
        ASSERT(n > 0 && strstr(b, "First run") == NULL);
        ASSERT(strstr(b, "z23 status") != NULL);
        n = boot_first_run_banner_text(b, sizeof(b), "/d", true, false);
        ASSERT(n == 0 && b[0] == '\0');
        ASSERT(boot_first_run_banner_text(b, 8, "/d", true, true) == 0);
    } _test_next:;
    return failures;
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

/* ── (a2) Header-chain seed gate over the loaded header index ─────────── */

/* The loaded-index shapes the header-seed gate is asked about. */
enum bbf_index_shape {
    BBF_IDX_NONE,      /* no index handed to the gate */
    BBF_IDX_EMPTY,     /* an index with no rows */
    BBF_IDX_STUB,      /* genesis + 5 header-only rows, no tip */
    BBF_IDX_POPULATED, /* 1025 header-only rows */
    BBF_IDX_BODY,      /* the stub with body data on its top row */
    BBF_IDX_TIP,       /* the stub with the active tip on its top row */
};

/* `n` linked rows: genesis with its body bit (as the ladder seats it), every
 * row above it header-only. Returns the top row. */
static struct block_index *bbf_stub_rows(struct main_state *ms, int n)
{
    struct block_index *prev = NULL;
    for (int h = 0; h < n; h++) {
        struct uint256 hash;
        memset(&hash, 0, sizeof(hash));
        hash.data[0] = (uint8_t)(h & 0xFF);
        hash.data[1] = (uint8_t)((h >> 8) & 0xFF);
        hash.data[3] = 0xC1;
        struct block_index *pi =
            chainstate_insert_block_index((struct chainstate *)ms, &hash);
        if (!pi)
            return NULL;
        pi->nHeight = h;
        pi->pprev = prev;
        pi->nStatus = h == 0 ? (unsigned int)(BLOCK_VALID_SCRIPTS |
                                              BLOCK_HAVE_DATA)
                             : (unsigned int)BLOCK_VALID_TREE;
        prev = pi;
    }
    return prev;
}

/* Shape `ms` as `shape`; false when the fixture could not be built. */
static bool bbf_shape_index(struct main_state *ms, enum bbf_index_shape shape)
{
    if (shape == BBF_IDX_EMPTY)
        return true;
    struct block_index *top =
        bbf_stub_rows(ms, shape == BBF_IDX_POPULATED ? 1025 : 6);
    if (!top)
        return false;
    if (shape == BBF_IDX_BODY)
        (void)block_index_status_fetch_or(top, (unsigned int)BLOCK_HAVE_DATA);
    if (shape == BBF_IDX_TIP)
        return active_chain_move_window_tip(&ms->chain_active, top);
    return true;
}

/* 1 / 0: the gate's answer for `dir` under `ctx` with a `shape` index;
 * -1 when the fixture could not be built. */
static int bbf_seed_gate(const char *dir, const struct app_context *ctx,
                         enum bbf_index_shape shape)
{
    if (shape == BBF_IDX_NONE)
        return boot_bundle_header_seed_needed_for_test(dir, ctx, NULL) ? 1 : 0;
    struct main_state ms;
    main_state_init(&ms);
    int r = -1;
    if (bbf_shape_index(&ms, shape))
        r = boot_bundle_header_seed_needed_for_test(dir, ctx, &ms) ? 1 : 0;
    main_state_free(&ms);
    return r;
}

/* Every refusal that ran before the index was consulted still wins over a
 * stub root index. */
static int case_header_seed_gate_refusals(const char *dir)
{
    int failures = 0;
    TEST("boot_bundle_fetch: opt-outs, non-mainnet, a landed seed and the marker still refuse over a stub") {
        struct app_context ctx;
        memset(&ctx, 0, sizeof(ctx));
        setenv("ZCL_NO_BUNDLE_FETCH", "1", 1);
        int env = bbf_seed_gate(dir, &ctx, BBF_IDX_STUB);
        unsetenv("ZCL_NO_BUNDLE_FETCH");
        ASSERT(env == 0);
        ctx.no_file_sync = true;
        ASSERT(bbf_seed_gate(dir, &ctx, BBF_IDX_STUB) == 0);
        memset(&ctx, 0, sizeof(ctx));
        ctx.regtest = true;
        ASSERT(bbf_seed_gate(dir, &ctx, BBF_IDX_STUB) == 0);
        memset(&ctx, 0, sizeof(ctx));
        ctx.testnet = true;
        ASSERT(bbf_seed_gate(dir, &ctx, BBF_IDX_STUB) == 0);
        memset(&ctx, 0, sizeof(ctx));
        ASSERT(bbf_seed_gate("", &ctx, BBF_IDX_STUB) == 0);
        /* Already downloaded: the import consumes it, no re-fetch. */
        char bundles[320];
        snprintf(bundles, sizeof(bundles), "%s/bundles", dir);
        ASSERT(mkdir(bundles, 0700) == 0);
        ASSERT(bbf_write_file(bundles, "block_index.bin",
                              (const uint8_t *)"seed", 4));
        ASSERT(bbf_seed_gate(dir, &ctx, BBF_IDX_STUB) == 0);
        test_rm_rf_recursive(bundles);
        ASSERT(bbf_seed_gate(dir, &ctx, BBF_IDX_STUB) == 1);
        /* Sovereign marker: never re-seed installed state. */
        uint8_t digest[32];
        memset(digest, 0xab, sizeof(digest));
        ASSERT(boot_consensus_bundle_marker_write(dir, 3056758, digest));
        ASSERT(bbf_seed_gate(dir, &ctx, BBF_IDX_STUB) == 0);
    } _test_next:;
    return failures;
}

static int case_header_seed_gate(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "bbf_hsgate", "ok");
    TEST("boot_bundle_fetch: header seed wanted on a fresh datadir or over a stub root index only") {
        struct app_context ctx;
        memset(&ctx, 0, sizeof(ctx));
        /* Fresh (no root block_index.bin). */
        ASSERT(bbf_seed_gate(dir, &ctx, BBF_IDX_NONE) == 1);
        ASSERT(bbf_seed_gate(dir, &ctx, BBF_IDX_EMPTY) == 1);
        ASSERT(bbf_seed_gate(dir, &ctx, BBF_IDX_STUB) == 1);
        ASSERT(bbf_seed_gate(dir, &ctx, BBF_IDX_POPULATED) == 0);
        /* A root block_index.bin is present. */
        ASSERT(bbf_write_file(dir, "block_index.bin",
                              (const uint8_t *)"stub", 4));
        ASSERT(bbf_seed_gate(dir, &ctx, BBF_IDX_NONE) == 0);
        ASSERT(bbf_seed_gate(dir, &ctx, BBF_IDX_EMPTY) == 0);
        ASSERT(bbf_seed_gate(dir, &ctx, BBF_IDX_STUB) == 1);
        ASSERT(bbf_seed_gate(dir, &ctx, BBF_IDX_POPULATED) == 0);
        ASSERT(bbf_seed_gate(dir, &ctx, BBF_IDX_BODY) == 0);
        ASSERT(bbf_seed_gate(dir, &ctx, BBF_IDX_TIP) == 0);
    } _test_next:;
    failures += case_header_seed_gate_refusals(dir);
    test_rm_rf_recursive(dir);
    return failures;
}

/* A regtest or testnet node never fetches mainnet bundle state (the artifact
 * binds to the mainnet CHECKPOINT_ROM). */
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

        ctx.testnet_profile = app_testnet_profile_by_name("ironwood");
        ASSERT(ctx.testnet_profile != NULL);
        ASSERT(!boot_bundle_fetch_should_run(dir, &ctx));
        ctx.testnet_profile = NULL;
        bool selected = chain_research_profile_select(CHAIN_RESEARCH_IRONWOOD);
        bool fetch = boot_bundle_fetch_should_run(dir, NULL);
        int seed = bbf_seed_gate(dir, &ctx, BBF_IDX_STUB);
        chain_params_select(CHAIN_MAIN);
        ASSERT(selected && !fetch && seed == 0);

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

        /* The whole weld is a no-op on regtest even with a -connect peer. */
        memset(&ctx, 0, sizeof(ctx));
        ctx.regtest = true;
        ctx.connect_only = true;
        ctx.connect_peers[0] = "127.0.0.1:39099";
        ctx.n_connect_peers = 1;
        ASSERT(boot_bundle_fetch_seed_count(&ctx) == 0);
        ASSERT(!boot_bundle_fetch_maybe(dir, &ctx, NULL));

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

/* Redirect stderr (at full log level) into a temporary file while a boot call
 * runs. Always restore stderr and its level before assertions run. */
struct bbf_capture {
    FILE *file;
    int saved;
    enum zcl_log_level level;
};

static bool bbf_capture_begin(struct bbf_capture *c)
{
    c->file = tmpfile();
    if (!c->file)
        LOG_FAIL("test_boot_bundle_fetch", "cannot create log capture");
    c->saved = dup(STDERR_FILENO);
    if (c->saved < 0) {
        fclose(c->file);
        LOG_FAIL("test_boot_bundle_fetch", "cannot save stderr");
    }
    fflush(stderr);
    if (dup2(fileno(c->file), STDERR_FILENO) < 0) {
        close(c->saved);
        fclose(c->file);
        LOG_FAIL("test_boot_bundle_fetch", "cannot redirect stderr");
    }
    c->level = zcl_log_level_get();
    zcl_log_level_set(ZCL_LOG_ALL);
    return true;
}

static bool bbf_capture_end(struct bbf_capture *c, char *out, size_t cap)
{
    fflush(stderr);
    zcl_log_level_set(c->level);
    int restored = dup2(c->saved, STDERR_FILENO);
    close(c->saved);
    if (restored < 0) {
        fclose(c->file);
        LOG_FAIL("test_boot_bundle_fetch", "cannot restore stderr");
    }
    rewind(c->file);
    size_t n = fread(out, 1, cap - 1, c->file);
    out[n] = '\0';
    bool ok = !ferror(c->file) && fgetc(c->file) == EOF;
    if (fclose(c->file) != 0)
        ok = false;
    if (!ok)
        LOG_FAIL("test_boot_bundle_fetch", "log capture failed or exceeded bound");
    return true;
}

/* Capture the real threaded download's foreground messages in this isolated
 * test process. */
static bool bbf_capture_download(const char *dir,
                                 const struct rom_fetch_peer *peers,
                                 const struct rom_fetch_manifest *manifest,
                                 bool *download_ok, char *out, size_t cap)
{
    struct bbf_capture c;
    if (!bbf_capture_begin(&c))
        return false;
    *download_ok = boot_bundle_fetch_download(dir, peers, 1, manifest);
    return bbf_capture_end(&c, out, cap);
}

/* The same capture around the production entry, boot_bundle_fetch_maybe. */
static bool bbf_capture_maybe(const char *dir, const struct app_context *ctx,
                              bool *landed, char *out, size_t cap)
{
    struct bbf_capture c;
    if (!bbf_capture_begin(&c))
        return false;
    *landed = boot_bundle_fetch_maybe(dir, ctx, NULL);
    return bbf_capture_end(&c, out, cap);
}

/* Observe actual callback counters rather than a simulated progress object. */
static bool bbf_progress_is_bounded(const char *log,
                                    const struct rom_fetch_manifest *manifest)
{
    unsigned last_chunks = 0, reports = 0;
    unsigned long long last_bytes = 0;
    for (const char *p = log; (p = strstr(p, " chunks=")) != NULL; p++) {
        unsigned chunks = 0, total_chunks = 0;
        unsigned long long bytes = 0, total_bytes = 0;
        if (sscanf(p, " chunks=%u/%u bytes=%llu/%llu", &chunks, &total_chunks,
                   &bytes, &total_bytes) != 4)
            continue;
        if (total_chunks != manifest->num_chunks ||
            total_bytes != manifest->size_bytes || chunks > total_chunks ||
            bytes > total_bytes || chunks < last_chunks || bytes < last_bytes)
            LOG_FAIL("test_boot_bundle_fetch", "progress regressed or exceeded manifest");
        last_chunks = chunks;
        last_bytes = bytes;
        reports++;
    }
    if (reports == 0 || reports > manifest->num_chunks + 2 ||
        last_chunks != manifest->num_chunks || last_bytes != manifest->size_bytes)
        LOG_FAIL("test_boot_bundle_fetch", "missing, unbounded or incomplete progress");
    return true;
}

static int case_e2e(void)
{
    int failures = 0;
    TEST("boot_bundle_fetch: E2E download lands + install fires + guards hold") {
        rom_seed_reset();
        /* Move ~3x the artifact inside one wall-second — raise the byte caps so
         * the outcome is not wall-clock dependent (reset restores defaults). */
        rom_seed_set_peer_bps_cap(1ull << 30);
        rom_seed_set_global_bps_cap(1ull << 30);

        char sroot[PATH_MAX];
        char *sdir = test_mkdtemp(sroot, sizeof(sroot), "zcl_bbf_srv");
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
        fs_server_start(sdir, 0, NULL); /* OS-assigned: no cross-checkout port collisions */
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
        char croot[PATH_MAX];
        char *cdir = test_mkdtemp(croot, sizeof(croot), "zcl_bbf_cli");
        ASSERT(cdir != NULL);
        struct rom_fetch_peer peers[1];
        memset(peers, 0, sizeof(peers));
        snprintf(peers[0].addr, sizeof(peers[0].addr), "%s", "127.0.0.1");
        peers[0].port = port;

        char progress_log[16384];
        bool download_ok = false;
        ASSERT(bbf_capture_download(cdir, peers, &m, &download_ok,
                                    progress_log, sizeof(progress_log)));
        ASSERT(download_ok);
        char landed[1200];
        snprintf(landed, sizeof(landed), "%s/bundles/%s", cdir, m.filename);
        ASSERT(rom_fetch_verify_file(landed, &m));

        /* The landed bundle is registered with rom_seed immediately, with the
         * same chunk_root as the source artifact. */
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
        char croot2[PATH_MAX];
        char *cdir2 = test_mkdtemp(croot2, sizeof(croot2), "zcl_bbf_bad");
        ASSERT(cdir2 != NULL);
        struct rom_fetch_manifest bad = m;
        bad.whole_sha3[0] ^= 0x01;
        char bad_progress_log[16384];
        ASSERT(bbf_capture_download(cdir2, peers, &bad, &download_ok,
                                    bad_progress_log, sizeof(bad_progress_log)));
        ASSERT(!download_ok);
        char *bad_auto = boot_autodetect_consensus_bundle(cdir2);
        ASSERT(bad_auto == NULL); /* nothing installable landed */
        free(bad_auto);
        /* Nothing landed, so nothing was registered with rom_seed. */

        /* (d) Production entry: a directory.json hint + -fileservice peer drives
         * the whole gate → pick → seed-assembly → download → land path. */
        char croot3[PATH_MAX];
        char *cdir3 = test_mkdtemp(croot3, sizeof(croot3), "zcl_bbf_maybe");
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

        ASSERT(boot_bundle_fetch_maybe(cdir3, &ctx, NULL));
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

        /* Assert UI behavior after stopping the server: a missing progress
         * callback must not leave a serving fixture behind for later cases. */
        const char *preparing = strstr(progress_log, "phase=preparing");
        const char *downloading = strstr(progress_log, "phase=downloading");
        const char *verifying = strstr(progress_log, "phase=verifying");
        const char *downloaded = strstr(progress_log, "phase=downloaded");
        ASSERT(preparing && downloading && verifying && downloaded);
        ASSERT(preparing < downloading && downloading < verifying &&
               verifying < downloaded);
        ASSERT(strstr(progress_log, "phase=ready") == NULL);
        ASSERT(strstr(progress_log, "phase=installed") == NULL);
        ASSERT(bbf_progress_is_bounded(progress_log, &m));
        verifying = strstr(bad_progress_log, "phase=verifying");
        const char *fallback = strstr(bad_progress_log, "phase=fallback");
        ASSERT(verifying && fallback && verifying < fallback);
        ASSERT(strstr(bad_progress_log, "phase=downloaded") == NULL);
        ASSERT(strstr(bad_progress_log, "phase=ready") == NULL);
        ASSERT(strstr(bad_progress_log, "phase=installed") == NULL);
        ASSERT(bbf_progress_is_bounded(bad_progress_log, &bad));
    } _test_next:;
    return failures;
}

/* ── (f) Warm boot: a landed, verified bundle is not downloaded again ───── */

static bool bbf_reseeded(const struct rom_fetch_manifest *m)
{
    char want[ROM_SEED_NAME_MAX];
    snprintf(want, sizeof(want), "%s/%s", ROM_SEED_BUNDLES_SUBDIR, m->filename);
    struct rom_artifact cat[ROM_SEED_MAX_ARTIFACTS];
    int cn = rom_seed_list(cat, ROM_SEED_MAX_ARTIFACTS);
    for (int i = 0; i < cn; i++)
        if (strcmp(cat[i].filename, want) == 0)
            return true;
    return false;
}

/* Land `content` (possibly truncated/flipped) as <cdir>/bundles/<name> and run
 * the download against `peers`; returns the download verdict. */
static bool bbf_download_with_staged(const char *cdir, const uint8_t *content,
                                     size_t len,
                                     const struct rom_fetch_peer *peers,
                                     const struct rom_fetch_manifest *m)
{
    char b[400];
    snprintf(b, sizeof(b), "%s/bundles", cdir);
    if (mkdir(b, 0700) != 0 || !bbf_write_file(b, m->filename, content, len))
        return false;
    return boot_bundle_fetch_download(cdir, peers, 1, m);
}

static int case_warm_landed(void)
{
    int failures = 0;
    TEST("boot_bundle_fetch: verified landed bundle skips the download") {
        rom_seed_reset();
        rom_seed_set_peer_bps_cap(1ull << 30);
        rom_seed_set_global_bps_cap(1ull << 30);
        char sroot[PATH_MAX];
        char *sdir = test_mkdtemp(sroot, sizeof(sroot), "zcl_bbf_wsrv");
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
        char dirjson[3072];
        bbf_directory_json(dirjson, sizeof(dirjson));
        struct rom_fetch_manifest m;
        memset(&m, 0, sizeof(m));
        ASSERT(boot_bundle_pick_manifest(dirjson, &m));
        rom_seed_reset(); /* drop the server-side registration */

        /* (a) Matching final file + a peer nobody listens on: any network
         * attempt would fail, so success proves zero network use. */
        struct rom_fetch_peer dead[1];
        memset(dead, 0, sizeof(dead));
        snprintf(dead[0].addr, sizeof(dead[0].addr), "%s", "127.0.0.1");
        dead[0].port = 1;
        char r1[PATH_MAX];
        char *c1 = test_mkdtemp(r1, sizeof(r1), "zcl_bbf_w1");
        ASSERT(c1 != NULL);
        ASSERT(bbf_download_with_staged(c1, content, size, dead, &m));
        boot_bundle_fetch_reseed_wait(); /* warm-boot reseed is a background job */
        ASSERT(bbf_reseeded(&m));
        ASSERT(!boot_consensus_bundle_marker_exists(c1));
        rom_seed_reset();

        /* (b)/(c) same-size flipped byte, and wrong size: must download. */
        fs_server_start(sdir, 0, NULL);
        for (int w = 0; w < 40 && !fs_server_is_running(); w++)
            platform_sleep_ms(50);
        ASSERT(fs_server_is_running() && fs_server_get_port() != 0);
        ASSERT(rom_seed_register(sdir, "consensus-state-bundle-3056758.sqlite",
                                 NULL, &art) == ROM_REG_OK);
        struct rom_fetch_peer live[1];
        memset(live, 0, sizeof(live));
        snprintf(live[0].addr, sizeof(live[0].addr), "%s", "127.0.0.1");
        live[0].port = fs_server_get_port();

        uint8_t *bad = malloc(size);
        ASSERT(bad != NULL);
        memcpy(bad, content, size);
        bad[size / 2] ^= 0x01;
        char r2[PATH_MAX];
        char *c2 = test_mkdtemp(r2, sizeof(r2), "zcl_bbf_w2");
        ASSERT(c2 != NULL);
        ASSERT(bbf_download_with_staged(c2, bad, size, live, &m));
        char p2[1200];
        snprintf(p2, sizeof(p2), "%s/bundles/%s", c2, m.filename);
        ASSERT(rom_fetch_verify_file(p2, &m)); /* replaced by the real bytes */

        char r3[PATH_MAX];
        char *c3 = test_mkdtemp(r3, sizeof(r3), "zcl_bbf_w3");
        ASSERT(c3 != NULL);
        ASSERT(bbf_download_with_staged(c3, content, size - 1, live, &m));
        char p3[1200];
        snprintf(p3, sizeof(p3), "%s/bundles/%s", c3, m.filename);
        ASSERT(rom_fetch_verify_file(p3, &m));

        fs_server_stop();
        free(bad);
        free(content);
        test_rm_rf_recursive(c1);
        test_rm_rf_recursive(c2);
        test_rm_rf_recursive(c3);
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
    /* The pick ranks newest-height-first (bandwidth-DoS guard, not a trust
     * source); a lone non-explicit newest candidate is accepted. */
    TEST("boot_bundle_fetch: quorum ranks newest-height-first, never refuses a "
         "valid newest candidate") {
        /* No candidates → still -1. */
        ASSERT(boot_bundle_quorum_pick_for_test(NULL, NULL, NULL, 0) == -1);

        /* A lone non-explicit seed is accepted. */
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

        /* Two single-seed triples at two heights: the newest wins, never -1. */
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
/* ── (e1b) The per-chunk manifest pre-flight is a sweep ──────
 *
 * Probes overlap; the lowest-indexed seed with a matching chunk count wins. */

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


/* ── (e2b) Manifest probe OOM: no seed is probed from a half-built pool ─────
 * The digest tables are all allocated before any probe starts. If the second
 * one fails, nothing has been spawned yet: no worker is left running against
 * a freed table or this frame's job array, and no fetch reaches the network. */

static _Atomic int rmf_oom_calls;
static bool counting_manifest_fetch(const char *addr, uint16_t port,
                                    const uint8_t chunk_root[32],
                                    uint8_t (*out)[32], uint32_t cap,
                                    uint32_t *out_n)
{
    (void)addr;
    (void)port;
    (void)chunk_root;
    (void)out;
    (void)cap;
    (void)out_n;
    atomic_fetch_add(&rmf_oom_calls, 1);
    return false;
}

static int case_manifest_probe_oom_spawns_nothing(void)
{
    int failures = 0;
    TEST("boot_bundle_fetch: a digest-table OOM in the manifest pre-flight "
         "fails before any seed probe is spawned or fetched") {
        struct rom_fetch_peer peers[3] = {0};
        for (size_t i = 0; i < 3; i++) {
            snprintf(peers[i].addr, sizeof(peers[i].addr), "seed%zu", i);
            peers[i].port = (uint16_t)(18034 + i);
        }
        uint8_t root[32];
        memset(root, 0x66, sizeof(root));
        uint8_t digests[4][32];
        memset(digests, 0, sizeof(digests));
        uint32_t n = 7;

        atomic_store(&rmf_oom_calls, 0);
        zcl_alloc_fault_fail_nth("bbf_manifest_probe", 2u);
        bool found = boot_bundle_probe_manifest_for_test(
            peers, 3, root, 4, digests, 4, &n, counting_manifest_fetch);
        bool consumed = zcl_alloc_fault_armed_label() == NULL;
        zcl_alloc_fault_clear();

        ASSERT(consumed);
        ASSERT(!found);
        ASSERT(n == 0);
        /* Before the fix, seed 0 was spawned and fetched before the OOM
         * return (red: 1 != 0), against a freed digest table. */
        ASSERT_EQ(atomic_load(&rmf_oom_calls), 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ── (e3) Fresh-node bundle choice: newest baked rung over the keystone ───── */
/* Guard, not a fix: the picker and ranker already order by advertised height.
 * This pins the owner's fresh-node policy for the h=3200000 rung: when both the
 * keystone bundle and the newer rung bundle are offered, the rung is chosen and
 * named by its height; when only the keystone bundle is offered it is chosen. */
static int case_pick_rung_over_keystone(void)
{
    int failures = 0;
    TEST("boot_bundle_fetch: the newer baked rung bundle beats the keystone "
         "bundle; the keystone is the fallback when no rung is offered") {
        uint64_t size = (uint64_t)ROM_SEED_CHUNK_SIZE + 4096;
        char both[1024];
        snprintf(both, sizeof(both),
                 "{\"artifacts\":["
                 "{\"kind\":\"consensus_bundle\",\"digest\":\"%064d\","
                 "\"whole_sha3\":\"%064d\",\"size\":%llu,\"chunk_size\":%u,"
                 "\"chunks\":2,\"height\":3056758},"
                 "{\"kind\":\"consensus_bundle\",\"digest\":\"%064d\","
                 "\"whole_sha3\":\"%064d\",\"size\":%llu,\"chunk_size\":%u,"
                 "\"chunks\":2,\"height\":3200000}]}",
                 1, 2, (unsigned long long)size, (unsigned)ROM_SEED_CHUNK_SIZE,
                 3, 4, (unsigned long long)size, (unsigned)ROM_SEED_CHUNK_SIZE);
        struct rom_fetch_manifest m;
        memset(&m, 0, sizeof(m));
        ASSERT(boot_bundle_pick_manifest(both, &m));
        ASSERT(m.height == 3200000);
        ASSERT(strcmp(m.filename, "consensus-state-bundle-3200000.sqlite") == 0);

        char only_keystone[512];
        snprintf(only_keystone, sizeof(only_keystone),
                 "{\"artifacts\":["
                 "{\"kind\":\"consensus_bundle\",\"digest\":\"%064d\","
                 "\"whole_sha3\":\"%064d\",\"size\":%llu,\"chunk_size\":%u,"
                 "\"chunks\":2,\"height\":3056758}]}",
                 1, 2, (unsigned long long)size, (unsigned)ROM_SEED_CHUNK_SIZE);
        memset(&m, 0, sizeof(m));
        ASSERT(boot_bundle_pick_manifest(only_keystone, &m));
        ASSERT(m.height == 3056758);

        /* Across seeds: a rung offered by one seed outranks a keystone offered
         * by two. */
        int64_t hs[] = { 3056758, 3200000 };
        int cs[] = { 2, 1 };
        bool fs[] = { true, false };
        ASSERT(boot_bundle_quorum_pick_for_test(hs, cs, fs, 2) == 1);

        /* The install readiness chain waits on the STAGED bundle's baked height:
         * a rung-named bundle waits on the rung's header + solution; any other
         * name (or none) waits on the compiled SHA3 checkpoint, as before. */
        struct sha3_utxo_checkpoint sha3;
        memset(&sha3, 0, sizeof(sha3));
        sha3.height = 500;
        memset(sha3.block_hash, 0xa1, 32);
        checkpoints_set_sha3_override_for_test(&sha3);
        struct rom_state_checkpoint ks;
        memset(&ks, 0, sizeof(ks));
        ks.height = 500;
        memset(ks.block_hash, 0xa1, 32);
        checkpoints_set_rom_state_override_for_test(&ks);
        struct rom_state_rung rg;
        memset(&rg, 0, sizeof(rg));
        rg.cp.height = 700;
        memset(rg.cp.block_hash, 0xd1, 32);
        checkpoints_set_rom_state_rungs_override_for_test(&rg, 1);
        int32_t wh = 0;
        uint8_t wb[32];
        ASSERT(boot_staged_bundle_wait_target(
            "/d/bundles/consensus-state-bundle-700.sqlite", &wh, wb));
        ASSERT(wh == 700 && wb[0] == 0xd1 && wb[31] == 0xd1);
        ASSERT(boot_staged_bundle_wait_target(
            "/d/bundles/consensus-state-bundle-500.sqlite", &wh, wb));
        ASSERT(wh == 500 && wb[0] == 0xa1);
        ASSERT(boot_staged_bundle_wait_target(
            "/d/bundles/consensus-state-bundle-600.sqlite", &wh, wb));
        ASSERT(wh == 500 && wb[0] == 0xa1); /* unbaked name -> compiled ckpt */
        ASSERT(boot_staged_bundle_wait_target(NULL, &wh, wb));
        ASSERT(wh == 500);
        checkpoints_reset_rom_state_rungs_override_for_test();
        checkpoints_reset_rom_state_override_for_test();
        checkpoints_reset_sha3_override_for_test();
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

        char sroot[PATH_MAX];
        char *sdir = test_mkdtemp(sroot, sizeof(sroot), "zcl_bbf_disc_srv");
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
        fs_server_start(sdir, 0, NULL); /* OS-assigned: no cross-checkout port collisions */
        for (int w = 0; w < 40 && !fs_server_is_running(); w++)
            platform_sleep_ms(50);
        if (fs_server_is_running())
            port = fs_server_get_port();
        ASSERT(port != 0);

        /* Fresh client datadir with NO bundles/directory.json hint. The explicit
         * -fileservice peer + connect_only (no clearnet seeds) makes the lone
         * reachable seed the operator-named one → quorum=1 accepted. */
        char croot[PATH_MAX];
        char *cdir = test_mkdtemp(croot, sizeof(croot), "zcl_bbf_disc_cli");
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

        ASSERT(boot_bundle_fetch_maybe(cdir, &ctx, NULL));

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

/* ── Discovery-outcome observability ──────────────────────────────────────
 *
 * bbf_discover_from_peers() persists a labeled outcome and seed/response
 * counts that boot_bundle_fetch_discovery_dump_state_json reads back. */
static int case_discovery_outcome_persists(void)
{
    int failures = 0;
    TEST("boot_bundle_fetch: discovery outcome persists + the diagnostics "
         "dumper reads it back labeled") {
        char proot[PATH_MAX];
        char *pdir = test_mkdtemp(proot, sizeof(proot), "zcl_bbf_disc_outcome_prog");
        ASSERT(pdir != NULL);
        progress_store_close();
        ASSERT(progress_store_open(pdir));

        /* (1) degraded_single_seed: a lone explicit seed proceeds with fetch
         * redundancy 1. */
        rom_seed_reset();
        rom_seed_set_peer_bps_cap(1ull << 30);
        rom_seed_set_global_bps_cap(1ull << 30);

        char sroot[PATH_MAX];
        char *sdir = test_mkdtemp(sroot, sizeof(sroot), "zcl_bbf_disc_outcome_srv");
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
        fs_server_start(sdir, 0, NULL); /* OS-assigned: no cross-checkout port collisions */
        for (int w = 0; w < 40 && !fs_server_is_running(); w++)
            platform_sleep_ms(50);
        if (fs_server_is_running())
            port = fs_server_get_port();
        ASSERT(port != 0);

        char croot[PATH_MAX];
        char *cdir = test_mkdtemp(croot, sizeof(croot), "zcl_bbf_disc_outcome_cli");
        ASSERT(cdir != NULL);

        struct app_context ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.datadir = cdir;
        char peer_hp[64];
        snprintf(peer_hp, sizeof(peer_hp), "127.0.0.1:%u", (unsigned)port);
        ctx.file_service_peer = peer_hp;
        ctx.connect_only = true;

        ASSERT(boot_bundle_fetch_maybe(cdir, &ctx, NULL));

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

        /* (2) no_quorum_fell_open_to_ibd: a seed that responds but advertises
         * no artifact overwrites the prior outcome. */
        char sroot2[PATH_MAX];
        char *sdir2 = test_mkdtemp(sroot2, sizeof(sroot2), "zcl_bbf_disc_outcome_empty_srv");
        ASSERT(sdir2 != NULL);

        uint16_t port2 = 0;
        fs_server_start(sdir2, 0, NULL); /* OS-assigned: no cross-checkout port collisions */
        for (int w = 0; w < 40 && !fs_server_is_running(); w++)
            platform_sleep_ms(50);
        if (fs_server_is_running())
            port2 = fs_server_get_port();
        ASSERT(port2 != 0);

        char croot2[PATH_MAX];
        char *cdir2 = test_mkdtemp(croot2, sizeof(croot2), "zcl_bbf_disc_outcome_empty_cli");
        ASSERT(cdir2 != NULL);

        struct app_context ctx2;
        memset(&ctx2, 0, sizeof(ctx2));
        ctx2.datadir = cdir2;
        char peer_hp2[64];
        snprintf(peer_hp2, sizeof(peer_hp2), "127.0.0.1:%u", (unsigned)port2);
        ctx2.file_service_peer = peer_hp2;
        ctx2.connect_only = true;

        /* An empty seed lands nothing, but the outcome is still persisted. */
        ASSERT(!boot_bundle_fetch_maybe(cdir2, &ctx2, NULL));

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

/* The seed set the weld may contact (boot_bundle_fetch_seeds.c). */
static int case_seed_set(void)
{
    int failures = 0;
    TEST("boot_bundle_fetch: seed set — connect-only uses the -connect hosts, "
         "never an empty set") {
        struct app_context ctx;

        /* (1) No flags: exactly the compiled clearnet seed set (empty by policy). */
        memset(&ctx, 0, sizeof(ctx));
        size_t compiled_seeds = 0;
        while (ZCL_BUNDLE_FETCH_CLEARNET_SEEDS[compiled_seeds])
            compiled_seeds++;
        size_t open_seeds = boot_bundle_fetch_seed_count(&ctx);
        ASSERT(open_seeds == compiled_seeds);

        /* (2) connect-only with -connect=host:8033 (default P2P port) and no
         * -fileservice seeds file-service at host:FS_PORT; a non-default port
         * stays refused. */
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

        /* (2b) A -connect value naming no port seeds the file service at FS_PORT. */
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
 * Peers advertise their file-service port via zfileaddr and the node caches it;
 * boot_bundle_fetch_peer_seeds.c turns that cache into seeds. A discovered seed
 * is only an address: it travels the same verification path as an
 * operator-named seed. No wall-clock duration is asserted. */

/* (1) PURE: does a cached peer endpoint become a seed? Only if that peer
 * actually advertised a file-service port. */
static int case_peer_seed_offer_filter(void)
{
    int failures = 0;
    TEST("boot_bundle_fetch: a peer becomes an instant-on seed IFF it "
         "advertised a file-service port, dialed at THAT port") {
        struct app_context ctx;
        boot_bundle_fetch_disarm_peer_seeds();

        /* Baseline: no flags, no peers -> the empty set. */
        memset(&ctx, 0, sizeof(ctx));
        size_t compiled_seeds = 0;
        while (ZCL_BUNDLE_FETCH_CLEARNET_SEEDS[compiled_seeds])
            compiled_seeds++;
        ASSERT(boot_bundle_fetch_seed_count(&ctx) == compiled_seeds);
        ASSERT(boot_bundle_fetch_armed_peer_seed_count() == 0);

        /* A cached peer row naming no file-service port is not offered. */
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

        /* The peer's own advertised port is used, not FS_PORT: an explicit
         * -fileservice for the same host and port de-dups onto it. */
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
    fs_server_start(s->dir, 0, NULL);
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
/* One-artifact /directory.json body advertising `a` (whole-file digest
 * `whole`) as a consensus bundle at `height`. */
static bool bbf_artifact_json(char *out, size_t cap,
                              const struct rom_artifact *a,
                              const uint8_t whole[32], int64_t height)
{
    char digest_hex[65], whole_hex[65];
    HexStr(a->chunk_root, 32, false, digest_hex, sizeof(digest_hex));
    HexStr(whole, 32, false, whole_hex, sizeof(whole_hex));
    int n = snprintf(out, cap,
                     "{\"count\":1,\"artifacts\":[{\"kind\":\"consensus_bundle\","
                     "\"digest\":\"%s\",\"whole_sha3\":\"%s\",\"size\":%llu,"
                     "\"chunk_size\":%u,\"chunks\":%u,\"height\":%lld}]}",
                     digest_hex, whole_hex,
                     (unsigned long long)a->size_bytes, a->chunk_size,
                     a->num_chunks, (long long)height);
    return n > 0 && (size_t)n < cap;
}

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
    char json[1024];
    if (!bbf_artifact_json(json, sizeof(json), a, whole, 3056758))
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

        /* (a) No operator flags: the only seed is the peer that advertised its
         * file-service port via zfileaddr. */
        char cdir[256];
        test_make_tmpdir(cdir, sizeof(cdir), "bbf_peerseed_ok", "ok");
        struct app_context ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.datadir = cdir;
        ASSERT(boot_bundle_fetch_seed_count(&ctx) == 0); /* the stranger today */
        boot_bundle_fetch_arm_peer_seed_for_test("127.0.0.1", srv.port);
        ASSERT(boot_bundle_fetch_seed_count(&ctx) == 1);
        ASSERT(bbf_write_hint(cdir, &srv.art, false));
        ASSERT(boot_bundle_fetch_maybe(cdir, &ctx, NULL));
        char *landed = boot_autodetect_consensus_bundle(cdir);
        ASSERT(landed != NULL);
        free(landed);

        /* (b) Same seed, but the client committed to a non-matching digest:
         * refused, nothing lands, no marker. */
        char bdir[256];
        test_make_tmpdir(bdir, sizeof(bdir), "bbf_peerseed_bad", "ok");
        struct app_context bctx;
        memset(&bctx, 0, sizeof(bctx));
        bctx.datadir = bdir;
        ASSERT(bbf_write_hint(bdir, &srv.art, true));
        ASSERT(!boot_bundle_fetch_maybe(bdir, &bctx, NULL));
        char *bad_auto = boot_autodetect_consensus_bundle(bdir);
        ASSERT(bad_auto == NULL);
        free(bad_auto);
        ASSERT(!boot_consensus_bundle_marker_exists(bdir));

        /* (c) The same corrupt commitment against a flag-supplied seed fails
         * identically. */
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
        ASSERT(!boot_bundle_fetch_maybe(fdir, &fctx, NULL));
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
        ASSERT(boot_bundle_fetch_maybe(gdir, &gctx, NULL));
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

/* (3) A peer that advertises the file service but does not serve costs a
 * bounded wait and is dropped; the remaining seeds still land the bundle.
 * The recv window is shortened here; the test asserts the default is unchanged. */
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
        platform_socket_t stall_fd = platform_socket_open(AF_INET,
                                                          SOCK_STREAM, 0,
                                                          true, false);
        ASSERT(stall_fd != PLATFORM_SOCKET_INVALID);
        ASSERT(platform_socket_set_reuse_address(stall_fd, true) == 0);
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sa.sin_port = 0; /* OS-assigned */
        ASSERT(platform_socket_bind(stall_fd, (struct sockaddr *)&sa,
                                    sizeof(sa)) == 0);
        ASSERT(platform_socket_listen(stall_fd, 8) == 0);
        size_t slen = sizeof(sa);
        ASSERT(platform_socket_local_address(stall_fd,
                                             (struct sockaddr *)&sa,
                                             &slen) == 0);
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
        ASSERT(boot_bundle_fetch_maybe(cdir, &ctx, NULL));
        char *landed = boot_autodetect_consensus_bundle(cdir);
        ASSERT(landed != NULL);
        free(landed);

        /* Restore the production bound for every later case. */
        rom_fetch_set_directory_io_timeout_ms_for_test(0);
        ASSERT(rom_fetch_directory_io_timeout_ms_for_test() ==
               rom_fetch_directory_io_timeout_default_ms_for_test());

        platform_socket_close(stall_fd);
        test_rm_rf_recursive(cdir);
        bbf_seeder_stop(&srv);
    } _test_next:;
    rom_fetch_set_directory_io_timeout_ms_for_test(0);
    boot_bundle_fetch_disarm_peer_seeds();
    return failures;
}

/* ── Poisoned hint, untrusted height, free space (hunt B[9], B[13]) ─────── */

static bool bbf_exists(const char *dir, const char *rel)
{
    char p[1024];
    int n = snprintf(p, sizeof(p), "%s/%s", dir, rel);
    return n > 0 && (size_t)n < sizeof(p) && access(p, F_OK) == 0;
}

/* FNV-1a over a file's bytes; false when unreadable. */
static bool bbf_file_fnv(const char *path, uint64_t *out)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    uint64_t h = 1469598103934665603ull;
    int ch;
    while ((ch = fgetc(f)) != EOF) {
        h ^= (uint64_t)(unsigned char)ch;
        h *= 1099511628211ull;
    }
    bool ok = !ferror(f);
    fclose(f);
    *out = h;
    return ok;
}

#define BBF_SNAP_MAX 32
#define BBF_SNAP_NAME 256

static int bbf_name_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

/* One "name size fnv" line per sorted entry of `dir`. */
static bool bbf_snapshot_lines(const char *dir, char (*names)[BBF_SNAP_NAME],
                               size_t n, char *out, size_t cap)
{
    size_t off = 0;
    out[0] = '\0';
    for (size_t i = 0; i < n; i++) {
        char p[1024];
        struct stat st;
        uint64_t h = 0;
        snprintf(p, sizeof(p), "%s/%s", dir, names[i]);
        if (stat(p, &st) != 0)
            return false;
        if (S_ISREG(st.st_mode) && !bbf_file_fnv(p, &h))
            return false;
        /* A directory's own st_size is filesystem bookkeeping; its entries
         * are snapshotted separately. */
        long long size = S_ISDIR(st.st_mode) ? 0 : (long long)st.st_size;
        int w = snprintf(out + off, cap - off, "%s %lld %016llx\n", names[i],
                         size, (unsigned long long)h);
        if (w < 0 || (size_t)w >= cap - off)
            return false;
        off += (size_t)w;
    }
    return true;
}

/* Byte-level snapshot of a directory: equal snapshots mean the same names,
 * sizes and contents. */
static bool bbf_snapshot_dir(const char *dir, char *out, size_t cap)
{
    static char names[BBF_SNAP_MAX][BBF_SNAP_NAME];
    size_t n = 0;
    DIR *d = opendir(dir);
    if (!d)
        return false;
    struct dirent *e;
    bool ok = true;
    while (ok && (e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        ok = n < BBF_SNAP_MAX && strlen(e->d_name) < BBF_SNAP_NAME;
        if (ok)
            snprintf(names[n++], BBF_SNAP_NAME, "%s", e->d_name);
    }
    closedir(d);
    if (!ok)
        return false;
    qsort(names, n, sizeof(names[0]), bbf_name_cmp);
    return bbf_snapshot_lines(dir, names, n, out, cap);
}

/* True when <datadir>/bundles/directory.json names the bundle `name`. */
static bool bbf_hint_names(const char *datadir, const char *name)
{
    char p[1024];
    snprintf(p, sizeof(p), "%s/bundles/directory.json", datadir);
    FILE *f = fopen(p, "rb");
    if (!f)
        return false;
    char body[4096];
    size_t n = fread(body, 1, sizeof(body) - 1, f);
    fclose(f);
    body[n] = '\0';
    struct rom_fetch_manifest m;
    memset(&m, 0, sizeof(m));
    return boot_bundle_pick_manifest(body, &m) && strcmp(m.filename, name) == 0;
}

static void bbf_refused_result(struct consensus_state_install_runtime_result *rr)
{
    memset(rr, 0, sizeof(*rr));
    rr->status = CONSENSUS_INSTALL_REFUSED;
    rr->height = -1;
    rr->hstar = -1;
    snprintf(rr->reason, sizeof(rr->reason), "%s",
             "test: bundle content matches no compiled authority");
}

#define BBF_POISON_HONEST_H    3100000          /* names no baked commitment */
#define BBF_POISON_JUNK_H      ((int64_t)1 << 40)
#define BBF_POISON_HONEST_NAME "consensus-state-bundle-3100000.sqlite"
#define BBF_POISON_JUNK_NAME   "consensus-state-bundle-1099511627776.sqlite"

static struct rom_artifact g_poison_honest, g_poison_junk;
static uint16_t g_poison_port;

/* Seed 127.0.0.1 lists only the honest artifact at H; seed 127.0.0.2 lists
 * only the junk artifact at 2^40. One wildcard-bound loopback server serves
 * both artifacts' chunks. */
static bool bbf_poison_directory(const char *addr, uint16_t port, char *buf,
                                 size_t cap)
{
    if (port != g_poison_port)
        return false;
    if (strcmp(addr, "127.0.0.1") == 0)
        return bbf_artifact_json(buf, cap, &g_poison_honest,
                                 g_poison_honest.whole_sha3,
                                 BBF_POISON_HONEST_H);
    if (strcmp(addr, "127.0.0.2") == 0)
        return bbf_artifact_json(buf, cap, &g_poison_junk,
                                 g_poison_junk.whole_sha3, BBF_POISON_JUNK_H);
    return false;
}

static bool bbf_poison_start(char *dir, size_t cap)
{
    /* A failed earlier case skips its cleanup; never serve from its root. */
    fs_server_stop();
    rom_seed_reset();
    rom_seed_set_peer_bps_cap(1ull << 30);
    rom_seed_set_global_bps_cap(1ull << 30);
    test_make_tmpdir(dir, cap, "bbf_poison_srv", "ok");
    size_t size = (size_t)ROM_SEED_CHUNK_SIZE + 4096;
    uint8_t *buf = malloc(size);
    if (!buf)
        return false;
    bbf_gen_content(buf, size);
    bool ok = bbf_write_file(dir, "consensus-state-bundle-3100000.sqlite", buf,
                             size);
    for (size_t i = 16; i < size; i++)
        buf[i] ^= 0x5a;
    ok = ok && bbf_write_file(dir, "consensus-state-bundle-3100001.sqlite", buf,
                              size);
    free(buf);
    ok = ok &&
         rom_seed_register(dir, "consensus-state-bundle-3100000.sqlite", NULL,
                           &g_poison_honest) == ROM_REG_OK &&
         rom_seed_register(dir, "consensus-state-bundle-3100001.sqlite", NULL,
                           &g_poison_junk) == ROM_REG_OK;
    if (!ok)
        return false;
    fs_server_start(dir, 0, NULL);
    for (int w = 0; w < 40 && !fs_server_is_running(); w++)
        platform_sleep_ms(50);
    g_poison_port = fs_server_is_running() ? fs_server_get_port() : 0;
    return g_poison_port != 0;
}

/* (a) A hostile seed's junk bundle lands, is refused at install and marked
 * .failed: the hint naming it is dropped, the next boot re-discovers, never
 * fetches the .failed triple again and fetches the honest one; refusing that
 * one too ends the cycle (never-stuck, no download loop). */
static int case_poisoned_hint_rediscovers(void)
{
    int failures = 0;
    static char log[262144];
    TEST("boot_bundle_fetch: a refused junk bundle drops the hint naming it; "
         "the next boot re-discovers, skips the .failed triple and fetches "
         "the honest one") {
        char sdir[256];
        boot_bundle_fetch_disarm_peer_seeds();
        ASSERT(bbf_poison_start(sdir, sizeof(sdir)));
        boot_bundle_fetch_set_directory_fetch_for_test(bbf_poison_directory);
        boot_bundle_fetch_arm_peer_seed_for_test("127.0.0.1", g_poison_port);
        boot_bundle_fetch_arm_peer_seed_for_test("127.0.0.2", g_poison_port);
        char cdir[256];
        test_make_tmpdir(cdir, sizeof(cdir), "bbf_poison_cli", "ok");
        struct app_context ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.datadir = cdir;
        ASSERT(boot_bundle_fetch_seed_count(&ctx) == 2);

        /* Boot 1: one seed each, no baked height, so the higher junk claim
         * ranks first; its bytes match its own manifest, so it lands. */
        ASSERT(boot_bundle_fetch_maybe(cdir, &ctx, NULL));
        ASSERT(bbf_exists(cdir, "bundles/" BBF_POISON_JUNK_NAME));
        ASSERT(!bbf_exists(cdir, "bundles/" BBF_POISON_HONEST_NAME));
        ASSERT(bbf_hint_names(cdir, BBF_POISON_JUNK_NAME));

        /* The installer refuses it for a genuine content reason. */
        char junk[1024];
        snprintf(junk, sizeof(junk), "%s/bundles/%s", cdir,
                 BBF_POISON_JUNK_NAME);
        struct consensus_state_install_runtime_result rr;
        bbf_refused_result(&rr);
        boot_auto_install_refusal_for_test(cdir, junk, &rr);
        ASSERT(bbf_exists(cdir, "bundles/" BBF_POISON_JUNK_NAME ".failed"));
        ASSERT(!bbf_exists(cdir, "bundles/directory.json"));
        /* Not provably junk to this build: the file itself stays. */
        ASSERT(bbf_exists(cdir, "bundles/" BBF_POISON_JUNK_NAME));

        /* Boot 2: discovery runs again; the .failed triple is not fetched. */
        bool landed = false;
        ASSERT(bbf_capture_maybe(cdir, &ctx, &landed, log, sizeof(log)));
        ASSERT(landed);
        ASSERT(strstr(log, "attempting peer directory discovery") != NULL);
        ASSERT(strstr(log, "checking download sources for "
                           BBF_POISON_HONEST_NAME) != NULL);
        ASSERT(strstr(log, "checking download sources for "
                           BBF_POISON_JUNK_NAME) == NULL);
        ASSERT(strstr(log, BBF_POISON_JUNK_NAME " already present") == NULL);
        ASSERT(bbf_exists(cdir, "bundles/" BBF_POISON_HONEST_NAME));
        ASSERT(bbf_hint_names(cdir, BBF_POISON_HONEST_NAME));

        /* Refusing the honest one too: hint dropped, boot 3 fetches nothing. */
        char honest[1024];
        snprintf(honest, sizeof(honest), "%s/bundles/%s", cdir,
                 BBF_POISON_HONEST_NAME);
        boot_auto_install_refusal_for_test(cdir, honest, &rr);
        ASSERT(!bbf_exists(cdir, "bundles/directory.json"));
        ASSERT(bbf_capture_maybe(cdir, &ctx, &landed, log, sizeof(log)));
        ASSERT(!landed);
        ASSERT(strstr(log, "checking download sources") == NULL);
        ASSERT(!bbf_exists(cdir, "bundles/directory.json"));

        test_rm_rf_recursive(cdir);
        fs_server_stop();
        test_rm_rf_recursive(sdir);
        rom_seed_reset();
    } _test_next:;
    boot_bundle_fetch_set_directory_fetch_for_test(NULL);
    boot_bundle_fetch_disarm_peer_seeds();
    return failures;
}

/* (b) An advertised height is an untrusted claim: agreement among more seeds
 * outranks one seed advertising a higher height. */
static int case_quorum_untrusted_height(void)
{
    int failures = 0;
    TEST("boot_bundle_fetch: two seeds agreeing on H outrank one seed "
         "advertising a higher height") {
        const int64_t huge = (int64_t)1 << 40;
        bool f[] = { false, false };
        int64_t h[] = { 3056758, huge };
        int c[] = { 2, 1 };
        ASSERT(boot_bundle_quorum_pick_for_test(h, c, f, 2) == 0);
        int64_t hr[] = { huge, 3056758 };
        int cr[] = { 1, 2 };
        ASSERT(boot_bundle_quorum_pick_for_test(hr, cr, f, 2) == 1);

        /* Neither height names a baked commitment: agreement first. */
        int64_t u[] = { 3100000, 3150000 };
        int uc[] = { 2, 1 };
        ASSERT(boot_bundle_quorum_pick_for_test(u, uc, f, 2) == 0);
        int ueq[] = { 1, 1 };
        ASSERT(boot_bundle_quorum_pick_for_test(u, ueq, f, 2) == 1);

        /* Any number of seeds claiming an unbaked height never outranks a
         * baked commitment. */
        int64_t b[] = { huge, 3056758 };
        int bc[] = { 3, 1 };
        ASSERT(boot_bundle_quorum_pick_for_test(b, bc, f, 2) == 1);
    } _test_next:;
    return failures;
}

static uint64_t g_fake_free;
static bool g_fake_free_ok;
static bool bbf_fake_disk_space(const char *path, uint64_t *available)
{
    (void)path;
    if (!g_fake_free_ok)
        return false;
    *available = g_fake_free;
    return true;
}

/* Write `n` bytes of non-repeating data as <dir>/<name> (a real partial). */
static bool bbf_write_partial(const char *dir, const char *name, size_t n)
{
    uint8_t *buf = malloc(n);
    if (!buf)
        return false;
    uint32_t x = 0x9e3779b9u;
    for (size_t i = 0; i < n; i++) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        buf[i] = (uint8_t)x;
    }
    bool ok = bbf_write_file(dir, name, buf, n);
    free(buf);
    return ok;
}

/* Run one gated download against a dead peer with `free_bytes` reported. */
static bool bbf_disk_attempt(const char *cdir, const struct rom_fetch_manifest *m,
                             bool reader_ok, uint64_t free_bytes, char *log,
                             size_t cap)
{
    struct rom_fetch_peer dead[1];
    memset(dead, 0, sizeof(dead));
    snprintf(dead[0].addr, sizeof(dead[0].addr), "%s", "127.0.0.1");
    dead[0].port = 1;
    g_fake_free_ok = reader_ok;
    g_fake_free = free_bytes;
    bool ok = true;
    return bbf_capture_download(cdir, dead, m, &ok, log, cap) && !ok;
}

/* (c) Free space below what the manifest needs: no fetch starts and the
 * reported reason names disk space, not a transfer failure. */
static int case_disk_space_gate(void)
{
    int failures = 0;
    static char log[65536];
    TEST("boot_bundle_fetch: too little free disk space starts no fetch and "
         "the reason names disk space") {
        uint64_t size = (uint64_t)ROM_SEED_CHUNK_SIZE + 4096;
        char body[1024];
        snprintf(body, sizeof(body),
                 "{\"artifacts\":[{\"kind\":\"consensus_bundle\","
                 "\"digest\":\"%064d\",\"whole_sha3\":\"%064d\",\"size\":%llu,"
                 "\"chunk_size\":%u,\"chunks\":2,\"height\":3056758}]}",
                 1, 2, (unsigned long long)size, (unsigned)ROM_SEED_CHUNK_SIZE);
        struct rom_fetch_manifest m;
        memset(&m, 0, sizeof(m));
        ASSERT(boot_bundle_pick_manifest(body, &m));
        char cdir[256];
        test_make_tmpdir(cdir, sizeof(cdir), "bbf_disk_cli", "ok");
        char part[512];
        snprintf(part, sizeof(part), "bundles/%s%s", m.filename,
                 ROM_FETCH_PART_SUFFIX);
        boot_bundle_fetch_set_disk_space_reader_for_test(bbf_fake_disk_space);
        const uint64_t margin = BOOT_BUNDLE_FETCH_DISK_MARGIN_BYTES;
        char want[128];

        ASSERT(bbf_disk_attempt(cdir, &m, true, size - 1, log, sizeof(log)));
        ASSERT(strstr(log, "not enough free disk space") != NULL);
        snprintf(want, sizeof(want), "free=%llu bytes, needed=%llu bytes",
                 (unsigned long long)(size - 1),
                 (unsigned long long)(size + margin));
        ASSERT(strstr(log, want) != NULL);
        ASSERT(strstr(log, "checking download sources") == NULL);
        ASSERT(strstr(log, "transport failure") == NULL);
        ASSERT(!bbf_exists(cdir, part));

        /* A partial already present is credited: one byte short refuses,
         * exactly enough starts the fetch. */
        char bdir[512];
        snprintf(bdir, sizeof(bdir), "%s/bundles", cdir);
        char part_name[256];
        snprintf(part_name, sizeof(part_name), "%s%s", m.filename,
                 ROM_FETCH_PART_SUFFIX);
        ASSERT(bbf_write_partial(bdir, part_name, 8192));
        ASSERT(bbf_disk_attempt(cdir, &m, true, size + margin - 8192 - 1, log,
                                sizeof(log)));
        snprintf(want, sizeof(want), "needed=%llu bytes",
                 (unsigned long long)(size + margin - 8192));
        ASSERT(strstr(log, want) != NULL);
        ASSERT(strstr(log, "checking download sources") == NULL);
        ASSERT(bbf_disk_attempt(cdir, &m, true, size + margin - 8192, log,
                                sizeof(log)));
        ASSERT(strstr(log, "not enough free disk space") == NULL);
        ASSERT(strstr(log, "checking download sources") != NULL);

        /* A failed free-space reading lets the fetch proceed, with a WARN. */
        ASSERT(bbf_disk_attempt(cdir, &m, false, 0, log, sizeof(log)));
        ASSERT(strstr(log, "could not read the free disk space") != NULL);
        ASSERT(strstr(log, "checking download sources") != NULL);
        test_rm_rf_recursive(cdir);
    } _test_next:;
    boot_bundle_fetch_set_disk_space_reader_for_test(NULL);
    return failures;
}

/* (d) The post-install, owner-gate and deferred outcomes, and a bundle an
 * older build already marked .failed, leave every file in place. */
static bool bbf_nongenuine_outcomes_keep(const char *cdir, const char *bundle,
                                         const char *before)
{
    static char after[8192];
    char bdir[512];
    snprintf(bdir, sizeof(bdir), "%s/bundles", cdir);
    for (int k = 0; k < 3; k++) {
        struct consensus_state_install_runtime_result rr;
        bbf_refused_result(&rr);
        rr.state_installed = k == 0;
        rr.owner_gate_refused = k == 1;
        rr.retriable_headers_not_ready = k == 2;
        boot_auto_install_refusal_for_test(cdir, bundle, &rr);
        if (!bbf_snapshot_dir(bdir, after, sizeof(after)) ||
            strcmp(before, after) != 0)
            return false;
    }
    return true;
}

static int case_nongenuine_refusals_touch_nothing(void)
{
    int failures = 0;
    static char before[8192], after[8192], root_before[2048], root_after[2048];
    TEST("boot_bundle_fetch: deferred, owner-gate and post-install outcomes "
         "and an older build's .failed bundle leave every file in place") {
        struct bbf_seeder srv;
        boot_bundle_fetch_disarm_peer_seeds();
        ASSERT(bbf_seeder_start(&srv));
        char cdir[256];
        test_make_tmpdir(cdir, sizeof(cdir), "bbf_keep_cli", "ok");
        ASSERT(bbf_write_hint(cdir, &srv.art, false));
        char bdir[512];
        snprintf(bdir, sizeof(bdir), "%s/bundles", cdir);
        static const char name[] = "consensus-state-bundle-3056758.sqlite";
        ASSERT(bbf_write_file(bdir, name, srv.content, srv.size));
        char bundle[1024];
        snprintf(bundle, sizeof(bundle), "%s/%s", bdir, name);
        ASSERT(bbf_snapshot_dir(bdir, before, sizeof(before)));
        ASSERT(bbf_nongenuine_outcomes_keep(cdir, bundle, before));
        ASSERT(!bbf_exists(cdir, "bundles/consensus-state-bundle-3056758"
                                 ".sqlite.failed"));

        /* An older build refused it: .failed present, hint still names it. */
        ASSERT(bbf_write_file(bdir, "consensus-state-bundle-3056758.sqlite"
                              ".failed", (const uint8_t *)"", 0));
        ASSERT(bbf_snapshot_dir(bdir, before, sizeof(before)));
        ASSERT(bbf_snapshot_dir(cdir, root_before, sizeof(root_before)));
        struct app_context ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.datadir = cdir;
        boot_bundle_fetch_arm_peer_seed_for_test("127.0.0.1", srv.port);
        ASSERT(!boot_bundle_fetch_maybe(cdir, &ctx, NULL));
        ASSERT(bbf_snapshot_dir(bdir, after, sizeof(after)));
        ASSERT(strcmp(before, after) == 0);
        ASSERT(bbf_snapshot_dir(cdir, root_after, sizeof(root_after)));
        ASSERT(strcmp(root_before, root_after) == 0);

        test_rm_rf_recursive(cdir);
        bbf_seeder_stop(&srv);
    } _test_next:;
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
    failures += case_first_run_banner();
    failures += case_gate();
    failures += case_header_seed_gate();
    failures += case_network_gate();
    failures += case_pick();
    failures += case_pick_kinds();
    failures += case_e2e();
    failures += case_warm_landed();
    failures += case_baked_facts();
    failures += case_pick_newest();
    failures += case_pick_rung_over_keystone();
    failures += case_quorum();
    failures += case_parallel_probe();
    failures += case_parallel_manifest_probe();
    failures += case_manifest_probe_oom_spawns_nothing();
    failures += case_discovery();
    failures += case_discovery_outcome_persists();
    failures += case_quorum_untrusted_height();
    failures += case_disk_space_gate();
    failures += case_nongenuine_refusals_touch_nothing();
    failures += case_poisoned_hint_rediscovers();
    /* Reap the registry-owned reseed workers the cases spawned. */
    boot_bundle_fetch_reseed_wait();
    (void)thread_registry_join_all(5);
    printf("=== boot_bundle_fetch: %d failure(s) ===\n", failures);
    return failures;
}
