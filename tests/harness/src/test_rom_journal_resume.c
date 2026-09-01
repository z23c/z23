/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ROM download resume journal (net/rom_journal.h) — crash-resume proof, in
 * the spirit of tests/harness/src/test_kill9_recovery.c: prove that an abrupt
 * stop mid-download never loses more than the in-flight chunk, and never
 * re-trusts a chunk it did not itself digest-verify.
 *
 * Drives the REAL per-chunk-verified download path (net/rom_fetch.h) against
 * a real fixture seeder (net/file_service.h's fs_server_start, same as
 * test_rom_fetch.c's loopback E2E) — no mocks. "Crash mid-download" is
 * simulated by hand-building the exact `.part` + `.part.journal` state a
 * real rom_fetch_download_verified() run would have left durable at the
 * chunk boundary (same pwrite -> fdatasync(.part) -> mark -> fdatasync
 * ordering rom_fetch.c uses) — this is not a shortcut around the durability
 * contract, it constructs precisely the state that contract promises to
 * leave behind, then "restarts" through the real driver's resume path.
 *
 * Byte accounting is proven server-side: rom_seed's `chunks_served` counter
 * (rom_seed_note_chunk_served, wired at every successful "ROM" chunk serve
 * in file_service.c) is authoritative ground truth for how many chunks
 * crossed the wire — client-side thread timing can't fudge it.
 *
 *   - test_rom_journal_kill9_resume: N-1 of N chunks durable pre-crash,
 *     restart re-fetches EXACTLY the missing chunk, whole-file verify passes.
 *   - test_rom_journal_header_mismatch_discard: a stale journal+part left by
 *     a DIFFERENT artifact (mismatched chunk_root) is discarded wholesale —
 *     no partial trust — and the real content is fetched fresh.
 *   - test_rom_journal_bad_chunk_then_recovery: a chunk that fails content
 *     verification is never journaled (so a resume never trusts it), the
 *     serving endpoint gets deprioritized (net/rom_peer_scoring.h, lane 2C),
 *     and a subsequent attempt with the correct digest completes by
 *     refetching ONLY that chunk — the previously-good chunk is never
 *     re-served. The verify failure here is driven by an intentionally wrong
 *     committed digest rather than a second malicious server (rom_seed's
 *     registration always re-derives digests from real bytes, so forging a
 *     peer that serves non-committed content under a chosen root isn't
 *     constructible through the public API) — the code path exercised is
 *     byte-for-byte the same one a lying peer would hit: rom_fetch_verify_chunk
 *     only ever compares received bytes against the caller's committed digest,
 *     never peer identity.
 */

#include "test/test_core.h"
#include "platform/file_sync.h"
#include "net/rom_journal.h"
#include "net/rom_fetch.h"
#include "net/rom_seed.h"
#include "net/rom_peer_scoring.h"
#include "net/file_service.h"
#include "json/json.h"
#include "platform/time_compat.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int test_rom_journal_header_layout(void)
{
    int failures = 0;
    TEST("rom_journal: on-disk header is exactly 88 bytes") {
        ASSERT(sizeof(struct rom_journal_header) == 88);
        ASSERT(ROM_JOURNAL_MAGIC_LEN == 8);
        ASSERT(strlen(ROM_JOURNAL_MAGIC) == ROM_JOURNAL_MAGIC_LEN);
        ASSERT(ROM_JOURNAL_VERSION == 1);
        PASS();
    } _test_next:;
    return failures;
}

static int test_rom_journal_null_safe(void)
{
    int failures = 0;
    TEST("rom_journal: NULL/degenerate args fail closed; discard is idempotent") {
        uint8_t root[32] = {0}, whole[32] = {0};
        ASSERT(rom_journal_open(NULL, root, whole, 4096, 1) == NULL);
        ASSERT(rom_journal_count_done(NULL) == 0);
        ASSERT(!rom_journal_is_done(NULL, 0));
        rom_journal_close(NULL); /* must not crash */
        ASSERT(rom_journal_discard("/tmp/zcl-nonexistent-journal-xyz.part.journal"));
        PASS();
    } _test_next:;
    return failures;
}

/* ── net/rom_peer_scoring.h — pure local deprioritize-list logic ────────── */

static int test_rom_peer_scoring_basic(void)
{
    int failures = 0;
    TEST("rom_peer_scoring: note/query/refresh/reset on the local list") {
        rom_peer_scoring_test_reset();

        ASSERT(!rom_peer_is_deprioritized("10.0.0.1", 9001));
        ASSERT(!rom_peer_note_bad_chunk(NULL, 9001, 0, "digest"));
        ASSERT(!rom_peer_note_bad_chunk("", 9001, 0, "digest"));

        ASSERT(rom_peer_note_bad_chunk("10.0.0.1", 9001, 3, "digest"));
        ASSERT(rom_peer_is_deprioritized("10.0.0.1", 9001));
        /* A different port is a different endpoint. */
        ASSERT(!rom_peer_is_deprioritized("10.0.0.1", 9002));

        /* Repeat offence on the same endpoint refreshes in place, not a
         * second entry. */
        ASSERT(rom_peer_note_bad_chunk("10.0.0.1", 9001, 4, "mac"));
        ASSERT(rom_peer_is_deprioritized("10.0.0.1", 9001));

        rom_peer_scoring_test_reset();
        ASSERT(!rom_peer_is_deprioritized("10.0.0.1", 9001));
        PASS();
    } _test_next:;
    return failures;
}

static int test_rom_peer_scoring_bounded(void)
{
    int failures = 0;
    TEST("rom_peer_scoring: bounded list caps at ROM_PEER_MAX_DEPRIORITIZE") {
        rom_peer_scoring_test_reset();

        char addr[32];
        for (int i = 0; i < ROM_PEER_MAX_DEPRIORITIZE; i++) {
            snprintf(addr, sizeof(addr), "10.0.1.%d", i + 1);
            ASSERT(rom_peer_note_bad_chunk(addr, 9000, 0, "digest"));
        }
        for (int i = 0; i < ROM_PEER_MAX_DEPRIORITIZE; i++) {
            snprintf(addr, sizeof(addr), "10.0.1.%d", i + 1);
            ASSERT(rom_peer_is_deprioritized(addr, 9000));
        }

        /* List full of live entries: one more DISTINCT endpoint is a bounded
         * drop, never an unbounded grow — and never crashes. */
        ASSERT(!rom_peer_note_bad_chunk("10.0.2.1", 9000, 0, "digest"));
        ASSERT(!rom_peer_is_deprioritized("10.0.2.1", 9000));

        /* A repeat offence against an EXISTING entry still refreshes fine
         * even while the list is full. */
        ASSERT(rom_peer_note_bad_chunk("10.0.1.1", 9000, 1, "mac"));

        rom_peer_scoring_test_reset();
        PASS();
    } _test_next:;
    return failures;
}

/* ── Fixture helpers (mirror tests/harness/src/test_rom_fetch.c) ────────────── */

static void gen_content(uint8_t *buf, size_t size)
{
    static const uint8_t magic[16] = "SQLite format 3";
    for (size_t i = 0; i < size; i++)
        buf[i] = (uint8_t)((i * 131u + 7u) & 0xffu);
    if (size >= 16)
        memcpy(buf, magic, 16);
}

static bool write_file(const char *dir, const char *name,
                       const uint8_t *buf, size_t size)
{
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return false;
    size_t off = 0;
    while (off < size) {
        ssize_t w = write(fd, buf + off, size - off);
        if (w <= 0) { close(fd); return false; }
        off += (size_t)w;
    }
    close(fd);
    return true;
}

static void manifest_from_artifact(const struct rom_artifact *a,
                                   struct rom_fetch_manifest *m)
{
    memset(m, 0, sizeof(*m));
    m->used = true;
    snprintf(m->filename, sizeof(m->filename), "%s", a->filename);
    m->size_bytes = a->size_bytes;
    m->chunk_size = a->chunk_size;
    m->num_chunks = a->num_chunks;
    memcpy(m->chunk_root, a->chunk_root, 32);
    memcpy(m->whole_sha3, a->whole_sha3, 32);
}

static uint16_t start_fixture_server(const char *dir)
{
    /* OS-assigned port: suites in parallel worktrees must never collide. */
    fs_server_start(dir, 0);
    for (int w = 0; w < 40 && !fs_server_is_running(); w++)
        platform_sleep_ms(50); /* up to 2 s for bind+listen */
    return fs_server_is_running() ? fs_server_get_port() : 0;
}

static int64_t seed_chunks_served(void)
{
    struct json_value dj;
    json_init(&dj);
    (void)rom_seed_dump_state_json(&dj, NULL);
    int64_t n = json_get_int(json_get(&dj, "chunks_served"));
    json_free(&dj);
    return n;
}

/* fs_send_chunk_fast() returns once the reply bytes are handed off; the
 * server worker increments its authoritative counter immediately afterward.
 * A fast client can therefore observe the reply a scheduler quantum before
 * the counter under heavy parallel-suite load. Wait only for that one-sided
 * handoff, then retain the exact-count assertion at every call site. */
static int64_t seed_chunks_served_wait_at_least(int64_t expected)
{
    int64_t observed = seed_chunks_served();
    for (int i = 0; observed < expected && i < 2000; i++) {
        platform_sleep_ms(1);
        observed = seed_chunks_served();
    }
    return observed;
}

/* ── (a) Kill-9-mid-download resume: byte accounting ────────────────────── */

static int test_rom_journal_kill9_resume(void)
{
    int failures = 0;
    TEST("rom_journal: kill-9-mid-download resume refetches ONLY the "
         "missing chunk (byte accounting via server-side chunks_served)") {
        fs_server_stop(); /* defensive: never inherit a server an earlier failed test leaked */
        rom_seed_reset();
        rom_peer_scoring_test_reset();
        rom_seed_set_peer_bps_cap(1ull << 30);
        rom_seed_set_global_bps_cap(1ull << 30);

        char sroot[] = "/tmp/zcl_romjrnl_k9srv_XXXXXX";
        char *sdir = mkdtemp(sroot);
        ASSERT(sdir != NULL);
        char croot[] = "/tmp/zcl_romjrnl_k9cli_XXXXXX";
        char *cdir = mkdtemp(croot);
        ASSERT(cdir != NULL);

        /* 3 chunks: two full 4 MB chunks + a short 4 KB tail. */
        size_t size = 2 * (size_t)ROM_SEED_CHUNK_SIZE + 4096;
        uint8_t *content = malloc(size);
        ASSERT(content != NULL);
        gen_content(content, size);
        ASSERT(write_file(sdir, "consensus-state-bundle-k9.sqlite",
                          content, size));

        struct rom_artifact art;
        ASSERT(rom_seed_register(sdir, "consensus-state-bundle-k9.sqlite",
                                 NULL, &art) == ROM_REG_OK);
        ASSERT(art.num_chunks == 3);
        struct rom_fetch_manifest m;
        manifest_from_artifact(&art, &m);

                uint16_t port = start_fixture_server(sdir);
        ASSERT(port != 0);

        /* Real manifest fetch — the actual RMF wire path. */
        uint8_t (*chunk_sha3)[32] =
            malloc((size_t)ROM_SEED_MAX_CHUNKS * 32);
        ASSERT(chunk_sha3 != NULL);
        uint32_t manifest_chunks = 0;
        ASSERT(rom_fetch_get_manifest("127.0.0.1", port, m.chunk_root,
                                      chunk_sha3, ROM_SEED_MAX_CHUNKS,
                                      &manifest_chunks));
        ASSERT(manifest_chunks == 3);

        /* Build the exact .part + .part.journal a real download_verified()
         * run would have left durable after chunks 0 and 1 (N-1 of N), then
         * died before chunk 2. */
        char part_path[1200];
        snprintf(part_path, sizeof(part_path), "%s/%s%s", cdir, m.filename,
                 ROM_FETCH_PART_SUFFIX);
        char jrnl_path[1264];
        snprintf(jrnl_path, sizeof(jrnl_path), "%s.journal", part_path);

        int fd = open(part_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
        ASSERT(fd >= 0);
        struct rom_journal *j = rom_journal_open(jrnl_path, m.chunk_root,
                                                 m.whole_sha3, m.chunk_size,
                                                 m.num_chunks);
        ASSERT(j != NULL);
        uint8_t *cbuf = malloc(ROM_SEED_CHUNK_SIZE);
        ASSERT(cbuf != NULL);
        for (uint32_t ci = 0; ci < 2; ci++) {
            uint32_t got = 0;
            ASSERT(rom_fetch_chunk("127.0.0.1", port, m.chunk_root, ci,
                                   cbuf, ROM_SEED_CHUNK_SIZE, &got));
            ASSERT(rom_fetch_verify_chunk(cbuf, got, chunk_sha3[ci]));
            ssize_t w = pwrite(fd, cbuf, got,
                              (off_t)((uint64_t)ci * m.chunk_size));
            ASSERT(w == (ssize_t)got);
            ASSERT(platform_data_sync(fd) == 0);
            ASSERT(rom_journal_mark(j, ci));
        }
        free(cbuf);
        close(fd);
        ASSERT(rom_journal_count_done(j) == 2);
        rom_journal_close(j); /* "process dies" here — no clean shutdown */

        int64_t served_before = seed_chunks_served();

        /* "Restart": resume through the real driver. */
        ASSERT(rom_fetch_download_verified("127.0.0.1", port, &m, chunk_sha3,
                                           manifest_chunks, cdir, NULL, NULL));

        int64_t served_after =
            seed_chunks_served_wait_at_least(served_before + 1);
        /* THE assertion: exactly ONE chunk crossed the wire on resume. */
        ASSERT(served_after - served_before == 1);

        char final_path[1200];
        snprintf(final_path, sizeof(final_path), "%s/%s", cdir, m.filename);
        ASSERT(rom_fetch_verify_file(final_path, &m));
        struct stat st;
        ASSERT(stat(jrnl_path, &st) != 0); /* journal cleaned up on install */

        free(chunk_sha3);
        fs_server_stop();
        free(content);
        char p[1024];
        snprintf(p, sizeof(p), "%s/consensus-state-bundle-k9.sqlite", sdir);
        unlink(p);
        unlink(final_path);
        rmdir(sdir);
        rmdir(cdir);
        rom_seed_reset();
        PASS();
    } _test_next:;
    return failures;
}

/* ── (b) Stale journal from a DIFFERENT artifact: discard, never partial-trust ── */

static int test_rom_journal_header_mismatch_discard(void)
{
    int failures = 0;
    TEST("rom_journal: header-mismatched journal+part is discarded wholesale "
         "through the real download path (no partial trust)") {
        fs_server_stop(); /* defensive: never inherit a server an earlier failed test leaked */
        rom_seed_reset();
        rom_peer_scoring_test_reset();
        rom_seed_set_peer_bps_cap(1ull << 30);
        rom_seed_set_global_bps_cap(1ull << 30);

        char sroot[] = "/tmp/zcl_romjrnl_hmsrv_XXXXXX";
        char *sdir = mkdtemp(sroot);
        ASSERT(sdir != NULL);
        char croot[] = "/tmp/zcl_romjrnl_hmcli_XXXXXX";
        char *cdir = mkdtemp(croot);
        ASSERT(cdir != NULL);

        size_t size = (size_t)ROM_SEED_CHUNK_SIZE + 4096; /* 2 chunks */
        uint8_t *content = malloc(size);
        ASSERT(content != NULL);
        gen_content(content, size);
        ASSERT(write_file(sdir, "consensus-state-bundle-hm.sqlite",
                          content, size));

        struct rom_artifact art;
        ASSERT(rom_seed_register(sdir, "consensus-state-bundle-hm.sqlite",
                                 NULL, &art) == ROM_REG_OK);
        ASSERT(art.num_chunks == 2);
        struct rom_fetch_manifest m;
        manifest_from_artifact(&art, &m);

                uint16_t port = start_fixture_server(sdir);
        ASSERT(port != 0);

        uint8_t (*chunk_sha3)[32] =
            malloc((size_t)ROM_SEED_MAX_CHUNKS * 32);
        ASSERT(chunk_sha3 != NULL);
        uint32_t manifest_chunks = 0;
        ASSERT(rom_fetch_get_manifest("127.0.0.1", port, m.chunk_root,
                                      chunk_sha3, ROM_SEED_MAX_CHUNKS,
                                      &manifest_chunks));

        char part_path[1200];
        snprintf(part_path, sizeof(part_path), "%s/%s%s", cdir, m.filename,
                 ROM_FETCH_PART_SUFFIX);
        char jrnl_path[1264];
        snprintf(jrnl_path, sizeof(jrnl_path), "%s.journal", part_path);

        /* A journal claiming full completion under a DIFFERENT artifact's
         * identity (wrong chunk_root), and a .part full of bytes that are
         * NOT the committed content. This is what a stale download of some
         * other artifact reusing the same filename would leave behind. */
        uint8_t wrong_root[32];
        memcpy(wrong_root, m.chunk_root, 32);
        wrong_root[0] ^= 0xFF;
        struct rom_journal *stale = rom_journal_open(
            jrnl_path, wrong_root, m.whole_sha3, m.chunk_size, m.num_chunks);
        ASSERT(stale != NULL);
        ASSERT(rom_journal_mark(stale, 0));
        rom_journal_close(stale);

        uint8_t *garbage = malloc(size);
        ASSERT(garbage != NULL);
        memset(garbage, 0x5A, size);
        ASSERT(write_file(cdir, "consensus-state-bundle-hm.sqlite.part",
                          garbage, size));
        free(garbage);

        int64_t served_before = seed_chunks_served();

        ASSERT(rom_fetch_download_verified("127.0.0.1", port, &m, chunk_sha3,
                                           manifest_chunks, cdir, NULL, NULL));

        int64_t served_after = seed_chunks_served_wait_at_least(
            served_before + (int64_t)m.num_chunks);
        /* Nothing carried over from the stale state: every chunk of the
         * real artifact crossed the wire fresh. */
        ASSERT(served_after - served_before == (int64_t)m.num_chunks);

        char final_path[1200];
        snprintf(final_path, sizeof(final_path), "%s/%s", cdir, m.filename);
        ASSERT(rom_fetch_verify_file(final_path, &m)); /* real content, not garbage */

        free(chunk_sha3);
        fs_server_stop();
        free(content);
        char p[1024];
        snprintf(p, sizeof(p), "%s/consensus-state-bundle-hm.sqlite", sdir);
        unlink(p);
        unlink(final_path);
        rmdir(sdir);
        rmdir(cdir);
        rom_seed_reset();
        PASS();
    } _test_next:;
    return failures;
}

/* ── (c) Bad chunk detected, endpoint deprioritized, then clean recovery ── */

static int test_rom_journal_bad_chunk_then_recovery(void)
{
    int failures = 0;
    TEST("rom_journal: a failed content-verify never journals the bad chunk, "
         "deprioritizes the endpoint, and a corrected retry refetches ONLY "
         "that chunk") {
        fs_server_stop(); /* defensive: never inherit a server an earlier failed test leaked */
        rom_seed_reset();
        rom_peer_scoring_test_reset();
        rom_seed_set_peer_bps_cap(1ull << 30);
        rom_seed_set_global_bps_cap(1ull << 30);

        char sroot[] = "/tmp/zcl_romjrnl_bcsrv_XXXXXX";
        char *sdir = mkdtemp(sroot);
        ASSERT(sdir != NULL);
        char croot[] = "/tmp/zcl_romjrnl_bccli_XXXXXX";
        char *cdir = mkdtemp(croot);
        ASSERT(cdir != NULL);

        size_t size = (size_t)ROM_SEED_CHUNK_SIZE + 4096; /* 2 chunks */
        uint8_t *content = malloc(size);
        ASSERT(content != NULL);
        gen_content(content, size);
        ASSERT(write_file(sdir, "consensus-state-bundle-bc.sqlite",
                          content, size));

        struct rom_artifact art;
        ASSERT(rom_seed_register(sdir, "consensus-state-bundle-bc.sqlite",
                                 NULL, &art) == ROM_REG_OK);
        ASSERT(art.num_chunks == 2);
        struct rom_fetch_manifest m;
        manifest_from_artifact(&art, &m);

                uint16_t port = start_fixture_server(sdir);
        ASSERT(port != 0);

        uint8_t (*good_sha3)[32] = malloc((size_t)ROM_SEED_MAX_CHUNKS * 32);
        ASSERT(good_sha3 != NULL);
        uint32_t manifest_chunks = 0;
        ASSERT(rom_fetch_get_manifest("127.0.0.1", port, m.chunk_root,
                                      good_sha3, ROM_SEED_MAX_CHUNKS,
                                      &manifest_chunks));
        ASSERT(manifest_chunks == 2);
        ASSERT(!rom_peer_is_deprioritized("127.0.0.1", port));

        /* Pre-seed chunk 0 as durable + verified (deterministic — mirrors
         * the kill-9 test's crash-boundary construction). */
        char part_path[1200];
        snprintf(part_path, sizeof(part_path), "%s/%s%s", cdir, m.filename,
                 ROM_FETCH_PART_SUFFIX);
        char jrnl_path[1264];
        snprintf(jrnl_path, sizeof(jrnl_path), "%s.journal", part_path);
        int fd = open(part_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
        ASSERT(fd >= 0);
        struct rom_journal *j = rom_journal_open(jrnl_path, m.chunk_root,
                                                 m.whole_sha3, m.chunk_size,
                                                 m.num_chunks);
        ASSERT(j != NULL);
        uint8_t *cbuf = malloc(ROM_SEED_CHUNK_SIZE);
        ASSERT(cbuf != NULL);
        uint32_t got = 0;
        ASSERT(rom_fetch_chunk("127.0.0.1", port, m.chunk_root, 0,
                               cbuf, ROM_SEED_CHUNK_SIZE, &got));
        ASSERT(rom_fetch_verify_chunk(cbuf, got, good_sha3[0]));
        ASSERT(pwrite(fd, cbuf, got, 0) == (ssize_t)got);
        ASSERT(platform_data_sync(fd) == 0);
        ASSERT(rom_journal_mark(j, 0));
        free(cbuf);
        close(fd);
        rom_journal_close(j);

        /* A committed digest for chunk 1 that does NOT match what the peer
         * actually has — the same failure shape a lying/corrupt peer would
         * produce (verify only ever compares bytes-vs-committed-digest). */
        uint8_t (*bad_sha3)[32] = malloc((size_t)ROM_SEED_MAX_CHUNKS * 32);
        ASSERT(bad_sha3 != NULL);
        memcpy(bad_sha3, good_sha3, (size_t)manifest_chunks * 32);
        bad_sha3[1][0] ^= 0xFF;

        int64_t served_before = seed_chunks_served();
        ASSERT(!rom_fetch_download_verified("127.0.0.1", port, &m, bad_sha3,
                                            manifest_chunks, cdir, NULL, NULL));
        int64_t served_after =
            seed_chunks_served_wait_at_least(served_before + 1);
        /* Chunk 1 was fetched over the wire (the server has no notion of
         * client-side digest correctness) but chunk 0 was NOT re-served. */
        ASSERT(served_after - served_before == 1);
        free(bad_sha3);

        /* The endpoint is now deprioritized — my rom_peer_scoring wiring at
         * the digest-mismatch site in rom_fetch.c fired. */
        ASSERT(rom_peer_is_deprioritized("127.0.0.1", port));

        /* State left resumable: chunk 0 still durably marked, chunk 1 not. */
        struct stat st;
        ASSERT(stat(part_path, &st) == 0);
        ASSERT(stat(jrnl_path, &st) == 0);
        struct rom_journal *check = rom_journal_open(
            jrnl_path, m.chunk_root, m.whole_sha3, m.chunk_size, m.num_chunks);
        ASSERT(check != NULL);
        ASSERT(rom_journal_is_done(check, 0));
        ASSERT(!rom_journal_is_done(check, 1));
        rom_journal_close(check);

        /* Recovery: the correct digest for chunk 1 completes the download,
         * refetching ONLY that chunk. */
        served_before = seed_chunks_served();
        ASSERT(rom_fetch_download_verified("127.0.0.1", port, &m, good_sha3,
                                           manifest_chunks, cdir, NULL, NULL));
        served_after = seed_chunks_served_wait_at_least(served_before + 1);
        ASSERT(served_after - served_before == 1);

        char final_path[1200];
        snprintf(final_path, sizeof(final_path), "%s/%s", cdir, m.filename);
        ASSERT(rom_fetch_verify_file(final_path, &m));

        free(good_sha3);
        fs_server_stop();
        free(content);
        char p[1024];
        snprintf(p, sizeof(p), "%s/consensus-state-bundle-bc.sqlite", sdir);
        unlink(p);
        unlink(final_path);
        rmdir(sdir);
        rmdir(cdir);
        rom_seed_reset();
        rom_peer_scoring_test_reset();
        PASS();
    } _test_next:;
    return failures;
}

int test_rom_journal_resume(void)
{
    int failures = 0;
    failures += test_rom_journal_header_layout();
    failures += test_rom_journal_null_safe();
    failures += test_rom_peer_scoring_basic();
    failures += test_rom_peer_scoring_bounded();
    failures += test_rom_journal_kill9_resume();
    failures += test_rom_journal_header_mismatch_discard();
    failures += test_rom_journal_bad_chunk_then_recovery();
    return failures;
}
