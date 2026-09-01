/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: chaos faults (g)-(i) — the ROM-artifact half of the sync fault
 * matrix (conflicting chunk peers, journal-commit write failure, kill at the
 * resume boundary) together with the shared ROM fixture helpers they are
 * built on: content generation, artifact registration, the real file-service
 * seeder, and the hand-driven BAD peer that answers one chunk with wrong
 * bytes.
 *
 * Split out of simnet_chaos_faults.c along the file-size ceiling seam at the
 * "(g)-(l) sync/ROM-artifact fault matrix" boundary that file already
 * declared. See sim/simnet_chaos_faults.h for the per-fault contract; the
 * symbols that cross the seam live in simnet_chaos_faults_internal.h.
 */

#include "simnet_chaos_faults_internal.h"

#include "sim/simnet_chaos_faults.h"
#include "platform/file_sync.h"
#include "platform/directory_compat.h"
#include "platform/socket_compat.h"
#include "platform/temp_directory.h"

#include "test/test_helpers.h"

#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/pow.h"
#include "coins/coins_view.h"
#include "conditions/segment_corruption.h"
#include "consensus/validation.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "crypto/sha3.h"
#include "event/event.h"
#include "framework/condition.h"
#include "json/json.h"
#include "jobs/reducer_frontier.h"
#include "jobs/stage_rederive_range.h"
#include "jobs/stage_repair.h"
#include "jobs/stage_row_itag.h"
#include "jobs/tip_finalize_stage.h"
#include "jobs/utxo_apply_stage.h"
#include "net/download.h"
#include "net/file_service.h"
#include "net/rom_fetch.h"
#include "net/rom_journal.h"
#include "net/rom_peer_scoring.h"
#include "net/rom_seed.h"
#include "platform/time_compat.h"
#include "sim/simnet.h"
#include "sim/simnet_byzantine.h"
#include "storage/chain_segment.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "sync/sync_planner.h"
#include "sync/sync_reduce.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include "util/stage.h"
#include "util/supervisor.h"
#include "validation/chainstate.h"
#include "validation/connect_block.h"
#include "validation/main_state.h"
#include <fcntl.h>
#include <pthread.h>
#if !defined(_WIN32)
#include <signal.h>
#endif
#include <sqlite3.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/resource.h>
#endif
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#if defined(_WIN32)
#include <io.h>
#endif

/* pread()/pwrite() have no Win32 equivalent; the CRT offers only a seek +
 * read/write pair, so the seam saves and restores the file position around
 * each transfer. Only this translation unit's ROM-artifact faults do
 * positioned IO, so the shim lives here. */
#if defined(_WIN32)
static ssize_t chaos_positioned_io(int fd, void *data, size_t size,
                                   int64_t offset, bool write_data)
{
    __int64 saved = _lseeki64(fd, 0, SEEK_CUR);
    if (saved < 0 || offset < 0 || _lseeki64(fd, offset, SEEK_SET) < 0)
        return -1;
    size_t done = 0;
    while (done < size) {
        unsigned int part = size - done > UINT_MAX ? UINT_MAX :
                                                    (unsigned int)(size - done);
        int n = write_data ? _write(fd, (char *)data + done, part)
                           : _read(fd, (char *)data + done, part);
        if (n <= 0) { done = 0; break; }
        done += (size_t)n;
    }
    bool restored = _lseeki64(fd, saved, SEEK_SET) >= 0;
    return done == size && restored ? (ssize_t)done : -1;
}
#define chaos_pwrite(fd, data, size, offset) \
    chaos_positioned_io((fd), (void *)(data), (size), (offset), true)
#define chaos_pread(fd, data, size, offset) \
    chaos_positioned_io((fd), (data), (size), (offset), false)
#else
#define chaos_pwrite pwrite
#define chaos_pread pread
#endif

/* ══════════════════════════════════════════════════════════════════════
 * (g)-(l): the sync/ROM-artifact fault matrix (lane G3). See
 * sim/simnet_chaos_faults.h for the per-fault contract.
 * ══════════════════════════════════════════════════════════════════════ */

void sfm_capsule_init(struct sync_fault_capsule *out, uint64_t seed)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->base.hstar_before = -1;
    out->base.hstar_after = -1;
    out->seed = seed;
}
/* mirrors chaos_note() above, writing into the embedded base.note. */
void sfm_note(struct sync_fault_capsule *out, const char *fmt, ...)
{
    if (!out) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(out->base.note, sizeof(out->base.note), fmt, ap);
    va_end(ap);
}

/* ── shared ROM-artifact fixture helpers (mirror tests/harness/src/
 * test_rom_journal_resume.c's proven fixture idioms) ───────────────────── */

#define SFM_ARTIFACT_BYTES 8192u /* < ROM_SEED_CHUNK_SIZE: one short chunk,
                                  * real content, fast to build/transfer */

static void sfm_gen_content(uint8_t *buf, size_t size, uint64_t seed)
{
    static const uint8_t magic[16] = "SQLite format 3";
    for (size_t i = 0; i < size; i++)
        buf[i] = (uint8_t)((i * 131u + 7u + seed) & 0xffu);
    if (size >= 16)
        memcpy(buf, magic, 16);
}

static bool sfm_write_file(const char *dir, const char *name,
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

static uint16_t sfm_start_fs_server(const char *dir, const uint16_t *cand,
                                    size_t n)
{
    for (size_t i = 0; i < n; i++) {
        fs_server_start(dir, cand[i]);
        for (int w = 0; w < 40 && !fs_server_is_running(); w++)
            platform_sleep_ms(50); /* up to 2 s for bind+listen */
        if (fs_server_is_running())
            return cand[i];
        fs_server_stop();
    }
    return 0;
}

static void sfm_manifest_from_artifact(const struct rom_artifact *a,
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

static int64_t sfm_seed_chunks_served(void)
{
    struct json_value dj;
    json_init(&dj);
    (void)rom_seed_dump_state_json(&dj, NULL);
    int64_t n = json_get_int(json_get(&dj, "chunks_served"));
    json_free(&dj);
    return n;
}

/* ══════════════════════════════════════════════════════════════════════
 * (g) two peers, same chunk index, different bytes
 * ══════════════════════════════════════════════════════════════════════ */

/* fs_send_chunk_fast has external linkage (core/modules/net/src/file_service.c) but
 * is not exposed via net/file_service.h — it is the honest serve path's
 * internal wire-framing + MAC primitive. This forward declaration (not a
 * #include; the real symbol links fine in this one-binary build — same
 * rationale as block_index_loader_seed_tip_from_finalized above) lets this
 * fixture's hand-built "bad peer" thread reuse the REAL frame+MAC format
 * instead of reimplementing it, while feeding it deliberately wrong chunk
 * bytes. Signature verified against core/modules/net/src/file_service.c at the time
 * this file was written. */
bool fs_send_chunk_fast(struct fs_session *s, const uint8_t *data,
                        uint32_t size, const uint8_t sha3[32]);

/* The BAD peer: a minimal, hand-driven listener speaking just enough real
 * file-service wire protocol (fs_session_init/fs_handshake/fs_recv_frame/
 * fs_parse_rom_request/fs_send_chunk_fast — every one a real production
 * primitive) to answer ONE ROM chunk request with deliberately wrong bytes.
 * The transport MAC it sends is real and self-consistent — fs_send_chunk_fast
 * binds the MAC to whatever (data, sha3) it is given, and the honest server
 * does the exact same thing with its own real data, so the MAC alone can
 * never distinguish this from an honest reply. Only the CALLER's separate
 * content check (rom_fetch_verify_chunk against the manifest's committed
 * digest) catches it — which is exactly the property this fault proves. */
struct sfm_bad_peer {
    platform_socket_t listen_fd;
    uint16_t     port;
    pthread_t    thread;
    uint32_t     reply_bytes;
    uint8_t      fill;
    _Atomic bool got_request;
};

static void *sfm_bad_peer_loop(void *arg)
{
    struct sfm_bad_peer *bp = (struct sfm_bad_peer *)arg;
    size_t peer_size = 0;
    platform_socket_t fd = platform_socket_accept(bp->listen_fd, NULL,
                                                   &peer_size);
    if (fd == PLATFORM_SOCKET_INVALID)
        return NULL;

    struct fs_session s;
    fs_session_init(&s, fd);
    uint8_t zero_root[32];
    memset(zero_root, 0, sizeof(zero_root));
    if (!fs_handshake(&s, zero_root, false)) {
        platform_socket_close(fd);
        return NULL;
    }

    uint8_t type;
    const uint8_t *payload;
    uint32_t plen;
    if (fs_recv_frame(&s, &type, &payload, &plen) && type == FS_REQUEST) {
        uint8_t root[32];
        uint32_t idx = 0;
        if (fs_parse_rom_request(payload, plen, root, &idx)) {
            atomic_store(&bp->got_request, true);
            uint8_t *wrong = malloc(bp->reply_bytes); // raw-alloc-ok:test
            if (wrong) {
                for (uint32_t i = 0; i < bp->reply_bytes; i++)
                    wrong[i] = (uint8_t)(bp->fill ^ (uint8_t)(i * 61u + 13u));
                uint8_t wrong_sha3[32];
                sha3_256(wrong, bp->reply_bytes, wrong_sha3);
                (void)fs_send_chunk_fast(&s, wrong, bp->reply_bytes,
                                         wrong_sha3);
                free(wrong);
            }
        } else {
            (void)fs_send_frame(&s, FS_DONE, NULL, 0);
        }
    }
    platform_socket_close(fd);
    return NULL;
}

static bool sfm_bad_peer_start(struct sfm_bad_peer *bp, uint32_t reply_bytes,
                               uint64_t seed)
{
    memset(bp, 0, sizeof(*bp));
    bp->listen_fd = platform_socket_open(AF_INET, SOCK_STREAM, 0, true, false);
    if (bp->listen_fd == PLATFORM_SOCKET_INVALID)
        return false;
    (void)platform_socket_set_reuse_address(bp->listen_fd, true);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    if (platform_socket_parse_address(AF_INET, "127.0.0.1",
                                      &sa.sin_addr) != 1) {
        platform_socket_close(bp->listen_fd);
        return false;
    }
    sa.sin_port = 0; /* ephemeral — no fixed-port collision risk */
    if (platform_socket_bind(bp->listen_fd, (struct sockaddr *)&sa,
                             sizeof(sa)) != 0) {
        platform_socket_close(bp->listen_fd);
        return false;
    }
    size_t sl = sizeof(sa);
    if (platform_socket_local_address(bp->listen_fd,
                                      (struct sockaddr *)&sa, &sl) != 0) {
        platform_socket_close(bp->listen_fd);
        return false;
    }
    bp->port = ntohs(sa.sin_port);
    if (platform_socket_listen(bp->listen_fd, 1) != 0) {
        platform_socket_close(bp->listen_fd);
        return false;
    }
    bp->reply_bytes = reply_bytes;
    bp->fill = (uint8_t)(seed ^ 0xA5u);
    /* raw-pthread-ok: single accept()->reply->exit, joined immediately below */
    if (pthread_create(&bp->thread, NULL, sfm_bad_peer_loop, bp) != 0) {
        platform_socket_close(bp->listen_fd);
        return false;
    }
    return true;
}

/* shutdown()+close() BEFORE join(): if the client never connected (an early
 * error-path teardown), the thread is still blocked inside accept() on this
 * exact fd — closing it first is what unblocks that accept() call. Safe to
 * call unconditionally either way (mirrors test_header_probe.c's
 * hp_mock_stop ordering). */
static void sfm_bad_peer_join(struct sfm_bad_peer *bp)
{
    platform_socket_shutdown_both(bp->listen_fd);
    platform_socket_close(bp->listen_fd);
    pthread_join(bp->thread, NULL);
}

bool chaos_fault_conflicting_chunk_peers(uint64_t seed,
                                         struct sync_fault_capsule *out)
{
    sfm_capsule_init(out, seed);
    snprintf(out->fault_point, sizeof(out->fault_point),
             "chunk 0 fetched from two real peers under one committed digest");

    fs_server_stop();
    rom_seed_reset();
    rom_peer_scoring_test_reset();
    rom_seed_set_peer_bps_cap(1ull << 30);
    rom_seed_set_global_bps_cap(1ull << 30);

    char sroot[PLATFORM_TEMP_PATH_MAX], croot[PLATFORM_TEMP_PATH_MAX];
    bool made_s = platform_temp_directory_create("zcl_sfm_g_srv_", sroot,
                                                 sizeof(sroot));
    if (!made_s || !platform_temp_directory_create("zcl_sfm_g_cli_", croot,
                                                   sizeof(croot))) {
        if (made_s) rmdir(sroot);
        sfm_note(out, "temporary directory create failed");
        return false;
    }
    char *sdir = sroot, *cdir = croot;

    uint8_t content[SFM_ARTIFACT_BYTES];
    sfm_gen_content(content, sizeof(content), seed);
    bool wrote = sfm_write_file(sdir, "consensus-state-bundle-sfmg.sqlite",
                                content, sizeof(content));
    struct rom_artifact art;
    bool reg = wrote && rom_seed_register(
        sdir, "consensus-state-bundle-sfmg.sqlite", NULL, &art) == ROM_REG_OK;
    if (!reg || art.num_chunks != 1) {
        sfm_note(out, "fixture registration failed (wrote=%d reg=%d)",
                 wrote, reg);
        rmdir(sdir); rmdir(cdir);
        return false;
    }

    static const uint16_t good_ports[] = { 18941, 18945, 18949 };
    uint16_t good_port = sfm_start_fs_server(sdir, good_ports, 3);
    if (good_port == 0) {
        sfm_note(out, "good fs_server failed to bind");
        rmdir(sdir); rmdir(cdir);
        return false;
    }

    struct sfm_bad_peer bad;
    if (!sfm_bad_peer_start(&bad, (uint32_t)art.size_bytes, seed)) {
        sfm_note(out, "bad peer listener failed to start");
        fs_server_stop();
        rmdir(sdir); rmdir(cdir);
        return false;
    }

    char part_path[1300];
    snprintf(part_path, sizeof(part_path),
             "%s/consensus-state-bundle-sfmg.sqlite.part", cdir);
    char jrnl_path[1364];
    snprintf(jrnl_path, sizeof(jrnl_path), "%s.journal", part_path);
    int fd = open(part_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    struct rom_journal *j = fd >= 0
        ? rom_journal_open(jrnl_path, art.chunk_root, art.whole_sha3,
                           art.chunk_size, art.num_chunks)
        : NULL;

    /* GOOD fetch first: real bytes, verifies, durably journaled + on disk. */
    uint8_t *good_buf = malloc(art.chunk_size); // raw-alloc-ok:test
    uint32_t good_got = 0;
    bool good_ok = fd >= 0 && j && good_buf &&
        rom_fetch_chunk("127.0.0.1", good_port, art.chunk_root, 0, good_buf,
                        art.chunk_size, &good_got) &&
        rom_fetch_verify_chunk(good_buf, good_got, art.chunk_sha3[0]) &&
        chaos_pwrite(fd, good_buf, good_got, 0) == (ssize_t)good_got &&
        platform_data_sync(fd) == 0 && rom_journal_mark(j, 0);
    snprintf(out->state_before, sizeof(out->state_before),
             "good peer fetched+verified+journaled chunk 0 (%u bytes)",
             good_got);
    if (!good_ok) {
        sfm_note(out, "good-peer baseline fetch/verify/mark failed");
        if (j) rom_journal_close(j);
        if (fd >= 0) close(fd);
        free(good_buf);
        sfm_bad_peer_join(&bad);
        fs_server_stop();
        rmdir(sdir); rmdir(cdir);
        return false;
    }

    /* BAD fetch: same chunk_root/index, a DIFFERENT real peer, DIFFERENT
     * real bytes. Transport succeeds (self-consistent MAC); content verify
     * must fail against the SAME committed digest the good peer satisfied. */
    uint8_t *bad_buf = malloc(art.chunk_size); // raw-alloc-ok:test
    uint32_t bad_got = 0;
    bool transport_ok = bad_buf &&
        rom_fetch_chunk("127.0.0.1", bad.port, art.chunk_root, 0, bad_buf,
                        art.chunk_size, &bad_got);
    bool content_differs = transport_ok && bad_got == good_got &&
        memcmp(bad_buf, good_buf, good_got) != 0;
    bool content_rejected = transport_ok &&
        !rom_fetch_verify_chunk(bad_buf, bad_got, art.chunk_sha3[0]);
    bool named = content_rejected &&
        rom_peer_note_bad_chunk("127.0.0.1", bad.port, 0, "digest");
    bool deprioritized = named &&
        rom_peer_is_deprioritized("127.0.0.1", bad.port);

    /* The good chunk is KEPT: this fixture never pwrites/marks the bad
     * bytes (mirrors rf_ver_worker's real "verify BEFORE any durable write"
     * ordering), so both the journal bit AND the on-disk .part bytes for
     * chunk 0 must still read back exactly what the good peer served. */
    uint8_t reread[SFM_ARTIFACT_BYTES];
    bool part_kept = chaos_pread(fd, reread, good_got, 0) == (ssize_t)good_got &&
                     memcmp(reread, good_buf, good_got) == 0;
    bool journal_kept = rom_journal_is_done(j, 0) &&
                        rom_journal_count_done(j) == 1;

    snprintf(out->state_after, sizeof(out->state_after),
             "bad peer transport_ok=%d content_differs=%d rejected=%d "
             "named=%d deprioritized=%d good chunk kept(part=%d,journal=%d)",
             transport_ok, content_differs, content_rejected, named,
             deprioritized, part_kept, journal_kept);
    out->event_number = 2; /* fetch #1 = good peer, fetch #2 = bad peer */
    snprintf(out->phase, sizeof(out->phase), "content_verify");
    snprintf(out->replay_command, sizeof(out->replay_command),
             "chaos_fault_conflicting_chunk_peers(0x%016llx, &out)",
             (unsigned long long)seed);

    out->base.ok = true;
    out->base.recovered = transport_ok && content_differs && content_rejected &&
                          named && deprioritized && part_kept && journal_kept;
    out->base.operator_paged = false;
    sfm_note(out, "conflicting chunk peers: good=%u/%u bad=%u/%u differ=%d "
             "reject=%d named=%d deprio=%d part_kept=%d journal_kept=%d",
             good_got, art.chunk_size, bad_got, art.chunk_size,
             content_differs, content_rejected, named, deprioritized,
             part_kept, journal_kept);

    free(good_buf);
    free(bad_buf);
    rom_journal_close(j);
    close(fd);
    sfm_bad_peer_join(&bad);
    fs_server_stop();
    char p[1024];
    snprintf(p, sizeof(p), "%s/consensus-state-bundle-sfmg.sqlite", sdir);
    unlink(p);
    rmdir(sdir);
    unlink(jrnl_path);
    unlink(part_path);
    rmdir(cdir);
    rom_seed_reset();
    rom_peer_scoring_test_reset();
    return true;
}

/* ══════════════════════════════════════════════════════════════════════
 * (h) ENOSPC (write failure) during a journal bitmap commit
 * ══════════════════════════════════════════════════════════════════════ */

bool chaos_fault_journal_commit_enospc(uint64_t seed,
                                       struct sync_fault_capsule *out)
{
#if defined(_WIN32)
    sfm_capsule_init(out, seed);
    snprintf(out->fault_point, sizeof(out->fault_point),
             "journal ENOSPC injection unavailable on Windows");
    sfm_note(out, "refused: RLIMIT_FSIZE/SIGXFSZ fault injection has no "
                  "qualified Windows equivalent");
    return false;
#else
    sfm_capsule_init(out, seed);
    snprintf(out->fault_point, sizeof(out->fault_point),
             "rom_journal_mark()'s pwrite of the bitmap byte");

    char dir[256];
    platform_directory_create("./test-tmp", 0755);
    test_fmt_tmpdir(dir, sizeof(dir), "chaos_journal_enospc", "main");
    platform_directory_create(dir, 0755);
    char jrnl_path[512];
    snprintf(jrnl_path, sizeof(jrnl_path), "%s/journal", dir);

    uint8_t root[32], whole[32];
    memset(root, (uint8_t)(seed & 0xff), 32);
    memset(whole, (uint8_t)((seed >> 8) & 0xff), 32);
    const uint32_t num_chunks = 8; /* single-byte bitmap: every mark() below
                                    * touches the SAME on-disk byte offset, so
                                    * one rlimit boundary covers every index */
    struct rom_journal *j = rom_journal_open(jrnl_path, root, whole, 4096,
                                             num_chunks);
    if (!j) {
        sfm_note(out, "journal open failed");
        test_cleanup_tmpdir(dir);
        return false;
    }
    if (!rom_journal_mark(j, 0)) {
        sfm_note(out, "baseline mark(0) failed (harness defect)");
        rom_journal_close(j);
        test_cleanup_tmpdir(dir);
        return false;
    }
    snprintf(out->state_before, sizeof(out->state_before),
             "count_done=1 (chunk 0 durably marked)");

    /* The bitmap byte's real on-disk offset is RJ_BITMAP_OFFSET==88 (right
     * after the 88-byte header), single byte for num_chunks<=8 — set the
     * rlimit exactly one byte below the file's current size so a pwrite AT
     * that offset fails (EFBIG — see sim/simnet_chaos_faults.h (h) for why
     * this is the privilege-free substitute for a literal full filesystem
     * in a sandboxed worktree), while the already-durable header + bit 0
     * stay untouched. */
    struct stat st;
    if (stat(jrnl_path, &st) != 0 || st.st_size < 89) {
        sfm_note(out, "journal file layout unexpected (size=%lld)",
                 (long long)st.st_size);
        rom_journal_close(j);
        test_cleanup_tmpdir(dir);
        return false;
    }
    rlim_t limit = (rlim_t)(st.st_size - 1);

    struct rlimit orig;
    if (getrlimit(RLIMIT_FSIZE, &orig) != 0) {
        sfm_note(out, "getrlimit failed");
        rom_journal_close(j);
        test_cleanup_tmpdir(dir);
        return false;
    }
    struct sigaction old_sa, ign_sa;
    memset(&ign_sa, 0, sizeof(ign_sa));
    ign_sa.sa_handler = SIG_IGN; /* EFBIG return instead of process death */
    sigaction(SIGXFSZ, &ign_sa, &old_sa);
    struct rlimit tight = { .rlim_cur = limit, .rlim_max = orig.rlim_max };
    bool limited = setrlimit(RLIMIT_FSIZE, &tight) == 0;

    bool mark_failed = limited && !rom_journal_mark(j, 1);
    bool bit_rolled_back = mark_failed && !rom_journal_is_done(j, 1);
    bool count_unaffected = mark_failed && rom_journal_count_done(j) == 1;

    /* Restore: raising the soft limit back toward the original is always
     * permitted (never requires privilege). */
    setrlimit(RLIMIT_FSIZE, &orig);
    sigaction(SIGXFSZ, &old_sa, NULL);

    bool retry_ok = mark_failed && rom_journal_mark(j, 1);
    rom_journal_close(j);

    /* Reopen fresh from disk: the failed attempt left ZERO trace — a set bit
     * ALWAYS implies durable data, never a half-committed one. */
    struct rom_journal *j2 = rom_journal_open(jrnl_path, root, whole, 4096,
                                              num_chunks);
    bool reopen_agrees = j2 && rom_journal_is_done(j2, 0) &&
                        rom_journal_is_done(j2, 1) &&
                        rom_journal_count_done(j2) == 2;
    rom_journal_close(j2);

    snprintf(out->state_after, sizeof(out->state_after),
             "mark_failed=%d rolled_back=%d count_unaffected=%d retry_ok=%d "
             "reopen_agrees=%d", mark_failed, bit_rolled_back,
             count_unaffected, retry_ok, reopen_agrees);
    out->event_number = 2; /* mark(0) baseline, mark(1) is the injected fault */
    snprintf(out->phase, sizeof(out->phase), "journal_mark");
    snprintf(out->replay_command, sizeof(out->replay_command),
             "chaos_fault_journal_commit_enospc(0x%016llx, &out)",
             (unsigned long long)seed);

    out->base.ok = limited;
    out->base.recovered = mark_failed && bit_rolled_back && count_unaffected &&
                          retry_ok && reopen_agrees;
    out->base.operator_paged = false;
    sfm_note(out, "journal write-failure (ENOSPC substitute): "
             "mark_failed=%d rolled_back=%d retry_ok=%d reopen_agrees=%d",
             mark_failed, bit_rolled_back, retry_ok, reopen_agrees);

    test_cleanup_tmpdir(dir);
    return true;
#endif
}

/* ══════════════════════════════════════════════════════════════════════
 * (i) kill at the two resume boundaries rom_journal.h documents
 * ══════════════════════════════════════════════════════════════════════ */

bool chaos_fault_kill_resume_boundary(uint64_t seed, bool after_bitmap_commit,
                                      struct sync_fault_capsule *out)
{
    sfm_capsule_init(out, seed);
    snprintf(out->fault_point, sizeof(out->fault_point),
             after_bitmap_commit
                 ? "kill after every chunk's bitmap bit, before the rename"
                 : "kill after data fsync, before that chunk's bitmap bit");

    fs_server_stop();
    rom_seed_reset();
    rom_peer_scoring_test_reset();
    rom_seed_set_peer_bps_cap(1ull << 30);
    rom_seed_set_global_bps_cap(1ull << 30);

    char sroot[PLATFORM_TEMP_PATH_MAX], croot[PLATFORM_TEMP_PATH_MAX];
    bool made_s = platform_temp_directory_create("zcl_sfm_i_srv_", sroot,
                                                 sizeof(sroot));
    if (!made_s || !platform_temp_directory_create("zcl_sfm_i_cli_", croot,
                                                   sizeof(croot))) {
        if (made_s) rmdir(sroot);
        sfm_note(out, "temporary directory create failed");
        return false;
    }
    char *sdir = sroot, *cdir = croot;

    size_t size = (size_t)ROM_SEED_CHUNK_SIZE + 4096; /* 2 chunks */
    uint8_t *content = malloc(size); // raw-alloc-ok:test
    if (!content) {
        sfm_note(out, "content alloc failed");
        rmdir(sdir); rmdir(cdir);
        return false;
    }
    sfm_gen_content(content, size, seed);
    char fname[80];
    snprintf(fname, sizeof(fname), "consensus-state-bundle-sfmi%s.sqlite",
             after_bitmap_commit ? "b" : "a");
    bool wrote = sfm_write_file(sdir, fname, content, size);

    struct rom_artifact art;
    bool reg = wrote &&
        rom_seed_register(sdir, fname, NULL, &art) == ROM_REG_OK;
    if (!reg || art.num_chunks != 2) {
        sfm_note(out, "fixture registration failed");
        free(content); rmdir(sdir); rmdir(cdir);
        return false;
    }
    struct rom_fetch_manifest m;
    sfm_manifest_from_artifact(&art, &m);

    static const uint16_t ports[] = { 18951, 18955, 18959 };
    uint16_t port = sfm_start_fs_server(sdir, ports, 3);
    if (port == 0) {
        sfm_note(out, "fs_server failed to bind");
        free(content); rmdir(sdir); rmdir(cdir);
        return false;
    }

    char part_path[1300];
    snprintf(part_path, sizeof(part_path), "%s/%s%s", cdir, m.filename,
             ROM_FETCH_PART_SUFFIX);
    char jrnl_path[1364];
    snprintf(jrnl_path, sizeof(jrnl_path), "%s.journal", part_path);

    int fd = open(part_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    struct rom_journal *j = fd >= 0
        ? rom_journal_open(jrnl_path, m.chunk_root, m.whole_sha3,
                           m.chunk_size, m.num_chunks)
        : NULL;
    uint8_t *cbuf = malloc(ROM_SEED_CHUNK_SIZE); // raw-alloc-ok:test
    bool built = fd >= 0 && j && cbuf;
    /* Chunk 0: always fully durable + marked — established prior progress. */
    if (built) {
        uint32_t got = 0;
        built = rom_fetch_chunk("127.0.0.1", port, m.chunk_root, 0, cbuf,
                                ROM_SEED_CHUNK_SIZE, &got) &&
               rom_fetch_verify_chunk(cbuf, got, art.chunk_sha3[0]) &&
               chaos_pwrite(fd, cbuf, got, 0) == (ssize_t)got &&
               platform_data_sync(fd) == 0 && rom_journal_mark(j, 0);
    }
    /* Chunk 1 (the short tail): data written+fsynced either way — the fault
     * is whether the BITMAP BIT was committed before the simulated kill. */
    if (built) {
        uint32_t got = 0;
        built = rom_fetch_chunk("127.0.0.1", port, m.chunk_root, 1, cbuf,
                                ROM_SEED_CHUNK_SIZE, &got) &&
               rom_fetch_verify_chunk(cbuf, got, art.chunk_sha3[1]) &&
               chaos_pwrite(fd, cbuf, got, (off_t)m.chunk_size) == (ssize_t)got &&
               platform_data_sync(fd) == 0;
        if (built && after_bitmap_commit)
            built = rom_journal_mark(j, 1); /* commit past this boundary too */
        /* else: bytes are durable on disk; the mark is deliberately skipped
         * — the simulated kill lands exactly between fdatasync(.part) and
         * rom_journal_mark(), the "before bitmap commit" boundary. */
    }
    free(cbuf);
    if (!built) {
        sfm_note(out, "fixture boundary construction failed");
        if (j) rom_journal_close(j);
        if (fd >= 0) close(fd);
        fs_server_stop(); free(content); rmdir(sdir); rmdir(cdir);
        return false;
    }
    uint32_t done_before_kill = rom_journal_count_done(j);
    snprintf(out->state_before, sizeof(out->state_before),
             "journal count_done=%u/2, .part fully written on disk, final "
             "rename not yet performed", done_before_kill);
    close(fd);
    rom_journal_close(j); /* "process dies" here — no clean shutdown */
    /* The response completes before the server records it; await setup. */
    for (int i = 0; i < 40 && sfm_seed_chunks_served() < 2; i++)
        platform_sleep_ms(50);
    int64_t served_before = sfm_seed_chunks_served();
    /* "Restart": resume through the real driver. */
    bool resumed = rom_fetch_download_verified(
        "127.0.0.1", port, &m, art.chunk_sha3, m.num_chunks, cdir, NULL, NULL);
    int64_t served_after = sfm_seed_chunks_served();
    int64_t refetched = served_after - served_before;
    char final_path[1300];
    snprintf(final_path, sizeof(final_path), "%s/%s", cdir, m.filename);
    bool verifies = resumed && rom_fetch_verify_file(final_path, &m);
    struct stat jst;
    bool journal_cleaned = resumed && stat(jrnl_path, &jst) != 0;

    int64_t want_refetch = after_bitmap_commit ? 0 : 1;
    snprintf(out->state_after, sizeof(out->state_after),
             "resumed=%d refetched=%lld (want %lld, always <=1) verifies=%d "
             "journal_cleaned=%d", resumed, (long long)refetched,
             (long long)want_refetch, verifies, journal_cleaned);
    out->event_number = 3;
    snprintf(out->phase, sizeof(out->phase), "resume");
    snprintf(out->replay_command, sizeof(out->replay_command),
             "chaos_fault_kill_resume_boundary(0x%016llx, %s, &out)",
             (unsigned long long)seed, after_bitmap_commit ? "true" : "false");

    out->base.ok = true;
    out->base.recovered = served_before >= 2 && resumed &&
                          refetched == want_refetch && refetched <= 1 &&
                          verifies && journal_cleaned;
    out->base.operator_paged = false;
    sfm_note(out, "kill at resume boundary (%s): refetched=%lld verifies=%d "
             "journal_cleaned=%d",
             after_bitmap_commit ? "after bitmap, before rename"
                                  : "before bitmap, after data fsync",
             (long long)refetched, verifies, journal_cleaned);

    fs_server_stop();
    free(content);
    char p[1024];
    snprintf(p, sizeof(p), "%s/%s", sdir, fname);
    unlink(p);
    unlink(final_path);
    unlink(part_path);
    unlink(jrnl_path);
    rmdir(sdir);
    rmdir(cdir);
    rom_seed_reset();
    rom_peer_scoring_test_reset();
    return true;
}
