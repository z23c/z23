/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * rebuild_recent — read a LIVE zclassicd data directory and rebuild N
 * blocks (or the WHOLE chain) into z23's native event-log format
 * at high speed, using io_uring for the write path. Times the rebuild.
 *
 * Why this is live-safe: past blocks are immutable and physically present
 * in blk*.dat (mmap-readable while zclassicd runs). Only the blocks/index/
 * LevelDB is locked, so we snapshot-copy just the index and read bodies
 * from the live, immutable .dat files. zclassicd never stops.
 *
 * Why io_uring: the first cut proved the rebuild was *fsync-bound* — the
 * durable event_log appender fsync()s twice per event. For a bulk rebuild
 * we don't need per-event durability, so we emit the SAME canonical wire
 * format into large buffers, stream them to disk via io_uring (8 buffers
 * in flight, overlapping serialization with I/O), and fsync ONCE at the
 * end. The output is a byte-identical native event log: openable by
 * event_log_open and consumable by every projection.
 *
 * Usage:
 *   build/bin/rebuild_recent [datadir] [N|all] [out_path]
 *     datadir   default $HOME/.zclassic
 *     N         number of most-recent blocks, or "all"/"0" = whole chain
 *     out_path  default ./rebuild_recent.evlog (removed unless you pass one)
 */

#define _GNU_SOURCE 1

#include "platform/time_compat.h"
#include "storage/blocks_index_legacy_reader.h"
#include "storage/blocks_mmap_reader.h"
#include "storage/event_log.h"
#include "storage/event_log_payloads.h"
#include "storage/ldb_snapshot.h"
#include "util/safe_alloc.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "core/serialize.h"
#include "core/uint256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <liburing.h>
#include <sys/stat.h>
#include <omp.h>

struct legacy_bootstrap_height_map_result {
    struct legacy_block_loc *map;
    size_t map_count;
    int tip_height;
};

static bool legacy_bootstrap_load_height_map(
    const char *legacy_index_dir,
    const struct uint256 *tip_filter,
    const char *log_prefix,
    struct legacy_bootstrap_height_map_result *out)
{
    if (out)
        *out = (struct legacy_bootstrap_height_map_result){
            .map = NULL,
            .map_count = 0,
            .tip_height = -1,
        };
    if (!legacy_index_dir || !log_prefix || !out) {
        fprintf(stderr, "[%s] load height map: bad args\n", log_prefix);
        return false;
    }

    struct bilr *bilr = NULL;
    if (!bilr_open(legacy_index_dir, &bilr)) {
        fprintf(stderr, "[%s] cannot open block index %s\n", log_prefix, legacy_index_dir);
        return false;
    }

    struct legacy_block_loc *map = NULL;
    size_t map_count = 0;
    bool ok = tip_filter
        ? bilr_load_height_map_for_tip(bilr, tip_filter, &map, &map_count)
        : bilr_load_height_map(bilr, &map, &map_count);
    bilr_close(bilr);
    if (!ok) {
        fprintf(stderr, "[%s] bilr_load_height_map%s failed\n", log_prefix, tip_filter ? "_for_tip" : "");
        return false;
    }

    int legacy_tip = (int)map_count - 1;
    while (legacy_tip > 0 && map[(size_t)legacy_tip].height < 0)
        legacy_tip--;

    out->map = map;
    out->map_count = map_count;
    out->tip_height = legacy_tip;
    return true;
}

#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/io_uring.h>
#include <nmmintrin.h>   /* SSE4.2 hardware CRC-32C */
#include <omp.h>

/* Provided by main.c in the node; standalone tools define their own. */
volatile sig_atomic_t g_shutdown_requested = 0;

static int64_t now_ms(void)
{
    struct timespec ts;
    platform_time_monotonic_timespec(&ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ── crc32c (Castagnoli) — CRC-32C value identical to event_log.c ──────
 * Software table is the reference; the SSE4.2 hardware path (this CPU has
 * it) is ~10-20x faster and is verified to match the table at startup. */
static uint32_t g_crc_tab[256];
static void crc_init(void)
{
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) c = (c >> 1) ^ (0x82F63B78u & -(c & 1u));
        g_crc_tab[i] = c;
    }
}
static uint32_t crc32c_sw(const void *data, size_t len)
{
    const uint8_t *p = data;
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++)
        crc = (crc >> 8) ^ g_crc_tab[(crc ^ p[i]) & 0xFFu];
    return crc ^ 0xFFFFFFFFu;
}
/* Hardware CRC-32C via SSE4.2 (8 bytes/step). Same polynomial + reflection
 * + 0xFFFFFFFF init/final-xor as the table, so values are identical. */
static uint32_t crc32c(const void *data, size_t len)
{
    const uint8_t *p = data;
    uint32_t crc = 0xFFFFFFFFu;
    while (len >= 8) { uint64_t v; memcpy(&v, p, 8);
        crc = (uint32_t)_mm_crc32_u64(crc, v); p += 8; len -= 8; }
    while (len--) crc = _mm_crc32_u8(crc, *p++);
    return crc ^ 0xFFFFFFFFu;
}
/* Abort early if HW and SW disagree — guarantees byte-valid output. */
static void crc_selfcheck(void)
{
    uint8_t buf[1031];
    for (size_t i = 0; i < sizeof buf; i++) buf[i] = (uint8_t)(i * 31u + 7u);
    for (size_t n = 0; n <= sizeof buf; n += (n < 16 ? 1 : 97)) {
        if (crc32c(buf, n) != crc32c_sw(buf, n)) {
            fprintf(stderr, "rebuild_recent: HW crc32c mismatch at n=%zu — abort\n", n);
            exit(2);
        }
    }
}
static void put_u32_le(uint8_t *d, uint32_t v) { for (int i=0;i<4;i++) d[i]=(uint8_t)(v>>(8*i)); }
static void put_u64_le(uint8_t *d, uint64_t v) { for (int i=0;i<8;i++) d[i]=(uint8_t)(v>>(8*i)); }

/* ── raw io_uring bulk writer ──────────────────────────────────────────
 * Canonical event framing (matches event_log wire format):
 *   [16B header: len|type|flags=0|crc32c(payload)] [payload] [16B sentinel]
 * Buffers stream to disk via IORING_OP_WRITE; one fsync at finish. */

#define UW_NBUF 8
#define UW_CAP  (4u * 1024u * 1024u)   /* per-buffer staging; > max block */
#define UW_QD   16

static int io_uring_setup_(unsigned e, struct io_uring_params *p)
{ return (int)syscall(__NR_io_uring_setup, e, p); }
static int io_uring_enter_(int fd, unsigned ts, unsigned mc, unsigned fl)
{ return (int)syscall(__NR_io_uring_enter, fd, ts, mc, fl, NULL, 0); }

struct uw {
    int ring_fd, out_fd;
    /* SQ ring */
    uint32_t *sq_tail, *sq_mask, *sq_array;
    struct io_uring_sqe *sqes;
    /* CQ ring */
    uint32_t *cq_head, *cq_tail, *cq_mask;
    struct io_uring_cqe *cqes;
    void *sq_ptr, *cq_ptr; size_t sq_sz, cq_sz, sqe_sz;

    uint8_t *buf[UW_NBUF];
    uint32_t blen[UW_NBUF];     /* bytes queued in an in-flight buffer */
    uint64_t boff[UW_NBUF];     /* file offset of an in-flight buffer  */
    bool     inflight[UW_NBUF];

    int cur;                    /* buffer currently being filled */
    uint32_t cursor;            /* bytes filled in cur */
    uint64_t base_off;          /* absolute file offset of cur's start */
    uint64_t total;             /* total bytes written */
    uint64_t events;
    int short_writes;
};

static bool full_pwrite(int fd, const uint8_t *b, size_t n, uint64_t off)
{
    while (n) { ssize_t w = pwrite(fd, b, n, (off_t)off);
        if (w < 0) { if (errno==EINTR) continue; return false; }
        b += w; n -= (size_t)w; off += (uint64_t)w; }
    return true;
}

static void uw_reap(struct uw *u, bool block)
{
    if (block) (void)io_uring_enter_(u->ring_fd, 0, 1, IORING_ENTER_GETEVENTS);
    uint32_t head = __atomic_load_n(u->cq_head, __ATOMIC_ACQUIRE);
    uint32_t tail = __atomic_load_n(u->cq_tail, __ATOMIC_ACQUIRE);
    while (head != tail) {
        struct io_uring_cqe *c = &u->cqes[head & *u->cq_mask];
        int idx = (int)c->user_data;
        if (c->res < 0) {
            fprintf(stderr, "rebuild_recent: uring write err idx=%d res=%d\n", idx, c->res);
        } else if ((uint32_t)c->res != u->blen[idx]) {
            /* short write — finish the remainder synchronously */
            uint32_t done = (uint32_t)c->res;
            full_pwrite(u->out_fd, u->buf[idx] + done, u->blen[idx] - done, u->boff[idx] + done);
            u->short_writes++;
        }
        u->inflight[idx] = false;
        head++;
    }
    __atomic_store_n(u->cq_head, head, __ATOMIC_RELEASE);
}

static int uw_get_free(struct uw *u)
{
    for (;;) {
        uw_reap(u, false);
        for (int i = 0; i < UW_NBUF; i++) if (!u->inflight[i]) return i;
        uw_reap(u, true);   /* all busy: block for at least one completion */
    }
}

static bool uw_submit(struct uw *u, int idx, uint32_t len, uint64_t off)
{
    uint32_t tail = *u->sq_tail;
    uint32_t i = tail & *u->sq_mask;
    struct io_uring_sqe *s = &u->sqes[i];
    memset(s, 0, sizeof *s);
    s->opcode = IORING_OP_WRITE;
    s->fd = u->out_fd;
    s->addr = (uint64_t)(uintptr_t)u->buf[idx];
    s->len = len;
    s->off = off;
    s->user_data = (uint64_t)idx;
    u->sq_array[i] = i;
    u->blen[idx] = len; u->boff[idx] = off; u->inflight[idx] = true;
    __atomic_store_n(u->sq_tail, tail + 1, __ATOMIC_RELEASE);
    int r = io_uring_enter_(u->ring_fd, 1, 0, 0);
    if (r < 0) { fprintf(stderr, "rebuild_recent: io_uring_enter: %s\n", strerror(errno)); return false; }
    return true;
}

/* flush the current buffer (if non-empty) and grab a fresh one */
static bool uw_flush(struct uw *u)
{
    if (u->cursor == 0) return true;
    if (!uw_submit(u, u->cur, u->cursor, u->base_off)) return false;
    u->base_off += u->cursor;
    u->total    += u->cursor;
    u->cur = uw_get_free(u);
    u->cursor = 0;
    return true;
}

/* append one framed event; copies payload into the staging buffer */
static bool uw_append(struct uw *u, uint32_t type, const void *payload, uint32_t plen)
{
    uint32_t evsize = 16u + plen + 16u;
    if (evsize > UW_CAP) { fprintf(stderr, "rebuild_recent: event too big (%u)\n", evsize); return false; }
    if (u->cursor + evsize > UW_CAP && !uw_flush(u)) return false;

    uint8_t *p = u->buf[u->cur] + u->cursor;
    uint64_t ev_start = u->base_off + u->cursor;
    put_u32_le(p + 0, plen);
    put_u32_le(p + 4, type);
    put_u32_le(p + 8, 0u);
    put_u32_le(p + 12, crc32c(payload, plen));
    if (plen) memcpy(p + 16, payload, plen);
    put_u64_le(p + 16 + plen, EVENT_LOG_SENTINEL_MAGIC);
    put_u64_le(p + 16 + plen + 8, ev_start);
    u->cursor += evsize;
    u->events++;
    return true;
}

static bool uw_setup(struct uw *u, const char *out_path)
{
    memset(u, 0, sizeof *u);
    u->out_fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (u->out_fd < 0) { perror("open(out)"); return false; }

    struct io_uring_params p; memset(&p, 0, sizeof p);
    u->ring_fd = io_uring_setup_(UW_QD, &p);
    if (u->ring_fd < 0) { perror("io_uring_setup"); return false; }

    u->sq_sz = p.sq_off.array + p.sq_entries * sizeof(uint32_t);
    u->cq_sz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
    u->sqe_sz = p.sq_entries * sizeof(struct io_uring_sqe);

    if (p.features & IORING_FEAT_SINGLE_MMAP) {
        size_t sz = u->sq_sz > u->cq_sz ? u->sq_sz : u->cq_sz;
        u->sq_sz = u->cq_sz = sz;
    }
    u->sq_ptr = mmap(0, u->sq_sz, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE, u->ring_fd, IORING_OFF_SQ_RING);
    if (u->sq_ptr == MAP_FAILED) { perror("mmap sq"); return false; }
    u->cq_ptr = (p.features & IORING_FEAT_SINGLE_MMAP) ? u->sq_ptr
              : mmap(0, u->cq_sz, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE, u->ring_fd, IORING_OFF_CQ_RING);
    if (u->cq_ptr == MAP_FAILED) { perror("mmap cq"); return false; }
    u->sqes = mmap(0, u->sqe_sz, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE, u->ring_fd, IORING_OFF_SQES);
    if (u->sqes == MAP_FAILED) { perror("mmap sqes"); return false; }

    u->sq_tail  = (uint32_t*)((char*)u->sq_ptr + p.sq_off.tail);
    u->sq_mask  = (uint32_t*)((char*)u->sq_ptr + p.sq_off.ring_mask);
    u->sq_array = (uint32_t*)((char*)u->sq_ptr + p.sq_off.array);
    u->cq_head  = (uint32_t*)((char*)u->cq_ptr + p.cq_off.head);
    u->cq_tail  = (uint32_t*)((char*)u->cq_ptr + p.cq_off.tail);
    u->cq_mask  = (uint32_t*)((char*)u->cq_ptr + p.cq_off.ring_mask);
    u->cqes     = (struct io_uring_cqe*)((char*)u->cq_ptr + p.cq_off.cqes);

    for (int i = 0; i < UW_NBUF; i++) {
        if (posix_memalign((void**)&u->buf[i], 4096, UW_CAP) != 0) { perror("posix_memalign"); return false; }
        u->inflight[i] = false;
    }
    u->cur = 0; u->cursor = 0; u->base_off = 0;
    return true;
}

/* submit last partial buffer, drain everything, single fsync */
static bool uw_finish(struct uw *u)
{
    if (!uw_flush(u)) return false;
    for (int i = 0; i < UW_NBUF; i++) {
        while (u->inflight[i]) uw_reap(u, true);
    }
    if (fsync(u->out_fd) < 0) { perror("fsync(out)"); return false; }
    return true;
}

static void uw_close(struct uw *u)
{
    for (int i = 0; i < UW_NBUF; i++) free(u->buf[i]);
    if (u->sqes && u->sqes != MAP_FAILED) munmap(u->sqes, u->sqe_sz);
    if (u->cq_ptr && u->cq_ptr != u->sq_ptr && u->cq_ptr != MAP_FAILED) munmap(u->cq_ptr, u->cq_sz);
    if (u->sq_ptr && u->sq_ptr != MAP_FAILED) munmap(u->sq_ptr, u->sq_sz);
    if (u->ring_fd > 0) close(u->ring_fd);
    if (u->out_fd > 0) close(u->out_fd);
}

/* ── live snapshot of the (locked) index dir ───────────────────────────── */
static bool snapshot_index_dir(const char *src, char *out, size_t out_cap)
{
    char tmpl[] = "/tmp/zcl_idx_XXXXXX";
    char *dst = mkdtemp(tmpl);
    if (!dst) { perror("mkdtemp"); return false; }
    int n = snprintf(out, out_cap, "%s", dst);
    if (n <= 0 || (size_t)n >= out_cap) {
        fprintf(stderr, "rebuild_recent: snapshot path too long\n");
        ldb_snapshot_destroy(dst);
        return false;
    }
    char err[128] = {0};
    if (!ldb_snapshot_make(src, out, err, sizeof(err))) {
        fprintf(stderr, "rebuild_recent: snapshot copy failed: %s\n", err);
        ldb_snapshot_destroy(out);
        return false;
    }
    return true;
}

/* Frame one block's events into writer `u`. Counts accumulate into the
 * caller's (thread-local) counters — no shared state. Returns false on
 * read/parse/write error. */
static bool frame_block(struct uw *u, const struct legacy_block_loc *loc,
                        struct blocks_mmap *bmr,
                        uint64_t *ntx, uint64_t *nadd, uint64_t *nspend)
{
    uint8_t hdr_buf[EV_BLOCK_HEADER_FIXED_BYTES + EV_BLOCK_HEADER_MAX_SOLUTION];
    uint8_t add_buf[EV_UTXO_ADD_HDR_WIRE_LEN + MAX_SCRIPT_SIZE];
    uint8_t spend_buf[EV_UTXO_SPEND_WIRE_LEN];

    size_t plen = 0;
    const uint8_t *payload = bmr_get_payload(bmr, loc->nFile, loc->nDataPos, &plen);
    if (!payload || !plen) return false;
    struct byte_stream s; stream_init_from_data(&s, payload, plen);
    struct block blk; block_init(&blk);
    bool dok = block_deserialize(&blk, &s); stream_free(&s);
    if (!dok) { block_free(&blk); return false; }

    struct uint256 bhash; block_get_hash(&blk, &bhash);
    struct ev_block_header eh; memset(&eh, 0, sizeof eh);
    memcpy(eh.hash, bhash.data, 32);
    memcpy(eh.hashPrev, blk.header.hashPrevBlock.data, 32);
    eh.height=loc->height; eh.nStatus=loc->nStatus; eh.nFile=loc->nFile;
    eh.nDataPos=loc->nDataPos; eh.nUndoPos=loc->nUndoPos;
    eh.nTime=blk.header.nTime; eh.nBits=blk.header.nBits;
    memcpy(eh.nNonce, blk.header.nNonce.data, 32);
    memcpy(eh.hashMerkleRoot, blk.header.hashMerkleRoot.data, 32);
    memcpy(eh.hashFinalSaplingRoot, blk.header.hashFinalSaplingRoot.data, 32);
    eh.nVersion=blk.header.nVersion; eh.nTx=(uint32_t)blk.num_vtx;
    eh.nSolutionSize=(uint16_t)blk.header.nSolutionSize;
    size_t hw = 0;
    bool ok = ev_block_header_serialize(&eh, blk.header.nSolution, hdr_buf, sizeof hdr_buf, &hw)
           && uw_append(u, EV_BLOCK_HEADER, hdr_buf, (uint32_t)hw)
           && uw_append(u, EV_BLOCK_BODY, payload, (uint32_t)plen);

    for (size_t ti = 0; ti < blk.num_vtx && ok; ti++) {
        struct transaction *tx = &blk.vtx[ti];
        transaction_compute_hash(tx);
        bool cb = transaction_is_coinbase(tx);
        for (size_t vo = 0; vo < tx->num_vout && ok; vo++) {
            const struct tx_out *o = &tx->vout[vo];
            struct ev_utxo_add_hdr ah; memset(&ah, 0, sizeof ah);
            memcpy(ah.txid, tx->hash.data, 32);
            ah.vout=(uint32_t)vo; ah.value=o->value; ah.height=(uint32_t)loc->height;
            ah.is_coinbase=cb?1u:0u; ah.script_len=(uint32_t)o->script_pub_key.size;
            size_t aw=0;
            ok = ev_utxo_add_serialize(&ah, o->script_pub_key.data, add_buf, sizeof add_buf, &aw)
              && uw_append(u, EV_UTXO_ADD, add_buf, (uint32_t)aw);
            (*nadd)++;
        }
        if (!cb) for (size_t vi = 0; vi < tx->num_vin && ok; vi++) {
            struct ev_utxo_spend sp; memcpy(sp.txid, tx->vin[vi].prevout.hash.data, 32);
            sp.vout = tx->vin[vi].prevout.n;
            ok = ev_utxo_spend_serialize(&sp, spend_buf)
              && uw_append(u, EV_UTXO_SPEND, spend_buf, EV_UTXO_SPEND_WIRE_LEN);
            (*nspend)++;
        }
        (*ntx)++;
    }
    block_free(&blk);
    return ok;
}

struct shard_res { uint64_t blocks, tx, add, spend, bytes; int short_writes; bool ok; };

/* Rebuild heights [lo,hi] into a standalone event-log segment at `path`.
 * Self-contained: own block-file mmap + own io_uring writer. */
static void run_range(const struct legacy_block_loc *map, int64_t lo, int64_t hi,
                      const char *blocks_dir, const char *path, struct shard_res *r)
{
    memset(r, 0, sizeof *r); r->ok = true;
    struct blocks_mmap *bmr = NULL;
    if (!bmr_open(blocks_dir, &bmr)) { r->ok = false; return; }
    struct uw u;
    if (!uw_setup(&u, path)) { r->ok = false; bmr_close(bmr); return; }
    for (int64_t h = lo; h <= hi && r->ok; h++) {
        if (map[h].height < 0) continue;
        if (!frame_block(&u, &map[h], bmr, &r->tx, &r->add, &r->spend)) {
            fprintf(stderr, "rebuild_recent: h=%lld failed\n", (long long)h); r->ok = false; break;
        }
        r->blocks++;
    }
    if (r->ok && !uw_finish(&u)) r->ok = false;
    r->bytes = u.total; r->short_writes = u.short_writes;
    uw_close(&u); bmr_close(bmr);
}

int main(int argc, char **argv)
{
    crc_init();
    crc_selfcheck();
    const char *home = getenv("HOME");
    char default_dd[2048];
    snprintf(default_dd, sizeof default_dd, "%s/.zclassic", home ? home : ".");
    const char *datadir = (argc > 1) ? argv[1] : default_dd;

    bool whole = false;
    int N = 10;
    if (argc > 2) {
        if (!strcmp(argv[2], "all") || !strcmp(argv[2], "0")) whole = true;
        else { N = atoi(argv[2]); if (N <= 0) N = 10; }
    }
    const char *out_path = (argc > 3) ? argv[3] : "rebuild_recent.evlog";
    bool out_is_temp = (argc <= 3);

    char idx_src[2200], blocks_dir[2200];
    snprintf(idx_src, sizeof idx_src, "%s/blocks/index", datadir);
    snprintf(blocks_dir, sizeof blocks_dir, "%s/blocks", datadir);
    int nthreads = omp_get_max_threads();
    printf("rebuild_recent: datadir=%s mode=%s threads=%d out=%s\n",
           datadir, whole ? "WHOLE-CHAIN" : "last-N", nthreads, out_path);

    int64_t t0 = now_ms();
    char idx_snap[2200];
    if (!snapshot_index_dir(idx_src, idx_snap, sizeof(idx_snap))) return 1;
    int64_t t_snap = now_ms() - t0;

    int64_t t1 = now_ms();
    struct legacy_bootstrap_height_map_result hmap;
    if (!legacy_bootstrap_load_height_map(idx_snap, NULL,
                                          "rebuild_recent", &hmap) ||
        hmap.map_count == 0) {
        fprintf(stderr, "load_height_map failed\n");
        bilr_free_height_map(hmap.map);
        ldb_snapshot_destroy(idx_snap);
        return 1;
    }
    struct legacy_block_loc *map = hmap.map;
    int64_t tip = hmap.tip_height;
    if (tip < 0) {
        fprintf(stderr, "empty index\n");
        bilr_free_height_map(map);
        ldb_snapshot_destroy(idx_snap);
        return 1;
    }
    int64_t lo = whole ? 0 : (tip - N + 1 < 0 ? 0 : tip - N + 1);
    int64_t t_load = now_ms() - t1;

    /* ── Rebuild ─────────────────────────────────────────────────────
     * Whole-chain: split [lo,tip] into NT contiguous segments, each rebuilt
     * by an independent thread — own block-file mmap, own io_uring writer,
     * own segment file out_path.<k>. No shared writer, no ordered gate; each
     * segment is a standalone valid event log. last-N: single file. */
    /* More segments than threads + dynamic scheduling balances the very
     * uneven historical block density (some height ranges are far heavier). */
    int NT = whole ? nthreads * 2 : 1;
    struct shard_res *res = zcl_calloc((size_t)NT, sizeof *res,
                                       "rebuild_recent shard results");
    if (!res) {
        bilr_free_height_map(map);
        ldb_snapshot_destroy(idx_snap);
        return 1;
    }
    int64_t span = (tip - lo + 1 + NT - 1) / NT;
    bool ok = true;

    int64_t t2 = now_ms();
    if (NT == 1) {
        run_range(map, lo, tip, blocks_dir, out_path, &res[0]);
    } else {
        #pragma omp parallel for schedule(dynamic) num_threads(nthreads)
        for (int s = 0; s < NT; s++) {
            int64_t mlo = lo + (int64_t)s * span;
            int64_t mhi = mlo + span - 1; if (mhi > tip) mhi = tip;
            if (mlo > tip) { res[s].ok = true; continue; }
            char sp[2300]; snprintf(sp, sizeof sp, "%s.%d", out_path, s);
            run_range(map, mlo, mhi, blocks_dir, sp, &res[s]);
        }
    }
    int64_t t_rebuild = now_ms() - t2;

    uint64_t n_blocks=0,n_tx=0,n_add=0,n_spend=0,bytes=0; int short_writes=0;
    for (int k=0;k<NT;k++){ ok = ok && res[k].ok;
        n_blocks+=res[k].blocks; n_tx+=res[k].tx; n_add+=res[k].add;
        n_spend+=res[k].spend; bytes+=res[k].bytes; short_writes+=res[k].short_writes; }
    uint64_t events = 2*n_blocks + n_add + n_spend;

    double secs = (double)t_rebuild / 1000.0;
    printf("\n=== rebuild_recent (parallel io_uring): %s ===\n", ok ? "OK" : "ABORTED");
    printf("  threads / segments    : %d / %d\n", nthreads, NT);
    printf("  source tip            : %lld\n", (long long)tip);
    printf("  blocks rebuilt        : %llu (heights %lld..%lld)\n",
           (unsigned long long)n_blocks, (long long)lo, (long long)tip);
    printf("  transactions          : %llu\n", (unsigned long long)n_tx);
    printf("  UTXO adds / spends    : %llu / %llu\n",
           (unsigned long long)n_add, (unsigned long long)n_spend);
    printf("  events written        : %llu  (short_writes=%d)\n",
           (unsigned long long)events, short_writes);
    printf("  native bytes written  : %llu (%.2f GB)\n",
           (unsigned long long)bytes, (double)bytes / 1e9);
    printf("\n  setup  : snapshot=%lld ms   index-load=%lld ms\n",
           (long long)t_snap, (long long)t_load);
    printf("  REBUILD: %.2f s  (%.0f blk/s, %.0f tx/s, %.0f MB/s, %.2f GB/s)\n",
           secs,
           secs>0 ? (double)n_blocks/secs : 0.0,
           secs>0 ? (double)n_tx/secs : 0.0,
           secs>0 ? (double)bytes/1e6/secs : 0.0,
           secs>0 ? (double)bytes/1e9/secs : 0.0);

    if (out_is_temp && NT > 1)
        for (int k=0;k<NT;k++){ char sp[2300]; snprintf(sp,sizeof sp,"%s.%d",out_path,k); unlink(sp); }
    free(res);
    bilr_free_height_map(map);
    ldb_snapshot_destroy(idx_snap);
    if (out_is_temp) unlink(out_path);
    return ok ? 0 : 1;
}
