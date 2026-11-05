/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Exercise the peer-reachable parameter-file wire decoders (the six
 * zparam* commands and the eight beta6 bootstrap commands) under sanitizers
 * and hold each bounded read to an independent oracle of its range rules.
 *
 * The first byte picks a decoder. Local fixtures only: a private /tmp tree
 * holds sparse files at the sizes the code compares against, nothing touches
 * a datadir, a socket or a thread. Replies land on a synthetic peer's send
 * queue, which is drained after every input. */

#include "chain/chainparams.h"
#include "core/serialize.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/netaddr.h"
#include "net/protocol.h"
#include "net/version.h"
#include "sapling/params_fetch.h"
#include "services/beta6_bootstrap.h"
#include "util/sync.h"

#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

volatile sig_atomic_t g_shutdown_requested = 0;

#define FUZZ_PW_MAX_INPUT 8192u
#define FUZZ_PW_ARMS 22u
#define FUZZ_PW_GUARD 64u
#define FUZZ_PW_ALLOC_CAP (2u * BETA6_BS_CHUNK_SIZE)
#define FUZZ_PW_BODY_FILL 0x5A
#define FUZZ_PW_GUARD_FILL 0xA5
#define FUZZ_PW_CMDS 14u
#define FUZZ_PW_SPARSE_SIZE ((uint64_t)(3u * BETA6_BS_CHUNK_SIZE + 5u))
#define FUZZ_PW_OUT_SIZE 3592860ULL
#define FUZZ_PW_VKEY_SIZE 1449ULL

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* ── fixture ─────────────────────────────────────────────────────────── */

struct fx_file {
    uint64_t size;
    int64_t mtime;
};

static bool g_ready;
static char g_base[64];
static char g_rf_dir[128];
static char g_params_dir[128];
static char g_src_dir[128];
static struct fx_file g_rf;
static struct fx_file g_params[2];
static struct chain_params g_chain;
static struct msg_processor g_mp;
static struct p2p_node g_node;
static const struct msg_dispatch_entry *g_rows[FUZZ_PW_CMDS];

static const char *const k_commands[FUZZ_PW_CMDS] = {
    "zparaminfo", "zparamhave", "zparammreq", "zparamman", "zparamcreq",
    "zparamdata", "getbsman",   "bsman",      "getbschk",  "bschk",
    "getbspman",  "bspman",     "getbspchk",  "bspchk",
};

/* The byte the fixture holds at `pos` of a file of `size` bytes: a marker at
 * every chunk boundary and at the last byte, zero elsewhere (sparse). */
static uint8_t expected_byte(uint64_t size, uint64_t pos)
{
    if (size > 0 && pos == size - 1)
        return 0xEE;
    if (pos % BETA6_BS_CHUNK_SIZE == 0 && pos < size)
        return (uint8_t)(0x40u + (uint8_t)(pos / BETA6_BS_CHUNK_SIZE));
    return 0;
}

static bool write_marked(const char *path, uint64_t size, struct fx_file *out)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    bool ok = true;
    for (uint64_t pos = 0; ok && pos < size; pos += BETA6_BS_CHUNK_SIZE)
        ok = fseeko(f, (off_t)pos, SEEK_SET) == 0 &&
             fputc(expected_byte(size, pos), f) != EOF;
    ok = ok && fseeko(f, (off_t)(size - 1), SEEK_SET) == 0 &&
         fputc(expected_byte(size, size - 1), f) != EOF;
    ok = (fclose(f) == 0) && ok;
    struct stat st;
    if (!ok || stat(path, &st) != 0)
        return false;
    if (out) {
        out->size = size;
        out->mtime = (int64_t)st.st_mtime;
    }
    return true;
}

static bool write_in(const char *dir, const char *name, uint64_t size,
                     struct fx_file *out)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    return write_marked(path, size, out);
}

static bool make_dir(const char *parent, const char *name, char *out, size_t cap)
{
    snprintf(out, cap, "%s/%s", parent, name);
    return mkdir(out, 0700) == 0;
}

static bool build_snapshot_tree(void)
{
    char blocks[160];
    char index[200];
    char chain[160];
    char sidecar[160];
    if (!make_dir(g_base, "src", g_src_dir, sizeof(g_src_dir)) ||
        !make_dir(g_src_dir, "blocks", blocks, sizeof(blocks)) ||
        !make_dir(blocks, "index", index, sizeof(index)) ||
        !make_dir(g_src_dir, "chainstate", chain, sizeof(chain)))
        return false;
    if (!write_in(blocks, "blk00000.dat", FUZZ_PW_SPARSE_SIZE, NULL) ||
        !write_in(index, "000005.ldb", 10, NULL) ||
        !write_in(chain, "000007.ldb", 20, NULL))
        return false;
    snprintf(sidecar, sizeof(sidecar), "%s.anchor", g_src_dir);
    FILE *f = fopen(sidecar, "w");
    if (!f)
        return false;
    fprintf(f, "3126937 00000663e40f1fe0bc32a7e7282fac25de5fe8ecefd9c627e2fd948d388f7053\n");
    return fclose(f) == 0;
}

/* Every entry of the fixture, children before parents. */
static const char *const k_fixture_entries[] = {
    "rf/f.bin", "rf/link.bin", "rf", "params/sapling-output.params",
    "params/sprout-verifying.key", "params", "src/blocks/blk00000.dat",
    "src/blocks/index/000005.ldb", "src/blocks/index", "src/blocks",
    "src/chainstate/000007.ldb", "src/chainstate", "src", "src.anchor",
};

static void cleanup_fixture(void)
{
    char path[256];
    if (g_base[0] == '\0')
        return;
    for (size_t i = 0; i < sizeof(k_fixture_entries) / sizeof(k_fixture_entries[0]); i++) {
        snprintf(path, sizeof(path), "%s/%s", g_base, k_fixture_entries[i]);
        (void)remove(path);
    }
    (void)remove(g_base);
}

static bool build_fixture(void)
{
    snprintf(g_base, sizeof(g_base), "/tmp/zcl_fuzz_param_wires_XXXXXX");
    if (!mkdtemp(g_base))
        return false;
    atexit(cleanup_fixture);
    if (!make_dir(g_base, "rf", g_rf_dir, sizeof(g_rf_dir)) ||
        !make_dir(g_base, "params", g_params_dir, sizeof(g_params_dir)))
        return false;
    char link_path[256];
    snprintf(link_path, sizeof(link_path), "%s/link.bin", g_rf_dir);
    if (!write_in(g_rf_dir, "f.bin", FUZZ_PW_SPARSE_SIZE, &g_rf) ||
        symlink("f.bin", link_path) != 0)
        return false;
    if (!write_in(g_params_dir, "sapling-output.params", FUZZ_PW_OUT_SIZE,
                  &g_params[0]) ||
        !write_in(g_params_dir, "sprout-verifying.key", FUZZ_PW_VKEY_SIZE,
                  &g_params[1]))
        return false;
    return build_snapshot_tree();
}

static bool seam_armed(void)
{
    return beta6_bs_inband_status().ok;
}

static bool seam_message(struct msg_processor *mp, struct p2p_node *node,
                         const char *command, const unsigned char *payload,
                         size_t payload_len)
{
    return beta6_bs_inband_serve(mp, node, command, payload, payload_len).ok;
}

static void init_peer(void)
{
    static const unsigned char magic[4] = { 0x24, 0xe9, 0x27, 0x64 };
    memcpy(g_chain.pchMessageStart, magic, sizeof(magic));
    g_mp.params = &g_chain;
    msg_processor_set_beta6_bootstrap(&g_mp, seam_armed, seam_message);
    g_node.socket = ZCL_INVALID_SOCKET;
    g_node.version = PROTOCOL_VERSION;
    zcl_mutex_init(&g_node.cs_send);
    net_address_init(&g_node.addr);
    g_node.addr.svc.addr.ip[10] = 0xff;
    g_node.addr.svc.addr.ip[11] = 0xff;
    g_node.addr.svc.addr.ip[12] = 127;
    g_node.addr.svc.addr.ip[15] = 1;
    g_node.addr.svc.port = 38033;
}

static void find_rows(void)
{
    for (size_t i = 0; i < FUZZ_PW_CMDS; i++) {
        for (const struct msg_dispatch_entry *e = msg_get_dispatch_table(); e->handler;
             e++)
            if (strcmp(e->command, k_commands[i]) == 0)
                g_rows[i] = e;
        if (!g_rows[i])
            abort();
    }
}

static void fuzz_init(void)
{
    if (g_ready)
        return;
    if (!build_fixture())
        abort();
    if (!beta6_bs_arm(g_src_dir, "main").ok)
        abort();
    if (!beta6_bs_inband_arm("main", g_params_dir).ok)
        abort();
    init_peer();
    find_rows();
    g_ready = true;
}

/* ── input cursor ────────────────────────────────────────────────────── */

struct cursor {
    const uint8_t *p;
    size_t n;
};

static uint64_t take_le(struct cursor *c, unsigned bytes)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < bytes; i++) {
        if (c->n > 0) {
            v |= (uint64_t)c->p[0] << (8u * i);
            c->p++;
            c->n--;
        }
    }
    return v;
}

/* ── buffers with guard bands ────────────────────────────────────────── */

struct guarded {
    uint8_t *raw;
    uint8_t *body;
    size_t cap;
};

static void guarded_open(struct guarded *g, size_t cap)
{
    g->raw = malloc(cap + 2u * FUZZ_PW_GUARD);
    if (!g->raw)
        abort();
    g->cap = cap;
    g->body = g->raw + FUZZ_PW_GUARD;
    memset(g->raw, FUZZ_PW_GUARD_FILL, FUZZ_PW_GUARD);
    memset(g->body, FUZZ_PW_BODY_FILL, cap);
    memset(g->body + cap, FUZZ_PW_GUARD_FILL, FUZZ_PW_GUARD);
}

static void require_guards(const struct guarded *g)
{
    for (size_t i = 0; i < FUZZ_PW_GUARD; i++)
        if (g->raw[i] != FUZZ_PW_GUARD_FILL ||
            g->body[g->cap + i] != FUZZ_PW_GUARD_FILL)
            abort();
}

/* After an ok read: exactly `length` bytes written, every one matching the
 * fixture, the rest of the buffer untouched. */
static void require_chunk(const struct guarded *g, uint64_t size, uint64_t offset,
                          uint32_t length)
{
    /* The fixture is zero except at the marked positions, so: every byte of
     * the range that is not a marker is zero (counted, not walked with a
     * modulo), and each marker inside the range holds its value. */
    uint64_t end = offset + length;
    uint64_t markers = 0;
    uint64_t first = (offset + BETA6_BS_CHUNK_SIZE - 1) / BETA6_BS_CHUNK_SIZE *
                     BETA6_BS_CHUNK_SIZE;
    for (uint64_t pos = first; pos < end && pos < size; pos += BETA6_BS_CHUNK_SIZE, markers++)
        if (g->body[pos - offset] != expected_byte(size, pos))
            abort();
    if (size > 0 && (size - 1) % BETA6_BS_CHUNK_SIZE != 0 && size - 1 >= offset &&
        size - 1 < end) {
        markers++;
        if (g->body[size - 1 - offset] != 0xEE)
            abort();
    }
    uint64_t nonzero = 0;
    for (uint32_t i = 0; i < length; i++)
        nonzero += g->body[i] != 0;
    if (nonzero != markers)
        abort();
    for (size_t i = length; i < g->cap; i++)
        if (g->body[i] != FUZZ_PW_BODY_FILL)
            abort();
}

static void guarded_close(struct guarded *g)
{
    require_guards(g);
    free(g->raw);
}

/* ── oracle ──────────────────────────────────────────────────────────── */

/* The chunk range rule stated once more, in 128-bit arithmetic. */
static bool range_oracle(uint64_t offset, uint64_t length, uint64_t file_size,
                         uint64_t chunk_size)
{
    if (chunk_size == 0)
        return false;
    unsigned __int128 end = (unsigned __int128)offset + length;
    if (end > file_size || offset > file_size || offset % chunk_size != 0)
        return false;
    uint64_t remaining = file_size - offset;
    return length == (remaining < chunk_size ? remaining : chunk_size);
}

static struct beta6_bs_chunk_request take_request(struct cursor *c)
{
    struct beta6_bs_chunk_request r;
    uint8_t off_style = (uint8_t)take_le(c, 1);
    uint8_t len_style = (uint8_t)take_le(c, 1);
    r.file_index = (uint32_t)take_le(c, 1);
    r.offset = off_style < 8 ? (uint64_t)off_style * BETA6_BS_CHUNK_SIZE
                             : take_le(c, 8);
    static const uint32_t k_lengths[] = { BETA6_BS_CHUNK_SIZE, 5, 0, 1, 447132u, 1449u };
    if (len_style < sizeof(k_lengths) / sizeof(k_lengths[0]))
        r.length = k_lengths[len_style];
    else
        r.length = (uint32_t)take_le(c, 4);
    return r;
}

static size_t alloc_for(const struct beta6_bs_chunk_request *r, uint8_t cap_style)
{
    uint64_t want = r->length;
    switch (cap_style % 4u) {
    case 0: break;
    case 1: want = want > 0 ? want - 1 : 0; break;
    case 2: want += 8; break;
    default: want = 0; break;
    }
    return want > FUZZ_PW_ALLOC_CAP ? FUZZ_PW_ALLOC_CAP : (size_t)want;
}

/* ── decoders ────────────────────────────────────────────────────────── */

static void require_manifest_shape(const struct beta6_bs_manifest *m)
{
    if (m->file_count > BETA6_BS_MAX_FILES || (m->file_count == 0) != (m->files == NULL))
        abort();
    if (memchr(m->network, '\0', sizeof(m->network)) == NULL)
        abort();
    for (size_t i = 0; i < m->file_count; i++)
        if (memchr(m->files[i].path, '\0', sizeof(m->files[i].path)) == NULL)
            abort();
}

/* The decoder copies a string byte for byte, an embedded NUL included, while
 * the encoder writes strlen() bytes, so a wire carrying one re-encodes
 * shorter. A re-encode may therefore be shorter than what was consumed, never
 * longer, and an equal length must be an equal byte string. The re-encoded
 * form must itself be a fixed point. */
static void require_manifest_roundtrip(const struct beta6_bs_manifest *m,
                                       const uint8_t *wire, size_t consumed)
{
    struct byte_stream out;
    stream_init(&out, 256);
    if (!beta6_bs_manifest_encode(m, &out).ok || out.size > consumed ||
        (out.size == consumed && memcmp(out.data, wire, consumed) != 0))
        abort();
    struct byte_stream again;
    stream_init_from_data(&again, out.data, out.size);
    struct beta6_bs_manifest m2;
    bool ok = beta6_bs_manifest_decode(&again, &m2).ok && again.read_pos == out.size;
    struct byte_stream out2;
    stream_init(&out2, 256);
    if (!ok || !beta6_bs_manifest_encode(&m2, &out2).ok || out2.size != out.size ||
        memcmp(out2.data, out.data, out.size) != 0)
        abort();
    stream_free(&out2);
    stream_free(&again);
    stream_free(&out);
    beta6_bs_manifest_free(&m2);
}

static void fuzz_manifest(const uint8_t *wire, size_t len)
{
    struct byte_stream in;
    stream_init_from_data(&in, wire, len);
    struct beta6_bs_manifest m;
    bool ok = beta6_bs_manifest_decode(&in, &m).ok;
    size_t consumed = in.read_pos;
    stream_free(&in);
    require_manifest_shape(&m);
    if (ok)
        require_manifest_roundtrip(&m, wire, consumed);
    beta6_bs_manifest_free(&m);
}

static void fuzz_request_roundtrip(const uint8_t *wire, size_t len)
{
    struct byte_stream in;
    stream_init_from_data(&in, wire, len);
    struct beta6_bs_chunk_request r;
    bool ok = beta6_bs_chunk_request_decode(&in, &r).ok;
    size_t consumed = in.read_pos;
    stream_free(&in);
    if (ok != (len >= 16) || (ok && consumed != 16))
        abort();
    if (!ok)
        return;
    struct byte_stream out;
    stream_init(&out, 16);
    if (!beta6_bs_chunk_request_encode(&r, &out).ok || out.size != 16 ||
        memcmp(out.data, wire, 16) != 0)
        abort();
    stream_free(&out);
}

static void require_chunk_frame(const struct byte_stream *out, uint32_t index,
                                uint64_t offset, const uint8_t *body, size_t n)
{
    struct byte_stream in;
    stream_init_from_data(&in, out->data, out->size);
    uint32_t got_index = 0;
    uint64_t got_offset = 0;
    uint64_t got_len = 0;
    bool ok = stream_read_u32_le(&in, &got_index) &&
              stream_read_u64_le(&in, &got_offset) &&
              stream_read_compact_size(&in, &got_len);
    if (!ok || got_index != index || got_offset != offset || got_len != n ||
        stream_remaining(&in) != n || (n > 0 && memcmp(out->data + in.read_pos, body, n) != 0))
        abort();
    stream_free(&in);
}

static void fuzz_chunk_encode(const uint8_t *rest, size_t len)
{
    struct cursor c = { rest, len };
    uint32_t index = (uint32_t)take_le(&c, 4);
    uint64_t offset = take_le(&c, 8);
    struct byte_stream out;
    stream_init(&out, 64);
    bool ok = beta6_bs_chunk_encode(index, offset, c.p, c.n, &out).ok;
    if (!ok)
        abort(); /* c.n is far under the chunk cap and the stream grows */
    require_chunk_frame(&out, index, offset, c.p, c.n);
    stream_free(&out);

    static const uint8_t k_zeros[16];
    struct byte_stream big;
    stream_init(&big, 64);
    if (beta6_bs_chunk_encode(index, offset, k_zeros, BETA6_BS_CHUNK_SIZE + 1u, &big).ok ||
        big.size != 0)
        abort(); /* over the cap: refused before a byte is written */
    stream_free(&big);
}

static void fuzz_validate_range(const uint8_t *rest, size_t len)
{
    struct cursor c = { rest, len };
    uint64_t offset = take_le(&c, 8);
    uint64_t length = take_le(&c, 8);
    uint64_t file_size = take_le(&c, 8);
    uint64_t chunk = take_le(&c, 8);
    bool ok = beta6_bs_validate_chunk_range(offset, length, file_size, chunk, "fuzz").ok;
    if (ok != range_oracle(offset, length, file_size, chunk))
        abort();
}

static const char *const k_rf_paths[] = {
    "f.bin", "nope.bin", "", "../rf/f.bin", "link.bin",
};

static void fuzz_file_chunk(const uint8_t *rest, size_t len)
{
    struct cursor c = { rest, len };
    uint8_t mode = (uint8_t)take_le(&c, 1);
    uint8_t cap_style = (uint8_t)take_le(&c, 1);
    struct beta6_bs_chunk_request r = take_request(&c);
    size_t path_index = mode % (sizeof(k_rf_paths) / sizeof(k_rf_paths[0]));
    struct beta6_bs_file file;
    memset(&file, 0, sizeof(file));
    snprintf(file.path, sizeof(file.path), "%s", k_rf_paths[path_index]);
    file.size = (mode & 0x08) ? take_le(&c, 8) : g_rf.size;
    file.mtime_seconds = g_rf.mtime + ((mode & 0x10) ? 1 : 0);

    struct guarded g;
    guarded_open(&g, alloc_for(&r, cap_style));
    bool ok = beta6_bs_read_file_chunk(g_rf_dir, &file, &r, "fuzz", g.body, g.cap).ok;
    /* Only the plain name may open; a missing name, an empty one, an escape
     * through "..", and a link are all refused. The other path spellings are
     * left to the code. */
    bool honest = path_index == 0 && file.size == g_rf.size && !(mode & 0x10);
    bool may_pass = honest && g.cap >= r.length &&
                    range_oracle(r.offset, r.length, file.size, BETA6_BS_CHUNK_SIZE);
    if (ok != may_pass)
        abort();
    if (ok)
        require_chunk(&g, file.size, r.offset, r.length);
    guarded_close(&g);
}

static void fuzz_param_chunk(const uint8_t *rest, size_t len)
{
    struct cursor c = { rest, len };
    uint8_t cap_style = (uint8_t)take_le(&c, 1);
    struct beta6_bs_chunk_request r = take_request(&c);
    struct guarded g;
    guarded_open(&g, alloc_for(&r, cap_style));
    bool ok = beta6_bs_read_param_chunk(g_params_dir, "main", &r, g.body, g.cap).ok;
    bool listed = r.file_index < 2;
    uint64_t size = listed ? g_params[r.file_index].size : 0;
    bool want = listed && r.length > 0 && r.length <= BETA6_BS_CHUNK_SIZE &&
                g.cap >= r.length &&
                range_oracle(r.offset, r.length, size, BETA6_BS_CHUNK_SIZE);
    if (ok != want)
        abort();
    if (ok)
        require_chunk(&g, size, r.offset, r.length);
    guarded_close(&g);
}

static void fuzz_snapshot_chunk(const uint8_t *rest, size_t len)
{
    struct cursor c = { rest, len };
    uint8_t cap_style = (uint8_t)take_le(&c, 1);
    struct beta6_bs_chunk_request r = take_request(&c);
    const struct beta6_bs_manifest *m = beta6_bs_manifest();
    if (!m || m->file_count != 3)
        abort();
    struct guarded g;
    guarded_open(&g, alloc_for(&r, cap_style));
    bool ok = beta6_bs_read_chunk(&r, g.body, g.cap).ok;
    bool listed = r.file_index < m->file_count;
    uint64_t size = listed ? m->files[r.file_index].size : 0;
    bool want = listed && r.length > 0 && r.length <= BETA6_BS_CHUNK_SIZE &&
                g.cap >= r.length &&
                range_oracle(r.offset, r.length, size, BETA6_BS_CHUNK_SIZE);
    if (ok != want)
        abort();
    if (ok)
        require_chunk(&g, size, r.offset, r.length);
    guarded_close(&g);
}

/* zcl_param_chunk_len and zcl_param_serve_ready take a signed index straight
 * from callers that hold a wire byte; the table lookup must hold for any int. */
static void fuzz_pin_index(const uint8_t *rest, size_t len)
{
    struct cursor c = { rest, len };
    int index = (int)(int32_t)take_le(&c, 4);
    uint32_t chunk = (uint32_t)take_le(&c, 4);
    size_t got = zcl_param_chunk_len(index, chunk);
    size_t want = 0;
    if (index >= 0 && index < ZCL_PARAM_FILE_COUNT) {
        const struct zcl_param_pin *p = &zcl_param_pins[index];
        uint64_t start = (uint64_t)chunk * ZCL_PARAM_CHUNK_BYTES;
        if (chunk < p->chunk_count && start < p->bytes)
            want = (size_t)((p->bytes - start) < ZCL_PARAM_CHUNK_BYTES
                                ? (p->bytes - start)
                                : ZCL_PARAM_CHUNK_BYTES);
    }
    if (got != want)
        abort();
    if (zcl_param_serve_ready(index))
        abort(); /* nothing is armed for serving in this process */
}

/* ── dispatch ────────────────────────────────────────────────────────── */

static void drain_peer(void)
{
    while (g_node.send_head) {
        struct send_segment *next = g_node.send_head->next;
        send_segment_free(g_node.send_head);
        g_node.send_head = next;
    }
    g_node.send_tail = NULL;
    g_node.send_size = 0;
}

static const char *first_reply(void)
{
    if (!g_node.send_head || g_node.send_head->size < 16)
        return NULL;
    return (const char *)g_node.send_head->data + 4;
}

/* The answer a request must draw: a valid chunk request is served, any other
 * is refused by name, never dropped. */
static void require_chunk_reply(size_t cmd, const uint8_t *payload, size_t len)
{
    bool params = cmd == 12;
    struct byte_stream in;
    stream_init_from_data(&in, payload, len);
    struct beta6_bs_chunk_request r;
    bool parsed = beta6_bs_chunk_request_decode(&in, &r).ok && stream_remaining(&in) == 0;
    stream_free(&in);
    bool serve = false;
    if (parsed && r.length > 0 && r.length <= BETA6_BS_CHUNK_SIZE) {
        const struct beta6_bs_manifest *m = beta6_bs_manifest();
        uint64_t size = 0;
        bool listed = params ? r.file_index < 2 : r.file_index < m->file_count;
        if (listed)
            size = params ? g_params[r.file_index].size : m->files[r.file_index].size;
        serve = listed && range_oracle(r.offset, r.length, size, BETA6_BS_CHUNK_SIZE);
    }
    const char *got = first_reply();
    const char *want = serve ? (params ? "bspchk" : "bschk") : "reject";
    if (!got || strcmp(got, want) != 0)
        abort();
}

static void fuzz_dispatch(size_t cmd, const uint8_t *payload, size_t len)
{
    beta6_bs_quota_clear();
    struct byte_stream s;
    stream_init_from_data(&s, payload, len);
    (void)g_rows[cmd]->handler(&g_mp, &g_node, &s);
    stream_free(&s);
    if (cmd == 6 && (!first_reply() || strcmp(first_reply(), "bsman") != 0))
        abort();
    if (cmd == 10 && (!first_reply() || strcmp(first_reply(), "bspman") != 0))
        abort();
    if (cmd == 8 || cmd == 12)
        require_chunk_reply(cmd, payload, len);
    if ((cmd == 7 || cmd == 9 || cmd == 11 || cmd == 13) && first_reply())
        abort(); /* an unsolicited server reply is dropped, never answered */
    drain_peer();
}

/* The first byte picks the decoder; the rest is its input. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!data || size == 0 || size > FUZZ_PW_MAX_INPUT)
        return 0;
    fuzz_init();

    const uint8_t *rest = data + 1;
    size_t len = size - 1;
    size_t arm = data[0] % FUZZ_PW_ARMS;
    switch (arm) {
    case 0: fuzz_manifest(rest, len); break;
    case 1: fuzz_request_roundtrip(rest, len); break;
    case 2: fuzz_chunk_encode(rest, len); break;
    case 3: fuzz_validate_range(rest, len); break;
    case 4: fuzz_file_chunk(rest, len); break;
    case 5: fuzz_param_chunk(rest, len); break;
    case 6: fuzz_snapshot_chunk(rest, len); break;
    case 7: fuzz_pin_index(rest, len); break;
    default: fuzz_dispatch(arm - 8u, rest, len); break;
    }
    return 0;
}
