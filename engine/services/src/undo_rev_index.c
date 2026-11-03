/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * undo_rev_index — see services/undo_rev_index.h. Finds a block's undo record
 * in the zclassicd rev files by verifying the PARENT-hash checksum, so a
 * bundle-seeded node (BLOCK_HAVE_UNDO cleared below the seed) can still
 * script-verify history. Read-only: it never writes a file or the index. */

#include "services/undo_rev_index.h"

#include "base/serialize_le.h"
#include "core/hash.h"
#include "core/serialize.h"
#include "storage/disk_block_io.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdlib.h>
#include <string.h>

#define UNDO_REV_MAX_RECORD (4u * 1024u * 1024u)
#define UNDO_REV_FRAME_HEAD 8u
#define UNDO_REV_CHECKSUM 32u
#define UNDO_REV_HASH_SIZE 32u
#define UNDO_REV_WINDOW 8u
#define UNDO_REV_FULLSCAN_BUDGET 3u
#define UNDO_REV_MAX_GAP 4
#define UNDO_REV_MAX_FILE_NO 99999
#define UNDO_REV_MAX_SLOTS (8u * 1024u * 1024u)

enum undo_rev_load { UNDO_REV_LOAD_OK, UNDO_REV_LOAD_ABSENT, UNDO_REV_LOAD_ERROR };

struct undo_rev_scan {
    const struct uint256 *parent;
    struct block_undo *out;
    bool any_file;
};

/* ── per-file slot list ─────────────────────────────────────── */

static void entry_release(struct undo_rev_cached_file *e)
{
    if (e->file_no >= 0)
        platform_positioned_file_close(&e->file);
    free(e->slots);
    e->slots = NULL;
    e->count = 0;
    e->capacity = 0;
    e->file_no = -1;
    platform_positioned_file_init(&e->file);
}

static bool slots_push(struct undo_rev_cached_file *e, uint64_t offset,
                       uint32_t size)
{
    if (e->count >= UNDO_REV_MAX_SLOTS)
        LOG_FAIL("undo_rev", "rev file %d has more than %u records", e->file_no,
                 UNDO_REV_MAX_SLOTS);
    if (e->count == e->capacity) {
        size_t cap = e->capacity ? e->capacity * 2 : 4096;
        struct undo_rev_slot *p = zcl_realloc(
            e->slots, cap * sizeof(*p), "undo_rev slots");
        if (!p)
            LOG_FAIL("undo_rev", "cannot grow slot list to %zu for rev %d", cap,
                     e->file_no);
        e->slots = p;
        e->capacity = cap;
    }
    e->slots[e->count].offset = offset;
    e->slots[e->count].size = size;
    e->count++;
    return true;
}

/* Walk the frames of one open file. A bad magic, an impossible size or a
 * record cut short by the end of the file ends the walk: nothing past it is
 * indexed, so a truncated tail can never be returned. */
static bool entry_index_frames(struct undo_rev_cached_file *e,
                               const unsigned char magic[UNDO_REV_MAGIC_SIZE],
                               uint64_t file_size)
{
    uint64_t pos = 0;
    while (pos + UNDO_REV_FRAME_HEAD + UNDO_REV_CHECKSUM <= file_size) {
        unsigned char h[UNDO_REV_FRAME_HEAD];
        if (platform_positioned_file_read(&e->file, h, sizeof(h), pos) !=
            (int64_t)sizeof(h))
            break;
        if (memcmp(h, magic, UNDO_REV_MAGIC_SIZE) != 0)
            break;
        uint32_t size = zcl_read_u32_le(h + UNDO_REV_MAGIC_SIZE);
        if (size == 0 || size > UNDO_REV_MAX_RECORD)
            break;
        uint64_t end = pos + UNDO_REV_FRAME_HEAD + size + UNDO_REV_CHECKSUM;
        if (end > file_size)
            break;
        if (!slots_push(e, pos + UNDO_REV_FRAME_HEAD, size))
            LOG_FAIL("undo_rev", "rev %d: cannot index record at offset %llu",
                     e->file_no, (unsigned long long)pos);
        pos = end;
    }
    return true;
}

static enum undo_rev_load entry_load(struct undo_rev_locator *loc,
                                     struct undo_rev_cached_file *e, int n)
{
    char path[512];
    struct disk_block_pos pos = { .nFile = n, .nPos = 0 };
    get_block_pos_filename(path, sizeof(path), loc->datadir, &pos, "rev");
    if (!platform_positioned_file_open(&e->file, path))
        return UNDO_REV_LOAD_ABSENT;
    e->file_no = n;
    uint64_t size = 0;
    if (!platform_positioned_file_size(&e->file, &size)) {
        LOG_ERROR("undo_rev", "cannot size %s", path);
        entry_release(e);
        return UNDO_REV_LOAD_ERROR;
    }
    if (!entry_index_frames(e, loc->magic, size)) {
        entry_release(e);
        return UNDO_REV_LOAD_ERROR;
    }
    return UNDO_REV_LOAD_OK;
}

/* The cached entry for rev file n, loading it (and evicting the entry used
 * least recently) on a miss. NULL when the file is absent or unreadable. */
static struct undo_rev_cached_file *cache_get(struct undo_rev_locator *loc,
                                              int n)
{
    for (int i = 0; i < UNDO_REV_CACHE_FILES; i++) {
        if (loc->cache[i].file_no == n) {
            loc->mru = i;
            return &loc->cache[i];
        }
    }
    int victim = (loc->mru + 1) % UNDO_REV_CACHE_FILES;
    for (int i = 0; i < UNDO_REV_CACHE_FILES; i++)
        if (loc->cache[i].file_no < 0)
            victim = i;
    entry_release(&loc->cache[victim]);
    if (entry_load(loc, &loc->cache[victim], n) != UNDO_REV_LOAD_OK)
        return NULL;
    loc->mru = victim;
    return &loc->cache[victim];
}

/* ── record verification ────────────────────────────────────── */

static bool payload_parse(const unsigned char *payload, size_t size,
                          struct block_undo *out)
{
    struct byte_stream s;
    block_undo_init(out);
    stream_init_from_data(&s, payload, size);
    if (block_undo_deserialize(out, &s) && !s.error && s.read_pos == size)
        return true;
    block_undo_free(out);
    block_undo_init(out);
    return false;
}

/* buf = [parent hash][CBlockUndo bytes][stored checksum] */
static bool checksum_matches(const unsigned char *buf, size_t size)
{
    unsigned char digest[SHA256_OUTPUT_SIZE];
    hash256(buf, UNDO_REV_HASH_SIZE + size, digest);
    return memcmp(digest, buf + UNDO_REV_HASH_SIZE + size,
                  UNDO_REV_CHECKSUM) == 0;
}

static enum undo_rev_status slot_check(const struct undo_rev_cached_file *e,
                                       const struct undo_rev_slot *slot,
                                       const struct uint256 *parent,
                                       struct block_undo *out)
{
    size_t body = (size_t)slot->size + UNDO_REV_CHECKSUM;
    unsigned char *buf = zcl_malloc(UNDO_REV_HASH_SIZE + body,
                                    "undo_rev record");
    if (!buf)
        LOG_RETURN(UNDO_REV_ERROR, "undo_rev",
                   "malloc failed for %zu byte record in rev %d",
                   UNDO_REV_HASH_SIZE + body, e->file_no);
    memcpy(buf, parent->data, UNDO_REV_HASH_SIZE);
    bool ok = platform_positioned_file_read(&e->file, buf + UNDO_REV_HASH_SIZE,
                                            body, slot->offset) ==
                  (int64_t)body &&
              checksum_matches(buf, slot->size) &&
              payload_parse(buf + UNDO_REV_HASH_SIZE, slot->size, out);
    free(buf);
    return ok ? UNDO_REV_FOUND : UNDO_REV_NOT_FOUND;
}

/* Try slots [from, to) of one cached file; a hit moves the cursor to the
 * record after it. */
static enum undo_rev_status try_slots(struct undo_rev_locator *loc,
                                      const struct undo_rev_cached_file *e,
                                      size_t from, size_t to,
                                      const struct uint256 *parent,
                                      struct block_undo *out)
{
    if (to > e->count)
        to = e->count;
    for (size_t i = from; i < to; i++) {
        enum undo_rev_status st = slot_check(e, &e->slots[i], parent, out);
        if (st == UNDO_REV_NOT_FOUND)
            continue;
        if (st == UNDO_REV_FOUND) {
            loc->cursor_file = e->file_no;
            loc->cursor_slot = i + 1;
        }
        return st;
    }
    return UNDO_REV_NOT_FOUND;
}

/* ── lookup ─────────────────────────────────────────────────── */

/* Records are written in connect order, so the block after the last hit is
 * almost always the next record of the same file (or the head of the next). */
static enum undo_rev_status try_window(struct undo_rev_locator *loc,
                                       const struct uint256 *parent,
                                       struct block_undo *out)
{
    if (loc->cursor_file < 0)
        return UNDO_REV_NOT_FOUND;
    int file = loc->cursor_file;
    struct undo_rev_cached_file *e = cache_get(loc, file);
    if (e) {
        enum undo_rev_status st = try_slots(
            loc, e, loc->cursor_slot, loc->cursor_slot + UNDO_REV_WINDOW,
            parent, out);
        if (st != UNDO_REV_NOT_FOUND)
            return st;
    }
    e = cache_get(loc, file + 1);
    if (!e)
        return UNDO_REV_NOT_FOUND;
    return try_slots(loc, e, 0, UNDO_REV_WINDOW, parent, out);
}

static enum undo_rev_status scan_file(struct undo_rev_locator *loc, int n,
                                      struct undo_rev_scan *sc, bool *present)
{
    struct undo_rev_cached_file *e = cache_get(loc, n);
    *present = e != NULL;
    if (!e)
        return UNDO_REV_NOT_FOUND;
    sc->any_file = true;
    return try_slots(loc, e, 0, e->count, sc->parent, sc->out);
}

static enum undo_rev_status scan_ascending(struct undo_rev_locator *loc,
                                           int skip_a, int skip_b,
                                           struct undo_rev_scan *sc)
{
    int gap = 0;
    for (int n = 0; n <= UNDO_REV_MAX_FILE_NO && gap < UNDO_REV_MAX_GAP; n++) {
        if (n == skip_a || n == skip_b)
            continue;
        bool present = false;
        enum undo_rev_status st = scan_file(loc, n, sc, &present);
        if (st != UNDO_REV_NOT_FOUND)
            return st;
        gap = present ? 0 : gap + 1;
    }
    return UNDO_REV_NOT_FOUND;
}

static enum undo_rev_status full_scan(struct undo_rev_locator *loc,
                                      const struct uint256 *parent,
                                      int hint_file, struct block_undo *out)
{
    struct undo_rev_scan sc = { .parent = parent, .out = out };
    int hint = hint_file <= UNDO_REV_MAX_FILE_NO ? hint_file : -1;
    int first[2] = { hint, loc->cursor_file };
    for (int i = 0; i < 2; i++) {
        if (first[i] < 0 || (i == 1 && first[1] == first[0]))
            continue;
        bool present = false;
        enum undo_rev_status st = scan_file(loc, first[i], &sc, &present);
        if (st != UNDO_REV_NOT_FOUND)
            return st;
    }
    enum undo_rev_status st = scan_ascending(loc, first[0], first[1], &sc);
    if (st == UNDO_REV_NOT_FOUND && !sc.any_file)
        return UNDO_REV_NO_FILE;
    return st;
}

/* ── public API ─────────────────────────────────────────────── */

bool undo_rev_locator_init(struct undo_rev_locator *loc, const char *datadir,
                           const unsigned char magic[UNDO_REV_MAGIC_SIZE])
{
    if (!loc || !datadir || !magic)
        LOG_FAIL("undo_rev", "locator init received invalid arguments");
    memset(loc, 0, sizeof(*loc));
    if (strlen(datadir) >= sizeof(loc->datadir))
        LOG_FAIL("undo_rev", "datadir path is %zu bytes, limit %zu",
                 strlen(datadir), sizeof(loc->datadir) - 1);
    memcpy(loc->datadir, datadir, strlen(datadir));
    memcpy(loc->magic, magic, UNDO_REV_MAGIC_SIZE);
    for (int i = 0; i < UNDO_REV_CACHE_FILES; i++) {
        loc->cache[i].file_no = -1;
        platform_positioned_file_init(&loc->cache[i].file);
    }
    loc->cursor_file = -1;
    zcl_mutex_init(&loc->lock);
    return true;
}

void undo_rev_locator_free(struct undo_rev_locator *loc)
{
    if (!loc)
        return;
    for (int i = 0; i < UNDO_REV_CACHE_FILES; i++)
        entry_release(&loc->cache[i]);
    zcl_mutex_destroy(&loc->lock);
}

enum undo_rev_status undo_rev_locator_read(struct undo_rev_locator *loc,
                                           const struct uint256 *parent,
                                           int hint_file,
                                           struct block_undo *out)
{
    if (!loc || !parent || !out)
        LOG_RETURN(UNDO_REV_ERROR, "undo_rev",
                   "locator read received invalid arguments");
    block_undo_init(out);
    zcl_mutex_lock(&loc->lock);
    enum undo_rev_status st = try_window(loc, parent, out);
    if (st == UNDO_REV_NOT_FOUND && loc->full_misses < UNDO_REV_FULLSCAN_BUDGET)
        st = full_scan(loc, parent, hint_file, out);
    if (st == UNDO_REV_FOUND)
        loc->full_misses = 0;
    else if (st != UNDO_REV_ERROR && loc->full_misses < UNDO_REV_FULLSCAN_BUDGET)
        loc->full_misses++;
    zcl_mutex_unlock(&loc->lock);
    return st;
}

static zcl_once_t g_shared_once = ZCL_ONCE_INIT;
static zcl_mutex_t g_shared_lock;
static struct undo_rev_locator g_shared;
static bool g_shared_ready;

static void shared_lock_init(void) { zcl_mutex_init(&g_shared_lock); }

static bool shared_matches(const char *datadir,
                           const unsigned char magic[UNDO_REV_MAGIC_SIZE])
{
    return g_shared_ready && strcmp(g_shared.datadir, datadir) == 0 &&
           memcmp(g_shared.magic, magic, UNDO_REV_MAGIC_SIZE) == 0;
}

enum undo_rev_status undo_rev_shared_read(
    const char *datadir, const unsigned char magic[UNDO_REV_MAGIC_SIZE],
    const struct uint256 *parent, int hint_file, struct block_undo *out)
{
    if (!datadir || !magic || !zcl_once_call(&g_shared_once, shared_lock_init))
        LOG_RETURN(UNDO_REV_ERROR, "undo_rev",
                   "shared read received invalid arguments");
    zcl_mutex_lock(&g_shared_lock);
    if (!shared_matches(datadir, magic)) {
        if (g_shared_ready)
            undo_rev_locator_free(&g_shared);
        g_shared_ready = undo_rev_locator_init(&g_shared, datadir, magic);
    }
    enum undo_rev_status st = g_shared_ready
        ? undo_rev_locator_read(&g_shared, parent, hint_file, out)
        : UNDO_REV_ERROR;
    zcl_mutex_unlock(&g_shared_lock);
    return st;
}
