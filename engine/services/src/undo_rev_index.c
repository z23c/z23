// one-result-type-ok:read-only-undo-lookup-status-enum
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * E2 override: every fallible call reports through enum undo_rev_status
 * (FOUND / NOT_FOUND / NO_FILE / ERROR) after a contextual LOG_*; the caller
 * must tell "no record" from "no file" from "failed", which a zcl_result would
 * only duplicate. The bool helpers are init and internal predicates.
 *
 * undo_rev_index — see services/undo_rev_index.h. Finds a block's undo record
 * in the zclassicd rev files by verifying the PARENT-hash checksum, so a
 * bundle-seeded node (BLOCK_HAVE_UNDO cleared below the seed) can still
 * script-verify history. Read-only: it never writes a file or the index. */

#include "services/undo_rev_index.h"

#include "base/serialize_le.h"
#include "core/hash.h"
#include "core/serialize.h"
#include "platform/time_compat.h"
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
#define UNDO_REV_SCAN_COST_MS 10000
#define UNDO_REV_SCAN_BURST 8
#define UNDO_REV_SCAN_CAP_MS (UNDO_REV_SCAN_COST_MS * UNDO_REV_SCAN_BURST)
#define UNDO_REV_MAX_GAP 4
#define UNDO_REV_MAX_FILE_NO 99999
#define UNDO_REV_MAX_SLOTS (8u * 1024u * 1024u)

enum undo_rev_load { UNDO_REV_LOAD_OK, UNDO_REV_LOAD_ABSENT, UNDO_REV_LOAD_ERROR };

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

/* Lookup state: what is being asked for and what the scan has found so far.
 * The checksum binds only the PARENT, so siblings that share a parent (an
 * orphan or reorged block still in the rev file) also pass it. A record is
 * therefore taken only if `accept` (the caller's shape check against THIS
 * block) agrees, and only when exactly one record in the scanned range does:
 * two matches are AMBIGUOUS and neither is returned. */
struct undo_rev_scan {
    const struct uint256 *parent;
    undo_rev_accept_fn accept;
    void *accept_ctx;
    struct block_undo *out;
    bool found;
    bool ambiguous;
    bool error;
    bool any_file;
    int file;
    size_t slot;
};

static enum undo_rev_status slot_check(const struct undo_rev_cached_file *e,
                                       const struct undo_rev_slot *slot,
                                       const struct undo_rev_scan *sc,
                                       struct block_undo *out)
{
    block_undo_init(out);
    size_t body = (size_t)slot->size + UNDO_REV_CHECKSUM;
    unsigned char *buf = zcl_malloc(UNDO_REV_HASH_SIZE + body,
                                    "undo_rev record");
    if (!buf)
        LOG_RETURN(UNDO_REV_ERROR, "undo_rev",
                   "malloc failed for %zu byte record in rev %d",
                   UNDO_REV_HASH_SIZE + body, e->file_no);
    memcpy(buf, sc->parent->data, UNDO_REV_HASH_SIZE);
    bool ok = platform_positioned_file_read(&e->file, buf + UNDO_REV_HASH_SIZE,
                                            body, slot->offset) ==
                  (int64_t)body &&
              checksum_matches(buf, slot->size) &&
              payload_parse(buf + UNDO_REV_HASH_SIZE, slot->size, out);
    free(buf);
    if (ok && sc->accept && !sc->accept(out, sc->accept_ctx)) {
        block_undo_free(out);
        block_undo_init(out);
        ok = false;
    }
    return ok ? UNDO_REV_FOUND : UNDO_REV_NOT_FOUND;
}

/* Fold one verified record into the scan: the first is kept, a second makes
 * the lookup ambiguous. */
static void scan_note_match(struct undo_rev_scan *sc, int file, size_t slot,
                            struct block_undo *rec)
{
    if (sc->found) {
        block_undo_free(rec);
        sc->ambiguous = true;
        return;
    }
    *sc->out = *rec;
    sc->found = true;
    sc->file = file;
    sc->slot = slot;
}

/* Try slots [from, to) of one cached file. Stops at an error or ambiguity. */
static void try_slots(const struct undo_rev_cached_file *e, size_t from,
                      size_t to, struct undo_rev_scan *sc)
{
    if (to > e->count)
        to = e->count;
    for (size_t i = from; i < to && !sc->error && !sc->ambiguous; i++) {
        struct block_undo rec;
        block_undo_init(&rec);
        enum undo_rev_status st = slot_check(e, &e->slots[i], sc, &rec);
        if (st == UNDO_REV_ERROR)
            sc->error = true;
        else if (st == UNDO_REV_FOUND)
            scan_note_match(sc, e->file_no, i, &rec);
    }
}

/* Turn the scan into a status; a clean single match moves the cursor to the
 * record after it. Anything else leaves *out empty. */
static enum undo_rev_status scan_finish(struct undo_rev_locator *loc,
                                        struct undo_rev_scan *sc)
{
    if (sc->error || sc->ambiguous) {
        if (sc->found)
            block_undo_free(sc->out);
        block_undo_init(sc->out);
        return sc->error ? UNDO_REV_ERROR : UNDO_REV_AMBIGUOUS;
    }
    if (!sc->found)
        return UNDO_REV_NOT_FOUND;
    loc->cursor_file = sc->file;
    loc->cursor_slot = sc->slot + 1;
    return UNDO_REV_FOUND;
}

/* ── lookup ─────────────────────────────────────────────────── */

/* Records are written in connect order, so the block is almost always near
 * the last hit: a window around the cursor (a stale sibling is written before
 * the winner, so it looks back too) and the head of the next file. */
static enum undo_rev_status try_window(struct undo_rev_locator *loc,
                                       struct undo_rev_scan *sc)
{
    if (loc->cursor_file < 0)
        return UNDO_REV_NOT_FOUND;
    int file = loc->cursor_file;
    size_t cur = loc->cursor_slot;
    struct undo_rev_cached_file *e = cache_get(loc, file);
    bool near_end = !e || cur + UNDO_REV_WINDOW > e->count;
    if (e) {
        sc->any_file = true;
        try_slots(e, cur > UNDO_REV_WINDOW ? cur - UNDO_REV_WINDOW : 0,
                  cur + UNDO_REV_WINDOW, sc);
    }
    if (near_end && !sc->ambiguous && !sc->error &&
        (e = cache_get(loc, file + 1)) != NULL) {
        sc->any_file = true;
        try_slots(e, 0, UNDO_REV_WINDOW, sc);
    }
    return scan_finish(loc, sc);
}

static void scan_file(struct undo_rev_locator *loc, int n,
                      struct undo_rev_scan *sc, bool *present)
{
    struct undo_rev_cached_file *e = cache_get(loc, n);
    *present = e != NULL;
    if (!e)
        return;
    sc->any_file = true;
    try_slots(e, 0, e->count, sc);
}

static bool scan_done(const struct undo_rev_scan *sc)
{
    return sc->found || sc->ambiguous || sc->error;
}

static void scan_ascending(struct undo_rev_locator *loc, int skip_a,
                           int skip_b, struct undo_rev_scan *sc)
{
    int gap = 0;
    for (int n = 0; n <= UNDO_REV_MAX_FILE_NO && gap < UNDO_REV_MAX_GAP &&
                    !scan_done(sc); n++) {
        if (n == skip_a || n == skip_b)
            continue;
        bool present = false;
        scan_file(loc, n, sc, &present);
        gap = present ? 0 : gap + 1;
    }
}

/* Scan whole files (hint, cursor, then ascending) and stop after the first
 * file that holds a match: a sibling in ANOTHER file is not looked for. */
static enum undo_rev_status full_scan(struct undo_rev_locator *loc,
                                      int hint_file,
                                      struct undo_rev_scan *sc)
{
    int hint = hint_file <= UNDO_REV_MAX_FILE_NO ? hint_file : -1;
    int first[2] = { hint, loc->cursor_file };
    for (int i = 0; i < 2 && !scan_done(sc); i++) {
        bool present = false;
        if (first[i] >= 0 && !(i == 1 && first[1] == first[0]))
            scan_file(loc, first[i], sc, &present);
    }
    if (!scan_done(sc))
        scan_ascending(loc, first[0], first[1], sc);
    enum undo_rev_status st = scan_finish(loc, sc);
    if (st == UNDO_REV_NOT_FOUND && !sc->any_file)
        return UNDO_REV_NO_FILE;
    return st;
}

/* Whole-file scans cost a full pass over a rev file, so they are metered:
 * a token bucket (one scan per UNDO_REV_SCAN_COST_MS, a burst of
 * UNDO_REV_SCAN_BURST) that keeps refilling. Misses slow the scan down; they
 * never switch it off, and the cheap cursor window is never metered. */
static bool scan_credit_take(struct undo_rev_locator *loc)
{
    int64_t now = platform_time_monotonic_ms();
    loc->scan_credit_ms += now - loc->scan_stamp_ms;
    loc->scan_stamp_ms = now;
    if (loc->scan_credit_ms > UNDO_REV_SCAN_CAP_MS)
        loc->scan_credit_ms = UNDO_REV_SCAN_CAP_MS;
    if (loc->scan_credit_ms < UNDO_REV_SCAN_COST_MS)
        return false;
    loc->scan_credit_ms -= UNDO_REV_SCAN_COST_MS;
    return true;
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
    loc->scan_credit_ms = UNDO_REV_SCAN_CAP_MS;
    loc->scan_stamp_ms = platform_time_monotonic_ms();
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
                                           undo_rev_accept_fn accept,
                                           void *accept_ctx,
                                           struct block_undo *out)
{
    if (!loc || !parent || !out)
        LOG_RETURN(UNDO_REV_ERROR, "undo_rev",
                   "locator read received invalid arguments");
    block_undo_init(out);
    struct undo_rev_scan sc = { .parent = parent, .accept = accept,
                                .accept_ctx = accept_ctx, .out = out };
    zcl_mutex_lock(&loc->lock);
    enum undo_rev_status st = try_window(loc, &sc);
    if (st == UNDO_REV_NOT_FOUND && scan_credit_take(loc)) {
        struct undo_rev_scan full = sc;
        st = full_scan(loc, hint_file, &full);
    }
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
    const struct uint256 *parent, int hint_file, undo_rev_accept_fn accept,
    void *accept_ctx, struct block_undo *out)
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
        ? undo_rev_locator_read(&g_shared, parent, hint_file, accept,
                                accept_ctx, out)
        : UNDO_REV_ERROR;
    zcl_mutex_unlock(&g_shared_lock);
    return st;
}
