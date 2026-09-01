/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ldb_reader_format — byte-level decoding for the C23 LevelDB reader:
 * varints, internal keys, prefix-compressed blocks, and the log-record
 * framing that MANIFEST and the write-ahead log share.
 *
 * Every function here is fed bytes another process wrote. The contract is
 * that a malformed input produces `false` (or a corrupt flag), never a
 * short read that looks like a successful one.
 */

#include "ldb_reader_internal.h"

#include "util/crc32c.h"
#include "util/safe_alloc.h"

#include <dirent.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── misc helpers ───────────────────────────────────────────────────── */

char *ldb_strdup(const char *s)
{
    size_t n = strlen(s) + 1;
    char *out = zcl_malloc(n, "ldb_reader_err");
    if (!out)
        return NULL;
    memcpy(out, s, n);
    return out;
}

char *ldb_errf(const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    return ldb_strdup(buf);
}

bool ldb_map_file(const char *path, struct ldb_file_mapping *out, char **err)
{
    if (!path || !out) return false;
    platform_positioned_file_init(&out->file);
    platform_read_mapping_init(&out->mapping);
    if (!platform_positioned_file_open(&out->file, path)) {
        if (err)
            *err = ldb_errf("ldb: validated open %s failed", path);
        return false;
    }
    struct platform_positioned_file_snapshot before, after;
    if (!platform_positioned_file_snapshot(&out->file, &before) ||
        before.size > SIZE_MAX) {
        if (err)
            *err = ldb_errf("ldb: snapshot %s failed", path);
        ldb_unmap_file(out);
        return false;
    }
    if (before.size == 0) {
        /* An empty file maps to nothing; callers treat size 0 explicitly
         * rather than dereferencing a zero-length mapping. */
        return true;
    }
    if (!platform_read_mapping_open_positioned(&out->mapping, &out->file,
                                                (size_t)before.size) ||
        !platform_positioned_file_snapshot(&out->file, &after) ||
        before.size != after.size || before.volume != after.volume ||
        before.file_low != after.file_low || before.file_high != after.file_high ||
        before.modified_seconds != after.modified_seconds ||
        before.modified_nanoseconds != after.modified_nanoseconds ||
        before.changed_seconds != after.changed_seconds ||
        before.changed_nanoseconds != after.changed_nanoseconds) {
        if (err)
            *err = ldb_errf("ldb: stable mapping %s failed", path);
        ldb_unmap_file(out);
        return false;
    }
    return true;
}

void ldb_unmap_file(struct ldb_file_mapping *file)
{
    if (!file) return;
    platform_read_mapping_close(&file->mapping);
    platform_positioned_file_close(&file->file);
}

/* ── little-endian + varint ─────────────────────────────────────────── */

uint32_t ldb_fixed32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

uint64_t ldb_fixed64(const uint8_t *p)
{
    return (uint64_t)ldb_fixed32(p) | ((uint64_t)ldb_fixed32(p + 4) << 32);
}

bool ldb_get_varint64(const uint8_t **pp, const uint8_t *end, uint64_t *out)
{
    uint64_t result = 0;
    const uint8_t *p = *pp;
    for (unsigned shift = 0; shift <= 63; shift += 7) {
        if (p >= end)
            return false;
        uint8_t byte = *p++;
        if (byte & 0x80) {
            result |= ((uint64_t)(byte & 0x7f)) << shift;
        } else {
            result |= ((uint64_t)byte) << shift;
            *pp = p;
            *out = result;
            return true;
        }
    }
    return false;   /* more than 10 bytes: not a valid varint64 */
}

bool ldb_get_varint32(const uint8_t **pp, const uint8_t *end, uint32_t *out)
{
    uint64_t wide = 0;
    const uint8_t *save = *pp;
    if (!ldb_get_varint64(pp, end, &wide))
        return false;
    if (wide > UINT32_MAX) {
        *pp = save;
        return false;
    }
    *out = (uint32_t)wide;
    return true;
}

bool ldb_get_length_prefixed(const uint8_t **pp, const uint8_t *end,
                             struct ldb_slice *out)
{
    uint32_t len = 0;
    const uint8_t *save = *pp;
    if (!ldb_get_varint32(pp, end, &len))
        return false;
    if ((size_t)(end - *pp) < (size_t)len) {
        *pp = save;
        return false;
    }
    out->p = *pp;
    out->n = len;
    *pp += len;
    return true;
}

uint32_t ldb_unmask_crc(uint32_t masked)
{
    const uint32_t kMaskDelta = 0xa282ead8u;
    uint32_t rot = masked - kMaskDelta;
    return ((rot >> 17) | (rot << 15));
}

/* ── internal keys ──────────────────────────────────────────────────── */

int ldb_ukey_cmp(const uint8_t *a, size_t an, const uint8_t *b, size_t bn)
{
    size_t m = an < bn ? an : bn;
    int r = m ? memcmp(a, b, m) : 0;
    if (r != 0)
        return r;
    if (an < bn)
        return -1;
    if (an > bn)
        return 1;
    return 0;
}

int ldb_ikey_cmp(const uint8_t *a, size_t an, const uint8_t *b, size_t bn)
{
    /* A key shorter than the 8-byte trailer is corrupt. Ordering it by raw
     * bytes keeps the comparator a total order (so sorts and binary
     * searches stay well-defined) while the parse-time checks reject it. */
    if (an < 8 || bn < 8)
        return ldb_ukey_cmp(a, an, b, bn);

    int r = ldb_ukey_cmp(a, an - 8, b, bn - 8);
    if (r != 0)
        return r;

    uint64_t anum = ldb_fixed64(a + an - 8);
    uint64_t bnum = ldb_fixed64(b + bn - 8);
    if (anum > bnum)
        return -1;      /* higher sequence sorts FIRST */
    if (anum < bnum)
        return 1;
    return 0;
}

bool ldb_ikey_user(const uint8_t *k, size_t n, struct ldb_slice *user,
                   uint64_t *sequence, uint8_t *type)
{
    if (n < 8)
        return false;
    uint64_t num = ldb_fixed64(k + n - 8);
    uint8_t t = (uint8_t)(num & 0xff);
    if (t != LDB_TYPE_DELETION && t != LDB_TYPE_VALUE)
        return false;
    if (user) {
        user->p = k;
        user->n = n - 8;
    }
    if (sequence)
        *sequence = num >> 8;
    if (type)
        *type = t;
    return true;
}

bool ldb_ikey_build(uint8_t *buf, size_t cap, const uint8_t *user, size_t n,
                    uint64_t seq, uint8_t type, size_t *out_len)
{
    if (cap < n + 8 || seq > LDB_MAX_SEQUENCE)
        return false;
    if (n)
        memcpy(buf, user, n);
    uint64_t num = (seq << 8) | (uint64_t)type;
    for (int i = 0; i < 8; i++)
        buf[n + i] = (uint8_t)((num >> (8 * i)) & 0xff);
    *out_len = n + 8;
    return true;
}

/* ── blocks ─────────────────────────────────────────────────────────── */

bool ldb_block_init(struct ldb_block *b, const uint8_t *data, size_t size,
                    uint8_t *owned)
{
    memset(b, 0, sizeof(*b));
    if (size < sizeof(uint32_t))
        return false;
    uint32_t num_restarts = ldb_fixed32(data + size - sizeof(uint32_t));
    /* (num_restarts + 1) * 4 must fit inside the block alongside at least
     * zero entry bytes. The multiply is done in 64-bit so a hostile count
     * cannot wrap into a plausible-looking offset. */
    uint64_t trailer = ((uint64_t)num_restarts + 1) * sizeof(uint32_t);
    if (trailer > (uint64_t)size)
        return false;
    b->data = data;
    b->size = size;
    b->num_restarts = num_restarts;
    b->restart_off = size - (size_t)trailer;
    b->owned = owned;
    return true;
}

void ldb_block_free(struct ldb_block *b)
{
    if (!b)
        return;
    free(b->owned);
    memset(b, 0, sizeof(*b));
}

static uint32_t block_restart_point(const struct ldb_block *b, uint32_t i)
{
    return ldb_fixed32(b->data + b->restart_off + i * sizeof(uint32_t));
}

static bool key_reserve(struct ldb_block_iter *it, size_t want)
{
    if (want <= it->key_cap)
        return true;
    size_t cap = it->key_cap ? it->key_cap : 64;
    while (cap < want)
        cap *= 2;
    uint8_t *nk = zcl_realloc(it->key, cap, "ldb_block_iter_key");
    if (!nk)
        return false;
    it->key = nk;
    it->key_cap = cap;
    return true;
}

/* Decode the entry starting at `off`, appending onto the shared prefix
 * already in it->key. Returns false on any framing violation. */
static bool parse_entry(struct ldb_block_iter *it, size_t off)
{
    const struct ldb_block *b = it->b;
    if (off >= b->restart_off) {
        it->valid = false;
        return true;               /* clean end of the entry region */
    }
    const uint8_t *p = b->data + off;
    const uint8_t *limit = b->data + b->restart_off;
    uint32_t shared = 0, non_shared = 0, value_len = 0;
    if (!ldb_get_varint32(&p, limit, &shared) ||
        !ldb_get_varint32(&p, limit, &non_shared) ||
        !ldb_get_varint32(&p, limit, &value_len))
        return false;
    if ((size_t)(limit - p) < (size_t)non_shared + (size_t)value_len)
        return false;
    if (shared > it->key_len)
        return false;              /* claims more prefix than we hold */
    if (!key_reserve(it, (size_t)shared + non_shared + 1))
        return false;
    if (non_shared)
        memcpy(it->key + shared, p, non_shared);
    it->key_len = (size_t)shared + non_shared;
    p += non_shared;
    it->value.p = p;
    it->value.n = value_len;
    p += value_len;
    it->cur = off;
    it->next_off = (size_t)(p - b->data);
    it->valid = true;
    return true;
}

bool ldb_block_iter_init(struct ldb_block_iter *it, const struct ldb_block *b)
{
    memset(it, 0, sizeof(*it));
    it->b = b;
    it->cur = 0;
    it->next_off = 0;
    return b->num_restarts > 0;
}

void ldb_block_iter_free(struct ldb_block_iter *it)
{
    if (!it)
        return;
    free(it->key);
    it->key = NULL;
    it->key_cap = 0;
    it->key_len = 0;
    it->valid = false;
}

static void seek_to_restart(struct ldb_block_iter *it, uint32_t restart_index)
{
    it->key_len = 0;
    it->valid = false;
    if (restart_index >= it->b->num_restarts) {
        it->corrupt = true;
        return;
    }
    uint32_t off = block_restart_point(it->b, restart_index);
    if ((size_t)off > it->b->restart_off) {
        it->corrupt = true;
        return;
    }
    it->next_off = off;
}

void ldb_block_iter_next(struct ldb_block_iter *it)
{
    if (it->corrupt) {
        it->valid = false;
        return;
    }
    if (!parse_entry(it, it->next_off)) {
        it->corrupt = true;
        it->valid = false;
    }
}

void ldb_block_iter_seek_first(struct ldb_block_iter *it)
{
    if (it->b->num_restarts == 0) {
        it->valid = false;
        return;
    }
    seek_to_restart(it, 0);
    ldb_block_iter_next(it);
}

void ldb_block_iter_seek(struct ldb_block_iter *it, const uint8_t *target,
                         size_t tlen)
{
    if (it->b->num_restarts == 0) {
        it->valid = false;
        return;
    }
    /* Binary search for the last restart point whose key is < target. */
    uint32_t left = 0, right = it->b->num_restarts - 1;
    while (left < right) {
        uint32_t mid = (left + right + 1) / 2;
        uint32_t region = block_restart_point(it->b, mid);
        if ((size_t)region >= it->b->restart_off) {
            it->corrupt = true;
            it->valid = false;
            return;
        }
        const uint8_t *p = it->b->data + region;
        const uint8_t *limit = it->b->data + it->b->restart_off;
        uint32_t shared = 0, non_shared = 0, value_len = 0;
        if (!ldb_get_varint32(&p, limit, &shared) ||
            !ldb_get_varint32(&p, limit, &non_shared) ||
            !ldb_get_varint32(&p, limit, &value_len) || shared != 0 ||
            (size_t)(limit - p) < (size_t)non_shared) {
            it->corrupt = true;
            it->valid = false;
            return;
        }
        if (ldb_ikey_cmp(p, non_shared, target, tlen) < 0)
            left = mid;
        else
            right = mid - 1;
    }

    seek_to_restart(it, left);
    for (;;) {
        ldb_block_iter_next(it);
        if (!it->valid || it->corrupt)
            return;
        if (ldb_ikey_cmp(it->key, it->key_len, target, tlen) >= 0)
            return;
    }
}

/* ── log-record framing (MANIFEST and the write-ahead log) ──────────── */

bool ldb_log_reader_init(struct ldb_log_reader *r, const uint8_t *base,
                         size_t size, bool verify)
{
    memset(r, 0, sizeof(*r));
    r->base = base;
    r->size = size;
    r->verify = verify;
    return true;
}

void ldb_log_reader_free(struct ldb_log_reader *r)
{
    if (!r)
        return;
    free(r->scratch);
    r->scratch = NULL;
    r->scratch_cap = 0;
    free(r->err);
    r->err = NULL;
}

static bool scratch_append(struct ldb_log_reader *r, const uint8_t *p, size_t n)
{
    size_t want = r->scratch_len + n;
    if (want > r->scratch_cap) {
        size_t cap = r->scratch_cap ? r->scratch_cap : 4096;
        while (cap < want)
            cap *= 2;
        uint8_t *ns = zcl_realloc(r->scratch, cap, "ldb_log_scratch");
        if (!ns)
            return false;
        r->scratch = ns;
        r->scratch_cap = cap;
    }
    memcpy(r->scratch + r->scratch_len, p, n);
    r->scratch_len = want;
    return true;
}

/* Reads one physical record. Returns 0 on success, 1 on clean end of file
 * (including a truncated tail, which LevelDB also drops), -1 on a checksum
 * or framing failure with r->err set. */
static int read_physical(struct ldb_log_reader *r, struct ldb_slice *out,
                         uint8_t *type)
{
    for (;;) {
        size_t in_block = r->pos % LDB_LOG_BLOCK_SIZE;
        size_t left_in_block = LDB_LOG_BLOCK_SIZE - in_block;
        if (left_in_block < LDB_LOG_HEADER_SIZE) {
            r->pos += left_in_block;      /* block trailer padding */
            continue;
        }
        if (r->pos + LDB_LOG_HEADER_SIZE > r->size)
            return 1;                     /* torn tail */

        const uint8_t *hdr = r->base + r->pos;
        uint32_t stored_crc = ldb_fixed32(hdr);
        uint32_t length = (uint32_t)hdr[4] | ((uint32_t)hdr[5] << 8);
        uint8_t t = hdr[6];

        if (t == LDB_REC_ZERO && length == 0) {
            /* Preallocated-but-unwritten region: skip the rest of the
             * block the way LevelDB's reader does. */
            r->pos += left_in_block;
            if (r->pos >= r->size)
                return 1;
            continue;
        }
        if (r->pos + LDB_LOG_HEADER_SIZE + length > r->size)
            return 1;                     /* writer died mid-record */
        if (length > left_in_block - LDB_LOG_HEADER_SIZE) {
            r->err = ldb_errf("ldb log: record length %u overruns block at "
                              "offset %zu", length, r->pos);
            return -1;
        }

        const uint8_t *payload = hdr + LDB_LOG_HEADER_SIZE;
        if (r->verify) {
            uint32_t want = ldb_unmask_crc(stored_crc);
            uint32_t got = zcl_crc32c(hdr + 6, (size_t)length + 1);
            if (want != got) {
                r->err = ldb_errf("ldb log: crc32c mismatch at offset %zu "
                                  "(want %08x got %08x)", r->pos, want, got);
                return -1;
            }
        }
        if (t != LDB_REC_FULL && t != LDB_REC_FIRST && t != LDB_REC_MIDDLE &&
            t != LDB_REC_LAST) {
            r->err = ldb_errf("ldb log: unknown record type %u at offset %zu",
                              (unsigned)t, r->pos);
            return -1;
        }
        r->pos += LDB_LOG_HEADER_SIZE + length;
        out->p = payload;
        out->n = length;
        *type = t;
        return 0;
    }
}

bool ldb_log_reader_next(struct ldb_log_reader *r, struct ldb_slice *rec)
{
    if (r->err)
        return false;
    r->scratch_len = 0;
    bool in_fragment = false;

    for (;;) {
        struct ldb_slice frag;
        uint8_t type = 0;
        int rc = read_physical(r, &frag, &type);
        if (rc < 0)
            return false;
        if (rc > 0) {
            if (in_fragment) {
                /* A record that begins but never finishes is a torn tail,
                 * not corruption — LevelDB drops it too. */
                return false;
            }
            return false;
        }
        if (type == LDB_REC_FULL) {
            if (in_fragment) {
                r->err = ldb_strdup("ldb log: FULL record inside a fragment");
                return false;
            }
            *rec = frag;
            return true;
        }
        if (type == LDB_REC_FIRST) {
            if (in_fragment) {
                r->err = ldb_strdup("ldb log: FIRST record inside a fragment");
                return false;
            }
            r->scratch_len = 0;
            if (!scratch_append(r, frag.p, frag.n)) {
                r->err = ldb_strdup("ldb log: out of memory");
                return false;
            }
            in_fragment = true;
            continue;
        }
        if (!in_fragment) {
            r->err = ldb_errf("ldb log: %s fragment with no FIRST",
                              type == LDB_REC_LAST ? "LAST" : "MIDDLE");
            return false;
        }
        if (!scratch_append(r, frag.p, frag.n)) {
            r->err = ldb_strdup("ldb log: out of memory");
            return false;
        }
        if (type == LDB_REC_LAST) {
            rec->p = r->scratch;
            rec->n = r->scratch_len;
            return true;
        }
    }
}

/* Does this directory hold anything that says "a LevelDB lived here"? Used
 * only to tell a fresh empty datadir apart from one that lost its CURRENT.
 * A read failure answers true: unreadable is not evidence of emptiness, and
 * for a storage reader the safe direction is to refuse. */
bool ldb_dir_holds_database_files(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d)
        return true;
    bool found = false;
    const struct dirent *e;
    while (!found && (e = readdir(d)) != NULL) {
        const char *n = e->d_name;
        size_t len = strlen(n);
        if (strncmp(n, "MANIFEST-", 9) == 0)
            found = true;
        else if (len > 4 && (strcmp(n + len - 4, ".ldb") == 0 ||
                             strcmp(n + len - 4, ".sst") == 0 ||
                             strcmp(n + len - 4, ".log") == 0))
            found = true;
    }
    closedir(d);
    return found;
}
