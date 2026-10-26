/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Raw blk-file scanner and Sapling decrypt workers for legacy wallet import. */

#include "legacy_import_scan.h"

#include "core/serialize.h"
#include "platform/read_mapping.h"
#include "util/safe_alloc.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const uint8_t ZCL_MAGIC[4] = {0x24, 0xe9, 0x27, 0x64};
#define SAPLING_ACTIVATION_HEIGHT 476969

static int extract_bip34_height(const struct transaction *coinbase)
{
    if (coinbase->num_vin == 0) return -1; // raw-return-ok:bin-parser-empty-vin
    const uint8_t *sig = coinbase->vin[0].script_sig.data;
    size_t sig_len = coinbase->vin[0].script_sig.size;
    if (sig_len < 1) return -1; // raw-return-ok:bin-parser-bounds

    uint8_t nbytes = sig[0];

    if (nbytes == 0x00) return 0;
    if (nbytes >= 0x51 && nbytes <= 0x60)
        return nbytes - 0x50;

    if (nbytes > 8 || (size_t)nbytes + 1 > sig_len) return -1; // raw-return-ok:bin-parser-bounds
    int64_t h = 0;
    for (uint8_t i = 0; i < nbytes; i++)
        h |= (int64_t)sig[1 + i] << (8 * i);
    if (sig[nbytes] & 0x80)
        h = -(h & ~((int64_t)0x80 << (8 * (nbytes - 1))));
    return (int)h;
}

static bool scan_file_raw(const uint8_t *data, size_t size,
                          const struct scan_addr_ht *ht)
{
    for (size_t i = 0; i + 25 <= size; i++) {
        if (data[i] == 0x76 && data[i + 1] == 0xa9 &&
            data[i + 2] == 0x14 &&
            data[i + 23] == 0x88 && data[i + 24] == 0xac) {
            if (scan_aht_has(ht, data + i + 3)) return true;
        }
        if (data[i] == 0xa9 && data[i + 1] == 0x14 &&
            i + 23 <= size && data[i + 22] == 0x87) {
            if (scan_aht_has(ht, data + i + 2)) return true;
        }
    }
    return false;
}

void *legacy_import_scan_file_thread(void *arg)
{
    struct legacy_import_scan_file_arg *a =
        (struct legacy_import_scan_file_arg *)arg;
    char path[512];
    snprintf(path, sizeof(path), "%s/blocks/blk%05d.dat",
             a->datadir, a->file_num);
    int fd = open(path, O_RDONLY);
    if (fd < 0) { a->result = false; return NULL; }
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); a->result = false; return NULL; }
    if (st.st_size <= 0 || (uintmax_t)st.st_size > SIZE_MAX) {
        close(fd);
        a->result = false;
        return NULL;
    }
    size_t sz = (size_t)st.st_size;
    struct platform_read_mapping mapping;
    platform_read_mapping_init(&mapping);
    if (!platform_read_mapping_open(&mapping, fd, sz)) {
        close(fd);
        a->result = false;
        return NULL;
    }
    a->result = scan_file_raw(mapping.data, mapping.size, a->ht);
    platform_read_mapping_close(&mapping);
    close(fd);
    return NULL;
}

int legacy_import_walk_block_file(const uint8_t *fdata,
                                  size_t fsize,
                                  legacy_import_block_visitor_fn visitor,
                                  void *ctx)
{
    int blocks = 0;
    size_t pos = 0;

    while (pos + 8 <= fsize) {
        if (memcmp(fdata + pos, ZCL_MAGIC, 4) != 0) {
            pos++;
            continue;
        }
        uint32_t blk_size;
        memcpy(&blk_size, fdata + pos + 4, 4);
        if (blk_size == 0 || blk_size > 4000000 ||
            pos + 8 + blk_size > fsize) {
            pos++;
            continue;
        }

        struct block blk;
        block_init(&blk);
        struct byte_stream bs;
        stream_init_from_data(&bs, fdata + pos + 8, blk_size);
        if (!block_deserialize(&blk, &bs)) {
            block_free(&blk);
            pos += 8 + blk_size;
            continue;
        }

        int height = -1;
        if (blk.num_vtx > 0)
            height = extract_bip34_height(&blk.vtx[0]);

        blocks++;
        visitor(&blk, height, ctx);
        block_free(&blk);
        pos += 8 + blk_size;
    }
    return blocks;
}

static int read_compact_size_raw(const uint8_t *d, size_t avail, uint64_t *out)
{
    if (avail < 1) return 0;
    if (d[0] < 0xfd) { *out = d[0]; return 1; }
    if (d[0] == 0xfd && avail >= 3) {
        *out = (uint64_t)d[1] | ((uint64_t)d[2] << 8);
        return 3;
    }
    if (d[0] == 0xfe && avail >= 5) {
        uint32_t v; memcpy(&v, d + 1, 4); *out = v;
        return 5;
    }
    if (d[0] == 0xff && avail >= 9) {
        memcpy(out, d + 1, 8);
        return 9;
    }
    return 0;
}

/* Skips the block solution and leaves *pos at the first transaction.
 * Returns -1 on malformed data, 0 on success. */
static int locate_block_tx_list_raw(const uint8_t *bdata, size_t bsize,
                                    size_t *pos)
{
    uint64_t sol_size;
    int n = read_compact_size_raw(bdata + *pos, bsize - *pos, &sol_size);
    if (n == 0 || sol_size > 4096) return -1; // raw-return-ok:bin-parser-bounds
    *pos += (size_t)n + (size_t)sol_size;

    if (*pos >= bsize) return -1; // raw-return-ok:bin-parser-bounds
    uint64_t num_tx;
    n = read_compact_size_raw(bdata + *pos, bsize - *pos, &num_tx);
    if (n == 0 || num_tx == 0) return -1; // raw-return-ok:bin-parser-bounds
    *pos += (size_t)n;
    return 0;
}

/* Walks the coinbase transaction prologue and leaves *pos at its scriptSig,
 * reporting the script length via *script_len. Returns -1 on malformed data. */
static int locate_coinbase_scriptsig_raw(const uint8_t *bdata, size_t bsize,
                                         size_t *pos, uint64_t *script_len)
{
    if (*pos + 4 > bsize) return -1; // raw-return-ok:bin-parser-bounds
    int32_t tx_ver;
    memcpy(&tx_ver, bdata + *pos, 4);
    *pos += 4;
    if (tx_ver & (int32_t)0x80000000) *pos += 4;

    if (*pos >= bsize) return -1; // raw-return-ok:bin-parser-bounds
    uint64_t vin_count;
    int n = read_compact_size_raw(bdata + *pos, bsize - *pos, &vin_count);
    if (n == 0 || vin_count == 0) return -1; // raw-return-ok:bin-parser-empty-vin
    *pos += (size_t)n;

    *pos += 36;
    if (*pos >= bsize) return -1; // raw-return-ok:bin-parser-bounds
    n = read_compact_size_raw(bdata + *pos, bsize - *pos, script_len);
    if (n == 0) return -1; // raw-return-ok:bin-parser-bounds
    *pos += (size_t)n;
    if (*pos + *script_len > bsize || *script_len == 0) return -1; // raw-return-ok:bin-parser-bounds
    return 0;
}

static int extract_height_raw(const uint8_t *bdata, size_t bsize)
{
    if (bsize < 141) return -1; // raw-return-ok:bin-parser-bounds
    size_t pos = 140;
    if (locate_block_tx_list_raw(bdata, bsize, &pos) != 0) return -1;
    uint64_t script_len;
    if (locate_coinbase_scriptsig_raw(bdata, bsize, &pos, &script_len) != 0)
        return -1;

    const uint8_t *sig = bdata + pos;
    uint8_t nbytes = sig[0];
    if (nbytes == 0x00) return 0;
    if (nbytes >= 0x51 && nbytes <= 0x60) return nbytes - 0x50;
    if (nbytes > 8 || (size_t)nbytes + 1 > script_len) return -1; // raw-return-ok:bin-parser-bounds
    int64_t h = 0;
    for (uint8_t i = 0; i < nbytes; i++)
        h |= (int64_t)sig[1 + i] << (8 * i);
    if (sig[nbytes] & 0x80)
        h = -(h & ~((int64_t)0x80 << (8 * (nbytes - 1))));
    return (int)h;
}

/* Reads a transaction version header, tracking the overwinter flag and
 * version-group id. Returns -1 on malformed data, 0 on success. */
static int parse_tx_header_raw(const uint8_t *bdata, size_t bsize, size_t *pos,
                               bool *overwintered, int32_t *ver,
                               uint32_t *vg_id)
{
    if (*pos + 4 > bsize) return -1; // raw-return-ok:bin-parser-bounds
    int32_t tx_ver;
    memcpy(&tx_ver, bdata + *pos, 4);
    *pos += 4;
    *overwintered = (tx_ver & (int32_t)0x80000000) != 0;
    *ver = tx_ver & 0x7FFFFFFF;
    *vg_id = 0;
    if (*overwintered) {
        if (*pos + 4 > bsize) return -1; // raw-return-ok:bin-parser-bounds
        memcpy(vg_id, bdata + *pos, 4);
        *pos += 4;
    }
    return 0;
}

/* Skips the transparent vin and vout lists of one transaction.
 * Returns -1 on malformed data, 0 on success. */
static int skip_tx_vin_vout_raw(const uint8_t *bdata, size_t bsize, size_t *pos)
{
    uint64_t vin_count;
    int n = read_compact_size_raw(bdata + *pos, bsize - *pos, &vin_count);
    if (n == 0) return -1; // raw-return-ok:bin-parser-bounds
    *pos += (size_t)n;
    for (uint64_t vi = 0; vi < vin_count; vi++) {
        *pos += 36;
        if (*pos >= bsize) return -1; // raw-return-ok:bin-parser-bounds
        uint64_t script_len;
        n = read_compact_size_raw(bdata + *pos, bsize - *pos, &script_len);
        if (n == 0) return -1; // raw-return-ok:bin-parser-bounds
        *pos += (size_t)n + (size_t)script_len + 4;
    }

    if (*pos >= bsize) return -1; // raw-return-ok:bin-parser-bounds
    uint64_t vout_count;
    n = read_compact_size_raw(bdata + *pos, bsize - *pos, &vout_count);
    if (n == 0) return -1; // raw-return-ok:bin-parser-bounds
    *pos += (size_t)n;
    for (uint64_t vo = 0; vo < vout_count; vo++) {
        *pos += 8;
        if (*pos >= bsize) return -1; // raw-return-ok:bin-parser-bounds
        uint64_t script_len;
        n = read_compact_size_raw(bdata + *pos, bsize - *pos, &script_len);
        if (n == 0) return -1; // raw-return-ok:bin-parser-bounds
        *pos += (size_t)n + (size_t)script_len;
    }
    return 0;
}

/* Skips the locktime and, when overwintered, the expiry height.
 * Returns -1 on malformed data, 0 on success. */
static int skip_tx_locktime_raw(size_t bsize, size_t *pos, bool overwintered)
{
    if (*pos + 4 > bsize) return -1; // raw-return-ok:bin-parser-bounds
    *pos += 4;
    if (overwintered) {
        if (*pos + 4 > bsize) return -1; // raw-return-ok:bin-parser-bounds
        *pos += 4;
    }
    return 0;
}

/* Scans a Sapling bundle: value balance, spends, then outputs.
 * Returns -1 on malformed data, 1 when the bundle has at least one output,
 * 0 otherwise. */
static int scan_sapling_bundle_raw(const uint8_t *bdata, size_t bsize,
                                   size_t *pos)
{
    if (*pos + 8 > bsize) return -1; // raw-return-ok:bin-parser-bounds
    *pos += 8;

    if (*pos >= bsize) return -1; // raw-return-ok:bin-parser-bounds
    uint64_t num_spend;
    int n = read_compact_size_raw(bdata + *pos, bsize - *pos, &num_spend);
    if (n == 0) return -1; // raw-return-ok:bin-parser-bounds
    *pos += (size_t)n;
    *pos += (size_t)num_spend * 384;

    if (*pos >= bsize) return -1; // raw-return-ok:bin-parser-bounds
    uint64_t num_output;
    n = read_compact_size_raw(bdata + *pos, bsize - *pos, &num_output);
    if (n == 0) return -1; // raw-return-ok:bin-parser-bounds
    *pos += (size_t)n;
    if (num_output > 0) return 1;
    *pos += (size_t)num_output * 948;
    return 0;
}

/* Skips the JoinSplit list of a v2+ pre-Sapling transaction.
 * Returns -1 on malformed data, 0 on success. */
static int skip_joinsplit_section_raw(const uint8_t *bdata, size_t bsize,
                                      size_t *pos, bool overwintered,
                                      uint32_t vg_id)
{
    if (*pos >= bsize) return -1; // raw-return-ok:bin-parser-bounds
    uint64_t num_js;
    int n = read_compact_size_raw(bdata + *pos, bsize - *pos, &num_js);
    if (n == 0) return -1; // raw-return-ok:bin-parser-bounds
    *pos += (size_t)n;
    if (num_js > 0) {
        size_t js_size = (overwintered && vg_id == 0x892F2085) ?
                          1698 : 1802;
        *pos += (size_t)num_js * js_size;
        *pos += 32 + 64;
    }
    return 0;
}

/* Walks one transaction, leaving *pos at the start of the next one.
 * Returns -1 on malformed data, 1 when a shielded element is present,
 * 0 otherwise. */
static int scan_tx_shielded_raw(const uint8_t *bdata, size_t bsize, size_t *pos)
{
    bool overwintered;
    int32_t ver;
    uint32_t vg_id;
    if (parse_tx_header_raw(bdata, bsize, pos, &overwintered, &ver,
                            &vg_id) != 0)
        return -1;
    if (skip_tx_vin_vout_raw(bdata, bsize, pos) != 0)
        return -1;
    if (skip_tx_locktime_raw(bsize, pos, overwintered) != 0) return -1;

    if (overwintered && vg_id == 0x892F2085) {
        int shielded = scan_sapling_bundle_raw(bdata, bsize, pos);
        if (shielded != 0) return shielded;
    }

    if (ver >= 2 && (!overwintered || ver < 5)) {
        if (skip_joinsplit_section_raw(bdata, bsize, pos, overwintered,
                                       vg_id) != 0)
            return -1;
    }
    return 0;
}

static bool block_has_shielded_raw(const uint8_t *bdata, size_t bsize)
{
    if (bsize < 141) return false;
    size_t pos = 140;
    uint64_t sol_size;
    int n = read_compact_size_raw(bdata + pos, bsize - pos, &sol_size);
    if (n == 0) return false;
    pos += (size_t)n + (size_t)sol_size;

    if (pos >= bsize) return false;
    uint64_t num_tx;
    n = read_compact_size_raw(bdata + pos, bsize - pos, &num_tx);
    if (n == 0 || num_tx == 0 || num_tx > 50000) return false;
    pos += (size_t)n;

    for (uint64_t ti = 0; ti < num_tx; ti++) {
        int shielded = scan_tx_shielded_raw(bdata, bsize, &pos);
        if (shielded != 0) return shielded > 0;
    }
    return false;
}

/* Opens a blk dat file and read-maps its whole contents. On success returns
 * the fd and sets *fsize; the caller closes the fd and the mapping. */
static int open_mapped_block_file(const char *datadir, int file_num,
                                  struct platform_read_mapping *mapping,
                                  size_t *fsize)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/blocks/blk%05d.dat",
             datadir, file_num);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return -1; }
    if (st.st_size <= 0 || (uintmax_t)st.st_size > SIZE_MAX) {
        close(fd);
        return -1;
    }
    *fsize = (size_t)st.st_size;
    platform_read_mapping_init(mapping);
    if (!platform_read_mapping_open(mapping, fd, *fsize)) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Doubles the filter hit buffer. Returns -1 (cap restored) on OOM,
 * 0 on success. */
static int grow_filter_hits(struct legacy_import_filter_file_ctx *ctx)
{
    ctx->hit_cap *= 2;
    struct legacy_import_block_pos *tmp = zcl_realloc(ctx->hits,
        (size_t)ctx->hit_cap * sizeof(struct legacy_import_block_pos),
        "legacy scan hits grow");
    if (!tmp) {
        /* OOM: keep the old buffer (zcl_realloc leaves it intact),
         * restore the cap to match it, skip this hit and keep scanning. */
        ctx->hit_cap /= 2;
        return -1;
    }
    ctx->hits = tmp;
    return 0;
}

/* Extracts the block height (tallying failures in ctx), applies the Sapling
 * activation and shielded-content gates. Returns 1 when the block must be
 * recorded, 0 when it must be skipped. */
static int check_sapling_filter_gate(struct legacy_import_filter_file_ctx *ctx,
                                     const uint8_t *fdata, size_t pos,
                                     uint32_t blk_size, int *height)
{
    *height = extract_height_raw(fdata + pos + 8, blk_size);
    if (*height < 0) ctx->height_failed++;
    if (*height >= 0 && *height < SAPLING_ACTIVATION_HEIGHT) return 0;
    return block_has_shielded_raw(fdata + pos + 8, blk_size);
}

void *legacy_import_sapling_filter_thread(void *arg)
{
    struct legacy_import_filter_file_ctx *ctx =
        (struct legacy_import_filter_file_ctx *)arg;
    size_t fsize;
    struct platform_read_mapping mapping;
    int fd = open_mapped_block_file(ctx->datadir, ctx->file_num, &mapping,
                                    &fsize);
    if (fd < 0) return NULL;
    const uint8_t *fdata = mapping.data;

    ctx->hit_cap = 256;
    ctx->hits = zcl_malloc((size_t)ctx->hit_cap *
                           sizeof(struct legacy_import_block_pos),
                           "legacy scan hits");
    if (!ctx->hits) {
        /* zcl_malloc already logged the OOM; unmap the block file and abort
         * the scan thread rather than writing through NULL at the hit append. */
        platform_read_mapping_close(&mapping);
        close(fd);
        return NULL;
    }

    size_t pos = 0;
    while (pos + 8 <= fsize) {
        if (memcmp(fdata + pos, ZCL_MAGIC, 4) != 0) { pos++; continue; }
        uint32_t blk_size;
        memcpy(&blk_size, fdata + pos + 4, 4);
        if (blk_size == 0 || blk_size > 4000000 ||
            pos + 8 + blk_size > fsize) { pos++; continue; }
        ctx->blocks_total++;

        int height;
        if (check_sapling_filter_gate(ctx, fdata, pos, blk_size,
                                      &height) == 0) {
            pos += 8 + blk_size;
            continue;
        }

        if (ctx->hit_count >= ctx->hit_cap) {
            if (grow_filter_hits(ctx) != 0) {
                pos += 8 + blk_size;
                continue;
            }
        }
        ctx->hits[ctx->hit_count++] = (struct legacy_import_block_pos){
            .file_num = ctx->file_num,
            .offset = pos,
            .blk_size = blk_size,
            .height = height,
        };
        ctx->blocks_passed++;
        pos += 8 + blk_size;
    }
    platform_read_mapping_close(&mapping);
    close(fd);
    return NULL;
}

/* Stores every wallet note whose txid matches the decrypted one, growing the
 * results buffer when needed. */
static void store_notes_matching_txid(struct legacy_import_decrypt_file_ctx *c,
                                      const struct uint256 *txid, int height)
{
    for (size_t ni = 0; ni < c->tw.num_sapling_notes; ni++) {
        struct sapling_received_note *note = &c->tw.sapling_notes[ni];
        if (!note->used) continue;
        if (memcmp(note->txid.data, txid->data, 32) != 0)
            continue;
        if (c->result_count >= c->result_cap) {
            c->result_cap *= 2;
            struct db_sapling_note *tmp = zcl_realloc(
                c->results,
                (size_t)c->result_cap * sizeof(struct db_sapling_note),
                "sapling decrypt results grow");
            if (!tmp) {
                /* OOM: keep the old buffer (zcl_realloc does
                 * not free on failure) and skip appending this
                 * note rather than NULL-deref. Partial results
                 * are tolerated by the caller. */
                c->result_cap /= 2;
                continue;
            }
            c->results = tmp;
        }
        struct db_sapling_note *dn = &c->results[c->result_count++];
        memset(dn, 0, sizeof(*dn));
        memcpy(dn->txid, note->txid.data, 32);
        dn->output_index = note->output_index;
        dn->value = (int64_t)note->value;
        memcpy(dn->rcm, note->rcm, 32);
        memcpy(dn->memo, note->memo, 512);
        dn->memo_len = 512;
        memcpy(dn->ivk, note->ivk, 32);
        memcpy(dn->diversifier, note->diversifier, 11);
        memcpy(dn->pk_d, note->pk_d, 32);
        memcpy(dn->cm, note->cm, 32);
        memcpy(dn->nullifier, note->nf, 32);
        dn->block_height = height;
    }
}

/* Decrypts one transaction's shielded outputs and records matching notes. */
static void decrypt_tx_shielded_outputs(struct legacy_import_decrypt_file_ctx *c,
                                        struct transaction *tx, int height)
{
    if (tx->num_shielded_output == 0) return;
    c->outputs_seen += (int)tx->num_shielded_output;
    struct uint256 txid = tx->hash;
    int n = wallet_try_sapling_decrypt(&c->tw, tx, &txid);
    if (n > 0) {
        c->notes_found += n;
        store_notes_matching_txid(c, &txid, height);
    }
}

void *legacy_import_decrypt_thread(void *arg)
{
    struct legacy_import_decrypt_file_ctx *c =
        (struct legacy_import_decrypt_file_ctx *)arg;
    if (c->count == 0) return NULL;

    size_t fsize;
    struct platform_read_mapping mapping;
    int fd = open_mapped_block_file(c->datadir, c->file_num, &mapping,
                                    &fsize);
    if (fd < 0) return NULL;
    const uint8_t *fdata = mapping.data;

    for (int hi = 0; hi < c->count; hi++) {
        struct legacy_import_block_pos *bp = &c->hits[hi];
        if (bp->offset > fsize || fsize - bp->offset < 8 ||
            (size_t)bp->blk_size > fsize - bp->offset - 8)
            continue;
        const uint8_t *bdata = fdata + bp->offset + 8;
        struct block blk;
        block_init(&blk);
        struct byte_stream bs;
        stream_init_from_data(&bs, bdata, bp->blk_size);
        if (!block_deserialize(&blk, &bs)) {
            block_free(&blk);
            continue;
        }

        int height = bp->height;
        if (height < 0 && blk.num_vtx > 0)
            height = extract_bip34_height(&blk.vtx[0]);

        for (size_t ti = 0; ti < blk.num_vtx; ti++)
            decrypt_tx_shielded_outputs(c, &blk.vtx[ti], height);
        block_free(&blk);
    }
    platform_read_mapping_close(&mapping);
    close(fd);
    return NULL;
}
