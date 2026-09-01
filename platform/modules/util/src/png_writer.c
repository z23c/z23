/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Minimal PNG encoder in pure C23. No external dependencies.
 * Implements CRC32, Adler32, and DEFLATE (stored blocks) natively.
 * Produces valid PNG files per ISO/IEC 15948 / RFC 2083. */

#include "util/png_writer.h"

#include "base/serialize_le.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util/safe_alloc.h"

/* ── CRC32 (PNG uses ISO 3309 / ITU-T V.42 polynomial) ─────── */

static uint32_t crc32_table[256];
static bool crc32_initialized = false;

static void crc32_init(void)
{
    for (uint32_t n = 0; n < 256; n++) {
        uint32_t c = n;
        for (int k = 0; k < 8; k++) {
            if (c & 1)
                c = 0xEDB88320U ^ (c >> 1);
            else
                c >>= 1;
        }
        crc32_table[n] = c;
    }
    crc32_initialized = true;
}

static uint32_t crc32_update(uint32_t crc, const uint8_t *data, size_t len)
{
    if (!crc32_initialized) crc32_init();
    crc ^= 0xFFFFFFFFU;
    for (size_t i = 0; i < len; i++)
        crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFU;
}

/* ── Adler32 (used inside zlib wrapper for DEFLATE stream) ──── */

static uint32_t adler32(const uint8_t *data, size_t len)
{
    uint32_t a = 1, b = 0;
    for (size_t i = 0; i < len; i++) {
        a = (a + data[i]) % 65521;
        b = (b + a) % 65521;
    }
    return (b << 16) | a;
}

/* ── PNG chunk writer ───────────────────────────────────────── */

static bool write_chunk(FILE *f, const char type[4],
                        const uint8_t *data, uint32_t len)
{
    uint8_t hdr[4];
    zcl_write_u32_be(hdr, len);
    if (fwrite(hdr, 1, 4, f) != 4) return false;
    if (fwrite(type, 1, 4, f) != 4) return false;

    uint32_t crc = crc32_update(0, (const uint8_t *)type, 4);
    if (len > 0) {
        if (fwrite(data, 1, len, f) != len) return false;
        crc = crc32_update(crc, data, len);
    }

    uint8_t crc_buf[4];
    zcl_write_u32_be(crc_buf, crc);
    if (fwrite(crc_buf, 1, 4, f) != 4) return false;
    return true;
}

/* ── DEFLATE stored blocks inside zlib wrapper ──────────────── */

/* Build the raw filtered scanline data (filter byte 0 = None per row),
 * then wrap in zlib format with stored DEFLATE blocks (type 00).
 *
 * zlib format: [CMF][FLG] [DEFLATE blocks...] [Adler32]
 * Stored block: [BFINAL|BTYPE=00] [LEN_LE16] [NLEN_LE16] [data...]
 * Max stored block payload: 65535 bytes. */

static uint8_t *build_idat(const uint8_t *pixels, uint32_t w, uint32_t h,
                            size_t *out_len)
{
    /* Filtered data: each row = 1 filter byte (0x00) + w*3 pixel bytes */
    size_t row_bytes = (size_t)w * 3;
    size_t filtered_len = (size_t)h * (1 + row_bytes);

    uint8_t *filtered = zcl_malloc(filtered_len, "png_filtered");
    if (!filtered) return NULL;

    for (uint32_t y = 0; y < h; y++) {
        filtered[y * (1 + row_bytes)] = 0x00; /* filter: None */
        memcpy(&filtered[y * (1 + row_bytes) + 1],
               &pixels[y * row_bytes], row_bytes);
    }

    /* Compute Adler32 of the filtered data */
    uint32_t adler = adler32(filtered, filtered_len);

    /* Count stored blocks needed (max 65535 bytes per block) */
    size_t max_block = 65535;
    size_t num_blocks = (filtered_len + max_block - 1) / max_block;
    if (num_blocks == 0) num_blocks = 1;

    /* Total IDAT size: 2 (zlib header) + blocks + 4 (adler32)
     * Each block: 1 (bfinal/btype) + 2 (len) + 2 (nlen) + payload */
    size_t idat_len = 2 + num_blocks * 5 + filtered_len + 4;
    uint8_t *idat = zcl_malloc(idat_len, "png_idat");
    if (!idat) { free(filtered); return NULL; }

    size_t pos = 0;

    /* zlib header: CMF=0x78 (deflate, window=32768), FLG=0x01 (no dict, level 0)
     * CMF*256+FLG must be divisible by 31: 0x78*256+0x01 = 30721, 30721%31=0 */
    idat[pos++] = 0x78;
    idat[pos++] = 0x01;

    /* Stored DEFLATE blocks */
    size_t remaining = filtered_len;
    size_t src_pos = 0;
    for (size_t blk = 0; blk < num_blocks; blk++) {
        size_t payload = remaining;
        if (payload > max_block) payload = max_block;
        bool is_final = (blk == num_blocks - 1);

        idat[pos++] = is_final ? 0x01 : 0x00; /* BFINAL | BTYPE=00 */
        zcl_write_u16_le(&idat[pos], (uint16_t)payload); pos += 2;
        zcl_write_u16_le(&idat[pos], (uint16_t)(~payload & 0xFFFF)); pos += 2;

        memcpy(&idat[pos], &filtered[src_pos], payload);
        pos += payload;
        src_pos += payload;
        remaining -= payload;
    }

    /* Adler32 checksum (big-endian) */
    zcl_write_u32_be(&idat[pos], adler);
    pos += 4;

    free(filtered);
    *out_len = pos;
    return idat;
}

/* ── Public API ─────────────────────────────────────────────── */

bool png_write_rgb(const char *path, const uint8_t *pixels,
                   uint32_t width, uint32_t height)
{
    if (!path || !pixels || width == 0 || height == 0)
        return false;

    FILE *f = fopen(path, "wb");
    if (!f) return false;

    /* PNG signature */
    static const uint8_t sig[8] = {137,80,78,71,13,10,26,10};
    if (fwrite(sig, 1, 8, f) != 8) { fclose(f); return false; }

    /* IHDR: width, height, bit_depth=8, color_type=2 (RGB),
     * compression=0, filter=0, interlace=0 */
    uint8_t ihdr[13];
    zcl_write_u32_be(&ihdr[0], width);
    zcl_write_u32_be(&ihdr[4], height);
    ihdr[8] = 8;   /* bit depth */
    ihdr[9] = 2;   /* color type: RGB */
    ihdr[10] = 0;  /* compression */
    ihdr[11] = 0;  /* filter */
    ihdr[12] = 0;  /* interlace */
    if (!write_chunk(f, "IHDR", ihdr, 13)) { fclose(f); return false; }

    /* IDAT: compressed image data */
    size_t idat_len = 0;
    uint8_t *idat = build_idat(pixels, width, height, &idat_len);
    if (!idat) { fclose(f); return false; }
    bool ok = write_chunk(f, "IDAT", idat, (uint32_t)idat_len);
    free(idat);
    if (!ok) { fclose(f); return false; }

    /* IEND */
    if (!write_chunk(f, "IEND", NULL, 0)) { fclose(f); return false; }

    fclose(f);
    return true;
}
