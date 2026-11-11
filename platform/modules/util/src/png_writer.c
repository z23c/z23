/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Minimal PNG encoder in pure C23, with optional zlib compression.
 * Implements CRC32, Adler32, and DEFLATE (stored blocks) natively.
 * Produces valid PNG files per ISO/IEC 15948 / RFC 2083. */

#include "util/png_writer.h"

#include "base/serialize_le.h"
#ifdef ZCL_PNG_USE_ZLIB
#include <limits.h>
#include <zlib.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util/safe_alloc.h"

static void png_release_buffer(void *buffer)
{
    free(buffer);
}

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

static uint32_t png_adler32(const uint8_t *data, size_t len)
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

static void encode_chunk(uint8_t **cursor, const char type[4],
                         const uint8_t *data, uint32_t len)
{
    zcl_write_u32_be(*cursor, len);
    *cursor += 4;
    memcpy(*cursor, type, 4u);
    uint32_t crc = crc32_update(0, (const uint8_t *)type, 4u);
    *cursor += 4;
    if (len > 0) {
        memcpy(*cursor, data, len);
        crc = crc32_update(crc, data, len);
        *cursor += len;
    }
    zcl_write_u32_be(*cursor, crc);
    *cursor += 4;
}

/* ── DEFLATE stored blocks inside zlib wrapper ──────────────── */

/* Pre-flight the encoded size before any pixel byte is touched. This is
 * the single overflow authority for both the buffer-encode path
 * (png_encode_channels, which has a caller cap to protect) and the
 * FILE* path (png_write_channels): row_bytes = w * channels,
 * filtered_len = h * (1 + row_bytes), and the stored-block count all
 * grow without bound from caller-supplied dimensions, and on 64-bit the
 * unguarded product wraps size_t. */
static bool png_layout_sizes(uint32_t width, uint32_t height,
                               size_t channels, size_t *idat_len,
                               size_t *png_len)
{
    if (width == 0 || height == 0 ||
        channels == 0 || width > SIZE_MAX / channels)
        return false;
    size_t row_bytes = (size_t)width * channels;
    if (row_bytes == SIZE_MAX || height > SIZE_MAX / (row_bytes + 1u))
        return false;
    size_t filtered_len = (size_t)height * (row_bytes + 1u);
    size_t blocks = filtered_len / 65535u +
                    (filtered_len % 65535u != 0 ? 1u : 0u);
    if (filtered_len > SIZE_MAX - 6u) return false;
    if (blocks > (SIZE_MAX - filtered_len - 6u) / 5u)
        return false;
    size_t idat = 2u + blocks * 5u + filtered_len + 4u;
    if (idat > UINT32_MAX || idat > SIZE_MAX - 57u)
        return false;
    *idat_len = idat;
    *png_len = 57u + idat;
    return true;
}

static bool png_encoded_layout(uint32_t width, uint32_t height,
                               size_t channels, size_t *idat_len,
                               size_t *png_len)
{
    if (idat_len) *idat_len = 0;
    if (png_len) *png_len = 0;
    if (!idat_len || !png_len) return false;
    return png_layout_sizes(width, height, channels, idat_len, png_len);
}

/* Build the raw filtered scanline data (filter byte 0 = None per row),
 * then wrap in zlib format with stored DEFLATE blocks (type 00).
 *
 * zlib format: [CMF][FLG] [DEFLATE blocks...] [Adler32]
 * Stored block: [BFINAL|BTYPE=00] [LEN_LE16] [NLEN_LE16] [data...]
 * Max stored block payload: 65535 bytes. */

/* Copy pixel rows into the filtered buffer, one filter byte (None) per
 * row. Only called after the size authority accepted the dimensions. */
static void png_fill_filtered_rows(uint8_t *filtered,
                                   const uint8_t *pixels, uint32_t h,
                                   size_t row_bytes)
{
    for (uint32_t y = 0; y < h; y++) {
        filtered[y * (1 + row_bytes)] = 0x00; /* filter: None */
        memcpy(&filtered[y * (1 + row_bytes) + 1],
               &pixels[y * row_bytes], row_bytes);
    }
}

/* Emit the zlib header, the stored-DEFLATE blocks over the filtered
 * data, and the Adler32 trailer. Returns false if the emitted length
 * would exceed idat_cap. */
static bool png_emit_stored_idat(uint8_t *idat, size_t idat_cap,
                                 const uint8_t *filtered, size_t filtered_len,
                                 uint32_t adler)
{
    size_t max_block = 65535;
    size_t num_blocks = filtered_len / max_block + (filtered_len % max_block != 0);
    if (num_blocks == 0) num_blocks = 1;
    size_t idat_len = 2 + num_blocks * 5 + filtered_len + 4;
    if (idat_len > idat_cap)
        return false;

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
    return pos == idat_len;
}

#ifdef ZCL_PNG_USE_ZLIB
static uint8_t *png_compress_idat(const uint8_t *filtered, size_t filtered_len,
                                  size_t *out_len)
{
    if (filtered_len > ULONG_MAX) return NULL;
    uLongf cap = compressBound((uLong)filtered_len);
    if (cap > UINT32_MAX || cap > SIZE_MAX) return NULL;
    uint8_t *idat = zcl_malloc((size_t)cap, "png_idat");
    if (!idat) return NULL;
    uLongf len = cap;
    if (compress2(idat, &len, filtered, (uLong)filtered_len, Z_BEST_SPEED) != Z_OK ||
        len > UINT32_MAX) {
        png_release_buffer(idat);
        return NULL;
    }
    *out_len = (size_t)len;
    return idat;
}
#endif

static uint8_t *stored_idat(uint8_t *filtered, size_t filtered_len,
                            bool empty_image, size_t layout_idat, size_t *out_len)
{
    uint32_t adler = png_adler32(filtered, filtered_len);
    size_t max_block = 65535;
    size_t num_blocks = filtered_len / max_block + (filtered_len % max_block != 0);
    if (num_blocks == 0) num_blocks = 1;
    size_t idat_len = 2 + num_blocks * 5 + filtered_len + 4;
    uint8_t *idat = zcl_malloc(idat_len, "png_idat");
    if (!idat) { png_release_buffer(filtered); return NULL; }
    bool emitted = png_emit_stored_idat(idat, idat_len, filtered, filtered_len, adler);
    png_release_buffer(filtered);
    if (!emitted || (!empty_image && idat_len != layout_idat)) {
        png_release_buffer(idat);
        return NULL;
    }
    *out_len = idat_len;
    return idat;
}

static uint8_t *build_idat_channels(const uint8_t *pixels, uint32_t w,
                                    uint32_t h, size_t channels,
                                    size_t *out_len)
{
    if (out_len) *out_len = 0;
    if (!pixels || !out_len || channels == 0)
        return NULL;

    /* Preserve the white-box 0x0 empty-stored-block IDAT. Public entry
     * points reject zero dimensions; every nonempty IDAT uses the shared
     * checked layout before allocation or pixel access. */
    const bool empty_image = (w == 0 && h == 0);
    size_t layout_idat = 0, layout_png = 0;
    if (!empty_image &&
        !png_encoded_layout(w, h, channels, &layout_idat, &layout_png))
        return NULL;

    size_t row_bytes = (size_t)w * channels;
    size_t filtered_len = (size_t)h * (1 + row_bytes);
    uint8_t *filtered = zcl_malloc(filtered_len, "png_filtered");
    if (!filtered) return NULL;
    png_fill_filtered_rows(filtered, pixels, h, row_bytes);

#ifdef ZCL_PNG_USE_ZLIB
    /* A compression failure is not a stored-block success: the caller sees
     * refusal and its buffer is left untouched. */
    if (!empty_image) {
        uint8_t *compressed = png_compress_idat(filtered, filtered_len, out_len);
        png_release_buffer(filtered);
        return compressed;
    }
#endif
    return stored_idat(filtered, filtered_len, empty_image, layout_idat, out_len);
}

static bool png_encode_channels(
    const uint8_t *pixels, uint32_t width, uint32_t height,
    size_t channels, uint8_t color_type,
    uint8_t *output, size_t output_cap, size_t *written)
{
    if (written) *written = 0;
    size_t expected_idat = 0, required = 0;
    if (!pixels || !written ||
        !png_encoded_layout(width, height, channels,
                            &expected_idat, &required))
        return false;
    *written = required;
#ifndef ZCL_PNG_USE_ZLIB
    if (!output) return true;
    if (output_cap < required) return false;
#endif
    size_t idat_len = 0;
    uint8_t *idat = build_idat_channels(
        pixels, width, height, channels, &idat_len);
    if (!idat) {
        *written = 0;
        return false;
    }
#ifdef ZCL_PNG_USE_ZLIB
    if (idat_len > SIZE_MAX - 57u) {
        png_release_buffer(idat);
        *written = 0;
        return false;
    }
    required = 57u + idat_len;
    *written = required;
    if (!output || output_cap < required) {
        png_release_buffer(idat);
        return !output;
    }
#else
    if (idat_len != expected_idat) {
        png_release_buffer(idat);
        *written = 0;
        return false;
    }
#endif
    static const uint8_t signature[8] = {137,80,78,71,13,10,26,10};
    uint8_t *cursor = output;
    memcpy(cursor, signature, sizeof(signature));
    cursor += sizeof(signature);
    uint8_t ihdr[13] = {0};
    zcl_write_u32_be(ihdr, width);
    zcl_write_u32_be(ihdr + 4u, height);
    ihdr[8] = 8u;
    ihdr[9] = color_type;
    encode_chunk(&cursor, "IHDR", ihdr, sizeof(ihdr));
    encode_chunk(&cursor, "IDAT", idat, (uint32_t)idat_len);
    encode_chunk(&cursor, "IEND", NULL, 0u);
    png_release_buffer(idat);
    bool ok = (size_t)(cursor - output) == required;
    if (!ok) *written = 0;
    return ok;
}

/* ── Public API ─────────────────────────────────────────────── */

static bool png_write_channels(const char *path, const uint8_t *pixels,
                               uint32_t width, uint32_t height,
                               size_t channels, uint8_t color_type)
{
    if (!path || !pixels || width == 0 || height == 0)
        return false;

    /* Refuse absurd dimensions (and size overflow) before creating the
     * file, so a refusal never leaves a truncated PNG behind. */
    size_t idat_len = 0;
    uint8_t *idat = build_idat_channels(pixels, width, height, channels,
                                        &idat_len);
    if (!idat) return false;

    FILE *f = fopen(path, "wb");
    if (!f) goto cleanup;

    /* PNG signature */
    static const uint8_t sig[8] = {137,80,78,71,13,10,26,10};
    if (fwrite(sig, 1, 8, f) != 8) goto cleanup;

    /* IHDR: 8-bit packed RGB/RGBA, no interlace. */
    uint8_t ihdr[13];
    zcl_write_u32_be(&ihdr[0], width);
    zcl_write_u32_be(&ihdr[4], height);
    ihdr[8] = 8;   /* bit depth */
    ihdr[9] = color_type;
    ihdr[10] = 0;  /* compression */
    ihdr[11] = 0;  /* filter */
    ihdr[12] = 0;  /* interlace */
    if (!write_chunk(f, "IHDR", ihdr, 13)) goto cleanup;

    /* IDAT: compressed image data */
    bool ok = write_chunk(f, "IDAT", idat, (uint32_t)idat_len);
    if (!ok) goto cleanup;

    /* IEND */
    if (!write_chunk(f, "IEND", NULL, 0)) goto cleanup;

    ok = true;
    goto finish;

cleanup:
    ok = false;
finish:
    png_release_buffer(idat);
    if (f && fclose(f) != 0) ok = false;
    return ok;
}

bool png_write_rgb(const char *path, const uint8_t *pixels,
                   uint32_t width, uint32_t height)
{
    return png_write_channels(path, pixels, width, height, 3u, 2u);
}

bool png_write_rgba(const char *path, const uint8_t *pixels,
                    uint32_t width, uint32_t height)
{
    return png_write_channels(path, pixels, width, height, 4u, 6u);
}

bool png_encode_rgb(const uint8_t *pixels, uint32_t width, uint32_t height,
                    uint8_t *output, size_t output_cap, size_t *written)
{
    return png_encode_channels(
        pixels, width, height, 3u, 2u, output, output_cap, written);
}

bool png_encode_rgba(const uint8_t *pixels, uint32_t width, uint32_t height,
                     uint8_t *output, size_t output_cap, size_t *written)
{
    return png_encode_channels(
        pixels, width, height, 4u, 6u, output, output_cap, written);
}
