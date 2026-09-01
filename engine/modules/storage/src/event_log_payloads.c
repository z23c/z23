/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * event_log_payloads — serialize/parse helpers for canonical wire
 * payloads carried by the append-only event log. See header for the
 * binary layout (it is frozen). */

#include "storage/event_log_payloads.h"

#include "util/log_macros.h"

#include <string.h>

/* ── little-endian byte helpers ────────────────────────────────────── */

static void put_u16_le(uint8_t *dst, uint16_t v)
{
    dst[0] = (uint8_t)(v        & 0xFF);
    dst[1] = (uint8_t)((v >> 8) & 0xFF);
}

static uint16_t get_u16_le(const uint8_t *src)
{
    return (uint16_t)src[0] | ((uint16_t)src[1] << 8);
}

static void put_u32_le(uint8_t *dst, uint32_t v)
{
    dst[0] = (uint8_t)(v        & 0xFF);
    dst[1] = (uint8_t)((v >> 8) & 0xFF);
    dst[2] = (uint8_t)((v >> 16) & 0xFF);
    dst[3] = (uint8_t)((v >> 24) & 0xFF);
}

static uint32_t get_u32_le(const uint8_t *src)
{
    return (uint32_t)src[0]
        | ((uint32_t)src[1] << 8)
        | ((uint32_t)src[2] << 16)
        | ((uint32_t)src[3] << 24);
}

/* ── EV_BLOCK_HEADER ───────────────────────────────────────────────── */

bool ev_block_header_serialize(const struct ev_block_header *h,
                               const uint8_t *solution,
                               uint8_t *out, size_t out_cap,
                               size_t *out_written)
{
    if (!h || !out)
        LOG_FAIL("event_log_payloads",
                 "ev_block_header_serialize: NULL h or out");
    if (h->nSolutionSize > EV_BLOCK_HEADER_MAX_SOLUTION)
        LOG_FAIL("event_log_payloads",
                 "ev_block_header_serialize: nSolutionSize %u > max %u",
                 (unsigned)h->nSolutionSize,
                 (unsigned)EV_BLOCK_HEADER_MAX_SOLUTION);
    if (h->nSolutionSize > 0 && !solution)
        LOG_FAIL("event_log_payloads",
                 "ev_block_header_serialize: solution NULL but nSolutionSize=%u",
                 (unsigned)h->nSolutionSize);

    size_t need = ev_block_header_wire_size(h->nSolutionSize);
    if (out_cap < need)
        LOG_FAIL("event_log_payloads",
                 "ev_block_header_serialize: out_cap=%zu < need=%zu",
                 out_cap, need);

    size_t off = 0;
    memcpy(out + off, h->hash, 32);                       off += 32;
    memcpy(out + off, h->hashPrev, 32);                   off += 32;
    put_u32_le(out + off, (uint32_t)h->height);           off += 4;
    put_u32_le(out + off, h->nStatus);                    off += 4;
    put_u32_le(out + off, (uint32_t)h->nFile);            off += 4;
    put_u32_le(out + off, h->nDataPos);                   off += 4;
    put_u32_le(out + off, h->nUndoPos);                   off += 4;
    put_u32_le(out + off, h->nTime);                      off += 4;
    put_u32_le(out + off, h->nBits);                      off += 4;
    memcpy(out + off, h->nNonce, 32);                     off += 32;
    memcpy(out + off, h->hashMerkleRoot, 32);             off += 32;
    memcpy(out + off, h->hashFinalSaplingRoot, 32);       off += 32;
    put_u32_le(out + off, (uint32_t)h->nVersion);         off += 4;
    put_u32_le(out + off, h->nTx);                        off += 4;
    put_u16_le(out + off, h->nSolutionSize);              off += 2;
    out[off++] = 0;  /* reserved[0] */
    out[off++] = 0;  /* reserved[1] */

    if (h->nSolutionSize > 0) {
        memcpy(out + off, solution, h->nSolutionSize);
        off += h->nSolutionSize;
    }

    if (out_written) *out_written = off;
    return true;
}

bool ev_block_header_parse(const uint8_t *in, size_t in_len,
                           struct ev_block_header *h_out,
                           const uint8_t **solution_out)
{
    if (!in || !h_out)
        LOG_FAIL("event_log_payloads",
                 "ev_block_header_parse: NULL in or h_out");
    if (in_len < EV_BLOCK_HEADER_FIXED_BYTES)
        LOG_FAIL("event_log_payloads",
                 "ev_block_header_parse: truncated (got %zu < %u)",
                 in_len, (unsigned)EV_BLOCK_HEADER_FIXED_BYTES);

    size_t off = 0;
    memcpy(h_out->hash, in + off, 32);                    off += 32;
    memcpy(h_out->hashPrev, in + off, 32);                off += 32;
    h_out->height   = (int32_t) get_u32_le(in + off);     off += 4;
    h_out->nStatus  =           get_u32_le(in + off);     off += 4;
    h_out->nFile    = (int32_t) get_u32_le(in + off);     off += 4;
    h_out->nDataPos =           get_u32_le(in + off);     off += 4;
    h_out->nUndoPos =           get_u32_le(in + off);     off += 4;
    h_out->nTime    =           get_u32_le(in + off);     off += 4;
    h_out->nBits    =           get_u32_le(in + off);     off += 4;
    memcpy(h_out->nNonce, in + off, 32);                  off += 32;
    memcpy(h_out->hashMerkleRoot, in + off, 32);          off += 32;
    memcpy(h_out->hashFinalSaplingRoot, in + off, 32);    off += 32;
    h_out->nVersion = (int32_t) get_u32_le(in + off);     off += 4;
    h_out->nTx      =           get_u32_le(in + off);     off += 4;
    h_out->nSolutionSize = get_u16_le(in + off);          off += 2;
    h_out->reserved[0] = in[off++];
    h_out->reserved[1] = in[off++];

    if (h_out->nSolutionSize > EV_BLOCK_HEADER_MAX_SOLUTION)
        LOG_FAIL("event_log_payloads",
                 "ev_block_header_parse: nSolutionSize %u > max %u",
                 (unsigned)h_out->nSolutionSize,
                 (unsigned)EV_BLOCK_HEADER_MAX_SOLUTION);

    size_t need = ev_block_header_wire_size(h_out->nSolutionSize);
    if (in_len < need)
        LOG_FAIL("event_log_payloads",
                 "ev_block_header_parse: truncated solution "
                 "(have %zu, need %zu)", in_len, need);

    if (solution_out) {
        *solution_out = h_out->nSolutionSize > 0 ? (in + off) : NULL;
    }
    return true;
}
