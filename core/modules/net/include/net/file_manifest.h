/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * File manifest protocol types for SHA3-verified chunk serving.
 *
 * These declarations are shared by the RPC/REST file controller and the
 * direct P2P file service. The controller owns routes; the net layer owns
 * transfer. The manifest shape itself is protocol data, not controller state.
 */

#ifndef ZCL_NET_FILE_MANIFEST_H
#define ZCL_NET_FILE_MANIFEST_H

#include <stdbool.h>
#include <stdint.h>

#define FILE_CHUNK_SIZE (50 * 1024 * 1024)  /* 50 MB per chunk */
#define FILE_MAX_CHUNKS 1024                /* ~50 GB max total */

struct file_chunk {
    uint8_t  sha3[32];        /* SHA3-256 hash of chunk data */
    uint64_t offset;          /* byte offset in source file */
    uint32_t size;            /* actual size (last chunk may be smaller) */
    uint8_t  file_index;      /* which source file (0=blk0000.dat, etc.) */
};

struct file_manifest {
    struct file_chunk chunks[FILE_MAX_CHUNKS];
    uint32_t          num_chunks;
    uint8_t           root_hash[32]; /* SHA3-256 of all chunk hashes */
    uint8_t           mmr_root[32];  /* MMR root at chain_height */
    int32_t           chain_height;  /* height when manifest was built */
    uint64_t          total_bytes;   /* total data size */
};

/* Build manifest from block files in datadir. */
bool file_manifest_build(struct file_manifest *fm, const char *datadir);

/* Find a chunk by its SHA3 hash. Returns NULL if not found. */
const struct file_chunk *file_manifest_find(const struct file_manifest *fm,
                                            const uint8_t sha3[32]);

/* Read chunk data from disk. Caller must free(*out). */
bool file_chunk_read(const struct file_chunk *chunk, const char *datadir,
                     uint8_t **out, uint32_t *out_size);

#endif
