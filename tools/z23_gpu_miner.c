/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * Native Windows Equihash miner front end. The C23 host dynamically loads the
 * installed GPU runtime; OpenCL kernels are JITed to device assembly. */

#include "miner/gpu_equihash.h"
#include "crypto/sha256.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(FILE *out)
{
    fprintf(out,
        "z23-gpu-miner probe\n"
        "z23-gpu-miner benchmark [nonces]\n"
        "z23-gpu-miner mine PRE_SOLUTION_HEADER_HEX [max_nonces]\n\n"
        "mine accepts exactly 108 header bytes (216 hex characters): version,\n"
        "previous hash, merkle root, final Sapling root, time, and bits. It\n"
        "searches little-endian 256-bit nonces and prints a consensus-verified\n"
        "400-byte Equihash solution when the complete header hash meets bits.\n");
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool decode_hex_exact(const char *hex, unsigned char *out, size_t bytes)
{
    if (!hex || strlen(hex) != bytes * 2u)
        return false;
    for (size_t i = 0; i < bytes; ++i) {
        int hi = hex_value(hex[2u * i]);
        int lo = hex_value(hex[2u * i + 1u]);
        if (hi < 0 || lo < 0)
            return false;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return true;
}

static void print_hex(const unsigned char *data, size_t bytes)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < bytes; ++i) {
        putchar(digits[data[i] >> 4]);
        putchar(digits[data[i] & 15]);
    }
}

static void print_json_string(const char *s)
{
    putchar('"');
    for (; s && *s; ++s) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') {
            putchar('\\');
            putchar(c);
        } else if (c >= 0x20) {
            putchar(c);
        }
    }
    putchar('"');
}

static bool parse_count(const char *s, uint64_t fallback, uint64_t *out)
{
    if (!s) {
        *out = fallback;
        return true;
    }
    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(s, &end, 10);
    if (errno || end == s || *end != '\0' || value == 0 || value > 1000000ull)
        return false;
    *out = (uint64_t)value;
    return true;
}

static void increment_nonce(unsigned char nonce[32])
{
    for (size_t i = 0; i < 32; ++i)
        if (++nonce[i] != 0)
            break;
}

static uint32_t read_u32_le(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void miner_hash256(const unsigned char *data, size_t len,
                          unsigned char hash[32])
{
    unsigned char first[32];
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_write(&ctx, data, len);
    sha256_finalize(&ctx, first);
    sha256_init(&ctx);
    sha256_write(&ctx, first, sizeof(first));
    sha256_finalize(&ctx, hash);
}

static bool hash_meets_target(const unsigned char prefix[108],
                              const unsigned char nonce[32],
                              const unsigned char solution[400])
{
    uint32_t compact = read_u32_le(prefix + 104);
    uint32_t size = compact >> 24;
    uint32_t word = compact & 0x007fffffu;
    bool overflow = word != 0 &&
        (size > 34u || (word > 0xffu && size > 33u) ||
         (word > 0xffffu && size > 32u));
    if ((compact & 0x00800000u) || word == 0 || overflow)
        return false;
    unsigned char target[32] = {0};
    if (size <= 3u) {
        word >>= 8u * (3u - size);
        target[0] = (unsigned char)word;
        target[1] = (unsigned char)(word >> 8);
        target[2] = (unsigned char)(word >> 16);
    } else {
        uint32_t at = size - 3u;
        if (at < 32u) target[at] = (unsigned char)word;
        if (at + 1u < 32u) target[at + 1u] = (unsigned char)(word >> 8);
        if (at + 2u < 32u) target[at + 2u] = (unsigned char)(word >> 16);
    }
    unsigned char serialized[108 + 32 + 3 + 400];
    memcpy(serialized, prefix, 108);
    memcpy(serialized + 108, nonce, 32);
    serialized[140] = 0xfd;
    serialized[141] = 0x90;
    serialized[142] = 0x01;
    memcpy(serialized + 143, solution, 400);
    unsigned char hash[32];
    miner_hash256(serialized, sizeof(serialized), hash);
    for (int i = 31; i >= 0; --i) {
        if (hash[i] < target[i]) return true;
        if (hash[i] > target[i]) return false;
    }
    return true;
}

static void print_device(const struct z23_gpu_equihash_device *d)
{
    printf("\"platform\":"); print_json_string(d->platform);
    printf(",\"vendor\":"); print_json_string(d->vendor);
    printf(",\"device\":"); print_json_string(d->name);
    printf(",\"compute_units\":%u,\"global_memory_bytes\":%" PRIu64
           ",\"max_allocation_bytes\":%" PRIu64,
           d->compute_units, d->global_memory_bytes, d->max_allocation_bytes);
}

static void print_stats(const struct z23_gpu_equihash_stats *s)
{
    printf("\"elapsed_us\":%" PRIu64 ",\"initial_hash_us\":%" PRIu64
           ",\"collision_round_us\":[",
           s->elapsed_us, s->initial_hash_us);
    for (size_t i = 0; i < 7; ++i)
        printf("%s%" PRIu64, i ? "," : "", s->collision_round_us[i]);
    printf("],\"candidates\":%u,\"valid_solutions\":%u",
           s->candidates, s->valid_solutions);
}

int main(int argc, char **argv)
{
    if (argc < 2 || strcmp(argv[1], "--help") == 0 ||
        strcmp(argv[1], "-h") == 0) {
        usage(argc < 2 ? stderr : stdout);
        return argc < 2 ? 2 : 0;
    }

    char error[4096] = {0};
    struct z23_gpu_equihash_device device;
    struct z23_gpu_equihash *gpu = z23_gpu_equihash_open(
        &device, error, sizeof(error));
    if (!gpu) {
        fprintf(stderr, "z23-gpu-miner: %s\n", error[0] ? error : "GPU open failed");
        return 1;
    }

    if (strcmp(argv[1], "probe") == 0) {
        printf("{\"schema\":\"z23.gpu_miner_probe.v1\",\"ok\":true,");
        print_device(&device);
        printf(",\"backend\":\"OpenCL 1.2 dynamic\",\"device_code\":\"driver-JIT native assembly\"}\n");
        z23_gpu_equihash_close(gpu);
        return 0;
    }

    uint64_t max_nonces = 0;
    unsigned char prefix[108] = {0};
    bool benchmark = strcmp(argv[1], "benchmark") == 0;
    if (benchmark) {
        if (argc > 3 || !parse_count(argc == 3 ? argv[2] : NULL, 4, &max_nonces)) {
            fprintf(stderr, "benchmark nonces must be in [1,1000000]\n");
            z23_gpu_equihash_close(gpu);
            return 2;
        }
        prefix[0] = 4;
        prefix[100] = 0x65;
        prefix[101] = 0x23;
        prefix[104] = 0xff;
        prefix[105] = 0xff;
        prefix[106] = 0x7f;
        prefix[107] = 0x20;
    } else if (strcmp(argv[1], "mine") == 0) {
        if (argc < 3 || argc > 4 ||
            !decode_hex_exact(argv[2], prefix, sizeof(prefix)) ||
            !parse_count(argc == 4 ? argv[3] : NULL, 256, &max_nonces)) {
            fprintf(stderr, "mine requires 216 hex characters and optional max_nonces [1,1000000]\n");
            z23_gpu_equihash_close(gpu);
            return 2;
        }
    } else {
        usage(stderr);
        z23_gpu_equihash_close(gpu);
        return 2;
    }

    struct equihash_params params;
    equihash_params_init(&params, 192, 7);
    unsigned char nonce[32] = {0};
    uint64_t total_us = 0;
    uint64_t total_candidates = 0;
    uint64_t total_valid = 0;
    bool found_equihash = false;
    bool found_pow = false;
    unsigned char last_solution[Z23_GPU_EQUIHASH_SOLUTION_BYTES] = {0};
    unsigned char last_nonce[32] = {0};
    struct z23_gpu_equihash_stats last_stats;
    memset(&last_stats, 0, sizeof(last_stats));

    for (uint64_t attempt = 0; attempt < max_nonces; ++attempt) {
        struct blake2b_ctx state;
        if (equihash_initialise_state(&params, &state) != 0 ||
            blake2b_update(&state, prefix, sizeof(prefix)) != 0 ||
            blake2b_update(&state, nonce, sizeof(nonce)) != 0) {
            fprintf(stderr, "failed to construct Equihash state\n");
            z23_gpu_equihash_close(gpu);
            return 1;
        }
        struct z23_gpu_equihash_stats stats;
        memset(&stats, 0, sizeof(stats));
        unsigned char solution[Z23_GPU_EQUIHASH_SOLUTION_BYTES];
        bool solved = z23_gpu_equihash_solve(gpu, &params, &state, solution,
                                             &stats, error, sizeof(error));
        total_us += stats.elapsed_us;
        total_candidates += stats.candidates;
        total_valid += stats.valid_solutions;
        if (solved) {
            found_equihash = true;
            if (benchmark) {
                memcpy(last_solution, solution, sizeof(last_solution));
                memcpy(last_nonce, nonce, sizeof(last_nonce));
                last_stats = stats;
            } else if (hash_meets_target(prefix, nonce, solution)) {
                found_pow = true;
                printf("{\"schema\":\"z23.gpu_miner_result.v1\",\"ok\":true,");
                print_device(&device);
                printf(",\"mode\":\"%s\",\"attempts\":%" PRIu64
                       ",\"total_elapsed_us\":%" PRIu64
                       ",\"solutions_per_second\":%.6f,\"nonce\":\"",
                       benchmark ? "benchmark" : "mine", attempt + 1,
                       total_us, total_us ? (1000000.0 * total_valid / total_us) : 0.0);
                print_hex(nonce, sizeof(nonce));
                printf("\",\"solution\":\"");
                print_hex(solution, sizeof(solution));
                printf("\",\"last_solve\":{");
                print_stats(&stats);
                printf("},\"pow_target_met\":%s}\n", found_pow ? "true" : "false");
                z23_gpu_equihash_close(gpu);
                return 0;
            }
        }
        increment_nonce(nonce);
    }

    if (benchmark && found_equihash) {
        printf("{\"schema\":\"z23.gpu_miner_result.v1\",\"ok\":true,");
        print_device(&device);
        printf(",\"mode\":\"benchmark\",\"attempts\":%" PRIu64
               ",\"total_elapsed_us\":%" PRIu64
               ",\"solutions_per_second\":%.6f,\"nonce\":\"",
               max_nonces, total_us,
               total_us ? (1000000.0 * total_valid / total_us) : 0.0);
        print_hex(last_nonce, sizeof(last_nonce));
        printf("\",\"solution\":\"");
        print_hex(last_solution, sizeof(last_solution));
        printf("\",\"last_solve\":{");
        print_stats(&last_stats);
        printf("},\"valid_solutions\":%" PRIu64
               ",\"pow_target_met\":false}\n", total_valid);
        z23_gpu_equihash_close(gpu);
        return 0;
    }

    printf("{\"schema\":\"z23.gpu_miner_result.v1\",\"ok\":false,");
    print_device(&device);
    printf(",\"mode\":\"%s\",\"attempts\":%" PRIu64
           ",\"total_elapsed_us\":%" PRIu64
           ",\"candidates\":%" PRIu64 ",\"valid_solutions\":%" PRIu64
           ",\"reason\":\"%s\"}\n",
           benchmark ? "benchmark" : "mine", max_nonces, total_us,
           total_candidates, total_valid,
           found_equihash ? "no solution met the encoded target" :
                            "no valid Equihash solution in nonce budget");
    z23_gpu_equihash_close(gpu);
    return benchmark ? 1 : 3;
}
