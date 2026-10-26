/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * Native Windows Equihash miner front end. The C23 host dynamically loads the
 * installed GPU runtime; OpenCL kernels are JITed to device assembly. */

#include "miner/gpu_equihash.h"
#include "base/hex.h"
#include "base/serialize_le.h"
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

static void print_hex(const unsigned char *data, size_t bytes)
{
    char encoded[2u * Z23_GPU_EQUIHASH_SOLUTION_BYTES + 1u];
    if (bytes > Z23_GPU_EQUIHASH_SOLUTION_BYTES)
        return;
    zcl_hex_encode(data, bytes, encoded);
    fputs(encoded, stdout);
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

static bool compact_bits_overflow(uint32_t compact)
{
    uint32_t size = compact >> 24;
    uint32_t word = compact & 0x007fffffu;
    return word != 0 &&
        (size > 34u || (word > 0xffu && size > 33u) ||
         (word > 0xffffu && size > 32u));
}

static void expand_compact_target(uint32_t compact, unsigned char target[32])
{
    uint32_t size = compact >> 24;
    uint32_t word = compact & 0x007fffffu;
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
}

static void hash_header_with_solution(const unsigned char prefix[108],
                                      const unsigned char nonce[32],
                                      const unsigned char solution[400],
                                      unsigned char hash[32])
{
    unsigned char serialized[108 + 32 + 3 + 400];
    memcpy(serialized, prefix, 108);
    memcpy(serialized + 108, nonce, 32);
    serialized[140] = 0xfd;
    serialized[141] = 0x90;
    serialized[142] = 0x01;
    memcpy(serialized + 143, solution, 400);
    miner_hash256(serialized, sizeof(serialized), hash);
}

static bool hash_meets_difficulty(const unsigned char hash[32],
                                  const unsigned char target[32])
{
    for (int i = 31; i >= 0; --i) {
        if (hash[i] < target[i]) return true;
        if (hash[i] > target[i]) return false;
    }
    return true;
}

static bool hash_meets_target(const unsigned char prefix[108],
                              const unsigned char nonce[32],
                              const unsigned char solution[400])
{
    uint32_t compact = zcl_read_u32_le(prefix + 104);
    uint32_t word = compact & 0x007fffffu;
    bool overflow = compact_bits_overflow(compact);
    if ((compact & 0x00800000u) || word == 0 || overflow)
        return false;
    unsigned char target[32] = {0};
    expand_compact_target(compact, target);
    unsigned char hash[32];
    hash_header_with_solution(prefix, nonce, solution, hash);
    return hash_meets_difficulty(hash, target);
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

static void print_probe_report(const struct z23_gpu_equihash_device *device)
{
    printf("{\"schema\":\"z23.gpu_miner_probe.v1\",\"ok\":true,");
    print_device(device);
    printf(",\"backend\":\"OpenCL 1.2 dynamic\",\"device_code\":\"driver-JIT native assembly\"}\n");
}

static bool missing_command_or_help(int argc, char **argv)
{
    return argc < 2 || strcmp(argv[1], "--help") == 0 ||
        strcmp(argv[1], "-h") == 0;
}

static bool parse_mine_args(int argc, char **argv, unsigned char prefix[108],
                            uint64_t *max_nonces)
{
    if (argc < 3 || argc > 4)
        return false;
    return zcl_hex_decode(argv[2], prefix, 108) &&
        parse_count(argc == 4 ? argv[3] : NULL, 256, max_nonces);
}

static void build_benchmark_prefix(unsigned char prefix[108])
{
    prefix[0] = 4;
    prefix[100] = 0x65;
    prefix[101] = 0x23;
    prefix[104] = 0xff;
    prefix[105] = 0xff;
    prefix[106] = 0x7f;
    prefix[107] = 0x20;
}

static int parse_mining_mode(int argc, char **argv,
                             struct z23_gpu_equihash *gpu, bool *benchmark,
                             uint64_t *max_nonces, unsigned char prefix[108])
{
    *benchmark = strcmp(argv[1], "benchmark") == 0;
    if (*benchmark) {
        if (argc > 3 || !parse_count(argc == 3 ? argv[2] : NULL, 4, max_nonces)) {
            fprintf(stderr, "benchmark nonces must be in [1,1000000]\n");
            z23_gpu_equihash_close(gpu);
            return 2;
        }
        build_benchmark_prefix(prefix);
        return 0;
    }
    if (strcmp(argv[1], "mine") == 0) {
        if (!parse_mine_args(argc, argv, prefix, max_nonces)) {
            fprintf(stderr, "mine requires 216 hex characters and optional max_nonces [1,1000000]\n");
            z23_gpu_equihash_close(gpu);
            return 2;
        }
        return 0;
    }
    usage(stderr);
    z23_gpu_equihash_close(gpu);
    return 2;
}

static bool build_equihash_state(struct equihash_params *params,
                                 unsigned char prefix[108],
                                 unsigned char nonce[32],
                                 struct blake2b_ctx *state)
{
    return equihash_initialise_state(params, state) == 0 &&
        blake2b_update(state, prefix, 108) == 0 &&
        blake2b_update(state, nonce, 32) == 0;
}

static void print_mine_solution_result(
    const struct z23_gpu_equihash_device *device, bool benchmark,
    uint64_t attempts, uint64_t total_us, uint64_t total_valid,
    const unsigned char nonce[32],
    const unsigned char solution[Z23_GPU_EQUIHASH_SOLUTION_BYTES],
    const struct z23_gpu_equihash_stats *stats, bool found_pow)
{
    printf("{\"schema\":\"z23.gpu_miner_result.v1\",\"ok\":true,");
    print_device(device);
    printf(",\"mode\":\"%s\",\"attempts\":%" PRIu64
           ",\"total_elapsed_us\":%" PRIu64
           ",\"solutions_per_second\":%.6f,\"nonce\":\"",
           benchmark ? "benchmark" : "mine", attempts,
           total_us, total_us ? (1000000.0 * total_valid / total_us) : 0.0);
    print_hex(nonce, 32);
    printf("\",\"solution\":\"");
    print_hex(solution, Z23_GPU_EQUIHASH_SOLUTION_BYTES);
    printf("\",\"last_solve\":{");
    print_stats(stats);
    printf("},\"pow_target_met\":%s}\n", found_pow ? "true" : "false");
}

static int mine_nonce_space(
    struct z23_gpu_equihash *gpu, const struct z23_gpu_equihash_device *device,
    struct equihash_params *params, unsigned char prefix[108],
    bool benchmark, uint64_t max_nonces, char *error, size_t error_size,
    uint64_t *total_us, uint64_t *total_candidates, uint64_t *total_valid,
    bool *found_equihash,
    unsigned char last_solution[Z23_GPU_EQUIHASH_SOLUTION_BYTES],
    unsigned char last_nonce[32],
    struct z23_gpu_equihash_stats *last_stats)
{
    unsigned char nonce[32] = {0};
    for (uint64_t attempt = 0; attempt < max_nonces; ++attempt) {
        struct blake2b_ctx state;
        if (!build_equihash_state(params, prefix, nonce, &state)) {
            fprintf(stderr, "failed to construct Equihash state\n");
            return 1;
        }
        struct z23_gpu_equihash_stats stats;
        memset(&stats, 0, sizeof(stats));
        unsigned char solution[Z23_GPU_EQUIHASH_SOLUTION_BYTES];
        bool solved = z23_gpu_equihash_solve(gpu, params, &state, solution,
                                             &stats, error, error_size);
        *total_us += stats.elapsed_us;
        *total_candidates += stats.candidates;
        *total_valid += stats.valid_solutions;
        if (solved) {
            *found_equihash = true;
            if (benchmark) {
                memcpy(last_solution, solution,
                       Z23_GPU_EQUIHASH_SOLUTION_BYTES);
                memcpy(last_nonce, nonce, sizeof(nonce));
                *last_stats = stats;
            } else if (hash_meets_target(prefix, nonce, solution)) {
                bool found_pow = true;
                print_mine_solution_result(device, benchmark, attempt + 1,
                                           *total_us, *total_valid, nonce,
                                           solution, &stats, found_pow);
                return 0;
            }
        }
        increment_nonce(nonce);
    }
    return -1;
}

static int report_search_exhausted(
    const struct z23_gpu_equihash_device *device,
    struct z23_gpu_equihash *gpu, bool benchmark, uint64_t max_nonces,
    uint64_t total_us, uint64_t total_candidates, uint64_t total_valid,
    bool found_equihash, const unsigned char last_nonce[32],
    const unsigned char last_solution[Z23_GPU_EQUIHASH_SOLUTION_BYTES],
    const struct z23_gpu_equihash_stats *last_stats)
{
    if (benchmark && found_equihash) {
        printf("{\"schema\":\"z23.gpu_miner_result.v1\",\"ok\":true,");
        print_device(device);
        printf(",\"mode\":\"benchmark\",\"attempts\":%" PRIu64
               ",\"total_elapsed_us\":%" PRIu64
               ",\"solutions_per_second\":%.6f,\"nonce\":\"",
               max_nonces, total_us,
               total_us ? (1000000.0 * total_valid / total_us) : 0.0);
        print_hex(last_nonce, 32);
        printf("\",\"solution\":\"");
        print_hex(last_solution, Z23_GPU_EQUIHASH_SOLUTION_BYTES);
        printf("\",\"last_solve\":{");
        print_stats(last_stats);
        printf("},\"valid_solutions\":%" PRIu64
               ",\"pow_target_met\":false}\n", total_valid);
        z23_gpu_equihash_close(gpu);
        return 0;
    }

    printf("{\"schema\":\"z23.gpu_miner_result.v1\",\"ok\":false,");
    print_device(device);
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

int main(int argc, char **argv)
{
    if (missing_command_or_help(argc, argv)) {
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
        print_probe_report(&device);
        z23_gpu_equihash_close(gpu);
        return 0;
    }

    bool benchmark = false;
    uint64_t max_nonces = 0;
    unsigned char prefix[108] = {0};
    int mode_status = parse_mining_mode(argc, argv, gpu, &benchmark,
                                        &max_nonces, prefix);
    if (mode_status != 0)
        return mode_status;

    struct equihash_params params;
    equihash_params_init(&params, 192, 7);
    uint64_t total_us = 0;
    uint64_t total_candidates = 0;
    uint64_t total_valid = 0;
    bool found_equihash = false;
    unsigned char last_solution[Z23_GPU_EQUIHASH_SOLUTION_BYTES] = {0};
    unsigned char last_nonce[32] = {0};
    struct z23_gpu_equihash_stats last_stats;
    memset(&last_stats, 0, sizeof(last_stats));

    int search_status = mine_nonce_space(
        gpu, &device, &params, prefix, benchmark, max_nonces, error,
        sizeof(error), &total_us, &total_candidates, &total_valid,
        &found_equihash, last_solution, last_nonce, &last_stats);
    if (search_status >= 0) {
        z23_gpu_equihash_close(gpu);
        return search_status;
    }
    return report_search_exhausted(&device, gpu, benchmark, max_nonces,
                                   total_us, total_candidates, total_valid,
                                   found_equihash, last_nonce, last_solution,
                                   &last_stats);
}
