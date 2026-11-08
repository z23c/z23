/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#include "test/test_core.h"
#include "services/wallet_history_export.h"
#include "services/wallet_history_manifest.h"
#include "services/block_index_loader.h"
#include "platform/directory_transaction.h"
#include "validation/main_state.h"
#include "chain/chainparams.h"
#include "core/arith_uint256.h"
#include "core/serialize.h"
#include "encoding/utilstrencodings.h"
#include "primitives/block.h"
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#if defined(__linux__)
#include <dirent.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

struct zcl_result wallet_history_export_test_run(const struct wallet_history_export_request *,
    struct wallet_history_export_result *, const struct uint256 *);

struct zcl_result wallet_history_export_test_validate_archive(const struct wallet_history_export_request *,
    const char *, const struct uint256 *);

static bool history_test_mine(struct block_header *header, struct uint256 *hash)
{
    struct arith_uint256 target, value;
    arith_uint256_set_compact(&target, header->nBits, NULL, NULL);
    for (uint32_t nonce = 0; nonce < 4096; nonce++) {
        header->nNonce.data[0] = (uint8_t)nonce;
        header->nNonce.data[1] = (uint8_t)(nonce >> 8);
        block_header_get_hash(header, hash);
        uint256_to_arith(&value, hash);
        if (arith_uint256_compare(&value, &target) <= 0) return true;
    }
    return false;
}
static bool history_test_block(FILE *f, struct main_state *state, struct block_index **prev,
    struct uint256 *hash, int height, bool bad_merkle)
{
    struct block block; block_init(&block);
    block.header.nVersion = 4; block.header.nTime = 100000 + (uint32_t)height;
    block.header.nBits = 0x200f0f0f; block.header.nSolutionSize = 1;
    block.header.nSolution[0] = (uint8_t)height;
    if (*prev) block.header.hashPrevBlock = *(*prev)->phashBlock;
    if (bad_merkle && height == 1) block.header.hashMerkleRoot.data[0] = 1;
    if (!history_test_mine(&block.header, hash)) return false;
    struct byte_stream stream; stream_init(&stream, 2048);
    bool ok = block_serialize(&block, &stream) && stream.size <= UINT32_MAX;
    long pos = ftell(f);
    const struct chain_params *params = chain_params_get();
    uint32_t size = (uint32_t)stream.size;
    uint8_t frame[8] = {0};
    if (params) memcpy(frame, params->pchMessageStart, 4);
    frame[4] = (uint8_t)size; frame[5] = (uint8_t)(size >> 8);
    frame[6] = (uint8_t)(size >> 16); frame[7] = (uint8_t)(size >> 24);
    ok = ok && params && pos >= 0 && fwrite(frame, 1, 8, f) == 8 &&
        fwrite(stream.data, 1, stream.size, f) == stream.size;
    stream_free(&stream);
    if (!ok) return false;
    struct block_index *row = chainstate_insert_block_index((struct chainstate *)state, hash);
    if (!row) return false;
    row->pprev = *prev; row->nHeight = height; row->nFile = 0; row->nDataPos = (unsigned)pos + 8;
    row->nVersion = block.header.nVersion; row->nTime = block.header.nTime;
    row->nBits = block.header.nBits; row->hashFinalSaplingRoot = block.header.hashFinalSaplingRoot;
    *prev = row;
    return true;
}
static bool history_test_source(const char *dir, struct uint256 hashes[3], bool bad_merkle)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/blocks", dir);
    if (mkdir(path, 0755) != 0 || chmod(path, 0755) != 0) return false;
    snprintf(path, sizeof(path), "%s/blocks/blk00000.dat", dir);
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    struct main_state state; main_state_init(&state);
    struct block_index *prev = NULL;
    bool ok = true;
    for (int h = 0; h < 3 && ok; h++) ok = history_test_block(f, &state, &prev, &hashes[h], h, bad_merkle);
    if (fclose(f) != 0 || chmod(path, 0664) != 0) ok = false;
    struct block_index_flat_identity identity;
    ok = ok && save_block_index_flat_identity(dir, &state, &identity).ok;
    main_state_free(&state);
    snprintf(path, sizeof(path), "%s/block_index.bin", dir);
    return ok && chmod(path, 0664) == 0;
}
static bool history_test_cancel(void *context) { (void)context; return true; }
struct manifest_cancel_test { const char *path; bool damage; bool fired; };
static bool history_manifest_fd_advanced(const struct stat *want)
{
    struct stat got;
    DIR *dir = opendir("/proc/self/fd");
    if (!dir) return false;
    bool found = false;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        char *end = NULL;
        long fd = strtol(entry->d_name, &end, 10);
        if (!end || *end || end == entry->d_name || fd < 0 || fd > INT_MAX) continue;
        if (fstat((int)fd, &got) == 0 && got.st_dev == want->st_dev && got.st_ino == want->st_ino &&
            lseek((int)fd, 0, SEEK_CUR) >= 65536) { found = true; break; }
    }
    (void)closedir(dir);
    return found;
}
static bool history_manifest_after_read(void *opaque)
{
    struct manifest_cancel_test *c = opaque;
    if (c->fired) return true;
    struct stat want;
    if (stat(c->path, &want) != 0) return false;
    c->fired = history_manifest_fd_advanced(&want);
    if (c->fired && c->damage) { if (truncate(c->path, 0) != 0) c->fired = false; return false; }
    return c->fired;
}
static int history_manifest_fds(void)
{
    DIR *dir = opendir("/proc/self/fd");
    if (!dir) return -1;
    int count = 0;
    while (readdir(dir)) count++;
    if (closedir(dir) != 0) return -1;
    return count;
}
static bool history_manifest_file(const char *path, size_t size)
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    char bytes[4096] = {1};
    bool ok = true;
    while (size && ok) {
        size_t n = size < sizeof(bytes) ? size : sizeof(bytes);
        ok = fwrite(bytes, 1, n, f) == n;
        size -= n;
    }
    if (fclose(f) != 0) ok = false;
    return ok;
}
static bool history_manifest_equal(const struct file_manifest *a, const struct file_manifest *b)
{
    if (a->num_chunks != b->num_chunks || a->total_bytes != b->total_bytes ||
        a->chain_height != b->chain_height || memcmp(a->root_hash, b->root_hash, 32) ||
        memcmp(a->mmr_root, b->mmr_root, 32)) return false;
    for (uint32_t i = 0; i < a->num_chunks; ++i) {
        const struct file_chunk *x = &a->chunks[i], *y = &b->chunks[i];
        if (x->offset != y->offset || x->size != y->size || x->file_index != y->file_index ||
            memcmp(x->sha3, y->sha3, 32)) return false;
    }
    return true;
}
static bool history_manifest_parity(const char *dir)
{
    static const uint8_t expected_root[32] = {
        0x07, 0xc5, 0x1d, 0xd8, 0x16, 0xb2, 0xc3, 0xdd,
        0x8f, 0xc9, 0xf6, 0xce, 0x53, 0xc8, 0xb9, 0x49,
        0x30, 0x28, 0xa6, 0xfc, 0x4b, 0xd7, 0xf6, 0x66,
        0x30, 0x78, 0x3c, 0xf8, 0x78, 0xfd, 0x9c, 0x08
    };
    struct file_manifest baseline = {0}, other = {0};
    return wallet_history_manifest_build(&baseline, dir, 1).ok &&
        wallet_history_manifest_build_cancelable(&other, dir, 1, NULL, NULL).ok &&
        history_manifest_equal(&baseline, &other) &&
        memcmp(baseline.root_hash, expected_root, sizeof(expected_root)) == 0;
}
static bool history_manifest_stops(const char *dir, const char *block)
{
    struct file_manifest other, untouched;
    memset(&untouched, 0xa5, sizeof(untouched));
    int fds = history_manifest_fds();
    memset(&other, 0xa5, sizeof(other));
    struct zcl_result r = wallet_history_manifest_build_cancelable(&other, dir, 1, history_test_cancel, NULL);
    bool ok = !r.ok && r.code == WALLET_HISTORY_MANIFEST_CANCELLED && memcmp(&other, &untouched, sizeof(other)) == 0;
    struct manifest_cancel_test cancel = {.path = block};
    r = wallet_history_manifest_build_cancelable(&other, dir, 1, history_manifest_after_read, &cancel);
    ok = ok && cancel.fired && !r.ok && r.code == WALLET_HISTORY_MANIFEST_CANCELLED &&
        memcmp(&other, &untouched, sizeof(other)) == 0;
    struct manifest_cancel_test damage = {.path = block, .damage = true};
    r = wallet_history_manifest_build_cancelable(&other, dir, 1, history_manifest_after_read, &damage);
    ok = ok && damage.fired && !r.ok && r.code != WALLET_HISTORY_MANIFEST_CANCELLED &&
        memcmp(&other, &untouched, sizeof(other)) == 0 && fds >= 0 && history_manifest_fds() == fds;
    return ok;
}
static bool history_manifest_cancel_cases(void)
{
    char dir[512], blocks[512], block[512], index[512];
    if (!test_mkdtemp(dir, sizeof(dir), "history_manifest_cancel")) return false;
    int a = snprintf(blocks, sizeof(blocks), "%s/blocks", dir);
    int b = snprintf(block, sizeof(block), "%s/blocks/blk00000.dat", dir);
    int c = snprintf(index, sizeof(index), "%s/block_index.bin", dir);
    bool ok = a > 0 && (size_t)a < sizeof(blocks) && b > 0 && (size_t)b < sizeof(block) &&
        c > 0 && (size_t)c < sizeof(index) && mkdir(blocks, 0700) == 0 &&
        history_manifest_file(block, 262144) && history_manifest_file(index, 32) &&
        history_manifest_parity(dir) && history_manifest_stops(dir, block);
    (void)test_rm_rf_recursive(dir);
    return ok;
}
static bool history_test_equal_prefix(const char *left, const char *right)
{
    FILE *a = fopen(left, "rb"), *b = fopen(right, "rb");
    if (!a || !b) { if (a) fclose(a); if (b) fclose(b); return false; }
    unsigned char x[4096], y[4096];
    bool ok = true;
    size_t n;
    while ((n = fread(y, 1, sizeof(y), b)) != 0) {
        if (fread(x, 1, n, a) != n || memcmp(x, y, n)) { ok = false; break; }
    }
    if (ferror(b)) ok = false;
    if (fclose(a) != 0) ok = false;
    if (fclose(b) != 0) ok = false;
    return ok;
}
static bool history_test_same_stat(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_size == b->st_size &&
        a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec;
}
static bool history_test_output(const char *source, const char *parent,
                                const struct stat *index_before, const struct stat *block_before)
{
    char src[512], dst[512]; struct stat a, b;
    snprintf(src, sizeof(src), "%s/blocks/blk00000.dat", source);
    snprintf(dst, sizeof(dst), "%s/ready/blocks/blk00000.dat", parent);
    if (stat(src, &a) != 0 || stat(dst, &b) != 0 || b.st_size >= a.st_size ||
        !history_test_same_stat(block_before, &a) || !history_test_equal_prefix(src, dst)) return false;
    snprintf(src, sizeof(src), "%s/block_index.bin", source);
    snprintf(dst, sizeof(dst), "%s/ready/block_index.bin", parent);
    return stat(src, &a) == 0 && history_test_same_stat(index_before, &a) &&
        history_test_equal_prefix(src, dst) && history_test_equal_prefix(dst, src);
}
static bool history_test_parent_guard(const char *source, const char *parent)
{
    char nested[512];
    if (snprintf(nested, sizeof(nested), "%s/guard-child", source) >= (int)sizeof(nested) ||
        mkdir(nested, 0700) != 0) return false;
    struct platform_directory_transaction dir;
    platform_directory_transaction_init(&dir);
    bool ok = platform_directory_transaction_open(&dir, nested) &&
              !wallet_history_export_parent_outside_source(source, &dir).ok;
    platform_directory_transaction_close(&dir);
    ok = ok && platform_directory_transaction_open(&dir, parent) &&
         wallet_history_export_parent_outside_source(source, &dir).ok;
    platform_directory_transaction_close(&dir);
    return rmdir(nested) == 0 && ok;
}
static bool history_test_publication_refusals(struct wallet_history_export_request *r,
    const char *source, const char *parent, const struct uint256 *genesis)
{
    struct wallet_history_export_result result;
    r->staging_leaf = "same-root"; r->private_parent = source;
    if (wallet_history_export_test_run(r, &result, genesis).ok) return false;
    char forbidden[512];
    snprintf(forbidden, sizeof(forbidden), "%s/same-root", source);
    if (access(forbidden, F_OK) == 0) return false;
    r->private_parent = parent; r->staging_leaf = "wrong-endpoint"; r->endpoint_hash[0] ^= 1;
    if (wallet_history_export_test_run(r, &result, genesis).ok) return false;
    r->endpoint_hash[0] ^= 1; r->staging_leaf = "stage2";
    if (wallet_history_export_test_run(r, &result, genesis).ok ||
        result.outcome != WALLET_HISTORY_EXPORT_FAILED || result.manifest.num_chunks != 0) return false;
    r->staging_leaf = "cancelled"; r->destination_leaf = "other"; r->cancelled = history_test_cancel;
    return !wallet_history_export_test_run(r, &result, genesis).ok;
}
static bool history_test_reopen(const struct wallet_history_export_request *request,
                                const char *parent, const struct uint256 *genesis)
{
    char root[512], path[512];
    if (snprintf(root, sizeof(root), "%s/ready", parent) >= (int)sizeof(root) ||
        snprintf(path, sizeof(path), "%s/ready/blocks/blk00000.dat", parent) >= (int)sizeof(path) ||
        !wallet_history_export_test_validate_archive(request, root, genesis).ok) return false;
    FILE *f = fopen(path, "r+b");
    if (!f) return false;
    bool ok = fseek(f, 8, SEEK_SET) == 0;
    int byte = ok ? fgetc(f) : EOF;
    ok = ok && byte != EOF && fseek(f, 8, SEEK_SET) == 0 &&
         fputc(byte ^ 1, f) != EOF;
    if (fclose(f) != 0) ok = false;
    if (!ok) return false;
    return !wallet_history_export_test_validate_archive(request, root, genesis).ok;
}
static bool history_test_run_cases(const char *source, const char *parent, const struct uint256 hashes[3])
{
    struct wallet_history_export_request r = {.source_datadir = source, .private_parent = parent,
        .staging_leaf = "stage", .destination_leaf = "ready", .endpoint_height = 1,
        .max_rows = 3, .max_bytes = 1048576, .min_free_bytes = 1};
    memcpy(r.endpoint_hash, hashes[1].data, 32);
    char path[512]; struct stat index_before, block_before;
    snprintf(path, sizeof(path), "%s/block_index.bin", source);
    if (stat(path, &index_before) != 0) return false;
    snprintf(path, sizeof(path), "%s/blocks/blk00000.dat", source);
    if (stat(path, &block_before) != 0) return false;
    struct wallet_history_export_result result;
    struct zcl_result done = wallet_history_export_test_run(&r, &result, &hashes[0]);
    return done.ok && result.outcome == WALLET_HISTORY_EXPORT_PUBLISHED && result.manifest.num_chunks == 2 &&
        history_test_output(source, parent, &index_before, &block_before) &&
        history_test_parent_guard(source, parent) &&
        history_test_reopen(&r, parent, &hashes[0]) &&
        history_test_publication_refusals(&r, source, parent, &hashes[0]);
}
static bool history_test_refusals(const char *source, const char *parent, const struct uint256 hashes[3])
{
    struct wallet_history_export_request r = {.source_datadir = source, .private_parent = parent,
        .staging_leaf = "short", .destination_leaf = "short-ready", .endpoint_height = 1,
        .max_rows = 2, .max_bytes = 1048576, .min_free_bytes = 1};
    memcpy(r.endpoint_hash, hashes[1].data, 32);
    struct wallet_history_export_result out;
    if (wallet_history_export_test_run(&r, &out, &hashes[0]).ok || out.outcome != WALLET_HISTORY_EXPORT_FAILED)
        return false;
    r.staging_leaf = "free-floor"; r.max_rows = 3; r.min_free_bytes = UINT64_MAX;
    if (wallet_history_export_test_run(&r, &out, &hashes[0]).ok) return false;
    r.min_free_bytes = 1;
    r.staging_leaf = "small"; r.max_bytes = 1;
    if (wallet_history_export_test_run(&r, &out, &hashes[0]).ok) return false;
    char target[512], alias[512];
    snprintf(target, sizeof(target), "%s/blocks/blk00000.dat", source);
    snprintf(alias, sizeof(alias), "%s/extra-link", source);
    if (link(target, alias) != 0) return false;
    r.staging_leaf = "linked"; r.max_bytes = 1048576;
    bool refused = !wallet_history_export_test_run(&r, &out, &hashes[0]).ok;
    if (unlink(alias) != 0) return false;
    if (!refused || rename(target, alias) != 0) return false;
    if (symlink("../extra-link", target) != 0) return false;
    r.staging_leaf = "symlink";
    refused = !wallet_history_export_test_run(&r, &out, &hashes[0]).ok;
    if (unlink(target) != 0 || rename(alias, target) != 0) return false;
    return refused;
}
static bool history_test_bad_merkle(const char *parent)
{
    char source[512]; struct uint256 hashes[3] = {0};
    if (!test_mkdtemp(source, sizeof(source), "history_bad_merkle")) return false;
    bool made = history_test_source(source, hashes, true);
    struct wallet_history_export_request r = {.source_datadir = source, .private_parent = parent,
        .staging_leaf = "bad-merkle", .destination_leaf = "bad-ready", .endpoint_height = 1,
        .max_rows = 3, .max_bytes = 1048576, .min_free_bytes = 1};
    memcpy(r.endpoint_hash, hashes[1].data, 32);
    struct wallet_history_export_result out;
    bool refused = made && !wallet_history_export_test_run(&r, &out, &hashes[0]).ok &&
        out.outcome == WALLET_HISTORY_EXPORT_FAILED && out.manifest.num_chunks == 0;
    (void)test_rm_rf_recursive(source);
    return refused;
}
static bool history_test_truncated(const char *source, const char *parent, const struct uint256 hashes[3])
{
    char path[512];
    snprintf(path, sizeof(path), "%s/blocks/blk00000.dat", source);
    if (truncate(path, 1) != 0) return false;
    struct wallet_history_export_request r = {.source_datadir = source, .private_parent = parent,
        .staging_leaf = "truncated", .destination_leaf = "truncated-ready", .endpoint_height = 1,
        .max_rows = 3, .max_bytes = 1048576, .min_free_bytes = 1};
    memcpy(r.endpoint_hash, hashes[1].data, 32);
    struct wallet_history_export_result out;
    return !wallet_history_export_test_run(&r, &out, &hashes[0]).ok &&
        out.outcome == WALLET_HISTORY_EXPORT_FAILED && out.manifest.num_chunks == 0;
}
struct history_probe {
    struct wallet_history_export_request request;
    struct uint256 endpoint;
};
static bool history_probe_decimal(const char *s, uint64_t max, uint64_t *out)
{
    if (!s || !*s || *s < '0' || *s > '9') return false;
    errno = 0; char *end = NULL;
    unsigned long long value = strtoull(s, &end, 10);
    if (errno || !end || *end || value > max) return false;
    *out = (uint64_t)value;
    return true;
}
static bool history_probe_private_dir(const char *path)
{
    char resolved[PATH_MAX]; struct stat st;
    return path && path[0] == '/' && realpath(path, resolved) && !strcmp(path, resolved) &&
        lstat(path, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == geteuid() &&
        (st.st_mode & 0777) == 0700;
}
static bool history_probe_leaf(const char *s)
{
    return s && s[0] && strcmp(s, ".") && strcmp(s, "..") && !strchr(s, '/');
}
static bool history_probe_bounds(uint64_t *rows, uint64_t *height, uint64_t *bytes, uint64_t *free_bytes)
{
    return history_probe_decimal(getenv("ZCL_HISTORY_ARCHIVE_MAX_ROWS"), 10000000, rows) && *rows &&
        history_probe_decimal(getenv("ZCL_HISTORY_ARCHIVE_HEIGHT"), INT_MAX - 1, height) && *height < *rows &&
        history_probe_decimal(getenv("ZCL_HISTORY_EXPORT_MAX_BYTES"), UINT64_MAX, bytes) && *bytes &&
        history_probe_decimal(getenv("ZCL_HISTORY_EXPORT_MIN_FREE_BYTES"), UINT64_MAX, free_bytes) && *free_bytes;
}
static bool history_probe_read(struct history_probe *p)
{
    const char *source = getenv("ZCL_HISTORY_ARCHIVE_DIR");
    const char *hash = getenv("ZCL_HISTORY_ARCHIVE_HASH");
    const char *parent = getenv("ZCL_HISTORY_EXPORT_PARENT");
    const char *stage = getenv("ZCL_HISTORY_EXPORT_STAGE");
    const char *destination = getenv("ZCL_HISTORY_EXPORT_DEST");
    uint64_t rows = 0, height = 0, bytes = 0, free_bytes = 0;
    if (!history_probe_private_dir(source) || !history_probe_private_dir(parent) ||
        !hash || strlen(hash) != 64 || !IsHex(hash) || !history_probe_leaf(stage) || !history_probe_leaf(destination) || !strcmp(stage, destination) ||
        !history_probe_bounds(&rows, &height, &bytes, &free_bytes))
        return false;
    uint256_set_hex(&p->endpoint, hash);
    p->request = (struct wallet_history_export_request){.source_datadir = source, .private_parent = parent,
        .staging_leaf = stage, .destination_leaf = destination, .endpoint_height = (int32_t)height,
        .max_rows = (size_t)rows, .max_bytes = bytes, .min_free_bytes = free_bytes};
    memcpy(p->request.endpoint_hash, p->endpoint.data, 32);
    return true;
}
static int64_t history_probe_time_ms(const struct timespec *t)
{ return (int64_t)t->tv_sec * 1000 + t->tv_nsec / 1000000; }
static int64_t history_probe_cpu_us(const struct rusage *r)
{
    return (int64_t)r->ru_utime.tv_sec * 1000000 + r->ru_utime.tv_usec +
        (int64_t)r->ru_stime.tv_sec * 1000000 + r->ru_stime.tv_usec;
}
static int history_export_probe(void)
{
    struct history_probe input = {0};
    if (!history_probe_read(&input)) { fputs("history export probe: invalid configuration\n", stderr); return 1; }
    struct timespec start, end; struct rusage before, after;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0 || getrusage(RUSAGE_SELF, &before) != 0) return 1;
    struct wallet_history_export_result out;
    struct zcl_result result = wallet_history_export_run(&input.request, &out);
    if (clock_gettime(CLOCK_MONOTONIC, &end) != 0 || getrusage(RUSAGE_SELF, &after) != 0) return 1;
    char root[65]; HexStr(out.manifest.root_hash, 32, false, root, sizeof(root));
    printf("{\"probe\":\"wallet_history_export\",\"ok\":%s,\"outcome\":%d,\"height\":%d,\"endpoint_hash\":\"%s\",\"max_rows\":%zu,\"max_bytes\":%" PRIu64 ",\"min_free_bytes\":%" PRIu64 ",\"elapsed_ms\":%" PRId64
           ",\"cpu_us\":%" PRId64 ",\"peak_rss_kib\":%ld,\"chunks\":%u,\"bytes\":%" PRIu64
           ",\"manifest_root\":\"%s\"}\n", result.ok ? "true" : "false", (int)out.outcome, input.request.endpoint_height,
           getenv("ZCL_HISTORY_ARCHIVE_HASH"), input.request.max_rows, input.request.max_bytes,
           input.request.min_free_bytes, history_probe_time_ms(&end) - history_probe_time_ms(&start),
           history_probe_cpu_us(&after) - history_probe_cpu_us(&before), after.ru_maxrss,
           out.manifest.num_chunks, out.manifest.total_bytes, root);
    if (!result.ok) fprintf(stderr, "history export probe refused: %s\n", result.message);
    return result.ok && out.outcome == WALLET_HISTORY_EXPORT_PUBLISHED ? 0 : 1;
}
static bool history_export_probe_requested(void)
{
    return getenv("ZCL_HISTORY_EXPORT_PARENT") || getenv("ZCL_HISTORY_EXPORT_STAGE") ||
        getenv("ZCL_HISTORY_EXPORT_DEST") || getenv("ZCL_HISTORY_EXPORT_MAX_BYTES") ||
        getenv("ZCL_HISTORY_EXPORT_MIN_FREE_BYTES");
}
static int history_export_probe_child(void)
{
    fflush(NULL);
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        chain_params_select(CHAIN_MAIN);
        int rc = history_export_probe();
        if (fflush(stdout) != 0) rc = 1;
        _exit(rc);
    }
    int status; pid_t waited;
    do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    return waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 1;
}
static bool history_probe_parser_test(void)
{
    uint64_t parsed = 0;
    return history_probe_decimal("123", 123, &parsed) && parsed == 123 &&
        !history_probe_decimal("-1", UINT64_MAX, &parsed) &&
        !history_probe_decimal("123x", UINT64_MAX, &parsed) &&
        !history_probe_decimal("18446744073709551616", UINT64_MAX, &parsed) &&
        !history_probe_leaf("../unsafe") && !history_probe_leaf(".");
}
static bool history_manifest_and_probe(void)
{ return history_manifest_cancel_cases() && history_probe_parser_test(); }

int test_wallet_history_export(void)
{
    const char *network = chain_params_get()->strNetworkID;
    enum chain_network previous = !strcmp(network, "regtest") ? CHAIN_REGTEST :
        !strcmp(network, "test") ? CHAIN_TESTNET : CHAIN_MAIN;
    chain_params_select(CHAIN_REGTEST);
    char source[512], parent[512]; struct uint256 hashes[3] = {0};
    if (!test_mkdtemp(source, sizeof(source), "history_source")) {
        chain_params_select(previous); return 1;
    }
    if (!test_mkdtemp(parent, sizeof(parent), "history_export")) {
        (void)test_rm_rf_recursive(source); chain_params_select(previous); return 1;
    }
    bool ok = history_manifest_and_probe() && history_test_source(source, hashes, false) && history_test_run_cases(source, parent, hashes) &&
        history_test_refusals(source, parent, hashes) && history_test_bad_merkle(parent) &&
        history_test_truncated(source, parent, hashes);
    (void)test_rm_rf_recursive(source); (void)test_rm_rf_recursive(parent);
    chain_params_select(previous);
    printf("wallet history export: %s\n", ok ? "PASS" : "FAIL");
    if (!ok) return 1;
    if (history_export_probe_requested() && history_export_probe_child() != 0) return 1;
    return ok ? 0 : 1;
}
#else
int test_wallet_history_export(void) { printf("SKIP (Linux-only history export)\n"); return 0; }
#endif
