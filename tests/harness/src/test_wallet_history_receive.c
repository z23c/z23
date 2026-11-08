/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/wallet_history_receive.h"
#include "services/wallet_history_manifest.h"
#include "config/state_offer_service.h"
#include "config/state_offer_store.h"
#include "config/consensus_state_install_runtime.h"
#include "crypto/sha3.h"
#include "net/file_service.h"
#include "net/file_service_generation.h"
#include "platform/directory_transaction.h"
#include "platform/time_compat.h"
#include "test/test_core.h"
#include <stdio.h>
#include <stdatomic.h>
#include <string.h>
#if !defined(_WIN32)
#include <arpa/inet.h>
#include <dirent.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

int test_wallet_history_receive(void);
void wallet_history_receiver_error_hook_for_test(void (*hook)(void *), void *context);
#if !defined(_WIN32)
struct zcl_result wallet_history_receiver_required_for_test(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t *);
struct zcl_result wallet_history_receiver_prefix_for_test(struct wallet_history_receiver *, const char *,
    const struct file_manifest *, uint32_t *, uint64_t *);
void wallet_history_receiver_before_transfer_for_test(struct wallet_history_receiver *, void (*)(void *), void *);
#endif

#if !defined(_WIN32)
struct receive_fixture {
    char server[512], parent[512];
    struct file_manifest manifest;
    uint8_t snapshot[32], endpoint[32];
    uint16_t port;
    bool server_dir, parent_dir, server_started;
};

static bool receive_file(const char *path, const char *bytes, size_t size)
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool ok = fwrite(bytes, 1, size, f) == size;
    if (fclose(f) != 0) ok = false;
    return chmod(path, 0600) == 0 && ok;
}

static bool receive_capacity_cases(void)
{
    uint64_t required = 0;
    return wallet_history_receiver_required_for_test(10, 20, 100, 0, &required).ok &&
        required == 130 &&
        wallet_history_receiver_required_for_test(10, 20, 100, 70, &required).ok &&
        required == 60 &&
        wallet_history_receiver_required_for_test(10, 20, 100, 100, &required).ok &&
        required == 30 &&
        !wallet_history_receiver_required_for_test(UINT64_MAX, 1, 0, 0, &required).ok &&
        !wallet_history_receiver_required_for_test(UINT64_MAX, 0, 1, 0, &required).ok &&
        !wallet_history_receiver_required_for_test(1, 1, 100, 101, &required).ok;
}

static bool receive_fixture_files(struct receive_fixture *f)
{
    char blocks[600], block[640], index[600];
    if (snprintf(blocks, sizeof(blocks), "%s/blocks", f->server) >= (int)sizeof(blocks) ||
        snprintf(block, sizeof(block), "%s/blk00000.dat", blocks) >= (int)sizeof(block) ||
        snprintf(index, sizeof(index), "%s/block_index.bin", f->server) >= (int)sizeof(index) ||
        mkdir(blocks, 0700) != 0) return false;
    return receive_file(block, "abc", 3) && receive_file(index, "index", 5) &&
        wallet_history_manifest_build(&f->manifest, f->server, 1).ok;
}

static bool receive_fixture_start(struct receive_fixture *f)
{
    memset(f, 0, sizeof(*f));
    if (!test_mkdtemp(f->server, sizeof(f->server), "history_receive_server")) return false;
    f->server_dir = true;
    if (!test_mkdtemp(f->parent, sizeof(f->parent), "history_receive_parent")) return false;
    f->parent_dir = true;
    if (!receive_fixture_files(f)) return false;
    struct platform_directory_transaction root;
    struct fs_history_generation generation;
    platform_directory_transaction_init(&root); fs_history_generation_init(&generation);
    f->snapshot[0] = 1; f->endpoint[0] = 2; f->manifest.chain_height = 1;
    bool ok = platform_directory_transaction_open(&root, f->server) &&
        fs_history_generation_take(&generation, &root, &f->manifest, f->snapshot, 1, f->endpoint) &&
        fs_server_start_with_history(&generation, f->server, 0, "127.0.0.1");
    platform_directory_transaction_close(&root); fs_history_generation_close(&generation);
    if (!ok) return false;
    f->server_started = true;
    char address[64];
    for (int i = 0; i < 2000; i++) {
        if (fs_server_listener_name(address, sizeof(address), &f->port) && f->port) return true;
        platform_sleep_ms(1); /* real-clock: loopback listener startup uses kernel thread scheduling */
    }
    return false;
}

static void receive_fixture_close(struct receive_fixture *f)
{
    if (f->server_started) fs_server_stop();
    if (f->server_dir) (void)test_rm_rf_recursive(f->server);
    if (f->parent_dir) (void)test_rm_rf_recursive(f->parent);
}

static struct wallet_history_receive_request receive_request(const struct receive_fixture *f,
                                                               const char *parent)
{
    struct wallet_history_receive_request request = {
        .peer = "127.0.0.1", .port = f->port, .private_parent = parent,
        .max_bytes = 1048576, .min_free_bytes = 1, .reserved_install_bytes = 1,
    };
    memcpy(request.snapshot_digest, f->snapshot, 32);
    memcpy(request.history_root, f->manifest.root_hash, 32);
    return request;
}

static bool receive_cancel_case(const struct receive_fixture *f)
{
    struct wallet_history_receive_request request = receive_request(f, f->parent);
    struct wallet_history_receiver *receiver = NULL;
    struct wallet_history_receive_result out;
    wallet_history_receive_result_init(&out);
    bool ok = wallet_history_receiver_create(&request, &receiver).ok;
    if (ok) wallet_history_receiver_cancel(receiver);
    ok = ok && !wallet_history_receiver_run(receiver, &out).ok &&
        out.outcome == WALLET_HISTORY_RECEIVE_STOPPED && out.parent.native == UINTPTR_MAX;
    wallet_history_receiver_destroy(&receiver); wallet_history_receive_result_close(&out);
    return ok;
}

struct receive_blocked_probe {
    int listener;
    _Atomic bool accepted, peer_eof, client_done;
    struct wallet_history_receiver *receiver;
    struct wallet_history_receive_result result;
    bool returned_ok;
    pthread_t server, client;
    bool server_started, client_started;
};

static bool receive_only_lock(const char *parent)
{
    DIR *dir = opendir(parent);
    if (!dir) return false;
    unsigned locks = 0;
    bool ok = true;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        const char *name = entry->d_name;
        if (!strcmp(name, ".") || !strcmp(name, "..")) continue;
        size_t len = strlen(name);
        if (len < 5 || strcmp(name + len - 5, "-lock")) { ok = false; break; }
        locks++;
    }
    if (closedir(dir) != 0) ok = false;
    return ok && locks == 1;
}

static void *receive_blocked_server(void *context)
{
    struct receive_blocked_probe *f = context;
    struct pollfd ready = {.fd = f->listener, .events = POLLIN};
    if (poll(&ready, 1, 3000) <= 0) return NULL;
    int fd = accept(f->listener, NULL, NULL);
    if (fd < 0) return NULL;
    atomic_store(&f->accepted, true);
    char bytes[128];
    ssize_t n;
    while ((n = recv(fd, bytes, sizeof(bytes), 0)) > 0) {}
    atomic_store(&f->peer_eof, n == 0);
    close(fd);
    return NULL;
}

static void *receive_blocked_client(void *context)
{
    struct receive_blocked_probe *f = context;
    f->returned_ok = wallet_history_receiver_run(f->receiver, &f->result).ok;
    atomic_store(&f->client_done, true);
    return NULL;
}

static bool receive_blocked_listen(struct receive_blocked_probe *f, uint16_t *port)
{
    f->listener = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t length = sizeof(address);
    bool ok = f->listener >= 0 && bind(f->listener, (struct sockaddr *)&address, length) == 0 &&
        listen(f->listener, 1) == 0 && getsockname(f->listener, (struct sockaddr *)&address, &length) == 0;
    if (ok) *port = ntohs(address.sin_port);
    return ok;
}

static bool receive_blocked_launch(struct receive_blocked_probe *f, const struct receive_fixture *fixture)
{
    struct wallet_history_receive_request request = receive_request(fixture, fixture->parent);
    if (!receive_blocked_listen(f, &request.port) ||
        !wallet_history_receiver_create(&request, &f->receiver).ok) return false;
    f->server_started = pthread_create(&f->server, NULL, receive_blocked_server, f) == 0;
    if (!f->server_started) return false;
    f->client_started = pthread_create(&f->client, NULL, receive_blocked_client, f) == 0;
    return f->client_started;
}

static bool receive_wait_flag(_Atomic bool *flag, int milliseconds)
{
    for (int i = 0; i < milliseconds && !atomic_load(flag); i++)
        platform_sleep_ms(1); /* real-clock: blocked socket cancellation uses kernel thread scheduling */
    return atomic_load(flag);
}

static bool receive_blocked_cancel_case(const struct receive_fixture *fixture)
{
    struct receive_blocked_probe f = {.listener = -1};
    wallet_history_receive_result_init(&f.result);
    bool ok = receive_blocked_launch(&f, fixture);
    ok = ok && receive_wait_flag(&f.accepted, 2000);
    wallet_history_receiver_cancel(f.receiver);
    bool completed = f.client_started && receive_wait_flag(&f.client_done, 3000);
    if (f.client_started) pthread_join(f.client, NULL);
    if (f.server_started) pthread_join(f.server, NULL);
    if (f.listener >= 0) close(f.listener);
    ok = ok && completed && atomic_load(&f.peer_eof) && !f.returned_ok &&
        f.result.outcome == WALLET_HISTORY_RECEIVE_ERROR && f.result.root.native == UINTPTR_MAX &&
        receive_only_lock(fixture->parent);
    wallet_history_receiver_destroy(&f.receiver); wallet_history_receive_result_close(&f.result);
    return ok;
}

static bool receive_wrong_root_case(const struct receive_fixture *f)
{
    struct wallet_history_receive_request request = receive_request(f, f->parent);
    request.history_root[0] ^= 1;
    struct wallet_history_receiver *receiver = NULL;
    struct wallet_history_receive_result out;
    wallet_history_receive_result_init(&out);
    bool ok = wallet_history_receiver_create(&request, &receiver).ok &&
        !wallet_history_receiver_run(receiver, &out).ok &&
        out.outcome == WALLET_HISTORY_RECEIVE_ERROR && out.parent.native == UINTPTR_MAX;
    wallet_history_receiver_destroy(&receiver); wallet_history_receive_result_close(&out);
    return ok;
}

static void receive_cancel_after_error(void *context)
{
    wallet_history_receiver_cancel(context);
}

static bool receive_error_then_cancel_case(const struct receive_fixture *f)
{
    struct wallet_history_receive_request request = receive_request(f, f->parent);
    request.history_root[0] ^= 1;
    struct wallet_history_receiver *receiver = NULL;
    struct wallet_history_receive_result out;
    wallet_history_receive_result_init(&out);
    bool ok = wallet_history_receiver_create(&request, &receiver).ok;
    if (ok) wallet_history_receiver_error_hook_for_test(receive_cancel_after_error, receiver);
    if (ok) ok = !wallet_history_receiver_run(receiver, &out).ok &&
        out.outcome == WALLET_HISTORY_RECEIVE_ERROR;
    wallet_history_receiver_error_hook_for_test(NULL, NULL);
    wallet_history_receiver_destroy(&receiver); wallet_history_receive_result_close(&out);
    return ok;
}

static bool receive_retained_files(struct wallet_history_receive_result *out)
{
    struct platform_directory_transaction blocks;
    struct platform_directory_child block, index;
    platform_directory_transaction_init(&blocks);
    platform_directory_child_init(&block); platform_directory_child_init(&index);
    char bytes[5] = {0};
    bool ok = platform_directory_transaction_open_child(&out->root, "blocks", false, &blocks) ==
        PLATFORM_DIRECTORY_OK && platform_directory_child_open(&blocks, "blk00000.dat", &block) &&
        platform_directory_child_read_exact(&block, bytes, 3, 0) && memcmp(bytes, "abc", 3) == 0 &&
        platform_directory_child_open(&out->root, "block_index.bin", &index) &&
        platform_directory_child_read_exact(&index, bytes, 5, 0) && memcmp(bytes, "index", 5) == 0;
    platform_directory_child_close(&index); platform_directory_child_close(&block);
    platform_directory_transaction_close(&blocks);
    return ok;
}

static bool receive_occupied_result_case(const struct receive_fixture *f,
                                         struct wallet_history_receive_result *out)
{
    struct wallet_history_receive_request request = receive_request(f, f->parent);
    struct wallet_history_receiver *receiver = NULL;
    uintptr_t root = out->root.native, lease = out->lease.native;
    bool ok = wallet_history_receiver_create(&request, &receiver).ok &&
        !wallet_history_receiver_run(receiver, out).ok &&
        out->outcome == WALLET_HISTORY_RECEIVE_COMPLETE && out->root.native == root &&
        out->lease.native == lease;
    wallet_history_receiver_destroy(&receiver);
    return ok;
}

static bool receive_complete_case(const struct receive_fixture *f, char root_leaf[256])
{
    struct wallet_history_receive_request request = receive_request(f, f->parent);
    struct wallet_history_receiver *receiver = NULL;
    struct wallet_history_receive_result out;
    wallet_history_receive_result_init(&out);
    bool ok = wallet_history_receiver_create(&request, &receiver).ok &&
        wallet_history_receiver_run(receiver, &out).ok &&
        out.outcome == WALLET_HISTORY_RECEIVE_COMPLETE && out.block_files == 1 &&
        memcmp(out.history_root, f->manifest.root_hash, 32) == 0 && receive_retained_files(&out) &&
        receive_occupied_result_case(f, &out);
    struct platform_directory_lock second;
    platform_directory_lock_init(&second);
    if (ok) ok = platform_directory_lock_acquire(&out.parent, out.lock_leaf, false,
        PLATFORM_DIRECTORY_LOCK_EXCLUSIVE, &second) == PLATFORM_DIRECTORY_REFUSED;
    platform_directory_lock_release(&second);
    if (ok) memcpy(root_leaf, out.root_leaf, strlen(out.root_leaf) + 1);
    wallet_history_receiver_destroy(&receiver); wallet_history_receive_result_close(&out);
    return ok;
}

static bool receive_existing_case(const struct receive_fixture *f)
{
    struct wallet_history_receive_request request = receive_request(f, f->parent);
    struct wallet_history_receiver *receiver = NULL;
    struct wallet_history_receive_result out;
    wallet_history_receive_result_init(&out);
    bool ok = wallet_history_receiver_create(&request, &receiver).ok &&
        wallet_history_receiver_run(receiver, &out).ok &&
        out.outcome == WALLET_HISTORY_RECEIVE_COMPLETE && receive_retained_files(&out);
    struct platform_directory_names names = {0};
    if (ok) ok = platform_directory_transaction_list_regular(&out.root, &names) &&
        names.count == 1 && strcmp(names.items[0], "block_index.bin") == 0;
    platform_directory_names_free(&names);
    wallet_history_receiver_destroy(&receiver); wallet_history_receive_result_close(&out);
    return ok;
}

static bool receive_existing_refused(const struct receive_fixture *f)
{
    struct wallet_history_receive_request request = receive_request(f, f->parent);
    struct wallet_history_receiver *receiver = NULL;
    struct wallet_history_receive_result out;
    wallet_history_receive_result_init(&out);
    bool ok = wallet_history_receiver_create(&request, &receiver).ok &&
        !wallet_history_receiver_run(receiver, &out).ok &&
        out.outcome == WALLET_HISTORY_RECEIVE_ERROR && out.root.native == UINTPTR_MAX;
    wallet_history_receiver_destroy(&receiver); wallet_history_receive_result_close(&out);
    return ok;
}

static bool receive_existing_corruption(const struct receive_fixture *f, const char *root_leaf)
{
    char root[1024], extra[1100], index[1100];
    if (snprintf(root, sizeof(root), "%s/%s", f->parent, root_leaf) >= (int)sizeof(root) ||
        snprintf(extra, sizeof(extra), "%s/unexpected", root) >= (int)sizeof(extra) ||
        snprintf(index, sizeof(index), "%s/block_index.bin", root) >= (int)sizeof(index) ||
        mkdir(extra, 0700) != 0) return false;
    bool ok = receive_existing_refused(f) && access(extra, F_OK) == 0;
    if (rmdir(extra) != 0) ok = false;
    if (truncate(index, 1) != 0) return false;
    struct stat st;
    return ok && receive_existing_refused(f) && stat(index, &st) == 0 && st.st_size == 1;
}

static bool receive_resume_prepare(const char *parent, const char *root_leaf, ino_t *inode)
{
    char stage[1024], blocks[1100], block[1150], index[1100];
    if (snprintf(stage, sizeof(stage), "%s/.%s-stage", parent, root_leaf) >= (int)sizeof(stage) ||
        snprintf(blocks, sizeof(blocks), "%s/blocks", stage) >= (int)sizeof(blocks) ||
        snprintf(block, sizeof(block), "%s/blk00000.dat", blocks) >= (int)sizeof(block) ||
        snprintf(index, sizeof(index), "%s/block_index.bin", stage) >= (int)sizeof(index) ||
        mkdir(stage, 0700) != 0 || mkdir(blocks, 0700) != 0 ||
        !receive_file(block, "abc", 3) || !receive_file(index, "", 0)) return false;
    struct stat st;
    if (stat(block, &st) != 0) return false;
    *inode = st.st_ino;
    return true;
}

static bool receive_credit_read(struct wallet_history_receiver *receiver, const char *stage,
    const struct file_manifest *manifest, uint32_t expected_chunks, uint64_t expected_bytes)
{
    uint32_t chunks = UINT32_MAX;
    uint64_t bytes = UINT64_MAX;
    return wallet_history_receiver_prefix_for_test(receiver, stage, manifest, &chunks, &bytes).ok &&
           chunks == expected_chunks && bytes == expected_bytes;
}

static bool receive_large_prefix(const char *path, uint8_t digest[32])
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    uint8_t buffer[4096]; memset(buffer, 'A', sizeof(buffer));
    struct sha3_256_ctx hash; sha3_256_init(&hash);
    bool ok = true;
    for (unsigned i = 0; i < 16; i++) {
        if (fwrite(buffer, 1, sizeof(buffer), f) != sizeof(buffer)) { ok = false; break; }
        sha3_256_write(&hash, buffer, sizeof(buffer));
    }
    if (fclose(f) != 0 || chmod(path, 0600) != 0) ok = false;
    if (ok) sha3_256_finalize(&hash, digest);
    return ok;
}

static bool receive_nearcomplete_case(const struct receive_fixture *f)
{
    char parent[512], stage[600], blocks[640], block[700], index[640];
    if (!test_mkdtemp(parent, sizeof(parent), "history_receive_nearcomplete")) return false;
    bool ok = snprintf(stage, sizeof(stage), "%s/stage", parent) < (int)sizeof(stage) &&
        snprintf(blocks, sizeof(blocks), "%s/blocks", stage) < (int)sizeof(blocks) &&
        snprintf(block, sizeof(block), "%s/blk00000.dat", blocks) < (int)sizeof(block) &&
        snprintf(index, sizeof(index), "%s/block_index.bin", stage) < (int)sizeof(index) &&
        mkdir(stage, 0700) == 0 && mkdir(blocks, 0700) == 0;
    struct file_manifest manifest = {.num_chunks = 2, .total_bytes = 65537};
    manifest.chunks[0].size = 65536; manifest.chunks[1].size = 1; manifest.chunks[1].file_index = 253;
    if (ok) ok = receive_large_prefix(block, manifest.chunks[0].sha3) && receive_file(index, "", 0);
    sha3_256((const uint8_t *)"B", 1, manifest.chunks[1].sha3);
    struct sha3_256_ctx hash; sha3_256_init(&hash);
    sha3_256_write(&hash, manifest.chunks[0].sha3, 32);
    sha3_256_write(&hash, manifest.chunks[1].sha3, 32);
    sha3_256_finalize(&hash, manifest.root_hash);
    struct wallet_history_receive_request request = receive_request(f, parent);
    memcpy(request.history_root, manifest.root_hash, 32);
    struct wallet_history_receiver *receiver = NULL;
    uint64_t required = 0;
    if (ok) ok = wallet_history_receiver_create(&request, &receiver).ok &&
        receive_credit_read(receiver, stage, &manifest, 1, 65536) &&
        wallet_history_receiver_required_for_test(10, 20, 65537, 65536, &required).ok && required == 31;
    wallet_history_receiver_destroy(&receiver);
    return test_rm_rf_recursive(parent) == 0 && ok;
}

static bool receive_sparse_file(const char *path)
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool ok = ftruncate(fileno(f), 3) == 0;
    if (fclose(f) != 0) ok = false;
    return ok;
}

static bool receive_credit_variants(struct wallet_history_receiver *receiver, const char *stage,
    const char *block, const char *index, const struct file_manifest *manifest)
{
    return receive_credit_read(receiver, stage, manifest, 1, 3) &&
        receive_file(block, "xxx", 3) && receive_credit_read(receiver, stage, manifest, 0, 0) &&
        receive_sparse_file(block) && receive_credit_read(receiver, stage, manifest, 0, 0) &&
        unlink(block) == 0 && receive_credit_read(receiver, stage, manifest, 0, 0) &&
        receive_file(block, "abc", 3) && receive_file(index, "index", 5) &&
        receive_credit_read(receiver, stage, manifest, 2, 8);
}

static bool receive_credit_case(const struct receive_fixture *f, const char *root_leaf)
{
    char parent[512], stage[1024], block[1150], index[1100];
    if (!test_mkdtemp(parent, sizeof(parent), "history_receive_credit")) return false;
    ino_t inode;
    bool ok = receive_resume_prepare(parent, root_leaf, &inode) &&
        snprintf(stage, sizeof(stage), "%s/.%s-stage", parent, root_leaf) < (int)sizeof(stage) &&
        snprintf(block, sizeof(block), "%s/blocks/blk00000.dat", stage) < (int)sizeof(block) &&
        snprintf(index, sizeof(index), "%s/block_index.bin", stage) < (int)sizeof(index);
    struct wallet_history_receive_request request = receive_request(f, parent);
    struct wallet_history_receiver *receiver = NULL;
    if (ok) ok = wallet_history_receiver_create(&request, &receiver).ok &&
        receive_credit_variants(receiver, stage, block, index, &f->manifest);
    if (ok) {
        wallet_history_receiver_cancel(receiver);
        uint32_t chunks = 0; uint64_t bytes = 0;
        struct zcl_result stopped = wallet_history_receiver_prefix_for_test(
            receiver, stage, &f->manifest, &chunks, &bytes);
        ok = !stopped.ok && stopped.code == -3;
    }
    wallet_history_receiver_destroy(&receiver);
    return test_rm_rf_recursive(parent) == 0 && ok;
}

struct receive_mutation { const char *path; bool changed; };
static void receive_mutate_prefix(void *context)
{
    struct receive_mutation *mutation = context;
    mutation->changed = receive_file(mutation->path, "xxx", 3);
}

static bool receive_corrupt_prefix_preserved(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    char bytes[3];
    bool ok = fread(bytes, 1, sizeof(bytes), f) == sizeof(bytes) && !memcmp(bytes, "xxx", 3);
    if (fclose(f) != 0) ok = false;
    return ok;
}

static bool receive_credit_guard_case(const struct receive_fixture *f, const char *root_leaf)
{
    char parent[512], stage[1024], block[1150], index[1100];
    if (!test_mkdtemp(parent, sizeof(parent), "history_receive_credit_guard")) return false;
    ino_t inode;
    bool ok = receive_resume_prepare(parent, root_leaf, &inode) &&
        snprintf(stage, sizeof(stage), "%s/.%s-stage", parent, root_leaf) < (int)sizeof(stage) &&
        snprintf(block, sizeof(block), "%s/blocks/blk00000.dat", stage) < (int)sizeof(block) &&
        snprintf(index, sizeof(index), "%s/block_index.bin", stage) < (int)sizeof(index);
    struct wallet_history_receive_request request = receive_request(f, parent);
    struct wallet_history_receiver *receiver = NULL;
    struct wallet_history_receive_result out;
    wallet_history_receive_result_init(&out);
    struct receive_mutation mutation = {.path = block};
    if (ok) ok = wallet_history_receiver_create(&request, &receiver).ok;
    if (ok) wallet_history_receiver_before_transfer_for_test(receiver, receive_mutate_prefix, &mutation);
    if (ok) ok = !wallet_history_receiver_run(receiver, &out).ok && mutation.changed &&
        out.outcome == WALLET_HISTORY_RECEIVE_ERROR && out.root.native == UINTPTR_MAX;
    struct stat st;
    if (ok) ok = stat(index, &st) == 0 && st.st_size == 0 && receive_corrupt_prefix_preserved(block);
    wallet_history_receiver_destroy(&receiver); wallet_history_receive_result_close(&out);
    return test_rm_rf_recursive(parent) == 0 && ok;
}

static bool receive_resume_case(const struct receive_fixture *f, const char *root_leaf)
{
    char parent[512];
    if (!test_mkdtemp(parent, sizeof(parent), "history_receive_resume")) return false;
    ino_t before = 0;
    bool ok = receive_resume_prepare(parent, root_leaf, &before);
    struct wallet_history_receive_request request = receive_request(f, parent);
    struct wallet_history_receiver *receiver = NULL;
    struct wallet_history_receive_result out;
    wallet_history_receive_result_init(&out);
    if (ok) ok = wallet_history_receiver_create(&request, &receiver).ok &&
        wallet_history_receiver_run(receiver, &out).ok && receive_retained_files(&out);
    struct platform_directory_transaction blocks;
    struct platform_directory_child file;
    struct platform_directory_child_info info;
    platform_directory_transaction_init(&blocks); platform_directory_child_init(&file);
    if (ok) ok = platform_directory_transaction_open_child(&out.root, "blocks", false, &blocks) ==
        PLATFORM_DIRECTORY_OK && platform_directory_child_open(&blocks, "blk00000.dat", &file) &&
        platform_directory_child_info(&file, &info) && info.file_low == (uint64_t)before;
    platform_directory_child_close(&file); platform_directory_transaction_close(&blocks);
    wallet_history_receiver_destroy(&receiver); wallet_history_receive_result_close(&out);
    return test_rm_rf_recursive(parent) == 0 && ok;
}

static bool receive_unknown_case(const struct receive_fixture *f, const char *root_leaf)
{
    char parent[512], published[1024];
    if (!test_mkdtemp(parent, sizeof(parent), "history_receive_unknown")) return false;
    struct wallet_history_receive_request request = receive_request(f, parent);
    struct wallet_history_receiver *receiver = NULL;
    struct wallet_history_receive_result out;
    wallet_history_receive_result_init(&out);
    bool ok = wallet_history_receiver_create(&request, &receiver).ok;
    if (ok) platform_directory_transaction_move_directory_test_fail_durability_once();
    if (ok) ok = !wallet_history_receiver_run(receiver, &out).ok &&
        out.outcome == WALLET_HISTORY_RECEIVE_UNKNOWN && out.root.native == UINTPTR_MAX;
    wallet_history_receiver_destroy(&receiver); wallet_history_receive_result_close(&out);
    if (ok) ok = snprintf(published, sizeof(published), "%s/%s", parent, root_leaf) < (int)sizeof(published) &&
        access(published, F_OK) == 0;
    if (ok) ok = wallet_history_receiver_create(&request, &receiver).ok &&
        wallet_history_receiver_run(receiver, &out).ok &&
        out.outcome == WALLET_HISTORY_RECEIVE_COMPLETE && receive_retained_files(&out);
    wallet_history_receiver_destroy(&receiver); wallet_history_receive_result_close(&out);
    return test_rm_rf_recursive(parent) == 0 && ok;
}

static bool receive_credit_suite(const struct receive_fixture *f, const char *root_leaf)
{
    bool resume = receive_resume_case(f, root_leaf);
    bool nearcomplete = receive_nearcomplete_case(f);
    bool credit = receive_credit_case(f, root_leaf);
    bool guard = receive_credit_guard_case(f, root_leaf);
    printf("receive credit: resume=%d nearcomplete=%d credit=%d guard=%d\n",
           resume, nearcomplete, credit, guard);
    return resume && nearcomplete && credit && guard;
}

static bool receive_request_matches(const struct receive_fixture *f, const char *datadir,
                                    const char *landed)
{
    struct boot_bound_bundle_observation observation;
    return boot_install_bound_bundle_read(datadir, &observation) == BOOT_BOUND_READ_READY &&
        observation.attempts == 0 && observation.endpoint_height == 1 &&
        !memcmp(observation.snapshot_sha3, f->snapshot, 32) &&
        !memcmp(observation.endpoint_hash, f->endpoint, 32) &&
        !memcmp(observation.history_manifest_root, f->manifest.root_hash, 32) &&
        !strcmp(observation.bundle_path, landed);
}

static bool receive_orchestration_case(const struct receive_fixture *f)
{
    char datadir[512], parent[600], landed[600];
    if (!test_mkdtemp(datadir, sizeof(datadir), "history_offer_orchestration")) return false;
    bool ok = snprintf(parent, sizeof(parent), "%s/inbox", datadir) < (int)sizeof(parent) &&
        snprintf(landed, sizeof(landed), "%s/snapshot.sqlite", datadir) < (int)sizeof(landed) &&
        mkdir(parent, 0700) == 0 && receive_file(landed, "snapshot", 8);
    struct state_offer_record target = {.file_service_port = f->port};
    target.peer_ip[10] = target.peer_ip[11] = 0xff;
    target.peer_ip[12] = 127; target.peer_ip[15] = 1;
    target.offer.bundle_height = 1;
    target.offer.content_bytes = 3;
    memcpy(target.offer.content_digest, f->snapshot, 32);
    memcpy(target.offer.header_hash, f->endpoint, 32);
    struct wallet_history_receive_result history;
    wallet_history_receive_result_init(&history);
    state_offer_service_start(datadir, NULL);
    bool fetched = ok && state_offer_service_test_history_fetch(&target, parent, &history);
    bool armed = fetched && state_offer_service_test_arm_bound(landed, &target.offer, parent, &history);
    printf("receive orchestration: setup=%d fetched=%d armed=%d height=%d\n",
           ok, fetched, armed, history.manifest.chain_height);
    ok = fetched && armed;
    if (ok) ok = receive_request_matches(f, datadir, landed);
    boot_install_bundle_clear(datadir);
    wallet_history_receive_result_close(&history);
    state_offer_service_shutdown();
    return test_rm_rf_recursive(datadir) == 0 && ok;
}

int test_wallet_history_receive(void)
{
    struct receive_fixture f;
    fs_server_stop();
    bool started = receive_fixture_start(&f);
    bool ok = started;
    char root_leaf[256] = {0};
    bool capacity = ok && receive_capacity_cases();
    bool cancel = capacity && receive_cancel_case(&f);
    bool blocked = cancel && receive_blocked_cancel_case(&f);
    bool wrong = blocked && receive_wrong_root_case(&f);
    bool error = wrong && receive_error_then_cancel_case(&f);
    bool complete = error && receive_complete_case(&f, root_leaf);
    bool existing = complete && receive_existing_case(&f);
    bool credit = existing && receive_credit_suite(&f, root_leaf);
    bool unknown = credit && receive_unknown_case(&f, root_leaf);
    bool corruption = unknown && receive_existing_corruption(&f, root_leaf);
    bool orchestration = corruption && receive_orchestration_case(&f);
    ok = orchestration;
    printf("receive cases: start=%d capacity=%d cancel=%d blocked=%d wrong=%d error=%d "
           "complete=%d existing=%d credit=%d unknown=%d corruption=%d orchestration=%d\n", started,
           capacity, cancel, blocked, wrong, error, complete, existing, credit, unknown, corruption, orchestration);
    receive_fixture_close(&f);
    printf("wallet_history_receive: %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
#else
int test_wallet_history_receive(void)
{
    printf("SKIP (wallet history receive is not supported on Windows)\n");
    return 0;
}
#endif
