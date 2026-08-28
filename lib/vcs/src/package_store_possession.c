/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bounded, generation-bound package possession proofs. */

#include "package_store_priv.h"

#if defined(_WIN32)
#include <string.h>

struct vcs_package_possession_proof { int unavailable; };

const char *vcs_package_possession_failure_string(
    enum vcs_package_possession_failure failure)
{
    switch (failure) {
    case VCS_PACKAGE_POSSESSION_NONE: return "none";
    case VCS_PACKAGE_POSSESSION_UNTRACKED: return "untracked";
    case VCS_PACKAGE_POSSESSION_INCOMPLETE: return "incomplete";
    case VCS_PACKAGE_POSSESSION_UNPINNED: return "unpinned";
    case VCS_PACKAGE_POSSESSION_MANIFEST: return "manifest-invalid";
    case VCS_PACKAGE_POSSESSION_CHUNK_MISSING: return "chunk-missing";
    case VCS_PACKAGE_POSSESSION_CHUNK_HASH: return "chunk-hash-mismatch";
    case VCS_PACKAGE_POSSESSION_MUTATED: return "package-mutated";
    case VCS_PACKAGE_POSSESSION_ALLOC: return "allocation-failed";
    }
    return "unknown";
}

static void windows_receipt_refused(
    struct vcs_package_possession_receipt *receipt, uint64_t generation,
    bool complete, bool pinned,
    enum vcs_package_possession_failure failure)
{
    if (receipt) *receipt = (struct vcs_package_possession_receipt){
        .mutation_generation = generation, .complete = complete,
        .pinned = pinned, .failure = failure};
}

bool vcs_package_store_possession_snapshot(
    struct vcs_package_store *store, const uint8_t package_root[32],
    struct vcs_package_possession_receipt *out)
{
    if (!store || !package_root || !out) return false;
    bool found = false;
    pthread_mutex_lock(&store->lock);
    for (size_t i = 0; i < store->pkg_count; i++) {
        const struct store_package *package = &store->pkgs[i];
        if (memcmp(package->root, package_root, 32) != 0) continue;
        windows_receipt_refused(out, package->mutation_generation,
                                package->committed, package->pinned,
                                VCS_PACKAGE_POSSESSION_NONE);
        found = true;
        break;
    }
    pthread_mutex_unlock(&store->lock);
    if (!found) windows_receipt_refused(out, 0, false, false,
                                        VCS_PACKAGE_POSSESSION_UNTRACKED);
    return found;
}

uint64_t vcs_package_store_mutation_epoch(struct vcs_package_store *store)
{
    if (!store) return 0;
    pthread_mutex_lock(&store->lock);
    uint64_t epoch = store->next_mutation_generation;
    pthread_mutex_unlock(&store->lock);
    return epoch;
}

struct vcs_package_possession_proof *vcs_package_store_possession_begin(
    struct vcs_package_store *store, const uint8_t package_root[32],
    bool require_pinned, struct vcs_package_possession_receipt *receipt)
{
    (void)store; (void)package_root; (void)require_pinned;
    windows_receipt_refused(receipt, 0, false, false,
                            VCS_PACKAGE_POSSESSION_CHUNK_MISSING);
    return NULL;
}

enum vcs_package_possession_step vcs_package_store_possession_step(
    struct vcs_package_possession_proof *proof, uint64_t byte_budget,
    uint32_t chunk_budget, struct vcs_package_possession_receipt *receipt,
    uint64_t *bytes_used)
{
    (void)proof; (void)byte_budget; (void)chunk_budget;
    if (bytes_used) *bytes_used = 0;
    windows_receipt_refused(receipt, 0, false, false,
                            VCS_PACKAGE_POSSESSION_CHUNK_MISSING);
    return VCS_PACKAGE_POSSESSION_FAILED;
}

void vcs_package_store_possession_free(
    struct vcs_package_possession_proof *proof) { (void)proof; }

void vcs_package_store_possession_apply_if_current(
    struct vcs_package_store *store, const uint8_t package_root[32],
    uint64_t successful_generation, bool require_pinned,
    vcs_package_possession_apply_fn apply, void *context)
{
    (void)store; (void)package_root; (void)successful_generation;
    (void)require_pinned;
    if (apply) apply(context, false);
}

bool vcs_package_store_verify_possession_receipt(
    struct vcs_package_store *store, const uint8_t package_root[32],
    bool require_pinned, struct vcs_package_possession_receipt *receipt)
{
    (void)store; (void)package_root; (void)require_pinned;
    windows_receipt_refused(receipt, 0, false, false,
                            VCS_PACKAGE_POSSESSION_CHUNK_MISSING);
    return false;
}

bool vcs_package_store_verify_possession(
    struct vcs_package_store *store, const uint8_t package_root[32],
    bool require_pinned)
{
    (void)store; (void)package_root; (void)require_pinned;
    return false;
}

#else
#include "base/hex.h"
#include "base/safe_alloc.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum possession_phase {
    POSSESSION_HASH_CHUNKS = 0,
    POSSESSION_RECHECK_FILES,
    POSSESSION_TERMINAL,
};

struct possession_fingerprint {
    dev_t device;
    ino_t inode;
    off_t size;
    struct timespec mtime;
    struct timespec ctime;
};

struct vcs_package_possession_proof {
    struct vcs_package_store *store;
    uint8_t root[32];
    char store_root[STORE_PATH_MAX];
    bool require_pinned;
    bool snapshot_pinned;
    uint64_t generation;
    struct vcs_package_manifest manifest;
    struct possession_fingerprint *fingerprints;
    uint32_t coordinate_count;
    uint32_t coordinate;
    uint32_t file_index;
    uint32_t chunk_index;
    uint64_t bytes_verified;
    enum possession_phase phase;
    enum vcs_package_possession_failure failure;
};

const char *vcs_package_possession_failure_string(
    enum vcs_package_possession_failure failure)
{
    switch (failure) {
    case VCS_PACKAGE_POSSESSION_NONE: return "none";
    case VCS_PACKAGE_POSSESSION_UNTRACKED: return "untracked";
    case VCS_PACKAGE_POSSESSION_INCOMPLETE: return "incomplete";
    case VCS_PACKAGE_POSSESSION_UNPINNED: return "unpinned";
    case VCS_PACKAGE_POSSESSION_MANIFEST: return "manifest-invalid";
    case VCS_PACKAGE_POSSESSION_CHUNK_MISSING: return "chunk-missing";
    case VCS_PACKAGE_POSSESSION_CHUNK_HASH: return "chunk-hash-mismatch";
    case VCS_PACKAGE_POSSESSION_MUTATED: return "package-mutated";
    case VCS_PACKAGE_POSSESSION_ALLOC: return "allocation-failed";
    }
    return "unknown";
}

static void receipt_set(struct vcs_package_possession_receipt *receipt,
                        uint64_t generation, uint64_t bytes,
                        uint32_t chunks, bool complete, bool pinned,
                        enum vcs_package_possession_failure failure)
{
    if (!receipt)
        return;
    *receipt = (struct vcs_package_possession_receipt){
        .mutation_generation = generation,
        .bytes_verified = bytes,
        .chunks_verified = chunks,
        .complete = complete,
        .pinned = pinned,
        .failure = failure,
    };
}

static bool timespec_same(struct timespec left, struct timespec right)
{
    return left.tv_sec == right.tv_sec && left.tv_nsec == right.tv_nsec;
}

static void fingerprint_set(struct possession_fingerprint *out,
                            const struct stat *status)
{
    out->device = status->st_dev;
    out->inode = status->st_ino;
    out->size = status->st_size;
    out->mtime = status->st_mtim;
    out->ctime = status->st_ctim;
}

static bool fingerprint_same(const struct possession_fingerprint *left,
                             const struct stat *right)
{
    return left->device == right->st_dev && left->inode == right->st_ino &&
           left->size == right->st_size &&
           timespec_same(left->mtime, right->st_mtim) &&
           timespec_same(left->ctime, right->st_ctim);
}

bool vcs_package_store_possession_snapshot(
    struct vcs_package_store *store, const uint8_t package_root[32],
    struct vcs_package_possession_receipt *out)
{
    if (!store || !package_root || !out)
        return false;
    bool found = false;
    pthread_mutex_lock(&store->lock);
    for (size_t i = 0; i < store->pkg_count; i++) {
        const struct store_package *package = &store->pkgs[i];
        if (memcmp(package->root, package_root, 32) != 0)
            continue;
        receipt_set(out, package->mutation_generation, 0, 0,
                    package->committed, package->pinned,
                    VCS_PACKAGE_POSSESSION_NONE);
        found = true;
        break;
    }
    pthread_mutex_unlock(&store->lock);
    if (!found)
        receipt_set(out, 0, 0, 0, false, false,
                    VCS_PACKAGE_POSSESSION_UNTRACKED);
    return found;
}

uint64_t vcs_package_store_mutation_epoch(struct vcs_package_store *store)
{
    if (!store)
        return 0;
    pthread_mutex_lock(&store->lock);
    uint64_t epoch = store->next_mutation_generation;
    pthread_mutex_unlock(&store->lock);
    return epoch;
}

static void proof_cas_path(const struct vcs_package_possession_proof *proof,
                           const uint8_t hash[32], char out[STORE_PATH_MAX])
{
    char hex[65];
    zcl_hex_encode(hash, 32, hex);
    static const char suffix[] = "/cas/sha3/";
    size_t root_len = strlen(proof->store_root);
    size_t suffix_len = sizeof(suffix) - 1u;
    size_t need = root_len + suffix_len + 2u + 1u + 64u + 1u;
    if (need > STORE_PATH_MAX) {
        out[0] = '\0';
        return;
    }
    memcpy(out, proof->store_root, root_len);
    memcpy(out + root_len, suffix, suffix_len);
    size_t offset = root_len + suffix_len;
    memcpy(out + offset, hex, 2u);
    offset += 2u;
    out[offset++] = '/';
    memcpy(out + offset, hex, 65u);
}

static bool read_exact(int descriptor, uint8_t *out, size_t length)
{
    size_t offset = 0;
    while (offset < length) {
        ssize_t got = read(descriptor, out + offset, length - offset);
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            return false;
        offset += (size_t)got;
    }
    return true;
}

static bool proof_read_chunk(struct vcs_package_possession_proof *proof,
                             const struct vcs_package_file *file,
                             uint32_t chunk_index, size_t expected,
                             struct possession_fingerprint *fingerprint)
{
    const uint8_t *hash = file->chunk_hashes + (size_t)chunk_index * 32u;
    char path[STORE_PATH_MAX];
    proof_cas_path(proof, hash, path);
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        proof->failure = VCS_PACKAGE_POSSESSION_CHUNK_MISSING;
        return false;
    }
    struct stat before, after;
    bool shape_ok = fstat(descriptor, &before) == 0 &&
                    S_ISREG(before.st_mode) && before.st_size >= 0 &&
                    (uint64_t)before.st_size == (uint64_t)expected;
    uint8_t *bytes = shape_ok
                         ? zcl_malloc(expected, "possession_chunk")
                         : NULL;
    if (shape_ok && !bytes)
        proof->failure = VCS_PACKAGE_POSSESSION_ALLOC;
    bool read_ok = shape_ok && bytes && read_exact(descriptor, bytes, expected);
    bool stable = fstat(descriptor, &after) == 0 &&
                  before.st_dev == after.st_dev &&
                  before.st_ino == after.st_ino &&
                  before.st_size == after.st_size &&
                  timespec_same(before.st_mtim, after.st_mtim) &&
                  timespec_same(before.st_ctim, after.st_ctim);
    (void)close(descriptor);
    bool verified = read_ok && stable &&
                    vcs_package_verify_chunk(file, chunk_index, bytes,
                                             expected);
    free(bytes);
    if (!verified && proof->failure == VCS_PACKAGE_POSSESSION_NONE)
        proof->failure = read_ok ? VCS_PACKAGE_POSSESSION_CHUNK_HASH
                                 : VCS_PACKAGE_POSSESSION_CHUNK_MISSING;
    if (verified)
        fingerprint_set(fingerprint, &after);
    return verified;
}

struct vcs_package_possession_proof *vcs_package_store_possession_begin(
    struct vcs_package_store *store, const uint8_t package_root[32],
    bool require_pinned, struct vcs_package_possession_receipt *receipt)
{
    receipt_set(receipt, 0, 0, 0, false, false,
                VCS_PACKAGE_POSSESSION_UNTRACKED);
    if (!store || !package_root)
        return NULL;
    struct vcs_package_possession_proof *proof =
        zcl_malloc(sizeof(*proof), "package_possession_proof");
    if (!proof) {
        receipt_set(receipt, 0, 0, 0, false, false,
                    VCS_PACKAGE_POSSESSION_ALLOC);
        return NULL;
    }
    memset(proof, 0, sizeof(*proof));
    proof->store = store;
    proof->require_pinned = require_pinned;
    memcpy(proof->root, package_root, 32);

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    bool complete = false;
    bool pinned = false;
    pthread_mutex_lock(&store->lock);
    struct store_package *package = NULL;
    for (size_t i = 0; i < store->pkg_count; i++)
        if (memcmp(store->pkgs[i].root, package_root, 32) == 0) {
            package = &store->pkgs[i];
            break;
        }
    if (package) {
        proof->generation = package->mutation_generation;
        complete = package->committed;
        pinned = package->pinned;
        (void)snprintf(proof->store_root, sizeof(proof->store_root), "%s",
                       store->root);
        if (complete && (!require_pinned || pinned)) {
            wire = zcl_malloc(package->manifest_wire_len,
                              "possession_manifest_wire");
            if (wire) {
                memcpy(wire, package->manifest_wire,
                       package->manifest_wire_len);
                wire_len = package->manifest_wire_len;
            }
        }
    }
    pthread_mutex_unlock(&store->lock);
    if (!package || !complete || (require_pinned && !pinned) || !wire) {
        enum vcs_package_possession_failure failure =
            !package ? VCS_PACKAGE_POSSESSION_UNTRACKED
                     : (!complete ? VCS_PACKAGE_POSSESSION_INCOMPLETE
                                  : (require_pinned && !pinned
                                         ? VCS_PACKAGE_POSSESSION_UNPINNED
                                         : VCS_PACKAGE_POSSESSION_ALLOC));
        receipt_set(receipt, proof->generation, 0, 0, complete, pinned,
                    failure);
        free(wire);
        free(proof);
        return NULL;
    }
    proof->snapshot_pinned = pinned;
    uint8_t derived_root[32];
    bool parsed = vcs_package_manifest_parse(wire, wire_len,
                                             &proof->manifest) &&
                  vcs_package_manifest_root(&proof->manifest, derived_root) &&
                  memcmp(derived_root, package_root, 32) == 0;
    free(wire);
    if (!parsed) {
        vcs_package_manifest_free(&proof->manifest);
        receipt_set(receipt, proof->generation, 0, 0, complete, pinned,
                    VCS_PACKAGE_POSSESSION_MANIFEST);
        free(proof);
        return NULL;
    }
    for (size_t i = 0; i < proof->manifest.count; i++)
        proof->coordinate_count += proof->manifest.files[i].chunk_count;
    proof->fingerprints = zcl_calloc(
        proof->coordinate_count ? proof->coordinate_count : 1u,
        sizeof(*proof->fingerprints),
        "possession_fingerprints");
    if (!proof->fingerprints) {
        vcs_package_manifest_free(&proof->manifest);
        receipt_set(receipt, proof->generation, 0, 0, complete, pinned,
                    VCS_PACKAGE_POSSESSION_ALLOC);
        free(proof);
        return NULL;
    }
    receipt_set(receipt, proof->generation, 0, 0, complete, pinned,
                VCS_PACKAGE_POSSESSION_NONE);
    return proof;
}

static size_t proof_expected_chunk(
    const struct vcs_package_file *file, uint32_t chunk_index)
{
    uint64_t offset = (uint64_t)chunk_index * VCS_PACKAGE_CHUNK_BYTES;
    uint64_t remaining = file->size - offset;
    return remaining > VCS_PACKAGE_CHUNK_BYTES
               ? VCS_PACKAGE_CHUNK_BYTES
               : (size_t)remaining;
}

static bool proof_generation_current(
    struct vcs_package_possession_proof *proof, bool *complete_out,
    bool *pinned_out)
{
    bool current = false;
    bool complete = false;
    bool pinned = false;
    pthread_mutex_lock(&proof->store->lock);
    for (size_t i = 0; i < proof->store->pkg_count; i++) {
        struct store_package *package = &proof->store->pkgs[i];
        if (memcmp(package->root, proof->root, 32) != 0)
            continue;
        complete = package->committed;
        pinned = package->pinned;
        current = package->mutation_generation == proof->generation &&
                  complete && (!proof->require_pinned || pinned);
        break;
    }
    if (current) {
        proof->phase = POSSESSION_TERMINAL;
        proof->failure = VCS_PACKAGE_POSSESSION_NONE;
    }
    pthread_mutex_unlock(&proof->store->lock);
    if (complete_out)
        *complete_out = complete;
    if (pinned_out)
        *pinned_out = pinned;
    return current;
}

enum vcs_package_possession_step vcs_package_store_possession_step(
    struct vcs_package_possession_proof *proof, uint64_t byte_budget,
    uint32_t chunk_budget, struct vcs_package_possession_receipt *receipt,
    uint64_t *bytes_used)
{
    if (bytes_used)
        *bytes_used = 0;
    if (!proof || proof->phase == POSSESSION_TERMINAL) {
        if (proof)
            receipt_set(receipt, proof->generation, proof->bytes_verified,
                        proof->coordinate_count, true,
                        proof->snapshot_pinned, proof->failure);
        return proof && proof->failure == VCS_PACKAGE_POSSESSION_NONE
                   ? VCS_PACKAGE_POSSESSION_SUCCESS
                   : VCS_PACKAGE_POSSESSION_FAILED;
    }
    uint64_t used = 0;
    uint32_t operations = 0;
    while (operations < chunk_budget) {
        if (proof->phase == POSSESSION_HASH_CHUNKS) {
            if (proof->file_index >= proof->manifest.count) {
                proof->phase = POSSESSION_RECHECK_FILES;
                proof->coordinate = 0;
                continue;
            }
            const struct vcs_package_file *file =
                &proof->manifest.files[proof->file_index];
            if (proof->chunk_index >= file->chunk_count) {
                proof->file_index++;
                proof->chunk_index = 0;
                continue;
            }
            size_t expected = proof_expected_chunk(file, proof->chunk_index);
            if ((uint64_t)expected > byte_budget - used) {
                receipt_set(receipt, proof->generation,
                            proof->bytes_verified, proof->coordinate,
                            true, proof->snapshot_pinned,
                            VCS_PACKAGE_POSSESSION_NONE);
                if (bytes_used)
                    *bytes_used = used;
                return used ? VCS_PACKAGE_POSSESSION_PROGRESS
                            : VCS_PACKAGE_POSSESSION_BUDGET;
            }
            if (!proof_read_chunk(proof, file, proof->chunk_index, expected,
                                  &proof->fingerprints[proof->coordinate])) {
                proof->phase = POSSESSION_TERMINAL;
                break;
            }
            proof->bytes_verified += expected;
            used += expected;
            proof->coordinate++;
            proof->chunk_index++;
            operations++;
            continue;
        }
        if (proof->coordinate < proof->coordinate_count) {
            uint32_t coordinate = 0;
            const struct vcs_package_file *file = NULL;
            uint32_t chunk_index = 0;
            for (size_t i = 0; i < proof->manifest.count; i++) {
                uint32_t count = proof->manifest.files[i].chunk_count;
                if (proof->coordinate < coordinate + count) {
                    file = &proof->manifest.files[i];
                    chunk_index = proof->coordinate - coordinate;
                    break;
                }
                coordinate += count;
            }
            if (!file) {
                proof->failure = VCS_PACKAGE_POSSESSION_MANIFEST;
                proof->phase = POSSESSION_TERMINAL;
                break;
            }
            const uint8_t *hash =
                file->chunk_hashes + (size_t)chunk_index * 32u;
            char path[STORE_PATH_MAX];
            struct stat status;
            proof_cas_path(proof, hash, path);
            if (lstat(path, &status) != 0 || !S_ISREG(status.st_mode) ||
                !fingerprint_same(&proof->fingerprints[proof->coordinate],
                                  &status)) {
                proof->failure = VCS_PACKAGE_POSSESSION_MUTATED;
                proof->phase = POSSESSION_TERMINAL;
                break;
            }
            proof->coordinate++;
            operations++;
            continue;
        }
        bool complete = false, pinned = false;
        bool current = proof_generation_current(proof, &complete, &pinned);
        if (!current) {
            proof->failure = VCS_PACKAGE_POSSESSION_MUTATED;
            proof->phase = POSSESSION_TERMINAL;
        }
        receipt_set(receipt, proof->generation, proof->bytes_verified,
                    proof->coordinate_count, complete, pinned,
                    proof->failure);
        if (bytes_used)
            *bytes_used = used;
        return current ? VCS_PACKAGE_POSSESSION_SUCCESS
                       : VCS_PACKAGE_POSSESSION_FAILED;
    }
    if (bytes_used)
        *bytes_used = used;
    receipt_set(receipt, proof->generation, proof->bytes_verified,
                proof->phase == POSSESSION_RECHECK_FILES
                    ? proof->coordinate_count
                    : proof->coordinate,
                true, proof->snapshot_pinned, proof->failure);
    return proof->phase == POSSESSION_TERMINAL
               ? VCS_PACKAGE_POSSESSION_FAILED
               : VCS_PACKAGE_POSSESSION_PROGRESS;
}

void vcs_package_store_possession_free(
    struct vcs_package_possession_proof *proof)
{
    if (!proof)
        return;
    vcs_package_manifest_free(&proof->manifest);
    free(proof->fingerprints);
    free(proof);
}

void vcs_package_store_possession_apply_if_current(
    struct vcs_package_store *store, const uint8_t package_root[32],
    uint64_t successful_generation, bool require_pinned,
    vcs_package_possession_apply_fn apply, void *context)
{
    if (!apply)
        return;
    if (!store || !package_root || !successful_generation) {
        apply(context, false);
        return;
    }
    bool current = false;
    pthread_mutex_lock(&store->lock);
    for (size_t i = 0; i < store->pkg_count; i++) {
        struct store_package *package = &store->pkgs[i];
        if (memcmp(package->root, package_root, 32) == 0) {
            current = package->mutation_generation == successful_generation &&
                      package->committed &&
                      (!require_pinned || package->pinned);
            break;
        }
    }
    apply(context, current);
    pthread_mutex_unlock(&store->lock);
}

bool vcs_package_store_verify_possession_receipt(
    struct vcs_package_store *store, const uint8_t package_root[32],
    bool require_pinned, struct vcs_package_possession_receipt *receipt)
{
    struct vcs_package_possession_receipt local;
    if (!receipt)
        receipt = &local;
    struct vcs_package_possession_proof *proof =
        vcs_package_store_possession_begin(store, package_root,
                                           require_pinned, receipt);
    if (!proof)
        return false;
    enum vcs_package_possession_step state;
    do {
        state = vcs_package_store_possession_step(
            proof, UINT64_MAX, UINT32_MAX, receipt, NULL);
    } while (state == VCS_PACKAGE_POSSESSION_PROGRESS);
    vcs_package_store_possession_free(proof);
    return state == VCS_PACKAGE_POSSESSION_SUCCESS;
}

bool vcs_package_store_verify_possession(
    struct vcs_package_store *store, const uint8_t package_root[32],
    bool require_pinned)
{
    return vcs_package_store_verify_possession_receipt(
        store, package_root, require_pinned, NULL);
}
#endif
