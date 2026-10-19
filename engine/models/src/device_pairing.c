/* purpose: Persist exact pairing authority and immutable private credentials with fail-closed publication. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE /* flock */
#endif
#include "models/device_pairing.h"
#include "base/hex.h"
#include "base/serialize_le.h"
#include "base/cleanse.h"
#include "base/safe_alloc.h"
#include "net/v2_identity.h"
#include "platform/clock.h"
#include "platform/private_directory.h"
#include "sha3/sha3.h"
#include "util/log_macros.h"
#include <stdio.h>
#include <errno.h>
#include <string.h>
#ifndef _WIN32
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

enum { DEVICE_PAIRING_V1_WIRE = 168, DEVICE_PAIRING_V2_WIRE = 176,
       DEVICE_PAIRING_HOST_WIRE = 256,
       DEVICE_PAIRING_GUEST_WIRE = 288, DEVICE_PAIRING_WIRE = 304 };
static const uint8_t pairing_magic[8] = {'Z','2','3','D','E','V',2,0};

#ifdef ZCL_TESTING
#include <stdatomic.h>
static _Thread_local unsigned interruption_stage;
static atomic_ullong test_full_acquisitions, test_cached_acquisitions;
void device_pairing_test_interrupt(unsigned stage)
{
    interruption_stage = stage;
}
void device_pairing_test_guard_counts(uint64_t *full, uint64_t *cached)
{
    if (full) *full = atomic_load_explicit(&test_full_acquisitions, memory_order_relaxed);
    if (cached) *cached = atomic_load_explicit(&test_cached_acquisitions, memory_order_relaxed);
}
#define DEVICE_PAIRING_TEST_COUNT(counter) atomic_fetch_add_explicit(&(counter), 1, memory_order_relaxed)
#else
#define DEVICE_PAIRING_TEST_COUNT(counter) ((void)0)
#endif

static bool publication_checkpoint(unsigned stage)
{
#ifdef ZCL_TESTING
    if (interruption_stage == stage) {
        interruption_stage = 0;
        LOG_FAIL("device_pairing", "injected publication interruption at %u", stage);
    }
#else
    (void)stage;
#endif
    return true;
}

static bool nonzero_key(const uint8_t value[32])
{
    uint8_t bits = 0;
    for (size_t i = 0; i < 32; ++i) bits |= value[i];
    return bits != 0;
}

static bool guest_scope_complete(const struct device_pairing_guest_scope *scope)
{
    return nonzero_key(scope->guest_id) && nonzero_key(scope->requester_ssh_key) &&
        nonzero_key(scope->owner_grant_root) && scope->enrollment_generation &&
        scope->port_mask && !(scope->port_mask & ~UINT64_C(15));
}

static bool guest_scope_empty(const struct device_pairing_guest_scope *scope)
{
    return !nonzero_key(scope->guest_id) && !nonzero_key(scope->requester_ssh_key) &&
        !nonzero_key(scope->owner_grant_root) && !scope->enrollment_generation &&
        !scope->port_mask;
}

static bool guest_authority_valid(const struct db_device_pairing *row)
{
    if (!(row->capabilities & DEVICE_PAIRING_CAP_GUEST_BIND))
        return guest_scope_empty(&row->guest_scope);
    return (row->capabilities & DEVICE_PAIRING_CAP_GUEST_STREAM) &&
        guest_scope_complete(&row->guest_scope);
}

static bool pairing_revocation_valid(const struct db_device_pairing *row)
{
    return (!row->revoked_at && !row->generation) ||
        (row->revoked_at >= row->paired_at && row->generation == 1);
}

static bool psk_binding_empty(const struct device_pairing_psk_binding *binding)
{
    return !nonzero_key(binding->credential_id) && !binding->key_epoch &&
        !nonzero_key(binding->endpoint_a) && !nonzero_key(binding->endpoint_b);
}
static bool psk_binding_valid(const struct device_pairing_psk_binding *binding)
{
    return nonzero_key(binding->credential_id) && binding->key_epoch &&
        nonzero_key(binding->endpoint_a) && nonzero_key(binding->endpoint_b) &&
        memcmp(binding->endpoint_a, binding->endpoint_b, 32) < 0;
}
static bool host_binding_valid(const struct device_pairing_host_binding *binding)
{
    if (binding->backend_profile == DEVICE_PAIRING_HOST_SHAKE256_WRAP_PSK)
        return psk_binding_valid(&binding->psk) && !nonzero_key(binding->local_pq_key_root) &&
            !nonzero_key(binding->peer_pq_key_root);
    return binding->backend_profile == DEVICE_PAIRING_HOST_OPENSSH_MLKEM768X25519_MLDSA44ED25519 &&
        nonzero_key(binding->local_pq_key_root) && nonzero_key(binding->peer_pq_key_root) &&
        psk_binding_empty(&binding->psk);
}

static bool host_binding_empty(const struct device_pairing_host_binding *binding)
{
    return !binding->backend_profile && !nonzero_key(binding->local_pq_key_root) &&
        !nonzero_key(binding->peer_pq_key_root) && psk_binding_empty(&binding->psk);
}
static bool psk_endpoints_match(const struct db_device_pairing *row)
{
    if (row->host_scope.binding.backend_profile != DEVICE_PAIRING_HOST_SHAKE256_WRAP_PSK) return true;
    const uint8_t *a = row->local_key, *b = row->peer_key;
    if (memcmp(a, b, 32) > 0) { a = row->peer_key; b = row->local_key; }
    return !memcmp(a, row->host_scope.binding.psk.endpoint_a, 32) &&
        !memcmp(b, row->host_scope.binding.psk.endpoint_b, 32);
}

static bool host_authority_valid(const struct db_device_pairing *row)
{
    bool scoped = row->host_scope.inbound_port || row->host_scope.outbound_port;
    if (!(row->capabilities & DEVICE_PAIRING_CAP_HOST_FORWARD))
        return !scoped && host_binding_empty(&row->host_scope.binding);
    return scoped && host_binding_valid(&row->host_scope.binding) && psk_endpoints_match(row) && !(row->capabilities &
        (DEVICE_PAIRING_CAP_GUEST_STREAM | DEVICE_PAIRING_CAP_GUEST_BIND));
}

bool db_device_pairing_validate(const struct db_device_pairing *row,
                                struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!row) {
        validates_custom(errors, false, "record", "is null");
        return false;
    }
    validates_custom(errors, nonzero_key(row->profile) &&
        nonzero_key(row->local_key) && nonzero_key(row->peer_key) &&
        memcmp(row->local_key, row->peer_key, 32), "identity", "is invalid");
    validates_custom(errors, row->paired_at && row->expires_at > row->paired_at &&
        row->expires_at - row->paired_at <= UINT64_C(2592000),
        "expiry", "must be within 30 days of pairing");
    validates_custom(errors, pairing_revocation_valid(row),
        "revocation", "must be an irreversible transition");
    validates_custom(errors, row->capabilities &&
        !(row->capabilities & ~DEVICE_PAIRING_CAP_KNOWN),
        "capabilities", "must contain only explicit supported authority");
    validates_custom(errors, guest_authority_valid(row), "guest_scope",
        "bind requires stream and complete scope; nonbinding scope must be empty");
    validates_custom(errors, host_authority_valid(row), "host_scope",
        "host requires an explicit port and typed identity binding; cannot mix with guest authority");
    return !ar_errors_any(errors);
}

bool device_pairing_store_open(struct device_pairing_store *store,
                               const char *directory,
                               const uint8_t profile[32],
                               const uint8_t local_key[32])
{
    if (!store || !directory || !profile || !local_key ||
        !nonzero_key(profile) || !nonzero_key(local_key))
        LOG_FAIL("device_pairing", "invalid profile");
    memset(store, 0, sizeof(*store));
    uintptr_t handle;
    if (!platform_private_directory_open_validated(directory, &handle))
        LOG_FAIL("device_pairing", "profile directory is not owner-private");
    platform_private_directory_close(handle);
    char path[1200], resolved[1200];
    int n = snprintf(path, sizeof(path), "%s/authority.lock", directory);
    if (n < 0 || (size_t)n >= sizeof(path) ||
        !platform_private_path_resolve(path, resolved, sizeof(resolved),
                                       store->directory, sizeof(store->directory)))
        LOG_FAIL("device_pairing", "profile path resolution failed");
    memcpy(store->profile, profile, 32);
    memcpy(store->local_key, local_key, 32);
    return true;
}

static bool bound(const struct device_pairing_store *store,
                   const struct db_device_pairing *row)
{
    return !memcmp(store->profile, row->profile, 32) &&
           !memcmp(store->local_key, row->local_key, 32);
}

static bool record_path(const struct device_pairing_store *store,
                         const uint8_t peer[32], char out[1200])
{
    char hex[65];
    zcl_hex_encode(peer, 32, hex);
    int n = snprintf(out, 1200, "%s/%s.grant", store->directory, hex);
    if (n < 0 || n >= 1200) LOG_FAIL("device_pairing", "grant path too long");
    return true;
}

static bool lock_store(struct device_pairing_store *store,
                        struct device_pairing_guard *guard, bool shared)
{
    memset(guard, 0, sizeof(*guard));
    platform_private_file_init(&guard->lock);
    uintptr_t directory;
    if (!platform_private_directory_open_validated(store->directory, &directory))
        LOG_FAIL("device_pairing", "profile directory authority changed");
    platform_private_directory_close(directory);
    char path[1200];
    int n = snprintf(path, sizeof(path), "%s/authority.lock", store->directory);
    if (n < 0 || (size_t)n >= sizeof(path) ||
        !(shared ? platform_private_file_open_observation(path, &guard->lock) :
          platform_private_file_open_locked_create(path, &guard->lock)))
        LOG_FAIL("device_pairing", "authority lock unavailable");
    guard->held = true;
    return true;
}

/* A descriptor of authority.lock that a revalidation memo keeps open. It pins
 * the lock inode, so an inode number compare against the path cannot be fooled
 * by reuse, and it is NOT locked between acquisitions: a writer's nonblocking
 * exclusive lock must keep succeeding. The cache and at most one outstanding
 * guard each hold a reference; the last drop closes the descriptor. */
#ifndef _WIN32
struct device_pairing_lock_lease { int fd; unsigned refs; bool lent; uint64_t volume, file; };
static struct device_pairing_lock_lease *lease_open(const char *lock,
    const struct platform_private_path_state *held)
{
    int fd = open(lock, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return NULL; // raw-return-ok:memo not built; the caller falls back to the full path
    struct stat st;
    struct device_pairing_lock_lease *lease = NULL;
    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && (uint64_t)st.st_dev == held->volume &&
        (uint64_t)st.st_ino == held->file) lease = zcl_calloc(1, sizeof(*lease), "device_pairing_lease");
    if (!lease) { close(fd); return NULL; } // raw-return-ok:memo not built; the caller falls back to the full path
    *lease = (struct device_pairing_lock_lease){.fd = fd, .refs = 1, .volume = held->volume, .file = held->file};
    return lease;
}
static void lease_unref(struct device_pairing_lock_lease *lease)
{
    if (!lease || --lease->refs) return;
    close(lease->fd); free(lease);
}
static bool lease_lent(const struct device_pairing_lock_lease *lease) { return lease && lease->lent; }
static void lease_return(struct device_pairing_lock_lease *lease)
{
    (void)flock(lease->fd, LOCK_UN); lease->lent = false; lease_unref(lease);
}
/* Takes the shared lock on the held descriptor, then requires the lock path to
 * still name that inode: lock first, compare second, so a replacement that
 * completes before the compare is seen. */
static bool lease_borrow(struct device_pairing_lock_lease *lease, const char *lock,
    struct device_pairing_guard *guard)
{
    struct platform_private_path_state now;
    if (lease->lent || flock(lease->fd, LOCK_SH | LOCK_NB) != 0) return false; // raw-return-ok:cache miss; the full acquisition logs
    if (!platform_private_path_state(lock, &now) || now.volume != lease->volume || now.file != lease->file) {
        (void)flock(lease->fd, LOCK_UN); return false; // raw-return-ok:cache miss; the full acquisition logs
    }
    lease->lent = true; lease->refs++; guard->lease = lease; guard->held = true;
    return true;
}
#else
struct device_pairing_lock_lease { int unused; };
static struct device_pairing_lock_lease *lease_open(const char *lock, const struct platform_private_path_state *held)
{ (void)lock; (void)held; return NULL; }
static void lease_unref(struct device_pairing_lock_lease *lease) { (void)lease; }
static bool lease_lent(const struct device_pairing_lock_lease *lease) { (void)lease; return false; }
static void lease_return(struct device_pairing_lock_lease *lease) { (void)lease; }
static bool lease_borrow(struct device_pairing_lock_lease *lease, const char *lock, struct device_pairing_guard *guard)
{ (void)lease; (void)lock; (void)guard; return false; }
#endif

void device_pairing_guard_release(struct device_pairing_guard *guard)
{
    if (!guard) return;
    if (guard->held && guard->lease) lease_return(guard->lease);
    else if (guard->held) platform_private_file_close(&guard->lock);
    memset(guard, 0, sizeof(*guard));
}


static size_t encode_host(const struct db_device_pairing *row, uint8_t wire[DEVICE_PAIRING_WIRE])
{
    memset(wire + 144, 0, 128);
    zcl_write_u16_le(wire + 144, row->host_scope.inbound_port);
    zcl_write_u16_le(wire + 146, row->host_scope.outbound_port);
    zcl_write_u64_le(wire + 152, row->host_scope.binding.backend_profile);
    if (row->host_scope.binding.backend_profile == DEVICE_PAIRING_HOST_SHAKE256_WRAP_PSK) {
        wire[6] = 5;
        const struct device_pairing_psk_binding *binding = &row->host_scope.binding.psk;
        memcpy(wire + 160, binding->credential_id, 32); zcl_write_u64_le(wire + 192, binding->key_epoch);
        memcpy(wire + 200, binding->endpoint_a, 32); memcpy(wire + 232, binding->endpoint_b, 32);
        return 272;
    }
    wire[6] = 4;
    memcpy(wire + 160, row->host_scope.binding.local_pq_key_root, 32);
    memcpy(wire + 192, row->host_scope.binding.peer_pq_key_root, 32);
    return 224;
}
static size_t encode(const struct db_device_pairing *row, uint8_t wire[DEVICE_PAIRING_WIRE])
{
    memcpy(wire, pairing_magic, 8);
    memcpy(wire + 8, row->profile, 32);
    memcpy(wire + 40, row->local_key, 32);
    memcpy(wire + 72, row->peer_key, 32);
    zcl_write_u64_le(wire + 104, row->paired_at);
    zcl_write_u64_le(wire + 112, row->expires_at);
    zcl_write_u64_le(wire + 120, row->revoked_at);
    zcl_write_u64_le(wire + 128, row->generation);
    zcl_write_u64_le(wire + 136, row->capabilities);
    size_t body = 144;
    if (row->capabilities & DEVICE_PAIRING_CAP_GUEST_BIND) {
        wire[6] = 3;
        memcpy(wire + 144, row->guest_scope.guest_id, 32);
        memcpy(wire + 176, row->guest_scope.requester_ssh_key, 32);
        memcpy(wire + 208, row->guest_scope.owner_grant_root, 32);
        zcl_write_u64_le(wire + 240, row->guest_scope.enrollment_generation);
        zcl_write_u64_le(wire + 248, row->guest_scope.port_mask);
        body = 256;
    }
    if (row->capabilities & DEVICE_PAIRING_CAP_HOST_FORWARD) body = encode_host(row, wire);
    zcl_sha3_256(wire, body, wire + body);
    return body + 32;
}

static bool pairing_version_valid(const uint8_t *wire, size_t length)
{
    bool legacy = length == DEVICE_PAIRING_V1_WIRE && wire[6] == 1;
    bool current = length == DEVICE_PAIRING_V2_WIRE && wire[6] == 2;
    bool scoped = length == DEVICE_PAIRING_GUEST_WIRE && wire[6] == 3;
    bool host = length == DEVICE_PAIRING_HOST_WIRE && wire[6] == 4;
    bool psk = length == DEVICE_PAIRING_WIRE && wire[6] == 5;
    return (legacy || current || scoped || host || psk) && !memcmp(wire, pairing_magic, 6) &&
        wire[7] == 0;
}

static bool decode_host_binding(const uint8_t *wire, struct device_pairing_host_binding *binding)
{
    if (wire[6] == 4) {
        if (binding->backend_profile != DEVICE_PAIRING_HOST_OPENSSH_MLKEM768X25519_MLDSA44ED25519)
            LOG_FAIL("device_pairing", "v4 requires backend1");
        memcpy(binding->local_pq_key_root, wire + 160, 32);
        memcpy(binding->peer_pq_key_root, wire + 192, 32);
        return true;
    }
    if (binding->backend_profile != DEVICE_PAIRING_HOST_SHAKE256_WRAP_PSK)
        LOG_FAIL("device_pairing", "v5 requires backend2");
    for (size_t i = 264; i < 272; ++i)
        if (wire[i]) LOG_FAIL("device_pairing", "nonzero PSK reserved byte");
    memcpy(binding->psk.credential_id, wire + 160, 32);
    binding->psk.key_epoch = zcl_read_u64_le(wire + 192);
    memcpy(binding->psk.endpoint_a, wire + 200, 32);
    memcpy(binding->psk.endpoint_b, wire + 232, 32);
    return true;
}
static bool decode_host_scope(const uint8_t *wire, struct db_device_pairing *row)
{
    bool host = wire[6] == 4 || wire[6] == 5;
    if (host != ((row->capabilities & DEVICE_PAIRING_CAP_HOST_FORWARD) != 0))
        LOG_FAIL("device_pairing", "host requires scoped v4/v5 encoding");
    if (!host) return true;
    if (wire[148] || wire[149] || wire[150] || wire[151])
        LOG_FAIL("device_pairing", "nonzero host reserved bytes");
    row->host_scope.inbound_port = zcl_read_u16_le(wire + 144);
    row->host_scope.outbound_port = zcl_read_u16_le(wire + 146);
    uint64_t profile = zcl_read_u64_le(wire + 152);
    if (profile > UINT32_MAX) LOG_FAIL("device_pairing", "host backend profile overflows");
    row->host_scope.binding.backend_profile = (uint32_t)profile;
    return decode_host_binding(wire, &row->host_scope.binding);
}

static bool decode(const uint8_t *wire, size_t length, struct db_device_pairing *row)
{
    if (!pairing_version_valid(wire, length))
        LOG_FAIL("device_pairing", "unsupported grant version or length");
    bool legacy = wire[6] == 1, scoped = wire[6] == 3;
    uint8_t digest[32];
    size_t body = length - sizeof(digest);
    zcl_sha3_256(wire, body, digest);
    if (memcmp(digest, wire + body, sizeof(digest)))
        LOG_FAIL("device_pairing", "corrupt grant");
    memset(row, 0, sizeof(*row));
    row->capabilities = legacy ? DEVICE_PAIRING_CAP_STATUS_READ : zcl_read_u64_le(wire + 136);
    memcpy(row->profile, wire + 8, 32);
    memcpy(row->local_key, wire + 40, 32);
    memcpy(row->peer_key, wire + 72, 32);
    row->paired_at = zcl_read_u64_le(wire + 104);
    row->expires_at = zcl_read_u64_le(wire + 112);
    row->revoked_at = zcl_read_u64_le(wire + 120);
    row->generation = zcl_read_u64_le(wire + 128);
    if (scoped) {
        memcpy(row->guest_scope.guest_id, wire + 144, 32);
        memcpy(row->guest_scope.requester_ssh_key, wire + 176, 32);
        memcpy(row->guest_scope.owner_grant_root, wire + 208, 32);
        row->guest_scope.enrollment_generation = zcl_read_u64_le(wire + 240);
        row->guest_scope.port_mask = zcl_read_u64_le(wire + 248);
    }
    if (scoped != ((row->capabilities & DEVICE_PAIRING_CAP_GUEST_BIND) != 0))
        LOG_FAIL("device_pairing", "bind requires scoped v3 encoding");
    if (!decode_host_scope(wire, row)) return false;
    struct ar_errors errors;
    if (!db_device_pairing_validate(row, &errors))
        LOG_FAIL("device_pairing", "invalid grant: %s", ar_errors_full(&errors));
    return true;
}

static bool publication_absent(const char *path)
{
    char pending[1240];
    int n = snprintf(pending, sizeof(pending), "%s.pending", path);
    if (n < 0 || (size_t)n >= sizeof(pending) ||
        !platform_private_path_absent(pending))
        LOG_FAIL("device_pairing", "unfinished authority publication; reconcile");
    return true;
}

static bool wire_length_supported(uint64_t size)
{
    return size == DEVICE_PAIRING_V1_WIRE || size == DEVICE_PAIRING_V2_WIRE ||
        size == DEVICE_PAIRING_GUEST_WIRE || size == DEVICE_PAIRING_WIRE || size == DEVICE_PAIRING_HOST_WIRE;
}

/* A non-NULL retain receives the descriptor that was actually read. */
static bool read_exact_retain(struct device_pairing_store *store, const uint8_t peer[32],
    struct db_device_pairing *row, uint8_t root[32], struct platform_private_file *retain)
{
    char path[1200];
    if (!record_path(store, peer, path) || !publication_absent(path)) return false;
    struct platform_private_file file;
    platform_private_file_init(&file);
    if (!platform_private_file_open_observation(path, &file))
        LOG_FAIL("device_pairing", "grant unavailable");
    uint64_t size = 0;
    uint8_t wire[DEVICE_PAIRING_WIRE];
    bool ok = platform_private_file_size(&file, &size) &&
              wire_length_supported(size) &&
              platform_private_file_read_at(&file, wire, (size_t)size, 0);
    ok = ok && decode(wire, (size_t)size, row) && bound(store, row) && !memcmp(peer, row->peer_key, 32);
    if (ok && retain) *retain = file;
    else platform_private_file_close(&file);
    if (!ok)
        LOG_FAIL("device_pairing", "grant read or identity binding failed");
    if (root) zcl_sha3_256(wire, (size_t)size, root);
    return true;
}
static bool read_exact_locked(struct device_pairing_store *store,
    const uint8_t peer[32], struct db_device_pairing *row, uint8_t root[32])
{
    return read_exact_retain(store, peer, row, root, NULL);
}

static bool read_locked(struct device_pairing_store *store,
    const uint8_t peer[32], struct db_device_pairing *row)
{
    return read_exact_locked(store, peer, row, NULL);
}

bool db_device_pairing_inspect(struct device_pairing_store *store,
    const uint8_t peer_key[32], struct db_device_pairing *row, uint8_t root[32])
{
    if (!store || !peer_key || !row || !root)
        LOG_FAIL("device_pairing", "missing inspection argument");
    struct device_pairing_guard guard;
    if (!lock_store(store, &guard, true)) return false;
    struct db_device_pairing found;
    uint8_t digest[32];
    bool ok = read_exact_locked(store, peer_key, &found, digest);
    device_pairing_guard_release(&guard);
    if (ok) {
        *row = found;
        memcpy(root, digest, 32);
    }
    return ok;
}

bool db_device_pairing_find(struct device_pairing_store *store,
                            const uint8_t peer_key[32],
                            struct db_device_pairing *row)
{
    if (!store || !peer_key || !row)
        LOG_FAIL("device_pairing", "missing lookup argument");
    struct device_pairing_guard guard;
    if (!lock_store(store, &guard, false)) return false;
    struct db_device_pairing found = {0};
    bool ok = read_locked(store, peer_key, &found);
    device_pairing_guard_release(&guard);
    if (ok) *row = found;
    return ok;
}

static bool begin_intent(const char *path, const char *directory,
                          const uint8_t wire[DEVICE_PAIRING_WIRE],
                          size_t length, struct platform_private_file *intent)
{
    platform_private_file_init(intent);
    if (!platform_private_file_create(path, intent) ||
        !platform_private_file_write_at(intent, wire + length - 32, 32, 0) ||
        !platform_private_file_authority_flush(intent) ||
        !platform_private_parent_flush(directory))
        LOG_FAIL("device_pairing", "intent publication incomplete; reconcile");
    return publication_checkpoint(1);
}

static bool publish_record(struct device_pairing_store *store,
                            const char *path, const uint8_t wire[DEVICE_PAIRING_WIRE],
                            size_t length, bool replace, enum device_pairing_publication *publication)
{
    char staging[1240];
    int n = snprintf(staging, sizeof(staging), "%s.staging", path);
    if (n < 0 || (size_t)n >= sizeof(staging))
        LOG_FAIL("device_pairing", "staging path too long");
    struct platform_private_file file;
    platform_private_file_init(&file);
    bool ok = platform_private_file_create(staging, &file) &&
        platform_private_file_write_at(&file, wire, length, 0) &&
        platform_private_file_authority_flush(&file);
    bool exists = false;
    if (ok) ok = replace ? platform_private_file_replace(&file, staging, path) :
        platform_private_file_publish_no_clobber(&file, staging, path, &exists);
    if (ok && !exists) {
        *publication = DEVICE_PAIRING_DURABILITY_UNKNOWN;
        ok = publication_checkpoint(2) &&
             platform_private_parent_flush(store->directory) &&
             publication_checkpoint(3);
    } else ok = false;
    platform_private_file_close(&file);
    if (!ok) LOG_FAIL("device_pairing", "grant publication incomplete; reconcile");
    return true;
}

enum { PSK_SECRET_WIRE = 216 };
static const uint8_t psk_magic[8] = {'Z','2','3','P','S','K','C','1'};
static bool psk_path(const struct device_pairing_store *store, const uint8_t id[32], char path[1200])
{
    char hex[65]; zcl_hex_encode(id, 32, hex);
    int n = snprintf(path, 1200, "%s/%s.psk", store->directory, hex);
    return n > 0 && n < 1200;
}
static void psk_checksum(const uint8_t wire[PSK_SECRET_WIRE], uint8_t output[32])
{
    static const uint8_t domain[] = "Z23PSKCREDENTIAL1";
    struct sha3_256_ctx hash;
    sha3_256_init(&hash); sha3_256_write(&hash, domain, sizeof(domain) - 1);
    sha3_256_write(&hash, wire, 184); sha3_256_finalize(&hash, output);
    memory_cleanse(&hash, sizeof(hash));
}
static void psk_encode(const struct db_device_pairing *row, const uint8_t secret[32],
    uint8_t wire[PSK_SECRET_WIRE])
{
    memset(wire, 0, PSK_SECRET_WIRE); memcpy(wire, psk_magic, 8);
    wire[9] = 1; wire[15] = PSK_SECRET_WIRE;
    memcpy(wire + 16, row->profile, 32);
    const struct device_pairing_psk_binding *binding = &row->host_scope.binding.psk;
    memcpy(wire + 48, binding->credential_id, 32);
    zcl_write_u64_be(wire + 80, binding->key_epoch);
    memcpy(wire + 88, binding->endpoint_a, 32); memcpy(wire + 120, binding->endpoint_b, 32);
    memcpy(wire + 152, secret, 32); psk_checksum(wire, wire + 184);
}
static bool psk_paths_absent(const struct device_pairing_store *store,
    const struct db_device_pairing *row)
{
    char path[1200], staging[1240];
    if (!psk_path(store, row->host_scope.binding.psk.credential_id, path)) return false;
    int n = snprintf(staging, sizeof(staging), "%s.staging", path);
    return n > 0 && (size_t)n < sizeof(staging) &&
        platform_private_path_absent(path) && platform_private_path_absent(staging);
}
static bool publish_psk_secret(struct device_pairing_store *store,
    const struct db_device_pairing *row, const uint8_t secret[32],
    struct device_pairing_psk_publication *report)
{
    char path[1200], staging[1240];
    if (!psk_path(store, row->host_scope.binding.psk.credential_id, path)) return false;
    int n = snprintf(staging, sizeof(staging), "%s.staging", path);
    if (n < 0 || (size_t)n >= sizeof(staging)) return false;
    uint8_t wire[PSK_SECRET_WIRE]; psk_encode(row, secret, wire);
    struct platform_private_file file; platform_private_file_init(&file);
    bool exists = false;
    bool ok = platform_private_file_create(staging, &file) &&
        platform_private_file_write_at(&file, wire, sizeof(wire), 0) &&
        platform_private_file_authority_flush(&file) && publication_checkpoint(4) &&
        platform_private_file_publish_no_clobber(&file, staging, path, &exists);
    if (ok && !exists) {
        report->secret = DEVICE_PAIRING_DURABILITY_UNKNOWN;
        ok = publication_checkpoint(5) && platform_private_parent_flush(store->directory);
        if (ok) {
            report->secret = DEVICE_PAIRING_DURABLE;
            ok = publication_checkpoint(6);
        }
    } else ok = false;
    platform_private_file_close(&file); memory_cleanse(wire, sizeof(wire));
    if (!ok) LOG_ERROR("device_pairing", "PSK publication incomplete; preserve intent and private artifacts");
    return ok;
}
static bool retire_publication_intent(struct device_pairing_store *store,
    struct platform_private_file *intent, const char *pending,
    struct device_pairing_psk_publication *report)
{
    if (!platform_private_file_retire(intent, pending)) return false;
    if (report) {
        report->intent_retired = true;
        if (!publication_checkpoint(7)) return false;
    }
    return platform_private_parent_flush(store->directory);
}
static bool publish_locked(struct device_pairing_store *store,
                            struct db_device_pairing *row, bool replace,
                            enum device_pairing_publication *publication,
                            const uint8_t *secret, struct device_pairing_psk_publication *report)
{
    struct ar_callbacks callbacks = {0};
    AR_BEGIN_SAVE(&callbacks, "device_pairing", row, db_device_pairing_validate);
    char path[1200], pending[1240];
    if (!record_path(store, row->peer_key, path)) return false;
    int n = snprintf(pending, sizeof(pending), "%s.pending", path);
    if (n < 0 || (size_t)n >= sizeof(pending))
        LOG_FAIL("device_pairing", "intent path too long");
    uint8_t wire[DEVICE_PAIRING_WIRE];
    size_t length = encode(row, wire);
    struct platform_private_file intent;
    bool ok = begin_intent(pending, store->directory, wire, length, &intent);
    if (ok && secret) ok = publish_psk_secret(store, row, secret, report);
    if (ok) ok = publish_record(store, path, wire, length, replace, publication);
    if (ok) ok = retire_publication_intent(store, &intent, pending, report);
    platform_private_file_close(&intent);
    if (ok) *publication = DEVICE_PAIRING_DURABLE;
    else LOG_ERROR("device_pairing", "publication incomplete; inspect intent and grant");
    AR_FINISH_SAVE(&callbacks, row, ok);
}

static bool owner_confirmed(const struct device_pairing_store *store,
    const struct db_device_pairing *row, const uint8_t confirmed[32])
{
    uint8_t fingerprint[32];
    return confirmed && bound(store, row) && !row->revoked_at && !row->generation &&
        v2_identity_public_fingerprint(row->peer_key, fingerprint) &&
        !memcmp(fingerprint, confirmed, 32);
}

bool device_pairing_host_proposal_root(const struct db_device_pairing *row,
    uint8_t root[32])
{
    struct ar_errors errors;
    if (!row || !root) LOG_FAIL("device_pairing", "missing host proposal argument");
    if (!(row->capabilities & DEVICE_PAIRING_CAP_HOST_FORWARD) || row->revoked_at ||
        row->generation || !db_device_pairing_validate(row, &errors))
        LOG_FAIL("device_pairing", "invalid active host proposal");
    uint8_t wire[DEVICE_PAIRING_WIRE];
    size_t length = encode(row, wire);
    static const uint8_t domain[] = "Z23HOSTPROPOSAL1";
    struct sha3_256_ctx hash;
    sha3_256_init(&hash);
    sha3_256_write(&hash, domain, sizeof(domain) - 1);
    sha3_256_write(&hash, wire, length);
    sha3_256_finalize(&hash, root);
    return true;
}

static bool approval_matches(const struct device_pairing_store *store,
    const struct db_device_pairing *row, const uint8_t confirmed[32], bool host)
{
    if (host != ((row->capabilities & DEVICE_PAIRING_CAP_HOST_FORWARD) != 0)) return false;
    if (!host) return owner_confirmed(store, row, confirmed);
    uint8_t proposal[32];
    return confirmed && bound(store, row) && device_pairing_host_proposal_root(row, proposal) &&
        !memcmp(proposal, confirmed, 32);
}

static bool upgrade_matches(const struct db_device_pairing *current,
    const struct db_device_pairing *replacement, uint64_t now)
{
    return !memcmp(current->profile, replacement->profile, 32) &&
        !memcmp(current->local_key, replacement->local_key, 32) &&
        !memcmp(current->peer_key, replacement->peer_key, 32) &&
        current->paired_at == replacement->paired_at &&
        now >= current->paired_at && now < current->expires_at &&
        !current->revoked_at && !current->generation && replacement->expires_at > now;
}

static bool mutation_supported(void)
{
#if defined(_WIN32)
    LOG_FAIL("device_pairing", "Windows directory publication durability is unsupported; mutation refused");
#else
    return true;
#endif
}

static bool pairing_upgrade(struct device_pairing_store *store,
    const struct db_device_pairing *replacement, const uint8_t confirmed_fingerprint[32],
    const uint8_t expected_root[32], uint64_t now,
    enum device_pairing_publication *publication, bool host)
{
    if (publication) *publication = DEVICE_PAIRING_NOT_PUBLISHED;
    if (!mutation_supported()) return false;
    if (!store || !replacement || !expected_root || !publication || !now)
        LOG_FAIL("device_pairing", "missing upgrade argument");
    struct ar_errors errors;
    if (!approval_matches(store, replacement, confirmed_fingerprint, host) ||
        !db_device_pairing_validate(replacement, &errors))
        LOG_FAIL("device_pairing", "invalid explicit replacement or confirmation");
    struct device_pairing_guard guard;
    if (!lock_store(store, &guard, false)) return false;
    struct db_device_pairing current, copy = *replacement;
    uint8_t root[32];
    bool ok = read_exact_locked(store, replacement->peer_key, &current, root) &&
        !memcmp(root, expected_root, 32) && upgrade_matches(&current, replacement, now);
    if (ok) ok = publish_locked(store, &copy, true, publication, NULL, NULL);
    else LOG_ERROR("device_pairing", "upgrade requires exact active inspected authority");
    device_pairing_guard_release(&guard);
    return ok;
}

static bool pairing_insert(struct device_pairing_store *store,
                              struct db_device_pairing *row,
                              const uint8_t confirmed_fingerprint[32],
                              enum device_pairing_publication *publication, bool host)
{
    if (publication) *publication = DEVICE_PAIRING_NOT_PUBLISHED;
    if (!mutation_supported()) return false;
    if (!store || !row || !publication ||
        !approval_matches(store, row, confirmed_fingerprint, host))
        LOG_FAIL("device_pairing", "owner confirmation or profile binding failed");
    struct device_pairing_guard guard;
    if (!lock_store(store, &guard, false)) return false;
    char path[1200];
    bool ok = record_path(store, row->peer_key, path) &&
              platform_private_path_absent(path);
    if (ok) {
        struct db_device_pairing normalized = *row;
        if (!normalized.capabilities) normalized.capabilities = DEVICE_PAIRING_CAP_STATUS_READ;
        ok = publish_locked(store, &normalized, false, publication, NULL, NULL);
        if (ok) *row = normalized;
    }
    else LOG_ERROR("device_pairing", "existing grant cannot be replaced by pairing");
    device_pairing_guard_release(&guard);
    return ok;
}

bool db_device_pairing_insert(struct device_pairing_store *store,
    struct db_device_pairing *row, const uint8_t confirmed_fingerprint[32],
    enum device_pairing_publication *publication)
{
    return pairing_insert(store, row, confirmed_fingerprint, publication, false);
}

bool db_device_pairing_insert_host(struct device_pairing_store *store,
    struct db_device_pairing *row, const uint8_t confirmed_proposal_root[32],
    enum device_pairing_publication *publication)
{
    if (row && row->host_scope.binding.backend_profile == DEVICE_PAIRING_HOST_SHAKE256_WRAP_PSK) {
        if (publication) *publication = DEVICE_PAIRING_NOT_PUBLISHED;
        LOG_FAIL("device_pairing", "backend2 requires dedicated credential publication");
    }
    return pairing_insert(store, row, confirmed_proposal_root, publication, true);
}

bool db_device_pairing_upgrade(struct device_pairing_store *store,
    const struct db_device_pairing *replacement, const uint8_t confirmed_fingerprint[32],
    const uint8_t expected_root[32], uint64_t now,
    enum device_pairing_publication *publication)
{
    return pairing_upgrade(store, replacement, confirmed_fingerprint, expected_root, now, publication, false);
}

bool db_device_pairing_upgrade_host(struct device_pairing_store *store,
    const struct db_device_pairing *replacement, const uint8_t confirmed_proposal_root[32],
    const uint8_t expected_root[32], uint64_t now,
    enum device_pairing_publication *publication)
{
    if (replacement && replacement->host_scope.binding.backend_profile == DEVICE_PAIRING_HOST_SHAKE256_WRAP_PSK) {
        if (publication) *publication = DEVICE_PAIRING_NOT_PUBLISHED;
        LOG_FAIL("device_pairing", "backend2 requires dedicated credential rotation");
    }
    return pairing_upgrade(store, replacement, confirmed_proposal_root, expected_root, now, publication, true);
}

static bool revoke_locked(struct device_pairing_store *store,
                          const uint8_t peer_key[32], uint64_t now,
                          const uint8_t expected_root[32],
                          enum device_pairing_publication *publication)
{
    if (publication) *publication = DEVICE_PAIRING_NOT_PUBLISHED;
    if (!mutation_supported()) return false;
    if (!store || !peer_key || !publication || !now)
        LOG_FAIL("device_pairing", "invalid revoke argument");
    struct device_pairing_guard guard;
    if (!lock_store(store, &guard, false)) return false;
    struct db_device_pairing row = {0};
    uint8_t root[32];
    bool ok = read_exact_locked(store, peer_key, &row, root);
    if (ok && expected_root && memcmp(expected_root, root, 32)) {
        LOG_ERROR("device_pairing", "revocation requires the exact inspected authority root");
        ok = false;
    }
    if (ok && row.revoked_at) {
        *publication = DEVICE_PAIRING_DURABILITY_UNKNOWN;
        ok = platform_private_parent_flush(store->directory);
        if (ok) *publication = DEVICE_PAIRING_DURABLE;
    }
    else if (ok) {
        row.revoked_at = now;
        row.generation = 1;
        ok = publish_locked(store, &row, true, publication, NULL, NULL);
    }
    device_pairing_guard_release(&guard);
    return ok;
}

bool db_device_pairing_revoke(struct device_pairing_store *store,
    const uint8_t peer_key[32], uint64_t now,
    enum device_pairing_publication *publication)
{
    return revoke_locked(store, peer_key, now, NULL, publication);
}

bool db_device_pairing_revoke_expected(struct device_pairing_store *store,
    const uint8_t peer_key[32], uint64_t now, const uint8_t expected_root[32],
    enum device_pairing_publication *publication)
{
    if (publication) *publication = DEVICE_PAIRING_NOT_PUBLISHED;
    if (!expected_root) LOG_FAIL("device_pairing", "exact revocation root required");
    return revoke_locked(store, peer_key, now, expected_root, publication);
}

static bool guard_arguments_valid(struct device_pairing_store *store,
    const uint8_t peer_key[32], uint64_t now, uint64_t required,
    struct device_pairing_guard *guard)
{
    return store && peer_key && guard && now && required &&
        !(required & ~DEVICE_PAIRING_CAP_KNOWN);
}

static bool guard_acquire_retain(struct device_pairing_store *store,
    const uint8_t peer_key[32], uint64_t now, uint64_t required,
    struct device_pairing_guard *guard, struct platform_private_file *retain)
{
    if (!guard_arguments_valid(store, peer_key, now, required, guard))
        LOG_FAIL("device_pairing", "invalid guard argument");
    if (!lock_store(store, guard, true)) return false;
    DEVICE_PAIRING_TEST_COUNT(test_full_acquisitions);
    bool ok = read_exact_retain(store, peer_key, &guard->row, guard->root, retain) &&
        now >= guard->row.paired_at && now < guard->row.expires_at &&
        !guard->row.revoked_at && !guard->row.generation &&
        (guard->row.capabilities & required) == required;
    if (!ok) {
        device_pairing_guard_release(guard);
        LOG_FAIL("device_pairing", "required capability grant unavailable or inactive");
    }
    return true;
}
static bool guard_acquire_capability(struct device_pairing_store *store,
    const uint8_t peer_key[32], uint64_t now, uint64_t required,
    struct device_pairing_guard *guard)
{
    return guard_acquire_retain(store, peer_key, now, required, guard, NULL);
}

bool device_pairing_guard_acquire_capability(struct device_pairing_store *store,
    const uint8_t peer_key[32], uint64_t now, uint64_t required,
    struct device_pairing_guard *guard)
{
    if (required & (DEVICE_PAIRING_CAP_GUEST_BIND | DEVICE_PAIRING_CAP_HOST_FORWARD))
        LOG_FAIL("device_pairing", "binding authority requires exact scope guard");
    return guard_acquire_capability(store, peer_key, now, required, guard);
}

static bool guest_scope_equal(const struct device_pairing_guest_scope *a,
                              const struct device_pairing_guest_scope *b)
{
    return !memcmp(a->guest_id, b->guest_id, 32) &&
        !memcmp(a->requester_ssh_key, b->requester_ssh_key, 32) &&
        !memcmp(a->owner_grant_root, b->owner_grant_root, 32) &&
        a->enrollment_generation == b->enrollment_generation &&
        a->port_mask == b->port_mask;
}

bool device_pairing_guard_acquire_guest_bind(struct device_pairing_store *store,
    const uint8_t peer_key[32], uint64_t now,
    const struct device_pairing_guest_scope *scope, unsigned slot, unsigned role,
    struct device_pairing_guard *guard)
{
    if (!guard) LOG_FAIL("device_pairing", "missing bind guard");
    memset(guard, 0, sizeof(*guard));
    if (!scope || slot >= 2 || role >= 2 || !guest_scope_complete(scope))
        LOG_FAIL("device_pairing", "invalid bind scope or port");
    if (!guard_acquire_capability(store, peer_key, now,
        DEVICE_PAIRING_CAP_GUEST_BIND | DEVICE_PAIRING_CAP_GUEST_STREAM, guard)) {
        int error = errno;
        LOG_RETURN((errno = error, false), "device_pairing", "current guest bind capability guard unavailable");
    }
    if (!guest_scope_equal(scope, &guard->row.guest_scope) ||
        !(scope->port_mask & (UINT64_C(1) << (slot * 2 + role)))) {
        device_pairing_guard_release(guard);
        LOG_FAIL("device_pairing", "guest scope or port differs from authority");
    }
    return true;
}

bool device_pairing_guard_acquire(struct device_pairing_store *store,
    const uint8_t peer_key[32], uint64_t now, struct device_pairing_guard *guard)
{
    return device_pairing_guard_acquire_capability(store, peer_key, now,
        DEVICE_PAIRING_CAP_STATUS_READ, guard);
}

bool device_pairing_guard_acquire_host_forward(struct device_pairing_store *store,
    const uint8_t peer_key[32], uint64_t now,
    const struct device_pairing_host_binding *authenticated_binding,
    enum device_pairing_host_direction direction, uint16_t port,
    struct device_pairing_guard *guard)
{
    if (!guard) LOG_FAIL("device_pairing", "missing host guard");
    memset(guard, 0, sizeof(*guard));
    if (!authenticated_binding || authenticated_binding->backend_profile !=
        DEVICE_PAIRING_HOST_OPENSSH_MLKEM768X25519_MLDSA44ED25519 || !host_binding_valid(authenticated_binding))
        LOG_FAIL("device_pairing", "missing authenticated PQ host binding");
    if (!port || (direction != DEVICE_PAIRING_HOST_INBOUND &&
                  direction != DEVICE_PAIRING_HOST_OUTBOUND))
        LOG_FAIL("device_pairing", "invalid host direction or port");
    if (!guard_acquire_capability(store, peer_key, now,
        DEVICE_PAIRING_CAP_HOST_FORWARD, guard)) {
        int error = errno;
        LOG_RETURN((errno = error, false), "device_pairing", "current PQ host-forward capability guard unavailable");
    }
    uint16_t permitted = direction == DEVICE_PAIRING_HOST_INBOUND ?
        guard->row.host_scope.inbound_port : guard->row.host_scope.outbound_port;
    const struct device_pairing_host_binding *bound_binding = &guard->row.host_scope.binding;
    bool matched = authenticated_binding->backend_profile == bound_binding->backend_profile &&
        !memcmp(authenticated_binding->local_pq_key_root, bound_binding->local_pq_key_root, 32) &&
        !memcmp(authenticated_binding->peer_pq_key_root, bound_binding->peer_pq_key_root, 32);
    if (permitted != port || !matched) {
        device_pairing_guard_release(guard);
        LOG_FAIL("device_pairing", "host direction or port differs from authority");
    }
    return true;
}

static bool psk_owner_approved(const struct device_pairing_store *store,
    const struct db_device_pairing *row, const uint8_t confirmed[32])
{
    uint8_t proposal[32];
    return confirmed && row->host_scope.binding.backend_profile == DEVICE_PAIRING_HOST_SHAKE256_WRAP_PSK &&
        bound(store, row) && device_pairing_host_proposal_root(row, proposal) && !memcmp(proposal, confirmed, 32);
}
static bool psk_mutation_preflight(struct device_pairing_store *store,
    const struct db_device_pairing *row, const uint8_t secret[32], const uint8_t confirmed[32],
    struct device_pairing_psk_publication *report)
{
    if (report) memset(report, 0, sizeof(*report));
    if (!mutation_supported()) return false;
    if (!store || !row || !secret || !report || !psk_owner_approved(store, row, confirmed))
        LOG_FAIL("device_pairing", "PSK import requires explicit approved owner-private credential and complete proposal");
    return true;
}
bool db_device_pairing_insert_host_psk(struct device_pairing_store *store,
    struct db_device_pairing *row, const uint8_t secret[32],
    const uint8_t confirmed_proposal_root[32], struct device_pairing_psk_publication *report)
{
    if (!psk_mutation_preflight(store, row, secret, confirmed_proposal_root, report)) return false;
    /* lock_store may itself create authority.lock: conservatively include it. */
    report->mutation_attempted = true;
    struct device_pairing_guard guard;
    if (!lock_store(store, &guard, false)) return false;
    char path[1200];
    bool ok = record_path(store, row->peer_key, path) && publication_absent(path) &&
        platform_private_path_absent(path) && psk_paths_absent(store, row);
    if (ok) ok = publish_locked(store, row, false, &report->grant, secret, report);
    else LOG_ERROR("device_pairing", "PSK insert requires absent grant, intent and unused credential ID");
    device_pairing_guard_release(&guard);
    return ok;
}
static bool psk_rotation_matches(const struct db_device_pairing *current,
    const struct db_device_pairing *replacement, uint64_t now)
{
    const struct device_pairing_psk_binding *old = &current->host_scope.binding.psk;
    const struct device_pairing_psk_binding *next = &replacement->host_scope.binding.psk;
    return current->host_scope.binding.backend_profile == DEVICE_PAIRING_HOST_SHAKE256_WRAP_PSK &&
        upgrade_matches(current, replacement, now) && next->key_epoch > old->key_epoch &&
        memcmp(old->credential_id, next->credential_id, 32);
}
bool db_device_pairing_rotate_host_psk(struct device_pairing_store *store,
    const struct db_device_pairing *replacement, const uint8_t secret[32],
    const uint8_t confirmed_proposal_root[32], const uint8_t expected_root[32],
    uint64_t now, struct device_pairing_psk_publication *report)
{
    if (!psk_mutation_preflight(store, replacement, secret, confirmed_proposal_root, report)) return false;
    if (!expected_root || !now) LOG_FAIL("device_pairing", "PSK rotation requires exact current root/time");
    report->mutation_attempted = true;
    struct device_pairing_guard guard;
    if (!lock_store(store, &guard, false)) return false;
    struct db_device_pairing current, copy = *replacement;
    uint8_t root[32];
    bool ok = read_exact_locked(store, replacement->peer_key, &current, root) &&
        !memcmp(root, expected_root, 32) && psk_rotation_matches(&current, replacement, now) &&
        psk_paths_absent(store, replacement);
    if (ok) ok = publish_locked(store, &copy, true, &report->grant, secret, report);
    else LOG_ERROR("device_pairing", "PSK rotation requires exact active root, new ID and increasing epoch");
    device_pairing_guard_release(&guard);
    return ok;
}
static bool psk_binding_equal(const struct device_pairing_psk_binding *a,
    const struct device_pairing_psk_binding *b)
{
    return !memcmp(a->credential_id, b->credential_id, 32) && a->key_epoch == b->key_epoch &&
        !memcmp(a->endpoint_a, b->endpoint_a, 32) && !memcmp(a->endpoint_b, b->endpoint_b, 32);
}
static bool psk_scope_matches(const struct device_pairing_guard *guard,
    const uint8_t expected_root[32], enum device_pairing_host_direction direction, uint16_t port)
{
    uint16_t permitted = direction == DEVICE_PAIRING_HOST_INBOUND ?
        guard->row.host_scope.inbound_port : guard->row.host_scope.outbound_port;
    return guard->row.host_scope.binding.backend_profile == DEVICE_PAIRING_HOST_SHAKE256_WRAP_PSK &&
        !memcmp(guard->root, expected_root, 32) && port == permitted;
}
static bool psk_scope_retain(struct device_pairing_store *store, const uint8_t peer[32],
    const uint8_t expected_root[32], uint64_t now, enum device_pairing_host_direction direction,
    uint16_t port, struct device_pairing_guard *guard, struct platform_private_file *retain)
{
    if (!guard) LOG_FAIL("device_pairing", "missing PSK guard");
    memset(guard, 0, sizeof(*guard));
    if (!expected_root || !port || (direction != DEVICE_PAIRING_HOST_INBOUND && direction != DEVICE_PAIRING_HOST_OUTBOUND))
        LOG_FAIL("device_pairing", "PSK guard requires root, exact direction and nonzero port");
    if (!guard_acquire_retain(store, peer, now, DEVICE_PAIRING_CAP_HOST_FORWARD, guard, retain)) {
        int error = errno;
        LOG_RETURN((errno = error, false), "device_pairing", "current PSK host-forward capability guard unavailable");
    }
    if (!psk_scope_matches(guard, expected_root, direction, port)) {
        device_pairing_guard_release(guard);
        LOG_FAIL("device_pairing", "PSK current root/backend/direction/port mismatch");
    }
    return true;
}
static bool psk_scope_acquire(struct device_pairing_store *store, const uint8_t peer[32],
    const uint8_t expected_root[32], uint64_t now, enum device_pairing_host_direction direction,
    uint16_t port, struct device_pairing_guard *guard)
{
    return psk_scope_retain(store, peer, expected_root, now, direction, port, guard, NULL);
}
static bool host_psk_retain(struct device_pairing_store *store,
    const uint8_t peer[32], const uint8_t expected_root[32], uint64_t now,
    const struct device_pairing_psk_binding *binding,
    enum device_pairing_host_direction direction, uint16_t port,
    struct device_pairing_guard *guard, struct platform_private_file *retain)
{
    if (!guard) LOG_FAIL("device_pairing", "missing PSK guard");
    memset(guard, 0, sizeof(*guard));
    if (!binding || !psk_binding_valid(binding)) LOG_FAIL("device_pairing", "invalid PSK binding");
    if (!psk_scope_retain(store, peer, expected_root, now, direction, port, guard, retain)) return false;
    if (!psk_binding_equal(binding, &guard->row.host_scope.binding.psk)) {
        device_pairing_guard_release(guard);
        LOG_FAIL("device_pairing", "PSK credential/epoch/endpoint binding mismatch");
    }
    return true;
}
bool device_pairing_guard_acquire_host_psk(struct device_pairing_store *store,
    const uint8_t peer[32], const uint8_t expected_root[32], uint64_t now,
    const struct device_pairing_psk_binding *binding,
    enum device_pairing_host_direction direction, uint16_t port,
    struct device_pairing_guard *guard)
{
    return host_psk_retain(store, peer, expected_root, now, binding, direction, port, guard, NULL);
}
void device_pairing_guard_cache_destroy(struct device_pairing_guard_cache *cache)
{
    if (!cache) return;
    if (cache->valid) platform_private_file_close(&cache->grant);
    lease_unref(cache->lease);
    memory_cleanse(cache, sizeof(*cache));
}
static bool cache_arguments_match(const struct device_pairing_guard_cache *cache,
    const struct device_pairing_store *store, const uint8_t peer[32], const uint8_t expected_root[32],
    const struct device_pairing_psk_binding *binding, enum device_pairing_host_direction direction, uint16_t port)
{
    return cache->valid && cache->store == store && peer && expected_root && !memcmp(cache->peer, peer, 32) &&
        !memcmp(cache->expected_root, expected_root, 32) && psk_binding_equal(&cache->binding, binding) &&
        cache->direction == direction && cache->port == port;
}
static bool cache_fresh(const struct device_pairing_guard_cache *cache, uint64_t now)
{
    int64_t mono = clock_now_monotonic_ns();
    return now && mono > 0 && mono >= cache->validated_ns &&
        mono - cache->validated_ns < DEVICE_PAIRING_GUARD_CACHE_NS &&
        now >= cache->row.paired_at && now < cache->row.expires_at;
}
static bool state_equal(const char *path, const struct platform_private_path_state *expected)
{
    struct platform_private_path_state actual;
    return platform_private_path_state(path, &actual) && !memcmp(&actual, expected, sizeof(actual));
}
/* The profile directory is compared by identity and protection only. Its
 * mtime/ctime move whenever any entry is created or renamed, and every entry
 * this memo depends on (lock, pending, grant) is compared on its own below, so
 * timestamps would add only spurious misses and would hide a missing check. */
static bool directory_equal(const char *path, const struct platform_private_path_state *expected)
{
    struct platform_private_path_state actual;
    return platform_private_path_state(path, &actual) && actual.volume == expected->volume &&
        actual.file == expected->file && actual.mode == expected->mode && actual.owner == expected->owner;
}
/* Cached revalidation. Guarantee: the returned guard holds the shared
 * authority.lock, and the row and root the last full acquisition read are
 * still the current authority, i.e. any revoke, rotation, upgrade, root change
 * or pending intent that completed before the check is observed by it, and a
 * replaced profile directory, lock inode or grant inode is never accepted.
 *
 * Protocol, in this order (6 syscalls, was 7; one open+fstat+close pair of
 * the lock file became a held descriptor):
 *   1. lstat(profile dir): same dev/ino/mode/owner as at the full read, so the
 *      path still names the directory every later path below resolves in.
 *   2. flock(held lock fd, SH|NB): the shared lock is taken before anything
 *      else is read. A writer holding or waiting for the exclusive lock makes
 *      this fail, which is a miss, exactly as the old open-then-flock did.
 *   3. lstat(authority.lock): must be the inode the descriptor pins. The
 *      descriptor keeps that inode alive, so its number cannot be reused; if
 *      the path names a different inode a publisher may hold the exclusive
 *      lock on it unseen by our lock, so we miss and the full path re-reads.
 *      Like the old code there is a window between lock and compare in which a
 *      replacement may land; it is ordered after this check, so it is not
 *      "completed before the check".
 *   4. lstat(<grant>.pending): absent. Under the lock no publisher is between
 *      intent and retirement, so an absent intent means no publication is in
 *      flight.
 *   5. lstat(grant): same inode, size, mode, owner, mtime and ctime as the
 *      retained descriptor at the full read. Every mutation renames a fresh
 *      inode over the path, so identical bytes in a new file still differ in
 *      inode and ctime.
 *   6. flock(LOCK_UN) at device_pairing_guard_release, replacing close().
 * Removed against the old sequence: open(authority.lock), its fstat and the
 * close. Each was only a way to obtain a fresh descriptor on the current lock
 * inode; step 3 proves the held descriptor is on that inode, so they carry no
 * information. The lock is never held between acquisitions, so writers are
 * not blocked. Any doubt is a miss and the full acquisition decides. */
static bool cache_revalidate(struct device_pairing_guard_cache *cache, struct device_pairing_store *store,
    const uint8_t peer[32], struct device_pairing_guard *guard)
{
    char lock[1200], grant[1200], pending[1240];
    int n = snprintf(lock, sizeof(lock), "%s/authority.lock", store->directory);
    if (n < 0 || (size_t)n >= sizeof(lock) || !record_path(store, peer, grant)) return false; // raw-return-ok:cache miss; the full acquisition logs
    n = snprintf(pending, sizeof(pending), "%s.pending", grant);
    if (n < 0 || (size_t)n >= sizeof(pending) || !cache->lease || !directory_equal(store->directory, &cache->directory)) return false; // raw-return-ok:cache miss; the full acquisition logs
    platform_private_file_init(&guard->lock);
    if (!lease_borrow(cache->lease, lock, guard)) return false; // raw-return-ok:cache miss; the full acquisition logs
    if (!platform_private_path_absent(pending) || !state_equal(grant, &cache->grant_state)) {
        device_pairing_guard_release(guard); return false; // raw-return-ok:cache miss; the full acquisition logs
    }
    guard->row = cache->row; memcpy(guard->root, cache->root, 32);
    DEVICE_PAIRING_TEST_COUNT(test_cached_acquisitions);
    return true;
}
static void cache_remember(struct device_pairing_guard_cache *cache, struct device_pairing_store *store,
    const uint8_t peer[32], const uint8_t expected_root[32], const struct device_pairing_psk_binding *binding,
    enum device_pairing_host_direction direction, uint16_t port,
    struct device_pairing_guard *guard, struct platform_private_file *retained)
{
    struct device_pairing_guard_cache next = {.grant = *retained, .row = guard->row, .binding = *binding,
        .store = store, .validated_ns = clock_now_monotonic_ns(), .direction = direction, .port = port};
    memcpy(next.root, guard->root, 32); memcpy(next.peer, peer, 32); memcpy(next.expected_root, expected_root, 32);
    struct platform_private_path_state held;
    char lock[1200];
    int n = snprintf(lock, sizeof(lock), "%s/authority.lock", store->directory);
    next.valid = next.validated_ns > 0 && n > 0 && (size_t)n < sizeof(lock) &&
        platform_private_file_state(retained, &next.grant_state) &&
        platform_private_path_state(store->directory, &next.directory) &&
        platform_private_file_state(&guard->lock, &held) &&
        (next.lease = lease_open(lock, &held)) != NULL;
    if (next.valid) *cache = next;
    else { platform_private_file_close(retained); lease_unref(next.lease); }
    memory_cleanse(&next, sizeof(next));
}
bool device_pairing_guard_acquire_host_psk_cached(struct device_pairing_store *store,
    const uint8_t peer[32], const uint8_t expected_root[32], uint64_t now,
    const struct device_pairing_psk_binding *binding,
    enum device_pairing_host_direction direction, uint16_t port,
    struct device_pairing_guard_cache *cache, struct device_pairing_guard *guard)
{
    if (!cache || !guard || !binding || lease_lent(cache->lease))
        return device_pairing_guard_acquire_host_psk(store, peer, expected_root, now, binding, direction, port, guard);
    memset(guard, 0, sizeof(*guard));
    if (cache_arguments_match(cache, store, peer, expected_root, binding, direction, port) &&
        cache_fresh(cache, now) && cache_revalidate(cache, store, peer, guard)) return true;
    device_pairing_guard_cache_destroy(cache);
    struct platform_private_file retained; platform_private_file_init(&retained);
    if (!host_psk_retain(store, peer, expected_root, now, binding, direction, port, guard, &retained)) {
        platform_private_file_close(&retained); return false; // raw-return-ok:host_psk_retain logged the refusal
    }
    cache_remember(cache, store, peer, expected_root, binding, direction, port, guard, &retained);
    return true;
}
static bool psk_wire_metadata_matches(const uint8_t wire[PSK_SECRET_WIRE],
    const struct db_device_pairing *row)
{
    const struct device_pairing_psk_binding *binding = &row->host_scope.binding.psk;
    uint64_t epoch = zcl_read_u64_be(wire + 80);
    return !memcmp(wire + 16, row->profile, 32) && !memcmp(wire + 48, binding->credential_id, 32) &&
        epoch == binding->key_epoch && !memcmp(wire + 88, binding->endpoint_a, 32) &&
        !memcmp(wire + 120, binding->endpoint_b, 32);
}
static bool psk_wire_valid(const uint8_t wire[PSK_SECRET_WIRE], const struct db_device_pairing *row)
{
    static const uint8_t header[16] = {'Z','2','3','P','S','K','C','1',0,1,0,0,0,0,0,216};
    uint8_t checksum[32]; psk_checksum(wire, checksum);
    bool ok = !memcmp(wire, header, sizeof(header)) && !memcmp(wire + 184, checksum, 32) &&
        psk_wire_metadata_matches(wire, row);
    memory_cleanse(checksum, sizeof(checksum));
    return ok;
}
static bool read_psk_secret_locked(const struct device_pairing_store *store,
    const struct db_device_pairing *row, uint8_t secret[32])
{
    char path[1200];
    if (!psk_path(store, row->host_scope.binding.psk.credential_id, path)) return false;
    struct platform_private_file file; platform_private_file_init(&file);
    uint8_t wire[PSK_SECRET_WIRE]; uint64_t length = 0;
    bool ok = platform_private_file_open_observation(path, &file) &&
        platform_private_file_size(&file, &length) && length == sizeof(wire) &&
        platform_private_file_read_at(&file, wire, sizeof(wire), 0) && psk_wire_valid(wire, row);
    if (ok) memcpy(secret, wire + 152, 32);
    platform_private_file_close(&file); memory_cleanse(wire, sizeof(wire));
    if (!ok) LOG_ERROR("device_pairing", "current PSK credential unavailable or metadata invalid; read never repairs");
    return ok;
}
bool device_pairing_psk_snapshot_acquire(struct device_pairing_store *store,
    const uint8_t peer[32], const uint8_t expected_root[32], uint64_t now,
    enum device_pairing_host_direction direction, uint16_t port,
    struct device_pairing_guard *guard, struct device_pairing_psk_snapshot *snapshot)
{
    if (!snapshot) {
        if (guard) memset(guard, 0, sizeof(*guard));
        LOG_FAIL("device_pairing", "missing owning PSK snapshot output");
    }
    if (!psk_scope_acquire(store, peer, expected_root, now, direction, port, guard)) return false;
    struct device_pairing_psk_snapshot trial = {0};
    trial.row = guard->row; memcpy(trial.root, guard->root, 32);
    bool ok = read_psk_secret_locked(store, &guard->row, trial.secret);
    if (ok) *snapshot = trial;
    else device_pairing_guard_release(guard);
    memory_cleanse(&trial, sizeof(trial));
    return ok;
}
void device_pairing_psk_snapshot_destroy(struct device_pairing_psk_snapshot *snapshot)
{
    if (snapshot) memory_cleanse(snapshot, sizeof(*snapshot));
}
