/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: atomic, lease-pinned publication of pure service vtables. */

#include "hotswap/hotswap_service.h"

#include "hotswap/hotswap.h"
#include "hotswap/hotswap_module.h"
#include "hotswap/hotswap_artifact_digest.h"
#include "hotswap/hotswap_elf_probe.h"
#include "hotswap/hotswap_sealed_image.h"

#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "platform/fd_path.h"
#include "platform/time_compat.h"
#include "base/hex.h"
#include "crypto/sha256.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#if ZCL_HOTSWAP_NATIVE_AVAILABLE
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#endif

struct service_slot {
    const char *service_id; /* resident contract string */
    const void *vtable;     /* immutable candidate object */
};

struct service_snapshot {
    uint32_t generation;
    size_t count;
    struct service_slot slots[ZCL_HOTSWAP_SERVICE_MAX];
    _Atomic uint32_t refs;
    struct service_snapshot *published_prev;
};

static struct service_snapshot *_Atomic g_active_services;
static struct service_snapshot *_Atomic g_published_services;
static atomic_flag g_service_write_lock = ATOMIC_FLAG_INIT;

struct service_manifest_row {
    const char *service_id;
    const char *source;
    const char *headers;
    const char *contract_headers;
    const char *probe;
};

static const struct service_manifest_row k_service_manifest[] = {
#define HOTSWAP_SERVICE(id_, source_, headers_, contract_headers_, imports_, abi_, schema_, wire_, kat_, probe_) \
    { (id_), (source_), (headers_), (contract_headers_), (probe_) },
#include "../../../engine/composition/hotswap_services.def"
#undef HOTSWAP_SERVICE
};

struct shadow_owner_row {
    const char *owner;
    const char *service;
};

static bool token_list_contains(const char *list, const char *token);

static const struct shadow_owner_row k_shadow_owners[] = {
#define HOTSHADOW_OWNER(owner_, service_) { (owner_), (service_) },
#define HOTSHADOW_SERVICE_MEMBERS(service_, members_)
#include "../../../engine/composition/hotswap_shadow_owners.def"
#undef HOTSHADOW_SERVICE_MEMBERS
#undef HOTSHADOW_OWNER
};

static const struct shadow_owner_row k_shadow_members[] = {
#define HOTSHADOW_OWNER(owner_, service_)
#define HOTSHADOW_SERVICE_MEMBERS(service_, members_) { (service_), (members_) },
#include "../../../engine/composition/hotswap_shadow_owners.def"
#undef HOTSHADOW_SERVICE_MEMBERS
#undef HOTSHADOW_OWNER
};

const char *zcl_hotswap_shadow_service_for_owner(const char *path)
{
    if (!path) return NULL;
    for (size_t i = 0; i < sizeof(k_shadow_owners) /
                            sizeof(k_shadow_owners[0]); i++)
        if (strcmp(path, k_shadow_owners[i].owner) == 0)
            return k_shadow_owners[i].service;
    for (size_t i = 0; i < sizeof(k_shadow_members) /
                            sizeof(k_shadow_members[0]); i++)
        if (token_list_contains(k_shadow_members[i].service, path))
            return k_shadow_members[i].owner;
    return NULL;
}

const char *zcl_hotswap_shadow_members_for_service(const char *service)
{
    if (!service) return NULL;
    for (size_t i = 0; i < sizeof(k_shadow_members) /
                            sizeof(k_shadow_members[0]); i++)
        if (strcmp(service, k_shadow_members[i].owner) == 0)
            return k_shadow_members[i].service;
    return NULL;
}

bool zcl_hotswap_shadow_path_is_static_owner(const char *path)
{
    if (!path) return false;
    for (size_t i = 0; i < sizeof(k_shadow_owners) /
                            sizeof(k_shadow_owners[0]); i++)
        if (strcmp(path, k_shadow_owners[i].owner) == 0) return true;
    return false;
}

static bool token_list_contains(const char *list, const char *token)
{
    if (!list || !token || !token[0] || strcmp(list, "-") == 0) return false;
    size_t want = strlen(token);
    for (const char *at = list; *at;) {
        while (*at == ' ' || *at == '\t') at++;
        const char *end = at;
        while (*end && *end != ' ' && *end != '\t') end++;
        if ((size_t)(end - at) == want && memcmp(at, token, want) == 0)
            return true;
        at = end;
    }
    return false;
}

const char *zcl_hotswap_service_contract_source_for_path(const char *path)
{
    if (!path) return NULL;
    for (size_t i = 0; i < sizeof(k_service_manifest) /
                            sizeof(k_service_manifest[0]); i++)
        if (token_list_contains(k_service_manifest[i].contract_headers, path))
            return k_service_manifest[i].source;
    return NULL;
}

const char *zcl_hotswap_service_source_for_path(const char *path)
{
    if (!path) return NULL;
    for (size_t i = 0; i < sizeof(k_service_manifest) /
                            sizeof(k_service_manifest[0]); i++)
        if (strcmp(path, k_service_manifest[i].source) == 0 ||
            token_list_contains(k_service_manifest[i].headers, path))
            return k_service_manifest[i].source;
    return NULL;
}

const char *zcl_hotswap_service_probe_for_source(const char *source)
{
    if (!source) return NULL;
    for (size_t i = 0; i < sizeof(k_service_manifest) /
                            sizeof(k_service_manifest[0]); i++)
        if (strcmp(source, k_service_manifest[i].source) == 0)
            return k_service_manifest[i].probe;
    return NULL;
}

const char *zcl_hotswap_service_probe_for_id(const char *service_id)
{
    if (!service_id) return NULL;
    for (size_t i = 0; i < sizeof(k_service_manifest) /
                            sizeof(k_service_manifest[0]); i++)
        if (strcmp(service_id, k_service_manifest[i].service_id) == 0)
            return k_service_manifest[i].probe;
    return NULL;
}

static void service_lock(void)
{
    while (atomic_flag_test_and_set_explicit(&g_service_write_lock,
                                             memory_order_acquire))
        ;
}

static void service_unlock(void)
{
    atomic_flag_clear_explicit(&g_service_write_lock, memory_order_release);
}

static void copy_text(char *out, size_t out_sz, const char *text)
{
    if (!out || !out_sz) return;
    (void)snprintf(out, out_sz, "%s", text ? text : "");
}

static bool reject(struct zcl_hotswap_service_report *report,
                   const char *stage, bool dev_restart, const char *detail)
{
    copy_text(report->stage, sizeof(report->stage), stage);
    copy_text(report->error, sizeof(report->error), detail);
    report->rolled_back = true;
    report->dev_restart = dev_restart;
    LOG_WARN("hotswap.service", "reject service=%s stage=%s: %s",
             report->service_id, report->stage, report->error);
    return false;
}

static bool equal_text(const char *a, const char *b)
{
    return a && b && strcmp(a, b) == 0;
}

static const void *snapshot_lookup(const struct service_snapshot *snapshot,
                                   const char *service_id)
{
    if (!snapshot || !service_id) return NULL;
    for (size_t i = 0; i < snapshot->count; i++)
        if (strcmp(snapshot->slots[i].service_id, service_id) == 0)
            return snapshot->slots[i].vtable;
    return NULL;
}

static struct service_snapshot *snapshot_acquire(void)
{
    for (;;) {
        struct service_snapshot *snapshot = atomic_load_explicit(
            &g_active_services, memory_order_acquire);
        if (!snapshot) return NULL;
        atomic_fetch_add_explicit(&snapshot->refs, 1, memory_order_acq_rel);
        if (snapshot == atomic_load_explicit(&g_active_services,
                                             memory_order_acquire))
            return snapshot;
        atomic_fetch_sub_explicit(&snapshot->refs, 1, memory_order_acq_rel);
    }
}

const void *zcl_hotswap_service_acquire(
    const char *service_id, struct zcl_hotswap_service_lease *lease)
{
    if (lease) lease->snapshot = NULL;
    if (!service_id || !service_id[0] || !lease)
        return NULL;
    struct service_snapshot *snapshot = snapshot_acquire();
    const void *vtable = snapshot_lookup(snapshot, service_id);
    if (!vtable) {
        if (snapshot)
            atomic_fetch_sub_explicit(&snapshot->refs, 1,
                                      memory_order_release);
        return NULL;
    }
    lease->snapshot = snapshot;
    return vtable;
}

void zcl_hotswap_service_release(struct zcl_hotswap_service_lease *lease)
{
    if (!lease || !lease->snapshot) return;
    struct service_snapshot *snapshot = lease->snapshot;
    lease->snapshot = NULL;
    atomic_fetch_sub_explicit(&snapshot->refs, 1, memory_order_release);
}

uint32_t zcl_hotswap_service_generation(void)
{
    const struct service_snapshot *snapshot = atomic_load_explicit(
        &g_active_services, memory_order_acquire);
    return snapshot ? snapshot->generation : 0u;
}

bool zcl_hotswap_service_all_retired_quiesced(void)
{
    const struct service_snapshot *active = atomic_load_explicit(
        &g_active_services, memory_order_acquire);
    const struct service_snapshot *snapshot = atomic_load_explicit(
        &g_published_services, memory_order_acquire);
    for (; snapshot; snapshot = snapshot->published_prev)
        if (snapshot != active &&
            atomic_load_explicit(&snapshot->refs, memory_order_acquire) != 0)
            return false;
    return true;
}

void zcl_hotswap_service_reset(void)
{
    service_lock();
    atomic_store_explicit(&g_active_services, NULL, memory_order_release);
    service_unlock();
}

bool zcl_hotswap_service_publish(
    const struct zcl_hotswap_service_contract *contract,
    const struct zcl_hotswap_service_candidate *candidate,
    bool activate, struct zcl_hotswap_service_report *report)
{
    if (!report)
        LOG_FAIL("hotswap.service", "publish report is NULL");
    memset(report, 0, sizeof(*report));
    report->verify_only = !activate;
    if (contract) copy_text(report->service_id, sizeof(report->service_id),
                            contract->service_id);
#ifdef _WIN32
    if (activate)
        return reject(report, "windows", false,
                      "service activation is disabled on Windows pending "
                      "validated PE imports and immutable staging");
#endif
    if (!contract || !candidate || !contract->service_id ||
        !contract->source_tu || !candidate->service_id ||
        !candidate->source_tu || !contract->frozen_kat ||
        !candidate->vtable)
        return reject(report, "fields", false,
                      "contract or candidate has missing required fields");
    if (!equal_text(contract->service_id, candidate->service_id) ||
        !equal_text(contract->source_tu, candidate->source_tu))
        return reject(report, "service", false,
                      "service id or owning source mismatch");
    if (contract->abi_version != candidate->abi_version ||
        contract->vtable_size != candidate->vtable_size ||
        !equal_text(contract->abi_fingerprint,
                    candidate->abi_fingerprint))
        return reject(report, "abi", true,
                      "service ABI changed; select DEV_RESTART");
    if (!equal_text(contract->schema_fingerprint,
                    candidate->schema_fingerprint))
        return reject(report, "schema", true,
                      "service schema changed; select DEV_RESTART");
    if (!equal_text(contract->wire_fingerprint,
                    candidate->wire_fingerprint))
        return reject(report, "wire", true,
                      "service wire contract changed; select DEV_RESTART");
    if (!equal_text(contract->kat_fingerprint,
                    candidate->kat_fingerprint))
        return reject(report, "kat", true,
                      "frozen KAT identity changed; select DEV_RESTART");
    char why[192] = {0};
    int64_t execute_started = platform_time_monotonic_us();
    bool kat_ok = contract->frozen_kat(candidate->vtable, why, sizeof(why));
    report->execute_us = platform_time_monotonic_us() - execute_started;
    if (!kat_ok)
        return reject(report, "kat", false,
                      why[0] ? why : "frozen KAT failed");
    report->probed = true;
    if (!activate) {
        report->ok = true;
        copy_text(report->stage, sizeof(report->stage), "verified");
        return true;
    }

    service_lock();
    const struct service_snapshot *old = atomic_load_explicit(
        &g_active_services, memory_order_acquire);
    struct service_snapshot *next = zcl_malloc(
        sizeof(*next), "hot-swap service snapshot");
    if (!next) {
        service_unlock();
        return reject(report, "publish", false,
                      "service snapshot allocation failed");
    }
    if (old) memcpy(next, old, sizeof(*next));
    else memset(next, 0, sizeof(*next));
    next->generation = old ? old->generation + 1u : 1u;
    atomic_store_explicit(&next->refs, 0, memory_order_relaxed);
    next->published_prev = NULL;
    size_t slot = next->count;
    for (size_t i = 0; i < next->count; i++)
        if (strcmp(next->slots[i].service_id, contract->service_id) == 0) {
            slot = i;
            break;
        }
    if (slot == next->count) {
        if (next->count >= ZCL_HOTSWAP_SERVICE_MAX) {
            service_unlock();
            /* Unpublished candidate is private, but snapshots follow the
             * never-free discipline; retain it rather than introduce a raw
             * deallocator into this safety-critical publication path. */
            return reject(report, "capacity", false,
                          "service registry capacity exceeded");
        }
        next->count++;
    }
    next->slots[slot].service_id = contract->service_id;
    next->slots[slot].vtable = candidate->vtable;
    next->published_prev = atomic_load_explicit(&g_published_services,
                                                memory_order_acquire);
    atomic_store_explicit(&g_published_services, next, memory_order_release);
    atomic_store_explicit(&g_active_services, next, memory_order_release);
    service_unlock();
    report->ok = true;
    report->activated = true;
    report->generation = next->generation;
    copy_text(report->stage, sizeof(report->stage), "activated");
    return true;
}

/* Host exclusions nest INSIDE the plain `#ifdef ZCL_DEV_BUILD` region so a
 * dl* call site can never leave the dev-only region (check-hotswap-dev-only
 * reads that exact toggle; a release build must link zero dl* code). */
#ifdef ZCL_DEV_BUILD
#if defined(__linux__) && !defined(_WIN32)
struct service_handle_slot {
    char service_id[96];
    void *handle;
};

static pthread_mutex_t g_handle_lock = PTHREAD_MUTEX_INITIALIZER;
static struct service_handle_slot g_handles[ZCL_HOTSWAP_SERVICE_MAX];
static size_t g_handle_count;

static bool service_image_sha256(int fd, char digest_hex[65])
{
    if (lseek(fd, 0, SEEK_SET) < 0) return false;
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    unsigned char bytes[64 * 1024];
    for (;;) {
        ssize_t count = read(fd, bytes, sizeof(bytes));
        if (count > 0) { sha256_write(&ctx, bytes, (size_t)count); continue; }
        if (count == 0) break;
        if (errno != EINTR) return false;
    }
    if (lseek(fd, 0, SEEK_SET) < 0) return false;
    unsigned char digest[SHA256_OUTPUT_SIZE];
    sha256_finalize(&ctx, digest);
    zcl_hex_encode(digest, sizeof(digest), digest_hex);
    return true;
}

static bool service_image_shape_ok(int fd, char *why, size_t why_sz)
{
    struct hotswap_elf_facts facts;
    if (!hotswap_elf_probe_fd(fd, &facts, why, why_sz)) return false;
    if (facts.has_dt_init || facts.init_array_entries ||
        facts.preinit_array_entries || facts.ifunc_symbol_count ||
        facts.has_irelative_relocation) {
        copy_text(why, why_sz, "service image has pre-load executable code");
        return false;
    }
    if (facts.has_runpath || facts.needed_truncated) {
        copy_text(why, why_sz, "service image has unbounded dependencies");
        return false;
    }
    for (size_t i = 0; i < facts.needed_count; i++)
        if (strcmp(facts.needed[i], "libc.so.6") != 0 &&
            strcmp(facts.needed[i], "libm.so.6") != 0) {
            copy_text(why, why_sz, "service image has an unapproved dependency");
            return false;
        }
    return true;
}

static int service_sealed_image(const char *path, char sha256[65],
                                char sha3[65],
                                char *why, size_t why_sz)
{
    int source = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    if (source < 0 || fstat(source, &st) != 0 || !S_ISREG(st.st_mode)) {
        if (source >= 0) (void)close(source);
        copy_text(why, why_sz, "cannot pin a regular service artifact");
        return -1;
    }
    int image = hotswap_sealed_image_from_fd(source, why, why_sz);
    (void)close(source);
    if (image < 0) return -1;
    if (!service_image_shape_ok(image, why, why_sz) ||
        !service_image_sha256(image, sha256) ||
        !hotswap_artifact_sha3_fd(image, sha3)) {
        if (!why[0]) copy_text(why, why_sz, "cannot hash sealed service image");
        (void)close(image);
        return -1;
    }
    return image;
}

static void *service_open_image(const char *path, char sha256[65],
                                char sha3[65],
                                int64_t *load_us,
                                struct zcl_hotswap_service_report *report)
{
    char why[256] = {0};
    int image = service_sealed_image(path, sha256, sha3, why, sizeof(why));
    if (image < 0) {
        (void)reject(report, "image", false, why);
        return NULL;
    }
    char pinned[64];
    if (!platform_fd_path(pinned, sizeof(pinned), image, NULL)) {
        (void)close(image);
        (void)reject(report, "image", false,
                     "cannot name sealed service image");
        return NULL;
    }
    int64_t started = platform_time_monotonic_us();
    void *handle = dlopen(pinned, RTLD_NOW | RTLD_LOCAL);
    *load_us = platform_time_monotonic_us() - started;
    (void)close(image);
    if (!handle) (void)reject(report, "dlopen", false, dlerror());
    return handle;
}

static void service_close_after_quiesce(void *handle)
{
    if (!handle) return;
    struct timespec pause = {.tv_nsec = 1000000L};
    for (unsigned i = 0; i < 250; i++) {
        if (zcl_hotswap_service_all_retired_quiesced()) {
            (void)dlclose(handle);
            return;
        }
        (void)nanosleep(&pause, NULL);
    }
    /* Safety wins over reclamation: retain a still-referenced mapping. */
    LOG_WARN("hotswap.service", "retaining superseded mapping: readers did not quiesce");
}

bool zcl_hotswap_service_activate_so_any(
    const char *so_path, const char *resolved_datadir, bool request_activate,
    const struct zcl_hotswap_service_contract *const *contracts,
    size_t contract_count,
    struct zcl_hotswap_service_report *report)
{
    if (!report)
        LOG_FAIL("hotswap.service", "activation report is NULL");
    memset(report, 0, sizeof(*report));
    report->verify_only = !request_activate;
    char why[256] = {0};
    if (!hotswap_path_is_acceptable(so_path, why, sizeof(why)))
        return reject(report, "path", false, why);
    if (request_activate &&
        !hotswap_activation_authorized(resolved_datadir, why, sizeof(why)))
        return reject(report, "authorize", false, why);
    int64_t load_us = 0;
    char sha256[65] = {0}, sha3[65] = {0};
    void *handle = service_open_image(so_path, sha256, sha3, &load_us, report);
    if (!handle) return false;
    copy_text(report->loaded_image_sha256,
              sizeof(report->loaded_image_sha256), sha256);
    copy_text(report->loaded_image_sha3_256,
              sizeof(report->loaded_image_sha3_256), sha3);
    dlerror();
    const struct zcl_hotswap_service_candidate *candidate =
        dlsym(handle, ZCL_HOTSWAP_SERVICE_SYMBOL);
    const char *sym_error = dlerror();
    if (sym_error || !candidate) {
        (void)dlclose(handle);
        return reject(report, "symbol", false,
                      "artifact does not export a service descriptor");
    }
    report->recognized = true;
    const struct zcl_hotswap_service_contract *contract = NULL;
    for (size_t i = 0; i < contract_count; i++)
        if (contracts && contracts[i] && contracts[i]->service_id &&
            candidate->service_id &&
            strcmp(contracts[i]->service_id, candidate->service_id) == 0) {
            contract = contracts[i];
            break;
        }
    if (!contract) {
        copy_text(report->service_id, sizeof(report->service_id),
                  candidate->service_id);
        (void)dlclose(handle);
        return reject(report, "service", true,
                      "service id has no resident frozen contract; select DEV_RESTART");
    }
    bool published = zcl_hotswap_service_publish(
        contract, candidate, request_activate, report);
    copy_text(report->loaded_image_sha256,
              sizeof(report->loaded_image_sha256), sha256);
    copy_text(report->loaded_image_sha3_256,
              sizeof(report->loaded_image_sha3_256), sha3);
    if (!published) {
        report->load_us = load_us;
        report->recognized = true;
        (void)dlclose(handle);
        return false;
    }
    report->load_us = load_us;
    report->recognized = true;
    if (!request_activate) {
        (void)dlclose(handle);
        return true;
    }

    void *old_handle = NULL;
    pthread_mutex_lock(&g_handle_lock);
    size_t slot = g_handle_count;
    for (size_t i = 0; i < g_handle_count; i++)
        if (strcmp(g_handles[i].service_id, candidate->service_id) == 0) {
            slot = i;
            break;
        }
    if (slot == g_handle_count && g_handle_count < ZCL_HOTSWAP_SERVICE_MAX)
        g_handle_count++;
    if (slot >= ZCL_HOTSWAP_SERVICE_MAX) {
        pthread_mutex_unlock(&g_handle_lock);
        /* The vtable is already published, so this mapping must remain loaded.
         * Refuse only reclamation bookkeeping, never invalidate live code. */
        LOG_WARN("hotswap.service", "handle table full; retaining active mapping");
        return true;
    }
    old_handle = g_handles[slot].handle;
    (void)snprintf(g_handles[slot].service_id,
                   sizeof(g_handles[slot].service_id), "%s",
                   candidate->service_id);
    g_handles[slot].handle = handle;
    pthread_mutex_unlock(&g_handle_lock);
    service_close_after_quiesce(old_handle);
    return true;
}

bool zcl_hotswap_service_activate_so(
    const char *so_path, const char *resolved_datadir, bool request_activate,
    const struct zcl_hotswap_service_contract *contract,
    struct zcl_hotswap_service_report *report)
{
    const struct zcl_hotswap_service_contract *contracts[] = {contract};
    return zcl_hotswap_service_activate_so_any(
        so_path, resolved_datadir, request_activate, contracts, 1, report);
}

static const struct zcl_hotswap_service_contract *service_contract_for(
    const struct zcl_hotswap_service_contract *const *contracts,
    size_t contract_count,
    const struct zcl_hotswap_service_candidate *candidate)
{
    for (size_t i = 0; i < contract_count; i++)
        if (contracts && contracts[i] &&
            equal_text(contracts[i]->service_id, candidate->service_id))
            return contracts[i];
    return NULL;
}

/* Verify-only probe of an already-open, already-confined image descriptor.
 * The mapping is the kernel's /proc/self/fd link for exactly that inode; no
 * pathname is resolved. `loaded` runs after the descriptor is resolved and
 * the resident contract selected, before any candidate function executes. */
bool zcl_hotswap_service_probe_fd_any(
    int image_fd,
    const struct zcl_hotswap_service_contract *const *contracts,
    size_t contract_count, zcl_hotswap_service_loaded_fn loaded,
    void *loaded_ctx, struct zcl_hotswap_service_report *report)
{
    if (!report)
        LOG_FAIL("hotswap.service", "probe report is NULL");
    memset(report, 0, sizeof(*report));
    report->verify_only = true;
    char pinned[PATH_MAX];
    if (image_fd < 0 || !platform_fd_path(pinned, sizeof(pinned), image_fd,
                                          NULL))
        return reject(report, "path", false, "image descriptor unavailable");
    void *handle = dlopen(pinned, RTLD_NOW | RTLD_LOCAL);
    if (!handle)
        return reject(report, "dlopen", false, dlerror());
    dlerror();
    const struct zcl_hotswap_service_candidate *candidate =
        dlsym(handle, ZCL_HOTSWAP_SERVICE_SYMBOL);
    const char *sym_error = dlerror();
    if (sym_error || !candidate) {
        (void)dlclose(handle);
        return reject(report, "symbol", false,
                      "artifact does not export a service descriptor");
    }
    report->recognized = true;
    const struct zcl_hotswap_service_contract *contract =
        service_contract_for(contracts, contract_count, candidate);
    copy_text(report->service_id, sizeof(report->service_id),
              candidate->service_id);
    char why[192] = {0};
    bool ok = false;
    if (!contract)
        ok = reject(report, "service", true,
                    "service id has no resident frozen contract; select DEV_RESTART");
    else if (loaded && !loaded(loaded_ctx, why, sizeof(why)))
        ok = reject(report, "confine", false,
                    why[0] ? why : "post-load confinement failed");
    else
        ok = zcl_hotswap_service_publish(contract, candidate, false, report);
    report->recognized = true;
    (void)dlclose(handle);
    return ok;
}
#else
#define ZCL_HOTSWAP_SERVICE_UNAVAILABLE 1
#endif /* Linux */
#else
#define ZCL_HOTSWAP_SERVICE_UNAVAILABLE 1
#endif /* ZCL_DEV_BUILD */

#ifdef ZCL_HOTSWAP_SERVICE_UNAVAILABLE
bool zcl_hotswap_service_activate_so_any(
    const char *so_path, const char *resolved_datadir, bool request_activate,
    const struct zcl_hotswap_service_contract *const *contracts,
    size_t contract_count,
    struct zcl_hotswap_service_report *report)
{
    (void)so_path; (void)resolved_datadir; (void)request_activate;
    (void)contracts; (void)contract_count;
    if (!report)
        LOG_FAIL("hotswap.service", "activation report is NULL");
    memset(report, 0, sizeof(*report));
    return reject(report, hotswap_native_unavailable_stage(), false,
                  hotswap_native_unavailable_reason());
}

bool zcl_hotswap_service_activate_so(
    const char *so_path, const char *resolved_datadir, bool request_activate,
    const struct zcl_hotswap_service_contract *contract,
    struct zcl_hotswap_service_report *report)
{
    const struct zcl_hotswap_service_contract *contracts[] = {contract};
    return zcl_hotswap_service_activate_so_any(
        so_path, resolved_datadir, request_activate, contracts, 1, report);
}

bool zcl_hotswap_service_probe_fd_any(
    int image_fd,
    const struct zcl_hotswap_service_contract *const *contracts,
    size_t contract_count, zcl_hotswap_service_loaded_fn loaded,
    void *loaded_ctx, struct zcl_hotswap_service_report *report)
{
    (void)image_fd; (void)contracts; (void)contract_count;
    (void)loaded; (void)loaded_ctx;
    if (!report)
        LOG_FAIL("hotswap.service", "probe report is NULL");
    memset(report, 0, sizeof(*report));
    return reject(report, hotswap_native_unavailable_stage(), false,
                  hotswap_native_unavailable_reason());
}
#endif /* ZCL_HOTSWAP_SERVICE_UNAVAILABLE */
#undef ZCL_HOTSWAP_SERVICE_UNAVAILABLE
