/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Stateless native-leaf hot-swap generations. Dynamic loading is DEV-ONLY;
 * pure guards, manifest validation, status, and the release refusal stub
 * compile in every build. A generation may only stage native command leaves.
 * The caller validates the complete batch and publishes one immutable command
 * snapshot after the
 * generation self-test succeeds. No generation code runs before its exported
 * manifest has passed the host ABI/capability/provenance/state contract. */
/* realpath() is declared by <stdlib.h> only under __USE_MISC/__USE_XOPEN_EXTENDED,
 * and the build's -D_POSIX_C_SOURCE=200809L sets neither. Without this the
 * declaration reaches the TU only through the glibc fortify inline that
 * -D_FORTIFY_SOURCE=2 pulls in at -O3 — so any -O0, -U_FORTIFY_SOURCE, or
 * non-glibc build fails with "implicit declaration of realpath", which is a
 * hard error in C23. Matches lib/net/src/connman.c and 26 other TUs. */
#if !defined(_WIN32)
#define _DEFAULT_SOURCE
#endif
#include "hotswap/hotswap.h"
#include "hotswap/hotswap_module.h"
#include "crypto/sha256.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "util/clientversion.h"
#include "util/log_macros.h"
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#define HOTSWAP_MAX_GENERATIONS 128
struct hotswap_generation {
    uint32_t gen;
    char so_path[512];
    void *handle;                 /* successful mappings are never closed */
    /* Keep the descriptor whose /proc/self/fd path was passed to dlopen.
     * Reusing that numeric fd while an older handle remains mapped makes the
     * dynamic loader return the older cached object for a different artifact. */
    int artifact_fd;
    time_t loaded_at;
    size_t replaced_count;
    bool ok;
    bool mapped;
    char rejection_stage[64];
    char error[256];
    char provider_id[96];
    char build_identity[96];
    char source_identity[256];
    char input_digest[128];
    char artifact_sha256[65];
    char mapped_tests_csv[256];
    char probe_tools_csv[256];
};
struct hotswap_rejection {
    bool present;
    uint32_t gen;
    time_t rejected_at;
    char stage[64];
    char error[256];
    char so_path[512];
    char source_identity[256];
};
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static struct hotswap_generation g_gens[HOTSWAP_MAX_GENERATIONS];
static size_t g_gen_count;
static uint32_t g_next_gen = 1;
static uint32_t g_active_gen;
static struct hotswap_rejection g_last_rejection;
static const struct {
    const char *source;
    const char *probe;
} g_eligible_sources[] = {
#define HOTSWAP_ELIGIBLE(path_) { .source = path_, .probe =
#define HOTSWAP_PROBE(probe_) probe_ },
#include "../../../config/hotswap_eligible.def"
#undef HOTSWAP_PROBE
#undef HOTSWAP_ELIGIBLE
};
static void copy_text(char *dst, size_t dst_sz, const char *src)
{
    if (!dst || dst_sz == 0)
        return;
    snprintf(dst, dst_sz, "%s", src ? src : "");
}

size_t hotswap_generation_count(void)
{
    pthread_mutex_lock(&g_lock);
    size_t n = g_gen_count;
    pthread_mutex_unlock(&g_lock);
    return n;
}

#if !defined(_WIN32)
static bool has_suffix(const char *s, const char *suffix)
{
    if (!s || !suffix)
        return false;
    size_t s_len = strlen(s), suffix_len = strlen(suffix);
    return s_len >= suffix_len &&
           memcmp(s + s_len - suffix_len, suffix, suffix_len) == 0;
}

static bool path_is_under(const char *path, const char *directory)
{
    size_t directory_len = strlen(directory);
    return directory_len > 0 &&
           strncmp(path, directory, directory_len) == 0 &&
           path[directory_len] == '/';
}
#endif

bool hotswap_path_is_acceptable(const char *so_path, char *why, size_t why_sz)
{
    if (why && why_sz)
        why[0] = '\0';
    if (!so_path || !so_path[0]) {
        if (why) snprintf(why, why_sz, "empty path");
        return false;
    }
#if defined(_WIN32)
    if (why)
        snprintf(why, why_sz,
                 "native Windows DLL hot-swap is disabled pending validated "
                 "PE imports and immutable generation loading");
    return false;
#else
    if (so_path[0] != '/') {
        if (why) snprintf(why, why_sz, "path must be absolute");
        return false;
    }
    if (strstr(so_path, "..")) {
        if (why) snprintf(why, why_sz, "path must not contain '..'");
        return false;
    }
    if (!has_suffix(so_path, ".so")) {
        if (why) snprintf(why, why_sz, "path must end in .so");
        return false;
    }
    if (access(so_path, R_OK) != 0) {
        if (why) snprintf(why, why_sz, "file does not exist / unreadable");
        return false;
    }

    char real[PATH_MAX];
    if (!realpath(so_path, real)) {
        if (why) snprintf(why, why_sz, "realpath failed");
        return false;
    }
    char real_tmp[PATH_MAX];
    const char *tmp = realpath("/tmp", real_tmp) ? real_tmp : "/tmp";
    bool under_tmp = path_is_under(real, tmp);
    bool under_build = strstr(real, "/build/hotswap/") != NULL;
    if (!under_tmp && !under_build) {
        if (why)
            snprintf(why, why_sz,
                     "resolved path %s not under /tmp or build/hotswap",
                     real);
        return false;
    }
    return true;
#endif
}

#if !defined(_WIN32)
static bool same_dir(const char *a, const char *b)
{
    if (!a || !a[0] || !b || !b[0])
        return false;
    char real_a[PATH_MAX], real_b[PATH_MAX];
    const char *path_a = realpath(a, real_a) ? real_a : a;
    const char *path_b = realpath(b, real_b) ? real_b : b;
    size_t a_len = strlen(path_a), b_len = strlen(path_b);
    if (a_len && path_a[a_len - 1] == '/') a_len--;
    if (b_len && path_b[b_len - 1] == '/') b_len--;
    return a_len == b_len && strncmp(path_a, path_b, a_len) == 0;
}
#endif

bool hotswap_datadir_is_dev(const char *resolved_datadir)
{
#if defined(_WIN32)
    (void)resolved_datadir;
    return false;
#else
    if (!resolved_datadir || !resolved_datadir[0])
        return false;
    const char *home = getenv("HOME");
    if (!home || home[0] != '/')
        return false;
    char exact_dev[PATH_MAX];
    snprintf(exact_dev, sizeof(exact_dev), "%s/.zclassic-c23-dev", home);
    return same_dir(resolved_datadir, exact_dev);
#endif
}

static const char *eligible_probe(const char *source_identity)
{
    if (!source_identity || !source_identity[0])
        return NULL;
    for (size_t i = 0;
         i < sizeof(g_eligible_sources) / sizeof(g_eligible_sources[0]); i++) {
        if (strcmp(source_identity, g_eligible_sources[i].source) == 0)
            return g_eligible_sources[i].probe;
    }
    return NULL;
}

static bool manifest_text_present(const char *value)
{
    return value && value[0] && strnlen(value, 4096) < 4096;
}

static bool lowercase_sha256_hex(const char *value)
{
    if (!value || strlen(value) != 64)
        return false;
    for (size_t i = 0; i < 64; i++) {
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f')))
            return false;
    }
    return true;
}

bool hotswap_manifest_v2_validate(
    const struct zcl_hotswap_manifest_v2 *manifest,
    char *why,
    size_t why_sz)
{
    if (why && why_sz)
        why[0] = '\0';
#define MANIFEST_REJECT(...) do {                                            \
        if (why) snprintf(why, why_sz, __VA_ARGS__);                         \
        return false;                                                        \
    } while (0)
    if (!manifest)
        MANIFEST_REJECT("missing zcl_hotswap_manifest_v2");
    if (manifest->schema_version != ZCL_HOTSWAP_MANIFEST_SCHEMA_V2)
        MANIFEST_REJECT("manifest schema %u != %u", manifest->schema_version,
                        ZCL_HOTSWAP_MANIFEST_SCHEMA_V2);
    if (manifest->struct_size != sizeof(*manifest))
        MANIFEST_REJECT("manifest struct size %u != %zu",
                        manifest->struct_size, sizeof(*manifest));
    /* Native command leaves are the sole provider class. The V4 ABI bump makes
     * every artifact built for a retired host layout fail closed here. */
    if (!manifest_text_present(manifest->provider_id) ||
        strcmp(manifest->provider_id, "native.leaves") != 0) {
        MANIFEST_REJECT("provider is reload-required or unknown: %s",
                        manifest->provider_id ? manifest->provider_id : "");
    }
    if (manifest->host_abi_version != ZCL_HOTSWAP_HOST_ABI_V4 ||
        manifest->host_struct_size != ZCL_HOTSWAP_HOST_STRUCT_SIZE_V4)
        MANIFEST_REJECT("host ABI/size mismatch: abi=%u size=%u",
                        manifest->host_abi_version,
                        manifest->host_struct_size);
    if (manifest->required_host_capabilities !=
        ZCL_HOTSWAP_V4_HOST_CAPABILITIES)
        MANIFEST_REJECT("missing/unsupported host capabilities: 0x%llx",
                        (unsigned long long)
                            manifest->required_host_capabilities);
    const char *host_source_id = zcl_build_source_id_sha256();
    if (!lowercase_sha256_hex(manifest->build_identity) ||
        !lowercase_sha256_hex(host_source_id) ||
        strcmp(manifest->build_identity, host_source_id) != 0)
        MANIFEST_REJECT(
            "build source identity mismatch: generation=%s host=%s",
            manifest->build_identity ? manifest->build_identity : "",
            host_source_id ? host_source_id : "");
    const char *required_probe = manifest_text_present(manifest->source_identity)
        ? eligible_probe(manifest->source_identity) : NULL;
    if (!required_probe)
        MANIFEST_REJECT("source is not runtime-eligible: %s",
                        manifest->source_identity ? manifest->source_identity : "");
    if (!lowercase_sha256_hex(manifest->input_digest))
        MANIFEST_REJECT("input content SHA-256 must be 64 lowercase hex chars");
    if (!manifest->stateless || manifest->state_schema_version != 0)
        MANIFEST_REJECT("stateful provider is reload-required");
    if (manifest->quiescence != ZCL_HOTSWAP_QUIESCENCE_NONE)
        MANIFEST_REJECT("quiescence contract is unsupported in stateless v2");
    if (!manifest_text_present(manifest->mapped_tests_csv) ||
        !manifest_text_present(manifest->probe_tools_csv))
        MANIFEST_REJECT("mapped tests/probe metadata is required");
    if (strcmp(manifest->probe_tools_csv, required_probe) != 0)
        MANIFEST_REJECT("probe metadata mismatch: generation=%s required=%s",
                        manifest->probe_tools_csv, required_probe);
    if (!manifest->self_test)
        MANIFEST_REJECT("generation self-test is required");
#undef MANIFEST_REJECT
    return true;
}

#if defined(ZCL_DEV_BUILD) && !defined(_WIN32)
static void rejection_set_locked(uint32_t gen, const char *stage,
                                 const char *error, const char *so_path,
                                 const char *source_identity)
{
    memset(&g_last_rejection, 0, sizeof(g_last_rejection));
    g_last_rejection.present = true;
    g_last_rejection.gen = gen;
    g_last_rejection.rejected_at = platform_time_wall_time_t();
    copy_text(g_last_rejection.stage, sizeof(g_last_rejection.stage), stage);
    copy_text(g_last_rejection.error, sizeof(g_last_rejection.error), error);
    copy_text(g_last_rejection.so_path, sizeof(g_last_rejection.so_path), so_path);
    copy_text(g_last_rejection.source_identity,
              sizeof(g_last_rejection.source_identity), source_identity);
}
#endif

static void generation_json(struct json_value *obj,
                            const struct hotswap_generation *generation)
{
    json_set_object(obj);
    json_push_kv_int(obj, "gen", (int64_t)generation->gen);
    json_push_kv_str(obj, "status",
                     generation->ok
                         ? (generation->gen == g_active_gen
                                ? "active" : "retired_mapped")
                         : "rejected");
    json_push_kv_str(obj, "so_path", generation->so_path);
    json_push_kv_int(obj, "loaded_at", (int64_t)generation->loaded_at);
    json_push_kv_int(obj, "replaced_count",
                     (int64_t)generation->replaced_count);
    json_push_kv_bool(obj, "ok", generation->ok);
    json_push_kv_bool(obj, "mapped", generation->mapped);
    json_push_kv_str(obj, "provider_id", generation->provider_id);
    json_push_kv_str(obj, "build_identity", generation->build_identity);
    json_push_kv_str(obj, "source_identity", generation->source_identity);
    json_push_kv_str(obj, "input_content_sha256", generation->input_digest);
    json_push_kv_str(obj, "artifact_sha256", generation->artifact_sha256);
    json_push_kv_bool(obj, "artifact_hash_available",
                      generation->artifact_sha256[0] != '\0');
    json_push_kv_bool(obj, "artifact_inode_pinned",
                      generation->mapped && generation->artifact_fd >= 0);
    json_push_kv_str(obj, "mapped_tests", generation->mapped_tests_csv);
    json_push_kv_str(obj, "probe_tools", generation->probe_tools_csv);
    if (generation->rejection_stage[0])
        json_push_kv_str(obj, "rejection_stage", generation->rejection_stage);
    if (generation->error[0])
        json_push_kv_str(obj, "error", generation->error);
}

bool hotswap_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);
    json_push_kv_str(out, "schema", "zcl.hotswap_generation.v2");
#if defined(ZCL_DEV_BUILD) && !defined(_WIN32)
    json_push_kv_bool(out, "available", true);
#else
    json_push_kv_bool(out, "available", false);
    json_push_kv_str(out, "note", "hotswap unavailable in release build");
#endif
    json_push_kv_bool(out, "ephemeral", true);
    json_push_kv_str(out, "mapping_policy",
                     "successful_generations_permanently_mapped");
    json_push_kv_str(out, "artifact_inode_policy",
                     "successful_generation_fd_pinned");
    json_push_kv_str(out, "admitted_provider_class", "native.leaves");
    json_push_kv_str(out, "input_hash_scope", "source_headers_flags");
    json_push_kv_str(out, "artifact_hash_scope", "shared_object_bytes");

    pthread_mutex_lock(&g_lock);
    json_push_kv_int(out, "generation_count", (int64_t)g_gen_count);
    json_push_kv_int(out, "next_gen", (int64_t)g_next_gen);
    json_push_kv_int(out, "active_generation", (int64_t)g_active_gen);

    struct json_value generations = {0};
    json_set_array(&generations);
    struct json_value rejected = {0};
    json_set_array(&rejected);
    for (size_t i = 0; i < g_gen_count; i++) {
        struct json_value obj = {0};
        generation_json(&obj, &g_gens[i]);
        json_push_back(&generations, &obj);
        if (!g_gens[i].ok)
            json_push_back(&rejected, &obj);
        json_free(&obj);
    }
    json_push_kv(out, "generations", &generations);
    json_push_kv(out, "rejected_generations", &rejected);
    json_free(&generations);
    json_free(&rejected);

    struct json_value last = {0};
    json_set_object(&last);
    json_push_kv_bool(&last, "present", g_last_rejection.present);
    if (g_last_rejection.present) {
        json_push_kv_int(&last, "gen", (int64_t)g_last_rejection.gen);
        json_push_kv_int(&last, "rejected_at",
                         (int64_t)g_last_rejection.rejected_at);
        json_push_kv_str(&last, "stage", g_last_rejection.stage);
        json_push_kv_str(&last, "error", g_last_rejection.error);
        json_push_kv_str(&last, "so_path", g_last_rejection.so_path);
        json_push_kv_str(&last, "source_identity",
                         g_last_rejection.source_identity);
    }
    json_push_kv(out, "last_rejection", &last);
    json_free(&last);
    pthread_mutex_unlock(&g_lock);

    /* Merge module-ABI telemetry into the same `z23 dumpstate hotswap`
     * document (takes its own lock). */
    hotswap_activate_dump_json(out);
    return true;
}

#ifdef ZCL_DEV_BUILD
#if !defined(_WIN32)

#include <dlfcn.h>

static bool artifact_sha256_fd(int fd, char hex_out[65])
{
    if (fd < 0 || !hex_out || lseek(fd, 0, SEEK_SET) < 0)
        return false;
    hex_out[0] = '\0';
    struct sha256_ctx context;
    sha256_init(&context);
    unsigned char buffer[64 * 1024];
    for (;;) {
        ssize_t count = read(fd, buffer, sizeof(buffer));
        if (count > 0) {
            sha256_write(&context, buffer, (size_t)count);
            continue;
        }
        if (count == 0)
            break;
        if (errno == EINTR)
            continue;
        return false;
    }
    if (lseek(fd, 0, SEEK_SET) < 0)
        return false;
    unsigned char digest[SHA256_OUTPUT_SIZE];
    sha256_finalize(&context, digest);
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < SHA256_OUTPUT_SIZE; i++) {
        hex_out[i * 2] = hex[digest[i] >> 4];
        hex_out[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    hex_out[64] = '\0';
    return true;
}

struct hotswap_leaf_tx {
    struct zcl_hotswap_leaf_replacement staged[ZCL_HOTSWAP_GEN_MAX_REPLACED];
    size_t staged_count;
    bool stage_failed;
    char stage_error[256];
};

/* Loads are serialized under g_lock, so only the current stack transaction is
 * ever reachable. */
static struct hotswap_leaf_tx *g_active_leaf_tx;

static bool hotswap_leaf_stage_thunk(const char *path,
                                     zcl_command_handler_fn handler)
{
    struct hotswap_leaf_tx *tx = g_active_leaf_tx;
    if (!tx)
        return false;
    if (!path || !path[0] || !handler) {
        tx->stage_failed = true;
        copy_text(tx->stage_error, sizeof(tx->stage_error),
                  "generation staged a malformed native leaf");
        return false;
    }
    if (tx->staged_count >= ZCL_HOTSWAP_GEN_MAX_REPLACED) {
        tx->stage_failed = true;
        copy_text(tx->stage_error, sizeof(tx->stage_error),
                  "generation staged too many native leaves");
        return false;
    }
    for (size_t i = 0; i < tx->staged_count; i++) {
        if (strcmp(tx->staged[i].path, path) == 0) {
            tx->stage_failed = true;
            snprintf(tx->stage_error, sizeof(tx->stage_error),
                     "generation staged duplicate leaf '%s'", path);
            return false;
        }
    }
    tx->staged[tx->staged_count++] =
        (struct zcl_hotswap_leaf_replacement){ .path = path, .handler = handler };
    return true;
}

static struct hotswap_generation *generation_add_locked(uint32_t gen,
                                                         const char *so_path,
                                                         void *handle,
                                                         int artifact_fd)
{
    struct hotswap_generation *slot = NULL;
    if (g_gen_count < HOTSWAP_MAX_GENERATIONS) {
        slot = &g_gens[g_gen_count++];
    } else {
        /* Rejected generations are already dlclose'd and no router snapshot
         * can reference them. Reuse those diagnostic slots so malformed edit
         * attempts cannot exhaust an otherwise healthy hot-swap host. */
        for (size_t i = 0; i < g_gen_count; i++) {
            if (!g_gens[i].ok && !g_gens[i].mapped && !g_gens[i].handle) {
                slot = &g_gens[i];
                break;
            }
        }
    }
    if (!slot)
        return NULL;
    memset(slot, 0, sizeof(*slot));
    slot->gen = gen;
    slot->handle = handle;
    slot->artifact_fd = artifact_fd;
    slot->loaded_at = platform_time_wall_time_t();
    copy_text(slot->so_path, sizeof(slot->so_path), so_path);
    return slot;
}

static void manifest_copy(struct hotswap_generation *slot,
                          struct hotswap_load_report *report,
                          const struct zcl_hotswap_manifest_v2 *manifest)
{
#define COPY_MANIFEST_TEXT(slot_field_, report_field_, source_) do {         \
        if (manifest_text_present(source_)) {                                \
            copy_text(slot->slot_field_, sizeof(slot->slot_field_), source_); \
            copy_text(report->report_field_, sizeof(report->report_field_),  \
                      source_);                                              \
        }                                                                    \
    } while (0)
    COPY_MANIFEST_TEXT(provider_id, provider_id, manifest->provider_id);
    COPY_MANIFEST_TEXT(build_identity, build_identity,
                       manifest->build_identity);
    COPY_MANIFEST_TEXT(source_identity, source_identity,
                       manifest->source_identity);
    COPY_MANIFEST_TEXT(input_digest, input_digest, manifest->input_digest);
    if (manifest_text_present(manifest->mapped_tests_csv))
        copy_text(slot->mapped_tests_csv, sizeof(slot->mapped_tests_csv),
                  manifest->mapped_tests_csv);
    if (manifest_text_present(manifest->probe_tools_csv))
        copy_text(slot->probe_tools_csv, sizeof(slot->probe_tools_csv),
                  manifest->probe_tools_csv);
#undef COPY_MANIFEST_TEXT
}

static bool generation_reject_locked(struct hotswap_generation *slot,
                                     struct hotswap_load_report *report,
                                     const char *stage, const char *error)
{
    copy_text(report->rejection_stage, sizeof(report->rejection_stage), stage);
    copy_text(report->error, sizeof(report->error), error);
    if (slot) {
        copy_text(slot->rejection_stage, sizeof(slot->rejection_stage), stage);
        copy_text(slot->error, sizeof(slot->error), error);
        slot->ok = false;
        slot->mapped = false;
        rejection_set_locked(slot->gen, stage, error, slot->so_path,
                             slot->source_identity);
        if (slot->handle) {
            dlclose(slot->handle);
            slot->handle = NULL;
        }
        if (slot->artifact_fd >= 0) {
            close(slot->artifact_fd);
            slot->artifact_fd = -1;
        }
    } else {
        rejection_set_locked(report->gen, stage, error, "",
                             report->source_identity);
    }
    LOG_WARN("hotswap", "generation rejected stage=%s: %s", stage, error);
    return false;
}

static bool load_precheck(const char *so_path, const char *resolved_datadir,
                          bool commit_cb_present,
                          struct hotswap_load_report *report)
{
    if (!report)
        return false;
    memset(report, 0, sizeof(*report));
    if (!commit_cb_present) {
        copy_text(report->rejection_stage, sizeof(report->rejection_stage),
                  "precheck");
        copy_text(report->error, sizeof(report->error),
                  "no transactional commit callback supplied");
        return false;
    }
    if (!hotswap_datadir_is_dev(resolved_datadir)) {
        copy_text(report->rejection_stage, sizeof(report->rejection_stage),
                  "precheck");
        snprintf(report->error, sizeof(report->error),
                 "refusing hot-swap outside exact dev datadir: '%s'",
                 resolved_datadir ? resolved_datadir : "");
        return false;
    }
    char why[192] = {0};
    if (!hotswap_path_is_acceptable(so_path, why, sizeof(why))) {
        copy_text(report->rejection_stage, sizeof(report->rejection_stage),
                  "precheck");
        snprintf(report->error, sizeof(report->error),
                 "rejected so_path: %s", why);
        return false;
    }
    return true;
}

/* Result of the shared load core (dlopen + hash + register + manifest
 * validation), common to every provider class. */
struct hotswap_prepared {
    struct hotswap_generation *slot;
    const struct zcl_hotswap_manifest_v2 *manifest;
    zcl_hotswap_gen_init_fn gen_init;
    uint32_t gen;
};

/* Shared dlopen/hash/register/manifest-validate/probe-match core. ASSUMES
 * g_lock is HELD and load_precheck already passed. On success returns true with
 * *out fully filled and the lock STILL HELD; on failure returns false (report
 * populated via generation_reject_locked) with the lock STILL HELD. The caller
 * unlocks in both cases. Provider-agnostic: the caller supplies the host vtable
 * and staging transaction after this returns. */
static bool load_prepare_locked(const char *so_path, const char *required_probe,
                                struct hotswap_load_report *report,
                                struct hotswap_prepared *out)
{
    memset(out, 0, sizeof(*out));
    int artifact_fd = open(so_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat artifact_stat;
    if (artifact_fd < 0 || fstat(artifact_fd, &artifact_stat) != 0 ||
        !S_ISREG(artifact_stat.st_mode) ||
        !artifact_sha256_fd(artifact_fd, report->artifact_sha256)) {
        if (artifact_fd >= 0)
            close(artifact_fd);
        return generation_reject_locked(
            NULL, report, "artifact_hash",
            "could not pin and hash a regular generation artifact");
    }
    /* Hash and dlopen the same pinned inode. Opening by the original pathname
     * after hashing creates a replacement race during rapid editor/build
     * activity; /proc/self/fd keeps identity exact through the loader call. */
    char pinned_path[64];
    (void)snprintf(pinned_path, sizeof(pinned_path), "/proc/self/fd/%d",
                   artifact_fd);
    void *handle = dlopen(pinned_path, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        const char *dl_error = dlerror();
        char error[256];
        snprintf(error, sizeof(error), "dlopen failed: %s",
                 dl_error ? dl_error : "(unknown)");
        close(artifact_fd);
        return generation_reject_locked(NULL, report, "dlopen", error);
    }

    uint32_t gen = g_next_gen++;
    report->gen = gen;
    struct hotswap_generation *slot =
        generation_add_locked(gen, so_path, handle, artifact_fd);
    if (!slot) {
        char error[128];
        snprintf(error, sizeof(error), "generation registry full (%d)",
                 HOTSWAP_MAX_GENERATIONS);
        dlclose(handle);
        close(artifact_fd);
        return generation_reject_locked(NULL, report, "registry", error);
    }
    copy_text(slot->artifact_sha256, sizeof(slot->artifact_sha256),
              report->artifact_sha256);

    dlerror();
    const struct zcl_hotswap_manifest_v2 *manifest =
        dlsym(handle, "zcl_hotswap_manifest_v2");
    const char *manifest_symbol_error = dlerror();
    char why[256] = {0};
    if (!manifest || manifest_symbol_error) {
        snprintf(why, sizeof(why), "missing zcl_hotswap_manifest_v2: %s",
                 manifest_symbol_error ? manifest_symbol_error :
                                         "symbol not found");
        return generation_reject_locked(slot, report, "manifest", why);
    }
    /* Once the exported object's schema and byte size prove all fields exist,
     * capture bounded provenance even when a later ABI/capability/identity
     * check rejects it. Rejected generations must remain diagnosable. */
    if (manifest->schema_version == ZCL_HOTSWAP_MANIFEST_SCHEMA_V2 &&
        manifest->struct_size == sizeof(*manifest))
        manifest_copy(slot, report, manifest);
    if (!hotswap_manifest_v2_validate(manifest, why, sizeof(why)))
        return generation_reject_locked(slot, report, "manifest", why);
    if (!required_probe || !required_probe[0] ||
        strcmp(required_probe, manifest->probe_tools_csv) != 0) {
        (void)snprintf(why, sizeof(why),
                       "requested probe mismatch: requested=%s manifest=%s",
                       required_probe ? required_probe : "",
                       manifest->probe_tools_csv);
        return generation_reject_locked(slot, report, "manifest", why);
    }

    dlerror();
    zcl_hotswap_gen_init_fn gen_init = NULL;
    *(void **)(&gen_init) = dlsym(handle, "zcl_hotswap_gen_init");
    const char *init_symbol_error = dlerror();
    if (!gen_init || init_symbol_error) {
        snprintf(why, sizeof(why), "missing zcl_hotswap_gen_init: %s",
                 init_symbol_error ? init_symbol_error : "symbol not found");
        return generation_reject_locked(slot, report, "manifest", why);
    }

    out->slot = slot;
    out->manifest = manifest;
    out->gen_init = gen_init;
    out->gen = gen;
    return true;
}

/* Shared entry preamble: precheck + acquire g_lock + run the load core. On
 * success returns true with g_lock HELD and *prep filled; on failure returns
 * false with g_lock NOT held (report populated). */
static bool load_enter(const char *so_path, const char *resolved_datadir,
                       bool commit_cb_present, const char *required_probe,
                       struct hotswap_load_report *report,
                       struct hotswap_prepared *prep)
{
    if (!load_precheck(so_path, resolved_datadir, commit_cb_present, report)) {
        if (report) {
            pthread_mutex_lock(&g_lock);
            rejection_set_locked(0, report->rejection_stage, report->error,
                                 so_path, "");
            pthread_mutex_unlock(&g_lock);
            LOG_WARN("hotswap", "%s", report->error);
        }
        return false;
    }
    pthread_mutex_lock(&g_lock);
    if (!load_prepare_locked(so_path, required_probe, report, prep)) {
        pthread_mutex_unlock(&g_lock);
        return false;
    }
    return true;
}

bool hotswap_load_leaves(const char *so_path,
                         const char *datadir,
                         const char *probe_leaf,
                         zcl_hotswap_leaf_commit_cb commit_cb,
                         void *ctx,
                         struct hotswap_load_report *report)
{
    struct hotswap_prepared prep;
    if (!load_enter(so_path, datadir, commit_cb != NULL, probe_leaf, report,
                    &prep))
        return false;

    struct zcl_hotswap_host host = {
        .abi_version = ZCL_HOTSWAP_HOST_ABI_V4,
        .struct_size = ZCL_HOTSWAP_HOST_STRUCT_SIZE_V4,
        .gen = prep.gen,
        .capabilities = ZCL_HOTSWAP_V4_HOST_CAPABILITIES,
        .leaf_stage = hotswap_leaf_stage_thunk,
    };
    struct hotswap_leaf_tx tx = {0};
    g_active_leaf_tx = &tx;
    bool init_ok = prep.gen_init(&host);
    g_active_leaf_tx = NULL;
    if (!init_ok || tx.stage_failed || tx.staged_count == 0) {
        const char *error = tx.stage_error[0]
            ? tx.stage_error
            : (tx.staged_count == 0
                   ? "generation staged no native leaves"
                   : "generation init returned false");
        bool result = generation_reject_locked(prep.slot, report, "init", error);
        pthread_mutex_unlock(&g_lock);
        return result;
    }

    char why[256] = {0};
    if (!prep.manifest->self_test(&host, why, sizeof(why))) {
        bool result = generation_reject_locked(
            prep.slot, report, "self_test",
            why[0] ? why : "generation self-test returned false");
        pthread_mutex_unlock(&g_lock);
        return result;
    }

    why[0] = '\0';
    if (!commit_cb(ctx, prep.gen, tx.staged, tx.staged_count,
                   why, sizeof(why))) {
        bool result = generation_reject_locked(
            prep.slot, report, "commit",
            why[0] ? why : "transactional leaf commit failed");
        pthread_mutex_unlock(&g_lock);
        return result;
    }

    prep.slot->ok = true;
    prep.slot->mapped = true;
    prep.slot->replaced_count = tx.staged_count;
    g_active_gen = prep.gen;
    report->ok = true;
    report->replaced_count = tx.staged_count;
    for (size_t i = 0; i < tx.staged_count; i++)
        copy_text(report->replaced[i], sizeof(report->replaced[i]),
                  tx.staged[i].path);

    pthread_mutex_unlock(&g_lock);
    return true;
}

#else
#define ZCL_HOTSWAP_LOADER_UNAVAILABLE 1
#endif /* !_WIN32 */
#else
#define ZCL_HOTSWAP_LOADER_UNAVAILABLE 1
#endif /* ZCL_DEV_BUILD */

#ifdef ZCL_HOTSWAP_LOADER_UNAVAILABLE
/* Release build or native Windows: fail closed. */

bool hotswap_load_leaves(const char *so_path,
                         const char *datadir,
                         const char *probe_leaf,
                         zcl_hotswap_leaf_commit_cb commit_cb,
                         void *ctx,
                         struct hotswap_load_report *report)
{
    (void)so_path;
    (void)datadir;
    (void)probe_leaf;
    (void)commit_cb;
    (void)ctx;
    if (!report)
        return false;
    memset(report, 0, sizeof(*report));
    copy_text(report->rejection_stage, sizeof(report->rejection_stage),
#if defined(_WIN32)
              "platform");
#else
              "release");
#endif
    copy_text(report->error, sizeof(report->error),
#if defined(_WIN32)
              "native Windows DLL hot-swap is disabled pending sandbox and "
              "validated immutable PE loading");
#else
              "hotswap unavailable in release build");
#endif
    return false;
}

#endif /* ZCL_HOTSWAP_LOADER_UNAVAILABLE */
#undef ZCL_HOTSWAP_LOADER_UNAVAILABLE
