/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Owner-private paid-content registration, restart, and tamper tests. */

#include "platform/directory_compat.h"
#include "test/test_core.h"

#include "base/hex.h"
#include "chain/chainparams.h"
#include "controllers/file_market_controller.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "models/file_offer.h"
#include "models/market_content.h"
#include "net/file_market.h"
#include "platform/positioned_file.h"
#include "platform/positioned_io.h"
#include "platform/time_compat.h"
#include "rpc/server.h"
#include "sapling/sapling.h"
#include "services/file_market_content_service.h"
#include "services/market_moderation_service.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(_WIN32)
#include <windows.h>
#endif

#if defined(_WIN32) && !defined(O_CLOEXEC)
/* mingw's <fcntl.h> has no O_CLOEXEC; this file is single-process fixture
 * I/O, so a zero fallback keeps open() valid on Windows. */
#define O_CLOEXEC 0
#endif

#define CONTENT_CHECK(label, condition) do {                         \
    printf("file_market content: %s... ", (label));                 \
    if (condition) printf("OK\n");                                  \
    else { printf("FAIL\n"); failures++; }                          \
} while (0)

static bool content_symlink_create(const char *target, const char *link)
{
#if defined(_WIN32)
    DWORD flags = SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;
    if (CreateSymbolicLinkA(link, target, flags) != 0)
        return true;
    return GetLastError() == ERROR_INVALID_PARAMETER &&
           CreateSymbolicLinkA(link, target, 0) != 0;
#else
    return symlink(target, link) == 0;
#endif
}

static bool content_special_create(const char *path)
{
#if defined(_WIN32)
    return platform_directory_create(path, 0700) == 0;
#else
    return mkfifo(path, 0600) == 0;
#endif
}

static bool content_canonical_file(const char *path, char *canonical,
                                   size_t canonical_size)
{
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    bool ok = platform_positioned_file_open(&file, path) &&
              platform_positioned_file_path(&file, canonical,
                                            canonical_size);
    platform_positioned_file_close(&file);
    return ok;
}

static bool content_write_file(const char *path, const uint8_t *data,
                               size_t size)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return false;
    size_t done = 0;
    while (done < size) {
        ssize_t wrote = write(fd, data + done, size - done);
        if (wrote < 0 && errno == EINTR)
            continue;
        if (wrote <= 0) {
            close(fd);
            return false;
        }
        done += (size_t)wrote;
    }
    return close(fd) == 0;
}

static void content_one_chunk_root(const uint8_t *data, size_t size,
                                   uint8_t chunk[32], uint8_t root[32])
{
    sha3_256(data, size, chunk);
    sha3_256(chunk, 32, root);
}

/* Distinct registry-row digest for window index i (two varied bytes so
 * i=0 and i=256 never collide). */
static void content_window_digest(int i, uint8_t out[32])
{
    memset(out, 0, 32);
    out[0] = (uint8_t)(i + 1);
    out[1] = (uint8_t)(i / 256);
}

static bool content_signed_offer(struct file_offer *offer,
                                 const uint8_t root[32], uint64_t size,
                                 uint64_t nonce, int64_t now_unix)
{
    const struct chain_params *params = chain_params_get();
    struct jub_point payment_key;
    uint8_t seed[32], secret[32];
    if (!params)
        return false;
    memset(offer, 0, sizeof(*offer));
    memset(seed, 0x63, sizeof(seed));
    memcpy(offer->root_hash, root, 32);
    memcpy(offer->network_genesis,
           params->consensus.hashGenesisBlock.data, 32);
    ed25519_keypair(offer->seller_pubkey, secret, seed);
    snprintf(offer->filename, sizeof(offer->filename), "paid-content.bin");
    offer->size_bytes = size;
    if (!file_market_num_chunks_for_size(size, &offer->num_chunks))
        return false;
    offer->price_per_mb = 1200;
    for (uint8_t d = 1; ; d++) {
        memset(offer->z_addr, 0, sizeof(offer->z_addr));
        offer->z_addr[0] = d;
        if (sapling_diversifier_to_gd(&payment_key, offer->z_addr))
            break;
        if (d == UINT8_MAX)
            return false;
    }
    jub_to_bytes(offer->z_addr + 11, &payment_key);
    offer->peer_ip[15] = 1;
    offer->peer_port = 18034;
    offer->last_seen = now_unix;
    offer->ttl = FILE_MARKET_MAX_TTL;
    offer->auth_version = FILE_MARKET_OFFER_VERSION;
    offer->nonce = nonce;
    offer->issued_unix = now_unix - 60;
    offer->expires_unix = now_unix + 600;
    return file_offer_auth_seal(offer, seed) == FILE_OFFER_AUTH_OK;
}

/* Drive one market RPC by name with a positional string-args JSON body,
 * mirroring the moderation tests' table harness. */
static bool content_rpc(struct rpc_table *t, const char *method,
                        const char *params_json, struct json_value *result)
{
    json_init(result);
    struct json_value params;
    if (params_json) {
        if (!json_read(&params, params_json, strlen(params_json)))
            return false;
    }
    bool ok = rpc_table_execute(t, method, params_json ? &params : NULL,
                                result);
    if (params_json)
        json_free(&params);
    return ok;
}

static const char *content_kv_str(struct json_value *value, const char *key)
{
    const struct json_value *found = json_get(value, key);
    return found && found->type == JSON_STR ? json_get_str(found) : NULL;
}

struct content_interleave_fixture {
    struct node_db *ndb;
    struct market_content_record row;
    bool saved;
};

static void content_interleave_registration(void *opaque)
{
    struct content_interleave_fixture *fixture = opaque;
    file_market_content_set_precommit_test_hook(NULL, NULL);
    fixture->saved = db_market_content_save(fixture->ndb, &fixture->row);
}

static void content_fill_payload(uint8_t *payload, size_t size)
{
    for (size_t i = 0; i < size; i++)
        payload[i] = (uint8_t)(i * 17u + 3u);
}

static bool content_market_dir_created(const char *dir)
{
    return platform_directory_create(dir, 0700) == 0 || errno == EEXIST;
}

static bool content_write_content_fixtures(const char *filepath,
    const char *symlink_path, const char *fifo_path, const char *wrong_path,
    const uint8_t *payload, size_t size)
{
#if defined(_WIN32)
    (void)symlink_path;
    (void)fifo_path;
    return content_write_file(filepath, payload, size) &&
        content_write_file(wrong_path, payload, size - 1);
#else
    return content_write_file(filepath, payload, size) &&
        content_symlink_create(filepath, symlink_path) &&
        content_special_create(fifo_path) &&
        content_write_file(wrong_path, payload, size - 1);
#endif
}

static bool content_authenticated_offer_opened(struct node_db *ndb,
    const char *dbpath, struct file_offer *offer, const uint8_t root[32],
    uint64_t size, int64_t now_unix)
{
    bool signed_offer = content_signed_offer(
        offer, root, size, 7301, now_unix);
    memset(ndb, 0, sizeof(*ndb));
    return signed_offer && node_db_open(ndb, dbpath) &&
           db_file_offer_save(ndb, offer);
}

static void content_close_open_node_db(struct node_db *ndb)
{
    if (ndb->open)
        node_db_close(ndb);
}

static bool content_registration_states_differ(struct node_db *ndb,
                                               const uint8_t offer_id[32])
{
    uint8_t identity[32];
    struct node_db closed_probe;
    memset(&closed_probe, 0, sizeof(closed_probe));
    return db_market_content_registration_identity(
            ndb, offer_id, identity) == MARKET_CONTENT_STATE_ABSENT &&
        db_market_content_registration_identity(
            &closed_probe, offer_id, identity) == MARKET_CONTENT_STATE_ERROR;
}

static bool content_initial_counts_fail_closed(struct node_db *ndb)
{
    struct node_db closed_probe;
    memset(&closed_probe, 0, sizeof(closed_probe));
    closed_probe.open = false;
    return db_market_content_count(ndb) == 0 &&
        db_file_offer_count(ndb) == 1 &&
        db_market_content_count(NULL) == -1 &&
        db_market_content_count(&closed_probe) == -1 &&
        db_file_offer_count(&closed_probe) == -1;
}

static bool content_manifest_bytes_match(const struct zcl_result *result,
    const struct market_content_public_record *registered, size_t size,
    const uint8_t root[32])
{
    return result->ok && registered->size_bytes == size &&
        registered->num_chunks == 1 &&
        memcmp(registered->root_hash, root, 32) == 0;
}

static bool content_one_offer_listed(int listed_count, int listed_total,
    const struct market_content_public_record *listed,
    const uint8_t offer_id[32])
{
    return listed_count == 1 && listed_total == 1 &&
        memcmp(listed[0].offer_id, offer_id, 32) == 0;
}

static bool content_verified_chunk_bytes(bool load_ok,
    const struct file_market_delivery_chunk *loaded, const uint8_t *payload,
    size_t size, const uint8_t chunk_sha3[32])
{
    return load_ok && loaded->size == size &&
        memcmp(loaded->data, payload, size) == 0 &&
        memcmp(loaded->sha3, chunk_sha3, 32) == 0;
}

static bool content_wrong_root_offer_saved(struct node_db *ndb,
    struct file_offer *wrong_root_offer, uint64_t size, int64_t now_unix)
{
    uint8_t wrong_root[32];
    memset(wrong_root, 0x92, sizeof(wrong_root));
    return content_signed_offer(
        wrong_root_offer, wrong_root, size, 7302, now_unix) &&
        db_file_offer_save(ndb, wrong_root_offer);
}

static bool content_root_mismatch_rejected(bool wrong_offer_ready,
                                           const struct zcl_result *result)
{
    return wrong_offer_ready && !result->ok;
}

static bool content_saved_offer_counts(struct node_db *ndb)
{
    return db_file_offer_count(ndb) == 2 &&
        db_market_content_count(ndb) == 1;
}

static bool content_index_hides_rows(bool hidden_indexed, size_t hidden_len,
    const char *hidden_rendered, const struct json_value *hidden_index)
{
    return hidden_indexed && hidden_len > 0 &&
        !strstr(hidden_rendered, "offer_id") &&
        json_get(hidden_index, "hidden_by_profile") == NULL &&
        json_get(hidden_index, "total") == NULL;
}

static bool content_reviewed_index_omits_path(bool signed_off_ok, bool indexed,
    size_t rendered_len, const char *rendered, const char *filepath)
{
    return signed_off_ok && indexed && rendered_len > 0 &&
        strstr(rendered, "offer_id") &&
        !strstr(rendered, "private_path") && !strstr(rendered, filepath);
}

static bool content_restarted_chunk_bytes(bool load_ok,
    const struct file_market_delivery_chunk *loaded, const uint8_t *payload,
    size_t size)
{
    return load_ok && loaded->size == size &&
        memcmp(loaded->data, payload, size) == 0;
}

static bool content_warm_chunk_bytes(const struct zcl_result *warm_result,
    const struct file_market_delivery_chunk *loaded, const uint8_t *payload,
    size_t size, const uint8_t chunk_sha3[32])
{
    return warm_result->ok && loaded->size == size &&
        memcmp(loaded->data, payload, size) == 0 &&
        memcmp(loaded->sha3, chunk_sha3, 32) == 0;
}

#if !defined(_WIN32)
static bool content_mtime_freeze_rejected(struct node_db *ndb,
    const uint8_t offer_id[32], const char *filepath, uint8_t first_byte)
{
    struct stat before_rewrite;
    bool captured = stat(filepath, &before_rewrite) == 0;
    int rewrite_fd = open(filepath, O_WRONLY | O_CLOEXEC);
    uint8_t swapped = (uint8_t)(first_byte ^ 0xffu);
    bool rewrote = captured && rewrite_fd >= 0 &&
        platform_positioned_write(rewrite_fd, &swapped, 1, 0) == 1;
    if (rewrite_fd >= 0)
        close(rewrite_fd);
    const struct timespec keep_times[2] = {
        before_rewrite.st_atim, before_rewrite.st_mtim,
    };
    bool clock_frozen = rewrote &&
        utimensat(AT_FDCWD, filepath, keep_times, 0) == 0;
    struct file_market_delivery_chunk loaded;
    struct zcl_result load_result = file_market_content_load_chunk(
        ndb, offer_id, 0, &loaded);
    return clock_frozen && !load_result.ok && loaded.data == NULL;
}
#endif /* !defined(_WIN32) */

static bool content_post_tamper_revoked(struct node_db *ndb,
    const uint8_t offer_id[32], const char *filepath, uint8_t first_byte)
{
    int mutate_fd = open(filepath, O_WRONLY | O_CLOEXEC);
    uint8_t changed = (uint8_t)(first_byte ^ 0xffu);
    bool mutated = mutate_fd >= 0 &&
        platform_positioned_write(mutate_fd, &changed, 1, 0) == 1;
    if (mutate_fd >= 0) close(mutate_fd);
    struct file_market_delivery_chunk loaded;
    struct zcl_result load_result = file_market_content_load_chunk(
        ndb, offer_id, 0, &loaded);
    bool load_ok = load_result.ok;
    return mutated && !load_ok && loaded.data == NULL;
}

static bool content_seed_index_window_rows(struct node_db *wndb,
    const char *wdbpath, size_t payload_size, int64_t now_unix)
{
    memset(wndb, 0, sizeof(*wndb));
    bool wopened = node_db_open(wndb, wdbpath);
    rpc_market_set_state(wndb);

    /* 257 registry rows, one past the window. The three newest are
     * reviewed-ok via real signed offers; the rest hide under the
     * boot-default profile. */
    struct file_offer reviewed[3];
    bool seeded = wopened;
    for (int k = 0; seeded && k < 3; k++) {
        uint8_t digest[32], root[32];
        content_window_digest(256 - k, digest);
        sha3_256(digest, sizeof(digest), root);
        seeded = content_signed_offer(&reviewed[k], root,
                                      payload_size,
                                      (uint64_t)(7401 + k),
                                      now_unix) &&
            db_file_offer_save(wndb, &reviewed[k]) &&
            market_moderation_set_review_state(
                reviewed[k].offer_id,
                MARKET_REVIEW_REVIEWED_OK).ok;
    }
    for (int i = 0; seeded && i < 257; i++) {
        uint8_t digest[32], root[32];
        content_window_digest(i, digest);
        sha3_256(digest, sizeof(digest), root);
        struct market_content_record row;
        memset(&row, 0, sizeof(row));
        if (i >= 254)
            memcpy(row.offer_id, reviewed[256 - i].offer_id, 32);
        else
            memcpy(row.offer_id, digest, 32);
        memcpy(row.root_hash, root, 32);
        snprintf(row.private_path, sizeof(row.private_path),
                 "/registered/window-%03d.bin", i);
        row.size_bytes = payload_size;
        row.num_chunks = 1;
        row.chunk_hashes = digest;
        row.chunk_hashes_len = sizeof(digest);
        row.registered_at = now_unix + 10000 + i;
        seeded = db_market_content_save(wndb, &row);
    }
    return seeded;
}

static bool content_registry_count_matches(struct node_db *wndb, bool seeded)
{
    return seeded && db_market_content_count(wndb) == 257;
}

static bool content_list_seeded_contents(bool seeded, struct json_value *index)
{
    return seeded && api_market_content_list(index);
}

static bool content_window_shows_three(const struct json_value *window_index,
    bool window_indexed, const struct json_value *shown_v,
    const struct json_value *rows_v)
{
    return window_indexed && shown_v && rows_v &&
        rows_v->type == JSON_ARR &&
        json_size(rows_v) == 3 &&
        json_get_int(shown_v) == 3 &&
        json_get(window_index, "total") == NULL &&
        json_get(window_index, "hidden_by_profile") == NULL;
}

static bool content_snapshot_row_total(int snapshot_count, int snapshot_total)
{
    return snapshot_count == 2 && snapshot_total == 257;
}

static bool content_uncountable_shown_only(bool uncountable_ok,
    const struct json_value *u_shown, const struct json_value *uncountable)
{
    return uncountable_ok && u_shown &&
        json_get_int(u_shown) == 0 &&
        json_get(uncountable, "total") == NULL;
}

static bool content_gate_bytes_offered(struct node_db *ndb,
    const char *gate_path, const uint8_t *payload, size_t size,
    const uint8_t root[32], int64_t now_unix, struct file_offer *gate_offer)
{
    return content_write_file(gate_path, payload, size) &&
        content_signed_offer(gate_offer, root, size, 7501, now_unix) &&
        db_file_offer_save(ndb, gate_offer);
}

static void content_copy_token_text(const char *token, char *out,
                                    size_t out_size)
{
    if (token)
        snprintf(out, out_size, "%s", token);
}

static bool content_plan_rows_unchanged(bool planned, const char *plan_status,
    const char *token_hex, struct node_db *ndb, int64_t rows_before)
{
    return planned && plan_status &&
        strcmp(plan_status, "planned") == 0 &&
        strlen(token_hex) == 64 &&
        db_market_content_count(ndb) == rows_before;
}

static char content_flip_leading_hex(char digit)
{
    return digit == '0' ? '1' : '0';
}

static const char *content_json_value_string(const struct json_value *value)
{
    return value->type == JSON_STR ? json_get_str(value) : NULL;
}

static bool content_stale_token_kept_rows(bool tamper_refused,
    const char *tamper_reason, struct node_db *ndb, int64_t rows_before)
{
    return tamper_refused && tamper_reason &&
        strstr(tamper_reason, "STALE_PLAN") != NULL &&
        db_market_content_count(ndb) == rows_before;
}

static bool content_bare_commit_kept_rows(bool bare_refused,
    struct node_db *ndb, int64_t rows_before)
{
    return bare_refused && db_market_content_count(ndb) == rows_before;
}

static bool content_commit_registered_receipt(bool committed,
    const struct json_value *committed_flag, const char *commit_status,
    const struct json_value *registered_at, const char *commit_rendered,
    const char *gate_path, struct node_db *ndb, int64_t rows_before)
{
    return committed && committed_flag &&
        committed_flag->type == JSON_BOOL &&
        json_get_bool(committed_flag) &&
        commit_status && strcmp(commit_status, "registered") == 0 &&
        registered_at && registered_at->type == JSON_INT &&
        json_get_int(registered_at) > 0 &&
        strstr(commit_rendered, gate_path) == NULL &&
        strstr(commit_rendered, "content_path") == NULL &&
        db_market_content_count(ndb) == rows_before + 1;
}

static int64_t content_json_int_if_present(const struct json_value *value)
{
    return value && value->type == JSON_INT ? json_get_int(value) : 0;
}

static bool content_stale_plan_text(bool replay_stale, const char *stale_reason)
{
    return replay_stale && stale_reason &&
        strstr(stale_reason, "STALE_PLAN") != NULL;
}

static bool content_token_texts_differ(const char *path_token_buf,
                                       const char *token_hex)
{
    return path_token_buf[0] && strcmp(path_token_buf, token_hex) != 0;
}

static bool content_path_commit_refused(bool path_planned,
    bool path_token_differs, bool path_refused, const char *path_reason,
    struct node_db *ndb, int64_t rows_before)
{
    return path_planned && path_token_differs && path_refused &&
        path_reason && strstr(path_reason, "STALE_PLAN") != NULL &&
        db_market_content_count(ndb) == rows_before + 1;
}

static bool content_alternate_gate_ready(const char *alternate_path,
    const uint8_t *payload, size_t size, const char *gate_path,
    char *canonical_gate, size_t canonical_gate_size,
    char *canonical_alternate, size_t canonical_alternate_size)
{
    return content_write_file(alternate_path, payload, size) &&
        content_canonical_file(gate_path, canonical_gate,
                               canonical_gate_size) &&
        content_canonical_file(alternate_path, canonical_alternate,
                               canonical_alternate_size);
}

static bool content_rebind_row_saved(bool before_ok, struct node_db *ndb,
                                     struct market_content_record *row)
{
    return before_ok && db_market_content_save(ndb, row);
}

static bool content_plan_digest_changed(bool after_ok,
    const uint8_t before_same_second[32], const uint8_t after_same_second[32])
{
    return after_ok &&
        memcmp(before_same_second, after_same_second, 32) != 0;
}

static bool content_interleave_refused(bool saved,
                                       const struct zcl_result *interleaved)
{
    return saved && !interleaved->ok &&
        strstr(interleaved->message, "STALE_PLAN") != NULL;
}

int file_market_content_tests(void)
{
    int failures = 0;
    enum { PAYLOAD_SIZE = 8193 };
    uint8_t payload[PAYLOAD_SIZE];
    content_fill_payload(payload, sizeof(payload));
    uint8_t chunk_sha3[32], root[32];
    content_one_chunk_root(payload, sizeof(payload), chunk_sha3, root);

    char dir[256], dbpath[512], filepath[512], symlink_path[512];
    char fifo_path[512], wrong_path[512];
    snprintf(dir, sizeof(dir), "./test-tmp/market_content_%d", (int)getpid());
    (void)platform_directory_create("./test-tmp", 0700);
    if (!content_market_dir_created(dir)) {
        CONTENT_CHECK("create fixture directory", false);
        return failures;
    }
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);
    snprintf(filepath, sizeof(filepath), "%s/content.bin", dir);
    snprintf(symlink_path, sizeof(symlink_path), "%s/content-link", dir);
    snprintf(fifo_path, sizeof(fifo_path), "%s/content-fifo", dir);
    snprintf(wrong_path, sizeof(wrong_path), "%s/wrong.bin", dir);
#if defined(_WIN32)
    /* No mkfifo, and symlink creation may lack privilege
     * (ERROR_PRIVILEGE_NOT_HELD), so the non-regular-file refusal fixtures
     * cannot be built. */
    bool files_ready = content_write_content_fixtures(
        filepath, symlink_path, fifo_path, wrong_path, payload,
        sizeof(payload));
    CONTENT_CHECK("regular and mismatch fixtures", files_ready);
    (void)symlink_path;
    (void)fifo_path;
#else
    bool files_ready = content_write_content_fixtures(
        filepath, symlink_path, fifo_path, wrong_path, payload,
        sizeof(payload));
    CONTENT_CHECK("regular, symlink, special, and mismatch fixtures",
                  files_ready);
#endif

    int64_t now_unix = (int64_t)platform_time_wall_time_t();
    struct file_offer offer;
    struct node_db ndb;
    bool opened = content_authenticated_offer_opened(
        &ndb, dbpath, &offer, root, sizeof(payload), now_unix);
    CONTENT_CHECK("authenticated offer database fixture", opened);
    if (!opened) {
        content_close_open_node_db(&ndb);
        test_cleanup_tmpdir(dir);
        return failures;
    }

    CONTENT_CHECK("registration state distinguishes absent from error",
        content_registration_states_differ(&ndb, offer.offer_id));

    /* Counts come from the store, uncapped: an empty registry counts zero,
     * an unreadable one fails closed to -1. */
    CONTENT_CHECK("store counts start measured and fail closed",
        content_initial_counts_fail_closed(&ndb));

    struct market_content_public_record registered;
    struct zcl_result result = file_market_content_register(
        &ndb, offer.offer_id, filepath, now_unix, &registered);
    CONTENT_CHECK("exact bytes register against signed manifest",
        content_manifest_bytes_match(&result, &registered, sizeof(payload),
                                     root));

    struct market_content_public_record listed[2];
    int listed_total = -1;
    int listed_count = db_market_content_list_snapshot(
        &ndb, listed, 2, &listed_total);
    CONTENT_CHECK("path-free model projection lists one binding",
        content_one_offer_listed(listed_count, listed_total, listed,
                                 offer.offer_id));

    struct file_market_delivery_chunk loaded;
    struct zcl_result load_result = file_market_content_load_chunk(
        &ndb, offer.offer_id, 0, &loaded);
    bool load_ok = load_result.ok;
    CONTENT_CHECK("verified reader returns exact registered chunk",
        content_verified_chunk_bytes(load_ok, &loaded, payload,
                                     sizeof(payload), chunk_sha3));
    free(loaded.data);

#if !defined(_WIN32)
    result = file_market_content_register(
        &ndb, offer.offer_id, symlink_path, now_unix + 1, &registered);
    CONTENT_CHECK("symbolic-link registration fails closed", !result.ok);
    result = file_market_content_register(
        &ndb, offer.offer_id, fifo_path, now_unix + 1, &registered);
    CONTENT_CHECK("non-regular registration fails closed", !result.ok);
#else
    printf("file_market_content: SKIP (Windows): symbolic-link registration "
           "fails closed (fixture unbuildable)\n");
    printf("file_market_content: SKIP (Windows): nonblocking FIFO "
           "registration fails closed (no mkfifo)\n");
#endif
    result = file_market_content_register(
        &ndb, offer.offer_id, wrong_path, now_unix + 1, &registered);
    CONTENT_CHECK("signed size mismatch fails before persistence", !result.ok);

    struct file_offer wrong_root_offer;
    bool wrong_offer_ready = content_wrong_root_offer_saved(
        &ndb, &wrong_root_offer, sizeof(payload), now_unix);
    result = wrong_offer_ready ? file_market_content_register(
        &ndb, wrong_root_offer.offer_id, filepath, now_unix + 1,
        &registered) : ZCL_ERR(-1, "wrong offer fixture failed");
    CONTENT_CHECK("signed root mismatch fails before persistence",
                  content_root_mismatch_rejected(wrong_offer_ready,
                                                 &result));

    CONTENT_CHECK("model counts follow the rows actually saved",
        content_saved_offer_counts(&ndb));

    rpc_market_set_state(&ndb);
    /* The registered-content index is a serving surface. Under the
     * boot-default profile it lists nothing and reports how much it
     * withheld, never a row the chunk-delivery gate would refuse. */
    struct json_value hidden_index;
    json_init(&hidden_index);
    bool hidden_indexed = api_market_content_list(&hidden_index);
    char hidden_rendered[4096];
    size_t hidden_len = json_write(&hidden_index, hidden_rendered,
                                   sizeof(hidden_rendered));
    CONTENT_CHECK("public index withholds rows and private counts",
        content_index_hides_rows(hidden_indexed, hidden_len,
                                 hidden_rendered, &hidden_index));
    json_free(&hidden_index);

    /* After this node signs off on its own content the row appears — and
     * the private filesystem path is still never returned. */
    struct zcl_result signed_off = market_moderation_set_review_state(
        offer.offer_id, MARKET_REVIEW_REVIEWED_OK);
    struct json_value public_index;
    json_init(&public_index);
    bool indexed = api_market_content_list(&public_index);
    char rendered[4096];
    size_t rendered_len = json_write(&public_index, rendered,
                                     sizeof(rendered));
    CONTENT_CHECK("private REST index omits filesystem references",
        content_reviewed_index_omits_path(signed_off.ok, indexed,
                                          rendered_len, rendered,
                                          filepath));
    json_free(&public_index);

    node_db_close(&ndb);
    bool reopened = node_db_open(&ndb, dbpath);
    load_result = reopened ? file_market_content_load_chunk(
        &ndb, offer.offer_id, 0, &loaded)
        : ZCL_ERR(-1, "database reopen failed");
    load_ok = load_result.ok;
    CONTENT_CHECK("restart reconstructs verified content reader",
        content_restarted_chunk_bytes(load_ok, &loaded, payload,
                                      sizeof(payload)));
    free(loaded.data);

    /* Slice-serving loads once per <=60 KiB slice of the same immutable
     * chunk; the second load rides the verified-digest table (same inode
     * identity, same bytes, memory copy instead of another SHA3). */
    struct zcl_result warm_result = file_market_content_load_chunk(
        &ndb, offer.offer_id, 0, &loaded);
    CONTENT_CHECK("warm slice load repeats the exact verified chunk",
        content_warm_chunk_bytes(&warm_result, &loaded, payload,
                                 sizeof(payload), chunk_sha3));
    free(loaded.data);

    /* An in-place rewrite restoring its old mtime via utimensat(2) must
     * still refuse: ctime cannot be set backwards, so the key misses and the
     * bytes are re-hashed. POSIX-only (st_atim/st_mtim, utimensat), so not
     * exercised on Windows. */
#if !defined(_WIN32)
    CONTENT_CHECK("mtime-frozen rewrite cannot ride the digest table",
                  content_mtime_freeze_rejected(&ndb, offer.offer_id,
                                                filepath, payload[0]));
#endif /* !defined(_WIN32) */

    CONTENT_CHECK("post-registration content tamper revokes delivery",
                  content_post_tamper_revoked(&ndb, offer.offer_id,
                                              filepath, payload[0]));

    /* ── the serving index discloses its window ──────────────────── */
    /* Past the index's 256-row listing window the index discloses shown and
     * total from the same store; an uncountable store drops the total. */
    {
        char wdir[256], wdbpath[512];
        snprintf(wdir, sizeof(wdir), "./test-tmp/market_index_window_%d",
                 (int)getpid());
        (void)platform_directory_create("./test-tmp", 0700);
        if (platform_directory_create(wdir, 0700) != 0 && errno != EEXIST) {
            CONTENT_CHECK("create index window fixture directory", false);
            node_db_close(&ndb);
            test_cleanup_tmpdir(dir);
            return failures;
        }
        snprintf(wdbpath, sizeof(wdbpath), "%s/node.db", wdir);
        struct node_db wndb;
        bool seeded = content_seed_index_window_rows(
            &wndb, wdbpath, sizeof(payload), now_unix);
        CONTENT_CHECK("registry seeds one past the index window",
            content_registry_count_matches(&wndb, seeded));

        struct json_value window_index;
        json_init(&window_index);
        bool window_indexed = content_list_seeded_contents(
            seeded, &window_index);
        const struct json_value *shown_v = json_get(&window_index, "shown");
        const struct json_value *rows_v =
            json_get(&window_index, "contents");
        CONTENT_CHECK("public index reveals only servable window rows",
            content_window_shows_three(&window_index, window_indexed,
                                       shown_v, rows_v));
        json_free(&window_index);

        struct market_content_public_record snapshot[2];
        int snapshot_total = -1;
        int snapshot_count = db_market_content_list_snapshot(
            &wndb, snapshot, 2, &snapshot_total);
        CONTENT_CHECK("local snapshot binds bounded rows to exact total",
            content_snapshot_row_total(snapshot_count, snapshot_total));

        /* An uncountable store keeps the listing but drops the total. */
        rpc_market_set_state(NULL);
        struct json_value uncountable;
        json_init(&uncountable);
        bool uncountable_ok = api_market_content_list(&uncountable);
        const struct json_value *u_shown = json_get(&uncountable, "shown");
        CONTENT_CHECK("uncountable store drops the total, keeps shown",
            content_uncountable_shown_only(uncountable_ok, u_shown,
                                           &uncountable));
        json_free(&uncountable);

        node_db_close(&wndb);
        test_cleanup_tmpdir(wdir);
    }

    /* ── the registration confirm gate ───────────────────────────── */
    /* Binding the owner's serving bytes is two-step: plan mints a token
     * bound to the offer, target path and current registration; commit
     * re-derives it from live state. A moved registration or changed path
     * stales the plan, and a plan never mutates. */
    {
        rpc_market_set_state(&ndb);
        /* The tamper tests corrupted filepath's bytes and commit hashes the
         * target, so the gate needs its own pristine file with the root. */
        char gate_path[512];
        snprintf(gate_path, sizeof(gate_path), "%s/gate.bin", dir);
        struct file_offer gate_offer;
        bool gate_ready = content_gate_bytes_offered(
            &ndb, gate_path, payload, sizeof(payload), root, now_unix,
            &gate_offer);
        CONTENT_CHECK("confirm-gate fixture offer", gate_ready);

        struct rpc_table gate_table;
        rpc_table_init(&gate_table);
        register_market_rpc_commands(&gate_table);
        set_rpc_warmup_finished();

        char gate_offer_hex[65];
        zcl_hex_encode(gate_offer.offer_id, 32, gate_offer_hex);
        int64_t rows_before = db_market_content_count(&ndb);
        char gate_params[600];
        struct json_value gate;

        /* Plan: mints the token, mutates nothing. */
        snprintf(gate_params, sizeof(gate_params),
                 "[\"%s\",\"%s\",\"plan\"]", gate_offer_hex, gate_path);
        json_init(&gate);
        bool planned = content_rpc(&gate_table, "zmarket_content_register",
                                   gate_params, &gate);
        const char *plan_token = content_kv_str(&gate, "plan_token");
        char token_hex[65];
        content_copy_token_text(plan_token, token_hex, sizeof(token_hex));
        const char *plan_status = content_kv_str(&gate, "status");
        CONTENT_CHECK("plan mints a token and mutates nothing",
            content_plan_rows_unchanged(planned, plan_status, token_hex,
                                        &ndb, rows_before));
        json_free(&gate);

        /* A well-formed but wrong token re-derives a different digest and
         * reads as a moved bind (the bare-commit leg covers malformed). */
        char tampered[65];
        snprintf(tampered, sizeof(tampered), "%s", token_hex);
        tampered[0] = content_flip_leading_hex(tampered[0]);
        snprintf(gate_params, sizeof(gate_params),
                 "[\"%s\",\"%s\",\"commit\",\"%s\"]", gate_offer_hex,
                 gate_path, tampered);
        json_init(&gate);
        bool tamper_refused = !content_rpc(
            &gate_table, "zmarket_content_register", gate_params, &gate);
        const char *tamper_reason = content_json_value_string(&gate);
        CONTENT_CHECK("tampered plan token is refused",
            content_stale_token_kept_rows(tamper_refused, tamper_reason,
                                          &ndb, rows_before));
        json_free(&gate);

        /* Commit without a token is refused. */
        snprintf(gate_params, sizeof(gate_params),
                 "[\"%s\",\"%s\",\"commit\"]", gate_offer_hex, gate_path);
        json_init(&gate);
        bool bare_refused = !content_rpc(
            &gate_table, "zmarket_content_register", gate_params, &gate);
        CONTENT_CHECK("commit without a plan token is refused",
            content_bare_commit_kept_rows(bare_refused, &ndb, rows_before));
        json_free(&gate);

        /* The real commit carries the planned token and binds the bytes —
         * and the receipt never echoes the private path. */
        snprintf(gate_params, sizeof(gate_params),
                 "[\"%s\",\"%s\",\"commit\",\"%s\"]", gate_offer_hex,
                 gate_path, token_hex);
        json_init(&gate);
        bool committed = content_rpc(&gate_table,
                                     "zmarket_content_register",
                                     gate_params, &gate);
        const struct json_value *committed_flag =
            json_get(&gate, "committed");
        const char *commit_status = content_kv_str(&gate, "status");
        const struct json_value *registered_at = json_get(&gate,
                                                          "registered_at");
        char commit_rendered[1024];
        (void)json_write(&gate, commit_rendered, sizeof(commit_rendered));
        CONTENT_CHECK("commit with the planned token registers",
            content_commit_registered_receipt(
                committed, committed_flag, commit_status, registered_at,
                commit_rendered, gate_path, &ndb, rows_before));
        int64_t gate_registered_at =
            content_json_int_if_present(registered_at);
        json_free(&gate);

        /* Replaying that commit after the registration moved is stale:
         * the state the token was minted against no longer exists. */
        json_init(&gate);
        bool replay_stale = !content_rpc(
            &gate_table, "zmarket_content_register", gate_params, &gate);
        const char *stale_reason = content_json_value_string(&gate);
        CONTENT_CHECK("replayed commit after the bind is stale",
            content_stale_plan_text(replay_stale, stale_reason));
        json_free(&gate);

        /* The target path is bound: a token planned for one path cannot
         * commit another. */
        snprintf(gate_params, sizeof(gate_params),
                 "[\"%s\",\"%s\",\"plan\"]", gate_offer_hex, wrong_path);
        json_init(&gate);
        bool path_planned = content_rpc(&gate_table,
                                        "zmarket_content_register",
                                        gate_params, &gate);
        const char *path_token = content_kv_str(&gate, "plan_token");
        char path_token_buf[65];
        path_token_buf[0] = '\0';
        content_copy_token_text(path_token, path_token_buf,
                                sizeof(path_token_buf));
        json_free(&gate);
        bool path_token_differs = content_token_texts_differ(
            path_token_buf, token_hex);
        snprintf(gate_params, sizeof(gate_params),
                 "[\"%s\",\"%s\",\"commit\",\"%s\"]", gate_offer_hex,
                 gate_path, path_token_buf);
        json_init(&gate);
        bool path_refused = !content_rpc(
            &gate_table, "zmarket_content_register", gate_params, &gate);
        const char *path_reason = content_json_value_string(&gate);
        CONTENT_CHECK("a plan for one path cannot commit another",
            content_path_commit_refused(path_planned, path_token_differs,
                path_refused, path_reason, &ndb, rows_before));
        json_free(&gate);

        /* A timestamp is not a row identity: rebinding the same offer in the
         * same second changes the plan, and a rewrite after hashing is
         * caught by the transactional compare. */
        char alternate_path[512], canonical_gate[MARKET_CONTENT_PATH_MAX];
        char canonical_alternate[MARKET_CONTENT_PATH_MAX];
        snprintf(alternate_path, sizeof(alternate_path), "%s/gate-alt.bin",
                 dir);
        bool alternate_ready = content_alternate_gate_ready(
            alternate_path, payload, sizeof(payload), gate_path,
            canonical_gate, sizeof(canonical_gate),
            canonical_alternate, sizeof(canonical_alternate));
        uint8_t before_same_second[32], after_same_second[32];
        char state_name[MARKET_CONTENT_REGISTRATION_STATE_MAX];
        struct zcl_result before_plan = alternate_ready
            ? file_market_content_registration_plan(
                &ndb, gate_offer.offer_id, gate_path, before_same_second,
                state_name)
            : ZCL_ERR(-1, "alternate fixture failed");
        struct market_content_record same_second;
        memset(&same_second, 0, sizeof(same_second));
        memcpy(same_second.offer_id, gate_offer.offer_id, 32);
        memcpy(same_second.root_hash, root, 32);
        snprintf(same_second.private_path, sizeof(same_second.private_path),
                 "%s", canonical_alternate);
        same_second.size_bytes = sizeof(payload);
        same_second.num_chunks = 1;
        same_second.chunk_hashes = chunk_sha3;
        same_second.chunk_hashes_len = sizeof(chunk_sha3);
        same_second.registered_at = gate_registered_at;
        bool rebound_same_second = content_rebind_row_saved(
            before_plan.ok, &ndb, &same_second);
        struct zcl_result after_plan = rebound_same_second
            ? file_market_content_registration_plan(
                &ndb, gate_offer.offer_id, gate_path, after_same_second,
                state_name)
            : ZCL_ERR(-1, "same-second rebind failed");
        CONTENT_CHECK("same-second durable row rewrite stales the plan",
            content_plan_digest_changed(after_plan.ok, before_same_second,
                                        after_same_second));

        struct content_interleave_fixture interleave;
        memset(&interleave, 0, sizeof(interleave));
        interleave.ndb = &ndb;
        interleave.row = same_second;
        snprintf(interleave.row.private_path,
                 sizeof(interleave.row.private_path), "%s", canonical_gate);
        file_market_content_set_precommit_test_hook(
            content_interleave_registration, &interleave);
        struct market_content_public_record refused_record;
        struct zcl_result interleaved =
            file_market_content_register_planned(
                &ndb, gate_offer.offer_id, gate_path, after_same_second,
                gate_registered_at, &refused_record);
        file_market_content_set_precommit_test_hook(NULL, NULL);
        CONTENT_CHECK("post-hash interleaving rewrite is atomically refused",
            content_interleave_refused(interleave.saved, &interleaved));
    }

    rpc_market_set_state(NULL);
    node_db_close(&ndb);
    test_cleanup_tmpdir(dir);
    return failures;
}
