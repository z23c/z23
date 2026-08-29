/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: typed operator surface for Git-free ZVCS source transport. */

#include "command/native_command.h"

#include "base/hex.h"
#include "controllers/rpc_client.h"
#include "controllers/rpc_params.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "platform/directory_transaction.h"
#include "platform/positioned_file.h"
#include "platform/private_file.h"
#include "util/safe_alloc.h"
#include "net/rom_fetch.h"
#include "services/source_bundle_fetch.h"
#include "vcs/source_bundle.h"
#include "vcs/source_package_checkout.h"
#include "vcs/package_store.h"
#include "vcs/vcs.h"

#if !defined(_WIN32)
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

#define ZSB_PATH_MAX 4400

static const char *zsb_str(const struct json_value *input, const char *key)
{
    const struct json_value *value = input ? json_get(input, key) : NULL;
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static void zsb_fail(struct zcl_command_reply *reply, const char *code,
                     const char *stage, const char *detail)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, stage, false,
                           false, detail, "zcode.workspace.source.bundle");
}

static bool zsb_root(const struct json_value *input, uint8_t out[32])
{
    const char *hex = zsb_str(input, "source_root");
    return hex && zcl_hex_decode_lower(hex, out, 32);
}

static bool zsb_named_root(const struct json_value *input, const char *key,
                           uint8_t out[32])
{
    const char *hex = zsb_str(input, key);
    return hex && zcl_hex_decode_lower(hex, out, 32);
}

static bool zsb_paths_disjoint(const char *left, const char *right)
{
    size_t left_len = strlen(left), right_len = strlen(right);
#if defined(_WIN32)
    return _stricmp(left, right) != 0 &&
        !(left_len < right_len && _strnicmp(left, right, left_len) == 0 &&
          (right[left_len] == '/' || right[left_len] == '\\')) &&
        !(right_len < left_len && _strnicmp(right, left, right_len) == 0 &&
          (left[right_len] == '/' || left[right_len] == '\\'));
#else
    return strcmp(left, right) != 0 &&
        !(left_len < right_len && strncmp(left, right, left_len) == 0 &&
          right[left_len] == '/') &&
        !(right_len < left_len && strncmp(right, left, right_len) == 0 &&
          left[right_len] == '/');
#endif
}

static uint8_t *zsb_read(const char *path, size_t *len_out)
{
    *len_out = 0;
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    if (!path || !platform_positioned_file_open(&file, path) ||
        !platform_positioned_file_snapshot(&file, &before) ||
        before.size == 0 || before.size > VCS_SOURCE_BUNDLE_MAX_WIRE_BYTES) {
        platform_positioned_file_close(&file);
        return NULL;
    }
    size_t len = (size_t)before.size;
    uint8_t *bytes = zcl_malloc(len, "zcode.workspace.source.bundle.read");
    if (!bytes) { platform_positioned_file_close(&file); return NULL; }
    size_t off = 0;
    while (off < len) {
        int64_t got = platform_positioned_file_read(
            &file, bytes + off, len - off, off);
        if (got <= 0) break;
        off += (size_t)got;
    }
    bool ok = off == len && platform_positioned_file_snapshot(&file, &after) &&
        platform_positioned_file_snapshot_equal(&before, &after);
    platform_positioned_file_close(&file);
    if (!ok) { free(bytes); return NULL; }
    *len_out = len;
    return bytes;
}

static bool zsb_write_exclusive(const char *path, const uint8_t *bytes,
                                size_t len)
{
#if defined(_WIN32)
    char resolved[ZSB_PATH_MAX], parent[ZSB_PATH_MAX];
    if (!path || !bytes || !platform_private_path_resolve(
            path, resolved, sizeof(resolved), parent, sizeof(parent)))
        return false;
    const char *slash = strrchr(resolved, '\\');
    if (!slash) slash = strrchr(resolved, '/');
    const char *leaf = slash ? slash + 1 : NULL;
    struct platform_directory_transaction directory;
    struct platform_directory_child file;
    platform_directory_transaction_init(&directory);
    platform_directory_child_init(&file);
    bool created = leaf && leaf[0] &&
        platform_directory_transaction_open(&directory, parent) &&
        platform_directory_child_create(&directory, leaf, &file);
    bool ok = created &&
        platform_directory_child_write_exact(&file, bytes, len, 0) &&
        platform_directory_child_flush(&file) &&
        platform_directory_transaction_flush(&directory);
    platform_directory_child_close(&file);
    if (created && !ok)
        (void)platform_directory_child_unlink(&directory, leaf, true);
    platform_directory_transaction_close(&directory);
    return ok;
#else
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                  0400);
    if (fd < 0) return false;
    size_t off = 0;
    while (off < len) {
        ssize_t wrote = write(fd, bytes + off, len - off);
        if (wrote < 0 && errno == EINTR) continue;
        if (wrote <= 0) break;
        off += (size_t)wrote;
    }
    bool ok = off == len;
    if (ok && fsync(fd) != 0) ok = false;
    if (close(fd) != 0) ok = false;
    if (!ok) (void)unlink(path);
    return ok;
#endif
}

static bool zsb_write_child_exclusive(
    struct platform_directory_transaction *directory, const char *leaf,
    const uint8_t *bytes, size_t len)
{
    struct platform_directory_child file;
    platform_directory_child_init(&file);
    bool created = platform_directory_child_create(directory, leaf, &file);
    bool ok = created &&
        platform_directory_child_write_exact(&file, bytes, len, 0) &&
        platform_directory_child_flush(&file) &&
        platform_directory_transaction_flush(directory);
    platform_directory_child_close(&file);
    if (created && !ok)
        (void)platform_directory_child_unlink(directory, leaf, true);
    return ok;
}

static bool zsb_empty_dir(const char *path)
{
#if defined(_WIN32)
    /* The current retained enumeration API intentionally omits reparse
     * points, so it cannot prove an attacker-controlled directory empty.
     * Refuse until an all-entry retained enumeration is available. */
    (void)path;
    return false;
#else
    DIR *dir = opendir(path);
    if (!dir) return false;
    bool empty = true;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0) {
            empty = false;
            break;
        }
    }
    return closedir(dir) == 0 && empty;
#endif
}

static void zsb_render(struct json_value *out, const uint8_t root[32],
                       const struct vcs_source_bundle_metrics *metrics)
{
    char hex[65];
    zcl_hex_encode(root, 32, hex);
    (void)json_push_kv_str(out, "source_root", hex);
    (void)json_push_kv_int(out, "source_bytes",
                           (int64_t)metrics->source_bytes);
    (void)json_push_kv_int(out, "compressed_bytes",
                           (int64_t)metrics->compressed_bytes);
    (void)json_push_kv_int(out, "file_count", metrics->file_count);
    (void)json_push_kv_int(out, "new_bytes", (int64_t)metrics->new_bytes);
    (void)json_push_kv_int(out, "reused_bytes",
                           (int64_t)metrics->reused_bytes);
    (void)json_push_kv_int(out, "new_blobs", metrics->new_blobs);
    (void)json_push_kv_int(out, "reused_blobs", metrics->reused_blobs);
    (void)json_push_kv_bool(out, "manifest_reused",
                            metrics->manifest_reused);
    (void)json_push_kv_bool(out, "repaired", metrics->repaired);
    (void)json_push_kv_bool(out, "git_required", false);
    (void)json_push_kv_bool(out, "source_executed", false);
}

void zcl_native_handle_zcode_source_capture(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *workspace_arg = zsb_str(request->input, "workspace");
    char workspace[ZSB_PATH_MAX];
    uint8_t root[32];
    if (!workspace_arg || !platform_directory_canonical_real(
            workspace_arg, workspace, sizeof(workspace)) ||
        vcs_tree_capture_path(workspace, root) != VCS_OK) {
        zsb_fail(reply, "SOURCE_CAPTURE_REFUSED", "capture",
                 "workspace must resolve and remain byte-stable through the complete ZVCS capture");
        return;
    }
    struct vcs_manifest manifest;
    if (!vcs_tree_load(workspace, root, &manifest)) {
        zsb_fail(reply, "SOURCE_CAPTURE_READBACK_REFUSED", "capture",
                 "captured manifest did not rederive from the ZVCS CAS");
        return;
    }
    uint64_t bytes = 0;
    bool bounded = manifest.count <= UINT32_MAX;
    for (size_t i = 0; bounded && i < manifest.count; i++) {
        bounded = manifest.entries[i].size <= UINT64_MAX - bytes;
        if (bounded) bytes += manifest.entries[i].size;
    }
    bounded = bounded && bytes <= INT64_MAX;
    uint32_t files = bounded ? (uint32_t)manifest.count : 0;
    vcs_manifest_free(&manifest);
    if (!bounded) {
        zsb_fail(reply, "SOURCE_CAPTURE_LIMIT", "capture",
                 "captured source accounting exceeded the typed result bounds");
        return;
    }
    char hex[65];
    zcl_hex_encode(root, 32, hex);
    (void)json_push_kv_str(&reply->data, "source_root", hex);
    (void)json_push_kv_int(&reply->data, "source_bytes", (int64_t)bytes);
    (void)json_push_kv_int(&reply->data, "file_count", files);
    (void)json_push_kv_bool(&reply->data, "accepted", false);
    (void)json_push_kv_bool(&reply->data, "git_required", false);
    (void)json_push_kv_bool(&reply->data, "source_executed", false);
    (void)json_push_kv_str(
        &reply->data, "next",
        "complete the existing proof and explicit zcode work accept lifecycle before publication");
}

void zcl_native_handle_zcode_source_bundle_create(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *workspace = zsb_str(request->input, "workspace");
    const char *output = zsb_str(request->input, "output");
    uint8_t root[32];
    if (!workspace || !output || !zsb_root(request->input, root) ||
        !zcl_native_zcode_workspace_is_explicit_scratch(output)) {
        zsb_fail(reply, "BAD_SOURCE_BUNDLE_CREATE_INPUT", "validate",
                 "workspace, source_root and an explicit scratch output path are required");
        return;
    }
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    struct vcs_source_bundle_metrics metrics;
    enum vcs_source_bundle_result result = vcs_source_bundle_create(
        workspace, root, &wire, &wire_len, &metrics);
    if (result != VCS_SOURCE_BUNDLE_OK ||
        !zsb_write_exclusive(output, wire, wire_len)) {
        free(wire);
        zsb_fail(reply, result == VCS_SOURCE_BUNDLE_OK
                            ? "SOURCE_BUNDLE_OUTPUT_REFUSED"
                            : "SOURCE_BUNDLE_CREATE_REFUSED",
                 "create", result == VCS_SOURCE_BUNDLE_OK
                    ? "output must be a new no-follow file in an existing scratch directory"
                    : vcs_source_bundle_result_string(result));
        return;
    }
    free(wire);
    zsb_render(&reply->data, root, &metrics);
    (void)json_push_kv_str(&reply->data, "output", output);
    (void)json_push_kv_int(&reply->data, "wire_bytes", (int64_t)wire_len);
}

void zcl_native_handle_zcode_source_bundle_verify(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *bundle = zsb_str(request->input, "bundle");
    uint8_t root[32];
    size_t wire_len = 0;
    uint8_t *wire = bundle ? zsb_read(bundle, &wire_len) : NULL;
    struct vcs_source_bundle_metrics metrics;
    enum vcs_source_bundle_result result = wire && zsb_root(request->input, root)
        ? vcs_source_bundle_verify(wire, wire_len, root, &metrics)
        : VCS_SOURCE_BUNDLE_ERR_NULL;
    free(wire);
    if (result != VCS_SOURCE_BUNDLE_OK) {
        zsb_fail(reply, "SOURCE_BUNDLE_VERIFY_REFUSED", "verify",
                 vcs_source_bundle_result_string(result));
        return;
    }
    zsb_render(&reply->data, root, &metrics);
    (void)json_push_kv_bool(&reply->data, "verified", true);
}

void zcl_native_handle_zcode_source_bundle_import(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *bundle = zsb_str(request->input, "bundle");
    const char *workspace = zsb_str(request->input, "workspace");
    char workspace_real[ZSB_PATH_MAX];
    uint8_t root[32];
    if (!bundle || !workspace || !zsb_root(request->input, root) ||
        !zcl_native_zcode_workspace_is_explicit_scratch(workspace) ||
        !platform_directory_canonical_real(
            workspace, workspace_real, sizeof(workspace_real))) {
        zsb_fail(reply, "BAD_SOURCE_BUNDLE_IMPORT_INPUT", "validate",
                 "bundle, source_root and an explicit scratch workspace are required");
        return;
    }
    size_t wire_len = 0;
    uint8_t *wire = zsb_read(bundle, &wire_len);
    struct vcs_source_bundle_metrics metrics;
    enum vcs_source_bundle_result result = wire
        ? vcs_source_bundle_import(wire, wire_len, root, workspace_real,
                                   &metrics)
        : VCS_SOURCE_BUNDLE_ERR_WIRE;
    free(wire);
    if (result != VCS_SOURCE_BUNDLE_OK) {
        zsb_fail(reply, "SOURCE_BUNDLE_IMPORT_REFUSED", "import",
                 vcs_source_bundle_result_string(result));
        return;
    }
    zsb_render(&reply->data, root, &metrics);
    (void)json_push_kv_bool(&reply->data, "imported", true);
}

void zcl_native_handle_zcode_source_bundle_checkout(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *bundle = zsb_str(request->input, "bundle");
    const char *workspace = zsb_str(request->input, "workspace");
    const char *destination = zsb_str(request->input, "destination");
    char workspace_real[ZSB_PATH_MAX];
    char destination_real[ZSB_PATH_MAX];
    uint8_t root[32];
    if (!bundle || !workspace || !destination ||
        !zsb_root(request->input, root) ||
        !zcl_native_zcode_workspace_is_explicit_scratch(workspace) ||
        !zcl_native_zcode_workspace_is_explicit_scratch(destination) ||
        !platform_directory_canonical_real(
            workspace, workspace_real, sizeof(workspace_real)) ||
        !platform_directory_canonical_real(
            destination, destination_real, sizeof(destination_real)) ||
        strcmp(workspace_real, destination_real) == 0 ||
        !zsb_empty_dir(destination_real)) {
        zsb_fail(reply, "BAD_SOURCE_BUNDLE_CHECKOUT_INPUT", "validate",
                 "bundle, source_root, a separate scratch CAS workspace, and an existing empty scratch destination are required");
        return;
    }
    size_t wire_len = 0;
    uint8_t *wire = zsb_read(bundle, &wire_len);
    struct vcs_source_bundle_metrics metrics;
    enum vcs_source_bundle_result result = wire
        ? vcs_source_bundle_import(wire, wire_len, root, workspace_real,
                                   &metrics)
        : VCS_SOURCE_BUNDLE_ERR_WIRE;
    free(wire);
    if (result != VCS_SOURCE_BUNDLE_OK ||
        vcs_tree_materialize(workspace_real, root, destination_real,
                             VCS_SOURCE_BUNDLE_MAX_SOURCE_BYTES, 0) != VCS_OK) {
        zsb_fail(reply, result == VCS_SOURCE_BUNDLE_OK
                            ? "SOURCE_BUNDLE_MATERIALIZE_REFUSED"
                            : "SOURCE_BUNDLE_IMPORT_REFUSED",
                 "checkout", result == VCS_SOURCE_BUNDLE_OK
                    ? "verified ZVCS source could not be materialized into the empty destination"
                    : vcs_source_bundle_result_string(result));
        return;
    }
    zsb_render(&reply->data, root, &metrics);
    (void)json_push_kv_bool(&reply->data, "checked_out", true);
    (void)json_push_kv_str(&reply->data, "destination", destination_real);
}

/* ── Fetch: the same bundle, arriving over the wire ──────────────────
 *
 * Everything below the parse is the identity-free path this leaf exists for:
 * the ONLY input that decides acceptance is `source_root`, and it is the
 * caller's own. See app/services/src/source_bundle_fetch.c for the trust model
 * and the bound on a hostile peer. This handler contributes exactly two things
 * the service deliberately does not do: it parses the operator's peer list, and
 * it commits the verified bytes — with the SAME O_EXCL/O_NOFOLLOW exclusive
 * write `create` uses, so a fetch can no more overwrite an existing file or
 * follow a symlink than a create can. */

/* Split "host:port" (or "[v6]:port") into a rom_fetch_peer. Rejects an empty
 * host, an over-length host, a missing/zero/out-of-range port, and anything
 * with no ':' at all — a peer entry is never guessed at, because guessing a
 * port is how a fetcher ends up hardcoding one. Real deployments do NOT agree
 * on 18034; the port is per-node and must be stated. */
static bool zsb_parse_peer(const char *text, struct rom_fetch_peer *out)
{
    if (!text || !out) return false;
    const char *colon = strrchr(text, ':');
    if (!colon || colon == text || !colon[1]) return false;
    size_t host_len = (size_t)(colon - text);
    const char *host = text;
    if (host_len >= 2 && host[0] == '[' && host[host_len - 1] == ']') {
        host++;
        host_len -= 2;
    }
    if (host_len == 0 || host_len >= sizeof(out->addr)) return false;
    long port = 0;
    for (const char *p = colon + 1; *p; p++) {
        if (*p < '0' || *p > '9') return false;
        port = port * 10 + (*p - '0');
        if (port > 65535) return false;
    }
    if (port <= 0) return false;
    memset(out, 0, sizeof(*out));
    memcpy(out->addr, host, host_len);
    out->addr[host_len] = '\0';
    out->port = (uint16_t)port;
    return true;
}

/* Parse the required "peers" value: a comma-separated list of "host:port".
 * A STRING rather than a JSON array because the command registry types every
 * unlisted input key as a string, so an array shape is unreachable from the
 * CLI — and a leaf whose only documented invocation is refused at normalize is
 * a leaf nobody can run.
 *
 * EVERY entry must parse. A list that silently dropped its malformed half
 * would let one typo look exactly like an unreachable swarm, which is the
 * confusion this whole path exists to remove. Returns the count, or 0 for any
 * refusal. */
static size_t zsb_parse_peers(const struct json_value *input,
                              struct rom_fetch_peer *out, size_t max)
{
    const char *csv = zsb_str(input, "peers");
    if (!csv || !csv[0]) return 0;
    size_t n = 0;
    while (*csv) {
        const char *comma = strchr(csv, ',');
        size_t len = comma ? (size_t)(comma - csv) : strlen(csv);
        char entry[160];
        if (len == 0 || len >= sizeof(entry) || n >= max) return 0;
        memcpy(entry, csv, len);
        entry[len] = '\0';
        if (!zsb_parse_peer(entry, &out[n])) return 0;
        n++;
        csv = comma ? comma + 1 : csv + len;
    }
    return n;
}

/* The staging directory is the output's own parent — deliberately not a
 * separate argument. It keeps the leaf's shape at (source_root, output, peers),
 * and it means the transient .part/.journal files live under the same explicit
 * scratch path the operator already named for the result. */
static bool zsb_parent_dir(const char *path, char *out, size_t out_size)
{
    const char *slash = strrchr(path, '/');
#if defined(_WIN32)
    const char *back = strrchr(path, '\\');
    if (back && (!slash || back > slash)) slash = back;
#endif
    if (!slash || slash == path) return false;
    size_t len = (size_t)(slash - path);
    if (len == 0 || len >= out_size) return false;
    memcpy(out, path, len);
    out[len] = '\0';
    return true;
}

static const char *zsb_leaf(const char *path)
{
    const char *slash = strrchr(path, '/');
#if defined(_WIN32)
    const char *back = strrchr(path, '\\');
    if (back && (!slash || back > slash)) slash = back;
#endif
    return slash && slash[1] ? slash + 1 : NULL;
}

void zcl_native_handle_zcode_source_bundle_fetch(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *output = zsb_str(request->input, "output");
    struct rom_fetch_peer peers[SOURCE_BUNDLE_FETCH_MAX_PEERS];
    char staging[ZSB_PATH_MAX], staging_real[ZSB_PATH_MAX];
    uint8_t root[32];
    size_t npeers = zsb_parse_peers(request->input, peers,
                                    SOURCE_BUNDLE_FETCH_MAX_PEERS);
    if (!output || !zsb_root(request->input, root) || npeers == 0 ||
        !zcl_native_zcode_workspace_is_explicit_scratch(output) ||
        !zsb_parent_dir(output, staging, sizeof(staging)) ||
        !platform_directory_canonical_real(staging, staging_real,
                                           sizeof(staging_real))) {
        zsb_fail(reply, "BAD_SOURCE_BUNDLE_FETCH_INPUT", "validate",
                 "source_root, a non-empty comma-separated peers list of host:port entries, and an explicit scratch output path inside an existing directory are required");
        return;
    }

    const char *output_leaf = zsb_leaf(output);
    struct platform_directory_transaction output_directory;
    platform_directory_transaction_init(&output_directory);
    if (!output_leaf || !platform_directory_transaction_open(
            &output_directory, staging_real)) {
        zsb_fail(reply, "SOURCE_BUNDLE_OUTPUT_REFUSED", "validate",
                 "the scratch parent must be a private real directory");
        return;
    }

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    struct source_bundle_fetch_metrics metrics;
    enum source_bundle_fetch_result result = source_bundle_fetch(
        peers, npeers, root, staging_real, &wire, &wire_len, &metrics);
    if (result != SOURCE_BUNDLE_FETCH_OK) {
        /* No output file was ever opened — the fetch service is not told the
         * output path at all, so "materialized: 0" here is structural.
         * A candidate that ARRIVED and was refused reports the content
         * check's own reason ("tree-root-mismatch" for a substitution,
         * "bundle-limit" for a truncation, "compression-codec" for garbage);
         * collapsing those into one message would hide which attack ran. */
        zsb_fail(reply, "SOURCE_BUNDLE_FETCH_REFUSED", "fetch",
                 result == SOURCE_BUNDLE_FETCH_ERR_ROOT
                     ? vcs_source_bundle_result_string(metrics.last_refusal)
                     : source_bundle_fetch_result_string(result));
        platform_directory_transaction_close(&output_directory);
        return;
    }
    if (!zsb_write_child_exclusive(&output_directory, output_leaf, wire,
                                   wire_len)) {
        free(wire);
        platform_directory_transaction_close(&output_directory);
        zsb_fail(reply, "SOURCE_BUNDLE_OUTPUT_REFUSED", "fetch",
                 "output must be a new no-follow file in an existing scratch directory");
        return;
    }
    free(wire);
    platform_directory_transaction_close(&output_directory);
    zsb_render(&reply->data, root, &metrics.bundle);
    (void)json_push_kv_str(&reply->data, "output", output);
    (void)json_push_kv_int(&reply->data, "wire_bytes", (int64_t)wire_len);
    (void)json_push_kv_int(&reply->data, "peers_asked", metrics.peers_asked);
    (void)json_push_kv_int(&reply->data, "peers_offering",
                           metrics.peers_offering);
    (void)json_push_kv_int(&reply->data, "candidates_tried",
                           metrics.candidates_tried);
    (void)json_push_kv_int(&reply->data, "candidates_refused",
                           metrics.candidates_refused);
    (void)json_push_kv_bool(&reply->data, "fetched", true);
    (void)json_push_kv_bool(&reply->data, "verified", true);
    (void)json_push_kv_bool(&reply->data, "signer_required", false);
    (void)json_push_kv_bool(&reply->data, "accepted", false);
}

/* ── Publish: the same bundle, offered to peers ──────────────────────
 *
 * The half of the loop `create` never had. `create` writes transport to a
 * scratch path and stops; nothing about that file is where this node seeds
 * artifacts from, in the running node's registry, or in any directory listing
 * a peer reads. This leaf produces an OFFER instead of a file: it captures the
 * workspace, builds the bundle, lands it under the node's own seeded
 * directory, registers it BY NAME, and prints the one 64-hex string another
 * machine needs to pull it with `fetch`.
 *
 * IT RUNS IN THE NODE, over RPC, and that is not an implementation detail: the
 * artifact registry is the daemon's process memory, so a registration
 * performed in this one-shot CLI process would be a publish that offered
 * nothing (see app/controllers/src/source_bundle_publish_rpc.c). This handler
 * therefore parses, forwards, and refuses loudly when the node does not
 * answer — it never falls back to a local write that would look like success.
 *
 * The node picks the destination; the caller never names a path. `source_root`
 * is optional and is a PIN, not a selector: supply it and a workspace that
 * captures to a different tree is refused before anything is written. */

/* The RPC body's failure shape, mirroring the other forwarding handlers: a
 * bare string, an {"error":...} envelope, or a {code,message} pair. Returns
 * NULL when the body carries no error. */
static const char *zsb_rpc_error(const struct json_value *body)
{
    if (!body)
        return "missing response body";
    if (body->type == JSON_STR)
        return json_get_str(body);
    if (body->type != JSON_OBJ)
        return NULL;
    const struct json_value *error = json_get(body, "error");
    if (error && !json_is_null(error)) {
        if (error->type == JSON_STR)
            return json_get_str(error);
        if (error->type == JSON_OBJ)
            return json_get_str(json_get(error, "message"));
        return "the node returned an unstructured RPC error";
    }
    const struct json_value *code = json_get(body, "code");
    const struct json_value *message = json_get(body, "message");
    if (code && code->type == JSON_INT && message && message->type == JSON_STR)
        return json_get_str(message);
    return NULL;
}

/* Copy one key from the node's reply into the leaf's typed result, preserving
 * its JSON type. A key the node did not send is simply absent — the leaf never
 * invents a plausible zero for a field the node declined to report. */
static void zsb_carry(struct json_value *out, const struct json_value *body,
                      const char *key)
{
    const struct json_value *v = json_get(body, key);
    if (!v) return;
    if (v->type == JSON_STR)
        (void)json_push_kv_str(out, key, json_get_str(v));
    else if (v->type == JSON_INT)
        (void)json_push_kv_int(out, key, json_get_int(v));
    else if (v->type == JSON_BOOL)
        (void)json_push_kv_bool(out, key, json_get_bool(v));
}

void zcl_native_handle_zcode_source_bundle_publish(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *workspace = zsb_str(request->input, "workspace");
    const char *pin_hex = zsb_str(request->input, "source_root");
    char workspace_real[ZSB_PATH_MAX];
    uint8_t pinned[32];
    bool pin_ok = !pin_hex || !pin_hex[0] ||
        (strlen(pin_hex) == 64 && zcl_hex_decode_lower(pin_hex, pinned, 32));
    if (!workspace || !pin_ok ||
        !platform_directory_canonical_real(workspace, workspace_real,
                                           sizeof(workspace_real))) {
        zsb_fail(reply, "BAD_SOURCE_BUNDLE_PUBLISH_INPUT", "validate",
                 "workspace must resolve to a real directory, and source_root, when given, must be 64 lower-case hex characters");
        return;
    }

    struct rpc_arg_builder args;
    rpc_arg_builder_init(&args);
    rpc_arg_builder_push_str(&args, workspace_real);
    rpc_arg_builder_push_str(&args, pin_hex ? pin_hex : "");
    char *params_json = rpc_arg_builder_to_json(&args);
    if (!params_json) {
        zsb_fail(reply, "SOURCE_BUNDLE_PUBLISH_ARGS", "normalize",
                 "the publish parameters could not be encoded");
        return;
    }

    zcl_native_bridge_ensure_rpc();
    char *raw = node_rpc_call("sourcebundle_publish", params_json);
    free(params_json);
    if (!raw) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_TRANSIENT, "NODE_UNAVAILABLE",
                               "dispatch", true, false,
                               "no running node answered; a bundle can only be offered by the process that holds the file service",
                               "zcode.workspace.source.bundle");
        return;
    }
    struct json_value body;
    json_init(&body);
    bool parsed = json_read(&body, raw, strlen(raw));
    free(raw);
    const char *rpc_error = parsed ? zsb_rpc_error(&body) : "unparseable body";
    const struct json_value *status = parsed ? json_get(&body, "status") : NULL;
    const char *status_str =
        status && status->type == JSON_STR ? json_get_str(status) : NULL;
    if (rpc_error || !status_str || strcmp(status_str, "published") != 0) {
        const struct json_value *why = parsed ? json_get(&body, "result") : NULL;
        char detail[256];
        (void)snprintf(detail, sizeof(detail), "%s",
                       rpc_error ? rpc_error
                       : (why && why->type == JSON_STR
                              ? json_get_str(why)
                              : "the node did not report the bundle as offered"));
        json_free(&body);
        zsb_fail(reply, "SOURCE_BUNDLE_PUBLISH_REFUSED", "publish", detail);
        return;
    }

    /* Success means one thing only: the node's registry confirmed, by root,
     * that a chunk request for this artifact would be answered. Everything
     * below is that fact, restated for the operator. */
    zsb_carry(&reply->data, &body, "source_root");
    zsb_carry(&reply->data, &body, "artifact_digest");
    zsb_carry(&reply->data, &body, "filename");
    zsb_carry(&reply->data, &body, "path");
    zsb_carry(&reply->data, &body, "wire_bytes");
    zsb_carry(&reply->data, &body, "chunks");
    zsb_carry(&reply->data, &body, "file_service_port");
    zsb_carry(&reply->data, &body, "republished");
    zsb_carry(&reply->data, &body, "seed_directory_entries");
    zsb_carry(&reply->data, &body, "rescan_guaranteed");
    zsb_carry(&reply->data, &body, "source_bytes");
    zsb_carry(&reply->data, &body, "file_count");
    (void)json_push_kv_bool(&reply->data, "offered", true);
    (void)json_push_kv_bool(&reply->data, "git_required", false);
    (void)json_push_kv_bool(&reply->data, "signer_required", false);
    (void)json_push_kv_bool(&reply->data, "source_executed", false);
    (void)json_push_kv_bool(&reply->data, "accepted", false);
    const struct json_value *root_v = json_get(&body, "source_root");
    const struct json_value *port = json_get(&body, "file_service_port");
    const struct json_value *rescan = json_get(&body, "rescan_guaranteed");
    char next[512];
    (void)snprintf(next, sizeof(next),
        "another machine needs only this source_root: z23 zcode workspace "
        "source bundle fetch --input='{\"source_root\":\"%s\",\"output\":"
        "\"/tmp/source.zvsb\",\"peers\":\"NODE_ADDRESS:%lld\"}'",
        root_v && root_v->type == JSON_STR ? json_get_str(root_v) : "",
        (long long)(port && port->type == JSON_INT ? json_get_int(port) : 0));
    (void)json_push_kv_str(&reply->data, "next", next);
    if (rescan && rescan->type == JSON_BOOL && !json_get_bool(rescan))
        (void)json_push_kv_str(&reply->data, "durability_note",
            "this bundle is offered now, but the seeded directory holds more "
            "entries than the boot-time sweep examines, so a restart may stop "
            "offering it — re-run publish after a restart");
    json_free(&body);
    reply->error.mutated = true;
}

void zcl_native_handle_zcode_source_package_checkout(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *datadir = zsb_str(request->input, "datadir");
    const char *workspace = zsb_str(request->input, "workspace");
    const char *destination = zsb_str(request->input, "destination");
    char workspace_real[ZSB_PATH_MAX], destination_real[ZSB_PATH_MAX];
    uint8_t package_root[32], source_root[32], accepted_work_root[32];
    bool valid = datadir && workspace && destination &&
        zsb_named_root(request->input, "package_root", package_root) &&
        zsb_named_root(request->input, "accepted_work_root",
                       accepted_work_root) &&
        zsb_root(request->input, source_root) &&
        zcl_native_zcode_workspace_is_explicit_scratch(workspace) &&
        zcl_native_zcode_workspace_is_explicit_scratch(destination) &&
        platform_directory_canonical_real(
            workspace, workspace_real, sizeof(workspace_real)) &&
        platform_directory_canonical_real(
            destination, destination_real, sizeof(destination_real)) &&
        zsb_paths_disjoint(workspace_real, destination_real) &&
        zsb_empty_dir(destination_real);
    if (!valid) {
        zsb_fail(reply, "BAD_SOURCE_PACKAGE_CHECKOUT_INPUT", "validate",
                 "datadir, package_root, source_root, accepted_work_root, a separate scratch CAS workspace, and an existing empty scratch destination are required");
        return;
    }
    struct vcs_package_store *store = vcs_package_store_open(
        datadir, vcs_package_store_quota_bytes());
    if (!store) {
        zsb_fail(reply, "SOURCE_PACKAGE_STORE_REFUSED", "open",
                 "the existing content.v2 package store could not be opened");
        return;
    }
    struct vcs_source_package_checkout_metrics metrics;
    enum vcs_source_package_checkout_result result =
        vcs_source_package_checkout_accepted(
            store, package_root, source_root, accepted_work_root,
            workspace_real, destination_real, &metrics);
    vcs_package_store_close(store);
    if (result != VCS_SOURCE_PACKAGE_CHECKOUT_OK) {
        zsb_fail(reply, "SOURCE_PACKAGE_CHECKOUT_REFUSED", "checkout",
                 vcs_source_package_checkout_result_string(result));
        return;
    }
    zsb_render(&reply->data, source_root, &metrics.source);
    char package_hex[65];
    zcl_hex_encode(package_root, 32, package_hex);
    (void)json_push_kv_str(&reply->data, "package_root", package_hex);
    (void)json_push_kv_int(&reply->data, "source_shards",
                           metrics.source_shards);
    (void)json_push_kv_int(&reply->data, "offline_input_bytes",
                           (int64_t)metrics.offline_input_bytes);
    (void)json_push_kv_int(&reply->data, "offline_input_files",
                           metrics.offline_input_files);
    (void)json_push_kv_int(&reply->data, "carrier_files",
                           metrics.carrier_files);
    char accepted_hex[65], signer_hex[65];
    zcl_hex_encode(accepted_work_root, 32, accepted_hex);
    zcl_hex_encode(metrics.accepted_signer, 32, signer_hex);
    (void)json_push_kv_str(&reply->data, "accepted_work_root", accepted_hex);
    (void)json_push_kv_str(&reply->data, "accepted_signer", signer_hex);
    (void)json_push_kv_int(&reply->data, "authority_objects",
                           metrics.authority_objects);
    (void)json_push_kv_int(&reply->data, "work_receipts",
                           metrics.work_receipts);
    (void)json_push_kv_bool(&reply->data, "checked_out", true);
    (void)json_push_kv_str(&reply->data, "destination", destination_real);
}
