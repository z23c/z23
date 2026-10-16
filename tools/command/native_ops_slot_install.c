/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: ops.slot.install - the receiver half of the fleet binary swarm.
 *          A machine that fetched a release's bytes installs them as a z23
 *          slot ONLY when four facts hold together:
 *            1. the release doc is a valid, unexpired signed ZIDR record;
 *            2. its signer is an owner key the receiver PINNED (no pin, no
 *               install; there is no trust-on-first-use path here);
 *            3. the doc commits to the package root the bytes came from;
 *            4. the bytes of `from` match that package's manifest entry
 *               exactly (size and every SHA3 chunk).
 *          The copy is hashed again while it is written, so the bytes that
 *          reach the slot are the bytes that were verified, whatever
 *          happens to `from` in between. It uses no chain, no wallet and
 *          no ZCL, and starts no process.
 *
 * Layout: <slots>/<name>/z23, where <slots> is ZCL_BINARY_SLOTS_DIR or the
 * per-user zclassic23-slots directory the launcher reads
 * (tools/zcl-nodectl.c). The slot appears by link(2) of a fully written,
 * fsynced 0755 temp file: all-or-nothing, and never over an existing slot.
 */

#include "command/native_command.h"
#include "command/native_slot_common.h"
#include "command/release_pin.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "crypto/sha256.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/os_binary_slots.h"
#include "platform/time_compat.h"
#include "vcs/package_manifest.h"
#include "vcs/package_store.h"
#include "zid/zid.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(_WIN32)
/* Slot install needs POSIX descriptor-relative file semantics; fail closed. */
static void osi_execute(const struct zcl_command_request *request,
                        struct zcl_command_reply *reply)
{
    (void)request;
    if (reply)
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "UNSUPPORTED_PLATFORM",
                               "normalize", false, false,
                               "slot install needs POSIX file semantics",
                               "ops.slot.install");
}
#else

#define OSI_CMD "ops.slot.install"
#define OSI_SLOT_FILE "z23"

enum osi_pass { OSI_PASS_OK, OSI_PASS_IO, OSI_PASS_SIZE, OSI_PASS_CHUNK,
                OSI_PASS_CHANGED };
enum osi_slot_state { OSI_SLOT_ABSENT, OSI_SLOT_SAME, OSI_SLOT_DIFFERENT,
                      OSI_SLOT_UNSAFE };

struct osi {
    const char *release, *from, *name, *member, *datadir;
    bool dry_run;
    uint8_t package_root[32];
    struct zid_doc doc;
    struct zid_release rel;
    struct vcs_package_manifest manifest;
    const struct vcs_package_file *file;
    char slots[SLOT_PATH_MAX];
    char name_dir[SLOT_PATH_MAX];
    char final_path[SLOT_PATH_MAX];
    char tmp_path[SLOT_PATH_MAX];
    uint8_t sha[SHA256_OUTPUT_SIZE];
    uint64_t size;
};

static void osi_fail(struct zcl_command_reply *reply, const char *code,
                     const char *phase, const char *message,
                     const char *evidence, bool mutated)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, code, phase, false,
                           mutated, message, evidence);
}

static void osi_invalid(struct zcl_command_reply *reply, const char *code,
                        const char *message, const char *evidence)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, "normalize", false,
                           false, message, evidence);
}

static const char *osi_str(const struct json_value *in, const char *key)
{
    const struct json_value *v = json_get(in, key);
    const char *s = v ? json_get_str(v) : NULL;
    return (s && s[0]) ? s : NULL;
}

static bool osi_parse_inputs(const struct zcl_command_request *request,
                             struct osi *st, struct zcl_command_reply *reply)
{
    const struct json_value *in = request->input;
    const struct json_value *dry = json_get(in, "dry_run");
    st->release = osi_str(in, "release");
    st->from = osi_str(in, "from");
    st->name = osi_str(in, "name");
    st->member = osi_str(in, "member");
    st->datadir = osi_str(in, "datadir");
    st->dry_run = dry && dry->type == JSON_BOOL && json_get_bool(dry);
    if (!st->member)
        st->member = OSI_SLOT_FILE;
    if (!st->datadir)
        st->datadir = zcl_native_command_datadir();
    if (!st->release || !st->from || !st->name) {
        osi_invalid(reply, "MISSING_INPUT",
                    "ops slot install needs release=<the .zid doc>, "
                    "from=<the checked-out binary> and name=<slot name>",
                    OSI_CMD);
        return false;
    }
    if (!slot_name_ok(st->name)) {
        osi_invalid(reply, "BAD_SLOT_NAME",
                    "a slot name is 1-64 characters of a-z 0-9 . _ -, "
                    "not starting with - or .", st->name);
        return false;
    }
    if (!st->datadir) {
        osi_invalid(reply, "MISSING_DATADIR",
                    "no datadir given: the package manifest is read from the "
                    "local package store", OSI_CMD);
        return false;
    }
    return true;
}

static bool osi_resolve_paths(struct osi *st, struct zcl_command_reply *reply)
{
    struct slot_paths sp;
    enum slot_path_status ps = slot_paths_resolve(&sp, st->name);
    if (ps != SLOT_PATH_OK) {
        osi_invalid(reply,
                    ps == SLOT_PATH_NO_ROOT ? "NO_SLOTS_DIR"
                                            : "SLOT_PATH_TOO_LONG",
                    ps == SLOT_PATH_NO_ROOT
                        ? "cannot locate the slots directory: set "
                          "ZCL_BINARY_SLOTS_DIR to an absolute path or "
                          "ensure HOME is set"
                        : "the slots directory path is too long",
                    OSI_CMD);
        return false;
    }
    memcpy(st->slots, sp.slots, sizeof(st->slots));
    memcpy(st->name_dir, sp.name_dir, sizeof(st->name_dir));
    memcpy(st->final_path, sp.final_path, sizeof(st->final_path));
    memcpy(st->tmp_path, sp.tmp_path, sizeof(st->tmp_path));
    return true;
}

/* Steps 1-3: the signed record, the pin, the root. */
static bool osi_check_release(const struct zcl_command_request *request,
                              struct osi *st, struct zcl_command_reply *reply)
{
    const char *code = NULL;
    uint8_t root[32];
    char err[128];
    if (!release_pin_read_doc(st->release, &st->doc, &code)) {
        osi_invalid(reply, code, "the release doc could not be read as a "
                    "saved .zid (hex text)", st->release);
        return false;
    }
    if (!zid_release_verify(&st->doc, &st->rel,
                            (uint64_t)platform_time_wall_unix())) {
        osi_fail(reply, "RELEASE_INVALID", "execute",
                 "the release doc is expired, tampered, or not a release "
                 "record; `zcode release verify` names which", st->release,
                 false);
        return false;
    }
    if (!zcl_native_require_hex64("package_root",
                                  osi_str(request->input, "package_root"),
                                  root, err, sizeof(err))) {
        osi_invalid(reply, "BAD_ROOT", err, OSI_CMD);
        return false;
    }
    memcpy(st->package_root, root, sizeof(root));
    return release_pin_gate(request->input, true, st->doc.master_pubkey,
                            st->rel.manifest_root, reply, OSI_CMD);
}

/* Step 4a: the manifest for that root, from the local store. */
static bool osi_load_manifest(struct osi *st, struct zcl_command_reply *reply)
{
    uint8_t *wire = NULL, root[32];
    size_t wire_len = 0;
    struct vcs_package_store *store = vcs_package_store_open(
        st->datadir, vcs_package_store_quota_bytes());
    enum vcs_package_store_result r = store
        ? vcs_package_store_get_manifest_wire(store, st->package_root, &wire,
                                              &wire_len)
        : VCS_PACKAGE_STORE_ERR_IO;
    if (store)
        vcs_package_store_close(store);
    vcs_package_manifest_init(&st->manifest);
    bool ok = r == VCS_PACKAGE_STORE_OK &&
              vcs_package_manifest_parse(wire, wire_len, &st->manifest) &&
              vcs_package_manifest_root(&st->manifest, root) &&
              memcmp(root, st->package_root, 32) == 0;
    free(wire);
    if (!ok) {
        osi_fail(reply, "PACKAGE_MANIFEST_MISSING", "execute",
                 "the package manifest for that root is not in the local "
                 "store; fetch the package first (`zcode package fetch`)",
                 OSI_CMD, false);
        return false;
    }
    for (size_t i = 0; i < st->manifest.count && !st->file; i++)
        if (strcmp(st->manifest.files[i].path, st->member) == 0)
            st->file = &st->manifest.files[i];
    if (!st->file)
        osi_fail(reply, "MEMBER_NOT_IN_PACKAGE", "execute",
                 "the package manifest has no such file; pass member=<path "
                 "of the binary inside the package>", st->member, false);
    return st->file != NULL;
}

static bool osi_write_all(int fd, const uint8_t *buf, size_t len)
{
    while (len > 0) {
        ssize_t w = write(fd, buf, len);
        if (w < 0 && errno == EINTR)
            continue;
        if (w <= 0)
            return false;
        buf += w;
        len -= (size_t)w;
    }
    return true;
}

/* Read one chunk-sized block, retrying short reads. */
static ssize_t osi_read_block(int fd, uint8_t *buf, size_t want)
{
    size_t got = 0;
    while (got < want) {
        ssize_t r = read(fd, buf + got, want - got);
        if (r < 0 && errno == EINTR)
            continue;
        if (r < 0)
            return -1;
        if (r == 0)
            break;
        got += (size_t)r;
    }
    return (ssize_t)got;
}

/* True iff `fd` is at end of file. */
static bool osi_at_eof(int fd)
{
    uint8_t extra;
    return osi_read_block(fd, &extra, 1) == 0;
}

/* The chunk loop of a pass: every chunk is checked at its exact index,
 * hashed into ctx and (dst >= 0) written out. */
static enum osi_pass osi_pass_chunks(const struct osi *st, int fd, int dst,
                                     uint8_t *buf, size_t block,
                                     struct sha256_ctx *ctx)
{
    for (uint32_t i = 0; i < st->file->chunk_count; i++) {
        size_t want = (size_t)(st->file->size - (uint64_t)i * block);
        if (want > block)
            want = block;
        ssize_t got = osi_read_block(fd, buf, want);
        if (got < 0 || (size_t)got != want)
            return OSI_PASS_SIZE;
        if (!vcs_package_verify_chunk(st->file, i, buf, want))
            return OSI_PASS_CHUNK;
        if (dst >= 0 && !osi_write_all(dst, buf, want))
            return OSI_PASS_IO;
        sha256_write(ctx, buf, want);
    }
    return OSI_PASS_OK;
}

/* One pass over `from`: size, chunks and SHA-256 of the whole, optionally
 * copied to dst. When `expect` is non-NULL the digest must equal it (the
 * copy pass). */
static enum osi_pass osi_pass(const struct osi *st, int dst,
                              const uint8_t *expect, uint8_t sha_out[32])
{
    const size_t block = VCS_PACKAGE_CHUNK_BYTES;
    uint8_t *buf = zcl_malloc(block, "ops.slot.install.block");
    struct sha256_ctx ctx;
    struct stat sb;
    int fd = buf ? open(st->from, O_RDONLY | O_CLOEXEC | O_NOFOLLOW) : -1;
    enum osi_pass res = OSI_PASS_OK;
    if (fd < 0 || fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode)) {
        if (fd >= 0)
            close(fd);
        free(buf);
        return OSI_PASS_IO;
    }
    sha256_init(&ctx);
    if ((uint64_t)sb.st_size != st->file->size)
        res = OSI_PASS_SIZE;
    else
        res = osi_pass_chunks(st, fd, dst, buf, block, &ctx);
    if (res == OSI_PASS_OK && !osi_at_eof(fd))
        res = OSI_PASS_SIZE;
    close(fd);
    free(buf);
    sha256_finalize(&ctx, sha_out);
    if (res == OSI_PASS_OK && expect && memcmp(expect, sha_out, 32) != 0)
        res = OSI_PASS_CHANGED;
    return res;
}


static void osi_pass_fail(struct zcl_command_reply *reply, enum osi_pass p,
                          const char *from)
{
    if (p == OSI_PASS_IO)
        osi_fail(reply, "SOURCE_UNREADABLE", "execute",
                 "`from` cannot be read as a regular file (it must exist and "
                 "not be a symlink)", from, false);
    else if (p == OSI_PASS_CHANGED)
        osi_fail(reply, "SOURCE_CHANGED", "execute",
                 "`from` changed while it was being installed; nothing was "
                 "installed, run it again once the file is stable", from,
                 false);
    else
        osi_fail(reply, "BINARY_DIGEST_MISMATCH", "execute",
                 "the bytes of `from` are not the bytes this signed release "
                 "committed to (size or SHA3 chunk differs); nothing was "
                 "written", from, false);
}

static enum osi_slot_state osi_slot_state(const struct osi *st)
{
    struct stat sb;
    uint8_t sha[32];
    struct osi probe = *st;
    if (lstat(st->name_dir, &sb) != 0)
        return errno == ENOENT ? OSI_SLOT_ABSENT : OSI_SLOT_UNSAFE;
    if (!S_ISDIR(sb.st_mode))
        return OSI_SLOT_UNSAFE;
    if (lstat(st->final_path, &sb) != 0)
        return errno == ENOENT ? OSI_SLOT_ABSENT : OSI_SLOT_UNSAFE;
    if (!S_ISREG(sb.st_mode))
        return OSI_SLOT_UNSAFE;
    probe.from = st->final_path;
    enum osi_pass p = osi_pass(&probe, -1, NULL, sha);
    return p == OSI_PASS_OK && memcmp(sha, st->sha, 32) == 0
        ? OSI_SLOT_SAME : OSI_SLOT_DIFFERENT;
}

static bool osi_sync_dir(const char *path)
{
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    bool ok = fd >= 0 && fsync(fd) == 0;
    if (fd >= 0)
        close(fd);
    return ok;
}

/* Write the temp file: copy + re-hash, 0755, fsync. */
static enum osi_pass osi_stage(const struct osi *st)
{
    uint8_t sha[32];
    int fd = open(st->tmp_path,
                  O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0700);
    if (fd < 0)
        return OSI_PASS_IO;
    enum osi_pass p = osi_pass(st, fd, st->sha, sha);
    if (p == OSI_PASS_OK && (fchmod(fd, 0755) != 0 || fsync(fd) != 0))
        p = OSI_PASS_IO;
    if (close(fd) != 0 && p == OSI_PASS_OK)
        p = OSI_PASS_IO;
    if (p != OSI_PASS_OK)
        unlink(st->tmp_path);
    return p;
}

/* Make <slots>/<name>/ ; *created says whether this call made it. */
static bool osi_make_name_dir(const struct osi *st, bool *created)
{
    char err[OS_BINARY_SLOTS_ERROR_MAX];
    *created = false;
    if (!os_binary_slots_ensure_directory(st->slots, err, sizeof(err)))
        return false;
    if (mkdir(st->name_dir, 0700) == 0) {
        *created = true;
        return true;
    }
    return errno == EEXIST;
}

/* Publish the staged file without ever replacing an existing slot. */
static bool osi_publish(const struct osi *st, int *link_errno)
{
    *link_errno = 0;
    if (link(st->tmp_path, st->final_path) != 0) {
        *link_errno = errno;
        return false;
    }
    return true;
}

static void osi_install_fail(struct zcl_command_reply *reply, const char *why)
{
    osi_fail(reply, "SLOT_WRITE_FAILED", "execute",
             "the slot could not be written durably; no partial slot was "
             "left in place", why, true);
}

static bool osi_commit(struct osi *st, struct zcl_command_reply *reply,
                       bool *idempotent)
{
    bool created = false;
    int link_errno = 0;
    *idempotent = false;
    if (!osi_make_name_dir(st, &created)) {
        osi_install_fail(reply, "slot directory");
        return false;
    }
    enum osi_pass p = osi_stage(st);
    if (p != OSI_PASS_OK) {
        if (created)
            rmdir(st->name_dir);
        if (p == OSI_PASS_IO)
            osi_install_fail(reply, "stage");
        else
            osi_pass_fail(reply, p, st->from);
        return false;
    }
    bool linked = osi_publish(st, &link_errno);
    unlink(st->tmp_path);
    if (!linked && link_errno == EEXIST &&
        osi_slot_state(st) == OSI_SLOT_SAME) {
        *idempotent = true;
        return true;
    }
    if (!linked || !osi_sync_dir(st->name_dir) || !osi_sync_dir(st->slots)) {
        if (!linked && created)
            rmdir(st->name_dir);
        osi_install_fail(reply, linked ? "fsync" : "link");
        return false;
    }
    return true;
}

static void osi_reply(const struct osi *st, struct zcl_command_reply *reply,
                      bool installed, bool idempotent, int64_t elapsed_ms)
{
    char sha_hex[65], fp[RELEASE_PIN_FINGERPRINT_HEX + 1], slot[96];
    char pub[65];
    zcl_hex_encode(st->sha, 32, sha_hex);
    zcl_hex_encode(st->doc.master_pubkey, 32, pub);
    release_pin_fingerprint(st->doc.master_pubkey, fp);
    snprintf(slot, sizeof(slot), "%s/%s", st->name, OSI_SLOT_FILE);
    json_push_kv_str(&reply->data, "slot", slot);
    json_push_kv_str(&reply->data, "sha256", sha_hex);
    json_push_kv_int(&reply->data, "size", (int64_t)st->size);
    json_push_kv_str(&reply->data, "signer", fp);
    json_push_kv_str(&reply->data, "signer_pubkey", pub);
    json_push_kv_str(&reply->data, "release_name", st->rel.name);
    json_push_kv_str(&reply->data, "release_version", st->rel.version);
    json_push_kv_bool(&reply->data, "installed", installed);
    json_push_kv_bool(&reply->data, "idempotent", idempotent);
    json_push_kv_bool(&reply->data, "dry_run", st->dry_run);
    json_push_kv_int(&reply->data, "elapsed_ms", elapsed_ms);
    json_push_kv_int(&reply->data, "zcl_spent", 0);
    json_push_kv_str(&reply->data, "note",
                     st->dry_run
                         ? "dry run: every check passed and nothing was "
                           "written"
                         : "signed by a pinned owner key, bytes verified "
                           "chunk by chunk, installed atomically; no chain, "
                           "no ZCL");
}

/* Steps 4b-5: verify the bytes, judge the slot, then install. */
static bool osi_install(struct osi *st, struct zcl_command_reply *reply,
                        int64_t t0)
{
    bool idempotent = false;
    enum osi_pass p = osi_pass(st, -1, NULL, st->sha);
    st->size = st->file->size;
    if (p != OSI_PASS_OK) {
        osi_pass_fail(reply, p, st->from);
        return false;
    }
    enum osi_slot_state state = osi_slot_state(st);
    if (state == OSI_SLOT_UNSAFE || state == OSI_SLOT_DIFFERENT) {
        osi_fail(reply, state == OSI_SLOT_UNSAFE ? "SLOT_PATH_UNSAFE"
                                                 : "SLOT_EXISTS_DIFFERENT",
                 "execute",
                 state == OSI_SLOT_UNSAFE
                     ? "the slot path exists but is not a plain directory "
                       "holding a regular file; refusing to touch it"
                     : "a slot with this name already holds different "
                       "bytes; choose a new name, an installed slot is "
                       "never overwritten",
                 st->name, false);
        return false;
    }
    idempotent = state == OSI_SLOT_SAME;
    if (!st->dry_run && !idempotent && !osi_commit(st, reply, &idempotent))
        return false;
    osi_reply(st, reply, !st->dry_run && !idempotent, idempotent,
              platform_time_monotonic_ms() - t0);
    return true;
}

static void osi_execute(const struct zcl_command_request *request,
                        struct zcl_command_reply *reply)
{
    struct osi st;
    int64_t t0 = platform_time_monotonic_ms();
    memset(&st, 0, sizeof(st));
    if (osi_parse_inputs(request, &st, reply) &&
        osi_resolve_paths(&st, reply) &&
        osi_check_release(request, &st, reply) &&
        osi_load_manifest(&st, reply))
        (void)osi_install(&st, reply, t0);
    vcs_package_manifest_free(&st.manifest);
}

#endif /* _WIN32 */

void zcl_native_handle_ops_slot_install(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    osi_execute(request, reply);
}
