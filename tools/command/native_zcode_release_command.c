/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native handlers for the `zcode release` tree — Sovereign Registry v1:
 * sign and verify zid release records (docs/spec/sovereign-identity-
 * layer.md). A release record is the canonical zid_doc body ("ZIDR" ‖
 * name ‖ version ‖ manifest_root) binding a package release to an
 * identity's master ed25519 key (contexts/wallet/modules/zid). v1 is file-based only: no DB,
 * no swarm distribution — sign writes <datadir>/zcode/releases/
 * <name>-<version>.zid, verify reads a doc from hex or file.
 *
 * Domain batching: anchor folds every doc under the releases dir into
 * the zid anchor-domain tree — the record digest of each doc is
 * SHA3-256 of its canonical wire bytes (zid_record_digest), digests are
 * sorted by bytes before appending so the same dir contents ALWAYS fold
 * to the same domain root — and anchors that root on-chain exactly like
 * core.epoch.anchor (anchor_publish RPC when a live node answers, else
 * op_return_hex + a next-step note). prove emits the zid_proof wire hex
 * for one release; verify --proof=<hex> --root=<hex> checks inclusion
 * separately from signature validity. The batch root is time-independent
 * by construction: docs are digested as wire bytes, never re-verified
 * against the clock.
 *
 * DURABLE DOMAINS (schema v38, models/zid_domain.h). anchor records the
 * sorted leaf set + the root it folds to in zid_domains/zid_domain_leaves
 * BEFORE any chain write, and prove reads that stored leaf set. Adding or
 * deleting a .zid file therefore no longer silently changes what a
 * previously-issued proof means: the anchored leaf set is on disk, and a
 * re-fold to a different root visibly clears the domain's anchor rather
 * than letting a new batch wear the old txid. Domains are named
 * (--domain, default "zcode") so zdesc/zdir/third-party registries
 * coexist, each anchoring at its own cadence. prove falls back to a
 * directory fold ONLY for a domain that has never been anchored, and
 * says so in `source`.
 *
 * Secret hygiene (sign): the seed file must be exactly 64 hex chars and
 * 0600/0400 perms (refused otherwise, with the chmod hint); the seed
 * buffer is memory_cleanse'd after use and is NEVER logged or echoed. */

#include "command/native_command.h"

#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "controllers/rpc_client.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "models/database.h"
#include "models/zid_domain.h"
#include "models/zid_identity.h"
#if defined(_WIN32)
#include "platform/directory_transaction.h"
#include "platform/positioned_file.h"
#endif
#include "platform/time_compat.h"
#include "support/cleanse.h"
#include "zanc/zanc.h"
#include "zid/zid.h"

#include <sqlite3.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <process.h>
#endif
#include <sys/stat.h>
#include <unistd.h>

/* ── small input helpers (native_zcode_command.c shape) ────────────── */

static const char *zr_input_str(const struct json_value *input,
                                const char *key)
{
    const struct json_value *v = json_get(input, key);
    return v ? json_get_str(v) : NULL;
}

static const char *zr_datadir(const struct zcl_command_request *request)
{
    const char *dd = zr_input_str(request->input, "datadir");
    if (dd && dd[0])
        return dd;
    dd = zcl_native_command_datadir();
    return (dd && dd[0]) ? dd : NULL;
}

#if defined(_WIN32)
static bool zr_snapshot_same(const struct platform_positioned_file_snapshot *a,
                             const struct platform_positioned_file_snapshot *b)
{
    return a->size == b->size && a->volume == b->volume &&
           a->file_low == b->file_low && a->file_high == b->file_high &&
           a->modified_seconds == b->modified_seconds &&
           a->modified_nanoseconds == b->modified_nanoseconds &&
           a->changed_seconds == b->changed_seconds &&
           a->changed_nanoseconds == b->changed_nanoseconds;
}

static bool zr_read_stable(const char *path, void *bytes, size_t cap,
                           size_t *size_out, bool require_private)
{
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    bool ok = platform_positioned_file_open(&file, path) &&
              (!require_private || platform_positioned_file_is_private(&file)) &&
              platform_positioned_file_snapshot(&file, &before) &&
              before.size <= cap;
    int64_t got = ok ? platform_positioned_file_read(
                           &file, bytes, (size_t)before.size, 0) : -1;
    ok = ok && got >= 0 && (uint64_t)got == before.size &&
         platform_positioned_file_snapshot(&file, &after) &&
         zr_snapshot_same(&before, &after);
    platform_positioned_file_close(&file);
    if (ok && size_out)
        *size_out = (size_t)before.size;
    return ok;
}
#endif

/* ── anchor domain (durable leaf set, models/zid_domain.h) ─────────── */

#define ZR_DOMAIN_DEFAULT "zcode"

/* Resolve --domain (default "zcode") and enforce the stored name shape:
 * 1..ZID_DOMAIN_NAME_MAX lowercase alphanumerics and hyphens, the same
 * rule db_zid_domain_validate applies. NULL on a rejected name. */
static const char *zr_domain(const struct json_value *in)
{
    const char *d = zr_input_str(in, "domain");
    if (!d || !d[0])
        return ZR_DOMAIN_DEFAULT;
    size_t n = strlen(d);
    if (n > ZID_DOMAIN_NAME_MAX)
        return NULL;
    for (size_t i = 0; i < n; i++) {
        char c = d[i];
        bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
        if (!ok)
            return NULL;
    }
    return d;
}

/* WRITE path — `zcode.release.anchor` (ZCL_COMMAND_READY_COMMAND) ONLY.
 *
 * node_db_open() is the BOOT ceremony: READWRITE|CREATE, then create_schema
 * + node_db_migrate, a rename() quarantine of node.db when PRAGMA
 * quick_check fails, and the snapshot_staging DELETEs. `anchor` stores the
 * folded leaf set, so it legitimately needs a writable store and accepts
 * that ceremony. A READ leaf must NOT come here — `datadir` is
 * caller-supplied and falls back to the operator's live node, so a read
 * leaf run with no arguments would perform every one of those writes on it.
 * Read leaves use zcl_native_node_db_require_readonly instead. */
static bool zr_open_ndb(const char *datadir, struct node_db *ndb,
                        struct zcl_command_reply *reply, const char *leaf)
{
    char path[1100];
    int n = snprintf(path, sizeof(path), "%s/node.db", datadir);
    if (n <= 0 || (size_t)n >= sizeof(path)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "datadir path too long", leaf);
        return false;
    }
    memset(ndb, 0, sizeof(*ndb));
    if (!node_db_open(ndb, path) || !ndb->open) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "DOMAIN_STORE",
                               "execute", true, false,
                               "node.db (the anchor-domain store) failed to "
                               "open — check --datadir is writable, or boot "
                               "the node once to create it", path);
        return false;
    }
    return true;
}

/* ── seed loading ──────────────────────────────────────────────────── */

/* Read exactly 32 seed bytes from a 64-hex-char file. Accepts one
 * trailing newline (echo > file). Refuses any other size and any perm
 * bits beyond 0600/0400. The 64-byte hex buffer is cleansed before
 * return (caller cleanses `seed_out`). Never logs content. */
static bool zr_read_seed(const char *path, uint8_t seed_out[32],
                         char *err, size_t err_size)
{
#if defined(_WIN32)
    uint8_t raw[65];
    size_t raw_size = 0;
    if (!zr_read_stable(path, raw, sizeof(raw), &raw_size, true)) {
        snprintf(err, err_size,
                 "seed file must be a private, stable 64-hex file");
        return false;
    }
    ssize_t n = (ssize_t)raw_size;
#else
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        snprintf(err, err_size, "cannot open seed file: %s", strerror(errno));
        return false;
    }
    struct stat st;
    if (fstat(fd, &st) != 0) {
        snprintf(err, err_size, "cannot stat seed file: %s", strerror(errno));
        close(fd);
        return false;
    }
    unsigned perms = (unsigned)(st.st_mode & 0777u);
    if (perms != 0600u && perms != 0400u) {
        snprintf(err, err_size,
                 "seed file perms are %03o — a master seed must be 0600 "
                 "(chmod 600 %s)", perms, path);
        close(fd);
        return false;
    }
    uint8_t raw[65]; /* 64 hex + optional one trailing newline */
    ssize_t n = read(fd, raw, sizeof(raw));
    close(fd);
#endif
    if (n < 64) {
        snprintf(err, err_size,
                 "seed file must be exactly 64 hex chars (read %zd bytes)", n);
        return false;
    }
    if (n != 64 && !(n == 65 && raw[64] == '\n')) {
        snprintf(err, err_size,
                 "seed file must be exactly 64 hex chars (read %zd bytes)", n);
        memory_cleanse(raw, sizeof(raw));
        return false;
    }
    char hex[65];
    memcpy(hex, raw, 64);
    hex[64] = '\0';
    memory_cleanse(raw, sizeof(raw));
    bool ok = IsHex(hex) && ParseHex(hex, seed_out, 32) == 32;
    memory_cleanse(hex, sizeof(hex));
    if (!ok)
        snprintf(err, err_size, "seed file is not 64 hex chars");
    return ok;
}

/* ── doc file I/O ──────────────────────────────────────────────────── */

static bool zr_write_doc_file(const char *datadir, const char *name,
                              const char *version, const char *doc_hex,
                              char *path_out, size_t path_size,
                              char *err, size_t err_size)
{
#if defined(_WIN32)
    struct platform_directory_transaction root, zcode, releases;
    struct platform_directory_child staged;
    platform_directory_transaction_init(&root);
    platform_directory_transaction_init(&zcode);
    platform_directory_transaction_init(&releases);
    platform_directory_child_init(&staged);
    char leaf[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u];
    int leaf_n = snprintf(leaf, sizeof(leaf), "%s-%s.zid", name, version);
    int path_n = snprintf(path_out, path_size, "%s/zcode/releases/%s",
                          datadir, leaf);
    bool ok = leaf_n > 0 && (size_t)leaf_n < sizeof(leaf) &&
        path_n > 0 && (size_t)path_n < path_size &&
        platform_directory_transaction_open(&root, datadir) &&
        platform_directory_transaction_open_child(&root, "zcode", true,
                                                  &zcode) ==
            PLATFORM_DIRECTORY_OK &&
        platform_directory_transaction_open_child(&zcode, "releases", true,
                                                  &releases) ==
            PLATFORM_DIRECTORY_OK;
    char staged_leaf[64];
    int staged_n = snprintf(staged_leaf, sizeof(staged_leaf),
                            ".release.%ld.tmp", (long)_getpid());
    bool staged_created = false;
    size_t len = strlen(doc_hex);
    ok = ok && staged_n > 0 && (size_t)staged_n < sizeof(staged_leaf) &&
        platform_directory_child_create(&releases, staged_leaf, &staged) &&
        (staged_created = true) &&
        platform_directory_child_write_exact(&staged, doc_hex, len, 0) &&
        platform_directory_child_write_exact(&staged, "\n", 1, len) &&
        platform_directory_child_flush(&staged) &&
        platform_directory_child_replace(&releases, &staged, leaf, false) &&
        platform_directory_transaction_flush(&releases);
    platform_directory_child_close(&staged);
    if (!ok && staged_created)
        (void)platform_directory_child_unlink(&releases, staged_leaf, true);
    platform_directory_transaction_close(&releases);
    platform_directory_transaction_close(&zcode);
    platform_directory_transaction_close(&root);
    if (!ok) {
        snprintf(err, err_size, "atomic release write failed");
        return false;
    }
    return true;
#else
    char dir[1024];
    int n = snprintf(dir, sizeof(dir), "%s/zcode", datadir);
    if (n <= 0 || (size_t)n >= sizeof(dir))
        goto too_long;
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        snprintf(err, err_size, "mkdir %s: %s", dir, strerror(errno));
        return false;
    }
    n = snprintf(dir, sizeof(dir), "%s/zcode/releases", datadir);
    if (n <= 0 || (size_t)n >= sizeof(dir))
        goto too_long;
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        snprintf(err, err_size, "mkdir %s: %s", dir, strerror(errno));
        return false;
    }
    n = snprintf(path_out, path_size, "%s/%s-%s.zid", dir, name, version);
    if (n <= 0 || (size_t)n >= path_size)
        goto too_long;
    int fd = open(path_out, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        snprintf(err, err_size, "open %s: %s", path_out, strerror(errno));
        return false;
    }
    size_t len = strlen(doc_hex);
    ssize_t w = write(fd, doc_hex, len);
    ssize_t w2 = (w == (ssize_t)len) ? write(fd, "\n", 1) : -1;
    close(fd);
    if (w != (ssize_t)len || w2 != 1) {
        snprintf(err, err_size, "write %s: %s", path_out, strerror(errno));
        return false;
    }
    return true;
too_long:
    snprintf(err, err_size, "path too long under datadir");
    return false;
#endif
}

/* ── release batch (domain tree over the releases dir) ───────────── */

/* One batch is one domain leaf set, so the two caps are the same number
 * by construction: a batch that loads always stores. */
#define ZR_BATCH_MAX ZID_DOMAIN_LEAVES_MAX

struct zr_batch_entry {
    uint8_t digest[32]; /* zid_record_digest of the doc's wire bytes */
    char name[ZID_RELEASE_NAME_MAX + 1];
    char version[ZID_RELEASE_VERSION_MAX + 1];
};

static int zr_entry_cmp(const void *a, const void *b)
{
    return memcmp(((const struct zr_batch_entry *)a)->digest,
                  ((const struct zr_batch_entry *)b)->digest, 32);
}

/* Scan <datadir>/zcode/releases for *.zid docs, decode each, and compute
 * its record digest. Entries come back sorted by digest bytes — THE
 * canonical order, so the same dir contents always fold to the same
 * domain root. Docs are digested as wire bytes and NOT re-verified
 * against the clock: the batch root must stay reproducible after a doc's
 * expiry passes. A *.zid file that does not decode as a well-formed zid
 * release doc is a hard error naming the file (the dir is managed by
 * zcode.release.sign, which only writes valid docs); non-.zid entries
 * are ignored. A missing releases dir is 0 releases, not an error.
 * Returns the entry count, or (size_t)-1 with `err` filled. */
static size_t zr_batch_load(const char *datadir,
                            struct zr_batch_entry *entries, size_t cap,
                            char *err, size_t err_size)
{
    char dir[1024];
    int n = snprintf(dir, sizeof(dir), "%s/zcode/releases", datadir);
    if (n <= 0 || (size_t)n >= sizeof(dir)) {
        snprintf(err, err_size, "path too long under datadir");
        return (size_t)-1;
    }
#if defined(_WIN32)
    struct platform_directory_transaction root, zcode, releases;
    struct platform_directory_names names = {0};
    platform_directory_transaction_init(&root);
    platform_directory_transaction_init(&zcode);
    platform_directory_transaction_init(&releases);
    if (!platform_directory_transaction_open(&root, datadir)) {
        snprintf(err, err_size, "unsafe datadir for release scan");
        return (size_t)-1;
    }
    enum platform_directory_result opened =
        platform_directory_transaction_open_child(&root, "zcode", false,
                                                  &zcode);
    if (opened == PLATFORM_DIRECTORY_MISSING) {
        platform_directory_transaction_close(&root);
        return 0;
    }
    if (opened != PLATFORM_DIRECTORY_OK) {
        snprintf(err, err_size, "unsafe zcode directory");
        platform_directory_transaction_close(&root);
        return (size_t)-1;
    }
    opened = platform_directory_transaction_open_child(&zcode, "releases",
                                                       false, &releases);
    if (opened == PLATFORM_DIRECTORY_MISSING) {
        platform_directory_transaction_close(&zcode);
        platform_directory_transaction_close(&root);
        return 0;
    }
    if (opened != PLATFORM_DIRECTORY_OK ||
        !platform_directory_transaction_list_regular(&releases, &names)) {
        snprintf(err, err_size, "unsafe releases directory");
        platform_directory_transaction_close(&releases);
        platform_directory_transaction_close(&zcode);
        platform_directory_transaction_close(&root);
        return (size_t)-1;
    }
    size_t count = 0;
    for (size_t i = 0; i < names.count; i++) {
        const char *fn = names.items[i];
        size_t fl = strlen(fn);
        if (fl < 5 || strcmp(fn + fl - 4, ".zid") != 0)
            continue;
        if (count == cap) {
            snprintf(err, err_size, "more than %zu releases under %s", cap,
                     dir);
            count = (size_t)-1;
            break;
        }
        struct platform_directory_child file;
        struct platform_directory_child_info before, after;
        platform_directory_child_init(&file);
        char hex[ZID_DOC_MAX * 2 + 2];
        bool read_ok = platform_directory_child_open(&releases, fn, &file) &&
            platform_directory_child_info(&file, &before) &&
            before.size > 0 && before.size < sizeof(hex) &&
            platform_directory_child_read_exact(&file, hex,
                                                (size_t)before.size, 0) &&
            platform_directory_child_info(&file, &after) &&
            before.volume == after.volume && before.file_low == after.file_low &&
            before.file_high == after.file_high && before.size == after.size &&
            before.modified_seconds == after.modified_seconds &&
            before.modified_nanoseconds == after.modified_nanoseconds &&
            before.changed_seconds == after.changed_seconds &&
            before.changed_nanoseconds == after.changed_nanoseconds;
        platform_directory_child_close(&file);
        if (!read_ok) {
            snprintf(err, err_size, "%s: empty, unstable or unreadable", fn);
            count = (size_t)-1;
            break;
        }
        size_t rn = (size_t)before.size;
        while (rn > 0 && (hex[rn - 1] == '\n' || hex[rn - 1] == '\r' ||
                          hex[rn - 1] == ' '))
            rn--;
        hex[rn] = '\0';
        if ((rn & 1u) != 0 || !IsHex(hex)) {
            snprintf(err, err_size, "%s: not even-length hex", fn);
            count = (size_t)-1;
            break;
        }
        uint8_t wire[ZID_DOC_MAX];
        size_t wire_len = (size_t)ParseHex(hex, wire, sizeof(wire));
        struct zid_doc doc;
        struct zid_release rel;
        if (wire_len == 0 || !zid_doc_decode(&doc, wire, wire_len) ||
            !zid_release_decode_body(&rel, doc.body, doc.body_len)) {
            snprintf(err, err_size, "%s: not a well-formed release doc", fn);
            count = (size_t)-1;
            break;
        }
        struct zr_batch_entry *e = &entries[count++];
        zid_record_digest(e->digest, wire, wire_len);
        snprintf(e->name, sizeof(e->name), "%s", rel.name);
        snprintf(e->version, sizeof(e->version), "%s", rel.version);
    }
    platform_directory_names_free(&names);
    platform_directory_transaction_close(&releases);
    platform_directory_transaction_close(&zcode);
    platform_directory_transaction_close(&root);
    if (count == (size_t)-1)
        return count;
#else
    DIR *d = opendir(dir);
    if (!d) {
        if (errno == ENOENT)
            return 0;
        snprintf(err, err_size, "opendir %s: %s", dir, strerror(errno));
        return (size_t)-1;
    }
    size_t count = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        const char *fn = ent->d_name;
        size_t fl = strlen(fn);
        if (fl < 5 || strcmp(fn + fl - 4, ".zid") != 0)
            continue;
        if (count == cap) {
            snprintf(err, err_size,
                     "more than %zu releases under %s — split the batch",
                     cap, dir);
            closedir(d);
            return (size_t)-1;
        }
        char path[1200];
        int pn = snprintf(path, sizeof(path), "%s/%s", dir, fn);
        if (pn <= 0 || (size_t)pn >= sizeof(path)) {
            snprintf(err, err_size, "path too long under %s", dir);
            closedir(d);
            return (size_t)-1;
        }
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            snprintf(err, err_size, "open %s: %s", path, strerror(errno));
            closedir(d);
            return (size_t)-1;
        }
        char hex[ZID_DOC_MAX * 2 + 2];
        ssize_t rn = read(fd, hex, sizeof(hex) - 1);
        close(fd);
        if (rn <= 0) {
            snprintf(err, err_size, "%s: empty or unreadable", path);
            closedir(d);
            return (size_t)-1;
        }
        while (rn > 0 && (hex[rn - 1] == '\n' || hex[rn - 1] == '\r' ||
                          hex[rn - 1] == ' '))
            rn--;
        hex[rn] = '\0';
        if ((rn & 1) != 0 || !IsHex(hex)) {
            snprintf(err, err_size, "%s: not even-length hex", path);
            closedir(d);
            return (size_t)-1;
        }
        uint8_t wire[ZID_DOC_MAX];
        size_t wire_len = (size_t)ParseHex(hex, wire, sizeof(wire));
        struct zid_doc doc;
        if (wire_len == 0 || !zid_doc_decode(&doc, wire, wire_len)) {
            snprintf(err, err_size, "%s: not a well-formed zid doc", path);
            closedir(d);
            return (size_t)-1;
        }
        struct zr_batch_entry *e = &entries[count];
        struct zid_release rel;
        if (!zid_release_decode_body(&rel, doc.body, doc.body_len)) {
            snprintf(err, err_size, "%s: doc body is not a ZIDR release "
                     "record", path);
            closedir(d);
            return (size_t)-1;
        }
        zid_record_digest(e->digest, wire, wire_len);
        snprintf(e->name, sizeof(e->name), "%s", rel.name);
        snprintf(e->version, sizeof(e->version), "%s", rel.version);
        count++;
    }
    closedir(d);
#endif
    qsort(entries, count, sizeof(entries[0]), zr_entry_cmp);
    return count;
}

/* Tip for the anchor label: explicit input `tip` wins (deterministic
 * testing), else the live node's getblockcount, else 0 (offline — the
 * label height is informational; the anchored digest is the truth). */
static int64_t zr_anchor_tip(const struct json_value *in)
{
    const struct json_value *tv = json_get(in, "tip");
    if (tv && tv->type == JSON_INT && json_get_int(tv) >= 0)
        return json_get_int(tv);
    zcl_native_bridge_ensure_rpc();
    char *raw = node_rpc_call("getblockcount", NULL);
    if (!raw)
        return 0;
    int64_t tip = 0;
    struct json_value v;
    if (json_read(&v, raw, strlen(raw))) {
        if (v.type == JSON_INT && json_get_int(&v) >= 0)
            tip = json_get_int(&v);
        json_free(&v);
    }
    free(raw);
    return tip;
}

/* A node_rpc_call body that is an error, not a result: the transport's
 * own {"error":{...}} envelope, the extracted JSON-RPC error value
 * ({"code":int,"message":str}), or a bare string (the RPC handler's
 * error message, e.g. anchor_publish's "Missing file or digest").
 * Returns the best human message (into msg, when non-NULL). */
static bool zr_rpc_body_error(const struct json_value *v, char *msg,
                              size_t msg_size)
{
    const char *m = NULL;
    if (v->type == JSON_STR) {
        m = json_get_str(v);
    } else if (v->type == JSON_OBJ) {
        const struct json_value *err = json_get(v, "error");
        if (err && err->type != JSON_NULL) {
            const struct json_value *em =
                err->type == JSON_OBJ ? json_get(err, "message") : NULL;
            m = (em && em->type == JSON_STR) ? json_get_str(em)
                                             : "node RPC error";
        } else {
            const struct json_value *code = json_get(v, "code");
            const struct json_value *msg_v = json_get(v, "message");
            if (code && code->type == JSON_INT && msg_v &&
                msg_v->type == JSON_STR)
                m = json_get_str(msg_v);
        }
    }
    if (m && msg)
        snprintf(msg, msg_size, "%s", m);
    return m != NULL;
}

/* Peel the contiguous digest array out of the sorted entries (the tree
 * prove/root helpers take [][32]). */
static uint8_t (*zr_batch_digests(const struct zr_batch_entry *entries,
                                  size_t count))[32]
{
    uint8_t(*digests)[32] = zcl_malloc(count * 32, "zcode_release.digests");
    if (!digests)
        return NULL;
    for (size_t i = 0; i < count; i++)
        memcpy(digests[i], entries[i].digest, 32);
    return digests;
}

/* ── zcode.release.sign ────────────────────────────────────────────── */

void zcl_native_handle_zcode_release_sign(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const struct json_value *in = request->input;

    const char *name = zr_input_str(in, "name");
    if (!name || !name[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_NAME",
                               "normalize", false, false,
                               "missing name — the package name this release "
                               "binds (1..64 printable ASCII)",
                               "zcode.release.sign");
        return;
    }
    const char *version = zr_input_str(in, "version");
    if (!version || !version[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_VERSION",
                               "normalize", false, false,
                               "missing version — e.g. \"1.0.0\" (1..32 "
                               "printable ASCII)",
                               "zcode.release.sign");
        return;
    }
    const char *root_hex = zr_input_str(in, "root");
    if (!root_hex || strlen(root_hex) != 64 || !IsHex(root_hex)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_ROOT",
                               "normalize", false, false,
                               "root must be the 64-hex manifest root — get "
                               "it from `zcode package publish plan`",
                               "zcode.release.sign");
        return;
    }
    const char *seed_file = zr_input_str(in, "seed_file");
    if (!seed_file || !seed_file[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_SEED_FILE",
                               "normalize", false, false,
                               "missing seed_file — path to a 0600 file "
                               "holding the 64-hex master seed",
                               "zcode.release.sign");
        return;
    }

    int64_t seq = json_get_int_or(in, "seq", 1);
    if (seq < 0) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_SEQ",
                               "normalize", false, false,
                               "seq must be >= 0 (monotonic per identity — a "
                               "newer release must use a strictly higher seq)",
                               "zcode.release.sign");
        return;
    }
    int64_t expiry = json_get_int_or(in, "expiry", 0);
    if (expiry == 0)
        expiry = platform_time_wall_unix() + 365 * 86400;

    struct zid_release rel;
    memset(&rel, 0, sizeof(rel));
    snprintf(rel.name, sizeof(rel.name), "%s", name);
    snprintf(rel.version, sizeof(rel.version), "%s", version);
    if (ParseHex(root_hex, rel.manifest_root, 32) != 32) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_ROOT",
                               "normalize", false, false,
                               "root is not decodable 64-hex",
                               "zcode.release.sign");
        return;
    }
    if (strlen(name) > ZID_RELEASE_NAME_MAX ||
        strlen(version) > ZID_RELEASE_VERSION_MAX) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "FIELD_TOO_LONG",
                               "normalize", false, false,
                               "name exceeds 64 or version exceeds 32 chars",
                               "zcode.release.sign");
        return;
    }

    uint8_t seed[32];
    char err[512];
    if (!zr_read_seed(seed_file, seed, err, sizeof(err))) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_SEED_FILE",
                               "normalize", false, false, err, seed_file);
        return;
    }

    struct zid_doc doc;
    bool signed_ok = zid_release_sign(&doc, &rel, (uint64_t)seq,
                                      (uint64_t)expiry, seed);
    memory_cleanse(seed, sizeof(seed));
    if (!signed_ok) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "SIGN_FAILED",
                               "execute", false, false,
                               "zid_release_sign failed (name/version not "
                               "printable ASCII?)", name);
        return;
    }

    uint8_t wire[ZID_DOC_MAX];
    size_t wire_len = zid_doc_encode(wire, sizeof(wire), &doc);
    if (wire_len == 0) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ENCODE_FAILED",
                               "serialize", false, false,
                               "zid_doc_encode failed", name);
        return;
    }
    char doc_hex[ZID_DOC_MAX * 2 + 1];
    HexStr(wire, wire_len, false, doc_hex, sizeof(doc_hex));

    char pk_hex[65];
    HexStr(doc.master_pubkey, 32, false, pk_hex, sizeof(pk_hex));

    /* Persist under <datadir>/zcode/releases/ (best-effort but reported:
     * a sign that cannot persist still returns the doc hex, with the
     * save error named). */
    char saved_path[1200];
    bool saved = false;
    char save_err[512] = {0};
    const char *datadir = zr_datadir(request);
    if (datadir)
        saved = zr_write_doc_file(datadir, rel.name, rel.version, doc_hex,
                                  saved_path, sizeof(saved_path),
                                  save_err, sizeof(save_err));

    json_push_kv_str(&reply->data, "doc_hex", doc_hex);
    json_push_kv_str(&reply->data, "master_pubkey", pk_hex);
    json_push_kv_str(&reply->data, "name", rel.name);
    json_push_kv_str(&reply->data, "version", rel.version);
    char root_out[65];
    HexStr(rel.manifest_root, 32, false, root_out, sizeof(root_out));
    json_push_kv_str(&reply->data, "manifest_root", root_out);
    json_push_kv_int(&reply->data, "seq", seq);
    json_push_kv_int(&reply->data, "expiry", expiry);
    json_push_kv_int(&reply->data, "doc_bytes", (int64_t)wire_len);
    json_push_kv_bool(&reply->data, "saved", saved);
    if (saved)
        json_push_kv_str(&reply->data, "saved_path", saved_path);
    else if (datadir)
        json_push_kv_str(&reply->data, "save_error", save_err);
    else
        json_push_kv_str(&reply->data, "save_error",
                         "no datadir resolved — pass --datadir to persist "
                         "the doc under <datadir>/zcode/releases/");
    json_push_kv_str(&reply->data, "next",
                     "distribute doc_hex to verifiers; anyone can check it "
                     "with `z23 zcode release verify --doc=<hex>`");
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

/* ── chain-rooted key trust (`--anchored`) ─────────────────────────── */

/* True iff the flag is set: a bare `--anchored` arrives as JSON true, an
 * explicit --anchored=true/1 as a bool or string. */
static bool zr_flag_set(const struct json_value *input, const char *key)
{
    const struct json_value *v = json_get(input, key);
    if (!v)
        return false;
    if (v->type == JSON_BOOL)
        return json_get_bool(v);
    if (v->type == JSON_INT)
        return json_get_int(v) != 0;
    if (v->type == JSON_STR) {
        const char *s = json_get_str(v);
        return s && (strcmp(s, "true") == 0 || strcmp(s, "1") == 0 ||
                     strcmp(s, "yes") == 0 || s[0] == '\0');
    }
    return false;
}

/* ── zcode.release.verify ──────────────────────────────────────────── */

void zcl_native_handle_zcode_release_verify(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const struct json_value *in = request->input;

    const char *doc_hex = zr_input_str(in, "doc");
    const char *file = zr_input_str(in, "file");
    if ((!doc_hex || !doc_hex[0]) && (!file || !file[0])) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DOC",
                               "normalize", false, false,
                               "give --doc=<hex> (from zcode release sign) "
                               "or --file=<path to a saved .zid>",
                               "zcode.release.verify");
        return;
    }

    /* Optional domain-batch inclusion check: --proof and --root must be
     * given together (proof from `zcode release prove`, root from the
     * on-chain anchored domain root). */
    const char *proof_hex = zr_input_str(in, "proof");
    const char *root_hex = zr_input_str(in, "root");
    bool have_proof = proof_hex && proof_hex[0];
    bool have_root = root_hex && root_hex[0];
    if (have_proof != have_root) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "INCOMPLETE_PROOF",
                               "normalize", false, false,
                               "proof and root must be given together — "
                               "proof from `zcode release prove`, root from "
                               "the anchored domain root (`zcode release "
                               "anchor`)", "zcode.release.verify");
        return;
    }

    char file_hex[ZID_DOC_MAX * 2 + 2];
    if (!doc_hex || !doc_hex[0]) {
#if defined(_WIN32)
        size_t file_size = 0;
        if (!zr_read_stable(file, file_hex, sizeof(file_hex) - 1u,
                            &file_size, false) || file_size == 0) {
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INVALID, "DOC_UNREADABLE",
                                   "normalize", false, false,
                                   "doc file empty, unsafe, unstable or unreadable",
                                   file);
            return;
        }
        ssize_t n = (ssize_t)file_size;
#else
        int fd = open(file, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INVALID, "DOC_UNREADABLE",
                                   "normalize", false, false,
                                   "cannot open doc file", strerror(errno));
            return;
        }
        ssize_t n = read(fd, file_hex, sizeof(file_hex) - 1);
        close(fd);
        if (n <= 0) {
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INVALID, "DOC_UNREADABLE",
                                   "normalize", false, false,
                                   "doc file empty or unreadable", file);
            return;
        }
#endif
        while (n > 0 && (file_hex[n - 1] == '\n' || file_hex[n - 1] == '\r' ||
                         file_hex[n - 1] == ' '))
            n--;
        file_hex[n] = '\0';
        doc_hex = file_hex;
    }

    size_t hex_len = strlen(doc_hex);
    if (hex_len == 0 || (hex_len & 1u) != 0 || hex_len > ZID_DOC_MAX * 2 ||
        !IsHex(doc_hex)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_DOC_HEX",
                               "normalize", false, false,
                               "doc must be even-length hex, at most "
                               "2*ZID_DOC_MAX chars — pass the exact "
                               "doc_hex from zcode release sign",
                               "zcode.release.verify");
        return;
    }
    uint8_t wire[ZID_DOC_MAX];
    size_t wire_len = (size_t)ParseHex(doc_hex, wire, sizeof(wire));
    if (wire_len == 0) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_DOC_HEX",
                               "normalize", false, false,
                               "doc hex did not decode", "zcode.release.verify");
        return;
    }

    struct zid_doc doc;
    if (!zid_doc_decode(&doc, wire, wire_len)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "DOC_DECODE_FAILED",
                               "execute", false, false,
                               "not a well-formed zid doc (version/wire "
                               "layout) — check the hex was not truncated",
                               "zcode.release.verify");
        return;
    }

    int64_t now = platform_time_wall_unix();
    struct zid_release rel;
    memset(&rel, 0, sizeof(rel));
    bool valid = zid_release_verify(&doc, &rel, (uint64_t)now);
    bool release_shape = true;
    if (!valid)
        /* Re-decode for display (verify left rel unfilled on failure). */
        release_shape = zid_release_decode_body(&rel, doc.body,
                                                doc.body_len);

    /* Always show the decoded fields so the caller can see WHAT failed;
     * an invalid doc is a hard failure with the reason named, never a
     * silent valid:false. */
    json_push_kv_str(&reply->data, "name", rel.name);
    json_push_kv_str(&reply->data, "version", rel.version);
    char hex[65];
    HexStr(rel.manifest_root, 32, false, hex, sizeof(hex));
    json_push_kv_str(&reply->data, "manifest_root", hex);
    HexStr(doc.master_pubkey, 32, false, hex, sizeof(hex));
    json_push_kv_str(&reply->data, "master_pubkey", hex);
    json_push_kv_int(&reply->data, "seq", (int64_t)doc.seq);
    json_push_kv_int(&reply->data, "expiry", (int64_t)doc.expiry);
    json_push_kv_int(&reply->data, "verified_at", now);
    json_push_kv_bool(&reply->data, "valid", valid);

    if (!valid) {
        if (!release_shape)
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_FAILED,
                                   "NOT_A_RELEASE_BODY", "execute", false,
                                   false,
                                   "signature/body is not a ZIDR release "
                                   "record — this doc was signed for "
                                   "something else", "zcode.release.verify");
        else if ((uint64_t)now >= doc.expiry)
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_FAILED,
                                   "DOC_EXPIRED", "execute", false, false,
                                   "release doc is expired — ask the "
                                   "publisher for a re-signed doc with a "
                                   "higher seq and later expiry",
                                   "zcode.release.verify");
        else
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_FAILED,
                                   "BAD_SIGNATURE", "execute", false, false,
                                   "ed25519 signature does not verify "
                                   "against the doc's master_pubkey — the "
                                   "doc was tampered with or corrupted",
                                   "zcode.release.verify");
        return;
    }

    /* Chain-rooted key trust (optional `--anchored`). The signature above
     * proves the doc was signed by the key it names — it says NOTHING
     * about whether that key is anyone you should trust. Without this
     * block a verifier has to take the publisher's key from a README:
     * trust-on-first-use. With it, the verifier's OWN node answers
     * whether the key is anchored on-chain, at what height, under which
     * ZNAM name, and whether it is still live.
     *
     * The two facts stay SEPARATE, exactly like batch_included above: a
     * valid signature by an unanchored key is a valid signature by an
     * unanchored key, and the output says both. Nothing here can turn an
     * invalid signature into a trusted one — this code only runs after
     * the `valid` verdict has already passed. */
    if (zr_flag_set(in, "anchored")) {
        const char *datadir = zr_datadir(request);
        if (!datadir) {
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INVALID,
                                   "MISSING_DATADIR", "normalize", false,
                                   false,
                                   "--anchored resolves the doc's "
                                   "master_pubkey against your node's "
                                   "identity projection — pass --datadir",
                                   "zcode.release.verify");
            return;
        }
        sqlite3 *db = NULL;
        struct node_db ndb;
        if (!zcl_native_node_db_require_readonly(
                datadir, reply, "the identity projection --anchored reads",
                &db, &ndb))
            return;
        struct zid_identity row;
        bool anchored = db_zid_identity_find(&ndb, doc.master_pubkey, &row);
        zcl_native_node_db_close_readonly(&db, &ndb);

        json_push_kv_bool(&reply->data, "anchored", anchored);
        if (!anchored) {
            HexStr(doc.master_pubkey, 32, false, hex, sizeof(hex));
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_FAILED,
                                   "KEY_NOT_ANCHORED", "execute", false,
                                   false,
                                   "the signature checks out, but this "
                                   "master key has no on-chain anchor this "
                                   "node has folded — you would be trusting "
                                   "the key on the publisher's word alone",
                                   hex);
            return;
        }

        json_push_kv_int(&reply->data, "anchor_height", row.anchor_height);
        HexStr(row.anchor_txid, 32, false, hex, sizeof(hex));
        json_push_kv_str(&reply->data, "anchor_txid", hex);
        json_push_kv_str(&reply->data, "anchor_name", row.name);
        json_push_kv_str(&reply->data, "anchor_status", row.status);
        json_push_kv_str(&reply->data, "anchor_source", row.source);
        json_push_kv_str(&reply->data, "anchor_owner_address",
                         row.owner_address);
        if (row.has_successor) {
            HexStr(row.successor_pubkey, 32, false, hex, sizeof(hex));
            json_push_kv_str(&reply->data, "successor", hex);
        }

        if (strcmp(row.status, ZID_IDENTITY_STATUS_REVOKED) == 0) {
            HexStr(doc.master_pubkey, 32, false, hex, sizeof(hex));
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_FAILED, "KEY_REVOKED",
                                   "execute", false, false,
                                   "the signature checks out, but the "
                                   "publisher revoked this master key "
                                   "on-chain — a revoked key has no "
                                   "successor and nothing it signed is "
                                   "current", hex);
            return;
        }
        if (strcmp(row.status, ZID_IDENTITY_STATUS_ROTATED) == 0)
            json_push_kv_str(&reply->data, "anchor_note",
                             "this key was rotated on-chain — the doc is "
                             "genuine and the key was live when signed, but "
                             "`successor` is the key the publisher signs "
                             "with now; ask for a doc signed by it");
    }

    /* Domain-batch inclusion (optional): the doc's record digest must be
     * leaf `index` of the tree that produced --root. Reported separately
     * from signature validity; a mismatch is a hard NOT_IN_BATCH. */
    if (have_proof) {
        uint8_t batch_root[32];
        if (strlen(root_hex) != 64 || !IsHex(root_hex) ||
            ParseHex(root_hex, batch_root, 32) != 32) {
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INVALID, "BAD_ROOT",
                                   "normalize", false, false,
                                   "root must be the 64-hex domain root "
                                   "from `zcode release anchor`",
                                   "zcode.release.verify");
            return;
        }
        size_t phex_len = strlen(proof_hex);
        if ((phex_len & 1u) != 0 || phex_len > ZID_PROOF_WIRE_MAX * 2 ||
            !IsHex(proof_hex)) {
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INVALID, "BAD_PROOF_HEX",
                                   "normalize", false, false,
                                   "proof must be even-length hex, at most "
                                   "2*ZID_PROOF_WIRE_MAX chars — pass the "
                                   "exact proof from `zcode release prove`",
                                   "zcode.release.verify");
            return;
        }
        uint8_t pwire[ZID_PROOF_WIRE_MAX];
        size_t pwire_len = (size_t)ParseHex(proof_hex, pwire, sizeof(pwire));
        uint64_t p_index = 0, p_num_leaves = 0;
        uint8_t p_sibs[ZID_TREE_MAX_PEAKS][32];
        uint32_t p_len = 0;
        if (pwire_len == 0 ||
            !zid_proof_decode(&p_index, &p_num_leaves, p_sibs, &p_len,
                              pwire, pwire_len)) {
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INVALID, "BAD_PROOF",
                                   "execute", false, false,
                                   "not a well-formed zid proof wire "
                                   "(version/layout) — check the hex was "
                                   "not truncated", "zcode.release.verify");
            return;
        }
        uint8_t rec[32];
        zid_record_digest(rec, wire, wire_len);
        bool included = zid_tree_verify(batch_root, rec, p_index,
                                        p_num_leaves,
                                        (const uint8_t (*)[32])p_sibs,
                                        p_len);
        HexStr(rec, 32, false, hex, sizeof(hex));
        json_push_kv_str(&reply->data, "record_digest", hex);
        HexStr(batch_root, 32, false, hex, sizeof(hex));
        json_push_kv_str(&reply->data, "batch_root", hex);
        json_push_kv_int(&reply->data, "batch_index", (int64_t)p_index);
        json_push_kv_int(&reply->data, "batch_num_leaves",
                         (int64_t)p_num_leaves);
        json_push_kv_bool(&reply->data, "batch_included", included);
        if (!included) {
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_FAILED, "NOT_IN_BATCH",
                                   "execute", false, false,
                                   "the doc's record digest is NOT in the "
                                   "batch that produced this root — the "
                                   "proof is for a different batch, the "
                                   "root is stale, or the doc is not the "
                                   "one that was anchored",
                                   "zcode.release.verify");
            return;
        }
    }
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

/* ── zcode.release.anchor ──────────────────────────────────────────── */

void zcl_native_handle_zcode_release_anchor(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *datadir = zr_datadir(request);
    if (!datadir) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given and no --datadir default",
                               "zcode.release.anchor");
        return;
    }
    const char *domain = zr_domain(request->input);
    if (!domain) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_DOMAIN",
                               "normalize", false, false,
                               "domain must be 1..63 lowercase "
                               "alphanumerics/hyphens (default \"zcode\")",
                               "zcode.release.anchor");
        return;
    }

    struct zr_batch_entry *entries =
        zcl_malloc(ZR_BATCH_MAX * sizeof(*entries), "zcode_release.batch");
    if (!entries) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ALLOC",
                               "execute", false, false,
                               "batch buffer", "zcode.release.anchor");
        return;
    }
    char err[512];
    size_t count = zr_batch_load(datadir, entries, ZR_BATCH_MAX, err,
                                 sizeof(err));
    if (count == (size_t)-1) {
        free(entries);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "BATCH_LOAD",
                               "execute", false, false, err, datadir);
        return;
    }
    if (count == 0) {
        free(entries);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "NO_RELEASES",
                               "execute", true, false,
                               "no .zid release docs under "
                               "<datadir>/zcode/releases — sign one first "
                               "with `zcode release sign`",
                               datadir);
        return;
    }

    /* Canonical fold: digests are already byte-sorted by zr_batch_load. */
    struct zid_tree t;
    zid_tree_init(&t);
    for (size_t i = 0; i < count; i++)
        zid_tree_append(&t, entries[i].digest);
    uint8_t root[32];
    zid_tree_root(&t, root);
    char root_hex[65];
    HexStr(root, 32, false, root_hex, sizeof(root_hex));

    /* Record the leaf set BEFORE any chain write. An anchor whose leaf
     * set is not on disk is exactly the silent meaning-change this store
     * exists to prevent, so a failure here refuses the anchor rather than
     * committing a root nobody can reproduce. */
    struct node_db ndb;
    if (!zr_open_ndb(datadir, &ndb, reply, "zcode.release.anchor")) {
        free(entries);
        return;
    }
    struct zid_domain_leaf *leaves =
        zcl_malloc(count * sizeof(*leaves), "zcode_release.leaves");
    if (!leaves) {
        free(entries);
        node_db_close(&ndb);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ALLOC",
                               "execute", false, false,
                               "domain leaf buffer", "zcode.release.anchor");
        return;
    }
    for (size_t i = 0; i < count; i++) {
        memset(&leaves[i], 0, sizeof(leaves[i]));
        snprintf(leaves[i].domain_name, sizeof(leaves[i].domain_name), "%s",
                 domain);
        leaves[i].leaf_index = (int64_t)i;
        memcpy(leaves[i].record_digest, entries[i].digest, 32);
        snprintf(leaves[i].label, sizeof(leaves[i].label), "%s@%s",
                 entries[i].name, entries[i].version);
    }
    bool stored = zid_domain_replace_leaves(&ndb, domain, leaves, count, root,
                                            NULL, 0);
    free(leaves);
    free(entries);
    if (!stored) {
        node_db_close(&ndb);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "DOMAIN_STORE",
                               "execute", false, false,
                               "the domain leaf set failed to store — "
                               "refusing to anchor a root whose leaves are "
                               "not recorded (see node.log for the SQL "
                               "failure)", domain);
        return;
    }

    int64_t tip = zr_anchor_tip(request->input);
    char label[ZANC_LABEL_MAX + 1];
    snprintf(label, sizeof(label), "%s@%lld", domain, (long long)tip);

    /* Live-node path: anchor_publish composes + broadcasts when the node
     * has a wallet loaded, and itself returns op_return_hex when not.
     * params is a JSON-RPC array whose [0] is the --input-style object;
     * only a JSON object result is a success — a string is the RPC's
     * error message, surfaced as node_rpc_error on the offline reply. */
    char params[384];
    snprintf(params, sizeof(params),
             "[{\"digest\":\"%s\",\"hash_type\":\"sha3\",\"label\":\"%s\"}]",
             root_hex, label);
    char rpc_err[256] = {0};
    zcl_native_bridge_ensure_rpc();
    char *rpc_result = node_rpc_call("anchor_publish", params);
    if (rpc_result) {
        struct json_value body;
        bool parsed = json_read(&body, rpc_result, strlen(rpc_result));
        bool error_body = parsed &&
                          zr_rpc_body_error(&body, rpc_err, sizeof(rpc_err));
        if (parsed && body.type == JSON_OBJ && !error_body) {
            /* Bind the broadcast txid to the stored root. anchored_height
             * is the height the anchor was broadcast at (a lower bound for
             * the lookup), not a confirmation depth. */
            bool anchor_recorded = false;
            const struct json_value *txv = json_get(&body, "txid");
            const char *txid_hex = txv ? json_get_str(txv) : NULL;
            uint8_t txid[32];
            if (txid_hex && strlen(txid_hex) == 64 && IsHex(txid_hex) &&
                ParseHex(txid_hex, txid, 32) == 32)
                anchor_recorded = zid_domain_set_anchor(&ndb, domain, txid,
                                                        tip);
            node_db_close(&ndb);
            json_push_kv_str(&body, "via", "node_rpc anchor_publish");
            json_push_kv_int(&body, "releases", (int64_t)count);
            json_push_kv_str(&body, "domain", domain);
            json_push_kv_str(&body, "domain_root", root_hex);
            json_push_kv_bool(&body, "domain_stored", true);
            json_push_kv_bool(&body, "anchor_recorded", anchor_recorded);
            json_push_kv_str(&body, "label", label);
            json_copy(&reply->data, &body);
            json_free(&body);
            free(rpc_result);
            reply->status = ZCL_COMMAND_STATUS_PASSED;
            reply->exit_code = ZCL_COMMAND_EXIT_OK;
            return;
        }
        if (!error_body)
            snprintf(rpc_err, sizeof(rpc_err), "%s",
                     parsed ? "node RPC returned an unexpected body"
                            : "node RPC returned an unparseable body");
        json_free(&body);
        free(rpc_result);
    }

    /* Offline / no-live-node path: build the same OP_RETURN locally. The
     * leaf set is already recorded, so re-running this after the node is
     * up re-folds to the same root and keeps the same stored batch. */
    node_db_close(&ndb);
    uint8_t script[128];
    size_t script_len = zanc_build_anchor(script, sizeof(script),
                                          ZANC_HASH_SHA3_256, root, label);
    if (script_len == 0) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL,
                               "OP_RETURN_BUILD_FAILED", "execute", false,
                               false, "zanc_build_anchor rejected the root/"
                               "label", label);
        return;
    }
    json_push_kv_int(&reply->data, "releases", (int64_t)count);
    json_push_kv_str(&reply->data, "domain", domain);
    json_push_kv_str(&reply->data, "domain_root", root_hex);
    json_push_kv_bool(&reply->data, "domain_stored", true);
    json_push_kv_bool(&reply->data, "anchor_recorded", false);
    json_push_kv_str(&reply->data, "label", label);
    json_push_kv_str(&reply->data, "hash_type", "sha3");
    if (rpc_err[0])
        json_push_kv_str(&reply->data, "node_rpc_error", rpc_err);
    char hex[257];
    HexStr(script, script_len, false, hex, sizeof(hex));
    json_push_kv_str(&reply->data, "op_return_hex", hex);
    json_push_kv_int(&reply->data, "op_return_size", (int64_t)script_len);
    json_push_kv_str(&reply->data, "status", "ready");
    json_push_kv_str(&reply->data, "note",
                     "no live node answered — start the node and re-run "
                     "`zcode release anchor` to compose+broadcast with the "
                     "node wallet, or include this OP_RETURN manually as "
                     "vout[0] of any transaction");
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

/* ── zcode.release.prove ───────────────────────────────────────────── */

/* Emit the inclusion proof for leaf `idx` of `digests`. On success fills
 * the reply and returns true; on failure the reply already carries the
 * named error. `source` names WHERE the leaf set came from — the stored
 * domain ("domain_table") or a fold of the releases dir for a domain
 * that has never been anchored ("release_dir"). */
static bool zr_emit_proof(struct zcl_command_reply *reply,
                          const uint8_t (*digests)[32], size_t count,
                          size_t idx, const char *domain, const char *source,
                          const char *name, const char *version)
{
    uint8_t proof[ZID_TREE_MAX_PEAKS][32];
    uint32_t proof_len = 0;
    uint8_t root[32];
    if (!zid_tree_prove_from_leaves(digests, count, idx, proof, &proof_len,
                                    root)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "PROVE_FAILED",
                               "execute", false, false,
                               "zid_tree_prove_from_leaves failed",
                               "zcode.release.prove");
        return false;
    }

    uint8_t pwire[ZID_PROOF_WIRE_MAX];
    size_t pwire_len = zid_proof_encode(pwire, sizeof(pwire), idx, count,
                                        (const uint8_t (*)[32])proof,
                                        proof_len);
    if (pwire_len == 0) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ENCODE_FAILED",
                               "serialize", false, false,
                               "zid_proof_encode failed",
                               "zcode.release.prove");
        return false;
    }
    char *proof_hex = zcl_malloc(pwire_len * 2 + 1, "zcode_release.proof_hex");
    if (!proof_hex) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ALLOC",
                               "serialize", false, false,
                               "proof hex buffer", "zcode.release.prove");
        return false;
    }
    HexStr(pwire, pwire_len, false, proof_hex, pwire_len * 2 + 1);

    char hex[65];
    json_push_kv_str(&reply->data, "name", name);
    json_push_kv_str(&reply->data, "version", version);
    json_push_kv_str(&reply->data, "domain", domain);
    json_push_kv_str(&reply->data, "source", source);
    HexStr(digests[idx], 32, false, hex, sizeof(hex));
    json_push_kv_str(&reply->data, "record_digest", hex);
    json_push_kv_int(&reply->data, "index", (int64_t)idx);
    json_push_kv_int(&reply->data, "num_leaves", (int64_t)count);
    HexStr(root, 32, false, hex, sizeof(hex));
    json_push_kv_str(&reply->data, "domain_root", hex);
    json_push_kv_str(&reply->data, "proof", proof_hex);
    json_push_kv_int(&reply->data, "proof_bytes", (int64_t)pwire_len);
    free(proof_hex);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
    return true;
}

/* Prove from the STORED leaf set — the durable path. Returns true when
 * the reply is complete (proof emitted, or a named failure set); false
 * means "this domain has never been anchored", and the caller falls back
 * to folding the releases dir. */
static bool zr_prove_from_domain(struct node_db *ndb, const char *domain,
                                 const char *name, const char *version,
                                 struct zcl_command_reply *reply)
{
    struct zid_domain dom;
    if (!zid_domain_get(ndb, domain, &dom) || dom.num_leaves <= 0)
        return false;

    size_t n_want = (size_t)dom.num_leaves;
    struct zid_domain_leaf *leaves =
        zcl_malloc(n_want * sizeof(*leaves), "zcode_release.stored_leaves");
    if (!leaves) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ALLOC",
                               "execute", false, false,
                               "stored leaf buffer", "zcode.release.prove");
        return true;
    }
    int got = zid_domain_leaves(ndb, domain, leaves, n_want);
    if (got != (int)n_want) {
        free(leaves);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "DOMAIN_STORE",
                               "execute", false, false,
                               "the stored leaf set is short of the domain's "
                               "num_leaves — re-run `zcode release anchor` to "
                               "rewrite it", domain);
        return true;
    }

    char want[ZID_RELEASE_NAME_MAX + ZID_RELEASE_VERSION_MAX + 2];
    snprintf(want, sizeof(want), "%s@%s", name, version);
    size_t idx = n_want;
    for (size_t i = 0; i < n_want; i++) {
        if (strcmp(leaves[i].label, want) == 0) {
            idx = i;
            break;
        }
    }
    if (idx == n_want) {
        free(leaves);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "RELEASE_NOT_FOUND",
                               "execute", false, false,
                               "no release with this name+version in the "
                               "anchored leaf set of this domain — re-run "
                               "`zcode release anchor` if the doc was signed "
                               "after the last anchor", want);
        return true;
    }

    uint8_t(*digests)[32] = zcl_malloc(n_want * 32, "zcode_release.digests");
    if (!digests) {
        free(leaves);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ALLOC",
                               "execute", false, false,
                               "digest array", "zcode.release.prove");
        return true;
    }
    for (size_t i = 0; i < n_want; i++)
        memcpy(digests[i], leaves[i].record_digest, 32);
    free(leaves);

    /* The stored leaves must re-fold to the stored root, or the proof
     * would be against a root nobody anchored. */
    uint8_t refold[32];
    if (!zid_tree_root_from_digests((const uint8_t (*)[32])digests, n_want,
                                    refold) ||
        memcmp(refold, dom.root, 32) != 0) {
        free(digests);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL,
                               "DOMAIN_ROOT_MISMATCH", "execute", false, false,
                               "the stored leaves do not re-fold to the "
                               "stored root — the domain row and its leaves "
                               "disagree; re-run `zcode release anchor`",
                               domain);
        return true;
    }

    bool ok = zr_emit_proof(reply, (const uint8_t (*)[32])digests, n_want, idx,
                            domain, "domain_table", name, version);
    free(digests);
    if (!ok)
        return true;

    json_push_kv_bool(&reply->data, "anchored", dom.anchored);
    if (dom.anchored) {
        char hex[65];
        HexStr(dom.anchored_txid, 32, false, hex, sizeof(hex));
        json_push_kv_str(&reply->data, "anchored_txid", hex);
        json_push_kv_int(&reply->data, "anchored_height", dom.anchored_height);
    }
    json_push_kv_str(&reply->data, "next",
                     dom.anchored
                         ? "anyone can confirm inclusion with `zclassic23 "
                           "zcode release verify --doc=<hex> --proof=<proof> "
                           "--root=<domain_root>` — domain_root is already "
                           "anchored on-chain at anchored_txid"
                         : "anyone can confirm inclusion with `zclassic23 "
                           "zcode release verify --doc=<hex> --proof=<proof> "
                           "--root=<domain_root>` once domain_root is "
                           "anchored on-chain (`zcode release anchor`)");
    return true;
}

void zcl_native_handle_zcode_release_prove(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const struct json_value *in = request->input;
    const char *datadir = zr_datadir(request);
    if (!datadir) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given and no --datadir default",
                               "zcode.release.prove");
        return;
    }
    const char *name = zr_input_str(in, "name");
    if (!name || !name[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_NAME",
                               "normalize", false, false,
                               "missing name — the release to prove "
                               "inclusion for", "zcode.release.prove");
        return;
    }
    const char *version = zr_input_str(in, "version");
    if (!version || !version[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_VERSION",
                               "normalize", false, false,
                               "missing version — the release to prove "
                               "inclusion for", "zcode.release.prove");
        return;
    }


    const char *domain = zr_domain(in);
    if (!domain) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_DOMAIN",
                               "normalize", false, false,
                               "domain must be 1..63 lowercase "
                               "alphanumerics/hyphens (default \"zcode\")",
                               "zcode.release.prove");
        return;
    }

    /* Durable path FIRST: prove against the leaf set that was stored when
     * the domain was folded, so a .zid added or deleted since then cannot
     * change what this proof means. */
    /* READ leaf: strictly read-only, and ABSENT is the one status we may
     * walk past. A machine that has never folded a domain has no node.db at
     * all, and the release-dir fold below is the whole answer for it — that
     * is the offline case this command is for. Every other status must
     * refuse: falling through on an UNREADABLE node.db would answer "not
     * anchored yet" when the truth is "I could not read the store", and the
     * caller cannot tell those apart from the reply. */
    sqlite3 *db = NULL;
    struct node_db ndb;
    char ndb_path[1200];
    enum zcl_node_db_ro_status ro_st = zcl_native_node_db_open_readonly(
        datadir, &db, &ndb, ndb_path, sizeof(ndb_path));
    if (ro_st != ZCL_NODE_DB_RO_OK && ro_st != ZCL_NODE_DB_RO_ABSENT) {
        (void)zcl_native_node_db_require_readonly(
            datadir, reply, "the stored anchor domain", &db, &ndb);
        return;
    }
    if (ro_st == ZCL_NODE_DB_RO_OK) {
        bool answered =
            zr_prove_from_domain(&ndb, domain, name, version, reply);
        zcl_native_node_db_close_readonly(&db, &ndb);
        if (answered)
            return;
    }

    /* Fallback: this domain has never been folded, so there is no stored
     * leaf set to read. Fold the releases dir exactly as `anchor` would —
     * same canonical byte-sorted order, same wire-byte digests, no clock
     * re-check — and label the reply source "release_dir" so the caller
     * knows the batch is not recorded yet. */
    struct zr_batch_entry *entries =
        zcl_malloc(ZR_BATCH_MAX * sizeof(*entries), "zcode_release.batch");
    if (!entries) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ALLOC",
                               "execute", false, false,
                               "batch buffer", "zcode.release.prove");
        return;
    }
    char err[512];
    size_t count = zr_batch_load(datadir, entries, ZR_BATCH_MAX, err,
                                 sizeof(err));
    if (count == (size_t)-1) {
        free(entries);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "BATCH_LOAD",
                               "execute", false, false, err, datadir);
        return;
    }
    if (count == 0) {
        free(entries);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "NO_RELEASES",
                               "execute", true, false,
                               "no .zid release docs under "
                               "<datadir>/zcode/releases — sign one first "
                               "with `zcode release sign`",
                               datadir);
        return;
    }

    size_t idx = count;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(entries[i].name, name) == 0 &&
            strcmp(entries[i].version, version) == 0) {
            idx = i;
            break;
        }
    }
    if (idx == count) {
        free(entries);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "RELEASE_NOT_FOUND",
                               "execute", false, false,
                               "no release doc with this name+version under "
                               "<datadir>/zcode/releases — check the saved "
                               "files or re-sign with `zcode release sign`",
                               name);
        return;
    }

    uint8_t(*digests)[32] = zr_batch_digests(entries, count);
    free(entries);
    if (!digests) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ALLOC",
                               "execute", false, false,
                               "digest array", "zcode.release.prove");
        return;
    }
    bool ok = zr_emit_proof(reply, (const uint8_t (*)[32])digests, count, idx,
                            domain, "release_dir", name, version);
    free(digests);
    if (!ok)
        return;
    json_push_kv_bool(&reply->data, "anchored", false);
    json_push_kv_str(&reply->data, "next",
                     "this domain has no stored leaf set yet — run `zcode "
                     "release anchor` to record it and commit domain_root "
                     "on-chain, then anyone can confirm inclusion with "
                     "`z23 zcode release verify --doc=<hex> "
                     "--proof=<proof> --root=<domain_root>`");
}

/* ── zcode.domain.list / zcode.domain.status ───────────────────────── */

#define ZR_DOMAIN_LIST_MAX 64
#define ZR_DOMAIN_LEAF_PREVIEW 50

static void zr_domain_json(struct json_value *obj, const struct zid_domain *d)
{
    json_set_object(obj);
    json_push_kv_str(obj, "domain", d->domain_name);
    json_push_kv_int(obj, "num_leaves", d->num_leaves);
    char hex[65];
    HexStr(d->root, 32, false, hex, sizeof(hex));
    json_push_kv_str(obj, "root", hex);
    json_push_kv_bool(obj, "anchored", d->anchored);
    if (d->anchored) {
        HexStr(d->anchored_txid, 32, false, hex, sizeof(hex));
        json_push_kv_str(obj, "anchored_txid", hex);
    }
    json_push_kv_int(obj, "anchored_height", d->anchored_height);
    json_push_kv_int(obj, "updated_at", d->updated_at);
    json_push_kv_bool(obj, "has_owner", d->has_owner);
    if (d->has_owner) {
        HexStr(d->owner_pubkey, 32, false, hex, sizeof(hex));
        json_push_kv_str(obj, "owner_pubkey", hex);
    }
}

void zcl_native_handle_zcode_domain_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *datadir = zr_datadir(request);
    if (!datadir) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given and no --datadir default",
                               "zcode.domain.list");
        return;
    }
    /* READ leaf: strictly read-only. An unreadable store must NOT come back
     * as an empty domain list — "no domains" and "I could not look" are
     * different answers. */
    sqlite3 *db = NULL;
    struct node_db ndb;
    if (!zcl_native_node_db_require_readonly(datadir, reply,
                                             "the anchor-domain store",
                                             &db, &ndb))
        return;

    struct zid_domain rows[ZR_DOMAIN_LIST_MAX];
    int n = zid_domain_list(&ndb, rows, ZR_DOMAIN_LIST_MAX);
    int64_t total = zid_domain_count(&ndb);
    zcl_native_node_db_close_readonly(&db, &ndb);

    struct json_value arr = {0};
    json_set_array(&arr);
    for (int i = 0; i < n; i++) {
        struct json_value obj;
        zr_domain_json(&obj, &rows[i]);
        json_push_back(&arr, &obj);
        json_free(&obj);
    }
    json_push_kv(&reply->data, "domains", &arr);
    json_free(&arr);
    json_push_kv_int(&reply->data, "count", (int64_t)n);
    json_push_kv_int(&reply->data, "total", total);
    json_push_kv_int(&reply->data, "list_cap", ZR_DOMAIN_LIST_MAX);
    json_push_kv_str(&reply->data, "next",
                     "inspect one domain's stored leaf set with `zclassic23 "
                     "zcode domain status --input='{\"domain\":\"zcode\"}'`");
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

void zcl_native_handle_zcode_domain_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *datadir = zr_datadir(request);
    if (!datadir) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given and no --datadir default",
                               "zcode.domain.status");
        return;
    }
    const char *domain = zr_domain(request->input);
    if (!domain) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_DOMAIN",
                               "normalize", false, false,
                               "domain must be 1..63 lowercase "
                               "alphanumerics/hyphens (default \"zcode\")",
                               "zcode.domain.status");
        return;
    }
    /* READ leaf: strictly read-only. Required — an unreadable store must
     * not be reported as DOMAIN_NOT_FOUND, which claims a fact about the
     * store's contents that was never actually read. */
    sqlite3 *db = NULL;
    struct node_db ndb;
    if (!zcl_native_node_db_require_readonly(datadir, reply,
                                             "the anchor-domain store",
                                             &db, &ndb))
        return;

    struct zid_domain d;
    if (!zid_domain_get(&ndb, domain, &d)) {
        zcl_native_node_db_close_readonly(&db, &ndb);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "DOMAIN_NOT_FOUND",
                               "execute", true, false,
                               "no such anchor domain — fold one with `zcode "
                               "release anchor`, or list what exists with "
                               "`zcode domain list`", domain);
        return;
    }

    int64_t leaf_rows = zid_domain_leaf_count(&ndb, domain);
    size_t want = (size_t)(d.num_leaves > ZR_DOMAIN_LEAF_PREVIEW
                               ? ZR_DOMAIN_LEAF_PREVIEW : d.num_leaves);
    struct zid_domain_leaf preview[ZR_DOMAIN_LEAF_PREVIEW];
    int shown = want > 0 ? zid_domain_leaves(&ndb, domain, preview, want) : 0;
    zcl_native_node_db_close_readonly(&db, &ndb);

    struct json_value obj;
    zr_domain_json(&obj, &d);
    json_push_kv(&reply->data, "domain_row", &obj);
    json_free(&obj);
    json_push_kv_str(&reply->data, "domain", d.domain_name);
    json_push_kv_int(&reply->data, "stored_leaf_rows", leaf_rows);
    /* The one integrity question that matters: does the stored leaf set
     * still re-fold to the stored root? A false here means the row and its
     * leaves disagree and every proof against this root is suspect. */
    json_push_kv_bool(&reply->data, "leaf_rows_match_num_leaves",
                      leaf_rows == d.num_leaves);

    struct json_value arr = {0};
    json_set_array(&arr);
    for (int i = 0; i < shown; i++) {
        struct json_value leaf = {0};
        json_set_object(&leaf);
        json_push_kv_int(&leaf, "index", preview[i].leaf_index);
        char hex[65];
        HexStr(preview[i].record_digest, 32, false, hex, sizeof(hex));
        json_push_kv_str(&leaf, "record_digest", hex);
        json_push_kv_str(&leaf, "label", preview[i].label);
        json_push_back(&arr, &leaf);
        json_free(&leaf);
    }
    json_push_kv(&reply->data, "leaves", &arr);
    json_free(&arr);
    json_push_kv_int(&reply->data, "leaves_shown", (int64_t)shown);
    json_push_kv_int(&reply->data, "leaf_preview_cap", ZR_DOMAIN_LEAF_PREVIEW);
    json_push_kv_str(&reply->data, "next",
                     d.anchored
                         ? "prove one release's inclusion with `zclassic23 "
                           "zcode release prove --input='{\"name\":\"<n>\","
                           "\"version\":\"<v>\"}'`"
                         : "this domain's root is not on-chain yet — commit "
                           "it with `z23 zcode release anchor`");
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}
