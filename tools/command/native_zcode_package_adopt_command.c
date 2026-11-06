/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zcode.package.adopt — the owner keeps one published release as
 * their own runnable copy — zcode.package.copies, the adopt record and the
 * adoption check later leaves (app.build, the launcher's copy open) call.
 *
 * Adopt plans first: it verifies the release and shows its publisher key,
 * its parent release and package roots and the files it changed against
 * that parent (both manifests read from <datadir>/zcode/manifests and
 * root-checked; the package store is not opened, so the plan writes
 * nothing). Confirm checks the release out as <datadir>/copies/<name>-<n>
 * through the same verified checkout and fork record zcode.package.fork
 * uses, with a random nonce in the root commit so every adopt has its own
 * root, then saves the adopt record.
 *
 * The record (zcl.pkg_adopt.v1) lives in the datadir, never in the copy.
 * Canonical wire, integers little-endian:
 *   [16 domain "zcl.pkg_adopt.v1"][32 root commit][32 release id]
 *   [32 package root][32 parent release or zero][33 publisher key]
 *   [8 adopted_at][33 name, NUL padded]
 *   [32 record id = SHA3-256(domain 0x00 || the 218 bytes before it)]
 * It is saved validate -> encode -> tmp, fsync, rename, fsync(dir)
 * (authority_receipt_write_atomic) under <datadir>/zcode/adopted. */

#include "command/native_command.h"
#include "command/native_zcode_package_copy.h"

#include "base/hex.h"
#include "base/serialize_le.h"
#include "crypto/random_secret.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "platform/time_compat.h"
#include "sha3/sha3.h"
#include "util/authority_receipt.h"
#include "util/file_io.h"
#include "vcs/package_checkout.h"
#include "vcs/package_manifest.h"
#include "vcs/package_release.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define ZPA_PATH_MAX 4400
#define ZPA_DOMAIN "zcl.pkg_adopt.v1"
#define ZPA_DOMAIN_BYTES 16u
#define ZPA_KEY_DOMAIN "zcl.package_adopt.key.v1"
#define ZPA_PLAN_DOMAIN "zcl.zcode_package_adopt.plan.v1"
#define ZPA_SUFFIX ".adopt"
#define ZPA_NAME_FIELD (ZCL_PACKAGE_ADOPT_NAME_MAX + 1u)
#define ZPA_BODY_BYTES                                                       \
    (ZPA_DOMAIN_BYTES + 4u * 32u + ZCL_PACKAGE_ADOPT_PUBKEY_BYTES + 8u +     \
     ZPA_NAME_FIELD)
#define ZPA_WIRE_BYTES (ZPA_BODY_BYTES + 32u)
/* The base of a copy name; "-<n>" (n up to 999) follows it. */
#define ZPA_BASE_MAX 24u
#define ZPA_COPIES_MAX 999u
#define ZPA_CHANGED_SHOWN 16u
#define ZPA_CHANGED_BYTES 1536u
/* One copies row is about 400 bytes; the list budget is 8 KiB. */
#define ZPA_LIST_MAX 16u

static const uint8_t k_zpa_zero[32];

/* ── the adopt record ───────────────────────────────────────────────── */

const char *zcl_package_copy_adoption_name(enum zcl_package_copy_adoption a)
{
    switch (a) {
    case ZCL_PACKAGE_COPY_ADOPTED:         return "adopted";
    case ZCL_PACKAGE_COPY_NOT_ADOPTED:     return "not_adopted";
    case ZCL_PACKAGE_COPY_FOREIGN_COMMITS: return "foreign_commits";
    case ZCL_PACKAGE_COPY_ADOPTION_UNREADABLE: break;
    }
    return "adoption_unreadable";
}

/* A copy name is 1..32 of [a-z0-9._-] and does not start with '.'. */
static bool zpa_name_valid(const char *name)
{
    size_t len = strnlen(name, ZPA_NAME_FIELD);
    if (len == 0 || len > ZCL_PACKAGE_ADOPT_NAME_MAX || name[0] == '.')
        return false;
    for (size_t i = 0; i < len; i++) {
        char ch = name[i];
        bool ok = (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
                  ch == '-' || ch == '_' || ch == '.';
        if (!ok)
            return false;
    }
    return true;
}

static bool zpa_record_valid(const struct zcl_package_adopt_record *r)
{
    return memcmp(r->root_commit, k_zpa_zero, 32) != 0 &&
           memcmp(r->release_id, k_zpa_zero, 32) != 0 &&
           memcmp(r->package_root, k_zpa_zero, 32) != 0 &&
           (r->publisher_pubkey[0] == 0x02 || r->publisher_pubkey[0] == 0x03) &&
           zpa_name_valid(r->name);
}

static void zpa_record_digest(const uint8_t body[ZPA_BODY_BYTES],
                              uint8_t out[32])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)ZPA_DOMAIN,
                   sizeof(ZPA_DOMAIN));
    sha3_256_write(&ctx, body, ZPA_BODY_BYTES);
    sha3_256_finalize(&ctx, out);
}

static void zpa_record_encode(const struct zcl_package_adopt_record *r,
                              uint8_t wire[ZPA_WIRE_BYTES])
{
    uint8_t *p = wire;
    memset(wire, 0, ZPA_WIRE_BYTES);
    memcpy(p, ZPA_DOMAIN, ZPA_DOMAIN_BYTES);
    p += ZPA_DOMAIN_BYTES;
    memcpy(p, r->root_commit, 32);
    memcpy(p + 32, r->release_id, 32);
    memcpy(p + 64, r->package_root, 32);
    memcpy(p + 96, r->parent_release, 32);
    p += 128;
    memcpy(p, r->publisher_pubkey, ZCL_PACKAGE_ADOPT_PUBKEY_BYTES);
    p += ZCL_PACKAGE_ADOPT_PUBKEY_BYTES;
    zcl_write_u64_le(p, r->adopted_at);
    p += 8;
    memcpy(p, r->name, strnlen(r->name, ZCL_PACKAGE_ADOPT_NAME_MAX));
    zpa_record_digest(wire, wire + ZPA_BODY_BYTES);
}

/* Strict decode: exact length, domain, record id, padding and fields. */
static bool zpa_record_decode(const uint8_t *wire, size_t len,
                              struct zcl_package_adopt_record *r)
{
    uint8_t digest[32];
    const uint8_t *p = wire + ZPA_DOMAIN_BYTES;
    if (!wire || len != ZPA_WIRE_BYTES ||
        memcmp(wire, ZPA_DOMAIN, ZPA_DOMAIN_BYTES) != 0)
        return false;
    zpa_record_digest(wire, digest);
    if (memcmp(digest, wire + ZPA_BODY_BYTES, 32) != 0)
        return false;
    memset(r, 0, sizeof(*r));
    memcpy(r->root_commit, p, 32);
    memcpy(r->release_id, p + 32, 32);
    memcpy(r->package_root, p + 64, 32);
    memcpy(r->parent_release, p + 96, 32);
    p += 128;
    memcpy(r->publisher_pubkey, p, ZCL_PACKAGE_ADOPT_PUBKEY_BYTES);
    p += ZCL_PACKAGE_ADOPT_PUBKEY_BYTES;
    r->adopted_at = zcl_read_u64_le(p);
    p += 8;
    memcpy(r->name, p, ZPA_NAME_FIELD);
    return r->name[ZCL_PACKAGE_ADOPT_NAME_MAX] == '\0' && zpa_record_valid(r);
}

static void zpa_key_name(const uint8_t root_commit[32],
                         const uint8_t release_id[32], char out[72])
{
    struct sha3_256_ctx ctx;
    uint8_t key[32];
    char hex[65];
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)ZPA_KEY_DOMAIN,
                   sizeof(ZPA_KEY_DOMAIN));
    sha3_256_write(&ctx, root_commit, 32);
    sha3_256_write(&ctx, release_id, 32);
    sha3_256_finalize(&ctx, key);
    zcl_hex_encode(key, 32, hex);
    (void)snprintf(out, 72, "%s%s", hex, ZPA_SUFFIX);
}

static bool zpa_join(char *out, size_t cap, const char *a, const char *b)
{
    int n = snprintf(out, cap, "%s/%s", a, b);
    return n > 0 && (size_t)n < cap;
}

bool zcl_package_adopt_record_save(const char *datadir,
                                   const struct zcl_package_adopt_record *rec)
{
    char zcode[ZPA_PATH_MAX], store[ZPA_PATH_MAX], name[72];
    uint8_t wire[ZPA_WIRE_BYTES];
    if (!datadir || !rec || !zpa_record_valid(rec)) {
        fprintf(stderr, "[zcode.package.adopt] refusing an invalid adopt "
                        "record\n");
        return false;
    }
    if (!zpa_join(zcode, sizeof(zcode), datadir, "zcode") ||
        !zpa_join(store, sizeof(store), zcode, "adopted") ||
        !platform_directory_ensure(zcode, 0700) ||
        !platform_directory_ensure(store, 0700)) {
        fprintf(stderr, "[zcode.package.adopt] cannot create %s/zcode/adopted\n",
                datadir);
        return false;
    }
    zpa_record_encode(rec, wire);
    zpa_key_name(rec->root_commit, rec->release_id, name);
    return authority_receipt_write_atomic(store, name, wire, sizeof(wire),
                                          NULL, 0);
}

static bool zpa_record_read(const char *path,
                            struct zcl_package_adopt_record *out)
{
    uint8_t *wire = NULL;
    size_t len = 0;
    bool ok = zcl_read_whole_file(path, ZPA_WIRE_BYTES, &wire, &len,
                                  "zcode.package.adopt") &&
              zpa_record_decode(wire, len, out);
    free(wire);
    return ok;
}

bool zcl_package_adopt_record_load(const char *datadir,
                                   const uint8_t root_commit[32],
                                   const uint8_t release_id[32],
                                   struct zcl_package_adopt_record *out,
                                   bool *found)
{
    char name[72], rel[160], path[ZPA_PATH_MAX];
    struct stat st;
    *found = false;
    zpa_key_name(root_commit, release_id, name);
    (void)snprintf(rel, sizeof(rel), "zcode/adopted/%s", name);
    if (!datadir || !zpa_join(path, sizeof(path), datadir, rel))
        return false;
    if (stat(path, &st) != 0)
        return true;
    *found = true;
    return S_ISREG(st.st_mode) && zpa_record_read(path, out) &&
           memcmp(out->root_commit, root_commit, 32) == 0 &&
           memcmp(out->release_id, release_id, 32) == 0;
}

/* The copy is <datadir>/copies/<name> itself, compared as canonical real
 * directories: a commit log copied elsewhere is not that copy. */
static bool zpa_copy_in_place(const char *datadir, const char *name,
                              const char *dir)
{
    char want[ZPA_PATH_MAX], want_real[ZPA_PATH_MAX], got_real[ZPA_PATH_MAX];
    int n = snprintf(want, sizeof(want), "%s/copies/%s", datadir, name);
    return n > 0 && (size_t)n < sizeof(want) && dir &&
           platform_directory_canonical_real(want, want_real,
                                             sizeof(want_real)) &&
           platform_directory_canonical_real(dir, got_real, sizeof(got_real)) &&
           strcmp(want_real, got_real) == 0;
}

enum zcl_package_copy_adoption zcl_package_copy_adopted(
    const char *datadir, const struct zcl_package_copy *copy,
    struct zcl_package_adopt_record *record)
{
    struct zcl_package_adopt_record rec;
    bool found = false;
    if (!datadir || !copy || !copy->repo ||
        !zcl_package_adopt_record_load(datadir, copy->fork_version,
                                       copy->parent_release, &rec, &found))
        return ZCL_PACKAGE_COPY_ADOPTION_UNREADABLE;
    if (!found)
        return ZCL_PACKAGE_COPY_NOT_ADOPTED;
    if (record)
        *record = rec;
    if (!zpa_copy_in_place(datadir, rec.name, vcs_repo_root(copy->repo)))
        return ZCL_PACKAGE_COPY_NOT_ADOPTED;
    return copy->foreign_versions ? ZCL_PACKAGE_COPY_FOREIGN_COMMITS
                                  : ZCL_PACKAGE_COPY_ADOPTED;
}

/* ── the plan: what will be adopted ─────────────────────────────────── */

struct zpa_plan {
    const char *datadir;
    struct vcs_package_release release;
    uint8_t release_id[32];
    bool parent_known;
    uint8_t parent_package[32];
    char name[ZPA_NAME_FIELD];
    char copy[ZPA_PATH_MAX];
    uint8_t plan_id[32];
};

/* The last segment of the release name, lowered to [a-z0-9._-]. */
static void zpa_name_base(const char *release_name, char base[ZPA_BASE_MAX + 1u])
{
    const char *slash = strrchr(release_name, '/');
    const char *s = slash ? slash + 1 : release_name;
    size_t n = 0;
    for (; *s && n < ZPA_BASE_MAX; s++) {
        char ch = *s;
        if (ch >= 'A' && ch <= 'Z')
            ch = (char)(ch - 'A' + 'a');
        bool keep = (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
                    ch == '_' || (ch == '.' && n > 0);
        base[n++] = keep ? ch : '-';
    }
    base[n] = '\0';
    if (n == 0)
        (void)snprintf(base, ZPA_BASE_MAX + 1u, "copy");
}

/* The first absent <datadir>/copies/<base>-<n>. */
static bool zpa_pick_copy(struct zpa_plan *p, struct zcl_command_reply *reply)
{
    char base[ZPA_BASE_MAX + 1u];
    struct stat st;
    zpa_name_base(p->release.name, base);
    for (unsigned n = 1; n <= ZPA_COPIES_MAX; n++) {
        (void)snprintf(p->name, sizeof(p->name), "%s-%u", base, n);
        int len = snprintf(p->copy, sizeof(p->copy), "%s/copies/%s",
                           p->datadir, p->name);
        if (len <= 0 || (size_t)len >= sizeof(p->copy))
            break;
        if (stat(p->copy, &st) != 0)
            return true;
    }
    zcl_package_copy_fail(reply, "COPIES_FULL", false,
                          "no free copy name under <datadir>/copies; remove "
                          "an old copy first", base);
    return false;
}

static void zpa_plan_id(struct zpa_plan *p)
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)ZPA_PLAN_DOMAIN,
                   sizeof(ZPA_PLAN_DOMAIN));
    sha3_256_write(&ctx, p->release_id, 32);
    sha3_256_write(&ctx, p->release.package_root, 32);
    sha3_256_write(&ctx, (const unsigned char *)p->copy, strlen(p->copy) + 1u);
    sha3_256_finalize(&ctx, p->plan_id);
}

static bool zpa_plan_derive(struct zpa_plan *p,
                            struct zcl_command_reply *reply)
{
    struct vcs_package_release parent;
    uint8_t parent_id[32];
    if (p->release.has_parent &&
        zcl_package_copy_find_release(p->datadir, p->release.parent_root,
                                      &parent, parent_id) ==
            ZCL_PACKAGE_COPY_FOUND &&
        memcmp(parent_id, p->release.parent_root, 32) == 0) {
        p->parent_known = true;
        memcpy(p->parent_package, parent.package_root, 32);
    }
    if (!zpa_pick_copy(p, reply))
        return false;
    zpa_plan_id(p);
    return true;
}

/* ── files changed against the parent ───────────────────────────────── */

struct zpa_changes {
    struct json_value paths;
    size_t count;
    size_t shown;
    size_t shown_bytes;
};

static void zpa_change(struct zpa_changes *ch, const char *path,
                       const char *kind)
{
    size_t len = strlen(path);
    ch->count++;
    if (ch->shown >= ZPA_CHANGED_SHOWN ||
        ch->shown_bytes + len > ZPA_CHANGED_BYTES)
        return;
    struct json_value row;
    json_init(&row);
    json_set_object(&row);
    (void)json_push_kv_str(&row, "path", path);
    (void)json_push_kv_str(&row, "change", kind);
    (void)json_push_back(&ch->paths, &row);
    json_free(&row);
    ch->shown++;
    ch->shown_bytes += len;
}

/* Read <datadir>/zcode/manifests/<root>: bounded, parsed and root-checked.
 * The package store is not opened (its recovery sweep writes). */
static bool zpa_manifest_load(const char *datadir, const uint8_t root[32],
                              struct vcs_package_manifest *m)
{
    char hex[65], rel[96], path[ZPA_PATH_MAX];
    uint8_t *wire = NULL, got[32];
    size_t len = 0;
    struct stat st;
    zcl_hex_encode(root, 32, hex);
    (void)snprintf(rel, sizeof(rel), "zcode/manifests/%s", hex);
    vcs_package_manifest_init(m);
    if (!zpa_join(path, sizeof(path), datadir, rel) || stat(path, &st) != 0 ||
        !zcl_read_whole_file(path, VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES, &wire,
                             &len, "zcode.package.adopt"))
        return false;
    bool ok = vcs_package_manifest_parse(wire, len, m) &&
              vcs_package_manifest_root(m, got) && memcmp(got, root, 32) == 0;
    free(wire);
    return ok;
}

static bool zpa_same_file(const struct vcs_package_file *a,
                          const struct vcs_package_file *b)
{
    uint8_t ha[32], hb[32];
    return vcs_package_file_hash(a, ha) && vcs_package_file_hash(b, hb) &&
           memcmp(ha, hb, 32) == 0;
}

/* Merge-walk two path-sorted manifests: parent `a` against release `b`. */
static void zpa_diff(const struct vcs_package_manifest *a,
                     const struct vcs_package_manifest *b,
                     struct zpa_changes *ch)
{
    size_t i = 0, j = 0;
    while (i < a->count || j < b->count) {
        int cmp = i >= a->count ? 1
                  : j >= b->count
                      ? -1
                      : strcmp(a->files[i].path, b->files[j].path);
        if (cmp < 0) {
            zpa_change(ch, a->files[i++].path, "removed");
        } else if (cmp > 0) {
            zpa_change(ch, b->files[j++].path, "added");
        } else {
            if (!zpa_same_file(&a->files[i], &b->files[j]))
                zpa_change(ch, b->files[j].path, "modified");
            i++;
            j++;
        }
    }
}

static void zpa_push_changes(struct json_value *data, const struct zpa_plan *p)
{
    struct vcs_package_manifest parent, release;
    struct zpa_changes ch = {.count = 0};
    if (!p->release.has_parent)
        return;
    vcs_package_manifest_init(&parent);
    vcs_package_manifest_init(&release);
    bool ok = p->parent_known &&
              zpa_manifest_load(p->datadir, p->parent_package, &parent);
    ok = zpa_manifest_load(p->datadir, p->release.package_root, &release) &&
         ok;
    if (ok) {
        json_init(&ch.paths);
        json_set_array(&ch.paths);
        zpa_diff(&parent, &release, &ch);
        (void)json_push_kv_int(data, "changes", (int64_t)ch.count);
        (void)json_push_kv(data, "changed_paths", &ch.paths);
        (void)json_push_kv_bool(data, "changed_paths_truncated",
                                ch.count > ch.shown);
        json_free(&ch.paths);
    } else {
        (void)json_push_kv_str(data, "changes_unavailable",
                               "the parent release or a package manifest is "
                               "not in this datadir; fetch the parent to see "
                               "the changed files");
    }
    vcs_package_manifest_free(&parent);
    vcs_package_manifest_free(&release);
}

static void zpa_describe(struct json_value *data, const struct zpa_plan *p,
                         const char *stage)
{
    char publisher[2u * ZCL_PACKAGE_ADOPT_PUBKEY_BYTES + 1u];
    zcl_hex_encode(p->release.publisher_pubkey, ZCL_PACKAGE_ADOPT_PUBKEY_BYTES,
                   publisher);
    (void)json_push_kv_str(data, "stage", stage);
    zcl_package_copy_push_root(data, "plan_id", p->plan_id);
    zcl_package_copy_push_root(data, "release_root", p->release_id);
    zcl_package_copy_push_root(data, "package_root", p->release.package_root);
    (void)json_push_kv_str(data, "name", p->release.name);
    (void)json_push_kv_str(data, "semver", p->release.semver);
    (void)json_push_kv_str(data, "publisher", publisher);
    (void)json_push_kv_bool(data, "has_parent", p->release.has_parent);
    if (p->release.has_parent)
        zcl_package_copy_push_root(data, "parent_release_root",
                                   p->release.parent_root);
    if (p->parent_known)
        zcl_package_copy_push_root(data, "parent_package_root",
                                   p->parent_package);
    (void)json_push_kv_str(data, "copy_name", p->name);
    (void)json_push_kv_str(data, "copy", p->copy);
}

/* ── confirm: make the copy, then the record ────────────────────────── */

static bool zpa_commit(struct zpa_plan *p, struct zcl_command_reply *reply,
                       uint8_t version[32])
{
    char copies[ZPA_PATH_MAX], session[64], nonce_hex[33];
    uint8_t nonce[16];
    struct vcs_package_checkout_metrics metrics = {0};
    if (!zpa_join(copies, sizeof(copies), p->datadir, "copies") ||
        !platform_directory_ensure(copies, 0700)) {
        zcl_package_copy_fail(reply, "COPIES_UNWRITABLE", false,
                              "<datadir>/copies could not be created", copies);
        return false;
    }
    if (!zcl_random_secret_bytes(nonce, sizeof(nonce), "zcode.package.adopt")) {
        zcl_package_copy_fail(reply, "NONCE_FAILED", false,
                              "no randomness for the copy's root commit",
                              p->copy);
        return false;
    }
    zcl_hex_encode(nonce, sizeof(nonce), nonce_hex);
    (void)snprintf(session, sizeof(session), "zcode.adopt:%s", nonce_hex);
    if (!zcl_package_copy_make(p->datadir, &p->release, p->release_id,
                               p->copy, session, version, &metrics, reply))
        return false;
    struct zcl_package_adopt_record rec = {
        .adopted_at = (uint64_t)platform_time_wall_unix(),
    };
    memcpy(rec.root_commit, version, 32);
    memcpy(rec.release_id, p->release_id, 32);
    memcpy(rec.package_root, p->release.package_root, 32);
    if (p->release.has_parent)
        memcpy(rec.parent_release, p->release.parent_root, 32);
    memcpy(rec.publisher_pubkey, p->release.publisher_pubkey,
           ZCL_PACKAGE_ADOPT_PUBKEY_BYTES);
    (void)snprintf(rec.name, sizeof(rec.name), "%s", p->name);
    if (zcl_package_adopt_record_save(p->datadir, &rec))
        return true;
    zcl_package_copy_fail(reply, "ADOPT_RECORD_FAILED", true,
                          "the copy was made but its adopt record was not "
                          "written, so it is not adopted; adopt again (the "
                          "next adopt makes a new copy)", p->copy);
    return false;
}

void zcl_native_handle_zcode_package_adopt(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *command = "zcode.package.adopt";
    struct zpa_plan p;
    uint8_t version[32];
    memset(&p, 0, sizeof(p));
    if (!request || !reply)
        return;
    p.datadir = zcl_package_copy_datadir(request->input, reply, command);
    if (!p.datadir ||
        !zcl_package_copy_resolve_release(request->input, p.datadir,
                                          &p.release, p.release_id, reply,
                                          command) ||
        !zpa_plan_derive(&p, reply))
        return;
    if (!zcl_package_copy_confirmed(request->input)) {
        zpa_describe(&reply->data, &p, "plan");
        zpa_push_changes(&reply->data, &p);
        (void)json_push_kv_str(&reply->data, "next",
                               "check the publisher and the changes, then "
                               "repeat with this plan_id and confirm:true");
        return;
    }
    if (!zcl_package_copy_plan_matches(request->input, p.plan_id, reply,
                                       command) ||
        !zpa_commit(&p, reply, version))
        return;
    zpa_describe(&reply->data, &p, "commit");
    zcl_package_copy_push_root(&reply->data, "root_commit", version);
    (void)json_push_kv_bool(&reply->data, "adopted", true);
    (void)json_push_kv_bool(&reply->data, "executed", false);
    reply->error.mutated = true;
}

/* ── zcode package copies ───────────────────────────────────────────── */

/* The live status of one recorded copy, read without writing. */
static const char *zpa_copy_status(const char *datadir,
                                   const struct zcl_package_adopt_record *rec,
                                   char *dir, size_t cap)
{
    struct zcl_package_copy copy;
    struct zcl_command_reply scratch;
    struct stat st;
    const char *status = "history_invalid";
    int n = snprintf(dir, cap, "%s/copies/%s", datadir, rec->name);
    if (n <= 0 || (size_t)n >= cap || stat(dir, &st) != 0)
        return "missing";
    zcl_command_reply_init(&scratch, "zcl.zcode_package_copies.v1");
    if (zcl_package_copy_open_as(dir, ZCL_PACKAGE_COPY_READ, &copy, &scratch,
                                 "zcode.package.copies")) {
        status = memcmp(copy.fork_version, rec->root_commit, 32) == 0
                     ? zcl_package_copy_adoption_name(
                           zcl_package_copy_adopted(datadir, &copy, NULL))
                     : "not_adopted";
        zcl_package_copy_close(&copy);
    }
    zcl_command_reply_free(&scratch);
    return status;
}

static void zpa_copies_row(struct json_value *rows, const char *datadir,
                           const char *store, const char *file)
{
    struct zcl_package_adopt_record rec;
    struct json_value row;
    char path[ZPA_PATH_MAX], dir[ZPA_PATH_MAX];
    json_init(&row);
    json_set_object(&row);
    if (!zpa_join(path, sizeof(path), store, file) ||
        !zpa_record_read(path, &rec)) {
        (void)json_push_kv_str(&row, "record", file);
        (void)json_push_kv_str(&row, "status", "record_invalid");
    } else {
        const char *status = zpa_copy_status(datadir, &rec, dir, sizeof(dir));
        (void)json_push_kv_str(&row, "name", rec.name);
        (void)json_push_kv_str(&row, "dir", dir);
        (void)json_push_kv_str(&row, "status", status);
        zcl_package_copy_push_root(&row, "root_commit", rec.root_commit);
        zcl_package_copy_push_root(&row, "release_root", rec.release_id);
        zcl_package_copy_push_root(&row, "package_root", rec.package_root);
        (void)json_push_kv_int(&row, "adopted_at", (int64_t)rec.adopted_at);
    }
    (void)json_push_back(rows, &row);
    json_free(&row);
}

static bool zpa_is_record(const char *name)
{
    size_t len = strlen(name), suffix = strlen(ZPA_SUFFIX);
    return len > suffix && strcmp(name + len - suffix, ZPA_SUFFIX) == 0;
}

void zcl_native_handle_zcode_package_copies(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *command = "zcode.package.copies";
    struct platform_directory_list list = {0};
    struct json_value rows;
    char store[ZPA_PATH_MAX];
    struct stat st;
    size_t count = 0;
    if (!request || !reply)
        return;
    const char *datadir =
        zcl_package_copy_datadir(request->input, reply, command);
    if (!datadir)
        return;
    bool present = zpa_join(store, sizeof(store), datadir, "zcode/adopted") &&
                   stat(store, &st) == 0;
    if (present && !platform_directory_list_regular_sorted(store, &list)) {
        zcl_package_copy_fail(reply, "ADOPTED_UNREADABLE", false,
                              "the adopt records could not be listed", store);
        return;
    }
    json_init(&rows);
    json_set_array(&rows);
    for (size_t i = 0; i < list.count; i++) {
        if (!zpa_is_record(list.entries[i].name))
            continue;
        if (count++ < ZPA_LIST_MAX)
            zpa_copies_row(&rows, datadir, store, list.entries[i].name);
    }
    platform_directory_list_free(&list);
    (void)json_push_kv_int(&reply->data, "count", (int64_t)count);
    (void)json_push_kv(&reply->data, "copies", &rows);
    (void)json_push_kv_bool(&reply->data, "truncated", count > ZPA_LIST_MAX);
    json_free(&rows);
}
