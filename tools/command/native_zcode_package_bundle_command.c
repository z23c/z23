/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: share a personal package copy by one file — the .z23share writer,
 * zcode.package.bundle.verify and the owner-only zcode.package.bundle.receive,
 * plus the receive trust record. Layout and record: native_zcode_package_bundle.h.
 *
 * Nothing here signs, builds or executes. Verify and the receive plan write
 * only private scratch they remove. The receive confirm keeps the package
 * through zcl_native_zcode_local_publication_commit (the publish.commit
 * lifecycle), makes the copy through the zcode.package.fork leaf itself, and
 * only then writes the owner's trust record. */

#include "command/native_zcode_package_bundle.h"
#include "command/native_zcode_package_copy.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "codec/cursor.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "platform/temp_directory.h"
#include "sha3/sha3.h"
#include "util/authority_receipt.h"
#include "util/file_io.h"
#include "util/file_tree_ops.h"
#include "vcs/package_manifest.h"
#include "vcs/package_publish.h"
#include "vcs/package_recipe.h"
#include "vcs/package_release.h"
#include "vcs/source_bundle.h"
#include "vcs/vcs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define ZPB_PATH_MAX 4400
#define ZPB_RECORD_MAX 1024u
#define ZPB_MAGIC_BYTES 8u

static const char k_zpb_verify[] = "zcode.package.bundle.verify";
static const char k_zpb_receive[] = "zcode.package.bundle.receive";

/* ── receive trust record ───────────────────────────────────────────── */

static bool zpb_record_name(const uint8_t copy_root[32],
                            const uint8_t release_id[32], char *out,
                            size_t cap)
{
    char copy_hex[65], release_hex[65];
    zcl_hex_encode(copy_root, 32, copy_hex);
    zcl_hex_encode(release_id, 32, release_hex);
    int n = snprintf(out, cap, "%s.%s.trust", copy_hex, release_hex);
    return n > 0 && (size_t)n < cap;
}

/* The one canonical text of a record; the reader re-renders and compares. */
static bool zpb_record_render(const struct zcl_package_receive_trust *t,
                              char *out, size_t cap)
{
    char copy[65], release[65], publisher[67], package[65], parent[65];
    zcl_hex_encode(t->copy_root, 32, copy);
    zcl_hex_encode(t->release_id, 32, release);
    zcl_hex_encode(t->publisher, 33, publisher);
    zcl_hex_encode(t->package_root, 32, package);
    if (t->has_parent)
        zcl_hex_encode(t->parent_release, 32, parent);
    else
        (void)snprintf(parent, sizeof(parent), "none");
    int n = snprintf(out, cap,
                     "%s\ncopy_root %s\nrelease_id %s\npublisher %s\n"
                     "package_root %s\nparent_release_root %s\n"
                     "confirmed owner\n",
                     ZCL_PACKAGE_RECEIVE_TRUST_SCHEMA, copy, release,
                     publisher, package, parent);
    return n > 0 && (size_t)n < cap;
}

/* Field values of a record, decoded; the caller re-renders to prove shape. */
static bool zpb_record_parse(const char *text,
                             struct zcl_package_receive_trust *t)
{
    char copy[65], release[65], publisher[67], package[65], parent[65];
    int n = sscanf(text,
                   ZCL_PACKAGE_RECEIVE_TRUST_SCHEMA
                   " copy_root %64s release_id %64s publisher %66s"
                   " package_root %64s parent_release_root %64s",
                   copy, release, publisher, package, parent);
    memset(t, 0, sizeof(*t));
    t->has_parent = n == 5 && strcmp(parent, "none") != 0;
    return n == 5 && zcl_hex_decode_lower(copy, t->copy_root, 32) &&
           zcl_hex_decode_lower(release, t->release_id, 32) &&
           zcl_hex_decode_lower(publisher, t->publisher, 33) &&
           zcl_hex_decode_lower(package, t->package_root, 32) &&
           (!t->has_parent ||
            zcl_hex_decode_lower(parent, t->parent_release, 32));
}

bool zcl_package_receive_trust_read(const char *datadir,
                                    const uint8_t copy_root[32],
                                    const uint8_t release_id[32],
                                    struct zcl_package_receive_trust *out)
{
    char name[160], path[ZPB_PATH_MAX], canonical[ZPB_RECORD_MAX];
    char *text = NULL;
    size_t len = 0;
    if (!datadir || !copy_root || !release_id || !out ||
        !zpb_record_name(copy_root, release_id, name, sizeof(name)))
        return false;
    int n = snprintf(path, sizeof(path), "%s/%s/%s", datadir,
                     ZCL_PACKAGE_RECEIVE_TRUST_DIR, name);
    if (n <= 0 || (size_t)n >= sizeof(path) ||
        !zcl_read_whole_file_text(path, ZPB_RECORD_MAX, &text, &len,
                                  "zcode.package.receive_trust"))
        return false;
    bool ok = zpb_record_parse(text, out) &&
              zpb_record_render(out, canonical, sizeof(canonical)) &&
              strcmp(canonical, text) == 0 &&
              memcmp(out->copy_root, copy_root, 32) == 0 &&
              memcmp(out->release_id, release_id, 32) == 0;
    free(text);
    return ok;
}

/* ── the share file ─────────────────────────────────────────────────── */

struct zpb_file {
    uint8_t *bytes;
    size_t len;
    struct zcl_package_bundle_wires wires;
    uint8_t tree[32];
    const uint8_t *source;
    size_t source_len;
};

static bool zpb_put_wire(struct zcl_codec_writer *w, const uint8_t *bytes,
                         size_t len)
{
    return len <= UINT32_MAX && zcl_codec_write_u32le(w, (uint32_t)len) &&
           zcl_codec_write_bytes(w, bytes, len);
}

static bool zpb_encode(const struct zcl_package_bundle_wires *wires,
                       const uint8_t tree[32], const uint8_t *source,
                       size_t source_len, struct zpb_file *out)
{
    size_t total = ZPB_MAGIC_BYTES + 4u * 5u + wires->release_len +
                   wires->manifest_len + wires->recipe_len + 32u + source_len;
    struct zcl_codec_writer w;
    size_t written = 0;
    out->bytes = zcl_malloc(total, "zcode.package.bundle.file");
    if (!out->bytes)
        return false;
    zcl_codec_writer_init(&w, out->bytes, total);
    out->len = total;
    return zcl_codec_write_bytes(&w, ZCL_PACKAGE_BUNDLE_MAGIC,
                                 ZPB_MAGIC_BYTES) &&
           zcl_codec_write_u32le(&w, ZCL_PACKAGE_BUNDLE_VERSION) &&
           zpb_put_wire(&w, wires->release, wires->release_len) &&
           zpb_put_wire(&w, wires->manifest, wires->manifest_len) &&
           zpb_put_wire(&w, wires->recipe, wires->recipe_len) &&
           zcl_codec_write_bytes(&w, tree, 32) &&
           zpb_put_wire(&w, source, source_len) &&
           zcl_codec_writer_finish(&w, &written) && written == total;
}

static bool zpb_take_wire(struct zcl_codec_reader *r, size_t cap,
                          const uint8_t **out, size_t *len)
{
    uint32_t n = 0;
    if (!zcl_codec_read_u32le(r, &n) || n == 0 || n > cap)
        return false;
    *out = zcl_codec_take(r, n);
    *len = n;
    return *out != NULL;
}

static bool zpb_decode(struct zpb_file *f)
{
    struct zcl_codec_reader r;
    uint8_t magic[ZPB_MAGIC_BYTES];
    uint32_t version = 0;
    zcl_codec_reader_init(&r, f->bytes, f->len);
    return zcl_codec_read_bytes(&r, magic, sizeof(magic)) &&
           memcmp(magic, ZCL_PACKAGE_BUNDLE_MAGIC, sizeof(magic)) == 0 &&
           zcl_codec_read_u32le(&r, &version) &&
           version == ZCL_PACKAGE_BUNDLE_VERSION &&
           zpb_take_wire(&r, VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES,
                         &f->wires.release, &f->wires.release_len) &&
           zpb_take_wire(&r, VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES,
                         &f->wires.manifest, &f->wires.manifest_len) &&
           zpb_take_wire(&r, VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES,
                         &f->wires.recipe, &f->wires.recipe_len) &&
           zcl_codec_read_bytes(&r, f->tree, 32) &&
           zpb_take_wire(&r, VCS_SOURCE_BUNDLE_MAX_WIRE_BYTES, &f->source,
                         &f->source_len) &&
           zcl_codec_reader_finish(&r);
}

bool zcl_package_bundle_write(const char *output, const char *copy_dir,
                              const uint8_t tree[32],
                              const struct zcl_package_bundle_wires *wires,
                              struct zcl_command_reply *reply)
{
    uint8_t *source = NULL;
    size_t source_len = 0;
    struct vcs_source_bundle_metrics metrics;
    struct zpb_file file = {0};
    bool ok = vcs_source_bundle_create(copy_dir, tree, &source, &source_len,
                                       &metrics) == VCS_SOURCE_BUNDLE_OK &&
              zpb_encode(wires, tree, source, source_len, &file) &&
              file.len <= VCS_SOURCE_BUNDLE_MAX_WIRE_BYTES;
    if (!ok)
        zcl_package_copy_fail(reply, "SHARE_FILE_ENCODE", true,
                              "the release is kept, but its saved tree "
                              "could not be packed into one share file",
                              copy_dir);
    else if (!zcl_native_source_bundle_write_exclusive(output, file.bytes,
                                                       file.len)) {
        zcl_package_copy_fail(reply, "SHARE_FILE_WRITE", true,
                              "the release is kept, but the share file could "
                              "not be created; name a new path as output",
                              output);
        ok = false;
    }
    free(source);
    free(file.bytes);
    return ok;
}

/* ── verify ─────────────────────────────────────────────────────────── */

struct zpb_receive {
    const struct json_value *input;
    struct zcl_command_reply *reply;
    const char *path;
    struct zpb_file file;
    struct vcs_package_release release;
    uint8_t release_id[32];
    struct vcs_package_manifest manifest;
    struct vcs_package_recipe recipe;
    bool parsed;
    char scratch[PLATFORM_TEMP_PATH_MAX];
    char store[ZPB_PATH_MAX];
    char src[ZPB_PATH_MAX];
    struct vcs_package_publish_report report;
    char fingerprint[67];
    char package_hex[65];
    char release_hex[65];
};

static bool zpb_refuse(struct zpb_receive *s, const char *why)
{
    zcl_package_copy_fail(s->reply, "BUNDLE_REFUSED", false,
                          "the share file does not verify; nothing was kept. "
                          "Ask the sender for the file again", why);
    return false;
}

static bool zpb_load(struct zpb_receive *s)
{
    s->path = zcl_package_copy_str(s->input, "file");
    s->file.bytes = s->path ? zcl_native_source_bundle_read(s->path,
                                                            &s->file.len)
                            : NULL;
    if (!s->file.bytes) {
        zcl_package_copy_fail(s->reply, "BUNDLE_UNREADABLE", false,
                              "file must name a readable share file of at "
                              "most 64 MiB", s->path ? s->path : k_zpb_verify);
        return false;
    }
    if (!zpb_decode(&s->file))
        return zpb_refuse(s, "not a version 1 .z23share file");
    if (vcs_package_release_parse(s->file.wires.release,
                                  s->file.wires.release_len, &s->release) !=
            VCS_PACKAGE_RELEASE_OK ||
        vcs_package_release_id(&s->release, s->release_id) !=
            VCS_PACKAGE_RELEASE_OK ||
        vcs_package_release_verify(&s->release) != VCS_PACKAGE_RELEASE_OK)
        return zpb_refuse(s, "the signed release envelope does not verify");
    zcl_hex_encode(s->release.publisher_pubkey,
                   VCS_PACKAGE_RELEASE_PUBKEY_BYTES, s->fingerprint);
    zcl_hex_encode(s->release.package_root, 32, s->package_hex);
    zcl_hex_encode(s->release_id, 32, s->release_hex);
    vcs_package_manifest_init(&s->manifest);
    vcs_package_recipe_init(&s->recipe);
    s->parsed = true;
    if (!vcs_package_manifest_parse(s->file.wires.manifest,
                                    s->file.wires.manifest_len,
                                    &s->manifest) ||
        vcs_package_recipe_parse(s->file.wires.recipe,
                                 s->file.wires.recipe_len, &s->recipe) !=
            VCS_PACKAGE_RECIPE_OK)
        return zpb_refuse(s, "the manifest or recipe wire does not parse");
    return true;
}

/* Rebuild the exact saved tree from the source bundle in private scratch. */
static bool zpb_materialize(struct zpb_receive *s)
{
    struct vcs_source_bundle_metrics metrics;
    int a = 0, b = 0;
    bool ok = platform_temp_directory_create("z23-receive-", s->scratch,
                                             sizeof(s->scratch));
    if (ok) {
        a = snprintf(s->store, sizeof(s->store), "%s/store", s->scratch);
        b = snprintf(s->src, sizeof(s->src), "%s/source", s->scratch);
    }
    ok = ok && a > 0 && (size_t)a < sizeof(s->store) && b > 0 &&
         (size_t)b < sizeof(s->src) && zcl_mkdir_p(s->store, 0700).ok &&
         zcl_mkdir_p(s->src, 0700).ok &&
         vcs_source_bundle_import(s->file.source, s->file.source_len,
                                  s->file.tree, s->store, &metrics) ==
             VCS_SOURCE_BUNDLE_OK &&
         vcs_tree_materialize(s->store, s->file.tree, s->src,
                              VCS_SOURCE_BUNDLE_MAX_SOURCE_BYTES, 0) == VCS_OK;
    return ok || zpb_refuse(s, "the source tree does not rebuild from the "
                               "bundle");
}

/* The publication rules publish.commit applies, without keeping anything:
 * signature, manifest root, recipe root and every chunk of every file. */
static bool zpb_validate(struct zpb_receive *s)
{
    vcs_package_publish_report_init(&s->report);
    vcs_package_publish_validate(&s->release, &s->manifest, &s->report);
    vcs_package_publish_validate_recipe(&s->release, &s->manifest,
                                        &s->recipe, &s->report);
    vcs_package_publish_verify_chunks(&s->manifest, s->src, &s->report);
    if (s->report.failure_count > 0 || !s->report.release_ok ||
        !s->report.manifest_ok || !s->report.recipe_ok)
        return zpb_refuse(s, s->report.failure_count
                                 ? vcs_package_publish_rule_string(
                                       s->report.failures[0].rule)
                                 : "publication rules");
    return true;
}

/* The source half of the check, after the cheap envelope half (zpb_load). */
static bool zpb_check_source(struct zpb_receive *s)
{
    return zpb_materialize(s) && zpb_validate(s);
}

static void zpb_free(struct zpb_receive *s)
{
    if (s->scratch[0])
        (void)zcl_tree_remove(s->scratch);
    if (s->parsed) {
        vcs_package_manifest_free(&s->manifest);
        vcs_package_recipe_free(&s->recipe);
    }
    free(s->file.bytes);
    free(s);
}

static struct zpb_receive *zpb_new(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply,
                                   const char *command)
{
    struct zpb_receive *s =
        request && reply ? zcl_calloc(1, sizeof(*s), command) : NULL;
    if (!s && reply)
        zcl_package_copy_fail(reply, "ALLOC", false, "receive state",
                              command);
    if (s) {
        s->input = request->input;
        s->reply = reply;
    }
    return s;
}

static void zpb_describe(struct zpb_receive *s, const char *stage)
{
    struct json_value *d = &s->reply->data;
    (void)json_push_kv_str(d, "stage", stage);
    (void)json_push_kv_str(d, "name", s->release.name);
    (void)json_push_kv_str(d, "semver", s->release.semver);
    (void)json_push_kv_str(d, "release_id", s->release_hex);
    (void)json_push_kv_str(d, "package_root", s->package_hex);
    (void)json_push_kv_str(d, "publisher_fingerprint", s->fingerprint);
    (void)json_push_kv_int(d, "publisher_sequence",
                           (int64_t)s->release.publisher_sequence);
    if (s->release.has_parent)
        zcl_package_copy_push_root(d, "parent_release_root",
                                   s->release.parent_root);
    (void)json_push_kv_int(d, "files", (int64_t)s->report.file_count);
    (void)json_push_kv_int(d, "bytes", (int64_t)s->report.total_bytes);
    (void)json_push_kv_bool(d, "verified", true);
    (void)json_push_kv_bool(d, "executed", false);
}

void zcl_native_handle_zcode_package_bundle_verify(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    struct zpb_receive *s = zpb_new(request, reply, k_zpb_verify);
    if (!s)
        return;
    if (zpb_load(s) && zpb_check_source(s)) {
        char next[1024];
        zpb_describe(s, "verify");
        (void)snprintf(next, sizeof(next),
                       "check publisher %s with the sender, then the owner "
                       "keeps it with: z23 zcode package bundle receive "
                       "--input='{\"file\":\"%s\",\"destination\":\"<new "
                       "folder>\"}'",
                       s->fingerprint, s->path);
        (void)json_push_kv_str(&reply->data, "next", next);
    }
    zpb_free(s);
}

/* ── receive ────────────────────────────────────────────────────────── */

struct zpb_keep {
    const char *datadir;
    const char *destination;
    uint8_t plan_id[32];
    uint8_t version[32];
    char record[ZPB_PATH_MAX];
};

/* Bound to the exact file contents, destination and datadir; each string is
 * hashed with its NUL so adjacent fields cannot run together. */
static void zpb_plan_id(const struct zpb_receive *s, struct zpb_keep *k)
{
    static const char domain[] = "zcl.zcode_package_bundle_receive.plan.v1";
    const char *const texts[] = {k->destination, k->datadir};
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)domain, sizeof(domain));
    sha3_256_write(&ctx, s->release_id, 32);
    sha3_256_write(&ctx, s->file.tree, 32);
    for (size_t i = 0; i < 2; i++)
        sha3_256_write(&ctx, (const unsigned char *)texts[i],
                       strlen(texts[i]) + 1u);
    sha3_256_finalize(&ctx, k->plan_id);
}

static bool zpb_receive_inputs(struct zpb_receive *s, struct zpb_keep *k)
{
    struct stat st;
    k->datadir = zcl_package_copy_datadir(s->input, s->reply, k_zpb_receive);
    k->destination = zcl_package_copy_str(s->input, "destination");
    if (!k->datadir)
        return false;
    if (!k->destination) {
        zcl_package_copy_fail(s->reply, "MISSING_DESTINATION", false,
                              "destination names the new folder for the "
                              "copy", k_zpb_receive);
        return false;
    }
    if (stat(k->destination, &st) == 0) {
        zcl_package_copy_fail(s->reply, "DESTINATION_EXISTS", false,
                              "a received copy is made in a new folder",
                              k->destination);
        return false;
    }
    return true;
}

/* The owner names the publisher and root they checked with the sender. */
static bool zpb_trusted(struct zpb_receive *s)
{
    const char *publisher = zcl_package_copy_str(s->input, "trust_publisher");
    const char *root = zcl_package_copy_str(s->input, "trust_root");
    if (!publisher || !root) {
        zcl_package_copy_fail(s->reply, "TRUST_REQUIRED", false,
                              "confirm the publisher fingerprint and package "
                              "root you checked with the sender as "
                              "trust_publisher and trust_root", s->fingerprint);
        return false;
    }
    if (strcmp(publisher, s->fingerprint) != 0 ||
        strcmp(root, s->package_hex) != 0) {
        zcl_package_copy_fail(s->reply, "TRUST_MISMATCH", false,
                              "trust_publisher and trust_root must equal this "
                              "file's publisher fingerprint and package root",
                              s->fingerprint);
        return false;
    }
    return true;
}

/* Keep the verified package through the publish.commit lifecycle. */
static bool zpb_store(struct zpb_receive *s, const struct zpb_keep *k)
{
    struct zcl_command_reply sub;
    const struct json_value *day = json_get(s->input, "day");
    const struct zcl_native_local_publication publication = {
        .datadir = k->datadir, .source_directory = s->src,
        .release_wire = s->file.wires.release,
        .release_wire_len = s->file.wires.release_len,
        .manifest_wire = s->file.wires.manifest,
        .manifest_wire_len = s->file.wires.manifest_len,
        .recipe_wire = s->file.wires.recipe,
        .recipe_wire_len = s->file.wires.recipe_len,
        .has_day = day != NULL, .day = day ? json_get_int(day) : 0,
    };
    zcl_command_reply_init(&sub, "zcl.zcode_package_publish_commit.v1");
    zcl_native_zcode_local_publication_commit(&publication, &sub);
    bool ok = sub.status == ZCL_COMMAND_STATUS_PASSED;
    if (!ok)
        zcl_package_copy_fail(s->reply, "RECEIVE_STORE_REFUSED",
                              sub.error.mutated,
                              "the local package store refused the verified "
                              "release", sub.error.message);
    zcl_command_reply_free(&sub);
    return ok;
}

/* One zcode.package.fork call, plan or confirm, through the registered leaf.
 * Its input (root, destination, datadir) is built here from the verified
 * file, never taken from the receive caller. */
static bool zpb_fork_call(struct json_value *in, struct zcl_command_reply *out)
{
    const struct zcl_command_spec *spec = zcl_command_registry_find(
        zcl_command_catalog(), "zcode.package.fork", NULL);
    const struct zcl_command_request request = {
        .input = in, .spec = spec, .invoked_name = "zcode.package.fork",
    };
    zcl_command_reply_init(out, "zcl.zcode_package_fork.v1");
    if (!spec || !spec->handler)
        return false;
    spec->handler(&request, out);
    return out->status == ZCL_COMMAND_STATUS_PASSED;
}

/* The copy is an ordinary fork of the received release. */
static bool zpb_fork(struct zpb_receive *s, struct zpb_keep *k)
{
    struct json_value in;
    struct zcl_command_reply out;
    json_init(&in);
    json_set_object(&in);
    (void)json_push_kv_str(&in, "root", s->release_hex);
    (void)json_push_kv_str(&in, "destination", k->destination);
    (void)json_push_kv_str(&in, "datadir", k->datadir);
    bool ok = zpb_fork_call(&in, &out);
    const char *plan = ok ? json_get_str(json_get(&out.data, "plan_id"))
                          : NULL;
    ok = plan && json_push_kv_str(&in, "plan_id", plan) &&
         json_push_kv_bool(&in, "confirm", true);
    if (ok) {
        zcl_command_reply_free(&out);
        ok = zpb_fork_call(&in, &out) &&
             zcl_hex_decode(json_get_str(json_get(&out.data, "version")),
                            k->version, 32);
    }
    if (!ok)
        zcl_package_copy_fail(s->reply, "RECEIVE_FORK_REFUSED", true,
                              "the release is kept, but the copy could not "
                              "be made", out.error.message);
    zcl_command_reply_free(&out);
    json_free(&in);
    return ok;
}

static bool zpb_record_write(struct zpb_receive *s, struct zpb_keep *k)
{
    struct zcl_package_receive_trust t = {.has_parent = s->release.has_parent};
    char dir[ZPB_PATH_MAX], name[160], text[ZPB_RECORD_MAX];
    memcpy(t.copy_root, k->version, 32);
    memcpy(t.release_id, s->release_id, 32);
    memcpy(t.publisher, s->release.publisher_pubkey, 33);
    memcpy(t.package_root, s->release.package_root, 32);
    if (t.has_parent)
        memcpy(t.parent_release, s->release.parent_root, 32);
    int n = snprintf(dir, sizeof(dir), "%s/%s", k->datadir,
                     ZCL_PACKAGE_RECEIVE_TRUST_DIR);
    bool ok = n > 0 && (size_t)n < sizeof(dir) &&
              zpb_record_name(k->version, s->release_id, name,
                              sizeof(name)) &&
              zpb_record_render(&t, text, sizeof(text)) &&
              zcl_mkdir_p(dir, 0700).ok &&
              authority_receipt_write_atomic(dir, name, (const uint8_t *)text,
                                             strlen(text), k->record,
                                             sizeof(k->record));
    if (!ok)
        zcl_package_copy_fail(s->reply, "TRUST_RECORD_FAILED", true,
                              "the copy was made, but the trust confirmation "
                              "was not recorded; receive again into a new "
                              "folder", dir);
    return ok;
}

static void zpb_keep_reply(struct zpb_receive *s, const struct zpb_keep *k)
{
    char next[512];
    zpb_describe(s, "commit");
    (void)json_push_kv_str(&s->reply->data, "destination", k->destination);
    zcl_package_copy_push_root(&s->reply->data, "version", k->version);
    (void)json_push_kv_str(&s->reply->data, "trust_record", k->record);
    (void)snprintf(next, sizeof(next),
                   "the copy in %s is yours to build and open; this "
                   "confirmation covers only publisher %s and root %s",
                   k->destination, s->fingerprint, s->package_hex);
    (void)json_push_kv_str(&s->reply->data, "next", next);
    s->reply->error.mutated = true;
}

static void zpb_receive_plan(struct zpb_receive *s, const struct zpb_keep *k)
{
    char next[1536];
    zpb_describe(s, "plan");
    zcl_package_copy_push_root(&s->reply->data, "plan_id", k->plan_id);
    char plan[65];
    zcl_hex_encode(k->plan_id, 32, plan);
    (void)snprintf(next, sizeof(next),
                   "check publisher %s and root %s with the sender, then: "
                   "z23 zcode package bundle receive --input='{\"file\":\"%s\","
                   "\"destination\":\"%s\",\"plan_id\":\"%s\","
                   "\"trust_publisher\":\"%s\",\"trust_root\":\"%s\","
                   "\"confirm\":true}'",
                   s->fingerprint, s->package_hex, s->path, k->destination,
                   plan, s->fingerprint, s->package_hex);
    (void)json_push_kv_str(&s->reply->data, "next", next);
}

void zcl_native_handle_zcode_package_bundle_receive(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    struct zpb_receive *s = zpb_new(request, reply, k_zpb_receive);
    struct zpb_keep k = {0};
    if (!s)
        return;
    /* Trust is checked against the signed envelope before the source is
     * rebuilt; nothing is kept until the whole file verifies. */
    if (zpb_receive_inputs(s, &k) && zpb_load(s)) {
        zpb_plan_id(s, &k);
        if (!zcl_package_copy_confirmed(s->input)) {
            if (zpb_check_source(s))
                zpb_receive_plan(s, &k);
        } else if (zcl_package_copy_plan_matches(s->input, k.plan_id, reply,
                                                 k_zpb_receive) &&
                   zpb_trusted(s) && zpb_check_source(s) &&
                   zpb_store(s, &k) && zpb_fork(s, &k) &&
                   zpb_record_write(s, &k))
            zpb_keep_reply(s, &k);
    }
    zpb_free(s);
}
