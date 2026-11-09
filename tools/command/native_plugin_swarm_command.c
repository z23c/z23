/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: plugin.publish and plugin.fetch — plugin distribution over the
 *          existing content.v2 package CAS and the authenticated zpkgswm
 *          swarm, with no new transport, registry or authority.
 *
 *          plugin.publish verifies a packed plugin directory (LICENSE, NAME,
 *          NAME.plugin.json, NAME.plugin.sig) self-consistently — the
 *          signature verifies under the key it names and the executable
 *          matches the signed SHA3-512 — then admits the directory as one
 *          ordinary package into <datadir>/zcode, pins it and names the
 *          package root. A running -packagehost=1 node serves the root from
 *          there; publication vouches for nothing: the bytes carry their own
 *          signature and every receiver re-verifies them.
 *
 *          plugin.fetch starts (or idempotently resumes) a swarm download of
 *          one root through the node-global engine when the hosting node
 *          runs (live:true), or persists the resumable download record for
 *          the next hosting boot like zcode.package.fetch (live:false). A
 *          one-shot CLI given a namespace instead asks the running node to
 *          route the root to authenticated zclassic23.plugin DHT providers
 *          and start the bounded fetch in-process, exactly like
 *          zcode.package.fetch; re-run plugin fetch when the store holds the
 *          complete package. Once the store holds the complete package it
 *          checks the tree out,
 *          verifies the plugin set under the key its signature names and
 *          reports whether the receiver's own publisher_keys lists that key
 *          (pinned/unpinned). Fetch is inert: it never installs, switches,
 *          builds or runs anything. Activation remains the owner command
 *          plugin.install, which verifies the signature against the
 *          receiver's publisher_keys. */

#include "native_plugin_common.h"
#include "native_zcode_discovery.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "plugin/plugin_store.h"
#include "vcs/package_checkout.h"
#include "vcs/package_manifest.h"
#include "vcs/package_public_shape.h"
#include "vcs/package_release.h"
#include "vcs/package_service.h"
#include "vcs/package_store.h"
#include "vcs/package_swarm_node.h"

#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define PSW_LEAF_MAX 255u
#define PSW_FILES_MAX 64u
#define PSW_TEXT_MAX 65536u /* one manifest or signature file */
/* The DHT namespace the optional announce publishes the plugin's POINTER and
 * PROVIDER records into; both name the package root (semantic == transport).
 * Records live one hour and the running service renews them. */
#define PSW_PLUGIN_NAMESPACE "zclassic23.plugin"
#define PSW_RECORD_SECONDS INT64_C(3600)

struct psw_file {
    char leaf[PSW_LEAF_MAX + 1];
    uint64_t size;
    uint32_t mode;
};

/* The verified view of one plugin package directory. */
struct psw_set {
    struct psw_file files[PSW_FILES_MAX];
    size_t file_count;
    uint64_t total_bytes;
    char name[PLUGIN_NAME_MAX + 1]; /* from the NAME.plugin.json leaf */
    struct plugin_manifest manifest;
    char publisher[65];             /* the key the signature names */
};

/* A named refusal: code is plugin_status_code or a PLUGIN_PUBLISH_* /
 * PLUGIN_FETCH_* literal. code NULL means no fault. */
struct psw_fault {
    const char *code;
    const char *next_action;
    char detail[256];
};

static void psw_refuse(struct zcl_command_reply *reply, const char *code,
                       const char *next_action, const char *what,
                       const char *evidence)
{
    if (!reply || !code || !what)
        return;
    char message[256];
    (void)snprintf(message, sizeof(message), "plugin %s refused: %s", what,
                   code);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, what, false, false,
                           message, evidence ? evidence : "");
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                   "%s", next_action);
    reply->error.human_action_required = true;
}

static void psw_refuse_fault(struct zcl_command_reply *reply,
                             const struct psw_fault *fault, const char *what)
{
    psw_refuse(reply, fault->code, fault->next_action, what, fault->detail);
}

static void psw_fault_set(struct psw_fault *fault, const char *code,
                          const char *next_action, const char *detail)
{
    fault->code = code;
    fault->next_action = next_action;
    (void)snprintf(fault->detail, sizeof(fault->detail), "%s",
                   detail ? detail : "");
}

static void psw_fault_plugin(struct psw_fault *fault, enum plugin_status st,
                             const char *detail)
{
    psw_fault_set(fault, plugin_status_code(st), plugin_status_next_action(st),
                  detail);
}

/* Attach a copyable next-command suggestion carrying one small JSON payload
 * (the follow-up command's own input). */
static void psw_push_next(struct zcl_command_reply *reply, const char *cmd,
                          const char *note, struct json_value *payload)
{
    size_t need = json_write(payload, NULL, 0) + 1;
    char *text = zcl_malloc(need, "plugin.swarm.next");
    if (text && json_write(payload, text, need) < need)
        (void)zcl_command_reply_add_next(reply, cmd, text, note);
    free(text);
}

/* Bounded whole-file read; false on any error or a file over cap. */
static bool psw_read(const char *path, size_t cap, uint8_t **out, size_t *len)
{
    *out = NULL;
    *len = 0;
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    uint8_t *buf = zcl_malloc(cap, "plugin.swarm.read");
    if (!buf) {
        (void)fclose(f);
        return false;
    }
    size_t n = fread(buf, 1, cap, f);
    bool ok = !ferror(f) && feof(f) && n > 0 && n < cap;
    if (fclose(f) != 0)
        ok = false;
    if (!ok) {
        free(buf);
        return false;
    }
    *out = buf;
    *len = n;
    return true;
}

static int psw_leaf_cmp(const void *a, const void *b)
{
    return strcmp(((const struct psw_file *)a)->leaf,
                  ((const struct psw_file *)b)->leaf);
}

static bool psw_ends(const char *leaf, const char *suffix)
{
    size_t n = strlen(leaf), s = strlen(suffix);
    return n > s && strcmp(leaf + n - s, suffix) == 0;
}

/* Validate and record one directory entry: a regular file, non-empty unless
 * the caller tolerates inert empty extras, within the package caps. */
static bool psw_scan_entry(const char *dir, const char *leaf,
                           struct psw_set *set, bool allow_empty)
{
    if (strlen(leaf) > PSW_LEAF_MAX || set->file_count == PSW_FILES_MAX)
        return false;
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", dir, leaf);
    if (n < 0 || (size_t)n >= sizeof(path))
        return false;
    struct stat st;
    if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_size < 0 || (!allow_empty && st.st_size == 0) ||
        (uint64_t)st.st_size > (uint64_t)VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES)
        return false;
    struct psw_file *f = &set->files[set->file_count++];
    (void)snprintf(f->leaf, sizeof(f->leaf), "%s", leaf);
    f->size = (uint64_t)st.st_size;
    set->total_bytes += f->size;
    return set->total_bytes <= (uint64_t)VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES;
}

/* Inventory the directory: regular files only, no subdirectories or links,
 * sorted by leaf name. */
static bool psw_scan_inventory(const char *dir, struct psw_set *set,
                               bool allow_empty, const char *layout_code,
                               const char *layout_next, struct psw_fault *fault)
{
    DIR *d = opendir(dir);
    if (!d) {
        psw_fault_set(fault, layout_code, layout_next,
                      "the directory could not be opened");
        return false;
    }
    bool ok = true;
    for (struct dirent *e = readdir(d); e && ok; e = readdir(d)) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        ok = psw_scan_entry(dir, e->d_name, set, allow_empty);
    }
    (void)closedir(d);
    if (!ok || set->file_count == 0) {
        psw_fault_set(fault, layout_code, layout_next,
                      "a directory entry is a subdirectory, a link, empty, "
                      "oversized or one too many");
        return false;
    }
    qsort(set->files, set->file_count, sizeof(set->files[0]), psw_leaf_cmp);
    return true;
}

/* Exactly one NAME.plugin.json selects the plugin name. */
static bool psw_pick_manifest(struct psw_set *set, const char *layout_code,
                              const char *layout_next, struct psw_fault *fault)
{
    const char *manifest_leaf = NULL;
    for (size_t i = 0; i < set->file_count; i++) {
        if (!psw_ends(set->files[i].leaf, ".plugin.json"))
            continue;
        if (manifest_leaf) {
            psw_fault_set(fault, layout_code, layout_next,
                          set->files[i].leaf);
            return false;
        }
        manifest_leaf = set->files[i].leaf;
    }
    if (!manifest_leaf) {
        psw_fault_set(fault, layout_code, layout_next,
                      "no NAME.plugin.json found");
        return false;
    }
    size_t name_len = strlen(manifest_leaf) - strlen(".plugin.json");
    if (name_len == 0 || name_len > PLUGIN_NAME_MAX) {
        psw_fault_set(fault, layout_code, layout_next, manifest_leaf);
        return false;
    }
    memcpy(set->name, manifest_leaf, name_len);
    set->name[name_len] = '\0';
    return true;
}

/* NAME, NAME.plugin.sig and LICENSE must sit beside the manifest; NAME is
 * the executable member. */
static bool psw_mark_members(struct psw_set *set)
{
    bool have_exe = false, have_sig = false, have_license = false;
    for (size_t i = 0; i < set->file_count; i++) {
        char expected[PSW_LEAF_MAX + 1];
        (void)snprintf(expected, sizeof(expected), "%s.plugin.sig", set->name);
        have_sig = have_sig || strcmp(set->files[i].leaf, expected) == 0;
        have_exe = have_exe || strcmp(set->files[i].leaf, set->name) == 0;
        have_license =
            have_license || strcmp(set->files[i].leaf, "LICENSE") == 0;
        set->files[i].mode = strcmp(set->files[i].leaf, set->name) == 0
                                 ? VCS_PACKAGE_MODE_EXECUTABLE
                                 : VCS_PACKAGE_MODE_FILE;
    }
    return have_exe && have_sig && have_license;
}

/* Inventory one flat plugin package directory: regular files only, no
 * subdirectories or links, sorted by leaf name. Exactly one NAME.plugin.json
 * selects the plugin name; NAME, NAME.plugin.sig and LICENSE must sit beside
 * it. Publish passes allow_empty false (a publisher never packs an empty
 * file); fetch passes true, tolerating inert empty extras in a package.
 * Layout refusals carry the caller's code and next action. */
static bool psw_scan(const char *dir, struct psw_set *set, bool allow_empty,
                     const char *layout_code, const char *layout_next,
                     struct psw_fault *fault)
{
    memset(set, 0, sizeof(*set));
    if (!psw_scan_inventory(dir, set, allow_empty, layout_code, layout_next,
                            fault))
        return false;
    if (!psw_pick_manifest(set, layout_code, layout_next, fault))
        return false;
    if (!psw_mark_members(set)) {
        psw_fault_set(fault, layout_code, layout_next, set->name);
        return false;
    }
    return true;
}

/* Verify the scanned set self-consistently: the manifest parses, its
 * signature verifies under the key the signature names, the manifest name
 * matches its file name and the executable matches the signed SHA3-512. This
 * grants no authority over the receiving store. */
static bool psw_verify_set(const char *dir, struct psw_set *set,
                           const char *layout_code, const char *layout_next,
                           struct psw_fault *fault)
{
    char manifest_path[PATH_MAX], sig_path[PATH_MAX], exe_path[PATH_MAX];
    if (snprintf(manifest_path, sizeof(manifest_path), "%s/%s.plugin.json",
                 dir, set->name) >= (int)sizeof(manifest_path) ||
        snprintf(sig_path, sizeof(sig_path), "%s/%s.plugin.sig", dir,
                 set->name) >= (int)sizeof(sig_path) ||
        snprintf(exe_path, sizeof(exe_path), "%s/%s", dir, set->name) >=
            (int)sizeof(exe_path)) {
        psw_fault_set(fault, layout_code, layout_next, dir);
        return false;
    }
    uint8_t *manifest = NULL, *sig = NULL;
    size_t manifest_len = 0, sig_len = 0;
    bool ok = psw_read(manifest_path, PSW_TEXT_MAX, &manifest, &manifest_len) &&
              psw_read(sig_path, PSW_TEXT_MAX, &sig, &sig_len);
    if (!ok) {
        free(manifest);
        free(sig);
        psw_fault_set(fault, "PLUGIN_IO",
                      "check permissions and free space and retry", dir);
        return false;
    }
    enum plugin_status st = plugin_verify_manifest_self(
        (const char *)manifest, manifest_len, (const char *)sig, sig_len,
        &set->manifest, set->publisher);
    free(manifest);
    free(sig);
    if (st != PLUGIN_OK) {
        psw_fault_plugin(fault, st, manifest_path);
        return false;
    }
    if (strcmp(set->manifest.name, set->name) != 0) {
        psw_fault_plugin(fault, PLUGIN_ERR_MANIFEST_INVALID,
                         "the manifest name does not match its file name");
        return false;
    }
    char digest[PLUGIN_HEX_SHA3_512 + 1];
    st = plugin_hash_file(exe_path, digest);
    if (st != PLUGIN_OK) {
        psw_fault_plugin(fault, st, exe_path);
        return false;
    }
    if (strcmp(digest, set->manifest.exe_sha3) != 0) {
        psw_fault_plugin(fault, PLUGIN_ERR_EXE_HASH, exe_path);
        return false;
    }
    return true;
}

/* The publish license gate: a node may publicly serve a plugin set only
 * when its LICENSE bytes match the frozen permissive allowlist (the same
 * authority the public-shape classifier applies at serve time). Publish
 * refuses anything else so a successful publish never names a root no peer
 * may fetch. */
static bool psw_license_serveable(const char *dir, struct psw_fault *fault)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/LICENSE", dir);
    uint8_t *text = NULL;
    size_t len = 0;
    bool ok = n > 0 && (size_t)n < sizeof(path) &&
              psw_read(path, VCS_PACKAGE_RELEASE_LICENSE_TEXT_MAX_BYTES,
                       &text, &len) &&
              vcs_package_release_license_text_allowed(text, len);
    free(text);
    if (!ok) {
        psw_fault_set(fault, "PLUGIN_PUBLISH_LICENSE",
                      "ship the exact text of a license on the permissive "
                      "allowlist (for example MIT); other licenses still "
                      "install by hand but no node may serve them",
                      "LICENSE is missing, unreadable or not allowlisted");
        return false;
    }
    return true;
}

static const char *psw_datadir(const struct zcl_command_request *request)
{
    const char *dd = plg_str(request, "datadir");
    if (dd && dd[0])
        return dd;
    dd = zcl_native_command_datadir();
    return (dd && dd[0]) ? dd : NULL;
}

/* Resolve the store for publish/fetch. With no explicit datadir and a live
 * node-global store, borrow the resident handle — the serving engine is
 * built over that same handle, so what publish admits is immediately
 * serveable and what the engine fetched is immediately visible to checkout.
 * An explicit datadir (or no resident store) takes the one-shot owned path,
 * and the caller closes only owned handles. */
static struct vcs_package_store *psw_store_open(
    const struct zcl_command_request *request, char *zcode_dir, size_t cap,
    bool *owned_out)
{
    *owned_out = false;
    const char *explicit_dd = plg_str(request, "datadir");
    if (!explicit_dd || !explicit_dd[0]) {
        struct vcs_package_store *resident = vcs_package_store_global();
        if (resident) {
            const char *root = vcs_package_store_root_dir(resident);
            int n = root ? snprintf(zcode_dir, cap, "%s", root) : -1;
            if (n > 0 && (size_t)n < cap)
                return resident;
        }
    }
    const char *datadir = psw_datadir(request);
    if (!datadir)
        return NULL;
    int n = snprintf(zcode_dir, cap, "%s/zcode", datadir);
    if (n < 0 || (size_t)n >= cap)
        return NULL;
    struct vcs_package_store *store =
        vcs_package_store_open(datadir, vcs_package_store_quota_bytes());
    if (store)
        *owned_out = true;
    return store;
}

static void psw_store_close(struct vcs_package_store *store, bool owned)
{
    if (owned)
        vcs_package_store_close(store);
}

/* Read one file of the verified set and add its chunk-digested entry to the
 * manifest under construction. */
static bool psw_manifest_add_file(struct vcs_package_manifest *manifest,
                                  const char *dir, const struct psw_file *f)
{
    char path[PATH_MAX];
    uint8_t *bytes = NULL;
    size_t len = 0;
    int n = snprintf(path, sizeof(path), "%s/%s", dir, f->leaf);
    bool ok = n > 0 && (size_t)n < sizeof(path) &&
              psw_read(path, (size_t)f->size + 1, &bytes, &len) &&
              len == f->size;
    uint32_t chunks =
        (uint32_t)((len + VCS_PACKAGE_CHUNK_BYTES - 1) / VCS_PACKAGE_CHUNK_BYTES);
    uint8_t *digests =
        ok ? zcl_malloc((size_t)chunks * 32, "plugin.swarm.digests") : NULL;
    ok = digests != NULL;
    for (uint32_t c = 0; c < chunks && ok; c++) {
        size_t off = (size_t)c * VCS_PACKAGE_CHUNK_BYTES;
        size_t cl = len - off;
        if (cl > VCS_PACKAGE_CHUNK_BYTES)
            cl = VCS_PACKAGE_CHUNK_BYTES;
        ok = vcs_package_chunk_hash(bytes + off, cl, digests + c * 32);
    }
    ok = ok && vcs_package_manifest_add(manifest, f->leaf, f->mode, len,
                                        digests, chunks);
    free(digests);
    free(bytes);
    return ok;
}

/* Re-read one file after the manifest landed and put its chunks under the
 * admitted root, so a file that changed mid-publish fails closed at
 * put_chunk. */
static enum vcs_package_store_result
psw_store_file_chunks(struct vcs_package_store *store, const uint8_t root[32],
                      const char *dir, const struct psw_file *f)
{
    char path[PATH_MAX];
    uint8_t *bytes = NULL;
    size_t len = 0;
    int n = snprintf(path, sizeof(path), "%s/%s", dir, f->leaf);
    if (n <= 0 || (size_t)n >= sizeof(path) ||
        !psw_read(path, (size_t)f->size + 1, &bytes, &len) ||
        len != f->size)
        return VCS_PACKAGE_STORE_ERR_IO;
    enum vcs_package_store_result r = VCS_PACKAGE_STORE_OK;
    for (size_t off = 0; off < len && r == VCS_PACKAGE_STORE_OK;
         off += VCS_PACKAGE_CHUNK_BYTES) {
        size_t cl = len - off;
        if (cl > VCS_PACKAGE_CHUNK_BYTES)
            cl = VCS_PACKAGE_CHUNK_BYTES;
        r = vcs_package_store_put_chunk(
            store, root, f->leaf, (uint32_t)(off / VCS_PACKAGE_CHUNK_BYTES),
            bytes + off, cl);
    }
    free(bytes);
    return r;
}

static bool psw_set_has(const struct psw_set *set, const char *leaf)
{
    for (size_t i = 0; i < set->file_count; i++)
        if (strcmp(set->files[i].leaf, leaf) == 0)
            return true;
    return false;
}

/* The admission member is not in the publisher's directory. It is part of
 * the package so a replica, which never sees the release envelope a dist
 * publish files beside the chunks, can still host this set. */
static bool psw_manifest_add_admission(struct vcs_package_manifest *manifest)
{
    static const char text[] = VCS_PACKAGE_PLUGIN_ADMISSION_TEXT;
    uint8_t digest[32];
    size_t len = sizeof(text) - 1u;
    return vcs_package_chunk_hash((const uint8_t *)text, len, digest) &&
           vcs_package_manifest_add(manifest, VCS_PACKAGE_PLUGIN_ADMISSION_LEAF,
                                    VCS_PACKAGE_MODE_FILE, len, digest, 1);
}

static enum vcs_package_store_result
psw_store_admission(struct vcs_package_store *store, const uint8_t root[32])
{
    static const char text[] = VCS_PACKAGE_PLUGIN_ADMISSION_TEXT;
    return vcs_package_store_put_chunk(
        store, root, VCS_PACKAGE_PLUGIN_ADMISSION_LEAF, 0,
        (const uint8_t *)text, sizeof(text) - 1u);
}

/* Admit every file of the verified set into the store under one content.v2
 * manifest, then pin the root. */
static bool psw_store_publish(struct vcs_package_store *store,
                              const char *dir, struct psw_set *set,
                              uint8_t root[32], struct psw_fault *fault)
{
    struct vcs_package_manifest manifest;
    vcs_package_manifest_init(&manifest);
    bool admit = !psw_set_has(set, VCS_PACKAGE_PLUGIN_ADMISSION_LEAF);
    bool ok = true;
    for (size_t i = 0; i < set->file_count && ok; i++)
        ok = psw_manifest_add_file(&manifest, dir, &set->files[i]);
    ok = ok && (!admit || psw_manifest_add_admission(&manifest));
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    ok = ok && vcs_package_manifest_serialize(&manifest, &wire, &wire_len);
    vcs_package_manifest_free(&manifest);
    if (!ok) {
        psw_fault_set(fault, "PLUGIN_PUBLISH_LAYOUT",
                      "reduce the file set and retry",
                      "the package manifest could not be built");
        return false;
    }
    enum vcs_package_store_result r =
        vcs_package_store_put_manifest(store, wire, wire_len, root);
    free(wire);
    for (size_t i = 0; i < set->file_count && r == VCS_PACKAGE_STORE_OK; i++)
        r = psw_store_file_chunks(store, root, dir, &set->files[i]);
    if (r == VCS_PACKAGE_STORE_OK && admit)
        r = psw_store_admission(store, root);
    if (r == VCS_PACKAGE_STORE_OK && admit) {
        set->file_count++;
        set->total_bytes += sizeof(VCS_PACKAGE_PLUGIN_ADMISSION_TEXT) - 1u;
    }
    if (r == VCS_PACKAGE_STORE_OK)
        r = vcs_package_store_pin(store, root, true);
    if (r != VCS_PACKAGE_STORE_OK) {
        psw_fault_set(fault, "PLUGIN_PUBLISH_STORE",
                      "check the datadir store quota and free space, then "
                      "retry; admitted chunks are reused",
                      vcs_package_store_result_string(r));
        return false;
    }
    return true;
}

/* The publish preflight: the directory is the flat four-file plugin set,
 * self-consistent under the key its signature names, and its LICENSE is one
 * every node may serve. False with the fault naming the rule that refused. */
static bool psw_publish_verify(const char *dir, struct psw_set *set,
                               struct psw_fault *fault)
{
    return psw_scan(dir, set, false, "PLUGIN_PUBLISH_LAYOUT",
                    "publish the plugin pack output directory: LICENSE, NAME, "
                    "NAME.plugin.json and NAME.plugin.sig as flat regular "
                    "files, within the package size cap",
                    fault) &&
           psw_verify_set(dir, set, "PLUGIN_PUBLISH_LAYOUT",
                          "publish the plugin pack output directory as --dir",
                          fault) &&
           psw_license_serveable(dir, fault);
}

/* The announce opt-in: publish the plugin's POINTER and PROVIDER records
 * naming the root into the plugin DHT namespace through this node's running
 * overlay service. The publish stands when the overlay is unreachable; the
 * refusal then names the incomplete announcement, not the store admission.
 * False only when a refusal was set on the reply. */
static bool psw_announce(struct zcl_command_reply *reply, const char *root_hex)
{
    int64_t now = platform_time_wall_unix();
    char ptoken[65], vtoken[65], perr[64] = {0}, verr[64] = {0};
    bool time_ok = now > 0 && now <= INT64_MAX - PSW_RECORD_SECONDS;
    bool pointer = time_ok && zcl_native_zcode_publish_record(
        "pointer", PSW_PLUGIN_NAMESPACE, root_hex, root_hex, now, now,
        now + PSW_RECORD_SECONDS, ptoken, perr, sizeof(perr));
    bool provider = time_ok && zcl_native_zcode_publish_record(
        "provider", PSW_PLUGIN_NAMESPACE, NULL, root_hex, now, now,
        now + PSW_RECORD_SECONDS, vtoken, verr, sizeof(verr));
    (void)json_push_kv_bool(&reply->data, "pointer_announced", pointer);
    (void)json_push_kv_bool(&reply->data, "provider_announced", provider);
    if (pointer && provider)
        return true;
    psw_refuse(reply, "PLUGIN_ANNOUNCE_INCOMPLETE",
               "the plugin is published and pinned; once this node's DHT "
               "overlay is up, retry the announcement with zcode network "
               "publish in the zclassic23.plugin namespace",
               "publish", perr[0] ? perr : verr);
    reply->error.mutated = true;
    return false;
}

void zcl_native_handle_plugin_publish(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *dir = plg_str(request, "dir");
    if (!dir || !dir[0]) {
        psw_refuse(reply, plugin_status_code(PLUGIN_ERR_ARGUMENT),
                   plugin_status_next_action(PLUGIN_ERR_ARGUMENT), "publish",
                   "dir is required: the plugin pack output directory");
        return;
    }
    struct psw_set set;
    struct psw_fault fault = {0};
    if (!psw_publish_verify(dir, &set, &fault)) {
        psw_refuse_fault(reply, &fault, "publish");
        return;
    }
    char zcode_dir[PATH_MAX];
    bool store_owned = false;
    struct vcs_package_store *store =
        psw_store_open(request, zcode_dir, sizeof(zcode_dir), &store_owned);
    if (!store) {
        psw_refuse(reply, "PLUGIN_PUBLISH_NO_STORE",
                   "pass --datadir with a writable zcode package store",
                   "publish", dir);
        return;
    }
    uint8_t root[32];
    bool ok = psw_store_publish(store, dir, &set, root, &fault);
    psw_store_close(store, store_owned);
    if (!ok) {
        psw_refuse_fault(reply, &fault, "publish");
        return;
    }
    char root_hex[65];
    zcl_hex_encode(root, 32, root_hex);
    json_set_object(&reply->data);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.plugin_publish.v1");
    (void)json_push_kv_str(&reply->data, "package_root", root_hex);
    (void)json_push_kv_str(&reply->data, "name", set.manifest.name);
    (void)json_push_kv_str(&reply->data, "version", set.manifest.version);
    (void)json_push_kv_int(&reply->data, "interface_version",
                           set.manifest.interface_version);
    (void)json_push_kv_str(&reply->data, "generation",
                           set.manifest.generation);
    (void)json_push_kv_str(&reply->data, "publisher", set.publisher);
    plg_push_capabilities(&reply->data, set.manifest.capabilities);
    (void)json_push_kv_int(&reply->data, "files", (int64_t)set.file_count);
    (void)json_push_kv_int(&reply->data, "bytes", (int64_t)set.total_bytes);
    (void)json_push_kv_bool(&reply->data, "pinned", true);
    (void)json_push_kv_str(&reply->data, "store", zcode_dir);
    reply->error.mutated = true;
    /* Explicit operator opt-in: announce the root on the DHT overlay. The
     * publish stands when the overlay is unreachable; the refusal then names
     * the incomplete announcement, not the store admission. */
    const struct json_value *an =
        request->input ? json_get(request->input, "announce") : NULL;
    if (an && json_get_bool(an) && !psw_announce(reply, root_hex))
        return;
    struct json_value follow_up;
    json_init(&follow_up);
    json_set_object(&follow_up);
    char manifest_path[PATH_MAX];
    if (snprintf(manifest_path, sizeof(manifest_path), "%s/%s.plugin.json",
                 dir, set.name) < (int)sizeof(manifest_path) &&
        json_push_kv_str(&follow_up, "root", root_hex) &&
        json_push_kv_str(&follow_up, "manifest", manifest_path))
        psw_push_next(reply, "plugin.index_add",
                      "sign the discovery entry: add key (the publisher "
                      "signing key) and index (the index directory)",
                      &follow_up);
    json_free(&follow_up);
}

/* ── plugin.fetch ─────────────────────────────────────────────────────── */

/* True when the receiver's publisher key file lists the claimed publisher.
 * A missing HOME or an unreadable file reports unknown, never pinned. */
static int psw_pinned(const char publisher[65])
{
    const char *home = getenv("HOME");
    if (!home || home[0] != '/')
        return -1;
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/.z23/plugins/publisher_keys",
                     home);
    if (n < 0 || (size_t)n >= sizeof(path))
        return -1;
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;
    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';
        if (len == 64 && strcmp(line, publisher) == 0)
            found = 1;
    }
    (void)fclose(f);
    return found;
}

static void psw_fetch_progress(struct zcl_command_reply *reply,
                               const char *root_hex, bool live,
                               struct vcs_swarm_engine *engine,
                               const uint8_t root[32])
{
    struct vcs_swarm_download_status st;
    memset(&st, 0, sizeof(st));
    bool have = vcs_swarm_engine_download_status(engine, root, &st);
    json_set_object(&reply->data);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.plugin_fetch.v1");
    (void)json_push_kv_str(&reply->data, "root", root_hex);
    (void)json_push_kv_bool(&reply->data, "complete", false);
    (void)json_push_kv_bool(&reply->data, "live", live);
    (void)json_push_kv_str(&reply->data, "state",
                           have ? vcs_swarm_download_state_string(st.state)
                                : "inactive");
    if (have && st.rule)
        (void)json_push_kv_str(&reply->data, "rule", st.rule);
    (void)json_push_kv_int(&reply->data, "present_chunks",
                           have ? (int64_t)st.present_chunks : 0);
    (void)json_push_kv_int(&reply->data, "total_chunks",
                           have ? (int64_t)st.total_chunks : 0);
    (void)json_push_kv_int(&reply->data, "present_bytes",
                           have ? (int64_t)st.present_bytes : 0);
    (void)json_push_kv_int(&reply->data, "fetched_bytes",
                           have ? (int64_t)st.fetched_bytes : 0);
    (void)json_push_kv_str(
        &reply->data, "hint",
        live ? "download in progress; re-run plugin fetch until complete is "
               "true"
             : "no live swarm engine in this process: the resumable record is "
               "stored and a node started with -packagehost=1 resumes it; "
               "re-run plugin fetch then");
}

/* Borrow the node-global engine when this process hosts one; otherwise build
 * a one-shot engine over the same store so the fetch record still persists
 * and a later hosting boot resumes it. */
static struct vcs_swarm_engine *psw_fetch_engine(
    struct vcs_package_store *store, const char *zcode_dir,
    struct vcs_service_book **book_out, bool *live_out)
{
    struct vcs_swarm_engine *engine = vcs_swarm_engine_global();
    *live_out = engine != NULL;
    *book_out = NULL;
    if (!engine) {
        *book_out = vcs_service_book_load(zcode_dir);
        engine =
            vcs_swarm_engine_create(store, *book_out, zcode_dir, NULL, NULL);
    }
    return engine;
}

static int64_t psw_fetch_day(const struct zcl_command_request *request)
{
    int64_t day = (int64_t)platform_time_wall_unix() / 86400;
    const struct json_value *dv = json_get(request->input, "day");
    if (dv && dv->type == JSON_INT)
        day = json_get_int(dv);
    return day;
}

static bool psw_fetch_complete(enum vcs_swarm_fetch_result r, bool have_status,
                               const struct vcs_swarm_download_status *st)
{
    return r == VCS_SWARM_FETCH_ALREADY_COMPLETE ||
           (have_status && st->state == VCS_SWARM_DL_COMPLETE);
}

static const char *psw_fetch_refusal_code(enum vcs_swarm_fetch_result r)
{
    if (r == VCS_SWARM_FETCH_NO_STORE)
        return "PLUGIN_FETCH_NO_STORE";
    if (r == VCS_SWARM_FETCH_FULL)
        return "PLUGIN_FETCH_SLOTS_FULL";
    if (r == VCS_SWARM_FETCH_RECORD_IO)
        return "PLUGIN_FETCH_RECORD_IO";
    if (r == VCS_SWARM_FETCH_BAD_INPUT)
        return "PLUGIN_FETCH_BAD_ROOT";
    return "PLUGIN_FETCH_REFUSED";
}

/* Report an incomplete fetch. The progress report needs the engine; with
 * the one-shot engine already freed, report from the persisted record state
 * instead. */
static void psw_fetch_stalled_reply(
    struct zcl_command_reply *reply, const char *root_hex, bool live,
    bool have_status, const struct vcs_swarm_download_status *st,
    const uint8_t root[32])
{
    if (live) {
        psw_fetch_progress(reply, root_hex, true, vcs_swarm_engine_global(),
                           root);
        return;
    }
    json_set_object(&reply->data);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.plugin_fetch.v1");
    (void)json_push_kv_str(&reply->data, "root", root_hex);
    (void)json_push_kv_bool(&reply->data, "complete", false);
    (void)json_push_kv_bool(&reply->data, "live", false);
    (void)json_push_kv_str(
        &reply->data, "state",
        have_status ? vcs_swarm_download_state_string(st->state) : "inactive");
    (void)json_push_kv_str(
        &reply->data, "hint",
        "no live swarm engine in this process: the resumable record is "
        "stored and a node started with -packagehost=1 resumes it; re-run "
        "plugin fetch then");
}

/* Check the completed package out to dir. On refusal the reply is filled
 * and false returned. */
static bool psw_fetch_checkout(struct vcs_package_store *store,
                               const uint8_t root[32], const char *dir,
                               struct vcs_package_checkout_metrics *metrics_out,
                               struct zcl_command_reply *reply,
                               const char *root_hex)
{
    enum vcs_package_checkout_result cr =
        vcs_package_checkout(store, root, dir, metrics_out);
    if (cr == VCS_PACKAGE_CHECKOUT_OK)
        return true;
    const char *code = "PLUGIN_FETCH_INCOMPLETE";
    const char *next =
        "re-run plugin fetch: the swarm re-downloads the missing chunk";
    if (cr == VCS_PACKAGE_CHECKOUT_CHUNK) {
        code = "PLUGIN_FETCH_CORRUPT";
        next = "a stored chunk failed its committed hash and was "
               "quarantined; re-run plugin fetch to repair from a peer";
    } else if (cr == VCS_PACKAGE_CHECKOUT_DESTINATION) {
        code = "PLUGIN_FETCH_DESTINATION";
        next = "choose an empty --dir; a checkout destination is created "
               "and never overwritten";
    } else if (cr == VCS_PACKAGE_CHECKOUT_MANIFEST) {
        code = "PLUGIN_FETCH_MANIFEST";
        next = "the tracked manifest does not parse; check the root and "
               "the store";
    }
    psw_refuse(reply, code, next, "fetch", root_hex);
    return false;
}

/* Validate the fetch arguments. On refusal the reply is already filled. */
static bool psw_fetch_args(const struct zcl_command_request *request,
                           uint8_t root[32], const char **root_hex_out,
                           const char **dir_out,
                           struct zcl_command_reply *reply)
{
    const char *root_hex = plg_str(request, "root");
    const char *dir = plg_str(request, "dir");
    if (!root_hex || !zcl_hex_decode(root_hex, root, 32)) {
        psw_refuse(reply, "PLUGIN_FETCH_BAD_ROOT",
                   "pass the 64-hex package root from plugin publish or a "
                   "verified plugin index entry",
                   "fetch", root_hex ? root_hex : "");
        return false;
    }
    if (!dir || !dir[0]) {
        psw_refuse(reply, plugin_status_code(PLUGIN_ERR_ARGUMENT),
                   plugin_status_next_action(PLUGIN_ERR_ARGUMENT), "fetch",
                   "dir is required: the checkout destination, created by "
                   "the fetch and never overwritten");
        return false;
    }
    *root_hex_out = root_hex;
    *dir_out = dir;
    return true;
}

/* The complete-and-verified report: what the bytes say, and whether the
 * receiver's own publisher_keys already pins the signing key. */
static void psw_fetch_complete_reply(
    struct zcl_command_reply *reply, const char *root_hex, bool live,
    const struct psw_set *set,
    const struct vcs_package_checkout_metrics *metrics, const char *dir)
{
    int pinned = psw_pinned(set->publisher);
    json_set_object(&reply->data);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.plugin_fetch.v1");
    (void)json_push_kv_str(&reply->data, "root", root_hex);
    (void)json_push_kv_bool(&reply->data, "complete", true);
    (void)json_push_kv_bool(&reply->data, "live", live);
    (void)json_push_kv_str(&reply->data, "name", set->manifest.name);
    (void)json_push_kv_str(&reply->data, "version", set->manifest.version);
    (void)json_push_kv_int(&reply->data, "interface_version",
                           set->manifest.interface_version);
    (void)json_push_kv_str(&reply->data, "generation",
                           set->manifest.generation);
    (void)json_push_kv_str(&reply->data, "publisher", set->publisher);
    (void)json_push_kv_str(&reply->data, "publisher_status",
                           pinned > 0 ? "pinned"
                                      : pinned == 0 ? "unpinned" : "unknown");
    plg_push_capabilities(&reply->data, set->manifest.capabilities);
    (void)json_push_kv_int(&reply->data, "files", (int64_t)metrics->files);
    (void)json_push_kv_int(&reply->data, "bytes", (int64_t)metrics->bytes);
    (void)json_push_kv_str(&reply->data, "dir", dir);
    reply->error.mutated = true;
    struct json_value follow_up;
    json_init(&follow_up);
    json_set_object(&follow_up);
    char manifest_path[PATH_MAX];
    if (snprintf(manifest_path, sizeof(manifest_path), "%s/%s.plugin.json",
                 dir, set->name) < (int)sizeof(manifest_path) &&
        json_push_kv_str(&follow_up, "manifest", manifest_path))
        psw_push_next(reply, "plugin.install",
                      "owner step: install verifies the publisher key "
                      "against your publisher_keys; this fetch installed "
                      "and ran nothing",
                      &follow_up);
    json_free(&follow_up);
}

/* Optional DHT provider discovery, mirroring zcode.package.fetch: a command
 * process holds no engine, so when the operator names a namespace the running
 * node routes the exact root to authenticated providers and starts the
 * bounded swarm fetch in-process. The reply then names the route, not a
 * completed download: re-run plugin fetch once the store holds the package
 * to verify and check out. Same boundary naming as package fetch — a routed
 * refusal keeps the daemon's own code; an unrouted root names discovery. */
static void psw_fetch_route(struct zcl_command_reply *reply,
                            const char *root_hex, const char *dir,
                            const char *namespace_name)
{
    struct json_value selector, routed;
    json_init(&selector);
    json_init(&routed);
    json_set_object(&selector);
    bool selector_ok =
        json_push_kv_str(&selector, "kind", "provider") &&
        json_push_kv_str(&selector, "namespace", namespace_name) &&
        json_push_kv_str(&selector, "transport_root", root_hex);
    uint32_t records = 0;
    bool routed_ok =
        selector_ok && zcl_native_zcode_provider_discover_and_route(
                           &selector, &routed, &records);
    json_free(&selector);
    if (routed_ok) {
        json_copy(&reply->data, &routed);
        json_free(&routed);
        (void)json_push_kv_str(&reply->data, "schema", "zcl.plugin_fetch.v1");
        (void)json_push_kv_str(&reply->data, "root", root_hex);
        (void)json_push_kv_bool(&reply->data, "routed", true);
        (void)json_push_kv_bool(&reply->data, "live", true);
        (void)json_push_kv_int(&reply->data, "provider_records",
                               (int64_t)records);
        struct json_value again;
        json_init(&again);
        json_set_object(&again);
        if (json_push_kv_str(&again, "root", root_hex) &&
            json_push_kv_str(&again, "dir", dir))
            psw_push_next(reply, "plugin.fetch",
                          "re-run once the node's download completes: it "
                          "verifies the signature and checks the set out",
                          &again);
        json_free(&again);
        return;
    }
    const char *route_code = json_get_str(json_get(&routed, "code"));
    const char *route_error = json_get_str(json_get(&routed, "error"));
    const char *fetch_result =
        json_get_str(json_get(&routed, "fetch_result"));
    char detail[224];
    if (route_code && route_code[0]) {
        char code_copy[64];
        (void)snprintf(code_copy, sizeof(code_copy), "%s", route_code);
        (void)snprintf(detail, sizeof(detail),
                       "%s: %s (fetch=%s, %lu provider record(s))", code_copy,
                       route_error ? route_error : "no reason given",
                       fetch_result ? fetch_result : "none",
                       (unsigned long)records);
        json_free(&routed);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED, code_copy, "fetch",
                               false, false, detail, "plugin.fetch");
        (void)snprintf(reply->error.next_action,
                       sizeof(reply->error.next_action),
                       "the running node routed the root and then refused "
                       "under its own name; inspect that refusal");
        reply->error.human_action_required = true;
        return;
    }
    (void)snprintf(detail, sizeof(detail),
                   "no authenticated DHT provider routed the root: "
                   "records=%lu authenticated=%lld denied=%lld pending=%lld",
                   (unsigned long)records,
                   (long long)json_get_int(
                       json_get(&routed, "authenticated_providers")),
                   (long long)json_get_int(json_get(&routed, "policy_denied")),
                   (long long)json_get_int(
                       json_get(&routed, "reachability_pending")));
    json_free(&routed);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                           ZCL_COMMAND_EXIT_TRANSIENT,
                           "PLUGIN_PROVIDER_DISCOVERY_FAILED", "fetch", true,
                           false, detail, "plugin.fetch");
    (void)snprintf(reply->error.next_action,
                   sizeof(reply->error.next_action),
                   "wait for a publisher announce, connect to the publisher "
                   "directly, or allow zclassic23.plugin with zcode network "
                   "policy mutate, then retry");
    reply->error.human_action_required = true;
}

/* The download is complete: check the tree out, verify the plugin set under
 * the key its signature names, and report. The verified checkout stays on
 * disk as evidence either way; the store keeps the package and nothing was
 * installed. */
static void psw_fetch_finish(struct vcs_package_store *store,
                             const uint8_t root[32], const char *dir,
                             const char *root_hex, bool live,
                             struct zcl_command_reply *reply)
{
    struct vcs_package_checkout_metrics metrics;
    if (!psw_fetch_checkout(store, root, dir, &metrics, reply, root_hex))
        return;
    struct psw_set set;
    struct psw_fault fault = {0};
    bool verified =
        psw_scan(dir, &set, true, "PLUGIN_FETCH_LAYOUT",
                 "the fetched package is not a plugin set: publish LICENSE, "
                 "NAME, NAME.plugin.json and NAME.plugin.sig",
                 &fault) &&
        psw_verify_set(dir, &set, "PLUGIN_FETCH_LAYOUT",
                       "the fetched package is not a plugin set: publish "
                       "LICENSE, NAME, NAME.plugin.json and NAME.plugin.sig",
                       &fault);
    if (!verified) {
        psw_refuse_fault(reply, &fault, "fetch");
        return;
    }
    psw_fetch_complete_reply(reply, root_hex, live, &set, &metrics, dir);
}

void zcl_native_handle_plugin_fetch(const struct zcl_command_request *request,
                                    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    uint8_t root[32];
    const char *root_hex = NULL;
    const char *dir = NULL;
    if (!psw_fetch_args(request, root, &root_hex, &dir, reply))
        return;
    /* A command process cannot share the daemon's node-global engine. When
     * the operator supplies a DHT namespace, route the exact root through
     * the running node instead: provider discovery selects authenticated
     * live providers and the daemon starts the bounded swarm fetch
     * in-process. A live engine drives the download itself below. */
    const char *namespace_name = plg_str(request, "namespace");
    if (!vcs_swarm_engine_global() && namespace_name && namespace_name[0]) {
        psw_fetch_route(reply, root_hex, dir, namespace_name);
        return;
    }
    char zcode_dir[PATH_MAX];
    bool store_owned = false;
    struct vcs_package_store *store =
        psw_store_open(request, zcode_dir, sizeof(zcode_dir), &store_owned);
    if (!store) {
        psw_refuse(reply, "PLUGIN_FETCH_NO_STORE",
                   "pass --datadir with a writable zcode package store",
                   "fetch", root_hex);
        return;
    }
    struct vcs_service_book *book = NULL;
    bool live = false;
    struct vcs_swarm_engine *engine =
        psw_fetch_engine(store, zcode_dir, &book, &live);
    if (!engine) {
        vcs_service_book_free(book);
        psw_store_close(store, store_owned);
        psw_refuse(reply, "PLUGIN_FETCH_ENGINE",
                   "the swarm engine failed to initialize; check the datadir",
                   "fetch", root_hex);
        return;
    }
    uint64_t now = (uint64_t)platform_time_wall_unix();
    enum vcs_swarm_fetch_result r =
        vcs_swarm_engine_fetch(engine, root, psw_fetch_day(request), now);
    struct vcs_swarm_download_status st;
    memset(&st, 0, sizeof(st));
    bool have_status = vcs_swarm_engine_download_status(engine, root, &st);
    bool complete = psw_fetch_complete(r, have_status, &st);
    if (!live) {
        vcs_swarm_engine_free(engine);
        vcs_service_book_free(book);
    }
    if (r != VCS_SWARM_FETCH_OK && r != VCS_SWARM_FETCH_ALREADY_COMPLETE) {
        psw_store_close(store, store_owned);
        psw_refuse(reply, psw_fetch_refusal_code(r),
                   "inspect the named rule and retry", "fetch",
                   vcs_swarm_fetch_result_string(r));
        return;
    }
    if (!complete) {
        psw_fetch_stalled_reply(reply, root_hex, live, have_status, &st,
                                root);
        psw_store_close(store, store_owned);
        return;
    }

    psw_fetch_finish(store, root, dir, root_hex, live, reply);
    psw_store_close(store, store_owned);
}
