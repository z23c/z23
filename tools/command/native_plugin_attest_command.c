/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: plugin.attest, plugin.attest_verify and plugin.reproduce. A builder
 *          signs the image bytes it observed; the verifier accepts a manifest
 *          only when K distinct pinned builder keys attest its sha3_512 for one
 *          source root. Reproduction re-derives the package root, reruns
 *          lab.promote on exported inputs and attests only an exact image and
 *          manifest match. These leaves never
 *          install, switch, fetch or contact the daemon; only reproduce starts
 *          local compiler and confined-case processes. All are owner-local. */

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "command/lab_priv.h"
#include "command/native_command.h"

#include "json/json.h"
#include "plugin/plugin_attest.h"
#include "platform/temp_directory.h"
#include "util/file_io.h"
#include "util/file_tree_ops.h"
#include "util/path_util.h"
#include "util/write_all.h"
#include "vcs/package_manifest.h"
#include "vcs/package_store.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void pat_refuse(struct zcl_command_reply *reply, const char *code,
                       const char *next_action, const char *what, const char *evidence)
{
    char message[192];
    (void)snprintf(message, sizeof(message), "plugin %s refused: %s", what, code);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                           code, what, false, false, message, evidence ? evidence : "");
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action), "%s",
                   next_action);
    reply->error.human_action_required = true;
}

/* An upstream store failure keeps the store's own code and next action. */
static void pat_refuse_status(struct zcl_command_reply *reply, enum plugin_attest_status st,
                              enum plugin_status cause, const char *what, const char *evidence)
{
    if (st == PLUGIN_ATTEST_UPSTREAM)
        pat_refuse(reply, plugin_status_code(cause), plugin_status_next_action(cause),
                   what, evidence);
    else
        pat_refuse(reply, plugin_attest_status_code(st),
                   plugin_attest_status_next_action(st), what, evidence);
}

void zcl_native_handle_plugin_attest(const struct zcl_command_request *request,
                                     struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    struct plugin_attest_request in = {
        .image_path = lab_in_str(request, "image"),
        .key_path = lab_in_str(request, "key"),
        .name = lab_in_str(request, "name"),
        .version = lab_in_str(request, "version"),
        .source_root = lab_in_str(request, "source-root"),
        .toolchain = lab_in_str(request, "toolchain"),
        .dir = lab_in_str(request, "dir"),
    };
    struct plugin_attest_result out;
    enum plugin_attest_status st = plugin_attest_make(&in, &out);
    if (st != PLUGIN_ATTEST_OK) {
        pat_refuse_status(reply, st, out.cause, "attest", in.image_path);
        return;
    }
    json_set_object(&reply->data);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.plugin_attest.v1");
    (void)json_push_kv_str(&reply->data, "name", out.record.name);
    (void)json_push_kv_str(&reply->data, "version", out.record.version);
    (void)json_push_kv_str(&reply->data, "source_root", out.record.source_root);
    (void)json_push_kv_str(&reply->data, "toolchain", out.record.toolchain);
    (void)json_push_kv_str(&reply->data, "image_sha3_512", out.record.image);
    (void)json_push_kv_str(&reply->data, "builder_key", out.record.builder_key);
    (void)json_push_kv_str(&reply->data, "attestation", out.path);
    reply->error.mutated = true;
}

/* A JSON integer, or a decimal string: any other shape is a refusal. */
static bool pat_threshold(const struct zcl_command_request *request, int64_t *out)
{
    const struct json_value *v = request->input ? json_get(request->input, "threshold") : NULL;
    if (v && v->type == JSON_INT) {
        *out = json_get_int(v);
        return true;
    }
    const char *s = v && v->type == JSON_STR ? json_get_str(v) : NULL;
    char *end = NULL;
    if (!s || !*s)
        return false;
    errno = 0;
    long long n = strtoll(s, &end, 10);
    if (errno != 0 || *end != '\0')
        return false;
    *out = n;
    return true;
}

static void pat_push_report(struct json_value *data, const struct plugin_attest_report *r)
{
    struct json_value builders;
    json_init(&builders);
    json_set_array(&builders);
    for (uint32_t i = 0; i < r->attested; i++) {
        struct json_value s;
        json_init(&s);
        json_set_str(&s, r->builders[i]);
        (void)json_push_back(&builders, &s);
        json_free(&s);
    }
    json_set_object(data);
    (void)json_push_kv_str(data, "schema", "zcl.plugin_attest_verify.v1");
    (void)json_push_kv_bool(data, "accepted", true);
    (void)json_push_kv_str(data, "name", r->name);
    (void)json_push_kv_str(data, "version", r->version);
    (void)json_push_kv_str(data, "source_root", r->source_root);
    (void)json_push_kv_str(data, "image_sha3_512", r->image);
    (void)json_push_kv_int(data, "threshold", r->threshold);
    (void)json_push_kv_int(data, "pinned", r->pinned);
    (void)json_push_kv_int(data, "attested", r->attested);
    (void)json_push_kv_int(data, "toolchains", r->toolchains);
    (void)json_push_kv(data, "builders", &builders);
    json_free(&builders);
}

static void pat_evidence(const struct plugin_attest_report *r, char *out, size_t cap)
{
    (void)snprintf(out, cap, "file=%s threshold=%u pinned=%u attested=%u", r->file,
                   (unsigned)r->threshold, (unsigned)r->pinned, (unsigned)r->attested);
}

void zcl_native_handle_plugin_attest_verify(const struct zcl_command_request *request,
                                            struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    int64_t k = 0;
    struct plugin_attest_report *rep = zcl_malloc(sizeof(*rep), "plugin.attest.report");
    char evidence[512];
    if (!rep) {
        pat_refuse_status(reply, PLUGIN_ATTEST_IO, PLUGIN_OK, "attest_verify", "");
        return;
    }
    memset(rep, 0, sizeof(*rep));
    enum plugin_attest_status st =
        pat_threshold(request, &k)
            ? plugin_attest_verify_dir(lab_in_str(request, "manifest"),
                                       lab_in_str(request, "attestations"),
                                       lab_in_str(request, "builders"), k,
                                       lab_in_str(request, "source-root"), rep)
            : PLUGIN_ATTEST_THRESHOLD_INVALID;
    pat_evidence(rep, evidence, sizeof(evidence));
    if (st != PLUGIN_ATTEST_OK)
        pat_refuse_status(reply, st, rep->cause, "attest_verify", evidence);
    else
        pat_push_report(&reply->data, rep);
    free(rep);
}

#define PR_PATH_MAX 4096
#define PR_TEXT_MAX 65536

struct pr_ctx {
    const char *dir, *root, *key, *out, *toolchain;
    char name[PLUGIN_NAME_MAX + 1], publisher[65];
    struct plugin_manifest manifest;
    char manifest_path[PR_PATH_MAX], image[PR_PATH_MAX];
    char source[PR_PATH_MAX], cases[PR_PATH_MAX];
};

struct pr_rebuilt {
    char sha[PLUGIN_HEX_SHA3_512 + 1], generation[PLUGIN_HEX_SHA3_512 + 1];
    char builder[65], manifest[PR_PATH_MAX], release_command[320];
    int64_t cases_passed;
};

#if defined(__linux__)
#if defined(ZCL_TESTING)
static void (*pr_capture_test_hook)(void *);
static void *pr_capture_test_arg;
void zcl_test_plugin_reproduce_capture_hook(void (*hook)(void *), void *arg);
void zcl_test_plugin_reproduce_capture_hook(void (*hook)(void *), void *arg)
{
    pr_capture_test_hook = hook;
    pr_capture_test_arg = arg;
}
#endif
/* Copy no more than the size observed on the opened regular file. */
static bool pr_capture_bytes(int in, int out, uint64_t size, uint64_t *copied)
{
    char buf[16384];
    *copied = 0;
    for (;;) {
        ssize_t n = read(in, buf, sizeof(buf));
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0)
            return false;
        if (n == 0)
            return *copied == size;
        *copied += (uint64_t)n;
        if (*copied > size || !zcl_write_all(out, buf, (size_t)n))
            return false;
    }
}

/* Capture a bounded flat package before verifying and compiling it. */
static bool pr_capture_file(int from, int to, const char *name, uint64_t *total)
{
    int in = openat(from, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (in < 0)
        return false;
    struct stat st;
    bool ok = fstat(in, &st) == 0 && S_ISREG(st.st_mode) && st.st_size >= 0 &&
              (uint64_t)st.st_size <= VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES - *total;
    int out = ok ? openat(to, name, O_WRONLY | O_CREAT | O_EXCL |
                          O_CLOEXEC | O_NOFOLLOW, 0600) : -1;
    uint64_t copied = 0;
    ok = ok && out >= 0 && pr_capture_bytes(in, out, (uint64_t)st.st_size, &copied);
    *total += copied;
    if (out >= 0 && close(out) != 0)
        ok = false;
    if (close(in) != 0)
        ok = false;
    return ok;
}

static bool pr_capture(const char *source, const char *scratch)
{
    DIR *dir = opendir(source);
    int to = open(scratch, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    bool ok = dir != NULL && to >= 0;
    uint64_t total = 0;
    size_t count = 0;
    errno = 0;
    for (struct dirent *e = dir ? readdir(dir) : NULL; e && ok; e = readdir(dir)) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
            continue;
        ok = ++count <= VCS_PACKAGE_MAX_FILES &&
             pr_capture_file(dirfd(dir), to, e->d_name, &total);
        errno = 0;
    }
    if (errno != 0)
        ok = false;
    if (dir && closedir(dir) != 0)
        ok = false;
    if (to >= 0 && close(to) != 0)
        ok = false;
    return ok && count > 0;
}
#endif

static bool pr_find_manifest(struct pr_ctx *c)
{
    DIR *d = opendir(c->dir);
    bool found = false, ok = d != NULL;
    for (struct dirent *e = d ? readdir(d) : NULL; e && ok; e = readdir(d)) {
        size_t len = strlen(e->d_name), suffix = strlen(".plugin.json");
        if (len <= suffix || strcmp(e->d_name + len - suffix, ".plugin.json") != 0)
            continue;
        size_t name_len = len - suffix;
        if (found || name_len > PLUGIN_NAME_MAX ||
            snprintf(c->manifest_path, sizeof(c->manifest_path), "%s/%s",
                     c->dir, e->d_name) >= (int)sizeof(c->manifest_path)) {
            ok = false;
            break;
        }
        memcpy(c->name, e->d_name, name_len);
        c->name[name_len] = '\0';
        found = true;
    }
    if (d && closedir(d) != 0)
        ok = false;
    return ok && found;
}

static bool pr_read(const char *path, char **bytes, size_t *len)
{
    return zcl_read_whole_file_text(path, PR_TEXT_MAX, bytes, len,
                                    "plugin.reproduce") &&
           *len > 0;
}

static bool pr_signature(struct pr_ctx *c, struct zcl_command_reply *reply)
{
    char sig_path[PR_PATH_MAX], *manifest = NULL, *sig = NULL;
    size_t manifest_len = 0, sig_len = 0;
    int n = snprintf(sig_path, sizeof(sig_path), "%s/%s.plugin.sig", c->dir, c->name);
    bool read = n > 0 && (size_t)n < sizeof(sig_path) &&
                pr_read(c->manifest_path, &manifest, &manifest_len) &&
                pr_read(sig_path, &sig, &sig_len);
    enum plugin_status st = read
        ? plugin_verify_manifest_self(manifest, manifest_len, sig, sig_len,
                                      &c->manifest, c->publisher)
        : PLUGIN_ERR_IO;
    free(manifest);
    free(sig);
    if (st == PLUGIN_OK)
        return true;
    pat_refuse(reply, plugin_status_code(st), plugin_status_next_action(st),
               "reproduce", c->manifest_path);
    return false;
}

static bool pr_paths(struct pr_ctx *c, struct zcl_command_reply *reply)
{
    int source_n = snprintf(c->source, sizeof(c->source), "%s/%s.c", c->dir, c->name);
    if (strcmp(c->name, c->manifest.name) == 0 && source_n >= 0 &&
        (size_t)source_n < sizeof(c->source) &&
        zcl_path_join(c->image, sizeof(c->image), c->dir, c->name) &&
        zcl_path_join(c->cases, sizeof(c->cases), c->dir, "cases.json"))
        return true;
    pat_refuse(reply, "PLUGIN_REPRODUCE_LAYOUT",
               "use a flat fetched plugin directory with bounded member names",
               "reproduce", c->name);
    return false;
}

static bool pr_image(struct pr_ctx *c, struct zcl_command_reply *reply)
{
    char digest[PLUGIN_HEX_SHA3_512 + 1];
    enum plugin_status st = plugin_hash_file(c->image, digest);
    if (st == PLUGIN_OK && strcmp(digest, c->manifest.exe_sha3) == 0)
        return true;
    enum plugin_status cause = st == PLUGIN_OK ? PLUGIN_ERR_EXE_HASH : st;
    pat_refuse(reply, plugin_status_code(cause), plugin_status_next_action(cause),
               "reproduce", c->image);
    return false;
}

static bool pr_inputs(struct pr_ctx *c, struct zcl_command_reply *reply)
{
    if (c->manifest.interface_version != 2) {
        pat_refuse(reply, "PLUGIN_REPRODUCE_INTERFACE",
                   "only interface 2 plugins exported by lab.promote can be reproduced",
                   "reproduce", c->manifest_path);
        return false;
    }
    if (access(c->source, R_OK) != 0 || access(c->cases, R_OK) != 0) {
        pat_refuse(reply, "PLUGIN_REPRODUCE_INPUT",
                   "publish with lab.promote include-source so NAME.c and cases.json travel with the pack",
                   "reproduce", c->source);
        return false;
    }
    return true;
}

static bool pr_manifest_add_file(const struct pr_ctx *c,
                                 struct vcs_package_manifest *manifest,
                                 const char *leaf)
{
    char path[PR_PATH_MAX];
    struct stat st;
    if (!zcl_path_join(path, sizeof(path), c->dir, leaf) ||
        lstat(path, &st) != 0 || !S_ISREG(st.st_mode))
        return false;
    uint8_t *bytes = NULL;
    size_t len = 0;
    bool ok = zcl_read_whole_file(path, 64u * 1024u * 1024u, &bytes, &len,
                                  "plugin.reproduce.root");
    uint32_t chunks = (uint32_t)((len + VCS_PACKAGE_CHUNK_BYTES - 1) /
                                 VCS_PACKAGE_CHUNK_BYTES);
    uint8_t *hashes = chunks ? zcl_calloc(chunks, 32, "plugin.reproduce.hashes")
                             : NULL;
    ok = ok && (chunks == 0 || hashes != NULL);
    for (uint32_t i = 0; ok && i < chunks; i++) {
        size_t off = (size_t)i * VCS_PACKAGE_CHUNK_BYTES;
        size_t cl = len - off;
        if (cl > VCS_PACKAGE_CHUNK_BYTES)
            cl = VCS_PACKAGE_CHUNK_BYTES;
        ok = vcs_package_chunk_hash(bytes + off, cl, hashes + (size_t)i * 32);
    }
    uint32_t mode = strcmp(leaf, c->manifest.name) == 0
                        ? VCS_PACKAGE_MODE_EXECUTABLE : VCS_PACKAGE_MODE_FILE;
    ok = ok && vcs_package_manifest_add(manifest, leaf, mode, len, hashes, chunks);
    free(hashes);
    free(bytes);
    return ok;
}

static bool pr_root_matches(struct pr_ctx *c, struct zcl_command_reply *reply)
{
    uint8_t expected[32], actual[32];
    bool ok = zcl_hex_decode(c->root, expected, 32);
    struct vcs_package_manifest manifest;
    vcs_package_manifest_init(&manifest);
    DIR *d = ok ? opendir(c->dir) : NULL;
    ok = d != NULL;
    for (struct dirent *e = d ? readdir(d) : NULL; e && ok; e = readdir(d)) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        ok = pr_manifest_add_file(c, &manifest, e->d_name);
    }
    if (d && closedir(d) != 0)
        ok = false;
    ok = ok && manifest.count > 0 && vcs_package_manifest_root(&manifest, actual) &&
         memcmp(expected, actual, 32) == 0;
    vcs_package_manifest_free(&manifest);
    if (ok)
        return true;
    pat_refuse(reply, "PLUGIN_REPRODUCE_ROOT_MISMATCH",
               "pass the package root returned by plugin publish; altered checkout bytes are not that package",
               "reproduce", c->root);
    return false;
}

static bool pr_verify(struct pr_ctx *c, struct zcl_command_reply *reply)
{
    if (!pr_find_manifest(c)) {
        pat_refuse(reply, "PLUGIN_REPRODUCE_LAYOUT",
                   "fetch one plugin with exactly one NAME.plugin.json", "reproduce", c->dir);
        return false;
    }
    return pr_signature(c, reply) && pr_paths(c, reply) && pr_image(c, reply) &&
           pr_inputs(c, reply) && pr_root_matches(c, reply);
}

static bool pr_capabilities(unsigned mask, struct json_value *caps)
{
    json_init(caps);
    json_set_array(caps);
    for (unsigned i = 0; plugin_capability_name(i); i++) {
        if ((mask & (1u << i)) == 0)
            continue;
        struct json_value name;
        json_init(&name);
        json_set_str(&name, plugin_capability_name(i));
        bool ok = json_push_back(caps, &name);
        json_free(&name);
        if (!ok)
            return false;
    }
    return true;
}

static bool pr_lab_input(const struct zcl_command_request *request,
                         const struct pr_ctx *c, struct json_value *in)
{
    static const char *const optional[] = { "sanitize", "timeout_ms", "mem_mb" };
    struct json_value caps;
    bool ok = pr_capabilities(c->manifest.capabilities, &caps);
    json_init(in);
    json_set_object(in);
    ok = ok && json_push_kv_str(in, "file", c->source) &&
         json_push_kv_str(in, "cases", c->cases) &&
         json_push_kv_str(in, "name", c->manifest.name) &&
         json_push_kv_str(in, "version", c->manifest.version) &&
         json_push_kv_str(in, "key", c->key) && json_push_kv_str(in, "dir", c->out) &&
         json_push_kv(in, "cap", &caps);
    json_free(&caps);
    for (size_t i = 0; ok && i < sizeof(optional) / sizeof(optional[0]); i++) {
        const struct json_value *v = json_get(request->input, optional[i]);
        if (v)
            ok = json_push_kv(in, optional[i], v);
    }
    return ok;
}

static bool pr_rebuilt_read(const struct zcl_command_reply *built,
                            struct pr_rebuilt *out)
{
    const char *sha = json_get_str(json_get(&built->data, "release_sha3_512"));
    const char *generation = json_get_str(json_get(&built->data, "generation"));
    const char *builder = json_get_str(json_get(&built->data, "public_key"));
    const char *manifest = json_get_str(json_get(&built->data, "manifest"));
    const char *command = json_get_str(json_get(&built->data, "release_command"));
    if (strlen(sha) != PLUGIN_HEX_SHA3_512 ||
        strlen(generation) != PLUGIN_HEX_SHA3_512 || strlen(builder) != 64 ||
        !manifest[0] || strlen(manifest) >= sizeof(out->manifest) ||
        strlen(command) >= sizeof(out->release_command))
        return false;
    snprintf(out->sha, sizeof(out->sha), "%s", sha);
    snprintf(out->generation, sizeof(out->generation), "%s", generation);
    snprintf(out->builder, sizeof(out->builder), "%s", builder);
    snprintf(out->manifest, sizeof(out->manifest), "%s", manifest);
    snprintf(out->release_command, sizeof(out->release_command), "%s", command);
    out->cases_passed = json_get_int(json_get(&built->data, "cases_passed"));
    return out->cases_passed > 0;
}

static void pr_nested_refusal(struct zcl_command_reply *reply,
                              const struct zcl_command_reply *nested,
                              const struct pr_ctx *c)
{
    pat_refuse(reply, nested->error.code[0] ? nested->error.code : "PLUGIN_REPRODUCE_BUILD",
               nested->error.next_action, "reproduce", nested->error.evidence);
    if (access(c->out, F_OK) == 0) {
        reply->error.mutated = true;
        snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                 "inspect the retained output named by out, then retry with a fresh absent out");
        return;
    }
    reply->error.mutated = nested->error.mutated;
}

static bool pr_report_identity(const struct pr_ctx *c,
                               struct zcl_command_reply *reply)
{
    return json_push_kv_str(&reply->data, "schema", "zcl.plugin_reproduce.v1") &&
           json_push_kv_bool(&reply->data, "reproduced", true) &&
           json_push_kv_bool(&reply->data, "physical_independence_attested", false) &&
           json_push_kv_bool(&reply->data, "installed", false) &&
           json_push_kv_bool(&reply->data, "activated", false) &&
           json_push_kv_str(&reply->data, "name", c->manifest.name) &&
           json_push_kv_str(&reply->data, "version", c->manifest.version) &&
           json_push_kv_str(&reply->data, "source_root", c->root);
}

static bool pr_report_proof(const struct pr_rebuilt *rebuilt,
                            const struct plugin_attest_result *attested,
                            struct zcl_command_reply *reply)
{
    return json_push_kv_str(&reply->data, "image_sha3_512", rebuilt->sha) &&
           json_push_kv_str(&reply->data, "generation", rebuilt->generation) &&
           json_push_kv_int(&reply->data, "cases_passed", rebuilt->cases_passed) &&
           json_push_kv_str(&reply->data, "release_command", rebuilt->release_command) &&
           json_push_kv_str(&reply->data, "rebuild_manifest", rebuilt->manifest) &&
           json_push_kv_str(&reply->data, "builder_key", attested->record.builder_key) &&
           json_push_kv_str(&reply->data, "toolchain", attested->record.toolchain) &&
           json_push_kv_str(&reply->data, "attestation", attested->path);
}

static bool pr_report(struct pr_ctx *c, const struct pr_rebuilt *rebuilt,
                      struct zcl_command_reply *reply)
{
    char image[PR_PATH_MAX];
    struct plugin_attest_request in = {
        .image_path = image, .key_path = c->key, .name = c->manifest.name,
        .version = c->manifest.version, .source_root = c->root,
        .toolchain = c->toolchain, .dir = c->out,
    };
    if (!zcl_path_join(image, sizeof(image), c->out, c->manifest.name)) {
        pat_refuse(reply, "PLUGIN_REPRODUCE_LAYOUT", "choose a shorter output path",
                   "reproduce", c->out);
        return false;
    }
    struct plugin_attest_result attested;
    enum plugin_attest_status st = plugin_attest_make(&in, &attested);
    if (st != PLUGIN_ATTEST_OK) {
        pat_refuse_status(reply, st, attested.cause, "reproduce", image);
        reply->error.mutated = true;
        return false;
    }
    if (strcmp(rebuilt->builder, attested.record.builder_key) != 0) {
        pat_refuse(reply, "PLUGIN_REPRODUCE_RECEIPT",
                   "retry with a fresh output directory and the same builder key",
                   "reproduce", attested.path);
        reply->error.mutated = true;
        return false;
    }
    json_set_object(&reply->data);
    bool ok = pr_report_identity(c, reply) &&
              pr_report_proof(rebuilt, &attested, reply);
    if (!ok)
        pat_refuse(reply, "PLUGIN_REPRODUCE_RECEIPT", "retry with a fresh output directory",
                   "reproduce", attested.path);
    reply->error.mutated = true;
    return ok;
}

static void pr_next_install(const struct pr_ctx *c, struct zcl_command_reply *reply)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    if (json_push_kv_str(&input, "manifest", c->manifest_path)) {
        size_t need = json_write(&input, NULL, 0) + 1;
        char *text = zcl_malloc(need, "plugin.reproduce.next");
        if (text && json_write(&input, text, need) < need)
            (void)zcl_command_reply_add_next(reply, "plugin.install", text,
                "after reviewing and pinning the publisher, install without switching");
        free(text);
    }
    json_free(&input);
}

static bool pr_arguments(const struct zcl_command_request *request,
                         struct pr_ctx *c, struct zcl_command_reply *reply)
{
    memset(c, 0, sizeof(*c));
    c->dir = lab_in_str(request, "dir");
    c->root = lab_in_str(request, "source-root");
    c->key = lab_in_str(request, "key");
    c->out = lab_in_str(request, "out");
    c->toolchain = lab_in_str(request, "toolchain");
    if (c->dir && c->dir[0] && c->root && c->key && c->key[0] && c->out &&
        c->out[0] && c->toolchain && c->toolchain[0] &&
        zcl_is_lower_hex(c->root, 64))
        return true;
    pat_refuse(reply, "PLUGIN_REPRODUCE_ARGUMENT",
               "pass dir, source-root, key, out and toolchain; source-root is 64 lowercase hex",
               "reproduce", "");
    return false;
}

static bool pr_output_absent(const struct pr_ctx *c, struct zcl_command_reply *reply)
{
    if (access(c->out, F_OK) != 0 && errno == ENOENT)
        return true;
    pat_refuse(reply, "PLUGIN_REPRODUCE_OUTPUT",
               "name an absent output directory so no prior pack or attestation can be reused",
               "reproduce", c->out);
    return false;
}

static bool pr_build(const struct zcl_command_request *request, const struct pr_ctx *c,
                     struct pr_rebuilt *rebuilt, struct zcl_command_reply *reply)
{
    struct json_value input;
    if (!pr_lab_input(request, c, &input)) {
        pat_refuse(reply, "PLUGIN_REPRODUCE_ALLOC", "retry after freeing memory",
                   "reproduce", "");
        json_free(&input);
        return false;
    }
    struct zcl_command_request sub = { .input = &input, .view = "normal" };
    struct zcl_command_reply built;
    zcl_command_reply_init(&built, "zcl.plugin_reproduce.build.v1");
    zcl_native_handle_lab_promote(&sub, &built);
    json_free(&input);
    if (built.status != ZCL_COMMAND_STATUS_PASSED) {
        pr_nested_refusal(reply, &built, c);
        zcl_command_reply_free(&built);
        return false;
    }
    memset(rebuilt, 0, sizeof(*rebuilt));
    bool read = pr_rebuilt_read(&built, rebuilt);
    zcl_command_reply_free(&built);
    if (read)
        return true;
    pat_refuse(reply, "PLUGIN_REPRODUCE_RECEIPT", "retry with a fresh output directory",
               "reproduce", c->out);
    reply->error.mutated = true;
    return false;
}

static bool pr_compare(const struct pr_ctx *c, const struct pr_rebuilt *rebuilt,
                       struct zcl_command_reply *reply)
{
    if (strcmp(rebuilt->sha, c->manifest.exe_sha3) == 0 &&
        strcmp(rebuilt->generation, c->manifest.generation) == 0)
        return true;
    bool hash = strcmp(rebuilt->sha, c->manifest.exe_sha3) != 0;
    json_set_object(&reply->data);
    struct json_value facts;
    json_init(&facts);
    json_set_object(&facts);
    bool fields = json_push_kv_str(&facts, "expected_sha3_512", c->manifest.exe_sha3) &&
                  json_push_kv_str(&facts, "actual_sha3_512", rebuilt->sha) &&
                  json_push_kv_str(&facts, "expected_generation", c->manifest.generation) &&
                  json_push_kv_str(&facts, "actual_generation", rebuilt->generation) &&
                  json_push_kv(&reply->data, "failure_facts", &facts);
    json_free(&facts);
    pat_refuse(reply, !fields ? "PLUGIN_REPRODUCE_RECEIPT"
                              : hash ? "PLUGIN_REPRODUCE_HASH_MISMATCH"
                                     : "PLUGIN_REPRODUCE_GENERATION_MISMATCH",
               "inspect the retained rebuild and error.facts; no attestation was written",
               "reproduce", !fields ? "mismatch detected; comparison fields could not be built"
                                   : hash ? "image digest differs; full expected and actual values are in error.facts"
                                          : "signed-manifest generation differs; full values are in error.facts");
    reply->error.mutated = true;
    return false;
}

void zcl_native_handle_plugin_reproduce(const struct zcl_command_request *request,
                                        struct zcl_command_reply *reply)
{
#if !defined(__linux__)
    (void)request;
    pat_refuse(reply, "PLUGIN_REPRODUCE_PLATFORM",
               "run the confined reproduction on a Linux host", "reproduce", "");
#else
    if (!request || !reply)
        return;
    struct pr_ctx c;
    struct pr_rebuilt rebuilt;
    if (!pr_arguments(request, &c, reply) || !pr_output_absent(&c, reply))
        return;
    char scratch[PLATFORM_TEMP_PATH_MAX];
    if (!platform_temp_directory_create("z23-reproduce-", scratch, sizeof(scratch))) {
        pat_refuse(reply, "PLUGIN_REPRODUCE_CAPTURE", "retry with private temporary storage",
                   "reproduce", c.dir);
        return;
    }
    const char *original = c.dir;
    bool captured = pr_capture(original, scratch);
    c.dir = scratch;
    if (!captured)
        pat_refuse(reply, "PLUGIN_REPRODUCE_CAPTURE", "retry with a stable flat package",
                   "reproduce", original);
    else if (pr_verify(&c, reply)) {
#if defined(ZCL_TESTING)
        if (pr_capture_test_hook)
            pr_capture_test_hook(pr_capture_test_arg);
#endif
        if (pr_build(request, &c, &rebuilt, reply) &&
            pr_compare(&c, &rebuilt, reply) && pr_report(&c, &rebuilt, reply)) {
            int n = snprintf(c.manifest_path, sizeof(c.manifest_path), "%s/%s.plugin.json",
                             original, c.name);
            if (n > 0 && (size_t)n < sizeof(c.manifest_path))
                pr_next_install(&c, reply);
        }
    }
    if (!zcl_result_is_ok(zcl_tree_remove(scratch))) {
        pat_refuse(reply, "PLUGIN_REPRODUCE_CLEANUP",
                   "remove the private temporary capture before retrying", "reproduce", scratch);
        reply->error.mutated = true;
    }
#endif
}
