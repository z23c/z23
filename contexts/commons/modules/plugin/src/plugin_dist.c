/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: publish a plugin generation as a package root and verify and
 *          install a delivered one as a new generation. See plugin_dist.h. */

#include "plugin/plugin_dist.h"

#include "plugin_internal.h"

#include "base/safe_alloc.h"
#include "core/uint256.h"
#include "keys/key.h"
#include "vcs/package_accept.h"
#include "vcs/package_checkout.h"
#include "vcs/package_manifest.h"
#include "vcs/package_release.h"
#include "vcs/package_store.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PD_LICENSE_MAX VCS_PACKAGE_RELEASE_LICENSE_TEXT_MAX_BYTES
#define PD_IMAGE_MAX_DEFAULT (48u * 1024u * 1024u)

static const struct {
    const char *code;
    const char *next;
} k_pd_status[] = {
    [PLUGIN_DIST_OK] = {"OK", ""},
    [PLUGIN_DIST_ERR_ARGUMENT] = {"PLUGIN_DIST_ARGUMENT",
        "pass the missing or malformed argument; see the command's usage"},
    [PLUGIN_DIST_ERR_SOURCE] = {"PLUGIN_DIST_SOURCE",
        "the generation must have NAME, NAME.plugin.json and NAME.plugin.sig that agree; re-run plugin pack or plugin install"},
    [PLUGIN_DIST_ERR_LICENSE] = {"PLUGIN_DIST_LICENSE",
        "pass --license-file with the real text of the SPDX license named by --spdx"},
    [PLUGIN_DIST_ERR_RELEASE] = {"PLUGIN_DIST_RELEASE",
        "pass --release-key with a 32-byte package signing key and a --sequence not used before by that key"},
    [PLUGIN_DIST_ERR_STORE] = {"PLUGIN_DIST_STORE",
        "check free space and that no node is running on this datadir"},
    [PLUGIN_DIST_ERR_NOT_FETCHED] = {"PLUGIN_DIST_NOT_FETCHED",
        "run a hosting node on this datadir connected to a peer that serves the root, then repeat plugin fetch"},
    [PLUGIN_DIST_ERR_ROOT_MISMATCH] = {"PLUGIN_DIST_ROOT_MISMATCH",
        "the bytes are not the package you asked for; discard them and ask for the root again from another peer"},
    [PLUGIN_DIST_ERR_TRUNCATED] = {"PLUGIN_DIST_TRUNCATED",
        "the transfer is incomplete; keep the hosting node running until the download completes, then repeat plugin fetch"},
    [PLUGIN_DIST_ERR_SHAPE] = {"PLUGIN_DIST_SHAPE",
        "the package is not a plugin generation (LICENSE, NAME, NAME.plugin.json, NAME.plugin.sig); do not install it"},
    [PLUGIN_DIST_ERR_PUBLISHER_UNPINNED] = {"PLUGIN_DIST_PUBLISHER_UNPINNED",
        "if you trust this publisher, pin its key with `z23 plugin publisher <64-hex public key>` and repeat plugin fetch"},
    [PLUGIN_DIST_ERR_IMAGE_HASH] = {"PLUGIN_DIST_IMAGE_HASH",
        "the image differs from the signed manifest sha3_512; the publisher or a peer sent the wrong bytes; do not install"},
    [PLUGIN_DIST_ERR_DOWNGRADE] = {"PLUGIN_DIST_DOWNGRADE",
        "this version is lower than the installed current one; only the owner may allow that, with --allow-downgrade"},
    [PLUGIN_DIST_ERR_PLUGIN] = {"PLUGIN_DIST_PLUGIN",
        "the plugin store refused the generation; the evidence names its PLUGIN_* code"},
    [PLUGIN_DIST_ERR_TOO_LARGE] = {"PLUGIN_DIST_TOO_LARGE",
        "the plugin image is over the 48 MiB cap; do not install it, ask the publisher for a smaller build"},
    [PLUGIN_DIST_ERR_IO] = {"PLUGIN_DIST_IO",
        "a file operation failed; check permissions and free space"},
};

const char *plugin_dist_status_code(enum plugin_dist_status status)
{
    if ((size_t)status >= sizeof(k_pd_status) / sizeof(k_pd_status[0]))
        return "PLUGIN_DIST_UNKNOWN";
    return k_pd_status[status].code;
}

const char *plugin_dist_status_next_action(enum plugin_dist_status status)
{
    if ((size_t)status >= sizeof(k_pd_status) / sizeof(k_pd_status[0]))
        return "";
    return k_pd_status[status].next;
}

/* ---- versions ---------------------------------------------------------- */

bool plugin_dist_version_parse(const char *version, uint64_t out[4])
{
    if (!version || !out)
        return false;
    memset(out, 0, 4 * sizeof(uint64_t));
    unsigned part = 0;
    const char *p = version;
    for (;;) {
        if (*p < '0' || *p > '9' || part == 4)
            return false;
        uint64_t v = 0;
        size_t digits = 0;
        while (*p >= '0' && *p <= '9') {
            if (++digits > 9)
                return false;
            v = v * 10 + (uint64_t)(*p - '0');
            p++;
        }
        out[part++] = v;
        if (*p == '\0')
            return true;
        if (*p != '.')
            return false;
        p++;
    }
}

int plugin_dist_version_compare(const char *a, const char *b, bool *comparable)
{
    uint64_t x[4], y[4];
    bool ok = plugin_dist_version_parse(a, x) && plugin_dist_version_parse(b, y);
    if (comparable)
        *comparable = ok;
    if (!ok)
        return 0;
    for (int i = 0; i < 4; i++)
        if (x[i] != y[i])
            return x[i] < y[i] ? -1 : 1;
    return 0;
}

#ifdef ZCL_TESTING
static bool g_skip_source_check;
void plugin_dist_test_skip_source_check(bool skip) { g_skip_source_check = skip; }
static uint64_t g_image_max;
void plugin_dist_test_set_image_max(uint64_t bytes) { g_image_max = bytes; }
#define PD_IMAGE_MAX (g_image_max ? g_image_max : PD_IMAGE_MAX_DEFAULT)
#define PD_SKIP_SOURCE_CHECK g_skip_source_check
#else
#define PD_SKIP_SOURCE_CHECK false
#define PD_IMAGE_MAX PD_IMAGE_MAX_DEFAULT
#endif

#if !defined(_WIN32)

static const char k_hex[] = "0123456789abcdef";

static bool pd_join(char *out, size_t cap, const char *a, const char *b)
{
    if (!a || !b || !a[0] || !b[0])
        return false;
    int n = snprintf(out, cap, "%s/%s", a, b);
    return n > 0 && (size_t)n < cap;
}

static void pd_detail(char *out, size_t cap, const char *fmt, const char *a)
{
    (void)snprintf(out, cap, fmt, a ? a : "");
}

static void pd_hex(char *out, const uint8_t *bytes, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = k_hex[bytes[i] >> 4];
        out[2 * i + 1] = k_hex[bytes[i] & 15];
    }
    out[2 * n] = '\0';
}

/* ---- publish ----------------------------------------------------------- */

struct pd_member {
    char leaf[PLUGIN_NAME_MAX + 32];
    char path[PLUGIN_PATH_MAX];
    uint32_t mode;
    uint64_t size;
    uint32_t chunks;
    uint8_t *digests;
};

/* Read exactly want bytes. */
static bool pd_read_full(int fd, uint8_t *buf, size_t want)
{
    size_t got = 0;
    while (got < want) {
        ssize_t r = read(fd, buf + got, want - got);
        if (r < 0 && errno == EINTR)
            continue;
        if (r <= 0)
            return false;
        got += (size_t)r;
    }
    return true;
}

static size_t pd_chunk_len(uint64_t left)
{
    return left > VCS_PACKAGE_CHUNK_BYTES ? VCS_PACKAGE_CHUNK_BYTES : (size_t)left;
}

static bool pd_hash_chunks(int fd, struct pd_member *m)
{
    uint8_t *buf = zcl_malloc(VCS_PACKAGE_CHUNK_BYTES, "plugin_dist_chunk");
    bool ok = buf != NULL;
    uint64_t left = m->size;
    for (uint32_t i = 0; ok && i < m->chunks; i++) {
        size_t want = pd_chunk_len(left);
        ok = pd_read_full(fd, buf, want) &&
             vcs_package_chunk_hash(buf, want, m->digests + (size_t)i * 32);
        left -= want;
    }
    free(buf);
    return ok;
}

static bool pd_hash_member(struct pd_member *m, size_t max_bytes)
{
    int fd = open(m->path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return false;
    struct stat st;
    bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0 &&
              (uint64_t)st.st_size <= max_bytes;
    if (ok) {
        m->size = (uint64_t)st.st_size;
        m->chunks = (uint32_t)((m->size + VCS_PACKAGE_CHUNK_BYTES - 1) /
                               VCS_PACKAGE_CHUNK_BYTES);
        m->digests = zcl_calloc(m->chunks, 32, "plugin_dist_digests");
        ok = m->digests && pd_hash_chunks(fd, m);
    }
    (void)close(fd);
    return ok;
}

static bool pd_put_member_chunks(struct vcs_package_store *store,
                                 const uint8_t root[32], const struct pd_member *m)
{
    int fd = open(m->path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return false;
    uint8_t *buf = zcl_malloc(VCS_PACKAGE_CHUNK_BYTES, "plugin_dist_chunk");
    bool ok = buf != NULL;
    uint64_t left = m->size;
    for (uint32_t i = 0; ok && i < m->chunks; i++) {
        size_t want = pd_chunk_len(left);
        /* The store hashes the bytes against the committed manifest, so a
         * file that changed since pd_hash_member is refused here. */
        ok = pd_read_full(fd, buf, want) &&
             vcs_package_store_put_chunk(store, root, m->leaf, i, buf, want) ==
                 VCS_PACKAGE_STORE_OK;
        left -= want;
    }
    free(buf);
    (void)close(fd);
    return ok;
}

/* Resolve the directory that holds the three plugin files. */
static enum plugin_dist_status pd_source(
    const struct plugin_dist_publish_request *rq, char dir[PLUGIN_PATH_MAX],
    struct plugin_dist_published *out)
{
    if (rq->src_dir) {
        if (strlen(rq->src_dir) >= PLUGIN_PATH_MAX)
            return PLUGIN_DIST_ERR_ARGUMENT;
        strcpy(dir, rq->src_dir);
        return PLUGIN_DIST_OK;
    }
    if (!rq->plugins_dir)
        return PLUGIN_DIST_ERR_ARGUMENT;
    char gen[PLUGIN_HEX_SHA3_512 + 1];
    if (rq->generation) {
        if (strlen(rq->generation) != PLUGIN_HEX_SHA3_512 ||
            !plugin_hex_valid(rq->generation, PLUGIN_HEX_SHA3_512)) {
            pd_detail(out->detail, sizeof(out->detail),
                      "generation %s is not 128 lowercase hex characters",
                      rq->generation);
            return PLUGIN_DIST_ERR_ARGUMENT;
        }
        memcpy(gen, rq->generation, sizeof(gen));
    } else {
        struct plugin_manifest cur;
        char exe[PLUGIN_PATH_MAX];
        enum plugin_status st =
            plugin_store_current(rq->plugins_dir, rq->name, &cur, exe, sizeof(exe));
        if (st != PLUGIN_OK) {
            pd_detail(out->detail, sizeof(out->detail),
                      "no current generation to publish (%s); pass the generation",
                      plugin_status_code(st));
            return PLUGIN_DIST_ERR_SOURCE;
        }
        memcpy(gen, cur.generation, sizeof(gen));
    }
    char a[PLUGIN_PATH_MAX], b[PLUGIN_PATH_MAX];
    if (!pd_join(a, sizeof(a), rq->plugins_dir, rq->name) ||
        !pd_join(b, sizeof(b), a, "generations") ||
        !pd_join(a, sizeof(a), b, gen))
        return PLUGIN_DIST_ERR_ARGUMENT;
    strcpy(dir, a);
    return PLUGIN_DIST_OK;
}

/* The release signing key: a 32-byte secp256k1 secret, never kept. */
static enum plugin_dist_status pd_release_key(
    const char *path, struct privkey *sk, struct pubkey *pk,
    struct plugin_dist_published *out)
{
    if (!path) {
        pd_detail(out->detail, sizeof(out->detail), "%s",
                  "--release-key is required: a hosting node serves only a signed release");
        return PLUGIN_DIST_ERR_RELEASE;
    }
    /* A CLI process has no node boot to start the signing context. */
    uint8_t seed[PLUGIN_KEY_FILE_BYTES];
    enum plugin_status ks = ecc_start_once() ? plugin_key_load(path, seed)
                                              : PLUGIN_ERR_IO;
    if (ks != PLUGIN_OK) {
        pd_detail(out->detail, sizeof(out->detail), "release key refused: %s",
                  plugin_status_code(ks));
        return PLUGIN_DIST_ERR_RELEASE;
    }
    memset(sk, 0, sizeof(*sk));
    memcpy(sk->vch, seed, 32);
    memset(seed, 0, sizeof(seed));
    sk->fValid = true;
    sk->fCompressed = true;
    if (!privkey_get_pubkey(sk, pk) || pk->size != VCS_PACKAGE_RELEASE_PUBKEY_BYTES) {
        memset(sk, 0, sizeof(*sk));
        pd_detail(out->detail, sizeof(out->detail), "%s",
                  "the release key is not a valid secp256k1 secret");
        return PLUGIN_DIST_ERR_RELEASE;
    }
    return PLUGIN_DIST_OK;
}

static bool pd_release_fill(struct vcs_package_release *r,
                            const struct plugin_dist_publish_request *rq,
                            const struct plugin_manifest *m, const uint8_t root[32],
                            const struct pubkey *pk)
{
    memset(r, 0, sizeof(*r));
    r->schema_version = VCS_PACKAGE_RELEASE_VERSION;
    bool ok = snprintf(r->name, sizeof(r->name), "plugin/%s", m->name) > 0 &&
              snprintf(r->semver, sizeof(r->semver), "%s", m->version) > 0;
    memcpy(r->package_root, root, 32);
    /* A plugin is a prebuilt, separately signed binary with no build recipe:
     * the recipe root is a fixed placeholder, as in the fixture releases. */
    for (int i = 0; i < 32; i++)
        r->recipe_root[i] = (uint8_t)(0x50 + i);
    memcpy(r->publisher_pubkey, pk->vch, VCS_PACKAGE_RELEASE_PUBKEY_BYTES);
    r->publisher_sequence = rq->sequence ? rq->sequence : 1u;
    snprintf(r->license, sizeof(r->license), "%s", rq->spdx ? rq->spdx : "MIT");
    return ok && vcs_package_accept_chain_id(r->chain_id, sizeof(r->chain_id));
}

static enum plugin_dist_status pd_sign_release(
    struct vcs_package_store *store, const struct plugin_dist_publish_request *rq,
    const struct plugin_manifest *m, const uint8_t root[32],
    struct plugin_dist_published *out)
{
    struct privkey sk;
    struct pubkey pk;
    enum plugin_dist_status ds = pd_release_key(rq->release_key, &sk, &pk, out);
    if (ds != PLUGIN_DIST_OK)
        return ds;
    struct vcs_package_release r;
    uint8_t id[VCS_PACKAGE_RELEASE_ID_BYTES];
    bool ok = pd_release_fill(&r, rq, m, root, &pk) &&
              vcs_package_release_id(&r, id) == VCS_PACKAGE_RELEASE_OK;
    struct uint256 hash;
    unsigned char compact[COMPACT_SIGNATURE_SIZE];
    memcpy(hash.data, id, 32);
    ok = ok && privkey_sign_compact(&sk, &hash, compact);
    memset(&sk, 0, sizeof(sk));
    if (!ok) {
        pd_detail(out->detail, sizeof(out->detail), "%s",
                  "release refused: the plugin version must be semver and the chain id available");
        return PLUGIN_DIST_ERR_RELEASE;
    }
    memcpy(r.signature, compact + 1, VCS_PACKAGE_RELEASE_SIGNATURE_BYTES);
    enum vcs_package_accept_result ar = VCS_PACKAGE_ACCEPT_ERR_NULL;
    enum vcs_package_store_result sr = vcs_package_store_put_release(store, &r, &ar);
    if (sr != VCS_PACKAGE_STORE_OK ||
        (ar != VCS_PACKAGE_ACCEPT_OK && ar != VCS_PACKAGE_ACCEPT_DUPLICATE)) {
        pd_detail(out->detail, sizeof(out->detail),
                  "release not accepted by the store (%s); use a new --sequence",
                  vcs_package_store_result_string(sr));
        return PLUGIN_DIST_ERR_RELEASE;
    }
    return PLUGIN_DIST_OK;
}

struct pd_pub {
    struct pd_member mem[4]; /* LICENSE, image, manifest, signature */
    char *manifest_bytes, *sig_bytes, *license;
    size_t manifest_len, sig_len, license_len;
    struct plugin_manifest m;
};

static void pd_pub_free(struct pd_pub *p)
{
    for (int i = 0; i < 4; i++)
        free(p->mem[i].digests);
    free(p->manifest_bytes);
    free(p->sig_bytes);
    free(p->license);
}

static bool pd_pub_members(struct pd_pub *p, const struct plugin_dist_publish_request *rq,
                           const char *dir)
{
    memset(p->mem, 0, sizeof(p->mem));
    snprintf(p->mem[0].leaf, sizeof(p->mem[0].leaf), "LICENSE");
    snprintf(p->mem[1].leaf, sizeof(p->mem[1].leaf), "%s", rq->name);
    snprintf(p->mem[2].leaf, sizeof(p->mem[2].leaf), "%s.plugin.json", rq->name);
    snprintf(p->mem[3].leaf, sizeof(p->mem[3].leaf), "%s.plugin.sig", rq->name);
    snprintf(p->mem[0].path, sizeof(p->mem[0].path), "%s", rq->license_file);
    for (int i = 1; i < 4; i++)
        if (!pd_join(p->mem[i].path, sizeof(p->mem[i].path), dir, p->mem[i].leaf))
            return false;
    p->mem[0].mode = p->mem[2].mode = p->mem[3].mode = VCS_PACKAGE_MODE_FILE;
    p->mem[1].mode = VCS_PACKAGE_MODE_EXECUTABLE;
    return true;
}

/* The three generation files must agree before they are offered. */
static enum plugin_dist_status pd_pub_source(struct pd_pub *p,
                                             const struct plugin_dist_publish_request *rq,
                                             const char *dir,
                                             struct plugin_dist_published *out)
{
    if (!plugin_read_file(p->mem[2].path, PLUGIN_FILE_MAX, PLUGIN_OPEN_NOFOLLOW,
                          &p->manifest_bytes, &p->manifest_len) ||
        !plugin_read_file(p->mem[3].path, PLUGIN_FILE_MAX, PLUGIN_OPEN_NOFOLLOW,
                          &p->sig_bytes, &p->sig_len)) {
        pd_detail(out->detail, sizeof(out->detail),
                  "cannot read the manifest or signature in %s", dir);
        return PLUGIN_DIST_ERR_SOURCE;
    }
    if (plugin_manifest_parse(p->manifest_bytes, p->manifest_len, &p->m) != PLUGIN_OK ||
        strcmp(p->m.name, rq->name) != 0) {
        pd_detail(out->detail, sizeof(out->detail),
                  "the manifest in %s is not a valid manifest for this plugin", dir);
        return PLUGIN_DIST_ERR_SOURCE;
    }
    char digest[PLUGIN_HEX_SHA3_512 + 1];
    if (!PD_SKIP_SOURCE_CHECK &&
        (plugin_hash_file(p->mem[1].path, digest) != PLUGIN_OK ||
         strcmp(digest, p->m.exe_sha3) != 0)) {
        pd_detail(out->detail, sizeof(out->detail),
                  "the image in %s does not match the manifest sha3_512", dir);
        return PLUGIN_DIST_ERR_SOURCE;
    }
    const char *spdx = rq->spdx ? rq->spdx : "MIT";
    if (!plugin_read_file(rq->license_file, PD_LICENSE_MAX, PLUGIN_OPEN_NOFOLLOW, &p->license,
                          &p->license_len)) {
        pd_detail(out->detail, sizeof(out->detail),
                  errno == ELOOP ? "the license file is a symlink; pass the regular file itself%s"
                                 : "the license file is unreadable%s", "");
        return PLUGIN_DIST_ERR_LICENSE;
    }
    if (!vcs_package_release_license_text_matches(spdx, (const uint8_t *)p->license,
                                                  p->license_len)) {
        pd_detail(out->detail, sizeof(out->detail),
                  "the license file is unreadable or is not the %s text", spdx);
        return PLUGIN_DIST_ERR_LICENSE;
    }
    return PLUGIN_DIST_OK;
}

static bool pd_pub_store(struct pd_pub *p, struct vcs_package_store *store,
                         struct plugin_dist_published *out)
{
    struct vcs_package_manifest pm;
    vcs_package_manifest_init(&pm);
    bool ok = true;
    for (int i = 0; ok && i < 4; i++) {
        struct pd_member *mem = &p->mem[i];
        ok = pd_hash_member(mem, i == 1 ? PD_IMAGE_MAX : PD_LICENSE_MAX) &&
             vcs_package_manifest_add(&pm, mem->leaf, mem->mode, mem->size,
                                      mem->digests, mem->chunks);
        if (ok)
            out->bytes += mem->size;
    }
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    ok = ok && vcs_package_manifest_serialize(&pm, &wire, &wire_len) &&
         vcs_package_store_put_manifest(store, wire, wire_len, out->root) ==
             VCS_PACKAGE_STORE_OK;
    for (int i = 0; ok && i < 4; i++)
        ok = pd_put_member_chunks(store, out->root, &p->mem[i]);
    free(wire);
    vcs_package_manifest_free(&pm);
    return ok;
}

static void pd_pub_fill(const struct pd_pub *p, struct plugin_dist_published *out)
{
    pd_hex(out->root_hex, out->root, 32);
    snprintf(out->name, sizeof(out->name), "%s", p->m.name);
    snprintf(out->version, sizeof(out->version), "%s", p->m.version);
    snprintf(out->exe_sha3, sizeof(out->exe_sha3), "%s", p->m.exe_sha3);
    out->files = 4;
    /* The signed-manifest digest is the generation id, recomputed from the
     * exact manifest bytes without trusting any key list. */
    uint8_t md[PLUGIN_DIGEST_BYTES];
    plugin_manifest_digest(p->manifest_bytes, p->manifest_len, md);
    pd_hex(out->generation, md, PLUGIN_DIGEST_BYTES);
}

static enum plugin_dist_status pd_publish(
    struct vcs_package_store *store,
    const struct plugin_dist_publish_request *rq,
    struct plugin_dist_published *out)
{
    if (!out)
        return PLUGIN_DIST_ERR_ARGUMENT;
    memset(out, 0, sizeof(*out));
    if (!store || !rq || !rq->name || !plugin_name_valid(rq->name) || !rq->license_file) {
        snprintf(out->detail, sizeof(out->detail),
                 "store, a valid plugin name and --license-file are required");
        return PLUGIN_DIST_ERR_ARGUMENT;
    }
    char dir[PLUGIN_PATH_MAX];
    enum plugin_dist_status ds = pd_source(rq, dir, out);
    if (ds != PLUGIN_DIST_OK)
        return ds;
    struct pd_pub p;
    memset(&p, 0, sizeof(p));
    if (!pd_pub_members(&p, rq, dir))
        return PLUGIN_DIST_ERR_ARGUMENT;
    ds = pd_pub_source(&p, rq, dir, out);
    if (ds == PLUGIN_DIST_OK && !pd_pub_store(&p, store, out)) {
        pd_detail(out->detail, sizeof(out->detail), "%s",
                  "the package store refused the manifest or a chunk");
        ds = PLUGIN_DIST_ERR_STORE;
    }
    if (ds == PLUGIN_DIST_OK)
        ds = pd_sign_release(store, rq, &p.m, out->root, out);
    /* Pinned roots are never evicted, so the offer outlives pool pressure. */
    if (ds == PLUGIN_DIST_OK &&
        vcs_package_store_pin(store, out->root, true) != VCS_PACKAGE_STORE_OK) {
        pd_detail(out->detail, sizeof(out->detail), "%s",
                  "the root was stored and signed but could not be pinned");
        ds = PLUGIN_DIST_ERR_STORE;
    }
    if (ds == PLUGIN_DIST_OK)
        pd_pub_fill(&p, out);
    pd_pub_free(&p);
    return ds;
}

/* ---- receive ----------------------------------------------------------- */

static void pd_rm_checkout(const char *dest, const char *name)
{
    char path[PLUGIN_PATH_MAX], leaf[PLUGIN_NAME_MAX + 32];
    if (pd_join(path, sizeof(path), dest, "LICENSE"))
        (void)unlink(path);
    const char *suffix[] = {"", ".plugin.json", ".plugin.sig"};
    for (size_t i = 0; i < 3; i++)
        if (snprintf(leaf, sizeof(leaf), "%s%s", name, suffix[i]) > 0 &&
            pd_join(path, sizeof(path), dest, leaf))
            (void)unlink(path);
    (void)rmdir(dest);
}

static bool pd_expect_members(const struct vcs_package_manifest *pm, const char *name)
{
    char want[4][PLUGIN_NAME_MAX + 32];
    snprintf(want[0], sizeof(want[0]), "LICENSE");
    snprintf(want[1], sizeof(want[1]), "%s", name);
    snprintf(want[2], sizeof(want[2]), "%s.plugin.json", name);
    snprintf(want[3], sizeof(want[3]), "%s.plugin.sig", name);
    if (pm->count != 4)
        return false;
    for (size_t i = 0; i < 4; i++) {
        bool found = false;
        for (size_t j = 0; j < 4 && !found; j++)
            found = strcmp(pm->files[j].path, want[i]) == 0;
        if (!found)
            return false;
    }
    return true;
}

struct pd_checkout {
    char manifest_path[PLUGIN_PATH_MAX], sig_path[PLUGIN_PATH_MAX],
        exe_path[PLUGIN_PATH_MAX], keys_path[PLUGIN_PATH_MAX];
};

static bool pd_checkout_paths(struct pd_checkout *c, const char *dest, const char *name,
                              const char *plugins_dir)
{
    char leaf[PLUGIN_NAME_MAX + 32];
    snprintf(leaf, sizeof(leaf), "%s.plugin.json", name);
    bool ok = pd_join(c->manifest_path, sizeof(c->manifest_path), dest, leaf);
    snprintf(leaf, sizeof(leaf), "%s.plugin.sig", name);
    return ok && pd_join(c->sig_path, sizeof(c->sig_path), dest, leaf) &&
           pd_join(c->exe_path, sizeof(c->exe_path), dest, name) &&
           pd_join(c->keys_path, sizeof(c->keys_path), plugins_dir, "publisher_keys");
}

/* Publisher pin: the signing key must already be in this machine's
 * publisher_keys. Nothing a peer sends can add to that list. */
static enum plugin_dist_status pd_check_pin(const struct pd_checkout *c,
                                            struct plugin_manifest *m,
                                            struct plugin_dist_received *out)
{
    char *mb = NULL, *sb = NULL;
    size_t ml = 0, sl = 0;
    if (!plugin_read_file(c->manifest_path, PLUGIN_FILE_MAX, PLUGIN_OPEN_NOFOLLOW, &mb, &ml) ||
        !plugin_read_file(c->sig_path, PLUGIN_FILE_MAX, PLUGIN_OPEN_NOFOLLOW, &sb, &sl)) {
        free(mb);
        pd_detail(out->detail, sizeof(out->detail), "%s",
                  "the checked-out manifest or signature cannot be read");
        return PLUGIN_DIST_ERR_IO;
    }
    enum plugin_status vs = plugin_verify_manifest(mb, ml, sb, sl, c->keys_path, m);
    free(mb);
    free(sb);
    if (vs == PLUGIN_OK)
        return PLUGIN_DIST_OK;
    pd_detail(out->detail, sizeof(out->detail),
              vs == PLUGIN_ERR_KEY_UNKNOWN || vs == PLUGIN_ERR_NO_KEYS
                  ? "the signing key is not in publisher_keys (%s)"
                  : "manifest or signature refused: %s",
              plugin_status_code(vs));
    if (vs == PLUGIN_ERR_KEY_UNKNOWN || vs == PLUGIN_ERR_NO_KEYS)
        return PLUGIN_DIST_ERR_PUBLISHER_UNPINNED;
    out->plugin = vs;
    return PLUGIN_DIST_ERR_PLUGIN;
}

/* The image is hashed from the bytes that were checked out, against the
 * signed manifest, before the plugin store sees any of it. */
static enum plugin_dist_status pd_check_image(const struct pd_checkout *c,
                                              const struct plugin_manifest *m,
                                              struct plugin_dist_received *out)
{
    char digest[PLUGIN_HEX_SHA3_512 + 1];
    if (plugin_hash_file(c->exe_path, digest) == PLUGIN_OK &&
        strcmp(digest, m->exe_sha3) == 0)
        return PLUGIN_DIST_OK;
    pd_detail(out->detail, sizeof(out->detail), "%s",
              "the image SHA3-512 differs from the signed manifest sha3_512");
    return PLUGIN_DIST_ERR_IMAGE_HASH;
}

/* Downgrade: compare with the installed current generation, if any. */
static enum plugin_dist_status pd_check_downgrade(
    const struct plugin_dist_receive_request *rq, const struct plugin_manifest *m,
    struct plugin_dist_received *out)
{
    struct plugin_manifest cur;
    char cexe[PLUGIN_PATH_MAX];
    enum plugin_status cs =
        plugin_store_current(rq->plugins_dir, rq->name, &cur, cexe, sizeof(cexe));
    if (cs == PLUGIN_ERR_NOT_INSTALLED || cs == PLUGIN_ERR_NO_GENERATION)
        return PLUGIN_DIST_OK;
    if (cs != PLUGIN_OK) {
        out->plugin = cs;
        pd_detail(out->detail, sizeof(out->detail),
                  "the installed current generation cannot be read: %s",
                  plugin_status_code(cs));
        return PLUGIN_DIST_ERR_PLUGIN;
    }
    snprintf(out->current_version, sizeof(out->current_version), "%s", cur.version);
    bool comparable = false;
    int c = plugin_dist_version_compare(m->version, cur.version, &comparable);
    if (comparable && c >= 0)
        return PLUGIN_DIST_OK;
    if (rq->allow_downgrade) {
        out->downgrade_allowed = true;
        return PLUGIN_DIST_OK;
    }
    snprintf(out->detail, sizeof(out->detail),
             comparable ? "version %s is lower than installed current %s"
                        : "version %s cannot be compared with installed current %s",
             m->version, cur.version);
    return PLUGIN_DIST_ERR_DOWNGRADE;
}

static enum plugin_dist_status pd_checks(
    const struct plugin_dist_receive_request *rq, const struct pd_checkout *c,
    struct plugin_manifest *m, struct plugin_dist_received *out)
{
    enum plugin_dist_status ds = pd_check_pin(c, m, out);
    if (ds != PLUGIN_DIST_OK)
        return ds;
    if (strcmp(m->name, rq->name) != 0) {
        pd_detail(out->detail, sizeof(out->detail),
                  "the package carries plugin %s, not the requested name", m->name);
        return PLUGIN_DIST_ERR_SHAPE;
    }
    ds = pd_check_image(c, m, out);
    return ds != PLUGIN_DIST_OK ? ds : pd_check_downgrade(rq, m, out);
}

/* Root identity, completeness and member shape, before any file is written. */
static enum plugin_dist_status pd_precheck(const struct plugin_dist_receive_request *rq,
                                           struct plugin_dist_received *out)
{
    struct vcs_package_store_status status;
    if (!vcs_package_store_package_status(rq->store, rq->requested_root, &status)) {
        snprintf(out->detail, sizeof(out->detail), "the root is not in the local package store");
        return PLUGIN_DIST_ERR_NOT_FETCHED;
    }
    /* The transfer's claim and the stored manifest must both name exactly
     * the requested root. */
    if (rq->delivered_root && memcmp(rq->delivered_root, rq->requested_root, 32) != 0) {
        snprintf(out->detail, sizeof(out->detail),
                 "the transfer delivered a different root than the one requested");
        return PLUGIN_DIST_ERR_ROOT_MISMATCH;
    }
    uint8_t *wire = NULL, derived[32];
    size_t wire_len = 0;
    struct vcs_package_manifest pm;
    if (vcs_package_store_get_manifest_wire(rq->store, rq->requested_root, &wire,
                                            &wire_len) != VCS_PACKAGE_STORE_OK) {
        snprintf(out->detail, sizeof(out->detail),
                 "the manifest for the root cannot be read from the store");
        return PLUGIN_DIST_ERR_TRUNCATED;
    }
    bool parsed = vcs_package_manifest_parse(wire, wire_len, &pm);
    free(wire);
    if (!parsed) {
        snprintf(out->detail, sizeof(out->detail), "the stored manifest does not parse");
        return PLUGIN_DIST_ERR_ROOT_MISMATCH;
    }
    enum plugin_dist_status ds = PLUGIN_DIST_OK;
    if (!vcs_package_manifest_root(&pm, derived) ||
        memcmp(derived, rq->requested_root, 32) != 0) {
        snprintf(out->detail, sizeof(out->detail),
                 "the stored manifest hashes to a different root than requested");
        ds = PLUGIN_DIST_ERR_ROOT_MISMATCH;
    } else if (!status.complete) {
        snprintf(out->detail, sizeof(out->detail),
                 "the transfer is partial: %u of %u chunks present",
                 (unsigned)status.present_chunks, (unsigned)status.total_chunks);
        ds = PLUGIN_DIST_ERR_TRUNCATED;
    } else if (!pd_expect_members(&pm, rq->name)) {
        snprintf(out->detail, sizeof(out->detail),
                 "the package members are not exactly LICENSE, %s, %s.plugin.json, %s.plugin.sig",
                 rq->name, rq->name, rq->name);
        ds = PLUGIN_DIST_ERR_SHAPE;
    } else {
        for (size_t i = 0; i < pm.count; i++)
            if (strcmp(pm.files[i].path, rq->name) == 0 && pm.files[i].size > PD_IMAGE_MAX) {
                snprintf(out->detail, sizeof(out->detail),
                         "the image is %llu bytes, over the %llu byte cap",
                         (unsigned long long)pm.files[i].size,
                         (unsigned long long)PD_IMAGE_MAX);
                ds = PLUGIN_DIST_ERR_TOO_LARGE;
            }
    }
    vcs_package_manifest_free(&pm);
    return ds;
}

/* Verify a checked-out package, then store it as a NEW generation through
 * the existing install path, which does not touch current or last-good. */
static enum plugin_dist_status pd_verify_install(
    const struct plugin_dist_receive_request *rq, const char *dest,
    struct plugin_dist_received *out)
{
    struct pd_checkout c;
    struct plugin_manifest m, installed;
    int present = 0;
    if (!pd_checkout_paths(&c, dest, rq->name, rq->plugins_dir))
        return PLUGIN_DIST_ERR_IO;
    enum plugin_dist_status ds = pd_checks(rq, &c, &m, out);
    if (ds != PLUGIN_DIST_OK)
        return ds;
    enum plugin_status ps = plugin_store_install(rq->plugins_dir, c.manifest_path, &installed, &present);
    if (ps != PLUGIN_OK) {
        out->plugin = ps;
        snprintf(out->detail, sizeof(out->detail), "plugin install refused: %s",
                 plugin_status_code(ps));
        return PLUGIN_DIST_ERR_PLUGIN;
    }
    snprintf(out->name, sizeof(out->name), "%s", installed.name);
    snprintf(out->version, sizeof(out->version), "%s", installed.version);
    snprintf(out->generation, sizeof(out->generation), "%s", installed.generation);
    out->already_present = present != 0;
    return PLUGIN_DIST_OK;
}

static enum plugin_dist_status pd_checkout_install(
    const struct plugin_dist_receive_request *rq, struct plugin_dist_received *out)
{
    char holder[PLUGIN_PATH_MAX], dest[PLUGIN_PATH_MAX];
    if (!pd_join(holder, sizeof(holder), rq->scratch_dir, "plugin-dist-XXXXXX") ||
        !mkdtemp(holder) || !pd_join(dest, sizeof(dest), holder, "pkg")) {
        snprintf(out->detail, sizeof(out->detail), "cannot create a checkout directory");
        return PLUGIN_DIST_ERR_IO;
    }
    struct vcs_package_checkout_metrics metrics;
    enum plugin_dist_status ds = PLUGIN_DIST_OK;
    enum vcs_package_checkout_result cr =
        vcs_package_checkout(rq->store, rq->requested_root, dest, &metrics);
    if (cr != VCS_PACKAGE_CHECKOUT_OK) {
        snprintf(out->detail, sizeof(out->detail), "checkout refused: %s",
                 vcs_package_checkout_result_string(cr));
        ds = (cr == VCS_PACKAGE_CHECKOUT_INCOMPLETE || cr == VCS_PACKAGE_CHECKOUT_CHUNK)
                 ? PLUGIN_DIST_ERR_TRUNCATED : PLUGIN_DIST_ERR_IO;
    } else {
        ds = pd_verify_install(rq, dest, out);
    }
    pd_rm_checkout(dest, rq->name);
    (void)rmdir(holder);
    return ds;
}

static enum plugin_dist_status pd_receive(
    const struct plugin_dist_receive_request *rq,
    struct plugin_dist_received *out)
{
    if (!out)
        return PLUGIN_DIST_ERR_ARGUMENT;
    memset(out, 0, sizeof(*out));
    if (!rq || !rq->store || !rq->name || !plugin_name_valid(rq->name) ||
        !rq->plugins_dir || !rq->scratch_dir) {
        snprintf(out->detail, sizeof(out->detail),
                 "store, a valid plugin name, plugin store and scratch are required");
        return PLUGIN_DIST_ERR_ARGUMENT;
    }
    enum plugin_dist_status ds = pd_precheck(rq, out);
    return ds != PLUGIN_DIST_OK ? ds : pd_checkout_install(rq, out);
}

#endif /* !_WIN32 */

enum plugin_dist_status plugin_dist_publish(
    struct vcs_package_store *store,
    const struct plugin_dist_publish_request *request,
    struct plugin_dist_published *out)
{
#if defined(_WIN32)
    (void)store;
    (void)request;
    if (out) {
        memset(out, 0, sizeof(*out));
        snprintf(out->detail, sizeof(out->detail), "needs POSIX file semantics");
    }
    return PLUGIN_DIST_ERR_ARGUMENT;
#else
    return pd_publish(store, request, out);
#endif
}

enum plugin_dist_status plugin_dist_receive(
    const struct plugin_dist_receive_request *request,
    struct plugin_dist_received *out)
{
#if defined(_WIN32)
    (void)request;
    if (out) {
        memset(out, 0, sizeof(*out));
        snprintf(out->detail, sizeof(out->detail), "needs POSIX file semantics");
    }
    return PLUGIN_DIST_ERR_ARGUMENT;
#else
    return pd_receive(request, out);
#endif
}
