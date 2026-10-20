/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: publish a plugin generation as a package root and verify and
 *          install a delivered one as a new generation. See plugin_dist.h. */

#include "plugin/plugin_dist.h"

#include "plugin_internal.h"

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
#define PD_IMAGE_MAX (48u * 1024u * 1024u)

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

#if defined(_WIN32)

enum plugin_dist_status plugin_dist_publish(
    struct vcs_package_store *store,
    const struct plugin_dist_publish_request *request,
    struct plugin_dist_published *out)
{
    (void)store;
    (void)request;
    if (out)
        snprintf(out->detail, sizeof(out->detail), "needs POSIX file semantics");
    return PLUGIN_DIST_ERR_ARGUMENT;
}

enum plugin_dist_status plugin_dist_receive(
    const struct plugin_dist_receive_request *request,
    struct plugin_dist_received *out)
{
    (void)request;
    if (out)
        snprintf(out->detail, sizeof(out->detail), "needs POSIX file semantics");
    return PLUGIN_DIST_ERR_ARGUMENT;
}

#ifdef ZCL_TESTING
void plugin_dist_test_skip_source_check(bool skip) { (void)skip; }
#endif

#else /* POSIX */

#ifdef ZCL_TESTING
static bool g_skip_source_check;
void plugin_dist_test_skip_source_check(bool skip) { g_skip_source_check = skip; }
#define PD_SKIP_SOURCE_CHECK g_skip_source_check
#else
#define PD_SKIP_SOURCE_CHECK false
#endif

static bool pd_join(char *out, size_t cap, const char *a, const char *b)
{
    int n = snprintf(out, cap, "%s/%s", a, b);
    return n > 0 && (size_t)n < cap;
}

static void pd_detail(char *out, size_t cap, const char *fmt, const char *a)
{
    (void)snprintf(out, cap, fmt, a ? a : "");
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

static bool pd_hash_member(struct pd_member *m, size_t max_bytes)
{
    int fd = open(m->path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return false;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
        (uint64_t)st.st_size > max_bytes) {
        (void)close(fd);
        return false;
    }
    m->size = (uint64_t)st.st_size;
    m->chunks = (uint32_t)((m->size + VCS_PACKAGE_CHUNK_BYTES - 1) /
                           VCS_PACKAGE_CHUNK_BYTES);
    m->digests = calloc(m->chunks, 32);
    uint8_t *buf = malloc(VCS_PACKAGE_CHUNK_BYTES);
    bool ok = m->digests && buf;
    uint64_t left = m->size;
    for (uint32_t i = 0; ok && i < m->chunks; i++) {
        size_t want = left > VCS_PACKAGE_CHUNK_BYTES ? VCS_PACKAGE_CHUNK_BYTES
                                                     : (size_t)left;
        size_t got = 0;
        while (ok && got < want) {
            ssize_t r = read(fd, buf + got, want - got);
            if (r < 0 && errno == EINTR)
                continue;
            if (r <= 0)
                ok = false;
            else
                got += (size_t)r;
        }
        ok = ok && vcs_package_chunk_hash(buf, want, m->digests + (size_t)i * 32);
        left -= want;
    }
    free(buf);
    (void)close(fd);
    return ok;
}

static bool pd_put_member_chunks(struct vcs_package_store *store,
                                 const uint8_t root[32],
                                 const struct pd_member *m)
{
    int fd = open(m->path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return false;
    uint8_t *buf = malloc(VCS_PACKAGE_CHUNK_BYTES);
    bool ok = buf != NULL;
    uint64_t left = m->size;
    for (uint32_t i = 0; ok && i < m->chunks; i++) {
        size_t want = left > VCS_PACKAGE_CHUNK_BYTES ? VCS_PACKAGE_CHUNK_BYTES
                                                     : (size_t)left;
        size_t got = 0;
        while (ok && got < want) {
            ssize_t r = read(fd, buf + got, want - got);
            if (r < 0 && errno == EINTR)
                continue;
            if (r <= 0)
                ok = false;
            else
                got += (size_t)r;
        }
        /* The store hashes the bytes against the committed manifest, so a
         * file that changed since pd_hash_member is refused here. */
        ok = ok && vcs_package_store_put_chunk(store, root, m->leaf, i, buf,
                                               want) == VCS_PACKAGE_STORE_OK;
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

static enum plugin_dist_status pd_sign_release(
    struct vcs_package_store *store, const struct plugin_dist_publish_request *rq,
    const struct plugin_manifest *m, const uint8_t root[32],
    struct plugin_dist_published *out)
{
    if (!rq->release_key) {
        pd_detail(out->detail, sizeof(out->detail), "%s",
                  "--release-key is required: a hosting node serves only a signed release");
        return PLUGIN_DIST_ERR_RELEASE;
    }
    uint8_t seed[PLUGIN_KEY_FILE_BYTES];
    enum plugin_status ks = plugin_key_load(rq->release_key, seed);
    if (ks != PLUGIN_OK) {
        pd_detail(out->detail, sizeof(out->detail),
                  "release key refused: %s", plugin_status_code(ks));
        return PLUGIN_DIST_ERR_RELEASE;
    }
    struct privkey sk;
    struct pubkey pk;
    memset(&sk, 0, sizeof(sk));
    memcpy(sk.vch, seed, 32);
    memset(seed, 0, sizeof(seed));
    sk.fValid = true;
    sk.fCompressed = true;
    struct vcs_package_release r;
    memset(&r, 0, sizeof(r));
    bool ok = privkey_get_pubkey(&sk, &pk) &&
              pk.size == VCS_PACKAGE_RELEASE_PUBKEY_BYTES;
    if (!ok) {
        memset(&sk, 0, sizeof(sk));
        pd_detail(out->detail, sizeof(out->detail), "%s",
                  "the release key is not a valid secp256k1 secret");
        return PLUGIN_DIST_ERR_RELEASE;
    }
    r.schema_version = VCS_PACKAGE_RELEASE_VERSION;
    ok = snprintf(r.name, sizeof(r.name), "plugin/%s", m->name) > 0;
    ok = ok && snprintf(r.semver, sizeof(r.semver), "%s", m->version) > 0;
    memcpy(r.package_root, root, 32);
    /* A plugin has no build recipe: it is a prebuilt, separately signed
     * binary. The recipe root is a fixed domain-derived placeholder. */
    for (int i = 0; i < 32; i++)
        r.recipe_root[i] = (uint8_t)(0x50 + i);
    memcpy(r.publisher_pubkey, pk.vch, VCS_PACKAGE_RELEASE_PUBKEY_BYTES);
    r.publisher_sequence = rq->sequence ? rq->sequence : 1u;
    snprintf(r.license, sizeof(r.license), "%s", rq->spdx ? rq->spdx : "MIT");
    ok = ok && vcs_package_accept_chain_id(r.chain_id, sizeof(r.chain_id));
    uint8_t id[VCS_PACKAGE_RELEASE_ID_BYTES];
    enum vcs_package_release_error re =
        ok ? vcs_package_release_id(&r, id) : VCS_PACKAGE_RELEASE_OK;
    if (!ok || re != VCS_PACKAGE_RELEASE_OK) {
        memset(&sk, 0, sizeof(sk));
        pd_detail(out->detail, sizeof(out->detail), "release refused: %s",
                  ok ? vcs_package_release_error_string(re)
                     : "version is not semver or the chain id is unavailable");
        return PLUGIN_DIST_ERR_RELEASE;
    }
    struct uint256 hash;
    memcpy(hash.data, id, 32);
    unsigned char compact[COMPACT_SIGNATURE_SIZE];
    ok = privkey_sign_compact(&sk, &hash, compact);
    memset(&sk, 0, sizeof(sk));
    if (!ok) {
        pd_detail(out->detail, sizeof(out->detail), "%s", "release signing failed");
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

enum plugin_dist_status plugin_dist_publish(
    struct vcs_package_store *store,
    const struct plugin_dist_publish_request *rq,
    struct plugin_dist_published *out)
{
    if (!out)
        return PLUGIN_DIST_ERR_ARGUMENT;
    memset(out, 0, sizeof(*out));
    if (!store || !rq || !rq->name || !plugin_name_valid(rq->name) ||
        !rq->license_file) {
        snprintf(out->detail, sizeof(out->detail),
                 "store, a valid plugin name and --license-file are required");
        return PLUGIN_DIST_ERR_ARGUMENT;
    }
    char dir[PLUGIN_PATH_MAX];
    enum plugin_dist_status ds = pd_source(rq, dir, out);
    if (ds != PLUGIN_DIST_OK)
        return ds;

    /* The three generation files must agree before they are offered. */
    struct pd_member mem[4];
    memset(mem, 0, sizeof(mem));
    snprintf(mem[0].leaf, sizeof(mem[0].leaf), "LICENSE");
    snprintf(mem[1].leaf, sizeof(mem[1].leaf), "%s", rq->name);
    snprintf(mem[2].leaf, sizeof(mem[2].leaf), "%s.plugin.json", rq->name);
    snprintf(mem[3].leaf, sizeof(mem[3].leaf), "%s.plugin.sig", rq->name);
    snprintf(mem[0].path, sizeof(mem[0].path), "%s", rq->license_file);
    for (int i = 1; i < 4; i++)
        if (!pd_join(mem[i].path, sizeof(mem[i].path), dir, mem[i].leaf))
            return PLUGIN_DIST_ERR_ARGUMENT;
    mem[0].mode = mem[2].mode = mem[3].mode = VCS_PACKAGE_MODE_FILE;
    mem[1].mode = VCS_PACKAGE_MODE_EXECUTABLE;

    char *manifest_bytes = NULL, *sig_bytes = NULL, *license = NULL;
    size_t manifest_len = 0, sig_len = 0, license_len = 0;
    struct plugin_manifest m;
    enum plugin_dist_status result = PLUGIN_DIST_ERR_SOURCE;
    if (!plugin_read_file(mem[2].path, PLUGIN_FILE_MAX, PLUGIN_OPEN_NOFOLLOW,
                          &manifest_bytes, &manifest_len) ||
        !plugin_read_file(mem[3].path, PLUGIN_FILE_MAX, PLUGIN_OPEN_NOFOLLOW,
                          &sig_bytes, &sig_len)) {
        pd_detail(out->detail, sizeof(out->detail),
                  "cannot read the manifest or signature in %s", dir);
        goto done;
    }
    if (plugin_manifest_parse(manifest_bytes, manifest_len, &m) != PLUGIN_OK ||
        strcmp(m.name, rq->name) != 0) {
        pd_detail(out->detail, sizeof(out->detail),
                  "the manifest in %s is not a valid manifest for this plugin", dir);
        goto done;
    }
    char digest[PLUGIN_HEX_SHA3_512 + 1];
    if (!PD_SKIP_SOURCE_CHECK &&
        (plugin_hash_file(mem[1].path, digest) != PLUGIN_OK ||
         strcmp(digest, m.exe_sha3) != 0)) {
        pd_detail(out->detail, sizeof(out->detail),
                  "the image in %s does not match the manifest sha3_512", dir);
        goto done;
    }
    if (!plugin_read_file(rq->license_file, PD_LICENSE_MAX, 0, &license,
                          &license_len) ||
        !vcs_package_release_license_text_matches(rq->spdx ? rq->spdx : "MIT",
                                                  (const uint8_t *)license,
                                                  license_len)) {
        pd_detail(out->detail, sizeof(out->detail),
                  "the license file is unreadable or is not the %s text",
                  rq->spdx ? rq->spdx : "MIT");
        result = PLUGIN_DIST_ERR_LICENSE;
        goto done;
    }

    struct vcs_package_manifest pm;
    vcs_package_manifest_init(&pm);
    bool ok = true;
    for (int i = 0; ok && i < 4; i++) {
        ok = pd_hash_member(&mem[i], i == 1 ? PD_IMAGE_MAX : PD_LICENSE_MAX) &&
             vcs_package_manifest_add(&pm, mem[i].leaf, mem[i].mode, mem[i].size,
                                      mem[i].digests, mem[i].chunks);
        if (ok)
            out->bytes += mem[i].size;
    }
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    result = PLUGIN_DIST_ERR_STORE;
    ok = ok && vcs_package_manifest_serialize(&pm, &wire, &wire_len) &&
         vcs_package_store_put_manifest(store, wire, wire_len, out->root) ==
             VCS_PACKAGE_STORE_OK;
    for (int i = 0; ok && i < 4; i++)
        ok = pd_put_member_chunks(store, out->root, &mem[i]);
    free(wire);
    vcs_package_manifest_free(&pm);
    if (!ok) {
        pd_detail(out->detail, sizeof(out->detail), "%s",
                  "the package store refused the manifest or a chunk");
        goto done;
    }
    result = pd_sign_release(store, rq, &m, out->root, out);
    if (result != PLUGIN_DIST_OK)
        goto done;
    /* Pinned roots are never evicted, so the offer outlives pool pressure. */
    if (vcs_package_store_pin(store, out->root, true) != VCS_PACKAGE_STORE_OK) {
        pd_detail(out->detail, sizeof(out->detail), "%s",
                  "the root was stored and signed but could not be pinned");
        result = PLUGIN_DIST_ERR_STORE;
        goto done;
    }
    static const char hexdigits[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out->root_hex[2 * i] = hexdigits[out->root[i] >> 4];
        out->root_hex[2 * i + 1] = hexdigits[out->root[i] & 15];
    }
    snprintf(out->name, sizeof(out->name), "%s", m.name);
    snprintf(out->version, sizeof(out->version), "%s", m.version);
    snprintf(out->exe_sha3, sizeof(out->exe_sha3), "%s", m.exe_sha3);
    out->files = 4;
    /* The signed-manifest digest is the generation id; recompute it from
     * the exact bytes without trusting the signer's key list. */
    uint8_t md[PLUGIN_DIGEST_BYTES];
    plugin_manifest_digest(manifest_bytes, manifest_len, md);
    for (size_t i = 0; i < PLUGIN_DIGEST_BYTES; i++) {
        out->generation[2 * i] = hexdigits[md[i] >> 4];
        out->generation[2 * i + 1] = hexdigits[md[i] & 15];
    }
    out->generation[PLUGIN_HEX_SHA3_512] = '\0';
    result = PLUGIN_DIST_OK;
done:
    for (int i = 0; i < 4; i++)
        free(mem[i].digests);
    free(manifest_bytes);
    free(sig_bytes);
    free(license);
    return result;
}

/* ---- receive ----------------------------------------------------------- */

static void pd_rm_checkout(const char *dest, const char *name)
{
    static const char *const fixed[] = {"LICENSE"};
    char path[PLUGIN_PATH_MAX], leaf[PLUGIN_NAME_MAX + 32];
    for (size_t i = 0; i < sizeof(fixed) / sizeof(fixed[0]); i++)
        if (pd_join(path, sizeof(path), dest, fixed[i]))
            (void)unlink(path);
    const char *suffix[] = {"", ".plugin.json", ".plugin.sig"};
    for (size_t i = 0; i < 3; i++)
        if (snprintf(leaf, sizeof(leaf), "%s%s", name, suffix[i]) > 0 &&
            pd_join(path, sizeof(path), dest, leaf))
            (void)unlink(path);
    (void)rmdir(dest);
}

static bool pd_expect_members(const struct vcs_package_manifest *pm,
                              const char *name)
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

static enum plugin_dist_status pd_checks(
    const struct plugin_dist_receive_request *rq, const char *dest,
    struct plugin_manifest *m, struct plugin_dist_received *out)
{
    char mpath[PLUGIN_PATH_MAX], spath[PLUGIN_PATH_MAX], epath[PLUGIN_PATH_MAX],
        leaf[PLUGIN_NAME_MAX + 32], keys[PLUGIN_PATH_MAX];
    snprintf(leaf, sizeof(leaf), "%s.plugin.json", rq->name);
    bool ok = pd_join(mpath, sizeof(mpath), dest, leaf);
    snprintf(leaf, sizeof(leaf), "%s.plugin.sig", rq->name);
    ok = ok && pd_join(spath, sizeof(spath), dest, leaf) &&
         pd_join(epath, sizeof(epath), dest, rq->name) &&
         pd_join(keys, sizeof(keys), rq->plugins_dir, "publisher_keys");
    char *mb = NULL, *sb = NULL;
    size_t ml = 0, sl = 0;
    enum plugin_dist_status result = PLUGIN_DIST_ERR_IO;
    if (!ok || !plugin_read_file(mpath, PLUGIN_FILE_MAX, PLUGIN_OPEN_NOFOLLOW, &mb, &ml) ||
        !plugin_read_file(spath, PLUGIN_FILE_MAX, PLUGIN_OPEN_NOFOLLOW, &sb, &sl)) {
        pd_detail(out->detail, sizeof(out->detail), "%s",
                  "the checked-out manifest or signature cannot be read");
        goto done;
    }
    /* Publisher pin: the signing key must already be in this machine's
     * publisher_keys. Nothing a peer sends can add to that list. */
    enum plugin_status vs = plugin_verify_manifest(mb, ml, sb, sl, keys, m);
    if (vs == PLUGIN_ERR_KEY_UNKNOWN || vs == PLUGIN_ERR_NO_KEYS) {
        pd_detail(out->detail, sizeof(out->detail),
                  "the signing key is not in publisher_keys (%s)",
                  plugin_status_code(vs));
        result = PLUGIN_DIST_ERR_PUBLISHER_UNPINNED;
        goto done;
    }
    if (vs != PLUGIN_OK) {
        out->plugin = vs;
        pd_detail(out->detail, sizeof(out->detail),
                  "manifest or signature refused: %s", plugin_status_code(vs));
        result = PLUGIN_DIST_ERR_PLUGIN;
        goto done;
    }
    if (strcmp(m->name, rq->name) != 0) {
        pd_detail(out->detail, sizeof(out->detail),
                  "the package carries plugin %s, not the requested name", m->name);
        result = PLUGIN_DIST_ERR_SHAPE;
        goto done;
    }
    /* The image is hashed from the bytes that were checked out, against the
     * signed manifest, before the plugin store sees any of it. */
    char digest[PLUGIN_HEX_SHA3_512 + 1];
    if (plugin_hash_file(epath, digest) != PLUGIN_OK ||
        strcmp(digest, m->exe_sha3) != 0) {
        pd_detail(out->detail, sizeof(out->detail), "%s",
                  "the image SHA3-512 differs from the signed manifest sha3_512");
        result = PLUGIN_DIST_ERR_IMAGE_HASH;
        goto done;
    }
    /* Downgrade: compare with the installed current generation, if any. */
    struct plugin_manifest cur;
    char cexe[PLUGIN_PATH_MAX];
    enum plugin_status cs =
        plugin_store_current(rq->plugins_dir, rq->name, &cur, cexe, sizeof(cexe));
    if (cs == PLUGIN_OK) {
        snprintf(out->current_version, sizeof(out->current_version), "%s", cur.version);
        bool comparable = false;
        int c = plugin_dist_version_compare(m->version, cur.version, &comparable);
        if (!comparable || c < 0) {
            if (!rq->allow_downgrade) {
                snprintf(out->detail, sizeof(out->detail),
                         comparable ? "version %s is lower than installed current %s"
                                    : "version %s cannot be compared with installed current %s",
                         m->version, cur.version);
                result = PLUGIN_DIST_ERR_DOWNGRADE;
                goto done;
            }
            out->downgrade_allowed = true;
        }
    } else if (cs != PLUGIN_ERR_NOT_INSTALLED && cs != PLUGIN_ERR_NO_GENERATION) {
        out->plugin = cs;
        pd_detail(out->detail, sizeof(out->detail),
                  "the installed current generation cannot be read: %s",
                  plugin_status_code(cs));
        result = PLUGIN_DIST_ERR_PLUGIN;
        goto done;
    }
    result = PLUGIN_DIST_OK;
done:
    free(mb);
    free(sb);
    return result;
}

enum plugin_dist_status plugin_dist_receive(
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
    struct vcs_package_store_status status;
    if (!vcs_package_store_package_status(rq->store, rq->requested_root, &status)) {
        snprintf(out->detail, sizeof(out->detail),
                 "the root is not in the local package store");
        return PLUGIN_DIST_ERR_NOT_FETCHED;
    }
    /* 1. Root identity: the transfer's claim and the stored manifest must
     * both name exactly the requested root. */
    if (rq->delivered_root && memcmp(rq->delivered_root, rq->requested_root, 32) != 0) {
        snprintf(out->detail, sizeof(out->detail),
                 "the transfer delivered a different root than the one requested");
        return PLUGIN_DIST_ERR_ROOT_MISMATCH;
    }
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_package_store_get_manifest_wire(rq->store, rq->requested_root, &wire,
                                            &wire_len) != VCS_PACKAGE_STORE_OK) {
        snprintf(out->detail, sizeof(out->detail),
                 "the manifest for the root cannot be read from the store");
        return PLUGIN_DIST_ERR_TRUNCATED;
    }
    struct vcs_package_manifest pm;
    uint8_t derived[32];
    bool parsed = vcs_package_manifest_parse(wire, wire_len, &pm);
    free(wire);
    if (!parsed) {
        snprintf(out->detail, sizeof(out->detail), "the stored manifest does not parse");
        return PLUGIN_DIST_ERR_ROOT_MISMATCH;
    }
    if (!vcs_package_manifest_root(&pm, derived) ||
        memcmp(derived, rq->requested_root, 32) != 0) {
        vcs_package_manifest_free(&pm);
        snprintf(out->detail, sizeof(out->detail),
                 "the stored manifest hashes to a different root than requested");
        return PLUGIN_DIST_ERR_ROOT_MISMATCH;
    }
    /* 2. Completeness, before any file is materialised. */
    if (!status.complete) {
        vcs_package_manifest_free(&pm);
        snprintf(out->detail, sizeof(out->detail),
                 "the transfer is partial: %u of %u chunks present",
                 (unsigned)status.present_chunks, (unsigned)status.total_chunks);
        return PLUGIN_DIST_ERR_TRUNCATED;
    }
    bool shape = pd_expect_members(&pm, rq->name);
    vcs_package_manifest_free(&pm);
    if (!shape) {
        snprintf(out->detail, sizeof(out->detail),
                 "the package members are not exactly LICENSE, %s, %s.plugin.json, %s.plugin.sig",
                 rq->name, rq->name, rq->name);
        return PLUGIN_DIST_ERR_SHAPE;
    }

    char holder[PLUGIN_PATH_MAX], dest[PLUGIN_PATH_MAX];
    if (!pd_join(holder, sizeof(holder), rq->scratch_dir, "plugin-dist-XXXXXX") ||
        !mkdtemp(holder)) {
        snprintf(out->detail, sizeof(out->detail), "cannot create a checkout directory");
        return PLUGIN_DIST_ERR_IO;
    }
    enum plugin_dist_status result = PLUGIN_DIST_ERR_IO;
    struct vcs_package_checkout_metrics metrics;
    struct plugin_manifest m;
    if (!pd_join(dest, sizeof(dest), holder, "pkg"))
        goto cleanup;
    enum vcs_package_checkout_result cr =
        vcs_package_checkout(rq->store, rq->requested_root, dest, &metrics);
    if (cr != VCS_PACKAGE_CHECKOUT_OK) {
        snprintf(out->detail, sizeof(out->detail), "checkout refused: %s",
                 vcs_package_checkout_result_string(cr));
        result = (cr == VCS_PACKAGE_CHECKOUT_INCOMPLETE ||
                  cr == VCS_PACKAGE_CHECKOUT_CHUNK)
                     ? PLUGIN_DIST_ERR_TRUNCATED : PLUGIN_DIST_ERR_IO;
        goto cleanup;
    }
    result = pd_checks(rq, dest, &m, out);
    if (result != PLUGIN_DIST_OK)
        goto cleanup;
    /* 3. The existing install path stores a NEW generation; it does not
     * touch current or last-good. */
    char mpath[PLUGIN_PATH_MAX], leaf[PLUGIN_NAME_MAX + 32];
    int present = 0;
    struct plugin_manifest installed;
    snprintf(leaf, sizeof(leaf), "%s.plugin.json", rq->name);
    if (!pd_join(mpath, sizeof(mpath), dest, leaf)) {
        result = PLUGIN_DIST_ERR_IO;
        goto cleanup;
    }
    enum plugin_status ps = plugin_store_install(rq->plugins_dir, mpath, &installed, &present);
    if (ps != PLUGIN_OK) {
        out->plugin = ps;
        snprintf(out->detail, sizeof(out->detail), "plugin install refused: %s",
                 plugin_status_code(ps));
        result = PLUGIN_DIST_ERR_PLUGIN;
        goto cleanup;
    }
    snprintf(out->name, sizeof(out->name), "%s", installed.name);
    snprintf(out->version, sizeof(out->version), "%s", installed.version);
    snprintf(out->generation, sizeof(out->generation), "%s", installed.generation);
    out->already_present = present != 0;
    result = PLUGIN_DIST_OK;
cleanup:
    pd_rm_checkout(dest, rq->name);
    (void)rmdir(holder);
    return result;
}

#endif /* POSIX */
