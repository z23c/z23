/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: prove the signed plugin store refuses unsigned, unknown-key and
 * altered plugins, keeps generations content addressed, and swaps the
 * current and last-good links without ever leaving them dangling. Fixtures
 * live under the repository test-tmp directory and sign with real Ed25519. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "crypto/ed25519.h"
#include "json/json.h"
#include "platform/atomic_link.h"
#include "plugin/plugin_pack.h"
#include "plugin/plugin_store.h"
#include "sha3/sha3.h"

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define PST_HEX (PLUGIN_HEX_SHA3_512 + 1)

struct pst_fx {
    char base[PATH_MAX];
    char home[PATH_MAX];
    char root[PATH_MAX];
    char src[PATH_MAX];
    uint8_t pk[2][32];
    uint8_t sk[2][32];
    char manifest[PATH_MAX];
    char generation[PST_HEX];
};

struct pst_opts {
    int key;
    const char *extra;
    const char *caps; /* JSON capability list body; default fs.read and clock */
    const char *sig_alg;
    bool tamper_exe;
    bool tamper_manifest;
};

static void pst_hex(const uint8_t *in, size_t n, char *out)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = d[in[i] >> 4];
        out[2 * i + 1] = d[in[i] & 15];
    }
    out[2 * n] = '\0';
}

static bool pst_write(const char *path, const char *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    bool ok = f && fwrite(data, 1, len, f) == len;
    if (f)
        ok = fclose(f) == 0 && ok;
    return ok;
}

/* Owner-only file, whatever the process umask: the keys_file file must be one. */
static bool pst_write_private(const char *path, const char *data, size_t len)
{
    return pst_write(path, data, len) && chmod(path, 0600) == 0;
}

static bool pst_slurp(const char *path, char *out, size_t cap)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    size_t n = fread(out, 1, cap - 1, f);
    fclose(f);
    out[n] = '\0';
    return true;
}

static bool pst_path(char *out, size_t cap, const char *a, const char *b)
{
    int n = snprintf(out, cap, "%s/%s", a, b);
    return n > 0 && (size_t)n < cap;
}

static bool pst_fx_open(struct pst_fx *fx, bool with_keys)
{
    memset(fx, 0, sizeof(*fx));
    if (!test_mkdtemp(fx->base, sizeof(fx->base), "plugin_store"))
        return false;
    bool ok = pst_path(fx->home, sizeof(fx->home), fx->base, "home") &&
              mkdir(fx->home, 0700) == 0;
    char dot[PATH_MAX];
    ok = ok && pst_path(dot, sizeof(dot), fx->home, ".z23") &&
         mkdir(dot, 0700) == 0 && pst_path(fx->root, sizeof(fx->root), dot, "plugins") &&
         mkdir(fx->root, 0700) == 0 &&
         pst_path(fx->src, sizeof(fx->src), fx->base, "src") &&
         mkdir(fx->src, 0700) == 0;
    for (int k = 0; k < 2; k++) {
        uint8_t seed[32];
        memset(seed, 0x11 * (k + 1), sizeof(seed));
        zcl_ed25519_keypair(fx->pk[k], fx->sk[k], seed);
    }
    if (ok && with_keys) {
        char hex[65], line[80], path[PATH_MAX];
        pst_hex(fx->pk[0], 32, hex);
        snprintf(line, sizeof(line), "%s\n", hex);
        ok = pst_path(path, sizeof(path), fx->root, "publisher_keys") &&
             pst_write_private(path, line, strlen(line));
    }
    return ok;
}

static void pst_fx_close(struct pst_fx *fx)
{
    if (fx->base[0])
        (void)test_rm_rf_recursive(fx->base);
}

static void pst_digest(const char *manifest, unsigned char digest[64])
{
    static const unsigned char domain[] = "z23.plugin.manifest.v1";
    struct sha3_512_ctx ctx;
    sha3_512_init(&ctx);
    sha3_512_write(&ctx, domain, sizeof(domain));
    sha3_512_write(&ctx, (const unsigned char *)manifest, strlen(manifest));
    sha3_512_finalize(&ctx, digest);
}

static void pst_sign(const struct pst_fx *fx, int key, const char *manifest,
                     char sig_hex[129])
{
    unsigned char digest[64];
    uint8_t sig[64];
    pst_digest(manifest, digest);
    zcl_ed25519_sign(sig, digest, sizeof(digest), fx->sk[key], fx->pk[key]);
    pst_hex(sig, 64, sig_hex);
}

static bool pst_flip_version(const char *path)
{
    char buf[1024];
    if (!pst_slurp(path, buf, sizeof(buf)))
        return false;
    char *p = strstr(buf, "1.0.0");
    if (!p)
        return false;
    p[4] = '1';
    return pst_write(path, buf, strlen(buf));
}

/* Writes NAME, NAME.plugin.json and NAME.plugin.sig under fx->src. */
static bool pst_publish(struct pst_fx *fx, const char *name, const char *exe,
                        const struct pst_opts *o)
{
    unsigned char digest[64];
    char sha[129], sig_hex[129], pub[65], path[PATH_MAX], leaf[96];
    char manifest[1024], sigdoc[512];
    zcl_sha3_512((const unsigned char *)exe, strlen(exe), digest);
    pst_hex(digest, 64, sha);
    snprintf(manifest, sizeof(manifest),
             "{\"schema\":\"z23.plugin.v1\",\"name\":\"%s\",\"version\":\"1.0.0\","
             "\"interface_version\":1,\"sha3_512\":\"%s\","
             "\"capabilities\":[%s]%s}",
             name, sha, o->caps ? o->caps : "\"fs.read\",\"clock\"",
             o->extra ? o->extra : "");
    /* A generation is named by the signed manifest digest, which covers the
     * capabilities as well as the executable hash. */
    pst_digest(manifest, digest);
    pst_hex(digest, 64, fx->generation);
    pst_sign(fx, o->key, manifest, sig_hex);
    pst_hex(fx->pk[o->key], 32, pub);
    snprintf(sigdoc, sizeof(sigdoc),
             "{\"sig_alg\":\"%s\",\"public_key\":\"%s\",\"signature\":\"%s\"}",
             o->sig_alg ? o->sig_alg : "ed25519", pub, sig_hex);
    snprintf(leaf, sizeof(leaf), "%s.plugin.json", name);
    bool ok = pst_path(fx->manifest, sizeof(fx->manifest), fx->src, leaf) &&
              pst_write(fx->manifest, manifest, strlen(manifest));
    snprintf(leaf, sizeof(leaf), "%s.plugin.sig", name);
    ok = ok && pst_path(path, sizeof(path), fx->src, leaf) &&
         pst_write(path, sigdoc, strlen(sigdoc)) &&
         pst_path(path, sizeof(path), fx->src, name) &&
         pst_write(path, o->tamper_exe ? "tampered" : exe, o->tamper_exe ? 8 : strlen(exe));
    return ok && (!o->tamper_manifest || pst_flip_version(fx->manifest));
}

static enum plugin_status pst_install(struct pst_fx *fx, const char *name,
                                      const char *exe, const struct pst_opts *o)
{
    struct plugin_manifest m;
    int present = 0;
    if (!pst_publish(fx, name, exe, o))
        return PLUGIN_ERR_IO;
    return plugin_store_install(fx->root, fx->manifest, &m, &present);
}

/* Target of NAME/link without the "generations/" prefix, or "". */
static void pst_link(const struct pst_fx *fx, const char *name, const char *link,
                     char out[PST_HEX])
{
    char dir[PATH_MAX], path[PATH_MAX], target[PATH_MAX];
    out[0] = '\0';
    if (!pst_path(dir, sizeof(dir), fx->root, name) ||
        !pst_path(path, sizeof(path), dir, link))
        return;
    ssize_t n = readlink(path, target, sizeof(target) - 1);
    if (n > 12 && strncmp(target, "generations/", 12) == 0 && (size_t)n - 12 < PST_HEX) {
        target[n] = '\0';
        memcpy(out, target + 12, (size_t)n - 12 + 1);
    }
}

static bool pst_exists(const char *a, const char *b)
{
    char p[PATH_MAX];
    return pst_path(p, sizeof(p), a, b) && access(p, F_OK) == 0;
}

static int pst_case_install_valid(void)
{
    int failures = 0;
    TEST_CASE("valid install stores a 0555 executable under its SHA3-512") {
        struct pst_fx fx;
        struct pst_opts o = {0};
        struct plugin_manifest m;
        int present = -1;
        char dir[PATH_MAX], exe[PATH_MAX], cur[PST_HEX], body[64];
        struct stat st;
        ASSERT(pst_fx_open(&fx, true));
        ASSERT(pst_publish(&fx, "hello", "#!/bin/sh\necho hi\n", &o));
        ASSERT_EQ(plugin_store_install(fx.root, fx.manifest, &m, &present), PLUGIN_OK);
        ASSERT_EQ(present, 0);
        ASSERT_STR_EQ(m.generation, fx.generation);
        ASSERT_EQ(m.capabilities, 1u | 32u);
        snprintf(dir, sizeof(dir), "%s/hello/generations/%s", fx.root, fx.generation);
        snprintf(exe, sizeof(exe), "%s/hello", dir);
        ASSERT_EQ(stat(exe, &st), 0);
        ASSERT_EQ((unsigned)(st.st_mode & 0777), 0555u);
        ASSERT(pst_slurp(exe, body, sizeof(body)) && strcmp(body, "#!/bin/sh\necho hi\n") == 0);
        pst_link(&fx, "hello", "current", cur);
        ASSERT_EQ(cur[0], '\0');
        ASSERT_EQ(plugin_store_install(fx.root, fx.manifest, &m, &present), PLUGIN_OK);
        ASSERT_EQ(present, 1);
        pst_fx_close(&fx);
    } TEST_END
    return failures;
}

static int pst_case_integrity_refusals(void)
{
    int failures = 0;
    TEST_CASE("tampered executable and manifest are refused and leave no trace") {
        struct pst_fx fx;
        struct pst_opts exe = { .tamper_exe = true };
        struct pst_opts man = { .tamper_manifest = true };
        ASSERT(pst_fx_open(&fx, true));
        ASSERT_EQ(pst_install(&fx, "hello", "payload", &exe), PLUGIN_ERR_EXE_HASH);
        ASSERT(!pst_exists(fx.root, "hello"));
        ASSERT_EQ(pst_install(&fx, "hello", "payload", &man), PLUGIN_ERR_SIG_BAD);
        ASSERT(!pst_exists(fx.root, "hello"));
        pst_fx_close(&fx);
    } TEST_END
    return failures;
}

static int pst_case_keys_refusals(void)
{
    int failures = 0;
    TEST_CASE("unknown signing key and missing keys_file file are refused") {
        struct pst_fx fx;
        struct pst_opts other = { .key = 1 };
        struct pst_opts good = {0};
        char keys_file[PATH_MAX];
        ASSERT(pst_fx_open(&fx, true));
        ASSERT_EQ(pst_install(&fx, "hello", "payload", &other), PLUGIN_ERR_KEY_UNKNOWN);
        ASSERT(pst_path(keys_file, sizeof(keys_file), fx.root, "publisher_keys"));
        ASSERT_EQ(unlink(keys_file), 0);
        ASSERT_EQ(pst_install(&fx, "hello", "payload", &good), PLUGIN_ERR_NO_KEYS);
        ASSERT(!pst_exists(fx.root, "hello"));
        pst_fx_close(&fx);
    } TEST_END
    return failures;
}

static int pst_case_strict_format(void)
{
    int failures = 0;
    TEST_CASE("duplicate key, unknown key and unknown sig_alg are refused") {
        struct pst_fx fx;
        struct pst_opts dup = { .extra = ",\"version\":\"9.9.9\"" };
        struct pst_opts unk = { .extra = ",\"extra\":1" };
        struct pst_opts okay = { .extra = "" };
        struct pst_opts alg = { .sig_alg = "rsa" };
        ASSERT(pst_fx_open(&fx, true));
        ASSERT_EQ(pst_install(&fx, "hello", "payload", &dup),
                  PLUGIN_ERR_MANIFEST_DUPLICATE_KEY);
        ASSERT_EQ(pst_install(&fx, "hello", "payload", &unk),
                  PLUGIN_ERR_MANIFEST_UNKNOWN_KEY);
        ASSERT_EQ(pst_install(&fx, "hello", "payload", &alg), PLUGIN_ERR_SIG_ALG);
        ASSERT_EQ(pst_install(&fx, "hello", "payload", &okay), PLUGIN_OK);
        ASSERT(!pst_exists(fx.root, "other"));
        pst_fx_close(&fx);
    } TEST_END
    return failures;
}

static int pst_case_manifest_vocabulary(void)
{
    int failures = 0;
    TEST_CASE("manifest parser refuses unknown capabilities and bad names") {
        struct plugin_manifest m;
        const char *base =
            "{\"schema\":\"z23.plugin.v1\",\"name\":\"%s\",\"version\":\"1\","
            "\"interface_version\":1,\"sha3_512\":\"%s\",\"capabilities\":[%s]}";
        char hex[129], doc[512];
        memset(hex, 'a', 128);
        hex[128] = '\0';
        snprintf(doc, sizeof(doc), base, "ok-1", hex, "\"fs.read\"");
        ASSERT_EQ(plugin_manifest_parse(doc, strlen(doc), &m), PLUGIN_OK);
        snprintf(doc, sizeof(doc), base, "ok-1", hex, "\"root.everything\"");
        ASSERT_EQ(plugin_manifest_parse(doc, strlen(doc), &m), PLUGIN_ERR_MANIFEST_INVALID);
        snprintf(doc, sizeof(doc), base, "ok-1", hex, "\"fs.read\",\"fs.read\"");
        ASSERT_EQ(plugin_manifest_parse(doc, strlen(doc), &m), PLUGIN_ERR_MANIFEST_INVALID);
        snprintf(doc, sizeof(doc), base, "Bad_Name", hex, "");
        ASSERT_EQ(plugin_manifest_parse(doc, strlen(doc), &m), PLUGIN_ERR_MANIFEST_INVALID);
        snprintf(doc, sizeof(doc), base, "ok-1", "ABC", "");
        ASSERT_EQ(plugin_manifest_parse(doc, strlen(doc), &m), PLUGIN_ERR_MANIFEST_INVALID);
        ASSERT_EQ(plugin_manifest_parse("not json", 8, &m), PLUGIN_ERR_MANIFEST_INVALID);
    } TEST_END
    return failures;
}

static int pst_case_switch_rollback(void)
{
    int failures = 0;
    TEST_CASE("switch records last-good and rollback restores it") {
        struct pst_fx fx;
        struct pst_opts o = {0};
        char a[PST_HEX], b[PST_HEX], cur[PST_HEX], lg[PST_HEX], back[PST_HEX];
        struct plugin_info *infos = NULL;
        size_t count = 0;
        ASSERT(pst_fx_open(&fx, true));
        ASSERT_EQ(pst_install(&fx, "hello", "version one", &o), PLUGIN_OK);
        memcpy(a, fx.generation, PST_HEX);
        ASSERT_EQ(pst_install(&fx, "hello", "version two", &o), PLUGIN_OK);
        memcpy(b, fx.generation, PST_HEX);
        ASSERT_EQ(plugin_store_switch(fx.root, "hello", a), PLUGIN_OK);
        pst_link(&fx, "hello", "current", cur);
        pst_link(&fx, "hello", "last-good", lg);
        ASSERT_STR_EQ(cur, a);
        ASSERT_EQ(lg[0], '\0');
        ASSERT_EQ(plugin_store_switch(fx.root, "hello", b), PLUGIN_OK);
        pst_link(&fx, "hello", "current", cur);
        pst_link(&fx, "hello", "last-good", lg);
        ASSERT_STR_EQ(cur, b);
        ASSERT_STR_EQ(lg, a);
        ASSERT_EQ(plugin_store_rollback(fx.root, "hello", back), PLUGIN_OK);
        pst_link(&fx, "hello", "current", cur);
        ASSERT_STR_EQ(cur, a);
        ASSERT_STR_EQ(back, a);
        ASSERT_EQ(plugin_store_list(fx.root, &infos, &count), PLUGIN_OK);
        ASSERT_EQ(count, 1u);
        ASSERT_EQ(infos[0].generation_count, 2u);
        ASSERT_STR_EQ(infos[0].current, a);
        ASSERT_STR_EQ(infos[0].last_good, a);
        plugin_store_list_free(infos, count);
        pst_fx_close(&fx);
    } TEST_END
    return failures;
}

static int pst_case_interrupted_swap(void)
{
    int failures = 0;
    TEST_CASE("an interrupted swap leaves current intact and the next swap clean") {
        struct pst_fx fx;
        struct pst_opts o = {0};
        char a[PST_HEX], b[PST_HEX], cur[PST_HEX], stale[PATH_MAX], bogus[PST_HEX];
        ASSERT(pst_fx_open(&fx, true));
        ASSERT_EQ(pst_install(&fx, "hello", "version one", &o), PLUGIN_OK);
        memcpy(a, fx.generation, PST_HEX);
        ASSERT_EQ(pst_install(&fx, "hello", "version two", &o), PLUGIN_OK);
        memcpy(b, fx.generation, PST_HEX);
        ASSERT_EQ(plugin_store_switch(fx.root, "hello", a), PLUGIN_OK);
        snprintf(stale, sizeof(stale), "%s/hello/current.new.%ld", fx.root, (long)getpid());
        ASSERT_EQ(symlink("generations/dangling", stale), 0);
        memset(bogus, 'a', 128);
        bogus[128] = '\0';
        ASSERT_EQ(plugin_store_switch(fx.root, "hello", bogus), PLUGIN_ERR_NO_GENERATION);
        pst_link(&fx, "hello", "current", cur);
        ASSERT_STR_EQ(cur, a);
        ASSERT_EQ(plugin_store_switch(fx.root, "hello", b), PLUGIN_OK);
        pst_link(&fx, "hello", "current", cur);
        ASSERT_STR_EQ(cur, b);
        ASSERT(access(stale, F_OK) != 0);
        pst_fx_close(&fx);
    } TEST_END
    return failures;
}

static int pst_case_atomic_link_failure(void)
{
    int failures = 0;
    TEST_CASE("a failed atomic link leaves the old path untouched") {
        struct pst_fx fx;
        char dir[PATH_MAX], inner[PATH_MAX], tmp[PATH_MAX], good[PATH_MAX];
        char target[64];
        ASSERT(pst_fx_open(&fx, false));
        ASSERT(pst_path(dir, sizeof(dir), fx.base, "occupied"));
        ASSERT(pst_path(inner, sizeof(inner), dir, "keep"));
        ASSERT_EQ(mkdir(dir, 0700), 0);
        ASSERT(pst_write(inner, "x", 1));
        ASSERT_EQ(platform_atomic_symlink("elsewhere", dir), -1);
        ASSERT(access(inner, F_OK) == 0);
        snprintf(tmp, sizeof(tmp), "%s.new.%ld", dir, (long)getpid());
        ASSERT(access(tmp, F_OK) != 0);
        ASSERT(pst_path(good, sizeof(good), fx.base, "link"));
        ASSERT_EQ(platform_atomic_symlink("one", good), 0);
        ASSERT_EQ(platform_atomic_symlink("two", good), 0);
        ssize_t n = readlink(good, target, sizeof(target) - 1);
        ASSERT(n == 3 && strncmp(target, "two", 3) == 0);
        pst_fx_close(&fx);
    } TEST_END
    return failures;
}

static int pst_case_rollback_refusals(void)
{
    int failures = 0;
    TEST_CASE("rollback without last-good and for unknown plugins refuses") {
        struct pst_fx fx;
        struct pst_opts o = {0};
        char back[PST_HEX], cur[PST_HEX];
        ASSERT(pst_fx_open(&fx, true));
        ASSERT_EQ(plugin_store_rollback(fx.root, "ghost", back), PLUGIN_ERR_NOT_INSTALLED);
        ASSERT_EQ(pst_install(&fx, "hello", "version one", &o), PLUGIN_OK);
        ASSERT_EQ(plugin_store_switch(fx.root, "hello", fx.generation), PLUGIN_OK);
        ASSERT_EQ(plugin_store_rollback(fx.root, "hello", back), PLUGIN_ERR_NO_LAST_GOOD);
        pst_link(&fx, "hello", "current", cur);
        ASSERT_STR_EQ(cur, fx.generation);
        pst_fx_close(&fx);
    } TEST_END
    return failures;
}

static int pst_case_post_install_tamper(void)
{
    int failures = 0;
    TEST_CASE("switch re-verifies a generation altered after install") {
        struct pst_fx fx;
        struct pst_opts o = {0};
        char exe[PATH_MAX], cur[PST_HEX];
        ASSERT(pst_fx_open(&fx, true));
        ASSERT_EQ(pst_install(&fx, "hello", "version one", &o), PLUGIN_OK);
        snprintf(exe, sizeof(exe), "%s/hello/generations/%s/hello", fx.root, fx.generation);
        ASSERT_EQ(chmod(exe, 0755), 0);
        ASSERT(pst_write(exe, "evil", 4));
        ASSERT_EQ(plugin_store_switch(fx.root, "hello", fx.generation), PLUGIN_ERR_EXE_HASH);
        pst_link(&fx, "hello", "current", cur);
        ASSERT_EQ(cur[0], '\0');
        pst_fx_close(&fx);
    } TEST_END
    return failures;
}


static bool pst_keys_path_of(const struct pst_fx *fx, char *out, size_t cap)
{
    return pst_path(out, cap, fx->root, "publisher_keys");
}

static int pst_case_insecure_keys(void)
{
    int failures = 0;
    TEST_CASE("keys_file file that is group-writable, a link or a directory is refused") {
        struct pst_fx fx;
        struct pst_opts o = {0};
        char keys_file[PATH_MAX], real[PATH_MAX];
        ASSERT(pst_fx_open(&fx, true));
        ASSERT(pst_keys_path_of(&fx, keys_file, sizeof(keys_file)));
        ASSERT_EQ(chmod(keys_file, 0664), 0);
        ASSERT_EQ(pst_install(&fx, "hello", "payload", &o), PLUGIN_ERR_KEYS_INSECURE);
        ASSERT_EQ(chmod(keys_file, 0600), 0);
        ASSERT_EQ(pst_install(&fx, "hello", "payload", &o), PLUGIN_OK);
        ASSERT(pst_path(real, sizeof(real), fx.base, "keys_elsewhere"));
        ASSERT_EQ(rename(keys_file, real), 0);
        ASSERT_EQ(symlink(real, keys_file), 0);
        ASSERT_EQ(plugin_store_switch(fx.root, "hello", fx.generation),
                  PLUGIN_ERR_KEYS_INSECURE);
        ASSERT_EQ(unlink(keys_file), 0);
        ASSERT_EQ(mkdir(keys_file, 0700), 0);
        ASSERT_EQ(plugin_store_switch(fx.root, "hello", fx.generation),
                  PLUGIN_ERR_KEYS_INSECURE);
        pst_fx_close(&fx);
    } TEST_END
    return failures;
}

static int pst_case_insecure_dirs(void)
{
    int failures = 0;
    TEST_CASE("store, plugin and generations directories must be closed to others") {
        struct pst_fx fx;
        struct pst_opts o = {0};
        char plug[PATH_MAX], gens[PATH_MAX];
        ASSERT(pst_fx_open(&fx, true));
        ASSERT_EQ(pst_install(&fx, "hello", "payload", &o), PLUGIN_OK);
        ASSERT(pst_path(plug, sizeof(plug), fx.root, "hello"));
        ASSERT(pst_path(gens, sizeof(gens), plug, "generations"));
        ASSERT_EQ(chmod(fx.root, 0777), 0);
        ASSERT_EQ(plugin_store_switch(fx.root, "hello", fx.generation), PLUGIN_ERR_KEYS_INSECURE);
        ASSERT_EQ(pst_install(&fx, "hello", "payload", &o), PLUGIN_ERR_KEYS_INSECURE);
        ASSERT_EQ(chmod(fx.root, 0700), 0);
        ASSERT_EQ(chmod(plug, 0770), 0);
        ASSERT_EQ(plugin_store_switch(fx.root, "hello", fx.generation), PLUGIN_ERR_KEYS_INSECURE);
        ASSERT_EQ(chmod(plug, 0700), 0);
        ASSERT_EQ(chmod(gens, 0707), 0);
        ASSERT_EQ(plugin_store_switch(fx.root, "hello", fx.generation), PLUGIN_ERR_KEYS_INSECURE);
        ASSERT_EQ(chmod(gens, 0700), 0);
        ASSERT_EQ(plugin_store_switch(fx.root, "hello", fx.generation), PLUGIN_OK);
        pst_fx_close(&fx);
    } TEST_END
    return failures;
}

static int pst_case_store_symlinks(void)
{
    int failures = 0;
    TEST_CASE("a generation reached through a symbolic link is refused") {
        struct pst_fx fx;
        struct pst_opts o = {0};
        char gen[PATH_MAX], copy[PATH_MAX], exe[PATH_MAX], stash[PATH_MAX];
        ASSERT(pst_fx_open(&fx, true));
        ASSERT_EQ(pst_install(&fx, "hello", "payload", &o), PLUGIN_OK);
        snprintf(gen, sizeof(gen), "%s/hello/generations/%s", fx.root, fx.generation);
        ASSERT(pst_path(copy, sizeof(copy), fx.base, "verified_copy"));
        ASSERT_EQ(rename(gen, copy), 0);
        ASSERT_EQ(symlink(copy, gen), 0);
        ASSERT_EQ(plugin_store_switch(fx.root, "hello", fx.generation), PLUGIN_ERR_KEYS_INSECURE);
        ASSERT_EQ(unlink(gen), 0);
        ASSERT_EQ(rename(copy, gen), 0);
        snprintf(exe, sizeof(exe), "%s/hello", gen);
        ASSERT(pst_path(stash, sizeof(stash), fx.base, "exe_elsewhere"));
        ASSERT_EQ(rename(exe, stash), 0);
        ASSERT_EQ(symlink(stash, exe), 0);
        ASSERT_EQ(plugin_store_switch(fx.root, "hello", fx.generation), PLUGIN_ERR_KEYS_INSECURE);
        pst_fx_close(&fx);
    } TEST_END
    return failures;
}

static int pst_case_republish_broken(void)
{
    int failures = 0;
    TEST_CASE("install replaces a broken generation and keeps current valid") {
        struct pst_fx fx;
        struct pst_opts o = {0};
        char exe[PATH_MAX], body[PST_HEX];
        int present = -1;
        struct plugin_manifest m;
        ASSERT(pst_fx_open(&fx, true));
        ASSERT_EQ(pst_install(&fx, "hello", "payload", &o), PLUGIN_OK);
        ASSERT_EQ(plugin_store_switch(fx.root, "hello", fx.generation), PLUGIN_OK);
        snprintf(exe, sizeof(exe), "%s/hello/generations/%s/hello", fx.root, fx.generation);
        ASSERT_EQ(chmod(exe, 0755), 0);
        ASSERT(pst_write(exe, "evil", 4));
        ASSERT_EQ(plugin_store_install(fx.root, fx.manifest, &m, &present), PLUGIN_OK);
        ASSERT_EQ(present, 0);
        ASSERT(pst_slurp(exe, body, sizeof(body)) && strcmp(body, "payload") == 0);
        ASSERT_EQ(plugin_store_install(fx.root, fx.manifest, &m, &present), PLUGIN_OK);
        ASSERT_EQ(present, 1);
        pst_link(&fx, "hello", "current", body);
        ASSERT_STR_EQ(body, fx.generation);
        ASSERT_EQ(plugin_store_switch(fx.root, "hello", fx.generation), PLUGIN_OK);
        pst_fx_close(&fx);
    } TEST_END
    return failures;
}

static int pst_case_keys_file_forms(void)
{
    int failures = 0;
    TEST_CASE("keys_file file: CRLF lines work, malformed lines and empty files refuse") {
        struct pst_fx fx;
        struct pst_opts o = {0};
        char keys_file[PATH_MAX], hex[65], line[160];
        ASSERT(pst_fx_open(&fx, true));
        ASSERT(pst_keys_path_of(&fx, keys_file, sizeof(keys_file)));
        pst_hex(fx.pk[0], 32, hex);
        snprintf(line, sizeof(line), "\r\n%s\r\n\r\n", hex);
        ASSERT(pst_write_private(keys_file, line, strlen(line)));
        ASSERT_EQ(pst_install(&fx, "hello", "payload", &o), PLUGIN_OK);
        snprintf(line, sizeof(line), "%s\nnot-a-key\n", hex);
        ASSERT(pst_write_private(keys_file, line, strlen(line)));
        ASSERT_EQ(pst_install(&fx, "hello", "payload", &o), PLUGIN_ERR_KEYS_MALFORMED);
        ASSERT(pst_write_private(keys_file, "\n\n", 2));
        ASSERT_EQ(pst_install(&fx, "hello", "payload", &o), PLUGIN_ERR_NO_KEYS);
        pst_fx_close(&fx);
    } TEST_END
    return failures;
}

static int pst_case_revoked_key(void)
{
    int failures = 0;
    TEST_CASE("removing a key from keys_file makes switch and rollback refuse") {
        struct pst_fx fx;
        struct pst_opts o = {0};
        char a[PST_HEX], back[PST_HEX], keys_file[PATH_MAX], hex[65], line[80];
        ASSERT(pst_fx_open(&fx, true));
        ASSERT_EQ(pst_install(&fx, "hello", "version one", &o), PLUGIN_OK);
        memcpy(a, fx.generation, PST_HEX);
        ASSERT_EQ(pst_install(&fx, "hello", "version two", &o), PLUGIN_OK);
        ASSERT_EQ(plugin_store_switch(fx.root, "hello", a), PLUGIN_OK);
        ASSERT_EQ(plugin_store_switch(fx.root, "hello", fx.generation), PLUGIN_OK);
        ASSERT(pst_keys_path_of(&fx, keys_file, sizeof(keys_file)));
        pst_hex(fx.pk[1], 32, hex);
        snprintf(line, sizeof(line), "%s\n", hex);
        ASSERT(pst_write_private(keys_file, line, strlen(line)));
        ASSERT_EQ(plugin_store_rollback(fx.root, "hello", back), PLUGIN_ERR_KEY_UNKNOWN);
        ASSERT_EQ(plugin_store_switch(fx.root, "hello", a), PLUGIN_ERR_KEY_UNKNOWN);
        pst_fx_close(&fx);
    } TEST_END
    return failures;
}

/* True when generation GEN of NAME stores a manifest that grants capability CAP. */
static bool pst_gen_grants(const struct pst_fx *fx, const char *name, const char *gen,
                           const char *cap)
{
    char path[PATH_MAX], body[1024], needle[32];
    snprintf(path, sizeof(path), "%s/%s/generations/%s/%s.plugin.json", fx->root, name, gen, name);
    snprintf(needle, sizeof(needle), "\"%s\"", cap);
    return pst_slurp(path, body, sizeof(body)) && strstr(body, needle) != NULL;
}

static enum plugin_status pst_install_present(struct pst_fx *fx, const char *name,
                                              const char *exe, const struct pst_opts *o,
                                              struct plugin_manifest *m, int *present)
{
    if (!pst_publish(fx, name, exe, o))
        return PLUGIN_ERR_IO;
    return plugin_store_install(fx->root, fx->manifest, m, present);
}

static int pst_case_permission_update(void)
{
    int failures = 0;
    TEST_CASE("same executable with narrower capabilities is a new generation") {
        struct pst_fx fx;
        struct pst_opts wide = { .caps = "\"fs.write\",\"clock\"" };
        struct pst_opts narrow = { .caps = "\"clock\"" };
        struct plugin_manifest m1, m2, m3;
        struct plugin_info *infos = NULL;
        size_t count = 0;
        int present = -1;
        char g1[PST_HEX], g2[PST_HEX], cur[PST_HEX], back[PST_HEX];
        ASSERT(pst_fx_open(&fx, true));
        ASSERT_EQ(pst_install_present(&fx, "hello", "shared exe", &wide, &m1, &present), PLUGIN_OK);
        ASSERT_EQ(present, 0);
        memcpy(g1, fx.generation, PST_HEX);
        ASSERT_EQ(plugin_store_switch(fx.root, "hello", g1), PLUGIN_OK);
        ASSERT_EQ(pst_install_present(&fx, "hello", "shared exe", &narrow, &m2, &present),
                  PLUGIN_OK);
        ASSERT_EQ(present, 0);
        memcpy(g2, fx.generation, PST_HEX);
        ASSERT(strcmp(g1, g2) != 0);
        ASSERT_STR_EQ(m1.exe_sha3, m2.exe_sha3);
        ASSERT_STR_EQ(m2.generation, g2);
        ASSERT_EQ(m1.capabilities & 2u, 2u);
        ASSERT_EQ(m2.capabilities & 2u, 0u);
        ASSERT(pst_gen_grants(&fx, "hello", g1, "fs.write"));
        ASSERT(!pst_gen_grants(&fx, "hello", g2, "fs.write"));
        /* installing never moves current: the wide grant is still live until switched */
        pst_link(&fx, "hello", "current", cur);
        ASSERT_STR_EQ(cur, g1);
        ASSERT_EQ(plugin_store_list(fx.root, &infos, &count), PLUGIN_OK);
        ASSERT_EQ(count, 1u);
        ASSERT_EQ(infos[0].generation_count, 2u);
        plugin_store_list_free(infos, count);
        /* switch to the narrow grant, roll back to the wide one, switch forward again */
        ASSERT_EQ(plugin_store_switch(fx.root, "hello", g2), PLUGIN_OK);
        pst_link(&fx, "hello", "current", cur);
        ASSERT_STR_EQ(cur, g2);
        ASSERT(!pst_gen_grants(&fx, "hello", cur, "fs.write"));
        ASSERT_EQ(plugin_store_rollback(fx.root, "hello", back), PLUGIN_OK);
        pst_link(&fx, "hello", "current", cur);
        ASSERT_STR_EQ(cur, g1);
        ASSERT(pst_gen_grants(&fx, "hello", cur, "fs.write"));
        ASSERT_EQ(plugin_store_switch(fx.root, "hello", g2), PLUGIN_OK);
        pst_link(&fx, "hello", "current", cur);
        ASSERT_STR_EQ(cur, g2);
        ASSERT(!pst_gen_grants(&fx, "hello", cur, "fs.write"));
        /* the identical manifest and executable is idempotent */
        ASSERT_EQ(pst_install_present(&fx, "hello", "shared exe", &narrow, &m3, &present),
                  PLUGIN_OK);
        ASSERT_EQ(present, 1);
        ASSERT_STR_EQ(m3.generation, g2);
        ASSERT_EQ(pst_install_present(&fx, "hello", "shared exe", &wide, &m3, &present),
                  PLUGIN_OK);
        ASSERT_EQ(present, 1);
        ASSERT_STR_EQ(m3.generation, g1);
        ASSERT_EQ(plugin_store_list(fx.root, &infos, &count), PLUGIN_OK);
        ASSERT_EQ(infos[0].generation_count, 2u);
        plugin_store_list_free(infos, count);
        pst_fx_close(&fx);
    } TEST_END
    return failures;
}

static int pst_case_permission_update_revoked(void)
{
    int failures = 0;
    TEST_CASE("a permission update signed by a revoked key is refused") {
        struct pst_fx fx;
        struct pst_opts wide = { .caps = "\"fs.write\",\"clock\"" };
        struct pst_opts narrow_revoked = { .key = 1, .caps = "\"clock\"" };
        struct plugin_manifest m;
        struct plugin_info *infos = NULL;
        size_t count = 0;
        int present = -1;
        ASSERT(pst_fx_open(&fx, true));
        ASSERT_EQ(pst_install_present(&fx, "hello", "shared exe", &wide, &m, &present), PLUGIN_OK);
        ASSERT_EQ(pst_install_present(&fx, "hello", "shared exe", &narrow_revoked, &m, &present),
                  PLUGIN_ERR_KEY_UNKNOWN);
        ASSERT_EQ(plugin_store_list(fx.root, &infos, &count), PLUGIN_OK);
        ASSERT_EQ(infos[0].generation_count, 1u);
        plugin_store_list_free(infos, count);
        pst_fx_close(&fx);
    } TEST_END
    return failures;
}

static int pst_case_legacy_generation(void)
{
    int failures = 0;
    TEST_CASE("generations named by the executable hash still verify, switch and roll back") {
        struct pst_fx fx;
        struct pst_opts o = {0};
        unsigned char dg[64];
        char exe_a[PST_HEX], exe_b[PST_HEX], from[PATH_MAX], to[PATH_MAX];
        char cur[PST_HEX], back[PST_HEX], bogus[PST_HEX];
        ASSERT(pst_fx_open(&fx, true));
        /* version one, renamed to the pre-change layout: exe hash as the name */
        ASSERT_EQ(pst_install(&fx, "hello", "version one", &o), PLUGIN_OK);
        zcl_sha3_512((const unsigned char *)"version one", strlen("version one"), dg);
        pst_hex(dg, 64, exe_a);
        snprintf(from, sizeof(from), "%s/hello/generations/%s", fx.root, fx.generation);
        snprintf(to, sizeof(to), "%s/hello/generations/%s", fx.root, exe_a);
        ASSERT_EQ(rename(from, to), 0);
        ASSERT_EQ(pst_install(&fx, "hello", "version two", &o), PLUGIN_OK);
        zcl_sha3_512((const unsigned char *)"version two", strlen("version two"), dg);
        pst_hex(dg, 64, exe_b);
        snprintf(from, sizeof(from), "%s/hello/generations/%s", fx.root, fx.generation);
        snprintf(to, sizeof(to), "%s/hello/generations/%s", fx.root, exe_b);
        ASSERT_EQ(rename(from, to), 0);
        ASSERT_EQ(plugin_store_switch(fx.root, "hello", exe_a), PLUGIN_OK);
        ASSERT_EQ(plugin_store_switch(fx.root, "hello", exe_b), PLUGIN_OK);
        ASSERT_EQ(plugin_store_rollback(fx.root, "hello", back), PLUGIN_OK);
        pst_link(&fx, "hello", "current", cur);
        ASSERT_STR_EQ(cur, exe_a);
        ASSERT_STR_EQ(back, exe_a);
        /* a directory whose name matches neither id of its stored manifest is refused */
        memset(bogus, 'b', 128);
        bogus[128] = '\0';
        snprintf(from, sizeof(from), "%s/hello/generations/%s", fx.root, exe_b);
        snprintf(to, sizeof(to), "%s/hello/generations/%s", fx.root, bogus);
        ASSERT_EQ(rename(from, to), 0);
        ASSERT_EQ(plugin_store_switch(fx.root, "hello", bogus), PLUGIN_ERR_MANIFEST_INVALID);
        pst_link(&fx, "hello", "current", cur);
        ASSERT_STR_EQ(cur, exe_a);
        pst_fx_close(&fx);
    } TEST_END
    return failures;
}

static int pst_case_tampered_last_good(void)
{
    int failures = 0;
    TEST_CASE("rollback refuses a last-good generation altered on disk") {
        struct pst_fx fx;
        struct pst_opts o = {0};
        char a[PST_HEX], back[PST_HEX], cur[PST_HEX], exe[PATH_MAX];
        ASSERT(pst_fx_open(&fx, true));
        ASSERT_EQ(pst_install(&fx, "hello", "version one", &o), PLUGIN_OK);
        memcpy(a, fx.generation, PST_HEX);
        ASSERT_EQ(pst_install(&fx, "hello", "version two", &o), PLUGIN_OK);
        ASSERT_EQ(plugin_store_switch(fx.root, "hello", a), PLUGIN_OK);
        ASSERT_EQ(plugin_store_switch(fx.root, "hello", fx.generation), PLUGIN_OK);
        snprintf(exe, sizeof(exe), "%s/hello/generations/%s/hello", fx.root, a);
        ASSERT_EQ(chmod(exe, 0755), 0);
        ASSERT(pst_write(exe, "evil", 4));
        ASSERT_EQ(plugin_store_rollback(fx.root, "hello", back), PLUGIN_ERR_EXE_HASH);
        pst_link(&fx, "hello", "current", cur);
        ASSERT_STR_EQ(cur, fx.generation);
        pst_fx_close(&fx);
    } TEST_END
    return failures;
}

static int pst_case_input_limits(void)
{
    int failures = 0;
    TEST_CASE("wrong-length signature hex and oversize manifest are refused") {
        struct pst_fx fx;
        struct pst_opts o = {0};
        struct plugin_manifest m;
        char sig[PATH_MAX], body[1024];
        int present;
        ASSERT(pst_fx_open(&fx, true));
        ASSERT(pst_publish(&fx, "hello", "payload", &o));
        ASSERT(pst_path(sig, sizeof(sig), fx.src, "hello.plugin.sig"));
        ASSERT(pst_slurp(sig, body, sizeof(body)));
        char *p = strstr(body, "\"signature\":\"");
        ASSERT(p);
        p[14] = '"';
        p[15] = '}';
        p[16] = '\0';
        ASSERT(pst_write(sig, body, strlen(body)));
        ASSERT_EQ(plugin_store_install(fx.root, fx.manifest, &m, &present),
                  PLUGIN_ERR_SIG_INVALID);
        char *big = malloc(70000);
        ASSERT(big);
        memset(big, ' ', 69999);
        big[69999] = '\0';
        ASSERT(pst_write(fx.manifest, big, 69999));
        free(big);
        ASSERT_EQ(plugin_store_install(fx.root, fx.manifest, &m, &present),
                  PLUGIN_ERR_MANIFEST_INVALID);
        pst_fx_close(&fx);
    } TEST_END
    return failures;
}

static bool pst_call(zcl_command_handler_fn fn, const char *input_json,
                     struct zcl_command_reply *reply)
{
    struct json_value input;
    json_init(&input);
    bool ok = json_read(&input, input_json, strlen(input_json));
    struct zcl_command_request request = { .input = &input, .view = "normal" };
    zcl_command_reply_init(reply, "zcl.plugin_test.v1");
    if (ok)
        fn(&request, reply);
    json_free(&input);
    return ok;
}

static int pst_case_commands(void)
{
    int failures = 0;
    struct pst_fx fx = {0};
    const char *old_home = getenv("HOME");
    TEST_CASE("the four commands install, list, switch, roll back and refuse") {
        struct pst_opts o = {0}, bad = { .key = 1 };
        struct zcl_command_reply r;
        char in[2 * PATH_MAX], a[PST_HEX];
        ASSERT(pst_fx_open(&fx, true));
        ASSERT_EQ(setenv("HOME", fx.home, 1), 0);
        ASSERT(pst_publish(&fx, "hello", "version one", &bad));
        snprintf(in, sizeof(in), "{\"manifest\":\"%s\"}", fx.manifest);
        ASSERT(pst_call(zcl_native_handle_plugin_install, in, &r));
        ASSERT_STR_EQ(r.error.code, "PLUGIN_KEY_UNKNOWN");
        ASSERT(r.error.next_action[0] != '\0');
        zcl_command_reply_free(&r);
        ASSERT(pst_publish(&fx, "hello", "version one", &o));
        memcpy(a, fx.generation, PST_HEX);
        ASSERT(pst_call(zcl_native_handle_plugin_install, in, &r));
        ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(&r.data, "generation")), a);
        zcl_command_reply_free(&r);
        snprintf(in, sizeof(in), "{\"name\":\"hello\",\"generation\":\"%s\"}", a);
        ASSERT(pst_call(zcl_native_handle_plugin_switch, in, &r));
        ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_OK);
        zcl_command_reply_free(&r);
        ASSERT(pst_call(zcl_native_handle_plugin_rollback, "{\"name\":\"hello\"}", &r));
        ASSERT_STR_EQ(r.error.code, "PLUGIN_NO_LAST_GOOD");
        zcl_command_reply_free(&r);
        ASSERT(pst_call(zcl_native_handle_plugin_list, "{}", &r));
        ASSERT_EQ(json_get_int(json_get(&r.data, "count")), 1);
        zcl_command_reply_free(&r);
        ASSERT(pst_call(zcl_native_handle_plugin_status, "{\"name\":\"hello\"}", &r));
        ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(&r.data, "current")), a);
        ASSERT_STR_EQ(json_get_str(json_get(&r.data, "last_good")), "");
        ASSERT_EQ(json_get_int(json_get(&r.data, "generations")), 1);
        ASSERT_EQ(json_get_int(json_get(json_get(&r.data, "work"), "scanned")), 1);
        ASSERT_EQ(json_get_int(json_get(json_get(&r.data, "work"), "verified")), 0);
        ASSERT_EQ(json_get_int(json_get(json_get(&r.data, "work"), "hashed")), 0);
        zcl_command_reply_free(&r);
        ASSERT(pst_call(zcl_native_handle_plugin_status, "{\"name\":\"ghost\"}", &r));
        ASSERT_STR_EQ(r.error.code, "PLUGIN_NOT_INSTALLED");
        zcl_command_reply_free(&r);
    } TEST_END
    if (old_home)
        setenv("HOME", old_home, 1);
    pst_fx_close(&fx);
    return failures;
}

struct pst_pk {
    struct pst_fx fx;
    char exe[PATH_MAX];
    char key[PATH_MAX];
    char dist[PATH_MAX];
    struct plugin_pack_request rq;
    struct plugin_pack_result res;
};

/* One plugin with two generations: v1 was current, v2 is current now, so both
 * links and the generations directory are populated. */
static bool pst_two_generations(struct pst_fx *fx, bool switch_current)
{
    struct pst_opts o = {0};
    if (!pst_fx_open(fx, true) || pst_install(fx, "hello", "payload one", &o) != PLUGIN_OK)
        return false;
    if (switch_current && plugin_store_switch(fx->root, "hello", fx->generation) != PLUGIN_OK)
        return false;
    return pst_install(fx, "hello", "payload two", &o) == PLUGIN_OK &&
           (!switch_current ||
            plugin_store_switch(fx->root, "hello", fx->generation) == PLUGIN_OK);
}

static bool pst_plug_path(const struct pst_fx *fx, const char *leaf, char *out, size_t cap)
{
    char plug[PATH_MAX];
    return pst_path(plug, sizeof(plug), fx->root, "hello") &&
           (leaf ? pst_path(out, cap, plug, leaf) : snprintf(out, cap, "%s", plug) > 0);
}

/* List the store and expect exactly the one plugin "hello". */
static bool pst_list_one(const struct pst_fx *fx, struct plugin_info **infos)
{
    size_t n = 0;
    *infos = NULL;
    if (plugin_store_list(fx->root, infos, &n) != PLUGIN_OK || n != 1) {
        plugin_store_list_free(*infos, n);
        *infos = NULL;
        return false;
    }
    return true;
}

static bool pst_states(const struct plugin_info *i, enum plugin_slot_state cur,
                       enum plugin_slot_state last, enum plugin_slot_state gens)
{
    return i->current_state == cur && i->last_good_state == last &&
           i->generations_state == gens;
}

static int pst_case_slot_states_readable(void)
{
    int failures = 0;
    TEST_CASE("list types a healthy plugin, a never-switched one and a removed generations directory") {
        struct pst_fx fx;
        struct plugin_info *i = NULL;
        char path[PATH_MAX];
        ASSERT(pst_two_generations(&fx, true));
        ASSERT(pst_list_one(&fx, &i));
        ASSERT(pst_states(i, PLUGIN_SLOT_OK, PLUGIN_SLOT_OK, PLUGIN_SLOT_OK));
        ASSERT_EQ(i->generation_count, 2u);
        plugin_store_list_free(i, 1);
        /* nothing was ever switched: unset is missing, not a fault */
        pst_fx_close(&fx);
        ASSERT(pst_two_generations(&fx, false));
        ASSERT(pst_list_one(&fx, &i));
        ASSERT(pst_states(i, PLUGIN_SLOT_MISSING, PLUGIN_SLOT_MISSING, PLUGIN_SLOT_OK));
        ASSERT_STR_EQ(i->current, "");
        ASSERT_EQ(i->generation_count, 2u);
        plugin_store_list_free(i, 1);
        /* the generations directory is gone */
        ASSERT(pst_plug_path(&fx, "generations", path, sizeof(path)));
        ASSERT_EQ(test_rm_rf_recursive(path), 0);
        ASSERT(pst_list_one(&fx, &i));
        ASSERT(pst_states(i, PLUGIN_SLOT_MISSING, PLUGIN_SLOT_MISSING, PLUGIN_SLOT_MISSING));
        ASSERT_EQ(i->generation_count, 0u);
        plugin_store_list_free(i, 1);
        pst_fx_close(&fx);
    } TEST_END
    return failures;
}

static int pst_case_slot_states_corrupt(void)
{
    int failures = 0;
    TEST_CASE("list types a current link that is not a generation link and a generations file as corrupt") {
        struct pst_fx fx;
        struct plugin_info *i = NULL;
        char path[PATH_MAX];
        ASSERT(pst_two_generations(&fx, true));
        /* current is a regular file, last-good points outside generations/ */
        ASSERT(pst_plug_path(&fx, "current", path, sizeof(path)));
        ASSERT_EQ(unlink(path), 0);
        ASSERT(pst_write(path, "x", 1));
        ASSERT(pst_plug_path(&fx, "last-good", path, sizeof(path)));
        ASSERT_EQ(unlink(path), 0);
        ASSERT_EQ(symlink("../elsewhere", path), 0);
        ASSERT(pst_list_one(&fx, &i));
        ASSERT(pst_states(i, PLUGIN_SLOT_CORRUPT, PLUGIN_SLOT_CORRUPT, PLUGIN_SLOT_OK));
        ASSERT_STR_EQ(i->current, "");
        ASSERT_STR_EQ(i->last_good, "");
        plugin_store_list_free(i, 1);
        /* the generations path is a file */
        ASSERT(pst_plug_path(&fx, "generations", path, sizeof(path)));
        ASSERT_EQ(test_rm_rf_recursive(path), 0);
        ASSERT(pst_write(path, "x", 1));
        ASSERT(pst_list_one(&fx, &i));
        ASSERT(pst_states(i, PLUGIN_SLOT_CORRUPT, PLUGIN_SLOT_CORRUPT, PLUGIN_SLOT_CORRUPT));
        plugin_store_list_free(i, 1);
        pst_fx_close(&fx);
    } TEST_END
    return failures;
}

static int pst_case_slot_states_unreadable(void)
{
    int failures = 0;
    TEST_CASE("list types a denied generations directory and a denied plugin directory as unreadable") {
        struct pst_fx fx;
        struct plugin_info *i = NULL;
        char gens[PATH_MAX], plug[PATH_MAX];
        ASSERT(pst_two_generations(&fx, true));
        ASSERT(pst_plug_path(&fx, "generations", gens, sizeof(gens)));
        ASSERT(pst_plug_path(&fx, NULL, plug, sizeof(plug)));
        if (geteuid() != 0) {
            /* only the generations directory is denied: the links still read */
            ASSERT_EQ(chmod(gens, 0), 0);
            ASSERT(pst_list_one(&fx, &i));
            ASSERT(pst_states(i, PLUGIN_SLOT_OK, PLUGIN_SLOT_OK, PLUGIN_SLOT_UNREADABLE));
            ASSERT_EQ(i->generation_count, 0u);
            ASSERT(i->current[0] != '\0');
            plugin_store_list_free(i, 1);
            ASSERT_EQ(chmod(gens, 0700), 0);
            /* the plugin directory cannot be searched: nothing in it can be read */
            ASSERT_EQ(chmod(plug, 0600), 0);
            ASSERT(pst_list_one(&fx, &i));
            ASSERT(pst_states(i, PLUGIN_SLOT_UNREADABLE, PLUGIN_SLOT_UNREADABLE,
                              PLUGIN_SLOT_UNREADABLE));
            ASSERT_STR_EQ(i->current, "");
            plugin_store_list_free(i, 1);
            ASSERT_EQ(chmod(plug, 0700), 0);
        }
        pst_fx_close(&fx);
    } TEST_END
    return failures;
}

static int pst_case_readdir_failure(void)
{
    int failures = 0;
    TEST_CASE("a directory read that fails part way is an error, not the end of the list") {
        struct pst_fx fx;
        struct plugin_info *i = NULL, *none = NULL;
        size_t n = 0;
        ASSERT(pst_two_generations(&fx, true));
        /* the generations directory holds ".", ".." and two ids */
        plugin_store_test_fail_readdir("/generations", 3);
        ASSERT(pst_list_one(&fx, &i));
        ASSERT(pst_states(i, PLUGIN_SLOT_OK, PLUGIN_SLOT_OK, PLUGIN_SLOT_UNREADABLE));
        ASSERT_EQ(i->generation_count, 0u);
        plugin_store_list_free(i, 1);
        /* the store root itself fails to read */
        plugin_store_test_fail_readdir("/plugins", 1);
        ASSERT_EQ(plugin_store_list(fx.root, &none, &n), PLUGIN_ERR_IO);
        ASSERT(none == NULL);
        ASSERT_EQ(n, 0u);
        plugin_store_test_fail_readdir(NULL, 0);
        ASSERT(pst_list_one(&fx, &i));
        ASSERT(pst_states(i, PLUGIN_SLOT_OK, PLUGIN_SLOT_OK, PLUGIN_SLOT_OK));
        ASSERT_EQ(i->generation_count, 2u);
        plugin_store_list_free(i, 1);
        pst_fx_close(&fx);
    } TEST_END
    plugin_store_test_fail_readdir(NULL, 0);
    return failures;
}

static const char *pst_str(const struct zcl_command_reply *r, const char *key)
{
    const char *s = json_get_str(json_get(&r->data, key));
    return s ? s : "";
}

static int pst_case_status_states(void)
{
    int failures = 0;
    struct pst_fx fx = {0};
    const char *old_home = getenv("HOME");
    TEST_CASE("status reports each state and refuses to call an unreadable or corrupt plugin empty") {
        struct zcl_command_reply r;
        char gens[PATH_MAX], cur[PATH_MAX];
        ASSERT(pst_two_generations(&fx, false));
        ASSERT_EQ(setenv("HOME", fx.home, 1), 0);
        /* never switched: ok exit, unset links reported as missing */
        ASSERT(pst_call(zcl_native_handle_plugin_status, "{\"name\":\"hello\"}", &r));
        ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(pst_str(&r, "current_state"), "missing");
        ASSERT_STR_EQ(pst_str(&r, "last_good_state"), "missing");
        ASSERT_STR_EQ(pst_str(&r, "generations_state"), "ok");
        ASSERT_EQ(json_get_int(json_get(&r.data, "generations")), 2);
        zcl_command_reply_free(&r);
        ASSERT(pst_plug_path(&fx, "generations", gens, sizeof(gens)));
        ASSERT(pst_plug_path(&fx, "current", cur, sizeof(cur)));
        /* a corrupt current link */
        ASSERT(pst_write(cur, "x", 1));
        ASSERT(pst_call(zcl_native_handle_plugin_status, "{\"name\":\"hello\"}", &r));
        ASSERT_STR_EQ(r.error.code, "PLUGIN_IO");
        ASSERT(strstr(r.error.evidence, "current corrupt") != NULL);
        zcl_command_reply_free(&r);
        ASSERT_EQ(unlink(cur), 0);
        /* a generations directory that cannot be read */
        if (geteuid() != 0) {
            ASSERT_EQ(chmod(gens, 0), 0);
            ASSERT(pst_call(zcl_native_handle_plugin_status, "{\"name\":\"hello\"}", &r));
            ASSERT_STR_EQ(r.error.code, "PLUGIN_IO");
            ASSERT(strstr(r.error.evidence, "generations unreadable") != NULL);
            zcl_command_reply_free(&r);
            ASSERT(pst_call(zcl_native_handle_plugin_list, "{}", &r));
            ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_OK);
            ASSERT_STR_EQ(json_get_str(json_get(json_at(json_get(&r.data, "plugins"), 0),
                                                "generations_state")), "unreadable");
            zcl_command_reply_free(&r);
            ASSERT_EQ(chmod(gens, 0700), 0);
        }
        /* a generations directory that failed part way through its read */
        plugin_store_test_fail_readdir("/generations", 3);
        ASSERT(pst_call(zcl_native_handle_plugin_status, "{\"name\":\"hello\"}", &r));
        ASSERT_STR_EQ(r.error.code, "PLUGIN_IO");
        ASSERT(strstr(r.error.evidence, "generations unreadable") != NULL);
        zcl_command_reply_free(&r);
        plugin_store_test_fail_readdir(NULL, 0);
    } TEST_END
    plugin_store_test_fail_readdir(NULL, 0);
    if (old_home)
        setenv("HOME", old_home, 1);
    pst_fx_close(&fx);
    return failures;
}

static const char pst_pk_body[] = "#!/bin/sh\necho packed\n";

/* A publisher workspace: an executable, a key file holding the publisher seed
 * with the given mode, and an output directory name. */
static bool pst_pk_open(struct pst_pk *pk, mode_t key_mode)
{
    memset(pk, 0, sizeof(*pk));
    if (!pst_fx_open(&pk->fx, true) ||
        !pst_path(pk->exe, sizeof(pk->exe), pk->fx.src, "hello.bin") ||
        !pst_path(pk->key, sizeof(pk->key), pk->fx.base, "publisher.key") ||
        !pst_path(pk->dist, sizeof(pk->dist), pk->fx.base, "dist"))
        return false;
    bool ok = pst_write(pk->exe, pst_pk_body, strlen(pst_pk_body)) &&
              pst_write(pk->key, (const char *)pk->fx.sk[0], 32) &&
              chmod(pk->key, key_mode) == 0;
    pk->rq = (struct plugin_pack_request){
        .exe_path = pk->exe, .name = "hello", .version = "1.0.0",
        .key_path = pk->key, .out_dir = pk->dist, .capabilities = 1u | 32u};
    return ok;
}

static bool pst_pk_file(const struct pst_pk *pk, const char *leaf, char *out, size_t cap)
{
    char path[PATH_MAX];
    return pst_path(path, sizeof(path), pk->dist, leaf) && pst_slurp(path, out, cap);
}

static int pst_case_pack_roundtrip(void)
{
    int failures = 0;
    TEST_CASE("pack output installs and matches the documented bytes") {
        struct pst_pk pk;
        struct plugin_manifest m;
        char want[512], got[512], sig[512], pub[65], sha[129];
        unsigned char digest[64];
        int present = -1;
        ASSERT(pst_pk_open(&pk, 0600));
        ASSERT_EQ(plugin_pack(&pk.rq, &pk.res), PLUGIN_OK);
        zcl_sha3_512((const unsigned char *)pst_pk_body, strlen(pst_pk_body), digest);
        pst_hex(digest, 64, sha);
        snprintf(want, sizeof(want),
                 "{\"schema\":\"z23.plugin.v1\",\"name\":\"hello\",\"version\":\"1.0.0\","
                 "\"interface_version\":1,\"sha3_512\":\"%s\","
                 "\"capabilities\":[\"fs.read\",\"clock\"]}\n", sha);
        ASSERT(pst_pk_file(&pk, "hello.plugin.json", got, sizeof(got)));
        ASSERT_STR_EQ(got, want);
        ASSERT(pst_pk_file(&pk, "hello.plugin.sig", sig, sizeof(sig)));
        pst_hex(pk.fx.pk[0], 32, pub);
        ASSERT_STR_EQ(pk.res.public_key, pub);
        ASSERT(strstr(sig, "\"sig_alg\":\"ed25519\"") && strstr(sig, pub));
        ASSERT_EQ(plugin_store_install(pk.fx.root, pk.res.manifest_path, &m, &present),
                  PLUGIN_OK);
        ASSERT_EQ(present, 0);
        ASSERT_STR_EQ(m.generation, pk.res.generation);
        ASSERT_EQ(m.capabilities, 1u | 32u);
        pst_fx_close(&pk.fx);
    } TEST_END
    return failures;
}

static int pst_case_pack_deterministic(void)
{
    int failures = 0;
    TEST_CASE("two packs of the same inputs are byte-identical") {
        struct pst_pk pk;
        static const char *const leaves[] = { "hello", "hello.plugin.json", "hello.plugin.sig" };
        char first[3][512], again[512];
        ASSERT(pst_pk_open(&pk, 0600));
        ASSERT_EQ(plugin_pack(&pk.rq, &pk.res), PLUGIN_OK);
        for (int i = 0; i < 3; i++)
            ASSERT(pst_pk_file(&pk, leaves[i], first[i], sizeof(first[i])));
        ASSERT_EQ(plugin_pack(&pk.rq, &pk.res), PLUGIN_OK);
        for (int i = 0; i < 3; i++) {
            ASSERT(pst_pk_file(&pk, leaves[i], again, sizeof(again)));
            ASSERT_STR_EQ(again, first[i]);
        }
        pst_fx_close(&pk.fx);
    } TEST_END
    return failures;
}

static int pst_case_pack_tampered_exe(void)
{
    int failures = 0;
    TEST_CASE("an executable changed after pack is refused at install") {
        struct pst_pk pk;
        struct plugin_manifest m;
        char path[PATH_MAX];
        int present = 0;
        ASSERT(pst_pk_open(&pk, 0600));
        ASSERT_EQ(plugin_pack(&pk.rq, &pk.res), PLUGIN_OK);
        ASSERT(pst_path(path, sizeof(path), pk.dist, "hello"));
        ASSERT_EQ(chmod(path, 0700), 0);
        ASSERT(pst_write(path, "tampered", 8));
        ASSERT_EQ(plugin_store_install(pk.fx.root, pk.res.manifest_path, &m, &present),
                  PLUGIN_ERR_EXE_HASH);
        ASSERT(!pst_exists(pk.fx.root, "hello"));
        pst_fx_close(&pk.fx);
    } TEST_END
    return failures;
}

static int pst_case_pack_key_refusals(void)
{
    int failures = 0;
    TEST_CASE("pack refuses a readable, short, linked or missing key file") {
        struct pst_pk pk;
        char link[PATH_MAX];
        ASSERT(pst_pk_open(&pk, 0644));
        ASSERT_EQ(plugin_pack(&pk.rq, &pk.res), PLUGIN_ERR_KEY_INSECURE);
        ASSERT(!pst_exists(pk.dist, "hello.plugin.json"));
        ASSERT_EQ(chmod(pk.key, 0600), 0);
        ASSERT(pst_write(pk.key, "short", 5) && chmod(pk.key, 0600) == 0);
        ASSERT_EQ(plugin_pack(&pk.rq, &pk.res), PLUGIN_ERR_KEY_MALFORMED);
        ASSERT(pst_path(link, sizeof(link), pk.fx.base, "linked.key"));
        ASSERT_EQ(symlink(pk.key, link), 0);
        pk.rq.key_path = link;
        ASSERT_EQ(plugin_pack(&pk.rq, &pk.res), PLUGIN_ERR_KEY_INSECURE);
        ASSERT_EQ(unlink(pk.key), 0);
        pk.rq.key_path = pk.key;
        ASSERT_EQ(plugin_pack(&pk.rq, &pk.res), PLUGIN_ERR_KEY_MISSING);
        pst_fx_close(&pk.fx);
    } TEST_END
    return failures;
}

static int pst_case_keygen(void)
{
    int failures = 0;
    TEST_CASE("keygen writes a private seed, prints the public key, never overwrites") {
        struct pst_pk pk;
        struct stat st;
        char pub[PLUGIN_HEX_PUBLIC_KEY + 1], again[PLUGIN_HEX_PUBLIC_KEY + 1];
        char before[64], after[64], keys_file[PATH_MAX], line[80];
        ASSERT(pst_pk_open(&pk, 0600));
        ASSERT_EQ(unlink(pk.key), 0);
        ASSERT_EQ(plugin_keygen(pk.key, pub), PLUGIN_OK);
        ASSERT_EQ(stat(pk.key, &st), 0);
        ASSERT_EQ((unsigned)(st.st_mode & 0777), 0600u);
        ASSERT_EQ((long)st.st_size, 32L);
        ASSERT(strlen(pub) == 64);
        ASSERT(pst_slurp(pk.key, before, sizeof(before)));
        ASSERT_EQ(plugin_keygen(pk.key, again), PLUGIN_ERR_KEY_EXISTS);
        ASSERT(pst_slurp(pk.key, after, sizeof(after)));
        ASSERT_EQ(memcmp(before, after, 32), 0);
        snprintf(line, sizeof(line), "%s\n", pub);
        ASSERT(pst_path(keys_file, sizeof(keys_file), pk.fx.root, "publisher_keys"));
        ASSERT(pst_write_private(keys_file, line, strlen(line)));
        ASSERT_EQ(plugin_pack(&pk.rq, &pk.res), PLUGIN_OK);
        ASSERT_STR_EQ(pk.res.public_key, pub);
        ASSERT_EQ(plugin_store_install(pk.fx.root, pk.res.manifest_path,
                                       &(struct plugin_manifest){0}, &(int){0}),
                  PLUGIN_OK);
        pst_fx_close(&pk.fx);
    } TEST_END
    return failures;
}

/* Removes the first occurrence of cut from the manifest, signs the result
 * with the listed key and writes both files, so only strictness can refuse. */
static bool pst_pk_resign_without(const struct pst_pk *pk, const char *cut)
{
    char text[512], sig_hex[129], pub[65], doc[512], path[PATH_MAX];
    char *p;
    if (!pst_pk_file(pk, "hello.plugin.json", text, sizeof(text)) ||
        !(p = strstr(text, cut)))
        return false;
    memmove(p, p + strlen(cut), strlen(p + strlen(cut)) + 1);
    pst_sign(&pk->fx, 0, text, sig_hex);
    pst_hex(pk->fx.pk[0], 32, pub);
    snprintf(doc, sizeof(doc),
             "{\"sig_alg\":\"ed25519\",\"public_key\":\"%s\",\"signature\":\"%s\"}\n",
             pub, sig_hex);
    return pst_path(path, sizeof(path), pk->dist, "hello.plugin.json") &&
           pst_write(path, text, strlen(text)) &&
           pst_path(path, sizeof(path), pk->dist, "hello.plugin.sig") &&
           pst_write(path, doc, strlen(doc));
}

static int pst_case_pack_field_mutation(void)
{
    int failures = 0;
    TEST_CASE("dropping any manifest field from pack output breaks install") {
        struct pst_pk pk;
        struct plugin_manifest m;
        char sha_cut[160];
        unsigned char exe_digest[64];
        char exe_hex[129];
        int present = 0;
        const char *cuts[6] = { "\"schema\":\"z23.plugin.v1\",", "\"name\":\"hello\",",
                                "\"version\":\"1.0.0\",", "\"interface_version\":1,",
                                NULL, ",\"capabilities\":[\"fs.read\",\"clock\"]" };
        for (int i = 0; i < 6; i++) {
            ASSERT(pst_pk_open(&pk, 0600));
            ASSERT_EQ(plugin_pack(&pk.rq, &pk.res), PLUGIN_OK);
            zcl_sha3_512((const unsigned char *)pst_pk_body, strlen(pst_pk_body), exe_digest);
            pst_hex(exe_digest, 64, exe_hex);
            snprintf(sha_cut, sizeof(sha_cut), "\"sha3_512\":\"%s\",", exe_hex);
            ASSERT(pst_pk_resign_without(&pk, cuts[i] ? cuts[i] : sha_cut));
            ASSERT_EQ(plugin_store_install(pk.fx.root, pk.res.manifest_path, &m, &present),
                      PLUGIN_ERR_MANIFEST_INVALID);
            pst_fx_close(&pk.fx);
        }
    } TEST_END
    return failures;
}

static int pst_case_pack_commands(void)
{
    int failures = 0;
    TEST_CASE("plugin.pack and plugin.keygen commands report public data only") {
        struct pst_pk pk;
        struct zcl_command_reply r;
        char in[3 * PATH_MAX], seed_hex[65];
        ASSERT(pst_pk_open(&pk, 0600));
        pst_hex(pk.fx.sk[0], 32, seed_hex);
        snprintf(in, sizeof(in),
                 "{\"exe\":\"%s\",\"name\":\"hello\",\"version\":\"1.0.0\",\"key\":\"%s\","
                 "\"cap\":\"fs.read,clock\",\"dir\":\"%s\"}", pk.exe, pk.key, pk.dist);
        ASSERT(pst_call(zcl_native_handle_plugin_pack, in, &r));
        ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_size(json_get(&r.data, "capabilities")) == 2);
        ASSERT(strcmp(json_get_str(json_get(&r.data, "public_key")), seed_hex) != 0);
        zcl_command_reply_free(&r);
        snprintf(in, sizeof(in), "{\"exe\":\"%s\",\"name\":\"hello\",\"version\":\"1.0.0\","
                 "\"key\":\"%s\",\"cap\":[\"clock\",\"clock\"]}", pk.exe, pk.key);
        ASSERT(pst_call(zcl_native_handle_plugin_pack, in, &r));
        ASSERT_STR_EQ(r.error.code, "PLUGIN_ARGUMENT");
        zcl_command_reply_free(&r);
        snprintf(in, sizeof(in), "{\"exe\":\"%s\",\"name\":\"hello\",\"version\":\"1.0.0\","
                 "\"key\":\"%s\",\"cap\":\"clock,\"}", pk.exe, pk.key);
        ASSERT(pst_call(zcl_native_handle_plugin_pack, in, &r));
        ASSERT_STR_EQ(r.error.code, "PLUGIN_ARGUMENT");
        zcl_command_reply_free(&r);
        snprintf(in, sizeof(in), "{\"exe\":\"%s\",\"name\":\"hello\",\"version\":\"1.0.0\","
                 "\"key\":\"%s\",\"cap\":\",\"}", pk.exe, pk.key);
        ASSERT(pst_call(zcl_native_handle_plugin_pack, in, &r));
        ASSERT_STR_EQ(r.error.code, "PLUGIN_ARGUMENT");
        zcl_command_reply_free(&r);
        snprintf(in, sizeof(in), "{\"key\":\"%s\"}", pk.key);
        ASSERT(pst_call(zcl_native_handle_plugin_keygen, in, &r));
        ASSERT_STR_EQ(r.error.code, "PLUGIN_KEY_EXISTS");
        zcl_command_reply_free(&r);
        snprintf(in, sizeof(in), "{\"key\":\"%s/second.key\"}", pk.fx.base);
        ASSERT(pst_call(zcl_native_handle_plugin_keygen, in, &r));
        ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_size(&r.data) == 3);
        ASSERT(strlen(json_get_str(json_get(&r.data, "public_key"))) == 64);
        zcl_command_reply_free(&r);
        pst_fx_close(&pk.fx);
    } TEST_END
    return failures;
}

static int pst_case_pack_next_escaping(void)
{
    int failures = 0;
    TEST_CASE("a quote and a backslash in dir stay one string in the next step") {
        struct pst_pk pk;
        struct zcl_command_reply r;
        struct json_value next, d;
        char in[3 * PATH_MAX], dir[PATH_MAX], esc[2 * PATH_MAX], want[PATH_MAX + 32];
        ASSERT(pst_pk_open(&pk, 0600));
        ASSERT(pst_path(dir, sizeof(dir), pk.fx.base, "d\"q\\x"));
        json_init(&d);
        json_set_str(&d, dir);
        ASSERT(json_write(&d, esc, sizeof(esc)) < sizeof(esc));
        json_free(&d);
        snprintf(in, sizeof(in),
                 "{\"exe\":\"%s\",\"name\":\"hello\",\"version\":\"1.0.0\","
                 "\"key\":\"%s\",\"dir\":%s}", pk.exe, pk.key, esc);
        ASSERT(pst_call(zcl_native_handle_plugin_pack, in, &r));
        ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(r.next_count == 1);
        snprintf(want, sizeof(want), "%s/hello.plugin.json", dir);
        json_init(&next);
        ASSERT(json_read(&next, r.next[0].input_json, strlen(r.next[0].input_json)));
        ASSERT(json_size(&next) == 1);
        ASSERT_STR_EQ(json_get_str(json_get(&next, "manifest")), want);
        json_free(&next);
        zcl_command_reply_free(&r);
        pst_fx_close(&pk.fx);
    } TEST_END
    return failures;
}

struct pst_trio {
    char a[PST_HEX], b[PST_HEX], c[PST_HEX];
};

/* Run fn in a forked child; its plugin_status comes back as the exit code. */
static pid_t pst_spawn(enum plugin_status (*fn)(struct pst_fx *, const struct pst_trio *),
                       struct pst_fx *fx, const struct pst_trio *t)
{
    fflush(NULL);
    pid_t pid = fork();
    if (pid == 0)
        _exit((int)fn(fx, t));
    return pid;
}

static int pst_reap(pid_t pid)
{
    int wst = 0;
    if (pid < 0 || waitpid(pid, &wst, 0) != pid || !WIFEXITED(wst))
        return -1;
    return WEXITSTATUS(wst);
}

static bool pst_three_generations(struct pst_fx *fx, struct pst_trio *t)
{
    struct pst_opts o = {0};
    if (!pst_fx_open(fx, true) || pst_install(fx, "hello", "version a", &o) != PLUGIN_OK)
        return false;
    memcpy(t->a, fx->generation, PST_HEX);
    if (pst_install(fx, "hello", "version b", &o) != PLUGIN_OK)
        return false;
    memcpy(t->b, fx->generation, PST_HEX);
    if (pst_install(fx, "hello", "version c", &o) != PLUGIN_OK)
        return false;
    memcpy(t->c, fx->generation, PST_HEX);
    return true;
}

static enum plugin_status pst_flip_worker(struct pst_fx *fx, const struct pst_trio *t)
{
    for (int i = 0; i < 20; i++) {
        enum plugin_status st = plugin_store_switch(fx->root, "hello", t->b);
        if (st == PLUGIN_OK)
            st = plugin_store_switch(fx->root, "hello", t->c);
        if (st != PLUGIN_OK)
            return st;
    }
    return PLUGIN_OK;
}

/* Every entry of the plugin directory must be a known name: no stray temp link. */
static bool pst_plugdir_clean(const struct pst_fx *fx)
{
    char dir[PATH_MAX];
    if (!pst_plug_path(fx, NULL, dir, sizeof(dir)))
        return false;
    DIR *d = opendir(dir);
    if (!d)
        return false;
    bool clean = true;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0 &&
            strcmp(e->d_name, "generations") != 0 && strcmp(e->d_name, "current") != 0 &&
            strcmp(e->d_name, "last-good") != 0 && strcmp(e->d_name, ".lock") != 0)
            clean = false;
    }
    closedir(d);
    return clean;
}

static int pst_case_concurrent_switch(void)
{
    int failures = 0;
    TEST_CASE("eight concurrent switchers leave current and last-good distinct and verified") {
        enum { KIDS = 8 };
        struct pst_fx fx;
        struct pst_trio t;
        pid_t pids[KIDS];
        char cur[PST_HEX], lg[PST_HEX], exe[PATH_MAX];
        struct plugin_manifest m;
        ASSERT(pst_three_generations(&fx, &t));
        ASSERT_EQ(plugin_store_switch(fx.root, "hello", t.a), PLUGIN_OK);
        for (int i = 0; i < KIDS; i++)
            pids[i] = pst_spawn(pst_flip_worker, &fx, &t);
        for (int i = 0; i < KIDS; i++)
            ASSERT_EQ(pst_reap(pids[i]), (int)PLUGIN_OK);
        pst_link(&fx, "hello", "current", cur);
        pst_link(&fx, "hello", "last-good", lg);
        ASSERT_EQ(plugin_store_current(fx.root, "hello", &m, exe, sizeof(exe)), PLUGIN_OK);
        ASSERT_STR_EQ(m.generation, cur);
        ASSERT(strcmp(cur, lg) != 0);
        ASSERT_EQ(plugin_store_switch(fx.root, "hello", lg), PLUGIN_OK); /* verifies lg */
        ASSERT(pst_plugdir_clean(&fx));
        pst_fx_close(&fx);
    } TEST_END
    return failures;
}

static enum plugin_status pst_busy_switch(struct pst_fx *fx, const struct pst_trio *t)
{
    return plugin_store_switch(fx->root, "hello", t->c);
}

static enum plugin_status pst_busy_rollback(struct pst_fx *fx, const struct pst_trio *t)
{
    char restored[PST_HEX];
    (void)t;
    return plugin_store_rollback(fx->root, "hello", restored);
}

static enum plugin_status pst_busy_install(struct pst_fx *fx, const struct pst_trio *t)
{
    struct pst_opts o = {0};
    (void)t;
    return pst_install(fx, "hello", "version d", &o);
}

static int pst_case_lock_exclusion(void)
{
    int failures = 0;
    TEST_CASE("a held plugin lock refuses install, switch and rollback with PLUGIN_BUSY") {
        struct pst_fx fx;
        struct pst_trio t;
        char lockpath[PATH_MAX], cur[PST_HEX], lg[PST_HEX];
        ASSERT(pst_three_generations(&fx, &t));
        ASSERT_EQ(plugin_store_switch(fx.root, "hello", t.a), PLUGIN_OK);
        ASSERT_EQ(plugin_store_switch(fx.root, "hello", t.b), PLUGIN_OK);
        ASSERT(pst_plug_path(&fx, ".lock", lockpath, sizeof(lockpath)));
        int fd = open(lockpath, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        ASSERT(fd >= 0);
        ASSERT_EQ(flock(fd, LOCK_EX | LOCK_NB), 0);
        pid_t sw = pst_spawn(pst_busy_switch, &fx, &t);
        pid_t rb = pst_spawn(pst_busy_rollback, &fx, &t);
        pid_t in = pst_spawn(pst_busy_install, &fx, &t);
        ASSERT_EQ(pst_reap(sw), (int)PLUGIN_ERR_BUSY);
        ASSERT_EQ(pst_reap(rb), (int)PLUGIN_ERR_BUSY);
        ASSERT_EQ(pst_reap(in), (int)PLUGIN_ERR_BUSY);
        ASSERT_STR_EQ(plugin_status_code(PLUGIN_ERR_BUSY), "PLUGIN_BUSY");
        pst_link(&fx, "hello", "current", cur);
        pst_link(&fx, "hello", "last-good", lg);
        ASSERT_STR_EQ(cur, t.b);
        ASSERT_STR_EQ(lg, t.a);
        /* The refused installer staged nothing. */
        ASSERT(pst_plugdir_clean(&fx));
        ASSERT_EQ(flock(fd, LOCK_UN), 0);
        close(fd);
        ASSERT_EQ(plugin_store_switch(fx.root, "hello", t.c), PLUGIN_OK);
        pst_link(&fx, "hello", "current", cur);
        pst_link(&fx, "hello", "last-good", lg);
        ASSERT_STR_EQ(cur, t.c);
        ASSERT_STR_EQ(lg, t.b);
        pst_fx_close(&fx);
    } TEST_END
    return failures;
}

static int pst_case_crashed_install(void)
{
    int failures = 0;
    TEST_CASE("a crash between staging and rename leaves no partial generation and the retry installs") {
        struct pst_fx fx;
        struct pst_opts o = {0};
        struct plugin_info *infos = NULL;
        struct plugin_manifest m;
        char a[PST_HEX], cur[PST_HEX], staging[PATH_MAX], leftover[PATH_MAX], tag[32];
        int present = -1;
        ASSERT(pst_fx_open(&fx, true));
        ASSERT_EQ(pst_install(&fx, "hello", "version a", &o), PLUGIN_OK);
        memcpy(a, fx.generation, PST_HEX);
        ASSERT_EQ(plugin_store_switch(fx.root, "hello", a), PLUGIN_OK);
        ASSERT(pst_publish(&fx, "hello", "version b", &o));
        /* What a crashed installer leaves: its staging directory, filled but
         * never renamed into generations/ (same pid as a reused one). */
        snprintf(tag, sizeof(tag), "staging.%ld", (long)getpid());
        ASSERT(pst_plug_path(&fx, tag, staging, sizeof(staging)));
        ASSERT_EQ(mkdir(staging, 0700), 0);
        ASSERT(pst_path(leftover, sizeof(leftover), staging, "hello"));
        ASSERT(pst_write(leftover, "partial", 7));
        ASSERT(pst_list_one(&fx, &infos));
        ASSERT_EQ(infos[0].generation_count, 1u);
        ASSERT_STR_EQ(infos[0].generations[0], a);
        plugin_store_list_free(infos, 1);
        ASSERT_EQ(plugin_store_install(fx.root, fx.manifest, &m, &present), PLUGIN_OK);
        ASSERT_EQ(present, 0);
        pst_link(&fx, "hello", "current", cur);
        ASSERT_STR_EQ(cur, a);
        ASSERT(access(staging, F_OK) != 0);
        ASSERT_EQ(plugin_store_switch(fx.root, "hello", m.generation), PLUGIN_OK);
        ASSERT(pst_list_one(&fx, &infos));
        ASSERT_EQ(infos[0].generation_count, 2u);
        plugin_store_list_free(infos, 1);
        pst_fx_close(&fx);
    } TEST_END
    return failures;
}

static int pst_case_registered(void)
{
    int failures = 0;
    TEST_CASE("the plugin leaves are registered with their handlers") {
        const struct zcl_command_registry *reg = zcl_command_catalog();
        const struct zcl_command_spec *s;
        ASSERT(reg);
        s = zcl_command_registry_find(reg, "plugin.install", NULL);
        ASSERT(s && s->handler == zcl_native_handle_plugin_install);
        s = zcl_command_registry_find(reg, "plugin.list", NULL);
        ASSERT(s && s->handler == zcl_native_handle_plugin_list);
        s = zcl_command_registry_find(reg, "plugin.status", NULL);
        ASSERT(s && s->handler == zcl_native_handle_plugin_status);
        s = zcl_command_registry_find(reg, "plugin.switch", NULL);
        ASSERT(s && s->handler == zcl_native_handle_plugin_switch);
        s = zcl_command_registry_find(reg, "plugin.rollback", NULL);
        ASSERT(s && s->handler == zcl_native_handle_plugin_rollback);
        s = zcl_command_registry_find(reg, "plugin.pack", NULL);
        ASSERT(s && s->handler == zcl_native_handle_plugin_pack);
        s = zcl_command_registry_find(reg, "plugin.keygen", NULL);
        ASSERT(s && s->handler == zcl_native_handle_plugin_keygen);
        ASSERT(zcl_native_command_is_root("plugin"));
    } TEST_END
    return failures;
}

int test_plugin_store(void)
{
    int failures = 0;
    printf("\n=== Plugin store tests ===\n");
    failures += pst_case_install_valid();
    failures += pst_case_integrity_refusals();
    failures += pst_case_keys_refusals();
    failures += pst_case_strict_format();
    failures += pst_case_manifest_vocabulary();
    failures += pst_case_switch_rollback();
    failures += pst_case_interrupted_swap();
    failures += pst_case_atomic_link_failure();
    failures += pst_case_rollback_refusals();
    failures += pst_case_post_install_tamper();
    failures += pst_case_insecure_keys();
    failures += pst_case_insecure_dirs();
    failures += pst_case_store_symlinks();
    failures += pst_case_republish_broken();
    failures += pst_case_keys_file_forms();
    failures += pst_case_revoked_key();
    failures += pst_case_permission_update();
    failures += pst_case_permission_update_revoked();
    failures += pst_case_legacy_generation();
    failures += pst_case_tampered_last_good();
    failures += pst_case_input_limits();
    failures += pst_case_commands();
    failures += pst_case_slot_states_readable();
    failures += pst_case_slot_states_corrupt();
    failures += pst_case_slot_states_unreadable();
    failures += pst_case_readdir_failure();
    failures += pst_case_status_states();
    failures += pst_case_pack_roundtrip();
    failures += pst_case_pack_deterministic();
    failures += pst_case_pack_tampered_exe();
    failures += pst_case_pack_key_refusals();
    failures += pst_case_keygen();
    failures += pst_case_pack_field_mutation();
    failures += pst_case_pack_commands();
    failures += pst_case_pack_next_escaping();
    failures += pst_case_concurrent_switch();
    failures += pst_case_lock_exclusion();
    failures += pst_case_crashed_install();
    failures += pst_case_registered();
    return failures;
}
