/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zcode_add — the ZCODE package INSTALL lifecycle (phase 1):
 * engine/services/src/package_lifecycle*.c plus its pure rules in
 * contexts/commons/modules/vcs/package_{deps,build,install}.c and the
 * zclassic23-package-verify --emit build worker.
 *
 * Coverage:
 *   1. Pure rules: the dependency declaration grammar, the lock wire, and
 *      the ADVERSARIAL DAG cases the resolver must name rather than paper
 *      over — a two-node CYCLE, a self-edge, an unresolvable root, and a
 *      label that disagrees with the resolved release. A cycle cannot be
 *      built out of honest content hashes (A's root commits its own
 *      declaration, so it cannot name a root that names A), which is
 *      exactly why the resolver is exercised through a synthetic source
 *      that CAN present one.
 *   2. Generation log + name splitting + plan expiry rules.
 *   3. End-to-end on a fixture datadir, with the REAL confined worker:
 *      plan -> commit -> a static archive and headers under
 *      <datadir>/zcode/installed/<root>/, a dependency installed before
 *      its dependent, install of a second version, rollback to the first,
 *      and the three refusals that must never install anything: an
 *      expired plan, a hand-edited plan file, and a tampered CAS chunk.
 *
 * The e2e lane forks build/bin/zclassic23-package-verify — it MUST exist
 * (make zclassic23-package-verify); a missing binary is a loud failure,
 * never a silent skip. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "core/uint256.h"
#include "crypto/sha3.h"
#include "json/json.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "services/package_lifecycle.h"
#include "../../../contexts/commons/services/src/package_lifecycle_internal.h"
#include "util/spawn.h"
#include "vcs/package_build.h"
#include "vcs/package_deps.h"
#include "vcs/package_install.h"
#include "vcs/package_manifest.h"
#include "vcs/package_recipe.h"
#include "vcs/package_release.h"
#include "vcs/package_reproduce.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ZA_CHECK(name, expr) do {                                       \
    if (expr) { printf("  zcode_add: %s... OK\n", (name)); }            \
    else { printf("  zcode_add: %s... FAIL\n", (name)); failures++; }   \
} while (0)

/* ── tiny filesystem + hex helpers (same shape as test_zcode_verify) ── */

static void za_hex(const uint8_t *in, size_t len, char *out)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i] = d[(in[i] >> 4) & 0xf];
        out[2 * i + 1] = d[in[i] & 0xf];
    }
    out[2 * len] = '\0';
}

static bool za_mkdir_p(const char *path)
{
    char buf[4096];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof(buf))
        return false;
    memcpy(buf, path, len + 1);
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(buf, 0700) != 0 && errno != EEXIST)
            return false;
        *p = '/';
    }
    return mkdir(buf, 0700) == 0 || errno == EEXIST;
}

static bool za_rm_rf(const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0)
        return errno == ENOENT;
    if (!S_ISDIR(st.st_mode))
        return unlink(path) == 0;
    DIR *d = opendir(path);
    if (!d)
        return false;
    struct dirent *e;
    bool ok = true;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        char child[4096];
        if (snprintf(child, sizeof(child), "%s/%s", path, e->d_name) >=
            (int)sizeof(child)) {
            ok = false;
            continue;
        }
        ok = za_rm_rf(child) && ok;
    }
    closedir(d);
    return rmdir(path) == 0 && ok;
}

static bool za_write_file(const char *path, const void *data, size_t len,
                          mode_t mode)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    bool ok = len == 0 || fwrite(data, 1, len, f) == len;
    if (fclose(f) != 0)
        ok = false;
    if (ok && chmod(path, mode) != 0)
        ok = false;
    return ok;
}

static bool za_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static bool za_link_targets_path(const char *link, const char *target)
{
    char actual[4400], expected[4400];
    ssize_t len = readlink(link, actual, sizeof(actual) - 1u);
    if (len <= 0 || !test_abs_path(target, expected, sizeof(expected)))
        return false;
    actual[len] = '\0';
    return strcmp(actual, expected) == 0;
}

/* Non-dot entry count of one directory (0 when it cannot be opened). The
 * fastobj cache's object+sidecar pairs are the only thing that lands there,
 * so a positive count proves the confined worker actually used the cache. */
static size_t za_dir_entries(const char *path)
{
    DIR *d = opendir(path);
    if (!d)
        return 0;
    struct dirent *e;
    size_t n = 0;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0)
            n++;
    }
    closedir(d);
    return n;
}

static bool za_read_json_file(const char *path, struct json_value *out)
{
    FILE *f = fopen(path, "rb");
    if (!f || fseek(f, 0, SEEK_END) != 0) {
        if (f) fclose(f);
        return false;
    }
    long end = ftell(f);
    if (end <= 0 || end > 512 * 1024 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return false;
    }
    size_t len = (size_t)end;
    char *wire = malloc(len);
    bool ok = wire && fread(wire, 1, len, f) == len;
    if (fclose(f) != 0) ok = false;
    if (!ok) {
        free(wire);
        return false;
    }
    json_init(out);
    ok = json_read(out, wire, len);
    free(wire);
    return ok;
}

/* ── 1. pure dependency rules ───────────────────────────────────────── */

/* A synthetic DAG source: the ONLY way to present the resolver a cycle,
 * because real roots are content hashes and cannot form one. */
struct za_fake_node {
    uint8_t root[32];
    const char *name;
    const char *semver;
    size_t dep_count;
    uint8_t deps[4][32];
};

struct za_fake_src {
    struct za_fake_node nodes[16];
    size_t count;
};

/* SHA3-256 of a file's bytes. Byte-exact identity of an installed artifact
 * is the whole claim a rollback makes, so the test hashes rather than
 * checking that "something is there". */
static bool za_file_sha3(const char *path, uint8_t out[32])
{
    memset(out, 0, 32);
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    uint8_t buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        sha3_256_write(&ctx, buf, n);
    bool ok = ferror(f) == 0;
    fclose(f);
    sha3_256_finalize(&ctx, out);
    return ok;
}

static void za_fake_root(uint8_t out[32], uint8_t tag)
{
    memset(out, 0, 32);
    out[0] = tag;
    out[31] = tag;
}

static bool za_fake_load(void *vctx, const uint8_t root[32],
                         char name_out[VCS_PACKAGE_RELEASE_NAME_MAX + 1u],
                         char semver_out[VCS_PACKAGE_RELEASE_SEMVER_MAX + 1u],
                         struct vcs_package_deps *deps_out)
{
    struct za_fake_src *s = vctx;
    vcs_package_deps_init(deps_out);
    for (size_t i = 0; i < s->count; i++) {
        if (memcmp(s->nodes[i].root, root, 32) != 0)
            continue;
        snprintf(name_out, VCS_PACKAGE_RELEASE_NAME_MAX + 1u, "%s",
                 s->nodes[i].name);
        snprintf(semver_out, VCS_PACKAGE_RELEASE_SEMVER_MAX + 1u, "%s",
                 s->nodes[i].semver);
        for (size_t j = 0; j < s->nodes[i].dep_count; j++) {
            struct vcs_package_dep *d = &deps_out->items[deps_out->count++];
            memcpy(d->root, s->nodes[i].deps[j], 32);
            d->name[0] = '\0';
            d->semver[0] = '\0';
        }
        return true;
    }
    return false; /* unresolvable — the resolver must NAME this */
}

static enum vcs_package_deps_error za_resolve(struct za_fake_src *s,
                                              uint8_t tag,
                                              struct vcs_package_lock *lock)
{
    struct vcs_package_deps_source src = { .ctx = s, .load = za_fake_load };
    uint8_t target[32];
    za_fake_root(target, tag);
    char detail[160];
    return vcs_package_lock_resolve(target, &src, lock, detail,
                                    sizeof(detail));
}

static int t_deps_rules(void)
{
    int failures = 0;

    /* Declaration grammar. */
    struct vcs_package_deps deps;
    const char *good =
        "{\"schema\":1,\"dependencies\":[{\"root\":"
        "\"1111111111111111111111111111111111111111111111111111111111111111\""
        ",\"name\":\"alice/base\",\"semver\":\"1.0.0\"}]}";
    ZA_CHECK("declaration parses",
             vcs_package_deps_parse_meta((const uint8_t *)good, strlen(good),
                                         &deps, NULL, 0) ==
                     VCS_PACKAGE_DEPS_OK &&
                 deps.count == 1);
    const char *no_root = "{\"schema\":1,\"dependencies\":[{\"name\":\"a/b\"}]}";
    ZA_CHECK("a dependency without a root is rejected",
             vcs_package_deps_parse_meta((const uint8_t *)no_root,
                                         strlen(no_root), &deps, NULL, 0) ==
                 VCS_PACKAGE_DEPS_ERR_DEP_ROOT);
    const char *upper =
        "{\"dependencies\":[{\"root\":"
        "\"AAAA111111111111111111111111111111111111111111111111111111111111\""
        "}]}";
    ZA_CHECK("an uppercase-hex root is rejected (one canonical spelling)",
             vcs_package_deps_parse_meta((const uint8_t *)upper,
                                         strlen(upper), &deps, NULL, 0) ==
                 VCS_PACKAGE_DEPS_ERR_DEP_ROOT);
    ZA_CHECK("an absent declaration means zero dependencies",
             vcs_package_deps_parse_meta((const uint8_t *)"", 0, &deps, NULL,
                                         0) == VCS_PACKAGE_DEPS_OK &&
                 deps.count == 0);

    /* The adversarial DAG cases. */
    struct za_fake_src s;
    struct vcs_package_lock lock;

    memset(&s, 0, sizeof(s));
    s.count = 2;
    za_fake_root(s.nodes[0].root, 0xA1);
    s.nodes[0].name = "alice/a";
    s.nodes[0].semver = "1.0.0";
    s.nodes[0].dep_count = 1;
    za_fake_root(s.nodes[0].deps[0], 0xB2);
    za_fake_root(s.nodes[1].root, 0xB2);
    s.nodes[1].name = "alice/b";
    s.nodes[1].semver = "1.0.0";
    s.nodes[1].dep_count = 1;
    za_fake_root(s.nodes[1].deps[0], 0xA1);
    ZA_CHECK("a two-node cycle is NAMED, never silently broken",
             za_resolve(&s, 0xA1, &lock) == VCS_PACKAGE_DEPS_ERR_CYCLE);

    memset(&s, 0, sizeof(s));
    s.count = 1;
    za_fake_root(s.nodes[0].root, 0xC3);
    s.nodes[0].name = "alice/c";
    s.nodes[0].semver = "1.0.0";
    s.nodes[0].dep_count = 1;
    za_fake_root(s.nodes[0].deps[0], 0xC3);
    ZA_CHECK("a self-dependency is named",
             za_resolve(&s, 0xC3, &lock) == VCS_PACKAGE_DEPS_ERR_SELF);

    memset(&s, 0, sizeof(s));
    s.count = 1;
    za_fake_root(s.nodes[0].root, 0xD4);
    s.nodes[0].name = "alice/d";
    s.nodes[0].semver = "1.0.0";
    s.nodes[0].dep_count = 1;
    za_fake_root(s.nodes[0].deps[0], 0xE5); /* nobody publishes 0xE5 */
    ZA_CHECK("an unresolvable dependency is named, not skipped",
             za_resolve(&s, 0xD4, &lock) == VCS_PACKAGE_DEPS_ERR_UNRESOLVED);

    /* A healthy diamond: one shared dependency, deduplicated, deps first. */
    memset(&s, 0, sizeof(s));
    s.count = 4;
    za_fake_root(s.nodes[0].root, 0x10);
    s.nodes[0].name = "alice/top";
    s.nodes[0].semver = "1.0.0";
    s.nodes[0].dep_count = 2;
    za_fake_root(s.nodes[0].deps[0], 0x11);
    za_fake_root(s.nodes[0].deps[1], 0x12);
    za_fake_root(s.nodes[1].root, 0x11);
    s.nodes[1].name = "alice/left";
    s.nodes[1].semver = "1.0.0";
    s.nodes[1].dep_count = 1;
    za_fake_root(s.nodes[1].deps[0], 0x13);
    za_fake_root(s.nodes[2].root, 0x12);
    s.nodes[2].name = "alice/right";
    s.nodes[2].semver = "1.0.0";
    s.nodes[2].dep_count = 1;
    za_fake_root(s.nodes[2].deps[0], 0x13);
    za_fake_root(s.nodes[3].root, 0x13);
    s.nodes[3].name = "alice/shared";
    s.nodes[3].semver = "1.0.0";
    s.nodes[3].dep_count = 0;
    bool diamond = za_resolve(&s, 0x10, &lock) == VCS_PACKAGE_DEPS_OK &&
                   lock.count == 4 && lock.nodes[3].depth == 0 &&
                   lock.nodes[0].depth == 2;
    ZA_CHECK("a diamond resolves once, in build order", diamond);
    struct vcs_package_lock diamond_lock = lock;

    /* The shared leaf is visited directly before it is reached through the
     * codec. Its depth must describe topology, not first-visit root order. */
    memset(&s, 0, sizeof(s));
    s.count = 3;
    za_fake_root(s.nodes[0].root, 0x20);
    s.nodes[0].name = "alice/top";
    s.nodes[0].semver = "1.0.0";
    s.nodes[0].dep_count = 2;
    za_fake_root(s.nodes[0].deps[0], 0x21);
    za_fake_root(s.nodes[0].deps[1], 0x22);
    za_fake_root(s.nodes[1].root, 0x21);
    s.nodes[1].name = "alice/base";
    s.nodes[1].semver = "1.0.0";
    za_fake_root(s.nodes[2].root, 0x22);
    s.nodes[2].name = "alice/codec";
    s.nodes[2].semver = "1.0.0";
    s.nodes[2].dep_count = 1;
    za_fake_root(s.nodes[2].deps[0], 0x21);
    bool uneven = za_resolve(&s, 0x20, &lock) == VCS_PACKAGE_DEPS_OK &&
                  lock.count == 3 && lock.nodes[0].depth == 2 &&
                  lock.nodes[1].depth == 1 && lock.nodes[2].depth == 0;
    ZA_CHECK("shared dependency depth follows the longest graph path", uneven);

    /* A direct edge must not hide a second path beyond the depth bound. */
    memset(&s, 0, sizeof(s));
    s.count = 10;
    za_fake_root(s.nodes[0].root, 0x30);
    s.nodes[0].name = "alice/deep-top";
    s.nodes[0].semver = "1.0.0";
    s.nodes[0].dep_count = 2;
    za_fake_root(s.nodes[0].deps[0], 0x31);
    za_fake_root(s.nodes[0].deps[1], 0x32);
    za_fake_root(s.nodes[1].root, 0x31);
    s.nodes[1].name = "alice/shared";
    s.nodes[1].semver = "1.0.0";
    for (size_t i = 0; i < 8; i++) {
        za_fake_root(s.nodes[i + 2].root, (uint8_t)(0x32u + i));
        s.nodes[i + 2].name = "alice/chain";
        s.nodes[i + 2].semver = "1.0.0";
        s.nodes[i + 2].dep_count = 1;
        za_fake_root(s.nodes[i + 2].deps[0],
                     i == 7 ? 0x31 : (uint8_t)(0x33u + i));
    }
    ZA_CHECK("a shared direct edge cannot hide an over-depth path",
             za_resolve(&s, 0x30, &lock) == VCS_PACKAGE_DEPS_ERR_DEPTH);
    lock = diamond_lock;

    /* The lock wire is closed: it roundtrips and rejects a flipped byte. */
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    bool wire_ok = vcs_package_lock_serialize(&lock, &wire, &wire_len) ==
                   VCS_PACKAGE_DEPS_OK;
    struct vcs_package_lock back;
    if (wire_ok)
        wire_ok = vcs_package_lock_parse(wire, wire_len, &back) ==
                      VCS_PACKAGE_DEPS_OK &&
                  back.count == lock.count;
    uint8_t r1[32], r2[32];
    if (wire_ok)
        wire_ok = vcs_package_lock_root(&lock, r1) == VCS_PACKAGE_DEPS_OK &&
                  vcs_package_lock_root(&back, r2) == VCS_PACKAGE_DEPS_OK &&
                  memcmp(r1, r2, 32) == 0;
    ZA_CHECK("the lock wire roundtrips to the same lock root", wire_ok);
    if (wire && wire_len > 12) {
        wire[0] ^= 0xff;
        ZA_CHECK("a corrupted lock magic is rejected",
                 vcs_package_lock_parse(wire, wire_len, &back) ==
                     VCS_PACKAGE_DEPS_ERR_WIRE_MAGIC);
        wire[0] ^= 0xff;
        ZA_CHECK("a truncated lock is rejected",
                 vcs_package_lock_parse(wire, wire_len - 1u, &back) !=
                     VCS_PACKAGE_DEPS_OK);
    }
    free(wire);
    return failures;
}

/* ── 2. generation log, name split, plan expiry ─────────────────────── */

static int t_generations(void)
{
    int failures = 0;
    struct vcs_package_generations g;
    vcs_package_generations_init(&g);
    uint8_t a[32], b[32], out[32];
    za_fake_root(a, 0x21);
    za_fake_root(b, 0x22);
    ZA_CHECK("first activation appends",
             vcs_package_generations_append(&g, a, 100) ==
                 VCS_PACKAGE_INSTALL_OK);
    ZA_CHECK("re-activating the active root is rejected (nothing changed)",
             vcs_package_generations_append(&g, a, 101) !=
                 VCS_PACKAGE_INSTALL_OK);
    ZA_CHECK("second activation appends",
             vcs_package_generations_append(&g, b, 102) ==
                 VCS_PACKAGE_INSTALL_OK);
    ZA_CHECK("previous() names the rollback target",
             vcs_package_generations_previous(&g, out) &&
                 memcmp(out, a, 32) == 0);
    uint8_t *wire = NULL;
    size_t len = 0;
    struct vcs_package_generations back;
    ZA_CHECK("the generation wire roundtrips",
             vcs_package_generations_serialize(&g, &wire, &len) ==
                     VCS_PACKAGE_INSTALL_OK &&
                 vcs_package_generations_parse(wire, len, &back) ==
                     VCS_PACKAGE_INSTALL_OK &&
                 back.count == 2);
    if (wire && len > 4) {
        wire[len - 1u] ^= 0xff;
        ZA_CHECK("a flipped generation byte is still a parse (a hash, not a "
                 "checksum, is what guards content)",
                 vcs_package_generations_parse(wire, len, &back) ==
                     VCS_PACKAGE_INSTALL_OK);
        ZA_CHECK("a truncated generation log is rejected",
                 vcs_package_generations_parse(wire, len - 1u, &back) !=
                     VCS_PACKAGE_INSTALL_OK);
    }
    free(wire);

    /* --- retention is bounded by EVICTION, never by refusal --------------
     * A log that refused its own append once full would deny the next
     * install AND the next rollback, bricking the package at the moment
     * going back matters most. So the policy is explicit and asserted here:
     * FIFO, oldest first, KEEP retained, append never fails on count, and
     * the rollback target always survives. */
    struct vcs_package_generations e;
    vcs_package_generations_init(&e);
    const size_t overrun = VCS_PACKAGE_GENERATION_KEEP + 37u;
    bool every_append_ok = true;
    for (size_t i = 0; i < overrun; i++) {
        uint8_t r[32];
        za_fake_root(r, (uint8_t)(0x40u + (i & 0x7fu)));
        /* za_fake_root's tag byte wraps; make every root distinct. */
        r[1] = (uint8_t)(i & 0xffu);
        r[2] = (uint8_t)((i >> 8) & 0xffu);
        if (vcs_package_generations_append(&e, r, 1000 + (int64_t)i) !=
            VCS_PACKAGE_INSTALL_OK)
            every_append_ok = false;
    }
    ZA_CHECK("a full generation log never refuses an append (it evicts)",
             every_append_ok);
    ZA_CHECK("retention is bounded to the KEEP newest generations",
             e.count == VCS_PACKAGE_GENERATION_KEEP);
    ZA_CHECK("eviction is FIFO: the surviving oldest is the KEEP-th newest",
             e.items[0].activated_unix ==
                 1000 + (int64_t)(overrun - VCS_PACKAGE_GENERATION_KEEP));
    ZA_CHECK("the newest generation is never the one evicted",
             e.items[e.count - 1u].activated_unix ==
                 1000 + (int64_t)(overrun - 1u));
    ZA_CHECK("a rollback target survives eviction",
             vcs_package_generations_previous(&e, out) &&
                 memcmp(out, e.items[e.count - 2u].root, 32) == 0);
    ZA_CHECK("an evicted log still serializes inside the wire bound",
             vcs_package_generations_serialize(&e, &wire, &len) ==
                     VCS_PACKAGE_INSTALL_OK &&
                 len <= VCS_PACKAGE_GENERATION_MAX_WIRE_BYTES);
    free(wire);
    wire = NULL;

    /* trim is the one eviction primitive, so assert it directly. */
    struct vcs_package_generations t;
    vcs_package_generations_init(&t);
    for (size_t i = 0; i < 5u; i++) {
        uint8_t r[32];
        za_fake_root(r, 0x50);
        r[1] = (uint8_t)i;
        (void)vcs_package_generations_append(&t, r, 2000 + (int64_t)i);
    }
    ZA_CHECK("trim drops exactly the oldest entries and reports the count",
             vcs_package_generations_trim(&t, 2u) == 3u && t.count == 2u &&
                 t.items[0].activated_unix == 2003 &&
                 t.items[1].activated_unix == 2004);
    ZA_CHECK("trim never empties a non-empty log",
             vcs_package_generations_trim(&t, 0) == 1u && t.count == 1u);
    ZA_CHECK("trim of a log already within the bound is a no-op",
             vcs_package_generations_trim(&t, 8u) == 0 && t.count == 1u);

    char pub[VCS_PACKAGE_RELEASE_NAME_MAX + 1u];
    char pkg[VCS_PACKAGE_RELEASE_NAME_MAX + 1u];
    ZA_CHECK("a well-formed name splits",
             vcs_package_name_split("alice/ringbuffer", pub, pkg) &&
                 strcmp(pub, "alice") == 0 &&
                 strcmp(pkg, "ringbuffer") == 0);
    ZA_CHECK("a name with a path escape never becomes a directory",
             !vcs_package_name_split("../../etc/passwd", pub, pkg) &&
                 !vcs_package_name_split("alice/../evil", pub, pkg) &&
                 !vcs_package_name_split("alice", pub, pkg) &&
                 !vcs_package_name_split("a/b/c", pub, pkg));

    struct vcs_package_plan plan;
    vcs_package_plan_init(&plan);
    plan.created_unix = 1000;
    plan.expires_unix = 1000 + VCS_PACKAGE_PLAN_TTL_SECONDS;
    ZA_CHECK("a plan expires exactly at its stated expiry",
             !vcs_package_plan_expired(&plan, plan.expires_unix - 1) &&
                 vcs_package_plan_expired(&plan, plan.expires_unix));
    return failures;
}

static int t_release_selection(void)
{
    int failures = 0;
    struct vcs_package_release releases[4] = {0};
    struct pkgl_ctx ctx = { .releases = releases, .release_count = 2 };
    for (size_t i = 0; i < 4; i++) {
        (void)snprintf(releases[i].name, sizeof(releases[i].name),
                       "alice/preview");
        releases[i].package_root[0] = (uint8_t)(i + 1u);
    }
    (void)snprintf(releases[0].semver, sizeof(releases[0].semver),
                   "1.0.0-rc.10");
    (void)snprintf(releases[1].semver, sizeof(releases[1].semver),
                   "1.0.0-rc.2");
    const struct vcs_package_release *selected =
        pkgl_release_for_name(&ctx, "alice/preview");
    ZA_CHECK("install selection orders numeric prerelease identifiers",
             selected == &releases[0]);
    (void)snprintf(releases[2].semver, sizeof(releases[2].semver),
                   "1.0.0");
    ctx.release_count = 3;
    selected = pkgl_release_for_name(&ctx, "alice/preview");
    ZA_CHECK("a stable release supersedes its prereleases",
             selected == &releases[2]);
    uint8_t resolved[32];
    struct zcl_result missing = pkgl_resolve_target(
        &ctx, "alice/preview@1.0.2", resolved);
    ZA_CHECK("an absent exact version names a usable selection action",
             !missing.ok && strstr(missing.message, "alice/preview@1.0.2") &&
                 strstr(missing.message, "latest published version"));
    (void)snprintf(releases[0].semver, sizeof(releases[0].semver),
                   "1.0.1-1");
    (void)snprintf(releases[1].semver, sizeof(releases[1].semver),
                   "1.0.1-alpha");
    ctx.release_count = 2;
    selected = pkgl_release_for_name(&ctx, "alice/preview");
    ZA_CHECK("numeric prerelease identifiers precede text identifiers",
             selected == &releases[1]);
    (void)snprintf(releases[0].semver, sizeof(releases[0].semver),
                   "1.0.10+build.2");
    (void)snprintf(releases[1].semver, sizeof(releases[1].semver),
                   "1.0.9+build.10");
    selected = pkgl_release_for_name(&ctx, "alice/preview");
    ZA_CHECK("install selection compares numeric version cores",
             selected == &releases[0]);
    (void)snprintf(releases[1].semver, sizeof(releases[1].semver),
                   "1.0.10+build.10");
    selected = pkgl_release_for_name(&ctx, "alice/preview");
    ZA_CHECK("build metadata does not change release precedence",
             selected == &releases[0]);
    return failures;
}

static int t_activation_target_shape(void)
{
    int failures = 0;
    char base[256], zcode[320], installed[400], active[400];
    test_make_tmpdir(base, sizeof(base), "zcode_add", "target-shape");
    (void)snprintf(zcode, sizeof(zcode), "%s/zcode", base);
    struct pkgl_ctx ctx = {0};
    (void)snprintf(ctx.zcode_dir, sizeof(ctx.zcode_dir), "%s", zcode);
    uint8_t root[32], previous[32];
    za_fake_root(root, 0x71);
    char hex[65];
    za_hex(root, 32, hex);
    (void)snprintf(installed, sizeof(installed), "%s/installed/%s", zcode,
                   hex);
    (void)snprintf(active, sizeof(active), "%s/active/alice/preview", zcode);
    char install_parent[400];
    (void)snprintf(install_parent, sizeof(install_parent), "%s/installed",
                   zcode);
    bool fixture = za_mkdir_p(install_parent) &&
                   za_write_file(installed, "not an install tree", 19, 0600);
    ZA_CHECK("non-directory install target fixture prepared", fixture);
    bool had_previous = false;
    struct zcl_result result = pkgl_activate(&ctx, "alice/preview", root,
                                             1000, previous, &had_previous);
    ZA_CHECK("activation refuses an installed root replaced by a file",
             fixture && !result.ok && strstr(result.message, "directory") &&
                 !za_exists(active));
    ZA_CHECK("activation target fixture removed", za_rm_rf(base));
    return failures;
}

static int t_active_temp_directory_preserved(void)
{
    int failures = 0;
    char base[256], installed[400], active[400], tmp[440], marker[480];
    test_make_tmpdir(base, sizeof(base), "zcode_add", "active-temp-dir");
    struct pkgl_ctx ctx = {0};
    (void)snprintf(ctx.zcode_dir, sizeof(ctx.zcode_dir), "%s/zcode", base);
    uint8_t root[32], previous[32];
    za_fake_root(root, 0x77);
    char hex[65];
    za_hex(root, 32, hex);
    (void)snprintf(installed, sizeof(installed), "%s/installed/%s",
                   ctx.zcode_dir, hex);
    (void)snprintf(active, sizeof(active), "%s/active/alice/preview",
                   ctx.zcode_dir);
    (void)snprintf(tmp, sizeof(tmp), "%s.zplnew.%ld", active, (long)getpid());
    (void)snprintf(marker, sizeof(marker), "%s/keep.txt", tmp);
    bool prepared = za_mkdir_p(installed) && za_mkdir_p(tmp) &&
                    za_write_file(marker, "keep", 4, 0600);
    bool had_previous = false;
    struct zcl_result activated = pkgl_activate(
        &ctx, "alice/preview", root, 1000, previous, &had_previous);
    ZA_CHECK("activation refuses a temporary path that is a directory",
             prepared && !activated.ok &&
                 strstr(activated.message, "temporary") != NULL &&
                 za_exists(marker) && !za_exists(active));
    ZA_CHECK("active temporary directory fixture removed", za_rm_rf(base));
    return failures;
}

static int t_active_parent_symlink(void)
{
    int failures = 0;
    char base[256], installed[400], active_parent[400];
    char outside[400], outside_abs[4400], escaped_link[440];
    test_make_tmpdir(base, sizeof(base), "zcode_add", "active-parent-link");
    struct pkgl_ctx ctx = {0};
    (void)snprintf(ctx.zcode_dir, sizeof(ctx.zcode_dir), "%s/zcode", base);
    uint8_t root[32], previous[32];
    za_fake_root(root, 0x78);
    char hex[65];
    za_hex(root, 32, hex);
    (void)snprintf(installed, sizeof(installed), "%s/installed/%s",
                   ctx.zcode_dir, hex);
    (void)snprintf(active_parent, sizeof(active_parent), "%s/active",
                   ctx.zcode_dir);
    (void)snprintf(outside, sizeof(outside), "%s/escaped-active", base);
    (void)snprintf(escaped_link, sizeof(escaped_link),
                   "%s/alice/preview", outside);
    bool prepared = za_mkdir_p(installed) && za_mkdir_p(outside) &&
                    test_abs_path(outside, outside_abs, sizeof(outside_abs)) &&
                    symlink(outside_abs, active_parent) == 0;
    bool had_previous = false;
    struct zcl_result activated = pkgl_activate(
        &ctx, "alice/preview", root, 1000, previous, &had_previous);
    struct stat escaped;
    bool outside_untouched = lstat(escaped_link, &escaped) != 0 &&
                             errno == ENOENT;
    ZA_CHECK("activation refuses a symlinked active directory outside the store",
             prepared && !activated.ok &&
                 strstr(activated.message, "active") != NULL &&
                 outside_untouched);
    char publisher_link[440];
    (void)snprintf(publisher_link, sizeof(publisher_link), "%s/alice",
                   active_parent);
    (void)snprintf(outside, sizeof(outside), "%s/escaped-publisher", base);
    (void)snprintf(escaped_link, sizeof(escaped_link), "%s/preview", outside);
    bool publisher_prepared = unlink(active_parent) == 0 &&
                              za_mkdir_p(active_parent) &&
                              za_mkdir_p(outside) &&
                              test_abs_path(outside, outside_abs,
                                            sizeof(outside_abs)) &&
                              symlink(outside_abs, publisher_link) == 0;
    activated = pkgl_activate(&ctx, "alice/preview", root, 1001, previous,
                              &had_previous);
    outside_untouched = lstat(escaped_link, &escaped) != 0 && errno == ENOENT;
    ZA_CHECK("activation refuses a symlinked publisher directory",
             publisher_prepared && !activated.ok && outside_untouched);
    ZA_CHECK("active parent symlink fixture removed", za_rm_rf(base));
    return failures;
}

static int t_generation_parent_symlink(void)
{
    int failures = 0;
    char base[256], installed[400], generations[400];
    char outside[400], outside_abs[4400], escaped_log[440];
    test_make_tmpdir(base, sizeof(base), "zcode_add", "generation-parent-link");
    struct pkgl_ctx ctx = {0};
    (void)snprintf(ctx.zcode_dir, sizeof(ctx.zcode_dir), "%s/zcode", base);
    uint8_t root[32], previous[32];
    za_fake_root(root, 0x79);
    char hex[65];
    za_hex(root, 32, hex);
    (void)snprintf(installed, sizeof(installed), "%s/installed/%s",
                   ctx.zcode_dir, hex);
    (void)snprintf(generations, sizeof(generations), "%s/generations",
                   ctx.zcode_dir);
    (void)snprintf(outside, sizeof(outside), "%s/escaped-generations", base);
    (void)snprintf(escaped_log, sizeof(escaped_log), "%s/alice/preview",
                   outside);
    bool prepared = za_mkdir_p(installed) && za_mkdir_p(outside) &&
                    test_abs_path(outside, outside_abs, sizeof(outside_abs)) &&
                    symlink(outside_abs, generations) == 0;
    bool had_previous = false;
    struct zcl_result activated = pkgl_activate(
        &ctx, "alice/preview", root, 1000, previous, &had_previous);
    struct stat escaped;
    bool outside_untouched = lstat(escaped_log, &escaped) != 0 &&
                             errno == ENOENT;
    ZA_CHECK("activation refuses a symlinked generation directory",
             prepared && !activated.ok && outside_untouched);
    char publisher_link[440];
    (void)snprintf(publisher_link, sizeof(publisher_link), "%s/alice",
                   generations);
    (void)snprintf(outside, sizeof(outside), "%s/escaped-gen-publisher", base);
    (void)snprintf(escaped_log, sizeof(escaped_log), "%s/preview", outside);
    bool publisher_prepared = unlink(generations) == 0 &&
                              za_mkdir_p(generations) &&
                              za_mkdir_p(outside) &&
                              test_abs_path(outside, outside_abs,
                                            sizeof(outside_abs)) &&
                              symlink(outside_abs, publisher_link) == 0;
    activated = pkgl_activate(&ctx, "alice/preview", root, 1001, previous,
                              &had_previous);
    outside_untouched = lstat(escaped_log, &escaped) != 0 && errno == ENOENT;
    ZA_CHECK("activation refuses a symlinked generation publisher directory",
             publisher_prepared && !activated.ok && outside_untouched);
    ZA_CHECK("generation parent symlink fixture removed", za_rm_rf(base));
    return failures;
}

static int t_data_parent_symlink(void)
{
    int failures = 0;
    char base[256], installed[400], data_parent[400];
    char outside[400], outside_abs[4400], escaped_data[440];
    test_make_tmpdir(base, sizeof(base), "zcode_add", "data-parent-link");
    struct pkgl_ctx ctx = {0};
    (void)snprintf(ctx.zcode_dir, sizeof(ctx.zcode_dir), "%s/zcode", base);
    uint8_t root[32], previous[32];
    za_fake_root(root, 0x7a);
    char hex[65];
    za_hex(root, 32, hex);
    (void)snprintf(installed, sizeof(installed), "%s/installed/%s",
                   ctx.zcode_dir, hex);
    (void)snprintf(data_parent, sizeof(data_parent), "%s/data",
                   ctx.zcode_dir);
    (void)snprintf(outside, sizeof(outside), "%s/escaped-data", base);
    (void)snprintf(escaped_data, sizeof(escaped_data), "%s/alice/preview",
                   outside);
    bool prepared = za_mkdir_p(installed) && za_mkdir_p(outside) &&
                    test_abs_path(outside, outside_abs, sizeof(outside_abs)) &&
                    symlink(outside_abs, data_parent) == 0;
    bool had_previous = false;
    struct zcl_result activated = pkgl_activate(
        &ctx, "alice/preview", root, 1000, previous, &had_previous);
    struct stat escaped;
    bool outside_untouched = lstat(escaped_data, &escaped) != 0 &&
                             errno == ENOENT;
    ZA_CHECK("activation refuses a symlinked package data directory",
             prepared && !activated.ok && outside_untouched);
    char publisher_link[440];
    (void)snprintf(publisher_link, sizeof(publisher_link), "%s/alice",
                   data_parent);
    (void)snprintf(outside, sizeof(outside), "%s/escaped-data-publisher", base);
    (void)snprintf(escaped_data, sizeof(escaped_data), "%s/preview", outside);
    bool publisher_prepared = unlink(data_parent) == 0 &&
                              za_mkdir_p(data_parent) &&
                              za_mkdir_p(outside) &&
                              test_abs_path(outside, outside_abs,
                                            sizeof(outside_abs)) &&
                              symlink(outside_abs, publisher_link) == 0;
    activated = pkgl_activate(&ctx, "alice/preview", root, 1001, previous,
                              &had_previous);
    outside_untouched = lstat(escaped_data, &escaped) != 0 && errno == ENOENT;
    ZA_CHECK("activation refuses a symlinked data publisher directory",
             publisher_prepared && !activated.ok && outside_untouched);
    ZA_CHECK("data parent symlink fixture removed", za_rm_rf(base));
    return failures;
}

static int t_atomic_write_temp_symlink(void)
{
    int failures = 0;
    char base[256], target[400], tmp[440], victim[400], victim_abs[4400];
    test_make_tmpdir(base, sizeof(base), "zcode_add", "atomic-temp-link");
    (void)snprintf(target, sizeof(target), "%s/report", base);
    (void)snprintf(tmp, sizeof(tmp), "%s.zpltmp.%ld", target, (long)getpid());
    (void)snprintf(victim, sizeof(victim), "%s/keep.txt", base);
    bool prepared = za_mkdir_p(base) &&
                    za_write_file(victim, "keep", 4, 0600) &&
                    test_abs_path(victim, victim_abs, sizeof(victim_abs)) &&
                    symlink(victim_abs, tmp) == 0;
    struct zcl_result wrote = pkgl_write_atomic(
        target, (const uint8_t *)"new", 3);
    uint8_t *kept = NULL;
    size_t kept_len = 0;
    struct zcl_result read = pkgl_read_file(victim, 16, &kept, &kept_len);
    struct stat temp_shape, target_shape;
    bool temp_held = lstat(tmp, &temp_shape) == 0 &&
                     S_ISLNK(temp_shape.st_mode);
    bool target_absent = lstat(target, &target_shape) != 0 && errno == ENOENT;
    ZA_CHECK("atomic write refuses a preexisting temporary symlink",
             prepared && !wrote.ok &&
                 strstr(wrote.message, "temporary") != NULL && temp_held &&
                 target_absent && read.ok && kept_len == 4 &&
                 memcmp(kept, "keep", 4) == 0);
    free(kept);
    ZA_CHECK("atomic temp symlink fixture removed", za_rm_rf(base));
    return failures;
}

static int t_relative_active_pointer(void)
{
    int failures = 0;
    char base[256], installed[400], active[400];
    (void)snprintf(base, sizeof(base), "test-tmp/za_relative_%ld",
                   (long)getpid());
    (void)za_rm_rf(base);
    bool private_base = za_mkdir_p(base);
    struct pkgl_ctx ctx = {0};
    (void)snprintf(ctx.zcode_dir, sizeof(ctx.zcode_dir), "%s/zcode", base);
    uint8_t root[32], previous[32];
    za_fake_root(root, 0x72);
    char hex[65];
    za_hex(root, 32, hex);
    (void)snprintf(installed, sizeof(installed), "%s/installed/%s",
                   ctx.zcode_dir, hex);
    (void)snprintf(active, sizeof(active), "%s/active/alice/preview",
                   ctx.zcode_dir);
    bool prepared = private_base && za_mkdir_p(installed);
    bool had_previous = false;
    struct zcl_result activated = pkgl_activate(
        &ctx, "alice/preview", root, 1000, previous, &had_previous);
    struct stat wanted, actual;
    ZA_CHECK("relative datadir activation points at its installed directory",
             prepared && activated.ok && stat(installed, &wanted) == 0 &&
                 stat(active, &actual) == 0 &&
                 wanted.st_dev == actual.st_dev &&
                 wanted.st_ino == actual.st_ino);
    ZA_CHECK("relative activation fixture removed", za_rm_rf(base));
    return failures;
}

static int t_active_log_divergence(void)
{
    int failures = 0;
    char base[256], installed[400], log_parent[400], active_path[400];
    test_make_tmpdir(base, sizeof(base), "zcode_add", "log-divergence");
    struct pkgl_ctx ctx = {0};
    (void)snprintf(ctx.zcode_dir, sizeof(ctx.zcode_dir), "%s/zcode", base);
    uint8_t root[32], previous[32], observed[32];
    za_fake_root(root, 0x73);
    char hex[65];
    za_hex(root, 32, hex);
    (void)snprintf(installed, sizeof(installed), "%s/installed/%s",
                   ctx.zcode_dir, hex);
    (void)snprintf(log_parent, sizeof(log_parent), "%s/generations",
                   ctx.zcode_dir);
    (void)snprintf(active_path, sizeof(active_path),
                   "%s/active/alice/preview", ctx.zcode_dir);
    bool prepared = za_mkdir_p(installed) &&
                    za_write_file(log_parent, "blocked", 7, 0600);
    bool had_previous = false;
    struct zcl_result activated = pkgl_activate(
        &ctx, "alice/preview", root, 1000, previous, &had_previous);
    size_t generations = 0;
    bool present = false;
    struct zcl_result read = package_lifecycle_active(
        base, "alice/preview", observed, &generations, &present);
    struct stat active_st;
    ZA_CHECK("a blocked generation log refuses before the active swap",
             prepared && !activated.ok &&
                 strstr(activated.message, "generation") != NULL &&
                 lstat(active_path, &active_st) != 0 && errno == ENOENT);
    ZA_CHECK("status reports the blocked generation directory",
             !read.ok && strstr(read.message, "generation") != NULL &&
                 !present && generations == 0);
    bool unblocked = unlink(log_parent) == 0;
    struct zcl_result retry = pkgl_activate(
        &ctx, "alice/preview", root, 1001, previous, &had_previous);
    read = package_lifecycle_active(base, "alice/preview", observed,
                                    &generations, &present);
    ZA_CHECK("retry after removing the blocker activates the exact root",
             unblocked && retry.ok && read.ok && present &&
                 generations == 1 && memcmp(observed, root, 32) == 0);
    ZA_CHECK("divergent activation fixture removed", za_rm_rf(base));
    return failures;
}

static int t_active_wrong_pointer(void)
{
    int failures = 0;
    char base[256], installed[400], other[400], other_abs[4400];
    char active_path[400];
    test_make_tmpdir(base, sizeof(base), "zcode_add", "wrong-pointer");
    struct pkgl_ctx ctx = {0};
    (void)snprintf(ctx.zcode_dir, sizeof(ctx.zcode_dir), "%s/zcode", base);
    uint8_t root[32], wrong[32], previous[32], observed[32];
    za_fake_root(root, 0x74);
    za_fake_root(wrong, 0x75);
    char hex[65];
    za_hex(root, 32, hex);
    (void)snprintf(installed, sizeof(installed), "%s/installed/%s",
                   ctx.zcode_dir, hex);
    za_hex(wrong, 32, hex);
    (void)snprintf(other, sizeof(other), "%s/installed/%s", ctx.zcode_dir,
                   hex);
    (void)snprintf(active_path, sizeof(active_path),
                   "%s/active/alice/preview", ctx.zcode_dir);
    bool prepared = za_mkdir_p(installed) && za_mkdir_p(other) &&
                    test_abs_path(other, other_abs, sizeof(other_abs));
    bool had_previous = false;
    struct zcl_result activated = pkgl_activate(
        &ctx, "alice/preview", root, 1000, previous, &had_previous);
    bool replaced = prepared && activated.ok && unlink(active_path) == 0 &&
                    symlink(other_abs, active_path) == 0;
    size_t generations = 0;
    bool present = false;
    struct zcl_result read = package_lifecycle_active(
        base, "alice/preview", observed, &generations, &present);
    ZA_CHECK("status refuses a pointer to the wrong installed generation",
             replaced && !read.ok &&
                 strstr(read.message, "generation log disagree") != NULL);
    ZA_CHECK("wrong-pointer fixture removed", za_rm_rf(base));
    return failures;
}

static int t_active_missing_install(void)
{
    int failures = 0;
    char base[256], installed[400];
    test_make_tmpdir(base, sizeof(base), "zcode_add", "missing-install");
    struct pkgl_ctx ctx = {0};
    (void)snprintf(ctx.zcode_dir, sizeof(ctx.zcode_dir), "%s/zcode", base);
    uint8_t root[32], previous[32], observed[32];
    za_fake_root(root, 0x76);
    char hex[65];
    za_hex(root, 32, hex);
    (void)snprintf(installed, sizeof(installed), "%s/installed/%s",
                   ctx.zcode_dir, hex);
    bool prepared = za_mkdir_p(installed);
    bool had_previous = false;
    struct zcl_result activated = pkgl_activate(
        &ctx, "alice/preview", root, 1000, previous, &had_previous);
    bool removed = activated.ok && za_rm_rf(installed);
    size_t generations = 0;
    bool present = false;
    struct zcl_result read = package_lifecycle_active(
        base, "alice/preview", observed, &generations, &present);
    ZA_CHECK("status refuses an active root whose install disappeared",
             prepared && removed && !read.ok &&
                 strstr(read.message, "installed root") != NULL);
    ZA_CHECK("missing-install fixture removed", za_rm_rf(base));
    return failures;
}

/* ── the user's own data, which no version owns ──────────────────────
 *
 * An install tree is content addressed: every update lands in a NEW
 * installed/<root>/ and a rollback points back at an OLD one. So the place
 * for what the USER made can live in neither tree — an update would leave
 * it behind with the version it replaced, and a rollback would resurrect
 * whatever stale copy the older tree happened to carry. The package gets
 * ONE directory keyed on its identity rather than on any root, and install,
 * update and rollback all leave it alone.
 *
 * The claim is three moments of one journey, so it is three functions over
 * one struct rather than three stretches of the transcript: the directory
 * exists at install, the update does not disturb it, and neither does going
 * back. */
struct za_user_data {
    char dir[4600];
    char file[4700];
    uint8_t sha_a[32]; /* what version A wrote */
    uint8_t sha_b[32]; /* what version B wrote over it */
    bool wrote_a;
    bool wrote_b;
};

static int za_user_data_after_install(const char *base, const char *zcode,
                                      struct za_user_data *u)
{
    int failures = 0;
    memset(u, 0, sizeof(*u));
    snprintf(u->dir, sizeof(u->dir), "%s/data/alice/ringbuffer", zcode);
    ZA_CHECK("installing a package creates its persistent data directory",
             za_exists(u->dir));
    /* A person has to be able to FIND it, so the service names it rather
     * than leaving the layout to be guessed at. */
    char reported[PACKAGE_LIFECYCLE_DATA_DIR_MAX + 1u];
    struct zcl_result ddr =
        package_lifecycle_data_dir(base, "alice/ringbuffer", reported,
                                   sizeof(reported));
    ZA_CHECK("the service names the data directory a person should look in",
             ddr.ok && strcmp(reported, u->dir) == 0);
    /* The name is what keys the path, so a malformed name must be refused
     * before it becomes one. */
    char bad[PACKAGE_LIFECYCLE_DATA_DIR_MAX + 1u];
    struct zcl_result bad_ddr =
        package_lifecycle_data_dir(base, "notapublisherpackage", bad,
                                   sizeof(bad));
    ZA_CHECK("a name that is not publisher/package never becomes a data path",
             !bad_ddr.ok && bad[0] == '\0');

    snprintf(u->file, sizeof(u->file), "%s/notes.txt", u->dir);
    const char note_a[] = "note written while running version A\n";
    u->wrote_a = za_exists(u->dir) &&
                 za_write_file(u->file, note_a, sizeof(note_a) - 1u, 0600) &&
                 za_file_sha3(u->file, u->sha_a);
    ZA_CHECK("the running version can persist data the user made",
             u->wrote_a);
    return failures;
}

static int za_user_data_after_update(struct za_user_data *u)
{
    int failures = 0;
    /* An UPDATE must not carry the user's data off with the version it
     * replaced: these are the SAME bytes in the same place, not a copy
     * migrated into the new tree. */
    uint8_t updated[32];
    bool readable = za_exists(u->file) && za_file_sha3(u->file, updated);
    ZA_CHECK("the update leaves the user's data byte-identical",
             u->wrote_a && readable &&
                 memcmp(updated, u->sha_a, 32) == 0);

    /* The user keeps working under the NEW version, so what has to survive
     * going back is the data version B wrote — not a snapshot taken before
     * the update, which would make the claim trivial. */
    const char note_b[] = "note rewritten while running version B\n";
    u->wrote_b = za_write_file(u->file, note_b, sizeof(note_b) - 1u, 0600) &&
                 za_file_sha3(u->file, u->sha_b);
    ZA_CHECK("the user mutates persistent data under the new version",
             u->wrote_b && memcmp(u->sha_b, u->sha_a, 32) != 0);
    return failures;
}

static int za_user_data_after_rollback(const struct za_user_data *u)
{
    int failures = 0;
    /* THE WHOLE CLAIM OF GOING BACK: the code is byte-exactly version A
     * again AND the user's CURRENT data — everything version B wrote — is
     * still there, untouched. A rollback that restores old code by
     * reverting the user's own work has not gone back, it has lost data. */
    uint8_t after[32];
    bool survived = za_exists(u->file) && za_file_sha3(u->file, after);
    ZA_CHECK("the persistent data directory is untouched by the rollback",
             za_exists(u->dir) && survived);
    ZA_CHECK("the user's CURRENT data survives going back to version A",
             u->wrote_b && survived && memcmp(after, u->sha_b, 32) == 0);
    return failures;
}

/* ── 3. end-to-end over a fixture datadir ───────────────────────────── */

struct za_file {
    const char *path;
    const char *content;
};

/* Publish one package (manifest + CAS chunks + recipe + signed release)
 * into <datadir>/zcode. `deps_json` is the package's own
 * zcode-package.json, or NULL for a package with no dependencies. */
/* `program_path` (nullable) declares one `app/<stem>.c` recipe PROGRAM, the
 * translation unit the verifier links into the install output bin/<stem>.
 * NULL keeps the library-only, recipe-schema-1 fixture unchanged. */
static bool za_publish_ex(const char *zcode, const char *name,
                          const char *semver, uint64_t sequence,
                          const struct za_file *files, size_t file_count,
                          const char *header_path, const char *source_path,
                          const char *test_path, const char *include_dir,
                          const char *program_path, uint8_t root_out[32])
{
    char dir[4400];
    const char *subs[] = { "manifests", "releases", "recipes", "cas/sha3" };
    for (size_t i = 0; i < 4; i++) {
        snprintf(dir, sizeof(dir), "%s/%s", zcode, subs[i]);
        if (!za_mkdir_p(dir))
            return false;
    }

    struct vcs_package_manifest m;
    vcs_package_manifest_init(&m);
    bool ok = true;
    for (size_t i = 0; i < file_count && ok; i++) {
        size_t len = strlen(files[i].content);
        uint8_t hash[32];
        struct sha3_256_ctx c;
        sha3_256_init(&c);
        sha3_256_write(&c, (const uint8_t *)files[i].content, len);
        sha3_256_finalize(&c, hash);
        ok = vcs_package_manifest_add(&m, files[i].path,
                                      VCS_PACKAGE_MODE_FILE, len, hash, 1);
        if (ok) {
            char hex[65];
            za_hex(hash, 32, hex);
            char cdir[4400];
            char cpath[4500];
            snprintf(cdir, sizeof(cdir), "%s/cas/sha3/%.2s", zcode, hex);
            snprintf(cpath, sizeof(cpath), "%s/%s", cdir, hex);
            ok = za_mkdir_p(cdir) &&
                 za_write_file(cpath, files[i].content, len, 0600);
        }
    }
    if (ok)
        ok = vcs_package_manifest_root(&m, root_out);
    uint8_t *mwire = NULL;
    size_t mlen = 0;
    if (ok)
        ok = vcs_package_manifest_serialize(&m, &mwire, &mlen);
    vcs_package_manifest_free(&m);
    if (!ok)
        return false;
    char root_hex[65];
    za_hex(root_out, 32, root_hex);
    char path[4500];
    snprintf(path, sizeof(path), "%s/manifests/%s", zcode, root_hex);
    ok = za_write_file(path, mwire, mlen, 0600);
    free(mwire);
    if (!ok)
        return false;

    struct vcs_package_recipe r;
    vcs_package_recipe_init(&r);
    ok = vcs_package_recipe_add_header(&r, header_path, NULL);
    for (size_t i = 0; i < file_count && ok; i++) {
        size_t path_len = strlen(files[i].path);
        if (strcmp(files[i].path, header_path) != 0 && path_len > 2u &&
            strcmp(files[i].path + path_len - 2u, ".h") == 0)
            ok = vcs_package_recipe_add_header(&r, files[i].path, NULL);
    }
    ok = ok &&
         vcs_package_recipe_add_source(&r, source_path, NULL) &&
         vcs_package_recipe_add_test_source(&r, test_path, NULL) &&
         vcs_package_recipe_add_include_dir(&r, include_dir, NULL) &&
         vcs_package_recipe_add_library(&r, VCS_PACKAGE_RECIPE_LIB_LIBC,
                                        NULL) &&
         (!program_path ||
          vcs_package_recipe_add_program(&r, program_path, NULL));
    vcs_package_recipe_set_test_limits(&r, 0, 60,
                                       UINT64_C(64) * 1024u * 1024u);
    uint8_t recipe_root[32];
    uint8_t *rwire = NULL;
    size_t rlen = 0;
    if (ok)
        ok = vcs_package_recipe_root(&r, recipe_root) ==
                 VCS_PACKAGE_RECIPE_OK &&
             vcs_package_recipe_serialize(&r, &rwire, &rlen) ==
                 VCS_PACKAGE_RECIPE_OK;
    vcs_package_recipe_free(&r);
    if (!ok)
        return false;
    char rhex[65];
    za_hex(recipe_root, 32, rhex);
    snprintf(path, sizeof(path), "%s/recipes/%s", zcode, rhex);
    ok = za_write_file(path, rwire, rlen, 0600);
    free(rwire);
    if (!ok)
        return false;

    struct privkey sk;
    struct pubkey pk;
    memset(sk.vch, 0x11, 32);
    sk.fValid = true;
    sk.fCompressed = true;
    if (!privkey_get_pubkey(&sk, &pk))
        return false;
    struct vcs_package_release rel;
    memset(&rel, 0, sizeof(rel));
    rel.schema_version = VCS_PACKAGE_RELEASE_VERSION;
    snprintf(rel.name, sizeof(rel.name), "%s", name);
    snprintf(rel.semver, sizeof(rel.semver), "%s", semver);
    memcpy(rel.package_root, root_out, 32);
    memcpy(rel.publisher_pubkey, pk.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    rel.publisher_sequence = sequence;
    snprintf(rel.reward_address, sizeof(rel.reward_address), "t1fixture");
    snprintf(rel.license, sizeof(rel.license), "MIT");
    memcpy(rel.recipe_root, recipe_root, 32);
    snprintf(rel.chain_id, sizeof(rel.chain_id), "zclassic-main");
    uint8_t id[VCS_PACKAGE_RELEASE_ID_BYTES];
    if (vcs_package_release_id(&rel, id) != VCS_PACKAGE_RELEASE_OK)
        return false;
    struct uint256 h;
    memcpy(h.data, id, 32);
    unsigned char compact[COMPACT_SIGNATURE_SIZE];
    if (!privkey_sign_compact(&sk, &h, compact))
        return false;
    memcpy(rel.signature, compact + 1, VCS_PACKAGE_RELEASE_SIGNATURE_BYTES);
    uint8_t *relwire = NULL;
    size_t rellen = 0;
    if (vcs_package_release_serialize(&rel, &relwire, &rellen) !=
        VCS_PACKAGE_RELEASE_OK)
        return false;
    char id_hex[65];
    za_hex(id, 32, id_hex);
    snprintf(path, sizeof(path), "%s/releases/%s", zcode, id_hex);
    ok = za_write_file(path, relwire, rellen, 0600);
    free(relwire);
    return ok;
}

/* The library-only fixture: no program, recipe schema 1. */
static bool za_publish(const char *zcode, const char *name,
                       const char *semver, uint64_t sequence,
                       const struct za_file *files, size_t file_count,
                       const char *header_path, const char *source_path,
                       const char *test_path, const char *include_dir,
                       uint8_t root_out[32])
{
    return za_publish_ex(zcode, name, semver, sequence, files, file_count,
                         header_path, source_path, test_path, include_dir,
                         NULL, root_out);
}

/* A minimal, real, permissively-licensed C library: a fixed-capacity ring
 * buffer, its public header, and a test that exercises it. */
#define ZA_RING_H \
    "#pragma once\n" \
    "#include <stddef.h>\n" \
    "#include <stdbool.h>\n" \
    "struct ring { int slot[8]; size_t head, tail, used; };\n" \
    "void ring_init(struct ring *r);\n" \
    "bool ring_push(struct ring *r, int v);\n" \
    "bool ring_pop(struct ring *r, int *out);\n"

#define ZA_RING_C \
    "#include \"ring.h\"\n" \
    "void ring_init(struct ring *r){ r->head=r->tail=r->used=0; }\n" \
    "bool ring_push(struct ring *r, int v){ if(r->used==8) return false;\n" \
    "  r->slot[r->head]=v; r->head=(r->head+1)%8; r->used++; return true; }\n" \
    "bool ring_pop(struct ring *r, int *out){ if(!r->used) return false;\n" \
    "  *out=r->slot[r->tail]; r->tail=(r->tail+1)%8; r->used--; return true; }\n"

#define ZA_RING_TEST \
    "#include \"ring.h\"\n#include <stdio.h>\n" \
    "int main(void){ struct ring r; ring_init(&r); int v=0;\n" \
    "  if(!ring_push(&r,42)) return 1;\n" \
    "  if(!ring_pop(&r,&v) || v!=42) return 1;\n" \
    "  if(ring_pop(&r,&v)) return 1;\n" \
    "  printf(\"ring ok\\n\"); return 0; }\n"

#define ZA_STACK_H \
    "#pragma once\n" \
    "int stack_push(int value);\n"

#define ZA_STACK_C \
    "#include \"stack.h\"\n" \
    "int stack_push(int value){ return value + 1; }\n"

#define ZA_STACK_TEST \
    "#include \"stack.h\"\n" \
    "int main(void){ return stack_push(1) == 2 ? 0 : 1; }\n"

#define ZA_LICENSE "MIT License\n\nPermission is hereby granted...\n"

/* Overwrite one CAS object with different bytes of the same length: the
 * store now holds content that does not match the manifest's commitment. */
/* Remove one CAS object: the bytes this node NEVER RECEIVED. Deliberately
 * beside za_tamper_chunk below, because the two model different failures
 * that must not collapse into one rule — bytes that never arrived (the
 * publisher is unreachable) versus bytes that arrived corrupted (the
 * publisher, or something between, is lying). Only content unique to one
 * package may be passed here: a chunk is keyed by its own hash, so two
 * packages shipping an identical file share one object. */
static bool za_remove_chunk(const char *zcode, const char *content)
{
    uint8_t hash[32];
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    sha3_256_write(&c, (const uint8_t *)content, strlen(content));
    sha3_256_finalize(&c, hash);
    char hex[65];
    za_hex(hash, 32, hex);
    char path[4500];
    snprintf(path, sizeof(path), "%s/cas/sha3/%.2s/%s", zcode, hex, hex);
    return unlink(path) == 0;
}

static bool za_tamper_chunk(const char *zcode, const char *content)
{
    uint8_t hash[32];
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    sha3_256_write(&c, (const uint8_t *)content, strlen(content));
    sha3_256_finalize(&c, hash);
    char hex[65];
    za_hex(hash, 32, hex);
    char path[4500];
    snprintf(path, sizeof(path), "%s/cas/sha3/%.2s/%s", zcode, hex, hex);
    size_t len = strlen(content);
    char *evil = malloc(len + 1u);
    if (!evil)
        return false;
    memcpy(evil, content, len + 1u);
    /* Same byte count, different bytes — a length check would miss this. */
    evil[len / 2u] = (char)(evil[len / 2u] ^ 0x01);
    bool ok = za_write_file(path, evil, len, 0600);
    free(evil);
    return ok;
}

static int t_installed_root_symlink(const char *base, const char *zcode,
                                    const char *installed_dir,
                                    int64_t now_unix)
{
    int failures = 0;
    struct package_lifecycle_plan_report plan;
    struct zcl_result planned = package_lifecycle_plan(
        base, "alice/ringbuffer", now_unix, &plan);
    char parent[4400], outside[4400], outside_abs[4400];
    char marker[4500], receipts[4400];
    snprintf(parent, sizeof(parent), "%s/installed", zcode);
    snprintf(outside, sizeof(outside), "%s/escaped-install", base);
    snprintf(marker, sizeof(marker), "%s/keep.txt", outside);
    snprintf(receipts, sizeof(receipts), "%s/receipts", zcode);
    bool ready = planned.ok && za_mkdir_p(parent) && za_mkdir_p(outside) &&
        za_write_file(marker, "keep", 4, 0600) &&
        test_abs_path(outside, outside_abs, sizeof(outside_abs)) &&
        symlink(outside_abs, installed_dir) == 0;
    struct package_lifecycle_commit_report commit = {0};
    struct zcl_result attempted = ready
        ? package_lifecycle_commit(base, plan.plan_id, now_unix + 1, &commit)
        : ZCL_ERR(-1, "installed root symlink fixture was not prepared");
    ZA_CHECK("install refuses a substituted root before filing its receipt",
             ready && !attempted.ok &&
                 strstr(attempted.message, "installed root") != NULL &&
                 za_exists(marker) && za_dir_entries(receipts) == 0);
    ZA_CHECK("installed root link fixture removed",
             ready && unlink(installed_dir) == 0);
    return failures;
}

static int t_addplans_parent_symlink(const char *base, const char *zcode,
                                     int64_t now_unix)
{
    int failures = 0;
    char parent[4400], outside[4400], outside_abs[4400];
    snprintf(parent, sizeof(parent), "%s/addplans", zcode);
    snprintf(outside, sizeof(outside), "%s/escaped-addplans", base);
    bool ready = za_mkdir_p(outside) &&
        test_abs_path(outside, outside_abs, sizeof(outside_abs)) &&
        symlink(outside_abs, parent) == 0;
    struct package_lifecycle_plan_report plan;
    struct zcl_result planned = package_lifecycle_plan(
        base, "alice/ringbuffer", now_unix, &plan);
    ZA_CHECK("planning refuses an addplans directory outside the store",
             ready && !planned.ok &&
                 strstr(planned.message, "plan") != NULL &&
                 za_dir_entries(outside) == 0);
    ZA_CHECK("addplans parent link fixture removed",
             ready && unlink(parent) == 0);
    return failures;
}

static int t_buildwork_parent_symlink(const char *base, const char *zcode,
                                      const char *installed_dir,
                                      const char *root_hex, int64_t now_unix)
{
    int failures = 0;
    struct package_lifecycle_plan_report plan;
    struct zcl_result planned = package_lifecycle_plan(
        base, "alice/ringbuffer", now_unix, &plan);
    char buildwork[4400], outside[4400], outside_abs[4400];
    char emit[4400], marker[4500];
    snprintf(buildwork, sizeof(buildwork), "%s/buildwork", zcode);
    snprintf(outside, sizeof(outside), "%s/escaped-buildwork", base);
    snprintf(emit, sizeof(emit), "%s/%s", outside, root_hex);
    snprintf(marker, sizeof(marker), "%s/keep.txt", emit);
    bool ready = planned.ok && za_mkdir_p(emit) &&
        za_write_file(marker, "keep", 4, 0600) &&
        test_abs_path(outside, outside_abs, sizeof(outside_abs)) &&
        symlink(outside_abs, buildwork) == 0;
    struct package_lifecycle_commit_report commit = {0};
    struct zcl_result attempted = ready
        ? package_lifecycle_commit(base, plan.plan_id, now_unix + 1, &commit)
        : ZCL_ERR(-1, "buildwork symlink fixture was not prepared");
    ZA_CHECK("install refuses linked buildwork before stale cleanup",
             ready && !attempted.ok &&
                 strstr(attempted.message, "buildwork") != NULL &&
                 za_exists(marker) && !za_exists(installed_dir));
    ZA_CHECK("buildwork parent link fixture removed",
             ready && unlink(buildwork) == 0);
    return failures;
}

static int t_receipt_parent_symlink(const char *base, const char *zcode,
                                    const char *installed_dir, int64_t now_unix)
{
    int failures = 0;
    struct package_lifecycle_plan_report plan;
    struct zcl_result planned = package_lifecycle_plan(
        base, "alice/ringbuffer", now_unix, &plan);
    char receipt_parent[4400], escaped_dir[4400], escaped_abs[4400];
    snprintf(receipt_parent, sizeof(receipt_parent), "%s/receipts", zcode);
    snprintf(escaped_dir, sizeof(escaped_dir), "%s/escaped-receipts", base);
    bool ready = planned.ok && za_mkdir_p(escaped_dir) &&
        test_abs_path(escaped_dir, escaped_abs, sizeof(escaped_abs)) &&
        symlink(escaped_abs, receipt_parent) == 0;
    struct package_lifecycle_commit_report commit = {0};
    struct zcl_result attempted = ready
        ? package_lifecycle_commit(base, plan.plan_id, now_unix + 1, &commit)
        : ZCL_ERR(-1, "receipt symlink fixture was not prepared");
    ZA_CHECK("install refuses a receipt parent linked outside the store",
             ready && !attempted.ok &&
                 strstr(attempted.message, "receipt") != NULL &&
                 za_dir_entries(escaped_dir) == 0 &&
                 !za_exists(installed_dir));
    ZA_CHECK("receipt parent link fixture removed",
             ready && unlink(receipt_parent) == 0);
    return failures;
}

// long-function-ok:one-lifecycle-transcript — this is a single ordered
// transcript (publish, plan, commit, upgrade, roll back, then the three
// refusals) against ONE fixture datadir; splitting it would either
// duplicate a slow real build or hide the ordering the assertions depend on.
static int t_e2e(void)
{
    int failures = 0;
    char base[4096];
    snprintf(base, sizeof(base), "test-tmp/za_e2e_%ld", (long)getpid());
    za_rm_rf(base);
    char zcode[4200];
    snprintf(zcode, sizeof(zcode), "%s/zcode", base);
    if (!za_mkdir_p(zcode)) {
        printf("  zcode_add: cannot create the fixture datadir... FAIL\n");
        return 1;
    }
    if (!za_exists("build/bin/zclassic23-package-verify-dev")) {
        printf("  zcode_add: build/bin/zclassic23-package-verify-dev missing "
               "(make dev-bin)... FAIL\n");
        za_rm_rf(base);
        return 1;
    }

    /* --- a package with no dependencies --------------------------------- */
    struct za_file ring_files[] = {
        { "LICENSE", ZA_LICENSE },
        { "src/ring.h", ZA_RING_H },
        { "src/noise.h", "int noise_only(void);\n" },
        { "src/ring.c", ZA_RING_C },
        { "test/test_ring.c", ZA_RING_TEST },
    };
    uint8_t ring_root[32];
    bool published = za_publish(zcode, "alice/ringbuffer", "1.0.0", 1,
                                ring_files, 5, "src/ring.h", "src/ring.c",
                                "test/test_ring.c", "src", ring_root);
    ZA_CHECK("fixture package published into the local store", published);
    if (!published) {
        za_rm_rf(base);
        return failures;
    }

    const int64_t t0 = 1700000000;
    failures += t_addplans_parent_symlink(base, zcode, t0);
    struct package_lifecycle_plan_report plan;
    struct zcl_result r =
        package_lifecycle_plan(base, "alice/ringbuffer", t0, &plan);
    ZA_CHECK("add plan resolves a NAME to one verified, ready step",
             r.ok && plan.ready && plan.plan.step_count == 1 &&
                 plan.plan.steps[0].state == VCS_PACKAGE_LIFECYCLE_VERIFIED &&
                 memcmp(plan.plan.target_root, ring_root, 32) == 0);

    /* An expired plan must refuse BEFORE anything is built or installed. */
    struct package_lifecycle_commit_report late;
    struct zcl_result lr = package_lifecycle_commit(
        base, plan.plan_id, t0 + VCS_PACKAGE_PLAN_TTL_SECONDS + 1, &late);
    char installed_dir[4400];
    char root_hex[65];
    za_hex(ring_root, 32, root_hex);
    snprintf(installed_dir, sizeof(installed_dir), "%s/installed/%s", zcode,
             root_hex);
    ZA_CHECK("an expired plan_id is refused and installs nothing",
             !lr.ok && strcmp(late.rule, "plan-expired") == 0 &&
                 !za_exists(installed_dir));

    /* A hand-edited plan file no longer hashes to its own id. */
    char plan_path[4500];
    char plan_hex[65];
    za_hex(plan.plan_id, 32, plan_hex);
    snprintf(plan_path, sizeof(plan_path), "%s/addplans/%s", zcode, plan_hex);
    bool edited = false;
    {
        FILE *f = fopen(plan_path, "r+b");
        if (f) {
            /* Push the expiry out by touching the wire, the exact edit an
             * attacker would want: keep the id, extend the authorization. */
            if (fseek(f, 74, SEEK_SET) == 0) {
                int c = fgetc(f);
                if (c != EOF && fseek(f, 74, SEEK_SET) == 0)
                    edited = fputc(c ^ 0x40, f) != EOF;
            }
            fclose(f);
        }
    }
    struct package_lifecycle_commit_report tampered;
    struct zcl_result tr =
        package_lifecycle_commit(base, plan.plan_id, t0 + 1, &tampered);
    ZA_CHECK("an edited plan file is refused (the id commits every field)",
             edited && !tr.ok &&
                 (strcmp(tampered.rule, "plan-tampered") == 0 ||
                  strcmp(tampered.rule, "plan-invalid") == 0) &&
                 !za_exists(installed_dir));

    failures += t_installed_root_symlink(base, zcode, installed_dir, t0);
    failures += t_buildwork_parent_symlink(base, zcode, installed_dir,
                                           root_hex, t0);
    failures += t_receipt_parent_symlink(base, zcode, installed_dir, t0);

    /* Re-plan after the blocked attempt and commit for real. */
    r = package_lifecycle_plan(base, "alice/ringbuffer", t0, &plan);
    struct package_lifecycle_commit_report commit;
    struct zcl_result cr =
        package_lifecycle_commit(base, plan.plan_id, t0 + 1, &commit);
    if (!cr.ok)
        printf("  zcode_add: commit failed rule=%s detail=%s msg=%s\n",
               commit.rule, commit.detail, cr.message);
    ZA_CHECK("add commit installs the package", r.ok && cr.ok &&
                                                    commit.installed);

    char archive[4600];
    char header[4600];
    snprintf(archive, sizeof(archive), "%s/lib/libringbuffer.a",
             installed_dir);
    snprintf(header, sizeof(header), "%s/include/ring.h", installed_dir);
    ZA_CHECK("a static archive and the public header land under "
             "installed/<root>/",
             za_exists(installed_dir) && za_exists(archive) &&
                 za_exists(header));
    char receipt[4600];
    snprintf(receipt, sizeof(receipt), "%s/build-report", installed_dir);
    ZA_CHECK("the reproducible build receipt travels with the install",
             za_exists(receipt));

    /* Fingerprint version A's artifacts NOW, while A is the version the
     * user is running. The rollback below has to land back on exactly these
     * bytes — "a working build of roughly the old thing" is not the
     * property being claimed. */
    uint8_t a_archive_sha[32], a_header_sha[32];
    bool a_fingerprinted = za_file_sha3(archive, a_archive_sha) &&
                           za_file_sha3(header, a_header_sha);
    ZA_CHECK("version A's installed artifacts are fingerprinted",
             a_fingerprinted);

    /* The user-data thread lives in its own three functions below, so the
     * transcript gains the claims without gaining their branches. */
    struct za_user_data user_data;
    failures += za_user_data_after_install(base, zcode, &user_data);
    ZA_CHECK("the step reached PINNED (seedable) or names why not",
             commit.step_count == 1 &&
                 (commit.steps[0].state == VCS_PACKAGE_LIFECYCLE_PINNED ||
                  commit.steps[0].rule[0] != '\0'));
    ZA_CHECK("the install carries a build receipt id",
             commit.steps[0].has_receipt);
    struct package_lifecycle_step reuse_inspection;
    bool reuse_installed = false;
    struct zcl_result reuse_inspected =
        package_lifecycle_installed_inspect(
            base, ring_root, &reuse_inspection, &reuse_installed);
    ZA_CHECK("reuse inspection accepts only the receipt-verified install",
             reuse_inspected.ok && reuse_installed &&
                 reuse_inspection.already_installed &&
                 reuse_inspection.has_receipt &&
                 memcmp(reuse_inspection.root, ring_root, 32) == 0);

    char workspace[4200], workspace_path[4400];
    snprintf(workspace, sizeof(workspace), "%s/workspace", base);
    snprintf(workspace_path, sizeof(workspace_path), "%s/include", workspace);
    bool workspace_ready = za_mkdir_p(workspace_path);
    snprintf(workspace_path, sizeof(workspace_path), "%s/src", workspace);
    workspace_ready = workspace_ready && za_mkdir_p(workspace_path);
    snprintf(workspace_path, sizeof(workspace_path), "%s/tests", workspace);
    workspace_ready = workspace_ready && za_mkdir_p(workspace_path);
    snprintf(workspace_path, sizeof(workspace_path), "%s/LICENSE", workspace);
    workspace_ready = workspace_ready &&
        za_write_file(workspace_path, ZA_LICENSE, strlen(ZA_LICENSE), 0600);
    static const char harness_header[] = "int harness(void);\n";
    static const char harness_source[] = "int harness(void){return 1;}\n";
    static const char harness_test[] = "int main(void){return 0;}\n";
    static const char harness_meta[] =
        "{\"schema\":1,\"name\":\"fixture/harness\","
        "\"semver\":\"0.1.0\",\"language\":\"c23\","
        "\"license\":\"MIT\",\"include_dir\":\"include\","
        "\"source_dir\":\"src\",\"dependencies\":[]}\n";
    snprintf(workspace_path, sizeof(workspace_path), "%s/include/harness.h",
             workspace);
    workspace_ready = workspace_ready && za_write_file(
        workspace_path, harness_header, strlen(harness_header), 0600);
    snprintf(workspace_path, sizeof(workspace_path), "%s/src/harness.c",
             workspace);
    workspace_ready = workspace_ready && za_write_file(
        workspace_path, harness_source, strlen(harness_source), 0600);
    snprintf(workspace_path, sizeof(workspace_path), "%s/tests/test.c",
             workspace);
    workspace_ready = workspace_ready && za_write_file(
        workspace_path, harness_test, strlen(harness_test), 0600);
    snprintf(workspace_path, sizeof(workspace_path), "%s/zcode-package.json",
             workspace);
    workspace_ready = workspace_ready && za_write_file(
        workspace_path, harness_meta, strlen(harness_meta), 0600);
    struct json_value work_input;
    json_init(&work_input); json_set_object(&work_input);
    bool input_ready = workspace_ready &&
        json_push_kv_str(&work_input, "workspace", workspace) &&
        json_push_kv_str(&work_input, "goal",
                         "use alice/ringbuffer@1.0.0") &&
        json_push_kv_str(&work_input, "profile", "quick") &&
        json_push_kv_str(&work_input, "datadir", base);
    struct zcl_command_request work_request = {.input = &work_input};
    struct zcl_command_reply work_reply;
    zcl_command_reply_init(&work_reply, "zcl.zcode_reuse_e2e.v1");
    if (input_ready)
        zcl_native_handle_zcode_work_start(&work_request, &work_reply);
    const struct json_value *reuse_plan =
        json_get(&work_reply.data, "reuse_plan");
    const struct json_value *reused = reuse_plan
        ? json_get(reuse_plan, "reused") : NULL;
    const struct json_value *selected = reused ? json_at(reused, 0) : NULL;
    const struct json_value *apis = selected ? json_get(selected, "apis") : NULL;
    bool saw_ring_symbol = false;
    for (size_t i = 0; apis && i < apis->num_children; i++) {
        const struct json_value *api = json_at(apis, i);
        if (api && api->type == JSON_STR &&
            strcmp(json_get_str(api), "ring_push") == 0)
            saw_ring_symbol = true;
    }
    snprintf(workspace_path, sizeof(workspace_path), "%s/.zvcs", workspace);
    struct json_value reuse_next_input;
    json_init(&reuse_next_input);
    bool reuse_next_ok = work_reply.next_count == 1 &&
        json_read(&reuse_next_input, work_reply.next[0].input_json,
                  strlen(work_reply.next[0].input_json)) &&
        reuse_next_input.type == JSON_OBJ &&
        reuse_next_input.num_children == 2 &&
        strcmp(json_get_str(json_get(&reuse_next_input, "name_or_root")),
               root_hex) == 0 &&
        strcmp(json_get_str(json_get(&reuse_next_input, "datadir")),
               base) == 0;
    const struct zcl_command_spec *reuse_next_spec =
        zcl_command_registry_find(zcl_command_catalog(), "zcode.use", NULL);
    char reuse_next_why[160] = {0};
    reuse_next_ok = reuse_next_ok && reuse_next_spec &&
        zcl_command_registry_input_validate(
            reuse_next_spec, &reuse_next_input, reuse_next_why,
            sizeof(reuse_next_why));
    ZA_CHECK("work start reuses exact installed APIs and creates zero task",
             input_ready &&
                 work_reply.status == ZCL_COMMAND_STATUS_PASSED &&
                 strcmp(json_get_str(json_get(&work_reply.data, "state")),
                        "REUSE_READY") == 0 &&
                 strcmp(json_get_str(json_get(&work_reply.data, "work_id")),
                        "") == 0 &&
                 reuse_plan && !json_get_bool(json_get(
                     reuse_plan, "new_code_required")) &&
                 selected && json_get_bool(json_get(selected, "installed")) &&
                 saw_ring_symbol && !za_exists(workspace_path) &&
                 reuse_next_ok &&
                 strcmp(work_reply.next[0].command, "zcode.use") == 0 &&
                 strstr(work_reply.next[0].input_json, root_hex) != NULL);
    json_free(&reuse_next_input);
    zcl_command_reply_free(&work_reply);
    json_free(&work_input);

    struct za_file stack_files[] = {
        { "LICENSE", ZA_LICENSE },
        { "src/stack.h", ZA_STACK_H },
        { "src/stack.c", ZA_STACK_C },
        { "test/test_stack.c", ZA_STACK_TEST },
    };
    uint8_t stack_root[32];
    bool stack_published = za_publish(
        zcode, "alice/stack", "1.0.0", 3, stack_files, 4,
        "src/stack.h", "src/stack.c", "test/test_stack.c", "src",
        stack_root);
    char stack_root_hex[65];
    za_hex(stack_root, sizeof(stack_root), stack_root_hex);
    json_init(&work_input); json_set_object(&work_input);
    input_ready = stack_published &&
        json_push_kv_str(&work_input, "workspace", workspace) &&
        json_push_kv_str(&work_input, "goal",
                         "Make harness use alice/stack") &&
        json_push_kv_str(&work_input, "context_symbol", "harness") &&
        json_push_kv_str(&work_input, "profile", "quick") &&
        json_push_kv_str(&work_input, "datadir", base);
    work_request.input = &work_input;
    zcl_command_reply_init(&work_reply,
                           "zcl.zcode_reuse_preparation.v1");
    if (input_ready)
        zcl_native_handle_zcode_work_start(&work_request, &work_reply);
    const struct json_value *prepare_plan =
        json_get(&work_reply.data, "reuse_plan");
    const struct json_value *prepare_reused = prepare_plan
        ? json_get(prepare_plan, "reused") : NULL;
    const struct json_value *prepare_available = prepare_plan
        ? json_get(prepare_plan, "available_after_use") : NULL;
    struct json_value prepare_next_input;
    json_init(&prepare_next_input);
    bool prepare_next_ok = work_reply.next_count == 1 &&
        json_read(&prepare_next_input, work_reply.next[0].input_json,
                  strlen(work_reply.next[0].input_json));
    const struct zcl_command_spec *prepare_next_spec =
        zcl_command_registry_find(zcl_command_catalog(), "zcode.use", NULL);
    char prepare_next_why[160] = {0};
    prepare_next_ok = prepare_next_ok && prepare_next_spec &&
        zcl_command_registry_input_validate(
            prepare_next_spec, &prepare_next_input, prepare_next_why,
            sizeof(prepare_next_why));
    snprintf(workspace_path, sizeof(workspace_path), "%s/.zvcs", workspace);
    ZA_CHECK("known source is explicitly used before it can count as reuse",
             input_ready && work_reply.status == ZCL_COMMAND_STATUS_PASSED &&
                 strcmp(json_get_str(json_get(&work_reply.data, "state")),
                        "REUSE_PREPARATION_REQUIRED") == 0 &&
                 prepare_reused && prepare_reused->num_children == 0 &&
                 prepare_available && prepare_available->num_children == 1 &&
                 prepare_next_ok &&
                 strcmp(work_reply.next[0].command, "zcode.use") == 0 &&
                 strcmp(json_get_str(json_get(
                            &prepare_next_input, "name_or_root")),
                        stack_root_hex) == 0 &&
                 strstr(work_reply.next[0].input_json, stack_root_hex) != NULL &&
                 !za_exists(workspace_path));
    struct zcl_command_request prepare_use_request = {
        .input = &prepare_next_input,
    };
    struct zcl_command_reply prepare_use_reply;
    zcl_command_reply_init(&prepare_use_reply,
                           "zcl.zcode_reuse_preparation_use.v1");
    if (prepare_next_ok)
        zcl_native_handle_zcode_use(&prepare_use_request, &prepare_use_reply);
    ZA_CHECK("the suggested action reaches the existing exact use plan",
             prepare_next_ok &&
                 prepare_use_reply.status == ZCL_COMMAND_STATUS_PASSED &&
                 json_get_bool(json_get(&prepare_use_reply.data, "ready")) &&
                 strcmp(json_get_str(json_get(
                            &prepare_use_reply.data, "target_root")),
                        stack_root_hex) == 0);
    zcl_command_reply_free(&prepare_use_reply);
    json_free(&prepare_next_input);
    zcl_command_reply_free(&work_reply);
    json_free(&work_input);

    bool dependency_workspace_ready = workspace_ready;
    json_init(&work_input); json_set_object(&work_input);
    input_ready = dependency_workspace_ready &&
        json_push_kv_str(&work_input, "workspace", workspace) &&
        json_push_kv_str(&work_input, "goal",
                         "Make harness call ring_push") &&
        json_push_kv_str(&work_input, "context_symbol", "harness") &&
        json_push_kv_str(&work_input, "profile", "quick") &&
        json_push_kv_str(&work_input, "datadir", base);
    work_request.input = &work_input;
    zcl_command_reply_init(&work_reply, "zcl.zcode_locked_context_start.v1");
    if (input_ready)
        zcl_native_handle_zcode_work_start(&work_request, &work_reply);
    const struct json_value *locked_work_id =
        json_get(&work_reply.data, "work_id");
    char locked_work_id_text[40] = {0};
    if (locked_work_id && locked_work_id->type == JSON_STR)
        snprintf(locked_work_id_text, sizeof(locked_work_id_text), "%s",
                 json_get_str(locked_work_id));
    const struct json_value *partial_reuse_plan =
        json_get(&work_reply.data, "reuse_plan");
    const struct json_value *partial_reused = partial_reuse_plan
        ? json_get(partial_reuse_plan, "reused") : NULL;
    const struct json_value *partial_selected = partial_reused
        ? json_at(partial_reused, 0) : NULL;
    const char *partial_composition = partial_selected
        ? json_get_str(json_get(partial_selected, "composition")) : NULL;
    snprintf(workspace_path, sizeof(workspace_path), "%s/zcode-package.json",
             workspace);
    struct json_value authoritative_metadata;
    bool authoritative_metadata_read = za_read_json_file(
        workspace_path, &authoritative_metadata);
    const struct json_value *authoritative_dependencies =
        authoritative_metadata_read
            ? json_get(&authoritative_metadata, "dependencies") : NULL;
    ZA_CHECK("a partial reuse goal enters the existing bounded work lifecycle",
             input_ready && work_reply.status == ZCL_COMMAND_STATUS_PASSED &&
                 strcmp(json_get_str(json_get(&work_reply.data, "state")),
                        "AWAITING_CANDIDATE") == 0 &&
                 partial_composition &&
                 strcmp(partial_composition, "candidate_only") == 0 &&
                 authoritative_dependencies &&
                 authoritative_dependencies->num_children == 0 &&
                 strncmp(locked_work_id_text, "work-", 5) == 0);
    if (authoritative_metadata_read) json_free(&authoritative_metadata);
    zcl_command_reply_free(&work_reply);
    json_free(&work_input);

    json_init(&work_input); json_set_object(&work_input);
    input_ready = locked_work_id_text[0] &&
        json_push_kv_str(&work_input, "workspace", workspace) &&
        json_push_kv_str(&work_input, "work", locked_work_id_text) &&
        json_push_kv_str(&work_input, "adapter", "manual") &&
        json_push_kv_str(&work_input, "datadir", base);
    work_request.input = &work_input;
    zcl_command_reply_init(&work_reply, "zcl.zcode_locked_context_run.v1");
    if (input_ready)
        zcl_native_handle_zcode_work_run(&work_request, &work_reply);
    const struct json_value *adapter_packet =
        json_get(&work_reply.data, "adapter_packet_path");
    const struct json_value *candidate_workspace =
        json_get(&work_reply.data, "candidate_workspace");
    struct json_value packet_json;
    bool packet_read = adapter_packet && adapter_packet->type == JSON_STR &&
        za_read_json_file(json_get_str(adapter_packet), &packet_json);
    const struct json_value *locked_dependencies = packet_read
        ? json_get(&packet_json, "locked_dependencies") : NULL;
    const struct json_value *dependency_context = packet_read
        ? json_get(&packet_json, "selected_dependency_context") : NULL;
    const struct json_value *ring_context = dependency_context
        ? json_at(dependency_context, 0) : NULL;
    const struct json_value *ring_headers = ring_context
        ? json_get(ring_context, "headers") : NULL;
    const struct json_value *ring_header = ring_headers
        ? json_at(ring_headers, 0) : NULL;
    const struct json_value *ring_content = ring_header
        ? json_get(ring_header, "content") : NULL;
    char candidate_metadata_path[4500] = {0};
    struct json_value candidate_metadata;
    bool candidate_metadata_read = candidate_workspace &&
        snprintf(candidate_metadata_path, sizeof(candidate_metadata_path),
                 "%s/zcode-package.json",
                 json_get_str(candidate_workspace)) > 0 &&
        za_read_json_file(candidate_metadata_path, &candidate_metadata);
    const struct json_value *candidate_dependencies = candidate_metadata_read
        ? json_get(&candidate_metadata, "dependencies") : NULL;
    const struct json_value *candidate_dependency = candidate_dependencies
        ? json_at(candidate_dependencies, 0) : NULL;
    const struct json_value *ring_apis = ring_context
        ? json_get(ring_context, "apis") : NULL;
    bool saw_selected_ring_api = false;
    bool saw_unrelated_noise_api = false;
    for (size_t i = 0; ring_apis && i < ring_apis->num_children; i++) {
        const char *api = json_get_str(json_at(ring_apis, i));
        if (api && strcmp(api, "ring_push") == 0)
            saw_selected_ring_api = true;
        if (api && strcmp(api, "noise_only") == 0)
            saw_unrelated_noise_api = true;
    }
    ZA_CHECK("the model packet contains only lock-bound receipt-verified C23 APIs",
             input_ready &&
                 work_reply.status == ZCL_COMMAND_STATUS_PASSED &&
                 locked_dependencies && locked_dependencies->num_children == 1 &&
                 dependency_context && dependency_context->num_children == 1 &&
                 json_get_bool(json_get(
                     &work_reply.data,
                     "candidate_dependency_metadata_changed")) &&
                 candidate_dependency &&
                 strcmp(json_get_str(json_get(candidate_dependency, "root")),
                        root_hex) == 0 &&
                 ring_context &&
                 strcmp(json_get_str(json_get(ring_context, "package_root")),
                        root_hex) == 0 &&
                 ring_headers && ring_headers->num_children == 1 &&
                 ring_content && strstr(json_get_str(ring_content),
                                        "ring_push") != NULL &&
                 strstr(json_get_str(ring_content), "noise_only") == NULL &&
                 saw_selected_ring_api && !saw_unrelated_noise_api &&
                 json_get_int(json_get(ring_header, "bytes")) > 0 &&
                 json_get(ring_header, "content_root") == NULL &&
                 json_get(&packet_json, "dependency_context_bytes") == NULL);
    if (candidate_metadata_read) json_free(&candidate_metadata);
    if (packet_read) json_free(&packet_json);
    zcl_command_reply_free(&work_reply);
    json_free(&work_input);

    json_init(&work_input); json_set_object(&work_input);
    input_ready = locked_work_id_text[0] &&
        json_push_kv_str(&work_input, "workspace", workspace) &&
        json_push_kv_str(&work_input, "work", locked_work_id_text) &&
        json_push_kv_str(&work_input, "adapter", "manual") &&
        json_push_kv_str(&work_input, "datadir", base);
    work_request.input = &work_input;
    zcl_command_reply_init(&work_reply,
                           "zcl.zcode_composition_not_behavior.v1");
    if (input_ready)
        zcl_native_handle_zcode_work_run(&work_request, &work_reply);
    ZA_CHECK("candidate-only dependency composition is not admitted as behavior",
             input_ready &&
                 work_reply.status == ZCL_COMMAND_STATUS_PASSED &&
                 strcmp(json_get_str(json_get(&work_reply.data, "state")),
                        "AWAITING_CANDIDATE") == 0 &&
                 !json_get_bool(json_get(
                     &work_reply.data,
                     "candidate_dependency_metadata_changed")));
    zcl_command_reply_free(&work_reply);
    json_free(&work_input);

    bool header_damaged = za_write_file(header, "corrupt\n", 8, 0600);
    json_init(&work_input); json_set_object(&work_input);
    input_ready = header_damaged && locked_work_id_text[0] &&
        json_push_kv_str(&work_input, "workspace", workspace) &&
        json_push_kv_str(&work_input, "work", locked_work_id_text) &&
        json_push_kv_str(&work_input, "adapter", "manual") &&
        json_push_kv_str(&work_input, "datadir", base);
    work_request.input = &work_input;
    zcl_command_reply_init(&work_reply, "zcl.zcode_locked_context_tamper.v1");
    if (input_ready)
        zcl_native_handle_zcode_work_run(&work_request, &work_reply);
    ZA_CHECK("changed installed header bytes are refused before model execution",
             input_ready &&
                 work_reply.status == ZCL_COMMAND_STATUS_FAILED &&
                 strcmp(work_reply.error.code, "MODEL_CONTEXT_REFUSED") == 0);
    zcl_command_reply_free(&work_reply);
    json_free(&work_input);
    ZA_CHECK("the exact verified fixture header is restored",
             za_write_file(header, ZA_RING_H, strlen(ZA_RING_H), 0600));

    uint8_t ring_receipt[32];
    memcpy(ring_receipt, commit.steps[0].receipt_id, sizeof(ring_receipt));
    struct vcs_package_build_receipt inspected_receipt;
    struct zcl_result inspected = package_lifecycle_receipt_read(
        base, ring_receipt, &inspected_receipt);
    ZA_CHECK("the filed receipt is readable only through its rederived exact id",
             inspected.ok &&
                 memcmp(inspected_receipt.package_root, ring_root, 32) == 0 &&
                 inspected_receipt.test_ran &&
                 inspected_receipt.result_class ==
                     VCS_PACKAGE_BUILD_RESULT_TEST_PASS);
    ZA_CHECK("a newly built package does not claim receipt reuse",
             !commit.steps[0].receipt_reused);

    uint8_t active[32];
    size_t gens = 0;
    bool present = false;
    struct zcl_result ar =
        package_lifecycle_active(base, "alice/ringbuffer", active, &gens,
                                 &present);
    ZA_CHECK("the installed root is the active generation",
             ar.ok && present && gens == 1 &&
                 memcmp(active, ring_root, 32) == 0);

    /* Exact identity is the cache key: reopening an installed root must
     * revalidate its receipt and outputs, then reuse that exact evidence
     * without rebuilding or appending a fake generation. */
    struct package_lifecycle_plan_report repeat_plan;
    struct zcl_result repeat_planned =
        package_lifecycle_plan(base, root_hex, t0 + 2, &repeat_plan);
    struct package_lifecycle_commit_report repeat_commit;
    struct zcl_result repeat_committed = package_lifecycle_commit(
        base, repeat_plan.plan_id, t0 + 3, &repeat_commit);
    ar = package_lifecycle_active(base, "alice/ringbuffer", active, &gens,
                                  &present);
    ZA_CHECK("an exact installed root reuses its verified build evidence",
             repeat_planned.ok && repeat_committed.ok &&
                 repeat_commit.step_count == 1 &&
                 repeat_commit.steps[0].already_installed &&
                 repeat_commit.steps[0].has_receipt &&
                 repeat_commit.steps[0].receipt_reused &&
                 memcmp(repeat_commit.steps[0].receipt_id, ring_receipt, 32) ==
                     0);
    ZA_CHECK("exact reuse does not append a generation",
             ar.ok && present && gens == 1 &&
                 memcmp(active, ring_root, 32) == 0);

    /* --- the installed node reproduces its own install build ------------
     * A standard-profile rebuild of the same committed inputs must emit
     * byte-identical outputs, hash to a DISTINCT receipt id, and file it —
     * which is exactly what the receipts scan needs to report reproduced.
     *
     * Both Linux seccomp/Landlock and macOS Seatbelt qualify as full package
     * isolation, so the complete reproduction/cache transcript is mandatory
     * on both native paths. */
    struct package_lifecycle_reproduce_report repro;
    struct zcl_result repr =
        package_lifecycle_reproduce(base, "alice/ringbuffer", NULL, &repro);
    if (!repr.ok)
        printf("  zcode_add: reproduce failed rule=%s detail=%s msg=%s\n",
               repro.rule, repro.detail, repr.message);
    ZA_CHECK("the standard-profile rebuild reproduces the install build",
             repr.ok && repro.matched && repro.filed &&
                 memcmp(repro.reference_receipt_id, ring_receipt, 32) == 0 &&
                 memcmp(repro.receipt_id, ring_receipt, 32) != 0);
    char repro_id_hex[65];
    za_hex(repro.receipt_id, 32, repro_id_hex);
    char repro_filed[4500];
    snprintf(repro_filed, sizeof(repro_filed), "%s/receipts/%s", zcode,
             repro_id_hex);
    ZA_CHECK("the second, distinct receipt is filed by its exact id",
             za_exists(repro_filed));
    char receipts_dir[4400];
    snprintf(receipts_dir, sizeof(receipts_dir), "%s/receipts", zcode);
    struct vcs_reproduce_report scan;
    bool scanned = vcs_package_reproduce_scan(receipts_dir, ring_root,
                                              inspected_receipt.recipe_root,
                                              &scan);
    ZA_CHECK("two distinct byte-identical receipts report reproduced",
             scanned && scan.reproduced && scan.matching == 2);

    /* The native command is idempotent: a re-run re-files the same
     * deterministic receipt and reports both ids. */
    struct json_value repro_input;
    json_init(&repro_input);
    json_set_object(&repro_input);
    bool repro_input_ready =
        json_push_kv_str(&repro_input, "name_or_root", "alice/ringbuffer") &&
        json_push_kv_str(&repro_input, "datadir", base);
    struct zcl_command_request repro_request = {
        .input = &repro_input,
    };
    struct zcl_command_reply repro_reply;
    zcl_command_reply_init(&repro_reply, "zcl.zcode_package_reproduce.v1");
    if (repro_input_ready)
        zcl_native_handle_zcode_package_reproduce(&repro_request,
                                                  &repro_reply);
    const char *repro_cmd_id = json_get_str(
        json_get(&repro_reply.data, "receipt_id"));
    ZA_CHECK("the reproduce command re-files the same receipt id",
             repro_input_ready &&
                 repro_reply.status == ZCL_COMMAND_STATUS_PASSED &&
                 json_get_bool(json_get(&repro_reply.data, "reproduced")) &&
                 repro_cmd_id &&
                 strcmp(repro_cmd_id, repro_id_hex) == 0);
    zcl_command_reply_free(&repro_reply);
    json_free(&repro_input);

    /* --- an optional fastobj cache rides along to the worker ------------
     * The confined worker is the cache's only writer: a directory that did
     * not exist before the run exists (with entries) after it only when
     * --fast-cache=<dir> actually reached the worker's argv. */
    char fast_dir[4600];
    snprintf(fast_dir, sizeof(fast_dir), "%s/fastobj-repro", base);
    struct package_lifecycle_reproduce_report fc_repro;
    struct zcl_result fcr = package_lifecycle_reproduce(
        base, "alice/ringbuffer", fast_dir, &fc_repro);
    if (!fcr.ok)
        printf("  zcode_add: fast-cache reproduce failed rule=%s detail=%s "
               "msg=%s\n",
               fc_repro.rule, fc_repro.detail, fcr.message);
    ZA_CHECK("a reproduce handed a fastobj cache still matches and re-files",
             fcr.ok && fc_repro.matched && fc_repro.filed &&
                 memcmp(fc_repro.receipt_id, repro.receipt_id, 32) == 0);
    ZA_CHECK("the cache directory was created and populated by the worker",
             fc_repro.fast_cache_used && za_exists(fast_dir) &&
                 za_dir_entries(fast_dir) > 0);
    ZA_CHECK("the cold cache reports its misses and its admission",
             fc_repro.fast_cache_misses > 0 && fc_repro.fast_cache_hits == 0 &&
                 strcmp(fc_repro.fast_cache_admission,
                        "local_candidate") == 0);

    /* The second run against the SAME populated cache is all hits — the
     * zero-compiler-spawn rebuild this seam exists for. */
    struct package_lifecycle_reproduce_report fc2_repro;
    struct zcl_result fc2r = package_lifecycle_reproduce(
        base, "alice/ringbuffer", fast_dir, &fc2_repro);
    ZA_CHECK("a re-run against the populated cache is all hits",
             fc2r.ok && fc2_repro.matched && fc2_repro.filed &&
                 fc2_repro.fast_cache_hits > 0 &&
                 fc2_repro.fast_cache_misses == 0 &&
                 memcmp(fc2_repro.receipt_id, repro.receipt_id, 32) == 0);

    /* The native command accepts the optional field and renders the cache
     * outcome in its reply (idempotently, against the same cache). */
    struct json_value fc_input;
    json_init(&fc_input);
    json_set_object(&fc_input);
    bool fc_input_ready =
        json_push_kv_str(&fc_input, "name_or_root", "alice/ringbuffer") &&
        json_push_kv_str(&fc_input, "datadir", base) &&
        json_push_kv_str(&fc_input, "fast_cache", fast_dir);
    struct zcl_command_request fc_request = {
        .input = &fc_input,
    };
    struct zcl_command_reply fc_reply;
    zcl_command_reply_init(&fc_reply, "zcl.zcode_package_reproduce.v1");
    if (fc_input_ready)
        zcl_native_handle_zcode_package_reproduce(&fc_request, &fc_reply);
    const struct json_value *fc_obj = json_get(&fc_reply.data, "fast_cache");
    const char *fc_admission =
        fc_obj ? json_get_str(json_get(fc_obj, "admission")) : NULL;
    ZA_CHECK("the reproduce command renders the cache outcome it was handed",
             fc_input_ready &&
                 fc_reply.status == ZCL_COMMAND_STATUS_PASSED &&
                 fc_obj &&
                 json_get_int(json_get(fc_obj, "hits")) > 0 &&
                 json_get_int(json_get(fc_obj, "misses")) == 0 &&
                 fc_admission &&
                 strcmp(fc_admission, "local_candidate") == 0);
    zcl_command_reply_free(&fc_reply);
    json_free(&fc_input);

    /* An empty-after-trim fast_cache is exactly the cold rebuild: the flag
     * must be omitted, not passed empty (an empty --fast-cache= makes the
     * worker refuse the run closed), so this succeeds and re-files. */
    struct package_lifecycle_reproduce_report blank_repro;
    struct zcl_result blankr = package_lifecycle_reproduce(
        base, "alice/ringbuffer", "", &blank_repro);
    ZA_CHECK("an empty fast_cache string is the cold rebuild",
             blankr.ok && blank_repro.matched && blank_repro.filed &&
                 !blank_repro.fast_cache_used &&
                 memcmp(blank_repro.receipt_id, repro.receipt_id, 32) == 0);
    /* --- a second version, then rollback -------------------------------- */
    struct za_file ring2_files[] = {
        { "LICENSE", ZA_LICENSE },
        { "src/ring.h", ZA_RING_H },
        { "src/ring.c", ZA_RING_C "/* v2 */\n" },
        { "test/test_ring.c", ZA_RING_TEST },
    };
    uint8_t ring2_root[32];
    bool p2 = za_publish(zcode, "alice/ringbuffer", "1.0.1", 2, ring2_files,
                         4, "src/ring.h", "src/ring.c", "test/test_ring.c",
                         "src", ring2_root);
    struct package_lifecycle_plan_report plan2;
    struct zcl_result r2 =
        package_lifecycle_plan(base, "alice/ringbuffer", t0 + 2, &plan2);
    ZA_CHECK("the name now SELECTS the higher semver's root",
             p2 && r2.ok && memcmp(plan2.plan.target_root, ring2_root, 32) == 0);
    struct package_lifecycle_plan_report exact_version_plan;
    struct zcl_result exact_version_planned = package_lifecycle_plan(
        base, "alice/ringbuffer@1.0.0", t0 + 2, &exact_version_plan);
    ZA_CHECK("name@semver selects that exact version instead of latest",
             exact_version_planned.ok && exact_version_plan.ready &&
                 memcmp(exact_version_plan.plan.target_root, ring_root, 32) ==
                     0);
    struct package_lifecycle_commit_report commit2;
    struct zcl_result cr2 =
        package_lifecycle_commit(base, plan2.plan_id, t0 + 3, &commit2);
    if (!cr2.ok)
        printf("  zcode_add: upgrade failed rule=%s detail=%s msg=%s\n",
               commit2.rule, commit2.detail, cr2.message);
    ZA_CHECK("the upgrade installs and reports the previous root",
             cr2.ok && commit2.installed && commit2.had_previous &&
                 memcmp(commit2.previous_root, ring_root, 32) == 0);
    char installed2[4400];
    char root2_hex[65];
    za_hex(ring2_root, 32, root2_hex);
    snprintf(installed2, sizeof(installed2), "%s/installed/%s", zcode,
             root2_hex);
    ZA_CHECK("BOTH generations are on disk after the upgrade",
             za_exists(installed_dir) && za_exists(installed2));

    failures += za_user_data_after_update(&user_data);

    /* --- NOW BREAK B, then go back ---------------------------------------
     * Reverting a version that still works proves almost nothing. The whole
     * reason to keep the old version is that the new one failed, so the
     * revert is exercised against a version that is not merely broken but
     * GONE: B's entire install tree is destroyed, leaving the active
     * symlink dangling. Nothing about going back may depend on B. */
    ZA_CHECK("version B's install tree is destroyed to stage the failure",
             za_rm_rf(installed2) && !za_exists(installed2));
    char blink[4400];
    snprintf(blink, sizeof(blink), "%s/active/alice/ringbuffer", zcode);
    struct stat broken_link;
    ZA_CHECK("the active version is now a dangling pointer (B is broken)",
             lstat(blink, &broken_link) == 0 &&
                 S_ISLNK(broken_link.st_mode) &&
                 za_link_targets_path(blink, installed2) && !za_exists(blink));

    /* And go back with NO NAME: the user knows only that they want the
     * thing they were running before, not an identifier or a hash. */
    char last_name[VCS_PACKAGE_RELEASE_NAME_MAX + 1u];
    bool last_present = false;
    struct zcl_result lar = package_lifecycle_last_activated(
        base, last_name, sizeof(last_name), &last_present);
    ZA_CHECK("the most recently changed package is named without being asked",
             lar.ok && last_present &&
                 strcmp(last_name, "alice/ringbuffer") == 0);

    struct package_lifecycle_rollback_report rb;
    struct zcl_result rbr =
        package_lifecycle_rollback(base, NULL, t0 + 4, &rb);
    ZA_CHECK("rollback with no name goes back one step on that package",
             rbr.ok && rb.selected_by_default &&
                 strcmp(rb.name, "alice/ringbuffer") == 0);
    ZA_CHECK("rollback re-activates the previous root even though B is gone",
             rbr.ok && memcmp(rb.from_root, ring2_root, 32) == 0 &&
                 memcmp(rb.to_root, ring_root, 32) == 0);
    ar = package_lifecycle_active(base, "alice/ringbuffer", active, &gens,
                                  &present);
    ZA_CHECK("A is active again and history was appended, not rewritten",
             ar.ok && present && gens == 3 &&
                 memcmp(active, ring_root, 32) == 0);
    char link[4400];
    char resolved[4400];
    snprintf(link, sizeof(link), "%s/active/alice/ringbuffer", zcode);
    ssize_t ln = readlink(link, resolved, sizeof(resolved) - 1u);
    if (ln > 0)
        resolved[ln] = '\0';
    else
        resolved[0] = '\0';
    ZA_CHECK("the active symlink points at A's install tree",
             ln > 0 && za_link_targets_path(link, installed_dir));

    /* The claim is byte-exactness, so assert byte-exactness: hash what the
     * active pointer resolves to TODAY and compare against the fingerprint
     * taken while A was the running version. Identity, not liveness. */
    char back_archive[4600];
    char back_header[4600];
    snprintf(back_archive, sizeof(back_archive), "%s/lib/libringbuffer.a",
             resolved);
    snprintf(back_header, sizeof(back_header), "%s/include/ring.h", resolved);
    uint8_t back_archive_sha[32], back_header_sha[32];
    bool back_hashed = za_file_sha3(back_archive, back_archive_sha) &&
                       za_file_sha3(back_header, back_header_sha);
    ZA_CHECK("the user is running BYTE-EXACTLY version A again",
             a_fingerprinted && back_hashed &&
                 memcmp(back_archive_sha, a_archive_sha, 32) == 0 &&
                 memcmp(back_header_sha, a_header_sha, 32) == 0);
    ZA_CHECK("and the root it went back to is A's exact identity",
             memcmp(rb.to_root, ring_root, 32) == 0 &&
                 memcmp(active, ring_root, 32) == 0);

    failures += za_user_data_after_rollback(&user_data);

    /* --- a dependent package, locked to its dependency's root ----------- */
    char deps_json[256];
    char base_root_hex[65];
    za_hex(ring_root, 32, base_root_hex);
    snprintf(deps_json, sizeof(deps_json),
             "{\"schema\":1,\"dependencies\":[{\"root\":\"%s\","
             "\"name\":\"alice/ringbuffer\",\"semver\":\"1.0.0\"}]}",
             base_root_hex);
    struct za_file q_files[] = {
        { "LICENSE", ZA_LICENSE },
        { "src/queue.h",
          "#pragma once\n#include \"ring.h\"\nint queue_probe(void);\n" },
        { "src/queue.c",
          "#include \"queue.h\"\n"
          "int queue_probe(void){ struct ring r; ring_init(&r);\n"
          "  return ring_push(&r, 7) ? 7 : -1; }\n" },
        { "test/test_queue.c",
          "#include \"queue.h\"\nint main(void){ return queue_probe()==7?0:1; }\n" },
        { VCS_PACKAGE_DEPS_META_PATH, deps_json },
    };
    uint8_t q_root[32];
    bool pq = za_publish(zcode, "alice/queue", "1.0.0", 3, q_files, 5,
                         "src/queue.h", "src/queue.c", "test/test_queue.c",
                         "src", q_root);
    struct package_lifecycle_plan_report qplan;
    struct zcl_result qr =
        package_lifecycle_plan(base, "alice/queue", t0 + 5, &qplan);
    ZA_CHECK("the dependent's plan locks its dependency, deps first",
             pq && qr.ok && qplan.plan.step_count == 2 &&
                 memcmp(qplan.plan.steps[0].root, ring_root, 32) == 0 &&
                 qplan.plan.steps[0].depth == 1 &&
                 memcmp(qplan.plan.steps[1].root, q_root, 32) == 0 &&
                 qplan.plan.steps[1].depth == 0);
    struct package_lifecycle_commit_report qcommit;
    struct zcl_result qcr =
        package_lifecycle_commit(base, qplan.plan_id, t0 + 6, &qcommit);
    if (!qcr.ok)
        printf("  zcode_add: dependent commit failed rule=%s detail=%s "
               "msg=%s\n", qcommit.rule, qcommit.detail, qcr.message);
    char q_installed[4400];
    char q_hex[65];
    za_hex(q_root, 32, q_hex);
    snprintf(q_installed, sizeof(q_installed), "%s/installed/%s", zcode,
             q_hex);
    char q_archive[4600];
    snprintf(q_archive, sizeof(q_archive), "%s/lib/libqueue.a", q_installed);
    ZA_CHECK("the dependent builds AGAINST its locked dependency and installs",
             qcr.ok && qcommit.installed && za_exists(q_archive) &&
                 qcommit.steps[0].already_installed &&
                 qcommit.steps[0].has_receipt &&
                 qcommit.steps[0].receipt_reused &&
                 memcmp(qcommit.steps[0].receipt_id, ring_receipt, 32) == 0);

    /* --- a tampered CAS object must never reach a build ----------------- */
    struct za_file evil_files[] = {
        { "LICENSE", ZA_LICENSE },
        { "src/ring.h", ZA_RING_H },
        { "src/ring.c", ZA_RING_C "/* v3 */\n" },
        { "test/test_ring.c", ZA_RING_TEST },
    };
    uint8_t evil_root[32];
    bool pe = za_publish(zcode, "bob/ringbuffer", "1.0.0", 4, evil_files, 4,
                         "src/ring.h", "src/ring.c", "test/test_ring.c",
                         "src", evil_root);
    struct package_lifecycle_plan_report eplan;
    struct zcl_result er =
        package_lifecycle_plan(base, "bob/ringbuffer", t0 + 7, &eplan);
    /* Published is not installed: reproduction without an install receipt
     * is a named refusal, not a build. */
    struct package_lifecycle_reproduce_report ni_repro;
    struct zcl_result nir =
        package_lifecycle_reproduce(base, "bob/ringbuffer", NULL, &ni_repro);
    ZA_CHECK("reproduce of a package that was never installed is refused",
             pe && !nir.ok &&
                 strcmp(ni_repro.rule, "not-installed") == 0);
    bool tampered_ok = pe && er.ok &&
                       za_tamper_chunk(zcode, ZA_RING_C "/* v3 */\n");
    /* Re-plan AFTER the tamper: the plan itself must now refuse to be
     * ready, and a commit must refuse too. */
    struct package_lifecycle_plan_report eplan2;
    struct zcl_result er2 =
        package_lifecycle_plan(base, "bob/ringbuffer", t0 + 8, &eplan2);
    ZA_CHECK("a tampered CAS object makes the plan not-ready and names it",
             tampered_ok && er2.ok && !eplan2.ready &&
                 eplan2.plan.steps[0].state ==
                     VCS_PACKAGE_LIFECYCLE_DISCOVERED &&
                 strcmp(eplan2.rule, "chunk-hash-mismatch") == 0);
    struct package_lifecycle_commit_report ecommit;
    struct zcl_result ecr =
        package_lifecycle_commit(base, eplan2.plan_id, t0 + 9, &ecommit);
    char evil_installed[4400];
    char evil_hex[65];
    za_hex(evil_root, 32, evil_hex);
    snprintf(evil_installed, sizeof(evil_installed), "%s/installed/%s", zcode,
             evil_hex);
    ZA_CHECK("commit refuses tampered content and installs nothing",
             !ecr.ok && strcmp(ecommit.rule, "chunk-hash-mismatch") == 0 &&
                 !za_exists(evil_installed));

    /* --- an unknown plan id is a named refusal, not a crash ------------- */
    uint8_t bogus[32];
    memset(bogus, 0x5a, 32);
    struct package_lifecycle_commit_report bcommit;
    struct zcl_result bcr =
        package_lifecycle_commit(base, bogus, t0 + 10, &bcommit);
    ZA_CHECK("an unknown plan_id is named, never guessed at",
             !bcr.ok && strcmp(bcommit.rule, "plan-unknown") == 0);

    /* Installed status alone is not proof. Corrupting a declared output
     * must invalidate the resident receipt before activation can succeed. */
    bool damaged = za_write_file(archive, "corrupt", 7, 0600);
    struct package_lifecycle_plan_report damaged_plan;
    struct zcl_result damaged_planned =
        package_lifecycle_plan(base, root_hex, t0 + 11, &damaged_plan);
    struct package_lifecycle_commit_report damaged_commit;
    struct zcl_result damaged_result = package_lifecycle_commit(
        base, damaged_plan.plan_id, t0 + 12, &damaged_commit);
    ZA_CHECK("an installed output that differs from its receipt is refused",
             damaged && damaged_planned.ok && !damaged_result.ok &&
                 strcmp(damaged_commit.rule,
                        "installed-receipt-invalid") == 0);
    reuse_installed = true;
    reuse_inspected = package_lifecycle_installed_inspect(
        base, ring_root, &reuse_inspection, &reuse_installed);
    ZA_CHECK("reuse inspection refuses a tampered installed output",
             !reuse_inspected.ok && !reuse_installed);

    za_rm_rf(base);
    return failures;
}

/* ── the program a person runs after `zcode use` ─────────────────────── */

/* Plan through the service, then COMMIT through the native leaf `zcode use`
 * dispatches to, so the reply under test is the one an operator reads. The
 * caller owns `commit_reply`. */
static bool za_use_commit(const char *datadir, const char *target,
                          int64_t now,
                          struct zcl_command_reply *commit_reply)
{
    struct package_lifecycle_plan_report plan;
    struct zcl_result r = package_lifecycle_plan(datadir, target, now, &plan);
    if (!r.ok) {
        printf("  zcode_add: plan for %s failed rule=%s msg=%s\n", target,
               plan.rule, r.message);
        return false;
    }
    char plan_hex[65];
    za_hex(plan.plan_id, 32, plan_hex);
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    bool ok = json_push_kv_str(&input, "plan_id", plan_hex) &&
              json_push_kv_str(&input, "datadir", datadir) &&
              json_push_kv_int(&input, "now_unix", now + 1);
    struct zcl_command_request request = { .input = &input };
    if (ok)
        zcl_native_handle_zcode_package_add_commit(&request, commit_reply);
    json_free(&input);
    return ok;
}

#define ZA_CLI_H \
    "#pragma once\n" \
    "int cli_total(void);\n"

#define ZA_CLI_C \
    "#include \"cli.h\"\n#include \"ring.h\"\n" \
    "int cli_total(void){ struct ring r; ring_init(&r);\n" \
    "  if(!ring_push(&r, 7)) return -1;\n" \
    "  int v = 0; return ring_pop(&r, &v) ? v : -1; }\n"

#define ZA_CLI_TEST \
    "#include \"cli.h\"\n" \
    "int main(void){ return cli_total() == 7 ? 0 : 1; }\n"

/* The program calls ring_* DIRECTLY, so it can only link if the locked
 * dependency's archive reached the PROGRAM's link line — not merely the
 * package's own objects. */
#define ZA_CLI_MAIN \
    "#include \"cli.h\"\n#include \"ring.h\"\n#include <stdio.h>\n" \
    "int main(void){ struct ring r; ring_init(&r);\n" \
    "  if(!ring_push(&r, cli_total())) return 1;\n" \
    "  int v = 0; if(!ring_pop(&r, &v)) return 1;\n" \
    "  printf(\"ringcli total=%d\\n\", v); return 0; }\n"

/* Content unique to the package whose bytes never arrive, so removing its
 * CAS objects cannot take a byte from anything already accepted. */
#define ZA_GHOST_H \
    "#pragma once\n" \
    "int ghost_value(void);\n"

#define ZA_GHOST_C \
    "#include \"ghost.h\"\n" \
    "int ghost_value(void){ return 41 + 1; }\n"

#define ZA_GHOST_TEST \
    "#include \"ghost.h\"\n" \
    "int main(void){ return ghost_value() == 42 ? 0 : 1; }\n"

/* A program that keeps state in a file it is handed: it prints whatever it
 * finds there, then records its own version over it. Two versions of that
 * program are what turn "the directory survived" into "the user's WORK
 * survived" — the bytes are written and read back by the installed program
 * itself, not by this harness standing in for it. */
#define ZA_STATE_H \
    "#pragma once\n" \
    "int state_run(const char *path);\n"

/* %s is the version tag this build records. */
#define ZA_STATE_C_FMT \
    "#include \"state.h\"\n#include <stdio.h>\n" \
    "int state_run(const char *path){\n" \
    "  char prev[64]; size_t n = 0;\n" \
    "  FILE *r = fopen(path, \"rb\");\n" \
    "  if (r) { n = fread(prev, 1, sizeof(prev) - 1u, r); fclose(r); }\n" \
    "  prev[n] = '\\0';\n" \
    "  printf(\"seen=%%s\\n\", prev);\n" \
    "  FILE *w = fopen(path, \"wb\");\n" \
    "  if (!w) return 1;\n" \
    "  int ok = fputs(\"%s\", w) >= 0;\n" \
    "  return (fclose(w) == 0 && ok) ? 0 : 1; }\n"

#define ZA_STATE_TEST \
    "#include \"state.h\"\n" \
    "int main(void){ return 0; }\n"

#define ZA_STATE_MAIN \
    "#include \"state.h\"\n#include <stdio.h>\n" \
    "int main(int argc, char **argv){\n" \
    "  if (argc < 2) { printf(\"usage: statecli PATH\\n\"); return 2; }\n" \
    "  return state_run(argv[1]); }\n"

/* ── the user's work, written by the program itself ──────────────────
 *
 * Everything above proves the DIRECTORY is left alone. This proves the
 * thing a person actually cares about: install a program, let it record
 * something, update to a version built from different source, and the
 * older version's record is still there to be read; then go back, and what
 * the NEWER version wrote is still there too.
 *
 * The bytes never pass through this harness — each version's own installed
 * binary writes and reads them. That is the only way the claim is about the
 * product rather than about the test. Three phases, three functions, one
 * struct, so the transcript does not carry their branches. */
struct za_state_app {
    char data_dir[PACKAGE_LIFECYCLE_DATA_DIR_MAX + 1u];
    char state_file[PACKAGE_LIFECYCLE_DATA_DIR_MAX + 32u];
    char alpha_path[PACKAGE_LIFECYCLE_DATA_DIR_MAX + 1u];
    char beta_path[PACKAGE_LIFECYCLE_DATA_DIR_MAX + 1u];
    uint8_t alpha_root[32];
    uint8_t beta_root[32];
};

/* Install one version of the state-keeping program and report where its
 * binary landed. `semver`/`sequence` pick the version; `body` is its
 * src/state.c, which differs per version so the roots differ. */
static bool za_state_publish_install(const char *base, const char *zcode,
                                     const char *semver, uint64_t sequence,
                                     const char *body, int64_t now,
                                     uint8_t out_root[32], char *out_path,
                                     size_t path_cap, char *out_data_dir,
                                     size_t data_cap)
{
    struct za_file files[] = {
        { "LICENSE", ZA_LICENSE },
        { "src/state.h", ZA_STATE_H },
        { "src/state.c", body },
        { "test/test_state.c", ZA_STATE_TEST },
        { "app/main.c", ZA_STATE_MAIN },
    };
    if (!za_publish_ex(zcode, "alice/statecli", semver, sequence, files, 5,
                       "src/state.h", "src/state.c", "test/test_state.c",
                       "src", "app/main.c", out_root))
        return false;
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.zcode_add_commit.v1");
    bool ok = za_use_commit(base, "alice/statecli", now, &reply);
    if (ok) {
        const struct json_value *programs = json_get(&reply.data, "programs");
        const struct json_value *first =
            programs ? json_at(programs, 0) : NULL;
        const char *path = first ? json_get_str(json_get(first, "path"))
                                 : NULL;
        const char *dir = json_get_str(json_get(&reply.data, "data_dir"));
        ok = path && path[0] == '/';
        if (ok)
            (void)snprintf(out_path, path_cap, "%s", path);
        if (ok && out_data_dir)
            (void)snprintf(out_data_dir, data_cap, "%s", dir ? dir : "");
    }
    zcl_command_reply_free(&reply);
    return ok;
}

/* Run one installed version against the state file and capture what it
 * printed. */
static int za_state_run(const char *program, const char *state_file,
                        char *out, size_t cap)
{
    out[0] = '\0';
    const char *argv[] = { program, state_file, NULL };
    return zcl_spawn_capture(argv, out, cap, 30000);
}

static int za_state_first_run(const char *base, const char *zcode,
                              int64_t t0, struct za_state_app *a)
{
    int failures = 0;
    char body[1024];
    snprintf(body, sizeof(body), ZA_STATE_C_FMT, "alpha");
    memset(a, 0, sizeof(*a));
    bool installed = za_state_publish_install(
        base, zcode, "1.0.0", 4, body, t0 + 30, a->alpha_root, a->alpha_path,
        sizeof(a->alpha_path), a->data_dir, sizeof(a->data_dir));
    ZA_CHECK("a program that keeps state installs and is named", installed);

    /* The reply hands the operator the directory, so a person running the
     * program is told where to point it rather than guessing. */
    char resolved[PACKAGE_LIFECYCLE_DATA_DIR_MAX + 1u];
    struct zcl_result ddr =
        package_lifecycle_data_dir(base, "alice/statecli", resolved,
                                   sizeof(resolved));
    ZA_CHECK("the install reply hands the operator the data directory",
             installed && ddr.ok && strcmp(a->data_dir, resolved) == 0);
    snprintf(a->state_file, sizeof(a->state_file), "%s/state", resolved);

    char out[512];
    int rc = installed ? za_state_run(a->alpha_path, a->state_file, out,
                                      sizeof(out))
                       : -1;
    ZA_CHECK("the first run finds nothing recorded and records itself",
             rc == 0 && strstr(out, "seen=\n") != NULL);
    return failures;
}

static int za_state_after_update(const char *base, const char *zcode,
                                 int64_t t0, struct za_state_app *a)
{
    int failures = 0;
    char body[1024];
    snprintf(body, sizeof(body), ZA_STATE_C_FMT, "beta");
    /* Built from DIFFERENT source, so this is a genuinely different root
     * and not a re-activation of the one already installed. */
    bool installed = za_state_publish_install(
        base, zcode, "1.0.1", 5, body, t0 + 31, a->beta_root, a->beta_path,
        sizeof(a->beta_path), NULL, 0);
    ZA_CHECK("the update installs a different root of the same program",
             installed && memcmp(a->beta_root, a->alpha_root, 32) != 0 &&
                 strcmp(a->beta_path, a->alpha_path) != 0);

    char out[512];
    int rc = installed ? za_state_run(a->beta_path, a->state_file, out,
                                      sizeof(out))
                       : -1;
    ZA_CHECK("the updated program reads what the old version recorded",
             rc == 0 && strstr(out, "seen=alpha") != NULL);
    return failures;
}

static int za_state_after_rollback(const char *base, int64_t t0,
                                   const struct za_state_app *a)
{
    int failures = 0;
    char hidden[PACKAGE_LIFECYCLE_DATA_DIR_MAX + 16u];
    int n = snprintf(hidden, sizeof(hidden), "%s.hidden", a->alpha_path);
    bool moved = n > 0 && (size_t)n < sizeof(hidden) &&
                 rename(a->alpha_path, hidden) == 0;
    struct package_lifecycle_rollback_report blocked_report;
    struct zcl_result blocked = package_lifecycle_rollback(
        base, "alice/statecli", t0 + 32, &blocked_report);
    uint8_t active[32];
    size_t generations = 0;
    bool present = false;
    struct zcl_result status = package_lifecycle_active(
        base, "alice/statecli", active, &generations, &present);
    ZA_CHECK("rollback refuses a previous program missing from its receipt",
             moved && !blocked.ok &&
                 strstr(blocked.message, "rollback") != NULL && status.ok &&
                 present && generations == 2 &&
                 memcmp(active, a->beta_root, 32) == 0);
    ZA_CHECK("rollback refusal names the repair in the bounded report",
             strcmp(blocked_report.rule, "rollback-target-invalid") == 0 &&
                 strstr(blocked_report.detail, "reinstall the exact root") != NULL);
    bool restored = moved && rename(hidden, a->alpha_path) == 0;
    ZA_CHECK("the previous program fixture is restored", restored);
    struct package_lifecycle_rollback_report rb;
    struct zcl_result rbr =
        package_lifecycle_rollback(base, "alice/statecli", t0 + 32, &rb);
    ZA_CHECK("the program rolls back to its previous exact root",
             rbr.ok && memcmp(rb.to_root, a->alpha_root, 32) == 0);

    /* THE WHOLE POINT: the running version is alpha again, and what BETA
     * wrote is still there. Going back changed the code and left the user's
     * work alone. */
    char out[512];
    int rc = za_state_run(a->alpha_path, a->state_file, out, sizeof(out));
    ZA_CHECK("after going back, the CURRENT user data is still there",
             rc == 0 && strstr(out, "seen=beta") != NULL);
    return failures;
}

static int za_program_data_survives(const char *base, const char *zcode,
                                    int64_t t0)
{
    struct za_state_app app;
    int failures = za_state_first_run(base, zcode, t0, &app);
    failures += za_state_after_update(base, zcode, t0, &app);
    failures += za_state_after_rollback(base, t0, &app);
    return failures;
}

/* ── the publisher is gone ───────────────────────────────────────────
 *
 * "Offline" for a content-addressed store is not a network error to handle;
 * it is the plain fact that a node can only ever use what it already holds.
 * Two claims have to hold AT ONCE, and collapsing them is how a store
 * either waits forever or quietly accepts something it never received:
 *
 *   1. everything already accepted stays usable with nothing left to
 *      contact, even while an unreachable package sits in the store beside
 *      it;
 *   2. the one thing that genuinely needs the publisher -- bytes this node
 *      does not hold -- is REFUSED BY NAME rather than waited on.
 *
 * Claim 1 alone describes a store that pretends; claim 2 alone describes
 * one that is merely broken. */
static int za_publisher_gone(const char *base, const char *zcode,
                             const char *program_path, bool program_exec,
                             int64_t t0)
{
    int failures = 0;
    struct za_file ghost_files[] = {
        { "LICENSE", ZA_LICENSE },
        { "src/ghost.h", ZA_GHOST_H },
        { "src/ghost.c", ZA_GHOST_C },
        { "test/test_ghost.c", ZA_GHOST_TEST },
    };
    uint8_t ghost_root[32];
    bool published =
        za_publish(zcode, "alice/ghost", "1.0.0", 3, ghost_files, 4,
                   "src/ghost.h", "src/ghost.c", "test/test_ghost.c", "src",
                   ghost_root);
    /* The release is known and its bytes are absent: exactly the state a
     * node is left in when the publisher goes away between discovery and
     * fetch. Only chunks unique to this package are removed, so nothing
     * already accepted loses a byte. */
    bool emptied = published && za_remove_chunk(zcode, ZA_GHOST_C) &&
                   za_remove_chunk(zcode, ZA_GHOST_H) &&
                   za_remove_chunk(zcode, ZA_GHOST_TEST);
    struct package_lifecycle_plan_report plan;
    struct zcl_result planned =
        package_lifecycle_plan(base, "alice/ghost", t0 + 20, &plan);
    ZA_CHECK("bytes this node never received are named, never waited on",
             emptied && planned.ok && !plan.ready &&
                 strcmp(plan.rule, "package-incomplete") == 0);
    ZA_CHECK("the unreachable step reports FETCHING, not a false VERIFIED",
             planned.ok && plan.plan.step_count == 1 &&
                 plan.plan.steps[0].state == VCS_PACKAGE_LIFECYCLE_FETCHING &&
                 !plan.plan.steps[0].complete);
    struct package_lifecycle_commit_report commit;
    struct zcl_result committed =
        package_lifecycle_commit(base, plan.plan_id, t0 + 21, &commit);
    char installed[4400];
    char hex[65];
    za_hex(ghost_root, 32, hex);
    snprintf(installed, sizeof(installed), "%s/installed/%s", zcode, hex);
    ZA_CHECK("a package whose bytes never arrived installs nothing",
             !committed.ok && !za_exists(installed));

    /* Claim 1: the accepted application is untouched by its neighbour's
     * unavailability. Same program, run again with an unreachable package
     * now resident in the same store. */
    char ran[512];
    ran[0] = '\0';
    const char *argv[] = { program_path, NULL };
    int rc = (program_path && program_exec)
        ? zcl_spawn_capture(argv, ran, sizeof(ran), 30000)
        : -1;
    ZA_CHECK("the accepted program still runs with the publisher gone",
             rc == 0 && strstr(ran, "ringcli total=7") != NULL);
    /* And the place the user's data lives is still there and still named,
     * which is what makes the accepted version usable rather than merely
     * present. */
    char data_dir[PACKAGE_LIFECYCLE_DATA_DIR_MAX + 1u];
    struct zcl_result ddr =
        package_lifecycle_data_dir(base, "alice/ringcli", data_dir,
                                   sizeof(data_dir));
    ZA_CHECK("the accepted app's data directory survives the publisher",
             ddr.ok && za_exists(data_dir));
    return failures;
}

static int za_program_missing_refusal(const char *base,
                                      const uint8_t root[32],
                                      const char *installed_bin,
                                      bool installed_exec)
{
    int failures = 0;
    char held_bin[4700];
    (void)snprintf(held_bin, sizeof(held_bin), "%s.held", installed_bin);
    bool moved = installed_exec && rename(installed_bin, held_bin) == 0;
    struct package_lifecycle_programs missing_programs;
    struct zcl_result missing_program = package_lifecycle_installed_programs(
        base, root, &missing_programs);
    ZA_CHECK("program listing refuses a missing receipt-bound executable",
             moved && !missing_program.ok);
    ZA_CHECK("program executable fixture restored",
             moved && rename(held_bin, installed_bin) == 0);
#ifndef _WIN32
    struct stat original_mode;
    bool mode_read = stat(installed_bin, &original_mode) == 0;
    bool demoted = mode_read &&
                   chmod(installed_bin,
                         (mode_t)(original_mode.st_mode & 0777u & ~0111u)) == 0;
    struct package_lifecycle_programs nonexec_programs;
    struct zcl_result nonexec = package_lifecycle_installed_programs(
        base, root, &nonexec_programs);
    ZA_CHECK("program listing refuses receipt-correct bytes without execute permission",
             demoted && !nonexec.ok &&
                 strstr(nonexec.message, "executable") != NULL);
    ZA_CHECK("program execute permission fixture restored",
             demoted &&
                 chmod(installed_bin, (mode_t)(original_mode.st_mode & 0777u)) == 0);
#endif
    return failures;
}

#ifndef _WIN32
static int za_program_parent_link_refusal(const char *base,
                                           const uint8_t root[32],
                                           const char *installed_bin)
{
    int failures = 0;
    char bin_dir[4700], outside[4700], outside_abs[4700];
    (void)snprintf(bin_dir, sizeof(bin_dir), "%s", installed_bin);
    char *slash = strrchr(bin_dir, '/');
    bool shaped = slash != NULL;
    if (shaped)
        *slash = '\0';
    (void)snprintf(outside, sizeof(outside), "%s/escaped-bin", base);
    bool moved = shaped && rename(bin_dir, outside) == 0;
    bool linked = moved && test_abs_path(outside, outside_abs,
                                         sizeof(outside_abs)) &&
                  symlink(outside_abs, bin_dir) == 0;
    struct package_lifecycle_programs programs;
    struct zcl_result listed = package_lifecycle_installed_programs(
        base, root, &programs);
    ZA_CHECK("program listing refuses an output reached through a parent symlink",
             linked && !listed.ok);
    bool removed_link = !linked || unlink(bin_dir) == 0;
    bool restored = removed_link && moved && rename(outside, bin_dir) == 0;
    ZA_CHECK("program parent directory fixture restored", restored);
    return failures;
}

static int za_installed_parent_link_refusal(const char *base,
                                            const uint8_t root[32])
{
    int failures = 0;
    char installed[4700], outside[4700], outside_abs[4700];
    (void)snprintf(installed, sizeof(installed), "%s/zcode/installed", base);
    (void)snprintf(outside, sizeof(outside), "%s/escaped-installed", base);
    bool moved = rename(installed, outside) == 0;
    bool linked = moved && test_abs_path(outside, outside_abs,
                                         sizeof(outside_abs)) &&
                  symlink(outside_abs, installed) == 0;
    struct package_lifecycle_programs programs;
    struct zcl_result listed = package_lifecycle_installed_programs(
        base, root, &programs);
    ZA_CHECK("program listing refuses an installed parent symlink outside the store",
             linked && !listed.ok &&
                 strstr(listed.message, "installed") != NULL);
    bool removed_link = !linked || unlink(installed) == 0;
    bool restored = removed_link && moved && rename(outside, installed) == 0;
    ZA_CHECK("installed parent directory fixture restored", restored);
    return failures;
}
#endif

static int t_programs(void)
{
    int failures = 0;
    char base[4096];
    snprintf(base, sizeof(base), "test-tmp/za_prog_%ld", (long)getpid());
    za_rm_rf(base);
    char zcode[4200];
    snprintf(zcode, sizeof(zcode), "%s/zcode", base);
    if (!za_mkdir_p(zcode)) {
        printf("  zcode_add: cannot create the program fixture datadir... "
               "FAIL\n");
        return 1;
    }
    if (!za_exists("build/bin/zclassic23-package-verify-dev")) {
        printf("  zcode_add: build/bin/zclassic23-package-verify-dev missing "
               "(make dev-bin)... FAIL\n");
        za_rm_rf(base);
        return 1;
    }
    const int64_t t0 = 1700000000;

    /* A library-only package: `programs` must be present and EMPTY, which
     * is a different fact from "we never looked". */
    struct za_file lib_files[] = {
        { "LICENSE", ZA_LICENSE },
        { "src/ring.h", ZA_RING_H },
        { "src/ring.c", ZA_RING_C },
        { "test/test_ring.c", ZA_RING_TEST },
    };
    uint8_t lib_root[32];
    bool lib_published = za_publish(zcode, "alice/ringlib", "1.0.0", 1,
                                    lib_files, 4, "src/ring.h", "src/ring.c",
                                    "test/test_ring.c", "src", lib_root);
    ZA_CHECK("a library-only fixture publishes", lib_published);
    if (!lib_published) {
        za_rm_rf(base);
        return failures;
    }
    struct zcl_command_reply lib_reply;
    zcl_command_reply_init(&lib_reply, "zcl.zcode_add_commit.v1");
    bool lib_used = za_use_commit(base, "alice/ringlib", t0, &lib_reply);
    const struct json_value *lib_programs =
        json_get(&lib_reply.data, "programs");
    ZA_CHECK("a library-only package reports zero programs, not silence",
             lib_used && lib_reply.status == ZCL_COMMAND_STATUS_PASSED &&
                 lib_programs && lib_programs->type == JSON_ARR &&
                 lib_programs->num_children == 0 &&
                 json_get_int(json_get(&lib_reply.data, "program_count")) ==
                     0 &&
                 json_get(&lib_reply.data, "next_action") == NULL);
    zcl_command_reply_free(&lib_reply);

    /* A package that ships an application, locked to that library. */
    char deps_json[256];
    char lib_hex[65];
    za_hex(lib_root, 32, lib_hex);
    snprintf(deps_json, sizeof(deps_json),
             "{\"schema\":1,\"dependencies\":[{\"root\":\"%s\","
             "\"name\":\"alice/ringlib\",\"semver\":\"1.0.0\"}]}", lib_hex);
    struct za_file cli_files[] = {
        { "LICENSE", ZA_LICENSE },
        { "src/cli.h", ZA_CLI_H },
        { "src/cli.c", ZA_CLI_C },
        { "test/test_cli.c", ZA_CLI_TEST },
        { "app/main.c", ZA_CLI_MAIN },
        { VCS_PACKAGE_DEPS_META_PATH, deps_json },
    };
    uint8_t cli_root[32];
    bool cli_published = za_publish_ex(
        zcode, "alice/ringcli", "1.0.0", 2, cli_files, 6, "src/cli.h",
        "src/cli.c", "test/test_cli.c", "src", "app/main.c", cli_root);
    ZA_CHECK("a fixture declaring app/main.c publishes", cli_published);

    struct zcl_command_reply cli_reply;
    zcl_command_reply_init(&cli_reply, "zcl.zcode_add_commit.v1");
    bool cli_used = cli_published &&
                    za_use_commit(base, "alice/ringcli", t0 + 2, &cli_reply);
    if (cli_used && cli_reply.status != ZCL_COMMAND_STATUS_PASSED)
        printf("  zcode_add: ringcli commit failed code=%s message=%s\n",
               cli_reply.error.code, cli_reply.error.message);

    char cli_hex[65];
    za_hex(cli_root, 32, cli_hex);
    char installed_bin[4600];
    snprintf(installed_bin, sizeof(installed_bin),
             "%s/installed/%s/bin/ringcli", zcode, cli_hex);
    struct stat pst;
    bool installed_exec = stat(installed_bin, &pst) == 0 &&
                          S_ISREG(pst.st_mode) && (pst.st_mode & 0111) != 0;
    ZA_CHECK("the program installs under installed/<root>/bin/ with the "
             "executable bit set",
             cli_used && cli_reply.status == ZCL_COMMAND_STATUS_PASSED &&
                 installed_exec);

    const struct json_value *cli_programs =
        json_get(&cli_reply.data, "programs");
    const struct json_value *first =
        cli_programs ? json_at(cli_programs, 0) : NULL;
    const char *first_output = first ? json_get_str(json_get(first, "output"))
                                     : NULL;
    const char *first_path =
        first ? json_get_str(json_get(first, "path")) : NULL;
    const char *next_action =
        json_get_str(json_get(&cli_reply.data, "next_action"));
    struct stat rst;
    ZA_CHECK("the reply names the exact program and where to run it",
             cli_programs && cli_programs->num_children == 1 &&
                 json_get_int(json_get(&cli_reply.data, "program_count")) ==
                     1 &&
                 first_output && strcmp(first_output, "bin/ringcli") == 0 &&
                 first_path && first_path[0] == '/' &&
                 stat(first_path, &rst) == 0 && S_ISREG(rst.st_mode) &&
                 (rst.st_mode & 0111) != 0 &&
                 next_action && strncmp(next_action, "run ", 4) == 0 &&
                 strcmp(next_action + 4, first_path) == 0);

    /* The program links its locked dependency's archive, so running it
     * exercises code that only reached it through the dependency closure. */
    char ran[512];
    ran[0] = '\0';
    const char *run_argv[] = { first_path, NULL };
    int prc = (first_path && installed_exec)
        ? zcl_spawn_capture(run_argv, ran, sizeof(ran), 30000)
        : -1;
    ZA_CHECK("running the installed program exercises the locked dependency",
             prc == 0 && strstr(ran, "ringcli total=7") != NULL);
    if (prc != 0)
        printf("  zcode_add: program run rc=%d out=%s\n", prc, ran);

    failures += za_publisher_gone(base, zcode, first_path, installed_exec,
                                  t0);
    failures += za_program_missing_refusal(base, cli_root, installed_bin,
                                           installed_exec);
#ifndef _WIN32
    failures += za_program_parent_link_refusal(base, cli_root, installed_bin);
    failures += za_installed_parent_link_refusal(base, cli_root);
#endif
    failures += za_program_data_survives(base, zcode, t0);
    zcl_command_reply_free(&cli_reply);

    /* Reproduce the installed executable through the qualified package
     * worker on every supported native platform, including macOS. */
    struct package_lifecycle_reproduce_report repro;
    struct zcl_result rr =
        package_lifecycle_reproduce(base, "alice/ringcli", NULL, &repro);
    if (!rr.ok)
        printf("  zcode_add: program reproduce failed rule=%s detail=%s "
               "msg=%s\n", repro.rule, repro.detail, rr.message);
    ZA_CHECK("a package shipping a program still reproduces byte-for-byte",
             rr.ok && repro.matched && repro.filed);

    za_rm_rf(base);
    return failures;
}

static int t_worker_literal_path(void)
{
    int failures = 0;
    char base[256], directory[512], executable[640], worker[640];
    char release_worker[640], found[4096];
    test_make_tmpdir(base, sizeof(base), "zcode_add", "worker-path");
    (void)snprintf(directory, sizeof(directory), "%s/kept (deleted) files", base);
    (void)snprintf(executable, sizeof(executable), "%s/z23", directory);
    (void)snprintf(worker, sizeof(worker), "%s/zclassic23-package-verify-dev", directory);
    bool prepared = za_mkdir_p(directory) && za_write_file(worker, "", 0, 0700);
    ZA_CHECK("worker discovery fixture prepared", prepared);
    ZA_CHECK("literal deleted text in install directory is preserved", prepared &&
        pkgl_worker_path_for_executable(executable, found, sizeof(found)).ok &&
        strcmp(found, worker) == 0);
    (void)snprintf(executable, sizeof(executable), "%s/z23 (deleted)", directory);
    ZA_CHECK("trailing kernel marker does not change verifier directory", prepared &&
        pkgl_worker_path_for_executable(executable, found, sizeof(found)).ok &&
        strcmp(found, worker) == 0);
    (void)snprintf(release_worker, sizeof(release_worker),
                   "%s/zclassic23-package-verify", directory);
    bool replaced = za_rm_rf(worker) && za_mkdir_p(worker) &&
                    za_write_file(release_worker, "", 0, 0700);
    ZA_CHECK("a directory named like the dev verifier cannot mask the release verifier",
             replaced &&
                 pkgl_worker_path_for_executable(executable, found,
                                                 sizeof(found)).ok &&
                 strcmp(found, release_worker) == 0);
    ZA_CHECK("worker discovery fixture removed", za_rm_rf(base));
    return failures;
}

static bool za_release_plan_refuses(const char *base, int64_t now,
                                    const char *first, const char *second)
{
    struct package_lifecycle_plan_report plan;
    struct zcl_result planned =
        package_lifecycle_plan(base, "alice/preview", now, &plan);
    return !planned.ok && strstr(planned.message, first) != NULL &&
           strstr(planned.message, second) != NULL;
}

static int t_release_parent_shape(void)
{
    int failures = 0;
    char base[256], zcode[400], releases[440], outside[400];
    char outside_abs[4400];
    test_make_tmpdir(base, sizeof(base), "zcode_add", "release-parent");
    (void)snprintf(zcode, sizeof(zcode), "%s/zcode", base);
    (void)snprintf(releases, sizeof(releases), "%s/releases", zcode);
    (void)snprintf(outside, sizeof(outside), "%s/outside", base);
    bool prepared = za_mkdir_p(zcode) && za_mkdir_p(outside) &&
                    test_abs_path(outside, outside_abs, sizeof(outside_abs)) &&
                    symlink(outside_abs, releases) == 0;
    ZA_CHECK("package plan refuses a linked local releases directory",
             prepared && za_release_plan_refuses(base, 1000, "releases",
                                                  "linked"));
    bool blocked = prepared && unlink(releases) == 0 &&
                   za_write_file(releases, "blocked", 7, 0600);
    ZA_CHECK("package plan names a non-directory releases blocker",
             blocked && za_release_plan_refuses(base, 1001, "releases",
                                                 "directory"));
    bool root_linked = blocked && unlink(releases) == 0 &&
                       rmdir(zcode) == 0 &&
                       symlink(outside_abs, zcode) == 0;
    ZA_CHECK("package plan refuses a linked local zcode root",
             root_linked && za_release_plan_refuses(base, 1002, "zcode",
                                                     "linked"));
    ZA_CHECK("release parent fixture removed", za_rm_rf(base));
    return failures;
}

int test_zcode_add(void)
{
    printf("\n=== zcode_add: package install lifecycle ===\n");
    int failures = 0;
    failures += t_worker_literal_path();
    failures += t_deps_rules();
    failures += t_generations();
    failures += t_release_selection();
    failures += t_release_parent_shape();
    failures += t_activation_target_shape();
    failures += t_active_temp_directory_preserved();
    failures += t_active_parent_symlink();
    failures += t_generation_parent_symlink();
    failures += t_data_parent_symlink();
    failures += t_atomic_write_temp_symlink();
    failures += t_relative_active_pointer();
    failures += t_active_log_divergence();
    failures += t_active_wrong_pointer();
    failures += t_active_missing_install();
    failures += t_e2e();
    failures += t_programs();
    printf("=== zcode_add complete: %d failure(s) ===\n", failures);
    return failures;
}
