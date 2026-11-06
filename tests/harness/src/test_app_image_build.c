/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_app_image_build — the zcl.app_build.v1 record (command/app_image.h).
 *
 *   1. Closure: a tiny fixture program compiled with cc -MD; the derived
 *      action's source list is exactly the depfile's prerequisite list, the
 *      record's closure root is that action's vcs_build_input_closure_v1
 *      root, an included header moves it and an unlisted file does not.
 *   2. Store: save then load by (package, env, dependency) is a hit with
 *      the same record; a later version does not displace an earlier one,
 *      so restoring the earlier version is a cache hit; other inputs miss.
 *   3. Launch: the recorded image passes resident_launch_prepare; the same
 *      image edited in place (same size, same inode) is refused.
 *   4. Domain separation: the ZCLBLD parser, the filed-receipt reader used
 *      by install, and the reproduce scan all refuse an app build record;
 *      the app decoder refuses a ZCLBLD wire.
 *   5. Malformed: every truncation, a trailing byte, a foreign domain, a
 *      zero field and every single-bit flip are refused with a reason; a
 *      truncated record on disk is a refusal, never a cache miss.
 *
 * All fixture state lives under ./test-tmp/. */

#include "test/test_core.h"

#include "base/hex.h"
#include "command/app_image.h"
#include "devloop_action_root.h"
#include "platform/directory_compat.h"
#include "services/package_lifecycle.h"
#include "sha3/sha3.h"
#include "util/spawn.h"
#include "vcs/build_action.h"
#include "vcs/package_build.h"
#include "vcs/package_reproduce.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define AIB_MAX_DEPS 8u

struct aib_fx {
    char root[PATH_MAX];
    char depfile[PATH_MAX];
    char image[PATH_MAX];
    const char *argv[12];
    const char *vfrom[2];
    const char *vto[2];
    const char *env[6];
    const char *system_dirs[1];
    struct vcs_action_abi_v2 abi[1];
    struct zcl_action_root_request req;
};

static void aib_named_root(const char *name, uint8_t out[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)name, strlen(name) + 1u);
    sha3_256_finalize(&sha, out);
}

static bool aib_write(const char *root, const char *rel, const char *text)
{
    char full[PATH_MAX];
    if (snprintf(full, sizeof(full), "%s/%s", root, rel) >= (int)sizeof(full))
        return false;
    FILE *f = fopen(full, "wb");
    if (!f)
        return false;
    bool ok = fputs(text, f) >= 0;
    return fclose(f) == 0 && ok;
}

static bool aib_run(const char *root, const char *const argv[])
{
    char out[4096];
    bool timed_out = false;
    int rc = zcl_spawn_capture_merged_in_dir_observed(argv, root, out,
                                                      sizeof(out), 60000,
                                                      &timed_out);
    if (rc != 0 || timed_out)
        printf("    %s failed rc=%d: %s\n", argv[0], rc, out);
    return rc == 0 && !timed_out;
}

/* The fixture compile, exactly as the derivation is told it ran. */
static bool aib_compile(struct aib_fx *x)
{
    static const char *const link[] = {
        "cc", "-o", "build/app", "build/main.o", NULL,
    };
    const char *compile[13];
    memcpy(compile, x->argv, sizeof(x->argv));
    compile[12] = NULL;
    return aib_run(x->root, compile) && aib_run(x->root, link);
}

static void aib_request(struct aib_fx *x, const uint8_t env_root[32])
{
    static const char *const argv[] = {
        "cc", "-std=c23", "-O2", "-MD", "-MF", "build/main.d",
        "-c", "-o", "build/main.o", "main.c",
    };
    memcpy(x->argv, argv, sizeof(argv));
    x->vfrom[0] = "build/main.o";
    x->vto[0] = "@out/object";
    x->vfrom[1] = "build/main.d";
    x->vto[1] = "@out/depfile";
    x->env[0] = "LANG=C";
    x->env[1] = "SOURCE_DATE_EPOCH=0";
    x->env[2] = "CCACHE_DISABLE=1";
    x->env[3] = "ZCC_DISABLE=1";
    x->env[4] = NULL;
    x->system_dirs[0] = "/usr/include";
    x->abi[0] = (struct vcs_action_abi_v2){ "app_build_fixture", 1 };
    struct zcl_action_root_request *r = &x->req;
    *r = (struct zcl_action_root_request){
        .root = x->root, .stage_kind = "c23.compile.app-fixture",
        .stage_version = 1, .argv = x->argv,
        .argc = sizeof(argv) / sizeof(argv[0]), .virtual_from = x->vfrom,
        .virtual_to = x->vto, .virtual_count = 2, .depfile = x->depfile,
        .system_dirs = x->system_dirs, .system_dir_count = 1,
        .child_env = x->env, .abi_generation = 1, .abi = x->abi,
        .abi_count = 1,
    };
    memcpy(r->toolchain_root, env_root, 32);
    r->harness.present = r->fixtures.present = r->policy.present = true;
    aib_named_root("app_build fixture harness", r->harness.root);
    aib_named_root("app_build fixture make fragment", r->fixtures.root);
    aib_named_root("app_build fixture policy", r->policy.root);
}

static bool aib_init(struct aib_fx *x, const char *tag,
                     const uint8_t env_root[32])
{
    char raw[PATH_MAX];
    memset(x, 0, sizeof(*x));
    test_make_tmpdir(raw, sizeof(raw), "app_image_build", tag);
    if (!platform_directory_canonical_real(raw, x->root, sizeof(x->root)) ||
        snprintf(x->depfile, sizeof(x->depfile), "%s/build/main.d",
                 x->root) >= (int)sizeof(x->depfile) ||
        snprintf(x->image, sizeof(x->image), "%s/build/app", x->root) >=
            (int)sizeof(x->image))
        return false;
    char build[PATH_MAX + 8];
    (void)snprintf(build, sizeof(build), "%s/build", x->root);
    aib_request(x, env_root);
    return mkdir(build, 0700) == 0 &&
           aib_write(x->root, "f.h", "#define BOOST 3\n") &&
           aib_write(x->root, "main.c",
                     "#include \"f.h\"\nint main(void) { return BOOST - 3; }\n") &&
           aib_write(x->root, "notes.txt", "not compiled\n") &&
           aib_compile(x);
}

/* The depfile's prerequisites, in order, the target and continuations
 * skipped. */
static size_t aib_depfile_list(const char *path, char deps[][64], size_t cap)
{
    char text[2048];
    FILE *f = fopen(path, "rb");
    if (!f)
        return 0;
    size_t len = fread(text, 1, sizeof(text) - 1u, f);
    (void)fclose(f);
    text[len] = '\0';
    size_t n = 0;
    char *save = NULL;
    for (char *t = strtok_r(text, " \t\r\n", &save); t && n < cap;
         t = strtok_r(NULL, " \t\r\n", &save)) {
        size_t tl = strlen(t);
        if (strcmp(t, "\\") == 0 || (tl > 0 && t[tl - 1u] == ':'))
            continue;
        (void)snprintf(deps[n++], 64, "%s", t);
    }
    return n;
}

static int aib_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

/* The derived action's sources, as paths, equal the depfile list. */
static bool aib_sources_equal_depfile(const struct aib_fx *x)
{
    char deps[AIB_MAX_DEPS][64];
    size_t n = aib_depfile_list(x->depfile, deps, AIB_MAX_DEPS);
    struct zcl_action_root_result r = {0};
    struct vcs_action_preimage_v2_decoded d = {0};
    char why[256] = "";
    bool ok = n == 2 && zcl_action_root_derive(&x->req, &r) &&
              vcs_action_preimage_v2_decode(r.preimage, r.preimage_len, &d,
                                            why, sizeof(why)) &&
              d.view.source_count == n;
    if (!ok)
        printf("    depfile n=%zu derive=%s why=%s\n", n, r.miss, why);
    qsort(deps, n, sizeof(deps[0]), aib_cmp);
    for (size_t i = 0; ok && i < n; i++)
        ok = strcmp(d.view.sources[i].path, deps[i]) == 0;
    vcs_action_preimage_v2_decoded_free(&d);
    zcl_action_root_result_free(&r);
    return ok;
}

/* The record's closure root is exactly vcs_build_input_closure_v1_root of
 * the derived action's input closure. */
static bool aib_closure_is_v1_root(const struct aib_fx *x,
                                   uint8_t closure[32])
{
    struct zcl_action_root_result r = {0};
    struct vcs_build_input_closure_v1 c;
    uint8_t want[32];
    bool ok = zcl_action_root_derive(&x->req, &r) &&
              vcs_action_preimage_v2_input_closure(r.preimage, r.preimage_len,
                                                   &c, NULL, 0) &&
              vcs_build_input_closure_v1_root(&c, want) &&
              app_image_closure_root(&x->req, 1, closure).ok &&
              memcmp(want, closure, 32) == 0;
    zcl_action_root_result_free(&r);
    return ok;
}

static int test_aib_closure_refused(struct aib_fx *x)
{
    int failures = 0;
    TEST("app_image_build: a closure that cannot be derived is refused") {
        uint8_t out[32];
        ASSERT(unlink(x->depfile) == 0);
        struct zcl_result r = app_image_closure_root(&x->req, 1, out);
        ASSERT(!r.ok && strstr(r.message, "depfile") != NULL);
        ASSERT(!app_image_closure_root(&x->req, 0, out).ok);
        PASS();
    } _test_next:;
    return failures;
}

static int test_aib_closure(const uint8_t env_root[32])
{
    int failures = 0;
    struct aib_fx x;
    TEST("app_image_build: closure equals the compiler -MD dependency list") {
        uint8_t base[32], same[32], moved[32];
        ASSERT(aib_init(&x, "closure", env_root));
        ASSERT(aib_sources_equal_depfile(&x));
        ASSERT(aib_closure_is_v1_root(&x, base));
        ASSERT(aib_write(x.root, "notes.txt", "still not compiled\n"));
        ASSERT(app_image_closure_root(&x.req, 1, same).ok);
        ASSERT(memcmp(base, same, 32) == 0);
        ASSERT(aib_write(x.root, "f.h", "#define BOOST 4\n"));
        ASSERT(aib_compile(&x));
        ASSERT(app_image_closure_root(&x.req, 1, moved).ok);
        ASSERT(memcmp(base, moved, 32) != 0);
        PASS();
    } _test_next:;
    failures += test_aib_closure_refused(&x);
    test_rm_rf(x.root);
    return failures;
}

/* A record over the fixture image, every root filled. */
static bool aib_record(const struct aib_fx *x, const uint8_t env_root[32],
                       const char *version, struct app_image_build *rec)
{
    memset(rec, 0, sizeof(*rec));
    aib_named_root(version, rec->package_root);
    memcpy(rec->env_root, env_root, 32);
    aib_named_root("app_build fixture dependencies", rec->dependency_root);
    return app_image_closure_root(&x->req, 1, rec->closure_root).ok &&
           app_image_capture(x->image, rec).ok;
}

static bool aib_record_equal(const struct app_image_build *a,
                             const struct app_image_build *b)
{
    uint8_t wa[APP_IMAGE_BUILD_WIRE_BYTES], wb[APP_IMAGE_BUILD_WIRE_BYTES];
    return app_image_build_encode(a, wa).ok && app_image_build_encode(b, wb).ok &&
           memcmp(wa, wb, sizeof(wa)) == 0;
}

static int test_aib_store(const struct aib_fx *x, const uint8_t env_root[32])
{
    int failures = 0;
    TEST("app_image_build: a restored version finds its record (cache hit)") {
        struct app_image_build v1, v2, got;
        bool hit = false;
        char store[PATH_MAX + 8];
        (void)snprintf(store, sizeof(store), "%s/store", x->root);
        ASSERT(mkdir(store, 0700) == 0);
        ASSERT(aib_record(x, env_root, "copy v1", &v1));
        ASSERT(aib_record(x, env_root, "copy v2", &v2));
        ASSERT(app_image_build_save(store, &v1, NULL, 0).ok);
        ASSERT(app_image_build_save(store, &v2, NULL, 0).ok);
        ASSERT(app_image_build_load(store, v1.package_root, v1.env_root,
                                    v1.dependency_root, &got, &hit).ok);
        ASSERT(hit && aib_record_equal(&got, &v1));
        ASSERT(app_image_build_load(store, v2.package_root, v2.env_root,
                                    v2.dependency_root, &got, &hit).ok);
        ASSERT(hit && aib_record_equal(&got, &v2));
        uint8_t other[32];
        aib_named_root("another dependency set", other);
        ASSERT(app_image_build_load(store, v1.package_root, v1.env_root,
                                    other, &got, &hit).ok);
        ASSERT(!hit);
        struct app_image_build empty = {0};
        ASSERT(!app_image_build_save(store, &empty, NULL, 0).ok);
        PASS();
    } _test_next:;
    return failures;
}

static bool aib_flip_image_byte(const char *path)
{
    int fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return false;
    uint8_t b = 0;
    bool ok = pread(fd, &b, 1, 64) == 1;
    b ^= 0x01u;
    ok = ok && pwrite(fd, &b, 1, 64) == 1 && fsync(fd) == 0;
    return close(fd) == 0 && ok;
}

static int test_aib_launch(const struct aib_fx *x, const uint8_t env_root[32])
{
    int failures = 0;
#if defined(_WIN32)
    (void)x; (void)env_root;
    printf("app_image_build: resident launch... SKIP (no descriptor exec)\n");
#else
    TEST("app_image_build: an image edited after recording fails prepare") {
        struct app_image_build rec;
        struct resident_launch launch;
        ASSERT(aib_record(x, env_root, "copy v1", &rec));
        struct zcl_result ok = app_image_build_prepare(&rec, x->image, &launch);
        if (ok.ok)
            resident_launch_close(&launch);
        ASSERT(ok.ok);
        ASSERT(aib_flip_image_byte(x->image));
        struct zcl_result edited =
            app_image_build_prepare(&rec, x->image, &launch);
        ASSERT(!edited.ok && strstr(edited.message, x->image) != NULL);
        PASS();
    } _test_next:;
#endif
    return failures;
}

static bool aib_file_at(const char *dir, const char *name,
                        const uint8_t *bytes, size_t len)
{
    char path[PATH_MAX + 80];
    (void)snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    bool ok = fwrite(bytes, 1, len, f) == len;
    return fclose(f) == 0 && ok;
}

/* The install-side filed-receipt reader refuses the record by parse. */
static bool aib_install_refuses(const char *root, const uint8_t id[32],
                                const uint8_t *wire)
{
    char data[PATH_MAX], zcode[PATH_MAX + 8], receipts[PATH_MAX + 24], hex[65];
    (void)snprintf(data, sizeof(data), "%s/datadir", root);
    (void)snprintf(zcode, sizeof(zcode), "%s/zcode", data);
    (void)snprintf(receipts, sizeof(receipts), "%s/receipts", zcode);
    zcl_hex_encode(id, 32, hex);
    struct vcs_package_build_receipt receipt;
    if (mkdir(data, 0700) != 0 || mkdir(zcode, 0700) != 0 ||
        mkdir(receipts, 0700) != 0 ||
        !aib_file_at(receipts, hex, wire, APP_IMAGE_BUILD_WIRE_BYTES))
        return false;
    struct zcl_result r = package_lifecycle_receipt_read(data, id, &receipt);
    if (r.ok)
        return false;
    printf("    install read: %s\n", r.message);
    return strstr(r.message, "filed receipt") != NULL;
}

static bool aib_reproduce_refuses(const char *root, const uint8_t id[32],
                                  const struct app_image_build *rec,
                                  const uint8_t *wire)
{
    char dir[PATH_MAX + 16], hex[65];
    (void)snprintf(dir, sizeof(dir), "%s/receipts", root);
    zcl_hex_encode(id, 32, hex);
    struct vcs_reproduce_report report;
    return mkdir(dir, 0700) == 0 &&
           aib_file_at(dir, hex, wire, APP_IMAGE_BUILD_WIRE_BYTES) &&
           vcs_package_reproduce_scan(dir, rec->package_root,
                                      rec->closure_root, &report) &&
           report.scanned == 1 && report.matching == 0 &&
           report.row_count == 0;
}

static int test_aib_domain(const struct aib_fx *x, const uint8_t env_root[32])
{
    int failures = 0;
    TEST("app_image_build: reproduce and install refuse an app build record") {
        struct app_image_build rec, back;
        uint8_t wire[APP_IMAGE_BUILD_WIRE_BYTES], id[32];
        ASSERT(aib_record(x, env_root, "copy v1", &rec));
        ASSERT(app_image_build_encode(&rec, wire).ok);
        ASSERT(memcmp(wire, APP_IMAGE_BUILD_DOMAIN,
                      APP_IMAGE_BUILD_DOMAIN_BYTES) == 0);
        ASSERT(app_image_build_id(&rec, id).ok);
        struct vcs_package_build_receipt receipt;
        ASSERT(vcs_package_build_parse(wire, sizeof(wire), &receipt) !=
               VCS_PACKAGE_BUILD_OK);
        ASSERT(aib_install_refuses(x->root, id, wire));
        ASSERT(aib_reproduce_refuses(x->root, id, &rec, wire));
        memcpy(wire, "ZCLBLD\r\n", 8);
        struct zcl_result r = app_image_build_decode(wire, sizeof(wire), &back);
        ASSERT(!r.ok && strstr(r.message, "domain") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static bool aib_refused(const uint8_t *wire, size_t len, const char *needle)
{
    struct app_image_build out;
    struct zcl_result r = app_image_build_decode(wire, len, &out);
    bool ok = !r.ok && strstr(r.message, "app build record") != NULL &&
              (!needle || strstr(r.message, needle) != NULL);
    if (!ok)
        printf("    len=%zu wanted refusal with '%s', got ok=%d '%s'\n", len,
               needle ? needle : "", (int)r.ok, r.message);
    return ok;
}

/* A wire with the package root zeroed and its record id recomputed, so only
 * the zero-field rule can refuse it. */
static void aib_zero_package_root(uint8_t wire[APP_IMAGE_BUILD_WIRE_BYTES])
{
    static const char domain[] = APP_IMAGE_BUILD_DOMAIN;
    memset(wire + APP_IMAGE_BUILD_DOMAIN_BYTES, 0, 32);
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, wire, APP_IMAGE_BUILD_BODY_BYTES);
    sha3_256_finalize(&sha, wire + APP_IMAGE_BUILD_BODY_BYTES);
}

static bool aib_every_bit_refused(const uint8_t wire[APP_IMAGE_BUILD_WIRE_BYTES])
{
    uint8_t flip[APP_IMAGE_BUILD_WIRE_BYTES];
    for (size_t bit = 0; bit < 8u * APP_IMAGE_BUILD_WIRE_BYTES; bit++) {
        memcpy(flip, wire, sizeof(flip));
        flip[bit / 8u] ^= (uint8_t)(1u << (bit % 8u));
        if (!aib_refused(flip, sizeof(flip), NULL))
            return false;
    }
    return true;
}

static bool aib_every_truncation_refused(
    const uint8_t wire[APP_IMAGE_BUILD_WIRE_BYTES])
{
    for (size_t len = 0; len < APP_IMAGE_BUILD_WIRE_BYTES; len++)
        if (!aib_refused(wire, len, "truncated"))
            return false;
    return true;
}

static int test_aib_malformed(const struct aib_fx *x,
                              const uint8_t env_root[32])
{
    int failures = 0;
    TEST("app_image_build: a malformed or truncated record is refused") {
        struct app_image_build rec, back;
        uint8_t wire[APP_IMAGE_BUILD_WIRE_BYTES + 1u] = {0};
        ASSERT(aib_record(x, env_root, "copy v1", &rec));
        ASSERT(app_image_build_encode(&rec, wire).ok);
        ASSERT(app_image_build_decode(wire, APP_IMAGE_BUILD_WIRE_BYTES,
                                      &back).ok);
        ASSERT(aib_record_equal(&rec, &back));
        ASSERT(aib_every_truncation_refused(wire));
        ASSERT(aib_refused(wire, sizeof(wire), "trailing"));
        ASSERT(aib_every_bit_refused(wire));
        aib_zero_package_root(wire);
        ASSERT(aib_refused(wire, APP_IMAGE_BUILD_WIRE_BYTES, "package_root"));
        PASS();
    } _test_next:;
    return failures;
}

static int test_aib_torn(const struct aib_fx *x, const uint8_t env_root[32])
{
    int failures = 0;
    TEST("app_image_build: a truncated stored record is refused, not a miss") {
        struct app_image_build rec, got;
        uint8_t wire[APP_IMAGE_BUILD_WIRE_BYTES], key[32];
        char store[PATH_MAX + 16], name[96], hex[65];
        bool hit = true;
        (void)snprintf(store, sizeof(store), "%s/torn", x->root);
        ASSERT(mkdir(store, 0700) == 0);
        ASSERT(aib_record(x, env_root, "copy v1", &rec));
        ASSERT(app_image_build_encode(&rec, wire).ok);
        app_image_build_key(rec.package_root, rec.env_root,
                            rec.dependency_root, key);
        zcl_hex_encode(key, 32, hex);
        (void)snprintf(name, sizeof(name), "%s%s", hex,
                       APP_IMAGE_BUILD_FILE_SUFFIX);
        ASSERT(aib_file_at(store, name, wire, 100));
        struct zcl_result r = app_image_build_load(
            store, rec.package_root, rec.env_root, rec.dependency_root, &got,
            &hit);
        ASSERT(!r.ok && !hit && strstr(r.message, "truncated") != NULL &&
               strstr(r.message, store) != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_aib_env(uint8_t env_root[32])
{
    int failures = 0;
    struct zcl_result env = app_image_env_root(env_root);
    TEST("app_image_build: env root is the captured toolchain capsule root") {
        struct vcs_toolchain_capsule_v1 capsule;
        uint8_t want[32];
        ASSERT(env.ok);
        ASSERT(vcs_toolchain_capsule_v1_capture(&capsule) &&
               vcs_toolchain_capsule_v1_root(&capsule, want));
        ASSERT(memcmp(want, env_root, 32) == 0);
        PASS();
    } _test_next:;
    if (!env.ok)
        aib_named_root("app_build fixture toolchain", env_root);
    return failures;
}

static int test_aib_records(const uint8_t env_root[32])
{
    int failures = 0;
    struct aib_fx x;
    TEST("app_image_build: fixture image") {
        ASSERT(aib_init(&x, "record", env_root));
        PASS();
    } _test_next:;
    if (failures)
        return failures;
    failures += test_aib_store(&x, env_root);
    failures += test_aib_domain(&x, env_root);
    failures += test_aib_malformed(&x, env_root);
    failures += test_aib_torn(&x, env_root);
    failures += test_aib_launch(&x, env_root);
    test_rm_rf(x.root);
    return failures;
}

int test_app_image_build(void)
{
    int failures = 0;
    uint8_t env_root[32];
    failures += test_aib_env(env_root);
    failures += test_aib_closure(env_root);
    failures += test_aib_records(env_root);
    return failures;
}
