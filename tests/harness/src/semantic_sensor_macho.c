/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: semantic_sensor checks that a Mach-O object compiler's IDENTITY follows its dylib closure: a changed dependency, direct or transitive, changes the libs hash, and a dependency that cannot be read or resolved makes the compiler unknown rather than partly hashed.
 *
 * Darwin only (compiles to a stub elsewhere; the ELF closure is covered by
 * semantic_sensor_identity.c). Part of the semantic_sensor group
 * (test_semantic_manifest.c); runs only where build/bin/z23-clang-manifest
 * is built. The fixture is a driver linked against dylib A (by @rpath),
 * which is linked against dylib B (by @loader_path rpath), all built in a
 * temp root with the system cc. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_core.h"

#include "test/semantic_consumer_fixture.h"
#include "test/semantic_facts_fixture.h"
#include "util/spawn.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int semantic_sensor_macho_tests(void);

#if defined(__APPLE__)
#define SSM_SENSOR "build/bin/z23-clang-manifest"
#define SSM_TC "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"

static bool ssm_write(const char *path, const char *text)
{
    FILE *fp = fopen(path, "wb");
    bool ok = fp != NULL && fputs(text, fp) >= 0;
    if (fp != NULL && fclose(fp) != 0)
        ok = false;
    return ok;
}

static bool ssm_run(const char *const argv[])
{
    char message[4096];
    bool timed_out = false;
    int rc = zcl_spawn_capture_merged_observed(argv, message, sizeof(message),
                                               60000, &timed_out);
    if (rc != 0 || timed_out)
        printf("  %s failed: %s\n", argv[0], message);
    return rc == 0 && !timed_out;
}

/* Build the dylib B returning `value` into <root>/lib. */
static bool ssm_build_b(const char *root, int value)
{
    char src[PATH_MAX], dst[PATH_MAX], body[96];
    (void)snprintf(src, sizeof(src), "%s/b.c", root);
    (void)snprintf(dst, sizeof(dst), "%s/lib/libzfxb.dylib", root);
    (void)snprintf(body, sizeof(body), "int zfx_b(void) { return %d; }\n", value);
    const char *argv[] = {"/usr/bin/cc", "-dynamiclib", "-o", dst, src,
                          "-install_name", "@rpath/libzfxb.dylib", NULL};
    (void)unlink(dst);
    return ssm_write(src, body) && ssm_run(argv);
}

/* Dylib A (needs B) and the driver (needs A), once. */
static bool ssm_build_rest(const char *root)
{
    char a_src[PATH_MAX], a_dst[PATH_MAX], m_src[PATH_MAX], m_dst[PATH_MAX];
    char libdir[PATH_MAX], lflag[PATH_MAX + 4];
    (void)snprintf(a_src, sizeof(a_src), "%s/a.c", root);
    (void)snprintf(a_dst, sizeof(a_dst), "%s/lib/libzfxa.dylib", root);
    (void)snprintf(m_src, sizeof(m_src), "%s/main.c", root);
    (void)snprintf(m_dst, sizeof(m_dst), "%s/bin-m/cc", root);
    (void)snprintf(libdir, sizeof(libdir), "%s/lib", root);
    (void)snprintf(lflag, sizeof(lflag), "-L%s", libdir);
    const char *a_argv[] = {"/usr/bin/cc", "-dynamiclib", "-o", a_dst, a_src,
                            lflag, "-lzfxb", "-install_name",
                            "@rpath/libzfxa.dylib", "-Wl,-rpath,@loader_path",
                            NULL};
    const char *m_argv[] = {"/usr/bin/cc", "-o", m_dst, m_src, lflag, "-lzfxa",
                            "-Wl,-rpath,@executable_path/../lib", NULL};
    return ssm_write(a_src, "int zfx_b(void);\n"
                            "int zfx_a(void) { return zfx_b() + 1; }\n") &&
           ssm_write(m_src, "int zfx_a(void);\n"
                            "int main(void) { return zfx_a() * 0; }\n") &&
           ssm_run(a_argv) && ssm_run(m_argv);
}

/* Emit ssi.c under the fixture driver into <root>/m<k>.zsm; read it back. */
static bool ssm_emit(const char *root, int k, uint8_t **m, size_t *n)
{
    char cc[PATH_MAX], out[PATH_MAX];
    (void)snprintf(cc, sizeof(cc), "%s/bin-m/cc", root);
    (void)snprintf(out, sizeof(out), "%s/m%d.zsm", root, k);
    const char *argv[] = {SSM_SENSOR, "emit", "--root", root, "--source",
                          "ssm.c", "--out", out, "--facts", "--cc", cc,
                          "--toolchain-id", SSM_TC, "--", "-std=c23", "-O1",
                          NULL};
    return ssm_run(argv) && sft_read(out, m, n);
}

static bool ssm_has(const uint8_t *b, size_t n, const char *text)
{
    size_t t = strlen(text);
    for (size_t k = 0; t <= n && k + t <= n; k++)
        if (memcmp(b + k, text, t) == 0)
            return true;
    return false;
}

/* The 64 hex digits after "libs sha3-256 " in the manifest, or "". */
static bool ssm_libs(const uint8_t *b, size_t n, char out[65])
{
    static const char key[] = "libs sha3-256 ";
    size_t t = sizeof(key) - 1;
    out[0] = '\0';
    for (size_t k = 0; k + t + 64 <= n; k++)
        if (memcmp(b + k, key, t) == 0) {
            memcpy(out, b + k + t, 64);
            out[64] = '\0';
            return true;
        }
    return false;
}

static bool ssm_setup(const char *root)
{
    char path[PATH_MAX];
    const char *dirs[] = {"lib", "bin-m"};
    for (size_t k = 0; k < 2; k++) {
        (void)snprintf(path, sizeof(path), "%s/%s", root, dirs[k]);
        if (!scx_mkdir(path))
            return false;
    }
    (void)snprintf(path, sizeof(path), "%s/ssm.c", root);
    return ssm_write(path, "int ssm_value(int x) { return x + 1; }\n") &&
           ssm_build_b(root, 1) && ssm_build_rest(root);
}

static int ssm_t_closure(void)
{
    int failures = 0;
    char root[1024] = {0}, h[3][65], dep[PATH_MAX];
    uint8_t *m[4] = {0};
    size_t n[4] = {0};
    TEST_CASE("semantic_sensor: a Mach-O compiler's IDENTITY follows its transitive dylibs") {
        ASSERT(test_mkdtemp(root, sizeof(root), "semsensor_macho") != NULL);
        ASSERT(ssm_setup(root));
        (void)snprintf(dep, sizeof(dep), "%s/lib/libzfxb.dylib", root);
        /* Known and stable. */
        ASSERT(ssm_emit(root, 0, &m[0], &n[0]));
        ASSERT(ssm_libs(m[0], n[0], h[0]));
        /* Only the transitive dependency B changes: the hash must too. */
        ASSERT(ssm_build_b(root, 2));
        ASSERT(ssm_emit(root, 1, &m[1], &n[1]));
        ASSERT(ssm_libs(m[1], n[1], h[1]));
        ASSERT(strcmp(h[0], h[1]) != 0);
        /* An unreadable dependency: unknown, not a partial hash. */
        ASSERT(chmod(dep, 0) == 0);
        ASSERT(ssm_emit(root, 2, &m[2], &n[2]));
        ASSERT(ssm_has(m[2], n[2], "; object-cc unknown"));
        ASSERT(!ssm_libs(m[2], n[2], h[2]));
        /* A dependency @rpath cannot resolve: unknown. */
        ASSERT(unlink(dep) == 0);
        ASSERT(ssm_emit(root, 3, &m[3], &n[3]));
        ASSERT(ssm_has(m[3], n[3], "; object-cc unknown"));
    } TEST_END
    for (size_t k = 0; k < 4; k++)
        free(m[k]);
    if (root[0] != '\0')
        (void)test_rm_rf_recursive(root);
    return failures;
}

/* The dylib libzfxc returning `value` into <root>/<dir>. */
static bool ssm_build_c(const char *root, const char *dir, int value)
{
    char src[PATH_MAX], dst[PATH_MAX], body[96];
    (void)snprintf(src, sizeof(src), "%s/c_%s.c", root, dir);
    (void)snprintf(dst, sizeof(dst), "%s/%s/libzfxc.dylib", root, dir);
    (void)snprintf(body, sizeof(body), "int zfx_c(void) { return %d; }\n", value);
    const char *argv[] = {"/usr/bin/cc", "-dynamiclib", "-o", dst, src,
                          "-install_name", "@rpath/libzfxc.dylib", NULL};
    (void)unlink(dst);
    return ssm_write(src, body) && ssm_run(argv);
}

/* A driver with two LC_RPATH entries (lib1 then lib2), each holding a
 * libzfxc of different bytes. */
static bool ssm_setup_order(const char *root)
{
    char path[PATH_MAX], m_src[PATH_MAX], m_dst[PATH_MAX], lflag[PATH_MAX + 4];
    const char *dirs[] = {"lib1", "lib2", "bin-m"};
    for (size_t k = 0; k < 3; k++) {
        (void)snprintf(path, sizeof(path), "%s/%s", root, dirs[k]);
        if (!scx_mkdir(path))
            return false;
    }
    (void)snprintf(path, sizeof(path), "%s/ssm.c", root);
    (void)snprintf(m_src, sizeof(m_src), "%s/main.c", root);
    (void)snprintf(m_dst, sizeof(m_dst), "%s/bin-m/cc", root);
    (void)snprintf(lflag, sizeof(lflag), "-L%s/lib1", root);
    const char *m_argv[] = {"/usr/bin/cc", "-o", m_dst, m_src, lflag, "-lzfxc",
                            "-Wl,-rpath,@executable_path/../lib1",
                            "-Wl,-rpath,@executable_path/../lib2", NULL};
    return ssm_write(path, "int ssm_value(int x) { return x + 1; }\n") &&
           ssm_build_c(root, "lib1", 1) && ssm_build_c(root, "lib2", 2) &&
           ssm_write(m_src, "int zfx_c(void);\n"
                            "int main(void) { return zfx_c() * 0; }\n") &&
           ssm_run(m_argv);
}

static int ssm_t_rpath_order(void)
{
    int failures = 0;
    char root[1024] = {0}, h[3][65];
    uint8_t *m[3] = {0};
    size_t n[3] = {0};
    TEST_CASE("semantic_sensor: a Mach-O compiler's identity binds the first LC_RPATH hit") {
        ASSERT(test_mkdtemp(root, sizeof(root), "semsensor_rpath") != NULL);
        ASSERT(ssm_setup_order(root));
        ASSERT(ssm_emit(root, 0, &m[0], &n[0]));
        ASSERT(ssm_libs(m[0], n[0], h[0]));
        /* The shadowed second entry's file is not the one dyld loads. */
        ASSERT(ssm_build_c(root, "lib2", 3));
        ASSERT(ssm_emit(root, 1, &m[1], &n[1]));
        ASSERT(ssm_libs(m[1], n[1], h[1]));
        ASSERT(strcmp(h[0], h[1]) == 0);
        /* The first entry's file is. */
        ASSERT(ssm_build_c(root, "lib1", 4));
        ASSERT(ssm_emit(root, 2, &m[2], &n[2]));
        ASSERT(ssm_libs(m[2], n[2], h[2]));
        ASSERT(strcmp(h[0], h[2]) != 0);
    } TEST_END
    for (size_t k = 0; k < 3; k++)
        free(m[k]);
    if (root[0] != '\0')
        (void)test_rm_rf_recursive(root);
    return failures;
}

int semantic_sensor_macho_tests(void)
{
    return ssm_t_closure() + ssm_t_rpath_order();
}
#else
int semantic_sensor_macho_tests(void)
{
    return 0;
}
#endif
