/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * The published FreeBSD 15.1-RELEASE riscv64 kernel, and with the release disk
 * image a single-user shell, booted by dev.app.machine.boot. Inputs are located
 * by environment variables and bound by size and sha256. An unset variable or a
 * readable file that is not the published one leaves its case unobserved; a named
 * path that cannot be read fails the group. The disk is never opened for writing. */
#include "test/test_core.h"
#include "base/hex.h"
#include "command/native_command.h"
#include "config/command_catalog.h"
#include "crypto/sha256.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <sys/stat.h>

#define FR_KERNEL_BYTES UINT64_C(62745584)
#define FR_KERNEL_SHA "69320e312d5601c5fe228aa3bcbdc4bbc55e0d86a4cf9e68eb6ffdc7247701b1"
#define FR_DISK_BYTES UINT64_C(7550318080)
#define FR_DISK_SHA "084980a2299d2a8bca7033fc4eefcc8e22b64096e7952ce63366d8408605ff15"
#define FR_KERNEL_MAX_INSTR INT64_C(1000000000)
#define FR_DISK_MAX_INSTR INT64_C(2000000000)
#define FR_WIRE 16384u
#define FR_TRANSCRIPT_MAX 65536u

struct fr_stat {
    uint64_t size;
    int64_t mtime;
    uint64_t inode;
};

static bool fr_stat(const char *path, struct fr_stat *out)
{
    struct stat sb;
    if (stat(path, &sb) != 0 || sb.st_size < 0) return false;
    out->size = (uint64_t)sb.st_size;
    out->mtime = (int64_t)sb.st_mtime;
    out->inode = (uint64_t)sb.st_ino;
    return true;
}

static bool fr_stat_same(const struct fr_stat *a, const struct fr_stat *b)
{
    return a->size == b->size && a->mtime == b->mtime && a->inode == b->inode;
}

/* Hashes the file, printing one line per GiB so a multi-gigabyte image on a slow
 * host is not mistaken for a hang by the runner's silence bound. */
static bool fr_sha256(const char *path, char hex[65])
{
    static uint8_t buf[1u << 20];
    FILE *f = fopen(path, "rb");
    if (f == NULL) return false;
    struct sha256_ctx sha;
    uint8_t digest[SHA256_OUTPUT_SIZE];
    uint64_t total = 0;
    size_t n;
    sha256_init(&sha);
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) {
        sha256_write(&sha, buf, n);
        total += n;
        if ((total & ((UINT64_C(1) << 30) - 1u)) == 0) {
            printf("  hashed %llu GiB of %s\n", (unsigned long long)(total >> 30), path);
            fflush(stdout);
        }
    }
    bool ok = !ferror(f);
    fclose(f);
    sha256_finalize(&sha, digest);
    zcl_hex_encode(digest, sizeof digest, hex);
    return ok;
}

enum fr_binding { FR_BOUND, FR_DIFFERENT, FR_UNREADABLE };

/* FR_BOUND: the file is the documented one. FR_DIFFERENT: a readable file of
 * another size or sha256. FR_UNREADABLE: the path cannot be read in full. A file
 * of another size is opened but not hashed. */
static enum fr_binding fr_bind(const char *path, uint64_t bytes, const char *sha)
{
    struct fr_stat st;
    char hex[65];
    if (!fr_stat(path, &st)) return FR_UNREADABLE;
    if (st.size != bytes) {
        FILE *f = fopen(path, "rb");
        int first = f != NULL ? fgetc(f) : EOF;
        bool readable = f != NULL && !ferror(f) &&
                        (first != EOF || feof(f));
        if (f != NULL) fclose(f);
        return readable ? FR_DIFFERENT : FR_UNREADABLE;
    }
    if (!fr_sha256(path, hex)) return FR_UNREADABLE;
    return strcmp(hex, sha) == 0 ? FR_BOUND : FR_DIFFERENT;
}

static bool fr_binding_case(void)
{
    char dir[256], path[320];
    if (test_mkdtemp(dir, sizeof dir, "freebsd_release_bind") == NULL) return false;
    snprintf(path, sizeof path, "%s/not-the-kernel", dir);
    FILE *f = fopen(path, "wb");
    bool ok = f != NULL && fputs("z23", f) >= 0;
    if (f != NULL) ok = fclose(f) == 0 && ok;
    ok = ok && fr_bind(path, FR_KERNEL_BYTES, FR_KERNEL_SHA) == FR_DIFFERENT &&
         fr_bind(path, 3, FR_KERNEL_SHA) == FR_DIFFERENT &&
         fr_bind(dir, FR_KERNEL_BYTES, FR_KERNEL_SHA) == FR_UNREADABLE;
    f = fopen(path, "wb");
    bool empty_created = f != NULL;
    if (f != NULL) empty_created = fclose(f) == 0 && empty_created;
    ok = ok && empty_created &&
         fr_bind(path, FR_KERNEL_BYTES, FR_KERNEL_SHA) == FR_DIFFERENT;
    snprintf(path, sizeof path, "%s/absent", dir);
    ok = ok && fr_bind(path, FR_KERNEL_BYTES, FR_KERNEL_SHA) == FR_UNREADABLE;
    test_cleanup_tmpdir(dir);
    return ok;
}

static int fr_run_binding(void)
{
    int failures = 0;
    TEST("FreeBSD release inputs: unreadable and different files are told apart") {
        ASSERT(fr_binding_case());
        PASS();
    } _test_next:;
    return failures;
}

static bool fr_read_text(const char *path, char *out, size_t cap)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) return false;
    size_t n = fread(out, 1, cap - 1u, f);
    bool whole = fgetc(f) == EOF;
    fclose(f);
    out[n] = '\0';
    return whole;
}

/* Runs the registered leaf on one JSON input; the reply envelope is parsed
 * into doc and the transcript, when written, is read into text. */
static bool fr_boot(const char *json, struct json_value *doc, const char *transcript,
                    char *text, size_t text_cap)
{
    static char wire[FR_WIRE];
    const struct zcl_command_spec *found =
        zcl_command_registry_find(zcl_command_catalog(), "dev.app.machine.boot", NULL);
    struct zcl_command_spec spec;
    struct json_value input;
    enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_INTERNAL;
    size_t len = 0;
    json_init(doc);
    json_init(&input);
    if (found == NULL) return false;
    spec = *found;
    spec.handler = zcl_native_handle_dev_machine_boot;
    if (json_read(&input, json, strlen(json)) && input.type == JSON_OBJ)
        len = zcl_command_registry_execute_json(zcl_command_catalog(), &spec, NULL,
                                                &input, false, "dev.app.machine.boot",
                                                NULL, 0, 0, NULL, wire, sizeof wire,
                                                &exit_code);
    json_free(&input);
    return len > 0 && json_read(doc, wire, len) && exit_code == ZCL_COMMAND_EXIT_OK &&
           json_get_bool(json_get(doc, "ok")) && fr_read_text(transcript, text, text_cap);
}

static int64_t fr_int(const struct json_value *doc, const char *key)
{
    const struct json_value *v = json_get(json_get(doc, "data"), key);
    return v != NULL && v->type == JSON_INT ? json_get_int(v) : -1;
}

static bool fr_flag(const struct json_value *doc, const char *key)
{
    const struct json_value *v = json_get(json_get(doc, "data"), key);
    return v != NULL && v->type == JSON_BOOL && json_get_bool(v);
}

static bool fr_stop_requested(const struct json_value *doc, int64_t bound)
{
    const char *stop = json_get_str(json_get(json_get(doc, "data"), "stop"));
    int64_t retired = fr_int(doc, "retired");
    return stop != NULL && strcmp(stop, "requested") == 0 &&
           fr_flag(doc, "marker_seen") && retired > 0 && retired <= bound;
}

static bool fr_kernel_case(const char *kernel, const char *dir)
{
    static char text[FR_TRANSCRIPT_MAX];
    char json[1024], transcript[512];
    struct json_value doc;
    snprintf(transcript, sizeof transcript, "%s/kernel.transcript", dir);
    snprintf(json, sizeof json,
             "{\"kernel\":\"%s\",\"max_instr\":%lld,\"until\":\"mountroot>\","
             "\"transcript\":\"%s\"}", kernel, (long long)FR_KERNEL_MAX_INSTR,
             transcript);
    bool ok = fr_boot(json, &doc, transcript, text, sizeof text) &&
              fr_stop_requested(&doc, FR_KERNEL_MAX_INSTR) &&
              strstr(text, "mountroot>") != NULL;
    json_free(&doc);
    return ok;
}

static bool fr_disk_case(const char *kernel, const char *disk, const char *dir)
{
    static char text[FR_TRANSCRIPT_MAX];
    char json[2048], transcript[512];
    struct json_value doc;
    struct fr_stat before, after;
    snprintf(transcript, sizeof transcript, "%s/disk.transcript", dir);
    snprintf(json, sizeof json,
             "{\"kernel\":\"%s\",\"disk\":\"%s\","
             "\"bootargs\":\"-s vfs.root.mountfrom=ufs:/dev/vtbd0p3\","
             "\"max_instr\":%lld,"
             "\"type_after\":[[\"RETURN for /bin/sh:\",\"\\n\"],"
             "[\"# \",\"uname -a\\n\"],"
             "[\"# \",\"sysctl hw.machine hw.ncpu hw.physmem\\n\"]],"
             "\"until\":\"# \",\"transcript\":\"%s\"}",
             kernel, disk, (long long)FR_DISK_MAX_INSTR, transcript);
    if (!fr_stat(disk, &before)) return false;
    bool ok = fr_boot(json, &doc, transcript, text, sizeof text) &&
              fr_stop_requested(&doc, FR_DISK_MAX_INSTR) &&
              strstr(text, "15.1-RELEASE") != NULL &&
              strstr(text, "GENERIC riscv") != NULL &&
              strstr(text, "hw.ncpu: 1") != NULL &&
              fr_stat(disk, &after) && fr_stat_same(&before, &after);
    json_free(&doc);
    return ok;
}

static int fr_run_kernel(const char *kernel, const char *dir)
{
    int failures = 0;
    TEST("FreeBSD 15.1 kernel boots to the root mount prompt") {
        fflush(stdout);
        ASSERT(fr_kernel_case(kernel, dir));
        PASS();
    } _test_next:;
    return failures;
}

static int fr_run_disk(const char *kernel, const char *disk, const char *dir)
{
    int failures = 0;
    TEST("FreeBSD 15.1 release disk boots to a single-user shell, disk unchanged") {
        fflush(stdout);
        ASSERT(fr_disk_case(kernel, disk, dir));
        PASS();
    } _test_next:;
    return failures;
}
/* Classifies one named input and prints its verdict: FAIL for a path that cannot
 * be read, UNOBSERVED for an unset variable or a readable file that is not the
 * published one. An unreadable path adds one to *failures. */
static bool fr_input(const char *label, const char *path, uint64_t bytes,
                     const char *sha, int *failures)
{
    if (path == NULL || !*path) {
        printf("UNOBSERVED (no FreeBSD release %s is named by the environment)\n", label);
        return false;
    }
    enum fr_binding b = fr_bind(path, bytes, sha);
    if (b == FR_UNREADABLE) {
        printf("FAIL (%s at %s is named by the environment but cannot be read)\n",
               label, path);
        (*failures)++;
    } else if (b == FR_DIFFERENT) {
        printf("UNOBSERVED (%s at %s is not the published file, which has %llu bytes "
               "and sha256 %s)\n", label, path, (unsigned long long)bytes, sha);
    }
    return b == FR_BOUND;
}
#endif

int test_rvmachine_freebsd_release(void);
int test_rvmachine_freebsd_release(void)
{
#if defined(_WIN32)
    printf("UNOBSERVED (FreeBSD release boot has no Windows qualification)\n");
    return 0;
#else
    char dir[256];
    int failures = fr_run_binding();
    int unreadable = 0;
    const char *kernel = getenv("ZCL_TEST_FREEBSD_RELEASE_KERNEL");
    const char *disk = getenv("ZCL_TEST_FREEBSD_RELEASE_DISK");
    /* Both inputs are classified before either boot, so an unreadable disk fails
     * the group even when the kernel is absent. */
    bool have_kernel = fr_input("kernel", kernel, FR_KERNEL_BYTES, FR_KERNEL_SHA,
                                &unreadable);
    bool have_disk = fr_input("disk", disk, FR_DISK_BYTES, FR_DISK_SHA, &unreadable);
    failures += unreadable;
    if (unreadable != 0 || !have_kernel) return failures;
    if (test_mkdtemp(dir, sizeof dir, "freebsd_release") == NULL) return failures + 1;
    failures += fr_run_kernel(kernel, dir);
    if (have_disk) failures += fr_run_disk(kernel, disk, dir);
    test_cleanup_tmpdir(dir);
    return failures;
#endif
}
